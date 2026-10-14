"""Desktop activity tracking (desk.*)."""

from __future__ import annotations

import base64
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .. import blockdev, ini
from ..host import Unreadable
from ..model import Evidence, Note, Outcome
from . import Check, Scan, register
from ._util import (Tally, absent, children, failed, files_under, human_size, installed, isdir, isfile, mounts, passed,
                    processes, read_text, recent_files, recent_hrefs, sqlite_count, storage_mounts, tally, thumbnail_dirs,
                    thumbnail_entries, unknown, uri_path, warned, xdg_user_dir)

REMOVABLE_ROOTS = ("/media/", "/run/media/", "/mnt/")


def _boot_unlocked(scan: Scan) -> set[str] | None:
    """Mapper names /etc/crypttab opens at boot (no noauto), or None when it can't be read."""
    try:
        text = scan.host.read_sys("/etc/crypttab")
    except Unreadable:
        return None
    out = set()
    for line in (text or "").splitlines():
        f = line.split()
        if f and not f[0].startswith("#") and "noauto" not in (f[3] if len(f) > 3 else "").split(","):
            out.add(f[0])
    return out


def _crypt_name(d: blockdev.Device) -> str | None:
    while d is not None and d.type != "crypt":
        d = d.parent
    return d.name if d is not None else None


def _sensitive_roots(scan: Scan) -> list[str]:
    """Mount points whose files shouldn't leave traces elsewhere: removable drives, and encrypted
    volumes opened on demand (a VeraCrypt container, a LUKS stick, cryptsetup by hand). Internal
    drives, and encrypted ones unlocked at boot with the system, are as protected as the cache;
    mounts lsblk doesn't show (FUSE: sshfs, phones, some containers) in the places drives go count."""
    devices = scan.context.devices or []
    home_dev = blockdev.holding(devices, str(scan.host.home))
    boot = _boot_unlocked(scan)
    roots, block_mounts = [], set()
    for mp, d in blockdev.mounted(devices):
        block_mounts.add(mp)
        if mp in ("/", "/boot", "/boot/efi", "/efi") or d is home_dev:
            continue
        on_demand = d.encrypted and (boot is None or _crypt_name(d) not in boot)
        if d.removable or on_demand:
            roots.append(mp.rstrip("/") + "/")
    for m in mounts(scan.host):
        if m.target.startswith(REMOVABLE_ROOTS) and m.target not in block_mounts and m.fstype not in ("tmpfs", "autofs"):
            roots.append(m.target.rstrip("/") + "/")
    return sorted(set(roots), key=len, reverse=True)


def sensitive_place(scan: Scan, roots: list[str] | None = None):
    """A function giving, for a file's path, the drive or volume it counts as sensitive on (None if it
    doesn't): a sensitive mount, or a place drives are mounted (/media, /run/media, /mnt) where nothing
    is mounted now (the drive it came from is gone)."""
    roots = _sensitive_roots(scan) if roots is None else roots
    mounted = sorted({m.target.rstrip("/") + "/" for m in mounts(scan.host) if m.target.startswith(REMOVABLE_ROOTS)},
                     key=len, reverse=True)

    def place(path: str) -> str | None:
        root = next((r for r in roots if path.startswith(r)), None)
        if root:
            return root.rstrip("/")
        base = next((r for r in REMOVABLE_ROOTS if path.startswith(r)), None)
        if base and not any(path.startswith(m) for m in mounted):
            return _drive_of(path, base)
        return None
    return place


def _drive_of(path: str, root: str) -> str:
    """Where a file on a drive that isn't mounted now lived: /media/<user>/<label>,
    /run/media/<user>/<label> or /mnt/<name>."""
    depth = {"/media/": 2, "/run/media/": 2, "/mnt/": 1}[root]
    rest = path[len(root):].split("/")
    return root + "/".join(rest[:depth])


def _exists(path: str) -> bool:
    try:
        return Path(path).exists()
    except OSError:
        return True             # can't tell: don't call it deleted


class MemoryMount:
    """One of the user's folders kept in memory by a systemd mount unit of the helper's own
    (mount_tmpfs: the thumbnail cache, GVFS metadata, ~/Ephemeral): its real path (the one a
    mount shows), the unit's name, whether the folder is a tmpfs mount now (and with which
    options), and whether the unit exists. `path` is where the app looks for the folder; the
    helper only ever mounts `expected` (the folder under the home), so the two must agree."""

    LABELS = {"thumbnails": "thumbnail cache", "gvfs-metadata": "GVFS metadata", "ephemeral": "~/Ephemeral folder"}

    def __init__(self, scan: Scan, target: str, path: Path | None = None):
        from ..helper import IN_MEMORY, UNIT_DIR, unit_name
        self.target, self.label = target, self.LABELS[target]
        self.parts = IN_MEMORY[target][0]
        self.expected = scan.host.home.joinpath(*self.parts)
        self.path = path if path is not None else self.expected
        self.real = os.path.realpath(self.path)
        root = os.path.realpath(scan.host.root)
        if root != "/" and self.real.startswith(root + "/"):        # a fixture tree: the path as the system sees it
            self.real = self.real[len(root):]
        self.unit = unit_name(self.real)
        self.unit_file = f"{UNIT_DIR}/{self.unit}"
        self.mount = next((m for m in reversed(mounts(scan.host)) if m.target in (self.real, str(self.path))), None)
        self.in_memory = self.mount is not None and self.mount.fstype == "tmpfs"
        self.unit_text = read_text(scan.host, scan.host.sys_path(self.unit_file)) if isfile(scan.host.sys_path(self.unit_file)) else None
        self.unit_exists = self.unit_text is not None

    @property
    def where(self) -> str:
        return "~/" + "/".join(self.parts)

    @property
    def options(self) -> dict[str, str]:
        """The mount's options now: {"size": "500M", "noexec": "", ...}."""
        if not self.in_memory:
            return {}
        return dict((o.split("=", 1) + [""])[:2] for o in self.mount.options.split(","))

    @property
    def until(self) -> str | None:
        """"logout" or "reboot", from the unit file."""
        if self.unit_text is None:
            return None
        return "logout" if "WantedBy=user@" in self.unit_text else "reboot"

    def why_not_mounted(self, scan: Scan) -> Note | None:
        """When the unit exists but the folder isn't in memory: what systemd says, in words."""
        if self.in_memory or not self.unit_exists:
            return None
        r = scan.host.run("systemctl", "show", "-p", "ConditionResult", "-p", "ActiveState", self.unit)
        props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line) if r.ok else {}
        on_the_way = " or ".join("~/" + "/".join(self.parts[:i + 1]) for i in range(len(self.parts)))
        written = "nothing can be saved in it" if self.target == "ephemeral" else "it is written to disk"
        if props.get("ConditionResult") == "no":
            return Note("risk", f"The in-memory {self.label} was skipped at {'login' if self.until == 'logout' else 'boot'}",
                        f"systemd didn't mount it because {on_the_way} was missing or had become a link (a link could "
                        f"send the mount somewhere else, so it is never followed). Until that is put right, {written}; "
                        f"then reboot, or run `sudo systemctl start '{self.unit}'`.")
        state = props.get("ActiveState") or "unknown"
        return Note("risk", f"The in-memory {self.label} isn't mounted",
                    f"The mount unit {self.unit_file} is there, but it is {state}, so {written}. "
                    f"`systemctl status '{self.unit}'` says why.")


def ThumbnailMount(scan: Scan) -> MemoryMount:
    return MemoryMount(scan, "thumbnails", scan.paths.cache_home / "thumbnails")


def _expiry(scan: Scan, name: str) -> str | None:
    """The app's user tmpfiles.d rule of that name, if it is there and the daily timer that
    applies it is enabled."""
    from ._util import systemctl_state
    from .guides import TMPFILES_TIMER, expire_rule
    rule = expire_rule(scan, name)
    if rule and systemctl_state(scan.host, "is-enabled", TMPFILES_TIMER, user=True) == "enabled":
        return rule
    return None


@register
class Thumbnails(Check):
    id = "desk.thumbnails"
    FINDING = "thumbnails_reference_removable_or_container"
    ON_DISK = "thumbnails_on_disk_none_leaking"
    EXPIRE = "thumbnails_expire"          # deleted within EXPIRE_DAYS: the lowest warning while on disk
    EXPIRE_DAYS = 30

    def detect(self, scan: Scan) -> Outcome:
        entries, count = thumbnail_entries(scan.paths)
        tm = ThumbnailMount(scan)
        in_memory = tm.in_memory
        if not count and not in_memory and not scan.context.desktop.names \
                and not any(isdir(d) for d in thumbnail_dirs(scan.paths)):
            return absent("No desktop makes thumbnails.")
        memory_note = Note("info", "The thumbnail cache is kept in memory",
                           "It is a tmpfs mount: emptied at every reboot, nothing written to disk.")
        notes = [n for n in [tm.why_not_mounted(scan)] if n]
        ev, orphans, sensitive = [], 0, 0
        # with the main cache in memory, what Flatpak and Snap apps cache for themselves is still on the disk
        disk_orphans = disk_sensitive = 0
        cache = str(tm.path).rstrip("/") + "/"
        if count:
            place_of = sensitive_place(scan)
            places: set[str] = set()
            for png, u in entries:
                path = uri_path(u)
                if path is None:
                    continue
                on_disk = not in_memory or not str(png).startswith(cache)
                place = place_of(path)
                if place:
                    sensitive += 1
                    disk_sensitive += on_disk
                    places.add(place)
                elif not _exists(path):
                    orphans += 1
                    disk_orphans += on_disk
            size = Tally()
            for d in thumbnail_dirs(scan.paths):
                size += tally(d)
            ev = [Evidence.val("Thumbnail cache", size.describe()),
                  Evidence.count("Of files that no longer exist", orphans),
                  Evidence.count("Of files on removable drives or other encrypted volumes", sensitive)]
            ev += [Evidence.path("From", p) for p in sorted(places)[:5]]
        from .fixes import _gnome_family
        from .guides.desktop import THUMBNAIL_SCHEMAS
        schema = THUMBNAIL_SCHEMAS.get(_gnome_family(scan) or "")
        expire: bool | None = False
        if schema:
            age = scan.gnome.gsettings(schema, "maximum-age")
            if age is not None:
                ev.append(Evidence.val("The desktop deletes thumbnails after", "never" if age == -1 else f"{age} days"))
                expire = isinstance(age, int) and 0 <= age <= self.EXPIRE_DAYS
            else:
                expire = None                 # couldn't read the setting: not assumed either way
        if _expiry(scan, "thumbnails"):
            ev.append(Evidence.val("Deleted when unused for", "30 days (a rule of this app's, daily)"))
            expire = True
        if in_memory:
            ev.insert(0, Evidence.val("Kept in", "memory (tmpfs), cleared at every reboot"))
            apps = [d for d in thumbnail_dirs(scan.paths) if d != tm.path and tally(d).files]
            if disk_sensitive or disk_orphans:
                ev.append(Evidence.count("Of those, in apps' own caches on the disk", disk_sensitive + disk_orphans))
                ev += [Evidence.path("App cache on the disk", scan.host.display(d)) for d in apps[:5]]
                n = disk_sensitive or disk_orphans
                what = "files from removable drives or encrypted containers" if disk_sensitive else "deleted files"
                return failed(f"{n} thumbnail{'s' if n > 1 else ''} in apps' own caches show {what}: the desktop's "
                              "cache is in memory, but Flatpak and Snap apps keep theirs on the disk.", *ev,
                              notes=[memory_note, Note("risk", "Apps' own thumbnail caches",
                                                       "A Flatpak or Snap app keeps a thumbnail cache of its own in its "
                                                       "folder (~/.var/app or ~/snap), on the disk. Guide… deletes the "
                                                       "thumbnails in them that leak.")],
                              findings={self.FINDING: disk_sensitive > 0, self.ON_DISK: False, self.EXPIRE: expire})
            leaks = sensitive + orphans
            if apps:
                notes.append(Note("info", "Apps' own thumbnail caches are on the disk",
                                  f"{', '.join(scan.host.display(d) for d in apps[:3])}: Flatpak and Snap apps keep "
                                  "thumbnails of their own there. None of them leaks now."))
            return passed(f"{leaks} thumbnail{'s' if leaks > 1 else ''} would leak, but the cache is in memory and gone "
                          "at the next reboot." if leaks else "The thumbnail cache is kept in memory.", *ev,
                          notes=[memory_note] + notes, findings={self.FINDING: False, self.ON_DISK: False,
                                                                 self.EXPIRE: expire})
        findings = {self.FINDING: sensitive > 0, self.ON_DISK: not (sensitive or orphans), self.EXPIRE: expire}
        if sensitive:
            notes.append(Note("risk", "Thumbnails outlive the drive they came from",
                              "Each thumbnail is a small copy of the image and records the file's full path. Browsing an "
                              "encrypted container or a USB stick leaves these copies on this disk after it's removed."))
            return failed(f"{sensitive} thumbnail{'s' if sensitive > 1 else ''} show files from removable drives or "
                          "encrypted containers.", *ev, notes=notes, findings=findings)
        if orphans:
            return failed(f"{orphans} thumbnail{'s' if orphans > 1 else ''} of deleted files are still cached.", *ev,
                          notes=notes, findings=findings)
        if not notes:              # the in-memory unit's own note already says why it is on disk
            notes.append(Note("risk", "The first USB stick you browse starts the record",
                              "Every picture a file manager or image viewer shows gets a small copy here, with the "
                              "picture's full path inside, kept long after the picture is deleted or the drive is "
                              "unplugged. Kept in memory, the cache is empty again at every boot."))
        kept = (f" for up to {self.EXPIRE_DAYS} days" if expire else "")
        return warned(("Nothing leaks now: the cached thumbnails only show files that still exist. But they are"
                       if count else "Nothing leaks now: no thumbnails are cached yet. But they would be")
                      + f" kept on disk{kept}, so the next picture you download and delete, or open from a USB drive, "
                      "leaves a copy here. Scan again later to see whether one has, or keep them in memory.",
                      *ev, notes=notes, findings=findings)


@register
class RecentFiles(Check):
    id = "desk.recent_files"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, total = [], 0
        for x in recent_files(scan.paths):
            if x.is_dir():                    # a folder where the file goes: no app can write it
                ev.append(Evidence.val(host.display(x), "blocked: a folder in its place"))
                continue
            n = len(recent_hrefs(host, x))
            total += n
            ev.append(Evidence.count(f"Entries in {host.display(x)}", n))
        from .fixes import _gnome_family
        from .guides.desktop import PRIVACY_SCHEMAS
        schema = PRIVACY_SCHEMAS.get(_gnome_family(scan) or "")
        if schema:
            remember = scan.gnome.gsettings(schema, "remember-recent-files")
            age = scan.gnome.gsettings(schema, "recent-files-max-age")
            if remember is not None:
                ev.append(Evidence.val("Remember recent files", remember))
            if age is not None:
                ev.append(Evidence.val("Kept for", "forever" if age == -1 else f"{age} days"))
        if total:
            return failed(f"{total} recently opened file{'s are' if total > 1 else ' is'} listed.", *ev)
        return passed("The recent files list is empty.", *ev)


@register
class KdeActivities(Check):
    id = "desk.kde_activities"

    def detect(self, scan: Scan) -> Outcome:
        data = scan.paths.data_home
        db = data / "kactivitymanagerd" / "resources" / "database"
        recent = [p for p in children(data / "RecentDocuments") if p.suffix == ".desktop"]
        if not scan.context.desktop.is_kde and not isfile(db) and not recent:
            return absent("Not a KDE Plasma session.")
        ev = []
        # VERIFY (catalogue): table names on the target Plasma version; if absent, only the size is shown
        events = sqlite_count(db, "SELECT count(*) FROM ResourceEvent", optional=True)
        scores = sqlite_count(db, "SELECT count(*) FROM ResourceScoreCache", optional=True)
        if isfile(db):
            ev.append(Evidence.val("Activity database", human_size(db.stat().st_size)))
        if events is not None:
            ev.append(Evidence.count("Recorded file and app events", events))
        if scores is not None:
            ev.append(Evidence.count("Remembered files and apps", scores))
        ev.append(Evidence.count("Recent documents", len(recent)))
        use_recent = scan.kde.get("kdeglobals", "RecentDocuments", "UseRecent")
        ev.append(Evidence.val("Remember recent documents", "yes (default)" if use_recent is None else use_recent))
        if (events or scores or recent) or (events is None and isfile(db) and db.stat().st_size > 64 * 1024):
            return failed("KDE keeps a history of the files and apps you use.", *ev)
        return passed("KDE's activity history is empty.", *ev)


def _outside_home(scan: Scan, folders: list[str]) -> list[str]:
    """The folders of an indexer's list that aren't in the home folder (removable drives, other volumes)."""
    home = str(scan.host.home).rstrip("/") + "/"
    out = []
    for f in folders:
        f = f.strip().replace("$HOME", str(scan.host.home))
        if f.startswith("/") and not (f.rstrip("/") + "/").startswith(home):
            out.append(f)
    return out


INDEXER_SCHEMA = "org.freedesktop.Tracker3.Miner.Files"


def _kpaths(kde, group: str, key: str, home: str) -> list[str] | None:
    """A KConfig path list (written with or without [$e]), $HOME expanded, each without its trailing slash."""
    raw = kde.get("baloofilerc", group, key)               # ini.parse drops the [$e] mark
    if raw is None:
        return None
    raw = raw.replace("${HOME}", home).replace("$HOME", home)
    return [f.rstrip("/") or "/" for f in raw.split(",") if f.strip()]


def baloo_folders(kde, home: Path) -> tuple[list[str], list[str]]:
    """(the folders Baloo indexes, those it leaves out): its default is the home folder, nothing left out."""
    h = str(home)
    return _kpaths(kde, "General", "folders", h) or [h], _kpaths(kde, "General", "exclude folders", h) or []


def baloo_covers(kde, home: Path, path: Path) -> bool:
    """Whether Baloo would index `path` (a folder under the home folder, not hidden): in a folder it indexes,
    in none it leaves out."""
    folders, excluded = baloo_folders(kde, home)
    p = str(path).rstrip("/")
    under = lambda f: p == f or p.startswith(f.rstrip("/") + "/")
    return any(under(f) for f in folders) and not any(under(f) for f in excluded)


def recoll_dir(scan: Scan) -> Path:
    d = scan.host.environ.get("RECOLL_CONFDIR")
    return Path(d) if d and d.startswith("/") else scan.host.home / ".recoll"


def recoll_index(scan: Scan) -> tuple[Path, int] | None:
    """(Recoll's configuration folder, the size of its index), when it has made one: a full-text index of
    the documents under its top folders (the home folder by default), in xapiandb."""
    conf = recoll_dir(scan)
    t = tally(conf / "xapiandb")
    return (conf, t.bytes) if t.files else None


def recoll_topdirs(scan: Scan, conf: Path) -> list[str]:
    m = re.search(r"^\s*topdirs\s*=\s*(.+)$", read_text(scan.host, conf / "recoll.conf") or "", re.M)
    home = str(scan.host.home)
    return [d.replace("~", home, 1) if d.startswith("~") else d for d in (m.group(1).split() if m else [])]


@register
class Indexers(Check):
    id = "desk.indexers"
    FINDING = "indexes_outside_home"
    UNENCRYPTED = "index_on_unencrypted_disk"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, content, basic, left, outside = scan.host, [], [], [], [], []
        baloo_index = scan.paths.data_home / "baloo" / "index"
        if isfile(baloo_index) or installed(host, "balooctl", "balooctl6") or isfile(scan.paths.config_home / "baloofilerc"):
            enabled = ini.truthy(scan.kde.get("baloofilerc", "Basic Settings", "Indexing-Enabled"))
            only_names = ini.truthy(scan.kde.get("baloofilerc", "General", "only basic indexing"))
            enabled = True if enabled is None else enabled          # KDE's default is on
            size = human_size(baloo_index.stat().st_size) if isfile(baloo_index) else "none"
            ev.append(Evidence.val("Baloo", ("off" if not enabled else "file names only" if only_names else
                                             "file contents") + f", index {size}"))
            if enabled and not only_names:
                content.append("Baloo")
                folders = (scan.kde.get("baloofilerc", "General", "folders[$e]")
                           or scan.kde.get("baloofilerc", "General", "folders") or "")
                outside += _outside_home(scan, folders.split(","))
            elif enabled:
                basic.append("Baloo")
            elif isfile(baloo_index):         # off, but what it indexed is still there
                left.append("Baloo")
        cmd = scan.gnome.indexer_command()
        if cmd:
            name = "LocalSearch" if cmd == "localsearch" else "Tracker"
            r = host.run(cmd, "status")
            m = re.search(r"Currently indexed:\s*([\d,]+)\s*files", r.stdout) if r.ok else None
            store = Tally()
            for sub in ("tracker3/files", "localsearch"):
                store += tally(scan.paths.cache_home / sub)
            recursive = scan.gnome.gsettings(INDEXER_SCHEMA, "index-recursive-directories")
            single = scan.gnome.gsettings(INDEXER_SCHEMA, "index-single-directories")
            removable = scan.gnome.gsettings(INDEXER_SCHEMA, "index-removable-devices") is True
            # no folders: it indexes nothing, and drops what it had indexed from them (tested with LocalSearch 3.11:
            # its count went to 0, and neither the words nor the file names were left in its database files)
            no_folders = recursive == [] and single == [] and not removable
            indexed = int(m.group(1).replace(",", "")) if m else None
            ev.append(Evidence.val("GNOME LocalSearch" if cmd == "localsearch" else "Tracker",
                                   ("no folders" if no_folders else f"{m.group(1)} files indexed" if m else
                                    "running" if r.ok else "installed") + f", database {human_size(store.bytes)}"))
            if r.ok and not no_folders:
                content.append(name)
                if removable:
                    outside.append("removable drives")
                outside += _outside_home(scan, recursive if isinstance(recursive, list) else [])
            elif (not r.ok and store.bytes) or (r.ok and indexed):   # not running now, or files still counted
                left.append(name)
        recoll = recoll_index(scan)
        if recoll is not None:
            conf, size = recoll
            ev.append(Evidence.val("Recoll", f"file contents, index {human_size(size)}"))
            content.append("Recoll")
            outside += _outside_home(scan, recoll_topdirs(scan, conf))
        if not ev:
            return absent("No file indexer is installed.")
        findings = {self.FINDING: bool(content and outside)}
        if not content and not left:
            findings[self.UNENCRYPTED] = False
            return passed("File search indexes file names only, not their contents." if basic else
                          "File indexing is off.", *ev, findings=findings)
        from .encryption import storage_of
        fde = scan.context["fde"]
        # the index is in the home folder: is that encrypted? ('partial' depends on where home is)
        protected = {"none": False, "home": True, "full": True}.get(fde) if fde != "partial" else None
        if protected is None:
            protected = storage_of(scan, str(host.home)).encrypted
        findings[self.UNENCRYPTED] = None if protected is None else not protected
        notes = [Note("risk", "What the index holds",
                      "The words of every document it could read in the folders it covers, and details such as "
                      "authors and where photos were taken. Anything running as you can search all of it at once, "
                      "backups of your home folder can take it along, and the words of a document you delete can "
                      "stay in it for a while." + (" On an unencrypted disk, so can anyone who has the disk."
                                                    if protected is False else ""))]
        if content and outside:
            ev.append(Evidence.val("Also indexes", ", ".join(dict.fromkeys(outside))[:200]))
            return failed(f"{' and '.join(content)} copies the text of files on removable drives or other volumes into "
                          "its index in your home folder, where it stays after the drive is gone.", *ev,
                          notes=notes, findings=findings)
        disk = " on an unencrypted disk" if protected is False else ""
        if content:
            return warned(f"{' and '.join(content)} keeps a searchable copy of the words inside your documents{disk}.",
                          *ev, notes=notes, findings=findings)
        return warned(f"Indexing is off, but the index {' and '.join(left)} made is still there{disk}, with the words "
                      "of the documents it read.", *ev, notes=notes, findings=findings)


# the files a clipboard manager keeps its history in
CLIPBOARD_FILES = re.compile(r"^(.*\.(dat|db|sqlite|lst|xml|txt|json))$|^textsrc$|^history", re.I)

CLIPBOARD_STORES = (
    ("GPaste", "data", "gpaste"),
    ("Clipman (XFCE)", "cache", "xfce4/clipman"),
    ("Clipboard Indicator (GNOME extension)", "cache", "clipboard-indicator@tudmotu.com"),
    ("Pano (GNOME extension)", "data", "pano@elhan.io"),
    ("Diodon", "data", "diodon"),
)

# Klipper, KDE's clipboard manager: on Plasma 6 a library inside plasmashell, loaded by the Clipboard applet
# (in the system tray); its history is ~/.local/share/klipper/history3.sqlite (with -wal, -shm) and a data/
# folder of what was copied (Plasma 5: history2.lst)
KLIPPER_APPLET = "org.kde.plasma.clipboard"


@dataclass
class Klipper:
    folder: Path
    files: Tally
    on: bool                # Plasma runs it (its applet is on), or a klipper process does
    plasma6: bool
    keep: bool              # KeepClipboardContents: history kept across sessions (the default)

    @property
    def records(self) -> bool:
        """It keeps what is copied on disk. Plasma 6's Klipper writes every copy to its database as it is
        made, whatever KeepClipboardContents says: that only empties it when Klipper starts (tested on Plasma
        6.7.5). VERIFY on Plasma 5: that with it off, history2.lst is never written."""
        return self.on and (self.plasma6 or self.keep)


def klipper(scan: Scan) -> Klipper:
    folder = scan.paths.data_home / "klipper"
    keep = ini.truthy(scan.kde.get("klipperrc", "General", "KeepClipboardContents")) is not False
    return Klipper(folder, tally(folder), scan.kde.applet(KLIPPER_APPLET).on or "klipper" in processes(scan.host),
                   (scan.kde.major or 0) >= 6 or isfile(folder / "history3.sqlite"), keep)


# CopyQ: copies go into one tab (Options/clipboard_tab), kept in copyq_tab_<name in base64>.dat unless the
# tab's "Store items" is off ([Tabs] N\store_items=false, a QSettings array in copyq.conf); items over 1 KB
# are files under its data folder's items/, shared by every tab. With storing off, CopyQ deletes the tab's
# file when it starts and those items when it quits (tested with CopyQ 16). Other tabs are the user's own.
# The tab files are beside copyq.conf up to CopyQ 16 and in the data folder from 17, which moves them there
# the first time it starts (its migrateDataFiles): both places are read, since either version may be the
# one that last ran (17.0.0 from Flathub tested on Mint 22.3: the fix applied and reverted). A tab that isn't
# stored still has a file while CopyQ runs, made when the tab is loaded: four zero bytes, a count of no items
# (seen with 16 and 17). That is no history: counted as nothing, or the check would fail again after its own fix.
COPYQ_FLATPAK = "com.github.hluk.copyq"


@dataclass
class CopyQ:
    config: Path            # the folder of copyq.conf
    data: Path              # its data folder (items/)
    text: str | None        # copyq.conf
    tab: str | None         # the tab copies go into (None: CopyQ doesn't keep them)
    stores: bool            # that tab is kept on disk
    tab_files: list[Path]   # that tab's files on the disk now: beside copyq.conf (to CopyQ 16), in the data folder (17)
    tab_bytes: int
    others: bool            # other tabs keep files of their own
    items: list[Path]       # files in items/

    @property
    def records(self) -> bool:
        return self.stores or self.tab_bytes > 0


def copyq_tabs(conf: dict) -> dict[str, dict[str, str]]:
    """copyq.conf's [Tabs] array: {tab name: its properties}."""
    return {ini.qsettings_value(e["name"]): e for e in ini.qsettings_array(conf, "Tabs") if e.get("name")}


def copyq_clipboard_tab(conf: dict) -> str | None:
    """The tab copies go into. Unset, it is CopyQ's default, "&clipboard" in the user's language, which is the
    first tab CopyQ made."""
    options = conf.get(("Options",), {})
    if "clipboard_tab" in options:
        return ini.qsettings_value(options["clipboard_tab"]) or None
    tabs = ini.qsettings_list(options.get("tabs", ""))
    return "&clipboard" if "&clipboard" in tabs or not tabs else tabs[0]


def copyq_tab_file(folder: Path, tab: str) -> Path:
    return folder / ("copyq_tab_" + base64.b64encode(tab.encode()).decode().replace("/", "-") + ".dat")


def _copyq_holds_items(f: Path) -> bool:
    """A tab's file with something in it: not the four zero bytes of a tab with no items."""
    try:
        if not isfile(f) or f.is_symlink():
            return False
        return f.lstat().st_size > 4 or bool(f.read_bytes().strip(b"\0"))
    except OSError:
        return True                 # there and unreadable: not known to be empty


def copyq(scan: Scan) -> list[CopyQ]:
    """Every CopyQ of this user's, native and Flatpak, that has run."""
    out = []
    places = [(scan.paths.config_home / "copyq", scan.paths.data_home / "copyq" / "copyq")]
    app = scan.paths.flatpak_root / COPYQ_FLATPAK
    places.append((app / "config" / "copyq", app / "data" / "copyq" / "copyq"))
    for config, data in places:
        text = read_text(scan.host, config / "copyq.conf")
        dats = [f for folder in (config, data) for f in children(folder)
                if f.name.startswith("copyq_tab_") and f.name.endswith(".dat")]
        if text is None and not dats:
            continue
        conf = ini.parse(text or "")
        tab = copyq_clipboard_tab(conf)
        mine = [copyq_tab_file(folder, tab) for folder in (config, data)] if tab else []
        stores = tab is not None and ini.truthy(copyq_tabs(conf).get(tab, {}).get("store_items")) is not False
        tab_files = [f for f in mine if _copyq_holds_items(f)]
        out.append(CopyQ(config, data, text, tab, stores, tab_files, sum(f.lstat().st_size for f in tab_files),
                         any(f not in mine for f in dats), files_under(data / "items")[0]))
    return out


@register
class ClipboardHistory(Check):
    id = "desk.clipboard_history"

    def detect(self, scan: Scan) -> Outcome:
        ev, found = [], []
        k = klipper(scan)
        if k.records:
            found.append("Klipper")
            ev.append(Evidence.val("Klipper", ("on: what you copy is written to disk as you copy it"
                                               if k.plasma6 else "on, saving its history across sessions")
                                   + (f" ({k.files.describe()})" if k.files.files else "")))
        elif k.files.files and k.files.bytes:
            found.append("Klipper")
            ev.append(Evidence.val("Klipper", ("history isn't kept across sessions, but" if k.on else "off, but")
                                   + f" its old history is still on disk ({k.files.describe()})"))
        elif k.on:
            ev.append(Evidence.val("Klipper", "history isn't kept across sessions"))
        for q in copyq(scan):
            label = "CopyQ" + (" (Flatpak)" if COPYQ_FLATPAK in q.config.parts else "")
            if q.stores:
                found.append("CopyQ")
                ev.append(Evidence.val(label, f"saves what you copy to disk (its tab \"{q.tab}\")"
                                       + (f", {human_size(q.tab_bytes)} so far" if q.tab_bytes else "")))
            elif q.tab_bytes:
                found.append("CopyQ")
                ev.append(Evidence.val(label, f"keeps its history in memory, but its old file is still on disk "
                                              f"({human_size(q.tab_bytes)})"))
            else:
                ev.append(Evidence.val(label, "keeps its history in memory only" if q.tab else "doesn't keep what you copy"))
        for label, kind, rel in CLIPBOARD_STORES:
            base = {"data": scan.paths.data_home, "config": scan.paths.config_home, "cache": scan.paths.cache_home}[kind]
            t = tally(base / rel, pattern=CLIPBOARD_FILES)
            if t.files and t.bytes:
                found.append(label)
                ev.append(Evidence.val(label, t.describe()))
        if found:
            return failed(f"Clipboard history is saved to disk by {', '.join(dict.fromkeys(found))}.", *ev)
        return passed("No clipboard history is saved to disk.", *ev)


@register
class Zeitgeist(Check):
    id = "desk.zeitgeist"

    def detect(self, scan: Scan) -> Outcome:
        db = scan.paths.data_home / "zeitgeist" / "activity.sqlite"
        running = "zeitgeist-daemon" in processes(scan.host) or "zeitgeist-datah" in processes(scan.host)
        if not isfile(db) and not running:
            return absent("Zeitgeist isn't in use.")
        ev = [Evidence.val("Activity log", human_size(db.stat().st_size) if isfile(db) else "none"),
              Evidence.val("Daemon", "running" if running else "not running")]
        return failed("Zeitgeist keeps a log of the files and apps you use.", *ev)


@register
class GvfsMetadata(Check):
    id = "desk.gvfs_metadata"

    def detect(self, scan: Scan) -> Outcome:
        d = scan.paths.data_home / "gvfs-metadata"
        if not isdir(d):
            return absent("No GVFS metadata.")
        mm = MemoryMount(scan, "gvfs-metadata", d)
        note = mm.why_not_mounted(scan)
        t = tally(d)
        if mm.in_memory:
            return passed("GVFS metadata is kept in memory and forgotten at every boot.",
                          Evidence.val("Metadata", t.describe()), Evidence.val("Kept in", "memory (tmpfs)"))
        if not t.files:
            return passed("GVFS metadata is empty.", notes=[note] if note else [])
        return failed("GVFS keeps per-file metadata (such as where you stopped reading a PDF) for the files you open.",
                      Evidence.val("Metadata", t.describe()), notes=[note] if note else [])


IMAGE = re.compile(r"\.(png|jpe?g|webp|avif|webm|mp4|mkv|gif)$", re.I)       # screenshots and screen recordings
SCREENSHOT_DIR = re.compile(r"screen ?shots?|screencasts?|recordings?", re.I)


def screenshot_dirs(scan: Scan) -> list[Path]:
    """Folders that hold only screenshots and screen recordings: Pictures/Screenshots and Videos/Screencasts (GNOME,
    Cinnamon, Spectacle), under the names Spectacle translated them to ([ImageSave] translatedScreenshotsFolder,
    [VideoSave] translatedScreencastsFolder, tested with Spectacle on Plasma 6.7), and Spectacle's own save folders when
    named like one (never Pictures, Videos or the home itself)."""
    host = scan.host
    pictures = xdg_user_dir(host, scan.paths, "PICTURES") or host.home / "Pictures"
    videos = xdg_user_dir(host, scan.paths, "VIDEOS") or host.home / "Videos"
    out = [pictures / "Screenshots", pictures / "Screenshot", videos / "Screencasts"]
    for group, key, base in (("ImageSave", "translatedScreenshotsFolder", pictures),
                             ("VideoSave", "translatedScreencastsFolder", videos)):
        name = scan.kde.get("spectaclerc", group, key)
        if name and "/" not in name and base / name not in out:
            out.append(base / name)
    for group, key in (("ImageSave", "imageSaveLocation"), ("General", "defaultSaveLocation"),
                       ("VideoSave", "videoSaveLocation")):
        loc = scan.kde.get("spectaclerc", group, key)
        if loc:
            d = Path(uri_path(loc) or loc)
            if SCREENSHOT_DIR.search(d.name) and d not in (pictures, videos, host.home) and d not in out:
                out.append(d)
    return out


@register
class Screenshots(Check):
    id = "desk.screenshots"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        pictures = xdg_user_dir(host, scan.paths, "PICTURES") or host.home / "Pictures"
        dirs = set(screenshot_dirs(scan))
        spectacle = (scan.kde.get("spectaclerc", "ImageSave", "imageSaveLocation")           # Plasma 6 (VERIFY)
                     or scan.kde.get("spectaclerc", "General", "defaultSaveLocation"))      # Plasma 5
        if spectacle:
            dirs.add(Path(uri_path(spectacle) or spectacle))
        t = Tally()
        for d in dirs:
            t += tally(d, pattern=IMAGE, max_depth=2)
        rule = _expiry(scan, "screenshots")
        expires = re.search(r":(\d+)d\s*$", rule or "", re.M)
        t += tally(pictures, pattern=re.compile(r"^(Screenshot|Screen ?shot|Bildschirmfoto|Capture).*\.(png|jpe?g)$", re.I),
                   max_depth=0)
        if not t.files:
            return passed("No screenshots or screen recordings are piling up.")
        age = int((time.time() - (t.oldest or time.time())) / 86400)
        what = f"{t.files} screenshot{'s and screen recordings are' if t.files > 1 else ' or screen recording is'} kept"
        if expires:
            return passed(f"{what}, each for at most {expires.group(1)} days.",
                          Evidence.val("Screenshots and recordings", t.describe()),
                          Evidence.val("Deleted after", f"{expires.group(1)} days (a rule of this app's, daily)"))
        return warned(f"{what}; the oldest is {age} day{'' if age == 1 else 's'} old.",
                      Evidence.val("Screenshots and recordings", t.describe()), Evidence.val("Oldest", f"{age} days"))


@register
class GnomeAppUsage(Check):
    id = "desk.gnome_app_usage"

    def detect(self, scan: Scan) -> Outcome:
        state = scan.paths.data_home / "gnome-shell" / "application_state"
        if not scan.context.desktop.is_gnome and not isfile(state):
            return absent("Not a GNOME session.")
        remember = scan.gnome.gsettings("org.gnome.desktop.privacy", "remember-app-usage")
        ev = [Evidence.val("Remember app usage", remember), Evidence.val("Usage file", "present" if isfile(state) else "none")]
        if remember is None and scan.context.desktop.is_gnome:
            return unknown("Couldn't read GNOME's app usage setting.", *ev)
        if remember or isfile(state):
            return failed("GNOME records which apps you use and how often.", *ev)
        return passed("GNOME doesn't record app usage.", *ev)


XFCE_SESSION = "xfce4-session"


def xfce_session_version(host) -> tuple[int, ...] | None:
    r = host.run("xfce4-session", "--version")
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", r.stdout) if r.ok else None
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


@dataclass
class XfceSession:
    """Xfce's session manager (xfce4-session, read from its own source): at logout it saves the session when
    /general/SaveOnExit is on (unset: on before 4.19, where the logout dialog's "Save session for future logins" box
    takes it as its default; off from 4.19), into ~/.cache/sessions/xfce4-session-HOST:DISPLAY; and, when the logout
    dialog is shown (/general/PromptOnLogout, on by default) with /general/ShowScreenshots (on by default), it keeps
    a screenshot of the whole screen, ~/.cache/sessions/thumbs-DISPLAY/SESSION.png."""
    saves: bool | None
    screenshots: bool
    saved: list[Path]
    thumbs: list[Path]


def xfce_session(scan: Scan) -> XfceSession:
    host = scan.host

    def get(prop: str) -> str | None:
        r = host.run("xfconf-query", "-c", XFCE_SESSION, "-p", prop)
        return r.stdout.strip().lower() if r.ok else None
    save, shots, prompt = get("/general/SaveOnExit"), get("/general/ShowScreenshots"), get("/general/PromptOnLogout")
    version = xfce_session_version(host)
    saves = save == "true" if save is not None else None if version is None else version < (4, 19)
    cache = scan.paths.cache_home / "sessions"
    saved = [f for f in children(cache) if f.name.startswith("xfce4-session-") and isfile(f)]
    thumbs = [f for d in children(cache) if d.name.startswith("thumbs-") and isdir(d) for f in children(d) if isfile(f)]
    return XfceSession(saves, shots != "false" and prompt != "false", saved, thumbs)


@register
class SessionRestore(Check):
    id = "desk.session_restore"

    def detect(self, scan: Scan) -> Outcome:
        d = scan.context.desktop
        if d.is_kde:
            mode = scan.kde.get("ksmserverrc", "General", "loginMode") or "restorePreviousLogout"
            ev = [Evidence.val("Plasma login mode", mode)]
            if mode == "emptySession":
                return passed("Plasma starts with an empty session.", *ev)
            return failed("Plasma reopens the apps (and often documents) from the last session.", *ev)
        names = set(d.names)
        if "xfce" in names:
            return self._xfce(scan)
        schema = "org.cinnamon.SessionManager" if names & {"x-cinnamon", "cinnamon"} else \
            "org.mate.session" if "mate" in names else "org.gnome.SessionManager" if d.is_gnome else None
        if schema is None:
            return absent(f"Session restore isn't checked on {d.label}.")
        save = scan.gnome.gsettings(schema, "auto-save-session")
        if save is None:
            return unknown("Couldn't read the session manager's settings.")
        if save:
            return failed("The session is saved and restored at login.", Evidence.val("auto-save-session", True))
        return passed("Each login starts with an empty session.", Evidence.val("auto-save-session", False))

    def _xfce(self, scan: Scan) -> Outcome:
        if not scan.host.runner.which("xfconf-query"):
            return unknown("Couldn't read Xfce's session settings: xfconf-query isn't installed.")
        x = xfce_session(scan)
        ev = [Evidence.val("Save the session at logout", "unknown" if x.saves is None else x.saves),
              Evidence.val("Screenshot of the screen at logout", x.screenshots),
              Evidence.count("Saved sessions", len(x.saved)), Evidence.count("Logout screenshots kept", len(x.thumbs))]
        problems = []
        if x.saves or x.saved:
            problems.append("saves the session at logout and reopens its apps at login" if x.saves else
                            "keeps sessions saved before")
        if x.screenshots or x.thumbs:
            problems.append("keeps a screenshot of the whole screen from each logout (~/.cache/sessions)")
        if problems:
            return failed(f"Xfce {' and '.join(problems)}.", *ev)
        if x.saves is None:
            return unknown("Couldn't tell whether Xfce saves the session at logout.", *ev)
        return passed("Each login starts with an empty session, and no logout screenshots are kept.", *ev)


# Dolphin (24.08 and later; 26.08 tested) keeps a folder's view settings in an extended attribute of the folder itself,
# KFileMetaData's user.kde.fm.viewproperties#1, and a .directory file only where the filesystem has none (its source)
DOLPHIN_ATTRIBUTE = "user.kde.fm.viewproperties#1"


def view_attributes(top: Path, max_depth: int = 3, limit: int = 5000) -> int:
    """Folders under `top` (not following links, not leaving its filesystem) carrying Dolphin's view settings."""
    try:
        dev = top.stat().st_dev
    except OSError:
        return 0
    n, seen, stack = 0, 0, [(top, 0)]
    while stack and seen < limit:
        d, depth = stack.pop()
        seen += 1
        try:
            os.getxattr(d, DOLPHIN_ATTRIBUTE, follow_symlinks=False)
            n += 1
        except OSError:
            pass
        if depth < max_depth:
            for p in children(d):
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
                    stack.append((p, depth + 1))
    return n


@register
class FolderViewRecords(Check):
    id = "desk.folder_view_records"

    def detect(self, scan: Scan) -> Outcome:
        views = tally(scan.paths.data_home / "dolphin" / "view_properties")
        on_drives, tagged = Tally(), 0
        for m in storage_mounts(scan.host):
            if m.target.startswith(REMOVABLE_ROOTS):
                on_drives += tally(scan.host.sys_path(m.target), pattern=re.compile(r"^\.directory$"), max_depth=3,
                                   limit=5000)
                tagged += view_attributes(scan.host.sys_path(m.target))
        if not views.files and not on_drives.files and not tagged and not installed(scan.host, "dolphin"):
            return absent("Dolphin isn't in use.")
        ev = [Evidence.val("Dolphin view records", views.describe()),
              Evidence.count(".directory files on removable drives", on_drives.files),
              Evidence.count("Folders on removable drives with Dolphin's view settings attached", tagged)]
        if views.files or on_drives.files or tagged:
            return failed("Dolphin keeps a record of folders you've opened (including on removable drives).", *ev)
        return passed("No folder view records.", *ev)


@register
class FileManagerActions(Check):
    id = "desk.file_manager_actions"

    def detect(self, scan: Scan) -> Outcome:
        from ..tools import integration as I
        entries = I.file_manager_entries(scan.paths.data_home, I.program(scan.host.environ))
        managers = sorted({e.manager for e in entries if installed(scan.host, e.program)})
        if not managers:
            return absent("None of the file managers it can add to (Nemo, Dolphin, Nautilus) is installed.")
        ev, missing, stale = [], [], []
        for m in managers:
            mine = [e for e in entries if e.manager == m]
            have = [read_text(scan.host, e.path) for e in mine]
            state = "set up" if all(h == e.content for h, e in zip(have, mine)) else \
                "not set up" if not any(have) else "from another copy of the app"
            ev.append(Evidence.val(m, state))
            (missing if state == "not set up" else stale if state != "set up" else []).append(m)
        if missing and len(missing) == len(managers):
            return warned(f"Not set up: \"Verify download…\" and \"Remove metadata…\" in {' and '.join(managers)}'s "
                          "right-click menu.", *ev)
        if missing or stale:
            return warned(f"Not set up for {', '.join(missing + stale)}: Set up… writes the entries for this copy of "
                          "the app.", *ev)
        return passed(f"\"Verify download…\" and \"Remove metadata…\" are in {' and '.join(managers)}'s right-click "
                      "menu.", *ev)


@register
class EphemeralFolder(Check):
    id = "desk.ephemeral_folder"

    def detect(self, scan: Scan) -> Outcome:
        from .guides.desktop import memory_leaks_to_disk
        mm = MemoryMount(scan, "ephemeral")
        leaks = memory_leaks_to_disk(scan)
        notes = [Note("risk", "Memory can still reach the disk", " ".join(leaks),
                      ("enc.swap_persistent", "enc.swap_unencrypted"))] if leaks else []
        if mm.in_memory:
            o = mm.options
            return passed("~/Ephemeral is kept in memory.",
                          Evidence.val("Size", o.get("size", "?")),
                          Evidence.val("Programs can run from it", "no" if "noexec" in o else "yes"),
                          Evidence.val("Emptied", "at logout and every reboot" if mm.until == "logout" else "at every reboot"),
                          notes=notes)
        note = mm.why_not_mounted(scan)
        if note:
            return warned("~/Ephemeral is set up but isn't in memory now.", notes=[note] + notes)
        return warned("Not set up: an optional folder kept in memory, for files that shouldn't outlive the task.",
                      notes=[Note("info", "What it is for",
                                  "Downloads, scans and working copies saved in ~/Ephemeral are never written to the "
                                  "disk, and are gone after a reboot (or a logout, if you choose).")] + notes)
