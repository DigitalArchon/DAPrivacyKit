"""Applications (app.*)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .. import ini
from ..host import Unreadable
from ..model import Evidence, Note, Outcome
from ..paths import Base
from . import Check, Scan, register
from ._util import (Tally, absent, children, failed, human_size, installed, isdir, isfile, mode_of, mozilla_profiles,
                    needs_root, passed, read_json, read_text, sqlite_count, tally, unknown, warned)
from .auth import SKIP_DIRS


def _first(scan: Scan, kind: Base, rel: str, flatpak=(), snap=()) -> list:
    return scan.paths.locate(kind, rel, flatpak=flatpak, snap=snap)


@register
class PhotoDbs(Check):
    id = "app.photo_dbs"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, faces = scan.host, [], 0
        for loc in _first(scan, Base.CONFIG, "digikamrc", flatpak=["org.kde.digikam"]):
            folder = ini.get(ini.parse(read_text(host, loc.path) or "", kde=True), "Database Settings", "Database Name")
            if folder:
                for name in ("digikam4.db", "recognition.db", "thumbnails-digikam.db", "similarity.db"):
                    p = Path(folder) / name
                    if isfile(p):
                        ev.append(Evidence.val(f"digiKam {name}", human_size(p.stat().st_size)))
                faces += sqlite_count(Path(folder) / "recognition.db", "SELECT count(*) FROM Identities") or 0
        for loc in _first(scan, Base.DATA, "shotwell/data/photo.db", flatpak=["org.gnome.Shotwell"]):
            ev.append(Evidence.val("Shotwell library", human_size(loc.path.stat().st_size)))
            faces += sqlite_count(loc.path, "SELECT count(*) FROM FaceTable", optional=True) or 0   # face detection builds
        for loc in _first(scan, Base.CACHE, "gthumb", flatpak=["org.gnome.gThumb"]):
            ev.append(Evidence.val("gThumb cache", tally(loc.path).describe()))
        if not ev:
            return absent("No digiKam, Shotwell or gThumb data.")
        notes = []
        if faces:
            ev.append(Evidence.count("Named faces", faces))
            notes.append(Note("risk", "Face recognition data is stored",
                              "The photo manager keeps the names of people it has recognised; anyone who copies the "
                              "library gets them too."))
        return failed("Photo manager databases hold your library's index" + (" and face recognition data." if faces
                      else "."), *ev, notes=notes)


# (label, base, rel, flatpak id, snap name)
MESSENGERS = (
    ("Signal", Base.CONFIG, "Signal", "org.signal.Signal", "signal-desktop"),
    ("Telegram", Base.DATA, "TelegramDesktop", "org.telegram.desktop", "telegram-desktop"),
    ("Discord", Base.CONFIG, "discord", "com.discordapp.Discord", "discord"),
    ("Slack", Base.CONFIG, "Slack", "com.slack.Slack", "slack"),
    ("Element", Base.CONFIG, "Element", "im.riot.Riot", "element-desktop"),
    ("Evolution", Base.DATA, "evolution", "org.gnome.Evolution", None),
    ("Geary", Base.DATA, "geary", "org.gnome.Geary", None),
)


@register
class MessengersMail(Check):
    id = "app.messengers_mail"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, plain_key, total = scan.host, [], [], 0
        for label, base, rel, fp, snap in MESSENGERS:
            for loc in scan.paths.locate(base, rel, flatpak=[fp], snap=[snap] if snap else []):
                t = tally(loc.path, limit=20_000)
                total += t.bytes
                where = "" if loc.install == "native" else f" ({loc.install})"
                ev.append(Evidence.val(f"{label}{where}", t.describe()))
                if label == "Signal":
                    cfg = read_json(host, loc.path / "config.json") or {}
                    if cfg.get("key") and not cfg.get("encryptedKey"):
                        plain_key.append(f"Signal{where}")
        for p in mozilla_profiles(host, scan.paths, ("Thunderbird",)):
            t = tally(p.path, limit=20_000)
            total += t.bytes
            ev.append(Evidence.val(p.label, t.describe()))
        if not ev:
            return absent("No desktop messengers or mail clients were found.")
        notes = [Note("info", "Protecting local message stores",
                      "Full-disk encryption protects these when the computer is off. Telegram Desktop can add a "
                      "local passcode; Signal Desktop has no lock of its own. Signal and other Electron apps should "
                      "keep their database key in the keyring: Signal moves it there by itself at its next start "
                      "when a keyring is running and the \"basic\" password store isn't forced.",
                      ("enc.fde_missing", "auth.chromium_basic_store"))]
        if plain_key:
            return failed(f"{' and '.join(plain_key)} keep{'s' if len(plain_key) == 1 else ''} its database key in "
                          "plain text next to the messages.", *ev, notes=notes)
        if total < 1024 * 1024:
            return passed("Messenger and mail apps hold little data here.", *ev, notes=notes)
        return warned("Messages and mail are stored locally by these apps.", *ev, notes=notes)


RESIDUE = re.compile(r"^(\..+\.sw[a-p]|#.+#|.+~)$")


# (folder in the config folder, Flatpak id) of VS Code and its builds
VSCODE_FAMILY = (("Code", "com.visualstudio.code"), ("Code - OSS", None), ("Code - Insiders", None),
                 ("VSCodium", "com.vscodium.codium"))
VSCODE_PROCESSES = ("code", "code-oss", "codium", "code-insiders")


@dataclass
class EditorHistory:
    label: str
    folder: Path            # what is deleted
    owner: Path             # what a running editor holds open
    settings: Path | None   # VS Code's settings.json, where its local history is turned off


def editor_histories(scan: Scan) -> list[EditorHistory]:
    """Copies of files an editor keeps each time they are saved: VS Code's Local History (User/History, on by default:
    every saved version of a file, kept after the file is deleted; workbench.localHistory.enabled) and JetBrains IDEs'
    LocalHistory (~/.cache/JetBrains/<product>/LocalHistory)."""
    out = []
    for rel, fp in VSCODE_FAMILY:
        for loc in scan.paths.config(rel, flatpak=[fp] if fp else []):
            where = "" if loc.install == "native" else f" ({loc.install})"
            out.append(EditorHistory(f"{rel}'s local history{where}", loc.path / "User" / "History", loc.path,
                                     loc.path / "User" / "settings.json"))
    for product in children(scan.paths.cache_home / "JetBrains"):
        if isdir(product / "LocalHistory"):
            out.append(EditorHistory(f"{product.name}'s local history", product / "LocalHistory", product, None))
    return out


@register
class EditorResidue(Check):
    id = "app.editor_residue"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, total = scan.host, [], 0
        for label, p in (("Vim history and registers", host.home / ".viminfo"),
                         ("Neovim history and registers", scan.paths.state_home / "nvim" / "shada")):
            t = tally(p) if isdir(p) else Tally(files=1, bytes=p.stat().st_size) if isfile(p) else Tally()
            if t.files:
                total += t.files
                ev.append(Evidence.val(label, t.describe()))
        for label, p in (("Vim swap files", host.home / ".vim" / "swap"), ("Vim undo files", host.home / ".vim" / "undo"),
                         ("Vim state", scan.paths.state_home / "vim"),
                         ("Neovim swap files", scan.paths.state_home / "nvim" / "swap"),
                         ("Neovim undo files", scan.paths.state_home / "nvim" / "undo"),
                         ("Emacs auto-saves", host.home / ".emacs.d" / "auto-save-list"),
                         ("Kate swap files", scan.paths.data_home / "kate" / "swap")):
            t = tally(p)
            if t.files:
                total += t.files
                ev.append(Evidence.val(label, t.describe()))
        for h in editor_histories(scan):
            t = tally(h.folder, limit=20_000)
            if t.files:
                total += t.files
                ev.append(Evidence.val(h.label, t.describe()))
        unsaved = Tally()
        for rel, fp in VSCODE_FAMILY:
            for loc in scan.paths.config(rel, flatpak=[fp] if fp else []):
                unsaved += tally(loc.path / "Backups", limit=20_000)
        notes = []
        if unsaved.files:
            ev.append(Evidence.val("Unsaved files VS Code keeps (hot exit)", unsaved.describe()))
            notes.append(Note("info", "VS Code keeps unsaved files on the disk",
                              "What you typed into a file and didn't save stays in its Backups folder until you save or "
                              "discard it (\"hot exit\"). It isn't deleted here, since it is work you haven't saved: "
                              "save or close those files in VS Code."))
        stray = Tally()
        stack = [(host.home, 0)]
        while stack:
            d, depth = stack.pop()
            for p in children(d):
                if p.is_symlink():
                    continue
                if isdir(p):
                    if depth < 3 and p.name not in SKIP_DIRS:
                        stack.append((p, depth + 1))
                elif RESIDUE.match(p.name):
                    try:
                        stray.add(p.stat())
                    except OSError:
                        continue
        if stray.files:
            total += stray.files
            ev.append(Evidence.val("Swap and backup files next to documents", stray.describe()))
        if total:
            return failed("Editors left copies and history of edited files behind.", *ev, notes=notes)
        return passed("No editor swap, backup or undo files were found.", *ev, notes=notes)


PICKLIST = re.compile(r"HistoryInfo\['PickList'\]/ItemList/org\.openoffice\.Office\.Histories:HistoryItem\['([^']+)'\]")


@register
class Office(Check):
    id = "app.office"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, found, items = scan.host, [], False, 0
        for loc in scan.paths.config("libreoffice/4/user", flatpak=["org.libreoffice.LibreOffice"], snap=["libreoffice"]):
            found = True
            text = read_text(host, loc.path / "registrymodifications.xcu") or ""
            recent = len(set(PICKLIST.findall(text)))
            backups = tally(loc.path / "backup")
            items += recent + backups.files
            where = "" if loc.install == "native" else f" ({loc.install})"
            ev.append(Evidence.count(f"LibreOffice recent documents{where}", recent))
            ev.append(Evidence.val(f"LibreOffice backup copies{where}", backups.describe()))
        for loc in scan.paths.data("onlyoffice", flatpak=["org.onlyoffice.desktopeditors"]):
            found = True
            t = tally(loc.path, pattern=re.compile(r"recent", re.I))
            items += t.files
            ev.append(Evidence.val("ONLYOFFICE recent list", t.describe()))
        if not found:
            return absent("No LibreOffice or ONLYOFFICE data.")
        if items:
            return failed("Office apps keep a list of recent documents and backup copies.", *ev)
        return passed("Office apps keep no recent documents or backup copies.", *ev)


CELLULOID_FLATPAK = "io.github.celluloid_player.Celluloid"
HARUNA_FLATPAK = "org.kde.haruna"
# Haruna (1.8, its source and tested): recently opened files and where each was left in haruna.db
# (tables recent_files and playback_position: full paths), the last one in haruna.conf [General] LastPlayedFile.
# It saves a position for anything longer than [Playback] MinDurationToSavePosition minutes (1 by default; whether
# it restores it is another setting), and lists MaxRecentFiles (10) recent files, none at 0. 9999 minutes is the
# most its settings page offers: about a week, so positions are never saved.
HARUNA_NEVER = "9999"
# the tables of haruna.db (1.8): the fix deletes the file only while it holds no other
HARUNA_TABLES = ("recent_files", "playback_position")


@dataclass
class Haruna:
    conf: Path
    db: Path
    recent: int
    positions: int
    last: bool
    max_recent: str | None
    min_duration: str | None
    where: str
    only_history: bool = False      # haruna.db holds no table but those two: deleting it loses nothing else


def haruna(scan: Scan) -> list[Haruna]:
    out = []
    for loc in scan.paths.config("haruna", flatpak=[HARUNA_FLATPAK]):
        conf = ini.parse(read_text(scan.host, loc.path / "haruna.conf") or "", kde=True)
        data = (scan.paths.flatpak_root / HARUNA_FLATPAK / "data" / "haruna") if loc.install == "flatpak" \
            else scan.paths.data_home / "haruna"
        db = data / "haruna.db"
        others = sqlite_count(db, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT IN "
                                  f"({', '.join(repr(t) for t in HARUNA_TABLES)}) AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'")
        out.append(Haruna(loc.path / "haruna.conf", db, sqlite_count(db, "SELECT count(*) FROM recent_files") or 0,
                          sqlite_count(db, "SELECT count(*) FROM playback_position") or 0,
                          bool(ini.get(conf, "General", "LastPlayedFile")), ini.get(conf, "General", "MaxRecentFiles"),
                          ini.get(conf, "Playback", "MinDurationToSavePosition"),
                          "" if loc.install == "native" else f" ({loc.install})", others == 0))
    return out


@register
class MediaPlayers(Check):
    id = "app.media_players"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, found, items = scan.host, [], False, 0
        for kind in (Base.STATE, Base.CONFIG):
            for loc in scan.paths.locate(kind, "mpv/watch_later", flatpak=["io.mpv.Mpv"]):
                found = True
                t = tally(loc.path)
                items += t.files
                ev.append(Evidence.count(f"mpv resume points ({host.display(loc.path)})", t.files))
        for loc in scan.paths.config("vlc", flatpak=["org.videolan.VLC"], snap=["vlc"]):
            found = True
            qt = ini.parse(read_text(host, loc.path / "vlc-qt-interface.conf") or "")
            recent = [x for x in (ini.get(qt, "RecentsMRL", "list") or "").split(",") if x.strip()]
            items += len(recent)
            ev.append(Evidence.count("VLC recent media", len(recent)))
        for loc in scan.paths.config("smplayer", flatpak=["info.smplayer.SMPlayer"]):
            found = True
            ini_text = read_text(host, loc.path / "smplayer.ini") or ""
            recent = re.findall(r"^recents\\\d+\\filename=", ini_text, re.M)
            settings = tally(loc.path / "file_settings")
            items += len(recent) + settings.files
            ev.append(Evidence.count("SMPlayer recent and per-file settings", len(recent) + settings.files))
        for loc in scan.paths.config("celluloid/watch_later", flatpak=[CELLULOID_FLATPAK]):
            found = True
            t = tally(loc.path)
            items += t.files
            ev.append(Evidence.count("Celluloid resume points", t.files))
        for h in haruna(scan):
            found = True
            items += h.recent + h.positions + bool(h.last)
            ev.append(Evidence.count("Haruna recent files and resume points" + h.where, h.recent + h.positions + bool(h.last)))
        if not found:
            return absent("No mpv, VLC, SMPlayer, Celluloid or Haruna data.")
        if items:
            return failed("Media players remember what you watched.", *ev)
        return passed("Media players keep no history.", *ev)


@register
class CupsSpool(Check):
    id = "app.cups_spool"

    def stored_at(self, scan: Scan) -> list[str]:
        return ["/var/spool/cups", "/var/cache/cups"]          # the documents and job history; CUPS's own cache

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        if not installed(host, "lpstat", "cupsd") and not isdir(host.sys_path("/etc/cups")):
            return absent("CUPS (printing) isn't installed.")
        try:
            conf = host.read_sys("/etc/cups/cupsd.conf") or ""
        except Unreadable:
            # root-only on Fedora: what it sets can't be told, and CUPS's defaults aren't assumed
            if scan.privileged is None:
                return needs_root("Reading /etc/cups/cupsd.conf")
            return unknown("Couldn't read /etc/cups/cupsd.conf.")
        def directive(name, default):
            m = re.search(rf"^\s*{name}\s+(\S+)", conf, re.M | re.I)
            return m.group(1) if m else default
        files = directive("PreserveJobFiles", "86400")
        history = directive("PreserveJobHistory", "Yes")
        r = host.run("lpstat", "-W", "completed", "-o")
        jobs = len([ln for ln in r.stdout.splitlines() if ln.strip()]) if r.ok else 0
        ev = [Evidence.val("PreserveJobFiles", files + (" (default: one day)" if files == "86400" else "")),
              Evidence.val("PreserveJobHistory", history + (" (default)" if history == "Yes" else "")),
              Evidence.count("Completed jobs CUPS remembers", jobs)]
        keeps = files.lower() not in ("no", "off", "false", "0") or history.lower() not in ("no", "off", "false", "0")
        if keeps:
            return failed("CUPS keeps printed documents and a history of print jobs.", *ev)
        return passed("CUPS doesn't keep printed documents or job history.", *ev)


# Okular keeps where each document was left in docdata (its recently opened documents, [Recent Files] of okularrc,
# are app.kde_recent_files's, with every KDE app's list). Zathura keeps every file it
# opened, with the page, in bookmarks.sqlite's fileinfo table (the sqlite database, its default; tested with
# zathura 0.5), beside the user's own bookmarks and quickmarks; the older plain database is a history file.
OKULAR_FLATPAK = "org.kde.okular"
ZATHURA_FILES = ("bookmarks.sqlite", "history")


def zathura_history(scan: Scan) -> tuple[list[Path], int, int]:
    """(Zathura's database files, documents it remembers, bookmarks and quickmarks the user made in them)."""
    files, docs, marks = [], 0, 0
    for loc in scan.paths.data("zathura", flatpak=["org.pwmt.zathura"]):
        db = loc.path / "bookmarks.sqlite"
        if isfile(db):
            files.append(db)
            docs += sqlite_count(db, "SELECT count(*) FROM fileinfo") or 0
            marks += sum(sqlite_count(db, f"SELECT count(*) FROM {t}", optional=True) or 0 for t in ("bookmarks", "quickmarks"))
        plain = loc.path / "history"
        if isfile(plain):
            files.append(plain)
            docs += len(re.findall(r"^\[", read_text(scan.host, plain) or "", re.M))
        if isfile(loc.path / "bookmarks"):
            marks += len(re.findall(r"^\[", read_text(scan.host, loc.path / "bookmarks") or "", re.M))
    return files, docs, marks


@register
class PdfReaders(Check):
    id = "app.pdf_readers"

    def detect(self, scan: Scan) -> Outcome:
        locs = scan.paths.data("okular/docdata", flatpak=[OKULAR_FLATPAK])
        zfiles, zdocs, _ = zathura_history(scan)
        evince = installed(scan.host, "evince", "atril", "papers")
        if not locs and not zfiles and not evince:
            return absent("Okular, Zathura, Evince, Atril and Papers aren't in use.")
        total = sum(tally(loc.path).files for loc in locs)
        ev = []
        if locs:
            ev.append(Evidence.count("Okular per-document records", total))
        if zfiles:
            ev.append(Evidence.count("Documents Zathura remembers", zdocs))
        notes = [Note("info", "Evince, Atril and Papers use GVFS metadata",
                      "Their reading positions are stored in GVFS metadata, which has its own check.",
                      ("desk.gvfs_metadata",))] if evince else []
        if locs:
            notes.append(Note("info", "Okular's Open Recent list", "It is checked with the other KDE apps' lists of what "
                              "you opened (app.kde_recent_files).", ("app.kde_recent_files",)))
        found = (["Okular"] if total else []) + (["Zathura"] if zdocs else [])
        if found:
            return failed(f"{' and '.join(found)} remember{'s' if len(found) == 1 else ''} the documents you've opened "
                          "and where you stopped.", *ev, notes=notes)
        return passed("PDF readers keep no per-document history.", *ev, notes=notes)


# ------------------------------------------------------------------ KDE apps' own recent lists

# KDE apps keep their own lists of what was opened, beside the shared one (desk.recent_files; KDE Gear 26.08.1,
# KF 6.30, Plasma 6.7.5, tested on CachyOS): apps using KConfigWidgets' KRecentFilesAction keep File1=, Name1= (with
# KConfig's [$e]) under [Recent Files] (or its default name, [RecentFiles]) in <app>rc or <app>staterc, written as a
# file is opened (KolourPaint) or when the app quits (Okular); Ark keeps a QSettings file of its own,
# ~/.local/share/ark/ark_recentfiles, written when it quits; Kate and KWrite keep theirs, with the documents open when
# they last closed, in anonymous.katesession; Gwenview a file for each folder browsed, in recentfolders. None has a
# setting that turns it off. A group marked [$i] (KConfig's Kiosk marker) is never written; an empty read-only folder
# where Ark's, Kate's or KWrite's file goes, or as Gwenview's folder, stops those (all tested: nothing recorded, the
# apps open files as before, no error shown). The marker in the app's own file doesn't last: an app that rewrites its
# file drops an empty group, marker and all (Gwenview at every close, Okular 26.08 when anything else in the file
# changed; tested, the list was back at the next start). It goes in ~/.config/kdedefaults instead, a folder Plasma puts
# in XDG_CONFIG_DIRS beneath the user's own (Plasma 6.7): KConfig honours a group locked in a file there, and never
# writes that file (tested with Gwenview and Okular 26.08 rewriting their own files: nothing listed). Flatpak apps and
# lists kept in a state file (<app>staterc, which KConfig reads alone) can't be locked that way: cleared only.
KDE_RECENT_GROUPS = ("Recent Files", "RecentFiles")
# apps with a KRecentFilesAction list, stopped before they list anything when installed: (name, program, Flatpak id)
KDE_LIST_APPS = (("KolourPaint", "kolourpaint", "org.kde.kolourpaint"), ("Okular", "okular", OKULAR_FLATPAK),
                 ("Gwenview", "gwenview", "org.kde.gwenview"))
# apps with a list of their own: (name, program, Flatpak id, its path under the data folder, a folder of files)
KDE_OWN_LISTS = (("Ark", "ark", "org.kde.ark", "ark/ark_recentfiles", False),
                 ("Gwenview", "gwenview", "org.kde.gwenview", "gwenview/recentfolders", True),
                 ("Kate", "kate", "org.kde.kate", "kate/anonymous.katesession", False),
                 ("KWrite", "kwrite", "org.kde.kwrite", "kwrite/anonymous.katesession", False))
KDE_APP_NAMES = {"kolourpaint": "KolourPaint", "okular": "Okular", "gwenview": "Gwenview", "krita": "Krita",
                 "kdenlive": "Kdenlive", "kile": "Kile", "kate": "Kate", "kwrite": "KWrite", "skanpage": "Skanpage",
                 "kstars": "KStars", "kexi": "Kexi", "calligra": "Calligra", "kmplot": "KmPlot", "kig": "Kig"}


@dataclass
class KdeList:
    app: str
    program: str
    path: Path                  # the settings file, Ark's or Kate's file, or Gwenview's folder
    kind: str                   # kconfig | file | folder
    group: str = ""             # kconfig: the group the list is in
    entries: int = 0
    stopped: bool = False
    install: str = "native"
    lock: Path | None = None    # kconfig: where the lasting lock goes (in ~/.config/kdedefaults); None when it can't

    @property
    def label(self) -> str:
        return self.app + ("" if self.install == "native" else f" ({self.install})")

    @property
    def stoppable(self) -> bool:
        """Whether something lasting stops it (a lock Plasma reads, a read-only folder), not only clearing it."""
        return self.kind != "kconfig" or self.lock is not None


def kde_lock_dir(scan: Scan) -> Path | None:
    """~/.config/kdedefaults, where it is among the folders Plasma's apps read settings from (XDG_CONFIG_DIRS in a
    Plasma 6 session), beneath the user's own; None elsewhere (another desktop, a Flatpak app)."""
    d = scan.paths.config_home / "kdedefaults"
    dirs = [x.rstrip("/") for x in (scan.host.environ.get("XDG_CONFIG_DIRS") or "").split(":")]
    return d if str(d) in dirs or (scan.context.desktop.is_kde and (scan.context.desktop.plasma_major or 6) >= 6) else None


def _locked_beneath(scan: Scan, lock_dir: Path | None, name: str, group: str) -> bool:
    """Whether a file the app reads beneath its own locks the group: in kdedefaults, or the system's (/etc/xdg)."""
    from ..fix import KConfigLock
    for f in ([lock_dir / name] if lock_dir else []) + [scan.host.sys_path(f"/etc/xdg/{name}")]:
        if KConfigLock.state(read_text(scan.host, f), group) == "locked":
            return True
    return False


def _kconfig_entries(text: str, group: str) -> int:
    m = re.search(rf"^\[{re.escape(group)}\](?:\[\$i\])?[ \t]*$\n((?:(?!\[).*\n?)*)", text, re.M)
    return len(re.findall(r"^File\d+(?:\[\$e\])?=\S", m.group(1), re.M)) if m else 0


def _kde_app_installed(scan: Scan, program: str, flatpak_id: str) -> list[str]:
    """Where a KDE app is installed: native, flatpak."""
    out = ["native"] if installed(scan.host, program) else []
    if flatpak_id in scan.paths.flatpak_apps():
        out.append("flatpak")
    return out


def kde_recent_lists(scan: Scan) -> list[KdeList]:
    """Every KDE app's own list of what was opened, and the known apps that would start one (installed, nothing yet)."""
    from ..fix import KConfigLock
    host, paths = scan.host, scan.paths
    out: list[KdeList] = []
    places = [(paths.config_home, "rc", "native"), (paths.state_home, "staterc", "native")]
    for app in paths.flatpak_apps():
        if app.startswith("org.kde."):
            places += [(paths.flatpak_root / app / "config", "rc", "flatpak"),
                       (paths.flatpak_root / app / ".local/state", "staterc", "flatpak")]
    lock_dir = kde_lock_dir(scan)
    for folder, suffix, how in places:
        lasting = how == "native" and suffix == "rc" and lock_dir is not None
        names = {f.name for f in children(folder) if f.name.endswith(suffix) and f.name != "kdeglobals" and f.is_file()}
        if lasting:                         # locked beneath, its own file holding no group (an app drops an empty one)
            names |= {f.name for f in children(lock_dir) if f.name.endswith(suffix) and f.name != "kdeglobals"}
        for fname in sorted(names):
            f = folder / fname
            text = read_text(host, f) or ""
            for group in KDE_RECENT_GROUPS:
                locked = lasting and _locked_beneath(scan, lock_dir, fname, group)
                # a marker in the app's own file doesn't last (it drops it as it rewrites the file): not stopped
                if KConfigLock.state(text, group) == "absent" and not locked:
                    continue
                program = fname[:-len(suffix)]
                out.append(KdeList(KDE_APP_NAMES.get(program, program), program, f, "kconfig", group,
                                   _kconfig_entries(text, group), locked, how, lock_dir / fname if lasting else None))
    for name, program, fid, rcname in ((n, p, f, f"{p}rc") for n, p, f in KDE_LIST_APPS):
        for how in _kde_app_installed(scan, program, fid):
            # one that can't be stopped for good isn't listed before it lists anything
            if not any(x.program == program and x.install == how for x in out) and how == "native" and lock_dir:
                out.append(KdeList(name, program, paths.config_home / rcname, "kconfig", "Recent Files", 0, False, how,
                                   lock_dir / rcname))
    for name, program, fid, rel, folder in KDE_OWN_LISTS:
        wheres = _kde_app_installed(scan, program, fid)
        for loc in paths.locate(Base.DATA, rel, flatpak=[fid], existing=False):
            how = loc.install
            p = loc.path
            if not (p.exists() or how in wheres):
                continue
            item = KdeList(name, program, p, "folder" if folder else "file", install=how)
            if folder and p.is_dir():
                item.entries = sum(1 for f in children(p) if f.is_file())
                item.stopped = not item.entries and not os.access(p, os.W_OK)
            elif not folder and p.is_dir():
                item.stopped = True                     # a folder where the file goes: nothing can write it
            elif p.is_file():
                text = read_text(host, p) or ""
                if program == "ark":
                    m = re.search(r"^files\\size=(\d+)", text, re.M)
                    item.entries = int(m.group(1)) if m else 0
                else:                                   # the session: its Open Recent list, and the documents open
                    item.entries = _kconfig_entries(text, "Recent Files") + len(re.findall(r"^URL=\S", text, re.M))
            out.append(item)
    return out


_LISTED_PATH = re.compile(r"^(?:File\d+|URL|url|files\\\d+\\[^=]*)(?:\[\$e\])?=(.+)$", re.M)


def kde_recent_paths(scan: Scan) -> list[str]:
    """The paths in KDE apps' own lists of what was opened (kde_recent_lists): KConfig's File<n> entries, Kate's and
    Gwenview's url entries, Ark's files array; $HOME and file:// addresses turned into paths. Read here only, never
    kept or shown."""
    from urllib.parse import unquote
    home = str(scan.host.home)
    out = []
    for x in kde_recent_lists(scan):
        files = [f for f in children(x.path) if f.is_file()] if x.kind == "folder" else [x.path]
        for f in files:
            text = read_text(scan.host, f) or ""
            if x.kind == "kconfig":                             # the list's own group only
                m = re.search(rf"^\[{re.escape(x.group)}\](?:\[\$i\])?[ \t]*$\n((?:(?!\[).*\n?)*)", text, re.M)
                text = m.group(1) if m else ""
            for v in _LISTED_PATH.findall(text):
                v = v.strip().strip('"').replace("${HOME}", home).replace("$HOME", home)
                if v.startswith("file://"):
                    v = unquote(v[len("file://"):])
                if v.startswith("/"):
                    out.append(v)
    return out


def kde_activity_count(scan: Scan, prefix: str) -> int | None:
    """How many files under `prefix` KDE's activity manager remembers (its resources database: what each app opened,
    by path); None without the database."""
    db = scan.paths.data_home / "kactivitymanagerd" / "resources" / "database"
    quoted = prefix.replace("'", "''")
    return sqlite_count(db, "SELECT count(*) FROM (SELECT targettedResource FROM ResourceScoreCache UNION SELECT "
                            f"targettedResource FROM ResourceEvent) WHERE substr(targettedResource, 1, {len(prefix)}) = "
                            f"'{quoted}'", optional=True)


@register
class KdeRecentFiles(Check):
    id = "app.kde_recent_files"

    def detect(self, scan: Scan) -> Outcome:
        lists = kde_recent_lists(scan)
        if not lists:
            return absent("No KDE app here keeps a list of the files you open.")
        ev = [Evidence.val(f"{x.label}: {scan.host.display(x.path)}",
                           f"{x.entries} listed" + (", stopped" if x.stopped else "") if x.entries
                           else "stopped" if x.stopped else "nothing listed yet") for x in lists]
        listed = [x for x in lists if x.entries]
        recording = list(dict.fromkeys(x.app for x in lists if not x.stopped and x.stoppable))
        unstoppable = list(dict.fromkeys(x.label for x in lists if not x.stoppable))
        notes = [Note("limitation", "Some lists can only be cleared",
                      f"{', '.join(unstoppable)} keep{'s' if len(unstoppable) == 1 else ''} a list nothing stops from "
                      "outside the app: a Flatpak app reads no settings of yours beneath its own, and a list kept in a "
                      "state file is read alone. Clearing it is all there is; it fills again as you open files.")] \
            if unstoppable else []
        if listed:
            total = sum(x.entries for x in listed)
            return failed(f"{total} {'files and folders' if total != 1 else 'file or folder'} you opened "
                          f"{'are' if total != 1 else 'is'} listed by {', '.join(dict.fromkeys(x.app for x in listed))}.",
                          *ev, notes=notes)
        if recording:
            return warned(f"Nothing listed yet, but {', '.join(recording)} will list the files you open until "
                          f"{'it is' if len(recording) == 1 else 'they are'} stopped.", *ev, notes=notes)
        if not any(x.stoppable for x in lists):
            return passed("Nothing is listed now.", *ev, notes=notes)
        return passed("These KDE apps are stopped from listing the files you open." if not unstoppable else
                      "Nothing is listed, and the apps that can be are stopped from listing the files you open.",
                      *ev, notes=notes)


ELECTRON_CACHES = ("Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache",
                   "Service Worker/CacheStorage", "Service Worker/ScriptCache")
BROWSER_DIRS = frozenset({"google-chrome", "google-chrome-beta", "google-chrome-unstable", "chromium", "BraveSoftware",
                          "microsoft-edge", "vivaldi", "opera"})


@register
class ElectronCaches(Check):
    id = "app.electron_caches"

    def detect(self, scan: Scan) -> Outcome:
        roots = [(d, "native") for d in children(scan.paths.config_home)]
        for app in scan.paths.flatpak_apps():
            roots += [(d, f"flatpak {app}") for d in children(scan.paths.flatpak_root / app / "config")]
        found: list[tuple[str, Tally]] = []
        for d, where in roots:
            if d.name in BROWSER_DIRS or not isdir(d) or not (isdir(d / "GPUCache") or isdir(d / "Code Cache")):
                continue
            t = Tally()
            for c in ELECTRON_CACHES:
                t += tally(d / c, limit=20_000)
            if t.files:
                found.append((d.name + ("" if where == "native" else f" ({where})"), t))
        if not found:
            return absent("No Electron app caches were found.")
        found.sort(key=lambda x: -x[1].bytes)
        total = sum(t.bytes for _, t in found)
        ev = [Evidence.val(name, t.describe()) for name, t in found[:15]]
        return failed(f"{len(found)} Electron app{'s keep' if len(found) > 1 else ' keeps'} {human_size(total)} of "
                      "web caches.", *ev, notes=[Note("info", "Clear caches only while the app is closed",
                                                      "These apps hold their caches open while running.")])


PACKAGE_LOGS = ("/var/log/apt/history.log", "/var/log/dpkg.log", "/var/log/pacman.log", "/var/log/zypp/history",
                "/var/lib/dnf/history.sqlite", "/usr/lib/sysimage/libdnf5/transaction_history.sqlite")


@register
class PackageLogs(Check):
    id = "app.package_logs"

    def detect(self, scan: Scan) -> Outcome:
        ev, everyone = [], []
        for p in PACKAGE_LOGS:
            f = scan.host.sys_path(p)
            if isfile(f):
                rotated = [x for x in children(f.parent) if x.name.startswith(f.name + ".")]
                mode = mode_of(f)
                if mode is not None and mode & 0o004:
                    everyone.append(p)
                ev.append(Evidence.val(p, human_size(f.stat().st_size) + (f", plus {len(rotated)} older" if rotated else "")
                                       + (", readable by every account" if p in everyone else "")))
        if not ev:
            return absent("No package manager logs were found.")
        if everyone:
            return failed("Package manager logs record what was installed and when, and every account on this "
                          "computer can read them.", *ev)
        return failed("Package manager logs record what was installed and when.", *ev)


LO_USER_DATA = re.compile(r'oor:path="/org\.openoffice\.UserProfile/Data"><prop oor:name="(givenname|sn|o|initials)"[^>]*>'
                          r'<value>([^<]+)</value>')
LO_REMOVE_INFO = re.compile(r'oor:path="/org\.openoffice\.Office\.Common/Security/Scripting"><prop oor:name='
                            r'"RemovePersonalInfoOnSaving"[^>]*><value>(true|false)</value>')


def libreoffice_profiles(scan: Scan) -> list:
    return scan.paths.config("libreoffice/4/user", flatpak=["org.libreoffice.LibreOffice"], snap=["libreoffice"])


# GIMP keeps only settings changed from its defaults in gimprc; these three are on by default, so
# an image exported from a phone photo keeps the photo's Exif (GPS included), XMP and IPTC.
# VERIFY: the option names and their default on GIMP 2.10 and 3.0
GIMP_EXPORT_KEYS = ("export-metadata-exif", "export-metadata-xmp", "export-metadata-iptc")
GIMP_PROCESSES = ("gimp", "gimp-2.10", "gimp-2.99", "gimp-3.0", "gimp-3")
_GIMP_VERSION = re.compile(r"^\d+\.\d+$")


def gimp_rcs(scan: Scan) -> list[tuple[str, Path]]:
    """(label, gimprc path) for each GIMP version's settings folder (the file may not exist yet)."""
    out = []
    for loc in scan.paths.config("GIMP", flatpak=["org.gimp.GIMP"], snap=["gimp"]):
        for d in children(loc.path):
            if _GIMP_VERSION.match(d.name) and isdir(d):
                where = "" if loc.install == "native" else f", {loc.install}"
                out.append((f"GIMP {d.name}{where}", d / "gimprc"))
    return out


def gimp_exported(text: str) -> list[str]:
    """The export-metadata options not turned off (a missing one is GIMP's default: on)."""
    return [k for k in GIMP_EXPORT_KEYS if not re.search(rf"^\({re.escape(k)}\s+no\)", text, re.M)]


def git_email(scan: Scan) -> str | None:
    """"own", "noreply" or None (not set): the address commits carry, never the address itself."""
    text = "".join(read_text(scan.host, p) or "" for p in (scan.host.home / ".gitconfig",
                                                           scan.paths.config_home / "git" / "config"))
    email = ini.parse(text).get(("user",), {}).get("email")
    if not email:
        return None
    return "noreply" if re.search(r"no-?reply", email, re.I) else "own"


@register
class SharedFileMetadata(Check):
    id = "app.shared_file_metadata"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, exposed = scan.host, [], []
        tools = [t for t in ("mat2", "exiftool") if installed(host, t)]
        profiles = libreoffice_profiles(scan)
        for loc in profiles:
            text = read_text(host, loc.path / "registrymodifications.xcu") or ""
            named = bool(LO_USER_DATA.search(text))               # whether a name is set, never the name
            m = LO_REMOVE_INFO.search(text)
            strips = bool(m and m.group(1) == "true")
            where = "" if loc.install == "native" else f" ({loc.install})"
            ev.append(Evidence.val(f"LibreOffice{where} user name in documents", "set" if named else "not set"))
            ev.append(Evidence.val(f"LibreOffice{where} removes personal information on saving", "yes" if strips else "no"))
            if named and not strips:
                exposed.append(f"LibreOffice{where} writes your name into every document you save")
        gimps = gimp_rcs(scan)
        for label, rc in gimps:
            on = gimp_exported(read_text(host, rc) or "")
            ev.append(Evidence.val(f"{label} copies a picture's metadata into what it exports",
                                   ", ".join(k.removeprefix("export-metadata-").upper() for k in on) if on else "no"))
            if on:
                exposed.append(f"{label} copies a photo's details, location included, into the images it exports")
        ev.append(Evidence.val("Metadata tools installed", ", ".join(tools) or "none (mat2 is recommended)"))
        notes = [Note("info", "Photos and other files you already have",
                      "Photos carry the camera and often where they were taken; documents carry their author. Tools → "
                      "Remove metadata shows what a file carries and makes a clean copy, and the Outbox "
                      "(app.metadata_outbox) does it for every file you put in it.", ("app.metadata_outbox",))]
        mail = git_email(scan)
        if mail:
            ev.append(Evidence.val("Git commits' email", "a no-reply address" if mail == "noreply" else "your own address"))
        if mail == "own":
            notes.append(Note("info", "Git commits carry your email address",
                              "Every commit records the name and email in your git settings, and anyone who can see the "
                              "repository once it is pushed can read them. Code hosts give you a no-reply address for "
                              "this (GitHub: Settings → Emails); set it with `git config --global user.email ADDRESS`."))
        if not profiles and not gimps:
            return absent("Neither LibreOffice nor GIMP has settings here; Tools → Remove metadata cleans other files.",
                          *ev, notes=notes)
        if exposed:
            return failed("; ".join(exposed) + ".", *ev, notes=notes)
        return passed("LibreOffice and GIMP don't add your name or location to what you save."
                      if profiles and gimps else "LibreOffice doesn't write your name into documents." if profiles
                      else "GIMP doesn't copy photos' details into what it exports.", *ev, notes=notes)


@register
class MetadataOutbox(Check):
    id = "app.metadata_outbox"

    def detect(self, scan: Scan) -> Outcome:
        from ..tools import integration as I
        from ._util import systemctl_state
        units = I.outbox_units(scan.paths.config_home, I.program(scan.host.environ))
        present = {p: read_text(scan.host, p) for p in units}
        mat2 = installed(scan.host, "mat2")
        ev = [Evidence.val("mat2 (which cleans the files)", "installed" if mat2 else "not installed")]
        if not any(present.values()):
            return warned("Not set up: an optional folder, ~/Outbox, that makes clean copies of the files you put in it.",
                          *ev)
        enabled = systemctl_state(scan.host, "is-enabled", f"{I.OUTBOX_UNIT}.path", user=True)
        ev += [Evidence.path("Units", scan.host.display(next(iter(units)).parent)), Evidence.val("Watching ~/Outbox", enabled or "unknown")]
        if any(present[p] != text for p, text in units.items()):
            return warned("The Outbox was set up by another copy or version of the app: Set up… writes it again for "
                          "this one.", *ev)
        if enabled != "enabled":
            return warned("The Outbox is set up but isn't watching ~/Outbox (its path unit is "
                          f"{enabled or 'in an unknown state'}).", *ev)
        if not mat2:
            return warned("The Outbox is set up, but mat2 isn't installed, so it can't clean anything.", *ev)
        return passed("Files put in ~/Outbox are cleaned of metadata into ~/Outbox/Cleaned.", *ev)


@register
class Boxes(Check):
    id = "app.boxes"

    def detect(self, scan: Scan) -> Outcome:
        from ..tools import box as B
        from ..tools import integration as I
        host = scan.host
        boxes = B.every(host)
        if not boxes:
            return warned("Not set up: an optional way to keep an app in a sandbox of its own, with a home folder of "
                          "its own that isn't yours.")
        command = I.program(host.environ)
        ev, wrong = [Evidence.val("Boxes", str(len(boxes)))], []
        net = {"off": "no network", "observed": "its own network, observed", "on": "its usual network"}
        for b in boxes:
            ev.append(Evidence.val(b.name, net[b.network]))
            why = B.problem(host, b)
            if why:
                wrong.append(f"{b.name}: {why}")
            elif read_text(host, B.launcher_path(scan.paths.data_home, b.slug)) != B.launcher_text(b, command):
                wrong.append(f"{b.name}: its menu entry is missing, or starts another copy or version of the app")
        if wrong:
            return warned("; ".join(wrong) + ". Set up… writes it again.", *ev)
        n = len(boxes)
        return passed(f"{n} app{'s are' if n > 1 else ' is'} kept in a Box: a sandbox with a home folder of its own.", *ev)


# ------------------------------------------------------------------ mail: remote content

EVOLUTION_POLICY = {"never": "blocked", "sometimes": "loaded from known contacts", "always": "loaded"}


@register
class MailRemoteContent(Check):
    id = "app.mail_remote_content"

    def detect(self, scan: Scan) -> Outcome:
        from ._util import firefox_prefs
        host, ev, loading, found = scan.host, [], [], False
        for p in mozilla_profiles(host, scan.paths, ("Thunderbird",)):
            found = True
            blocked = firefox_prefs(host, p.path).get("mailnews.message_display.disable_remote_image", True) is not False
            ev.append(Evidence.val(p.label, "remote content blocked" if blocked else "remote content loaded"))
            if not blocked:
                loading.append(p.label)
        if installed(host, "evolution") or scan.paths.data("evolution", flatpak=["org.gnome.Evolution"]):
            found = True
            policy = scan.gnome.gsettings("org.gnome.evolution.mail", "image-loading-policy")
            policy = str(policy).lower() if policy is not None else None
            ev.append(Evidence.val("Evolution", EVOLUTION_POLICY.get(policy or "", "unknown setting")))
            if policy in ("always", "sometimes"):
                loading.append("Evolution")
        if not found:
            return absent("No Thunderbird or Evolution.")
        if loading:
            return failed(f"Remote content in mail is loaded by {', '.join(loading)}: senders learn when and where "
                          "you read their messages.", *ev)
        return passed("Mail clients block remote content.", *ev)


# ------------------------------------------------------------------ what starts at login

SYSTEM_BIN = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
# programs that see a password or a key when you type them: one of the same name earlier on PATH would too
SENSITIVE = frozenset({"sudo", "su", "doas", "pkexec", "ssh", "ssh-add", "scp", "gpg", "gpg2", "passwd", "git",
                       "cryptsetup", "openssl", "pass", "keepassxc-cli", "bw", "op"})
USER_UNIT_DIRS = (".config/systemd/user",)
SYSTEM_UNIT_DIRS = ("/etc/systemd/user", "/usr/lib/systemd/user", "/lib/systemd/user")
PLASMA_SCRIPTS = (".config/autostart-scripts", ".config/plasma-workspace/env", ".config/plasma-workspace/shutdown")
X_SESSION_FILES = (".xprofile", ".xsessionrc")


def _exec_program(cmd: str) -> str:
    """The program a desktop entry's Exec line starts, by name ("env A=1 flatpak run x" -> "flatpak run x")."""
    words = [w for w in cmd.replace('"', " ").split() if not w.startswith("%")]
    while words and (words[0] in ("env", "/usr/bin/env") or "=" in words[0]):
        words.pop(0)
    if not words:
        return "?"
    name = Path(words[0]).name
    if name == "flatpak" and "run" in words:
        rest = [w for w in words[words.index("run") + 1:] if not w.startswith("-")]
        return f"flatpak app {rest[0]}" if rest else name
    return name


@dataclass
class LoginItem:
    item: str               # how it is named in the list and in "new since the last scan"
    what: str               # what it starts, in words
    yours: bool             # added by the user (or an app they ran), not by the system's packages


def autostart_entries(scan: Scan) -> list[LoginItem]:
    """XDG autostart entries the session starts: the user's folder over $XDG_CONFIG_DIRS (same file
    name: the user's wins), less hidden or disabled ones, those for other desktops, and those whose
    TryExec program is missing."""
    host = scan.host
    desktops = {d.lower() for d in (host.environ.get("XDG_CURRENT_DESKTOP") or "").split(":") if d}
    found: dict[str, tuple[Path, bool]] = {}
    for d in reversed(scan.paths.config_dirs()):
        for f in children(host.sys_path(str(d / "autostart"))):
            if f.suffix == ".desktop":
                found[f.name] = (f, False)
    for f in children(scan.paths.config_home / "autostart"):
        if f.suffix == ".desktop":
            found[f.name] = (f, True)
    out = []
    for name, (f, yours) in sorted(found.items()):
        entry = ini.parse(read_text(host, f) or "").get(("Desktop Entry",), {})
        if ini.truthy(entry.get("Hidden")) or ini.truthy(entry.get("X-GNOME-Autostart-enabled")) is False:
            continue
        only = {x.lower() for x in (entry.get("OnlyShowIn") or "").split(";") if x}
        never = {x.lower() for x in (entry.get("NotShowIn") or "").split(";") if x}
        if desktops and ((only and not only & desktops) or never & desktops):
            continue
        try_exec = entry.get("TryExec")
        if try_exec and not (host.sys_path(try_exec).exists() if try_exec.startswith("/") else installed(host, try_exec)):
            continue
        prog = _exec_program(entry.get("Exec") or "")
        label = entry.get("Name") or name
        out.append(LoginItem(host.display(f), f"starts {prog}" + (f" ({label})" if label.lower() != prog.lower() else ""),
                             yours))
    return out


def enabled_user_units(scan: Scan) -> list[LoginItem]:
    """User units wanted by a target the session reaches: links in *.wants and *.requires folders,
    the user's own (~/.config/systemd/user) and the system's (/etc, /usr/lib); units the user
    masked are left out."""
    host = scan.host
    user_root = host.home / USER_UNIT_DIRS[0]
    masked = {f.name for f in children(user_root) if f.is_symlink() and str(f.readlink()) == "/dev/null"}
    out, seen = [], set()
    for root, yours in [(user_root, True)] + [(host.sys_path(d), False) for d in SYSTEM_UNIT_DIRS]:
        for wants in children(root):
            if not wants.name.endswith((".wants", ".requires")) or not isdir(wants):
                continue
            target = wants.name.rsplit(".", 1)[0]
            for unit in children(wants):
                if unit.name in masked or unit.name in seen:
                    continue
                seen.add(unit.name)
                own = unit.name.startswith("daprivacyscanner")
                out.append(LoginItem(f"user unit {unit.name}", f"wanted by {target}"
                                     + (" (this app's own)" if own else ""), yours and not own))
    return out


def crontab_entries(scan: Scan) -> tuple[list[LoginItem], int, bool]:
    """The user's crontab: (its entries, as hashes of their lines: the commands are never shown, they
    can hold passwords; how many run at boot; whether crontab could be read)."""
    import hashlib
    r = scan.host.run("crontab", "-l")
    if r.missing:
        return [], 0, False
    if not r.ok:
        return [], 0, "no crontab" in (r.stderr + r.stdout).lower()
    out, boot = [], 0
    for line in r.stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
            continue
        boot += s.startswith("@reboot")
        out.append(LoginItem(f"crontab entry {hashlib.sha256(s.encode()).hexdigest()[:8]}",
                             "runs at boot" if s.startswith("@reboot") else "runs on a schedule", True))
    return out, boot, True


def path_shadows(scan: Scan) -> tuple[list[Path], list[LoginItem]]:
    """Folders on PATH under home that come before the system's, and the programs in them that take
    the place of a system program of the same name."""
    from .auth import user_path_dirs
    host = scan.host
    path = [p for p in (host.environ.get("PATH") or "").split(":") if p]
    first_system = next((i for i, p in enumerate(path) if p in SYSTEM_BIN), len(path))
    early = [d for d in user_path_dirs(host) if str(d) in path[:first_system]]
    system = set()
    for d in SYSTEM_BIN:
        system |= {f.name for f in children(host.sys_path(d))}
    out = []
    for d in early:
        for f in children(d)[:2000]:
            if f.name in system and not f.name.startswith("."):
                out.append(LoginItem(f"{f.name} on PATH ({host.display(f)})", "takes the place of the system's", True))
    return early, out


@register
class LoginItems(Check):
    id = "app.login_items"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        autostart = autostart_entries(scan)
        units = enabled_user_units(scan)
        cron, boot, cron_read = crontab_entries(scan)
        scripts = [LoginItem(host.display(f), "a script your Plasma session runs", True)
                   for d in PLASMA_SCRIPTS for f in children(host.home / d) if isfile(f)]
        scripts += [LoginItem(host.display(host.home / f), "read by X11 sessions at login", True)
                    for f in X_SESSION_FILES if (read_text(host, host.home / f) or "").strip()]
        early, shadows = path_shadows(scan)
        everything = autostart + units + cron + scripts + shadows
        yours = [i for i in everything if i.yours]
        ev = [Evidence.val(i.item, i.what) for i in yours[:40]]
        if len(yours) > 40:
            ev.append(Evidence.count("More of yours", len(yours) - 40))
        ev += [Evidence.count("Autostart entries from the system's packages", sum(not i.yours for i in autostart)),
               Evidence.count("User services the system enables", sum(not i.yours for i in units))]
        if cron_read:
            ev.append(Evidence.count("Entries in your crontab", len(cron)) if not boot else
                      Evidence.val("Entries in your crontab", f"{len(cron)}, {boot} at boot"))
        if early:
            ev.append(Evidence.val("Your folders on PATH before the system's", ", ".join(host.display(d) for d in early)))
        notes = []
        risky = sorted({i.item.split(" ", 1)[0] for i in shadows} & SENSITIVE)
        if risky:
            notes.append(Note("risk", "Programs that see passwords are replaced",
                              f"{', '.join(risky)} in your own folder run{'' if len(risky) > 1 else 's'} instead of the "
                              "system's. That is how a program that steals your password would hide: if you didn't "
                              "put it there, delete it and change your password."))
        notes.append(Note("info", "New entries are marked",
                          "Each scan remembers a hash of every entry here (not its name), so the next one can mark what "
                          "is new; scheduled scans notify you about new entries."))
        items = [i.item for i in everything]
        if yours:
            return warned(f"{len(yours)} of your own: programs that start by themselves, or run instead of the "
                          "system's.", *ev, notes=notes, items=items)
        return passed("Only the system's own programs start when you log in.", *ev, notes=notes, items=items)


# ------------------------------------------------------------------ apps newer than the checks

@register
class NewerThanChecked(Check):
    id = "app.newer_than_checked"

    def detect(self, scan: Scan) -> Outcome:
        from .. import appversions
        apps = appversions.load()
        have = scan.installed_apps()
        if not have:
            return absent("None of the apps the checks read was found by its package, Flatpak or Snap.")
        ev, newer = [], []
        for app in apps:
            inst = have.get(app.id)
            if inst is None or not app.ahead(inst.version):
                continue
            newer.append(app.name)
            where = "" if not app.data or app.data_found(scan.paths) else "; nothing where the older version kept its data"
            how = "tested with" if app.basis == "tested" else "made for"
            ev.append(Evidence.val(app.name, f"{inst.short} installed, {how} {app.checked_text}{where}"))
        ev.append(Evidence.count("Apps the checks read, installed here", len(have)))
        if newer:
            return warned(f"{', '.join(newer)} {'is' if len(newer) == 1 else 'are'} newer than this version of DA Privacy "
                          "Kit was made for.", *ev)
        return passed("Every app the checks read is a version this app was made for.", *ev)
