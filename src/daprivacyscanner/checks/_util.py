"""Shared pieces for check implementations: outcome shorthands, bounded file counting, running
processes, mounts, systemd state, and where browsers keep their profiles."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..host import FormatChanged, Host, Unreadable
from ..model import Evidence, Note, Outcome, Status
from ..paths import Base, Location, PathResolver

# Walking a directory stops after this many entries: a scan must stay quick on a huge home.
WALK_LIMIT = 50_000


# ------------------------------------------------------------------ outcomes

def passed(summary: str, *evidence: Evidence, notes: Iterable[Note] = (), **kw) -> Outcome:
    return Outcome(Status.PASS, summary, list(evidence), notes=list(notes), **kw)


def failed(summary: str, *evidence: Evidence, notes: Iterable[Note] = (), **kw) -> Outcome:
    return Outcome(Status.FAIL, summary, list(evidence), notes=list(notes), **kw)


def warned(summary: str, *evidence: Evidence, notes: Iterable[Note] = (), **kw) -> Outcome:
    return Outcome(Status.WARN, summary, list(evidence), notes=list(notes), **kw)


def absent(summary: str, *evidence: Evidence, notes: Iterable[Note] = ()) -> Outcome:
    """The thing the check is about isn't on this machine (no Docker, not KDE...)."""
    return Outcome(Status.NOT_APPLICABLE, summary, list(evidence), notes=list(notes))


def unknown(summary: str, *evidence: Evidence, notes: Iterable[Note] = ()) -> Outcome:
    """Couldn't be checked here: its own status, never a pass and never a finding."""
    return Outcome(Status.UNKNOWN, summary, list(evidence), notes=list(notes), partial=True)


def needs_root(what: str, *evidence: Evidence) -> Outcome:
    o = unknown(f"Partial detection: {what} needs administrator access. Scan with administrator access "
                "to check it.", *evidence)
    o.needs_admin = True
    return o


# ------------------------------------------------------------------ data on an encrypted disk

# set by the runner for checks whose modifiers use it (Check.stored_at says where their data is): each such
# modifier is one lower than the severity it would otherwise have, and the result gets ENCRYPTED_DISK_NOTE
ON_ENCRYPTED_DISK = "data_on_encrypted_disk"
ENCRYPTED_DISK_NOTE = Note(
    "info", "Severity lowered by one: this is on an encrypted disk",
    "Disk encryption keeps it safe while the computer is shut down (not asleep: a sleeping computer keeps the "
    "disk's key in memory). While the computer is on and unlocked, malware running as you, or a person who gets "
    "to use the computer, can still read it.", ("kern.suspend_keys_in_ram",))


def on_encrypted_disk(scan, *paths: str | Path) -> bool | None:
    """Whether every one of these paths is on encrypted storage, as the fde context sees it: all of them with
    full-disk encryption, those in the home folder when only it is encrypted (eCryptfs and fscrypt included,
    which the block devices don't show), each one's own filesystem where only some are encrypted. None when it
    can't be told."""
    fde = scan.context["fde"]
    if fde in (None, "none", "full") or not paths:
        return {"none": False, "full": True}.get(fde) if paths else None
    if fde == "home":
        home = str(scan.host.home).rstrip("/") + "/"
        return all((str(p).rstrip("/") + "/").startswith(home) for p in paths)
    from .encryption import storage_of
    states = [storage_of(scan, str(p)).encrypted for p in paths]
    return False if False in states else None if None in states else True


# ------------------------------------------------------------------ files

@dataclass
class Tally:
    files: int = 0
    bytes: int = 0
    truncated: bool = False
    oldest: float | None = None     # mtime
    newest: float | None = None

    def add(self, st: os.stat_result) -> None:
        self.files += 1
        self.bytes += st.st_size
        self.oldest = st.st_mtime if self.oldest is None else min(self.oldest, st.st_mtime)
        self.newest = st.st_mtime if self.newest is None else max(self.newest, st.st_mtime)

    def __iadd__(self, other: "Tally") -> "Tally":
        self.files += other.files
        self.bytes += other.bytes
        self.truncated |= other.truncated
        for attr, fn in (("oldest", min), ("newest", max)):
            a, b = getattr(self, attr), getattr(other, attr)
            setattr(self, attr, b if a is None else a if b is None else fn(a, b))
        return self

    def describe(self) -> str:
        more = "+" if self.truncated else ""
        return f"{self.files}{more} file{'s' if self.files != 1 else ''}, {human_size(self.bytes)}{more}"


def tally(path: Path, limit: int = WALK_LIMIT, pattern: re.Pattern | None = None, max_depth: int = 64) -> Tally:
    """Regular files under `path` (not following symlinks), optionally only names matching
    `pattern`. Stops after `limit` entries and says so."""
    t = Tally()
    seen = 0
    stack = [(path, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            it = os.scandir(d)
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        with it:
            for e in it:
                seen += 1
                if seen > limit:
                    t.truncated = True
                    return t
                try:
                    if e.is_dir(follow_symlinks=False):
                        if depth < max_depth:
                            stack.append((Path(e.path), depth + 1))
                    elif e.is_file(follow_symlinks=False) and (pattern is None or pattern.search(e.name)):
                        t.add(e.stat(follow_symlinks=False))
                except OSError:
                    continue
    return t


def human_size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def isdir(path: Path) -> bool:
    """Path.is_dir() that treats "permission denied" as "no" instead of raising."""
    try:
        return path.is_dir()
    except OSError:
        return False


def isfile(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def children(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir())
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []


def read_text(host: Host, path: Path) -> str | None:
    """A user file's text, or None if missing or unreadable."""
    try:
        return host.read_file(path)
    except Unreadable:
        return None


def read_json(host: Host, path: Path):
    """A JSON file's data; None if missing, unreadable or empty. One that doesn't parse raises FormatChanged: the
    check couldn't read it, which is never a pass."""
    text = read_text(host, path)
    if text is None or not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError as e:
        raise FormatChanged(path, f"it isn't valid JSON ({e})") from None


def read_jsonc(host: Host, path: Path):
    """JSON with comments and trailing commas (VS Code settings), as read_json."""
    text = read_text(host, path)
    if text is None or not text.strip():
        return None
    try:
        return json.loads(strip_jsonc(text))
    except ValueError as e:
        raise FormatChanged(path, f"it isn't valid JSON, even allowing comments ({e})") from None


def strip_jsonc(text: str) -> str:
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


MAX_SQLITE_COPY = 256 * 1024 * 1024


def _sqlite_query(uri: str, sql: str, path: Path | None = None) -> int:
    """With `path`: a table or column the query names that the database lacks, while it has tables of its own, raises
    FormatChanged (an empty database, one its app has only just made, is just unreadable)."""
    con = sqlite3.connect(uri, uri=True, timeout=1)
    try:
        try:
            return int(con.execute(sql).fetchone()[0])
        except sqlite3.OperationalError as e:
            missing = re.match(r"no such (table|column): (\S+)", str(e))
            if path is not None and missing and con.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]:
                raise FormatChanged(path, f"its database has no {missing.group(1)} {missing.group(2)}") from None
            raise
    finally:
        con.close()


def _memory_dir() -> str | None:
    """A folder in memory for a moment's copy of a database (never the disk: a deleted copy there could be read back)."""
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as f:
            in_memory = {w[1] for w in (line.split() for line in f) if len(w) > 2 and w[2] in ("tmpfs", "ramfs")}
    except OSError:
        return None
    for d in (os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm"):
        if d and d in in_memory and os.access(d, os.W_OK):
            return d
    return None


def sqlite_count(path: Path, sql: str, optional: bool = False) -> int | None:
    """A count from an SQLite database, opened read-only, never written. Immutable (no lock an app holding it would
    notice) unless it has a write-ahead log with records in it: those are only seen by a reader that takes part in
    its locking, so it is then opened read-only as the app's other readers are (a shared read lock, which never holds
    the app up; tested with Vorta's database: immutable saw no tables, read-only all 22), else read from a copy made
    in memory. None if missing or unreadable. A table or column the database lacks (it has others) raises
    FormatChanged, unless `optional`: one that only some versions or builds of the app make."""
    import shutil
    import tempfile
    from urllib.parse import quote
    if not isfile(path):
        return None
    wal = path.with_name(path.name + "-wal")
    try:
        live = isfile(wal) and wal.stat().st_size > 0
    except OSError:
        live = False
    if live:
        try:
            return _sqlite_query(f"file:{quote(str(path))}?mode=ro", sql, None if optional else path)
        except sqlite3.Error:
            pass
        mem = _memory_dir()
        try:
            if mem and path.stat().st_size + wal.stat().st_size <= MAX_SQLITE_COPY:
                with tempfile.TemporaryDirectory(prefix="daprivacyscanner-db-", dir=mem) as d:
                    shutil.copyfile(path, os.path.join(d, "db"))
                    shutil.copyfile(wal, os.path.join(d, "db-wal"))
                    return _sqlite_query(f"file:{quote(os.path.join(d, 'db'))}", sql, None if optional else path)
        except (OSError, sqlite3.Error):
            pass
    try:
        return _sqlite_query(f"file:{quote(str(path))}?mode=ro&immutable=1", sql, None if optional else path)
    except sqlite3.Error:
        return None


def mode_of(path: Path) -> int | None:
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return None


# ------------------------------------------------------------------ the running system

def processes(host: Host) -> set[str]:
    """Names (comm) of running processes."""
    out = set()
    for p in children(host.sys_path("/proc")):
        if p.name.isdigit():
            try:
                out.add((p / "comm").read_text().strip())
            except OSError:
                continue
    return out


def removed_while_running(host: Host, name: str) -> bool:
    """Whether the processes called `name` run a program that has since been removed: /proc/PID/exe reads
    "PATH (deleted)" and nothing is at PATH now. Package managers remove the files and leave what runs running, a
    session's daemon until logout (KDE Connect's, tested with pacman). An upgrade leaves "(deleted)" too, with the new
    program at PATH. Other accounts' processes can't be read and don't count; False when none could be read."""
    found = False
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit():
            continue
        try:
            if (p / "comm").read_text().strip() != name:
                continue
            exe = os.readlink(p / "exe")
        except OSError:
            continue
        path, deleted = exe.removesuffix(" (deleted)"), exe.endswith(" (deleted)")
        if not deleted or not path.startswith("/") or os.path.lexists(host.sys_path(path)):
            return False
        found = True
    return found


def open_files(host: Host) -> list[tuple[str, frozenset[str]]]:
    """(process name, paths it holds) for each of this user's processes: its working directory,
    open files and mapped files, from /proc (what `fuser` reads). One pass over /proc: reading
    every process's memory map is the slow part (a browser maps thousands of files), so
    holders() asks this once per plan, not once per folder. The app's own process is left out:
    it never uses the user's folders by path, and the user couldn't close it to let a fix go ahead."""
    out = []
    me = str(os.getpid()) if host.root == Path("/") else None
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit() or p.name == me:
            continue
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue                                # other users' processes can't be inspected anyway
            name = (p / "comm").read_text().strip()
        except OSError:
            continue
        paths = set()
        for link in [p / "cwd", *children(p / "fd")]:
            try:
                paths.add(os.readlink(link))
            except OSError:
                continue
        try:
            for line in (p / "maps").read_text(errors="replace").splitlines():
                f = line.split(None, 5)
                if len(f) == 6 and f[5].startswith("/"):
                    paths.add(f[5])
        except OSError:
            pass
        out.append((name, frozenset(paths)))
    return out


def holders(scan, directory: Path) -> set[str]:
    """Names of this user's processes that have a file under `directory` open, mapped, or as
    their working directory. The reliable way to know an app is using its data folder, whatever
    its process is called: a fix must never clear a cache or history out from under a running
    app. The processes are read once per Scan (a plan is built from a fresh one)."""
    try:
        root = str(directory.resolve()).rstrip("/") + "/"
    except OSError:
        return set()
    return {name for name, paths in scan.open_files() if any(p.startswith(root) or p == root[:-1] for p in paths)}


def chromium_in_use(user_data_dir: Path) -> bool:
    """A Chromium-family browser keeps a SingletonLock symlink in its user data directory while
    it runs (it names the host and PID; only its presence is used)."""
    try:
        return (user_data_dir / "SingletonLock").is_symlink()
    except OSError:
        return False


@dataclass(frozen=True)
class Mount:
    source: str
    target: str
    fstype: str
    options: str


VIRTUAL_FS = frozenset({"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs", "pstore",
                        "efivarfs", "bpf", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs",
                        "autofs", "binfmt_misc", "rpc_pipefs", "nsfs", "ramfs", "squashfs", "overlay", "fuse.portal",
                        "fuse.gvfsd-fuse", "selinuxfs", "erofs"})


def mounts(host: Host) -> list[Mount]:
    out = []
    for line in (host.read_sys("/proc/mounts") or "").splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append(Mount(f[0], f[1].replace("\\040", " "), f[2], f[3]))
    return out


def storage_mounts(host: Host) -> list[Mount]:
    """Mounted filesystems that hold files (not /proc, tmpfs, snaps...)."""
    return [m for m in mounts(host) if m.fstype not in VIRTUAL_FS]


def systemctl_state(host: Host, verb: str, unit: str, user: bool = False) -> str:
    """`systemctl [--user] is-active|is-enabled <unit>` output ("active", "enabled", "masked",
    ...), or "" if systemctl is missing."""
    argv = ["systemctl"] + (["--user"] if user else []) + [verb, unit]
    r = host.run(*argv)
    return "" if r.missing else (r.stdout.strip().splitlines() or [""])[0]


def installed(host: Host, *programs: str) -> bool:
    return any(host.runner.which(p) for p in programs)


def xdg_user_dir(host: Host, paths: PathResolver, name: str) -> Path | None:
    """XDG_<name>_DIR from user-dirs.dirs (e.g. "DOWNLOAD", "PICTURES"), or None."""
    text = read_text(host, paths.config_home / "user-dirs.dirs") or ""
    m = re.search(rf'^XDG_{name}_DIR="([^"]*)"', text, re.M)
    if not m:
        return None
    value = m.group(1).replace("$HOME", str(host.home))
    p = Path(value)
    return p if p.is_absolute() and p != host.home else None


def user_names(host: Host) -> tuple[str, list[str]]:
    """The user's login name and the words of their full name (GECOS), for spotting names in
    hostnames and device aliases."""
    login = host.environ.get("USER") or host.environ.get("LOGNAME") or host.home.name
    words: list[str] = []
    r = host.run("getent", "passwd", login)
    line = r.stdout if r.ok else ""
    f = line.strip().split(":")
    if len(f) >= 5:
        words = [w for w in re.split(r"[\s,]+", f[4].split(",")[0]) if len(w) >= 3]
    return login, words


def mentions_name(text: str, login: str, words: list[str]) -> str | None:
    t = text.lower()
    for w in [login, *words]:
        if w and len(w) >= 3 and w.lower() in t:
            return w
    return None


# ------------------------------------------------------------------ browsers

# (name, native config dir, Flatpak app id, Flatpak config dir, snap name, snap dir under the snap root)
CHROMIUM_BROWSERS = (
    ("Google Chrome", "google-chrome", "com.google.Chrome", "google-chrome", None, None),
    ("Google Chrome Beta", "google-chrome-beta", "com.google.ChromeDev", "google-chrome-beta", None, None),
    ("Google Chrome Dev", "google-chrome-unstable", "com.google.ChromeDev", "google-chrome-unstable", None, None),
    ("Chromium", "chromium", "org.chromium.Chromium", "chromium", "chromium", "chromium"),
    ("Brave", "BraveSoftware/Brave-Browser", "com.brave.Browser", "BraveSoftware/Brave-Browser", "brave",
     ".config/BraveSoftware/Brave-Browser"),
    ("Brave Beta", "BraveSoftware/Brave-Browser-Beta", "com.brave.Browser.beta", "BraveSoftware/Brave-Browser-Beta", None, None),
    ("Brave Nightly", "BraveSoftware/Brave-Browser-Nightly", "com.brave.Browser.nightly",
     "BraveSoftware/Brave-Browser-Nightly", None, None),
    ("Brave Origin", "BraveSoftware/Brave-Origin", "com.brave.Origin", "BraveSoftware/Brave-Origin", None, None),
    ("Microsoft Edge", "microsoft-edge", "com.microsoft.Edge", "microsoft-edge", None, None),
    ("Vivaldi", "vivaldi", "com.vivaldi.Vivaldi", "vivaldi", None, None),
    ("Opera", "opera", "com.opera.Opera", "opera", None, None),
)


@dataclass(frozen=True)
class BrowserDir:
    browser: str
    root: Location              # the browser's user data directory

    @property
    def label(self) -> str:
        how = "" if self.root.install == "native" else f", {self.root.install}"
        return f"{self.browser}{how}"


def chromium_dirs(paths: PathResolver) -> list[BrowserDir]:
    out = []
    for name, native, fp_id, fp_dir, snap, snap_dir in CHROMIUM_BROWSERS:
        for loc in paths.config(native):
            out.append(BrowserDir(name, loc))
        for loc in paths.locate(Base.CONFIG, fp_dir, flatpak=[fp_id]):
            if loc.install == "flatpak":
                out.append(BrowserDir(name, loc))
        if snap:
            for root in paths.snap_roots(snap):
                p = root.path / snap_dir
                if isdir(p):
                    out.append(BrowserDir(name, Location(p, "snap", snap, root.revision, root.current)))
    return out


def chromium_profiles(d: BrowserDir) -> list[Path]:
    """Profile directories ("Default", "Profile 1", ...) in a Chromium user data directory."""
    return [p for p in children(d.root.path) if (p.name == "Default" or p.name.startswith("Profile "))
            and (p / "Preferences").is_file()]


# Firefox-family profile roots: (name, native dot-dir, flatpak id, snap name)
MOZILLA_APPS = (
    ("Firefox", ".mozilla/firefox", "org.mozilla.firefox", "firefox"),
    ("LibreWolf", ".librewolf", "io.gitlab.librewolf-community", None),
    # VERIFY: the forks' profile folders and Flatpak ids (browsers.yaml)
    ("Waterfox", ".waterfox", "net.waterfox.waterfox", None),
    ("Zen", ".zen", "app.zen_browser.zen", None),
    ("Floorp", ".floorp", "one.ablaze.floorp", None),
    ("Thunderbird", ".thunderbird", "org.mozilla.Thunderbird", "thunderbird"),
)


@dataclass(frozen=True)
class MozProfile:
    app: str
    path: Path
    install: str

    @property
    def label(self) -> str:
        how = "" if self.install == "native" else f", {self.install}"
        return f"{self.app} profile {self.path.name}{how}"


def mozilla_profiles(host: Host, paths: PathResolver, apps: Iterable[str] | None = None) -> list[MozProfile]:
    """Profiles listed in each profiles.ini (native, Flatpak, Snap and the XDG location newer
    Firefox may use; VERIFY that location against current releases)."""
    out, seen = [], set()
    for name, dotdir, fp, snap in MOZILLA_APPS:
        if apps is not None and name not in apps:
            continue
        roots = paths.dotdir(dotdir, flatpak=[fp], snap=[snap] if snap else [])
        if name == "Firefox":
            roots += paths.config("mozilla/firefox")
        for root in roots:
            ini = read_text(host, root.path / "profiles.ini") or ""
            for m in re.finditer(r"^\[Profile\d+\]\s*$(.*?)(?=^\[|\Z)", ini, re.M | re.S):
                body = m.group(1)
                p = re.search(r"^Path=(.+)$", body, re.M)
                if not p:
                    continue
                rel = re.search(r"^IsRelative=(\d)", body, re.M)
                prof = (root.path / p.group(1).strip()) if (not rel or rel.group(1) == "1") else Path(p.group(1).strip())
                if isdir(prof) and prof.resolve() not in seen:
                    seen.add(prof.resolve())
                    out.append(MozProfile(name, prof, root.install))
    return out


def mozilla_cache(paths: PathResolver, p: MozProfile) -> Path:
    """A Firefox-family profile's disk cache (cache2). Firefox keeps it outside the profile, at the profile's place
    under the profiles' root mirrored into the cache folder: ~/.mozilla/firefox/X or ~/.config/mozilla/firefox/X ->
    ~/.cache/mozilla/firefox/X/cache2 (tested on Firefox 157), ~/.librewolf/X -> ~/.cache/librewolf/X/cache2. A Flatpak's
    cache folder is ~/.var/app/ID/cache, a Snap's .cache beside the dot folder. A profile outside its root (IsRelative=0)
    keeps the cache inside it. VERIFY: the forks' and the Snap's cache folders."""
    prof = p.path
    root = prof.parent
    rel = "mozilla/firefox" if root.parts[-2:] in (("mozilla", "firefox"), (".mozilla", "firefox")) else root.name.lstrip(".")
    base = paths.cache_home
    if p.install == "flatpak":
        app = next((a for a in prof.parents if a.parent == paths.flatpak_root), None)
        base = app / "cache" if app is not None else base
    elif p.install == "snap":
        home = next((a.parent for a in prof.parents if a.name.startswith(".")), None)
        base = home / ".cache" if home is not None else base
    out = base / rel / prof.name / "cache2"
    inside = prof / "cache2"
    return inside if not isdir(out) and isdir(inside) else out


_PREF = re.compile(r'^\s*user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;', re.M)


def firefox_prefs(host: Host, profile: Path) -> dict:
    """prefs.js with user.js on top (user.js wins at startup)."""
    out: dict = {}
    for name in ("prefs.js", "user.js"):
        for key, raw in _PREF.findall(read_text(host, profile / name) or ""):
            try:
                out[key] = json.loads(raw)
            except ValueError:
                out[key] = raw
    return out


FIREFOX_POLICY_FILES = ("/etc/firefox/policies/policies.json", "/usr/lib/firefox/distribution/policies.json",
                        "/usr/lib64/firefox/distribution/policies.json", "/opt/firefox/distribution/policies.json",
                        "/usr/lib/firefox-esr/distribution/policies.json")


def firefox_policies(host: Host) -> dict:
    out: dict = {}
    for p in FIREFOX_POLICY_FILES:
        try:
            data = json.loads(host.read_sys(p) or "null")
        except (ValueError, Unreadable):
            continue
        if isinstance(data, dict) and isinstance(data.get("policies"), dict):
            out.update(data["policies"])
    return out


CHROMIUM_POLICY_DIRS = {
    "Google Chrome": "/etc/opt/chrome/policies/managed", "Chromium": "/etc/chromium/policies/managed",
    "Brave": "/etc/brave/policies/managed", "Microsoft Edge": "/etc/opt/edge/policies/managed",
    "Vivaldi": "/etc/vivaldi/policies/managed",
}


def chromium_policies(host: Host, browser: str) -> dict:
    out: dict = {}
    d = next((v for k, v in CHROMIUM_POLICY_DIRS.items() if browser.startswith(k)), None)
    if not d:
        return out
    for f in children(host.sys_path(d)):
        if f.suffix == ".json":
            data = read_json(host, f)
            if isinstance(data, dict):
                out.update(data)
    return out


def dig(data, *keys, default=None):
    for k in keys:
        if not isinstance(data, dict) or k not in data:
            return default
        data = data[k]
    return data


# ------------------------------------------------------------------ thumbnails and recent files

def png_text(head: bytes) -> dict[str, str]:
    """tEXt chunks from the start of a PNG (thumbnails put Thumb::URI there, before the image
    data). `head` only needs the first few KB."""
    out: dict[str, str] = {}
    if not head.startswith(b"\x89PNG\r\n\x1a\n"):
        return out
    i = 8
    while i + 8 <= len(head):
        length = int.from_bytes(head[i:i + 4], "big")
        kind = head[i + 4:i + 8]
        data = head[i + 8:i + 8 + length]
        if kind == b"IDAT" or len(data) < length:
            break
        if kind == b"tEXt" and b"\0" in data:
            k, v = data.split(b"\0", 1)
            out[k.decode("latin-1")] = v.decode("utf-8", errors="replace")
        i += 12 + length
    return out


def uri_path(uri: str) -> str | None:
    """The local path of a file:// URI."""
    from urllib.parse import unquote, urlsplit

    u = urlsplit(uri)
    return unquote(u.path) if u.scheme == "file" else None


def thumbnail_dirs(paths: PathResolver) -> list[Path]:
    return [loc.path for loc in paths.cache("thumbnails", all_flatpaks=True, all_snaps=True)]


def thumbnail_uris(paths: PathResolver, limit: int = WALK_LIMIT) -> tuple[list[str], int]:
    """The original URI of every cached thumbnail, and how many thumbnails there are."""
    entries, count = thumbnail_entries(paths, limit)
    return [u for _, u in entries], count


def thumbnail_entries(paths: PathResolver, limit: int = WALK_LIMIT) -> tuple[list[tuple[Path, str]], int]:
    """(thumbnail file, original URI) for every cached thumbnail, and how many there are."""
    uris, count = [], 0
    for d in thumbnail_dirs(paths):
        stack = [d]
        while stack:
            for p in children(stack.pop()):
                if count >= limit:
                    return uris, count
                if isdir(p):
                    stack.append(p)
                elif p.suffix == ".png":
                    count += 1
                    try:
                        with open(p, "rb") as f:
                            uri = png_text(f.read(4096)).get("Thumb::URI")
                    except OSError:
                        continue
                    if uri:
                        uris.append((p, uri))
    return uris, count


def recent_files(paths: PathResolver) -> list[Path]:
    """Every recently-used.xbel (GTK's recent files list), native and sandboxed."""
    return [loc.path for loc in paths.data("recently-used.xbel", all_flatpaks=True, all_snaps=True)]


def recent_hrefs(host: Host, xbel: Path) -> list[str]:
    from html import unescape

    return [unescape(h) for h in re.findall(r'<bookmark\s[^>]*href="([^"]+)"', read_text(host, xbel) or "")]


def files_under(root: Path, limit: int = WALK_LIMIT, pattern: re.Pattern | None = None) -> tuple[list[Path], bool]:
    """Every regular file under `root` (symlinks not followed), for a deletion plan; and whether
    the walk stopped at `limit`."""
    out, stack = [], [root]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        with it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(Path(e.path))
                    elif e.is_file(follow_symlinks=False) and (pattern is None or pattern.search(e.name)):
                        out.append(Path(e.path))
                        if len(out) >= limit:
                            return out, True
                except OSError:
                    continue
    return out, False
