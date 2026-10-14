"""What a program did with files, summed up for the page (docs/TECHNICAL.md, Tools): shared by "What does this
app keep?" (tools/appwatch.py: the helper's fanotify watch of one app on the real machine) and "Try an app"
(tools/trial.py: inotify on a trial's throwaway home). Both hand over the same raw records, one per file:

    [path, flags, opens, writes, minutes, who]

`flags`: OPENED, WRITTEN, CREATED, DELETED, RAN, MOVED, DIR; `minutes`: in how many different minutes it was
written to; `who`: "" for the app watched, else the name of another program of the user's.

The summary works in counts per folder (rule 2's spirit: the list of files a person opened is itself a
recent-files record, so it is never shown, saved or exported). Named are only: the folders; a file or database the
app writes to regularly (`regular`: the user needs to see what it is); and the files, written during the session
by the app or by any other program of the user's, that hold the names of the user's own files the app opened
(`find_records`: the thumbnail with the file's path in it, the recent-files list), which are the leak this looks
for. Nothing here is kept: the caller holds the result in memory for as long as the tool is open."""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import quote

OPENED, WRITTEN, CREATED, DELETED, RAN, MOVED, DIR = 1, 2, 4, 8, 16, 32, 64

# a file counts as written to regularly: in this many different minutes, or (a session too short for that) this often
REGULAR_MINUTES = 3
REGULAR_WRITES = 20
REGULAR_MAX = 40
PLACES_MAX = 400
NAMES_PER_PLACE = 60                    # a trial's own files, named (its home is made up: nothing of the user's)

# where the user's programs keep things about them: opened by an app that isn't theirs, it is worth knowing. Paths
# under the home folder (a folder and everything in it, or one file); the words say what it is, not which file.
SENSITIVE = (
    (".ssh", "SSH keys and settings"),
    (".gnupg", "GnuPG keys"),
    (".local/share/keyrings", "the login keyring (saved passwords)"),
    (".local/share/kwalletd", "the KDE wallet (saved passwords)"),
    (".password-store", "the password store (pass)"),
    (".config/keepassxc", "KeePassXC's settings"),
    (".config/Bitwarden", "Bitwarden's data"),
    (".mozilla", "Firefox's profile (history, cookies, saved logins)"),
    (".var/app/org.mozilla.firefox", "Firefox's profile (history, cookies, saved logins)"),
    (".config/google-chrome", "Chrome's profile (history, cookies, saved logins)"),
    (".config/chromium", "Chromium's profile (history, cookies, saved logins)"),
    (".config/BraveSoftware", "Brave's profile (history, cookies, saved logins)"),
    (".config/microsoft-edge", "Edge's profile (history, cookies, saved logins)"),
    (".config/vivaldi", "Vivaldi's profile (history, cookies, saved logins)"),
    (".thunderbird", "Thunderbird's mail and accounts"),
    (".var/app/org.mozilla.Thunderbird", "Thunderbird's mail and accounts"),
    (".config/Signal", "Signal's messages"),
    (".local/share/TelegramDesktop", "Telegram's data"),
    (".config/discord", "Discord's data"),
    (".aws", "cloud credentials (AWS)"),
    (".kube", "cluster credentials (Kubernetes)"),
    (".docker", "Docker's settings and logins"),
    (".config/gh", "GitHub's command-line login"),
    (".netrc", "saved logins (.netrc)"),
    (".git-credentials", "saved Git logins"),
    (".bash_history", "the shell's history"),
    (".zsh_history", "the shell's history"),
    (".local/share/fish/fish_history", "the shell's history"),
    (".bitcoin", "a Bitcoin wallet"),
    (".electrum", "an Electrum wallet"),
    (".ethereum", "an Ethereum wallet"),
    (".monero", "a Monero wallet"),
    (".config/Exodus", "an Exodus wallet"),
    (".local/share/recently-used.xbel", "the list of recently used files"),
)

TEMP = ("/tmp", "/var/tmp", "/dev/shm")
MEDIA = ("/media", "/mnt", "/run/media")
KIND_WORDS = {"app": "Programs' own data", "yours": "Your files", "temp": "Temporary files", "media": "Other disks",
              "system": "The system"}


@dataclass
class Where:
    """How paths are sorted into places: the home folder (real path), the user's id (for /run/user/UID) and the
    folders programs keep their own data in (relative to the home; the XDG ones when they were moved)."""
    home: str
    uid: int = 0
    data_dirs: tuple[str, ...] = (".config", ".cache", ".local/share", ".local/state")

    @classmethod
    def of(cls, host) -> "Where":
        from ..paths import PathResolver
        home = os.path.realpath(host.home)
        paths = PathResolver(host.home, host.environ)
        dirs = [".config", ".cache", ".local/share", ".local/state"]
        for p in (paths.config_home, paths.cache_home, paths.data_home, paths.state_home):
            rel = _under(os.path.realpath(p), home)
            if rel and rel not in dirs:
                dirs.append(rel)
        return cls(home, host.uid, tuple(dirs))


def _under(path: str, base: str) -> str | None:
    """`path` relative to `base` when it is inside it ("" for the folder itself), else None."""
    if path == base:
        return ""
    return path[len(base) + 1:] if path.startswith(base.rstrip("/") + "/") else None


def _head(rel: str, n: int) -> str:
    return "/".join(rel.split("/")[:n])


def place(path: str, w: Where, is_dir: bool = False) -> tuple[str, str]:
    """(kind, folder) for a path: which of KIND_WORDS it belongs to and the folder it is counted under, deep
    enough to say whose it is (~/.config/Foo/Cache, ~/.var/app/org.x.App/data/x, ~/Documents/Work) and no
    deeper. `is_dir`: the path is itself a folder (it is counted under itself, not its parent)."""
    rel = _under(path, w.home)
    if rel is not None:
        parts = rel.split("/") if rel else []
        folders = parts if is_dir else parts[:-1]
        if not parts:
            return "yours", "~"
        if parts[0] == ".var" and len(parts) > 2 and parts[1] == "app":
            return "app", "~/" + "/".join(folders[:5]) if len(folders) > 2 else "~/" + "/".join(parts[:3])
        if parts[0] == "snap" and len(parts) > 1:
            return "app", "~/" + "/".join((folders or parts)[:4])
        for base in sorted(w.data_dirs, key=len, reverse=True):
            sub = _under(rel, base)
            if sub is not None:
                depth = len(base.split("/"))
                return "app", "~/" + "/".join(folders[:depth + 2] or parts[:depth])
        if parts[0].startswith("."):
            return "app", "~/" + "/".join(folders[:2]) if folders else "~ (hidden files)"
        return "yours", "~/" + "/".join(folders[:3]) if folders else "~"
    run = f"/run/user/{w.uid}"
    for base in (*TEMP, run):
        sub = _under(path, base)
        if sub is not None:
            first = sub.split("/")[0] if sub else ""
            deeper = "/" in sub or is_dir
            return "temp", f"{base}/{first}" if first and deeper else base
    for base in MEDIA:
        sub = _under(path, base)
        if sub is not None:
            parts = sub.split("/") if sub else []
            return "media", base + ("/" + "/".join((parts if is_dir else parts[:-1])[:3]) if parts else "")
    parts = path.strip("/").split("/")
    return "system", "/" + "/".join((parts if is_dir else parts[:-1])[:2]) if len(parts) > 1 else "/"


def sensitive(path: str, w: Where) -> str | None:
    """What of SENSITIVE the path is in, in words, or None."""
    rel = _under(path, w.home)
    if not rel:
        return None
    for prefix, words in SENSITIVE:
        if rel == prefix or rel.startswith(prefix + "/"):
            return words
    return None


MAGIC = ((b"SQLite format 3\0", "an SQLite database"), (b"\x89PNG\r\n\x1a\n", "a PNG picture"),
         (b"\xff\xd8\xff", "a JPEG picture"), (b"mozLz40\0", "a compressed Firefox file"),
         (b"PK\x03\x04", "a ZIP archive"), (b"\x1f\x8b", "a gzip file"), (b"<?xml", "an XML file"),
         (b"{", "a JSON file"), (b"[", "a settings or JSON file"))


def file_type(path: str) -> str:
    """What kind of file it is, in words, from its first bytes and its name (read as the user)."""
    name = os.path.basename(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return "a file"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return "not a plain file"
        head = os.read(fd, 16)
    except OSError:
        return "a file"
    finally:
        os.close(fd)
    if name.endswith(("-wal", "-journal", "-shm")) and "sqlite" in name or name.endswith((".db-wal", ".db-journal", ".db-shm")):
        return "an SQLite database's journal"
    if name.endswith(".ldb") or name.startswith("MANIFEST-") or (name.endswith(".log") and name[:-4].isdigit()):
        return "part of a LevelDB database"
    for magic, words in MAGIC:
        if head.startswith(magic):
            return words
    if name.endswith(".log"):
        return "a log"
    return "a text file" if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head) else "a file"


def tilde(path: str, w: Where) -> str:
    rel = _under(path, w.home)
    return path if rel is None else ("~/" + rel if rel else "~")


def _size(path: str) -> int | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return st.st_size if stat.S_ISREG(st.st_mode) else 0


def summarise(records: Iterable[list], w: Where, seconds: float, names: bool = False,
              size_of: Callable[[str], int | None] = _size) -> dict:
    """The app's own records (`who` empty) as the page shows them: totals, places (folders with counts), the
    files written to regularly, the sensitive places it opened, and how many of the user's own files it opened.
    `names`: also name each place's files (a trial's made-up home; never for the real one)."""
    places: dict[tuple[str, str], dict] = {}
    totals = {"opened": 0, "written": 0, "created": 0, "deleted": 0, "ran": 0}
    regular, touched, seen = [], {}, 0
    short = seconds < REGULAR_MINUTES * 60 + 60
    for rec in records:
        path, flags, opens, writes, minutes, who = rec[:6]
        if who:
            continue
        seen += 1
        is_dir = bool(flags & DIR)
        kind, folder = place(path, w, is_dir)
        p = places.setdefault((kind, folder), {"kind": kind, "folder": folder, "opened": 0, "written": 0, "created": 0,
                                               "deleted": 0, "left": 0, "bytes": 0, "files": []})
        if is_dir:                                     # folders aren't counted: the files in them are
            continue
        only_read = not flags & (WRITTEN | CREATED | DELETED | MOVED)
        if flags & RAN:
            totals["ran"] += 1
        if flags & OPENED and only_read:
            p["opened"] += 1
            totals["opened"] += 1
        if flags & (WRITTEN | MOVED) and not flags & CREATED:
            p["written"] += 1
            totals["written"] += 1
        if flags & CREATED:
            p["created"] += 1
            totals["created"] += 1
        if flags & DELETED:
            p["deleted"] += 1
            totals["deleted"] += 1
        elif flags & (WRITTEN | CREATED | MOVED):
            size = size_of(path)
            if size is not None:
                p["left"] += 1
                p["bytes"] += size
        if names and len(p["files"]) < NAMES_PER_PLACE:
            p["files"].append({"name": tilde(path, w), "did": _did(flags)})
        words = sensitive(path, w)
        if words:
            t = touched.setdefault(words, {"what": words, "opened": 0, "written": 0})
            t["written" if flags & (WRITTEN | CREATED | DELETED | MOVED) else "opened"] += 1
        if kind != "system" and not flags & DELETED and (
                minutes >= REGULAR_MINUTES or (short and writes >= REGULAR_WRITES)):
            regular.append({"path": tilde(path, w), "real": path, "writes": writes, "minutes": minutes})
    regular.sort(key=lambda r: (-r["minutes"], -r["writes"], r["path"]))
    regular = regular[:REGULAR_MAX]
    for r in regular:
        real = r.pop("real")
        r["type"], r["size"] = file_type(real), size_of(real) or 0
    order = {"app": 0, "yours": 1, "temp": 2, "media": 3, "system": 4}
    shown = sorted(places.values(), key=lambda p: (order[p["kind"]], -(p["written"] + p["created"] + p["deleted"]),
                                                   -p["opened"], p["folder"]))
    shown = [p for p in shown if p["opened"] or p["written"] or p["created"] or p["deleted"]]
    for p in shown:
        if not names:
            del p["files"]
    yours = [p for p in shown if p["kind"] == "yours"]
    return {"seconds": round(seconds), "files": seen, "totals": totals, "places": shown[:PLACES_MAX],
            "places_left_out": max(0, len(shown) - PLACES_MAX), "regular": regular,
            "sensitive": sorted(touched.values(), key=lambda t: t["what"]),
            "yours": {"opened": sum(p["opened"] for p in yours),
                      "changed": sum(p["written"] + p["created"] + p["deleted"] for p in yours)},
            "kinds": KIND_WORDS}


def _did(flags: int) -> str:
    words = [word for bit, word in ((CREATED, "created"), (WRITTEN, "written"), (MOVED, "renamed"), (DELETED, "deleted"),
                                    (RAN, "run")) if flags & bit]
    return ", ".join(words) or "opened"


# ------------------------------------------------------------------ who recorded what the app opened

SEARCH_FILE_MAX = 128 << 20              # a file larger than this isn't searched (said in the result)
SEARCH_TOTAL_MAX = 2 << 30               # nor anything past this much in all
SEARCH_SECONDS = 45.0
NEEDLES_MAX = 2000
CHUNK = 4 << 20


def needles(records: Iterable[list], w: Where) -> list[str]:
    """The user's own files the app opened (not folders, not programs' data): the names to look for."""
    out = []
    for rec in records:
        path, flags, who = rec[0], rec[1], rec[5]
        if who or flags & DIR or len(out) >= NEEDLES_MAX:
            continue
        if place(path, w)[0] in ("yours", "media"):
            out.append(path)
    return out


def _forms(path: str) -> set[bytes]:
    """How a path is written in the files that record it: as it is, as a file:// address (percent-encoded and
    not), in UTF-8 and in UTF-16 (Qt's settings, some databases)."""
    texts = {path, "file://" + path, "file://" + quote(path), quote(path)}
    return {t.encode("utf-8", "surrogateescape") for t in texts} | {t.encode("utf-16-le", "surrogatepass") for t in texts}


def find_records(records: list[list], w: Where, skip: Callable[[str], bool] = lambda p: False,
                 deadline: float | None = None) -> dict:
    """Which files written during the session hold the names of the user's own files the app opened: by the
    app itself or by another program of the user's (`who`). Read as the user, raw (a thumbnail's text chunk, a
    database's pages, a recent-files list all hold the path as bytes); compressed or encrypted stores can't be
    read this way, and the result says so. Returns {"found": [{path, who, names, type}], "searched", "skipped",
    "names"}: `names` is how many of the user's files were looked for."""
    wanted = needles(records, w)
    forms: dict[bytes, int] = {}
    for i, path in enumerate(wanted):
        for f in _forms(path):
            forms[f] = i
    markers = {m for m in (w.home.encode("utf-8", "surrogateescape"), w.home.encode("utf-16-le", "surrogatepass"),
                           quote(w.home).encode()) if m}
    for base in MEDIA:                                   # a file on another disk is recorded under its own path
        if any(p.startswith(base + "/") for p in wanted):
            markers |= {base.encode(), base.encode("utf-16-le")}
    lengths = sorted({len(f) for f in forms}, reverse=True)
    longest = lengths[0] if lengths else 0
    found, searched, skipped, total = [], 0, 0, 0
    deadline = deadline if deadline is not None else time.monotonic() + SEARCH_SECONDS
    own = set(wanted)
    hay = sorted({(rec[0], rec[5]) for rec in records
                  if rec[1] & (WRITTEN | CREATED | MOVED) and not rec[1] & (DELETED | DIR) and rec[0] not in own})
    for path, who in hay if forms else []:
        if skip(path) or place(path, w)[0] in ("yours", "media", "system"):
            continue
        if time.monotonic() > deadline or total > SEARCH_TOTAL_MAX:
            skipped += 1
            continue
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size > SEARCH_FILE_MAX:
                skipped += 1
                continue
            hits = _search(fd, forms, markers, lengths, longest)
            total += st.st_size
            searched += 1
        except OSError:
            continue
        finally:
            os.close(fd)
        if hits:
            found.append({"path": tilde(path, w), "who": who, "names": len(hits), "type": file_type(path)})
    found.sort(key=lambda f: (-f["names"], f["path"]))
    return {"found": found, "searched": searched, "skipped": skipped, "names": len(wanted)}


def _search(fd: int, forms: dict[bytes, int], markers: set[bytes], lengths: list[int], longest: int) -> set[int]:
    """Which of the names (by index) the file holds: every place a marker (the home folder's path) starts is
    compared with the forms of each length."""
    hits: set[int] = set()
    tail = b""
    while True:
        chunk = os.read(fd, CHUNK)
        if not chunk:
            break
        data = tail + chunk
        for marker in markers:
            i = data.find(marker)
            while i != -1:
                for back in (0, 7, 14):                  # "file://" before it, in UTF-8 or UTF-16
                    if back > i:
                        break
                    for n in lengths:
                        got = forms.get(data[i - back:i - back + n])
                        if got is not None:
                            hits.add(got)
                            break
                i = data.find(marker, i + 1)
        tail = data[-(longest + 16):] if longest else b""
    return hits


def folders_only(path: str) -> str:
    """A path's folder, for messages that must not name the file."""
    return str(Path(path).parent)
