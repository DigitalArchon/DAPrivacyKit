"""What a program did with files, summed up for the page (docs/TECHNICAL.md, Tools): shared by "What does this
app keep?" (tools/appwatch.py: the helper's fanotify watch of one app on the real machine) and "Try an app"
(tools/trial.py: inotify on a trial's throwaway home). Both hand over the same raw records, one per file:

    [path, flags, opens, writes, minutes, who]

`flags`: OPENED, WRITTEN, CREATED, DELETED, RAN, MOVED, DIR; `minutes`: in how many different minutes it was
written to; `who`: "" for the app watched, else the name of another program of the user's.

The summary works in counts per folder (rule 2's spirit: the list of files a person opened is itself a
recent-files record, so it is never shown, saved or exported). Named are only: the folders; a file or database the
app writes to regularly (`regular`: the user needs to see what it is; a document of the user's own, saved often, is
only counted, `regular_yours`); and the files, written during the session
by the app or by any other program of the user's, that hold the names of the user's own files the app opened
(`find_records`: the thumbnail with the file's path in it, the recent-files list), which are the leak this looks
for. Nothing here is kept: the caller holds the result in memory for as long as the tool is open."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import quote

OPENED, WRITTEN, CREATED, DELETED, RAN, MOVED, DIR = 1, 2, 4, 8, 16, 32, 64
MAPPED = 128            # changed though no write was seen: its date moved while the app had it open (a memory map)

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
         (b"\xda\x1ameta", "the desktop's notes on files (GVFS metadata)"),
         (b"\xda\x1ajour", "the desktop's notes on files (GVFS metadata, its journal)"),
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
    regular, touched, seen, regular_yours = [], {}, 0, 0
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
            if kind in ("yours", "media") and not names:
                regular_yours += 1                     # the user's own document, saved often: counted, never named
            else:
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
            "places_left_out": max(0, len(shown) - PLACES_MAX), "regular": regular, "regular_yours": regular_yours,
            "sensitive": sorted(touched.values(), key=lambda t: t["what"]),
            "yours": {"opened": sum(p["opened"] for p in yours),
                      "changed": sum(p["written"] + p["created"] + p["deleted"] for p in yours)},
            "kinds": KIND_WORDS}


def _did(flags: int) -> str:
    words = [word for bit, word in ((CREATED, "created"), (WRITTEN, "written"), (MOVED, "renamed"), (DELETED, "deleted"),
                                    (RAN, "run")) if flags & bit and not (bit == WRITTEN and flags & MAPPED)]
    if flags & MAPPED:
        words.append("changed (by its date)")
    return ", ".join(words) or "opened"


# ------------------------------------------------------------------ who recorded what the app opened

SEARCH_FILE_MAX = 128 << 20              # a file larger than this isn't searched (said in the result)
SEARCH_TOTAL_MAX = 2 << 30               # nor anything past this much in all
SEARCH_SECONDS = 45.0
NEEDLES_MAX = 2000
CHUNK = 4 << 20
TEXT_MAX = 1 << 20                       # a PNG's text chunk read (and unpacked) this far at most
PNG_CHUNKS_MAX = 4096

# a file in a temporary folder that the app opened but another program made (a mail attachment, a download opened
# from the browser) is the user's too: looked for as theirs
TEMP_OPENED = ("/tmp", "/var/tmp")

# how programs percent-encode a path in a file:// address (letters, digits and -._~ stay as they are everywhere):
# Python's quote() leaves "/" alone; GLib's g_filename_to_uri also !$&'()*+,:=@ (tested with GLib 2.80: "Report
# (final).txt" is Report%20(final).txt, which the first version missed); Qt's QUrl what RFC 3986 allows in a path
# (";" too)
URI_SAFE = ("/", "/!$&'()*+,:=@", "/!$&'()*+,;:=@")

# GVFS's metadata (gvfsd-metadata, for Nemo, Nautilus, Xed and other GLib programs): a database per filesystem
# ("home" for the home folder, "root" for /, others by their UUID) and its journal, home-1a2b3c4d.log, which hold
# paths relative to the filesystem's top or, for "home", to the home folder: "/Documents/letter.odt" (tested on
# Mint 22.3, with gio set as Xed does; the database splits a path into its names, the journal holds it whole)
GVFS_FOLDER = "gvfs-metadata"
GVFS_JOURNAL = re.compile(r"(.+)-[0-9a-f]{8}\.log")
GVFS_PATHS_MAX = 200000


def needles(records: Iterable[list], w: Where) -> list[str]:
    """The user's own files the app opened (not folders, not programs' data), and the files it opened in /tmp
    or /var/tmp that another program made: the names to look for."""
    out = []
    for rec in records:
        path, flags, who = rec[0], rec[1], rec[5]
        if who or flags & DIR or len(out) >= NEEDLES_MAX:
            continue
        kind = place(path, w)[0]
        if kind in ("yours", "media") or kind == "temp" and _temp_opened(path, flags):
            out.append(path)
    return out


def _temp_opened(path: str, flags: int) -> bool:
    """A file in /tmp or /var/tmp the app only opened (another program made it), none of whose names is hidden
    (a program's own: .X0-lock, .ICE-unix)."""
    if not flags & OPENED or flags & (CREATED | WRITTEN | MOVED | DELETED):
        return False
    for base in TEMP_OPENED:
        rel = _under(path, base)
        if rel:
            return not any(part.startswith(".") for part in rel.split("/"))
    return False


def _xml(text: str) -> set[str]:
    """The text as an XML file holds it: & < > escaped, an apostrophe and a quotation mark either way (GLib's
    bookmark file writes &apos;, older GLib &#39;; Qt's writer leaves an apostrophe as it is)."""
    if not any(c in text for c in "&<>'\""):
        return set()
    base = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return {base.replace("'", a).replace('"', q) for a in ("'", "&apos;", "&#39;") for q in ('"', "&quot;", "&#34;")}


def _spellings(path: str) -> set[str]:
    """How a path is written in the files that record it: as it is, percent-encoded as each kind of program does
    (URI_SAFE), and each of those as an XML file escapes it."""
    raw = path.encode("utf-8", "surrogateescape")
    texts = {path} | {quote(raw, safe=safe) for safe in URI_SAFE}
    return texts | {x for t in texts for x in _xml(t)}


def _encoded(texts: Iterable[str]) -> set[bytes]:
    """In UTF-8 and in UTF-16 (Qt's settings, some databases)."""
    texts = set(texts)
    return {t.encode("utf-8", "surrogateescape") for t in texts} | {t.encode("utf-16-le", "surrogatepass") for t in texts}


def _forms(path: str) -> set[bytes]:
    """Every way the files that record a path may hold it: its spellings, as they are and as file:// addresses."""
    return _encoded(prefix + t for t in _spellings(path) for prefix in ("", "file://"))


def _root(path: str, w: Where) -> str:
    """Where a path is looked for from: the home folder, or the folder of disks or temporary files it is in."""
    if _under(path, w.home) is not None:
        return w.home
    return next((base for base in (*MEDIA, *TEMP_OPENED) if _under(path, base)), path)


def find_records(records: list[list], w: Where, skip: Callable[[str], bool] = lambda p: False,
                 deadline: float | None = None, gvfs: dict | None = None) -> dict:
    """Which files written during the session hold the names of the user's own files the app opened: by the
    app itself or by another program of the user's (`who`). Read as the user, raw (a database's pages, a
    recent-files list hold the path as bytes), a PNG's text chunks unpacked (a thumbnail's Thumb::URI), GVFS's
    metadata by the paths it holds; other compressed or encrypted stores can't be read this way, and the result
    says so. `gvfs`: what GVFS's metadata held as the session began (`gvfs_snapshot`): its files are then
    searched whether or not a write to them was seen, for what was added since. Returns {"found": [{path, who,
    names, type}], "searched", "skipped", "names"}: `names` is how many of the user's files were looked for."""
    wanted = needles(records, w)
    forms: dict[bytes, int] = {}
    for i, path in enumerate(wanted):
        for f in _forms(path):
            forms[f] = i
    # a file is recorded under its own path: from the home folder, or from the disk's or temporary folder's
    markers = {m for root in {_root(p, w) for p in wanted} for m in _encoded(_spellings(root)) if m}
    lengths = sorted({len(f) for f in forms}, reverse=True)
    longest = lengths[0] if lengths else 0
    found, searched, skipped, total = [], 0, 0, 0
    deadline = deadline if deadline is not None else time.monotonic() + SEARCH_SECONDS
    own = set(wanted)
    hay = {(rec[0], rec[5]) for rec in records
           if rec[1] & (WRITTEN | CREATED | MOVED) and not rec[1] & (DELETED | DIR) and rec[0] not in own}
    fresh = None
    if gvfs is not None and forms:
        now = gvfs_snapshot(gvfs["folder"], gvfs["salt"])
        fresh = {key for key, n in now["entries"].items() if n > gvfs["entries"].get(key, 0)}
        written = {p for p, _who in hay}
        hay |= {(p, "gvfsd-metadata") for p in now["files"] if p not in written}
    keys = _GvfsKeys(wanted, w, fresh, gvfs["salt"] if gvfs else b"")
    for path, who in sorted(hay) if forms else []:
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
            if os.path.basename(os.path.dirname(path)) == GVFS_FOLDER:
                hits = keys.hits(fd, os.path.basename(path))
            else:
                hits = _scan(iter(lambda: os.read(fd, CHUNK), b""), forms, markers, lengths, longest)
                if os.pread(fd, 8, 0) == b"\x89PNG\r\n\x1a\n":
                    for text in _png_texts(fd, st.st_size):
                        hits |= _scan((text,), forms, markers, lengths, longest)
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


def _scan(chunks: Iterable[bytes], forms: dict[bytes, int], markers: set[bytes], lengths: list[int],
          longest: int) -> set[int]:
    """Which of the names (by index) the data holds: every place a marker (the home folder's path, in each of its
    spellings) starts is compared with the forms of each length."""
    hits: set[int] = set()
    tail = b""
    for chunk in chunks:
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


def _png_texts(fd: int, size: int) -> list[bytes]:
    """A PNG's text chunks: tEXt as it is, zTXt and a compressed iTXt unpacked (Qt writes a thumbnail's Thumb::URI
    longer than 40 characters as zTXt, which a search of the raw bytes never matched: Dolphin's thumbnails on
    CachyOS)."""
    out, pos = [], 8
    for _ in range(PNG_CHUNKS_MAX):
        head = os.pread(fd, 8, pos)
        if len(head) < 8:
            break
        n, kind = int.from_bytes(head[:4], "big"), head[4:]
        if kind == b"IEND" or pos + 12 + n > size:
            break
        if kind in (b"tEXt", b"zTXt", b"iTXt") and n <= 4 * TEXT_MAX:
            _key, _nul, rest = os.pread(fd, n, pos + 8).partition(b"\0")
            if kind == b"tEXt":
                out.append(rest[:TEXT_MAX])
            elif kind == b"zTXt" and rest[:1] == b"\0":
                out.append(_inflate(rest[1:]))
            elif kind == b"iTXt" and len(rest) >= 2:
                packed, method = rest[0], rest[1]
                _lang, _nul, rest = rest[2:].partition(b"\0")
                _translated, _nul, text = rest.partition(b"\0")
                out.append(_inflate(text) if packed == 1 and method == 0 else text[:TEXT_MAX])
        pos += 12 + n
    return out


def _inflate(data: bytes) -> bytes:
    try:
        return zlib.decompressobj().decompress(data, TEXT_MAX)
    except zlib.error:
        return b""


class _GvfsKeys:
    """The names looked for, as GVFS's metadata holds them, per database: relative to the home folder ("home"), as
    they are ("root"), or relative to the top of the filesystem they are on (another disk's, named by its UUID)."""

    def __init__(self, wanted: list[str], w: Where, fresh: set[bytes] | None = None, salt: bytes = b""):
        self.wanted, self.w, self.keys, self.fresh, self.salt = wanted, w, {}, fresh, salt

    def _key(self, tree: str, path: str) -> str | None:
        if tree == "home":
            rel = _under(path, self.w.home)
            return "/" + rel if rel else None
        if tree == "root":
            return path
        top = os.path.dirname(path)
        while top != "/" and not os.path.ismount(top):
            top = os.path.dirname(top)
        return path[len(top):] if top != "/" else None

    def hits(self, fd: int, name: str) -> set[int]:
        journal = GVFS_JOURNAL.fullmatch(name)
        tree = journal.group(1) if journal else name
        if tree not in self.keys:
            self.keys[tree] = {key.encode("utf-8", "surrogateescape"): i for i, path in enumerate(self.wanted)
                               if (key := self._key(tree, path))}
        keys = self.keys[tree]
        data = b"".join(iter(lambda: os.read(fd, CHUNK), b""))
        return {keys[p] for p in (_gvfs_journal(data) if journal else _gvfs_tree(data)) if p in keys
                and (self.fresh is None or _gvfs_key(self.salt, tree, p) in self.fresh)}


def _gvfs_key(salt: bytes, tree: str, path: bytes) -> bytes:
    return hashlib.blake2b(tree.encode("utf-8", "surrogateescape") + b"\0" + path, key=salt, digest_size=16).digest()


def gvfs_snapshot(folder: str, salt: bytes) -> dict:
    """How many entries GVFS's metadata in `folder` holds for each path, by a keyed hash of its database and path
    (no name is kept), and its files: taken as a watch begins and again at its end. gvfsd-metadata writes its
    journal through a memory map, which fanotify never reports, nor does the file's date always move (tested on
    Mint: a second `gio set` during the watch left neither), so its files are searched at the end whatever was
    seen, for the paths whose entries grew meanwhile."""
    entries: dict[bytes, int] = {}
    files = []
    try:
        names = sorted(os.listdir(folder))[:200]
    except OSError:
        names = []
    for name in names:
        path = os.path.join(folder, name)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > SEARCH_FILE_MAX:
                continue
            data = b"".join(iter(lambda: os.read(fd, CHUNK), b""))
        except OSError:
            continue
        finally:
            os.close(fd)
        files.append(path)
        journal = GVFS_JOURNAL.fullmatch(name)
        tree = journal.group(1) if journal else name
        found = _gvfs_journal(data) if journal else dict.fromkeys(_gvfs_tree(data), 1)
        for p, n in found.items():
            key = _gvfs_key(salt, tree, p)
            entries[key] = entries.get(key, 0) + n
    return {"folder": folder, "salt": salt, "entries": entries, "files": files}


def _gvfs_journal(data: bytes) -> dict[bytes, int]:
    """The paths in a GVFS metadata journal, with how many entries each has: after its 20-byte header, entries of
    [size, crc32, time (8 bytes), type, path NUL, …], a copy's (type 3) source path second."""
    out: dict[bytes, int] = {}
    pos = 20
    if not data.startswith(b"\xda\x1ajour"):
        return out
    while pos + 21 <= len(data) and len(out) < GVFS_PATHS_MAX:
        size = int.from_bytes(data[pos:pos + 4], "big")
        if size < 21 or pos + size > len(data):
            break
        first, _nul, rest = data[pos + 17:pos + size].partition(b"\0")
        out[first] = out.get(first, 0) + 1
        if data[pos + 16] == 3:
            source = rest.partition(b"\0")[0]
            out[source] = out.get(source, 0) + 1
        pos += size
    return out


def _gvfs_tree(data: bytes) -> set[bytes]:
    """The paths in a GVFS metadata database: from the root entry its header points to, entries of [name,
    children, metadata, time] (offsets, big-endian), the children a count and their entries."""
    out: set[bytes] = set()
    if not data.startswith(b"\xda\x1ameta") or len(data) < 32:
        return out
    stack, seen = [(int.from_bytes(data[16:20], "big"), None)], set()
    while stack and len(out) < GVFS_PATHS_MAX:
        at, parent = stack.pop()
        if at in seen or at + 16 > len(data):
            continue
        seen.add(at)
        name_at, children = int.from_bytes(data[at:at + 4], "big"), int.from_bytes(data[at + 4:at + 8], "big")
        end = data.find(b"\0", name_at) if name_at < len(data) else -1
        if end == -1:
            continue
        path = b"" if parent is None else parent + b"/" + data[name_at:end]
        if parent is not None:
            out.add(path)
        if children and children + 4 <= len(data):
            count = min(int.from_bytes(data[children:children + 4], "big"), (len(data) - children - 4) // 16)
            stack.extend((children + 4 + 16 * k, path) for k in range(count))
    return out


def folders_only(path: str) -> str:
    """A path's folder, for messages that must not name the file."""
    return str(Path(path).parent)
