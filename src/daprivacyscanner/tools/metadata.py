"""Remove metadata (docs/TECHNICAL.md, Tools): what a file carries besides what you see in it (where a photo
was taken, who wrote a document, which camera or computer made it, with what software, when), and a
cleaned copy made with mat2 beside it. The original is never changed.

Reading uses exiftool when it is installed (`-json`: every tag, grouped), else mat2's own list
(`mat2 --show`). Cleaning is mat2 only: exiftool can't clean every format (in a PDF its edits can be
undone), mat2 can. Both are the host's programs; neither is bundled.

mat2 (0.15, read from its source): `--show` prints "[+] Metadata for FILE:" then "    key: value"
lines (a nested file of an archive or document gets "[++] Metadata for MEMBER:" and two more spaces),
or "  No metadata found in FILE."; problems are "[-] ..." lines. Cleaning writes FILE.cleaned.EXT
beside the original (FILE.cleaned.tar.gz for a .tar.gz). For a PDF, the normal mode redraws every
page as an image (text can no longer be selected or searched); --lightweight redraws the pages
keeping their text, and removes less.

Many files and folders (`collect`, `show_many`, `clean_many`): the user may choose files, folders or
both. A folder is walked without following links or entering other mounts, hidden files left out
unless asked, at most MAX_FILES files. Both programs take many files in one call, so they are run in
batches (perl's and python's start-up would otherwise dominate). mat2 decides what it can clean by
the file name's type (mimetypes.guess_type, libmat2/parser_factory.py), and `mat2 --list` prints those
types with their extensions: `cleanable` tells beforehand, from the name, as mat2 will. A file chosen
on its own is cleaned beside itself, as above; the files of a chosen folder go into a new folder beside
it, "NAME (cleaned)", with the same subfolders and only the cleaned copies (a file mat2 can't clean
is left out and listed, so nothing in it passes for clean). They are cleaned from copies in a hidden
working folder inside that new folder (no extended attributes copied: browsers keep a download's
address in one), so mat2 never writes into the user's folder.

The Outbox: `run_outbox` cleans every file put in ~/Outbox into ~/Outbox/Cleaned and moves the
original to ~/Outbox/Originals (nothing is deleted); a file mat2 can't clean goes to
~/Outbox/Not cleaned. A user path unit runs it (`daprivacyscanner --outbox`) when files arrive."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from ..host import Host

MAX_VALUE = 300
TIMEOUT = 300

# what each kind of tag gives away, first match wins (tag names, case-insensitive)
GROUPS = [
    ("location", "Where it was made", re.compile(r"gps|location|latitude|longitude|altitude|city|country|"
                                                r"sub-?location|province|state$|geo", re.I)),
    ("people", "Who made or edited it", re.compile(r"author|creator$|artist|owner|by-?line|last-?modified-?by|"
                                                  r"company|manager|contributor|publisher|rights|copyright|"
                                                  r"initials|user-?name|^user$|writer|editor|xpauthor", re.I)),
    ("device", "The camera, phone or computer", re.compile(r"^make$|model|serial|lens|camera|host-?computer|"
                                                          r"device|uniquecameramodel|bodyserial|imageuniqueid", re.I)),
    ("software", "Software that made or edited it", re.compile(r"software|producer|creatortool|creator-?tool|"
                                                              r"application|app-?version|generator|history|"
                                                              r"template|encoder|writing-?app", re.I)),
    ("dates", "Dates and times", re.compile(r"date|time|created|modified|printed", re.I)),
    ("text", "Titles, comments and descriptions", re.compile(r"comment|description|title|subject|keyword|"
                                                            r"caption|headline|notes?$|label|instructions", re.I)),
]
GROUP_TITLES = {g: t for g, t, _ in GROUPS} | {"other": "Other"}
# exiftool groups that describe the file on disk or exiftool itself, not what the file carries
EXIFTOOL_SKIP_GROUPS = {"System", "ExifTool", "Composite"}
WARN_GROUPS = ("location", "people", "device")
EXIFTOOL_SKIP_TAGS = {"SourceFile", "FileType", "FileTypeExtension", "MIMEType", "ExifByteOrder", "ImageWidth",
                      "ImageHeight", "EncodingProcess", "BitsPerSample", "ColorComponents", "YCbCrSubSampling",
                      "CurrentIPTCDigest"}
SKIP_NAMES = re.compile(r"(^\.|\.part$|\.crdownload$|\.download$|\.tmp$|~$|\.swp$)", re.I)
OUTBOX, CLEANED, ORIGINALS, NOT_CLEANED = "Outbox", "Cleaned", "Originals", "Not cleaned"


@dataclass
class Item:
    key: str
    value: str
    group: str
    member: str = ""               # inside an archive or document: which member


@dataclass
class FileMeta:
    path: Path
    items: list[Item] = field(default_factory=list)
    tool: str = ""                 # "exiftool" or "mat2"
    error: str = ""
    supported: bool = True         # mat2 knows the format (when mat2 read it)

    def to_dict(self) -> dict:
        groups: dict[str, list] = {}
        for it in self.items:
            groups.setdefault(it.group, []).append({"key": it.key, "value": it.value, "member": it.member})
        order = [g for g, _, _ in GROUPS] + ["other"]
        return {"path": str(self.path), "name": self.path.name, "tool": self.tool, "error": self.error,
                "supported": self.supported, "count": len(self.items),
                "groups": [{"id": g, "title": GROUP_TITLES[g], "items": groups[g]} for g in order if g in groups]}


    def summary(self, rel: str = "", root: Path | None = None, cleanable: bool | None = None) -> dict:
        """What the page lists for each of many files: each group's count and its first few items (the
        rest on request, `to_dict` of a `show`)."""
        groups: dict[str, list[Item]] = {}
        for it in self.items:
            groups.setdefault(it.group, []).append(it)
        order = [g for g, _, _ in GROUPS] + ["other"]
        if not self.supported:
            cleanable = False
        return {"path": str(self.path), "name": self.path.name, "rel": rel or self.path.name,
                "root": str(root) if root else None, "tool": self.tool, "error": self.error,
                "supported": self.supported, "cleanable": cleanable, "count": len(self.items),
                "groups": [{"id": g, "title": GROUP_TITLES[g], "count": len(groups[g]),
                            "sample": [{"key": it.key, "value": it.value, "member": it.member}
                                       for it in groups[g][:SAMPLES if g in WARN_GROUPS else 2]]}
                           for g in order if g in groups]}


def group_of(key: str, member: str = "", tool: str = "exiftool") -> str:
    # a PDF's Creator is the program that made it: exiftool's PDF:Creator, mat2's bare "creator" at the top (a PDF's
    # metadata; inside a document's member it is a person, as dc:creator is)
    if key == "PDF:Creator" or (tool == "mat2" and key == "creator" and not member):
        return "software"
    bare = key.split(":")[-1]
    return next((g for g, _, rx in GROUPS if rx.search(bare)), "other")


def _short(v) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    s = "".join(ch for ch in s if ch.isprintable())
    return s if len(s) <= MAX_VALUE else s[:MAX_VALUE] + "…"


def parse_exiftool(out: str) -> list[Item]:
    """`exiftool -json -G1 -a -s` output: one object per file, keys "Group:Tag"."""
    return [it for items, _ in parse_exiftool_files(out).values() for it in items]


def parse_exiftool_files(out: str) -> dict[str, tuple[list[Item], str]]:
    """The same for many files: {SourceFile: (items, exiftool's error about it)}."""
    try:
        data = json.loads(out)
    except ValueError:
        return {}
    files: dict[str, tuple[list[Item], str]] = {}
    for obj in data if isinstance(data, list) else []:
        if not isinstance(obj, dict):
            continue
        items = []
        for k, v in obj.items():
            grp, _, tag = k.rpartition(":")
            if grp in EXIFTOOL_SKIP_GROUPS or tag in EXIFTOOL_SKIP_TAGS or (grp == "File" and tag.startswith("File")):
                continue
            key = f"{grp}:{tag}" if grp else tag
            items.append(Item(key, _short(v), group_of(key)))
        error = obj.get("ExifTool:Error") or obj.get("Error") or ""
        files[str(obj.get("SourceFile", ""))] = (items, "" if items else _short(error))
    return files


_SHOW_HEAD = re.compile(r"^\[(\++)\] Metadata for (.*):$")


def parse_mat2_show(out: str, filename: str) -> tuple[list[Item], bool, str]:
    """(items, whether mat2 supports the format, its complaint) from `mat2 --show FILE`."""
    items, member, error = [], "", ""
    for line in out.splitlines():
        m = _SHOW_HEAD.match(line.strip())
        if m:
            member = "" if len(m.group(1)) == 1 else m.group(2)
            continue
        if line.startswith("[-] "):
            error = line[4:].strip()
            if filename.startswith("/"):
                error = error.replace(filename, os.path.basename(filename))    # the page shows the file's name
            continue
        if "No metadata found" in line:
            continue
        k, sep, v = line.strip().partition(": ")
        if sep and k:
            items.append(Item(k, _short(v), group_of(k, member, "mat2"), member))
    return items, "is not supported" not in error, error


def parse_mat2_show_files(out: str, paths: list[str]) -> dict[str, tuple[list[Item], bool, str]]:
    """`mat2 --show A B C`: {path: (items, supported, complaint)} for each of `paths` mat2 spoke of.
    mat2 names each file as it was given (in no particular order); a file whose name it couldn't print
    as given (control characters) is left out, to be read on its own."""
    known = set(paths)
    longest = sorted(paths, key=len, reverse=True)
    out_: dict[str, tuple[list[Item], bool, str]] = {}
    cur, member = None, ""
    for line in out.splitlines():
        s = line.strip()
        m = _SHOW_HEAD.match(s)
        if m:
            if len(m.group(1)) == 1:
                cur, member = (m.group(2) if m.group(2) in known else None), ""
                if cur is not None:
                    out_.setdefault(cur, ([], True, ""))
            else:
                member = m.group(2)
            continue
        if line.startswith("[-] "):
            body = line[4:].strip()
            p = next((n for n in longest if body.startswith(n) or f" {n}" in body), None)
            if p is not None:
                said = body.replace(p, os.path.basename(p))                  # the page shows the file's name
                out_[p] = (out_.get(p, ([], True, ""))[0], "is not supported" not in body, said)
            cur = None
            continue
        if line.startswith("  No metadata found in ") and not line.startswith("   "):
            name = s[len("No metadata found in "):-1]
            if name in known:
                out_.setdefault(name, ([], True, ""))
            cur = None
            continue
        if cur is not None and "No metadata found" not in line:
            k, sep, v = s.partition(": ")
            if sep and k:
                out_[cur][0].append(Item(k, _short(v), group_of(k, member, "mat2"), member))
    return out_


def show(host: Host, path: Path) -> FileMeta:
    """What the file carries. Reads it; changes nothing."""
    path = Path(path)
    if host.runner.which("exiftool"):
        r = host.run("exiftool", "-json", "-G1", "-a", "-s", "-q", "--", str(path), timeout=TIMEOUT)
        if r.ok or r.stdout.strip().startswith("["):
            return FileMeta(path, parse_exiftool(r.stdout), "exiftool")
        return FileMeta(path, [], "exiftool", error=(r.stderr or r.stdout).strip()[:300] or "exiftool couldn't read it")
    if host.runner.which("mat2"):
        r = host.run("mat2", "--show", "--", str(path), timeout=TIMEOUT)
        items, supported, error = parse_mat2_show(r.stdout + r.stderr, str(path))
        return FileMeta(path, items, "mat2", error=error, supported=supported)
    return FileMeta(path, [], "", error="Reading metadata needs exiftool or mat2, and neither is installed.")


def cleaned_name(path: Path) -> Path:
    """Where mat2 writes the cleaned copy: photo.jpg -> photo.cleaned.jpg (a .tar.gz keeps both)."""
    stem, ext = os.path.splitext(str(path))
    if stem.endswith(".tar") and len(stem) > 4:
        stem, ext = stem[:-4], ".tar" + ext
    return Path(stem + ".cleaned" + ext)


@dataclass
class CleanResult:
    path: Path
    ok: bool
    output: Path | None = None
    message: str = ""
    remaining: FileMeta | None = None

    def to_dict(self) -> dict:
        return {"path": str(self.path), "name": self.path.name, "ok": self.ok,
                "output": str(self.output) if self.output else None,
                "output_name": self.output.name if self.output else None, "message": self.message,
                "remaining": self.remaining.to_dict() if self.remaining else None}


TMP_PREFIX = ".daprivacyscanner-mat2-"


@contextlib.contextmanager
def _tmp_beside(folder: Path, runtime: str | None = None):
    """mat2's temporary files in a hidden folder of the app's own beside what it cleans, on that file's filesystem
    (the RAM disk, for the browser's files), removed afterwards: left to itself it writes them to /tmp, on the disk on
    Debian, Ubuntu and Mint, and a document's parts (an office file's or EPUB's every member, a PDF's pages as images,
    an audio file's cover) would stay there in free space after it deletes them (mat2 0.15: archive.py, pdf.py,
    audio.py). Yields the environment to add; nothing where the folder can't be written to (mat2's own default then).

    mat2 reaches that folder by a short name, a link in `runtime` ($XDG_RUNTIME_DIR, the user's own and in memory): with
    Python 3.14 its worker processes start through a socket made in TMPDIR, and a socket's path may be 107 bytes at
    most, which a hidden folder beside a file in some folder of the user's soon exceeds (mat2 then failed with
    "AF_UNIX path too long": seen on CachyOS, Python 3.14.7, mat2 0.15). The files still land beside what is cleaned."""
    try:
        tmp = Path(tempfile.mkdtemp(prefix=TMP_PREFIX, dir=folder))
    except OSError:
        yield {}
        return
    link = None
    if runtime and os.path.isdir(runtime):
        try:
            link = Path(tempfile.mktemp(prefix="dps-", dir=runtime))      # a name only: the link is made, never a file
            os.symlink(tmp, link)
        except OSError:
            link = None
    try:
        yield {"TMPDIR": str(link or tmp)}
    finally:
        if link is not None:
            with contextlib.suppress(OSError):
                os.unlink(link)
        shutil.rmtree(tmp, ignore_errors=True)


def clean(host: Host, path: Path, lightweight: bool = False, check_after: bool = True) -> CleanResult:
    """A cleaned copy beside the file, made by mat2. Never overwrites anything: refuses when the
    copy's name is taken."""
    path = Path(path)
    if not host.runner.which("mat2"):
        return CleanResult(path, False, message="Cleaning needs mat2, which isn't installed.")
    out = cleaned_name(path)
    if out.exists() or out.is_symlink():
        return CleanResult(path, False, message=f"{out.name} is already there: rename or delete it first, so it "
                                                "isn't overwritten.")
    with _tmp_beside(path.parent, host.environ.get("XDG_RUNTIME_DIR")) as env:
        r = host.run("mat2", *(["--lightweight"] if lightweight else []), "--", str(path), timeout=TIMEOUT, env=env)
    problems = [ln[4:].strip().replace(str(path), path.name)            # the page shows the file's name
                for ln in (r.stdout + r.stderr).splitlines() if ln.startswith("[-] ")]
    if not out.is_file():
        said = (r.stderr or r.stdout).strip()
        if "Traceback (most recent call last)" in said:             # mat2 itself failed: its last line says how
            said = "mat2 stopped with an error: " + said.splitlines()[-1].strip()
        return CleanResult(path, False, message=problems[0] if problems else
                           said[:300] or "mat2 didn't make a cleaned copy.")
    res = CleanResult(path, True, out, "; ".join(problems))
    if check_after:
        res.remaining = show(host, out)
    return res


# ------------------------------------------------------------------ many files and folders

MAX_FILES = 5000
BATCH = 40
SAMPLES = 3
CLEANED_FOLDER = "{name} (cleaned)"
WORK_PREFIX = ".daprivacyscanner-cleaning-"
UNFINISHED = re.compile(r"(\.part|\.crdownload|\.download|\.partial)$", re.I)


class Stopped(Exception):
    """The user stopped it. `run`: what a clean-up had done by then (kept, and listed)."""
    run: "CleanRun | None" = None


@dataclass
class Chosen:
    """A file to read or clean: chosen on its own (root None) or found in the folder `root`."""
    path: Path
    root: Path | None = None

    @property
    def rel(self) -> str:
        return str(self.path.relative_to(self.root)) if self.root else self.path.name


@dataclass
class Selection:
    files: list[Chosen] = field(default_factory=list)
    folders: list[Path] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)    # why -> how many (files, or folders when they are)
    truncated: bool = False                                  # MAX_FILES reached: the rest isn't listed

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1

    def to_dict(self, host: Host) -> dict:
        return {"files": len(self.files), "folders": [host.display(f) for f in self.folders],
                "skipped": dict(self.skipped), "truncated": self.truncated, "limit": MAX_FILES}


def _mount_points() -> set[str]:
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return set()
    return {re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), ln.split()[1]) for ln in lines if len(ln.split()) > 1}


def collect(paths: list[Path], hidden: bool = False, limit: int = MAX_FILES) -> Selection:
    """The files to work on: each file chosen, and every file in each folder chosen and its
    subfolders (sorted, a folder's files before its subfolders), without following links or entering
    another mount, hidden names (and the app's own working folders) left out unless `hidden`,
    unfinished downloads always. The same file reached twice counts once. Stops at `limit`."""
    sel = Selection()
    seen: set[tuple[int, int]] = set()
    mounts = _mount_points()

    def add(p: Path, root: Path | None, st: os.stat_result) -> bool:
        if (st.st_dev, st.st_ino) in seen:
            return True
        if len(sel.files) >= limit:
            sel.truncated = True
            return False
        seen.add((st.st_dev, st.st_ino))
        sel.files.append(Chosen(p, root))
        return True

    def walk(d: Path, root: Path, depth: int) -> bool:
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            sel.skip("unreadable")
            return True
        subdirs = []
        for e in entries:
            if e.name.startswith(WORK_PREFIX) or (e.name.startswith(".") and not hidden):
                sel.skip("hidden")
                continue
            try:
                if e.is_symlink():
                    sel.skip("links")
                    continue
                st = e.stat(follow_symlinks=False)
            except OSError:
                sel.skip("unreadable")
                continue
            if stat.S_ISDIR(st.st_mode):
                subdirs.append(e)
            elif not stat.S_ISREG(st.st_mode):
                sel.skip("special")
            elif UNFINISHED.search(e.name):
                sel.skip("unfinished")
            elif not os.access(e.path, os.R_OK):
                sel.skip("unreadable")
            elif not add(Path(e.path), root, st):
                return False
        for e in subdirs:
            if os.path.realpath(e.path) in mounts:
                sel.skip("other_disks")
            elif depth >= 64:
                sel.skip("too_deep")
            elif not walk(Path(e.path), root, depth + 1):
                return False
        return True

    for p in paths:
        p = Path(p)
        try:
            st = os.stat(p)
        except OSError:
            sel.skip("unreadable")
            continue
        if stat.S_ISDIR(st.st_mode):
            sel.folders.append(p)
            if not walk(p, p, 0):
                break
        elif stat.S_ISREG(st.st_mode):
            if not add(p, None, st):
                break
        else:
            sel.skip("special")
    return sel


def mat2_formats(host: Host) -> set[str] | None:
    """The extensions mat2 cleans (`mat2 --list`: "  - image/jpeg (.jpe, .jpeg, .jpg)"), or None when
    there is no mat2 or no list."""
    if not host.runner.which("mat2"):
        return None
    r = host.run("mat2", "--list", timeout=60)
    exts = {x.strip().lower() for m in re.finditer(r"\(([^)]*)\)", r.stdout) for x in m.group(1).split(",")}
    exts = {x for x in exts if x.startswith(".")}
    return exts or None


def cleanable(name: str, formats: set[str] | None) -> bool | None:
    """Whether mat2 will clean a file of this name (it goes by the name's type), None when unknown."""
    if formats is None:
        return None
    low = name.lower()
    if re.search(r"\.tar\.(gz|bz2|xz)$", low):
        return ".tar" in formats
    return os.path.splitext(low)[1] in formats


def show_many(host: Host, paths: list[Path], progress=None, stop=None) -> list[FileMeta]:
    """`show` for many files, in batches: exiftool's JSON names each file, mat2 too. A file a batch
    didn't account for is read on its own. `progress(done, path)` after each batch; `stop()` true
    ends it (Stopped)."""
    exiftool, mat2 = host.runner.which("exiftool"), host.runner.which("mat2")
    out: list[FileMeta] = []
    for i in range(0, len(paths), BATCH):
        if stop is not None and stop():
            raise Stopped()
        batch = [Path(p) for p in paths[i:i + BATCH]]
        if exiftool:
            r = host.run("exiftool", "-json", "-G1", "-a", "-s", "-q", "--", *map(str, batch),
                         timeout=TIMEOUT + 10 * len(batch))
            got = parse_exiftool_files(r.stdout)
            for p in batch:
                if str(p) in got:
                    items, error = got[str(p)]
                    out.append(FileMeta(p, items, "exiftool", error=error))
                else:
                    out.append(show(host, p))
        elif mat2:
            r = host.run("mat2", "--show", "--", *map(str, batch), timeout=TIMEOUT + 10 * len(batch))
            got = parse_mat2_show_files(r.stdout + r.stderr, [str(p) for p in batch])
            for p in batch:
                if str(p) in got:
                    items, supported, error = got[str(p)]
                    out.append(FileMeta(p, items, "mat2", error=error, supported=supported))
                else:
                    out.append(show(host, p))
        else:
            out += [show(host, p) for p in batch]
        if progress is not None:
            progress(len(out), batch[-1])
    return out


def read_many(host: Host, sel: Selection, progress=None, stop=None) -> list[dict]:
    """Each chosen file's `summary`, in the selection's order."""
    formats = mat2_formats(host)
    metas = show_many(host, [c.path for c in sel.files], progress, stop)
    return [m.summary(c.rel, c.root, cleanable(c.path.name, formats)) for c, m in zip(sel.files, metas)]


def output_folder(folder: Path) -> Path:
    """Where a folder's cleaned copies go: "NAME (cleaned)" beside it, or "NAME (cleaned 2)"… when that
    is taken: never into a folder that is already there."""
    folder = Path(folder)
    for n in range(1, 1000):
        name = CLEANED_FOLDER.format(name=folder.name) if n == 1 else f"{folder.name} (cleaned {n})"
        target = folder.parent / name
        if not (target.exists() or target.is_symlink()):
            return target
    raise OSError(f"There are too many folders named like {folder.name} (cleaned) already.")


@dataclass
class Cleaned:
    chosen: Chosen
    ok: bool
    output: Path | None = None
    message: str = ""
    remaining: FileMeta | None = None


@dataclass
class CleanRun:
    results: list[Cleaned] = field(default_factory=list)
    outputs: dict[Path, Path | None] = field(default_factory=dict)      # chosen folder -> its cleaned folder

    def to_dict(self, host: Host) -> dict:
        return {
            "results": [{"path": str(r.chosen.path), "name": r.chosen.path.name, "rel": r.chosen.rel,
                         "root": str(r.chosen.root) if r.chosen.root else None, "ok": r.ok,
                         "output": host.display(r.output) if r.output else None,
                         "output_name": r.output.name if r.output else None, "message": r.message,
                         "remaining": r.remaining.summary(r.chosen.rel) if r.remaining else None}
                        for r in self.results],
            "folders": [{"folder": host.display(f), "output": host.display(o) if o else None, "output_path": str(o) if o else None}
                        for f, o in self.outputs.items()],
            "cleaned": sum(r.ok for r in self.results), "failed": sum(not r.ok for r in self.results)}


def _problems(text: str, path: str) -> str:
    lines = [ln[4:].strip().replace(path, os.path.basename(path)) for ln in text.splitlines()
             if ln.startswith("[-] ") and path in ln]
    return "; ".join(lines)


def _mat2(host: Host, lightweight: bool, files: list[Path]):
    with _tmp_beside(files[0].parent, host.environ.get("XDG_RUNTIME_DIR")) as env:
        return host.run("mat2", *(["--lightweight"] if lightweight else []), "--", *map(str, files),
                        timeout=TIMEOUT + 30 * len(files), env=env)


def clean_many(host: Host, files: list[Chosen], lightweight: bool = False, progress=None, stop=None,
               check_after: bool = True) -> CleanRun:
    """Cleaned copies of `files`: beside each file chosen on its own (as `clean`), and for the files of
    a chosen folder, into a new folder beside it (`output_folder`) with the same subfolders. A file mat2
    can't clean gets no copy. `progress(done, path)`; `stop()` true ends it after the batch (Stopped,
    with what was cleaned so far kept and listed in `run`)."""
    run = CleanRun()
    if not host.runner.which("mat2"):
        run.results = [Cleaned(c, False, message="Cleaning needs mat2, which isn't installed.") for c in files]
        return run
    done = 0

    def tick(batch):
        nonlocal done
        done += len(batch)
        if progress is not None:
            progress(done, batch[-1].path)

    def check():
        if stop is not None and stop():
            raise Stopped()

    singles = [c for c in files if c.root is None]
    for i in range(0, len(singles), BATCH):
        if stop is not None and stop():
            raise _stopped(run)
        batch, todo = singles[i:i + BATCH], []
        for c in batch:
            out = cleaned_name(c.path)
            if out.exists() or out.is_symlink():
                run.results.append(Cleaned(c, False, message=f"{out.name} is already there: rename or delete it "
                                                             "first, so it isn't overwritten."))
            else:
                todo.append(c)
        r = _mat2(host, lightweight, [c.path for c in todo]) if todo else None
        for c in todo:
            out = cleaned_name(c.path)
            if out.is_file():
                run.results.append(Cleaned(c, True, out, _problems(r.stdout + r.stderr, str(c.path))))
            else:
                run.results.append(Cleaned(c, False, message=_problems(r.stdout + r.stderr, str(c.path))
                                           or "mat2 didn't make a cleaned copy."))
        tick(batch)

    roots: dict[Path, list[Chosen]] = {}
    for c in files:
        if c.root is not None:
            roots.setdefault(c.root, []).append(c)
    try:
        for root, mine in roots.items():
            check()
            _clean_folder(host, root, mine, lightweight, run, tick, check)
    except Stopped as e:
        e.run = run
        raise

    if check_after:
        made = [r for r in run.results if r.ok and r.output]
        try:
            metas = show_many(host, [r.output for r in made], stop=stop)
        except Stopped:
            raise _stopped(run) from None
        for r, meta in zip(made, metas):
            r.remaining = meta
    return run


def _stopped(run: CleanRun) -> Stopped:
    e = Stopped()
    e.run = run
    return e


def _clean_folder(host: Host, root: Path, files: list[Chosen], lightweight: bool, run: CleanRun, tick, check) -> None:
    parent = root.parent
    if not os.access(parent, os.W_OK | os.X_OK):
        run.outputs[root] = None
        msg = f"You can't write to {host.display(parent)}, where the cleaned folder would go."
        run.results += [Cleaned(c, False, message=msg) for c in files]
        tick(files)
        return
    out_root = output_folder(root)
    os.mkdir(out_root, 0o777)
    run.outputs[root] = out_root
    work = out_root / f"{WORK_PREFIX}{os.urandom(6).hex()}"
    os.mkdir(work, 0o700)
    try:
        for i in range(0, len(files), BATCH):
            check()
            batch = files[i:i + BATCH]
            try:
                need = sum(c.path.stat().st_size for c in batch) * 2 + (16 << 20)
            except OSError:
                need = 16 << 20
            free = os.statvfs(out_root)
            if need > free.f_bavail * free.f_frsize:
                left = files[i:]
                run.results += [Cleaned(c, False, message=f"There isn't room in {host.display(parent)} for the "
                                                          "cleaned copies.") for c in left]
                tick(left)
                return
            copies: list[tuple[Chosen, Path | None, str]] = []
            for n, c in enumerate(batch):
                slot = work / str(i + n)
                os.mkdir(slot, 0o700)
                copy = slot / c.path.name
                try:
                    shutil.copyfile(c.path, copy, follow_symlinks=False)      # contents only: no extended attributes
                    shutil.copymode(c.path, copy)
                    copies.append((c, copy, ""))
                except OSError as e:
                    copies.append((c, None, f"It couldn't be read: {e.strerror or e}."))
            todo = [p for _, p, _ in copies if p is not None]
            r = _mat2(host, lightweight, todo) if todo else None
            for c, copy, err in copies:
                if copy is None:
                    run.results.append(Cleaned(c, False, message=err))
                    continue
                cleaned = cleaned_name(copy)
                said = _problems(r.stdout + r.stderr, str(copy))
                if not cleaned.is_file() or cleaned.is_symlink():
                    run.results.append(Cleaned(c, False, message=said or "mat2 didn't make a cleaned copy."))
                    continue
                dest = out_root / c.rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest = _free_name(dest.parent, dest.name)
                os.rename(cleaned, dest)
                run.results.append(Cleaned(c, True, dest, said))
            for n in range(len(batch)):
                shutil.rmtree(work / str(i + n), ignore_errors=True)
            tick(batch)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        try:
            next(out_root.iterdir())
        except StopIteration:
            out_root.rmdir()                       # nothing could be cleaned: no empty folder left behind
            run.outputs[root] = None
        except OSError:
            pass


# ------------------------------------------------------------------ installing what it needs

PACKAGES = {"mat2": {"debian": "mat2", "fedora": "mat2", "arch": "mat2", "suse": "mat2"},
            "exiftool": {"debian": "libimage-exiftool-perl", "fedora": "perl-Image-ExifTool",
                         "arch": "perl-image-exiftool", "suse": "exiftool"}}


def install_command(host: Host, program: str) -> str | None:
    from ..checks.guides import install
    return install(SimpleNamespace(host=host), **PACKAGES[program])


def status(host: Host) -> dict:
    return {p: {"installed": host.runner.which(p), "install": install_command(host, p)} for p in PACKAGES}


# ------------------------------------------------------------------ the Outbox

def outbox_dir(home: Path) -> Path:
    return Path(home) / OUTBOX


def _free_name(folder: Path, name: str) -> Path:
    """`name` in `folder`, or "name (2).ext" and so on when it is taken: nothing is overwritten."""
    target = folder / name
    stem, ext = os.path.splitext(name)
    n = 2
    while target.exists() or target.is_symlink():
        target = folder / f"{stem} ({n}){ext}"
        n += 1
    return target


@dataclass
class OutboxRun:
    cleaned: list[str] = field(default_factory=list)
    not_cleaned: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def run_outbox(host: Host, folder: Path | None = None, settle: float = 2.0) -> OutboxRun:
    """Each file put directly in the Outbox: copied into a private temporary folder (in memory where
    there is one), cleaned there, the clean copy moved to Cleaned/ and the original to Originals/.
    A file mat2 can't clean goes to "Not cleaned/". Files still being written (changed in the last
    `settle` seconds), hidden files and partial downloads are left for the next run."""
    folder = Path(folder) if folder else outbox_dir(host.home)
    run = OutboxRun()
    if not folder.is_dir() or folder.is_symlink():
        return run
    base = host.environ.get("XDG_RUNTIME_DIR")
    for entry in sorted(folder.iterdir()):
        if entry.is_symlink() or not entry.is_file() or SKIP_NAMES.search(entry.name):
            continue
        try:
            if time.time() - entry.stat().st_mtime < settle:
                run.skipped.append(entry.name)
                continue
        except OSError:
            continue
        # the working copy goes in the runtime folder (memory); without one, in a hidden folder inside the Outbox,
        # beside the original, never in /tmp on the disk (the path unit ignores hidden names and folders)
        with tempfile.TemporaryDirectory(prefix="daprivacyscanner-outbox-" if base and os.path.isdir(base) else
                                         ".daprivacyscanner-outbox-",
                                         dir=base if base and os.path.isdir(base) else folder) as tmp:
            work = Path(tmp) / entry.name
            shutil.copy2(entry, work)
            res = clean(host, work, check_after=False)
            if res.ok and res.output:
                (folder / CLEANED).mkdir(mode=0o700, exist_ok=True)
                (folder / ORIGINALS).mkdir(mode=0o700, exist_ok=True)
                shutil.move(str(res.output), _free_name(folder / CLEANED, entry.name))
                shutil.move(str(entry), _free_name(folder / ORIGINALS, entry.name))
                run.cleaned.append(entry.name)
            else:
                (folder / NOT_CLEANED).mkdir(mode=0o700, exist_ok=True)
                shutil.move(str(entry), _free_name(folder / NOT_CLEANED, entry.name))
                run.not_cleaned.append((entry.name, res.message))
    return run


# how long one run stays for files still being written (a large copy) before leaving them for the next
OUTBOX_WAIT = 900.0


def run_outbox_settled(host: Host, folder: Path | None = None, settle: float = 2.0, wait: float = OUTBOX_WAIT,
                       sleep=time.sleep) -> OutboxRun:
    """What the Outbox's unit runs. systemd starts it the moment a file lands, when that file is younger than `settle`,
    and doesn't start it again for a folder that hasn't changed since, nor for what lands while it runs: a single pass
    left the file that started it where it was (seen on Mint 22.3, where the AppImage starts within a second). So it
    goes on, a pass a second, until one finds nothing to do and nothing still settling, or `wait` is up."""
    total, deadline = OutboxRun(), time.monotonic() + wait
    while True:
        run = run_outbox(host, folder, settle)
        total.cleaned += run.cleaned
        total.not_cleaned += run.not_cleaned
        total.skipped = run.skipped
        if not (run.skipped or run.cleaned or run.not_cleaned) or time.monotonic() >= deadline:
            return total
        sleep(1.0)


def notify_outbox(host: Host, run: OutboxRun) -> None:
    """A desktop notification after a run that did something: how many, never the files' names (a notification
    daemon's history can keep them on the disk, and the lock screen can show them; the folders say which)."""
    if not (run.cleaned or run.not_cleaned) or not host.runner.which("notify-send"):
        return
    parts = []
    if run.cleaned:
        parts.append(f"{len(run.cleaned)} cleaned, in ~/Outbox/{CLEANED}")
    if run.not_cleaned:
        parts.append(f"{len(run.not_cleaned)} couldn't be cleaned (moved to ~/Outbox/{NOT_CLEANED})")
    host.run("notify-send", "--app-name=DA Privacy Kit", "--icon=document-send",
             "Outbox: " + "; ".join(parts), "The originals are in ~/Outbox/" + ORIGINALS + ".")
