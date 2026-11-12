"""Try an app (docs/TECHNICAL.md, Tools): run a program you don't know yet in a sandbox with a throwaway home,
and see what it does: what it writes, which decoy files it looks at, which hosts it contacts. Nothing of the
user's is within its reach, and nothing of the trial is kept.

What can be tried (`prepare`):
- a downloaded file: an AppImage (run with APPIMAGE_EXTRACT_AND_RUN, since it can't mount itself in a sandbox),
  a program, a script. It is copied into the trial's folder; the original isn't touched or run;
- an archive (tar, zip): unpacked inside a sandbox with no network, then the user picks the program in it;
- a .deb: unpacked the same way, never installed; its /usr is laid over the computer's inside the sandbox (an
  overlay: bubblewrap's own from 0.10, which works under Ubuntu's AppArmor profile for bubblewrap, tested on Ubuntu
  26.04; with bubblewrap 0.9, which has none, mounted by a first bubblewrap that is root of its own user namespace,
  then the real sandbox inside it, tested on Mint 22.3) and its /opt put at /opt, so the program finds its files
  where it expects them. What it depends on isn't installed for it;
- an installed app from the menu, with a throwaway home: what it does on a first run, without the real profile;
- a Flatpak app: in Flatpak's own sandbox with what it declares for itself dropped (`flatpak run --sandbox`) and
  only what the trial grants put back, HOME pointing at the throwaway home, so its data goes there and "home"
  is the made-up one (tested with Flatpak 1.14 on Mint 22.3: the real /home isn't there).

The sandbox (the `bubblewrap` engine; engines sit behind ENGINES so another can be added, see ROADMAP.md for
the microVM): tools/sandbox.py's pieces, as the browser's and the viewer's: every namespace, no capabilities, a
new session, an environment built from scratch, /usr read-only, the computer's /etc with what names the user or
computer covered, the throwaway home at /home/user, the program read-only at /app, the display (on Wayland a
socket the compositor marks as a sandbox's where it can; on X11 the X server's, or Xephyr when asked), no
session D-Bus, keyring or agents. The graphics card when ticked (on by default: a trial should feel as the app
would), sound when ticked. The network: none, or its own through pasta, fenced off from the local network,
with the packets summed up as hosts contacted (tools/pcap.py); never the computer's own network. A Flatpak
can't be put behind pasta (it would run as root of pasta's namespace): none, or its usual network, unobserved.

What is watched (tools/homewatch.py, inotify, no administrator access): everything the program does in the
throwaway home, and the decoys there (tools/bait.py): made-up SSH keys, browser profiles, wallets, documents.
A program that opens them has gone looking.

The trial's folder is in memory ($XDG_RUNTIME_DIR, a tmpfs) or, for something large, on the disk
($XDG_CACHE_HOME); discarding overwrites and deletes it in memory, and only deletes it on the disk (rule 8: that
doesn't erase it, and the page says so). In memory it is ended before it fills the runtime folder, which the whole
session uses (RoomWatch). One trial at a time; quitting the app ends and discards it."""

from __future__ import annotations

import fcntl
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..fix import make_writable
from ..host import Host
from ..hostenv import host_env
from . import activity, bait, homewatch, menu, pcap, ramdisk, sandbox, seccomp, wayland
from .viewer import _program, flatpak_open

FOLDER = "daprivacyscanner-trial"
APP_IN = "/app"
COPY_MAX = 8 << 30                       # the largest file copied in
UNPACK_MAX = 8 << 30                     # the most an archive may unpack to (and no more than there is room for)
MEMBERS_MAX = 200000                     # the most files and folders it may unpack to
ROOM_KEPT = 128 << 20                    # what unpacking leaves free where it unpacks (the runtime folder is the session's),
                                         # and a trial in memory while it runs: it is ended when less is left (RoomWatch)
ROOM_EVERY = 1.0                         # seconds between looks at the room left, while a trial in memory runs
ROOM_WORDS = "was ended here: the memory it runs in, which your whole session shares, was nearly full"
CANDIDATES_MAX = 60
OUTPUT_KEPT = 16000                      # the last of the program's own output, shown when it fails
START_WAIT = 2.0
NESTED_WAIT = 5.0
FLATPAK_OWN = (".local/share/flatpak", ".cache/flatpak")    # Flatpak's own folders in the made-up home: not the app's
# what a trial's home must not be on for a program to run from it
ST_NOEXEC = 8


class TrialError(ValueError):
    pass


CURRENT: "Trial | None" = None           # the trial there is (the server sets it): what a Box can be made from


# ------------------------------------------------------------------ what is being tried

@dataclass
class Subject:
    kind: str                            # appimage, program, script, archive, deb
    what: str                            # in words
    problem: str = ""                    # why it can't be tried


def classify(path: Path) -> Subject:
    """What a file is, by its first bytes (and its name for an archive's kind or a script without #!)."""
    name = path.name.lower()
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as e:
        return Subject("unknown", "a file", f"It can't be read ({e.strerror}).")
    if head.startswith(b"!<arch>\ndebian-binary"):
        return Subject("deb", "a Debian package (.deb)")
    if head.startswith(b"\x7fELF"):
        if head[8:11] == b"AI\x02":
            return Subject("appimage", "an AppImage")
        if head[8:11] == b"AI\x01" or (name.endswith(".appimage") and head[8:10] != b"AI"):
            return Subject("appimage", "an AppImage of the old kind (type 1)",
                           "It can only start by mounting itself, which a sandbox doesn't allow. Ask its maker for "
                           "a current AppImage (type 2), or unpack it yourself and try the folder as an archive.")
        return Subject("program", "a Linux program")
    if head.startswith(b"#!"):
        return Subject("script", "a script")
    if head[257:262] == b"ustar" or head.startswith((b"\x1f\x8b", b"\xfd7zXZ\x00", b"BZh", b"\x28\xb5\x2f\xfd")):
        return Subject("archive", "an archive")
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        if name.endswith((".jar", ".apk", ".docx", ".xlsx", ".odt", ".epub")):
            return Subject("unknown", "not a program", "It isn't a program or an archive of one that this can run.")
        return Subject("archive", "a ZIP archive")
    if name.endswith((".py", ".sh")) and b"\0" not in head:
        return Subject("script", "a script")
    if head.startswith(b"MZ"):
        return Subject("unknown", "a Windows program", "It is a Windows program, which doesn't run here.")
    return Subject("unknown", "not a program this recognises",
                   "It isn't an AppImage, a Linux program, a script, an archive or a .deb.")


def safe_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._+-]", "_", name).lstrip(".-") or "program"
    return clean[:120]


# ------------------------------------------------------------------ where a trial lives

def places(host: Host) -> list[dict]:
    """Where a trial's folder can be: in memory (the runtime folder, a tmpfs) and on the disk (the cache
    folder), each with its room and whether programs can run from it."""
    from ..paths import PathResolver
    runtime = host.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{host.uid}"
    out = []
    for pid, base, words in (("memory", Path(runtime), "In memory"),
                             ("disk", PathResolver(host.home, host.environ).cache_home, "On the disk")):
        p = base if str(base).startswith(str(host.home)) else host.sys_path(str(base))
        there = p
        while not there.exists() and there != there.parent:      # a cache folder not made yet: its filesystem's room
            there = there.parent
        try:
            vfs = os.statvfs(there)
        except OSError:
            continue
        out.append({"id": pid, "words": words, "folder": str(p / FOLDER), "free": vfs.f_bavail * vfs.f_frsize,
                    "noexec": bool(vfs.f_flag & ST_NOEXEC)})
    return out


def _place(host: Host, where: str) -> dict:
    found = next((p for p in places(host) if p["id"] == where), None)
    if found is None:
        raise TrialError("That place for the trial isn't available here.")
    return found


# ------------------------------------------------------------------ a trial

@dataclass
class Trial:
    id: str
    folder: Path                         # holds home, app and private; the app's own, 0700
    where: str                           # memory, disk
    kind: str                            # appimage, program, script, archive, deb, installed, flatpak
    name: str
    what: str
    argv: list[str] = field(default_factory=list)       # inside the sandbox (or `flatpak run …` on the computer)
    prepared: list[str] | None = None    # argv before the arguments the user gives: each start's choose() adds them to it
    candidates: list[dict] = field(default_factory=list)
    flatpak: str | None = None
    host_opt: bool = False               # the computer's /opt, read-only (an installed app that lives there)
    env: dict[str, str] = field(default_factory=dict)
    state: str = "ready"                 # ready, running, ended
    options: dict = field(default_factory=dict)
    how: dict = field(default_factory=dict)
    decoys: dict[str, str] = field(default_factory=dict)
    started: float | None = None
    ended: float | None = None
    exit: int | None = None
    stopped: bool = False
    result: dict | None = None
    notes: list[str] = field(default_factory=list)
    private_at: Path | None = None       # a Box's: the sandbox's own files in the runtime folder, not in the Box
    binds: list[tuple[str, str]] = field(default_factory=list)      # a Box's: (a folder, where it is inside), writable
    portal_before: dict | None = None    # a Flatpak trial's: the autostart folder and the portals' records at the start
    short_of_room: int | None = None     # ended for it (RoomWatch): the room that was left in the runtime folder
    nesting: str | None = None           # why it looks like a program that starts sandboxes of its own (seccomp.nesting_reason)
    # while it runs
    proc: Any = None                     # a Popen (or what tests give): used through poll, pid, wait, stdout
    xephyr: Any = None
    watch: homewatch.HomeWatch | None = None
    shared: list[homewatch.HomeWatch] = field(default_factory=list)      # a Box's: its Exchange folder's (binds)
    flows: pcap.Flows | None = None
    output: "Tail | None" = None
    reader: "PipeReader | None" = None
    room: "RoomWatch | None" = None
    lock: threading.Lock = field(default_factory=threading.Lock)     # ending it (stop, poll, discard) happens once

    @property
    def home(self) -> Path:
        return self.folder / "home"

    @property
    def app(self) -> Path:
        return self.folder / "app"

    @property
    def private(self) -> Path:
        return self.private_at or self.folder / "private"

    def view(self) -> dict:
        live, watch, flows = None, self.watch, self.flows      # taken once: a finish in another thread drops them
        if self.state == "running" and watch is not None:
            live = {**watch.counts(), "decoys_seen": watch.decoys()[:12],
                    "hosts": flows.result()["hosts"][:12] if flows is not None else None}
        return {"id": self.id, "kind": self.kind, "name": self.name, "what": self.what, "where": self.where,
                "state": self.state, "command": shlex.join(self.argv) if self.argv else "",
                "candidates": [{k: v for k, v in c.items() if k != "real"} for c in self.candidates],
                "options": self.options, "how": self.how, "started": self.started, "ended": self.ended,
                "exit": self.exit, "stopped": self.stopped, "notes": self.notes, "live": live, "result": self.result,
                "nesting": self.nesting, "now": time.time()}


# Each trial's folder is locked (flock on the folder itself) by the copy of the app that made it, for as long as that
# copy runs: every right-click entry starts a copy of its own, and one clearing leftovers removed a trial another was
# running. A folder no running copy holds is a leftover; the kernel lets go of the lock however the copy ended.
_HELD: dict[str, int] = {}


def _hold(folder: Path) -> int | None:
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _let_go(folder: Path) -> None:
    fd = _HELD.pop(str(folder), None)
    if fd is not None:
        os.close(fd)


def _make(host: Host, where: str) -> tuple[str, Path]:
    place = _place(host, where)
    base = Path(place["folder"])
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    if base.is_symlink() or not base.is_dir() or base.stat().st_uid != os.getuid():
        raise TrialError("The trial's folder isn't a folder of yours.")
    os.chmod(base, 0o700)
    tid = os.urandom(6).hex()
    folder = base / tid
    folder.mkdir(mode=0o700)
    fd = _hold(folder)
    if fd is not None:
        _HELD[str(folder)] = fd
    for sub in ("home", "app", "private"):
        (folder / sub).mkdir(mode=0o700)
    return tid, folder


def leftovers(host: Host) -> list[str]:
    """Trial folders a copy of the app left that has ended (killed, crashed): removed at the next start. A folder
    a running copy holds (_HELD, this one's included) is that copy's trial, never a leftover."""
    out = []
    for place in places(host):
        base = Path(place["folder"])
        try:
            names = [n for n in os.listdir(base) if re.fullmatch(r"[0-9a-f]{12}", n)]
        except OSError:
            continue
        for n in names:
            fd = _hold(base / n)
            if fd is not None:
                os.close(fd)
                out.append(str(base / n))
    return out


def _remove(folder: Path, in_memory: bool) -> None:
    if not folder.is_dir() or folder.is_symlink():
        return
    if in_memory:
        try:
            ramdisk.wipe(folder)                      # overwritten in place: its pages are memory (rule 8)
        except OSError:
            pass
    else:
        make_writable(folder)                     # read-only folders in it (Go's module cache, a tarball's)
    shutil.rmtree(folder, ignore_errors=True)
    _remove_base(folder.parent)


def _remove_base(base: Path) -> None:
    """The trials' own folder (daprivacyscanner-trial in the runtime or cache folder), once no trial is left in it:
    nothing of a trial stays behind, not even its empty folder."""
    if base.name != FOLDER or base.is_symlink():
        return
    try:
        base.rmdir()                                  # only while empty: another trial's folder keeps it
    except OSError:
        pass


def clear_leftovers(host: Host) -> None:
    memory = {p["folder"] for p in places(host) if p["id"] == "memory"}
    for path in leftovers(host):
        _remove(Path(path), str(Path(path).parent) in memory)
    for place in places(host):                        # an empty one an earlier version left
        _remove_base(Path(place["folder"]))


# ------------------------------------------------------------------ unpacking, inside a sandbox

# runs inside the sandbox: unpacks argv[1] into argv[2], at most argv[3] bytes and argv[4] files and folders in all,
# counted before each is written (a zip by the sizes it declares, which zipfile holds it to). A .deb is an ar archive
# holding data.tar.*; tar's own filter keeps every member inside the folder (and the sandbox would anyway).
UNPACK = r"""
import io, os, subprocess, sys, tarfile, zipfile
src, dst, limit, most = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def too_much():
    sys.exit("It unpacks to more than %d MB or %d files, the most there is room for here." % (limit >> 20, most))
def tar(f):
    kw = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
    total = count = 0
    with tarfile.open(fileobj=f, mode="r|*") as t:
        for m in t:
            total, count = total + m.size, count + 1
            if total > limit or count > most:
                too_much()
            if m.isdev():
                continue
            t.extract(m, dst, **kw)
with open(src, "rb") as f:
    head = f.read(8)
    f.seek(0)
    if head == b"!<arch>\n":
        f.seek(8)
        while True:
            h = f.read(60)
            if len(h) < 60:
                sys.exit("The package holds no files (no data.tar).")
            name, size = h[:16].decode().strip().rstrip("/"), int(h[48:58])
            if name.startswith("data.tar"):
                if name.endswith(".zst") and sys.version_info < (3, 14):      # tarfile reads zstd from 3.14
                    if os.path.exists("/usr/bin/dpkg-deb"):     # its tar, through the same counts (not dpkg-deb -x)
                        p = subprocess.Popen(["/usr/bin/dpkg-deb", "--fsys-tarfile", src], stdout=subprocess.PIPE)
                        tar(p.stdout)
                        p.stdout.close()
                        sys.exit(p.wait())
                    p = subprocess.Popen(["zstd", "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    import threading
                    def pump(left=size):
                        while left > 0:
                            b = f.read(min(1 << 20, left))
                            if not b: break
                            p.stdin.write(b); left -= len(b)
                        p.stdin.close()
                    threading.Thread(target=pump, daemon=True).start()
                    tar(p.stdout)
                else:
                    tar(io.BytesIO(f.read(size)) if size < (256 << 20) else f)
                break
            f.seek(size + size % 2, 1)
    elif zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            if sum(i.file_size for i in z.infolist()) > limit or len(z.infolist()) > most:
                too_much()
            for i in z.infolist():
                out = z.extract(i, dst)
                mode = (i.external_attr >> 16) & 0o777
                if mode and not i.is_dir():
                    os.chmod(out, mode | 0o600)
    elif head[:4] == b"\x28\xb5\x2f\xfd" and sys.version_info < (3, 14):      # a .tar.zst: through zstd, as a .deb's
        try:
            p = subprocess.Popen(["zstd", "-dcq", src], stdout=subprocess.PIPE)
        except OSError:
            sys.exit("It is compressed with zstd, and unpacking it needs the zstd program (the zstd package): install "
                     "it, or unpack it yourself and try the program in it.")
        tar(p.stdout)
        p.stdout.close()
        sys.exit(p.wait())
    else:
        tar(f)
"""


def unpack_argv(host: Host, source: Path, dest: Path, limit: int = UNPACK_MAX, most: int = MEMBERS_MAX,
                filt: sandbox.Filter | None = None) -> list[str]:
    """The archive or .deb `source` unpacked into `dest` by the computer's python3 in a sandbox with no network,
    which sees only the file (read-only) and the folder: at most `limit` bytes and `most` files and folders. It ends
    with bubblewrap (--die-with-parent): at the time limit, or with the app killed, only bubblewrap was ended, and the
    unpacker went on writing into the folder removed meanwhile (the review of 2026-11-04). `filt`: its system-call
    filter (strict), whose descriptor the caller passes."""
    return [sandbox._need(host, sandbox.BWRAP), "--die-with-parent", *sandbox.namespaces(False),
            *sandbox.no_new_userns(host), *(filt.argv() if filt else []), *sandbox.system(host),
            "--ro-bind", str(source), "/in/source", "--bind", str(dest), "/out", "--chdir", "/out",
            "--setenv", "PATH", "/usr/bin:/bin", "--",
            sandbox.PYTHON, "-I", "-c", UNPACK, "/in/source", "/out", str(limit), str(most)]


def unpack_limit(place: dict) -> int:
    """The most an archive may unpack to in `place`: UNPACK_MAX, or what is free there less ROOM_KEPT, whichever is
    less. An archive that unpacks to more than it says (a "zip bomb", a .deb of the kind dpkg-deb unpacked without
    a limit) would otherwise fill the runtime folder, which the whole session uses (found in the 2026-10-17 review:
    8 GB allowed whatever was free)."""
    return max(0, min(UNPACK_MAX, place["free"] - ROOM_KEPT))


def _looks_runnable(name: str, head: bytes, mode: int) -> str | None:
    """What a file in an unpacked tree is, if it is something to start (by its name, its first bytes and its mode):
    in words, or None."""
    if head.startswith(b"\x7fELF"):
        if head[8:10] == b"AI":
            return "an AppImage"
        return "a Linux program" if mode & 0o111 and head[16:18] in (b"\x02\x00", b"\x03\x00") else None
    if head.startswith(b"#!"):
        return "a script"
    if Path(name).suffix in (".py", ".sh") and b"\0" not in head:
        return "a script"
    return None


LINKS_MAX = 40                           # links followed in resolving one path of an unpacked tree (the kernel's limit)
DESKTOP_READ = 20000                     # what is read of a menu entry in an unpacked tree


def in_tree(root: str, rel: str) -> str | None:
    """Where the path `rel` in the unpacked tree `root` leads, every part of it resolved inside the tree as it will be
    in the sandbox: a link to an absolute path (a package's /usr/bin/foo -> /opt/Foo/foo) means that path in the tree,
    never the computer's. The real path, relative to the tree, with no link left in it; None when it leaves the tree,
    isn't there, or goes through too many links. The app reads the tree outside any sandbox: only the last part was
    resolved before, so a folder linked to the computer's (usr/bin -> /usr/bin) listed the computer's own programs
    as the package's (the review of 2026-11-04)."""
    parts, links = [p for p in rel.split("/") if p not in ("", ".")], 0
    done: list[str] = []
    while parts:
        part = parts.pop(0)
        if part == "..":
            if not done:
                return None
            done.pop()
            continue
        path = os.path.join(root, *done, part)
        try:
            st = os.lstat(path)
            target = os.readlink(path) if stat.S_ISLNK(st.st_mode) else None
        except OSError:
            return None
        if target is not None:
            links += 1
            if links > LINKS_MAX:
                return None
            if target.startswith("/"):
                done = []
            parts = [p for p in target.split("/") if p not in ("", ".")] + parts
            continue
        if parts and not stat.S_ISDIR(st.st_mode):
            return None
        done.append(part)
    return "/".join(done)


def _read_in_tree(root: str, rel: str, most: int) -> tuple[bytes, int] | None:
    """The first `most` bytes of the regular file `rel` in the unpacked tree (resolved by in_tree) and its mode, or
    None: never a file outside the tree, a device or a pipe. A menu entry linked to /dev/zero was read until memory
    ran out, one linked to a pipe kept Try an app waiting for good (the review of 2026-11-04)."""
    real = in_tree(root, rel)
    if real is None:
        return None
    try:
        fd = os.open(os.path.join(root, real), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        return (os.read(fd, most), st.st_mode) if stat.S_ISREG(st.st_mode) else None
    except OSError:
        return None
    finally:
        os.close(fd)


def candidates(tree: Path, deb: bool) -> list[dict]:
    """The programs in an unpacked archive or package that the user can pick: {"rel", "what", "label", "real"}, "real"
    being where it really is in the tree (the server's: what choose() runs). A menu entry's program first (a .deb's
    /usr/share/applications), then programs near the top, every path resolved inside the tree (in_tree), never
    through a link to the computer's files."""
    found: dict[str, dict] = {}
    root = os.path.realpath(tree)

    def add(rel: str, label: str = "") -> None:
        real = in_tree(root, rel)
        if real is None or real in found or len(found) >= CANDIDATES_MAX:
            return
        if deb and not real.startswith(("usr/", "opt/")):         # the sandbox has only these of the package
            return
        got = _read_in_tree(root, real, 20)
        what = _looks_runnable(real, *got) if got else None
        if what:
            found[real] = {"rel": rel, "what": what, "label": label, "real": real}

    desks = []
    for folder in ("usr/share/applications", ""):
        where = in_tree(root, folder)
        if where is None:
            continue
        try:
            names = sorted(e.name for e in os.scandir(os.path.join(root, where))
                           if e.name.endswith(".desktop") and not e.name.startswith("."))
        except OSError:
            continue
        desks += [f"{where}/{n}" if where else n for n in names]
    for desk in desks:
        got = _read_in_tree(root, desk, DESKTOP_READ)
        if got is None:
            continue
        text = got[0].decode("utf-8", "replace")
        name = re.search(r"^Name=(.+)$", text, re.M)
        ex = re.search(r"^Exec=(.+)$", text, re.M)
        try:
            argv = shlex.split(ex.group(1)) if ex else []
        except ValueError:
            argv = []
        while argv and (argv[0] == "env" or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argv[0])):
            argv = argv[1:]
        if not argv:
            continue
        first = argv[0]
        tries = [str(Path(first.lstrip("/")))] if first.startswith("/") else \
            [str(Path(d) / first) for d in ("usr/bin", "usr/games", "usr/local/bin", "bin", "")]
        for rel in tries:
            if in_tree(root, rel) is not None:
                add(rel, name.group(1).strip() if name else "")
                break
    tops = ("usr/bin", "usr/games", "usr/local/bin", "opt") if deb else ("",)
    for top in tops:
        base = in_tree(root, top)                    # a folder linked elsewhere in the tree is listed where it leads
        if base is None:
            continue
        depth_max = 3 if top in ("opt", "") else 1
        stack = [(top, base, 0)]                     # (the path as the tree names it, where it really is, depth)
        while stack:
            folder, real, depth = stack.pop(0)
            try:
                entries = sorted(os.scandir(os.path.join(root, real)), key=lambda e: e.name)
            except OSError:
                continue
            for e in entries:
                rel = f"{folder}/{e.name}" if folder else e.name
                if e.is_dir(follow_symlinks=False):
                    if depth + 1 < depth_max and not e.name.startswith(".") and e.name not in ("lib", "lib64", "share", "locales", "resources", "node_modules"):
                        stack.append((rel, f"{real}/{e.name}" if real else e.name, depth + 1))
                else:
                    add(rel)
    return list(found.values())


# ------------------------------------------------------------------ preparing

def prepare_file(host: Host, path: Path, where: str, run: Callable = subprocess.run) -> Trial:
    """A trial of the file `path` (checked by the server: a regular file of the user's): copied in, and an
    archive or .deb unpacked in a sandbox. The file itself is neither changed nor run."""
    sub = classify(path)
    if sub.problem:
        raise TrialError(f"{path.name} is {sub.what}. {sub.problem}")
    size = path.stat().st_size
    place = _place(host, where)
    need = size * (4 if sub.kind in ("archive", "deb", "appimage") else 1) + (64 << 20)
    if size > COPY_MAX:
        raise TrialError(f"{path.name} is larger than this tries ({COPY_MAX >> 30} GB).")
    if place["free"] < need:
        raise TrialError(f"There isn't room for it {place['words'].lower()} ({place['free'] >> 20} MB free, about "
                         f"{need >> 20} MB needed)." + (" Choose the disk instead." if where == "memory" else ""))
    if place["noexec"]:
        raise TrialError("Programs can't be run from that place here (it is mounted noexec)."
                         + (" Choose the disk instead." if where == "memory" else ""))
    tid, folder = _make(host, where)
    t = Trial(tid, folder, where, sub.kind, path.name, sub.what)
    try:
        if sub.kind in ("archive", "deb"):
            if not sandbox.program(host, sandbox.BWRAP):
                raise TrialError("Unpacking it safely needs bubblewrap (the bubblewrap package).")
            filt = sandbox.make_filter(seccomp.STRICT)
            try:
                r = run(unpack_argv(host, path, t.app, unpack_limit(place), filt=filt), cwd="/", env=host_env(host.environ),
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=900,
                        **({"pass_fds": filt.fds()} if filt.fds() else {}))
            finally:
                filt.close()
            if r.returncode:
                err = (r.stderr or b"").decode(errors="replace").strip().splitlines()
                raise TrialError(f"{path.name} couldn't be unpacked: " + (err[-1][:300] if err else f"exit status {r.returncode}"))
            if sub.kind == "deb":                       # said now, not only when it is started (package_part)
                package_part(t, "usr")
                package_part(t, "opt")
            t.candidates = candidates(t.app, sub.kind == "deb")
            if not t.candidates:
                raise TrialError(f"Nothing in {path.name} looks like a program to start.")
            t.nesting = seccomp.nesting_reason(path, folder=t.app)
            if sub.kind == "deb":
                t.notes.append("The package is unpacked, not installed: what it depends on isn't installed for it, and "
                               "the set-up scripts it would run as root at installation aren't run.")
        else:
            dest = t.app / safe_name(path.name)
            # the file's contents, whatever the path is (a link in Downloads to the real file: copying the link
            # would have left the trial a link to nowhere inside the sandbox, and the chmod below would have
            # reached the user's own file through it); the copy is the trial's, the original is left as it is
            shutil.copyfile(path, dest)
            os.chmod(dest, 0o700)
            t.argv = [f"{APP_IN}/{dest.name}"]
            t.nesting = seccomp.nesting_reason(dest)
            if sub.kind == "appimage":
                t.env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
                t.notes.append("An AppImage can't mount itself inside a sandbox: it unpacks itself into the sandbox's "
                               "/tmp (memory) each time it starts, which takes a moment.")
            if sub.kind == "script":
                with open(dest, "rb") as f:
                    shebang = f.read(2) == b"#!"
                if not shebang:
                    t.argv = [sandbox.PYTHON if dest.suffix == ".py" else "/bin/sh", t.argv[0]]
    except BaseException:
        _remove(folder, where == "memory")
        _let_go(folder)
        raise
    return t


def prepare_app(host: Host, app: menu.App, where: str) -> Trial:
    """A trial of an installed app from the menu, with a throwaway home."""
    if app.terminal:
        raise TrialError(f"{app.name} runs in a terminal, which this can't start for it.")
    if app.kind == "snap":
        raise TrialError(f"{app.name} is a Snap, which can't be started inside another sandbox.")
    if app.kind == "flatpak":
        if not app.flatpak or not re.fullmatch(r"[A-Za-z0-9_.-]+", app.flatpak):
            raise TrialError(f"Which Flatpak {app.name} is can't be told from its menu entry.")
        tid, folder = _make(host, where)
        keep = [a for a in app.argv if a.startswith(("--branch=", "--arch=", "--command="))]
        return Trial(tid, folder, where, "flatpak", app.name, "a Flatpak app", argv=[*keep, app.flatpak], flatpak=app.flatpak,
                     notes=["It runs in Flatpak's own sandbox with the permissions it declares for itself dropped, and "
                            "only what this trial grants given back. Its real data (in ~/.var/app) isn't given to it.",
                            "It can still ask the desktop through its portals, as every Flatpak app can, and the "
                            "desktop asks you before it does any of it: a file chooser you answer (a file you pick "
                            "there is a real one), notifications, opening a web address in your usual browser (which "
                            "has a network even when this trial has none), and starting itself at every login, which "
                            "the desktop writes as an autostart entry. Say no to what you didn't expect: the result "
                            "lists any autostart entry or permission that appeared while it ran.",
                            "It can also ask Flatpak to start another copy of itself, as apps do to draw pictures: that copy "
                            "isn't watched, and it gets the app's real data in ~/.var/app, though not your files, the "
                            "desktop services the app declares or a network this trial doesn't give (the versions of "
                            "Flatpak tested refuse to start one at all). It is ended with the trial."])
    prog = _program(host, app.argv[0])
    if prog is None:
        raise TrialError(f"{app.name}'s program ({app.argv[0]}) isn't in the system's folders, so it can't be started "
                         "in the sandbox (which has no home folder of yours in it).")
    tid, folder = _make(host, where)
    return Trial(tid, folder, where, "installed", app.name, "an installed app", argv=[prog, *app.argv[1:]],
                 host_opt=prog.startswith("/opt/") or any(a.startswith("/opt/") for a in app.argv), env=dict(app.env),
                 notes=["It starts as on a first run: none of your settings, accounts or files are there."],
                 nesting=seccomp.installed_reason(str(host.sys_path(prog))))


def choose(t: Trial, rel: str, extra: str = "") -> None:
    """The program in an unpacked archive or package the user picked, and arguments for it (or for any trial)."""
    try:
        args = shlex.split(extra) if extra else []
    except ValueError:
        raise TrialError("The arguments can't be read (an open quote?).") from None
    if len(args) > 40 or any(len(a) > 2000 for a in args):
        raise TrialError("Too many arguments.")
    if t.kind in ("archive", "deb"):
        c = next((c for c in t.candidates if c["rel"] == rel), None)
        if c is None:
            raise TrialError("Choose one of the programs listed.")
        # the program where it really is in the tree, as candidates() found it, read without following a link and run
        # there: the path listed can be a link (a package's /usr/bin/x -> /opt/X/x, as Google Chrome's and Brave's
        # are), which opened here led to the computer's own /opt, so it couldn't be started, or the computer's file
        # was read in its place (the review of 2026-11-04)
        real = c["real"]
        got = _read_in_tree(os.path.realpath(t.app), real, 2)
        if got is None:
            raise TrialError(f"{rel} can't be read in what was unpacked.")
        first, mode = got
        inside = ("/" + real) if t.kind == "deb" else f"{APP_IN}/{real}"
        if c["what"] == "a script" and first != b"#!":
            t.argv = [sandbox.PYTHON if real.endswith(".py") else "/bin/sh", inside]
        elif c["what"] == "a script" and not mode & stat.S_IXUSR:
            t.argv = ["/bin/sh", "-c", 'exec "$(sed -n \'1s/^#! *//p\' "$0" | cut -d" " -f1)" "$0" "$@"', inside]
        else:
            t.argv = [inside]
        t.env.pop("APPIMAGE_EXTRACT_AND_RUN", None)
        if c["what"] == "an AppImage":
            t.env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
        t.argv += args
    else:
        # from the command as prepared each time: a start that failed after this (pasta not usable, no Xephyr) left
        # them added, the next start added them again, and a Box kept from the trial had them twice for good
        if t.prepared is None:
            t.prepared = list(t.argv)
        t.argv = [*t.prepared, *args]


# ------------------------------------------------------------------ the sandbox's command

# The sandbox's command lasts as long as anything the program started does: a launcher that starts the real
# program and ends would otherwise take the sandbox with it. A subreaper, to which what is left comes. Once the
# program itself has ended, the session's own helpers that it (or its toolkit) started are not waited for: a
# D-Bus daemon started on demand stays for good, and the trial would never end by itself (seen with Xed on
# Mint 22.3: its window closed, dbus-daemon left). Their names (comm, 15 characters at most):
HELPERS = ("dbus-daemon", "dbus-launch", "dbus-broker", "dbus-broker-lau", "at-spi-bus-laun", "at-spi2-registr",
           "dconf-service", "gvfsd", "gvfsd-fuse", "gvfsd-metadata", "gvfsd-trash", "ibus-daemon", "ibus-x11",
           "ibus-portal", "ibus-dconf", "ibus-engine-sim", "ibus-ui-gtk3", "fcitx5", "kded5", "kded6", "kdeinit5",
           "klauncher", "kioworker", "kioslave5", "kio_http_cache_", "kglobalacceld", "kglobalaccel5", "kwalletd5",
           "kwalletd6", "ksecretd", "gpg-agent", "ssh-agent", "xdg-document-po", "xdg-permission-", "xdg-desktop-por",
           "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber", "gconfd-2", "xfconfd", "fusermount3", "gnome-keyring-d")
# STAY is the sandbox's PID 1 (--as-pid-1), and sets its own parent-death signal (prctl 1, SIGKILL) as it starts:
# bubblewrap's --die-with-parent sets it before the exec, and under Ubuntu's AppArmor profile for bubblewrap the exec
# into its unpriv_bwrap domain clears it, so with bubblewrap ended (Stop, or the app killed: TETHER) the sandbox ran
# on, the program with it (tested on Ubuntu 26.04 on 2026-10-17; bubblewrap's own init, which isn't exec'd, keeps it,
# and so did Mint 22.3). As PID 1, its subreaper setting (prctl 36) is moot but harmless.
# Ending a trial asks STAY (SIGTERM, by its number on the computer: stop()), and it passes that on to everything in the
# sandbox (kill -1 from a PID namespace's PID 1 reaches that namespace's processes only), which then end as they would,
# reaped as ever: SIGTERM sent to the command's group reached bubblewrap (or pasta) first, which ended at once, and
# --die-with-parent then killed the sandbox, so the program never had the grace to end cleanly (a trap on TERM inside
# never ran: the review of 2026-11-04). The kernel passes a signal from outside to a namespace's PID 1 only when it has
# a handler for it. Where it isn't PID 1 (a test), only the program is asked. It passes one on once: at a logout every
# process of the session's unit is sent SIGTERM at once, those in the sandbox included, and the launcher's Stop asks
# again; a program can take a second one for "end now". It starts the program with every signal at its default and
# none blocked, as from the menu: the wrappers before it start with SIGTERM and SIGHUP blocked (TETHER's hold), and
# python3 ignores SIGPIPE and SIGXFSZ, which an exec keeps (programs in the sandbox had both ignored, and a shell can't
# even trap a signal it was started with ignored).
STAY = """\
import ctypes, os, signal, sys, time
HELPERS = %r
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(36, 1, 0, 0, 0)
libc.prctl(1, 9, 0, 0, 0)
first, asked = 0, False
def ask(signum, frame):
    global asked
    if asked:
        return
    try:
        if os.getpid() == 1:
            os.kill(-1, signum)
            asked = True
        elif first > 0:
            os.kill(first, signum)
            asked = True
    except OSError:
        pass
signal.signal(signal.SIGTERM, ask)
signal.pthread_sigmask(signal.SIG_UNBLOCK, (signal.SIGTERM, signal.SIGHUP))
first = os.fork()
if not first:
    for s in signal.valid_signals():
        if s not in (signal.SIGKILL, signal.SIGSTOP):
            try:
                signal.signal(s, signal.SIG_DFL)
            except (OSError, ValueError):
                pass
    signal.pthread_sigmask(signal.SIG_SETMASK, ())
    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    except OSError as e:
        sys.stderr.write("It couldn't be started: %%s\\n" %% e.strerror)
        os._exit(127)
def only_helpers():
    for p in os.listdir("/proc"):
        if p.isdigit() and int(p) not in (1, os.getpid()):
            try:
                with open("/proc/" + p + "/comm", errors="replace") as f:
                    if f.read().strip() not in HELPERS:
                        return False
            except OSError:
                pass
    return True
status = None
while True:
    try:
        pid, st = os.waitpid(-1, 0 if status is None else os.WNOHANG)
    except ChildProcessError:
        break
    if pid == first:
        status = os.waitstatus_to_exitcode(st)
    if status is not None and pid == 0:
        if only_helpers():
            break
        time.sleep(0.5)
status = status or 0
sys.exit(status if status >= 0 else 128 - status)
""" % (HELPERS,)
# A trial (and a Box's run) ends with the copy of the app that started it. bubblewrap's --die-with-parent answers to
# bubblewrap's parent, which under the observed network is pasta, not the app: with the app killed, pasta was adopted by
# init and the sandbox ran on, online and unobserved (the tools review of 2026-10-17, on the lab). The kernel's
# parent-death signal (PR_SET_PDEATHSIG) answers to the parent thread, and the app starts trials from a pool of worker
# threads. So the command runs under TETHER, the computer's python3, one thread: it starts the command with the
# parent-death signal (SIGKILL) set, which only its own end can set off, and ends as soon as the app's process has (a
# pidfd on it; its parent's number changing where the kernel has no pidfds), killing the command first: pasta or
# bubblewrap, and the sandbox with it. What the app sends the group (Stop's SIGTERM) reaches the command as before:
# TETHER ignores it, and passes the command's exit status on (a signal as 128 plus its number, as STAY does).
# A program's sandbox (--hold) gets the time to end at a logout. systemd then sends SIGTERM to every process of the
# session's unit at once: bubblewrap, which has no handler for it, ended at once, and pasta's handler ends it without
# waiting for its command (pasta 2024-02-20: tested), and --die-with-parent then killed the sandbox, so a boxed mail
# client was cut off mid-save. So the command starts with SIGTERM and SIGHUP blocked, which every exec keeps and
# neither bubblewrap nor pasta undoes: they stay pending in bubblewrap, pasta (its network with them) and the wrappers
# between, while STAY, which unblocks them, and the program, which it starts with every signal at its default, get
# theirs. The program ends as it chooses; the launcher's stop() kills what is left after its few seconds, and
# systemd's SIGKILL anything after its own (TimeoutStopSec, 5 s for user@ on Mint 22.3). Tested with bubblewrap 0.9,
# with and without pasta: a program trapping TERM wrote its file, one ignoring it was killed by stop(), nothing was left.
TETHER = """\
import ctypes, os, select, signal, sys, time
app, me, quiet = int(sys.argv[1]), os.getpid(), (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
hold = sys.argv[2] == "--hold"
argv = sys.argv[3:] if hold else sys.argv[2:]
for s in quiet:
    signal.signal(s, signal.SIG_IGN)
child = os.fork()
if not child:
    for s in quiet:
        signal.signal(s, signal.SIG_DFL)
    if hold:
        signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGTERM, signal.SIGHUP))
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0)
    if os.getppid() != me:
        os._exit(1)
    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        sys.stderr.write("It couldn't be started: %s\\n" % e.strerror)
    os._exit(127)
null = os.open("/dev/null", os.O_RDWR)               # the command's output and the sync pipe are its own to close
for fd in (0, 1, 2):
    os.dup2(null, fd)
os.closerange(3, 65536)
def gone():
    os.kill(child, signal.SIGKILL)
    os._exit(1)
try:
    fds = [os.pidfd_open(app), os.pidfd_open(child)]
except (AttributeError, OSError):
    fds = None
while True:
    if os.getppid() != app:
        gone()
    if fds:
        if fds[0] in select.select(fds, [], [])[0]:
            gone()
    else:
        time.sleep(0.5)
    try:
        pid, st = os.waitpid(child, os.WNOHANG)
    except ChildProcessError:
        os._exit(1)
    if pid:
        code = os.waitstatus_to_exitcode(st)
        os._exit(code if code >= 0 else 128 - code)
"""


# A trial's and a Box's run in a group of its own, with a limit on the memory and the processes it may take
# (`capped`): the sandbox holds a program to the trial's folder, and RoomWatch holds a trial in memory to the room
# there, but nothing held what it took of the computer itself. A program that asks for memory until there is none
# has the kernel kill something to get it (the app, the session, the desktop), and one that starts processes without
# end fills the user's own limit, so nothing of the user's can start either (the review of 2026-11-12). systemd's
# user manager has the memory and pids controllers, so a scope of the app's own can cap both: at MEMORY_SHARE of
# the computer's memory (at least MEMORY_LEAST) and TASKS_MAX processes and threads. What is left when the program
# is killed for the limit is the trial's own folder, as after End; the result says it was the limit.
SYSTEMD_RUN = "systemd-run"
# what the journal says of the scope: never the program's name, and the same for a trial and a Box (the journal
# would otherwise say which app is kept in a Box, and when it ran)
DESCRIPTION = "A program in a sandbox of DA Privacy Kit's"
MEMORY_SHARE = 0.7
MEMORY_LEAST = 1 << 30
TASKS_MAX = 1024
_CAPPED: dict[str, str | None] = {}     # the computer's systemd-run -> why a scope can't cap it, or None


def total_memory(host: Host) -> int | None:
    try:
        for line in (host.read_sys("/proc/meminfo") or "").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def memory_cap(host: Host) -> int:
    """The memory a trial may take: MEMORY_SHARE of the computer's, at least MEMORY_LEAST."""
    total = total_memory(host)
    return max(MEMORY_LEAST, int(total * MEMORY_SHARE)) if total else MEMORY_LEAST


def limits(host: Host) -> list[str]:
    """The scope's properties: how much memory and how many processes a trial may take."""
    return [f"-pMemoryMax={memory_cap(host)}", f"-pTasksMax={TASKS_MAX}"]


def probe_capped(host: Host) -> str | None:
    """Why a trial can't be capped here, or None: systemd-run tried once with the same properties around `true`
    (a user manager without the memory or pids controller refuses them, and a start that failed would have left
    the user with no trial at all)."""
    if not host.runner.which(SYSTEMD_RUN):
        return "systemd-run isn't installed."
    runtime = host.environ.get("XDG_RUNTIME_DIR", f"/run/user/{host.uid}")
    if not host.sys_path(f"{runtime}/systemd").exists():
        return "systemd's user session isn't running here."
    found = sandbox.program(host, SYSTEMD_RUN) or SYSTEMD_RUN
    if found not in _CAPPED:
        r = host.run(found, "--user", "--scope", "--collect", "--quiet", f"--description={DESCRIPTION}",
                     *limits(host), "--", "/usr/bin/true", timeout=20)
        err = [ln for ln in (r.stderr or r.stdout).strip().splitlines() if ln.strip()]
        _CAPPED[found] = None if r.ok else (err[-1][:200] if err else f"exit status {r.returncode}")
    return _CAPPED[found]


def capped(host: Host, argv: list[str]) -> list[str]:
    """`argv` in a scope of its own with the limits (above), where that works here (probe_capped); as it is
    otherwise, and the panel says so."""
    if probe_capped(host):
        return argv
    return [sandbox.program(host, SYSTEMD_RUN) or SYSTEMD_RUN, "--user", "--scope", "--collect", "--quiet",
            f"--description={DESCRIPTION}", *limits(host), "--", *argv]


def cap_env(host: Host) -> dict[str, str]:
    """What systemd-run needs in its environment to reach the user's own systemd, added to what a sandbox is
    started with (sandbox.SPAWN_ENV): the runtime folder, where it finds the user's bus (tested: nothing else is
    needed). It says only the user's number, which the sandbox has as its own anyway; and with python3 on the
    computer, STAY is the sandbox's PID 1, so no process the program can see carries it at all."""
    runtime = host.environ.get("XDG_RUNTIME_DIR")
    return {"XDG_RUNTIME_DIR": runtime} if runtime else {}


def tethered(host: Host, argv: list[str], hold: bool = False) -> list[str]:
    """`argv` under TETHER: it ends with this process. As it is where there is no python3 (bubblewrap's own
    --die-with-parent is all there is then). `hold`: a program's sandbox with STAY in it, which a logout's SIGTERM
    doesn't end before the program has (TETHER's comment); never Xephyr's, which _finish ends with SIGTERM."""
    if not host.sys_path(sandbox.PYTHON).exists():
        return argv
    return [sandbox.PYTHON, "-I", "-c", TETHER, str(os.getpid()), *(["--hold"] if hold else []), *argv]


# "$1" is mount, "$2" the package's usr folder: its ":" "," and "\" escaped as overlayfs's options want them (a trial's
# folder is under the runtime or cache folder, whose path is the user's to choose), then the command after the two
OVERLAY = (r"""lower=$(printf %s "$2" | sed -e 's/\\/\\\\/g' -e 's/,/\\,/g' -e 's/:/\\:/g'); """
           '"$1" -t overlay overlay -o "lowerdir=$lower:/usr" /usr || { echo "The package\'s files could not be laid over '
           '/usr" >&2; exit 1; }; shift 2; exec "$@"')


LINKED_PART = ("This package's {name} folder is a link to somewhere outside the package, which no real package has: "
               "given to the sandbox, it would have reached this computer's own files. It isn't started.")


def package_part(t: "Trial", name: str) -> str | None:
    """A .deb's usr or opt folder as a bind source (sandbox.bind_source), or None when the package has none. Where it
    is a link that leads to a folder inside the package (in_tree), that folder; one that leads out of it, or to
    something else, refuses the start (LINKED_PART)."""
    if not os.path.lexists(t.app / name):
        return None
    real = in_tree(os.path.realpath(t.app), name)
    try:
        found = sandbox.bind_source(t.app, real) if real else None
    except sandbox.SandboxError:
        found = None
    if found is None:
        raise TrialError(LINKED_PART.format(name=name))
    return found


def own_part(base: Path, rel: str, what: str) -> str | None:
    """One of the trial's or Box's own folders (its home, its program, a Box's Exchange) as a bind source: never through
    a link (sandbox.bind_source). None when it isn't there."""
    try:
        return sandbox.bind_source(base, rel)
    except sandbox.SandboxError:
        raise TrialError(f"{what} isn't a plain folder (a link, perhaps), so it isn't given to the sandbox.") from None


class Engine:
    """How a trial is run. `probe`: why it can't be here, or None. `command`: the whole command line."""
    id = ""
    name = ""

    def probe(self, host: Host) -> str | None:
        raise NotImplementedError

    def command(self, host: Host, t: Trial, parts: "Parts") -> list[str]:
        raise NotImplementedError


@dataclass
class Parts:
    """What a start has put together for the engine."""
    disp: sandbox.Display
    etc: dict[str, Path]
    pasta: str | None = None             # its path, when the network is observed
    pcap: Path | None = None             # the pipe pasta writes its packets to
    sync_fd: int | None = None           # held open by bubblewrap: the marked Wayland socket's
    devices: tuple[str, ...] = ()
    sound: bool = False
    filt: sandbox.Filter | None = None   # its system-call filter (strict, or nesting when ticked): sandbox.make_filter


class Bubblewrap(Engine):
    id, name = "bubblewrap", "bubblewrap"

    def probe(self, host: Host) -> str | None:
        return sandbox.probe(host)

    def command(self, host: Host, t: Trial, parts: Parts) -> list[str]:
        bwrap = sandbox._need(host, sandbox.BWRAP)
        # what the computer resolves (bind sources, the overlay's lower folder) never through a link in the tree
        # (package_part, own_part): bubblewrap and the kernel follow it outside the sandbox
        deb_usr = package_part(t, "usr") if t.kind == "deb" else None
        native = bool(deb_usr) and native_overlay(host)
        home = own_part(t.folder, "home", "The trial's home folder")
        if home is None:
            raise TrialError("The trial's home folder is missing.")
        # No /proc masks (sandbox.proc_masks), as the browser's innermost sandbox has: with a file of /proc covered the
        # kernel refuses a new /proc inside, and WebKitGTK's web processes and GNOME's thumbnailer mount one for their
        # own sandbox (tested on Fedora 44, GNOME 50: a WebKit page failed with "Can't mount proc"). The page says the
        # program can read the kernel command line and the boot id.
        # --die-with-parent: Stop ends bubblewrap, and the sandbox must go with it. Its own process is in a session
        # of its own (--new-session), so a signal to the group doesn't reach it: without this the program ran on
        # after Stop, its folder deleted under it (seen with KWrite on CachyOS)
        # strict: no namespaces of its own, also by bubblewrap's own --disable-userns; nesting (ticked, for a program
        # that starts sandboxes of its own) lets it make them, mounts included (seccomp.py)
        strict = parts.filt is None or parts.filt.profile == seccomp.STRICT
        a: list[str] = [bwrap, "--die-with-parent", *sandbox.namespaces(bool(parts.pasta)),
             *(sandbox.no_new_userns(host) if strict else []), *(parts.filt.argv() if parts.filt else []),
             *sandbox.system(host, etc=False),
             # bubblewrap 0.10 and later lay the package's /usr over the computer's themselves (the first source at
             # the bottom), before AppArmor's bwrap-userns-restrict profile takes the capabilities from what they start
             *(["--overlay-src", "/usr", "--overlay-src", deb_usr, "--ro-overlay", "/usr"]
               if native and deb_usr else []),
             # an /etc of the sandbox's own, holding only what programs read and nothing of the computer's settings
             # (sandbox.app_etc): what it covered over the computer's own /etc missed the account's name in passwd-,
             # the mirrors, tokens in /etc/environment and more (the review of 2026-11-12)
             *sandbox.app_etc(host, parts.etc, resolv=bool(parts.pasta)), *sandbox._gpu_argv(parts.devices)]
        a += ["--bind", home, sandbox.HOME_IN, "--perms", "0700", "--dir", sandbox.RUNTIME_IN]
        if t.kind == "deb":
            opt = package_part(t, "opt")
            if opt:
                a += ["--ro-bind", opt, "/opt"]
        else:
            app = own_part(t.folder, "app", "The program's folder")
            if app:
                a += ["--ro-bind", app, APP_IN]
            if t.host_opt:
                a += ["--ro-bind", "/opt", "/opt"]
        for outside, inside in t.binds:
            src = own_part(Path(outside).parent, Path(outside).name, f"{Path(outside).name}")
            if src is None:
                raise TrialError(f"{Path(outside).name} is missing.")
            a += ["--bind", src, inside]
        snd = sandbox.sound(host) if parts.sound else None
        a += sandbox._desktop(parts.disp, snd, inside=False)
        env = {"HOME": sandbox.HOME_IN, "USER": sandbox.USER_IN, "LOGNAME": sandbox.USER_IN,
               "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/games", "XDG_RUNTIME_DIR": sandbox.RUNTIME_IN, "SHELL": "/bin/sh",
               **({} if parts.devices else sandbox.software_gl(host)),
               **{k: host.environ[k] for k in sandbox.PASSED_ENV if host.environ.get(k)}, **parts.disp.env, **t.env}
        if snd:
            env["PULSE_SERVER"] = f"unix:{sandbox.RUNTIME_IN}/pulse/native"
        for k, v in env.items():
            a += ["--setenv", k, v]
        if parts.sync_fd is not None:
            a += ["--sync-fd", str(0 if parts.pasta else parts.sync_fd)]
        stay = [sandbox.PYTHON, "-I", "-c", STAY] if host.sys_path(sandbox.PYTHON).exists() else []
        # STAY reaps, so it can be the sandbox's PID 1: bubblewrap's own process, whose environment and command line
        # name the user and the computer, is then out of the program's sight (sandbox.SPAWN_ENV)
        a += [*(["--as-pid-1"] if stay else []), "--chdir", sandbox.HOME_IN, "--", *stay, *t.argv]
        if deb_usr and not native:
            # an older bubblewrap (0.9, Mint 22.3's) has no overlay of its own: a first bubblewrap, root of its own user
            # namespace, lays the package's /usr over the computer's; the sandbox proper then starts inside that view
            a = [bwrap, "--die-with-parent", "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "ALL",
                 "--dev-bind", "/", "/", "--", "/bin/sh", "-c", OVERLAY, "sh", sandbox._need(host, "mount"),
                 deb_usr, *a]
        if parts.filt is not None:
            a = parts.filt.wrap(a)                      # under pasta, the shell that opens the filter's file
        if not parts.pasta:
            return a
        # --no-icmp (among pasta's options, sandbox.pasta_opts): pasta sends the namespace's pings on from ping sockets of the computer's,
        # and the packets are summed up as TCP and UDP only (tools/pcap.py): a program could send data in pings to any
        # host while the list said it contacted nothing, wherever the computer's ping_group_range takes in the user, as
        # systemd's default does (the review of 2026-11-04). A program on trial needs no ping. Then the fence and the
        # lookups' filter (sandbox.pasta_command).
        cmd, _filtered = sandbox.pasta_command(host, a, parts.pasta, proxies=False, extra=("--pcap", str(parts.pcap)))
        return cmd


class Flatpak(Engine):
    id, name = "flatpak", "Flatpak's own sandbox"

    def probe(self, host: Host) -> str | None:
        return None if host.runner.which("flatpak") else "Flatpak isn't installed."

    def command(self, host: Host, t: Trial, parts: Parts) -> list[str]:
        o = t.options
        # --session-bus: the filtered bus Flatpak gives every app, which --sandbox takes away. Without it the
        # portals are out of reach, and GTK 4 apps, which start their image loaders through one, stop at once
        # (Evince 48 from Flathub: "Loader process exited early", tested on Mint 22.3). Filtered, it reaches the
        # portals and names of its own, nothing of the session's other programs.
        # One of those portals starts another copy of the app (flatpak-spawn, what GTK 4's image loaders use), and
        # Flatpak gives that copy the app's declared permissions, not --sandbox, with this command's other options
        # on top, home meaning the real one (found in the 2026-10-17 review on Mint 22.3, Flatpak 1.14.6: a copy
        # of Text Editor listed the real home, which the app declares as host). So everything the app declares is
        # taken back here (`taken_back`), which the copy inherits, and the throwaway home is given by its path.
        # Flatpak 1.14.6 and 1.17.6 then refuse to start such a copy at all (they pass a taken-away bus name or
        # shared namespace on in a form their own `flatpak run` rejects); a sandboxed copy still starts (tested).
        # --own-name: its own name on the bus, which --sandbox takes away too, and without which an app that runs one
        # instance (a GApplication: GNOME Text Editor 51) ends at once, "Failed to register" (found by the review of
        # View offline…, Flatpak 1.14.6)
        a = [sandbox.program(host, "flatpak") or "flatpak", "run", "--sandbox", "--session-bus",
             *([f"--own-name={t.flatpak}"] if t.flatpak and BUS_NAME.fullmatch(t.flatpak) else []), "--die-with-parent",
             *taken_back(host, t, parts.disp.kind), f"--filesystem={t.home}",
             "--share=network" if o.get("network") == "on" else "--unshare=network"]
        a += ["--socket=wayland"] if parts.disp.kind == "wayland" else ["--socket=x11", "--share=ipc"]
        if o.get("gpu"):
            a.append("--device=dri")
        if o.get("sound"):
            a.append("--socket=pulseaudio")
        # for the refusal only (Flatpak resolves a path in --filesystem on the computer, as bubblewrap does a bind
        # source): a home or an Exchange folder that has become a link isn't given to it (own_part raises)
        own_part(t.folder, "home", "The home folder")
        for outside, _inside in t.binds:
            own_part(Path(outside).parent, Path(outside).name, Path(outside).name)
        a += [f"--filesystem={outside}" for outside, _inside in t.binds]
        return a + t.argv


FLATPAK_WORD = re.compile(r"[\w~/.@+-]+")
BUS_NAME = re.compile(r"[\w-]+(\.[\w-]+)*(\.\*)?")


def declared(host: Host, app: str) -> dict[str, list[str]]:
    """What a Flatpak app declares for itself, with the user's and the system's overrides: {"filesystems", "sockets",
    "devices", "shared", "features"}, each a list (entries the overrides take away left out), and "session_bus" and
    "system_bus", the names it may talk to or own on each bus."""
    from types import SimpleNamespace
    from ..checks.sandbox import flatpak_permissions
    from ..paths import PathResolver
    scan = SimpleNamespace(host=host, paths=PathResolver(host.home, host.environ))      # all it reads of a Scan
    perms = flatpak_permissions(scan, app)  # type: ignore[arg-type]  # a Scan's .host and .paths alone
    ctx = perms.get(("Context",), {})
    out = {k: [x.strip() for x in ctx.get(k, "").split(";") if x.strip() and not x.strip().startswith("!")]
           for k in ("filesystems", "sockets", "devices", "shared", "features")}
    for key, group in (("session_bus", "Session Bus Policy"), ("system_bus", "System Bus Policy")):
        out[key] = [name for name, policy in perms.get((group,), {}).items() if policy.strip() in ("see", "talk", "own")]
    return out


def taken_back(host: Host, t: Trial, display: str) -> list[str]:
    """Options that take away what the Flatpak app declares and the trial doesn't give: a copy of it started through
    Flatpak's portal gets the app's own permissions with these on top (Flatpak.command). Its real data folder in
    ~/.var/app, which Flatpak gives every copy, stays. The desktop services it declares go too, and GVFS always (it
    fetches over the network for its callers: gio cat http:// worked with no network, found by the review of View
    offline…). Flatpak 1.14 passes a taken-away name on to such a copy in a form its own `flatpak run` refuses
    ("--none-name"), so there the copy isn't started at all; a sandboxed copy (flatpak-spawn --sandbox, as GTK 4's
    image loaders start) doesn't take these options and still starts (tested on Mint 22.3, Flatpak 1.14.6)."""
    d = declared(host, t.flatpak or "")
    out = ["--nofilesystem=host", "--nofilesystem=home"]
    for fs in d["filesystems"]:
        fs = re.sub(r":(ro|rw|create)$", "", fs)
        if fs not in ("host", "home") and FLATPAK_WORD.fullmatch(fs):
            out.append(f"--nofilesystem={fs}")
    given = {"wayland"} if display == "wayland" else {"x11"}
    if t.options.get("sound"):
        given.add("pulseaudio")
    out += [f"--nosocket={s}" for s in d["sockets"] if s not in given and FLATPAK_WORD.fullmatch(s)]
    out += [f"--nodevice={x}" for x in d["devices"] if FLATPAK_WORD.fullmatch(x)]        # dri given back after, if ticked
    out += [f"--unshare={s}" for s in d["shared"] if FLATPAK_WORD.fullmatch(s)
            and not (s == "ipc" and display != "wayland") and not (s == "network" and t.options.get("network") == "on")]
    out += [f"--disallow={f}" for f in d["features"] if FLATPAK_WORD.fullmatch(f)]
    out += [f"--no-talk-name={n}" for n in dict.fromkeys(["org.gtk.vfs.*", *d["session_bus"]])
            if BUS_NAME.fullmatch(n) and n != t.flatpak]
    out += [f"--system-no-talk-name={n}" for n in d["system_bus"] if BUS_NAME.fullmatch(n)]
    return out


# What a Flatpak trial can ask the desktop for through its portals, and what that leaves behind. `flatpak run
# --sandbox` drops what the app declares, but the filtered session bus (--session-bus, which GTK 4 apps need to start
# at all) always reaches the portals, as it does for every Flatpak app: among them OpenURI, which asks the desktop to
# open a web address in the user's own browser, with the browser's network, though the trial may have none; and
# Background, which asks to start the app at every login, which the desktop records as an autostart entry of the
# app's own. Both ask the user in current versions of xdg-desktop-portal, and the user answers them: the trial's
# notes say so, and after the trial the app looks for what they leave (portal_marks, `portal`): a new or changed
# entry in the autostart folder, and the portals' own record of what the app may do
# (the permission store, $XDG_DATA_HOME/flatpak/db/*: "background" holds the autostart and background permissions).
PERMISSION_DBS = ("background", "notifications", "devices", "location", "screenshot", "documents")


def _mark(path: Path) -> str | None:
    """A file as it is now, for comparing afterwards: its size and when it last changed. None when it isn't there."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return f"{st.st_size}:{st.st_mtime_ns}"


def portal_marks(host: Host) -> dict:
    """The autostart folder's entries and the portals' permission store as they are now."""
    from ..paths import PathResolver
    paths = PathResolver(host.home, host.environ)
    auto = paths.config_home / "autostart"
    try:
        entries = {n: _mark(auto / n) for n in sorted(os.listdir(auto))}
    except OSError:
        entries = {}
    dbs = paths.data_home / "flatpak/db"
    return {"autostart": entries, "permissions": {n: _mark(dbs / n) for n in PERMISSION_DBS}}


def portal_changes(before: dict, after: dict) -> dict:
    """What the portals left: {"autostart": the entries new or changed since, "permissions": the records changed}."""
    old, new = before.get("autostart", {}), after.get("autostart", {})
    return {"autostart": sorted(n for n, m in new.items() if old.get(n) != m),
            "permissions": sorted(n for n, m in after.get("permissions", {}).items()
                                  if before.get("permissions", {}).get(n) != m)}


def flatpak_copies(host: Host, t: Trial) -> list[int]:
    """Copies of a Flatpak trial's app started through Flatpak's portal: they outlive the trial's own command, as
    the portal's children (found in the 2026-10-17 review: one ran on after Stop). Flatpak records each instance
    with the options it was started with (extra-args in $XDG_RUNTIME_DIR/.flatpak/<id>/info), the trial's home's
    path among them, which no other app's copy has; each is its sandbox's first process (bwrapinfo.json's
    child-pid), checked to be in that sandbox's PID namespace still (a number used again can't pass)."""
    import json
    runtime = Path(host.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{host.uid}")
    base = (runtime if str(runtime).startswith(str(host.home)) else host.sys_path(str(runtime))) / ".flatpak"
    mark = f"--filesystem={t.home}"
    out = []
    try:
        instances = [d for d in base.iterdir() if d.name.isdigit()]
    except OSError:
        return []
    for d in instances:
        try:
            info = (d / "info").read_text(errors="replace")
            bw = json.loads((d / "bwrapinfo.json").read_text())
            pid, ns = int(bw["child-pid"]), int(bw["pid-namespace"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        extra = next((ln.split("=", 1)[1] for ln in info.splitlines() if ln.startswith("extra-args=")), "")
        if mark not in extra.split(";"):
            continue
        try:
            if os.readlink(host.sys_path(f"/proc/{pid}/ns/pid")) == f"pid:[{ns}]":
                out.append(pid)
        except OSError:
            continue
    return out


def end_flatpak_copies(host: Host, t: Trial) -> int:
    """Ends what flatpak_copies finds: SIGKILL to the first process of each sandbox takes the whole sandbox."""
    n = 0
    for pid in flatpak_copies(host, t):
        try:
            os.kill(pid, signal.SIGKILL)
            n += 1
        except OSError:
            pass
    return n


ENGINES: dict[str, Engine] = {e.id: e for e in (Bubblewrap(), Flatpak())}


def engine_of(t: Trial) -> Engine:
    return ENGINES["flatpak" if t.kind == "flatpak" else "bubblewrap"]


_NATIVE: dict[str, bool] = {}           # bubblewrap's path -> whether it has overlays of its own


def native_overlay(host: Host) -> bool:
    """Whether this bubblewrap mounts overlays itself (--overlay-src and --ro-overlay, bubblewrap 0.10 and later)."""
    bwrap = sandbox.program(host, sandbox.BWRAP)
    if not bwrap:
        return False
    if bwrap not in _NATIVE:
        r = host.run(bwrap, "--help", timeout=10)
        _NATIVE[bwrap] = "--ro-overlay" in (r.stdout + r.stderr)
    return _NATIVE[bwrap]


APPARMOR_BWRAP = ("AppArmor here takes every capability from the programs bubblewrap starts (the bwrap-userns-restrict "
                  "profile, as Ubuntu ships it), and laying the package's files over /usr needs one in the sandbox's own "
                  "namespace. A bubblewrap of version 0.10 or later lays them itself, which that profile allows (as "
                  "Ubuntu 26.04's does).")


def probe_overlay(host: Host) -> str | None:
    """Why a .deb's files can't be laid over /usr here, or None: tried with an empty folder, the way a trial will
    (bubblewrap's own overlay where it has one, else a first bubblewrap that mounts it)."""
    bwrap, mount = sandbox.program(host, sandbox.BWRAP), sandbox.program(host, "mount")
    empty = "/var/empty" if host.sys_path("/var/empty").is_dir() else "/mnt"
    if bwrap and native_overlay(host):
        r = host.run(bwrap, *sandbox.namespaces(False), *sandbox.system(host), "--overlay-src", "/usr", "--overlay-src",
                     empty, "--ro-overlay", "/usr", "--", "/usr/bin/true", timeout=20)
    elif not bwrap or not mount:
        return "bubblewrap or mount isn't installed."
    else:
        r = host.run(bwrap, "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "ALL", "--dev-bind", "/", "/",
                     "--", "/bin/sh", "-c", OVERLAY, "sh", mount, empty, "/usr/bin/true", timeout=20)
    if r.ok:
        return None
    if apparmor_strips_bwrap(host):
        return APPARMOR_BWRAP
    err = (r.stderr or r.stdout).strip().splitlines()
    return f"an overlay can't be mounted in a sandbox here ({err[-1][:160] if err else f'exit status {r.returncode}'})."


def apparmor_strips_bwrap(host: Host) -> bool:
    """Whether AppArmor confines what bubblewrap starts to Ubuntu's unpriv_bwrap profile (bwrap-userns-restrict: no
    capabilities, even as root of its own namespace): read from a program started that way, as the user (the list of
    loaded profiles is root's to read)."""
    bwrap = sandbox.program(host, sandbox.BWRAP)
    if not bwrap or not host.sys_path("/sys/kernel/security/apparmor").is_dir():
        return False
    r = host.run(bwrap, "--dev-bind", "/", "/", "--", "/bin/cat", "/proc/self/attr/current", timeout=10)
    return "unpriv_bwrap" in r.stdout


# ------------------------------------------------------------------ what the program prints, and pasta's packets

class Tail(threading.Thread):
    """Reads a pipe to its end, keeping only the last of it: a program's output isn't kept, but why it failed
    to start is worth showing."""

    def __init__(self, stream, keep: int = OUTPUT_KEPT):
        super().__init__(name="trial-output", daemon=True)
        self.stream, self.keep, self.data = stream, keep, b""

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read1(65536) if hasattr(self.stream, "read1") else self.stream.read(65536)
                if not chunk:
                    return
                self.data = (self.data + chunk)[-self.keep:]
        except (OSError, ValueError):
            return

    def lines(self, n: int = 12) -> list[str]:
        text = self.data.decode("utf-8", "replace")
        return [ln for ln in text.splitlines() if ln.strip() and not quiet(ln)][-n:]


def quiet(line: str) -> bool:
    return sandbox.quiet_line(line) or line.strip().startswith("Saving packet capture to")


class PipeReader(threading.Thread):
    """Feeds what pasta writes into its capture pipe to pcap.Flows, as it comes. The pipe is opened for reading
    and writing, so opening it never waits for pasta and reading never ends before stop()."""

    def __init__(self, path: Path, flows: pcap.Flows):
        super().__init__(name="trial-packets", daemon=True)
        path.unlink(missing_ok=True)                    # a Box's runtime folder is used again: an earlier run's pipe
        os.mkfifo(path, 0o600)
        self.fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        self.flows, self.done = flows, threading.Event()

    def run(self) -> None:
        # Never silently: what stops the summing up (memory running short, a packet nothing foresaw) ended this thread
        # without a word, the rest of the trial unobserved (the review of 2026-11-04). The result says so now
        # (Flows.stopped), and the pipe is still read, so pasta, which waits while it is full, keeps the network going.
        import select
        try:
            while True:
                ready = select.select([self.fd], [], [], 0.3)[0]
                if ready:
                    try:
                        data = os.read(self.fd, 1 << 18)
                    except BlockingIOError:
                        continue
                    if not self.flows.stopped:
                        try:
                            self.flows.feed(data)
                        except Exception:  # noqa: BLE001 - whatever it was, watching ends here, and says so
                            self.flows.stopped = True
                elif self.done.is_set():
                    return
        except (OSError, ValueError):
            if not self.done.is_set():
                self.flows.stopped = True

    def stop(self) -> None:
        self.done.set()
        self.join(timeout=3)
        try:
            os.close(self.fd)
        except OSError:
            pass


def room(folder: Path) -> int | None:
    """The room left on the filesystem of `folder` for the user's files, or None when it can't be told."""
    try:
        vfs = os.statvfs(folder)
    except OSError:
        return None
    return vfs.f_bavail * vfs.f_frsize


class RoomWatch(threading.Thread):
    """A trial in memory is in the runtime folder, the session's own tmpfs (a tenth or so of the memory), and nothing
    held it to a size while it ran: a browser's or an Electron app's cache, or a program writing all it can, filled
    it, and the session's other programs couldn't write their runtime files there until the trial was discarded. This
    looks at the room left every ROOM_EVERY seconds while it runs, whether or not the panel is open, and ends the trial
    (its result kept, as Stop's) once less than ROOM_KEPT is left. What it wrote stays until it is discarded."""

    def __init__(self, host: Host, t: "Trial"):
        super().__init__(name="trial-room", daemon=True)
        self.host, self.t, self.every, self.done = host, t, ROOM_EVERY, threading.Event()

    def run(self) -> None:
        while not self.done.wait(self.every):
            if self.t.state != "running":
                return
            left = room(self.t.folder)
            if left is not None and left < ROOM_KEPT:
                self.t.short_of_room = left
                stop(self.host, self.t)
                return


# ------------------------------------------------------------------ starting, ending

def status(host: Host) -> dict:
    """What a trial can have here: the engines, the network, the display, where it can live."""
    from . import browser
    sb = browser.sandbox_status(host)
    flat = ENGINES["flatpak"].probe(host)
    where = places(host)
    for p in where:
        if p["id"] == "memory":
            # the runtime folder is a tmpfs without noswap: swap on a disk can take its pages, and hibernating writes
            # all of memory there (the page said nothing of the trial touched the disk: the 2026-10-17 review)
            p["swap"] = [s["name"] for s in browser._swaps(host)]
            p["hibernation"] = ramdisk.hibernation_possible(host)
    why_cap = probe_capped(host)
    return {"capped": None if why_cap else {"memory": memory_cap(host), "tasks": TASKS_MAX}, "capped_why": why_cap,
            "available": sb["available"], "why": sb["why"], "apparmor": sb["apparmor"], "python": sb["python"],
            "pasta": sb["pasta"], "display": sb["display"], "wayland_context": sb["wayland_context"],
            "wayland_risky": sb["wayland_risky"], "wlroots": sb["wlroots"], "xephyr": sb["xephyr"],
            "sound": sb["sound"], "gpu": sb["gpu"],
            "flatpak": flat is None, "places": where, "room_kept": ROOM_KEPT,
            "engines": [{"id": e.id, "name": e.name} for e in ENGINES.values()]}


def _nested(host: Host, t: Trial, spawn: Callable):
    """Xephyr in its own sandbox, started and waited for: (the display the program then gets, its process). Its focus
    keeper sizes the program's main windows to the display (fill): there is no window manager inside to do it."""
    if not sandbox.program(host, sandbox.XEPHYR):
        raise TrialError("A display of its own needs Xephyr, which isn't installed. Untick it, or install it.")
    filt = sandbox.make_filter(seccomp.STRICT)
    try:
        title = f"{t.name}, in its Box" if t.private_at is not None else f"Try an app: {t.name}"
        nest = sandbox.nested(host, t.private, title, sandbox.screen_size(host), filt=filt, fill=True)
        if nest is None:
            raise TrialError("A display of its own works on this computer's own X11 display only. Untick it.")
        proc = spawn(tethered(host, sandbox.fresh_keyring(host, nest.argv)), cwd="/", env=host_env(host.environ),
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                     **({"pass_fds": filt.fds()} if filt.fds() else {}))
    finally:
        filt.close()
    if not hasattr(proc, "poll"):
        return nest.display, proc
    deadline = time.monotonic() + NESTED_WAIT
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            if stat.S_ISSOCK(os.stat(nest.socket, follow_symlinks=False).st_mode):
                return nest.display, proc
        except OSError:
            pass
        time.sleep(0.1)
    if proc.poll() is None:
        proc.kill()
    raise TrialError("Xephyr didn't open its display.")


def start(host: Host, t: Trial, options: dict, spawn: Callable = subprocess.Popen) -> dict:
    """Starts the trial with `options` ({"network": off|observed|on, "gpu", "sound", "nested", "decoys"}): plants
    the decoys, starts the watch, then the program in its sandbox. Returns how it runs (`how`)."""
    if t.state != "ready":
        raise TrialError("This trial has already run: start a new one to try it again.")
    if not t.argv:
        raise TrialError("Choose the program to start first.")
    eng = engine_of(t)
    why = eng.probe(host)
    if why:
        raise TrialError(f"It can't be run here: {why}")
    left = room(t.folder) if t.where == "memory" else None
    if left is not None and left < ROOM_KEPT:
        raise TrialError(f"There is too little room left in memory for it to run: {left >> 20} MB in the runtime folder, "
                         f"which your whole session shares, and a trial there is ended when less than {ROOM_KEPT >> 20} "
                         "MB is left. Discard it and prepare it on the disk instead.")
    network = options.get("network") if options.get("network") in ("off", "observed", "on") else "off"
    if network == "on" and eng.id != "flatpak":
        raise TrialError("A trial never shares this computer's network: choose no network, or the observed one.")
    if network == "observed" and eng.id == "flatpak":
        raise TrialError("A Flatpak app's network can't be observed from here: choose none, or its usual network.")
    if eng.id == "flatpak":
        # an app that runs one copy at a time (a GApplication, a KDBusService) finds its name taken by the copy already
        # open, hands this start to it and ends at once (Text Editor 51 did with View offline…, tested on Mint 22.3):
        # that copy has the real home and its network, and the trial would say the app ended by itself
        open_now = flatpak_open(host, t.flatpak or "")
        if open_now is None:
            raise TrialError(f"Whether {t.name} is open already couldn't be told (flatpak ps didn't answer), so it isn't "
                             f"started: if it were, the copy that is open would be handed this start, outside the "
                             "sandbox.")
        if open_now:
            raise TrialError(f"{t.name} is open already: started now, it would hand this start to the copy that is open, "
                             f"which has your real files and its network, and end at once. Close {t.name} first, then "
                             "start it again.")
    # sandboxes of its own (seccomp's nesting profile): as ticked, else as the trial guessed (seccomp.nesting_reason)
    nesting = options["nesting"] is True if isinstance(options.get("nesting"), bool) else bool(t.nesting)
    t.options = {"network": network, "gpu": bool(options.get("gpu")), "sound": bool(options.get("sound")),
                 "nested": bool(options.get("nested")), "decoys": options.get("decoys") is not False,
                 "nesting": nesting and eng.id == "bubblewrap", "real_display": options.get("real_display") is True}
    what = "the app" if t.private_at is not None else "the program"         # a Box's, a trial's
    disp = sandbox.display(host, t.private, landlock=False, what=what)
    # on X11 a display of its own wherever Xephyr is installed; this one only when the user said it may (own_display)
    if disp.kind == "x11" and not disp.network:
        from .browser import _install_command
        if eng.id == "flatpak":
            if not t.options["real_display"]:       # Flatpak gives it the X server's own socket: no Xephyr for it
                raise TrialError("On X11, a Flatpak app is given this display, where it could read what every other "
                                 "window shows and what you type into them, and type into them itself, a terminal "
                                 "included. Tick that it may use this display, knowing that, to start it.")
        else:
            try:
                t.options["nested"] = sandbox.own_display(host, disp, options.get("nested"), t.options["real_display"],
                                                          what, _install_command(host, "Xephyr"))
            except sandbox.SandboxError as e:
                raise TrialError(str(e)) from None
    if disp.network:
        raise TrialError(f"{disp.note}: the sandbox, which never has the computer's own network, can't reach it. "
                         f"Start {what} from the computer's own desktop.")
    if disp.kind == "none":
        raise TrialError(disp.note or f"There is no display to show {what} on.")
    sync, context, pasta_path, unmarked, filt = None, None, None, False, None
    if t.options["decoys"] and not t.decoys:
        t.decoys = bait.plant(t.home)
    ignore = FLATPAK_OWN if eng.id == "flatpak" else ()
    if eng.id == "flatpak":                             # what its portals may leave outside the sandbox (portal_marks)
        t.portal_before = portal_marks(host)
    t.watch = homewatch.HomeWatch(t.home, t.decoys, ignore)
    # a Box's Exchange folder is bound into the home: what the app saves there goes to that folder, which the home's
    # watch never sees (only the empty mount point under the bind), so it has a watch of its own (put_in_shared)
    t.shared = [homewatch.HomeWatch(Path(outside)) for outside, _inside in t.binds]
    try:
        if eng.id == "bubblewrap":
            if t.kind == "deb" and package_part(t, "usr"):
                problem = probe_overlay(host)
                if problem:
                    raise TrialError(f"This package can't be tried here: {problem}")
            if t.options["nested"] and disp.kind == "x11":
                disp, t.xephyr = _nested(host, t, spawn)
            elif disp.kind == "wayland":
                compositor = str(host.sys_path(disp.binds[0][0]))
                try:
                    sync = wayland.sandbox_socket(compositor, t.private / "wayland-0", "org.daprivacyscanner.trial")
                    context = sync is not None
                except (OSError, wayland.WaylandError):
                    # the desktop has the protocol, but marking failed: the program is on its own connection, and the
                    # page says so (it said only when the connection was marked: the review of 2026-11-04)
                    context, unmarked = False, True
                if sync is not None:
                    disp.binds[0] = (str(t.private / "wayland-0"), disp.binds[0][1])
            if network == "observed":
                pasta_path = sandbox.program(host, sandbox.PASTA)
                if not pasta_path or sandbox.probe_pasta(host):
                    raise TrialError("The observed network needs pasta (the passt package), which isn't usable here. "
                                     "Choose no network.")
                if sandbox.probe_fence(host):
                    raise TrialError("The local network can't be fenced off here, so the trial isn't given a network.")
                t.flows = pcap.Flows(sandbox.DNS_FORWARD)      # its lookups go there: not a host contacted
                t.reader = PipeReader(t.private / "packets", t.flows)
            # the lookups go through the filter in front of pasta's forwarder where python3 is there (sandbox.dns_filter)
            etc = sandbox.identity_files(t.private / "etc", sandbox.lookups_resolv(host, True) if pasta_path else None)
        else:
            etc = {}
        devices = tuple(sandbox.gpu(host)) if t.options["gpu"] and t.xephyr is None and eng.id == "bubblewrap" else ()
        if eng.id == "bubblewrap":                      # under pasta a file of the app's, else a memory file
            filt = sandbox.make_filter(seccomp.NESTING if t.options["nesting"] else seccomp.STRICT,
                                       sandbox.filter_folder(host, t.private) if pasta_path else None)
        parts = Parts(disp, etc, pasta_path, t.private / "packets" if pasta_path else None, sync, devices, t.options["sound"],
                      filt)
        # bubblewrap's sandbox has STAY as its first process (python3 is there: tethered needs it too), Flatpak's doesn't
        cmd = tethered(host, sandbox.fresh_keyring(host, eng.command(host, t, parts)), hold=eng.id == "bubblewrap")
        # in a group of its own, with a limit on the memory and the processes it may take (`capped`). Outermost, and
        # systemd-run --scope becomes the command's own process, so TETHER still answers to the app and Stop still
        # reaches the group. A Flatpak app moves itself into a group of Flatpak's, which this one doesn't hold: not
        # capped there, and the page says so
        cap_why = probe_capped(host) if eng.id == "bubblewrap" else "a Flatpak app runs in a group of Flatpak's own."
        env = dict(sandbox.SPAWN_ENV)                   # none of the app's: the program could read it (bubblewrap's)
        if eng.id == "bubblewrap":
            cmd = capped(host, cmd)
            if not cap_why:
                env.update(cap_env(host))
        if eng.id == "flatpak":
            env = host_env(host.environ)
            real = host.home / ".local/share/flatpak"
            env = {**env, "HOME": str(t.home), **({"FLATPAK_USER_DIR": str(real)} if real.is_dir() else {})}
        t.how = {"engine": eng.id, "engine_name": eng.name, "network": network, "lan_blocked": network == "observed",
                 "display": disp.kind, "wayland_context": context, "wayland_failed": unmarked,
                 "nested": t.xephyr is not None, "nesting": t.options["nesting"],
                 "filter": filt is not None and (filt.fd is not None or filt.file is not None),
                 "gpu": bool(devices) or (eng.id == "flatpak" and t.options["gpu"]), "sound": t.options["sound"],
                 "decoys": sum(1 for k in t.decoys if not t.decoys[k].startswith("the folder ")),
                 "capped": None if cap_why else {"memory": memory_cap(host), "tasks": TASKS_MAX},
                 "capped_why": cap_why, "whole": shown(cmd)}
        t.watch.start()
        for w in t.shared:
            w.start()
        if t.reader is not None:
            t.reader.start()
        through_stdin = bool(pasta_path) and sync is not None
        t.proc = spawn(cmd, cwd="/", env=env, stdin=sync if through_stdin else subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                       pass_fds=((sync,) if sync is not None and not through_stdin else ()) + (filt.fds() if filt else ()))
    except BaseException:
        _abort(t, sync)
        raise
    finally:
        if filt is not None:
            filt.close()                                # bubblewrap has read it
    if sync is not None:
        os.close(sync)                                  # bubblewrap holds it now
    t.state, t.started = "running", time.time()
    if t.where == "memory":                             # the session's own tmpfs: it is ended before it fills it
        t.room = RoomWatch(host, t)
        t.room.start()
    if getattr(t.proc, "stdout", None) is not None:
        t.output = Tail(t.proc.stdout)
        t.output.start()
    if hasattr(t.proc, "poll"):
        deadline = time.monotonic() + START_WAIT
        while t.proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
    return t.how


SCRIPTS = {STAY: "<wait for everything it starts>", sandbox.KEYRING: "<a keyring of its own, no crash dumps>",
           TETHER: "<end it if the app ends>", sandbox.OPEN_FILTER: "<open its system-call filter>"}


def shown(cmd: list[str]) -> str:
    """The command as the page shows it: whole, but for the two small programs passed to python3 -c, named."""
    return shlex.join([SCRIPTS.get(a, a) for a in cmd])


def _abort(t: Trial, sync: int | None) -> None:
    if sync is not None:
        os.close(sync)
    if t.xephyr is not None and hasattr(t.xephyr, "kill"):
        t.xephyr.kill()
        t.xephyr = None
    if t.watch is not None and t.watch.fd >= 0:
        t.watch.stop()
    for w in t.shared:
        if w.fd >= 0:
            w.stop()
    t.shared = []
    if t.reader is not None:
        t.reader.stop()
        t.reader = None


def _signal(proc, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError, OSError, AttributeError):
        pass


def poll(host: Host, t: Trial) -> None:
    """Notices that the program has ended by itself, and sums the trial up then. The page asks while a stop may
    be under way in another thread: then there is nothing to do here."""
    if not t.lock.acquire(blocking=False):
        return
    try:
        if t.state == "running" and hasattr(t.proc, "poll") and t.proc.poll() is not None:
            _finish(host, t)
    finally:
        t.lock.release()


def _stay_of(pid: int) -> int | None:
    """The sandbox's first process, STAY, by its number on the computer: among the descendants of `pid` (the trial's
    command), the one that is PID 1 of a PID namespace of its own and runs STAY. None where there is none (no python3
    on the computer, a Flatpak's sandbox, or not started yet)."""
    kids: dict[int, list[int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return None
    for name in names:
        if name.isdigit():
            try:
                with open(f"/proc/{name}/stat", encoding="utf-8", errors="replace") as f:
                    kids.setdefault(int(f.read().rsplit(")", 1)[1].split()[1]), []).append(int(name))
            except (OSError, IndexError, ValueError):
                continue
    todo, seen = list(kids.get(pid, [])), set()
    while todo:
        p = todo.pop(0)
        if p in seen:
            continue
        seen.add(p)
        try:
            with open(f"/proc/{p}/status", encoding="utf-8", errors="replace") as f:     # its name: any bytes
                ns = next((ln.split()[1:] for ln in f if ln.startswith("NSpid:")), [])
            with open(f"/proc/{p}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        if len(ns) > 1 and ns[-1] == "1" and STAY.encode() in argv:
            return p
        todo += kids.get(p, [])
    return None


def stop(host: Host, t: Trial) -> None:
    """Ends the trial's program (it is the trial's own: started here, in its sandbox) and sums it up: asked to end
    (SIGTERM to STAY, which passes it on in the sandbox; to the command's group where there is no STAY, which a held
    command, bubblewrap's, keeps pending), killed when it hasn't after a few seconds."""
    with t.lock:
        if t.state != "running":
            return
        t.stopped = True
        if hasattr(t.proc, "poll"):
            stay = _stay_of(t.proc.pid)
            if stay is not None:
                try:
                    os.kill(stay, signal.SIGTERM)
                except OSError:
                    stay = None
            if stay is None:
                _signal(t.proc, signal.SIGTERM)
            deadline = time.monotonic() + 4
            while t.proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            if t.proc.poll() is None:
                _signal(t.proc, signal.SIGKILL)
                try:
                    t.proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    pass
        _finish(host, t)


def _finish(host: Host, t: Trial) -> None:
    t.exit = t.proc.poll() if hasattr(t.proc, "poll") else 0
    t.ended, t.state = time.time(), "ended"
    if t.room is not None:
        t.room.done.set()
        t.room = None
    copies = end_flatpak_copies(host, t) if t.kind == "flatpak" else 0     # what it started through Flatpak's portal
    time.sleep(0.3)                                     # the last events
    if t.watch is not None:
        t.watch.stop()
    for shared in t.shared:
        shared.stop()
    if t.reader is not None:
        t.reader.stop()
    if t.xephyr is not None and hasattr(t.xephyr, "poll") and t.xephyr.poll() is None:
        _signal(t.xephyr, signal.SIGTERM)
    if t.output is not None:
        t.output.join(timeout=2)
    seconds = (t.ended or 0) - (t.started or 0)
    ignore = FLATPAK_OWN if t.kind == "flatpak" else ()
    w = activity.Where(str(t.home), host.uid)
    records = t.watch.records() if t.watch is not None else []
    sig = ended_by_signal(t.exit) if not t.stopped else None
    # a program asked to end (SIGTERM at logout or shutdown, a hang-up, an interrupt) or killed didn't fail: only an
    # exit status of its own, or a crash, is an error
    failed = t.exit not in (0, None) and not t.stopped and (sig is None or sig in CRASHES)
    t.result = {
        "signal": sig, "ended": ROOM_WORDS if t.short_of_room is not None
        else ended_words(t.exit, t.stopped, sig, t.how.get("capped")),
        "short_of_room": t.short_of_room,
        "summary": activity.summarise(records, w, seconds, names=True),
        "decoys": t.watch.decoys() if t.watch is not None else [],
        "decoys_planted": t.how.get("decoys", 0),
        "left": homewatch.left(t.home, t.decoys, ignore),
        "network": t.how.get("network", "off"),
        "hosts": t.flows.result() if t.flows is not None else None,
        "seconds": round(seconds),
        "failed": failed,
        "output": t.output.lines() if t.output is not None and (failed or seconds < 5) else [],
        "missed": (t.watch.overflow if t.watch is not None else 0) + (t.watch.left_out if t.watch is not None else 0),
        "copies_ended": copies,
        # what its portals left outside the sandbox: an autostart entry, a permission the desktop recorded
        "portal": portal_changes(t.portal_before, portal_marks(host)) if t.portal_before is not None else None,
        "exchange": put_in_shared(t.shared) if t.binds else None,
    }
    t.watch = None
    t.shared = []
    t.reader = None


def put_in_shared(watches: list[homewatch.HomeWatch]) -> int:
    """How many files were put in a Box's Exchange folder while it ran (made, written or moved in, and still there),
    from that folder's own watch. inotify doesn't say who did it: one copied in from outside meanwhile counts too."""
    return sum(1 for w in watches for path, flags, *_ in w.records()
               if not flags & activity.DIR and flags & (activity.CREATED | activity.WRITTEN | activity.MOVED)
               and not flags & activity.DELETED)


CRASHES = ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE", "SIGSYS", "SIGTRAP")
SIGNAL_WORDS = {"SIGTERM": "was asked to end (SIGTERM, as at logout or shutdown)",
                "SIGHUP": "ended with its session (SIGHUP)",
                "SIGINT": "was interrupted (SIGINT)",
                "SIGKILL": "was killed (SIGKILL: by the system when memory ran short, or by a kill command)",
                "SIGQUIT": "was asked to quit (SIGQUIT)"}


def ended_by_signal(code: int | None) -> str | None:
    """The signal that ended the program, by name, from its exit status: negative for the process the app started,
    128 plus the signal's number as bubblewrap and the sandbox's command (STAY) pass it on. None for an exit of its
    own."""
    if code is None:
        return None
    n = -code if code < 0 else code - 128 if 128 < code <= 128 + 64 else 0
    if not n:
        return None
    try:
        return signal.Signals(n).name
    except ValueError:
        return f"signal {n}"


def ended_words(code: int | None, stopped: bool, sig: str | None, capped: dict | None = None) -> str:
    """How the program ended, in words, after "It ran for N minutes and …". `capped`: the limits it ran under
    (how["capped"]), which is what kills a program with SIGKILL while there is memory left on the computer."""
    if stopped:
        return "was ended here"
    if sig in CRASHES:
        return f"crashed ({sig})"
    if sig == "SIGKILL" and capped:
        return ("was killed (SIGKILL), which is what happens when a trial reaches the limit on the memory or the "
                "number of processes it may take, or when the computer itself runs short of memory")
    if sig:
        return SIGNAL_WORDS.get(sig, f"was ended by a signal ({sig})")
    if code not in (0, None):
        return f"ended with an error (exit status {code})"
    return "ended by itself"


def discard(host: Host, t: Trial) -> None:
    """Ends the trial if it runs and removes everything of it: overwritten first when it is in memory."""
    if t.state == "running":
        stop(host, t)
    _remove(t.folder, t.where == "memory")
    _let_go(t.folder)
    t.state = "discarded"
