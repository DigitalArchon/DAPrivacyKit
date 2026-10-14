"""Try an app (docs/TECHNICAL.md, Tools): run a program you don't know yet in a sandbox with a throwaway home,
and see what it does: what it writes, which decoy files it looks at, which hosts it contacts. Nothing of the
user's is within its reach, and nothing of the trial is kept.

What can be tried (`prepare`):
- a downloaded file: an AppImage (run with APPIMAGE_EXTRACT_AND_RUN, since it can't mount itself in a sandbox),
  a program, a script. It is copied into the trial's folder; the original isn't touched or run;
- an archive (tar, zip): unpacked inside a sandbox with no network, then the user picks the program in it;
- a .deb: unpacked the same way, never installed; its /usr is laid over the computer's inside the sandbox (an
  overlay, mounted by a first bubblewrap that is root of its own user namespace, then the real sandbox inside
  it: works with bubblewrap 0.9, which has no overlay option of its own; tested on Mint 22.3) and its /opt put
  at /opt, so the program finds its files where it expects them. What it depends on isn't installed for it;
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
doesn't erase it, and the page says so). One trial at a time; quitting the app ends and discards it."""

from __future__ import annotations

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
from typing import Callable

from ..host import Host
from ..hostenv import host_env
from . import activity, bait, homewatch, menu, pcap, ramdisk, sandbox, wayland
from .viewer import _program

FOLDER = "daprivacyscanner-trial"
APP_IN = "/app"
COPY_MAX = 8 << 30                       # the largest file copied in
UNPACK_MAX = 8 << 30                     # the most an archive may unpack to
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
    # while it runs
    proc: object = None
    xephyr: object = None
    watch: homewatch.HomeWatch | None = None
    flows: pcap.Flows | None = None
    output: "Tail | None" = None
    reader: "PipeReader | None" = None
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
                "state": self.state, "command": shlex.join(self.argv) if self.argv else "", "candidates": self.candidates,
                "options": self.options, "how": self.how, "started": self.started, "ended": self.ended,
                "exit": self.exit, "stopped": self.stopped, "notes": self.notes, "live": live, "result": self.result,
                "now": time.time()}


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
    for sub in ("home", "app", "private"):
        (folder / sub).mkdir(mode=0o700)
    return tid, folder


def leftovers(host: Host) -> list[str]:
    """Trial folders an earlier run of the app left (it was killed): removed at the next start."""
    out = []
    for place in places(host):
        base = Path(place["folder"])
        try:
            out += [str(base / n) for n in os.listdir(base) if re.fullmatch(r"[0-9a-f]{12}", n)]
        except OSError:
            continue
    return out


def _remove(folder: Path, in_memory: bool) -> None:
    if not folder.is_dir() or folder.is_symlink():
        return
    if in_memory:
        try:
            ramdisk.wipe(folder)                      # overwritten in place: its pages are memory (rule 8)
        except OSError:
            pass
    shutil.rmtree(folder, ignore_errors=True)


def clear_leftovers(host: Host) -> None:
    memory = {p["folder"] for p in places(host) if p["id"] == "memory"}
    for path in leftovers(host):
        _remove(Path(path), str(Path(path).parent) in memory)


# ------------------------------------------------------------------ unpacking, inside a sandbox

# runs inside the sandbox: unpacks argv[1] into argv[2], at most argv[3] bytes in all. A .deb is an ar archive
# holding data.tar.*; tar's own filter keeps every member inside the folder (and the sandbox would anyway).
UNPACK = r"""
import io, os, subprocess, sys, tarfile, zipfile
src, dst, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
def tar(f):
    kw = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
    total = 0
    with tarfile.open(fileobj=f, mode="r|*") as t:
        for m in t:
            total += m.size
            if total > limit:
                sys.exit("It unpacks to more than this allows.")
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
                    if os.path.exists("/usr/bin/dpkg-deb"):
                        sys.exit(subprocess.run(["/usr/bin/dpkg-deb", "-x", src, dst]).returncode)
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
            if sum(i.file_size for i in z.infolist()) > limit:
                sys.exit("It unpacks to more than this allows.")
            for i in z.infolist():
                out = z.extract(i, dst)
                mode = (i.external_attr >> 16) & 0o777
                if mode and not i.is_dir():
                    os.chmod(out, mode | 0o600)
    else:
        tar(f)
"""


def unpack_argv(host: Host, source: Path, dest: Path, limit: int = UNPACK_MAX) -> list[str]:
    """The archive or .deb `source` unpacked into `dest` by the computer's python3 in a sandbox with no network,
    which sees only the file (read-only) and the folder."""
    return [sandbox._need(host, sandbox.BWRAP), *sandbox.namespaces(False), *sandbox.system(host),
            "--ro-bind", str(source), "/in/source", "--bind", str(dest), "/out", "--chdir", "/out",
            "--setenv", "PATH", "/usr/bin:/bin", "--",
            sandbox.PYTHON, "-I", "-c", UNPACK, "/in/source", "/out", str(limit)]


def _looks_runnable(path: Path, st: os.stat_result) -> str | None:
    """What a file in an unpacked tree is, if it is something to start: in words, or None."""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if head.startswith(b"\x7fELF"):
        if head[8:10] == b"AI":
            return "an AppImage"
        return "a Linux program" if st.st_mode & 0o111 and head[16:18] in (b"\x02\x00", b"\x03\x00") else None
    if head.startswith(b"#!"):
        return "a script"
    if path.suffix in (".py", ".sh") and b"\0" not in head:
        return "a script"
    return None


def candidates(tree: Path, deb: bool) -> list[dict]:
    """The programs in an unpacked archive or package that the user can pick: {"rel", "what", "label"}. A menu
    entry's program first (a .deb's /usr/share/applications), then programs near the top, never through a link
    that leaves the tree."""
    found: dict[str, dict] = {}
    root = os.path.realpath(tree)

    def resolved(p: Path) -> str | None:
        """Where `p` leads inside the tree, as it will in the sandbox: a link to an absolute path (a package's
        /usr/bin/foo -> /opt/Foo/foo) means that path in the tree, never the computer's. None when it leaves it."""
        path = os.path.normpath(os.path.join(root, os.path.relpath(p, tree)))
        for _ in range(12):
            if path != root and not path.startswith(root + "/"):
                return None
            if not os.path.islink(path):
                return path
            target = os.readlink(path)
            path = os.path.normpath(root + target if target.startswith("/") else os.path.join(os.path.dirname(path), target))
        return None

    def add(p: Path, label: str = "") -> None:
        real = resolved(p)
        if real is None or real in found or len(found) >= CANDIDATES_MAX:
            return
        try:
            st = os.lstat(real)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode):
            return
        what = _looks_runnable(Path(real), st)
        if what:
            found[real] = {"rel": str(p)[len(str(tree)) + 1:], "what": what, "label": label}

    for desk in sorted(tree.glob("usr/share/applications/*.desktop")) + sorted(tree.glob("*.desktop")):
        try:
            text = desk.read_text(errors="replace")[:20000]
        except OSError:
            continue
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
        tries = [tree / first.lstrip("/")] if first.startswith("/") else \
            [tree / d / first for d in ("usr/bin", "usr/games", "usr/local/bin", "bin", "")]
        for t in tries:
            if resolved(t) and os.path.exists(resolved(t)):
                add(t, name.group(1).strip() if name else "")
                break
    tops = ("usr/bin", "usr/games", "usr/local/bin", "opt") if deb else ("",)
    for top in tops:
        base = tree / top if top else tree
        depth_max = 3 if top in ("opt", "") else 1
        stack = [(base, 0)]
        while stack:
            folder, depth = stack.pop(0)
            try:
                entries = sorted(os.scandir(folder), key=lambda e: e.name)
            except OSError:
                continue
            for e in entries:
                p = Path(e.path)
                if e.is_dir(follow_symlinks=False):
                    if depth + 1 < depth_max and not e.name.startswith(".") and e.name not in ("lib", "lib64", "share", "locales", "resources", "node_modules"):
                        stack.append((p, depth + 1))
                else:
                    add(p)
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
        raise TrialError(f"Programs can't be run from that place here (it is mounted noexec)."
                         + (" Choose the disk instead." if where == "memory" else ""))
    tid, folder = _make(host, where)
    t = Trial(tid, folder, where, sub.kind, path.name, sub.what)
    try:
        if sub.kind in ("archive", "deb"):
            if not sandbox.program(host, sandbox.BWRAP):
                raise TrialError("Unpacking it safely needs bubblewrap (the bubblewrap package).")
            r = run(unpack_argv(host, path, t.app), cwd="/", env=host_env(host.environ), stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=900)
            if r.returncode:
                err = (r.stderr or b"").decode(errors="replace").strip().splitlines()
                raise TrialError(f"{path.name} couldn't be unpacked: " + (err[-1][:300] if err else f"exit status {r.returncode}"))
            t.candidates = candidates(t.app, sub.kind == "deb")
            if not t.candidates:
                raise TrialError(f"Nothing in {path.name} looks like a program to start.")
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
                            "only what this trial grants given back. Its real data (in ~/.var/app) isn't touched.",
                            "It can still ask the desktop through its portals, as every Flatpak app can: a file chooser "
                            "that you answer (a file you pick there is a real one), notifications, opening a link."])
    prog = _program(host, app.argv[0])
    if prog is None:
        raise TrialError(f"{app.name}'s program ({app.argv[0]}) isn't in the system's folders, so it can't be started "
                         "in the sandbox (which has no home folder of yours in it).")
    tid, folder = _make(host, where)
    return Trial(tid, folder, where, "installed", app.name, "an installed app", argv=[prog, *app.argv[1:]],
                 host_opt=prog.startswith("/opt/") or any(a.startswith("/opt/") for a in app.argv), env=dict(app.env),
                 notes=["It starts as on a first run: none of your settings, accounts or files are there."])


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
        inside = ("/" + rel) if t.kind == "deb" else f"{APP_IN}/{rel}"
        with (t.app / rel).open("rb") as f:
            first = f.read(2)
        if c["what"] == "a script" and first != b"#!":
            t.argv = [sandbox.PYTHON if rel.endswith(".py") else "/bin/sh", inside]
        elif c["what"] == "a script" and not os.access(t.app / rel, os.X_OK):
            t.argv = ["/bin/sh", "-c", 'exec "$(sed -n \'1s/^#! *//p\' "$0" | cut -d" " -f1)" "$0" "$@"', inside]
        else:
            t.argv = [inside]
        t.env.pop("APPIMAGE_EXTRACT_AND_RUN", None)
        if c["what"] == "an AppImage":
            t.env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
        t.argv += args
    elif args:
        t.argv = [*t.argv, *args]


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
STAY = """\
import ctypes, os, sys, time
HELPERS = %r
ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)
first = os.fork()
if not first:
    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    except OSError as e:
        sys.stderr.write("It couldn't be started: %%s\\n" %% e.strerror)
        os._exit(127)
def only_helpers():
    for p in os.listdir("/proc"):
        if p.isdigit() and int(p) not in (1, os.getpid()):
            try:
                with open("/proc/" + p + "/comm") as f:
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
# "$1" is mount, "$2" the package's usr folder: its ":" "," and "\" escaped as overlayfs's options want them (a trial's
# folder is under the runtime or cache folder, whose path is the user's to choose), then the command after the two
OVERLAY = (r"""lower=$(printf %s "$2" | sed -e 's/\\/\\\\/g' -e 's/,/\\,/g' -e 's/:/\\:/g'); """
           '"$1" -t overlay overlay -o "lowerdir=$lower:/usr" /usr || { echo "The package\'s files could not be laid over '
           '/usr" >&2; exit 1; }; shift 2; exec "$@"')


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


class Bubblewrap(Engine):
    id, name = "bubblewrap", "bubblewrap"

    def probe(self, host: Host) -> str | None:
        return sandbox.probe(host)

    def command(self, host: Host, t: Trial, parts: Parts) -> list[str]:
        bwrap = sandbox._need(host, sandbox.BWRAP)
        # --die-with-parent: Stop ends bubblewrap, and the sandbox must go with it. Its own process is in a session
        # of its own (--new-session), so a signal to the group doesn't reach it: without this the program ran on
        # after Stop, its folder deleted under it (seen with KWrite on CachyOS)
        a = [bwrap, "--die-with-parent", *sandbox.namespaces(bool(parts.pasta)), *sandbox.system(host),
             *sandbox.identity(host, parts.etc, own_dns=bool(parts.pasta)), *sandbox._gpu_argv(parts.devices)]
        a += ["--bind", str(t.home), sandbox.HOME_IN, "--perms", "0700", "--dir", sandbox.RUNTIME_IN]
        if t.kind == "deb":
            if (t.app / "opt").is_dir():
                a += ["--ro-bind", str(t.app / "opt"), "/opt"]
        else:
            if t.app.is_dir():
                a += ["--ro-bind", str(t.app), APP_IN]
            if t.host_opt:
                a += ["--ro-bind", "/opt", "/opt"]
        for outside, inside in t.binds:
            a += ["--bind", outside, inside]
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
        a += ["--chdir", sandbox.HOME_IN, "--", *stay, *t.argv]
        if t.kind == "deb" and (t.app / "usr").is_dir():
            # a first bubblewrap, root of its own user namespace, lays the package's /usr over the computer's; the
            # sandbox proper then starts inside that view
            a = [bwrap, "--die-with-parent", "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "ALL",
                 "--dev-bind", "/", "/", "--", "/bin/sh", "-c", OVERLAY, "sh", sandbox._need(host, "mount"),
                 str(t.app / "usr"), *a]
        if not parts.pasta:
            return a
        fence = sandbox.fence(host, proxies=False)
        if fence is None:
            raise sandbox.SandboxError("The local network can't be fenced off (iproute2's ip isn't installed).")
        return [parts.pasta, *sandbox.PASTA_OPTS, "--pcap", str(parts.pcap), "--", *fence, *a]


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
        a = [sandbox.program(host, "flatpak") or "flatpak", "run", "--sandbox", "--session-bus", "--die-with-parent",
             "--filesystem=home",
             "--share=network" if o.get("network") == "on" else "--unshare=network"]
        a += ["--socket=wayland"] if parts.disp.kind == "wayland" else ["--socket=x11", "--share=ipc"]
        if o.get("gpu"):
            a.append("--device=dri")
        if o.get("sound"):
            a.append("--socket=pulseaudio")
        a += [f"--filesystem={outside}" for outside, _inside in t.binds]
        return a + t.argv


ENGINES: dict[str, Engine] = {e.id: e for e in (Bubblewrap(), Flatpak())}


def engine_of(t: Trial) -> Engine:
    return ENGINES["flatpak" if t.kind == "flatpak" else "bubblewrap"]


def probe_overlay(host: Host) -> str | None:
    """Why a .deb's files can't be laid over /usr here, or None: tried with an empty folder."""
    bwrap, mount = sandbox.program(host, sandbox.BWRAP), sandbox.program(host, "mount")
    if not bwrap or not mount:
        return "bubblewrap or mount isn't installed."
    r = host.run(bwrap, "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "ALL", "--dev-bind", "/", "/", "--",
                 "/bin/sh", "-c", OVERLAY, "sh", mount, "/var/empty" if host.sys_path("/var/empty").is_dir() else "/mnt",
                 "/usr/bin/true", timeout=20)
    if r.ok:
        return None
    err = (r.stderr or r.stdout).strip().splitlines()
    return f"an overlay can't be mounted in a sandbox here ({err[-1][:160] if err else f'exit status {r.returncode}'})."


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
        import select
        try:
            while True:
                ready = select.select([self.fd], [], [], 0.3)[0]
                if ready:
                    try:
                        self.flows.feed(os.read(self.fd, 1 << 18))
                    except BlockingIOError:
                        pass
                elif self.done.is_set():
                    return
        except (OSError, ValueError):
            return

    def stop(self) -> None:
        self.done.set()
        self.join(timeout=3)
        try:
            os.close(self.fd)
        except OSError:
            pass


# ------------------------------------------------------------------ starting, ending

def status(host: Host) -> dict:
    """What a trial can have here: the engines, the network, the display, where it can live."""
    from . import browser
    sb = browser.sandbox_status(host)
    flat = ENGINES["flatpak"].probe(host)
    return {"available": sb["available"], "why": sb["why"], "apparmor": sb["apparmor"], "python": sb["python"],
            "pasta": sb["pasta"], "display": sb["display"], "wayland_context": sb["wayland_context"],
            "wayland_risky": sb["wayland_risky"], "xephyr": sb["xephyr"], "sound": sb["sound"], "gpu": sb["gpu"],
            "flatpak": flat is None, "places": places(host),
            "engines": [{"id": e.id, "name": e.name} for e in ENGINES.values()]}


def _nested(host: Host, t: Trial, spawn: Callable):
    """Xephyr in its own sandbox, started and waited for: (the display the program then gets, its process)."""
    if not sandbox.program(host, sandbox.XEPHYR):
        raise TrialError("A display of its own needs Xephyr, which isn't installed. Untick it, or install it.")
    nest = sandbox.nested(host, t.private, f"Try an app: {t.name}", sandbox.screen_size(host))
    if nest is None:
        raise TrialError("A display of its own works on this computer's own X11 display only. Untick it.")
    proc = spawn(sandbox.fresh_keyring(host, nest.argv), cwd="/", env=host_env(host.environ), stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
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
    network = options.get("network") if options.get("network") in ("off", "observed", "on") else "off"
    if network == "on" and eng.id != "flatpak":
        raise TrialError("A trial never shares this computer's network: choose no network, or the observed one.")
    if network == "observed" and eng.id == "flatpak":
        raise TrialError("A Flatpak app's network can't be observed from here: choose none, or its usual network.")
    t.options = {"network": network, "gpu": bool(options.get("gpu")), "sound": bool(options.get("sound")),
                 "nested": bool(options.get("nested")), "decoys": options.get("decoys") is not False}
    disp = sandbox.display(host, t.private, landlock=False)
    if disp.kind == "none" or disp.network:
        raise TrialError(disp.note or "There is no display to show it on.")
    sync, context, pasta_path = None, None, None
    if t.options["decoys"] and not t.decoys:
        t.decoys = bait.plant(t.home)
    ignore = FLATPAK_OWN if eng.id == "flatpak" else ()
    t.watch = homewatch.HomeWatch(t.home, t.decoys, ignore)
    try:
        if eng.id == "bubblewrap":
            if t.kind == "deb" and (t.app / "usr").is_dir():
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
                    context = False
                if sync is not None:
                    disp.binds[0] = (str(t.private / "wayland-0"), disp.binds[0][1])
            if network == "observed":
                pasta_path = sandbox.program(host, sandbox.PASTA)
                if not pasta_path or sandbox.probe_pasta(host):
                    raise TrialError("The observed network needs pasta (the passt package), which isn't usable here. "
                                     "Choose no network.")
                if sandbox.probe_fence(host):
                    raise TrialError("The local network can't be fenced off here, so the trial isn't given a network.")
                t.flows = pcap.Flows()
                t.reader = PipeReader(t.private / "packets", t.flows)
            etc = sandbox.identity_files(t.private / "etc", f"nameserver {sandbox.DNS_FORWARD}\n" if pasta_path else None)
        else:
            etc = {}
        devices = tuple(sandbox.gpu(host)) if t.options["gpu"] and t.xephyr is None and eng.id == "bubblewrap" else ()
        parts = Parts(disp, etc, pasta_path, t.private / "packets" if pasta_path else None, sync, devices, t.options["sound"])
        cmd = sandbox.fresh_keyring(host, eng.command(host, t, parts))
        env = host_env(host.environ)
        if eng.id == "flatpak":
            real = host.home / ".local/share/flatpak"
            env = {**env, "HOME": str(t.home), **({"FLATPAK_USER_DIR": str(real)} if real.is_dir() else {})}
        t.how = {"engine": eng.id, "engine_name": eng.name, "network": network, "lan_blocked": network == "observed",
                 "display": disp.kind, "wayland_context": context, "nested": t.xephyr is not None,
                 "gpu": bool(devices) or (eng.id == "flatpak" and t.options["gpu"]), "sound": t.options["sound"],
                 "decoys": sum(1 for k in t.decoys if not t.decoys[k].startswith("the folder ")),
                 "whole": shown(cmd)}
        t.watch.start()
        if t.reader is not None:
            t.reader.start()
        through_stdin = bool(pasta_path) and sync is not None
        t.proc = spawn(cmd, cwd="/", env=env, stdin=sync if through_stdin else subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                       pass_fds=(sync,) if sync is not None and not through_stdin else ())
    except BaseException:
        _abort(t, sync)
        raise
    if sync is not None:
        os.close(sync)                                  # bubblewrap holds it now
    t.state, t.started = "running", time.time()
    if getattr(t.proc, "stdout", None) is not None:
        t.output = Tail(t.proc.stdout)
        t.output.start()
    if hasattr(t.proc, "poll"):
        deadline = time.monotonic() + START_WAIT
        while t.proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
    return t.how


SCRIPTS = {STAY: "<wait for everything it starts>", sandbox.KEYRING: "<a keyring of its own, no crash dumps>"}


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


def stop(host: Host, t: Trial) -> None:
    """Ends the trial's program (it is the trial's own: started here, in its sandbox) and sums it up."""
    with t.lock:
        if t.state != "running":
            return
        t.stopped = True
        if hasattr(t.proc, "poll"):
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
    time.sleep(0.3)                                     # the last events
    if t.watch is not None:
        t.watch.stop()
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
    failed = t.exit not in (0, None) and not t.stopped
    t.result = {
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
    }
    t.watch = None
    t.reader = None


def discard(host: Host, t: Trial) -> None:
    """Ends the trial if it runs and removes everything of it: overwritten first when it is in memory."""
    if t.state == "running":
        stop(host, t)
    _remove(t.folder, t.where == "memory")
    t.state = "discarded"
