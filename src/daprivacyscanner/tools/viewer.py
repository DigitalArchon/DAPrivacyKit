"""View offline… (docs/TECHNICAL.md, Tools: Tor or Mullvad Browser in memory): a document or picture the browser
downloaded, opened in the user's own viewer for its kind of file, in a sandbox with no network, so opening it
can't fetch anything and reveal the real address (PDFs, office documents and web pages can).

The viewer is the one the desktop uses (`xdg-mime query default`, then its .desktop file's Exec line). The
file is first copied, through a descriptor opened without following links, into a folder of the app's own in
the RAM disk (.view-<random>, which no sandbox is given): the browser can change its Downloads folder at any
moment, and must not be able to swap the file for a link to something else between the check and the open.
- An ordinary program (in /usr, or /opt) runs in bubblewrap: no network at all (only loopback), the system
  read-only, /etc covered as the browser's sandbox has it, its home an empty folder in memory, that one file
  read-only in it, and the display's socket. No sound, no session D-Bus, no other file of the user's.
- A Flatpak app runs in Flatpak's own sandbox with what it declares for itself dropped (`flatpak run --sandbox`:
  no network, folders, sound, GVFS or ~/.var/app) and only the display, the filtered session bus with its own
  name, and the copy's folder, read-only, given back (FLATPAK_RUN); never while it is already open (`flatpak ps`:
  that copy would be handed the file over the session bus and open it with its network), and never a web
  browser. Links clicked in it can still open in the default browser (a portal), which the page says.
- A Snap, or a program in the home folder, isn't started: the page says why and what to choose instead.
Either runs under a keeper (KEEPER) and with --die-with-parent: ending any part of it ends all of it, while
quitting the app leaves it open.
The copy is judged again once it is out of the browser's reach (transfer.snapshot), and opened only when it is
what the page showed (`check`): the browser could have changed its file after it was listed.
Nothing is kept: the copies are overwritten and removed with the RAM disk, and earlier views' copies when the
next one starts, once their viewer has ended and no program holds them open (one too new to tell stays a
minute)."""

from __future__ import annotations

import mimetypes
import os
import re
import shlex
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..host import Host
from ..hostenv import host_env
from . import ramdisk, sandbox, sniff, transfer, wayland

SYSTEM_DIRS = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/games")
FIELD_FILE = ("%f", "%F", "%u", "%U")
FIELD_DROP = ("%i", "%c", "%k", "%d", "%D", "%n", "%N", "%v", "%m")
WATCH = 2.0                                  # seconds a viewer is watched for an error at its start
# what Python's own table may lack (it reads /etc/mime.types where there is one)
EXTRA_MIME = {".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
              ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
              ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
              ".odt": "application/vnd.oasis.opendocument.text", ".ods": "application/vnd.oasis.opendocument.spreadsheet",
              ".odp": "application/vnd.oasis.opendocument.presentation", ".epub": "application/epub+zip",
              ".doc": "application/msword", ".xls": "application/vnd.ms-excel", ".ppt": "application/vnd.ms-powerpoint",
              ".rtf": "application/rtf", ".webp": "image/webp", ".svg": "image/svg+xml", ".md": "text/markdown"}


class ViewError(ValueError):
    pass


@dataclass
class Viewer:
    app: str                                 # its name, from its .desktop file
    desktop_id: str
    argv: list[str]                          # inside the sandbox (native) or on the computer (flatpak)
    flatpak: str | None = None               # its app id
    opt: bool = False                        # it lives in /opt, which the sandbox then gets read-only
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"app": self.app, "desktop_id": self.desktop_id, "flatpak": self.flatpak,
                "command": shlex.join(self.argv), "notes": self.notes}


def mime_of(name: str, ins: sniff.Inspection) -> str | None:
    if ins.mime:
        return ins.mime
    ext = os.path.splitext(name)[1].lower()
    return EXTRA_MIME.get(ext) or mimetypes.guess_type(name, strict=False)[0]


def _data_dirs(host: Host) -> list[Path]:
    env = host.environ
    home_data = Path(env.get("XDG_DATA_HOME") or host.home / ".local/share")
    dirs = [home_data] + [Path(d) for d in (env.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":") if d]
    for extra in (host.home / ".local/share/flatpak/exports/share", Path("/var/lib/flatpak/exports/share")):
        if extra not in dirs:
            dirs.append(extra)
    return dirs


def desktop_entry(host: Host, desktop_id: str) -> tuple[Path, dict[str, str]] | None:
    """The [Desktop Entry] section of the app `desktop_id`, from the first data folder that has it."""
    if not re.fullmatch(r"[\w.+-]+\.desktop", desktop_id):
        return None
    for d in _data_dirs(host):
        p = d / "applications" / desktop_id
        path = p if str(p).startswith(str(host.home)) else host.sys_path(str(p))
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        entry, inside = {}, False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                inside = s == "[Desktop Entry]"
            elif inside and "=" in s and not s.startswith("#"):
                k, v = s.split("=", 1)
                entry.setdefault(k.strip(), v.strip())
        return path, entry
    return None


def _program(host: Host, name: str) -> str | None:
    """A program by its full path, from the system's folders only (never the home folder)."""
    if name.startswith("/"):
        ok = name.startswith(("/usr/", "/bin/", "/sbin/", "/opt/")) and host.sys_path(name).is_file()
        return name if ok else None
    for d in SYSTEM_DIRS:
        if host.sys_path(f"{d}/{name}").is_file():
            return f"{d}/{name}"
    return None


def viewer_for(host: Host, name: str, ins: sniff.Inspection, copy_name: str, view_dir: str) -> Viewer:
    """The desktop's viewer for the file `name`, whose copy `copy_name` will be in the folder `view_dir`, with the
    path it will be opened at in its command (in a native viewer's sandbox, its home; in a Flatpak's, where it is).
    Raises ViewError when there is none this can start."""
    if not ins.viewable:
        raise ViewError(f"{name} isn't a document or picture: View offline… opens only those.")
    mime = mime_of(name, ins)
    if not mime:
        raise ViewError(f"What kind of file {name} is couldn't be told, so no viewer could be chosen.")
    if not host.runner.which("xdg-mime"):
        raise ViewError("Choosing the viewer needs xdg-mime (the xdg-utils package), which isn't installed.")
    r = host.run("xdg-mime", "query", "default", mime)
    desktop_id = (r.stdout or "").strip().splitlines()[0] if r.ok and (r.stdout or "").strip() else ""
    found = desktop_entry(host, desktop_id) if desktop_id else None
    if not found:
        raise ViewError(f"No app is set to open {mime} files here. Choose one in your file manager (Open With → "
                        "set as default), then try again.")
    _, entry = found
    app = entry.get("Name", desktop_id)
    try:
        argv = shlex.split(entry.get("Exec", ""))
    except ValueError:
        argv = []
    while argv and (argv[0] == "env" or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argv[0])):
        argv = argv[1:]
    if not argv:
        raise ViewError(f"{app}'s launcher has no command in it.")
    if os.path.basename(argv[0]) == "flatpak":
        return _flatpak_viewer(host, app, desktop_id, entry, argv, f"{view_dir}/{copy_name}", view_dir)
    if argv[0].startswith("/snap/") or entry.get("X-SnapInstanceName") or os.path.basename(argv[0]) == "snap":
        raise ViewError(f"{app} is a Snap, which can't be started inside another sandbox. Choose a viewer from your "
                        "distribution's packages as the default for this kind of file, then try again.")
    prog = _program(host, argv[0])
    if prog is None:
        raise ViewError(f"{app}'s program ({argv[0]}) isn't in the system's folders, so it isn't started in the "
                        "sandbox. Choose a viewer from your distribution's packages as the default, then try again.")
    out, placed, file_in = [prog], False, f"{sandbox.HOME_IN}/{copy_name}"
    for a in argv[1:]:
        if a in FIELD_FILE:
            if not placed:
                out.append(file_in)
                placed = True
        elif a in FIELD_DROP:
            continue
        else:
            out.append(a.replace("%%", "%"))
    if not placed:
        out.append(file_in)
    return Viewer(app, desktop_id, out, opt=prog.startswith("/opt/"))


# A Flatpak viewer runs with what the app declares for itself dropped (`--sandbox`) and only this put back: the
# display, the filtered session bus (the portals: GTK 4 apps start their image loaders through one, and without it
# Evince 48 stopped at once, as in Try an app) with the app's own name to own (Text Editor 51 won't start without it:
# "Failed to register", tested on Mint 22.3 with Flatpak 1.14.6), and the copy's folder read-only. The review of
# 2026-10-17 found the launcher's own permissions with only the network and folders taken away too much: GVFS's
# daemons, outside the sandbox, fetched a web address for it (`gio cat http://…`) and read the trash, and the sound
# server's socket let it load a module that connected out. Under --sandbox, tested: none of those, no sound socket,
# no ~/.var/app/<id> at all (its home and /tmp are the sandbox's own, in memory: the per-app /tmp that kept
# Evince's recently-used.xbel after ~/TempBrowser had closed isn't there), and a launcher's own options are left out
# but for which branch, architecture and command. --die-with-parent: the keeper below is its parent.
FLATPAK_RUN = ("--sandbox", "--session-bus", "--die-with-parent", "--unshare=network", "--no-talk-name=org.gtk.vfs.*",
               "--nosocket=pulseaudio")
FLATPAK_KEPT = ("--branch=", "--arch=", "--command=")         # of a launcher's own options
FLATPAK_FORWARDING = ("--file-forwarding", "@@", "@@u")      # the document portal: the copy's folder is given instead
# What it would remember goes to its own /tmp, in memory, as well: flatpak run's --env can't move XDG_* (Flatpak sets
# them after it), so the command becomes `env`, which sets them inside, then runs the app's own command (Evince 48
# wrote the file's name into ~/.var/app's recently-used.xbel and GVFS metadata before --sandbox: tested).
FLATPAK_MEMORY = ("XDG_DATA_HOME=/tmp/.view/data", "XDG_CACHE_HOME=/tmp/.view/cache", "XDG_CONFIG_HOME=/tmp/.view/config",
                  "XDG_STATE_HOME=/tmp/.view/state", "TMPDIR=/tmp")
FLATPAK_NOTE = ("It runs in Flatpak's own sandbox with what it usually asks for taken away: no network, none of your "
                "folders, no sound, and no reaching your other programs (such as the one that fetches web addresses for "
                "apps): it gets this one file, read-only. What it would remember (recent files, where you were in the "
                "file, its settings) stays in that sandbox, in memory, and is gone when it closes. A screen reader "
                "can't read it. A link you click in it can still open in your usual browser, which would then load it.")


def _flatpak_viewer(host: Host, app: str, desktop_id: str, entry: dict[str, str], argv: list[str], file_in: str,
                    view_dir: str) -> Viewer:
    """A Flatpak app as the viewer: `flatpak run` with FLATPAK_RUN, the display, the app's own name and the copy's
    folder, and the launcher's branch, architecture and command; never a web browser."""
    i = argv.index("run") + 1 if "run" in argv else None
    pos = next((j for j in range(i, len(argv)) if not argv[j].startswith("-")), None) if i else None
    app_id = argv[pos] if pos is not None else None
    if (not app_id or not re.fullmatch(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+", app_id)
            or entry.get("X-Flatpak", app_id) != app_id):
        raise ViewError(f"{app}'s launcher couldn't be read.")
    # a browser from Flatpak: it hands what it opens to a copy of itself already running, with its network and
    # history (Flatpak Firefox fetched a page's pictures and wrote the file into places.sqlite, the 2026-10-17
    # review), and runs a page's scripts
    if browser_app(desktop_id, app_id, entry):
        raise ViewError(f"{app} is a web browser, which from Flatpak can hand the file to a copy of itself already "
                        "running, with its network and history, so View offline… doesn't use it. Choose a document "
                        "viewer for this kind of file as the default in your file manager (Open With → set as default), "
                        "or a browser from your distribution's packages, then try again.")
    flatpak = sandbox.program(host, "flatpak")
    if flatpak is None:
        raise ViewError(f"{app} is a Flatpak app, and Flatpak's program isn't in the system's folders.")
    disp = _session_kind(host)
    if disp == "none":
        raise ViewError("There is no display to show it on.")
    own = [o for o in argv[i:pos] if o.startswith(FLATPAK_KEPT)]
    display = ["--socket=wayland"] if disp == "wayland" else ["--socket=x11", "--share=ipc"]
    out = [flatpak, "run", *FLATPAK_RUN, f"--own-name={app_id}", *display, f"--filesystem={view_dir}:ro", *own, app_id]
    placed = False
    for a in argv[pos + 1:]:
        if a in FIELD_FILE:
            if not placed:
                out.append(file_in)
                placed = True
        elif a not in FIELD_DROP and a not in FLATPAK_FORWARDING:
            out.append(a)
    if not placed:
        out.append(file_in)
    return Viewer(app, desktop_id, _in_memory(host, out, app_id), flatpak=app_id, notes=[FLATPAK_NOTE])


def _session_kind(host: Host) -> str:
    if host.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    return "x11" if host.environ.get("DISPLAY") else "none"


def browser_app(desktop_id: str, app_id: str, entry: dict[str, str]) -> bool:
    """Whether the app is a web browser: one browsers.yaml lists by its menu entry, or whose entry says so."""
    from .. import browsers
    try:
        data = browsers.load()
    except Exception:  # noqa: BLE001 - the data file is the app's own: without it, the entry alone decides
        data = None
    if data is not None and (data.by_desktop(desktop_id) or data.by_desktop(f"{app_id}.desktop")):
        return True
    cats = entry.get("Categories", "").split(";")
    return "WebBrowser" in cats or "x-scheme-handler/https" in entry.get("MimeType", "").split(";")


def _in_memory(host: Host, argv: list[str], app_id: str | None) -> list[str]:
    """`flatpak run …` with the app's own command run through `env` and FLATPAK_MEMORY (above). Refuses (ViewError)
    when the app's command can't be told: it isn't started where it might remember the file."""
    i = argv.index("run") + 1
    pos = next((j for j in range(i, len(argv)) if not argv[j].startswith("-")), None)
    if pos is None:
        raise ViewError("Its Flatpak launcher names no app.")
    opts = argv[i:pos]
    command = next((o.split("=", 1)[1] for o in opts if o.startswith("--command=")), None)
    if command is None and app_id and re.fullmatch(r"[\w.-]+", app_id):
        r = host.run("flatpak", "info", "--show-metadata", app_id)
        m = re.search(r"^\[Application\][^\[]*?^command=([^\n]+)$", r.stdout or "", re.M | re.S) if r.ok else None
        command = m.group(1).strip() if m else None
    if not command or not re.fullmatch(r"[\w./+-]+", command):
        raise ViewError("Which program its Flatpak runs can't be told, so it isn't started (it might remember the file "
                        "where it shouldn't). Choose a viewer from your distribution's packages as the default, then try "
                        "again.")
    opts = [o for o in opts if not o.startswith("--command=")] + ["--command=env"]
    return argv[:i] + opts + [argv[pos], *FLATPAK_MEMORY, command] + argv[pos + 1:]


def flatpak_open(host: Host, app_id: str) -> list[int] | None:
    """The processes (`flatpak ps`) of the Flatpak app `app_id` running now, or None when that couldn't be asked."""
    r = host.run("flatpak", "ps", "--columns=pid,application")
    if not r.ok:
        return None
    out = []
    for line in (r.stdout or "").splitlines():
        f = line.split()
        if len(f) >= 2 and f[1] == app_id and f[0].isdigit():
            out.append(int(f[0]))
    return out


def _inodes(folder: Path) -> set[tuple[int, int]]:
    out = set()
    try:
        for e in os.scandir(folder):
            st = e.stat(follow_symlinks=False)
            out.add((st.st_dev, st.st_ino))
    except OSError:
        pass
    return out


def _held(host: Host) -> set[tuple[int, int]]:
    """(device, inode) of every file this user's programs hold open or mapped: a viewer in its sandbox sees
    its copy at another path, so the file is matched by its inode."""
    from ..checks._util import children
    out = set()
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit():
            continue
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue
        except OSError:
            continue
        for link in children(p / "fd"):
            try:
                st = os.stat(link)
                out.add((st.st_dev, st.st_ino))
            except OSError:
                continue
        try:                                            # mapped, its descriptor closed: still in use
            for ln in (p / "maps").read_text(errors="replace").splitlines():
                f = ln.split(None, 5)
                if len(f) == 6 and f[4] != "0":
                    major, minor = (int(x, 16) for x in f[3].split(":"))
                    out.add((os.makedev(major, minor), int(f[4])))
        except (OSError, ValueError):
            pass
    return out


VIEW_PREFIX = ".view-"
GRACE = 60.0                        # seconds a view's folder is kept before its viewer can be known to have opened it
_VIEWS: dict[str, int] = {}         # this copy's views: folder name -> the process of the viewer it started for it


def _keep(base: Path, name: str, held: set[tuple[int, int]], running: dict[int, str], now: float) -> bool:
    """Whether an earlier view's folder stays: its viewer still runs (it may have read the file and closed it, and
    read it again later), a program holds its copy open or mapped, or it is too new to tell (a viewer starting, or
    another copy of the app's view being set up: two views a second apart removed the first's copy before its viewer
    had opened it, the 2026-10-17 review)."""
    pid = _VIEWS.get(name)
    if pid is not None and pid in running:
        return True
    if _inodes(base / name) & held:
        return True
    if pid is not None:
        return False                                    # this copy's, and its viewer has ended
    try:
        return now - os.stat(base / name, follow_symlinks=False).st_mtime < GRACE
    except OSError:
        return False


def _staging(host: Host) -> tuple[Path, int]:
    """A new folder of the app's own at the RAM disk's top for this view's copy (the previous views' removed
    first, unless _keep), opened without following links: (its path, its fd)."""
    base = ramdisk.folder(host, ramdisk.BROWSER)
    bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held, running, now = _held(host), launched(), time.time()
        for old in os.listdir(bfd):
            if old.startswith(VIEW_PREFIX) and not _keep(base, old, held, running, now):
                ramdisk.wipe(base / old)
                shutil.rmtree(base / old, ignore_errors=True)
                _VIEWS.pop(old, None)
        name = f"{VIEW_PREFIX}{os.urandom(6).hex()}"
        os.mkdir(name, 0o700, dir_fd=bfd)
        return base / name, os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=bfd)
    finally:
        os.close(bfd)


def _source(host: Host, folder: str, name: str) -> tuple[int, sniff.Inspection]:
    """The finished download `name`, opened without following links and checked as Save… checks it."""
    try:
        fd = transfer.open_finished(host, folder, name)
    except transfer.TransferError as e:
        raise ViewError(str(e)) from None
    return fd, sniff.inspect(fd, name, os.fstat(fd).st_size)


def plan(host: Host, folder: str, name: str) -> Viewer:
    """Which viewer would open the download, and how (nothing started, nothing copied). The copy's folder gets its
    random name when it is made: the command shows where it will be, with <random> in its place."""
    fd, ins = _source(host, folder, name)
    os.close(fd)
    stage = ramdisk.folder(host, ramdisk.BROWSER) / f"{VIEW_PREFIX}<random>"
    return viewer_for(host, name, ins, transfer.safe_name(name), str(stage))


def own_folder(private: Path) -> Path:
    """The viewer's files (its X authority file, /etc files, log, Wayland socket): a folder of their own in the
    browser's private folder, never the browser's, which its sandbox sees and which a view would rewrite."""
    own = private / "view"
    try:
        os.mkdir(own, 0o700)
    except FileExistsError:
        pass
    if own.is_symlink() or not own.is_dir():
        raise ViewError("The viewer's folder in ~/TempBrowser isn't a plain folder.")
    return own


def _socket(host: Host, path: str) -> str | None:
    """`path` (as the system sees it) when a socket is there, else None."""
    real = str(host.sys_path(path))
    try:
        return real if stat.S_ISSOCK(os.stat(real).st_mode) else None
    except OSError:
        return None


def marked_socket(host: Host, disp: sandbox.Display, own: Path) -> int | None:
    """On Wayland, a socket the compositor marks as a sandbox's (as the browser's: tools/wayland.py), put in
    the display's place; returns the descriptor bubblewrap holds to keep it open (--sync-fd), or None where
    the compositor hasn't the protocol or setting it up failed (the compositor's own socket is used then)."""
    if disp.kind != "wayland":
        return None
    compositor = _socket(host, disp.binds[0][0])
    if compositor is None:
        return None
    try:
        for old in own.glob("wayland-*"):           # earlier views': their sandboxes have it mounted already
            old.unlink(missing_ok=True)
        path = own / f"wayland-{os.urandom(4).hex()}"
        sync = wayland.sandbox_socket(compositor, path, "org.daprivacyscanner.viewer")
    except (OSError, wayland.WaylandError):
        return None
    if sync is not None:
        disp.binds[0] = (str(path), disp.binds[0][1])
    return sync


def argv(host: Host, v: Viewer, copy: Path, name_in: str, own: Path, disp: sandbox.Display | None = None,
         sync: int | None = None) -> list[str]:
    """The whole command for a native viewer: bubblewrap with no network around it."""
    disp = disp or sandbox.display(host, own, landlock=False)
    if disp.kind == "none" or disp.network:
        raise ViewError(disp.note or "There is no display to show it on.")
    etc = sandbox.identity_files(own / "etc", None)
    a = [sandbox._need(host, sandbox.BWRAP), *sandbox.namespaces(False), *sandbox.system(host),
         *sandbox.identity(host, etc, own_dns=False)]
    if kept(host):
        a.append("--die-with-parent")                   # its parent is the keeper (KEEPER), not the app
    if sync is not None:
        a += ["--sync-fd", str(sync)]
    if v.opt:
        a += ["--ro-bind", "/opt", "/opt"]
    a += ["--perms", "0700", "--dir", sandbox.RUNTIME_IN, "--ro-bind", str(copy), f"{sandbox.HOME_IN}/{name_in}"]
    for src, dst in disp.binds:
        a += ["--ro-bind", src, dst]
    env = {"HOME": sandbox.HOME_IN, "USER": sandbox.USER_IN, "LOGNAME": sandbox.USER_IN,
           "PATH": "/usr/local/bin:/usr/bin:/bin", "XDG_RUNTIME_DIR": sandbox.RUNTIME_IN, **sandbox.software_gl(host),
           **{k: host.environ[k] for k in sandbox.PASSED_ENV if host.environ.get(k)}, **disp.env}
    for k, val in env.items():
        a += ["--setenv", k, val]
    return a + ["--chdir", sandbox.HOME_IN, "--", *v.argv]


_LAUNCHED: dict[int, str] = {}           # viewers View offline… started: pid -> the viewer's name (for "Close X first")

# The viewer's sandbox, bubblewrap's or Flatpak's, runs under this, the computer's python3, which waits for it:
# with --die-with-parent the whole sandbox ends when its parent does, and its parent is this keeper, not the app,
# so quitting the app leaves an open viewer open, while ending any part of it ends all of it. Without, a SIGTERM to
# bubblewrap left its init (the sandbox's PID 1, which ignores one from outside) and the viewer running, out of the
# app's sight under another process than the one it had started (the 2026-10-17 review).
KEEPER = """\
import os, sys
pid = os.fork()
if not pid:
    os.execv(sys.argv[1], sys.argv[1:])
_, st = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(st)
sys.exit(code if code >= 0 else 128 - code)
"""


def kept(host: Host) -> bool:
    """Whether the viewer runs under KEEPER (and so with --die-with-parent): where the computer has python3."""
    return host.sys_path(sandbox.PYTHON).exists()


def _keeper(host: Host, cmd: list[str]) -> list[str]:
    return [sandbox.PYTHON, "-I", "-c", KEEPER, *cmd] if kept(host) else cmd


def launched() -> dict[int, str]:
    """The viewers started here that still run (their process, the top of their sandbox), by pid."""
    for pid in list(_LAUNCHED):
        try:
            os.kill(pid, 0)
            with open(f"/proc/{pid}/stat") as f:
                if f.read().rsplit(")", 1)[-1].split()[0] == "Z":
                    raise ProcessLookupError
        except (ProcessLookupError, PermissionError, OSError):
            _LAUNCHED.pop(pid, None)
    return dict(_LAUNCHED)


def view(host: Host, folder: str, name: str, private: Path, spawn: Callable = subprocess.Popen,
         check: str | None = None) -> dict:
    """Copies the download where no sandbox reaches, judges the copy again (only what the page showed,
    `check`, is opened) and opens it in the desktop's viewer with no network. Returns the viewer's
    description, with the command that ran."""
    if not sandbox.program(host, sandbox.BWRAP):
        raise ViewError("Opening it without the network needs bubblewrap (the bubblewrap package).")
    stage, sfd = _staging(host)
    try:
        try:
            snap = transfer.snapshot(host, folder, name, check, stage=(stage, sfd), mode=0o400)
        except transfer.TransferError:
            shutil.rmtree(stage, ignore_errors=True)
            raise
    finally:
        os.close(sfd)
    ins, name_in, copy = snap.inspection, snap.name, snap.path
    flat, sync = None, None
    own = own_folder(private)
    try:
        v = viewer_for(host, name, ins, name_in, str(stage))
        if v.flatpak:
            # already open, it is handed the file over the session bus and opens it itself, with its network and
            # what it remembers (Text Editor 51 did, tested on Mint 22.3; Flatpak Firefox fetched a page's pictures)
            open_now = flatpak_open(host, v.flatpak)
            if open_now is None:
                raise ViewError(f"Whether {v.app} is already open couldn't be told (flatpak ps didn't answer), so it "
                                "isn't started: if it were, it would be given the file with its network.")
            if open_now and set(open_now) & set(launched()):
                raise ViewError(f"{v.app} is already open from an earlier View offline…: it would be given this file, "
                                f"which it can't reach from its own sandbox. Close it first, then try again.")
            if open_now:
                raise ViewError(f"{v.app} is already open: it would be given this file and open it itself, with its "
                                f"network and outside this sandbox. Close {v.app} first, then try again.")
            cmd, flat = v.argv, True
        else:
            disp = sandbox.display(host, own, landlock=False)
            sync = marked_socket(host, disp, own)
            cmd = argv(host, v, copy, name_in, own, disp, sync)
    except ViewError:
        if sync is not None:
            os.close(sync)
        snap.remove()                                   # no viewer: the copy goes at once
        raise
    # what runs: bubblewrap's options from a descriptor (sandbox.sealed: the viewer can read its init's command line,
    # which would name the copy's path in the user's home) and none of the app's environment, under the keeper
    # (KEEPER); what the page shows is the same command with the options written out
    shown = sandbox.fresh_keyring(host, _keeper(host, cmd))      # no reaching the session's kernel keyring
    args_fd, env = None, host_env(host.environ)
    if not flat:
        cmd, args_fd = sandbox.sealed(cmd)
        env = dict(sandbox.SPAWN_ENV)
    cmd = sandbox.fresh_keyring(host, _keeper(host, cmd))
    log = sandbox.log_file("view-log")                  # a memory file: no path for the viewer to see
    fds = tuple(fd for fd in (sync, args_fd) if fd is not None)
    try:
        proc = spawn(cmd, cwd="/", env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=log, start_new_session=True, **({"pass_fds": fds} if fds else {}))
    except BaseException:
        os.close(log)
        snap.remove()
        raise
    finally:
        if args_fd is not None:
            os.close(args_fd)
        if sync is not None:
            os.close(sync)                              # bubblewrap holds it now, for as long as the viewer runs
    if isinstance(getattr(proc, "pid", None), int):
        _LAUNCHED[proc.pid] = v.app
        _VIEWS[stage.name] = proc.pid
    if hasattr(proc, "poll"):
        deadline = time.monotonic() + WATCH
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        rc = proc.poll()
        if rc not in (None, 0):
            lines = [ln for ln in sandbox.read_log(log).splitlines() if ln.strip()]
            os.close(log)
            raise ViewError(f"{v.app} couldn't open it: " + ("; ".join(lines[-3:])[:400] or f"exit status {rc}"))
        if rc == 0:                                     # ended at once, showing nothing (in its sandbox it can't
            os.close(log)                               # go on in the background: its sandbox ends with it)
            if flat:
                raise ViewError(f"{v.app} closed at once. If it was opened meanwhile, it may have been given the file "
                                f"there, with its network: close {v.app}, then try again.")
            # xreader with one already open from an earlier view (tested on Mint 22.3)
            raise ViewError(f"{v.app} closed at once without showing it. If it is already open from an earlier View "
                            f"offline…, close that one first, then try again.")
    os.close(log)
    return {**v.to_dict(), "flatpak": v.flatpak if flat else None, "whole": shlex.join(shown)}
