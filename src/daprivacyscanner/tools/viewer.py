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
- A Flatpak app runs in Flatpak's own sandbox with its network taken away (`flatpak run --unshare=network`)
  and every folder it is given (`flatpak info --show-permissions`: home, host, xdg-download…, each taken away
  with --nofilesystem; taking away home alone left ~/Downloads readable: tested), the file passed through
  the document portal; links clicked in it can still open in the default browser (a portal), which the page
  says.
- A Snap, or a program in the home folder, isn't started: the page says why and what to choose instead.
The copy is judged again once it is out of the browser's reach (transfer.snapshot), and opened only when it is
what the page showed (`check`): the browser could have changed its file after it was listed.
Nothing is kept: the copies are overwritten and removed with the RAM disk, and earlier views' copies that
no program holds open any more when the next one starts."""

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


def viewer_for(host: Host, name: str, ins: sniff.Inspection, file_in: str) -> Viewer:
    """The desktop's viewer for the file `name`, with `file_in` (the path it will be opened at) in
    its command. Raises ViewError when there is none this can start."""
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
    flatpak = entry.get("X-Flatpak") or (argv[1] if len(argv) > 2 and os.path.basename(argv[0]) == "flatpak"
                                         and argv[1] == "run" else None)
    if os.path.basename(argv[0]) == "flatpak":
        if "run" not in argv or any(a.startswith("--share=network") for a in argv):
            raise ViewError(f"{app}'s launcher couldn't be used without its network.")
        i = argv.index("run") + 1
        argv = argv[:i] + ["--unshare=network", *_no_folders(host, flatpak)] + argv[i:]
        argv = [file_in if a in FIELD_FILE else a for a in argv if a not in FIELD_DROP]
        argv = _in_memory(host, argv, flatpak)
        return Viewer(app, desktop_id, argv, flatpak=flatpak or "app",
                      notes=["It runs in Flatpak's own sandbox with its network and every folder of yours it is "
                             "usually given taken away: it gets this one file. What it would remember (recent files, "
                             "where you were in the file) is kept in memory and forgotten when it closes, and so are "
                             "its own settings for this time. A link you click in it can still open in your usual "
                             "browser, which would then load it."])
    if argv[0].startswith("/snap/") or entry.get("X-SnapInstanceName") or os.path.basename(argv[0]) == "snap":
        raise ViewError(f"{app} is a Snap, which can't be started inside another sandbox. Choose a viewer from your "
                        "distribution's packages as the default for this kind of file, then try again.")
    prog = _program(host, argv[0])
    if prog is None:
        raise ViewError(f"{app}'s program ({argv[0]}) isn't in the system's folders, so it isn't started in the "
                        "sandbox. Choose a viewer from your distribution's packages as the default, then try again.")
    out, placed = [prog], False
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


# A Flatpak app keeps its data in ~/.var/app/<id>, on the disk, whatever folders it is given: Evince 48 (Flathub)
# wrote the file's name into its recently-used.xbel and its GVFS metadata there (tested). flatpak run's --env can't
# move those folders (Flatpak sets them after it), so the command becomes `env`, which sets them inside, into the
# sandbox's own /tmp (a tmpfs of its own, in memory; its /var/tmp is the disk), then runs the app's own command.
FLATPAK_MEMORY = ("XDG_DATA_HOME=/tmp/.view/data", "XDG_CACHE_HOME=/tmp/.view/cache", "XDG_CONFIG_HOME=/tmp/.view/config",
                  "XDG_STATE_HOME=/tmp/.view/state", "TMPDIR=/tmp")


def _in_memory(host: Host, argv: list[str], app_id: str | None) -> list[str]:
    """`flatpak run …` with the app's own command run through `env` and FLATPAK_MEMORY (above). Refuses (ViewError)
    when the app's command can't be told: it isn't started where it would remember the file on the disk."""
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
        raise ViewError("Which program its Flatpak runs can't be told, so it isn't started (it would remember the file "
                        "on the disk). Choose a viewer from your distribution's packages as the default, then try again.")
    opts = [o for o in opts if not o.startswith("--command=")] + ["--command=env"]
    return argv[:i] + opts + [argv[pos], *FLATPAK_MEMORY, command] + argv[pos + 1:]


def _no_folders(host: Host, app_id: str | None) -> list[str]:
    """`--nofilesystem` for every folder the Flatpak app `app_id` is given (and home and host, whatever it
    says): a document made to exploit the viewer can't then read or plant files of the user's."""
    gone = ["host", "home"]
    if app_id and re.fullmatch(r"[\w.-]+", app_id):
        r = host.run("flatpak", "info", "--show-permissions", app_id)
        m = re.search(r"^filesystems=(.*)$", r.stdout or "", re.M) if r.ok else None
        for entry in (m.group(1).split(";") if m else []):
            entry = re.sub(r":(ro|rw|create)$", "", entry.strip())
            if entry and not entry.startswith("!") and entry not in gone and re.fullmatch(r"[\w~/.@+-]+", entry):
                gone.append(entry)
    return [f"--nofilesystem={e}" for e in gone]


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


def _staging(host: Host) -> tuple[Path, int]:
    """A new folder of the app's own at the RAM disk's top for this view's copy (the previous views'
    removed first), opened without following links: (its path, its fd)."""
    base = ramdisk.folder(host, ramdisk.BROWSER)
    bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held = _held(host)
        for old in os.listdir(bfd):
            if old.startswith(".view-") and not _inodes(base / old) & held:
                ramdisk.wipe(base / old)
                shutil.rmtree(base / old, ignore_errors=True)
        name = f".view-{os.urandom(6).hex()}"
        os.mkdir(name, 0o700, dir_fd=bfd)
        return base / name, os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=bfd)
    finally:
        os.close(bfd)


def _source(host: Host, folder: str, name: str) -> tuple[int, sniff.Inspection]:
    """The finished download `name`, opened without following links and checked as Save… checks it."""
    if not isinstance(name, str) or not name or "/" in name or name in (".", "..") or "\0" in name:
        raise ViewError("That isn't one of the browser's downloads.")
    listed = {e.name: e for e in transfer.downloads(host, folder)[0]}
    if name not in listed:
        raise ViewError(f"{name} isn't a finished download in the browser's folder.")
    dfd = transfer._open_dir(host, transfer.downloads_dir(host, folder))
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        raise ViewError(f"{name} can't be read (it may have just changed).") from None
    finally:
        os.close(dfd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_dev != transfer._ramdisk_dev(host):
        os.close(fd)
        raise ViewError(f"{name} isn't a plain file in ~/TempBrowser.")
    return fd, sniff.inspect(fd, name, st.st_size)


def plan(host: Host, folder: str, name: str) -> Viewer:
    """Which viewer would open the download, and how (nothing started, nothing copied)."""
    fd, ins = _source(host, folder, name)
    os.close(fd)
    return viewer_for(host, name, ins, f"{sandbox.HOME_IN}/{transfer.safe_name(name)}")


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
        v = viewer_for(host, name, ins, f"{sandbox.HOME_IN}/{name_in}")
        if v.flatpak:
            v = viewer_for(host, name, ins, str(copy))
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
    # which would name the copy's path in the user's home) and none of the app's environment; what the page shows is
    # the same command with the options written out
    shown = sandbox.fresh_keyring(host, cmd)            # no reaching the session's kernel keyring
    args_fd, env = None, host_env(host.environ)
    if not flat:
        cmd, args_fd = sandbox.sealed(cmd)
        env = dict(sandbox.SPAWN_ENV)
    cmd = sandbox.fresh_keyring(host, cmd)
    log = sandbox.log_file("view-log")                  # a memory file: no path for the viewer to see
    fds = tuple(fd for fd in (sync, args_fd) if fd is not None)
    try:
        proc = spawn(cmd, cwd="/", env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=log, start_new_session=True, **({"pass_fds": fds} if fds else {}))
    except BaseException:
        os.close(log)
        raise
    finally:
        if args_fd is not None:
            os.close(args_fd)
        if sync is not None:
            os.close(sync)                              # bubblewrap holds it now, for as long as the viewer runs
    if isinstance(getattr(proc, "pid", None), int):
        _LAUNCHED[proc.pid] = v.app
    if hasattr(proc, "poll"):
        deadline = time.monotonic() + WATCH
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        rc = proc.poll()
        if rc not in (None, 0):
            lines = [ln for ln in sandbox.read_log(log).splitlines() if ln.strip()]
            os.close(log)
            raise ViewError(f"{v.app} couldn't open it: " + ("; ".join(lines[-3:])[:400] or f"exit status {rc}"))
    os.close(log)
    return {**v.to_dict(), "flatpak": v.flatpak if flat else None, "whole": shlex.join(shown)}
