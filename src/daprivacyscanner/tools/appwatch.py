"""What does this app keep? (docs/TECHNICAL.md, Tools): the user picks an app from the menu, the tool starts it
and watches it for as long as the user leaves it on, on the real machine with their real profile, then says where
it read and wrote: its own folders with counts, the files or databases it writes to regularly (named: the user
needs to see what they are), which of the user's own folders it opened files in (counted, never named), which
sensitive places it opened (SSH keys, a browser's profile), and which files written meanwhile, by it or by
another program of the user's, hold the names of the files it opened (the thumbnail, the recent-files list).

How: the app is started in a systemd scope of its own (`systemd-run --user --scope`), so every process it starts
is in one cgroup; Flatpak and Snap move an app into a scope of theirs, matched by its name. The helper watches the
filesystems with fanotify (helper.py, watch_begin) and keeps what processes of that cgroup do, and what the user's
other programs write. That needs administrator access for the whole session: the page says so before it starts
(WARNING), and the access is dropped when the watch ends unless something else was using it.

What it can't see, said on the page (LIMITS): what other accounts and system services record (the journal, the
print spooler); what is inside a file; a process that ended before it could be looked up (counted per folder);
an app that was already running, or that hands its work to a service outside its scope (counted under "other
programs"). Never always on: one app, one session, started and ended by the user.

Nothing is kept: the result is in the app's memory until the tool is dismissed or the app quits, never in
History, a report or an export."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Callable

from ..host import Host
from ..hostenv import host_env
from . import activity, menu

SYSTEMD_RUN = "systemd-run"
UNIT = "daprivacyscanner-watch-{token}.scope"
DESCRIPTION = "An app watched by DA Privacy Kit"
QUIET_AFTER = 20.0                      # seconds running with no file of its own or the user's opened: handed over?
OTHERS_SHOWN = 40
WARNING = ("This needs administrator access from the moment you start until you end it: watching which files a "
           "program opens can only be done as root. Use the app as you normally do, with everything you usually "
           "do in it, then end as soon as is practical, so the access is given up again.")
LIMITS = [
    "It sees this app's own processes. What other accounts and system services record about it (the system's "
    "log, the print spooler) isn't shown.",
    "It says where files were read and written, not what is in them. A file that holds the names of the files "
    "you opened is found only when the names are stored as plain text; compressed or encrypted stores can't be "
    "read.",
    "A helper program that ran for an instant may have ended before it could be identified: what it touched "
    "under your home folder is counted, per folder.",
    "An app that was already running, or that passes its work to a background service of its own, does that "
    "work outside what is watched: it shows under what your other programs wrote, when it wrote something.",
]


class WatchError(ValueError):
    pass


def available(host: Host) -> str | None:
    """Why an app can't be watched here, or None."""
    if not host.runner.which(SYSTEMD_RUN):
        return "It needs systemd-run, which isn't installed."
    runtime = host.environ.get("XDG_RUNTIME_DIR", f"/run/user/{host.uid}")
    if not host.sys_path(f"{runtime}/systemd").exists():
        return "It needs systemd's user session (to start the app in a group of its own), which isn't running here."
    return None


def units(app: menu.App, token: str) -> list[str]:
    """The cgroup units the app's processes are in: the scope it is started in, and the one Flatpak or Snap
    moves it to (named after the app, with a part of their own at the end)."""
    out = [UNIT.format(token=token)]
    if app.flatpak and re.fullmatch(r"[A-Za-z0-9_.-]+", app.flatpak):
        out.append(f"app-flatpak-{app.flatpak}-*.scope")
    if app.snap and re.fullmatch(r"[A-Za-z0-9_-]+", app.snap):
        out.append(f"snap.{app.snap}.*.scope")
    return out


def command(app: menu.App, token: str) -> list[str]:
    # the description is what the journal says the scope is: without one, systemd names the command ("Started
    # daprivacyscanner-watch-….scope - /usr/bin/xed.", tested on Mint), which says which app was watched, when
    return [SYSTEMD_RUN, "--user", "--scope", "--collect", "--quiet", f"--unit={UNIT.format(token=token)}",
            f"--description={DESCRIPTION}", "--",
            *(["env", *(f"{k}={v}" for k, v in app.env.items())] if app.env else []), *app.argv]


# a command's first word that says nothing of the app: it runs something else (the app's script, another program)
INTERPRETERS = ("sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node", "gjs", "java")
LAUNCHERS = ("env", "flatpak", "snap", "gtk-launch", "xdg-open", "exo-open", "kde-open", "kioclient", "kioclient5")
# folders shared by many programs: a script there, or one it names, doesn't tell the app's processes apart
SHARED = ("/bin", "/sbin", "/lib", "/lib64", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec",
          "/usr/share", "/usr/games", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/opt",
          "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/snap", "/snap/bin")
SCRIPT_READ = 65536


def _real(host: Host, path: str) -> str:
    """A path of the host's with its links resolved (a test's own root taken off again)."""
    real = os.path.realpath(host.sys_path(path))
    root = str(host.root).rstrip("/")
    return real[len(root):] if root and real.startswith(root + "/") else real


def _which(host: Host, word: str) -> str | None:
    """A command's word as the session would find it: the program's path, or None."""
    if "/" in word:
        return word if word.startswith("/") and host.sys_path(word).is_file() else None
    for folder in (host.environ.get("PATH") or os.defpath).split(":"):
        if folder.startswith("/") and os.access(host.sys_path(f"{folder.rstrip('/')}/{word}"), os.X_OK):
            return f"{folder.rstrip('/')}/{word}"
    return None


def _signs(host: Host, app: menu.App) -> tuple[set[str], set[str], set[str]]:
    """How a running copy of the app is told by its processes: (programs one runs or runs as its script, folders
    one runs from or runs a script from, folders one only runs from). A menu entry's command is often a script that
    starts the real program (LibreOffice's soffice starts oosplash and soffice.bin beside it, Firefox's and
    Thunderbird's start the program they name, VS Code's the one in the folder above its own, Mint's tools run a
    Python script they name), whose processes never run the script itself."""
    first = _which(host, app.argv[0])
    if not first:
        return set(), set(), set()
    prog = _real(host, first)
    if os.path.basename(prog).rstrip("0123456789.") in INTERPRETERS:   # python3 /usr/share/foo/foo.py
        script = next((a for a in app.argv[1:] if not a.startswith("-")), None)
        found = _which(host, script) if script and "-m" not in app.argv[1:] else None
        if not found:
            return set(), set(), set()
        prog = _real(host, found)
    if os.path.basename(prog) in LAUNCHERS:
        return set(), set(), set()
    programs, folders, dirs = {prog}, set(), set()
    try:
        with open(host.sys_path(prog), "rb") as f:
            head = f.read(SCRIPT_READ)
    except OSError:
        head = b""
    if head.startswith(b"#!"):
        here = os.path.dirname(prog)
        folders |= {here, os.path.dirname(here)} if os.path.basename(here) == "bin" else {here}
        name = os.path.basename(prog).split(".")[0]
        for named in re.findall(rb"(?<![\w$.-])/[\w.+-]+(?:/[\w.+-]+)+", head[2:]):
            path = named.decode("utf-8", "replace")
            if os.path.basename(path).rstrip("0123456789.") in INTERPRETERS + LAUNCHERS:
                continue
            target = host.sys_path(path)
            if target.is_dir():
                dirs.add(_real(host, path))
            elif target.is_file() and os.access(target, os.X_OK):
                real = _real(host, path)
                # a tool it uses (/usr/bin/zenity) isn't the app; foo's foo-bin or foo.real beside it is
                if os.path.dirname(real) not in SHARED or os.path.basename(real).startswith(name):
                    programs.add(real)
                    folders.add(os.path.dirname(real))
    keep = lambda f: f not in SHARED and f.count("/") >= 2 and not f.startswith("/home/")   # noqa: E731
    return programs, {f for f in folders if keep(f)}, {d for d in dirs if keep(d)}


def _inside(path: str, folders: set[str]) -> bool:
    return any(path.startswith(f.rstrip("/") + "/") for f in folders)


def _own_pids(host: Host) -> list[str]:
    try:
        pids = [p for p in os.listdir(host.sys_path("/proc")) if p.isdigit()]
    except OSError:
        return []
    if str(host.root) != "/":                    # a test's /proc: its files are the test's own
        return pids
    out = []
    for pid in pids:
        try:
            if host.sys_path(f"/proc/{pid}").stat().st_uid == host.uid:
                out.append(pid)
        except OSError:
            continue
    return out


def running(host: Host, app: menu.App) -> bool:
    """Whether the app runs already: started again it would hand over to that copy, outside what is watched.
    Flatpak's own list says for a Flatpak app, the cgroup Snap starts it in for a Snap (snap.<name>.…scope); for
    anything else, a process of the user's that runs the app's program, or what its script starts (`_signs`)."""
    if app.flatpak:
        r = host.run("flatpak", "ps", "--columns=application")
        return r.ok and app.flatpak in (r.stdout or "").split()
    if app.snap:
        mark = f"/snap.{app.snap}."
        for pid in _own_pids(host):
            try:
                with open(host.sys_path(f"/proc/{pid}/cgroup"), "rb") as f:
                    if mark.encode() in f.read(8192):
                        return True
            except OSError:
                continue
        return False
    programs, folders, dirs = _signs(host, app)
    if not programs:
        return False
    for pid in _own_pids(host):
        try:
            exe = os.readlink(host.sys_path(f"/proc/{pid}/exe")).removesuffix(" (deleted)")
        except OSError:
            continue
        if exe in programs or _inside(exe, folders | dirs):
            return True
        try:
            with open(host.sys_path(f"/proc/{pid}/cmdline"), "rb") as f:
                args = f.read(4096).split(b"\0")[:3]
        except OSError:
            continue
        for arg in args:                         # a script run by its interpreter: python3 /usr/lib/foo/foo.py
            text = arg.decode("utf-8", "surrogateescape")
            if text.startswith("/") and ((real := _real(host, text)) in programs or _inside(real, folders)):
                return True
    return False


def start(host: Host, app: menu.App, token: str, spawn: Callable = subprocess.Popen):
    """Starts the app in its scope (the watch is already on). Returns the process (systemd-run becomes the app)."""
    if app.terminal:
        raise WatchError(f"{app.name} runs in a terminal, which this can't start for it.")
    return spawn(command(app, token), cwd=str(host.home), env=host_env(host.environ), stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def alive(host: Host, wanted: list[str]) -> int:
    """How many processes are left in the app's units (0: it has ended)."""
    import fnmatch
    base = host.sys_path(f"/sys/fs/cgroup/user.slice/user-{host.uid}.slice")
    count = 0
    try:
        for folder, dirs, files in os.walk(base):
            if any(fnmatch.fnmatchcase(os.path.basename(folder), u) for u in wanted) and "cgroup.procs" in files:
                with open(os.path.join(folder, "cgroup.procs")) as f:
                    count += len(f.read().split())
                for sub, _d, subfiles in os.walk(folder):
                    if sub != folder and "cgroup.procs" in subfiles:
                        with open(os.path.join(sub, "cgroup.procs")) as f:
                            count += len(f.read().split())
                dirs[:] = []
    except OSError:
        pass
    return count


def report(host: Host, app: menu.App, raw: dict, started: dict) -> dict:
    """The watch's records (the helper's watch_end) as the page shows them."""
    from ..history import state_dir
    from ..paths import PathResolver
    w = activity.Where.of(host)
    records = raw.get("files") or []
    out = activity.summarise(records, w, raw.get("seconds") or 0)
    paths = PathResolver(host.home, host.environ)
    own = (os.path.realpath(state_dir(paths)), os.path.realpath(paths.config_home / "daprivacyscanner"))
    out["records"] = activity.find_records(records, w, skip=lambda p: p.startswith(own))
    out["others"] = sum(1 for r in records if r[5])
    # what the user's other programs wrote meanwhile, per program and folder: where the work of a background service
    # of the app's own, or of a copy that was already running, shows (counts only, as everything else)
    # (in the user's own folders and on other disks, and past the helper's limit, changes per folder: never one by one)
    others: dict[tuple[str, str], dict] = {}
    for r in records:
        if r[5]:
            o = others.setdefault((r[5], activity.place(r[0], w)[1]), {"files": 0, "changes": 0})
            o["files"] += 1
    for who, folder, n in raw.get("others_folded") or []:
        o = others.setdefault((who, activity.tilde(folder, w) if folder else ""), {"files": 0, "changes": 0})
        o["changes"] += n
    out["others_changes"] = sum(o["changes"] for o in others.values())
    out["others_places"] = sorted(({"who": k[0], "folder": k[1], **v} for k, v in others.items()),
                                  key=lambda o: (-o["files"] - o["changes"], o["who"], o["folder"]))[:OTHERS_SHOWN]
    out["system"] = sorted(({"folder": k, "files": v} for k, v in (raw.get("system") or {}).items()),
                           key=lambda s: -s["files"])[:40]
    out["gone"] = sorted(({"folder": activity.tilde(k, w), "events": v} for k, v in (raw.get("gone") or {}).items()),
                         key=lambda s: -s["events"])[:40]
    out["folded"] = sum((raw.get("folded") or {}).values())
    out.update({k: raw.get(k, 0) for k in ("events", "foreign", "overflow", "unresolved", "others_left")})
    out.update({"app": app.name, "watched": started.get("watched") or [], "not_watched": started.get("skipped") or [],
                "limits": LIMITS})
    return out

