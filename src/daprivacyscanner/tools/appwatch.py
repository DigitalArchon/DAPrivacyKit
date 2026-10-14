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
    "work outside what is watched: it shows under other programs, when it wrote something.",
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
    return [SYSTEMD_RUN, "--user", "--scope", "--collect", "--quiet", f"--unit={UNIT.format(token=token)}", "--",
            *(["env", *(f"{k}={v}" for k, v in app.env.items())] if app.env else []), *app.argv]


def _program(host: Host, app: menu.App) -> str | None:
    """The app's program by its real path (its command's first word, found as the session would find it)."""
    import shutil
    first = app.argv[0]
    path = first if first.startswith("/") else shutil.which(first, path=host.environ.get("PATH") or os.defpath)
    return os.path.realpath(path) if path else None


def running(host: Host, app: menu.App) -> bool:
    """Whether the app runs already: started again it would hand over to that copy, outside what is watched."""
    if app.flatpak:
        r = host.run("flatpak", "ps", "--columns=application")
        return r.ok and app.flatpak in (r.stdout or "").split()
    prog = _program(host, app)
    if not prog or os.path.basename(prog) in ("env", "sh", "bash", "python3", "flatpak", "snap", "gtk-launch"):
        return False
    try:
        pids = [p for p in os.listdir(host.sys_path("/proc")) if p.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            if host.sys_path(f"/proc/{pid}").stat().st_uid == host.uid and \
                    os.readlink(host.sys_path(f"/proc/{pid}/exe")) == prog:
                return True
        except OSError:
            continue
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
    out["system"] = sorted(({"folder": k, "files": v} for k, v in (raw.get("system") or {}).items()),
                           key=lambda s: -s["files"])[:40]
    out["gone"] = sorted(({"folder": activity.tilde(k, w), "events": v} for k, v in (raw.get("gone") or {}).items()),
                         key=lambda s: -s["events"])[:40]
    out["folded"] = sum((raw.get("folded") or {}).values())
    out.update({k: raw.get(k, 0) for k in ("events", "foreign", "overflow", "unresolved", "others_left")})
    out.update({"app": app.name, "watched": started.get("watched") or [], "not_watched": started.get("skipped") or [],
                "limits": LIMITS})
    return out

