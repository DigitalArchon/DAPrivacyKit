"""Tor Browser or Mullvad Browser in the RAM disk (docs/TECHNICAL.md, Tools): a browser that keeps nothing
between sessions, run from memory so that the browser itself leaves no trace on the disk either.

The app downloads the browser's archive and its signature into ~/TempBrowser (a user-started step that
names the hosts it contacts, through online.Net: rule 10), or takes an archive the user downloaded;
checks the signature with Verify a download against the Tor Browser Developers key bundled in
signing-keys.yaml (both browsers are signed by it), refusing anything that isn't verified; unpacks it
into ~/TempBrowser/<folder> (regular files and folders only, nothing outside that folder); and starts it
with its caches and settings pointed into the RAM disk too (XDG_CONFIG_HOME, XDG_CACHE_HOME,
XDG_DATA_HOME, XDG_STATE_HOME and TMPDIR: the browser's start script moves HOME into its own folder,
but GTK, fontconfig and Mesa follow those variables when the session sets them). Closing the RAM disk
(tools/ramdisk.py) overwrites and removes all of it; it is refused while the browser runs.

The RAM disk must be open with programs allowed (noexec off) for the browser to start from it.

It starts inside a sandbox (tools/sandbox.py: bubblewrap; Tor Browser with no network but tor's, Mullvad
Browser in pasta's network namespace where pasta is installed) unless bubblewrap can't run here or the
user turns it off (a screen reader or an input method can't reach a sandboxed browser); then it starts
as an ordinary program, and the page says it can reach your other files. A copy that has run in the
sandbox is never started without it: its profile could hold what a website left there. Files go in and
out through its "To upload" and Downloads folders (tools/transfer.py).

Beside each browser's folder, the app keeps a private folder (.<folder>-app, never shown to the
browser): the sandbox's /etc files, the X authority file, the start log, the bridges chosen for Tor
Browser and tor's sockets and status, and the mark that it has run in the sandbox. The session folder
(.<folder>-session: the XDG folders) is overwritten and made again at every start."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..host import Host
from ..hostenv import host_env
from . import owner, ramdisk, sandbox, transfer, wayland

PROJECT = "torbrowser"                  # signing-keys.yaml: the Tor Browser Developers key, which signs both
MAX_ARCHIVE = 600 * 1024 * 1024
MIN_MB = 1024                           # an archive (~140 MB) and its unpacked files (~350 MB), then a session
DOWNLOADS = ".downloads"                # in the RAM disk
START_WAIT = 3.0                        # seconds a start is watched for an error before it counts as started


@dataclass(frozen=True)
class Browser:
    id: str
    name: str
    index: str                          # download-<platform>.json: {"version", "binary", "sig"}
    hosts: tuple[str, ...]              # every host a download contacts
    folder: str                         # the archive's top folder
    start: str                          # the start script, inside it
    platforms: tuple[str, ...]
    about: str
    writable: tuple[str, ...]           # inside the folder: its profile and Downloads, all it may change
    hidden: tuple[str, ...] = ()        # inside the folder: kept from the browser (tor's data)
    tor: bool = False                   # its own tor, in a sandbox of its own
    version_file: str = ""              # inside the folder: {"version": …}, checked against the archive's name
    profile: str = ""                   # inside the folder: the profile the archive ships, where the level is set
    security: str = "standard"          # the security level it starts at (SECURITY_LEVELS)

    def archive_name(self, name: str) -> bool:
        return re.fullmatch(rf"{re.escape(self.folder)}-linux-(x86_64|i686)-[0-9][0-9a-z.]*\.tar\.xz", name) is not None


BROWSERS = {
    "tor": Browser("tor", "Tor Browser",
                   "https://aus1.torproject.org/torbrowser/update_3/release/download-{platform}.json",
                   ("aus1.torproject.org", "dist.torproject.org"), "tor-browser", "Browser/start-tor-browser",
                   ("linux-x86_64", "linux-i686"),
                   "Hides your address by default: it connects through the Tor network, so sites can't see your "
                   "address, and your network can't see which sites you visit. It doesn't hide who you are if you "
                   "sign in or say so. Some sites block Tor or ask for more captchas.",
                   ("Browser/TorBrowser/Data/Browser", f"Browser/{sandbox.DOWNLOADS}"),
                   ("Browser/TorBrowser/Data/Tor",), tor=True, version_file="Browser/tbb_version.json",
                   profile="Browser/TorBrowser/Data/Browser/profile.default", security="safest"),
    "mullvad": Browser("mullvad", "Mullvad Browser",
                       "https://cdn.mullvad.net/browser/update_responses/update_1/release/download-{platform}.json",
                       ("cdn.mullvad.net",), "mullvad-browser", "Browser/start-mullvad-browser", ("linux-x86_64",),
                       "Tor Browser's protections against tracking and fingerprinting, without the Tor network. On "
                       "its own it hides nothing of your address: every site sees it. Use it with a VPN you trust, "
                       "best Mullvad VPN: its extension's features need it, and its users then look alike.",
                       ("Data", f"Browser/{sandbox.DOWNLOADS}"), version_file="Browser/version.json"),
}


class Stopped(Exception):
    pass


class BrowserError(ValueError):
    pass


def platform_name() -> str | None:
    m = platform.machine()
    return {"x86_64": "linux-x86_64", "amd64": "linux-x86_64", "i686": "linux-i686", "i386": "linux-i686"}.get(m)


DISK = ramdisk.BROWSER                  # ~/TempBrowser: its own RAM disk, not the RAM disk tool's


def root(host: Host) -> Path:
    return ramdisk.folder(host, DISK)


def private_dir(host: Host, b: Browser) -> Path:
    return root(host) / f".{b.folder}-app"


def session_dir(host: Host, b: Browser) -> Path:
    return root(host) / f".{b.folder}-session"


def installed(host: Host, b: Browser) -> bool:
    try:
        return (root(host) / b.folder / b.start).is_file()
    except OSError:
        return False


def _read_small(path: Path, limit: int = 65536) -> str:
    """At most `limit` bytes of a small file of the app's own, opened without following links; "" when it
    can't be read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return ""
    try:
        return os.read(fd, limit).decode("utf-8", "replace")
    except OSError:
        return ""
    finally:
        os.close(fd)


def _ramdisk_dev(host: Host) -> int | None:
    try:
        return os.stat(root(host), follow_symlinks=False).st_dev
    except OSError:
        return None


def running(host: Host, b: Browser) -> list[int]:
    """This user's processes whose program is the browser's, in the RAM disk: on its device, and in
    its folder (seen from outside the sandbox the path is the one inside it, /home/user/<folder>/…)."""
    dev = _ramdisk_dev(host)
    real = os.path.realpath(root(host) / b.folder).rstrip("/") + "/"
    inside = f"{sandbox.HOME_IN}/{b.folder}/"
    from ..checks._util import children
    out = []
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit():
            continue
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue
            exe = os.readlink(p / "exe")
            st = os.stat(p / "exe")
        except OSError:
            continue
        if exe.startswith(real) or (exe.startswith(inside) and st.st_dev == dev):
            out.append(int(p.name))
    return sorted(out)


_PROBED: dict[tuple[str, str, str], tuple[str | None, float]] = {}
REPROBE = 15.0                          # seconds before a failed probe is tried again (passt installed meanwhile)


def _probe(host: Host, what: str, fn) -> str | None:
    """`fn(host)`, once per run of the app when it succeeds; a failure is tried again after REPROBE seconds,
    so installing what was missing shows when the panel is opened again."""
    key = (what, str(host.root), str(host.home))
    got = _PROBED.get(key)
    if got is None or (got[0] is not None and time.monotonic() - got[1] > REPROBE):
        _PROBED[key] = got = (fn(host), time.monotonic())
    return got[0]


WLROOTS = {"sway", "hyprland", "river", "labwc", "wayfire", "niri", "dwl", "qtile", "cage"}


def sandbox_status(host: Host) -> dict:
    """Whether the browser can run in the sandbox here (bubblewrap, and pasta, tried once per run of
    the app), what Landlock adds, and the session's display."""
    why = _probe(host, "bwrap", sandbox.probe)
    pasta = _probe(host, "pasta", sandbox.probe_pasta) if why is None else "the sandbox can't be used."
    lan = _probe(host, "fence", sandbox.probe_fence) if pasta is None else "pasta isn't used."
    desktop = [d.lower() for d in host.environ.get("XDG_CURRENT_DESKTOP", "").split(":") if d]
    restricted = (host.read_sys("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") or "").strip() == "1"
    exposure = wayland_exposure(host)
    return {"available": why is None, "why": why or "", "landlock": sandbox.landlock_usable(host),
            "apparmor": why is not None and restricted,
            "python": host.sys_path(sandbox.PYTHON).exists(),
            "xephyr": {"available": bool(host.runner.which(sandbox.XEPHYR)), "install": _install_command(host, "Xephyr")},
            "pasta": {"available": pasta is None, "why": pasta or "",
                      "install": _install_command(host, "passt"),
                      # installed, but AppArmor's restriction keeps it from the user namespace it starts in: Ubuntu
                      # 24.04's passt package has a profile for passt, none for pasta (seen on Mint 22.3 with the
                      # restriction on: "clone: Operation not permitted", and fine with a profile like bubblewrap's)
                      "apparmor": why is None and pasta is not None and restricted and bool(host.runner.which("pasta")),
                      "lan_blocked": lan is None, "lan_why": lan or ""},
            "display": session_display(host), "desktop": desktop, "wayland_context": exposure[0],
            "wayland_risky": exposure[1],
            "wlroots": any(d in WLROOTS for d in desktop), "sound": bool(sandbox.sound(host)),
            "gpu": bool(sandbox.gpu(host))}


# a package's name where it differs between distributions: debian, fedora, arch, suse
PACKAGES = {"Xephyr": ("xserver-xephyr", "xorg-x11-server-Xephyr", "xorg-server-xephyr", "xorg-x11-server-Xephyr")}


def _install_command(host: Host, package: str) -> str:
    text = host.read_sys("/etc/os-release") or ""
    ids = set(" ".join(re.findall(r'^(?:ID|ID_LIKE)="?([^"\n]*)', text, re.M)).lower().split())
    names = PACKAGES.get(package, (package,) * 4)
    if ids & {"debian", "ubuntu", "linuxmint"}:
        return f"sudo apt install {names[0]}"
    if ids & {"fedora", "rhel", "centos"}:
        return f"sudo dnf install {names[1]}"
    if "arch" in ids:
        return f"sudo pacman -Syu {names[2]}"      # never -S alone: a stale database (fresh Omarchy) fails
    if ids & {"suse", "opensuse", "opensuse-tumbleweed", "opensuse-leap"}:
        return f"sudo zypper install {names[3]}"
    return ""


def _socket_at(host: Host, path: str) -> str | None:
    """`path` (as the system sees it) on this host, when a socket is there; else None (a fixture's file)."""
    real = host.sys_path(path)
    try:
        return str(real) if stat.S_ISSOCK(os.stat(real).st_mode) else None
    except OSError:
        return None


def _compositor(host: Host) -> str | None:
    """The compositor's socket, as the session names it, when it is there, or None."""
    wl = host.environ.get("WAYLAND_DISPLAY", "")
    if not wl:
        return None
    runtime = host.environ.get("XDG_RUNTIME_DIR", f"/run/user/{host.uid}")
    return _socket_at(host, wl if wl.startswith("/") else f"{runtime}/{wl}")


_CONTEXT: dict[str, tuple[tuple[bool, list[dict]], float]] = {}   # compositor's socket -> (what it gives, when asked)
CONTEXT_AGAIN = 60.0                             # seconds before the compositor is asked again (the panel polls)


def wayland_exposure(host: Host) -> tuple[bool | None, list[dict] | None]:
    """(whether the compositor can mark the browser's connection as a sandbox's, tools/wayland.py; None outside
    Wayland, and what it still offers that connection from wayland.RISKY: {"global", "what"}, or None when the
    compositor couldn't be asked: not the same as none offered). Asked through a throwaway marked socket in a
    folder of the app's in the runtime folder; the plain socket's globals without one."""
    sock = _compositor(host)
    if sock is None:
        return None, []
    got = _CONTEXT.get(sock)
    if got is not None and time.monotonic() - got[1] < CONTEXT_AGAIN:
        return got[0]
    import tempfile
    context, offered = False, None
    try:
        plain = set(wayland.globals_of(sock, timeout=2))
        offered = plain
        if wayland.MANAGER in plain:
            folder = Path(tempfile.mkdtemp(prefix="daprivacyscanner-", dir=host.environ.get("XDG_RUNTIME_DIR") or None))
            try:
                marked = wayland.sandboxed_globals(sock, folder, timeout=2)
            finally:
                shutil.rmtree(folder, ignore_errors=True)
            if marked is not None:
                context, offered = True, marked
    except (OSError, wayland.WaylandError):
        pass
    risky = None if offered is None else [{"global": g, "what": wayland.RISKY[g]} for g in sorted(offered)
                                          if g in wayland.RISKY]
    _CONTEXT[sock] = ((context, risky), time.monotonic())
    return context, risky


def wayland_context(host: Host) -> bool | None:
    """Whether the compositor can mark the browser's connection as a sandbox's; None outside Wayland."""
    return wayland_exposure(host)[0]


def session_display(host: Host) -> str:
    """wayland or x11 (or none): what the browser's windows will be on."""
    if host.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    return "x11" if host.environ.get("DISPLAY") else "none"


def network_of(b: Browser, sb: dict) -> str:
    """What the browser's network will be in the sandbox: tor (Tor's only), private (pasta's), shared."""
    if b.tor:
        return "tor"
    return "private" if sb["pasta"]["available"] else "shared"


def status(host: Host) -> dict:
    rd = ramdisk.status(host, DISK)
    plat = platform_name()
    sb = sandbox_status(host)
    out = []
    for b in BROWSERS.values():
        here = rd.open and installed(host, b)
        entry = {"id": b.id, "name": b.name, "about": b.about, "hosts": list(b.hosts),
                 "available": plat in b.platforms, "folder": f"~/{DISK}/{b.folder}",
                 "installed": here, "running": bool(rd.open and running(host, b)),
                 "network": network_of(b, sb), "tor": b.tor, "security": b.security,
                 "uploads_folder": f"~/{DISK}/{b.folder}/Browser/{sandbox.UPLOADS}",
                 "downloads_folder": f"~/{DISK}/{b.folder}/Browser/{sandbox.DOWNLOADS}"}
        problem = launch_problem(b)
        if problem:
            entry["start_error"] = problem
        if here:
            got, other = transfer.downloads(host, b.folder)
            entry.update(downloads=[e.to_dict() for e in got], downloads_other=other,
                         uploads=transfer.uploads(host, b.folder), sandboxed_before=sandboxed_before(host, b),
                         outbox=transfer.outbox_view(host, b.folder, b.name))
            entry["release"] = release_info(host, b)
            if b.tor:
                entry.update(bridges=bridges_view(host, b), connection=tor_status(host, b))
        out.append(entry)
    return {"platform": plat, "min_mb": MIN_MB, "mat2": bool(host.runner.which("mat2")),
            "ramdisk": {**rd.to_dict(host.home), "max_mb": ramdisk.max_mb(host), "default_mb": ramdisk.DEFAULT_MB,
                        "commands": ramdisk.commands(host, DISK)},
            "sandbox": sb, "risks": risks(host), "browsers": out}


# ------------------------------------------------------------------ before it starts: swap and thumbnails

SWAP_STATE = "/run/daprivacyscanner/swap.json"       # the helper's: what swap_off turned off


def _swaps(host: Host) -> list[dict]:
    out = []
    for ln in (host.read_sys("/proc/swaps") or "").splitlines()[1:]:
        f = ln.split()
        if len(f) < 5:
            continue
        name = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), f[0])
        m = re.fullmatch(r"/dev/(zram\d+)", name)
        if m and (host.read_sys(f"/sys/block/{m.group(1)}/backing_dev") or "none").strip() in ("", "none"):
            continue                                     # zram without writeback: in memory only
        try:
            out.append({"name": name, "used_mb": int(f[3]) // 1024, "priority": int(f[4])})
        except ValueError:
            continue
    return out


def risks(host: Host) -> dict:
    """What can put the browser's session on the disk however it is run: swap that reaches a disk
    (the browser's own memory, not only the RAM disk, can be written there), thumbnails the file
    manager keeps on the disk of what is in To upload and Downloads, and crash dumps kept on the
    disk (enc.coredumps_retained: the browser's own are left without memory, other programs' aren't).
    With the commands the swap buttons run, for the user to learn."""
    disk = _swaps(host)
    try:
        paused = json.loads(host.read_sys(SWAP_STATE) or "{}").get("devices", [])
        paused = [d for d in paused if isinstance(d, dict) and isinstance(d.get("name"), str)]
    except (ValueError, AttributeError):
        paused = []
    cache = Path(host.environ.get("XDG_CACHE_HOME") or host.home / ".cache") / "thumbnails"
    real, base = os.path.realpath(cache), os.path.realpath(host.root)
    if base != "/" and real.startswith(base + "/"):                # a fixture tree: the path as the system sees it
        real = real[len(base):]
    mounted = any(m[1] == real and m[2] == "tmpfs" for m in ramdisk._mounts(host))
    from ..checks.encryption import crash_dumps
    try:
        dumps_kept = crash_dumps(host)[0]
    except Exception:  # noqa: BLE001 - a risk note, never a reason the panel fails
        dumps_kept = None
    q = shlex.quote
    on_cmds =[f"sudo swapon {'-p ' + str(d['priority']) + ' ' if isinstance(d.get('priority'), int) and d['priority'] >= 0 else ''}"
               f"{q(d['name'])}" for d in (paused or [{"name": s["name"], "priority": s["priority"]} for s in disk])]
    return {"swap": {"on_disk": [s["name"] for s in disk], "used_mb": sum(s["used_mb"] for s in disk),
                     "paused": [d["name"] for d in paused],
                     "off_commands": [f"sudo swapoff {q(s['name'])}" for s in disk], "on_commands": on_cmds},
            "thumbnails": {"in_memory": mounted, "folder": "~/" + os.path.relpath(cache, host.home)
                           if str(cache).startswith(str(host.home) + "/") else str(cache)},
            "crash_dumps": {"kept": dumps_kept, "start": CRASH_COMMANDS}, "indexing": indexing(host),
            "hibernation": ramdisk.hibernation_possible(host), "opensnitch": opensnitch_records(host),
            "memory": _memory(host)}


_OPENSNITCH: dict[str, tuple[dict | None, float]] = {}


def opensnitch_records(host: Host) -> dict | None:
    """What OpenSnitch, where it runs, writes to the disk about the browser's connections: its log at level 2 or
    below (every question, answered or not, a line naming the site or program, in a log any account can read), and
    the window's list of connections when it is a file (every connection, with the site's name). Mullvad Browser's
    connections are passt's, named after the site; Tor Browser's are tor's, to its relays only. None when neither
    (or OpenSnitch isn't running); read at most every OPENSNITCH_AGAIN seconds (the panel asks every 2)."""
    key = str(host.home)
    got = _OPENSNITCH.get(key)
    if got is not None and time.monotonic() - got[1] < OPENSNITCH_AGAIN:
        return got[0]
    from .. import opensnitch as osn
    from ..paths import PathResolver
    try:
        s = osn.read(host, PathResolver(host.home, host.environ))
    except Exception:  # noqa: BLE001 - the panel goes on without it
        s = None
    out = None
    if s is not None and s.daemon and s.active:
        level = s.log_level
        logs = level is not None and level <= 2
        if logs or s.database_file:
            out = {"log_level": level if logs else None, "log": osn.LOG if logs else None, "database": s.database_file}
    _OPENSNITCH[key] = (out, time.monotonic())
    return out


OPENSNITCH_AGAIN = 30.0


BROWSER_MB = 2048                       # about what the browser itself takes in memory, with a few tabs


def _memory(host: Host) -> dict:
    """This computer's memory, in MB (/proc/meminfo): what turning swap off leaves for ~/TempBrowser and the browser."""
    got = {}
    for ln in (host.read_sys("/proc/meminfo") or "").splitlines():
        f = ln.split()
        if len(f) >= 2 and f[0] in ("MemTotal:", "MemAvailable:") and f[1].isdigit():
            got[f[0][:-1]] = int(f[1]) // 1024
    return {"total_mb": got.get("MemTotal"), "available_mb": got.get("MemAvailable"), "browser_mb": BROWSER_MB}


UNINDEXED = (".trackerignore", ".nomedia")       # LocalSearch (Tracker) leaves a folder holding either alone


def _unindexed(host: Host) -> None:
    """Marks ~/TempBrowser's top for LocalSearch, which then never indexes anything in it (where the user has it
    index the whole home folder): empty files, made without following links, never over anything."""
    try:
        fd = os.open(root(host), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return
    try:
        for name in UNINDEXED:
            try:
                os.close(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                 dir_fd=fd))
            except OSError:
                pass
    finally:
        os.close(fd)


_INDEXING: dict[str, tuple[dict, float]] = {}
INDEXING_AGAIN = 15.0                            # seconds before it is read again (the panel polls)


def indexing(host: Host) -> dict:
    """File search (desk.indexers, briefly): Baloo, on or with an index left on the disk, and whether it would index
    ~/TempBrowser (a RAM disk under the home folder: tested, it does, contents included; and it isn't to be trusted to
    forget: a folder excluded afterwards stayed in its index, tested, so the panel offers only turning it off and
    deleting the index), and LocalSearch or Tracker with folders to index, where what is saved out of the browser into
    those folders gets indexed too. Each None when it isn't on (Baloo: nor its index there)."""
    key = str(host.home)
    got = _INDEXING.get(key)
    if got is not None and time.monotonic() - got[1] < INDEXING_AGAIN:
        return got[0]
    from ..checks.desktop import INDEXER_SCHEMA, baloo_covers
    from ..desktop import GNOME, KDE, DesktopInfo
    from ..paths import PathResolver
    from .. import ini
    paths = PathResolver(host.home, host.environ)
    info = DesktopInfo(())
    kde, gnome = KDE(host, paths, info), GNOME(host, info)
    baloo = None
    index = (paths.data_home / "baloo/index").is_file()
    if (host.runner.which("balooctl6") or host.runner.which("balooctl") or index
            or (paths.config_home / "baloofilerc").is_file()):
        enabled = ini.truthy(kde.get("baloofilerc", "Basic Settings", "Indexing-Enabled"))
        if enabled is not False:                                       # KDE's default is on
            baloo = {"on": True, "contents": not ini.truthy(kde.get("baloofilerc", "General", "only basic indexing")),
                     "covers": baloo_covers(kde, host.home, root(host)), "index": index}
        elif index:                                                    # off, but what it indexed is still there
            baloo = {"on": False, "contents": False, "covers": False, "index": True}
    local = None
    cmd = gnome.indexer_command()
    if cmd:
        folders = [gnome.gsettings(INDEXER_SCHEMA, k) for k in ("index-recursive-directories", "index-single-directories")]
        if any(folders) or gnome.gsettings(INDEXER_SCHEMA, "index-removable-devices") is True:
            local = "LocalSearch" if cmd == "localsearch" else "Tracker"
    out = {"baloo": baloo, "localsearch": local}
    _INDEXING[key] = (out, time.monotonic())
    return out


# how every start keeps the browser's memory out of crash dumps (sandbox.KEYRING does it in python3), as a shell
# would, shown to learn from
CRASH_COMMANDS = ["echo 0 > /proc/self/coredump_filter", "prlimit --pid $$ --core=1:1"]   # not ulimit: it counts in KB


def ready(host: Host) -> str | None:
    """Why the browser can't go into the RAM disk now, or None."""
    rd = ramdisk.status(host, DISK)
    if rd.other:
        return f"Something else ({rd.other}) is mounted on ~/{DISK}."
    if not rd.open:
        return (f"Open the browser's RAM disk (~/{DISK}) first, with programs allowed to run from it (at least "
                f"{MIN_MB} MB).")
    if rd.noexec:
        return (f"~/{DISK} is open with programs not allowed to run from it, so the browser couldn't start there. "
                "Close it and open it again with that box unticked.")
    return None


# ------------------------------------------------------------------ getting it

def release(net, b: Browser, plat: str) -> tuple[str, str, str]:
    """(version, archive URL, signature URL) from the project's own index. Every URL must be https
    on one of the browser's hosts, and the file name the project's own pattern."""
    url = b.index.format(platform=plat)
    r = net.http_get(url, hosts=b.hosts)
    if not r.ok:
        raise BrowserError(f"{urllib.parse.urlsplit(url).hostname} didn't answer ({r.status or r.error}).")
    try:
        data = json.loads(r.text())
        version, binary, sig = str(data["version"]), str(data["binary"]), str(data["sig"])
    except (ValueError, KeyError, TypeError):
        raise BrowserError("The project's download index couldn't be read.") from None
    for u in (binary, sig):
        parts = urllib.parse.urlsplit(u)
        if parts.scheme != "https" or parts.hostname not in b.hosts:
            raise BrowserError(f"The download index points somewhere unexpected ({parts.hostname}); nothing was downloaded.")
    name = Path(urllib.parse.urlsplit(binary).path).name
    if sig != binary + ".asc" or not b.archive_name(name):
        raise BrowserError("The download index names a file the app doesn't expect; nothing was downloaded.")
    if version_of(name) != version:
        raise BrowserError(f"The download index says version {version} but names {name}; nothing was downloaded.")
    return version, binary, sig


def version_of(archive_name: str) -> str:
    """The version in an archive's name: tor-browser-linux-x86_64-15.0.24.tar.xz -> 15.0.24."""
    m = re.search(r"-linux-(?:x86_64|i686)-([0-9][0-9a-z.]*)\.tar\.xz$", archive_name)
    return m.group(1) if m else ""


def download(host: Host, net, b: Browser, job: dict, stop: Callable[[], bool]) -> Path:
    """Downloads the archive and its signature into the RAM disk; returns the archive's path."""
    problem = ready(host)
    if problem:
        raise BrowserError(problem)
    plat = platform_name()
    if plat not in b.platforms:
        raise BrowserError(f"{b.name} isn't made for this processor ({platform.machine()}).")
    job.update(phase=f"Asking {urllib.parse.urlsplit(b.index).hostname} for the latest version")
    version, binary, sig = release(net, b, plat)
    job["version"] = version
    dest = root(host) / DOWNLOADS
    dest.mkdir(mode=0o700, exist_ok=True)
    archive = dest / Path(urllib.parse.urlsplit(binary).path).name
    files = ((sig, archive.with_name(archive.name + ".asc"), "signature"), (binary, archive, "archive"))

    def progress(done: int, total: int | None) -> None:
        job.update(done=done, total=total or 0)
    try:
        for url, path, what in files:
            job.update(phase=f"Downloading the {what} from {urllib.parse.urlsplit(url).hostname}", done=0, total=0)
            part = path.with_name(path.name + ".part")
            r = net.download(url, part, progress=progress, stop=stop, limit=MAX_ARCHIVE, hosts=b.hosts)
            if stop():
                raise Stopped("Stopped: nothing was kept.")
            if not r.ok:
                raise BrowserError(f"The {what} couldn't be downloaded ({r.status or r.error}).")
            os.replace(part, path)
    except BaseException:
        for _, path, _ in files:
            for p in (path, path.with_name(path.name + ".part")):
                p.unlink(missing_ok=True)
        raise
    return archive


def verified(host: Host, archive: Path) -> dict:
    """Verify a download on the archive, with only the app's own list of keys (not the user's keyring:
    the answer must be the Tor Browser Developers key, nothing else). Raises unless it is verified."""
    from . import verify as V
    v = V.verify(host, archive, [], "", use_keyring=False)
    good = [s for s in v.signatures if s.good and s.project is not None and s.project.id == PROJECT]
    if v.level != "verified" or not good:
        raise BrowserError(f"{archive.name} isn't verified ({v.title}). It was not unpacked." +
                           ("" if v.signatures else f" Its signature ({archive.name}.asc) must be next to it."))
    # when it was signed: the verified signature's own creation time (gpgv's VALIDSIG, or the packet naming the key
    # sqv checked), never read from the file apart: a second packet there, by any key, could carry any date
    return {"title": v.title, "fingerprint": good[0].fingerprint, "signer": good[0].project.name,
            "signed": good[0].signed_at}


def which(archive: Path) -> Browser:
    b = next((b for b in BROWSERS.values() if b.archive_name(archive.name)), None)
    if b is None:
        raise BrowserError(f"{archive.name} isn't a Tor Browser or Mullvad Browser archive for Linux "
                           "(tor-browser-linux-x86_64-<version>.tar.xz, or mullvad-browser-…).")
    return b


def copy_in(host: Host, archive: Path, job: dict) -> Path:
    """An archive the user picked, and its signature, copied into the RAM disk's downloads first: what is
    verified is then what is unpacked (the file the user picked could change between the two, on a shared
    or removable disk), and the user's own file is never touched. Returns the copy's path."""
    problem = ready(host)
    if problem:
        raise BrowserError(problem)
    dest = root(host) / DOWNLOADS
    dest.mkdir(mode=0o700, exist_ok=True)
    if archive.parent.resolve() == dest.resolve():
        return archive
    job.update(phase=f"Copying {archive.name} into ~/{DISK}", done=0, total=0)
    for src in (archive.with_name(archive.name + ".asc"), archive):
        (dest / src.name).unlink(missing_ok=True)       # nothing of an earlier copy stays, a signature included
    for src in (archive.with_name(archive.name + ".asc"), archive):
        try:
            fd = os.open(src, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        except FileNotFoundError:
            continue                                    # no signature beside it: verifying says so
        except OSError as e:
            raise BrowserError(f"{src.name} can't be read: {e.strerror or e}.") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ARCHIVE:
                raise BrowserError(f"{src.name} isn't a browser archive (or its signature).")
            if st.st_size + 64 * 1024 * 1024 > shutil.disk_usage(root(host)).free:
                raise BrowserError(f"There isn't room for {src.name} in ~/{DISK}. Close it and open it again bigger.")
            target = dest / src.name
            out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(out, "wb") as w, os.fdopen(os.dup(fd), "rb") as r:
                job["total"], copied = st.st_size, 0
                while chunk := r.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > MAX_ARCHIVE:            # growing while it is read: not the file that was checked
                        target.unlink(missing_ok=True)
                        raise BrowserError(f"{src.name} grew past {MAX_ARCHIVE // 2**20} MB while it was copied: "
                                           "it isn't a browser archive.")
                    w.write(chunk)
                    job["done"] = job.get("done", 0) + len(chunk)
        finally:
            os.close(fd)
    return dest / archive.name


def _inner_version(tar: tarfile.TarFile, members: list, b: Browser) -> str:
    """The version the archive says it is, from its own version file (not its name, which anyone can change)."""
    name = f"{b.folder}/{b.version_file}"
    m = next((m for m in members if m.name == name and m.isfile() and m.size < 4096), None)
    try:
        data = json.loads(tar.extractfile(m).read()) if m else None
        return str(data["version"]) if isinstance(data, dict) else ""
    except (ValueError, KeyError, TypeError, AttributeError):
        return ""


def unpack(host: Host, archive: Path, b: Browser, job: dict) -> Path:
    """Unpacks the archive into ~/TempBrowser/<folder>: regular files and folders only, every one inside
    that folder, permissions limited to the user; first into a hidden folder, then renamed. Refuses
    when there isn't room, the folder is already there (the browser in it may be running), or the version
    in the archive isn't the one its name says: a signed old release renamed as the latest would pass
    the signature check and the check for a newer version."""
    problem = ready(host)
    if problem:
        raise BrowserError(problem)
    base = root(host)
    _unindexed(host)
    target = base / b.folder
    if target.exists() or target.is_symlink():
        raise BrowserError(f"~/{DISK}/{b.folder} is already there. Close ~/{DISK} (it overwrites it) "
                           "to start again with a fresh copy.")
    job.update(phase=f"Unpacking into ~/{DISK}/{b.folder}", done=0, total=0)
    with tarfile.open(archive, "r:xz") as tar:
        members = tar.getmembers()
        size = 0
        for m in members:
            name = m.name.rstrip("/")
            if not (name == b.folder or name.startswith(b.folder + "/")) or ".." in Path(name).parts \
                    or Path(name).is_absolute():
                raise BrowserError(f"The archive holds {m.name}, outside {b.folder}: it was not unpacked.")
            if not (m.isfile() or m.isdir()):
                raise BrowserError(f"The archive holds {m.name}, which isn't a file or a folder: it was not unpacked.")
            size += m.size
        inner, named = _inner_version(tar, members, b), version_of(archive.name)
        if inner != named:
            raise BrowserError(f"{archive.name} says it is version {named}, but what is inside is "
                               f"{'version ' + inner if inner else 'of no version the app can read'}: it was not "
                               "unpacked. Download it from the project itself.")
        free = shutil.disk_usage(base).free
        if size + 64 * 1024 * 1024 > free:
            raise BrowserError(f"It needs {size // 2**20 + 64} MB and the RAM disk has {free // 2**20} MB free. Close "
                               f"~/{DISK} and open it again bigger.")
        staging = base / f".{b.folder}.unpacking"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(mode=0o700)
        job["total"] = size
        try:
            for m in members:
                rel = Path(m.name).relative_to(b.folder) if m.name.rstrip("/") != b.folder else Path(".")
                dest = staging / rel
                if m.isdir():
                    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                src = tar.extractfile(m)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                with src, open(os.open(dest, flags, 0o600), "wb") as out:
                    shutil.copyfileobj(src, out, 1024 * 1024)
                os.chmod(dest, 0o700 if m.mode & 0o100 else 0o600)
                job["done"] = job.get("done", 0) + m.size
            os.rename(staging, target)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    return target


# It is for one session, or a few over a day: it never updates itself (its program files are read-only to it
# in the sandbox, and a copy in the RAM disk is gone when it closes anyway), and setting it up again downloads
# the latest. A copy set up more than SESSION_HOURS ago checks the project's index before it starts (the
# panel says so beforehand, naming the host), and doesn't start when a newer version is out, or when that
# can't be checked. An archive the user picked is checked against the index before it is unpacked.
SESSION_HOURS = 24
RECHECK_SECONDS = 3600            # one check covers starts within the hour after it


def index_host(b: Browser) -> str:
    return urllib.parse.urlsplit(b.index).hostname or ""


def _version_key(v: str) -> tuple:
    """Orders versions as the projects do: 15.0.24 > 15.0 > 15.0b2 > 15.0a1 (an alpha or beta comes before the
    release it leads to, so one isn't taken for newer than it)."""
    m = re.fullmatch(r"(\d+(?:\.\d+)*)(?:([ab])(\d+))?.*", v)
    if not m:
        return ((), 0, 0)
    numbers = tuple(int(x) for x in m.group(1).split("."))
    return (numbers, 1, 0) if not m.group(2) else (numbers, 0, int(m.group(3)) + (1000 if m.group(2) == "b" else 0))


class Unreachable(BrowserError):
    """The project's index couldn't be read: where its server is blocked (censorship), or the network is down."""


# Where the index can't be reached (the project's server blocked: the users GetTor serves), an archive the user
# picked is accepted, with a warning, when its signature (verified) was made within RECENT_DAYS, and a copy set up
# more than a day ago still starts within that time. Releases come every few weeks: a card names one signed more
# than STALE_DAYS before it was set up, even where the index agreed (an index and archive both served by someone
# who can intercept the connection would be old ones).
RECENT_DAYS = 30
STALE_DAYS = 56


def latest_version(net, b: Browser) -> str:
    """The latest version, from the project's own index (one https request to its host). Raises
    Unreachable when it can't be learnt."""
    plat = platform_name()
    if plat not in b.platforms:
        raise BrowserError(f"{b.name} isn't made for this processor ({platform.machine()}).")
    try:
        return release(net, b, plat)[0]
    except BrowserError as e:
        raise Unreachable(f"Which version of {b.name} is the latest couldn't be checked: {e}") from None


FUTURE_SKEW = 86400               # a signature dated further ahead than this isn't trusted for its date


def _days(seconds: float) -> int:
    return max(0, int(seconds // 86400))


def _recent(signed: int | None, now: float | None = None) -> bool:
    """Whether a verified signature's date is within RECENT_DAYS, and not in the future beyond a clock's error."""
    now = time.time() if now is None else now
    return signed is not None and -FUTURE_SKEW <= now - signed <= RECENT_DAYS * 86400


def accept_unchecked(archive: Path, b: Browser, why: str, signed: int | None) -> str:
    """An archive the user picked, verified, whose being the latest couldn't be checked (`why`): accepted when its
    signature (`signed`: when the verified signature was made, from `verified`) was made within RECENT_DAYS.
    Returns the warning to show; raises BrowserError otherwise."""
    if signed is None:
        raise BrowserError(f"{why} When its signature was made can't be read either, so it isn't accepted without "
                           "that check. Nothing was unpacked.")
    if time.time() - signed < -FUTURE_SKEW:
        raise BrowserError(f"{why} Its signature is dated in the future ({_days(signed - time.time())} days ahead), "
                           "which this computer's clock, or the file, has wrong: it isn't accepted without that check. "
                           "Nothing was unpacked.")
    days = _days(time.time() - signed)
    if days > RECENT_DAYS:
        raise BrowserError(f"{why} Its signature was made {days} days ago: without that check, the app accepts only "
                           f"an archive signed in the last {RECENT_DAYS} days (a newer version, with security fixes, is "
                           "likely out by now). Get the latest archive (from the project's site, a mirror, or GetTor) "
                           "and try again. Nothing was unpacked.")
    return (f"Whether {b.name} {version_of(archive.name)} is the latest couldn't be checked ({why.split(': ', 1)[-1]}). "
            f"Its signature was made {days} day{'s' if days != 1 else ''} ago, so it is recent, but a newer version with "
            "security fixes may be out: check when you can (the project's site, a mirror, or GetTor).")


def check_latest(net, b: Browser, archive_name: str) -> str:
    """For an archive the user picked: refuses one older than the latest; raises Unreachable when that can't be
    checked (accept_unchecked decides then, once the signature is verified). Returns the latest version."""
    latest = latest_version(net, b)
    mine = version_of(archive_name)
    if _version_key(mine) < _version_key(latest):
        raise BrowserError(f"{archive_name} is version {mine}, and {b.name} {latest} is out: an old version has "
                           "security holes the new one fixes. Download it again here (Download…), or the latest "
                           "archive yourself. Nothing was unpacked.")
    return latest


# The security level each browser starts at. Tor Browser: Safest, preset when it is unpacked (the shield button
# lowers it, for as long as the RAM disk is open): it turns off JavaScript's optimisers and more, which most
# exploits need. Mullvad Browser: Standard, its own default (nothing is preset for it; preset_vpn's profile leaves the
# level alone): it is for everyday browsing, where sites need more of what Safest turns off.
SECURITY_LEVELS = {"safest": 1, "safer": 2, "standard": 4}
SECURITY_MODULE = "modules/SecurityLevel.sys.mjs"                    # in omni.ja: the prefs each level sets


def _security_prefs(omni: Path, level: int) -> dict[str, bool]:
    """The prefs the browser's own security-level module sets for `level` (its kSecuritySettings table),
    so the profile starts as the browser would have set it (else it asks for a restart). {} when the
    table can't be read."""
    import zipfile
    try:
        with zipfile.ZipFile(omni) as z:
            text = z.read(SECURITY_MODULE).decode(errors="replace")
    except (OSError, KeyError, zipfile.BadZipFile):
        return {}
    table = text[text.find("kSecuritySettings = {"):]
    table = table[:table.find("};")]
    out = {}
    for name, values in re.findall(r'"([\w.]+)":\s*\[\s*,\s*((?:true|false)(?:\s*,\s*(?:true|false)){3})\s*\]', table):
        out[name] = [v.strip() == "true" for v in values.split(",")][level - 1]
    return out


def preset_security(host: Host, b: Browser, target: Path) -> str:
    """Sets the security level the browser starts at in the profile the archive ships (b.security); returns
    the level. Only where the archive has that profile (Tor Browser)."""
    if not b.profile or b.security == "standard":
        return b.security
    level = SECURITY_LEVELS[b.security]
    profile = target / b.profile
    if not profile.is_dir() or profile.is_symlink():
        return "standard"
    prefs = {"browser.security_level.security_slider": level, "browser.security_level.security_custom": False,
             "browser.security_level.noscript_inited": False, **_security_prefs(target / "Browser/omni.ja", level)}
    lines = [f"// Set by DA Privacy Kit when it set this copy up: the {b.security.capitalize()} security level "
             "(the shield button changes it).\n"]
    lines += [f'user_pref("{k}", {str(v).lower() if isinstance(v, bool) else v});\n' for k, v in prefs.items()]
    fd = os.open(profile / "prefs.js", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write("".join(lines))
    return b.security


# Mullvad Browser set up for Mullvad VPN (the panel's tick, on by default): its extension's proxy on for every site,
# through one of Mullvad's SOCKS5 proxies inside the VPN's tunnel (vpn-providers.yaml `browser_proxy`: Zurich), so no
# page loads unless Mullvad VPN is connected; the extension's permissions (proxy, tabs, every site) granted, which it
# otherwise asks for when first opened; and secure DNS (Mullvad's DNS over HTTPS, the browser's default, mode 3) off,
# as the extension advises while connected: lookups go through the proxy, or to the VPN's DNS. Mullvad Browser makes
# its profile at its first start, in a folder named per install, so the app makes one first, Data/profile.default
# named in Data/profiles.ini, which the browser uses when started with MOZ_LEGACY_PROFILES=1 (browser_env; without it
# the browser made a profile of its own beside it). The grant is the legacy permission store (extension-preferences.json,
# what release builds use), the proxy a storage.js the browser imports into the extension's storage at its first use
# (keepStorageOnUninstall: without it a fresh install marks the extension's storage migrated and skips the file). Tested
# headless on 15.0.24 (Firefox ESR 140) with extension 0.9.10: the grant kept through the extension's install, the file
# imported, every connection to the proxy and none direct (on a normal start; a web address passed on the command line,
# which the app never does, loads before the extension starts). These are the extension's and Firefox's internal
# formats, so only for the versions tested (VPN_TESTED); otherwise nothing is preset and the card says why.
MULLVAD_EXTENSION = "{d19a89b9-76c1-4a61-bcd4-49e8de916403}"
VPN_TESTED = {"browser": re.compile(r"15\.\d+(\.\d+)*"), "extension": re.compile(r"0\.9\.\d+")}
VPN_DATA = "Data"
VPN_PROFILE = "profile.default"
VPN_ENV = {"MOZ_LEGACY_PROFILES": "1"}


def _extension_version(target: Path) -> str:
    import zipfile
    try:
        with zipfile.ZipFile(target / f"Browser/distribution/extensions/{MULLVAD_EXTENSION}.xpi") as z:
            v = json.loads(z.read("manifest.json")).get("version")
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        return ""
    return v if isinstance(v, str) else ""


def _write_new(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def preset_vpn(host: Host, b: Browser, target: Path, archive: Path, proxy=None) -> dict | None:
    """Mullvad Browser just unpacked at `target`, set up for Mullvad VPN (see above). Returns what to record:
    {"set": True, "server", "hostname", "city", "country", "address", "port"}, or {"set": False, "why"} when
    this version wasn't tested; None for another browser."""
    if b.id != "mullvad":
        return None
    if proxy is None:
        from .. import vpn
        proxy = vpn.load()["mullvad"].browser_proxy
    version, ext = version_of(archive.name), _extension_version(target)
    if not VPN_TESTED["browser"].fullmatch(version) or not VPN_TESTED["extension"].fullmatch(ext):
        this = version or "a version the app can't read"
        with_ext = f"extension {ext}" if ext else "no extension the app recognises"
        return {"set": False, "why": f"The app's settings for Mullvad VPN were made for Mullvad Browser 15 with its "
                f"extension 0.9; this is {this} with {with_ext}, so it starts as the browser leaves it. Update the app "
                "for a version that sets it up."}
    data = _dir(host, f"{b.folder}/{VPN_DATA}")
    store = _dir(host, f"{b.folder}/{VPN_DATA}/{VPN_PROFILE}/browser-extension-data/{MULLVAD_EXTENSION}")
    profile = data / VPN_PROFILE
    js = lambda v: json.dumps(v, separators=(",", ":"))      # noqa: E731 - the extension keeps JSON text
    _write_new(data / "profiles.ini", f"[Profile0]\nName=default-release\nIsRelative=1\nPath={VPN_PROFILE}\nDefault=1\n\n"
                                      "[General]\nStartWithLastProfile=1\nVersion=2\n")
    _write_new(profile / "prefs.js",
               "// Set by DA Privacy Kit when it set this copy up for Mullvad VPN: secure DNS off (Settings, Privacy\n"
               "// & Security, DNS over HTTPS turns it back on), and the extension's settings kept on its first start.\n"
               'user_pref("network.trr.mode", 5);\n'
               'user_pref("extensions.webextensions.keepStorageOnUninstall", true);\n')
    _write_new(profile / "extension-preferences.json", js(
        {MULLVAD_EXTENSION: {"permissions": ["proxy", "tabs"], "origins": ["<all_urls>"], "data_collection": []}}))
    _write_new(store / "storage.js", js({
        "globalProxy": js({"host": proxy.address, "port": proxy.port, "proxyDNS": True, "type": "socks"}),
        "globalProxyDetails": js({"socksEnabled": True, "server": proxy.server, "country": proxy.country,
                                  "countryCode": proxy.country_code, "city": proxy.city, "proxyDNS": True}),
        "excludedHosts": "[]", "hostProxies": "{}", "hostProxiesDetails": "{}", "randomProxyMode": "false"}))
    return {"set": True, "server": proxy.server, "hostname": proxy.hostname, "city": proxy.city,
            "country": proxy.country, "address": proxy.address, "port": proxy.port}


def browser_env(host: Host, b: Browser) -> dict[str, str]:
    """What the start adds to the browser's environment: for a copy set up for Mullvad VPN, the variable
    that makes it use the profile the app made."""
    vpn = _release(host, b).get("vpn")
    return dict(VPN_ENV) if isinstance(vpn, dict) and vpn.get("set") is True else {}


def record_release(host: Host, b: Browser, archive: Path, source: str, security: str = "standard",
                   unchecked: bool = False, signed: int | None = None, vpn: dict | None = None) -> dict:
    """What was unpacked: its version (from the verified archive's name), when its signature was made
    (`signed`, from `verified`: the verified signature's own date), when it was set up, the security level it
    starts at, whether its being the latest couldn't be checked, and what preset_vpn did, kept in the app's
    private folder for the RAM disk's lifetime."""
    _write_release(host, b, {"version": version_of(archive.name), "signed": signed, "source": source,
                             "unpacked": int(time.time()), "checked": int(time.time()), "security": security,
                             "unchecked": unchecked, "vpn": vpn})
    return release_info(host, b) or {}


def _write_release(host: Host, b: Browser, info: dict) -> None:
    private = _dir(host, private_dir(host, b).name)
    fd = os.open(private / "release.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(info, f)


def _release(host: Host, b: Browser) -> dict:
    try:
        d = json.loads(_read_small(private_dir(host, b) / "release.json"))
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def release_info(host: Host, b: Browser) -> dict | None:
    """{"version", "signed", "source", "unpacked", "check_from", "check_due", "host"} for what is in the
    RAM disk, or None. check_due: starting it now first asks the index for a newer version."""
    d = _release(host, b)
    if not d:
        return None
    num = lambda k: d.get(k) if isinstance(d.get(k), int) else None      # noqa: E731
    unpacked, checked = num("unpacked"), num("checked")
    check_from = unpacked + SESSION_HOURS * 3600 if unpacked else None
    now = time.time()
    due = check_from is None or (now >= check_from and not (checked and now - checked < RECHECK_SECONDS))
    security = d.get("security") if d.get("security") in SECURITY_LEVELS else "standard"
    signed = num("signed")
    age = _days((unpacked or now) - signed) if signed else None
    return {"version": str(d.get("version", ""))[:40], "signed": signed, "source": str(d.get("source", "")),
            "unpacked": unpacked, "check_from": check_from, "check_due": due, "host": index_host(b),
            "security": security, "unchecked": d.get("unchecked") is True, "signed_days": age,
            "stale": age is not None and age > STALE_DAYS, "vpn": _vpn_view(d.get("vpn"))}


def _vpn_view(v) -> dict | None:
    if not isinstance(v, dict):
        return None
    keys = ("server", "hostname", "city", "country", "address", "why") if v.get("set") is True else ("why",)
    return {"set": v.get("set") is True, **{k: str(v.get(k, ""))[:400] for k in keys}}


def check_before_start(host: Host, b: Browser, net) -> None:
    """A copy set up more than SESSION_HOURS ago: refuses to start when a newer version is out, or when
    that can't be checked; otherwise notes the check (it covers the next hour's starts)."""
    info = release_info(host, b)
    if info is None:                                    # unpacked, but never recorded (an interrupted set-up)
        raise BrowserError(f"How this copy of {b.name} was set up isn't recorded (its set-up may have been "
                           f"interrupted), so it doesn't start. Close ~/{DISK} and set it up again.")
    if not info["check_due"]:
        return
    if net is None:
        raise BrowserError(f"{b.name} was set up more than a day ago, and checking for a newer version needs the "
                           "network.")
    try:
        latest = latest_version(net() if callable(net) else net, b)
    except Unreachable as e:
        if _recent(info["signed"]):
            # the project's server blocked: a release signed within RECENT_DAYS still starts, its card says why
            _write_release(host, b, {**_release(host, b), "checked": int(time.time()), "unchecked": True})
            return
        raise BrowserError(f"{e} It was set up more than a day ago, and its signature is more than {RECENT_DAYS} days "
                           f"old, so it doesn't start without that check. Save what you need from its Downloads, then "
                           f"close ~/{DISK} and set it up again.") from None
    except BrowserError as e:
        raise BrowserError(f"{e} It was set up more than a day ago, so it doesn't start without that check. Save "
                           f"what you need from its Downloads, then close ~/{DISK} and set it up again.") from None
    if info["version"] and _version_key(latest) > _version_key(info["version"]):
        raise BrowserError(f"{b.name} {latest} is out, and this copy is {info['version']}: it doesn't update itself, "
                           f"so it won't start. Save what you need from its Downloads (Save…), then close ~/{DISK} "
                           "(that overwrites everything in it) and download it again here.")
    _write_release(host, b, {**_release(host, b), "checked": int(time.time()), "unchecked": False})


def tidy(host: Host, archive: Path) -> None:
    """A downloaded archive and signature, unpacked or refused: removed to give their memory back
    (they are the project's public files, nothing of the user's). An archive the user chose stays."""
    if archive.parent == root(host) / DOWNLOADS:
        for p in (archive, archive.with_name(archive.name + ".asc")):
            p.unlink(missing_ok=True)


# ------------------------------------------------------------------ its folders

def _dir(host: Host, rel: str, create: bool = True) -> Path:
    """~/TempBrowser/<rel>, made when missing: every folder on the way opened without following
    links, the user's own and on the RAM disk. Refuses anything else (the browser, run without the
    sandbox, could have put a link there)."""
    base = root(host)
    dev = _ramdisk_dev(host)
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in Path(rel).parts:
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nfd
            st = os.fstat(fd)
            if st.st_uid != host.uid or st.st_dev != dev:
                raise OSError("not the user's folder on the RAM disk")
    except OSError:
        os.close(fd)
        raise BrowserError(f"~/{DISK}/{rel} isn't a folder of yours in the RAM disk any more (it may have been "
                           f"replaced by a link). Close ~/{DISK} and set the browser up again.") from None
    os.close(fd)
    return base / rel


def prepare(host: Host, b: Browser) -> tuple[Path, Path, Path]:
    """The folders a start needs, checked: (the browser's folder, its session folder made afresh,
    the app's private folder). The profile, Downloads and To upload; the two things the start script
    would otherwise try to make in its (read-only) folder: .config/ibus and .local/share as a link to
    /dev/null (its guard against GTK's recent-files list); the session folder overwritten and made
    again (nothing a previous run left there carries over), with Tor Browser's GTK settings (no
    recent files) copied into it."""
    folder = _dir(host, b.folder, create=False)
    _unindexed(host)
    for rel in (*b.writable, *b.hidden, f"Browser/{sandbox.UPLOADS}", "Browser/.config/ibus", "Browser/.local"):
        _dir(host, f"{b.folder}/{rel}")
    try:
        transfer.prepare(host, b.folder)
    except transfer.TransferError as e:
        raise BrowserError(str(e)) from None
    local = folder / "Browser/.local"
    share = local / "share"
    if share.is_symlink():
        if os.readlink(share) != "/dev/null":
            raise BrowserError(f"~/{DISK}/{b.folder}/Browser/.local/share isn't what the app made. Close ~/{DISK} "
                               "and set the browser up again.")
    elif share.exists():
        raise BrowserError(f"~/{DISK}/{b.folder}/Browser/.local/share isn't what the app made. Close ~/{DISK} "
                           "and set the browser up again.")
    else:
        os.symlink("/dev/null", share)
    session = _dir(host, session_dir(host, b).name)
    ramdisk.wipe(session)
    for sub in sandbox.SESSION_DIRS.values():
        (session / sub).mkdir(mode=0o700)
    gtk = folder / "Browser/.config/gtk-3.0/settings.ini"
    if gtk.is_file() and not gtk.is_symlink():
        (session / "config/gtk-3.0").mkdir(mode=0o700)
        shutil.copyfile(gtk, session / "config/gtk-3.0/settings.ini", follow_symlinks=False)
    private = _dir(host, private_dir(host, b).name)
    return folder, session, private


def environment(host: Host, b: Browser, session: Path) -> dict[str, str]:
    """The environment without the sandbox: the host's (no AppImage variables), with every folder a
    desktop library writes to pointed inside the RAM disk."""
    return host_env(host.environ, **{k: str(session / v) for k, v in sandbox.SESSION_DIRS.items()},
                    **browser_env(host, b))


def sandboxed_before(host: Host, b: Browser) -> bool:
    return (private_dir(host, b) / "sandboxed").exists()


# ------------------------------------------------------------------ Tor Browser's bridges

BRIDGE_MODES = ("none", "obfs4", "snowflake", "meek", "custom")
BRIDGE_LINE = re.compile(r"^(?:(obfs4|webtunnel|snowflake|meek_lite|conjure)\s+)?"
                         r"(\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}"
                         r"(?:\s+[0-9A-Fa-f]{40})?(?:\s+[A-Za-z0-9_-]+=[!-~]+)*$")
PT_CONFIG = "chrome/toolkit/content/global/pt_config.json"


def builtin_bridges(host: Host, b: Browser) -> dict[str, list[str]]:
    """Tor Browser's built-in bridges, from its own pt_config.json (in omni.ja): obfs4, snowflake,
    meek. Each line checked like one the user pastes."""
    import zipfile
    try:
        with zipfile.ZipFile(root(host) / b.folder / "Browser/omni.ja") as z:
            data = json.loads(z.read(PT_CONFIG))
        found = data["bridges"]
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        return {}
    return {k: [ln for ln in v if isinstance(ln, str) and BRIDGE_LINE.match(ln)]
            for k, v in found.items() if k in BRIDGE_MODES and isinstance(v, list)}


def parse_bridges(text: str) -> list[str]:
    """Bridge lines as bridges.torproject.org gives them (a "Bridge " in front is fine); raises on
    anything else."""
    out = []
    for raw in text.splitlines():
        line = re.sub(r"^\s*Bridge\s+", "", raw.strip(), flags=re.I)
        if not line:
            continue
        if len(line) > 2000 or not BRIDGE_LINE.match(line):
            raise BrowserError(f"\"{line[:60]}\" isn't a bridge line. They look like: obfs4 192.0.2.1:443 "
                               "1234…ABCD cert=… iat-mode=0")
        out.append(line)
    if len(out) > 50:
        raise BrowserError("That is more than 50 bridges: a few are enough.")
    return out


def bridges(host: Host, b: Browser) -> dict:
    """The bridges chosen, as set_bridges kept them: custom lines checked again here (parse_bridges), as they
    were when they were kept, before anything writes them into a torrc."""
    try:
        d = json.loads(_read_small(private_dir(host, b) / "bridges.json"))
        if d.get("mode") in BRIDGE_MODES and isinstance(d.get("lines", []), list):
            lines = [str(x) for x in d.get("lines", [])]
            return {"mode": d["mode"], "lines": parse_bridges("\n".join(lines)) if d["mode"] == "custom" else []}
    except (ValueError, AttributeError, BrowserError):
        pass
    return {"mode": "none", "lines": []}


def set_bridges(host: Host, b: Browser, mode: str, text: str = "") -> None:
    """The bridges Tor Browser's tor uses from its next start, kept in the RAM disk (gone when it
    closes)."""
    if not b.tor or mode not in BRIDGE_MODES:
        raise BrowserError("Choose how Tor Browser connects.")
    lines = parse_bridges(text) if mode == "custom" else []
    if mode == "custom" and not lines:
        raise BrowserError("Paste at least one bridge line.")
    if mode not in ("none", "custom") and not builtin_bridges(host, b).get(mode):
        raise BrowserError(f"This Tor Browser has no built-in {mode} bridges.")
    private = _dir(host, private_dir(host, b).name)
    fd = os.open(private / "bridges.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"mode": mode, "lines": lines}, f)


def bridges_view(host: Host, b: Browser) -> dict:
    cur = bridges(host, b)
    return {"mode": cur["mode"], "count": len(cur["lines"]), "builtin": sorted(builtin_bridges(host, b))}


def torrc(host: Host, b: Browser) -> str:
    cur = bridges(host, b)
    lines = cur["lines"] if cur["mode"] == "custom" else builtin_bridges(host, b).get(cur["mode"], [])
    if cur["mode"] != "none" and not lines:
        raise BrowserError("The bridges chosen for Tor Browser aren't there any more: choose them again.")
    head = "# Written by DA Privacy Kit for this session of Tor Browser in ~/TempBrowser.\n"
    return head + ("UseBridges 1\n" + "".join(f"Bridge {ln}\n" for ln in lines) if lines else "")


def tor_status(host: Host, b: Browser) -> dict | None:
    """tor's connection, as the gate writes it (checked: it comes from inside a sandbox)."""
    try:
        d = json.loads(_read_small(private_dir(host, b) / "tor/status.json", 20000))
    except ValueError:
        return None
    if not isinstance(d, dict) or d.get("state") not in ("starting", "connecting", "connected", "failed", "stopped"):
        return None
    pct = d.get("progress")
    return {"state": d["state"], "progress": max(0, min(100, pct)) if isinstance(pct, int) else 0,
            "summary": str(d.get("summary", ""))[:200], "problem": str(d.get("problem", ""))[:300]}


# ------------------------------------------------------------------ running it

_LAUNCHED: dict[str, object] = {}                    # browser id -> its process, once it has started
_STARTING: set[str] = set()                           # browser ids a start is under way for
_LOCK = threading.Lock()

# What the start log holds when the sandbox, the gate or tor stopped before the browser ran: bubblewrap's own
# errors, the Landlock and keyring wrappers' (sys.exit), the gate's and Xephyr's (_start_nested). The browser's own
# output never reaches the log (QUIET sends it to /dev/null), so one of these says no website ever reached this copy.
NEVER_RAN = ("bwrap: ", "Landlock could not be applied", "A keyring of its own could not be made",
             "tor couldn't be started", "tor didn't start", "pasta: ")


def _file_text(log: Path) -> str:
    try:
        return log.read_bytes()[-4000:].decode("utf-8", "replace")
    except OSError:
        return ""


def _log_reason(text: str, rc: int) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not sandbox.quiet_line(ln)]
    return "; ".join(lines[-3:])[:500] if lines else f"it stopped at once (exit status {rc})"


def _ended(rc: int) -> str:
    """How a browser that had started ended, by its exit status alone."""
    if rc in (137, -9):
        return f"it was killed (exit status {rc}), as happens when the computer runs out of memory"
    return f"it stopped (exit status {rc})"


def launch_problem(b: Browser) -> str | None:
    """Why the browser started last stopped with an error, once (then forgotten); None while it runs
    or after a clean exit. Collects its exit status, so nothing is left behind. By the exit status alone: once it
    has run, the start log could hold anything a website that took the browser over wrote into it (the sandbox's
    descriptor of it is in its reach), which the page would then show as the app's own words."""
    with _LOCK:
        proc = _LAUNCHED.get(b.id)
        if proc is None:
            return None
        rc = proc.poll()
        if rc is None:
            return None
        del _LAUNCHED[b.id]
    return None if rc == 0 else f"{b.name} stopped with an error: {_ended(rc)}"


def _never_ran(text: str) -> bool:
    """Whether the start log says the sandbox stopped before the browser ran (NEVER_RAN)."""
    return any(any(mark in ln for mark in NEVER_RAN) for ln in text.splitlines() if not sandbox.quiet_line(ln))


def _watch(b: Browser, proc, log: int) -> None:
    """A start is watched for START_WAIT seconds: a sandbox that couldn't be set up, tor that
    couldn't start, Landlock refused, say why at once, from the start log (`log`, a memory file); after that,
    status() says it, by the exit status."""
    if not hasattr(proc, "poll"):
        return                                           # a test's stand-in
    deadline = time.monotonic() + START_WAIT
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    rc = proc.poll()
    if rc not in (None, 0):
        raise BrowserError(f"{b.name} couldn't start: {_log_reason(sandbox.read_log(log), rc)}")
    if rc is None:
        with _LOCK:
            _LAUNCHED[b.id] = proc


EXPECTED = ("network", "lan_blocked", "wayland_context")   # what the panel showed that a start must not fall short of


def _weaker(how: dict, expect: dict | None) -> str | None:
    """What a start would do that is weaker than the panel showed (`expect`: the panel's EXPECTED values, from
    sandbox_status: pasta or its fence gone since, or the compositor refusing a marked socket now), or None."""
    if not expect:
        return None
    rank = {"tor": 2, "private": 1, "shared": 0}
    if "network" in expect and rank.get(how["network"], 0) < rank.get(expect["network"], 0):
        return {"private": "a network of its own", "tor": "no network but Tor's"}.get(expect["network"], "its network")
    if expect.get("lan_blocked") and not how["lan_blocked"]:
        return "the local network fenced off"
    if expect.get("wayland_context") is True and how.get("wayland_context") is not True:
        return "a connection the desktop marks as a sandbox's"
    return None


def start(host: Host, b: Browser, spawn: Callable = subprocess.Popen, sandboxed: bool = True,
          with_sound: bool = False, net=None, nested: bool = False, expect: dict | None = None,
          gpu: bool = False) -> dict:
    """Starts the browser: in the sandbox when asked and bubblewrap can run here, else as it is. `gpu`: the
    sandbox gets the graphics card (sandbox.gpu) when the user allowed it.
    `net` (an online.Net, or what makes one) is used only for a copy set up more than a day ago, to
    check for a newer version first (check_before_start). `expect`: what the panel showed of the sandbox
    (EXPECTED): a start that would be weaker than that refuses, so what the user saw is what they get.
    Returns {"sandboxed", "display", "landlock", "network", "lan_blocked", "wayland_context", "nested", "gpu"}.
    One start at a time per browser."""
    with _LOCK:
        if b.id in _STARTING:
            raise BrowserError(f"{b.name} is already starting.")
        _STARTING.add(b.id)
    busy = owner.hold(host, f"browser-{b.id}")          # and in no other copy of the app: its start would empty
    if busy is None:                                    # the session folder this one's browser runs in
        with _LOCK:
            _STARTING.discard(b.id)
        raise BrowserError(f"{b.name} is being set up or started in another window of this app.")
    try:
        return _start(host, b, spawn, sandboxed, with_sound, net, nested, expect, gpu)
    finally:
        owner.let_go(busy)
        with _LOCK:
            _STARTING.discard(b.id)


def _start(host: Host, b: Browser, spawn: Callable, sandboxed: bool, with_sound: bool, net, nested: bool,
           expect: dict | None, gpu: bool = False) -> dict:
    problem = ready(host)
    if problem:
        raise BrowserError(problem)
    script = root(host) / b.folder / b.start
    try:
        st = os.stat(script, follow_symlinks=False)
    except OSError:
        raise BrowserError(f"{b.name} isn't unpacked in ~/{DISK}.") from None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != host.uid:
        raise BrowserError(f"{b.name} isn't unpacked in ~/{DISK}.")
    if running(host, b):
        raise BrowserError(f"{b.name} is already running.")
    check_before_start(host, b, net)                    # set up more than a day ago: a newer version?
    if not sandboxed and sandboxed_before(host, b):
        raise BrowserError(f"This copy of {b.name} has run in the sandbox, so its folder may hold something a website "
                           f"left there, which would then run outside it. To start it without the sandbox, close "
                           f"~/{DISK} (that overwrites it) and set {b.name} up again.")
    folder, session, private = prepare(host, b)
    through_stdin = False                               # the Wayland sync pipe as stdin (under pasta)
    if sandboxed:
        sb = sandbox_status(host)
        if not sb["available"]:
            raise BrowserError(f"The sandbox can't be used here: {sb['why']} Untick \"Run it in a sandbox\" to start "
                               "it without one.")
        if b.tor and not sb["python"]:
            raise BrowserError(f"Tor Browser's sandbox needs the computer's python3 ({sandbox.PYTHON}), which isn't "
                               "there. Install python3, or untick \"Run it in a sandbox\".")
        landlock = sb["landlock"]
        disp = sandbox.display(host, private, landlock)
        if disp.kind == "none":
            raise BrowserError(disp.note)
        xephyr, sync = None, None
        try:                                            # what is made from here on is undone if no spawn comes
            if nested and disp.kind == "x11":
                disp, xephyr = _start_nested(host, b, private, disp, spawn)
            lay = sandbox.Layout(b.folder, folder, session, private, b.start, b.writable, b.hidden,
                                 tuple(browser_env(host, b).items()))
            # not under Xephyr: it has no hardware OpenGL, so the browser draws in software there anyway (tested)
            devices = tuple(sandbox.gpu(host)) if gpu and xephyr is None else ()
            context = None
            compositor = _socket_at(host, disp.binds[0][0]) if disp.kind == "wayland" else None
            if compositor:
                try:
                    sync = wayland.sandbox_socket(compositor, private / "wayland-0", b.id)
                    context = sync is not None
                except (OSError, wayland.WaylandError) as e:
                    context = f"the compositor's own socket is used: {e}"
                if sync is not None:
                    disp.binds[0] = (str(private / "wayland-0"), disp.binds[0][1])
            if b.tor:
                if disp.network:
                    raise BrowserError(f"{disp.note}, which Tor Browser's sandbox can't reach: it has no network but "
                                       "Tor's. Untick \"Run it in a sandbox\" to use it here.")
                tor_dir = _dir(host, f"{private.name}/tor")
                os.chmod(tor_dir, 0o700)
                fd = os.open(tor_dir / "torrc", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(torrc(host, b))
                (tor_dir / "status.json").unlink(missing_ok=True)
                etc = sandbox.identity_files(private / "etc", None)
                gate = (Path(__file__).with_name("torgate.py")).read_text()
                argv = sandbox.tor_argv(host, lay, tor_dir, disp, with_sound, landlock, etc, gate, sync, devices)
                network = "tor"
            else:
                pasta = sandbox.program(host, sandbox.PASTA) if sb["pasta"]["available"] and not disp.network else None
                etc = sandbox.identity_files(private / "etc", sandbox.FORWARD_RESOLV if pasta
                                             else sandbox.resolver(host))
                # pasta passes its command only stdin, stdout and stderr: the pipe goes in as stdin, held as --sync-fd 0
                argv = sandbox.browser_argv(host, lay, disp, with_sound, landlock, etc, pasta, sb["pasta"]["lan_blocked"],
                                            0 if pasta and sync is not None else sync, devices, stay=sb["python"])
                through_stdin = bool(pasta) and sync is not None
                network = "private" if pasta else "shared"
            how = {"sandboxed": True, "display": disp.kind, "landlock": landlock, "network": network,
                   "lan_blocked": network == "tor" or (network == "private" and sb["pasta"]["lan_blocked"]),
                   "wayland_context": context, "nested": xephyr is not None, "gpu": bool(devices)}
            short = _weaker(how, expect)
            if short:
                raise BrowserError(f"{b.name} wasn't started: it would run without {short}, which the panel said it "
                                   "would have. Open the panel again to see what changed, then start it from there.")
            marked_before = sandboxed_before(host, b)
            (private / "sandboxed").touch()
            # the app's own directory, never the RAM disk; none of the app's environment (sandbox.SPAWN_ENV)
            cmd, cwd, env = argv, "/", dict(sandbox.SPAWN_ENV)
        except BaseException:
            _abort(xephyr, sync)
            raise
    else:
        cmd, cwd, env = [str(script), "--detach"], str(script.parent), environment(host, b, session)
        sync, xephyr = None, None
        how = {"sandboxed": False, "display": session_display(host), "landlock": False, "network": "shared",
               "lan_blocked": False, "gpu": True}
    cmd = sandbox.fresh_keyring(host, cmd)              # nothing it starts reaches the session's kernel keyring
    log = sandbox.log_file("start-log")                 # the sandbox's own errors: a memory file, not a path
    try:
        try:
            if through_stdin:
                proc = spawn(cmd, cwd=cwd, env=env, stdin=sync, stdout=subprocess.DEVNULL, stderr=log,
                             start_new_session=True)
            else:
                proc = spawn(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
                             start_new_session=True, pass_fds=(sync,) if sync is not None else ())
        except OSError:
            _abort(xephyr, sync)
            sync = None
            if sandboxed and not marked_before:         # it never started: no website ever reached this copy
                (private / "sandboxed").unlink(missing_ok=True)
            raise
        finally:
            if sync is not None:
                os.close(sync)                          # bubblewrap holds it now, for as long as the sandbox runs
        try:
            _watch(b, proc, log)
        except BrowserError:
            _abort(xephyr, None)                        # it would wait for a browser that never comes
            # the mark stays unless the log says the sandbox stopped before the browser ran: a browser that ran, even
            # briefly, could have been reached (or, taken over, stopped itself with an error to shed the mark)
            if sandboxed and not marked_before and _never_ran(sandbox.read_log(log)):
                (private / "sandboxed").unlink(missing_ok=True)
            raise
    finally:
        os.close(log)                                   # read only during the start's watch (launch_problem)
    return how


def _abort(xephyr, sync: int | None) -> None:
    """Undoes what a start made before it could spawn: Xephyr (it would wait for a browser that never comes)
    and the compositor's listener (held by the pipe until it is closed)."""
    if xephyr is not None and hasattr(xephyr, "kill"):
        xephyr.kill()
    if sync is not None:
        os.close(sync)


NESTED_WAIT = 5.0                       # seconds Xephyr has to open its socket


def _start_nested(host: Host, b: Browser, private: Path, disp, spawn: Callable):
    """Xephyr in its own sandbox (sandbox.nested), started and waited for: (the display the browser then
    gets, Xephyr's process). Raises when it can't be used here, or didn't open its socket."""
    if not sandbox.program(host, sandbox.XEPHYR):
        raise BrowserError("A display of its own needs Xephyr, which isn't installed"
                           + (f" ({_install_command(host, 'Xephyr')})." if _install_command(host, "Xephyr") else ".")
                           + " Untick it to start the browser on this display.")
    nest = sandbox.nested(host, private, sandbox.XEPHYR_TITLE.format(name=b.name), sandbox.screen_size(host))
    if nest is None:
        raise BrowserError("A display of its own works on this computer's own X11 display only. Untick it.")
    log = private / "xephyr.log"
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        proc = spawn(sandbox.fresh_keyring(host, nest.argv), cwd="/", env=host_env(host.environ), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=fd, start_new_session=True)
    finally:
        os.close(fd)
    if not hasattr(proc, "poll"):
        return nest.display, proc                       # a test's stand-in
    deadline = time.monotonic() + NESTED_WAIT
    while time.monotonic() < deadline:
        try:
            if stat.S_ISSOCK(os.stat(nest.socket, follow_symlinks=False).st_mode):
                return nest.display, proc
        except OSError:
            pass
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if proc.poll() is None:
        proc.kill()
    raise BrowserError(f"Xephyr didn't open its display: {_log_reason(_file_text(log), proc.poll() or 0)}")


# what a browser's sandbox runs around it, by process name (comm, at most 15 characters): its ancestors up to the
# app, and what they start beside it (tor, its pluggable transports)
SANDBOX_PROCS = {"bwrap", "python3", "sh", "bash", "env", "pasta", "pasta.avx2", "start-tor-brows", "start-mullvad-b",
                 "tor", "lyrebird", "conjure-client", "snowflake-clien"}     # bash, env: a start script run through env


def _procs(host: Host) -> dict[int, tuple[int, str]]:
    """This user's processes: pid -> (parent's pid, name)."""
    from ..checks._util import children
    procs: dict[int, tuple[int, str]] = {}
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit():
            continue
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue
            status = (p / "status").read_text(errors="replace")
            ppid = int(re.search(r"^PPid:\s*(\d+)", status, re.M).group(1))
            procs[int(p.name)] = (ppid, (p / "comm").read_text().strip())
        except (OSError, AttributeError, ValueError):
            continue
    return procs


def _with_descendants(procs: dict[int, tuple[int, str]], roots: set[int]) -> set[int]:
    tree, grew = set(roots), True
    while grew:
        grew = False
        for pid, (ppid, _) in procs.items():
            if ppid in tree and pid not in tree:
                tree.add(pid)
                grew = True
    return tree


def _browser_tree(host: Host, procs: dict[int, tuple[int, str]] | None = None) -> set[int]:
    """The processes of every running browser and of the sandbox around it: the browser's own (running()),
    their parents up through the sandbox (SANDBOX_PROCS), never this app itself (its python3 started the
    sandbox: its other children, a viewer, aren't the browser's), and everything those started. Another
    program of the user's with the same name (a python3 script, a shell) isn't in it."""
    procs = _procs(host) if procs is None else procs
    me = os.getpid() if host.root == Path("/") else None
    tree = {pid for b in BROWSERS.values() for pid in running(host, b)}
    for pid in list(tree):
        parent = procs.get(pid, (0, ""))[0]
        while parent in procs and procs[parent][1] in SANDBOX_PROCS and parent not in tree and parent != me:
            tree.add(parent)
            parent = procs[parent][0]
    return _with_descendants(procs, tree)


def disk_users(host: Host, path: Path) -> list[str]:
    """Programs using the RAM disk at `path`: a running browser named as the browser (its sandbox, tor and
    content processes with it), a viewer View offline… started as that viewer, then every other program by
    its own name."""
    from . import viewer
    held = ramdisk.holders_on_device(host, path)
    path_held = ramdisk.users_of(host, path) if not held else []
    procs = _procs(host) if held else {}
    tree = _browser_tree(host, procs) if held else set()
    named = [b.name for b in BROWSERS.values() if running(host, b)]
    for pid, app in viewer.launched().items():
        vtree = _with_descendants(procs, {pid}) - tree
        if vtree & set(held):
            named.append(f"{app} (opened by View offline…)")
            tree |= vtree
    return named + sorted({name for pid, name in held.items() if pid not in tree} | set(path_held))


def default_outbox(host: Host, b: Browser) -> bool:
    """The TempOutbox, made with the browser (on by default) where mat2 can clean and the permanent Outbox
    isn't set up (then the page says to use that one). Whether it was made."""
    if not host.runner.which("mat2") or transfer.permanent_outbox(host):
        return False
    try:
        transfer.make_outbox(host, b.name)
    except (transfer.TransferError, OSError):
        return False
    return True


def run_outboxes(host: Host) -> None:
    """What the app's watcher does every few seconds: each set-up browser's TempOutbox emptied into its
    To upload, while ~/TempBrowser is open, by the copy of the app that owns it (owner.py): two copies' watchers
    would clean one file twice."""
    if not ramdisk.mounted(host, DISK) or not owner.owns(host, DISK, root(host)):
        return
    with transfer.OUTBOX_LOCK:
        for b in BROWSERS.values():
            if installed(host, b):
                transfer.run_outbox(host, b.folder, b.name)


def wipe_disk(path: Path) -> "ramdisk.Wipe":
    """~/TempBrowser's files overwritten and deleted, once the TempOutboxes aren't being emptied. Whoever owned it
    owns nothing from here on (its mark goes first, so it isn't counted among the user's files)."""
    owner.unmark(path)
    with transfer.OUTBOX_LOCK:
        w = ramdisk.wipe(path)
    transfer.forget_recent()
    return w


def close_disk(host: Host, helper: Callable[[], object]) -> str:
    """When the app quits: ~/TempBrowser closed like the RAM disk tool's (every file overwritten and
    deleted as the user, then the helper unmounts it, asking for administrator access if it has to), by the
    copy of the app that opened it or took it over (owner.py), never by another copy quitting.
    Returns what happened, for the terminal: "" when it wasn't open or isn't this copy's."""
    rd = ramdisk.status(host, DISK)
    if not rd.open or not owner.owns(host, DISK, rd.path):
        return ""
    users = disk_users(host, rd.path)
    if users:
        return (f"~/{DISK} stays open: {', '.join(users)} still uses it. Close it in the app's "
                "Tools panel later, or restart the computer.")
    w = wipe_disk(rd.path)
    h = helper()
    if h is None:
        return f"~/{DISK}'s files were overwritten and deleted, but it couldn't be unmounted without administrator access."
    h.call("ramdisk_close", {"name": DISK})
    owner.release(host, DISK)
    return f"~/{DISK} was closed: {w.files} file{'' if w.files == 1 else 's'} overwritten and deleted."
