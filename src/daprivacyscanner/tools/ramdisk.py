"""The RAM disk (docs/TECHNICAL.md, Tools): ~/RAMDisk, a folder in memory opened when the user wants one and
closed from the app, which overwrites what is in it and unmounts it. The browser in memory has one of
its own, ~/TempBrowser (BROWSER), opened and closed the same way, so closing one never touches the
other; the app also closes that one when it quits.

Opening and unmounting need root (the helper's ramdisk_open and ramdisk_close). Everything else is
done here, as the user: the status, the check that no program is using it (never closing a program:
"Close X first"), and the overwrite. Overwriting is what rule 8 allows here and nowhere else on a
filesystem: a tmpfs's files live in memory pages that writing replaces in place, not on a disk that
moves writes elsewhere. It covers the files' contents, on the RAM disk's own device only, never
through a link. It can't reach copies made elsewhere (programs that read a file, thumbnails, the
clipboard), file names, or pages swapped to disk before noswap existed; the page says so."""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ..host import Host

NAME = "RAMDisk"
BROWSER = "TempBrowser"                 # the browser in memory's (tools/browser.py)
NAMES = (NAME, BROWSER)                 # the helper knows these two, and no other
DEFAULT_MB = 1024
CHUNK = 1024 * 1024
ZEROS = bytes(CHUNK)
MAX_FILES = 100_000


def folder(host: Host, name: str = NAME) -> Path:
    return host.home / name


@dataclass
class Status:
    path: Path
    open: bool
    size: str = ""                  # the mount's size= option ("1024M")
    noexec: bool = True
    noswap: bool = False
    used: int = 0                   # bytes in use, and the total
    total: int = 0
    files: int = 0
    other: str = ""                 # something else is mounted there
    leftover: bool = False          # closed, and its empty folder is still there (after a reboot)
    notes: list[str] = field(default_factory=list)

    def to_dict(self, home: Path) -> dict:
        return {"path": "~/" + self.path.name, "name": self.path.name, "full_path": str(self.path), "open": self.open, "size": self.size,
                "noexec": self.noexec, "noswap": self.noswap, "used": self.used, "total": self.total,
                "files": self.files, "other": self.other, "leftover": self.leftover, "notes": self.notes}


def _mounts(host: Host) -> list[list[str]]:
    try:
        text = host.read_sys("/proc/mounts") or ""
    except Exception:  # noqa: BLE001 - no mount table: nothing is open
        text = ""
    return [ln.split() for ln in text.splitlines() if len(ln.split()) > 3]


def _memory_mb(host: Host) -> int | None:
    m = re.search(r"^MemTotal:\s+(\d+) kB", host.read_sys("/proc/meminfo") or "", re.M)
    return int(m.group(1)) // 1024 if m else None


def max_mb(host: Host) -> int:
    mem = _memory_mb(host)
    return min(65536, mem // 2) if mem else 4096


def commands(host: Host, name: str = NAME, size_mb: int = DEFAULT_MB) -> dict[str, list[str]]:
    """What opening and closing run as root, as the commands that do the same (the helper mounts and
    unmounts through system calls, and answers with these: "ran"), for the page to show before the user
    opens or closes it. "open" with programs not allowed to run, "open_exec" with them allowed; "close"
    after every file has been overwritten and deleted as the user."""
    import pwd
    from .. import helper
    from ..fix import shell
    path = os.path.realpath(folder(host, name))
    try:
        gid = pwd.getpwuid(host.uid).pw_gid
    except KeyError:
        gid = host.uid
    noswap = helper._kernel_has_noswap()

    def opening(noexec: bool) -> list[str]:
        import json
        import stat as st_
        options = ",".join(["nosuid", "nodev", *(["noexec"] if noexec else []), f"size={size_mb}M", "mode=0700",
                            f"uid={host.uid}", f"gid={gid}", *(["noswap"] if noswap else [])])
        exists = os.path.lexists(path)
        made = [] if exists else [shell(["install", "-d", "-m", "700", "-o", str(host.uid), "-g", str(gid), path])]
        try:
            mode = st_.S_IMODE(os.lstat(path).st_mode) if exists else None
        except OSError:
            mode = None
        # what to put back when it is closed, kept on the folder itself (the helper's _remember_folder)
        remember = json.dumps({"created": not exists, "folder_mode": mode})
        return made + [shell(["setfattr", "-n", helper.RAMDISK_XATTR, "-v", remember, path]), shell(["chmod", "500", path]),
                       shell(["mount", "-t", "tmpfs", "-o", options, "tmpfs", path])]
    return {"open": opening(True), "open_exec": opening(False), "close": [shell(["umount", path])]}


def _here(host: Host, path: Path) -> list[list[str]]:
    real = os.path.realpath(path)
    root = os.path.realpath(host.root)
    if root != "/" and real.startswith(root + "/"):          # a fixture tree: the path as the system sees it
        real = real[len(root):]
    return [f for f in _mounts(host) if f[1] in (real, str(path))]


def mounted(host: Host, name: str = NAME) -> bool:
    """Whether it is open (a tmpfs there), from the mount table alone: cheap enough to ask every few seconds."""
    here = _here(host, folder(host, name))
    return bool(here) and here[-1][2] == "tmpfs"


def status(host: Host, name: str = NAME) -> Status:
    path = folder(host, name)
    here = _here(host, path)
    st = Status(path, False)
    if here:
        last = here[-1]
        if last[2] != "tmpfs":
            st.other = last[2]
            return st
        opts = dict((o.split("=", 1) + [""])[:2] for o in last[3].split(","))
        st.open, st.size, st.noexec, st.noswap = True, opts.get("size", ""), "noexec" in opts, "noswap" in opts
        try:
            v = os.statvfs(path)
            st.total, st.used = v.f_blocks * v.f_frsize, (v.f_blocks - v.f_bfree) * v.f_frsize
        except OSError:
            pass
        st.files = sum(len(fs) for _, _, fs in os.walk(path))
    else:
        try:
            st.leftover = path.is_dir() and not path.is_symlink() and not any(path.iterdir()) and left_by_app(path)
        except OSError:
            st.leftover = False
    st.notes = memory_notes(host, st)
    return st


def left_by_app(path: Path) -> bool:
    """Whether a closed RAM disk's folder is the one an open left behind (a restart ended the mount): it carries the
    helper's record of the open (helper.RAMDISK_XATTR), or, on a filesystem without extended attributes, the mode
    0500 the open gives it. An empty folder of the user's own is neither."""
    from ..helper import RAMDISK_XATTR
    try:
        os.getxattr(path, RAMDISK_XATTR, follow_symlinks=False)
        return True
    except OSError:
        pass
    try:
        return stat.S_IMODE(os.lstat(path).st_mode) == 0o500
    except OSError:
        return False


def hibernation_possible(host: Host) -> bool:
    """The kernel can hibernate (disk in /sys/power/state, not disabled) and has swap on a disk to write the image to:
    all of memory, a RAM disk with noswap included, would go there."""
    try:
        state = host.read_sys("/sys/power/state") or ""
        disk = host.read_sys("/sys/power/disk") or ""
        swaps = host.read_sys("/proc/swaps") or ""
    except Exception:  # noqa: BLE001
        return False
    disk_swap = [ln.split()[0] for ln in swaps.splitlines()[1:] if ln.split() and not ln.startswith("/dev/zram")]
    return "disk" in state.split() and bool(disk_swap) and "[disabled]" not in disk


def memory_notes(host: Host, st: Status) -> list[str]:
    """What the RAM disk can't protect from, on this machine."""
    notes = []
    swaps = [ln.split()[0] for ln in (host.read_sys("/proc/swaps") or "").splitlines()[1:] if ln.split()]
    disk_swap = [s for s in swaps if not s.startswith("/dev/zram")]
    if st.open and not st.noswap and disk_swap:
        notes.append("This kernel can't keep it out of swap (noswap needs Linux 6.4), and there is swap on disk "
                     f"({', '.join(disk_swap)}): under memory pressure, parts of it can be written there and stay "
                     "after it is closed.")
    if hibernation_possible(host):
        notes.append("Hibernating writes all of memory, this folder included, to the disk: close it before "
                     "hibernating, or turn hibernation off.")
    cmdline = host.read_sys("/proc/cmdline") or ""
    if re.search(r"\binit_on_free=1\b", cmdline):
        notes.append("The kernel clears memory as it is freed (init_on_free=1), so even pages the overwrite can't "
                     "reach are cleared when it is closed.")
    return notes


# ------------------------------------------------------------------ closing

def users_of(host: Host, path: Path) -> list[str]:
    """Names of this user's programs holding a file or folder in it open, mapped or as their
    working directory (like fuser): by path, and by device, since a sandboxed program sees it
    at another path (the browser's sandbox puts it at /home/user/…) and /proc shows that one."""
    from ..checks._util import open_files
    root = os.path.realpath(path).rstrip("/") + "/"
    names = {name for name, paths in open_files(host) if any(p.startswith(root) or p == root[:-1] for p in paths)}
    return sorted(names | on_device(host, path))


def on_device(host: Host, path: Path) -> set[str]:
    """Names of this user's programs with a working directory, an open file or a mapped file on
    `path`'s filesystem (a RAM disk is a filesystem of its own)."""
    return set(holders_on_device(host, path).values())


def holders_on_device(host: Host, path: Path) -> dict[int, str]:
    """As on_device, by process: pid -> name."""
    from ..checks._util import children
    try:
        dev = os.stat(path, follow_symlinks=False).st_dev
    except OSError:
        return {}
    mapped = f"{os.major(dev):02x}:{os.minor(dev):02x}"
    me = str(os.getpid()) if host.root == Path("/") else None
    out: dict[int, str] = {}
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit() or p.name == me:
            continue
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue
            name = (p / "comm").read_text().strip()
        except OSError:
            continue
        found = False
        for link in [p / "cwd", *children(p / "fd")]:
            try:
                if os.stat(link).st_dev == dev:
                    found = True
                    break
            except OSError:
                continue
        if not found:
            try:
                found = any(len(f := ln.split(None, 5)) == 6 and f[3] == mapped and f[5].startswith("/")
                            for ln in (p / "maps").read_text(errors="replace").splitlines())
            except OSError:
                pass
        if found:
            out[int(p.name)] = name
    return out


@dataclass
class Wipe:
    files: int = 0
    bytes: int = 0
    failed: list[str] = field(default_factory=list)      # names that couldn't be overwritten


def _overwrite(fd: int, size: int) -> int:
    """Zeros over every data region of the file (holes have nothing to overwrite), in place."""
    written, pos = 0, 0
    while pos < size:
        try:
            start = os.lseek(fd, pos, os.SEEK_DATA)
        except OSError:
            break                                         # ENXIO: no more data
        end = os.lseek(fd, start, os.SEEK_HOLE)
        os.lseek(fd, start, os.SEEK_SET)
        left = end - start
        while left > 0:
            n = os.write(fd, ZEROS[:min(CHUNK, left)])
            left -= n
            written += n
        pos = end
    os.fsync(fd)
    return written


def wipe(path: Path, device: int | None = None, delete: bool = True) -> Wipe:
    """Overwrite the contents of every regular file under `path` with zeros, then delete everything
    in it. Only on the folder's own device (the RAM disk), never through a link; folders and files
    the user made unreadable or read-only are made writable first (they are the user's)."""
    root = Path(path)
    dev = os.stat(root, follow_symlinks=False).st_dev if device is None else device
    w = Wipe()
    for top, dirs, files, dfd in os.fwalk(root, follow_symlinks=False):
        for d in list(dirs):
            try:
                st = os.stat(d, dir_fd=dfd, follow_symlinks=False)
                if st.st_dev != dev or not stat.S_ISDIR(st.st_mode):
                    dirs.remove(d)                        # a link, or another filesystem mounted inside: not ours
                elif stat.S_IMODE(st.st_mode) & 0o700 != 0o700:
                    os.chmod(d, stat.S_IMODE(st.st_mode) | 0o700, dir_fd=dfd)
            except OSError:
                dirs.remove(d)
        for f in files:
            if w.files >= MAX_FILES:
                break
            try:
                st = os.stat(f, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_dev != dev:
                continue                                  # links, sockets, pipes: nothing to overwrite
            try:
                if not st.st_mode & stat.S_IWUSR:
                    os.chmod(f, stat.S_IMODE(st.st_mode) | stat.S_IWUSR, dir_fd=dfd)
                fd = os.open(f, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            except OSError:
                w.failed.append(os.path.join(os.path.relpath(top, root), f))
                continue
            try:
                if os.fstat(fd).st_dev == dev and stat.S_ISREG(os.fstat(fd).st_mode):
                    w.bytes += _overwrite(fd, os.fstat(fd).st_size)
                    w.files += 1
            except OSError:
                w.failed.append(os.path.join(os.path.relpath(top, root), f))
            finally:
                os.close(fd)
    for child in list(root.iterdir()) if delete else []:
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        except OSError:
            pass
    return w
