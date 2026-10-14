"""The TRIM test (docs/TECHNICAL.md, Tools): once deleted data on this SSD has been trimmed, can it still be
read back from the drive?

The app writes test files through the filesystem, as the user, filled with records only this run
can recognise (helper.trim_record), and file names that carry the run's tag. The helper then reads
the filesystem's own block device from start to end (read-only, straight from the drive) and counts
them: a baseline, which must find everything (or nothing later would mean anything), then the files
are deleted, the filesystem is trimmed (fstrim, as the weekly timer does), and the device is read
again, and once more a few minutes later when that can change the answer. Nothing is ever written to
the device itself, and what the helper reads never leaves it: only counts and offsets come back.

What a pass means: nobody can read the deleted test data back by plugging the drive in, even with
the encryption key, because the drive's controller has dropped it. Not what is on the flash chips
(chip-off, vendor diagnostic modes): those can still hold it, readable by someone who also has the
key, or by anyone if the disk isn't encrypted. Drives say what a trimmed block reads back as: zeros,
all 0xFF, a fixed but unspecified value (SATA DRAT), or nothing at all. The markers count as gone
whatever the fill; only a drive that reports zeros or 0xFF can show that TRIM itself failed when they
survive. The test also counts the deleted files' names: on ext4 they stay in the journal (and, under
kernels before Linux 5.13, in the folder's own block), out of TRIM's reach. Deleted file names (names.py) looks for the user's own.

The result is shown and can be copied; it is never kept (Tools keep nothing)."""

from __future__ import annotations

import base64
import fcntl
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import helper as H
from ..checks._util import Mount, children, mounts, read_text, systemctl_state
from ..host import Host
from ..paths import PathResolver
from ..storage import Drive, Layer, dev_name, device_stats, drive, layers, num, stop_reason

FOLDER = "trim-test"
SMALL = (512, 1024, 1536)                   # small enough for btrfs to keep inside its own records
DATA = (64 << 10,) * 8 + (63 << 20,) * 4
TEST_BYTES = sum(SMALL) + sum(DATA)
SPARE = 1 << 30                             # free space to leave beyond twice the test files
CALL_BYTES = 512 << 20                      # one trim_scan request
LATER = 180                                 # seconds after the trim before the second rescan
FSTRIM_TIMEOUT = 900
SCAN_TIMEOUT = 300
BATCH = 2048                                # records per write
NAME = re.compile(r"^[0-9a-f]{%d}$" % (H.TRIM_NAME_HEX + 4))
FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_ENCRYPT_FL, FS_NOCOMP_FL = 0x80086601, 0x40086602, 0x800, 0x400
BTRFS_IOC_SUBVOL_CREATE = 0x5000940E
# per terabyte, for one pass: a fast NVMe drive to a SATA one (the scan itself is Python's bytes.find)
MINUTES_PER_TB = (10, 35)


class Stopped(Exception):
    """The user stopped the test, or administrator access ended."""


@dataclass
class Target:
    mount: str
    fstype: str
    source: str
    options: str
    device: str = ""                        # the filesystem's own block device (name in /sys/class/block)
    layers: list[Layer] = field(default_factory=list)
    drives: list[Drive] = field(default_factory=list)
    folder: Path | None = None
    size: int = 0                           # the device's size
    free: int = 0
    blocked: str = ""                       # why it can't be tested
    unreadable: bool = False                # blocked because the helper can't read it at all (not for want of space)
    known: str = ""                         # the answer, already known without testing
    no_trim: str = ""                       # why TRIM can't reach the drive: "vm", "hdd" or "layer"
    notes: list[str] = field(default_factory=list)
    trim: str | None = None                 # continuous (discard), weekly (fstrim.timer), none; None: unknown
    guide: str = ""                         # the check whose guide turns TRIM on here (enc.trim_off)
    encrypted: bool = False
    vm: bool = False

    def to_dict(self, host: Host) -> dict:
        lo, hi = (round(self.size / 1e12 * m) for m in MINUTES_PER_TB)
        return {"mount": self.mount, "fstype": self.fstype, "size": self.size, "free": self.free,
                "folder": host.display(self.folder) if self.folder else None, "blocked": self.blocked,
                "known": self.known, "notes": self.notes, "trim": self.trim, "encrypted": self.encrypted,
                "vm": self.vm, "minutes": [max(1, lo), max(1, hi)], "environment": environment(self),
                "guide": self.guide}


# ------------------------------------------------------------------ where

def logical(host: Host, path: Path | str) -> str:
    """A path as the system sees it (fixture trees: without the fixture root)."""
    real = os.path.realpath(path)
    root = os.path.realpath(host.root)
    return real[len(root):] if root != "/" and real.startswith(root + "/") else real


def holding(table: list[Mount], path: str) -> Mount | None:
    best = None
    for m in table:
        if path == m.target or path.startswith(m.target.rstrip("/") + "/"):
            if best is None or len(m.target) >= len(best.target):
                best = m
    return best


# other disks offered besides / and the home's: mounted where people mount data disks, or wherever
# the user can write the top folder; never the boot partitions, snaps or system mounts
OTHER_PLACES = ("/mnt/", "/media/", "/run/media/", "/srv/", "/data")
NOT_OFFERED = ("/boot", "/efi", "/snap", "/var/snap", "/var/lib/snapd", "/proc", "/sys", "/dev", "/run/user")


def other_folder(host: Host, mount: str) -> Path:
    """The test folder on a disk other than / and the home's: at its top, hidden."""
    return host.sys_path(mount) / f".daprivacyscanner-{FOLDER}-{host.uid}"


def other_mounts(host: Host, table: list[Mount]) -> list[Mount]:
    """Disks besides / and the home's the user may want to test (a second SSD, an external one)."""
    out = []
    for m in table:
        if not m.source.startswith("/dev/") or m.source.startswith("/dev/loop") or m.target == "/":
            continue
        if any(m.target == p or m.target.startswith(p.rstrip("/") + "/") for p in NOT_OFFERED):
            continue
        if m.target.startswith(OTHER_PLACES) or m.target == "/data" or os.access(host.sys_path(m.target), os.W_OK):
            out.append(m)
    return out


def candidates(host: Host) -> list[Path]:
    """Where the test folder can be, in order: under the data folder (on the home's filesystem),
    or in /var/tmp (on /'s, when the home is elsewhere)."""
    return [PathResolver(host.home, host.environ).data_home / "daprivacyscanner" / FOLDER,
            host.sys_path("/var/tmp") / f"daprivacyscanner-{FOLDER}-{host.uid}"]


def _nearest(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def _btrfs_devices(host: Host, name: str) -> int:
    for fs in children(host.sys_path("/sys/fs/btrfs")):
        devs = [d.name for d in children(fs / "devices")]
        if name in devs:
            return len(devs)
    return 1


def _option(options: str, key: str) -> str | None:
    for o in options.split(","):
        k, _, v = o.partition("=")
        if k == key:
            return v
    return None


def targets(host: Host) -> list[Target]:
    """The filesystems that hold / and the home folder, then other disks (other_mounts), once
    each (by device), and whether each can be tested here."""
    table = mounts(host)
    out: list[Target] = []
    vm = host.run("systemd-detect-virt", "--vm").stdout.strip() not in ("", "none")
    main = [holding(table, w) for w in ("/", logical(host, host.home))]
    for m in main + other_mounts(host, table):
        if m is None or any(t.source == m.source for t in out):
            continue
        t = Target(m.target, m.fstype, m.source, m.options, vm=vm)
        out.append(t)
        if m.fstype == "ecryptfs":
            t.blocked = ("Your home folder is encrypted file by file (eCryptfs): everything in it, names included, "
                         "reaches the disk encrypted, so the test can't recognise its own files there. That also means "
                         "deleted files in it can't be read without your password.")
            t.unreadable = True
            continue
        if m.fstype not in H.TRIM_FSTYPES:
            t.blocked, t.unreadable = f"Only ext4 and btrfs can be tested; {m.target} is {m.fstype}.", True
            continue
        if not m.source.startswith("/dev/"):
            t.blocked, t.unreadable = f"{m.target} isn't on a disk device.", True
            continue
        t.device = dev_name(host, m.source)
        t.layers = layers(host, t.device)
        t.drives = [drive(host, x.name) for x in t.layers if x.kind == "disk"]
        t.encrypted = any(x.kind == "crypt" for x in t.layers)
        t.size = (num(read_text(host, host.sys_path(f"/sys/class/block/{t.device}/size"))) or 0) * 512
        if re.search(r"(^|,)discard(=async|=sync)?(,|$)", m.options):
            t.trim = "continuous"
        else:
            timer = systemctl_state(host, "is-enabled", "fstrim.timer")
            t.trim = "weekly" if timer == "enabled" else None if timer == "" else "none"
        if m.fstype == "btrfs" and _btrfs_devices(host, t.device) > 1:
            t.blocked, t.unreadable = "btrfs spread over more than one device can't be tested.", True
            continue
        if vm:
            t.known = ("This is a virtual machine. The test would only show what its virtual disk does, which depends "
                       "on how the host stores that disk (its image file and settings), not what any real drive does. "
                       "Run the app on the host to test the drive itself.")
            t.no_trim = "vm"
            continue
        if t.drives and all(d.rotational for d in t.drives):
            t.known = ("This is a hard disk. Hard disks have no TRIM: deleted data stays on them until something "
                       "overwrites it. Encryption is what protects it.")
            t.no_trim = "hdd"
            continue
        stuck = next((x for x in t.layers if x.discard_max == 0), None)
        if stuck is not None:
            t.known, t.no_trim = no_trim_text(t, stuck), "layer"
            if stuck.kind == "crypt" or stuck.kind == "md" and stuck.label in ("raid4", "raid5", "raid6"):
                t.guide = "enc.trim_off"
            continue
        if m in main:
            t.folder = next((c for c in candidates(host)
                             if (h := holding(table, logical(host, _nearest(c)))) is not None and h.source == m.source),
                            None)
        elif os.access(host.sys_path(m.target), os.W_OK | os.X_OK):
            t.folder = other_folder(host, m.target)
        if t.folder is None:
            t.blocked = (f"There's no folder you can write to on {m.target}." if m in main else
                         f"You can't create files at the top of {m.target}, so the test has nowhere to put its files.")
            continue
        try:
            v = os.statvfs(_nearest(t.folder))
            t.free = v.f_bavail * v.f_frsize
        except OSError:
            t.free = 0
        if t.free < 2 * TEST_BYTES + SPARE:
            t.blocked = (f"The test needs {fmt_size(2 * TEST_BYTES + SPARE)} free on {m.target} "
                         f"({fmt_size(t.free)} is).")
        if any(d.transport == "usb" for d in t.drives):
            t.notes.append("The drive is connected by USB: many USB adapters don't pass TRIM on, or answer for the "
                           "drive.")
        if t.trim == "none":
            t.notes.append("TRIM has never run on its own here (no discard option, no fstrim timer), so the test's trim "
                           "is probably this filesystem's first: it trims all of the free space at once, which can take "
                           "a while, and if the drive's TRIM firmware is faulty, this is where it would show. Have a "
                           "backup before you start.")
    return out


def no_trim_text(t: Target, layer: Layer) -> str:
    return (f"TRIM doesn't reach the drive here: {stop_reason(layer, t.drives, t.vm)}. Deleted data stays readable on "
            "it until it is overwritten, so the test would find all of it. Encryption is what protects it.")


def fmt_size(n: int) -> str:
    for unit, k in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= k:
            return f"{n / k:.1f} {unit}"
    return f"{n} bytes"


# ------------------------------------------------------------------ the test files

@dataclass
class TestFile:
    name: str
    number: int
    first: int                              # index of its first record
    count: int
    small: bool


def plan_files(tag: str) -> list[TestFile]:
    files, index = [], 0
    for n, size in enumerate(SMALL + DATA):
        files.append(TestFile(f"{tag}{n:04x}", n, index, size // H.TRIM_RECORD, n < len(SMALL)))
        index += size // H.TRIM_RECORD
    return files


def records(run: bytes, first: int, file: int, count: int) -> bytes:
    payload = os.urandom(count * H.TRIM_PAYLOAD)
    p = H.TRIM_PAYLOAD
    return b"".join(H.trim_record(run, first + j, file, payload[j * p:(j + 1) * p]) for j in range(count))


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _fs_encrypted(path: Path) -> bool:
    """Whether the folder is encrypted file by file (fscrypt: FS_ENCRYPT_FL)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        buf = bytearray(8)
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
        return bool(int.from_bytes(buf[:4], sys.byteorder) & FS_ENCRYPT_FL)
    except OSError:
        return False
    finally:
        os.close(fd)


def _subvolume(parent: Path, name: str) -> bool:
    """Makes `name` a btrfs subvolume of its own (allowed to the folder's owner), so snapshots of
    the home folder (snapper, Timeshift) taken during the test don't keep the test files."""
    try:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        args = bytearray(4096)
        args[8:8 + len(name)] = name.encode()
        fcntl.ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, args)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


SUBVOLUME = _subvolume                       # tests replace it


def _no_compression(folder: Path) -> bool:
    """Marks the folder not to be compressed (chattr +m, FS_NOCOMP_FL; its files inherit it): with
    btrfs's compress mount option (CachyOS and others default to compress=zstd), a small file whose
    records repeat their 32-byte head shrinks and is stored compressed, in a form the scan can't
    recognise. compress-force overrides the flag. False where the filesystem doesn't take it."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        buf = bytearray(8)
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
        flags = int.from_bytes(buf[:4], sys.byteorder) | FS_NOCOMP_FL
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, flags.to_bytes(8, sys.byteorder))
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


NO_COMPRESSION = _no_compression             # tests replace it


def make_folder(t: Target) -> bool:
    """The test folder, empty and the user's own. Returns whether it is a subvolume of its own."""
    folder = t.folder
    remove_folder(folder)
    folder.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    sub = t.fstype == "btrfs" and SUBVOLUME(folder.parent, folder.name)
    if not sub:
        os.mkdir(folder, 0o700)
    os.chmod(folder, 0o700)
    return sub


def remove_folder(folder: Path) -> bool:
    """Deletes the test files (and nothing else: only names this test makes, regular files, never
    through a link) and the folder. Returns whether the folder is gone."""
    try:
        st = os.lstat(folder)
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(st.st_mode):
        return False
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        for e in os.scandir(fd):
            if NAME.match(e.name) and e.is_file(follow_symlinks=False):
                os.unlink(e.name, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.rmdir(folder)                         # an empty btrfs subvolume goes the same way (Linux 4.18+)
    except OSError:
        return False
    return True


def leftovers(host: Host) -> list[str]:
    """Removes test folders a test that didn't finish left behind (the app closed or crashed).
    Returns the ones that couldn't be removed."""
    stuck = []
    others = [other_folder(host, m.target) for m in mounts(host) if m.source.startswith("/dev/")]
    for c in candidates(host) + others:
        if os.path.lexists(c) and not remove_folder(c):
            stuck.append(host.display(c))
    return stuck


def write_files(folder: Path, run: bytes, files: list[TestFile], cancelled: Callable[[], bool]) -> None:
    for f in files:
        fd = os.open(folder / f.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            done = 0
            while done < f.count:
                if cancelled():
                    raise Stopped("Stopped.")
                k = min(BATCH, f.count - done)
                _write_all(fd, records(run, f.first + done, f.number, k))
                done += k
            os.fsync(fd)
        finally:
            os.close(fd)
    dfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    os.sync()


def delete_files(folder: Path, files: list[TestFile]) -> None:
    """Deletes the files and keeps their folder (as when someone deletes files from a folder they
    keep), then syncs twice: the commit that frees the blocks (ext4's journal, btrfs's transaction)
    has to be on the disk before fstrim can trim them."""
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for f in files:
            os.unlink(f.name, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.sync()
    os.sync()


def count_bits(bits: bytes, start: int, end: int) -> int:
    n = 0
    for i in range(start, end):
        if bits[i >> 3] & (1 << (i & 7)):
            n += 1
    return n


# ------------------------------------------------------------------ running it

# The test's steps, in order, as the page lists them (`job["steps"]`): each with its state (pending,
# running, done, skipped), when it started and finished, its progress (done/total: bytes for a
# scan, seconds for the wait) and an estimate in seconds where one is worth giving. "wait" and
# "later" happen only when the first rescan can't settle it (optional).
STEPS = (("begin", "Asking the drive about itself", False),
         ("write", "Writing the test files", False),
         ("baseline", "Reading the whole disk to find the test files", False),
         ("trim", "Deleting the test files and trimming", False),
         ("after", "Reading the whole disk again after the trim", False),
         ("wait", "Waiting a few minutes: drives can finish trimming in the background", True),
         ("later", "Reading the whole disk a last time", True),
         ("remove", "Removing the test folder", False))
SCANS = ("baseline", "after", "later")


def new_steps(size: int) -> list[dict]:
    per_pass = size / 1e12 * 60 * sum(MINUTES_PER_TB) / len(MINUTES_PER_TB)
    est = {"baseline": per_pass, "after": per_pass, "later": per_pass, "wait": float(LATER)}
    return [{"id": i, "label": label, "optional": opt, "state": "pending", "started": None, "finished": None,
             "done": 0, "total": 0, "estimate": est.get(i)} for i, label, opt in STEPS]


def run(host: Host, mount: str, privileged: Callable[[], object | None], job: dict,
        sleep: Callable[[float], None] = time.sleep) -> dict:
    """The whole test, for the target at `mount`. `privileged()` gives the helper (None when
    administrator access has ended); `job` is updated as it goes (steps, phase, pass, done, total)
    and its "cancel" stops it. Returns the result (result_view); the test folder is removed whatever
    happens."""
    t = next((x for x in targets(host) if x.mount == mount), None)
    if t is None or t.blocked or t.known or t.folder is None:
        raise ValueError((t.blocked or t.known) if t else "That filesystem can't be tested.")
    job["steps"] = steps = new_steps(t.size)
    by_id = {st["id"]: st for st in steps}

    def helper():
        h = privileged()
        if h is None:
            raise Stopped("Administrator access ended, so the test stopped.")
        return h

    def cancelled() -> bool:
        return bool(job.get("cancel"))

    def phase(step: str, total: int = 0) -> None:
        """Begins a step: the running one (if any) is done."""
        now = time.time()
        for st in steps:
            if st["state"] == "running":
                st.update(state="done", finished=now, done=st["total"] or st["done"])
        by_id[step].update(state="running", started=now, done=0, total=total)
        job.update(phase=by_id[step]["label"], scan=step if step in SCANS else None, done=0, total=total,
                   phase_started=now)

    def progress(done: int) -> None:
        job["done"] = done
        for st in steps:
            if st["state"] == "running":
                st["done"] = done

    def skip(*names: str) -> None:
        for n in names:
            if by_id[n]["state"] == "pending":
                by_id[n]["state"] = "skipped"

    def scan(name: str, until: tuple[int, int] | None = None) -> dict:
        phase(name, size)
        off, started = 0, time.time()
        while off < size:
            if cancelled():
                raise Stopped("Stopped.")
            r = helper().call("trim_scan", {"pass": name, "offset": off, "length": CALL_BYTES}, SCAN_TIMEOUT)
            off += CALL_BYTES
            progress(min(off, size))
            if cancelled():
                raise Stopped("Stopped.")
            if until and r["found"] >= until[0] and r["names"] >= until[1]:
                break                            # the baseline found everything: no need to read on
            if r["read"] <= 0:
                break
        took = time.time() - started
        if took > 0 and min(off, size) > 0:      # the passes still to come, at the rate this one read
            for later in SCANS[SCANS.index(name) + 1:]:
                by_id[later]["estimate"] = size / (min(off, size) / took)
        return helper().call("trim_result", {"pass": name})

    phase("begin")
    begin = helper().call("trim_begin", {"mount": t.mount})
    size, run_id, tag = begin["size"], bytes.fromhex(begin["run"]), begin["tag"]
    files = plan_files(tag)
    total = sum(f.count for f in files)
    passes: dict[str, dict] = {}
    stats: dict[str, dict] = {}
    home_fs = holding(mounts(host), logical(host, host.home))
    inline = t.fstype == "btrfs"                 # only btrfs keeps small files inside its own records
    facts = {"subvolume": False, "nocompress": False, "trimmed": None, "deleted_at": None, "trimmed_at": None,
             "home_here": home_fs is not None and home_fs.source == t.source, "missing": {}}
    try:
        phase("write")
        facts["subvolume"] = make_folder(t)
        facts["nocompress"] = inline and NO_COMPRESSION(t.folder)
        if _fs_encrypted(t.folder):
            return blocked_result(t, "This folder is encrypted file by file (fscrypt): what is written to it, names "
                                  "included, reaches the disk encrypted, so the test can't recognise its own files. "
                                  "That also means deleted files in it can't be read without the key.")
        write_files(t.folder, run_id, files, cancelled)
        passes["baseline"] = scan("baseline", (total, len(files)))
        base_bits = base64.b64decode(passes["baseline"]["bits"])
        facts["missing"] = {f.number: f.count - count_bits(base_bits, f.first, f.first + f.count) for f in files}
        # blocks the baseline couldn't find stop the test, unless they are only in btrfs's small inline
        # files (stored in another form, compressed: those go untested and the data files are tested)
        if (any(n for f, n in facts["missing"].items() if not (files[f].small and inline))
                or len(passes["baseline"]["names"]) < len(files)):
            skip("trim", "after", "wait", "later")
            return result_view(t, begin, files, passes, stats, facts)
        if cancelled():
            raise Stopped("Stopped.")
        phase("trim")
        stats["before"] = snapshot(host, t)
        delete_files(t.folder, files)
        facts["deleted_at"] = time.time()
        facts["trimmed"] = helper().call("trim_fstrim", {}, FSTRIM_TIMEOUT).get("trimmed")
        facts["trimmed_at"] = time.time()
        stats["trimmed"] = snapshot(host, t)
        passes["after"] = scan("after")
        stats["after"] = snapshot(host, t)
        behaviour = drive_behaviour(begin)
        if passes["after"]["found"] or behaviour not in ("zeros", "ones"):
            wait = facts["trimmed_at"] + LATER - time.time()
            if wait > 0:
                phase("wait", total=int(wait))
                end = time.time() + wait
                while time.time() < end:
                    if cancelled():
                        raise Stopped("Stopped.")
                    helper()                     # access dropped meanwhile (the app quit): stop now, not after the wait
                    sleep(min(1.0, max(0.0, end - time.time())))
                    progress(int(wait - max(0, end - time.time())))
            else:
                skip("wait")
            passes["later"] = scan("later")
        else:
            skip("wait", "later")
        return result_view(t, begin, files, passes, stats, facts)
    finally:
        phase("remove")
        facts["removed"] = remove_folder(t.folder)
        for st in steps:
            if st["state"] == "running":
                st.update(state="done", finished=time.time())
        try:
            h = privileged()
            if h is not None:
                h.call("trim_end", {})
        except Exception:  # noqa: BLE001 - the run ends with the helper anyway
            pass


def snapshot(host: Host, t: Target) -> dict:
    """Sectors written and discarded so far, at the filesystem's device and at each drive."""
    return {name: device_stats(host, name) for name in [t.device] + [d.name for d in t.drives]}


def drive_behaviour(begin: dict) -> str | None:
    """What a trimmed block reads back as, for the drives under the filesystem together: theirs if
    they agree, None (unknown) if any couldn't tell or they differ."""
    kinds = {d.get("behaviour") for d in begin.get("drives", [])}
    return kinds.pop() if len(kinds) == 1 else None


# ------------------------------------------------------------------ the result

TRANSPORT = {"nvme": "NVMe", "sata": "SATA", "usb": "USB", "virtio": "virtual disk", "mmc": "SD card or eMMC",
             "scsi": "SCSI"}

BEHAVIOUR = {
    "zeros": "reads trimmed blocks back as zeros",
    "ones": "reads trimmed blocks back as all 0xFF",
    "deterministic": "returns the same thing for a trimmed block every time, without saying what (DRAT)",
    "unreported": "doesn't say what trimmed blocks read back as",
    None: "couldn't be asked what trimmed blocks read back as",
}


def _delta(a: dict, b: dict, name: str, field_: int) -> int | None:
    x, y = a.get(name, (None, None))[field_], b.get(name, (None, None))[field_]
    return y - x if x is not None and y is not None else None


def outside(ranges: list[list[int]], within: list[list[int]]) -> int:
    """How many bytes of `ranges` ([offset, length] each) lie outside every range in `within`."""
    total = 0
    for off, length in ranges:
        end = off + length
        covered = 0
        for w, k in within:
            lo, hi = max(off, w), min(end, w + k)
            if hi > lo:
                covered += hi - lo
        total += length - covered
    return total


def unreadable_text(t: Target, final: dict, base: dict, newly: int, all_found: bool) -> list[str]:
    """What the parts of the disk the drive couldn't read mean for the result."""
    size, places = final.get("unreadable", 0), len(final.get("unreadable_ranges", []))
    out = [f"The drive couldn't read {fmt_size(size)} of the disk ({places}{'+' if final.get('unreadable_more') else ''} "
           f"{'places' if places != 1 else 'place'}): it answered with errors there, which usually means failing "
           "sectors. The test skipped those parts and counted nothing in them, and it never writes to the disk "
           "directly. Back this drive up and check its health (smartctl -a, below)."]
    if newly:
        out.append(f"{fmt_size(newly)} of that was readable when the test files were written, so deleted test data could "
                   "be hiding there, out of the test's sight: the result is inconclusive.")
    elif all_found and base.get("unreadable"):
        out.append("Those parts were unreadable before the test too, and every test block was found elsewhere, so "
                   "nothing of the test can be hiding in them.")
    return out


def blocked_result(t: Target, why: str) -> dict:
    return {"verdict": "not_run", "headline": "The test couldn't run on this folder.", "explanation": [why],
            "lines": [], "environment": environment(t), "offsets": [], "text": why, "finished": time.time()}


def environment(t: Target, begin: dict | None = None) -> list[dict]:
    env = [{"label": "Filesystem", "value": f"{t.mount} ({t.fstype})"}]
    opts = [o for o in t.options.split(",") if re.match(r"^(discard|nodiscard|compress|compress-force|max_inline|data)"
                                                         r"(=|$)", o)]
    if t.fstype == "btrfs" and _option(t.options, "max_inline") is None:
        opts.append("max_inline=2048 (default)")
    if opts:
        env.append({"label": "Mount options", "value": ", ".join(opts)})
    kinds = {"crypt": "LUKS encryption", "lvm": "LVM", "dm": "device-mapper", "md": "software RAID",
             "partition": "partition", "disk": "drive"}
    if t.layers:
        env.append({"label": "Storage", "value": " → ".join(
            f"{kinds[x.kind]} {x.label or x.name}" + ("" if x.discard_max is None else
                                                     " (no TRIM)" if x.discard_max == 0 else "")
            for x in t.layers)})
    by_disk = {d.get("disk"): d for d in (begin or {}).get("drives", [])}
    for d in t.drives:
        parts = [x for x in (d.model, f"firmware {d.firmware}" if d.firmware else "", TRANSPORT.get(d.transport, ""))
                 if x]
        env.append({"label": f"Drive {d.name}", "value": ", ".join(parts) or "unknown"})
        if begin is not None:
            b = by_disk.get(d.name, {})
            how = BEHAVIOUR.get(b.get("behaviour"), BEHAVIOUR[None])
            why = f" ({b['why']})" if b.get("why") else f" ({b['source']})" if b.get("source") else ""
            env.append({"label": f"After TRIM, {d.name}", "value": how + why})
            env.append({"label": f"Encryption in {d.name}", "value": encryption_line(b.get("encryption") or {})})
    env.append({"label": "TRIM runs", "value": {"continuous": "at once, as files are deleted (discard)",
                                                "weekly": "once a week (fstrim.timer)",
                                                "none": "not on its own (no discard option, no fstrim timer)",
                                                None: "unknown"}[t.trim]})
    return env


def result_view(t: Target, begin: dict, files: list[TestFile], passes: dict, stats: dict, facts: dict) -> dict:
    total = sum(f.count for f in files)
    base = passes["baseline"]
    final_name = "later" if "later" in passes else "after" if "after" in passes else None
    env = environment(t, begin)
    lines: list[dict] = []
    explanation: list[str] = []
    offsets: list[list[int]] = []

    if final_name is None:                       # the baseline didn't find everything
        missing = total - base["found"]
        names = len(files) - len(base["names"])
        what = []
        if missing:
            what.append(f"{missing} of {total} test blocks")
        if names:
            what.append(f"{names} of {len(files)} file names")
        headline = "Inconclusive: the test couldn't find its own files on the disk."
        explanation = [
            f"Before deleting anything, the test read the whole disk and couldn't find {' and '.join(what)}. Without "
            "that, finding nothing after deleting would mean nothing, so it stopped there.",
            "Usually this means the files reach the disk in another form, such as encrypted file by file or "
            "compressed (btrfs compress-force), or are stored somewhere other than this device. It isn't a fault of "
            "the drive."]
        if base.get("unreadable"):
            lines.append({"label": "Parts of the disk the drive couldn't read", "value": fmt_size(base["unreadable"])})
            explanation.append(f"But the drive couldn't read {fmt_size(base['unreadable'])} of the disk (it answered "
                               "with errors there, which usually means failing sectors), and the missing test blocks "
                               "may lie in those parts. Back this drive up and check its health (smartctl -a, below).")
        explanation.append("Whether the names of deleted files stay on this filesystem wasn't tested. The Deleted "
                           "file names tool still shows which names of your own deleted files the disk holds.")
        verdict = "inconclusive"
    else:
        final = passes[final_name]
        bits = base64.b64decode(final["bits"])
        first_bits = base64.b64decode(passes["after"]["bits"])
        inline = t.fstype == "btrfs"             # only btrfs keeps small files inside its own records
        data = [f for f in files if not (f.small and inline)]
        small = [f for f in files if f.small and inline]
        missing = facts.get("missing") or {}
        small_missing = sum(missing.get(f.number, 0) for f in small)      # unrecognisable before deletion: untested
        data_total, small_total = sum(f.count for f in data), sum(f.count for f in small) - small_missing
        data_left = sum(count_bits(bits, f.first, f.first + f.count) for f in data)
        small_left = sum(count_bits(bits, f.first, f.first + f.count) for f in small)
        data_first = sum(count_bits(first_bits, f.first, f.first + f.count) for f in data)
        names_left = len(final["names"])
        offsets = final["offsets"][:20]
        behaviour = drive_behaviour(begin)
        fill = behaviour in ("zeros", "ones")
        reached = [d for d in (_delta(stats["before"], stats["trimmed"], x.name, 1) for x in t.drives) if d is not None]
        drive_discards = sum(reached) * 512 if reached else None
        written = _delta(stats["trimmed"], stats["after"], t.device, 0)

        # parts the drive couldn't read in the last pass that it could read when the files were written
        # (or that can't be compared, when a pass had more ranges than the helper keeps)
        newly = (final.get("unreadable", 0) if final.get("unreadable_more") or base.get("unreadable_more") else
                 outside(final.get("unreadable_ranges", []), base.get("unreadable_ranges", [])))

        if data_left == 0 and drive_discards == 0:
            verdict = "inconclusive"
            headline = ("Inconclusive: the deleted test data is gone, but the drive received no TRIM, so it was "
                        "probably overwritten.")
        elif data_left == 0 and newly:
            verdict = "inconclusive"
            headline = ("Inconclusive: none of the deleted test data could be read back, but parts of the disk that "
                        "were readable before the trim couldn't be read after it, so deleted data there couldn't be "
                        "checked.")
        elif data_left == 0:
            verdict = "pass"
            headline = ("TRIM works on this drive: none of the deleted test data could be read back." if fill else
                        "None of the deleted test data could be read back after TRIM.")
        elif fill or drive_discards == 0:
            verdict = "fail"
            headline = (f"TRIM isn't clearing deleted data here: {data_left} of {data_total} deleted test blocks could "
                        "still be read back.")
        else:
            verdict = "inconclusive"
            headline = (f"Deleted test data could still be read back ({data_left} of {data_total} blocks); whether TRIM "
                        "reached it can't be told on this drive.")

        lines.append({"label": "Test data read back after deleting",
                      "value": f"{data_left} of {data_total} blocks" + (
                          f" (just after the trim: {data_first})" if final_name == "later" and data_first != data_left
                          else "")})
        if small:
            lines.append({"label": "Small files read back", "value": f"{small_left} of {small_total} blocks"
                          + (f" ({small_missing} more couldn't be tested)" if small_missing else "")})
        lines.append({"label": "Deleted file names still on the disk", "value": f"{names_left} of {len(files)}"})
        if facts.get("trimmed") is not None:
            lines.append({"label": "fstrim trimmed", "value": fmt_size(facts["trimmed"])})
        if drive_discards is not None:
            lines.append({"label": "TRIM that reached the drive", "value": fmt_size(drive_discards) if drive_discards
                          else "none"})
        if written is not None:
            lines.append({"label": "Written to the disk between the trim and the rescan",
                          "value": fmt_size(written * 512)})
        if final.get("unreadable") or base.get("unreadable"):
            lines.append({"label": "Parts of the disk the drive couldn't read", "value": fmt_size(final.get("unreadable", 0))
                          + (f" (before the test: {fmt_size(base.get('unreadable', 0))})"
                             if base.get("unreadable", 0) != final.get("unreadable", 0) else "")})

        explanation += meaning(t, verdict, behaviour, fill, data_left, data_total, drive_discards)
        if final.get("unreadable"):
            explanation += unreadable_text(t, final, base, newly, True)
        if small_missing:
            explanation.append(
                f"{small_missing} of the small test files' {small_total + small_missing} blocks couldn't be recognised on "
                "the disk even before they were deleted, so they weren't tested. btrfs keeps small files inside its own "
                "records, and with the compress mount option it stores them compressed when that makes them smaller"
                + (" (the test asked btrfs not to compress its folder, which compress-force overrides)."
                   if facts.get("nocompress") else
                   " (the test couldn't mark its folder as not to be compressed on this filesystem).")
                + " Nothing is lost by it: the data files, which are what TRIM reaches, were all found and tested.")
        if small_left:
            explanation.append(
                "btrfs keeps small files (up to max_inline, 2048 bytes by default) inside its own records rather than "
                f"in blocks of their own. Contents of the small test files could still be read back ({small_left} of "
                f"{small_total} blocks): they are in parts of the disk btrfs still uses, which aren't free space, so "
                "TRIM never reaches them.")
        explanation.append(names_text(t, names_left, len(files)))
        if written and written * 512 > TEST_BYTES:
            explanation.append(f"Other programs wrote {fmt_size(written * 512)} to this disk between the trim and the "
                               "rescan: some of the freed blocks may have been reused rather than trimmed, which also "
                               "hides what was in them.")
    if begin.get("drives"):
        explanation.append(drive_encryption_text(begin))
    if not facts.get("subvolume") and t.fstype == "btrfs":
        explanation.append("The test folder couldn't be made a subvolume of its own, so a snapshot taken during the "
                           "test could have kept the test files.")
    if not facts.get("removed", True):
        explanation.append(f"The test folder {t.folder} couldn't be removed; it is empty, and you can delete it.")
    text = "\n".join([f"TRIM test: {headline}", ""] + [f"{x['label']}: {x['value']}" for x in lines] + [""]
                     + explanation + ["", "Environment:"] + [f"  {x['label']}: {x['value']}" for x in env]
                     + ([""] + ["Surviving blocks (index: offset on the device):"]
                        + [f"  {i}: {o}" for i, o in offsets] if offsets else []))
    commands = ["sudo fstrim -av"] if final_name and t.trim != "continuous" else []
    if any(p.get("unreadable") for p in passes.values()):
        commands += [f"sudo smartctl -a /dev/{d.name}" for d in t.drives]
    return {"verdict": verdict, "headline": headline, "explanation": explanation, "lines": lines, "environment": env,
            "offsets": offsets, "text": text, "commands": commands,
            "names_mount": t.mount if facts.get("home_here", False) or t.mount != "/" else None,
            "guide": "enc.trim_off" if final_name and t.trim == "none" else "",
            "finished": time.time()}


def meaning(t: Target, verdict: str, behaviour: str | None, fill: bool, data_left: int, data_total: int,
            drive_discards: int | None) -> list[str]:
    """What the result means for the user (see the module docstring)."""
    out = []
    when = {"continuous": "That happens as soon as a file is deleted here (the discard option).",
            "weekly": "Here TRIM runs once a week (the fstrim timer): until then, deleted files can still be read back "
                      "from the drive. To trim whenever you want, run sudo fstrim -av.",
            "none": "Here TRIM doesn't run on its own (no discard option and no fstrim timer), so deleted files stay "
                    "readable until something trims them: turn on the fstrim timer (sudo systemctl enable --now "
                    "fstrim.timer), or trim whenever you want with sudo fstrim -av.",
            None: ""}[t.trim]
    if verdict == "pass":
        out.append("Once deleted data has been trimmed, nobody can read it back by plugging this drive in"
                   + (", even with your encryption key" if t.encrypted else "")
                   + ": the drive's controller has dropped it. " + when)
        if not fill:
            out.append(f"This drive {BEHAVIOUR[behaviour]}, so this is what it returned during the test, not a "
                       "promise for later reads.")
    elif verdict == "fail":
        if drive_discards == 0:
            out.append("The drive received no TRIM during the trim, so it still holds the deleted data and returns it "
                       "when asked. Something between the filesystem and the drive drops it.")
        else:
            out.append(f"The drive {BEHAVIOUR[behaviour]}, yet deleted test data came back unchanged, so those blocks "
                       "weren't trimmed" + (": the discards didn't clear them." if data_left == data_total else
                                            ". When only some survive, the drive often ignores discards smaller than "
                                            "its own internal unit."))
        out.append("Until it is overwritten, deleted data on it can be read back by anyone with the disk"
                   + (" and your encryption key." if t.encrypted else "."))
    elif verdict == "inconclusive" and data_left:
        out.append(f"This drive {BEHAVIOUR[behaviour]}, so data that survives may be a TRIM that didn't arrive or a "
                   "drive that still returns old data after it. Either way, deleted data could be read back from it "
                   "during the test" + (" by someone with your encryption key." if t.encrypted else "."))
    out.append("What TRIM doesn't protect against: someone examining the flash chips themselves (or using the "
               "maker's diagnostic modes), which can still hold data the controller has dropped"
               + (", if they also have your encryption key." if t.encrypted else
                  ". This disk isn't encrypted, so that data is readable to anyone who does that: full-disk encryption "
                  "is what protects it (see “Full-disk encryption not enabled”).")
               + " Nor copies the filesystem still keeps (snapshots, its journal, its own records), which aren't free "
                 "space and are never trimmed.")
    return out


def names_text(t: Target, left: int, total: int) -> str:
    if not left:
        return "None of the deleted test files' names could be read back."
    where = ("On ext4 a deleted file's name stays in the journal, which keeps copies of its folder's records as they "
             "were before (and, under kernels before Linux 5.13, in the folder's own records). " if t.fstype == "ext4"
             else "")
    protect = (" Your disk is encrypted, so they can be read only with your key." if t.encrypted else
               " This disk isn't encrypted, so anyone with it can read them.")
    return (f"The names of {left} of {total} deleted test files could still be read from the disk after TRIM. "
            + where + "TRIM doesn't reach them where they are. Encryption is what protects file names (full-disk "
            "encryption, or per-folder encryption such as fscrypt)." + protect + " The Deleted file names tool shows "
            "which names of your own deleted files the disk holds, and clears them where it safely can.")


# ------------------------------------------------------------------ encryption in the drive itself

def encryption_signals(e: dict) -> tuple[list[str], list[str]]:
    """What the drive says that means it encrypts what it stores, and what it was asked that
    says nothing of the kind."""
    yes, no = [], []
    if e.get("encrypts_all"):
        yes.append("its identify data says it encrypts all user data")
    elif e.get("encrypts_all") is False:
        no.append("its identify data doesn't say it encrypts all user data")
    tcg = e.get("tcg")
    if tcg:
        ssc = ", ".join(tcg["ssc"]) or "TCG storage"
        if tcg.get("media_encryption"):
            yes.append(f"it supports {ssc} and reports media encryption")
        elif tcg.get("encrypting_ssc"):
            yes.append(f"it supports {ssc}, which comes with an encryption engine")
        else:
            no.append(f"it supports {ssc}, which gives locking without encryption")
    if e.get("crypto_erase"):
        by = " and ".join(e.get("crypto_erase_by") or [])
        yes.append("it offers crypto erase" + (f" ({by})" if by else "") + ", which only works on data it encrypts")
    elif e.get("crypto_erase") is False:
        no.append("it doesn't offer crypto erase")
    return yes, no


def encryption_line(e: dict) -> str:
    yes, no = encryption_signals(e)
    if yes:
        return "; ".join(yes)
    if no:
        return "nothing says it encrypts what it stores (" + "; ".join(no) + ")"
    return "couldn't be asked" + (f" ({'; '.join(e.get('notes') or [])})" if e.get("notes") else "")


def drive_encryption_text(begin: dict) -> str:
    """Whether the drive encrypts what it stores, as far as it says, and what that's worth."""
    signals = [encryption_signals(d.get("encryption") or {}) for d in begin.get("drives", [])]
    notes = [n for d in begin.get("drives", []) for n in (d.get("encryption") or {}).get("notes", [])]
    if any(yes for yes, _ in signals):
        said = "; ".join(x for yes, _ in signals for x in yes)
        return ("The drive says it encrypts what it stores with a key of its own (" + said + "). If it really does, "
                "and does it well, what it has dropped but not yet erased is only ciphertext on its flash chips, which "
                "helps against chip-off recovery. Makers' claims about this have often been wrong: researchers found "
                "self-encrypting SSDs whose data could be read without the password, and Windows stopped relying on "
                "drive encryption for BitLocker (KB4516071). Count it as a bonus on top of disk encryption, never "
                "instead of it.")
    if any(no for _, no in signals):
        return ("Nothing the drive reports says it encrypts what it stores (" + "; ".join(x for _, no in signals
                for x in no) + "). Some drives encrypt without saying so, but assume that what it has dropped can stay "
                "readable on its flash chips until it is erased.")
    return ("Whether the drive encrypts what it stores couldn't be asked" + (": " + "; ".join(notes) if notes else "")
            + ".")
