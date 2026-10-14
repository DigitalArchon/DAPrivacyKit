"""The TRIM test: the helper's scan (a regular file stands in for the device, in a fixture tree), the
app's view of the storage (fixture /sys), and whole runs against a simulated disk that keeps or drops
what was deleted. Nothing here reads a real disk or runs fstrim."""

from __future__ import annotations

import base64
import errno
import json
import os
import struct
import time

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper
from daprivacyscanner.host import FakeRunner, Host
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.server import AdminSession, create_app
from daprivacyscanner.tools import trimtest as T

ME = (os.geteuid(), os.getegid())
H = {"X-Token": "t"}
DEVICE_SIZE = 4 << 20


def nvme(dlfeat=1, sanicap=0, fna=0, oacs=0, level0=None):
    """A fake NVMe drive's answers to the helper's admin commands."""
    def admin(path, opcode, cdw10, cdw11=0, length=4096, namespace=True):
        if opcode == helper.NVME_IDENTIFY and cdw10 == 0:
            return bytes(33) + bytes([dlfeat]) + bytes(4062)
        if opcode == helper.NVME_IDENTIFY and cdw10 == 1:
            b = bytearray(4096)
            b[256:258], b[328:332], b[524] = oacs.to_bytes(2, "little"), sanicap.to_bytes(4, "little"), fna
            return bytes(b)
        if opcode == helper.NVME_SECURITY_RECEIVE:
            return level0
        return None
    return admin


def level0(*features):
    """A TCG Level 0 Discovery response with these (code, data) feature descriptors."""
    body = b"".join(code.to_bytes(2, "big") + b"\x10" + bytes([len(data)]) + data for code, data in features)
    return (44 + len(body)).to_bytes(4, "big") + bytes(44) + body + bytes(64)


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def link(path, target):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_symlink():
        os.symlink(target, path)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def make_storage(r, fstype="ext4", discard_max="2199023255040", rotational="0", luks=False, options="rw,relatime"):
    """/ on nvme0n1p2 (or on LUKS dm-0 over it), with the sysfs a real system has: class/block links
    into /sys/devices, the partition under its disk."""
    (r / "proc/self").mkdir(parents=True, exist_ok=True)
    source = "/dev/mapper/luks-1" if luks else "/dev/nvme0n1p2"
    (r / "proc/self/mounts").write_text(f"{source} / {fstype} {options} 0 0\nproc /proc proc rw 0 0\n")
    if not (r / "proc/mounts").is_symlink():
        os.symlink("self/mounts", r / "proc/mounts")
    disk = r / "sys/devices/pci0000:00/nvme/nvme0/nvme0n1"
    write(disk / "queue/discard_max_bytes", discard_max + "\n")
    write(disk / "queue/rotational", rotational + "\n")
    write(disk / "device/model", "Example SSD 1TB\n")
    write(disk / "device/firmware_rev", "1B2QEXM7\n")
    write(disk / "stat", " ".join(["0"] * 17) + "\n")
    write(disk / "nvme0n1p2/partition", "2\n")
    write(disk / "nvme0n1p2/size", str(DEVICE_SIZE // 512) + "\n")
    write(disk / "nvme0n1p2/stat", " ".join(["0"] * 17) + "\n")
    link(r / "sys/class/block/nvme0n1", "../../devices/pci0000:00/nvme/nvme0/nvme0n1")
    link(r / "sys/class/block/nvme0n1p2", "../../devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p2")
    link(r / "sys/block/nvme0n1", "../devices/pci0000:00/nvme/nvme0/nvme0n1")
    dev = r / "dev/nvme0n1p2"
    dev.parent.mkdir(parents=True, exist_ok=True)
    with open(dev, "wb") as f:
        f.truncate(DEVICE_SIZE)
    if luks:
        dm = r / "sys/devices/virtual/block/dm-0"
        write(dm / "dm/name", "luks-1\n")
        write(dm / "dm/uuid", "CRYPT-LUKS2-abc-luks-1\n")
        write(dm / "queue/discard_max_bytes", ("0" if luks == "no-discards" else discard_max) + "\n")
        write(dm / "size", str(DEVICE_SIZE // 512) + "\n")
        write(dm / "stat", " ".join(["0"] * 17) + "\n")
        (dm / "slaves").mkdir(parents=True, exist_ok=True)
        link(dm / "slaves/nvme0n1p2", "../../../../pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p2")
        link(r / "sys/class/block/dm-0", "../../devices/virtual/block/dm-0")
        link(r / "dev/mapper/luks-1", "../dm-0")
        with open(r / "dev/dm-0", "wb") as f:
            f.truncate(DEVICE_SIZE)
    return dev


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    monkeypatch.setattr(helper, "IS_BLOCK", lambda st: True)
    monkeypatch.setattr(helper, "NVME_ADMIN", nvme())
    monkeypatch.setattr(helper, "_TRIM", {})
    monkeypatch.setattr(helper, "_NAMES", {})
    return r


def host_for(r, commands=None):
    home = r / "home/alice"
    cmds = {"systemd-detect-virt --vm": "none\n", "systemctl is-enabled fstrim.timer": "enabled\n", **(commands or {})}
    return Host(home=home, environ={"HOME": str(home)}, runner=FakeRunner(cmds), root=r, uid=ME[0])


# ------------------------------------------------------------------ the helper's scan

def test_records_are_found_whole_once_each_across_reads_and_calls(root, monkeypatch):
    dev = make_storage(root)
    monkeypatch.setattr(helper, "TRIM_READ", 16384)          # small reads, so records cross their edges
    monkeypatch.setattr(helper, "TRIM_ALIGN", 4096)
    b = call("trim_begin", mount="/")
    assert b["device"] == "/dev/nvme0n1p2" and b["size"] == DEVICE_SIZE and b["fstype"] == "ext4"
    [d] = b["drives"]
    assert (d["disk"], d["behaviour"], d["source"]) == ("nvme0n1", "zeros", "NVMe identify data, DLFEAT")
    run, tag = bytes.fromhex(b["run"]), b["tag"]
    rec = lambda i: helper.trim_record(run, i, 0, os.urandom(helper.TRIM_PAYLOAD))
    other = helper.trim_record(os.urandom(16), 9, 0, os.urandom(helper.TRIM_PAYLOAD))
    bad = bytearray(rec(8))
    bad[100] ^= 1                                            # a damaged record doesn't count
    place = {100: rec(0), 16384 - 200: rec(1), 32768 - 10: rec(2), 65536 - 300: rec(3), 70000: rec(3),
             90000: other, 100000: bytes(bad), 120000: (tag + "0004").encode(), 131072 - 5: (tag + "0005").encode(),
             140000: (tag + "0004").encode(), 150000: (tag + "zzzz").encode()}
    with open(dev, "r+b") as f:
        for off, data in place.items():
            f.seek(off)
            f.write(data)
    for off in range(0, DEVICE_SIZE, 65536):                 # calls that end inside a record
        r = call("trim_scan", **{"pass": "after", "offset": off, "length": 65536})
    assert (r["found"], r["copies"], r["names"]) == (4, 5, 2)
    res = call("trim_result", **{"pass": "after"})
    bits = base64.b64decode(res["bits"])
    assert [i for i in range(10) if bits[i >> 3] & (1 << (i & 7))] == [0, 1, 2, 3]
    assert sorted(res["offsets"]) == [[0, 100], [1, 16184], [2, 32758], [3, 65236]]
    assert res["names"] == {"4": 2, "5": 1}


def eio_at(monkeypatch, ranges, when=lambda: True):
    """Reads of the device that touch one of these [offset, length] ranges fail with EIO, as a
    failing sector does, while `when()` holds."""
    real = os.preadv

    def fake(fd, bufs, off):
        n = sum(len(b) for b in bufs)
        if when() and any(off < lo + k and lo < off + n for lo, k in ranges):
            del bufs                                         # as the real preadv: no frame of its own keeps the buffer
            raise OSError(errno.EIO, "Input/output error")
        return real(fd, bufs, off)
    monkeypatch.setattr(os, "preadv", fake)


def test_unreadable_parts_are_skipped_zero_filled_and_counted(root, monkeypatch):
    dev = make_storage(root)
    b = call("trim_begin", mount="/")
    run = bytes.fromhex(b["run"])
    rec = lambda i: helper.trim_record(run, i, 0, os.urandom(helper.TRIM_PAYLOAD))
    with open(dev, "r+b") as f:
        f.seek(100)
        f.write(rec(0))                                      # readable
        f.seek((1 << 20) + 70000)
        f.write(rec(1))                                      # in the bad part: the drive can't give it back
        f.seek((3 << 20) + 1000)
        f.write(rec(2))
    eio_at(monkeypatch, [[1 << 20, 100000]])                 # 100000 bytes: two 64 KiB pieces fail
    r = call("trim_scan", **{"pass": "after", "offset": 0, "length": DEVICE_SIZE})
    assert (r["found"], r["unreadable"]) == (2, 2 * helper.TRIM_PIECE)
    res = call("trim_result", **{"pass": "after"})
    assert res["unreadable_ranges"] == [[1 << 20, 2 * helper.TRIM_PIECE]] and not res["unreadable_more"]
    assert sorted(res["offsets"]) == [[0, 100], [2, (3 << 20) + 1000]]


def test_other_read_errors_are_not_skipped(root, monkeypatch):
    make_storage(root)
    call("trim_begin", mount="/")

    def fake(fd, bufs, off):
        del bufs                                             # as the real preadv: no frame of its own keeps the buffer
        raise OSError(errno.EINVAL, "Invalid argument")
    monkeypatch.setattr(os, "preadv", fake)
    with pytest.raises(helper.Refused, match="couldn't be read: Invalid argument"):
        call("trim_scan", **{"pass": "after", "offset": 0, "length": DEVICE_SIZE})


def test_outside_of_ranges():
    assert T.outside([[0, 100], [500, 100]], []) == 200
    assert T.outside([[0, 100], [500, 100]], [[0, 100]]) == 100
    assert T.outside([[0, 100]], [[50, 20], [90, 30]]) == 70
    assert T.outside([], [[0, 100]]) == 0


def test_scan_requests_are_checked(root):
    make_storage(root)
    with pytest.raises(helper.Refused, match="no TRIM test"):
        call("trim_scan", **{"pass": "after", "offset": 0, "length": 1 << 20})
    call("trim_begin", mount="/")
    for args in ({"pass": "other", "offset": 0, "length": 1 << 20}, {"pass": "after", "offset": 4096, "length": 1 << 20},
                 {"pass": "after", "offset": 0, "length": 2 << 30}, {"pass": "after", "offset": DEVICE_SIZE, "length": 1 << 20},
                 {"pass": "after", "offset": True, "length": 1 << 20}):
        with pytest.raises(helper.Refused):
            call("trim_scan", **args)
    with pytest.raises(helper.Refused, match="hasn't run"):
        call("trim_result", **{"pass": "later"})


def test_begin_takes_only_slash_or_the_home_filesystem(root):
    make_storage(root)
    with pytest.raises(helper.Refused, match="only /, the filesystem holding your home"):
        call("trim_begin", mount="/proc")
    with pytest.raises(helper.Refused, match="only /, the filesystem holding your home"):
        call("trim_begin", mount="/mnt")
    (root / "proc/self/mounts").write_text("/dev/nvme0n1p2 / xfs rw 0 0\n")
    with pytest.raises(helper.Refused, match="only ext4 and btrfs"):
        call("trim_begin", mount="/")


def test_multi_device_btrfs_is_refused(root):
    make_storage(root, fstype="btrfs")
    for d in ("nvme0n1p2", "sda1"):
        (root / f"sys/fs/btrfs/1234/devices/{d}").mkdir(parents=True)
    with pytest.raises(helper.Refused, match="more than one device"):
        call("trim_begin", mount="/")


def test_drives_under_luks_and_what_they_report(root, monkeypatch):
    make_storage(root, luks=True)
    monkeypatch.setattr(helper, "NVME_ADMIN", nvme(dlfeat=2))
    b = call("trim_begin", mount="/")
    assert b["device"] == "/dev/dm-0" and [d["behaviour"] for d in b["drives"]] == ["ones"]
    monkeypatch.setattr(helper, "NVME_ADMIN", lambda *a, **k: None)
    assert call("trim_begin", mount="/")["drives"][0]["behaviour"] is None


def test_hdparm_wording():
    assert helper.parse_hdparm_trim("\t   *\tData Set Management TRIM supported (limit 8 blocks)\n"
                                    "\t   *\tDeterministic read ZEROs after TRIM\n") == "zeros"
    assert helper.parse_hdparm_trim("\t   *\tData Set Management TRIM supported (limit 8 blocks)\n"
                                    "\t   *\tDeterministic read data after TRIM\n") == "deterministic"
    assert helper.parse_hdparm_trim("\t   *\tData Set Management TRIM supported (limit 8 blocks)\n") == "unreported"
    assert helper.parse_hdparm_trim("Commands/features:\n") is None


def test_fstrim_runs_on_the_runs_filesystem(root, monkeypatch):
    make_storage(root)
    seen = []
    monkeypatch.setattr(helper, "TRIM_RUN", lambda argv: (seen.append(argv), (0, "/: 1.2 GiB (1288490188 bytes) trimmed on "
                                                                              "/dev/nvme0n1p2\n", ""))[1])
    with pytest.raises(helper.Refused):
        call("trim_fstrim")
    call("trim_begin", mount="/")
    assert call("trim_fstrim") == {"trimmed": 1288490188} and seen == [["fstrim", "-v", "/"]]
    call("trim_end")
    with pytest.raises(helper.Refused):
        call("trim_fstrim")


# ------------------------------------------------------------------ the app's view of the storage

def test_a_testable_ssd(root):
    make_storage(root)
    host = host_for(root)
    [t] = T.targets(host)
    assert (t.mount, t.fstype, t.device, t.trim, t.blocked, t.known) == ("/", "ext4", "nvme0n1p2", "weekly", "", "")
    assert [(x.name, x.kind) for x in t.layers] == [("nvme0n1p2", "partition"), ("nvme0n1", "disk")]
    assert (t.drives[0].model, t.drives[0].firmware, t.drives[0].transport) == ("Example SSD 1TB", "1B2QEXM7", "nvme")
    assert t.folder == root / "home/alice/.local/share/daprivacyscanner/trim-test" and t.size == DEVICE_SIZE
    env = {e["label"]: e["value"] for e in T.environment(t)}
    assert env["Storage"] == "partition nvme0n1p2 → drive nvme0n1" and env["TRIM runs"] == "once a week (fstrim.timer)"


def test_known_answers_without_testing(root):
    make_storage(root, luks="no-discards")
    [t] = T.targets(host_for(root))
    assert t.encrypted and "isn't opened with discards allowed" in t.known and t.folder is None
    make_storage(root, rotational="1")
    (root / "proc/self/mounts").write_text("/dev/nvme0n1p2 / ext4 rw 0 0\n")
    [t] = T.targets(host_for(root))
    assert "hard disk" in t.known
    make_storage(root, discard_max="0")
    [t] = T.targets(host_for(root))
    assert "the drive doesn't take TRIM" in t.known


def test_a_filesystem_never_trimmed_is_told_this_trim_is_its_first(root):
    make_storage(root)
    [t] = T.targets(host_for(root, {"systemctl is-enabled fstrim.timer": "disabled\n"}))
    assert t.trim == "none" and any("probably this filesystem's first" in n for n in t.notes)
    [t] = T.targets(host_for(root))
    assert t.trim == "weekly" and not any("first" in n for n in t.notes)


def test_what_cant_be_tested(root):
    make_storage(root)
    (root / "proc/self/mounts").write_text("/dev/nvme0n1p2 / xfs rw 0 0\n")
    assert "Only ext4 and btrfs" in T.targets(host_for(root))[0].blocked
    (root / "proc/self/mounts").write_text("/dev/nvme0n1p2 / ext4 rw 0 0\n/home/alice/.Private /home/alice ecryptfs rw 0 0\n")
    ts = T.targets(host_for(root))
    assert [t.mount for t in ts] == ["/", "/home/alice"] and "eCryptfs" in ts[1].blocked


# ------------------------------------------------------------------ whole runs, on a simulated disk

class SimDisk:
    """A fake privileged helper whose device shows the test folder's files, as a disk would: what
    is in them, at aligned places, and a directory block with their names. After fstrim the
    deleted files' data is gone (`trims`) or still there; names stay (as ext4 leaves them) unless
    `names_go`. `hide_small` keeps the small files off the disk (as compression or file-level
    encryption would change them)."""

    def __init__(self, root, folder, trims=True, names_go=False, hide_small=False, discards=True, keep_small=False):
        self.fake = FakePrivileged()
        self.root, self.folder, self.dev = root, folder, root / "dev/nvme0n1p2"
        self.trims, self.names_go, self.hide_small, self.discards = trims, names_go, hide_small, discards
        self.keep_small = keep_small                # small files in records the filesystem still uses (btrfs inline)
        self.kept: dict[str, bytes] = {}           # deleted, not trimmed
        self.names: set[str] = set()
        self.seen: dict[str, bytes] = {}
        self.calls = []

    def refresh(self) -> None:
        now = {}
        if self.folder.is_dir():
            for p in sorted(self.folder.iterdir()):
                now[p.name] = p.read_bytes()
        for name in set(self.seen) - set(now):
            self.kept[name] = self.seen.pop(name)            # deleted since: on the disk until trimmed
        self.seen.update(now)
        self.names |= set(now)
        if self.names_go:
            self.names = set(now)
        blobs = list(now.items()) + [(k, v) for k, v in self.kept.items() if k not in now]
        with open(self.dev, "r+b") as f:
            f.seek(0)
            f.write(bytes(DEVICE_SIZE))
            pos = 1 << 20
            for name, data in sorted(blobs):
                if self.hide_small and len(data) < 2048:
                    continue
                f.seek(pos)
                f.write(data)
                pos += -(-len(data) // 4096) * 4096
            f.seek(4096)
            f.write(b"".join(n.encode() + b"\0" for n in sorted(self.names)))

    def call(self, action, args, timeout=None):
        self.calls.append(action)
        if action == "trim_scan" and args["offset"] == 0:
            self.refresh()
        if action == "trim_fstrim":
            self.refresh()
            if self.trims:
                self.kept = {k: v for k, v in self.kept.items() if self.keep_small and len(v) < 2048}
            if self.discards:
                stat = self.root / "sys/devices/pci0000:00/nvme/nvme0/nvme0n1/stat"
                f = stat.read_text().split()
                f[13] = str(int(f[13]) + 1000)
                stat.write_text(" ".join(f) + "\n")
            return {"trimmed": 123456789}
        return self.fake.call(action, args)


@pytest.fixture
def small(monkeypatch):
    monkeypatch.setattr(T, "DATA", (64 << 10,) * 2 + (256 << 10,))
    monkeypatch.setattr(T, "TEST_BYTES", sum(T.SMALL) + sum(T.DATA))
    monkeypatch.setattr(T, "SPARE", 0)
    monkeypatch.setattr(T, "LATER", 0)


def run(root, sim=None, job=None, fstype="ext4", **kw):
    make_storage(root, fstype=fstype)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = sim or SimDisk(root, folder, **kw)
    job = job if job is not None else {}
    return T.run(host, "/", lambda: sim, job, sleep=lambda s: None), sim, folder


def test_a_drive_that_drops_what_was_trimmed_passes(root, small):
    r, sim, folder = run(root)
    assert r["verdict"] == "pass" and r["headline"].startswith("TRIM works on this drive")
    lines = {x["label"]: x["value"] for x in r["lines"]}
    assert lines["Test data read back after deleting"].startswith("0 of ")
    n = len(T.SMALL) + len(T.DATA)
    assert lines["Deleted file names still on the disk"] == f"{n} of {n}"
    assert lines["TRIM that reached the drive"] == "512.0 kB"
    text = " ".join(r["explanation"])
    assert "nobody can read it back by plugging this drive in:" in text and "once a week" in text
    assert "flash chips" in text and "This disk isn't encrypted" in text
    assert "Encryption is what protects file names" in text and "Deleted file names tool" in text
    assert sim.calls.count("trim_result") == 2                 # clean on a drive that promises zeros: no later rescan
    assert not folder.exists() and sim.calls[-1] == "trim_end"
    assert "TRIM test: TRIM works" in r["text"] and "Environment:" in r["text"]


def test_a_drive_that_keeps_deleted_data_fails_when_it_promises_zeros(root, small):
    r, sim, folder = run(root, trims=False)
    assert r["verdict"] == "fail" and "could still be read back" in r["headline"]
    assert sim.calls.count("trim_result") == 3                 # a later rescan, in case it was still working on it
    assert r["offsets"] and not folder.exists()


def test_when_the_drive_promises_nothing_survivors_are_inconclusive(root, small, monkeypatch):
    monkeypatch.setattr(helper, "NVME_ADMIN", nvme(dlfeat=0))                  # DLFEAT not reported
    r, sim, _ = run(root, trims=False)
    assert r["verdict"] == "inconclusive" and "can't be told" in r["headline"]
    monkeypatch.setattr(helper, "_TRIM", {})
    r, sim, _ = run(root)
    assert r["verdict"] == "pass" and r["headline"].startswith("None of the deleted test data")
    assert any("not a promise for later reads" in p for p in r["explanation"])
    assert sim.calls.count("trim_result") == 3


def test_no_discards_reaching_the_drive_is_a_failure(root, small):
    r, *_ = run(root, trims=False, discards=False)
    assert r["verdict"] == "fail" and any("received no TRIM" in p for p in r["explanation"])


def test_names_that_go_with_trim(root, small):
    r, *_ = run(root, names_go=True)
    assert any(p.startswith("None of the deleted test files' names") for p in r["explanation"])


def test_bad_sectors_the_whole_time_leave_a_pass_standing_with_a_warning(root, small, monkeypatch):
    eio_at(monkeypatch, [[3 << 20, 65536]])                  # away from where the simulated disk puts the files
    r, sim, _ = run(root)
    assert r["verdict"] == "pass"
    assert any(x["label"] == "Parts of the disk the drive couldn't read" and x["value"] == "65.5 kB" for x in r["lines"])
    assert any("failing sectors" in x for x in r["explanation"])
    assert any("unreadable before the test too" in x for x in r["explanation"])
    assert "sudo smartctl -a /dev/nvme0n1" in r["commands"]


def test_bad_sectors_appearing_after_the_trim_make_a_pass_inconclusive(root, small, monkeypatch):
    state = {"trimmed": False}
    eio_at(monkeypatch, [[3 << 20, 65536]], when=lambda: state["trimmed"])
    make_storage(root)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = SimDisk(root, folder)
    real = sim.call

    def failing_after_trim(action, args, timeout=None):
        out = real(action, args, timeout)
        if action == "trim_fstrim":
            state["trimmed"] = True
        return out
    sim.call = failing_after_trim
    r = T.run(host, "/", lambda: sim, {}, sleep=lambda s: None)
    assert r["verdict"] == "inconclusive" and "readable before the trim" in r["headline"]
    assert any("could be hiding there" in x for x in r["explanation"])


def test_a_baseline_that_cant_read_parts_of_the_disk_says_the_files_may_be_there(root, small, monkeypatch):
    eio_at(monkeypatch, [[1 << 20, 1 << 20]])                # where the simulated disk puts the files
    r, sim, folder = run(root)
    assert r["verdict"] == "inconclusive" and "couldn't find its own files" in r["headline"]
    assert any("may lie in those parts" in x for x in r["explanation"])
    assert "trim_fstrim" not in sim.calls and not folder.exists()


def test_the_job_lists_every_step_with_its_state_and_estimates(root, small):
    job = {}
    r, sim, _ = run(root, job=job)                            # zeros drive, clean first rescan: no wait, no last pass
    states = {st["id"]: st["state"] for st in job["steps"]}
    assert states == {"begin": "done", "write": "done", "baseline": "done", "trim": "done", "after": "done",
                      "wait": "skipped", "later": "skipped", "remove": "done"}
    by = {st["id"]: st for st in job["steps"]}
    assert all(st["started"] is not None and st["finished"] is not None for st in job["steps"] if st["state"] == "done")
    assert by["baseline"]["total"] == DEVICE_SIZE and by["after"]["done"] == DEVICE_SIZE
    assert by["after"]["estimate"] is not None and by["wait"]["estimate"] == T.LATER
    assert [st["optional"] for st in job["steps"]].count(True) == 2

    job = {}
    run(root, job=job, trims=False)                           # survivors: the wait and the last pass happen
    states = {st["id"]: st["state"] for st in job["steps"]}
    assert states["wait"] == "skipped" and states["later"] == "done"      # LATER is 0 here: nothing to wait for

    job = {}
    run(root, job=job, hide_small=True)                       # the baseline misses files: nothing after it
    states = {st["id"]: st["state"] for st in job["steps"]}
    assert states["baseline"] == "done" and states["remove"] == "done"
    assert all(states[k] == "skipped" for k in ("trim", "after", "wait", "later"))


def test_a_baseline_that_misses_files_stops_before_deleting(root, small):
    r, sim, folder = run(root, hide_small=True)
    assert r["verdict"] == "inconclusive" and "couldn't find its own files" in r["headline"]
    assert "trim_fstrim" not in sim.calls and not folder.exists()
    assert r["names_mount"] == "/" and any("Deleted file names tool" in x for x in r["explanation"])   # the tool still helps


def test_on_btrfs_small_files_stored_compressed_go_untested_and_the_data_is_tested(root, small, monkeypatch):
    """compress=zstd (CachyOS's default): the inline files shrink and can't be recognised, so the
    test asks for no compression on its folder, and when they still can't be found it goes on with
    the data files rather than stopping."""
    marked = []
    monkeypatch.setattr(T, "NO_COMPRESSION", lambda folder: marked.append(folder.name) or True)
    r, sim, folder = run(root, fstype="btrfs", hide_small=True)
    assert marked == ["trim-test"] and "trim_fstrim" in sim.calls and not folder.exists()
    assert r["verdict"] == "pass"
    lines = {x["label"]: x["value"] for x in r["lines"]}
    assert lines["Test data read back after deleting"] == "0 of 768 blocks"
    assert lines["Small files read back"] == "0 of 0 blocks (6 more couldn't be tested)"
    assert any("couldn't be recognised on the disk even before they were deleted" in x and "compress-force overrides" in x
               for x in r["explanation"])
    marked.clear()
    run(root, hide_small=True)                               # ext4: no compression to turn off, and missing blocks stop it
    assert marked == []


def test_no_compression_flag_is_asked_for_without_failing_where_unsupported(tmp_path):
    assert isinstance(T._no_compression(tmp_path), bool)
    assert T._no_compression(tmp_path / "missing") is False


def test_stopping_removes_the_test_files(root, small):
    make_storage(root)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = SimDisk(root, folder)
    job = {}
    real = sim.call

    def stop_on_scan(action, args, timeout=None):
        if action == "trim_scan":
            job["cancel"] = True
        return real(action, args, timeout)
    sim.call = stop_on_scan
    with pytest.raises(T.Stopped):
        T.run(host, "/", lambda: sim, job)
    assert not folder.exists() and "trim_fstrim" not in sim.calls


def test_losing_administrator_access_stops_it(root, small):
    make_storage(root)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = SimDisk(root, folder)
    given = iter([sim, sim])
    with pytest.raises(T.Stopped, match="Administrator access ended"):
        T.run(host, "/", lambda: next(given, None), {})
    assert not folder.exists()


def test_losing_access_during_the_wait_stops_it_at_once(root, small, monkeypatch):
    """The app quit (or Drop) while the test waited for the drive: it stops within a second, not
    after the wait, so the process and the test folder don't linger."""
    monkeypatch.setattr(T, "LATER", 3600)
    make_storage(root)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = SimDisk(root, folder, trims=False)     # survivors: the test waits for a second rescan
    state = {"gone": False}
    slept = []

    def sleep(s):
        slept.append(s)
        state["gone"] = True                     # access dropped during the wait
    with pytest.raises(T.Stopped, match="Administrator access ended"):
        T.run(host, "/", lambda: None if state["gone"] else sim, {}, sleep=sleep)
    assert len(slept) == 1 and not folder.exists()


def test_leftovers_are_removed_and_nothing_else(root):
    host = host_for(root)
    folder = T.candidates(host)[0]
    folder.mkdir(parents=True)
    (folder / ("a" * 20)).write_bytes(b"x")
    (folder / "notes.txt").write_text("mine")
    assert T.leftovers(host) == ["~/.local/share/daprivacyscanner/trim-test"]
    assert (folder / "notes.txt").exists() and not (folder / ("a" * 20)).exists()
    (folder / "notes.txt").unlink()
    assert T.leftovers(host) == [] and not folder.exists()


# ------------------------------------------------------------------ the server

def test_the_server_runs_it_as_a_job(cat, root, small, monkeypatch):
    make_storage(root)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = SimDisk(root, folder)
    sim.alive = lambda: True
    sim.close = lambda: None
    with TestClient(create_app("t", cat, make_host=lambda: host, start_helper=lambda: sim)) as c:
        d = c.get("/api/tools/trim", headers=H).json()
        assert [t["mount"] for t in d["targets"]] == ["/"] and d["job"] is None and d["leftovers"] == []
        assert c.post("/api/tools/trim/start", headers=H, json={}).status_code == 400
        job = c.post("/api/tools/trim/start", headers=H, json={"mount": "/"}).json()["job"]
        for _ in range(1000):
            job = c.get("/api/tools/trim", headers=H).json()["job"]
            if job["state"] not in ("asking", "running"):
                break
            time.sleep(0.01)
        assert job["state"] == "done" and job["result"]["verdict"] == "pass", job
        assert c.get("/api/tools/trim", headers=H).json()["admin_active"]
        assert c.post("/api/tools/trim/dismiss", headers=H).json()["job"] is None


def test_held_access_outlasts_idle_time_and_scans():
    class P:
        def alive(self):
            return True

        def close(self):
            pass
    a = AdminSession(lambda: P(), idle=0)
    assert a.get(True) is not None and not a.active()                  # idle at once without a hold
    a.get(True)
    with a.hold():
        assert a.active() and a.held()
        time.sleep(0.01)
        assert a.active()
    assert not a.held()


def test_on_an_encrypted_disk_a_pass_holds_even_with_the_key(root, small):
    make_storage(root, luks=True)
    host = host_for(root)
    folder = T.candidates(host)[0]
    sim = SimDisk(root, folder)
    sim.dev = root / "dev/dm-0"                                # the decrypted device is the one read
    r = T.run(host, "/", lambda: sim, {}, sleep=lambda s: None)
    text = " ".join(r["explanation"])
    assert r["verdict"] == "pass" and "even with your encryption key" in text
    assert "if they also have your encryption key" in text and "can be read only with your key" in text


def test_btrfs_small_files_kept_in_its_own_records_are_told_apart(root, small, monkeypatch):
    made = []
    monkeypatch.setattr(T, "SUBVOLUME", lambda parent, name: (parent / name).mkdir() or made.append(name) or True)
    r, sim, folder = run(root, fstype="btrfs", keep_small=True, names_go=True)
    lines = {x["label"]: x["value"] for x in r["lines"]}
    assert r["verdict"] == "pass" and lines["Small files read back"] == "6 of 6 blocks" and made == ["trim-test"]
    assert any(p.startswith("btrfs keeps small files") for p in r["explanation"])
    assert not any("couldn't be made a subvolume" in p for p in r["explanation"]) and not folder.exists()
    env = {e["label"]: e["value"] for e in r["environment"]}
    assert env["Mount options"] == "max_inline=2048 (default)"


def test_on_ext4_small_files_count_as_data(root, small):
    r, *_ = run(root, keep_small=True)
    lines = {x["label"]: x["value"] for x in r["lines"]}
    assert "Small files read back" not in lines and r["verdict"] == "fail"


# ------------------------------------------------------------------ in a virtual machine: no test

def test_a_virtual_machine_gets_its_answer_without_a_test(root):
    make_storage(root)
    [t] = T.targets(host_for(root, {"systemd-detect-virt --vm": "kvm\n"}))
    assert "virtual machine" in t.known and "on the host" in t.known and t.folder is None


# ------------------------------------------------------------------ does the drive encrypt what it stores?

def test_nvme_crypto_erase_and_tcg_discovery(root, monkeypatch):
    make_storage(root)
    opal = level0((0x0001, bytes(12)), (0x0002, bytes([0x09]) + bytes(11)), (0x0203, bytes(16)))
    monkeypatch.setattr(helper, "NVME_ADMIN", nvme(sanicap=1, fna=4, oacs=1, level0=opal))
    [d] = call("trim_begin", mount="/")["drives"]
    e = d["encryption"]
    assert e["crypto_erase"] and e["crypto_erase_by"] == ["sanitize", "format"] and e["encrypts_all"] is None
    assert e["tcg"] == {"ssc": ["Opal 2"], "encrypting_ssc": True, "media_encryption": True, "locking_enabled": False}
    text = T.drive_encryption_text({"drives": [d]})
    assert "helps against chip-off recovery" in text and "KB4516071" in text and "never instead of it" in text
    assert "Opal 2 and reports media encryption" in T.encryption_line(e)


def test_pyrite_and_no_crypto_erase_say_nothing_of_encryption(root, monkeypatch):
    make_storage(root)
    pyrite = level0((0x0002, bytes([0x01]) + bytes(11)), (0x0303, bytes(16)))
    monkeypatch.setattr(helper, "NVME_ADMIN", nvme(oacs=1, level0=pyrite))
    [d] = call("trim_begin", mount="/")["drives"]
    text = T.drive_encryption_text({"drives": [d]})
    assert text.startswith("Nothing the drive reports says it encrypts") and "locking without encryption" in text
    assert helper.parse_level0(bytes(512)) is None                           # an empty answer lists nothing


SMARTCTL = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.8.0] (local build)

=== START OF INFORMATION SECTION ===
=== START OF READ SMART DATA SECTION ===
ATA IDENTIFY DEVICE data:

Word     Bit   Value   Description
  0      -    0x0040  General configuration
 59      -    0x3110  Sanitize/sectors per interrupt
 69      -    0x4030  Additional support
169      -    0x0001  Data set management
"""


def test_sata_identify_words_through_smartctl(root, monkeypatch):
    seen = []

    def run(argv):
        seen.append(argv[0])
        return (0, SMARTCTL, "") if argv[0] == "smartctl" else (127, "", "")
    monkeypatch.setattr(helper, "RUN", run)
    f = helper._drive_facts("sda")
    e = f["encryption"]
    assert f["behaviour"] == "zeros" and e["encrypts_all"] and e["crypto_erase"]
    assert any("sedutil isn't installed" in n for n in e["notes"]) and seen == ["smartctl", "sedutil-cli"]
    assert "identify data says it encrypts all user data" in T.encryption_line(e)


def test_sata_without_smartmontools_falls_back_to_hdparm(root, monkeypatch):
    hdparm = ("\t   *\tData Set Management TRIM supported (limit 8 blocks)\n\t   *\tDeterministic read data after TRIM\n"
              "\t   *\tSANITIZE feature set\n\t   *\tBLOCK_ERASE_EXT command\n")
    monkeypatch.setattr(helper, "RUN", lambda argv: (0, hdparm, "") if argv[0] == "hdparm" else
                        (1, "", "") if argv[0] == "sedutil-cli" else (127, "", ""))
    f = helper._drive_facts("sda")
    e = f["encryption"]
    assert f["behaviour"] == "deterministic" and e["encrypts_all"] is None and e["crypto_erase"] is False
    assert any("smartmontools" in n for n in e["notes"]) and any("libata.allow_tpm=1" in n for n in e["notes"])


def test_sedutil_query_wording():
    text = ("/dev/sda ATA Samsung SSD 860 EVO\nTPer function (0x0001)\n    ACKNAK = N\n"
            "Locking function (0x0002)\n    Locked = N, LockingEnabled = N, LockingSupported = Y, MBRDone = N, "
            "MBREnabled = N, MediaEncrypt = Y\nOpal V2 function (0x0203)\n")
    assert helper.parse_sedutil_query(text) == {"ssc": ["Opal 2"], "encrypting_ssc": True, "media_encryption": True,
                                                "locking_enabled": False}
    assert helper.parse_sedutil_query("Invalid or unsupported disk /dev/sda\n") is None


def test_the_result_says_how_to_trim_by_hand(root, small):
    r, *_ = run(root)
    assert r["commands"] == ["sudo fstrim -av"] and any("sudo fstrim -av" in p for p in r["explanation"])
    assert any(e["label"] == "Encryption in nvme0n1" for e in r["environment"])
    assert r["names_mount"] == "/"                              # the home is on this filesystem: the tool can look


# ------------------------------------------------------------------ names of deleted files: parsing

def dirent(ino, name, rec_len, ftype=1):
    return struct.pack("<IHBB", ino, rec_len, len(name), ftype) + name


def ext4_block(entries, size=4096):
    b = bytearray(size)
    for off, data in entries:
        b[off:off + len(data)] = data
    return bytes(b)


def test_ext4_deleted_entries_are_found_where_deleting_leaves_them():
    block = ext4_block([(0, dirent(2, b".", 12, 2)), (12, dirent(2, b"..", 12, 2)),
                        (24, dirent(12, b"keep.txt", 4096 - 24)),            # grew over the two after it
                        (40, dirent(13, b"secret-plan.odt", 24)), (64, dirent(14, b"tax 2025.pdf", 4032))])
    assert helper.parse_ext4_dir_block(block) == {b"secret-plan.odt", b"tax 2025.pdf"}
    first = ext4_block([(0, dirent(0, b"gone.txt", 4096))])                  # the first entry: its inode zeroed
    assert helper.parse_ext4_dir_block(first) == {b"gone.txt"}
    index = ext4_block([(0, struct.pack("<IHBB", 0, 4096, 0, 0)), (40, dirent(13, b"looks-like-a-name", 28))])
    assert helper.parse_ext4_dir_block(index) == set()                      # an htree index block
    root_block = ext4_block([(0, dirent(2, b".", 12, 2)), (12, dirent(2, b"..", 4084, 2)),
                             (40, dirent(13, b"index-bytes", 20))])
    assert helper.parse_ext4_dir_block(root_block, skip_index=True) == set()


def test_crc32c():
    assert helper._crc32c(b"123456789") == 0xE3069283


FSID = bytes(range(16, 32))


def dir_item(name, typ=1):
    return struct.pack("<QBQQHHB", 300, 1, 0, 7, 0, len(name), typ) + name


def btrfs_leaf(owner, items, stale=(), node=16384):
    """A leaf of the `owner` tree holding DIR_INDEX items (folder inode, name), and stale headers
    past them pointing at stale data in its free space; crc32c checksum."""
    b = bytearray(node)
    b[32:48], b[88:96], b[96:100], b[100] = FSID, owner.to_bytes(8, "little"), len(items).to_bytes(4, "little"), 0
    off = node - 101
    for i, (ino, name) in enumerate(list(items) + list(stale)):
        data = dir_item(name)
        off -= len(data) + (64 if i >= len(items) else 0)
        b[101 + off:101 + off + len(data)] = data
        struct.pack_into("<QBQII", b, 101 + 25 * i, ino, helper.BTRFS_DIR_INDEX, i + 2, off, len(data))
    b[0:4] = helper._crc32c(bytes(b[32:])).to_bytes(4, "little")
    return bytes(b)


def test_btrfs_leaves_give_their_folder_entries_stale_ones_too():
    fs = {"fsid": FSID, "nodesize": 16384, "sectorsize": 4096, "csum": 0}
    leaf = btrfs_leaf(5, [(257, b"kept.txt")], stale=[(257, b"old-diary.txt")])
    assert helper.parse_btrfs_leaf(leaf, fs, {5}) == [(5, 257, b"kept.txt"), (5, 257, b"old-diary.txt")]
    assert helper.parse_btrfs_leaf(leaf, fs, {6}) == []                       # another subvolume's tree
    broken = bytearray(leaf)
    broken[5000] ^= 1
    assert helper.parse_btrfs_leaf(bytes(broken), fs, {5}) == []              # a wrong checksum
    sb = bytearray(4096)
    sb[0x20:0x30], sb[0x40:0x48] = FSID, b"_BHRfS_M"
    sb[0x90:0x94], sb[0x94:0x98] = (4096).to_bytes(4, "little"), (16384).to_bytes(4, "little")
    assert helper.parse_btrfs_superblock(bytes(sb)) == fs


# ------------------------------------------------------------------ names of deleted files: on a fixture disk

def home_folders(root):
    home = root / "home/alice"
    (home / "Documents").mkdir(parents=True)
    (home / "Documents/keep.txt").write_text("x")
    (home / ".cache/app").mkdir(parents=True)
    outside = root / "elsewhere"
    outside.mkdir()
    os.symlink(outside, home / "link")
    return home


def test_ext4_names_of_files_gone_from_folders_the_user_owns(root, monkeypatch):
    dev = make_storage(root)
    home = home_folders(root)
    places = {os.stat(home / "Documents").st_ino: 1 << 20, os.stat(home / ".cache/app").st_ino: 2 << 20,
              os.stat(root / "elsewhere").st_ino: 3 << 20}
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(places[os.fstat(fd).st_ino], 4096)]
                        if os.fstat(fd).st_ino in places else [])
    with open(dev, "r+b") as f:
        f.seek(1 << 20)
        f.write(ext4_block([(0, dirent(2, b".", 12, 2)), (12, dirent(2, b"..", 12, 2)),
                            (24, dirent(12, b"keep.txt", 4072)), (40, dirent(13, b"secret-plan.odt", 24)),
                            (64, dirent(14, b"keep.txt", 20))]))           # an older entry of a file still there
        f.seek(2 << 20)
        f.write(ext4_block([(0, dirent(0, b"tmp-1234", 4096))]))
        f.seek(3 << 20)
        f.write(ext4_block([(0, dirent(0, b"not-mine.txt", 4096))]))
    b = call("names_begin", mount="/")
    assert b["unit"] == "folders" and b["folders"] == 4 and b["total"] == 2
    while call("names_step")["done"] < b["total"]:
        pass
    r = call("names_result")
    assert r["folders"] == [{"path": ".cache/app", "names": ["tmp-1234"]},
                            {"path": "Documents", "names": ["secret-plan.odt"]}] and r["count"] == 2
    with pytest.raises(helper.Refused):                                    # forgotten once handed over
        call("names_result")


def test_names_in_folder_blocks_the_drive_cant_read_are_counted_as_missing(root, monkeypatch):
    dev = make_storage(root)
    home = home_folders(root)
    places = {os.stat(home / "Documents").st_ino: 1 << 20, os.stat(home / ".cache/app").st_ino: 2 << 20}
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(places[os.fstat(fd).st_ino], 4096)]
                        if os.fstat(fd).st_ino in places else [])
    with open(dev, "r+b") as f:
        f.seek(1 << 20)
        f.write(ext4_block([(0, dirent(0, b"secret-plan.odt", 4096))]))
        f.seek(2 << 20)
        f.write(ext4_block([(0, dirent(0, b"tmp-1234", 4096))]))
    eio_at(monkeypatch, [[2 << 20, 4096]])
    b = call("names_begin", mount="/")
    while call("names_step")["done"] < b["total"]:
        pass
    r = call("names_result")
    assert r["folders"] == [{"path": "Documents", "names": ["secret-plan.odt"]}] and r["unreadable"] == 4096


def test_btrfs_names_from_the_home_subvolumes_tree(root, monkeypatch):
    dev = make_storage(root, fstype="btrfs")
    home = home_folders(root)
    docs = os.stat(home / "Documents").st_ino
    monkeypatch.setattr(helper, "BTRFS_TREE_ID", lambda fd: 5)
    sb = bytearray(4096)
    sb[0x20:0x30], sb[0x40:0x48] = FSID, b"_BHRfS_M"
    sb[0x90:0x94], sb[0x94:0x98] = (4096).to_bytes(4, "little"), (16384).to_bytes(4, "little")
    with open(dev, "r+b") as f:
        f.seek(helper.BTRFS_SUPER)
        f.write(sb)
        f.seek(1 << 20)                                       # an old copy, freed and not yet trimmed
        f.write(btrfs_leaf(5, [(docs, b"keep.txt"), (docs, b"old-diary.txt")]))
        f.seek(3 << 20)
        f.write(btrfs_leaf(5, [(docs, b"keep.txt")], stale=[(docs, b"letter.odt")]))
        f.seek((4 << 20) - 16384)
        f.write(btrfs_leaf(9, [(docs, b"other-subvolume.txt")]))
    b = call("names_begin", mount="/")
    assert b["unit"] == "bytes" and b["total"] == DEVICE_SIZE
    while call("names_step")["done"] < b["total"]:
        pass
    assert call("names_result")["folders"] == [{"path": "Documents", "names": ["letter.odt", "old-diary.txt"]}]


def test_names_when_the_home_is_a_subvolume_of_the_system_disk(root, monkeypatch):
    """Fedora, openSUSE and Timeshift layouts: / and /home are subvolumes of one device, and the
    test (deduplicated by device) names "/": the home's folders are still what is listed."""
    dev = make_storage(root, fstype="btrfs")
    with open(root / "proc/self/mounts", "a") as f:
        f.write("/dev/nvme0n1p2 /home btrfs rw,subvol=/@home 0 0\n")
    home = home_folders(root)
    docs = os.stat(home / "Documents").st_ino
    monkeypatch.setattr(helper, "BTRFS_TREE_ID", lambda fd: 5)
    sb = bytearray(4096)
    sb[0x20:0x30], sb[0x40:0x48] = FSID, b"_BHRfS_M"
    sb[0x90:0x94], sb[0x94:0x98] = (4096).to_bytes(4, "little"), (16384).to_bytes(4, "little")
    with open(dev, "r+b") as f:
        f.seek(helper.BTRFS_SUPER)
        f.write(sb)
        f.seek(1 << 20)
        f.write(btrfs_leaf(5, [(docs, b"old-diary.txt")]))
    assert [t.mount for t in T.targets(host_for(root))] == ["/"]
    b = call("names_begin", mount="/")
    assert b["scope"] == "home" and b["root"] == "/home/alice"
    while call("names_step")["done"] < b["total"]:
        pass
    assert call("names_result")["folders"] == [{"path": "Documents", "names": ["old-diary.txt"]}]


# ------------------------------------------------------------------ other disks: a second SSD, an external one

def add_data_disk(root, target="/mnt/data", fstype="ext4", writable=True):
    """sdb1, mounted at `target`, a SATA SSD."""
    with open(root / "proc/self/mounts", "a") as f:
        f.write(f"/dev/sdb1 {target} {fstype} rw,relatime 0 0\n")
    disk = root / "sys/devices/pci0000:00/ata2/sdb"
    write(disk / "queue/discard_max_bytes", "2147450880\n")
    write(disk / "queue/rotational", "0\n")
    write(disk / "device/vendor", "ATA     \n")
    write(disk / "device/model", "Data SSD\n")
    write(disk / "sdb1/partition", "1\n")
    write(disk / "sdb1/size", str(DEVICE_SIZE // 512) + "\n")
    link(root / "sys/class/block/sdb", "../../devices/pci0000:00/ata2/sdb")
    link(root / "sys/class/block/sdb1", "../../devices/pci0000:00/ata2/sdb/sdb1")
    link(root / "sys/block/sdb", "../devices/pci0000:00/ata2/sdb")
    with open(root / "dev/sdb1", "wb") as f:
        f.truncate(DEVICE_SIZE)
    top = root / target.lstrip("/")
    top.mkdir(parents=True, exist_ok=True)
    top.chmod(0o755 if writable else 0o555)
    return top


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write whatever the mode")
def test_other_disks_are_offered_when_the_user_can_write_to_them(root, monkeypatch):
    make_storage(root)
    top = add_data_disk(root)
    monkeypatch.setattr(helper, "RUN", lambda argv: (127, "", ""))
    ts = T.targets(host_for(root))
    assert [t.mount for t in ts] == ["/", "/mnt/data"]
    assert ts[1].folder == top / f".daprivacyscanner-trim-test-{ME[0]}" and not ts[1].blocked
    assert call("trim_begin", mount="/mnt/data")["device"] == "/dev/sdb1"
    top.chmod(0o555)
    assert "can't create files at the top of /mnt/data" in T.targets(host_for(root))[1].blocked
    with pytest.raises(helper.Refused, match="you can write to"):
        call("trim_begin", mount="/mnt/data")


@pytest.mark.skipif(os.geteuid() == 0, reason="root can open whatever the mode")
def test_names_on_another_disk_cover_the_folders_the_user_can_open(root, monkeypatch):
    make_storage(root)
    top = add_data_disk(root)
    (top / "Photos").mkdir()
    (top / "locked").mkdir()
    places = {os.stat(top).st_ino: 1 << 20, os.stat(top / "Photos").st_ino: 2 << 20,
              os.stat(top / "locked").st_ino: 3 << 20}
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(places[os.fstat(fd).st_ino], 4096)])
    with open(root / "dev/sdb1", "r+b") as f:
        for off, name in ((1 << 20, b"old-backup.tar"), (2 << 20, b"IMG_0001.jpg"), (3 << 20, b"private.txt")):
            f.seek(off)
            f.write(ext4_block([(0, dirent(0, name, 4096))]))
    (top / "locked").chmod(0o000)
    try:
        b = call("names_begin", mount="/mnt/data")
        assert b["scope"] == "mount" and b["folders"] == 2
        while call("names_step")["done"] < b["total"]:
            pass
        r = call("names_result")
    finally:
        (top / "locked").chmod(0o755)
    assert r["folders"] == [{"path": "", "names": ["old-backup.tar"]}, {"path": "Photos", "names": ["IMG_0001.jpg"]}]
    assert r["scope"] == "mount" and r["root"] == "/mnt/data"


def test_the_system_disk_outside_the_home_isnt_listed(root):
    make_storage(root)
    with open(root / "proc/self/mounts", "a") as f:
        f.write("/dev/nvme0n1p3 /home ext4 rw 0 0\n")
    with pytest.raises(helper.Refused, match="only your home folder's names"):
        call("names_begin", mount="/")
