"""Names that aren't UTF-8 where the system hands over bytes (found with ruff's PLW1514, 2026-11-12): a process's
name (comm, in /proc/PID/stat and status), which any account can set to anything, and a mount point, which can be any
bytes but the four the kernel escapes (another account's FUSE mount, a stick's label). Read as text in the strict
default, one such name raised UnicodeDecodeError, which the code around it didn't catch: a process given an undo
entry's old number broke reading the undo log, one given a viewer's broke the list of running viewers, and one mount
point anywhere in the mount table broke deleting a folder whole and the rebuild's look at other mount views."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from daprivacyscanner import fix as F
from daprivacyscanner import undo
from daprivacyscanner.tools import rebuild as R
from daprivacyscanner.tools import trial, viewer

from test_trimtest import home_folders, host_for, make_storage, root  # noqa: F401 - the fixture

BAD_NAME = b"bad\xff\xfe"
NAMED = ("import ctypes, sys, time\n"
         "ctypes.CDLL(None).prctl(15, ctypes.c_char_p(sys.argv[1].encode('latin-1')), 0, 0, 0)  # PR_SET_NAME\n"
         "print('ready', flush=True)\n"
         "time.sleep(60)\n")


@pytest.fixture
def badly_named():
    """A child process of this one whose name isn't UTF-8."""
    p = subprocess.Popen([sys.executable, "-c", NAMED, BAD_NAME.decode("latin-1")], stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout is not None and p.stdout.readline().strip() == "ready"
        with open(f"/proc/{p.pid}/comm", "rb") as f:
            assert f.read().rstrip(b"\n") == BAD_NAME
        yield p.pid
    finally:
        p.kill()
        p.wait()


def test_an_undo_entrys_process_with_a_name_that_isnt_utf8_is_read(badly_named):
    started = undo._started(badly_named)
    assert started.isdigit()
    assert undo._started(badly_named) == started


def test_a_viewer_with_a_name_that_isnt_utf8_is_still_listed(badly_named, monkeypatch):
    monkeypatch.setattr(viewer, "_LAUNCHED", {badly_named: "Xreader"})
    monkeypatch.setattr(viewer, "_DISPLAYS", {badly_named: badly_named})
    assert viewer.launched() == {badly_named: "Xreader"}


def test_a_process_with_a_name_that_isnt_utf8_is_walked_past_looking_for_stay(badly_named):
    # a descendant of this process, as the sandbox's processes are of a trial's command: its stat read (it was skipped,
    # the decoding error caught as a ValueError) and then its status, which holds the same name, without an error
    assert trial._stay_of(os.getpid()) is None


def test_a_mount_point_that_isnt_utf8_is_matched_as_paths_are(tmp_path, monkeypatch):
    table = tmp_path / "mounts"
    table.write_bytes(b"/dev/sda1 /media/alice/Caf\xe9 vfat rw 0 0\n/dev/sdb1 /media/alice/USB\\040stick vfat rw 0 0\n")
    monkeypatch.setattr(F, "MOUNT_TABLE", str(table))
    assert F.DeleteFiles._mounted_under(Path(os.fsdecode(b"/media/alice/Caf\xe9")))
    assert F.DeleteFiles._mounted_under(Path("/media/alice"))
    assert F.DeleteFiles._mounted_under(Path("/media/alice/USB stick"))
    assert not F.DeleteFiles._mounted_under(Path("/media/alice/Cafe"))


def test_another_view_with_a_mount_point_that_isnt_utf8_is_still_read(root, monkeypatch):  # noqa: F811 - the fixture
    make_storage(root)
    home = home_folders(root)
    st = os.stat(home / "Documents")
    dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    (root / "proc/self/ns").mkdir(parents=True)
    os.symlink("mnt:[4026531841]", root / "proc/self/ns/mnt")
    (root / "proc/self/mountinfo").write_bytes(f"22 1 {dev} / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n"
                                               .encode() + b"23 22 0:40 / /media/alice/Caf\xe9 rw - vfat /dev/sda1 rw\n")
    p = root / "proc/600"
    (p / "ns").mkdir(parents=True)
    (p / "comm").write_text("org.example.Ap\n")
    os.symlink("mnt:[4026532999]", p / "ns/mnt")
    (p / "mountinfo").write_bytes(b"39 30 0:41 / /run/Caf\xe9 rw - tmpfs tmpfs rw\n" +
                                  f"40 30 {dev} /home/alice/Documents /home/alice/Documents rw - ext4 /dev/x rw\n".encode())
    assert R.bind_users(host_for(root), home / "Documents") == ["org.example.Ap"]
