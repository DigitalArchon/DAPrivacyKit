"""The RAM disk: the helper's ramdisk_open / ramdisk_close (fixture tree, fake mount calls), and the
app's side (status, who is using it, the overwrite). Nothing here mounts anything."""

from __future__ import annotations

import errno
import json
import os
import stat

import pytest

from daprivacyscanner import helper
from daprivacyscanner.tools import ramdisk as R

from conftest import make_host
from fakes import FakeSystem

ME = (os.geteuid(), os.getegid())


def xattrs_work(folder) -> bool:
    """Whether this filesystem keeps user extended attributes (the folder's memory of what to put back)."""
    try:
        os.setxattr(folder, "user.daprivacyscanner.test", b"1")
        os.removexattr(folder, "user.daprivacyscanner.test")
        return True
    except OSError:
        return False


def remembered(created: bool, mode: int | None, path: str) -> list[str]:
    import json
    import shlex
    value = json.dumps({"created": created, "folder_mode": mode})
    return [f"setfattr -n {helper.RAMDISK_XATTR} -v {shlex.quote(value)} {path}"]


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    (r / "proc").mkdir()
    (r / "proc/meminfo").write_text("MemTotal:       16384000 kB\n")
    (r / "proc/self").mkdir()
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", r / "proc/mounts")              # as on a real system: a link
    monkeypatch.setattr(helper, "ROOT", str(r))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    mounts = []

    def mount(target, flags, options):
        real = os.path.realpath(target)                      # what /proc/self/fd/N names: the folder opened
        if "noswap" in options and mount.no_noswap:
            return errno.EINVAL
        mounts.append((real, flags, options))
        with open(r / "proc/self/mounts", "a") as f:
            f.write(f"tmpfs {real[len(str(r)):]} tmpfs rw,{options}{',noexec' if flags & 8 else ''} 0 0\n")
        return 0
    mount.no_noswap = False

    def umount(target):
        if umount.busy:
            return errno.EBUSY
        lines = (r / "proc/self/mounts").read_text().splitlines()
        (r / "proc/self/mounts").write_text("".join(ln + "\n" for ln in lines if f" {target[len(str(r)):]} " not in ln))
        return 0
    umount.busy = False
    monkeypatch.setattr(helper, "MOUNT", mount)
    monkeypatch.setattr(helper, "UMOUNT", umount)
    monkeypatch.setattr(helper, "_kernel_has_noswap", lambda release=None: True)
    return r, mounts, mount, umount


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def test_mount_table_through_its_link(root):
    r, *_ = root
    assert helper._mounted_at("/") and not helper._mounted_at("/home/alice/RAMDisk")


def test_open_mounts_the_folder_it_opened_and_close_puts_it_back(root):
    r, mounts, _, _ = root
    res = call("ramdisk_open", size_mb=512, noexec=True)
    kept = remembered(True, None, "/home/alice/RAMDisk") if xattrs_work(r / "home/alice") else []
    assert res == {"path": "/home/alice/RAMDisk", "size_mb": 512, "noexec": True, "noswap": True,
                   "ran": [f"install -d -m 700 -o {ME[0]} -g {ME[1]} /home/alice/RAMDisk", *kept, "chmod 500 /home/alice/RAMDisk",
                           "mount -t tmpfs -o nosuid,nodev,noexec,size=512M,mode=0700,uid=1000,gid=1000,noswap tmpfs "
                           "/home/alice/RAMDisk"]}
    real, flags, options = mounts[0]
    assert real == str(r / "home/alice/RAMDisk")
    assert flags == helper.MS_NOSUID | helper.MS_NODEV | helper.MS_NOEXEC
    assert options == f"size=512M,mode=0700,uid={ME[0]},gid={ME[1]},noswap"
    folder = r / "home/alice/RAMDisk"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o500                 # nothing saved in it while closed
    state = r / f"run/daprivacyscanner/ramdisk/{ME[0]}.json"
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    with pytest.raises(helper.Refused, match="open already"):
        call("ramdisk_open", size_mb=512, noexec=True)
    assert call("ramdisk_close") == {"closed": True, "was_open": True,
                                     "ran": ["umount /home/alice/RAMDisk", "rmdir /home/alice/RAMDisk"]}
    assert not folder.exists() and not state.exists()                    # the helper made it, so it goes


def test_executable_and_without_noswap(root):
    r, mounts, mount, _ = root
    mount.no_noswap = True
    res = call("ramdisk_open", size_mb=100, noexec=False)
    assert res["noswap"] is False and mounts[0][1] == helper.MS_NOSUID | helper.MS_NODEV
    assert "noswap" not in mounts[0][2]


def test_an_existing_folder_gets_its_permissions_back(root):
    r, *_ = root
    folder = r / "home/alice/RAMDisk"
    folder.mkdir(mode=0o750)
    folder.chmod(0o750)
    call("ramdisk_open", size_mb=100, noexec=True)
    call("ramdisk_close")
    assert folder.is_dir() and stat.S_IMODE(folder.stat().st_mode) == 0o750


def test_after_a_reboot_the_folder_itself_says_what_to_put_back(root):
    """/run is empty after a reboot (the state with it, and the mount): the folder's own attribute says whether the
    helper made it (removed) or what its mode was (put back). Before, a folder of the user's was taken for the
    helper's and removed, and one that stayed kept the 0500 of an open RAM disk."""
    r, *_ = root
    if not xattrs_work(r / "home/alice"):
        pytest.skip("no user extended attributes on this filesystem")
    folder, state = r / "home/alice/RAMDisk", r / f"run/daprivacyscanner/ramdisk/{ME[0]}.json"
    folder.mkdir(mode=0o750)
    folder.chmod(0o750)
    call("ramdisk_open", size_mb=100, noexec=True)
    assert stat.S_IMODE(folder.stat().st_mode) == 0o500
    state.unlink()
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")        # as after a reboot
    res = call("ramdisk_close")
    assert res["was_open"] is False and res["ran"] == ["chmod 750 /home/alice/RAMDisk"]
    assert folder.is_dir() and stat.S_IMODE(folder.stat().st_mode) == 0o750
    with pytest.raises(OSError):                                               # the attribute goes with the close
        os.getxattr(folder, helper.RAMDISK_XATTR)
    # one the helper made goes, as it would have with the state
    folder.rmdir()
    call("ramdisk_open", size_mb=100, noexec=True)
    state.unlink()
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    assert call("ramdisk_close")["ran"] == ["rmdir /home/alice/RAMDisk"] and not folder.exists()
    # an attribute that isn't the helper's (the user can write one) is ignored, and with nothing else recording an open,
    # the folder is the user's own: left as it is (before, the guess removed an empty folder of theirs)
    folder.mkdir(mode=0o700)
    os.setxattr(folder, helper.RAMDISK_XATTR, b'{"created": "yes", "folder_mode": 99999}')
    assert "ran" not in call("ramdisk_close") and folder.is_dir() and stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_refusals(root):
    r, _, _, umount = root
    for bad in (10, 10**6, True, "512"):
        with pytest.raises(helper.Refused, match="bad size"):
            call("ramdisk_open", size_mb=bad, noexec=True)
    with pytest.raises(helper.Refused, match="half of the memory"):
        call("ramdisk_open", size_mb=9000, noexec=True)
    (r / "home/alice/RAMDisk").mkdir()
    (r / "home/alice/RAMDisk/note.txt").write_text("on disk")
    with pytest.raises(helper.Refused, match="files in it on the disk"):
        call("ramdisk_open", size_mb=100, noexec=True)
    (r / "home/alice/RAMDisk/note.txt").unlink()
    call("ramdisk_open", size_mb=100, noexec=True)
    umount.busy = True
    with pytest.raises(helper.Refused, match="close it first"):
        call("ramdisk_close")


def test_a_link_in_place_of_the_folder_is_refused(root, tmp_path):
    r, mounts, _, _ = root
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", r / "home/alice/RAMDisk")
    with pytest.raises(helper.Refused, match="link or not a folder"):
        call("ramdisk_open", size_mb=100, noexec=True)
    assert mounts == []


def test_close_never_unmounts_something_else(root):
    r, *_ = root
    with open(r / "proc/self/mounts", "a") as f:
        f.write("/dev/sdb1 /home/alice/RAMDisk ext4 rw 0 0\n")
    with pytest.raises(helper.Refused, match="something other"):
        call("ramdisk_close")


def test_kernel_versions_for_noswap():
    assert helper._kernel_has_noswap("6.8.0-45-generic") and helper._kernel_has_noswap("7.0.0-38-generic")
    assert not helper._kernel_has_noswap("6.1.0-26-amd64") and not helper._kernel_has_noswap("5.15.0")


# ------------------------------------------------------------------ the app's side

def test_wipe_overwrites_in_place_and_never_follows_links(tmp_path):
    disk = tmp_path / "ram"
    (disk / "sub").mkdir(parents=True)
    secret = disk / "sub" / "secret.txt"
    secret.write_bytes(b"top secret" * 1000)
    ino = secret.stat().st_ino
    secret.chmod(0o400)
    (disk / "sub").chmod(0o500)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    os.symlink(outside, disk / "link.txt")
    os.symlink(tmp_path, disk / "dirlink")
    sparse = disk / "sparse.img"
    with open(sparse, "wb") as f:
        f.seek(50 * 1024 * 1024)
        f.write(b"tail data")
    w = R.wipe(disk, delete=False)
    assert w.files == 2 and not w.failed
    assert secret.stat().st_ino == ino and secret.read_bytes() == bytes(10000)        # the same file, zeroed
    assert w.bytes < 50 * 1024 * 1024                                                 # holes left alone
    assert sparse.read_bytes()[-9:] == bytes(9)
    assert outside.read_text() == "keep me" and stat.S_IMODE(tmp_path.stat().st_mode) != 0o777
    R.wipe(disk)
    assert list(disk.iterdir()) == [] and outside.exists()


def test_status_reads_the_mount_and_says_what_it_cant_protect(tmp_path):
    from daprivacyscanner.host import CommandResult
    host = make_host(tmp_path, files={"/proc/mounts": "", "/proc/swaps": "Filename Type Size Used Priority\n/swapfile file 4194300 0 -2\n",
                                      "/sys/power/state": "freeze mem disk\n", "/sys/power/disk": "[platform] shutdown\n",
                                      "/proc/meminfo": "MemTotal: 8000000 kB\n", "/proc/cmdline": "ro resume=UUID=x\n"})
    host.runner.handlers["busctl"] = lambda argv: CommandResult(argv, 0, 's "yes"\n')        # logind lets this user
    st = R.status(host)
    assert not st.open and not st.leftover and R.max_mb(host) == 3906
    assert any("Hibernating" in n for n in st.notes)
    folder = host.home / "RAMDisk"
    folder.mkdir()
    (tmp_path / "root/proc/mounts").write_text(f"tmpfs {folder} tmpfs rw,nosuid,nodev,noexec,size=1048576k,mode=700 0 0\n")
    st = R.status(host)
    assert st.open and st.noexec and not st.noswap and st.size == "1048576k"
    assert any("swap on disk (/swapfile)" in n for n in st.notes)
    (tmp_path / "root/proc/mounts").write_text(f"/dev/sdb1 {folder} ext4 rw 0 0\n")
    assert R.status(host).other == "ext4"


def test_the_browsers_ramdisk_is_a_separate_one(root):
    r, mounts, _, _ = root
    call("ramdisk_open", size_mb=512, noexec=True)
    res = call("ramdisk_open", size_mb=1536, noexec=False, name="TempBrowser")
    assert res["path"] == "/home/alice/TempBrowser" and mounts[1][0] == str(r / "home/alice/TempBrowser")
    assert (r / f"run/daprivacyscanner/ramdisk/{ME[0]}-TempBrowser.json").exists()
    with pytest.raises(helper.Refused, match="unknown RAM disk"):
        call("ramdisk_open", size_mb=100, noexec=True, name="../.ssh")
    assert call("ramdisk_close", name="TempBrowser") == {"closed": True, "was_open": True,
                                                         "ran": ["umount /home/alice/TempBrowser", "rmdir /home/alice/TempBrowser"]}
    assert not (r / "home/alice/TempBrowser").exists() and helper._mounted_at("/home/alice/RAMDisk")
    assert call("ramdisk_close") == {"closed": True, "was_open": True,
                                     "ran": ["umount /home/alice/RAMDisk", "rmdir /home/alice/RAMDisk"]}


def test_a_program_using_it_is_found_whatever_path_it_sees(tmp_path):
    """A sandboxed program sees the RAM disk at another path (/home/user/…), and /proc shows that
    one: it is found by the device its files are on."""
    host = make_host(tmp_path)
    disk = host.home / "TempBrowser"
    (disk / "tor-browser").mkdir(parents=True)
    (disk / "tor-browser/places.sqlite").write_text("")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(disk / "tor-browser/places.sqlite", elsewhere / "inside-path")      # its path says nothing of the disk
    for pid, name, target in (("50", "firefox.real", elsewhere / "inside-path"), ("51", "bash", "/proc/self")):
        d = host.root / "proc" / pid
        (d / "fd").mkdir(parents=True)
        (d / "comm").write_text(name + "\n")
        os.symlink(target, d / "fd/3")
        os.symlink("/proc", d / "cwd")                                          # another filesystem
    assert R.on_device(host, disk) == {"firefox.real"}
    assert "firefox.real" in R.users_of(host, disk)


# ------------------------------------------------------------------ swap, for the browser's session

def swap_system(r, monkeypatch, avail_kb=8000000):
    """/proc/swaps with a partition, a swap file whose name has a space, and zram (one with a
    writeback device): swapoff and swapon change it, as the kernel would."""
    (r / "proc/meminfo").write_text(f"MemTotal:       16384000 kB\nMemAvailable:    {avail_kb} kB\n")
    for z, backing in (("zram0", "none"), ("zram1", "/dev/sdb2")):
        (r / f"sys/block/{z}").mkdir(parents=True)
        (r / f"sys/block/{z}/backing_dev").write_text(backing + "\n")
    lines = {"/dev/sda3": "/dev/sda3 partition 2097148 102400 -2",
             "/swap file": "/swap\\040file file 1048572 0 5",
             "/dev/zram0": "/dev/zram0 partition 4000000 0 100",
             "/dev/zram1": "/dev/zram1 partition 4000000 2048 50"}
    active = dict(lines)
    calls = []

    def write():
        (r / "proc/swaps").write_text("Filename Type Size Used Priority\n" + "".join(v + "\n" for v in active.values()))

    def run(argv):
        calls.append(list(argv))
        name = argv[-1]
        if argv[0] == "swapoff" and name in active:
            del active[name]
        elif argv[0] == "swapon" and name in lines:
            active[name] = lines[name]
        else:
            return 255, "", f"{argv[0]}: {name}: failed"
        write()
        return 0, "", ""
    write()
    monkeypatch.setattr(helper, "RUN", run)
    return calls


def test_swap_off_for_the_session_and_back_on(root, monkeypatch):
    r = root[0]
    calls = swap_system(r, monkeypatch)
    assert [s["name"] for s in helper.swaps_on_disk()] == ["/dev/sda3", "/swap file", "/dev/zram1"]   # zram0 is memory only
    got = call("swap_off")
    assert got == {"off": ["/dev/sda3", "/swap file", "/dev/zram1"], "failed": [],
                   "ran": ["swapoff /dev/sda3", "swapoff '/swap file'", "swapoff /dev/zram1"]}
    assert calls == [["swapoff", "/dev/sda3"], ["swapoff", "/swap file"], ["swapoff", "/dev/zram1"]]
    assert "/dev/zram0" in (r / "proc/swaps").read_text()
    state = json.loads((r / "run/daprivacyscanner/swap.json").read_text())
    assert [d["name"] for d in state["devices"]] == ["/dev/sda3", "/swap file", "/dev/zram1"]
    assert stat.S_IMODE(os.stat(r / "run/daprivacyscanner/swap.json").st_mode) == 0o644     # the app shows it
    calls.clear()
    assert call("swap_on") == {"on": ["/dev/sda3", "/swap file", "/dev/zram1"], "failed": [],
                               "ran": ["swapon /dev/sda3", "swapon -p 5 '/swap file'", "swapon -p 50 /dev/zram1"]}
    assert calls == [["swapon", "/dev/sda3"], ["swapon", "-p", "5", "/swap file"], ["swapon", "-p", "50", "/dev/zram1"]]
    assert not (r / "run/daprivacyscanner/swap.json").exists()


def test_swap_stays_on_when_memory_cant_take_it_back(root, monkeypatch):
    calls = swap_system(root[0], monkeypatch, avail_kb=300000)                     # 292 MB free, 102 MB in swap
    with pytest.raises(helper.Refused, match="enough free memory"):
        call("swap_off")
    assert calls == []


def test_the_panel_names_swap_and_thumbnails_on_the_disk(root, monkeypatch, tmp_path):
    from daprivacyscanner.host import FakeRunner, Host
    from daprivacyscanner.tools import browser as B
    r = root[0]
    swap_system(r, monkeypatch)
    host = Host(home=r / "home/alice", environ={"HOME": str(r / "home/alice")}, runner=FakeRunner(), root=r, uid=os.getuid())
    risk = B.risks(host)
    assert risk["swap"]["on_disk"] == ["/dev/sda3", "/swap file", "/dev/zram1"] and risk["swap"]["used_mb"] == 102
    assert risk["swap"]["off_commands"][:2] == ["sudo swapoff /dev/sda3", "sudo swapoff '/swap file'"]
    assert risk["swap"]["on_commands"][1] == "sudo swapon -p 5 '/swap file'"
    assert risk["thumbnails"] == {"in_memory": False, "folder": "~/.cache/thumbnails"}
    with open(r / "proc/self/mounts", "a") as f:
        f.write("tmpfs /home/alice/.cache/thumbnails tmpfs rw,size=262144k 0 0\n")
    (r / "home/alice/.cache/thumbnails").mkdir(parents=True)
    assert B.risks(host)["thumbnails"]["in_memory"]


def test_the_panel_says_when_crash_dumps_are_kept(root, monkeypatch):
    from daprivacyscanner.host import FakeRunner, Host
    from daprivacyscanner.tools import browser as B
    r = root[0]
    swap_system(r, monkeypatch)
    host = Host(home=r / "home/alice", environ={"HOME": str(r / "home/alice")}, runner=FakeRunner(), root=r, uid=os.getuid())
    (r / "proc/sys/kernel").mkdir(parents=True, exist_ok=True)
    (r / "proc/sys/kernel/core_pattern").write_text("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h\n")
    risk = B.risks(host)["crash_dumps"]
    assert risk["kept"] is True and "echo 0 > /proc/self/coredump_filter" in risk["start"]
    (r / "etc/systemd/coredump.conf.d").mkdir(parents=True)
    (r / "etc/systemd/coredump.conf.d/60-daprivacyscanner.conf").write_text("[Coredump]\nStorage=none\nProcessSizeMax=0\n")
    assert B.risks(host)["crash_dumps"]["kept"] is False


def test_the_commands_the_page_shows_are_what_the_helper_runs(root, tmp_path):
    """The page shows, before opening or closing, the commands that do what the helper does; the helper answers
    with the same ones ("ran"), for the same user, size and choice of programs."""
    import pwd
    from conftest import make_host
    host = make_host(tmp_path / "h")
    if host.uid != ME[0] or pwd.getpwuid(host.uid).pw_gid != ME[1]:
        pytest.skip("this account's group differs from its primary one")
    shown = R.commands(host, "RAMDisk", 512)
    here = os.path.realpath(host.home / "RAMDisk")
    for noexec, key in ((True, "open"), (False, "open_exec")):
        ran = call("ramdisk_open", size_mb=512, noexec=noexec)["ran"]
        assert [c.replace("/home/alice/RAMDisk", here) for c in ran] == shown[key]
        closed = call("ramdisk_close")["ran"]
        assert closed[0].replace("/home/alice/RAMDisk", here) == shown["close"][0]
