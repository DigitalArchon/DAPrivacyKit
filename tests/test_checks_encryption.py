import json
import os

import pytest

from daprivacyscanner.context import ContextValue
from daprivacyscanner.model import Status
from daprivacyscanner.privileged import FakePrivileged

from conftest import detect, ev, lsblk, make_host, make_scan, sample, skip_if_root
from daprivacyscanner.host import CommandResult

SWAPS = "Filename\tType\tSize\tUsed\tPriority\n"
FEDORA = lsblk("fedora-40-btrfs-luks.json")
DEBIAN = lsblk("debian-12-partial.json")
MINT = lsblk("mint-22-ext4-plain.json")
UBUNTU = lsblk("ubuntu-24.04-luks-lvm.json")


def fde(value, *evidence):
    return ContextValue("fde", value, list(evidence), "why")


@pytest.mark.parametrize("value, status", [("none", Status.FAIL), ("full", Status.PASS), ("partial", Status.PASS),
                                           (None, Status.UNKNOWN)])
def test_fde_missing(cat, tmp_path, value, status):
    o = detect(cat, "enc.fde_missing", make_scan(make_host(tmp_path), fde=fde(value)))
    assert o.status is status and o.partial is (value is None)


def test_fde_missing_with_an_ecryptfs_home(cat, tmp_path):
    host = make_host(tmp_path)
    host.sys_path("/proc").mkdir(parents=True, exist_ok=True)
    host.sys_path("/proc/mounts").write_text(f"/dev/sda2 / ext4 rw 0 0\n/home/.ecryptfs/alice/.Private {host.home} ecryptfs rw 0 0\n")
    o = detect(cat, "enc.fde_missing", make_scan(host, fde=fde("home"), devices=MINT))
    assert o.status is Status.FAIL and "eCryptfs" in o.summary and o.findings == {"home_ecryptfs": True}
    assert [n.title for n in o.notes] == ["What home folder encryption leaves open", "eCryptfs is no longer recommended"]


@pytest.mark.parametrize("value, status", [("partial", Status.FAIL), ("full", Status.PASS), (None, Status.UNKNOWN),
                                           ("home", Status.NOT_APPLICABLE)])
def test_partial_fde(cat, tmp_path, value, status):
    assert detect(cat, "enc.partial_fde", make_scan(make_host(tmp_path), fde=fde(value))).status is status


# ------------------------------------------------------------------ swap

@pytest.mark.parametrize("swaps, devices, files, status", [
    ("", FEDORA, {}, Status.PASS),
    ("/dev/zram0 partition 8388604 0 100\n", FEDORA, {}, Status.PASS),
    # a swap file on the encrypted btrfs root
    ("/home/swapfile file 8388604 0 -2\n", FEDORA, {}, Status.PASS),
    # Debian's swap LV inside LUKS, as the kernel names it
    ("/dev/dm-2 partition 999420 0 -2\n", DEBIAN, {"/sys/block/dm-2/dm/name": "vg-swap_1\n"}, Status.PASS),
    ("/swapfile file 2097148 0 -2\n", MINT, {}, Status.FAIL),
    ("/dev/sda1 partition 2097148 0 -2\n", MINT, {}, Status.FAIL),
    ("/dev/nvme9n1p9 partition 2097148 0 -2\n", FEDORA, {}, Status.UNKNOWN),    # not in lsblk
])
def test_swap_unencrypted(cat, tmp_path, swaps, devices, files, status):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + swaps, **files})
    assert detect(cat, "enc.swap_unencrypted", make_scan(host, devices=devices)).status is status


def test_hibernation_impossible_passes_and_keeps_the_near_miss_note(cat, tmp_path):
    from daprivacyscanner.model import Note

    note = Note("risk", "Hibernation is one step away", "...")
    scan = make_scan(make_host(tmp_path), hibernation=ContextValue("hibernation", False, notes=[note]))
    o = detect(cat, "enc.hibernate_unencrypted", scan)
    assert o.status is Status.PASS and o.notes == [note]


@pytest.mark.parametrize("devices, resume_target, swaps, status", [
    (DEBIAN, "dm-2", "", Status.PASS),          # resume device is the LV inside LUKS
    (MINT, "sda3", "", Status.FAIL),
    (MINT, None, "/swapfile file 16777212 0 -2\n", Status.FAIL),          # no fixed resume device
    (FEDORA, None, "/home/swapfile file 16777212 0 -2\n", Status.PASS),
])
def test_hibernate_unencrypted(cat, tmp_path, devices, resume_target, swaps, status):
    files = {"/proc/swaps": SWAPS + swaps, "/sys/block/dm-2/dm/name": "vg-swap_1\n",
             "/sys/power/resume": "254:2\n" if resume_target else "0:0\n"}
    links = {"/sys/dev/block/254:2": f"../../block/{resume_target}"} if resume_target else {}
    host = make_host(tmp_path, files=files, links=links)
    if resume_target:
        (host.sys_path("/sys/block") / resume_target).mkdir(parents=True, exist_ok=True)
    scan = make_scan(host, devices=devices, hibernation=True)
    assert detect(cat, "enc.hibernate_unencrypted", scan).status is status


@pytest.mark.parametrize("swaps, files, devices, status", [
    ("", {}, FEDORA, Status.PASS),
    ("/dev/zram0 partition 8388604 0 100\n", {"/sys/block/zram0/backing_dev": "none\n"}, FEDORA, Status.PASS),
    ("/dev/zram0 partition 8388604 0 100\n", {"/sys/block/zram0/backing_dev": "/dev/sda4\n"}, FEDORA, Status.FAIL),
    ("/home/swapfile file 8388604 0 -2\n", {}, FEDORA, Status.FAIL),               # encrypted, but persistent
])
def test_swap_persistent(cat, tmp_path, swaps, files, devices, status):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + swaps, **files})
    assert detect(cat, "enc.swap_persistent", make_scan(host, devices=devices)).status is status


def test_swap_with_a_random_key_each_boot_is_not_persistent(cat, tmp_path):
    import daprivacyscanner.blockdev as b

    devices = b.parse_lsblk(json.dumps({"blockdevices": [
        {"name": "sda", "type": "disk", "children": [
            {"name": "sda2", "type": "part", "fstype": None, "children": [
                {"name": "cryptswap", "type": "crypt", "fstype": "swap", "mountpoints": ["[SWAP]"]}]}]}]}))
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/dev/dm-0 partition 4194300 0 -2\n",
                                      "/sys/block/dm-0/dm/name": "cryptswap\n",
                                      "/etc/crypttab": "cryptswap /dev/sda2 /dev/urandom swap,cipher=aes-xts-plain64\n"})
    assert detect(cat, "enc.swap_persistent", make_scan(host, devices=devices)).status is Status.PASS


# ------------------------------------------------------------------ LUKS headers

@pytest.mark.parametrize("dump, status", [
    ("luks2-tpm2-no-pin.txt", Status.PASS),         # keyslot 1 is PBKDF2, but it holds the TPM's random key
    ("luks2-passphrase.txt", Status.PASS),
    ("luks1.txt", Status.FAIL),
])
def test_luks_weak_kdf(cat, tmp_path, dump, status):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged(luks={"/dev/nvme0n1p3": sample(f"luksdump/{dump}")})
    assert detect(cat, "enc.luks_weak_kdf", make_scan(host, devices=FEDORA)).status is status


def test_luks_weak_kdf_with_a_pbkdf2_passphrase_slot(cat, tmp_path):
    dump = sample("luksdump/luks2-tpm2-no-pin.txt").replace("  0: systemd-tpm2", "  0: something").replace(
        "\tKeyslot:    1", "\tKeyslot:    0")
    host = make_host(tmp_path)
    host.privileged = FakePrivileged(luks={"/dev/nvme0n1p3": dump})
    o = detect(cat, "enc.luks_weak_kdf", make_scan(host, devices=FEDORA))
    assert o.status is Status.FAIL and "keyslot 1 uses pbkdf2" in ev(o)["nvme0n1p3"]


def test_luks_weak_kdf_needs_root_or_luks(cat, tmp_path):
    assert detect(cat, "enc.luks_weak_kdf", make_scan(make_host(tmp_path), devices=FEDORA)).partial
    assert detect(cat, "enc.luks_weak_kdf", make_scan(make_host(tmp_path), devices=MINT)).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("value, devices, status", [
    (True, FEDORA, Status.FAIL), (False, FEDORA, Status.PASS), (None, FEDORA, Status.UNKNOWN),
    (False, MINT, Status.NOT_APPLICABLE),
])
def test_tpm_no_pin(cat, tmp_path, value, devices, status):
    scan = make_scan(make_host(tmp_path), devices=devices, tpm_unlock_no_pin=value)
    assert detect(cat, "enc.tpm_no_pin", scan).status is status


# ------------------------------------------------------------------ backups

def test_timeshift_on_unencrypted_drive(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/timeshift/timeshift.json": json.dumps(
        {"backup_device_uuid": "1111-2222", "btrfs_mode": "false"})}, links={"/dev/disk/by-uuid/1111-2222": "../../sdb1"})
    o = detect(cat, "enc.backups_unencrypted", make_scan(host, devices=DEBIAN))
    assert o.status is Status.FAIL and "Timeshift" in o.summary


def test_timeshift_btrfs_snapshots_on_encrypted_root(cat, tmp_path):
    host = make_host(tmp_path, files={
        "/etc/timeshift/timeshift.json": json.dumps({"backup_device_uuid": "abcd", "btrfs_mode": "true"}),
        "/sys/block/dm-0/dm/name": "luks-0f2c4e5a-1b2c-4d3e-8f90-123456789abc\n"},
        links={"/dev/disk/by-uuid/abcd": "../../dm-0"})
    assert detect(cat, "enc.backups_unencrypted", make_scan(host, devices=FEDORA)).status is Status.PASS


def test_timeshift_on_a_luks_drive_given_by_its_luks_uuid(cat, tmp_path):
    """The UUID recorded may be the LUKS container's own: that drive is encrypted, whatever is mounted on it."""
    host = make_host(tmp_path, files={"/etc/timeshift/timeshift.json": json.dumps(
        {"backup_device_uuid": "5555", "btrfs_mode": "false"})}, links={"/dev/disk/by-uuid/5555": "../../nvme0n1p3"})
    o = detect(cat, "enc.backups_unencrypted", make_scan(host, devices=FEDORA))
    assert o.status is Status.PASS and ev(o)["Timeshift"].startswith("rsync on encrypted nvme0n1p3")


@pytest.mark.parametrize("files, status", [
    (["duplicity-full.20260101T000000Z.vol1.difftar.gz", "duplicity-full.20260101T000000Z.manifest"], Status.FAIL),
    (["duplicity-full.20260101T000000Z.vol1.difftar.gpg"], Status.PASS),
])
def test_dejadup_local_duplicity(cat, tmp_path, files, status):
    home_files = {f"Backups/{f}": "x" for f in files}
    gs = "gsettings get org.gnome.DejaDup"
    host = make_host(tmp_path, home_files=home_files, commands={
        f"{gs} last-backup": "'2026-09-01T10:00:00Z'\n", f"{gs} tool": "'duplicity'\n", f"{gs} backend": "'local'\n",
        f"{gs}.Local folder": "'Backups'\n"})
    assert detect(cat, "enc.backups_unencrypted", make_scan(host, devices=FEDORA)).status is status


def test_dejadup_flatpak_restic_from_its_keyfile(cat, tmp_path):
    host = make_host(tmp_path, home_files={".var/app/org.gnome.DejaDup/config/glib-2.0/settings/keyfile":
                                           "[org/gnome/deja-dup]\nlast-backup='2026-09-01'\ntool='restic'\n"})
    o = detect(cat, "enc.backups_unencrypted", make_scan(host, devices=FEDORA))
    assert o.status is Status.PASS and ev(o)["Déjà Dup"].startswith("restic")


def test_no_backups_found_says_what_was_not_checked(cat, tmp_path):
    o = detect(cat, "enc.backups_unencrypted", make_scan(make_host(tmp_path), devices=FEDORA))
    assert o.status is Status.PASS and o.notes[0].kind == "limitation"


# ------------------------------------------------------------------ removable drives

def test_removable(cat, tmp_path):
    o = detect(cat, "enc.removable_unencrypted", make_scan(make_host(tmp_path), devices=FEDORA))
    assert o.status is Status.FAIL and ev(o)["Not encrypted"] == "sda1 (vfat, at /run/media/alice/STICK)"
    o = detect(cat, "enc.removable_unencrypted", make_scan(make_host(tmp_path), devices=MINT))   # only a CD drive
    assert o.status is Status.PASS


def test_installer_sticks_are_left_out(cat, tmp_path):
    import json
    from daprivacyscanner import blockdev
    devs = blockdev.parse_lsblk(json.dumps({"blockdevices": [{"name": "sdb", "type": "disk", "tran": "usb", "children": [
        {"name": "sdb1", "type": "part", "fstype": "exfat", "label": "Ventoy", "mountpoints": ["/media/alice/Ventoy"]},
        {"name": "sdb2", "type": "part", "fstype": "vfat", "label": "VTOYEFI"}]}]}))
    o = detect(cat, "enc.removable_unencrypted", make_scan(make_host(tmp_path), devices=devs))
    assert o.status is Status.PASS and ev(o)["Installer or boot stick, left out"] == "sdb"


# ------------------------------------------------------------------ crash dumps

@pytest.mark.parametrize("files, status", [
    ({"/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n"}, Status.FAIL),
    ({"/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P\n",
      "/etc/systemd/coredump.conf.d/50-off.conf": "[Coredump]\nStorage=none\nProcessSizeMax=0\n"}, Status.PASS),
    ({"/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P\n",
      "/etc/systemd/coredump.conf.d/50-off.conf": "[Coredump]\nStorage=none\n",
      "/var/lib/systemd/coredump/core.firefox.1000.zst": "x"}, Status.FAIL),           # old dumps remain
    ({"/proc/sys/kernel/core_pattern": "|/usr/share/apport/apport -p%p -s%s -c%c\n",
      "/etc/default/apport": "enabled=0\n"}, Status.PASS),
    ({"/proc/sys/kernel/core_pattern": "|/usr/share/apport/apport -p%p\n", "/etc/default/apport": "enabled=1\n"},
     Status.FAIL),
    ({"/proc/sys/kernel/core_pattern": "core\n", "/proc/self/limits": "Max core file size        0   unlimited  bytes\n"},
     Status.PASS),
])
def test_coredumps(cat, tmp_path, files, status):
    assert detect(cat, "enc.coredumps_retained", make_scan(make_host(tmp_path, files=files))).status is status


# ------------------------------------------------------------------ snapshots and journal

def test_snapshots(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/snapper/configs/root": 'SUBVOLUME="/"\nTIMELINE_CREATE="yes"\n'})
    o = detect(cat, "enc.snapshots_retain_deleted", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Snapper config root"] == \
        "/: up to 50 numbered (update) snapshots; timeline: 10 hourly, 10 daily, 10 monthly, 10 yearly"
    host = make_host(tmp_path / "zfs", commands={"zfs list -H -t snapshot -o name": "rpool/home@a\nrpool/home@b\n"})
    assert ev(detect(cat, "enc.snapshots_retain_deleted", make_scan(host)))["ZFS snapshots"] == 2
    assert detect(cat, "enc.snapshots_retain_deleted", make_scan(make_host(tmp_path / "n"))).status is Status.PASS


@pytest.mark.parametrize("files, status", [
    ({"/var/log/journal/abc/system.journal": "x"}, Status.FAIL),
    ({"/var/log/journal/abc/system.journal": "x", "/etc/systemd/journald.conf.d/privacy.conf":
      "[Journal]\nMaxRetentionSec=2week\n"}, Status.PASS),
    ({"/var/log/journal/abc/system.journal": "x", "/etc/systemd/journald.conf": "[Journal]\nMaxRetentionSec=1month\n"},
     Status.PASS),
    # a limit of years is no limit worth the name
    ({"/var/log/journal/abc/system.journal": "x", "/etc/systemd/journald.conf": "[Journal]\nMaxRetentionSec=5year\n"},
     Status.FAIL),
    # text logs a syslog daemon left, with the journal in memory
    ({"/etc/systemd/journald.conf": "[Journal]\nStorage=volatile\n", "/var/log/syslog.2.gz": "x"}, Status.WARN),
    # in memory from now on, but the old logs are still on the disk
    ({"/var/log/journal/abc/system.journal": "x", "/etc/systemd/journald.conf": "[Journal]\nStorage=volatile\n"},
     Status.WARN),
    ({"/etc/systemd/journald.conf": "[Journal]\nStorage=volatile\n"}, Status.PASS),
    ({}, Status.PASS),                                   # auto, and no /var/log/journal
    ({"/etc/systemd/journald.conf": "[Journal]\nStorage=persistent\n"}, Status.FAIL),
])
def test_journal(cat, tmp_path, files, status):
    assert detect(cat, "enc.journal_persistent", make_scan(make_host(tmp_path, files=files))).status is status


def test_journal_with_rsyslog_running(cat, tmp_path):
    """rsyslog keeps its own copy in /var/log: limiting the journal, or keeping it in memory, isn't enough."""
    from fakes import FakeSystem
    for conf in ("[Journal]\nMaxRetentionSec=2week\n", "[Journal]\nStorage=volatile\n"):
        host = make_host(tmp_path / conf[10:15], files={"/var/log/journal/x": "", "/etc/systemd/journald.conf": conf,
                                                        "/var/log/syslog": "x", "/var/log/auth.log.1": "x",
                                                        "/var/log/Xorg.0.log": "x"})
        host.runner.handlers["systemctl"] = FakeSystem({"rsyslog.service": ["enabled", "active"]}).handler
        o = detect(cat, "enc.journal_persistent", make_scan(host))
        assert o.status is Status.FAIL and "rsyslog also writes" in o.summary
        assert ev(o)["rsyslog (writes text logs in /var/log)"].startswith("running, 2 files")
    # Arch's syslog-ng writes nothing until a destination is turned on: running alone isn't a finding
    host = make_host(tmp_path / "arch", files={"/var/log/journal/x": "",
                                               "/etc/systemd/journald.conf": "[Journal]\nMaxRetentionSec=2week\n"})
    host.runner.handlers["systemctl"] = FakeSystem({"syslog-ng@default.service": ["enabled", "active"]}).handler
    o = detect(cat, "enc.journal_persistent", make_scan(host))
    assert o.status is Status.PASS and ev(o)["syslog-ng"] == "running, but no text logs of its own in /var/log"


def test_journal_dropins_override_the_main_file(cat, tmp_path):
    host = make_host(tmp_path, files={"/var/log/journal/x": "", "/etc/systemd/journald.conf": "[Journal]\nMaxRetentionSec=1month\n",
                                      "/usr/lib/systemd/journald.conf.d/10-distro.conf": "[Journal]\nMaxRetentionSec=0\n"})
    assert detect(cat, "enc.journal_persistent", make_scan(host)).status is Status.FAIL


# ------------------------------------------------------------------ trash

def test_trash(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/Trash/files/a.txt": "abc", ".local/share/Trash/files/dir/b": "x",
                                           ".local/share/Trash/info/a.txt.trashinfo": "[Trash Info]"})
    usb = tmp_path / "usb"
    (usb / ".Trash-1000/files").mkdir(parents=True)
    (usb / ".Trash-1000/files/photo.jpg").write_text("x")
    host.sys_path("/proc").mkdir(parents=True, exist_ok=True)
    host.sys_path("/proc/mounts").write_text(f"/dev/sdb1 {usb} vfat rw 0 0\nproc /proc proc rw 0 0\n")
    o = detect(cat, "enc.trash", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and o.summary.startswith("3 items")


def test_empty_trash_with_gnome_hint(cat, tmp_path):
    host = make_host(tmp_path, commands={"gsettings get org.gnome.desktop.privacy remove-old-trash-files": "false\n"})
    o = detect(cat, "enc.trash", make_scan(host))
    assert o.status is Status.PASS and o.notes


def test_trash_survives_unreadable_mounts(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/mounts": "/dev/sda2 /boot/efi vfat rw 0 0\n"})
    efi = host.sys_path("/boot/efi")
    efi.mkdir(parents=True, exist_ok=True)
    os.chmod(efi, 0)
    try:
        assert detect(cat, "enc.trash", make_scan(host)).status is Status.PASS
    finally:
        os.chmod(efi, 0o755)


# ------------------------------------------------------------------ boot, tmp, TRIM

SB = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-e39e1ffa9b81"


OTHER_VAR = "/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-e39e1ffa9b81"
STUB = "/sys/firmware/efi/efivars/StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"


@pytest.mark.parametrize("files, commands, status, said", [
    # on, but shim and GRUB leave the initramfs unchecked: a warning; a booted UKI (StubInfo) is checked whole
    ({SB: b"\x06\x00\x00\x00\x01"}, {}, Status.WARN, "on (the firmware's SecureBoot setting)"),
    ({SB: b"\x06\x00\x00\x00\x01", STUB: b"\x06\x00\x00\x00s\x00"}, {}, Status.PASS,
     "on (the firmware's SecureBoot setting)"),
    ({SB: b"\x06\x00\x00\x00\x00"}, {}, Status.FAIL, "off (the firmware's SecureBoot setting)"),
    (None, {}, Status.FAIL, "off (not available with legacy BIOS boot)"),
    # UEFI whose firmware has no SecureBoot setting at all (VMs, older PCs): not supported, so off
    ({OTHER_VAR: b"\x07\x00\x00\x00\x00\x00"}, {}, Status.FAIL, "off (the firmware doesn't support Secure Boot)"),
    # the firmware's settings not visible: mokutil (its answer on stderr), then the kernel's boot message
    ({}, {("mokutil", "--sb-state"): CommandResult((), 0, "", "SecureBoot enabled\n")}, Status.WARN, "on (mokutil)"),
    ({}, {"dmesg": "[    0.000000] secureboot: Secure boot disabled\n"}, Status.FAIL, "off (the kernel's boot messages)"),
    ({}, {}, Status.UNKNOWN, None),
])
def test_boot_no_secureboot(cat, tmp_path, files, commands, status, said):
    host = make_host(tmp_path, commands=commands)
    if files is not None:
        (host.sys_path("/sys/firmware/efi/efivars")).mkdir(parents=True)
    for p, data in (files or {}).items():
        host.sys_path(p).write_bytes(data)
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=UBUNTU))
    assert o.status is status
    assert ev(o).get("Secure Boot") == said


@skip_if_root
def test_secure_boot_setting_only_root_may_read(cat, tmp_path):
    """The variable is there but unreadable: never "not supported". Without administrator access
    it needs it (after mokutil and the kernel's message); with it, the helper reads it."""
    from daprivacyscanner.privileged import FakePrivileged
    host = make_host(tmp_path)
    (host.sys_path("/sys/firmware/efi/efivars")).mkdir(parents=True)
    host.sys_path(OTHER_VAR).write_bytes(b"\x07\x00\x00\x00\x00\x00")
    var = host.sys_path(SB)
    var.write_bytes(b"\x06\x00\x00\x00\x01")
    var.chmod(0)
    try:
        o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=UBUNTU))
        assert o.status is Status.UNKNOWN and o.needs_admin and "Secure Boot setting" in o.summary
        host.privileged = FakePrivileged(files={SB: "\x06\x00\x00\x00\x01"})
        o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=UBUNTU))
        assert o.status is Status.WARN and ev(o)["Secure Boot"] == "on (the firmware's SecureBoot setting)"
    finally:
        var.chmod(0o644)


def test_grub_encrypted_boot_passes(cat, tmp_path):
    no_boot = [d for d in UBUNTU if "/boot" not in d.mountpoints]       # /boot on the encrypted root
    for d in no_boot:
        d.mountpoints = [m for m in d.mountpoints if m != "/boot/efi"]
    assert detect(cat, "enc.boot_no_secureboot", make_scan(make_host(tmp_path), devices=no_boot)).status is Status.PASS


@pytest.mark.parametrize("mounts_text, status", [
    ("tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n", Status.PASS),
    ("/dev/sda3 / ext4 rw 0 0\n", Status.FAIL),
])
def test_tmp_on_disk(cat, tmp_path, mounts_text, status):
    host = make_host(tmp_path, files={"/proc/mounts": mounts_text})
    assert detect(cat, "enc.tmp_on_disk", make_scan(host)).status is status


@pytest.mark.parametrize("discard, note", [("4294966784", "What TRIM through LUKS reveals, and what it protects"),
                                           ("0", "Without TRIM, deleted files stay on the SSD")])
def test_trim_is_a_pass_with_a_note_on_both_sides(cat, tmp_path, discard, note):
    host = make_host(tmp_path, files={"/sys/block/dm-0/dm/name": "luks-0f2c4e5a-1b2c-4d3e-8f90-123456789abc\n",
                                      "/sys/block/dm-0/queue/discard_max_bytes": discard + "\n"})
    o = detect(cat, "enc.trim_through_luks", make_scan(host, devices=FEDORA))
    assert o.status is Status.PASS and [n.title for n in o.notes] == [note]


def test_backups_of_back_in_time_kup_vorta_and_pika(cat, tmp_path):
    """Read from each tool's own settings; one that doesn't encrypt is judged by its drive."""
    import json
    import sqlite3
    devs = lsblk("fedora-40-btrfs-luks.json")
    host = make_host(tmp_path, home_files={
        ".config/backintime/config": "profiles=1:2\nprofile1.snapshots.mode=local_gocryptfs\n"
                                     "profile1.snapshots.path=/run/media/alice/STICK\n"
                                     "profile2.snapshots.mode=ssh\nprofile2.snapshots.ssh.host=nas\n",
        ".config/pika-backup/config.json": json.dumps([{"id": "a", "encryption_mode": "repokey"},
                                                       {"id": "b", "encryption_mode": "none"}])})
    (host.home / ".local/share/Vorta").mkdir(parents=True)
    db = sqlite3.connect(host.home / ".local/share/Vorta/settings.db")
    db.executescript("CREATE TABLE repomodel (id INTEGER, url TEXT, encryption TEXT);"
                     "INSERT INTO repomodel VALUES (1, '/x', 'repokey-blake2');")
    db.commit()
    db.close()
    o = detect(cat, "enc.backups_unencrypted", make_scan(host, devices=devs))
    assert o.status is Status.FAIL and o.summary == "Unencrypted backups: Back In Time, Pika Backup."
    e = [(x.label, x.value) for x in o.evidence]
    assert ("Back In Time", "profile 1: encrypted (local_gocryptfs)") in e
    assert ("Vorta", "1 repository, encrypted") in e and ("Pika Backup", "1 of 2 backups not encrypted") in e
    kup = make_host(tmp_path / "kup", home_files={".config/kuprc": "[Plan/1]\nDestination type=1\nExternal drive UUID=nope\n"})
    o = detect(cat, "enc.backups_unencrypted", make_scan(kup, devices=devs))
    assert o.status is Status.UNKNOWN and ev(o)["Kup"] == "plan 1: Kup doesn't encrypt; its drive isn't attached"


@pytest.mark.parametrize("conf, status", [
    ("volume /mnt/btr_pool\n  subvolume home\n", Status.FAIL),                     # snapshot_preserve_min all (default)
    ("snapshot_preserve_min 2d\nsnapshot_preserve 14d 4w\nvolume /mnt/pool\n", Status.FAIL),
    ("snapshot_preserve_min 2d\nsnapshot_preserve 7d\nvolume /mnt/pool\n", Status.PASS),
])
def test_btrbk_retention(cat, tmp_path, conf, status):
    host = make_host(tmp_path, files={"/etc/btrbk/btrbk.conf": conf})
    o = detect(cat, "enc.snapshots_retain_deleted", make_scan(host))
    assert o.status is status and "btrbk snapshots" in ev(o)


PARTIAL_MOUNTS = "/dev/mapper/vg-root / ext4 rw 0 0\n/dev/sdb1 /srv/data ext4 rw 0 0\n"


@pytest.mark.parametrize("disk, paths, expected", [
    ("full", ["/var/spool/cups"], True),
    ("none", ["/home/alice"], False),
    (None, ["/tmp"], None),
    ("home", ["HOME", "HOME/.cache"], True),               # eCryptfs or fscrypt: the block devices don't show it
    ("home", ["HOME", "/var/spool/cups"], False),          # / isn't encrypted
    ("partial", ["/var/spool/cups"], True),                # on the encrypted /
    ("partial", ["/", "/srv/data/snapshots"], False),      # one of them on the unencrypted disk
])
def test_on_encrypted_disk(tmp_path, disk, paths, expected):
    from daprivacyscanner.checks._util import on_encrypted_disk
    host = make_host(tmp_path, files={"/proc/mounts": PARTIAL_MOUNTS})
    scan = make_scan(host, devices=DEBIAN, fde=fde(disk))
    assert on_encrypted_disk(scan, *(p.replace("HOME", str(host.home)) for p in paths)) is expected


@pytest.mark.parametrize("files, commands, disk, expected", [
    ({"/etc/snapper/configs/root": 'SUBVOLUME="/"\n'}, {}, "partial", True),
    ({"/etc/btrbk/btrbk.conf": "volume /srv/data\n  subvolume home\n"}, {}, "partial", False),
    ({"/etc/btrbk/btrbk.conf": "volume /srv/data\n"}, {}, "full", True),
    ({}, {"zfs list -H -t snapshot -o name": "rpool/home@a\n"}, "partial", None),     # where it is mounted unknown
    ({}, {"zfs list -H -t snapshot -o name": "rpool/home@a\n",
          "zfs list -H -t filesystem -o name,mountpoint": "rpool\t/rpool\nrpool/home\t/srv/data/home\n"},
     "partial", False),
])
def test_snapshots_say_whether_they_are_on_an_encrypted_disk(cat, tmp_path, files, commands, disk, expected):
    host = make_host(tmp_path, files={"/proc/mounts": PARTIAL_MOUNTS, **files}, commands=commands)
    o = detect(cat, "enc.snapshots_retain_deleted", make_scan(host, devices=DEBIAN, fde=fde(disk)))
    assert o.status is Status.FAIL and o.findings["data_on_encrypted_disk"] is expected


SHORT_SNAPPER = 'SUBVOLUME="{sv}"\nNUMBER_LIMIT="10"\nNUMBER_LIMIT_IMPORTANT="5"\nTIMELINE_LIMIT_MONTHLY="0"\nTIMELINE_LIMIT_YEARLY="0"\n'


def _snapshot_host(tmp_path, layout, files=None, commands=None):
    """A fixture host whose mount table puts the (real) fixture home on the subvolumes `layout` names: "@home" its own
    mount at its parent, "@" inside the root's subvolume (mounted at tmp_path), "ext4" home not on btrfs."""
    probe = make_host(tmp_path)
    home, top = probe.home, tmp_path
    table = {"@home": f"/dev/sda2 / btrfs rw,subvolid=256,subvol=/@ 0 0\n/dev/sda2 {top}/home btrfs rw,subvolid=257,subvol=/@home 0 0\n"
                      "/dev/sda2 /mnt/pool btrfs rw,subvolid=5,subvol=/ 0 0\n",
             "@": f"/dev/sda2 / btrfs rw,subvolid=256,subvol=/@ 0 0\n/dev/sda2 {top} btrfs rw,subvolid=256,subvol=/@ 0 0\n",
             "ext4": f"/dev/sda2 / btrfs rw,subvolid=256,subvol=/@ 0 0\n/dev/sdb1 {top}/home ext4 rw 0 0\n",
             "zfs": f"rpool/ROOT / zfs rw 0 0\nrpool/home {top}/home zfs rw 0 0\n",
             None: ""}[layout]
    files = {k.replace("HOME", str(home)).replace("TOP", str(top)): v.replace("HOME", str(home)).replace("TOP", str(top))
             for k, v in (files or {}).items()}
    return make_host(tmp_path, files={"/proc/mounts": table, **files}, commands=commands)


@pytest.mark.parametrize("layout, files, commands, status, home_in", [
    # snapper's root config on @, the home folder on @home: kept short, so a pass, with the advice to keep it out
    ("@home", {"/etc/snapper/configs/root": SHORT_SNAPPER.format(sv="/")}, {}, Status.PASS, "no"),
    # a snapper config for the home folder's subvolume: a fail even with short retention
    ("@home", {"/etc/snapper/configs/home": SHORT_SNAPPER.format(sv="TOP/home")}, {}, Status.FAIL, "Snapper (home)"),
    # no subvolume of its own: the home folder is in @, and so in the root config's snapshots
    ("@", {"/etc/snapper/configs/root": SHORT_SNAPPER.format(sv="TOP")}, {}, Status.FAIL, "Snapper (root)"),
    ("ext4", {"/etc/snapper/configs/root": SHORT_SNAPPER.format(sv="/")}, {}, Status.PASS, "no"),
    (None, {"/etc/snapper/configs/root": SHORT_SNAPPER.format(sv="/")}, {}, Status.PASS, "couldn't be told"),
    # btrbk names subvolumes from the top level, mounted elsewhere: the same subvolume, a glob included
    ("@home", {"/etc/btrbk/btrbk.conf": "snapshot_preserve_min 2d\nsnapshot_preserve 7d\nvolume /mnt/pool\n  subvolume @home\n"},
     {}, Status.FAIL, "btrbk"),
    ("@home", {"/etc/btrbk/btrbk.conf": "snapshot_preserve_min 2d\nsnapshot_preserve 7d\nvolume /mnt/pool\n  subvolume @h*\n"},
     {}, Status.FAIL, "btrbk"),
    ("@home", {"/etc/btrbk/btrbk.conf": "snapshot_preserve_min 2d\nsnapshot_preserve 7d\nvolume /mnt/pool\n  subvolume @\n"},
     {}, Status.PASS, "no"),
    ("@home", {"/etc/timeshift/timeshift.json": json.dumps({"backup_device_uuid": "a", "btrfs_mode": "true",
                                                             "include_btrfs_home_for_backup": "true"})}, {}, Status.FAIL, "Timeshift"),
    ("@home", {"/etc/timeshift/timeshift.json": json.dumps({"backup_device_uuid": "a", "btrfs_mode": "true",
                                                             "include_btrfs_home_for_backup": "false"})}, {}, Status.PASS, "no"),
    ("zfs", {}, {"zfs list -H -t snapshot -o name": "rpool/home@a\nrpool/ROOT@b\n",
                 "zfs list -H -t filesystem -o name,mountpoint": "rpool/ROOT\t/\nrpool/home\tTOP/home\n"},
     Status.FAIL, "ZFS (rpool/home)"),
])
def test_snapshots_of_the_home_folder(cat, tmp_path, layout, files, commands, status, home_in):
    commands = {k: v.replace("TOP", str(tmp_path)) for k, v in commands.items()}
    host = _snapshot_host(tmp_path, layout, files, commands)
    o = detect(cat, "enc.snapshots_retain_deleted", make_scan(host))
    assert o.status is status and ev(o)["Home folder in them"] == home_in
    titles = [n.title for n in o.notes]
    assert ("Keep your home folder out of them" in titles) is (home_in == "no")
    if status is Status.FAIL:
        assert "include your home folder" in o.summary


def test_long_kept_snapshots_without_the_home_folder_say_so(cat, tmp_path):
    host = _snapshot_host(tmp_path, "@home", {"/etc/snapper/configs/root": 'SUBVOLUME="/"\n'})
    o = detect(cat, "enc.snapshots_retain_deleted", make_scan(host))
    assert o.status is Status.FAIL and o.summary.endswith("Your home folder isn't in them.")
    assert any(n.title == "Keep your home folder out of them" for n in o.notes)
