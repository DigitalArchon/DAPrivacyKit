"""enc.trim_off and its guide, Turn on TRIM: on fixture /sys trees (the stacks the TRIM test reads),
with the timer option applied and reverted through the real helper code against the fixture tree."""

from __future__ import annotations

import os

import pytest

from daprivacyscanner import helper
from daprivacyscanner.checks import load_all
from daprivacyscanner.fix import apply_plan, revert_entry
from daprivacyscanner.host import FakeRunner, Host
from daprivacyscanner.model import Status
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.undo import UndoLog

from conftest import make_scan
from fakes import FakeSystem
from test_trimtest import ME, add_data_disk, link, make_storage, write

CHECK = "enc.trim_off"


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    return r


def host_for(r, timer="enabled", installed=(), virt="none"):
    home = r / "home/alice"
    return Host(home=home, environ={"HOME": str(home)}, root=r, uid=ME[0],
                runner=FakeRunner({"systemctl is-enabled fstrim.timer": timer + "\n",
                                   "systemctl show --property=LoadState --value fstrim.timer": "loaded\n"}, installed))


def luks_version(r, version):
    """udev's database entry for the LUKS partition under dm-0."""
    write(r / "sys/devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p2/dev", "259:2\n")
    write(r / "run/udev/data/b259:2", f"S:disk/by-uuid/abc\nE:ID_FS_TYPE=crypto_LUKS\nE:ID_FS_VERSION={version}\n")


def detect(cat, host, **context):
    check = load_all()[CHECK](cat[CHECK])
    scan = make_scan(host, **context)
    return check, scan, check.detect(scan)


def guide(cat, host, **context):
    check, scan, outcome = detect(cat, host, **context)
    assert outcome.status is Status.FAIL and check.can_fix(scan, outcome), outcome.summary
    # what the guide can turn on is the check's own, not findings: no severity depends on it, and the
    # runner refuses findings its catalogue entry doesn't use (a scan reported the check as failed)
    assert not outcome.findings
    outcome.blocked = check.blocked
    return check.plan_guide(scan, outcome), outcome


def test_luks2_without_discards_gets_the_persistent_flag(cat, root):
    make_storage(root, luks="no-discards")
    luks_version(root, 2)
    g, outcome = guide(cat, host_for(root), fde="full")
    assert "encrypted volume luks-1 isn't opened with discards allowed" in outcome.summary
    assert outcome.blocked == {"luks"}
    [luks, check_it] = g.steps
    assert luks.commands == ["sudo cryptsetup --allow-discards --persistent refresh luks-1"]
    assert "however this system unlocks the disk" in luks.text and "LUKS1" not in luks.text
    assert any("which parts of the disk are in use" in x for x in luks.side_effects)
    assert check_it.commands == ["sudo fstrim -av"] and "/etc/fstab doesn't need changing" in g.intro


def test_luks1_on_debian_edits_crypttab_and_rebuilds_the_initramfs(cat, root):
    make_storage(root, luks="no-discards")
    luks_version(root, 1)
    write(root / "etc/crypttab", "# <target> <source> <key> <options>\nluks-1 UUID=abc none luks\n")
    write(root / "proc/cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/mapper/luks-1 ro quiet\n")
    g, _ = guide(cat, host_for(root, installed=("update-initramfs",)), fde="full")
    step = g.steps[0]
    assert step.title == "Allow TRIM through luks-1 (LUKS1)"
    assert step.commands == ["sudo cryptsetup --allow-discards refresh luks-1", "sudoedit /etc/crypttab",
                             "sudo update-initramfs -u -k all"]
    assert "luks-1 UUID=abc none luks,discard" in step.text and "until the next restart" in step.text


def test_luks1_with_archs_encrypt_hook_changes_the_kernel_command_line(cat, root):
    make_storage(root, luks="no-discards")
    luks_version(root, 1)
    write(root / "proc/cmdline", "cryptdevice=UUID=abc:luks-1 root=/dev/mapper/luks-1 rw\n")
    write(root / "etc/default/grub", 'GRUB_CMDLINE_LINUX="cryptdevice=UUID=abc:luks-1"\n')
    g, _ = guide(cat, host_for(root, installed=("grub-mkconfig", "mkinitcpio")), fde="full")
    step = g.steps[0]
    assert "cryptdevice=UUID=abc:luks-1:allow-discards" in step.text and "doesn't read /etc/crypttab" in step.text
    assert step.commands[1:] == ["sudoedit /etc/default/grub", "sudo grub-mkconfig -o /boot/grub/grub.cfg"]


def test_rd_luks_options_on_fedora_go_through_grubby(cat, root):
    make_storage(root, luks="no-discards")
    luks_version(root, 1)
    write(root / "proc/cmdline", "rd.luks.uuid=abc rd.luks.options=tpm2-device=auto root=/dev/mapper/luks-1\n")
    g, _ = guide(cat, host_for(root, installed=("grubby", "dracut")), fde="full")
    assert g.steps[0].commands[1] == ("sudo grubby --update-kernel=ALL --remove-args='rd.luks.options=tpm2-device=auto' "
                                      "--args='rd.luks.options=tpm2-device=auto,discard'")


def test_unknown_luks_version_says_how_to_tell(cat, root):
    make_storage(root, luks="no-discards")
    g, _ = guide(cat, host_for(root), fde="full")
    assert g.steps[0].commands == ["sudo cryptsetup --allow-discards --persistent refresh luks-1"]
    assert "sudo cryptsetup luksDump /dev/nvme0n1p2 | head" in g.steps[0].text


def test_the_weekly_timer_is_turned_on_and_off_again(cat, root, monkeypatch):
    make_storage(root)
    system = FakeSystem(units={"fstrim.timer": ["disabled", "inactive"]})
    monkeypatch.setattr(helper, "RUN", system)
    host = host_for(root, timer="disabled")
    host.privileged = FakePrivileged()
    host.runner.handlers["systemctl"] = system.handler
    g, outcome = guide(cat, host, fde="none")
    assert outcome.blocked == {"never_runs"} and "TRIM never runs" in outcome.summary
    [timer, _] = g.steps
    [opt] = timer.options
    assert opt.recommended and opt.label == "Turn on the weekly TRIM timer"
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(opt.plan, host, log)
    assert res.ok, res.error
    assert system.units["fstrim.timer"] == ["enabled", "active"]
    _, scan, after = detect(cat, host, fde="none")
    assert after.status is Status.PASS
    assert all(r.ok for r in revert_entry(log.get(res.entry_id), host, log))
    assert system.units["fstrim.timer"] == ["disabled", "inactive"]


def test_raid5_gets_the_careful_step(cat, root):
    make_storage(root)
    (root / "proc/self/mounts").write_text("/dev/md0 / ext4 rw 0 0\n")
    md = root / "sys/devices/virtual/block/md0"
    write(md / "md/level", "raid5\n")
    write(md / "queue/discard_max_bytes", "0\n")
    (md / "slaves").mkdir(parents=True)
    link(md / "slaves/nvme0n1p2", "../../../../pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p2")
    link(root / "sys/class/block/md0", "../../devices/virtual/block/md0")
    g, outcome = guide(cat, host_for(root, installed=("dracut",)))
    assert outcome.blocked == {"raid"} and "raid5 RAID array md0 drops TRIM" in outcome.summary
    step = g.steps[0]
    assert "only if every drive in it reads zeros after TRIM" in step.title
    assert step.commands == ["echo 'options raid456 devices_handle_discard_safely=Y' | sudo tee "
                             "/etc/modprobe.d/raid456-discard.conf", "sudo dracut -f --regenerate-all"]


def test_a_usb_adapter_that_drops_trim_has_nothing_to_fix(cat, root):
    make_storage(root)
    (root / "proc/self/mounts").write_text("/dev/nvme0n1p2 / ext4 rw 0 0\n/dev/sdb1 /media/alice/ext ext4 rw 0 0\n")
    add_data_disk(root, "/media/alice/ext")
    (root / "proc/self/mounts").write_text("/dev/sdb1 / ext4 rw 0 0\n")
    usb = root / "sys/devices/pci0000:00/usb2/2-1/sdb"
    os.makedirs(usb.parent, exist_ok=True)
    os.rename(root / "sys/devices/pci0000:00/ata2/sdb", usb)
    for p in ("sys/class/block/sdb", "sys/class/block/sdb1", "sys/block/sdb"):
        os.unlink(root / p)
    link(root / "sys/class/block/sdb", "../../devices/pci0000:00/usb2/2-1/sdb")
    link(root / "sys/class/block/sdb1", "../../devices/pci0000:00/usb2/2-1/sdb/sdb1")
    link(root / "sys/block/sdb", "../devices/pci0000:00/usb2/2-1/sdb")
    write(usb / "queue/discard_max_bytes", "0\n")
    check, scan, outcome = detect(cat, host_for(root))
    assert outcome.status is Status.FAIL and "USB connection doesn't pass TRIM on" in outcome.summary
    assert not check.can_fix(scan, outcome)


def test_passes_hard_disks_and_virtual_machines(cat, root):
    make_storage(root)
    assert detect(cat, host_for(root))[2].status is Status.PASS
    make_storage(root, rotational="1")
    assert detect(cat, host_for(root))[2].status is Status.NOT_APPLICABLE
    make_storage(root, rotational="0")
    assert detect(cat, host_for(root), virtualization="vm")[2].status is Status.NOT_APPLICABLE
    make_storage(root, options="rw,discard=async")
    assert "as files are deleted" in detect(cat, host_for(root, timer="disabled"))[2].evidence[0].value


@pytest.mark.parametrize("storage", ["luks", "timer_off", "trimmed"])
def test_a_scan_runs_it_without_error(cat, root, storage):
    """Through the runner, as a scan does: it refuses findings the catalogue's modifiers don't use."""
    from daprivacyscanner.runner import Runner
    make_storage(root, **({"luks": "no-discards"} if storage == "luks" else {}))
    if storage == "luks":
        luks_version(root, 2)
    host = host_for(root, timer="disabled" if storage == "timer_off" else "enabled")
    r = Runner(cat, host).scan(only=[CHECK]).results[CHECK]
    assert r.status is (Status.PASS if storage == "trimmed" else Status.FAIL), (r.status, r.error, r.summary)
    assert not r.error and r.fixable is (storage != "trimmed")
