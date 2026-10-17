"""Encryption and kernel checks corrected after the review of 2026-10-17 (what a P330 with Mint 22.3, the Ubuntu 26.04,
Fedora 44 and Omarchy VMs showed, and what reading the checks against their fixes found)."""

import pytest

from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status

from conftest import detect, ev, lsblk, make_host, make_scan
from test_guides import _advice, system  # noqa: F401 - the root helper on the fixture tree

UBUNTU = lsblk("ubuntu-24.04-luks-lvm.json")
EFIVARS = "/sys/firmware/efi/efivars"
GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


# ------------------------------------------------------------------ Secure Boot

def _efi(host, secure_boot: bytes | None):
    host.sys_path(EFIVARS).mkdir(parents=True)
    host.sys_path(f"{EFIVARS}/SetupMode-{GLOBAL}").write_bytes(b"\x06\x00\x00\x00\x00")
    if secure_boot is not None:
        host.sys_path(f"{EFIVARS}/SecureBoot-{GLOBAL}").write_bytes(b"\x06\x00\x00\x00" + secure_boot)


@pytest.mark.parametrize("value, said", [(b"\x00", "off (the firmware's SecureBoot setting)"),
                                         (b"\x01", "on (the firmware's SecureBoot setting)"),
                                         (None, "off (the firmware doesn't support Secure Boot)")])
def test_the_secure_boot_variable_is_read_under_the_efi_global_guid(cat, tmp_path, value, said):
    """The variable is SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c (seen on the P330, where mokutil says
    "SecureBoot disabled"): a wrong GUID made every UEFI machine "doesn't support Secure Boot"."""
    host = make_host(tmp_path)
    _efi(host, value)
    assert ev(detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=UBUNTU)))["Secure Boot"] == said


def test_the_helper_may_read_the_right_variable():
    from daprivacyscanner import helper
    assert helper.readable(f"{EFIVARS}/SecureBoot-{GLOBAL}")
    assert not helper.readable(f"{EFIVARS}/SecureBoot-8be4df61-93ca-11d2-aa0d-e39e1ffa9b81")


MOK = "/var/lib/shim-signed/mok/MOK.der"
MINT = {"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", MOK: "der",
        "/proc/sys/kernel/osrelease": "7.0.0-38-generic\n",
        "/usr/lib/modules/7.0.0-38-generic/updates/dkms/nvidia.ko.zst": "",
        "/usr/lib/modules/7.0.0-38-generic/updates/dkms/nvidia-drm.ko.zst": ""}


def test_secure_boot_guide_enrols_the_drivers_key_first_where_it_isnt(cat, tmp_path):
    """On the P330 NVIDIA's DKMS module is signed by a key of the machine's own that is neither enrolled nor waiting:
    turning Secure Boot on would leave the driver unloaded, so its enrolment comes first."""
    said = CommandResult((), 1, "", f"Failed to accesss kernel trusted keyring: Required key not available\n"
                                    f"{MOK} is not enrolled\n")
    host = make_host(tmp_path, files=MINT, commands={("mokutil", "--test-key", MOK): said})
    g = _advice(cat, host, "enc.boot_no_secureboot")
    first, firmware = g.steps[0], g.steps[1]
    assert first.title.startswith("First: enrol the key")
    assert first.commands == [f"sudo mokutil --import {MOK}", f"mokutil --test-key {MOK}"]
    assert "nvidia, nvidia-drm" in first.text and "wouldn't load" in first.text
    assert "MOK" not in firmware.text and "enrolled" not in firmware.text


@pytest.mark.parametrize("answer, words", [(f"{MOK} is already enrolled\n", "is enrolled already"),
                                           (f"{MOK} is already in the enrollment request\n", "waiting to be enrolled")])
def test_secure_boot_guide_says_where_the_drivers_key_stands(cat, tmp_path, answer, words):
    host = make_host(tmp_path, files=MINT, commands={("mokutil", "--test-key", MOK): answer})
    g = _advice(cat, host, "enc.boot_no_secureboot")
    assert g.steps[0].title == "Turn it on in the firmware" and words in g.steps[0].text


def test_secure_boot_guide_without_a_drivers_key_says_what_would_be_needed(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": "ID=fedora\n"})
    step = _advice(cat, host, "enc.boot_no_secureboot").steps[0]
    assert step.title == "Turn it on in the firmware" and "has to be enrolled first" in step.text


# ------------------------------------------------------------------ where the kernels really are

def _no_boot_partition(devices):
    out = [d for d in devices if "/boot" not in d.mountpoints]
    for d in out:
        d.mountpoints = ["/efi" if m == "/boot/efi" else m for m in d.mountpoints]
    return out


def test_kernels_on_the_efi_partition_are_not_on_encrypted_storage(cat, tmp_path):
    """systemd-boot with unified kernel images: no /boot partition, the root encrypted, the ESP at /efi holding the
    kernels. "/boot is on encrypted storage" was a false pass."""
    host = make_host(tmp_path, files={"/efi/EFI/Linux/arch-linux.efi": "MZ", "/efi/EFI/systemd/systemd-bootx64.efi": "MZ"})
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=_no_boot_partition(lsblk("ubuntu-24.04-luks-lvm.json"))))
    assert o.status is Status.FAIL and "/efi" in o.summary
    assert ev(o)["/efi"].endswith("not encrypted")


def test_systemd_boot_entries_name_kernels_on_the_efi_partition(cat, tmp_path):
    host = make_host(tmp_path, files={
        "/efi/loader/entries/abc-6.12.conf": "title Linux\nlinux /abc/6.12/linux\ninitrd /abc/6.12/initrd\n",
        "/efi/abc/6.12/linux": "MZ", "/efi/abc/6.12/initrd": "x"})
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=_no_boot_partition(lsblk("ubuntu-24.04-luks-lvm.json"))))
    assert o.status is not Status.PASS


def test_grub_with_boot_on_the_encrypted_root_still_passes(cat, tmp_path):
    """Only GRUB's own program is on the EFI partition; the kernels are in /boot on the encrypted root."""
    host = make_host(tmp_path, files={"/boot/vmlinuz-6.8.0": "x", "/boot/initrd.img-6.8.0": "x",
                                      "/efi/EFI/ubuntu/grubx64.efi": "MZ"})
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=_no_boot_partition(lsblk("ubuntu-24.04-luks-lvm.json"))))
    assert o.status is Status.PASS and o.summary == "/boot is on encrypted storage."


# ------------------------------------------------------------------ hibernation

def _hib_host(tmp_path, files=None, logind=None):
    base = {"/sys/power/state": "freeze mem disk\n", "/sys/power/disk": "[platform] shutdown reboot\n",
            "/proc/swaps": "Filename Type Size Used Priority\n/swap.img file 4194300 0 -1\n",
            "/proc/cmdline": "ro quiet resume=UUID=x\n", "/sys/power/resume": "0:0\n",
            "/sys/power/image_size": str(2 * 2**30)}
    host = make_host(tmp_path, files={**base, **(files or {})})
    asked = []
    if logind is not None:
        def busctl(argv):
            asked.append(argv[-1])
            said = logind.get(argv[-1], "na") if isinstance(logind, dict) else logind
            return CommandResult(argv, 0, f's "{said}"\n')
        host.runner.handlers["busctl"] = busctl
    return host, asked


def test_hibernation_turned_off_in_sleep_conf_is_off(cat, tmp_path):
    """The guide's "Turn hibernation off" writes this drop-in; it was never read, so the check never passed and swap
    stayed at severity 9."""
    from daprivacyscanner.context import detect_hibernation
    dropin = "[Sleep]\nAllowHibernation=no\nAllowSuspendThenHibernate=no\nAllowHybridSleep=no\n"
    host, asked = _hib_host(tmp_path, {"/etc/systemd/sleep.conf.d/60-daprivacyscanner.conf": dropin}, logind="yes")
    v = detect_hibernation(host)
    assert v.value is False and "sleep settings" in v.note and asked == []
    o = detect(cat, "enc.hibernate_unencrypted", make_scan(host, hibernation=v))
    assert o.status is Status.PASS and "turned off in systemd's sleep settings" in o.summary


def test_a_mode_switched_back_on_still_hibernates(tmp_path):
    """sleep.conf(5): AllowHibernation=no turns suspend-then-hibernate and hybrid sleep off too, unless they say yes."""
    from daprivacyscanner.context import detect_hibernation
    host, asked = _hib_host(tmp_path, {"/etc/systemd/sleep.conf": "[Sleep]\nAllowHibernation=no\nAllowHybridSleep=yes\n"},
                            logind={"CanHybridSleep": "yes"})
    assert detect_hibernation(host).value is True and asked == ["CanHybridSleep"]


def test_a_dropin_of_the_same_name_in_etc_hides_the_vendors(tmp_path):
    from daprivacyscanner import ini
    from daprivacyscanner.context import systemd_config
    host = make_host(tmp_path, files={"/usr/lib/systemd/sleep.conf.d/10-x.conf": "[Sleep]\nAllowHibernation=no\n",
                                      "/etc/systemd/sleep.conf.d/10-x.conf": "[Sleep]\nAllowSuspend=yes\n",
                                      "/usr/lib/systemd/sleep.conf.d/20-y.conf": "[Sleep]\nHibernateDelaySec=1h\n"})
    cfg, used = systemd_config(host, "sleep.conf")
    assert ini.get(cfg, "Sleep", "AllowHibernation") is None and ini.get(cfg, "Sleep", "HibernateDelaySec") == "1h"
    assert used == ["/etc/systemd/sleep.conf.d/10-x.conf", "/usr/lib/systemd/sleep.conf.d/20-y.conf"]


def test_ubuntus_policy_refusing_hibernation_makes_it_one_step_away(tmp_path):
    """Ubuntu's com.ubuntu.desktop.rules refuses login1.hibernate to users and logind's CanHibernate answers "no" (seen
    on 26.04): a Problem 9 on a stock install was wrong. An administrator can still hibernate: a risk note says so."""
    from daprivacyscanner.context import detect_hibernation
    host, _ = _hib_host(tmp_path, logind="no")
    v = detect_hibernation(host)
    assert v.value is False and "policy" in v.note
    [note] = v.notes
    assert note.title == "Hibernation is one step away" and "sudo systemctl hibernate" in note.text
    host, _ = _hib_host(tmp_path / "b", logind="challenge")
    assert detect_hibernation(host).value is True


def test_without_logind_a_hibernation_the_rest_allows_is_unknown(cat, tmp_path):
    from daprivacyscanner.context import detect_hibernation
    host, _ = _hib_host(tmp_path)
    v = detect_hibernation(host)
    assert v.value is None and v.notes[0].kind == "limitation"
    assert detect(cat, "enc.hibernate_unencrypted", make_scan(host, hibernation=v)).status is Status.UNKNOWN


FEDORA = lsblk("fedora-40-btrfs-luks.json")
SWAPFILE = {"/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n/home/swapfile file 8388604 0 -2\n",
            "/sys/power/resume": "0:0\n", "/sys/power/state": "freeze mem disk\n", "/etc/os-release": "ID=fedora\n"}


def test_suspend_then_hibernate_set_up_by_the_guide_passes(cat, tmp_path, system, monkeypatch):
    """The check read only /sys/power/state, so neither of the guide's fixes was recognised, and its "this check shows
    it at the next scan" was wrong."""
    from daprivacyscanner.checks import load_all
    from test_guides import apply, options, revert, rooted
    host = make_host(tmp_path, files=SWAPFILE)
    rooted(host, system, monkeypatch)
    scan = make_scan(host, devices=FEDORA, hibernation=True, fde="full")
    assert detect(cat, "kern.suspend_keys_in_ram", scan).status is Status.FAIL
    check = load_all()["kern.suspend_keys_in_ram"](cat["kern.suspend_keys_in_ram"])
    log, res = apply(host, options(check.plan_guide(scan, Outcome(Status.FAIL, "x")))["Suspend, then hibernate after 1 hour"])
    o = detect(cat, "kern.suspend_keys_in_ram", scan)
    assert o.status is Status.PASS and "hibernates after 1 hour" in o.summary
    assert next(s for s in check.plan_guide(scan, o).steps if s.title.startswith("Hibernate")).done
    o = detect(cat, "kern.suspend_keys_in_ram", make_scan(host, devices=FEDORA, hibernation=False, fde="full"))
    assert o.status is Status.FAIL and "hibernation doesn't work here" in o.summary       # gone back to plain suspend
    revert(host, log, res)


def test_plasma_and_cinnamon_decide_the_lid_themselves(cat, tmp_path):
    """PowerDevil and Cinnamon's settings daemon hold logind's lid inhibitor: their own settings count, and the guide
    says where they are."""
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.desktop import GNOME
    from fakes import FakeGSettings
    check = load_all()["kern.suspend_keys_in_ram"](cat["kern.suspend_keys_in_ram"])
    host = make_host(tmp_path, files=SWAPFILE,
                     home_files={".config/powerdevilrc": "[Battery][SuspendAndShutdown]\nSleepMode=3\n"})
    kde = make_scan(host, devices=FEDORA, hibernation=True, fde="full", desktop=("kde",), plasma_major=6)
    assert detect(cat, "kern.suspend_keys_in_ram", kde).status is Status.PASS
    (host.home / ".config/powerdevilrc").write_text("[Battery][SuspendAndShutdown]\nSleepMode=1\n")
    step = next(s for s in check.plan_guide(kde, Outcome(Status.FAIL, "x")).steps if s.title.startswith("Hibernate"))
    assert "System Settings → Power Management" in step.text and "Standby, then hibernate" in step.text
    assert [a.args["name"] for o in step.options for a in o.plan.actions] == ["sleep-delay", "sleep-delay"]

    gs = FakeGSettings({("org.cinnamon.settings-daemon.plugins.power", "lid-close-battery-action"): "'suspend'",
                        ("org.cinnamon.settings-daemon.plugins.power", "inhibit-lid-switch"): "true"})
    host = make_host(tmp_path / "c", files={**SWAPFILE, "/etc/systemd/logind.conf.d/60-x.conf":
                                            "[Login]\nHandleLidSwitch=suspend-then-hibernate\n"})
    host.runner.handlers["gsettings"] = gs
    cin = make_scan(host, devices=FEDORA, hibernation=True, fde="full", desktop=("x-cinnamon",))
    assert detect(cat, "kern.suspend_keys_in_ram", cin).status is Status.FAIL      # Cinnamon holds the lid: logind's isn't used
    step = next(s for s in check.plan_guide(cin, Outcome(Status.FAIL, "x")).steps if "lid" in s.title.lower())
    assert "When the lid is closed to Hibernate" in step.text and not step.options
    gs.values[("org.cinnamon.settings-daemon.plugins.power", "lid-close-battery-action")] = "'hibernate'"
    cin = make_scan(host, devices=FEDORA, hibernation=True, fde="full", desktop=("x-cinnamon",))
    o = detect(cat, "kern.suspend_keys_in_ram", cin)
    assert o.status is Status.PASS and "closing the lid hibernates" in o.summary


def test_cryptsetup_suspend_installed_passes(cat, tmp_path):
    host = make_host(tmp_path, files={**SWAPFILE, "/usr/lib/systemd/system/systemd-suspend.service.d/"
                                                  "cryptsetup-suspend.conf": "[Service]\n"})
    o = detect(cat, "kern.suspend_keys_in_ram", make_scan(host, devices=FEDORA, hibernation=False, fde="full"))
    assert o.status is Status.PASS and "cryptsetup-suspend" in o.summary


def test_the_panels_say_what_the_scan_says(tmp_path):
    """The RAM disk and browser panels said "this computer can hibernate" where the scan said it can't."""
    from daprivacyscanner.tools import ramdisk as R
    host, _ = _hib_host(tmp_path, logind="no")
    assert R.hibernation_possible(host) is False
    assert not any("Hibernating" in n or "hibernate" in n for n in R.memory_notes(host, R.status(host)))
