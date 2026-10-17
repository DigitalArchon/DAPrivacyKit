"""Encryption and kernel checks corrected after the review of 2026-10-17 (what a P330 with Mint 22.3, the Ubuntu 26.04,
Fedora 44 and Omarchy VMs showed, and what reading the checks against their fixes found)."""

import pytest

from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status

from conftest import detect, ev, lsblk, make_host, make_scan
from test_guides import _advice

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
