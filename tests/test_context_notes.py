"""Virtualization, informational notes, and context detection with the privileged helper."""

import os

import pytest

from daprivacyscanner import blockdev, network
from daprivacyscanner.context import (detect_autologin, detect_context, detect_exposed_services, detect_hibernation,
                                    detect_tpm_unlock_no_pin, detect_virtualization)
from daprivacyscanner.host import CommandResult, Unreadable
from daprivacyscanner.privileged import FakePrivileged

from conftest import make_host, sample, skip_if_root

VIRT_C = ("systemd-detect-virt", "--container")
VIRT_V = ("systemd-detect-virt", "--vm")
NONE = CommandResult((), 1, "none\n")


def devices(name):
    return blockdev.parse_lsblk(sample(f"lsblk/{name}"))


# ------------------------------------------------------------------ virtualization

@pytest.mark.parametrize("commands, files, expected", [
    ({VIRT_C: NONE, VIRT_V: "kvm\n"}, {}, "vm"),
    ({VIRT_C: NONE, VIRT_V: "oracle\n"}, {}, "vm"),
    ({VIRT_C: "podman\n"}, {}, "container"),
    ({VIRT_C: NONE, VIRT_V: NONE}, {}, "none"),
    # no systemd-detect-virt
    ({}, {"/run/.containerenv": ""}, "container"),
    ({}, {"/proc/version": "Linux version 5.15.153.1-microsoft-standard-WSL2"}, "vm"),
    ({}, {"/sys/class/dmi/id/sys_vendor": "QEMU\n", "/sys/class/dmi/id/product_name": "Standard PC (Q35 + ICH9, 2009)\n"}, "vm"),
    ({}, {"/sys/class/dmi/id/sys_vendor": "innotek GmbH\n"}, "vm"),
    ({}, {"/proc/cpuinfo": "processor\t: 0\nflags\t\t: fpu vme de pse hypervisor lahf_lm\n"}, "vm"),
    ({}, {"/sys/class/dmi/id/sys_vendor": "LENOVO\n", "/proc/cpuinfo": "flags\t\t: fpu vme\n"}, "none"),
])
def test_virtualization(tmp_path, commands, files, expected):
    assert detect_virtualization(make_host(tmp_path, commands=commands, files=files)).value == expected


def test_vm_notes_explain_risks_and_limits(tmp_path):
    v = detect_virtualization(make_host(tmp_path, commands={VIRT_C: NONE, VIRT_V: "kvm\n"}))
    kinds = [n.kind for n in v.notes]
    assert kinds.count("risk") == 2 and kinds.count("limitation") == 1
    assert any("memory" in n.text for n in v.notes)


def test_vm_notes_name_guest_agents_and_shared_folders(tmp_path):
    host = make_host(tmp_path, commands={VIRT_C: NONE, VIRT_V: "oracle\n"}, files={
        "/proc/812/comm": "VBoxClient\n", "/proc/900/comm": "bash\n", "/proc/self/comm": "python3\n",
        "/proc/mounts": "/dev/sda3 / ext4 rw 0 0\nshare /media/sf_share vboxsf rw 0 0\n",
    })
    v = detect_virtualization(host)
    assert ("Guest agent running", "VBoxClient") in [(e.label, e.value) for e in v.evidence]
    channels = next(n for n in v.notes if n.title == "Channels between this VM and the host")
    assert "shared clipboard" in channels.text and "/media/sf_share" in channels.text


def test_container_note(tmp_path):
    v = detect_virtualization(make_host(tmp_path, commands={VIRT_C: "docker\n"}))
    assert v.notes[0].kind == "limitation"


def test_in_a_vm_the_device_type_is_unknown(tmp_path):
    host = make_host(tmp_path, commands={VIRT_C: NONE, VIRT_V: "microsoft\n"},
                     files={"/sys/class/dmi/id/chassis_type": "3\n"})       # Hyper-V reports a desktop chassis
    ctx = detect_context(host)
    assert ctx["virtualization"] == "vm" and ctx["device"] is None


def test_in_a_container_the_hosts_chassis_counts(tmp_path):
    host = make_host(tmp_path, commands={VIRT_C: "podman\n"}, files={"/sys/class/dmi/id/chassis_type": "9\n"})
    assert detect_context(host)["device"] == "laptop"


# ------------------------------------------------------------------ hibernation notes

SWAP_2G = "Filename\tType\tSize\tUsed\tPriority\n/swapfile file\t2097148\t0\t-2\n"
SWAP_16G = "Filename\tType\tSize\tUsed\tPriority\n/swapfile file\t16777212\t0\t-2\n"


def hib_files(swaps, cmdline):
    return {"/sys/power/state": "freeze mem disk", "/sys/power/disk": "[platform] shutdown", "/proc/swaps": swaps,
            "/proc/cmdline": cmdline, "/sys/power/resume": "0:0", "/sys/power/image_size": str(6 * 2**30)}


def test_hibernation_one_step_away_when_swap_is_too_small(tmp_path):
    v = detect_hibernation(make_host(tmp_path, files=hib_files(SWAP_2G, "ro resume=UUID=x")))
    assert v.value is False
    [note] = v.notes
    assert note.kind == "risk" and "smaller than the hibernation image" in note.text
    assert "6.0 GiB" in note.text and "enc.hibernate_unencrypted" in note.related


def test_hibernation_one_step_away_when_resume_is_missing(tmp_path):
    v = detect_hibernation(make_host(tmp_path, files=hib_files(SWAP_16G, "ro quiet")))
    assert v.value is False and "no resume device" in v.notes[0].text


@pytest.mark.parametrize("swaps, cmdline", [(SWAP_16G, "ro resume=UUID=x"), (SWAP_2G, "ro quiet")])
def test_no_hibernation_note_when_it_is_possible_or_far_off(tmp_path, swaps, cmdline):
    from daprivacyscanner.host import CommandResult
    host = make_host(tmp_path, files=hib_files(swaps, cmdline))
    host.runner.handlers["busctl"] = lambda argv: CommandResult(argv, 0, 's "yes"\n')     # logind lets this user
    assert detect_hibernation(host).notes == []


# ------------------------------------------------------------------ LLMNR and port names

def test_llmnr_gets_an_explanation(tmp_path):
    host = make_host(tmp_path, commands={network.SS_ARGS: sample("ss/fedora-40.txt")})
    v = detect_exposed_services(host)
    assert "5355/tcp (LLMNR name resolution)" in [e.value for e in v.evidence]
    assert v.notes[0].title.startswith("LLMNR") and "LLMNR=no" in v.notes[0].text


def test_ports_are_named(tmp_path):
    v = detect_exposed_services(make_host(tmp_path, commands={network.SS_ARGS: sample("ss/mint-22.txt")}))
    assert [e.value for e in v.evidence if e.label == "Listening"] == ["22/tcp (SSH)", "3389/tcp (remote desktop (RDP))"]
    assert v.notes == []


# ------------------------------------------------------------------ TPM with the helper

FEDORA_LUKS = "/dev/nvme0n1p3"


def test_luks_devices_and_paths():
    assert [d.path for d in blockdev.luks_devices(devices("fedora-40-btrfs-luks.json"))] == [FEDORA_LUKS]
    assert [d.path for d in blockdev.luks_devices(devices("debian-12-partial.json"))] == ["/dev/sda3"]
    lv = next(d for d in devices("ubuntu-24.04-luks-lvm.json") if d.type == "lvm")
    assert lv.path == "/dev/mapper/ubuntu--vg-ubuntu--lv"


@pytest.mark.parametrize("dump, clevis, expected", [
    ("luks2-tpm2-no-pin.txt", None, True),
    ("luks2-tpm2-pin.txt", None, False),
    ("luks2-passphrase.txt", None, False),
    ("luks1.txt", None, False),
    ("luks2-clevis.txt", "tpm2.txt", True),
    ("luks2-clevis.txt", "sss-tpm2-and-tang.txt", False),     # needs Tang too
])
def test_tpm_with_root(tmp_path, dump, clevis, expected):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged(luks={FEDORA_LUKS: sample(f"luksdump/{dump}")},
                                     clevis={FEDORA_LUKS: sample(f"clevis/{clevis}")} if clevis else {})
    v = detect_tpm_unlock_no_pin(host, devices("fedora-40-btrfs-luks.json"))
    assert v.value is expected and not v.notes


def test_tpm_unknown_when_a_header_cannot_be_read(tmp_path):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged()
    v = detect_tpm_unlock_no_pin(host, devices("fedora-40-btrfs-luks.json"))
    assert v.value is None and v.partial


def test_tpm_without_root_says_how_to_find_out(tmp_path):
    v = detect_tpm_unlock_no_pin(make_host(tmp_path), devices("fedora-40-btrfs-luks.json"))
    assert v.value is None and v.notes[0].kind == "limitation" and "administrator" in v.notes[0].title


def test_tpm_no_pin_raises_autologin_severity(cat, tmp_path):
    from daprivacyscanner.catalogue import effective_severity

    host = make_host(tmp_path, commands={("lsblk", "-J", "-o", blockdev.COLUMNS): sample("lsblk/fedora-40-btrfs-luks.json")})
    host.privileged = FakePrivileged(luks={FEDORA_LUKS: sample("luksdump/luks2-tpm2-no-pin.txt")})
    ctx = detect_context(host)
    assert ctx["tpm_unlock_no_pin"] is True
    assert effective_severity(cat["auth.autologin"], ctx.vars()).value == 10


# ------------------------------------------------------------------ root-only files through the helper

@skip_if_root
def test_unreadable_files_are_read_through_the_helper(tmp_path):
    host = make_host(tmp_path, files={"/etc/sddm.conf.d/kde_settings.conf": "secret\n", "/etc/shadow": "x\n"},
                     links={"/etc/systemd/system/display-manager.service": "/usr/lib/systemd/system/sddm.service"})
    for p in ("/etc/sddm.conf.d/kde_settings.conf", "/etc/shadow"):
        os.chmod(host.sys_path(p), 0)
    assert detect_autologin(host).value is None                         # without root: unknown

    host.privileged = FakePrivileged(files={"/etc/sddm.conf.d/kde_settings.conf": "[Autologin]\nUser=alice\n"})
    assert detect_autologin(host).value is True
    with pytest.raises(Unreadable):
        host.read_sys("/etc/shadow")                                    # not on the helper's list
