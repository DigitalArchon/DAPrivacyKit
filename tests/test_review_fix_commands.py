"""Commands the guides give users to paste, and two fixes' curation, corrected after the review of 2026-11-12: lines
added to /etc/fstab and /etc/crypttab, GRUB's quoting, how boot entries take /etc/kernel/cmdline, USBGuard's policy,
the TPM's binding, the home folder's subvolume, DNF's countme and automatic login."""

import subprocess

import pytest

from daprivacyscanner.checks.guides import append_line
from daprivacyscanner.model import Status

from conftest import make_host, make_scan
from test_guides import _advice


def _run(cmd: str, path, tmp_path) -> None:
    """A command as the user pastes it, run on a copy: sudo left out, the system file replaced by `path`."""
    subprocess.run(cmd.replace("sudo ", "").replace("/etc/fstab", str(path)).replace("/etc/default/grub", str(path)),
                   shell=True, check=True, cwd=tmp_path, capture_output=True)


# ------------------------------------------------------------------ lines added to system files

@pytest.mark.parametrize("before, after", [
    ("UUID=1 / ext4 defaults 0 1", "UUID=1 / ext4 defaults 0 1\nNEW LINE\n"),       # no final newline: one first
    ("UUID=1 / ext4 defaults 0 1\n", "UUID=1 / ext4 defaults 0 1\nNEW LINE\n"),
    ("", "NEW LINE\n"),
    (None, "NEW LINE\n"),                                                            # no file yet (crypttab)
])
def test_a_line_added_never_joins_the_last_one(tmp_path, before, after):
    """`echo LINE | sudo tee -a /etc/fstab` glued the line onto a last line without a newline, breaking that mount."""
    f = tmp_path / "fstab"
    if before is not None:
        f.write_text(before)
    _run(append_line("NEW LINE", "/etc/fstab"), f, tmp_path)
    assert f.read_text() == after


def test_the_guides_add_fstab_and_crypttab_lines_safely(cat, tmp_path):
    host = make_host(tmp_path)
    cmds = _advice(cat, host, "kern.proc_hidepid").steps[3].commands
    assert cmds == [append_line("proc /proc proc defaults,hidepid=invisible,gid=proc 0 0", "/etc/fstab")]
    assert cmds[0].startswith('[ -z "$(sudo tail -c1 /etc/fstab 2>/dev/null)" ] || echo | sudo tee -a /etc/fstab')


# ------------------------------------------------------------------ GRUB

@pytest.mark.parametrize("before, after", [
    ('GRUB_CMDLINE_LINUX_DEFAULT="quiet init_on_free=0"\nGRUB_CMDLINE_LINUX="init_on_free=0"\n',
     'GRUB_CMDLINE_LINUX_DEFAULT="quiet  init_on_free=1"\nGRUB_CMDLINE_LINUX=""\n'),
    # single quotes, as some installers write them: the double-quoted sed added nothing, silently
    ("GRUB_CMDLINE_LINUX_DEFAULT='quiet splash'\nGRUB_CMDLINE_LINUX='init_on_free=0'\n",
     "GRUB_CMDLINE_LINUX_DEFAULT='quiet splash init_on_free=1'\nGRUB_CMDLINE_LINUX=''\n"),
    ("GRUB_CMDLINE_LINUX_DEFAULT=quiet\n", 'GRUB_CMDLINE_LINUX_DEFAULT="quiet init_on_free=1"\n'),
    # no such line: one is added
    ('GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="init_on_free=0"', 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=""\n'
                                                            'GRUB_CMDLINE_LINUX_DEFAULT="init_on_free=1"\n'),
])
def test_grub_options_whatever_the_quotes(cat, tmp_path, before, after):
    host = make_host(tmp_path, files={"/etc/default/grub": before, "/etc/os-release": "ID=debian\n"})
    step = _advice(cat, host, "kern.init_on_free").steps[0]
    grub = tmp_path / "grub"
    grub.write_text(before)
    for cmd in step.commands[:-1]:
        _run(cmd, grub, tmp_path)
    assert grub.read_text() == after and step.commands[-1] == "sudo update-grub"
    sourced = subprocess.run(["bash", "-c", f'. "{grub}"; printf %s "$GRUB_CMDLINE_LINUX_DEFAULT"'],
                             capture_output=True, text=True, check=True).stdout
    assert sourced.split()[-1] == "init_on_free=1"


def test_grub_drop_in_that_sets_it_too_is_named(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/default/grub": 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\n',
                                      "/etc/default/grub.d/50-cloudimg-settings.cfg":
                                          'GRUB_CMDLINE_LINUX_DEFAULT="console=tty1"\n'})
    text = _advice(cat, host, "kern.init_on_free").steps[0].text
    assert "sudoedit /etc/default/grub.d/50-cloudimg-settings.cfg" in text


# ------------------------------------------------------------------ /etc/kernel/cmdline

@pytest.mark.parametrize("files, installed, version, command", [
    # openSUSE's systemd-boot: sdbootutil keeps the entries
    ({}, ("sdbootutil",), "systemd 257 (257.7)", "sudo sdbootutil update-all-entries"),
    # Arch's mkinitcpio builds the unified kernel images from its presets, never through kernel-install
    ({"/etc/mkinitcpio.d/linux.preset": 'PRESETS=(default)\ndefault_uki="/efi/EFI/Linux/arch-linux.efi"\n'}, (),
     "systemd 262 (262.1-1-arch)", "sudo mkinitcpio -P"),
    # a commented-out UKI line (CachyOS's preset) isn't one
    ({"/etc/mkinitcpio.d/linux.preset": '#default_uki="/efi/EFI/Linux/arch-linux.efi"\n'}, (),
     "systemd 262 (262.1-1-arch)", "sudo kernel-install add-all"),
    ({}, (), "systemd 255 (255.4-1ubuntu8)", "sudo kernel-install add-all"),
    # add-all came with systemd 255: Debian 12's 252 adds each kernel in turn
    ({}, (), "systemd 252 (252.33-1~deb12u1)", "kernel-install add \"$(basename \"$d\")\" \"$d/vmlinuz\""),
])
def test_kernel_cmdline_is_taken_by_what_makes_the_entries(cat, tmp_path, files, installed, version, command):
    host = make_host(tmp_path, files={"/etc/kernel/cmdline": "root=/dev/x quiet\n", **files},
                     commands={"systemctl --version": version + "\n+PAM\n"}, installed=installed)
    cmds = _advice(cat, host, "kern.init_on_free").steps[0].commands
    assert cmds[0].startswith("sudo sed -i -E '1s/") and command in cmds[1]


# ------------------------------------------------------------------ USBGuard and the TPM

def test_usbguard_policy_lets_serial_less_devices_in_on_any_port_and_says_the_way_back(cat, tmp_path):
    """generate-policy binds a device without a serial number to its port (via-port): a keyboard moved to another one
    was blocked at the login screen, and the guide gave no way back."""
    g = _advice(cat, make_host(tmp_path, files={"/etc/os-release": "ID=fedora\n"}), "kern.usb_trusted")
    cmds = [c for s in g.steps for c in s.commands]
    assert "sudo sh -c 'usbguard generate-policy -P > /etc/usbguard/rules.conf'" in cmds
    assert not any("generate-policy >" in c for c in cmds)
    back = next(s for s in g.steps if s.title == "If the keyboard is blocked at startup")
    assert "systemd.mask=usbguard.service" in back.text


def test_tpm_reenrol_shows_the_old_binding_first(cat, tmp_path):
    from test_review_enc import UBUNTU
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.model import Outcome
    check = load_all()["enc.tpm_no_pin"](cat["enc.tpm_no_pin"])
    g = check.plan_guide(make_scan(make_host(tmp_path), devices=UBUNTU), Outcome(Status.FAIL, "x"))
    step = g.steps[1]
    assert "PCR 7" in step.text and "--tpm2-pcrs=" in step.text
    dev = step.commands[0].split()[3]
    assert step.commands[:2] == [f"sudo cryptsetup luksDump {dev} | grep -E 'tpm2-(hash-pcrs|pubkey-pcrs|pcrlock)'",
                                 f"sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-with-pin=yes {dev}"]
