"""The system-detection review of 2026-11-12: process names, unreadable folders and commands, the severity range
over unknown context keys, and the auth, encryption, kernel and sandbox checks it found wanting."""

from __future__ import annotations

from pathlib import Path

import pytest

from daprivacyscanner import procnames
from daprivacyscanner.checks import _util
from daprivacyscanner import context as ctxmod

from conftest import make_host, make_scan, skip_if_root

# ------------------------------------------------------------------ process names

# the kernel cuts a name at 15 bytes: "Évolution-données" ends in half an "é"; any process can set its own bytes
CUT = "Évolution-donn".encode() + b"\xc3"
ODD = b"\xff\xfe\x80name"


def _proc(tmp_path, procs: dict[int, bytes]):
    host = make_host(tmp_path)
    for pid, name in procs.items():
        d = host.sys_path(f"/proc/{pid}")
        d.mkdir(parents=True)
        (d / "comm").write_bytes(name + b"\n")
        (d / "fd").mkdir()
    return host


def test_a_name_cut_mid_character_or_of_any_bytes_is_read_leniently(tmp_path):
    host = _proc(tmp_path, {10: CUT, 11: ODD, 12: b"ssh-agent", 13: b"qemu-ga"})
    assert procnames.comm(host.sys_path("/proc/10")) == "Évolution-donn�"
    assert procnames.comm(host.sys_path("/proc/11")).endswith("name")
    names = _util.processes(host)
    assert {"ssh-agent", "qemu-ga"} <= names and len(names) == 4
    assert not _util.removed_while_running(host, "ssh-agent")
    assert {n for n, _ in _util.open_files(host)} >= {"ssh-agent", "qemu-ga"}
    assert ctxmod._guest_agents(host) == ["qemu-ga"]


def test_a_process_that_ended_is_skipped(tmp_path):
    host = _proc(tmp_path, {12: b"ssh-agent"})
    (host.sys_path("/proc/99")).mkdir()                 # gone between the listing and the read: no comm
    assert _util.processes(host) == {"ssh-agent"}
    with pytest.raises(OSError):
        procnames.comm(host.sys_path("/proc/99"))


def test_no_module_reads_a_name_as_strict_text():
    src = Path(__file__).resolve().parents[1] / "src" / "daprivacyscanner"
    import re
    strict = re.compile(r'/ "comm"\)\.read_text\(\)|/comm"\)\)? as f')      # open(...comm) with no errors=
    bad = [str(p.relative_to(src)) for p in src.rglob("*.py") if strict.search(p.read_text())]
    assert not bad, bad


# ------------------------------------------------------------------ a folder or command that couldn't be read

@skip_if_root
def test_a_root_only_system_folder_is_unreadable_never_empty(tmp_path):
    from daprivacyscanner.checks.encryption import snapper_configs
    from daprivacyscanner.host import Unreadable
    host = make_host(tmp_path, files={"/etc/snapper/configs/root": 'SUBVOLUME="/"\n'})
    assert [p.name for p in _util.sys_children(host, "/etc/snapper/configs")] == ["root"]
    assert _util.sys_children(host, "/etc/nothing-here") == []
    folder = host.sys_path("/etc/snapper/configs")
    folder.chmod(0o000)
    try:
        with pytest.raises(Unreadable):
            _util.sys_children(host, "/etc/snapper/configs")
        assert _util.children(folder) == []                     # the user's-files helper reads it as nothing
        assert snapper_configs(make_scan(host)) == ([], ["*"])     # a config that couldn't be read, never none
    finally:
        folder.chmod(0o755)


def test_a_command_that_failed_says_so():
    from daprivacyscanner.host import CommandResult
    assert _util.output(CommandResult(("x",), 0, "a\n")) == "a\n"
    assert _util.output(CommandResult(("x",), 0, "")) == ""
    assert _util.output(CommandResult(("x",), 1, "partial")) is None
    assert _util.output(CommandResult(("x",), 127, "")) is None


# the other detection agent's modules still list some system folders as the user would (follow-up: convert them)
LISTS_AS_THE_USER = {"network.py", "telemetry.py", "apps.py", "browser.py"}


def test_checks_list_system_folders_with_sys_children():
    """children() turns "permission denied" into "empty": a system check without administrator access would pass on a
    folder only root can list. Allowed: /proc, and lines marked as listing what the user's own programs see."""
    import re
    checks = Path(__file__).resolve().parents[1] / "src" / "daprivacyscanner" / "checks"
    bad = re.compile(r"children\((?:scan\.)?host\.sys_path\((?!\"/proc\"\))")
    found = [f"{p.name}:{n}" for p in sorted(checks.rglob("*.py")) if p.name not in LISTS_AS_THE_USER
             for n, line in enumerate(p.read_text().splitlines(), 1)
             if bad.search(line) and "as the user sees it" not in line]
    assert not found, found


# ------------------------------------------------------------------ a severity over what couldn't be told

def test_an_unprivileged_scan_ranks_autologin_by_what_tpm_unlock_could_make_it(cat, tmp_path):
    """Without administrator access a laptop with TPM unlock and automatic login showed 6, not 10: the unknown key
    was read as the benign branch. Now it is 6–10, ranked, counted and reported at 10, with what settles it."""
    import json
    from daprivacyscanner import report as report_mod
    from daprivacyscanner.model import Outcome, Status
    from test_runner import check, laptop_host, run
    autologin = check("auth.autologin", lambda self, scan: Outcome(Status.FAIL, "Logs in by itself."))
    host = laptop_host(tmp_path, lsblk="fedora-40-btrfs-luks.json")
    report = run(cat, host, autologin)
    r = report.results["auth.autologin"]
    assert (r.lowest, r.effective_severity, r.severity_text()) == (6, 10, "6–10") and report.findings == [r]
    assert report.context.values["tpm_unlock_no_pin"].needs_admin
    d = report.to_dict()
    assert d["results"]["auth.autologin"]["severity_low"] == 6
    assert d["context"]["values"]["tpm_unlock_no_pin"]["needs_admin"] is True
    text = report_mod.export(d, cat, "text", None, False, {})
    assert "[6–10] Problem: Automatic login enabled" in text
    assert ("Severity 6–10: it depends on whether the disk unlocks with nothing typed, which needs administrator access "
            "(a scan with administrator access, --admin, settles it). Ranked at 10, the highest it could be.") in text
    exported = json.loads(report_mod.export(d, cat, "json", None, False, {}))
    assert exported["report"]["results"]["auth.autologin"]["severity_low"] == 6
    # known: no range, and nothing said
    r.severity_low = None
    assert r.severity_text() == "10" and "severity_low" not in r.to_dict()


def test_a_risk_with_a_range_is_lowered_at_both_ends(cat, tmp_path):
    from daprivacyscanner.model import Outcome, Status
    from test_runner import check, laptop_host, run
    autologin = check("auth.autologin", lambda self, scan: Outcome(Status.WARN, "Logs in by itself, sometimes."))
    r = run(cat, laptop_host(tmp_path, lsblk="fedora-40-btrfs-luks.json"), autologin).results["auth.autologin"]
    lower = cat["auth.autologin"].warn_lower
    assert (r.severity_low, r.effective_severity) == (6 - lower, 10 - lower) and r.as_warning


# ------------------------------------------------------------------ what unlocks the disk with nothing typed

ROOT_LUKS = "luks-0f2c4e5a-1b2c-4d3e-8f90-123456789abc"      # the Fedora sample's root; its /boot is plain ext4


class FakeHelper:
    def __init__(self, dump=None, clevis=None):
        self.dump, self.clevis = dump or {"version": 2, "tokens": []}, clevis
        self.can_read = lambda path: False

    def luks_dump(self, device):
        return self.dump

    def clevis_list(self, device):
        from daprivacyscanner.privileged import HelperError
        if self.clevis is None:
            raise HelperError("clevis is not installed")
        return self.clevis


def _tpm(tmp_path, files=None, helper=None):
    from conftest import lsblk
    host = make_host(tmp_path, files=files or {})
    host.privileged = helper
    return ctxmod.detect_tpm_unlock_no_pin(host, lsblk("fedora-40-btrfs-luks.json"))


@pytest.mark.parametrize("files, value, label", [
    # the root volume's key file, which Debian's KEYFILE_PATTERN copies into the initramfs on the plain /boot
    ({"/etc/crypttab": ROOT_LUKS + " UUID=x /etc/keys/root.key luks\n",
      "/etc/cryptsetup-initramfs/conf-hook": 'KEYFILE_PATTERN="/etc/keys/*.key"\n'}, True, ctxmod.KEY_FILE_READABLE),
    # without it the initramfs may or may not carry it: couldn't tell
    ({"/etc/crypttab": ROOT_LUKS + " UUID=x /etc/keys/root.key luks\n"}, None, ctxmod.NOT_TOLD),
    # a data volume's key file on the unencrypted /boot
    ({"/etc/crypttab": "data UUID=y /boot/data.key luks\n"}, True, ctxmod.KEY_FILE_READABLE),
    # on the encrypted root: only the root's passphrase reaches it
    ({"/etc/crypttab": "data UUID=y /etc/keys/data.key luks\n"}, None, None),
    # a key on a USB stick, and swap with a random key
    ({"/etc/crypttab": "data UUID=y /data.key:UUID=stick luks\nswap /dev/sda3 /dev/urandom swap\n"}, None, None),
    ({"/proc/cmdline": "root=x rd.luks.key=/root.key quiet\n"}, True, ctxmod.KEY_FILE_READABLE),
    ({"/proc/cmdline": "root=x rd.luks.key=/root.key:UUID=1234 quiet\n"}, None, None),
    ({"/proc/cmdline": "cryptdevice=UUID=x:root cryptkey=rootfs:/crypto_keyfile.bin\n"}, True, ctxmod.KEY_FILE_READABLE),
    ({"/proc/cmdline": "cryptdevice=UUID=x:root cryptkey=/dev/sdb1:ext4:/key\n"}, None, None),
    ({"/etc/crypttab": ROOT_LUKS + " UUID=x none try-empty-password\n"}, None, ctxmod.NOT_TOLD),
])
def test_key_files_anyone_with_the_disk_can_read_are_found_without_administrator_access(tmp_path, files, value, label):
    v = _tpm(tmp_path, files)
    assert v.value is value
    if label:
        assert label in {e.label for e in v.evidence}
    assert v.needs_admin is (value is None)          # the headers could still say more


@pytest.mark.parametrize("token, value", [
    ({"id": 0, "type": "systemd-tpm2", "keyslots": [1], "tpm2_pin": False, "described": True}, True),
    ({"id": 0, "type": "systemd-tpm2", "keyslots": [1], "tpm2_pin": True, "described": True}, False),
    # systemd's plugin before 251 printed the token but no tpm2-pin: no PINs then
    ({"id": 0, "type": "systemd-tpm2", "keyslots": [1], "tpm2_pin": None, "described": True}, True),
    # no plugin: only the keyslot is printed, which says nothing about a PIN (it was read as "no PIN")
    ({"id": 0, "type": "systemd-tpm2", "keyslots": [1], "tpm2_pin": None}, None),
    ({"id": 0, "type": "ubuntu-fde", "keyslots": [0], "ubuntu_auth": "none"}, True),
    ({"id": 0, "type": "ubuntu-fde", "keyslots": [0], "ubuntu_auth": "pin"}, False),
    ({"id": 0, "type": "ubuntu-fde", "keyslots": [0]}, None),
    ({"id": 1, "type": "ubuntu-fde-recovery", "keyslots": [1]}, False),
    ({"id": 0, "type": "systemd-fido2", "keyslots": [2], "auth": {"fido2-clientPin-required": False,
                                                                  "fido2-up-required": False}}, True),
    ({"id": 0, "type": "systemd-fido2", "keyslots": [2], "auth": {"fido2-clientPin-required": True}}, False),
    ({"id": 0, "type": "systemd-fido2", "keyslots": [2]}, None),
])
def test_tokens_that_unlock_with_nothing_typed(tmp_path, token, value):
    v = _tpm(tmp_path, helper=FakeHelper({"version": 2, "tokens": [token]}))
    assert v.value is value and not v.needs_admin


def test_clevis_on_luks1_is_listed_through_luksmeta(tmp_path):
    binding = [{"slot": 1, "pin": "tpm2", "config": '{"hash":"sha256"}'}]
    assert _tpm(tmp_path, helper=FakeHelper({"version": 1, "tokens": []}, binding)).value is True
    assert _tpm(tmp_path / "b", helper=FakeHelper({"version": 1, "tokens": []})).value is False   # no Clevis


def test_the_helper_reads_token_details_from_the_json_metadata():
    import json
    from daprivacyscanner import helper
    dump = {"version": 2, "tokens": [{"id": 0, "type": "ubuntu-fde", "keyslots": [0], "tpm2_pin": None},
                                     {"id": 1, "type": "systemd-tpm2", "keyslots": [1], "tpm2_pin": None},
                                     {"id": 2, "type": "systemd-fido2", "keyslots": [2], "tpm2_pin": None}]}
    meta = {"tokens": {"0": {"type": "ubuntu-fde", "keyslots": ["0"], "ubuntu_fde_name": "default",
                             "ubuntu_fde_data": {"platform_name": "tpm2", "pin_params": {"iterations": 4}}},
                       "1": {"type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": [7]},
                       "2": {"type": "systemd-fido2", "keyslots": ["2"], "fido2-clientPin-required": False,
                             "fido2-up-required": True, "fido2-credential": "c2VjcmV0"}}}
    out = helper.parse_luks_json(json.dumps(meta), dump)
    t = {x["id"]: x for x in out["tokens"]}
    assert t[0]["ubuntu_auth"] == "pin"
    assert t[1]["tpm2_pin"] is False                      # enrolled before systemd 251: no PIN
    assert t[2]["auth"] == {"fido2-clientPin-required": False, "fido2-up-required": True}
    assert "c2VjcmV0" not in json.dumps(out)              # key material never leaves the helper


def test_the_check_names_what_unlocks_it_and_the_guide_covers_key_files(cat, tmp_path):
    from conftest import detect, lsblk
    from test_guides import build
    files = {"/etc/crypttab": "data UUID=y /boot/data.key luks\n"}
    v = _tpm(tmp_path, files)
    host = make_host(tmp_path / "h", files=files)
    o = detect(cat, "enc.tpm_no_pin", make_scan(host, devices=lsblk("fedora-40-btrfs-luks.json"), tpm_unlock_no_pin=v))
    assert o.summary == "A volume unlocks at boot with nothing typed: with a key file anyone holding the disk can read."
    g = build(cat, host, "enc.tpm_no_pin", devices=lsblk("fedora-40-btrfs-luks.json"), tpm_unlock_no_pin=v)
    assert g.title == "Make the disk ask for something at boot" and "luksKillSlot" in " ".join(g.steps[0].commands)
