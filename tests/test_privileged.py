"""The privileged helper: its parsers, its own argument checks, its protocol, and how the app
starts it. pkexec is replaced with a stand-in, so nothing here runs as root."""

import json
import os
import stat
import subprocess
import sys

import pytest

from daprivacyscanner import helper, privileged
from daprivacyscanner.privileged import HelperDeclined, HelperUnavailable, PkexecHelper

from conftest import sample

HELPER = helper.__file__


# ------------------------------------------------------------------ parsing

def test_parse_luks2_dump():
    d = helper.parse_luks_dump(sample("luksdump/luks2-tpm2-no-pin.txt"))
    assert d["version"] == 2
    assert d["keyslots"] == [{"id": 0, "type": "luks2", "pbkdf": "argon2id"}, {"id": 1, "type": "luks2", "pbkdf": "pbkdf2"}]
    assert d["tokens"] == [{"id": 0, "type": "systemd-tpm2", "keyslots": [1], "tpm2_pin": False}]
    assert "Salt" not in json.dumps(d)                    # nothing beyond what detection needs


def test_parse_luks1_dump():
    d = helper.parse_luks_dump(sample("luksdump/luks1.txt"))
    # LUKS1 has no persistent flags ("flags", LUKS2's, for the TRIM guide since the review of 2026-10-17)
    assert d == {"version": 1, "keyslots": [{"id": 0, "type": "luks1", "pbkdf": "pbkdf2"}], "tokens": [], "flags": None}


def test_parse_clevis_list():
    assert helper.parse_clevis_list(sample("clevis/tpm2.txt"))[0]["pin"] == "tpm2"


# ------------------------------------------------------------------ the helper's own checks

@pytest.mark.parametrize("device", ["/etc/passwd", "/dev/../etc/passwd", "dev/sda", "/dev/sda; rm -rf /", 7, None])
def test_refuses_non_device_paths(device):
    with pytest.raises(helper.Refused):
        helper._block_device(device)


def test_refuses_character_devices():
    with pytest.raises(helper.Refused, match="not a block device"):
        helper._block_device("/dev/null")


@pytest.mark.parametrize("path", ["/etc/shadow", "/etc/sddm.conf.d/../../shadow", "etc/crypttab", "/root/.ssh/id_rsa", 3])
def test_refuses_files_not_on_its_list(path):
    with pytest.raises(helper.Refused):
        helper.read_file({"path": path})


def test_reads_listed_files_but_not_through_symlinks(tmp_path, monkeypatch):
    real = tmp_path / "crypttab"
    real.write_text("root UUID=x none luks\n")
    link = tmp_path / "linked.conf"
    link.symlink_to("/etc/passwd")
    monkeypatch.setattr(helper, "READABLE", (str(real), str(tmp_path / "*.conf"), str(tmp_path / "missing")))
    assert helper.read_file({"path": str(real)}) == {"text": "root UUID=x none luks\n"}
    assert helper.read_file({"path": str(tmp_path / "missing")}) == {"missing": True}
    with pytest.raises(helper.Refused, match="symlinks"):
        helper.read_file({"path": str(link)})


def test_handle_protocol():
    assert helper.handle('{"id": 1, "action": "hello"}')["result"]["version"] == helper.PROTOCOL
    assert helper.handle('{"id": 2, "action": "rm", "args": {}}') == {"id": 2, "ok": False, "error": "unknown action"}
    assert helper.handle('{"id": 3, "action": "read_file", "args": {"path": "/etc/shadow"}}')["ok"] is False
    assert helper.handle("not json")["ok"] is False
    assert helper.handle('[1, 2]')["ok"] is False


def test_helper_runs_standalone_in_isolated_mode():
    """As pkexec runs it: `python3 -I helper.py`, no package on the path."""
    p = subprocess.run([sys.executable, "-I", HELPER], input='{"id": 1, "action": "hello"}\n',
                       capture_output=True, text=True, timeout=20, cwd="/")
    reply = json.loads(p.stdout)
    assert reply == {"id": 1, "ok": True, "result": {"version": helper.PROTOCOL, "uid": os.geteuid()}}


# ------------------------------------------------------------------ starting it

def fake_pkexec(tmp_path, monkeypatch, body: str):
    """A `pkexec` on PATH that runs `body` (a shell script) instead of asking for root."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "pkexec"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setattr(privileged, "SYSTEM_PYTHON", sys.executable)


def test_declined(tmp_path, monkeypatch):
    fake_pkexec(tmp_path, monkeypatch, "echo 'Error executing command as another user: Request dismissed' >&2\nexit 126\n")
    with pytest.raises(HelperDeclined):
        PkexecHelper.start(timeout=10)


def test_no_polkit_agent(tmp_path, monkeypatch):
    fake_pkexec(tmp_path, monkeypatch, "echo 'Error executing command as another user: No authentication agent found.' >&2\nexit 127\n")
    with pytest.raises(HelperUnavailable, match="authentication agent") as e:
        PkexecHelper.start(timeout=10)
    assert not isinstance(e.value, HelperDeclined)


@pytest.mark.skipif(os.geteuid() == 0, reason="the stand-in would really be root")
def test_a_helper_that_is_not_root_is_refused(tmp_path, monkeypatch):
    fake_pkexec(tmp_path, monkeypatch, 'exec "$@"\n')           # runs the helper as this user
    with pytest.raises(HelperUnavailable, match="did not start as root"):
        PkexecHelper.start(timeout=20)


def test_talks_to_a_running_helper(tmp_path, monkeypatch):
    fake_pkexec(tmp_path, monkeypatch, 'exec "$@"\n')
    proc = subprocess.Popen(["pkexec", sys.executable, "-I", HELPER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    h = PkexecHelper(proc, privileged.helper_command())
    try:
        if os.geteuid() != 0:
            with pytest.raises(privileged.HelperError, match="changes need root"):
                h.call("write_dropin", {"name": "sleep", "settings": {"AllowHibernation": "no"}})
        with pytest.raises(privileged.HelperError, match="not on the helper's list"):
            h.read_file("/etc/shadow")
        with pytest.raises(privileged.HelperError, match="not a block device"):
            h.luks_dump("/dev/null")
        assert h._call("hello", {})["version"] == helper.PROTOCOL
    finally:
        h.close()
    assert proc.returncode == 0


def test_installed_helper_must_be_root_owned(tmp_path, monkeypatch):
    fake = tmp_path / "daprivacyscanner-helper"
    fake.write_text("#!/usr/bin/python3 -I\n")
    fake.chmod(0o755)
    monkeypatch.setattr(privileged, "INSTALLED_HELPER", fake)
    if os.geteuid() != 0:
        assert privileged.installed_helper() is None                  # owned by this user: not trusted
        assert privileged.helper_command()[1:3] == [privileged.SYSTEM_PYTHON, "-I"]


# ------------------------------------------------------------------ an installed helper from another version

def helper_surface() -> str:
    """What an installed helper must have to serve this app: its actions and allowlists."""
    import hashlib
    surface = {"actions": sorted(helper.ACTIONS), "readable": sorted(map(str, helper.READABLE)),
               "dropins": sorted(helper.DROPINS), "edits": sorted(helper.EDITS), "services": sorted(helper.SERVICES),
               "sysctls": sorted(helper.SYSCTLS), "policies": {k: sorted(v) for k, v in helper.POLICIES.items()},
               "in_memory": list(helper.IN_MEMORY), "unit_dir": helper.UNIT_DIR}
    return hashlib.sha256(json.dumps(surface, sort_keys=True).encode()).hexdigest()[:16]


# the surface each protocol version stands for
SURFACES = {4: "afe8f5a5be1c5b48", 5: "87c08bf809a1a000", 6: "f74cc3bd8d4bdd5f", 7: "e5030f7f229d9b28", 8: "07b86ce070388f82", 9: "47adc7186ce4674e",
            10: "6eda0bae1887c092", 11: "7308893a8ed980b7", 12: "8572e84fd6bda23a", 13: "3ad984a35bada39f",
            14: "fd55a46e5596d111", 15: "fd55a46e5596d111",     # 15: names_check counts by block (same surface)
            16: "73e2b548e7e8ffd2", 17: "73e2b548e7e8ffd2",     # 17: ramdisk_open/close take a name (TempBrowser)
            18: "483d10ebb3b07a38",                             # 18: swap_off and swap_on
            19: "95948b383a5008fb",                             # 19: Plasma Login Manager's autologin files
            20: "95948b383a5008fb",                             # 20: changes say what they ran ("ran") and wrote
            21: "95948b383a5008fb",                             # 21: reverts remove the folders a change made
            22: "95948b383a5008fb",                             # 22: and the .wants folders enabling a unit made
            23: "5a2261b2fc5d7e85",                             # 23: clear_syslog, syslog daemons, NetworkManager defaults
            24: "3dc70eec096a02f8",                             # 24: OpenSnitch: its rules, settings, log and service
            25: "6a0cdefc1e1dd2ec",                             # 25: names from the ext4 journal, and clearing it
            26: "2df0660e730b9b6a",                             # 26: the watch of one app (What does this app keep?)
            27: "2df0660e730b9b6a",                             # 27: install_self installs the code read at start; ramdisk_open's answer
            28: "eeefe6d32bd215ed"}                             # 28: set_service takes units together and records a partial failure; reverts say what they put back; the SecureBoot variable's right GUID; clear_journal_files; SafeBrowsingProtectionLevel


def test_changing_what_the_helper_does_bumps_its_protocol():
    """An installed helper is a copy made at install time. If actions or allowlists change while
    PROTOCOL stays, this app would accept an older copy and fail on what it lacks."""
    assert SURFACES.get(helper.PROTOCOL) == helper_surface(), \
        "The helper's actions or allowlists changed: bump helper.PROTOCOL and record the new surface in SURFACES."


def test_an_installed_helper_from_another_version_is_named_as_such(tmp_path, monkeypatch):
    installed = tmp_path / "daprivacyscanner-helper"
    installed.write_text("#!/usr/bin/python3 -I\nPROTOCOL = 3\n")
    monkeypatch.setattr(privileged, "installed_helper", lambda: installed)
    assert privileged.installed_helper_protocol() == 3 and privileged.installed_helper_stale()
    installed.write_text(f"PROTOCOL = {helper.PROTOCOL}\n")
    assert not privileged.installed_helper_stale()
    monkeypatch.setattr(privileged, "installed_helper", lambda: None)
    assert not privileged.installed_helper_stale()


def test_without_a_runtime_folder_the_helper_copy_goes_in_a_private_folder_of_its_own(tmp_path, monkeypatch):
    """Never a fixed name in /tmp, which another account could make first: a folder under a random name of this
    process's own, 0700, the copy 0600 in it."""
    import stat
    import tempfile
    from daprivacyscanner import hostenv, privileged

    appdir = tmp_path / "squashfs-root"
    (appdir / "x").mkdir(parents=True)
    src = appdir / "x/helper.py"
    src.write_text("print(1)\n")
    monkeypatch.setattr(hostenv, "appdir", lambda: str(appdir))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(privileged, "_TMP", None)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    dest = privileged._readable_by_root(src)
    assert dest.read_text() == "print(1)\n" and dest.parent.parent == tmp_path
    assert dest.parent.name.startswith("daprivacyscanner-") and dest.parent.name != "daprivacyscanner"
    assert stat.S_IMODE(dest.parent.stat().st_mode) == 0o700 and stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert privileged._readable_by_root(src).parent == dest.parent             # the same folder for this process
    # with a runtime folder: the user's own folder in it, as before
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    assert privileged._readable_by_root(src).parent == tmp_path / "run/daprivacyscanner"


def test_a_copy_that_cant_be_made_is_said_not_raised(monkeypatch):
    import shutil
    from daprivacyscanner import privileged

    def fail():
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/pkexec")
    monkeypatch.setattr(privileged, "helper_command", fail)
    with pytest.raises(privileged.HelperUnavailable, match="where root can read it"):
        privileged.PkexecHelper.start()
