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
