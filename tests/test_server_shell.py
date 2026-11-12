"""The local server and the app shell (the review of 2026-11-12): who may talk to the server, what it answers with,
quitting, redaction, exports, the state files, the network for the online tests and how commands are run."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from conftest import make_host, skip_if_root


# ------------------------------------------------------------------ host.py: "not installed" means only that

def test_a_program_that_cant_start_isnt_called_missing(tmp_path):
    """Any OSError read as "not installed" (exit status 127), which checks take for "not on this machine": a program
    that may not be run, one in a wrong format, or an input that couldn't be opened. Only a missing program is."""
    from daprivacyscanner.host import CANT_RUN, NOT_FOUND, SystemRunner
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bad = bindir / "badformat"
    bad.write_bytes(b"\x00\x01\x02 not a program")
    bad.chmod(0o755)
    runner = SystemRunner({"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path)})
    r = runner.run(["badformat"])
    assert r.returncode == CANT_RUN and r.cant_run and not r.missing and not r.ok
    assert "couldn't be started" in r.stderr
    r = runner.run(["nosuchprogram"])
    assert r.returncode == NOT_FOUND and r.missing and not r.cant_run
    ok = bindir / "fine"
    ok.write_text("#!/bin/sh\ncat\n")
    ok.chmod(0o755)
    r = runner.run(["fine"], stdin=tmp_path / "no-such-input")
    assert r.cant_run and not r.missing and "its input couldn't be opened" in r.stderr
    (tmp_path / "input").write_text("hello\n")
    r = runner.run(["fine"], stdin=tmp_path / "input")
    assert r.ok and r.stdout == "hello\n"
    gone = bindir / "noshell"                      # a script whose interpreter isn't installed: not installed, as before
    gone.write_text("#!/nonexistent/interpreter\n")
    gone.chmod(0o755)
    assert runner.run(["noshell"]).missing


# ------------------------------------------------------------------ history.py: the user's accepted findings

def test_an_unreadable_accepted_list_is_kept_aside_never_written_over(tmp_path):
    """A damaged accepted.json read as empty, and accepting the next finding saved itself over it alone: every other
    accepted finding, and the notes written for them, were gone without a word. It is kept aside, as the undo log's."""
    from daprivacyscanner.history import Accepted, kept_aside
    from daprivacyscanner.paths import PathResolver
    acc = Accepted(PathResolver(tmp_path, {"HOME": str(tmp_path)}))
    acc.file.parent.mkdir(parents=True)
    acc.file.write_text('{"auth.screen_lock": {"note": "my desk at the office"')       # cut short
    assert acc.all() == {}
    said = acc.damaged()
    assert "can't be read" in said and "kept as it is" in said
    data = acc.set("net.firewall_off", True, "behind the router")
    assert list(data) == ["net.firewall_off"]
    aside = kept_aside(acc.file)
    assert len(aside) == 1 and "my desk at the office" in aside[0].read_text()
    assert "kept aside" in acc.damaged() and str(aside[0]) in acc.damaged()
    acc.file.write_text("[1, 2]")                                                     # JSON, not the list's form
    acc.set("auth.sudo_nopasswd", True)
    assert len(kept_aside(acc.file)) == 2 and list(acc.all()) == ["auth.sudo_nopasswd"]


@skip_if_root
def test_an_accepted_list_that_cant_be_read_at_all_isnt_replaced(cat, tmp_path):
    from fastapi.testclient import TestClient

    from daprivacyscanner.history import Accepted
    from daprivacyscanner.paths import PathResolver
    from daprivacyscanner.server import create_app
    host = make_host(tmp_path)
    acc = Accepted(PathResolver(host.home, host.environ))
    acc.file.parent.mkdir(parents=True)
    acc.file.write_text('{"auth.screen_lock": {"note": "kept"}}')
    acc.file.chmod(0)
    try:
        c = TestClient(create_app("t", cat, make_host=lambda: host))
        r = c.post("/api/accept", headers={"X-Token": "t"}, json={"check_id": "auth.screen_lock", "accept": False})
        assert r.status_code == 400 and "couldn't be changed" in r.json()["error"]
        assert "can't be read" in c.get("/api/state", headers={"X-Token": "t"}).json()["accepted_damaged"]
    finally:
        acc.file.chmod(0o600)
    assert "kept" in acc.file.read_text()


def test_state_files_reach_the_disk_before_they_replace_the_old_ones(tmp_path, monkeypatch):
    """write_json renamed a file into place whose data might not be on the disk yet: after a power cut the list could
    be empty. The file and then its folder are synced."""
    from daprivacyscanner import history
    synced = []
    real = os.fsync

    def fsync(fd):
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        return real(fd)
    monkeypatch.setattr(history.os, "fsync", fsync)
    history.write_json(tmp_path / "state" / "x.json", {"a": 1})
    assert synced == [False, True]
    assert (tmp_path / "state" / "x.json").read_text().startswith("{")


# ------------------------------------------------------------------ app.py: --export as Save… writes

def test_export_never_writes_over_a_file_nor_through_a_link(cat, tmp_path, monkeypatch, capsys):
    """--export truncated whatever FILE was, followed a link there (a planted one, into another file of the user's)
    and kept an existing file's wider mode. It writes as Save… does: a new file, 0600, the next free name."""
    import json

    from daprivacyscanner import app
    from daprivacyscanner.host import Host
    host = make_host(tmp_path)
    monkeypatch.setattr(Host, "local", staticmethod(lambda: host))
    old = os.umask(0o022)
    try:
        out = tmp_path / "everything.json"
        out.write_text("my own notes")
        out.chmod(0o644)
        victim = tmp_path / "victim.txt"
        victim.write_text("precious")
        link = tmp_path / "linked.txt"
        link.symlink_to(victim)
        assert app.export_cli(cat, str(out), False) == 0
        assert out.read_text() == "my own notes" and stat.S_IMODE(out.stat().st_mode) == 0o644
        new = tmp_path / "everything (2).json"
        assert stat.S_IMODE(new.stat().st_mode) == 0o600 and json.loads(new.read_text())["changes"] == []
        said = capsys.readouterr().out
        assert "everything (2).json" in said and "is there already" in said
        assert app.export_cli(cat, str(link), False) == 0
        assert victim.read_text() == "precious" and link.is_symlink()
        assert (tmp_path / "linked (2).txt").read_text().startswith("DA Privacy Kit: everything it keeps")
        assert app.export_cli(cat, str(tmp_path / "nowhere" / "x.txt"), False) == 2
        assert app.export_cli(cat, str(tmp_path) + "/", False) == 2
    finally:
        os.umask(old)
