"""The review of 2026-10-17, tools and the helper's service and mount handling: what the app's own units and menu
entries leave in the journal, the RAM disk's close, Remove metadata's and Verify's words, Deleted file names' notes,
Try an app and Boxes, Presentation mode's words, in-memory folders put back while busy, services turned off together
(and a failure part way recorded), what a revert says it put back, and the known_hosts undo hint."""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper
from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.server import create_app

from conftest import make_host, skip_if_root
from fakes import FakeSystem

H = {"X-Token": "t0ken"}
ME = (os.geteuid(), os.getegid())


def helper_call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        e = helper.Refused(reply["error"])
        e.reply = reply
        raise e
    return reply["result"]


@pytest.fixture
def system_root(tmp_path, monkeypatch):
    """The helper against a fixture tree, with a fake systemctl; alice is the user pkexec names."""
    r = tmp_path / "root"
    (r / "home/alice/.cache").mkdir(parents=True)
    (r / "etc/systemd/system").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    system = FakeSystem()
    monkeypatch.setattr(helper, "RUN", system)
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    return r, system


# ------------------------------------------------------------------ 1. nothing names a file in the journal

def outbox_run(cleaned=(), not_cleaned=()):
    from daprivacyscanner.tools import metadata as M
    run = M.OutboxRun()
    run.cleaned, run.not_cleaned = list(cleaned), list(not_cleaned)
    return run


def test_the_outbox_unit_writes_counts_to_the_journal_never_the_files_names(monkeypatch, capsys):
    """Its unit's output goes to the journal, kept on the disk on Mint: the names of what the user shares stayed
    there ("cleaned: passport-scan.jpg"). Counts only, as in its notification; names only in a terminal."""
    from daprivacyscanner import app
    from daprivacyscanner.tools import metadata as M
    run = outbox_run(["passport-scan.jpg"], [("contract draft.docx", "mat2 can't clean this kind of file (x).")])
    monkeypatch.setattr(M, "run_outbox_settled", lambda host: run)
    monkeypatch.setattr(M, "notify_outbox", lambda host, r: None)
    assert app.outbox_cli() == 0
    out = capsys.readouterr()
    assert out.out == "Outbox: 1 cleaned, 1 not cleaned.\n" and "passport" not in out.out + out.err
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)       # someone ran it by hand
    assert app.outbox_cli() == 0
    assert "cleaned: passport-scan.jpg" in capsys.readouterr().out


def test_an_outbox_error_is_said_by_its_kind_only(monkeypatch, capsys):
    from daprivacyscanner import app
    from daprivacyscanner.tools import metadata as M

    def broken(host):
        raise PermissionError(13, "Permission denied", "/home/alice/Outbox/passport-scan.jpg")
    monkeypatch.setattr(M, "run_outbox_settled", broken)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    assert app.outbox_cli() == 1
    err = capsys.readouterr().err
    assert "PermissionError" in err and "passport" not in err


def test_errors_nothing_caught_are_said_by_their_kind_off_a_terminal(monkeypatch, capsys):
    """A unit, a timer, a menu entry or a right-click entry: stderr is the journal or ~/.xsession-errors, and a
    traceback's message can name a file. Only the kind goes there."""
    import threading

    from daprivacyscanner import app
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    app.quiet_tracebacks()
    try:
        raise FileNotFoundError(2, "No such file", "/home/alice/Documents/secret plan.odt")
    except FileNotFoundError as e:
        sys.excepthook(type(e), e, e.__traceback__)
    err = capsys.readouterr().err
    assert "FileNotFoundError" in err and "secret" not in err and "Traceback" not in err


def test_the_scheduled_scan_prints_nothing(cat, tmp_path, monkeypatch, capsys):
    """`--scan --notify --quiet` is what the timer runs: no report, no titles, in its journal."""
    from daprivacyscanner import app
    from daprivacyscanner.host import Host as RealHost
    host = make_host(tmp_path)
    monkeypatch.setattr(RealHost, "local", staticmethod(lambda: host))
    monkeypatch.setattr("daprivacyscanner.runner.Runner.scan",
                        lambda self: SimpleNamespace(to_dict=lambda: {"results": {}, "context": {}}))
    app.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=True, redact=False)
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


# ------------------------------------------------------------------ 2. the RAM disk

def ramdisk_host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    home.mkdir(parents=True)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", root / "proc/mounts")
    (root / "proc/meminfo").write_text("MemTotal: 8000000 kB\n")
    return Host(home=home, environ={"HOME": str(home)}, runner=FakeRunner(), root=root, uid=os.getuid())


def test_closing_a_ram_disk_that_isnt_open_is_refused_and_touches_nothing(cat, tmp_path):
    """Before, the helper took the user's own empty ~/RAMDisk for its own and removed it."""
    host = ramdisk_host(tmp_path)
    mine = host.home / "RAMDisk"
    mine.mkdir(mode=0o755)

    def no_helper():
        raise AssertionError("nothing to close: the helper isn't asked")
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=no_helper))
    r = c.post("/api/tools/ramdisk/close", headers=H, json={})
    assert r.status_code == 409 and "isn't open" in r.json()["error"] and mine.is_dir()


def test_the_helper_never_removes_a_folder_nothing_records_it_made(system_root):
    r, _ = system_root
    (r / "proc/self").mkdir(parents=True)
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", r / "proc/mounts")
    mine = r / "home/alice/RAMDisk"
    mine.mkdir(mode=0o755)
    mine.chmod(0o755)
    res = helper_call("ramdisk_close")
    assert res == {"closed": True, "was_open": False} and mine.is_dir() and stat.S_IMODE(mine.stat().st_mode) == 0o755


def test_a_leftover_is_only_a_folder_an_open_left(tmp_path):
    """"An empty, read-only ~/RAMDisk folder is left from before a restart" was said of the user's own 0755 folder."""
    from daprivacyscanner.tools import ramdisk as R
    host = ramdisk_host(tmp_path)
    folder = host.home / "RAMDisk"
    folder.mkdir()
    folder.chmod(0o755)
    assert R.status(host).leftover is False                              # an empty folder of the user's own
    folder.chmod(0o500)                                                  # as an open leaves it
    assert R.status(host).leftover is True
    folder.chmod(0o755)
    try:
        os.setxattr(folder, helper.RAMDISK_XATTR, b'{"created": true, "folder_mode": null}')
    except OSError:
        pytest.skip("no user extended attributes on this filesystem")
    assert R.status(host).leftover is True                               # the helper's record of an open
