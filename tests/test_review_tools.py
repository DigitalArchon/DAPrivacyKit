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
