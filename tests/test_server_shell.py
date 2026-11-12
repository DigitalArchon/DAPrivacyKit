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
