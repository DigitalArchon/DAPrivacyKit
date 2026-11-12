"""The command runner: a command that times out ends the call, even when something it started holds its output."""

import shutil
import time

import pytest

from daprivacyscanner.host import TIMED_OUT, SystemRunner


@pytest.mark.skipif(not shutil.which("sh") or not shutil.which("sleep"), reason="needs sh and sleep")
def test_a_timed_out_command_whose_child_holds_its_output_doesnt_hold_the_caller():
    """After the kill the runner drained the pipes with no limit: a child the command started (here a background
    sleep) kept them open, and the scan waited for it."""
    started = time.monotonic()
    r = SystemRunner().run(["sh", "-c", "sleep 30 & sleep 30"], timeout=0.5)
    assert r.returncode == TIMED_OUT
    assert time.monotonic() - started < 15
