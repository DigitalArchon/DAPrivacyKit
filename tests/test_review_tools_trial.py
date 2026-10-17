"""The tools review of 2026-10-17, Try an app and Boxes: what it found, each fixed and tested here (live on the lab
as each test says)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from daprivacyscanner.tools import trial


# ------------------------------------------------------------------ E2: a trial ends with the app that started it

def _children(pid: int) -> list[int]:
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            return [int(x) for x in f.read().split()]
    except OSError:
        return []


def _gone(pid: int, within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as f:
                if f.read().rsplit(")", 1)[1].split()[0] == "Z":
                    return True
        except OSError:
            return True
        time.sleep(0.05)
    return False


def test_the_command_ends_when_the_app_is_killed():
    """An observed trial ran on after the app was killed: pasta was adopted by init, and bubblewrap answers to pasta.
    TETHER, started by a stand-in for the app from a worker thread as the server does, kills its command when the
    app's process ends (on p330-2: pasta, bubblewrap and the program gone at once)."""
    app = subprocess.Popen([sys.executable, "-I", "-c", """
import subprocess, sys, threading, time, os
def start():
    p = subprocess.Popen([sys.executable, "-I", "-c", sys.argv[1], str(os.getpid()), "/bin/sleep", "60"],
                         start_new_session=True)
    print(p.pid, flush=True)
t = threading.Thread(target=start)
t.start(); t.join()                       # the thread that started it has ended: the tether doesn't answer to it
time.sleep(60)
""", trial.TETHER], stdout=subprocess.PIPE, text=True)
    try:
        tether = int(app.stdout.readline())
        deadline = time.monotonic() + 5
        while not _children(tether) and time.monotonic() < deadline:
            time.sleep(0.05)
        (sleeper,) = _children(tether)
        time.sleep(0.3)
        assert not _gone(sleeper, 0.2), "the thread that started it ending ends nothing"
        app.kill()
        app.wait()
        assert _gone(sleeper) and _gone(tether)
    finally:
        app.kill()


def test_the_commands_exit_status_is_passed_on_and_stop_reaches_the_command():
    run = lambda *argv: subprocess.run([sys.executable, "-I", "-c", trial.TETHER, str(os.getpid()), *argv],   # noqa: E731
                                       timeout=20).returncode
    assert run("/bin/sh", "-c", "exit 3") == 3
    assert run("/bin/sh", "-c", "kill -SEGV $$") == 128 + signal.SIGSEGV
    assert trial.ended_by_signal(128 + signal.SIGSEGV) == "SIGSEGV"
    assert run("/nonexistent/program") == 127
    # Stop: SIGTERM to the group reaches the command, which ends; the tether ignores it and reports how it ended
    p = subprocess.Popen([sys.executable, "-I", "-c", trial.TETHER, str(os.getpid()), "/bin/sleep", "60"],
                         start_new_session=True)
    time.sleep(0.5)
    os.killpg(p.pid, signal.SIGTERM)
    assert p.wait(timeout=10) == 128 + signal.SIGTERM


def test_a_trial_and_its_display_start_under_the_tether(tmp_path):
    from daprivacyscanner.host import FakeRunner, Host
    root = tmp_path / "root"
    (root / "usr/bin").mkdir(parents=True)
    host = Host(home=root / "home/a", environ={}, runner=FakeRunner(), root=root, uid=1000)
    assert trial.tethered(host, ["/usr/bin/bwrap", "x"]) == ["/usr/bin/bwrap", "x"], "no python3: as it was"
    (root / "usr/bin/python3").write_text("")
    a = trial.tethered(host, ["/usr/bin/bwrap", "x"])
    assert a[:4] == ["/usr/bin/python3", "-I", "-c", trial.TETHER] and a[4] == str(os.getpid()) and a[5:] == ["/usr/bin/bwrap", "x"]
    assert "<end it if the app ends>" in trial.shown(a)
    compile(trial.TETHER, "tether", "exec")
