"""The tools review of 2026-10-17: bubblewrap's init was the sandbox's PID 1, and everything in the sandbox could read
its environment (the user, the home folder, SESSION_MANAGER with the computer's name), its command line (every folder
it binds, in the user's home) and its open files (the start log's path). Tested on p330 and CachyOS."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import sandbox as S
from daprivacyscanner.tools import trial

from test_browser_sandbox import Proc, bwrap_ok, host, identity_etc, installed, wayland  # noqa: F401


def mullvad(host):  # noqa: F811
    installed(host, "mullvad")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    b = B.BROWSERS["mullvad"]
    folder, session, private = B.prepare(host, b)
    disp = S.display(host, private, landlock=True)
    etc = S.identity_files(private / "etc", "nameserver 9.9.9.9\n")
    return b, S.Layout(b.folder, folder, session, private, b.start, b.writable, b.hidden), disp, etc


def test_the_browsers_reaper_is_its_sandboxs_pid_1(host):  # noqa: F811
    b, lay, disp, etc = mullvad(host)
    argv = S.browser_argv(host, lay, disp, False, True, etc, None)
    end = argv.index("--")
    assert "--as-pid-1" in argv[:end] and argv[end + 1:end + 4] == [S.PYTHON, "-I", "-c"]
    assert argv[end + 4] == S.STAY
    no_python = S.browser_argv(host, lay, disp, False, True, etc, None, stay=False)
    assert "--as-pid-1" not in no_python                # the start script can't reap: bubblewrap's init stays


def test_tor_browsers_inner_sandbox_too(host):  # noqa: F811
    installed(host, "tor")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    b = B.BROWSERS["tor"]
    folder, session, private = B.prepare(host, b)
    disp = S.display(host, private, landlock=True)
    etc = S.identity_files(private / "etc", None)
    lay = S.Layout(b.folder, folder, session, private, b.start, b.writable, b.hidden)
    argv = S.tor_argv(host, lay, private / "tor", disp, False, True, etc, "gate")
    inner = json.loads(argv[-1])["inner"]
    assert "--as-pid-1" in inner[:inner.index("--")] and inner[inner.index("--") + 4] == S.STAY


def test_the_browser_starts_with_none_of_the_apps_environment_and_a_log_in_memory(host):  # noqa: F811
    b, *_ = mullvad(host)
    host.environ.update(SESSION_MANAGER="local/alice-laptop:@/tmp/.ICE-unix/1", SECRET_TOKEN="abc")
    seen = {}

    def spawn(argv, **kw):
        seen.update(env=kw["env"], log=os.readlink(f"/proc/self/fd/{kw['stderr']}"))
        return Proc()
    B.start(host, b, spawn=spawn)
    assert seen["env"] == S.SPAWN_ENV and seen["log"].startswith("/memfd:")
    assert not (B.private_dir(host, b) / "start.log").exists()


def test_sealed_options_come_back_as_they_were():
    argv = ["bwrap", "--ro-bind", "/home/alice/TempBrowser/x", "/home/user/x", "--setenv", "A", "two words", "--",
            "/usr/bin/xreader", "/home/user/x"]
    cmd, fd = S.sealed(argv)
    try:
        assert cmd == ["bwrap", "--args", str(fd), "--", "/usr/bin/xreader", "/home/user/x"]
        assert os.read(fd, 4096).split(b"\0")[:-1] == [a.encode() for a in argv[1:argv.index("--")]]
    finally:
        os.close(fd)


def _bwrap_runs() -> bool:
    if not shutil.which("bwrap"):
        return False
    r = subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "--", "true"], capture_output=True)
    return r.returncode == 0


PROBE = r"""
import os
out = {"pids": sorted(int(p) for p in os.listdir("/proc") if p.isdigit()),
       "cmdline": open("/proc/1/cmdline").read(), "environ": open("/proc/1/environ").read(),
       "fds": [os.readlink("/proc/1/fd/" + f) for f in os.listdir("/proc/1/fd")]}
print(repr(out))
"""


@pytest.mark.skipif(not _bwrap_runs(), reason="bubblewrap can't run here")
def test_from_inside_pid_1_names_nothing_of_the_user(tmp_path):
    """The real bubblewrap, as the app starts it: what the sandbox reads of PID 1 holds no path or variable of
    the app's (run unprivileged on the developer's machine)."""
    secret = str(tmp_path / "alice-home")
    argv = ["bwrap", *S.namespaces(False), "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", str(tmp_path), "/mnt", "--setenv", "PATH", "/usr/bin:/bin", "--as-pid-1", "--",
            sys.executable, "-I", "-c", S.STAY, "/nonexistent", sys.executable, "-I", "-c", PROBE]
    cmd, fd = S.sealed(argv)
    log = S.log_file("start-log")
    try:
        r = subprocess.run(cmd, env={**S.SPAWN_ENV}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log,
                           pass_fds=(fd,), timeout=30)
    finally:
        os.close(fd)
        os.close(log)
    got = eval(r.stdout.decode())                       # noqa: S307 - our own probe's repr
    assert got["pids"][0] == 1 and "bwrap" not in got["cmdline"] and str(tmp_path) not in got["cmdline"]
    assert "SESSION_MANAGER" not in got["environ"] and secret not in got["environ"] and "HOME=" not in got["environ"]
    assert not any(str(tmp_path) in f for f in got["fds"])


GATE = r"""
import os, signal, subprocess, sys, threading, time
from daprivacyscanner.tools import torgate
inner = subprocess.Popen([sys.executable, "-c", sys.argv[1]])
time.sleep(0.5)
end = torgate.ender(inner, 1)
signal.signal(signal.SIGTERM, end)
threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
print(inner.wait(), flush=True)
"""


@pytest.mark.parametrize("child, code", [
    ("import time; time.sleep(30)", -15),                                                   # ends on SIGTERM
    ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)", -9),   # killed after
])
def test_the_gate_ends_on_sigterm_instead_of_hanging(child, code):
    """Its handler waited on the lock the main thread's inner.wait() held: the gate hung (tested on Mint)."""
    src = str(Path(__file__).resolve().parents[1] / "src")
    r = subprocess.run([sys.executable, "-c", GATE, child], capture_output=True, text=True, timeout=20,
                       env={**os.environ, "PYTHONPATH": src})
    assert r.stdout.strip() == str(code), r.stderr
