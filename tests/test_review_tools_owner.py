"""The tools review of 2026-10-17: what a copy of the app opened is that copy's (owner.py). Every right-click entry
starts a copy of its own, and quitting one closed ~/TempBrowser under another (seen on p330); one opening its Try an
app panel removed the trial another was running. Another copy is a real process here, holding the locks."""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from daprivacyscanner import app as app_module
from daprivacyscanner.host import Host
from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import owner, trial

from test_browser_tool import open_ramdisk
from test_server_tools import host  # noqa: F401 - the fixture

SRC = str(Path(__file__).resolve().parents[1] / "src")

# another copy of the app: claims the disk (or holds a lock, or a trial folder) and waits until it is stopped
OTHER = r"""
import fcntl, json, os, sys, time
from pathlib import Path
from daprivacyscanner.host import Host
from daprivacyscanner.tools import owner
a = json.loads(sys.argv[1])
host = Host(home=Path(a["home"]), environ={"HOME": a["home"]}, runner=None, root=Path(a["root"]))
if a["what"] == "claim":
    ok = owner.claim(host, "TempBrowser", Path(a["path"]))
elif a["what"] == "hold":
    ok = owner.hold(host, a["key"]) is not None
else:
    fd = os.open(a["path"], os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    ok = True
print("yes" if ok else "no", flush=True)
time.sleep(60)
"""


@pytest.fixture
def other(host):  # noqa: F811
    procs = []

    def start(what: str, **kw) -> bool:
        args = json.dumps({"what": what, "home": str(host.home), "root": str(host.root), **{k: str(v) for k, v in kw.items()}})
        p = subprocess.Popen([sys.executable, "-c", OTHER, args], stdout=subprocess.PIPE, text=True,
                             env={**os.environ, "PYTHONPATH": SRC})
        procs.append(p)
        return p.stdout.readline().strip() == "yes"

    def end() -> None:
        for p in procs:
            p.kill()
            p.wait()
        procs.clear()

    start.end = end
    yield start
    end()


@pytest.fixture(autouse=True)
def nothing_held():
    yield
    for name in list(owner._HELD):
        owner._drop(Host(home=Path("/nonexistent"), environ={}, runner=None), name)


def quiet(monkeypatch):
    from daprivacyscanner.tools import ramdisk as R
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {})
    monkeypatch.setattr(R, "users_of", lambda host, path: [])
    monkeypatch.setattr(B, "running", lambda host, b: [])


class Helper:
    def __init__(self):
        self.calls = []

    def call(self, action, args, timeout=None):
        self.calls.append((action, args))
        return {}


def test_a_copy_that_didnt_open_tempbrowser_leaves_it_open_when_it_quits(host, other, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    (disk / "Downloads").mkdir()
    (disk / "Downloads/kept.pdf").write_text("not saved yet")
    quiet(monkeypatch)
    assert other("claim", path=disk)                    # the copy that opened it is running
    assert not owner.claim(host, "TempBrowser", disk)
    h = Helper()
    assert B.close_disk(host, lambda: h) == "" and not h.calls
    assert (disk / "Downloads/kept.pdf").exists()


def test_a_disk_whose_owner_ended_is_taken_over_by_the_copy_showing_the_panel(host, other, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert other("claim", path=disk)
    other.end()                                         # it crashed, or was killed
    h = Helper()
    assert B.close_disk(host, lambda: h) == ""          # quitting without having shown the panel: not this copy's
    assert owner.claim(host, "TempBrowser", disk)       # the panel was shown here
    assert "closed" in B.close_disk(host, lambda: h) and h.calls == [("ramdisk_close", {"name": "TempBrowser"})]


def test_a_disk_closed_and_opened_again_by_another_copy_isnt_the_first_ones(host, other, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    B.wipe_disk(disk)                                   # another copy closed it (Close and overwrite…)…
    assert other("claim", path=disk)                    # …and opened it again
    assert not owner.owns(host, "TempBrowser", disk)
    h = Helper()
    assert B.close_disk(host, lambda: h) == "" and not h.calls


def test_the_wipe_count_leaves_out_the_owners_mark(host, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "page.html").write_text("visited")
    assert "1 file overwritten" in B.close_disk(host, lambda: Helper())
    assert not (disk / owner.TOKEN).exists()


def test_only_the_owner_empties_the_tempoutbox(host, other, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    ran = []
    monkeypatch.setattr(B.transfer, "run_outbox", lambda host, folder, name: ran.append(name))
    monkeypatch.setattr(B, "installed", lambda host, b: True)
    assert other("claim", path=disk)
    B.run_outboxes(host)
    assert ran == []
    other.end()
    assert owner.claim(host, "TempBrowser", disk)
    B.run_outboxes(host)
    assert ran == ["Tor Browser", "Mullvad Browser"]


def test_a_browser_isnt_started_while_another_copy_sets_it_up_or_starts_it(host, other):  # noqa: F811
    assert other("hold", key="browser-tor")
    with pytest.raises(B.BrowserError, match="another window of this app"):
        B.start(host, B.BROWSERS["tor"])


def test_a_trial_another_copy_runs_isnt_a_leftover(host, other, monkeypatch):  # noqa: F811
    monkeypatch.setattr(trial, "places", lambda h: [{"id": "disk", "words": "On the disk", "folder": str(host.home / "t"),
                                                     "free": 1 << 40, "noexec": False}])
    base = host.home / "t"
    running, ended = base / "0a1b2c3d4e5f", base / "aaaaaaaaaaaa"
    for f in (running, ended):
        (f / "home").mkdir(parents=True)
    assert other("lock", path=running)
    assert trial.leftovers(host) == [str(ended)]
    trial.clear_leftovers(host)
    assert running.exists() and not ended.exists()
    tid, mine = trial._make(host, "disk")             # this copy's own trial isn't a leftover either
    assert str(mine) not in trial.leftovers(host)
    trial._remove(mine, False)
    trial._let_go(mine)
    other.end()
    assert trial.leftovers(host) == [str(running)]


def test_quitting_the_window_discards_the_trial():
    """--browser mode's Quit did; the window's own quit (app.py's finally) didn't, so a trial on the disk stayed."""
    src = inspect.getsource(app_module.main)
    assert "app.state.discard_trial()" in src[src.index("finally:"):]


def test_trial_leftovers_go_at_the_start(cat, host, monkeypatch):  # noqa: F811
    from daprivacyscanner.server import create_app
    from daprivacyscanner.tools import transfer
    monkeypatch.setitem(transfer.WATCHED, "on", transfer.WATCHED.get("on"))
    cleared = []
    monkeypatch.setattr(trial, "clear_leftovers", lambda h: cleared.append(True))
    monkeypatch.setattr("daprivacyscanner.server.OUTBOX_EVERY", 3600)
    create_app("t0ken", cat, make_host=lambda: host, watch_outbox=True)
    deadline = time.monotonic() + 5
    while not cleared and time.monotonic() < deadline:
        time.sleep(0.02)
    assert cleared
