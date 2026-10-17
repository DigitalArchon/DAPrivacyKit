"""The tools review of 2026-10-17, the browser's lifecycle and panel: what quitting says and where, what closing leaves
in the journal, a RAM disk left from before a restart, Xephyr after the browser, closing during a set-up, a start's
error kept until it is dismissed, Stop while unpacking, proxies, and the texts."""

from __future__ import annotations

import inspect
import json
import os
import time
from pathlib import Path

import pytest

from daprivacyscanner import app as app_module
from daprivacyscanner.host import Host
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import owner
from daprivacyscanner.tools import ramdisk as R

from test_browser_tool import open_ramdisk
from test_server_tools import H, host  # noqa: F401 - the fixture


@pytest.fixture(autouse=True)
def nothing_held():
    yield
    for name in list(owner._HELD):
        owner._drop(Host(home=Path("/nonexistent"), environ={}, runner=None), name)
    B._LAUNCHED.clear()
    getattr(B, "_PROBLEMS", {}).clear()


def quiet(monkeypatch):
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {})
    monkeypatch.setattr(R, "users_of", lambda host, path: [])
    monkeypatch.setattr(B, "running", lambda host, b: [])


class Helper:
    def __init__(self):
        self.calls = []

    def call(self, action, args, timeout=None):
        self.calls.append((action, args))
        return {}


# ------------------------------------------------------------------ A2, and quitting at a logout

def test_quitting_says_what_happened_on_a_terminal_only(cat, host, monkeypatch, capsys):  # noqa: F811
    """stderr off a terminal is ~/.xsession-errors or the journal: "Tor Browser still uses it" and the count went there."""
    monkeypatch.setattr(B, "close_disk", lambda host, helper: "~/TempBrowser stays open: Tor Browser still uses it.")
    app = create_app("t0ken", cat, make_host=lambda: host)
    monkeypatch.setattr("sys.stderr.isatty", lambda: False, raising=False)
    assert "Tor Browser" in app.state.close_browser_disk()
    assert capsys.readouterr().err == ""


def test_quitting_at_a_logout_asks_for_no_password(cat, host, monkeypatch):  # noqa: F811
    asked = []

    def close_disk(host, helper):
        helper()
        return ""
    monkeypatch.setattr(B, "close_disk", close_disk)
    app = create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: asked.append(True))
    app.state.close_browser_disk(prompt=False)
    assert asked == []
    src = inspect.getsource(app_module.main)
    assert 'close_browser_disk(prompt=not ended["by_signal"])' in src[src.index("finally:"):]
    assert "signal.SIGTERM, told_to_end" in src                       # --browser mode: Python would end at once


def test_at_a_logout_the_files_are_overwritten_and_the_disk_stays_mounted(host, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "page.html").write_text("visited")
    msg = B.close_disk(host, lambda: None)                              # no access, and none asked for
    assert "couldn't be unmounted" in msg and not (disk / "page.html").exists()
