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


# ------------------------------------------------------------------ A3: systemd's line in the journal at every close

from test_ramdisk import ME, call, root, xattrs_work  # noqa: E402,F401 - the helper's fixture tree


def test_systemd_logs_nothing_about_the_ram_disks_mount_unit(root):  # noqa: F811
    """systemd logged "home-<user>-TempBrowser.mount: Deactivated successfully." in the persistent journal at every
    close: a drop-in in /run gives the unit LogLevelMax=notice, read as the unit is made at the mount (no reload)."""
    from daprivacyscanner import helper
    r, *_ = root
    (r / "run/systemd/system").mkdir(parents=True)
    dropin = r / "run/systemd/system/home-alice-TempBrowser.mount.d/50-daprivacyscanner-quiet.conf"
    ran = call("ramdisk_open", size_mb=100, noexec=False, name="TempBrowser")["ran"]
    assert "[Mount]\nLogLevelMax=notice\n" in dropin.read_text()
    assert ran[-3:-1] == helper.quiet_commands("/home/alice/TempBrowser", True) and ran[-1].startswith("mount ")
    assert "LogLevelMax=notice" in ran[-2] and "home-alice-TempBrowser.mount.d" in ran[-2]
    closed = call("ramdisk_close", name="TempBrowser")["ran"]
    assert closed[:3] == ["umount /home/alice/TempBrowser", *helper.quiet_commands("/home/alice/TempBrowser", False)]
    assert not dropin.parent.exists() and (r / "run/systemd/system").is_dir()


def test_the_page_shows_the_drop_in_among_what_opening_runs(tmp_path):
    from conftest import make_host
    host = make_host(tmp_path, files={"/run/systemd/system/.keep": ""})
    shown = R.commands(host, "TempBrowser")
    assert any("LogLevelMax=notice" in c for c in shown["open_exec"]) and shown["open_exec"][-1].startswith("mount ")
    assert shown["close"][1].startswith("rm -f ") and shown["close"][2].startswith("rmdir ")
    assert not any("LogLevelMax" in c for c in R.commands(make_host(tmp_path / "bare"), "TempBrowser")["open"])


# ------------------------------------------------------------------ A4: open again after a restart, and the leftover

def test_an_open_after_a_restart_keeps_the_folders_record(root):  # noqa: F811
    """After a restart with ~/TempBrowser open, opening it again wrote "created: false, 0500" over the record that the
    helper had made the folder, and closing left the empty read-only folder for good."""
    from daprivacyscanner import helper
    r, *_ = root
    if not xattrs_work(r / "home/alice"):
        pytest.skip("no user extended attributes on this filesystem")
    folder, state = r / "home/alice/TempBrowser", r / f"run/daprivacyscanner/ramdisk/{ME[0]}-TempBrowser.json"
    call("ramdisk_open", size_mb=100, noexec=False, name="TempBrowser")       # the helper makes the folder
    state.unlink()
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")            # a restart
    call("ramdisk_open", size_mb=100, noexec=False, name="TempBrowser")
    assert json.loads(os.getxattr(folder, helper.RAMDISK_XATTR)) == {"created": True, "folder_mode": None}
    assert call("ramdisk_close", name="TempBrowser")["ran"][-1] == "rmdir /home/alice/TempBrowser"
    assert not folder.exists()
    # a folder of the user's (0750) the same way: its mode comes back, not the 0500 of the first open
    folder.mkdir()
    folder.chmod(0o750)
    call("ramdisk_open", size_mb=100, noexec=False, name="TempBrowser")
    state.unlink()
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    call("ramdisk_open", size_mb=100, noexec=False, name="TempBrowser")
    call("ramdisk_close", name="TempBrowser")
    assert folder.is_dir() and (folder.stat().st_mode & 0o7777) == 0o750


def test_a_leftover_is_put_back_from_the_page_without_administrator_access(cat, host):  # noqa: F811
    from daprivacyscanner import helper
    from fastapi.testclient import TestClient
    folder = host.home / "TempBrowser"
    folder.mkdir()
    try:
        os.setxattr(folder, helper.RAMDISK_XATTR, b'{"created": false, "folder_mode": 488}')        # 0750
    except OSError:
        pytest.skip("no user extended attributes on this filesystem")
    folder.chmod(0o500)                                                 # as the open left it (the attribute first)

    def no_helper():
        raise AssertionError("putting a leftover back needs no administrator access")
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=no_helper))
    assert c.get("/api/tools/browser", headers=H).json()["ramdisk"]["leftover"]
    r = c.post("/api/tools/ramdisk/tidy", headers=H, json={"disk": "browser"})
    assert r.status_code == 200 and "permissions put back" in r.json()["done"]
    assert (folder.stat().st_mode & 0o7777) == 0o750 and not r.json()["ramdisk"]["leftover"]
    with pytest.raises(OSError):
        os.getxattr(folder, helper.RAMDISK_XATTR)
    # one the app made goes; the user's own empty folder isn't a leftover, and is left alone
    os.setxattr(folder, helper.RAMDISK_XATTR, b'{"created": true, "folder_mode": null}')
    folder.chmod(0o500)
    assert c.post("/api/tools/ramdisk/tidy", headers=H, json={"disk": "browser"}).status_code == 200
    assert not folder.exists()
    folder.mkdir()
    folder.chmod(0o755)
    assert c.post("/api/tools/ramdisk/tidy", headers=H, json={"disk": "browser"}).status_code == 409 and folder.is_dir()
