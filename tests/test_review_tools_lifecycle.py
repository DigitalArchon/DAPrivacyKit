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
from test_review_tools_owner import other  # noqa: F401 - another copy of the app, a real process
from test_server_tools import H, host  # noqa: F401 - the fixture


@pytest.fixture(autouse=True)
def nothing_held():
    yield
    for name in list(owner._HELD):
        owner._drop(Host(home=Path("/nonexistent"), environ={}, runner=None), name)
    B._LAUNCHED.clear()
    B._PROBLEMS.clear()


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


def test_quitting_at_a_logout_asks_for_the_password_as_quit_does(cat, host, monkeypatch):  # noqa: F811
    """The owner's decision of 2026-10-17: unmounted properly at a logout too, not left mounted and empty."""
    asked = []

    def close_disk(host, helper):
        helper()
        return ""
    monkeypatch.setattr(B, "close_disk", close_disk)
    app = create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: asked.append(True))
    app.state.close_browser_disk()
    assert asked == [True]
    src = inspect.getsource(app_module.main)
    assert "app.state.close_browser_disk()" in src[src.index("finally:"):]
    assert "signal.SIGTERM, told_to_end" in src                       # --browser mode: Python would end at once


def test_the_files_are_overwritten_while_the_password_is_asked_for(host, monkeypatch):  # noqa: F811
    """Not after it: at a logout the prompt can stay up, or be declined, and the files go all the same."""
    import threading
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "page.html").write_text("visited")
    gone = threading.Event()
    real = B.wipe_disk

    def wipe(path):
        w = real(path)
        gone.set()
        return w
    monkeypatch.setattr(B, "wipe_disk", wipe)

    class Helper:
        calls = []

        def call(self, action, args, timeout=None):
            self.calls.append(action)
            return {}

    def helper():                                       # the prompt: still waiting while the files go
        assert gone.wait(10), "the overwrite waited on the password"
        return Helper()
    msg = B.close_disk(host, helper)
    assert "1 file overwritten" in msg and Helper.calls == ["ramdisk_close"] and not (disk / "page.html").exists()


def test_declined_the_files_are_overwritten_and_the_disk_stays_mounted(host, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "page.html").write_text("visited")
    msg = B.close_disk(host, lambda: None)                              # the password declined
    assert "couldn't be unmounted" in msg and not (disk / "page.html").exists()
    # its mark went with the wipe, and so does the lock's file (it stayed in the runtime folder: seen on p330)
    assert "TempBrowser" not in owner._HELD and not list(owner._locks(host).glob("*.lock"))


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


# ------------------------------------------------------------------ A5: Xephyr after the browser has quit

# the app (python3, its parent a shell), the display's sandbox: bwrap, bwrap, the focus keeper's python3, Xephyr; and a
# python3 script of the user's
PROCS = {10: (1, "bash"), 100: (10, "python3"), 200: (100, "bwrap"), 201: (200, "bwrap"), 202: (201, "python3"),
         203: (202, "Xephyr"), 300: (10, "python3")}


def test_a_display_of_its_own_is_ended_when_the_browser_has_quit(host, monkeypatch):  # noqa: F811
    """Closing was refused for ~15-18 s after the browser quit ("Close Xephyr, bwrap, python3 first"), and quitting the
    app then left ~/TempBrowser open: the display the app started for the browser is ended now."""
    disk = open_ramdisk(host)
    holders = {201: "bwrap", 202: "python3", 203: "Xephyr", 300: "python3"}
    monkeypatch.setattr(B, "_procs", lambda host: dict(PROCS))
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: dict(holders))
    monkeypatch.setattr(B, "running", lambda host, b: [])
    monkeypatch.setattr(B, "DISPLAY_WAIT", 0.2)
    assert B.disk_users(host, disk) == [B.DISPLAY_NAME, "python3"]       # the user's own script is named as itself
    killed = []

    def kill(pid, sig):
        killed.append((pid, sig))
        holders.pop(pid, None)
    assert B.end_display(host, disk, kill=kill)
    assert {pid for pid, _ in killed} == {200, 201, 202, 203}            # never the app (100) nor the script (300)
    assert holders == {300: "python3"}
    # while a browser runs, its display goes under its name, and nothing is ended
    holders.update({203: "Xephyr", 400: "firefox.real"})
    monkeypatch.setattr(B, "running", lambda host, b: [400] if b.id == "tor" else [])
    monkeypatch.setattr(B, "_browser_tree", lambda host, procs=None: {400})
    assert B.disk_users(host, disk) == ["Tor Browser", "python3"]
    assert not B.end_display(host, disk, kill=lambda *a: pytest.fail("killed while the browser runs"))


# ------------------------------------------------------------------ A6: closing during a set-up

def test_closing_is_refused_while_a_browser_is_set_up_here_or_in_another_copy(cat, host, monkeypatch):  # noqa: F811
    """"Close and overwrite…" was accepted during a set-up job: it wiped under the download, the job failed (LZMAError,
    ENOENT), and the close answered 400 naming no program."""
    from fastapi.testclient import TestClient
    disk = open_ramdisk(host)
    (disk / ".downloads").mkdir()
    (disk / ".downloads/tor-browser-linux-x86_64-15.0.24.tar.xz.part").write_bytes(b"x" * 100)
    quiet(monkeypatch)
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: Helper()))
    c.app.state.browser_job = {"state": "running", "name": "Tor Browser"}
    r = c.post("/api/tools/ramdisk/close", headers=H, json={"disk": "browser"})
    assert r.status_code == 409 and "being set up" in r.json()["error"]
    assert (disk / ".downloads/tor-browser-linux-x86_64-15.0.24.tar.xz.part").exists()
    c.app.state.browser_job = None
    held = owner.hold(host, "browser-mullvad")                          # a start under way in this copy
    r = c.post("/api/tools/ramdisk/close", headers=H, json={"disk": "browser"})
    assert r.status_code == 409 and "Mullvad Browser is being set up or started here" in r.json()["error"]
    owner.let_go(held)
    assert (disk / ".downloads/tor-browser-linux-x86_64-15.0.24.tar.xz.part").exists()


def test_quitting_leaves_tempbrowser_to_the_copy_setting_a_browser_up_in_it(host, monkeypatch, other):  # noqa: F811
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "page.html").write_text("visited")
    assert other("hold", key="browser-tor")                             # another copy is downloading into it
    h = Helper()
    assert "another window of this app" in B.close_disk(host, lambda: h) and not h.calls
    assert (disk / "page.html").exists()
    other.end()
    mine = owner.hold(host, "browser-tor")                              # this copy's own set-up: it ends with it
    assert "closed" in B.close_disk(host, lambda: h) and h.calls
    owner.let_go(mine)


# ------------------------------------------------------------------ A7: a start's error, until it is dismissed

class Ended:
    def __init__(self, rc):
        self.rc = rc

    def poll(self):
        return self.rc


def test_a_starts_error_stays_until_dismissed_or_started_again(cat, host, monkeypatch):  # noqa: F811
    """launch_problem was consumed by the first GET, and the panel's poll two seconds later drew the card without it."""
    from fastapi.testclient import TestClient
    tor = B.BROWSERS["tor"]
    B._LAUNCHED["tor"] = Ended(137)
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    for _ in range(3):
        card = c.get("/api/tools/browser", headers=H).json()["browsers"][0]
        assert "out of memory" in card["start_error"]
    assert c.post("/api/tools/browser/dismiss", headers=H, json={"browser": "tor"}).status_code == 200
    assert "start_error" not in c.get("/api/tools/browser", headers=H).json()["browsers"][0]
    B._LAUNCHED["tor"] = Ended(1)
    assert B.launch_problem(tor) == "Tor Browser stopped with an error: it stopped (exit status 1)"
    with pytest.raises(B.BrowserError):                                 # started again: its own error is the news now
        B.start(host, tor)
    assert B.launch_problem(tor) is None
    B._LAUNCHED["tor"] = Ended(0)                                       # a clean exit is no error
    assert B.launch_problem(tor) is None and "tor" not in B._LAUNCHED


# ------------------------------------------------------------------ A9: Stop while unpacking

def test_stop_while_unpacking_stops_and_keeps_nothing(host):  # noqa: F811
    """Stop during unpacking was ignored: the job went on to the end and said done."""
    from test_browser_tool import TOR, tarball
    disk = open_ramdisk(host)
    archive = disk / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    archive.write_bytes(tarball(TOR))

    class Job(dict):
        def __setitem__(self, k, v):                                    # Stop pressed as the first file is written
            super().__setitem__(k, v)
            if k == "done":
                super().__setitem__("cancel", True)
    with pytest.raises(B.Stopped, match="while unpacking"):
        B.unpack(host, archive, B.BROWSERS["tor"], Job())
    assert not (disk / "tor-browser").exists() and not (disk / ".tor-browser.unpacking").exists()


def test_stop_while_a_picked_archive_is_copied_in_leaves_no_copy(host):  # noqa: F811
    disk = open_ramdisk(host)
    mine = host.home / "Downloads/tor-browser-linux-x86_64-15.0.24.tar.xz"
    mine.write_bytes(b"x" * 3_000_000)
    mine.with_name(mine.name + ".asc").write_bytes(b"sig")

    class Job(dict):
        def __setitem__(self, k, v):
            super().__setitem__(k, v)
            if k == "done" and v > 1_000_000:
                super().__setitem__("cancel", True)
    with pytest.raises(B.Stopped):
        B.copy_in(host, mine, Job())
    assert not list((disk / ".downloads").iterdir()) and mine.exists()


# ------------------------------------------------------------------ A10: a proxy the download doesn't use

def test_the_panel_names_a_proxy_the_download_doesnt_use(host):  # noqa: F811
    """The download and the version checks go out directly (online.Net), silently past HTTPS_PROXY or ALL_PROXY; only
    the online tests' dialog said so."""
    assert B.status(host)["proxy_vars"] == []
    host.environ.update({"ALL_PROXY": "socks5h://127.0.0.1:9050", "https_proxy": " "})
    assert B.status(host)["proxy_vars"] == ["ALL_PROXY"]


# ------------------------------------------------------------------ A11: the texts

def test_a_server_that_cant_be_reached_is_said_in_plain_words(tmp_path, monkeypatch):
    """"(aus1.torproject.org didn't answer ([Errno 111] Connection refused).)." was shown."""
    from daprivacyscanner.online import FakeNet, HttpResult
    from test_browser_tool import INDEX
    monkeypatch.setattr(B.platform, "machine", lambda: "x86_64")
    tor = B.BROWSERS["tor"]
    net = FakeNet(http={INDEX: HttpResult(None, b"", "[Errno 111] Connection refused")})
    with pytest.raises(B.Unreachable) as e:
        B.latest_version(net, tor)
    assert str(e.value).endswith("aus1.torproject.org didn't answer (Connection refused).")
    archive = tmp_path / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    said = B.accept_unchecked(archive, tor, str(e.value), int(time.time()) - 2 * 86400)
    assert "couldn't be checked (aus1.torproject.org didn't answer (Connection refused)). Its signature" in said
    assert ".)." not in said and "Errno" not in said
    assert B._failed(HttpResult(503, b"")) == "the server answered 503"


def test_the_card_says_how_old_the_signature_was_when_it_was_accepted_unchecked(host, monkeypatch):  # noqa: F811
    """A copy set up two days after its release, started 25 days later with the index blocked, was accepted on its age
    then (27 days), while the card said "signed 2 days before it was set up"."""
    from daprivacyscanner.online import FakeNet
    from test_browser_tool import set_up_tor
    monkeypatch.setattr(B.platform, "machine", lambda: "x86_64")
    b = set_up_tor(host, hours_ago=25 * 24, signed_days=27)
    d = json.loads((B.private_dir(host, b) / "release.json").read_text())
    d["signed"] = d["unpacked"] - 2 * 86400                             # signed two days before it was set up
    (B.private_dir(host, b) / "release.json").write_text(json.dumps(d))
    B.check_before_start(host, b, FakeNet())                            # the index can't be reached
    info = B.release_info(host, b)
    assert info["unchecked"] and info["signed_days"] == 2 and info["unchecked_days"] == 27
    archive = host.home / "x/tor-browser-linux-x86_64-15.0.24.tar.xz"
    assert B.record_release(host, b, archive, "file", unchecked=True, signed=int(time.time()) - 5 * 86400)[
        "unchecked_days"] == 5


# ------------------------------------------------------------------ suspicions: what a killed set-up leaves

def test_what_a_killed_set_up_left_goes_when_the_panel_is_shown(cat, host, other):  # noqa: F811
    """.tor-browser.unpacking (some 350 MB of memory) and the download's .part files stayed after the copy setting it up
    was killed, until the next set-up of that browser."""
    from fastapi.testclient import TestClient
    disk = open_ramdisk(host)
    (disk / ".tor-browser.unpacking/Browser").mkdir(parents=True)
    (disk / ".tor-browser.unpacking/Browser/libxul.so").write_bytes(b"x" * 1000)
    (disk / ".downloads").mkdir()
    for name in ("tor-browser-linux-x86_64-15.0.24.tar.xz.part", "tor-browser-linux-x86_64-15.0.24.tar.xz.asc",
                 "mullvad-browser-linux-x86_64-15.0.24.tar.xz.part", "notes.txt"):
        (disk / ".downloads" / name).write_bytes(b"x")
    assert other("hold", key="browser-mullvad")                         # Mullvad Browser is being set up elsewhere
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    c.get("/api/tools/browser", headers=H)
    assert not (disk / ".tor-browser.unpacking").exists()
    assert sorted(p.name for p in (disk / ".downloads").iterdir()) == ["mullvad-browser-linux-x86_64-15.0.24.tar.xz.part",
                                                                       "notes.txt"]
    other.end()
    c.get("/api/tools/browser", headers=H)
    assert sorted(p.name for p in (disk / ".downloads").iterdir()) == ["notes.txt"]


def test_a_copy_whose_set_up_was_interrupted_is_removed_on_its_own(cat, host, monkeypatch):  # noqa: F811
    """It doesn't start (no record), and only closing all of ~/TempBrowser, the other browser with it, took it away."""
    from fastapi.testclient import TestClient
    from test_browser_tool import set_up_tor
    tor = set_up_tor(host)
    disk = host.home / "TempBrowser"
    (disk / "mullvad-browser/Browser").mkdir(parents=True)
    (disk / "mullvad-browser/Browser/start-mullvad-browser").write_text("#!/bin/sh\n")
    (disk / ".mullvad-browser-session/config").mkdir(parents=True)
    (disk / ".mullvad-browser-app").mkdir()
    (disk / ".mullvad-browser-app/sandboxed").write_text("")
    monkeypatch.setattr(B, "running", lambda host, b: [])
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    r = c.post("/api/tools/browser/remove", headers=H, json={"browser": "tor"})
    assert r.status_code == 409 and "set up in full" in r.json()["error"] and B.installed(host, tor)
    r = c.post("/api/tools/browser/remove", headers=H, json={"browser": "mullvad"})
    assert r.status_code == 200 and r.json()["removed"] == 2
    assert not any((disk / n).exists() for n in ("mullvad-browser", ".mullvad-browser-session", ".mullvad-browser-app"))
    assert B.installed(host, tor)                                       # the other browser stays
    monkeypatch.setattr(B, "running", lambda host, b: [1])
    (disk / "mullvad-browser/Browser").mkdir(parents=True)
    (disk / "mullvad-browser/Browser/start-mullvad-browser").write_text("#!/bin/sh\n")
    assert "is running" in c.post("/api/tools/browser/remove", headers=H, json={"browser": "mullvad"}).json()["error"]
