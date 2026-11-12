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
    # every way a run ends goes through app.finish, which quits as Quit does (app.state.shutdown, which closes it)
    src = inspect.getsource(app_module.main)
    assert "finish(app, server, thread" in src[src.index("finally:"):]
    assert "signal.SIGTERM, told_to_end" in src                       # --browser mode: Python would end at once
    app = create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: asked.append(True))
    app.state.shutdown()
    assert asked == [True, True]


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


def outbox_at_work(host, monkeypatch, held: dict):
    """The TempOutbox's watcher, cleaning a file in ~/TempBrowser with mat2 for half a second, under way: the event is
    set once mat2 holds it."""
    import threading
    started = threading.Event()

    def run_outbox(host, folder, name):
        held[4242] = "mat2"
        started.set()
        time.sleep(0.5)
        del held[4242]
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: dict(held))
    monkeypatch.setattr(B.transfer, "run_outbox", run_outbox)
    monkeypatch.setattr(B, "installed", lambda host, b: b.id == "tor")
    t = threading.Thread(target=B.run_outboxes, args=(host,))
    t.start()
    assert started.wait(5)
    return t


def test_the_tempoutboxs_own_mat2_isnt_a_program_using_tempbrowser(cat, host, monkeypatch):  # noqa: F811
    """The TempOutbox's mat2, cleaning a file in ~/TempBrowser as closing looked for programs using it, was named among
    them: Quit left the disk open and its files not overwritten ("mat2 still uses it"), and Close was refused ("Close
    mat2 first"). The TempOutbox is stopped after its file first, then they are looked for."""
    from fastapi.testclient import TestClient
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "page.html").write_text("visited")
    held: dict = {}
    t = outbox_at_work(host, monkeypatch, held)
    h = Helper()
    msg = B.close_disk(host, lambda: h)
    t.join()
    assert "1 file overwritten" in msg and h.calls == [("ramdisk_close", {"name": "TempBrowser"})]
    assert not (disk / "page.html").exists()
    (disk / "page.html").write_text("visited again")                   # opened again, and the page's Close
    assert owner.claim(host, "TempBrowser", disk)

    class Admin(Helper):
        def alive(self):
            return True

        def close(self):
            pass
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=Admin))
    t = outbox_at_work(host, monkeypatch, held)
    r = c.post("/api/tools/ramdisk/close", headers=H, json={"disk": "browser"})
    t.join()
    assert r.status_code == 200 and r.json()["wiped"]["files"] == 1 and not (disk / "page.html").exists()


# ------------------------------------------------------------------ A3: systemd's line in the journal at every close

from test_ramdisk import ME, call, root, xattrs_work  # noqa: E402,F401 - the helper's fixture tree


def test_systemd_logs_nothing_about_the_ram_disks_mount_unit(root):  # noqa: F811
    """systemd logged "home-<user>-TempBrowser.mount: Deactivated successfully." in the persistent journal at every
    close: a drop-in in /run gives the unit LogLevelMax=notice, read as the unit is made at the mount (no reload).
    ~/TempBrowser's also ends with its owner's session (the owner's decision of 2026-10-17): systemd unmounts it once
    their manager has stopped, since at a logout no password can be asked for. ~/RAMDisk's doesn't."""
    from daprivacyscanner import helper
    r, *_ = root
    (r / "run/systemd/system").mkdir(parents=True)
    dropin = r / "run/systemd/system/home-alice-TempBrowser.mount.d/50-daprivacyscanner.conf"
    ran = call("ramdisk_open", size_mb=100, noexec=False, name="TempBrowser")["ran"]
    text = dropin.read_text()
    assert "[Mount]\nLogLevelMax=notice\n" in text
    assert f"[Unit]\nBindsTo=user@{ME[0]}.service\nBefore=user@{ME[0]}.service\n" in text
    assert ran[-3:-1] == helper.dropin_commands("/home/alice/TempBrowser", True, ME[0]) and ran[-1].startswith("mount ")
    assert "LogLevelMax=notice" in ran[-2] and f"BindsTo=user@{ME[0]}.service" in ran[-2]
    closed = call("ramdisk_close", name="TempBrowser")["ran"]
    assert closed[:3] == ["umount /home/alice/TempBrowser", *helper.dropin_commands("/home/alice/TempBrowser", False)]
    assert not dropin.parent.exists() and (r / "run/systemd/system").is_dir()
    call("ramdisk_open", size_mb=100, noexec=False, name="RAMDisk")
    other = (r / "run/systemd/system/home-alice-RAMDisk.mount.d/50-daprivacyscanner.conf").read_text()
    assert "LogLevelMax=notice" in other and "BindsTo" not in other                   # the RAM disk tool's stays open
    call("ramdisk_close", name="RAMDisk")


def test_the_page_shows_the_drop_in_among_what_opening_runs(tmp_path):
    from conftest import make_host
    host = make_host(tmp_path, files={"/run/systemd/system/.keep": ""})
    shown = R.commands(host, "TempBrowser")
    assert any("LogLevelMax=notice" in c for c in shown["open_exec"]) and shown["open_exec"][-1].startswith("mount ")
    assert any(f"BindsTo=user@{host.uid}.service" in c for c in shown["open_exec"])
    assert not any("BindsTo" in c for c in R.commands(host, "RAMDisk")["open_exec"])
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


def test_only_the_display_holding_tempbrowser_is_ended(host, monkeypatch):  # noqa: F811
    """Every Xephyr of the user's was taken for the browser's display, and all of them were ended once one held
    ~/TempBrowser: a trial's display of its own, the user's own Xephyr. Each is apart now, and only one in a sandbox
    that holds ~/TempBrowser is ended; the user's own (no sandbox around it), its working folder there, is named."""
    disk = open_ramdisk(host)
    procs = {**PROCS, 400: (1, "bwrap"), 401: (400, "bwrap"), 402: (401, "python3"), 403: (402, "Xephyr"),   # a trial's
             500: (10, "bash"), 501: (500, "Xephyr")}                                      # the user's, from a terminal
    holders = {201: "bwrap", 202: "python3", 203: "Xephyr", 501: "Xephyr"}
    monkeypatch.setattr(B, "_procs", lambda host: dict(procs))
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: dict(holders))
    monkeypatch.setattr(B, "running", lambda host, b: [])
    monkeypatch.setattr(B, "DISPLAY_WAIT", 0.2)
    assert B.disk_users(host, disk) == [B.DISPLAY_NAME, "Xephyr"]
    killed = []

    def kill(pid, sig):
        killed.append(pid)
        holders.pop(pid, None)
    assert B.end_display(host, disk, kill=kill)
    assert set(killed) == {200, 201, 202, 203} and holders == {501: "Xephyr"}
    assert not B.end_display(host, disk, kill=lambda *a: pytest.fail("the user's own Xephyr was ended"))


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


def test_the_folder_a_logout_left_is_put_back_at_the_start(cat, host, monkeypatch):  # noqa: F811
    """systemd unmounts ~/TempBrowser when the session has ended; the folder underneath, made by the open, goes the
    next time the app starts (as the user: never a path removed as root)."""
    import json
    import time
    from daprivacyscanner import helper
    from daprivacyscanner.tools import transfer, trial
    monkeypatch.setitem(transfer.WATCHED, "on", transfer.WATCHED.get("on"))
    monkeypatch.setattr("daprivacyscanner.server.OUTBOX_EVERY", 3600)
    monkeypatch.setattr(trial, "clear_leftovers", lambda h: None)
    folder = host.home / "TempBrowser"
    folder.mkdir(mode=0o700)
    try:
        os.setxattr(folder, helper.RAMDISK_XATTR, json.dumps({"created": True, "folder_mode": None}).encode())
    except OSError:
        pytest.skip("no extended attributes here")
    os.chmod(folder, 0o500)
    create_app("t0ken", cat, make_host=lambda: host, watch_outbox=True)
    deadline = time.monotonic() + 5
    while folder.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not folder.exists()


# ------------------------------------------------------------------ quitting while something else keeps it open

VIEWER = "Document Viewer (opened by View offline…)"


def viewer_holds(monkeypatch, browser: bool = False) -> dict:
    """A viewer View offline… opened holding a file in ~/TempBrowser (and Tor Browser too, `browser`)."""
    from daprivacyscanner.tools import viewer
    held = {4242: "xreader", **({5151: "firefox.real"} if browser else {})}
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: dict(held))
    monkeypatch.setattr(R, "users_of", lambda host, path: [])
    monkeypatch.setattr(B, "_procs", lambda host: {4242: (1, "xreader"), 5151: (1, "firefox.real")})
    monkeypatch.setattr(B, "running", lambda host, b: [p for p in held if p == 5151 and b.id == "tor"])
    monkeypatch.setattr(viewer, "launched", lambda: {4242: "Document Viewer"})
    return held


def test_quitting_asks_first_when_a_viewer_would_keep_tempbrowser_open(cat, host, monkeypatch):  # noqa: F811
    """Quit left ~/TempBrowser open and its files in it while a viewer View offline… opened still had one open, and
    the window said nothing (the panel promised quitting closes it unless the browser still runs). What would keep it
    open, the browser apart, is what the page asks about first (GET /api/quit: from Quit, and the window's close)."""
    from fastapi.testclient import TestClient
    disk = open_ramdisk(host)
    assert owner.claim(host, "TempBrowser", disk)
    held = viewer_holds(monkeypatch)
    assert B.left_open_by(host) == [VIEWER]
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    assert c.get("/api/quit", headers=H).json() == {"left_open": [VIEWER]}
    del held[4242]
    held[5151] = "firefox.real"
    assert B.left_open_by(host) == []                   # the browser alone: the panel says that it keeps it open
    held[4242] = "xreader"
    assert B.left_open_by(host) == ["Tor Browser", VIEWER]
    owner.release(host, "TempBrowser")                  # another copy's to close: this one's quit leaves it alone
    assert B.left_open_by(host) == [] and c.get("/api/quit", headers=H).json() == {"left_open": []}


def runtime_folder(host) -> Path:
    """The runtime folder, in the fixture's tree: where the note goes."""
    runtime = host.root / "run/user/1000"
    runtime.mkdir(mode=0o700, parents=True)
    host.environ["XDG_RUNTIME_DIR"] = "/run/user/1000"
    return runtime / "daprivacyscanner" / B.LEFT_OPEN


def test_a_quit_that_left_tempbrowser_open_says_why_at_the_next_start(cat, host, monkeypatch):  # noqa: F811
    """Said once, on the browser panel of the copy that owns it then, from a note in the runtime folder (memory, gone at
    logout), never on the disk; kept on the panel until OK, and gone once the disk is closed."""
    from fastapi.testclient import TestClient
    note = runtime_folder(host)
    disk = open_ramdisk(host)
    assert owner.claim(host, "TempBrowser", disk)
    (disk / "report.pdf").write_text("pdf")
    viewer_holds(monkeypatch)
    h = Helper()
    assert "stays open" in B.close_disk(host, lambda: h) and not h.calls and (disk / "report.pdf").exists()
    assert (note.stat().st_mode & 0o777) == 0o600
    owner._drop(host, "TempBrowser")                    # that copy has ended, and the next one shows the panel
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    lo = c.get("/api/tools/browser", headers=H).json()["left_open"]
    assert lo["why"] == f"{VIEWER} was still using it, so its files are still in it" and lo["when"] > 0
    assert not note.exists()                            # taken as it is shown
    assert c.get("/api/tools/browser", headers=H).json()["left_open"] == lo
    assert c.post("/api/tools/browser/dismiss", headers=H, json={"left_open": True}).json() == {"ok": True}
    assert c.get("/api/tools/browser", headers=H).json()["left_open"] is None
    B.note_left_open(host, "x was still using it")      # left open again, then gone (a logout's unmount, here)
    (host.root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    assert c.get("/api/tools/browser", headers=H).json()["left_open"] is None and not note.exists()


def test_closing_tempbrowser_puts_away_why_a_quit_left_it_open(cat, host, monkeypatch):  # noqa: F811
    from fastapi.testclient import TestClient
    note = runtime_folder(host)
    disk = open_ramdisk(host)
    quiet(monkeypatch)
    B.note_left_open(host, "x was still using it")

    class Admin(Helper):
        def alive(self):
            return True

        def close(self):
            pass
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=Admin))
    assert c.get("/api/tools/browser", headers=H).json()["left_open"]["why"] == "x was still using it"
    assert c.post("/api/tools/ramdisk/close", headers=H, json={"disk": "browser"}).status_code == 200
    assert c.get("/api/tools/browser", headers=H).json()["left_open"] is None
    B.note_left_open(host, "x was still using it")      # and a quit that closes it
    assert owner.claim(host, "TempBrowser", disk)
    assert "was closed" in B.close_disk(host, lambda: Helper()) and not note.exists()


def test_without_a_runtime_folder_nothing_is_kept_of_why(host):  # noqa: F811
    """Never a file on the disk instead (what quitting did is said off a terminal nowhere, for that reason)."""
    before = set(host.root.rglob("*"))
    B.note_left_open(host, "x was still using it")
    assert set(host.root.rglob("*")) == before and B.take_left_open(host) is None


class Window:
    """pywebview's window as CloseGuard uses it; run_js answers what the page's script would."""

    def __init__(self, asks=True):
        self.js, self.destroyed, self.asks = [], 0, asks

    def run_js(self, script):
        self.js.append(script)
        return self.asks

    def destroy(self):
        self.destroyed += 1


def settled(cond) -> bool:
    deadline = time.monotonic() + 5
    while not cond() and time.monotonic() < deadline:
        time.sleep(0.01)
    return bool(cond())


def test_closing_the_window_asks_the_page_first_when_quitting_would_leave_tempbrowser_open():
    """Put off (pywebview's closing event) only when ~/TempBrowser is open and this copy's, and something other than
    the browser keeps it open; closing again quits all the same, as a page that can't ask does, or a session ending."""
    from daprivacyscanner.app import CloseGuard
    left = [VIEWER]
    w = Window()                                        # not open, or not this copy's: at once, nothing asked
    assert CloseGuard(w, lambda: False, lambda: left).closing() is True and not w.js
    w = Window()                                        # open, and nothing else keeps it: closed once that is known
    g = CloseGuard(w, lambda: True, lambda: [])
    assert g.closing() is False and settled(lambda: w.destroyed == 1) and not w.js
    assert g.closing() is True                          # the close that follows goes through
    w = Window()                                        # a viewer keeps it: put off, and the page asks
    g = CloseGuard(w, lambda: True, lambda: left)
    assert g.closing() is False and settled(lambda: w.js) and "quit()" in w.js[0] and not w.destroyed
    assert g.closing() is True                          # closed again: it quits all the same
    g.asked -= CloseGuard.AGAIN                         # a while later: asked again
    assert g.closing() is False and settled(lambda: len(w.js) == 2) and not w.destroyed
    g.go()                                              # the page's Quit anyway (POST /api/quit)
    assert w.destroyed == 1 and g.closing() is True
    w = Window(asks=False)                              # a page that can't ask: it quits, as before
    assert CloseGuard(w, lambda: True, lambda: left).closing() is False and settled(lambda: w.destroyed == 1)
    w = Window()                                        # the session ending (SIGTERM, SIGHUP): as it was
    g = CloseGuard(w, lambda: True, lambda: left)
    g.ending = True
    assert g.closing() is True and not w.js
    src = inspect.getsource(app_module.main)
    assert "window.events.closing += guard.closing" in src and "guard.ending = True" in src


def test_quit_anyway_in_the_window_closes_it(cat, host):  # noqa: F811
    from fastapi.testclient import TestClient
    closed = []
    with TestClient(create_app("t0ken", cat, make_host=lambda: host, close_window=lambda: closed.append(1))) as c:
        assert c.get("/api/state", headers=H).json()["can_quit"] is False         # no Quit button in the window
        assert c.post("/api/quit", headers=H).json() == {"ok": True}
        assert settled(lambda: closed == [1])
