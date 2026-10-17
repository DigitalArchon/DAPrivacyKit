"""What does this app keep?: the summary of what a program did with files (tools/activity.py), the helper's
watch (its tally, the parsing of fanotify's events, which filesystems it plans to watch: the watch itself needs
root and the real kernel, and was tried on real machines), the menu's apps and the tool's API."""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper
from daprivacyscanner.host import FakeRunner, Host
from daprivacyscanner.privileged import HelperError, Privileged
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import activity as A
from daprivacyscanner.tools import appwatch, menu

H = {"X-Token": "t0ken"}
W = A.Where("/home/alice", 1000)


# ------------------------------------------------------------------ places and the summary

@pytest.mark.parametrize("path, kind, folder", [
    ("/home/alice/.config/Foo/Cache/ab/cd/x.bin", "app", "~/.config/Foo/Cache"),
    ("/home/alice/.config/kdeglobals", "app", "~/.config"),
    ("/home/alice/.local/share/Foo/db.sqlite", "app", "~/.local/share/Foo"),
    ("/home/alice/.var/app/org.x.App/data/x/y/z.db", "app", "~/.var/app/org.x.App/data/x"),
    ("/home/alice/.var/app/org.x.App/file", "app", "~/.var/app/org.x.App"),
    ("/home/alice/snap/foo/current/a/b/c", "app", "~/snap/foo/current/a"),
    ("/home/alice/.mozilla/firefox/abc.default/places.sqlite", "app", "~/.mozilla/firefox"),
    ("/home/alice/.bash_history", "app", "~ (hidden files)"),
    ("/home/alice/Documents/Work/2026/letter.odt", "yours", "~/Documents/Work/2026"),
    ("/home/alice/notes.txt", "yours", "~"),
    ("/tmp/foo/bar.tmp", "temp", "/tmp/foo"),
    ("/tmp/bar.tmp", "temp", "/tmp"),
    ("/run/user/1000/app/x", "temp", "/run/user/1000/app"),
    ("/media/alice/STICK/Photos/a.jpg", "media", "/media/alice/STICK/Photos"),
    ("/usr/lib/x86_64-linux-gnu/libc.so.6", "system", "/usr/lib"),
    ("/etc/hostname", "system", "/etc"),
])
def test_a_path_is_counted_under_the_folder_that_says_whose_it_is(path, kind, folder):
    assert A.place(path, W) == (kind, folder)


def test_a_folder_is_counted_under_itself():
    assert A.place("/home/alice/.config/Foo", W, is_dir=True) == ("app", "~/.config/Foo")


def test_the_summary_counts_per_folder_and_names_only_what_is_written_regularly(tmp_path):
    home = tmp_path / "home"
    (home / ".config/Foo").mkdir(parents=True)
    db = home / ".config/Foo/history.db"
    db.write_bytes(b"SQLite format 3\0" + b"\0" * 100)
    w = A.Where(str(home), 1000)
    doc = str(home / "Documents/letter.odt")
    recs = [
        [str(db), A.OPENED | A.WRITTEN, 4, 40, 12, ""],                       # written in 12 different minutes
        [str(home / ".config/Foo/settings.json"), A.OPENED | A.WRITTEN, 1, 1, 1, ""],
        [str(home / ".cache/Foo/thumb1.png"), A.CREATED | A.WRITTEN, 0, 1, 1, ""],
        [str(home / ".cache/Foo/tmp1"), A.CREATED | A.WRITTEN | A.DELETED, 0, 1, 1, ""],
        [doc, A.OPENED, 1, 0, 0, ""],
        [str(home / "Documents/other.odt"), A.OPENED | A.WRITTEN, 1, 2, 1, ""],
        [str(home / ".ssh/id_ed25519"), A.OPENED, 1, 0, 0, ""],
        [str(home / ".local/share/recently-used.xbel"), A.WRITTEN, 0, 1, 1, "nemo"],   # another program's: not the app's
    ]
    s = A.summarise(recs, w, 1800)
    assert s["files"] == 7 and s["totals"] == {"opened": 2, "written": 3, "created": 2, "deleted": 1, "ran": 0}
    folders = {p["folder"]: p for p in s["places"]}
    assert folders["~/.config/Foo"]["written"] == 2 and folders["~/.config/Foo"]["left"] == 1
    assert folders["~/.cache/Foo"]["created"] == 2 and folders["~/.cache/Foo"]["deleted"] == 1
    assert [r["path"] for r in s["regular"]] == ["~/.config/Foo/history.db"]
    assert s["regular"][0]["type"] == "an SQLite database" and s["regular"][0]["minutes"] == 12
    assert s["yours"] == {"opened": 1, "changed": 1}
    assert s["sensitive"] == [{"what": "SSH keys and settings", "opened": 1, "written": 0}]
    # the user's own files are never named: not in the places, nor anywhere in the summary
    assert "letter.odt" not in repr(s) and "other.odt" not in repr(s) and "files" not in folders["~/Documents"]


def test_a_trials_own_files_can_be_named(tmp_path):
    s = A.summarise([[str(tmp_path / ".config/Foo/a.json"), A.CREATED | A.WRITTEN, 0, 1, 1, ""]],
                    A.Where(str(tmp_path), 1000), 60, names=True)
    assert s["places"][0]["files"] == [{"name": "~/.config/Foo/a.json", "did": "created, written"}]


def test_files_that_hold_the_names_of_what_was_opened_are_found(tmp_path):
    home = tmp_path / "home"
    for d in (".cache/thumbnails/large", ".local/share", ".config/Foo", "Documents"):
        (home / d).mkdir(parents=True)
    doc = home / "Documents/tax return 2025.pdf"
    doc.write_bytes(b"%PDF-1.4 the document itself, which mentions " + str(doc).encode())
    w = A.Where(str(home), 1000)
    thumb = home / ".cache/thumbnails/large/0a1b.png"                         # the path as a file:// address
    thumb.write_bytes(b"\x89PNG\r\n\x1a\n" + b"tEXtThumb::URI\0file://" + str(doc).replace(" ", "%20").encode())
    recent = home / ".local/share/recently-used.xbel"
    recent.write_text(f'<bookmark href="file://{str(doc).replace(" ", "%20")}"/>')
    qt = home / ".config/Foo/recent.conf"                                     # UTF-16, as Qt writes some settings
    qt.write_bytes(b"\xff\xfe" + f"last={doc}".encode("utf-16-le"))
    clean = home / ".config/Foo/settings.json"
    clean.write_text('{"theme": "dark", "home": "%s"}' % home)                # the home folder alone isn't a name
    recs = [[str(doc), A.OPENED, 1, 0, 0, ""],
            [str(thumb), A.CREATED | A.WRITTEN, 0, 1, 1, "tumblerd"],
            [str(recent), A.WRITTEN, 0, 1, 1, "nemo"],
            [str(qt), A.WRITTEN, 0, 1, 1, ""],
            [str(clean), A.WRITTEN, 0, 1, 1, ""],
            [str(home / ".config/Foo/gone.tmp"), A.CREATED | A.WRITTEN | A.DELETED, 0, 1, 1, ""]]
    r = A.find_records(recs, w)
    assert r["names"] == 1 and r["searched"] == 4
    assert {(f["path"], f["who"]) for f in r["found"]} == {
        ("~/.cache/thumbnails/large/0a1b.png", "tumblerd"), ("~/.local/share/recently-used.xbel", "nemo"),
        ("~/.config/Foo/recent.conf", "")}
    assert all(f["names"] == 1 for f in r["found"])


def test_nothing_is_searched_when_the_app_opened_none_of_the_users_files(tmp_path):
    f = tmp_path / ".config/x"
    f.parent.mkdir()
    f.write_text("x")
    r = A.find_records([[str(f), A.WRITTEN, 0, 1, 1, ""]], A.Where(str(tmp_path), 1000))
    assert r == {"found": [], "searched": 0, "skipped": 0, "names": 0}


# ------------------------------------------------------------------ the helper's watch

def tally(procs, minute=[0]):
    return helper._Tally(1000, "/home/alice", ["daprivacyscanner-watch-ab.scope", "app-flatpak-org.x.App-*.scope"],
                         proc=lambda pid: procs.get(pid), clock=lambda: minute[0] * 60.0)


APP = "/user.slice/user-1000.slice/user@1000.service/app.slice/daprivacyscanner-watch-ab.scope"
FLATPAK = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.x.App-4242.scope"
OTHER = "/user.slice/user-1000.slice/session-2.scope"


def test_units_are_matched_under_the_callers_own_slice_only():
    units = ["daprivacyscanner-watch-ab.scope", "app-flatpak-org.x.App-*.scope"]
    assert helper._watch_in_units(APP, 1000, units) and helper._watch_in_units(FLATPAK, 1000, units)
    assert not helper._watch_in_units(OTHER, 1000, units)
    assert not helper._watch_in_units(APP, 1001, units)                       # another account's slice
    assert not helper._watch_in_units("/system.slice/daprivacyscanner-watch-ab.scope", 1000, units)
    # the session's own units hold every process of the session: never "the app", and never a pattern allowed
    session = "/user.slice/user-1000.slice/user@1000.service/app.slice/xed.scope"
    assert not helper._watch_in_units(session, 1000, ["user@1000.service", "user@*.service", "session-2.scope"])
    for bad in ("user@1000.service", "user@*.service", "session-2.scope", "session-*.scope"):
        assert not helper.WATCH_UNIT.fullmatch(bad), bad


@pytest.mark.parametrize("units", [None, [], ["x"], ["../x.scope"], ["a b.scope"], ["x.scope"] * 9, ["*"], [5]])
def test_the_helper_refuses_units_it_doesnt_expect(units):
    with pytest.raises(helper.Refused):
        helper._watch_units(units)
    assert helper._watch_units(["daprivacyscanner-watch-0a1b.scope", "snap.foo.*.scope"])


def test_the_tally_keeps_the_apps_files_and_only_what_the_users_other_programs_wrote():
    minute = [0]
    procs = {10: (1000, APP, "foo"), 11: (1000, OTHER, "nemo"), 12: (0, "/system.slice/x.service", "rootd"),
             14: (1001, "/user.slice/user-1001.slice/session-9.scope", "bob")}
    t = tally(procs, minute)
    t.add(helper.FAN_OPEN, 10, "/home/alice/Documents/a.odt")
    t.add(helper.FAN_CREATE, 10, "/home/alice/.config/Foo/h.db")
    for m in (0, 0, 1, 5):
        minute[0] = m
        t.add(helper.FAN_MODIFY, 10, "/home/alice/.config/Foo/h.db")
    t.add(helper.FAN_OPEN | helper.FAN_OPEN_EXEC, 10, "/usr/bin/foo")
    t.add(helper.FAN_OPEN, 10, "/etc/hostname")
    t.add(helper.FAN_OPEN, 11, "/home/alice/Documents/a.odt")                 # another program reading: not kept
    t.add(helper.FAN_MODIFY, 11, "/home/alice/.local/share/recently-used.xbel")
    t.add(helper.FAN_MODIFY, 12, "/var/log/syslog")                           # root's, and another account's: dropped
    t.add(helper.FAN_MODIFY, 14, "/home/alice/x")
    t.add(helper.FAN_MODIFY, 13, "/home/alice/.cache/Foo/sub/deep/x.tmp")     # a process that had ended
    t.add(helper.FAN_OPEN, 10, None)
    r = t.result()
    files = {f[0]: f for f in r["files"]}
    assert files["/home/alice/Documents/a.odt"] == ["/home/alice/Documents/a.odt", helper.W_OPENED, 1, 0, 0, ""]
    assert files["/home/alice/.config/Foo/h.db"][1:] == [helper.W_CREATED | helper.W_WRITTEN, 0, 4, 3, ""]
    assert files["/home/alice/.local/share/recently-used.xbel"][1:] == [helper.W_WRITTEN, 0, 1, 1, "nemo"]
    assert len(files) == 3
    assert r["system"] == {"/usr/bin": 1, "/etc": 1} and r["gone"] == {"/home/alice/.cache/Foo": 1}
    assert r["foreign"] == 2 and r["unresolved"] == 1 and r["events"] == 14
    assert "syslog" not in repr(r) and "bob" not in repr(r)


def test_a_program_that_has_just_been_run_is_looked_up_again():
    """systemd-run moves itself into the scope, then runs the app: what was remembered of it is out of date."""
    procs = {10: (1000, OTHER, "systemd-run")}
    t = tally(procs)
    t.add(helper.FAN_OPEN, 10, "/home/alice/.config/x")                       # before the move: another program's
    procs[10] = (1000, APP, "foo")
    t.add(helper.FAN_OPEN | helper.FAN_OPEN_EXEC, 10, "/usr/bin/foo")
    t.add(helper.FAN_MODIFY, 10, "/home/alice/.config/Foo/a")
    assert [f[0] for f in t.result()["files"]] == ["/home/alice/.config/Foo/a"]


def test_a_file_moved_into_place_counts_as_written_and_one_made_again_isnt_deleted():
    t = tally({10: (1000, APP, "foo")})
    t.add(helper.FAN_CREATE, 10, "/home/alice/.config/Foo/a.tmp")
    t.add(helper.FAN_MOVED_FROM, 10, "/home/alice/.config/Foo/a.tmp")
    t.add(helper.FAN_MOVED_TO, 10, "/home/alice/.config/Foo/a")
    t.add(helper.FAN_DELETE, 10, "/home/alice/.config/Foo/b")
    t.add(helper.FAN_CREATE, 10, "/home/alice/.config/Foo/b")
    files = {f[0].rsplit("/", 1)[1]: f for f in t.result()["files"]}
    assert files["a.tmp"][1] & helper.W_DELETED and files["a"][1] == helper.W_MOVED and files["a"][3] == 1
    assert not files["b"][1] & helper.W_DELETED and files["b"][1] & helper.W_CREATED


def test_past_the_limit_files_are_counted_per_folder(monkeypatch):
    monkeypatch.setattr(helper, "WATCH_FILES_MAX", 2)
    t = tally({10: (1000, APP, "foo")})
    for i in range(5):
        t.add(helper.FAN_OPEN, 10, f"/home/alice/.cache/Foo/{i}")
    r = t.result()
    assert len(r["files"]) == 2 and r["folded"] == {"/home/alice/.cache/Foo": 3} and t.counts()["files"] == 5


def _event(mask, pid, handle=b"\x01" * 8, name=b"a.txt", kind=helper.FAN_INFO_DFID_NAME):
    info = struct.pack("=BBH", kind, 0, 0) + b"\0" * 8 + struct.pack("=Ii", len(handle), 1) + handle + name + b"\0"
    info += b"\0" * (-len(info) % 4)
    info = struct.pack("=BBH", kind, 0, len(info)) + info[4:]
    return struct.pack("=IBBHQii", 24 + len(info), 3, 0, 24, mask, -1, pid) + info


def test_fanotify_events_are_parsed_and_a_cut_off_one_is_left():
    buf = _event(helper.FAN_OPEN, 7) + _event(helper.FAN_MODIFY, 8, b"\x02" * 12, "ä.txt".encode())
    buf += struct.pack("=IBBHQii", 24, 3, 0, 24, helper.FAN_Q_OVERFLOW, -1, 0)
    got = list(helper._fan_events(buf + _event(helper.FAN_OPEN, 9)[:30]))
    assert got == [(helper.FAN_OPEN, 7, [(helper.FAN_INFO_DFID_NAME, 1, b"\x01" * 8, b"a.txt")]),
                   (helper.FAN_MODIFY, 8, [(helper.FAN_INFO_DFID_NAME, 1, b"\x02" * 12, "ä.txt".encode())]),
                   (helper.FAN_Q_OVERFLOW, 0, [])]


MOUNTINFO_BTRFS = """\
24 1 0:27 /@ / rw,noatime shared:1 - btrfs /dev/sda3 rw,subvolid=256,subvol=/@
30 24 0:27 /@home /home rw,noatime shared:2 - btrfs /dev/sda3 rw,subvolid=257,subvol=/@home
31 24 0:27 /@log /var/log rw shared:3 - btrfs /dev/sda3 rw
40 24 0:40 / /tmp rw,nosuid shared:9 - tmpfs tmpfs rw
41 24 0:41 / /dev/shm rw shared:10 - tmpfs tmpfs rw
42 24 0:42 / /run rw shared:11 - tmpfs tmpfs rw
43 42 0:43 / /run/user/1000 rw shared:12 - tmpfs tmpfs rw
50 24 8:17 / /run/media/alice/STICK rw - vfat /dev/sdb1 rw
51 24 8:33 /sub /mnt/part rw - ext4 /dev/sdc1 rw
"""


def test_the_filesystems_to_watch_each_once(tmp_path, monkeypatch):
    (tmp_path / "proc/self").mkdir(parents=True)
    (tmp_path / "proc/self/mountinfo").write_text(MOUNTINFO_BTRFS)
    monkeypatch.setattr(helper, "ROOT", str(tmp_path))
    plan, skipped = helper._watch_plan(1000, "/home/alice")
    assert [(p["mount"], p["top"]) for p in plan] == [("/", True), ("/tmp", False), ("/dev/shm", False),
                                                      ("/run/user/1000", False), ("/run/media/alice/STICK", False)]
    # a btrfs is reached through its top level, each subvolume mapped to where it is mounted, deepest first
    assert plan[0]["subvolumes"][-1] == ["/@", "/"] and ["/@home", "/home"] in plan[0]["subvolumes"]
    assert skipped == [["/mnt/part", "only part of that filesystem is mounted here"]]


def test_a_btrfs_path_is_turned_into_the_callers():
    w = helper._Watched.__new__(helper._Watched)
    w.strip = "/run/daprivacyscanner-watch/0"
    w.fs = {"subvolumes": [["/@home", "/home"], ["/@log", "/var/log"], ["/@", "/"]]}
    assert w._mapped("/run/daprivacyscanner-watch/0/@home/alice/.config") == "/home/alice/.config"
    assert w._mapped("/run/daprivacyscanner-watch/0/@/etc") == "/etc"
    assert w._mapped("/run/daprivacyscanner-watch/0/@") == "/"
    assert w._mapped("/run/daprivacyscanner-watch/0/@snapshots/3/x") is None      # mounted nowhere: no path of theirs
    assert w._mapped("/run/daprivacyscanner-watch/0/@home/alice/x (deleted)") is None


def test_the_watch_is_refused_off_the_real_system(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "ROOT", str(tmp_path))
    monkeypatch.setattr(helper, "CALLER", (1000, 1000, "/home/alice"))
    (tmp_path / "home/alice").mkdir(parents=True)
    r = helper.handle('{"id": 1, "action": "watch_begin", "args": {"units": ["daprivacyscanner-watch-ab.scope"]}}')
    assert not r["ok"] and "real system" in r["error"]
    assert not helper.handle('{"id": 2, "action": "watch_end", "args": {}}')["ok"]


# ------------------------------------------------------------------ the menu, and the tool

DESKTOP = """[Desktop Entry]
Type=Application
Name={name}
Comment=Does things
Exec={exec}
{extra}
[Desktop Action new]
Exec=other --new
"""


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    apps = root / "usr/share/applications"
    apps.mkdir(parents=True)
    (home / ".local/share/applications").mkdir(parents=True)
    (apps / "foo.desktop").write_text(DESKTOP.format(name="Foo", exec="env LANG=C foo --open %U", extra=""))
    (apps / "hidden.desktop").write_text(DESKTOP.format(name="Hidden", exec="hidden", extra="NoDisplay=true"))
    (apps / "term.desktop").write_text(DESKTOP.format(name="Term", exec="htop", extra="Terminal=true"))
    (apps / "org.x.App.desktop").write_text(DESKTOP.format(
        name="App", exec="/usr/bin/flatpak run --branch=stable --command=app org.x.App @@u %u @@", extra="X-Flatpak=org.x.App"))
    (home / ".local/share/applications/foo.desktop").write_text(DESKTOP.format(name="My Foo", exec="foo --mine", extra=""))
    (root / "run/user/1000/systemd").mkdir(parents=True)
    return Host(home=home, environ={"HOME": str(home), "XDG_DATA_DIRS": "/usr/share", "XDG_RUNTIME_DIR": "/run/user/1000"},
                runner=FakeRunner(installed=["systemd-run"]), root=root, uid=1000)


def test_the_menus_apps(host):
    found = {a.id: a for a in menu.apps(host)}
    assert set(found) == {"foo.desktop", "term.desktop", "org.x.App.desktop"}
    assert found["foo.desktop"].name == "My Foo" and found["foo.desktop"].argv == ["foo", "--mine"]    # the user's wins
    flat = found["org.x.App.desktop"]
    assert flat.kind == "flatpak" and flat.flatpak == "org.x.App" and "%u" not in flat.argv
    assert menu.app(host, "hidden.desktop").name == "Hidden" and menu.app(host, "../x.desktop") is None


def test_the_apps_units_and_command(host):
    flat = menu.app(host, "org.x.App.desktop")
    assert appwatch.units(flat, "0a1b") == ["daprivacyscanner-watch-0a1b.scope", "app-flatpak-org.x.App-*.scope"]
    (host.root / "usr/share/applications/env.desktop").write_text(DESKTOP.format(name="E", exec="env A=1 foo", extra=""))
    assert appwatch.command(menu.app(host, "env.desktop"), "0a1b") == [
        "systemd-run", "--user", "--scope", "--collect", "--quiet", "--unit=daprivacyscanner-watch-0a1b.scope",
        "--description=An app watched by DA Privacy Kit", "--", "env", "A=1", "foo"]
    assert all(helper.WATCH_UNIT.fullmatch(u) for u in appwatch.units(flat, "0a1b"))
    assert appwatch.available(host) is None
    host.runner = FakeRunner()
    assert "systemd-run" in appwatch.available(host)


class WatchingHelper(Privileged):
    """The helper's three watch actions, canned."""

    def __init__(self, home: Path):
        self.calls, self.home, self.open = [], home, True

    def call(self, action, args, timeout=None):
        self.calls.append((action, args))
        if action == "watch_begin":
            return {"watched": ["/"], "skipped": [["/mnt/x", "this kind of filesystem can't be watched"]], "units": args["units"]}
        if action == "watch_poll":
            return {"events": 9, "files": 2, "others": 1, "overflow": 0, "seconds": 1.0}
        if action == "watch_end":
            doc = str(self.home / "Documents/letter.odt")
            return {"files": [[doc, A.OPENED, 1, 0, 0, ""],
                              [str(self.home / ".config/Foo/recent"), A.WRITTEN, 0, 5, 4, ""],
                              [str(self.home / ".local/share/recently-used.xbel"), A.WRITTEN, 0, 1, 1, "nemo"]],
                    "folded": {}, "system": {"/usr/lib": 40}, "gone": {str(self.home / ".cache"): 2}, "events": 60,
                    "foreign": 7, "overflow": 0, "unresolved": 0, "others_left": 0, "seconds": 600.0}
        raise HelperError("unknown action")

    def alive(self):
        return self.open

    def close(self):
        self.open = False


def test_the_tool_watches_an_app_and_hands_over_counts(cat, host, monkeypatch):
    from daprivacyscanner import server
    monkeypatch.setattr(server, "KEEPS_EVERY", 0.05)
    home = host.home
    (home / "Documents").mkdir()
    (home / ".config/Foo").mkdir(parents=True)
    (home / "Documents/letter.odt").write_text("x")
    (home / ".config/Foo/recent").write_text(f"last={os.path.realpath(home)}/Documents/letter.odt\n")
    (home / ".local/share/recently-used.xbel").write_text("nothing of it here")
    fake, spawned = WatchingHelper(Path(os.path.realpath(home))), []
    with TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: fake,
                               spawn_app=lambda argv, **kw: spawned.append(argv))) as c:
        d = c.get("/api/tools/keeps", headers=H).json()
        assert d["unavailable"] is None and [a["id"] for a in d["apps"]] == ["org.x.App.desktop", "foo.desktop"]
        assert "administrator access" in d["warning"] and d["job"] is None
        assert c.post("/api/tools/keeps/start", headers=H, json={"app": "term.desktop"}).status_code == 400
        assert c.post("/api/tools/keeps/start", headers=H, json={"app": "foo.desktop"}).json()["job"]["state"] == "asking"

        def job():
            return c.get("/api/tools/keeps", headers=H).json()["job"]
        deadline = time.time() + 5
        while (job()["state"] != "running" or not job()["counts"]) and time.time() < deadline:
            time.sleep(0.02)
        j = job()
        assert j["state"] == "running" and j["counts"]["files"] == 2 and j["not_watched"][0][0] == "/mnt/x"
        assert spawned and spawned[0][:4] == ["systemd-run", "--user", "--scope", "--collect"] and spawned[0][-2:] == ["foo", "--mine"]
        assert fake.calls[0][0] == "watch_begin" and fake.calls[0][1]["units"][0].startswith("daprivacyscanner-watch-")
        assert c.post("/api/tools/keeps/start", headers=H, json={"app": "foo.desktop"}).status_code == 409
        assert c.get("/api/tools/keeps", headers=H).json()["admin_active"] is True      # held while it watches
        c.post("/api/tools/keeps/stop", headers=H)
        while job()["state"] != "done" and time.time() < deadline:
            time.sleep(0.02)
        r = job()["result"]
        assert r["app"] == "My Foo" and r["yours"] == {"opened": 1, "changed": 0}
        assert [f["path"] for f in r["regular"]] == ["~/.config/Foo/recent"]
        assert [(f["path"], f["who"]) for f in r["records"]["found"]] == [("~/.config/Foo/recent", "")]
        assert r["system"] == [{"folder": "/usr/lib", "files": 40}] and r["gone"] == [{"folder": "~/.cache", "events": 2}]
        assert "letter.odt" not in repr(r)                                              # the user's file: never named
        assert c.get("/api/tools/keeps", headers=H).json()["admin_active"] is False     # given up when it ends
        assert c.post("/api/tools/keeps/dismiss", headers=H).json() == {"job": None}


def test_an_app_that_is_open_isnt_watched(cat, host, monkeypatch):
    monkeypatch.setattr(appwatch, "running", lambda h, a: True)
    with TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: 1 / 0)) as c:
        r = c.post("/api/tools/keeps/start", headers=H, json={"app": "foo.desktop"})
        assert r.status_code == 409 and "Close My Foo first" in r.json()["error"]
