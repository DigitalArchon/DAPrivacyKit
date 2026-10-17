"""What does this app keep?: what the tools review of 2026-10-17 found (D1 to D13 and the suspicions it confirmed),
each with the test that keeps it fixed. The watch itself needs root and the real kernel: what it does there was
tried on the lab machines; here, its parts."""

from __future__ import annotations

import struct
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper
from daprivacyscanner.host import FakeRunner, Host
from daprivacyscanner.privileged import HelperError, Privileged
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import activity as A
from daprivacyscanner.tools import appwatch, menu


# ------------------------------------------------------------------ D1: the user's own files are never named

def test_the_users_own_documents_saved_often_are_counted_not_named(tmp_path):
    home = tmp_path / "home"
    w = A.Where(str(home), 1000)
    recs = [[str(home / "Documents/Legal/letter-to-my-lawyer.odt"), A.OPENED | A.WRITTEN, 3, 5, 4, ""],
            ["/media/alice/USB/Diary/2026-10-17.txt", A.OPENED | A.WRITTEN, 1, 30, 1, ""],
            [str(home / ".config/xed/state"), A.WRITTEN, 0, 9, 3, ""]]
    for seconds in (600, 100):                       # in different minutes, or (a short watch) often
        s = A.summarise(recs, w, seconds, size_of=lambda p: 10)
        assert [r["path"] for r in s["regular"]] == ["~/.config/xed/state"]
        assert "letter-to-my-lawyer" not in repr(s) and "2026-10-17.txt" not in repr(s)     # folders are named, files not
    assert A.summarise(recs, w, 600, size_of=lambda p: 10)["regular_yours"] == 1
    assert A.summarise(recs, w, 100, size_of=lambda p: 10)["regular_yours"] == 2
    # a trial's home is made up: its "documents" may be named
    s = A.summarise(recs[:1], w, 600, names=True, size_of=lambda p: 10)
    assert [r["path"] for r in s["regular"]] == ["~/Documents/Legal/letter-to-my-lawyer.odt"] and not s["regular_yours"]


# ------------------------------------------------------------------ D2, D3, D4: who recorded what was opened

def _home(tmp_path):
    home = tmp_path / "home"
    for d in (".cache/thumbnails/large", ".local/share/gvfs-metadata", ".config/Foo", "Documents"):
        (home / d).mkdir(parents=True, exist_ok=True)
    return home, A.Where(str(home), 1000)


def _png(*chunks: tuple[bytes, bytes]) -> bytes:
    out = b"\x89PNG\r\n\x1a\n"
    for kind, data in (*chunks, (b"IEND", b"")):
        out += struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return out


def test_glib_and_qt_addresses_and_xml_escapes_are_found(tmp_path):
    """GLib leaves ()'&!$*+,=@ unescaped in a file:// address, Qt ; too, and a bookmark file escapes & and ' for
    XML: "Report (final) & co's.txt" was missed in the recent-files list."""
    home, w = _home(tmp_path)
    doc = f"{home}/Documents/Report (final) & co's.txt"
    other = f"{home}/Documents/a;b.txt"
    glib = f"file://{home}/Documents/Report%20(final)%20&amp;%20co&apos;s.txt"     # as GLib 2.80 wrote it (tested)
    xbel = home / ".local/share/recently-used.xbel"
    xbel.write_text(f'<bookmark href="{glib}" added="x"/>\n<bookmark href="file://{home}/Documents/a;b.txt"/>')
    old = home / ".config/Foo/history"                                          # GLib before 2.80: &#39;
    old.write_text(f"file://{home}/Documents/Report%20(final)%20&amp;%20co&#39;s.txt")
    recs = [[doc, A.OPENED, 1, 0, 0, ""], [other, A.OPENED, 1, 0, 0, ""],
            [str(xbel), A.WRITTEN, 0, 1, 1, "xed"], [str(old), A.WRITTEN, 0, 1, 1, ""]]
    r = A.find_records(recs, w)
    assert {f["path"]: f["names"] for f in r["found"]} == {"~/.local/share/recently-used.xbel": 2,
                                                          "~/.config/Foo/history": 1}


def test_a_thumbnails_compressed_text_chunk_is_read(tmp_path):
    """Qt writes a Thumb::URI longer than 40 characters as zTXt (Dolphin's thumbnails on CachyOS)."""
    home, w = _home(tmp_path)
    doc = f"{home}/Documents/holiday photo.jpg"
    uri = f"file://{home}/Documents/holiday%20photo.jpg".encode()
    ztxt = home / ".cache/thumbnails/large/1.png"
    ztxt.write_bytes(_png((b"zTXt", b"Thumb::URI\0\0" + zlib.compress(uri)), (b"IDAT", b"\0" * 64)))
    itxt = home / ".cache/thumbnails/large/2.png"
    itxt.write_bytes(_png((b"iTXt", b"Thumb::URI\0\x01\x00\0\0" + zlib.compress(uri))))
    plain = home / ".cache/thumbnails/large/3.png"
    plain.write_bytes(_png((b"tEXt", b"Thumb::MTime\x00123")))
    recs = [[doc, A.OPENED, 1, 0, 0, ""]] + [[str(p), A.CREATED | A.WRITTEN, 0, 1, 1, "kioworker"]
                                             for p in (ztxt, itxt, plain)]
    r = A.find_records(recs, w)
    assert sorted(f["path"] for f in r["found"]) == ["~/.cache/thumbnails/large/1.png",
                                                     "~/.cache/thumbnails/large/2.png"]
    # a broken chunk is no error: nothing found in it
    bad = home / ".cache/thumbnails/large/4.png"
    bad.write_bytes(_png((b"zTXt", b"Thumb::URI\0\0not zlib at all")) + b"trailing")
    assert not A.find_records([[doc, A.OPENED, 1, 0, 0, ""], [str(bad), A.WRITTEN, 0, 1, 1, ""]], w)["found"]


def _gvfs_tree(paths: list[str]) -> bytes:
    """A GVFS metadata database as gvfsd-metadata writes it (the layout read from one on Mint 22.3)."""
    tree: dict = {}
    for p in paths:
        node = tree
        for part in p.strip("/").split("/"):
            node = node.setdefault(part, {})
    blob = bytearray(b"\xda\x1ameta\x01\x00" + b"\0" * 24)

    def put(data: bytes) -> int:
        blob.extend(data)
        return len(blob) - len(data)

    def entry(name: str, children: dict) -> bytes:
        name_at = put(name.encode() + b"\0")
        kids = [entry(k, v) for k, v in children.items()]
        dir_at = put(struct.pack(">I", len(kids)) + b"".join(kids)) if kids else 0
        return struct.pack(">IIII", name_at, dir_at, 0, 0)
    blob[16:20] = struct.pack(">I", put(entry("/", tree)))
    return bytes(blob)


def _gvfs_journal(paths: list[str]) -> bytes:
    out = b"\xda\x1ajour\x01\x00" + struct.pack(">III", 0x12345678, 32768, len(paths))
    for p in paths:
        body = struct.pack(">IQ", 0, 0) + b"\x00" + p.encode() + b"\0xed-position\x003\0"
        out += struct.pack(">I", len(body) + 4) + body
    return out


def test_gvfs_metadata_is_read_by_its_own_paths(tmp_path):
    """gvfsd-metadata keeps paths relative to the home folder ("/Documents/x"), whole in its journal and split into
    names in its database: Xed's cursor position for the file opened was never found (Mint 22.3)."""
    home, w = _home(tmp_path)
    doc, other = f"{home}/Documents/Sub dir/Report (final).txt", f"{home}/Documents/notes.txt"
    folder = home / ".local/share/gvfs-metadata"
    (folder / "home-fd7a2957.log").write_bytes(_gvfs_journal(["/Documents/Sub dir/Report (final).txt", "/x.txt"]))
    (folder / "home").write_bytes(_gvfs_tree(["/Documents/notes.txt", "/Music/notes.txt"]))
    (folder / "root-0a0b0c0d.log").write_bytes(_gvfs_journal(["/Documents/notes.txt"]))  # another tree: not home's
    recs = [[doc, A.OPENED, 1, 0, 0, ""], [other, A.OPENED, 1, 0, 0, ""]]
    recs += [[str(p), A.WRITTEN, 0, 1, 1, "gvfsd-metadata"] for p in sorted(folder.iterdir())]
    r = A.find_records(recs, w)
    assert {f["path"]: f["names"] for f in r["found"]} == {"~/.local/share/gvfs-metadata/home-fd7a2957.log": 1,
                                                          "~/.local/share/gvfs-metadata/home": 1}
    assert all("GVFS" in f["type"] for f in r["found"])
    # what isn't whole gives nothing, and no error
    (folder / "home").write_bytes(_gvfs_tree(["/Documents/notes.txt"])[:40])
    (folder / "home-fd7a2957.log").write_bytes(b"\xda\x1ajour" + b"\xff" * 40)
    assert not A.find_records(recs, w)["found"]


def test_a_file_opened_from_a_temporary_folder_is_looked_for(tmp_path):
    """A mail attachment or a download opened from /tmp is the user's: its name in the recent-files list counts.
    A program's own files there (made by the app, or hidden) and the runtime folder's don't."""
    home, w = _home(tmp_path)
    xbel = home / ".local/share/recently-used.xbel"
    xbel.write_text('<bookmark href="file:///tmp/mozilla_alice0/tax%20return.pdf"/>')
    recs = [["/tmp/mozilla_alice0/tax return.pdf", A.OPENED, 1, 0, 0, ""],
            ["/tmp/.X11-unix/lock", A.OPENED, 1, 0, 0, ""], ["/var/tmp/foo/own.tmp", A.CREATED | A.OPENED, 1, 0, 0, ""],
            ["/run/user/1000/dconf/user", A.OPENED, 1, 0, 0, ""], [str(xbel), A.WRITTEN, 0, 1, 1, "xreader"]]
    assert A.needles(recs, w) == ["/tmp/mozilla_alice0/tax return.pdf"]
    r = A.find_records(recs, w)
    assert r["names"] == 1 and [f["path"] for f in r["found"]] == ["~/.local/share/recently-used.xbel"]


# ------------------------------------------------------------------ D5: an app behind a script, a Snap

def _file(root: Path, path: str, text: str = "\x7fELF", mode: int = 0o755) -> None:
    f = root / path.lstrip("/")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    f.chmod(mode)


@pytest.fixture
def machine(tmp_path):
    root = tmp_path / "root"
    _file(root, "/usr/lib/libreoffice/program/soffice", '#!/bin/sh\nsd_prog=$(dirname "$0")\n'
          'exec $RRCHECK "$sd_prog/oosplash" "$@"\n')
    for p in ("/usr/lib/libreoffice/program/oosplash", "/usr/lib/libreoffice/program/soffice.bin",
              "/usr/lib/firefox/firefox", "/usr/share/code/code", "/usr/bin/zenity", "/usr/bin/python3", "/bin/sh",
              "/usr/bin/xed"):
        _file(root, p)
    (root / "usr/bin/libreoffice").symlink_to("../lib/libreoffice/program/soffice")
    _file(root, "/usr/bin/firefox", "#!/bin/sh\nexport MOZ_APP_LAUNCHER=/usr/bin/firefox\nexec /usr/lib/firefox/firefox \"$@\"\n")
    _file(root, "/usr/bin/mintupdate", '#!/usr/bin/python3\nimport os\nos.system("/usr/lib/linuxmint/mintUpdate/mintUpdate.py show &")\n')
    _file(root, "/usr/lib/linuxmint/mintUpdate/mintUpdate.py", "#!/usr/bin/python3\n")
    _file(root, "/usr/share/code/bin/code", '#!/usr/bin/env sh\nVSCODE_PATH="/usr/share/code"\nELECTRON="$VSCODE_PATH/code"\n'
          '"$ELECTRON" "$@"\n')
    (root / "usr/bin/code").symlink_to("../share/code/bin/code")
    _file(root, "/usr/bin/asker", "#!/bin/sh\n/usr/bin/zenity --question || exit\nexec /usr/lib/asker/asker\n")
    _file(root, "/usr/lib/asker/asker")
    (root / "proc").mkdir()
    home = root / "home/alice"
    home.mkdir(parents=True)
    return Host(home=home, environ={"HOME": str(home), "PATH": "/usr/bin:/bin"}, runner=FakeRunner(), root=root, uid=1000)


def _process(host: Host, pid: int, exe: str, *args: str, cgroup: str = "0::/user.slice/user-1000.slice/session-2.scope"):
    d = host.root / "proc" / str(pid)
    d.mkdir()
    (d / "exe").symlink_to(exe)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in (args or (exe,))) + b"\0")
    (d / "cgroup").write_text(cgroup + "\n")


@pytest.mark.parametrize("argv, exe, args", [
    (["libreoffice", "--writer"], "/usr/lib/libreoffice/program/oosplash", ()),     # the script beside it starts it
    (["libreoffice"], "/usr/lib/libreoffice/program/soffice.bin", ()),
    (["firefox"], "/usr/lib/firefox/firefox", ()),                                   # the program the script names
    (["mintupdate"], "/usr/bin/python3", ("/usr/bin/python3", "/usr/lib/linuxmint/mintUpdate/mintUpdate.py", "show")),
    (["/usr/bin/code"], "/usr/share/code/code", ()),                                # in the folder the script names
    (["xed"], "/usr/bin/xed", ()),
    (["python3", "/usr/lib/linuxmint/mintUpdate/mintUpdate.py"], "/usr/bin/python3",
     ("python3", "/usr/lib/linuxmint/mintUpdate/mintUpdate.py")),
])
def test_an_app_behind_a_script_is_found_running(machine, argv, exe, args):
    """running() compared processes with the menu entry's program, a script whose processes never run it: LibreOffice
    already open was started again, handed over, and the watch saw nothing (Mint 22.3)."""
    app = menu.App("x.desktop", "X", argv, "native")
    _process(machine, 50, "/usr/bin/zenity")                                         # somebody else's tool
    _process(machine, 51, "/usr/bin/python3", "/usr/bin/python3", "/usr/lib/other/thing.py")
    assert not appwatch.running(machine, app)
    _process(machine, 60, exe, *args)
    assert appwatch.running(machine, app)


def test_a_tool_a_script_uses_isnt_the_app(machine):
    app = menu.App("asker.desktop", "Asker", ["asker"], "native")
    _process(machine, 50, "/usr/bin/zenity")
    assert not appwatch.running(machine, app)
    _process(machine, 51, "/usr/lib/asker/asker")
    assert appwatch.running(machine, app)


def test_a_snap_is_found_running_by_its_cgroup(machine):
    app = menu.App("firefox_firefox.desktop", "Firefox", ["/snap/bin/firefox"], "snap", snap="firefox")
    _process(machine, 50, "/usr/lib/firefox/firefox", cgroup="0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
             "snap.firefox-esr.firefox-esr-1.scope")
    assert not appwatch.running(machine, app)
    _process(machine, 51, "/snap/firefox/6000/usr/lib/firefox/firefox", cgroup="0::/user.slice/user-1000.slice/"
             "user@1000.service/app.slice/snap.firefox.firefox-0a1b2c3d.scope")
    assert appwatch.running(machine, app)


def test_a_watch_that_saw_nothing_of_the_app_says_it_may_have_handed_over():
    """oosplash stays in the scope when it hands over to a LibreOffice already open: alive, and not one file."""
    src = (Path(__file__).parent.parent / "src/daprivacyscanner/server.py").read_text()
    assert 'job["quiet"]' in src and "appwatch.QUIET_AFTER" in src
    js = (Path(__file__).parent.parent / "src/daprivacyscanner/web/app.js").read_text()
    assert "job.quiet ?" in js and "!r.files ?" in js and "r.others_places" in js


# ------------------------------------------------------------------ D12: the journal doesn't say which app

def test_the_scope_has_a_description_that_doesnt_name_the_app():
    """Without one, systemd journals "Started daprivacyscanner-watch-….scope - /usr/bin/xed." (Mint 22.3)."""
    argv = appwatch.command(menu.App("xed.desktop", "Xed", ["/usr/bin/xed", "--new-window"], "native"), "0a1b")
    sep = argv.index("--")
    assert "--description=An app watched by DA Privacy Kit" in argv[:sep]
    assert not any("xed" in a.lower() for a in argv[:sep]) and argv[sep + 1:] == ["/usr/bin/xed", "--new-window"]


# ------------------------------------------------------------------ the tool's API

H = {"X-Token": "t0ken"}


class FakeWatch(Privileged):
    """The helper's watch actions, canned; `poll` can be made to fail."""

    def __init__(self):
        self.calls, self.open = [], True

    def call(self, action, args, timeout=None):
        self.calls.append(action)
        if action == "watch_begin":
            return {"watched": ["/"], "skipped": [], "units": args["units"]}
        if action == "watch_poll":
            return {"events": 1, "files": 1, "others": 0, "overflow": 0, "seconds": 1.0}
        if action == "watch_end":
            return {"files": [], "folded": {}, "system": {}, "gone": {}, "events": 1, "foreign": 0, "overflow": 0,
                    "unresolved": 0, "others_left": 0, "seconds": 5.0}
        raise HelperError("unknown action")

    def alive(self):
        return self.open

    def close(self):
        self.open = False


@pytest.fixture
def menu_host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    (root / "usr/share/applications").mkdir(parents=True)
    (home / ".local/share/applications").mkdir(parents=True)
    (root / "usr/share/applications/foo.desktop").write_text("[Desktop Entry]\nType=Application\nName=Foo\nExec=foo\n")
    (root / "run/user/1000/systemd").mkdir(parents=True)
    return Host(home=home, environ={"HOME": str(home), "XDG_DATA_DIRS": "/usr/share", "XDG_RUNTIME_DIR": "/run/user/1000"},
                runner=FakeRunner(installed=["systemd-run"]), root=root, uid=1000)


def _wait(c, until, seconds=5.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        job = c.get("/api/tools/keeps", headers=H).json()["job"]
        if until(job):
            return job
        time.sleep(0.02)
    raise AssertionError(f"the job didn't get there: {job}")


def test_two_starts_at_once_make_one_watch(cat, menu_host, monkeypatch):
    """Both passed the check before either had made its job: the first went on watching with administrator access
    held, and End reached only the second (D10, live on Mint)."""
    from daprivacyscanner import server
    monkeypatch.setattr(server, "KEEPS_EVERY", 0.05)
    monkeypatch.setattr(appwatch, "running", lambda h, a: time.sleep(0.3) or False)    # a slow look at /proc
    fake = FakeWatch()
    with TestClient(create_app("t0ken", cat, make_host=lambda: menu_host, start_helper=lambda: fake,
                               spawn_app=lambda argv, **kw: None)) as c:
        with ThreadPoolExecutor(2) as pool:
            codes = sorted(f.result().status_code for f in [pool.submit(c.post, "/api/tools/keeps/start", headers=H,
                                                                        json={"app": "foo.desktop"}) for _ in range(2)])
        assert codes == [200, 409]
        _wait(c, lambda j: j["state"] == "running")
        c.post("/api/tools/keeps/stop", headers=H)
        _wait(c, lambda j: j["state"] == "done")
        assert fake.calls.count("watch_begin") == 1 and fake.calls.count("watch_end") == 1


def test_the_watch_and_the_other_long_root_work_keep_apart(cat, menu_host, monkeypatch):
    """Installing the helper during a watch dropped the access and lost the watch (D13); the TRIM test or Deleted
    file names alongside it held its polling behind minutes-long disk reads (the suspicion, confirmed)."""
    from daprivacyscanner import server
    monkeypatch.setattr(server, "KEEPS_EVERY", 0.05)
    monkeypatch.setattr(appwatch, "running", lambda h, a: False)
    fake = FakeWatch()
    with TestClient(create_app("t0ken", cat, make_host=lambda: menu_host, start_helper=lambda: fake,
                               spawn_app=lambda argv, **kw: None)) as c:
        assert c.post("/api/tools/keeps/start", headers=H, json={"app": "foo.desktop"}).status_code == 200
        _wait(c, lambda j: j["state"] == "running")
        r = c.post("/api/helper/install", headers=H, json={})
        assert r.status_code == 409 and "What does this app keep?" in r.json()["error"]
        for path, body in (("/api/tools/trim/start", {"mount": "/"}), ("/api/tools/names/start", {"mount": "/"}),
                           ("/api/tools/names/clean", {"mount": "/", "folders": ["x"], "not_synced": True})):
            r = c.post(path, headers=H, json=body)
            assert r.status_code == 409 and "end the watch first" in r.json()["error"], path
        assert c.app.state.trim_job is None and c.app.state.names_job is None and fake.open
        c.post("/api/tools/keeps/stop", headers=H)
        _wait(c, lambda j: j["state"] == "done")
        c.post("/api/tools/keeps/dismiss", headers=H)
        c.app.state.trim_job = {"state": "running", "cancel": False}             # the TRIM test, running
        r = c.post("/api/tools/keeps/start", headers=H, json={"app": "foo.desktop"})
        assert r.status_code == 409 and "TRIM test" in r.json()["error"] and fake.calls.count("watch_begin") == 1
        c.app.state.trim_job = None


# ------------------------------------------------------------------ the helper's watch

def test_the_kernels_queue_is_bounded_and_an_overflow_is_counted():
    """FAN_UNLIMITED_QUEUE let the kernel's queue grow to 1.7 GB under busy programs, never reporting an overflow
    (D6): the default queue drops what doesn't fit and says so, and the watch counts it."""
    assert not helper.WATCH_INIT_FLAGS & helper.FAN_UNLIMITED_QUEUE
    assert helper.WATCH_INIT_FLAGS & helper.FAN_REPORT_DIR_FID and helper.WATCH_INIT_FLAGS & helper.FAN_REPORT_NAME
    src = Path(helper.__file__).read_text()
    assert "FAN_UNLIMITED_QUEUE |" not in src and "| FAN_UNLIMITED_QUEUE" not in src
    events = list(helper._fan_events(struct.pack("=IBBHQii", 24, 3, 0, 24, helper.FAN_Q_OVERFLOW, -1, 0)))
    assert events == [(helper.FAN_Q_OVERFLOW, 0, [])]


def _event(mask, pid=7, handle=b"\x01" * 8, name=b"d1"):
    info = struct.pack("=BBH", helper.FAN_INFO_DFID_NAME, 0, 0) + b"\0" * 8 + struct.pack("=Ii", len(handle), 1)
    info += handle + name + b"\0"
    info += b"\0" * (-len(info) % 4)
    info = struct.pack("=BBH", helper.FAN_INFO_DFID_NAME, 0, len(info)) + info[4:]
    return struct.pack("=IBBHQii", 24 + len(info), 3, 0, 24, mask, -1, pid) + info


def test_a_folder_renamed_makes_the_remembered_paths_go():
    """Files made in ~/aw-ren/d2 were reported under ~/aw-ren/d1, its name before (D9, live on Mint): folders' handles
    were remembered as paths for good. A group of its own reports folders renamed, moved or removed."""
    import os
    assert helper.FAN_FOLDERS_MOVED & helper.FAN_ONDIR and not helper.FAN_WATCHED & helper.FAN_ONDIR
    assert helper.FAN_FOLDERS_MOVED & helper.FAN_MOVED_FROM and helper.FAN_FOLDERS_MOVED & helper.FAN_DELETE
    w = helper._Watched.__new__(helper._Watched)
    r, wr = os.pipe()
    os.set_blocking(r, False)
    w.dirs, w.paths = r, {(1, b"\x01" * 8): "/home/alice/aw-ren/d1"}
    try:
        os.write(wr, _event(helper.FAN_MOVED_FROM, name=b"file.txt"))           # a file renamed: nothing to forget
        w.moved()
        assert w.paths
        os.write(wr, _event(helper.FAN_MOVED_FROM | helper.FAN_ONDIR) + _event(helper.FAN_MOVED_TO | helper.FAN_ONDIR))
        w.moved()
        assert w.paths == {} and w.dirs == r
    finally:
        os.close(r)
        os.close(wr)


class FakeLibc:
    def __init__(self, mount=0):
        self.calls, self._mount = [], mount

    def mount(self, *args):
        self.calls.append(("mount", args[1]))
        return self._mount

    def umount2(self, path, flags):
        self.calls.append(("umount2", path, flags))
        return 0

    def fanotify_init(self, *args):
        return -1


def test_a_watched_filesystem_closes_and_removes_the_folder_it_mounted(tmp_path, monkeypatch):
    """/run/daprivacyscanner-watch/N was left on CachyOS (btrfs) after the access was dropped or the app quit (D11)."""
    import os
    monkeypatch.setattr(helper, "WATCH_MOUNT_DIR", str(tmp_path / "w"))
    libc = FakeLibc(mount=-1)                                    # the top level can't be mounted: nothing left
    with pytest.raises(OSError):
        helper._Watched(libc, {"mount": "/", "top": True, "source": "/dev/sda3", "fstype": "btrfs"}, 0)
    assert not (tmp_path / "w/0").exists()
    w = helper._Watched.__new__(helper._Watched)
    (tmp_path / "w/1").mkdir(parents=True)
    fds = [os.open(os.devnull, os.O_RDONLY) for _ in range(3)]
    w.libc, w.fan, w.dirs, w.mfd = FakeLibc(), *fds
    w.made = w.strip = str(tmp_path / "w/1")
    w.close()
    assert w.libc.calls == [("umount2", str(tmp_path / "w/1").encode(), 2)] and not (tmp_path / "w/1").exists()
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    w.close()                                                    # twice is nothing


OTHER = "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"


def test_what_other_programs_write_in_the_users_folders_doesnt_crowd_out_the_records(monkeypatch, tmp_path):
    """A build writing 30,000 files filled the other programs' records and the thumbnail written after it was
    dropped, unsaid (D8). The user's own folders and other disks are counted per folder (never searched for records
    anyway); past the limit, the rest too, and the result says how many."""
    procs = {10: (1000, OTHER, "npm"), 11: (1000, OTHER, "tumblerd"), 12: (1000, OTHER, "cp")}
    t = helper._Tally(1000, "/home/u", ["daprivacyscanner-watch-abc.scope"], proc=lambda pid: procs.get(pid))
    for i in range(helper.WATCH_OTHERS_MAX + 10):
        t.add(helper.FAN_CREATE | helper.FAN_MODIFY, 10, f"/home/u/project/node_modules/pkg{i}/index.js")
    t.add(helper.FAN_CREATE, 12, "/media/u/STICK/Photos/2026/a.jpg")
    t.add(helper.FAN_MODIFY, 12, "/home/u/notes.txt")
    t.add(helper.FAN_CREATE | helper.FAN_MODIFY, 11, "/home/u/.cache/thumbnails/normal/abc.png")
    r = t.result()
    assert [f[0] for f in r["files"] if f[5]] == ["/home/u/.cache/thumbnails/normal/abc.png"] and r["others_left"] == 0
    assert r["others_folded"] == [["npm", "/home/u/project/node_modules", helper.WATCH_OTHERS_MAX + 10],
                                  ["cp", "/media/u/STICK/Photos", 1], ["cp", "/home/u", 1]]
    assert t.counts()["others"] == helper.WATCH_OTHERS_MAX + 13
    # past the limit, programs' data is counted per folder too, and said
    monkeypatch.setattr(helper, "WATCH_OTHERS_MAX", 2)
    t = helper._Tally(1000, "/home/u", ["daprivacyscanner-watch-abc.scope"], proc=lambda pid: procs.get(pid))
    for i in range(5):
        t.add(helper.FAN_CREATE, 11, f"/home/u/.cache/thumbnails/normal/{i}.png")
    r = t.result()
    assert len(r["files"]) == 2 and r["others_left"] == 3
    assert r["others_folded"] == [["tumblerd", "/home/u/.cache/thumbnails/normal", 3]]
    # the result shows them per program and folder, changes apart from files
    host = Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner(), uid=1000)
    home = str(tmp_path.resolve())
    raw = {"files": [[f"{home}/.cache/thumbnails/normal/0.png", helper.W_CREATED, 0, 1, 1, "tumblerd"]],
           "others_folded": [["npm", f"{home}/project/node_modules", 40], ["cp", "", 2]], "others_left": 2}
    out = appwatch.report(host, menu.App("x.desktop", "X", ["x"], "native"), raw, {})
    assert out["others"] == 1 and out["others_changes"] == 42 and out["others_left"] == 2
    assert out["others_places"][0] == {"who": "npm", "folder": "~/project/node_modules", "files": 0, "changes": 40}
    assert {"who": "cp", "folder": "", "files": 0, "changes": 2} in out["others_places"]
    js = (Path(__file__).parent.parent / "src/daprivacyscanner/web/app.js").read_text()
    assert "r.others_left ?" in js and "o.changes" in js


MOUNTS = [
    {"dev": "252:1", "root": "/", "mount": "/", "fstype": "ext4", "source": "/dev/mapper/vgmint-root"},
    {"dev": "0:30", "root": "/", "mount": "/dev/shm", "fstype": "tmpfs", "source": "tmpfs"},
    {"dev": "0:50", "root": "/", "mount": "/run/user/1000", "fstype": "tmpfs", "source": "tmpfs"},
    {"dev": "8:17", "root": "/", "mount": "/home/u/Data", "fstype": "ext4", "source": "/dev/sdb1"},
    {"dev": "0:60", "root": "/", "mount": "/home/u/.cache/thumbnails", "fstype": "tmpfs", "source": "tmpfs"},
    {"dev": "0:61", "root": "/", "mount": "/home/u/RAMDisk", "fstype": "tmpfs", "source": "tmpfs"},
    {"dev": "0:62", "root": "/", "mount": "/run/user/1000/doc", "fstype": "fuse.portal", "source": "portal"},
    {"dev": "0:63", "root": "/", "mount": "/tmp/.mount_DAPrivXy", "fstype": "fuse.DAPrivacyKit", "source": "x"},
    {"dev": "0:27", "root": "/", "mount": "/run/media/u/POOL", "fstype": "btrfs", "source": "/dev/sdc1"},
    {"dev": "0:27", "root": "/photos", "mount": "/home/u/Photos", "fstype": "btrfs", "source": "/dev/sdc1"},
    {"dev": "0:28", "root": "/", "mount": "/run/daprivacyscanner-watch/0", "fstype": "btrfs", "source": "/dev/sda3"},
    {"dev": "0:28", "root": "/@home", "mount": "/home/other", "fstype": "btrfs", "source": "/dev/sda3"},
]


def test_whats_mounted_in_the_home_and_the_runtime_folder_is_watched_or_said_not_to_be(monkeypatch):
    """A disk at ~/Data, a tmpfs at ~/.cache/thumbnails (the app's own fix), ~/RAMDisk and the document portal were
    neither watched nor listed as not watched (D7)."""
    monkeypatch.setattr(helper, "_watch_mountinfo", lambda: MOUNTS)
    plan, skipped = helper._watch_plan(1000, "/home/u")
    mounts = {p["mount"]: p for p in plan}
    assert {"/home/u/Data", "/home/u/.cache/thumbnails", "/home/u/RAMDisk", "/run/user/1000/doc",
            "/tmp/.mount_DAPrivXy"} <= set(mounts) and not skipped
    assert all(p["dev"] for p in plan) and len({p["dev"] for p in plan}) == len(plan)
    # a btrfs whose top level the system mounted is looked through there; its own private mount is never planned
    pool = next(p for p in plan if p["dev"] == "0:27")
    assert pool["top"] and pool["at"] == "/run/media/u/POOL" and ["/photos", "/home/u/Photos"] in pool["subvolumes"]
    assert "0:28" not in {p["dev"] for p in plan}                 # /home/other isn't the caller's; ours is filtered
    why = helper._watch_why(mounts["/run/user/1000/doc"], 1000, OSError(13, "Permission denied"))
    assert "document portal" in why and "aren't counted as the app's" in why
    assert "AppImage" in helper._watch_why(mounts["/tmp/.mount_DAPrivXy"], 1000, OSError(13, "Permission denied"))
    assert helper._watch_why(mounts["/home/u/Data"], 1000, OSError(22, "no")) == "no (EINVAL)"


def test_a_btrfs_looked_through_its_system_mount_maps_paths_back():
    w = helper._Watched.__new__(helper._Watched)
    w.strip, w.fs = "/", {"subvolumes": [["/@home", "/home"], ["/", "/"]]}
    assert w._mapped("/@home/u/x") == "/home/u/x" and w._mapped("/etc/fstab") == "/etc/fstab"
    w.strip, w.fs = "/run/media/u/POOL", {"subvolumes": [["/photos", "/home/u/Photos"], ["/", "/run/media/u/POOL"]]}
    assert w._mapped("/run/media/u/POOL/photos/a.jpg") == "/home/u/Photos/a.jpg"
    assert w._mapped("/run/media/u/POOL/other/b") == "/run/media/u/POOL/other/b"


def test_a_disks_mount_isnt_held_open_and_one_replaced_isnt_looked_through(tmp_path):
    """A descriptor of each disk's mount was held for the whole watch: the disk couldn't be unmounted until it ended.
    It is opened for each look-up now, and only while it is still that filesystem."""
    import os
    w = helper._Watched.__new__(helper._Watched)
    w.mfd, w.at, w.dev = -1, str(tmp_path), os.stat(tmp_path).st_dev
    fd = w._mount_fd()
    assert fd >= 0
    os.close(fd)
    w.dev = w.dev + 1                                             # something else is mounted there now
    assert w._mount_fd() == -1
    w.at = str(tmp_path / "gone")
    assert w._mount_fd() == -1


class FakeWatched:
    closed: list = []

    def __init__(self, libc, fs, index, private=True):
        if fs["fstype"].startswith("fuse"):
            raise OSError(13, "Permission denied")
        self.fs, self.paths, self.fan, self.dirs = fs, {"x": "y"}, index + 100, -1

    def close(self):
        FakeWatched.closed.append(self.fs["mount"])


def test_a_disk_mounted_during_the_watch_is_watched_and_one_unmounted_let_go(monkeypatch):
    """Mounts added mid-watch weren't watched, nor listed (D7). The mount table is read again every few seconds."""
    table = [dict(m) for m in MOUNTS[:3]]
    monkeypatch.setattr(helper, "_watch_mountinfo", lambda: table)
    monkeypatch.setattr(helper, "_Watched", FakeWatched)
    FakeWatched.closed = []
    fss = helper._Filesystems(None, 1000, "/home/u", True)
    fss.add(*helper._watch_plan(1000, "/home/u"))
    assert fss.names() == {"watched": ["/", "/dev/shm", "/run/user/1000"], "skipped": []}
    table += [MOUNTS[5], MOUNTS[6]]                               # ~/RAMDisk opened, a Flatpak app's portal
    fss.replan()
    names = fss.names()
    assert names["watched"][-1] == "/home/u/RAMDisk"
    assert names["skipped"] == [["/run/user/1000/doc", helper._watch_why(MOUNTS[6], 1000, OSError(13, "x"))
                                 + ", mounted during the watch"]]
    fss.replan()                                                  # nothing new: nothing added twice
    assert fss.names() == names and len(fss.watched) == 4
    del table[3]                                                  # ~/RAMDisk closed: let go, still named as watched
    fss.replan()
    assert FakeWatched.closed == ["/home/u/RAMDisk"] and len(fss.watched) == 3
    assert "/home/u/RAMDisk" in fss.names()["watched"]
    table.insert(3, dict(MOUNTS[5], dev="0:70"))                  # opened again: watched again
    fss.replan()
    assert len(fss.watched) == 4


def test_the_result_and_the_page_follow_the_filesystems_watched(tmp_path):
    host = Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner(), uid=1000)
    raw = {"files": [], "watched": ["/", "/home/u/RAMDisk"], "skipped": [["/run/user/1000/doc", "the portal"]]}
    out = appwatch.report(host, menu.App("x.desktop", "X", ["x"], "native"), raw, {"watched": ["/"], "skipped": []})
    assert out["watched"] == ["/", "/home/u/RAMDisk"] and out["not_watched"] == [["/run/user/1000/doc", "the portal"]]
    assert any("document portal" in t for t in appwatch.LIMITS)
    src = (Path(__file__).parent.parent / "src/daprivacyscanner/server.py").read_text()
    assert 'job["not_watched"] = job["counts"].pop("skipped", [])' in src


def test_a_file_written_through_memory_counts_as_changed_by_its_date(tmp_path):
    """A memory map's writes make no fanotify event: SQLite's -shm the app had open showed as only read (the
    suspicion, confirmed). Its date moved during the watch: counted as changed, and searched for records."""
    import os
    home = tmp_path / "home"
    (home / ".config/Foo").mkdir(parents=True)
    (home / "Documents").mkdir()
    shm = home / ".config/Foo/history.sqlite-shm"
    shm.write_bytes(b"\0" * 32)
    doc = home / "Documents/letter.odt"
    doc.write_text("x")
    old = home / ".config/Foo/settings.ini"
    old.write_text("x")
    since = time.time() - 5
    os.utime(old, (since - 100, since - 100))
    recs = [[str(shm), A.OPENED, 1, 0, 0, ""], [str(doc), A.OPENED, 1, 0, 0, ""], [str(old), A.OPENED, 1, 0, 0, ""]]
    w = A.Where(str(home), 1000)
    assert appwatch._changed_by_date(recs, w, since) == 1
    assert recs[0][1] == A.OPENED | A.WRITTEN | A.MAPPED and recs[1][1] == recs[2][1] == A.OPENED
    s = A.summarise(recs, w, 600)
    assert s["totals"]["written"] == 1 and s["totals"]["opened"] == 2
    assert A._did(recs[0][1]) == "changed (by its date)"


def test_gvfs_metadata_written_through_memory_is_searched_for_what_it_gained(tmp_path):
    """gvfsd-metadata writes its journal through a memory map: no event, nor always a newer date (a second `gio set`
    during a watch on Mint left neither), so its files never reached the search. Compared with a snapshot taken as
    the watch began, the paths whose entries grew are what was recorded meanwhile."""
    home, w = _home(tmp_path)
    folder = home / ".local/share/gvfs-metadata"
    journal = folder / "home-caaaa677.log"
    journal.write_bytes(_gvfs_journal(["/Documents/old.txt", "/Documents/again.txt"]))
    before = A.gvfs_snapshot(str(folder), b"k" * 16)
    assert before["files"] == [str(journal)] and len(before["entries"]) == 2 and "old.txt" not in repr(before)
    journal.write_bytes(_gvfs_journal(["/Documents/old.txt", "/Documents/again.txt", "/Documents/new.txt",
                                       "/Documents/again.txt"]))
    recs = [[f"{home}/Documents/{n}", A.OPENED, 1, 0, 0, ""] for n in ("old.txt", "again.txt", "new.txt")]
    r = A.find_records(recs, w, gvfs=before)                    # no record of the journal being written
    assert r["found"] == [{"path": "~/.local/share/gvfs-metadata/home-caaaa677.log", "who": "gvfsd-metadata",
                           "names": 2, "type": "the desktop's notes on files (GVFS metadata, its journal)"}]
    assert not A.find_records(recs, w)["found"]                # without the snapshot: never searched


def test_the_helper_ends_a_watch_when_its_input_ends(monkeypatch):
    """Dropping the access (or the app going) closes the helper's input: the watch ends through its clean-up."""
    import io
    import sys
    ended = []
    monkeypatch.setattr(helper, "_no_dumps", lambda: None)
    monkeypatch.setattr(helper, "own_source", lambda: None)
    monkeypatch.setattr(helper, "_watch_forget", lambda: ended.append(True))
    monkeypatch.setattr(helper, "_WATCH", {"proc": object(), "uid": 1000})
    monkeypatch.setattr(sys, "argv", ["helper.py"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    helper.main()
    assert ended == [True]
