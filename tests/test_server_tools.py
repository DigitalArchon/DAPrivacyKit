"""The Tools panel's API: listing, the file dialog, Verify a download, Remove metadata and the RAM
disk (through the real helper code against a fixture tree, with fake mount calls)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper
from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import ramdisk as R

from fakes import FakeSystem

H = {"X-Token": "t0ken"}
SAMPLES = Path(__file__).parent / "samples" / "verify"


def app_for(cat, host, **kw):
    return TestClient(create_app("t0ken", cat, make_host=lambda: host, **kw))


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    (home / "Downloads").mkdir(parents=True)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", root / "proc/mounts")
    (root / "proc/meminfo").write_text("MemTotal: 8000000 kB\n")
    return Host(home=home, environ={"HOME": str(home)}, runner=FakeRunner(), root=root, uid=os.getuid())


def test_tools_list(cat, host):
    d = app_for(cat, host).get("/api/tools", headers=H).json()
    assert [t["id"] for t in d["tools"]] == ["verify", "metadata", "ramdisk", "browser", "trial", "keeps", "trim", "names", "handover",
                                             "retire", "travel", "presentation", "inuse"]
    assert set(d["features"]) == {"net.outgoing_firewall", "desk.ephemeral_folder", "desk.file_manager_actions",
                                  "app.metadata_outbox", "app.boxes"}
    assert d["can_pick"] is False and d["ramdisk"]["open"] is False and d["ramdisk"]["max_mb"] == 3906
    # the panel's groups, in order, and every tool in one, with a one-line summary for its tile
    assert [g["id"] for g in d["groups"]] == ["files", "memory", "apps", "drives", "everyday"]
    assert all(t["group"] in {g["id"] for g in d["groups"]} and 0 < len(t["short"]) < len(t["text"]) for t in d["tools"])
    assert d["browser_disk"] is False


def test_pick_uses_the_window_dialog_or_says_there_is_none(cat, host):
    assert app_for(cat, host).post("/api/tools/pick", headers=H, json={}).json() == {"unavailable": True, "paths": []}
    seen = []
    c = app_for(cat, host, pick=lambda kind, multiple, start: seen.append((multiple, start)) or ["/x/a.iso"])
    assert c.post("/api/tools/pick", headers=H, json={"multiple": True}).json() == {"paths": ["/x/a.iso"]}
    assert seen == [(True, str(host.home))]


def test_open_tool_is_given_to_the_page_once(cat, host):
    c = app_for(cat, host, open_tool={"tool": "verify", "paths": ["/x/a.iso"]})
    assert c.get("/api/state", headers=H).json()["open_tool"] == {"tool": "verify", "paths": ["/x/a.iso"]}
    assert c.get("/api/state", headers=H).json()["open_tool"] is None


def test_verify_checks_the_path_it_is_given(cat, host):
    c = app_for(cat, host)
    for bad in ("relative.iso", "/proc/self/status", str(host.home / "missing.iso"), ""):
        r = c.post("/api/tools/verify", headers=H, json={"path": bad})
        assert r.status_code == 400, bad
    f = host.home / "Downloads" / "notes.txt"
    f.write_text("hello\n")
    v = c.post("/api/tools/verify", headers=H, json={"path": "~/Downloads/notes.txt",
                                                     "expected": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"}).json()["verdict"]
    assert v["level"] == "intact" and v["path"] == "~/Downloads/notes.txt"


def follow(c, path="/api/tools/metadata/job"):
    for _ in range(500):
        job = c.get(path, headers=H).json()["job"]
        if job["state"] != "running":
            return job
        time.sleep(0.01)
    raise AssertionError("still running")


def test_metadata_show_read_and_clean_files_and_folders(cat, host):
    f = host.home / "photo.jpg"
    f.write_bytes(b"img")
    (host.home / "Trip/Day 2").mkdir(parents=True)
    (host.home / "Trip/a.jpg").write_bytes(b"a")
    (host.home / "Trip/Day 2/b.jpg").write_bytes(b"b")

    def mat2(argv):
        files = argv[argv.index("--") + 1:] if "--" in argv else []
        if argv[1] == "--list":
            return CommandResult(argv, 0, "  - image/jpeg (.jpeg, .jpg)\n")
        if argv[1] == "--show":
            return CommandResult(argv, 0, "".join(f"[+] Metadata for {x}:\n    GPSLatitude: 47 N\n" for x in files))
        for x in files:
            Path(x).with_name(Path(x).stem + ".cleaned.jpg").write_bytes(b"clean")
        return CommandResult(argv, 0, "")
    host.runner.handlers["mat2"] = mat2
    with TestClient(create_app("t0ken", cat, make_host=lambda: host)) as c:
        files = c.post("/api/tools/metadata/show", headers=H, json={"paths": [str(f)]}).json()["files"]
        assert files[0]["groups"][0]["id"] == "location"
        # a folder isn't one file to show, but can be read and cleaned
        assert c.post("/api/tools/metadata/show", headers=H, json={"paths": [str(host.home / "Trip")]}).status_code == 400
        assert c.post("/api/tools/metadata/read", headers=H, json={"paths": ["/proc/self"]}).status_code == 400
        c.post("/api/tools/metadata/read", headers=H, json={"paths": [str(f), "~/Trip"]})
        job = follow(c)
        assert job["state"] == "done" and job["selection"]["folders"] == ["~/Trip"]
        assert [(x["rel"], x["cleanable"], x["groups"][0]["id"]) for x in job["result"]["files"]] == [
            ("photo.jpg", True, "location"), ("a.jpg", True, "location"), ("Day 2/b.jpg", True, "location")]
        assert c.post("/api/tools/metadata/clean", headers=H, json={"paths": [str(f)], "files": []}).status_code == 400
        # only the ticked ones
        c.post("/api/tools/metadata/clean", headers=H, json={"paths": [str(f), "~/Trip"],
                                                             "files": [str(f), str(host.home / "Trip/Day 2/b.jpg")]})
        job = follow(c)
        res = job["result"]
        assert job["state"] == "done" and res["cleaned"] == 2 and res["failed"] == 0
        assert (host.home / "photo.cleaned.jpg").exists() and f.read_bytes() == b"img"
        assert (host.home / "Trip (cleaned)/Day 2/b.jpg").exists() and not (host.home / "Trip (cleaned)/a.jpg").exists()
        assert res["folders"] == [{"folder": "~/Trip", "output": "~/Trip (cleaned)",
                                   "output_path": str(host.home / "Trip (cleaned)")}]
        assert all(r["remaining"]["count"] == 1 for r in res["results"])
        opened = []
        host.runner.handlers["xdg-open"] = lambda argv: opened.append(argv[1]) or CommandResult(argv, 0, "")
        assert c.post("/api/tools/metadata/open", headers=H, json={"folder": str(host.home)}).json() == {"ok": True}
        assert c.post("/api/tools/metadata/open", headers=H, json={"folder": "/etc"}).status_code == 400
        assert opened == [str(host.home)]


def test_a_file_name_that_isnt_utf8_goes_to_the_page_and_back(cat, host):
    """Linux allows any bytes in a name; the page gets it escaped and sends the same path back."""
    import json as J
    trip = host.home / "Trip"
    trip.mkdir()
    bad = os.path.join(os.fsencode(trip), b"bad\xffname.jpg")
    with open(bad, "wb") as f:
        f.write(b"img")
    name = os.fsdecode(bad)

    def mat2(argv):
        files = argv[argv.index("--") + 1:] if "--" in argv else []
        if argv[1] == "--list":
            return CommandResult(argv, 0, "  - image/jpeg (.jpeg, .jpg)\n")
        if argv[1] == "--show":
            return CommandResult(argv, 0, "".join(f"[+] Metadata for {x}:\n    Artist: Al\n" for x in files))
        for x in files:
            Path(x).with_name(Path(x).stem + ".cleaned.jpg").write_bytes(b"clean")
        return CommandResult(argv, 0, "")
    host.runner.handlers["mat2"] = mat2
    with TestClient(create_app("t0ken", cat, make_host=lambda: host)) as c:
        c.post("/api/tools/metadata/read", headers=H, json={"paths": ["~/Trip"]})
        r = c.get("/api/tools/metadata/job", headers=H)
        for _ in range(500):
            if r.json()["job"]["state"] != "running":
                break
            time.sleep(0.01)
            r = c.get("/api/tools/metadata/job", headers=H)
        assert r.status_code == 200 and r.content.isascii()
        f = J.loads(r.content)["job"]["result"]["files"][0]
        assert f["path"] == name and f["groups"][0]["id"] == "people"          # the same surrogate, back in Python
        # what the page sends back names the file
        body = J.dumps({"paths": [f["path"]]})
        assert c.post("/api/tools/metadata/show", headers={**H, "Content-Type": "application/json"},
                      content=body).json()["files"][0]["count"] == 1
        c.post("/api/tools/metadata/clean", headers={**H, "Content-Type": "application/json"},
               content=J.dumps({"paths": ["~/Trip"], "files": [f["path"]]}))
        job = follow(c)
        assert job["result"]["cleaned"] == 1
        assert os.path.exists(os.path.join(os.fsencode(host.home), b"Trip (cleaned)", b"bad\xffname.jpg"))


@pytest.fixture
def mounting(host, monkeypatch):
    root = host.root
    monkeypatch.setattr(helper, "ROOT", str(root))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    monkeypatch.setattr(helper, "CALLER", (os.geteuid(), os.getegid(), "/home/alice"))
    monkeypatch.setattr(helper, "_kernel_has_noswap", lambda release=None: True)

    def mount(target, flags, options):
        real = os.path.realpath(target)
        with open(root / "proc/self/mounts", "a") as f:
            f.write(f"tmpfs {real[len(str(root)):]} tmpfs rw,{options} 0 0\n")
        return 0

    def umount(target):
        lines = (root / "proc/self/mounts").read_text().splitlines()
        (root / "proc/self/mounts").write_text("".join(ln + "\n" for ln in lines if " /home/alice/RAMDisk " not in ln))
        return 0
    monkeypatch.setattr(helper, "MOUNT", mount)
    monkeypatch.setattr(helper, "UMOUNT", umount)
    return FakePrivileged()


def test_ramdisk_open_and_close_overwrites_first(cat, host, mounting, monkeypatch):
    c = app_for(cat, host, start_helper=lambda: mounting)
    assert c.post("/api/tools/ramdisk/open", headers=H, json={"size_mb": 10}).status_code == 400
    r = c.post("/api/tools/ramdisk/open", headers=H, json={"size_mb": 256, "noexec": True}).json()
    assert r["ramdisk"]["open"] and r["ramdisk"]["noswap"] and r["admin_active"]
    disk = host.home / "RAMDisk"
    disk.chmod(0o700)                                  # the tmpfs's own root (the fake mount doesn't make one)
    (disk / "secret.txt").write_text("secret")
    monkeypatch.setattr(R, "users_of", lambda host, path: ["libreoffice"])
    r = c.post("/api/tools/ramdisk/close", headers=H)
    assert r.status_code == 409 and "Close libreoffice first" in r.json()["error"]
    assert (disk / "secret.txt").read_text() == "secret"            # nothing touched
    monkeypatch.setattr(R, "users_of", lambda host, path: [])
    wiped = []
    real_wipe = R.wipe
    monkeypatch.setattr(R, "wipe", lambda path, **kw: wiped.append((path / "secret.txt").read_text()) or real_wipe(path, **kw))
    r = c.post("/api/tools/ramdisk/close", headers=H).json()
    assert r["wiped"]["files"] == 1 and not r["ramdisk"]["open"] and wiped == ["secret"]
    assert [a for a, _ in mounting.calls] == ["ramdisk_open", "ramdisk_close"]
    assert not disk.exists()


def test_ramdisk_open_declined(cat, host):
    from daprivacyscanner.privileged import HelperDeclined

    def declined():
        raise HelperDeclined("no")
    r = app_for(cat, host, start_helper=declined).post("/api/tools/ramdisk/open", headers=H, json={"size_mb": 256})
    assert r.status_code == 403 and r.json()["declined"]


def test_api_answers_are_never_cached_and_errors_say_no_paths(cat, host, monkeypatch, capsys):
    """In --browser mode the user's browser kept a JSON answer in its disk cache (tested with Firefox): every API
    answer is no-store. An error nothing caught reaches the page by its kind, and stderr (a log on the disk for an app
    started from the menu) only its kind and route: never its message, which can name a file."""
    from daprivacyscanner.tools import browser as B
    c = app_for(cat, host)
    r = c.get("/api/tools", headers=H)
    assert r.headers["cache-control"] == "no-store"

    def broken(h):
        raise OSError(2, "No such file", "/home/alice/TempBrowser/tor-browser/Browser/Downloads/secret-name.pdf")
    monkeypatch.setattr(B, "status", broken)
    r = c.get("/api/tools/browser", headers=H)
    assert r.status_code == 500 and "FileNotFoundError" in r.json()["error"] and "secret" not in r.text
    assert r.headers["cache-control"] == "no-store"
    err = capsys.readouterr().err
    assert "GET /api/tools/browser: FileNotFoundError" in err and "secret" not in err
