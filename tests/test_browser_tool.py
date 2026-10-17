"""Tor Browser or Mullvad Browser in the RAM disk: the project's index read and checked, the archive
downloaded into the RAM disk (through FakeNet: the suite never goes online), refused unless verified,
unpacked safely, and started with its caches inside the RAM disk."""

from __future__ import annotations

import io
import json
import shutil
import os
import tarfile
import time

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner.online import FakeNet, HttpResult
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import ramdisk as R

from test_server_tools import H, app_for, host  # noqa: F401 - the fixture

INDEX = "https://aus1.torproject.org/torbrowser/update_3/release/download-linux-x86_64.json"
ARCHIVE = "https://dist.torproject.org/torbrowser/15.0.24/tor-browser-linux-x86_64-15.0.24.tar.xz"


def index(binary=ARCHIVE, sig=None):
    return HttpResult(200, json.dumps({"version": "15.0.24", "binary": binary, "sig": sig or binary + ".asc"}).encode())


def tarball(entries: dict) -> bytes:
    """A .tar.xz: name -> bytes (a file, executable when the name ends in start-*), None (a folder),
    or ("link", target)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o700
                tar.addfile(info)
            elif isinstance(data, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, data[1]
                tar.addfile(info)
            else:
                info.size, info.mode = len(data), 0o700 if "start-" in name else 0o600
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TOR = {"tor-browser": None, "tor-browser/Browser": None, "tor-browser/Browser/start-tor-browser": b"#!/bin/sh\n",
       "tor-browser/Browser/firefox.real": b"\x7fELF", "tor-browser/Browser/TorBrowser/Data/x.txt": b"data",
       "tor-browser/Browser/tbb_version.json": b'{"version":"15.0.24","architecture":"linux-x86_64","channel":"release"}'}


def mullvad(version="15.0.24"):
    return {"mullvad-browser/Browser/start-mullvad-browser": b"#!/bin/sh\n",
            "mullvad-browser/Browser/version.json": json.dumps({"version": version}).encode()}


def open_ramdisk(host, noexec=False, name="TempBrowser"):
    """The browser's RAM disk (or the RAM disk tool's), open: a folder and a tmpfs in the mount table."""
    disk = host.home / name
    disk.mkdir(exist_ok=True)
    with open(host.root / "proc/self/mounts", "a") as f:
        f.write(f"tmpfs /home/alice/{name} tmpfs rw,nosuid,nodev,{'noexec,' if noexec else ''}size=1536M,noswap 0 0\n")
    return disk


@pytest.fixture
def x86(monkeypatch):
    monkeypatch.setattr(B.platform, "machine", lambda: "x86_64")


def signed_at(archive) -> int | None:
    """The date in the signature beside `archive` (what the real verified() gets from gpgv for the verified one)."""
    from daprivacyscanner.tools import keys as K
    try:
        return K.signature_created(archive.with_name(archive.name + ".asc").read_bytes())
    except (OSError, K.PacketError):
        return None


def good(monkeypatch):
    monkeypatch.setattr(B, "verified", lambda host, archive: {"title": "Verified: made by Tor Browser Developers",
                                                              "fingerprint": "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290",
                                                              "signer": "Tor Browser Developers",
                                                              "signed": signed_at(archive)})


# ------------------------------------------------------------------ the index

def test_the_index_is_checked_before_anything_is_downloaded():
    tor = B.BROWSERS["tor"]
    assert B.release(FakeNet(http={INDEX: index()}), tor, "linux-x86_64")[0] == "15.0.24"
    for bad in (index(binary="https://evil.example/tor-browser-linux-x86_64-15.0.24.tar.xz"),
                index(binary=ARCHIVE.replace("https", "http")),
                index(binary=ARCHIVE.replace("15.0.24.tar.xz", "15.0.24.tar.xz;rm")),
                index(sig="https://dist.torproject.org/other.asc"), HttpResult(200, b"not json")):
        with pytest.raises(B.BrowserError):
            B.release(FakeNet(http={INDEX: bad}), tor, "linux-x86_64")


def test_ready_needs_an_open_ramdisk_that_runs_programs(host):  # noqa: F811
    assert "Open the browser's RAM disk (~/TempBrowser) first" in B.ready(host)
    open_ramdisk(host, name="RAMDisk")                        # the RAM disk tool's: not the browser's
    assert "Open the browser's RAM disk" in B.ready(host)
    open_ramdisk(host, noexec=True)
    assert "programs not allowed" in B.ready(host)


# ------------------------------------------------------------------ download, verify, unpack

def test_download_goes_into_the_ramdisk(host, x86):  # noqa: F811
    disk = open_ramdisk(host)
    net = FakeNet(http={INDEX: index()}, files={ARCHIVE: tarball(TOR), ARCHIVE + ".asc": b"-----BEGIN PGP SIGNATURE-----"})
    job = {}
    archive = B.download(host, net, B.BROWSERS["tor"], job, lambda: False)
    assert archive == disk / ".downloads/tor-browser-linux-x86_64-15.0.24.tar.xz" and archive.exists()
    assert archive.with_name(archive.name + ".asc").exists() and job["version"] == "15.0.24"
    assert net.contacted == [INDEX, ARCHIVE + ".asc", ARCHIVE]


def test_a_failed_download_leaves_nothing(host, x86):  # noqa: F811
    disk = open_ramdisk(host)
    net = FakeNet(http={INDEX: index()}, files={ARCHIVE + ".asc": b"sig", ARCHIVE: HttpResult(None, b"", "reset")})
    with pytest.raises(B.BrowserError, match="couldn't be downloaded"):
        B.download(host, net, B.BROWSERS["tor"], {}, lambda: False)
    assert not list((disk / ".downloads").iterdir())                 # not even the signature that did arrive


def test_unpack_puts_it_in_the_ramdisk(host):  # noqa: F811
    disk = open_ramdisk(host)
    archive = disk / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    archive.write_bytes(tarball(TOR))
    target = B.unpack(host, archive, B.BROWSERS["tor"], {})
    assert target == disk / "tor-browser" and (target / "Browser/TorBrowser/Data/x.txt").read_bytes() == b"data"
    assert os.stat(target / "Browser/start-tor-browser").st_mode & 0o777 == 0o700
    assert os.stat(target / "Browser/TorBrowser/Data/x.txt").st_mode & 0o777 == 0o600
    assert B.installed(host, B.BROWSERS["tor"])
    with pytest.raises(B.BrowserError, match="already there"):
        B.unpack(host, archive, B.BROWSERS["tor"], {})


@pytest.mark.parametrize("extra", [{"tor-browser/../../escape": b"x"}, {"/etc/evil": b"x"},
                                   {"tor-browser/Browser/link": ("link", "/home/alice/.bashrc")},
                                   {"other-folder/x": b"x"}])
def test_unpack_refuses_anything_outside_its_folder(host, extra):  # noqa: F811
    disk = open_ramdisk(host)
    archive = disk / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    archive.write_bytes(tarball({**TOR, **extra}))
    with pytest.raises(B.BrowserError, match="not unpacked"):
        B.unpack(host, archive, B.BROWSERS["tor"], {})
    assert not (disk / "tor-browser").exists() and not list(disk.glob(".tor-browser*"))


def test_an_old_release_renamed_as_the_latest_is_not_unpacked(host):  # noqa: F811
    """A signed old release passes the signature check; renamed as the latest, it would pass the check
    for a newer version too. What is inside says which it is."""
    disk = open_ramdisk(host)
    archive = disk / "mullvad-browser-linux-x86_64-15.0.24.tar.xz"
    archive.write_bytes(tarball(mullvad("14.5.1")))
    with pytest.raises(B.BrowserError, match="says it is version 15.0.24, but what is inside is version 14.5.1"):
        B.unpack(host, archive, B.BROWSERS["mullvad"], {})
    archive.write_bytes(tarball({"mullvad-browser/Browser/start-mullvad-browser": b"#!/bin/sh\n"}))
    with pytest.raises(B.BrowserError, match="of no version the app can read"):
        B.unpack(host, archive, B.BROWSERS["mullvad"], {})
    assert not (disk / "mullvad-browser").exists()


def test_a_picked_archive_is_copied_in_before_it_is_checked(host):  # noqa: F811
    disk = open_ramdisk(host)
    mine = host.home / "Downloads/tor-browser-linux-x86_64-15.0.24.tar.xz"
    mine.parent.mkdir(parents=True, exist_ok=True)
    mine.write_bytes(tarball(TOR))
    mine.with_name(mine.name + ".asc").write_bytes(b"sig")
    job = {}
    copy = B.copy_in(host, mine, job)
    assert copy == disk / ".downloads" / mine.name and copy.read_bytes() == mine.read_bytes()
    assert (disk / ".downloads" / (mine.name + ".asc")).read_bytes() == b"sig" and job["done"] == mine.stat().st_size + 3
    picked = mine.read_bytes()
    mine.write_bytes(b"changed afterwards")                          # what is checked and unpacked is the copy
    assert copy.read_bytes() == picked
    assert B.copy_in(host, copy, {}) == copy                          # already in the RAM disk: as it is


def test_verified_insists_on_the_tor_browser_key(host, monkeypatch, tmp_path):  # noqa: F811
    from daprivacyscanner.tools import verify as V
    f = tmp_path / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    f.write_bytes(b"x")
    monkeypatch.setattr(V, "verify", lambda *a, **k: V.Verdict(f, 1, "intact", "Intact only", "", signatures=[]))
    with pytest.raises(B.BrowserError, match="isn't verified"):
        B.verified(host, f)


def test_the_signature_s_date_is_the_verified_signature_s_own(host, monkeypatch, tmp_path):  # noqa: F811
    """A .asc can hold more than one signature packet, and one by an unknown key leaves gpgv's verdict on the real
    one as it is. So the date comes from the verified signature itself (gpgv's VALIDSIG), never from the first
    packet in the file: an old release with a fresh packet prepended would otherwise pass as recent."""
    from daprivacyscanner.tools import keys as K
    from daprivacyscanner.tools import verify as V
    f = tmp_path / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    f.write_bytes(b"x")
    old, fresh = int(time.time()) - 90 * 86400, int(time.time()) - 86400
    f.with_name(f.name + ".asc").write_bytes(signature(fresh) + signature(old))     # the fresh one first, by nobody
    tor = next(p for p in K.load() if p.id == "torbrowser")
    sig = V.Signature(f.with_name(f.name + ".asc"), f, "openpgp", "good", "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290",
                      project=tor, signed_at=old)
    monkeypatch.setattr(V, "verify", lambda *a, **k: V.Verdict(f, 1, "verified", "Verified", "", signatures=[sig]))
    assert B.verified(host, f)["signed"] == old
    with pytest.raises(B.BrowserError, match="signature was made 90 days ago"):
        B.accept_unchecked(f, B.BROWSERS["tor"], "Blocked.", old)
    with pytest.raises(B.BrowserError, match="dated in the future"):
        B.accept_unchecked(f, B.BROWSERS["tor"], "Blocked.", int(time.time()) + 3 * 86400)
    assert "1 day ago" in B.accept_unchecked(f, B.BROWSERS["tor"], "Blocked.", fresh)


def test_versions_are_ordered_as_the_projects_order_them():
    k = B._version_key
    assert k("15.0.24") > k("15.0.2") > k("15.0") > k("15.0b2") > k("15.0a1") > k("14.5.9")
    assert k("15.0a1") < k("15.0") and k("15.0") == k("15.0")


def test_start_points_caches_into_the_ramdisk(host):  # noqa: F811
    disk = open_ramdisk(host)
    (disk / "tor-browser/Browser").mkdir(parents=True)
    (disk / "tor-browser/Browser/start-tor-browser").write_text("#!/bin/sh\n")
    B.record_release(host, B.BROWSERS["tor"], disk / "tor-browser-linux-x86_64-15.0.24.tar.xz", "download")
    calls = []
    how = B.start(host, B.BROWSERS["tor"], spawn=lambda argv, **kw: calls.append((argv, kw)), sandboxed=False)
    [(argv, kw)] = calls
    assert argv == [str(disk / "tor-browser/Browser/start-tor-browser"), "--detach"] and not how["sandboxed"]
    for var in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "TMPDIR"):
        assert kw["env"][var].startswith(str(disk / ".tor-browser-session")) and os.path.isdir(kw["env"][var])
    assert kw["start_new_session"]


# ------------------------------------------------------------------ through the API

def client(cat, host, **kw):  # noqa: F811
    """A client that keeps one event loop running, so the background job advances between requests."""
    return TestClient(create_app("t0ken", cat, make_host=lambda: host, **kw))


def wait(c):
    for _ in range(200):
        job = c.get("/api/tools/browser", headers=H).json()["job"]
        if job and job["state"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError("the job didn't finish")


def test_the_whole_flow(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = open_ramdisk(host)
    net = FakeNet(http={INDEX: index()}, files={ARCHIVE: tarball(TOR), ARCHIVE + ".asc": b"sig"})
    spawned = []
    with client(cat, host, make_net=lambda: net, spawn_browser=lambda argv, **kw: spawned.append(argv)) as c:
        flow(c, disk, spawned)


def flow(c, disk, spawned):
    d = c.get("/api/tools/browser", headers=H).json()
    assert [b["id"] for b in d["browsers"]] == ["tor", "mullvad"] and d["browsers"][0]["hosts"] == \
        ["aus1.torproject.org", "dist.torproject.org"]
    assert c.post("/api/tools/browser/get", headers=H, json={"browser": "chrome"}).status_code == 400
    assert c.post("/api/tools/browser/get", headers=H, json={"browser": "tor"}).json()["job"]["hosts"]
    job = wait(c)
    assert job["state"] == "done" and job["version"] == "15.0.24" and job["verdict"]["signer"] == "Tor Browser Developers"
    assert (disk / "tor-browser/Browser/start-tor-browser").exists()
    assert not list((disk / ".downloads").iterdir())                 # the archive gave its memory back
    d = c.get("/api/tools/browser", headers=H).json()
    assert d["browsers"][0]["installed"] and not d["browsers"][0]["running"]
    r = c.post("/api/tools/browser/start", headers=H, json={"browser": "tor"})       # no bubblewrap here
    assert r.status_code == 409 and "Untick" in r.json()["error"] and not spawned
    assert c.post("/api/tools/browser/start", headers=H, json={"browser": "tor", "sandbox": False}).status_code == 200
    assert spawned and spawned[0][-1] == "--detach"


def test_the_graphics_card_only_when_the_page_asks_for_it(cat, host, monkeypatch):  # noqa: F811
    asked = []
    monkeypatch.setattr(B, "start", lambda *a: asked.append(a[-1]) or {"sandboxed": True, "gpu": a[-1]})
    with client(cat, host) as c:
        for gpu in (None, False, "yes", 1, True):
            body = {"browser": "mullvad"} | ({} if gpu is None else {"gpu": gpu})
            assert c.post("/api/tools/browser/start", headers=H, json=body).status_code == 200
    assert asked == [False, False, False, False, True]


def test_an_unverified_download_is_removed(cat, host, x86, monkeypatch):  # noqa: F811
    def bad(host, archive):
        raise B.BrowserError(f"{archive.name} isn't verified (Bad signature). It was not unpacked.")
    monkeypatch.setattr(B, "verified", bad)
    disk = open_ramdisk(host)
    net = FakeNet(http={INDEX: index()}, files={ARCHIVE: tarball(TOR), ARCHIVE + ".asc": b"sig"})
    with client(cat, host, make_net=lambda: net) as c:
        c.post("/api/tools/browser/get", headers=H, json={"browser": "tor"})
        job = wait(c)
    assert job["state"] == "failed" and "isn't verified" in job["error"]
    assert not (disk / "tor-browser").exists() and not list((disk / ".downloads").iterdir())


def test_an_archive_the_user_downloaded(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = open_ramdisk(host)
    mine = host.home / "Downloads/mullvad-browser-linux-x86_64-15.0.24.tar.xz"
    mine.write_bytes(tarball(mullvad()))
    (host.home / "Downloads/mullvad-browser-linux-x86_64-15.0.24.tar.xz.asc").write_bytes(b"sig")
    net = FakeNet(http={MULLVAD_INDEX: mullvad_index()})
    with client(cat, host, make_net=lambda: net) as c:
        r = c.post("/api/tools/browser/get", headers=H, json={"archive": str(mine)}).json()
        assert r["job"]["name"] == "Mullvad Browser" and r["job"]["source"] == "file"
        assert wait(c)["state"] == "done" and (disk / "mullvad-browser/Browser/start-mullvad-browser").exists()
        assert mine.exists() and mine.with_name(mine.name + ".asc").exists()     # the user's own files stay
        assert not list((disk / ".downloads").iterdir())             # the copy that was checked is gone
        assert net.contacted == [MULLVAD_INDEX]                      # only the index: is it the latest?
        other = host.home / "Downloads/firefox-130.tar.xz"
        other.write_bytes(b"x")
        assert c.post("/api/tools/browser/dismiss", headers=H).status_code == 200
        assert c.post("/api/tools/browser/get", headers=H, json={"archive": str(other)}).status_code == 400


def test_closing_the_ramdisk_names_the_browser(cat, host, monkeypatch):  # noqa: F811
    open_ramdisk(host)
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {123: "firefox.real", 124: "tor", 200: "vim"})
    monkeypatch.setattr(B, "_browser_tree", lambda host, procs=None: {123, 124})
    monkeypatch.setattr(B, "running", lambda host, b: [123] if b.id == "tor" else [])
    r = app_for(cat, host).post("/api/tools/ramdisk/close", headers=H, json={"disk": "browser"})
    assert r.status_code == 409 and r.json()["error"].startswith("Close Tor Browser, vim first")
    assert "~/TempBrowser" in r.json()["error"]


def test_quitting_closes_the_browsers_ramdisk_unless_the_browser_runs(host, monkeypatch):  # noqa: F811
    disk = open_ramdisk(host)
    (disk / "tor-browser").mkdir()
    (disk / "tor-browser/page.html").write_text("visited")
    calls = []

    class Helper:
        def call(self, action, args, timeout=None):
            calls.append((action, args))
            return {"closed": True}
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {7: "firefox.real"})
    monkeypatch.setattr(B, "_browser_tree", lambda host, procs=None: {7})
    monkeypatch.setattr(B, "running", lambda host, b: [7] if b.id == "tor" else [])
    assert "stays open: Tor Browser still uses it" in B.close_disk(host, Helper) and not calls
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {})
    monkeypatch.setattr(R, "users_of", lambda host, path: [])
    monkeypatch.setattr(B, "running", lambda host, b: [])
    msg = B.close_disk(host, Helper)
    assert calls == [("ramdisk_close", {"name": "TempBrowser"})] and "1 file overwritten" in msg
    assert not (disk / "tor-browser/page.html").exists()


def signature(created: int) -> bytes:
    """A v4 OpenPGP signature packet with only a creation time (enough for signature_created)."""
    hashed = bytes([5, 2]) + created.to_bytes(4, "big")
    body = bytes([4, 0, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed + (0).to_bytes(2, "big") + b"\xab\xcd" \
        + (8).to_bytes(2, "big") + b"\x01"
    return bytes([0xC2, len(body)]) + body


def test_the_index_and_the_archive_agree_on_the_version():
    assert B.version_of("tor-browser-linux-x86_64-15.0.24.tar.xz") == "15.0.24"
    with pytest.raises(B.BrowserError, match="says version 15.0.25"):
        B.release(FakeNet(http={INDEX: HttpResult(200, json.dumps({"version": "15.0.25", "binary": ARCHIVE,
                                                                    "sig": ARCHIVE + ".asc"}).encode())}),
                  B.BROWSERS["tor"], "linux-x86_64")


MULLVAD_INDEX = "https://cdn.mullvad.net/browser/update_responses/update_1/release/download-linux-x86_64.json"


def mullvad_index(version="15.0.24"):
    binary = f"https://cdn.mullvad.net/browser/{version}/mullvad-browser-linux-x86_64-{version}.tar.xz"
    return HttpResult(200, json.dumps({"version": version, "binary": binary, "sig": binary + ".asc"}).encode())


def set_up_tor(host, hours_ago=0, version="15.0.24", signed_days=3):
    disk = open_ramdisk(host)
    archive = disk / f"tor-browser-linux-x86_64-{version}.tar.xz"
    (disk / "tor-browser/Browser").mkdir(parents=True)
    (disk / "tor-browser/Browser/start-tor-browser").write_text("#!/bin/sh\n")
    archive.with_name(archive.name + ".asc").write_bytes(signature(int(time.time()) - signed_days * 86400))
    b = B.BROWSERS["tor"]
    B.record_release(host, b, archive, "download", signed=signed_at(archive))
    if hours_ago:
        d = json.loads((B.private_dir(host, b) / "release.json").read_text())
        d["unpacked"] = d["checked"] = int(time.time() - hours_ago * 3600)
        (B.private_dir(host, b) / "release.json").write_text(json.dumps(d))
    return b


def test_a_copy_without_its_record_does_not_start(host, x86):  # noqa: F811
    """Unpacked, but its set-up interrupted before the record was written: no record, no start (the record
    is what the freshness check and the card rest on)."""
    b = set_up_tor(host)
    (B.private_dir(host, b) / "release.json").unlink()
    with pytest.raises(B.BrowserError, match="isn't recorded.*set it up again"):
        B.start(host, b, spawn=lambda *a, **k: pytest.fail("started"), sandboxed=False)


def test_a_fresh_copy_starts_without_asking_anyone(host, x86):  # noqa: F811
    b = set_up_tor(host)
    info = B.release_info(host, b)
    assert info["version"] == "15.0.24" and not info["check_due"] and info["host"] == "aus1.torproject.org"
    assert info["check_from"] - info["unpacked"] == 24 * 3600
    calls = []
    B.start(host, b, spawn=lambda argv, **kw: calls.append(argv), sandboxed=False,
            net=lambda: pytest.fail("no network for a copy set up today"))
    assert calls


def test_after_a_day_a_newer_version_stops_the_start(host, x86):  # noqa: F811
    b = set_up_tor(host, hours_ago=25)
    assert B.release_info(host, b)["check_due"]
    newer = FakeNet(http={INDEX: HttpResult(200, json.dumps({
        "version": "15.0.25", "binary": ARCHIVE.replace("15.0.24", "15.0.25"),
        "sig": ARCHIVE.replace("15.0.24", "15.0.25") + ".asc"}).encode())})
    with pytest.raises(B.BrowserError, match="15.0.25 is out.*won't start.*Save what you need"):
        B.start(host, b, spawn=lambda *a, **k: pytest.fail("started"), sandboxed=False, net=lambda: newer)
    with pytest.raises(B.BrowserError, match="needs the network"):
        B.start(host, b, spawn=lambda *a, **k: pytest.fail("started"), sandboxed=False)
    same = FakeNet(http={INDEX: index()})
    calls = []
    B.start(host, b, spawn=lambda argv, **kw: calls.append(argv), sandboxed=False, net=lambda: same)
    assert calls and same.contacted == [INDEX]
    assert not B.release_info(host, b)["check_due"]                     # one check covers the next hour's starts


def test_where_the_index_is_blocked_a_recent_release_still_starts(host, x86):  # noqa: F811
    """The project's server blocked (censorship): a copy whose signature is less than RECENT_DAYS old starts, and
    its card says the check couldn't be made; an older one doesn't."""
    b = set_up_tor(host, hours_ago=25, signed_days=3)
    calls = []
    B.start(host, b, spawn=lambda argv, **kw: calls.append(argv), sandboxed=False, net=lambda: FakeNet())
    info = B.release_info(host, b)
    assert calls and info["unchecked"] and not info["check_due"]
    B._LAUNCHED.clear()
    shutil.rmtree(host.home / "TempBrowser")
    host.root.joinpath("proc/self/mounts").write_text("")
    b = set_up_tor(host, hours_ago=25, signed_days=40)
    with pytest.raises(B.BrowserError, match="couldn't be checked.*more than 30 days old.*doesn't start"):
        B.start(host, b, spawn=lambda *a, **k: pytest.fail("started"), sandboxed=False, net=lambda: FakeNet())


def test_a_release_signed_long_before_it_was_set_up_is_named(host):  # noqa: F811
    """Releases come every few weeks: one signed more than STALE_DAYS before it was set up is named on its card,
    even where the index agreed (an index and an archive both old, served by someone in the way)."""
    b = set_up_tor(host, signed_days=60)
    info = B.release_info(host, b)
    assert info["stale"] and info["signed_days"] == 60
    d = json.loads((B.private_dir(host, b) / "release.json").read_text())
    d["signed"] = d["unpacked"] - 10 * 86400
    (B.private_dir(host, b) / "release.json").write_text(json.dumps(d))
    assert not B.release_info(host, b)["stale"]


def test_a_picked_archive_signed_recently_is_accepted_where_the_index_is_blocked(cat, host, x86, monkeypatch):  # noqa: F811
    """GetTor's users: the project's server can't be reached, so whether it is the latest can't be checked. Once
    its signature is verified, one made in the last RECENT_DAYS is accepted with a warning; an older one isn't."""
    good(monkeypatch)
    disk = open_ramdisk(host)
    mine = host.home / "Downloads/mullvad-browser-linux-x86_64-15.0.24.tar.xz"
    mine.parent.mkdir(parents=True, exist_ok=True)
    mine.write_bytes(tarball(mullvad("15.0.24")))
    mine.with_name(mine.name + ".asc").write_bytes(signature(int(time.time()) - 40 * 86400))
    with client(cat, host, make_net=lambda: FakeNet()) as c:
        c.post("/api/tools/browser/get", headers=H, json={"archive": str(mine)})
        job = wait(c)
    assert job["state"] == "failed" and "signature was made 40 days ago" in job["error"]
    assert not (disk / "mullvad-browser").exists()
    mine.with_name(mine.name + ".asc").write_bytes(signature(int(time.time()) - 2 * 86400))
    with client(cat, host, make_net=lambda: FakeNet()) as c:
        c.post("/api/tools/browser/get", headers=H, json={"archive": str(mine)})
        job = wait(c)
    assert job["state"] == "done" and "couldn't be checked" in job["warning"] and "2 days ago" in job["warning"]
    assert (disk / "mullvad-browser").is_dir() and job["release"]["unchecked"]


def test_an_archive_the_user_picked_must_be_the_latest(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = open_ramdisk(host)
    old_one = host.home / "Downloads/mullvad-browser-linux-x86_64-15.0.2.tar.xz"
    old_one.parent.mkdir(parents=True, exist_ok=True)
    old_one.write_bytes(tarball(mullvad("15.0.2")))
    with client(cat, host, make_net=lambda: FakeNet(http={MULLVAD_INDEX: mullvad_index()})) as c:
        r = c.post("/api/tools/browser/get", headers=H, json={"archive": str(old_one)}).json()
        assert r["job"]["hosts"] == ["cdn.mullvad.net"]
        job = wait(c)
    assert job["state"] == "failed" and "is version 15.0.2, and Mullvad Browser 15.0.24 is out" in job["error"]
    assert not (disk / "mullvad-browser").exists()
    with client(cat, host, make_net=lambda: FakeNet()) as c:
        c.post("/api/tools/browser/get", headers=H, json={"archive": str(old_one)})
        job = wait(c)
    assert job["state"] == "failed" and "couldn't be checked" in job["error"]


SECURITY_TABLE = b'''const kSecuritySettings = {
  // Preference name:                        [0, 1-high 2-m    3-m    4-low]
  "javascript.options.ion":                  [,  false, false, false, true ],
  "svg.disabled":                            [,  true,  false, false, false],
  "javascript.options.wasm":                 [,  true,  true,  true,  true ],
};'''


def omni(table=SECURITY_TABLE) -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(B.SECURITY_MODULE, table)
    return buf.getvalue()


def test_tor_browser_is_set_up_at_safest(host):  # noqa: F811
    """The level and every pref the browser's own module sets for it, from that module's table, so it starts
    there without asking for a restart; appended to the profile the archive ships."""
    disk = open_ramdisk(host)
    archive = disk / "tor-browser-linux-x86_64-15.0.24.tar.xz"
    archive.write_bytes(tarball({**TOR, "tor-browser/Browser/omni.ja": omni(),
                                 "tor-browser/Browser/TorBrowser/Data/Browser/profile.default": None}))
    target = B.unpack(host, archive, B.BROWSERS["tor"], {})
    assert B.preset_security(host, B.BROWSERS["tor"], target) == "safest"
    prefs = (target / "Browser/TorBrowser/Data/Browser/profile.default/prefs.js").read_text()
    for line in ('user_pref("browser.security_level.security_slider", 1);', 'user_pref("javascript.options.ion", false);',
                 'user_pref("svg.disabled", true);', 'user_pref("browser.security_level.security_custom", false);'):
        assert line in prefs
    info = B.record_release(host, B.BROWSERS["tor"], archive, "download", "safest", signed=1790687273)
    assert info["security"] == "safest" and info["signed"] == 1790687273
    assert B.preset_security(host, B.BROWSERS["mullvad"], disk / "mullvad-browser") == "standard"    # its own default


def xpi(version="0.9.10") -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({"manifest_version": 2, "version": version}))
    return buf.getvalue()


def mullvad_with_extension(version="15.0.24", ext="0.9.10"):
    return {**mullvad(version), f"mullvad-browser/Browser/distribution/extensions/{B.MULLVAD_EXTENSION}.xpi": xpi(ext)}


def test_mullvad_browser_is_set_up_for_mullvad_vpn(host):  # noqa: F811
    """A profile of the app's own, which the browser uses with MOZ_LEGACY_PROFILES: the extension's permissions
    granted, its proxy on for every site through the Zurich proxy inside the tunnel, secure DNS off."""
    disk = open_ramdisk(host)
    b = B.BROWSERS["mullvad"]
    archive = disk / "mullvad-browser-linux-x86_64-15.0.24.tar.xz"
    archive.write_bytes(tarball(mullvad_with_extension()))
    target = B.unpack(host, archive, b, {})
    done = B.preset_vpn(host, b, target, archive)
    assert done == {"set": True, "server": "ch-zrh-wg-001", "hostname": "ch-zrh-wg-socks5-001.relays.mullvad.net",
                    "city": "Zurich", "country": "Switzerland", "address": "10.124.0.241", "port": 1080}
    data = target / "Data"
    assert "Path=profile.default\nDefault=1" in (data / "profiles.ini").read_text()
    profile = data / "profile.default"
    prefs = (profile / "prefs.js").read_text()
    assert 'user_pref("network.trr.mode", 5);' in prefs
    assert 'user_pref("extensions.webextensions.keepStorageOnUninstall", true);' in prefs
    granted = json.loads((profile / "extension-preferences.json").read_text())[B.MULLVAD_EXTENSION]
    assert granted["permissions"] == ["proxy", "tabs"] and granted["origins"] == ["<all_urls>"]
    store = json.loads((profile / f"browser-extension-data/{B.MULLVAD_EXTENSION}/storage.js").read_text())
    assert json.loads(store["globalProxy"]) == {"host": "10.124.0.241", "port": 1080, "proxyDNS": True, "type": "socks"}
    details = json.loads(store["globalProxyDetails"])
    assert details["socksEnabled"] is True and details["server"] == "ch-zrh-wg-001" and details["countryCode"] == "ch"
    assert all(isinstance(store[k], str) and json.loads(store[k]) is not None
               for k in ("excludedHosts", "hostProxies", "hostProxiesDetails", "randomProxyMode"))
    for f in (data / "profiles.ini", profile / "prefs.js"):
        assert f.stat().st_mode & 0o777 == 0o600
    assert B.browser_env(host, b) == {}                                 # nothing recorded yet
    info = B.record_release(host, b, archive, "download", vpn=done)
    assert info["vpn"]["set"] and info["vpn"]["city"] == "Zurich"
    assert B.browser_env(host, b) == {"MOZ_LEGACY_PROFILES": "1"}
    assert B.environment(host, b, disk / ".session")["MOZ_LEGACY_PROFILES"] == "1"
    assert B.preset_vpn(host, B.BROWSERS["tor"], target, archive) is None


def test_an_untested_mullvad_browser_isn_t_preset(host):  # noqa: F811
    """Its extension's and Firefox's internal formats: only the versions tested; otherwise the card says why."""
    disk = open_ramdisk(host)
    b = B.BROWSERS["mullvad"]
    for version, ext, said in (("15.0.24", "1.0.0", "extension 1.0.0"), ("16.0", "0.9.10", "this is 16.0"),
                               ("15.0.24", None, "no extension the app recognises")):
        shutil.rmtree(disk / "mullvad-browser", ignore_errors=True)
        archive = disk / f"mullvad-browser-linux-x86_64-{version}.tar.xz"
        archive.write_bytes(tarball(mullvad_with_extension(version, ext) if ext else mullvad(version)))
        target = B.unpack(host, archive, b, {})
        done = B.preset_vpn(host, b, target, archive)
        assert done["set"] is False and said in done["why"] and not (target / "Data").exists()
        B.record_release(host, b, archive, "download", vpn=done)
        assert B.browser_env(host, b) == {} and B.release_info(host, b)["vpn"] == {"set": False, "why": done["why"]}


def test_the_vpn_set_up_is_the_user_s_choice(cat, host, x86, monkeypatch):  # noqa: F811
    """On unless the page says no; for Mullvad Browser only."""
    good(monkeypatch)
    disk = open_ramdisk(host)
    mine = host.home / "Downloads/mullvad-browser-linux-x86_64-15.0.24.tar.xz"
    mine.parent.mkdir(parents=True, exist_ok=True)
    mine.write_bytes(tarball(mullvad_with_extension()))
    net = lambda: FakeNet(http={MULLVAD_INDEX: mullvad_index()})        # noqa: E731
    with client(cat, host, make_net=net) as c:
        c.post("/api/tools/browser/get", headers=H, json={"archive": str(mine), "vpn": False})
        job = wait(c)
    assert job["state"] == "done" and job["release"]["vpn"] is None and not (disk / "mullvad-browser/Data").exists()
    shutil.rmtree(disk / "mullvad-browser")
    with client(cat, host, make_net=net) as c:
        c.post("/api/tools/browser/get", headers=H, json={"archive": str(mine)})
        job = wait(c)
    assert job["state"] == "done" and job["release"]["vpn"]["set"] and (disk / "mullvad-browser/Data/profiles.ini").is_file()


def test_only_the_browser_s_own_processes_go_under_its_name(host, monkeypatch):  # noqa: F811
    """A python3 script or a shell of the user's in ~/TempBrowser is named, even while the browser (whose
    sandbox also runs python3 and sh) is open."""
    proc = host.root / "proc"
    for pid, ppid, comm in ((10, 1, "bwrap"), (11, 10, "python3"), (12, 11, "bwrap"), (13, 12, "firefox.real"),
                            (14, 11, "tor"), (15, 13, "Web Content"), (20, 1, "python3"), (21, 20, "sh")):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "status").write_text(f"Name:\t{comm}\nPPid:\t{ppid}\n")
        (proc / str(pid) / "comm").write_text(comm + "\n")
    monkeypatch.setattr(B, "running", lambda host, b: [13] if b.id == "tor" else [])
    assert B._browser_tree(host) == {10, 11, 12, 13, 14, 15}
    open_ramdisk(host)
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {11: "python3", 13: "firefox.real", 20: "python3", 21: "sh"})
    assert B.disk_users(host, host.home / "TempBrowser") == ["Tor Browser", "python3", "sh"]


def test_the_panel_knows_memory_apparmor_and_file_search(host, monkeypatch):  # noqa: F811
    """What the panel says before a start: the memory there is with swap off, AppArmor's restriction when it is what
    stops the sandbox, and file search that would index ~/TempBrowser."""
    (host.root / "proc").mkdir(exist_ok=True)
    (host.root / "proc/meminfo").write_text("MemTotal:        8000000 kB\nMemFree: 1 kB\nMemAvailable:    2048000 kB\n")
    assert B._memory(host) == {"total_mb": 7812, "available_mb": 2000, "browser_mb": B.BROWSER_MB}
    (host.root / "proc/sys/kernel").mkdir(parents=True, exist_ok=True)
    (host.root / "proc/sys/kernel/apparmor_restrict_unprivileged_userns").write_text("1\n")
    B._PROBED.clear()
    monkeypatch.setattr(B.sandbox, "probe", lambda h: "bubblewrap can't set up a sandbox here (uid map).")
    assert B.sandbox_status(host)["apparmor"]
    B._PROBED.clear()
    monkeypatch.setattr(B.sandbox, "probe", lambda h: None)
    monkeypatch.setattr(B.sandbox, "probe_pasta", lambda h: None)
    monkeypatch.setattr(B.sandbox, "probe_fence", lambda h: None)
    st = B.sandbox_status(host)
    assert not st["apparmor"] and not st["pasta"]["apparmor"]
    # bubblewrap has its profile, pasta is installed but AppArmor stops it (Ubuntu 24.04's passt package has no profile
    # for pasta; seen on Mint 22.3 with the restriction on): the panel is told, to give pasta's profile
    B._PROBED.clear()
    monkeypatch.setattr(B.sandbox, "probe_pasta", lambda h: "pasta couldn't start a sandbox here (clone: Operation not permitted).")
    host.runner.installed.add("pasta")
    st = B.sandbox_status(host)
    assert st["available"] and not st["pasta"]["available"] and st["pasta"]["apparmor"]
    host.runner.installed.discard("pasta")                                      # not installed: the usual "install passt"
    B._PROBED.clear()
    assert not B.sandbox_status(host)["pasta"]["apparmor"]
    B._PROBED.clear()
    monkeypatch.setattr(B.sandbox, "probe_pasta", lambda h: None)
    B._INDEXING.clear()
    host.runner.handlers["balooctl6"] = lambda argv: None
    (host.home / ".config").mkdir(parents=True, exist_ok=True)
    assert B.indexing(host)["baloo"] == {"on": True, "contents": True, "covers": True, "index": False}   # KDE's default: home
    B._INDEXING.clear()
    (host.home / ".config/baloofilerc").write_text("[General]\nexclude folders[$e]=$HOME/TempBrowser/\n")
    assert B.indexing(host)["baloo"]["covers"] is False
    B._INDEXING.clear()
    (host.home / ".config/baloofilerc").write_text("[Basic Settings]\nIndexing-Enabled=false\n")
    assert B.indexing(host)["baloo"] is None
    B._INDEXING.clear()
    (host.home / ".local/share/baloo").mkdir(parents=True)
    (host.home / ".local/share/baloo/index").write_bytes(b"x")
    assert B.indexing(host)["baloo"] == {"on": False, "contents": False, "covers": False, "index": True}   # left behind


def test_the_panel_names_what_the_desktop_still_offers_a_sandbox(host, monkeypatch):  # noqa: F811
    """Asked of the compositor: what a client of a marked socket gets, from wayland.RISKY (KDE Plasma 6.7: data
    control); without the protocol, what any client gets."""
    from daprivacyscanner.tools import wayland as W
    B._CONTEXT.clear()
    monkeypatch.setattr(B, "_compositor", lambda h: "/run/user/1000/wayland-0")
    monkeypatch.setattr(W, "globals_of", lambda path, timeout=5: {"wl_compositor": (1, 1), W.MANAGER: (2, 1),
                                                                   "ext_data_control_manager_v1": (3, 1)})
    monkeypatch.setattr(W, "sandboxed_globals", lambda sock, folder, timeout=5: {"wl_compositor", "ext_data_control_manager_v1"})
    host.environ["XDG_RUNTIME_DIR"] = str(host.home)
    context, risky = B.wayland_exposure(host)
    assert context is True and risky == [{"global": "ext_data_control_manager_v1",
                                          "what": "read and change the clipboard in the background"}]
    assert not [p for p in host.home.iterdir() if p.name.startswith("daprivacyscanner-")]     # the probe's folder is gone
    B._CONTEXT.clear()
    monkeypatch.setattr(W, "globals_of", lambda path, timeout=5: {"wl_compositor": (1, 1), "zwlr_screencopy_manager_v1": (2, 1)})
    assert B.wayland_exposure(host) == (False, [{"global": "zwlr_screencopy_manager_v1", "what": "record the screen"}])
    B._CONTEXT.clear()


def test_a_viewer_and_a_start_script_run_by_bash_go_under_their_names(host, monkeypatch):  # noqa: F811
    """On Arch a start script runs as bash (through env): it is the browser's sandbox, not a program of the user's.
    A viewer View offline… started holds its copy: named as that viewer, its processes with it, not one by one."""
    from daprivacyscanner.tools import viewer as V
    proc = host.root / "proc"
    for pid, ppid, comm in ((10, 1, "bwrap"), (11, 10, "bash"), (13, 11, "mullvadbrowser."),
                            (30, 1, "bwrap"), (31, 30, "firefox"), (32, 31, "Isolated Web Co"), (33, 31, "RDD Process"),
                            (40, 1, "bash")):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "status").write_text(f"Name:\t{comm}\nPPid:\t{ppid}\n")
        (proc / str(pid) / "comm").write_text(comm + "\n")
    monkeypatch.setattr(B, "running", lambda host, b: [13] if b.id == "mullvad" else [])
    assert B._browser_tree(host) == {10, 11, 13}                        # the user's own bash (40) isn't in it
    monkeypatch.setattr(V, "launched", lambda: {30: "Firefox"})
    open_ramdisk(host)
    monkeypatch.setattr(R, "holders_on_device", lambda host, path: {11: "bash", 13: "mullvadbrowser.", 31: "firefox",
                                                                     32: "Isolated Web Co", 33: "RDD Process", 40: "bash"})
    assert B.disk_users(host, host.home / "TempBrowser") == ["Mullvad Browser", "Firefox (opened by View offline…)", "bash"]


def test_hibernation_and_opensnitch_are_named_before_a_start(host, monkeypatch):  # noqa: F811
    """Hibernating writes all of memory, ~/TempBrowser's noswap pages and the browser's included, to the swap on the
    disk; OpenSnitch's log at level 2 and its window's list in a file record the browser's sites."""
    from daprivacyscanner import opensnitch as osn
    sys_ = host.root / "sys/power"
    sys_.mkdir(parents=True)
    (sys_ / "state").write_text("freeze mem disk\n")
    (sys_ / "disk").write_text("[platform] shutdown reboot suspend\n")
    (host.root / "proc/swaps").write_text("Filename Type Size Used Priority\n/dev/zram0 partition 1 0 100\n")
    assert not R.hibernation_possible(host)                             # zram alone: nowhere to write the image
    (host.root / "proc/swaps").write_text("Filename Type Size Used Priority\n/dev/zram0 partition 1 0 100\n"
                                          "/dev/dm-1 partition 2000000 0 -2\n")
    assert R.hibernation_possible(host) is False                        # no resume device: the scan says it can't
    (host.root / "proc/cmdline").write_text("ro quiet resume=/dev/dm-1\n")
    (sys_ / "image_size").write_text(str(2**30))
    assert R.hibernation_possible(host) is None                         # logind couldn't be asked: never a guess
    from daprivacyscanner.host import CommandResult
    host.runner.handlers["busctl"] = lambda argv: CommandResult(argv, 0, 's "yes"\n')
    assert R.hibernation_possible(host)
    (sys_ / "disk").write_text("[disabled]\n")
    assert not R.hibernation_possible(host)
    state = {"s": osn.OpenSnitch(daemon=True, active=True, config={"LogLevel": 2})}
    monkeypatch.setattr(osn, "read", lambda h, paths, procs=None: state["s"])
    B._OPENSNITCH.clear()
    assert B.opensnitch_records(host) == {"log_level": 2, "log": osn.LOG, "database": None}
    B._OPENSNITCH.clear()
    state["s"] = osn.OpenSnitch(daemon=True, active=True, config={"LogLevel": 3})
    assert B.opensnitch_records(host) is None                           # level 3, list in memory: nothing on the disk
    B._OPENSNITCH.clear()
    state["s"] = osn.OpenSnitch(daemon=True, active=False, config={"LogLevel": 1})
    assert B.opensnitch_records(host) is None                           # not running
    B._OPENSNITCH.clear()


def test_the_app_and_what_it_starts_leave_no_crash_record():
    """A core size limit of 1, inherited: the kernel skips the dump altogether (at 0, systemd-coredump wrote the
    command line, the environment and the open files' paths into the journal, tested)."""
    import subprocess
    import sys
    code = ("from daprivacyscanner.app import no_core_dumps; no_core_dumps(); import subprocess, sys; "
            "print(subprocess.run([sys.executable, '-c', 'import resource; print(resource.getrlimit(resource.RLIMIT_CORE), "
            "open(\"/proc/self/coredump_filter\").read().strip())'], capture_output=True, text=True).stdout)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert "(1, 1) 00000000" in out.stdout, out.stderr
