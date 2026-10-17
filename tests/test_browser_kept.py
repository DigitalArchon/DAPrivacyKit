"""Kept downloads of Tor Browser and Mullvad Browser (tools/kept.py, the owner's request of 2026-10-17): kept only when
ticked and only once verified, one per browser, set up again the way an archive the user picked is (the same
refusals), deleted from the panel, and removed by packaging/uninstall.sh."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from daprivacyscanner.online import FakeNet, HttpResult
from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import kept as K

from test_browser_tool import (ARCHIVE, INDEX, MULLVAD_INDEX, TOR, client, good, index, mullvad, mullvad_index,
                               open_ramdisk, signature, tarball, wait)
from test_server_tools import H, host  # noqa: F401 - the fixture


@pytest.fixture
def x86(monkeypatch):
    monkeypatch.setattr(B.platform, "machine", lambda: "x86_64")


def tor_net(version="15.0.24", signed_days=3, data=None):
    url = ARCHIVE.replace("15.0.24", version)
    idx = HttpResult(200, json.dumps({"version": version, "binary": url, "sig": url + ".asc"}).encode())
    entries = dict(TOR)
    entries["tor-browser/Browser/tbb_version.json"] = json.dumps({"version": version}).encode()
    return FakeNet(http={INDEX: idx}, files={url: data or tarball(entries),
                                             url + ".asc": signature(int(time.time()) - signed_days * 86400)})


def kept_dir(host):
    return K.folder(host) / "tor"


def download(c, keep=True, browser="tor"):
    r = c.post("/api/tools/browser/get", headers=H, json={"browser": browser, "keep": keep})
    assert r.status_code == 200, r.text
    return wait(c)


def close_disk(host):
    """~/TempBrowser closed: what was set up in it gone."""
    import shutil
    shutil.rmtree(host.home / "TempBrowser")
    host.root.joinpath("proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")


# ------------------------------------------------------------------ keeping

def test_nothing_is_kept_unless_ticked(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    open_ramdisk(host)
    with client(cat, host, make_net=tor_net) as c:
        job = download(c, keep=False)
    assert job["state"] == "done" and "kept" not in job and not K.folder(host).exists()


def test_a_verified_download_is_kept_owner_only_on_the_disk(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = open_ramdisk(host)
    net = tor_net()
    with client(cat, host, make_net=lambda: net) as c:
        job = download(c)
        d = c.get("/api/tools/browser", headers=H).json()
    assert job["state"] == "done" and job["kept"]["version"] == "15.0.24"
    assert job["kept"]["folder"] == "~/.cache/daprivacyscanner/browsers"
    name = "tor-browser-linux-x86_64-15.0.24.tar.xz"
    assert sorted(os.listdir(kept_dir(host))) == [name, name + ".asc"]
    assert (kept_dir(host) / name).read_bytes() == net.files[ARCHIVE]            # the verified file, byte for byte
    for p in (K.folder(host), K.folder(host).parent, kept_dir(host)):
        assert stat.S_IMODE(p.stat().st_mode) == 0o700
    assert stat.S_IMODE((kept_dir(host) / name).stat().st_mode) == 0o600
    assert net.contacted == [INDEX, ARCHIVE + ".asc", ARCHIVE]                    # kept from the file, not fetched again
    assert not list((disk / ".downloads").iterdir())                             # the RAM disk's copy gave its memory back
    assert d["kept"]["copies"] == [{"browser": "tor", "name": "Tor Browser", "version": "15.0.24", "kept": d["kept"]["copies"][0]["kept"],
                                    "size": (kept_dir(host) / name).stat().st_size + (kept_dir(host) / (name + ".asc")).stat().st_size,
                                    "file": name}]


def test_never_an_unverified_file(cat, host, x86, monkeypatch):  # noqa: F811
    """An unverified download is refused before anything else; and the copy where it would be kept is verified again
    before it is put in place (here it fails there: nothing is kept, the set-up itself stands)."""
    def bad(host, archive):
        raise B.BrowserError(f"{archive.name} isn't verified (Bad signature). It was not unpacked.")
    monkeypatch.setattr(B, "verified", bad)
    open_ramdisk(host)
    with client(cat, host, make_net=tor_net) as c:
        assert download(c)["state"] == "failed"
    assert not kept_dir(host).exists()
    close_disk(host)
    open_ramdisk(host)

    def only_in_memory(host, archive):
        if "TempBrowser" not in str(archive):
            raise B.BrowserError("isn't verified (Bad signature)")
        return {"title": "Verified", "fingerprint": "EF6E", "signer": "Tor Browser Developers", "signed": None}
    monkeypatch.setattr(B, "verified", only_in_memory)
    with client(cat, host, make_net=tor_net) as c:
        job = download(c)
    assert job["state"] == "done" and "wasn't kept" in job["keep_error"] and "kept" not in job
    assert not kept_dir(host).exists() and not [p for p in K.folder(host).iterdir() if p.name.startswith(".")]


def test_a_newer_download_replaces_the_kept_one(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    open_ramdisk(host)
    with client(cat, host, make_net=tor_net) as c:
        download(c)
    close_disk(host)
    open_ramdisk(host)
    with client(cat, host, make_net=lambda: tor_net("15.0.25")) as c:
        assert download(c)["kept"]["version"] == "15.0.25"
    assert sorted(os.listdir(kept_dir(host))) == ["tor-browser-linux-x86_64-15.0.25.tar.xz",
                                                  "tor-browser-linux-x86_64-15.0.25.tar.xz.asc"]
    assert [p.name for p in K.folder(host).iterdir()] == ["tor"]                  # nothing of the swap left beside it


# ------------------------------------------------------------------ setting up from the kept copy

def keep_one(cat, host, version="15.0.24", signed_days=3, data=None):
    open_ramdisk(host)
    with client(cat, host, make_net=lambda: tor_net(version, signed_days, data)) as c:
        assert download(c)["state"] == "done"
    close_disk(host)
    return open_ramdisk(host)


def from_kept(cat, host, net):
    with client(cat, host, make_net=lambda: net) as c:
        r = c.post("/api/tools/browser/get", headers=H, json={"kept": "tor"})
        assert r.status_code == 200 and r.json()["job"]["hosts"] == ["aus1.torproject.org"]
        return wait(c)


def test_the_kept_copy_is_set_up_as_a_picked_archive_is(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = keep_one(cat, host)
    net = FakeNet(http={INDEX: index()})
    job = from_kept(cat, host, net)
    assert job["state"] == "done" and job["source"] == "kept" and job["release"]["source"] == "kept"
    assert net.contacted == [INDEX]                                               # only: is it the latest?
    assert B.installed(host, B.BROWSERS["tor"]) and not list((disk / ".downloads").iterdir())
    assert K.kept(host, B.BROWSERS["tor"]) is not None                            # it stays kept


def test_a_kept_copy_older_than_the_latest_isnt_used(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = keep_one(cat, host)
    job = from_kept(cat, host, tor_net("15.0.25"))
    assert job["state"] == "failed" and job["newer"] == "15.0.25"
    assert "The kept copy is Tor Browser 15.0.24, and 15.0.25 is out" in job["error"] and "isn't used" in job["error"]
    assert not (disk / "tor-browser").exists() and not list((disk / ".downloads").iterdir())


def test_a_kept_copy_renamed_as_a_newer_one_isnt_unpacked(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = keep_one(cat, host)
    d = kept_dir(host)
    for n in ("tor-browser-linux-x86_64-15.0.24.tar.xz", "tor-browser-linux-x86_64-15.0.24.tar.xz.asc"):
        (d / n).rename(d / n.replace("15.0.24", "15.0.25"))
    job = from_kept(cat, host, tor_net("15.0.25"))
    assert job["state"] == "failed" and "says it is version 15.0.25, but what is inside is version 15.0.24" in job["error"]
    assert not (disk / "tor-browser").exists()


def test_a_kept_copy_whose_signature_doesnt_verify_isnt_unpacked(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = keep_one(cat, host)

    def bad(host, archive):
        raise B.BrowserError(f"{archive.name} isn't verified (Bad signature). It was not unpacked.")
    monkeypatch.setattr(B, "verified", bad)
    job = from_kept(cat, host, FakeNet(http={INDEX: index()}))
    assert job["state"] == "failed" and "isn't verified" in job["error"] and not (disk / "tor-browser").exists()


def test_where_the_index_cant_be_reached_only_a_recently_signed_kept_copy_is_used(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = keep_one(cat, host, signed_days=40)
    job = from_kept(cat, host, FakeNet())
    assert job["state"] == "failed" and "signature was made 40 days ago" in job["error"]
    assert not (disk / "tor-browser").exists()
    import shutil
    shutil.rmtree(K.folder(host))
    close_disk(host)
    disk = keep_one(cat, host, signed_days=2)
    job = from_kept(cat, host, FakeNet())
    assert job["state"] == "done" and "couldn't be checked" in job["warning"] and job["release"]["unchecked"]


def test_no_kept_copy_no_set_up(cat, host, x86):  # noqa: F811
    open_ramdisk(host)
    with client(cat, host) as c:
        r = c.post("/api/tools/browser/get", headers=H, json={"kept": "tor"})
    assert r.status_code == 409 and "No download of Tor Browser is kept" in r.json()["error"]


# ------------------------------------------------------------------ deleting

def test_a_kept_copy_is_deleted_from_the_panel(cat, host, x86, monkeypatch):  # noqa: F811
    from daprivacyscanner.tools import owner
    good(monkeypatch)
    keep_one(cat, host)
    with client(cat, host) as c:
        held = owner.hold(host, "browser-tor")                                     # a set-up from it under way
        r = c.post("/api/tools/browser/kept/delete", headers=H, json={"browser": "tor"})
        assert r.status_code == 409 and K.kept(host, B.BROWSERS["tor"]) is not None
        owner.let_go(held)
        r = c.post("/api/tools/browser/kept/delete", headers=H, json={"browser": "tor"})
        assert r.status_code == 200 and r.json()["deleted"] and r.json()["kept"]["copies"] == []
    assert not K.folder(host).exists()                                             # its folders go once empty


def test_a_link_in_place_of_the_folder_is_never_written_through(cat, host, x86, monkeypatch, tmp_path):  # noqa: F811
    good(monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    K.folder(host).parent.mkdir(parents=True)
    os.symlink(elsewhere, K.folder(host))
    open_ramdisk(host)
    with client(cat, host, make_net=tor_net) as c:
        job = download(c)
    assert job["state"] == "done" and "isn't a folder of yours" in job["keep_error"] and not list(elsewhere.iterdir())
    assert K.kept(host, B.BROWSERS["tor"]) is None


def test_mullvad_browser_is_kept_beside_tor_browser(cat, host, x86, monkeypatch):  # noqa: F811
    good(monkeypatch)
    disk = keep_one(cat, host)
    m = "https://cdn.mullvad.net/browser/15.0.24/mullvad-browser-linux-x86_64-15.0.24.tar.xz"
    net = FakeNet(http={MULLVAD_INDEX: mullvad_index()},
                  files={m: tarball(mullvad()), m + ".asc": signature(int(time.time()) - 86400)})
    with client(cat, host, make_net=lambda: net) as c:
        assert download(c, browser="mullvad")["kept"]["version"] == "15.0.24"
        copies = c.get("/api/tools/browser", headers=H).json()["kept"]["copies"]
    assert [x["browser"] for x in copies] == ["tor", "mullvad"] and (disk / "mullvad-browser").is_dir()
