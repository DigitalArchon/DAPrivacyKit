"""The tools review of 2026-10-17, files in and out of the browser in memory (transfer.py, viewer.py, sniff.py):
what the browser plants in its own folders is never followed, what a download is is judged within bounds, the
TempOutbox passes on only what has finished arriving, and View offline… with a Flatpak viewer keeps the file
away from the app's usual, networked self. Nothing here runs bubblewrap, Flatpak or a viewer."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from daprivacyscanner.tools import pick
from daprivacyscanner.tools import transfer as T

from test_browser_sandbox import H, app_for, host, installed_tor, old  # noqa: F401 - the fixture


def key(host) -> Path:
    """A private key of the user's, outside ~/TempBrowser, which the browser can't see."""
    k = host.home / ".ssh/id_ed25519"
    k.parent.mkdir(exist_ok=True)
    k.write_text("PRIVATE KEY")
    return k


# ------------------------------------------------------------------ C2: a link the browser planted

def test_a_link_planted_in_the_downloads_folder_is_never_copied_into_to_upload(host):
    """Live on Mint: Downloads/notes.txt -> ~/.ssh/id_ed25519, chosen with Add a file to upload…, put the key in To
    upload, where the browser reads it, with the box for metadata ticked or not."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    planted = T.downloads_dir(host, "tor-browser") / "notes.txt"
    os.symlink(key(host), planted)
    host.runner.handlers["mat2"] = lambda argv: pytest.fail("nothing is cleaned")
    for clean in (False, True):
        with pytest.raises(T.TransferError, match="link in ~/TempBrowser"):
            T.add(host, "tor-browser", planted, clean=clean)
    assert list(T.uploads_dir(host, "tor-browser").iterdir()) == []
    with pytest.raises(pick.PathRefused, match="link in ~/TempBrowser"):
        pick.checked(str(planted), host.home)


def test_a_folder_link_planted_in_the_browser_s_folder_is_not_followed_either(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    key(host)
    os.symlink(host.home / ".ssh", T.downloads_dir(host, "tor-browser") / "keys")
    through = T.downloads_dir(host, "tor-browser") / "keys/id_ed25519"
    with pytest.raises(T.TransferError, match="link in ~/TempBrowser"):
        T.add(host, "tor-browser", through, clean=False)
    with pytest.raises(pick.PathRefused):
        pick.checked(str(through), host.home)
    # nor a way in from outside: the user's own link to the browser's folder, then the browser's link
    os.symlink(T.downloads_dir(host, "tor-browser"), host.home / "dl")
    with pytest.raises(T.TransferError, match="link in ~/TempBrowser"):
        T.add(host, "tor-browser", host.home / "dl/keys/id_ed25519", clean=False)
    assert list(T.uploads_dir(host, "tor-browser").iterdir()) == []


def test_a_second_name_for_a_file_in_the_ram_disk_is_refused(host):
    """A hard link can't cross into the RAM disk, but the browser can give one of its files a second name there:
    only plain files with one link are used, as for a finished download."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "a.txt").write_text("x")
    os.link(d / "a.txt", d / "b.txt")
    with pytest.raises(T.TransferError, match="isn't a plain file"):
        T.add(host, "tor-browser", d / "b.txt", clean=False)


def test_the_user_s_own_files_and_links_elsewhere_are_still_fine(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    (host.home / "Documents").mkdir()
    (host.home / "Documents/cv.txt").write_text("cv")
    os.symlink(host.home / "Documents/cv.txt", host.home / "Downloads/latest-cv.txt")    # the user's own link
    assert pick.checked(str(host.home / "Downloads/latest-cv.txt"), host.home) == host.home / "Downloads/latest-cv.txt"
    assert T.add(host, "tor-browser", host.home / "Downloads/latest-cv.txt", clean=False)["name"] == "latest-cv.txt"
    # a real file in the browser's own folder, reached without a link, is fine too
    (T.downloads_dir(host, "tor-browser") / "page.txt").write_text("p")
    assert T.add(host, "tor-browser", T.downloads_dir(host, "tor-browser") / "page.txt", clean=False)["name"] == "page.txt"
    assert sorted(x.name for x in T.uploads_dir(host, "tor-browser").iterdir()) == ["latest-cv.txt", "page.txt"]
    with pytest.raises(pick.PathRefused):
        pick.checked("/proc/self/environ", host.home)


def test_resolved_walks_as_the_kernel_does(tmp_path):
    (tmp_path / "a/b").mkdir(parents=True)
    (tmp_path / "a/b/f").write_text("f")
    os.symlink("b", tmp_path / "a/l")
    os.symlink(tmp_path / "a/l/f", tmp_path / "abs")
    os.symlink("loop", tmp_path / "loop")
    assert pick.resolved(tmp_path / "a/l/../b/./f", tmp_path) == tmp_path / "a/b/f"
    assert pick.resolved(tmp_path / "abs", tmp_path) == tmp_path / "a/b/f"
    assert pick.resolved(tmp_path / "a/missing/x", tmp_path) == tmp_path / "a/missing/x"
    with pytest.raises(pick.PathRefused, match="too many links"):
        pick.resolved(tmp_path / "loop", tmp_path)


def test_a_folder_link_planted_in_the_ram_disk_isn_t_a_place_to_save_to(host):
    """Save… into a folder reached through a link the browser made would write where it points (an autostart
    folder runs a launcher whatever its mode)."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "x.desktop").write_text("[Desktop Entry]\nExec=sh\n")
    old(d / "x.desktop")
    autostart = host.home / ".config/autostart"
    autostart.mkdir(parents=True)
    os.symlink(autostart, d / "Pictures")
    shown = next(e.check for e in T.downloads(host, "tor-browser")[0] if e.name == "x.desktop")
    with pytest.raises(T.TransferError, match="link in ~/TempBrowser"):
        T.save(host, "tor-browser", "x.desktop", d / "Pictures", shown)
    assert list(autostart.iterdir()) == []


def test_through_the_api_a_planted_link_is_refused(cat, host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    planted = T.downloads_dir(host, "tor-browser") / "notes.txt"
    os.symlink(key(host), planted)
    c = app_for(cat, host)
    r = c.post("/api/tools/browser/upload", headers=H, json={"browser": "tor", "paths": [str(planted)], "clean": False})
    assert r.status_code == 400 and "link in ~/TempBrowser" in r.json()["error"]
    assert list(T.uploads_dir(host, "tor-browser").iterdir()) == []


# ------------------------------------------------------------------ C4, C5: judging a download, within bounds

def test_a_zip_whose_index_is_too_long_isn_t_read(tmp_path, monkeypatch):
    """zipfile loads a ZIP's whole index first: a million entries took 3.6 s and 534 MB. The end record says how
    long it is, and a longer one isn't opened: an archive, unchecked."""
    import struct
    import zipfile
    from daprivacyscanner.tools import sniff
    f = tmp_path / "big.zip"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("a.txt", "a")
    data = bytearray(f.read_bytes())
    end = data.rfind(b"PK\x05\x06")
    data[end + 8:end + 16] = struct.pack("<HHI", 0xFFFE, 0xFFFE, 64 << 20)     # 65,534 entries, a 64 MB index
    f.write_bytes(bytes(data))
    monkeypatch.setattr(sniff.zipfile, "ZipFile", lambda *a, **k: pytest.fail("the index isn't loaded"))
    fd = os.open(f, os.O_RDONLY)
    try:
        ins = sniff.inspect(fd, "report.docx", len(data))
    finally:
        os.close(fd)
    assert ins.kind == "archive" and not ins.viewable and any("too long to look through" in w for w in ins.warnings)


def test_a_zip_of_ordinary_size_is_still_looked_into(tmp_path):
    import zipfile
    from daprivacyscanner.tools import sniff
    f = tmp_path / "doc.docx"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/vbaProject.bin", "macro")
    fd = os.open(f, os.O_RDONLY)
    try:
        ins = sniff.inspect(fd, "doc.docx", f.stat().st_size)
    finally:
        os.close(fd)
    assert ins.what == "an Office document" and any("macros" in w for w in ins.warnings)


def test_a_file_of_holes_or_larger_than_the_disk_isn_t_read(host, monkeypatch):
    """A sparse file the browser made 8 EiB long was hashed for ever, one server worker per listing: one that
    isn't plain (its blocks don't hold its size, or the RAM disk couldn't hold it) is never read."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    with open(d / "huge.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n")
        f.truncate(1 << 40)                                            # a TiB of holes
    old(d / "huge.pdf")
    (d / "small.pdf").write_bytes(b"%PDF-1.7\n" + bytes(4096))
    old(d / "small.pdf")
    monkeypatch.setattr(T, "digest", lambda fd, limit=None: "d" if os.fstat(fd).st_size < 1 << 20 else pytest.fail("read"))
    got, other = T.downloads(host, "tor-browser")
    assert [e.name for e in got] == ["small.pdf"] and other == 1
    with pytest.raises(T.TransferError, match="isn't a finished download"):
        T.snapshot(host, "tor-browser", "huge.pdf", "x")
    monkeypatch.setattr(T, "_disk_size", lambda host: 1000)            # larger than the disk: not plain either
    assert T.downloads(host, "tor-browser") == ([], 2)


def test_a_listing_doesn_t_wait_for_a_download_being_judged(host):
    """One download judged at a time; a listing that finds one being judged (by a listing in another worker) goes on
    without it, and shows it once it has been judged."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "a.pdf").write_bytes(b"%PDF-1.7\n")
    old(d / "a.pdf")
    T._SEEN.clear()
    assert T._INSPECTING.acquire(blocking=False)
    try:
        assert T.downloads(host, "tor-browser") == ([], 1)
    finally:
        T._INSPECTING.release()
    assert [e.name for e in T.downloads(host, "tor-browser")[0]] == ["a.pdf"]


def test_a_digest_stops_when_the_disk_is_being_closed(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(bytes(3 << 20))
    fd = os.open(f, os.O_RDONLY)
    try:
        assert T.digest(fd) and T.digest(fd, 3 << 20)
        with pytest.raises(T.Stopped):
            T.digest(fd, 1 << 20)                                       # more than it said it held
        T.STOP.set()
        with pytest.raises(T.Stopped):
            T.digest(fd)
    finally:
        T.STOP.clear()
        os.close(fd)


def test_a_picture_rewritten_as_a_program_with_its_time_put_back_is_judged_again(host):
    """The listing's memory was keyed on (device, inode, size, mtime): a PNG rewritten as an ELF of the same size,
    its mtime put back, stayed "a PNG picture", while Save… found it changed every time. The ctime can't be put
    back."""
    import time
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))
    old(d / "photo.png")
    assert T.downloads(host, "tor-browser")[0][0].what == "a PNG picture"
    st = os.stat(d / "photo.png")
    time.sleep(0.02)
    with open(d / "photo.png", "r+b") as f:
        f.write(b"\x7fELF" + bytes(68))
    os.utime(d / "photo.png", ns=(st.st_atime_ns, st.st_mtime_ns))
    [e] = T.downloads(host, "tor-browser")[0]
    assert e.kind == "program" and e.what == "a Linux program"
    dest = host.home / "Documents"
    dest.mkdir()
    assert T.save(host, "tor-browser", "photo.png", dest, e.check).read_bytes().startswith(b"\x7fELF")
