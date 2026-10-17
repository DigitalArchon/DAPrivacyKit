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


# ------------------------------------------------------------------ C6, C8, C10: the TempOutbox

@pytest.fixture
def outbox(host, request):
    """Tor Browser set up with its TempOutbox, this copy of the app its owner, and mat2 that drops "+gps"."""
    from daprivacyscanner.host import CommandResult
    from daprivacyscanner.tools import browser as B, owner
    from daprivacyscanner.tools.metadata import cleaned_name
    installed_tor(host)
    T.prepare(host, "tor-browser")
    T.forget_recent()
    seen = []

    def mat2(argv):
        p = Path(argv[-1])
        seen.append(p)
        if p.suffix == ".xyz":
            return CommandResult(tuple(argv), 0, f"[-] {p}'s format (chemical/x-xyz) is not supported\n")
        cleaned_name(p).write_bytes(p.read_bytes().replace(b"+gps", b""))
        for hook in list(hooks):
            hook(p)
        return CommandResult(tuple(argv), 0)
    hooks: list = []
    host.runner.handlers["mat2"] = mat2
    assert B.default_outbox(host, B.BROWSERS["tor"])
    assert owner.claim(host, "TempBrowser", host.home / "TempBrowser")
    request.addfinalizer(lambda: owner.release(host, "TempBrowser"))
    box = host.home / "TempBrowser/Outbox for Tor Browser"
    return box, (lambda: B.run_outboxes(host)), hooks


def writer(host, path: Path, pid: int = 4242):
    """A process of the user's holding `path` open for writing, as a file manager copying it in does while it
    pauses: its descriptor and fdinfo in the fixture's /proc."""
    d = host.root / f"proc/{pid}"
    (d / "fd").mkdir(parents=True, exist_ok=True)
    (d / "fdinfo").mkdir(exist_ok=True)
    os.symlink(path, d / "fd/7")
    (d / "fdinfo/7").write_text("pos:\t98304\nflags:\t0100001\nmnt_id:\t31\n")
    return d


def test_a_copy_that_pauses_isn_t_cleaned_half_way(host, outbox):
    """Live on Mint: a copy into the TempOutbox that paused 5 seconds was cleaned half-way (95 KB) into To upload
    and reported cleaned. A file still open for writing waits, however long ago it last changed."""
    box, run, _ = outbox
    (box / "photo.jpg").write_bytes(b"half+gps")
    old(box / "photo.jpg")
    proc = writer(host, box / "photo.jpg")
    run()
    run()
    up = T.uploads_dir(host, "tor-browser")
    assert list(up.iterdir()) == [] and (box / "photo.jpg").exists()
    assert T.outbox_view(host, "tor-browser", "Tor Browser")["waiting"] == 1
    (proc / "fd/7").unlink()                                         # the copy has finished
    (box / "photo.jpg").write_bytes(b"whole+gps")
    old(box / "photo.jpg")
    run()
    assert list(up.iterdir()) == []                                  # changed since the last look: once more
    run()
    assert (up / "photo.jpg").read_bytes() == b"whole" and (box / "Originals/photo.jpg").read_bytes() == b"whole+gps"


def test_a_file_that_changes_while_it_is_cleaned_goes_no_further(host, outbox):
    box, run, hooks = outbox
    (box / "photo.jpg").write_bytes(b"part+gps")
    old(box / "photo.jpg")

    def more(p):                                                     # the copy in goes on meanwhile
        with open(box / "photo.jpg", "ab") as f:
            f.write(b"+more")
        hooks.clear()
    hooks.append(more)
    run()
    run()
    up = T.uploads_dir(host, "tor-browser")
    assert list(up.iterdir()) == [] and (box / "photo.jpg").exists() and not list((box / "Originals").iterdir())
    assert T.recent("tor-browser") == []                             # nothing said: it is still arriving
    old(box / "photo.jpg")
    run()
    run()
    assert (up / "photo.jpg").read_bytes() == b"part+more"


def test_partial_copies_are_left_alone_and_counted_apart_and_unreadable_files_don_t_wait_for_ever(host, outbox):
    box, run, _ = outbox
    (box / "film.mp4.part").write_bytes(b"p")
    (box / "notes.txt~").write_bytes(b"n")
    (box / "locked.jpg").write_bytes(b"l+gps")
    for n in ("film.mp4.part", "notes.txt~", "locked.jpg"):
        old(box / n)
    v = T.outbox_view(host, "tor-browser", "Tor Browser")
    assert v["waiting"] == 1 and v["partial"] == 2
    if os.geteuid() != 0:
        os.chmod(box / "locked.jpg", 0)
        run()
        run()
        assert (box / "Not cleaned/locked.jpg").exists()
        v = T.outbox_view(host, "tor-browser", "Tor Browser")
        assert v["waiting"] == 0 and v["partial"] == 2 and v["not_cleaned"] == ["locked.jpg"]
        assert "can't be read" in T.recent("tor-browser")[0]["detail"]
    assert (box / "film.mp4.part").exists() and (box / "notes.txt~").exists()


def test_closing_the_disk_stops_the_tempoutbox_after_the_file_under_way(host, outbox):
    """Quitting waited for a whole pass, every file's mat2 (up to 300 s each), under OUTBOX_LOCK."""
    box, run, hooks = outbox
    for n in ("a.jpg", "b.jpg", "c.jpg"):
        (box / n).write_bytes(b"x+gps")
        old(box / n)
    run()
    hooks.append(lambda p: T.STOP.set())
    try:
        run()
    finally:
        T.STOP.clear()
    assert sorted(x.name for x in T.uploads_dir(host, "tor-browser").iterdir()) == ["a.jpg"]
    assert (box / "b.jpg").exists() and (box / "c.jpg").exists()


def test_the_page_shows_partial_copies_apart():
    import inspect as _inspect
    from daprivacyscanner.tools import browser as B
    assert "transfer.STOP.set()" in _inspect.getsource(B.wipe_disk)
    js = (Path(__file__).resolve().parents[1] / "src/daprivacyscanner/web/app.js").read_text()
    assert "o.partial ?" in js and "b.outbox.partial" in js


# ------------------------------------------------------------------ C1, C3, C7, C9: View offline… with a Flatpak

PAPERS = ("org.gnome.Papers.desktop", "/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=papers "
          "--file-forwarding org.gnome.Papers @@u %U @@", "X-Flatpak=org.gnome.Papers\n")


def private_of(host) -> Path:
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    return private


def flatpak_ps(host, running: str = "", ok: bool = True):
    from daprivacyscanner.host import CommandResult
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(
        tuple(argv), 0 if ok or argv[1] != "ps" else 1, running if argv[1] == "ps" else "")


def listed(host) -> str:
    return T.downloads(host, "tor-browser")[0][0].check


def test_a_flatpak_viewer_already_open_isn_t_handed_the_file(host):
    """Live on Mint: with Text Editor (or Firefox) from Flatpak already open, `flatpak run --unshare=network` handed the
    file over the session bus to that copy, which has its network and keeps what it opens (Text Editor recorded it in
    its recently-used.xbel and session; Firefox fetched the page's pictures and wrote it into places.sqlite)."""
    from test_viewer import set_up
    from test_browser_sandbox import Proc
    from daprivacyscanner.tools import viewer as V
    set_up(host, *PAPERS)
    flatpak_ps(host, "123\torg.gnome.Papers\n")
    calls = []
    with pytest.raises(V.ViewError, match="Document Viewer is already open: .*with its network.*Close Document Viewer first"):
        V.view(host, "tor-browser", "report.pdf", private_of(host), lambda argv, **kw: calls.append(argv) or Proc(),
               listed(host))
    assert calls == [] and not list((host.home / "TempBrowser").glob(".view-*/*"))         # nothing copied stays
    flatpak_ps(host, "", ok=False)
    with pytest.raises(V.ViewError, match="couldn't be told"):
        V.view(host, "tor-browser", "report.pdf", private_of(host), lambda argv, **kw: calls.append(argv) or Proc(),
               listed(host))
    flatpak_ps(host, "77\torg.mozilla.firefox\n")                                         # another app: fine
    V.view(host, "tor-browser", "report.pdf", private_of(host), lambda argv, **kw: calls.append(argv) or Proc(),
           listed(host))
    assert len(calls) == 1


def test_one_view_offline_opened_is_named_as_such(host, monkeypatch):
    from test_viewer import set_up
    from daprivacyscanner.tools import viewer as V
    set_up(host, *PAPERS)
    monkeypatch.setitem(V._LAUNCHED, os.getpid(), "Document Viewer")    # a pid that runs: this process, standing in
    flatpak_ps(host, f"{os.getpid()}\torg.gnome.Papers\n")
    with pytest.raises(V.ViewError, match=r"already open from an earlier View offline…: .*Close it first"):
        V.view(host, "tor-browser", "report.pdf", private_of(host), lambda argv, **kw: None, listed(host))


@pytest.mark.parametrize("desktop_id, exec_, extra", [
    ("org.mozilla.firefox.desktop", "/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=firefox "
     "--file-forwarding org.mozilla.firefox @@u %u @@", "X-Flatpak=org.mozilla.firefox\nCategories=Network;\n"),
    ("org.example.Surf.desktop", "/usr/bin/flatpak run org.example.Surf %u",
     "X-Flatpak=org.example.Surf\nCategories=Network;WebBrowser;\n"),
])
def test_a_browser_from_flatpak_isn_t_used_as_a_viewer(host, desktop_id, exec_, extra):
    """Firefox-family and Chromium-family browsers hand what they open to a copy already running and keep their
    state where the app can't keep it in memory: say what to choose instead."""
    from test_viewer import set_up
    from daprivacyscanner.tools import viewer as V
    set_up(host, desktop_id, exec_, extra)
    flatpak_ps(host)
    with pytest.raises(V.ViewError, match="is a web browser.*Choose a document viewer"):
        V.plan(host, "tor-browser", "report.pdf")


def test_a_native_browser_is_still_fine(host):
    """From the distribution's packages it runs in the app's own sandbox, with an empty home in memory."""
    from test_viewer import set_up
    from daprivacyscanner.tools import viewer as V
    set_up(host, "firefox.desktop", "xreader %u", "Categories=Network;WebBrowser;\n")
    assert V.plan(host, "tor-browser", "report.pdf").argv == ["/usr/bin/xreader", "/home/user/report.pdf"]


def test_the_plan_shows_where_a_flatpak_viewer_will_find_the_copy(host):
    """The confirmation showed `@@u /home/user/report.pdf @@` while the run passed ~/TempBrowser/.view-…/report.pdf."""
    from test_viewer import set_up
    from daprivacyscanner.tools import viewer as V
    set_up(host, *PAPERS)
    flatpak_ps(host)
    shown = V.plan(host, "tor-browser", "report.pdf").to_dict()["command"]
    where = f"{host.home}/TempBrowser/.view-<random>"
    assert f"'--filesystem={where}:ro'" in shown and shown.endswith(f"'{where}/report.pdf'")
    assert "@@" not in shown and "/home/user/report.pdf" not in shown


def test_without_a_display_a_flatpak_viewer_isn_t_started(host):
    from test_viewer import set_up
    from daprivacyscanner.tools import viewer as V
    set_up(host, *PAPERS)
    flatpak_ps(host)
    host.environ.pop("WAYLAND_DISPLAY", None)
    host.environ.pop("DISPLAY", None)
    with pytest.raises(V.ViewError, match="no display"):
        V.plan(host, "tor-browser", "report.pdf")
    host.environ["DISPLAY"] = ":0"
    argv = V.plan(host, "tor-browser", "report.pdf").argv
    assert "--socket=x11" in argv and "--share=ipc" in argv and "--socket=wayland" not in argv


# ------------------------------------------------------------------ suspicions: copies, the keeper

def test_an_earlier_view_s_copy_stays_while_its_viewer_runs_or_is_new(host, monkeypatch):
    """A viewer may read its copy and close it (and read it again later), and one starting a second ago hasn't opened
    it yet: the next view removed both. Copies stay while their viewer runs, and for a minute when nothing says."""
    import time
    from test_viewer import set_up
    from daprivacyscanner.tools import viewer as V
    set_up(host)
    base = host.home / "TempBrowser"
    for name in (".view-running", ".view-ended", ".view-fresh", ".view-stale"):
        (base / name).mkdir()
        (base / name / "x.pdf").write_bytes(b"x")
    t = time.time() - 120
    for name in (".view-running", ".view-ended", ".view-stale"):
        os.utime(base / name, (t, t))
    monkeypatch.setitem(V._VIEWS, ".view-running", os.getpid())
    monkeypatch.setitem(V._VIEWS, ".view-ended", 4_194_400)
    monkeypatch.setitem(V._LAUNCHED, os.getpid(), "Document Viewer")
    path, fd = V._staging(host)
    os.close(fd)
    assert sorted(x.name for x in base.glob(".view-*")) == sorted([".view-running", ".view-fresh", path.name])


@pytest.fixture
def bwrap_here():
    import shutil
    import subprocess
    b = shutil.which("bwrap")
    if not b or not os.path.exists("/usr/bin/python3") or subprocess.run(
            [b, "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--", "true"]).returncode:
        pytest.skip("bubblewrap can't run here")
    return b


def _descendants(pid: int) -> set[int]:
    kids: dict[int, list[int]] = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                with open(f"/proc/{p}/stat") as f:
                    ppid = int(f.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                continue
            kids.setdefault(ppid, []).append(int(p))
    out, todo = set(), [pid]
    while todo:
        for c in kids.get(todo.pop(), []):
            if c not in out:
                out.add(c)
                todo.append(c)
    return out


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _wait(cond, timeout=5.0) -> bool:
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


@pytest.mark.parametrize("victim", ["keeper", "bubblewrap"])
def test_ending_any_part_of_a_viewer_s_sandbox_ends_all_of_it(bwrap_here, victim):
    """A SIGTERM to bubblewrap left its init (the sandbox's PID 1, which ignores one from outside) and the viewer
    running, out of the app's sight. Under the keeper, with --die-with-parent, ending either ends the viewer."""
    import signal
    import subprocess
    from daprivacyscanner.tools import viewer as V
    p = subprocess.Popen(["/usr/bin/python3", "-I", "-c", V.KEEPER, bwrap_here, "--unshare-all", "--die-with-parent",
                          "--ro-bind", "/", "/", "--", "sleep", "60"], start_new_session=True)
    try:
        assert _wait(lambda: len(_descendants(p.pid)) >= 3)                # bubblewrap, its init, the viewer
        tree = _descendants(p.pid)
        outer = min(tree, key=lambda x: len(_descendants(x)) * -1)         # the one with the most below it
        os.kill(p.pid if victim == "keeper" else outer, signal.SIGTERM)
        assert _wait(lambda: not any(_alive(x) for x in tree))
    finally:
        p.kill()
        p.wait()


def test_quitting_the_app_leaves_an_open_viewer_open(bwrap_here):
    """The keeper, not the app, is bubblewrap's parent: the app ending doesn't end the viewer."""
    import signal
    import subprocess
    import time
    from daprivacyscanner.tools import viewer as V
    app = ("import subprocess, sys; p = subprocess.Popen(sys.argv[1:], start_new_session=True, stdin=subprocess.DEVNULL, "
           "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print(p.pid, flush=True)")
    out = subprocess.run(["/usr/bin/python3", "-c", app, "/usr/bin/python3", "-I", "-c", V.KEEPER, bwrap_here,
                          "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--", "sleep", "60"],
                         capture_output=True, text=True, timeout=10)
    keeper = int(out.stdout.split()[0])
    try:
        assert _wait(lambda: len(_descendants(keeper)) >= 3)
        time.sleep(0.3)
        assert _alive(keeper) and len(_descendants(keeper)) >= 3           # the "app" has ended: still there
    finally:
        tree = _descendants(keeper)
        os.kill(keeper, signal.SIGTERM)
        _wait(lambda: not any(_alive(x) for x in tree | {keeper}))


def test_a_native_viewer_runs_under_the_keeper_where_there_is_python3(host):
    from test_viewer import set_up
    from test_browser_sandbox import Proc
    from daprivacyscanner.tools import viewer as V
    set_up(host)
    (host.root / "usr/bin/python3").write_text("")
    calls = []
    got = V.view(host, "tor-browser", "report.pdf", private_of(host), lambda argv, **kw: calls.append(argv) or Proc(),
                 listed(host))
    [argv] = calls
    k = argv.index(V.KEEPER)
    assert argv[k - 3:k] == ["/usr/bin/python3", "-I", "-c"]
    assert argv[k + 1] == "bwrap" and argv[k + 2] == "--args"
    assert "--die-with-parent" in got["whole"] and "os.fork()" in got["whole"]


@pytest.mark.parametrize("flatpak, says", [(False, "closed at once without showing it.*close that one first"),
                                            (True, "closed at once. If it was opened meanwhile.*with its network")])
def test_a_viewer_that_ends_at_once_says_so(host, monkeypatch, flatpak, says):
    """xreader with one already open from an earlier view ended at once, showing nothing, while the page said it was
    opening (tested on Mint 22.3); a Flatpak viewer that ends at once may have handed the file to a copy opened
    meanwhile."""
    from test_viewer import set_up
    from test_browser_sandbox import Proc
    from daprivacyscanner.tools import viewer as V
    monkeypatch.setattr(V, "WATCH", 0.05)
    set_up(host, *(PAPERS if flatpak else ()))
    flatpak_ps(host)
    with pytest.raises(V.ViewError, match=says):
        V.view(host, "tor-browser", "report.pdf", private_of(host), lambda argv, **kw: Proc(rc=0), listed(host))
