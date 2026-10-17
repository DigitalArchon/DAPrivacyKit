"""What does this app keep?: what the tools review of 2026-10-17 found (D1 to D13 and the suspicions it confirmed),
each with the test that keeps it fixed. The watch itself needs root and the real kernel: what it does there was
tried on the lab machines; here, its parts."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pytest

from daprivacyscanner.host import FakeRunner, Host
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
