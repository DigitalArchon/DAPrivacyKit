"""What does this app keep?: what the tools review of 2026-10-17 found (D1 to D13 and the suspicions it confirmed),
each with the test that keeps it fixed. The watch itself needs root and the real kernel: what it does there was
tried on the lab machines; here, its parts."""

from __future__ import annotations

import struct
import zlib

from daprivacyscanner.tools import activity as A


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
