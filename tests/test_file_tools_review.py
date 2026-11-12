"""The file tools' wording and judgement (the review of 2026-11-12): what the RAM disk's overwrite reaches, Office
macros found by type rather than name, and the TRIM test's answers where it can't see everything."""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from daprivacyscanner.tools import ramdisk, sniff
from daprivacyscanner.tools import trimtest as T

from conftest import make_host
from test_trimtest import root, run, small  # noqa: F401 - the fixtures


# ------------------------------------------------------------------ the RAM disk's overwrite

@pytest.mark.parametrize("cmdline, on", [("ro quiet", False), ("ro init_on_free=1", True), ("init_on_free=on", True),
                                         ("init_on_free=1 init_on_free=0", False), ("xinit_on_free=1", False),
                                         ("init_on_free=Y splash", True)])
def test_init_on_free_is_read_as_the_kernel_reads_it(tmp_path, cmdline, on):
    host = make_host(tmp_path, files={"/proc/cmdline": cmdline + "\n", "/proc/swaps": "Filename Type\n"})
    assert ramdisk.init_on_free(host) is on
    st = ramdisk.status(host)
    assert st.to_dict(host.home)["init_on_free"] is on
    assert any("deleted or replaced" in n for n in st.notes) is on


def test_the_close_dialog_says_what_the_overwrite_doesnt_reach():
    """Zeroing a file in place reaches the files still there: not what was deleted or replaced while it was open (a
    save that writes a new copy frees the old one's pages as they are), nor programs' own memory."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "src/daprivacyscanner/web/app.js").read_text()
    body = js[js.index("function closeRamdisk("):js.index("// ------------------------------------------------------------------ Before you hand over")]
    assert "files deleted or replaced while it was open" in body and "what programs keep in their own memory" in body
    assert 'checkChip("kern.init_on_free"' in body and "rd.init_on_free" in body
    assert "Every file still in" in body


# ------------------------------------------------------------------ Office macros, by type

def office(parts: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():
            z.writestr(name, text)
    return buf.getvalue()


TYPES = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
         '<Default Extension="xml" ContentType="application/xml"/>{}</Types>')
PLAIN = TYPES.format('<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.'
                     'wordprocessingml.document.main+xml"/>')


def inspected(tmp_path, data: bytes, name: str):
    p = tmp_path / name
    p.write_bytes(data)
    fd = os.open(p, os.O_RDONLY)
    try:
        return sniff.inspect(fd, name, len(data))
    finally:
        os.close(fd)


def test_a_vba_project_under_another_name_is_found_by_its_content_type(tmp_path):
    renamed = TYPES.format('<Override PartName="/word/data7.dat" ContentType="application/vnd.ms-office.vbaProject"/>')
    ins = inspected(tmp_path, office({"[Content_Types].xml": renamed, "word/document.xml": "<w/>",
                                      "word/data7.dat": "VBA"}), "letter.docx")
    assert any(w.startswith("contains macros") for w in ins.warnings)
    # or only by the relationship to it
    rels = ('<Relationships><Relationship Id="rId9" Type="http://schemas.microsoft.com/office/2006/relationships/'
            'vbaProject" Target="x.bin"/></Relationships>')
    ins = inspected(tmp_path, office({"[Content_Types].xml": PLAIN, "word/_rels/document.xml.rels": rels,
                                      "word/x.bin": "VBA"}), "letter2.docx")
    assert any(w.startswith("contains macros") for w in ins.warnings)
    # a plain document says nothing of macros
    ins = inspected(tmp_path, office({"[Content_Types].xml": PLAIN, "word/document.xml": "<w/>"}), "plain.docx")
    assert ins.kind == "document" and not any("macro" in w for w in ins.warnings)


def test_excel_4_macro_sheets_and_activex_are_named(tmp_path):
    xlm = TYPES.format('<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.'
                       'macrosheet+xml"/>')
    ins = inspected(tmp_path, office({"[Content_Types].xml": xlm, "xl/macrosheets/sheet1.xml": "<m/>"}), "budget.xlsx")
    assert any("Excel 4.0 macro sheets" in w for w in ins.warnings)
    ax = TYPES.format('<Override PartName="/word/activeX/activeX1.xml" ContentType="application/vnd.ms-office.activeX+xml"/>')
    ins = inspected(tmp_path, office({"[Content_Types].xml": ax}), "form.docx")
    assert any("ActiveX" in w for w in ins.warnings)


def test_what_is_read_of_an_office_file_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(sniff, "OOXML_PART", 64)
    late = TYPES.format(" " * 200 + '<Override PartName="/a" ContentType="application/vnd.ms-office.vbaProject"/>')
    ins = inspected(tmp_path, office({"[Content_Types].xml": late}), "big.docx")
    assert not any(w.startswith("contains macros") for w in ins.warnings)        # past what is read: not looked at


# ------------------------------------------------------------------ the TRIM test

def test_a_clean_rescan_without_the_discard_counts_is_inconclusive(root, small, monkeypatch):  # noqa: F811
    """drive_discards None (the counters unreadable) fell through to a pass: a clean rescan with no discards known
    to have reached the drive may be blocks overwritten, not trimmed."""
    monkeypatch.setattr(T, "snapshot", lambda host, t: {})
    r, *_ = run(root)
    assert r["verdict"] == "inconclusive" and "whether TRIM reached the drive couldn't be seen" in r["headline"]
    assert any("counts couldn't be read" in p for p in r["explanation"])


def test_a_few_survivors_of_a_trim_that_arrived_dont_read_as_trim_not_working(root, small):  # noqa: F811
    """Some blocks left at the edges of what was freed, on a drive that ignores discards smaller than its own unit:
    the headline said "TRIM isn't clearing deleted data here"."""
    r, *_ = run(root, keep_small=True)                      # ext4: the small files' blocks survive, the rest are trimmed
    assert r["verdict"] == "fail" and r["headline"].startswith("TRIM cleared most of the deleted test data, but not all")
    assert any("smaller than its own internal unit" in p for p in r["explanation"])
    r, *_ = run(root, trims=False)
    assert r["headline"].startswith("TRIM isn't clearing deleted data here")


# ------------------------------------------------------------------ malformed packages and files (property tests' finds)

def test_an_ar_member_size_that_isnt_a_count_is_refused(tmp_path):
    """A size field of "-60" kept the reader on the same header for ever, the list growing."""
    from daprivacyscanner.tools import packages as P
    head = lambda name, size: f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{size:<10}`\n".encode()  # noqa: E731
    deb = tmp_path / "x.deb"
    for size in ("-60", "+5", "1e3", "999999"):
        deb.write_bytes(b"!<arch>\n" + head("debian-binary", size) + b"2.0\n")
        with pytest.raises(P.PackageError, match="member size"):
            P.ar_members(deb)


def test_rpm_values_of_the_wrong_kind_are_refused(tmp_path):
    """An INT32 signature tag reached write_bytes(int), a STRING digest algorithm was looked up as a dict key:
    TypeError, which Verify didn't catch."""
    import struct
    from daprivacyscanner.tools import packages as P
    from test_verify_packages import header
    work = tmp_path / "w"
    work.mkdir()

    def rpm(sig_tags, main_tags):
        sighdr = header(sig_tags)
        sighdr += b"\0" * (-len(sighdr) % 8)
        p = tmp_path / "app-1.0-1.x86_64.rpm"
        p.write_bytes(b"\xed\xab\xee\xdb" + b"\0" * 92 + sighdr + header(main_tags) + b"payload")
        return p
    with pytest.raises(P.PackageError, match="wrong kind"):
        P.rpm(rpm([(1002, 4, struct.pack(">I", 7), 1)], [(1000, 6, b"app\0", 1)]), work)
    with pytest.raises(P.PackageError, match="wrong kind"):
        P.rpm(rpm([(268, 7, b"sig", 3)], [(5092, 8, b"ab\0", 1), (5093, 6, b"sha256\0", 1)]), work)


def test_a_zip_whose_mimetype_wont_unpack_is_an_archive(tmp_path):
    """zlib.error escaped from a mimetype entry deflated with broken data."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text" * 20)
    data = bytearray(buf.getvalue())
    start = 30 + len("mimetype")                         # the local header, then the deflated data
    data[start:start + 8] = b"\xff" * 8
    ins = inspected(tmp_path, bytes(data), "letter.odt")
    assert ins.kind == "archive"


def test_a_program_is_named_as_a_program_whatever_else_it_carries(tmp_path):
    elf = bytearray(b"\x7fELF" + b"\0" * 0x9000)
    elf[257:262] = b"ustar"
    assert inspected(tmp_path, bytes(elf), "notes.tar").kind == "program"
    elf = bytearray(b"\x7fELF" + b"\0" * 0x9000)
    elf[0x8001:0x8006] = b"CD001"
    ins = inspected(tmp_path, bytes(elf), "photos.iso")
    assert ins.kind == "program" and ins.what == "a Linux program"


def test_an_ipv6_connection_behind_a_hop_by_hop_header_is_counted():
    from test_pcap_review import ME6, eth6, feed, ip6
    from test_trial import tcp
    hop = bytes([6, 0]) + b"\0" * 6                      # hop-by-hop options, then TCP
    hosts = feed([eth6(ip6(ME6, "2001:db8::7", 0, hop + tcp(5000, 443, 0x02)))])
    assert hosts["2001:db8::7"]["ports"] == ["443"]
