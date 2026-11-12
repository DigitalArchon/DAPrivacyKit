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
