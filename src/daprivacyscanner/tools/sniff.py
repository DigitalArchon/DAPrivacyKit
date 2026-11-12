"""What a file from the browser really is (docs/TECHNICAL.md, Tools: Tor or Mullvad Browser in memory): judged by
its content, not only its name, before the user saves or opens it. A taken-over or tricked browser can save a
program as "invoice.pdf"; the file manager would then run or mount it by what it is.

Read-only, from an open file descriptor (never a path that could be swapped), at most SCAN_LIMIT bytes:
- the first bytes: ELF, Windows (MZ), Mach-O and Java programs, scripts (#!), desktop launchers, Windows
  shortcuts, disk images (ISO 9660 and UDF at 32 KiB, DMG's trailer, qcow2, VHDX, VMDK), archives (zip, 7z,
  RAR, gzip, xz, bzip2, zstd, cabinet, tar), PDF, HTML and SVG, old Office (OLE2), pictures;
- inside a ZIP-based file, its index: Android apps and Java programs, Office (OOXML) and OpenDocument files,
  EPUB, and for an archive the programs it holds;
- macros: OOXML's VBA project (vbaProject.bin, or a part of any name by its content type or the relationship to
  it), Excel 4.0 macro sheets and ActiveX controls (from [Content_Types].xml and the .rels parts, each read
  bounded), OLE2's _VBA_PROJECT stream, OpenDocument's Basic and Scripts folders; in a
  PDF, JavaScript, /Launch and embedded files (a PDF's objects can be compressed, so finding none proves
  nothing, and the page never says it is safe).
Then the name: a program or launcher whose name says otherwise is named as such ("its name says pdf"), and
names the content can't confirm keep their own warnings (a disk image or macros by extension)."""

from __future__ import annotations

import os
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO

SCAN_LIMIT = 16 * 1024 * 1024          # bytes read looking for macros or a PDF's actions
HEAD = 4096
ZIP_ENTRIES = 20_000                   # a ZIP's index is read only up to this many entries
ZIP_INDEX = 2 * 1024 * 1024            # and this many bytes (an entry takes 46 bytes and its name: 45,000 at most)

RUNS = re.compile(r"\.(desktop|sh|bash|zsh|run|bin|appimage|exe|msi|bat|cmd|com|scr|ps1|vbs|jar|py|pl|rb|deb|rpm|"
                  r"apk|flatpakref|flatpakrepo|flatpak|snap|pkg|lnk|hta|js|elf|so|reg|msc|cpl|application|appx|"
                  r"msix|url|webloc|wsf)$", re.I)
DISK_IMAGE = re.compile(r"\.(iso|img|dmg|vhdx?|vmdk|qcow2|ova)$", re.I)
ARCHIVE = re.compile(r"\.(zip|7z|rar|tar|t?gz|t?xz|t?bz2|zst|cab|lzh|arj)$", re.I)
MACROS = re.compile(r"\.(docm|dotm|xlsm|xltm|xlam|pptm|potm|ppam|sldm)$", re.I)
# documents that can fetch things from the internet when opened, so reveal the real address
FETCHES = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp|odg|rtf|html?|xhtml|svg|epub|xps|mhtml?|eml|"
                     r"docm|dotm|xlsm|pptm)$", re.I)
PICTURE = re.compile(r"\.(jpe?g|png|gif|webp|avif|bmp|tiff?)$", re.I)
TEXT = re.compile(r"\.(txt|md|csv|log)$", re.I)

RUNS_TEXT = "runs as a program when opened: open it only if you trust where it came from"
FETCH_TEXT = ("can fetch things from the internet when opened, which reveals your real address: View offline… "
              "opens it with no network")
FETCH_TEXT_PLAIN = ("can fetch things from the internet when opened, which reveals your real address: open it with "
                    "the network off")


@dataclass
class Inspection:
    kind: str                           # program, disk image, archive, document, picture, text, unknown
    what: str = ""                      # "a Linux program", "a PDF"
    warnings: list[str] = field(default_factory=list)
    mime: str | None = None             # for choosing a viewer
    viewable: bool = False              # a document or picture: View offline… can open it

    def to_dict(self) -> dict:
        return {"kind": self.kind, "what": self.what, "warnings": self.warnings, "viewable": self.viewable}


_MAGIC = (
    (b"\x7fELF", "program", "a Linux program"),
    (b"\xcf\xfa\xed\xfe", "program", "a Mac program"), (b"\xce\xfa\xed\xfe", "program", "a Mac program"),
    (b"\xca\xfe\xba\xbe", "program", "a Mac or Java program"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "program", "a Windows shortcut"),
    (b"QFI\xfb", "disk image", "a disk image (qcow2)"), (b"vhdxfile", "disk image", "a disk image (VHDX)"),
    (b"KDMV", "disk image", "a disk image (VMDK)"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "a 7-Zip archive"), (b"Rar!\x1a\x07", "archive", "a RAR archive"),
    (b"\x1f\x8b", "archive", "a gzip archive"), (b"\xfd7zXZ\x00", "archive", "an xz archive"),
    (b"BZh", "archive", "a bzip2 archive"), (b"\x28\xb5\x2f\xfd", "archive", "a zstd archive"),
    (b"MSCF", "archive", "a cabinet archive"),
    (b"%PDF", "pdf", "a PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "an Office document (old format)"),
    (b"\xff\xd8\xff", "picture", "a JPEG picture"), (b"\x89PNG\r\n\x1a\n", "picture", "a PNG picture"),
    (b"GIF87a", "picture", "a GIF picture"), (b"GIF89a", "picture", "a GIF picture"),
)
_MIME = {"pdf": "application/pdf", "a JPEG picture": "image/jpeg", "a PNG picture": "image/png",
         "a GIF picture": "image/gif"}


def _read(fd: int, size: int, offset: int) -> bytes:
    try:
        return os.pread(fd, size, offset)
    except OSError:
        return b""


def _scan(fd: int, size: int, *needles: bytes) -> set[bytes]:
    """Which of `needles` appear in the first SCAN_LIMIT bytes (read in pieces that overlap)."""
    found: set[bytes] = set()
    pos, tail = 0, b""
    longest = max(len(n) for n in needles)
    while pos < min(size, SCAN_LIMIT) and len(found) < len(needles):
        chunk = _read(fd, 1 << 20, pos)
        if not chunk:
            break
        data = tail + chunk
        found |= {n for n in needles if n in data}
        tail, pos = data[-longest:], pos + len(chunk)
    return found


def _desktop_entry(head: bytes) -> bool:
    for line in head.splitlines():
        s = line.strip()
        if not s or s.startswith(b"#"):
            continue
        return s == b"[Desktop Entry]"
    return False


def _zip_index(f: BinaryIO) -> tuple[int, int] | None:
    """(how many entries, how many bytes) the ZIP's index says it has, from its end record (ZIP64's where it says
    so), read as zipfile reads it (its own _EndRecData: what it would then load); None when there is none."""
    try:
        # zipfile's own private reader and offsets, on purpose (typeshed doesn't declare them): a Python without them
        # raises AttributeError, caught below
        end = zipfile._EndRecData(f)  # type: ignore[attr-defined]
        return (int(end[zipfile._ECD_ENTRIES_TOTAL]),  # type: ignore[attr-defined]
                int(end[zipfile._ECD_SIZE])) if end else None  # type: ignore[attr-defined]
    except (AttributeError, IndexError, TypeError, ValueError, OSError, zipfile.BadZipFile):
        return None


OOXML_PART = 256 * 1024                # what is read of [Content_Types].xml and of each relationships part, unpacked
OOXML_RELS = 200                       # relationships parts read at most
# what in an Office (OOXML) file's content types or relationships says it holds code, whatever its parts are named:
# the VBA project (a part of any name, found by its content type or the relationship to it), the macro-enabled main
# parts, Excel 4.0 (XLM) macro sheets, and ActiveX controls (ECMA-376 and [MS-OFFMACRO2], [MS-XLSX], [MS-OI29500])
OOXML_MACROS = {
    "vba": (b"application/vnd.ms-office.vbaproject", b"/relationships/vbaproject", b"macroenabled",
            b"application/vnd.ms-excel.addin.macroenabled"),
    "xlm": (b"application/vnd.ms-excel.macrosheet", b"application/vnd.ms-excel.intlmacrosheet",
            b"/relationships/xlmacrosheet", b"/relationships/xlintlmacrosheet"),
    "activex": (b"application/vnd.ms-office.activex", b"/relationships/activexcontrol"),
}


def _ooxml_parts(z: zipfile.ZipFile, names: list[str]) -> bytes:
    """An Office file's content types and relationships, lower-cased, read bounded (at most OOXML_PART of each, as
    unpacked, from OOXML_RELS relationships parts): what its parts are, by type rather than by name. A VBA project
    renamed (word/vbaProject.bin is only the usual name) was found by neither, and macro sheets not at all."""
    out = []
    wanted = [n for n in names if n.lower() == "[content_types].xml"] + \
        [n for n in names if n.lower().endswith(".rels")][:OOXML_RELS]
    for n in wanted:
        try:
            with z.open(n) as part:
                out.append(part.read(OOXML_PART).lower())
        except (zipfile.BadZipFile, OSError, KeyError, ValueError, RuntimeError, NotImplementedError, EOFError,
                zlib.error):
            continue
    return b"\n".join(out)


def _zip(fd: int, name: str) -> Inspection:
    try:
        with os.fdopen(os.dup(fd), "rb") as f:
            # zipfile loads the whole index before anything can be asked of it: a ZIP of a million entries took 3.6 s
            # and 534 MB, three million 11 s and 1.6 GB (the 2026-10-17 review), and it stays small compressed. So
            # the index's size comes from the end record first, and a larger one isn't read: an archive, unchecked.
            index = _zip_index(f)
            if index is None:
                return Inspection("archive", "a ZIP archive")
            if index[0] > ZIP_ENTRIES or index[1] > ZIP_INDEX:
                return Inspection("archive", "a ZIP archive", [f"its list of contents is too long to look through "
                                                              f"(it says it holds {index[0]:,} files)"])
            f.seek(0)
            with zipfile.ZipFile(f) as z:
                names = z.namelist()[:ZIP_ENTRIES]
                mimetype = ""
                if "mimetype" in names:
                    with z.open("mimetype") as m:             # its first bytes only: a huge entry isn't unpacked
                        mimetype = m.read(100).decode("ascii", "replace").strip()
                office = _ooxml_parts(z, names) if any(n.lower() == "[content_types].xml" for n in names) else b""
    except (zipfile.BadZipFile, OSError, KeyError, ValueError, RuntimeError, NotImplementedError, EOFError, zlib.error):
        return Inspection("archive", "a ZIP archive")            # a broken deflate stream raises zlib.error
    lower = [n.lower() for n in names]
    if "androidmanifest.xml" in lower or "classes.dex" in lower:
        return Inspection("program", "an Android app")
    if "meta-inf/manifest.mf" in lower and any(n.endswith(".class") for n in lower):
        return Inspection("program", "a Java program")
    if "[content_types].xml" in lower:
        ins = Inspection("document", "an Office document", viewable=True)
        found = {k for k, marks in OOXML_MACROS.items() if any(m in office for m in marks)}
        if any(n.endswith("vbaproject.bin") for n in lower) or "vba" in found:
            ins.warnings.append("contains macros (programs that run in the office suite): open it with macros "
                                "turned off, or not at all")
        if "xlm" in found:
            ins.warnings.append("contains Excel 4.0 macro sheets (old-style macros, which run in the spreadsheet even "
                                "where newer macros are blocked): open it with macros turned off, or not at all")
        if "activex" in found:
            ins.warnings.append("contains ActiveX controls (programs the office suite can start): open it with them "
                                "turned off, or not at all")
        return ins
    if mimetype.startswith("application/vnd.oasis.opendocument"):
        ins = Inspection("document", "an OpenDocument file", mime=mimetype, viewable=True)
        if any(re.match(r"(basic/[^/]+/(?!script-lb|dialog-lb)[^/]+\.xml|scripts/.+)$", n) for n in lower):
            ins.warnings.append("contains macros or scripts (programs that run in the office suite): open it with "
                                "macros turned off, or not at all")
        return ins
    if mimetype == "application/epub+zip":
        return Inspection("document", "an e-book (EPUB)", mime=mimetype, viewable=True)
    ins = Inspection("archive", "a ZIP archive")
    runs = [n for n in names if RUNS.search(n) or DISK_IMAGE.search(n)]
    if runs:
        shown = ", ".join(os.path.basename(n.rstrip("/")) for n in runs[:3]) + (" …" if len(runs) > 3 else "")
        ins.warnings.append(f"it holds files that run as programs ({shown})")
    return ins


def _content(fd: int, size: int, name: str) -> Inspection:
    head = _read(fd, HEAD, 0)
    if head.startswith(b"#!"):
        return Inspection("program", "a script")
    if _desktop_entry(head):
        return Inspection("program", "a desktop launcher")
    if head.startswith(b"MZ") and size >= 64:
        return Inspection("program", "a Windows program")
    # a program is named as one first, whatever else it also carries: an ELF with "ustar" at byte 257, or "CD001"
    # at 32 KiB, was called a tar archive or a disk image, and its warnings weren't a program's
    for magic, kind, what in _MAGIC:
        if kind == "program" and head.startswith(magic):
            return Inspection(kind, what)
    if _read(fd, 5, 0x8001) in (b"CD001", b"BEA01") or (size >= 512 and _read(fd, 4, size - 512) == b"koly"):
        return Inspection("disk image", "a disk image")
    if head[257:262] == b"ustar":
        return Inspection("archive", "a tar archive")
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _zip(fd, name)
    for magic, kind, what in _MAGIC:
        if head.startswith(magic):
            if kind == "pdf":
                ins = Inspection("document", what, mime="application/pdf", viewable=True)
                found = _scan(fd, size, b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile")
                if found & {b"/JavaScript", b"/JS"}:
                    ins.warnings.append("contains JavaScript, which some PDF viewers run when it opens")
                if b"/Launch" in found:
                    ins.warnings.append("asks to start programs when it opens (/Launch)")
                if b"/EmbeddedFile" in found:
                    ins.warnings.append("carries other files inside it")
                return ins
            if kind == "ole":
                ins = Inspection("document", what, viewable=True)
                if _scan(fd, size, "_VBA_PROJECT".encode("utf-16-le")):
                    ins.warnings.append("contains macros (programs that run in the office suite): open it with "
                                        "macros turned off, or not at all")
                return ins
            if kind == "picture":
                return Inspection("picture", what, mime=_MIME.get(what), viewable=True)
            return Inspection(kind, what)
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return Inspection("picture", "a WebP picture", mime="image/webp", viewable=True)
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith(b"<") and (b"<svg" in text):
        return Inspection("document", "an SVG picture", mime="image/svg+xml", viewable=True)
    if text.startswith(b"<") and (b"<html" in text or b"<!doctype html" in text):
        return Inspection("document", "a web page", mime="text/html", viewable=True)
    if head and b"\x00" not in head:
        if re.search(r"\.(html?|xhtml|mhtml?)$", name, re.I):
            return Inspection("document", "a web page", mime="text/html", viewable=True)
        return Inspection("text", "text", mime="text/plain", viewable=bool(TEXT.search(name)))
    return Inspection("unknown")


def _ext(name: str) -> str:
    ext = os.path.splitext(name)[1]
    return ext[1:].lower() if ext and len(ext) <= 8 else ""


def inspect(fd: int, name: str, size: int) -> Inspection:
    """What the open file `fd` (named `name`, `size` bytes) is, and what to say before it is saved or opened."""
    ins = _content(fd, size, name)
    ext, out = _ext(name), []
    if ins.kind == "program":
        if RUNS.search(name):
            out.append(RUNS_TEXT)
            inner = os.path.splitext(os.path.splitext(name)[0])[1]
            if inner and (FETCHES.search(inner) or PICTURE.search(inner) or TEXT.search(inner)):
                out.append(f"its name makes it look like a {inner[1:]} file, which it isn't")
        else:
            out.append(f"it is {ins.what}, though its name says {ext + ' file' if ext else 'nothing of that'}: it "
                       "runs as a program when opened. Don't open it")
        ins.viewable = False
    elif ins.kind == "disk image" or DISK_IMAGE.search(name):
        out.append("a disk image: opening it mounts it, and it can hold programs and launchers that look like documents")
        ins.viewable = False
    elif ins.kind == "archive" or ARCHIVE.search(name):
        out.append("an archive: what is inside isn't checked here; look at what comes out before opening any of it")
        ins.viewable = False
    elif RUNS.search(name):
        out.append(RUNS_TEXT)
        inner = os.path.splitext(os.path.splitext(name)[0])[1]
        if inner and (FETCHES.search(inner) or PICTURE.search(inner) or TEXT.search(inner)):
            out.append(f"its name makes it look like a {inner[1:]} file, which it isn't")
        ins.viewable = False
    if ins.viewable and ins.kind == "document" or (ins.kind != "program" and FETCHES.search(name) and not out):
        out.append(FETCH_TEXT if ins.viewable else FETCH_TEXT_PLAIN)
    if MACROS.search(name) and not any("macros" in w for w in ins.warnings):
        out.append("its kind of file can carry macros (programs that run in the office suite): open it with macros "
                   "turned off")
    ins.warnings = out + ins.warnings
    return ins
