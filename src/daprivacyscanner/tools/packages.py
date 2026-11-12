"""Signatures inside a package (Verify a download): a .deb or .rpm carries its own, rather than a
.sig beside it, so Verify reads it out and checks it the same way (gpgv, the app's keys first).

.deb (an ar archive):
- dpkg-sig: a member named _gpg<role> (_gpgorigin, _gpgbuilder, _gpgrepo…) holding a clearsigned
  list ("Files:") of every other member's MD5, SHA-1 and size. The list's signature is checked, then
  every member against it; a member the list doesn't name, or one that differs, makes it bad.
- debsigs: _gpgorigin (or another _gpg<role>) holding a detached OpenPGP signature over debian-binary,
  control.tar.* and data.tar.* joined in that order.
.rpm: the signature header's OpenPGP signatures. RPMSIGTAG_PGP / GPG (1002, 1006) cover the header and
the payload; RPMSIGTAG_RSA / DSA (268, 267) and RPMSIGTAG_OPENPGP (278, rpm 6) only the header, which
then has to hold the payload's digest (RPMTAG_PAYLOADDIGEST, 5092, in the algorithm 5093 names): the
payload is hashed and compared, and without that digest the contents aren't covered, said so.

Nothing is unpacked, run or kept. Small pieces (a signature, an RPM header) are written into the
KeySet's temporary folder; what a signature covers that can be large (a .deb's parts joined, an RPM's
header and payload) is streamed to gpgv through a named pipe there, straight from the package, so a
large package is never copied into memory-backed /run."""

from __future__ import annotations

import hashlib
import os
import re
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

AR_MAGIC = b"!<arch>\n"
RPM_LEAD = b"\xed\xab\xee\xdb"
HEADER_MAGIC = b"\x8e\xad\xe8\x01"
MAX_MEMBER_LIST = 1 << 20                 # a _gpg* member is a few KB
MAX_VALUE = 1 << 16                       # an OpenPGP signature in an RPM's signature header is a few hundred bytes
DIGEST_ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}
_FILES = re.compile(r"^\s+([0-9a-f]{32})\s+([0-9a-f]{40})\s+(\d+)\s+(\S+)\s*$")


class PackageError(ValueError):
    pass


@dataclass
class Embedded:
    """One signature inside the package: `sig` checked over `data` (None: clearsigned), and what
    else must hold for it to count (`problem`, a member or payload that doesn't match, makes it bad)."""
    label: str                            # where it is in the package, for the user ("_gpgorigin")
    sig: Path
    data: Path | None                     # a file, None (clearsigned), or the pipe `ranges` are streamed into
    problem: str = ""                     # something it covers doesn't match: bad
    note: str = ""
    uncovered: str = ""                   # it doesn't cover the contents: not a verification
    ranges: list[tuple[int, int]] = field(default_factory=list)      # (offset, size) of the package, in order
    source: Path | None = None
    signed: str | None = None             # clearsigned: the text read as signed, which gpgv's must match


def kind(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if head == AR_MAGIC and path.name.endswith((".deb", ".udeb", ".ddeb")):
        return "deb"
    if head[:4] == RPM_LEAD:
        return "rpm"
    return None


# ------------------------------------------------------------------ .deb

MAX_MEMBERS = 1000                        # a .deb has three or four


def ar_members(path: Path) -> list[tuple[str, int, int]]:
    """(name, offset of its data, size) of each member. A size that isn't a plain count of bytes ("-60" kept the
    reader on the same header for ever), or one past the end of the file, is a damaged package."""
    out = []
    with open(path, "rb") as f:
        if f.read(8) != AR_MAGIC:
            raise PackageError("not an ar archive")
        end = os.fstat(f.fileno()).st_size
        pos = 8
        while True:
            f.seek(pos)
            h = f.read(60)
            if not h:
                break
            if len(h) < 60 or h[58:60] != b"`\n":
                raise PackageError("a damaged member header")
            name = h[:16].decode("ascii", "replace").strip().rstrip("/")
            field_ = h[48:58].strip()
            if not field_.isdigit():
                raise PackageError("a damaged member size")
            size = int(field_)
            if pos + 60 + size > end or len(out) >= MAX_MEMBERS:
                raise PackageError("a damaged member size")
            out.append((name, pos + 60, size))
            pos += 60 + size + (size & 1)
    return out


def _read(path: Path, off: int, size: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(size)


def _digests(path: Path, off: int, size: int) -> tuple[str, str]:
    md5, sha1 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False)
    with open(path, "rb") as f:
        f.seek(off)
        left = size
        while left:
            b = f.read(min(left, 1 << 20))
            if not b:
                break
            md5.update(b)
            sha1.update(b)
            left -= len(b)
    return md5.hexdigest(), sha1.hexdigest()


def deb(path: Path, work: Path) -> list[Embedded]:
    members = ar_members(path)
    parts = [m for m in members if not m[0].startswith("_gpg")]
    out = []
    for name, off, size in members:
        if not name.startswith("_gpg"):
            continue
        if size > MAX_MEMBER_LIST:
            raise PackageError(f"{name} is too large to be a signature")
        body = _read(path, off, size)
        sig = work / f"deb-{name}"
        sig.write_bytes(body)
        if b"-----BEGIN PGP SIGNED MESSAGE-----" in body:               # dpkg-sig
            # only what is inside its one signed message counts, and gpgv is given that message alone: with lines
            # added around it, or a marker hidden in one, an attacker's "Files:" lines (the parts dpkg-deb then reads,
            # postinst included) counted as signed
            from .verify import Unclear, clearsigned
            try:
                c, unclear = clearsigned(body), ""
            except Unclear as e:
                c, unclear = None, str(e)
            if c is not None:
                sig.write_bytes(c.message)
            listed = {}
            for line in (c.text if c is not None else "").splitlines():
                m = _FILES.match(line)
                if m:
                    listed[m.group(4)] = (m.group(1), m.group(2), int(m.group(3)))
            problem = f"its signed list: {unclear}" if unclear else \
                "its signed list isn't a whole signed message" if c is None else ""
            for pname, poff, psize in parts:
                if problem:
                    break
                want = listed.pop(pname, None)
                if want is None:
                    problem = f"{pname} in the package isn't in its signed list"
                    break
                if (want[0], want[1], want[2]) != (*_digests(path, poff, psize), psize):
                    problem = f"{pname} in the package doesn't match its signed list"
                    break
            if not problem and listed:
                problem = f"the signed list names {', '.join(sorted(listed))}, which the package doesn't have"
            out.append(Embedded(name, sig, None, problem,
                                "The package's signed list gives MD5 and SHA-1 checksums of its parts (dpkg-sig): "
                                "weak algorithms, but nobody can make a different part to match one already "
                                "signed.", signed=c.text if c is not None else None))
        else:                                                              # debsigs: over the parts joined
            order = [p for prefix in ("debian-binary", "control.tar", "data.tar")
                     for p in parts if p[0] == prefix or p[0].startswith(prefix + ".")]
            out.append(Embedded(name, sig, work / f"deb-{name}.pipe", ranges=[(o, z) for _, o, z in order],
                                source=path))
    return out


# ------------------------------------------------------------------ .rpm

def _header(f, off: int) -> tuple[dict[int, tuple[int, int, int]], int, int]:
    """(tag -> (type, absolute offset of its data, count), where the header starts, where it ends)."""
    f.seek(off)
    h = f.read(16)
    if len(h) < 16 or h[:4] != HEADER_MAGIC:
        raise PackageError("a damaged RPM header")
    n, size = struct.unpack(">II", h[8:16])
    if n > 100000 or size > 1 << 28:
        raise PackageError("an RPM header too large to be real")
    index = f.read(16 * n)
    if len(index) < 16 * n:
        raise PackageError("a damaged RPM header")
    store = off + 16 + 16 * n
    tags = {}
    for i in range(n):
        tag, typ, o, cnt = struct.unpack(">IIII", index[16 * i:16 * i + 16])
        if o > size or typ == 7 and o + cnt > size:               # a value must lie in the header's own store
            raise PackageError("a damaged RPM header")
        tags[tag] = (typ, store + o, cnt)
    return tags, off, store + size


def _value(f, entry: tuple[int, int, int], limit: int = MAX_VALUE) -> bytes | int | list[str]:
    typ, off, cnt = entry
    f.seek(off)
    if typ == 7:                                                   # BIN
        if cnt > limit:                     # its count is the package's to set: it had the whole file read into /run
            raise PackageError("a value in its signature header is too large to be a signature")
        return f.read(cnt)
    if typ == 4:                                                   # INT32
        return struct.unpack(">I", f.read(4))[0]
    if typ in (6, 8, 9):                                           # STRING, STRING_ARRAY, I18NSTRING
        raw = f.read(65536)
        return [s.decode("utf-8", "replace") for s in raw.split(b"\0")[:max(cnt, 1)]]
    raise PackageError(f"an RPM value of type {typ}")


def _typed(f, entry: tuple[int, int, int], *kinds: type):
    """_value(), refused unless it is of a kind the tag has: a signature as bytes (or text, for rpm 6's), the digest's
    algorithm as a number, the digest as text. The type is the package's to set: an INT32 signature tag reached
    write_bytes(int), a STRING algorithm tag was looked up as a dict key (TypeError, uncaught)."""
    v = _value(f, entry)
    if not isinstance(v, kinds):
        raise PackageError("a value in its header is of the wrong kind")
    return v


def rpm(path: Path, work: Path) -> list[Embedded]:
    with open(path, "rb") as f:
        if f.read(4) != RPM_LEAD:
            raise PackageError("not an RPM package")
        sig_tags, _, end = _header(f, 96)
        start = (end + 7) // 8 * 8                                   # the signature header is padded to 8
        main, hstart, hend = _header(f, start)
        out = []
        whole = next((t for t in (1002, 1006) if t in sig_tags), None)
        if whole is not None:
            sig = work / "rpm-signature"
            sig.write_bytes(_typed(f, sig_tags[whole], bytes))
            size = os.fstat(f.fileno()).st_size
            out.append(Embedded("its signature header", sig, work / "rpm-signed.pipe", ranges=[(hstart, size - hstart)],
                                source=path))
            return out
        head = next((t for t in (268, 267, 278) if t in sig_tags), None)
        if head is None:
            return []
        raw = _typed(f, sig_tags[head], bytes, list)
        sig = work / "rpm-signature"
        sig.write_bytes("\n".join(raw).encode() if isinstance(raw, list) else raw)
        problem, uncovered = "", ""
        if 5092 in main:
            algo = DIGEST_ALGOS.get(_typed(f, main[5093], int) if 5093 in main else 1)
            want = _typed(f, main[5092], list)
            want = (want[0] if want else "").lower()
            if algo is None or not want:
                uncovered = "its signed header names its contents' digest in a form the app can't read"
            else:
                h = hashlib.new(algo)
                f.seek(hend)
                while b := f.read(1 << 20):
                    h.update(b)
                if h.hexdigest() != want:
                    problem = "its contents don't match the digest in its signed header"
        else:
            uncovered = "only its header is signed, and the header holds no digest of the contents"
        # the header (up to 256 MB) streamed to gpgv as the payload is, never copied into /run
        out.append(Embedded("its signature header", sig, work / "rpm-header.pipe", problem, uncovered=uncovered,
                            ranges=[(hstart, hend - hstart)], source=path))
        return out


def embedded(path: Path, work: Path) -> list[Embedded]:
    """The signatures inside `path`, if it is a package; [] otherwise (or when it carries none)."""
    k = kind(path)
    if k == "deb":
        return deb(path, work)
    if k == "rpm":
        return rpm(path, work)
    return []


@contextmanager
def streamed(e: Embedded, timeout: float = 600):
    """While in use, `e.data` is a named pipe that the package's `ranges` are written into, for each
    reader (gpgv) that opens it in turn: the signature is checked against the app's keys and the user's
    apart (verify.KeySet.runs), so it is read once per check. Nothing to do for an Embedded without ranges."""
    if not e.ranges:
        yield
        return
    os.mkfifo(e.data, 0o600)
    stop = threading.Event()

    def feed():
        deadline = time.monotonic() + timeout
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                fd = os.open(e.data, os.O_WRONLY | os.O_NONBLOCK)       # ENXIO until a reader has it open
            except OSError:
                time.sleep(0.02)
                continue
            os.set_blocking(fd, True)
            try:
                with open(e.source, "rb") as src:
                    for off, size in e.ranges:
                        src.seek(off)
                        left = size
                        while left and not stop.is_set():
                            b = src.read(min(left, 1 << 20))
                            if not b:
                                break
                            os.write(fd, b)
                            left -= len(b)
            except OSError:
                pass                                                  # the reader went away
            finally:
                os.close(fd)
            time.sleep(0.02)                  # the reader sees the end and closes before the next one is waited for
    t = threading.Thread(target=feed, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join(timeout=5)
