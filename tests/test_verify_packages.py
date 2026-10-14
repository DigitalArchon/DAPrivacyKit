"""Verify a download on packages that carry their own signature: .deb (dpkg-sig's signed list,
debsigs' detached signature) and .rpm (a header signature with the payload's digest, or one over
header and payload), built here and signed with a throwaway key; then changed, to see them refused."""

from __future__ import annotations

import datetime as dt
import hashlib
import struct
from pathlib import Path

import pytest

from daprivacyscanner.tools import keys as K
from daprivacyscanner.tools import packages as P
from daprivacyscanner.tools import verify as V

from test_verify import needs_gpg, real_host, signer  # noqa: F401 - the fixture


def project(tmp_path, fpr):
    return K.Project("test", "Test Project", "its packages", "https://example.org", "x", dt.date(2026, 10, 5),
                     ("app*",), "how", ((fpr, "Test release key"),), K.dearmor((tmp_path / "signer.asc").read_bytes()))


def ar(members: list[tuple[str, bytes]]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode() + data + (b"\n" if len(data) % 2 else b"")
    return out


PARTS = [("debian-binary", b"2.0\n"), ("control.tar.xz", b"control" * 50), ("data.tar.xz", b"data" * 4000)]


def dpkg_sig_deb(tmp_path, sign, parts=PARTS) -> Path:
    lines = "".join(f"\t{hashlib.md5(d).hexdigest()} {hashlib.sha1(d).hexdigest()} {len(d)} {n}\n" for n, d in parts)
    listing = tmp_path / "list"
    listing.write_text(f"Version: 4\nSigner: X\nDate: Mon Oct  5 12:00:00 2026\nRole: origin\nFiles: \n{lines}")
    sign(listing, clear=True)
    deb = tmp_path / "app_1.0_amd64.deb"
    deb.write_bytes(ar(parts + [("_gpgorigin", (tmp_path / "list.asc").read_bytes())]))
    return deb


@needs_gpg
def test_a_deb_signed_with_dpkg_sig(tmp_path, signer):
    home, fpr, sign = signer
    deb = dpkg_sig_deb(tmp_path, sign)
    h = real_host(tmp_path)
    v = V.verify(h, deb, projects=[project(tmp_path, fpr)])
    assert v.level == "verified" and "inside the package" in v.text and v.signatures[0].inside == "_gpgorigin"
    assert len(v.signatures) == 1 and any("MD5 and SHA-1" in n for n in v.notes)
    assert V.verify(h, deb).signatures[0].status == "no_key"            # a key the app doesn't have
    # a part changed after signing
    tampered = tmp_path / "t" / deb.name
    tampered.parent.mkdir()
    data = bytearray(deb.read_bytes())
    i = data.index(b"datadata")
    data[i] = ord("D")
    tampered.write_bytes(bytes(data))
    v = V.verify(h, tampered, projects=[project(tmp_path, fpr)])
    assert v.level == "bad" and "data.tar.xz in the package doesn't match" in v.text


@needs_gpg
def test_a_deb_with_a_part_the_signed_list_doesnt_name(tmp_path, signer):
    home, fpr, sign = signer
    deb = dpkg_sig_deb(tmp_path, sign)
    extra = deb.read_bytes() + ar([("zzz-extra", b"evil")])[8:]
    deb.write_bytes(extra)
    v = V.verify(real_host(tmp_path), deb, projects=[project(tmp_path, fpr)])
    assert v.level == "bad" and "zzz-extra in the package isn't in its signed list" in v.text


@needs_gpg
def test_only_the_signed_block_of_the_list_counts(tmp_path, signer):
    """Lines before the clearsigned block aren't signed: a list there can't stand in for the real one."""
    home, fpr, sign = signer
    deb = dpkg_sig_deb(tmp_path, sign)
    assert "_gpgorigin" in [m[0] for m in P.ar_members(deb)]
    fake = [("debian-binary", b"2.0\n"), ("control.tar.xz", b"evil control"), ("data.tar.xz", b"evil data")]
    lines = "".join(f"\t{hashlib.md5(d).hexdigest()} {hashlib.sha1(d).hexdigest()} {len(d)} {n}\n" for n, d in fake)
    signed = (tmp_path / "list.asc").read_bytes()
    forged = tmp_path / "f" / deb.name
    forged.parent.mkdir()
    forged.write_bytes(ar(fake + [("_gpgorigin", f"Files: \n{lines}\n".encode() + signed)]))
    v = V.verify(real_host(tmp_path), forged, projects=[project(tmp_path, fpr)])
    assert v.level == "bad" and "doesn't match its signed list" in v.text


@needs_gpg
def test_a_deb_signed_with_debsigs(tmp_path, signer):
    home, fpr, sign = signer
    joined = tmp_path / "joined"
    joined.write_bytes(b"".join(d for _, d in PARTS))
    sign(joined)
    deb = tmp_path / "app_2.0_amd64.deb"
    deb.write_bytes(ar(PARTS + [("_gpgorigin", (tmp_path / "joined.asc").read_bytes())]))
    h = real_host(tmp_path)
    v = V.verify(h, deb, projects=[project(tmp_path, fpr)])
    assert v.level == "verified" and v.signatures[0].inside == "_gpgorigin"
    assert not list((tmp_path / "home").glob("*.pipe"))
    data = bytearray(deb.read_bytes())
    data[data.index(b"control")] = ord("C")
    deb.write_bytes(bytes(data))
    assert V.verify(h, deb, projects=[project(tmp_path, fpr)]).level == "bad"


# ------------------------------------------------------------------ .rpm

def header(tags: list[tuple[int, int, bytes, int]]) -> bytes:
    """An RPM header: (tag, type, data, count) entries."""
    index, store = b"", b""
    for tag, typ, data, count in tags:
        if typ == 4:                                     # INT32 aligned to 4
            store += b"\0" * (-len(store) % 4)
        index += struct.pack(">IIII", tag, typ, len(store), count)
        store += data
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", len(tags), len(store)) + index + store


def rpm(tmp_path, sign, payload=b"payload " * 500, digest=True, whole=False) -> Path:
    main_tags = [(1000, 6, b"app\0", 1)]
    if digest:
        main_tags += [(5092, 8, hashlib.sha256(payload).hexdigest().encode() + b"\0", 1), (5093, 4, struct.pack(">I", 8), 1)]
    main = header(main_tags)
    signed = tmp_path / "signed"
    signed.write_bytes(main + payload if whole else main)
    sign(signed)
    sig = K.dearmor((tmp_path / "signed.asc").read_bytes())
    sighdr = header([(1002 if whole else 268, 7, sig, len(sig))])
    sighdr += b"\0" * (-len(sighdr) % 8)
    lead = b"\xed\xab\xee\xdb" + b"\0" * 92
    out = tmp_path / "app-1.0-1.x86_64.rpm"
    out.write_bytes(lead + sighdr + main + payload)
    return out


@needs_gpg
@pytest.mark.parametrize("whole", [False, True])
def test_an_rpm(tmp_path, signer, whole):
    home, fpr, sign = signer
    pkg = rpm(tmp_path, sign, whole=whole)
    h = real_host(tmp_path)
    v = V.verify(h, pkg, projects=[project(tmp_path, fpr)])
    assert v.level == "verified" and v.signatures[0].inside == "its signature header"
    data = bytearray(pkg.read_bytes())
    data[-3] ^= 1                                        # the payload changed
    pkg.write_bytes(bytes(data))
    v = V.verify(h, pkg, projects=[project(tmp_path, fpr)])
    assert v.level == "bad"
    if not whole:
        assert "contents don't match the digest" in v.text


@needs_gpg
def test_an_rpm_whose_header_doesnt_cover_its_contents_isnt_verified(tmp_path, signer):
    home, fpr, sign = signer
    v = V.verify(real_host(tmp_path), rpm(tmp_path, sign, digest=False), projects=[project(tmp_path, fpr)])
    assert v.level == "unchecked" and "only its header is signed" in " ".join(v.steps)


def test_not_a_package():
    assert P.kind(Path(__file__)) is None


# ------------------------------------------------------------------ checksums a project publishes

def test_a_checksum_the_project_publishes_verifies_it(tmp_path):
    from test_verify import put
    d = put(tmp_path, repo_DASH_release__deb=b"release package")
    p = K.Project("vpn", "Some VPN", "its packages", "https://example.org/linux", "", dt.date(2026, 10, 5), ("repo-*",),
                  "how", (), b"", unsigned=True,
                  checksums=(("repo-release.deb", hashlib.sha256(b"release package").hexdigest(),
                              "https://example.org/linux"),))
    v = V.verify(real_host(tmp_path), d / "repo-release.deb", projects=[p])
    assert v.level == "verified" and "example.org" in v.text and "doesn't sign this file" in v.notes[-1]
    (d / "repo-release.deb").write_bytes(b"something else")
    assert V.verify(real_host(tmp_path), d / "repo-release.deb", projects=[p]).level == "unchecked"


def test_the_loader_checks_unsigned_projects_and_checksums():
    base = {"id": "x", "name": "X", "signs": "its ISOs", "source": "https://x.example/", "checked": dt.date(2026, 10, 5),
            "files": ["x-*.iso"], "how": "X doesn't sign its ISOs.", "unsigned": True}
    [p] = K.parse({"schema_version": 1, "projects": [base]})
    assert p.unsigned and not p.keys
    with pytest.raises(K.DataError, match="has no keys"):
        K.parse({"schema_version": 1, "projects": [{**base, "keys": [{"fingerprint": "A" * 40, "name": "k"}]}]})
    with pytest.raises(K.DataError, match="each checksum needs"):
        K.parse({"schema_version": 1, "projects": [{**base, "checksums": [{"file": "a", "sha256": "abc",
                                                                            "source": "https://x.example/"}]}]})
    with pytest.raises(K.DataError, match="each checksum needs"):
        K.parse({"schema_version": 1, "projects": [{**base, "checksums": [{"file": "a", "sha256": "a" * 64,
                                                                            "source": "http://x.example/"}]}]})
