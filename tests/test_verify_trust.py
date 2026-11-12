"""Verify a download: whose signature counts as a project's, and when (the review of 2026-11-12). Keys are made
here, in GnuPG homes of the tests' own: a project's key with a signing subkey; that subkey stolen and wrapped as a
primary key of the thief's; keys that have expired, or been revoked as well; signatures that have expired."""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from daprivacyscanner.tools import keys as K
from daprivacyscanner.tools import verify as V

from test_verify import put, real_host, signer  # noqa: F401 - the fixture

needs_gpg = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("gpgv") and shutil.which("gpgconf")),
                               reason="gpg isn't installed")
DAY = 86400


class GPG:
    """One throwaway GnuPG home."""

    def __init__(self, home: Path):
        self.home = home
        home.mkdir(mode=0o700, parents=True)

    def __call__(self, *args, when: int | None = None, **kw) -> subprocess.CompletedProcess:
        fake = ["--faked-system-time", f"{when}!"] if when else []
        return subprocess.run(["gpg", "--homedir", str(self.home), "--batch", "--quiet", "--pinentry-mode", "loopback",
                               "--passphrase", "", *fake, *args], check=True, capture_output=True, **kw)

    def fprs(self, who: str | None = None) -> list[str]:
        out = self("--with-colons", "--list-keys", *([who] if who else [])).stdout.decode()
        return [ln.split(":")[9] for ln in out.splitlines() if ln.startswith("fpr")]

    def export(self, fpr: str) -> bytes:
        return self("--export", fpr).stdout

    def close(self):
        subprocess.run(["gpgconf", "--homedir", str(self.home), "--kill", "gpg-agent"], capture_output=True)


def project(key: bytes, primary: str, files=("app*",), pid="test", name="Test Project") -> K.Project:
    return K.Project(pid, name, f"{name}'s files", "https://example.org", "x", dt.date(2026, 11, 1), files, "how",
                     ((primary, f"{name} release key"),), key)


def revoke_subkey(g: GPG, primary: str):
    """gpg --edit-key's revkey on the first subkey (there is no quick command for it)."""
    subprocess.run(["gpg", "--homedir", str(g.home), "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                    "--command-fd", "0", "--edit-key", primary], input=b"key 1\nrevkey\ny\n1\n\ny\nsave\n",
                   check=True, capture_output=True)


def packets(data: bytes, keep) -> bytes:
    """The packets of key data that `keep(primary fingerprint)` says to keep, written again (new format)."""
    out, take = b"", False
    for tag, body in K.packets(data):
        if tag == K.PUBLIC_KEY:
            take = keep(K.fingerprint(body))
        if take:
            out += bytes([0xC0 | tag, 255]) + len(body).to_bytes(4, "big") + body
    return out


@pytest.fixture
def stolen(tmp_path):
    """A project's key with a signing subkey, the project's copy once the subkey was revoked, and the thief's key:
    the stolen subkey's secret wrapped as a primary key with a self-signature of the thief's (gpg's Key-Grip, at the
    subkey's creation time), so its fingerprint is the subkey's. Its file evil.txt is signed with it."""
    g = GPG(tmp_path / "project")
    g("--quick-gen-key", "Project <p@example.org>", "ed25519", "cert", "never")
    primary = g.fprs()[0]
    g("--quick-add-key", primary, "ed25519", "sign", "never")
    sub = g.fprs()[1]
    clean = g.export(primary)
    out = g("--with-colons", "--with-keygrip", "--list-keys", primary).stdout.decode().splitlines()
    grip = [ln.split(":")[9] for ln in out if ln.startswith("grp")][1]
    created = int([ln.split(":")[5] for ln in out if ln.startswith("sub")][0])
    secret = g("--export-secret-subkeys", sub + "!").stdout
    d = put(tmp_path, app_DASH_1__0__iso=b"the real release")
    g("-u", sub + "!", "--detach-sign", "-o", str(d / "app-1.0.iso.sig"), str(d / "app-1.0.iso"))
    revoke_subkey(g, primary)
    revoked = g.export(primary)
    t = GPG(tmp_path / "thief")
    t("--import", input=secret)
    (tmp_path / "params").write_text(
        f"%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Grip: {grip}\nKey-Usage: sign\nName-Real: Thief\n"
        f"Creation-Date: {time.strftime('%Y%m%dT%H%M%S', time.gmtime(created))}\nExpire-Date: 0\n")
    try:
        t("--gen-key", str(tmp_path / "params"))
    except subprocess.CalledProcessError:
        pytest.skip("this gpg can't make a key from an existing key grip")
    theirs = packets(t("--export").stdout, lambda f: f == sub)
    assert [k.fingerprint for k in K.parse_keys(theirs)] == [sub]          # a primary with the subkey's fingerprint
    (tmp_path / "thief.gpg").write_bytes(theirs)
    (d / "app-2.0.iso").write_bytes(b"evil")
    t("-u", sub + "!", "--detach-sign", "-o", str(d / "app-2.0.iso.sig"), str(d / "app-2.0.iso"))
    yield {"g": g, "t": t, "primary": primary, "sub": sub, "clean": clean, "revoked": revoked, "dir": d}
    g.close()
    t.close()


@needs_gpg
def test_a_stolen_subkey_wrapped_as_a_primary_isnt_the_projects(tmp_path, stolen):
    """gpgv says GOODSIG with the thief's primary in VALIDSIG's last field, which is the project's subkey's
    fingerprint: matched against subkeys, it was "Verified: made by Test Project"."""
    s, d = stolen, stolen["dir"]
    proj = project(s["revoked"], s["primary"])
    assert K.pinned([proj], s["sub"], s["sub"]) is None                         # a subkey's fingerprint as a primary
    assert K.pinned([proj], s["primary"], s["sub"])[2] is True                  # signed by a subkey the app has
    h = real_host(tmp_path)
    # as a key file the user chose, searched before the app's: the app's copy says the subkey is revoked
    v = V.verify(h, d / "app-2.0.iso", key_files=[tmp_path / "thief.gpg"], projects=[proj], use_keyring=False)
    assert v.level == "bad" and "revoked" in v.text and "Test Project" in v.text, v.text
    # imported into the user's keyring
    home = GPG(tmp_path / "user")
    home("--import", input=(tmp_path / "thief.gpg").read_bytes())
    v = V.verify(real_host(tmp_path, GNUPGHOME=str(home.home)), d / "app-2.0.iso", projects=[proj])
    assert v.level == "bad" and "revoked" in v.text
    home.close()
    # even with no revocation anywhere, the thief's key is never the project's: their file is only "signed"
    other = project(s["revoked"], s["primary"], files=("other*",))
    v = V.verify(h, d / "app-2.0.iso", key_files=[tmp_path / "thief.gpg"], projects=[other], use_keyring=False)
    assert v.level == "bad"            # the app's copy still knows the subkey is revoked: it counts
    unrevoked = project(packets(s["revoked"], lambda f: False), s["primary"])    # a project with none of that key
    v = V.verify(h, d / "app-2.0.iso", key_files=[tmp_path / "thief.gpg"], projects=[unrevoked], use_keyring=False)
    assert v.level == "signed" and v.signatures[0].project is None and "Thief" in v.text


@needs_gpg
def test_a_stale_copy_of_a_listed_key_cant_hide_the_revocation_the_apps_copy_holds(tmp_path, stolen):
    """The user's copy of the project's key from before the revocation, chosen as a key file (or in their keyring):
    gpgv used it first and found the stolen subkey's signature good."""
    s, d = stolen, stolen["dir"]
    (tmp_path / "stale.gpg").write_bytes(s["clean"])
    proj = project(s["revoked"], s["primary"])
    h = real_host(tmp_path)
    # app-1.0.iso: signed by the project's subkey before it was stolen and revoked
    assert V.verify(h, d / "app-1.0.iso", projects=[project(s["clean"], s["primary"])],
                    use_keyring=False).level == "verified"
    v = V.verify(h, d / "app-1.0.iso", key_files=[tmp_path / "stale.gpg"], projects=[proj], use_keyring=False)
    assert v.level == "bad" and "revoked" in v.text
    home = GPG(tmp_path / "user")
    home("--import", input=s["clean"])
    v = V.verify(real_host(tmp_path, GNUPGHOME=str(home.home)), d / "app-1.0.iso", projects=[proj])
    assert v.level == "bad" and "revoked" in v.text
    home.close()


@pytest.fixture
def expired_key(tmp_path):
    """A key made three years ago that expired after one, with a signing subkey, and a file it signed then."""
    g = GPG(tmp_path / "old")
    past = int(time.time()) - 3 * 365 * DAY
    g("--quick-gen-key", "Old Project <o@example.org>", "ed25519", "cert", "1y", when=past)
    primary = g.fprs()[0]
    g("--quick-add-key", primary, "ed25519", "sign", "1y", when=past)
    d = put(tmp_path, app__iso=b"an old release")
    g("-u", primary, "--detach-sign", "-o", str(d / "app.iso.sig"), str(d / "app.iso"), when=past + DAY)
    yield g, primary, d
    g.close()


@needs_gpg
def test_a_signature_by_an_expired_key_isnt_verified(tmp_path, expired_key, monkeypatch, capsys):
    """The date in a signature is the signer's own claim: whoever holds an expired key can sign today and date it
    back. EXPKEYSIG was "Verified" with a note."""
    from daprivacyscanner import app
    g, primary, d = expired_key
    proj = project(g.export(primary), primary)
    v = V.verify(real_host(tmp_path), d / "app.iso", projects=[proj], use_keyring=False)
    assert v.level == "expired" and v.title == "Not verified: signed with a key that has expired", v.title
    assert "own claim" in v.text and "Test Project" in v.text and v.signed_at is None
    sig = v.to_dict()["signatures"][0]
    assert sig["badge"] == "expired key" and sig["badge_kind"] == "expired" and sig["expired"] == "key"
    # --verify says so, and exits 1
    monkeypatch.setattr(V.K, "load", lambda *a: (proj,))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("GNUPGHOME", raising=False)
    assert app.verify_cli(str(d / "app.iso"), [], "") == 1
    assert "made with a key that has expired" in capsys.readouterr().out


@needs_gpg
def test_a_key_both_expired_and_revoked_is_revoked(tmp_path, expired_key):
    """gpgv 2.4.4 reports such a key as expired only (EXPKEYSIG, no REVKEYSIG): the revocation is read from the
    key's copies, the app's and the user's."""
    g, primary, d = expired_key
    before = g.export(primary)
    rev = (g.home / "openpgp-revocs.d" / f"{primary}.rev").read_text().replace(":-----BEGIN", "-----BEGIN")
    g("--import", input=rev.encode())
    after = g.export(primary)
    assert primary in K.revoked_keys(after) and not K.revoked_keys(before)
    status = subprocess.run(["gpgv", "--homedir", str(tmp_path / "old"), "--status-fd", "1", "--keyring",
                             str(g.home / "pubring.kbx"), str(d / "app.iso.sig"), str(d / "app.iso")],
                            capture_output=True, text=True).stdout
    assert "EXPKEYSIG" in status and "REVKEYSIG" not in status                 # what gpgv says of it
    h = real_host(tmp_path)
    v = V.verify(h, d / "app.iso", projects=[project(after, primary)], use_keyring=False)
    assert v.level == "bad" and "revoked" in v.text
    # the app's copy from before the revocation, the user's keyring after it (a keybox, read for its revocations)
    v = V.verify(real_host(tmp_path, GNUPGHOME=str(g.home)), d / "app.iso", projects=[project(before, primary)])
    assert v.level == "bad" and "revoked" in v.text


@needs_gpg
def test_an_expired_signature_isnt_good(tmp_path):
    """EXPSIG (the signature itself has expired) was read as good, with no note at all."""
    g = GPG(tmp_path / "k")
    past = int(time.time()) - 30 * DAY
    g("--quick-gen-key", "Project <p@example.org>", "ed25519", "sign", "never", when=past)
    primary = g.fprs()[0]
    d = put(tmp_path, app__iso=b"release")
    g("--default-sig-expire", "1d", "-u", primary, "--detach-sign", "-o", str(d / "app.iso.sig"), str(d / "app.iso"),
      when=past + 60)
    v = V.verify(real_host(tmp_path), d / "app.iso", projects=[project(g.export(primary), primary)], use_keyring=False)
    assert v.level == "expired" and v.title == "Not verified: its signature has expired"
    assert v.signatures[0].expired == "signature"
    g.close()


def test_expiry_and_revocation_in_gpgvs_status():
    exp = V.parse_gpg_status("[GNUPG:] NEWSIG\n[GNUPG:] EXPSIG 1 x\n[GNUPG:] VALIDSIG S 1 2 3 4 0 22 2 00 P\n")[0]
    assert (exp["status"], exp["expired"], exp["signer"], exp["fpr"], exp["hash"]) == ("expired", "signature", "S", "P", 2)


def _sig(path, status="good", project=None, **kw):
    return V.Signature(path.with_name(path.name + ".asc"), path, "openpgp", status, "AB" * 20, project=project,
                       key_name="k", source="list", **kw)


def test_a_listed_key_verifies_only_its_own_projects_files(tmp_path):
    """Any listed key verified any file name: one person's key, or a build server's, would have made a Tails image
    "Verified"."""
    tails = K.Project("tails", "Tails", "Tails images", "https://tails.net", "", dt.date(2026, 11, 1),
                      ("tails-*.img",), "Download tails-*.img.sig beside it.", (("CD" * 20, "Tails key"),), b"")
    other = K.Project("other", "Someone", "Someone's tools", "https://example.org", "", dt.date(2026, 11, 1),
                      ("tool-*",), "how", (("AB" * 20, "their key"),), b"")
    f = tmp_path / "tails-amd64-7.0.img"
    v = V.decide(f, 1, {"sha256": "ab" * 32}, [_sig(f, project=other)], [], None, [tails, other])
    assert v.level == "other_project" and v.title == "Not verified: signed by Someone, but named as Tails's file"
    assert "Tails images" in v.text and any("tails-*.img.sig" in s for s in v.steps)
    # their own file, and a file named as nobody's, are theirs to verify
    g = tmp_path / "tool-1.0.tar"
    assert V.decide(g, 1, {}, [_sig(g, project=other)], [], None, [tails, other]).level == "verified"
    n = tmp_path / "renamed.bin"
    assert V.decide(n, 1, {}, [_sig(n, project=other)], [], None, [tails, other]).level == "verified"
    # with Tails's own signature beside the other one, it is Tails's
    v = V.decide(f, 1, {}, [_sig(f, project=other), _sig(f, project=tails)], [], None, [tails, other])
    assert v.level == "verified" and "Tails" in v.title


def test_weak_hashes_under_a_good_signature_get_a_note(tmp_path):
    p = K.Project("p", "P", "P's files", "https://example.org", "", dt.date(2026, 11, 1), ("x*",), "how",
                  (("AB" * 20, "k"),), b"")
    f = tmp_path / "x.iso"
    v = V.decide(f, 1, {}, [_sig(f, project=p, hash_algo=2)], [], None, [p])
    assert v.level == "verified" and any("SHA-1 hash, which is weak" in n for n in v.notes)
    assert not any("weak" in n for n in V.decide(f, 1, {}, [_sig(f, project=p, hash_algo=8)], [], None, [p]).notes)
    # a signed list that holds only an MD5 for the file
    lst = tmp_path / "MD5SUMS"
    sig = V.Signature(tmp_path / "MD5SUMS.gpg", lst, "openpgp", "good", "AB" * 20, project=p, key_name="k", source="list")
    e = V.Entry("md5", "0" * 32, "x.iso")
    sums = V.SumsList(lst, [e], signature=sig, matched=[(e, True)])
    v = V.decide(f, 1, {"md5": "0" * 32}, [], [sums], None, [p])
    assert v.level == "verified" and any("only an MD5 checksum" in n for n in v.notes)


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="ssh-keygen isn't installed")
def test_an_ssh_signature_says_anyone_can_make_one(tmp_path):
    key = tmp_path / "id"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    d = put(tmp_path, tool__tar=b"tool")
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "file", str(d / "tool.tar")],
                   check=True, capture_output=True)
    v = V.verify(real_host(tmp_path), d / "tool.tar", use_keyring=False, projects=[])
    assert v.level == "signed" and v.title == "Not verified: signed by an unknown key"
    assert "anyone can make one" in v.text and "proves" not in v.text
    s = v.to_dict()["signatures"][0]
    assert s["badge"] == "good, but by the key inside it" and s["badge_kind"] == "unlisted"


def test_every_level_below_verified_says_it_isnt():
    """Titles a non-expert reads: only "Verified" is green, "Don't use this file" is bad, the rest say "Not ..."."""
    f = Path("/x/f.iso")
    for v in (V.decide(f, 1, {}, [], [], None, []),
              V.decide(f, 1, {}, [V.Signature(f.with_name("f.iso.sig"), f, "openpgp", "no_key")], [], None, [])):
        assert v.title.startswith("Not verified: "), v.title


@needs_gpg
def test_two_checks_run_apart_and_the_users_copy_still_verifies_a_newer_subkey(tmp_path):
    """The user's copy of a listed key with a signing subkey made after the app's copy: gpgv found it bound to the
    pinned primary, so it is the project's, with a note."""
    g = GPG(tmp_path / "p")
    g("--quick-gen-key", "Project <p@example.org>", "ed25519", "cert", "never")
    primary = g.fprs()[0]
    g("--quick-add-key", primary, "ed25519", "sign", "never")
    old = g.export(primary)
    g("--quick-add-key", primary, "ed25519", "sign", "never")
    new_sub = g.fprs()[2]
    (tmp_path / "current.gpg").write_bytes(g.export(primary))
    d = put(tmp_path, app__iso=b"release")
    g("-u", new_sub + "!", "--detach-sign", "-o", str(d / "app.iso.sig"), str(d / "app.iso"))
    proj = project(old, primary)
    h = real_host(tmp_path)
    assert V.verify(h, d / "app.iso", projects=[proj], use_keyring=False).level == "unchecked"   # the app's copy only
    v = V.verify(h, d / "app.iso", key_files=[tmp_path / "current.gpg"], projects=[proj], use_keyring=False)
    assert v.level == "verified" and v.signatures[0].newer_subkey and v.signatures[0].signer == new_sub
    assert any("doesn't have yet" in n for n in v.notes)
    g.close()


def test_a_keybox_is_read_for_its_key_blocks():
    block = bytes([0x99, 0, 1, 4])
    blob = (len(block) + 32).to_bytes(4, "big") + bytes([2, 1, 0, 0]) + (32).to_bytes(4, "big") + \
        len(block).to_bytes(4, "big") + b"\0" * 16 + block
    header = (32).to_bytes(4, "big") + bytes([1, 1, 0, 0]) + b"KBXf" + b"\0" * 20
    assert list(K.keybox_blocks(header + blob)) == [block]
    assert list(K.keybox_blocks(header + blob[:-2])) == []                  # a blob longer than the file


# ------------------------------------------------------------------ packages

@needs_gpg
def test_a_package_is_streamed_once_per_check(tmp_path, signer):
    """With a keyring of the user's, each signature is checked twice (the app's keys, then the user's), and what a
    package's signature covers is read from its pipe each time: a pipe served once left the second gpgv waiting."""
    from test_verify_packages import PARTS, ar, project as pkg_project, rpm
    home, fpr, sign = signer
    joined = tmp_path / "joined"
    joined.write_bytes(b"".join(d for _, d in PARTS))
    sign(joined)
    deb = tmp_path / "app_2.0_amd64.deb"
    deb.write_bytes(ar(PARTS + [("_gpgorigin", (tmp_path / "joined.asc").read_bytes())]))
    h = real_host(tmp_path, GNUPGHOME=str(home))           # the signer's own home stands for the user's keyring
    started = time.monotonic()
    assert V.verify(h, deb, projects=[pkg_project(tmp_path, fpr)]).level == "verified"
    for whole in (False, True):
        assert V.verify(h, rpm(tmp_path, sign, whole=whole), projects=[pkg_project(tmp_path, fpr)]).level == "verified"
    assert time.monotonic() - started < 60


def test_an_rpm_value_larger_than_a_signature_is_refused(tmp_path):
    """The signature's size is the package's to set: it had the whole file read into memory and written into /run."""
    import struct
    from daprivacyscanner.tools import packages as P
    from test_verify_packages import header
    sig = b"x" * 100
    sighdr = header([(268, 7, sig, len(sig))])
    # its count says 1 GB
    n = sighdr.index(struct.pack(">I", len(sig)), 16)
    big = sighdr[:n] + struct.pack(">I", 1 << 30) + sighdr[n + 4:]
    big += b"\0" * (-len(big) % 8)
    pkg = tmp_path / "app-1.0-1.x86_64.rpm"
    pkg.write_bytes(b"\xed\xab\xee\xdb" + b"\0" * 92 + big + header([(1000, 6, b"app\0", 1)]) + b"payload")
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(P.PackageError, match="damaged|too large"):
        P.rpm(pkg, work)
    assert not list(work.iterdir())
    # the count within the header, but beyond what a signature can be
    store = b"y" * (P.MAX_VALUE + 1)
    sighdr = header([(268, 7, store, len(store))])
    sighdr += b"\0" * (-len(sighdr) % 8)
    pkg.write_bytes(b"\xed\xab\xee\xdb" + b"\0" * 92 + sighdr + header([(1000, 6, b"app\0", 1)]) + b"payload")
    with pytest.raises(P.PackageError, match="too large"):
        P.rpm(pkg, work)
