"""Verify a download: the bundled keys, checksum lists, gpgv's status, and whole verdicts against
real signatures (Linux Mint, Fedora, Ubuntu, Debian; tests/samples/verify) and keys made here."""

from __future__ import annotations

import copy
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.tools import keys as K
from daprivacyscanner.tools import verify as V

SAMPLES = Path(__file__).parent / "samples" / "verify"
REPO = Path(__file__).resolve().parents[1]
needs_gpgv = pytest.mark.skipif(not shutil.which("gpgv"), reason="gpgv isn't installed")
needs_gpg = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("gpgv")), reason="gpg isn't installed")


def real_host(tmp_path: Path, **env) -> Host:
    """The real gpgv, with a home of its own (never the developer's keyring)."""
    from daprivacyscanner.host import SystemRunner
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    environ = {"HOME": str(home), "PATH": "/usr/bin:/bin", **env}
    return Host(home=home, environ=environ, runner=SystemRunner(environ))


def put(tmp_path: Path, **files) -> Path:
    d = tmp_path / "dl"
    d.mkdir(exist_ok=True)
    for name, src in files.items():
        name = name.replace("__", ".").replace("_DASH_", "-")
        if isinstance(src, Path):
            shutil.copy(src, d / name)
        else:
            (d / name).write_bytes(src if isinstance(src, bytes) else src.encode())
    return d


# ------------------------------------------------------------------ the bundled keys

def test_every_bundled_key_matches_its_pins():
    projects = K.load(REPO / K.DATA_NAME)
    assert {p.id for p in projects} >= {"linuxmint", "ubuntu", "debian", "fedora", "archlinux", "tails", "torbrowser",
                                        "keepassxc", "veracrypt", "mullvad", "kali"}
    for p in projects:
        assert p.source.startswith("https://") and p.how and p.files
        if p.unsigned:                                   # what it publishes is said in `how`, with no key
            assert not p.keys and not p.key and "doesn't sign" in p.how, p.id
            continue
        assert {k.fingerprint for k in K.parse_keys(p.key)} == {f for f, _ in p.keys}, p.id
    assert {p.id for p in projects if p.unsigned} == {"garuda", "bazzite"}
    assert any(p.checksums for p in projects if p.id == "protonvpn")


def test_the_apps_own_releases_name_its_key():
    """The release key in docs/release-key.asc is the one the app carries, and its releases' names lead to it."""
    own = next(p for p in K.load(REPO / K.DATA_NAME) if p.id == "digitalarchon")
    assert own.keys == (("3AA5C06133BBC05A4151EA415B5948EB785ED3AF", "Digital Archon Release Signing"),)
    assert [k.fingerprint for k in K.parse_keys((REPO / "docs/release-key.asc").read_text())] == [own.keys[0][0]]
    assert K.key_expiries(own.key) == {own.keys[0][0]: None}       # never: old copies can't learn of an extension
    assert own.matches("DAPrivacyKit-0.1.0b1-x86_64.AppImage") and own.matches("DAPrivacyKit-0.1.0b1-x86_64.AppImage.sha256")


def test_a_key_that_doesnt_match_its_pin_is_refused():
    data = yaml.safe_load((REPO / K.DATA_NAME).read_text())
    swapped = copy.deepcopy(data)
    swapped["projects"][0]["key"] = data["projects"][1]["key"]            # Ubuntu's key under Mint's pin
    with pytest.raises(K.DataError, match="not the fingerprints pinned"):
        K.parse(swapped)
    unpinned = copy.deepcopy(data)
    unpinned["projects"][0]["keys"][0]["fingerprint"] = "0" * 40
    with pytest.raises(K.DataError, match="not the fingerprints pinned"):
        K.parse(unpinned)
    plain = copy.deepcopy(data)
    plain["projects"][0]["source"] = "http://example.org/"
    with pytest.raises(K.DataError, match="https"):
        K.parse(plain)


def test_issuer_read_from_the_signature_packets():
    projects = K.load(REPO / K.DATA_NAME)
    for sig, project in [("mint-22.3-sha256sum.txt.gpg", "linuxmint"), ("ubuntu-24.04-SHA256SUMS.gpg", "ubuntu"),
                         ("debian-SHA512SUMS.sign", "debian"), ("Fedora-Workstation-44-1.7-x86_64-CHECKSUM", "fedora")]:
        issuers = K.signature_issuers((SAMPLES / sig).read_bytes())
        assert len(issuers) == 1 and len(issuers[0]) == 40
        assert K.owner(projects, issuers[0])[0].id == project
        assert K.owner(projects, issuers[0][-16:])[0].id == project            # a key id finds it too


def test_recognised_file_names_and_grouping():
    projects = K.load(REPO / K.DATA_NAME)
    assert K.for_file(projects, "linuxmint-22.3-cinnamon-64bit.iso").id == "linuxmint"
    assert K.for_file(projects, "mullvad-browser-linux-x86_64-15.0.tar.xz").id == "torbrowser"
    assert K.for_file(projects, "holiday.jpg") is None
    assert K.group("27DEB15644C6B3CF3BD7D291300F846BA25BAE09") == "27DE B156 44C6 B3CF 3BD7  D291 300F 846B A25B AE09"


def test_dearmor_refuses_what_isnt_openpgp():
    with pytest.raises(K.PacketError):
        K.dearmor("hello")
    with pytest.raises(K.PacketError):
        K.parse_keys((SAMPLES / "mint-22.3-sha256sum.txt.gpg").read_bytes())     # a signature, not a key


# ------------------------------------------------------------------ checksum lists

def test_parse_sums_formats():
    text = ("# comment\n"
            "a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4 *linuxmint.iso\n"
            "SHA256 (Fedora.iso) = 1620295F6A00C27C3208F0C00B8ECE4EAB1EC69B9002152D97488BF26A426DDF\n"
            "d41d8cd98f00b204e9800998ecf8427e  ./old.tar\n")
    e = V.parse_sums(text)
    assert [(x.algo, x.name) for x in e] == [("sha256", "linuxmint.iso"), ("sha256", "Fedora.iso"), ("md5", "old.tar")]
    assert e[1].digest == e[1].digest.lower()
    b2 = V.parse_sums("ab" * 64 + "  arch.iso\n", "b2sums.txt")
    assert b2[0].algo == "blake2b"
    bare = V.parse_sums("ab" * 32 + "\n", "foo.iso.sha256")
    assert V.for_file(bare, "foo.iso", "foo.iso.sha256") == bare
    assert V.for_file(bare, "bar.iso", "foo.iso.sha256") == []


def test_only_the_signed_part_of_a_clearsigned_list_counts():
    text = ("aaaa" * 16 + "  evil.iso\n" + (SAMPLES / "Fedora-Workstation-44-1.7-x86_64-CHECKSUM").read_text()
            + "bbbb" * 16 + "  evil2.iso\n")
    body = V.signed_text(text)
    names = {e.name for e in V.parse_sums(body)}
    assert "evil.iso" not in names and "evil2.iso" not in names
    assert "Fedora-Workstation-Live-44-1.7.x86_64.iso" in names
    assert V.signed_text("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n- -dashed\nx\n"
                         "-----BEGIN PGP SIGNATURE-----\n") == "-dashed\nx"
    assert V.signed_text("not signed") is None


@pytest.mark.parametrize("text, digest_len, algos", [
    ("5891B5B522D5DF086D0FF0B110FBD9D21BB4FC7163AF34D08286A2E846F6BE03", 64, ["sha256"]),
    ("sha256: 5891b5b5 22d5df08 6d0ff0b1 10fbd9d2 1bb4fc71 63af34d0 8286a2e8 46f6be03", 64, ["sha256"]),
    ("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  random.bin", 64, ["sha256"]),
    ("ab" * 64, 128, ["sha512", "blake2b"]),
])
def test_pasted_checksums(text, digest_len, algos):
    digest, got = V.pasted(text)
    assert len(digest) == digest_len and got == algos


def test_pasted_text_that_isnt_a_checksum():
    assert V.pasted("hello") is None and V.pasted("abc") is None


# ------------------------------------------------------------------ gpgv's status lines

def test_parse_gpg_status():
    good = ("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 300F846BA25BAE09 Linux Mint\n"
            "[GNUPG:] VALIDSIG AAAA 2026-01-11 1768138182 0 4 0 1 10 00 27DEB15644C6B3CF3BD7D291300F846BA25BAE09\n")
    s = V.parse_gpg_status(good)[0]
    assert s["status"] == "good" and s["fpr"] == "27DEB15644C6B3CF3BD7D291300F846BA25BAE09" and s["time"] == 1768138182
    nokey = ("[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 300F846BA25BAE09 1 10 00 1768138182 9 "
             "27DEB15644C6B3CF3BD7D291300F846BA25BAE09\n[GNUPG:] NO_PUBKEY 300F846BA25BAE09\n")
    s = V.parse_gpg_status(nokey)[0]
    assert s["status"] == "no_key" and s["issuer"] == "27DEB15644C6B3CF3BD7D291300F846BA25BAE09"
    assert V.parse_gpg_status("[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 300F846BA25BAE09 x\n")[0]["status"] == "bad"
    assert V.parse_gpg_status("[GNUPG:] NEWSIG\n[GNUPG:] REVKEYSIG 1 x\n")[0]["status"] == "revoked"
    assert V.parse_gpg_status("[GNUPG:] NEWSIG\n[GNUPG:] EXPKEYSIG 1 x\n[GNUPG:] VALIDSIG F 1 2 0 4 0 1 8 00 F\n")[0][
        "status"] == "expired"


# ------------------------------------------------------------------ verdicts, with the real gpgv

@needs_gpgv
def test_a_signed_list_from_linux_mint_is_verified(tmp_path):
    d = put(tmp_path, sha256sum__txt=SAMPLES / "mint-22.3-sha256sum.txt",
            sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg")
    v = V.verify(real_host(tmp_path), d / "sha256sum.txt")
    assert v.level == "verified" and "Linux Mint" in v.title
    assert v.signatures[0].fingerprint == "27DEB15644C6B3CF3BD7D291300F846BA25BAE09"


@needs_gpgv
@pytest.mark.parametrize("sums, sig", [("ubuntu-24.04-SHA256SUMS", "ubuntu-24.04-SHA256SUMS.gpg"),
                                       ("debian-SHA512SUMS", "debian-SHA512SUMS.sign")])
def test_ubuntu_and_debian_lists_are_verified(tmp_path, sums, sig):
    d = put(tmp_path, SUMS=SAMPLES / sums, **{"SUMS" + Path(sig).suffix.replace(".", "__"): SAMPLES / sig})
    v = V.verify(real_host(tmp_path), d / "SUMS")
    assert v.level == "verified", v.text


@needs_gpgv
def test_choosing_the_signature_verifies_the_file_it_signs(tmp_path):
    d = put(tmp_path, sha256sum__txt=SAMPLES / "mint-22.3-sha256sum.txt",
            sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg")
    v = V.verify(real_host(tmp_path), d / "sha256sum.txt.gpg")
    assert v.path.name == "sha256sum.txt" and v.level == "verified"


@needs_gpgv
def test_fedoras_clearsigned_checksum_file_is_verified(tmp_path):
    d = put(tmp_path, CHECKSUM=SAMPLES / "Fedora-Workstation-44-1.7-x86_64-CHECKSUM")
    v = V.verify(real_host(tmp_path), d / "CHECKSUM")
    assert v.level == "verified" and v.signatures[0].project.id == "fedora"


@needs_gpgv
def test_a_changed_list_is_bad(tmp_path):
    text = (SAMPLES / "mint-22.3-sha256sum.txt").read_text().replace("a081", "b081", 1)
    d = put(tmp_path, sha256sum__txt=text, sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg")
    v = V.verify(real_host(tmp_path), d / "sha256sum.txt")
    assert v.level == "bad" and "doesn't match" in v.text


@needs_gpgv
def test_a_file_that_doesnt_match_the_signed_list_is_bad(tmp_path):
    d = put(tmp_path, sha256sum__txt=SAMPLES / "mint-22.3-sha256sum.txt",
            sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg",
            **{"linuxmint-22.3-cinnamon-64bit.iso": b"not the real thing"})
    v = V.verify(real_host(tmp_path), d / "linuxmint-22.3-cinnamon-64bit.iso")
    assert v.level == "bad" and "SHA-256" in v.text and "sha256sum.txt" in v.text
    assert v.lists[0].signature.good and v.lists[0].matched[0][1] is False


@needs_gpgv
def test_a_signature_whose_key_is_missing_says_whose_it_is(tmp_path):
    d = put(tmp_path, sha256sum__txt=SAMPLES / "mint-22.3-sha256sum.txt",
            sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg")
    others = [p for p in K.load(REPO / K.DATA_NAME) if p.id != "linuxmint"]
    v = V.verify(real_host(tmp_path), d / "sha256sum.txt", projects=others)
    assert v.level == "unchecked"
    assert v.signatures[0].status == "no_key" and v.signatures[0].issuer == "27DEB15644C6B3CF3BD7D291300F846BA25BAE09"
    assert any("27DE B156" in s for s in v.steps)


def test_nothing_to_check_names_what_to_download(tmp_path):
    d = put(tmp_path, **{"tails-amd64-7.0.img": b"x"})
    v = V.verify(Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner()), d / "tails-amd64-7.0.img")
    assert v.level == "unchecked" and v.project_hint.id == "tails"
    assert any(s.startswith("Tails:") and ".sig" in s for s in v.steps)


def test_a_pasted_checksum_proves_intact_only(tmp_path):
    d = put(tmp_path, random__bin=b"hello\n")
    h = Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner())
    v = V.verify(h, d / "random.bin", expected="5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")
    assert v.level == "intact" and "doesn't show who made it" in v.text
    v = V.verify(h, d / "random.bin", expected="0" * 64)
    assert v.level == "bad"
    v = V.verify(h, d / "random.bin", expected="d41d8cd98f00b204e9800998ecf8427e")       # md5 of nothing
    assert v.level == "bad"


def test_weak_checksums_are_called_weak(tmp_path):
    import hashlib
    d = put(tmp_path, f__bin=b"data", MD5SUMS=hashlib.md5(b"data").hexdigest() + "  f.bin\n")
    v = V.verify(Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner()), d / "f.bin")
    assert v.level == "intact" and any("weak" in n for n in v.notes)


def test_without_gpgv_the_signature_is_named_but_not_checked(tmp_path):
    d = put(tmp_path, sha256sum__txt=SAMPLES / "mint-22.3-sha256sum.txt",
            sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg")
    v = V.verify(Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner()), d / "sha256sum.txt")
    assert v.level == "unchecked" and v.signatures[0].status == "no_tool"
    assert any("gpgv" in s for s in v.steps)


def test_sqv_is_used_when_gpgv_is_missing(tmp_path):
    d = put(tmp_path, sha256sum__txt=SAMPLES / "mint-22.3-sha256sum.txt",
            sha256sum__txt__gpg=SAMPLES / "mint-22.3-sha256sum.txt.gpg")
    seen = []

    def sqv(argv):
        seen.append(argv)
        return CommandResult(argv, 0, "27DEB15644C6B3CF3BD7D291300F846BA25BAE09\n")
    v = V.verify(Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner(handlers={"sqv": sqv})),
                 d / "sha256sum.txt")
    assert v.level == "verified" and seen and seen[0][-2:] == (str(d / "sha256sum.txt.gpg"), str(d / "sha256sum.txt"))


# ------------------------------------------------------------------ keys made here

@pytest.fixture
def signer(tmp_path):
    """A throwaway signing key in a GnuPG home of its own."""
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    run = lambda *a, **kw: subprocess.run(["gpg", "--homedir", str(home), "--batch", "--quiet", *a],  # noqa: E731
                                          check=True, capture_output=True, **kw)
    run("--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", "Test Signer <t@example.org>",
        "ed25519", "sign", "never")
    fpr = [ln.split(":")[9] for ln in run("--with-colons", "--list-keys").stdout.decode().splitlines()
           if ln.startswith("fpr")][0]
    (tmp_path / "signer.asc").write_bytes(run("--armor", "--export", fpr).stdout)

    def sign(path: Path, clear: bool = False):
        run("--yes", "--armor", "--clearsign" if clear else "--detach-sign", str(path))
    yield home, fpr, sign
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], capture_output=True)


@needs_gpg
def test_signed_list_and_matching_file_with_a_chosen_key_file(tmp_path, signer):
    import hashlib
    home, fpr, sign = signer
    d = put(tmp_path, app__tar=b"release", SHA256SUMS=hashlib.sha256(b"release").hexdigest() + "  app.tar\n")
    sign(d / "SHA256SUMS")
    h = real_host(tmp_path)
    v = V.verify(h, d / "app.tar", key_files=[tmp_path / "signer.asc"])
    assert v.level == "signed" and K.group(fpr) in v.text and "Test Signer" in v.text
    # the same key listed as a project's: verified
    p = K.Project("test", "Test Project", "test releases", "https://example.org", "x", __import__("datetime").date(2026, 1, 1),
                  ("app*",), "how", ((fpr, "Test release key"),), K.dearmor((tmp_path / "signer.asc").read_bytes()))
    v = V.verify(h, d / "app.tar", projects=[p])
    assert v.level == "verified" and "SHA256SUMS" in v.text
    # without the key: unchecked, and the issuer is named
    v = V.verify(h, d / "app.tar")
    assert v.level == "intact" and v.lists[0].signature.status == "no_key"
    assert v.lists[0].signature.issuer == fpr


@needs_gpg
def test_the_users_keyring_is_read_and_left_alone(tmp_path, signer):
    home, fpr, sign = signer
    d = put(tmp_path, notes__txt=b"x")
    sign(d / "notes.txt")
    before = sorted((p.name, p.stat().st_mtime_ns) for p in home.iterdir())
    v = V.verify(real_host(tmp_path, GNUPGHOME=str(home)), d / "notes.txt")
    assert v.level == "signed" and v.signatures[0].source == "keyring"
    assert sorted((p.name, p.stat().st_mtime_ns) for p in home.iterdir()) == before
    assert V.verify(real_host(tmp_path, GNUPGHOME=str(home)), d / "notes.txt", use_keyring=False).level == "unchecked"


@needs_gpg
def test_text_added_around_a_clearsigned_list_doesnt_count(tmp_path, signer):
    import hashlib
    home, fpr, sign = signer
    d = put(tmp_path, CHECKSUM="SHA256 (good.iso) = " + hashlib.sha256(b"good").hexdigest() + "\n",
            evil__iso=b"evil", good__iso=b"good")
    sign(d / "CHECKSUM", clear=True)
    (d / "CHECKSUM.asc").rename(d / "CHECKSUM")
    text = (d / "CHECKSUM").read_text()
    (d / "CHECKSUM").write_text("SHA256 (evil.iso) = " + hashlib.sha256(b"evil").hexdigest() + "\n" + text)
    h = real_host(tmp_path)
    assert V.verify(h, d / "good.iso", key_files=[tmp_path / "signer.asc"]).level == "signed"
    assert V.verify(h, d / "evil.iso", key_files=[tmp_path / "signer.asc"]).level == "unchecked"


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="ssh-keygen isn't installed")
def test_ssh_signatures(tmp_path):
    key = tmp_path / "id"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    d = put(tmp_path, tool__tar=b"tool")
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "file", str(d / "tool.tar")],
                   check=True, capture_output=True)
    v = V.verify(real_host(tmp_path), d / "tool.tar")
    assert v.level == "signed" and v.signatures[0].fingerprint.startswith("SHA256:")
    (d / "tool.tar").write_bytes(b"changed")
    assert V.verify(real_host(tmp_path), d / "tool.tar").level == "bad"


def test_key_expiries_from_the_bundled_tor_browser_key():
    """Read from the binding signatures alone, as gpg --show-keys gives them (checked against it)."""
    from daprivacyscanner.tools import keys as K
    tor = next(p for p in K.load() if p.id == "torbrowser")
    exp = K.key_expiries(tor.key)
    assert exp["EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"] == 1921241627
    assert exp["022DA248432D2A0E0F54E65E316C1FACD62D07D9"] == 1859033025      # the subkey signing 15.0.x
    assert sum(1 for v in exp.values() if v is None) <= 1


def test_a_signatures_creation_time_is_read_from_its_hashed_part():
    from daprivacyscanner.tools import keys as K
    hashed = bytes([5, 2]) + (1790687273).to_bytes(4, "big")
    unhashed = bytes([5, 2]) + (1).to_bytes(4, "big")                        # unhashed: anyone could change it
    body = bytes([4, 0, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed + len(unhashed).to_bytes(2, "big") + unhashed
    assert K.signature_created(bytes([0xC2, len(body)]) + body) == 1790687273
    body = bytes([4, 0, 1, 8]) + (0).to_bytes(2, "big") + len(unhashed).to_bytes(2, "big") + unhashed
    assert K.signature_created(bytes([0xC2, len(body)]) + body) is None


def test_the_creation_time_can_be_asked_of_the_signature_by_one_key():
    """Two signature packets in one file: with `issuer`, only the one naming that key (its fingerprint, subpacket
    33, or its key id, 16) gives its date; the other's date, by whoever, doesn't."""
    from daprivacyscanner.tools import keys as K

    def packet(created, fpr=None, keyid=None):
        hashed = bytes([5, 2]) + created.to_bytes(4, "big")
        if fpr:
            hashed += bytes([22, 33, 4]) + bytes.fromhex(fpr)
        if keyid:
            hashed += bytes([9, 16]) + bytes.fromhex(keyid)
        body = bytes([4, 0, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed + (0).to_bytes(2, "big") + b"\xab\xcd"
        return bytes([0xC2, len(body)]) + body
    real, other = "022DA248432D2A0E0F54E65E316C1FACD62D07D9", "1111111111111111111111111111111111111111"
    data = packet(200, fpr=other) + packet(100, fpr=real)
    assert K.signature_created(data) == 200
    assert K.signature_created(data, issuer=real) == 100
    assert K.signature_created(data, issuer=real.lower()) == 100
    assert K.signature_created(data, issuer="316C1FACD62D07D9") == 100                 # by key id
    assert K.signature_created(packet(300, keyid="316C1FACD62D07D9"), issuer=real) == 300
    assert K.signature_created(data, issuer="2222222222222222222222222222222222222222") is None


def test_a_list_of_a_whole_tree_names_the_file_once_per_folder():
    """Mozilla's SHA512SUMS lists firefox-N.tar.xz for every platform and language: the entry that matches is this
    file's, the others are other files. Judging them all made a good download "Don't use this file" (Firefox 157.0.1)."""
    a, b, c = "a" * 128, "b" * 128, "c" * 128
    text = (f"{a}  linux-aarch64/de/firefox-1.0.tar.xz\n{b}  linux-x86_64/en-US/firefox-1.0.tar.xz\n"
            f"{c}  linux-x86_64/de/firefox-1.0.tar.xz\n{'d' * 64}  linux-x86_64/en-US/firefox-1.0.tar.xz\n")
    entries = V.for_file(V.parse_sums(text, "SHA512SUMS"), "firefox-1.0.tar.xz", "SHA512SUMS")
    assert len(entries) == 4
    ok = V.judge(entries, {"sha512": b, "sha256": "d" * 64})
    assert [(e.name, e.algo, m) for e, m in ok] == [("linux-x86_64/en-US/firefox-1.0.tar.xz", "sha512", True),
                                                    ("linux-x86_64/en-US/firefox-1.0.tar.xz", "sha256", True)]
    bad = V.judge(entries, {"sha512": "e" * 128, "sha256": "d" * 64})                 # none of the tree's is this file
    assert [m for _, m in bad] == [False, True] and len(bad) == 2
    # the same name twice in one folder's list is not a tree: both lines are about this file, and both are judged
    twice = V.for_file(V.parse_sums(f"{'1' * 64}  x.iso\n{'2' * 64}  x.iso\n", "SHA256SUMS"), "x.iso", "SHA256SUMS")
    assert [m for _, m in V.judge(twice, {"sha256": "1" * 64})] == [True, False]
