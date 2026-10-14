"""The KWallet reader (kwallet.py) against KWallet's own code: its Blowfish test vector
(backend/tests/testbf.cpp), values from its SHA1 class and password2hash compiled from
KWallet 6.30's source, and wallets made by KWallet 6.30 (tests/samples/kwallet)."""

import struct

import pytest

from daprivacyscanner import kwallet
from daprivacyscanner.kwallet import BLANK, MAGIC, PASSWORD, Blowfish, Unsure, check_blank, kwallet_sha1, legacy_key

from conftest import SAMPLES


def test_blowfish_matches_kwallets_test_vector():
    bf = Blowfish(b"testkey")
    assert (bf.encrypt_block(b"This is ") + bf.encrypt_block(b"a test.\0")).hex() == "3f3c2dae8c0784f2a76d28bd0d0bb879"


def test_pi_tables():
    words = kwallet._pi_words()
    assert (words[0], words[17], words[18], words[-1]) == (0x243F6A88, 0x8979FB1B, 0xD1310BA6, 0x3AC372E6)


def test_kwallets_sha1_is_its_own():
    """KWallet's SHA-1 on PCs reads and writes its words little-endian: not hashlib's."""
    assert kwallet_sha1(b"abc").hex() == "9006c21416fb53f6804f6e39b4af9d4c4f3d516e"
    assert legacy_key(b"").hex() == "e6a93e8bb9bb9cc588750a88a862a701382fbb58"
    assert legacy_key(b"secret").hex() == "d1259557cea6935e8f0648dd3727656ac3f56e8c"


@pytest.mark.parametrize("name, state", [("blank", BLANK), ("protected", PASSWORD)])
def test_real_wallets(name, state):
    assert check_blank(SAMPLES / "kwallet" / f"{name}.kwl") == state


def test_only_the_first_two_blocks_are_decrypted(monkeypatch):
    """The wallet's contents never leave the file encrypted: the probe decrypts 16 bytes."""
    seen = []
    original = kwallet.Blowfish.decrypt

    def decrypt(self, data, cbc=True):
        seen.append(len(data))
        return original(self, data, cbc)
    monkeypatch.setattr(kwallet.Blowfish, "decrypt", decrypt)
    assert check_blank(SAMPLES / "kwallet" / "blank.kwl") == BLANK
    assert check_blank(SAMPLES / "kwallet" / "protected.kwl") == PASSWORD
    assert seen == [16, 16]


def _legacy_wallet(path, cipher, key):
    """A wallet in the pre-4.13 format (minor version 0, the SHA-1 key), written as KWallet's
    BlowfishPersistHandler::write does, with the pieces checked above."""
    data = b"\x00\x00\x00\x00"                                  # no folders (a QDataStream of them)
    newsize = len(data) + 8 + 4 + 20
    delta = 8 - newsize % 8
    plain = bytes(8) + struct.pack(">I", len(data)) + data + bytes(delta) + kwallet_sha1(data)
    bf, prev, enc = Blowfish(key), bytes(8), b""
    for off in range(0, len(plain), 8):
        block = plain[off:off + 8]
        if cipher == 3:
            block = bytes(a ^ b for a, b in zip(block, prev))
        prev = bf.encrypt_block(block)
        enc += prev
    path.write_bytes(MAGIC + bytes([0, 0, cipher, 0]) + struct.pack(">I", 0) + enc)


@pytest.mark.parametrize("cipher", [0, 3])                      # ECB (the old "CBC"), real CBC
def test_legacy_wallets(tmp_path, cipher):
    _legacy_wallet(tmp_path / "old.kwl", cipher, legacy_key(b""))
    assert check_blank(tmp_path / "old.kwl") == BLANK
    _legacy_wallet(tmp_path / "old.kwl", cipher, legacy_key(b"secret"))
    assert check_blank(tmp_path / "old.kwl") == PASSWORD


@pytest.mark.parametrize("content, said", [
    (b"KWALLET\n\r\0\r\n" + bytes([1, 0, 3, 2]), "format version"),
    (b"KWALLET\n\r\0\r\n" + bytes([0, 0, 1, 0]), "encryption the app doesn't know"),
    (b"KWALLET\n\r\0\r\n" + bytes([0, 0, 3, 0]) + b"\xff\xff\xff\xff", "damaged"),
    (b"GnomeKeyring", "isn't a KWallet file"),
])
def test_what_cant_be_judged(tmp_path, content, said):
    (tmp_path / "w.kwl").write_bytes(content)
    with pytest.raises(Unsure, match=said):
        check_blank(tmp_path / "w.kwl")
