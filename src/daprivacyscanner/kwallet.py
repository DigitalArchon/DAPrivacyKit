"""Whether a KDE wallet (KWallet) opens with an empty password, from its file alone.

A wallet with a blank password is still encrypted, with a key made from the empty password,
so its file looks like any other: the only test is to try that key. Only the first two blocks
are decrypted, in memory: the size field they hold must fit the file (a wrong key passes about
once in 500 million tries). The wallet's contents are never decrypted, so none of the user's
secrets are ever in this process's memory; the answer is all that comes out.

The format, from KWallet's backend (kwalletbackend.cc, backendpersisthandler.cpp, blowfish.cc,
cbc.cc, sha1.cc; checked against wallets made by KWallet 6.30, tests/samples/kwallet):

    "KWALLET\\n\\r\\0\\r\\n", then four bytes: major version 0; minor version (1: the key is
    PBKDF2-SHA512 of the password with <wallet>.salt, 50000 rounds, 56 bytes; 0: an older key,
    SHA-1 applied 2000 times); cipher (0 Blowfish ECB, 3 Blowfish CBC, 2 GPG); hash (2 PBKDF2,
    0 SHA-1). Then MD5s of the folder and entry names, in the clear. Then the encrypted part:
    [8 random bytes][data size, 4 bytes big-endian][data][1 to 8 random bytes][SHA-1 of data].

One quirk to match: KWallet's SHA-1 is built as if every machine were big-endian (its source
forces that), so on PCs it reads and writes its 32-bit words little-endian: not the standard
SHA-1, so it can't come from hashlib. (Its Blowfish forces the same setting, which there
cancels out: it is the standard cipher, checked with KWallet's own test vector.) Python's
standard library has no Blowfish, so it is here too."""

from __future__ import annotations

import hashlib
import struct
from functools import lru_cache
from pathlib import Path

MAGIC = b"KWALLET\n\r\0\r\n"
BLANK, PASSWORD, GPG = "blank", "password", "gpg"


class Unsure(Exception):
    """The file couldn't be judged; the message says why."""


@lru_cache(maxsize=1)
def _pi_words() -> tuple[int, ...]:
    """Blowfish's initial P-array and S-boxes: the hexadecimal digits of pi after "3.", in
    1042 words of 32 bits (computed with Machin's formula rather than written out)."""
    n = 18 + 4 * 256
    bits = 32 * n + 64                                  # 64 guard bits

    def arctan_inv(x: int) -> int:                      # arctan(1/x) * 2**bits
        term = total = (1 << bits) // x
        k, sign = 1, -1
        while term:
            term //= x * x
            k += 2
            total += sign * (term // k)
            sign = -sign
        return total
    frac = (16 * arctan_inv(5) - 4 * arctan_inv(239)) - (3 << bits)
    frac >>= 64
    return tuple((frac >> (32 * (n - 1 - i))) & 0xFFFFFFFF for i in range(n))


class Blowfish:
    """The standard Blowfish cipher (decryption, and encryption of single blocks for tests)."""

    def __init__(self, key: bytes):
        if not 1 <= len(key) <= 56:
            raise ValueError("Blowfish keys are 1 to 56 bytes")
        words = list(_pi_words())
        self.P = words[:18]
        self.S = [words[18 + 256 * i:18 + 256 * (i + 1)] for i in range(4)]
        j = 0
        for i in range(18):
            d = 0
            for _ in range(4):
                d = (d << 8) | key[j]
                j = (j + 1) % len(key)
            self.P[i] ^= d
        left = right = 0
        for i in range(0, 18, 2):
            left, right = self._encipher(left, right)
            self.P[i], self.P[i + 1] = left, right
        for box in self.S:
            for i in range(0, 256, 2):
                left, right = self._encipher(left, right)
                box[i], box[i + 1] = left, right

    def _f(self, x: int) -> int:
        s0, s1, s2, s3 = self.S
        return ((((s0[x >> 24] + s1[(x >> 16) & 0xFF]) & 0xFFFFFFFF) ^ s2[(x >> 8) & 0xFF]) + s3[x & 0xFF]) & 0xFFFFFFFF

    def _encipher(self, left: int, right: int) -> tuple[int, int]:
        P, f = self.P, self._f
        for i in range(16):
            left ^= P[i]
            right ^= f(left)
            left, right = right, left
        left, right = right, left
        return left ^ P[17], right ^ P[16]

    def _decipher(self, left: int, right: int) -> tuple[int, int]:
        P, f = self.P, self._f
        for i in range(17, 1, -1):
            left ^= P[i]
            right ^= f(left)
            left, right = right, left
        left, right = right, left
        return left ^ P[0], right ^ P[1]

    def encrypt_block(self, block: bytes) -> bytes:
        return struct.pack(">2I", *self._encipher(*struct.unpack(">2I", block)))

    def decrypt(self, data: bytes, cbc: bool = True) -> bytes:
        """Decrypt whole blocks: CBC with a zero starting vector, or ECB (wallets that were
        written before KWallet's "CBC" was made real)."""
        out, prev = bytearray(), bytes(8)
        for off in range(0, len(data) - len(data) % 8, 8):
            block = data[off:off + 8]
            plain = struct.pack(">2I", *self._decipher(*struct.unpack(">2I", block)))
            if cbc:
                plain = bytes(a ^ b for a, b in zip(plain, prev))
                prev = block
            out += plain
        return bytes(out)


def kwallet_sha1(data: bytes) -> bytes:
    """SHA-1 as KWallet computes it on little-endian machines: the message's 32-bit words and
    the digest's are read and written little-endian. (Its length field is still big-endian.)"""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = data + b"\x80" + bytes((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "big")
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF   # noqa: E731
    for off in range(0, len(msg), 64):
        w = list(struct.unpack("<16I", msg[off:off + 64]))
        for i in range(16, 80):
            w.append(rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f, k = (b & c) | (~b & d), 0x5A827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            a, b, c, d, e = (rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF, a, rol(b, 30), c, d
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e))]
    return struct.pack("<5I", *h)


def legacy_key(password: bytes = b"") -> bytes:
    """The key of wallets from before KDE 4.13 (minor version 0), for passwords of up to 16
    bytes: KWallet's SHA-1 of the password, then of its own result, 2000 times."""
    if len(password) > 16:
        raise ValueError("only passwords of up to 16 bytes")
    block = kwallet_sha1(password)
    for _ in range(1999):
        block = kwallet_sha1(block)
    return block


def _encrypted_part(data: bytes) -> bytes:
    """Skip the header and the name hashes; what is left is encrypted."""
    off = len(MAGIC) + 4
    try:
        (folders,) = struct.unpack_from(">I", data, off)
        off += 4
        if folders > 0xFFFF:
            raise Unsure("the wallet file is damaged")
        for _ in range(folders):
            (entries,) = struct.unpack_from(">I", data, off + 16)
            off += 20 + 16 * entries
    except struct.error:
        raise Unsure("the wallet file is damaged") from None
    if off > len(data):
        raise Unsure("the wallet file is damaged")
    return data[off:]


def opens_with(data: bytes, key: bytes, cbc: bool) -> bool:
    """Whether this key opens the wallet whose file is `data`: the size field in its first two
    blocks and the padding must add up. Only those 16 bytes (8 random bytes, the size, and the
    first 4 bytes of the data) are ever decrypted: the contents stay encrypted, so a crash dump
    of this process could never hold them. A wrong key passes about once in 500 million tries
    (8 of 2**32 sizes fit), which the SHA-1 at the end could rule out only by decrypting it all."""
    enc = _encrypted_part(data)
    if not enc or len(enc) % 8:
        raise Unsure("the wallet file is damaged")
    head = Blowfish(key).decrypt(enc[:16], cbc)
    (size,) = struct.unpack_from(">I", head, 8)
    return 1 <= len(enc) - 32 - size <= 8                # 8 random + 4 size + data + 1-8 padding + 20 hash


def check_blank(path: Path) -> str:
    """BLANK (opens with an empty password), PASSWORD (it doesn't) or GPG (protected by a GPG
    key). Raises Unsure when it can't be told, OSError when the file can't be read."""
    data = path.read_bytes()
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
        raise Unsure("it isn't a KWallet file")
    major, minor, cipher, kdf = data[len(MAGIC):len(MAGIC) + 4]
    if major != 0 or minor not in (0, 1):
        raise Unsure(f"its format version ({major}.{minor}) is unknown to the app")
    if cipher == 2:
        return GPG
    if cipher not in (0, 3) or kdf not in (0, 2):
        raise Unsure("it uses an encryption the app doesn't know")
    if minor == 1:
        salt_file = path.with_suffix(".salt")
        try:
            salt = salt_file.read_bytes()
        except FileNotFoundError:
            raise Unsure(f"its salt file ({salt_file.name}) is missing") from None
        if not salt:
            raise Unsure(f"its salt file ({salt_file.name}) is empty")
        key = hashlib.pbkdf2_hmac("sha512", b"", salt, 50000, 56)
    else:
        key = legacy_key(b"")
    return BLANK if opens_with(data, key, cbc=cipher == 3) else PASSWORD
