"""The release signing keys in signing-keys.yaml, and just enough OpenPGP to check them: reading
armour, the packets of a key (primary key, subkeys, user IDs) and computing their fingerprints, and
the issuer of a signature. Verifying signatures is the host's gpgv (or sqv); this module only makes
sure the keys handed to it are the ones the data pins, and names who made a signature.

The loader refuses a key block whose primary keys aren't exactly the fingerprints listed with it, so
a key changed in the data file without its pin (or the other way round) never loads."""

from __future__ import annotations

import base64
import datetime as dt
import fnmatch
import functools
import hashlib
import os
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml

DATA_NAME = "signing-keys.yaml"
SCHEMA_VERSION = 1
_FPR = re.compile(r"^[0-9A-F]{40}$")
_ARMOR = re.compile(r"-----BEGIN PGP (PUBLIC KEY BLOCK|SIGNATURE|MESSAGE)-----\r?\n(.*?)-----END PGP \1-----", re.S)

# packet tags (RFC 9580, 5.)
SIGNATURE, PUBLIC_KEY, USER_ID, PUBLIC_SUBKEY = 2, 6, 13, 14


class DataError(ValueError):
    pass


class PacketError(ValueError):
    pass


# ------------------------------------------------------------------ OpenPGP, read only

def dearmor(data: bytes | str) -> bytes:
    """The binary packets of armoured data (every block in it, in order); binary data as it is."""
    text = data.decode("ascii", errors="replace") if isinstance(data, bytes) else data
    blocks = _ARMOR.findall(text)
    if not blocks:
        if isinstance(data, bytes) and data[:1] and data[0] & 0x80:
            return data
        raise PacketError("not OpenPGP data")
    out = b""
    for _, body in blocks:
        lines = body.splitlines()
        start = lines.index("") + 1 if "" in lines else 0        # armour headers end at the first empty line
        payload = "".join(ln.strip() for ln in lines[start:] if ln.strip() and not ln.startswith("="))
        try:
            out += base64.b64decode(payload, validate=True)
        except ValueError:
            raise PacketError("damaged armour") from None
    return out


def packets(data: bytes):
    """(tag, body) for each packet. Old and new packet formats; partial lengths aren't used in keys
    or detached signatures, so they are refused."""
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if not b & 0x80:
            raise PacketError("not an OpenPGP packet")
        if b & 0x40:                                     # new format
            tag = b & 0x3F
            o = data[i + 1] if i + 1 < n else None
            if o is None:
                raise PacketError("truncated")
            if o < 192:
                length, i = o, i + 2
            elif o < 224:
                if i + 2 >= n:
                    raise PacketError("truncated")
                length, i = ((o - 192) << 8) + data[i + 2] + 192, i + 3
            elif o == 255:
                length, i = int.from_bytes(data[i + 2:i + 6], "big"), i + 6
            else:
                raise PacketError("partial lengths aren't supported here")
        else:                                            # old format
            tag, kind = (b >> 2) & 0x0F, b & 0x03
            if kind == 3:
                length, i = n - i - 1, i + 1
            else:
                size = (1, 2, 4)[kind]
                length, i = int.from_bytes(data[i + 1:i + 1 + size], "big"), i + 1 + size
        if i + length > n:
            raise PacketError("truncated")
        yield tag, data[i:i + length]
        i += length


def fingerprint(body: bytes) -> str:
    """A public key or subkey packet's fingerprint: v4 SHA-1, v5 and v6 SHA-256 (RFC 9580, 5.5.4)."""
    version = body[0] if body else 0
    if version == 4:
        return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
    if version in (5, 6):
        prefix = b"\x9a" if version == 5 else b"\x9b"
        return hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body).hexdigest().upper()
    raise PacketError(f"key version {version} isn't supported")


@dataclass(frozen=True)
class KeyInfo:
    fingerprint: str                      # the primary key's
    subkeys: tuple[str, ...] = ()
    uids: tuple[str, ...] = ()

    @property
    def all(self) -> tuple[str, ...]:
        return (self.fingerprint,) + self.subkeys


def parse_keys(data: bytes | str) -> list[KeyInfo]:
    """The keys in armoured or binary key data, each with its subkeys and user IDs."""
    keys: list[dict] = []
    for tag, body in packets(dearmor(data)):
        if tag == PUBLIC_KEY:
            keys.append({"fpr": fingerprint(body), "subs": [], "uids": []})
        elif tag == PUBLIC_SUBKEY and keys:
            keys[-1]["subs"].append(fingerprint(body))
        elif tag == USER_ID and keys:
            keys[-1]["uids"].append(body.decode("utf-8", errors="replace"))
    if not keys:
        raise PacketError("no public key in it")
    return [KeyInfo(k["fpr"], tuple(k["subs"]), tuple(k["uids"])) for k in keys]


def _subpackets(body: bytes):
    """(kind, data, hashed) for each subpacket of a v4, v5 or v6 signature packet's body."""
    pos, wide = 4, body[0] in (5, 6)                 # version, type, pubkey algo, hash algo; v5/v6 counts are 4 bytes
    for hashed in (True, False):
        size = 4 if wide else 2
        count = int.from_bytes(body[pos:pos + size], "big")
        area, pos = body[pos + size:pos + size + count], pos + size + count
        j = 0
        while j < len(area):
            o = area[j]
            if o < 192:
                ln, j = o, j + 1
            elif o < 255:
                ln, j = ((o - 192) << 8) + area[j + 1] + 192, j + 2
            else:
                ln, j = int.from_bytes(area[j + 1:j + 5], "big"), j + 5
            sub = area[j:j + ln]
            j += ln
            if sub:
                yield sub[0] & 0x7F, sub[1:], hashed


def _signatures(data: bytes | str):
    for tag, body in packets(dearmor(data)):
        if tag == SIGNATURE and body and body[0] in (4, 5, 6):
            yield body


def signature_issuers(data: bytes | str) -> list[str]:
    """Who made each signature in signature data: the issuer fingerprint (subpacket 33) when it
    is there, else the issuer key id (subpacket 16, 16 hex digits). Read from the packets alone,
    so it works without gpgv and without the key."""
    out = []
    for body in _signatures(data):
        fpr = keyid = None
        for kind, sub, _ in _subpackets(body):
            if kind == 33 and len(sub) >= 1:
                fpr = sub[1:].hex().upper()
            elif kind == 16 and len(sub) == 8:
                keyid = sub.hex().upper()
        if fpr or keyid:
            out.append(fpr or keyid)
    return out


def signature_created(data: bytes | str, issuer: str | None = None) -> int | None:
    """When the signature was made, from its hashed creation-time subpacket (2): part of what is
    signed, so a good signature vouches for it. `issuer`: only a signature that names that key (its
    fingerprint, or the key id a fingerprint ends in) counts, so the date is the verified signature's
    and not another packet's in the same file (one by any key, with any date, leaves gpgv's verdict
    on the real one as it is). Without it, the first signature's. None when there isn't one."""
    want = (issuer or "").upper()
    for body in _signatures(data):
        if want:
            names = set()
            for kind, sub, _ in _subpackets(body):
                if kind == 33 and len(sub) >= 1:
                    names.add(sub[1:].hex().upper())
                elif kind == 16 and len(sub) == 8:
                    names.add(sub.hex().upper())
            if not any(n == want or (len(n) == 16 and want.endswith(n)) or (len(want) == 16 and n.endswith(want))
                       for n in names):
                continue
        for kind, sub, hashed in _subpackets(body):
            if kind == 2 and hashed and len(sub) == 4:
                return int.from_bytes(sub, "big")
    return None


def key_expiries(data: bytes | str) -> dict[str, int | None]:
    """When each key and subkey in key data expires (seconds since the epoch), None for never: from
    the newest self-signature (primary) or binding signature (subkey), its key-expiration subpacket
    (9) counted from the key's creation. For checking, before a release, that a project's bundled
    key hasn't run out (packaging/check-signing-keys.py)."""
    out: dict[str, int | None] = {}
    newest: dict[str, int] = {}
    current = created = None
    for tag, body in packets(dearmor(data)):
        if tag in (PUBLIC_KEY, PUBLIC_SUBKEY):
            current, created = fingerprint(body), int.from_bytes(body[1:5], "big")
            out.setdefault(current, None)
        elif tag == SIGNATURE and current and body and body[0] in (4, 5, 6):
            sig_type = body[1]
            if sig_type not in (0x10, 0x11, 0x12, 0x13, 0x18, 0x1F):
                continue
            when, life = 0, None
            for kind, sub, hashed in _subpackets(body):
                if hashed and kind == 2 and len(sub) == 4:
                    when = int.from_bytes(sub, "big")
                elif hashed and kind == 9 and len(sub) == 4:
                    life = int.from_bytes(sub, "big")
            if when >= newest.get(current, -1):
                newest[current] = when
                out[current] = created + life if life else None
    return out


def group(fpr: str) -> str:
    """A fingerprint as people compare it: "27DE B156 44C6 ..." (two halves of five groups)."""
    g = [fpr[i:i + 4] for i in range(0, len(fpr), 4)]
    return " ".join(g[:5]) + "  " + " ".join(g[5:]) if len(g) == 10 else " ".join(g)


# ------------------------------------------------------------------ the data

@dataclass(frozen=True)
class Project:
    id: str
    name: str
    signs: str
    source: str
    key_from: str
    checked: dt.date
    files: tuple[str, ...]
    how: str
    keys: tuple[tuple[str, str], ...]            # (primary fingerprint, name)
    key: bytes                                   # the binary key packets, as checked
    subkeys: tuple[str, ...] = ()
    note: str = ""
    unsigned: bool = False                       # it publishes no signature: `how` says what there is
    # SHA-256s the project publishes on its own site for files it doesn't sign: (file, sha256, page)
    checksums: tuple[tuple[str, str, str], ...] = ()

    def matches(self, filename: str) -> bool:
        return any(fnmatch.fnmatchcase(filename, pat) for pat in self.files)

    def key_name(self, fpr: str) -> str:
        return next((n for f, n in self.keys if f == fpr), self.name)


def default_path() -> Path:
    env = os.environ.get("DAPRIVACYSCANNER_SIGNING_KEYS")
    if env:
        return Path(env)
    repo = Path(__file__).resolve().parents[3] / DATA_NAME
    if repo.is_file():
        return repo
    return Path(str(resources.files("daprivacyscanner") / DATA_NAME))


def _text(v) -> str:
    return " ".join(str(v).split()) if v is not None else ""


def parse(data) -> list[Project]:
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise DataError(f"{DATA_NAME}: unsupported schema_version")
    out, seen = [], set()
    for i, p in enumerate(data.get("projects") or []):
        where = f"projects[{i}]" + (f" ({p.get('id')})" if isinstance(p, dict) else "")
        if not isinstance(p, dict):
            raise DataError(f"{where}: must be a mapping")
        unsigned = p.get("unsigned") is True
        required = ("id", "name", "signs", "source", "checked", "files", "how") + (() if unsigned else ("key_from", "keys", "key"))
        missing = [k for k in required if not p.get(k)]
        if missing:
            raise DataError(f"{where}: missing {', '.join(missing)}")
        if unsigned and (p.get("keys") or p.get("key")):
            raise DataError(f"{where}: a project marked unsigned has no keys")
        unknown = set(p) - {"id", "name", "signs", "source", "key_from", "checked", "note", "files", "how", "keys", "key",
                            "unsigned", "checksums"}
        if unknown:
            raise DataError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
        if p["id"] in seen:
            raise DataError(f"{where}: duplicate id")
        seen.add(p["id"])
        if not str(p["source"]).startswith("https://"):
            raise DataError(f"{where}: the source must be an https:// page of the project's")
        if not isinstance(p["checked"], dt.date):
            raise DataError(f"{where}: checked must be a date (YYYY-MM-DD)")
        sums = []
        for c in p.get("checksums") or []:
            c = c or {}
            digest, page = str(c.get("sha256", "")).lower(), str(c.get("source", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", digest) or not c.get("file") or not page.startswith("https://"):
                raise DataError(f"{where}: each checksum needs a file, its sha256 and the https:// page it is on")
            sums.append((str(c["file"]), digest, page))
        if unsigned:
            out.append(Project(p["id"], _text(p["name"]), _text(p["signs"]), p["source"], _text(p.get("key_from")),
                               p["checked"], tuple(str(x) for x in p["files"]), _text(p["how"]), (), b"",
                               note=_text(p.get("note")), unsigned=True, checksums=tuple(sums)))
            continue
        pins = []
        for k in p["keys"]:
            fpr = str((k or {}).get("fingerprint", "")).upper()
            if not _FPR.match(fpr) or not (k or {}).get("name"):
                raise DataError(f"{where}: each key needs a 40-digit fingerprint and a name")
            pins.append((fpr, _text(k["name"])))
        try:
            binary = dearmor(str(p["key"]))
            infos = parse_keys(binary)
        except PacketError as e:
            raise DataError(f"{where}: the key block can't be read ({e})") from None
        got = {k.fingerprint for k in infos}
        if got != {f for f, _ in pins}:
            raise DataError(f"{where}: the key block holds {', '.join(sorted(got))}, not the fingerprints "
                            f"pinned with it ({', '.join(f for f, _ in pins)})")
        out.append(Project(p["id"], _text(p["name"]), _text(p["signs"]), p["source"], _text(p["key_from"]),
                           p["checked"], tuple(str(x) for x in p["files"]), _text(p["how"]), tuple(pins), binary,
                           tuple(s for k in infos for s in k.subkeys), _text(p.get("note")), checksums=tuple(sums)))
    if not out:
        raise DataError(f"{DATA_NAME}: no projects")
    return out


@functools.lru_cache(maxsize=4)
def _load_cached(path: str, mtime: float) -> tuple[Project, ...]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise DataError(f"can't read {path}: {e}") from None
    return tuple(parse(data))


def load(path: Path | str | None = None) -> tuple[Project, ...]:
    p = Path(path) if path else default_path()
    try:
        mtime = p.stat().st_mtime
    except OSError as e:
        raise DataError(f"can't read {p}: {e}") from None
    return _load_cached(str(p), mtime)


def owner(projects, fpr: str) -> tuple[Project, str] | None:
    """The project whose key (primary or subkey) has this fingerprint or key id, and the key's name."""
    fpr = fpr.upper()
    for p in projects:
        for f, name in p.keys:
            if f == fpr or (len(fpr) == 16 and f.endswith(fpr)):
                return p, name
        if fpr in p.subkeys or (len(fpr) == 16 and any(s.endswith(fpr) for s in p.subkeys)):
            return p, p.keys[0][1] if len(p.keys) == 1 else p.name
    return None


def published(projects, sha256: str | None) -> tuple[Project, str, str] | None:
    """(project, file name, page) when a project publishes this SHA-256 on its own site."""
    if not sha256:
        return None
    for p in projects:
        for name, digest, page in p.checksums:
            if digest == sha256.lower():
                return p, name, page
    return None


def for_file(projects, filename: str) -> Project | None:
    return next((p for p in projects if p.matches(filename)), None)


def keyring(projects) -> bytes:
    """Every project's keys as one binary keyring, as gpgv and sqv read it."""
    return b"".join(p.key for p in projects)
