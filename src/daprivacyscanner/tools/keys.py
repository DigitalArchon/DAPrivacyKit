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
from collections.abc import Iterable, Iterator
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


def packets(data: bytes) -> Iterator[tuple[int, bytes]]:
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
    subkeys: tuple[str, ...] = ()         # those its primary key binds (a subkey binding signature it made follows)
    uids: tuple[str, ...] = ()
    unbound: tuple[str, ...] = ()         # subkey packets with no binding signature by this primary: never its own

    @property
    def all(self) -> tuple[str, ...]:
        return (self.fingerprint,) + self.subkeys


def _names_key(sig_body: bytes, fpr: str) -> bool:
    """Whether a signature names this key as its issuer: its fingerprint (subpacket 33), or its key id (16), which is
    a v4 fingerprint's last 16 hex digits and a v6 one's first."""
    for kind, sub, _ in _subpackets(sig_body):
        if kind == 33 and len(sub) >= 1 and sub[1:].hex().upper() == fpr:
            return True
        if kind == 16 and len(sub) == 8 and sub.hex().upper() in (fpr[-16:], fpr[:16]):
            return True
    return False


def parse_keys(data: bytes | str) -> list[KeyInfo]:
    """The keys in armoured or binary key data, each with its subkeys and user IDs. A subkey counts as the key's only
    when a subkey binding signature (type 0x18) issued by that primary key follows it: a subkey packet spliced into
    a key block from elsewhere stays `unbound`. This reads the packets' structure; gpgv and sqv check the
    signatures themselves, and accept nothing a binding doesn't hold up."""
    keys: list[dict] = []
    sub: str | None = None
    for tag, body in packets(dearmor(data)):
        if tag == PUBLIC_KEY:
            keys.append({"fpr": fingerprint(body), "subs": [], "uids": [], "bound": set()})
            sub = None
        elif tag == PUBLIC_SUBKEY and keys:
            sub = fingerprint(body)
            keys[-1]["subs"].append(sub)
        elif tag == USER_ID and keys:
            keys[-1]["uids"].append(body.decode("utf-8", errors="replace"))
            sub = None
        elif tag == SIGNATURE and keys and sub and body[:1] in (b"\x04", b"\x05", b"\x06") and len(body) > 1 \
                and body[1] == 0x18 and _names_key(body, keys[-1]["fpr"]):
            keys[-1]["bound"].add(sub)
    if not keys:
        raise PacketError("no public key in it")
    return [KeyInfo(k["fpr"], tuple(s for s in k["subs"] if s in k["bound"]), tuple(k["uids"]),
                    tuple(s for s in k["subs"] if s not in k["bound"])) for k in keys]


def _subpackets(body: bytes) -> Iterator[tuple[int, bytes, bool]]:
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


def _signatures(data: bytes | str) -> Iterator[bytes]:
    for tag, body in packets(dearmor(data)):
        if tag == SIGNATURE and body and body[0] in (4, 5, 6):
            yield body


def signature_issuers(data: bytes | str) -> list[str]:
    """Who made each signature in signature data: the issuer fingerprint (subpacket 33) when it
    is there, else the issuer key id (subpacket 16, 16 hex digits). Read from the packets alone,
    so it works without gpgv and without the key."""
    out: list[str] = []
    for body in _signatures(data):
        fpr = keyid = ""
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
    current: str | None = None
    created = 0                                      # the current key's, set with it
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


KEY_REVOCATION, SUBKEY_REVOCATION = 0x20, 0x28
USER_ATTRIBUTE = 17


def revoked_keys(data: bytes) -> set[str]:
    """The fingerprints of the keys and subkeys that key data holds a revocation for: a key revocation (0x20)
    after a primary key, which takes its subkeys with it, or a subkey revocation (0x28) after a subkey. The
    revocations aren't checked here: those in a keyring were checked by gpg as it imported them, the app's own
    copies are its own, and one in a key file the user chose can at worst make a good file look bad. gpgv sees
    only the first copy of a key it finds, and reports a key both expired and revoked as only expired
    (EXPKEYSIG, tested with gpgv 2.4.4), so a revocation in any copy has to be looked for here."""
    out: set[str] = set()
    primary: str | None = None
    current: str | None = None
    subs: list[str] = []
    gone = False

    def done() -> None:
        if primary and gone:
            out.add(primary)
            out.update(subs)

    for tag, body in packets(data):
        if tag == PUBLIC_KEY:
            done()
            try:
                primary = current = fingerprint(body)
            except PacketError:
                primary = current = None
            subs, gone = [], False
        elif tag == PUBLIC_SUBKEY:
            try:
                current = fingerprint(body)
                subs.append(current)
            except PacketError:
                current = None
        elif tag in (USER_ID, USER_ATTRIBUTE):
            current = None                            # what follows certifies the user ID, it revokes no key
        elif tag == SIGNATURE and current and body:
            kind = body[2] if body[0] == 3 and len(body) > 2 else body[1] if len(body) > 1 else None
            if kind == KEY_REVOCATION and current == primary:
                gone = True
            elif kind == SUBKEY_REVOCATION and current != primary:
                out.add(current)
    done()
    return out


def keybox_blocks(data: bytes) -> Iterator[bytes]:
    """The OpenPGP key blocks in a GnuPG keybox (pubring.kbx): each blob is its length (4 bytes), its type (1
    byte, 2 for OpenPGP), version and flags, then where its key block starts in it and how long it is."""
    i, n = 0, len(data)
    while i + 16 <= n:
        size = int.from_bytes(data[i:i + 4], "big")
        if size < 16 or i + size > n:
            return
        if data[i + 4] == 2:
            off, length = int.from_bytes(data[i + 8:i + 12], "big"), int.from_bytes(data[i + 12:i + 16], "big")
            if off + length <= size:
                yield data[i + off:i + off + length]
        i += size


def keyring_revocations(data: bytes) -> set[str]:
    """revoked_keys() over a keyring file as gpgv reads it: a keybox, or OpenPGP packets one after the other.
    Damaged blocks are passed over."""
    blocks = list(keybox_blocks(data)) if data[8:12] == b"KBXf" else [data]
    out: set[str] = set()
    for b in blocks:
        try:
            out |= revoked_keys(b)
        except PacketError:
            continue
    return out


@functools.lru_cache(maxsize=64)
def _subkeys_by_primary(key: bytes) -> dict[str, tuple[str, ...]]:
    return {k.fingerprint: k.subkeys for k in parse_keys(key)} if key else {}


def pinned(projects: Iterable[Project], primary: str, signer: str = "") -> tuple[Project, str, bool] | None:
    """(project, key name, the signing key is in the app's copy) when `primary`, the primary key gpgv says made a
    signature (VALIDSIG's last field), is one a project pins. Only a primary counts: a v4 fingerprint is the
    same whether its packet is a primary key or a subkey, so a project's signing subkey, stolen and wrapped as a
    primary key of someone else's with a self-signature of their own, has the subkey's fingerprint as its
    primary's, and matching subkeys here made a file signed with it "Verified". `signer` (VALIDSIG's first
    field): the key that signed, the primary or one of its subkeys; one the app's copy doesn't have came from the
    user's copy of the key, where gpgv found it bound to that primary."""
    primary, signer = primary.upper(), (signer or primary).upper()
    for p in projects:
        for f, name in p.keys:
            if f == primary:
                return p, name, signer == f or signer in _subkeys_by_primary(p.key).get(f, ())
    return None


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


def _text(v: object) -> str:
    return " ".join(str(v).split()) if v is not None else ""


def parse(data: object) -> list[Project]:
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
            if set(k) - {"fingerprint", "name"}:
                raise DataError(f"{where}: a key has a fingerprint and a name, nothing else")
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


def owner(projects: Iterable[Project], fpr: str) -> tuple[Project, str] | None:
    """The project whose key (primary or subkey) has this fingerprint or key id, and the key's name: for naming
    who a signature says made it (an issuer whose key is missing, a bad signature), never for deciding that a
    good one is a project's (pinned())."""
    fpr = fpr.upper()
    for p in projects:
        for f, name in p.keys:
            if f == fpr or (len(fpr) == 16 and f.endswith(fpr)):
                return p, name
        if fpr in p.subkeys or (len(fpr) == 16 and any(s.endswith(fpr) for s in p.subkeys)):
            return p, p.keys[0][1] if len(p.keys) == 1 else p.name
    return None


def published(projects: Iterable[Project], sha256: str | None) -> tuple[Project, str, str] | None:
    """(project, file name, page) when a project publishes this SHA-256 on its own site."""
    if not sha256:
        return None
    for p in projects:
        for name, digest, page in p.checksums:
            if digest == sha256.lower():
                return p, name, page
    return None


def for_file(projects: Iterable[Project], filename: str) -> Project | None:
    return next((p for p in projects if p.matches(filename)), None)


def all_for_file(projects: Iterable[Project], filename: str) -> list[Project]:
    """Every project whose files are named like this one (Tor Browser Developers sign Mullvad Browser too)."""
    return [p for p in projects if p.matches(filename)]


def keyring(projects: Iterable[Project]) -> bytes:
    """Every project's keys as one binary keyring, as gpgv and sqv read it."""
    return b"".join(p.key for p in projects)
