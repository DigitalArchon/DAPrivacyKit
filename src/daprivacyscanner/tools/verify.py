"""Verify a download (docs/TECHNICAL.md, Tools): is this file the one its makers published?

Two different questions, kept apart in the verdict:
- is it intact: does it match a checksum (from a list next to it, or one the user pastes)? That
  catches a damaged download, not a changed one: whoever could change the file could change a
  checksum published next to it;
- who made it: is it, or a checksum list that holds its hash, signed by a key, and whose? Only a
  good signature by a key listed in signing-keys.yaml (fingerprints confirmed on the project's own
  site) is "verified"; a good signature by any other key shows the fingerprint, to compare.

Signatures are checked by the host's gpgv (or sqv, for detached OpenPGP signatures when gpgv is
missing), ssh-keygen and minisign. gpgv runs with a temporary home and keyrings of the app's own;
the user's GnuPG keyring is only ever read. Nothing is fetched and nothing is kept."""

from __future__ import annotations

import hashlib
import os
import re
import struct
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..host import CommandResult, Host
from . import keys as K
from . import packages as P

MAX_COMPANION = 2 * 1024 * 1024         # checksum lists and signatures are small; anything bigger isn't one
MAX_KEYRING = 64 * 1024 * 1024          # a keyring read for its revocations (gpgv itself reads any size)
MAX_DIR_ENTRIES = 2000
CHUNK = 1024 * 1024
SIG_SUFFIXES = (".asc", ".sig", ".gpg", ".sign", ".minisig")
# lists of checksums: SHA256SUMS, sha256sum.txt, b2sums.txt, CHECKSUM, Fedora-...-CHECKSUM, foo.iso.sha256, foo.DIGEST
SUMS_NAME = re.compile(r"^(?:(?:sha(?:1|224|256|384|512)|md5|b2)sums?|checksums?)(?:\.txt)?$|checksum$"
                       r"|\.(?:sha(?:1|256|512)(?:sum)?|md5|digest)(?:\.txt)?$", re.I)
HEX_ALGOS = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
BSD_ALGOS = {"MD5": "md5", "SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256", "SHA384": "sha384",
             "SHA512": "sha512", "BLAKE2B": "blake2b", "BLAKE2B-512": "blake2b"}
WEAK = {"md5", "sha1"}
ALGO_TITLE = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
              "sha512": "SHA-512", "blake2b": "BLAKE2b"}
_BSD = re.compile(r"^(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|BLAKE2b(?:-512)?)\s*\((.+)\)\s*=\s*([0-9A-Fa-f]+)\s*$", re.I)
_GNU = re.compile(r"^\\?([0-9A-Fa-f]{32,128})\s+\*?(.+?)\s*$")
_BARE = re.compile(r"^([0-9A-Fa-f]{32,128})\s*$")
CLEARSIGNED = "-----BEGIN PGP SIGNED MESSAGE-----"
SIGNATURE_BEGIN, SIGNATURE_END = "-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----"

LEVELS = ("verified", "other_project", "expired", "signed", "intact", "bad", "unchecked")


# ------------------------------------------------------------------ checksum lists

@dataclass(frozen=True)
class Entry:
    algo: str
    digest: str               # lower-case hex
    name: str | None          # the file it is for; None for a bare checksum (a <file>.sha256 holding only that)


class Unclear(ValueError):
    """What a clearsigned file signs can't be told for sure: it is taken as changed since it was signed."""


@dataclass(frozen=True)
class Clearsigned:
    """A clearsigned message's place in a file, and what it signs."""
    before: bytes                        # what comes before its first armour line
    message: bytes                       # "-----BEGIN PGP SIGNED MESSAGE-----" through "-----END PGP SIGNATURE-----"
    after: bytes
    text: str                            # what it signs: after the armour headers, up to the signature


def clearsigned(data: bytes) -> Clearsigned | None:
    """The clearsigned message in `data` (RFC 9580, 7.1), or None if there is none. Read as GnuPG reads it:
    lines end at "\\n" alone, an armour line is its marker at a line's start (white space may follow), the
    headers end at the first blank line, dash-escaping is undone and trailing white space dropped (as gpgv
    writes the text out). Raises Unclear when the marker is anywhere else, or there more than once: gpgv
    checks the one real message and passes over the rest, so a marker hidden at the end of a line, or a
    second message (signed by anyone, or by no one), would have the text after it taken for signed (a file
    of someone else's was "Verified: made by Fedora" with one line added above Fedora's real list)."""
    marker = CLEARSIGNED.encode()
    count = data.count(marker)
    if not count:
        return None
    if count > 1:
        raise Unclear("it holds more than one signed part, or text made to look like one")
    lines, pos = [], 0
    for raw in data.split(b"\n"):
        lines.append((pos, raw))
        pos += len(raw) + 1

    def armour(raw: bytes, word: str) -> bool:
        return raw.rstrip(b" \t\r") == word.encode()

    start = next(i for i, (_, raw) in enumerate(lines) if marker in raw)
    if not armour(lines[start][1], CLEARSIGNED):
        raise Unclear("text in it is made to look like the start of a signed part")
    try:
        body = next(i for i in range(start + 1, len(lines)) if not lines[i][1].rstrip(b" \t\r")) + 1
        sig = next(i for i in range(body, len(lines)) if armour(lines[i][1], SIGNATURE_BEGIN))
        end = next(i for i in range(sig + 1, len(lines)) if armour(lines[i][1], SIGNATURE_END))
    except StopIteration:
        return None
    a, b = lines[start][0], min(lines[end][0] + len(lines[end][1]) + 1, len(data))
    text = "\n".join((raw[2:] if raw.startswith(b"- ") else raw).decode("utf-8", "replace").rstrip(" \t\r")
                     for _, raw in lines[body:sig])
    return Clearsigned(data[:a], data[a:b], data[b:], text)


def signed_text(text: str) -> str | None:
    """The text a clearsigned message signs (clearsigned()), or None if it isn't one. Only this is
    trusted: anything before or after the message is ignored. Raises Unclear (see clearsigned)."""
    c = clearsigned(text.encode("utf-8", "surrogateescape"))
    return None if c is None else c.text


def _same_text(a: str, b: str) -> bool:
    """Whether two readings of a signed text agree, line by line, but for trailing white space and blank lines."""
    def lines(t: str) -> list[str]:
        out = [ln.rstrip(" \t\r") for ln in t.split("\n")]
        while out and not out[-1]:
            out.pop()
        return out
    return lines(a) == lines(b)


def parse_sums(text: str, list_name: str = "") -> list[Entry]:
    """Every checksum in a list: GNU (`hash  name`, `hash *name`), BSD (`SHA256 (name) = hash`) and
    a bare hash. The algorithm comes from the BSD tag, else from the length; a list named b2sums is
    BLAKE2b (as long as SHA-512)."""
    blake = list_name.lower().startswith("b2")
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _BSD.match(line)
        if m:
            out.append(Entry(BSD_ALGOS[m.group(1).upper()], m.group(3).lower(), m.group(2).strip()))
            continue
        m = _GNU.match(line) or _BARE.match(line)
        if m and len(m.group(1)) in HEX_ALGOS:
            algo = "blake2b" if blake and len(m.group(1)) == 128 else HEX_ALGOS[len(m.group(1))]
            name = m.group(2) if m.re is _GNU else None
            if name and name.startswith("./"):
                name = name[2:]
            out.append(Entry(algo, m.group(1).lower(), name))
    return out


def for_file(entries: list[Entry], filename: str, list_name: str) -> list[Entry]:
    """The entries about this file: by its name (or path ending in it), or a bare checksum in a list
    named after it (foo.iso.sha256)."""
    named = [e for e in entries if e.name and (e.name == filename or e.name.endswith("/" + filename))]
    if named:
        return named
    if list_name.lower().startswith(filename.lower() + "."):
        return [e for e in entries if e.name is None]
    return []


def judge(entries: list[Entry], hashes: dict[str, str]) -> list[tuple[Entry, bool]]:
    """(entry, it matches the file) for a list's entries about this file's name. The list of a whole tree names a file
    once per folder (Mozilla's SHA512SUMS: firefox-N.tar.xz for every platform and language, 206 of them): those under
    other paths are other files. Where one of them matches, that one is this file's and the rest say nothing about
    it; where none does, one mismatch says so. Calling every other folder's entry a mismatch made a good Firefox
    download "Don't use this file" (seen with Firefox and Thunderbird 157.0.1)."""
    out = []
    for algo in dict.fromkeys(e.algo for e in entries):
        mine = [(e, hashes.get(e.algo) == e.digest) for e in entries if e.algo == algo]
        if len({e.name for e, _ in mine}) > 1:
            mine = [(e, ok) for e, ok in mine if ok] or mine[:1]
        out += mine
    return out


def hash_file(path: Path, algos: set[str]) -> dict[str, str]:
    """The file's hex digests, read once whatever the number of algorithms."""
    hs = {a: (hashlib.blake2b() if a == "blake2b" else hashlib.new(a)) for a in algos}
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            for h in hs.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hs.items()}


def pasted(text: str) -> tuple[str, list[str]] | None:
    """A checksum pasted from a web page: hex digits, maybe with spaces, a "sha256:" prefix, or a
    whole "hash  name" line. (digest, possible algorithms), or None if it isn't one."""
    t = text.strip()
    t = re.sub(r"^(sha(?:1|224|256|384|512)|md5|blake2b)\s*[:=]\s*", "", t, flags=re.I)
    m = _GNU.match(t) or _BSD.match(t)
    if m:
        t = m.group(3) if m.re is _BSD else m.group(1)
    t = re.sub(r"\s+", "", t).lower()
    if not re.fullmatch(r"[0-9a-f]+", t) or len(t) not in HEX_ALGOS:
        return None
    algos = [HEX_ALGOS[len(t)]] + (["blake2b"] if len(t) == 128 else [])
    return t, algos


# ------------------------------------------------------------------ signatures

@dataclass
class Signature:
    """One signature checked: over the file itself, or over a checksum list."""
    path: Path
    over: Path                           # what it signs (the same file, for a clearsigned list)
    kind: str                            # "openpgp", "ssh" or "minisign"
    status: str                          # good | expired | bad | no_key | revoked | error | no_tool | unsupported
    fingerprint: str = ""                # the signer's primary key (OpenPGP), "SHA256:..." (SSH) or key id (minisign)
    issuer: str = ""                     # who the signature says made it, when the key isn't available
    project: K.Project | None = None
    key_name: str = ""
    source: str = ""                     # where the key came from: "list", "keyring", "keyfile:NAME", "signature"
    expired: str = ""                    # status expired: "key" (it has expired) or "signature" (the signature has)
    signed_at: int | None = None
    detail: str = ""
    inside: str = ""                     # a signature inside the package: where ("_gpgorigin")
    install: str = ""                    # no_tool: the command that installs the program it needs, on this system
    signer: str = ""                     # OpenPGP: the key that signed, the primary or one of its subkeys
    hash_algo: int | None = None         # OpenPGP: the signature's hash algorithm (RFC 9580, 9.5)
    newer_subkey: bool = False           # a project's, by a subkey the app's copy of its key doesn't have

    @property
    def good(self) -> bool:
        return self.status == "good"

    @property
    def badge(self) -> tuple[str, str]:
        """(words, kind) for the page's badge: green only for a good signature by a key the app lists."""
        if self.status == "good" and not self.project:
            return ("good, but by the key inside it" if self.kind == "ssh" else "good, but by an unlisted key"), "unlisted"
        if self.status == "expired":
            return ("expired key" if self.expired == "key" else "expired signature"), "expired"
        return BADGE_WORDS.get(self.status, self.status.replace("_", " ")), self.status

    @property
    def words(self) -> str:
        if self.status == "good" and not self.project:
            return ("a good signature by the key inside it, which anyone can make" if self.kind == "ssh" else
                    "a good signature, by a key the app doesn't list")
        if self.status == "expired":
            return "made with a key that has expired" if self.expired == "key" else "a signature that has expired"
        return STATUS_WORDS.get(self.status, self.status)

    def to_dict(self, home: Path | None = None) -> dict:
        badge, badge_kind = self.badge
        return {"path": _show(self.path, home), "over": _show(self.over, home), "kind": self.kind,
                "status": self.status, "fingerprint": self.fingerprint,
                "fingerprint_grouped": K.group(self.fingerprint) if re.fullmatch(r"[0-9A-F]{40}", self.fingerprint) else self.fingerprint,
                "issuer": self.issuer, "project": self.project.name if self.project else None,
                "project_signs": self.project.signs if self.project else None, "key_name": self.key_name,
                "source": self.source, "expired": self.expired, "signed_at": self.signed_at, "detail": self.detail,
                "inside": self.inside, "install": self.install, "status_words": self.words,
                "badge": badge, "badge_kind": badge_kind}


# a signature's status in words, for the terminal's report, and on the page's badges
STATUS_WORDS = {"good": "good signature", "bad": "bad signature", "no_key": "the key that made it isn't available",
                "revoked": "made with a revoked key", "error": "couldn't be checked",
                "no_tool": "can't be checked: a program it needs isn't installed", "unsupported": "a kind this can't check"}
BADGE_WORDS = {"good": "good signature", "bad": "bad signature", "no_key": "no key", "revoked": "revoked key",
               "error": "couldn't be checked", "no_tool": "no program to check it", "unsupported": "unsupported"}
# OpenPGP hash algorithms too weak to rely on (RFC 9580, 9.5): someone able to make two files with the same hash
# could have one signed and hand out the other
WEAK_SIG_HASHES = {1: "MD5", 2: "SHA-1", 3: "RIPEMD-160"}
# the packages that hold the programs that check signatures, by distribution family (checks.guides.install)
TOOL_PACKAGES = {"gpgv": {"debian": "gpgv", "fedora": "gnupg2", "arch": "gnupg", "suse": "gpg2"},
                 "ssh-keygen": {"debian": "openssh-client", "fedora": "openssh-clients", "arch": "openssh",
                                "suse": "openssh-clients"},
                 "minisign": {"debian": "minisign", "fedora": "minisign", "arch": "minisign", "suse": "minisign"}}


def install_command(host: Host, program: str) -> str:
    """The command that installs `program` here, or "" where the distribution isn't one the app knows."""
    from types import SimpleNamespace

    from ..checks.guides import install
    if TYPE_CHECKING:
        from ..checks import Scan
    # install() reads only the scan's host
    return install(cast("Scan", SimpleNamespace(host=host)), **TOOL_PACKAGES[program]) or ""


def sig_kind(data: bytes) -> str | None:
    head = data[:64].lstrip()
    if head.startswith(b"-----BEGIN PGP SIGNATURE-----") or head.startswith(b"-----BEGIN PGP MESSAGE-----"):
        return "openpgp"
    if head.startswith(b"-----BEGIN SSH SIGNATURE-----"):
        return "ssh"
    if head.startswith(b"untrusted comment:"):
        return "minisign"
    if data[:1] and data[0] & 0x80:
        try:
            if any(tag == K.SIGNATURE for tag, _ in K.packets(data)):
                return "openpgp"
        except K.PacketError:
            return None
    return None


def parse_gpg_status(text: str) -> list[dict]:
    """gpgv's --status-fd lines, one dict per signature (NEWSIG starts each). VALIDSIG gives the key that signed
    first (`signer`, a subkey or the primary), its primary key last (`fpr`), and the hash algorithm. EXPSIG (the
    signature itself has expired) and EXPKEYSIG (the key has) are both `expired`, never good: the date in a
    signature is the signer's own claim, so whoever holds an expired key can sign today and date it back."""
    sigs: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        parts = line[9:].split()
        if not parts:
            continue
        word, args = parts[0], parts[1:]
        if word == "NEWSIG" or cur is None and word in ("GOODSIG", "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG",
                                                          "REVKEYSIG", "VALIDSIG"):
            cur = {"status": None}
            sigs.append(cur)
            if word == "NEWSIG":
                continue
        if word in ("GOODSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG"):
            cur["status"] = {"GOODSIG": "good", "EXPSIG": "expired", "EXPKEYSIG": "expired",
                             "REVKEYSIG": "revoked", "BADSIG": "bad"}[word]
            if word in ("EXPSIG", "EXPKEYSIG"):
                cur["expired"] = "signature" if word == "EXPSIG" else "key"
            cur["keyid"] = args[0] if args else ""
        elif word == "VALIDSIG" and args:
            cur["signer"] = args[0]
            cur["fpr"] = args[-1] if len(args) >= 10 else args[0]
            cur["time"] = int(args[2]) if len(args) > 2 and args[2].isdigit() else None
            cur["hash"] = int(args[7]) if len(args) > 7 and args[7].isdigit() else None
        elif word == "ERRSIG" and args:
            cur["status"] = cur.get("status") or ("no_key" if len(args) > 5 and args[5] == "9" else "error")
            cur["issuer"] = args[6] if len(args) > 6 and re.fullmatch(r"[0-9A-Fa-f]{40,64}", args[6]) else args[0]
        elif word == "NO_PUBKEY" and args:
            cur["status"] = "no_key"
            cur.setdefault("issuer", args[0])
    return sigs


class KeySet:
    """The keys a signature may be checked against: the listed projects', key files the user
    chose, and (read only) the user's own GnuPG keyring. Written to a private temporary folder
    for gpgv/sqv while it is in use."""

    def __init__(self, host: Host, projects: Sequence[K.Project], key_files: Sequence[Path] = (),
                 use_keyring: bool = True):
        self.host, self.projects = host, projects
        self.key_files: list[tuple[Path, list[K.KeyInfo]]] = []
        self.problems: list[str] = []
        for p in key_files:
            try:
                data = p.read_bytes()[:MAX_COMPANION]
                if data.lstrip().startswith(b"untrusted comment:") or data.lstrip().startswith(b"RW"):
                    self.key_files.append((p, []))           # a minisign public key
                    continue
                self.key_files.append((p, K.parse_keys(data)))
            except (OSError, K.PacketError) as e:
                self.problems.append(f"{p.name} isn't a public key the app can read ({e}).")
        self.user_keyrings: list[Path] = []
        if use_keyring:
            gh = Path(host.environ.get("GNUPGHOME") or host.home / ".gnupg")
            self.user_keyrings = [gh / n for n in ("pubring.kbx", "pubring.gpg") if (gh / n).is_file()]
        self._dir: tempfile.TemporaryDirectory | None = None
        self.revoked: set[str] = set()           # every key and subkey a copy anywhere says is revoked

    def __enter__(self) -> "KeySet":
        base = self.host.environ.get("XDG_RUNTIME_DIR")
        self._dir = tempfile.TemporaryDirectory(prefix="daprivacyscanner-verify-",
                                                dir=base if base and os.path.isdir(base) else None)
        d = Path(self._dir.name)
        (d / "home").mkdir(mode=0o700)
        listed = K.keyring(self.projects)
        (d / "listed.gpg").write_bytes(listed)
        sources = [listed]
        for i, (p, infos) in enumerate(self.key_files):
            if infos:
                binary = K.dearmor(p.read_bytes())
                (d / f"chosen-{i}.gpg").write_bytes(binary)
                sources.append(binary)
        for kr in self.user_keyrings:
            try:
                if kr.stat().st_size <= MAX_KEYRING:
                    sources.append(kr.read_bytes())
            except OSError:
                pass
        for data in sources:
            try:
                self.revoked |= K.keyring_revocations(data)
            except (K.PacketError, IndexError):
                pass
        return self

    def __exit__(self, *exc: object) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    @property
    def dir(self) -> Path:
        assert self._dir is not None, "use KeySet as a context manager"
        return Path(self._dir.name)

    def chosen_rings(self) -> list[Path]:
        return [self.dir / f"chosen-{i}.gpg" for i, (_, infos) in enumerate(self.key_files) if infos]

    def runs(self) -> list[tuple[str, list[Path]]]:
        """The keyrings each signature is checked against, apart: the app's listed keys alone, then the user's own
        (the key files they chose, their GnuPG keyring) alone. gpgv uses the first copy of a key it finds, so
        together the first copy hid what another held: the user's stale copy of a listed key, a revocation the
        app's copy carries; the app's copy, a revocation made since that only theirs carries; and a project's
        stolen signing subkey re-wrapped as a primary key of the thief's, in a key file or the keyring, was used
        ahead of the app's copy, which says it is revoked. The worst of the two counts (combined())."""
        user = [*self.chosen_rings(), *self.user_keyrings]
        return [("list", [self.dir / "listed.gpg"])] + ([("user", user)] if user else [])

    def keyrings(self) -> list[Path]:
        """Every keyring, the user's own first (as one gpgv call would read them)."""
        return [*self.chosen_rings(), *self.user_keyrings, self.dir / "listed.gpg"]

    def minisign_keys(self) -> list[Path]:
        return [p for p, infos in self.key_files if not infos]

    def is_revoked(self, *fprs: str) -> bool:
        """Whether any copy says this key (a fingerprint, or the key id a fingerprint ends in) is revoked."""
        for f in (x.upper() for x in fprs if x):
            if f in self.revoked or (len(f) == 16 and any(r.endswith(f) for r in self.revoked)):
                return True
        return False

    def classify(self, fpr: str, signer: str = "", run: str = "list") -> tuple[K.Project | None, str, str, bool]:
        """(project, key name, where the key came from, by a subkey the app's copy lacks) for a good signature:
        `fpr` its primary key (VALIDSIG's last field), `signer` the key that signed. A project's only when the
        primary is one it pins (keys.pinned): never by a subkey's fingerprint."""
        where = "list" if run == "list" else next(
            (f"keyfile:{p.name}" for p, infos in self.key_files for k in infos if k.fingerprint == fpr), "keyring")
        hit = K.pinned(self.projects, fpr, signer or fpr)
        if hit:
            return hit[0], hit[1], where, not hit[2]
        for _p, infos in self.key_files:
            for k in infos:
                if k.fingerprint == fpr:
                    return None, (k.uids[0] if k.uids else ""), where, False
        return None, "", where, False


def check_openpgp(host: Host, keyset: KeySet, sig: Path, data: Path | None, signed: str | None = None) -> Signature:
    """A detached signature over `data`, or a clearsigned file (`data` None). For a clearsigned one, `signed` is
    the text the app read as signed (clearsigned()): gpgv writes out the text it checked, and the signature
    counts only when the two agree."""
    over = data or sig
    if host.runner.which("gpgv"):
        runs: list[list[Signature]] = []
        failed: CommandResult | None = None
        for run, rings in keyset.runs():
            argv = ["gpgv", "--homedir", str(keyset.dir / "home"), "--status-fd", "1"]
            for kr in rings:
                argv += ["--keyring", str(kr)]
            out = None
            if data is None and signed is not None:
                fd, name = tempfile.mkstemp(dir=keyset.dir, suffix=".txt")
                os.close(fd)
                out = Path(name)
                argv += ["--output", str(out)]
            argv += [str(sig)] + ([str(data)] if data else [])
            try:
                r = host.run(*argv, timeout=600)
                checked = out.read_bytes().decode("utf-8", "replace") if out is not None else None
            finally:
                if out is not None:
                    out.unlink(missing_ok=True)
            found = parse_gpg_status(r.stdout)
            if not found:
                failed = failed or r
                continue
            if out is not None and signed is not None and not _same_text(checked or "", signed):
                return Signature(sig, over, "openpgp", "bad", detail="what its signature covers isn't what the app read "
                                 "as signed in it")
            runs.append([_from_status(keyset, sig, over, s, run) for s in found])
        if not runs:
            said = (failed.stderr or failed.stdout).strip()[:300] if failed is not None else ""
            return Signature(sig, over, "openpgp", "error", detail=said or "gpgv found no signature in it")
        # every signature in the file must be good; report the first that isn't, else the first by a listed key
        results = combined(runs)
        bad = next((s for s in results if s.status in ("bad", "revoked")), None)
        if bad:
            return bad
        good = [s for s in results if s.good]
        if good:
            return next((s for s in good if s.project), good[0])
        return next((s for s in results if s.status == "expired"), results[0])
    if host.runner.which("sqv") and data is not None:
        return _check_sqv(host, keyset, sig, data)
    issuers = _issuers(sig)
    return Signature(sig, over, "openpgp", "no_tool", issuer=issuers[0] if issuers else "",
                     detail="Checking OpenPGP signatures needs gpgv" + (" (or sqv)" if data is not None else "")
                     + ", which isn't installed.", install=install_command(host, "gpgv"))


def check_clearsigned(host: Host, keyset: KeySet, path: Path, c: Clearsigned) -> Signature:
    """A clearsigned file's signature: gpgv is given its one message alone (whatever is around it can't be
    taken for part of it), and the text it checked must be the text the app read (check_openpgp)."""
    fd, name = tempfile.mkstemp(dir=keyset.dir, suffix=".asc")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(c.message)
        s = check_openpgp(host, keyset, Path(name), None, signed=c.text)
    finally:
        os.unlink(name)
    s.path = s.over = path
    return s


def keyring_args(keyset: KeySet) -> list[Path]:
    return keyset.keyrings()


def _issuers(sig: Path) -> list[str]:
    try:
        return K.signature_issuers(sig.read_bytes()[:MAX_COMPANION])
    except (OSError, K.PacketError):
        return []


RANK = {"revoked": 0, "good": 1, "expired": 2, "bad": 3, "no_key": 4, "error": 5}


def combined(runs: list[list[Signature]]) -> list[Signature]:
    """Each signature as the worst the separate checks (KeySet.runs) found it, a revocation known anywhere first;
    otherwise good by any copy of the key beats expired (an expiry can be extended, and the newer copy says so),
    the app's listed copy first. A bad signature counts unless another copy of a key found it good: that is a
    different key with the same key id, and says nothing of the file."""
    out = []
    for i in range(max(len(r) for r in runs)):
        found = [r[i] for r in runs if i < len(r)]
        out.append(min(found, key=lambda s: RANK.get(s.status, 9)))     # min keeps the first of a rank: the list's
    return out


def _from_status(keyset: KeySet, sig: Path, over: Path, s: dict, run: str = "list") -> Signature:
    status = s.get("status") or "error"
    if status in ("good", "expired", "revoked") and s.get("fpr"):
        fpr = s["fpr"].upper()
        signer = (s.get("signer") or fpr).upper()
        project, name, source, newer = keyset.classify(fpr, signer, run)
        if keyset.is_revoked(fpr, signer):
            status = "revoked"              # gpgv says only "expired" of a key both expired and revoked
        if status == "revoked" and project is None:          # whose key it was, to say so
            hit = K.owner(keyset.projects, signer) or K.owner(keyset.projects, fpr)
            project, name = (hit[0], hit[1]) if hit else (None, name)
        return Signature(sig, over, "openpgp", status, fpr, project=project, key_name=name, source=source,
                         expired=s.get("expired", "") if status == "expired" else "", signed_at=s.get("time"),
                         signer=signer, hash_algo=s.get("hash"), newer_subkey=newer)
    if status == "revoked":
        fpr = (s.get("keyid") or "").upper()
        hit = K.owner(keyset.projects, fpr) if fpr else None
        return Signature(sig, over, "openpgp", "revoked", fpr, project=hit[0] if hit else None,
                         key_name=hit[1] if hit else "", source=run)
    if status == "bad":
        issuer = (s.get("keyid") or "").upper()
        hit = K.owner(keyset.projects, issuer) if issuer else None
        return Signature(sig, over, "openpgp", "bad", issuer=issuer, project=hit[0] if hit else None)
    issuer = (s.get("issuer") or "").upper()
    hit = K.owner(keyset.projects, issuer) if issuer else None
    return Signature(sig, over, "openpgp", "no_key" if status == "no_key" else "error", issuer=issuer,
                     project=hit[0] if hit else None)


def _check_sqv(host: Host, keyset: KeySet, sig: Path, data: Path) -> Signature:
    """sqv (Sequoia's verifier) reads OpenPGP keyrings, not keybox files: the listed keys and chosen
    key files only. It prints the fingerprint of each key that made a good signature; that may be a
    signing subkey, which is mapped to its primary key."""
    chosen = [(keyset.dir / f"chosen-{i}.gpg", infos) for i, (_, infos) in enumerate(keyset.key_files) if infos]
    listed = [k for p in keyset.projects if p.key for k in K.parse_keys(p.key)]
    runs = [("list", [keyset.dir / "listed.gpg"], listed)]
    if chosen:                                 # apart, as with gpgv (KeySet.runs)
        runs.append(("user", [p for p, _ in chosen], [k for _, infos in chosen for k in infos]))
    results = []
    for run, rings, infos in runs:
        argv = ["sqv"]
        for kr in rings:
            argv += ["--keyring", str(kr)]
        r = host.run(*argv, str(sig), str(data), timeout=600)
        fprs = [ln.strip().upper() for ln in r.stdout.splitlines() if re.fullmatch(r"[0-9A-Fa-f]{40,64}", ln.strip())]
        if r.ok and fprs:
            signer = fprs[0]
            try:                                   # when it was made: the packet naming the key sqv checked
                signed_at = K.signature_created(sig.read_bytes()[:MAX_COMPANION], issuer=signer)
            except (OSError, K.PacketError):
                signed_at = None
            # the primary of the key sqv used, in the keyrings of this run (a primary there is its own)
            fpr = next((k.fingerprint for k in infos if k.fingerprint == signer), None) or next(
                (k.fingerprint for k in infos if signer in k.subkeys), signer)
            project, name, source, newer = keyset.classify(fpr, signer, run)
            status = "revoked" if keyset.is_revoked(fpr, signer) else "good"
            if status == "revoked" and project is None:
                hit = K.owner(keyset.projects, signer)
                project, name = (hit[0], hit[1]) if hit else (None, name)
            results.append(Signature(sig, data, "openpgp", status, fpr, project=project, key_name=name, source=source,
                                     signed_at=signed_at, signer=signer, newer_subkey=newer))
            continue
        issuers = _issuers(sig)
        issuer = issuers[0] if issuers else ""
        hit = K.owner(keyset.projects, issuer) if issuer and run == "list" else None
        text = (r.stderr or r.stdout).lower()
        status = "bad" if hit or "bad signature" in text else "no_key"
        if hit and keyset.is_revoked(issuer):
            status = "revoked"                 # sqv refuses a revoked key's signature as it does a bad one
        results.append(Signature(sig, data, "openpgp", status, issuer=issuer, project=hit[0] if hit else None,
                                 detail=(r.stderr or r.stdout).strip()[:300]))
    if any(s.status == "revoked" for s in results):
        return next(s for s in results if s.status == "revoked")
    return next((s for s in results if s.good), results[0])


_SSH_GOOD = re.compile(r'Good "[^"]*" signature with (\S+) key (SHA256:\S+)')


def check_ssh(host: Host, sig: Path, data: Path) -> Signature:
    """An SSH signature (ssh-keygen -Y sign), namespace "file": checked for being good, and the
    key's fingerprint shown; no list of SSH keys exists, so it is never "verified"."""
    if not host.runner.which("ssh-keygen"):
        return Signature(sig, data, "ssh", "no_tool", detail="Checking SSH signatures needs ssh-keygen (OpenSSH), which "
                         "isn't installed.", install=install_command(host, "ssh-keygen"))
    r = host.run("ssh-keygen", "-Y", "check-novalidate", "-n", "file", "-s", str(sig), timeout=600, stdin=data)
    m = _SSH_GOOD.search(r.stdout + r.stderr)
    if r.ok and m:
        return Signature(sig, data, "ssh", "good", m.group(2), key_name=f"{m.group(1)} SSH key", source="signature")
    return Signature(sig, data, "ssh", "bad" if "incorrect signature" in (r.stdout + r.stderr).lower() else "error",
                     detail=(r.stderr or r.stdout).strip()[:300])


def check_minisign(host: Host, keyset: KeySet, sig: Path, data: Path) -> Signature:
    """A minisign signature: needs the project's minisign public key, chosen as a key file."""
    keyid = _minisign_keyid(sig)
    pubs = keyset.minisign_keys()
    if not pubs:
        missing = not host.runner.which("minisign")          # both needed: said together, not one after the other
        return Signature(sig, data, "minisign", "no_key", issuer=keyid,
                         detail="A minisign signature: choose the project's minisign public key (a .pub file, or "
                                "the key from its site saved to a file) as the key file."
                                + (" Checking it also needs minisign, which isn't installed." if missing else ""),
                         install=install_command(host, "minisign") if missing else "")
    if not host.runner.which("minisign"):
        return Signature(sig, data, "minisign", "no_tool", issuer=keyid,
                         detail="Checking it needs minisign, which isn't installed.", install=install_command(host, "minisign"))
    for pub in pubs:
        r = host.run("minisign", "-V", "-q", "-m", str(data), "-x", str(sig), "-p", str(pub), timeout=600)
        if r.ok:
            return Signature(sig, data, "minisign", "good", keyid, key_name=f"minisign key {keyid}",
                             source=f"keyfile:{pub.name}")
    return Signature(sig, data, "minisign", "no_key", issuer=keyid,
                     detail="None of the chosen minisign keys made this signature, or it doesn't match the file.")


def _minisign_keyid(sig: Path) -> str:
    import base64
    try:
        lines = sig.read_text(encoding="utf-8", errors="replace").splitlines()
        raw = base64.b64decode(lines[1].strip())
        return raw[2:10][::-1].hex().upper()
    except (OSError, IndexError, ValueError):
        return ""


def check_signature(host: Host, keyset: KeySet, sig: Path, data: Path | None) -> Signature:
    try:
        head = sig.read_bytes()[:MAX_COMPANION]
    except OSError as e:
        return Signature(sig, data or sig, "", "error", detail=str(e))
    kind = sig_kind(head)
    if kind == "openpgp":
        return check_openpgp(host, keyset, sig, data)
    if kind == "ssh" and data is not None:
        return check_ssh(host, sig, data)
    if kind == "minisign" and data is not None:
        return check_minisign(host, keyset, sig, data)
    return Signature(sig, data or sig, "", "unsupported", detail="Not a signature the app knows how to check.")


# ------------------------------------------------------------------ what is next to the file

@dataclass
class SumsList:
    path: Path
    entries: list[Entry]                 # about this file only
    clearsigned: bool = False
    signature: Signature | None = None   # over the list (detached, or clearsigned)
    matched: list[tuple[Entry, bool]] = field(default_factory=list)   # (entry, matches the file)
    message: Clearsigned | None = None   # a clearsigned list's message, which alone is given to gpgv
    unclear: str = ""                    # why what it signs can't be told (Unclear): taken as changed since signed


def _small_file(p: Path) -> bool:
    try:
        st = p.stat()
    except OSError:
        return False
    return p.is_file() and st.st_size <= MAX_COMPANION


def companions(path: Path) -> tuple[list[Path], list[Path]]:
    """(signatures of the file, checksum lists) in its folder."""
    sigs = [path.with_name(path.name + s) for s in SIG_SUFFIXES]
    sigs = [s for s in sigs if _small_file(s)]
    lists = []
    try:
        with os.scandir(path.parent) as it:
            for i, e in enumerate(it):
                if i >= MAX_DIR_ENTRIES:
                    break
                if e.name != path.name and SUMS_NAME.search(e.name) and not e.name.endswith(SIG_SUFFIXES):
                    p = Path(e.path)
                    if _small_file(p):
                        lists.append(p)
    except OSError:
        pass
    return sigs, sorted(lists)


def _clearsigned(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return CLEARSIGNED.encode() in f.read(4096)
    except OSError:
        return False


def _chosen_clearsigned(host: Host, keyset: KeySet, path: Path) -> Signature:
    """A clearsigned file chosen itself (a signed checksum list): it is the file they published only when it is
    its message alone, with nothing but white space around it. gpgv passes over text before and after the
    message, so a script or a list with lines of someone else's around a real signed part was "the file they
    published, unchanged"."""
    try:
        c = clearsigned(path.read_bytes()[:MAX_COMPANION])
    except Unclear as e:
        return Signature(path, path, "openpgp", "bad", detail=str(e))
    except OSError as e:
        return Signature(path, path, "openpgp", "error", detail=str(e))
    if c is None:
        return Signature(path, path, "openpgp", "error", detail="it starts a signed part that doesn't end as one does")
    if c.before.strip() or c.after.strip():
        return Signature(path, path, "openpgp", "bad", detail="text was added to it outside its signed part")
    return check_clearsigned(host, keyset, path, c)


def target_of(path: Path) -> Path:
    """When the user picked a signature rather than the file (foo.iso.sig), the file it signs."""
    for s in SIG_SUFFIXES:
        if path.name.endswith(s) and len(path.name) > len(s):
            other = path.with_name(path.name[:-len(s)])
            if other.is_file():
                return other
    return path


# ------------------------------------------------------------------ the verdict

@dataclass
class Verdict:
    path: Path
    size: int
    level: str                                   # LEVELS
    title: str
    text: str
    hashes: dict[str, str] = field(default_factory=dict)
    signatures: list[Signature] = field(default_factory=list)   # over the file itself
    lists: list[SumsList] = field(default_factory=list)
    pasted: dict | None = None                   # {"digest", "algo", "matches"}
    steps: list[str] = field(default_factory=list)              # what to do next
    notes: list[str] = field(default_factory=list)
    project_hint: K.Project | None = None
    signed_at: int | None = None                 # when the good signature it rests on was made (verified, signed)

    def to_dict(self, home: Path | None = None) -> dict:
        return {
            "path": _show(self.path, home), "name": self.path.name, "size": self.size, "level": self.level,
            "title": self.title, "text": self.text, "signed_at": self.signed_at, "hashes": self.hashes,
            "signatures": [s.to_dict(home) for s in self.signatures],
            "lists": [{"path": _show(l.path, home), "name": l.path.name, "clearsigned": l.clearsigned,
                       "signature": l.signature.to_dict(home) if l.signature else None,
                       "entries": [{"algo": e.algo, "algo_title": ALGO_TITLE[e.algo], "digest": e.digest,
                                    "name": e.name, "matches": ok} for e, ok in l.matched]} for l in self.lists],
            "pasted": self.pasted, "steps": self.steps, "notes": self.notes,
            "project_hint": {"name": self.project_hint.name, "how": self.project_hint.how,
                             "source": self.project_hint.source} if self.project_hint else None,
        }

    def text_report(self) -> str:
        lines = [f"{self.path.name}: {self.title}",
                 f"  {self.text}" + (f" {signed_on(self.signed_at)}" if self.signed_at else "")]
        for a in ("sha256", "sha512"):
            if a in self.hashes:
                lines.append(f"  {ALGO_TITLE[a]}: {self.hashes[a]}")
        for s in self.signatures + [l.signature for l in self.lists if l.signature]:
            who = s.project.name if s.project else (s.key_name or s.issuer or "an unknown key")
            lines.append(f"  Signature {s.path.name}: {s.words} ({who}"
                         + (f", {K.group(s.fingerprint)}" if re.fullmatch(r"[0-9A-F]{40}", s.fingerprint) else "") + ")")
        for l in self.lists:
            for e, ok in l.matched:
                lines.append(f"  {l.path.name}: {ALGO_TITLE[e.algo]} {'matches' if ok else 'DOES NOT MATCH'}")
        lines += [f"  - {s}" for s in self.steps]
        lines += [f"  Note: {n}" for n in self.notes]
        return "\n".join(lines)


def signed_on(t: int) -> str:
    """When a good signature was made, as a date in local time, for the terminal's report (the page words the same
    from the verdict's signed_at): an older release renamed as a newer one still matches its own signature, and only
    the date gives it away."""
    tm = time.localtime(t)
    return (f"Signed on {tm.tm_mday} {time.strftime('%B %Y', tm)}: releases are signed as they come out, so if the "
            "one you wanted came out well after that, this is an older one.")


def _show(p: Path, home: Path | None) -> str:
    if home is not None:
        try:
            return "~/" + str(p.relative_to(home))
        except ValueError:
            pass
    return str(p)


def _who(s: Signature) -> str:
    if s.project:
        return f"{s.project.name} ({s.project.signs})"
    return s.key_name or "a key the app doesn't list"


def verify(host: Host, path: Path, key_files: Sequence[Path] = (), expected: str = "", use_keyring: bool = True,
           projects: Sequence[K.Project] | None = None, given: bool = False) -> Verdict:
    """Everything that can be checked about the file now. Reads the file and the companions next to
    it; changes nothing. `given`: the checksum came with the command (--checksum), not pasted into the page."""
    path = target_of(Path(path))
    size = path.stat().st_size
    projects = K.load() if projects is None else projects
    sig_paths, list_paths = companions(path)

    lists: list[SumsList] = []
    for lp in list_paths:
        try:
            data = lp.read_bytes()[:MAX_COMPANION]
        except OSError:
            continue
        try:
            c, unclear = clearsigned(data), ""
        except Unclear as err:
            c, unclear = None, str(err)
        entries = for_file(parse_sums(c.text if c is not None else data.decode("utf-8", "replace"), lp.name),
                           path.name, lp.name)
        if entries:
            lists.append(SumsList(lp, entries, clearsigned=c is not None, message=c, unclear=unclear))

    want = {"sha256"} | {e.algo for l in lists for e in l.entries}
    paste = pasted(expected) if expected else None
    if paste:
        want |= set(paste[1])
    hashes = hash_file(path, want)

    with KeySet(host, projects, list(key_files), use_keyring) as ks:
        signatures = [check_signature(host, ks, s, path) for s in sig_paths]
        package_notes: list[str] = []
        try:
            inner = P.embedded(path, ks.dir)
        except (P.PackageError, OSError, struct.error, ValueError, TypeError, IndexError) as err:  # a package's to set
            why = err if isinstance(err, (P.PackageError, OSError)) else P.PackageError("it is damaged")
            inner = []
            package_notes.append(f"The package's own signature couldn't be read ({why}).")
        for e in inner:
            with P.streamed(e):
                s = check_openpgp(host, ks, e.sig, e.data, signed=e.signed)
            s.path, s.over, s.inside = path, path, e.label
            if e.problem and s.status in ("good", "no_key", "error"):
                s.status, s.detail = "bad", e.problem
            elif e.uncovered and s.good:
                s.status, s.detail = "error", e.uncovered
            elif e.note and s.good:
                package_notes.append(e.note)
            signatures.append(s)
        if size <= MAX_COMPANION and _clearsigned(path) and not P.kind(path):   # a signed list chosen itself
            signatures.append(_chosen_clearsigned(host, ks, path))
        for l in lists:
            l.matched = judge(l.entries, hashes)
            if l.unclear:
                l.signature = Signature(l.path, l.path, "openpgp", "bad", detail=l.unclear)
            elif l.clearsigned:
                assert l.message is not None, "a clearsigned list keeps its message"
                l.signature = check_clearsigned(host, ks, l.path, l.message)
            else:
                sig = next((l.path.with_name(l.path.name + s) for s in SIG_SUFFIXES
                            if _small_file(l.path.with_name(l.path.name + s))), None)
                if sig is not None:
                    l.signature = check_signature(host, ks, sig, l.path)
        key_problems = list(ks.problems)

    paste_info = None
    if expected and not paste:
        key_problems.append(f"What was {'given with --checksum' if given else 'pasted'} isn't a checksum (32 to 128 "
                            "hexadecimal digits).")
    elif paste:
        ok = any(hashes.get(a) == paste[0] for a in paste[1])
        algo = next((a for a in paste[1] if hashes.get(a) == paste[0]), paste[1][0])
        paste_info = {"digest": paste[0], "algo": algo, "algo_title": ALGO_TITLE[algo], "matches": ok,
                      "said": "given" if given else "you pasted"}

    v = decide(path, size, hashes, signatures, lists, paste_info, projects, given)
    v.notes = key_problems + v.notes + package_notes
    return v


def decide(path: Path, size: int, hashes: dict, signatures: list[Signature], lists: list[SumsList],
           paste_info: dict | None, projects: Sequence[K.Project], given: bool = False) -> Verdict:
    hint = K.for_file(projects, path.name)
    v = Verdict(path, size, "unchecked", "", "", hashes, signatures, lists, paste_info, project_hint=hint)
    all_sigs = signatures + [l.signature for l in lists if l.signature is not None]

    # bad: a signature that doesn't match, a revoked key, or a checksum that doesn't
    bad_sig = next((s for s in all_sigs if s.status == "bad"), None)
    revoked = next((s for s in all_sigs if s.status == "revoked"), None)
    mismatch = [(l, e) for l in lists for e, ok in l.matched if not ok]
    if bad_sig or revoked or mismatch or (paste_info and not paste_info["matches"]):
        v.level, v.title = "bad", "Don't use this file"
        if bad_sig and bad_sig.inside:
            v.text = (f"The signature inside it doesn't match it ({bad_sig.detail or 'a bad signature'}): the package "
                      "has been changed or damaged since it was signed.")
        elif bad_sig and bad_sig.over == path and bad_sig.path == path:     # clearsigned, chosen itself
            why = bad_sig.detail or "its signature doesn't match it"
            v.text = f"It has been changed since it was signed ({why}): it isn't the file as it was published."
        elif bad_sig and bad_sig.over == path:
            v.text = (f"Its signature ({bad_sig.path.name}) doesn't match it: the file has been changed or damaged "
                      "since it was signed, or the signature is for another file.")
        elif bad_sig and bad_sig.path == bad_sig.over:                       # a clearsigned list
            why = bad_sig.detail or "its signature doesn't match it"
            v.text = (f"The checksum list {bad_sig.over.name} has been changed since it was signed ({why}), so nothing "
                      "in it can be trusted.")
        elif bad_sig:
            v.text = (f"The checksum list {bad_sig.over.name} has been changed since it was signed "
                      f"({bad_sig.path.name} doesn't match it), so nothing in it can be trusted.")
        elif revoked:
            v.text = (f"It is signed with a key its owner has revoked ({_who(revoked)}): the key may have fallen into "
                      "the wrong hands. Get the file again from the project's site and look for news about the key.")
        elif mismatch:
            l, e = mismatch[0]
            v.text = (f"Its {ALGO_TITLE[e.algo]} checksum doesn't match the one in {l.path.name}: the download is "
                      "damaged or not the file that list describes.")
        else:
            assert paste_info is not None           # nothing else is left that is bad
            v.text = (f"Its {paste_info['algo_title']} checksum doesn't match the one {paste_info.get('said', 'you pasted')}: "
                      "the download is "
                      "damaged, or not the file that checksum is for.")
        v.steps = ["Delete it and download it again, from the project's own site.",
                   "If it fails again, don't use it: tell the project, and check where the download came from."]
        return v

    good_direct = [s for s in signatures if s.good]
    good_lists = [l.signature for l in lists if l.signature and l.signature.good and any(ok for _, ok in l.matched)]
    by_project = [s for s in good_direct if s.project] + [s for s in good_lists if s.project]
    other = [s for s in good_direct if not s.project] + [s for s in good_lists if not s.project]
    intact = any(ok for l in lists for _, ok in l.matched) or bool(paste_info and paste_info["matches"])
    # a file named as one project's is verified only by that project's key: otherwise the weakest of the listed
    # keys (some are one person's, some a build server's) would have made anything "Verified", Tails images too
    named = K.all_for_file(projects, path.name)
    trusted = [s for s in by_project if not named or s.project is not None and s.project.id in {p.id for p in named}]
    foreign = [s for s in by_project if all(s is not t for t in trusted)]

    if trusted:
        s = trusted[0]
        made = s.project
        assert made is not None                 # by_project's
        via = (" (the signature inside the package)" if s.inside else
               "" if s.over == path else f", through the checksum list {s.over.name},")
        v.level, v.title = "verified", f"Verified: made by {made.name}"
        v.text = (f"It is signed{via} by {made.name}'s release key ({s.key_name}), whose fingerprint the app "
                  f"checked on {made.name}'s own site on {made.checked.isoformat()}. "
                  "It is the file they published, unchanged.")
        v.signed_at = s.signed_at
        v.notes += _weak_notes(s, lists, path)
        if s.newer_subkey:
            mine = "your GnuPG keyring" if s.source == "keyring" else f"the key file {s.source.split(':', 1)[-1]}"
            v.notes.append(f"It was signed with a signing subkey the app's copy of {made.name}'s key doesn't have "
                           f"yet. Your copy of the key, in {mine}, shows {made.name}'s key vouching for it.")
        elif s.source == "keyring":
            v.notes.append("The key came from your own GnuPG keyring, and its fingerprint is the one the app lists.")
        return v
    pinned = K.published(projects, hashes.get("sha256"))
    if pinned:
        p, name, page = pinned
        host = re.sub(r"^https://([^/]+).*", r"\1", page)
        v.level, v.title = "verified", f"Verified: made by {p.name}"
        v.text = (f"It matches the SHA-256 checksum {p.name} publishes for {name} on its own site ({host}), which the "
                  f"app recorded on {p.checked.isoformat()}. It is the file they published, unchanged.")
        v.notes.append(f"{p.name} doesn't sign this file, so this rests on that page: a newer release has a new "
                       "checksum, which the app only knows once it is updated.")
        return v
    if foreign:
        s, theirs = foreign[0], named[0]
        made = s.project
        assert made is not None                 # by_project's
        via = "" if s.over == path else f", through the checksum list {s.over.name},"
        v.level, v.title = "other_project", f"Not verified: signed by {made.name}, but named as {theirs.name}'s file"
        v.text = (f"It has a good signature{via} by {made.name}'s release key ({s.key_name}), but its name is "
                  f"that of {theirs.signs}, and {made.name} doesn't sign those. A file renamed by mistake can look "
                  f"like this; so can a file made to pass for {theirs.name}'s by someone who got hold of "
                  f"{made.name}'s key. The app only calls a file verified when the key is that of the project "
                  "whose file it is.")
        v.signed_at = s.signed_at
        v.steps = [f"If it is {made.name}'s file, give it back its own name and verify it again.",
                   f"If it should be {theirs.name}'s, don't use it: download it again from {theirs.name}'s own site. "
                   f"{theirs.how}"]
        return v

    good_list_sigs = [l.signature for l in lists if l.signature and any(ok for _, ok in l.matched)]
    expired = [s for s in signatures + good_list_sigs if s.status == "expired"]
    if expired:
        s = next((x for x in expired if x.project), expired[0])
        via = "" if s.over == path else f", through the checksum list {s.over.name},"
        who = f"{s.project.name}'s key ({s.key_name})" if s.project else _who(s)
        key = s.expired == "key"
        v.level = "expired"
        v.title = "Not verified: signed with a key that has expired" if key else "Not verified: its signature has expired"
        v.text = (f"It has a signature{via} by {who} that matches it, but "
                  + ("that key has expired. " if key else "the signature itself has expired. ")
                  + "The date a signature carries is the signer's own claim, so anyone who got hold of an old key "
                  "could sign a file today and date it back to when the key was still valid: a signature by an "
                  "expired key can't show who made the file.")
        v.steps = ["If it is an old release, that may be all it is: compare its SHA-256 (below) with the one the "
                   "project's own site gives for that release.",
                   "For anything new, download it again with its current signature: a new release is signed with a "
                   "key that is valid now."]
        return v

    if other:
        s = other[0]
        via = "" if s.over == path else f" (through the checksum list {s.over.name})"
        fpr = K.group(s.fingerprint) if re.fullmatch(r'[0-9A-F]{40}', s.fingerprint) else s.fingerprint
        v.level, v.title = "signed", "Not verified: signed by an unknown key"
        if s.kind == "ssh":
            v.text = (f"It has an SSH signature{via} that matches it, by the key with fingerprint {fpr}. An SSH "
                      "signature carries the key that made it, and is checked against that same key, so anyone can "
                      "make one with a key of their own. It shows the file hasn't changed since whoever holds that key "
                      "signed it, not who that is. The app lists no SSH keys, so an SSH signature is never verified.")
        else:
            where = {"keyring": "a key in your GnuPG keyring"}.get(
                s.source, f"the key in {s.source.split(':', 1)[-1]}" if s.source.startswith("keyfile:") else "a key")
            v.text = (f"It has a good signature{via} by {where}" + (f" ({s.key_name})" if s.key_name else "")
                      + f", fingerprint {fpr}, which the app doesn't list. It shows the file hasn't changed since "
                      "whoever holds that key signed it, not who that is: anyone can make a key with any name on it. "
                      "Whether that key is the project's is for you to check.")
        v.signed_at = s.signed_at
        v.notes += _weak_notes(s, lists, path)
        v.steps = ["Compare that fingerprint, every character, with the one on the project's own website (over "
                   "https), ideally in more than one place (its site, its source repository, a release "
                   "announcement)."]
        return v

    unchecked = [s for s in all_sigs if s.status in ("no_key", "no_tool", "error", "unsupported")]
    if intact:
        v.level, v.title = "intact", "Not damaged, but not verified"
        what = (f"the {paste_info['algo_title']} checksum {paste_info.get('said', 'you pasted')}"
                if paste_info and paste_info["matches"] else
                f"the checksum in {next(l.path.name for l in lists if any(ok for _, ok in l.matched))}")
        v.text = (f"It matches {what}, so it wasn't damaged on the way. That doesn't show who made it: anyone "
                  "who could change the file could have changed a checksum published beside it.")
        if any(e.algo in WEAK for l in lists for e, ok in l.matched if ok) and not any(
                e.algo not in WEAK for l in lists for e, ok in l.matched if ok):
            v.notes.append("MD5 and SHA-1 checksums are weak: fine for spotting a damaged download, no protection "
                           "against a file made on purpose to match.")
    else:
        none = not all_sigs and not lists
        v.level = "unchecked"
        v.title = "Not verified: nothing to check it against" if none else "Not verified: its signature couldn't be checked"
        v.text = ("There is no signature or checksum list next to it" if none else
                  "Its signature couldn't be checked here") + ", so the app can't tell whether it is the file its " \
                 "makers published."
    for s in unchecked:
        v.steps.append(_unchecked_step(s, path))
    if hint and hint.unsigned and intact:
        v.notes.append(f"{hint.name} doesn't sign this file, so this is as far as a check can go.")
    elif not all_sigs:
        if hint:
            v.steps.append(f"{hint.name}: {hint.how}")
        else:
            v.steps.append("Look on the download page for a signature (.asc, .sig, .gpg or .sign) or a signed list "
                           "of checksums (SHA256SUMS with SHA256SUMS.gpg, for example), and save it next to the "
                           "file." + ("" if paste_info else " A checksum shown on the page can be "
                                      + ("given with --checksum" if given else "pasted here") + " to "
                                      "check the file isn't damaged."))
    return v


def _weak_notes(s: Signature, lists: list[SumsList], path: Path) -> list[str]:
    """Notes on a good signature that rests on a weak hash: the signature's own (VALIDSIG's hash algorithm), or a
    signed checksum list whose entries for the file are MD5 or SHA-1 only."""
    out = []
    if s.hash_algo in WEAK_SIG_HASHES:
        out.append(f"The signature is made over a {WEAK_SIG_HASHES[s.hash_algo]} hash, which is weak: someone able to "
                   "make two files with the same hash could have had one of them signed and passed off the other. It "
                   "is still the key's signature; a project that cares about it signs with SHA-256 or better.")
    if s.over != path:
        mine = [e for l in lists if l.signature is s for e, ok in l.matched if ok]
        if mine and all(e.algo in WEAK for e in mine):
            names = " and ".join(sorted({ALGO_TITLE[e.algo] for e in mine}))
            out.append(f"The signed list gives only {'an' if names.startswith('MD5') else 'a'} {names} checksum for this "
                       "file, which is weak: the signature shows the list is theirs, but a file made on purpose to "
                       "match that checksum would match it too.")
    return out


def _unchecked_step(s: Signature, path: Path) -> str:
    who = (f"{s.project.name}'s key" if s.project else
           f"key {K.group(s.issuer) if len(s.issuer) == 40 else s.issuer}" if s.issuer else "a key")
    if s.status == "no_tool":
        return f"{s.path.name}: {s.detail}" + (f" Install it with: {s.install}" if s.install else "")
    if s.status == "no_key":
        if s.kind == "minisign":
            return f"{s.path.name}: {s.detail}"
        return (f"{s.path.name} was made by {who}, which the app doesn't have, and isn't in your GnuPG keyring. "
                "Download the project's public key from its own website and choose it as the key file, then "
                "compare the fingerprint the app shows with the one on the site.")
    if s.status == "unsupported":
        return f"{s.path.name}: {s.detail}"
    return f"{s.path.name} couldn't be checked: {s.detail or 'gpgv reported an error'}"
