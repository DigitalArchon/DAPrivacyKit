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
from dataclasses import dataclass, field
from pathlib import Path

from ..host import Host
from . import keys as K
from . import packages as P

MAX_COMPANION = 2 * 1024 * 1024         # checksum lists and signatures are small; anything bigger isn't one
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

LEVELS = ("verified", "signed", "intact", "bad", "unchecked")


# ------------------------------------------------------------------ checksum lists

@dataclass(frozen=True)
class Entry:
    algo: str
    digest: str               # lower-case hex
    name: str | None          # the file it is for; None for a bare checksum (a <file>.sha256 holding only that)


def signed_text(text: str) -> str | None:
    """The text a clearsigned message signs (RFC 9580, 7.1): after the armour headers, up to the
    signature, with dash-escaping undone. None if it isn't clearsigned. Only this is trusted:
    anything before or after the block is ignored."""
    start = text.find(CLEARSIGNED)
    if start < 0:
        return None
    lines = text[start:].splitlines()[1:]
    try:
        body = lines.index("") + 1                     # "Hash: SHA256" and other headers end at an empty line
    except ValueError:
        return None
    out = []
    for ln in lines[body:]:
        if ln.startswith("-----BEGIN PGP SIGNATURE-----"):
            return "\n".join(out)
        out.append(ln[2:] if ln.startswith("- ") else ln)
    return None


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
    status: str                          # good | bad | no_key | revoked | error | no_tool | unsupported
    fingerprint: str = ""                # the signer's primary key (OpenPGP), "SHA256:..." (SSH) or key id (minisign)
    issuer: str = ""                     # who the signature says made it, when the key isn't available
    project: K.Project | None = None
    key_name: str = ""
    source: str = ""                     # where the key came from: "list", "keyring", "keyfile"
    expired: bool = False                # good, but the key has expired since
    signed_at: int | None = None
    detail: str = ""
    inside: str = ""                     # a signature inside the package: where ("_gpgorigin")
    install: str = ""                    # no_tool: the command that installs the program it needs, on this system

    @property
    def good(self) -> bool:
        return self.status == "good"

    def to_dict(self, home: Path | None = None) -> dict:
        return {"path": _show(self.path, home), "over": _show(self.over, home), "kind": self.kind,
                "status": self.status, "fingerprint": self.fingerprint,
                "fingerprint_grouped": K.group(self.fingerprint) if re.fullmatch(r"[0-9A-F]{40}", self.fingerprint) else self.fingerprint,
                "issuer": self.issuer, "project": self.project.name if self.project else None,
                "project_signs": self.project.signs if self.project else None, "key_name": self.key_name,
                "source": self.source, "expired": self.expired, "signed_at": self.signed_at, "detail": self.detail,
                "inside": self.inside, "install": self.install, "status_words": STATUS_WORDS.get(self.status, self.status)}


# a signature's status in words, for the terminal's report (the page has its own badges)
STATUS_WORDS = {"good": "good signature", "bad": "bad signature", "no_key": "the key that made it isn't available",
                "revoked": "made with a revoked key", "error": "couldn't be checked",
                "no_tool": "can't be checked: a program it needs isn't installed", "unsupported": "a kind this can't check"}
# the packages that hold the programs that check signatures, by distribution family (checks.guides.install)
TOOL_PACKAGES = {"gpgv": {"debian": "gpgv", "fedora": "gnupg2", "arch": "gnupg", "suse": "gpg2"},
                 "ssh-keygen": {"debian": "openssh-client", "fedora": "openssh-clients", "arch": "openssh",
                                "suse": "openssh-clients"},
                 "minisign": {"debian": "minisign", "fedora": "minisign", "arch": "minisign", "suse": "minisign"}}


def install_command(host: Host, program: str) -> str:
    """The command that installs `program` here, or "" where the distribution isn't one the app knows."""
    from types import SimpleNamespace

    from ..checks.guides import install
    return install(SimpleNamespace(host=host), **TOOL_PACKAGES[program]) or ""


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
    """gpgv's --status-fd lines, one dict per signature (NEWSIG starts each)."""
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
            cur["status"] = {"GOODSIG": "good", "EXPSIG": "good", "EXPKEYSIG": "expired",
                             "REVKEYSIG": "revoked", "BADSIG": "bad"}[word]
            cur["keyid"] = args[0] if args else ""
        elif word == "VALIDSIG" and args:
            cur["fpr"] = args[-1] if len(args) >= 10 else args[0]
            cur["time"] = int(args[2]) if len(args) > 2 and args[2].isdigit() else None
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

    def __init__(self, host: Host, projects, key_files: list[Path] = (), use_keyring: bool = True):
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

    def __enter__(self) -> "KeySet":
        base = self.host.environ.get("XDG_RUNTIME_DIR")
        self._dir = tempfile.TemporaryDirectory(prefix="daprivacyscanner-verify-",
                                                dir=base if base and os.path.isdir(base) else None)
        d = Path(self._dir.name)
        (d / "home").mkdir(mode=0o700)
        (d / "listed.gpg").write_bytes(K.keyring(self.projects))
        for i, (p, infos) in enumerate(self.key_files):
            if infos:
                (d / f"chosen-{i}.gpg").write_bytes(K.dearmor(p.read_bytes()))
        return self

    def __exit__(self, *exc) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    @property
    def dir(self) -> Path:
        assert self._dir is not None, "use KeySet as a context manager"
        return Path(self._dir.name)

    def keyrings(self) -> list[Path]:
        chosen = [self.dir / f"chosen-{i}.gpg" for i, (_, infos) in enumerate(self.key_files) if infos]
        return [self.dir / "listed.gpg", *chosen, *self.user_keyrings]

    def minisign_keys(self) -> list[Path]:
        return [p for p, infos in self.key_files if not infos]

    def classify(self, fpr: str) -> tuple[K.Project | None, str, str]:
        """(project, key name, where the key came from) for a signer's fingerprint."""
        hit = K.owner(self.projects, fpr)
        if hit:
            return hit[0], hit[1], "list"
        for p, infos in self.key_files:
            for k in infos:
                if fpr in k.all:
                    return None, (k.uids[0] if k.uids else ""), f"keyfile:{p.name}"
        return None, "", "keyring"


def check_openpgp(host: Host, keyset: KeySet, sig: Path, data: Path | None) -> Signature:
    """A detached signature over `data`, or a clearsigned file (`data` None)."""
    over = data or sig
    if host.runner.which("gpgv"):
        argv = ["gpgv", "--homedir", str(keyset.dir / "home"), "--status-fd", "1"]
        for kr in keyring_args(keyset):
            argv += ["--keyring", str(kr)]
        argv += [str(sig)] + ([str(data)] if data else [])
        r = host.run(*argv, timeout=600)
        found = parse_gpg_status(r.stdout)
        if not found:
            return Signature(sig, over, "openpgp", "error", detail=(r.stderr or r.stdout).strip()[:300]
                             or "gpgv found no signature in it")
        # every signature in the file must be good; report the first that isn't, else the first by a listed key
        results = [_from_status(keyset, sig, over, s) for s in found]
        bad = next((s for s in results if s.status in ("bad", "revoked")), None)
        if bad:
            return bad
        good = [s for s in results if s.good]
        if good:
            return next((s for s in good if s.project), good[0])
        return results[0]
    if host.runner.which("sqv") and data is not None:
        return _check_sqv(host, keyset, sig, data)
    issuers = _issuers(sig)
    return Signature(sig, over, "openpgp", "no_tool", issuer=issuers[0] if issuers else "",
                     detail="Checking OpenPGP signatures needs gpgv" + (" (or sqv)" if data is not None else "")
                     + ", which isn't installed.", install=install_command(host, "gpgv"))


def keyring_args(keyset: KeySet) -> list[Path]:
    return keyset.keyrings()


def _issuers(sig: Path) -> list[str]:
    try:
        return K.signature_issuers(sig.read_bytes()[:MAX_COMPANION])
    except (OSError, K.PacketError):
        return []


def _from_status(keyset: KeySet, sig: Path, over: Path, s: dict) -> Signature:
    status = s.get("status") or "error"
    if status in ("good", "expired") and s.get("fpr"):
        fpr = s["fpr"].upper()
        project, name, source = keyset.classify(fpr)
        return Signature(sig, over, "openpgp", "good", fpr, project=project, key_name=name, source=source,
                         expired=status == "expired", signed_at=s.get("time"))
    if status == "revoked":
        fpr = (s.get("fpr") or s.get("keyid") or "").upper()
        project, name, source = keyset.classify(fpr) if fpr else (None, "", "")
        return Signature(sig, over, "openpgp", "revoked", fpr, project=project, key_name=name, source=source)
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
    rings = [k for k in keyset.keyrings() if k.suffix == ".gpg" and k.parent == keyset.dir]
    argv = ["sqv"]
    for kr in rings:
        argv += ["--keyring", str(kr)]
    r = host.run(*argv, str(sig), str(data), timeout=600)
    fprs = [ln.strip().upper() for ln in r.stdout.splitlines() if re.fullmatch(r"[0-9A-Fa-f]{40,64}", ln.strip())]
    if r.ok and fprs:
        fpr = fprs[0]
        try:                                   # when it was made: the packet naming the key sqv checked
            signed_at = K.signature_created(sig.read_bytes()[:MAX_COMPANION], issuer=fpr)
        except (OSError, K.PacketError):
            signed_at = None
        project, name, source = keyset.classify(fpr)
        if project is not None:
            fpr = next((f for f, _ in project.keys if f == fpr), project.keys[0][0])
        else:
            for _, infos in keyset.key_files:
                fpr = next((k.fingerprint for k in infos if fpr in k.all), fpr)
        return Signature(sig, data, "openpgp", "good", fpr, project=project, key_name=name, source=source,
                         signed_at=signed_at)
    issuers = _issuers(sig)
    issuer = issuers[0] if issuers else ""
    hit = K.owner(keyset.projects, issuer) if issuer else None
    text = (r.stderr or r.stdout).lower()
    status = "bad" if hit or "bad signature" in text else "no_key"
    return Signature(sig, data, "openpgp", status, issuer=issuer, project=hit[0] if hit else None,
                     detail=(r.stderr or r.stdout).strip()[:300])


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
        return Signature(sig, data, "minisign", "no_key", issuer=keyid,
                         detail="A minisign signature: choose the project's minisign public key (a .pub file, or "
                                "the key from its site saved to a file) as the key file.")
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
        lines = sig.read_text(errors="replace").splitlines()
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

    def to_dict(self, home: Path | None = None) -> dict:
        return {
            "path": _show(self.path, home), "name": self.path.name, "size": self.size, "level": self.level,
            "title": self.title, "text": self.text, "hashes": self.hashes,
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
        lines = [f"{self.path.name}: {self.title}", f"  {self.text}"]
        for a in ("sha256", "sha512"):
            if a in self.hashes:
                lines.append(f"  {ALGO_TITLE[a]}: {self.hashes[a]}")
        for s in self.signatures + [l.signature for l in self.lists if l.signature]:
            who = s.project.name if s.project else (s.key_name or s.issuer or "an unknown key")
            lines.append(f"  Signature {s.path.name}: {STATUS_WORDS.get(s.status, s.status)} ({who}"
                         + (f", {K.group(s.fingerprint)}" if re.fullmatch(r"[0-9A-F]{40}", s.fingerprint) else "") + ")")
        for l in self.lists:
            for e, ok in l.matched:
                lines.append(f"  {l.path.name}: {ALGO_TITLE[e.algo]} {'matches' if ok else 'DOES NOT MATCH'}")
        lines += [f"  - {s}" for s in self.steps]
        lines += [f"  Note: {n}" for n in self.notes]
        return "\n".join(lines)


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


def verify(host: Host, path: Path, key_files: list[Path] = (), expected: str = "", use_keyring: bool = True,
           projects=None, given: bool = False) -> Verdict:
    """Everything that can be checked about the file now. Reads the file and the companions next to
    it; changes nothing. `given`: the checksum came with the command (--checksum), not pasted into the page."""
    path = target_of(Path(path))
    size = path.stat().st_size
    projects = K.load() if projects is None else projects
    sig_paths, list_paths = companions(path)

    lists: list[SumsList] = []
    for lp in list_paths:
        try:
            text = lp.read_text(errors="replace")
        except OSError:
            continue
        body = signed_text(text)
        entries = for_file(parse_sums(body if body is not None else text, lp.name), path.name, lp.name)
        if entries:
            lists.append(SumsList(lp, entries, clearsigned=body is not None))

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
        except (P.PackageError, OSError, struct.error) as e:
            inner = []
            package_notes.append(f"The package's own signature couldn't be read ({e}).")
        for e in inner:
            with P.streamed(e):
                s = check_openpgp(host, ks, e.sig, e.data)
            s.path, s.over, s.inside = path, path, e.label
            if e.problem and s.status in ("good", "no_key", "error"):
                s.status, s.detail = "bad", e.problem
            elif e.uncovered and s.good:
                s.status, s.detail = "error", e.uncovered
            elif e.note and s.good:
                package_notes.append(e.note)
            signatures.append(s)
        if size <= MAX_COMPANION and _clearsigned(path) and not P.kind(path):   # a signed list chosen itself
            signatures.append(check_openpgp(host, ks, path, None))
        for l in lists:
            l.matched = judge(l.entries, hashes)
            if l.clearsigned:
                l.signature = check_openpgp(host, ks, l.path, None)
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
           paste_info: dict | None, projects, given: bool = False) -> Verdict:
    hint = K.for_file(projects, path.name)
    v = Verdict(path, size, "unchecked", "", "", hashes, signatures, lists, paste_info, project_hint=hint)
    all_sigs = signatures + [l.signature for l in lists if l.signature]

    # bad: a signature that doesn't match, a revoked key, or a checksum that doesn't
    bad_sig = next((s for s in all_sigs if s.status == "bad"), None)
    revoked = next((s for s in all_sigs if s.status == "revoked"), None)
    mismatch = [(l, e) for l in lists for e, ok in l.matched if not ok]
    if bad_sig or revoked or mismatch or (paste_info and not paste_info["matches"]):
        v.level, v.title = "bad", "Don't use this file"
        if bad_sig and bad_sig.inside:
            v.text = (f"The signature inside it doesn't match it ({bad_sig.detail or 'a bad signature'}): the package "
                      "has been changed or damaged since it was signed.")
        elif bad_sig and bad_sig.over == path:
            v.text = (f"Its signature ({bad_sig.path.name}) doesn't match it: the file has been changed or damaged "
                      "since it was signed, or the signature is for another file.")
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
            v.text = (f"Its {paste_info['algo_title']} checksum doesn't match the one {paste_info.get('said', 'you pasted')}: "
                      "the download is "
                      "damaged, or not the file that checksum is for.")
        v.steps = ["Delete it and download it again, from the project's own site.",
                   "If it fails again, don't use it: tell the project, and check where the download came from."]
        return v

    good_direct = [s for s in signatures if s.good]
    good_lists = [l for l in lists if l.signature and l.signature.good and any(ok for _, ok in l.matched)]
    trusted = [s for s in good_direct if s.project] + [l.signature for l in good_lists if l.signature.project]
    other = [s for s in good_direct if not s.project] + [l.signature for l in good_lists if not l.signature.project]
    intact = any(ok for l in lists for _, ok in l.matched) or bool(paste_info and paste_info["matches"])

    if trusted:
        s = trusted[0]
        via = (" (the signature inside the package)" if s.inside else
               "" if s.over == path else f", through the checksum list {s.over.name},")
        v.level, v.title = "verified", f"Verified: made by {s.project.name}"
        v.text = (f"It is signed{via} by {s.project.name}'s release key ({s.key_name}), whose fingerprint the app "
                  f"checked on {s.project.name}'s own site on {s.project.checked.isoformat()}. "
                  "It is the file they published, unchanged.")
        if s.expired:
            v.notes.append("The key has expired since. A signature made while it was valid still counts; if the "
                           "file is new, ask why it was signed with an expired key.")
        if s.source == "keyring":
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
    if other:
        s = other[0]
        via = "" if s.over == path else f" (through the checksum list {s.over.name})"
        v.level, v.title = "signed", "Signed, by a key the app doesn't list"
        where = {"keyring": "a key in your GnuPG keyring", "signature": "the key named in the signature"}.get(
            s.source, f"the key in {s.source.split(':', 1)[-1]}" if s.source.startswith("keyfile:") else "a key")
        v.text = (f"It has a good signature{via} by {where}" + (f" ({s.key_name})" if s.key_name else "")
                  + f", fingerprint {K.group(s.fingerprint) if re.fullmatch(r'[0-9A-F]{40}', s.fingerprint) else s.fingerprint}. "
                  "That proves it is unchanged since that key signed it; whether that key is the project's is "
                  "for you to check.")
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
        v.level, v.title = "unchecked", "Nothing to check it against"
        v.text = ("There is no signature or checksum list next to it" if not all_sigs and not lists else
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
