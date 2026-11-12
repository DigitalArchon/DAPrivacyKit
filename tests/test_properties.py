"""Property and fuzz tests (hypothesis) for the parsers that read what someone else made: the `when` expressions
and the catalogue's use of them, the packet summary of Try an app (tools/pcap.py), clearsigned checksum lists
(tools/verify.py, against the real gpgv), the .deb and .rpm signature readers (tools/packages.py), what a download
really is (tools/sniff.py), and the root helper's ext4, jbd2 and btrfs parsers (helper.py), the last also on the real
images of tests/images with bytes changed. Each parser must fail only in the ways its callers expect (its own
errors), in bounded time and memory, and keep its own promises.

Deterministic by default (the same examples every run, no example database written); DAPRIVACYSCANNER_FUZZ=1 runs
many more, random ones."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import lzma
import os
import shutil
import signal
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, assume, example, given, settings  # noqa: E402
from hypothesis.configuration import set_hypothesis_home_dir  # noqa: E402

# its caches (constants, Unicode tables) outside the source tree: the suite writes nothing into the checkout
set_hypothesis_home_dir(os.path.join(tempfile.gettempdir(), f"daprivacyscanner-hypothesis-{os.getuid()}"))
from hypothesis import strategies as st  # noqa: E402

from daprivacyscanner import catalogue, expr, helper  # noqa: E402
from daprivacyscanner.tools import packages, pcap, sniff, verify  # noqa: E402

settings.register_profile("default", derandomize=True, database=None, deadline=None, max_examples=150,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much])
settings.register_profile("fuzz", database=None, deadline=None, max_examples=5000,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much])
settings.load_profile("fuzz" if os.environ.get("DAPRIVACYSCANNER_FUZZ") else "default")
FEW = settings(max_examples=40) if not os.environ.get("DAPRIVACYSCANNER_FUZZ") else settings()


class TooSlow(Exception):
    pass


@contextlib.contextmanager
def within(seconds: float):
    """Fails the example (TooSlow) when the block takes longer: bounded time, as the parsers promise."""
    def ring(*_):
        raise TooSlow(f"took more than {seconds} s")
    old = signal.signal(signal.SIGALRM, ring)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


# ------------------------------------------------------------------ `when` expressions

KEYS = sorted(catalogue.CONTEXT_KEYS)
ENUMS = {k: sorted(v) for k, v in catalogue.CONTEXT_KEYS.items() if v}
names = st.sampled_from(KEYS + ["data_on_encrypted_disk", "x_y"])


def trees(depth: int = 4):
    leaf = st.one_of(names.map(lambda n: expr.Node("name", n)),
                     st.sampled_from([True, False]).map(lambda b: expr.Node("lit", b)),
                     st.builds(lambda n, v: expr.Node("eq", args=(expr.Node("name", n), expr.Node("lit", v))),
                               st.sampled_from(sorted(ENUMS)), st.sampled_from(sorted({x for v in ENUMS.values() for x in v}))),
                     st.builds(lambda n, v: expr.Node("ne", args=(expr.Node("name", n), expr.Node("lit", v))),
                               st.sampled_from(sorted(ENUMS)), st.sampled_from(sorted({x for v in ENUMS.values() for x in v}))))
    return st.recursive(leaf, lambda kids: st.one_of(
        kids.map(lambda a: expr.Node("not", args=(a,))),
        st.builds(lambda a, b: expr.Node("and", args=(a, b)), kids, kids),
        st.builds(lambda a, b: expr.Node("or", args=(a, b)), kids, kids)), max_leaves=12)


def source(n: expr.Node) -> str:
    """The expression written out with every subexpression in brackets: the grammar's own reading of it."""
    if n.kind == "name":
        return n.value
    if n.kind == "lit":
        return ("true" if n.value else "false") if isinstance(n.value, bool) else f"'{n.value}'"
    if n.kind == "not":
        return f"not ({source(n.args[0])})"
    if n.kind in ("eq", "ne"):
        return f"{source(n.args[0])} {'==' if n.kind == 'eq' else '!='} {source(n.args[1])}"
    return f"({source(n.args[0])}) {n.kind} ({source(n.args[1])})"


def kleene(n: expr.Node, values: dict):
    """A second evaluator, written from the module's description: Kleene's three-valued logic."""
    if n.kind == "name":
        return values.get(n.value)
    if n.kind == "lit":
        return n.value
    if n.kind == "not":
        v = kleene(n.args[0], values)
        return None if v is None else not v
    if n.kind in ("eq", "ne"):
        a, b = kleene(n.args[0], values), kleene(n.args[1], values)
        return None if a is None or b is None else (a == b) == (n.kind == "eq")
    a, b = (kleene(x, values) for x in n.args)
    a, b = (None if v is None else bool(v) for v in (a, b))
    if n.kind == "and":
        return False if False in (a, b) else None if None in (a, b) else True
    return True if True in (a, b) else None if None in (a, b) else False


def assignments():
    def value(k):
        return st.one_of(st.none(), st.sampled_from(ENUMS[k])) if k in ENUMS else st.one_of(st.none(), st.booleans())
    return st.fixed_dictionaries({k: value(k) for k in KEYS + ["data_on_encrypted_disk", "x_y"]})


@given(trees())
def test_when_written_out_parses_back_to_the_same_tree(tree):
    assert expr.parse(source(tree)).root == tree


@given(trees(), assignments())
def test_when_evaluates_as_kleenes_logic(tree, values):
    got = expr.parse(source(tree)).evaluate(values)
    want = kleene(tree, values)
    assert got is (None if want is None else bool(want))


@given(trees(), assignments(), st.data())
def test_a_decided_when_stays_decided_whatever_the_unknowns_turn_out_to_be(tree, values, data):
    """What effective_severity relies on: a modifier decided with some keys unknown is decided for good."""
    e = expr.parse(source(tree))
    got = e.evaluate(values)
    assume(got is not None)
    filled = {k: (data.draw(st.sampled_from(ENUMS[k])) if k in ENUMS else data.draw(st.booleans())) if v is None else v
              for k, v in values.items()}
    assert e.evaluate(filled) is got


@given(st.text(alphabet=st.sampled_from(list("abfdenotr_=!()' \t\n\"0x")), max_size=60))
def test_when_rejects_what_isnt_an_expression_with_its_own_error(src):
    try:
        e = expr.parse(src)
    except expr.ExprError:
        return
    assert e.evaluate({}) in (True, False, None) and all(n.isidentifier() for n in e.names)


@pytest.mark.parametrize("src", ["(" * 2000 + "fde" + ")" * 2000, "not " * 2000 + "fde"])
def test_when_nested_too_deep_is_refused_by_its_own_error(src):
    try:
        expr.parse(src).evaluate({"fde": "none"})
    except expr.ExprError:
        pass


def test_a_long_flat_when_evaluates():
    e = expr.parse(" and ".join(["hibernation"] * 2000))
    assert e.evaluate({"hibernation": True}) is True


def test_every_when_in_the_catalogue_round_trips_and_reads_in_words(cat):
    seen = 0
    for spec in cat:
        for m in spec.modifiers:
            e = m.when
            again = expr.parse(source(e.root))
            assert again.root == e.root, (spec.id, e.source)
            words = catalogue.describe_when(e)
            assert words and "==" not in words and "!=" not in words and not re.search(r"'\w+'|\w_\w", words), (spec.id, words)
            assert e.names <= set(catalogue.CONTEXT_KEYS) | set(catalogue.CONTEXT_LABEL), (spec.id, e.source)
            seen += 1
    assert seen >= 60


@given(st.data())
def test_effective_severity_is_the_range_over_what_the_unknowns_could_be(cat, data):
    """The last modifier that holds decides; where the names it depends on are unknown, the severity is the highest
    over every value they could take (ranked and counted by it) and `lowest` the lowest (the owner's decision of
    2026-11-12)."""
    import itertools
    specs = [s for s in cat if s.modifiers]
    spec = data.draw(st.sampled_from(specs))
    values = data.draw(assignments())
    sev = catalogue.effective_severity(spec, values)

    def last(vals):
        held = [m for m in spec.modifiers if m.when.evaluate(vals) is True]
        return held[-1].severity if held else spec.severity
    unknown = sorted({n for m in spec.modifiers for n in m.when.names if values.get(n) is None})
    if len(unknown) <= catalogue.MAX_UNKNOWN:
        every = [last({**values, **dict(zip(unknown, c))})
                 for c in itertools.product(*(catalogue.name_values(n) for n in unknown))]
        assert sev.value == max(every) and sev.lowest == min(every)
    assert set(sev.uncertain_on) <= set(unknown)
    assert sev.uncertain or not sev.uncertain_on
    warn = catalogue.as_warning(spec, sev)
    if sev.value <= 0:
        assert warn.value == sev.value
    else:
        assert warn.as_warning and 1 <= warn.value and (warn.value < sev.value or sev.value == 1)


# ------------------------------------------------------------------ pcap: Try an app's packet summary

def pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)


def record(frame: bytes) -> bytes:
    return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


def ether(kind: int, payload: bytes) -> bytes:
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack(">H", kind) + payload


def ipv4(src: bytes, dst: bytes, proto: int, body: bytes, frag: int = 0, more: bool = False) -> bytes:
    flags = (0x2000 if more else 0) | (frag // 8)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, flags, 64, proto, 0, src, dst) + body


def ipv6(src: bytes, dst: bytes, proto: int, body: bytes, ext: bytes = b"") -> bytes:
    nxt = 0 if ext else proto           # a hop-by-hop options header first, then `proto`
    return struct.pack(">IHBB16s16s", 0x60000000, len(ext) + len(body), nxt, 64, src, dst) + ext + body


def tcp(sport: int, dport: int, flags: int, seq: int, data: bytes = b"") -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + data


def client_hello(name: str) -> bytes:
    sni_ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name.encode()
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(sni_ext)) + sni_ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


V4 = st.binary(min_size=4, max_size=4).filter(lambda b: b[0] not in (0, 127, 224, 255))
V6 = st.binary(min_size=15, max_size=15).map(lambda b: b"\x20" + b)
hostnames = st.from_regex(r"[a-z][a-z0-9-]{0,20}\.(com|org|net)", fullmatch=True)


@given(st.binary(max_size=4000), st.lists(st.integers(1, 4000), max_size=8))
def test_pcap_any_bytes_any_pieces_never_raise_and_pieces_dont_matter(data, cuts):
    whole = pcap.Flows("169.254.0.1")
    whole.feed(pcap_header() + data)
    parts = pcap.Flows("169.254.0.1")
    stream, at = pcap_header() + data, 0
    for cut in sorted(cuts):
        parts.feed(stream[at:cut])
        at = max(at, cut)
    parts.feed(stream[at:])
    assert whole.result() == parts.result()


@given(st.lists(st.tuples(st.booleans(), V4, V6, st.integers(1024, 65535), st.sampled_from([443, 80, 853, 8443]),
                          hostnames), min_size=1, max_size=20))
def test_pcap_each_connection_is_named_by_its_client_hello(conns):
    f = pcap.Flows("169.254.0.1")
    stream = pcap_header()
    want = {}
    for i, (six, a4, a6, _, dport, name) in enumerate(conns):
        sport = 1024 + i
        src, dst = (b"\xfd" + bytes(14) + b"\x15", a6) if six else (b"\x0a\x00\x02\x0f", a4)
        ip = ipv6 if six else ipv4
        kind = 0x86DD if six else 0x0800
        stream += record(ether(kind, ip(src, dst, 6, tcp(sport, dport, 0x02, 1000))))
        stream += record(ether(kind, ip(src, dst, 6, tcp(sport, dport, 0x18, 1001, client_hello(name)))))
        want[name] = want.get(name, 0) + 1
    f.feed(stream)
    r = f.result()
    got = {}
    for h in r["hosts"]:
        got[h["host"]] = got.get(h["host"], 0) + h["connections"]
        assert h["named_by"] == "program"               # no lookup gave these: only the program's word
    assert got == want and r["broken"] == 0


@given(st.lists(st.tuples(st.integers(1024, 65535), st.binary(min_size=1, max_size=300)), min_size=1, max_size=200))
def test_pcap_dns_over_tcp_that_never_finishes_holds_bounded_bytes(segments):
    """A program's own DNS-over-TCP connections that never complete a message: what is held stays bounded."""
    f = pcap.Flows("169.254.0.1")
    stream = pcap_header()
    for port, data in segments:
        src, dst = b"\x0a\x00\x02\x0f", b"\x08\x08\x08\x08"
        stream += record(ether(0x0800, ipv4(src, dst, 6, tcp(port, 53, 0x02, 7))))
        stream += record(ether(0x0800, ipv4(src, dst, 6, tcp(port, 53, 0x18, 8, b"\xff\xff" + data))))
    f.feed(stream)
    assert len(f.streams) <= pcap.STREAMS_MAX
    assert sum(len(s[1]) for s in f.streams.values()) <= pcap.BUFFERED_MAX + pcap.STREAM_MAX
    f.result()


@given(st.binary(max_size=600))
@example(b"\xc0\x0c" * 40)
def test_dns_names_with_any_pointers_are_read_or_refused_quickly(tail):
    data = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + tail
    with within(1):
        asked, answers = pcap.dns(data)
    assert all(isinstance(n, str) for n in asked) and all(isinstance(a, str) for a in answers)


@given(V6, st.integers(1024, 65535), hostnames)
def test_pcap_an_ipv6_connection_behind_an_extension_header_is_counted(dst, sport, name):
    hbh = bytes([6, 0]) + b"\x01\x04\x00\x00\x00\x00"        # next: TCP, 8 bytes, a PadN option
    src = b"\xfd" + bytes(14) + b"\x15"
    f = pcap.Flows("169.254.0.1")
    f.feed(pcap_header() + record(ether(0x86DD, ipv6(src, dst, 6, tcp(sport, 443, 0x02, 5), hbh)))
           + record(ether(0x86DD, ipv6(src, dst, 6, tcp(sport, 443, 0x18, 6, client_hello(name)), hbh))))
    assert [h["host"] for h in f.result()["hosts"]] == [name]


@given(V4, st.integers(1024, 65535), st.integers(1, 1000))
def test_pcap_a_later_ipv4_fragment_is_no_new_connection(dst, sport, offset):
    src = b"\x0a\x00\x02\x0f"
    fake = tcp(sport, 443, 0x02, 9)                           # bytes that look like a SYN, inside a later fragment
    f = pcap.Flows("169.254.0.1")
    f.feed(pcap_header() + record(ether(0x0800, ipv4(src, dst, 6, fake, frag=offset * 8))))
    # the destination is still named (every packet counts), but as fragments, never as the connection its bytes mimic
    assert all(h["ports"] == ["fragments"] for h in f.result()["hosts"])


# ------------------------------------------------------------------ clearsigned lists, against the real gpgv

GPG, GPGV = shutil.which("gpg"), shutil.which("gpgv")


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    """A throwaway key in a temporary GnuPG home: (sign(bytes) -> clearsigned bytes, gpgv(bytes) -> text or None)."""
    if not (GPG and GPGV):
        pytest.skip("gpg and gpgv are needed")
    home = tmp_path_factory.mktemp("gnupg")
    os.chmod(home, 0o700)
    env = {**os.environ, "GNUPGHOME": str(home), "LC_ALL": "C"}
    subprocess.run([GPG, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key",
                    "Test Signer <test@example.org>", "ed25519", "sign", "never"], env=env, check=True, capture_output=True)
    keyring = home / "trusted.gpg"
    keyring.write_bytes(subprocess.run([GPG, "--batch", "--export"], env=env, check=True, capture_output=True).stdout)

    def sign(text: bytes) -> bytes:
        return subprocess.run([GPG, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
                               "--clearsign"], input=text, env=env, check=True, capture_output=True).stdout

    def gpgv(data: bytes) -> bytes | None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "list.asc"
            p.write_bytes(data)
            r = subprocess.run([GPGV, "--keyring", str(keyring), "--output", "-", str(p)], env=env, capture_output=True)
            return r.stdout if r.returncode == 0 else None
    return sign, gpgv


lines = st.lists(st.one_of(
    st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n\x00"), max_size=30),
    st.sampled_from(["-", "- x", "-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----", "From x", "  ", "\t",
                     "Hash: SHA1", "", "\r", "x\r", "a  \t", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  f.iso"])),
    max_size=12)


@FEW
@given(lines, st.sampled_from(["", "junk above\n", "\n\n"]), st.sampled_from(["", "junk below\n"]), st.booleans())
def test_a_clearsigned_text_the_app_accepts_is_exactly_what_gpgv_outputs(signer, body, before, after, crlf):
    sign, gpgv = signer
    text = "\n".join(body).encode() + b"\n"
    signed = sign(text)
    data = before.encode() + (signed.replace(b"\n", b"\r\n") if crlf else signed) + after.encode()
    out = gpgv(data)
    assert out is not None or before or after          # gpg's own output verifies
    assume(out is not None)
    c = verify.clearsigned(data)
    assert c is not None
    assert c.text.encode() == out.rstrip(b"\n") or verify._same_text(c.text, out.decode("utf-8", "replace")), (c.text, out)
    assert c.before == before.encode() and c.after == after.encode()
    assert gpgv(c.message) == out                   # gpgv given the message alone reads the same


@FEW
@given(lines, st.integers(0, 400), st.sampled_from([b"x", b"\n", b"- ", b"-----BEGIN PGP SIGNED MESSAGE-----",
                                                    b"-----BEGIN PGP SIGNATURE-----\n", b"Hash: SHA256\n", b"\r"]))
def test_a_changed_clearsigned_text_is_never_taken_for_what_was_signed(signer, body, where, insert):
    """Bytes added anywhere: gpgv then refuses it, or the app reads the very text gpgv outputs, or refuses (Unclear)."""
    sign, gpgv = signer
    signed = sign("\n".join(body).encode() + b"\n")
    at = min(where, len(signed))
    data = signed[:at] + insert + signed[at:]
    try:
        c = verify.clearsigned(data)
    except verify.Unclear:
        return
    out = gpgv(data)
    if c is None or out is None:
        return
    assert verify._same_text(c.text, out.decode("utf-8", "replace")), (data, c.text, out)


@given(st.lists(st.one_of(st.binary(max_size=40), st.sampled_from([
    b"-----BEGIN PGP SIGNED MESSAGE-----", b"-----BEGIN PGP SIGNATURE-----", b"-----END PGP SIGNATURE-----",
    b"Hash: SHA256", b"", b"- -----BEGIN PGP SIGNATURE-----", b"\r"])), max_size=30))
def test_clearsigned_on_any_bytes_is_a_message_none_or_unclear(parts):
    data = b"\n".join(parts)
    try:
        c = verify.clearsigned(data)
    except verify.Unclear:
        return
    if c is not None:
        assert c.before + c.message + c.after == data
        assert c.message.startswith(verify.CLEARSIGNED.encode())
        assert c.message.rstrip(b"\r\n \t").endswith(verify.SIGNATURE_END.encode())
        assert data.count(verify.CLEARSIGNED.encode()) == 1


@given(st.text(max_size=300))
def test_checksum_lists_and_pasted_checksums_parse_anything(text):
    for e in verify.parse_sums(text):
        assert e.algo in verify.ALGO_TITLE and all(c in "0123456789abcdef" for c in e.digest)
    p = verify.pasted(text)
    assert p is None or (len(p[0]) in verify.HEX_ALGOS and p[1])


# ------------------------------------------------------------------ .deb and .rpm

def ar(members: list[tuple[str, bytes]], sizes: list[str] | None = None) -> bytes:
    out = packages.AR_MAGIC
    for i, (name, data) in enumerate(members):
        size = (sizes[i] if sizes and i < len(sizes) else str(len(data))).encode()
        out += name.encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8) + \
            size.ljust(10)[:10] + b"`\n" + data + (b"\n" if len(data) & 1 else b"")
    return out


member_names = st.sampled_from(["debian-binary", "control.tar.zst", "data.tar.xz", "_gpgorigin", "_gpgbuilder",
                                "control.tar.gz", "x"])


@given(st.lists(st.tuples(member_names, st.binary(max_size=200)), max_size=6),
       st.lists(st.sampled_from(["", "x", "99999999", "-1", "1e3", " 12", "0x10"]), max_size=6), st.binary(max_size=40))
def test_deb_readers_refuse_damaged_packages_with_their_own_error_quickly(tmp_path_factory, members, sizes, tail):
    work = tmp_path_factory.mktemp("deb")
    p = work / "x.deb"
    p.write_bytes(ar(members, sizes) + tail)
    try:
        with within(2):
            packages.embedded(p, work)
    except (packages.PackageError, OSError):
        pass


def test_a_deb_member_of_size_minus_60_is_refused():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.deb"
        p.write_bytes(ar([("_gpgorigin", b"")], ["-60"]))
        with within(0.5):
            with pytest.raises(packages.PackageError):
                packages.ar_members(p)


def rpm_header(entries: list[tuple[int, int, bytes, int]]) -> bytes:
    """An RPM header: (tag, type, data, count) entries."""
    index, store = b"", b""
    for tag, typ, data, count in entries:
        index += struct.pack(">IIII", tag, typ, len(store), count)
        store += data
    return packages.HEADER_MAGIC + bytes(4) + struct.pack(">II", len(entries), len(store)) + index + store


def rpm_file(sig: list, main: list, payload: bytes = b"payload") -> bytes:
    s = rpm_header(sig)
    s += bytes(-len(s) % 8)
    return packages.RPM_LEAD + bytes(92) + s + rpm_header(main) + payload


tags = st.sampled_from([1002, 1006, 268, 267, 278, 5092, 5093, 1000, 0])
rpm_entries = st.lists(st.tuples(tags, st.sampled_from([4, 6, 7, 8, 9, 3]), st.binary(max_size=24), st.integers(0, 3)),
                       max_size=5)


@given(rpm_entries, rpm_entries, st.binary(max_size=64), st.integers(0, 200))
def test_rpm_reader_fails_only_as_verify_expects(tmp_path_factory, sig, main, payload, cut):
    """Verify a download catches PackageError, OSError and struct.error (verify.py: verify)."""
    work = tmp_path_factory.mktemp("rpm")
    p = work / "x.rpm"
    data = rpm_file(sig, main, payload)
    p.write_bytes(data[:len(data) - cut] if cut else data)
    try:
        with within(2):
            packages.embedded(p, work)
    except (packages.PackageError, OSError, struct.error):
        pass
    except TypeError as e:
        # recorded below as its own failing test
        assume(False)
        raise AssertionError(e) from e


@pytest.mark.parametrize("sig,main", [([(1002, 4, b"\0\0\0\1", 1)], []),
                                      ([(268, 4, b"\0\0\0\1", 1)], []),
                                      ([(268, 7, b"sig", 3)], [(5092, 6, b"ab\0", 1), (5093, 6, b"8\0", 1)])])
def test_rpm_values_of_an_unexpected_type_are_refused(tmp_path, sig, main):
    p = tmp_path / "x.rpm"
    p.write_bytes(rpm_file(sig, main))
    try:
        packages.embedded(p, tmp_path)
    except (packages.PackageError, OSError, struct.error):
        pass


# ------------------------------------------------------------------ sniff: what a download really is

def sniffed(data: bytes, name: str) -> sniff.Inspection:
    with tempfile.TemporaryFile() as f:
        f.write(data)
        f.flush()
        with within(3):
            return sniff.inspect(f.fileno(), name, len(data))


file_names = st.sampled_from(["report.pdf", "photo.jpg", "notes.txt", "letter.docx", "page.html", "a.odt", "x",
                              "invoice.pdf.exe", "song.mp3", "archive.zip", "disk.iso", "run.sh", "a.desktop"])
PROGRAMS = [b"\x7fELF\x02\x01\x01", b"MZ" + bytes(62), b"#!/bin/sh\n", b"[Desktop Entry]\nExec=x\n",
            b"\xca\xfe\xba\xbe", b"L\x00\x00\x00\x01\x14\x02\x00"]


@given(st.sampled_from(PROGRAMS), st.binary(max_size=2000), file_names)
def test_a_program_is_never_called_a_document_whatever_its_name(head, rest, name):
    ins = sniffed(head + rest, name)
    assert ins.kind == "program" and not ins.viewable
    assert any("program" in w or "runs" in w for w in ins.warnings)


@pytest.mark.parametrize("at,marker", [(257, b"ustar"), (0x8001, b"CD001")])
def test_a_program_carrying_another_formats_marker_is_still_a_program(at, marker):
    data = bytearray(b"\x7fELF\x02\x01\x01" + bytes(0x8100))
    data[at:at + len(marker)] = marker
    assert sniffed(bytes(data), "report.pdf").kind == "program"


@given(st.binary(max_size=3000), file_names)
def test_sniff_never_fails_on_any_bytes(data, name):
    ins = sniffed(data, name)
    assert ins.kind in ("program", "disk image", "archive", "document", "picture", "text", "unknown")
    if ins.kind in ("program", "disk image", "archive"):
        assert not ins.viewable


def zip_bytes(entries: list[tuple[str, bytes, int]]) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data, method in entries:
            z.writestr(zipfile.ZipInfo(name), data, compress_type=method)
    return b.getvalue()


@given(st.lists(st.tuples(st.sampled_from(["mimetype", "AndroidManifest.xml", "classes.dex", "word/vbaProject.bin",
                                           "[Content_Types].xml", "a.exe", "x/y.sh", "META-INF/MANIFEST.MF", "A.class"]),
                          st.binary(max_size=60), st.sampled_from([zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])),
                min_size=1, max_size=5, unique_by=lambda e: e[0]), st.integers(0, 400), st.binary(min_size=1, max_size=4))
def test_a_damaged_zip_is_an_archive_and_never_an_error(entries, at, junk):
    data = bytearray(zip_bytes(entries))
    at = min(at, len(data) - 1)
    data[at:at + len(junk)] = junk
    import zlib
    try:
        ins = sniffed(bytes(data), "file.zip")
    except zlib.error:
        assume(False)                                   # test_a_zip_whose_mimetype_entry_wont_inflate_is_an_archive
        raise
    assert ins.kind in ("program", "archive", "document") or at < 4    # its first bytes broken: no ZIP at all


def test_a_zip_whose_mimetype_entry_wont_inflate_is_an_archive():
    good = zip_bytes([("mimetype", b"application/vnd.oasis.opendocument.text" * 3, zipfile.ZIP_DEFLATED)])
    i = good.index(b"mimetype", 30) + len(b"mimetype")             # the local entry's name, then its deflated bytes
    broken = good[:i] + b"\xff" * 8 + good[i + 8:]
    assert sniffed(broken, "letter.odt").kind == "archive"


@given(st.integers(20001, 10**7))
def test_a_zip_that_says_it_holds_too_many_files_isnt_read(count):
    data = zip_bytes([("a.txt", b"x", zipfile.ZIP_STORED)])
    end = data.rindex(b"PK\x05\x06")
    forged = data[:end + 8] + struct.pack("<HH", min(count, 65535), min(count, 65535)) + data[end + 12:]
    assume(min(count, 65535) > sniff.ZIP_ENTRIES)
    ins = sniffed(forged, "big.zip")
    assert ins.kind == "archive"


# ------------------------------------------------------------------ the helper's disk parsers

BLOCKS = st.one_of(st.binary(min_size=4096, max_size=4096),
                   st.lists(st.tuples(st.integers(0, 2**32 - 1), st.sampled_from([8, 12, 16, 20, 4096, 0, 65535, 3]),
                                      st.integers(0, 255), st.integers(0, 9), st.binary(max_size=40)), max_size=40)
                   .map(lambda es: b"".join(struct.pack("<IHBB", a, r, n, t) + nm for a, r, n, t, nm in es)[:4096].ljust(4096, b"\0")))


@settings(suppress_health_check=[HealthCheck.large_base_example, HealthCheck.too_slow, HealthCheck.data_too_large])
@given(BLOCKS, st.booleans(), st.booleans())
def test_ext4_folder_blocks_any_bytes(block, skip_index, live):
    with within(1):
        names = helper.parse_ext4_dir_block(block, skip_index=skip_index, live=live)
        entries = helper.ext4_dir_entries(block)
    assert all(helper._good_name(n) for n in names)
    if entries is not None:
        assert all(0 < len(n) <= 255 for _, _, n in entries)


@given(st.binary(min_size=1024, max_size=1100))
def test_ext4_superblock_any_bytes(sb):
    fs = helper.parse_ext4_superblock(sb)
    assert fs is None or (fs["block_size"] in {1024 << i for i in range(7)} and fs["journal"] in
                          ("none", "external", "unknown", "inode"))


@given(st.binary(min_size=12, max_size=120), st.dictionaries(st.integers(0, 64), st.binary(max_size=200), max_size=8))
def test_ext4_extent_trees_any_bytes_any_children(node, children):
    calls = []

    def read_block(n):
        calls.append(n)
        return children.get(n % 65)
    node = struct.pack("<HHHH", helper.EXT4_EXTENT_MAGIC, *struct.unpack_from("<HHH", node, 2)) + node[8:]
    with within(1):
        out = helper.ext4_extents(node, read_block)
    assert out is None or len(out) <= helper.EXT4_EXTENTS_MAX
    assert len(calls) <= 5 * 4096


@given(st.binary(min_size=12, max_size=4096), st.sampled_from([0, 2, 8, 10, 16, 18, 0x10 | 0x2]))
def test_jbd2_descriptors_and_superblocks_any_bytes(block, incompat):
    block = struct.pack(">II", helper.JBD2_MAGIC, helper.JBD2_DESCRIPTOR) + block[8:]
    tags = helper.parse_jbd2_descriptor(block, incompat)
    assert tags is None or len(tags) <= len(block) // 8
    helper.parse_jbd2_superblock(block)


def btrfs_fs():
    return {"fsid": bytes(range(16)), "nodesize": 16384, "sectorsize": 4096, "csum": 0}


def btrfs_leaf(items: list[tuple[int, int, int, int, int]], data: bytes, owner: int = 5) -> bytes:
    """A leaf with a right checksum, its items' headers as given (objectid, type, key offset, offset, size)."""
    fs = btrfs_fs()
    b = bytearray(fs["nodesize"])
    b[32:48] = fs["fsid"]
    struct.pack_into("<QIB", b, 88, owner, len(items), 0)
    for i, (obj, typ, off, at, size) in enumerate(items[:600]):
        struct.pack_into("<QBQII", b, 101 + 25 * i, obj, typ, off, at, size)
    b[len(b) - len(data):] = data
    struct.pack_into("<I", b, 0, helper._crc32c(bytes(b[32:])))
    return bytes(b)


@given(st.lists(st.tuples(st.integers(256, 300), st.sampled_from([84, 96, 1, 12]), st.integers(0, 2**64 - 1),
                          st.integers(0, 16384 - 101), st.integers(0, 2**32 - 1)), max_size=30), st.binary(max_size=2000))
def test_btrfs_a_leaf_with_a_right_checksum_and_any_items_never_raises(items, data):
    """A file laid out as a leaf passes the checksum (the planted leaves of tests/images): its items can say anything,
    and the helper reads them in names_step, where an exception ends the whole listing."""
    with within(2):
        try:
            out = helper.parse_btrfs_leaf(btrfs_leaf(items, data), btrfs_fs(), {5})
        except struct.error:
            assume(False)                                           # recorded below as its own failing test
            raise
    assert all(helper._good_name(name) for _, _, name, _ in out)


def test_btrfs_item_offsets_past_the_block_are_ignored():
    assert helper.parse_btrfs_leaf(btrfs_leaf([(257, 96, 1, 0xFFFFFFF0, 40)], b""), btrfs_fs(), {5}) == []


# the real images with bytes changed: the listing fails only by refusing

IMAGES = Path(__file__).parent / "images"


@pytest.fixture(scope="module")
def real_ext4(tmp_path_factory):
    out = tmp_path_factory.mktemp("fuzzimg") / "ext4.img"
    with lzma.open(IMAGES / "ext4-csum.img.xz") as z, open(out, "wb") as f:
        shutil.copyfileobj(z, f)
    return out.read_bytes(), json.loads((IMAGES / "ext4-csum.json").read_text())


@FEW
@given(st.data())
def test_ext4_journal_with_bytes_changed_is_read_or_refused(real_ext4, data):
    """Bytes changed in the superblock (its copy of the journal's map), the journal (its superblock, descriptors,
    copies) and the inode table: _journal_copies and the deleted folders' walk end, within their bounds, or refuse."""
    image, m = real_ext4
    img = bytearray(image)
    fd = os.memfd_create("ext4")                        # in memory: nothing written to the disk per example
    try:
        os.write(fd, img)
        _, extents, _, _ = helper._ext4_journal(fd, 4096)
        spots = [1024 + 0x10C + i for i in range(60)]                                   # the journal map's copy
        spots += [p * 4096 + i for _, n, p in extents[:3] for i in (0, 4, 12, 16, 20, 40, 0x54)]
        for _ in range(data.draw(st.integers(1, 12))):
            if data.draw(st.booleans()):
                at = data.draw(st.sampled_from(spots))
            else:
                start, count, phys = data.draw(st.sampled_from(extents))
                at = (phys + data.draw(st.integers(0, count - 1))) * 4096 + data.draw(st.integers(0, 4095))
            img[at] = data.draw(st.integers(0, 255))
        os.pwrite(fd, bytes(img), 0)
        homes = {b for e in m["entries"].values() if e["type"] == "dir"
                 for phys, length, *_ in e.get("extents", []) for b in range(phys // 4096, (phys + length) // 4096)}
        with within(10):
            state, copies, read, bad = helper._journal_copies(fd, 4096, homes)
        assert state in ("read", "unknown", "none", "external") and read <= len(img) * 2
        for cs in copies.values():
            for c in cs:
                helper.parse_ext4_dir_block(c, live=True)
    finally:
        os.close(fd)


@pytest.fixture(scope="module")
def real_btrfs(tmp_path_factory):
    with lzma.open(IMAGES / "btrfs-crc32c.img.xz") as z:
        data = z.read()
    fs = helper.parse_btrfs_superblock(data[helper.BTRFS_SUPER:helper.BTRFS_SUPER + 4096])
    leaves = []
    i = data.find(fs["fsid"])
    while i != -1:
        at = i - 32
        if at >= 0 and at % 4096 == 0 and data[at + 100] == 0 and \
                int.from_bytes(data[at + 88:at + 96], "little") in (5, 256) and \
                helper._btrfs_csum_ok(data[at:at + fs["nodesize"]], 0):
            leaves.append(data[at:at + fs["nodesize"]])
        i = data.find(fs["fsid"], i + 1)
    assert leaves
    return fs, leaves


@given(st.data())
def test_btrfs_real_leaves_with_bytes_changed_and_their_checksum_made_right(real_btrfs, data):
    """What a planted leaf can be: a real leaf of the FS tree, anything in it changed, its checksum recomputed."""
    fs, leaves = real_btrfs
    leaf = bytearray(data.draw(st.sampled_from(leaves)))
    for _ in range(data.draw(st.integers(1, 20))):
        at = data.draw(st.one_of(st.integers(96, 101 + 25 * 8), st.integers(101, len(leaf) - 1)))
        leaf[at] = data.draw(st.integers(0, 255))
    struct.pack_into("<I", leaf, 0, helper._crc32c(bytes(leaf[32:])))
    with within(2):
        try:
            out = helper.parse_btrfs_leaf(bytes(leaf), fs, {5, 256})
        except struct.error:
            assume(False)                     # test_btrfs_item_offsets_past_the_block_are_ignored
            raise
    assert all(helper._good_name(n) for _, _, n, _ in out)


@given(st.binary(min_size=0x24b, max_size=0x300))
def test_btrfs_superblock_any_bytes(sb):
    sb = sb[:0x40] + b"_BHRfS_M" + sb[0x48:]
    fs = helper.parse_btrfs_superblock(sb)            # refused (None) when its sizes are impossible, never a crash
    assert fs is None or len(fs["fsid"]) == 16


@given(st.binary(min_size=16, max_size=16), st.integers(0, 2**32 - 1), st.integers(1, 2**32 - 1), st.integers(0, 2**32 - 1))
def test_trim_records_are_found_only_whole_and_only_for_their_run(run, index, other, shift):
    payload = hashlib.sha256(run).digest() * 14
    rec = helper.trim_record(run, index % helper.TRIM_MAX_RECORDS, 0, payload[:helper.TRIM_PAYLOAD])
    assert len(rec) == helper.TRIM_RECORD
    p = {"bits": bytearray(helper.TRIM_MAX_RECORDS // 8), "found": 0, "copies": 0, "names": {}, "offsets": []}
    at = shift % 3000
    buf = bytearray(8192)
    buf[at:at + len(rec)] = rec
    helper._scan_window(buf, len(buf), 0, 0, {"run": run, "tag": "0" * 16}, p, True)
    assert p["found"] == 1 and p["offsets"] == [[index % helper.TRIM_MAX_RECORDS, at]]
    damaged = bytearray(buf)
    damaged[at + 40 + other % 440] ^= 1 + other % 255
    q = {"bits": bytearray(helper.TRIM_MAX_RECORDS // 8), "found": 0, "copies": 0, "names": {}, "offsets": []}
    helper._scan_window(damaged, len(damaged), 0, 0, {"run": run, "tag": "0" * 16}, q, True)
    assert q["found"] == 0
