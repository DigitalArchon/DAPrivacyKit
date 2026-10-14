"""auth.gpg_keys: weak and expired keys of the user's own (matched by keygrip), and a long
passphrase cache; the guide shortens the cache and reverts."""

from __future__ import annotations

from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.checks.auth import GPG_LIST
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan, sample
from test_guides import apply, build, options, revert

CHECK = "auth.gpg_keys"
GOOD, WEAK, DSA, EXPIRED = ("CF5D0B09EC4CE07452DEDA15044D292EE53C9425", "0B5DF1787D4E0DB5E633BDF618B3A48214A5A76D",
                            "489CAA657C10F436260C7ACE2C6923417AD257E8", "801A0A7F94B40A1B1A388DCC268A390E4C7AA4B3")
WEAK_SUB = "5555555555555555555555555555555555555555"


def gpg_host(tmp_path, grips, conf=None):
    files = {f".gnupg/private-keys-v1.d/{g}.key": "(protected-private-key ...)" for g in grips}
    if conf is not None:
        files[".gnupg/gpg-agent.conf"] = conf
    return make_host(tmp_path, home_files=files, commands={GPG_LIST: sample("gpg/list-keys.txt")})


def test_no_secret_keys(cat, tmp_path):
    assert detect(cat, CHECK, make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


def test_a_good_key_passes(cat, tmp_path):
    o = detect(cat, CHECK, make_scan(gpg_host(tmp_path, [GOOD])))
    assert o.status is Status.PASS and ev(o)["Your keys (with a secret part here)"] == 1
    assert ev(o)["max-cache-ttl"] == "2 h (GnuPG's default)" and "example" not in str(o.evidence)


def test_weak_keys_fail_and_someone_elses_keys_are_left_out(cat, tmp_path):
    o = detect(cat, CHECK, make_scan(gpg_host(tmp_path, [GOOD, WEAK_SUB, WEAK, DSA])))
    assert o.status is Status.FAIL and o.findings == {"gpg_weak_key": True}
    e = ev(o)
    assert e["Your keys (with a secret part here)"] == 3
    assert e["Weak: RSA 1024-bit"] == 1 and e["Weak: RSA 1024-bit subkey"] == 1 and e["Weak: DSA 2048-bit"] == 1
    assert effective_severity(cat[CHECK], o.findings).value == 5


def test_long_cache_warns_and_an_expired_key_is_only_noted(cat, tmp_path):
    o = detect(cat, CHECK, make_scan(gpg_host(tmp_path, [GOOD, EXPIRED], conf="default-cache-ttl 34560000\n"
                                                                            "max-cache-ttl 34560000\n")))
    assert o.status is Status.WARN and ev(o)["Expired"] == 1
    assert o.summary == "Your GnuPG passphrase is remembered for 400 days after each use, and up to 400 days in all."
    o = detect(cat, CHECK, make_scan(gpg_host(tmp_path / "b", [GOOD, EXPIRED])))
    assert o.status is Status.PASS and any(n.title == "1 expired key" for n in o.notes)


def test_the_new_key_command_makes_an_encryption_subkey_too(cat, tmp_path):
    """gpg(1): naming an algorithm makes the primary key only; future-default makes both."""
    g = build(cat, gpg_host(tmp_path, [WEAK]), CHECK)
    assert g.steps[0].commands[0].startswith("gpg --quick-gen-key 'YOUR NAME <YOU@EXAMPLE.COM>' future-default default 2y")


def test_max_cache_ttl_caps_the_cache_after_use(cat, tmp_path):
    o = detect(cat, CHECK, make_scan(gpg_host(tmp_path, [GOOD], conf="default-cache-ttl 86400\n")))
    assert o.status is Status.WARN and "for 2 h after each use, and up to 2 h in all" in o.summary
    o = detect(cat, CHECK, make_scan(gpg_host(tmp_path / "b", [GOOD], conf="default-cache-ttl 1800\nmax-cache-ttl 28800\n")))
    assert o.status is Status.PASS
    assert effective_severity(cat[CHECK], o.findings).value == 2


def test_guide_gives_commands_and_shortens_the_cache(cat, tmp_path):
    conf = "# mine\ndefault-cache-ttl 86400\nenable-ssh-support\nmax-cache-ttl 864000\n"
    host = gpg_host(tmp_path, [WEAK, EXPIRED], conf=conf)
    g = build(cat, host, CHECK)
    titles = [s.title for s in g.steps]
    assert titles == ["Replace weak keys", "Renew or remove expired keys", "Remember the passphrase for less time"]
    assert any("--gen-revoke B398F937B70E241AFFFB4F97655B5C6E1EA70091" in c for c in g.steps[0].commands)
    assert "gpg --quick-set-expire 068D2C86F3D5C64BEBF250EC05D316C6258BF24E 2y" in g.steps[1].commands
    plan = options(g)["GnuPG's defaults: 10 minutes after last use, at most 2 hours"]
    log, res = apply(host, plan)
    path = host.home / ".gnupg/gpg-agent.conf"
    assert path.read_text() == "# mine\ndefault-cache-ttl 600\nenable-ssh-support\nmax-cache-ttl 7200\n"
    revert(host, log, res)
    assert path.read_text() == conf
