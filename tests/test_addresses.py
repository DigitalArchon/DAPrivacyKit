"""online.check_url and is_local_host: an address is used only when it reads one way (the DA apps' one security
standard, 2026-11-14): no whitespace, backslash or control character, no user name or password, a port an address
can have, no "%" in its host but an IPv6 zone's, never 0.0.0.0; plain http only to the local networks the HTTPS rule
lists, a numeric address with a dot after it being a name, and a .local, .localhost or .onion name only as DNS writes
one."""

from __future__ import annotations

import json

import pytest

from daprivacyscanner import online


@pytest.mark.parametrize("url", [
    "http://192.168.1.1%.attacker.example/rootDesc.xml",       # cut at the "%", it read as the router
    "http://192.168.1.1%2e.attacker.example/",
    "http://nano%2dgpt.local/", "https://example%2ecom/",
    "https://example.com /x", "https://example.com\t/x", "https://exa\nmple.com/", "https://example.com\\@evil.example/",
    "https://example.com\x00/", "https://example.com\x7f/",
    "https://user:secret@example.com/", "https://user@example.com/",
    "https://example.com:99999/", "https://example.com:port/", "https://[fd00::5/", "https://example.com:0/",
    "https://0.0.0.0/", "http://0.0.0.0:8080/", "https://[::]/", "https://0/", "http://0.0.0.0./",
])
def test_an_address_that_reads_more_than_one_way_is_refused(url):
    assert online.address_problem(url)
    with pytest.raises(online.NotHttps, match="isn't used"):
        online.check_url(url)


def test_a_password_in_an_address_is_never_in_the_words():
    with pytest.raises(online.NotHttps) as e:
        online.check_url("https://someone:hunter2@example.com/")
    assert "hunter2" not in str(e.value) and "someone" not in str(e.value)


@pytest.mark.parametrize("host, local", [
    ("192.168.1.50", True), ("192.168.1.50.", False), ("127.0.0.1.", False), ("[fe80::1%25eth0]", True),
    ("fe80::1%eth0", True), ("::ffff:192.168.1.1", True), ("router.local", True), ("router.local.", True),
    ("app.localhost", True), ("localhost", True), ("abc.onion", True),
    ("evil%2eexample.local", False), ("a b.local", False), ("x/y.local", False), ("evil.example\n.local", False),
    ("192.168.1.1%.attacker.example", False),
    # Python's is_private takes these too; the HTTPS rule's list doesn't
    ("198.18.0.1", False), ("192.0.2.10", False), ("240.0.0.1", False), ("0.0.0.0", False), ("100.64.0.1", False),
    ("10.1.2.3", True), ("172.16.0.1", True), ("169.254.1.1", True), ("fd12::1", True), ("::1", True),
])
def test_what_counts_as_the_local_network(host, local):
    assert online.is_local_host(host) is local


def test_a_numeric_address_with_a_dot_after_it_gets_no_plain_http():
    online.check_url("http://192.168.1.50/desc.xml")
    with pytest.raises(online.NotHttps, match="only https"):
        online.check_url("http://192.168.1.50./desc.xml")


def test_online_json_refuses_an_address_that_reads_more_than_one_way(tmp_path):
    for value in ("https://user:pw@api.ipify.org", "https://api.ipify.org\\x", "https://0.0.0.0/",
                  "https://api ipify.org"):
        f = online.settings_path(tmp_path)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"ip_echo_v4": value}))
        with pytest.raises(online.SettingsError, match="isn't used") as e:
            online.load_settings(tmp_path)
        assert "pw@" not in str(e.value)


def test_online_json_s_host_names_have_no_newline_after_them(tmp_path):
    f = online.settings_path(tmp_path)
    f.parent.mkdir(parents=True)
    f.write_text(json.dumps({"dnssec_valid": "example.com\n"}))
    with pytest.raises(online.SettingsError, match="host name"):
        online.load_settings(tmp_path)
    f.write_text(json.dumps({"tls_sites": ["www.debian.org", "letsencrypt.org\n"]}))
    with pytest.raises(online.SettingsError, match="host names"):
        online.load_settings(tmp_path)
