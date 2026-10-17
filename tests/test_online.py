"""Online tests, against canned network answers (FakeNet): the test suite never touches the
network. Also: a normal scan never uses the network at all."""

import json

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper, network, online, probe
from daprivacyscanner.catalogue import CatalogueError, parse
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.online import online_checks, phone_home, ss_connections, upnp_controls
from daprivacyscanner.context import ContextValue
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.online import DEFAULTS, FakeNet, HttpResult, Resolved, TlsPeer
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.runner import Runner
from daprivacyscanner.server import create_app

from conftest import make_host, make_scan, sample

SETTINGS = json.loads(json.dumps(DEFAULTS))


def run(cat, check_id, host, fake, settings=None, **ctx):
    scan = make_scan(host, **ctx)
    scan.net, scan.online = fake, dict(settings or SETTINGS)
    return load_all()[check_id](cat[check_id]).detect(scan)


def val(o, label):
    return next(e.value for e in o.evidence if e.label == label)


# ------------------------------------------------------------------ the catalogue and the runner

def test_every_online_check_is_implemented_and_lists_its_contacts(cat):
    specs = {s.id for s in cat if s.scope.value == "online"}
    assert specs == set(online_checks()) and len(specs) == 11
    assert all(cat[i].contacts and cat[i].tier.value in ("advice", "guided") for i in specs)
    # the two guided ones borrow another check's guide, built from the kept result (never by running the test)
    assert {i for i in specs if cat[i].tier.value == "guided"} == {"net.dns_encryption_in_use", "net.ipv6_reachable"}


def test_contacts_belong_to_online_checks_only(cat):
    raw = {"schema_version": 1, "checks": [{**{k: v for k, v in cat["enc.trash"].to_dict().items()
                                               if k in ("id", "title", "category", "severity", "scope", "tier",
                                                        "detect", "fix", "remedy")}, "contacts": ["x"]}]}
    with pytest.raises(CatalogueError, match="contacts"):
        parse(raw)


def test_a_normal_scan_never_touches_the_network(cat, tmp_path, monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("a normal scan used the network")
    monkeypatch.setattr(online, "RealNet", no_network)
    c = TestClient(create_app("t", cat, make_host=lambda: make_host(tmp_path), make_net=no_network))
    r = c.post("/api/scan", headers={"X-Token": "t"}).json()
    assert set(r["online_pending"]) == set(online_checks())
    assert not set(r["online_pending"]) & set(r["results"])


def test_scan_online_needs_a_network(cat, tmp_path):
    with pytest.raises(ValueError):
        Runner(cat, make_host(tmp_path)).scan_online(["net.dnssec_validation"])


# ------------------------------------------------------------------ settings

def test_settings_validation(tmp_path):
    p = online.settings_path(tmp_path)
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"tls_sites": ["example.org"], "observe_seconds": 30}))
    s = online.load_settings(tmp_path)
    assert s["tls_sites"] == ["example.org"] and s["dns_leak"] == DEFAULTS["dns_leak"]
    for bad in ({"ip_echo_v4": "http://plain.example"}, {"tls_sites": ["a b"]}, {"surprise": 1},
                {"observe_seconds": 9999}, {"dnssec_failed": "x/../y"}):
        p.write_text(json.dumps(bad))
        with pytest.raises(online.SettingsError):
            online.load_settings(tmp_path)


# ------------------------------------------------------------------ DNS

def test_dnssec(cat, tmp_path):
    good = FakeNet(dns={"example.com": ["93.184.215.14"]})
    assert run(cat, "net.dnssec_validation", make_host(tmp_path), good).status is Status.PASS
    bad = FakeNet(dns={"example.com": ["93.184.215.14"], "dnssec-failed.org": ["96.99.227.255"]})
    assert run(cat, "net.dnssec_validation", make_host(tmp_path), bad).status is Status.FAIL
    assert run(cat, "net.dnssec_validation", make_host(tmp_path), FakeNet()).status is Status.UNKNOWN    # no DNS at all


def test_nxdomain_rewrite(cat, tmp_path):
    rewriting = FakeNet(resolver=lambda name: Resolved(("198.51.100.7",)))
    assert run(cat, "net.nxdomain_rewrite", make_host(tmp_path), rewriting).status is Status.FAIL
    honest = FakeNet()
    assert run(cat, "net.nxdomain_rewrite", make_host(tmp_path), honest).status is Status.PASS
    assert honest.contacted[0].startswith("dns:daps-") and honest.contacted[0].endswith(".com")


def test_nxdomain_answered_with_server_failure(cat, tmp_path):
    """Some resolvers answer a name that doesn't exist with SERVFAIL: no address, so no rewriting."""
    servfail = FakeNet(resolver=lambda name: Resolved(("93.184.215.14",)) if name == "example.com"
                       else Resolved((), "[Errno -3] Temporary failure in name resolution"))
    o = run(cat, "net.nxdomain_rewrite", make_host(tmp_path), servfail)
    assert o.status is Status.PASS and o.notes[0].title == "Your resolver reports a failure instead"
    assert sum(c.startswith("dns:daps-") for c in servfail.contacted) == 2      # asked again once
    no_dns = FakeNet(resolver=lambda name: Resolved((), "[Errno -3] Temporary failure in name resolution"))
    o = run(cat, "net.nxdomain_rewrite", make_host(tmp_path), no_dns)
    assert o.status is Status.UNKNOWN and o.summary.startswith("DNS isn't working")


def resolved_host(tmp_path, dot="+DNSOverTLS", query_line="yes"):
    return make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"}, commands={
        ("resolvectl", "status"): f"Global\n  Protocols: {dot} DNSSEC=no\n",
        ("resolvectl", "query", "--cache=no", "example.com"):
            f"example.com: 93.184.215.14\n\n-- Information acquired via protocol DNS in 20ms.\n"
            f"-- Data is authenticated: no; Data was acquired via local or encrypted transport: {query_line}\n"})


def test_dns_encryption_in_use(cat, tmp_path):
    assert run(cat, "net.dns_encryption_in_use", resolved_host(tmp_path / "a"), FakeNet()).status is Status.PASS
    assert run(cat, "net.dns_encryption_in_use", resolved_host(tmp_path / "b", query_line="no"), FakeNet()).status \
        is Status.FAIL
    o = run(cat, "net.dns_encryption_in_use", resolved_host(tmp_path / "c", "DNSOverTLS=opportunistic", "no"), FakeNet())
    assert o.status is Status.WARN
    assert run(cat, "net.dns_encryption_in_use", resolved_host(tmp_path / "d", "-DNSOverTLS"), FakeNet()).status \
        is Status.NOT_APPLICABLE


def leak_net(resolver_asn):
    report = [{"ip": "203.0.113.9", "country_name": "Netherlands", "asn": "AS9009 M247", "type": "ip"},
              {"ip": "198.51.100.53", "country_name": "Australia", "asn": resolver_asn, "type": "dns"},
              {"ip": "DNS may be leaking.", "type": "conclusion"}]
    # the service's ids were digits, now letters and digits (as seen 2026-10-03)
    return FakeNet(http={"https://bash.ws/id": HttpResult(200, b"z7hij91nf410831q\n"),
                         "https://bash.ws/dnsleak/test/z7hij91nf410831q?json": HttpResult(200, json.dumps(report).encode())})


def test_dns_leak_with_a_vpn(cat, tmp_path):
    fake = leak_net("AS1221 Telstra")
    o = run(cat, "net.dns_leak", make_host(tmp_path), fake, vpn_active=True)
    assert o.status is Status.FAIL and "Telstra" in val(o, "Resolver")
    assert sum(1 for c in fake.contacted if c.startswith("dns:") and c.endswith(".z7hij91nf410831q.bash.ws")) == 10
    assert run(cat, "net.dns_leak", make_host(tmp_path), leak_net("AS9009 M247"), vpn_active=True).status is Status.PASS


@pytest.mark.parametrize("resolver, note", [
    ("AS60068 Datacamp Limited", "Resolvers in another hosting network"),       # a VPN renting DNS elsewhere
    ("AS13335 CLOUDFLARENET", "A public DNS service answers inside the tunnel"),
    ("AS62371 PROTON Proton AG", None),                                        # the provider's own network
])
def test_dns_leak_doesnt_blame_a_vpns_own_choices(cat, tmp_path, resolver, note):
    o = run(cat, "net.dns_leak", make_host(tmp_path), leak_net(resolver), vpn_active=True)
    assert o.status is Status.PASS and [n.title for n in o.notes] == ([note] if note else [])


def test_dns_leak_names_the_leaking_network(cat, tmp_path):
    report = [{"ip": "203.0.113.9", "asn": "AS9009 M247", "type": "ip"},
              {"ip": "198.51.100.53", "asn": "AS9009 M247", "type": "dns"},
              {"ip": "198.51.100.54", "asn": "AS1221 Telstra", "type": "dns"}]
    fake = FakeNet(http={"https://bash.ws/id": HttpResult(200, b"z7hij91nf410831q\n"),
                         "https://bash.ws/dnsleak/test/z7hij91nf410831q?json": HttpResult(200, json.dumps(report).encode())})
    o = run(cat, "net.dns_leak", make_host(tmp_path), fake, vpn_active=True)
    assert o.status is Status.FAIL and o.summary.startswith("DNS is leaking: resolvers in AS1221 Telstra answered")


@pytest.mark.parametrize("answer, said", [(HttpResult(200, b"<html>moved</html>"), "doesn't recognise"),
                                          (HttpResult(503), "HTTP 503"), (HttpResult(None, error="timed out"), "timed out")])
def test_dns_leak_service_trouble_is_said_plainly(cat, tmp_path, answer, said):
    o = run(cat, "net.dns_leak", make_host(tmp_path), FakeNet(http={"https://bash.ws/id": answer}), vpn_active=True)
    assert o.status is Status.UNKNOWN and said in o.summary


def test_dns_leak_without_a_vpn_is_informational(cat, tmp_path):
    o = run(cat, "net.dns_leak", make_host(tmp_path), leak_net("AS1221 Telstra"), vpn_active=False)
    assert o.status is Status.PASS and o.notes[0].title == "Who sees your lookups"


# ------------------------------------------------------------------ VPN and IPv6

def vpn_host(tmp_path):
    return make_host(tmp_path, files={
        "/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n", "/sys/class/net/wlp2s0/uevent": "DEVTYPE=wlan\n",
        "/proc/net/route": "Iface\tDestination\nwg0\t00000000\t00000000\n",
        "/proc/net/ipv6_route": "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                                "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlp2s0\n",
        "/proc/net/if_inet6": "2a0212340000000012345678abcdef01 03 40 00 00   wlp2s0\n"})


def test_ipv6_goes_around_the_vpn(cat, tmp_path):
    fake = FakeNet(http={"https://api.ipify.org": HttpResult(200, b"203.0.113.9"),
                         "https://api6.ipify.org": HttpResult(200, b"2a02:1234::1234:5678:abcd:ef01")})
    o = run(cat, "net.vpn_ipv6_leak", vpn_host(tmp_path), fake, vpn_active=True)
    assert o.status is Status.FAIL and val(o, "Public IPv4 address websites see") == "203.0.113.9"
    no_v6 = FakeNet(http={"https://api.ipify.org": HttpResult(200, b"203.0.113.9")})
    assert run(cat, "net.vpn_ipv6_leak", vpn_host(tmp_path), no_v6, vpn_active=True).status is Status.PASS


# ------------------------------------------------------------------ where traffic exits

OWNERS = {"198.51.100.7": "ASN-TELSTRA Telstra Limited", "2001:db8:1::7": "ASN-TELSTRA Telstra Limited",
          "203.0.113.9": "M247 M247 Europe SRL", "185.159.157.1": "PROTON Proton AG"}
# as RIPEstat names them: the network's handle, then the company (AS9009 seen 2026-10-04)
ASNS = {"ASN-TELSTRA Telstra Limited": 1221, "M247 M247 Europe SRL": 9009, "PROTON Proton AG": 62371}


def ripe(url, body=None):
    from urllib.parse import parse_qs, urlsplit
    holder = OWNERS.get(parse_qs(urlsplit(url).query)["resource"][0])
    asns = [{"asn": ASNS[holder], "holder": holder}] if holder else []
    return HttpResult(200, json.dumps({"status": "ok", "data": {"asns": asns}}).encode())


def exit_net(v4=None, v6=None, v4b=None, **more):
    http = {"https://stat.ripe.net/data/prefix-overview/data.json*": ripe}
    for url, a in (("https://api.ipify.org", v4), ("https://ipv4.icanhazip.com", v4b or v4),
                   ("https://api6.ipify.org", v6), ("https://ipv6.icanhazip.com", v6)):
        if a:
            http[url] = HttpResult(200, f"{a}\n".encode())
    return FakeNet(http={**http, **more})


def lan_host(tmp_path, **files):
    return make_host(tmp_path, files={"/sys/class/net/wlp2s0/uevent": "DEVTYPE=wlan\n", **files},
                     commands={"ip -4 route get 1.1.1.1": "1.1.1.1 via 192.168.1.1 dev wlp2s0 src 192.168.1.20\n"})


def test_vpn_exit_without_a_vpn(cat, tmp_path):
    o = run(cat, "net.vpn_exit", lan_host(tmp_path), exit_net("198.51.100.7"))
    assert o.status is Status.PASS and o.summary == "No VPN: websites see your internet provider, Telstra Limited (AS1221)."
    assert not o.findings and o.notes[0].title == "Asked twice"


def test_vpn_exit_refuses_disagreeing_services(cat, tmp_path):
    o = run(cat, "net.vpn_exit", lan_host(tmp_path), exit_net("198.51.100.7", v4b="203.0.113.9"))
    assert o.status is Status.UNKNOWN and "gave different answers" in o.summary


def test_router_vpn_with_ipv6_going_around_it(cat, tmp_path):
    fake = exit_net("203.0.113.9", "2001:db8:1::7")
    o = run(cat, "net.vpn_exit", lan_host(tmp_path), fake, virtualization="none")
    assert o.status is Status.FAIL and not o.findings
    assert "upstream of this computer (likely the router), but IPv6 leaves through Telstra Limited (AS1221)" in o.summary
    assert any(n.title == "A hint, not proof" for n in o.notes)
    o = run(cat, "net.vpn_exit", lan_host(tmp_path), exit_net("203.0.113.9", "2001:db8:1::7"), virtualization="vm")
    assert "the computer this virtual machine runs on" in o.summary


def test_router_vpn_by_a_provider_with_its_own_network(cat, tmp_path):
    o = run(cat, "net.vpn_exit", lan_host(tmp_path), exit_net("185.159.157.1"))
    assert o.status is Status.PASS and o.summary.endswith("websites see Proton VPN.")
    assert {e.label: e.value for e in o.evidence}["IPv4 exit network"] == "Proton VPN"


def test_proton_exiting_through_a_rented_network(cat, tmp_path):
    """As seen with Proton VPN on the dev VM (2026-10-04): both exits in M247's network."""
    host = make_host(tmp_path, files={"/sys/class/net/proton0/uevent": "DEVTYPE=wireguard\n"},
                     commands={"ip -4 route get 1.1.1.1": sample("ip/mint-22-proton-route-get-4.txt")})
    OWNERS["2001:db8:26::12"] = "M247 M247 Europe SRL"
    o = run(cat, "net.vpn_exit", host, exit_net("203.0.113.9", "2001:db8:26::12"))
    assert o.status is Status.PASS and o.summary == ("Traffic leaves through Proton VPN: websites see an address in "
                                                     "M247 Europe SRL (AS9009), a hosting network Proton VPN rents "
                                                     "servers from.")
    assert {e.label: e.value for e in o.evidence}["IPv6 exit network"] == "M247 Europe SRL (AS9009)"


def mullvad_host(tmp_path, relay="se-got-wg-001"):
    return make_host(tmp_path, files={"/sys/class/net/wg0-mullvad/uevent": "DEVTYPE=wireguard\n"},
                     commands={"ip -4 route get 1.1.1.1": "1.1.1.1 dev wg0-mullvad table 1836018789 src 10.64.0.2\n",
                               "mullvad status": f"Connected\n    Relay:    {relay}\n"})


def mullvad_says(ip="203.0.113.9", own=True, hostname="se-got-wg-001"):
    return HttpResult(200, json.dumps({"ip": ip, "organization": "M247 Europe SRL", "mullvad_exit_ip": own,
                                       "mullvad_exit_ip_hostname": hostname}).encode())


def test_mullvad_is_asked_about_its_own_exit(cat, tmp_path):
    fake = exit_net("203.0.113.9", **{"https://ipv4.am.i.mullvad.net/json": mullvad_says()})
    o = run(cat, "net.vpn_exit", mullvad_host(tmp_path), fake)
    assert o.status is Status.PASS and o.summary == "Traffic leaves through Mullvad VPN, as its own check confirms."
    assert not any("icanhazip" in c or "ripe" in c for c in fake.contacted)     # Mullvad was asked instead
    moved = exit_net("203.0.113.9", **{"https://ipv4.am.i.mullvad.net/json": mullvad_says(hostname="se-sto-wg-005")})
    o = run(cat, "net.vpn_exit", mullvad_host(tmp_path), moved)
    assert o.status is Status.WARN and "reports server se-got-wg-001, but traffic leaves through se-sto-wg-005" in o.summary
    not_ours = exit_net("203.0.113.9", **{"https://ipv4.am.i.mullvad.net/json": mullvad_says(own=False)})
    assert run(cat, "net.vpn_exit", mullvad_host(tmp_path), not_ours).status is Status.FAIL


def test_a_vpn_exiting_through_an_ordinary_provider_is_suspect(cat, tmp_path):
    host = make_host(tmp_path, files={"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n"},
                     commands={"ip -4 route get 1.1.1.1": "1.1.1.1 dev wg0 table 51820 src 10.0.0.2\n"})
    o = run(cat, "net.vpn_exit", host, exit_net("198.51.100.7"))
    assert o.status is Status.WARN and o.notes[-1].title == "Is that your internet provider?"


def test_ipv6_reachable_with_and_without_a_probe(cat, tmp_path):
    listeners = network.parse_ss(sample("ss/mint-22.txt"))
    host = make_host(tmp_path, files={"/proc/net/if_inet6": "2a0212340000000012345678abcdef01 02 40 00 00   eth0\n"})
    o = run(cat, "net.ipv6_reachable", host, FakeNet(), listeners=listeners, ipv6_global=True)
    assert o.status is Status.WARN and "22/tcp" in val(o, "Listening on IPv6 and not blocked here")
    probe_url = "https://probe.example.net/check"
    fake = FakeNet(http={probe_url + "*": lambda url, body: HttpResult(200, json.dumps(
        {"open": "port=22" in url}).encode())})
    o = run(cat, "net.ipv6_reachable", host, fake, {**SETTINGS, "port_probe": probe_url}, listeners=listeners,
            ipv6_global=True)
    assert o.status is Status.FAIL and val(o, "Reachable from outside") == "22/tcp (SSH)"


# ------------------------------------------------------------------ UPnP

IGD_XML = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device>
<deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList>
</device></root>"""


def mapping(i, client, ext, port, desc):
    return (f"<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse><NewExternalPort>{ext}</NewExternalPort>"
            f"<NewProtocol>TCP</NewProtocol><NewInternalPort>{port}</NewInternalPort><NewInternalClient>{client}"
            f"</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{desc}"
            "</NewPortMappingDescription></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>").encode()


def test_upnp_controls():
    assert upnp_controls(IGD_XML, "http://192.168.1.1:5000/rootDesc.xml") == [
        ("urn:schemas-upnp-org:service:WANIPConnection:1", "http://192.168.1.1:5000/ctl/IPConn")]


def test_upnp_forwards_to_this_machine(cat, tmp_path):
    entries = [mapping(0, "192.168.1.20", 51413, 51413, "Transmission"), mapping(1, "192.168.1.30", 3074, 3074, "Xbox")]

    def soap(url, body):
        i = int(body.decode().split("<NewPortMappingIndex>")[1].split("<")[0])
        return HttpResult(200, entries[i]) if i < len(entries) else HttpResult(500, b"SpecifiedArrayIndexInvalid")
    fake = FakeNet(ssdp=[{"_from": "192.168.1.1", "location": "http://192.168.1.1:5000/rootDesc.xml"}],
                   http={"http://192.168.1.1:5000/rootDesc.xml": HttpResult(200, IGD_XML.encode()),
                         "http://192.168.1.1:5000/ctl/IPConn": soap})
    host = make_host(tmp_path, commands={("ip", "-4", "-o", "addr", "show"):
                                         "2: wlp2s0    inet 192.168.1.20/24 brd 192.168.1.255 scope global wlp2s0\n"})
    check = load_all()["net.upnp_forwards"](cat["net.upnp_forwards"])
    scan = make_scan(host)
    scan.net, scan.online = fake, SETTINGS
    o = check.detect(scan)
    assert o.status is Status.FAIL and val(o, "Port forwards on the router") == 2
    assert val(o, "Internet port 51413/TCP") == "→ this machine's port 51413 (Transmission)"
    assert "net.exposed_services" in check.notes_for_others


def test_upnp_ignores_devices_off_the_local_network(cat, tmp_path):
    fake = FakeNet(ssdp=[{"_from": "192.168.1.1", "location": "http://203.0.113.5/desc.xml"}])
    assert run(cat, "net.upnp_forwards", make_host(tmp_path), fake).summary.startswith("No router")
    assert "http://203.0.113.5/desc.xml" not in fake.contacted


# ------------------------------------------------------------------ TLS

def tls_net(issuer, verified=True, error=""):
    return FakeNet(tls={s: TlsPeer(s, verified, {"organizationName": issuer} if issuer else {}, error)
                        for s in DEFAULTS["tls_sites"]})


def test_tls_interception(cat, tmp_path):
    assert run(cat, "net.tls_interception", make_host(tmp_path), tls_net("Let's Encrypt")).status is Status.PASS
    o = run(cat, "net.tls_interception", make_host(tmp_path), tls_net("Kaspersky Anti-Virus Personal Root"))
    assert o.status is Status.FAIL and "Kaspersky" in o.summary
    assert run(cat, "net.tls_interception", make_host(tmp_path), tls_net("", False, "unable to get local issuer "
                                                                          "certificate")).status is Status.WARN
    assert run(cat, "net.tls_interception", make_host(tmp_path), tls_net("Acme Corp Proxy CA")).status is Status.WARN
    assert run(cat, "net.tls_interception", make_host(tmp_path), FakeNet()).summary.startswith("None of the test sites")


def test_locally_added_roots_are_noted(cat, tmp_path):
    host = make_host(tmp_path, files={"/usr/local/share/ca-certificates/corp/proxy-root.crt":
                                      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"})
    o = run(cat, "net.tls_interception", host, tls_net("DigiCert Inc"))
    assert o.status is Status.PASS and "corp/proxy-root.crt" in o.notes[0].text


# ------------------------------------------------------------------ updates with fresh lists

def test_updates_refreshed_apt_uses_its_own_lists(cat, tmp_path):
    calls = []

    def apt(argv):
        calls.append(argv)
        if argv[1] == "list":
            return CommandResult(argv, 0, "Listing...\nopenssl/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]\n")
        return CommandResult(argv, 0, "")
    host = make_host(tmp_path)
    host.runner.handlers["apt-get"] = apt
    host.runner.handlers["apt"] = apt
    o = run(cat, "kern.updates_refreshed", host, FakeNet())
    assert o.status is Status.FAIL and val(o, "Security updates") == 1
    lists = f"Dir::State::Lists={host.home}/.cache/daprivacyscanner/apt/lists"
    assert all(lists in a for a in calls)                     # never the system's lists


def test_updates_refreshed_pacman_needs_checkupdates(cat, tmp_path):
    host = make_host(tmp_path, installed=["pacman"])
    assert "checkupdates" in run(cat, "kern.updates_refreshed", host, FakeNet()).summary


# ------------------------------------------------------------------ observed traffic

def test_phone_home_matching():
    assert phone_home("incoming.telemetry.mozilla.org.")[1] == "tel.browser_telemetry"
    assert phone_home("collector.p3a.brave.com")[0] == "Brave P3A analytics"
    assert phone_home("www.mozilla.org") is None


def test_ss_connections_keep_public_peers_only():
    text = ('tcp ESTAB 0 0 192.168.1.20:40000 34.117.65.55:443 users:(("firefox",pid=9,fd=1))\n'
            'tcp ESTAB 0 0 127.0.0.1:40001 127.0.0.1:631 users:(("cups",pid=9,fd=1))\n'
            'tcp ESTAB 0 0 192.168.1.20:40002 192.168.1.1:80\n')
    assert ss_connections(text) == [{"process": "firefox", "peer": "34.117.65.55", "proto": "tcp"}]


def test_observed_traffic_with_root_names_programs_but_not_browsing(cat, tmp_path):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged(traffic={
        "queries": [{"name": "incoming.telemetry.mozilla.org", "addresses": ["34.120.208.123"]},
                    {"name": "my-bank.example", "addresses": ["198.51.100.10"]},
                    {"name": "metrics.someapp.example", "addresses": []}],
        "connections": [{"process": "firefox", "peer": "34.120.208.123", "proto": "tcp"},
                        {"process": "firefox", "peer": "198.51.100.10", "proto": "tcp"}]})
    o = run(cat, "tel.observed_traffic", host, FakeNet())
    assert o.status is Status.FAIL and val(o, "Firefox telemetry") == "incoming.telemetry.mozilla.org (by firefox)"
    assert "my-bank" not in json.dumps([e.to_dict() for e in o.evidence])
    assert val(o, "Looks like telemetry") == "metrics.someapp.example"


def test_observed_traffic_without_root(cat, tmp_path):
    host = make_host(tmp_path, commands={("ss", "-tunpH"): 'tcp ESTAB 0 0 10.0.0.2:5 52.1.2.3:443 users:(("code",pid=1,fd=2))\n'})
    fake = FakeNet(dns={"dc.services.visualstudio.com": ["52.1.2.3"]})
    o = run(cat, "tel.observed_traffic", host, fake, {**SETTINGS, "observe_seconds": 5})
    assert o.status is Status.WARN and o.partial and "by code" in val(o, "Microsoft / VS Code telemetry")
    assert o.summary.startswith("Possibly")                            # an address match is only a lead


def test_a_shared_address_is_not_pinned_on_one_service(cat, tmp_path):
    host = make_host(tmp_path, commands={("ss", "-tunpH"): 'tcp ESTAB 0 0 10.0.0.2:5 34.1.1.1:443 users:(("mintUpdate",pid=1,fd=2))\n'})
    fake = FakeNet(dns={"nmcheck.gnome.org": ["34.1.1.1"], "location.services.mozilla.com": ["34.1.1.1"]})
    o = run(cat, "tel.observed_traffic", host, fake, {**SETTINGS, "observe_seconds": 5})
    assert o.status is Status.WARN
    assert val(o, "One of: GNOME connectivity check / Location lookup (GeoClue)").endswith("(by mintUpdate)")


def test_helper_observes_traffic(monkeypatch):
    class Mon:
        def terminate(self):
            pass

        def communicate(self, timeout):
            line = {"question": [{"class": 1, "type": 1, "name": "nmcheck.gnome.org"}],
                    "answer": [{"rr": {"key": {"name": "nmcheck.gnome.org"}, "address": [151, 101, 1, 91]}}]}
            return json.dumps(line) + "\nnot json\n", ""
    monkeypatch.setattr(helper, "MONITOR", lambda: Mon())
    monkeypatch.setattr(helper, "SLEEP", lambda s: None)
    monkeypatch.setattr(helper, "RUN", lambda argv: (0, 'tcp ESTAB 0 0 10.0.0.2:5 151.101.1.91:443 users:(("NetworkManager",pid=1,fd=2))\n', ""))
    r = helper.observe_traffic({"seconds": 5})
    assert r["queries"] == [{"name": "nmcheck.gnome.org", "addresses": ["151.101.1.91"]}]
    assert r["connections"] == [{"process": "NetworkManager", "peer": "151.101.1.91", "proto": "tcp"}]
    with pytest.raises(helper.Refused):
        helper.observe_traffic({"seconds": 100000})


# ------------------------------------------------------------------ server

H = {"X-Token": "t"}


def run_job(c, body):
    """Start online tests and follow the job, as the page does, until it ends."""
    import time
    job = c.post("/api/online/run", headers=H, json=body).json()["job"]
    assert job["state"] in ("starting", "asking", "running")
    for _ in range(500):
        job = c.get("/api/online/status", headers=H).json()["job"]
        if job["state"] in ("done", "stopped", "failed"):
            return job
        time.sleep(0.01)
    raise AssertionError(f"the online job never ended: {job}")


def test_online_endpoints(cat, tmp_path):
    host = make_host(tmp_path)
    fake = FakeNet(dns={"example.com": ["93.184.215.14"]})
    with TestClient(create_app("t", cat, make_host=lambda: host, make_net=lambda: fake)) as c:
        plan = c.get("/api/online", headers=H).json()
        tests = {t["id"]: t for t in plan["tests"]}
        assert tests["net.tls_interception"]["hosts"] == DEFAULTS["tls_sites"] and tests["net.tls_interception"]["default"]
        assert not tests["net.dns_leak"]["default"] and tests["net.dns_leak"]["hosts"][0] == "bash.ws"
        assert fake.contacted == []                                      # listing contacts nobody
        assert c.post("/api/online/run", headers=H, json={"ids": ["net.dnssec_validation"]}).status_code == 400
        c.post("/api/scan", headers=H)
        job = run_job(c, {"ids": ["net.dnssec_validation", "enc.trash"]})
        assert job["state"] == "done" and (job["done"], job["total"]) == (1, 1)
        assert list(job["results"]) == ["net.dnssec_validation"]         # only online tests, only those asked
        rep = c.get("/api/state", headers=H).json()["report"]
        assert rep["results"]["net.dnssec_validation"]["status"] == "pass" and rep["online"]["ids"] == ["net.dnssec_validation"]
        rep = c.post("/api/scan", headers=H).json()                       # a new scan keeps them
        assert rep["results"]["net.dnssec_validation"]["status"] == "pass" and rep["online"]


def test_online_job_shows_progress_and_stops_between_tests(cat, tmp_path):
    import threading
    gate, started = threading.Event(), threading.Event()

    def slow(name):
        started.set()
        gate.wait(5)
        return Resolved((), "not found")
    fake = FakeNet(resolver=slow)
    with TestClient(create_app("t", cat, make_host=lambda: make_host(tmp_path), make_net=lambda: fake)) as c:
        c.post("/api/scan", headers=H)
        c.post("/api/online/run", headers=H, json={"ids": ["net.dnssec_validation", "net.nxdomain_rewrite"]})
        assert c.post("/api/online/run", headers=H, json={"ids": ["net.dnssec_validation"]}).status_code == 409
        assert started.wait(5)
        job = c.get("/api/online/status", headers=H).json()["job"]
        assert job["state"] == "running" and job["current"]["title"] == cat["net.dnssec_validation"].title
        assert (job["done"], job["total"]) == (0, 2)
        assert c.post("/api/scan", headers=H).status_code == 200          # the rest of the app stays usable
        assert c.post("/api/online/stop", headers=H).json()["job"]["stopping"]
        gate.set()
        import time
        for _ in range(500):
            job = c.get("/api/online/status", headers=H).json()["job"]
            if job["state"] not in ("starting", "asking", "running"):
                break
            time.sleep(0.01)
        assert job["state"] == "stopped" and list(job["results"]) == ["net.dnssec_validation"]


def test_a_crashing_online_job_says_so(cat, tmp_path):
    def broken():
        raise RuntimeError("no network stack")
    with TestClient(create_app("t", cat, make_host=lambda: make_host(tmp_path), make_net=broken)) as c:
        c.post("/api/scan", headers=H)
        job = run_job(c, {"ids": ["net.dnssec_validation"]})
        assert job["state"] == "failed" and "no network stack" in job["error"]


# ------------------------------------------------------------------ the probe

def test_probe():
    assert probe.parse_ports("22,8000-8002") == [22, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        probe.parse_ports("1-70000")

    def connect(addr, timeout):
        if addr[1] == 22:
            class C:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False
            return C()
        raise ConnectionRefusedError if addr[1] == 80 else TimeoutError
    assert probe.probe("2001:db8::5", [22, 80, 443], connect=connect) == [(22, "open"), (80, "closed"), (443, "no answer")]


def test_context_keys_for_online_checks(cat):
    from daprivacyscanner.catalogue import effective_severity
    assert effective_severity(cat["net.vpn_ipv6_leak"], {"vpn_active": False}).value == 0
    assert effective_severity(cat["net.dns_leak"], {"vpn_active": True}).value == 7
    assert effective_severity(cat["net.ipv6_reachable"], {"ipv6_global": False}).value == 0
    assert ContextValue  # noqa: B018 - imported for make_scan's keys


def test_every_online_test_says_why_it_is_or_isnt_ticked(cat):
    ids = {s.id for s in cat if s.scope.value == "online"}
    assert set(online.DEFAULTS_WHY) == ids and all(why for _, why in online.DEFAULTS_WHY.values())
    assert set(online.WITH_ADMIN) <= ids
    assert not online.DEFAULT_ON & {"net.dns_leak", "net.vpn_ipv6_leak", "kern.updates_refreshed"}


def test_online_dialog_data_and_administrator_access(cat, tmp_path):
    host = make_host(tmp_path, files={"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n"},
                     commands={"ip -4 route get 1.1.1.1": "1.1.1.1 dev wg0 table 51820 src 10.64.0.2 uid 1000\n"})
    asked = []
    with TestClient(create_app("t", cat, make_host=lambda: host, make_net=lambda: FakeNet(),
                               start_helper=lambda: asked.append(1) or FakePrivileged())) as c:
        plan = c.get("/api/online", headers=H).json()
        tests = {t["id"]: t for t in plan["tests"]}
        assert plan["vpn_active"] and "A VPN is connected now" in tests["net.dns_leak"]["default_why"]
        assert tests["tel.observed_traffic"]["with_admin"] and not tests["net.dnssec_validation"]["with_admin"]
        c.post("/api/scan", headers=H)
        job = run_job(c, {"ids": ["tel.observed_traffic"], "observe_seconds": 5})
        assert not asked and job["results"]["tel.observed_traffic"]["partial"]   # not asked for: not used
        job = run_job(c, {"ids": ["tel.observed_traffic"], "observe_seconds": 5, "admin": True})
        assert asked == [1] and job["privileged"] and not job["results"]["tel.observed_traffic"]["partial"]
        assert c.get("/api/online/status", headers=H).json()["admin_active"]


def test_a_proxy_in_the_environment_is_named_since_the_tests_bypass_it(cat, tmp_path):
    """RealNet goes out directly: someone who routes everything through a local proxy must be told before the
    hosts see their own address."""
    assert online.proxy_vars({"ALL_PROXY": "socks5://127.0.0.1:9050", "no_proxy": "x", "HTTP_PROXY": " "}) == ["ALL_PROXY"]
    assert online.proxy_vars({}) == []
    host = make_host(tmp_path, env={"https_proxy": "http://proxy.example:3128"})
    with TestClient(create_app("t", cat, make_host=lambda: host, make_net=lambda: FakeNet())) as c:
        assert c.get("/api/online", headers=H).json()["proxy_vars"] == ["https_proxy"]
    with TestClient(create_app("t", cat, make_host=lambda: make_host(tmp_path / "b"), make_net=lambda: FakeNet())) as c:
        assert c.get("/api/online", headers=H).json()["proxy_vars"] == []


def test_declining_administrator_access_still_runs_the_online_tests(cat, tmp_path):
    from daprivacyscanner.privileged import HelperDeclined

    def decline():
        raise HelperDeclined("declined")
    with TestClient(create_app("t", cat, make_host=lambda: make_host(tmp_path), make_net=lambda: FakeNet(),
                               start_helper=decline)) as c:
        c.post("/api/scan", headers=H)
        job = run_job(c, {"ids": ["tel.observed_traffic"], "observe_seconds": 5, "admin": True})
        assert job["admin_message"] and job["results"]["tel.observed_traffic"]["partial"]


def test_contact_groups():
    s = dict(DEFAULTS)
    assert online.contact_group("tel.observed_traffic", s) == "nobody"
    assert online.contact_group("net.ipv6_reachable", s) == "nobody"
    assert online.contact_group("net.ipv6_reachable", {**s, "port_probe": "https://probe.example.net"}) == "own"
    assert online.contact_group("net.tls_interception", s) == "own"
    assert {online.contact_group(i, s) for i in ("net.dns_leak", "net.vpn_ipv6_leak", "kern.updates_refreshed")} == {"third"}


def test_stop_now_discards_the_running_test_and_keeps_earlier_results(cat, tmp_path):
    import threading
    import time
    gate, blocked = threading.Event(), threading.Event()

    def resolver(name):
        if name.startswith("daps-"):                       # the second test: hangs until let go
            blocked.set()
            gate.wait(5)
        return Resolved(("93.184.215.14",)) if name == "example.com" else Resolved((), "not found")
    with TestClient(create_app("t", cat, make_host=lambda: make_host(tmp_path),
                               make_net=lambda: FakeNet(resolver=resolver))) as c:
        c.post("/api/scan", headers=H)
        c.post("/api/online/run", headers=H, json={"ids": ["net.dnssec_validation", "net.nxdomain_rewrite"]})
        assert blocked.wait(5)
        job = c.post("/api/online/stop", headers=H, json={"now": True}).json()["job"]
        assert job["state"] == "stopped" and job["cancelled"] == cat["net.nxdomain_rewrite"].title
        assert list(job["results"]) == ["net.dnssec_validation"] and job["winding_down"]
        assert c.post("/api/online/run", headers=H, json={"ids": ["net.dnssec_validation"]}).status_code == 409
        gate.set()
        for _ in range(500):
            job = c.get("/api/online/status", headers=H).json()["job"]
            if not job["winding_down"]:
                break
            time.sleep(0.01)
        assert job["state"] == "stopped" and list(job["results"]) == ["net.dnssec_validation"]   # result dropped
        rep = c.get("/api/state", headers=H).json()["report"]
        assert "net.nxdomain_rewrite" not in rep["results"] and rep["online"]["ids"] == ["net.dnssec_validation"]
        assert run_job(c, {"ids": ["net.dnssec_validation"]})["state"] == "done"                  # free again


def test_traffic_is_watched_in_chunks_so_a_stop_is_quick(cat, tmp_path):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged()
    scan = make_scan(host)
    scan.net, scan.online = FakeNet(), {**SETTINGS, "observe_seconds": 17}
    load_all()["tel.observed_traffic"](cat["tel.observed_traffic"]).detect(scan)
    assert [int(s) for a, s in host.privileged.calls if a == "observe_traffic"] == [5, 5, 7]
    host.privileged.calls.clear()
    stops = iter([False, True])
    scan.stop = lambda: next(stops, True)
    load_all()["tel.observed_traffic"](cat["tel.observed_traffic"]).detect(scan)
    assert [a for a, _ in host.privileged.calls].count("observe_traffic") == 1


def test_an_online_findings_guide_is_built_from_its_kept_result_never_by_running_it_again(cat, tmp_path):
    """How to… on an online finding: the runner takes the test's result as the report keeps it, and the
    network isn't touched; before the test has run, the server says to run it first."""
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"})
    bad = DEFAULTS["dnssec_failed"]
    fake = FakeNet(dns={DEFAULTS["dnssec_valid"]: ["93.184.215.14"], bad: ["203.0.113.9"]})
    with TestClient(create_app("t", cat, make_host=lambda: host, make_net=lambda: fake)) as c:
        c.post("/api/scan", headers=H)
        r = c.post("/api/fix/net.dnssec_validation/plan", headers=H)
        assert r.status_code == 400 and "Run this online test first" in r.json()["error"]
        job = run_job(c, {"ids": ["net.dnssec_validation"]})
        assert job["results"]["net.dnssec_validation"]["status"] == "fail"
        contacted = list(fake.contacted)
        r = c.post("/api/fix/net.dnssec_validation/plan", headers=H).json()
        assert r["guide"]["advice"] and r["guide"]["steps"][0]["title"] == "Turn on validation in systemd-resolved"
        assert r["result"]["status"] == "fail" and r["result"]["how_to"]
        assert fake.contacted == contacted                                   # built from the kept result
        rep = c.get("/api/state", headers=H).json()["report"]
        assert rep["results"]["net.dnssec_validation"]["status"] == "fail" and rep["results"]["net.dnssec_validation"]["how_to"]
