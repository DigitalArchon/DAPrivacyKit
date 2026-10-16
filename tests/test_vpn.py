import copy
import datetime as dt

import pytest
import yaml

from daprivacyscanner import vpn
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan

VIA = "ip -4 route get 1.1.1.1"
RESOLVECTL = """Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 2 (wlp2s0)
    Current Scopes: DNS
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 192.168.1.1

Link 7 ({tunnel})
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: {dns}
       DNS Servers: {dns}
        DNS Domain: ~.
"""


@pytest.fixture(scope="module")
def data():
    return vpn.load()


def raw():
    return yaml.safe_load(vpn.default_path().read_text())


def tunnel_host(tmp_path, name, dns=None, procs=(), commands=None):
    files = {f"/sys/class/net/{name}/uevent": "DEVTYPE=wireguard\n", "/sys/class/net/wlp2s0/uevent": "DEVTYPE=wlan\n"}
    files.update({f"/proc/{100 + i}/comm": f"{p}\n" for i, p in enumerate(procs)})
    cmds = {VIA: f"1.1.1.1 dev {name} table 51820 src 10.64.0.2 uid 1000\n", **(commands or {})}
    if dns:
        cmds["resolvectl status"] = RESOLVECTL.format(tunnel=name, dns=dns)
    return make_host(tmp_path, files=files, commands=cmds)


# ------------------------------------------------------------------ the data

def test_every_fact_has_a_source_and_a_date(data):
    for p in data:
        assert p.all_facts(), p.id
        for f in p.all_facts():
            assert f.source.startswith("https://") and isinstance(f.verified, dt.date) and f.text
    assert {"mullvad", "proton", "expressvpn", "pia", "cyberghost"} <= set(data.providers)
    assert data["expressvpn"].group_name == "Kape Technologies" and data["pia"].group == "kape"


@pytest.mark.parametrize("mangle, said", [
    (lambda d: d["providers"][0]["facts"][0].pop("source"), "needs exactly topic, text, source and verified"),
    (lambda d: d["providers"][0]["facts"][0].update(verified="recently"), "verified must be a date"),
    (lambda d: d["providers"][0]["facts"][0].update(topic="verdict"), "topic must be one of"),
    (lambda d: d["providers"][0]["facts"][0].update(source="http://example.com"), "https://"),
    (lambda d: d["providers"][0].update(group="nobody"), "isn't in groups"),
    (lambda d: d["providers"][0].update(score=2), "unknown keys"),
    (lambda d: d["providers"][0]["browser_proxy"].update(address="185.65.135.1"), "private IPv4 address"),
    (lambda d: d["providers"][0]["browser_proxy"].pop("verified"), "needs exactly"),
    (lambda d: d["providers"][0]["browser_proxy"].update(source="http://api.mullvad.net"), "https://"),
])
def test_claims_without_a_source_are_refused(mangle, said):
    d = copy.deepcopy(raw())
    mangle(d)
    with pytest.raises(vpn.DataError, match=said):
        vpn.parse(d)


def test_mullvad_browser_s_proxy_is_one_its_sandbox_lets_through(data):
    """The proxy Mullvad Browser is set up with: inside Mullvad's tunnel, named as its extension names it,
    and let through the sandbox's fence (TCP to that port)."""
    import ipaddress
    from daprivacyscanner.tools import sandbox
    p = data["mullvad"].browser_proxy
    assert p.server == "ch-zrh-wg-001" and p.country_code == "ch" and p.source.startswith("https://")
    assert any(ipaddress.ip_address(p.address) in ipaddress.ip_network(net) and port == p.port
               for net, port in sandbox.FENCE_ALLOWED)


def test_stale_facts_are_said(data):
    p = data["mullvad"]
    assert vpn.stale(p, p.oldest_check() + dt.timedelta(days=30)) is None
    assert vpn.stale(p, p.oldest_check() + dt.timedelta(days=400)) == p.oldest_check()


def test_network_owners(data):
    assert data.network_owner("AS39351 31173 Services AB").id == "mullvad"
    assert data.network_owner("AS1221 Telstra") is None
    assert data.is_datacentre("AS9009 M247 Europe SRL") and not data.is_datacentre("AS1221 Telstra")


# ------------------------------------------------------------------ recognising the provider

def test_recognised_by_its_interface_and_status_command(tmp_path, data):
    host = tunnel_host(tmp_path, "wg0-mullvad", procs=["mullvad-daemon"],
                       commands={"mullvad status": "Connected\n    Relay:    se-got-wg-001\n"})
    [m] = vpn.identify(host, data)
    assert m.provider.id == "mullvad" and m.in_use and m.relay == "se-got-wg-001"
    assert ("process", "mullvad-daemon") in m.signs


def test_recognised_by_the_dns_server_in_its_tunnel(tmp_path, data):
    [m] = vpn.identify(tunnel_host(tmp_path, "wg0", dns="10.2.0.1"), data)
    assert m.provider.id == "proton" and m.signs == [("resolver", "10.2.0.1 on wg0")]


def test_a_running_daemon_alone_is_not_a_vpn_in_use(tmp_path, data):
    host = make_host(tmp_path, files={"/proc/42/comm": "nordvpnd\n"})
    [m] = vpn.identify(host, data)
    assert m.provider.id == "nordvpn" and not m.in_use


# ------------------------------------------------------------------ the check

def test_vpn_provider_shows_sourced_facts(cat, tmp_path):
    o = detect(cat, "net.vpn_provider", make_scan(tunnel_host(tmp_path, "wg0-mullvad")))
    assert o.status is Status.PASS and o.summary == "Your VPN is Mullvad VPN."
    notes = {n.title: n.text for n in o.notes}
    assert "Source: https://en.wikipedia.org/wiki/Mullvad, checked " in notes["Who runs it"]
    assert "https://mullvad.net/check" in notes["Mullvad VPN's own connection check"]


def test_vpn_provider_names_the_owner(cat, tmp_path):
    host = tunnel_host(tmp_path, "wgpia0", procs=["pia-daemon"])
    o = detect(cat, "net.vpn_provider", make_scan(host))
    assert o.summary == "Your VPN is Private Internet Access, owned by Kape Technologies."
    assert "Crossrider" in {n.title: n.text for n in o.notes}["Its owner, Kape Technologies"]
    assert ev(o)["Private Internet Access recognised by"] == "interface wgpia0, process pia-daemon"


def test_vpn_provider_unrecognised_and_absent(cat, tmp_path):
    o = detect(cat, "net.vpn_provider", make_scan(tunnel_host(tmp_path / "a", "wg0")))
    assert o.status is Status.PASS and "wasn't recognised" in o.summary
    assert detect(cat, "net.vpn_provider", make_scan(make_host(tmp_path / "b"))).status is Status.NOT_APPLICABLE
    idle = detect(cat, "net.vpn_provider", make_scan(make_host(tmp_path / "c", files={"/proc/7/comm": "nordvpnd\n"})))
    assert idle.status is Status.PASS and "not connected now" in idle.summary


# ------------------------------------------------------------------ the rating

@pytest.mark.parametrize("pid, label", [
    ("mullvad", "Recommended"), ("ivpn", "Recommended"),
    ("proton", "Good"), ("windscribe", "Good"), ("airvpn", "Good"),
    ("nordvpn", "Acceptable"),
    ("pia", "Ownership concerns: owned by Kape Technologies"),
    ("surfshark", "Closed client"), ("hotspotshield", "Closed client"),
    ("expressvpn", "Closed client, and owned by Kape Technologies"),
    ("cyberghost", "Closed client, and owned by Kape Technologies"),
    ("ipvanish", "Avoid (also a closed client)"), ("purevpn", "Avoid"), ("hola", "Avoid"), ("urbanvpn", "Avoid"),
])
def test_every_provider_is_rated_with_its_receipts(data, pid, label):
    r = vpn.rate(data[pid])
    assert r.label == label
    # a gate always shows the facts that decided it, each with its source
    if r.concern:
        assert r.reasons and all(f.source.startswith("https://") for f in r.reasons)


@pytest.mark.parametrize("flags, severity", [
    ({"vpn_ownership_concerns": True}, 4),
    ({"vpn_closed_client": True}, 5),
    ({"vpn_closed_client": True, "vpn_ownership_concerns": True}, 6),
    ({"vpn_avoid": True, "vpn_closed_client": True}, 8),
])
def test_severity_by_gate(cat, flags, severity):
    from daprivacyscanner.catalogue import effective_severity
    values = {"vpn_avoid": False, "vpn_closed_client": False, "vpn_ownership_concerns": False, **flags}
    for check_id in ("net.vpn_trust", "br.vpn_extensions"):
        assert effective_severity(cat[check_id], values).value == severity


def _provider(d, pid):
    return next(p for p in d["providers"] if p["id"] == pid)


@pytest.mark.parametrize("mangle, said", [
    (lambda d: _provider(d, "pia").update(rating={"tier": "good"}), "a gate decides"),
    (lambda d: _provider(d, "proton")["rating"].update(tier="recommended"), "linux_flaw"),
    (lambda d: _provider(d, "mullvad").update(facts=[f for f in _provider(d, "mullvad")["facts"]
                                                     if "open_client" not in f.get("supports", [])]),
     "needs a fact supporting open_client"),
    (lambda d: d["groups"]["kape"].update(facts=[{**f, "supports": []} for f in d["groups"]["kape"]["facts"]]),
     "a cap needs facts"),
    (lambda d: _provider(d, "mullvad")["facts"][0].update(supports=["trustworthy"]), "supports only"),
])
def test_the_data_cant_contradict_the_rating_rules(mangle, said):
    d = copy.deepcopy(raw())
    mangle(d)
    with pytest.raises(vpn.DataError, match=said):
        vpn.parse(d)


def test_vpn_trust_lists_kape_and_the_closed_client(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/42/comm": "expressvpnd\n"})
    o = detect(cat, "net.vpn_trust", make_scan(host))
    assert o.status is Status.FAIL
    assert o.summary == "The VPN app running here, ExpressVPN, is rated Closed client, and owned by Kape Technologies."
    assert o.findings == {"vpn_avoid": False, "vpn_closed_client": True, "vpn_ownership_concerns": True}
    notes = {n.title: n.text for n in o.notes}
    assert "proprietary" in notes["Its Linux app is closed source"] and "Source: https://" in notes[
        "Its Linux app is closed source"]
    assert "Crossrider" in notes["Its owner, Kape Technologies"] and "vpnMentor" in notes["Its owner, Kape Technologies"]
    # the providers to move to come from the data, never from a list written into the catalogue's text
    rated = notes["Providers rated Recommended or Good"]
    assert rated.startswith("Recommended: IVPN, Mullvad VPN. Good: AirVPN, Proton VPN, Windscribe.")
    assert "Mullvad" not in cat["net.vpn_trust"].remedy and "Proton" not in cat["net.vpn_trust"].remedy


def test_vpn_trust_explains_the_outliers(cat, tmp_path):
    o = detect(cat, "net.vpn_trust", make_scan(tunnel_host(tmp_path / "a", "wgpia0")))
    assert o.status is Status.FAIL and o.findings["vpn_ownership_concerns"] and not o.findings["vpn_closed_client"]
    assert "2016" in {n.title: n.text for n in o.notes}["DA Privacy Kit's view"]
    o = detect(cat, "net.vpn_trust", make_scan(tunnel_host(tmp_path / "b", "surfshark_wg")))
    assert o.status is Status.FAIL and "audits" in {n.title: n.text for n in o.notes}["DA Privacy Kit's view"]


def test_vpn_trust_passes_good_providers_and_says_why(cat, tmp_path):
    o = detect(cat, "net.vpn_trust", make_scan(tunnel_host(tmp_path / "a", "proton0")))
    assert o.status is Status.PASS and o.summary == "Your VPN, Proton VPN, is rated Good."
    assert "kill switch" in o.notes[0].text
    assert detect(cat, "net.vpn_trust", make_scan(make_host(tmp_path / "b"))).status is Status.NOT_APPLICABLE


def test_vpn_provider_shows_the_rating(cat, tmp_path):
    o = detect(cat, "net.vpn_provider", make_scan(tunnel_host(tmp_path, "wg0-mullvad")))
    assert ev(o)["DA Privacy Kit's rating"] == "Recommended"
    assert o.notes[0].title == "DA Privacy Kit's rating: Recommended" and "Monero" in o.notes[0].text


# ------------------------------------------------------------------ browser extensions

def urban_chrome(home):
    import json
    prof = home / ".config/google-chrome/Default"
    ext = prof / "Extensions/eppiocemhmnlbhjplcgkofciiegomcon/5.5.0_0"
    ext.mkdir(parents=True)
    (prof / "Preferences").write_text("{}")
    (ext / "manifest.json").write_text(json.dumps({"name": "Urban VPN Proxy", "manifest_version": 3,
                                                   "permissions": ["proxy"]}))      # site access not even asked for


def test_vpn_extensions_with_harm_on_record(cat, tmp_path):
    host = make_host(tmp_path)
    urban_chrome(host.home)
    o = detect(cat, "br.vpn_extensions", make_scan(host))
    assert o.status is Status.FAIL and "Urban VPN Proxy" in o.summary and o.findings["vpn_avoid"]
    assert "AI chatbots" in o.notes[0].text and "Source: https://thehackernews.com" in o.notes[0].text
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.model import Outcome
    g = load_all()["br.vpn_extensions"](cat["br.vpn_extensions"]).plan_guide(make_scan(host), Outcome(Status.FAIL))
    assert g.steps[0].title.startswith("Urban VPN Proxy") and g.steps[0].options


def test_no_vpn_extensions(cat, tmp_path):
    host = make_host(tmp_path)
    (host.home / ".config/google-chrome/Default").mkdir(parents=True)
    (host.home / ".config/google-chrome/Default/Preferences").write_text("{}")
    assert detect(cat, "br.vpn_extensions", make_scan(host)).status is Status.PASS
    assert detect(cat, "br.vpn_extensions", make_scan(make_host(tmp_path / "b"))).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("mangle, said", [
    (lambda d: d["providers"][0]["leak_protection"].pop("if_leaking"), "needs text, source, verified and if_leaking"),
    (lambda d: d["providers"][0]["leak_protection"].update(source="http://github.com"), "https://"),
    (lambda d: d["providers"][0]["leak_protection"]["lockdown"].pop("cost"), "needs exactly"),
])
def test_leak_protection_is_checked(mangle, said):
    d = copy.deepcopy(raw())
    assert d["providers"][0]["id"] == "mullvad"
    mangle(d)
    with pytest.raises(vpn.DataError, match=said):
        vpn.parse(d)
