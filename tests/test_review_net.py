"""The network checks' fixes from the review of 2026-10-17: firewalld 2.x on Fedora, its legacy CA bundle, NetworkManager's
[connection*] sections, ufw.service on Arch, networkd's container file, systemd-resolved's mDNS and LLMNR, unconnected
ports, DNS inside a VPN, Firefox's DNS over HTTPS, Podman's docker, names in hostnames."""

import json

import pytest

from daprivacyscanner import helper
from daprivacyscanner.checks._util import mentions_name
from daprivacyscanner.checks.network import _nm_spec_covers, nm_default
from daprivacyscanner.context import ContextValue
from daprivacyscanner.host import CommandResult
from daprivacyscanner.ini import parse
from daprivacyscanner.model import Status
from daprivacyscanner.network import Listener

from conftest import detect, ev, make_host, make_scan
from fakes import FakeNmcli, FakeSystem
from test_guides import apply, build, options, revert, rooted


def exposed(value=True):
    return ContextValue("exposed_services", value, [], "")



# ------------------------------------------------------------------ 3. NetworkManager's [connection*] sections

FEDORA_NM = """[main]
configure-and-quit=no

[connectivity]
enabled=true
uri=http://fedoraproject.org/static/hotspot.txt
interval=300

[device]

[device-nbft-no-ignore-carrier]
match-device=interface-name:nbft*
ignore-carrier=no

[connection.22-wifi-mac-addr]
match-device=type:wifi
wifi.cloned-mac-address=stable-ssid
"""


def test_nm_sections_in_networkmanagers_order():
    cfg = parse("[connection]\nipv6.ip6-privacy=0\nwifi.cloned-mac-address=stable\n"
                "[connection-app-1]\nmatch-device=driver:wl\nwifi.cloned-mac-address=preserve\n"
                "[connection-a]\nmatch-device=type:wifi\nipv6.ip6-privacy=1\n"
                "[connection-c]\nmatch-device=type:ethernet\nstop-match=yes\n"
                "[connection.22-wifi-mac-addr]\nmatch-device=type:wifi\nwifi.cloned-mac-address=stable-ssid\n")
    # [connection] comes last, though --print-config prints it first; a driver's section isn't Wi-Fi's default
    assert nm_default(cfg, "wifi.cloned-mac-address", "wifi") == ("stable-ssid", "connection.22-wifi-mac-addr")
    assert nm_default(cfg, "ipv6.ip6-privacy", "wifi") == ("1", "connection-a")
    assert nm_default(cfg, "ipv6.ip6-privacy", "ethernet") == (None, "connection-c")       # stop-match
    assert nm_default(parse(""), "ipv6.ip6-privacy", "wifi") == (None, None)
    assert _nm_spec_covers("*", "wifi") and _nm_spec_covers("except:type:ethernet", "wifi")
    assert not _nm_spec_covers("except:type:wifi", "wifi") and not _nm_spec_covers("interface-name:wlan0", "wifi")


def test_fedoras_stable_ssid_default_passes_and_no_easy_fix_replaces_it(cat, tmp_path):
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": ""}})
    host = make_host(tmp_path, commands={("NetworkManager", "--print-config"): FEDORA_NM})
    host.runner.handlers["nmcli"] = nm
    o = detect(cat, "net.mac_permanent", make_scan(host))
    assert o.status is Status.PASS
    assert ev(o)["Default for Wi-Fi"] == "stable-ssid (from NetworkManager's [connection.22-wifi-mac-addr] section)"


def test_mac_guide_doesnt_write_a_default_fedoras_section_outranks(cat, tmp_path):
    """Scanning with the hardware address is still fixed; the Wi-Fi default the app would write in [connection] would
    change nothing, so it isn't written."""
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": ""}})
    host = make_host(tmp_path, commands={("NetworkManager", "--print-config"):
                                         FEDORA_NM.replace("[device]\n", "[device]\nwifi.scan-rand-mac-address=no\n")})
    host.runner.handlers["nmcli"] = nm
    g = build(cat, host, "net.mac_permanent")
    plan = options(g)["A random address for each network, kept for it (stable)"]
    assert plan.actions[0].args == {"name": "nm-mac", "settings": {"device:wifi.scan-rand-mac-address": "yes"}}
    assert "already a made-up address" in g.steps[0].text


def test_hostname_default_from_a_distributions_section(cat, tmp_path):
    """A named section that sends the hostname for Wi-Fi outranks the app's [connection] default: those connections
    are changed one by one, and the guide says why."""
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home",
                           "ipv4.dhcp-send-hostname": "-1", "ipv6.dhcp-send-hostname": "-1"}})
    host = make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n"}, env={"USER": "alice"},
                     commands={("NetworkManager", "--print-config"):
                               "[connection-wifi]\nmatch-device=type:wifi\nipv4.dhcp-send-hostname=1\n",
                               ("NetworkManager", "--version"): "1.56.0-1.fc44\n"})
    host.runner.handlers["nmcli"] = nm
    g = build(cat, host, "net.hostname_broadcast")
    plan = options(g)["Stop sending it"]
    assert plan.actions[0].request == "write_dropin"
    assert {(a.name, a.prop) for a in plan.actions[1:]} == {("Home", "ipv4.dhcp-send-hostname"),
                                                           ("Home", "ipv6.dhcp-send-hostname")}
    assert any("[connection-wifi] section" in e for e in plan.side_effects)


# ------------------------------------------------------------------ 14. NetworkManager's version

def test_nm_version_says_the_default_is_read_when_no_connection_shows_minus_one(cat, tmp_path):
    nm = FakeNmcli({"u1": {"type": "802-3-ethernet", "connection.id": "Wired",
                           "ipv4.dhcp-send-hostname": "yes", "ipv6.dhcp-send-hostname": "yes"}})
    host = make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n"}, env={"USER": "alice"},
                     commands={("NetworkManager", "--print-config"): "[main]\n",
                               ("NetworkManager", "--version"): "1.56.0-1.fc44\n"})
    host.runner.handlers["nmcli"] = nm
    o = detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[]))
    assert ev(o)["Networks joined from now on"] == "send the hostname"          # not "(... before 1.52)"
    plan = options(build(cat, host, "net.hostname_broadcast", listeners=[]))["Stop sending it"]
    assert plan.actions[0].describe().startswith("Write /etc/NetworkManager/conf.d/99-daprivacyscanner-hostname.conf")
    host.runner.outputs[("NetworkManager", "--version")] = CommandResult((), 0, "1.46.0\n")
    o = detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[]))
    assert "before 1.52" in ev(o)["Networks joined from now on"]


# ------------------------------------------------------------------ 4. ufw.service on Arch

@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(r))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    return r


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def test_ufw_enable_enables_its_unit_where_the_package_didnt(root):
    """Arch: `ufw enable` writes ENABLED=yes, but ufw.service, which loads the rules at boot, stays disabled."""
    helper.RUN.units = {"ufw.service": ["disabled", "inactive"]}
    r = call("ufw_enable", allow=[])
    assert helper.RUN.ufw_active and helper.RUN.units["ufw.service"] == ["enabled", "active"]
    assert ["systemctl", "enable", "ufw.service"] in helper.RUN.calls
    assert "systemctl enable ufw.service" in r["ran"] and "systemctl start ufw.service" in r["ran"]
    back = call("revert", change_id=r["change_id"])
    assert back["ok"] and not helper.RUN.ufw_active and helper.RUN.units["ufw.service"] == ["disabled", "inactive"]


def test_ufw_on_but_its_unit_off_is_a_change(root):
    """ufw turned on by an earlier version (ENABLED=yes, rules loaded), its unit never enabled: still a change."""
    helper.RUN.units = {"ufw.service": ["disabled", "inactive"]}
    helper.RUN.ufw_active = True
    r = call("ufw_enable", allow=[])
    assert r["changed"] and helper.RUN.units["ufw.service"] == ["enabled", "active"]
    call("revert", change_id=r["change_id"])
    assert helper.RUN.ufw_active and helper.RUN.units["ufw.service"] == ["disabled", "inactive"]


def test_ufw_enabled_unit_is_left_alone(root):
    helper.RUN.units = {"ufw.service": ["enabled", "active"]}          # Debian, Ubuntu, Mint
    call("ufw_enable", allow=[])
    assert not any(c[:2] == ["systemctl", "enable"] for c in helper.RUN.calls)
    helper.RUN.ufw_active = True
    assert not call("ufw_enable", allow=[])["changed"]


def test_ufw_dry_run_names_the_unit_when_it_isnt_enabled(root):
    (root / "usr/lib/systemd/system").mkdir(parents=True)
    (root / "usr/lib/systemd/system/ufw.service").write_text("[Unit]\n")
    assert helper.planned("ufw_enable", {"allow": []})[-2:] == ["systemctl enable ufw.service",
                                                                 "systemctl start ufw.service"]
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "ufw.service").symlink_to("/usr/lib/systemd/system/ufw.service")
    assert helper.planned("ufw_enable", {"allow": []}) == ["ufw --force enable"]


def test_ufw_guide_says_it_turns_the_unit_on(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=no\n", "/etc/os-release": "ID=arch\n"},
                     commands={("systemctl", "is-enabled", "ufw.service"): "disabled\n",
                               ("systemctl", "is-active", "ufw.service"): "inactive\n"})
    g = build(cat, host, "net.firewall_off", listeners=[])
    plan = options(g)["Turn on ufw"]
    assert "systemctl enable --now ufw" in plan.actions[0].describe()
    assert any("ufw.service isn't set to start at boot" in e for e in plan.side_effects)


# ------------------------------------------------------------------ 5. systemd-networkd and systemd-resolved

def networkd_host(tmp_path, files, ifaces=("enp1s0",), resolvectl=""):
    nets = {f"/sys/class/net/{i}/operstate": "up\n" for i in ifaces}
    return make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n", **nets, **files},
                     env={"USER": "alice"},
                     commands={("systemctl", "is-active", "systemd-networkd"): "active\n",
                               "resolvectl status": resolvectl})


CONTAINER_NETWORK = "[Match]\nVirtualization=container\nName=host0\n\n[Network]\nDHCP=yes\nLinkLocalAddressing=yes\n"


def test_systemds_container_file_doesnt_count_on_a_host(cat, tmp_path):
    host = networkd_host(tmp_path, {"/usr/lib/systemd/network/80-container-host0.network": CONTAINER_NETWORK})
    o = detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[], virtualization="none"))
    assert ev(o)["Announced via"] == "nothing found"
    inside = networkd_host(tmp_path / "c", {"/usr/lib/systemd/network/80-container-host0.network": CONTAINER_NETWORK},
                           ifaces=("host0",))
    o = detect(cat, "net.hostname_broadcast", make_scan(inside, listeners=[], virtualization="container"))
    assert ev(o)["Announced via"] == "DHCP (systemd-networkd)"


def test_networkd_first_matching_file_and_its_dropin(cat, tmp_path):
    files = {"/usr/lib/systemd/network/89-ethernet.network": "[Match]\nName=en*\n[Network]\nDHCP=yes\n",
             "/etc/systemd/network/10-wlan.network": "[Match]\nName=wl*\n[Network]\nDHCP=no\n"}
    host = networkd_host(tmp_path, files)
    assert ev(detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[])))["Announced via"] == \
        "DHCP (systemd-networkd)"
    step = next(s for s in build(cat, host, "net.hostname_broadcast", listeners=[]).steps
                if s.title == "systemd-networkd: don't send the hostname")
    assert "/usr/lib/systemd/network/89-ethernet.network" in step.text and "copy" not in step.text
    assert step.commands == ["sudo mkdir -p /etc/systemd/network/89-ethernet.network.d",
                             "printf '[DHCPv4]\\nSendHostname=no\\n' | sudo tee "
                             "/etc/systemd/network/89-ethernet.network.d/60-no-hostname.conf",
                             "sudo networkctl reload"]
    # what the commands write: the file stays the package's, the drop-in turns the hostname off
    d = host.sys_path("/etc/systemd/network/89-ethernet.network.d")
    d.mkdir(parents=True)
    (d / "60-no-hostname.conf").write_text("[DHCPv4]\nSendHostname=no\n")
    assert ev(detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[])))["Announced via"] == "nothing found"


RESOLVED_MDNS = """Global
         Protocols: LLMNR=resolve +mDNS -DNSOverTLS DNSSEC=no/unsupported
Link 2 (enp1s0)
         Protocols: +DefaultRoute LLMNR=resolve +mDNS -DNSOverTLS
"""


def test_resolved_mdns_announcing_gets_a_step_that_keeps_llmnr(cat, tmp_path, monkeypatch):
    host = make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n",
                                      "/etc/systemd/resolved.conf.d/60-daprivacyscanner-llmnr.conf":
                                          helper.DROPIN_HEADER + "[Resolve]\nLLMNR=no\n"},
                     env={"USER": "alice"}, commands={"resolvectl status": RESOLVED_MDNS})
    system = FakeSystem()
    monkeypatch.setattr(helper, "RUN", system)
    host = rooted(host, system, monkeypatch)
    o = detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[Listener("udp", "0.0.0.0", 5355)]))
    # LLMNR=resolve only asks (Fedora's default listens on 5355 all the same): not a channel
    assert ev(o)["Announced via"] == "mDNS (systemd-resolved)"
    g = build(cat, host, "net.hostname_broadcast", listeners=[Listener("udp", "0.0.0.0", 5355)])
    assert "Stop answering LLMNR" not in [s.title for s in g.steps]
    plan = options(g)["Stop announcing it, and keep finding .local names"]
    assert plan.actions[0].args["settings"] == {"LLMNR": "no", "MulticastDNS": "resolve"}
    log, res = apply(host, plan)
    conf = host.sys_path("/etc/systemd/resolved.conf.d/60-daprivacyscanner-llmnr.conf").read_text()
    assert conf.endswith("[Resolve]\nLLMNR=no\nMulticastDNS=resolve\n")
    host.runner.outputs[("resolvectl", "status")] = CommandResult((), 0, RESOLVED_MDNS.replace("+mDNS", "mDNS=resolve"))
    assert ev(detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[])))["Announced via"] == "nothing found"
    revert(host, log, res)
    assert host.sys_path("/etc/systemd/resolved.conf.d/60-daprivacyscanner-llmnr.conf").read_text().endswith(
        "[Resolve]\nLLMNR=no\n")


def test_llmnr_answered_by_resolved_is_a_channel(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n"}, env={"USER": "alice"},
                     commands={"resolvectl status": RESOLVED_MDNS.replace("LLMNR=resolve", "+LLMNR").replace("+mDNS", "-mDNS")})
    assert ev(detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[])))["Announced via"] == "LLMNR"


# ------------------------------------------------------------------ 10. connectivity interval=0

def test_connectivity_interval_zero_is_off(cat, tmp_path):
    host = make_host(tmp_path, commands={"NetworkManager --print-config":
                                         "[connectivity]\nuri=http://fedoraproject.org/static/hotspot.txt\ninterval=0\n"})
    assert detect(cat, "net.connectivity_check", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ 13. hidden networks forgotten by UUID

def test_forgetting_a_hidden_network_names_it_by_uuid(cat, tmp_path):
    nm = FakeNmcli({"u-1": {"type": "802-11-wireless", "connection.id": 'Bob\'s "$(reboot)" `x`',
                            "802-11-wireless.hidden": "yes"}})
    host = make_host(tmp_path)
    host.runner.handlers["nmcli"] = nm
    g = build(cat, host, "net.hidden_ssid")
    assert g.steps[1].commands == ['nmcli connection delete u-1     # Bob\'s "$(reboot)" `x`']


# ------------------------------------------------------------------ 17. names in hostnames

@pytest.mark.parametrize("text, login, words, found", [
    ("alice-laptop", "alice", [], "alice"), ("AlicesPC", "alice", [], "alice"), ("jsmith-pc", "jsmith", [], "jsmith"),
    ("alicepc", "alice", [], "alice"), ("JSmithLaptop", "jsmith", [], "jsmith"),
    ("Alice's MacBook Pro", "x", ["Alice", "Smith"], "Alice"),
    ("GPUTestPC", "test", ["Test"], None), ("planner", "bob", ["Ann"], None), ("annual-report", "bob", ["Ann"], None),
    ("alicetest", "alice", [], None)])
def test_mentions_name_matches_whole_words(text, login, words, found):
    assert mentions_name(text, login, words) == found
