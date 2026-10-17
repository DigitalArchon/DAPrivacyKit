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
from daprivacyscanner.privileged import FakePrivileged

from conftest import detect, ev, make_host, make_scan
from fakes import FakeNmcli, FakeSystem
from test_checks_telemetry_browser import firefox, pref
from test_guides import apply, build, options, revert, rooted


def exposed(value=True):
    return ContextValue("exposed_services", value, [], "")


PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


# ------------------------------------------------------------------ 1. firewalld 2.x (Fedora 44, as read there)

FEDORA_ZONE = """FedoraWorkstation (default, active)
  target: default
  ingress-priority: 0
  egress-priority: 0
  icmp-block-inversion: no
  interfaces: enp1s0
  sources:
  services: dhcpv6-client samba-client ssh
  ports: 1025-65535/udp 1025-65535/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
"""


def service(ports, includes=""):
    return (f"x\n  ports: {ports}\n  protocols: \n  source-ports: \n  modules: \n  destination: \n"
            f"  includes: {includes}\n  helpers: \n")


def firewalld_host(tmp_path, zone=FEDORA_ZONE, **extra):
    return make_host(tmp_path, commands={
        ("systemctl", "is-active", "firewalld"): "active\n",
        ("firewall-cmd", "--get-active-zones"): "FedoraWorkstation (default)\n  interfaces: enp1s0\n",
        ("firewall-cmd", "--zone=FedoraWorkstation", "--list-all"): zone,
        ("firewall-cmd", "--info-service=dhcpv6-client"): service("546/udp"),
        ("firewall-cmd", "--info-service=samba-client"): service("138/udp", "netbios-ns"),
        ("firewall-cmd", "--info-service=netbios-ns"): service("137/udp"),
        ("firewall-cmd", "--info-service=ssh"): service("22/tcp"), **extra})


FEDORA_SS = [Listener("tcp", "0.0.0.0", 22, None), Listener("tcp", "[::]", 22, None),
             Listener("tcp", "0.0.0.0", 5355, None), Listener("udp", "0.0.0.0", 5355, None)]


def test_firewalld_2_zone_is_read_and_its_port_range_lets_services_in(cat, tmp_path):
    """firewalld 2.x prints "FedoraWorkstation (default)": the zone is the first word. Fedora Workstation's zone lets in
    1025-65535, so LLMNR on 5355 is reachable, and SSH through its service."""
    o = detect(cat, "net.exposed_services", make_scan(firewalld_host(tmp_path), listeners=FEDORA_SS,
                                                      exposed_services=exposed()))
    assert o.status is Status.FAIL and o.summary == "3 services are reachable from other machines."
    assert ev(o)["Blocked by firewalld"] == "none" and "Not sure whether firewalld lets in" not in ev(o)
    assert not any(n.kind == "limitation" and "firewalld" in n.title for n in o.notes)


def test_firewalld_service_includes_count(cat, tmp_path):
    """samba-client includes netbios-ns (137/udp): a zone without the port range still lets 137 in."""
    zone = FEDORA_ZONE.replace("  ports: 1025-65535/udp 1025-65535/tcp\n", "  ports: \n")
    listeners = [Listener("udp", "0.0.0.0", 137, "nmbd"), Listener("tcp", "0.0.0.0", 5355, None)]
    o = detect(cat, "net.exposed_services", make_scan(firewalld_host(tmp_path, zone), listeners=listeners,
                                                      exposed_services=exposed()))
    assert "137/udp" not in ev(o)["Blocked by firewalld"] and "5355/tcp" in ev(o)["Blocked by firewalld"]
    assert o.status is Status.FAIL and o.summary.startswith("1 of 2 services")


def test_firewalld_unreadable_says_why_and_not_to_scan_as_administrator(cat, tmp_path):
    host = make_host(tmp_path, commands={
        ("systemctl", "is-active", "firewalld"): "active\n",
        ("firewall-cmd", "--get-active-zones"): "FedoraWorkstation (default)\n  interfaces: enp1s0\n",
        ("firewall-cmd", "--zone=FedoraWorkstation", "--list-all"):
            CommandResult((), 1, "", "Authorization failed.\n    Make sure polkit agent is running\n")})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=FEDORA_SS, exposed_services=exposed()))
    note = next(n for n in o.notes if n.title == "A firewall (firewalld) is active")
    assert "Authorization failed." in note.text and "administrator access" not in note.text


def test_ufw_note_still_asks_for_administrator_access(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=yes\n"},
                     commands={("systemctl", "is-active", "ufw"): "active\n"})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=FEDORA_SS, exposed_services=exposed()))
    assert "Scan with administrator access" in next(n.text for n in o.notes if n.title == "A firewall (ufw) is active")


# ------------------------------------------------------------------ 2. root certificates

def test_fedoras_legacy_bundle_and_empty_files_are_not_added_roots(cat, tmp_path):
    host = make_host(tmp_path, files={
        "/usr/share/pki/ca-trust-legacy/ca-bundle.legacy.default.crt": "",
        "/etc/pki/ca-trust/source/README": "about",
        "/etc/pki/ca-trust/source/anchors/empty.crt": "",
        "/usr/local/share/ca-certificates/kept.pem": PEM,              # update-ca-certificates takes *.crt only
        "/usr/local/share/ca-certificates/note.crt": "not a certificate\n"},
        links={"/etc/pki/ca-trust/source/ca-bundle.legacy.crt": "/usr/share/pki/ca-trust-legacy/ca-bundle.legacy.default.crt",
               "/etc/pki/ca-trust/source/anchors/relative.crt": "../../../../../usr/share/pki/ca-trust-legacy/"
                                                                 "ca-bundle.legacy.default.crt"})
    o = detect(cat, "net.local_root_certs", make_scan(host))
    assert o.status is Status.PASS


def test_real_added_roots_still_count(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/pki/ca-trust/source/anchors/corp.crt": PEM,
                                      "/etc/pki/ca-trust/source/anchors/der.cer": "",
                                      "/etc/pki/ca-trust/source/trusted.pem":
                                          "-----BEGIN TRUSTED CERTIFICATE-----\nMIIB\n-----END TRUSTED CERTIFICATE-----\n",
                                      "/opt/corp/root.crt": PEM},
                     links={"/etc/pki/ca-trust/source/anchors/linked.crt": "/opt/corp/root.crt"})
    host.sys_path("/etc/pki/ca-trust/source/anchors/der.cer").write_bytes(b"\x30\x82\x01\x0a")
    o = detect(cat, "net.local_root_certs", make_scan(host))
    assert o.status is Status.WARN and ev(o)["Added root certificates"] == 4


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


# ------------------------------------------------------------------ 6, 12, 15. the exposed services guide and sshd

def test_kde_connect_ports_get_a_step(cat, tmp_path):
    listeners = [Listener("tcp", "[::]", 1716, None), Listener("udp", "[::]", 1716, None)]
    g = build(cat, make_host(tmp_path), "net.exposed_services", listeners=listeners, exposed_services=exposed())
    step = next(s for s in g.steps if s.title.startswith("KDE Connect or GSConnect"))
    assert step.title == "KDE Connect or GSConnect (port 1716)" and "net.kdeconnect" in step.text


def test_another_accounts_listener_says_what_is_true(cat, tmp_path):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged()
    g = build(cat, host, "net.exposed_services", listeners=[Listener("tcp", "0.0.0.0", 8443, None)],
              exposed_services=exposed())
    step = next(s for s in g.steps if s.title.startswith("Port 8443"))
    assert "without administrator access" not in step.text and "other accounts' programs" in step.text


SSHD = "Include /etc/ssh/sshd_config.d/*.conf\n"


def test_keys_only_option_is_done_once_the_apps_file_is_in_place(cat, tmp_path):
    dropin = helper.dropin_content("sshd", {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
                                            "PermitRootLogin": "no"}).decode()
    host = make_host(tmp_path, files={"/etc/ssh/sshd_config": SSHD,
                                      "/etc/ssh/sshd_config.d/10-daprivacyscanner.conf": dropin})
    listeners = [Listener("tcp", "0.0.0.0", 22, None)]
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=listeners, exposed_services=exposed()))
    g = load_guide(cat, host, o, listeners)
    ssh = g.steps[0]
    assert ssh.done and "Keep SSH, but only with keys" not in [x.label for x in ssh.options]
    # in place, yet an earlier file turns passwords on: sshd keeps the first value it reads
    host.sys_path("/etc/ssh/sshd_config.d/05-site.conf").write_text("PasswordAuthentication yes\n")
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=listeners, exposed_services=exposed()))
    ssh = load_guide(cat, host, o, listeners).steps[0]
    assert not ssh.done and "a setting read before this file says yes" in ssh.text and ssh.commands


def load_guide(cat, host, outcome, listeners):
    from daprivacyscanner.checks import load_all
    check = load_all()["net.exposed_services"](cat["net.exposed_services"])
    return check.plan_guide(make_scan(host, listeners=listeners, exposed_services=exposed()), outcome)


@pytest.mark.parametrize("line, shown", [
    ("PasswordAuthentication=no\n", "no"), ("PasswordAuthentication = No\n", "No"),
    ("passwordauthentication\tYes\n", "Yes"), ('PasswordAuthentication "no"\n', "no")])
def test_sshd_config_forms_sshd_accepts(cat, tmp_path, line, shown):
    host = make_host(tmp_path, files={"/etc/ssh/sshd_config": line})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=[Listener("tcp", "0.0.0.0", 22, "sshd")],
                                                      exposed_services=exposed()))
    assert ev(o)["SSH password logins"] == shown
    assert any(n.title == "SSH accepts passwords" for n in o.notes) is shown.lower().startswith("yes")


# ------------------------------------------------------------------ 7. IPv6 privacy on unconnected ports

def nm_ipv6_host(tmp_path, operstate="down", if_inet6="", tempaddr="0", default="2", conn="-1"):
    nm = FakeNmcli({"u1": {"type": "802-3-ethernet", "connection.id": "Wired", "ipv6.ip6-privacy": conn}})
    host = make_host(tmp_path, files={"/sys/class/net/enp1s0/device/vendor": "x",
                                      "/sys/class/net/enp1s0/operstate": operstate + "\n",
                                      "/proc/sys/net/ipv6/conf/enp1s0/use_tempaddr": tempaddr + "\n",
                                      "/proc/sys/net/ipv6/conf/default/use_tempaddr": "0\n",
                                      "/proc/net/if_inet6": if_inet6},
                     commands={("NetworkManager", "--print-config"): f"[connection]\nipv6.ip6-privacy={default}\n"})
    host.runner.handlers["nmcli"] = nm
    return host


GLOBAL = "2a0212340000000012345678abcdef01 02 40 00 00   enp1s0\n"


def test_an_unplugged_port_isnt_judged_by_its_kernel_value(cat, tmp_path):
    o = detect(cat, "net.ipv6_privacy", make_scan(nm_ipv6_host(tmp_path)))
    assert o.status is Status.PASS and "not on an IPv6 network now" in ev(o)["enp1s0"]
    o = detect(cat, "net.ipv6_privacy", make_scan(nm_ipv6_host(tmp_path / "up", "up", GLOBAL)))
    assert o.status is Status.FAIL and "enp1s0" in o.summary


def test_a_saved_network_that_turns_them_off_is_a_finding(cat, tmp_path):
    o = detect(cat, "net.ipv6_privacy", make_scan(nm_ipv6_host(tmp_path, conn="0")))
    assert o.status is Status.FAIL and o.summary.startswith("1 saved network turns IPv6 privacy addresses off")


def test_fix_with_nothing_left_says_reconnect(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    host = nm_ipv6_host(tmp_path, "up", GLOBAL)                 # connected before the default was set
    check = load_all()["net.ipv6_privacy"](cat["net.ipv6_privacy"])
    scan = make_scan(host)
    plan = check.plan_fix(scan, check.detect(scan))
    assert plan.empty and "next time it connects" in plan.side_effects[0]


# ------------------------------------------------------------------ 8. DNS inside a VPN, Firefox's DNS over HTTPS

MULLVAD_RESOLVECTL = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (wlp0s20f3)
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 192.168.1.1

Link 7 (wg0-mullvad)
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 10.64.0.1
        DNS Domain: ~.
"""


def test_lookups_routed_into_the_vpn_tunnel_are_protected(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n",
                                      "/sys/class/net/wg0-mullvad/uevent": "DEVTYPE=wireguard\n",
                                      "/sys/class/net/wlp0s20f3/uevent": "DEVTYPE=wlan\n"},
                     commands={"resolvectl status": MULLVAD_RESOLVECTL,
                               "ip -4 route get 1.1.1.1": "1.1.1.1 dev wg0-mullvad table 1836018789 src 10.64.0.2\n"})
    o = detect(cat, "net.dns_unencrypted", make_scan(host))
    assert o.status is Status.PASS and "inside the VPN tunnel (wg0-mullvad)" in o.summary
    assert o.notes[0].title == "Lookups go inside the VPN"
    leaky = host.runner.outputs[("resolvectl", "status")].stdout.replace("        DNS Domain: ~.\n", "")
    host.runner.outputs[("resolvectl", "status")] = CommandResult((), 0, leaky)
    assert detect(cat, "net.dns_unencrypted", make_scan(host)).status is Status.FAIL


def test_firefox_doh_is_seen(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 192.168.1.1\n"})
    firefox(host.home, pref("network.trr.mode", 2))
    o = detect(cat, "net.dns_unencrypted", make_scan(host))
    assert o.status is Status.WARN and o.summary.startswith("Firefox encrypts its own lookups")
    assert ev(o)["Firefox profiles using DNS over HTTPS"] == "Firefox profile abcd.default-release"
    assert "can't see that setting" not in " ".join(n.text for n in o.notes)
    firefox(host.home, pref("network.trr.mode", 5))
    o = detect(cat, "net.dns_unencrypted", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Firefox profiles using DNS over HTTPS"] == "none of 1"


# ------------------------------------------------------------------ 9. OpenSnitch's deny-mode step

def test_deny_mode_step_reads_as_a_sentence(cat, tmp_path):
    from daprivacyscanner.checks.guides.network import DENY_MODE
    from test_opensnitch import installed_host
    text = next(s.text for s in _os_guide(cat, installed_host(tmp_path)).steps if s.title == DENY_MODE)
    assert "about included)" not in text and text.count("(") == text.count(")")
    assert "Three kinds of connection are let through" in text


def _os_guide(cat, host):
    from daprivacyscanner.checks import load_all
    check = load_all()["net.outgoing_firewall"](cat["net.outgoing_firewall"])
    scan = make_scan(host)
    return check.plan_guide(scan, check.detect(scan))


# ------------------------------------------------------------------ 10. connectivity interval=0

def test_connectivity_interval_zero_is_off(cat, tmp_path):
    host = make_host(tmp_path, commands={"NetworkManager --print-config":
                                         "[connectivity]\nuri=http://fedoraproject.org/static/hotspot.txt\ninterval=0\n"})
    assert detect(cat, "net.connectivity_check", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ 11. the IPv6 address probed

def test_ipv6_probe_uses_this_computers_address_not_the_tunnels(cat, tmp_path):
    from daprivacyscanner.online import HttpResult
    from test_online import FakeNet, SETTINGS, run
    seen = []

    def answer(url, body):
        seen.append(url)
        return HttpResult(200, json.dumps({"open": False}).encode())
    host = make_host(tmp_path, files={"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n", "/proc/net/if_inet6":
                                      "fd000000000000000000000000000002 07 40 00 00   wg0\n"
                                      "2a07e3400000000000000000000000aa 07 80 00 00   wg0\n"
                                      "2a0212340000000012345678abcdef01 02 40 00 00   eth0\n"})
    probe = "https://probe.example.net/check"
    run(cat, "net.ipv6_reachable", host, FakeNet(http={probe + "*": answer}), {**SETTINGS, "port_probe": probe},
        listeners=[Listener("tcp", "[::]", 22, "sshd")], ipv6_global=True)
    assert seen and all("2a02%3A1234%3A%3A1234%3A5678%3Aabcd%3Aef01" in u for u in seen)
    o = run(cat, "net.ipv6_reachable", host, FakeNet(), listeners=[Listener("tcp", "[::]", 22, "sshd")], ipv6_global=True)
    assert "--probe 2a02:1234::1234:5678:abcd:ef01" in o.notes[0].text


# ------------------------------------------------------------------ 13. hidden networks forgotten by UUID

def test_forgetting_a_hidden_network_names_it_by_uuid(cat, tmp_path):
    nm = FakeNmcli({"u-1": {"type": "802-11-wireless", "connection.id": 'Bob\'s "$(reboot)" `x`',
                            "802-11-wireless.hidden": "yes"}})
    host = make_host(tmp_path)
    host.runner.handlers["nmcli"] = nm
    g = build(cat, host, "net.hidden_ssid")
    assert g.steps[1].commands == ['nmcli connection delete u-1     # Bob\'s "$(reboot)" `x`']


# ------------------------------------------------------------------ 16. Docker and Podman

def test_podman_docker_shim_rootless_passes(cat, tmp_path):
    host = make_host(tmp_path, commands={
        ("docker", "--version"): "podman version 5.4.0\n",
        ("docker", "info", "--format", "{{.Host.Security.Rootless}}"): "true\n",
        ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): "web\t0.0.0.0:8080->80/tcp\n"})
    o = detect(cat, "net.docker_bypass", make_scan(host))
    assert o.status is Status.PASS and "Podman" in o.summary
    assert ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}") not in host.runner.calls


def test_docker_service_not_running_is_no_container_and_isnt_started(cat, tmp_path):
    """Omarchy: docker.socket enabled, docker.service inactive; docker ps would start it through the socket."""
    host = make_host(tmp_path, commands={
        ("docker", "--version"): "Docker version 29.7.2, build 1\n",
        ("systemctl", "is-active", "docker.service"): CommandResult((), 3, "inactive\n"),
        ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"):
            CommandResult((), 1, "", "permission denied while trying to connect to the docker API\n")})
    o = detect(cat, "net.docker_bypass", make_scan(host))
    assert o.status is Status.PASS and "isn't running" in o.summary
    assert ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}") not in host.runner.calls
    (host.root / "proc/42").mkdir(parents=True)
    (host.root / "proc/42/comm").write_text("containerd-shim\n")          # live-restore: containers run on
    assert detect(cat, "net.docker_bypass", make_scan(host)).status is Status.UNKNOWN


def test_docker_finding_says_docker_user_rules_arent_read(cat, tmp_path):
    host = make_host(tmp_path, commands={
        ("docker", "--version"): "Docker version 29.7.2, build 1\n",
        ("systemctl", "is-active", "docker.service"): "active\n",
        ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): "web\t0.0.0.0:8080->80/tcp\n"})
    o = detect(cat, "net.docker_bypass", make_scan(host))
    assert o.status is Status.FAIL and "Rules in DOCKER-USER aren't read" in [n.title for n in o.notes]
    step = build(cat, host, "net.docker_bypass").steps[1]
    assert "accept the finding" in step.text


# ------------------------------------------------------------------ 17. names in hostnames

@pytest.mark.parametrize("text, login, words, found", [
    ("alice-laptop", "alice", [], "alice"), ("AlicesPC", "alice", [], "alice"), ("jsmith-pc", "jsmith", [], "jsmith"),
    ("alicepc", "alice", [], "alice"), ("JSmithLaptop", "jsmith", [], "jsmith"),
    ("Alice's MacBook Pro", "x", ["Alice", "Smith"], "Alice"),
    ("GPUTestPC", "test", ["Test"], None), ("planner", "bob", ["Ann"], None), ("annual-report", "bob", ["Ann"], None),
    ("alicetest", "alice", [], None)])
def test_mentions_name_matches_whole_words(text, login, words, found):
    assert mentions_name(text, login, words) == found
