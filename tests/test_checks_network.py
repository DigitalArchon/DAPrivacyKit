import os

import pytest

from daprivacyscanner import network
from daprivacyscanner.context import ContextValue
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.network import Listener
from daprivacyscanner.privileged import FakePrivileged

from conftest import skip_if_root, detect, ev, make_host, make_scan, sample

MINT_SS = network.parse_ss(sample("ss/mint-22.txt"))


def exposed(value=True):
    return ContextValue("exposed_services", value, [], "")


def test_exposed_services_with_ssh_defaults(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n",
                                      "/etc/ssh/sshd_config.d/50-cloud.conf": "PermitRootLogin no\n"})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=MINT_SS, exposed_services=exposed()))
    assert o.status is Status.FAIL and o.summary.startswith("2 services")
    assert ev(o)["SSH password logins"] == "yes (default)" and ev(o)["SSH root login"] == "no"
    assert any(n.title == "SSH accepts passwords" for n in o.notes)


@skip_if_root
def test_sshd_config_unreadable_is_not_assumed_to_allow_passwords(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/ssh/sshd_config": "PasswordAuthentication no\n"})
    os.chmod(host.sys_path("/etc/ssh/sshd_config"), 0)                      # Fedora keeps it root-only
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=MINT_SS, exposed_services=exposed()))
    assert o.partial and ev(o)["SSH password logins"].startswith("unknown")
    assert not any(n.title == "SSH accepts passwords" for n in o.notes)
    assert any(n.kind == "limitation" and "SSH" in n.title for n in o.notes)


def test_sshd_first_value_wins_and_match_blocks_are_ignored(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/ssh/sshd_config": "Include sshd_config.d/*.conf\nPasswordAuthentication yes\n"
                                                              "Match User bob\n  PasswordAuthentication yes\n",
                                      "/etc/ssh/sshd_config.d/10-hardening.conf": "PasswordAuthentication no\n"})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=MINT_SS, exposed_services=exposed()))
    assert ev(o)["SSH password logins"] == "no" and not any(n.title == "SSH accepts passwords" for n in o.notes)


def test_exposed_services_prefers_sshd_t_with_root(cat, tmp_path):
    host = make_host(tmp_path)
    host.privileged = FakePrivileged(sshd={"passwordauthentication": ["no"], "permitrootlogin": ["without-password"]})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=MINT_SS, exposed_services=exposed()))
    assert ev(o)["SSH password logins"] == "no"


def test_nothing_exposed(cat, tmp_path):
    o = detect(cat, "net.exposed_services", make_scan(make_host(tmp_path), listeners=[], exposed_services=exposed(False)))
    assert o.status is Status.PASS


@pytest.mark.parametrize("out, status", [
    ("web\t0.0.0.0:8080->80/tcp, :::8080->80/tcp\ndb\t127.0.0.1:5432->5432/tcp\n", Status.FAIL),
    ("db\t127.0.0.1:5432->5432/tcp\nworker\t\n", Status.PASS),
    (CommandResult((), 1, "", "permission denied while trying to connect to the Docker daemon socket"), Status.UNKNOWN),
])
def test_docker(cat, tmp_path, out, status):
    host = make_host(tmp_path, commands={("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): out})
    o = detect(cat, "net.docker_bypass", make_scan(host))
    assert o.status is status
    if status is Status.FAIL:
        assert ev(o) == {"web": "8080 → 80/tcp on all interfaces"}


def test_no_docker(cat, tmp_path):
    assert detect(cat, "net.docker_bypass", make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("files, commands, status", [
    ({"/etc/ufw/ufw.conf": "ENABLED=yes\n"}, {"systemctl is-active ufw": "active\n"}, Status.PASS),
    ({"/etc/ufw/ufw.conf": "ENABLED=no\n"}, {"systemctl is-active ufw": "active\n"}, Status.FAIL),   # Mint's default
    ({}, {"systemctl is-active firewalld": "active\n"}, Status.PASS),
    ({}, {}, Status.FAIL),
])
def test_firewall(cat, tmp_path, files, commands, status):
    host = make_host(tmp_path, files=files, commands=commands, installed=["systemctl"])
    assert detect(cat, "net.firewall_off", make_scan(host)).status is status


def test_firewall_rules_seen_with_root(cat, tmp_path):
    host = make_host(tmp_path, installed=["systemctl"])
    assert detect(cat, "net.firewall_off", make_scan(host)).partial
    host.privileged = FakePrivileged(firewall={"nft_tables": 1, "nft_rules": 12, "nft_input_filters": 1})
    assert detect(cat, "net.firewall_off", make_scan(host)).status is Status.PASS
    # Docker's or libvirt's NAT and forward rules filter nothing coming in
    host.privileged = FakePrivileged(firewall={"nft_tables": 3, "nft_rules": 40, "nft_input_filters": 0})
    assert detect(cat, "net.firewall_off", make_scan(host)).status is Status.FAIL


DOCKER_ONLY = """table ip nat {
\tchain POSTROUTING {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\tip saddr 172.17.0.0/16 oifname != "docker0" counter masquerade
\t}
}
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t}
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t\tcounter jump DOCKER-USER
\t}
}
"""
UFW_LIKE = """table ip filter {
\tchain ufw-user-input {
\t\ttcp dport 22 counter accept
\t}
\tchain INPUT {
\t\ttype filter hook input priority filter; policy drop;
\t\tcounter jump ufw-user-input
\t}
}
table inet firewalld {
\tchain filter_INPUT {
\t\ttype filter hook input priority filter + 10; policy accept;
\t\treject with icmpx admin-prohibited
\t}
}
"""


def test_nft_input_filters():
    from daprivacyscanner.helper import nft_input_filters
    assert nft_input_filters(DOCKER_ONLY) == 0 and nft_input_filters(UFW_LIKE) == 2 and nft_input_filters("") == 0


# ------------------------------------------------------------------ Wi-Fi

NM_LIST = ("nmcli", "-t", "-f", "UUID,TYPE", "connection", "show")


def nm(uuid, *fields):
    return ("nmcli", "-g", ",".join(fields), "connection", "show", uuid)


WIFI = {NM_LIST: "u1:802-11-wireless\nu2:802-11-wireless\nu3:802-3-ethernet\n",
        nm("u1", "connection.id", "802-11-wireless.cloned-mac-address"): "Home\n\n",
        nm("u2", "connection.id", "802-11-wireless.cloned-mac-address"): "Cafe\\: Free\nrandom\n"}


def test_mac_permanent(cat, tmp_path):
    o = detect(cat, "net.mac_permanent", make_scan(make_host(tmp_path, commands=WIFI)))
    assert o.status is Status.FAIL and o.summary.startswith("1 of 2")
    assert ev(o)["Cafe: Free"] == "random"


def test_mac_global_default(cat, tmp_path):
    host = make_host(tmp_path, commands={**WIFI, "NetworkManager --print-config":
                                         "[connection]\nwifi.cloned-mac-address=stable\n"})
    assert detect(cat, "net.mac_permanent", make_scan(host)).status is Status.PASS


def test_hidden_ssid(cat, tmp_path):
    host = make_host(tmp_path, commands={NM_LIST: "u1:802-11-wireless\n",
                                         nm("u1", "connection.id", "802-11-wireless.hidden"): "Office\nyes\n"})
    o = detect(cat, "net.hidden_ssid", make_scan(host))
    assert o.status is Status.FAIL and "Office" in o.summary


def test_no_wifi(cat, tmp_path):
    assert detect(cat, "net.mac_permanent", make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ names

def test_hostname_with_name(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": "alice-ThinkPad-T480\n"},
                     commands={"getent passwd alice": "alice:x:1000:1000:Alice Smith,,,:/home/alice:/bin/bash\n",
                               NM_LIST: "u1:802-3-ethernet\n", nm("u1", *SEND): "yes\nyes\n"})
    o = detect(cat, "net.hostname_broadcast", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Contains your name"] == "alice" and "DHCP" in o.summary


SEND = ("ipv4.dhcp-send-hostname", "ipv6.dhcp-send-hostname")


def test_hostname_over_dhcp_counts_only_what_runs_dhcp(cat, tmp_path):
    """A VPN app's WireGuard and dummy connections keep the default setting, but never run DHCP; the
    guide changes only Wi-Fi and Ethernet, so counting the others would leave the check failing after it."""
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": "alice-laptop\n"},
                     commands={NM_LIST: "u1:802-3-ethernet\nu2:wireguard\nu3:dummy\nu4:loopback\n",
                               nm("u1", *SEND): "no\nyes\n", nm("u2", *SEND): "yes\nyes\n",
                               nm("u3", *SEND): "yes\nyes\n", nm("u4", *SEND): "yes\nyes\n"})
    assert ev(detect(cat, "net.hostname_broadcast", make_scan(host)))[
        "Connections that send the hostname over DHCP"] == 1


def test_hostname_with_full_name_over_llmnr(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "as"}, files={"/proc/sys/kernel/hostname": "smiths-laptop\n"},
                     commands={"getent passwd as": "as:x:1000:1000:Alice Smith:/home/as:/bin/bash\n"})
    o = detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[Listener("udp", "0.0.0.0", 5355)]))
    assert o.status is Status.FAIL and "LLMNR" in o.summary


def test_generic_hostname(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": "fedora\n"})
    assert detect(cat, "net.hostname_broadcast", make_scan(host)).status is Status.PASS


def test_kdeconnect(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/77/comm": "kdeconnectd\n"},
                     home_files={".config/kdeconnect/trusted_devices": "[abc]\nname=Phone\n[def]\nname=Tablet\n"})
    o = detect(cat, "net.kdeconnect", make_scan(host, listeners=[Listener("udp", "*", 1716)]))
    assert o.status is Status.FAIL and ev(o)["Paired devices"] == 2


# ------------------------------------------------------------------ VPN and DNS

RESOLVECTL_LEAK = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (wlp0s20f3)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1

Link 5 (wg0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 10.2.0.1
        DNS Domain: ~.
"""
ROUTE = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nwg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n"


def vpn_host(tmp_path, resolvectl):
    return make_host(tmp_path, files={"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\nINTERFACE=wg0\n",
                                      "/sys/class/net/wlp0s20f3/uevent": "DEVTYPE=wlan\n", "/proc/net/route": ROUTE},
                     commands={"resolvectl status": resolvectl})


# the same, with "~." on the VPN's link: every query goes there and the Wi-Fi's DNS isn't asked (systemd-resolved(8))
RESOLVECTL_ROUTED = RESOLVECTL_LEAK
RESOLVECTL_LEAK = RESOLVECTL_LEAK.replace("        DNS Domain: ~.\n", "")


def test_vpn_dns_leak(cat, tmp_path):
    o = detect(cat, "net.vpn_leaks", make_scan(vpn_host(tmp_path, RESOLVECTL_LEAK)))
    assert o.status is Status.FAIL and "wlp0s20f3" in o.summary


def test_vpn_with_the_catch_all_routing_domain_doesnt_leak(cat, tmp_path):
    o = detect(cat, "net.vpn_leaks", make_scan(vpn_host(tmp_path, RESOLVECTL_ROUTED)))
    assert o.status is Status.PASS and ev(o)["Every lookup routed to"] == "wg0 (~.)"
    both = RESOLVECTL_ROUTED.replace("       DNS Servers: 192.168.1.1\n", "       DNS Servers: 192.168.1.1\n        DNS Domain: ~.\n")
    assert detect(cat, "net.vpn_leaks", make_scan(vpn_host(tmp_path / "b", both))).status is Status.FAIL


def test_vpn_without_leak(cat, tmp_path):
    fixed = RESOLVECTL_LEAK.replace("+DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\nCurrent DNS Server: 192",
                                    "-DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\nCurrent DNS Server: 192")
    assert detect(cat, "net.vpn_leaks", make_scan(vpn_host(tmp_path, fixed))).status is Status.PASS


def test_a_policy_routed_vpn_is_not_mistaken_for_a_split_tunnel(cat, tmp_path):
    """wg-quick's full tunnel: the main table's default route stays on Wi-Fi; a rule sends the rest to wg0."""
    host = make_host(tmp_path, files={"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\nINTERFACE=wg0\n",
                                      "/sys/class/net/wlp0s20f3/uevent": "DEVTYPE=wlan\n",
                                      "/proc/net/route": "Iface\tDestination\nwlp0s20f3\t00000000\t0101A8C0\n"},
                     commands={"resolvectl status": RESOLVECTL_LEAK,
                               "ip -4 route get 1.1.1.1": "1.1.1.1 dev wg0 table 51820 src 10.2.0.2 uid 1000 \n",
                               "ip -6 route get 2606:4700:4700::1111": "unreachable 2606:4700:4700::1111 dev lo\n"})
    o = detect(cat, "net.vpn_leaks", make_scan(host))
    assert o.status is Status.FAIL and "wlp0s20f3" in o.summary


def test_no_vpn(cat, tmp_path):
    assert detect(cat, "net.vpn_leaks", make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("resolvconf, resolvectl, procs, status", [
    ("nameserver 127.0.0.53\n", RESOLVECTL_LEAK, {}, Status.FAIL),
    ("nameserver 127.0.0.53\n", RESOLVECTL_LEAK.replace("-DNSOverTLS", "+DNSOverTLS"), {}, Status.PASS),
    ("nameserver 127.0.0.53\n", "Global\n  Protocols: DNSOverTLS=opportunistic\n", {}, Status.WARN),
    ("nameserver 127.0.0.1\n", "", {"/proc/9/comm": "dnscrypt-proxy\n"}, Status.PASS),
    ("nameserver 127.0.0.1\n", "", {"/proc/9/comm": "unbound\n"}, Status.UNKNOWN),      # recursive, plain DNS by default
    ("nameserver 192.168.1.1\n", "", {}, Status.FAIL),
])
def test_dns(cat, tmp_path, resolvconf, resolvectl, procs, status):
    host = make_host(tmp_path, files={"/etc/resolv.conf": resolvconf, **procs}, commands={"resolvectl status": resolvectl})
    assert detect(cat, "net.dns_unencrypted", make_scan(host)).status is status


@pytest.mark.parametrize("tempaddr, status", [("2", Status.PASS), ("0", Status.FAIL)])
def test_ipv6_privacy(cat, tmp_path, tempaddr, status):
    host = make_host(tmp_path, files={"/sys/class/net/enp1s0/device/vendor": "0x8086",
                                      "/sys/class/net/docker0/uevent": "DEVTYPE=bridge",
                                      "/proc/sys/net/ipv6/conf/enp1s0/use_tempaddr": tempaddr + "\n"})
    o = detect(cat, "net.ipv6_privacy", make_scan(host))
    assert o.status is status and "docker0 use_tempaddr" not in ev(o)


@pytest.mark.parametrize("show, status", [
    ("Controller 00:11:22:33:44:55 (public)\n\tAlias: alice-laptop\n\tPowered: yes\n\tDiscoverable: no\n", Status.FAIL),
    ("Controller 00:11:22:33:44:55 (public)\n\tAlias: laptop\n\tPowered: yes\n\tDiscoverable: yes\n", Status.FAIL),
    ("Controller 00:11:22:33:44:55 (public)\n\tAlias: laptop\n\tPowered: yes\n\tDiscoverable: no\n", Status.PASS),
    ("Controller 00:11:22:33:44:55 (public)\n\tAlias: laptop\n\tPowered: no\n\tDiscoverable: no\n", Status.PASS),
])
def test_bluetooth(cat, tmp_path, show, status):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/sys/class/bluetooth/hci0/uevent": ""},
                     commands={"systemctl is-active bluetooth": "active\n", "bluetoothctl show": show})
    assert detect(cat, "net.bluetooth", make_scan(host)).status is status


def test_connectivity_check(cat, tmp_path):
    host = make_host(tmp_path, commands={"NetworkManager --print-config":
                                         "[connectivity]\nuri=http://connectivity-check.ubuntu.com./\n"})
    o = detect(cat, "net.connectivity_check", make_scan(host))
    assert o.status is Status.FAIL and "connectivity-check.ubuntu.com." in o.summary
    host = make_host(tmp_path / "b", commands={"NetworkManager --print-config": "[connectivity]\nenabled=false\nuri=x\n"})
    assert detect(cat, "net.connectivity_check", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ exposed services behind a firewall

UFW_DENY = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
1714:1764/udp              ALLOW IN    Anywhere
OpenSSH                    ALLOW IN    192.168.1.0/24
1714:1764/udp (v6)         ALLOW IN    Anywhere (v6)
"""


def test_parse_ufw_status():
    r = network.parse_ufw_status(UFW_DENY)
    assert r.default_allows is False and r.unparsed == 0
    assert r.allows(22, "tcp") is True and r.allows(1720, "udp") is True and r.allows(1720, "tcp") is False
    assert r.allows(3389, "tcp") is False
    assert network.parse_ufw_status("Status: inactive\n") is None
    odd = network.parse_ufw_status(UFW_DENY.replace("OpenSSH", "Apache Full"))
    assert odd.allows(3389, "tcp") is None                             # an app profile it can't map


def test_parse_firewalld_zone():
    zone = ("FedoraWorkstation (default, active)\n  target: default\n  services: dhcpv6-client samba-client ssh\n"
            "  ports: 1025-65535/udp 1025-65535/tcp\n  rich rules:\n")
    r = network.parse_firewalld_zone(zone, {"ssh": ["22/tcp"], "dhcpv6-client": ["546/udp"], "samba-client": ["137/udp"]})
    assert r.allows(22, "tcp") and r.allows(3389, "tcp") and r.allows(631, "tcp") is False
    assert network.parse_firewalld_zone("public\n  target: ACCEPT\n", {}).allows(631, "tcp") is True


def ufw_host(tmp_path):
    return make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=yes\n"},
                     commands={("systemctl", "is-active", "ufw"): "active\n"})


def test_exposed_services_all_blocked_by_ufw(cat, tmp_path):
    host = ufw_host(tmp_path)
    host.privileged = FakePrivileged(ufw=UFW_DENY.replace("OpenSSH                    ALLOW IN    192.168.1.0/24\n", ""))
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=MINT_SS, exposed_services=exposed()))
    assert o.status is Status.WARN and o.findings == {"firewall_blocks_exposed": True}
    assert "22/tcp" in ev(o)["Blocked by ufw"] and "3389/tcp" in ev(o)["Blocked by ufw"]
    assert any(n.title == "ufw blocks 2 of them" for n in o.notes)


def test_exposed_services_some_let_through(cat, tmp_path):
    host = ufw_host(tmp_path)
    host.privileged = FakePrivileged(ufw=UFW_DENY)
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=MINT_SS, exposed_services=exposed()))
    assert o.status is Status.FAIL and o.findings == {"firewall_blocks_exposed": False}
    assert o.summary.startswith("1 of 2 services")


def test_exposed_services_firewall_rules_unreadable(cat, tmp_path):
    o = detect(cat, "net.exposed_services", make_scan(ufw_host(tmp_path), listeners=MINT_SS, exposed_services=exposed()))
    assert o.status is Status.FAIL and o.findings == {"firewall_blocks_exposed": None}
    assert any(n.kind == "limitation" and "administrator access" in n.text for n in o.notes)


def test_exposed_services_severity_follows_the_firewall(cat, tmp_path):
    from daprivacyscanner.runner import Runner

    host = ufw_host(tmp_path)
    host.privileged = FakePrivileged(ufw=UFW_DENY.replace("OpenSSH                    ALLOW IN    192.168.1.0/24\n", ""))
    host.runner.outputs[("ss", "-tulpnH")] = CommandResult((), 0, sample("ss/mint-22.txt"))
    r = Runner(cat, host).scan(only=["net.exposed_services"]).results["net.exposed_services"]
    assert (r.status.value, r.effective_severity) == ("warn", 2)    # 4 behind the firewall, a risk 2 lower
