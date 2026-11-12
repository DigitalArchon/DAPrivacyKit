"""Where lookups and IPv6 go with a VPN up (net.vpn_leaks), and whether the system's DNS is encrypted
(net.dns_unencrypted): a pass claims only what was read."""

from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from test_checks_network import RESOLVECTL_LEAK, RESOLVECTL_ROUTED, ROUTE

V4_TUNNEL = "1.1.1.1 dev wg0 table 51820 src 10.2.0.2 uid 1000\n"
V6_LAN = "2606:4700:4700::1111 from :: via fe80::1 dev wlp0s20f3 proto ra src 2001:db8::5 metric 600 pref medium\n"
IF_INET6 = "20010db8000000000000000000000005 03 40 00 00 wlp0s20f3\n"


def tunnel_host(tmp_path, resolvectl=RESOLVECTL_ROUTED, files=None, commands=None, iface="wg0"):
    return make_host(tmp_path, files={f"/sys/class/net/{iface}/uevent": "DEVTYPE=wireguard\n",
                                      "/sys/class/net/wlp0s20f3/uevent": "DEVTYPE=wlan\n", "/proc/net/route": ROUTE,
                                      **(files or {})},
                     commands={"resolvectl status": resolvectl,
                               "ip -4 route get 1.1.1.1": V4_TUNNEL.replace("wg0", iface), **(commands or {})})


def test_an_ipv4_only_tunnel_on_a_dual_stack_network_is_a_leak(cat, tmp_path):
    """AllowedIPs = 0.0.0.0/0 alone: IPv6 leaves by the Wi-Fi, visible offline in the route lookup; it passed on DNS."""
    host = tunnel_host(tmp_path, files={"/proc/net/if_inet6": IF_INET6},
                       commands={"ip -6 route get 2606:4700:4700::1111": V6_LAN})
    o = detect(cat, "net.vpn_leaks", make_scan(host))
    assert o.status is Status.FAIL and "IPv6 traffic leaves by wlp0s20f3" in o.summary
    assert ev(o)["IPv6 internet traffic leaves by"] == "wlp0s20f3"


def test_without_a_global_ipv6_address_the_route_alone_is_no_leak(cat, tmp_path):
    host = tunnel_host(tmp_path, commands={"ip -6 route get 2606:4700:4700::1111": V6_LAN})
    assert detect(cat, "net.vpn_leaks", make_scan(host)).status is Status.PASS


def test_a_tunnels_dns_server_on_the_lan_is_asked_outside_it(cat, tmp_path):
    """A WireGuard file's DNS = 192.168.1.1: systemd-resolved puts it on wg0, with ~., and the lookups still go out by
    the Wi-Fi, where the router answers them."""
    lan_dns = RESOLVECTL_ROUTED.replace("DNS Servers: 10.2.0.1", "DNS Servers: 192.168.1.1")
    host = tunnel_host(tmp_path, lan_dns, commands={"ip route get 192.168.1.1": "192.168.1.1 dev wlp0s20f3 src 192.168.1.20\n"})
    o = detect(cat, "net.vpn_leaks", make_scan(host))
    assert o.status is Status.FAIL and "192.168.1.1 (through wlp0s20f3)" in o.summary
    from daprivacyscanner.checks.network import dns_in_tunnel
    assert dns_in_tunnel(host) == []


MULLVAD_LAN_DNS = RESOLVECTL_ROUTED.replace("Link 5 (wg0)", "Link 5 (wg0-mullvad)").replace(
    "DNS Servers: 10.2.0.1", "DNS Servers: 192.168.1.5")


def mullvad(tmp_path, resolvectl, **kw):
    return tunnel_host(tmp_path, resolvectl, iface="wg0-mullvad", files={"/proc/321/comm": "mullvad-daemon\n",
                                                                        **kw.pop("files", {})},
                       commands={"mullvad status": "Connected\n", "mullvad lockdown-mode get": "off\n",
                                 **kw.pop("commands", {})})


def test_mullvad_with_a_custom_dns_server_on_the_lan_isnt_a_pass(cat, tmp_path):
    """Mullvad's app lets lookups out to the server it was set to, a Pi-hole on the LAN included, outside the tunnel
    (its own leak_protection text says so): the unconditional pass said it rejected them."""
    host = mullvad(tmp_path, MULLVAD_LAN_DNS,
                   commands={"ip route get 192.168.1.5": "192.168.1.5 dev wlp0s20f3 src 192.168.1.20\n"})
    o = detect(cat, "net.vpn_leaks", make_scan(host))
    assert o.status is Status.WARN and "192.168.1.5 (through wlp0s20f3)" in o.summary
    assert "rejects" not in o.summary


def test_mullvad_blocks_ipv6_outside_its_tunnel(cat, tmp_path):
    host = mullvad(tmp_path, RESOLVECTL_ROUTED.replace("Link 5 (wg0)", "Link 5 (wg0-mullvad)"),
                   files={"/proc/net/if_inet6": IF_INET6}, commands={"ip -6 route get 2606:4700:4700::1111": V6_LAN})
    o = detect(cat, "net.vpn_leaks", make_scan(host))
    assert o.status is Status.PASS and any(n.title == "Mullvad VPN blocks IPv6 outside the tunnel" for n in o.notes)


def test_an_ipsec_vpn_is_not_no_vpn(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/77/comm": "charon-systemd\n"})
    o = detect(cat, "net.vpn_leaks", make_scan(host))
    assert o.status is Status.UNKNOWN and "IPsec" in o.summary


# ------------------------------------------------------------------ encrypted DNS


def test_dot_on_the_vpns_link_doesnt_cover_the_wifis_lookups(cat, tmp_path):
    """DNS over TLS on one link passed while the link with the default route sent lookups in plain DNS."""
    mixed = RESOLVECTL_LEAK.replace("Link 5 (wg0)\n    Current Scopes: DNS\n         Protocols: +DefaultRoute -LLMNR -mDNS "
                                    "-DNSOverTLS", "Link 5 (wg0)\n    Current Scopes: DNS\n         Protocols: "
                                    "+DefaultRoute -LLMNR -mDNS +DNSOverTLS")
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"},
                     commands={"resolvectl status": mixed})
    o = detect(cat, "net.dns_unencrypted", make_scan(host))
    assert o.status is Status.FAIL and "wlp0s20f3: no" in ev(o)["systemd-resolved DNSOverTLS"]


def test_dot_on_the_link_every_lookup_goes_to_passes(cat, tmp_path):
    routed = RESOLVECTL_ROUTED.replace("Link 5 (wg0)\n    Current Scopes: DNS\n         Protocols: +DefaultRoute -LLMNR "
                                       "-mDNS -DNSOverTLS", "Link 5 (wg0)\n    Current Scopes: DNS\n         Protocols: "
                                       "+DefaultRoute -LLMNR -mDNS +DNSOverTLS")
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"}, commands={"resolvectl status": routed})
    assert detect(cat, "net.dns_unencrypted", make_scan(host)).status is Status.PASS


def local(tmp_path, procs, cmdline=None):
    files = {"/etc/resolv.conf": "nameserver 127.0.0.1\n"}
    for pid, name in procs.items():
        files[f"/proc/{pid}/comm"] = name + "\n"
    if cmdline:
        files[f"/proc/{next(iter(procs))}/cmdline"] = "\0".join(cmdline)
    return make_host(tmp_path, files=files)


def test_a_cloudflared_tunnel_beside_dnsmasq_is_no_encrypting_resolver(cat, tmp_path):
    host = local(tmp_path, {"9": "cloudflared", "10": "dnsmasq"}, ["cloudflared", "tunnel", "run"])
    o = detect(cat, "net.dns_unencrypted", make_scan(host))
    assert o.status is Status.UNKNOWN and "dnsmasq" in o.summary


def test_cloudflared_as_the_only_dns_proxy_passes(cat, tmp_path):
    host = local(tmp_path, {"9": "cloudflared"}, ["cloudflared", "proxy-dns", "--port", "53"])
    o = detect(cat, "net.dns_unencrypted", make_scan(host))
    assert o.status is Status.PASS and "the only DNS server running here" in o.summary
    host = local(tmp_path / "t", {"9": "cloudflared"}, ["cloudflared", "tunnel", "run"])
    assert detect(cat, "net.dns_unencrypted", make_scan(host)).status is Status.UNKNOWN


def test_a_dockerised_pihole_beside_stubby_is_unknown(cat, tmp_path):
    host = local(tmp_path, {"9": "stubby", "10": "docker-proxy"})
    assert detect(cat, "net.dns_unencrypted", make_scan(host)).status is Status.UNKNOWN


def test_the_program_listening_there_is_believed(cat, tmp_path):
    from daprivacyscanner.network import Listener
    host = local(tmp_path, {"9": "stubby", "10": "dnsmasq"})
    o = detect(cat, "net.dns_unencrypted", make_scan(host, listeners=[Listener("udp", "127.0.0.1", 53, "dnsmasq")]))
    assert o.status is Status.UNKNOWN and "dnsmasq" in o.summary
    o = detect(cat, "net.dns_unencrypted", make_scan(host, listeners=[Listener("udp", "127.0.0.1", 53, "stubby")]))
    assert o.status is Status.PASS
