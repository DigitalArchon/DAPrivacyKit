"""Try an app's packets (the review of 2026-11-12): every IP packet a program sends is counted for its destination.
Only IPv6 next header 6 or 17 was: a Fragment header (any datagram above the link's size) or a Routing header
(anyone may add one) hid where the packet went, and pasta may send it on."""

from __future__ import annotations

import ipaddress
import struct

from daprivacyscanner.tools import pcap

from test_trial import eth, ip4, tcp, udp

ME4, ME6 = "10.0.2.15", "fd00::15"


def ip6(src, dst, nxt, body):
    return struct.pack(">IHBB", 0x60000000, len(body), nxt, 64) + ipaddress.ip_address(src).packed + \
        ipaddress.ip_address(dst).packed + body


def eth6(payload):
    return b"\x02" * 6 + b"\x04" * 6 + b"\x86\xdd" + payload


def frag4(src, dst, proto, body, ident, offset, more):
    fl = (0x2000 if more else 0) | (offset // 8)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, fl, 64, proto, 0, ipaddress.ip_address(src).packed,
                       ipaddress.ip_address(dst).packed) + body


def feed(packets) -> dict:
    stream = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    stream += b"".join(struct.pack("<IIII", 0, 0, len(p), len(p)) + p for p in packets)
    f = pcap.Flows(forwarder="169.254.0.1")
    f.feed(stream)
    return {h["host"]: h for h in f.result()["hosts"]}


def test_an_ipv6_datagram_in_fragments_names_its_destination():
    data = b"z" * 3000
    first = udp(7000, 9999, data)[:1200]                     # the UDP header and the start of the data
    frag1 = struct.pack(">BBHI", 17, 0, 0x0001, 77) + first                  # offset 0, more to come
    frag2 = struct.pack(">BBHI", 17, 0, (1200 & 0xFFF8) | 0, 77) + udp(7000, 9999, data)[1200:]
    hosts = feed([eth6(ip6(ME6, "2001:db8::99", 44, frag1)), eth6(ip6(ME6, "2001:db8::99", 44, frag2))])
    h = hosts["2001:db8::99"]
    assert h["ports"] == ["9999/udp"] and h["connections"] == 1 and h["sent"] == 3000


def test_extension_headers_are_walked_to_the_transports():
    hop = struct.pack(">BB6x", 43, 0)                                         # hop-by-hop options, then a routing header
    routing = struct.pack(">BBBB4x", 6, 2, 4, 1) + ipaddress.ip_address("2001:db8::bad").packed
    body = hop + routing + tcp(5000, 443, 0x02)
    hosts = feed([eth6(ip6(ME6, "2001:db8::1", 0, body))])
    assert hosts["2001:db8::1"]["ports"] == ["443"]


def test_ipv4_fragments_and_other_protocols_are_counted():
    data = b"q" * 2000
    whole = udp(7001, 4444, data)
    pkts = [eth(frag4(ME4, "198.51.100.20", 17, whole[:1480], 5, 0, True)),
            eth(frag4(ME4, "198.51.100.20", 17, whole[1480:], 5, 1480, False)),
            eth(frag4(ME4, "198.51.100.30", 17, b"w" * 500, 9, 1480, False)),         # its first piece never seen
            eth(ip4(ME4, "203.0.113.5", 1, b"\x08\x00" + b"\0" * 30)),                # a ping
            eth(ip4(ME4, "203.0.113.6", 132, b"s" * 40))]                             # SCTP
    hosts = feed(pkts)
    assert hosts["198.51.100.20"]["ports"] == ["4444/udp"] and hosts["198.51.100.20"]["sent"] == 2000
    assert hosts["198.51.100.30"]["ports"] == ["fragments"] and hosts["198.51.100.30"]["sent"] == 500
    assert hosts["203.0.113.5"]["ports"] == ["icmp"] and hosts["203.0.113.6"]["ports"] == ["sctp"]
    # a non-first IPv4 fragment's payload was read as a TCP or UDP header: no made-up ports
    assert all(p in ("4444/udp", "fragments", "icmp", "sctp") for h in hosts.values() for p in h["ports"])


def test_the_links_own_traffic_and_replies_from_outside_arent_hosts():
    nd = b"\x87\x00" + b"\0" * 22                                           # a neighbour solicitation
    reply = b"\x00\x00" + b"\0" * 30                                         # an echo reply to nothing it sent
    hosts = feed([eth(ip4(ME4, "169.254.0.1", 17, udp(4000, 53, b"\0" * 12))),
                  eth6(ip6(ME6, "ff02::1:ff00:1", 58, nd)),
                  eth(ip4("203.0.113.77", ME4, 1, reply))])
    assert hosts == {}


def test_a_hosts_ports_are_capped():
    pkts = [eth(ip4(ME4, "203.0.113.8", 6, tcp(5000 + p, p, 0x02))) for p in range(1, 200)]
    h = feed(pkts)["203.0.113.8"]
    assert len(h["ports"]) == pcap.PORTS_MAX and h["more_ports"] and h["connections"] == 199
