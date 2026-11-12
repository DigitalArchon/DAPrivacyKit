"""Which hosts a trial's program contacted (docs/TECHNICAL.md, Tools: Try an app): read from the packets pasta
passes for the sandbox's network namespace (`pasta --pcap`, into a pipe the app reads as they come), and kept
only as sums: per host, how many connections, to which ports, how many bytes each way. No packet and no payload
is kept; nothing is written to the disk.

Each connection is named by what the program itself said or asked, in this order: the name in its first message
(a TLS connection's SNI, what a program using DNS over HTTPS still sends, or an HTTP request's Host line), else the
DNS answer that had given the address it connected to (the sandbox's DNS goes through pasta's forwarder, in plain
text on this link, over UDP or TCP), else the address. Per connection, not per address: one address serves many
sites (a CDN's, Cloudflare's), and two connections to it naming two sites are two hosts (found in the 2026-10-17
review: the last DNS answer for an address had named every connection to it). Connections with the same name are
summed up as one host, with the servers' addresses. Names looked up and never used are listed apart. DNS sent to
pasta's forwarder is the sandbox's own resolver, never a host; DNS sent anywhere else goes to a server of the
program's own choosing, which is listed, and whose answers name nothing: a program could have its own server say
any name was any address. A name the program gave when connecting that the resolver never gave for that address is
only the program's word, and such a host is kept apart, named_by "program" (the review of 2026-11-04: everything
sent to one server of its own could be listed as dns.google and github.com). A TCP connection is counted once,
however often its first packet is sent again (one lookup hanging on a server that didn't answer was counted as five
connections). Every IP packet the program sends counts for its destination: IPv6's extension headers are walked to
the transport's, a fragmented datagram's later pieces go with its first, and anything else (ICMP, SCTP, pieces whose
first wasn't seen) is listed under its protocol's name (the review of 2026-11-12: only TCP and UDP right after the IP
header were counted, so a Fragment or Routing header hid where a packet went). What can't be told: what was sent (it
is encrypted), and a name hidden by Encrypted Client Hello. Standard library only."""

from __future__ import annotations

import ipaddress
import struct
import threading

MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
ETHERNET = 1
CONNS_MAX = 20000
HOSTS_MAX = 2000
NAMES_MAX = 5000
ADDRESSES_MAX = 8                       # a host's addresses kept to show; more are said as more
PACKET_MAX = 262144 + 64
STREAM_MAX = 70000                      # DNS over TCP: what is kept of a message not complete yet (one is 65537 at most)
# DNS over TCP read at once (each way of a connection a stream), and the bytes held for all of them: the program's own
# traffic must not grow what is kept without a bound (the review of 2026-11-04: 3,000 connections that never finished a
# message held 171 MB, never dropped). A lookup past these isn't read, and its address is named by itself.
STREAMS_MAX = 64
BUFFERED_MAX = 1 << 20
PORTS_MAX = 32                          # a host's ports kept to show; more are said as more (one per packet otherwise)
FRAGMENTS_MAX = 1024                    # fragmented datagrams followed at once, to give later pieces to their connection
LOCAL_MAX = 16                          # the sandbox's own addresses, learnt from what it sends
# IPv6 extension headers that come before the transport's (RFC 8200, 4; 7045): hop-by-hop, routing, fragment,
# destination options, authentication, mobility, host identity, shim6
IPV6_EXTENSIONS = {0, 43, 44, 60, 51, 135, 139, 140}
PROTO_NAMES = {1: "icmp", 2: "igmp", 58: "icmpv6", 132: "sctp", 136: "udplite", 47: "gre", 50: "esp", 51: "ah", 33: "dccp"}


def _name(data: bytes, at: int, depth: int = 0) -> tuple[str, int]:
    """A DNS name at `at` (following compression pointers): (the name, where reading goes on)."""
    labels, end = [], None
    for _ in range(64):
        if at >= len(data):
            raise ValueError
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if at + 1 >= len(data) or depth > 8:
                raise ValueError
            if end is None:
                end = at + 2
            at, depth = ((n & 0x3F) << 8) | data[at + 1], depth + 1
            continue
        labels.append(data[at + 1:at + 1 + n].decode("ascii", "replace"))
        at += 1 + n
    return ".".join(labels).lower(), end if end is not None else at


def dns(data: bytes) -> tuple[list[str], dict[str, str]]:
    """A DNS message's questions and the addresses it answers with: ([names asked], {address: the name asked})."""
    asked: list[str] = []
    answers: dict[str, str] = {}
    try:
        _id, flags, qd, an = struct.unpack_from(">HHHH", data, 0)
        at = 12
        for _ in range(min(qd, 8)):
            name, at = _name(data, at)
            at += 4
            if name:
                asked.append(name)
        if flags & 0x8000:
            for _ in range(min(an, 64)):
                _owner, at = _name(data, at)
                kind, _cls, _ttl, n = struct.unpack_from(">HHIH", data, at)
                at += 10
                if kind in (1, 28) and n in (4, 16) and at + n <= len(data) and asked:
                    answers[str(ipaddress.ip_address(data[at:at + n]))] = asked[0]
                at += n
    except (struct.error, ValueError, IndexError):
        pass
    return asked, answers


def sni(data: bytes) -> str | None:
    """The server's name in a TLS ClientHello, or None."""
    try:
        if len(data) < 48 or data[0] != 0x16 or data[5] != 0x01:
            return None
        at = 5 + 4 + 2 + 32
        at += 1 + data[at]                                   # session id
        at += 2 + struct.unpack_from(">H", data, at)[0]      # cipher suites
        at += 1 + data[at]                                   # compression
        end = at + 2 + struct.unpack_from(">H", data, at)[0]
        at += 2
        while at + 4 <= min(end, len(data)):
            kind, n = struct.unpack_from(">HH", data, at)
            at += 4
            if kind == 0 and n >= 5:
                size = struct.unpack_from(">H", data, at + 3)[0]
                name = data[at + 5:at + 5 + size].decode("ascii", "replace").lower()
                return name if name and all(c.isalnum() or c in "-._" for c in name) else None
            at += n
    except (struct.error, IndexError):
        pass
    return None


def http_host(data: bytes) -> str | None:
    if not data[:8].split(b" ")[0] in (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT"):
        return None
    for line in data[:2048].split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            name = line[5:].strip().decode("ascii", "replace").lower().rsplit(":", 1)[0]
            return name if name and all(c.isalnum() or c in "-._[]:" for c in name) else None
    return None


class Flows:
    """Fed a pcap stream piece by piece (feed), it sums up who was contacted (result). `forwarder`: the address of the
    sandbox's own DNS resolver (pasta's forwarder), whose traffic is lookups, never a host contacted; None takes every
    DNS server for the sandbox's own."""

    def __init__(self, forwarder: str | None = None):
        self.forwarder = forwarder
        self.buf = bytearray()
        self.order: str | None = None
        self.link = ETHERNET
        self.names: dict[str, str] = {}                 # address -> the name whose lookup last gave it
        self.gave: set[tuple[str, str]] = set()         # (address, name): every answer of the sandbox's resolver
        self.asked: dict[str, int] = {}                 # names looked up -> how often
        self.conns: dict[tuple, dict] = {}              # (src, sport, dst, dport, proto) -> that connection's sums
        self.folded: dict[tuple, dict] = {}             # connections the table had no more room for, summed by host
        self.used: set[str] = set()                     # the names looked up that those were made under (DNS, SNI, Host)
        self.streams: dict[tuple, list] = {}            # DNS over TCP, each way: [the next sequence number, bytes]
        self.fragments: dict[tuple, tuple] = {}         # (src, dst, IP id) -> the connection its first piece was for
        self.local: set[str] = set()                    # the sandbox's own addresses, seen sending
        self.packets = self.broken = self.left_out = 0
        self.stopped = False                            # the reader stopped watching partway (PipeReader): said
        self.lock = threading.Lock()                    # fed by the reader thread, summed up by the page's requests

    def feed(self, data: bytes) -> None:
        with self.lock:
            self._feed(data)

    def _feed(self, data: bytes) -> None:
        self.buf += data
        if self.order is None:
            if len(self.buf) < 24:
                return
            self.order = MAGICS.get(bytes(self.buf[:4]))
            if self.order is None:
                self.broken += 1
                self.buf.clear()
                self.order = ""
                return
            self.link = struct.unpack_from(self.order + "I", self.buf, 20)[0]
            del self.buf[:24]
        if not self.order:
            self.buf.clear()
            return
        at, size = 0, len(self.buf)
        while at + 16 <= size:
            n = struct.unpack_from(self.order + "I", self.buf, at + 8)[0]
            if n > PACKET_MAX:                              # not a packet header: the stream is out of step
                self.broken += 1
                self.order = ""
                self.buf.clear()
                return
            if at + 16 + n > size:
                break
            self._packet(bytes(self.buf[at + 16:at + 16 + n]))
            at += 16 + n
        del self.buf[:at]

    def _packet(self, p: bytes) -> None:
        self.packets += 1
        if self.link != ETHERNET or len(p) < 14:
            return
        kind, at = struct.unpack_from(">H", p, 12)[0], 14
        if kind == 0x8100 and len(p) >= 18:
            kind, at = struct.unpack_from(">H", p, 16)[0], 18
        try:
            frag = None                                     # (IP id, offset, more to come) of a fragmented datagram
            if kind == 0x0800:
                ihl = (p[at] & 0x0F) * 4
                total, ident, fl = struct.unpack_from(">HHH", p, at + 2)
                proto, raw_src, raw_dst = p[at + 9], p[at + 12:at + 16], p[at + 16:at + 20]
                body = p[at + ihl:at + total] if total >= ihl else b""
                if fl & 0x3FFF:                             # more fragments, or not the first
                    frag = (ident, (fl & 0x1FFF) * 8, bool(fl & 0x2000))
            elif kind == 0x86DD:
                proto, raw_src, raw_dst = p[at + 6], p[at + 8:at + 24], p[at + 24:at + 40]
                body = p[at + 40:at + 40 + struct.unpack_from(">H", p, at + 4)[0]]
                # the extension headers before the transport's: a Fragment header (any datagram larger than the link
                # takes, which pasta reassembles and sends on) or a Routing header (anyone may add one) hid the
                # packet's destination from the report
                for _ in range(16):
                    if proto not in IPV6_EXTENSIONS or len(body) < 8:
                        break
                    if proto == 44:
                        off = struct.unpack_from(">H", body, 2)[0]
                        frag = (struct.unpack_from(">I", body, 4)[0], off & 0xFFF8, bool(off & 1))
                        proto, body = body[0], body[8:]
                    else:
                        size = (body[1] + 2) * 4 if proto == 51 else (body[1] + 1) * 8
                        proto, body = body[0], body[size:]
            else:
                return
            src, dst = str(ipaddress.ip_address(raw_src)), str(ipaddress.ip_address(raw_dst))
            if frag is not None and frag[1]:                # a later piece: no ports in it
                self._piece(src, dst, frag, proto, len(body))
                return
            if proto == 6 and len(body) >= 20:
                sport, dport, seq = struct.unpack_from(">HHI", body, 0)
                flags, data = body[13], body[(body[12] >> 4) * 4:]
                self._tcp(src, sport, dst, dport, flags, seq, data)
                key = (src, sport, dst, dport, "tcp")
            elif proto == 17 and len(body) >= 8:
                sport, dport = struct.unpack_from(">HH", body, 0)
                self._udp(src, sport, dst, dport, body[8:])
                key = (src, sport, dst, dport, "udp")
            else:
                # anything else a program sends is still to somewhere: ICMP, SCTP, a protocol pasta drops or not
                key = self._other(src, dst, PROTO_NAMES.get(proto, f"protocol {proto}"), len(body),
                                  body[0] if body else None)
            if frag is not None:                            # its first piece: the rest go with it
                if len(self.fragments) >= FRAGMENTS_MAX:
                    del self.fragments[next(iter(self.fragments))]
                self.fragments[(src, dst, frag[0])] = key
        except (IndexError, struct.error, ValueError):
            self.broken += 1

    # ------------------------------------------------------------------ lookups

    def _questions(self, data: bytes) -> None:
        for name in dns(data)[0]:
            if name in self.asked or len(self.asked) < NAMES_MAX:
                self.asked[name] = self.asked.get(name, 0) + 1

    def _answers(self, data: bytes) -> None:
        """The sandbox's own resolver's answers (only its: _udp, _tcp), which name the addresses they give."""
        for address, name in dns(data)[1].items():
            if address in self.names or len(self.names) < NAMES_MAX:
                self.names[address] = name
            if (address, name) in self.gave or len(self.gave) < NAMES_MAX:
                self.gave.add((address, name))

    def _resolver(self, address: str) -> bool:
        """Whether DNS to or from `address` is the sandbox's own lookups (pasta's forwarder), not a host contacted."""
        return self.forwarder is None or address == self.forwarder

    def _dns_stream(self, key: tuple, seq: int, data: bytes, answers: bool) -> None:
        """DNS over TCP, one way: each message after a two-byte length, possibly over several segments. Only the
        segment that comes next in order is taken: one sent again is skipped."""
        st = self.streams.get(key)
        if st is None or not data or seq != st[0]:
            return
        st[0] = (seq + len(data)) & 0xFFFFFFFF
        st[1] += data
        while len(st[1]) >= 2:
            n = struct.unpack_from(">H", st[1], 0)[0]
            if len(st[1]) < 2 + n:
                break
            msg = bytes(st[1][2:2 + n])
            del st[1][:2 + n]
            (self._answers if answers else self._questions)(msg)
        # not DNS after all, or more held than lookups ever need: that way of the connection isn't read any more
        if len(st[1]) > STREAM_MAX or sum(len(s[1]) for s in self.streams.values()) > BUFFERED_MAX:
            del self.streams[key]

    def _stream(self, key: tuple, seq: int) -> None:
        """A way of a DNS-over-TCP connection to read, from the sequence number `seq` on, while there is room."""
        if key in self.streams or len(self.streams) < STREAMS_MAX:
            self.streams[key] = [seq & 0xFFFFFFFF, bytearray()]

    # ------------------------------------------------------------------ connections

    def _sender(self, address: str) -> None:
        if len(self.local) < LOCAL_MAX:
            self.local.add(address)

    def _other(self, src: str, dst: str, proto: str, size: int, kind: int | None = None) -> tuple:
        """A packet that isn't TCP or UDP (or whose ports can't be read): still sent somewhere, so it is counted for
        its destination, under its protocol's name. IPv6's neighbour discovery and multicast listener reports are the
        link's own; something unasked for from outside isn't the program's. Returns the key it is counted under."""
        out, back = (src, 0, dst, 0, proto), (dst, 0, src, 0, proto)
        if proto == "icmpv6" and kind in (130, 131, 132, 133, 134, 135, 136, 137, 143) or proto == "igmp":
            return out
        c = self.conns.get(back)
        if c is not None:
            c["received"] += size
            return back
        if dst in self.local and src not in self.local:
            return back
        self._sender(src)
        c = self.conns.get(out) or self._open(out, dst, 0, proto)
        c["sent"] += size
        return out

    def _piece(self, src: str, dst: str, frag: tuple, proto: int, size: int) -> None:
        """A later piece of a fragmented datagram: counted with the connection its first piece was for. One whose
        first piece wasn't seen goes to its destination as "fragments"; one whose first piece was a lookup, nowhere."""
        key = self.fragments.get((src, dst, frag[0]))
        if key is None:
            self._other(src, dst, "fragments", size)
            return
        rev = (key[2], key[3], key[0], key[1], key[4])
        stored = key if key in self.conns else rev if rev in self.conns else None
        if stored is not None:
            self.conns[stored]["sent" if stored[0] == src else "received"] += size

    def _open(self, key: tuple, address: str, port: int, proto: str, isn: int | None = None) -> dict:
        if len(self.conns) >= CONNS_MAX:
            self._fold()
        c = self.conns[key] = {"address": address, "port": port, "proto": proto, "dns": self.names.get(address),
                               "said": None, "sent": 0, "received": 0, "closed": False, "isn": isn}
        return c

    def _fold(self) -> None:
        """The table is full: the older half of the connections are summed up by name and dropped (what still comes
        for one of them isn't counted)."""
        for key in list(self.conns)[:CONNS_MAX // 2]:
            self._retire(key)

    def _retire(self, key: tuple) -> None:
        c = self.conns.pop(key)
        # only names looked up: `used` leaves them out of those looked up and never used, and kept every name a
        # connection gave (100,000 TLS names of the program's own left 80,000 here)
        self.used.update(n for n in (c["said"], c["dns"]) if n and n in self.asked)
        if not self._add(self.folded, c):
            self.left_out += 1

    def _add(self, merged: dict[tuple, dict], c: dict) -> bool:
        """Adds the connection `c` to the hosts in `merged`, by its name; False when there is no room for another. A
        name it gave when connecting that the sandbox's resolver never gave for its address is the program's word only
        ("program"): a host apart from one the resolver named so, which can't then be passed off as it."""
        known = c["dns"] or self.names.get(c["address"])
        said = c["said"]
        how = ("tls" if said in (known, c["dns"]) or (c["address"], said) in self.gave else "program") if said \
            else "dns" if known else "address"
        name = said or known or c["address"]
        m = merged.get((name, how == "program"))
        if m is None:
            if len(merged) >= HOSTS_MAX:
                return False
            m = merged[(name, how == "program")] = {"host": name, "named_by": how, "addresses": set(),
                                                    "more_addresses": False, "ports": set(), "more_ports": False,
                                                    "connections": 0, "sent": 0, "received": 0}
        if c["address"] in m["addresses"] or len(m["addresses"]) < ADDRESSES_MAX:
            m["addresses"].add(c["address"])
        else:
            m["more_addresses"] = True
        port = str(c["port"]) if c["proto"] == "tcp" else f"{c['port']}/udp" if c["proto"] == "udp" else c["proto"]
        if port in m["ports"] or len(m["ports"]) < PORTS_MAX:          # a scan of every port: one each, unbounded
            m["ports"].add(port)
        else:
            m["more_ports"] = True
        m["connections"] += 1
        m["sent"] += c["sent"]
        m["received"] += c["received"]
        return True

    def _tcp(self, src: str, sport: int, dst: str, dport: int, flags: int, seq: int, data: bytes) -> None:
        out, back = (src, sport, dst, dport, "tcp"), (dst, dport, src, sport, "tcp")
        if flags & 0x02 and not flags & 0x10:               # SYN: the program connects out
            self._sender(src)
            c = self.conns.get(out)
            if c is not None and (not c["closed"] or seq == c["isn"]):
                # the same SYN sent again, its first sequence number the same: the same attempt, also after the
                # RST pasta answers each with while its own connection to the server waits (seen on Mint 22.3)
                c["closed"] = False
                if dport == 53 and out not in self.streams:  # its questions' way, dropped with that RST
                    self._stream(out, seq + 1)
                return
            if c is not None:                               # these ports used again: the earlier one is summed up
                self._retire(out)
            if dport == 53:                                 # DNS over TCP: its questions are read
                self._stream(out, seq + 1)
                if self._resolver(dst):
                    return                                  # a lookup through the sandbox's own resolver
            self._open(out, dst, dport, "tcp", seq)
            return
        if flags & 0x12 == 0x12:                            # SYN-ACK: where the answers' bytes start
            if sport == 53 and back in self.streams and self._resolver(src):      # the sandbox's resolver's only
                self._stream(out, seq + 1)
            return
        if dport == 53:
            self._dns_stream(out, seq, data, answers=False)
        elif sport == 53:
            self._dns_stream(out, seq, data, answers=True)
        if flags & 0x05 and self.streams:                   # FIN: nothing more that way; RST: nothing either way
            self.streams.pop(out, None)
            if flags & 0x04:
                self.streams.pop(back, None)
        c = self.conns.get(out)
        if c is not None:
            if data:
                if not c["sent"] and c["said"] is None:
                    c["said"] = sni(data) or http_host(data)
                c["sent"] += len(data)
            if flags & 0x05:                                # FIN or RST: a SYN on these ports again is a new one
                c["closed"] = True
            return
        c = self.conns.get(back)
        if c is not None:
            c["received"] += len(data)
            if flags & 0x05:
                c["closed"] = True

    def _udp(self, src: str, sport: int, dst: str, dport: int, data: bytes) -> None:
        if dport == 53:
            self._sender(src)
            self._questions(data)
            if self._resolver(dst):
                return
        elif sport == 53 and self._resolver(src):          # a server of the program's own names nothing
            self._answers(data)
            return
        out, back = (src, sport, dst, dport, "udp"), (dst, dport, src, sport, "udp")
        c = self.conns.get(back)
        if c is not None:
            c["received"] += len(data)
            return
        self._sender(src)
        c = self.conns.get(out) or self._open(out, dst, dport, "udp")
        c["sent"] += len(data)

    def result(self) -> dict:
        """{"hosts": [{"host", "named_by" (dns, tls, program, address), "addresses" (the servers', ADDRESSES_MAX at
        most), "more_addresses", "ports", "connections", "sent", "received"}], "looked_up": [names asked for and never
        used], "packets", "left_out", "stopped" (watching stopped partway)}: hosts by what was sent, most first."""
        with self.lock:
            return self._result()

    def _result(self) -> dict:
        merged = {k: {**m, "addresses": set(m["addresses"]), "ports": set(m["ports"])} for k, m in self.folded.items()}
        used, left_out = set(self.used), self.left_out
        for c in self.conns.values():
            used.update(n for n in (c["said"], c["dns"]) if n)
            if not self._add(merged, c):
                left_out += 1
        hosts = sorted(merged.values(), key=lambda m: (-m["sent"], -m["connections"], m["host"], m["named_by"]))
        for m in hosts:
            m["addresses"] = sorted(m["addresses"], key=lambda a: (ipaddress.ip_address(a).version, ipaddress.ip_address(a)))
            m["ports"] = sorted(m["ports"], key=lambda p: (len(p), p))
        shown = {m["host"] for m in hosts}
        return {"hosts": hosts, "looked_up": sorted(n for n in self.asked if n not in shown and n not in used),
                "packets": self.packets, "left_out": left_out, "broken": self.broken, "stopped": self.stopped}
