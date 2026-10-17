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
summed up as one host. Names looked up and never used are listed apart. DNS sent to pasta's forwarder is the
sandbox's own resolver, never a host; DNS sent anywhere else goes to a server of the program's own choosing, which
is listed. A TCP connection is counted once, however often its first packet is sent again (one lookup hanging on a
server that didn't answer was counted as five connections). What can't be told: what was sent (it is encrypted),
and a name hidden by Encrypted Client Hello. Standard library only."""

from __future__ import annotations

import ipaddress
import struct
import threading

MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
ETHERNET = 1
CONNS_MAX = 20000
HOSTS_MAX = 2000
NAMES_MAX = 5000
PACKET_MAX = 262144 + 64
STREAM_MAX = 70000                      # DNS over TCP: what is kept of a message not complete yet (one is 65537 at most)


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
        self.asked: dict[str, int] = {}                 # names looked up -> how often
        self.conns: dict[tuple, dict] = {}              # (src, sport, dst, dport, proto) -> that connection's sums
        self.folded: dict[str, dict] = {}               # connections the table had no more room for, summed by name
        self.used: set[str] = set()                     # the names those were made under (DNS, SNI, Host)
        self.streams: dict[tuple, list] = {}            # DNS over TCP, each way: [the next sequence number, bytes]
        self.packets = self.broken = self.left_out = 0
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
            if kind == 0x0800:
                ihl = (p[at] & 0x0F) * 4
                total = struct.unpack_from(">H", p, at + 2)[0]
                proto, src, dst = p[at + 9], p[at + 12:at + 16], p[at + 16:at + 20]
                body = p[at + ihl:at + total] if total >= ihl else b""
            elif kind == 0x86DD:
                proto, src, dst = p[at + 6], p[at + 8:at + 24], p[at + 24:at + 40]
                body = p[at + 40:at + 40 + struct.unpack_from(">H", p, at + 4)[0]]
            else:
                return
            src, dst = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
            if proto == 6 and len(body) >= 20:
                sport, dport, seq = struct.unpack_from(">HHI", body, 0)
                flags, data = body[13], body[(body[12] >> 4) * 4:]
                self._tcp(src, sport, dst, dport, flags, seq, data)
            elif proto == 17 and len(body) >= 8:
                sport, dport = struct.unpack_from(">HH", body, 0)
                self._udp(src, sport, dst, dport, body[8:])
        except (IndexError, struct.error, ValueError):
            self.broken += 1

    # ------------------------------------------------------------------ lookups

    def _questions(self, data: bytes) -> None:
        for name in dns(data)[0]:
            if name in self.asked or len(self.asked) < NAMES_MAX:
                self.asked[name] = self.asked.get(name, 0) + 1

    def _answers(self, data: bytes) -> None:
        for address, name in dns(data)[1].items():
            if address in self.names or len(self.names) < NAMES_MAX:
                self.names[address] = name

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
        if len(st[1]) > STREAM_MAX:                         # not DNS after all
            st[1].clear()

    # ------------------------------------------------------------------ connections

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
        if len(self.streams) > CONNS_MAX:
            self.streams.clear()

    def _retire(self, key: tuple) -> None:
        c = self.conns.pop(key)
        self.used.update(n for n in (c["said"], c["dns"]) if n)
        if not self._add(self.folded, c):
            self.left_out += 1

    def _add(self, merged: dict[str, dict], c: dict) -> bool:
        """Adds the connection `c` to the hosts in `merged`, by its name; False when there is no room for another."""
        known = c["dns"] or self.names.get(c["address"])
        name = c["said"] or known or c["address"]
        m = merged.get(name)
        if m is None:
            if len(merged) >= HOSTS_MAX:
                return False
            m = merged[name] = {"host": name, "named_by": "tls" if c["said"] else "dns" if known else "address",
                                "addresses": set(), "ports": set(), "connections": 0, "sent": 0, "received": 0}
        m["addresses"].add(c["address"])
        m["ports"].add(f"{c['port']}/udp" if c["proto"] == "udp" else str(c["port"]))
        m["connections"] += 1
        m["sent"] += c["sent"]
        m["received"] += c["received"]
        return True

    def _tcp(self, src: str, sport: int, dst: str, dport: int, flags: int, seq: int, data: bytes) -> None:
        out, back = (src, sport, dst, dport, "tcp"), (dst, dport, src, sport, "tcp")
        if flags & 0x02 and not flags & 0x10:               # SYN: the program connects out
            c = self.conns.get(out)
            if c is not None and (not c["closed"] or seq == c["isn"]):
                # the same SYN sent again, its first sequence number the same: the same attempt, also after the
                # RST pasta answers each with while its own connection to the server waits (seen on Mint 22.3)
                c["closed"] = False
                return
            if c is not None:                               # these ports used again: the earlier one is summed up
                self._retire(out)
            if dport == 53:                                 # DNS over TCP: its questions are read
                self.streams[out] = [(seq + 1) & 0xFFFFFFFF, bytearray()]
                if self._resolver(dst):
                    return                                  # a lookup through the sandbox's own resolver
            self._open(out, dst, dport, "tcp", seq)
            return
        if flags & 0x12 == 0x12:                            # SYN-ACK: where the answers' bytes start
            if sport == 53 and back in self.streams:
                self.streams[out] = [(seq + 1) & 0xFFFFFFFF, bytearray()]
            return
        if dport == 53:
            self._dns_stream(out, seq, data, answers=False)
        elif sport == 53:
            self._dns_stream(out, seq, data, answers=True)
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
            self._questions(data)
            if self._resolver(dst):
                return
        elif sport == 53:
            self._answers(data)
            if self._resolver(src):
                return
        out, back = (src, sport, dst, dport, "udp"), (dst, dport, src, sport, "udp")
        c = self.conns.get(back)
        if c is not None:
            c["received"] += len(data)
            return
        c = self.conns.get(out) or self._open(out, dst, dport, "udp")
        c["sent"] += len(data)

    def result(self) -> dict:
        """{"hosts": [{"host", "named_by", "addresses", "ports", "connections", "sent", "received"}], "looked_up":
        [names asked for and never used], "packets", "left_out"}: hosts by what was sent, most first."""
        with self.lock:
            return self._result()

    def _result(self) -> dict:
        merged = {k: {**m, "addresses": set(m["addresses"]), "ports": set(m["ports"])} for k, m in self.folded.items()}
        used, left_out = set(self.used), self.left_out
        for c in self.conns.values():
            used.update(n for n in (c["said"], c["dns"]) if n)
            if not self._add(merged, c):
                left_out += 1
        hosts = sorted(merged.values(), key=lambda m: (-m["sent"], -m["connections"], m["host"]))
        for m in hosts:
            m["addresses"], m["ports"] = len(m["addresses"]), sorted(m["ports"], key=lambda p: (len(p), p))
        return {"hosts": hosts, "looked_up": sorted(n for n in self.asked if n not in merged and n not in used),
                "packets": self.packets, "left_out": left_out, "broken": self.broken}
