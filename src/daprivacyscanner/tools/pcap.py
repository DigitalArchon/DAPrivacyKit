"""Which hosts a trial's program contacted (docs/TECHNICAL.md, Tools: Try an app): read from the packets pasta
passes for the sandbox's network namespace (`pasta --pcap`, into a pipe the app reads as they come), and kept
only as sums: per host, how many connections, to which ports, how many bytes each way. No packet and no payload
is kept; nothing is written to the disk.

A host's name comes from what the program itself asked or said, in this order: the DNS answer that gave the
address (the sandbox's DNS goes through pasta's forwarder, in plain text on this link), else the name in a TLS
connection's first message (SNI: what a program using DNS over HTTPS still sends), else an HTTP request's Host
line; without any of them, the address. Names looked up and never connected to are listed apart. What can't be
told: what was sent (it is encrypted), and a name hidden by Encrypted Client Hello. Standard library only."""

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
    """Fed a pcap stream piece by piece (feed), it sums up who was contacted (result)."""

    def __init__(self):
        self.buf = bytearray()
        self.order: str | None = None
        self.link = ETHERNET
        self.names: dict[str, str] = {}                 # address -> the name whose lookup gave it
        self.asked: dict[str, int] = {}                 # names looked up -> how often
        self.conns: dict[tuple, tuple[str, int, str]] = {}   # (src, sport, dst, dport, proto) -> its host's key
        self.hosts: dict[tuple[str, int, str], dict] = {}    # (address, port, proto) -> sums
        self.said: dict[tuple[str, int, str], str] = {}      # the name the program gave itself (SNI, Host)
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
                sport, dport = struct.unpack_from(">HH", body, 0)
                flags, data = body[13], body[(body[12] >> 4) * 4:]
                self._tcp(src, sport, dst, dport, flags, data)
            elif proto == 17 and len(body) >= 8:
                sport, dport = struct.unpack_from(">HH", body, 0)
                self._udp(src, sport, dst, dport, body[8:])
        except (IndexError, struct.error, ValueError):
            self.broken += 1

    def _host(self, key: tuple[str, int, str]) -> dict | None:
        h = self.hosts.get(key)
        if h is None:
            if len(self.hosts) >= HOSTS_MAX:
                self.left_out += 1
                return None
            h = self.hosts[key] = {"connections": 0, "sent": 0, "received": 0}
        return h

    def _tcp(self, src: str, sport: int, dst: str, dport: int, flags: int, data: bytes) -> None:
        out, back = (src, sport, dst, dport, "tcp"), (dst, dport, src, sport, "tcp")
        if flags & 0x02 and not flags & 0x10:               # SYN: the program connects out
            if len(self.conns) >= CONNS_MAX:
                self.conns.clear()
            key = (dst, dport, "tcp")
            h = self._host(key)
            if h is not None:
                self.conns[out] = key
                h["connections"] += 1
            return
        if out in self.conns:
            key = self.conns[out]
            h = self.hosts.get(key)
            if h is not None and data:
                if not h["sent"] and key not in self.said:
                    name = sni(data) or http_host(data)
                    if name:
                        self.said[key] = name
                h["sent"] += len(data)
        elif back in self.conns:
            h = self.hosts.get(self.conns[back])
            if h is not None:
                h["received"] += len(data)

    def _udp(self, src: str, sport: int, dst: str, dport: int, data: bytes) -> None:
        if dport == 53:
            for name in dns(data)[0]:
                if name in self.asked or len(self.asked) < NAMES_MAX:
                    self.asked[name] = self.asked.get(name, 0) + 1
            return
        if sport == 53:
            for address, name in dns(data)[1].items():
                if address in self.names or len(self.names) < NAMES_MAX:
                    self.names[address] = name
            return
        out, back = (src, sport, dst, dport, "udp"), (dst, dport, src, sport, "udp")
        if back in self.conns:
            h = self.hosts.get(self.conns[back])
            if h is not None:
                h["received"] += len(data)
            return
        if out not in self.conns:
            if len(self.conns) >= CONNS_MAX:
                self.conns.clear()
            key = (dst, dport, "udp")
            h = self._host(key)
            if h is None:
                return
            self.conns[out] = key
            h["connections"] += 1
        h = self.hosts.get(self.conns[out])
        if h is not None:
            h["sent"] += len(data)

    def result(self) -> dict:
        """{"hosts": [{"host", "named_by", "addresses", "ports", "connections", "sent", "received"}], "looked_up":
        [names asked for and never connected to], "packets", "left_out"}: hosts by what was sent, most first."""
        with self.lock:
            return self._result()

    def _result(self) -> dict:
        merged: dict[str, dict] = {}
        for (address, port, proto), h in self.hosts.items():
            by = "dns" if address in self.names else "tls" if (address, port, proto) in self.said else "address"
            name = self.names.get(address) or self.said.get((address, port, proto)) or address
            m = merged.setdefault(name, {"host": name, "named_by": by, "addresses": set(), "ports": set(),
                                         "connections": 0, "sent": 0, "received": 0})
            m["addresses"].add(address)
            m["ports"].add(f"{port}/udp" if proto == "udp" else str(port))
            for k in ("connections", "sent", "received"):
                m[k] += h[k]
        hosts = sorted(merged.values(), key=lambda m: (-m["sent"], -m["connections"], m["host"]))
        for m in hosts:
            m["addresses"], m["ports"] = len(m["addresses"]), sorted(m["ports"], key=lambda p: (len(p), p))
        return {"hosts": hosts, "looked_up": sorted(n for n in self.asked if n not in merged),
                "packets": self.packets, "left_out": self.left_out, "broken": self.broken}
