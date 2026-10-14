"""Listening sockets from `ss`: shared by the exposed_services context key and the network checks."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .host import Host

SS_ARGS = ("ss", "-tulpnH")
WILDCARDS = frozenset({"0.0.0.0", "[::]", "*", "[::ffff:0.0.0.0]"})
# expected UDP listeners: DHCP clients (68, 546). mDNS (5353) is net.hostname_broadcast's.
EXPECTED_UDP = frozenset({68, 546, 5353})
DEFAULT_EPHEMERAL = (32768, 60999)
_PROCESS = re.compile(r'\(\("([^"]+)"(?:,pid=(\d+))?')
# what usually listens on a port, to say in plain words what is exposed (a guess: the process
# name, when ss can see it, is shown too)
PORT_NAMES = {
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "web server", 111: "rpcbind (NFS)", 139: "Windows file sharing (SMB)",
    443: "web server", 445: "Windows file sharing (SMB)", 631: "CUPS printing", 2049: "NFS", 3000: "development server",
    3306: "MySQL/MariaDB", 3389: "remote desktop (RDP)", 5000: "development server", 5355: "LLMNR name resolution",
    5432: "PostgreSQL", 5900: "VNC remote desktop", 5901: "VNC remote desktop", 6379: "Redis", 8000: "development server",
    8080: "web server", 9090: "Cockpit web console", 27017: "MongoDB",
}
for _p in range(1714, 1765):
    PORT_NAMES.setdefault(_p, "KDE Connect / GSConnect")


@dataclass(frozen=True)
class Listener:
    proto: str               # tcp | udp
    address: str             # as ss prints it, e.g. 0.0.0.0, [::], 127.0.0.53%lo
    port: int
    process: str | None = None
    pid: int | None = None   # ss names the process only for the user's own sockets, or as root

    @property
    def interface(self) -> str | None:
        """The interface a socket is bound to (127.0.0.53%lo -> lo)."""
        return self.address.split("%", 1)[1] if "%" in self.address else None

    @property
    def host_part(self) -> str:
        return self.address.split("%", 1)[0]

    @property
    def wildcard(self) -> bool:
        return self.host_part in WILDCARDS and self.interface in (None, "")

    def label(self) -> str:
        parts = [p for p in (PORT_NAMES.get(self.port), self.process) if p]
        return f"{self.port}/{self.proto}" + (f" ({', '.join(parts)})" if parts else "")


def parse_ss(text: str) -> list[Listener]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] not in ("tcp", "udp"):
            continue
        addr, _, port = f[4].rpartition(":")
        if not port.isdigit():
            continue
        proc = _PROCESS.search(line)
        out.append(Listener(f[0], addr, int(port), proc.group(1) if proc else None,
                            int(proc.group(2)) if proc and proc.group(2) else None))
    return out


def ephemeral_range(host: Host) -> tuple[int, int]:
    try:
        text = host.read_sys("/proc/sys/net/ipv4/ip_local_port_range")
        lo, hi = (int(x) for x in (text or "").split())
        return lo, hi
    except Exception:  # noqa: BLE001 - unreadable or malformed: the kernel default
        return DEFAULT_EPHEMERAL


def exposed(listeners: list[Listener], ephemeral: tuple[int, int] = DEFAULT_EPHEMERAL) -> list[Listener]:
    """Services reachable from other machines: bound to all interfaces, except the expected
    UDP listeners and UDP sockets on ephemeral ports (clients, such as browsers and DNS
    lookups, which ss -u lists alongside servers). The same port on IPv4 and IPv6 counts once."""
    out, seen = [], set()
    for s in listeners:
        if not s.wildcard:
            continue
        if s.proto == "udp" and (s.port in EXPECTED_UDP or ephemeral[0] <= s.port <= ephemeral[1]):
            continue
        if (s.proto, s.port) in seen:
            continue
        seen.add((s.proto, s.port))
        out.append(s)
    return sorted(out, key=lambda s: (s.proto, s.port))


# ------------------------------------------------------------------ firewall rules

def _port_set(spec: str) -> list[tuple[int, int, str | None]]:
    """"22/tcp", "80,443/tcp", "1714:1764/udp", "1025-65535/tcp", "8080" -> [(lo, hi, proto or None)]."""
    ports, _, proto = spec.partition("/")
    out = []
    for part in ports.split(","):
        lo, _, hi = part.replace("-", ":").partition(":")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            return []
        out.append((int(lo), int(hi or lo), proto or None))
    return out


@dataclass
class FirewallRules:
    """Which incoming ports a firewall lets through. `allows` answers True, False, or None when
    it can't tell (a rule that names an app profile, a rich rule, an unknown policy)."""
    tool: str
    default_allows: bool | None                         # the incoming policy: accept or not
    open_ports: list[tuple[int, int, str | None]]
    unparsed: int = 0                                   # allow rules this couldn't read

    def allows(self, port: int, proto: str) -> bool | None:
        if self.default_allows:
            return True
        if any(lo <= port <= hi and p in (None, proto) for lo, hi, p in self.open_ports):
            return True
        if self.default_allows is None or self.unparsed:
            return None
        return False


# ufw application profiles that are only a port, for the common ones; others are left unknown
UFW_PROFILES = {"openssh": "22/tcp", "ssh": "22/tcp", "cups": "631", "samba": "137,138/udp",
                "kde connect": "1714:1764", "gsconnect": "1714:1764"}


def parse_ufw_status(text: str) -> FirewallRules | None:
    """`ufw status verbose`, or None when ufw is inactive."""
    if not re.search(r"^Status: active", text, re.M):
        return None
    m = re.search(r"^Default: (\w+) \(incoming\)", text, re.M)
    rules = FirewallRules("ufw", None if not m else m.group(1) == "allow", [])
    body = text.split("----", 1)[1] if "----" in text else ""
    for line in body.splitlines():
        m = re.match(r"^(.+?)\s{2,}(ALLOW|LIMIT)(?: IN)?\s{2,}", line)
        if not m:
            continue
        to = re.sub(r"\s*\(v6\)$", "", m.group(1).strip())
        to = re.sub(r"\s+on\s+\S+$", "", to)            # "22/tcp on eth0"
        to = UFW_PROFILES.get(to.lower(), to)
        if to.lower() == "anywhere":
            rules.open_ports.append((0, 65535, None))
            continue
        ports = _port_set(to.split()[-1]) if to.split() else []
        if ports:
            rules.open_ports += ports
        else:
            rules.unparsed += 1
    return rules


def parse_firewalld_zone(text: str, service_ports: dict[str, list[str]]) -> FirewallRules:
    """`firewall-cmd --zone=Z --list-all`; `service_ports` maps a service name to its ports
    (from `firewall-cmd --info-service`), or to [] when unknown."""
    def field(name):
        m = re.search(rf"^\s*{name}:[ \t]*(.*)$", text, re.M)
        return m.group(1).split() if m else []
    target = (field("target") or ["default"])[0]
    rules = FirewallRules("firewalld", target.upper() == "ACCEPT", [])
    for spec in field("ports"):
        rules.open_ports += _port_set(spec)
    for svc in field("services"):
        ports = service_ports.get(svc)
        if not ports:
            rules.unparsed += 1
        for spec in ports or []:
            rules.open_ports += _port_set(spec)
    if re.search(r"^\s*rich rules:[ \t]*\n\s+\S", text, re.M):
        rules.unparsed += 1
    return rules


# ------------------------------------------------------------------ VPN and IPv6 (context keys)

def _ifaces(host: Host) -> list[str]:
    try:
        return sorted(os.listdir(host.sys_path("/sys/class/net")))
    except OSError:
        return []


IFF_TUN, IFF_TAP = 0x0001, 0x0002


def vpn_links(host: Host) -> list[str]:
    """Interfaces that are VPN tunnels: WireGuard, or TUN devices (OpenVPN and most VPN apps).
    TAP devices are left out: they carry Ethernet frames, as libvirt's vnetN do for virtual machines.
    Whether a tunnel carries this machine's internet traffic is `internet_links`'."""
    out = []
    for name in _ifaces(host):
        p = host.sys_path(f"/sys/class/net/{name}")
        try:
            uevent = (p / "uevent").read_text()
        except OSError:
            uevent = ""
        if "DEVTYPE=wireguard" in uevent:
            out.append(name)
            continue
        try:
            flags = (p / "tun_flags").read_text().strip()
        except OSError:
            continue
        try:
            if int(flags, 16) & (IFF_TUN | IFF_TAP) == IFF_TAP:
                continue
        except ValueError:
            pass
        out.append(name)
    return out


# any public address will do: a route lookup sends nothing
PUBLIC_PROBE = {4: "1.1.1.1", 6: "2606:4700:4700::1111"}


def internet_route(host: Host, family: int) -> set[str]:
    """The interface the kernel would send this machine's internet traffic through, for IPv4 or IPv6
    (empty when there is no route). Asked with `ip route get`, which follows policy routing: wg-quick,
    NetworkManager's WireGuard and VPN apps such as Mullvad's route everything into the tunnel with
    rules and a table of their own, leaving the main table's default route on the LAN. Without `ip`,
    the main table's default routes."""
    r = host.run("ip", f"-{family}", "route", "get", PUBLIC_PROBE[family])
    if r.missing:
        return default_route_links_v6(host) if family == 6 else default_route_links_v4(host)
    first = r.stdout.strip().splitlines()[0] if r.ok and r.stdout.strip() else ""
    m = re.search(r"\bdev (\S+)", first)
    if not m or m.group(1) == "lo" or re.match(r"(unreachable|prohibit|blackhole|throw)\b", first):
        return set()
    return {m.group(1)}


def internet_links(host: Host) -> set[str]:
    """The interfaces carrying this machine's internet traffic, IPv4 and IPv6."""
    return internet_route(host, 4) | internet_route(host, 6)


def carrying_vpn_links(host: Host, tunnels: list[str] | None = None) -> list[str]:
    """The VPN tunnels that carry this machine's internet traffic (not a split tunnel or a mesh
    network such as Tailscale without an exit node)."""
    tunnels = vpn_links(host) if tunnels is None else tunnels
    if not tunnels:
        return []
    routed = internet_links(host)
    return [t for t in tunnels if t in routed]


def default_route_links_v4(host: Host) -> set[str]:
    """Interfaces with an IPv4 route to 0.0.0.0 in the main table (a default route, or OpenVPN's
    0.0.0.0/1). Policy routing isn't seen here: see `internet_route`."""
    out = set()
    for line in (host.read_sys("/proc/net/route") or "").splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000":
            out.add(f[0])
    return out


def default_route_links_v6(host: Host) -> set[str]:
    out = set()
    for line in (host.read_sys("/proc/net/ipv6_route") or "").splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            out.add(f[9])
    return out


def global_ipv6(host: Host) -> dict[str, list[str]]:
    """Global (internet-routable) IPv6 addresses per interface, from /proc/net/if_inet6: scope 0,
    excluding unique-local fc00::/7."""
    out: dict[str, list[str]] = {}
    for line in (host.read_sys("/proc/net/if_inet6") or "").splitlines():
        f = line.split()
        if len(f) < 6 or f[3] != "00" or f[0][:2].lower() in ("fc", "fd"):
            continue
        addr = ":".join(f[0][i:i + 4] for i in range(0, 32, 4))
        out.setdefault(f[5], []).append(addr)
    return out
