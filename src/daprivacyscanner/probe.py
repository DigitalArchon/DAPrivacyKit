"""Check which TCP ports of a machine answer, from another machine: the outside view the online
tests can't get from inside. Standard library only, so this file can be copied to any machine with
Python 3 and run on its own:

    python3 probe.py 2001:db8::5            # common service ports
    python3 probe.py 192.0.2.10 --ports 22,3389,8000-8010

Run it from a different network than the machine probed (a phone hotspot, a server) to see what
the internet sees; from the same network it shows what other local devices see."""

from __future__ import annotations

import argparse
import socket
import sys

COMMON = (21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 631, 993, 995, 1714, 2049, 3000, 3306, 3389, 5000,
          5432, 5900, 5901, 6379, 8000, 8080, 8443, 9090, 27017)


def parse_ports(spec: str) -> list[int]:
    out = []
    for part in spec.split(","):
        lo, _, hi = part.strip().partition("-")
        lo_i, hi_i = int(lo), int(hi or lo)
        if not (1 <= lo_i <= hi_i <= 65535) or hi_i - lo_i > 5000:
            raise ValueError(f"bad port range {part!r}")
        out += range(lo_i, hi_i + 1)
    return out


def probe(address: str, ports, timeout: float = 2.0, connect=socket.create_connection) -> list[tuple[int, str]]:
    """(port, "open" | "closed" | "no answer") for each port."""
    out = []
    for port in ports:
        try:
            with connect((address, port), timeout=timeout):
                out.append((port, "open"))
        except ConnectionRefusedError:
            out.append((port, "closed"))
        except OSError:
            out.append((port, "no answer"))           # filtered by a firewall, or nothing there
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="probe", description="Which TCP ports of a machine answer, seen from here.")
    ap.add_argument("address", help="IPv4 or IPv6 address (or host name) of the machine to probe")
    ap.add_argument("--ports", help="comma-separated ports or ranges (default: common service ports)")
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args(argv)
    try:
        ports = parse_ports(args.ports) if args.ports else list(COMMON)
    except ValueError as e:
        ap.error(str(e))
    results = probe(args.address, ports, args.timeout)
    for port, state in results:
        if state == "open" or args.ports:
            print(f"{port:>5}/tcp  {state}")
    open_ = [p for p, s in results if s == "open"]
    print(f"\n{len(open_)} of {len(ports)} ports open on {args.address}"
          + (": " + ", ".join(map(str, open_)) if open_ else "."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
