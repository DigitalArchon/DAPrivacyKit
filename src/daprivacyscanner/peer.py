"""Whose program is on the other end of a connection to the local server: the account that owns the client's TCP
socket, as /proc/net/tcp and tcp6 list it (the kernel's socket table for this network namespace, readable by every
account, uid included). The server answers only its own account's programs (server.py): any account on the computer
can connect to 127.0.0.1, and in --browser mode read the launch link from a command line for a moment."""

from __future__ import annotations

import os
import socket
import struct

TABLES = ("/proc/net/tcp", "/proc/net/tcp6")


def _hex4(ip: str) -> str:
    return "%08X" % struct.unpack("=I", socket.inet_aton(ip))[0]


def _hex6(ip: str) -> str:
    return "".join("%08X" % w for w in struct.unpack("=4I", socket.inet_pton(socket.AF_INET6, ip)))


def _keys(host: str, port: int) -> list[str]:
    """How the kernel's table writes an address and port: its 32-bit words in this machine's byte order, the port in
    hex; an IPv4 address also as IPv6 maps it, for a socket of the IPv6 family."""
    out = []
    try:
        out.append(f"{_hex4(host)}:{port:04X}")
        out.append(f"{_hex6('::ffff:' + host)}:{port:04X}")
    except OSError:
        try:
            out.append(f"{_hex6(host.split('%', 1)[0])}:{port:04X}")
        except OSError:
            pass
    return out


def peer_uid(client: tuple[str, int], server: tuple[str, int], tables=TABLES) -> int | None:
    """The uid owning the socket at `client` that is connected to `server` (both on this computer), or None when the
    tables don't list it (it has gone, or isn't on this computer's network)."""
    local, remote = set(_keys(*client)), set(_keys(*server))
    if not local or not remote:
        return None
    pairs = [f" {a} {b} ".encode() for a in local for b in remote]
    for table in tables:
        try:
            with open(table, "rb") as f:
                data = f.read()
        except OSError:
            continue
        for pair in pairs:                          # the line found by its two addresses, then only it read
            at = data.find(pair)
            if at < 0:
                continue
            start = data.rfind(b"\n", 0, at) + 1
            end = data.find(b"\n", at)
            fields = data[start:end if end >= 0 else len(data)].decode("ascii", "replace").split()
            # sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
            if len(fields) > 7 and fields[1] in local and fields[2] in remote:
                try:
                    return int(fields[7])
                except ValueError:
                    return None
    return None


def same_user(client, server) -> bool:
    """`client`'s program runs as this process's account. Anything that can't be told is refused."""
    if not client or not server:
        return False
    try:
        host, port = client[0], int(client[1])
        shost, sport = server[0], int(server[1])
    except (TypeError, ValueError, IndexError):
        return False
    return peer_uid((host, port), (shost, sport)) == os.getuid()
