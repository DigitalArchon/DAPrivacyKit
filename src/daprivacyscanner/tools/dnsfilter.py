"""A filter in front of pasta's DNS forwarder (docs/TECHNICAL.md, Tools: Mullvad Browser's network; Try an app's).

pasta forwards the lookups its namespace sends to 169.254.0.1 to this computer's own resolver, and the fence lets
them through. That resolver answers more than the internet's names: on Mint 22.3 (systemd-resolved, tested from
pasta's namespace on 2026-11-12) "_gateway" gave the router's address, "_outbound" this computer's address on the
local network, the computer's own name its addresses, a reverse lookup of the router's address its name
("OPNsense.localdomain"), and of this computer's its name; a router's DNS answers its network's device names, and a
name with one label can go out as LLMNR to the local network. So a browser a website took over, or a program on
trial, could learn the local network's addresses and names that way, though it can't reach them.

So the sandbox's lookups go here first: this runs in pasta's namespace, as its root (started by the fence's script
just before bubblewrap, by the computer's python3, its source passed with -c: standard library only, nothing of the
app's imported), listens on 127.0.0.1:53 there (the sandbox's resolv.conf names it), and passes on only:
- one question, of a name of two labels or more (not a single label, which resolved answers itself or asks the local
  network for: "_gateway", "_outbound", the computer's name),
- outside the names local networks use (local, localhost, lan, home, internal, localdomain, intranet, corp, private,
  home.arpa),
- and no reverse lookup (in-addr.arpa, ip6.arpa) of an address in a refused network (the fence's ranges, this
  computer's own networks, NAT64's forms of them);
and of the answers, only those with no address (A, AAAA) in a refused network: a name the local network's resolver
answers with a local address is refused as a whole. Everything refused gets REFUSED. Its own queries go to pasta's
forwarder marked (SO_MARK, which needs the namespace's CAP_NET_ADMIN: the sandbox inside has none), and the fence
lets only marked packets reach the forwarder, so the sandbox can't go round it.

What it can't tell: a network whose resolver answers names under its own public domain (a company's split DNS) still
gets those names resolved here, though not their local addresses.

It forks: the child serves, the parent becomes the next command (bubblewrap). The child dies with it (the kernel's
parent-death signal, and a look at its parent every second), drops every capability once its sockets are made, sets
no_new_privs, and loads the sandbox's strict system-call filter (given in its configuration) and Landlock's limits on
files where the kernel has them: nothing of it outlives the sandbox, and it holds no file."""

import ctypes
import ipaddress
import json
import os
import platform
import select
import signal
import socket
import struct
import sys
import threading
import time

LISTEN = "127.0.0.1"
PORT = 53
TIMEOUT = 4.0                           # seconds a query waits for pasta's forwarder
MAX_PENDING = 256                       # queries waiting at once: more are refused
LOCAL_TLDS = {"local", "localhost", "lan", "home", "internal", "localdomain", "intranet", "corp", "private"}
LOCAL_SUFFIXES = (("home", "arpa"),)
REFUSED, SERVFAIL = 5, 2
A, AAAA = 1, 28
SO_MARK = 36
CAPSET = {"x86_64": 126, "amd64": 126, "aarch64": 91, "arm64": 91, "riscv64": 91, "i686": 185, "armv7l": 185,
          "ppc64le": 184, "s390x": 185}


def qname(msg, off):
    """The question's name: (labels, offset after it); raises ValueError when it isn't plain labels."""
    labels = []
    while True:
        if off >= len(msg):
            raise ValueError("cut short")
        n = msg[off]
        off += 1
        if n == 0:
            return labels, off
        if n & 0xC0 or off + n > len(msg) or len(labels) >= 127:
            raise ValueError("not a plain name")
        labels.append(msg[off:off + n].decode("ascii", "replace").lower())
        off += n


def skip_name(msg, off):
    while True:
        if off >= len(msg):
            raise ValueError("cut short")
        n = msg[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        if n & 0xC0:
            raise ValueError("bad label")
        off += 1 + n


def reverse_network(labels):
    """The network a reverse-lookup name covers (in-addr.arpa: up to 4 numbers; ip6.arpa: up to 32 nibbles), or
    None when the name isn't one; a name that is one but can't be read covers everything."""
    if labels[-2:] == ["in-addr", "arpa"]:
        parts = labels[:-2][::-1]
        try:
            nums = [int(p) for p in parts]
            if len(nums) > 4 or any(not 0 <= n <= 255 for n in nums) or any(p != str(int(p)) for p in parts):
                raise ValueError
        except ValueError:
            return ipaddress.ip_network("0.0.0.0/0")
        return ipaddress.ip_network((bytes(nums + [0] * (4 - len(nums))), 8 * len(nums)))
    if labels[-2:] == ["ip6", "arpa"]:
        nibbles = labels[:-2][::-1]
        if len(nibbles) > 32 or any(len(x) != 1 or x not in "0123456789abcdef" for x in nibbles):
            return ipaddress.ip_network("::/0")
        value = int("".join(nibbles) + "0" * (32 - len(nibbles)), 16)
        return ipaddress.ip_network((value, 4 * len(nibbles)))
    return None


class Policy:
    def __init__(self, refuse, allow):
        self.refuse = [ipaddress.ip_network(n) for n in refuse]
        self.allow = [ipaddress.ip_network(n) for n in allow]

    def address_refused(self, addr):
        if any(addr.version == n.version and addr in n for n in self.allow):
            return False
        return any(addr.version == n.version and addr in n for n in self.refuse)

    def question(self, msg):
        """None when the query may go on; else why not (for a test to read)."""
        if len(msg) < 12:
            return "short"
        if msg[2] & 0x80 or (msg[2] >> 3) & 0xF:                     # a response, or not a standard query
            return "not a query"
        qd, an, ns = struct.unpack_from(">HHH", msg, 4)
        if qd != 1 or an or ns:
            return "not one question"
        labels, _ = qname(msg, 12)
        if len(labels) < 2:
            return "one label"
        if labels[-1] in LOCAL_TLDS or any(tuple(labels[-len(s):]) == s for s in LOCAL_SUFFIXES):
            return "a local name"
        net = reverse_network(labels)
        if net is not None and any(net.version == n.version and net.overlaps(n) for n in self.refuse):
            return "a local address's name"
        return None

    def answer(self, msg):
        """None when the answer may go back; else why not."""
        qd, an, ns, ar = struct.unpack_from(">HHHH", msg, 4)
        off = 12
        for _ in range(qd):
            off = skip_name(msg, off) + 4
        for _ in range(an + ns + ar):
            off = skip_name(msg, off)
            kind, _cls, _ttl, size = struct.unpack_from(">HHIH", msg, off)
            off += 10
            data = msg[off:off + size]
            if len(data) != size:
                raise ValueError("cut short")
            off += size
            if kind == A and size == 4 or kind == AAAA and size == 16:
                if self.address_refused(ipaddress.ip_address(data)):
                    return "a local address"
        return None


def refusal(query, code=REFUSED):
    """The answer that refuses `query`: its id, its question, no records."""
    try:
        _, end = qname(query, 12)
        question = query[12:end + 4]
    except ValueError:
        question = b""
    flags = 0x8000 | (query[2] & 0x01) << 8 | 0x0080 | code               # QR, RD as asked, RA, the code
    return query[:2] + struct.pack(">HHHHH", flags, 1 if question else 0, 0, 0, 0) + question


class Forwarder:
    """Queries from the sandbox to pasta's forwarder over one marked socket: each sent with an id of its own, its
    answer matched back and checked."""

    def __init__(self, policy, upstream, mark):
        self.policy, self.upstream = policy, upstream
        self.up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.up.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        self.up.connect((upstream, PORT))
        self.pending = {}                        # our id -> (their id, reply callable, the query, deadline)
        self.lock = threading.Lock()

    def ask(self, query, reply):
        why = None
        try:
            why = self.policy.question(query)
        except ValueError:
            why = "unreadable"
        if why:
            reply(refusal(query))
            return
        with self.lock:
            if len(self.pending) >= MAX_PENDING:
                reply(refusal(query, SERVFAIL))
                return
            while True:
                qid = int.from_bytes(os.urandom(2), "big")
                if qid not in self.pending:
                    break
            self.pending[qid] = (query[:2], reply, query, time.monotonic() + TIMEOUT)
        try:
            self.up.send(qid.to_bytes(2, "big") + query[2:])
        except OSError:
            with self.lock:
                self.pending.pop(qid, None)
            reply(refusal(query, SERVFAIL))

    def answered(self, msg):
        if len(msg) < 12:
            return
        with self.lock:
            got = self.pending.pop(int.from_bytes(msg[:2], "big"), None)
        if got is None:
            return
        their, reply, query, _ = got
        try:
            why = self.policy.answer(msg)
        except (ValueError, struct.error):
            why = "unreadable"
        reply(refusal(query) if why else their + msg[2:])

    def expire(self):
        now = time.monotonic()
        with self.lock:
            late = [k for k, v in self.pending.items() if v[3] < now]
            gone = [self.pending.pop(k) for k in late]
        for _their, reply, query, _ in gone:
            reply(refusal(query, SERVFAIL))


def serve_tcp(conn, fwd):
    """One TCP client: its queries (length-prefixed) passed on as the UDP ones are, answered in order."""
    conn.settimeout(10)
    done = threading.Event()
    try:
        while True:
            head = conn.recv(2)
            if len(head) < 2:
                return
            n = int.from_bytes(head, "big")
            q = b""
            while len(q) < n:
                more = conn.recv(n - len(q))
                if not more:
                    return
                q += more
            box = []
            done.clear()

            def reply(data, box=box):
                box.append(data)
                done.set()
            fwd.ask(q, reply)
            if not done.wait(TIMEOUT + 1) or not box:
                return
            conn.sendall(len(box[0]).to_bytes(2, "big") + box[0])
    except OSError:
        return
    finally:
        conn.close()


def drop_privileges(program_hex):
    """Every capability dropped (capset to nothing), no_new_privs, Landlock's limits on files where the kernel has them
    (none allowed), then the strict system-call filter."""
    libc = ctypes.CDLL(None, use_errno=True)

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]
    nr = CAPSET.get(platform.machine())
    if nr is not None and libc.syscall(nr, ctypes.byref(Header(0x20080522, 0)), (Data * 2)()) != 0:
        raise OSError(ctypes.get_errno(), "capset")
    if libc.prctl(38, 1, 0, 0, 0):                                                     # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "no_new_privs")

    class Ruleset(ctypes.Structure):
        _fields_ = [("fs", ctypes.c_uint64)]
    abi = libc.syscall(444, None, 0, 1)
    if abi >= 1:                        # every right on files this ABI knows, handled: none granted
        fs = (1 << 13) - 1 if abi < 2 else (1 << 14) - 1 if abi < 3 else (1 << 15) - 1 if abi < 5 else (1 << 16) - 1
        rs = Ruleset(fs)
        fd = libc.syscall(444, ctypes.byref(rs), ctypes.sizeof(rs), 0)
        if fd >= 0:
            libc.syscall(446, fd, 0)                                               # landlock_restrict_self
            os.close(fd)
    if program_hex:
        prog = bytes.fromhex(program_hex)

        class Prog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
        buf = ctypes.create_string_buffer(prog, len(prog))
        if libc.prctl(22, 2, ctypes.byref(Prog(len(prog) // 8, ctypes.cast(buf, ctypes.c_void_p))), 0, 0):
            raise OSError(ctypes.get_errno(), "seccomp")


def serve(cfg, parent, udp, tcp, fwd):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(1, signal.SIGKILL, 0, 0, 0)                                          # PR_SET_PDEATHSIG
    if os.getppid() != parent:
        os._exit(0)
    null = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1):
        os.dup2(null, fd)
    keep = {udp.fileno(), tcp.fileno(), fwd.up.fileno(), 2}
    for fd in range(3, 1024):
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass
    warm_up(fwd.policy)
    try:
        drop_privileges(cfg.get("filter", ""))
    except OSError:
        os._exit(1)
    threading.Thread(target=accept, args=(tcp, fwd), daemon=True).start()
    last = time.monotonic()
    while True:
        ready = select.select([udp, fwd.up], [], [], 1.0)[0]
        if udp in ready:
            try:
                data, addr = udp.recvfrom(65535)
            except OSError:
                data = b""
            if data:
                fwd.ask(data, lambda out, addr=addr: _send(udp, out, addr))
        if fwd.up in ready:
            try:
                fwd.answered(fwd.up.recv(65535))
            except OSError:
                pass
        if time.monotonic() - last > 1.0:
            last = time.monotonic()
            fwd.expire()
            if os.getppid() != parent:
                os._exit(0)


def warm_up(policy):
    """Everything serving uses, used once before Landlock closes the files: Python loads some of it on first use."""
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    policy.question(q)
    policy.question(q[:12] + b"\x011\x01a\x07in-addr\x04arpa\x00\x00\x0c\x00\x01")
    policy.question(q[:12] + b"\x01a\x03ip6\x04arpa\x00\x00\x0c\x00\x01")
    policy.answer(b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:] + b"\xc0\x0c\x00\x01\x00\x01"
                  b"\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22")
    refusal(q)
    threading.Event().wait(0)


def _send(sock, data, addr):
    try:
        sock.sendto(data, addr)
    except OSError:
        pass


def accept(tcp, fwd):
    while True:
        try:
            conn, _ = tcp.accept()
        except OSError:
            return
        if threading.active_count() > 64:
            conn.close()
            continue
        threading.Thread(target=serve_tcp, args=(conn, fwd), daemon=True).start()


def main(argv):
    cfg, command = json.loads(argv[0]), argv[1:]
    policy = Policy(cfg["refuse"], cfg.get("allow", []))
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((LISTEN, PORT))
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((LISTEN, PORT))
        tcp.listen(16)
        fwd = Forwarder(policy, cfg["upstream"], int(cfg["mark"]))
    except OSError as e:
        sys.exit(f"The lookups' filter could not be set up ({e.strerror or e})")
    parent = os.getpid()
    if os.fork() == 0:
        serve(cfg, parent, udp, tcp, fwd)
        os._exit(0)
    for s in (udp, tcp, fwd.up):
        s.close()
    os.execv(command[0], command)


if __name__ == "__main__":
    main(sys.argv[1:])
