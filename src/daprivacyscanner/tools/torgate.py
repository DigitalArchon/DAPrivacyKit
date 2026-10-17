"""Tor Browser's gate (docs/TECHNICAL.md, Tools; tools/sandbox.py): runs inside the outer sandbox, the one on
the computer's network, as the host's `python3 -I -c <this file's source> <config>`. Standard library
only, and nothing of the app's imported: the AppImage that started it may be gone by the time the
browser closes. It:

1. applies Landlock's scopes (abstract Unix sockets, signals) when the kernel has them;
2. starts tor, Tor Browser's own, in a sandbox of its own (sandbox.tor_argv: none of the display, sound or
   the browser's profile the outer one holds), with its SOCKS and control ports as Unix sockets in the outer
   sandbox's tor folder, and follows its log for the bootstrap status (written to status.json, which
   the app shows: Tor Browser's own Connect page is off when it doesn't start tor);
3. listens on the browser's control socket and filters what goes to tor's: what Tor Browser needs to
   show circuits, ask for a new identity and keep onion-site keys passes; anything that would change
   tor's settings (a proxy or a bridge of the browser's choosing would make tor reveal the address) is
   refused with 510. The browser authenticates to the filter with anything; the filter authenticates
   to tor with the cookie, which the browser never sees;
4. runs the inner sandbox (the browser, with no network) and waits for it; then stops tor (halt: over
   its control port, so that it saves its state). The inner
   sandbox's command (sandbox.STAY) lasts until no browser process is left, also when the browser restarts
   itself as a new process, and the sandbox dies with this gate (--die-with-parent).

Messages for the user (why it couldn't start) go to stderr, which is the start log in the app's
private folder; tor's own log is kept in memory, its last lines only."""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

WAIT_FOR_TOR = 60                   # seconds for tor to open its sockets
MAX_LINE = 65536
MAX_CONNECTIONS = 16                # the browser opens one or two control connections; a flood is refused

# ------------------------------------------------------------------ the control port filter

GETINFO_OK = re.compile(r"^(version|status/bootstrap-phase|status/circuit-established|circuit-status|"
                        r"net/listeners/socks|ns/purpose/bridge|ns/id/\$?[0-9A-Fa-f]{40}|"
                        r"ip-to-country/[0-9A-Fa-f.:]{2,45})$")
GETCONF_OK = {"BRIDGE", "CLIENTTRANSPORTPLUGIN", "USEBRIDGES"}
EVENTS_OK = {"CIRC", "STREAM", "STATUS_CLIENT", "EXTENDED"}
SIGNALS_OK = {"NEWNYM"}
ONION = r"[a-z2-7]{56}(\.onion)?"
ONION_ADD = re.compile(rf"^{ONION} x25519:[A-Za-z0-9+/]{{43}}=?( ClientName=[A-Za-z0-9_-]{{1,64}})?( Flags=Permanent)?$")
ONION_ONE = re.compile(rf"^{ONION}$")
PROTOCOLINFO = '250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor="{version}"\r\n250 OK'
FILTERED = "510 Command filtered"
TOR_VERSION = ["0.4.8"]                 # tor's own, asked once it is up (tor_version); this until then


def decide(line):
    """What to do with one command line from the browser: ("forward", None), ("reply", text) or
    ("quit", text)."""
    word, _, rest = line.strip().partition(" ")
    cmd, rest = word.upper(), rest.strip()
    if cmd == "AUTHENTICATE":
        return "reply", "250 OK"
    if cmd == "PROTOCOLINFO":
        return "reply", PROTOCOLINFO.format(version=TOR_VERSION[0])
    if cmd == "QUIT":
        return "quit", "250 closing connection"
    keys = rest.split()
    if cmd == "GETINFO" and keys and all(GETINFO_OK.match(k) for k in keys):
        return "forward", None
    if cmd == "GETCONF" and keys and all(k.upper() in GETCONF_OK for k in keys):
        return "forward", None
    if cmd == "SETEVENTS" and all(k.upper() in EVENTS_OK for k in keys):
        return "forward", None
    if cmd == "SIGNAL" and rest.upper() in SIGNALS_OK:
        return "forward", None
    if cmd == "ONION_CLIENT_AUTH_VIEW" and (not rest or ONION_ONE.match(rest)):
        return "forward", None
    if cmd == "ONION_CLIENT_AUTH_ADD" and ONION_ADD.match(rest):
        return "forward", None
    if cmd == "ONION_CLIENT_AUTH_REMOVE" and ONION_ONE.match(rest):
        return "forward", None
    return "reply", FILTERED


def lines(sock):
    """The CRLF (or LF) terminated lines from a socket, as bytes with their ending; stops at the end,
    or at a line longer than MAX_LINE (with or without its ending in the same read)."""
    buf = b""
    while True:
        i = buf.find(b"\n")
        if i >= 0:
            if i > MAX_LINE:
                return
            line, buf = buf[:i + 1], buf[i + 1:]
            yield line
            continue
        if len(buf) > MAX_LINE:
            return
        try:
            chunk = sock.recv(16384)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk


def messages(sock):
    """Whole control-port messages from tor (a reply or an event: up to its "NNN " line, data
    blocks included), as bytes."""
    msg, in_data = [], False
    for line in lines(sock):
        msg.append(line)
        if in_data:
            if line.rstrip(b"\r\n") == b".":
                in_data = False
            continue
        if len(line) >= 4 and line[3:4] == b"+":
            in_data = True
        elif len(line) >= 4 and line[3:4] == b" ":
            yield b"".join(msg)
            msg = []


class Replies:
    """The browser's replies in the order of its commands: one answered here (a filtered command, AUTHENTICATE)
    while an earlier one is still with tor waits for tor's reply, so a browser that sends two commands at once
    gets its answers in order, as the control protocol promises. tor's asynchronous events (650) go at once."""

    def __init__(self, client):
        self.client, self.queue = client, []          # [text, or None: tor's reply, awaited]
        self.lock = threading.Condition()

    def local(self, text):
        with self.lock:
            self.queue.append(text)
            self._flush()

    def drain(self, timeout):
        """Waits until every reply has gone out (tor's to commands sent before QUIT): True, or False on time."""
        with self.lock:
            return self.lock.wait_for(lambda: not self.queue, timeout)

    def forwarded(self):
        with self.lock:
            self.queue.append(None)

    def from_tor(self, msg):
        with self.lock:
            if msg.startswith(b"650"):
                self.client.sendall(msg)
                return
            for i, item in enumerate(self.queue):
                if item is None:
                    self.queue[i] = msg
                    break
            else:
                self.client.sendall(msg)              # a reply to nothing asked: passed on as it is
            self._flush()

    def _flush(self):
        while self.queue and self.queue[0] is not None:
            self.client.sendall(self.queue.pop(0))
        self.lock.notify_all()


def serve(client, upstream, cookie):
    """One browser connection: its own connection to tor, authenticated with the cookie."""
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replies = messages(up)                       # one reader for tor's side: what it buffers stays with it
    try:
        up.connect(upstream)
        up.sendall(b"AUTHENTICATE " + cookie.hex().encode() + b"\r\n")
        first = next(replies, b"")
        if not first.startswith(b"250"):
            raise OSError("tor refused the cookie")
    except (OSError, StopIteration):
        client.close()
        up.close()
        return
    out = Replies(client)

    def pump():
        for msg in replies:
            try:
                out.from_tor(msg)
            except OSError:
                break
        for s in (client, up):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    threading.Thread(target=pump, daemon=True).start()
    data = lines(client)
    for line in data:
        if line.startswith(b"+"):                    # a multi-line command: never passed, its data skipped
            for more in data:
                if more.rstrip(b"\r\n") == b".":
                    break
            action, text = "reply", FILTERED
        else:
            action, text = decide(line.decode("utf-8", "replace"))
        try:
            if action == "forward":
                out.forwarded()
                up.sendall(line.rstrip(b"\r\n") + b"\r\n")
            else:
                out.local(text.encode() + b"\r\n")
                if action == "quit":
                    out.drain(10)                    # tor's replies to what went before QUIT reach the browser
                    break
        except OSError:
            break
    for s in (client, up):                           # shut down first: it wakes the pump, which may be in recv
        for f in (lambda: s.shutdown(socket.SHUT_RDWR), s.close):
            try:
                f()
            except OSError:
                pass


def tor_version(upstream, cookie):
    """tor's version, asked on a connection of the gate's own (for the PROTOCOLINFO answer); None if
    it can't be learnt."""
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.settimeout(5)
        up.connect(upstream)
        up.sendall(b"AUTHENTICATE " + cookie.hex().encode() + b"\r\nGETINFO version\r\nQUIT\r\n")
        for msg in messages(up):
            m = re.search(rb"250[-+ ]version=([0-9][0-9A-Za-z.\-]{0,40})", msg)
            if m:
                return m.group(1).decode()
    except OSError:
        pass
    finally:
        up.close()
    return None


def listen(path, upstream, cookie):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(8)
    active = []                                      # the threads serving connections: at most MAX_CONNECTIONS

    def accept():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            active[:] = [t for t in active if t.is_alive()]
            if len(active) >= MAX_CONNECTIONS:
                c.close()
                continue
            t = threading.Thread(target=serve, args=(c, upstream, cookie), daemon=True)
            active.append(t)
            t.start()
    threading.Thread(target=accept, daemon=True).start()
    return srv


# ------------------------------------------------------------------ tor

BOOTSTRAP = re.compile(r"Bootstrapped (\d+)%(?: \(([^)]*)\))?: (.*)")


class Status:
    """status.json in the tor folder: what the app shows of tor's connection."""

    def __init__(self, path):
        self.path, self.data, self.lock = path, {"state": "starting", "progress": 0, "summary": "", "problem": ""}, \
            threading.Lock()
        self.write()

    def update(self, **kw):
        with self.lock:
            self.data.update(kw, time=time.time())
            self.write()

    def write(self):
        tmp = self.path + ".new"
        try:
            with open(tmp, "w") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)
        except OSError:
            pass


def follow(tor, status, tail):
    """tor's log: the bootstrap progress into the status, warnings kept as the last problem."""
    for raw in tor.stdout:
        line = raw.decode("utf-8", "replace").strip()
        tail.append(line)
        del tail[:-6]
        m = BOOTSTRAP.search(line)
        if m:
            pct = int(m.group(1))
            status.update(state="connected" if pct >= 100 else "connecting", progress=pct, summary=m.group(3)[:200])
        elif "[warn]" in line or "[err]" in line:
            status.update(problem=line.split("] ", 1)[-1][:300])
    status.update(state="stopped")


def apply_landlock():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)

    class Attr(ctypes.Structure):
        _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]
    a = Attr(0, 0, 3)
    fd = libc.syscall(444, ctypes.byref(a), ctypes.sizeof(a), 0)
    if fd < 0 or libc.prctl(38, 1, 0, 0, 0) or libc.syscall(446, fd, 0):
        sys.exit("Landlock could not be applied (%d)" % ctypes.get_errno())


def halt(upstream, cookie, tor, wait=10):
    """tor asked to exit cleanly over its control port (SIGNAL HALT: as SIGTERM, it saves its state first) and
    waited for, then stopped if it hasn't: it runs in a sandbox of its own (sandbox.tor_argv), whose bubblewrap a
    signal ends at once, taking tor with it unsaved."""
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.settimeout(5)
        up.connect(upstream)
        up.sendall(b"AUTHENTICATE " + cookie.hex().encode() + b"\r\nSIGNAL HALT\r\n")
        tor.wait(wait)
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        up.close()
    stop(tor)


def stop(proc, wait=10):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(wait)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main(cfg):
    if cfg.get("landlock"):
        apply_landlock()
    for p in (cfg["control"], cfg["socks"], cfg["upstream"], cfg["cookie"]):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    status = Status(cfg["status"])
    argv = [a.replace("@PID@", str(os.getpid())) for a in cfg["tor"]]
    os.makedirs(argv[argv.index("ClientOnionAuthDir") + 1], mode=0o700, exist_ok=True)
    tail = []
    try:
        tor = subprocess.Popen(argv, cwd=cfg["cwd"], env=cfg["tor_env"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as e:
        status.update(state="failed", problem=str(e))
        sys.exit(f"tor couldn't be started: {e}")
    threading.Thread(target=follow, args=(tor, status, tail), daemon=True).start()
    deadline = time.monotonic() + WAIT_FOR_TOR
    while not all(os.path.exists(p) for p in (cfg["upstream"], cfg["socks"], cfg["cookie"])):
        if tor.poll() is not None or time.monotonic() > deadline:
            stop(tor)
            time.sleep(0.2)
            status.update(state="failed", problem=" / ".join(tail[-2:])[:300])
            sys.exit("tor didn't start: " + (" / ".join(tail[-3:]) or f"exit status {tor.returncode}"))
        time.sleep(0.1)
    time.sleep(0.1)
    with open(cfg["cookie"], "rb") as f:
        cookie = f.read()
    TOR_VERSION[0] = tor_version(cfg["upstream"], cookie) or TOR_VERSION[0]
    srv = listen(cfg["control"], cfg["upstream"], cookie)
    inner = subprocess.Popen(cfg["inner"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    def end(signum, frame):
        stop(inner, 5)
    signal.signal(signal.SIGTERM, end)
    signal.signal(signal.SIGINT, end)
    rc = inner.wait()
    srv.close()
    halt(cfg["upstream"], cookie, tor)
    for p in (cfg["control"], cfg["socks"], cfg["upstream"]):
        try:
            os.unlink(p)
        except OSError:
            pass
    status.update(state="stopped")
    sys.exit(rc)


if __name__ == "__main__":
    main(json.loads(sys.argv[1]))
