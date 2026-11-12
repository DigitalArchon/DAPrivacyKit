"""Tor Browser's keeper and gate (docs/TECHNICAL.md, Tools; tools/sandbox.py), run by the host's
`python3 -I -c <this file's source> <config>`. Standard library only, and nothing of the app's imported: the
AppImage that started it may be gone by the time the browser closes. One file, two parts (the config's "role"):

The keeper runs on the computer, outside any sandbox, and starts three sandboxes side by side (sandbox.tor_argv):
tor's, on the computer's network; the gate's, with no network; the browser's, with no network. They meet only
through the Unix sockets in the app's tor folder: tor's SOCKS and control ports, and the gate's filtered control
port, which is all the browser's sandbox gets of them. Side by side, not one inside another, because each must be
the first bubblewrap: under Ubuntu's AppArmor profile for bubblewrap (bwrap-userns-restrict, on in 24.10 and later)
whatever a bubblewrap starts runs in its unpriv_bwrap profile, without capabilities even in a namespace of its own,
so a bubblewrap started inside one can't make its namespaces ("No permissions to create a new namespace", the
kernel's apparmor="DENIED" operation="capable" profile="unpriv_bwrap" capname="sys_admin": Tor Browser's sandbox
couldn't start there at all, found on Ubuntu 26.04 on 2026-11-12). The keeper:

1. starts the gate's sandbox, then tor's, tor's log going to the gate (a pipe: the keeper reads none of it);
2. waits until the gate says tor is up and its filter listening (a line on another pipe), then starts the
   browser's sandbox; it reads nothing else of any of them, only their exit statuses;
3. waits for the browser's sandbox, whose command (sandbox.STAY) lasts until no browser process is left, also when
   the browser restarts itself as a new process; then tells the gate to stop tor (by closing a pipe), and ends
   whatever is left. Each sandbox dies with the keeper (--die-with-parent), and the browser's with the gate: a
   browser is never left running with tor or its filter gone.

The gate runs in its sandbox, with no network and nothing of the browser's (its display, sound, profile or
processes), only the tor folder:

1. follows tor's log (its stdin) for the bootstrap status (written to status.json, which the app shows: Tor
   Browser's own Connect page is off when it doesn't start tor);
2. listens on the browser's control socket and filters what goes to tor's: what Tor Browser needs to
   show circuits, ask for a new identity and keep onion-site keys passes; anything that would change
   tor's settings (a proxy or a bridge of the browser's choosing would make tor reveal the address) is
   refused with 510. The browser authenticates to the filter with anything; the filter authenticates
   to tor with the cookie, which the browser never sees;
3. once told the browser has ended, stops tor (halt: over its control port, so that it saves its state).

Messages for the user (why it couldn't start) go to stderr, which is the start log, a memory file of the app's;
tor's own log is kept in memory, its last lines only."""

import json
import os
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time

NO_FILTER = "The sandbox's system-call filter couldn't be made"     # browser.NEVER_RAN knows it: before the browser ran
WAIT_FOR_TOR = 60                   # seconds for tor to open its sockets
READY_MARK = b"ready\n"             # the gate to the keeper: tor's sockets are there and the filter listens
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


def follow(log, status, tail):
    """tor's log (its output, as lines of bytes): the bootstrap progress into the status, warnings kept as the last
    problem; "stopped" once it ends, as tor's output closes when tor has."""
    for raw in log:
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


def halt(upstream, cookie, ended, wait=10):
    """tor asked to exit cleanly over its control port (SIGNAL HALT: as SIGTERM, it saves its state first), and
    waited for: `ended(timeout)` says whether it has (the gate: its log's end). Only then does the keeper end what is
    left of tor's sandbox, since a signal to its bubblewrap ends tor at once, unsaved. Whether it ended."""
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.settimeout(5)
        up.connect(upstream)
        up.sendall(b"AUTHENTICATE " + cookie.hex().encode() + b"\r\nSIGNAL HALT\r\n")
        return ended(wait)
    except OSError:
        return ended(0)
    finally:
        up.close()


def stop(proc, wait=10):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(wait)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def ender(proc, wait=5):
    """The keeper's SIGTERM handler: the browser's sandbox is told to stop, and killed `wait` seconds later if it
    hasn't. Signals only: a wait here, on the lock a wait in the main thread holds, waited for ever (the gate hung on
    SIGTERM, found in the review of 2026-10-17 on Mint)."""
    def end(signum, frame):
        try:
            proc.send_signal(signal.SIGTERM)
        except OSError:
            return
        t = threading.Timer(wait, lambda: proc.returncode is None and _kill(proc))
        t.daemon = True
        t.start()
    return end


def _kill(proc):
    try:
        proc.kill()
    except OSError:
        pass


FILTER_MARK = re.compile(r"@SECCOMP:([a-z]+)@")


def with_filters(argv, programs):
    """`argv` (a bubblewrap's command) with each filter's placeholder (sandbox.gate_filter) replaced by a descriptor of
    that filter, a memory file made here from `programs` (profile -> the program, in hex): (argv, the descriptors to
    pass, which the caller closes once it has started it). A placeholder for a filter not given is refused."""
    out, fds = [], []
    try:
        for a in argv:
            m = FILTER_MARK.fullmatch(a)
            if m is None:
                out.append(a)
                continue
            fd = os.memfd_create("seccomp-" + m.group(1))
            fds.append(fd)
            os.write(fd, bytes.fromhex(programs[m.group(1)]))
            os.lseek(fd, 0, os.SEEK_SET)
            out.append(str(fd))
    except (KeyError, ValueError, OSError):
        for fd in fds:
            os.close(fd)
        raise
    return out, fds


def seal(argv):
    """`argv` (a bubblewrap's command) with its options, everything before "--", read from a memory file (--args N):
    without --as-pid-1 bubblewrap's own init is the sandbox's PID 1, whose command line anything inside can read, and
    these options name the folders bound in from the user's home (sandbox.sealed does the same). bubblewrap closes the
    descriptor once it has read it. Returns (the command, the descriptor to pass, which the caller closes)."""
    end = argv.index("--", 1)
    fd = os.memfd_create("bwrap-args")
    try:
        data = b"".join(a.encode() + b"\0" for a in argv[1:end])
        while data:
            data = data[os.write(fd, data):]
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        os.close(fd)
        raise
    return [argv[0], "--args", str(fd), *argv[end:]], fd


def _close(fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


# ------------------------------------------------------------------ the keeper, on the computer

class Start(Exception):
    """A sandbox couldn't be started: why, for the start log (browser.NEVER_RAN knows these: before the browser ran)."""


def spawn(argv, filters, sealed, what, keep=(), **kw):
    """One of the three sandboxes, started by the keeper itself, so that it is the first bubblewrap: its filter's
    placeholder made a descriptor (with_filters), its options sealed where its init is its PID 1 (`sealed`), `keep`'s
    descriptors passed on as well, and nothing else of the keeper's."""
    fds = []
    try:
        argv, fds = with_filters(argv, filters)
        if sealed:
            argv, args = seal(argv)
            fds.append(args)
    except (KeyError, ValueError, OSError):
        _close(fds)
        raise Start(NO_FILTER) from None
    try:
        return subprocess.Popen(argv, cwd="/", pass_fds=(*fds, *keep), **kw)
    except OSError as e:
        raise Start(f"{what} couldn't be started: {e.strerror or e}") from None
    finally:
        _close(fds)


def ready(fd, timeout):
    """The gate's word that tor is up and its filter listens (READY_MARK), within `timeout` seconds: whether it came.
    Nothing else of what the gate writes is read, and at most that line."""
    deadline, got = time.monotonic() + timeout, b""
    while len(got) < len(READY_MARK):
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            return False
        chunk = os.read(fd, len(READY_MARK) - len(got))
        if not chunk:
            return False
        got += chunk
    return got == READY_MARK


def link_sockets(spec):
    """tor's SOCKS socket and the gate's control socket, hard-linked from the tor folder into a folder of the app's
    that no sandbox is given (`spec`: {"from", "to", "names"}), each checked there to be a socket of the user's; the
    browser's sandbox binds them from there. tor's sandbox can write in the tor folder: a link it left in a socket's
    place would have had bubblewrap, which resolves a bind's source on the computer, bind what it points to (a file
    in the home) into the browser's sandbox. A hard link of a link is a link (linkat without AT_SYMLINK_FOLLOW), and in
    the app's folder nothing can swap it between the check and the bind. Raises Start."""
    import stat
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    src = dst = None
    try:
        src, dst = os.open(spec["from"], flags), os.open(spec["to"], flags)
        for name in spec["names"]:
            try:
                os.unlink(name, dir_fd=dst)
            except FileNotFoundError:
                pass
            os.link(name, name, src_dir_fd=src, dst_dir_fd=dst, follow_symlinks=False)
            st = os.stat(name, dir_fd=dst, follow_symlinks=False)
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
                os.unlink(name, dir_fd=dst)
                raise Start(f"tor didn't start: its {name} socket isn't a socket of yours")
    except OSError as e:
        raise Start(f"tor didn't start: its sockets couldn't be passed on ({e.strerror or e})") from None
    finally:
        _close(fd for fd in (src, dst) if fd is not None)


def unlink_sockets(spec):
    """The links link_sockets made, once the browser has ended."""
    try:
        dst = os.open(spec["to"], os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return
    try:
        for name in spec["names"]:
            try:
                os.unlink(name, dir_fd=dst)
            except OSError:
                pass
    finally:
        os.close(dst)


def watch(browser, gate):
    """Waits for the browser's sandbox to end, and returns its exit status. The gate ending first (the filter gone)
    ends the browser too, as when the browser's sandbox was inside the gate's and died with it. By pidfds where the
    kernel has them, else every half second."""
    fds = {}
    try:
        for p in (browser, gate):
            fds[os.pidfd_open(p.pid)] = p
    except (AttributeError, OSError):
        _close(fds)
        fds = {}
    told = False
    try:
        while browser.poll() is None:
            if not told and gate.poll() is not None:
                told = True
                ender(browser, 5)(None, None)
                for fd in [fd for fd, p in fds.items() if p is gate]:
                    os.close(fd)
                    del fds[fd]
            if fds:
                select.select(list(fds), [], [])
            else:
                time.sleep(0.5)
    finally:
        _close(fds)
    return browser.returncode


def keep(cfg):
    filters, env, sync = cfg.get("filters") or {}, cfg.get("env") or {}, cfg.get("sync")
    log_r, log_w = os.pipe()                # tor's output, to the gate
    ready_r, ready_w = os.pipe()            # the gate's word that tor is up
    halt_r, halt_w = os.pipe()              # closed by the keeper once the browser has ended: the gate stops tor
    gate = tor = None
    try:
        gate = spawn([*cfg["gate"], str(halt_r)], filters, True, "tor", keep=(halt_r,), env=env, stdin=log_r,
                     stdout=ready_w)
        tor = spawn(cfg["tor"], filters, True, "tor", env=env, stdin=subprocess.DEVNULL, stdout=log_w,
                    stderr=subprocess.STDOUT)
    except Start as e:
        for p in (tor, gate):
            if p is not None:
                stop(p, 5)
        sys.exit(str(e))
    finally:
        _close((log_r, log_w, ready_w, halt_r))
    if not ready(ready_r, cfg.get("wait", WAIT_FOR_TOR + 30)):
        timed_out = gate.poll() is None
        stop(tor, 5)
        stop(gate, 5)
        if timed_out:
            sys.exit("tor didn't start in time")
        sys.exit(gate.returncode if gate.returncode > 0 else 1)     # the gate said why, in the start log
    os.close(ready_r)

    def done():                             # the gate stops tor (over its control port) and waits for it
        os.close(halt_w)
        for p, wait in ((gate, 15), (tor, 5)):
            try:
                p.wait(wait)
            except subprocess.TimeoutExpired:
                pass
            stop(p, 5)
        unlink_sockets(cfg["sockets"])
    try:
        link_sockets(cfg["sockets"])
        browser = spawn(cfg["browser"], filters, False, "The browser's sandbox", keep=() if sync is None else (sync,),
                        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except Start as e:
        done()
        sys.exit(str(e))
    finally:
        if sync is not None:
            _close((sync,))                 # bubblewrap holds it now, for as long as the browser's sandbox runs
    end = ender(browser, 5)
    signal.signal(signal.SIGTERM, end)
    signal.signal(signal.SIGINT, end)
    rc = watch(browser, gate)
    done()
    sys.exit(rc if rc >= 0 else 128 - rc)


# ------------------------------------------------------------------ the gate, in its sandbox

def gate(cfg, halt_fd):
    status = Status(cfg["status"])
    tail = []
    follower = threading.Thread(target=follow, args=(sys.stdin.buffer, status, tail), daemon=True)
    follower.start()
    deadline = time.monotonic() + cfg.get("wait", WAIT_FOR_TOR)
    while not all(os.path.exists(p) for p in (cfg["upstream"], cfg["socks"], cfg["cookie"])):
        if not follower.is_alive() or time.monotonic() > deadline:
            follower.join(0.5)
            status.update(state="failed", problem=" / ".join(tail[-2:])[:300])
            sys.exit("tor didn't start: " + (" / ".join(tail[-3:]) or "it ended"))
        time.sleep(0.1)
    time.sleep(0.1)
    with open(cfg["cookie"], "rb") as f:
        cookie = f.read(1024)
    TOR_VERSION[0] = tor_version(cfg["upstream"], cookie) or TOR_VERSION[0]
    srv = listen(cfg["control"], cfg["upstream"], cookie)
    os.write(1, READY_MARK)
    null = os.open(os.devnull, os.O_WRONLY)           # nothing more goes to the keeper
    os.dup2(null, 1)
    os.close(null)
    while True:                                       # until the keeper closes it: the browser has ended
        try:
            if not os.read(halt_fd, 64):
                break
        except InterruptedError:
            continue
        except OSError:
            break
    srv.close()
    halt(cfg["upstream"], cookie, lambda t: (follower.join(t), not follower.is_alive())[1])
    for p in (cfg["control"], cfg["socks"], cfg["upstream"]):
        try:
            os.unlink(p)
        except OSError:
            pass
    status.update(state="stopped")


def main(argv):
    cfg = json.loads(argv[1])
    if cfg.get("role") == "keeper":
        keep(cfg)
    elif cfg.get("role") == "gate":
        gate(cfg, int(argv[2]))
    else:
        sys.exit("tor couldn't be started: the configuration names no role")


if __name__ == "__main__":
    main(sys.argv)


