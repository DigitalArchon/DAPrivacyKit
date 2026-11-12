"""Tor Browser's keeper and gate (tools/torgate.py): the control-port filter between the browser, which has no
network, and tor, which has; tried against a fake tor on a Unix socket; and the keeper, which starts tor's, the
gate's and the browser's sandboxes side by side, run whole with stand-ins for bubblewrap, tor and the browser.
Nothing here runs tor or bubblewrap."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from daprivacyscanner.tools import torgate as G

COOKIE = bytes(range(32))


@pytest.mark.parametrize("line", [
    "authenticate ", "AUTHENTICATE 00ff", "PROTOCOLINFO 1", "GETINFO version", "GETINFO status/bootstrap-phase",
    "GETINFO circuit-status", "GETINFO ns/id/$" + "AB" * 20, "GETINFO ip-to-country/203.0.113.9",
    "GETINFO ns/purpose/bridge", "GETINFO net/listeners/socks", "GETCONF BRIDGE", "getconf ClientTransportPlugin",
    "SETEVENTS CIRC STREAM", "SETEVENTS", "SIGNAL NEWNYM", "ONION_CLIENT_AUTH_VIEW",
    "ONION_CLIENT_AUTH_ADD " + "a" * 56 + " x25519:" + "A" * 43 + "= Flags=Permanent",
    "ONION_CLIENT_AUTH_REMOVE " + "b" * 56 + ".onion", "QUIT"])
def test_what_tor_browser_needs_passes(line):
    assert G.decide(line)[1] != G.FILTERED


@pytest.mark.parametrize("line", [
    "SETCONF Socks5Proxy=203.0.113.9:1080", "SETCONF UseBridges=1 Bridge=\"203.0.113.9:443\"", "RESETCONF Bridge",
    "SAVECONF", "LOADCONF", "TAKEOWNERSHIP", "DROPOWNERSHIP", "SIGNAL SHUTDOWN", "SIGNAL HALT", "SIGNAL DUMP",
    "GETINFO address", "GETINFO fingerprint", "GETINFO config-file", "GETINFO version address",
    "GETINFO ip-to-country/1.2.3.4;x", "GETCONF ControlPort", "SETEVENTS CIRC ADDRMAP", "SETEVENTS DEBUG",
    "ADD_ONION NEW:BEST Port=80", "MAPADDRESS 1.2.3.4=evil.example", "EXTENDCIRCUIT 0 $" + "AB" * 20,
    "ONION_CLIENT_AUTH_ADD x x", "AUTHCHALLENGE SAFECOOKIE 00", "+POSTDESCRIPTOR"])
def test_anything_that_changes_tor_is_refused(line):
    assert G.decide(line) == ("reply", G.FILTERED)


class FakeTor:
    """A control port: wants the cookie first, answers GETINFO circuit-status with a data block,
    and sends an event after every reply. Records every command it gets."""

    def __init__(self, path, delay=0.0):
        self.got: list[str] = []
        self.delay = delay                              # before answering circuit-status: a slow tor
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(path))
        self.srv.listen(1)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        c, _ = self.srv.accept()
        for line in G.lines(c):
            cmd = line.decode().strip()
            self.got.append(cmd)
            if cmd.startswith("AUTHENTICATE"):
                c.sendall(b"250 OK\r\n" if cmd == "AUTHENTICATE " + COOKIE.hex() else b"515 Bad authentication\r\n")
            elif cmd == "GETINFO version":
                c.sendall(b"250-version=0.4.8.17 (git-9a2d5e1f2b0c8a71)\r\n250 OK\r\n")
            elif cmd == "GETINFO circuit-status":
                time.sleep(self.delay)
                c.sendall(b"250+circuit-status=\r\n1 BUILT $AB~relay PURPOSE=GENERAL\r\n.\r\n250 OK\r\n"
                          b"650 CIRC 1 BUILT $AB~relay\r\n")
            else:
                c.sendall(b"250 OK\r\n")


def talk(client, *cmds, events=None):
    """Each command's reply; asynchronous events (650) collected apart in `events`."""
    f = client.makefile("rb")
    out = []
    for cmd in cmds:
        client.sendall(cmd.encode() + b"\r\n")
        reply = []
        while True:
            ln = f.readline().decode()
            if ln.startswith("650"):
                events.append(ln) if events is not None else None
                continue
            reply.append(ln)
            if len(ln) >= 4 and ln[3] == " ":
                break
        out.append("".join(reply))
    return out


def test_the_filter_between_the_browser_and_tor(tmp_path):
    tor = FakeTor(tmp_path / "tor-control")
    ours, browser = socket.socketpair()
    t = threading.Thread(target=G.serve, args=(ours, str(tmp_path / "tor-control"), COOKIE), daemon=True)
    t.start()
    events = []
    replies = talk(browser, "authenticate ", "GETINFO circuit-status", "SETCONF Socks5Proxy=203.0.113.9:1080",
                   "SIGNAL NEWNYM", "+LOADCONF\r\nSocksPort 9050\r\n.", "QUIT",
                   events=events)
    assert replies[0] == "250 OK\r\n"                                           # the browser's own: answered here
    assert "1 BUILT $AB~relay" in replies[1] and replies[1].endswith("250 OK\r\n")
    assert replies[2] == "510 Command filtered\r\n" and replies[3] == "250 OK\r\n"
    assert events and events[0] == "650 CIRC 1 BUILT $AB~relay\r\n"             # events come through, whole
    assert replies[4] == "510 Command filtered\r\n" and replies[5] == "250 closing connection\r\n"
    t.join(5)
    # tor saw the cookie, then only what passed
    assert tor.got == ["AUTHENTICATE " + COOKIE.hex(), "GETINFO circuit-status", "SIGNAL NEWNYM"]


def test_replies_come_in_the_order_of_the_commands(tmp_path):
    """Two commands sent at once, the first forwarded (tor answers after a moment), the second answered by the
    gate itself: the browser must get the first's reply first, as the control protocol promises."""
    tor = FakeTor(tmp_path / "tor-control", delay=0.3)
    ours, browser = socket.socketpair()
    t = threading.Thread(target=G.serve, args=(ours, str(tmp_path / "tor-control"), COOKIE), daemon=True)
    t.start()
    browser.sendall(b"AUTHENTICATE\r\n")
    f = browser.makefile("rb")
    assert f.readline() == b"250 OK\r\n"
    browser.sendall(b"GETINFO circuit-status\r\nSETCONF Socks5Proxy=1.2.3.4:1\r\nSIGNAL NEWNYM\r\nQUIT\r\n")
    got = b""
    while b"closing connection" not in got:
        ln = f.readline()
        if not ln:
            break
        got += ln
    assert got.index(b"1 BUILT $AB~relay") < got.index(b"510 Command filtered") < got.index(b"250 closing")
    assert got.count(b"250 OK\r\n") == 2                                     # circuit-status's end, then NEWNYM's
    t.join(5)
    assert not t.is_alive() and tor.got[-1] == "SIGNAL NEWNYM"


def test_a_line_too_long_ends_the_connection_even_with_its_ending_in_the_same_read(tmp_path):
    ours, browser = socket.socketpair()
    browser.sendall(b"GETINFO " + b"x" * (G.MAX_LINE + 10) + b"\r\n")
    assert list(G.lines(ours)) == []
    ours, browser = socket.socketpair()
    browser.sendall(b"GETINFO version\r\n")
    browser.close()
    assert list(G.lines(ours)) == [b"GETINFO version\r\n"]


def test_a_bad_cookie_closes_the_browsers_connection(tmp_path):
    FakeTor(tmp_path / "tor-control")
    ours, browser = socket.socketpair()
    G.serve(ours, str(tmp_path / "tor-control"), b"wrong")
    browser.settimeout(5)
    assert browser.recv(100) == b""


def test_bootstrap_lines_become_the_status(tmp_path):
    class Tor:
        stdout = [b"Oct 05 19:00:00.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors\n",
                  b"Oct 05 19:00:01.000 [warn] Problem bootstrapping. Stuck at 45%: Connection refused.\n",
                  b"Oct 05 19:00:02.000 [notice] Bootstrapped 100% (done): Done\n"]
    st = G.Status(str(tmp_path / "status.json"))
    states = []
    real = st.update
    st.update = lambda **kw: (states.append(dict(kw)), real(**kw))
    G.follow(Tor.stdout, st, [])
    assert states[0] == {"state": "connecting", "progress": 45, "summary": "Asking for relay descriptors"}
    assert states[1]["problem"].startswith("Problem bootstrapping. Stuck at 45%")
    assert states[2]["state"] == "connected" and states[-1] == {"state": "stopped"}


def test_protocolinfo_names_tor_s_own_version(tmp_path, monkeypatch):
    FakeTor(tmp_path / "tor-control")
    assert G.tor_version(str(tmp_path / "tor-control"), COOKIE) == "0.4.8.17"
    monkeypatch.setattr(G, "TOR_VERSION", ["0.4.8.17"])
    assert G.decide("PROTOCOLINFO 1") == ("reply", '250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n'
                                                   '250-VERSION Tor="0.4.8.17"\r\n250 OK')
    assert G.tor_version(str(tmp_path / "nothing-here"), COOKIE) is None


# ------------------------------------------------------------------ the keeper, whole

# bubblewrap's stand-in: its options from --args (sealed) or the command line, written down, then the command run
FAKE_BWRAP = """\
import json, os, sys
args, sealed = sys.argv[1:], False
if args[:1] == ["--args"]:
    fd, data = int(args[1]), b""
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        data += chunk
    os.close(fd)
    args, sealed = [a.decode() for a in data.split(b"\\0") if a] + args[2:], True
i = args.index("--")
with open(os.path.join(args[args.index("--log") + 1], "bwrap-%d" % os.getpid()), "w") as f:
    json.dump({"sealed": sealed, "role": args[args.index("--role") + 1]}, f)
os.execv(args[i + 1], args[i + 1:])
"""
# tor's: its sockets and cookie in the folder, a bootstrap line on its output, a control port that halts
FAKE_TOR = """\
import os, socket, sys, time
d, how = sys.argv[1], sys.argv[2]
if how == "fail":
    print("Nov 12 00:00:00.000 [err] Reading config failed", flush=True)
    sys.exit(1)
socks = socket.socket(socket.AF_UNIX)
socks.bind(d + "/socks")
socks.listen(1)
ctl = socket.socket(socket.AF_UNIX)
ctl.bind(d + "/tor-control")
ctl.listen(4)
with open(d + "/cookie", "wb") as f:
    f.write(bytes(range(32)))
print("Nov 12 00:00:00.000 [notice] Bootstrapped 100% (done): Done", flush=True)
while True:
    conn, _ = ctl.accept()
    for line in conn.makefile("rb"):
        line = line.strip()
        if line == b"SIGNAL HALT":
            open(d + "/halted", "w").close()
            sys.exit(0)
        if line == b"GETINFO version":
            conn.sendall(b"250-version=0.4.8.99\\r\\n250 OK\\r\\n")
        elif line == b"QUIT":
            conn.sendall(b"250 closing connection\\r\\n")
            break
        else:
            conn.sendall(b"250 OK\\r\\n")
    conn.close()
"""
# the browser's: what it gets of the tor folder, through the gate's filter
FAKE_BROWSER = """\
import os, socket, stat, sys
stage, out = sys.argv[1], sys.argv[2]
kinds = [stat.S_ISSOCK(os.lstat(os.path.join(stage, n)).st_mode) for n in ("socks", "control")]
c = socket.socket(socket.AF_UNIX)
c.connect(os.path.join(stage, "control"))
f = c.makefile("rb")
replies = []
for cmd in (b"AUTHENTICATE", b"GETINFO version", b"SETCONF Socks5Proxy=203.0.113.9:1080"):
    c.sendall(cmd + b"\\r\\n")
    while True:
        ln = f.readline()
        replies.append(ln.decode().strip())
        if ln[3:4] == b" ":
            break
with open(out, "w") as o:
    o.write(repr((kinds, replies)))
sys.exit(7)
"""


def keeper_cfg(tmp_path, how="ok"):
    d = tmp_path / "tor"
    stage = tmp_path / "tor-sockets"
    logs = tmp_path / "bwraps"
    for p in (d, stage, logs):
        p.mkdir()
    bwrap = tmp_path / "bwrap"
    bwrap.write_text(f"#!{sys.executable}\n{FAKE_BWRAP}")
    bwrap.chmod(0o700)
    py = sys.executable
    src = Path(G.__file__).read_text()
    gate_cfg = {"role": "gate", "upstream": f"{d}/tor-control", "control": f"{d}/control", "socks": f"{d}/socks",
                "cookie": f"{d}/cookie", "status": f"{d}/status.json", "wait": 10}

    def box(role, *cmd):
        return [str(bwrap), "--die-with-parent", "--role", role, "--log", str(logs), "--", *cmd]
    cfg = {"role": "keeper", "env": {"PATH": "/usr/bin:/bin"}, "sync": None, "filters": {}, "wait": 20,
           "tor": box("tor", py, "-I", "-c", FAKE_TOR, str(d), how),
           "gate": box("gate", py, "-I", "-c", src, json.dumps(gate_cfg)),
           "browser": box("browser", py, "-I", "-c", FAKE_BROWSER, str(stage), str(tmp_path / "browser.txt")),
           "sockets": {"from": str(d), "to": str(stage), "names": ["socks", "control"]}}
    return cfg, d, stage, logs


def run_keeper(cfg):
    return subprocess.run([sys.executable, "-I", "-c", Path(G.__file__).read_text(), json.dumps(cfg)],
                          capture_output=True, text=True, timeout=60, cwd="/")


def test_the_keeper_starts_the_three_side_by_side_and_stops_tor_when_the_browser_ends(tmp_path):
    """Each sandbox is started by the keeper itself (none inside another: Ubuntu's AppArmor profile for bubblewrap
    refuses that), tor's and the gate's options sealed; the browser's only once the gate says tor is up, with the two
    sockets linked where no sandbox can swap them; the gate filters; tor is asked to halt once the browser has ended,
    the links removed, and the keeper ends with the browser's status."""
    if len(str(tmp_path)) > 80:
        pytest.skip("a Unix socket's path holds 107 bytes")
    cfg, d, stage, logs = keeper_cfg(tmp_path)
    r = run_keeper(cfg)
    assert r.returncode == 7, r.stderr
    kinds, replies = eval((tmp_path / "browser.txt").read_text())       # noqa: S307 - the stand-in's own repr
    assert kinds == [True, True]
    assert replies == ["250 OK", "250-version=0.4.8.99", "250 OK", "510 Command filtered"]
    assert (d / "halted").exists() and json.loads((d / "status.json").read_text())["state"] == "stopped"
    assert sorted(os.listdir(stage)) == [] and not (d / "control").exists()
    seen = {json.loads(p.read_text())["role"]: json.loads(p.read_text())["sealed"] for p in logs.iterdir()}
    assert seen == {"tor": True, "gate": True, "browser": False}


def test_a_tor_that_doesnt_start_never_starts_the_browser(tmp_path):
    if len(str(tmp_path)) > 80:
        pytest.skip("a Unix socket's path holds 107 bytes")
    cfg, d, stage, logs = keeper_cfg(tmp_path, how="fail")
    r = run_keeper(cfg)
    assert r.returncode != 0 and "tor didn't start: " in r.stderr and "Reading config failed" in r.stderr
    assert not (tmp_path / "browser.txt").exists()
    assert {json.loads(p.read_text())["role"] for p in logs.iterdir()} == {"tor", "gate"}
    assert json.loads((d / "status.json").read_text())["state"] in ("failed", "stopped")


def test_a_link_in_a_sockets_place_is_never_passed_on(tmp_path):
    """tor's sandbox can write in the tor folder: a link it left as "control" would have had bubblewrap bind what it
    points to (a file in the home) into the browser's sandbox. Hard-linked into the app's folder, a link stays a
    link, and is refused there."""
    d, stage = tmp_path / "t", tmp_path / "s"
    d.mkdir()
    stage.mkdir()
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(d / "socks"))
    secret = tmp_path / "id_ed25519"
    secret.write_text("PRIVATE KEY")
    (d / "control").symlink_to(secret)
    spec = {"from": str(d), "to": str(stage), "names": ["socks", "control"]}
    with pytest.raises(G.Start, match="control socket isn't a socket of yours"):
        G.link_sockets(spec)
    assert stat.S_ISSOCK(os.lstat(stage / "socks").st_mode) and not os.path.lexists(stage / "control")
    (d / "control").unlink()
    (d / "control").write_text("")
    with pytest.raises(G.Start):
        G.link_sockets(spec)
    with pytest.raises(G.Start, match="couldn't be passed on"):
        G.link_sockets({**spec, "names": ["missing"]})
    G.unlink_sockets(spec)
    assert os.listdir(stage) == []
