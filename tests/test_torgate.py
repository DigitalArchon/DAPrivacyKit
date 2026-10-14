"""Tor Browser's gate (tools/torgate.py): the control-port filter between the browser, which has no
network, and tor, which has; tried against a fake tor on a Unix socket. Nothing here runs tor."""

from __future__ import annotations

import socket
import threading
import time

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
    G.follow(Tor, st, [])
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
