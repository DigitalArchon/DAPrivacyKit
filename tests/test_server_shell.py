"""The local server and the app shell (the review of 2026-11-12): who may talk to the server, what it answers with,
quitting, redaction, exports, the state files, the network for the online tests and how commands are run."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from conftest import make_host, skip_if_root


# ------------------------------------------------------------------ host.py: "not installed" means only that

def test_a_program_that_cant_start_isnt_called_missing(tmp_path):
    """Any OSError read as "not installed" (exit status 127), which checks take for "not on this machine": a program
    that may not be run, one in a wrong format, or an input that couldn't be opened. Only a missing program is."""
    from daprivacyscanner.host import CANT_RUN, NOT_FOUND, SystemRunner
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bad = bindir / "badformat"
    bad.write_bytes(b"\x00\x01\x02 not a program")
    bad.chmod(0o755)
    runner = SystemRunner({"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path)})
    r = runner.run(["badformat"])
    assert r.returncode == CANT_RUN and r.cant_run and not r.missing and not r.ok
    assert "couldn't be started" in r.stderr
    r = runner.run(["nosuchprogram"])
    assert r.returncode == NOT_FOUND and r.missing and not r.cant_run
    ok = bindir / "fine"
    ok.write_text("#!/bin/sh\ncat\n")
    ok.chmod(0o755)
    r = runner.run(["fine"], stdin=tmp_path / "no-such-input")
    assert r.cant_run and not r.missing and "its input couldn't be opened" in r.stderr
    (tmp_path / "input").write_text("hello\n")
    r = runner.run(["fine"], stdin=tmp_path / "input")
    assert r.ok and r.stdout == "hello\n"
    gone = bindir / "noshell"                      # a script whose interpreter isn't installed: not installed, as before
    gone.write_text("#!/nonexistent/interpreter\n")
    gone.chmod(0o755)
    assert runner.run(["noshell"]).missing


# ------------------------------------------------------------------ history.py: the user's accepted findings

def test_an_unreadable_accepted_list_is_kept_aside_never_written_over(tmp_path):
    """A damaged accepted.json read as empty, and accepting the next finding saved itself over it alone: every other
    accepted finding, and the notes written for them, were gone without a word. It is kept aside, as the undo log's."""
    from daprivacyscanner.history import Accepted, kept_aside
    from daprivacyscanner.paths import PathResolver
    acc = Accepted(PathResolver(tmp_path, {"HOME": str(tmp_path)}))
    acc.file.parent.mkdir(parents=True)
    acc.file.write_text('{"auth.screen_lock": {"note": "my desk at the office"')       # cut short
    assert acc.all() == {}
    said = acc.damaged()
    assert "can't be read" in said and "kept as it is" in said
    data = acc.set("net.firewall_off", True, "behind the router")
    assert list(data) == ["net.firewall_off"]
    aside = kept_aside(acc.file)
    assert len(aside) == 1 and "my desk at the office" in aside[0].read_text()
    assert "kept aside" in acc.damaged() and str(aside[0]) in acc.damaged()
    acc.file.write_text("[1, 2]")                                                     # JSON, not the list's form
    acc.set("auth.sudo_nopasswd", True)
    assert len(kept_aside(acc.file)) == 2 and list(acc.all()) == ["auth.sudo_nopasswd"]


@skip_if_root
def test_an_accepted_list_that_cant_be_read_at_all_isnt_replaced(cat, tmp_path):
    from fastapi.testclient import TestClient

    from daprivacyscanner.history import Accepted
    from daprivacyscanner.paths import PathResolver
    from daprivacyscanner.server import create_app
    host = make_host(tmp_path)
    acc = Accepted(PathResolver(host.home, host.environ))
    acc.file.parent.mkdir(parents=True)
    acc.file.write_text('{"auth.screen_lock": {"note": "kept"}}')
    acc.file.chmod(0)
    try:
        c = TestClient(create_app("t", cat, make_host=lambda: host))
        r = c.post("/api/accept", headers={"X-Token": "t"}, json={"check_id": "auth.screen_lock", "accept": False})
        assert r.status_code == 400 and "couldn't be changed" in r.json()["error"]
        assert "can't be read" in c.get("/api/state", headers={"X-Token": "t"}).json()["accepted_damaged"]
    finally:
        acc.file.chmod(0o600)
    assert "kept" in acc.file.read_text()


def test_state_files_reach_the_disk_before_they_replace_the_old_ones(tmp_path, monkeypatch):
    """write_json renamed a file into place whose data might not be on the disk yet: after a power cut the list could
    be empty. The file and then its folder are synced."""
    from daprivacyscanner import history
    synced = []
    real = os.fsync

    def fsync(fd):
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        return real(fd)
    monkeypatch.setattr(history.os, "fsync", fsync)
    history.write_json(tmp_path / "state" / "x.json", {"a": 1})
    assert synced == [False, True]
    assert (tmp_path / "state" / "x.json").read_text().startswith("{")


# ------------------------------------------------------------------ app.py: --export as Save… writes

def test_export_never_writes_over_a_file_nor_through_a_link(cat, tmp_path, monkeypatch, capsys):
    """--export truncated whatever FILE was, followed a link there (a planted one, into another file of the user's)
    and kept an existing file's wider mode. It writes as Save… does: a new file, 0600, the next free name."""
    import json

    from daprivacyscanner import app
    from daprivacyscanner.host import Host
    host = make_host(tmp_path)
    monkeypatch.setattr(Host, "local", staticmethod(lambda: host))
    old = os.umask(0o022)
    try:
        out = tmp_path / "everything.json"
        out.write_text("my own notes")
        out.chmod(0o644)
        victim = tmp_path / "victim.txt"
        victim.write_text("precious")
        link = tmp_path / "linked.txt"
        link.symlink_to(victim)
        assert app.export_cli(cat, str(out), False) == 0
        assert out.read_text() == "my own notes" and stat.S_IMODE(out.stat().st_mode) == 0o644
        new = tmp_path / "everything (2).json"
        assert stat.S_IMODE(new.stat().st_mode) == 0o600 and json.loads(new.read_text())["changes"] == []
        said = capsys.readouterr().out
        assert "everything (2).json" in said and "is there already" in said
        assert app.export_cli(cat, str(link), False) == 0
        assert victim.read_text() == "precious" and link.is_symlink()
        assert (tmp_path / "linked (2).txt").read_text().startswith("DA Privacy Kit: everything it keeps")
        assert app.export_cli(cat, str(tmp_path / "nowhere" / "x.txt"), False) == 2
        assert app.export_cli(cat, str(tmp_path) + "/", False) == 2
    finally:
        os.umask(old)


# ------------------------------------------------------------------ online.py: https only, ports, Stop

@pytest.mark.parametrize("url, ok", [
    ("https://api.ipify.org", True), ("https://[2001:db8::1]:8443/x", True),
    ("http://192.168.1.1:5000/rootDesc.xml", True), ("http://10.0.0.138/desc", True), ("http://[fe80::1%25eth0]/d", True),
    ("http://127.0.0.1:8080/", True), ("http://localhost/", True), ("http://router.local/", True),
    ("http://example.com/", False), ("http://8.8.8.8/", False), ("http://[2001:4860::8888]/", False),
    ("http://192.168.1.1.evil.example/", False), ("file:///etc/passwd", False), ("ftp://ftp.debian.org/x", False),
    ("data:text/plain,hi", False), ("https:///nohost", False)])
def test_only_https_is_used_plain_http_only_on_the_local_network(url, ok):
    from daprivacyscanner import online
    if ok:
        online.check_url(url)
    else:
        with pytest.raises(online.NotHttps):
            online.check_url(url)


def test_the_real_opener_reads_no_files_and_nothing_but_http(tmp_path):
    """build_opener added file:, ftp: and data: handlers: an address in online.json or a download index naming
    file:///home/... was read from the disk."""
    import urllib.request

    from daprivacyscanner import online
    secret = tmp_path / "secret.txt"
    secret.write_text("the user's file")
    net = online.RealNet()
    r = net.http_get(f"file://{secret}")
    assert r.status is None and b"the user's file" not in r.body and "https" in r.error
    for url in (f"file://{secret}", "data:text/plain,hi", "ftp://127.0.0.1/x"):
        with pytest.raises(online.NotHttps):
            net._opener.open(urllib.request.Request(url))
    assert not any(isinstance(h, (urllib.request.FileHandler, urllib.request.FTPHandler, urllib.request.DataHandler))
                   for h in net._opener.handlers)
    r = net.download(f"file://{secret}", tmp_path / "out")
    assert r.status is None and not (tmp_path / "out").exists()


def _follow(url, to, hosts=()):
    import io
    import urllib.request
    from email.message import Message

    from daprivacyscanner import online
    req = urllib.request.Request(url)
    req.allowed_hosts = tuple(hosts)
    return online.ConfinedRedirects().redirect_request(req, io.BytesIO(), 302, "Found", Message(), to)


def test_a_redirect_to_another_port_of_the_same_host_is_stopped():
    from daprivacyscanner import online
    assert _follow("https://api.ipify.org/", "https://api.ipify.org:443/x") is not None
    assert _follow("http://192.168.1.1/", "https://192.168.1.1/x") is not None        # the upgrade, 80 to 443
    assert _follow("http://192.168.1.1:5000/a", "http://192.168.1.1:5000/b") is not None
    for to, hosts in [("https://api.ipify.org:8443/x", ()), ("http://192.168.1.1:8080/b", ()),
                      ("https://dist.torproject.org:8443/x", ("dist.torproject.org",)),
                      ("http://example.org/x", ())]:
        src = "http://192.168.1.1:5000/a" if to.startswith("http://192") else "https://api.ipify.org/"
        with pytest.raises(online.Redirected):
            _follow(src, to, hosts)
    with pytest.raises(online.Redirected, match="isn't https"):     # same host and port, but plain http on the internet
        _follow("http://example.org/a", "http://example.org/b")


class _SlowServer:
    """A server on 127.0.0.1 that sends headers saying `length` bytes, then `first` bytes, then a byte every `drip`
    seconds (or nothing more, drip None) until closed."""

    def __init__(self, length=10_000_000, first=1000, drip=None):
        import socket
        import threading
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.length, self.first, self.drip, self.closed = length, first, drip, threading.Event()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        import time
        conn, _ = self.sock.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {self.length}\r\n\r\n".encode() + b"x" * self.first)
            while not self.closed.is_set():
                if self.drip is not None:
                    try:
                        conn.sendall(b"x")
                    except OSError:
                        return
                self.closed.wait(self.drip or 0.1)

    def close(self):
        self.closed.set()
        self.sock.close()


def test_stop_ends_a_stalled_download_at_once(tmp_path, monkeypatch):
    """The download read 1 MiB at a time, and a read waited for the whole MiB however slowly it came: Stop wasn't
    looked at for as long as a stalled server liked (up to the 60 s timeout per read, and on)."""
    import threading
    import time

    from daprivacyscanner import online
    monkeypatch.setattr(online, "STOP_EVERY", 0.1)
    srv = _SlowServer()
    try:
        stop, done = threading.Event(), []
        t = threading.Thread(target=lambda: done.append(online.RealNet().download(
            f"http://127.0.0.1:{srv.port}/f", tmp_path / "f", stop=stop.is_set, timeout=30)))
        t.start()
        time.sleep(0.5)
        t0 = time.monotonic()
        stop.set()
        t.join(5)
        assert done and done[0].error == "stopped" and time.monotonic() - t0 < 2
        assert (tmp_path / "f").stat().st_size == 1000
    finally:
        srv.close()


def test_an_answer_trickling_in_is_cut_off_at_its_timeout(tmp_path):
    import time

    from daprivacyscanner import online
    srv = _SlowServer(length=5_000_000, first=10, drip=0.05)
    try:
        t0 = time.monotonic()
        r = online.RealNet().http_get(f"http://127.0.0.1:{srv.port}/x", timeout=0.6)
        assert r.status is None and "took longer" in r.error and time.monotonic() - t0 < 3
    finally:
        srv.close()
