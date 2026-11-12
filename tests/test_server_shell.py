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


# ------------------------------------------------------------------ launch.py: what lasting entries may run

def _program(folder: Path, mode=0o755) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / "DAPrivacyKit-0.1.0b8-x86_64.AppImage"
    p.write_text("#!/bin/sh\n")
    p.chmod(mode)
    return p


@pytest.fixture
def safe_above(tmp_path, monkeypatch):
    """pytest's own folders, above tmp_path, are in /tmp, which anyone may write to: seen as a home's folders are
    (root's, 0755), so what the tests make below them decides."""
    from daprivacyscanner import launch
    real, above = launch._status, {str(p) for p in tmp_path.parents}

    def status(p, follow):
        st = real(p, follow)
        if p in above:
            return os.stat_result((stat.S_IFDIR | 0o755, st.st_ino, st.st_dev, st.st_nlink, 0, 0, st.st_size,
                                   int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
        return st
    monkeypatch.setattr(launch, "_status", status)
    tmp_path.chmod(0o755)


def test_a_program_anyone_could_replace_isnt_put_into_lasting_entries(tmp_path, monkeypatch, safe_above):
    """The timer, the Outbox's units, the right-click entries and a Box's menu entry run the AppImage's path as it is
    when they start: run from /tmp or a shared folder, once the file was gone another account could put its own
    program there, and it ran as this account. Refused, saying why and what to do."""
    from daprivacyscanner import launch
    from daprivacyscanner.tools import integration as I
    mine = _program(tmp_path / "Applications")
    tmp_path.chmod(0o755)
    assert launch.unsafe_place(str(mine)) == "" and I.command_problem([str(mine)], "the timer") == ""
    shared = tmp_path / "shared"
    mine2 = _program(shared)
    shared.chmod(0o1777)                                    # as /tmp: sticky, and anyone may add a file
    why = I.command_problem([str(mine2)], "the timer")
    assert "every account can write to" in why and f"the folder {shared}" in why
    assert "the timer would run it as you" in why and "~/Applications" in why
    loose = _program(tmp_path / "loose", 0o757)               # the file itself
    assert "can be changed by anyone" in launch.unsafe_place(str(loose))
    link = tmp_path / "Applications" / "app"                 # a link of the user's own, to a file in a shared folder
    link.symlink_to(mine2)
    assert "every account can write to" in launch.unsafe_place(str(link))
    assert "belongs to another account" in launch.unsafe_place(str(mine), uid=os.getuid() + 1)
    group = _program(tmp_path / "team")
    (tmp_path / "team").chmod(0o775)
    monkeypatch.setattr(launch, "_own_group", lambda gid, uid: False)
    assert "members of its group" in launch.unsafe_place(str(group))
    monkeypatch.setattr(launch, "_own_group", lambda gid, uid: True)    # a private group: the account alone
    assert launch.unsafe_place(str(group)) == ""
    assert "can't be found" in I.command_problem([str(tmp_path / "gone")], "the Outbox")


def test_scheduling_refuses_a_program_another_account_could_replace(tmp_path, monkeypatch, capsys, safe_above):
    import subprocess

    from daprivacyscanner import app
    shared = tmp_path / "shared"
    image = _program(shared)
    shared.chmod(0o1777)
    tmp_path.chmod(0o755)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(app, "scan_command", lambda: [str(image)])
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: ran.append(argv) or subprocess.CompletedProcess(argv, 0))
    assert app.schedule("daily") == 2
    err = capsys.readouterr().err
    assert "Scans are not scheduled" in err and "every account can write to" in err
    assert not (tmp_path / "config").exists() and ran == []


def test_the_guides_block_entries_that_would_run_a_replaceable_program(cat, tmp_path, monkeypatch, safe_above):
    from daprivacyscanner.runner import Runner
    from daprivacyscanner.tools import integration as I
    shared = tmp_path / "shared"
    image = _program(shared)
    shared.chmod(0o1777)
    tmp_path.chmod(0o755)
    monkeypatch.setattr(I, "program", lambda environ: [str(image)])
    host = make_host(tmp_path, installed=("nemo", "mat2"))
    for cid in ("desk.file_manager_actions", "app.metadata_outbox"):
        _, guide = Runner(cat, host).plan_fix(cid)
        blockers = [b for p in guide.plans for b in p.blockers]
        assert any("every account can write to" in b for b in blockers), (cid, blockers)


# ------------------------------------------------------------------ report.py: redacting paths with spaces

def _redactor(tmp_path, **kw):
    from daprivacyscanner.report import Redactor
    host = make_host(tmp_path, env={"USER": "user"}, files={"/proc/sys/kernel/hostname": "mint-box\n"}, **kw)
    return host, Redactor(host)


@pytest.mark.parametrize("text, shown", [
    # a folder of the user's own: everything after ~/, however its names run
    ("~/Documents/Taxes 2024/Smith family.kdbx is readable by every account",
     "~/[redacted] is readable by every account"),
    ("~/Documents/Taxes 2024/Smith family.kdbx", "~/[redacted]"),
    ("Saved in ~/Documents/Taxes 2024. Move it.", "Saved in ~/[redacted]. Move it."),
    ("~/Pictures/Holiday in Crete (12 files)", "~/[redacted] (12 files)"),
    ("~/Documents/My Passport backup/report.pdf, ~/.ssh/id_rsa", "~/[redacted], ~/.ssh/id_rsa"),
    ("rm -f '~/Documents/Taxes 2024/x.kdbx' and then", "rm -f '~/[redacted]' and then"),
    ("+ export PATH=~/bin:$PATH", "+ export PATH=~/[redacted]:$PATH"),
    ("files in ~/x and ~/.cache/thumbnails/large", "files in ~/[redacted] and ~/.cache/thumbnails/large"),
    # a dot-folder: the programs' folders stay, from the first name a person chose on it goes
    ("~/.var/app/org.example.Notes/data/Client Jones/notes.txt is readable",
     "~/.var/app/org.example.Notes/data/[redacted] is readable"),
    ("~/.local/share/Trash/files/Taxes.pdf", "~/.local/share/Trash/files/[redacted]"),
    ("~/.local/share/notes/Smith über.md", "~/.local/share/notes/[redacted]"),
    ("kwriteconfig6 --file ~/.config/kdeglobals --group General --key X true",
     "kwriteconfig6 --file ~/.config/kdeglobals --group General --key X true"),
    ("~/.config/user/settings", "~/.config/[redacted]/settings"),        # the account's name, as anywhere
])
def test_paths_with_spaces_are_redacted_whole(tmp_path, text, shown):
    """The redaction took a path to its first space: "~/Documents/Taxes 2024/Smith family.kdbx" went out as
    "~/[redacted] 2024/Smith family.kdbx", in a report meant for a public issue tracker; and nothing in a dot-folder
    was redacted, a folder named after a client in an app's data included."""
    _, r = _redactor(tmp_path)
    assert r.text(text) == shown
    assert r.text(text.replace("~", str(r.home), 1)) == shown


def test_what_is_on_the_disk_and_what_the_report_names_is_redacted_exactly(tmp_path):
    """A folder whose name has words a sentence goes on with ("Bob and Alice") is taken whole when it is on the disk,
    or when the report names it as a path (evidence) anywhere: then a summary naming it, which the words alone
    couldn't tell, is redacted the same."""
    host, r = _redactor(tmp_path, home_files={"Documents/Bob and Alice/notes.txt": "x"})
    assert r.text("~/Documents/Bob and Alice/notes.txt is readable") == "~/[redacted] is readable"
    report = {"results": {"x.y": {"summary": "~/Projects/Me and You/keys.txt is world-readable", "notes": [],
                                  "evidence": [{"kind": "path", "label": "Readable by others",
                                                "value": f"{host.home}/Projects/Me and You/keys.txt"},
                                               {"kind": "value", "label": "~/Work/In and Out", "value": "3 files"}]}}}
    out = r.report(report)["results"]["x.y"]
    assert out["summary"] == "~/[redacted] is world-readable"
    assert out["evidence"][0]["value"] == "~/[redacted]" and out["evidence"][1]["label"] == "~/[redacted]"
    assert r.text("In ~/Work/In and Out, 3 files") == "In ~/[redacted], 3 files"


def test_a_redacted_export_names_nothing_the_user_named(cat, tmp_path):
    from daprivacyscanner.fix import FixPlan, WriteFile, apply_plan
    from daprivacyscanner.report import export, export_all
    from daprivacyscanner.undo import UndoLog
    host, _ = _redactor(tmp_path, home_files={"Documents/Taxes 2024/Smith family.kdbx": "A=1\n"})
    target = host.home / "Documents/Taxes 2024/Smith family.kdbx"
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    assert apply_plan(FixPlan("auth.screen_lock", "Change it", [
        WriteFile(target, lambda old: old + "B=2\n", "Add B", host.display(target))]), host, log).ok
    secret = ("Taxes", "Smith", "family", "Client", "Jones", "Crete")
    report = {"started": 1, "context": {"values": {}, "desktop": {"label": "GNOME"}}, "results": {
        "auth.screen_lock": {"status": "fail", "effective_severity": 7, "kind": "finding", "is_finding": True,
                             "summary": "~/Documents/Taxes 2024/Smith family.kdbx is readable by every account.",
                             "notes": [{"kind": "info", "title": "Where", "text":
                                        "~/.var/app/org.example.Notes/data/Client Jones/notes.txt and "
                                        "~/Pictures/Holiday in Crete"}],
                             "evidence": [{"kind": "path", "label": "Readable", "value":
                                           f"{host.home}/Documents/Taxes 2024/Smith family.kdbx"}]}}}
    entries = log.entries()
    assert "Smith family" in export_all(report, cat, entries, {}, "text", host, False)
    target.unlink()                     # gone since: the words alone decide, and the report's own paths
    for fmt in ("text", "json"):
        out = export(report, cat, fmt, host, True, {})
        assert not any(w in out for w in secret), out
        everything = export_all(report, cat, entries, {}, fmt, host, True)
        assert not any(w in everything for w in secret), everything
        if fmt == "json":
            assert "org.example.Notes/data/[redacted]" in out


# ------------------------------------------------------------------ server.py: who may talk to it, and what it says

T = "t0ken"
HT = {"X-Token": T}


def _client(cat, tmp_path, **kw):
    from fastapi.testclient import TestClient

    from daprivacyscanner.server import create_app
    host = make_host(tmp_path)
    return TestClient(create_app(T, cat, make_host=lambda: host, **kw))


def test_the_kernel_says_whose_program_is_on_the_other_end(tmp_path):
    """peer.peer_uid reads the socket's owner from /proc/net/tcp (and tcp6), as the kernel lists it for every account."""
    import socket

    from daprivacyscanner import peer
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept()
    try:
        assert peer.peer_uid(cli.getsockname(), srv.getsockname()) == os.getuid()
        assert peer.same_user(cli.getsockname(), srv.getsockname())
        assert peer.peer_uid(("127.0.0.1", 1), srv.getsockname()) is None             # no such socket
        assert not peer.same_user(None, srv.getsockname()) and not peer.same_user(("testclient", 50000), ("x", 80))
        # another account's socket, as the table lists it
        port, sport = cli.getsockname()[1], srv.getsockname()[1]
        table = tmp_path / "tcp"
        table.write_text("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                         f"   0: {peer._hex4('127.0.0.1')}:{port:04X} {peer._hex4('127.0.0.1')}:{sport:04X} 01 "
                         "00000000:00000000 00:00000000 00000000  1234        0 99 1 0 20 4 30 10 -1\n")
        assert peer.peer_uid(cli.getsockname(), srv.getsockname(), tables=(str(table),)) == 1234
    finally:
        for s in (cli, conn, srv):
            s.close()


def test_another_accounts_program_is_refused_everything(cat, tmp_path):
    """In --browser mode the launch link was on a command line, which every account can read: another account that
    used it first held the session (and with Try an app, ran its program as the user, on the user's display). Every
    connection whose program isn't this account's is refused, the page and its script included."""
    asked = []
    c = _client(cat, tmp_path, same_user=lambda client, server: asked.append((client, server)) or False,
                launch_token="launch")
    for path in ("/", "/?t=launch", "/static/app.js", "/api/state"):
        r = c.get(path, headers=HT)
        assert r.status_code == 403 and "only programs of the account" in r.text, path
    assert c.post("/api/scan", headers=HT).status_code == 403
    assert asked and asked[0][0] == ("testclient", 50000)
    ok = _client(cat, tmp_path / "b", same_user=lambda client, server: True, launch_token="launch")
    assert ok.get("/static/app.js").status_code == 200 and "data-token" in ok.get("/?t=launch").text


def test_the_real_server_answers_its_own_account_on_the_socket_it_was_given(cat, tmp_path):
    """app.main binds the socket and hands it to uvicorn as it is (a port picked, closed and bound again could be taken
    in between), and the server asks the kernel whose each connection is."""
    import http.client
    import threading
    import time

    import uvicorn

    from daprivacyscanner import app as app_mod, peer
    from daprivacyscanner.server import create_app
    host = make_host(tmp_path)
    sock = app_mod._listen(0)
    port = sock.getsockname()[1]
    seen = []

    def check(client, server):
        seen.append(peer.same_user(client, server))
        return seen[-1]
    application = create_app(T, cat, make_host=lambda: host, same_user=check,
                             allowed_hosts={f"127.0.0.1:{port}"})
    server = uvicorn.Server(uvicorn.Config(application, log_level="warning", ws="none", lifespan="on"))
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    try:
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.02)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/api/state", headers=HT)
        r = conn.getresponse()
        assert r.status == 200 and r.getheader("X-Admin-Active") == "0"
        r.read()
        conn.request("GET", "/static/icon.svg")
        r = conn.getresponse()
        assert r.status == 200 and r.getheader("Cross-Origin-Resource-Policy") == "same-origin"
        r.read()
        assert seen and all(seen)
    finally:
        server.should_exit = True
        t.join(10)


def test_every_answer_is_for_this_origin_alone(cat, tmp_path):
    """/ and /static answered any website, with no Cross-Origin-Resource-Policy: a page elsewhere could load them to
    tell the app runs, and which version. The policy, nosniff and frame-ancestors are headers on every answer."""
    c = _client(cat, tmp_path)
    for path, headers in (("/", {}), ("/static/app.js", {}), ("/api/state", HT), ("/api/state", {}),
                          ("/nowhere", {})):
        r = c.get(path, headers=headers)
        assert r.headers["Cross-Origin-Resource-Policy"] == "same-origin", path
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert "script-src 'self'" in r.headers["Content-Security-Policy"]


def test_every_route_needs_the_token_but_the_pages_shell(cat, tmp_path):
    """Authentication was each route's own Depends(auth): a route that forgot it was open. The guard asks for the
    token on everything but / and /static."""
    c = _client(cat, tmp_path)
    c.app.get("/api/forgot")(lambda: {"open": True})          # a route added without Depends(auth)
    c.app.post("/api/forgot-post")(lambda: {"open": True})
    assert c.get("/api/forgot").status_code == 403 and c.post("/api/forgot-post").status_code == 403
    assert c.get("/api/forgot", headers={"X-Token": "wrong"}).status_code == 403
    assert c.get("/api/forgot", headers={"X-Token": "tök".encode()}).status_code == 403  # beyond ASCII: just wrong
    assert c.get("/api/forgot", headers=HT).json() == {"open": True}
    assert c.post("/", headers={}).status_code == 403                                   # the shell is GET only
    assert c.get("/static/style.css").status_code == 200 and c.get("/").status_code == 200
    from daprivacyscanner.server import create_app
    for route in create_app(T, cat).routes:                 # and every route of the app's own
        path = getattr(route, "path", "")
        if path.startswith("/api/") and "{" not in path:
            for method in getattr(route, "methods", ()) or ():
                assert c.request(method, path).status_code == 403, (method, path)


def test_the_page_learns_administrator_access_ended_by_itself(cat, tmp_path):
    """The badge was the page's own: access dropped after 5 idle minutes still read "Administrator". Every API answer
    says whether it is held now."""
    from daprivacyscanner.privileged import FakePrivileged
    helper = FakePrivileged()
    c = _client(cat, tmp_path, start_helper=lambda: helper)
    assert c.get("/api/state", headers=HT).headers["X-Admin-Active"] == "0"
    c.post("/api/scan", headers=HT, json={"admin": True})
    assert c.get("/api/online/status", headers=HT).headers["X-Admin-Active"] == "1"
    c.app.state.admin.idle = 0                              # idle long enough
    assert c.get("/api/online/status", headers=HT).headers["X-Admin-Active"] == "0"


def test_work_on_a_thread_gets_a_copy_of_the_report(cat, tmp_path, monkeypatch):
    """The report was saved and exported in worker threads while the loop merged online results into it: a dict
    changing size under json.dumps stops it with a RuntimeError. Threads get a copy, taken on the loop."""
    from fastapi.testclient import TestClient

    from conftest import sample
    from daprivacyscanner import blockdev, history, report as report_mod
    from daprivacyscanner.server import create_app
    saved, exported = [], []
    monkeypatch.setattr(history.LastReport, "save", lambda self, report: saved.append(report))
    real = report_mod.export
    monkeypatch.setattr(report_mod, "export", lambda report, *a, **kw: exported.append(report) or real(report, *a, **kw))
    host = make_host(tmp_path, commands={("lsblk", "-J", "-o", blockdev.COLUMNS): sample("lsblk/debian-12-partial.json")})
    c = TestClient(create_app(T, cat, make_host=lambda: host))
    c.post("/api/scan", headers=HT)
    c.get("/api/report?format=json", headers=HT)
    live = c.app.state.report
    assert saved and exported and all(r is not live and r["results"] is not live["results"] for r in saved + exported)
    assert saved[-1]["results"] == live["results"]


# ------------------------------------------------------------------ jobs and quitting

def test_jobs_are_told_to_stop_and_waited_for_and_none_starts_after(cat, tmp_path):
    import asyncio
    import threading

    from daprivacyscanner.jobs import Job, Jobs, Quitting, in_thread, view

    class State:
        pass
    jobs, stopped = Jobs(State()), threading.Event()

    async def main():
        def work(job):                                   # a long job's work, looking at its cancel as it goes
            while not job["cancel"]:
                threading.Event().wait(0.01)
            stopped.set()

        async def run(job):
            await in_thread(work, job)
            job["state"] = "stopped"
        job = jobs.start(Job("meta", "running", phase="x"), run)
        assert jobs.running("meta") and view(job)["phase"] == "x" and "cancel" not in view(job)
        await asyncio.sleep(0.05)
        told = jobs.cancel_all()
        assert told == ["meta"] and view(job)["stopping"]
        left = await asyncio.to_thread(jobs.wait, 5)
        assert left == [] and stopped.is_set() and job.ended.is_set()
        with pytest.raises(Quitting):
            jobs.start(Job("trim", "asking"), run)
    asyncio.run(main())


def test_quitting_stops_the_online_tests_and_closes_what_it_must(cat, tmp_path, monkeypatch):
    """Quit set no cancel flag: after the window closed an invisible process went on running the online tests,
    contacting third-party hosts. shutdown tells every job to stop, waits for them, then closes ~/TempBrowser, discards
    the trial, drops administrator access; a request after that is refused, and a second call does nothing again."""
    import threading
    import time

    from fastapi.testclient import TestClient

    from daprivacyscanner import runner as runner_mod
    from daprivacyscanner.server import create_app
    from daprivacyscanner.tools import browser as B
    running, ended = threading.Event(), threading.Event()

    def scan_online(self, ids, progress=None, stopped=None, on_result=None):
        running.set()
        while not stopped():
            time.sleep(0.01)
        ended.set()
    monkeypatch.setattr(runner_mod.Runner, "scan_online", scan_online)
    closed = []
    monkeypatch.setattr(B, "close_disk", lambda host, helper: closed.append(1) or "")
    host = make_host(tmp_path)
    with TestClient(create_app(T, cat, make_host=lambda: host)) as c:
        c.app.state.report = {"results": {}, "modifiers": {}, "context": {"values": {}}}
        oid = next(s.id for s in cat if s.scope.value == "online")
        assert c.post("/api/online/run", headers=HT, json={"ids": [oid]}).status_code == 200
        assert running.wait(5)
        t0 = time.monotonic()
        said = c.app.state.shutdown()
        assert ended.is_set() and time.monotonic() - t0 < 5 and said["told"] == ["online"] and said["left"] == []
        assert closed == [1]
        assert c.post("/api/scan", headers=HT).status_code == 503
        assert c.app.state.shutdown() is said and closed == [1]


def test_quitting_waits_for_a_fix_under_way(cat, tmp_path, monkeypatch):
    """A fix applied as the window closes is finished, not cut off half-way by the process ending."""
    import threading
    import time

    from fastapi.testclient import TestClient

    from daprivacyscanner import server as server_mod
    from daprivacyscanner.server import create_app
    from daprivacyscanner.tools import browser as B
    monkeypatch.setattr(B, "close_disk", lambda host, helper: "")
    started, finished = threading.Event(), threading.Event()
    real = server_mod.apply_plan

    def slow_apply(*a, **kw):
        started.set()
        time.sleep(0.5)
        finished.set()
        return real(*a, **kw)
    monkeypatch.setattr(server_mod, "apply_plan", slow_apply)
    from conftest import sample
    from daprivacyscanner import blockdev
    host = make_host(tmp_path, commands={("lsblk", "-J", "-o", blockdev.COLUMNS): sample("lsblk/debian-12-partial.json")})
    profile = host.home / ".profile"                   # an auto fix to apply, whatever the umask the suite runs under
    profile.write_text("# login\n")
    profile.chmod(0o666)
    with TestClient(create_app(T, cat, make_host=lambda: host)) as c:
        c.post("/api/scan", headers=HT)
        cid = next(cid for cid, r in c.app.state.report["results"].items() if r.get("fixable")
                   and cat[cid].tier.value == "auto")
        plan = c.post(f"/api/fix/{cid}/plan", headers=HT).json()["plan"]
        threading.Thread(target=lambda: c.post("/api/fix/apply", headers=HT, json={"plan_id": plan["id"],
                                                                                   "confirm_irreversible": True}),
                         daemon=True).start()
        assert started.wait(5)
        said = c.app.state.shutdown(wait=0.1)
        assert finished.is_set() and said["settled"]


def test_a_file_chooser_left_open_is_closed_at_quit(tmp_path):
    """zenity waited up to an hour for an answer, the app with it."""
    import threading
    import time

    from daprivacyscanner.host import SystemRunner
    from daprivacyscanner.tools.pick import end_dialogs
    bindir = tmp_path / "bin"
    bindir.mkdir()
    zenity = bindir / "zenity"
    zenity.write_text("#!/bin/sh\nexec sleep 30\n")
    zenity.chmod(0o755)
    runner, out = SystemRunner({"PATH": f"{bindir}:/usr/bin:/bin"}), []
    t = threading.Thread(target=lambda: out.append(runner.run(["zenity", "--file-selection"], timeout=60)))
    t.start()
    for _ in range(100):
        if end_dialogs():
            break
        time.sleep(0.05)
    t.join(5)
    assert out and not out[0].ok and not t.is_alive()


def test_the_end_of_a_run_quits_then_ends_the_process(monkeypatch):
    """However the window or the browser run ends, what quitting closes runs, the server stops, and the process ends
    at once, whatever threads are still busy (Python waited for them, an invisible process going on)."""
    from types import SimpleNamespace

    from daprivacyscanner import app as app_mod
    done, exited = [], []
    monkeypatch.setattr(app_mod, "exit_now", lambda code: exited.append(code))
    fake = SimpleNamespace(state=SimpleNamespace(shutdown=lambda: done.append("shutdown")))
    server = SimpleNamespace(should_exit=False)
    thread = SimpleNamespace(join=lambda timeout=None: done.append("joined"))
    app_mod.finish(fake, server, thread, lambda: done.append("launcher"))
    assert done == ["shutdown", "launcher", "joined"] and server.should_exit and exited == [0]

    def broken():
        raise RuntimeError("x")
    fake.state.shutdown = broken
    with pytest.raises(RuntimeError):
        app_mod.finish(fake, server, thread)
    assert exited == [0, 0]                                 # it ends all the same


# ------------------------------------------------------------------ app.py: the launch link never on a command line

def test_the_browser_gets_the_link_in_a_file_only_this_account_reads(tmp_path, monkeypatch):
    """webbrowser.open(url) put ?t=<launch token> on xdg-open's and the browser's command lines, which every account
    can read (/proc/*/cmdline). The browser is handed a file in the runtime folder, 0600, that opens the link."""
    from daprivacyscanner import app as app_mod
    runtime = tmp_path / "run"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    url = "http://127.0.0.1:4242/?t=SECRET&x=1"
    f = app_mod.launcher_file(url)
    assert f.parent == runtime / "daprivacyscanner" and stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and "SECRET" not in f.as_uri()
    page = f.read_text()
    assert 'http-equiv="refresh" content="0;url=http://127.0.0.1:4242/?t=SECRET&amp;x=1"' in page
    app_mod.remove_launcher(f)
    assert not f.exists()
    monkeypatch.delenv("XDG_RUNTIME_DIR")                    # none: a private folder of its own in /tmp
    g = app_mod.launcher_file(url)
    assert stat.S_IMODE(g.parent.stat().st_mode) == 0o700 and g.parent.name.startswith("daprivacyscanner-")
    app_mod.remove_launcher(g)
    assert not g.parent.exists()


def test_using_the_launch_link_removes_the_launcher(cat, tmp_path):
    gone = []
    c = _client(cat, tmp_path, launch_token="L", on_launched=lambda: gone.append(1))
    assert "data-token" in c.get("/?t=L").text and gone == [1]
    assert c.get("/?t=L").status_code == 403 and gone == [1]


def test_the_browser_warning_says_whose_programs_can_use_the_pages_key():
    from daprivacyscanner.app import BROWSER_EXPOSES
    assert "only programs of your own account can use it" in BROWSER_EXPOSES
    assert "worthless once the app has quit" in BROWSER_EXPOSES
