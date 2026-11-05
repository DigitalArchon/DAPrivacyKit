"""The tools review of 2026-10-17, Try an app and Boxes: what it found, each fixed and tested here (live on the lab
as each test says)."""

from __future__ import annotations

import ipaddress
import os
import signal
import struct
import subprocess
import sys
import time

import pytest

from daprivacyscanner.tools import pcap, trial

from test_trial import client_hello, eth, ip4, qname, udp


# ------------------------------------------------------------------ E2: a trial ends with the app that started it

def _children(pid: int) -> list[int]:
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            return [int(x) for x in f.read().split()]
    except OSError:
        return []


def _gone(pid: int, within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as f:
                if f.read().rsplit(")", 1)[1].split()[0] == "Z":
                    return True
        except OSError:
            return True
        time.sleep(0.05)
    return False


def test_the_command_ends_when_the_app_is_killed():
    """An observed trial ran on after the app was killed: pasta was adopted by init, and bubblewrap answers to pasta.
    TETHER, started by a stand-in for the app from a worker thread as the server does, kills its command when the
    app's process ends (on p330-2: pasta, bubblewrap and the program gone at once)."""
    app = subprocess.Popen([sys.executable, "-I", "-c", """
import subprocess, sys, threading, time, os
def start():
    p = subprocess.Popen([sys.executable, "-I", "-c", sys.argv[1], str(os.getpid()), "/bin/sleep", "60"],
                         start_new_session=True)
    print(p.pid, flush=True)
t = threading.Thread(target=start)
t.start(); t.join()                       # the thread that started it has ended: the tether doesn't answer to it
time.sleep(60)
""", trial.TETHER], stdout=subprocess.PIPE, text=True)
    try:
        tether = int(app.stdout.readline())
        deadline = time.monotonic() + 5
        while not _children(tether) and time.monotonic() < deadline:
            time.sleep(0.05)
        (sleeper,) = _children(tether)
        time.sleep(0.3)
        assert not _gone(sleeper, 0.2), "the thread that started it ending ends nothing"
        app.kill()
        app.wait()
        assert _gone(sleeper) and _gone(tether)
    finally:
        app.kill()


def test_the_sandboxs_first_process_dies_with_bubblewrap():
    """Live on Ubuntu 26.04: with the app killed (or Stop), bubblewrap ended but the sandbox ran on, the program with it:
    STAY is the sandbox's PID 1, and the exec into AppArmor's unpriv_bwrap domain clears the parent-death signal
    --die-with-parent had set. STAY sets its own; here its parent (standing for bubblewrap) is killed."""
    parent = subprocess.Popen([sys.executable, "-I", "-c", """
import subprocess, sys, time
p = subprocess.Popen([sys.executable, "-I", "-c", sys.argv[1], "/bin/sleep", "60"])
print(p.pid, flush=True)
time.sleep(60)
""", trial.STAY], stdout=subprocess.PIPE, text=True)
    sleepers = []
    try:
        stay = int(parent.stdout.readline())
        time.sleep(0.5)
        sleepers = _children(stay)
        assert not _gone(stay, 0.2) and sleepers
        parent.kill()
        parent.wait()
        assert _gone(stay)
    finally:
        parent.kill()
        for pid in sleepers:                            # outside a PID namespace its child outlives it: not ours to keep
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


@pytest.mark.skipif(not os.path.exists("/usr/bin/bwrap") or not os.path.exists("/usr/bin/python3"), reason="bubblewrap")
def test_ending_a_trial_lets_its_program_end_cleanly(tmp_path):
    """The review of 2026-11-04: "End the trial" (and a Box's launcher told to end) sent SIGTERM to the command's group,
    which reached bubblewrap first: it ended at once, and --die-with-parent killed the sandbox, so the program never had
    the grace to end (a trap on TERM inside never ran). The sandbox's first process (STAY) is asked now and passes it
    on to everything in the sandbox; the group is killed only when that hasn't ended it. Here with a real bubblewrap
    and a program that cleans up when asked to end."""
    import shlex
    from daprivacyscanner.host import FakeRunner, Host
    done = tmp_path / "ended"
    prog = ["/bin/sh", "-c", f"trap 'echo cleanly > {shlex.quote(str(done))}; exit 0' TERM; while :; do sleep 0.1; done"]
    cmd = [sys.executable, "-I", "-c", trial.TETHER, str(os.getpid()), "/usr/bin/bwrap", "--die-with-parent", "--unshare-pid",
           "--new-session", "--as-pid-1", "--dev-bind", "/", "/", "--", "/usr/bin/python3", "-I", "-c", trial.STAY, *prog]
    folder = tmp_path / "t"
    for sub in ("home", "app", "private"):
        (folder / sub).mkdir(parents=True)
    t = trial.Trial("0a1b2c3d4e5f", folder, "memory", "program", "tool", "a Linux program", argv=prog, state="running")
    t.proc = subprocess.Popen(cmd, start_new_session=True, stdin=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while (t.proc.poll() is None and time.monotonic() < deadline
               and not any(_runs(c, prog[:2]) for c in _descendants(t.proc.pid))):
            time.sleep(0.05)
        if t.proc.poll() is not None or time.monotonic() >= deadline:
            pytest.skip("bubblewrap can't make a sandbox here")
        time.sleep(0.3)
        trial.stop(Host(home=tmp_path, environ={}, runner=FakeRunner(), root=tmp_path / "root", uid=os.getuid()), t)
        assert done.exists() and done.read_text() == "cleanly\n", "the program ended as it does when asked"
        assert t.exit == 0 and t.result["ended"] == "was ended here"
    finally:
        if t.proc.poll() is None:
            os.killpg(t.proc.pid, signal.SIGKILL)
            t.proc.wait()


def test_the_commands_exit_status_is_passed_on_and_stop_reaches_the_command():
    import resource
    # with a core size limit of 1, as the app runs its own commands: the shell's SIGSEGV below left a real crash dump
    # in /var/lib/systemd/coredump at every run of the suite
    no_dump = lambda: resource.setrlimit(resource.RLIMIT_CORE, (1, 1))  # noqa: E731
    run = lambda *argv: subprocess.run([sys.executable, "-I", "-c", trial.TETHER, str(os.getpid()), *argv],   # noqa: E731
                                       timeout=20, preexec_fn=no_dump).returncode
    assert run("/bin/sh", "-c", "exit 3") == 3
    assert run("/bin/sh", "-c", "kill -SEGV $$") == 128 + signal.SIGSEGV
    assert trial.ended_by_signal(128 + signal.SIGSEGV) == "SIGSEGV"
    assert run("/nonexistent/program") == 127
    # Stop: SIGTERM to the group reaches the command, which ends; the tether ignores it and reports how it ended
    p = subprocess.Popen([sys.executable, "-I", "-c", trial.TETHER, str(os.getpid()), "/bin/sleep", "60"],
                         start_new_session=True)
    time.sleep(0.5)
    os.killpg(p.pid, signal.SIGTERM)
    assert p.wait(timeout=10) == 128 + signal.SIGTERM


def test_a_trial_and_its_display_start_under_the_tether(tmp_path):
    from daprivacyscanner.host import FakeRunner, Host
    root = tmp_path / "root"
    (root / "usr/bin").mkdir(parents=True)
    host = Host(home=root / "home/a", environ={}, runner=FakeRunner(), root=root, uid=1000)
    assert trial.tethered(host, ["/usr/bin/bwrap", "x"]) == ["/usr/bin/bwrap", "x"], "no python3: as it was"
    (root / "usr/bin/python3").write_text("")
    a = trial.tethered(host, ["/usr/bin/bwrap", "x"])
    assert a[:4] == ["/usr/bin/python3", "-I", "-c", trial.TETHER] and a[4] == str(os.getpid()) and a[5:] == ["/usr/bin/bwrap", "x"]
    assert "<end it if the app ends>" in trial.shown(a)
    compile(trial.TETHER, "tether", "exec")


# ------------------------------------------------------------------ E4: hosts named per connection; DNS over TCP

def _capture(packets: list[bytes]) -> bytes:
    stream = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    return stream + b"".join(struct.pack("<IIII", 0, 0, len(p), len(p)) + p for p in packets)


def _flows(packets, forwarder="169.254.0.1"):
    f = pcap.Flows(forwarder)
    data = _capture(packets)
    for i in range(0, len(data), 53):                   # as it comes from a pipe: in pieces
        f.feed(data[i:i + 53])
    return f.result()


def _query(qid, name):
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack(">HH", 1, 1)


def _answer(qid, name, address):
    return (struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + qname(name) + struct.pack(">HH", 1, 1) + b"\xc0\x0c"
            + struct.pack(">HHIH", 1, 1, 60, 4) + ipaddress.ip_address(address).packed)


def _tcp(sp, dp, flags, seq=0, data=b""):
    return struct.pack(">HHIIBBHHH", sp, dp, seq, 0, 0x50, flags, 0, 0, 0) + data


ME, FWD = "10.0.2.15", "169.254.0.1"


def test_two_sites_on_one_address_are_two_hosts():
    """Found live on p330-2: two TLS connections to 1.1.1.1 naming one.one.one.one and site-b.example were shown as
    one host, named by the last DNS answer for the address, and one.one.one.one as looked up and never connected to."""
    p = [eth(ip4(ME, FWD, 17, udp(4000, 53, _query(1, "one.one.one.one")))),
         eth(ip4(FWD, ME, 17, udp(53, 4000, _answer(1, "one.one.one.one", "1.1.1.1")))),
         eth(ip4(ME, FWD, 17, udp(4001, 53, _query(2, "1dot1dot1dot1.cloudflare-dns.com")))),
         eth(ip4(FWD, ME, 17, udp(53, 4001, _answer(2, "1dot1dot1dot1.cloudflare-dns.com", "1.1.1.1")))),
         eth(ip4(ME, "1.1.1.1", 6, _tcp(5000, 443, 0x02))),
         eth(ip4(ME, "1.1.1.1", 6, _tcp(5000, 443, 0x18, 1, client_hello("one.one.one.one")))),
         eth(ip4(ME, "1.1.1.1", 6, _tcp(5001, 443, 0x02))),
         eth(ip4(ME, "1.1.1.1", 6, _tcp(5001, 443, 0x18, 1, client_hello("site-b.example")))),
         eth(ip4("1.1.1.1", ME, 6, _tcp(443, 5001, 0x18, 1, b"z" * 300))),
         eth(ip4(ME, "1.1.1.1", 6, _tcp(5002, 80, 0x02))),                    # no name of its own: the lookup's
         eth(ip4(ME, "1.1.1.1", 6, _tcp(5002, 80, 0x18, 1, b"\x00binary"))),
         eth(ip4(ME, FWD, 17, udp(4002, 53, _query(3, "never-used.example"))))]
    r = _flows(p)
    hosts = {h["host"]: h for h in r["hosts"]}
    assert set(hosts) == {"one.one.one.one", "site-b.example", "1dot1dot1dot1.cloudflare-dns.com"}
    assert hosts["one.one.one.one"]["named_by"] == "tls" and hosts["one.one.one.one"]["connections"] == 1
    assert hosts["site-b.example"]["received"] == 300 and hosts["site-b.example"]["named_by"] == "program"
    assert hosts["1dot1dot1dot1.cloudflare-dns.com"]["named_by"] == "dns"
    assert hosts["1dot1dot1dot1.cloudflare-dns.com"]["ports"] == ["80"]
    assert r["looked_up"] == ["never-used.example"]
    assert FWD not in hosts, "the sandbox's own resolver is no host"


def test_dns_over_tcp_is_read_and_a_hung_lookup_is_one_connection():
    """Found live on p330-2: DNS over TCP wasn't read (the forwarder showed as a host by its address), and one lookup
    hanging on a server that didn't answer, its SYN sent again and again, counted as about five connections."""
    q, a = _query(7, "tcp.example"), _answer(7, "tcp.example", "203.0.113.5")
    framed_q, framed_a = struct.pack(">H", len(q)) + q, struct.pack(">H", len(a)) + a
    p = [eth(ip4(ME, FWD, 6, _tcp(6000, 53, 0x02, 100))),
         eth(ip4(FWD, ME, 6, _tcp(53, 6000, 0x12, 900))),
         eth(ip4(ME, FWD, 6, _tcp(6000, 53, 0x18, 101, framed_q[:5]))),     # the question over two segments
         eth(ip4(ME, FWD, 6, _tcp(6000, 53, 0x18, 101, framed_q[:5]))),     # one of them sent again
         eth(ip4(ME, FWD, 6, _tcp(6000, 53, 0x18, 106, framed_q[5:]))),
         eth(ip4(FWD, ME, 6, _tcp(53, 6000, 0x18, 901, framed_a))),
         eth(ip4(ME, "203.0.113.5", 6, _tcp(6001, 443, 0x02))),
         eth(ip4(ME, "203.0.113.5", 6, _tcp(6001, 443, 0x18, 1, b"\x17\x03\x03hello"))),
         # a server of its own, silent: the SYN sent again and again, pasta answering some with RST meanwhile (as
         # captured on Mint 22.3: SYN, SYN, RST, SYN, SYN, RST, SYN, every SYN with the same first sequence number)
         *[eth(ip4(*((ME, "192.0.2.53") if f == 0x02 else ("192.0.2.53", ME)), 6,
                   _tcp(*((6002, 53) if f == 0x02 else (53, 6002)), f, 5000 if f == 0x02 else 77)))
           for f in (0x02, 0x02, 0x04, 0x02, 0x02, 0x04, 0x02)],
         eth(ip4(ME, "8.8.8.8", 17, udp(6003, 53, _query(8, "own-server.example")))),
         eth(ip4("8.8.8.8", ME, 17, udp(53, 6003, _answer(8, "own-server.example", "198.51.100.1"))))]
    r = _flows(p)
    hosts = {h["host"]: h for h in r["hosts"]}
    assert hosts["tcp.example"]["named_by"] == "dns" and hosts["tcp.example"]["connections"] == 1
    assert FWD not in hosts
    assert hosts["192.0.2.53"]["connections"] == 1 and hosts["192.0.2.53"]["ports"] == ["53"]
    assert hosts["8.8.8.8"]["ports"] == ["53/udp"], "DNS sent past the sandbox's resolver goes to a server of its own"
    assert r["looked_up"] == ["own-server.example"]


def test_a_connection_made_again_on_the_same_ports_counts_again():
    p = [eth(ip4(ME, "203.0.113.9", 6, _tcp(7000, 443, 0x02, 1000))), eth(ip4(ME, "203.0.113.9", 6, _tcp(7000, 443, 0x11, 1001))),
         eth(ip4(ME, "203.0.113.9", 6, _tcp(7000, 443, 0x02, 555000)))]                  # a new first sequence number
    assert _flows(p)["hosts"][0]["connections"] == 2


def test_a_full_table_folds_the_older_connections_into_their_hosts(monkeypatch):
    monkeypatch.setattr(pcap, "CONNS_MAX", 4)
    p = [eth(ip4(ME, "203.0.113.%d" % (i % 2 + 1), 6, _tcp(8000 + i, 443, 0x02))) for i in range(9)]
    r = _flows(p)
    assert sum(h["connections"] for h in r["hosts"]) == 9 and len(r["hosts"]) == 2
    assert _flows(p)["hosts"] == r["hosts"], "summing up twice changes nothing"


def test_a_program_cant_have_its_own_server_named_as_it_likes():
    """The review of 2026-11-04: answers from any DNS server named addresses, the program's own server's too, and a
    name given when connecting labelled a connection whatever address it went to, while the page had only a count of
    addresses: sending everything to one server of its own, a program could have the list read dns.google and
    github.com. Names come from the sandbox's own resolver's answers only, a name the program gave that the resolver
    never gave for that address is marked as its word (apart from the same name looked up), and the servers' addresses
    are listed."""
    evil, real = "203.0.113.7", "140.82.121.4"
    p = [eth(ip4(ME, evil, 17, udp(40000, 53, _query(1, "dns.google")))),
         eth(ip4(evil, ME, 17, udp(53, 40000, _answer(1, "dns.google", evil)))),          # "dns.google is me"
         eth(ip4(ME, evil, 17, udp(40001, 53, _query(2, "github.com")))),
         eth(ip4(evil, ME, 17, udp(53, 40001, _answer(2, "github.com", evil)))),          # "github.com is me"
         eth(ip4(ME, evil, 6, _tcp(50000, 443, 0x02))),
         eth(ip4(ME, evil, 6, _tcp(50000, 443, 0x18, 1, b"\x00" * 3000))),               # no name of its own
         eth(ip4(ME, evil, 6, _tcp(50001, 443, 0x02))),
         eth(ip4(ME, evil, 6, _tcp(50001, 443, 0x18, 1, client_hello("github.com")))),     # never looked up for it
         eth(ip4(ME, FWD, 17, udp(40002, 53, _query(3, "github.com")))),                   # the real one, looked up
         eth(ip4(FWD, ME, 17, udp(53, 40002, _answer(3, "github.com", real)))),
         eth(ip4(ME, real, 6, _tcp(50002, 443, 0x02))),
         eth(ip4(ME, real, 6, _tcp(50002, 443, 0x18, 1, client_hello("github.com"))))]
    r = _flows(p)
    hosts = {(h["host"], h["named_by"]): h for h in r["hosts"]}
    assert set(hosts) == {(evil, "address"), ("github.com", "program"), ("github.com", "tls")}, set(hosts)
    assert hosts[(evil, "address")]["ports"] == ["443", "53/udp"] and hosts[(evil, "address")]["addresses"] == [evil]
    assert hosts[("github.com", "program")]["addresses"] == [evil] and hosts[("github.com", "tls")]["addresses"] == [real]
    assert r["looked_up"] == ["dns.google"]
    # one name on many addresses: the first few are listed, and that there are more
    many = _flows([eth(ip4(ME, f"198.51.100.{i}", 6, _tcp(51000 + i, 443, flags, 1, data)))
                   for i in range(12) for flags, data in ((0x02, b""), (0x18, client_hello("cdn.example")))])
    cdn = next(h for h in many["hosts"] if h["host"] == "cdn.example")
    assert len(cdn["addresses"]) == pcap.ADDRESSES_MAX and cdn["more_addresses"] is True


def test_what_the_packets_are_summed_up_in_has_a_bound(monkeypatch):
    """The review of 2026-11-04: under the program's own traffic, Flows kept a name for every connection it summed up
    (100,000 TLS names left 80,000), and up to 70 KB of every unfinished DNS-over-TCP message, never dropped when the
    connection closed (3,000 to the resolver held 171 MB)."""
    monkeypatch.setattr(pcap, "CONNS_MAX", 10)
    p = []
    for i in range(200):
        p += [eth(ip4(ME, "203.0.113.9", 6, _tcp(20000 + i, 443, 0x02, 1000))),
              eth(ip4(ME, "203.0.113.9", 6, _tcp(20000 + i, 443, 0x18, 1001, client_hello(f"n{i}.example"))))]
    f = pcap.Flows(FWD)
    f.feed(_capture(p))
    assert len(f.used) == 0 and len(f.result()["hosts"]) == 200, "names nobody looked up aren't kept to leave out"
    unfinished = struct.pack(">H", 60000) + b"q" * 20000         # a message that never completes

    def lookup(port, close=None):
        return [eth(ip4(ME, FWD, 6, _tcp(port, 53, 0x02, 5000))), eth(ip4(ME, FWD, 6, _tcp(port, 53, 0x18, 5001, unfinished))),
                *([eth(ip4(ME, FWD, 6, _tcp(port, 53, close, 5001 + len(unfinished))))] if close else [])]
    f = pcap.Flows(FWD)
    f.feed(_capture([x for i in range(300) for x in lookup(30000 + i)]))
    assert len(f.streams) <= pcap.STREAMS_MAX and sum(len(s[1]) for s in f.streams.values()) <= pcap.BUFFERED_MAX
    # closed (FIN, or RST), a lookup's streams go, and leave room for the next one
    q, a = _query(9, "late.example"), _answer(9, "late.example", "203.0.113.20")
    f = pcap.Flows(FWD)
    f.feed(_capture([x for i in range(150) for x in lookup(31000 + i, 0x11 if i % 2 else 0x14)]
                    + [eth(ip4(ME, FWD, 6, _tcp(32000, 53, 0x02, 100))), eth(ip4(FWD, ME, 6, _tcp(53, 32000, 0x12, 900))),
                       eth(ip4(ME, FWD, 6, _tcp(32000, 53, 0x18, 101, struct.pack(">H", len(q)) + q))),
                       eth(ip4(FWD, ME, 6, _tcp(53, 32000, 0x18, 901, struct.pack(">H", len(a)) + a)))]))
    assert f.names.get("203.0.113.20") == "late.example" and len(f.streams) == 2


def test_the_result_says_when_watching_the_network_stopped(tmp_path):
    """The review of 2026-11-04: an error while summing up (a MemoryError) ended the reader without a word, the rest of
    the trial unobserved. The result says so, and the pipe is still read: pasta waits while it is full."""
    f = pcap.Flows(FWD)

    def fails(data):
        raise MemoryError
    f.feed = fails
    reader = trial.PipeReader(tmp_path / "packets", f)
    reader.start()
    try:
        w = os.open(tmp_path / "packets", os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(w, b"\0" * 4096)
            deadline = time.monotonic() + 3
            while not f.stopped and time.monotonic() < deadline:
                time.sleep(0.02)
            os.set_blocking(w, True)
            for _ in range(64):                                   # 4 MB, many times what a pipe holds
                os.write(w, b"\0" * 65536)
        finally:
            os.close(w)
    finally:
        reader.stop()
    assert f.stopped and pcap.Flows.result(f)["stopped"] is True


# ------------------------------------------------------------------ E5: no /proc masks in a trial, and the page says so

def test_a_trial_has_no_proc_masks_and_says_what_it_can_read(tmp_path):
    """E5: the review found that a trial's program reads the real kernel command line and boot id, which the browser's
    sandbox covers. Covering them breaks programs that start a sandbox with a /proc of their own: a WebKitGTK page in
    a sandbox like the trial's loaded without the masks and failed with them ("Can't mount proc", Fedora 44 with GNOME
    50, 2026-10-17). So a trial and a Box get none, and the page and the Box's guide say what the program can read."""
    from pathlib import Path
    from test_trial import a_trial, pairs, parts
    from daprivacyscanner.host import CommandResult, FakeRunner, Host
    from daprivacyscanner.tools import sandbox
    root = tmp_path / "root"
    (root / "tmp/.X11-unix").mkdir(parents=True)
    host = Host(home=root / "home/a", environ={"DISPLAY": ":0"},
                runner=FakeRunner(handlers={"bwrap": lambda a: CommandResult(a, 0, "")}), root=root, uid=1000)
    a = trial.ENGINES["bubblewrap"].command(host, a_trial(tmp_path), parts(host, tmp_path))
    covered = {inside for _outside, inside in pairs(a, "--ro-bind")}
    assert not covered & set(sandbox.PROC_OWN.values()) and not any(c.startswith("/proc/") for c in covered)
    js = (Path(__file__).parent.parent / "src/daprivacyscanner/web/app.js").read_text()
    assert "its command line (which often names your disks' ids)" in js


# ------------------------------------------------------------------ suspicion: a Flatpak trial's copies through the portal

PERMS = """[Context]
shared=network;ipc;
sockets=x11;wayland;pulseaudio;fallback-x11;pcsc;
devices=all;
features=devel;
filesystems=host;xdg-download;/run/media:ro;!xdg-music;

[Session Bus Policy]
org.gtk.vfs.*=talk
org.mpris.MediaPlayer2.app=own

[System Bus Policy]
org.freedesktop.NetworkManager=talk
"""


def _flatpak_host(tmp_path):
    from daprivacyscanner.host import CommandResult, FakeRunner, Host
    root = tmp_path / "root"
    (root / "run/user/1000/.flatpak").mkdir(parents=True)
    (root / "home/a").mkdir(parents=True)
    perms = lambda argv: CommandResult(argv, 0, PERMS if "--show-permissions" in argv else "")     # noqa: E731
    return Host(home=root / "home/a", environ={"XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"},
                runner=FakeRunner(handlers={"flatpak": perms}), root=root, uid=1000)


def test_a_flatpak_trial_takes_back_what_the_app_declares(tmp_path):
    """Found live on Mint 22.3 (Flatpak 1.14.6): a Flatpak trial's program ran `flatpak-spawn`, and the copy Flatpak's
    portal started had the app's declared permissions (Text Editor's host: the real home listed) and --filesystem=home
    meaning the real home. Everything declared is taken back on the command line, which the copy inherits, and the
    throwaway home is given by its path (tested there: the copy saw the trial's home and not the real one)."""
    from test_trial import a_trial, parts
    host = _flatpak_host(tmp_path)
    t = a_trial(tmp_path, kind="flatpak", argv=["org.x.App"], flatpak="org.x.App")
    t.options = {"network": "off", "gpu": True, "sound": False}
    a = trial.ENGINES["flatpak"].command(host, t, parts(host, tmp_path))
    assert "--filesystem=home" not in a and f"--filesystem={t.home}" in a
    for taken in ("--nofilesystem=host", "--nofilesystem=home", "--nofilesystem=xdg-download", "--nofilesystem=/run/media",
                  "--nosocket=wayland", "--nosocket=pulseaudio", "--nosocket=fallback-x11", "--nosocket=pcsc",
                  "--nodevice=all", "--unshare=network", "--disallow=devel"):
        assert taken in a, taken
    assert "--nosocket=x11" not in a and "--unshare=ipc" not in a, "what the trial gives (an X11 display) stays"
    assert a.index("--nodevice=all") < a.index("--device=dri"), "the graphics card, ticked, is given back after"
    assert "--nofilesystem=xdg-music" not in a
    # its declared bus names, and GVFS, which fetches over the network for its callers (the review of View offline…);
    # a copy that GTK 4's image loaders start sandboxed doesn't take these and still starts (tested, Flatpak 1.14.6)
    assert "--no-talk-name=org.gtk.vfs.*" in a and "--system-no-talk-name=org.freedesktop.NetworkManager" in a
    assert a.count("--no-talk-name=org.gtk.vfs.*") == 1 and "--no-talk-name=org.mpris.MediaPlayer2.app" in a
    assert a[4] == "--own-name=org.x.App", "a one-instance app must own its name, which --sandbox takes away"


def test_the_copies_flatpak_started_for_a_trial_are_ended_with_it(tmp_path, monkeypatch):
    """Found live: a copy started through the portal ran on after the trial was stopped. Flatpak records each copy's
    options, the trial's home's path among them; only those, alive in their own PID namespace, are ended."""
    import json
    from test_trial import a_trial
    host = _flatpak_host(tmp_path)
    t = a_trial(tmp_path, kind="flatpak", argv=["org.x.App"], flatpak="org.x.App")
    base = host.root / "run/user/1000/.flatpak"

    def instance(iid, home, pid, ns, alive_ns):
        (base / iid).mkdir()
        (base / iid / "info").write_text(f"[Application]\nname=org.x.App\n\n[Instance]\ninstance-id={iid}\n"
                                         f"extra-args=--unshare=network;--nofilesystem=home;--filesystem={home};\n")
        (base / iid / "bwrapinfo.json").write_text(json.dumps({"child-pid": pid, "pid-namespace": ns}))
        (host.root / f"proc/{pid}/ns").mkdir(parents=True)
        os.symlink(f"pid:[{alive_ns}]", host.root / f"proc/{pid}/ns/pid")
    instance("111", t.home, 4001, 9001, 9001)                   # the trial's copy, running
    instance("222", "/home/a/other", 4002, 9002, 9002)          # another app's (or the user's own) copy
    instance("333", t.home, 4003, 9003, 7777)                   # an ended copy whose number is used again
    (base / "org.x.App").mkdir()
    assert trial.flatpak_copies(host, t) == [4001]
    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))
    assert trial.end_flatpak_copies(host, t) == 1 and killed == [(4001, signal.SIGKILL)]


# ------------------------------------------------------------------ suspicion: decoys seen only through their own path

def test_a_decoy_is_seen_however_it_is_reached(tmp_path):
    """The review's suspicion, confirmed here: a folder's watch reports a file by the name it was opened under in that
    folder, so a decoy linked into another folder and read there, or read after its folder was renamed, went unseen.
    Each decoy file now has a watch on its own inode."""
    from daprivacyscanner.tools import bait, homewatch
    home = tmp_path / "home"
    home.mkdir()
    decoys = bait.plant(home)
    key = next(rel for rel, what in decoys.items() if rel == ".ssh/id_ed25519")
    wallet = next(rel for rel, what in decoys.items() if "wallet" in what.lower() and (home / rel).is_file())
    w = homewatch.HomeWatch(home, decoys)
    w.start()
    try:
        os.link(home / key, home / "innocent.txt")                     # a second name for the key, elsewhere
        (home / "innocent.txt").read_bytes()
        os.rename(home / os.path.dirname(wallet), home / "renamed")      # the wallet's folder renamed, then read
        (home / "renamed" / os.path.basename(wallet)).read_bytes()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len([d for d in w.decoys() if d["opened"]]) < 2:
            time.sleep(0.05)
    finally:
        w.stop()
    seen = {d["path"]: d for d in w.decoys()}
    assert seen["~/" + key]["opened"] == 1, "read through another name"
    assert seen["~/" + wallet]["opened"] == 1, "read in its folder under a new name"
    # reached by its own path, an opening is counted once, not by the folder's watch as well
    w = homewatch.HomeWatch(home, {".ssh/id_ed25519": decoys[".ssh/id_ed25519"]})
    w.start()
    try:
        (home / ".ssh/id_ed25519").read_bytes()
        time.sleep(0.3)
    finally:
        w.stop()
    assert w.decoys()[0]["opened"] == 1


def test_a_folder_swapped_for_a_link_isnt_listed_through_it(tmp_path, monkeypatch):
    """The review of 2026-11-04: between a new folder's watch being added and its listing, the program could swap the
    folder for a link (on a trial on the disk, ../../../.. leads to the real home): the listing followed it, the real
    home's names were recorded as made by the program, and its folders were watched. The folder is opened without
    following a link, watched and listed through that descriptor. The swap is made here at that very moment."""
    from daprivacyscanner.tools import homewatch
    home, outside = tmp_path / "home", tmp_path / "real-home"
    (outside / "Documents").mkdir(parents=True)
    (outside / "secret-name.txt").write_text("x")
    home.mkdir()
    real_watch = homewatch.HomeWatch._watch

    def swapping(self, path, *a):
        got = real_watch(self, path, *a)
        if path.endswith("/new") and os.path.isdir(path) and not os.path.islink(path):
            os.rename(path, path + ".old")
            os.symlink(str(outside), path)
        return got
    monkeypatch.setattr(homewatch.HomeWatch, "_watch", swapping)
    w = homewatch.HomeWatch(home)
    w.start()
    try:
        (home / "new").mkdir()
        deadline = time.monotonic() + 3
        while not (home / "new").is_symlink() and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.3)
        (outside / "Documents/later.txt").write_text("y")                # in a real folder of the user's
        time.sleep(0.5)
    finally:
        w.stop()
    seen = [r[0] for r in w.records()]
    assert not any("secret-name" in p or "Documents" in p or "later" in p for p in seen), seen
    assert not any(p.startswith(str(outside)) for p in w.wds.values()), "no watch on the real home's folders"

def test_no_display_says_what_has_nowhere_to_show(tmp_path):
    """Found live: a trial and a Box with no display said "There is no display to show the browser on"."""
    from daprivacyscanner.host import CommandResult, FakeRunner, Host
    from daprivacyscanner.tools import sandbox
    root = tmp_path / "root"
    (root / "run/user/1000").mkdir(parents=True)
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    host = Host(home=root / "home/a", environ={"XDG_RUNTIME_DIR": "/run/user/1000"},
                runner=FakeRunner(handlers={"bwrap": ok}), root=root, uid=1000)
    assert sandbox.display(host, tmp_path, False).note == "There is no display to show the browser on."
    folder = tmp_path / "t"
    for sub in ("home", "app", "private"):
        (folder / sub).mkdir(parents=True)
    t = trial.Trial("0a1b2c3d4e5f", folder, "memory", "program", "tool", "a Linux program", argv=["/app/tool"])
    with pytest.raises(trial.TrialError, match="^There is no display to show the program on.$"):
        trial.start(host, t, {}, lambda *a, **k: None)
    box = trial.Trial("0a1b2c3d4e5e", folder, "disk", "installed", "Chat", "a Box", argv=["/usr/bin/chat"],
                      private_at=folder / "private")
    with pytest.raises(trial.TrialError, match="^There is no display to show the app on.$"):
        trial.start(host, box, {}, lambda *a, **k: None)
    host.environ["DISPLAY"] = "localhost:10.0"                                     # forwarded over SSH
    with pytest.raises(trial.TrialError, match="over the network.*can't reach it"):
        trial.start(host, t, {}, lambda *a, **k: None)


def test_a_trial_says_what_wayland_gives_it_and_when_its_connection_couldnt_be_marked(tmp_path, monkeypatch):
    """The review of 2026-11-04: on Wayland the trial said only that its window was on a connection the desktop marks
    as a sandbox's. The page now has what the browser panel has (what the desktop still offers a marked connection,
    wlroots desktops), and the start says when marking the connection failed and the program got the desktop's own."""
    from types import SimpleNamespace
    from test_trial import a_trial
    from daprivacyscanner.host import CommandResult, FakeRunner, Host
    from daprivacyscanner.tools import sandbox
    root = tmp_path / "root"
    (root / "run/user/1000").mkdir(parents=True)
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    host = Host(home=root / "home/a", environ={"XDG_RUNTIME_DIR": "/run/user/1000", "WAYLAND_DISPLAY": "wayland-0",
                                               "XDG_CURRENT_DESKTOP": "sway"},
                runner=FakeRunner(handlers={"bwrap": ok, "pasta": ok, "ip": ok}), root=root, uid=1000)
    assert trial.status(host)["wlroots"] is True
    monkeypatch.setattr(sandbox, "display", lambda *a, **k: sandbox.Display(
        "wayland", [("/run/user/1000/wayland-0", "/run/user/1000/wayland-0")], {"WAYLAND_DISPLAY": "wayland-0"}))

    def fails(*a, **k):
        raise trial.wayland.WaylandError("the compositor refused it")
    monkeypatch.setattr(trial.wayland, "sandbox_socket", fails)
    t = a_trial(tmp_path, argv=["/app/tool"])
    how = trial.start(host, t, {}, lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None))
    try:
        assert how["display"] == "wayland" and how["wayland_context"] is False and how["wayland_failed"] is True
    finally:
        trial.stop(host, t)
    monkeypatch.setattr(trial.wayland, "sandbox_socket", lambda *a, **k: None)          # a desktop without the protocol
    t = a_trial(tmp_path / "b", argv=["/app/tool"])
    how = trial.start(host, t, {}, lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None))
    trial.stop(host, t)
    assert how["wayland_context"] is False and how["wayland_failed"] is False


# ------------------------------------------------------------------ E6: a Box whose program fails at start says so

def _box_host(tmp_path):
    from daprivacyscanner.host import CommandResult
    from conftest import make_host
    from test_box import DESKTOP
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    h = make_host(tmp_path, files={
        "/usr/share/applications/chat.desktop": DESKTOP.format(name="Chat App", exec="chat --flag %U", extra=""),
        "/usr/bin/chat": "", "/tmp/.X11-unix/X0": "", "/run/user/1000/x": ""},
        env={"XDG_DATA_DIRS": "/usr/share", "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"})
    for name in ("bwrap", "pasta", "ip", "flatpak"):
        h.runner.handlers[name] = ok
    return h


def test_a_flatpak_box_whose_app_is_gone_says_so(tmp_path):
    """Found in the review: box.problem() didn't ask whether a Flatpak Box's app is still installed, so its launcher
    only failed, out of sight."""
    from daprivacyscanner.host import CommandResult
    from daprivacyscanner.tools import box as B
    from test_box import a_box, set_up
    host = _box_host(tmp_path)
    set_up(host, a_box(slug="meet", name="Meet", kind="flatpak", argv=["--branch=stable", "org.x.Meet"], flatpak="org.x.Meet"))
    assert B.problem(host, B.read(host, "meet")) is None
    asked = []
    host.runner.handlers["flatpak"] = lambda argv: asked.append(argv) or CommandResult(argv, 1, "", "error: not installed")
    assert B.problem(host, B.read(host, "meet")) == "its Flatpak app (org.x.Meet) is no longer installed"
    assert list(asked[-1][-3:]) == ["--show-ref", "org.x.Meet", "stable"]


def test_a_box_whose_program_fails_at_once_says_so_in_a_dialog(tmp_path, monkeypatch):
    """Found live: a Box whose program failed as it started ended with exit status 0 and said nothing (box_cli
    ignored the run's result)."""
    from daprivacyscanner import app
    from daprivacyscanner.host import Host as RealHost
    from daprivacyscanner.tools import box as B
    from test_box import a_box, set_up
    host = _box_host(tmp_path)
    set_up(host, a_box())
    monkeypatch.setattr(RealHost, "local", staticmethod(lambda: host))
    said = []
    monkeypatch.setattr(app, "show_error", lambda text, detail="": said.append((text, detail)) or 2)
    result = {"failed": True, "seconds": 1, "ended": "ended with an error (exit status 127)",
              "output": ["chat: error while loading shared libraries: libfoo.so.1"]}
    monkeypatch.setattr(B, "run_to_end", lambda h, b: trial.Trial("x", tmp_path, "disk", "installed", "Chat App", "a Box",
                                                                   result=result))
    assert app.box_cli("chat-app") == 2
    assert said == [("Chat App couldn't start in its Box: it ended with an error (exit status 127).",
                     "What it printed last:\nchat: error while loading shared libraries: libfoo.so.1")]
    said.clear()
    result.update(seconds=3600)                         # ended with an error after an hour's use: not a failed start
    assert app.box_cli("chat-app") == 0 and said == []


# ------------------------------------------------------------------ E9: in memory isn't off the disk where swap is

def test_the_memory_place_says_when_swap_or_hibernation_can_reach_a_disk(tmp_path, monkeypatch):
    """The page said nothing of a trial in memory touched the disk, but the runtime folder isn't kept out of swap."""
    from daprivacyscanner.host import CommandResult, FakeRunner, Host
    from daprivacyscanner.tools import ramdisk
    root = tmp_path / "root"
    (root / "run/user/1000").mkdir(parents=True)
    (root / "proc").mkdir()
    (root / "proc/swaps").write_text("Filename\tType\tSize\tUsed\tPriority\n/swapfile file 2097148 0 -2\n"
                                     "/dev/zram0 partition 4000000 0 100\n")
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    host = Host(home=root / "home/a", environ={"XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"},
                runner=FakeRunner(handlers={"bwrap": ok, "pasta": ok, "ip": ok}), root=root, uid=1000)
    monkeypatch.setattr(ramdisk, "hibernation_possible", lambda h: True)
    memory = next(p for p in trial.status(host)["places"] if p["id"] == "memory")
    assert memory["swap"] == ["/swapfile"] and memory["hibernation"] is True, "zram without a writeback device isn't a disk"


# ------------------------------------------------------------------ E8: unpacking stops at the room there is

def _unpack(src, dst, limit, most=1000):
    dst.mkdir(exist_ok=True)
    return subprocess.run([sys.executable, "-I", "-c", trial.UNPACK, str(src), str(dst), str(limit), str(most)],
                          capture_output=True, text=True, timeout=60)


def test_unpacking_never_takes_more_than_there_is_room_for(tmp_path):
    """Found in the review: a zip bomb was unpacked in full (8 GB allowed whatever was free, in the runtime folder the
    whole session uses), and a .deb of the kind dpkg-deb -x unpacked had no limit at all."""
    import io
    import tarfile
    import zipfile
    assert trial.unpack_limit({"free": 1 << 30}) == (1 << 30) - trial.ROOM_KEPT
    assert trial.unpack_limit({"free": 64 << 30}) == trial.UNPACK_MAX and trial.unpack_limit({"free": 1 << 20}) == 0
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
        for i in range(3):
            f.writestr(f"part{i}", b"\0" * (1 << 20))
    r = _unpack(z, tmp_path / "z", 2 << 20)
    assert r.returncode and "the most there is room for here" in r.stderr and not list((tmp_path / "z").iterdir())
    t = tmp_path / "bomb.tar.gz"
    with tarfile.open(t, "w:gz") as f:
        for i in range(5):
            info = tarfile.TarInfo(f"part{i}")
            info.size = 1 << 20
            f.addfile(info, io.BytesIO(b"\0" * info.size))
    r = _unpack(t, tmp_path / "t", (5 << 20) // 2)
    assert r.returncode and len(list((tmp_path / "t").iterdir())) == 2, "it stops before writing past the limit"
    assert _unpack(t, tmp_path / "t2", 64 << 20, most=3).returncode, "and at the most files"
    assert _unpack(t, tmp_path / "t3", 64 << 20).returncode == 0 and len(list((tmp_path / "t3").iterdir())) == 5


@pytest.mark.skipif(not os.path.exists("/usr/bin/dpkg-deb") or sys.version_info >= (3, 14), reason="dpkg-deb's path")
def test_a_zstd_package_goes_through_the_same_limit(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "DEBIAN").mkdir(parents=True)
    (pkg / "DEBIAN/control").write_text("Package: big\nVersion: 1\nArchitecture: all\nMaintainer: x <x@example.org>\n"
                                        "Description: test\n")
    (pkg / "usr/share/big").mkdir(parents=True)
    (pkg / "usr/share/big/blob").write_bytes(os.urandom(3 << 20))
    deb = tmp_path / "big.deb"
    built = subprocess.run(["/usr/bin/dpkg-deb", "--root-owner-group", "-Zzstd", "--build", str(pkg), str(deb)],
                           capture_output=True)
    if built.returncode:
        pytest.skip("this dpkg-deb can't build a zstd package")
    r = _unpack(deb, tmp_path / "out", 1 << 20)
    assert r.returncode and "the most there is room for here" in r.stderr
    assert not (tmp_path / "out/usr/share/big/blob").exists()
    assert _unpack(deb, tmp_path / "ok", 64 << 20).returncode == 0 and (tmp_path / "ok/usr/share/big/blob").stat().st_size == 3 << 20


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="tarfile reads zstd itself from Python 3.14")
def test_a_zstd_tarball_goes_through_zstd(tmp_path):
    """The review of 2026-11-04: a .tar.zst was taken as an archive and then failed to unpack, "tarfile.ReadError:
    truncated header" (tarfile reads zstd only from Python 3.14). It goes through zstd, as a .deb's files do, within
    the same limits; without zstd it says so in plain words."""
    import tarfile
    zst = tmp_path / "tool.tar.zst"
    zst.write_bytes(b"\x28\xb5\x2f\xfd" + b"\0" * 60)
    (tmp_path / "nothing").mkdir()
    (tmp_path / "none").mkdir()
    r = subprocess.run([sys.executable, "-I", "-c", trial.UNPACK, str(zst), str(tmp_path / "none"), str(1 << 20), "100"],
                       capture_output=True, text=True, timeout=60, env={"PATH": str(tmp_path / "nothing")})
    assert r.returncode and r.stderr.strip().endswith("unpack it yourself and try the program in it.")
    if not os.path.exists("/usr/bin/zstd"):
        pytest.skip("zstd isn't installed")
    (tmp_path / "tool").mkdir()
    (tmp_path / "tool/run.sh").write_text("#!/bin/sh\necho hi\n")
    with tarfile.open(tmp_path / "tool.tar", "w") as t:
        t.add(tmp_path / "tool", arcname="tool")
    zst.unlink()
    subprocess.run(["/usr/bin/zstd", "-q", str(tmp_path / "tool.tar"), "-o", str(zst)], check=True)
    assert trial.classify(zst).kind == "archive"
    r = _unpack(zst, tmp_path / "out", 64 << 20)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "out/tool/run.sh").read_text() == "#!/bin/sh\necho hi\n"
    r = _unpack(zst, tmp_path / "small", 4)
    assert r.returncode and "the most there is room for here" in r.stderr


def test_preparing_passes_the_room_there_is(tmp_path, monkeypatch):
    from daprivacyscanner.host import FakeRunner, Host
    root = tmp_path / "root"
    (root / "home/a/Downloads").mkdir(parents=True)
    host = Host(home=root / "home/a", environ={}, runner=FakeRunner(), root=root, uid=1000)
    src = host.home / "Downloads/a.tar.gz"
    src.write_bytes(b"\x1f\x8b\x08" + b"\0" * 20)
    got = []
    monkeypatch.setattr(trial, "places", lambda h: [{"id": "memory", "words": "In memory", "free": 900 << 20,
                                                    "noexec": False, "folder": str(tmp_path / "rt/daprivacyscanner-trial")}])
    monkeypatch.setattr(trial.sandbox, "program", lambda h, n: "/usr/bin/bwrap")
    run = lambda argv, **kw: got.append(argv) or subprocess.CompletedProcess(argv, 1, b"", b"stop here")   # noqa: E731
    with pytest.raises(trial.TrialError):
        trial.prepare_file(host, src, "memory", run=run)
    assert got[0][-2:] == [str((900 << 20) - trial.ROOM_KEPT), str(trial.MEMBERS_MAX)]


def _descendants(pid: int) -> set[int]:
    kids: dict[int, list[int]] = {}
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                with open(f"/proc/{name}/stat") as f:
                    kids.setdefault(int(f.read().rsplit(")", 1)[1].split()[1]), []).append(int(name))
            except (OSError, IndexError, ValueError):
                pass
    out, todo = set(), [pid]
    while todo:
        for c in kids.get(todo.pop(), []):
            if c not in out:
                out.add(c)
                todo.append(c)
    return out


def _runs(pid: int, argv: list[str]) -> bool:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().split(b"\0")[:len(argv)] == [a.encode() for a in argv]
    except OSError:
        return False


@pytest.mark.skipif(not os.path.exists("/usr/bin/bwrap") or not os.path.exists("/usr/bin/python3"), reason="bubblewrap")
def test_unpacking_ends_with_its_bubblewrap(tmp_path):
    """The review of 2026-11-04: the unpacking sandbox had no --die-with-parent, so at the 900 s time limit (or with the
    app killed) only bubblewrap was ended, and the unpacker went on writing into the trial's folder, removed meanwhile.
    Here it waits for an archive that never comes (a pipe), and bubblewrap is killed."""
    from pathlib import Path
    from daprivacyscanner.host import FakeRunner, Host
    host = Host(home=tmp_path, environ={}, runner=FakeRunner(installed=["bwrap"]), root=Path("/"), uid=os.getuid())
    source, out = tmp_path / "source", tmp_path / "out"
    os.mkfifo(source)
    out.mkdir()
    argv = trial.unpack_argv(host, source, out)
    assert "--die-with-parent" in argv[:argv.index("--")]
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    unpacker = None
    try:
        deadline = time.monotonic() + 10
        while unpacker is None and p.poll() is None and time.monotonic() < deadline:
            unpacker = next((c for c in _descendants(p.pid) if _runs(c, [trial.sandbox.PYTHON, "-I", "-c", trial.UNPACK])), None)
            time.sleep(0.05)
        if unpacker is None:
            pytest.skip("bubblewrap can't make a sandbox here")
        p.kill()
        p.wait()
        assert _gone(unpacker), "the unpacker ends with bubblewrap"
    finally:
        p.kill()
        if unpacker is not None and not _gone(unpacker, 0.1):     # the old way: it waits on the pipe for good
            try:
                os.close(os.open(source, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass


def test_the_box_says_its_site_codes_can_be_tested(cat, tmp_path):
    """E7, the owner's decision: the per-host HMACs in runs.json stay (they count the new hosts), and the text that said
    no names of sites were kept says what they allow: anyone who can read the Box's folder can test a guess."""
    from pathlib import Path
    from test_guides import build
    host = _box_host(tmp_path)
    g = build(cat, host, "app.boxes")
    text = " ".join(body for s in g.steps for _head, body in (s.parts or []))
    assert "No names of sites" not in text and "could check whether it contacted a site" in text
    js = (Path(__file__).parent.parent / "src/daprivacyscanner/web/app.js").read_text()
    assert "no names of sites or files are kept" not in js and "could check whether it contacted a site" in js


# ------------------------------------------------------------------ E11: a newer copy of a Box's program

def test_a_newer_copy_of_a_boxs_program_replaces_the_old_one_and_reverts(cat, tmp_path, monkeypatch):
    """Found in the review: keeping a newer program of the same file name in its Box silently kept the old one (the
    copy was skipped since the Box's app folder was there, and the guide said there was nothing left to do)."""
    from daprivacyscanner.tools import box as B
    from daprivacyscanner.tools import integration as I
    from daprivacyscanner.runner import Runner
    from test_guides import apply, build, options, revert
    host = _box_host(tmp_path)
    exe = tmp_path / "bin/daprivacyscanner"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(I, "program", lambda environ: [str(exe)])
    src = host.home / "Downloads"
    src.mkdir()
    v1 = b"\x7fELF\x02\x01\x01\x00AI\x02" + b"1" * 80
    (src / "Great Tool.AppImage").write_bytes(v1)
    t1 = trial.prepare_file(host, src / "Great Tool.AppImage", "disk")
    monkeypatch.setattr(trial, "CURRENT", t1)
    apply(host, options(build(cat, host, "app.boxes"))["Set up a Box for Great Tool"])
    trial.discard(host, t1)
    f = host.home / "Boxes/great-tool"
    (f / "home/settings").write_text("the app's own data")
    # the same release tried again: nothing to change
    t2 = trial.prepare_file(host, src / "Great Tool.AppImage", "disk")
    monkeypatch.setattr(trial, "CURRENT", t2)
    g = Runner(cat, host).plan_fix("app.boxes", {"source": "trial"})[1]
    assert g.steps[1].done and not any(o.plan.actions for st in g.steps for o in st.options)
    trial.discard(host, t2)
    # a newer release of the same name: it replaces the copy in the Box, said, and reverting puts the old one back
    v2 = b"\x7fELF\x02\x01\x01\x00AI\x02" + b"2" * 90
    (src / "Great Tool.AppImage").write_bytes(v2)
    t3 = trial.prepare_file(host, src / "Great Tool.AppImage", "disk")
    monkeypatch.setattr(trial, "CURRENT", t3)
    try:
        g = Runner(cat, host).plan_fix("app.boxes", {"source": "trial"})[1]
        opt = next(o for st in g.steps for o in st.options)
        assert not g.steps[1].done and [a.kind for a in opt.plan.actions] == ["copytree"]
        assert any("already holds another copy of Great Tool" in e for e in opt.plan.side_effects)
        log, res = apply(host, opt.plan)
        assert (f / "app/Great_Tool.AppImage").read_bytes() == v2 and (f / "home/settings").exists()
        revert(host, log, res)
        assert (f / "app/Great_Tool.AppImage").read_bytes() == v1, "the earlier copy is put back"
        assert (f / "home/settings").read_text() == "the app's own data"
    finally:
        trial.discard(host, t3)


def test_sound_says_all_the_sound_server_gives(cat, tmp_path):
    """The review's suspicion: the sound tick said only "the microphone", while the browser panel lists more for the
    same socket (the user's and computer's names, other programs, and modules that connect out or listen, past the
    sandbox's network). The Box's guide says it all; the page's tick lists soundRisks (the web test)."""
    from daprivacyscanner.runner import Runner
    g = Runner(cat, _box_host(tmp_path)).plan_fix("app.boxes", {"source": "chat.desktop"})[1]
    sound = next(i for s in g.steps for i in s.inputs if i.name == "sound")
    assert "microphone" in sound.help and "computer's name" in sound.help and "even with no network of its own" in sound.help


def test_what_a_program_printed_never_goes_to_the_journal(monkeypatch, capsys):
    from daprivacyscanner import app
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert app.show_error("Chat App couldn't start in its Box.", "What it printed last:\n/home/a/secret.txt") == 2
    err = capsys.readouterr().err
    assert "couldn't start" in err and "secret" not in err
