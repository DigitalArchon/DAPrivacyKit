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


def test_the_commands_exit_status_is_passed_on_and_stop_reaches_the_command():
    run = lambda *argv: subprocess.run([sys.executable, "-I", "-c", trial.TETHER, str(os.getpid()), *argv],   # noqa: E731
                                       timeout=20).returncode
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
    assert hosts["site-b.example"]["received"] == 300 and hosts["site-b.example"]["named_by"] == "tls"
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
         *[eth(ip4(ME, "192.0.2.53", 6, _tcp(6002, 53, 0x02, 5000))) for _ in range(5)],   # a server of its own, silent
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
    p = [eth(ip4(ME, "203.0.113.9", 6, _tcp(7000, 443, 0x02))), eth(ip4(ME, "203.0.113.9", 6, _tcp(7000, 443, 0x11, 1))),
         eth(ip4(ME, "203.0.113.9", 6, _tcp(7000, 443, 0x02)))]
    assert _flows(p)["hosts"][0]["connections"] == 2


def test_a_full_table_folds_the_older_connections_into_their_hosts(monkeypatch):
    monkeypatch.setattr(pcap, "CONNS_MAX", 4)
    p = [eth(ip4(ME, "203.0.113.%d" % (i % 2 + 1), 6, _tcp(8000 + i, 443, 0x02))) for i in range(9)]
    r = _flows(p)
    assert sum(h["connections"] for h in r["hosts"]) == 9 and len(r["hosts"]) == 2
    assert _flows(p)["hosts"] == r["hosts"], "summing up twice changes nothing"


# ------------------------------------------------------------------ E10: a trial's and a Box's own words

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


def test_what_a_program_printed_never_goes_to_the_journal(monkeypatch, capsys):
    from daprivacyscanner import app
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert app.show_error("Chat App couldn't start in its Box.", "What it printed last:\n/home/a/secret.txt") == 2
    err = capsys.readouterr().err
    assert "couldn't start" in err and "secret" not in err
