"""The review of 2026-11-12 (the sandbox's walls): a system-call filter on every sandbox, wired in as each starts; on
X11 a display of its own by default; the lookups' filter in front of pasta's forwarder; NAT64 and pings fenced; text
from inside shown only as the program's own; chmod never through a link; the focus keeper sizing windows."""

import errno
import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.tools import dnsfilter as D
from daprivacyscanner.tools import ramdisk as R
from daprivacyscanner.tools import sandbox as S
from daprivacyscanner.tools import seccomp
from daprivacyscanner.tools import torgate
from daprivacyscanner.tools import xfocus as X


def a_host(tmp_path, **env):
    root = tmp_path / "root"
    home = root / "home/alice"
    for d in ("home/alice", "tmp/.X11-unix", "usr/bin", "etc", "proc/net"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "proc/net/unix").write_text("")
    return Host(home=home, environ={"HOME": str(home), **env}, root=root, uid=1000,
                runner=FakeRunner(handlers={"bwrap": lambda argv: CommandResult(tuple(argv), 0, ""),
                                            "ip": lambda argv: CommandResult(tuple(argv), 0, "[]" if "-j" in argv else "")}))


# ------------------------------------------------------------------ the filter, as each sandbox gets it

def test_a_filter_is_a_memory_file_or_under_pasta_a_file_opened_on_the_far_side(tmp_path):
    f = S.make_filter(seccomp.STRICT)
    try:
        if not seccomp.supported():
            assert f.argv() == [] and f.fds() == ()
            return
        assert f.argv() == ["--seccomp", str(f.fd)] and f.fds() == (f.fd,)
        assert os.pread(f.fd, 1 << 20, 0) == seccomp.program(seccomp.STRICT)
        assert f.wrap(["bwrap", "x"]) == ["bwrap", "x"]
    finally:
        f.close()
    assert f.fd is None
    g = S.make_filter(seccomp.BROWSER, tmp_path)
    assert g.argv() == ["--seccomp", str(S.FILTER_FD)] and g.fds() == ()
    assert g.file.read_bytes() == seccomp.program(seccomp.BROWSER)
    assert g.wrap(["bwrap", "x"]) == ["/bin/sh", "-c", S.OPEN_FILTER, str(g.file), "bwrap", "x"]


@pytest.mark.skipif(not shutil.which("bwrap") or not seccomp.supported(), reason="bubblewrap on x86-64")
def test_the_shell_opens_the_file_for_bubblewrap_which_closes_it_before_anything_runs(tmp_path):
    """As under pasta: nothing in the sandbox holds the filter's file (its path names the user)."""
    if subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"]).returncode:
        pytest.skip("bubblewrap can't make a sandbox here")
    f = S.make_filter(seccomp.STRICT, tmp_path)
    probe = ("import os, ctypes\nl = ctypes.CDLL(None, use_errno=True)\nfds = []\n"
             "for x in os.listdir('/proc/self/fd'):\n    try:\n        fds.append(os.readlink('/proc/self/fd/' + x))\n"
             "    except OSError:\n        pass\nprint(sorted(fds))\nprint(l.syscall(250, 0, -3, 0), ctypes.get_errno())\n")
    r = subprocess.run(f.wrap(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
                               *f.argv(), "--", sys.executable, "-I", "-c", probe]),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    fds, keyctl = r.stdout.strip().splitlines()
    assert str(tmp_path) not in fds and keyctl == f"-1 {errno.EPERM}"


def test_the_filter_folder_is_the_runtime_folder_when_it_is_the_users(tmp_path):
    host = a_host(tmp_path, XDG_RUNTIME_DIR=str(tmp_path / "run"))
    (tmp_path / "run").mkdir(mode=0o700)
    assert S.filter_folder(host, tmp_path / "priv") == tmp_path / "run"
    host = a_host(tmp_path)
    assert S.filter_folder(host, tmp_path / "priv") == tmp_path / "priv"


def test_strict_sandboxes_refuse_user_namespaces_twice_where_bubblewrap_can(tmp_path):
    host = a_host(tmp_path)
    assert S.no_new_userns(host) == []                   # this bubblewrap's --help doesn't name it
    S._BWRAP_HELP.clear()
    host.runner.handlers["bwrap"] = lambda argv: CommandResult(tuple(argv), 0, "    --disable-userns  Disable further use")
    assert S.no_new_userns(host) == ["--unshare-user", "--disable-userns"]
    S._BWRAP_HELP.clear()


def test_tor_browser_s_inner_sandboxes_get_theirs_from_the_gate(tmp_path):
    """The gate makes each inner filter's descriptor from the program in its configuration, in place of the
    placeholder: tor's strict, the browser's the browser profile; the outer one gets the nesting profile."""
    if not seccomp.supported():
        pytest.skip("x86-64")
    programs = {p: seccomp.program(p).hex() for p in (seccomp.STRICT, seccomp.BROWSER)}
    argv, fds = torgate.with_filters(["bwrap", *S.gate_filter(seccomp.STRICT), "--", "tor"], programs)
    try:
        assert argv[1] == "--seccomp" and int(argv[2]) == fds[0] and argv[3:] == ["--", "tor"]
        assert os.pread(fds[0], 1 << 20, 0) == seccomp.program(seccomp.STRICT)
    finally:
        torgate._close(fds)
    with pytest.raises(KeyError):
        torgate.with_filters(["bwrap", "--seccomp", "@SECCOMP:nesting@"], programs)
    assert torgate.with_filters(["bwrap", "--", "x"], {}) == (["bwrap", "--", "x"], [])


# ------------------------------------------------------------------ X11: a display of its own by default

def test_on_x11_a_display_of_its_own_unless_the_user_says_otherwise(tmp_path):
    host = a_host(tmp_path, DISPLAY=":0")
    disp = S.Display("x11", [("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0")], {"DISPLAY": ":0"})
    with pytest.raises(S.SandboxError, match="Xephyr.*isn't installed here: install it \\(sudo apt install x\\)"):
        S.own_display(host, disp, None, False, "the program", "sudo apt install x")
    assert S.own_display(host, disp, None, True, "the program") is False          # the opt-out, ticked
    with pytest.raises(S.SandboxError):
        S.own_display(host, disp, True, True, "the program")                       # asked for, and missing
    host.runner.handlers["Xephyr"] = lambda argv: CommandResult(tuple(argv), 0, "")
    assert S.own_display(host, disp, None, False, "the program") is True          # the default where it is there
    assert S.own_display(host, disp, None, True, "the program") is False
    wl = S.Display("wayland", [], {})
    assert S.own_display(host, wl, None, False) is False
    over_ssh = S.Display("x11", [], {}, network=True)
    assert S.own_display(host, over_ssh, None, False) is False


def test_the_focus_keeper_fills_the_display_for_programs_not_the_browser(tmp_path):
    host = a_host(tmp_path, DISPLAY=":0")
    (host.root / "tmp/.X11-unix/X0").write_text("")
    (host.root / "usr/bin/python3").write_text("")
    host.runner.handlers["Xephyr"] = lambda argv: CommandResult(tuple(argv), 0, "")
    private = tmp_path / "private"
    private.mkdir()
    n = S.nested(host, private, "t", "1280x800")
    i = n.argv.index("--")
    assert n.argv[i + 1:i + 4] == [S.PYTHON, "-I", "-c"] and n.argv[i + 5] == "Xephyr"
    n = S.nested(host, private, "t", "1280x800", fill=True)
    i = n.argv.index("--")
    assert n.argv[i + 5:i + 7] == ["--fill", "Xephyr"]
    f = S.make_filter(seccomp.STRICT)
    try:
        n = S.nested(host, private, "t", "1280x800", filt=f)
        assert n.argv[n.argv.index("--seccomp") + 1] == str(f.fd) if f.fd is not None else "--seccomp" not in n.argv
    finally:
        f.close()


class FakeConn:
    def __init__(self, replies):
        self.root, self.width, self.height = 1, 1400, 1000
        self.sent, self.replies, self.events = [], replies, []

    def send(self, req):
        self.sent.append(req)
        return len(self.sent)

    def ask(self, req):
        self.sent.append(req)
        return self.replies.get(req[0], lambda r: None)(req)


def geometry(x, y, w, h):
    return b"\x01" + b"\0" * 11 + struct.pack("<hhHH", x, y, w, h) + b"\0" * 12


def prop(words):
    return bytes([1, 32]) + b"\0" * 14 + struct.pack("<I", len(words)) + b"\0" * 12 + struct.pack(f"<{len(words)}I", *words)


def test_fill_sizes_a_main_window_to_the_display_and_leaves_dialogs_and_the_browser():
    def reply(req):
        window, atom = struct.unpack_from("<II", req, 4)
        if atom == X.WM_TRANSIENT_FOR:
            return prop([7] if window == 30 else [])
        return prop([X.P_MAX_SIZE, 0, 0, 0, 0, 0, 0, 800, 600]) if window == 40 else prop([])
    c = FakeConn({X.GET_GEOMETRY: lambda r: geometry(0, 0, 300, 200), X.GET_PROPERTY: reply})
    k = X.Keeper(c, fill=True)
    configured = lambda: [struct.unpack_from("<IHxxiiII", r, 4) for r in c.sent if r[0] == X.CONFIGURE_WINDOW]  # noqa: E731
    for w in (20, 30, 40):
        k.alive.add(w)
        k.handle(struct.pack("<BxHIIB", X.MAP_NOTIFY, 0, c.root, w, 0) + b"\0" * 19)
    assert configured() == [(20, 15, 0, 0, 1400, 1000), (40, 15, 300, 200, 800, 600)]     # the dialog (30) as it is
    # the display resized (Xephyr's window, by the user): the main windows with it
    c.sent.clear()
    k.handle(struct.pack("<BxHIIIhhHH", X.CONFIGURE_NOTIFY, 0, c.root, c.root, 0, 0, 0, 1200, 900) + b"\0" * 8)
    assert configured() == [(20, 15, 0, 0, 1200, 900), (40, 15, 200, 150, 800, 600)]
    # the browser's keeper never sizes a window (resistFingerprinting sizes the browser's own)
    c = FakeConn({X.GET_GEOMETRY: lambda r: geometry(0, 0, 300, 200), X.GET_PROPERTY: reply})
    k = X.Keeper(c)
    k.alive.add(20)
    k.handle(struct.pack("<BxHIIB", X.MAP_NOTIFY, 0, c.root, 20, 0) + b"\0" * 19)
    assert not [r for r in c.sent if r[0] in (X.CONFIGURE_WINDOW, X.GET_PROPERTY)]
    assert X.fill_size([], 1280, 800) == (1280, 800) and X.fill_size([X.P_MAX_SIZE, 0, 0, 0, 0, 0, 0, 2000, 400], 1280, 800) == (1280, 400)


# ------------------------------------------------------------------ the lookups' filter

def query(name, qtype=1, qid=0x1234):
    return (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0" + struct.pack(">HH", qtype, 1))


def answer(q, *addrs):
    rr = b""
    for a in addrs:
        packed = socket.inet_pton(socket.AF_INET6 if ":" in a else socket.AF_INET, a)
        rr += b"\xc0\x0c" + struct.pack(">HHIH", 28 if ":" in a else 1, 1, 60, len(packed)) + packed
    return q[:2] + struct.pack(">HHHHH", 0x8180, 1, len(addrs), 0, 0) + q[12:] + rr


POLICY = D.Policy([*S.FENCE_V4, *S.FENCE_V6, "203.0.113.0/24", "2001:db8:1::/64", *S.nat64(["203.0.113.0/24"])],
                  ["10.64.0.1/32", "10.124.0.0/22"])


@pytest.mark.parametrize("name, qtype, refused", [
    ("example.com", 1, None), ("mullvad.net", 28, None), ("_dmarc.example.com", 16, None),
    ("_gateway", 1, "one label"), ("_outbound", 1, "one label"), ("devbox", 1, "one label"),
    ("printer.local", 1, "a local name"), ("nas.lan", 1, "a local name"), ("OPNsense.localdomain", 1, "a local name"),
    ("box.home.arpa", 1, "a local name"),
    ("1.1.168.192.in-addr.arpa", 12, "a local address's name"), ("168.192.in-addr.arpa", 6, "a local address's name"),
    ("5.113.0.203.in-addr.arpa", 12, "a local address's name"), ("in-addr.arpa", 12, "a local address's name"),
    ("x.y.in-addr.arpa", 12, "a local address's name"), ("8.8.8.8.in-addr.arpa", 12, None),
    (ipaddress.ip_address("fe80::1").reverse_pointer, 12, "a local address's name"),
    (ipaddress.ip_address("2001:db8:1::5").reverse_pointer, 12, "a local address's name"),
    ("8.e.f.ip6.arpa", 12, "a local address's name"),
    (ipaddress.ip_address("2001:4860:4860::8888").reverse_pointer, 12, None),
    ("4.0.0.2.ip6.arpa", 6, None), ("1.0.0.2.ip6.arpa", 6, "a local address's name"),     # 2001::/16 holds a local one
])
def test_the_filter_passes_internet_names_and_refuses_the_local_network_s(name, qtype, refused):
    assert POLICY.question(query(name, qtype)) == refused


def test_answers_with_a_local_address_are_refused_whole():
    q = query("example.com")
    assert POLICY.answer(answer(q, "93.184.215.14")) is None
    assert POLICY.answer(answer(q, "93.184.215.14", "192.168.1.5")) == "a local address"
    assert POLICY.answer(answer(q, "203.0.113.7")) == "a local address"                 # one of this computer's networks
    assert POLICY.answer(answer(q, "64:ff9b::c0a8:105")) == "a local address"           # DNS64's form of 192.168.1.5
    assert POLICY.answer(answer(q, "64:ff9b::5db8:d70e")) is None                       # an internet address through NAT64
    assert POLICY.answer(answer(q, "fd00::1")) == "a local address"
    assert POLICY.answer(answer(q, "10.124.0.241")) is None, "Mullvad's proxies, which the fence lets through too"
    r = D.refusal(q)
    assert r[:2] == q[:2] and r[3] & 0xF == D.REFUSED and r[2] & 0x80 and struct.unpack_from(">H", r, 6)[0] == 0
    assert r[12:] == q[12:]
    with pytest.raises(ValueError):
        POLICY.question(q[:12] + b"\xc0\x0c\x00\x01\x00\x01")                     # a pointer in the question


def test_the_fence_lets_only_the_filter_s_marked_queries_through(tmp_path):
    host = a_host(tmp_path)
    script = S.fence(host, networks=([], []), filtered=True)[2]
    assert f"dport 53 fwmark {S.DNS_MARK:#x} pref 50" in script and "ipproto tcp" not in script.split("prohibit")[0]
    assert "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter" in script and "/conf/eth0/rp_filter" in script
    script = S.fence(host, networks=([], []))[2]
    assert "fwmark" not in script and "rp_filter" not in script
    # the NAT64 forms of the fence's own ranges are fenced, the rest of the prefix (the IPv4 internet) isn't
    assert "64:ff9b::c0a8:0/112" in S.FENCE_V6 and "64:ff9b::a00:0/104" in S.FENCE_V6 and "64:ff9b::/96" not in S.FENCE_V6
    assert "--no-icmp" in S.PASTA_OPTS


def test_pasta_s_command_runs_the_fence_then_the_filter_then_bubblewrap(tmp_path):
    host = a_host(tmp_path)
    assert S.pasta_command(host, ["bwrap", "--", "x"], "pasta", proxies=True)[1] is False      # no python3 here
    (host.root / "usr/bin/python3").write_text("")
    f = S.make_filter(seccomp.BROWSER, tmp_path) if seccomp.supported() else None
    cmd, filtered = S.pasta_command(host, ["bwrap", "--", "x"], "pasta", proxies=True, filt=f)
    assert filtered and S.lookups_resolv(host, True) == S.FILTER_RESOLV and S.lookups_resolv(host, False) == S.FORWARD_RESOLV
    i = cmd.index("--")
    fence = cmd.index("/bin/sh")
    python = cmd.index(S.PYTHON)
    assert i < fence < python < cmd.index("bwrap") and "fwmark" in cmd[fence + 2]
    cfg = json.loads(cmd[python + 4])
    assert cfg["upstream"] == S.DNS_FORWARD and cfg["mark"] == S.DNS_MARK and "10.124.0.0/22" in cfg["allow"]
    assert "192.168.0.0/16" in cfg["refuse"] and "64:ff9b::c0a8:0/112" in cfg["refuse"]
    if f is not None:
        assert cmd[python + 5:python + 9] == ["/bin/sh", "-c", S.OPEN_FILTER, str(f.file)]
    host.runner.handlers.pop("ip")
    host.runner.installed.discard("ip")
    with pytest.raises(S.SandboxError, match="can't be fenced off"):
        S.pasta_command(host, ["bwrap"], "pasta", proxies=False)


def _pasta_works():
    if not (shutil.which("pasta") and shutil.which("bwrap") and shutil.which("ip")):
        return False
    return subprocess.run(["pasta", "--config-net", "--quiet", "--", "/bin/true"], capture_output=True,
                          timeout=30).returncode == 0


LOOKUP = r"""
import socket, struct, sys
def q(name, server):
    msg = struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) \
        + b"\0\0\1\0\1"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(msg, (server, 53))
        return s.recv(4096)[3] & 15
    except OSError as e:
        return type(e).__name__
out = {"gateway": q("_gateway", "127.0.0.1"), "direct": q("_gateway", "169.254.0.1")}
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).setsockopt(socket.SOL_SOCKET, 36, 0x5EC)
    out["mark"] = "set"
except OSError as e:
    out["mark"] = e.errno
print(out)
"""


@pytest.mark.skipif(not _pasta_works(), reason="pasta, bubblewrap and ip")
def test_in_pasta_s_namespace_the_sandbox_can_t_go_round_the_filter(tmp_path):
    """The real pasta and bubblewrap (no packet leaves: the questions are refused before any is passed on): the filter
    refuses _gateway, the forwarder itself is out of the sandbox's reach, and the sandbox can't mark a socket."""
    host = Host(home=Path.home(), environ=dict(os.environ), runner=__import__("daprivacyscanner.host").host.SystemRunner())
    etc = S.identity_files(tmp_path / "etc", S.FILTER_RESOLV)
    bwrap = S.program(host, S.BWRAP)
    a = [bwrap, *S.namespaces(True), *S.system(host, etc=False), *S.etc_argv(host, etc, "own"), "--",
         S.PYTHON, "-I", "-c", LOOKUP]
    cmd, filtered = S.pasta_command(host, a, S.program(host, S.PASTA), proxies=False)
    assert filtered
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=S.SPAWN_ENV, cwd="/")
    assert r.returncode == 0, r.stderr
    out = eval(r.stdout.strip().splitlines()[-1])        # noqa: S307 - our own probe's repr
    assert out == {"gateway": D.REFUSED, "direct": "PermissionError", "mark": errno.EPERM}, out


# ------------------------------------------------------------------ the program's own words

def test_text_from_inside_is_shown_only_as_the_program_s_own():
    shown = S.visible("evil\u202egnp.exe\x1b[2J" + "x" * 500, 40)
    assert shown.startswith("evil<U+202E>gnp.exe<U+001B>[2Jxxx") and shown.endswith("x…") and len(shown) == 40
    assert S.visible("one\ntwo\n\n three") == "one / two / three"
    assert S.start_reason("pasta: Failed to open tun\n", 1).startswith("its network of its own (pasta) couldn't be set up")
    assert S.start_reason("Mullvad Browser needs an update: call 0800 123 456\n", 1, own_output=False) == \
        "it stopped at once (exit status 1)"
    said = S.start_reason("Loading failed: \u202efdp.exe\n", 3)
    assert said.startswith("it stopped at once (exit status 3); the last it printed: “") and "<U+202E>" in said


# ------------------------------------------------------------------ chmod never through a link

def test_the_wipe_s_chmod_never_follows_a_link(tmp_path):
    disk, outside = tmp_path / "disk", tmp_path / "outside"
    disk.mkdir()
    outside.write_text("keep")
    outside.chmod(0o400)
    os.symlink(outside, disk / "swapped")
    dfd = os.open(disk, os.O_RDONLY | os.O_DIRECTORY)
    dev = os.fstat(dfd).st_dev
    try:
        with pytest.raises(OSError):
            R._chmod_entry("swapped", dfd, 0o600, False, dev)
        assert outside.stat().st_mode & 0o777 == 0o400
        # a file the user made unreadable, and a folder they closed: changed by their own descriptors
        (disk / "secret").write_text("x")
        (disk / "secret").chmod(0)
        R._chmod_entry("secret", dfd, 0o200, False, dev)
        assert (disk / "secret").stat().st_mode & 0o777 == 0o200
        (disk / "shut").mkdir(mode=0)
        R._chmod_entry("shut", dfd, 0o700, True, dev)
        assert (disk / "shut").stat().st_mode & 0o777 == 0o700
        with pytest.raises(OSError):
            R._chmod_entry("secret", dfd, 0o700, True, dev)                  # not a folder any more: refused
        with pytest.raises(OSError):
            R._chmod_entry("shut", dfd, 0o700, True, dev + 1)                # another filesystem's
    finally:
        os.close(dfd)
        (disk / "shut").chmod(0o700)
    w = R.wipe(disk)
    assert w.files == 1 and not w.failed and outside.read_text() == "keep" and outside.stat().st_mode & 0o777 == 0o400


# ------------------------------------------------------------------ programs that start sandboxes of their own

def test_programs_that_sandbox_themselves_are_recognised(tmp_path):
    tree = tmp_path / "tree"
    (tree / "app/resources").mkdir(parents=True)
    (tree / "app/resources/app.asar").write_text("")
    assert seccomp.nesting_reason(tmp_path / "missing", folder=tree) == "an Electron app"
    (tmp_path / "gtkapp").write_bytes(b"\x7fELF" + b"\0" * 100 + b"libwebkit2gtk-4.1.so.0\0")
    assert seccomp.nesting_reason(tmp_path / "gtkapp") == "built on WebKitGTK"
    (tmp_path / "plain").write_bytes(b"\x7fELF" + b"\0" * 100 + b"libgtk-3.so.0\0")
    assert seccomp.nesting_reason(tmp_path / "plain") is None
    # an AppImage: its folder listing read from the squashfs after the runtime, never run
    names = b"\x01\x00chrome-sandbox\x00resources"
    block = zlib.compress(names)
    runtime = bytearray(b"\x7fELF\x02" + b"\0" * 59)
    struct.pack_into("<Q", runtime, 0x28, 64)
    struct.pack_into("<HH", runtime, 0x3A, 0, 0)
    sb = bytearray(b"hsqs" + b"\0" * 92)
    struct.pack_into("<H", sb, 20, 1)
    struct.pack_into("<QQQ", sb, 72, 96, 96 + 2 + len(block), 0xFFFFFFFFFFFFFFFF)
    image = bytes(runtime) + bytes(sb) + struct.pack("<H", len(block)) + block
    (tmp_path / "Chat.AppImage").write_bytes(image)
    assert seccomp.nesting_reason(tmp_path / "Chat.AppImage") == "an Electron or Chromium app"
    # an installed Electron app: /usr/bin/code a script, its program beside chrome-sandbox
    share = tmp_path / "usr/share/code"
    (share / "resources").mkdir(parents=True)
    (share / "code").write_bytes(b"\x7fELF")
    (share / "resources/app.asar").write_text("")
    assert seccomp.installed_reason(str(share / "code")) == "an Electron app"
    assert seccomp.installed_reason(str(tmp_path / "plain")) is None
