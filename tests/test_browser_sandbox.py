"""The browser in the RAM disk, in its sandbox: bubblewrap's command line built from the session
(Wayland or X11, sound only when asked, nothing of the home folder), and files moved in and out by
the app without following anything the browser could have planted. Nothing here runs bubblewrap."""

from __future__ import annotations

import json
import os
import struct
import time
from pathlib import Path

import pytest

from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import sandbox as S
from daprivacyscanner.tools import transfer as T
from daprivacyscanner.tools.metadata import cleaned_name

from test_browser_tool import open_ramdisk
from test_server_tools import H, app_for

UID = os.getuid()


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    (home / "Downloads").mkdir(parents=True)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", root / "proc/mounts")
    (root / "proc/meminfo").write_text("MemTotal: 8000000 kB\n")
    (root / f"run/user/{UID}").mkdir(parents=True)
    env = {"HOME": str(home), "USER": "alice", "LANG": "en_AU.UTF-8", "SSH_AUTH_SOCK": f"/run/user/{UID}/ssh",
           "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{UID}/bus", "XDG_RUNTIME_DIR": f"/run/user/{UID}"}
    return Host(home=home, environ=env, runner=FakeRunner(), root=root, uid=UID)


def installed(host, which):
    disk = open_ramdisk(host)
    b = B.BROWSERS[which]
    (disk / b.folder / "Browser/TorBrowser/Data/Browser").mkdir(parents=True)
    (disk / b.folder / "Browser/TorBrowser/Data/Tor").mkdir(parents=True)
    (disk / b.folder / b.start).write_text("#!/bin/sh\n")
    B.record_release(host, b, disk / f"{b.folder}-linux-x86_64-15.0.24.tar.xz", "download")   # as set up today
    return disk


def installed_tor(host):
    return installed(host, "tor")


def bwrap_ok(host, calls=None):
    def bwrap(argv):
        if calls is not None:
            calls.append(argv)
        return CommandResult(tuple(argv), 0)
    host.runner.handlers["bwrap"] = bwrap


def ip_ok(host, addresses="[]", routes="[]"):
    """iproute2's ip: rules set, and the computer's own networks listed (none by default) as `ip -j` prints them."""
    def ip(argv):
        if "-j" in argv:
            return CommandResult(tuple(argv), 0, addresses if "address" in argv else routes)
        return CommandResult(tuple(argv), 0)
    host.runner.handlers["ip"] = ip


def pairs(argv, flag):
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == flag]


def env_of(argv):
    return dict(pairs(argv, "--setenv"))


# ------------------------------------------------------------------ can it run here

def test_probe_says_why_bubblewrap_cant_be_used(host):
    assert S.probe(host) == "bubblewrap (bwrap) isn't installed."
    host.runner.handlers["bwrap"] = lambda argv: CommandResult(tuple(argv), 1, "", "bwrap: setting up uid map: Permission denied\n")
    assert "AppArmor" in S.probe(host)
    calls = []
    bwrap_ok(host, calls)
    assert S.probe(host) is None and calls[0][-2:] == ("--", "/usr/bin/true") and "--clearenv" in calls[0]
    assert pairs(calls[0], "--uid")[0][0] == "1000"


def test_pasta_is_tried_around_a_sandbox(host):
    bwrap_ok(host)
    assert "passt" in S.probe_pasta(host)
    calls = []
    host.runner.handlers["pasta"] = lambda argv: calls.append(argv) or CommandResult(
        tuple(argv), 0, "", "No routable interface for IPv6: IPv6 is disabled\n")
    assert S.probe_pasta(host) is None
    assert calls[0][:2] == ("pasta", "--config-net") and "--no-map-gw" in calls[0]
    i = calls[0].index("--")
    assert calls[0][i + 1] == "bwrap" and calls[0][-1] == "/usr/bin/true"
    host.runner.handlers["pasta"] = lambda argv: CommandResult(
        tuple(argv), 1, "", "No routable interface for IPv6: IPv6 is disabled\nCouldn't open tun device\n")
    assert "Couldn't open tun device" in S.probe_pasta(host)


def test_pasta_s_namespace_is_fenced_off_from_the_local_network(host, monkeypatch):
    """pasta connects anywhere the computer can: the router, printers, Docker's bridge. Rules set as root
    of pasta's namespace, before bubblewrap, refuse the local and private ranges."""
    monkeypatch.setattr(S, "_DNS_TCP", {})                  # not yet asked whether pasta forwards DNS over TCP
    bwrap_ok(host)
    calls = []
    host.runner.handlers["pasta"] = lambda argv: calls.append(argv) or CommandResult(tuple(argv), 0)
    assert S.probe_fence(host) == "iproute2's ip isn't installed."
    ip_ok(host)
    assert S.probe_fence(host) is None
    a = list(calls[-1])
    i = a.index("--")
    assert a[i + 1:i + 3] == ["/bin/sh", "-c"] and a[i + 4] == "bwrap"
    script = a[i + 3]
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"):
        assert f"ip rule add prohibit to {net} pref 100" in script
    # the DNS forwarder's address for DNS alone (not every port there), first
    for proto in ("udp", "tcp"):
        assert script.index(f"lookup main to {S.DNS_FORWARD} ipproto {proto} dport 53 pref 50") < script.index("prohibit")
    assert f"lookup main to {S.DNS_FORWARD} pref" not in script
    # Mullvad VPN's proxies in its tunnel (the extension's location switch): TCP to 1080 only, ahead of the fence
    assert "ip rule add lookup main to 10.64.0.1 ipproto tcp dport 1080 pref 40" in script
    assert "ip rule add lookup main to 10.124.0.0/22 ipproto tcp dport 1080 pref 40" in script
    assert script.endswith('exec "$0" "$@"') and "exit 1" in script                             # no fence, no start
    # the IPv6 rules must be set wherever the kernel has IPv6 (never tolerated for another reason), not without it
    assert "if [ -e /proc/net/if_inet6 ]; then ip -6 rule add prohibit to fc00::/7 pref 100 && " in script
    assert "2>/dev/null" not in script.split("fc00::/7")[1].split("own 6")[0]
    # then the network's own prefixes (public ones on IPv6 and some IPv4 networks): every route pasta copied but the
    # default; a listing that fails is a failure (not hidden by the pipe)
    assert 'routes=$(ip -"$1" -o route show table main type unicast) || return 1' in script
    assert 'ip -"$1" rule add prohibit to "$net" pref 100' in script and "own 4 ||" in script and "own 6 ||" in script
    assert '[ "$net" = default ] && continue' in script and '*"File exists"*) ;;' in script
    # and, from inside, that the fence refuses what it should: a route lookup, no packet
    check = a[-1]
    assert a[-3:-1] == ["/bin/sh", "-c"] and "ip route get" in check and "exit 1" in check and check.endswith("exit 0")
    for addr in ("192.0.0.8", S.DNS_FORWARD, "10.64.0.1"):
        assert addr in check
    host.runner.handlers["pasta"] = lambda argv: CommandResult(tuple(argv), 1, "", "The local network could not be fenced off\n")
    assert "fenced off" in S.probe_fence(host)


# ------------------------------------------------------------------ the command line

def wayland(host):
    (host.root / f"run/user/{UID}/wayland-0").write_text("")
    host.environ["WAYLAND_DISPLAY"] = "wayland-0"
    host.environ["DISPLAY"] = ":0"                     # XWayland is there too: not given to the browser


def layout(host, b):
    folder, session, private = B.prepare(host, b)
    return S.Layout(b.folder, folder, session, private, b.start, b.writable, b.hidden), private


def identity_etc(host):
    etc = host.root / "etc"
    etc.mkdir(exist_ok=True)
    for name in ("passwd", "group", "hostname", "hosts", "machine-id", "fstab", "ld.so.cache", "default/grub",
                 "mdadm/mdadm.conf", "apt/sources.list", "environment"):
        (etc / name).parent.mkdir(parents=True, exist_ok=True)
        (etc / name).write_text(f"real {name} of alice-laptop\n")
    (etc / "ssh").mkdir(exist_ok=True)
    (etc / "ssh/ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAA root@alice-laptop\n")
    (etc / "fonts").mkdir(exist_ok=True)
    (host.root / "usr/lib").mkdir(parents=True, exist_ok=True)
    (host.root / "usr/lib/os-release").write_text("NAME=Linux Mint\n")
    os.symlink("../usr/lib/os-release", etc / "os-release")
    os.symlink("/usr/share/zoneinfo/Australia/Sydney", etc / "localtime")
    (host.root / "usr/share/zoneinfo/Etc").mkdir(parents=True, exist_ok=True)
    (host.root / "usr/share/zoneinfo/Etc/UTC").write_text("TZif")
    (host.root / "run/systemd/resolve").mkdir(parents=True, exist_ok=True)
    (host.root / "run/systemd/resolve/stub-resolv.conf").write_text("nameserver 127.0.0.53\n")
    os.symlink("../run/systemd/resolve/stub-resolv.conf", etc / "resolv.conf")


def test_a_copy_set_up_for_mullvad_vpn_starts_on_the_app_s_profile(host):
    """MOZ_LEGACY_PROFILES in the sandbox's environment, from the layout; nothing for a copy that wasn't."""
    installed(host, "mullvad")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    b = B.BROWSERS["mullvad"]
    folder, session, private = B.prepare(host, b)
    disp = S.display(host, private, landlock=True)
    etc = S.identity_files(private / "etc", "nameserver 9.9.9.9\n")
    lay = S.Layout(b.folder, folder, session, private, b.start, b.writable, b.hidden, (("MOZ_LEGACY_PROFILES", "1"),))
    assert env_of(S.browser_argv(host, lay, disp, False, True, etc, None))["MOZ_LEGACY_PROFILES"] == "1"
    lay = S.Layout(b.folder, folder, session, private, b.start, b.writable, b.hidden)
    assert "MOZ_LEGACY_PROFILES" not in env_of(S.browser_argv(host, lay, disp, False, True, etc, None))


def test_mullvad_in_its_own_network_sees_nothing_of_home_or_the_computer(host):
    disk = installed(host, "mullvad")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    b = B.BROWSERS["mullvad"]
    lay, private = layout(host, b)
    disp = S.display(host, private, landlock=True)
    assert disp.kind == "wayland"
    etc = S.identity_files(private / "etc", f"nameserver {S.DNS_FORWARD}\n")
    with pytest.raises(S.SandboxError, match="can't be fenced off.*wasn't started"):     # fenced, but no ip: no start
        S.browser_argv(host, lay, disp, False, True, etc, "pasta")
    argv = S.browser_argv(host, lay, disp, False, True, etc, "pasta", fenced=False)    # as the panel said: unfenced
    assert argv[:2] == ["pasta", "--config-net"] and "--no-map-gw" in argv
    i = argv.index("--")
    assert argv[i + 1] == "bwrap"
    ip_ok(host)
    fenced = S.browser_argv(host, lay, disp, False, True, etc, "pasta")
    j = fenced.index("--")
    assert fenced[j + 1:j + 3] == ["/bin/sh", "-c"] and "192.168.0.0/16" in fenced[j + 3] and fenced[j + 4] == "bwrap"
    assert S.browser_argv(host, lay, disp, False, True, etc, "pasta", fenced=False)[i + 1] == "bwrap"
    del host.runner.handlers["ip"]
    a = argv[i + 1:]
    for flag in ("--unshare-all", "--share-net", "--new-session", "--clearenv"):
        assert flag in a                                             # --share-net: pasta's network, not the computer's
    assert a[a.index("--cap-drop") + 1] == "ALL"
    binds, ro = pairs(a, "--bind"), pairs(a, "--ro-bind")
    real = str(disk / "mullvad-browser")
    assert (real, "/home/user/mullvad-browser") in ro                 # the program files: read-only
    assert binds == [(f"{real}/Data", "/home/user/mullvad-browser/Data"),
                     (f"{real}/Browser/Downloads", "/home/user/mullvad-browser/Browser/Downloads"),
                     (str(lay.session), "/home/user/.session")]       # nothing else writable
    assert (f"/run/user/{UID}/wayland-0", "/run/user/1000/wayland-0") in ro
    assert not any(str(host.home) in dst for _, dst in binds + ro)    # the real path, naming the user, isn't used inside
    # an /etc of its own: only what the browser needs, the sandbox's own identity, the clock on UTC
    assert ("/etc", "/etc") not in ro and "/etc" in [a[i + 1] for i, x in enumerate(a) if x == "--tmpfs"]
    assert a[a.index("--remount-ro") + 1] == "/etc"
    assert (str(etc["passwd"]), "/etc/passwd") in ro and (str(etc["machine-id"]), "/etc/machine-id") in ro
    assert ("/etc/ld.so.cache", "/etc/ld.so.cache") in ro and ("/etc/fonts", "/etc/fonts") in ro
    links = pairs(a, "--symlink")
    assert ("../usr/lib/os-release", "/etc/os-release") in links and ("/usr/share/zoneinfo/Etc/UTC", "/etc/localtime") in links
    for gone in ("fstab", "ssh", "default", "mdadm", "apt", "environment"):
        assert not any(x == f"/etc/{gone}" or x.startswith(f"/etc/{gone}/") for x in a), gone
    assert (str(etc["resolv.conf"]), "/etc/resolv.conf") in ro
    # /proc's kernel command line (the disks' UUIDs) and boot id: the sandbox's own, after /proc is mounted
    assert (str(etc["cmdline"]), "/proc/cmdline") in ro and (str(etc["boot_id"]), "/proc/sys/kernel/random/boot_id") in ro
    assert a.index("/proc/cmdline") > a.index("--proc") and "alice" not in etc["cmdline"].read_text()
    assert "nameserver 169.254.0.1" in etc["resolv.conf"].read_text() and "alice" not in etc["passwd"].read_text()
    assert (host.root / "etc/passwd").read_text() == "real passwd of alice-laptop\n"     # the computer's untouched
    e = env_of(a)
    assert e["HOME"] == "/home/user" and e["USER"] == "user" and e["XDG_CONFIG_HOME"] == "/home/user/.session/config"
    assert e["WAYLAND_DISPLAY"] == "wayland-0" and e["MOZ_ENABLE_WAYLAND"] == "1" and "DISPLAY" not in e
    assert "SSH_AUTH_SOCK" not in e and "DBUS_SESSION_BUS_ADDRESS" not in e and e["LANG"] == "en_AU.UTF-8"
    assert e["TZ"] == "UTC"
    assert not any("pulse" in x for x in a)                           # no sound unless asked
    j = a.index("--")
    assert a[-1] == "/home/user/mullvad-browser/Browser/start-mullvad-browser" and a[-4:-1] == S.QUIET and "--detach" not in a
    # the command stays for as long as the browser, then Landlock's scopes around the start script alone
    assert a[j + 1:j + 6] == [S.PYTHON, "-I", "-c", S.STAY, "/home/user/mullvad-browser"]
    assert a[j + 6:j + 10] == [S.PYTHON, "-I", "-c", S.LANDLOCK] and "--die-with-parent" not in a    # it outlives the app
    # without pasta: the computer's network, and its resolver
    shared = S.browser_argv(host, lay, disp, False, False, S.identity_files(private / "etc", None), None)
    assert shared[0] == "bwrap" and S.LANDLOCK not in shared and "--share-net" in shared
    k = shared.index("--")
    assert shared[k + 1:k + 6] == [S.PYTHON, "-I", "-c", S.STAY, "/home/user/mullvad-browser"] and shared[k + 6:k + 9] == S.QUIET
    bare = S.browser_argv(host, lay, disp, False, False, S.identity_files(private / "etc", None), None, stay=False)
    assert S.PYTHON not in bare and bare[bare.index("--") + 1:][:3] == S.QUIET       # no python3 on the computer
    assert ("/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf") in pairs(shared, "--ro-bind")
    (host.root / f"run/user/{UID}/pulse").mkdir()
    (host.root / f"run/user/{UID}/pulse/native").write_text("")
    with_sound = S.browser_argv(host, lay, disp, True, False, etc, None)
    assert env_of(with_sound)["PULSE_SERVER"] == "unix:/run/user/1000/pulse/native"
    assert (f"/run/user/{UID}/pulse/native", "/run/user/1000/pulse/native") in pairs(with_sound, "--ro-bind")


def test_opengl_draws_with_mesa_s_software_renderer(host):
    """No GPU in the sandbox: GLVND would pick NVIDIA's libraries, which fail there (no WebGL, Xephyr crashed), so
    GLX and EGL are pointed at Mesa's, drawing in software."""
    assert S.software_gl(host) == {"__GLX_VENDOR_LIBRARY_NAME": "mesa", "LIBGL_ALWAYS_SOFTWARE": "1"}   # no EGL vendors
    vendors = host.root / "usr/share/glvnd/egl_vendor.d"
    vendors.mkdir(parents=True)
    for name in ("10_nvidia.json", "50_mesa.json", "README"):
        (vendors / name).write_text("{}")
    assert S.software_gl(host)["__EGL_VENDOR_LIBRARY_FILENAMES"] == "/usr/share/glvnd/egl_vendor.d/50_mesa.json"
    e = env_of(S._env(host, S.Display("x11", [], {"DISPLAY": ":99"}), False))
    assert e["__GLX_VENDOR_LIBRARY_NAME"] == "mesa" and e["__EGL_VENDOR_LIBRARY_FILENAMES"].endswith("/50_mesa.json")


def gpu_devices(host):
    for d in ("dev/dri/by-path", "dev"):
        (host.root / d).mkdir(parents=True, exist_ok=True)
    for name in ("dri/card1", "dri/renderD128", "nvidiactl", "nvidia0", "nvidia-modeset", "nvidia-uvm", "nvidia-uvm-tools", "null"):
        (host.root / "dev" / name).write_text("")


def test_the_graphics_card_only_when_the_user_allows_it(host, monkeypatch):
    """Ticked, the sandbox gets the render nodes and NVIDIA's control and card files (all its driver needed, tested),
    never the primary node, nvidia-modeset or CUDA's, and OpenGL is left to pick the card's own driver."""
    assert S.gpu(host) == []
    gpu_devices(host)
    assert S.gpu(host) == ["/dev/dri/renderD128", "/dev/nvidia0", "/dev/nvidiactl"]
    installed(host, "mullvad")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    lay, private = layout(host, B.BROWSERS["mullvad"])
    disp = S.display(host, private, landlock=False)
    etc = S.identity_files(private / "etc", None)
    plain = S.browser_argv(host, lay, disp, False, False, etc, None)
    assert "--dev-bind" not in plain and env_of(plain)["LIBGL_ALWAYS_SOFTWARE"] == "1"
    allowed = S.browser_argv(host, lay, disp, False, False, etc, None, gpu=tuple(S.gpu(host)))
    assert pairs(allowed, "--dev-bind") == [(d, d) for d in S.gpu(host)]
    assert allowed.index("--dev-bind") > allowed.index("--dev")                       # after the sandbox's own /dev
    assert not any(k in env_of(allowed) for k in S.software_gl(host))
    # Tor Browser: in both sandboxes, the inner one binding them from the outer one's /dev
    tor = B.BROWSERS["tor"]
    installed(host, "tor")
    lay, private = layout(host, tor)
    (private / "tor").mkdir(exist_ok=True)
    argv = S.tor_argv(host, lay, private / "tor", disp, False, False, etc, "GATE", gpu=("/dev/nvidia0",))
    inner = json.loads(argv[-1])["inner"]
    assert ("/dev/nvidia0", "/dev/nvidia0") in pairs(argv, "--dev-bind") and pairs(inner, "--dev-bind") == [("/dev/nvidia0",) * 2]
    assert "__GLX_VENDOR_LIBRARY_NAME" not in env_of(inner)
    # the start: only when asked
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    calls = []
    assert B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))["gpu"] is False and "--dev-bind" not in calls[-1][0]
    monkeypatch.setattr(B, "running", lambda h, b: False)                          # the first is still "running"
    assert B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls), gpu=True)["gpu"] is True
    assert pairs(calls[-1][0], "--dev-bind") == [(d, d) for d in S.gpu(host)]


def test_tor_browser_has_no_network_but_tors(host):
    disk = installed(host, "tor")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    b = B.BROWSERS["tor"]
    lay, private = layout(host, b)
    disp = S.display(host, private, landlock=False)
    tor_dir = private / "tor"
    tor_dir.mkdir()
    etc = S.identity_files(private / "etc", None)
    argv = S.tor_argv(host, lay, tor_dir, disp, False, False, etc, "GATE")
    real = str(disk / "tor-browser")
    # the outer sandbox: the computer's network, tor's data writable, the gate in the host's python3
    assert argv[0] == "bwrap" and "--share-net" in argv
    assert (f"{real}/Browser/TorBrowser/Data/Tor", "/home/user/tor-browser/Browser/TorBrowser/Data/Tor") in pairs(argv, "--bind")
    assert (str(tor_dir), "/run/user/1000/tor") in pairs(argv, "--bind")
    # its /etc: the computer's resolver (tor's pluggable transports look names up), the sandbox's identity
    outer_ro = pairs(argv, "--ro-bind")
    assert ("/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf") in outer_ro and ("/etc", "/etc") not in outer_ro
    assert (str(etc["passwd"]), "/etc/passwd") in outer_ro and (str(private / "etc"), "/run/identity") in outer_ro
    assert "/proc/cmdline" not in argv[:argv.index("--")]      # the inner one masks it: masking here would stop its /proc
    i = argv.index("--")
    assert argv[i + 1:i + 5] == [S.PYTHON, "-I", "-c", "GATE"]
    cfg = json.loads(argv[-1])
    tor = cfg["tor"]
    assert tor[0] == "bwrap" and tor[tor.index("--") + 1] == "/home/user/tor-browser/Browser/TorBrowser/Tor/tor"
    assert "@PID@" not in tor and "__OwningControllerProcess" not in tor       # its own PID namespace: it dies with the gate
    assert tor[tor.index("+__SocksPort") + 1].startswith("unix:/run/user/1000/tor/socks ")
    assert tor[tor.index("+__ControlPort") + 1] == "unix:/run/user/1000/tor/tor-control"     # the filter's is "control"
    assert cfg["control"] == "/run/user/1000/tor/control" and cfg["upstream"] == "/run/user/1000/tor/tor-control"
    # the inner sandbox: no network at all, tor's data hidden, the two sockets only
    inner = cfg["inner"]
    assert inner[0] == "bwrap" and "--unshare-all" in inner and "--share-net" not in inner
    assert ("/run/user/1000/tor/socks", "/run/user/1000/tor/socks") in pairs(inner, "--ro-bind")
    assert ("/run/user/1000/tor/control", "/run/user/1000/tor/control") in pairs(inner, "--ro-bind")
    assert not any("tor-control" in x or "cookie" in x for x in inner)
    assert inner[inner.index("--tmpfs", inner.index("/home/user/.session") - 3) + 1:].count(
        "/home/user/tor-browser/Browser/TorBrowser/Data/Tor") == 1
    assert ("/home/user/tor-browser", "/home/user/tor-browser") in pairs(inner, "--ro-bind")
    assert [d for _, d in pairs(inner, "--bind")] == ["/home/user/tor-browser/Browser/TorBrowser/Data/Browser",
                                                      "/home/user/tor-browser/Browser/Downloads", "/home/user/.session"]
    assert ("/run/user/1000/wayland-0", "/run/user/1000/wayland-0") in pairs(inner, "--ro-bind")
    # its /etc from the outer one's, with no resolver at all (it has no network); /proc's own files
    inner_ro = pairs(inner, "--ro-bind")
    assert ("/etc/passwd", "/etc/passwd") in inner_ro and ("/etc/ld.so.cache", "/etc/ld.so.cache") in inner_ro
    assert not any("resolv" in x for x in inner) and ("/etc", "/etc") not in inner_ro
    assert ("/run/identity/cmdline", "/proc/cmdline") in inner_ro and ("/run/identity/boot_id", "/proc/sys/kernel/random/boot_id") in inner_ro
    # its command lasts as long as the browser (the gate stops tor when it ends), and it dies with the gate
    n = inner.index("--")
    assert inner[n + 1:n + 6] == [S.PYTHON, "-I", "-c", S.STAY, "/home/user/tor-browser"] and inner[n + 6:n + 9] == S.QUIET
    assert inner[1] == "--die-with-parent" and "--die-with-parent" not in argv[:argv.index("--")]
    e = env_of(inner)
    assert e["TOR_SKIP_LAUNCH"] == "1" and e["TOR_SOCKS_IPC_PATH"] == "/run/user/1000/tor/socks"
    assert e["TOR_CONTROL_IPC_PATH"] == "/run/user/1000/tor/control" and "TOR_CONTROL_PASSWD" not in e


def xauth(*entries):
    out = b""
    for family, addr, num, cookie in entries:
        out += struct.pack(">H", family)
        for f in (addr, num, b"MIT-MAGIC-COOKIE-1", cookie):
            out += struct.pack(">H", len(f)) + f
    return out


def test_x11_under_a_free_display_number_with_its_own_cookie(host):
    installed(host, "tor")
    (host.root / "tmp/.X11-unix").mkdir(parents=True)
    for n in ("0", "99"):
        (host.root / f"tmp/.X11-unix/X{n}").write_text("")
    (host.root / "proc/net").mkdir()
    (host.root / "proc/net/unix").write_text("0: 00000002 0 10000 0001 01 1 @/tmp/.X11-unix/X100\n")
    (host.home / ".Xauthority").write_bytes(xauth((256, b"box", b"0", b"A" * 16), (256, b"box", b"1", b"B" * 16)))
    host.environ["DISPLAY"] = ":0.0"
    _, private = layout(host, B.BROWSERS["tor"])
    disp = S.display(host, private, landlock=True)
    assert disp.kind == "x11" and disp.env["DISPLAY"] == ":101"         # 99 has a socket, 100 an abstract one
    assert ("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X101") in disp.binds
    assert (str(private / "Xauthority"), "/tmp/.Xauthority") in disp.binds    # kept where the browser can't see it
    written = (private / "Xauthority").read_bytes()
    assert written == struct.pack(">HH", 0xFFFF, 0) + struct.pack(">H", 3) + b"101" + \
        struct.pack(">H", 18) + b"MIT-MAGIC-COOKIE-1" + struct.pack(">H", 16) + b"A" * 16
    assert oct(os.stat(private / "Xauthority").st_mode & 0o777) == "0o600"
    plain = S.display(host, private, landlock=False)                    # without Landlock, its own number
    assert plain.env["DISPLAY"] == ":0"
    host.environ["DISPLAY"] = "localhost:10.0"                          # over SSH: it needs the network
    assert S.display(host, private, landlock=False).network
    del host.environ["DISPLAY"]
    assert S.display(host, private, landlock=True).kind == "none"


# ------------------------------------------------------------------ starting it

class Proc:
    """A stand-in for the started process: running, or ended with `rc` (and `log` in the start log)."""

    def __init__(self, rc=None, log=b"", kw=None):
        self.rc, self.log, self.kw = rc, log, kw

    def poll(self):
        return self.rc


def spawner(calls, rc=None, log=b""):
    def spawn(argv, **kw):
        calls.append((argv, kw))
        if log:
            os.write(kw["stderr"], log)
        return Proc(rc, log)
    return spawn


def test_start_in_the_sandbox(host, monkeypatch):
    disk = installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    calls = []
    how = B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))
    [(argv, kw)] = calls
    assert how == {"sandboxed": True, "display": "wayland", "landlock": how["landlock"], "network": "shared",
                   "lan_blocked": False, "wayland_context": None, "nested": False,
                   "gpu": False}                                   # the fixture's socket is a file: not tried
    assert argv[0] == "bwrap" and kw["cwd"] == "/" and kw["start_new_session"]       # no python3 here: no wrapper
    for rel in ("Browser/To upload", "Browser/Downloads", "Data", "Browser/.config/ibus"):
        assert (disk / "mullvad-browser" / rel).is_dir()
    assert os.readlink(disk / "mullvad-browser/Browser/.local/share") == "/dev/null"
    assert (disk / ".mullvad-browser-app/sandboxed").exists() and B.sandboxed_before(host, B.BROWSERS["mullvad"])
    assert B.launch_problem(B.BROWSERS["mullvad"]) is None                   # still running


def test_a_start_that_couldn_t_be_launched_leaves_no_mark(host, monkeypatch):
    """The mark that it ran sandboxed is set before the launch: one that fails outright removes it, so a later
    start without the sandbox isn't refused for a session that never happened."""
    disk = installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)

    def spawn(argv, **kw):
        raise FileNotFoundError(2, "No such file or directory", "bwrap")
    with pytest.raises(OSError):
        B.start(host, B.BROWSERS["mullvad"], spawn=spawn)
    assert not (disk / ".mullvad-browser-app/sandboxed").exists()


def test_without_pasta_the_sandbox_gets_the_computer_s_resolver_without_its_search_domains(host, monkeypatch):
    """The computer's resolv.conf names the network (a company's or university's domain, from DHCP): only its
    servers and options go into the sandbox."""
    disk = installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)
    (host.root / "etc").mkdir(exist_ok=True)
    (host.root / "etc/resolv.conf").write_text("# Generated by NetworkManager\nsearch corp.example.com lan\n"
                                               "nameserver 127.0.0.53\noptions edns0 trust-ad\n")
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    calls = []
    B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))
    [(argv, kw)] = calls
    own = disk / ".mullvad-browser-app/etc/resolv.conf"
    assert own.read_text() == "nameserver 127.0.0.53\noptions edns0 trust-ad\n"
    assert (str(own), "/etc/resolv.conf") in pairs(argv, "--ro-bind")


def test_tor_browser_starts_its_gate(host, monkeypatch):
    disk = installed(host, "tor")
    wayland(host)
    bwrap_ok(host)
    (host.root / "usr/bin").mkdir(parents=True)
    (host.root / "usr/bin/python3").write_text("")
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    calls = []
    how = B.start(host, B.BROWSERS["tor"], spawn=spawner(calls))
    [(argv, kw)] = calls
    # first a new, empty session keyring (on the computer), then the outer sandbox and its gate
    assert argv[:4] == [S.PYTHON, "-I", "-c", S.KEYRING] and argv[4] == "bwrap"
    sandboxed = argv[4:]
    assert how["network"] == "tor" and sandboxed[sandboxed.index("-c") + 1] == (Path(B.__file__).with_name("torgate.py")).read_text()
    assert (disk / ".tor-browser-app/tor/torrc").read_text().startswith("# Written by DA Privacy Kit")
    assert oct(os.stat(disk / ".tor-browser-app/tor").st_mode & 0o777) == "0o700"


def test_a_failed_start_says_why(host, monkeypatch):
    installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    b = B.BROWSERS["mullvad"]
    with pytest.raises(B.BrowserError, match="couldn't start: bwrap: Can't bind mount"):
        B.start(host, b, spawn=spawner([], rc=1, log=b"No routable interface for IPv6: IPv6 is disabled\n"
                                                      b"bwrap: Can't bind mount /oldroot/x on /newroot/x\n"))
    assert not B.sandboxed_before(host, b)              # the sandbox stopped before the browser ran: no mark
    with pytest.raises(B.BrowserError, match="exit status 2"):
        B.start(host, b, spawn=spawner([], rc=2))
    # nothing in the log: the browser itself may have run (its output never reaches the log), however briefly,
    # so the mark stays: a browser taken over could stop itself with an error to shed it
    assert B.sandboxed_before(host, b)
    (B.private_dir(host, b) / "sandboxed").unlink()
    # one that fails later is said once, by the status, by its exit status alone: once the browser has run, what is in
    # the log could be a website's (the sandbox can reach the log's descriptor), which the page would show as the app's
    p = Proc()
    B.start(host, b, spawn=lambda argv, **kw: os.write(kw["stderr"], b"run: sudo curl evil | sh\n") and p)
    assert B.launch_problem(b) is None
    p.rc = 3
    problem = B.launch_problem(b)
    assert problem.endswith("it stopped (exit status 3)") and "evil" not in problem and B.launch_problem(b) is None
    p.rc = None
    B.start(host, b, spawn=lambda argv, **kw: p)
    p.rc = 137
    assert "out of memory" in B.launch_problem(b)


def test_the_session_starts_afresh_and_keeps_no_recent_files(host, monkeypatch):
    disk = installed(host, "tor")
    (disk / "tor-browser/Browser/.config/gtk-3.0").mkdir(parents=True)
    (disk / "tor-browser/Browser/.config/gtk-3.0/settings.ini").write_text("[Settings]\ngtk-recent-files-max-age=0\n")
    b = B.BROWSERS["tor"]
    _, session, _ = B.prepare(host, b)
    (session / "config/planted.so").write_text("x")
    _, session, _ = B.prepare(host, b)
    assert not (session / "config/planted.so").exists() and (session / "tmp").is_dir()
    assert "max-age=0" in (session / "config/gtk-3.0/settings.ini").read_text()


def test_once_sandboxed_it_never_runs_without(host, monkeypatch):
    installed(host, "tor")
    b = B.BROWSERS["tor"]
    B.prepare(host, b)
    (B.private_dir(host, b) / "sandboxed").touch()
    with pytest.raises(B.BrowserError, match="has run in the sandbox"):
        B.start(host, b, spawn=lambda *a, **k: pytest.fail("started"), sandboxed=False)


def test_a_planted_link_stops_the_start(host):
    disk = installed(host, "tor")
    bwrap_ok(host)
    wayland(host)
    os.symlink(host.home, disk / "tor-browser/Browser/To upload")
    with pytest.raises(B.BrowserError, match="isn't a folder of yours"):
        B.start(host, B.BROWSERS["tor"], spawn=lambda *a, **k: pytest.fail("started"))
    os.unlink(disk / "tor-browser/Browser/To upload")
    (disk / "tor-browser/Browser/TorBrowser/Data/Browser").rmdir()
    os.symlink(host.home, disk / "tor-browser/Browser/TorBrowser/Data/Browser")   # a profile that leads home
    with pytest.raises(B.BrowserError, match="isn't a folder of yours"):
        B.start(host, B.BROWSERS["tor"], spawn=lambda *a, **k: pytest.fail("started"))


def test_running_is_found_at_the_path_inside_the_sandbox(host, monkeypatch):
    disk = installed(host, "tor")
    proc = host.root / "proc"
    for pid, exe in (("41", "/home/user/tor-browser/Browser/firefox.real"), ("42", "/home/user/mullvad-browser/x"),
                     ("43", str(disk / "tor-browser/Browser/firefox.real")), ("44", "/usr/bin/bash"),
                     ("45", "/home/user/tor-browser/Browser/firefox.real")):
        (proc / pid).mkdir()
        target = disk / "tor-browser/Browser/firefox.real" if pid in ("41", "43") else host.root / "proc/meminfo"
        target.touch()
        os.symlink(exe, proc / pid / "exe")
    real_stat = os.stat

    def stat(p, *a, **k):          # /proc's exe link leads to the file wherever its path says it is
        if str(p).endswith("/exe"):
            pid = Path(p).parent.name
            if pid == "45":
                return real_stat("/proc")              # the same path inside another sandbox, not on this RAM disk
            return real_stat(disk / "tor-browser/Browser/firefox.real" if pid in ("41", "43") else host.root / "proc/meminfo")
        return real_stat(p, *a, **k)
    monkeypatch.setattr(B.os, "stat", stat)
    assert B.running(host, B.BROWSERS["tor"]) == [41, 43] and B.running(host, B.BROWSERS["mullvad"]) == [42]


def test_bridges(host):
    import zipfile
    disk = installed(host, "tor")
    b = B.BROWSERS["tor"]
    snowflake = ("snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B28 "
                 "url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302")
    with zipfile.ZipFile(disk / "tor-browser/Browser/omni.ja", "w") as z:
        z.writestr(B.PT_CONFIG, json.dumps({"bridges": {"snowflake": [snowflake], "obfs4": ["obfs4 bad line; rm -rf"]}}))
    assert B.builtin_bridges(host, b) == {"snowflake": [snowflake], "obfs4": []}
    assert B.torrc(host, b).count("\n") == 1                               # directly: no bridges
    B.set_bridges(host, b, "snowflake")
    assert B.torrc(host, b).endswith(f"UseBridges 1\nBridge {snowflake}\n")
    with pytest.raises(B.BrowserError, match="no built-in obfs4"):
        B.set_bridges(host, b, "obfs4")
    mine = "Bridge obfs4 203.0.113.7:9001 0123456789ABCDEF0123456789ABCDEF01234567 cert=AbC+/x iat-mode=0\n\n" \
           "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/a ver=0.0.1"
    B.set_bridges(host, b, "custom", mine)
    assert B.bridges_view(host, b) == {"mode": "custom", "count": 2, "builtin": ["obfs4", "snowflake"]}
    assert "Bridge obfs4 203.0.113.7:9001" in B.torrc(host, b) and "Bridge Bridge" not in B.torrc(host, b)
    for bad in ("obfs4 203.0.113.7:9001 x\nControlPort 9051", "Socks5Proxy 203.0.113.9:1080", "UseBridges 0"):
        with pytest.raises(B.BrowserError, match="isn't a bridge line"):
            B.set_bridges(host, b, "custom", bad)
    with pytest.raises(B.BrowserError):
        B.set_bridges(host, B.BROWSERS["mullvad"], "snowflake")


def test_tor_status_is_checked(host):
    installed(host, "tor")
    b = B.BROWSERS["tor"]
    d = B.private_dir(host, b) / "tor"
    d.mkdir(parents=True)
    (d / "status.json").write_text(json.dumps({"state": "connecting", "progress": 999, "summary": "x" * 900}))
    assert B.tor_status(host, b) == {"state": "connecting", "progress": 100, "summary": "x" * 200, "problem": ""}
    (d / "status.json").write_text(json.dumps({"state": "<script>"}))
    assert B.tor_status(host, b) is None


# ------------------------------------------------------------------ uploads

def test_a_file_to_upload_is_copied_in(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    src = host.home / "Downloads/photo.jpg"
    src.write_bytes(b"jpeg")
    r = T.add(host, "tor-browser", src, clean=False)
    copy = T.uploads_dir(host, "tor-browser") / "photo.jpg"
    assert r["name"] == "photo.jpg" and copy.read_bytes() == b"jpeg" and src.read_bytes() == b"jpeg"
    assert oct(copy.stat().st_mode & 0o777) == "0o600"
    assert T.add(host, "tor-browser", src, clean=False)["name"] == "photo (2).jpg"
    assert [u["name"] for u in T.uploads(host, "tor-browser")] == ["photo (2).jpg", "photo.jpg"]
    T.remove_upload(host, "tor-browser", "photo.jpg")
    assert not copy.exists() and src.exists()
    with pytest.raises(T.TransferError):
        T.remove_upload(host, "tor-browser", "../../Downloads/photo.jpg")


def test_metadata_is_removed_on_the_way_in(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    src = host.home / "Downloads/photo.jpg"
    src.write_bytes(b"jpeg+gps")

    seen = []

    def mat2(argv):
        p = Path(argv[-1])
        seen.append(p)
        cleaned_name(p).write_bytes(p.read_bytes().replace(b"+gps", b""))
        return CommandResult(tuple(argv), 0)
    with pytest.raises(T.TransferError, match="mat2"):
        T.add(host, "tor-browser", src, clean=True)
    host.runner.handlers["mat2"] = mat2
    r = T.add(host, "tor-browser", src, clean=True)
    up = T.uploads_dir(host, "tor-browser")
    assert r["cleaned"] and (up / "photo.jpg").read_bytes() == b"jpeg" and src.read_bytes() == b"jpeg+gps"
    assert sorted(p.name for p in up.iterdir()) == ["photo.jpg"]      # the staging folder is gone
    # the original, metadata and all, was never where the browser can see it
    assert seen and seen[0].parent.parent == host.home / "TempBrowser" and seen[0].parent.name.startswith(".adding-")
    assert not seen[0].parent.exists()


# ------------------------------------------------------------------ the TempOutbox

def outbox_mat2(host, seen=None):
    """mat2 that drops "+gps" from what it cleans, and doesn't know .xyz files."""
    def mat2(argv):
        p = Path(argv[-1])
        if seen is not None:
            seen.append(p)
        if p.suffix == ".xyz":
            return CommandResult(tuple(argv), 0, f"[-] {p}'s format (chemical/x-xyz) is not supported\n")
        cleaned_name(p).write_bytes(p.read_bytes().replace(b"+gps", b""))
        return CommandResult(tuple(argv), 0)
    host.runner.handlers["mat2"] = mat2


def test_the_tempoutbox_cleans_into_to_upload_and_keeps_the_originals(host, request):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    b = B.BROWSERS["tor"]
    assert not B.default_outbox(host, b)                      # without mat2: it couldn't clean anything
    seen = []
    outbox_mat2(host, seen)
    assert B.default_outbox(host, b)
    box = host.home / "TempBrowser/Outbox for Tor Browser"
    assert sorted(x.name for x in box.iterdir()) == ["Not cleaned", "Originals"]
    for name, data in (("photo.jpg", b"jpeg+gps"), ("notes.xyz", b"x"), ("fresh.jpg", b"new+gps"), (".hidden", b"h"),
                       ("film.mp4.part", b"p")):
        (box / name).write_bytes(data)
    for name in ("photo.jpg", "notes.xyz", ".hidden", "film.mp4.part"):
        old(box / name)
    (box / "Album").mkdir()
    os.symlink(host.home / ".ssh/id_ed25519", box / "key.jpg")
    old(box / "key.jpg")
    T.forget_recent()
    from daprivacyscanner.tools import owner
    assert owner.claim(host, "TempBrowser", host.home / "TempBrowser")      # this copy's (only the owner empties it)
    request.addfinalizer(lambda: owner.release(host, "TempBrowser"))
    B.run_outboxes(host)
    up = T.uploads_dir(host, "tor-browser")
    assert sorted(x.name for x in up.iterdir()) == ["photo.jpg"] and (up / "photo.jpg").read_bytes() == b"jpeg"
    assert (box / "Originals/photo.jpg").read_bytes() == b"jpeg+gps" and (box / "Not cleaned/notes.xyz").exists()
    assert sorted(x.name for x in box.iterdir()) == [".hidden", "Album", "Not cleaned", "Originals", "film.mp4.part",
                                                     "fresh.jpg", "key.jpg"]            # waiting, or left alone
    assert all(x.parent.name.startswith(".adding-") for x in seen)          # cleaned out of the browser's sight
    v = T.outbox_view(host, "tor-browser", "Tor Browser")
    assert v["on"] and v["folder"] == "~/TempBrowser/Outbox for Tor Browser" and v["originals"] == 1
    assert v["not_cleaned"] == ["notes.xyz"] and v["waiting"] == 2 and not v["permanent"]
    assert [(r["what"], r["name"]) for r in v["recent"]] == [("cleaned", "photo.jpg"), ("not_cleaned", "notes.xyz")]
    assert "can't clean this kind of file" in v["recent"][1]["detail"]          # newest first
    # a second photo of the same name: To upload keeps both, the originals too
    (box / "photo.jpg").write_bytes(b"two+gps")
    old(box / "photo.jpg")
    B.run_outboxes(host)
    assert (up / "photo (2).jpg").read_bytes() == b"two" and (box / "Originals/photo (2).jpg").exists()
    # turning it off is refused while it holds files (an original may be the only copy)
    with pytest.raises(T.TransferError, match="still holds"):
        T.remove_outbox(host, "Tor Browser")
    for x in sorted(box.rglob("*"), key=lambda x: -len(x.parts)):
        if x.is_dir() and not x.is_symlink() and x.name not in ("Originals", "Not cleaned"):
            x.rmdir()
        elif not x.is_dir() or x.is_symlink():
            x.unlink()
    T.remove_outbox(host, "Tor Browser")
    assert not box.exists() and not T.outbox_view(host, "tor-browser", "Tor Browser")["on"]
    # closing ~/TempBrowser forgets what it did
    B.wipe_disk(host.home / "TempBrowser")
    assert T.recent("tor-browser") == []


def test_no_tempoutbox_with_the_permanent_outbox_or_a_closed_disk(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    outbox_mat2(host)
    units = host.home / ".config/systemd/user"
    (units / "default.target.wants").mkdir(parents=True)
    (units / "daprivacyscanner-outbox.path").write_text("[Path]\n")
    assert not T.permanent_outbox(host)                       # set up but not watching: not the one to use
    os.symlink("../daprivacyscanner-outbox.path", units / "default.target.wants/daprivacyscanner-outbox.path")
    assert T.permanent_outbox(host) and not B.default_outbox(host, B.BROWSERS["tor"])
    assert T.outbox_view(host, "tor-browser", "Tor Browser")["permanent"]
    # with the RAM disk closed, nothing is looked at
    box = T.make_outbox(host, "Tor Browser")
    (box / "photo.jpg").write_bytes(b"jpeg+gps")
    old(box / "photo.jpg")
    mounts = host.root / "proc/self/mounts"
    mounts.write_text("".join(ln + "\n" for ln in mounts.read_text().splitlines() if "TempBrowser" not in ln))
    B.run_outboxes(host)
    assert (box / "photo.jpg").exists() and not list(T.uploads_dir(host, "tor-browser").iterdir())


def test_the_tempoutbox_through_the_api(cat, host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    outbox_mat2(host)
    c = app_for(cat, host)
    tor = c.get("/api/tools/browser", headers=H).json()["browsers"][0]
    assert tor["outbox"]["on"] is False and tor["outbox"]["watched"] is False
    tor = c.post("/api/tools/browser/outbox", headers=H, json={"browser": "tor", "on": True}).json()["browsers"][0]
    assert tor["outbox"]["on"] and tor["outbox"]["mat2"]
    opened = []
    host.runner.handlers["xdg-open"] = lambda argv: opened.append(argv[1]) or CommandResult(tuple(argv), 0)
    assert c.post("/api/tools/browser/show", headers=H, json={"browser": "tor", "which": "outbox"}).json()["ok"]
    assert opened == [str(host.home / "TempBrowser/Outbox for Tor Browser")]
    assert c.post("/api/tools/browser/show", headers=H, json={"browser": "tor", "which": "permanent"}).status_code == 409
    (host.home / "TempBrowser/Outbox for Tor Browser/a.jpg").write_bytes(b"x")
    assert c.post("/api/tools/browser/outbox", headers=H, json={"browser": "tor", "on": False}).status_code == 400
    (host.home / "TempBrowser/Outbox for Tor Browser/a.jpg").unlink()
    tor = c.post("/api/tools/browser/outbox", headers=H, json={"browser": "tor", "on": False}).json()["browsers"][0]
    assert tor["outbox"]["on"] is False


# ------------------------------------------------------------------ downloads

def old(p: Path):
    t = time.time() - 60
    os.utime(p, (t, t), follow_symlinks=False)


def test_only_finished_plain_files_are_listed(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    for name in ("report.pdf", "tool.sh", "invoice.pdf.desktop", "big.iso", "big.iso.part", "fresh.txt", "linked.txt"):
        (d / name).write_bytes(b"x")
    for name in ("report.pdf", "tool.sh", "invoice.pdf.desktop", "big.iso", "big.iso.part", "linked.txt"):
        old(d / name)
    os.link(d / "linked.txt", d / "twin.txt")
    os.symlink(host.home / ".ssh/id_ed25519", d / "key")
    os.mkfifo(d / "pipe")
    (d / "folder").mkdir()
    got, other = T.downloads(host, "tor-browser")
    assert [e.name for e in got] == ["invoice.pdf.desktop", "report.pdf", "tool.sh"]
    assert other == 8
    w = {e.name: e.warnings for e in got}
    assert "real address" in w["report.pdf"][0] and "runs as a program" in w["tool.sh"][0]
    assert any("look like a pdf" in x for x in w["invoice.pdf.desktop"])


def test_saving_copies_a_new_file_never_executable(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "tool.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    os.chmod(d / "tool.sh", 0o755)
    old(d / "tool.sh")
    dest = host.home / "Documents"
    dest.mkdir()
    (dest / "tool.sh").write_text("mine")
    out = T.save(host, "tor-browser", "tool.sh", dest, check(host, "tool.sh"))
    assert out == dest / "tool (2).sh" and out.read_bytes().startswith(b"#!/bin/sh")
    assert not os.stat(out).st_mode & 0o111 and (dest / "tool.sh").read_text() == "mine"
    assert (d / "tool.sh").exists()                                   # the RAM disk's copy stays until it closes
    with pytest.raises(T.TransferError):
        T.save(host, "tor-browser", "../../../.bashrc", dest, "x")
    assert not list(B.root(host).glob(".checking-*"))                 # its checked copy is gone too


def check(host, name, folder="tor-browser"):
    """What the page sends back with Save… and View offline…: the listing's check for `name`."""
    return next(e.check for e in T.downloads(host, folder)[0] if e.name == name)


def test_a_download_changed_after_it_was_listed_is_not_saved(host):
    """The browser owns its Downloads folder: it can swap a file the page showed as a picture for a
    program once the user has looked. What is saved is a copy made out of its reach and judged again."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))
    old(d / "photo.png")
    shown = check(host, "photo.png")
    (d / "photo.png").write_bytes(b"\x7fELF" + bytes(68))              # swapped after the user looked
    old(d / "photo.png")
    dest = host.home / "Documents"
    dest.mkdir()
    with pytest.raises(T.Changed, match="changed after it was listed .*program"):
        T.save(host, "tor-browser", "photo.png", dest, shown)
    assert list(dest.iterdir()) == [] and not list(B.root(host).glob(".checking-*"))
    with pytest.raises(T.TransferError, match="out of date"):
        T.save(host, "tor-browser", "photo.png", dest, None)
    out = T.save(host, "tor-browser", "photo.png", dest, check(host, "photo.png"))   # what it is now, once shown
    assert out.read_bytes().startswith(b"\x7fELF") and not list(B.root(host).glob(".checking-*"))


def test_a_download_swapped_for_one_of_the_same_size_and_kind_is_not_saved(host):
    """The check covers the content too: another picture of the same size isn't the one the user chose."""
    installed_tor(host)
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))
    old(d / "photo.png")
    shown = check(host, "photo.png")
    (d / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x01" * 64)
    old(d / "photo.png")
    dest = host.home / "Documents"
    dest.mkdir()
    with pytest.raises(T.Changed, match="not the same file"):
        T.save(host, "tor-browser", "photo.png", dest, shown)
    assert list(dest.iterdir()) == []


def test_a_link_planted_as_the_downloads_folder_is_not_followed(host):
    installed_tor(host)
    T.prepare(host, "tor-browser")
    secrets_dir = host.home / ".ssh"
    secrets_dir.mkdir()
    (secrets_dir / "id_ed25519").write_text("PRIVATE")
    old(secrets_dir / "id_ed25519")
    d = T.downloads_dir(host, "tor-browser")
    d.rmdir()
    os.symlink(secrets_dir, d)
    assert T.downloads(host, "tor-browser") == ([], 0)
    with pytest.raises(T.TransferError):
        T.save(host, "tor-browser", "id_ed25519", host.home / "Downloads", "x")
    assert not (host.home / "Downloads/id_ed25519").exists()


def test_safe_names():
    assert T.safe_name("-rf.txt") == "rf.txt" and T.safe_name(".hidden") == "hidden"
    assert T.safe_name("a\nb\x1b[31m.pdf") == "a_b_[31m.pdf" and T.safe_name("...") == "download"
    assert len(T.safe_name("x" * 300 + ".pdf").encode()) <= 200 and T.safe_name("x" * 300 + ".pdf").endswith(".pdf")


# ------------------------------------------------------------------ through the API

def test_the_api(cat, host):
    disk = installed_tor(host)
    T.prepare(host, "tor-browser")
    src = host.home / "Downloads/notes.txt"
    src.write_text("n")
    (T.downloads_dir(host, "tor-browser") / "page.html").write_text("<p>")
    old(T.downloads_dir(host, "tor-browser") / "page.html")
    c = app_for(cat, host)
    d = c.get("/api/tools/browser", headers=H).json()
    tor = d["browsers"][0]
    assert not d["sandbox"]["available"] and "bwrap" in d["sandbox"]["why"]
    assert [x["name"] for x in tor["downloads"]] == ["page.html"] and tor["uploads"] == []
    r = c.post("/api/tools/browser/upload", headers=H, json={"browser": "tor", "paths": [str(src)], "clean": False}).json()
    assert [a["name"] for a in r["added"]] == ["notes.txt"] and r["browsers"][0]["uploads"][0]["name"] == "notes.txt"
    assert c.post("/api/tools/browser/upload", headers=H,
                  json={"browser": "tor", "paths": [str(disk)], "clean": False}).status_code == 400   # not a file
    listed = tor["downloads"][0]["check"]
    r = c.post("/api/tools/browser/save", headers=H, json={"browser": "tor", "name": "page.html", "folder": "~/Downloads",
                                                            "check": listed})
    assert r.status_code == 200 and (host.home / "Downloads/page.html").read_text() == "<p>"
    (T.downloads_dir(host, "tor-browser") / "page.html").write_text("<p>changed")
    old(T.downloads_dir(host, "tor-browser") / "page.html")
    r = c.post("/api/tools/browser/save", headers=H, json={"browser": "tor", "name": "page.html", "folder": "~/Downloads",
                                                            "check": listed})
    assert r.status_code == 409 and r.json()["changed"]
    assert c.post("/api/tools/browser/save", headers=H,
                  json={"browser": "tor", "name": "page.html", "folder": "relative"}).status_code == 400
    r = c.post("/api/tools/browser/upload/remove", headers=H, json={"browser": "tor", "name": "notes.txt"}).json()
    assert r["browsers"][0]["uploads"] == []


def test_the_folder_chooser(host):
    from daprivacyscanner.tools.pick import dialog
    calls = []

    def zenity(argv):
        calls.append(argv)
        return CommandResult(tuple(argv), 0, "/home/alice/Documents\n")
    host.runner.handlers["zenity"] = zenity
    assert dialog(host)("folder", False, "/home/alice") == ["/home/alice/Documents"] and "--directory" in calls[0]
    host = Host(home=host.home, environ={**host.environ, "XDG_CURRENT_DESKTOP": "KDE"}, runner=FakeRunner(), root=host.root)
    host.runner.handlers["kdialog"] = lambda argv: calls.append(argv) or CommandResult(tuple(argv), 0, "/home/alice/x\n")
    assert dialog(host)("folder", False, "/home/alice") == ["/home/alice/x"] and "--getexistingdirectory" in calls[-1]


def test_the_sandbox_s_command_stays_until_the_browser_s_last_process_has_gone(tmp_path):
    """Run for real, on this machine's python3: STAY around a start script. A browser that restarts itself is a
    new process while the old one, and the script waiting for it, end: the command must last until that one
    has gone too, and give the script's status. A program from elsewhere that lingers isn't waited for, and an
    orphan that ends before the browser has started doesn't end it."""
    import shutil
    import signal
    import subprocess
    import sys
    import time
    folder = tmp_path / "browser"
    folder.mkdir()
    real = folder / "firefox.real"
    shutil.copy("/usr/bin/sleep", real)
    try:
        subprocess.run([str(real), "0"], check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("programs can't be run from the temporary folder here")
    stay = [sys.executable, "-I", "-c", S.STAY, str(folder), "/bin/sh", "-c"]

    def run(script):
        t = time.monotonic()
        r = subprocess.run([*stay, script, "sh", str(real), str(tmp_path / "pid")], timeout=30)
        return r.returncode, time.monotonic() - t
    # the "restart": the first process starts a second one and ends, and the script with it
    code, took = run('"$1" 1.2 & exit 7')
    assert code == 7 and took >= 1.1
    # an orphan gone before the browser runs, then the browser itself in the script's place
    code, took = run('(/usr/bin/true &); /usr/bin/sleep 0.4; exec "$1" 0.8')
    assert code == 0 and took >= 1.1
    # what lingers from /usr isn't the browser: not waited for
    code, took = run('/usr/bin/sleep 20 & echo $! > "$2"; exit 3')
    assert code == 3 and took < 5
    os.kill(int((tmp_path / "pid").read_text()), signal.SIGKILL)
    # a script that was killed: its signal as the status, as a shell gives it
    assert run('kill -TERM $$')[0] == 128 + signal.SIGTERM


def test_the_keyring_wrapper_joins_a_new_session_keyring_then_runs_the_program(tmp_path):
    """Run for real: the wrapper on this machine's python3, around a program that reports whether a key
    put in the login session's keyring is still reachable. The key is removed afterwards."""
    import ctypes
    import subprocess
    import sys
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "syscall") or os.uname().machine not in ("x86_64", "i686"):
        pytest.skip("keyctl numbers checked on x86 only")
    nr_add, nr_ctl = (248, 250) if os.uname().machine == "x86_64" else (286, 288)
    kid = libc.syscall(nr_add, b"user", b"dap-wrapper-test", b"secret", 6, -3)
    if kid < 0:
        pytest.skip("no kernel keyring here")
    try:
        probe = tmp_path / "probe.py"
        probe.write_text("import ctypes, sys\nlibc = ctypes.CDLL(None, use_errno=True)\n"
                         f"print(libc.syscall({nr_ctl - 1}, b'user', b'dap-wrapper-test', None, 0) > 0)\n")
        before = subprocess.run([sys.executable, "-I", str(probe)], capture_output=True, text=True).stdout.strip()
        after = subprocess.run([sys.executable, "-I", "-c", S.KEYRING, sys.executable, "-I", str(probe)],
                               capture_output=True, text=True)
        assert before == "True" and after.stdout.strip() == "False" and after.returncode == 0
    finally:
        libc.syscall(nr_ctl, 21, kid)


def test_the_wrapper_leaves_memory_out_of_crash_dumps():
    """Run for real: a program started through the wrapper has no memory in a crash dump (coredump_filter
    0, inherited across exec) and a core size limit of 1, at which the kernel doesn't dump at all: with 0, systemd-coredump
    still wrote the program's command line and open files' paths into the journal (tested)."""
    import subprocess
    import sys
    probe = ("import resource; print(open('/proc/self/coredump_filter').read().strip(), "
             "resource.getrlimit(resource.RLIMIT_CORE))")
    out = subprocess.run([sys.executable, "-I", "-c", S.KEYRING, sys.executable, "-I", "-c", probe],
                         capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.split()[0] == "00000000" and "(1, 1)" in out.stdout


def test_without_python3_only_the_core_limit_is_set(host):
    host.runner.handlers["prlimit"] = lambda argv: CommandResult(tuple(argv), 0)
    assert S.fresh_keyring(host, ["bwrap", "x"]) == ["prlimit", "--core=1:1", "--", "bwrap", "x"]


def test_every_start_gets_a_fresh_keyring(host, monkeypatch):
    installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)
    (host.root / "usr/bin").mkdir(parents=True)
    (host.root / "usr/bin/python3").write_text("")
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    calls = []
    B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))
    assert calls[0][0][:5] == [S.PYTHON, "-I", "-c", S.KEYRING, "bwrap"]


def test_a_failed_probe_is_tried_again(host, monkeypatch):
    """Installing passt (or bubblewrap) shows when the panel is opened again, without restarting the app."""
    answers = ["pasta isn't installed (the passt package).", None, "never asked"]
    monkeypatch.setattr(B, "REPROBE", 0.0)
    probe = lambda h: answers.pop(0)                          # noqa: E731
    assert B._probe(host, "test", probe) == "pasta isn't installed (the passt package)."
    assert B._probe(host, "test", probe) is None              # tried again: installed now
    assert B._probe(host, "test", probe) is None and answers == ["never asked"]    # a success is kept


def test_on_wayland_the_browser_gets_a_socket_marked_as_a_sandbox_s(host, monkeypatch):
    """Where the compositor has the security-context protocol, the browser's socket is one the compositor
    marks as a sandbox's (no screen recording, no clipboard in the background), kept open by bubblewrap's
    --sync-fd; the app's own copy of the pipe is closed once the sandbox has it."""
    from daprivacyscanner.tools import wayland as W
    installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    monkeypatch.setattr(B, "_socket_at", lambda h, path: "/run/compositor-0")
    made = {}

    def sandbox_socket(compositor, path, app_id):
        r, w = os.pipe()
        made.update(compositor=compositor, path=path, app_id=app_id, read=r, write=w)
        return w
    monkeypatch.setattr(W, "sandbox_socket", sandbox_socket)
    calls = []
    how = B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))
    [(argv, kw)] = calls
    w = made["write"]
    assert how["wayland_context"] is True and made["compositor"] == "/run/compositor-0" and made["app_id"] == "mullvad"
    assert (str(made["path"]), "/run/user/1000/wayland-0") in pairs(argv, "--ro-bind") and made["path"].name == "wayland-0"
    assert argv[argv.index("--sync-fd") + 1] == str(w) and kw["pass_fds"] == (w,)
    with pytest.raises(OSError):
        os.fstat(w)                                                     # the app's copy is closed
    os.close(made["read"])
    monkeypatch.setattr(W, "sandbox_socket", lambda *a: (_ for _ in ()).throw(W.WaylandError("the compositor refused it: nested")))
    calls.clear()
    B._LAUNCHED.clear()
    how = B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))
    assert "compositor's own socket" in how["wayland_context"] and "--sync-fd" not in calls[0][0]
    assert (f"/run/user/{UID}/wayland-0", "/run/user/1000/wayland-0") in pairs(calls[0][0], "--ro-bind")


def test_under_pasta_the_wayland_pipe_goes_in_as_stdin(host, monkeypatch):
    """pasta passes its command only stdin, stdout and stderr (tested: a descriptor 7 was gone inside), so the
    security context's pipe, which bubblewrap must hold, goes in as stdin: --sync-fd 0. The browser itself gets
    /dev/null as stdin. (Mullvad Browser on KDE with passt stopped at once before.)"""
    from daprivacyscanner.tools import wayland as W
    installed(host, "mullvad")
    wayland(host)
    bwrap_ok(host)
    host.runner.handlers["pasta"] = lambda argv: CommandResult(tuple(argv), 0)
    ip_ok(host)
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    monkeypatch.setattr(B, "_socket_at", lambda h, path: "/run/compositor-0")
    B._PROBED.clear()
    made = {}

    def sandbox_socket(compositor, path, app_id):
        r, w = os.pipe()
        made.update(read=r, write=w)
        return w
    monkeypatch.setattr(W, "sandbox_socket", sandbox_socket)
    calls = []
    how = B.start(host, B.BROWSERS["mullvad"], spawn=spawner(calls))
    [(argv, kw)] = calls
    assert how["network"] == "private" and how["wayland_context"] is True
    assert argv[argv.index("--sync-fd") + 1] == "0" and kw["stdin"] == made["write"] and not kw.get("pass_fds")
    assert argv[argv.index("pasta"):].index("--sync-fd") > 0                     # bubblewrap's option, inside pasta
    assert 'exec "$0" "$@" </dev/null >/dev/null 2>&1' in argv                       # the browser's own stdin: nothing
    with pytest.raises(OSError):
        os.fstat(made["write"])
    os.close(made["read"])
    B._PROBED.clear()


def test_on_x11_a_display_of_its_own_keeps_it_from_other_windows(host, monkeypatch):
    """Xephyr, in a sandbox of its own, is the only thing with the computer's X server; the browser gets
    Xephyr's socket alone, with a cookie of its own, under a display number nobody uses."""
    from daprivacyscanner.tools import wayland as W
    installed(host, "mullvad")
    bwrap_ok(host)
    (host.root / "tmp/.X11-unix").mkdir(parents=True)
    (host.root / "tmp/.X11-unix/X0").write_text("")
    (host.root / "proc/net").mkdir()
    (host.root / "proc/net/unix").write_text("")
    (host.home / ".Xauthority").write_bytes(xauth((256, b"box", b"0", b"A" * 16)))
    host.environ["DISPLAY"] = ":0"
    monkeypatch.setattr(B, "START_WAIT", 0.05)
    b = B.BROWSERS["mullvad"]
    with pytest.raises(B.BrowserError, match="needs Xephyr"):
        B.start(host, b, spawn=spawner([]), nested=True)
    host.runner.handlers["Xephyr"] = lambda argv: CommandResult(tuple(argv), 0)
    calls = []

    class Server(Proc):
        def poll(self):
            return None

    def spawn(argv, **kw):
        calls.append((argv, kw))
        if "Xephyr" in argv:                                            # it opens its socket
            sock = W.socket.socket(W.socket.AF_UNIX)
            W._bind(sock, B.private_dir(host, b) / "x11/X1")
            return Server()
        return Proc()
    how = B.start(host, b, spawn=spawn, nested=True)
    (xe, _), (browser, _) = calls
    assert how["nested"] and xe[xe.index("--") + 1:xe.index("--") + 3] == ["Xephyr", ":1"]
    for opt in ("-terminate", "-nolisten", "-auth", "-no-host-grab"):
        assert opt in xe
    assert xe.count("-nolisten") == 2 and "local" in xe and "tcp" in xe and "--share-net" not in xe
    assert env_of(xe)["__GLX_VENDOR_LIBRARY_NAME"] == "mesa"                           # NVIDIA's GL crashed it without
    assert env_of(browser)["LIBGL_ALWAYS_SOFTWARE"] == "1"
    assert ("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0") in pairs(xe, "--ro-bind")         # the computer's display: Xephyr's only
    private = B.private_dir(host, b)
    ro = pairs(browser, "--ro-bind")
    assert (str(private / "x11/X1"), "/tmp/.X11-unix/X99") in ro and not any(src.endswith("X11-unix/X0") for src, _ in ro)
    assert (str(private / "xauth-browser"), "/tmp/.Xauthority") in ro and env_of(browser)["DISPLAY"] == ":99"
    browser_cookie = (private / "xauth-browser").read_bytes()[-16:]
    assert browser_cookie == (private / "xauth-xephyr").read_bytes()[-16:] and browser_cookie != b"A" * 16
    assert (private / "xauth-computer").read_bytes().endswith(b"A" * 16)                # the real cookie: Xephyr's only


def test_xephyr_runs_under_the_focus_keeper_where_the_computer_has_python3(host):
    """tools/xfocus.py, by the computer's python3, starts Xephyr and keeps the focus on the browser's windows
    (without a window manager its menus closed when the pointer moved onto them); without python3, Xephyr alone."""
    bwrap_ok(host)
    host.runner.handlers["Xephyr"] = lambda argv: CommandResult(tuple(argv), 0)
    (host.root / "tmp/.X11-unix").mkdir(parents=True)
    (host.root / "tmp/.X11-unix/X0").write_text("")
    host.environ["DISPLAY"] = ":0"
    private = host.home / "private"
    private.mkdir()
    rest = lambda argv: argv[argv.index("--") + 1:]                       # noqa: E731
    assert rest(S.nested(host, private, "t", "1400x1000").argv)[:2] == ["Xephyr", ":1"]
    (host.root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (host.root / "usr/bin/python3").write_text("")
    after = rest(S.nested(host, private, "t", "1400x1000").argv)
    assert after[:3] == [S.PYTHON, "-I", "-c"] and after[3] == Path(S.__file__).with_name("xfocus.py").read_text()
    assert after[4:6] == ["Xephyr", ":1"] and "-auth" in after


def test_the_nested_display_has_the_room_the_browser_would_have(host):
    def workarea(text):
        host.runner.handlers["xprop"] = lambda argv: CommandResult(tuple(argv), 0 if text else 1, text)
    def screen(w, h):
        host.runner.handlers["xdpyinfo"] = lambda argv: CommandResult(tuple(argv), 0, f"  dimensions:    {w}x{h} pixels (361x203 millimeters)\n")
    screen(1920, 1080)
    workarea("_NET_WORKAREA = 0, 0, 1920, 1050, 0, 0, 1920, 1050\n")      # the work area, panels left out: as the browser has it
    assert S.screen_size(host) == "1400x1050"                               # a 1400x800 page, as outside (it was 1400x700)
    workarea("_NET_WORKAREA = 0, 0, 1440, 870\n")
    assert S.screen_size(host) == "1400x870"
    workarea("_NET_WORKAREA = 0, 0, 2516, 1292\n")
    assert S.screen_size(host) == "1400x1100"                               # room for a 1400x900 page and the toolbars
    workarea("_NET_WORKAREA = 0, 0, 1024, 560\n")
    assert S.screen_size(host) == "1024x600"
    workarea("")                                                            # no work area: the screen less a panel
    assert S.screen_size(host) == "1400x1032"
    screen(1366, 768)
    assert S.screen_size(host) == "1366x720"
    del host.runner.handlers["xprop"], host.runner.handlers["xdpyinfo"]
    assert S.screen_size(host) == "1280x800"
