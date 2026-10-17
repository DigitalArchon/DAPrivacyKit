"""What the tools review of 2026-10-17 found in the browser's sandbox and network (sandbox.py, torgate.py), kept
fixed. Nothing here starts bubblewrap or pasta."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.tools import browser as B
from daprivacyscanner.tools import sandbox as S

from test_browser_sandbox import bwrap_ok, host, identity_etc, installed, layout, pairs, wayland  # noqa: F401 (host: a fixture)

DOCS = Path(__file__).resolve().parents[1] / "docs"

# `ip -j address show` and `ip -j route show table all type unicast` of a computer with a LAN (and its public IPv6
# prefix), a second network card on a public network, Docker with a public IPv6 network, a split VPN (a public range
# through tun0, and Tailscale-like routes in table 52), and a WireGuard tunnel carrying everything but private ranges
# with broad routes in place of a default one (as captured in a throwaway namespace built so, trimmed)
ADDRESSES = [
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                                   {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]},
    {"ifname": "eno1", "addr_info": [
        {"family": "inet", "local": "192.168.1.50", "prefixlen": 24, "scope": "global"},
        {"family": "inet6", "local": "2001:db8:1:0:9afa:9bff:fe0b:3a31", "prefixlen": 64, "scope": "global"},
        {"family": "inet6", "local": "fe80::9afa:9bff:fe0b:3a31", "prefixlen": 64, "scope": "link"}]},
    {"ifname": "eno2", "addr_info": [{"family": "inet", "local": "203.0.113.5", "prefixlen": 24, "scope": "global"}]},
    {"ifname": "docker0", "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global"},
                                        {"family": "inet6", "local": "2001:db8:d0c::1", "prefixlen": 64, "scope": "global"}]},
    {"ifname": "tun0", "addr_info": [{"family": "inet", "local": "10.8.0.6", "prefixlen": 24, "scope": "global"}]},
    {"ifname": "ppp0", "addr_info": [{"family": "inet", "local": "100.80.0.9", "address": "192.88.99.1", "prefixlen": 32,
                                      "scope": "global"}]},
    {"ifname": "wg0", "addr_info": [{"family": "inet", "local": "10.66.66.2", "prefixlen": 32, "scope": "global"}]},
]
EXCLUDE_PRIVATE = ("0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2",
                   "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "173.0.0.0/8", "174.0.0.0/7", "176.0.0.0/4", "193.0.0.0/8",
                   "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4")
ROUTES = [
    {"dst": "default", "gateway": "192.168.1.1", "dev": "eno1", "flags": []},
    {"dst": "192.168.1.0/24", "dev": "eno1", "protocol": "kernel", "scope": "link", "prefsrc": "192.168.1.50"},
    {"dst": "203.0.113.0/24", "dev": "eno2", "protocol": "kernel", "scope": "link", "prefsrc": "203.0.113.5"},
    {"dst": "10.8.0.0/24", "dev": "tun0", "protocol": "kernel", "scope": "link", "prefsrc": "10.8.0.6"},
    {"dst": "198.51.100.0/24", "gateway": "10.8.0.1", "dev": "tun0", "flags": []},
    {"dst": "100.70.0.0/16", "dev": "tun0", "table": "52", "scope": "link"},
    {"dst": "192.0.2.0/24", "dev": "tun0", "table": "52", "scope": "link"},
    {"dst": "default", "dev": "tun0", "table": "52", "scope": "link"},
    *({"dst": n, "dev": "wg0", "scope": "link"} for n in EXCLUDE_PRIVATE),
    {"dst": "2001:db8:1::/64", "dev": "eno1", "protocol": "kernel", "metric": 256},
    {"dst": "2001:db8:d0c::/64", "dev": "docker0", "protocol": "kernel", "metric": 256},
    {"dst": "fe80::/64", "dev": "eno1", "protocol": "kernel", "metric": 256},
    {"dst": "default", "gateway": "fe80::3a10:d5ff:fe12:3456", "dev": "eno1", "metric": 1024},
]


def computer(tmp_path, addresses=ADDRESSES, routes=ROUTES, fails=False):
    calls = []

    def ip(argv):
        calls.append(argv)
        if "-j" not in argv:
            return CommandResult(tuple(argv), 0)
        if fails:
            return CommandResult(tuple(argv), 1, "", "Cannot open netlink socket: Address family not supported\n")
        if "address" in argv:
            return CommandResult(tuple(argv), 0, json.dumps(addresses))
        if not isinstance(routes, list):
            return CommandResult(tuple(argv), 0, json.dumps(routes))
        v6 = [r for r in routes if ":" in r.get("dst", "") + r.get("gateway", "")]
        return CommandResult(tuple(argv), 0, json.dumps(v6 if "-6" in argv else [r for r in routes if r not in v6]))
    ok = lambda argv: calls.append(argv) or CommandResult(tuple(argv), 0)      # noqa: E731
    host = Host(home=tmp_path, environ={}, runner=FakeRunner(handlers={"ip": ip, "pasta": ok, "bwrap": ok}),
                root=tmp_path, uid=1000)
    return host, calls


def test_the_docs_give_the_core_limit_the_start_sets():
    """B8: the start sets a core size limit of 1, at which the kernel skips the dump (at 0 systemd-coredump kept one
    and journalled the command line); the design notes said 0."""
    assert S.NO_CORE == 1 and "resource.RLIMIT_CORE, (1, 1)" in S.KEYRING
    text = (DOCS / "TECHNICAL.md").read_text()
    assert "Sets `RLIMIT_CORE` to (1, 1)" in text and "Sets `RLIMIT_CORE` to (0, 0)." not in text
    source = Path(S.__file__).read_text()
    assert not re.search(r"a core size limit of 0\.", source)


def test_only_the_language_goes_in_not_the_regional_formats(tmp_path):
    """B6: the regional formats (ro_RO on one machine, hu_HU on another, under an English LANG) said the country
    while the clock inside is UTC. The language goes in; the formats, and LC_ALL that would carry them, don't."""
    env = {"LANG": "en_US.UTF-8", "LANGUAGE": "en_US", "LC_CTYPE": "en_US.UTF-8", "LC_MESSAGES": "en_US.UTF-8",
           "LC_TIME": "ro_RO.UTF-8", "LC_NUMERIC": "ro_RO.UTF-8", "LC_MONETARY": "ro_RO.UTF-8", "LC_PAPER": "ro_RO.UTF-8",
           "LC_MEASUREMENT": "ro_RO.UTF-8", "LC_ALL": "hu_HU.UTF-8", "TZ": "Europe/Bucharest"}
    host = Host(home=tmp_path, environ=env, runner=FakeRunner(), root=tmp_path, uid=1000)
    argv = S._env(host, S.Display("x11", [], {"DISPLAY": ":99"}), False)
    got = {argv[i + 1]: argv[i + 2] for i, a in enumerate(argv) if a == "--setenv"}
    assert {k: got[k] for k in ("LANG", "LANGUAGE", "LC_CTYPE", "LC_MESSAGES")} == {
        "LANG": "en_US.UTF-8", "LANGUAGE": "en_US", "LC_CTYPE": "en_US.UTF-8", "LC_MESSAGES": "en_US.UTF-8"}
    assert not any(k in got for k in ("LC_TIME", "LC_NUMERIC", "LC_MONETARY", "LC_PAPER", "LC_MEASUREMENT", "LC_ALL"))
    assert got["TZ"] == "UTC" and "ro_RO" not in " ".join(argv) and "hu_HU" not in " ".join(argv)


# ------------------------------------------------------------------ B2: the computer's own networks are fenced off

def test_the_computer_s_own_networks_are_listed_on_every_interface_and_table(tmp_path):
    """B2: the fence refused only what pasta copied from the default route's interface. The computer's addresses and
    networks on every interface, a point-to-point link's far end, and routes to particular networks in every table
    are refused too; the default routes and a tunnel's routes that carry most of the internet aren't."""
    host, calls = computer(tmp_path)
    v4, v6 = S.host_networks(host)
    assert v4 == ["192.0.2.0/24", "192.88.99.1/32", "198.51.100.0/24", "203.0.113.0/24"]
    assert v6 == ["2001:db8:1::/64", "2001:db8:d0c::/64"]
    # listed from every table, by iproute2's JSON, on the computer
    assert ("ip", "-j", "-4", "route", "show", "table", "all", "type", "unicast") in calls
    assert ("ip", "-j", "-6", "route", "show", "table", "all", "type", "unicast") in calls
    assert ("ip", "-j", "address", "show") in calls
    # an OpenVPN that redirects everything with 0.0.0.0/1 and 128.0.0.0/1 carries the internet: not refused
    host, _ = computer(tmp_path, routes=[{"dst": "0.0.0.0/1", "gateway": "10.8.0.1", "dev": "tun0"},
                                         {"dst": "128.0.0.0/1", "gateway": "10.8.0.1", "dev": "tun0"},
                                         {"dst": "185.65.135.5", "gateway": "192.168.1.1", "dev": "eno1"}])
    v4, _ = S.host_networks(host)
    assert "185.65.135.5/32" in v4 and not any(n.endswith("/1") for n in v4)


def test_the_fence_refuses_them_after_its_own_ranges_and_before_the_browser(tmp_path):
    host, _ = computer(tmp_path)
    script = S.fence(host)[2]
    four = ('for n in 192.0.2.0/24 192.88.99.1/32 198.51.100.0/24 203.0.113.0/24; do ip -4 rule add prohibit to "$n" '
            "pref 100 || { echo 'The local network could not be fenced off' >&2; exit 1; }; done; ")
    six = ('for n in 2001:db8:1::/64 2001:db8:d0c::/64; do ip -6 rule add prohibit to "$n" pref 100 || '
           "{ echo 'The local network could not be fenced off' >&2; exit 1; }; done; ")
    assert four in script and six in script
    assert script.index("prohibit to 224.0.0.0/3") < script.index(four) < script.index("own 4 ||")
    assert script.index("if [ -e /proc/net/if_inet6 ]") < script.index(six) < script.index("own 6 ||")
    # pasta's DNS forwarder and Mullvad's proxies are still let through first (pref 50 and 40, ahead of 100)
    assert "dport 53 pref 50" in script and "dport 1080 pref 40" in script and script.endswith('exec "$0" "$@"')
    # nothing to add on a computer with no networks of its own beyond the fence's ranges
    host, _ = computer(tmp_path, addresses=ADDRESSES[:1], routes=ROUTES[:2])
    assert "for n in" not in S.fence(host)[2]


@pytest.mark.parametrize("trouble", ["fails", "garbled", "too many"])
def test_the_fence_fails_closed_when_the_networks_can_t_be_listed(tmp_path, trouble):
    """No listing, no fence: nothing starts fenced on a guess. The panel then says the local network isn't fenced off
    and why, and a start the panel showed fenced is refused."""
    if trouble == "fails":
        host, _ = computer(tmp_path, fails=True)
    elif trouble == "garbled":
        host, _ = computer(tmp_path, routes={"dst": "203.0.113.0/24"})
    else:
        host, _ = computer(tmp_path, routes=[{"dst": f"203.{i // 256}.{i % 256}.1", "dev": "eno2"}
                                             for i in range(S.FENCE_MAX + 1)])
    with pytest.raises(S.SandboxError, match="networks"):
        S.fence(host)
    why = S.probe_fence(host)
    assert why and "networks" in why


def test_the_probe_checks_from_inside_that_the_computer_s_networks_are_refused(tmp_path):
    host, calls = computer(tmp_path)
    assert S.probe_fence(host) is None
    pasta = next(c for c in calls if c[0] == "pasta")
    check = pasta[-1]
    assert "192.0.2.1" in check and "2001:db8:1::1" in check and "the fence is not in place" in check


# ------------------------------------------------------------------ B4: pasta's namespace has addresses of its own

def opts_of(argv):
    """pasta's options as {flag: [values]}."""
    out: dict[str, list[str]] = {}
    i = 1
    while argv[i] != "--":
        if argv[i] in ("-4", "-6", "--config-net", "--quiet", "--no-map-gw"):
            out.setdefault(argv[i], [])
            i += 1
        else:
            out.setdefault(argv[i], []).append(argv[i + 1])
            i += 2
    return out


def test_pasta_s_namespace_gets_fixed_addresses_not_the_computer_s(tmp_path):
    """B4: pasta copied the computer's interface name, its global IPv6 address (a VPN hides it; its EUI-64 form
    holds the hardware address) and its gateway, whose hardware address it showed inside: the computer's own (pasta
    2024-02-20) or the router's (2026-01-20). Now: eth0, a hardware address the same for everyone, 10.0.2.15/24
    through 10.0.2.2, fd00::15 through pasta's own link-local address."""
    host, _ = computer(tmp_path)
    o = opts_of(["pasta", *S.pasta_opts(host), "--"])
    assert o["-I"] == ["eth0"] and o["-M"] == ["9a:55:9a:55:9a:55"] and o["-n"] == ["24"]
    assert o["-a"] == ["10.0.2.15", "fd00::15"] and o["-g"] == ["10.0.2.2", "fe80::9855:9aff:fe55:9a55"]
    assert "-4" not in o and "-6" not in o and o["--dns-forward"] == [S.DNS_FORWARD]
    text = " ".join(S.pasta_opts(host))
    for real in ("eno1", "192.168.1.", "2001:db8:1:", "98:fa:9b", "fe80::3a10"):
        assert real not in text
    # the gateway is never one of the computer's neighbours (newer pasta shows a neighbour's hardware address): with a
    # network of the computer's over 10.0.2.0/24, the next candidate
    lan = [{"ifname": "enp0s3", "addr_info": [{"family": "inet", "local": "10.0.2.15", "prefixlen": 24, "scope": "global"}]}]
    host, _ = computer(tmp_path, addresses=lan, routes=[{"dst": "default", "gateway": "10.0.2.2", "dev": "enp0s3"}])
    o = opts_of(["pasta", *S.pasta_opts(host), "--"])
    assert o["-a"] == ["10.0.3.15"] and o["-g"] == ["10.0.3.2"] and "-4" in o      # and no IPv6 without a route for it
    # without a listing: the first candidate, and both versions (pasta leaves out one it has no route for)
    host, _ = computer(tmp_path, fails=True)
    o = opts_of(["pasta", *S.pasta_opts(host), "--"])
    assert o["-a"] == ["10.0.2.15", "fd00::15"] and "-4" not in o


def test_ipv6_only_where_the_computer_has_a_route_for_it(tmp_path):
    """Without an IPv6 default route newer pasta made one up for its namespace, through fe80::1, a common router
    address it would then answer for with the router's hardware address (tested on Fedora 44): -4 leaves IPv6 out."""
    host, _ = computer(tmp_path, routes=[r for r in ROUTES if ":" not in r["dst"] + r.get("gateway", "")])
    o = opts_of(["pasta", *S.pasta_opts(host), "--"])
    assert "-4" in o and o["-a"] == ["10.0.2.15"] and not any(":" in g for g in o["-g"])
    host, _ = computer(tmp_path, routes=[r for r in ROUTES if ":" in r["dst"] + r.get("gateway", "")])
    o = opts_of(["pasta", *S.pasta_opts(host), "--"])
    assert "-6" in o and o["-a"] == ["fd00::15"]


def test_the_browser_and_a_trial_start_pasta_with_them(tmp_path):
    host, calls = computer(tmp_path)
    S.probe_pasta(host)
    o = opts_of(next(c for c in calls if c[0] == "pasta"))
    assert o["-I"] == ["eth0"] and "10.0.2.15" in o["-a"]
    from daprivacyscanner.tools import trial
    source = Path(trial.__file__).read_text()
    assert "sandbox.pasta_opts(host)" in source and "sandbox.PASTA_OPTS" not in source
    assert "*pasta_opts(host)" in Path(S.__file__).read_text().split("def browser_argv")[1]


# ------------------------------------------------------------------ B7: DNS over TCP only where pasta forwards it

@pytest.mark.parametrize("forwards", [True, False])
def test_dns_over_tcp_is_let_through_only_where_pasta_s_forwarder_takes_it(tmp_path, monkeypatch, forwards):
    """B7: pasta 2024-02-20 (Mint 22.3) doesn't forward DNS over TCP: the connection went on to 169.254.0.1 itself and
    timed out, while the fence let it through. The probe connects from inside; the rule is set only where it worked
    (pasta 2026-01-20), and elsewhere TCP to the forwarder is refused at once."""
    monkeypatch.setattr(S, "_DNS_TCP", {})
    host, calls = computer(tmp_path)
    host.runner.handlers["pasta"] = lambda argv: calls.append(argv) or CommandResult(
        tuple(argv), 0, f"{S.DNS_TCP_MARK}\n" if forwards else "")
    assert "ipproto tcp dport 53" not in S.fence(host)[2]               # not probed yet: refused
    assert S.probe_fence(host) is None
    probe = next(c for c in calls if c[0] == "pasta")
    assert "ipproto tcp dport 53" in probe[probe.index("-c") + 1]      # the probe tries it, with the rule in place
    assert f'socket.create_connection(("{S.DNS_FORWARD}", 53), 2)' in probe[-1] and S.DNS_TCP_MARK in probe[-1]
    script = S.fence(host)[2]
    assert ("ipproto tcp dport 53 pref 50" in script) is forwards and "ipproto udp dport 53 pref 50" in script
    # an answer too large for 512 bytes then comes over UDP: the sandbox's resolver asks with EDNS0
    assert S.FORWARD_RESOLV == f"nameserver {S.DNS_FORWARD}\noptions edns0\n"
    etc = S.identity_files(tmp_path / "etc", S.FORWARD_RESOLV)
    assert "options edns0" in etc["resolv.conf"].read_text()


# ------------------------------------------------------------------ B3: /proc says less about the computer

def proc_tree(host, *names):
    for name in names:
        p = host.root / "proc" / name
        if name in ("bus", "scsi", "driver"):
            (p / "x").mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("real\n")


def test_proc_masks_cover_the_disks_swap_input_devices_and_drivers(host, tmp_path):
    """B3: /proc/driver/nvidia/gpus/*/information (the graphics card's serial number, whether or not the card was
    given), /proc/bus/input/devices (a Bluetooth device's hardware address, serial numbers), /proc/partitions,
    /proc/scsi (the disks' models) and /proc/swaps were readable inside. Covered: by empty files, or an empty folder
    made read-only; /proc/driver only while the card isn't given (NVIDIA's driver reads its files there)."""
    proc_tree(host, "partitions", "swaps", "bus", "scsi", "driver")
    m = S.proc_masks("/src", host=host)
    binds = [(m[i + 1], m[i + 2]) for i, a in enumerate(m) if a == "--ro-bind"]
    assert binds == [("/src/cmdline", "/proc/cmdline"), ("/src/boot_id", "/proc/sys/kernel/random/boot_id"),
                     ("/src/partitions", "/proc/partitions"), ("/src/swaps", "/proc/swaps")]
    covered = [m[i + 1] for i, a in enumerate(m) if a == "--tmpfs"]
    assert covered == ["/proc/bus", "/proc/scsi", "/proc/driver"]
    assert [m[i + 1] for i, a in enumerate(m) if a == "--remount-ro"] == covered
    assert "/proc/driver" not in S.proc_masks("/src", gpu=True, host=host)
    # only what this kernel has: bubblewrap can't make a mount point in /proc
    (host.root / "proc/scsi/x").rmdir()
    (host.root / "proc/scsi").rmdir()
    assert "/proc/scsi" not in S.proc_masks("/src", host=host)
    etc = S.identity_files(tmp_path / "etc", None)
    assert etc["partitions"].read_text() == "major minor  #blocks  name\n\n"
    assert etc["swaps"].read_text().split() == ["Filename", "Type", "Size", "Used", "Priority"]


def test_both_browsers_innermost_sandboxes_get_them(host):
    proc_tree(host, "partitions", "swaps", "bus", "scsi", "driver")
    installed(host, "mullvad")
    bwrap_ok(host)
    wayland(host)
    identity_etc(host)
    lay, private = layout(host, B.BROWSERS["mullvad"])
    disp = S.display(host, private, landlock=False)
    etc = S.identity_files(private / "etc", None)
    a = S.browser_argv(host, lay, disp, False, False, etc, None)
    assert (str(etc["partitions"]), "/proc/partitions") in pairs(a, "--ro-bind") and a.index("/proc/bus") > a.index("--proc")
    assert "/proc/driver" in a and "/proc/driver" not in S.browser_argv(host, lay, disp, False, False, etc, None,
                                                                        gpu=("/dev/nvidia0",))
    installed(host, "tor")
    lay, private = layout(host, B.BROWSERS["tor"])
    (private / "tor").mkdir(exist_ok=True)
    argv = S.tor_argv(host, lay, private / "tor", disp, False, False, etc, "GATE")
    inner = json.loads(argv[-1])["inner"]
    assert ("/run/identity/swaps", "/proc/swaps") in pairs(inner, "--ro-bind") and "/proc/bus" in inner
    assert "/proc/bus" not in argv[:argv.index("--")]                # never the outer one: its /proc stays whole
