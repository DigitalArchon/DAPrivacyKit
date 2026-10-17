"""What the tools review of 2026-10-17 found in the browser's sandbox and network (sandbox.py, torgate.py), kept
fixed. Nothing here starts bubblewrap or pasta."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.tools import sandbox as S

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
        return CommandResult(tuple(argv), 0, json.dumps(addresses if "address" in argv else routes))
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
    assert ("ip", "-j", "route", "show", "table", "all", "type", "unicast") in calls
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
