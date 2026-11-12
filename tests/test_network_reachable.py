"""What other machines can reach (net.exposed_services, net.docker_bypass), and what ufw's status says it lets in."""

import pytest

from daprivacyscanner import network
from daprivacyscanner.context import ContextValue
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.network import Listener
from daprivacyscanner.privileged import FakePrivileged

from conftest import detect, ev, make_host, make_scan

# CachyOS's ufw, as captured (2026-11-12): a To column wider than its width is followed by one space
CACHY_UFW = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
1714:1764/udp (KDE Connect) ALLOW IN    Anywhere
1714:1764/tcp (KDE Connect) ALLOW IN    Anywhere
22/tcp                     ALLOW IN    192.0.2.10/24             # ssh-lan
1714:1764/udp (KDE Connect (v6)) ALLOW IN    Anywhere (v6)
1714:1764/tcp (KDE Connect (v6)) ALLOW IN    Anywhere (v6)
3389/tcp                   DENY IN     Anywhere
53/udp                     ALLOW OUT   Anywhere
"""


def test_ufw_rules_whose_to_column_overflows_are_read():
    r = network.parse_ufw_status(CACHY_UFW)
    assert r.unparsed == 0
    assert r.allows(1716, "udp") is True and r.allows(1716, "tcp") is True and r.allows(22, "tcp") is True
    assert r.allows(3389, "tcp") is False and r.allows(53, "udp") is False          # a deny, and an outgoing rule


def exposed(value=True):
    return ContextValue("exposed_services", value, [], "")


ADDR = ("ip", "-o", "addr", "show")
ADDRESSES = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
             "2: eth0    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth0\n"
             "2: eth0    inet6 2001:db8::20/64 scope global\n"
             "3: docker0    inet 172.17.0.1/16 scope global docker0\n"
             "4: virbr0    inet 192.168.122.1/24 scope global virbr0\n")


@pytest.mark.parametrize("listener, counted", [
    (Listener("tcp", "0.0.0.0", 445), True),
    (Listener("tcp", "192.168.1.20", 445), True),                 # Samba bound to the LAN address
    (Listener("tcp", "[2001:db8::20]", 22), True),                # sshd on the public IPv6 address
    (Listener("tcp", "[fe80::1]%eth0", 631), True),               # CUPS on a link-local address, as ss prints it
    (Listener("udp", "172.17.0.1", 53), False),                   # resolved's extra stub, no docker0 yet (freebind)
    (Listener("tcp", "127.0.0.1", 631), False),
    (Listener("tcp", "[::1]", 631), False),
    (Listener("udp", "127.0.0.53%lo", 53), False),
    (Listener("udp", "192.168.122.1", 53), False),                # libvirt's dnsmasq on its own bridge
    (Listener("tcp", "172.17.0.1", 8080), False),                 # Docker's bridge
    (Listener("udp", "0.0.0.0", 45678), False),                   # an ephemeral port: a client's
    (Listener("udp", "0.0.0.0", 51820), False),                   # WireGuard: listed apart, answers only peers
])
def test_what_other_machines_can_reach(tmp_path, listener, counted):
    host = make_host(tmp_path, commands={ADDR: ADDRESSES})
    assert bool(network.exposed([listener], addresses=network.address_interfaces(host))) is counted
    # without the computer's addresses, only a socket bound to every interface counts
    assert bool(network.exposed([listener])) is (counted and listener.wildcard)


def test_silent_vpn_ports_are_listed_not_counted(cat, tmp_path):
    host = make_host(tmp_path, commands={ADDR: ADDRESSES})
    ls = [Listener("udp", "0.0.0.0", 51820), Listener("udp", "0.0.0.0", 41641)]
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=ls, exposed_services=exposed(False)))
    assert o.status is Status.PASS and o.summary == "No service accepts connections from other machines."
    assert "WireGuard" in ev(o)["Answering only their peers"] and "Tailscale" in ev(o)["Answering only their peers"]
    assert any(n.title == "What isn't counted" for n in o.notes)


def test_a_service_bound_to_the_lan_address_is_reachable(cat, tmp_path):
    host = make_host(tmp_path, commands={ADDR: ADDRESSES})
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=[Listener("tcp", "192.168.1.20", 445, "smbd")],
                                                        exposed_services=exposed()))
    assert o.status is Status.FAIL and "1 service is reachable" in o.summary


DOCKER_PORTS = ("docker", "-H", "unix:///run/docker.sock", "ps", "--format", "{{.Ports}}")


def ufw_docker_host(tmp_path, ports_out):
    host = make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=yes\n"}, installed=("docker",), commands={
        ("systemctl", "is-active", "ufw"): "active\n", ("systemctl", "is-active", "docker.service"): "active\n",
        ("docker", "--version"): "Docker version 27.5.1, build 9f9e405\n", DOCKER_PORTS: ports_out, ADDR: ADDRESSES})
    host.privileged = FakePrivileged(ufw="Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo  Action  From\n"
                                         "--  ------  ----\n")
    return host


def test_docker_published_ports_are_never_blocked_by_ufw(cat, tmp_path):
    """ufw denies everything, and `docker run -p 8080:80` is still reachable: Docker forwards it before ufw's input
    rules. It was "Blocked by ufw: 8080", a risk, contradicting net.docker_bypass."""
    host = ufw_docker_host(tmp_path, "0.0.0.0:8080->80/tcp, :::8080->80/tcp\n")
    ls = [Listener("tcp", "0.0.0.0", 8080), Listener("tcp", "0.0.0.0", 3389)]
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=ls, exposed_services=exposed()))
    assert o.status is Status.FAIL and o.findings == {"firewall_blocks_exposed": False}
    assert "8080" in ev(o)["Published by Docker, past the firewall"] and "8080" not in ev(o)["Blocked by ufw"]
    assert any(n.title == "Docker's ports get past the firewall" for n in o.notes)


def test_docker_ports_that_cant_be_listed_leave_the_verdict_open(cat, tmp_path):
    host = ufw_docker_host(tmp_path, CommandResult((), 1, "", "permission denied while trying to connect"))
    ls = [Listener("tcp", "0.0.0.0", 8080), Listener("tcp", "0.0.0.0", 4000, "node")]
    o = detect(cat, "net.exposed_services", make_scan(host, listeners=ls, exposed_services=exposed()))
    assert o.findings == {"firewall_blocks_exposed": None}
    assert "8080" in ev(o)["Not sure whether ufw lets in"] and "4000" in ev(o)["Blocked by ufw"]


def test_rootful_podman_without_docker_is_not_passed_over(cat, tmp_path):
    host = make_host(tmp_path, installed=("podman",), files={
        "/proc/4242/status": "Name:\tconmon\nUid:\t0\t0\t0\t0\n", "/proc/4343/status": "Name:\tbash\nUid:\t1000\n"})
    o = detect(cat, "net.docker_bypass", make_scan(host))
    assert o.status is Status.UNKNOWN and "as root" in o.summary
    (host.root / "proc/4242/status").write_text("Name:\tconmon\nUid:\t1000\t1000\t1000\t1000\n")
    assert detect(cat, "net.docker_bypass", make_scan(host)).status is Status.PASS


def test_a_process_whose_name_isnt_utf8_doesnt_hide_rootful_podman(cat, tmp_path):
    """Any account can name its process anything: one name that isn't UTF-8 in /proc/PID/status raised
    UnicodeDecodeError, and the check couldn't run at all."""
    from daprivacyscanner.checks.network import rootful_podman
    host = make_host(tmp_path, installed=("podman",), files={"/proc/4343/status": "Name:\tbash\nUid:\t1000\n"})
    (host.root / "proc/4141").mkdir()
    (host.root / "proc/4141/status").write_bytes(b"Name:\tbad\xff\xfe\nUid:\t1001\t1001\t1001\t1001\n")
    assert rootful_podman(host) is False
    assert detect(cat, "net.docker_bypass", make_scan(host)).status is Status.PASS
    (host.root / "proc/4242").mkdir()
    (host.root / "proc/4242/status").write_text("Name:\tconmon\nUid:\t0\t0\t0\t0\n")
    o = detect(cat, "net.docker_bypass", make_scan(host))
    assert o.status is Status.UNKNOWN and "as root" in o.summary
