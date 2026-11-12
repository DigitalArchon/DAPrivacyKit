"""Recognised across networks: the Wi-Fi address with iwd as NetworkManager's backend, DHCP's identifiers, and a
hostname few computers share (net.mac_permanent, net.hostname_broadcast)."""

import pytest

from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from test_checks_network import NM_LIST, SEND, nm

STABLE = "[connection]\nwifi.cloned-mac-address=stable\n"


def wifi_host(tmp_path, config=STABLE, files=None, **fields):
    cmds = {NM_LIST: "u1:802-11-wireless\n", nm("u1", "connection.id", "802-11-wireless.cloned-mac-address"): "Home\n\n",
            "NetworkManager --print-config": config,
            nm("u1", "connection.id", "ipv6.dhcp-duid", "ipv6.method", "ipv4.dhcp-client-id"):
                "Home\n{duid}\n{method}\n{cid}\n".format(**{"duid": "", "method": "auto", "cid": "", **fields})}
    return make_host(tmp_path, commands=cmds, files=files)


def test_duid_made_from_the_machine_id_is_said_with_a_random_address(cat, tmp_path):
    o = detect(cat, "net.mac_permanent", make_scan(wifi_host(tmp_path)))
    assert o.status is Status.PASS
    assert ev(o)["DHCPv6 identifier (DUID) by default"].startswith("lease (NetworkManager's default")
    assert any(n.title == "The same DHCPv6 identifier on every network" and n.kind == "risk" for n in o.notes)


@pytest.mark.parametrize("config, fields, said", [
    (STABLE + "ipv6.dhcp-duid=stable-uuid\n", {}, False),
    (STABLE, {"duid": "stable-uuid"}, False),
    (STABLE, {"method": "ignore"}, False),                  # no DHCPv6 on it
    (STABLE, {"duid": "00:04:aa:bb"}, True),                # a fixed DUID: the same everywhere
])
def test_duid_per_network_or_not_used_isnt_said(cat, tmp_path, config, fields, said):
    o = detect(cat, "net.mac_permanent", make_scan(wifi_host(tmp_path, config, **fields)))
    assert any(n.title == "The same DHCPv6 identifier on every network" for n in o.notes) is said


def test_a_client_id_of_the_permanent_address_is_said(cat, tmp_path):
    o = detect(cat, "net.mac_permanent", make_scan(wifi_host(tmp_path, STABLE + "ipv6.dhcp-duid=stable-uuid\n",
                                                             cid="perm-mac")))
    assert any(n.title == "The same DHCP client identifier on every network" for n in o.notes)


def test_iwd_backend_keeps_the_permanent_address_unless_it_randomises_per_network(cat, tmp_path):
    """With wifi.backend=iwd, NetworkManager's stable and random addresses apply only where iwd's own
    AddressRandomization is network (its default is disabled), and its scan setting doesn't apply."""
    config = STABLE + "[device]\nwifi.backend=iwd\nwifi.scan-rand-mac-address=no\n"
    o = detect(cat, "net.mac_permanent", make_scan(wifi_host(tmp_path / "a", config)))
    assert o.status is Status.FAIL and "iwd" in o.summary and "permanent MAC address" in o.summary
    assert "wifi.scan-rand-mac-address=no" not in o.summary            # iwd randomises its own scans
    o = detect(cat, "net.mac_permanent", make_scan(wifi_host(
        tmp_path / "b", config, files={"/etc/iwd/main.conf": "[General]\nAddressRandomization=network\n"})))
    assert o.status is Status.PASS and any(n.title == "iwd decides the address" for n in o.notes)
    o = detect(cat, "net.mac_permanent", make_scan(wifi_host(
        tmp_path / "c", config, files={"/etc/iwd/main.conf": "[General]\nAddressRandomization=network\n"
                                                             "[Scan]\nDisableMacAddressRandomization=true\n"})))
    assert o.status is Status.FAIL and "DisableMacAddressRandomization" in o.summary


@pytest.mark.parametrize("hostname, status", [
    ("t14-7q2", Status.WARN),          # sent over DHCP on every network: a label networks know it by
    ("fedora", Status.PASS),
    ("ubuntu-pc", Status.PASS),
    ("GPUTestPC1", Status.WARN),
])
def test_a_unique_hostname_sent_everywhere_is_a_risk(cat, tmp_path, hostname, status):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": hostname + "\n"},
                     commands={NM_LIST: "u1:802-3-ethernet\n", nm("u1", *SEND): "yes\nyes\n"})
    o = detect(cat, "net.hostname_broadcast", make_scan(host))
    assert o.status is status, o.summary


def test_a_unique_hostname_sent_nowhere_passes(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": "t14-7q2\n"},
                     commands={NM_LIST: "u1:802-3-ethernet\n", nm("u1", *SEND): "no\nno\n",
                               "NetworkManager --version": "1.58.1\n",
                               "NetworkManager --print-config": "[connection]\nipv4.dhcp-send-hostname=0\n"
                                                                "ipv6.dhcp-send-hostname=0\n"})
    o = detect(cat, "net.hostname_broadcast", make_scan(host))
    assert o.status is Status.PASS and "doesn't seem to be announced" in o.summary
