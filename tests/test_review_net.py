"""The network checks' fixes from the review of 2026-10-17: firewalld 2.x on Fedora, its legacy CA bundle, NetworkManager's
[connection*] sections, ufw.service on Arch, networkd's container file, systemd-resolved's mDNS and LLMNR, unconnected
ports, DNS inside a VPN, Firefox's DNS over HTTPS, Podman's docker, names in hostnames."""

import json

import pytest

from daprivacyscanner import helper
from daprivacyscanner.context import ContextValue
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.network import Listener

from conftest import detect, ev, make_host, make_scan
from fakes import FakeNmcli, FakeSystem
from test_guides import apply, build, options, revert, rooted


def exposed(value=True):
    return ContextValue("exposed_services", value, [], "")



# ------------------------------------------------------------------ 4. ufw.service on Arch

@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(r))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    return r


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def test_ufw_enable_enables_its_unit_where_the_package_didnt(root):
    """Arch: `ufw enable` writes ENABLED=yes, but ufw.service, which loads the rules at boot, stays disabled."""
    helper.RUN.units = {"ufw.service": ["disabled", "inactive"]}
    r = call("ufw_enable", allow=[])
    assert helper.RUN.ufw_active and helper.RUN.units["ufw.service"] == ["enabled", "active"]
    assert ["systemctl", "enable", "ufw.service"] in helper.RUN.calls
    assert "systemctl enable ufw.service" in r["ran"] and "systemctl start ufw.service" in r["ran"]
    back = call("revert", change_id=r["change_id"])
    assert back["ok"] and not helper.RUN.ufw_active and helper.RUN.units["ufw.service"] == ["disabled", "inactive"]


def test_ufw_on_but_its_unit_off_is_a_change(root):
    """ufw turned on by an earlier version (ENABLED=yes, rules loaded), its unit never enabled: still a change."""
    helper.RUN.units = {"ufw.service": ["disabled", "inactive"]}
    helper.RUN.ufw_active = True
    r = call("ufw_enable", allow=[])
    assert r["changed"] and helper.RUN.units["ufw.service"] == ["enabled", "active"]
    call("revert", change_id=r["change_id"])
    assert helper.RUN.ufw_active and helper.RUN.units["ufw.service"] == ["disabled", "inactive"]


def test_ufw_enabled_unit_is_left_alone(root):
    helper.RUN.units = {"ufw.service": ["enabled", "active"]}          # Debian, Ubuntu, Mint
    call("ufw_enable", allow=[])
    assert not any(c[:2] == ["systemctl", "enable"] for c in helper.RUN.calls)
    helper.RUN.ufw_active = True
    assert not call("ufw_enable", allow=[])["changed"]


def test_ufw_dry_run_names_the_unit_when_it_isnt_enabled(root):
    (root / "usr/lib/systemd/system").mkdir(parents=True)
    (root / "usr/lib/systemd/system/ufw.service").write_text("[Unit]\n")
    assert helper.planned("ufw_enable", {"allow": []})[-2:] == ["systemctl enable ufw.service",
                                                                 "systemctl start ufw.service"]
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "ufw.service").symlink_to("/usr/lib/systemd/system/ufw.service")
    assert helper.planned("ufw_enable", {"allow": []}) == ["ufw --force enable"]


def test_ufw_guide_says_it_turns_the_unit_on(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=no\n", "/etc/os-release": "ID=arch\n"},
                     commands={("systemctl", "is-enabled", "ufw.service"): "disabled\n",
                               ("systemctl", "is-active", "ufw.service"): "inactive\n"})
    g = build(cat, host, "net.firewall_off", listeners=[])
    plan = options(g)["Turn on ufw"]
    assert "systemctl enable --now ufw" in plan.actions[0].describe()
    assert any("ufw.service isn't set to start at boot" in e for e in plan.side_effects)


