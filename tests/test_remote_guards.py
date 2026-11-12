"""Options that would cut the connection this machine is used through from another one (SSH, a remote desktop) are
refused, or keep it open (finding 5 of the 2026-11-12 review): keys only without a key, a firewall turned on with
nothing let in for the remote access in use."""

import pytest

from daprivacyscanner import network
from daprivacyscanner.checks import guides
from daprivacyscanner.checks.guides import remote_access, remote_session
from daprivacyscanner.context import ContextValue

from conftest import make_host, make_scan, sample
from test_guides import apply, build, options, revert, rooted, system  # noqa: F401 - the fixture
from test_ssh_checks import ED

SSH_ENV = {"SSH_CONNECTION": "203.0.113.5 40022 198.51.100.7 2222"}
UFW = {"/etc/ufw/ufw.conf": "ENABLED=no\n"}


def ss(*lines: str):
    return network.parse_ss("".join(ln + "\n" for ln in lines))


def scan_of(host, listeners=()):
    return make_scan(host, listeners=list(listeners))


# ------------------------------------------------------------------ what is in use

def test_ssh_is_this_sessions_and_its_port_comes_from_the_connection(tmp_path):
    host = make_host(tmp_path, env=SSH_ENV)
    got = remote_access(scan_of(host))
    assert [(r.name, r.ports, r.session) for r in got] == [("ssh", ("2222/tcp",), True)]
    assert remote_session(scan_of(host)) == {"ssh"}
    assert remote_access(scan_of(make_host(tmp_path / "t", env={"SSH_TTY": "/dev/pts/1"})))[0].ports == ("22/tcp",)
    assert remote_access(scan_of(make_host(tmp_path / "c", env={"SSH_CLIENT": "10.0.0.2 5 2200"})))[0].ports == \
        ("2200/tcp",)
    assert remote_access(scan_of(make_host(tmp_path / "n"))) == []


def test_xrdp_counts_for_the_firewall_but_is_this_sessions_only_with_xrdp_session(tmp_path):
    host = make_host(tmp_path, files={"/proc/9/comm": "xrdp\n"})
    got = remote_access(scan_of(host, ss("tcp LISTEN 0 2 *:3389 *:*")))
    assert [(r.name, r.ports, r.session) for r in got] == [("xrdp", ("3389/tcp",), False)]
    assert remote_session(scan_of(host)) == set()       # a running xrdp isn't this session: its off option isn't blocked
    host = make_host(tmp_path / "s", env={"XRDP_SESSION": "1"},
                     files={"/etc/xrdp/xrdp.ini": "[Globals]\nport=3390\n[Xorg]\nport=-1\n"})
    got = remote_access(scan_of(host))
    assert [(r.name, r.ports, r.session) for r in got] == [("xrdp", ("3390/tcp",), True)]
    assert "xrdp" in remote_session(scan_of(host))


@pytest.mark.parametrize("comm,name,listen,ports", [
    ("x11vnc", "vnc", "tcp LISTEN 0 32 0.0.0.0:5900 0.0.0.0:*", ("5900/tcp",)),
    ("Xtigervnc", "vnc", "tcp LISTEN 0 32 0.0.0.0:5901 0.0.0.0:*", ("5901/tcp",)),
    ("gnome-remote-de", "gnome-remote-desktop", "tcp LISTEN 0 32 *:3389 *:*", ("3389/tcp",)),
    ("nxd", "nomachine", "tcp LISTEN 0 32 0.0.0.0:4000 0.0.0.0:*", ("4000/tcp",)),
    ("sunshine", "sunshine", "tcp LISTEN 0 32 0.0.0.0:47989 0.0.0.0:*", ("47989/tcp",)),
    ("anydesk", "anydesk", "tcp LISTEN 0 32 0.0.0.0:7070 0.0.0.0:*", ("7070/tcp",)),
])
def test_remote_desktop_programs_and_the_ports_they_listen_on(tmp_path, comm, name, listen, ports):
    host = make_host(tmp_path, files={"/proc/7/comm": comm + "\n"})
    got = remote_access(scan_of(host, ss(listen)))
    assert [(r.name, r.ports, r.unknown) for r in got] == [(name, ports, False)]
    assert name in remote_session(scan_of(host, ss(listen)))


def test_a_programs_own_socket_counts_on_any_port_and_loopback_needs_nothing(tmp_path):
    host = make_host(tmp_path, files={"/proc/7/comm": "x11vnc\n"})
    own = ss('tcp LISTEN 0 32 0.0.0.0:5999 0.0.0.0:* users:(("x11vnc",pid=7,fd=3))')
    assert remote_access(scan_of(host, own))[0].ports == ("5999/tcp",)
    # tunnelled through SSH: on loopback only, nothing for a firewall to let in
    local = ss("tcp LISTEN 0 32 127.0.0.1:5900 0.0.0.0:*")
    assert [(r.ports, r.unknown) for r in remote_access(scan_of(host, local))] == [((), False)]


def test_relay_tools_need_no_port_and_a_system_vnc_elsewhere_is_unknown(tmp_path, monkeypatch):
    host = make_host(tmp_path, files={"/proc/7/comm": "teamviewerd\n"})
    assert [(r.name, r.ports, r.unknown) for r in remote_access(scan_of(host))] == [("teamviewer", (), False)]
    # a VNC server of another account's (root's), with nothing on its usual ports: it may listen anywhere
    monkeypatch.setattr(guides, "processes", lambda host, own=False: set() if own else {"x11vnc"})
    got = remote_access(scan_of(host, ss("tcp LISTEN 0 32 0.0.0.0:22 0.0.0.0:*")))
    assert [(r.name, r.unknown) for r in got] == [("vnc", True)]


# ------------------------------------------------------------------ SSH: keys only

def ssh_guide(cat, host):
    return build(cat, host, "net.exposed_services", listeners=network.parse_ss(sample("ss/mint-22.txt")),
                 exposed_services=ContextValue("exposed_services", True, [], ""))


def test_keys_only_over_ssh_needs_a_key_that_can_log_in(cat, tmp_path, system, monkeypatch):
    system.units = {"ssh.service": ["enabled", "active"]}
    host = rooted(make_host(tmp_path, env=SSH_ENV), system, monkeypatch)
    plan = options(ssh_guide(cat, host))["Keep SSH, but only with keys"]
    assert "no key in ~/.ssh/authorized_keys" in plan.blockers[0] and "ssh-copy-id" in plan.blockers[0]
    host = rooted(make_host(tmp_path / "k", env=SSH_ENV, home_files={".ssh/authorized_keys": ED + "\n"},
                            files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"}), system, monkeypatch)
    plan = options(ssh_guide(cat, host))["Keep SSH, but only with keys"]
    assert not plan.blockers and "second terminal" in plan.side_effects[0]
    log, res = apply(host, plan)
    revert(host, log, res)
    # restricted keys only: said
    host = rooted(make_host(tmp_path / "r", env=SSH_ENV,
                            home_files={".ssh/authorized_keys": 'command="backup" ' + ED + "\n"}), system, monkeypatch)
    plan = options(ssh_guide(cat, host))["Keep SSH, but only with keys"]
    assert not plan.blockers and any("is limited" in s for s in plan.side_effects)


def test_keys_only_from_the_machine_itself_is_not_blocked(cat, tmp_path, system, monkeypatch):
    system.units = {"ssh.service": ["enabled", "active"]}
    host = rooted(make_host(tmp_path), system, monkeypatch)
    plan = options(ssh_guide(cat, host))["Keep SSH, but only with keys"]
    assert not plan.blockers and not any("second terminal" in s for s in plan.side_effects)


def test_ssh_and_xrdp_off_are_still_blocked_from_inside_their_session(cat, tmp_path, system, monkeypatch):
    system.units = {"ssh.service": ["enabled", "active"], "xrdp.service": ["enabled", "active"]}
    host = rooted(make_host(tmp_path, env={**SSH_ENV, "XRDP_SESSION": "1"}), system, monkeypatch)
    opts = options(ssh_guide(cat, host))
    assert "connected over SSH now" in opts["Turn off the SSH server"].blockers[0]
    assert "over xrdp now" in opts["Turn off Remote desktop"].blockers[0]


# ------------------------------------------------------------------ ufw

def test_ufw_over_ssh_lets_the_connection_in(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, env=SSH_ENV, files=UFW), system, monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=[])
    assert list(options(g)) == ["Turn on ufw, still allowing your remote access"]
    plan = options(g)["Turn on ufw, still allowing your remote access"]
    assert plan.actions[0].args == {"allow": ["2222/tcp"]} and not plan.blockers
    assert any("SSH (2222/tcp)" in s for s in plan.side_effects)
    log, res = apply(host, plan)
    assert system.ufw_active and system.ufw_rules == ["2222/tcp"]
    revert(host, log, res)
    assert not system.ufw_active and system.ufw_rules == []


def test_ufw_keeping_exposed_services_keeps_the_remote_port_too(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, env=SSH_ENV, files=UFW), system, monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=network.parse_ss(sample("ss/mint-22.txt")))
    labels = list(options(g))
    assert labels[0] == "Turn on ufw, still allowing your remote access"
    assert options(g)[labels[0]].actions[0].args["allow"] == ["2222/tcp"]
    assert any("These stop being reachable: 22/tcp" in s for s in options(g)[labels[0]].side_effects)
    assert options(g)[labels[1]].actions[0].args["allow"] == ["2222/tcp", "22/tcp", "3389/tcp"]


def test_ufw_with_nothing_left_to_cut_offers_one_option(cat, tmp_path, system, monkeypatch):
    """Over SSH on port 22 with only sshd listening: the plain option already lets it in, so there is no second one
    that says the same."""
    host = rooted(make_host(tmp_path, env={"SSH_CONNECTION": "10.0.0.2 5 10.0.0.1 22"}, files=UFW), system,
                  monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=ss("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"))
    assert list(options(g)) == ["Turn on ufw, still allowing your remote access"]
    assert g.steps[0].options[0].recommended


def test_ufw_is_refused_when_a_remote_desktops_port_cant_be_told(cat, tmp_path, system, monkeypatch):
    monkeypatch.setattr(guides, "processes", lambda host, own=False: set() if own else {"Xvnc"})
    host = rooted(make_host(tmp_path, files=UFW), system, monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=[])
    plan = options(g)["Turn on ufw"]
    assert "couldn't be found" in plan.blockers[0] and "VNC (Xvnc)" in plan.blockers[0]


def test_ufw_from_the_machine_itself_is_as_before(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files=UFW), system, monkeypatch)
    plan = options(build(cat, host, "net.firewall_off", listeners=[]))["Turn on ufw"]
    assert plan.actions[0].args == {"allow": []} and not plan.blockers


# ------------------------------------------------------------------ firewalld

PUBLIC = ('<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <short>Public</short>\n  <service name="ssh"/>\n'
          '  <service name="mdns"/>\n</zone>\n')
FEDORA_WS = ('<zone>\n  <service name="ssh"/>\n  <port protocol="udp" port="1025-65535"/>\n'
             '  <port protocol="tcp" port="1025-65535"/>\n</zone>\n')
SERVICES = {"/usr/lib/firewalld/services/ssh.xml": '<service><port protocol="tcp" port="22"/></service>',
            "/usr/lib/firewalld/services/mdns.xml": '<service><port protocol="udp" port="5353"/></service>'}


def firewalld_host(tmp_path, system, monkeypatch, env=None, files=None):
    system.units["firewalld.service"] = ["disabled", "inactive"]
    return rooted(make_host(tmp_path, env=env, files={**SERVICES, "/usr/lib/firewalld/zones/public.xml": PUBLIC,
                                                      **(files or {})}), system, monkeypatch)


def test_firewalld_over_ssh_on_a_port_its_zone_lets_in(cat, tmp_path, system, monkeypatch):
    host = firewalld_host(tmp_path, system, monkeypatch, env={"SSH_CONNECTION": "10.0.0.2 5 10.0.0.1 22"},
                          files={"/etc/firewalld/firewalld.conf": "DefaultZone=public\n"})
    g = build(cat, host, "net.firewall_off", listeners=[])
    assert not options(g)["Start and enable firewalld"].blockers and not g.steps[0].commands


def test_firewalld_over_ssh_on_another_port_is_refused_with_the_commands(cat, tmp_path, system, monkeypatch):
    host = firewalld_host(tmp_path, system, monkeypatch, env=SSH_ENV,
                          files={"/etc/firewalld/firewalld.conf": "DefaultZone=public\n"})
    g = build(cat, host, "net.firewall_off", listeners=[])
    plan = options(g)["Start and enable firewalld"]
    assert "default zone, public, doesn't let 2222/tcp in" in plan.blockers[0]
    assert g.steps[0].commands[-2:] == ["sudo firewall-offline-cmd --add-port=2222/tcp",
                                        "sudo systemctl enable --now firewalld"]


def test_firewalld_zone_ranges_and_the_administrators_copy(cat, tmp_path, system, monkeypatch):
    """Fedora Workstation's zone lets in 1025-65535; a copy of a zone in /etc/firewalld wins over the package's."""
    host = firewalld_host(tmp_path, system, monkeypatch, env=SSH_ENV, files={
        "/etc/firewalld/firewalld.conf": "DefaultZone=FedoraWorkstation\n",
        "/usr/lib/firewalld/zones/FedoraWorkstation.xml": FEDORA_WS})
    assert not options(build(cat, host, "net.firewall_off", listeners=[]))["Start and enable firewalld"].blockers
    (host.root / "etc/firewalld/zones").mkdir(parents=True)
    (host.root / "etc/firewalld/zones/FedoraWorkstation.xml").write_text(PUBLIC)
    assert options(build(cat, host, "net.firewall_off", listeners=[]))["Start and enable firewalld"].blockers


def test_firewalld_settings_only_root_can_read_refuse_it(cat, tmp_path, system, monkeypatch):
    """Fedora keeps /etc/firewalld root's alone (0750): what the default zone lets in can't be told."""
    host = firewalld_host(tmp_path, system, monkeypatch, env={"SSH_CONNECTION": "10.0.0.2 5 10.0.0.1 22"},
                          files={"/etc/firewalld/firewalld.conf": "DefaultZone=public\n"})
    from daprivacyscanner.host import Host, Unreadable
    real = Host.read_file

    def guarded(p):
        if "/etc/firewalld" in str(p):
            raise Unreadable(str(p))
        return real(p)
    monkeypatch.setattr(Host, "read_file", staticmethod(guarded))
    g = build(cat, host, "net.firewall_off", listeners=[])
    plan = options(g)["Start and enable firewalld"]
    assert "can only be read as administrator" in plan.blockers[0]
    assert "sudo firewall-offline-cmd --add-port=22/tcp" in g.steps[0].commands


def test_firewalld_from_the_machine_itself_is_as_before(cat, tmp_path, system, monkeypatch):
    host = firewalld_host(tmp_path, system, monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=[])
    plan = options(g)["Start and enable firewalld"]
    assert not plan.blockers and not g.steps[0].commands
    log, res = apply(host, plan)
    revert(host, log, res)
