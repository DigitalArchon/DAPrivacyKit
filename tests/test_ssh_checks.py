"""auth.ssh_client_settings and auth.ssh_authorized_keys: SSH settings that weaken every
connection, and the keys that can log in as you; their guides apply and revert."""

from __future__ import annotations

import pytest

from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.network import parse_ss

from conftest import detect, ev, make_host, make_scan
from test_guides import apply, build, options, revert

SETTINGS = "auth.ssh_client_settings"
KEYS = "auth.ssh_authorized_keys"

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFQsIvI0z3bygb1udZnZw4BxHi8M+W0EHgBYsNZSaeIv alice@example.com"
RSA1K = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7iXsbM/FLbezWj/fXrQTIFf2J9mPuEiRWdejIzgLRNagjvgiaB8meHYCXTiigHukdsw"
         "RKa8wqNUT6oh94xPO9Paihw0zFMPUC+CGi5GPGdBN/E2Itil/bldxj3rJxryM3x5mzcCiZk7fJ5ZIXih5vKL8QSUSnMzgXZhwu9nndhw== "
         "old@laptop")
RSA3K = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCs8AvVmvbaKTjWGXbZXWffamz/H2qGfOtTEmR42ZC+PLjz/a38bEYB/h6CY4yGLLOtPEr0"
         "AJEDZrg7LK8vu2ZMvTPwVKPz1kQAhHJLMi2roBbz6alFud4DjaBa0mU44ecsPgFxZA/HmC/ecdV1s+vS1vjdB+loGPwj/PUJmeCALWTzZVkhC5B"
         "ooUbKJ6u993SP6aAnWTeQ3u9xho7s+NNHmYEY13JK2Y/HUmMDSkD9NbloTVbAkKHOMB40WqRf80Gg9IZd87LH21AfIPTLsLxtBTxcQ7Pc1PJ8dBA9"
         "9YEWgGkOwXQaUBZG+Iii0ml+0NmXo3uVZAFkQgo7jx4akmB0eGelBAUPbcGTOhE/8q3hHz64ZyFX84+2X0aWRTv6GH4qX+kt1i5fX3cwBES6Xhq+u"
         "zcLKCoyyQNKMcAvVtMVIvpvfj0EYxHzug4wjoStXJ2UHdOWBAu0J5K8Tf99e+FUQSjag5SVs8pH9ezCyl9EKCFLVdloevPBnB9oHFHqq+E= work")
SSHD_ALL = parse_ss("tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n")
SSHD_LOCAL = parse_ss("tcp   LISTEN 0      128        127.0.0.1:22        0.0.0.0:*\n")
DEBIAN_SSH_CONFIG = "Include /etc/ssh/ssh_config.d/*.conf\n\nHost *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n"


def ssh_host(tmp_path, home=None, system=None, agent=None, env=None):
    host = make_host(tmp_path, home_files=home, files=system, installed=("ssh",), env=env)
    if agent is not None:
        host.runner.handlers["ssh-add"] = lambda argv: agent
    return host


# ------------------------------------------------------------------ client settings

def test_safe_defaults_pass(cat, tmp_path):
    o = detect(cat, SETTINGS, make_scan(ssh_host(tmp_path, system={"/etc/ssh/ssh_config": DEBIAN_SSH_CONFIG})))
    assert o.status is Status.PASS and ev(o)["ForwardAgent"] == "not set (ssh's default)"
    assert o.findings == {"agent_forwarded_everywhere": False, "host_keys_unchecked": False, "agent_keys_unlimited": False}


def test_no_ssh_at_all(cat, tmp_path):
    assert detect(cat, SETTINGS, make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


def test_forwarding_everywhere_from_the_users_file(cat, tmp_path):
    cfg = "Host build\n  ForwardAgent yes\n\nHost *\n  ForwardAgent yes\n  StrictHostKeyChecking no\n"
    o = detect(cat, SETTINGS, make_scan(ssh_host(tmp_path, home={".ssh/config": cfg})))
    assert o.status is Status.FAIL and o.findings["agent_forwarded_everywhere"] and o.findings["host_keys_unchecked"]
    assert ev(o)["ForwardAgent"] == "yes (~/.ssh/config) — for every server"
    assert any("1 setting turns agent forwarding on" in n.text for n in o.notes)
    assert effective_severity(cat[SETTINGS], o.findings).value == 5


def test_a_server_specific_block_alone_is_only_a_note(cat, tmp_path):
    o = detect(cat, SETTINGS, make_scan(ssh_host(tmp_path, home={".ssh/config": "Host pi\n  ForwardAgent yes\n"})))
    assert o.status is Status.PASS and o.notes


def test_known_hosts_dev_null_from_an_included_system_file(cat, tmp_path):
    system = {"/etc/ssh/ssh_config": DEBIAN_SSH_CONFIG,
              "/etc/ssh/ssh_config.d/50-lab.conf": "UserKnownHostsFile /dev/null\n"}
    o = detect(cat, SETTINGS, make_scan(ssh_host(tmp_path, system=system)))
    assert o.status is Status.FAIL and ev(o)["UserKnownHostsFile"].startswith("/dev/null (/etc/ssh/ssh_config.d/50-lab.conf)")


def test_keys_without_a_time_limit_warn(cat, tmp_path):
    agent = CommandResult(("ssh-add", "-l"), 0, "256 SHA256:x me@example (ED25519)\n")
    o = detect(cat, SETTINGS, make_scan(ssh_host(tmp_path, agent=agent, env={"SSH_AUTH_SOCK": "/run/user/1000/ssh-agent.socket"})))
    assert o.status is Status.WARN and o.findings["agent_keys_unlimited"]
    assert ev(o)["Keys loaded in the agent"] == 1 and "me@example" not in str(o.evidence)
    assert effective_severity(cat[SETTINGS], o.findings).value == 2


@pytest.mark.parametrize("sock", ["/run/user/1000/gcr/ssh", "/run/user/1000/keyring/ssh"])
def test_gnome_agents_list_keys_before_they_are_unlocked_so_they_are_only_noted(cat, tmp_path, sock):
    """GNOME's agents offer every key in ~/.ssh from login on: the count isn't of unlocked keys."""
    agent = CommandResult(("ssh-add", "-l"), 0, "256 SHA256:x me@example (ED25519)\n")
    o = detect(cat, SETTINGS, make_scan(ssh_host(tmp_path, agent=agent, env={"SSH_AUTH_SOCK": sock})))
    assert o.status is Status.PASS and o.findings["agent_keys_unlimited"] is None
    assert ev(o)["Keys the agent offers (unlocked or not)"] == 1
    assert any(n.title == "Keys stay unlocked until you log out once used" for n in o.notes)


def test_ssh_agent_with_a_lifetime_passes(cat, tmp_path):
    agent = CommandResult(("ssh-add", "-l"), 0, "256 SHA256:x me (ED25519)\n")
    host = ssh_host(tmp_path, agent=agent, env={"SSH_AUTH_SOCK": "/tmp/ssh-XXXX/agent.99"},
                    system={"/proc/100/comm": "ssh-agent\n", "/proc/100/cmdline": "ssh-agent\0-t\x003600\0"})
    o = detect(cat, SETTINGS, make_scan(host))
    assert o.status is Status.PASS and ev(o)["The agent's time limit for keys"] == "1 h"


def test_guide_edits_the_users_line_and_overrides_the_system(cat, tmp_path):
    cfg = "Host build\n  ForwardAgent yes\n\nHost *\n    ForwardAgent yes\n"
    system = {"/etc/ssh/ssh_config": "Host *\n  StrictHostKeyChecking no\n"}
    host = ssh_host(tmp_path, home={".ssh/config": cfg}, system=system)
    g = build(cat, host, SETTINGS)
    assert g.steps[1].commands == ["sudoedit /etc/ssh/ssh_config"]
    plan = options(g)["Change them for every server"]
    log, res = apply(host, plan)
    text = (host.home / ".ssh/config").read_text()
    assert "Host build\n  ForwardAgent yes\n" in text and "Host *\n    ForwardAgent no\n" in text
    assert text.endswith("Host *\n    StrictHostKeyChecking accept-new\n")
    assert detect(cat, SETTINGS, make_scan(host)).status is Status.PASS
    revert(host, log, res)
    assert (host.home / ".ssh/config").read_text() == cfg


def test_guide_creates_the_users_config_when_only_the_system_is_weak(cat, tmp_path):
    host = ssh_host(tmp_path, system={"/etc/ssh/ssh_config": "ForwardAgent yes\n"})
    log, res = apply(host, options(build(cat, host, SETTINGS))["Change them for every server"])
    cfg = host.home / ".ssh/config"
    assert cfg.stat().st_mode & 0o777 == 0o600 and (host.home / ".ssh").stat().st_mode & 0o777 == 0o700
    assert detect(cat, SETTINGS, make_scan(host)).status is Status.PASS
    revert(host, log, res)
    assert not cfg.exists() and not (host.home / ".ssh").exists()


# ------------------------------------------------------------------ authorized keys

def test_no_authorized_keys(cat, tmp_path):
    assert detect(cat, KEYS, make_scan(make_host(tmp_path), listeners=SSHD_ALL)).status is Status.NOT_APPLICABLE


def test_keys_counted_by_type_never_by_comment(cat, tmp_path):
    keys = f"# my keys\n{ED}\nfrom=\"10.0.0.0/8\",no-pty {RSA3K}\n"
    o = detect(cat, KEYS, make_scan(make_host(tmp_path, home_files={".ssh/authorized_keys": keys}), listeners=SSHD_ALL))
    assert o.status is Status.WARN and o.findings == {"sshd_reachable": True, "weak_authorized_keys": False}
    e = ev(o)
    assert e["Keys that can log in as you"] == 2 and e["Ed25519"] == 1 and e["RSA 3072-bit"] == 1
    assert e["Limited to some addresses or one command"] == 1
    assert "alice@example.com" not in str(o.evidence) and "work" not in str(o.evidence)
    assert effective_severity(cat[KEYS], o.findings).value == 4


def test_weak_key_and_a_server_only_on_loopback(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/authorized_keys": RSA1K + "\n"})
    o = detect(cat, KEYS, make_scan(host, listeners=SSHD_LOCAL))
    assert o.status is Status.FAIL and ev(o)["RSA 1024-bit (weak)"] == 1
    assert o.findings == {"sshd_reachable": False, "weak_authorized_keys": True}
    assert effective_severity(cat[KEYS], o.findings).value == 5


def test_keys_with_no_server_listening_pass_with_a_note(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/authorized_keys2": ED + "\n"})
    o = detect(cat, KEYS, make_scan(host, listeners=[]))
    assert o.status is Status.PASS and o.notes[0].title == "If an SSH server is started"


def test_a_custom_port_counts(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/authorized_keys": ED + "\n"},
                     files={"/etc/ssh/sshd_config.d/port.conf": "Port 2222\n"})
    listeners = parse_ss("tcp   LISTEN 0      128          [::]:2222        [::]:*\n")
    assert detect(cat, KEYS, make_scan(host, listeners=listeners)).findings["sshd_reachable"] is True


def test_fingerprints_match_ssh_keygen():
    from pathlib import Path
    from daprivacyscanner.checks.auth import parse_authorized_key
    assert parse_authorized_key(Path("x"), ED).fingerprint == "SHA256:hKJ0H+Zmb20plNzaMBkFO7fwd5iHowrGekqhiXWp5a4"
    k = parse_authorized_key(Path("x"), 'command="echo hi there",restrict ' + RSA1K)
    assert k.fingerprint == "SHA256:tmR8NiXcwoLJZ8/azcX2iY0SVXiIkYvb81lgXgXaL3Q" and k.bits == 1024
    assert k.restricted and k.weak


def test_guide_removes_one_key_and_reverts(cat, tmp_path):
    text = f"{ED}\n{RSA1K}\n"
    host = make_host(tmp_path, home_files={".ssh/authorized_keys": text})
    g = build(cat, host, KEYS, listeners=SSHD_ALL)
    labels = list(options(g))
    assert labels[1].startswith("Remove key 2: RSA 1024-bit (weak), SHA256:tmR8") and g.steps[0].options[1].recommended
    assert "Replace weak keys" in [s.title for s in g.steps]
    assert any("disable --now" in c for s in g.steps for c in s.commands)
    log, res = apply(host, options(g)[labels[1]])
    assert (host.home / ".ssh/authorized_keys").read_text() == ED + "\n"
    # the removed line's comment (often an email address) is in neither the dry run nor the log
    assert "old@laptop" not in str(options(g)[labels[1]].actions[0].preview())
    assert "old@laptop" not in (host.home / ".local/state/daprivacyscanner/undo.json").read_text()
    revert(host, log, res)
    assert (host.home / ".ssh/authorized_keys").read_text() == text
