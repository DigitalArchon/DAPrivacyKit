"""OpenSnitch, the outgoing firewall (net.outgoing_firewall): what the helper writes (rule files from its own lists,
one line of the daemon's settings, the log emptied), the window's settings changed one key at a time, the feature's
detection, and its guide applied and reverted, root steps through the real helper code against the fixture tree."""

import json
import os

import pytest

from daprivacyscanner import helper, ini
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.online import PHONE_HOME
from daprivacyscanner.fix import apply_plan, revert_entry
from daprivacyscanner.model import Status
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.undo import UndoLog

from conftest import detect, ev, make_host, make_scan
from fakes import FakeSystem

CONFIG_172 = """{
    "Server":
    {
        "Address":"unix:///tmp/osui.sock",
        "LogFile":"/var/log/opensnitchd.log"
    },
    "DefaultAction": "allow",
    "DefaultDuration": "once",
    "InterceptUnknown": false,
    "ProcMonitorMethod": "ebpf",
    "LogLevel": 2,
    "LogUTC": true,
    "Firewall": "nftables",
    "FwOptions": {
        "ConfigPath": "/etc/opensnitchd/system-fw.json",
        "QueueBypass": true
    },
    "Rules": {
        "Path": "/etc/opensnitchd/rules/",
        "EnableChecksums": false
    }
}
"""
# the window's settings as 1.7.2 writes them on its first start (tested)
WINDOW_172 = "[database]\nfile=file::memory:\njrnl_wal=false\ntype=0\n\n[global]\ndefault_action=0\ndefault_duration=6\n" \
             "default_target=0\ndefault_timeout=30\n\n[statsDialog]\ngeometry=@ByteArray(x)\n"
PROGRAMS = {"/usr/lib/systemd/systemd-resolved": "", "/usr/bin/NetworkManager": "", "/usr/bin/pacman": "",
            "/usr/lib/apt/methods/http": ""}


def installed_host(tmp_path, config=CONFIG_172, window=None, rules=(), running=False, files=None):
    fs = {"/usr/bin/opensnitchd": "", "/usr/bin/opensnitch-ui": "", "/usr/lib/systemd/system/opensnitchd.service": "",
          "/usr/lib/python3.14/site-packages/opensnitch/version.py": "version = '1.7.2'\n",
          "/var/log/opensnitchd.log": "", **PROGRAMS, **(files or {})}
    if config is not None:
        fs["/etc/opensnitchd/default-config.json"] = config
    for name in rules:
        fs[f"/etc/opensnitchd/rules/{name}.json"] = "{}"
    if running:
        fs["/proc/4242/comm"] = "opensnitch-ui\n"
    host = make_host(tmp_path, files=fs, home_files={".config/opensnitch/settings.conf": window} if window else None,
                     links={"/usr/lib/apt/methods/https": "http", "/usr/sbin": "bin"})
    (host.root / "etc/opensnitchd/rules").mkdir(parents=True, exist_ok=True)
    return host


@pytest.fixture
def system(monkeypatch):
    s = FakeSystem(units={"opensnitchd.service": ["enabled", "active"]})
    monkeypatch.setattr(helper, "RUN", s)
    return s


def rooted(host, system, monkeypatch):
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    host.privileged = FakePrivileged()
    host.runner.handlers["systemctl"] = system.handler
    return host


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def guide(cat, host, **kw):
    check = load_all()["net.outgoing_firewall"](cat["net.outgoing_firewall"])
    scan = make_scan(host, **kw)
    return check.plan_guide(scan, check.detect(scan))


def step(g, title):
    return next(s for s in g.steps if s.title.startswith(title))


# ------------------------------------------------------------------ the helper

def test_starter_rules_from_the_helpers_own_lists(tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path), system, monkeypatch)
    r = call("opensnitch_rules", set="starter")
    rules = host.root / "etc/opensnitchd/rules"
    allow = json.loads((rules / "000-daprivacyscanner-allow-system.json").read_text())
    deny = json.loads((rules / "000-daprivacyscanner-deny-telemetry.json").read_text())
    # each program by its real path (links resolved, as /proc/PID/exe names it), each once
    assert allow["operator"]["data"] == ("^(/usr/lib/systemd/systemd-resolved|/usr/bin/NetworkManager|"
                                         "/usr/lib/apt/methods/http|/usr/bin/pacman|Kernel connection)$")
    assert allow["action"] == "allow" and allow["precedence"] is False and allow["duration"] == "always"
    assert deny["action"] == "deny" and deny["operator"]["operand"] == "dest.host"
    assert r"incoming\.telemetry\.mozilla\.org" in deny["operator"]["data"] and r".+\.p3a\.brave\.com" in deny["operator"]["data"]
    assert ["systemctl", "try-restart", "opensnitchd.service"] in system.calls
    assert call("revert", change_id=r["change_id"])["ok"] and not list(rules.iterdir())


def test_rule_sets_are_named_never_sent(tmp_path, system, monkeypatch):
    rooted(installed_host(tmp_path), system, monkeypatch)
    with pytest.raises(helper.Refused, match="unknown rule set"):
        call("opensnitch_rules", set="../../etc/shadow")
    with pytest.raises(helper.Refused, match="unknown rule set"):
        call("opensnitch_rules")
    # what the request carries besides the set's name is never used: the rules come from the helper's lists
    r = call("opensnitch_rules", set="connectivity", hosts=["example.com"])
    assert "example" not in json.dumps([json.loads(c) for c in helper.opensnitch_rule_files("connectivity").values()])
    assert r["changed"]


def test_rules_refused_where_opensnitch_isnt_installed(tmp_path, system, monkeypatch):
    rooted(make_host(tmp_path), system, monkeypatch)
    with pytest.raises(helper.Refused, match="isn't installed"):
        call("opensnitch_rules", set="connectivity")


def test_rule_regexps_match_what_they_name():
    import re
    for which, names in (("starter", [h for h, _ in helper.OPENSNITCH_TELEMETRY]),
                         ("connectivity", [h for h, _ in helper.OPENSNITCH_CONNECTIVITY])):
        files = helper.opensnitch_rule_files(which, root="/nonexistent")
        rule = next(json.loads(c) for p, c in files.items() if "deny" in p)
        pattern = re.compile(rule["operator"]["data"])
        for name in names:
            assert pattern.match("x" + name if name.startswith(".") else name)
        assert not pattern.match("example.com") and not pattern.match("telemetry.mozilla.org.evil.example")


def test_blocked_hosts_are_the_traffic_tests_phone_home_hosts():
    known = {name: check for name, _, check in PHONE_HOME}
    assert all(h in known and known[h] != "net.connectivity_check" for h, _ in helper.OPENSNITCH_TELEMETRY)
    assert all(known.get(h) == "net.connectivity_check" for h, _ in helper.OPENSNITCH_CONNECTIVITY)


def test_log_level_changed_on_its_own_line(tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path), system, monkeypatch)
    r = call("edit_config", target="opensnitch", values={"LogLevel": "3"})
    f = host.root / "etc/opensnitchd/default-config.json"
    assert f.read_text() == CONFIG_172.replace('"LogLevel": 2,', '"LogLevel": 3,')
    assert ["systemctl", "try-restart", "opensnitchd.service"] in system.calls
    assert call("revert", change_id=r["change_id"])["ok"] and f.read_text() == CONFIG_172


def test_default_action_and_a_missing_key(tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path, config='{"DefaultAction": "allow",\n "Firewall": "iptables"}\n'), system,
                  monkeypatch)
    call("edit_config", target="opensnitch", values={"DefaultAction": "deny", "LogLevel": "3"})
    data = json.loads((host.root / "etc/opensnitchd/default-config.json").read_text())
    assert data == {"DefaultAction": "deny", "Firewall": "iptables", "LogLevel": 3}


def test_logging_is_never_made_worse(tmp_path, system, monkeypatch):
    rooted(installed_host(tmp_path), system, monkeypatch)
    for level in ("0", "1", "3\n", "3, \"x\": 1"):
        with pytest.raises(helper.Refused, match="aren't allowed"):
            call("edit_config", target="opensnitch", values={"LogLevel": level})
    with pytest.raises(helper.Refused, match="aren't allowed"):
        call("edit_config", target="opensnitch", values={"Server": "x"})


def test_log_emptied_and_rotated_copies_deleted(tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path, files={
        "/var/log/opensnitchd.log": "Saved new rule: deny if dest.host is 'example.org'\n",
        "/var/log/opensnitchd.log.1": "x", "/var/log/opensnitchd.log.2.gz": "x", "/var/log/syslog": "keep"}), system,
        monkeypatch)
    os.symlink("/etc/shadow", host.root / "var/log/opensnitchd.log.3")
    r = call("clear_opensnitch_log")
    log = host.root / "var/log"
    assert r["emptied"] == 1 and r["deleted"] == 2 and (log / "opensnitchd.log").read_text() == ""
    assert sorted(p.name for p in log.iterdir()) == ["opensnitchd.log", "opensnitchd.log.3", "syslog"]
    assert r["ran"] == [helper._opensnitch_log_command()]


# ------------------------------------------------------------------ the window's settings, one key at a time

def test_qsettings_set():
    text = "[global]\ndefault_action=0\ndefault_timeout=30\n\n[statsDialog]\ngeometry=@ByteArray(x)\n"
    assert ini.qsettings_set(text, "global", "default_action", "1") == text.replace("default_action=0", "default_action=1")
    added = ini.qsettings_set(text, "global", "default_duration", "6")
    assert added == text.replace("default_timeout=30\n", "default_timeout=30\ndefault_duration=6\n")
    assert ini.qsettings_set(text, "database", "type", "0").endswith("geometry=@ByteArray(x)\n\n[database]\ntype=0\n")
    assert ini.qsettings_set(None, "global", "default_action", "1") == "[global]\ndefault_action=1\n"
    assert ini.qsettings_set("[global]\ndefault_action=1\n", "global", "default_action", None) == ""
    assert ini.qsettings_set(text, "global", "nothing", None) == text


# ------------------------------------------------------------------ the feature

def test_not_installed(cat, tmp_path):
    o = detect(cat, "net.outgoing_firewall", make_scan(make_host(tmp_path)))
    assert o.status is Status.WARN and o.summary.startswith("Not set up") and [n.kind for n in o.notes] == ["info"]


def test_installed_but_not_running(cat, tmp_path, system):
    system.units["opensnitchd.service"] = ["disabled", "inactive"]
    host = installed_host(tmp_path)
    host.runner.handlers["systemctl"] = system.handler
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    assert o.status is Status.WARN and "isn't running" in o.summary
    assert ev(o)["Version"] == "1.7.2" and ev(o)["Daemon"] == "not running, doesn't start at boot"


def test_allow_mode_is_warned_about_with_the_log(cat, tmp_path, system):
    # the two loopback rules upstream's package comes with (1.8.0) aren't the user's own
    host = installed_host(tmp_path, window=WINDOW_172, running=True,
                          rules=["deny-always-simple-www-secret-example-org", "000-allow-localhost", "000-allow-localhost6"])
    host.runner.handlers["systemctl"] = system.handler
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    assert o.status is Status.WARN and "allow mode" in o.summary
    assert [n.title for n in o.notes if n.kind == "risk"] == ["Allow mode", "Your answers are written to a log"]
    e = ev(o)
    # the window's 0 is deny; the daemon's allow applies while it isn't running: allow mode either way
    assert e["A question nobody answers"] == "deny" and e["A connection while the window isn't running"] == "allow"
    assert e["Rules of your own"] == 1 and e["Log level"] == 2
    assert "secret" not in json.dumps([x.to_dict() for x in o.evidence] + [n.to_dict() for n in o.notes])


def test_deny_mode_and_level_three_pass(cat, tmp_path, system):
    config = CONFIG_172.replace('"LogLevel": 2', '"LogLevel": 3').replace('"DefaultAction": "allow"', '"DefaultAction": "deny"')
    host = installed_host(tmp_path, config=config, window=WINDOW_172, running=True)
    host.runner.handlers["systemctl"] = system.handler
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    assert o.status is Status.PASS and not [n for n in o.notes if n.kind == "risk"]


def test_window_allow_written_as_text_is_deny(cat, tmp_path, system):
    """1.5.8 writes "allow" on its first start, then reads it as a number, fails and takes 0 (tested with Qt)."""
    host = installed_host(tmp_path, window="[global]\ndefault_action=allow\n")
    host.runner.handlers["systemctl"] = system.handler
    assert ev(detect(cat, "net.outgoing_firewall", make_scan(host)))["A question nobody answers"] == "deny"


def test_connection_list_in_a_file_and_forwarded_logs(cat, tmp_path, system):
    window = WINDOW_172.replace("file=file::memory:", "file=/home/alice/os.db").replace("type=0", "type=1")
    config = CONFIG_172.replace('"LogFile"', '"Loggers": [{"Name": "syslog"}],\n        "LogFile"')
    host = installed_host(tmp_path, config=config, window=window)
    host.runner.handlers["systemctl"] = system.handler
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    titles = [n.title for n in o.notes if n.kind == "risk"]
    assert "Every connection is saved to a file" in titles and "Connections are sent to another log" in titles


# ------------------------------------------------------------------ the guide

def test_guide_on_a_machine_without_opensnitch(cat, tmp_path):
    g = guide(cat, make_host(tmp_path, files={"/etc/os-release": "ID=arch\n"}))
    assert step(g, "Install OpenSnitch").commands == ["sudo pacman -S opensnitch"]
    starter = step(g, "Start with rules").options[0].plan
    assert any("Install OpenSnitch first" in b for b in starter.blockers)
    assert all(o.plan.blockers for s in g.steps for o in s.options)


def test_starter_rules_and_allow_mode_applied_and_reverted(cat, tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path, window=WINDOW_172), system, monkeypatch)
    plan = step(guide(cat, host), "Start with rules").options[0].plan
    assert [a.kind for a in plan.actions] == ["root", "qsettings"] and not plan.blockers
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(plan, host, log)
    assert res.ok
    settings = host.home / ".config/opensnitch/settings.conf"
    assert "default_action=1\n" in settings.read_text() and "geometry=@ByteArray(x)" in settings.read_text()
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    assert ev(o)["The app's starter rules"] == "in place" and ev(o)["A question nobody answers"] == "allow"
    assert step(guide(cat, host), "Start with rules").done
    # the window rewrites the rest of its file as it runs: that doesn't stop the revert
    settings.write_text(settings.read_text().replace("geometry=@ByteArray(x)", "geometry=@ByteArray(y)"))
    assert all(r.ok for r in revert_entry(log.get(res.entry_id), host, log))
    assert not list((host.root / "etc/opensnitchd/rules").iterdir())
    assert settings.read_text() == WINDOW_172.replace("geometry=@ByteArray(x)", "geometry=@ByteArray(y)")


def test_window_settings_wait_until_it_is_closed(cat, tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path, window=WINDOW_172, running=True), system, monkeypatch)
    plan = step(guide(cat, host), "Start with rules").options[0].plan
    assert any(b.startswith("Close OpenSnitch's window first") for b in plan.blockers)


def test_deny_mode_waits_for_the_starter_rules(cat, tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path, window=WINDOW_172.replace("default_action=0", "default_action=1")), system,
                  monkeypatch)
    deny = step(guide(cat, host), "Deny mode").options[0].plan
    assert any(b.startswith("Add the starter rules first") for b in deny.blockers)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    assert apply_plan(step(guide(cat, host), "Start with rules").options[0].plan, host, log).ok
    deny = step(guide(cat, host), "Deny mode").options[0].plan
    assert not deny.blockers and [a.kind for a in deny.actions] == ["root", "qsettings"]
    assert apply_plan(deny, host, log).ok
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    assert o.status is Status.PASS and "deny mode" in o.summary and step(guide(cat, host), "Deny mode").done


def test_a_vpn_installed_since_holds_deny_mode_back(cat, tmp_path, system, monkeypatch):
    # tested with Mullvad VPN: deny mode without a rule for its service (and the kernel's WireGuard tunnel) left the
    # computer offline, its kill switch blocking while it retried
    host = rooted(installed_host(tmp_path, window=WINDOW_172.replace("default_action=0", "default_action=1")), system,
                  monkeypatch)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    assert apply_plan(step(guide(cat, host), "Start with rules").options[0].plan, host, log).ok
    (host.root / "usr/bin/mullvad-daemon").write_text("")
    g = guide(cat, host)
    assert any(b.startswith("Bring the starter rules up to date first") for b in step(g, "Deny mode").options[0].plan.blockers)
    assert "VPN (Mullvad VPN's service): /usr/bin/mullvad-daemon" in dict(step(g, "Start with rules").parts)[
        "Allowed, by program (found on this computer)"]
    assert apply_plan(step(g, "Start with rules").options[0].plan, host, log).ok
    allow = json.loads((host.root / "etc/opensnitchd/rules/000-daprivacyscanner-allow-system.json").read_text())
    assert "|/usr/bin/mullvad-daemon|Kernel connection)$" in allow["operator"]["data"]
    assert not step(guide(cat, host), "Deny mode").options[0].plan.blockers


def test_log_level_step_and_the_old_log(cat, tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path, files={"/var/log/opensnitchd.log": "Added new rule: deny if ...\n"}), system,
                  monkeypatch)
    g = guide(cat, host)
    level = step(g, "What OpenSnitch keeps")
    assert "log level is 2 (important)" in level.text and level.commands[0] == "sudoedit /etc/opensnitchd/default-config.json"
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(level.options[0].plan, host, log)
    assert res.ok and '"LogLevel": 3,' in (host.root / "etc/opensnitchd/default-config.json").read_text()
    clear = step(guide(cat, host), "Delete what the log").options[0].plan
    assert clear.irreversible and apply_plan(clear, host, log, confirmed_irreversible=True).ok
    g = guide(cat, host)
    assert step(g, "What OpenSnitch keeps").done and step(g, "Delete what the log").done
    assert all(r.ok for r in revert_entry(log.get(res.entry_id), host, log))
    assert '"LogLevel": 2,' in (host.root / "etc/opensnitchd/default-config.json").read_text()


def test_connectivity_checks_blocked_only_when_chosen(cat, tmp_path, system, monkeypatch):
    host = rooted(installed_host(tmp_path), system, monkeypatch)
    conn = step(guide(cat, host), "Connectivity checks")
    assert not conn.options[0].recommended and any("limited connectivity" in x for x in conn.options[0].plan.side_effects)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    assert apply_plan(conn.options[0].plan, host, log).ok
    assert (host.root / "etc/opensnitchd/rules/000-daprivacyscanner-deny-connectivity-checks.json").is_file()
    assert step(guide(cat, host), "Connectivity checks").done
    o = detect(cat, "net.outgoing_firewall", make_scan(host))
    assert ev(o)["Connectivity checks"] == "blocked"
