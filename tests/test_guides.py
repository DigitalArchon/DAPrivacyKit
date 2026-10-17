"""Guided fixes: every guided check has a guide that builds without changing anything, and the
options it offers apply and revert from the undo log (root ones through the real helper code,
in this process, against the fixture tree)."""

import json
import os

import pytest

from daprivacyscanner import helper, network
from daprivacyscanner.catalogue import load as load_catalogue
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.guides import GUIDES
from daprivacyscanner.context import ContextValue
from daprivacyscanner.fix import apply_plan, revert_entry
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Evidence, Outcome, Status
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.undo import UndoLog

from conftest import make_host, make_scan, sample
from fakes import FakeBluetoothctl, FakeGSettings, FakeKwriteconfig, FakeNmcli, FakeSystem
from test_checks_telemetry_browser import firefox, png, pref


@pytest.fixture
def system(monkeypatch):
    """A root helper on the fixture tree; returns the fake systemctl/ufw shared by app and helper."""
    s = FakeSystem()
    monkeypatch.setattr(helper, "RUN", s)
    return s


def rooted(host, system, monkeypatch):
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    host.privileged = FakePrivileged()
    host.runner.handlers["systemctl"] = system.handler
    return host


def build(cat, host, check_id, **scan_kw):
    check = load_all()[check_id](cat[check_id])
    scan = make_scan(host, **scan_kw)
    outcome = check.detect(scan)
    assert outcome.status in (Status.FAIL, Status.WARN), outcome.summary
    return check.plan_guide(scan, outcome)


def options(guide):
    return {o.label: o.plan for s in guide.steps for o in s.options}


def apply(host, plan):
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(plan, host, log, confirmed_irreversible=True)
    assert res.ok, res.error
    return log, res


def revert(host, log, res, force=False):
    results = revert_entry(log.get(res.entry_id), host, log, force)
    assert all(r.ok for r in results), [r.message for r in results]
    return results


# ------------------------------------------------------------------ every guide

def test_every_guided_check_has_a_guide(cat):
    assert {s.id for s in cat if s.tier.value in ("guided", "feature")} <= set(GUIDES)
    assert all(load_all()[i].supports_fix for i in GUIDES)
    # the rest are advice checks' How to… guides: they explain, and never offer changes
    assert all(cat[i].tier.value == "advice" for i in set(GUIDES) - {s.id for s in cat if s.tier.value in ("guided", "feature")})


ADVICE_GUIDES = sorted(i for i in GUIDES if load_catalogue()[i].tier.value == "advice")


@pytest.mark.parametrize("check_id", ADVICE_GUIDES)
def test_advice_guides_offer_no_changes(cat, tmp_path, check_id):
    check = load_all()[check_id](cat[check_id])
    g = check.plan_guide(make_scan(make_host(tmp_path)), Outcome(Status.FAIL, "x"))
    assert not g.plans and g.steps


def test_advice_check_offers_how_to(cat, tmp_path):
    """A failing advice check with a guide says so (how_to), is never fixable, and plan_fix gives its guide."""
    from daprivacyscanner.runner import Runner
    host = make_host(tmp_path, files={"/etc/os-release": "ID=ubuntu\n"})
    host.runner.handlers["lsblk"] = lambda argv: CommandResult(argv, 0, sample("lsblk/mint-22-ext4-plain.json"))
    result, plan = Runner(cat, host).plan_fix("enc.fde_missing")
    assert result.status is Status.FAIL and result.how_to and not result.fixable
    assert plan.advice and "Use LVM and encryption" in plan.steps[1].text


@pytest.mark.parametrize("check_id", sorted(GUIDES))
def test_every_guide_builds_on_a_bare_machine(cat, tmp_path, check_id):
    """With nothing installed and a bare failing outcome: no crash, and building changes nothing."""
    host = make_host(tmp_path)
    before = sorted(p for p in tmp_path.rglob("*"))
    check = load_all()[check_id](cat[check_id])
    g = check.plan_guide(make_scan(host), Outcome(Status.FAIL, "x"))
    assert g.check_id == check_id and g.title
    json.dumps(g.to_dict())
    assert g.dry_run().startswith(f"Guide for {check_id}")
    assert sorted(p for p in tmp_path.rglob("*")) == before
    # developer notes never reach the user
    assert "VERIFY" not in g.intro and not any("VERIFY" in st.text for st in g.steps)


def _advice(cat, host, check_id, outcome=None):
    check = load_all()[check_id](cat[check_id])
    return check.plan_guide(make_scan(host), outcome or Outcome(Status.FAIL, "x"))


def test_kernel_option_with_limine(cat, tmp_path):
    """limine-entry-tool reads /etc/default/limine last: a plain "=" there replaces what a drop-in
    adds, so the option goes on that line instead."""
    files = {"/usr/bin/limine-update": "", "/etc/os-release": "ID=cachyos\nID_LIKE=arch\n"}
    host = make_host(tmp_path, files={**files, "/etc/default/limine": 'KERNEL_CMDLINE[default]+="quiet rw"\n'})
    cmds = _advice(cat, host, "kern.init_on_free").steps[0].commands
    assert "KERNEL_CMDLINE[default]+=init_on_free=1" in cmds[1] and cmds[-1] == "sudo limine-update"
    host = make_host(tmp_path / "b", files={**files, "/etc/default/limine": 'KERNEL_CMDLINE[default]="quiet rw"\n'})
    step = _advice(cat, host, "kern.init_on_free").steps[0]
    assert step.commands == ["sudoedit /etc/default/limine", "sudo limine-update"] and "inside its quotes" in step.text


def test_secure_boot_with_limine_enrols_its_config(cat, tmp_path):
    host = make_host(tmp_path, files={"/usr/bin/limine-update": "", "/usr/bin/sbctl-batch-sign": "",
                                      "/etc/os-release": "ID=cachyos\nID_LIKE=arch\n"})
    g = _advice(cat, host, "enc.boot_no_secureboot")
    cmds = g.steps[0].commands
    assert "sudo limine-enroll-config" in cmds and "sudo sbctl-batch-sign" in cmds and "sudo pacman -S sbctl" in cmds
    assert "Secure Boot" in g.intro and not any(st.done for st in g.steps)


def test_encrypted_dns_without_resolved(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 192.168.1.1\n"})
    host.runner.handlers["systemctl"] = lambda argv: CommandResult(argv, 0, "loaded\n")
    prof = firefox(host.home)
    g = build(cat, host, "net.dns_unencrypted")
    assert "sudo systemctl enable --now systemd-resolved" in g.steps[0].commands
    log, res = apply(host, options(g)[f"Use DNS over HTTPS (Quad9) in Firefox: Firefox profile {prof.name}"])
    prefs = (prof / "prefs.js").read_text()
    assert 'user_pref("network.trr.mode", 2);' in prefs and "dns.quad9.net" in prefs
    revert(host, log, res)


def test_other_exposed_services_named_by_their_unit(cat, tmp_path):
    ss = ('tcp LISTEN 0 511 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=4242,fd=3))\n'
          'tcp LISTEN 0 511 0.0.0.0:8443 0.0.0.0:*\n'
          'tcp LISTEN 0 511 0.0.0.0:8001 0.0.0.0:* users:(("python3",pid=4343,fd=3))\n')
    host = make_host(tmp_path, files={
        "/proc/4242/cgroup": "0::/user.slice/user-1000.slice/user@1000.service/app.slice/devserver.service\n",
        "/proc/4343/cgroup": "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.scope\n"})
    g = build(cat, host, "net.exposed_services", listeners=network.parse_ss(ss),
              exposed_services=ContextValue("exposed_services", True, [], ""))
    steps = {st.title: st for st in g.steps}
    assert steps["Port 3000/tcp (node)"].commands == ["systemctl --user disable --now devserver.service"]
    assert "program you started" in steps["Port 8001/tcp (python3)"].text
    assert steps["Port 8443/tcp"].commands[0] == "sudo ss -ltnp 'sport = :8443'"


# ------------------------------------------------------------------ user-level options

def test_home_permissions(cat, tmp_path):
    host = make_host(tmp_path)
    host.home.chmod(0o755)
    g = build(cat, host, "auth.home_world_readable")
    log, res = apply(host, options(g)["Only you, and members of your own group (750)"])
    assert host.home.stat().st_mode & 0o777 == 0o750
    revert(host, log, res)
    assert host.home.stat().st_mode & 0o777 == 0o755


def test_shell_history_lines_removed_and_ignorespace_added(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".bash_history": "ls\nexport GITHUB_TOKEN=ghp_" + "a" * 36 + "\ncd /tmp\nmysql -u root -phunter22\n",
        ".bashrc": "alias ll='ls -l'\n",
        ".local/share/fish/fish_history": "- cmd: echo hi\n  when: 1\n- cmd: curl -u bob:s3cret https://x\n  when: 2\n"
                                          "  paths:\n    - x\n- cmd: ls\n  when: 3\n"})
    g = build(cat, host, "auth.shell_history_secrets")
    log, res = apply(host, options(g)["Remove them"])
    assert (host.home / ".bash_history").read_text() == "ls\ncd /tmp\n"
    assert (host.home / ".local/share/fish/fish_history").read_text() == "- cmd: echo hi\n  when: 1\n- cmd: ls\n  when: 3\n"
    assert "ghp_" not in log.file.read_text()
    log2, res2 = apply(host, options(g)["Turn it on"])
    assert "HISTCONTROL=ignoreboth" in (host.home / ".bashrc").read_text()
    revert(host, log2, res2)
    assert (host.home / ".bashrc").read_text() == "alias ll='ls -l'\n"


def bt_host(tmp_path, bt):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/sys/class/bluetooth/hci0/uevent": ""},
                     commands={"systemctl is-active bluetooth": "active\n"})
    host.runner.handlers["bluetoothctl"] = bt
    return host


def test_bluetooth_discoverable_and_named(cat, tmp_path):
    bt = FakeBluetoothctl(discoverable="yes", alias="alice-laptop", name="alice-laptop")
    host = bt_host(tmp_path, bt)
    g = build(cat, host, "net.bluetooth")
    log, res = apply(host, options(g)["Turn off discoverable mode and use a generic name"])
    assert bt.state["Discoverable"] == "no" and bt.state["Alias"] == "Computer" and bt.state["Powered"] == "yes"
    assert "alice" not in UndoLog.summary(log.entries()[0])["steps"][0]["text"]   # kept for revert, not shown
    revert(host, log, res)
    assert bt.state["Discoverable"] == "yes" and bt.state["Alias"] == "alice-laptop"


def test_bluetooth_power_off_is_a_separate_step(cat, tmp_path):
    bt = FakeBluetoothctl()
    bt.state["Discoverable"] = "yes"                       # being on alone isn't a finding
    host = bt_host(tmp_path, bt)
    g = build(cat, host, "net.bluetooth")
    assert not g.steps[0].done and "disconnect" in " ".join(g.steps[1].options[0].plan.side_effects)
    log, res = apply(host, options(g)["Turn Bluetooth off now"])
    assert bt.state["Powered"] == "no"
    revert(host, log, res)
    assert bt.state["Powered"] == "yes"


def test_chromium_basic_store_flag_removed(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/brave-flags.conf": "--ozone-platform=wayland\n--password-store=basic\n"},
                     files={"/usr/share/applications/google-chrome.desktop":
                            "[Desktop Entry]\nExec=/usr/bin/google-chrome-stable --password-store=basic %U\n"})
    g = build(cat, host, "auth.chromium_basic_store")
    log, res = apply(host, options(g)["Remove the flag"])
    assert (host.home / ".config/brave-flags.conf").read_text() == "--ozone-platform=wayland\n\n"
    local = host.home / ".local/share/applications/google-chrome.desktop"
    assert "Exec=/usr/bin/google-chrome-stable %U" in local.read_text()
    revert(host, log, res)
    assert "--password-store=basic" in (host.home / ".config/brave-flags.conf").read_text() and not local.exists()


def test_plaintext_credentials_chmod(cat, tmp_path):
    host = make_host(tmp_path, home_files={".git-credentials": "https://bob:tok@github.com\n"})
    (host.home / ".git-credentials").chmod(0o644)
    g = build(cat, host, "auth.plaintext_credentials")
    assert any(s.title.startswith("Git") for s in g.steps)
    log, res = apply(host, options(g)["Restrict to you (chmod 600)"])
    assert (host.home / ".git-credentials").stat().st_mode & 0o777 == 0o600
    revert(host, log, res)
    assert (host.home / ".git-credentials").stat().st_mode & 0o777 == 0o644


def test_firefox_prefs_set_while_closed_and_reverted_alone(cat, tmp_path):
    host = make_host(tmp_path)
    prof = firefox(host.home, pref("browser.startup.page", 3))
    g = build(cat, host, "br.tracking_protection")
    [label] = [k for k in options(g) if k.startswith("Strict")]
    log, res = apply(host, options(g)[label])
    assert '"browser.contentblocking.category", "strict"' in (prof / "prefs.js").read_text()
    (prof / "prefs.js").write_text((prof / "prefs.js").read_text() + pref("browser.zoom", 1))   # Firefox ran since
    revert(host, log, res)
    text = (prof / "prefs.js").read_text()
    assert "contentblocking" not in text and "browser.zoom" in text and "browser.startup.page" in text


def test_firefox_options_blocked_while_it_runs(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home)
    (host.root / "proc/4242").mkdir(parents=True)
    (host.root / "proc/4242/comm").write_text("firefox\n")
    g = build(cat, host, "br.disk_cache")
    plan = next(p for k, p in options(g).items() if k.startswith("Keep the cache"))
    assert plan.blockers and "Close Firefox" in plan.blockers[0]


def test_history_retention_two_choices(cat, tmp_path):
    host = make_host(tmp_path)
    prof = firefox(host.home)
    g = build(cat, host, "br.history_retention")
    labels = list(options(g))
    assert len(labels) == 2 and labels[0].startswith("Clear history, cookies")
    apply(host, options(g)[labels[1]])
    assert '"privacy.clearOnShutdown_v2.cookiesAndStorage", false' in (prof / "prefs.js").read_text()
    # history is cleared at exit (cookies kept on purpose), so the profile no longer keeps it
    assert build_status(cat, host, "br.history_retention") is Status.PASS


def test_firefox_blocker_names_the_program_that_is_running(cat, tmp_path):
    """Thunderbird running doesn't block Firefox's options, and the blocker names what to close."""
    host = make_host(tmp_path)
    firefox(host.home)
    (host.root / "proc/4242").mkdir(parents=True)
    (host.root / "proc/4242/comm").write_text("thunderbird\n")
    g = build(cat, host, "br.disk_cache")
    plan = next(p for k, p in options(g).items() if k.startswith("Keep the cache"))
    assert not plan.blockers
    # each profile is held up by its own program only (review of 2026-10-17): LibreWolf doesn't rewrite Firefox's prefs
    (host.root / "proc/4242/comm").write_text("librewolf\n")
    g = build(cat, host, "br.disk_cache")
    plan = next(p for k, p in options(g).items() if k.startswith("Keep the cache"))
    assert not plan.blockers
    (host.root / "proc/4242/comm").write_text("firefox\n")
    g = build(cat, host, "br.disk_cache")
    plan = next(p for k, p in options(g).items() if k.startswith("Keep the cache"))
    assert plan.blockers == ["Close Firefox first: it rewrites its settings as it exits."]


def build_status(cat, host, check_id):
    return load_all()[check_id](cat[check_id]).detect(make_scan(host)).status


def test_ipv6_privacy_default_for_networks_joined_later(cat, tmp_path, system, monkeypatch):
    """The kernel's default is off: a network joined later wouldn't use privacy addresses. The fix writes
    NetworkManager's default (root) and changes only the connections that set their own value."""
    from test_fixes import nm_host
    host, nm = nm_host(tmp_path)
    host = rooted(host, system, monkeypatch)
    host.runner.outputs[("NetworkManager", "--print-config")] = CommandResult((), 0, "[main]\n")
    (host.root / "proc/sys/net/ipv6/conf/default").mkdir(parents=True)
    (host.root / "proc/sys/net/ipv6/conf/default/use_tempaddr").write_text("0\n")
    (host.root / "proc/sys/net/ipv6/conf/enp1s0/use_tempaddr").write_text("2\n")
    o = build_status_outcome(cat, host, "net.ipv6_privacy")
    assert o.status is Status.FAIL and "networks joined from now on won't" in o.summary
    check = load_all()["net.ipv6_privacy"](cat["net.ipv6_privacy"])
    scan = make_scan(host)
    plan = check.plan_fix(scan, check.detect(scan))
    assert plan.needs_root and [a.describe() for a in plan.actions][0].startswith(
        "Write /etc/NetworkManager/conf.d/99-daprivacyscanner-ipv6-privacy.conf")
    assert sorted(a.name for a in plan.actions[1:]) == ["Wired"]                     # Home takes the default
    log, res = apply(host, plan)
    conf = host.root / "etc/NetworkManager/conf.d/99-daprivacyscanner-ipv6-privacy.conf"
    assert "[connection]\nipv6.ip6-privacy=2" in conf.read_text()
    host.runner.outputs[("NetworkManager", "--print-config")] = CommandResult((), 0, conf.read_text())
    assert build_status(cat, host, "net.ipv6_privacy") is Status.PASS
    revert(host, log, res)
    assert not conf.exists() and nm.connections["u3"]["ipv6.ip6-privacy"] == "0"


def build_status_outcome(cat, host, check_id):
    return load_all()[check_id](cat[check_id]).detect(make_scan(host))


def test_hostname_default_for_networks_joined_later(cat, tmp_path, system, monkeypatch):
    """NetworkManager 1.52+ (a connection that doesn't set it shows -1): one default covers every network, those
    joined later included. Older ones (yes/no only) have none: each saved connection is changed, and the guide says
    a network joined later sends it again."""
    for new in (True, False):
        nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home",
                               "ipv4.dhcp-send-hostname": "-1" if new else "yes", "ipv6.dhcp-send-hostname": "-1" if new else "yes"},
                        "u2": {"type": "802-3-ethernet", "connection.id": "Wired",
                               "ipv4.dhcp-send-hostname": "yes", "ipv6.dhcp-send-hostname": "-1" if new else "yes"}})
        host = rooted(make_host(tmp_path / str(new), files={
            "/proc/sys/kernel/hostname": "alices-laptop\n",
            "/etc/passwd": "alice:x:1000:1000:Alice Smith:/home/alice:/bin/bash\n"}, env={"USER": "alice"}),
            system, monkeypatch)
        host.runner.handlers["nmcli"] = nm
        host.runner.outputs[("NetworkManager", "--print-config")] = CommandResult((), 0, "[main]\n")
        o = build_status_outcome(cat, host, "net.hostname_broadcast")
        assert o.status is Status.FAIL and ev_of(o)["Networks joined from now on"].startswith("send the hostname")
        g = build(cat, host, "net.hostname_broadcast")
        plan = options(g)["Stop sending it"]
        changed = [(a.name, a.prop) for a in plan.actions if hasattr(a, "prop")]
        if new:
            assert plan.actions[0].describe().startswith("Write /etc/NetworkManager/conf.d/99-daprivacyscanner-hostname")
            assert changed == [("Wired", "ipv4.dhcp-send-hostname")]
            log, res = apply(host, plan)
            conf = host.root / "etc/NetworkManager/conf.d/99-daprivacyscanner-hostname.conf"
            host.runner.outputs[("NetworkManager", "--print-config")] = CommandResult((), 0, conf.read_text())
            o = build_status_outcome(cat, host, "net.hostname_broadcast")
            assert o.status is Status.PASS and "Networks joined from now on" not in ev_of(o)
        else:
            assert not any(a.describe().startswith("Write") for a in plan.actions) and len(changed) == 4
            assert any("before 1.52" in e for e in plan.side_effects)


def ev_of(o):
    return {e.label: e.value for e in o.evidence}


def test_hostname_not_sent_over_dhcp(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n",
                                      "/etc/passwd": "alice:x:1000:1000:Alice Smith:/home/alice:/bin/bash\n"},
                     env={"USER": "alice"})
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home", "ipv4.dhcp-send-hostname": "yes",
                           "ipv6.dhcp-send-hostname": "yes"}})
    host.runner.handlers["nmcli"] = nm
    g = build(cat, host, "net.hostname_broadcast")
    log, res = apply(host, options(g)["Stop sending it"])
    assert nm.connections["u1"]["ipv4.dhcp-send-hostname"] == "no"
    # a NetworkManager before 1.52 has no default for it: a network joined later sends it again
    o = build_status_outcome(cat, host, "net.hostname_broadcast")
    assert o.status is Status.FAIL and ev_of(o)["Announced via"] == "DHCP (networks joined from now on)"
    revert(host, log, res)
    assert nm.connections["u1"]["ipv6.dhcp-send-hostname"] == "yes"


def test_flatpak_override_is_backed_up_and_reverted(cat, tmp_path):
    host = make_host(tmp_path)
    overrides = host.home / ".local/share/flatpak/overrides/org.x.App"

    def flatpak(argv):
        if argv[1:3] == ("list", "--app"):
            return CommandResult(argv, 0, "org.x.App\n")
        if argv[1:3] == ("info", "--show-permissions"):
            return CommandResult(argv, 0, "[Context]\nfilesystems=home;xdg-download:ro;\n")
        if argv[1:3] == ("override", "--user"):
            overrides.parent.mkdir(parents=True, exist_ok=True)
            overrides.write_text("[Context]\nfilesystems=!home;\n")
            return CommandResult(argv, 0, "")
        return None
    host.runner.handlers["flatpak"] = flatpak
    g = build(cat, host, "sbx.flatpak_broad_perms")
    plan = options(g)["Take away home"]
    assert plan.actions[0].argv == ["flatpak", "override", "--user", "--nofilesystem=home", "org.x.App"]
    log, res = apply(host, plan)
    assert overrides.exists()
    revert(host, log, res)
    assert not overrides.exists()


def test_leftover_flatpak_folder_removed(cat, tmp_path):
    host = make_host(tmp_path, home_files={".var/app/org.gone.App/config/x.conf": "1",
                                           ".var/app/org.gone.App/data/db": "2", ".var/app/org.kept.App/config/y": "3"})
    os.symlink("/etc/passwd", host.home / ".var/app/org.gone.App/link")
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 0, "org.kept.App\n")
    g = build(cat, host, "sbx.leftover_data")
    apply(host, options(g)["Delete ~/.var/app/org.gone.App"])
    assert not (host.home / ".var/app/org.gone.App").exists() and (host.home / ".var/app/org.kept.App/config/y").exists()


def test_baloo_off_and_index_deleted(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/baloo/index": "x" * 100, ".local/share/baloo/index-lock": ""})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    calls = []
    host.runner.handlers["balooctl6"] = lambda argv: calls.append(argv) or CommandResult(argv, 0, "")
    g = build(cat, host, "desk.indexers", desktop=("kde",), plasma_major=6, fde=ContextValue("fde", "none", [], ""))
    opts = options(g)
    assert g.steps[0].options[0].recommended and g.steps[0].options[0].label == "Turn indexing off and delete the index"
    log, res = apply(host, opts["Index file names only, and rebuild the index without contents"])
    assert "only basic indexing=true" in (host.home / ".config/baloofilerc").read_text()
    # not `disable` (it turns indexing off outside the plan's record), and `enable` detached from the app's output,
    # here without the systemd unit (the review of 2026-10-17: enable held the app's pipe until its timeout)
    assert not (host.home / ".local/share/baloo/index").exists() and calls == []
    assert ("sh", "-c", 'exec "$0" enable </dev/null >/dev/null 2>&1', "balooctl6") in host.runner.calls
    revert(host, log, res)
    assert not (host.home / ".config/baloofilerc").exists()                   # the fix made it: it goes
    (host.home / ".local/share/baloo/index").write_text("x" * 100)
    calls.clear()
    log, res = apply(host, opts["Turn indexing off and delete the index"])
    assert "Indexing-Enabled=false" in (host.home / ".config/baloofilerc").read_text()
    assert not (host.home / ".local/share/baloo/index").exists() and [c[1] for c in calls] == ["disable"]
    revert(host, log, res)
    assert not (host.home / ".config/baloofilerc").exists()                   # the fix made it: it goes


def test_localsearch_no_folders_and_database_deleted(cat, tmp_path):
    host = make_host(tmp_path, home_files={".cache/localsearch/meta.db": "x" * 100},
                     commands={"localsearch status": "Currently indexed: 10 files\n"})
    calls = []
    host.runner.handlers["systemctl"] = lambda argv: calls.append(list(argv[2:])) or CommandResult(argv, 0, "active\n")
    schema = "org.freedesktop.Tracker3.Miner.Files"
    gs = FakeGSettings({(schema, "index-recursive-directories"): "['&DOCUMENTS']",
                        (schema, "index-single-directories"): "['$HOME']", (schema, "index-removable-devices"): "false"})
    host.runner.handlers["gsettings"] = gs
    g = build(cat, host, "desk.indexers", gnome_major=47, fde=ContextValue("fde", "full", [], ""))
    plan = options(g)["Index no folders and delete its database"]
    kinds = [type(a).__name__ for a in plan.actions]
    assert kinds.count("GSettingsSet") == 2 and "DeleteFiles" in kinds        # removable drives: already off
    log, res = apply(host, plan)
    assert gs.values[(schema, "index-recursive-directories")] == "@as []" and not (host.home / ".cache/localsearch/meta.db").exists()
    assert ["stop", "localsearch-3.service"] in calls and ["start", "localsearch-3.service"] in calls
    revert(host, log, res)
    assert gs.values[(schema, "index-recursive-directories")] == "['&DOCUMENTS']"


def test_editor_residue_skips_running_editors(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/state/nvim/swap/%home%alice%notes.md.swp": "s",
                                           ".vim/undo/%home%alice%a.txt": "u", "Documents/report.txt~": "b"})
    (host.root / "proc/7").mkdir(parents=True)
    (host.root / "proc/7/comm").write_text("nvim\n")
    g = build(cat, host, "app.editor_residue")
    apply(host, options(g)["Delete them"])
    assert (host.home / ".local/state/nvim/swap/%home%alice%notes.md.swp").exists()
    assert not (host.home / ".vim/undo/%home%alice%a.txt").exists() and (host.home / "Documents/report.txt~").exists()
    apply(host, options(g)["Delete 1 backup file"])            # one file, said so (review of 2026-10-17)
    assert not (host.home / "Documents/report.txt~").exists()


def test_remote_desktop_off_warns_and_is_blocked_from_inside_the_session(cat, tmp_path, system, monkeypatch):
    system.units["xrdp.service"] = ["enabled", "active"]
    host = rooted(make_host(tmp_path, files={"/proc/9/comm": "xrdp\n"}), system, monkeypatch)
    g = build(cat, host, "auth.remote_desktop", listeners=[])
    plan = options(g)["Stop and disable xrdp"]
    assert not plan.blockers and any("you included if you are using this machine remotely" in s for s in plan.side_effects)
    host = rooted(make_host(tmp_path / "r", files={"/proc/9/comm": "xrdp\n"}, env={"XRDP_SESSION": "1"}), system, monkeypatch)
    g = build(cat, host, "auth.remote_desktop", listeners=[])
    assert "over xrdp now" in options(g)["Stop and disable xrdp"].blockers[0]
    # the same option in the exposed-services guide, and SSH over an SSH connection
    system.units["ssh.service"] = ["enabled", "active"]
    host = rooted(make_host(tmp_path / "s", env={"XRDP_SESSION": "1", "SSH_CONNECTION": "10.0.0.2 5 10.0.0.1 22"}),
                  system, monkeypatch)
    g = build(cat, host, "net.exposed_services", listeners=network.parse_ss(sample("ss/mint-22.txt")),
              exposed_services=ContextValue("exposed_services", True, [], ""))
    opts = options(g)
    assert "over xrdp now" in opts["Turn off Remote desktop"].blockers[0]
    assert "connected over SSH now" in opts["Turn off the SSH server"].blockers[0]


def test_gnome_remote_desktop_off(cat, tmp_path):
    host = make_host(tmp_path)
    gs = FakeGSettings({("org.gnome.desktop.remote-desktop.rdp", "enable"): "true",
                        ("org.gnome.desktop.remote-desktop.vnc", "enable"): "false"})
    host.runner.handlers["gsettings"] = gs
    host.runner.handlers["grdctl"] = lambda argv: CommandResult(argv, 0, "RDP:\n\tStatus: enabled\n")
    g = build(cat, host, "auth.remote_desktop", listeners=[])
    log, res = apply(host, options(g)["Turn off desktop sharing"])
    assert gs.values[("org.gnome.desktop.remote-desktop.rdp", "enable")] == "false"
    revert(host, log, res)
    assert gs.values[("org.gnome.desktop.remote-desktop.rdp", "enable")] == "true"


# ------------------------------------------------------------------ root options

def test_autologin_off_and_back(cat, tmp_path, system, monkeypatch):
    conf = "/etc/lightdm/lightdm.conf.d/70-linuxmint.conf"
    host = rooted(make_host(tmp_path, files={conf: "[Seat:*]\nautologin-user=alice\n"}), system, monkeypatch)
    av = ContextValue("autologin", True, [__import__("daprivacyscanner.model", fromlist=["Evidence"]).Evidence.val(
        "LightDM [Seat:*] autologin-user", "alice")], "")
    g = build(cat, host, "auth.autologin", autologin=av)
    log, res = apply(host, options(g)["Turn off automatic login"])
    assert (host.root / conf.lstrip("/")).read_text() == "[Seat:*]\n#autologin-user=alice\n"
    assert UndoLog.needs_root(log.get(res.entry_id))
    revert(host, log, res)
    assert (host.root / conf.lstrip("/")).read_text() == "[Seat:*]\nautologin-user=alice\n"


def test_root_step_without_the_helper_fails_cleanly(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/yum.repos.d/f.repo": "[f]\ncountme=1\n"})
    check = load_all()["tel.countme"](cat["tel.countme"])
    scan = make_scan(host)
    plan = check.plan_fix(scan, check.detect(scan))
    res = apply_plan(plan, host, UndoLog(host.home / "log"))
    assert not res.ok and "administrator access" in res.error


def test_journal_retention_and_vacuum(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/var/log/journal/x/system.journal": "j"}), system, monkeypatch)
    g = build(cat, host, "enc.journal_persistent")
    log, res = apply(host, options(g)["Keep two weeks"])
    assert build_status(cat, host, "enc.journal_persistent") is Status.PASS
    log2, res2 = apply(host, options(g)["Delete journal entries older than two weeks"])
    assert "120.0M freed" in log2.get(res2.entry_id)["records"][0]["text"]
    revert(host, log, res)
    assert build_status(cat, host, "enc.journal_persistent") is Status.FAIL


def test_journal_guide_turns_rsyslog_off_and_deletes_its_logs(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/var/log/journal/x/system.journal": "j", "/var/log/syslog": "s",
                                             "/var/log/messages-20261001.gz": "m", "/var/log/Xorg.0.log": "keep"}),
                  system, monkeypatch)
    system.units["rsyslog.service"] = ["enabled", "active"]
    g = build(cat, host, "enc.journal_persistent")
    apply(host, options(g)["Keep two weeks"])
    assert build_status(cat, host, "enc.journal_persistent") is Status.FAIL          # rsyslog still keeps a copy
    plan = options(g)["Turn off rsyslog and delete its text logs"]
    assert plan.actions[-1].commands() == [helper._syslog_command()]
    log, res = apply(host, plan)
    assert system.units["rsyslog.service"] == ["disabled", "inactive"]
    assert not (host.root / "var/log/syslog").exists() and (host.root / "var/log/Xorg.0.log").exists()
    assert build_status(cat, host, "enc.journal_persistent") is Status.PASS
    revert(host, log, res)
    assert system.units["rsyslog.service"] == ["enabled", "active"]


def test_firewall_prefers_the_one_the_machine_already_uses(cat, tmp_path, system, monkeypatch):
    """ufw and firewalld both installed: firewalld set to start (or running) is the one to turn
    on; otherwise ufw, with a warning to leave firewalld off."""
    system.units["firewalld.service"] = ["enabled", "inactive"]
    host = rooted(make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=no\n"}), system, monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=[])
    assert list(options(g)) == ["Start and enable firewalld"]
    assert any("ufw is installed too: leave it off" in s for s in g.steps[0].side_effects)
    system.units["firewalld.service"] = ["disabled", "inactive"]
    g = build(cat, host, "net.firewall_off", listeners=[])
    assert list(options(g)) == ["Turn on ufw"]
    assert any("firewalld is installed too, but off: leave it off" in s for s in options(g)["Turn on ufw"].side_effects)


def test_firewall_on_keeping_exposed_services(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/ufw/ufw.conf": "ENABLED=no\n"}), system, monkeypatch)
    g = build(cat, host, "net.firewall_off", listeners=network.parse_ss(sample("ss/mint-22.txt")))
    labels = list(options(g))
    assert labels[0] == "Turn on ufw" and "22/tcp" in labels[1] and "3389/tcp" in labels[1]
    log, res = apply(host, options(g)[labels[1]])
    assert system.ufw_active and system.ufw_rules == ["22/tcp", "3389/tcp"]
    revert(host, log, res)
    assert not system.ufw_active and system.ufw_rules == []


def test_ssh_keys_only_or_off(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"}),
                  system, monkeypatch)
    system.units = {"ssh.service": ["enabled", "active"], "ssh.socket": ["disabled", "inactive"]}
    exposed = ContextValue("exposed_services", True, [], "")
    g = build(cat, host, "net.exposed_services", listeners=network.parse_ss(sample("ss/mint-22.txt")),
              exposed_services=exposed)
    off = options(g)["Turn off the SSH server"]
    assert [a.args["unit"] for a in off.actions] == ["ssh.service"]          # the socket is already off
    log, res = apply(host, options(g)["Keep SSH, but only with keys"])
    assert "PasswordAuthentication no" in (host.root / "etc/ssh/sshd_config.d/10-daprivacyscanner.conf").read_text()
    revert(host, log, res)
    log, res = apply(host, off)
    assert system.units["ssh.service"] == ["disabled", "inactive"]
    revert(host, log, res)
    assert system.units["ssh.service"] == ["enabled", "active"]


def test_ptrace_now_and_at_boot(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/proc/sys/kernel/yama/ptrace_scope": "0\n"}), system, monkeypatch)
    g = build(cat, host, "kern.ptrace_scope")
    log, res = apply(host, options(g)["Set ptrace_scope to 1"])
    assert (host.root / "proc/sys/kernel/yama/ptrace_scope").read_text() == "1"
    assert (host.root / "etc/sysctl.d/60-daprivacyscanner.conf").read_text().endswith("kernel.yama.ptrace_scope = 1\n")
    revert(host, log, res)
    assert (host.root / "proc/sys/kernel/yama/ptrace_scope").read_text() == "0"
    assert not (host.root / "etc/sysctl.d/60-daprivacyscanner.conf").exists()


def test_coredumps_off_and_cleared(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={
        "/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n",
        "/var/lib/systemd/coredump/core.app.1000.b.1.zst": "core"}), system, monkeypatch)
    g = build(cat, host, "enc.coredumps_retained")
    log, res = apply(host, options(g)["Stop storing core dumps"])
    apply(host, options(g)["Delete existing core dumps and crash reports"])
    assert build_status(cat, host, "enc.coredumps_retained") is Status.PASS
    revert(host, log, res)


def test_apport_off(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/default/apport": "# comment\nenabled=1\n"}), system, monkeypatch)
    system.units = {"apport.service": ["enabled", "active"]}
    g = build(cat, host, "tel.crash_reporters", desktop=("x-cinnamon",))
    log, res = apply(host, options(g)["Turn off apport"])
    assert (host.root / "etc/default/apport").read_text() == "# comment\nenabled=0\n"
    assert system.units["apport.service"] == ["disabled", "inactive"]
    assert build_status(cat, host, "tel.crash_reporters") is Status.PASS
    revert(host, log, res)
    assert (host.root / "etc/default/apport").read_text() == "# comment\nenabled=1\n"


def test_cups_keeps_nothing(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/cups/cupsd.conf": "LogLevel warn\n"}, installed=["lpstat"]),
                  system, monkeypatch)
    g = build(cat, host, "app.cups_spool")
    log, res = apply(host, options(g)["Keep neither documents nor job history"])
    assert build_status(cat, host, "app.cups_spool") is Status.PASS
    revert(host, log, res)
    assert (host.root / "etc/cups/cupsd.conf").read_text() == "LogLevel warn\n"


def test_dns_over_tls(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"}), system, monkeypatch)
    host.runner.handlers["resolvectl"] = lambda argv: CommandResult(argv, 0, "Global\n  Protocols: -DNSOverTLS\n")
    g = build(cat, host, "net.dns_unencrypted")
    plan = options(g)["Encrypt DNS, using Quad9"]
    log, res = apply(host, plan)
    text = (host.root / "etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf").read_text()
    assert "DNSOverTLS=yes" in text and "9.9.9.9#dns.quad9.net" in text and "Domains=~." in text
    assert ["systemctl", "try-restart", "systemd-resolved.service"] in system.calls
    revert(host, log, res)


def test_browser_policies(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    firefox(host.home)
    from test_checks_telemetry_browser import chrome
    chrome(host.home, root=".config/BraveSoftware/Brave-Browser", local_state={"brave": {"p3a": {"enabled": True}}})
    g = build(cat, host, "tel.browser_telemetry")
    log, res = apply(host, options(g)["Turn off usage statistics: Brave, for every user (policy)"])
    assert json.loads((host.root / "etc/brave/policies/managed/daprivacyscanner.json").read_text()) == {
        "MetricsReportingEnabled": False, "BraveP3AEnabled": False, "BraveStatsPingEnabled": False}
    revert(host, log, res)
    log, res = apply(host, options(g)["Firefox, for every user (policy)"])
    assert json.loads((host.root / "etc/firefox/policies/policies.json").read_text())["policies"]["DisableTelemetry"]
    revert(host, log, res)


def test_hibernation_off(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    check = load_all()["enc.hibernate_unencrypted"](cat["enc.hibernate_unencrypted"])
    g = check.plan_guide(make_scan(host), Outcome(Status.FAIL, "x"))
    log, res = apply(host, options(g)["Turn hibernation off"])
    assert "AllowHibernation=no" in (host.root / "etc/systemd/sleep.conf.d/60-daprivacyscanner.conf").read_text()
    revert(host, log, res)


def test_tmp_mount_when_the_unit_exists(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    system.units = {"tmp.mount": ["disabled", "inactive"]}
    g = build(cat, host, "enc.tmp_on_disk")
    log, res = apply(host, options(g)["Enable tmp.mount"])
    assert system.units["tmp.mount"] == ["enabled", "inactive"]                # not mounted over a live /tmp
    revert(host, log, res)
    assert system.units["tmp.mount"] == ["disabled", "inactive"]


def test_connectivity_check_off(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, installed=["NetworkManager"]), system, monkeypatch)
    host.runner.outputs[("NetworkManager", "--print-config")] = CommandResult(
        (), 0, "[connectivity]\nuri=http://connectivity-check.ubuntu.com./\n")
    g = build(cat, host, "net.connectivity_check")
    log, res = apply(host, options(g)["Turn off the connectivity check"])
    assert (host.root / "etc/NetworkManager/conf.d/60-daprivacyscanner-connectivity.conf").read_text().endswith(
        "[connectivity]\nenabled=false\n")
    revert(host, log, res)


# ------------------------------------------------------------------ thumbnails: delete, or keep in memory

def thumbnail_home(tmp_path, **kw):
    host = make_host(tmp_path, home_files={"kept.jpg": "x"}, **kw)
    d = host.home / ".cache/thumbnails/normal"
    d.mkdir(parents=True)
    (d / "keep.png").write_bytes(png((host.home / "kept.jpg").as_uri()))
    (d / "gone.png").write_bytes(png((host.home / "deleted.jpg").as_uri()))
    (d / "usb.png").write_bytes(png("file:///media/alice/USB/x.jpg"))
    fail = d.parent / "fail/gnome-thumbnail-factory"                       # a "couldn't thumbnail" marker
    fail.mkdir(parents=True)
    (fail / "broken.png").write_bytes(png((host.home / "deleted.mov").as_uri()))
    return host, d


def test_thumbnails_step_one_deletes_only_the_leaky_ones(cat, tmp_path):
    host, d = thumbnail_home(tmp_path)
    g = build(cat, host, "desk.thumbnails", devices=[])
    opts = options(g)
    assert sorted(len(a.files) for a in opts["Delete every cached thumbnail"].actions) == [1, 3]   # fail/ apart
    log, res = apply(host, opts["Delete thumbnails of deleted files and of removable or encrypted drives"])
    assert sorted(p.name for p in d.iterdir()) == ["keep.png"]
    o = load_all()["desk.thumbnails"](cat["desk.thumbnails"]).detect(make_scan(host, devices=[]))
    assert o.status is Status.WARN and o.findings["thumbnails_on_disk_none_leaking"]      # nothing leaks; still on disk


def home_on_the_system(tmp_path, system, monkeypatch):
    """A host whose home is inside the fixture tree, so the app and the root helper (which works
    from the account's home, /home/alice) see the same folders; alice is this test's user."""
    from daprivacyscanner.host import Host

    base = make_host(tmp_path)
    home = base.root / "home/alice"
    host = Host(home=home, environ={"HOME": str(home)}, runner=base.runner, root=base.root, uid=os.geteuid())
    d = home / ".cache/thumbnails/normal"
    d.mkdir(parents=True)
    (d / "gone.png").write_bytes(png((home / "deleted.jpg").as_uri()))
    rooted(host, system, monkeypatch)
    monkeypatch.setattr(helper, "CALLER", (os.geteuid(), os.getegid(), "/home/alice"))
    return host, d


def thumbnails_check(cat):
    return load_all()["desk.thumbnails"](cat["desk.thumbnails"])


def test_thumbnails_kept_in_memory_by_a_mount_unit(cat, tmp_path, system, monkeypatch):
    host, d = home_on_the_system(tmp_path, system, monkeypatch)
    name = "home-alice-.cache-thumbnails.mount"
    g = build(cat, host, "desk.thumbnails", devices=[])
    step = g.steps[-1]
    assert step.title == "Keep the thumbnail cache in memory" and not step.done
    plan = step.options[0].plan
    assert plan.needs_root and [a.kind for a in plan.actions] == ["delete", "root"]      # deletions first
    assert plan.actions[0].root == d.parent
    assert plan.actions[1].args == {"size_mb": 200}                     # no path: the helper takes the user's own
    assert f"/etc/systemd/system/{name}" in plan.dry_run()
    log, res = apply(host, plan)
    assert d.parent.is_dir() and not any(d.parent.iterdir())                   # emptied and pruned, root kept
    unit = host.root / "etc/systemd/system" / name
    assert "Where=/home/alice/.cache/thumbnails" in unit.read_text() and not (host.root / "etc/fstab").exists()
    assert name in system.mounted
    # the check sees the mount, and the guide's last step is done
    (host.root / "proc").mkdir(exist_ok=True)
    (host.root / "proc/mounts").write_text("tmpfs /home/alice/.cache/thumbnails tmpfs rw,nosuid,nodev,noexec 0 0\n")
    scan = make_scan(host, devices=[])
    o = thumbnails_check(cat).detect(scan)
    assert o.status is Status.PASS and any("in memory" in n.title for n in o.notes)
    d.mkdir(parents=True)
    (d / "later.png").write_bytes(png((host.home / "deleted.jpg").as_uri()))
    o = thumbnails_check(cat).detect(make_scan(host, devices=[]))
    assert o.status is Status.PASS and "gone at the next reboot" in o.summary
    assert thumbnails_check(cat).plan_guide(scan, o).steps[-1].done
    revert(host, log, res)
    assert not unit.exists() and name not in system.mounted


def test_a_mount_unit_skipped_at_boot_is_explained(cat, tmp_path, system, monkeypatch):
    """The unit is there but systemd skipped it (~/.cache became a link, say): the check says
    so, and the guide doesn't offer to set it up a second time."""
    host, d = home_on_the_system(tmp_path, system, monkeypatch)
    name = "home-alice-.cache-thumbnails.mount"
    (host.root / "etc/systemd/system").mkdir(parents=True)
    (host.root / "etc/systemd/system" / name).write_text("[Mount]\n")
    host.runner.handlers["systemctl"] = lambda argv: CommandResult(tuple(argv), 0, "ConditionResult=no\nActiveState=inactive\n") \
        if argv[1] == "show" else CommandResult(tuple(argv), 0, "")
    o = thumbnails_check(cat).detect(make_scan(host, devices=[]))
    assert any(n.title == "The in-memory thumbnail cache was skipped at boot" for n in o.notes)
    # said in the step, not a blocked option (an Easy fix counted that as still to apply: review of 2026-10-17)
    step = build(cat, host, "desk.thumbnails", devices=[]).steps[-1]
    assert not step.options and "isn't mounted now" in step.text


def test_thumbnails_in_memory_only_for_the_usual_cache_folder(cat, tmp_path):
    host, d = thumbnail_home(tmp_path)
    other = tmp_path / "elsewhere"
    other.mkdir()
    host.environ["XDG_CACHE_HOME"] = str(other)
    (other / "thumbnails/normal").mkdir(parents=True)
    (other / "thumbnails/normal/gone.png").write_bytes(png((host.home / "deleted.jpg").as_uri()))
    g = build(cat, host, "desk.thumbnails", devices=[])
    assert not g.steps[-1].options and "set elsewhere" in g.steps[-1].text      # said, not a blocked option


# ------------------------------------------------------------------ KDE Connect and GSConnect

def test_kdeconnect_turned_off_for_the_user(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/77/comm": "kdeconnectd\n", "/etc/os-release": "ID=arch\n"},
                     home_files={".config/kdeconnect/trusted_devices": "[abc]\nname=Phone\n"})
    calls = []
    host.runner.handlers["pkill"] = lambda argv: (calls.append(argv), CommandResult(argv, 0, ""))[1]
    g = build(cat, host, "net.kdeconnect", desktop=("kde",))
    log, res = apply(host, options(g)["Turn KDE Connect off for you"])
    autostart = host.home / ".config/autostart/org.kde.kdeconnect.daemon.desktop"
    dbus = host.home / ".local/share/dbus-1/services/org.kde.kdeconnect.service"
    assert "Hidden=true" in autostart.read_text() and "Exec=/bin/false" in dbus.read_text()
    assert calls and calls[0][-1] == "kdeconnectd"
    revert(host, log, res)
    assert not autostart.exists() and not dbus.exists()
    remove = next(s for s in g.steps if s.title == "Or remove it for every account")
    assert remove.commands == ["sudo pacman -R kdeconnect", "pkill -TERM -x -u 1000 kdeconnectd"]
    assert "until that account logs out" in remove.text


def test_kdeconnect_removed_while_running_is_stopped(cat, tmp_path):
    """Removed, with the session's daemon still running from before: the guide only stops it (nothing starts it
    again), and doesn't offer to turn off or remove what is gone."""
    host = make_host(tmp_path, files={"/proc/77/comm": "kdeconnectd\n", "/etc/os-release": "ID=arch\n"},
                     links={"/proc/77/exe": "/usr/bin/kdeconnectd (deleted)"})
    calls = []
    host.runner.handlers["pkill"] = lambda argv: (calls.append(argv), CommandResult(argv, 0, ""))[1]
    g = build(cat, host, "net.kdeconnect", desktop=("kde",))
    assert [s.title for s in g.steps] == ["Stop the copy that is still running"]
    apply(host, options(g)["Stop it now"])
    assert calls == [("pkill", "-TERM", "-x", "-u", "1000", "kdeconnectd")]


def test_gsconnect_turned_off(cat, tmp_path):
    host = make_host(tmp_path)
    gs = FakeGSettings({("org.gnome.shell", "enabled-extensions"): "['gsconnect@andyholmes.github.io', 'other@x']",
                        ("org.gnome.shell", "disabled-extensions"): "@as []"})
    host.runner.handlers["gsettings"] = gs
    host.runner.handlers["gnome-extensions"] = lambda argv: CommandResult(argv, 0, "gsconnect@andyholmes.github.io\nother@x\n")
    g = build(cat, host, "net.kdeconnect")
    log, res = apply(host, options(g)["Turn the GSConnect extension off"])
    assert gs.values[("org.gnome.shell", "enabled-extensions")] == "['other@x']"
    assert gs.values[("org.gnome.shell", "disabled-extensions")] == "['gsconnect@andyholmes.github.io']"
    revert(host, log, res)
    assert "gsconnect" in gs.values[("org.gnome.shell", "enabled-extensions")]


# ------------------------------------------------------------------ umask

def test_umask_in_login_files(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/self/status": "Name:\tx\nUmask:\t0002\n",
                                      "/etc/passwd": "alice:x:1000:1000::/home/alice:/usr/bin/zsh\n"},
                     home_files={".bash_profile": "[[ -f ~/.bashrc ]] && . ~/.bashrc\n"}, env={"USER": "alice"})
    g = build(cat, host, "auth.umask")
    plan = options(g)["Set umask 027 in your login files"]
    assert [a.path.name for a in plan.actions] == [".profile", ".bash_profile", ".zprofile"]
    log, res = apply(host, plan)
    assert (host.home / ".bash_profile").read_text().startswith("[[ -f ~/.bashrc ]]")
    assert (host.home / ".zprofile").read_text().endswith("umask 027\n")
    g = build(cat, host, "auth.umask")                       # still failing: the session's is 0002 until next login
    assert g.steps[0].done and not g.steps[0].options
    revert(host, log, res)
    assert not (host.home / ".profile").exists() and "umask" not in (host.home / ".bash_profile").read_text()
    root = options(build(cat, host, "auth.umask", ))["Set umask 027 for your user manager"]
    assert root.actions[0].args == {"name": "user-umask", "settings": {"UMask": "0027"}}


# ------------------------------------------------------------------ LUKS key derivation

def _luks_host(tmp_path, dump, grub=None):
    files = {"/etc/default/grub": grub} if grub else {}
    host = make_host(tmp_path, files=files)
    host.privileged = FakePrivileged(luks={"/dev/nvme0n1p3": dump})
    return host


def test_luks_weak_kdf_commands_per_weak_keyslot(cat, tmp_path):
    from conftest import lsblk
    dump = sample("luksdump/luks2-tpm2-no-pin.txt").replace("  0: systemd-tpm2", "  0: something").replace(
        "\tKeyslot:    1", "\tKeyslot:    0")
    g = build(cat, _luks_host(tmp_path, dump), "enc.luks_weak_kdf", devices=lsblk("fedora-40-btrfs-luks.json"))
    cmds = [c for s in g.steps for c in s.commands]
    assert cmds[0].startswith("sudo cryptsetup luksHeaderBackup /dev/nvme0n1p3")
    assert cmds[1:] == ["sudo cryptsetup luksConvertKey /dev/nvme0n1p3 --key-slot 1 --pbkdf argon2id"]
    assert not g.plans                                              # commands only: it needs the passphrase


def test_luks_weak_kdf_leaves_token_keyslots_and_grub(cat, tmp_path):
    from conftest import lsblk
    dump = sample("luksdump/luks2-tpm2-no-pin.txt")
    o = load_all()["enc.luks_weak_kdf"](cat["enc.luks_weak_kdf"]).detect(
        make_scan(_luks_host(tmp_path / "a", dump), devices=lsblk("fedora-40-btrfs-luks.json")))
    assert o.status is Status.PASS and "TPM: a long random key" in {e.label: e.value for e in o.evidence}["nvme0n1p3 keyslot 1"]
    # /boot inside the encrypted disk, opened by GRUB: converting would leave it unbootable
    weak = dump.replace("  0: systemd-tpm2", "  0: something").replace("\tKeyslot:    1", "\tKeyslot:    0")
    devices = [d for d in lsblk("fedora-40-btrfs-luks.json") if "/boot" not in d.mountpoints]
    g = build(cat, _luks_host(tmp_path / "b", weak, grub='GRUB_ENABLE_CRYPTODISK=y\n'), "enc.luks_weak_kdf", devices=devices)
    assert any("GRUB unlocks it" in s.title for s in g.steps) and not [c for s in g.steps for c in s.commands]


# ------------------------------------------------------------------ snapshots

SNAPPER_ROOT = 'SUBVOLUME="/"\nFSTYPE="btrfs"\nNUMBER_LIMIT="50"\nTIMELINE_CREATE="yes"\nTIMELINE_LIMIT_MONTHLY="10"\n'


def test_snapshots_keep_fewer(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/snapper/configs/root": SNAPPER_ROOT}), system, monkeypatch)
    g = build(cat, host, "enc.snapshots_retain_deleted")
    plan = options(g)["Keep at most 10 update snapshots, 5 hourly and 7 daily"]
    assert plan.irreversible                                     # the clean-up deletes snapshots
    log, res = apply(host, plan)
    text = (host.root / "etc/snapper/configs/root").read_text()
    assert 'NUMBER_LIMIT="10"' in text and 'TIMELINE_LIMIT_MONTHLY="0"' in text and 'TIMELINE_LIMIT_YEARLY="0"' in text
    assert ["snapper", "--no-dbus", "-c", "root", "cleanup", "number"] in system.calls
    assert build_status(cat, host, "enc.snapshots_retain_deleted") is Status.PASS     # kept for days, not months
    revert(host, log, res)
    assert (host.root / "etc/snapper/configs/root").read_text() == SNAPPER_ROOT


def test_snapshots_keep_count_is_an_input(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/snapper/configs/root": SNAPPER_ROOT}), system, monkeypatch)
    g = build(cat, host, "enc.snapshots_retain_deleted", )
    check = load_all()["enc.snapshots_retain_deleted"](cat["enc.snapshots_retain_deleted"])
    scan = make_scan(host)
    scan.params = {"keep": 4}
    g = check.plan_guide(scan, check.detect(scan))
    assert "Keep at most 4 update snapshots, 4 hourly and 4 daily" in options(g)
    scan.params = {"keep": 999}                                  # out of range: the default
    assert "Keep at most 10 update snapshots, 5 hourly and 7 daily" in options(check.plan_guide(scan, check.detect(scan)))


def test_snapshots_off_warns_and_names_the_hook(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path, files={"/etc/snapper/configs/root": SNAPPER_ROOT,
                                             "/usr/share/libalpm/hooks/05-snap-pac-pre.hook": "[Trigger]\n",
                                             "/etc/os-release": "ID=cachyos\nID_LIKE=arch\n"}), system, monkeypatch)
    g = build(cat, host, "enc.snapshots_retain_deleted")
    step = next(s for s in g.steps if "turn snapshots off" in s.title)
    assert step.commands == ["sudo pacman -R snap-pac"]
    assert step.options[0].plan.side_effects[0].startswith("Not recommended.")
    assert not step.options[0].recommended


def test_timeshift_keep_fewer(cat, tmp_path, system, monkeypatch):
    ts = {"btrfs_mode": "true", "backup_device_uuid": "abc", "schedule_monthly": "true", "count_monthly": "2",
          "schedule_daily": "true", "count_daily": "5"}
    host = rooted(make_host(tmp_path, files={"/etc/timeshift/timeshift.json": json.dumps(ts, indent=2) + "\n"}),
                  system, monkeypatch)
    g = build(cat, host, "enc.snapshots_retain_deleted")
    log, res = apply(host, options(g)["Keep at most 7 daily and no weekly or monthly snapshots"])
    data = json.loads((host.root / "etc/timeshift/timeshift.json").read_text())
    assert data["schedule_monthly"] == "false" and data["count_daily"] == "7" and data["backup_device_uuid"] == "abc"
    revert(host, log, res)


def test_timeshift_leaves_the_home_folder_out(cat, tmp_path, system, monkeypatch):
    ts = {"btrfs_mode": "true", "backup_device_uuid": "abc", "include_btrfs_home_for_backup": "true"}
    host = rooted(make_host(tmp_path, files={"/etc/timeshift/timeshift.json": json.dumps(ts, indent=2) + "\n"}),
                  system, monkeypatch)
    assert build_status(cat, host, "enc.snapshots_retain_deleted") is Status.FAIL
    g = build(cat, host, "enc.snapshots_retain_deleted")
    assert g.steps[0].title == "Timeshift: leave your home folder out" and g.steps[0].options[0].recommended
    log, res = apply(host, options(g)["Leave @home out of Timeshift's snapshots"])
    data = json.loads((host.root / "etc/timeshift/timeshift.json").read_text())
    assert data["include_btrfs_home_for_backup"] == "false" and data["backup_device_uuid"] == "abc"
    assert build_status(cat, host, "enc.snapshots_retain_deleted") is Status.PASS
    revert(host, log, res)
    assert json.loads((host.root / "etc/timeshift/timeshift.json").read_text())["include_btrfs_home_for_backup"] == "true"


def test_home_out_of_snapper(cat, tmp_path):
    from test_checks_encryption import SHORT_SNAPPER, _snapshot_host
    # a config of its own for the home folder's subvolume: delete that config, never the system's
    host = _snapshot_host(tmp_path / "own", "@home", {"/etc/snapper/configs/home": SHORT_SNAPPER.format(sv="TOP/home"),
                                                      "/etc/snapper/configs/root": SHORT_SNAPPER.format(sv="/")})
    step = build(cat, host, "enc.snapshots_retain_deleted").steps[0]
    assert step.commands == ["sudo snapper -c home delete-config"]
    # in the system's subvolume: a subvolume of its own, made from a copy, the old folder deleted last
    host = _snapshot_host(tmp_path / "in", "@", {"/etc/snapper/configs/root": SHORT_SNAPPER.format(sv="TOP")})
    steps = build(cat, host, "enc.snapshots_retain_deleted").steps
    assert steps[0].title == "Give your home folder a subvolume of its own"
    home = str(host.home)
    assert steps[0].commands[:2] == [f"sudo mv {home} {home}.old", f"sudo btrfs subvolume create {home}"]
    assert steps[0].commands[-1].startswith(f"sudo rm -rf {home}.old")
    assert not any("delete-config" in c for st in steps for c in st.commands)


# ------------------------------------------------------------------ extensions

def _step_options(guide, title_start):
    step = next(s for s in guide.steps if s.title.startswith(title_start))
    return step, {o.label: o.plan for o in step.options}


def test_extensions_removed_by_policy(cat, tmp_path, system, monkeypatch):
    from test_checks_telemetry_browser import chrome
    host = rooted(make_host(tmp_path), system, monkeypatch)
    firefox(host.home, extensions=[{"id": "grabber@example.com", "type": "extension", "active": True,
                                    "location": "app-profile", "defaultLocale": {"name": "Page Grabber"},
                                    "userPermissions": {"origins": ["<all_urls>"]}}])
    ext = chrome(host.home) / "Extensions" / ("a" * 32) / "1.0_0"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({"name": "Grammar Helper", "host_permissions": ["<all_urls>"]}))
    g = build(cat, host, "br.extensions_broad")
    policy = "Remove it and keep it off, for every account on this computer (policy)"
    _, ff = _step_options(g, "Page Grabber")
    step, ch = _step_options(g, "Grammar Helper")
    assert set(ff) == set(ch) == {policy}          # no .xpi in the profile: only the policy can remove it
    assert f"chrome://extensions/?id={'a' * 32}" in step.text and "On click" in step.text
    log, res = apply(host, ff[policy])
    pol = json.loads((host.root / "etc/firefox/policies/policies.json").read_text())
    assert pol["policies"]["ExtensionSettings"] == {"grabber@example.com": {"installation_mode": "blocked"}}
    apply(host, ch[policy])
    chrome_pol = json.loads((host.root / "etc/opt/chrome/policies/managed/daprivacyscanner.json").read_text())
    assert chrome_pol["ExtensionInstallBlocklist"] == ["a" * 32]
    revert(host, log, res)
    assert not (host.root / "etc/firefox/policies/policies.json").exists()


def test_firefox_extension_removed_from_the_profile(cat, tmp_path):
    """Deleting an extension's .xpi while Firefox is closed removes it (Firefox 157 drops it at the
    next start); while Firefox runs, the step says to close it first."""
    host = make_host(tmp_path)
    prof = firefox(host.home, extensions=[{"id": "grabber@example.com", "type": "extension", "active": True,
                                           "location": "app-profile", "manifestVersion": 3,
                                           "defaultLocale": {"name": "Page Grabber"},
                                           "optionalPermissions": {"origins": ["<all_urls>"]}}])
    (prof / "extension-preferences.json").write_text(json.dumps({"grabber@example.com": {"origins": ["<all_urls>"]}}))
    xpi = prof / "extensions" / "grabber@example.com.xpi"
    xpi.parent.mkdir()
    xpi.write_bytes(b"PK")
    g = build(cat, host, "br.extensions_broad")
    step, opts = _step_options(g, "Page Grabber")
    assert "Permissions and data" in step.text           # MV3: its access can be turned off in Firefox
    plan = opts["Remove it from this profile"]
    assert opts and not plan.blockers
    apply(host, plan)
    assert not xpi.exists() and xpi.parent.is_dir()
    (host.root / "proc/88").mkdir(parents=True)
    (host.root / "proc/88/comm").write_text("firefox\n")
    xpi.write_bytes(b"PK")
    step, opts = _step_options(build(cat, host, "br.extensions_broad"), "Page Grabber")
    assert opts["Remove it from this profile"].blockers


def test_extension_blocking_refuses_wildcards(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "ROOT", str(tmp_path))
    for browser, ids in (("firefox", ["*"]), ("chrome", ["*"]), ("chrome", ["notanid"]), ("firefox", [])):
        reply = helper.handle(json.dumps({"id": 1, "action": "block_extensions", "args": {"browser": browser, "ids": ids}}))
        assert not reply["ok"] and "extension ids" in reply["error"]


# ------------------------------------------------------------------ recent files: a folder where the list goes

def test_recent_files_blocked_by_a_folder(cat, tmp_path):
    """A read-only file stops KDE apps but not GTK ones (they rename a new file over it); a folder
    where the file goes stops both. KDE's hidden UseRecent setting is turned off too."""
    xbel = '<xbel version="1.0"><bookmark href="file:///home/alice/secret.pdf" added="x"/></xbel>'
    host = make_host(tmp_path, home_files={".local/share/recently-used.xbel": xbel})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    g = build(cat, host, "desk.recent_files", desktop=("kde",), plasma_major=6)
    plan = options(g)["Put a folder where the list is kept"]
    log, res = apply(host, plan)
    path = host.home / ".local/share/recently-used.xbel"
    assert path.is_dir() and not any(path.iterdir()) and path.stat().st_mode & 0o777 == 0o500
    assert "UseRecent=false" in (host.home / ".config/kdeglobals").read_text()
    o = load_all()["desk.recent_files"](cat["desk.recent_files"]).detect(make_scan(host, desktop=("kde",)))
    assert o.status is Status.PASS and "blocked: a folder in its place" in [e.value for e in o.evidence]
    revert(host, log, res)
    assert not path.exists() and not (host.home / ".config/kdeglobals").exists()     # the fix made it: it goes


def test_recent_files_of_flatpak_apps_blocked_too(cat, tmp_path):
    """A Flatpak app keeps its own list in ~/.var/app/ID/data: the folder goes there as well, so the check can pass."""
    xbel = '<xbel version="1.0"><bookmark href="file:///home/alice/secret.pdf" added="x"/></xbel>'
    host = make_host(tmp_path, home_files={".local/share/recently-used.xbel": xbel,
                                           ".var/app/org.gimp.GIMP/data/recently-used.xbel": xbel})
    g = build(cat, host, "desk.recent_files")
    log, res = apply(host, options(g)["Put a folder where the list is kept"])
    for p in (".local/share/recently-used.xbel", ".var/app/org.gimp.GIMP/data/recently-used.xbel"):
        assert (host.home / p).is_dir()
    o = load_all()["desk.recent_files"](cat["desk.recent_files"]).detect(make_scan(host))
    assert o.status is Status.PASS
    revert(host, log, res)
    assert (host.home / ".var/app/org.gimp.GIMP/data").is_dir() and not (host.home / ".var/app/org.gimp.GIMP/data/recently-used.xbel").exists()


def test_guides_name_other_checks_by_title(cat, tmp_path):
    from daprivacyscanner.runner import Runner
    host = make_host(tmp_path, files={"/etc/os-release": "ID=ubuntu\n"})
    host.runner.handlers["lsblk"] = lambda argv: CommandResult(argv, 0, sample("lsblk/mint-22-ext4-plain.json"))
    _, g = Runner(cat, host).plan_fix("enc.fde_missing")
    text = " ".join([g.intro] + [s.text for s in g.steps])
    assert "enc." not in text
    g = load_all()["enc.boot_no_secureboot"](cat["enc.boot_no_secureboot"]).plan_guide(
        make_scan(host), Outcome(Status.FAIL, "x"))
    g.name_checks(lambda i: cat[i].title if i in cat.checks else None)
    assert "“" + cat["enc.tpm_no_pin"].title + "”" in " ".join(s.text for s in g.steps)


def test_vpn_guide_names_the_provider_and_its_own_check(cat, tmp_path):
    host = make_host(tmp_path, files={"/sys/class/net/wg0-mullvad/uevent": "DEVTYPE=wireguard\n"})
    g = _advice(cat, host, "net.vpn_leaks")
    assert g.steps[0].title == "In Mullvad VPN" and g.steps[-1].commands == ["xdg-open https://mullvad.net/check"]
    plain = _advice(cat, make_host(tmp_path / "b"), "net.vpn_leaks")
    assert plain.steps[0].title == "In your VPN app" and not plain.steps[-1].commands


def test_luks1_opened_by_grub_is_never_converted(cat, tmp_path):
    """LUKS1 is usually there because GRUB opens /boot from it: converting it to LUKS2 would leave the
    computer unable to boot, so no conversion command is given."""
    from conftest import lsblk
    devices = [d for d in lsblk("fedora-40-btrfs-luks.json") if "/boot" not in d.mountpoints]
    g = build(cat, _luks_host(tmp_path, sample("luksdump/luks1.txt"), grub="GRUB_ENABLE_CRYPTODISK=y\n"),
              "enc.luks_weak_kdf", devices=devices)
    assert any("GRUB unlocks it" in s.title for s in g.steps)
    assert not any("convert" in c for s in g.steps for c in s.commands)
    g = build(cat, _luks_host(tmp_path / "b", sample("luksdump/luks1.txt")), "enc.luks_weak_kdf", devices=devices)
    assert any("cryptsetup convert --type luks2" in c for s in g.steps for c in s.commands)


def test_login_databases_get_a_step_of_their_own(cat, tmp_path):
    """wtmpdb and lastlog2 aren't covered by the tmpfiles rule: the guide mustn't say there is nothing left."""
    host = make_host(tmp_path, files={"/var/lib/wtmpdb/wtmp.db": "x"})
    os.chmod(host.sys_path("/var/lib/wtmpdb/wtmp.db"), 0o644)
    g = build(cat, host, "auth.login_history", multi_user=ContextValue("multi_user", True, [], ""))
    assert ["sudo chmod o-r /var/lib/wtmpdb/wtmp.db"] in [s.commands for s in g.steps]


# ------------------------------------------------------------------ X11

def test_x11_guide_names_wayland_desktops_and_cinnamons_timeline(cat, tmp_path):
    host = make_host(tmp_path)
    g = build(cat, host, "sbx.x11_session", session="x11", desktop=("x-cinnamon",))
    assert "clipboard" in g.intro and not any(s.options for s in g.steps)
    assert "Cinnamon on Wayland" in g.steps[0].text and "end of 2026" in g.steps[0].text
    assert "GNOME or KDE Plasma" in g.steps[0].text
    g = build(cat, host, "sbx.x11_session", session="x11", desktop=("xfce",))
    assert "end of 2026" not in g.steps[0].text and "full Wayland support" in g.steps[0].text
    g = build(cat, host, "sbx.x11_session", session="x11", desktop=("kde",), plasma_major=6)
    assert "Plasma (Wayland)" in g.steps[0].text


# ------------------------------------------------------------------ Firefox profiles in use

def test_firefox_pref_refuses_a_profile_a_fork_holds_open(tmp_path):
    """The lock symlink alone is a stale leftover after a crash; with a process of the user's
    holding a file in the profile, whatever it is called (a fork such as Waterfox), the profile is
    in use and prefs.js would be rewritten over the change as it exits."""
    from daprivacyscanner.fix import FirefoxPref, FixContext, FixError
    host = make_host(tmp_path)
    prof = firefox(host.home, 'user_pref("a", 1);\n')
    ctx = FixContext(host, tmp_path / "backups")
    action = FirefoxPref(prof, "Firefox default", "privacy.x", True, "~/.mozilla/firefox/abcd.default-release")
    (prof / "lock").symlink_to("127.0.1.1:+4242")
    assert "privacy.x" in json.dumps(action.apply(ctx))                   # a stale lock, nothing running
    (host.root / "proc/4242/fd").mkdir(parents=True)
    (host.root / "proc/4242/comm").write_text("waterfox\n")
    os.symlink(prof / "places.sqlite", host.root / "proc/4242/fd/7")
    with pytest.raises(FixError, match="is open"):
        action.apply(ctx)
    os.unlink(host.root / "proc/4242/fd/7")
    os.symlink(host.home / "Documents/other.txt", host.root / "proc/4242/fd/7")
    action.apply(ctx)                                                      # holds something else: not this profile


@pytest.mark.parametrize("os_release, release, lsm, says, command", [
    ('ID=ubuntu\nVERSION_ID="24.04"\n', "6.8.0-45-generic", "lockdown,capability,landlock,yama,apparmor",
     "hardware enablement", "sudo apt install --install-recommends linux-generic-hwe-24.04"),
    ('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22.1"\n', "6.8.0-45-generic", "landlock,yama,apparmor",
     "Update Manager", "sudo apt install --install-recommends linux-generic-hwe-24.04"),
    ('ID=debian\nVERSION_ID="12"\n', "6.1.0-25-amd64", "landlock,yama,apparmor",
     "backports", "sudo apt install -t bookworm-backports linux-image-amd64"),
    ('ID=ubuntu\nVERSION_ID="22.04"\n', "6.8.0-45-generic", "landlock,yama,apparmor",
     "Upgrade", "sudo do-release-upgrade"),
    ('ID=fedora\n', "6.11.4-301.fc41.x86_64", "landlock,yama,selinux", "Update", "sudo dnf upgrade --refresh"),
])
def test_landlock_guide_for_an_old_kernel(cat, tmp_path, os_release, release, lsm, says, command):
    host = make_host(tmp_path, files={"/etc/os-release": os_release, "/proc/sys/kernel/osrelease": release + "\n",
                                      "/sys/kernel/security/lsm": lsm + "\n"})
    g = _advice(cat, host, "kern.landlock")
    assert says in g.steps[0].title + g.steps[0].text and command in g.steps[0].commands
    assert "cat /sys/kernel/security/lsm" in g.steps[-1].commands


def test_landlock_guide_turns_it_on_keeping_the_other_modules(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": 'ID=debian\nVERSION_ID="13"\n', "/etc/default/grub": "",
                                      "/proc/sys/kernel/osrelease": "6.12.9-amd64\n",
                                      "/sys/kernel/security/lsm": "capability,lockdown,yama,apparmor\n",
                                      "/boot/config-6.12.9-amd64": "CONFIG_SECURITY_LANDLOCK=y\n"})
    g = _advice(cat, host, "kern.landlock")
    assert g.title == "Turn on Landlock"
    # at the end of the line, an older lsm= taken out (the kernel uses the last: one put in front changed nothing)
    assert any('\\1 lsm=landlock,lockdown,yama,apparmor"' in c and '(\\"| )lsm=' not in c and '("| )lsm=' in c
               for c in g.steps[0].commands)


# ------------------------------------------------------------------ online findings: a guide for every one

ROUTE = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
         "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n")
NM_ACTIVE = ("nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active")


def test_every_online_finding_has_a_guide(cat):
    """Each online test that can be a finding offers a Guide… or How to… (net.vpn_trust's and
    tel.observed_traffic's remedies are the whole answer)."""
    from daprivacyscanner.checks.online import online_checks
    without = {i for i in online_checks() if cat[i].kind == "finding" and i not in GUIDES}
    assert without == {"tel.observed_traffic"}


def test_dns_leak_guide_names_the_vpn_connection(cat, tmp_path):
    host = make_host(tmp_path, commands={NM_ACTIVE: "Home Wi-Fi:802-11-wireless:wlan0\nMy VPN\\: work:wireguard:wg0\n"})
    out = Outcome(Status.FAIL, "leaking", [Evidence.val("Resolver", "1.2.3.4 (Telstra, Australia)")])
    g = _advice(cat, host, "net.dns_leak", out)
    assert "Telstra" in g.intro
    cmds = [c for s in g.steps for c in s.commands]
    assert cmds[0] == ("nmcli connection modify 'My VPN: work' ipv4.dns-priority -50 ipv6.dns-priority -50 "
                       "ipv4.dns-search '~.' ipv6.dns-search '~.'") and cmds[1] == "nmcli connection up 'My VPN: work'"
    assert g.steps[-1].title == "Check again" and "net.dns_leak" in g.steps[-1].text
    # a tunnel NetworkManager doesn't manage, with systemd-resolved: the resolvectl way
    host = make_host(tmp_path / "b", files={"/etc/resolv.conf": "nameserver 127.0.0.53\n",
                                            "/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n"},
                     commands={("ip", "-4", "route", "get", "1.1.1.1"): "1.1.1.1 dev wg0 src 10.0.0.2\n",
                               ("ip", "-6", "route", "get", "2606:4700:4700::1111"): ""})
    g = _advice(cat, host, "net.dns_leak")
    assert "resolvectl domain wg0 '~.'" in [c for s in g.steps for c in s.commands]


def test_vpn_ipv6_leak_guide_turns_ipv6_off_on_the_leaking_connection(cat, tmp_path):
    files = {"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n", "/sys/class/net/wlan0/uevent": "INTERFACE=wlan0\n"}
    v6 = ("ip", "-6", "route", "get", "2606:4700:4700::1111")
    host = make_host(tmp_path, files=files, commands={v6: "2606:4700:4700::1111 from :: via fe80::1 dev wlan0 src 2001:db8::5\n",
                                                      NM_ACTIVE: "Home Wi-Fi:802-11-wireless:wlan0\nMy VPN:wireguard:wg0\n"})
    g = _advice(cat, host, "net.vpn_ipv6_leak")
    cmds = [c for s in g.steps for c in s.commands]
    assert cmds == ["nmcli connection modify 'Home Wi-Fi' ipv6.method disabled", "nmcli connection up 'Home Wi-Fi'"]
    assert "ipv6.method back to auto on Home Wi-Fi" in g.steps[1].text
    # the same device without NetworkManager: the kernel setting, said to last until a restart
    host = make_host(tmp_path / "b", files=files, commands={v6: "2606:4700:4700::1111 dev wlan0 src 2001:db8::5\n"})
    g = _advice(cat, host, "net.vpn_ipv6_leak")
    assert [c for s in g.steps for c in s.commands] == ["sudo sysctl -w net.ipv6.conf.wlan0.disable_ipv6=1"]
    # IPv6 inside the tunnel: nothing to turn off
    host = make_host(tmp_path / "c", files=files, commands={v6: "2606:4700:4700::1111 dev wg0 src 2001:db8::5\n"})
    assert [s.title for s in _advice(cat, host, "net.vpn_ipv6_leak").steps] == ["In your VPN app", "Check again"]


def test_vpn_exit_guide_for_a_vpn_on_the_router(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/net/route": ROUTE})
    out = Outcome(Status.FAIL, "x", [Evidence.val("Public IPv6 address websites see", "2001:db8::5")])
    g = _advice(cat, host, "net.vpn_exit", out)
    router = next(s for s in g.steps if s.title == "If the VPN runs on your router")
    assert "http://192.168.1.1/" in router.text and router.commands == ["xdg-open http://192.168.1.1/"]
    assert "2001:db8::5" in g.intro


def test_dnssec_guide_with_and_without_resolved(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\noptions edns0\n"})
    g = _advice(cat, host, "net.dnssec_validation")
    cmds = g.steps[0].commands
    assert cmds[1].startswith("printf '[Resolve]\\nDNSSEC=allow-downgrade\\n' | sudo tee /etc/systemd/resolved.conf.d/")
    assert cmds[2] == "sudo systemctl restart systemd-resolved"
    g = _advice(cat, make_host(tmp_path / "b", files={"/etc/resolv.conf": "nameserver 192.168.1.1\n"}), "net.dnssec_validation")
    assert g.steps[0].title == "Use a resolver that validates" and "net.dns_unencrypted" in g.steps[0].text
    assert not g.steps[0].commands


def test_nxdomain_guide_points_at_the_router_when_it_answers(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 192.168.1.1\n", "/proc/net/route": ROUTE})
    out = Outcome(Status.FAIL, "x", [Evidence.val("Answered with", "198.51.100.7")])
    g = _advice(cat, host, "net.nxdomain_rewrite", out)
    assert "198.51.100.7" in g.intro and "192.168.1.1" in g.intro
    assert g.steps[1].title.startswith("Or turn the redirection off in the router") and g.steps[1].commands == ["xdg-open http://192.168.1.1/"]
    g = _advice(cat, make_host(tmp_path / "b", files={"/etc/resolv.conf": "nameserver 9.9.9.9\n"}), "net.nxdomain_rewrite")
    assert g.steps[1].title == "Or turn it off at the provider" and not g.steps[1].commands


def test_tls_interception_guide_names_the_issuer_and_the_root_to_remove(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n",
                                      "/usr/local/share/ca-certificates/kaspersky.crt":
                                          "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"})
    out = Outcome(Status.FAIL, "HTTPS is decrypted on the way: certificates are issued by Kaspersky Anti-Virus Personal Root.",
                  [Evidence.val("www.wikipedia.org", "issued by Kaspersky Anti-Virus Personal Root")])
    g = _advice(cat, host, "net.tls_interception", out)
    assert "issued by Kaspersky Anti-Virus Personal Root" in g.intro
    assert g.steps[0].commands == ["trust list | grep -i -B2 -A8 Kaspersky"] and "kaspersky.crt" in g.steps[0].text
    assert g.steps[1].commands == ["sudo rm /usr/local/share/ca-certificates/kaspersky.crt && sudo update-ca-certificates --fresh"]
    # Fedora, nothing added locally: the command names the file to fill in
    g = _advice(cat, make_host(tmp_path / "b", files={"/etc/os-release": "ID=fedora\n"}), "net.tls_interception", out)
    assert g.steps[1].commands == ["sudo rm /etc/pki/ca-trust/source/anchors/NAME.crt && sudo update-ca-trust"]
    assert "replace NAME" in g.steps[1].text


def test_upnp_guide_names_the_program_behind_each_forward(cat, tmp_path):
    from daprivacyscanner.network import Listener
    host = make_host(tmp_path, files={"/proc/net/route": ROUTE})
    out = Outcome(Status.FAIL, "x", [Evidence.val("Internet port 51413/TCP", "→ this machine's port 51413 (qBittorrent)"),
                                     Evidence.val("Internet port 32400/TCP", "→ this machine's port 32400")])
    check = load_all()["net.upnp_forwards"](cat["net.upnp_forwards"])
    scan = make_scan(host, listeners=[Listener("tcp", "0.0.0.0", 32400, "plexmediaserver", 7)])
    g = check.plan_guide(scan, out)
    assert "port 51413/tcp (internet port 51413): qBittorrent" in g.steps[0].text
    assert "port 32400/tcp (internet port 32400): plexmediaserver" in g.steps[0].text
    assert g.steps[0].commands == ["ss -lnpt 'sport = :51413'", "ss -lnpt 'sport = :32400'"]
    assert g.steps[1].commands == ["xdg-open http://192.168.1.1/"] and "2 ports" in g.intro


def test_updates_refreshed_guide_is_the_update_commands_without_options(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": "ID=debian\n", "/usr/bin/unattended-upgrade": ""})
    g = _advice(cat, host, "kern.updates_refreshed")
    assert g.steps[0].commands == ["sudo apt update && sudo apt upgrade"] and not g.plans
    assert all(not s.options for s in g.steps)


def test_online_guided_checks_borrow_their_guides(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"})
    check = load_all()["net.dns_encryption_in_use"](cat["net.dns_encryption_in_use"])
    g = check.plan_guide(make_scan(host), Outcome(Status.FAIL, "x"))
    assert g.check_id == "net.dns_encryption_in_use" and "doesn't answer over TLS" in g.intro
    labels = [o.label for o in g.steps[0].options]
    assert labels[0] == "Encrypt DNS, using Quad9" and all(p.check_id == "net.dns_encryption_in_use" for p in g.plans)
    from daprivacyscanner.network import Listener
    check = load_all()["net.ipv6_reachable"](cat["net.ipv6_reachable"])
    scan = make_scan(host, listeners=[Listener("tcp", "[::]", 631, "cupsd", 5)])
    g = check.plan_guide(scan, Outcome(Status.FAIL, "x"))
    assert g.title == "Close the services the internet reaches over IPv6" and g.steps[0].title == "CUPS printing (port 631)"


def test_editor_local_histories_of_vscode_and_jetbrains(cat, tmp_path):
    """VS Code keeps a copy of every version of a file it saved (User/History); JetBrains IDEs, LocalHistory. The guide
    deletes them and turns VS Code's off; unsaved files (Backups) are named, never deleted."""
    host = make_host(tmp_path, home_files={
        ".config/Code/User/History/-1a2b/entries.json": "{}", ".config/Code/User/History/-1a2b/AbCd.txt": "draft v1",
        ".config/Code/User/settings.json": '{\n    "editor.fontSize": 14\n}\n',
        ".config/Code/Backups/123/file/x": "unsaved",
        ".cache/JetBrains/PyCharm2026.2/LocalHistory/changes.storageData": "x"})
    o = load_all()["app.editor_residue"](cat["app.editor_residue"]).detect(make_scan(host))
    assert o.status is Status.FAIL and ev_of(o)["Code's local history"].startswith("2 files")
    assert "PyCharm2026.2's local history" in ev_of(o) and "Unsaved files VS Code keeps (hot exit)" in ev_of(o)
    g = build(cat, host, "app.editor_residue")
    log, res = apply(host, options(g)["Delete it and stop keeping it"])
    assert not list((host.home / ".config/Code/User/History").rglob("*.txt"))
    settings = (host.home / ".config/Code/User/settings.json").read_text()
    assert '"workbench.localHistory.enabled": false' in settings and '"editor.fontSize": 14' in settings
    assert (host.home / ".config/Code/Backups/123/file/x").exists()
    apply(host, options(g)["Delete it"])
    assert not (host.home / ".cache/JetBrains/PyCharm2026.2/LocalHistory/changes.storageData").exists()


def test_editor_leftovers_say_where_they_are(cat, tmp_path):
    """A deletion says where its files are, so the user can look first: the backup files next to documents one by
    one, and VS Code's history folders (named by a hash) by the file whose versions they hold."""
    host = make_host(tmp_path, home_files={
        "Documents/report.txt~": "old", "Projects/app/.main.py.swp": "x",
        ".config/Code/User/History/-1a2b/entries.json": '{"version":1,"resource":"file:///home/alice/Projects/app/my%20notes.md","entries":[]}',
        ".config/Code/User/History/-1a2b/AbCd.md": "draft v1"})
    g = build(cat, host, "app.editor_residue")
    stray = next(s for s in g.steps if s.title == "Backup files next to your documents")
    assert "listed with where it is" in stray.text
    lines = stray.options[0].plan.to_dict()["steps"][0]["lines"]
    assert lines == ["~/Documents/report.txt~", "~/Projects/app/.main.py.swp"]
    code = next(s for s in g.steps if s.title.startswith("Code's local history"))
    lines = next(st["lines"] for st in code.options[0].plan.to_dict()["steps"] if st["kind"] == "delete")
    assert lines == ["~/.config/Code/User/History/-1a2b/  (2 files: earlier versions of /home/alice/Projects/app/my notes.md)"]


def test_pkgstats_and_motd_news(cat, tmp_path, system, monkeypatch):
    """Arch's pkgstats (its timer static, linked by the package: masked or removed by hand) and Ubuntu's motd-news
    (turned off through the helper; Mint ships its script empty, so it isn't counted there)."""
    script = "#!/bin/sh\n[ -r /etc/default/motd-news ] || exit 0\n. /etc/default/motd-news\ncurl -A \"$USER_AGENT\"\n"
    host = rooted(make_host(tmp_path, files={"/usr/lib/systemd/system/pkgstats.timer": "[Timer]\n",
                                             "/etc/default/motd-news": "ENABLED=1\nURLS=x\n",
                                             "/etc/update-motd.d/50-motd-news": script}), system, monkeypatch)
    system.units["pkgstats.timer"] = ["static", "inactive"]
    system.units["motd-news.timer"] = ["enabled", "active"]
    o = build_status_outcome(cat, host, "tel.crash_reporters")
    assert o.status is Status.FAIL and "pkgstats" in o.summary and "motd-news" in o.summary
    g = build(cat, host, "tel.crash_reporters")
    assert any("mask --now pkgstats.timer" in c for st in g.steps for c in st.commands)
    log, res = apply(host, options(g)["Turn off motd-news"])
    assert "ENABLED=0" in (host.root / "etc/default/motd-news").read_text()
    assert system.units["motd-news.timer"] == ["disabled", "inactive"]
    system.units["pkgstats.timer"] = ["masked", "inactive"]
    assert build_status(cat, host, "tel.crash_reporters") is Status.PASS
    revert(host, log, res)
    assert "ENABLED=1" in (host.root / "etc/default/motd-news").read_text()
    (host.root / "etc/update-motd.d/50-motd-news").write_text("#!/bin/sh\n")                    # Mint's
    assert build_status(cat, host, "tel.crash_reporters") is Status.PASS


def test_hostname_sent_by_systemd_networkd_or_dhcpcd(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/sys/kernel/hostname": "alices-laptop\n",
                                      "/etc/passwd": "alice:x:1000:1000:Alice Smith:/home/alice:/bin/bash\n",
                                      "/etc/systemd/network/20-wired.network": "[Match]\nName=en*\n[Network]\nDHCP=yes\n",
                                      "/sys/class/net/enp1s0/operstate": "up\n",
                                      "/etc/dhcpcd.conf": "# Inform the DHCP server of our hostname for DDNS.\nhostname\n"},
                     env={"USER": "alice"})
    host.runner.handlers["systemctl"] = FakeSystem({"systemd-networkd": ["enabled", "active"],
                                                    "dhcpcd": ["enabled", "active"]}).handler
    o = build_status_outcome(cat, host, "net.hostname_broadcast")
    assert o.status is Status.FAIL and ev_of(o)["Announced via"] == "DHCP (systemd-networkd, dhcpcd)"
    titles = [s.title for s in build(cat, host, "net.hostname_broadcast").steps]
    assert "systemd-networkd: don't send the hostname" in titles and "dhcpcd: don't send the hostname" in titles
    host.sys_path("/etc/systemd/network/20-wired.network").write_text(
        "[Network]\nDHCP=yes\n[DHCPv4]\nSendHostname=no\n")
    host.sys_path("/etc/dhcpcd.conf").write_text("#hostname\n")
    assert build_status(cat, host, "net.hostname_broadcast") is Status.PASS


def test_name_checks_reaches_every_text_a_guide_shows(cat):
    from daprivacyscanner.fix import FixPlan
    from daprivacyscanner.guide import Guide, Input, Option, Step
    plan = FixPlan("enc.swap_unencrypted", "Swap in memory", blockers=["Turn off enc.hibernate_unencrypted's fix first."],
                   side_effects=["See enc.fde_missing."])
    step = Step("About enc.fde_missing", "Text enc.fde_missing", options=[Option("Like enc.fde_missing", plan, "Detail enc.fde_missing")],
                inputs=[Input("size", "Size for enc.fde_missing", "number", 1, 1, help="Help enc.fde_missing")],
                parts=[("Head enc.fde_missing", "Part enc.fde_missing")])
    g = Guide("enc.swap_unencrypted", "Swap", intro="Intro enc.fde_missing", steps=[step])
    g.name_checks(lambda i: cat[i].title if i in cat.checks else None)
    shown = [g.intro, step.title, step.text, step.inputs[0].label, step.inputs[0].help, *step.parts[0],
             step.options[0].label, step.options[0].detail, *plan.side_effects, *plan.blockers]
    assert not any("enc." in t for t in shown), shown
    assert all("“" in t for t in shown)


@pytest.mark.parametrize("os_release, command, text", [
    ('ID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 20.3"\nVERSION_ID="20.3"\nUBUNTU_CODENAME=focal\n',
     "sudo mintupgrade", "Mint moves to its next major version"),
    ("ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 20.04.6 LTS\"\nVERSION_ID=\"20.04\"\nUBUNTU_CODENAME=focal\n",
     "sudo do-release-upgrade", "next release"),
    ("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\nVERSION_ID=\"11\"\nVERSION_CODENAME=bullseye\n",
     "sudo apt update && sudo apt full-upgrade", "one release at a time"),
    ("ID=fedora\nPRETTY_NAME=\"Fedora Linux 41\"\nVERSION_ID=41\nSUPPORT_END=2025-12-15\n",
     "sudo dnf system-upgrade download --releasever=42", "--releasever=43"),
    ("ID=opensuse-leap\nPRETTY_NAME=\"openSUSE Leap 15.5\"\nVERSION_ID=\"15.5\"\n", None, "own upgrade tool"),
])
def test_release_unsupported_how_to_is_for_this_distribution(cat, tmp_path, monkeypatch, os_release, command, text):
    import datetime as dt
    from daprivacyscanner.checks import kernel

    monkeypatch.setattr(kernel, "_today", lambda: dt.date(2026, 10, 12))
    csv = ("version,codename,series,created,release,eol,eol-server,eol-esm\n"
           "20.04 LTS,Focal Fossa,focal,2019-10-17,2020-04-23,2025-05-29,2025-05-29,2030-04-23\n")
    host = make_host(tmp_path, files={"/etc/os-release": os_release, "/usr/share/distro-info/ubuntu.csv": csv})
    g = _advice(cat, host, "kern.release_unsupported")
    assert g.steps[0].title == "Back up your files first" and text in g.steps[1].text
    assert (command in g.steps[1].commands) if command else not g.steps[1].commands
    pro = [s for s in g.steps if "Ubuntu Pro" in s.title]
    assert bool(pro) == os_release.startswith("ID=ubuntu") and all("sudo pro attach" in s.commands for s in pro)



def test_vpn_guides_never_ask_for_a_switch_mullvad_s_app_doesn_t_have(cat, tmp_path):
    """Mullvad VPN's app keeps lookups and traffic in the tunnel with no setting for it: its guides say so, and
    offer the one setting there is, lockdown mode, instead of "turn on its DNS leak protection"."""
    host = make_host(tmp_path, files={"/sys/class/net/wg0-mullvad/uevent": "DEVTYPE=wireguard\n",
                                      "/proc/321/comm": "mullvad-daemon\n"})
    for cid in ("net.vpn_leaks", "net.dns_leak", "net.vpn_ipv6_leak", "net.vpn_exit"):
        g = _advice(cat, host, cid)
        text = " ".join(s.text for s in g.steps)
        assert "Turn on its" not in text and "turn on its leak protection" not in text, cid
        assert "There is nothing to turn on" in text and "mullvad lockdown-mode set on" in [c for s in g.steps
                                                                                             for c in s.commands], cid
    leak = _advice(cat, host, "net.dns_leak")
    assert "Split tunneling" in leak.steps[0].text
