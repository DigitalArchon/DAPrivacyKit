"""The checks added in the review round: known_hosts, login records, Wi-Fi history and open
networks, KDE feedback, sync inventories, browser accounts and ad features, mail remote content,
LibreOffice metadata, AppImages; and the extensions to existing checks."""

import pytest

from daprivacyscanner.checks import load_all
from daprivacyscanner.fix import apply_plan, revert_entry
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.undo import UndoLog

from conftest import detect, ev, make_host, make_scan
from fakes import FakeGSettings, FakeKwriteconfig, FakeNmcli, fail
from test_checks_telemetry_browser import chrome, firefox, pref
from test_fixes import redetect, revert, run_fix
from test_guides import build


# ------------------------------------------------------------------ known_hosts

KH = "github.com ssh-ed25519 AAAAC3\n|1|abc=|def= ssh-rsa AAAAB3\n@cert-authority *.corp ssh-rsa AAAAB3\n"


def fake_ssh_keygen(argv):
    """ssh-keygen -H: hashes the host field and leaves the plain copy as .old. As the real one
    (ssh-keygen.c, known_hosts_hash), @cert-authority and @revoked lines and wildcard patterns
    are written out unchanged."""
    from pathlib import Path
    if list(argv[1:3]) != ["-H", "-f"]:
        return fail("bad ssh-keygen call")
    p = Path(argv[3])
    text = p.read_text()
    p.with_name(p.name + ".old").write_text(text)
    out = []
    for line in text.splitlines():
        f = line.split()
        if f and not f[0].startswith(("@", "|1|")) and "*" not in f[0] and "?" not in f[0]:
            f[0] = "|1|salt|hash"
        out.append(" ".join(f))
    p.write_text("\n".join(out) + "\n")
    return CommandResult(tuple(argv), 0, "")


def test_known_hosts_plain(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/known_hosts": KH})
    o = detect(cat, "auth.ssh_known_hosts_plain", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Servers listed by name"] == 1 and ev(o)["Hashed entries"] == 1
    assert ev(o)["Lines ssh-keygen can't hash (@cert-authority, @revoked, wildcards)"] == 1
    # a CA or revoked line without a wildcard is left as it is by ssh-keygen -H too, so it isn't a plain
    # entry: counting it as one would keep the finding after the fix
    host = make_host(tmp_path / "ca", home_files={".ssh/known_hosts": "@cert-authority ca.example ssh-rsa X\n"
                                                                     "@revoked old.example ssh-rsa Y\n|1|a|b ssh-rsa Z\n",
                                                 ".ssh/config": "HashKnownHosts yes\n"})
    o = detect(cat, "auth.ssh_known_hosts_plain", make_scan(host))
    assert o.status is Status.PASS and ev(o)["Servers listed by name"] == 0
    host = make_host(tmp_path / "b", home_files={".ssh/known_hosts": "|1|a|b ssh-rsa X\n", ".ssh/config": "HashKnownHosts yes\n"})
    assert detect(cat, "auth.ssh_known_hosts_plain", make_scan(host)).status is Status.PASS
    host = make_host(tmp_path / "c", home_files={".ssh/known_hosts": "|1|a|b ssh-rsa X\n"})
    assert detect(cat, "auth.ssh_known_hosts_plain", make_scan(host)).status is Status.WARN


HASHED = "|1|a|b ssh-rsa X\n"
DEBIAN_SSH_CONFIG = "Include /etc/ssh/ssh_config.d/*.conf\n\nHost *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n"


@pytest.mark.parametrize("home, system, status, shown", [
    # Debian, Ubuntu and Mint turn it on for every user in /etc/ssh/ssh_config
    ({}, {"/etc/ssh/ssh_config": DEBIAN_SSH_CONFIG}, Status.PASS, "yes (/etc/ssh/ssh_config)"),
    ({}, {"/etc/ssh/ssh_config": DEBIAN_SSH_CONFIG, "/etc/ssh/ssh_config.d/10-local.conf": "HashKnownHosts no\n"},
     Status.WARN, "no (/etc/ssh/ssh_config.d/10-local.conf)"),
    # the user's own config is read first, and the first value wins
    ({".ssh/config": "HashKnownHosts no\n"}, {"/etc/ssh/ssh_config": DEBIAN_SSH_CONFIG}, Status.WARN, "no (~/.ssh/config)"),
    # a setting for some servers only doesn't count
    ({".ssh/config": "Host work\n  HashKnownHosts yes\n"}, {}, Status.WARN, "not set (ssh's default: no)"),
    ({".ssh/config": "Host work\n  User me\nHost *\n  HashKnownHosts yes\n"}, {}, Status.PASS, "yes (~/.ssh/config)"),
])
def test_known_hosts_reads_hashing_like_ssh(cat, tmp_path, home, system, status, shown):
    host = make_host(tmp_path, home_files={".ssh/known_hosts": HASHED, **home}, files=system)
    o = detect(cat, "auth.ssh_known_hosts_plain", make_scan(host))
    assert o.status is status and ev(o)["HashKnownHosts"] == shown


def test_known_hosts_fix_hashes_and_reverts(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/known_hosts": KH})
    host.runner.handlers["ssh-keygen"] = fake_ssh_keygen
    plan, res, log = run_fix(cat, host, "auth.ssh_known_hosts_plain")
    kh = host.home / ".ssh/known_hosts"
    assert res.ok and "github.com" not in kh.read_text() and not kh.with_name("known_hosts.old").exists()
    assert "HashKnownHosts yes" in (host.home / ".ssh/config").read_text()
    assert (host.home / ".ssh/config").stat().st_mode & 0o777 == 0o600
    assert redetect(cat, host, "auth.ssh_known_hosts_plain").status is Status.PASS
    assert all(r.ok for r in revert(host, log, res))
    assert kh.read_text() == KH and not (host.home / ".ssh/config").exists()


def test_known_hosts_plain_copy_is_kept_for_a_week_only(cat, tmp_path):
    """The backup that lets the fix be reverted is the very list it hides: deleted after 7 days (or sooner, from
    History); the step then says it can't be put back, and reverting the entry puts back the rest."""
    import time

    from daprivacyscanner.fix import revert_entry
    from daprivacyscanner.undo import UndoLog
    host = make_host(tmp_path, home_files={".ssh/known_hosts": KH})
    host.runner.handlers["ssh-keygen"] = fake_ssh_keygen
    plan, res, log = run_fix(cat, host, "auth.ssh_known_hosts_plain")
    assert any("7 days" in s for s in plan.side_effects) and "7 days" in plan.actions[0].describe()
    rec = next(r for r in log.get(res.entry_id)["records"] if r["kind"] == "hashkh")
    backup = rec["backup"]
    assert "github.com" in open(backup).read()
    step = next(s for s in UndoLog.summary(log.get(res.entry_id))["steps"] if s["backup_until"])
    assert step["reversible"] and step["backup_until"] > time.time() + 6 * 86400
    assert log.expire_backups() == 0                                   # not yet
    assert log.expire_backups(now=time.time() + 8 * 86400) == 1
    import os
    assert not os.path.exists(backup)
    summary = UndoLog.summary(log.get(res.entry_id))
    step = next(s for s in summary["steps"] if s["backup_dropped"])
    assert not step["reversible"] and summary["can_revert"]                 # ~/.ssh/config's line still can be
    results = revert_entry(log.get(res.entry_id), host, log)
    assert all(r.ok for r in results) and any("can't be undone" in r.message.lower() for r in results)
    assert "github.com" not in (host.home / ".ssh/known_hosts").read_text() and not (host.home / ".ssh/config").exists()
    assert log.get(res.entry_id)["state"] == "reverted"


def test_known_hosts_plain_copy_can_be_deleted_from_history(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/known_hosts": KH})
    host.runner.handlers["ssh-keygen"] = fake_ssh_keygen
    plan, res, log = run_fix(cat, host, "auth.ssh_known_hosts_plain")
    assert log.drop_backups("nonexistent") == 0 and log.drop_backups(res.entry_id) == 1
    assert not list((log.backup_dir(res.entry_id)).glob("*known_hosts"))


def test_known_hosts_fix_leaves_ssh_config_alone_when_hashing_is_on_system_wide(cat, tmp_path):
    host = make_host(tmp_path, home_files={".ssh/known_hosts": KH}, files={"/etc/ssh/ssh_config": DEBIAN_SSH_CONFIG})
    host.runner.handlers["ssh-keygen"] = fake_ssh_keygen
    plan, res, log = run_fix(cat, host, "auth.ssh_known_hosts_plain")
    assert res.ok and not (host.home / ".ssh/config").exists()
    assert redetect(cat, host, "auth.ssh_known_hosts_plain").status is Status.PASS


# ------------------------------------------------------------------ login records

def test_login_history(cat, tmp_path):
    import os
    host = make_host(tmp_path, files={"/var/log/wtmp": "", "/var/log/lastlog": "", "/var/log/btmp": ""})
    os.chmod(host.sys_path("/var/log/wtmp"), 0o664)
    os.chmod(host.sys_path("/var/log/lastlog"), 0o640)
    os.chmod(host.sys_path("/var/log/btmp"), 0o600)
    o = detect(cat, "auth.login_history", make_scan(host, multi_user=True))
    assert o.status is Status.FAIL and "wtmp" in o.summary + str(ev(o)) and not o.notes
    os.chmod(host.sys_path("/var/log/wtmp"), 0o640)
    assert detect(cat, "auth.login_history", make_scan(host, multi_user=True)).status is Status.PASS
    assert detect(cat, "auth.login_history", make_scan(make_host(tmp_path / "b"))).status is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ Wi-Fi

def nm_host(tmp_path, now):
    nm = FakeNmcli({
        "u1": {"type": "802-11-wireless", "connection.id": "Home", "connection.timestamp": str(now - 86400),
               "802-11-wireless-security.key-mgmt": "wpa-psk", "connection.autoconnect": "yes"},
        "u2": {"type": "802-11-wireless", "connection.id": "Airport Free WiFi", "connection.timestamp": str(now - 200 * 86400),
               "802-11-wireless-security.key-mgmt": "", "connection.autoconnect": "yes"},
        "u3": {"type": "802-11-wireless", "connection.id": "Cafe", "connection.timestamp": "0",
               "802-11-wireless-security.key-mgmt": "", "connection.autoconnect": "no"}})
    host = make_host(tmp_path, files={"/sys/class/net/wlp2s0/wireless/x": ""})
    host.runner.handlers["nmcli"] = nm
    return host, nm


def test_wifi_history_and_guide(cat, tmp_path):
    import time
    host, nm = nm_host(tmp_path, int(time.time()))
    o = detect(cat, "net.wifi_history", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Not used for 90 days or more"] == 1
    assert "Airport" not in str(o.evidence)                        # names stay out of evidence
    check = load_all()["net.wifi_history"](cat["net.wifi_history"])
    g = check.plan_guide(make_scan(host, fde="none"), o)
    assert any("nmcli connection delete u2" in c for s in g.steps for c in s.commands)
    assert not g.steps[-1].done


def test_open_autoconnect_fix(cat, tmp_path):
    import time
    host, nm = nm_host(tmp_path, int(time.time()))
    o = detect(cat, "net.open_autoconnect", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Open network that reconnects by itself"] == "Airport Free WiFi"
    plan, res, log = run_fix(cat, host, "net.open_autoconnect")
    assert res.ok and nm.connections["u2"]["connection.autoconnect"] == "no" and nm.connections["u1"]["connection.autoconnect"] == "yes"
    assert redetect(cat, host, "net.open_autoconnect").status is Status.PASS
    revert(host, log, res)
    assert nm.connections["u2"]["connection.autoconnect"] == "yes"


def test_mac_permanent_scan_randomisation_off(cat, tmp_path):
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": "stable"}})
    host = make_host(tmp_path, commands={("NetworkManager", "--print-config"): "[device]\nwifi.scan-rand-mac-address=no\n"})
    host.runner.handlers["nmcli"] = nm
    o = detect(cat, "net.mac_permanent", make_scan(host))
    assert o.status is Status.FAIL and "scan" in o.summary


def test_hostname_announced_by_resolved_mdns(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": "alice-laptop\n"},
                     commands={("resolvectl", "status"): "Global\n  Protocols: -LLMNR +mDNS -DNSOverTLS\n\n"
                               "Link 2 (wlp2s0)\n  Protocols: +DefaultRoute -LLMNR +mDNS -DNSOverTLS\n"})
    o = detect(cat, "net.hostname_broadcast", make_scan(host, listeners=[]))
    assert o.status is Status.FAIL and "systemd-resolved" in ev(o)["Announced via"]


# ------------------------------------------------------------------ telemetry

def test_kde_feedback_and_fix(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/PlasmaUserFeedback": "[Global]\nFeedbackLevel=48\n"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    kw = dict(desktop=("kde",), plasma_major=6)
    assert detect(cat, "tel.kde_feedback", make_scan(host, **kw)).status is Status.FAIL
    plan, res, log = run_fix(cat, host, "tel.kde_feedback", **kw)
    assert redetect(cat, host, "tel.kde_feedback", **kw).status is Status.PASS
    revert(host, log, res)
    assert "FeedbackLevel=48" in (host.home / ".config/PlasmaUserFeedback").read_text()
    # 16 is KUserFeedback's BasicSystemInformation, not off; the fix writes NoTelemetry (0)
    basic = make_host(tmp_path / "d", home_files={".config/PlasmaUserFeedback": "[Global]\nFeedbackLevel=16\n"})
    basic.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(basic.home / ".config")
    o = detect(cat, "tel.kde_feedback", make_scan(basic, **kw))
    assert o.status is Status.FAIL and "basic system information" in o.summary
    plan, res, log = run_fix(cat, basic, "tel.kde_feedback", **kw)
    assert [a.value for a in plan.actions] == ["0"]
    assert redetect(cat, basic, "tel.kde_feedback", **kw).status is Status.PASS
    assert detect(cat, "tel.kde_feedback", make_scan(make_host(tmp_path / "b"), desktop=("kde",))).status is Status.PASS
    assert detect(cat, "tel.kde_feedback", make_scan(make_host(tmp_path / "c"))).status is Status.NOT_APPLICABLE


def test_browser_telemetry_covers_thunderbird(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, root=".thunderbird", prefs="")
    o = detect(cat, "tel.browser_telemetry", make_scan(host))
    assert o.status is Status.FAIL and "Thunderbird" in o.summary
    assert list(ev(o).values()) == ["telemetry on"]                          # Thunderbird runs no studies


def test_cloud_sync_is_information(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".config/goa-1.0/accounts.conf": "[Account account_1]\nProvider=google\nIdentity=alice@example.com\n\n[Account account_2]\nProvider=google\n",
        ".config/Nextcloud/nextcloud.cfg": "[General]\n", ".config/rclone/rclone.conf": "[gdrive]\ntype=drive\n"})
    o = detect(cat, "tel.cloud_sync", make_scan(host))
    assert o.status is Status.WARN and ev(o)["GNOME Online Accounts"] == "google (2)" and ev(o)["rclone remotes"] == 1
    assert "alice@example.com" not in str(o.evidence)
    assert cat["tel.cloud_sync"].kind == "info"
    assert detect(cat, "tel.cloud_sync", make_scan(make_host(tmp_path / "b"))).status is Status.PASS


def test_background_callers(cat, tmp_path):
    host = make_host(tmp_path, commands={"systemctl is-enabled fwupd-refresh.timer": "enabled\n",
                                         "systemctl is-active systemd-timesyncd": "active\n"},
                     files={"/etc/systemd/timesyncd.conf": "[Time]\nNTP=ntp.example.org\n"})
    o = detect(cat, "tel.background_callers", make_scan(host))
    assert o.status is Status.WARN and ev(o)["systemd-timesyncd: asks time servers"] == "ntp.example.org"
    assert any(e.label == "fwupd" for e in o.evidence)


def test_devtools_jetbrains_and_copilot(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".config/JetBrains/IntelliJIdea2024.3/options/usage.statistics.xml":
            '<application><component name="UsageStatistics"><option name="allowed" value="true" /></component></application>',
        ".vscode/extensions/github.copilot-1.2.3/package.json": "{}"}, installed=["terraform"])
    o = detect(cat, "tel.devtools", make_scan(host))
    assert o.status is Status.FAIL and "JetBrains IntelliJIdea2024.3" in o.summary and "Terraform" in o.summary
    assert any("Copilot" in n.title or "AI assistant" in n.title for n in o.notes)
    plan, res, log = run_fix(cat, host, "tel.devtools")
    assert "CHECKPOINT_DISABLE=1" in (host.home / ".config/environment.d/60-daprivacyscanner-telemetry.conf").read_text()
    assert any("JetBrains" in s for s in plan.side_effects)


# ------------------------------------------------------------------ browsers

def test_account_sync(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("services.sync.username", "alice@example.com"))
    chrome(host.home, prefs={"account_info": [{"email": "a@b"}], "sync": {"has_setup_completed": True}})
    o = detect(cat, "br.account_sync", make_scan(host))
    assert o.status is Status.FAIL and len(o.evidence) == 2 and "example.com" not in str(o.evidence) and "a@b" not in str(o.evidence)
    host = make_host(tmp_path / "b")
    chrome(host.home, prefs={"account_info": [{"email": "a@b"}]})
    o = detect(cat, "br.account_sync", make_scan(host))
    assert o.status is Status.PASS and "sync not set up" in ev(o)["Google Chrome, Default"]



def test_account_sync_end_to_end_encrypted_is_a_risk(cat, tmp_path):
    """Firefox Sync, and Chrome with the sync passphrase the guide recommends, can't be read by the provider: a
    low-severity risk, not the problem readable sync is; the guide speaks to each browser here."""
    from daprivacyscanner.catalogue import as_warning, effective_severity
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("services.sync.username", "alice@example.com"))
    chrome(host.home, prefs={"account_info": [{"email": "a@b"}], "sync": {"has_setup_completed": True,
                                                                          "passphrase_type": 2}})
    scan = make_scan(host)
    o = detect(cat, "br.account_sync", scan)
    assert o.status is Status.WARN and "passphrase" in ev(o)["Google Chrome, Default"]
    assert as_warning(cat["br.account_sync"], effective_severity(cat["br.account_sync"], scan.context)).value == 2
    g = build(cat, host, "br.account_sync")
    assert [s.title for s in g.steps] == ["Firefox: Sync is end-to-end encrypted",
                                          "Google Chrome: synced with a sync passphrase"]


def test_ad_features_and_guide(cat, tmp_path):
    host = make_host(tmp_path)
    prof = firefox(host.home, prefs=pref("browser.search.suggest.enabled", False)
                   + pref("browser.urlbar.suggest.quicksuggest.sponsored", False)
                   + pref("browser.newtabpage.activity-stream.showSponsoredTopSites", True))
    chrome(host.home, prefs={"privacy_sandbox": {"m1": {"topics_enabled": True, "fledge_enabled": False, "ad_measurement_enabled": False}},
                             "search": {"suggest_enabled": False}})
    o = detect(cat, "br.ad_features", make_scan(host))
    assert o.status is Status.FAIL and "sponsored shortcuts" in ev(o)["Firefox profile abcd.default-release"]
    assert ev(o)["Google Chrome, Default"] == "ad topics from your history"
    check = load_all()["br.ad_features"](cat["br.ad_features"])
    g = check.plan_guide(make_scan(host), o)
    [opt] = g.steps[0].options
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    assert apply_plan(opt.plan, host, log).ok
    assert 'showSponsoredTopSites", false' in (prof / "prefs.js").read_text()
    assert detect(cat, "br.ad_features", make_scan(host)).evidence[0].value == "off"
    assert "PrivacySandboxAdTopicsEnabled" in g.steps[1].options[0].plan.dry_run()


def test_ad_features_that_are_only_browser_defaults_are_a_note_not_a_finding(cat, tmp_path):
    """A stock Firefox profile and a Chromium profile that never saw Chrome's ad privacy notice:
    nothing was turned on, so nothing is counted (every machine would fail otherwise)."""
    host = make_host(tmp_path)
    firefox(host.home, prefs="")
    chrome(host.home, root=".config/chromium", prefs={})
    o = detect(cat, "br.ad_features", make_scan(host))
    assert o.status is Status.PASS
    assert "search suggestions as you type (browser default)" in ev(o)["Firefox profile abcd.default-release"]
    assert "ad topics" not in ev(o)["Chromium, Default"]
    assert o.notes and "aren't counted" in o.notes[0].text


def test_a_policy_turning_an_ad_feature_off_wins(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/opt/chrome/policies/managed/p.json": '{"PrivacySandboxAdTopicsEnabled": false}'})
    chrome(host.home, prefs={"privacy_sandbox": {"m1": {"topics_enabled": True}}, "search": {"suggest_enabled": False}})
    assert detect(cat, "br.ad_features", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ mail and documents

def test_mail_remote_content(cat, tmp_path):
    host = make_host(tmp_path, installed=["evolution"])
    host.runner.handlers["gsettings"] = FakeGSettings({("org.gnome.evolution.mail", "image-loading-policy"): "'always'"})
    tb = firefox(host.home, root=".thunderbird", prefs=pref("mailnews.message_display.disable_remote_image", False))
    o = detect(cat, "app.mail_remote_content", make_scan(host))
    assert o.status is Status.FAIL and "Evolution" in o.summary and "Thunderbird" in o.summary
    check = load_all()["app.mail_remote_content"](cat["app.mail_remote_content"])
    g = check.plan_guide(make_scan(host), o)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    for step in g.steps:
        assert apply_plan(step.options[0].plan, host, log).ok
    assert detect(cat, "app.mail_remote_content", make_scan(host)).status is Status.PASS
    assert 'disable_remote_image", true' in (tb / "prefs.js").read_text()


def test_shared_file_metadata_guide(cat, tmp_path):
    from test_checks_apps_sandbox_kernel import LO_XCU
    host = make_host(tmp_path, home_files={".config/libreoffice/4/user/registrymodifications.xcu": LO_XCU.format(extra="")})
    o = detect(cat, "app.shared_file_metadata", make_scan(host))
    check = load_all()["app.shared_file_metadata"](cat["app.shared_file_metadata"])
    g = check.plan_guide(make_scan(host), o)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(g.steps[0].options[0].plan, host, log)
    xcu = (host.home / ".config/libreoffice/4/user/registrymodifications.xcu").read_text()
    assert res.ok and "RemovePersonalInfoOnSaving" in xcu and "Alice" in xcu and xcu.count("</oor:items>") == 1
    assert detect(cat, "app.shared_file_metadata", make_scan(host)).status is Status.PASS
    revert_entry(log.get(res.entry_id), host, log)
    assert "RemovePersonalInfoOnSaving" not in (host.home / ".config/libreoffice/4/user/registrymodifications.xcu").read_text()


def test_appimages(cat, tmp_path):
    host = make_host(tmp_path, home_files={"Applications/Foo-1.0.AppImage": "x", "Downloads/bar.appimage": "x"})
    o = detect(cat, "sbx.appimages", make_scan(host))
    assert o.status is Status.WARN and o.evidence[0].value.startswith("2 files") and cat["sbx.appimages"].kind == "info"


# ------------------------------------------------------------------ gsettings in one go

def test_gsettings_read_once_per_schema(tmp_path):
    from daprivacyscanner.desktop import GNOME, DesktopInfo
    host = make_host(tmp_path, commands={("gsettings", "list-recursively", "org.gnome.desktop.privacy"):
                                         "org.gnome.desktop.privacy remember-app-usage true\n"
                                         "org.gnome.desktop.privacy recent-files-max-age -1\n"
                                         "org.gnome.desktop.privacy remove-old-trash-files false\n"})
    g = GNOME(host, DesktopInfo(("gnome",)))
    assert g.gsettings("org.gnome.desktop.privacy", "remember-app-usage") is True
    assert g.gsettings("org.gnome.desktop.privacy", "recent-files-max-age") == -1
    assert g.gsettings("org.gnome.desktop.privacy", "nope") is None
    assert [c for c in host.runner.calls if c[0] == "gsettings"] == [("gsettings", "list-recursively", "org.gnome.desktop.privacy")]


# ------------------------------------------------------------------ partitions this system doesn't use

GIB = 1024 ** 3
ESP, WINRE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
PARTITIONS = "lsblk -J -b -o NAME,TYPE,FSTYPE,MOUNTPOINTS,RM,HOTPLUG,TRAN,LABEL,SIZE,PARTTYPE,UUID"


def _part(name, fstype, size, mountpoints=(), parttype=None, label=None, uuid=None, children=None, type="part"):
    return {"name": name, "type": type, "fstype": fstype, "mountpoints": list(mountpoints) or [None], "rm": False,
            "hotplug": False, "tran": None, "label": label, "size": size, "parttype": parttype, "uuid": uuid,
            **({"children": children} if children else {})}


def _dual_boot(windows="ntfs", extra=()):
    import json
    root = _part("root", "ext4", 200 * GIB, ["/"], type="crypt")
    return json.dumps({"blockdevices": [{"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoints": [None],
                                         "rm": False, "hotplug": False, "tran": "nvme", "label": None,
                                         "size": 500 * GIB, "parttype": None, "uuid": None, "children": [
        _part("nvme0n1p1", "vfat", 300 * 1024 ** 2, ["/boot/efi"], ESP),
        _part("nvme0n1p2", None, 16 * 1024 ** 2, parttype="e3c9e316-0b5c-4db8-817d-f92df00215ae"),
        _part("nvme0n1p3", windows, 237 * GIB, label="Windows"),
        _part("nvme0n1p4", "ntfs", 20 * GIB, parttype=WINRE),                 # a large OEM recovery partition
        _part("nvme0n1p5", "ntfs", 900 * 1024 ** 2, label="WinRE tools"),
        _part("nvme0n1p6", "crypto_LUKS", 200 * GIB, children=[root]),
        *extra]}]})


def test_unused_windows_partition_is_found_and_the_boot_and_recovery_ones_are_not(cat, tmp_path):
    host = make_host(tmp_path, commands={PARTITIONS: _dual_boot()})
    o = detect(cat, "enc.unmounted_unencrypted", make_scan(host))
    assert o.status is Status.FAIL and o.summary.startswith("1 partition this system doesn't use isn't encrypted (Windows)")
    assert ev(o) == {"/dev/nvme0n1p3": "not encrypted: Windows (NTFS), 237.0 GB"}


def test_unused_partitions_bitlocker_and_locked_luks_are_encrypted(cat, tmp_path):
    extra = [_part("nvme0n1p7", "crypto_LUKS", 50 * GIB)]
    host = make_host(tmp_path, commands={PARTITIONS: _dual_boot("BitLocker", extra)})
    o = detect(cat, "enc.unmounted_unencrypted", make_scan(host))
    assert o.status is Status.PASS
    assert ev(o) == {"/dev/nvme0n1p3": "encrypted (BitLocker, 237.0 GB)", "/dev/nvme0n1p7": "encrypted (LUKS, 50.0 GB)"}


def test_unused_partitions_an_old_linux_one_and_the_second_device_of_a_mounted_btrfs(cat, tmp_path):
    extra = [_part("nvme0n1p7", "ext4", 80 * GIB),                                     # an earlier install
             _part("nvme0n1p8", "btrfs", 100 * GIB, ["/data"], uuid="aaaa"),           # in use: the fde key's business
             _part("nvme0n1p9", "btrfs", 100 * GIB, uuid="aaaa"),                      # its second device
             _part("nvme0n1p10", "swap", 8 * GIB), _part("nvme0n1p11", "LVM2_member", 50 * GIB)]
    host = make_host(tmp_path, commands={PARTITIONS: _dual_boot("BitLocker", extra)})
    o = detect(cat, "enc.unmounted_unencrypted", make_scan(host))
    assert o.status is Status.FAIL and "(Linux)" in o.summary
    assert [e.label for e in o.evidence if "not encrypted" in e.value] == ["/dev/nvme0n1p7"]


def test_unused_partitions_removable_drives_are_another_checks(cat, tmp_path):
    import json
    stick = {"blockdevices": [{"name": "sdb", "type": "disk", "fstype": None, "mountpoints": [None], "rm": True,
                               "hotplug": True, "tran": "usb", "size": 64 * GIB,
                               "children": [_part("sdb1", "exfat", 64 * GIB)]}]}
    host = make_host(tmp_path, commands={PARTITIONS: json.dumps(stick)})
    assert detect(cat, "enc.unmounted_unencrypted", make_scan(host)).status is Status.PASS
    assert detect(cat, "enc.unmounted_unencrypted", make_scan(make_host(tmp_path / "b"))).status is Status.UNKNOWN
    assert detect(cat, "enc.unmounted_unencrypted",
                  make_scan(host, virtualization="container")).status is Status.NOT_APPLICABLE


def test_unused_partitions_how_to_names_each_and_what_to_do(cat, tmp_path):
    from test_guides import build
    extra = [_part("nvme0n1p7", "ext4", 80 * GIB)]
    g = build(cat, make_host(tmp_path, commands={PARTITIONS: _dual_boot(extra=extra)}), "enc.unmounted_unencrypted")
    titles = [s.title for s in g.steps]
    assert titles == ["Which partitions", "A Windows partition: encrypt it from Windows",
                      "A partition you still use: encrypt it here", "A partition you no longer need: clear it", "Check again"]
    assert "/dev/nvme0n1p3 (Windows (NTFS), 237.0 GB)" in g.steps[0].text and "/dev/nvme0n1p7" in g.steps[2].text
    assert "doesn't erase" in g.steps[3].text and not any(o for s in g.steps for o in s.options)


# ------------------------------------------------------------------ root certificates added to the store

PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

def test_local_root_certs(cat, tmp_path):
    from daprivacyscanner.host import CommandResult
    assert detect(cat, "net.local_root_certs", make_scan(make_host(tmp_path / "none"))).status is Status.PASS
    # update-ca-certificates takes *.crt alone from this folder: a .pem there is in no store
    files = {"/usr/local/share/ca-certificates/mitm.crt": PEM, "/usr/local/share/ca-certificates/corp/root.crt": PEM,
             "/usr/local/share/ca-certificates/corp/unused.pem": PEM, "/usr/local/share/ca-certificates/README": "not one"}
    host = make_host(tmp_path, files=files)
    o = detect(cat, "net.local_root_certs", make_scan(host))
    assert o.status is Status.WARN and o.summary.startswith("2 root certificates were added")
    assert ev(o)["Added root certificates"] == 2 and ev(o)["/usr/local/share/ca-certificates/mitm.crt"] == "a certificate file"
    assert all(e.named for e in o.evidence if e.label.startswith("/")) and o.notes[0].kind == "limitation"
    # with openssl, each is named by who it says it is
    path = str(host.root / "usr/local/share/ca-certificates/mitm.crt")
    cmds = {("openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253", "-in", path):
            CommandResult((), 0, "subject=CN=mitmproxy,O=mitmproxy\n")}
    host = make_host(tmp_path, files=files, commands=cmds)
    o = detect(cat, "net.local_root_certs", make_scan(host))
    assert ev(o)["/usr/local/share/ca-certificates/mitm.crt"] == "issued to mitmproxy"
    assert ev(o)["/usr/local/share/ca-certificates/corp/root.crt"] == "a certificate file"       # openssl couldn't read it


def test_local_root_certs_added_with_the_trust_tool(cat, tmp_path):
    """`trust anchor FILE` writes NAME.p11-kit beside the anchors folder (seen on CachyOS), where the check missed it."""
    files = {"/etc/ca-certificates/trust-source/DAP_Test_Root.p11-kit": "[p11-kit-object-v1]\ntrusted: true\nx-distrusted: false\n",
             "/etc/ca-certificates/trust-source/README": "about this folder",
             "/etc/ca-certificates/trust-source/blocklist/bad.p11-kit": "[p11-kit-object-v1]\nx-distrusted: true\n",
             "/etc/ca-certificates/trust-source/distrusted.p11-kit": "[p11-kit-object-v1]\nx-distrusted: true\n",
             "/etc/pki/ca-trust/source/corp.p11-kit": "[p11-kit-object-v1]\ntrusted: true\n", "/etc/os-release": "ID=arch\n"}
    host = make_host(tmp_path, files=files)
    o = detect(cat, "net.local_root_certs", make_scan(host))
    assert o.status is Status.WARN and ev(o)["Added root certificates"] == 2
    assert {"/etc/ca-certificates/trust-source/DAP_Test_Root.p11-kit", "/etc/pki/ca-trust/source/corp.p11-kit"} < set(ev(o))
    g = build(cat, host, "net.local_root_certs")
    assert g.steps[1].commands[0] == "sudo trust anchor --remove /etc/ca-certificates/trust-source/DAP_Test_Root.p11-kit"


def test_local_root_certs_is_a_risk_below_the_problem(cat, tmp_path):
    from daprivacyscanner.catalogue import CONTEXT_KEYS, as_warning, effective_severity
    sev = effective_severity(cat["net.local_root_certs"], {k: None for k in CONTEXT_KEYS})
    assert sev.value == 6 and as_warning(cat["net.local_root_certs"], sev).value == 4


def test_local_root_certs_how_to_removes_them_the_distributions_way(cat, tmp_path):
    from test_guides import build
    files = {"/etc/pki/ca-trust/source/anchors/corp root.crt": PEM, "/etc/os-release": "ID=fedora\n"}
    g = build(cat, make_host(tmp_path, files=files), "net.local_root_certs")
    assert g.steps[0].commands == ["openssl x509 -noout -subject -issuer -dates -in "
                                   "'/etc/pki/ca-trust/source/anchors/corp root.crt'"]
    assert g.steps[1].commands == ["sudo rm '/etc/pki/ca-trust/source/anchors/corp root.crt' && sudo update-ca-trust"]


# ------------------------------------------------------------------ HTTPS-Only Mode

def test_https_only(cat, tmp_path):
    from test_checks_telemetry_browser import chrome, firefox, pref
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("dom.security.https_only_mode_pbm", True))
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.FAIL and "private windows only" in list(ev(o).values())[0]
    firefox(host.home, prefs=pref("dom.security.https_only_mode", True))
    firefox(host.home, root=".librewolf", name="lw.default")                        # on unless turned off
    chrome(host.home, prefs={"https_only_mode_enabled": True})
    chrome(host.home, prefs={"https_first_balanced_mode_enabled": True}, root=".config/chromium")
    strict = {"profile": {"default_content_setting_values": {"httpsUpgrades": 2}}}      # as Brave 1.97 writes Strict
    chrome(host.home, prefs=strict, root=".config/BraveSoftware/Brave-Browser")
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.PASS, ev(o)
    firefox(host.home, prefs=pref("dom.security.https_only_mode", False), root=".librewolf", name="lw.default")
    chrome(host.home, prefs={}, root=".config/BraveSoftware/Brave-Browser")          # Standard: falls back
    chrome(host.home, prefs={"https_only_mode_enabled": False})
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.FAIL and o.summary.startswith("3 browser profiles open unencrypted pages")
    assert "Standard (falls back to HTTP)" in ev(o)["Brave, Default"]
    chrome(host.home, prefs={"profile": {"default_content_setting_values": {"httpsUpgrades": 1}}}, root=".config/BraveSoftware/Brave-Browser")
    assert ev(detect(cat, "br.https_only", make_scan(host)))["Brave, Default"] == "Upgrade connections to HTTPS: off"
    assert detect(cat, "br.https_only", make_scan(make_host(tmp_path / "n"))).status is Status.NOT_APPLICABLE


def test_https_only_policies(cat, tmp_path):
    from test_checks_telemetry_browser import chrome, firefox
    import json
    files = {"/etc/firefox/policies/policies.json": json.dumps({"policies": {"HttpsOnlyMode": "force_enabled"}}),
             "/etc/opt/chrome/policies/managed/x.json": json.dumps({"HttpsOnlyMode": "force_enabled"})}
    host = make_host(tmp_path, files=files)
    firefox(host.home)
    chrome(host.home)
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.PASS and all("a policy" in v for v in ev(o).values()), ev(o)


def test_https_only_guide_sets_one_pref_and_says_where_for_the_rest(cat, tmp_path):
    from test_checks_telemetry_browser import chrome, firefox
    from test_guides import build, options
    host = make_host(tmp_path)
    firefox(host.home)
    firefox(host.home, root=".librewolf", name="lw.default")
    chrome(host.home, root=".config/BraveSoftware/Brave-Browser")
    g = build(cat, host, "br.https_only")
    opts = [o for s in g.steps for o in s.options]
    assert [o.label for o in opts] == ["Turn on HTTPS-Only Mode: Firefox profile abcd.default-release"]
    assert opts[0].key == "https_only" and len(opts[0].plan.actions) == 1
    assert "dom.security.https_only_mode" in opts[0].plan.actions[0].describe()
    assert "Brave: Settings → Shields" in g.steps[1].text and "chrome://" not in g.steps[1].text and not g.steps[1].done

