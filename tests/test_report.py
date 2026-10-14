import json

from daprivacyscanner.report import Redactor, replace_addresses

from conftest import make_host


def redactor(tmp_path):
    host = make_host(tmp_path, env={"USER": "user"}, files={"/proc/sys/kernel/hostname": "mint-box\n"},
                     commands={("nmcli", "-g", "NAME", "connection", "show"): "CafeFreeWiFi\nHome\\:5G\nlo\n"})
    return Redactor(host)


def test_saved_network_names_are_redacted_in_labels_and_text(tmp_path):
    r = redactor(tmp_path)
    # net.mac_permanent uses each saved network's name as the evidence label
    assert r.evidence({"kind": "value", "label": "CafeFreeWiFi", "value": "permanent"})["label"] == "[redacted]"
    assert r.text("joined Home:5G yesterday") == "joined [redacted] yesterday"


def test_names_are_redacted_as_whole_words_only(tmp_path):
    r = redactor(tmp_path)
    assert r.text("other users can read user's files on mint-box") == "other users can read [redacted]'s files on [redacted]"


def test_drive_labels_uuids_and_profile_names_are_redacted(tmp_path):
    """A drive's label in the folder it is mounted on, a disk's UUID and a Firefox profile's folder identify their
    owner as much as a name does; a mount point that is the whole text keeps no part of its label."""
    r = redactor(tmp_path)
    assert r.text("sdb1 (exfat, at /media/user/Taxes 2024)") == "sdb1 (exfat, at /media/[redacted]/[drive])"
    assert r.text("thumbnails from /media/user/My Passport were found") == \
        "thumbnails from /media/[redacted]/[drive] were found"
    assert r.text("sdb1 (exfat, at /media/user/Taxes_2024)") == "sdb1 (exfat, at /media/[redacted]/[drive])"
    assert r.text("/run/media/user/My Passport") == "/run/media/[redacted]/[drive]"
    assert r.text("/mnt/clientwork/sub") == "/mnt/[drive]/sub"
    assert r.text("encrypted (luks-3f2a9c1e-1b2c-4d5e-8f90-0a1b2c3d4e5f)") == "encrypted (luks-[uuid])"
    assert r.text("Firefox profile k3j9x2ab.work-acme, flatpak") == "Firefox profile [profile], flatpak"


def test_names_the_user_chose_are_redacted_everywhere(tmp_path):
    """Evidence marked `named` (a key file's or wallet's name) is redacted in labels and in every text; the default
    names say nothing and stay."""
    r = redactor(tmp_path)
    report = {"results": {"auth.ssh_key_no_passphrase": {
        "summary": "id_ed25519_acme_prod has no passphrase.", "notes": [], "error": "",
        "evidence": [{"kind": "value", "label": "id_ed25519_acme_prod", "value": "no passphrase", "named": True},
                     {"kind": "value", "label": "id_ed25519", "value": "protected by a passphrase", "named": True}]}}}
    out = r.report(report)["results"]["auth.ssh_key_no_passphrase"]
    assert "acme" not in json.dumps(out)
    assert [e["label"] for e in out["evidence"]] == ["[redacted]", "id_ed25519"]


def test_only_real_addresses_are_redacted():
    text = "at 14:26:05, version 1.2.3, from 192.168.1.20 and fe80::1c2:3ff:fe4:5, listening on [::]:22, 0.0.0.0:631, ::1"
    assert replace_addresses(text, "[ipv4]", "[ipv6]") == \
        "at 14:26:05, version 1.2.3, from [ipv4] and [ipv6], listening on [::]:22, 0.0.0.0:631, ::1"


def test_resurfacing_rule_and_its_reason():
    from daprivacyscanner.history import hidden, resurfaced, why_resurfaced

    rec = {"note": "", "when": 1790000000, "severity": 4, "severity_reason": ""}
    assert not resurfaced(rec, 4) and resurfaced(rec, 7)
    assert not resurfaced({"note": ""}, 9)                     # accepted before severities were kept: stays hidden
    assert hidden({"x.y": rec}, "x.y", {"effective_severity": 3}) and not hidden({"x.y": rec}, "x.y", {"effective_severity": 5})
    why = why_resurfaced(rec, {"effective_severity": 7, "severity_reason": "device type is laptop"})
    assert "rose from 4 to 7" in why and "then: its base severity; now: device type is laptop" in why
    assert "rates it higher now" in why_resurfaced(rec, {"effective_severity": 7, "severity_reason": ""})


def test_redacted_exports_redact_the_accepted_findings_notes(tmp_path):
    """The note the user writes when accepting a finding can name anything: it goes through the Redactor like
    the rest, in the text and JSON report exports as in Export everything."""
    from daprivacyscanner import catalogue
    from daprivacyscanner.report import export, export_all
    cat = catalogue.load()
    host = make_host(tmp_path, env={"USER": "user"}, files={"/proc/sys/kernel/hostname": "mint-box\n"})
    report = {"started": 1, "context": {"values": {}, "desktop": {"label": "GNOME"}},
              "results": {"auth.screen_lock": {"status": "fail", "effective_severity": 7, "kind": "finding",
                                               "is_finding": True, "summary": "", "evidence": [], "notes": []}}}
    accepted = {"auth.screen_lock": {"note": "my mint-box at work, user's desk", "when": 1, "severity": 7}}
    for fmt in ("text", "json"):
        plain = export(report, cat, fmt, host, False, accepted)
        assert "mint-box" in plain
        redacted = export(report, cat, fmt, host, True, accepted)
        assert "mint-box" not in redacted and "[redacted] at work" in redacted
        assert "mint-box" not in export_all(report, cat, [], accepted, fmt, host, True)


def test_the_saved_report_leaves_out_what_isnt_kept_between_runs():
    """Inventory entries (named in `items` and as evidence labels) and the online tests' addresses and lookup
    names go; the rest stays; nothing is changed in the report itself."""
    from daprivacyscanner.history import NOT_KEPT_VALUE, strip_for_saving
    report = {"started": 1, "restored": True, "changes": {"new": [], "new_items": {"app.login_items": ["~/x.desktop"]}},
              "results": {
                  "app.login_items": {"status": "warn", "items": ["~/x.desktop", "user unit a.service"], "notes": [],
                                      "evidence": [{"label": "~/x.desktop", "value": "autostart"},
                                                   {"label": "Entries in your crontab", "value": 2}]},
                  "net.vpn_exit": {"status": "pass", "notes": [], "evidence": [
                      {"label": "Public IPv4 address websites see", "value": "203.0.113.9"},
                      {"label": "VPN in use", "value": "Mullvad"}]},
                  "auth.screen_lock": {"status": "pass", "evidence": [{"label": "Lock enabled", "value": "yes"}]}}}
    saved = strip_for_saving(report)
    text = json.dumps(saved)
    assert "x.desktop" not in text and "a.service" not in text and "203.0.113.9" not in text and "restored" not in saved
    assert saved["results"]["app.login_items"]["evidence"] == [{"label": "Entries in your crontab", "value": 2}]
    assert saved["results"]["net.vpn_exit"]["evidence"][0]["value"] == NOT_KEPT_VALUE
    assert saved["results"]["net.vpn_exit"]["evidence"][1]["value"] == "Mullvad"
    assert [n["title"] for n in saved["results"]["net.vpn_exit"]["notes"]] == ["Not kept between runs"]
    assert "notes" not in saved["results"]["auth.screen_lock"]
    assert saved["not_kept"] == ["the entries of app.login_items", "the addresses net.vpn_exit saw"]
    assert saved["changes"]["new_items"] == {}
    assert report["results"]["app.login_items"]["items"] and report["changes"]["new_items"]     # untouched


def test_the_saved_report_leaves_out_wifi_network_names():
    """Saved networks a check names say where the computer has been: shown, never saved (the undo log keeps them
    by UUID for the same reason)."""
    from daprivacyscanner.history import NOT_KEPT_VALUE, strip_for_saving
    report = {"started": 1, "results": {
        "net.open_autoconnect": {"status": "fail", "notes": [], "evidence": [
            {"label": "Open network that reconnects by itself", "value": "Airport Free WiFi"}]},
        "net.hidden_ssid": {"status": "fail", "notes": [], "evidence": [{"label": "Hidden network", "value": "HomeNet"}]}}}
    saved = strip_for_saving(report)
    text = json.dumps(saved)
    assert "Airport Free WiFi" not in text and "HomeNet" not in text
    assert saved["results"]["net.hidden_ssid"]["evidence"][0]["value"] == NOT_KEPT_VALUE
    assert saved["not_kept"] == ["the network names net.open_autoconnect listed", "the network names net.hidden_ssid listed"]


def test_export_everything_carries_what_history_shows(tmp_path):
    """The text export says of every change what it ran, wrote and made, how it goes back by hand, what putting
    it back ran, and where the change came from; a failed attempt says what failed and that it was put back."""
    from daprivacyscanner import catalogue
    from daprivacyscanner.fix import FixPlan, GSettingsSet, WriteFile, apply_plan, revert_entry
    from daprivacyscanner.report import export_all
    from daprivacyscanner.undo import UndoLog
    from fakes import FakeGSettings, fail
    cat = catalogue.load()
    key = ("org.gnome.system.location", "enabled")
    gs = FakeGSettings({key: "true"})
    host = make_host(tmp_path, home_files={"env.conf": "A=1\n"})
    host.runner.handlers["gsettings"] = gs
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    plan = FixPlan("tel.location", "Turn off location services",
                   [GSettingsSet(*key, "false"), WriteFile(host.home / "env.conf", lambda old: old + "B=2\n", "Add B", "~/env.conf")],
                   via={"guide": "Location", "step": 1, "step_title": "Turn it off", "option": "Off", "options": 2})
    res = apply_plan(plan, host, log)
    revert_entry(log.get(res.entry_id), host, log)
    host.runner.handlers["gsettings"] = lambda argv: fail("no dconf")
    failed = apply_plan(FixPlan("tel.location", "Turn off location services",
                                [WriteFile(host.home / "env.conf", lambda old: old + "C=3\n", "Add C", "~/env.conf"),
                                 GSettingsSet(*key, "false")]), host, log)
    assert not failed.ok and failed.entry_id
    text = export_all(None, cat, log.entries(), {}, "text", host)
    assert "From the guide “Location”, step 1 (Turn it off), the option “Off”" in text
    assert "        ran: gsettings set org.gnome.system.location enabled false" in text
    assert "        line: + B=2" in text
    assert "        putting it back ran: gsettings set org.gnome.system.location enabled true" in text
    assert "        putting it back ran: cp " in text and "[reverted]  (reverted " in text
    assert "    FAILED: gsettings get org.gnome.system.location enabled failed: no dconf (at: gsettings set " in text
    assert "    The steps that had run were put back, as listed under each." in text
    data = json.loads(export_all(None, cat, log.entries(), {}, "json", host))
    assert data["changes"][0]["steps"][1]["lines"] == ["+ B=2"] and data["changes"][1]["state"] == "failed"
    assert data["changes"][1]["steps"][0]["reverted"] and data["changes"][1]["steps"][0]["revert_ran"][0].startswith("cp ")


# ------------------------------------------------------------------ what changed: unchecked is never resolved

def _scan(status, severity=7, started=1):
    return {"started": started, "results": {"enc.luks_weak": {"status": status, "effective_severity": severity,
                                                             "kind": "finding", "id": "enc.luks_weak"}}}


def test_a_problem_that_couldnt_be_checked_again_isnt_resolved_nor_new_when_found_again(tmp_path):
    from daprivacyscanner.history import Baseline
    from daprivacyscanner.paths import PathResolver
    b = Baseline(PathResolver(tmp_path, {"HOME": str(tmp_path)}))
    assert b.record(_scan("fail", started=100)) is None                   # with administrator access: a problem
    ch = b.record(_scan("unknown", started=200))                          # without: it couldn't be checked
    assert ch["resolved"] == [] and ch["new"] == []
    assert ch["unchecked"] == [{"id": "enc.luks_weak", "status": "fail", "severity": 7, "checked": 100}]
    ch = b.record(_scan("error", started=300))                            # and again: still what it was at 100
    assert ch["resolved"] == [] and ch["unchecked"][0]["checked"] == 100
    ch = b.record(_scan("fail", 9, started=400))                          # checked again: not new, its severity changed
    assert ch["new"] == [] and ch["unchecked"] == []
    assert ch["changed"] == [{"id": "enc.luks_weak", "from": 7, "to": 9, "was": "fail", "now": "fail"}]
    b.record(_scan("unknown", started=500))
    ch = b.record(_scan("pass", 0, started=600))                          # only a scan that checked it resolves it
    assert ch["resolved"] == ["enc.luks_weak"] and ch["unchecked"] == []
    assert "last" not in b.load()["results"]["enc.luks_weak"]


def test_unchecked_after_a_pass_is_nothing_and_a_problem_after_it_is_new(tmp_path):
    from daprivacyscanner.history import Baseline
    from daprivacyscanner.paths import PathResolver
    b = Baseline(PathResolver(tmp_path, {"HOME": str(tmp_path)}))
    b.record(_scan("pass", 0))
    ch = b.record(_scan("unknown"))
    assert ch["unchecked"] == [] and ch["resolved"] == []
    assert b.record(_scan("fail"))["new"] == ["enc.luks_weak"]


def test_text_report_says_what_an_unchecked_result_was(cat):
    from daprivacyscanner import report as report_mod
    cid = next(iter(cat.checks))
    rep = {"started": 1, "context": {}, "results": {cid: {"status": "unknown", "effective_severity": 7, "kind": "finding",
                                                           "needs_admin": True, "summary": "Needs administrator access."}},
           "changes": {"previous": 1, "new": [], "resolved": [], "changed": [], "new_items": {},
                       "unchecked": [{"id": cid, "status": "fail", "severity": 7, "checked": 86400 * 400}]}}
    text = report_mod.export(rep, cat, "text", None, False, {})
    assert "Problem, severity 7, when it was last checked (1971-" in text and "isn't resolved" in text
