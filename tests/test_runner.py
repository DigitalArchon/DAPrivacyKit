import os

import pytest

from daprivacyscanner import blockdev
from daprivacyscanner.catalogue import CatalogueError
from daprivacyscanner.checks import REGISTRY, Check, register
from daprivacyscanner.model import Evidence, Note, Outcome, Status
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.runner import Runner

from conftest import make_host, sample, skip_if_root

LSBLK = ("lsblk", "-J", "-o", blockdev.COLUMNS)


def laptop_host(tmp_path, lsblk="mint-22-ext4-plain.json", **kw):
    return make_host(tmp_path, commands={LSBLK: sample(f"lsblk/{lsblk}")},
                     files={"/sys/class/dmi/id/chassis_type": "10\n", **kw.pop("files", {})}, **kw)


def check(check_id, detect, **attrs):
    return type(f"Fake_{check_id.replace('.', '_')}", (Check,), {"id": check_id, "detect": detect, **attrs})


def run(cat, host, *checks, privileged=None):
    host.privileged = privileged
    return Runner(cat, host, {c.id: c for c in checks}).scan(only=[c.id for c in checks])


def test_runs_implemented_checks_and_lists_the_rest(cat, tmp_path):
    fde = check("enc.fde_missing", lambda self, scan: Outcome(Status.FAIL, "Root is not encrypted",
                                                             [Evidence.path("Not encrypted", "/")]))
    report = Runner(cat, laptop_host(tmp_path), {fde.id: fde}).scan()
    r = report.results["enc.fde_missing"]
    assert (r.status, r.effective_severity, r.base_severity) == (Status.FAIL, 10, 10)
    assert r.is_finding and report.findings == [r]
    online = [s.id for s in cat if s.scope.value == "online"]
    assert len(report.not_implemented) == len(cat) - 1 - len(online)
    assert report.online_pending == online and not set(online) & set(report.results)   # never in a normal scan
    # not implemented, and not applicable on an unencrypted machine
    assert report.not_implemented["enc.partial_fde"].not_applicable
    d = report.to_dict()
    assert d["results"]["enc.fde_missing"]["evidence"] == [{"kind": "path", "label": "Not encrypted", "value": "/"}]
    assert d["modifiers"]["enc.fde_missing"] == [False, False]      # no encryption at all


def test_severity_follows_context(cat, tmp_path):
    mac = check("net.mac_permanent", lambda self, scan: Outcome(Status.FAIL))
    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/mint-22-ext4-plain.json")},
                     files={"/sys/class/dmi/id/chassis_type": "3\n"})
    assert run(cat, host, mac).results[mac.id].effective_severity == 2           # a desktop
    # an unencrypted disk is critical whatever the machine
    fde = check("enc.fde_missing", lambda self, scan: Outcome(Status.FAIL))
    assert run(cat, host, fde).results[fde.id].effective_severity == 10


def test_not_applicable_by_context_is_not_run(cat, tmp_path):
    calls = []
    partial = check("enc.partial_fde", lambda self, scan: calls.append(1) or Outcome(Status.FAIL))
    r = run(cat, laptop_host(tmp_path), partial).results[partial.id]
    assert r.status is Status.NOT_APPLICABLE and r.effective_severity == 0 and not r.is_finding
    assert calls == []


def test_findings_raise_severity(cat, tmp_path):
    thumbs = check("desk.thumbnails", lambda self, scan: Outcome(
        Status.FAIL, findings={"thumbnails_reference_removable_or_container": True,
                               "thumbnails_on_disk_none_leaking": False, "thumbnails_expire": False}))
    report = run(cat, laptop_host(tmp_path), thumbs)
    assert report.results[thumbs.id].effective_severity == 7
    assert report.modifiers[thumbs.id] == [False, False, False, False, False, True, False]     # an unencrypted disk


@pytest.mark.parametrize("lsblk, severity", [("fedora-40-btrfs-luks.json", 6), ("mint-22-ext4-plain.json", 7)])
def test_on_an_encrypted_disk_severity_is_one_lower_and_the_result_says_why(cat, tmp_path, lsblk, severity):
    from daprivacyscanner.checks._util import ENCRYPTED_DISK_NOTE
    blank = check("auth.keyring_blank", lambda self, scan: Outcome(Status.FAIL, "Opens without a password"))
    r = run(cat, laptop_host(tmp_path, lsblk=lsblk), blank).results[blank.id]
    assert r.effective_severity == severity and not r.uncertain_on
    assert r.findings["data_on_encrypted_disk"] is (severity == 6)
    assert (ENCRYPTED_DISK_NOTE in r.notes) is (severity == 6)
    if severity == 6:
        assert r.severity_reason == "it is kept on an encrypted disk"
        assert "malware" in ENCRYPTED_DISK_NOTE.text and "shut down" in ENCRYPTED_DISK_NOTE.text
    # a pass says nothing about it, and isn't uncertain either
    ok = check("auth.keyring_blank", lambda self, scan: Outcome(Status.PASS, "Keyrings have a password"))
    r = run(cat, laptop_host(tmp_path, lsblk=lsblk), ok).results[ok.id]
    assert ENCRYPTED_DISK_NOTE not in r.notes and not r.uncertain_on


def test_findings_not_in_the_catalogue_are_an_error(cat, tmp_path):
    bad = check("desk.thumbnails", lambda self, scan: Outcome(Status.FAIL, findings={"made_up": True}))
    r = run(cat, laptop_host(tmp_path), bad).results[bad.id]
    assert r.status is Status.ERROR and "made_up" in r.error


def test_unknown_context_is_reported_as_uncertainty(cat, tmp_path):
    autologin = check("auth.autologin", lambda self, scan: Outcome(Status.FAIL))
    host = laptop_host(tmp_path, lsblk="fedora-40-btrfs-luks.json")      # encrypted: TPM state needs root
    r = run(cat, host, autologin).results[autologin.id]
    assert r.effective_severity == 6 and r.uncertain_on == ("tpm_unlock_no_pin",)


def test_a_crashing_check_is_an_error_and_the_scan_goes_on(cat, tmp_path):
    boom = check("enc.trash", lambda self, scan: 1 / 0)
    ok = check("auth.umask", lambda self, scan: Outcome(Status.PASS))
    report = run(cat, laptop_host(tmp_path), boom, ok)
    assert report.results["enc.trash"].status is Status.ERROR
    assert "ZeroDivisionError" in report.results["enc.trash"].error
    assert report.results["auth.umask"].status is Status.PASS


def test_detect_must_return_an_outcome(cat, tmp_path):
    bad = check("enc.trash", lambda self, scan: "fail")
    assert run(cat, laptop_host(tmp_path), bad).results["enc.trash"].status is Status.ERROR


@skip_if_root
def test_system_check_without_root_reports_partial_detection(cat, tmp_path):
    host = laptop_host(tmp_path, files={"/etc/cups/cupsd.conf": "PreserveJobFiles Yes\n"})
    os.chmod(host.sys_path("/etc/cups/cupsd.conf"), 0)
    cups = check("app.cups_spool", lambda self, scan: Outcome(Status.PASS) if scan.host.read_sys("/etc/cups/cupsd.conf") else None)
    r = run(cat, host, cups).results[cups.id]
    assert r.status is Status.UNKNOWN and r.partial and not r.error
    assert r.evidence[0].value == "/etc/cups/cupsd.conf"           # shown as on the host, not the fixture path


@skip_if_root
def test_user_check_that_cannot_read_is_an_error(cat, tmp_path):
    host = laptop_host(tmp_path, home_files={".netrc": "machine x\n"})
    os.chmod(host.home / ".netrc", 0)
    creds = check("auth.plaintext_credentials", lambda self, scan: scan.host.read_file(scan.host.home / ".netrc"))
    r = run(cat, host, creds).results[creds.id]
    assert r.status is Status.ERROR and not r.partial and "~/.netrc" in r.summary


def planned(self, scan, outcome):
    from daprivacyscanner.fix import Command, FixPlan
    return FixPlan(self.id, "x", [Command(["true"], "test")])


@pytest.mark.parametrize("tier_id, attrs, privileged, fixable", [
    ("enc.trash", {"supports_fix": True, "plan_fix": planned}, None, True),     # auto, user
    ("enc.trash", {"supports_fix": True}, None, False),                     # an empty trash: nothing to change
    ("enc.trash", {}, None, False),                                         # no fix implemented
    ("auth.autologin", {"supports_fix": True}, None, True),                # root steps ask for root when applied
    ("tel.countme", {"supports_fix": True, "fix_needs_root": True}, None, True),
    ("tel.countme", {"supports_fix": True, "fix_needs_root": True}, FakePrivileged(), True),
    ("enc.fde_missing", {"supports_fix": True}, None, False),               # advice: never fixed by the app
    ("enc.trash", {"supports_fix": True, "can_fix": lambda self, scan, o: False}, None, False),
])
def test_fixable(cat, tmp_path, tier_id, attrs, privileged, fixable):
    c = check(tier_id, lambda self, scan: Outcome(Status.FAIL), **attrs)
    assert run(cat, laptop_host(tmp_path), c, privileged=privileged).results[tier_id].fixable is fixable


def test_an_unknown_result_is_not_fixable(cat, tmp_path):
    c = check("auth.empty_password", lambda self, scan: Outcome(Status.UNKNOWN, "needs root", partial=True), supports_fix=True)
    assert run(cat, laptop_host(tmp_path), c).results["auth.empty_password"].fixable is False


def test_passing_checks_are_not_fixable(cat, tmp_path):
    c = check("enc.trash", lambda self, scan: Outcome(Status.PASS), supports_fix=True)
    assert run(cat, laptop_host(tmp_path), c).results["enc.trash"].fixable is False


def test_implementations_must_be_in_the_catalogue(cat, tmp_path):
    with pytest.raises(CatalogueError, match="enc.nope"):
        Runner(cat, laptop_host(tmp_path), {"enc.nope": check("enc.nope", lambda s, x: None)})


def test_registry_refuses_two_implementations_of_one_id(monkeypatch):
    import daprivacyscanner.checks as checks

    monkeypatch.setattr(checks, "REGISTRY", {})
    register(check("tel.countme", lambda self, scan: Outcome(Status.PASS)))
    with pytest.raises(TypeError, match="two implementations"):
        register(check("tel.countme", lambda self, scan: Outcome(Status.PASS)))


def test_every_registered_check_is_in_the_catalogue(cat):
    assert set(REGISTRY) <= set(cat.checks)


def test_context_detection_runs_only_read_only_commands(cat, tmp_path):
    host = laptop_host(tmp_path)
    Runner(cat, host, {}).scan()
    # context detection only runs read-only commands
    allowed = {"lsblk", "hostnamectl", "getent", "ss", "systemctl", "systemd-detect-virt", "gnome-shell", "plasmashell",
               "lsattr"}
    assert {argv[0] for argv in host.runner.calls} <= allowed


@pytest.mark.parametrize("value", ["x" * 301, ["a"], {"a": 1}])
def test_evidence_is_never_file_contents(value):
    with pytest.raises((ValueError, TypeError)):
        Evidence.val("contents", value)


def test_notes_reach_the_result(cat, tmp_path):
    c = check("enc.trash", lambda self, scan: Outcome(Status.PASS, notes=[Note("info", "Empty", "Nothing in the trash")]))
    r = run(cat, laptop_host(tmp_path), c).results["enc.trash"]
    assert r.to_dict()["notes"] == [{"kind": "info", "title": "Empty", "text": "Nothing in the trash", "related": []}]


def test_report_says_whether_root_was_available(cat, tmp_path):
    assert run(cat, laptop_host(tmp_path)).privileged is False
    assert run(cat, laptop_host(tmp_path / "b"), privileged=FakePrivileged()).privileged is True


def test_every_catalogue_check_is_implemented(cat):
    from daprivacyscanner.checks import load_all

    assert set(load_all()) == set(cat.checks)


@pytest.mark.parametrize("desktop", ["GNOME", "KDE", "X-Cinnamon", ""])
def test_every_check_survives_a_bare_machine(cat, tmp_path, desktop):
    """Nothing installed, nothing configured, no commands: no check may crash."""
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": desktop})
    report = Runner(cat, host).scan()
    errors = {k: r.error for k, r in report.results.items() if r.status is Status.ERROR}
    assert errors == {}
    assert not report.not_implemented


def test_every_check_survives_a_populated_machine(cat, tmp_path):
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "KDE", "USER": "alice"},
                     commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json"),
                               ("ss", "-tulpnH"): sample("ss/fedora-40.txt")},
                     files={"/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 8388604 0 100\n",
                            "/sys/power/state": "freeze mem disk\n", "/proc/mounts": "/dev/dm-0 / btrfs rw 0 0\n",
                            "/etc/crypttab": "luks-x UUID=y none discard\n"},
                     home_files={".local/share/recently-used.xbel": '<bookmark href="file:///x"/>',
                                 ".mozilla/firefox/profiles.ini": "[Profile0]\nPath=p\n", ".mozilla/firefox/p/prefs.js": "",
                                 ".config/google-chrome/Default/Preferences": "{}", ".bash_history": "ls\n"})
    report = Runner(cat, host).scan()
    assert {k: r.error for k, r in report.results.items() if r.status is Status.ERROR} == {}
    assert len(report.findings) > 10


def test_rescan_keeps_context_that_needs_root_once_root_has_gone(cat, tmp_path, monkeypatch):
    """Scanned with administrator access, then a fix after access ended: the TPM key can't be
    read again, but it didn't change. It keeps its value, and the checks depending on it are
    not re-run into "couldn't check"."""
    from daprivacyscanner import helper

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json")},
                     files={"/etc/crypttab": "luks-x UUID=y none tpm2-device=auto\n"})
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    host.privileged = FakePrivileged(luks={"/dev/nvme0n1p3": sample("luksdump/luks2-tpm2-no-pin.txt")})
    first = Runner(cat, host).scan().to_dict()
    assert first["context"]["values"]["tpm_unlock_no_pin"]["value"] is True
    host.privileged = None
    again = Runner(cat, host).rescan(["auth.screen_lock"], first["context"])
    assert again.kept_context == ["tpm_unlock_no_pin"] and again.context["tpm_unlock_no_pin"] is True
    assert "enc.tpm_no_pin" not in again.results and "auth.autologin" not in again.results


def test_what_needs_administrator_access_says_so(cat, tmp_path):
    """needs_root() and an unreadable file in a system check without root: couldn't check, and a
    scan with administrator access would. Other unknowns don't claim that."""
    from daprivacyscanner.checks._util import needs_root, unknown
    from daprivacyscanner.host import Unreadable

    def unreadable(self, scan):
        raise Unreadable("/etc/shadow")
    report = run(cat, laptop_host(tmp_path), check("enc.luks_weak_kdf", lambda self, scan: needs_root("Reading /etc/shadow")),
                 check("kern.updates", unreadable), check("auth.umask", lambda self, scan: unknown("No idea.")))
    r = report.results
    assert r["enc.luks_weak_kdf"].needs_admin and r["kern.updates"].needs_admin
    assert r["auth.umask"].status is Status.UNKNOWN and not r["auth.umask"].needs_admin
    assert report.to_dict()["results"]["kern.updates"]["needs_admin"] is True


def test_text_report_lists_what_couldnt_be_checked_after_the_findings(cat, tmp_path):
    from daprivacyscanner.checks._util import needs_root
    from daprivacyscanner.report import render_text

    report = run(cat, laptop_host(tmp_path), check("enc.luks_weak_kdf", lambda self, scan: needs_root("Reading /etc/shadow")),
                 check("enc.trash", lambda self, scan: 1 / 0), check("auth.umask", lambda self, scan: Outcome(Status.FAIL, "Open")))
    text = render_text(report.to_dict(), cat, {})
    heads = [ln for ln in text.splitlines() if ln.startswith("== ")]
    assert heads[0].startswith("== Findings") and heads[1].startswith("== Couldn't be checked")
    # each line leads with the check's title; its id follows, for reference
    assert f"[admin] {cat['enc.luks_weak_kdf'].title} (enc.luks_weak_kdf)" in text
    assert f"[failed to run] {cat['enc.trash'].title} (enc.trash)" in text and "ZeroDivisionError" in text


def test_a_fix_that_doesnt_cover_this_machine_says_why(cat, tmp_path):
    from daprivacyscanner.checks import No
    c = check("tel.location", lambda self, scan: Outcome(Status.WARN), supports_fix=True,
              can_fix=lambda self, scan, o: No("The fix covers GNOME only; see tel.kde_feedback."))
    r = run(cat, laptop_host(tmp_path), c).results["tel.location"]
    assert not r.fixable and r.no_fix == "The fix covers GNOME only; see “KDE user feedback (telemetry) enabled”."
    assert r.to_dict()["no_fix"] == r.no_fix
    c = check("tel.location", lambda self, scan: Outcome(Status.WARN), supports_fix=True,
              can_fix=lambda self, scan, o: False)
    assert run(cat, laptop_host(tmp_path / "b"), c).results["tel.location"].no_fix == "Fix… doesn't cover this machine."


def test_an_empty_plan_is_not_offered_and_its_notes_say_why(cat, tmp_path):
    from daprivacyscanner.fix import FixPlan
    c = check("tel.devtools", lambda self, scan: Outcome(Status.FAIL), supports_fix=True,
              plan_fix=lambda self, scan, o: FixPlan(self.id, "x", [], side_effects=["Turn it off in the IDE."]))
    r = run(cat, laptop_host(tmp_path), c).results["tel.devtools"]
    assert not r.fixable and r.no_fix == "Turn it off in the IDE." and not r.easy
    blocked = check("tel.devtools", lambda self, scan: Outcome(Status.FAIL), supports_fix=True,
                    plan_fix=lambda self, scan, o: FixPlan(self.id, "x", [], blockers=["Close X first."]))
    r = run(cat, laptop_host(tmp_path / "b"), blocked).results["tel.devtools"]
    assert r.fixable and not r.no_fix                                     # blocked is still offered, greyed with why


def test_a_root_fix_planned_at_the_scan_keeps_administrator_access(cat, tmp_path):
    from daprivacyscanner.fix import FixPlan, RootChange
    from daprivacyscanner.server import needs_root_to_fix
    c = check("tel.location", lambda self, scan: Outcome(Status.WARN), supports_fix=True,
              can_fix=lambda self, scan, o: True,
              plan_fix=lambda self, scan, o: FixPlan(self.id, "x", [RootChange("write_dropin", {}, "x")]))
    r = run(cat, laptop_host(tmp_path), c).results["tel.location"]
    assert r.fix_root and needs_root_to_fix(cat, r.to_dict())


def test_every_fix_condition_gives_its_reason(cat, tmp_path):
    """A fix or guide that doesn't cover a machine says why (No), never a bare False: the page
    shows the reason in place of the button."""
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.checks.fixes import FIXES
    from daprivacyscanner.checks.guides import GUIDES
    from conftest import make_scan
    load_all()
    bare = make_scan(make_host(tmp_path), desktop=("lxqt",))
    for check_id, entry in {**FIXES, **GUIDES}.items():
        if entry.can is not None:
            r = entry.can(bare)
            assert r is True or (not r and str(r).strip()), f"{check_id}: {r!r}"


def test_results_name_other_checks_by_title(cat, tmp_path):
    """A check that refers to another by id in its summary or a note ("see enc.fde_missing") shows its title."""
    from daprivacyscanner.model import Note
    c = check("enc.swap_unencrypted", lambda self, scan: Outcome(Status.FAIL, "Swap is plain; see enc.fde_missing.",
              notes=[Note("info", "About enc.fde_missing", "Encrypt the disk (enc.fde_missing) first.", ("enc.fde_missing",))]))
    r = run(cat, laptop_host(tmp_path), c).results["enc.swap_unencrypted"]
    title = "“" + cat["enc.fde_missing"].title + "”"
    assert r.summary == f"Swap is plain; see {title}."
    assert r.notes[0].title == f"About {title}" and r.notes[0].text == f"Encrypt the disk ({title}) first."
    assert r.notes[0].related == ("enc.fde_missing",)         # the chips keep the id: the page shows the title


def test_a_warning_is_rated_below_the_same_check_failing(cat, tmp_path):
    """auth.screen_lock is 7 on a laptop as a problem; as a risk it is warn_lower (4) less, says why, and is marked."""
    spec = cat["auth.screen_lock"]
    fail = run(cat, laptop_host(tmp_path / "f"), check(spec.id, lambda self, scan: Outcome(Status.FAIL, "Never locks"))).results[spec.id]
    warn = run(cat, laptop_host(tmp_path / "w"), check(spec.id, lambda self, scan: Outcome(Status.WARN, "Locks late"))).results[spec.id]
    assert fail.effective_severity == 7 and not fail.as_warning and fail.severity_reason == ""
    assert warn.effective_severity == 7 - spec.warn_lower == 3 and warn.as_warning
    assert warn.severity_reason == "it is a risk rather than a confirmed problem (4 lower, never below 1)"
    assert warn.to_dict()["as_warning"] is True and "as_warning" not in fail.to_dict()
    # never below 1: a low-severity check's warning stays a finding
    low = run(cat, laptop_host(tmp_path / "l"), check("tel.location", lambda self, scan: Outcome(Status.WARN, "Apps can ask"))).results["tel.location"]
    assert low.effective_severity == 1 and low.found


def test_text_report_says_problem_or_risk_and_puts_problems_first(cat, tmp_path):
    from daprivacyscanner.report import render_text
    report = run(cat, laptop_host(tmp_path), check("tel.location", lambda self, scan: Outcome(Status.WARN, "Apps can ask")),
                 check("auth.screen_lock", lambda self, scan: Outcome(Status.FAIL, "Never locks")))
    text = render_text(report.to_dict(), cat, {})
    assert f"[7] Problem: {cat['auth.screen_lock'].title} (auth.screen_lock)" in text
    assert f"[1] Risk: {cat['tel.location'].title} (tel.location)" in text
    assert text.index("Problem: ") < text.index("Risk: ")
