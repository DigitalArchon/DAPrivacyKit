from fastapi.testclient import TestClient

from daprivacyscanner import blockdev
from daprivacyscanner.server import create_app

from conftest import make_host, sample

TOKEN = "t0ken"
LSBLK = ("lsblk", "-J", "-o", blockdev.COLUMNS)


def client(cat, tmp_path, **kw):
    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    return TestClient(create_app(TOKEN, cat, make_host=lambda: host, **kw))


def test_api_needs_the_token(cat, tmp_path):
    c = client(cat, tmp_path)
    assert c.get("/api/state").status_code == 403
    assert c.get("/api/state", headers={"X-Token": "wrong"}).status_code == 403
    assert c.post("/api/scan").status_code == 403


def test_page_and_static_files_are_served(cat, tmp_path):
    c = client(cat, tmp_path)
    page = c.get("/")
    assert page.status_code == 200 and "Content-Security-Policy" in page.text
    for f in ("app.js", "style.css", "icon.svg"):
        assert c.get(f"/static/{f}").status_code == 200


def test_state_then_scan(cat, tmp_path):
    c = client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    state = c.get("/api/state", headers=h).json()
    assert len(state["catalogue"]) == len(cat) and state["report"] is None and not state["can_quit"]
    report = c.post("/api/scan", headers=h).json()
    assert report["context"]["values"]["fde"]["value"] == "partial"
    partial = report["results"]["enc.partial_fde"]
    assert (partial["status"], partial["effective_severity"]) == ("fail", 8)
    assert c.get("/api/state", headers=h).json()["report"]["started"] == report["started"]


def test_quit_only_when_offered(cat, tmp_path):
    quit_called = []
    c = client(cat, tmp_path, on_quit=lambda: quit_called.append(1))
    assert c.get("/api/state", headers={"X-Token": TOKEN}).json()["can_quit"]
    assert c.post("/api/quit", headers={"X-Token": TOKEN}).json() == {"ok": True}
    assert client(cat, tmp_path / "b").post("/api/quit", headers={"X-Token": TOKEN}).status_code in (404, 405)


def test_scan_with_administrator_access(cat, tmp_path):
    from daprivacyscanner.privileged import FakePrivileged

    helper = FakePrivileged(luks={"/dev/sda3": sample("luksdump/luks2-tpm2-no-pin.txt")})
    closed = []
    helper.close = lambda: closed.append(1)
    c = client(cat, tmp_path, start_helper=lambda: helper)
    report = c.post("/api/scan", headers={"X-Token": TOKEN}, json={"admin": True}).json()
    assert report["admin"] == {"requested": True, "granted": True, "message": "", "dropped": False} and report["privileged"]
    assert report["context"]["values"]["tpm_unlock_no_pin"]["value"] is True
    assert closed == [] and report["admin_active"]         # kept for the fixes that follow
    assert c.get("/api/state", headers={"X-Token": TOKEN}).json()["admin_active"]
    assert c.post("/api/admin/drop", headers={"X-Token": TOKEN}).json() == {"admin_active": False}
    assert closed == [1]


def test_a_later_scan_uses_access_already_granted(cat, tmp_path):
    from daprivacyscanner.privileged import FakePrivileged

    started = []
    c = client(cat, tmp_path, start_helper=lambda: started.append(1) or FakePrivileged())
    c.post("/api/scan", headers={"X-Token": TOKEN}, json={"admin": True})
    again = c.post("/api/scan", headers={"X-Token": TOKEN}, json={"admin": False}).json()
    assert again["privileged"] and again["admin_active"] and started == [1]


def test_administrator_access_ends_when_idle(cat, tmp_path):
    from daprivacyscanner.privileged import FakePrivileged
    from daprivacyscanner.server import AdminSession

    helper, closed = FakePrivileged(), []
    helper.close = lambda: closed.append(1)
    session = AdminSession(lambda: helper, idle=0)
    assert session.get(prompt=True) is helper
    assert not session.active() and closed == [1]


def test_the_prompt_holds_nothing_else_up_and_one_prompt_serves_every_request(cat, tmp_path):
    """While the password prompt is up, active() answers at once (the page polls it from the event loop: the lock
    used to be held across the prompt, and every request waited on it); a second request asking meanwhile
    waits for that prompt's answer rather than putting up another, and shares a refusal."""
    import threading
    import time
    from daprivacyscanner.privileged import FakePrivileged, HelperDeclined
    from daprivacyscanner.server import AdminSession

    for outcome in ("granted", "declined"):
        asked, answer, helper = threading.Event(), threading.Event(), FakePrivileged()

        def start():
            asked.set()
            answer.wait(5)
            if outcome == "declined":
                raise HelperDeclined("Administrator access was declined.")
            return helper
        session = AdminSession(start)
        got: list = []

        def ask():
            try:
                got.append(session.get(prompt=True))
            except HelperDeclined as e:
                got.append(str(e))
        first = threading.Thread(target=ask)
        first.start()
        assert asked.wait(5)
        t0 = time.monotonic()
        assert session.active() is False and time.monotonic() - t0 < 1             # not held up by the prompt
        assert session.get(prompt=False) is None
        second = threading.Thread(target=ask)
        second.start()
        time.sleep(0.2)
        assert got == [], "the second request waits for the prompt that is up, and no second prompt appears"
        answer.set()
        first.join(5)
        second.join(5)
        if outcome == "granted":
            assert got == [helper, helper] and session.active()
        else:
            assert got == ["Administrator access was declined."] * 2 and not session.active()


def test_declined_administrator_access_still_scans(cat, tmp_path):
    from daprivacyscanner.privileged import HelperDeclined

    def decline():
        raise HelperDeclined("Administrator access was declined.")

    c = client(cat, tmp_path, start_helper=decline)
    report = c.post("/api/scan", headers={"X-Token": TOKEN}, json={"admin": True}).json()
    assert report["admin"]["granted"] is False and "declined" in report["admin"]["message"]
    assert not report["privileged"]
    assert report["context"]["values"]["tpm_unlock_no_pin"]["value"] is None


def test_plain_scan_never_asks_for_root(cat, tmp_path):
    def must_not_run():
        raise AssertionError("asked for root")

    c = client(cat, tmp_path, start_helper=must_not_run)
    assert c.post("/api/scan", headers={"X-Token": TOKEN}).json()["admin"]["requested"] is False


def fix_client(cat, tmp_path):
    from fakes import FakeGSettings

    gs = FakeGSettings({("org.gnome.system.location", "enabled"): "true"})
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "GNOME"},
                     home_files={".local/share/Trash/files/a.pdf": "x", ".local/share/Trash/info/a.pdf.trashinfo": "i"})
    host.runner.handlers["gsettings"] = gs
    return TestClient(create_app(TOKEN, cat, make_host=lambda: host)), host, gs


def test_fix_plan_apply_and_revert_through_the_api(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    c.post("/api/scan", headers=h)
    r = c.post("/api/fix/tel.location/plan", headers=h).json()
    assert r["plan"]["steps"][0]["text"] == "gsettings set org.gnome.system.location enabled false"
    assert gs.values[("org.gnome.system.location", "enabled")] == "true"           # the dry run changed nothing
    applied = c.post("/api/fix/apply", headers=h, json={"plan_id": r["plan"]["id"]}).json()
    assert applied["ok"] and applied["result"]["status"] == "pass"
    # the answer carries the History entry as made: what it did, exactly, for the page to show at once
    assert applied["entry"]["id"] == applied["entry_id"] and applied["entry"]["via_text"] == "Applied with its Fix… button"
    assert applied["entry"]["steps"][0]["commands"] == ["gsettings set org.gnome.system.location enabled false"]
    assert c.get("/api/state", headers=h).json()["report"]["results"]["tel.location"]["status"] == "pass"
    [entry] = c.get("/api/undo", headers=h).json()["entries"]
    assert entry["can_revert"] and entry == applied["entry"]
    reverted = c.post(f"/api/undo/{entry['id']}/revert", headers=h, json={}).json()
    assert reverted["ok"] and reverted["entry"]["state"] == "reverted" and reverted["result"]["status"] == "fail"
    assert gs.values[("org.gnome.system.location", "enabled")] == "true"


def test_plans_are_used_once_and_deletions_need_confirmation(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    plan = c.post("/api/fix/enc.trash/plan", headers=h).json()["plan"]
    assert plan["irreversible_files"] == 2
    r = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]})
    assert r.status_code == 400 and "confirm" in r.json()["error"]
    assert (host.home / ".local/share/Trash/files/a.pdf").exists()
    r = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"], "confirm_irreversible": True})
    assert r.status_code == 400 and "expired" in r.json()["error"]                  # a refused plan is spent
    plan = c.post("/api/fix/enc.trash/plan", headers=h).json()["plan"]
    assert c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"], "confirm_irreversible": True}).json()["ok"]
    assert not (host.home / ".local/share/Trash/files/a.pdf").exists()


def test_fix_endpoints_need_the_token_and_a_fixable_check(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    assert c.post("/api/fix/tel.location/plan").status_code == 403
    assert c.get("/api/undo").status_code == 403
    r = c.post("/api/fix/enc.fde_missing/plan", headers={"X-Token": TOKEN})          # advice tier
    assert r.status_code == 400


# ------------------------------------------------------------------ root fixes and guides

def root_client(cat, tmp_path, monkeypatch, start_helper):
    from daprivacyscanner import helper

    host = make_host(tmp_path, files={"/etc/yum.repos.d/fedora.repo": "[fedora]\nname=Fedora\nenabled=1\ncountme=1\n"})
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    return TestClient(create_app(TOKEN, cat, make_host=lambda: host, start_helper=start_helper)), host


def test_a_root_fix_asks_for_administrator_access_when_applied(cat, tmp_path, monkeypatch):
    from daprivacyscanner.privileged import FakePrivileged

    asked = []

    def start():
        asked.append(1)
        return FakePrivileged()

    c, host = root_client(cat, tmp_path, monkeypatch, start)
    h = {"X-Token": TOKEN}
    r = c.post("/api/fix/tel.countme/plan", headers=h).json()
    assert r["plan"]["needs_root"] and not asked                       # the dry run needs no root
    applied = c.post("/api/fix/apply", headers=h, json={"plan_id": r["plan"]["id"]}).json()
    assert applied["ok"] and asked == [1] and applied["result"]["status"] == "pass"
    assert "countme=0" in (host.root / "etc/yum.repos.d/fedora.repo").read_text()
    [entry] = c.get("/api/undo", headers=h).json()["entries"]
    assert entry["needs_root"]
    assert c.post(f"/api/undo/{entry['id']}/revert", headers=h, json={}).json()["ok"]
    assert "countme=1" in (host.root / "etc/yum.repos.d/fedora.repo").read_text() and asked == [1]


def test_declining_root_changes_nothing(cat, tmp_path, monkeypatch):
    from daprivacyscanner.privileged import HelperDeclined

    def decline():
        raise HelperDeclined("declined")

    c, host = root_client(cat, tmp_path, monkeypatch, decline)
    h = {"X-Token": TOKEN}
    plan = c.post("/api/fix/tel.countme/plan", headers=h).json()["plan"]
    r = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]})
    assert r.status_code == 403 and r.json()["declined"] and "countme=1" in (host.root / "etc/yum.repos.d/fedora.repo").read_text()
    assert c.get("/api/undo", headers=h).json()["entries"] == []


def test_guide_through_the_api(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    host.home.chmod(0o755)
    h = {"X-Token": TOKEN}
    r = c.post("/api/fix/auth.home_world_readable/plan", headers=h).json()
    guide = r["guide"]
    assert guide["check_id"] == "auth.home_world_readable" and "Step 1" in r["dry_run"]
    [step] = guide["steps"]
    assert [o["label"] for o in step["options"]][0].startswith("Only you, and members")
    assert (host.home.stat().st_mode & 0o777) == 0o755                              # building it changed nothing
    plan = step["options"][1]["plan"]
    assert plan["via"] == {"guide": guide["title"], "step": 1, "step_title": step["title"],
                           "option": step["options"][1]["label"], "options": len(step["options"])}
    applied = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]}).json()
    assert applied["result"]["status"] == "pass"
    assert (host.home.stat().st_mode & 0o777) == 0o700
    # History says which guide, step and option the change came from
    assert applied["entry"]["via_text"] == f"From the guide “{guide['title']}”, step 1 ({step['title']}), " \
                                           f"the option “{step['options'][1]['label']}”"
    assert applied["entry"]["steps"][0]["commands"] == [f"chmod 700 {host.home}"]


# ------------------------------------------------------------------ access: launch token, session token, Host

def test_launch_token_is_exchanged_once_for_the_session_token(cat, tmp_path):
    """The page gets the session token in its body, once, and keeps it in its session storage (an origin's own,
    port included): never a cookie, which the browser would send to every other local server on 127.0.0.1."""
    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host, launch_token="launch1", allowed_hosts={"testserver"}))
    assert c.get("/?t=%FF").status_code == 403                                       # not a 500 on odd bytes
    r = c.get("/?t=launch1")
    assert r.status_code == 200 and f'<body data-token="{TOKEN}">' in r.text and r.headers["cache-control"] == "no-store"
    assert "set-cookie" not in r.headers and not c.cookies
    assert c.get("/?t=launch1").status_code == 403                                   # used once
    plain = c.get("/")
    assert plain.status_code == 200 and "data-token" not in plain.text               # the page alone, without the link
    assert c.get("/api/state").status_code == 403                                    # nothing but the header gets in
    assert c.get("/api/state", headers={"X-Requested-With": "daprivacyscanner"}).status_code == 403
    assert c.get("/api/state", headers={b"X-Token": b"\xff" + TOKEN.encode()}).status_code == 403   # not a 500
    assert c.get("/api/state", headers={"X-Token": TOKEN}).status_code == 200
    assert c.get("/api/state", headers={"X-Token": TOKEN, "Host": "evil.example"}).status_code == 421


def test_report_export_and_redaction(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "alice"}, commands={LSBLK: sample("lsblk/debian-12-partial.json")},
                     files={"/proc/sys/kernel/hostname": "alice-laptop\n"})
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
    h = {"X-Token": TOKEN}
    assert c.get("/api/report", headers=h).status_code == 400
    c.post("/api/scan", headers=h)
    text = c.get("/api/report", headers=h).text
    assert text.startswith("DA Privacy Kit report") and "alice-laptop" in text and "== Findings" in text
    red = c.get("/api/report?redact=1", headers=h).text
    assert "alice" not in red and "[redacted]" in red and "(redacted)" in red.splitlines()[0]
    data = c.get("/api/report?format=json&redact=1", headers=h).json()
    assert data["report"]["redacted"] and data["format"] == "daprivacyscanner-report"


def test_accept_a_finding(cat, tmp_path):
    c = client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    assert c.post("/api/accept", headers=h, json={"check_id": "enc.nope", "accept": True}).status_code == 404
    r = c.post("/api/accept", headers=h, json={"check_id": "enc.partial_fde", "accept": True, "note": "data disk is scratch"}).json()
    assert r["accepted"]["enc.partial_fde"]["note"] == "data disk is scratch"
    assert c.get("/api/state", headers=h).json()["accepted"].keys() == {"enc.partial_fde"}
    assert c.post("/api/accept", headers=h, json={"check_id": "enc.partial_fde", "accept": False}).json()["accepted"] == {}


def test_an_accepted_finding_is_hidden_until_its_severity_rises(cat, tmp_path):
    """Accepted at its severity now; the export lists it apart. If the severity is higher later,
    it is a finding again, with the reason."""
    from daprivacyscanner.history import Accepted
    from daprivacyscanner.paths import PathResolver

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
    h = {"X-Token": TOKEN}
    sev = c.post("/api/scan", headers=h).json()["results"]["enc.partial_fde"]["effective_severity"]
    rec = c.post("/api/accept", headers=h, json={"check_id": "enc.partial_fde", "accept": True, "note": "scratch"}).json()
    assert rec["accepted"]["enc.partial_fde"]["severity"] == sev
    text = c.get("/api/report", headers=h).text
    assert text.index("enc.partial_fde") > text.index("== Accepted risks")
    # as if it had been accepted when it rated lower
    Accepted(PathResolver(host.home, host.environ)).set("enc.partial_fde", True, "scratch", sev - 2, "")
    text = c.get("/api/report", headers=h).text
    assert "== Accepted risks" not in text and f"its severity rose from {sev - 2} to {sev}" in text


def test_scan_reports_changes_since_the_last_one(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    first = c.post("/api/scan", headers=h).json()
    assert first["changes"] is None
    gs.values[("org.gnome.system.location", "enabled")] = "false"
    second = c.post("/api/scan", headers=h).json()
    assert "tel.location" in second["changes"]["resolved"] and second["changes"]["previous"] == first["started"]
    assert c.get("/api/state", headers=h).json()["last_scan"] == second["started"]


def test_there_is_no_fix_everything(cat, tmp_path):
    """Fixes are applied one check at a time, each after its own dry run: a single button for all
    of them put deletions and settings changes behind one confirmation."""
    c = client(cat, tmp_path)
    c.post("/api/scan", headers={"X-Token": TOKEN})
    assert c.post("/api/fix/plan-all", headers={"X-Token": TOKEN}).status_code in (404, 405)


def test_forget_history(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    c.post("/api/scan", headers=h)
    plan = c.post("/api/fix/tel.location/plan", headers=h).json()["plan"]
    c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]})
    assert c.post("/api/undo/forget", headers=h, json={}).json()["forgotten"] == 0        # applied, and recent
    r = c.post("/api/undo/forget", headers=h, json={"everything": True}).json()
    assert r["forgotten"] == 1 and r["entries"] == []


def test_a_fix_that_changes_the_context_recomputes_dependents(cat, tmp_path, monkeypatch):
    """Turning off autologin changes the `autologin` context key, so enc.tpm_no_pin (whose severity
    depends on it) is re-run and the context pane is updated, not left stale."""
    from daprivacyscanner import helper
    from daprivacyscanner.privileged import FakePrivileged

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json")},
                     files={"/etc/gdm/custom.conf": "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n",
                            "/etc/crypttab": "luks-x UUID=y none tpm2-device=auto\n"},
                     links={"/etc/systemd/system/display-manager.service": "/usr/lib/systemd/system/gdm.service"})
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    helper_obj = FakePrivileged(luks={"/dev/nvme0n1p3": sample("luksdump/luks2-tpm2-no-pin.txt")})
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host, start_helper=lambda: helper_obj))
    h = {"X-Token": TOKEN}
    report = c.post("/api/scan", headers=h, json={"admin": True}).json()
    assert report["context"]["values"]["autologin"]["value"] is True
    assert report["results"]["enc.tpm_no_pin"]["effective_severity"] == 10
    guide = c.post("/api/fix/auth.autologin/plan", headers=h).json()["guide"]
    plan = next(o["plan"] for s in guide["steps"] for o in s["options"])
    r = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]}).json()
    assert r["ok"] and r["result"]["status"] == "pass"
    assert r["context"]["values"]["autologin"]["value"] is False
    assert "enc.tpm_no_pin" in r["rechecked"] and r["rechecked"]["enc.tpm_no_pin"]["effective_severity"] == 6
    state = c.get("/api/state", headers=h).json()["report"]
    assert state["context"]["values"]["autologin"]["value"] is False
    assert state["results"]["enc.tpm_no_pin"]["effective_severity"] == 6


def test_a_fix_on_a_restored_report_recomputes_dependents(cat, tmp_path, monkeypatch):
    """The app reopened on the saved report (no scan since): the autologin fix still re-runs
    the checks whose severity depends on autologin."""
    from daprivacyscanner import helper
    from daprivacyscanner.privileged import FakePrivileged

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json")},
                     files={"/etc/gdm/custom.conf": "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n",
                            "/etc/crypttab": "luks-x UUID=y none tpm2-device=auto\n"},
                     links={"/etc/systemd/system/display-manager.service": "/usr/lib/systemd/system/gdm.service"})
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    helper_obj = FakePrivileged(luks={"/dev/nvme0n1p3": sample("luksdump/luks2-tpm2-no-pin.txt")})
    h = {"X-Token": TOKEN}
    TestClient(create_app(TOKEN, cat, make_host=lambda: host, start_helper=lambda: helper_obj)).post(
        "/api/scan", headers=h, json={"admin": True})
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host, start_helper=lambda: helper_obj))
    restored = c.get("/api/state", headers=h).json()["report"]
    assert restored["restored"] and restored["results"]["enc.tpm_no_pin"]["effective_severity"] == 10
    guide = c.post("/api/fix/auth.autologin/plan", headers=h).json()["guide"]
    plan = next(o["plan"] for s in guide["steps"] for o in s["options"])
    r = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]}).json()
    assert r["ok"] and r["context"]["values"]["autologin"]["value"] is False
    assert r["rechecked"]["enc.tpm_no_pin"]["effective_severity"] == 6


def test_root_is_dropped_after_a_scan_with_nothing_for_it_to_fix(cat, tmp_path, monkeypatch):
    from daprivacyscanner import server
    from daprivacyscanner.privileged import FakePrivileged

    helper = FakePrivileged()
    closed = []
    helper.close = lambda: closed.append(1)
    c = client(cat, tmp_path, start_helper=lambda: helper)
    report = c.post("/api/scan", headers={"X-Token": TOKEN}, json={"admin": True}).json()
    assert report["admin"]["granted"] and not report["admin"]["dropped"] and report["admin_active"]   # root fixes waiting
    monkeypatch.setattr(server, "needs_root_to_fix", lambda catalogue, result: False)
    report = c.post("/api/scan", headers={"X-Token": TOKEN}, json={"admin": True}).json()
    assert report["admin"]["dropped"] and not report["admin_active"] and closed == [1]


# ------------------------------------------------------------------ the terminal scan and capture

def test_scan_cli_prints_text_or_json_and_sets_the_exit_status(cat, tmp_path, monkeypatch, capsys):
    from daprivacyscanner import app as app_mod
    from daprivacyscanner.host import Host

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    monkeypatch.setattr(Host, "local", classmethod(lambda cls: host))
    assert app_mod.scan_cli(cat, as_json=False, notify=False, admin=False, quiet=False, redact=False) == 1
    out = capsys.readouterr().out
    assert out.startswith("DA Privacy Kit report") and "enc.partial_fde" in out
    assert (host.home / ".local/state/daprivacyscanner/last-report.json").exists()     # the app opens on it
    assert app_mod.scan_cli(cat, as_json=True, notify=True, admin=False, quiet=False, redact=True) == 1
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["report"]["redacted"] and data["report"]["changes"] is not None
    assert ("notify-send",) not in {c[:1] for c in host.runner.calls}          # nothing new since the first scan


def test_scan_cli_leaves_accepted_findings_out_of_what_changed(cat, tmp_path, monkeypatch, capsys):
    """"Since the last scan" counts nothing the user accepted, new or resolved, as on the page."""
    import json
    import re

    from daprivacyscanner import app as app_mod
    from daprivacyscanner.history import Accepted
    from daprivacyscanner.host import Host
    from daprivacyscanner.paths import PathResolver

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    monkeypatch.setattr(Host, "local", classmethod(lambda cls: host))
    baseline = host.home / ".local/state/daprivacyscanner/last-scan.json"

    def since(passed_before: str, failed_before: str) -> tuple[int, int]:
        data = json.loads(baseline.read_text())
        data["results"][passed_before]["status"] = "pass"          # so it is new in the next scan
        data["results"][failed_before].update(status="fail", severity=5)     # and this one resolved
        baseline.write_text(json.dumps(data))
        app_mod.scan_cli(cat, as_json=False, notify=False, admin=False, quiet=False, redact=False)
        m = re.search(r"Since the last scan: (\d+) new, (\d+) resolved", capsys.readouterr().out)
        return int(m[1]), int(m[2])

    app_mod.scan_cli(cat, as_json=False, notify=False, admin=False, quiet=True, redact=False)
    results = json.loads(baseline.read_text())["results"]
    gone = next(k for k, r in results.items() if r["status"] == "pass" and r["kind"] == "finding")
    assert results["enc.partial_fde"]["status"] == "fail"
    assert since("enc.partial_fde", gone) == (1, 1)
    accepted = Accepted(PathResolver(host.home, host.environ))
    accepted.set("enc.partial_fde", True, severity=10)
    accepted.set(gone, True, severity=10)
    assert since("enc.partial_fde", gone) == (0, 0)


def test_capture_writes_sanitised_samples(tmp_path, capsys):
    from daprivacyscanner import capture

    host = make_host(tmp_path, env={"USER": "alice"}, files={"/proc/sys/kernel/hostname": "alice-box\n",
                                                             "/etc/os-release": 'ID=fedora\nVERSION_ID=40\n'},
                     commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json"), ("ss", "-tulpnH"): sample("ss/fedora-40.txt"),
                               ("cat", "/etc/os-release"): "ID=fedora\nVERSION_ID=40\n",
                               ("bluetoothctl", "show"): "Controller AA:BB:CC:DD:EE:FF (public)\n\tAlias: alice-box\n",
                               ("resolvectl", "status"): "Global\n  DNS Domain: corp.acme.example\nLink 2 (eth0)\n"
                                                         "  Current DNS Server: 10.0.0.1\n  DNS Domain: lan.acme.example\n"})
    written = capture.capture(host, tmp_path / "out")
    rs = (tmp_path / "out/fedora-40/misc/resolvectl-status.txt").read_text()
    assert "acme" not in rs and rs.count("DNS Domain: example.net") == 2 and "10.0.0.1" not in rs
    names = {p.relative_to(tmp_path / "out").as_posix() for p in written}
    assert {"fedora-40/lsblk/lsblk.json", "fedora-40/ss/ss.txt", "fedora-40/README.md"} <= names
    bt = (tmp_path / "out/fedora-40/misc/bluetoothctl-show.txt").read_text()
    assert "AA:BB" not in bt and "alice" not in bt
    assert "skipped" in capsys.readouterr().out                              # commands not installed are listed


def test_last_report_is_restored_on_the_next_start(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    assert c.get("/api/state", headers=h).json()["report"] is None             # nothing saved yet
    report = c.post("/api/scan", headers=h).json()
    saved = host.home / ".local/state/daprivacyscanner/last-report.json"
    assert saved.exists() and oct(saved.stat().st_mode & 0o777) == "0o600"
    again = TestClient(create_app(TOKEN, cat, make_host=lambda: host))        # a new start, same machine
    state = again.get("/api/state", headers=h).json()
    assert state["report"]["restored"] and state["report"]["started"] == report["started"]
    assert state["report"]["results"]["tel.location"]["status"] == "fail"
    assert "restored" not in report                                           # only a loaded report is marked
    # a fix on the restored report works and is saved too
    plan = again.post("/api/fix/tel.location/plan", headers=h).json()["plan"]
    r = again.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]}).json()
    assert r["ok"] and r["result"]["status"] == "pass"
    third = TestClient(create_app(TOKEN, cat, make_host=lambda: host)).get("/api/state", headers=h).json()
    assert third["report"]["results"]["tel.location"]["status"] == "pass"
    # forgetting everything in History drops the saved scan; the next start is blank
    again.post("/api/undo/forget", headers=h, json={"everything": True})
    assert not saved.exists()
    assert TestClient(create_app(TOKEN, cat, make_host=lambda: host)).get("/api/state", headers=h).json()["report"] is None


def test_restored_report_ignores_checks_no_longer_in_the_catalogue(cat, tmp_path):
    import json
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    c.post("/api/scan", headers=h)
    saved = host.home / ".local/state/daprivacyscanner/last-report.json"
    data = json.loads(saved.read_text())
    data["results"]["old.gone"] = data["results"]["tel.location"]
    saved.write_text(json.dumps(data))
    state = TestClient(create_app(TOKEN, cat, make_host=lambda: host)).get("/api/state", headers=h).json()
    assert "old.gone" not in state["report"]["results"]
    assert state["report"]["results"]["tel.location"]["status"] == "fail"
    saved.write_text("not json")
    assert TestClient(create_app(TOKEN, cat, make_host=lambda: host)).get("/api/state", headers=h).json()["report"] is None


def test_plans_carry_the_deletion_note_and_export_everything(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    plan = c.post("/api/fix/enc.trash/plan", headers=h).json()["plan"]
    assert any(e.startswith("Deleted, not wiped") for e in plan["side_effects"])
    assert c.get("/api/export").status_code == 403
    text = c.get("/api/export", headers=h).text
    assert text.startswith("DA Privacy Kit: everything it keeps") and "== Changes made by DA Privacy Kit (0)" in text
    data = c.get("/api/export?format=json&redact=1", headers=h).json()
    assert data["format"] == "daprivacyscanner-export" and data["redacted"] and data["changes"] == []


def test_a_feature_is_set_up_through_its_guide_with_the_users_inputs(cat, tmp_path):
    c, host, gs = fix_client(cat, tmp_path)
    h = {"X-Token": TOKEN}
    g = c.post("/api/fix/desk.ephemeral_folder/plan", headers=h, json={"params": {"size_mb": 300}}).json()["guide"]
    setup = next(s for s in g["steps"] if s["title"] == "Set up ~/Ephemeral")
    assert {i["name"]: i["value"] for i in setup["inputs"]}["size_mb"] == 300
    assert "300 MB" in setup["options"][0]["plan"]["steps"][0]["text"]


def test_a_guide_asks_for_administrator_access_again(cat, tmp_path):
    """Administrator access ended after the scan that found weak LUKS keyslots: opening the guide
    asks for it again rather than turning the finding into "couldn't be checked"; declined, the
    finding stays as it was."""
    from daprivacyscanner.privileged import FakePrivileged, HelperDeclined

    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json")})
    helper_obj = FakePrivileged(luks={"/dev/nvme0n1p3": sample("luksdump/luks1.txt")})
    answer = [helper_obj]

    def start():
        if answer[0] is None:
            raise HelperDeclined("Administrator access was declined.")
        return answer[0]

    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host, start_helper=start))
    h = {"X-Token": TOKEN}
    assert c.post("/api/scan", headers=h, json={"admin": True}).json()["results"]["enc.luks_weak_kdf"]["status"] == "fail"
    c.post("/api/admin/drop", headers=h)
    answer[0] = None
    r = c.post("/api/fix/enc.luks_weak_kdf/plan", headers=h)
    assert r.status_code == 400 and "administrator access" in r.json()["error"]
    assert c.get("/api/state", headers=h).json()["report"]["results"]["enc.luks_weak_kdf"]["status"] == "fail"
    answer[0] = helper_obj
    r = c.post("/api/fix/enc.luks_weak_kdf/plan", headers=h).json()
    assert any("LUKS1" in s["title"] for s in r["guide"]["steps"])


def test_a_backup_kept_for_a_while_can_be_deleted_from_history(cat, tmp_path):
    """History shows until when known_hosts' plain copy is kept, and deletes it on request."""
    from daprivacyscanner.undo import UndoLog
    host = make_host(tmp_path)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    backup = log.backup_dir("e1") / "x-known_hosts"
    backup.parent.mkdir(parents=True)
    backup.write_text("github.com ssh-ed25519 AAAA\n")
    log.add("e1", "auth.ssh_known_hosts_plain", "Hash", [{"kind": "hashkh", "path": str(host.home / ".ssh/known_hosts"),
                                                          "display": "~/.ssh/known_hosts", "backup": str(backup),
                                                          "backup_expires": 4e9, "after_sha": "x", "text": "Hashed"}])
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
    h = {"X-Token": TOKEN}
    [entry] = c.get("/api/undo", headers=h).json()["entries"]
    assert entry["steps"][0]["backup_until"] == 4e9 and entry["steps"][0]["reversible"]
    assert c.post("/api/undo/nope/drop-backup", headers=h, json={}).status_code == 404
    r = c.post("/api/undo/e1/drop-backup", headers=h, json={}).json()
    assert r["dropped"] == 1 and not backup.exists()
    assert r["entry"]["steps"][0]["backup_dropped"] and not r["entry"]["steps"][0]["reversible"]
    assert not r["entry"]["can_revert"]
