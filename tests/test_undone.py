"""A fix the user applied, undone since: found on the next scan and shown loudly everywhere."""

import json
import os

from fastapi.testclient import TestClient

from daprivacyscanner.fix import ACTION_KINDS
from daprivacyscanner.server import create_app
from daprivacyscanner.undo import UndoLog

from conftest import make_host, sample
from fakes import FakeGSettings
from test_server import LSBLK, TOKEN

H = {"X-Token": TOKEN}
KEY = ("org.gnome.system.location", "enabled")


def fixed_location(cat, tmp_path):
    """Location services turned off through the app, as the user would."""
    gs = FakeGSettings({KEY: "true"})
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "GNOME"}, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    host.runner.handlers["gsettings"] = gs
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
    c.post("/api/scan", headers=H)
    plan = c.post("/api/fix/tel.location/plan", headers=H).json()["plan"]
    applied = c.post("/api/fix/apply", headers=H, json={"plan_id": plan["id"]}).json()
    assert applied["ok"] and applied["result"]["status"] == "pass" and applied["undone"] == []
    return c, host, gs


def test_a_fix_changed_back_is_found_by_the_next_scan(cat, tmp_path):
    c, host, gs = fixed_location(cat, tmp_path)
    gs.values[KEY] = "true"                                   # an update, a sync or another app turns it back on
    report = c.post("/api/scan", headers=H).json()
    [u] = report["undone"]
    assert u["check_id"] == "tel.location" and u["severity"] > 0
    assert u["changed_back"] == ["org.gnome.system.location enabled is true again (the fix set false)"]
    # the text report leads with it, and the finding says so too
    text = c.get("/api/report", headers=H).text
    assert "!! 1 FIX UNDONE: a problem you fixed is back" in text.split("Context:")[0]
    assert "You fixed this, and it has been undone since" in text
    # History marks the entry
    [entry] = c.get("/api/undo", headers=H).json()["entries"]
    assert entry["undone_since"] and entry["state"] == "applied"
    # it stays on the restored report the app opens on next time
    restarted = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
    assert restarted.get("/api/state", headers=H).json()["report"]["undone"][0]["check_id"] == "tel.location"


def test_fixing_it_again_accepting_it_or_reverting_it_clears_the_alarm(cat, tmp_path):
    c, host, gs = fixed_location(cat, tmp_path)
    gs.values[KEY] = "true"
    assert c.post("/api/scan", headers=H).json()["undone"]
    # accepted on purpose: quiet; un-accepted: loud again
    assert c.post("/api/accept", headers=H, json={"check_id": "tel.location", "accept": True}).json()["undone"] == []
    assert c.post("/api/accept", headers=H, json={"check_id": "tel.location", "accept": False}).json()["undone"]
    # fixed again
    plan = c.post("/api/fix/tel.location/plan", headers=H).json()["plan"]
    assert c.post("/api/fix/apply", headers=H, json={"plan_id": plan["id"]}).json()["undone"] == []
    assert c.post("/api/scan", headers=H).json()["undone"] == []
    assert not any(e["undone_since"] for e in c.get("/api/undo", headers=H).json()["entries"])


def test_a_fix_reverted_from_history_is_not_an_alarm(cat, tmp_path):
    c, host, gs = fixed_location(cat, tmp_path)
    [entry] = c.get("/api/undo", headers=H).json()["entries"]
    assert c.post(f"/api/undo/{entry['id']}/revert", headers=H, json={}).json()["undone"] == []
    assert c.post("/api/scan", headers=H).json()["undone"] == []


def test_a_fix_that_left_the_problem_in_place_is_not_called_undone(tmp_path):
    """A guided fix that does one step of several: the check was still failing right after it."""
    log = UndoLog(tmp_path / "state")
    log.add("e1", "net.hostname_broadcast", "Stop sending the hostname", [])
    log.set_outcome("e1", {"status": "fail", "effective_severity": 4})
    assert log.undone({"net.hostname_broadcast": {"status": "fail", "effective_severity": 4}}) == []
    # one the scan didn't cover says nothing either way
    log.set_outcome("e1", {"status": "pass", "effective_severity": 4})
    assert log.undone({}) == []
    assert len(log.undone({"net.hostname_broadcast": {"status": "warn", "effective_severity": 4}})) == 1


def test_steps_say_what_was_changed_back(tmp_path):
    host = make_host(tmp_path)
    f = tmp_path / "conf"
    f.write_text("new\n")
    os.chmod(f, 0o600)
    from daprivacyscanner.fix import _sha
    write = {"kind": "file", "path": str(f), "display": "~/conf", "after_sha": _sha(b"new\n")}
    mode = {"kind": "chmod", "path": str(f), "display": "~/conf", "after": 0o600}
    assert ACTION_KINDS["file"].changed_back(write, host) is None
    assert ACTION_KINDS["chmod"].changed_back(mode, host) is None
    f.write_text("old\n")
    os.chmod(f, 0o644)
    assert ACTION_KINDS["file"].changed_back(write, host) == "~/conf was edited since"
    assert ACTION_KINDS["chmod"].changed_back(mode, host) == "~/conf is mode 644 again (the fix set 600)"
    prefs = tmp_path / "prof"
    prefs.mkdir()
    (prefs / "prefs.js").write_text('user_pref("toolkit.telemetry.enabled", true);\n')
    rec = {"kind": "ffpref", "profile": str(prefs), "label": "Firefox", "key": "toolkit.telemetry.enabled", "after": False}
    assert ACTION_KINDS["ffpref"].changed_back(rec, host) == \
        "Firefox: toolkit.telemetry.enabled is true again (the fix set false)"


def test_redacted_reports_hide_what_was_changed_back(cat, tmp_path):
    c, host, gs = fixed_location(cat, tmp_path)
    gs.values[KEY] = "true"
    c.post("/api/scan", headers=H)
    data = json.loads(c.get("/api/report?format=json&redact=1", headers=H).text)
    assert data["report"]["undone"][0]["check_id"] == "tel.location"


def test_the_terminal_scan_warns_and_notifies(cat, tmp_path, monkeypatch, capsys):
    from daprivacyscanner import app as app_mod
    from daprivacyscanner.host import Host

    c, host, gs = fixed_location(cat, tmp_path)
    gs.values[KEY] = "true"
    monkeypatch.setattr(Host, "local", classmethod(lambda cls: host))
    app_mod.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=False, redact=False)
    out = capsys.readouterr().out
    assert "!! 1 FIX UNDONE" in out.split("Context:")[0]
    [note] = [call for call in host.runner.calls if call[0] == "notify-send" and "--urgency=critical" in call]
    # counted, never named: the lock screen and a notification history would show what is weak here
    assert "1 fix undone" in note[-2] and "Location" not in note[-1] and "Open the app" in note[-1]
    # found once: the next scheduled scan doesn't notify about it again
    host.runner.calls.clear()
    app_mod.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=True, redact=False)
    assert not [call for call in host.runner.calls if call[0] == "notify-send" and "--urgency=critical" in call]


def test_caches_growing_back_after_a_clean_up_is_not_undone(tmp_path):
    log = UndoLog(tmp_path / "state")
    log.add("e1", "desk.thumbnails", "Clean the thumbnail cache", [])
    log.set_outcome("e1", {"status": "pass", "effective_severity": 3})
    assert log.undone({"desk.thumbnails": {"status": "fail", "effective_severity": 3, "kind": "hygiene"}}) == []



def test_a_clean_up_that_only_deleted_files_is_never_undone(tmp_path):
    """What it deleted comes back with use; and it doesn't hide an earlier fix of the same check
    whose setting has been changed back."""
    log = UndoLog(tmp_path / "state")
    log.add("e1", "desk.thumbnails", "Keep the thumbnail cache in memory", [{"kind": "root", "change_id": "c1"}])
    log.set_outcome("e1", {"status": "pass", "effective_severity": 2})
    log.add("e2", "desk.thumbnails", "Delete thumbnails of deleted files",
            [{"kind": "delete", "root": "~/.cache/thumbnails", "deleted": 3}])
    log.set_outcome("e2", {"status": "pass", "effective_severity": 4})
    [u] = log.undone({"desk.thumbnails": {"status": "warn", "effective_severity": 2}})
    assert u["entry_id"] == "e1"
    log.add("e3", "app.editor_residue", "Delete editor swap files", [{"kind": "delete", "root": "~", "deleted": 1}])
    log.set_outcome("e3", {"status": "pass", "effective_severity": 3})
    assert log.undone({"app.editor_residue": {"status": "fail", "effective_severity": 3}}) == []


def test_thumbnails_leaking_again_after_a_clean_up_notify_as_worse(cat, tmp_path, monkeypatch):
    """The clean-up isn't reported undone, but thumbnails of deleted pictures turn the warning
    (cache on disk, severity 2) into a failure (4): the scheduled scan says it got worse."""
    from daprivacyscanner import app as app_mod
    from daprivacyscanner.host import Host
    from test_checks_telemetry_browser import png

    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "GNOME"}, commands={LSBLK: sample("lsblk/debian-12-partial.json")})
    monkeypatch.setattr(Host, "local", classmethod(lambda cls: host))
    log = UndoLog.for_user(__import__("daprivacyscanner.paths", fromlist=["PathResolver"]).PathResolver(host.home, host.environ))
    log.add("e1", "desk.thumbnails", "Delete thumbnails of deleted files", [{"kind": "delete", "root": "~", "deleted": 2}])
    log.set_outcome("e1", {"status": "warn", "effective_severity": 2})
    app_mod.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=True, redact=False)
    host.runner.calls.clear()
    d = host.home / ".cache/thumbnails/normal"
    d.mkdir(parents=True)
    (d / "a.png").write_bytes(png((host.home / "deleted.jpg").as_uri()))
    app_mod.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=True, redact=False)
    notes = [c for c in host.runner.calls if c[0] == "notify-send"]
    assert not [c for c in notes if "--urgency=critical" in c]                  # not "undone"
    [note] = notes
    assert "1 finding got worse" in note[-2] and cat["desk.thumbnails"].title not in " ".join(note)
