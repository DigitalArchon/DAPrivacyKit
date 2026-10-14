"""Easy fixes: the catalogue's `easy` fixes of the checks that fail or warn, each with what it costs,
applied together after one dry run, each as its own fix in History; and `meanwhile`, what is
worth doing until a check the app can't fix is fixed."""

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import catalogue
from daprivacyscanner.catalogue import CatalogueError, Tier
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.fixes import FIXES
from daprivacyscanner.checks.guides import GUIDES
from daprivacyscanner.runner import Runner
from daprivacyscanner.server import create_app

from conftest import make_host
from fakes import FakeGSettings

TOKEN = "t0ken"
H = {"X-Token": TOKEN}
EASY_HERE = ["auth.lockscreen_notifications", "desk.recent_files", "tel.location"]


# ------------------------------------------------------------------ the catalogue

def test_every_easy_fix_is_an_auto_fix_or_a_declared_option_of_a_guide(cat):
    load_all()
    easy = [s for s in cat if s.easy]
    assert len(easy) >= 15
    for s in easy:
        if s.tier is Tier.AUTO:
            assert s.id in FIXES and not s.easy.option, s.id
        else:
            assert s.tier is Tier.GUIDED and s.easy.option in GUIDES[s.id].keys, s.id
    # the user's own examples, and what costs something stays out
    ids = {s.id for s in easy}
    assert {"desk.thumbnails", "enc.tmp_on_disk", "kern.dmesg_restrict"} <= ids
    assert not ids & {"auth.screen_lock", "tel.location", "desk.clipboard_history", "net.firewall_off", "desk.indexers",
                      "enc.swap_unencrypted", "kern.init_on_alloc"}
    assert "after each restart" in cat["desk.thumbnails"].easy.cost


def test_without_disk_encryption_what_to_do_meanwhile(cat):
    mw = cat["enc.fde_missing"].meanwhile
    assert mw.checks[0] == "enc.swap_unencrypted" and "desk.ephemeral_folder" in mw.checks
    assert {"enc.tmp_on_disk", "desk.thumbnails", "enc.coredumps_retained"} <= set(mw.checks)
    assert "Cryptomator" in mw.text and "don't remove what is already on it" in mw.text
    assert "worth backing up your files and reinstalling" in cat["enc.fde_missing"].remedy


BASE = {"id": "enc.x", "title": "X", "category": "encryption", "severity": 3, "scope": "user", "detect": ["d"],
        "fix": "f", "remedy": "r"}


@pytest.mark.parametrize("extra, error", [
    ({"tier": "advice", "easy": True}, "auto and guided checks only"),
    ({"tier": "feature", "easy": True}, "auto and guided checks only"),
    ({"tier": "guided", "easy": True}, "option key"),
    ({"tier": "guided", "easy": {"option": False}}, "option key"),           # YAML's bare `off`
    ({"tier": "auto", "easy": {"option": "x"}}, "takes no `option`"),
    ({"tier": "auto", "easy": {"cost": "c", "when": "fde"}}, "only `option` and `cost`"),
    ({"tier": "guided", "meanwhile": {"text": "t", "checks": ["enc.y"]}}, "for advice checks"),
    ({"tier": "advice", "meanwhile": {"text": "t"}}, "exactly `text` and `checks`"),
    ({"tier": "advice", "meanwhile": {"text": "t", "checks": []}}, "each once"),
    ({"tier": "advice", "meanwhile": {"text": "t", "checks": ["enc.nope"]}}, "meanwhile id 'enc.nope'"),
    ({"tier": "advice", "meanwhile": {"text": "t", "checks": ["enc.x"]}}, "lists the check itself"),
])
def test_easy_and_meanwhile_are_checked(extra, error):
    with pytest.raises(CatalogueError, match=error):
        catalogue.parse({"schema_version": 1, "checks": [{**BASE, **extra}]})


def test_easy_parses(cat):
    c = catalogue.parse({"schema_version": 1, "checks": [{**BASE, "tier": "auto", "easy": True},
                                                         {**BASE, "id": "enc.y", "tier": "guided",
                                                          "easy": {"option": "in_memory", "cost": "Some\n  cost."}}]})
    assert c["enc.x"].easy.to_dict() == {"option": "", "cost": ""}
    assert c["enc.y"].easy.to_dict() == {"option": "in_memory", "cost": "Some cost."}
    assert c["enc.y"].to_dict()["easy"] == {"option": "in_memory", "cost": "Some cost."}


# ------------------------------------------------------------------ the plans

def gnome_host(tmp_path):
    gs = FakeGSettings({
        ("org.gnome.desktop.notifications", "show-in-lock-screen"): "true",
        ("org.gnome.desktop.notifications", "application-children"): "['org-gnome-chat']",
        ("org.gnome.desktop.notifications.application:/org/gnome/desktop/notifications/application/org-gnome-chat/",
         "details-in-lock-screen"): "true",
        ("org.gnome.desktop.privacy", "remember-recent-files"): "true",
        ("org.gnome.desktop.privacy", "recent-files-max-age"): "-1",
        ("org.gnome.system.location", "enabled"): "true"})
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "GNOME"},
                     home_files={".local/share/recently-used.xbel": '<xbel><bookmark href="file:///a"/></xbel>'})
    host.runner.handlers["gsettings"] = gs
    return host, gs


def test_plan_easy_gives_auto_plans_and_the_guides_keyed_options(cat, tmp_path):
    host, gs = gnome_host(tmp_path)
    items = {r.id: (r, plans) for r, plans in Runner(cat, host).plan_easy(EASY_HERE)}
    assert set(items) == {"auth.lockscreen_notifications", "desk.recent_files"}     # location isn't easy
    r, [plan] = items["auth.lockscreen_notifications"]
    assert r.easy and r.found and "show-in-lock-screen false" in plan.dry_run()
    r, [plan] = items["desk.recent_files"]
    assert plan.title == "Keep recent files for at most 30 days"                       # not "Clear it", nor "Stop"
    assert "recent-files-max-age 30" in plan.dry_run() and not plan.irreversible
    assert gs.values[("org.gnome.desktop.privacy", "recent-files-max-age")] == "-1"   # building changed nothing


def test_a_result_is_easy_only_when_its_fix_applies(cat, tmp_path):
    host, gs = gnome_host(tmp_path)
    report = Runner(cat, host).scan(only=EASY_HERE)
    assert report.results["auth.lockscreen_notifications"].easy
    assert not report.results["tel.location"].easy                  # fixable, but not an Easy fix
    assert report.results["desk.recent_files"].to_dict()["easy"] is True


def test_nothing_left_to_change_is_not_offered(cat, tmp_path):
    host, gs = gnome_host(tmp_path)
    gs.values[("org.gnome.desktop.privacy", "recent-files-max-age")] = "30"
    # the list still has entries (a hygiene finding), but the lasting setting is in place: nothing easy left
    assert [r.id for r, _ in Runner(cat, host).plan_easy(["desk.recent_files"])] == []
    # nor counted: the page's "Easy fixes (n)…" and the row's badge go by the result, the dialog by plan_easy
    r = Runner(cat, host).scan(only=["desk.recent_files"]).results["desk.recent_files"]
    assert r.found and r.fixable and not r.easy


# ------------------------------------------------------------------ the server

def easy_client(cat, tmp_path):
    host, gs = gnome_host(tmp_path)
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
    c.post("/api/scan", headers=H)
    return c, host, gs


def test_apply_easy_fixes_each_as_its_own_fix_in_history(cat, tmp_path):
    c, host, gs = easy_client(cat, tmp_path)
    report = c.get("/api/state", headers=H).json()["report"]
    assert report["results"]["auth.lockscreen_notifications"]["easy"]
    items = {it["check_id"]: it for it in c.post("/api/easy/plan", headers=H).json()["items"]}
    assert {"auth.lockscreen_notifications", "desk.recent_files"} <= set(items)
    it = items["desk.recent_files"]
    assert it["cost"] == catalogue.load()["desk.recent_files"].easy.cost and it["kind"] == "hygiene"
    assert not it["needs_root"] and not it["irreversible"] and not it["blockers"]
    assert gs.values[("org.gnome.desktop.notifications", "show-in-lock-screen")] == "true"    # the dry run changed nothing
    ids = [p["id"] for k in ("auth.lockscreen_notifications", "desk.recent_files") for p in items[k]["plans"]]
    r = c.post("/api/easy/apply", headers=H, json={"plan_ids": ids}).json()
    assert r["ok"] and [x["check_id"] for x in r["results"]] == ["auth.lockscreen_notifications", "desk.recent_files"]
    assert gs.values[("org.gnome.desktop.notifications", "show-in-lock-screen")] == "false"
    assert gs.values[("org.gnome.desktop.privacy", "recent-files-max-age")] == "30"
    assert r["rechecked"]["auth.lockscreen_notifications"]["status"] == "pass"
    # each result carries its History entry as made, which says it was applied as an Easy fix
    assert all(x["entry"]["id"] == x["entry_id"] and x["entry"]["via"]["easy"] for x in r["results"])
    assert r["results"][0]["entry"]["via_text"] == "Applied as an Easy fix"
    assert r["results"][0]["entry"]["steps"][0]["commands"] == [
        "gsettings set org.gnome.desktop.notifications show-in-lock-screen false"]
    entries = c.get("/api/undo", headers=H).json()["entries"]
    assert sorted(e["check_id"] for e in entries) == ["auth.lockscreen_notifications", "desk.recent_files"]
    # each reverts on its own
    lock = next(e for e in entries if e["check_id"] == "auth.lockscreen_notifications")
    assert c.post(f"/api/undo/{lock['id']}/revert", headers=H, json={}).json()["ok"]
    assert gs.values[("org.gnome.desktop.notifications", "show-in-lock-screen")] == "true"
    assert gs.values[("org.gnome.desktop.privacy", "recent-files-max-age")] == "30"
    # applied plans are spent
    r = c.post("/api/easy/apply", headers=H, json={"plan_ids": ids})
    assert r.status_code == 400


def test_the_scan_counts_the_easy_fixes_the_dialog_lists(cat, tmp_path):
    """One applied of several: the results marked easy, which the page counts, are the ones still offered,
    right after applying and in the scans that follow."""
    c, host, gs = easy_client(cat, tmp_path)

    def counted():
        results = c.get("/api/state", headers=H).json()["report"]["results"]
        return {k for k, r in results.items() if r["easy"]}

    def listed():
        return {it["check_id"]: it for it in c.post("/api/easy/plan", headers=H).json()["items"]}

    assert counted() == set(listed()) >= {"auth.lockscreen_notifications", "desk.recent_files"}
    before = counted()
    ids = [p["id"] for p in listed()["desk.recent_files"]["plans"]]
    r = c.post("/api/easy/apply", headers=H, json={"plan_ids": ids}).json()
    assert r["ok"] and r["rechecked"]["desk.recent_files"]["status"] != "pass"     # the list still has its entries
    assert not r["rechecked"]["desk.recent_files"]["easy"]
    assert counted() == set(listed()) == before - {"desk.recent_files"}
    c.post("/api/scan", headers=H)
    assert counted() == set(listed()) == before - {"desk.recent_files"}


def test_easy_fixes_apply_only_their_own_plans(cat, tmp_path):
    """Not a "Fix all": a fix that isn't easy is applied on its own, after its own dry run."""
    c, host, gs = easy_client(cat, tmp_path)
    other = c.post("/api/fix/tel.location/plan", headers=H).json()["plan"]["id"]
    r = c.post("/api/easy/apply", headers=H, json={"plan_ids": [other]})
    assert r.status_code == 400 and "Easy fixes' own plans" in r.json()["error"]
    assert gs.values[("org.gnome.system.location", "enabled")] == "true"
    for bad in ({}, {"plan_ids": []}, {"plan_ids": "x"}, {"plan_ids": [1]}, {"plan_ids": ["a", "a"]}):
        assert c.post("/api/easy/apply", headers=H, json=bad).status_code == 400
    assert c.post("/api/easy/plan").status_code == 403
    assert c.post("/api/fix/plan-all", headers=H).status_code in (404, 405)


def test_an_accepted_finding_is_not_offered(cat, tmp_path):
    c, host, gs = easy_client(cat, tmp_path)
    c.post("/api/accept", headers=H, json={"check_id": "auth.lockscreen_notifications", "accept": True})
    items = [it["check_id"] for it in c.post("/api/easy/plan", headers=H).json()["items"]]
    assert "auth.lockscreen_notifications" not in items and "desk.recent_files" in items


@pytest.mark.parametrize("grant", [False, True])
def test_easy_fixes_that_need_root_ask_once_and_go_on_without_it(cat, tmp_path, monkeypatch, grant):
    """Administrator access is asked for once, when applying; declined, the root ones are skipped
    and the others applied."""
    from daprivacyscanner import helper
    from daprivacyscanner.privileged import FakePrivileged, HelperDeclined

    asked = []

    def start():
        asked.append(1)
        if not grant:
            raise HelperDeclined("declined")
        return FakePrivileged()

    host, gs = gnome_host(tmp_path)
    (host.root / "etc/yum.repos.d").mkdir(parents=True)
    repo = host.root / "etc/yum.repos.d/fedora.repo"
    repo.write_text("[fedora]\nname=Fedora\nenabled=1\ncountme=1\n")
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    c = TestClient(create_app(TOKEN, cat, make_host=lambda: host, start_helper=start))
    c.post("/api/scan", headers=H)
    items = {it["check_id"]: it for it in c.post("/api/easy/plan", headers=H).json()["items"]}
    assert items["tel.countme"]["needs_root"] and not asked                        # the dry run needs no root
    ids = [items[k]["plans"][0]["id"] for k in ("auth.lockscreen_notifications", "tel.countme")]
    r = c.post("/api/easy/apply", headers=H, json={"plan_ids": ids}).json()
    assert asked == [1] and gs.values[("org.gnome.desktop.notifications", "show-in-lock-screen")] == "false"
    count = {x["check_id"]: x for x in r["results"]}["tel.countme"]
    if grant:
        assert r["ok"] and count["ok"] and "countme=0" in repo.read_text()
    else:
        assert not r["ok"] and count.get("declined") and "countme=1" in repo.read_text()
        assert [e["check_id"] for e in c.get("/api/undo", headers=H).json()["entries"]] == ["auth.lockscreen_notifications"]


def test_cli_dry_run_easy(cat, tmp_path, monkeypatch, capsys):
    from daprivacyscanner import app
    from daprivacyscanner.host import Host

    host, gs = gnome_host(tmp_path)
    monkeypatch.setattr(Host, "local", staticmethod(lambda: host))
    assert app.dry_run(cat, "easy") == 0
    out = capsys.readouterr().out
    assert "Easy fix for desk.recent_files" in out and "What it costs: Files you opened more than 30 days" in out
    assert "Keep recent files for at most 30 days" in out and "tel.location" not in out
