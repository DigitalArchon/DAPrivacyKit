"""Shared fix machinery corrected after the review of 2026-10-17: what a plan holds and shows, a command after a
write, reverting a value the user had already put back, KDE settings a distribution sets in /etc/xdg."""

from daprivacyscanner.checks import load_all
from daprivacyscanner.fix import FixPlan, GSettingsSet, MakeDir, WriteFile, apply_plan, bus_reload, revert_entry
from daprivacyscanner.host import CommandResult
from daprivacyscanner.undo import UndoLog

from conftest import make_host, make_scan
from fakes import FakeGSettings, FakeKwriteconfig
from test_guides import apply, build, options, revert


def _log(host):
    return UndoLog(host.home / ".local/state/daprivacyscanner")


def test_a_write_that_changes_nothing_is_no_step(tmp_path):
    """An option applied before would otherwise be offered for ever, each time a new History entry."""
    host = make_host(tmp_path, home_files={".config/x.conf": "a=1\n"})
    same = WriteFile(host.home / ".config/x.conf", lambda old: "a=1\n", "Set a", "~/.config/x.conf")
    new = WriteFile(host.home / ".config/y.conf", lambda old: "b=1\n", "Set b", "~/.config/y.conf")
    plan = FixPlan("t", "t", [same, new])
    assert plan.actions == [new]
    assert FixPlan("t", "t", [same]).empty


def test_a_folder_an_earlier_step_makes_is_made_once_in_the_dry_run(tmp_path):
    host = make_host(tmp_path)
    box = host.home / "Boxes" / "b"
    plan = FixPlan("t", "t", [MakeDir(host.home / "Boxes", "~/Boxes"), MakeDir(box, "~/Boxes/b"),
                              WriteFile(box / "box.json", lambda old: "{}", "Write it", "~/Boxes/b/box.json"),
                              WriteFile(host.home / ".config/systemd/user/a.path", lambda old: "a", "a", "a"),
                              WriteFile(host.home / ".config/systemd/user/a.service", lambda old: "a", "a", "a")])
    cmds = plan.step_commands()
    assert cmds[2] == []                                    # ~/Boxes and ~/Boxes/b are the MakeDirs'
    assert len(cmds[3]) == 3 and cmds[4] == []             # .config/systemd/user made by the first unit file only
    assert plan.dry_run().count("also runs: mkdir") == 3 and plan.to_dict()["steps"][4]["commands"] == []


def test_a_command_after_writing_runs_on_apply_and_on_revert(tmp_path):
    host = make_host(tmp_path, commands={tuple(bus_reload(make_host(tmp_path / "x"))): ""})
    host.runner.installed.add("dbus-send")
    reload = bus_reload(host)
    f = host.home / ".local/share/dbus-1/services/org.kde.kdeconnect.service"
    plan = FixPlan("net.kdeconnect", "t", [WriteFile(f, lambda old: "[D-BUS Service]\nExec=/bin/false\n", "Override",
                                                     "~/x", then=reload)])
    assert plan.step_commands()[0][-1].startswith(reload[0])
    log = _log(host)
    res = apply_plan(plan, host, log)
    assert res.ok and f.is_file() and host.runner.calls.count(tuple(reload)) == 1
    assert any(reload[0] in c for c in log.get(res.entry_id)["records"][0].get("ran", []))
    revert_entry(log.get(res.entry_id), host, log)
    assert not f.exists() and host.runner.calls.count(tuple(reload)) == 2


def test_reverting_a_setting_already_back_by_hand_is_no_conflict(tmp_path):
    """The red "undone" banner shows it changed back; reverting the entry then has nothing to resolve."""
    gs = FakeGSettings({("org.cinnamon.desktop.session", "idle-delay"): "uint32 0"})
    host = make_host(tmp_path)
    host.runner.handlers["gsettings"] = gs
    log = _log(host)
    res = apply_plan(FixPlan("auth.screen_lock", "t", [GSettingsSet("org.cinnamon.desktop.session", "idle-delay",
                                                                    "uint32 300")]), host, log)
    assert gs.values[("org.cinnamon.desktop.session", "idle-delay")] == "uint32 300"
    gs.values[("org.cinnamon.desktop.session", "idle-delay")] = "uint32 0"          # put back by hand
    results = revert_entry(log.get(res.entry_id), host, log)
    assert all(r.ok and not r.conflict for r in results)
    gs.values[("org.cinnamon.desktop.session", "idle-delay")] = "uint32 600"        # changed to something else
    res = apply_plan(FixPlan("auth.screen_lock", "t", [GSettingsSet("org.cinnamon.desktop.session", "idle-delay",
                                                                    "uint32 300")]), host, log)
    gs.values[("org.cinnamon.desktop.session", "idle-delay")] = "uint32 900"
    assert revert_entry(log.get(res.entry_id), host, log)[0].conflict


def test_a_kde_default_in_etc_xdg_is_what_the_fix_compares_with(cat, tmp_path):
    """A distribution's /etc/xdg default is what Plasma reads unless the user's file says otherwise: the fix writes
    the user's file then, rather than leaving a failing check with an empty plan."""
    host = make_host(tmp_path, files={"/etc/xdg/PlasmaUserFeedback": "[Global]\nFeedbackLevel=16\n"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    check = load_all()["tel.kde_feedback"](cat["tel.kde_feedback"])
    scan = make_scan(host, desktop=("kde",), plasma_major=6)
    outcome = check.detect(scan)
    assert outcome.status.value == "fail"
    plan = check.plan_fix(scan, outcome)
    assert not plan.empty
    log, res = apply(host, plan)
    assert check.detect(make_scan(host, desktop=("kde",), plasma_major=6)).status.value == "pass"


def test_deletions_name_the_folder_the_file_is_in(cat, tmp_path):
    """0.1.0b2 showed ~/.local/share/recently-used.xbel/recently-used.xbel, and a mkdir with words in its path."""
    xbel = '<xbel version="1.0"><bookmark href="file:///home/alice/secret.pdf" added="x"/></xbel>'
    host = make_host(tmp_path, home_files={".local/share/recently-used.xbel": xbel})
    g = build(cat, host, "desk.recent_files", desktop=("cinnamon",))
    clear = options(g)["Clear it"]
    assert "in ~/.local/share" in clear.actions[0].describe() and "xbel/" not in clear.dry_run()
    block = options(g)["Put a folder where the list is kept"]
    mk = next(a for a in block.actions if isinstance(a, MakeDir))
    assert mk.describe().startswith("mkdir -m 500 ~/.local/share/recently-used.xbel   (")
