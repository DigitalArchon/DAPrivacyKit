import json
import os
import stat

from daprivacyscanner.fix import (ClearInFile, Command, DeleteFiles, FixPlan, GSettingsSet, KConfigSet, WriteFile,
                                apply_plan, revert_entry)
from daprivacyscanner.undo import UndoLog

from conftest import make_host
from fakes import FakeGSettings, FakeKwriteconfig, fail

SCREEN = ("org.gnome.desktop.screensaver", "lock-enabled")


def setup(tmp_path, gsettings=None, **kw):
    gs = FakeGSettings(gsettings or {SCREEN: "false"})
    host = make_host(tmp_path, **kw)
    host.runner.handlers["gsettings"] = gs
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    return host, gs, UndoLog(host.home / ".local/state/daprivacyscanner")


def test_gsettings_apply_and_revert(tmp_path):
    host, gs, log = setup(tmp_path)
    res = apply_plan(FixPlan("auth.screen_lock", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    assert res.ok and gs.values[SCREEN] == "true"
    entry = log.get(res.entry_id)
    assert entry["records"][0]["before"] == "false" and entry["state"] == "applied"
    [r] = revert_entry(entry, host, log)
    assert r.ok and gs.values[SCREEN] == "false" and log.get(res.entry_id)["state"] == "reverted"


def test_revert_does_not_overwrite_a_later_change_unless_forced(tmp_path):
    host, gs, log = setup(tmp_path, {("org.gnome.desktop.session", "idle-delay"): "uint32 0"})
    res = apply_plan(FixPlan("x", "t", [GSettingsSet("org.gnome.desktop.session", "idle-delay", "uint32 300")]), host, log)
    gs.values[("org.gnome.desktop.session", "idle-delay")] = "uint32 600"            # the user changes it again
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert not r.ok and r.conflict and gs.values[("org.gnome.desktop.session", "idle-delay")] == "uint32 600"
    [r] = revert_entry(log.get(res.entry_id), host, log, force=True)
    assert r.ok and gs.values[("org.gnome.desktop.session", "idle-delay")] == "uint32 0"


def test_kconfig_default_is_deleted_again_on_revert(tmp_path):
    host, _, log = setup(tmp_path, home_files={".config/kscreenlockerrc": "[Daemon]\nTimeout=30\n"})
    rc = host.home / ".config/kscreenlockerrc"
    plan = FixPlan("x", "t", [KConfigSet("kwriteconfig6", rc, "kscreenlockerrc", "Daemon", "Autolock", "true"),
                              KConfigSet("kwriteconfig6", rc, "kscreenlockerrc", "Daemon", "Timeout", "5")])
    res = apply_plan(plan, host, log)
    assert "Autolock=true" in rc.read_text() and "Timeout=5" in rc.read_text()
    revert_entry(log.get(res.entry_id), host, log)
    assert "Autolock" not in rc.read_text() and "Timeout=30" in rc.read_text()


def test_write_file_backup_restore_and_conflict(tmp_path):
    host, _, log = setup(tmp_path, home_files={"settings.json": '{"a": 1}'})
    f = host.home / "settings.json"
    new = host.home / "new.conf"
    plan = FixPlan("x", "t", [WriteFile(f, lambda old: old.replace("1", "2"), "edit", "~/settings.json"),
                              WriteFile(new, lambda old: "X=1\n", "create", "~/new.conf")])
    res = apply_plan(plan, host, log)
    assert f.read_text() == '{"a": 2}' and new.read_text() == "X=1\n"
    backups = list(log.backup_dir(res.entry_id).iterdir())
    assert len(backups) == 1 and stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    new.write_text("X=1\nY=2\n")                                       # edited since
    results = revert_entry(log.get(res.entry_id), host, log)
    assert [r.ok for r in results] == [False, True] and f.read_text() == '{"a": 1}' and new.exists()
    assert log.get(res.entry_id)["state"] == "partly reverted"


def test_write_file_keeps_a_link_and_changes_the_file_it_points_to(tmp_path):
    """A dotfiles manager's link (~/.ssh/config -> ~/dotfiles/ssh_config) stays a link, both ways."""
    host, _, log = setup(tmp_path, home_files={"dotfiles/ssh_config": "ForwardAgent yes\n"})
    (host.home / ".ssh").mkdir()
    link = host.home / ".ssh/config"
    link.symlink_to(host.home / "dotfiles/ssh_config")
    w = WriteFile(link, lambda old: old.replace("yes", "no"), "edit", "~/.ssh/config")
    assert "a link: the file it points to" in w.describe()
    res = apply_plan(FixPlan("x", "t", [w]), host, log)
    assert link.is_symlink() and (host.home / "dotfiles/ssh_config").read_text() == "ForwardAgent no\n"
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and link.is_symlink() and (host.home / "dotfiles/ssh_config").read_text() == "ForwardAgent yes\n"


def test_delete_stays_inside_its_root_and_never_follows_symlinks(tmp_path):
    host, _, log = setup(tmp_path, home_files={"cache/a/x": "1", "cache/b": "2", "keep/secret": "3"})
    (host.home / "cache/link").symlink_to(host.home / "keep/secret")
    files = [host.home / "cache/a/x", host.home / "cache/b", host.home / "cache/link", host.home / "keep/secret",
             host.home / "cache/../keep/secret"]
    res = apply_plan(FixPlan("x", "t", [DeleteFiles(host.home / "cache", files, "cache", "~/cache")]), host, log,
                     confirmed_irreversible=True)
    assert res.ok and (host.home / "keep/secret").exists() and (host.home / "cache/link").is_symlink()
    assert not (host.home / "cache/a").exists() and (host.home / "cache").is_dir()     # emptied subfolder tidied
    assert "Deleted 2 files of cache in ~/cache (3 skipped)" in res.applied


def test_deleted_paths_are_not_written_to_the_log(tmp_path):
    host, _, log = setup(tmp_path, home_files={"hist/private-diary.txt": "x"})
    apply_plan(FixPlan("x", "t", [DeleteFiles(host.home / "hist", [host.home / "hist/private-diary.txt"], "h", "~/hist")]),
               host, log, confirmed_irreversible=True)
    assert "private-diary" not in log.file.read_text()


def test_irreversible_steps_need_confirmation_and_blockers_stop_everything(tmp_path):
    host, gs, log = setup(tmp_path, home_files={"c/x": "1"})
    plan = FixPlan("x", "t", [GSettingsSet(*SCREEN, "true"), DeleteFiles(host.home / "c", [host.home / "c/x"], "c", "~/c")])
    assert not apply_plan(plan, host, log).ok and gs.values[SCREEN] == "false" and (host.home / "c/x").exists()
    blocked = FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")], blockers=["Close Okular first."])
    assert "Close Okular" in apply_plan(blocked, host, log).error and gs.values[SCREEN] == "false"
    assert log.entries() == []


def test_failure_rolls_back_earlier_steps(tmp_path):
    host, gs, log = setup(tmp_path, {SCREEN: "false", ("org.gnome.desktop.session", "idle-delay"): "uint32 0"})
    host.runner.handlers["nmcli"] = lambda argv: fail("Insufficient privileges")
    from daprivacyscanner.fix import NmSet
    plan = FixPlan("x", "t", [GSettingsSet(*SCREEN, "true"),
                              GSettingsSet("org.gnome.desktop.session", "idle-delay", "uint32 300"),
                              NmSet("u1", "Home", "ipv6.ip6-privacy", "2")])
    res = apply_plan(plan, host, log)
    assert not res.ok and "Insufficient privileges" in res.error and len(res.rolled_back) == 2
    assert gs.values == {SCREEN: "false", ("org.gnome.desktop.session", "idle-delay"): "uint32 0"}
    # the attempt is in History, as failed: what each step did and what putting it back did, so the user can see
    # what happened; nothing is left to revert
    [entry] = log.entries()
    assert entry["id"] == res.entry_id and entry["state"] == "failed" and "Insufficient privileges" in entry["error"]
    assert entry["failed_step"].startswith("nmcli connection modify u1")
    s = UndoLog.summary(entry)
    assert not s["can_revert"] and s["error"] == entry["error"] and s["via_text"] == "Applied with its Fix… button"
    assert [st["reverted"] for st in s["steps"]] == [True, True]
    assert s["steps"][1]["revert_ran"] == ["gsettings set org.gnome.desktop.session idle-delay 'uint32 0'"]
    assert log.undone({"x": {"status": "fail", "effective_severity": 3}}) == []     # a failed attempt fixed nothing
    assert log.forget() == 1


def test_an_attempt_that_changed_nothing_leaves_no_entry(tmp_path):
    host, gs, log = setup(tmp_path)
    host.runner.handlers["gsettings"] = lambda argv: fail("no schema")
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    assert not res.ok and res.entry_id is None and log.entries() == []


def test_a_step_that_cannot_be_put_back_stays_revertible_from_history(tmp_path):
    host, gs, log = setup(tmp_path, {SCREEN: "false", ("org.gnome.desktop.session", "idle-delay"): "uint32 0"})
    from daprivacyscanner.fix import NmSet
    calls = []

    def flaky(argv):                      # the first set works, then everything fails (gsettings included)
        calls.append(argv)
        if argv[1] == "set" and len([c for c in calls if c[1] == "set"]) > 1:
            return fail("dconf went away")
        return gs(argv)
    host.runner.handlers["gsettings"] = flaky
    host.runner.handlers["nmcli"] = lambda argv: fail("Insufficient privileges")
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true"), NmSet("u1", "Home", "ipv6.ip6-privacy", "2")]),
                     host, log)
    assert not res.ok and res.rolled_back == ["NOT put back: gsettings set org.gnome.desktop.screensaver lock-enabled "
                                              "false failed: dconf went away"]
    s = UndoLog.summary(log.get(res.entry_id))
    assert s["state"] == "failed" and s["can_revert"] and not s["steps"][0]["reverted"]
    host.runner.handlers["gsettings"] = gs
    assert all(r.ok for r in revert_entry(log.get(res.entry_id), host, log)) and gs.values[SCREEN] == "false"


def test_history_says_where_a_change_came_from(tmp_path):
    host, gs, log = setup(tmp_path)
    plan = FixPlan("x", "Lock it", [GSettingsSet(*SCREEN, "true")])
    plan.via = {"guide": "Lock the screen", "step": 2, "step_title": "The lock", "option": "After 5 minutes", "options": 2}
    res = apply_plan(plan, host, log)
    assert UndoLog.summary(log.get(res.entry_id))["via_text"] == \
        "From the guide “Lock the screen”, step 2 (The lock), the option “After 5 minutes”"
    plan = FixPlan("x", "Lock it", [GSettingsSet(*SCREEN, "false")], via={"easy": True})
    assert UndoLog.via_text(log.get(apply_plan(plan, host, log).entry_id)) == "Applied as an Easy fix"
    plan = FixPlan("x", "Lock it", [GSettingsSet(*SCREEN, "true")],
                   via={"guide": "G", "step": 1, "step_title": "S", "option": "Only one", "options": 1, "easy": True})
    assert UndoLog.via_text(log.get(apply_plan(plan, host, log).entry_id)) == "From the guide “G”, step 1 (S), applied as an Easy fix"
    assert UndoLog.via_text({"records": []}) == ""                                   # an entry from before
    assert plan.to_dict()["via"]["guide"] == "G"


def test_plan_order_and_dry_run(tmp_path):
    host = make_host(tmp_path, home_files={"d/x": "1"})
    plan = FixPlan("desk.x", "Clear", [
        Command(["systemctl", "--user", "start", "x"], "start again", after=True),
        DeleteFiles(host.home / "d", [host.home / "d/x"], "stuff", "~/d"),
        Command(["systemctl", "--user", "stop", "x"], "holds it open"),
        GSettingsSet(*SCREEN, "true")])
    assert [type(a).__name__ for a in plan.actions] == ["GSettingsSet", "Command", "DeleteFiles", "Command"]
    text = plan.dry_run()
    assert "[can be undone] gsettings set org.gnome.desktop.screensaver lock-enabled true" in text
    assert "[CANNOT be undone] Delete 1 file (1 bytes) of stuff in ~/d" in text
    d = plan.to_dict()
    assert d["irreversible_files"] == 1 and [s["irreversible"] for s in d["steps"]] == [False, False, True, False]


def test_clear_in_file_is_irreversible_and_not_backed_up(tmp_path):
    host, _, log = setup(tmp_path, home_files={"vlc.conf": "[RecentsMRL]\nlist=file:///secret.mkv\n"})
    plan = FixPlan("x", "t", [ClearInFile(host.home / "vlc.conf", lambda t: t.replace("file:///secret.mkv", ""),
                                          "Clear", "~/vlc.conf")])
    assert plan.irreversible
    res = apply_plan(plan, host, log, confirmed_irreversible=True)
    assert "secret" not in (host.home / "vlc.conf").read_text()
    assert not log.backup_dir(res.entry_id).exists()


def test_undo_log_is_private(tmp_path):
    host, _, log = setup(tmp_path)
    apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    assert stat.S_IMODE(os.stat(log.dir).st_mode) == 0o700 and stat.S_IMODE(os.stat(log.file).st_mode) == 0o600
    assert json.loads(log.file.read_text())["version"] == 1
    summary = UndoLog.summary(log.entries()[0])
    assert summary["can_revert"] and summary["steps"][0]["reversible"]


def test_nm_records_hold_no_network_names(tmp_path):
    from fakes import FakeNmcli
    from daprivacyscanner.fix import NmSet
    host, _, log = setup(tmp_path)
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Secret Cafe", "ipv6.ip6-privacy": "-1"}})
    host.runner.handlers["nmcli"] = nm
    res = apply_plan(FixPlan("x", "t", [NmSet("u1", "Secret Cafe", "ipv6.ip6-privacy", "2")]), host, log)
    assert res.ok and "Secret Cafe" not in log.file.read_text()
    assert UndoLog.summary(log.entries()[0])["steps"][0]["text"].startswith("Saved connection:")
    assert UndoLog.summary(log.entries()[0], host)["steps"][0]["text"].startswith("Secret Cafe:")


def test_forget_history(tmp_path):
    host, gs, log = setup(tmp_path)
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    res2 = apply_plan(FixPlan("y", "t", [GSettingsSet(*SCREEN, "false")]), host, log)
    revert_entry(log.get(res2.entry_id), host, log)
    assert log.forget() == 1 and [e["id"] for e in log.entries()] == [res.entry_id]
    assert log.forget(everything=True) == 1 and log.entries() == []


def test_commands_shown_can_be_pasted_into_a_shell(tmp_path):
    import shlex
    from daprivacyscanner.fix import NmSet, UserUnitSet, shell
    rc = tmp_path / "baloofilerc"
    shown = [GSettingsSet("org.gnome.desktop.session", "idle-delay", "uint32 300").describe(),
             GSettingsSet("org.gnome.shell", "disabled-extensions", "['a@b', 'c@d']").describe(),
             KConfigSet("kwriteconfig6", rc, "baloofilerc", "Basic Settings", "Indexing-Enabled", "false").describe(),
             NmSet("u1", "Home", "ipv6.ip6-privacy", "2").describe().split("   (")[0],
             UserUnitSet("systemd-tmpfiles-clean.timer", True).describe()]
    assert shlex.split(shown[0]) == ["gsettings", "set", "org.gnome.desktop.session", "idle-delay", "uint32 300"]
    assert shlex.split(shown[1])[-1] == "['a@b', 'c@d']"
    assert shlex.split(shown[2])[4] == "Basic Settings"
    assert shlex.split(shown[3]) == ["nmcli", "connection", "modify", "u1", "ipv6.ip6-privacy", "2"]
    assert shlex.split(shown[4]) == ["systemctl", "--user", "enable", "--now", "systemd-tmpfiles-clean.timer"]
    assert shell(["rm", "~/My Files/x"]) == "rm ~/'My Files/x'"          # the ~ stays outside the quotes


def test_a_failed_step_names_the_whole_command(tmp_path):
    host, gs, log = setup(tmp_path, {SCREEN: "false"})
    host.runner.handlers["gsettings"] = lambda argv: fail("No such key") if argv[1] == "set" else gs(argv)
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    assert not res.ok and "gsettings set org.gnome.desktop.screensaver lock-enabled true failed: No such key" in res.error


def test_history_shows_the_command_that_ran_the_lines_written_and_how_to_undo_by_hand(tmp_path):
    host, gs, log = setup(tmp_path, home_files={"env.conf": "A=1\n"})
    f = host.home / "env.conf"
    plan = FixPlan("x", "t", [GSettingsSet("org.gnome.desktop.session", "idle-delay", "uint32 300"),
                              WriteFile(f, lambda old: old + "DOTNET_CLI_TELEMETRY_OPTOUT=1\n", "Add it", "~/env.conf")])
    gs.values[("org.gnome.desktop.session", "idle-delay")] = "uint32 0"
    steps = plan.to_dict()["steps"]
    assert steps[1]["lines"] == ["+ DOTNET_CLI_TELEMETRY_OPTOUT=1"]                  # the dry run shows what it writes
    res = apply_plan(plan, host, log)
    shown = UndoLog.summary(log.get(res.entry_id))["steps"]
    assert shown[0]["commands"] == ["gsettings set org.gnome.desktop.session idle-delay 'uint32 300'"]
    assert shown[0]["undo"] == "gsettings set org.gnome.desktop.session idle-delay 'uint32 0'"
    assert shown[1]["lines"] == ["+ DOTNET_CLI_TELEMETRY_OPTOUT=1"] and shown[1]["undo"].startswith("cp ")
    revert_entry(log.get(res.entry_id), host, log)
    assert [s["undo"] for s in UndoLog.summary(log.get(res.entry_id))["steps"]] == ["", ""]   # reverted: nothing to undo


def test_entries_from_before_show_their_commands_too(tmp_path):
    old = {"kind": "gsettings", "schema": "org.gnome.desktop.screensaver", "key": "lock-enabled", "before": "false",
           "after": "true", "text": "org.gnome.desktop.screensaver lock-enabled: false → true"}
    s = UndoLog.step(old)
    assert s["commands"] == ["gsettings set org.gnome.desktop.screensaver lock-enabled true"] and s["lines"] == []
    assert UndoLog.step({"kind": "root", "change_id": "a" * 32, "text": "x"})["commands"] == []   # the helper didn't say


def test_a_written_file_shows_at_most_some_lines(tmp_path):
    from daprivacyscanner.fix import CHANGED_LINES, changed_lines
    out = changed_lines("a\n", "\n".join(f"line {i}" for i in range(100)))
    assert len(out) == CHANGED_LINES + 1 and out[0] == "- a" and out[-1].startswith("… and ")


# ------------------------------------------------------------------ a revert is a full revert, and breaks nothing else's

def test_a_file_and_the_folders_it_needed_go_on_revert(tmp_path):
    host, _, log = setup(tmp_path)
    (host.home / ".config").mkdir()                                             # there on every system
    f = host.home / ".config/environment.d/sub/60-x.conf"
    res = apply_plan(FixPlan("x", "t", [WriteFile(f, lambda old: "A=1\n", "Add it", "~/.config/environment.d/sub/60-x.conf")]),
                     host, log)
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and not (host.home / ".config/environment.d").exists() and (host.home / ".config").is_dir()


def test_a_folder_that_holds_what_was_added_since_stays_and_the_revert_says_why(tmp_path):
    host, _, log = setup(tmp_path)
    f = host.home / ".config/environment.d/60-x.conf"
    res = apply_plan(FixPlan("x", "t", [WriteFile(f, lambda old: "A=1\n", "Add it", "~/.config/environment.d/60-x.conf")]),
                     host, log)
    other = host.home / ".config/environment.d/50-mine.conf"
    other.write_text("B=2\n")                                                    # the user's, added since
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and not f.exists() and other.read_text() == "B=2\n"
    assert "environment.d was left, with what is in it" in r.message and "50-mine.conf" in r.message
    assert UndoLog.summary(log.get(res.entry_id))["steps"][0]["undo"] == ""      # reverted: nothing left to undo


def test_the_hand_undo_names_the_folders_too(tmp_path):
    host, _, log = setup(tmp_path)
    f = host.home / ".config/user-tmpfiles.d/60-x.conf"
    res = apply_plan(FixPlan("x", "t", [WriteFile(f, lambda old: "x\n", "Add it", "~/x")]), host, log)
    undo = UndoLog.summary(log.get(res.entry_id))["steps"][0]["undo"]
    assert undo.startswith(f"rm {f}; rmdir {f.parent}") and "removed only if empty" in undo


def test_a_kde_file_the_fix_made_goes_unless_it_holds_more_now(tmp_path):
    host, _, log = setup(tmp_path)
    rc = host.home / ".config/klipperrc"
    step = lambda: KConfigSet("kwriteconfig6", rc, "klipperrc", "General", "KeepClipboardContents", "false")  # noqa: E731
    res = apply_plan(FixPlan("x", "t", [step()]), host, log)
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and not rc.exists() and "removed (the fix made it)" in r.message
    res = apply_plan(FixPlan("x", "t", [step()]), host, log)
    rc.write_text(rc.read_text() + "MaxClipItems=30\n")                          # Klipper's own, written since
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and "MaxClipItems=30" in rc.read_text() and "KeepClipboardContents" not in rc.read_text()
    assert "holds settings added since" in r.message


def test_a_kde_file_that_was_there_stays(tmp_path):
    host, _, log = setup(tmp_path, home_files={".config/klipperrc": ""})
    rc = host.home / ".config/klipperrc"
    res = apply_plan(FixPlan("x", "t", [KConfigSet("kwriteconfig6", rc, "klipperrc", "General", "KeepClipboardContents",
                                                   "false")]), host, log)
    revert_entry(log.get(res.entry_id), host, log)
    assert rc.exists()


def test_the_folders_systemctl_made_to_enable_a_unit_go_when_it_is_disabled_again(tmp_path):
    from daprivacyscanner.fix import UserUnitSet
    from daprivacyscanner.host import CommandResult
    host, _, log = setup(tmp_path)
    wants = host.home / ".config/systemd/user/timers.target.wants"
    state = {"x.timer": "disabled"}

    def systemctl(argv):
        verb, unit = argv[2], argv[-1]
        if verb == "is-enabled":
            return CommandResult(argv, 0, state[unit] + "\n")
        state[unit] = "enabled" if verb == "enable" else "disabled"
        link = wants / unit
        if verb == "enable":
            wants.mkdir(parents=True, exist_ok=True)
            link.symlink_to("/usr/lib/systemd/user/" + unit)
        else:
            link.unlink(missing_ok=True)                                      # systemctl leaves the folders
        return CommandResult(argv, 0, "")
    host.runner.handlers["systemctl"] = systemctl
    res = apply_plan(FixPlan("x", "t", [UserUnitSet("x.timer", True)]), host, log)
    assert sorted(log.get(res.entry_id)["records"][0]["dirs"]) == sorted(
        [str(host.home / ".config/systemd"), str(host.home / ".config/systemd/user"), str(wants)])
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and not (host.home / ".config/systemd").exists() and (host.home / ".config").is_dir()
    # a unit file of the user's written there since keeps its folder, and the rest of the way to it
    res = apply_plan(FixPlan("x", "t", [UserUnitSet("x.timer", True)]), host, log)
    (host.home / ".config/systemd/user/mine.service").write_text("[Service]\n")
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert not wants.exists() and (host.home / ".config/systemd/user/mine.service").exists()
    assert "systemd/user was left, with what is in it" in r.message and "mine.service" in r.message


def test_a_made_folder_that_holds_files_now_stays(tmp_path):
    from daprivacyscanner.fix import MakeDir
    host, _, log = setup(tmp_path)
    d = host.home / "Pictures/Screenshots"
    (host.home / "Pictures").mkdir()
    res = apply_plan(FixPlan("x", "t", [MakeDir(d, "~/Pictures/Screenshots")]), host, log)
    (d / "shot.png").write_text("x")
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and (d / "shot.png").exists() and "shot.png" in r.message


def test_a_setting_that_was_at_its_default_is_reset_not_pinned(tmp_path):
    """Writing the default back as a value would keep it even if the distribution changes the default later."""
    from daprivacyscanner.host import CommandResult
    host = make_host(tmp_path, installed=("dconf",))
    gs = FakeGSettings({SCREEN: "false"})
    user_set = set()

    def gsettings(argv):
        if argv[1] == "list-schemas":
            return CommandResult(argv, 0, "org.gnome.desktop.screensaver /org/gnome/desktop/screensaver/\n"
                                          "org.gnome.Relocatable \n")
        if argv[1] == "reset":
            gs.values[(argv[2], argv[3])] = "false"
            user_set.discard((argv[2], argv[3]))
            return CommandResult(argv, 0, "")
        if argv[1] == "set":
            user_set.add((argv[2], argv[3]))
        return gs(argv)
    host.runner.handlers["gsettings"] = gsettings
    host.runner.handlers["dconf"] = lambda argv: CommandResult(argv, 0, "true\n" if SCREEN in user_set else "")
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    rec = log.get(res.entry_id)["records"][0]
    assert rec["was_default"] is True and "(its default)" in rec["text"]
    assert UndoLog.step(rec)["undo"] == "gsettings reset org.gnome.desktop.screensaver lock-enabled"
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and SCREEN not in user_set and gs.values[SCREEN] == "false" and "its default" in r.message
    assert UndoLog.step(log.get(res.entry_id)["records"][0])["revert_ran"] == [
        "gsettings reset org.gnome.desktop.screensaver lock-enabled"]
    # a value the user had set is written back as it was
    user_set.add(SCREEN)
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true")]), host, log)
    assert log.get(res.entry_id)["records"][0]["was_default"] is False
    revert_entry(log.get(res.entry_id), host, log)
    assert SCREEN in user_set and gs.values[SCREEN] == "false"


def test_history_says_what_reverting_a_step_did(tmp_path):
    host, gs, log = setup(tmp_path)
    (host.home / ".config").mkdir()
    f = host.home / ".config/environment.d/60-x.conf"
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*SCREEN, "true"),
                                        WriteFile(f, lambda old: "A=1\n", "Add it", "~/x")]), host, log)
    applied = UndoLog.summary(log.get(res.entry_id))["steps"]
    assert applied[1]["dirs"] == [str(f.parent)] and applied[0]["commands"] == [
        "gsettings set org.gnome.desktop.screensaver lock-enabled true"]
    revert_entry(log.get(res.entry_id), host, log)
    steps = UndoLog.summary(log.get(res.entry_id))["steps"]
    assert steps[0]["revert_ran"] == ["gsettings set org.gnome.desktop.screensaver lock-enabled false"]
    assert steps[1]["revert_ran"] == [f"rm {f}", f"rmdir {f.parent}"]


def test_a_prefs_js_the_fix_made_goes_unless_the_browser_wrote_more(tmp_path):
    from daprivacyscanner.fix import FirefoxPref
    host, _, log = setup(tmp_path)
    profile = host.home / ".mozilla/firefox/x.default"
    profile.mkdir(parents=True)
    step = lambda: FirefoxPref(profile, "Firefox", "toolkit.telemetry.enabled", False, "~/x")  # noqa: E731
    res = apply_plan(FixPlan("x", "t", [step()]), host, log)
    assert UndoLog.summary(log.get(res.entry_id))["steps"][0]["commands"] == [
        f"# toolkit.telemetry.enabled set to false in {profile}/prefs.js (with Firefox closed)"]
    revert_entry(log.get(res.entry_id), host, log)
    assert not (profile / "prefs.js").exists()
    res = apply_plan(FixPlan("x", "t", [step()]), host, log)
    with open(profile / "prefs.js", "a") as f:
        f.write('user_pref("browser.startup.page", 3);\n')                           # the browser's, since
    revert_entry(log.get(res.entry_id), host, log)
    text = (profile / "prefs.js").read_text()
    assert "browser.startup.page" in text and "telemetry" not in text


def test_write_atomic_keeps_the_temporary_file_private(tmp_path, monkeypatch):
    """A file being rewritten (a shell history cleaned) is never readable by others on the way, whatever the umask,
    and a temporary file left by an interrupted write is replaced, not followed."""
    import os
    import stat as st

    from daprivacyscanner import fix
    p = tmp_path / ".bash_history"
    p.write_text("ls\nexport TOKEN=x\n")
    p.chmod(0o600)
    seen = []
    real_replace = os.replace

    def replace(a, b):
        seen.append(st.S_IMODE(os.lstat(a).st_mode))
        return real_replace(a, b)
    monkeypatch.setattr(fix.os, "replace", replace)
    stale = tmp_path / ".bash_history.daprivacyscanner-tmp"
    target = tmp_path / "elsewhere"
    stale.symlink_to(target)
    old = os.umask(0o002)
    try:
        fix._write_atomic(p, b"ls\n")
    finally:
        os.umask(old)
    assert p.read_text() == "ls\n" and st.S_IMODE(p.stat().st_mode) == 0o600 and seen == [0o600]
    assert not target.exists() and not stale.exists()


def test_a_restored_file_gets_its_own_mode_back(tmp_path):
    """Reverting a change to a file removed since puts it back with the mode it had, not the umask's."""
    from daprivacyscanner.fix import FixPlan, WriteFile, apply_plan, revert_entry
    from daprivacyscanner.undo import UndoLog
    from conftest import make_host
    host = make_host(tmp_path)
    f = host.home / ".ssh" / "config"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("Host *\n")
    f.chmod(0o600)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(FixPlan("x", "t", [WriteFile(f, lambda old: old + "HashKnownHosts yes\n", "add", "~/.ssh/config")]),
                     host, log)
    assert res.ok
    f.unlink()
    assert all(r.ok for r in revert_entry(log.get(res.entry_id), host, log, force=True))
    assert f.read_text() == "Host *\n" and (f.stat().st_mode & 0o777) == 0o600
