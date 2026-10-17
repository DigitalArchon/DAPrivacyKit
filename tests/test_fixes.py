"""Every auto fix: detect the problem, apply the fix, see it fixed, revert from the undo log and
see the settings back (docs/TECHNICAL.md, Testing). Deleted history stays deleted."""

import pytest

from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.fixes import FIXES, set_jsonc_key
from daprivacyscanner.fix import apply_plan, revert_entry
from daprivacyscanner.model import Status
from daprivacyscanner.undo import UndoLog

from conftest import detect, ev, make_host, make_scan
from fakes import FakeGSettings, FakeKwriteconfig, FakeNmcli, recorder
from test_checks_telemetry_browser import chrome


def run_fix(cat, host, check_id, confirm=True, **scan_kw):
    """Detect, plan, apply. Returns (plan, apply result, undo log, scan_kw)."""
    check = load_all()[check_id](cat[check_id])
    scan = make_scan(host, **scan_kw)
    outcome = check.detect(scan)
    assert outcome.status in (Status.FAIL, Status.WARN), outcome.summary
    plan = check.plan_fix(scan, outcome)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    return plan, apply_plan(plan, host, log, confirmed_irreversible=confirm), log


def redetect(cat, host, check_id, **scan_kw):
    return load_all()[check_id](cat[check_id]).detect(make_scan(host, **scan_kw))


def revert(host, log, res):
    return revert_entry(log.get(res.entry_id), host, log)


def gnome(tmp_path, values, **kw):
    gs = FakeGSettings(values)
    host = make_host(tmp_path, **kw)
    host.runner.handlers["gsettings"] = gs
    return host, gs


def test_every_auto_check_has_a_fix(cat):
    auto = {s.id for s in cat if s.tier.value == "auto"}
    assert auto == set(FIXES)
    assert all(load_all()[i].supports_fix for i in FIXES)
    assert {i for i in FIXES if load_all()[i].fix_needs_root} == {"tel.countme", "kern.dmesg_restrict"}


# ------------------------------------------------------------------ settings fixes (apply, then revert)

def test_screen_lock_gnome(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.gnome.desktop.screensaver", "lock-enabled"): "false",
                                ("org.gnome.desktop.session", "idle-delay"): "uint32 0",
                                ("org.gnome.desktop.screensaver", "lock-delay"): "uint32 0"})
    plan, res, log = run_fix(cat, host, "auth.screen_lock")
    assert res.ok and len(plan.actions) == 2 and not plan.irreversible
    assert redetect(cat, host, "auth.screen_lock").status is Status.PASS
    assert all(r.ok for r in revert(host, log, res))
    assert gs.values[("org.gnome.desktop.session", "idle-delay")] == "uint32 0"
    assert gs.values[("org.gnome.desktop.screensaver", "lock-enabled")] == "false"


def test_screen_lock_cinnamon(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.cinnamon.desktop.screensaver", "lock-enabled"): "true",
                                ("org.cinnamon.desktop.session", "idle-delay"): "uint32 0",
                                ("org.cinnamon.desktop.screensaver", "lock-delay"): "uint32 0",
                                ("org.cinnamon.settings-daemon.plugins.power", "lock-on-suspend"): "false"})
    plan, res, log = run_fix(cat, host, "auth.screen_lock", desktop=("x-cinnamon",))
    assert res.ok and redetect(cat, host, "auth.screen_lock", desktop=("x-cinnamon",)).status is Status.PASS
    revert(host, log, res)
    assert gs.values[("org.cinnamon.settings-daemon.plugins.power", "lock-on-suspend")] == "false"


def test_screen_lock_kde(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/kscreenlockerrc": "[Daemon]\nAutolock=false\nTimeout=30\n"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    kw = dict(desktop=("kde",), plasma_major=6)
    plan, res, log = run_fix(cat, host, "auth.screen_lock", **kw)
    assert res.ok and redetect(cat, host, "auth.screen_lock", **kw).status is Status.PASS
    revert(host, log, res)
    text = (host.home / ".config/kscreenlockerrc").read_text()
    assert "Autolock=false" in text and "Timeout=30" in text


def test_lockscreen_notifications(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.gnome.desktop.notifications", "show-in-lock-screen"): "true",
                                ("org.gnome.desktop.notifications", "application-children"): "['org-gnome-chat']",
                                ("org.gnome.desktop.notifications.application:/org/gnome/desktop/notifications/"
                                 "application/org-gnome-chat/", "details-in-lock-screen"): "true"})
    plan, res, log = run_fix(cat, host, "auth.lockscreen_notifications")
    assert gs.values[("org.gnome.desktop.notifications", "show-in-lock-screen")] == "false"
    revert(host, log, res)
    assert gs.values[("org.gnome.desktop.notifications", "show-in-lock-screen")] == "true"


def test_location(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.gnome.system.location", "enabled"): "true"})
    plan, res, log = run_fix(cat, host, "tel.location")
    assert redetect(cat, host, "tel.location").status is Status.PASS
    revert(host, log, res)
    assert gs.values[("org.gnome.system.location", "enabled")] == "true"


def test_session_restore_kde_back_to_default(cat, tmp_path):
    host = make_host(tmp_path)
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    plan, res, log = run_fix(cat, host, "desk.session_restore", desktop=("kde",), plasma_major=6)
    assert "loginMode=emptySession" in (host.home / ".config/ksmserverrc").read_text()
    revert(host, log, res)
    assert not (host.home / ".config/ksmserverrc").exists()          # the default again: the fix made the file, so it goes


def test_session_restore_gnome(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.gnome.SessionManager", "auto-save-session"): "true"})
    plan, res, log = run_fix(cat, host, "desk.session_restore")
    revert(host, log, res)
    assert gs.values[("org.gnome.SessionManager", "auto-save-session")] == "true"


def nm_host(tmp_path):
    nm = FakeNmcli({
        "u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": "",
               "802-11-wireless.hidden": "no", "ipv6.ip6-privacy": "-1"},
        "u2": {"type": "802-11-wireless", "connection.id": "Cafe", "802-11-wireless.cloned-mac-address": "random",
               "ipv6.ip6-privacy": "2"},
        "u3": {"type": "802-3-ethernet", "connection.id": "Wired", "ipv6.ip6-privacy": "0"}})
    host = make_host(tmp_path, files={"/sys/class/net/enp1s0/device/vendor": "x",
                                      "/proc/sys/net/ipv6/conf/enp1s0/use_tempaddr": "0\n"})
    host.runner.handlers["nmcli"] = nm
    return host, nm




def test_ipv6_privacy(cat, tmp_path):
    """With the default for new networks already 2, only the connections that set something else are changed;
    those that take the default follow it."""
    host, nm = nm_host(tmp_path)
    (host.root / "proc/sys/net/ipv6/conf/default").mkdir(parents=True)
    (host.root / "proc/sys/net/ipv6/conf/default/use_tempaddr").write_text("2\n")
    plan, res, log = run_fix(cat, host, "net.ipv6_privacy")
    assert sorted(a.name for a in plan.actions) == ["Wired"]
    assert nm.connections["u3"]["ipv6.ip6-privacy"] == "2"
    revert(host, log, res)
    assert (nm.connections["u1"]["ipv6.ip6-privacy"], nm.connections["u3"]["ipv6.ip6-privacy"]) == ("-1", "0")


def test_devtools(cat, tmp_path):
    original = '{\n    // my settings\n    "editor.fontSize": 14,\n}\n'
    host = make_host(tmp_path, installed=["dotnet"], home_files={".config/Code/User/settings.json": original})
    plan, res, log = run_fix(cat, host, "tel.devtools")
    settings = (host.home / ".config/Code/User/settings.json").read_text()
    assert '"telemetry.telemetryLevel": "off"' in settings and "// my settings" in settings
    env = host.home / ".config/environment.d/60-daprivacyscanner-telemetry.conf"
    assert "DOTNET_CLI_TELEMETRY_OPTOUT=1" in env.read_text()
    assert redetect(cat, host, "tel.devtools").status is Status.PASS
    revert(host, log, res)
    assert (host.home / ".config/Code/User/settings.json").read_text() == original and not env.exists()


@pytest.mark.parametrize("text, expected", [
    (None, '{\n    "k": "off"\n}\n'),
    ("{}", '{\n    "k": "off"}'),
    ('{"k": "all", "x": 1}', '{"k": "off", "x": 1}'),
    ('{\n  "a": 1\n}', '{\n    "k": "off",\n  "a": 1\n}'),
])
def test_set_jsonc_key(text, expected):
    assert set_jsonc_key(text, "k", '"off"') == expected


# ------------------------------------------------------------------ clearing history and caches

def test_trash(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.gnome.desktop.privacy", "remove-old-trash-files"): "false"},
                     home_files={".local/share/Trash/files/old.pdf": "x", ".local/share/Trash/files/dir/a": "y",
                                 ".local/share/Trash/info/old.pdf.trashinfo": "[Trash Info]"})
    plan, res, log = run_fix(cat, host, "enc.trash")
    assert res.ok and len(plan.irreversible) == 2
    assert redetect(cat, host, "enc.trash").status is Status.PASS
    assert (host.home / ".local/share/Trash/files").is_dir()                         # the folder itself stays
    revert(host, log, res)
    assert gs.values[("org.gnome.desktop.privacy", "remove-old-trash-files")] == "false"
    assert not (host.home / ".local/share/Trash/files/old.pdf").exists()            # deleted stays deleted


def test_deletion_needs_confirmation(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/Trash/files/a": "x"})
    plan, res, log = run_fix(cat, host, "enc.trash", confirm=False, desktop=("kde",))
    assert not res.ok and (host.home / ".local/share/Trash/files/a").exists()




def test_kde_activities_stops_and_restarts_the_daemon(cat, tmp_path):
    calls = []
    host = make_host(tmp_path, files={"/proc/42/comm": "kactivitymanage\n"},
                     home_files={".local/share/kactivitymanagerd/resources/database": "x",
                                 ".local/share/kactivitymanagerd/resources/database-wal": "x",
                                 ".local/share/RecentDocuments/a.pdf.desktop": "[Desktop Entry]"})
    host.runner.handlers["systemctl"] = recorder(calls)
    plan, res, log = run_fix(cat, host, "desk.kde_activities", desktop=("kde",))
    assert res.ok and [c[2] for c in calls if c[2] in ("stop", "start")] == ["stop", "start"]
    assert not (host.home / ".local/share/kactivitymanagerd/resources/database").exists()
    assert redetect(cat, host, "desk.kde_activities", desktop=("kde",)).status is Status.PASS


def test_kde_activities_blocked_without_its_service(cat, tmp_path):
    from daprivacyscanner.host import CommandResult
    host = make_host(tmp_path, files={"/proc/42/comm": "kactivitymanage\n"},
                     home_files={".local/share/kactivitymanagerd/resources/database": "x",
                                 ".local/share/RecentDocuments/a.desktop": "[Desktop Entry]"},
                     commands={("systemctl", "--user", "cat", "plasma-kactivitymanagerd.service"): CommandResult((), 1)})
    plan, res, log = run_fix(cat, host, "desk.kde_activities", desktop=("kde",))
    assert plan.blockers and not res.ok


KLIPPER_DB = {".local/share/klipper/history3.sqlite": "rows", ".local/share/klipper/data/ab/ab": "copied"}


def plasma6(tmp_path, running=True, **kw):
    from fakes import APPLETSRC_6, FakePlasmaShell
    home_files = {".config/plasma-org.kde.plasma.desktop-appletsrc": APPLETSRC_6, **KLIPPER_DB, **kw.pop("home_files", {})}
    files = {"/proc/3/comm": "plasmashell\n"} if running else {}
    host = make_host(tmp_path, home_files=home_files, files={**files, **kw.pop("files", {})}, **kw)
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    shell = host.runner.handlers["qdbus6"] = FakePlasmaShell(host.home / ".config", host.home / ".local/share", running)
    return host, shell


def test_clipboard_klipper_turned_off_and_its_history_deleted(cat, tmp_path):
    from daprivacyscanner.desktop import tray_applet
    host, shell = plasma6(tmp_path)
    appletsrc = host.home / ".config/plasma-org.kde.plasma.desktop-appletsrc"
    plan, res, log = run_fix(cat, host, "desk.clipboard_history", desktop=("kde",), plasma_major=6)
    assert [a.kind for a in plan.actions] == ["kconfig", "clear-command", "plasmatray"]     # cleared while it still runs
    assert plan.actions[1].destructive and not plan.blockers
    assert any("Install CopyQ (flatpak install flathub com.github.hluk.copyq)" in e for e in plan.side_effects)
    assert res.ok and shell.cleared == 1 and not tray_applet(appletsrc.read_text(), "org.kde.plasma.clipboard").on
    assert not (host.home / ".local/share/klipper/data/ab/ab").exists()
    # its emptied database is left (Plasma may hold it until logout): still a finding, and a second Fix… deletes it
    o = redetect(cat, host, "desk.clipboard_history", desktop=("kde",), plasma_major=6)
    assert o.status is Status.FAIL and "off, but" in o.evidence[0].value
    plan2, res2, _ = run_fix(cat, host, "desk.clipboard_history", desktop=("kde",), plasma_major=6)
    assert [a.kind for a in plan2.actions] == ["delete"] and res2.ok
    assert redetect(cat, host, "desk.clipboard_history", desktop=("kde",), plasma_major=6).status is Status.PASS
    revert(host, log, res)                                  # Klipper back on, its setting back to the default
    assert tray_applet(appletsrc.read_text(), "org.kde.plasma.clipboard").trays == ("28",)
    assert not (host.home / ".config/klipperrc").exists()


def test_clipboard_klipper_leftover_waits_for_logout(cat, tmp_path):
    from fakes import APPLETSRC_6
    off = APPLETSRC_6.replace("org.kde.plasma.clipboard,", "")
    off = off.replace("[Containments][23][Applets][28][Applets][31]\nimmutability=1\nplugin=org.kde.plasma.clipboard\n\n", "")
    db = str(tmp_path / "home/alice/.local/share/klipper/history3.sqlite")
    host, _ = plasma6(tmp_path, home_files={".config/plasma-org.kde.plasma.desktop-appletsrc": off},
                      links={"/proc/3/fd/32": db})
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])
    plan = check.plan_fix(make_scan(host, desktop=("kde",), plasma_major=6), None)
    assert plan.empty and plan.blockers[0].startswith("Log out and back in first")


def test_clipboard_klipper_outside_plasma(cat, tmp_path):
    host, shell = plasma6(tmp_path, running=False)
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])
    plan = check.plan_fix(make_scan(host, desktop=("gnome",), plasma_major=6), None)
    assert [a.kind for a in plan.actions] == ["kconfig", "delete"] and not plan.blockers
    assert any("while you are logged in to Plasma" in e for e in plan.side_effects)


def test_clipboard_klipper_widget_of_its_own_blocks(cat, tmp_path):
    from fakes import APPLETSRC_6
    widget = APPLETSRC_6 + "\n[Containments][1]\nplugin=org.kde.desktopcontainment\n\n[Containments][1][Applets][7]\nplugin=org.kde.plasma.clipboard\n"
    host, _ = plasma6(tmp_path, home_files={".config/plasma-org.kde.plasma.desktop-appletsrc": widget})
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])
    plan = check.plan_fix(make_scan(host, desktop=("kde",), plasma_major=6), None)
    assert plan.blockers and "Remove the Clipboard widget" in plan.blockers[0]


def test_clipboard_skips_running_managers(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/7/comm": "copyq\n"},
                     home_files={".config/copyq/copyq.conf": "[Options]\ntabs=&clipboard\n"})
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])
    plan = check.plan_fix(make_scan(host), None)
    assert plan.empty and plan.blockers[0].startswith("Close copyq first (its tray icon → Exit)")


def test_clipboard_copyq_kept_in_memory(cat, tmp_path):
    conf = "[Options]\ntabs=&clipboard\n\n[MainWindow]\ngeometry=@ByteArray(x)\n"
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": conf,
                                           ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat": "copied",
                                           ".local/share/copyq/copyq/items/a/b.dat": "a large copy"})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    assert res.ok and [a.kind for a in plan.actions] == ["copyq-tab", "copyq-command", "delete", "delete"]
    written = (host.home / ".config/copyq/copyq.conf").read_text()
    assert "[Tabs]\n1\\name=&clipboard\n1\\store_items=false\nsize=1\n" in written and "geometry=@ByteArray(x)" in written
    assert not (host.home / ".local/share/copyq/copyq/items/a/b.dat").exists()
    assert redetect(cat, host, "desk.clipboard_history").status is Status.PASS
    revert(host, log, res)
    assert (host.home / ".config/copyq/copyq.conf").read_text() == conf
    # CopyQ 17's layout: the tab's file in the data folder, beside items/; one a move left behind goes too
    host = make_host(tmp_path / "17", home_files={".config/copyq/copyq.conf": conf,
                                                  ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat": "left behind",
                                                  ".local/share/copyq/copyq/copyq_tab_JmNsaXBib2FyZA==.dat": "copied",
                                                  ".local/share/copyq/copyq/items/a/b.dat": "a large copy"})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    assert res.ok and [a.kind for a in plan.actions] == ["copyq-tab", "copyq-command", "delete", "delete", "delete"]
    assert not list((host.home / ".local/share/copyq/copyq").rglob("*.dat")) and not list((host.home / ".config/copyq").glob("*.dat"))
    assert redetect(cat, host, "desk.clipboard_history").status is Status.PASS


def test_clipboard_copyq_leaves_the_users_own_tabs(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": "[Options]\ntabs=&clipboard, Notes\n",
                                           ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat": "copied",
                                           ".config/copyq/copyq_tab_Tm90ZXM=.dat": "my notes",
                                           ".local/share/copyq/copyq/items/a/b.dat": "a note's large item, or a copy's"})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    assert res.ok and [a.kind for a in plan.actions] == ["copyq-tab", "copyq-command"]   # CopyQ deletes its own
    assert any("next time it starts" in e for e in plan.side_effects)
    assert (host.home / ".config/copyq/copyq_tab_Tm90ZXM=.dat").exists()
    assert (host.home / ".local/share/copyq/copyq/items/a/b.dat").exists()


# copyq-commands.ini as CopyQ 16 writes it (its first default command)
COPYQ_COMMANDS = ("[Commands]\n1\\Command=copyq: plugins.itempinned.pin()\n1\\Icon=\n1\\InMenu=true\n1\\Input=!OUTPUT\n"
                  "1\\InternalId=copyq_pinned_pin\n1\\Name=Pin\n1\\Output=application/x-copyq-item-pinned\nsize=1\n")


def test_clipboard_copyq_keeps_the_clipboard_like_klipper(cat, tmp_path):
    from daprivacyscanner import ini
    from daprivacyscanner.checks.fixes import COPYQ_KEEP_NAME, COPYQ_KEEP_SCRIPT
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": "[Options]\ntabs=&clipboard\n",
                                           ".config/copyq/copyq-commands.ini": COPYQ_COMMANDS})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    ini_file = host.home / ".config/copyq/copyq-commands.ini"
    text = ini_file.read_text()
    # the layout CopyQ wrote for the same command (tested): quoted, \n and \" escaped, IsScript, Name; size counted
    assert '2\\Command="copyq:\\n// Added by DA Privacy Kit.' in text and "2\\IsScript=true\n" in text
    assert text.endswith(f"2\\Name={COPYQ_KEEP_NAME}\nsize=2\n") and text.startswith(COPYQ_COMMANDS[:-len("size=1\n")])
    entry = ini.qsettings_array(ini.parse(text), "Commands")[1]
    assert ini.qsettings_value(entry["Command"]) == COPYQ_KEEP_SCRIPT
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])        # not added twice
    (host.home / ".config/copyq/copyq.conf").write_text("[Options]\ntabs=&clipboard\n")
    assert "copyq-command" not in [a.kind for a in check.plan_fix(make_scan(host), None).actions]
    revert(host, log, res)
    assert ini_file.read_text() == COPYQ_COMMANDS


def test_clipboard_copyq_command_older_version_replaced(cat, tmp_path):
    from daprivacyscanner import ini
    from daprivacyscanner.checks.fixes import COPYQ_KEEP_NAME, COPYQ_KEEP_SCRIPT
    old = ('[Commands]\n1\\Command="copyq:\\nvar item = getItem(0)\\n"\n1\\IsScript=true\n'
           f"1\\Name={COPYQ_KEEP_NAME}\nsize=1\n")
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": "[Options]\ntabs=&clipboard\n",
                                           ".config/copyq/copyq-commands.ini": old})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    ini_file = host.home / ".config/copyq/copyq-commands.ini"
    entries = ini.qsettings_array(ini.parse(ini_file.read_text()), "Commands")
    assert len(entries) == 1 and ini.qsettings_value(entries[0]["Command"]) == COPYQ_KEEP_SCRIPT
    assert "application/x-copyq-item-pinned" in COPYQ_KEEP_SCRIPT       # the newest copy, not a pinned item
    revert(host, log, res)
    assert ini_file.read_text() == old


def test_clipboard_copyq_command_edited_since_is_kept(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": "[Options]\ntabs=&clipboard\n"})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    ini_file = host.home / ".config/copyq/copyq-commands.ini"
    ini_file.write_text(ini_file.read_text().replace("from memory", "from memory, edited"))
    results = revert(host, log, res)
    assert any(not r.ok and r.conflict for r in results) and "edited" in ini_file.read_text()


def test_copyq_set_tab_prop():
    from daprivacyscanner.fix import copyq_set_tab_prop as put
    assert put(None, "&clipboard", "store_items", "false") == "[Tabs]\n1\\name=&clipboard\n1\\store_items=false\nsize=1\n"
    conf = ("[Options]\ntabs=Notes, &clipboard\n\n[Tabs]\n1\\icon=\n1\\max_item_count=0\n1\\name=Notes\n"
            "1\\store_items=true\nsize=1\n\n[Shortcuts]\nx=y\n")
    out = put(conf, "&clipboard", "store_items", "false")
    assert "1\\name=Notes\n1\\store_items=true\n" in out and "2\\name=&clipboard\n2\\store_items=false\nsize=2\n\n[Shortcuts]\nx=y\n" in out
    assert put(out, "&clipboard", "store_items", "false") == out
    assert put(out, "&clipboard", "store_items", None) == conf                 # the entry it added goes again
    assert "1\\store_items=false" in put(conf, "Notes", "store_items", "false")
    assert '1\\name="a, b"' in put(None, "a, b", "store_items", "false")


def test_clipboard_copyq_revert_ignores_what_copyq_rewrote(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": "[Options]\ntabs=&clipboard\n"})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    conf = host.home / ".config/copyq/copyq.conf"
    conf.write_text(conf.read_text().replace("tabs=&clipboard", "tabs=&clipboard, Notes"))    # CopyQ, as it ran (tested)
    assert revert(host, log, res)[0].ok
    assert conf.read_text() == "[Options]\ntabs=&clipboard, Notes\n"


def test_zeitgeist(cat, tmp_path):
    calls = []
    # the kernel keeps 15 characters of a process's name: zeitgeist-daemon runs as "zeitgeist-daemo" (the review of
    # 2026-10-17: the 16-character name here never matched a real process, so --quit never ran)
    host = make_host(tmp_path, files={"/etc/xdg/autostart/zeitgeist-datahub.desktop": "[Desktop Entry]\nExec=zeitgeist-datahub\n",
                                      "/proc/9/comm": "zeitgeist-daemo\n"},
                     home_files={".local/share/zeitgeist/activity.sqlite": "x", ".local/share/zeitgeist/activity.sqlite-wal": "x"})

    def quit_daemon(argv):
        import shutil
        shutil.rmtree(host.root / "proc/9")          # it exits
        return recorder(calls)(argv)
    host.runner.handlers["zeitgeist-daemon"] = quit_daemon
    plan, res, log = run_fix(cat, host, "desk.zeitgeist")
    override = host.home / ".config/autostart/zeitgeist-datahub.desktop"
    assert res.ok and "Hidden=true" in override.read_text() and calls == [("zeitgeist-daemon", "--quit")]
    assert not (host.home / ".local/share/zeitgeist/activity.sqlite").exists()
    # started over D-Bus on demand: the user's own service file starts /bin/false instead
    engine = host.home / ".local/share/dbus-1/services/org.gnome.zeitgeist.Engine.service"
    assert engine.read_text() == "[D-BUS Service]\nName=org.gnome.zeitgeist.Engine\nExec=/bin/false\n"
    revert(host, log, res)
    assert not override.exists() and not engine.exists()




def test_gnome_app_usage(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.gnome.desktop.privacy", "remember-app-usage"): "true"},
                     home_files={".local/share/gnome-shell/application_state": "<application-state/>"})
    plan, res, log = run_fix(cat, host, "desk.gnome_app_usage")
    assert redetect(cat, host, "desk.gnome_app_usage").status is Status.PASS
    revert(host, log, res)
    assert gs.values[("org.gnome.desktop.privacy", "remember-app-usage")] == "true"


def test_media_players(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".local/state/mpv/watch_later/ABC": "start=1",
        ".config/vlc/vlc-qt-interface.conf": "[RecentsMRL]\nlist=file:///secret.mkv\ntimes=10\n[MainWindow]\nx=1\n",
        ".config/vlc/vlcrc": "[qt]\n#qt-recentplay=1\n"})
    plan, res, log = run_fix(cat, host, "app.media_players")
    qt = (host.home / ".config/vlc/vlc-qt-interface.conf").read_text()
    assert "secret" not in qt and "x=1" in qt and "qt-recentplay=0" in (host.home / ".config/vlc/vlcrc").read_text()
    assert redetect(cat, host, "app.media_players").status is Status.PASS
    revert(host, log, res)
    assert "#qt-recentplay=1" in (host.home / ".config/vlc/vlcrc").read_text()       # the setting is back
    assert "secret" not in (host.home / ".config/vlc/vlc-qt-interface.conf").read_text()   # the history isn't


def test_media_players_haruna_and_celluloid(cat, tmp_path):
    """Haruna 1.8 (tested) keeps recent files and resume points in haruna.db and the last file in haruna.conf; the fix
    clears them and sets its own settings so it keeps neither. Celluloid's resume points are mpv's watch_later files."""
    import sqlite3
    host = make_host(tmp_path, home_files={
        ".config/haruna/haruna.conf": "[General]\nLastPlayedFile=file:///home/alice/Videos/secret.mp4\nOsdFontSize=25\n",
        ".config/celluloid/watch_later/0123ABCD": "start=28.1\n"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    (host.home / ".local/share/haruna").mkdir(parents=True)
    db = sqlite3.connect(host.home / ".local/share/haruna/haruna.db")
    db.executescript("CREATE TABLE recent_files (recent_file_id INTEGER, url TEXT, filename TEXT, opened_from TEXT,"
                     " timestamp INTEGER); CREATE TABLE playback_position (md5_hash TEXT, path TEXT, position REAL);"
                     "INSERT INTO recent_files VALUES (1, 'file:///home/alice/Videos/secret.mp4', 'secret.mp4', 'x', 1);"
                     "INSERT INTO playback_position VALUES ('d2f8', 'file:///home/alice/Videos/secret.mp4', 28.1);")
    db.commit()
    db.close()
    o = detect(cat, "app.media_players", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.FAIL and ev(o)["Haruna recent files and resume points"] == 3
    assert ev(o)["Celluloid resume points"] == 1
    plan, res, log = run_fix(cat, host, "app.media_players", desktop=("kde",), plasma_major=6)
    conf = (host.home / ".config/haruna/haruna.conf").read_text()
    assert "secret" not in conf and "OsdFontSize=25" in conf and "MaxRecentFiles=0" in conf
    assert "MinDurationToSavePosition=9999" in conf
    assert not (host.home / ".local/share/haruna/haruna.db").exists()
    assert not (host.home / ".config/celluloid/watch_later/0123ABCD").exists()
    assert redetect(cat, host, "app.media_players", desktop=("kde",), plasma_major=6).status is Status.PASS
    revert(host, log, res)
    conf = (host.home / ".config/haruna/haruna.conf").read_text()
    assert "MaxRecentFiles" not in conf and "MinDurationToSavePosition" not in conf and "secret" not in conf


def test_media_players_say_they_clear_lines_not_delete_settings(cat, tmp_path):
    """VLC's and Haruna's history is in their settings files: the dry run says only those lines change, names the
    keys, never their values (the history), and VLC's edit stays inside [RecentsMRL]."""
    import sqlite3
    qt = ("[General]\nlist=keep-me\n[RecentsMRL]\nlist=file:///secret.mkv, file:///other.mkv\ntimes=10, 20\n"
          "[OpenDialog]\ntimes=keep\n")
    host = make_host(tmp_path, home_files={".config/vlc/vlc-qt-interface.conf": qt,
                                           ".config/haruna/haruna.conf": "[General]\nLastPlayedFile=file:///secret.mp4\n"})
    (host.home / ".local/share/haruna").mkdir(parents=True)
    db = sqlite3.connect(host.home / ".local/share/haruna/haruna.db")
    db.executescript("CREATE TABLE recent_files (url TEXT); CREATE TABLE playback_position (path TEXT, position REAL);"
                     "INSERT INTO recent_files VALUES ('file:///secret.mp4');")
    db.commit()
    db.close()
    plan = FIXES["app.media_players"].plan(cat["app.media_players"], make_scan(host), None)
    steps = {st["text"]: st["lines"] for st in plan.to_dict()["steps"]}
    vlc = next(t for t in steps if "VLC" in t)
    assert "only these lines change, the file and the rest of it stay" in vlc
    assert steps[vlc] == ["- list=…", "- times=…", "+ list=", "+ times="]
    assert "secret" not in " ".join(sum(steps.values(), []))
    haruna = next(t for t in steps if "Haruna's database" in t)
    assert steps[haruna] == ["~/.local/share/haruna/haruna.db"]
    from daprivacyscanner.checks.fixes import _clear_vlc_recents
    assert _clear_vlc_recents(qt) == ("[General]\nlist=keep-me\n[RecentsMRL]\nlist=\ntimes=\n"
                                      "[OpenDialog]\ntimes=keep\n")


def test_haruna_s_database_is_kept_when_it_holds_more_than_history(cat, tmp_path):
    """Deleting haruna.db is right only while it holds the two history tables (1.8): a later Haruna that keeps
    anything else there keeps its database, and the plan says so."""
    import sqlite3
    host = make_host(tmp_path)
    (host.home / ".config/haruna").mkdir(parents=True)
    (host.home / ".local/share/haruna").mkdir(parents=True)
    db = sqlite3.connect(host.home / ".local/share/haruna/haruna.db")
    db.executescript("CREATE TABLE recent_files (url TEXT); CREATE TABLE playback_position (path TEXT, position REAL);"
                     "CREATE TABLE playlists (name TEXT); INSERT INTO recent_files VALUES ('file:///x.mp4');")
    db.commit()
    db.close()
    plan = FIXES["app.media_players"].plan(cat["app.media_players"], make_scan(host), None)
    assert not any("haruna.db" in a.describe() or "Haruna's database" in a.describe() for a in plan.actions)
    assert any("isn't deleted" in e for e in plan.side_effects)


def test_a_shell_history_s_lines_are_never_previewed(tmp_path):
    """ClearInFile shows changed keys only for settings files: a history's lines can hold the secret being removed."""
    from daprivacyscanner.fix import ClearInFile
    f = tmp_path / "history"
    f.write_text("ls\nmysql -psecret --host=db\n")
    a = ClearInFile(f, lambda t: "ls\n", "Remove 1 line", "~/history")
    assert a.preview() == []
    b = ClearInFile(f, lambda t: "ls\n", "Remove 1 line", "~/history", settings=True)
    assert b.preview() == ["… and 1 other line"]


def test_a_deletion_lists_where_its_files_are(tmp_path):
    """The dry run shows where the files are, so the user can look first: each one when few, else each folder."""
    from daprivacyscanner.fix import DeleteFiles
    home = tmp_path / "home"
    few = [home / "Documents" / "a.txt~", home / "Projects" / "x" / ".b.py.swp"]
    assert DeleteFiles(home, few, "editor backup files", "~").preview() == ["~/Documents/a.txt~", "~/Projects/x/.b.py.swp"]
    many = [home / "cache" / f"d{i % 3}" / f"{i:040x}" for i in range(60)] + [home / "cache" / "top"]
    lines = DeleteFiles(home / "cache", many, "a cache", "~/.cache/x").preview()
    assert lines == ["~/.cache/x/d0/  (20 files)", "~/.cache/x/d1/  (20 files)", "~/.cache/x/d2/  (20 files)",
                     "~/.cache/x/  (1 file)"]


def test_pdf_readers_blocked_while_okular_runs(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/5/comm": "okular\n"},
                     home_files={".local/share/okular/docdata/1.x.pdf.xml": "x"})
    plan, res, log = run_fix(cat, host, "app.pdf_readers", desktop=("kde",))
    assert not res.ok and (host.home / ".local/share/okular/docdata/1.x.pdf.xml").exists()
    (host.sys_path("/proc/5/comm")).write_text("bash\n")
    plan, res, log = run_fix(cat, host, "app.pdf_readers", desktop=("kde",))
    assert res.ok and not (host.home / ".local/share/okular/docdata/1.x.pdf.xml").exists()


OKULARRC = "[General]\nShowSidebar=true\n\n[Recent Files]\nFile1[$e]=$HOME/Documents/secret.pdf\nName1[$e]=secret.pdf\n\n[Zoom]\nx=1\n"


def zathura_db(path, marks=0):
    import sqlite3
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE fileinfo (file TEXT, page INTEGER); CREATE TABLE bookmarks (file TEXT, id TEXT);"
                     "CREATE TABLE quickmarks (file TEXT, id TEXT);"
                     "INSERT INTO fileinfo VALUES ('/home/alice/Documents/secret.pdf', 3);")
    for i in range(marks):
        db.execute("INSERT INTO bookmarks VALUES ('/home/alice/Documents/secret.pdf', ?)", (str(i),))
    db.commit()
    db.close()


def test_pdf_readers_okular_docdata_and_zathura(cat, tmp_path):
    """Okular's docdata goes (its Open Recent list is app.kde_recent_files's, and stays); Zathura's database goes
    when it holds no bookmarks of the user's, and is left (and said) when it does."""
    host = make_host(tmp_path, home_files={".config/okularrc": OKULARRC,
                                           ".local/share/okular/docdata/1.secret.pdf.xml": "x"})
    zathura_db(host.home / ".local/share/zathura/bookmarks.sqlite")
    o = detect(cat, "app.pdf_readers", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and o.summary.startswith("Okular and Zathura remember")
    assert ev(o)["Okular per-document records"] == 1 and ev(o)["Documents Zathura remembers"] == 1
    assert "Okular recent documents" not in ev(o) and any(n.related == ("app.kde_recent_files",) for n in o.notes)
    plan, res, log = run_fix(cat, host, "app.pdf_readers", desktop=("kde",))
    assert (host.home / ".config/okularrc").read_text() == OKULARRC
    assert not (host.home / ".local/share/okular/docdata/1.secret.pdf.xml").exists()
    assert not (host.home / ".local/share/zathura/bookmarks.sqlite").exists()
    assert redetect(cat, host, "app.pdf_readers", desktop=("kde",)).status is Status.PASS
    zathura_db(host.home / ".local/share/zathura/bookmarks.sqlite", marks=2)
    plan, res, log = run_fix(cat, host, "app.pdf_readers", desktop=("kde",))
    assert (host.home / ".local/share/zathura/bookmarks.sqlite").exists()
    assert any("2 bookmarks of yours" in e for e in plan.side_effects)


def test_electron_caches_skip_running_apps(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/3/comm": "codium\n"}, home_files={
        ".config/Slack/Cache/Cache_Data/f1": "x", ".config/Slack/GPUCache/d": "x", ".config/Slack/Local Storage/keep": "x",
        ".config/VSCodium/Code Cache/js/a": "x"})
    plan, res, log = run_fix(cat, host, "app.electron_caches")
    assert res.ok and not (host.home / ".config/Slack/Cache/Cache_Data/f1").exists()
    assert (host.home / ".config/Slack/Local Storage/keep").exists()                 # not a cache: kept
    assert (host.home / ".config/VSCodium/Code Cache/js/a").exists()                 # running: left alone
    assert any("VSCodium" in s for s in plan.side_effects)


def test_electron_caches_skip_an_app_holding_its_cache_open(cat, tmp_path):
    """The process isn't named after its folder; an open file under the folder is what counts."""
    host = make_host(tmp_path, files={"/proc/3/comm": "teams\n"},
                     home_files={".config/Microsoft Teams/Cache/Cache_Data/f1": "x", ".config/Microsoft Teams/GPUCache/d": "x",
                                 ".config/Other/Cache/f": "x", ".config/Other/GPUCache/d": "x"})
    fd = host.sys_path("/proc/3/fd")
    fd.mkdir(parents=True)
    (fd / "7").symlink_to(host.home / ".config/Microsoft Teams/Cache/Cache_Data/f1")
    plan, res, log = run_fix(cat, host, "app.electron_caches")
    assert (host.home / ".config/Microsoft Teams/Cache/Cache_Data/f1").exists() and any("Microsoft Teams" in e for e in plan.side_effects)
    assert not (host.home / ".config/Other/Cache/f").exists()


def test_crashpad_blocked_while_the_browser_runs(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/4/comm": "brave\n"},
                     home_files={".config/BraveSoftware/Brave-Browser/Crash Reports/pending/x.dmp": "x"})
    chrome(host.home, root=".config/BraveSoftware/Brave-Browser")
    plan, res, log = run_fix(cat, host, "br.crashpad_dumps")
    assert plan.blockers == ["Close Brave first."] and not res.ok
    assert (host.home / ".config/BraveSoftware/Brave-Browser/Crash Reports/pending/x.dmp").exists()


def test_crashpad_blocked_by_the_singleton_lock(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/chromium/Crash Reports/completed/x.dmp": "x"})
    chrome(host.home, root=".config/chromium")
    (host.home / ".config/chromium/SingletonLock").symlink_to("host-1234")
    plan, res, log = run_fix(cat, host, "br.crashpad_dumps")
    assert plan.blockers == ["Close Chromium first."]


def test_crash_dumps_of_firefox_and_electron_apps(cat, tmp_path):
    """Firefox keeps a pending report beside its profiles (a minidump of the process's memory and its notes; tested on
    Firefox 157), content crashes in each profile's minidumps; Electron apps keep Crashpad reports of their own."""
    from test_checks_telemetry_browser import firefox
    host = make_host(tmp_path, home_files={".config/Slack/GPUCache/d": "x", ".config/Slack/Crashpad/completed/a.dmp": "m",
                                           ".config/Slack/Crashpad/settings.dat": "keep"})
    prof = firefox(host.home, root=".config/mozilla/firefox")
    pending = host.home / ".config/mozilla/firefox/Crash Reports/pending"
    pending.mkdir(parents=True)
    (pending / "1f69.dmp").write_text("memory")
    (pending / "1f69.extra").write_text("{}")
    (host.home / ".config/mozilla/firefox/Crash Reports/LastCrash").write_text("1")
    (prof / "minidumps").mkdir()
    (prof / "minidumps/2a.dmp").write_text("memory")
    o = detect(cat, "br.crashpad_dumps", make_scan(host))
    assert o.status is Status.FAIL and o.summary.startswith("4 crash dump files")
    assert set(ev(o)) == {"Firefox", "Firefox profile abcd.default-release", "Slack (Electron)"}
    (host.root / "proc/7").mkdir(parents=True)
    (host.root / "proc/7/comm").write_text("firefox\n")
    plan, res, log = run_fix(cat, host, "br.crashpad_dumps")
    assert "Skipped: Close Firefox first." in plan.side_effects and not (host.home / ".config/Slack/Crashpad/completed/a.dmp").exists()
    (host.root / "proc/7/comm").write_text("bash\n")
    plan, res, log = run_fix(cat, host, "br.crashpad_dumps")
    assert not list(pending.iterdir()) and (host.home / ".config/Slack/Crashpad/settings.dat").exists()
    assert redetect(cat, host, "br.crashpad_dumps").status is Status.PASS


def test_crashpad(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/chromium/Crash Reports/completed/x.dmp": "x",
                                           ".config/chromium/Crash Reports/settings.dat": "keep"})
    chrome(host.home, root=".config/chromium")
    plan, res, log = run_fix(cat, host, "br.crashpad_dumps")
    assert res.ok and (host.home / ".config/chromium/Crash Reports/settings.dat").exists()
    assert redetect(cat, host, "br.crashpad_dumps").status is Status.PASS


def test_flatpak_caches(cat, tmp_path):
    host = make_host(tmp_path, commands={("flatpak", "ps", "--columns=application"): "org.mozilla.firefox\n"},
                     home_files={".var/app/org.mozilla.firefox/cache/a": "x", ".var/app/org.gnome.Loupe/cache/b": "x",
                                 ".var/app/org.gnome.Loupe/data/keep": "x"})
    plan, res, log = run_fix(cat, host, "sbx.flatpak_caches")
    assert not (host.home / ".var/app/org.gnome.Loupe/cache/b").exists()
    assert (host.home / ".var/app/org.gnome.Loupe/data/keep").exists()
    assert (host.home / ".var/app/org.mozilla.firefox/cache/a").exists()             # running: left alone


def test_processes_are_read_once_per_plan(cat, tmp_path, monkeypatch):
    """Reading every process's open files and memory map is slow on a desktop with a browser
    running; a plan that checks many folders reads /proc once."""
    from daprivacyscanner.checks import _util

    calls = []
    real = _util.open_files
    monkeypatch.setattr(_util, "open_files", lambda host: calls.append(1) or real(host))
    host = make_host(tmp_path, home_files={f".config/App{i}/Cache/f": "x" for i in range(4)}
                     | {f".config/App{i}/GPUCache/d": "x" for i in range(4)})
    run_fix(cat, host, "app.electron_caches")
    assert len(calls) == 1


def test_folder_view_records(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/dolphin/view_properties/global/.directory": "[Dolphin]"},
                     installed=["dolphin"])
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    plan, res, log = run_fix(cat, host, "desk.folder_view_records", desktop=("kde",), plasma_major=6)
    assert res.ok and not (host.home / ".local/share/dolphin/view_properties/global/.directory").exists()
    assert "GlobalViewProps=true" in (host.home / ".config/dolphinrc").read_text()
    assert redetect(cat, host, "desk.folder_view_records", desktop=("kde",)).status is Status.PASS
    revert(host, log, res)
    assert not (host.home / ".config/dolphinrc").exists()                     # the fix made it: it goes


def test_location_outside_gnome_turns_off_geoclues_lookup_as_root(cat, tmp_path):
    files = {"/etc/geoclue/geoclue.conf": "[wifi]\nenable=true\nurl=https://api.beacondb.net/v1/geolocate\n"}
    check = load_all()["tel.location"](cat["tel.location"])
    host = make_host(tmp_path / "old", files=files)                    # GeoClue before 2.7: no conf.d
    scan = make_scan(host, desktop=("x-cinnamon",))
    assert check.detect(scan).status is Status.WARN and check.can_fix(scan, None)
    [a] = check.plan_fix(scan, None).actions
    assert (a.request, a.args) == ("edit_config", {"target": "geoclue"})
    host = make_host(tmp_path / "new", files={**files, "/etc/geoclue/conf.d/README": ""})
    plan = check.plan_fix(make_scan(host, desktop=("kde",)), None)
    assert plan.needs_root and [(a.request, a.args) for a in plan.actions] == [
        ("write_dropin", {"name": "geoclue", "settings": {"enable": "false"}})]
    # what the helper writes, read back: off
    (host.root / "etc/geoclue/conf.d/90-daprivacyscanner.conf").write_text("[wifi]\nenable=false\n")
    assert check.detect(make_scan(host, desktop=("kde",))).status is Status.PASS


class FakeXfconf:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def __call__(self, argv):
        from daprivacyscanner.host import CommandResult
        a = list(argv[1:])
        channel, prop = a[a.index("-c") + 1], a[a.index("-p") + 1]
        key = (channel, prop)
        if "-r" in a:
            self.values.pop(key, None)
        elif "-s" in a:
            if key not in self.values and "-n" not in a:
                return CommandResult(tuple(argv), 1, "", "Property does not exist")
            self.values[key] = a[a.index("-s") + 1]
        elif key not in self.values:
            return CommandResult(tuple(argv), 1, "", f'Property "{prop}" does not exist on channel "{channel}".\n')
        else:
            return CommandResult(tuple(argv), 0, self.values[key] + "\n", "")
        return CommandResult(tuple(argv), 0, "", "")


@pytest.mark.parametrize("version, saves", [("4.18.3", True), ("4.20.4", False)])
def test_session_restore_xfce(cat, tmp_path, version, saves):
    """xfce4-session (its source): SaveOnExit unset is on before 4.19 and off from it; the logout dialog keeps a
    screenshot of the whole screen (ShowScreenshots, on by default) in ~/.cache/sessions/thumbs-DISPLAY."""
    xf = FakeXfconf()
    host = make_host(tmp_path, installed=["xfconf-query"], commands={"xfce4-session --version":
                                                                     f"xfce4-session {version} (Xfce 4.x)\n"},
                     home_files={".cache/sessions/xfce4-session-laptop:0": "[Session: Default]\nClient0_Command=firefox\n",
                                 ".cache/sessions/thumbs-:0/Default.png": "png"})
    host.runner.handlers["xfconf-query"] = xf
    o = detect(cat, "desk.session_restore", make_scan(host, desktop=("xfce",)))
    assert o.status is Status.FAIL and "screenshot of the whole screen" in o.summary
    assert ev(o)["Save the session at logout"] is saves
    plan, res, log = run_fix(cat, host, "desk.session_restore", desktop=("xfce",))
    assert res.ok and not list((host.home / ".cache/sessions").rglob("*.png"))
    assert not (host.home / ".cache/sessions/xfce4-session-laptop:0").exists()
    assert xf.values[("xfce4-session", "/general/ShowScreenshots")] == "false"
    assert (("xfce4-session", "/general/SaveOnExit") in xf.values) is saves
    assert redetect(cat, host, "desk.session_restore", desktop=("xfce",)).status is Status.PASS
    assert all(r.ok for r in revert(host, log, res)) and xf.values == {}


def test_session_restore_mate(cat, tmp_path):
    host, gs = gnome(tmp_path, {("org.mate.session", "auto-save-session"): "true"})
    o = detect(cat, "desk.session_restore", make_scan(host, desktop=("mate",)))
    assert o.status is Status.FAIL
    plan, res, log = run_fix(cat, host, "desk.session_restore", desktop=("mate",))
    assert gs.values[("org.mate.session", "auto-save-session")] == "false"
    revert(host, log, res)
    assert gs.values[("org.mate.session", "auto-save-session")] == "true"


def test_screen_lock_xfce(cat, tmp_path):
    xf = FakeXfconf({("xfce4-screensaver", "/saver/idle-activation/delay"): "20",
                     ("xfce4-screensaver", "/lock/saver-activation/enabled"): "false"})
    host = make_host(tmp_path, installed=["xfconf-query", "xfce4-screensaver"])
    host.runner.handlers["xfconf-query"] = xf
    plan, res, log = run_fix(cat, host, "auth.screen_lock", desktop=("xfce",))
    assert res.ok and [a.prop for a in plan.actions] == ["/lock/saver-activation/enabled", "/saver/idle-activation/delay"]
    assert redetect(cat, host, "auth.screen_lock", desktop=("xfce",)).status is Status.PASS
    assert all(r.ok for r in revert(host, log, res))
    assert xf.values == {("xfce4-screensaver", "/saver/idle-activation/delay"): "20",
                         ("xfce4-screensaver", "/lock/saver-activation/enabled"): "false"}


def test_xfce_screen_lock_defaults_pass_and_light_locker_is_unknown(cat, tmp_path):
    host = make_host(tmp_path, installed=["xfconf-query", "xfce4-screensaver"])
    host.runner.handlers["xfconf-query"] = FakeXfconf()
    assert redetect(cat, host, "auth.screen_lock", desktop=("xfce",)).status is Status.PASS     # every default
    host = make_host(tmp_path / "ll", installed=["xfconf-query", "light-locker"])
    assert redetect(cat, host, "auth.screen_lock", desktop=("xfce",)).status is Status.UNKNOWN


def test_gnome_app_usage_record_left_outside_gnome_is_deleted(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/gnome-shell/application_state": "<x/>"})
    plan, res, log = run_fix(cat, host, "desk.gnome_app_usage", desktop=("kde",))
    assert res.ok and not (host.home / ".local/share/gnome-shell/application_state").exists()


def test_clipboard_diodon_cleared_and_pano_explained(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/diodon/storage.xml": "x",
                                           ".local/share/pano@elhan.io/pano.db": "x"})
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])
    plan = check.plan_fix(make_scan(host), None)
    assert [a.label for a in plan.actions] == ["Diodon clipboard history"]
    assert any("Pano's own menu" in s for s in plan.side_effects)
