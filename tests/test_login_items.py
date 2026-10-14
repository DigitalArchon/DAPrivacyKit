"""app.login_items: what starts at login, and the entries that are new since the last scan (the
baseline keeps salted hashes of their names, never the names); scheduled scans notify about them."""

from __future__ import annotations

import json

from daprivacyscanner.history import Baseline, diff, snapshot
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status
from daprivacyscanner.paths import PathResolver

from conftest import detect, ev, make_host, make_scan

CHECK = "app.login_items"
SYNC = "[Desktop Entry]\nType=Application\nName=Sync\nExec=env A=1 /opt/sync/syncd --quiet %U\n"
SYSTEM_ENTRY = "[Desktop Entry]\nType=Application\nName=Print queue\nExec=system-config-printer-applet\n"
GNOME_ONLY = "[Desktop Entry]\nName=G\nExec=gnome-thing\nOnlyShowIn=GNOME;\n"


def login_host(tmp_path, home=None, system=None, crontab="", env=None, **kw):
    files = {"/etc/xdg/autostart/print-applet.desktop": SYSTEM_ENTRY, "/etc/xdg/autostart/gnome-thing.desktop": GNOME_ONLY,
             **(system or {})}
    host = make_host(tmp_path, home_files=home, files=files, env={"XDG_CURRENT_DESKTOP": "X-Cinnamon", **(env or {})},
                     **kw)
    host.runner.handlers["crontab"] = lambda argv: CommandResult(argv, 0, crontab) if crontab is not None else \
        CommandResult(argv, 1, "", "no crontab for alice\n")
    return host


def test_only_the_systems_entries_pass(cat, tmp_path):
    o = detect(cat, CHECK, make_scan(login_host(tmp_path, crontab=None)))
    assert o.status is Status.PASS
    assert ev(o)["Autostart entries from the system's packages"] == 1          # the GNOME-only one isn't started
    assert o.items == ["/etc/xdg/autostart/print-applet.desktop"]


def test_the_users_own_entries(cat, tmp_path):
    home = {".config/autostart/sync.desktop": SYNC,
            ".config/autostart/print-applet.desktop": SYSTEM_ENTRY + "Hidden=true\n",        # turned off by the user
            ".config/systemd/user/default.target.wants/syncthing.service": "",
            ".config/plasma-workspace/env/agent.sh": "eval $(ssh-agent)\n"}
    crontab = "MAILTO=me\n# a comment\n*/5 * * * * /home/alice/bin/backup --password=hunter2\n@reboot /home/alice/bin/x\n"
    host = login_host(tmp_path, home=home, crontab=crontab)
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.WARN
    e = ev(o)
    assert e["~/.config/autostart/sync.desktop"] == "starts syncd (Sync)"
    assert e["user unit syncthing.service"] == "wanted by default.target"
    assert e["~/.config/plasma-workspace/env/agent.sh"] == "a script your Plasma session runs"
    assert e["Entries in your crontab"] == "2, 1 at boot"
    assert "hunter2" not in json.dumps([x.to_dict() for x in o.evidence]) + json.dumps(o.items)
    assert e["Autostart entries from the system's packages"] == 0


def test_programs_that_take_the_place_of_the_systems(cat, tmp_path):
    host = login_host(tmp_path, home={".local/bin/sudo": "#!/bin/sh\n", ".local/bin/mytool": "x"},
                      system={"/usr/bin/sudo": "", "/usr/bin/ls": ""}, crontab=None)
    host.environ = {**host.environ, "PATH": f"{host.home}/.local/bin:/usr/bin:{host.home}/late"}
    o = detect(cat, CHECK, make_scan(host))
    assert ev(o)["sudo on PATH (~/.local/bin/sudo)"] == "takes the place of the system's"
    assert ev(o)["Your folders on PATH before the system's"] == "~/.local/bin"
    assert any(n.title == "Programs that see passwords are replaced" for n in o.notes)


def test_the_apps_own_units_are_named_and_not_counted_as_yours(cat, tmp_path):
    host = login_host(tmp_path, home={".config/systemd/user/timers.target.wants/daprivacyscanner-scan.timer": ""},
                      crontab=None)
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.PASS and "user unit daprivacyscanner-scan.timer" in o.items


def test_baseline_marks_new_items_and_keeps_only_hashes(tmp_path):
    def report(items):
        return {"started": 1, "results": {CHECK: {"status": "warn", "effective_severity": 2, "kind": "info",
                                                  "items": items}}}
    paths = PathResolver(tmp_path, {"HOME": str(tmp_path)})
    b = Baseline(paths)
    assert b.record(report(["~/.config/autostart/a.desktop"])) is None              # the first scan: nothing is "new"
    saved = b.file.read_text()
    assert "a.desktop" not in saved and json.loads(saved)["results"][CHECK]["items"]
    changes = b.record(report(["~/.config/autostart/a.desktop", "~/.config/autostart/evil.desktop"]))
    assert changes["new_items"] == {CHECK: ["~/.config/autostart/evil.desktop"]}
    assert b.record(report(["~/.config/autostart/evil.desktop"]))["new_items"] == {}
    # a baseline from before inventories were remembered marks nothing new
    old = snapshot(report([]))
    del old["results"][CHECK]["items"]
    assert diff(old, report(["x"]))["new_items"] == {}


def test_report_and_scheduled_scan_name_new_items(cat, tmp_path, monkeypatch, capsys):
    from daprivacyscanner import app as app_mod
    from daprivacyscanner.host import Host
    host = login_host(tmp_path, crontab=None)
    monkeypatch.setattr(Host, "local", classmethod(lambda cls: host))
    app_mod.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=True, redact=False)
    assert not [c for c in host.runner.calls if c[0] == "notify-send" and "new in" in c[-2]]
    (host.home / ".config/autostart").mkdir(parents=True)
    (host.home / ".config/autostart/sync.desktop").write_text(SYNC)
    app_mod.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=False, redact=False)
    out = capsys.readouterr().out
    assert 'New since the last scan in "What starts when you log in":\n    + ~/.config/autostart/sync.desktop' in out
    [note] = [c for c in host.runner.calls if c[0] == "notify-send" and "new in" in c[-2]]
    assert note[-2] == "DA Privacy Kit: 1 new in what starts when you log in"
    # counted, never named: a notification daemon's history can keep the text on the disk
    assert "sync.desktop" not in note[-1] and "1 new entry" in note[-1]
    # nor does the saved last report keep the names beside the baseline's hashes: entries and the evidence naming
    # them are left out, the result says so, and the restored page is told what was left out
    from daprivacyscanner.history import LastReport
    from daprivacyscanner.paths import PathResolver
    saved = LastReport(PathResolver(host.home, host.environ)).file.read_text()
    assert "sync.desktop" not in saved
    restored = LastReport(PathResolver(host.home, host.environ)).load()
    r = restored["results"][CHECK]
    assert "items" not in r and any(n["title"] == "Not kept between runs" for n in r["notes"])
    assert restored["not_kept"] == [f"the entries of {CHECK}"] and restored["changes"]["new_items"] == {}


def test_how_to_gives_this_desktops_place_and_commands(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    home = {".config/systemd/user/default.target.wants/syncthing.service": "", ".local/bin/sudo": "x",
            ".config/autostart/my app.desktop": SYNC}
    host = login_host(tmp_path, home=home, system={"/usr/bin/sudo": ""}, crontab="0 * * * * x\n")
    host.environ = {**host.environ, "PATH": f"{host.home}/.local/bin:/usr/bin"}
    g = load_all()[CHECK](cat[CHECK]).plan_guide(make_scan(host, desktop=("x-cinnamon",)), Outcome(Status.WARN, "x"))
    cmds = [c for s in g.steps for c in s.commands]
    assert "cinnamon-settings startup" in cmds and "systemctl --user disable --now syncthing.service" in cmds
    assert "crontab -e" in cmds and "rm ~/.local/bin/sudo" in cmds and "rm ~/'.config/autostart/my app.desktop'" in cmds
    assert not g.plans
