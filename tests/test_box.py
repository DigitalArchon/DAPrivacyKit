"""A Box (app.boxes): an app kept in a sandbox with a home of its own. Its settings file, the guide that sets it
up and its revert, the sandbox it starts in, the runs it keeps in numbers, the menu entry and the API."""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner.fix import CopyTree, FixContext
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import box as B
from daprivacyscanner.tools import integration as I
from daprivacyscanner.tools import trial

from conftest import detect, make_host, make_scan
from test_guides import apply, build, options, revert

H = {"X-Token": "t0ken"}
DESKTOP = "[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\n{extra}"


@pytest.fixture
def program(monkeypatch, tmp_path):
    exe = tmp_path / "bin" / "daprivacyscanner"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(I, "program", lambda environ: [str(exe)])
    monkeypatch.setattr(I, "unsafe_place", lambda path, uid=None: "")     # pytest's folders are in /tmp, anyone's
    return exe


@pytest.fixture
def host(tmp_path):
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    h = make_host(tmp_path, files={
        "/usr/share/applications/chat.desktop": DESKTOP.format(name="Chat App", exec="chat --flag %U", extra=""),
        "/usr/share/applications/org.x.Meet.desktop": DESKTOP.format(
            name="Meet", exec="flatpak run --branch=stable org.x.Meet", extra="X-Flatpak=org.x.Meet\n"),
        "/usr/share/applications/term.desktop": DESKTOP.format(name="Term", exec="htop", extra="Terminal=true\n"),
        "/usr/bin/chat": "", "/tmp/.X11-unix/X0": "", "/run/user/1000/x": ""},
        env={"XDG_DATA_DIRS": "/usr/share", "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"})
    for name in ("bwrap", "pasta", "ip", "flatpak"):
        h.runner.handlers[name] = ok
    return h


def a_box(**kw):
    return B.Box(**{"slug": "chat-app", "name": "Chat App", "kind": "installed", "argv": ["/usr/bin/chat", "--flag"], **kw})


# ------------------------------------------------------------------ its settings

def test_the_settings_file_reads_back_as_written():
    b = a_box(network="observed", sound=True, env={"A": "1"})
    assert B.parse(B.config_text(b), "chat-app") == b
    flat = B.Box("meet", "Meet", "flatpak", ["org.x.Meet"], flatpak="org.x.Meet", network="on")
    assert B.parse(B.config_text(flat), "meet") == flat


@pytest.mark.parametrize("change", [
    {"slug": "other"}, {"kind": "exe"}, {"network": "lan"}, {"argv": []}, {"argv": "chat"}, {"argv": [5]},
    {"env": {"1BAD": "x"}}, {"env": []}, {"name": ""}, {"name": "Chat\nExec=evil"}, {"network": "on"},   # "on" is a Flatpak's only
    {"kind": "flatpak"}, {"kind": "flatpak", "flatpak": "../x"}, {"kind": "flatpak", "flatpak": "org.x.A", "network": "observed"},
])
def test_a_settings_file_that_isnt_what_the_guide_writes_is_no_box(change):
    d = {**json.loads(B.config_text(a_box())), **change}
    assert B.parse(json.dumps(d), "chat-app") is None
    assert B.parse("not json", "chat-app") is None and B.parse("[]", "chat-app") is None


def test_a_name_becomes_a_folder_name():
    assert B.slug_of("Chat App (v2)!") == "chat-app-v2" and B.slug_of("Ünïcode") == "n-code" and B.slug_of("***") == "app"
    # a file's name can hold a newline: one line in the menu entry, never a second (an Exec= of its own)
    assert B.clean_name("Tool\nExec=evil\t v2") == "Tool Exec=evil v2" and B.clean_name("\x01") == "app"
    assert "\n" not in B.launcher_text(B.Box("t", B.clean_name("T\nExec=x"), "program", ["/app/t"]), ["/usr/bin/daps"]).split("Name=")[1].split("\n")[0]
    with pytest.raises(trial.TrialError):
        B.folder(SimpleNamespace(home=Path("/h")), "../etc")


# ------------------------------------------------------------------ set up, used, reverted

def test_a_box_for_an_installed_app_is_set_up_and_reverted(cat, host, program):
    from daprivacyscanner.runner import Runner
    assert detect(cat, "app.boxes", make_scan(host)).status is Status.WARN
    g = build(cat, host, "app.boxes")
    step = g.steps[1]
    apps = dict(step.inputs[0].choices)
    assert apps == {"": "Choose an app", "chat.desktop": "Chat App", "org.x.Meet.desktop": "Meet (Flatpak)"}, \
        "no terminal apps, no trial"
    g = Runner(cat, host).plan_fix("app.boxes", {"source": "chat.desktop"})[1]
    plan = options(g)["Set up a Box for Chat App"]
    assert [a.kind for a in plan.actions] == ["mkdir", "mkdir", "mkdir", "mkdir", "file", "file"]
    log, res = apply(host, plan)
    f = host.home / "Boxes/chat-app"
    assert stat.S_IMODE((f / "home").stat().st_mode) == 0o700 and stat.S_IMODE((f / "box.json").stat().st_mode) == 0o600
    box = B.read(host, "chat-app")
    assert box.argv == ["/usr/bin/chat", "--flag"] and box.network == "off" and box.gpu and not box.sound
    launcher = (host.home / ".local/share/applications/daprivacyscanner-box-chat-app.desktop").read_text()
    assert f"Exec={program} --box chat-app" in launcher and "Name=Chat App (in its Box)" in launcher and B.MARK in launcher
    o = detect(cat, "app.boxes", make_scan(host))
    assert o.status is Status.PASS and "1 app is kept in a Box" in o.summary
    # set up, the same choice has nothing left to change; the Box's own menu entry isn't offered for a Box
    again = Runner(cat, host).plan_fix("app.boxes", {"source": "chat.desktop"})[1]
    assert again.steps[1].done and "daprivacyscanner-box-chat-app.desktop" not in dict(again.steps[1].inputs[0].choices)
    # the app has run and left data: reverting takes the menu entry and settings, never the data
    (f / "home/.config").mkdir()
    (f / "home/.config/chat.db").write_text("messages")
    revert(host, log, res)
    assert not (f / "box.json").exists() and not (host.home / ".local/share/applications").exists()
    assert (f / "home/.config/chat.db").read_text() == "messages" and not (f / "Exchange").exists()
    assert detect(cat, "app.boxes", make_scan(host)).status is Status.WARN


SETTINGS_PAGES = {   # as Mint 22.3 (Cinnamon), Ubuntu (GNOME) and Plasma 6 have them, the fields that tell
    "cinnamon-settings-universal-access.desktop": ("Accessibility", "cinnamon-settings accessibility",
                                                   "OnlyShowIn=X-Cinnamon;\nCategories=Settings;\n"),
    "cinnamon-display-panel.desktop": ("Display", "cinnamon-settings display",
                                       "Categories=GTK;Settings;HardwareSettings;X-Cinnamon-Settings-Panel;\n"
                                       "OnlyShowIn=X-Cinnamon;\nX-Cinnamon-Settings-Panel=display\n"),
    "cinnamon-settings.desktop": ("System Settings", "env WEBKIT_DISABLE_COMPOSITING_MODE=1 cinnamon-settings",
                                  "Categories=Settings;\nOnlyShowIn=X-Cinnamon;\n"),
    "gufw.desktop": ("Firewall Configuration", "gufw", "Categories=GNOME;GTK;Settings;Security;X-GNOME-Settings-Panel;\n"
                     "X-GNOME-Settings-Panel=gufw\n"),
    "gnome-wifi-panel.desktop": ("Wi-Fi", "gnome-control-center wifi",
                                 "Categories=GTK;GNOME;Settings;X-GNOME-NetworkSettings;HardwareSettings;\n"),
    "kcm_kscreen.desktop": ("Display Configuration", "systemsettings kcm_kscreen", "X-KDE-AliasFor=systemsettings\n"),
}
APPS_TOO = {         # in the Settings category, but apps of their own
    "blueman-manager.desktop": ("Bluetooth Manager", "blueman-manager", "Categories=GTK;GNOME;Settings;HardwareSettings;\n"),
    "mintbackup.desktop": ("Backup Tool", "mintbackup", "NotShowIn=KDE;\nCategories=Application;System;Settings\n"),
}


def test_no_app_is_chosen_for_the_user_and_the_desktops_settings_pages_arent_offered(cat, tmp_path, program, monkeypatch):
    """Found in use: the guide chose the menu's first entry, on Cinnamon its Accessibility settings, one click from a Box
    for it, and listed every page of the desktop's settings (34 on Mint 22.3) among the apps. Now nothing is chosen
    until the user chooses (the option is blocked), but for the program on trial, and the settings pages are left
    out."""
    files = {"/usr/share/applications/chat.desktop": DESKTOP.format(name="Chat App", exec="chat", extra="")}
    for desk, (name, exe, extra) in {**SETTINGS_PAGES, **APPS_TOO}.items():
        files[f"/usr/share/applications/{desk}"] = DESKTOP.format(name=name, exec=exe, extra=extra)
        files[f"/usr/bin/{exe.split()[-1] if exe.startswith('env') else exe.split()[0]}"] = ""
    host = make_host(tmp_path, files={**files, "/usr/bin/chat": "", "/tmp/.X11-unix/X0": ""},
                     env={"XDG_DATA_DIRS": "/usr/share", "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"})
    from daprivacyscanner.runner import Runner
    from daprivacyscanner.tools import menu
    assert {a.id for a in menu.apps(host) if a.panel} == set(SETTINGS_PAGES)
    monkeypatch.setattr(trial, "CURRENT", None)
    g = build(cat, host, "app.boxes")
    step = g.steps[1]
    assert step.inputs[0].value == "" and step.inputs[0].choices[0] == ("", "Choose an app")
    assert [c[1] for c in step.inputs[0].choices[1:]] == ["Backup Tool", "Bluetooth Manager", "Chat App"]
    [opt] = step.options
    assert opt.plan.blockers == ["Choose the app to keep in a Box first."] and not opt.plan.actions and not step.done
    chosen = Runner(cat, host).plan_fix("app.boxes", {"source": "chat.desktop"})[1]
    assert "Set up a Box for Chat App" in options(chosen)
    assert Runner(cat, host).plan_fix("app.boxes", {"source": "cinnamon-settings-universal-access.desktop"})[1] \
        .steps[1].inputs[0].value == "", "a settings page can't be chosen at all"
    # the program on trial is what "Keep it in a Box…" opens the guide for: it is the one chosen
    monkeypatch.setattr(trial, "CURRENT", SimpleNamespace(kind="appimage", argv=["/app/Tool.AppImage"], state="ready",
                                                          name="Tool.AppImage", env={}, app=tmp_path))
    assert build(cat, host, "app.boxes").steps[1].inputs[0].value == "trial"


def test_the_guide_says_what_wayland_still_gives_a_boxed_app(cat, host, program):
    """The review of 2026-11-04: the Box's guide said only what X11 gives an app with a window. On KDE Plasma 6.7 the
    connection marked as a sandbox's still gets the clipboard, and desktops built on wlroots without the protocol give
    any app the screen and the clipboard, as the browser panel says."""
    text = " ".join(body for s in build(cat, host, "app.boxes").steps for _head, body in (s.parts or []))
    assert "KDE Plasma 6.7 still lets it read the clipboard" in text and "built on wlroots" in text
    assert "record the screen" in text


def test_the_guide_says_the_mount_list_names_the_account(cat, host, program):
    """The review of 2026-11-04: inside the sandbox /proc/self/mountinfo has each folder's real path, so a Box's app
    can read /home/<account>/Boxes/<name>/home: the account's name, which the sandbox otherwise hides ("user"). Said
    where the guide lists what the app can read."""
    text = " ".join(body for s in build(cat, host, "app.boxes").steps for _head, body in (s.parts or []))
    assert "The list of what is mounted where" in text and "~/Boxes/NAME in your home folder, which names your account" in text


def test_the_guide_takes_the_network_and_what_it_gets(cat, host, program):
    from daprivacyscanner.runner import Runner
    g = Runner(cat, host).plan_fix("app.boxes", {"source": "org.x.Meet.desktop", "network": "on", "gpu": False, "sound": True})[1]
    opt = next(o for st in g.steps for o in st.options)
    apply(host, opt.plan)
    box = B.read(host, "meet")
    assert (box.kind, box.flatpak, box.network, box.gpu, box.sound) == ("flatpak", "org.x.Meet", "on", False, True)
    assert box.argv == ["--branch=stable", "org.x.Meet"]
    # a Flatpak can't have the observed network: the value isn't taken
    g2 = Runner(cat, host).plan_fix("app.boxes", {"source": "org.x.Meet.desktop", "network": "observed"})[1]
    assert g2.steps[1].inputs[1].value == "off"


def test_a_program_on_trial_is_kept_by_copying_it_into_the_box(cat, host, program, monkeypatch):
    src = host.home / "Downloads"
    src.mkdir()
    (src / "Great Tool.AppImage").write_bytes(b"\x7fELF\x02\x01\x01\x00AI\x02" + b"\0" * 80)
    t = trial.prepare_file(host, src / "Great Tool.AppImage", "disk")
    monkeypatch.setattr(trial, "CURRENT", t)
    try:
        g = build(cat, host, "app.boxes")
        assert g.steps[1].inputs[0].choices[0] == ("trial", "The program on trial now: Great Tool.AppImage")
        plan = options(g)["Set up a Box for Great Tool"]
        assert "copytree" in [a.kind for a in plan.actions]
        log, res = apply(host, plan)
        f = host.home / "Boxes/great-tool"
        assert (f / "app/Great_Tool.AppImage").stat().st_mode & 0o100, "the copy keeps its permission to run"
        box = B.read(host, "great-tool")
        assert box.kind == "appimage" and box.argv == ["/app/Great_Tool.AppImage"] and box.env == {"APPIMAGE_EXTRACT_AND_RUN": "1"}
        trial.discard(host, t)                                              # the trial goes; the Box has its own copy
        assert (f / "app/Great_Tool.AppImage").exists() and B.problem(host, box) is None
        revert(host, log, res)
        assert not f.exists(), "nothing ran in it: the whole Box goes, the copied program too"
    finally:
        trial.discard(host, t)


@pytest.mark.parametrize("file, name", [
    ("Obsidian-1.6.7.AppImage", "Obsidian"), ("Obsidian-1.7.4.AppImage", "Obsidian"), ("Great Tool.AppImage", "Great Tool"),
    ("kdenlive-24.02.1-x86_64.AppImage", "kdenlive"), ("FreeCAD_0.21.2-Linux-x86_64.AppImage", "FreeCAD"),
    ("OpenShot-v3.1.1-x86_64.AppImage", "OpenShot"), ("LibreWolf-128.0-1.x86_64.AppImage", "LibreWolf"),
    ("tor-browser-linux-x86_64-14.0.tar.xz", "tor-browser"), ("hello_2.10-3_amd64.deb", "hello"),
    ("Foo-1.2.3-beta.1.AppImage", "Foo"), ("nvim.appimage", "nvim"), ("tool.tar.gz", "tool"), ("7-Zip.AppImage", "7-Zip"),
    ("Tool 2.AppImage", "Tool 2"), ("1.2.AppImage", "1"),
])
def test_a_downloaded_programs_box_is_named_without_its_release(file, name):
    """Found in use: a Box was named after its file, so Obsidian-1.6.7.AppImage and Obsidian-1.7.4.AppImage were two
    programs, and the newer one got a Box of its own with an empty home."""
    assert B.program_name(file) == name


def _kept(cat, host, src, file, data=b""):
    """A trial of the downloaded `file`, kept in a Box through the guide; the trial discarded. (log, result)."""
    from daprivacyscanner.runner import Runner
    (src / file).write_bytes(b"\x7fELF\x02\x01\x01\x00AI\x02" + data + b"\0" * 80)
    t = trial.prepare_file(host, src / file, "disk")
    trial.CURRENT = t
    try:
        g = Runner(cat, host).plan_fix("app.boxes", {"source": "trial"})[1]
        return g, t
    except BaseException:
        trial.discard(host, t)
        raise


def test_a_newer_release_replaces_the_program_of_its_box_and_keeps_its_home(cat, host, program, monkeypatch):
    """A newer release of a program kept in a Box (another file name: Obsidian-1.7.4.AppImage) was offered a Box of its
    own, blocked ("there already for another program") once it was named as the old one: the Box of the same program
    is now offered, its program replaced and its home and Exchange kept; any other Box kept from a trial can be chosen;
    reverting puts the earlier program and its settings back."""
    monkeypatch.setattr(trial, "CURRENT", None)
    src = host.home / "Downloads"
    src.mkdir()
    g, t = _kept(cat, host, src, "Obsidian-1.6.7.AppImage", b"1")
    apply(host, options(g)["Set up a Box for Obsidian"])
    trial.discard(host, t)
    f = host.home / "Boxes/obsidian"
    (f / "home/vault.md").write_text("notes")
    (f / "Exchange/in.txt").write_text("given")
    g, t = _kept(cat, host, src, "Obsidian-1.7.4.AppImage", b"22")
    try:
        step = g.steps[1]
        into = next(i for i in step.inputs if i.name == "into")
        assert into.value == "obsidian" and ("obsidian", "Replace the program of Box “Obsidian”") in into.choices
        plan = options(g)["Replace the program of Box Obsidian"]
        assert [a.kind for a in plan.actions] == ["copytree", "file"] and plan.actions[0].replace and not plan.blockers
        assert any("already holds another copy of Obsidian" in e and "Obsidian-1.7.4.AppImage takes its place" in e
                   for e in plan.side_effects)
        log, res = apply(host, plan)
        assert (f / "app/Obsidian-1.7.4.AppImage").exists() and not (f / "app/Obsidian-1.6.7.AppImage").exists()
        assert B.read(host, "obsidian").argv == ["/app/Obsidian-1.7.4.AppImage"] and B.read(host, "obsidian").name == "Obsidian"
        assert (f / "home/vault.md").read_text() == "notes" and (f / "Exchange/in.txt").read_text() == "given"
        assert [b.slug for b in B.every(host)] == ["obsidian"], "no second Box"
        revert(host, log, res)
        assert (f / "app/Obsidian-1.6.7.AppImage").exists() and B.read(host, "obsidian").argv == ["/app/Obsidian-1.6.7.AppImage"]
        assert (f / "home/vault.md").read_text() == "notes"
        # a new Box of it isn't made beside the one there: it would be the same folder
        from daprivacyscanner.runner import Runner
        new = Runner(cat, host).plan_fix("app.boxes", {"source": "trial", "into": "new"})[1]
        assert any("There is a Box named “Obsidian” already: choose to replace its program above" in b
                   for o in new.steps[1].options for b in o.plan.blockers)
    finally:
        trial.discard(host, t)
    # a Box named after its file before this (Obsidian-1.6.7) is the same program's, and keeps its name
    old = json.loads((f / "box.json").read_text())
    f = f.rename(host.home / "Boxes/obsidian-1-6-7")
    (f / "box.json").write_text(B.config_text(B.Box("obsidian-1-6-7", "Obsidian-1.6.7", "appimage", old["argv"], old["env"])))
    g, t = _kept(cat, host, src, "Obsidian-1.7.4.AppImage", b"22")
    try:
        assert [i.value for i in g.steps[1].inputs if i.name == "into"] == ["obsidian-1-6-7"]
        assert "Replace the program of Box Obsidian-1.6.7" in options(g)
    finally:
        trial.discard(host, t)


def test_a_reverted_boxs_home_is_taken_up_again(cat, host, program):
    """Reverting a Box keeps its home and Exchange folders while they hold anything, and they then blocked a new Box of
    that name for good ("is there already and isn't a Box this app made"). A folder holding only those is taken up
    again, and the guide says so; anything else in it still blocks."""
    from daprivacyscanner.runner import Runner
    plan_of = lambda: options(Runner(cat, host).plan_fix("app.boxes", {"source": "chat.desktop"})[1])["Set up a Box for Chat App"]  # noqa: E731
    log, res = apply(host, plan_of())
    f = host.home / "Boxes/chat-app"
    (f / "home/.config").mkdir()
    (f / "home/.config/chat.db").write_text("messages")
    revert(host, log, res)
    assert sorted(os.listdir(f)) == ["home"]
    plan = plan_of()
    assert not plan.blockers and [a.kind for a in plan.actions] == ["mkdir", "file", "file"]
    assert any("holds what a Box of this name left when it was reverted (its home folder): this Box takes it up again"
               in e for e in plan.side_effects)
    log, res = apply(host, plan)
    assert B.read(host, "chat-app") is not None and (f / "home/.config/chat.db").read_text() == "messages"
    (f / "runs.json").write_text("{}")                                  # it ran: the record of its runs stays with the home
    revert(host, log, res)
    assert sorted(os.listdir(f)) == ["home", "runs.json"] and not plan_of().blockers
    (f / "notes.txt").write_text("someone's")
    assert "isn't a Box this app made" in " ".join(plan_of().blockers)
    (f / "notes.txt").unlink()
    os.symlink(str(host.home), f / "Exchange")
    assert "isn't a Box this app made" in " ".join(plan_of().blockers), "a link isn't a Box's folder"


def test_copying_a_tree_refuses_a_place_that_is_taken(tmp_path, host):
    (tmp_path / "src/sub").mkdir(parents=True)
    (tmp_path / "src/sub/x").write_text("x")
    os.symlink("sub/x", tmp_path / "src/link")
    ctx = FixContext(host, tmp_path / "backups")
    rec = CopyTree(tmp_path / "src", tmp_path / "dest", "~/dest", "the program").apply(ctx)
    assert os.readlink(tmp_path / "dest/link") == "sub/x" and CopyTree.changed_back(rec, host) is None
    from daprivacyscanner.fix import FixError
    with pytest.raises(FixError, match="already there"):
        CopyTree(tmp_path / "src", tmp_path / "dest", "~/dest", "the program").apply(ctx)
    assert CopyTree.revert(rec, ctx).ok and not (tmp_path / "dest").exists() and (tmp_path / "src/sub/x").exists()
    assert CopyTree.revert(rec, ctx).message.endswith("already gone")


def test_a_program_with_read_only_folders_is_removed_on_revert_and_its_backup_forgotten(tmp_path, host):
    """A program's tree copied with its modes (a tarball's, Go's module cache): shutil.rmtree couldn't delete what is
    in its read-only folders, so the Box couldn't be reverted ("couldn't be removed completely"), nor the copy a newer
    program replaced forgotten with History."""
    from daprivacyscanner.fix import FixPlan, apply_plan, revert_entry
    from daprivacyscanner.undo import UndoLog
    for v in ("v1", "v2"):
        (tmp_path / v / "lib/cache").mkdir(parents=True)
        (tmp_path / v / "lib/cache/mod").write_text(v)
        os.chmod(tmp_path / v / "lib/cache", 0o500)
        os.chmod(tmp_path / v / "lib", 0o555)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    dest = host.home / "Boxes/prog/app"
    dest.parent.mkdir(parents=True)
    try:
        one = apply_plan(FixPlan("app.boxes", "Box", [CopyTree(tmp_path / "v1", dest, "~/Boxes/prog/app", "prog")]),
                         host, log)
        two = apply_plan(FixPlan("app.boxes", "Box", [CopyTree(tmp_path / "v2", dest, "~/Boxes/prog/app", "prog",
                                                               replace=True)]), host, log)
        assert one.ok and two.ok and (dest / "lib/cache/mod").read_text() == "v2"
        assert all(r.ok for r in revert_entry(log.get(two.entry_id), host, log)) and (dest / "lib/cache/mod").read_text() == "v1"
        assert all(r.ok for r in revert_entry(log.get(one.entry_id), host, log)) and not dest.exists()
        apply_plan(FixPlan("app.boxes", "Box", [CopyTree(tmp_path / "v1", dest, "~/Boxes/prog/app", "prog")]), host, log)
        apply_plan(FixPlan("app.boxes", "Box", [CopyTree(tmp_path / "v2", dest, "~/Boxes/prog/app", "prog",
                                                         replace=True)]), host, log)
        assert log.forget(everything=True) and not (log.dir / "backups").exists()
    finally:
        for p in [*tmp_path.rglob("*")]:
            if p.is_dir() and not p.is_symlink():
                os.chmod(p, 0o700)


def _two_copies(tmp_path, host):
    """A Box set up with its program, then a newer program of the same name kept in it: two History entries."""
    from daprivacyscanner.fix import FixPlan, MakeDir, apply_plan
    from daprivacyscanner.undo import UndoLog
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    for v in ("v1", "v2"):
        (tmp_path / v / "bin").mkdir(parents=True)
        (tmp_path / v / "bin/prog").write_text(v)
    f = host.home / "Boxes/prog"
    one = apply_plan(FixPlan("app.boxes", "Box", [MakeDir(f.parent, "~/Boxes", 0o700), MakeDir(f, "~/Boxes/prog", 0o700),
                                                  CopyTree(tmp_path / "v1", f / "app", "~/Boxes/prog/app", "prog")]), host, log)
    two = apply_plan(FixPlan("app.boxes", "Box", [CopyTree(tmp_path / "v2", f / "app", "~/Boxes/prog/app", "prog, newer",
                                                           replace=True)]), host, log)
    assert one.ok and two.ok and (f / "app/bin/prog").read_text() == "v2"
    return log, f, one.entry_id, two.entry_id


def test_reverting_a_box_leaves_a_newer_copy_to_its_own_entry(tmp_path, host):
    """The Box's entry reverted while a later entry's newer copy of its program stood: that copy was removed, and
    reverting the later entry then made ~/Boxes/<name>/app again to put the old program in it."""
    from daprivacyscanner.fix import revert_entry
    log, f, one, two = _two_copies(tmp_path, host)
    copy = revert_entry(log.get(one), host, log)[0]                    # the last step is put back first
    assert copy.conflict and not copy.ok and "revert the later change first" in copy.message
    assert (f / "app/bin/prog").read_text() == "v2"
    assert all(r.ok for r in revert_entry(log.get(two), host, log)) and (f / "app/bin/prog").read_text() == "v1"
    assert all(r.ok for r in revert_entry(log.get(one), host, log)) and not (f / "app").exists()
    # and the Box's folders, which the first revert left while the newer copy stood in them, went with it: counted as
    # put back then, they stayed for good, empty
    assert not f.exists() and not f.parent.exists() and log.get(one)["state"] == "reverted"


def test_a_copy_put_back_never_makes_its_folders_again(tmp_path, host):
    """The Box's folder removed by hand: reverting the newer copy's entry made it again (0755, with the old program in
    it) to put the earlier copy back."""
    import shutil
    from daprivacyscanner.fix import revert_entry
    log, f, one, two = _two_copies(tmp_path, host)
    shutil.rmtree(f.parent)
    [r] = revert_entry(log.get(two), host, log)
    assert not r.ok and "the folder it was in is gone" in r.message and not f.parent.exists()


# ------------------------------------------------------------------ how it runs

def set_up(host, box):
    f = B.folder(host, box.slug)
    for sub in ("home", "Exchange"):
        (f / sub).mkdir(parents=True)
    (f / "box.json").write_text(B.config_text(box))
    return f


def test_a_box_runs_in_a_trials_sandbox_with_its_own_home_and_the_exchange_folder(host):
    f = set_up(host, a_box())
    t = B.as_trial(host, B.read(host, "chat-app"))
    assert t.home == f / "home" and t.private == host.root / "run/user/1000/daprivacyscanner-box-chat-app"
    assert stat.S_IMODE(t.private.stat().st_mode) == 0o700
    spawned = []
    how = trial.start(host, t, B.options(a_box()), lambda argv, **kw: spawned.append(argv) or SimpleNamespace(pid=1 << 22, stdout=None))
    try:
        argv = spawned[0]
        binds = [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == "--bind"]
        assert (str(f / "home"), "/home/user") in binds and (str(f / "Exchange"), "/home/user/Exchange") in binds
        assert how["decoys"] == 0 and not list((f / "home").iterdir()), "no decoys in a Box: it is the app's real home"
        assert not any(str(f / "private") in a for a in argv) and not (f / "private").exists()
        assert argv[argv.index("--") + 1:] == ["/usr/bin/chat", "--flag"]
    finally:
        trial.stop(host, t)


def test_a_box_that_cant_start_says_why(host):
    f = set_up(host, a_box(argv=["/usr/bin/gone"]))
    assert B.problem(host, B.read(host, "chat-app")) == "its program (/usr/bin/gone) is no longer installed"
    with pytest.raises(trial.TrialError, match="no longer installed"):
        B.as_trial(host, B.read(host, "chat-app"))
    kept = set_up(host, a_box(slug="tool", name="Tool", kind="appimage", argv=["/app/tool"]))
    assert B.problem(host, B.read(host, "tool")) == "its program is missing from the Box" and kept.is_dir()
    assert f.is_dir()
    # the Exchange folder is bound into the sandbox writable: a link there would hand it whatever the link points to
    (f / "Exchange").rmdir()
    os.symlink(str(host.home), f / "Exchange")
    assert "a link" in B.problem(host, B.read(host, "chat-app"))


def test_a_flatpak_box_isnt_started_while_its_app_is_open(host):
    """The review of 2026-11-04: a Box's copy of a Flatpak app owns the app's name on the bus, so with the app open as
    usual it handed its start to that copy (the real home, its network) and ended: the launcher opened the app outside
    the Box without a word. Its dialog now says to close the app first."""
    set_up(host, a_box(slug="meet", name="Meet", kind="flatpak", argv=["--branch=stable", "org.x.Meet"], flatpak="org.x.Meet"))
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 0, "4242 org.x.Meet\n" if "ps" in argv else "")
    spawned = []
    with pytest.raises(trial.TrialError, match="Meet is open already.*Close Meet first"):
        B.run_to_end(host, B.read(host, "meet"), lambda argv, **kw: spawned.append(argv), wait=0.01)
    assert not spawned and not B.running(host, "meet") and B.runs(host, "meet")["runs"] == []


def test_what_a_box_puts_in_its_exchange_folder_is_counted_apart(host):
    """Found in use: a Box's runs missed what the app saved in its Exchange folder, which is bound into its home: the
    home's watch saw only the empty mount point under the bind, never the folder's files. The folder has a watch of
    its own while the Box runs, and what was put there (made, written or moved in, and still there) is counted apart
    from what it wrote in its home, in the run's numbers."""
    f = set_up(host, a_box())
    t = B.as_trial(host, B.read(host, "chat-app"))
    trial.start(host, t, B.options(a_box()), lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None))
    try:
        time.sleep(0.2)
        for name in ("report.pdf", "photo.jpg"):                    # as the app saves them, through the bind
            (f / "Exchange" / name).write_text("saved")
        (f / "Exchange/part.tmp").write_text("x")
        (f / "Exchange/part.tmp").unlink()                          # gone again: nothing was put there
        (f / "Exchange/Sub").mkdir()                                # a folder isn't a file
        (f / "home/settings.conf").write_text("its own")
        time.sleep(0.3)
    finally:
        trial.stop(host, t)
    assert t.result["exchange"] == 2 and t.result["summary"]["totals"]["created"] == 1, "apart from what it wrote at home"
    run = B.record_run(host, B.read(host, "chat-app"), t)
    assert run["exchange"] == 2 and run["written"] == 1
    own = host.home / "a-trial"
    for sub in ("home", "app", "private"):
        (own / sub).mkdir(parents=True)
    plain = trial.Trial("0a1b2c3d4e5f", own, "disk", "installed", "Chat", "an installed app", argv=["/usr/bin/chat"])
    trial.start(host, plain, {}, lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None))
    trial.stop(host, plain)
    assert plain.result["exchange"] is None, "a trial has no Exchange folder"


def test_runs_are_kept_in_numbers_and_hosts_as_hashes(host):
    box = a_box(network="observed")
    f = set_up(host, box)

    def a_run(hosts):
        return SimpleNamespace(started=1790000000, result={
            "seconds": 600, "failed": False, "summary": {"totals": {"written": 2, "created": 5, "deleted": 1}},
            "exchange": 3, "hosts": {"hosts": [{"host": h, "sent": 1000} for h in hosts]}})
    first = B.record_run(host, box, a_run(["chat.example.net", "cdn.example.net"]))
    assert first == {"when": 1790000000, "seconds": 600, "written": 7, "deleted": 1, "exchange": 3, "network": "observed",
                     "hosts": 2, "new_hosts": 2, "sent": 2000, "failed": False, "signal": None}
    second = B.record_run(host, box, a_run(["chat.example.net", "tracker.example.org"]))
    assert second["hosts"] == 2 and second["new_hosts"] == 1, "one host it had never contacted before"
    saved = (f / "runs.json").read_text()
    assert "example" not in saved, "no host is kept by name"
    assert stat.S_IMODE((f / "runs.json").stat().st_mode) == 0o600 and len(json.loads(saved)["hosts"]) == 3
    for _ in range(B.RUNS_KEPT + 5):
        B.record_run(host, box, a_run([]))
    assert len(B.runs(host, "chat-app")["runs"]) == B.RUNS_KEPT
    quiet = B.record_run(host, a_box(), a_run([]))                          # a Box with no network: nothing to count
    assert quiet["hosts"] is None and quiet["new_hosts"] is None
    B.clear_runs(host, "chat-app")
    assert B.runs(host, "chat-app")["runs"] == []


def test_the_launcher_runs_the_box_to_its_end_and_notes_that_it_runs(host):
    set_up(host, a_box())
    box = B.read(host, "chat-app")
    seen = []

    def spawn(argv, **kw):
        seen.append(B.running(host, "chat-app"))                            # while it runs, the panel can tell
        return SimpleNamespace(pid=1 << 22, stdout=None)
    t = B.run_to_end(host, box, spawn, wait=0.01)
    assert seen == [True] and t.state == "ended" and not B.running(host, "chat-app")
    assert len(B.runs(host, "chat-app")["runs"]) == 1
    # the lock is a process's, not a number's: held, a second launcher is refused; a stale file means nothing
    lock = host.root / "run/user/1000/daprivacyscanner-box-chat-app/lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("")
    assert not B.running(host, "chat-app")
    import fcntl
    with open(lock, "r+") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert B.running(host, "chat-app")
        with pytest.raises(trial.TrialError, match="already running"):
            B.run_to_end(host, box, spawn, wait=0.01)
    assert not B.running(host, "chat-app")


# ------------------------------------------------------------------ the API

def test_boxes_through_the_api(cat, host, program):
    f = set_up(host, a_box())
    launcher = B.launcher_path(host.home / ".local/share", "chat-app")
    launcher.parent.mkdir(parents=True)
    launcher.write_text(B.launcher_text(a_box(), [str(program)]))
    spawned = []
    with TestClient(create_app("t0ken", cat, make_host=lambda: host,
                               spawn_app=lambda argv, **kw: spawned.append((argv, kw)))) as c:
        d = c.get("/api/tools/boxes", headers=H).json()["boxes"]
        assert len(d) == 1 and d[0]["name"] == "Chat App" and d[0]["launcher"] is True and d[0]["problem"] is None
        assert d[0]["folder"] == "~/Boxes/chat-app" and d[0]["runs"] == [] and d[0]["running"] is False
        assert c.post("/api/tools/boxes/start", headers=H, json={"box": "../x"}).status_code == 400
        assert c.post("/api/tools/boxes/start", headers=H, json={"box": "chat-app"}).json() == {"ok": True}
        argv, kw = spawned[0]
        assert argv == [str(program), "--box", "chat-app"] and kw["start_new_session"] is True
        (f / "runs.json").write_text(json.dumps({"salt": "00" * 16, "hosts": [], "runs": [{"when": 1, "seconds": 5}]}))
        assert len(c.get("/api/tools/boxes", headers=H).json()["boxes"][0]["runs"]) == 1
        assert c.post("/api/tools/boxes/clear", headers=H, json={"box": "chat-app"}).json() == {"ok": True}
        assert not (f / "runs.json").exists()
        assert "app.boxes" in c.get("/api/tools", headers=H).json()["features"]
