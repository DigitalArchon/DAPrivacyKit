"""A Box (app.boxes): an app kept in a sandbox with a home of its own. Its settings file, the guide that sets it
up and its revert, the sandbox it starts in, the runs it keeps in numbers, the menu entry and the API."""

from __future__ import annotations

import json
import os
import stat
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
    assert detect(cat, "app.boxes", make_scan(host)).status is Status.WARN
    g = build(cat, host, "app.boxes")
    step = g.steps[1]
    apps = dict(step.inputs[0].choices)
    assert apps == {"chat.desktop": "Chat App", "org.x.Meet.desktop": "Meet (Flatpak)"}, "no terminal apps, no trial"
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
    from daprivacyscanner.runner import Runner
    again = Runner(cat, host).plan_fix("app.boxes", {"source": "chat.desktop"})[1]
    assert again.steps[1].done and "daprivacyscanner-box-chat-app.desktop" not in dict(again.steps[1].inputs[0].choices)
    # the app has run and left data: reverting takes the menu entry and settings, never the data
    (f / "home/.config").mkdir()
    (f / "home/.config/chat.db").write_text("messages")
    revert(host, log, res)
    assert not (f / "box.json").exists() and not (host.home / ".local/share/applications").exists()
    assert (f / "home/.config/chat.db").read_text() == "messages" and not (f / "Exchange").exists()
    assert detect(cat, "app.boxes", make_scan(host)).status is Status.WARN


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


def test_runs_are_kept_in_numbers_and_hosts_as_hashes(host):
    box = a_box(network="observed")
    f = set_up(host, box)

    def a_run(hosts):
        return SimpleNamespace(started=1790000000, result={
            "seconds": 600, "failed": False, "summary": {"totals": {"written": 2, "created": 5, "deleted": 1}},
            "hosts": {"hosts": [{"host": h, "sent": 1000} for h in hosts]}})
    first = B.record_run(host, box, a_run(["chat.example.net", "cdn.example.net"]))
    assert first == {"when": 1790000000, "seconds": 600, "written": 7, "deleted": 1, "network": "observed", "hosts": 2,
                     "new_hosts": 2, "sent": 2000, "failed": False, "signal": None}
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
