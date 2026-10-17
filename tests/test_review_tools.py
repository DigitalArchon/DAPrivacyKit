"""The review of 2026-10-17, tools and the helper's service and mount handling: what the app's own units and menu
entries leave in the journal, the RAM disk's close, Remove metadata's and Verify's words, Deleted file names' notes,
Try an app and Boxes, Presentation mode's words, in-memory folders put back while busy, services turned off together
(and a failure part way recorded), what a revert says it put back, and the known_hosts undo hint."""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner import helper
from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.server import create_app

from conftest import make_host, skip_if_root
from fakes import FakeSystem

H = {"X-Token": "t0ken"}
ME = (os.geteuid(), os.getegid())


def helper_call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        e = helper.Refused(reply["error"])
        e.reply = reply
        raise e
    return reply["result"]


@pytest.fixture
def system_root(tmp_path, monkeypatch):
    """The helper against a fixture tree, with a fake systemctl; alice is the user pkexec names."""
    r = tmp_path / "root"
    (r / "home/alice/.cache").mkdir(parents=True)
    (r / "etc/systemd/system").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    system = FakeSystem()
    monkeypatch.setattr(helper, "RUN", system)
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    return r, system


# ------------------------------------------------------------------ 1. nothing names a file in the journal

def outbox_run(cleaned=(), not_cleaned=()):
    from daprivacyscanner.tools import metadata as M
    run = M.OutboxRun()
    run.cleaned, run.not_cleaned = list(cleaned), list(not_cleaned)
    return run


def test_the_outbox_unit_writes_counts_to_the_journal_never_the_files_names(monkeypatch, capsys):
    """Its unit's output goes to the journal, kept on the disk on Mint: the names of what the user shares stayed
    there ("cleaned: passport-scan.jpg"). Counts only, as in its notification; names only in a terminal."""
    from daprivacyscanner import app
    from daprivacyscanner.tools import metadata as M
    run = outbox_run(["passport-scan.jpg"], [("contract draft.docx", "mat2 can't clean this kind of file (x).")])
    monkeypatch.setattr(M, "run_outbox_settled", lambda host: run)
    monkeypatch.setattr(M, "notify_outbox", lambda host, r: None)
    assert app.outbox_cli() == 0
    out = capsys.readouterr()
    assert out.out == "Outbox: 1 cleaned, 1 not cleaned.\n" and "passport" not in out.out + out.err
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)       # someone ran it by hand
    assert app.outbox_cli() == 0
    assert "cleaned: passport-scan.jpg" in capsys.readouterr().out


def test_an_outbox_error_is_said_by_its_kind_only(monkeypatch, capsys):
    from daprivacyscanner import app
    from daprivacyscanner.tools import metadata as M

    def broken(host):
        raise PermissionError(13, "Permission denied", "/home/alice/Outbox/passport-scan.jpg")
    monkeypatch.setattr(M, "run_outbox_settled", broken)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    assert app.outbox_cli() == 1
    err = capsys.readouterr().err
    assert "PermissionError" in err and "passport" not in err


def test_errors_nothing_caught_are_said_by_their_kind_off_a_terminal(monkeypatch, capsys):
    """A unit, a timer, a menu entry or a right-click entry: stderr is the journal or ~/.xsession-errors, and a
    traceback's message can name a file. Only the kind goes there."""
    import threading

    from daprivacyscanner import app
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    app.quiet_tracebacks()
    try:
        raise FileNotFoundError(2, "No such file", "/home/alice/Documents/secret plan.odt")
    except FileNotFoundError as e:
        sys.excepthook(type(e), e, e.__traceback__)
    err = capsys.readouterr().err
    assert "FileNotFoundError" in err and "secret" not in err and "Traceback" not in err


def test_the_scheduled_scan_prints_nothing(cat, tmp_path, monkeypatch, capsys):
    """`--scan --notify --quiet` is what the timer runs: no report, no titles, in its journal."""
    from daprivacyscanner import app
    from daprivacyscanner.host import Host as RealHost
    host = make_host(tmp_path)
    monkeypatch.setattr(RealHost, "local", staticmethod(lambda: host))
    monkeypatch.setattr("daprivacyscanner.runner.Runner.scan",
                        lambda self: SimpleNamespace(to_dict=lambda: {"results": {}, "context": {}}))
    app.scan_cli(cat, as_json=False, notify=True, admin=False, quiet=True, redact=False)
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


# ------------------------------------------------------------------ 2. the RAM disk

def ramdisk_host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    home.mkdir(parents=True)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", root / "proc/mounts")
    (root / "proc/meminfo").write_text("MemTotal: 8000000 kB\n")
    return Host(home=home, environ={"HOME": str(home)}, runner=FakeRunner(), root=root, uid=os.getuid())


def test_closing_a_ram_disk_that_isnt_open_is_refused_and_touches_nothing(cat, tmp_path):
    """Before, the helper took the user's own empty ~/RAMDisk for its own and removed it."""
    host = ramdisk_host(tmp_path)
    mine = host.home / "RAMDisk"
    mine.mkdir(mode=0o755)

    def no_helper():
        raise AssertionError("nothing to close: the helper isn't asked")
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=no_helper))
    r = c.post("/api/tools/ramdisk/close", headers=H, json={})
    assert r.status_code == 409 and "isn't open" in r.json()["error"] and mine.is_dir()


def test_the_helper_never_removes_a_folder_nothing_records_it_made(system_root):
    r, _ = system_root
    (r / "proc/self").mkdir(parents=True)
    (r / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n")
    os.symlink("self/mounts", r / "proc/mounts")
    mine = r / "home/alice/RAMDisk"
    mine.mkdir(mode=0o755)
    mine.chmod(0o755)
    res = helper_call("ramdisk_close")
    assert res == {"closed": True, "was_open": False} and mine.is_dir() and stat.S_IMODE(mine.stat().st_mode) == 0o755


def test_a_leftover_is_only_a_folder_an_open_left(tmp_path):
    """"An empty, read-only ~/RAMDisk folder is left from before a restart" was said of the user's own 0755 folder."""
    from daprivacyscanner.tools import ramdisk as R
    host = ramdisk_host(tmp_path)
    folder = host.home / "RAMDisk"
    folder.mkdir()
    folder.chmod(0o755)
    assert R.status(host).leftover is False                              # an empty folder of the user's own
    folder.chmod(0o500)                                                  # as an open leaves it
    assert R.status(host).leftover is True
    folder.chmod(0o755)
    try:
        os.setxattr(folder, helper.RAMDISK_XATTR, b'{"created": true, "folder_mode": null}')
    except OSError:
        pytest.skip("no user extended attributes on this filesystem")
    assert R.status(host).leftover is True                               # the helper's record of an open


# ------------------------------------------------------------------ 3. Remove metadata

@skip_if_root
def test_a_single_file_in_a_folder_the_user_cant_write_to_says_so(tmp_path):
    from daprivacyscanner.tools import metadata as M
    host = make_host(tmp_path, home_files={"Shared/photo.jpg": "img"})
    calls = []
    host.runner.handlers["mat2"] = lambda argv: calls.append(argv) or CommandResult(argv, 0, "")
    folder = host.home / "Shared"
    folder.chmod(0o555)
    try:
        r = M.clean(host, folder / "photo.jpg")
        assert not r.ok and r.message == "You can't write to ~/Shared, where the cleaned copy would go."
        run = M.clean_many(host, M.collect([folder / "photo.jpg"]).files, check_after=False)
        assert run.results[0].message == "You can't write to ~/Shared, where the cleaned copy would go."
        assert calls == []                                               # mat2 isn't run for nothing
    finally:
        folder.chmod(0o755)


@pytest.mark.parametrize("said, sentence", [
    ("something went wrong when cleaning /h/a b/broken.jpg: ",
     "mat2 couldn't read it: it may be damaged, or not the kind of file its name says."),
    ("something went wrong when cleaning /h/a b/broken.jpg: Couldn't recognize the image file format for file "
     "'/h/a b/broken.jpg'",
     "mat2 couldn't read it: it may be damaged, or not the kind of file its name says (Couldn't recognize the image "
     "file format for file 'broken.jpg')."),
    ("something went wrong when processing /h/a b/broken.jpg: ",
     "mat2 couldn't read it: it may be damaged, or not the kind of file its name says."),
    ("/h/a b/broken.jpg's format (application/x-thing) is not supported", "mat2 can't clean this kind of file "
                                                                           "(application/x-thing)."),
    ("/h/a b/broken.jpg can't be cleaned: no space left", "mat2 couldn't clean it (no space left)."),
    ("/h/a b/broken.jpg is not r nor e nor a nor d.", "It can't be read."),
    ("odd thing about /h/a b/broken.jpg:", "Odd thing about broken.jpg."),
])
def test_mat2s_half_sentences_become_sentences_without_the_path(said, sentence):
    from daprivacyscanner.tools import metadata as M
    assert M._sentence(said, "/h/a b/broken.jpg") == sentence
    assert M._problems(f"[-] {said}\n", "/h/a b/broken.jpg") == sentence


# ------------------------------------------------------------------ 4. Verify a download

def debian_host(tmp_path, **kw):
    return make_host(tmp_path, files={"/etc/os-release": 'ID=linuxmint\nID_LIKE="ubuntu debian"\n'}, **kw)


def test_a_missing_minisign_gets_its_install_command(tmp_path):
    from daprivacyscanner.tools import verify as V
    host = debian_host(tmp_path)
    sig, data = tmp_path / "f.minisig", tmp_path / "f"
    sig.write_text("untrusted comment: signature\nRWQBAgMEBQYHCAkKCwwNDg8Q\n")
    data.write_text("x")
    keys = SimpleNamespace(minisign_keys=lambda: [tmp_path / "key.pub"])
    s = V.check_minisign(host, keys, sig, data)
    assert s.status == "no_tool" and s.install == "sudo apt install minisign" and s.to_dict()["install"] == s.install
    assert V._unchecked_step(s, data) == ("f.minisig: Checking it needs minisign, which isn't installed. Install it "
                                          "with: sudo apt install minisign")
    assert V.check_ssh(host, sig, data).install == "sudo apt install openssh-client"


def test_the_terminal_report_says_a_signatures_state_in_words(tmp_path):
    from daprivacyscanner.tools import verify as V
    v = V.Verdict(tmp_path / "f.iso", 1, "unchecked", "Nothing to check it against", "x", {}, [
        V.Signature(tmp_path / "f.iso.sig", tmp_path / "f.iso", "openpgp", "no_tool"),
        V.Signature(tmp_path / "f.iso.asc", tmp_path / "f.iso", "openpgp", "no_key")], [], None)
    text = v.text_report()
    assert "no_tool" not in text and "no_key" not in text
    assert "can't be checked: a program it needs isn't installed" in text and "the key that made it isn't available" in text


def test_a_signed_list_has_its_comma_and_a_checksum_given_is_given(tmp_path):
    from daprivacyscanner.tools import keys as K
    from daprivacyscanner.tools import verify as V
    projects = K.load()
    mint = next(p for p in projects if p.id == "linuxmint")
    entry = V.Entry("sha256", "ab" * 32, "linuxmint.iso")
    s = V.Signature(tmp_path / "sha256sum.txt.gpg", tmp_path / "sha256sum.txt", "openpgp", "good", mint.keys[0][0],
                    project=mint, key_name="Linux Mint ISO Signing Key")
    sl = V.SumsList(tmp_path / "sha256sum.txt", [entry], signature=s, matched=[(entry, True)])
    v = V.decide(tmp_path / "linuxmint.iso", 1, {"sha256": "ab" * 32}, [], [sl], None, projects)
    assert v.text.startswith("It is signed, through the checksum list sha256sum.txt, by Linux Mint's release key")
    f = tmp_path / "notes.txt"
    f.write_text("hello\n")
    host = make_host(tmp_path)
    digest = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    assert "the SHA-256 checksum given" in V.verify(host, f, expected=digest, given=True).text
    assert "the SHA-256 checksum you pasted" in V.verify(host, f, expected=digest).text
    assert "doesn't match the one given" in V.verify(host, f, expected="00" * 32, given=True).text
    assert any("given with --checksum" in n for n in V.verify(host, f, expected="zz", given=True).notes)


# ------------------------------------------------------------------ 5. Deleted file names

from test_trimtest import home_folders, host_for, make_storage, root  # noqa: E402,F401 - fixtures


def test_the_large_folder_note_is_there_without_a_watcher_and_fillers_move_nothing(root, monkeypatch):
    from daprivacyscanner.tools import rebuild as R
    make_storage(root)
    home_folders(root)
    monkeypatch.setattr(R, "_flags", lambda fd: R.FS_INDEX_FL)            # an indexed (large) folder
    monkeypatch.setattr(R, "watchers", lambda host, path: [])             # and nothing watching it
    p = R.plan(host_for(root), "/", [""])
    assert p["folders"][0]["method"] == "fillers"                         # the home itself can't be swapped
    assert any(x.startswith("In a large folder (an indexed one)") for x in p["side_effects"])
    kept = next(x for x in p["side_effects"] if x.startswith("Nothing is kept"))
    assert "moved" not in kept and "fillers are only added and deleted again" in kept


# ------------------------------------------------------------------ 6. Try an app and Boxes

@pytest.fixture
def trial_host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    for d in ("home/alice/Downloads", "run/user/1000", "tmp/.X11-unix", "usr/bin", "etc"):
        (root / d).mkdir(parents=True)
    (root / "tmp/.X11-unix/X0").write_text("")
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    return Host(home=home, environ={"HOME": str(home), "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"},
                runner=FakeRunner(handlers={"bwrap": ok, "pasta": ok, "ip": ok, "mount": ok}), root=root, uid=1000)


def test_discarding_the_last_trial_leaves_no_empty_folder(trial_host):
    from daprivacyscanner.tools import trial
    src = trial_host.home / "Downloads/tool.sh"
    src.write_text("#!/bin/sh\necho hi\n")
    base = trial_host.root / "run/user/1000" / trial.FOLDER
    t = trial.prepare_file(trial_host, src, "memory")
    assert base.is_dir()
    trial.discard(trial_host, t)
    assert not base.exists()
    base.mkdir()                                                          # an empty one an earlier version left
    trial.clear_leftovers(trial_host)
    assert not base.exists()


@pytest.mark.parametrize("code, failed, ended", [
    (143, False, "was asked to end (SIGTERM, as at logout or shutdown)"),    # through bubblewrap and STAY
    (-signal.SIGTERM, False, "was asked to end (SIGTERM, as at logout or shutdown)"),
    (-signal.SIGKILL, False, "was killed (SIGKILL: by the system when memory ran short, or by a kill command)"),
    (139, True, "crashed (SIGSEGV)"),
    (2, True, "ended with an error (exit status 2)"),
    (0, False, "ended by itself"),
])
def test_a_program_ended_by_a_signal_didnt_fail(trial_host, tmp_path, code, failed, ended):
    from daprivacyscanner.tools import trial
    folder = tmp_path / "t"
    for sub in ("home", "app", "private"):
        (folder / sub).mkdir(parents=True)
    t = trial.Trial("0a1b2c3d4e5f", folder, "memory", "program", "tool", "a program", argv=["/app/tool"])
    t.proc, t.started, t.state = SimpleNamespace(poll=lambda: code), time.time(), "running"
    trial._finish(trial_host, t)
    assert t.result["failed"] is failed and t.result["ended"] == ended


def box_host(tmp_path):
    desktop = "[Desktop Entry]\nType=Application\nName=Chat App\nExec=chat --flag %U\n"
    h = make_host(tmp_path, files={"/usr/share/applications/chat.desktop": desktop, "/usr/bin/chat": "",
                                   "/tmp/.X11-unix/X0": "", "/run/user/1000/x": ""},
                  env={"XDG_DATA_DIRS": "/usr/share", "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"})
    for name in ("bwrap", "pasta", "ip", "flatpak"):
        h.runner.handlers[name] = lambda argv: CommandResult(argv, 0, "")
    return h


def test_a_boxs_revert_takes_its_runs_and_the_exchange_mount_point(cat, tmp_path, monkeypatch):
    """Before, runs.json (the app's own record) and the empty home/Exchange bubblewrap mounts on kept the Box's folder
    for ever, Exchange listed as "added since"."""
    from daprivacyscanner.tools import box as B
    from daprivacyscanner.tools import integration as I
    from test_guides import apply, build, options, revert
    exe = tmp_path / "bin/daprivacyscanner"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(I, "program", lambda environ: [str(exe)])
    host = box_host(tmp_path)
    plan = options(build(cat, host, "app.boxes"))["Set up a Box for Chat App"]
    log, res = apply(host, plan)
    f = host.home / "Boxes/chat-app"
    box = B.read(host, "chat-app")
    B.record_run(host, box, SimpleNamespace(started=1, result={"seconds": 5, "summary": {"totals": {}}}))
    (f / "home/Exchange").mkdir()                                         # the mount point a run left before
    assert (f / "runs.json").exists()
    results = revert(host, log, res)
    assert not f.exists() and not (host.home / "Boxes").exists(), [r.message for r in results]
    assert not any("Boxes" in r.message and "added since" in r.message for r in results), [r.message for r in results]


def test_a_box_run_removes_the_mount_point_it_made_and_keeps_what_is_in_one(tmp_path):
    from daprivacyscanner.tools import box as B
    host = box_host(tmp_path)
    box = B.Box("chat-app", "Chat App", "installed", ["/usr/bin/chat"])
    f = B.folder(host, "chat-app")
    for sub in ("home", "Exchange"):
        (f / sub).mkdir(parents=True)
    (f / "box.json").write_text(B.config_text(box))

    def spawn(argv, **kw):
        (f / "home/Exchange").mkdir(exist_ok=True)                        # as bubblewrap makes it to mount on
        return SimpleNamespace(pid=1 << 22, stdout=None)
    B.run_to_end(host, box, spawn, wait=0.01)
    assert not (f / "home/Exchange").exists()
    (f / "home/Exchange").mkdir()
    (f / "home/Exchange/mine.txt").write_text("the app's own")             # a Flatpak's, say: never removed
    B.run_to_end(host, box, spawn, wait=0.01)
    assert (f / "home/Exchange/mine.txt").read_text() == "the app's own"
    assert B.runs(host, "chat-app")["runs"][-1]["signal"] is None


def overlay_host(trial_host, native: bool, apparmor: bool = False):
    from daprivacyscanner.tools import trial

    def bwrap(argv):
        if argv[1:] == ("--help",) or list(argv[1:]) == ["--help"]:
            return CommandResult(argv, 0, "    --ro-overlay DEST   Mount overlayfs read-only on DEST\n" if native else
                                 "    --bind SRC DEST\n")
        if "/proc/self/attr/current" in argv:
            return CommandResult(argv, 0, "bwrap//&unpriv_bwrap (enforce)\n" if apparmor else "unconfined\n")
        if "--ro-overlay" in argv:
            return CommandResult(argv, 0, "")
        return CommandResult(argv, 32, "", "mount: /usr: permission denied.\n" if apparmor else "")
    trial_host.runner.handlers["bwrap"] = bwrap
    trial._NATIVE.clear()
    return trial_host


def test_a_packages_usr_is_laid_over_by_bubblewrap_itself_where_it_can(trial_host, tmp_path, monkeypatch):
    """Ubuntu 26.04's AppArmor profile for bubblewrap takes every capability from what it starts, so a first
    bubblewrap's mount failed; bubblewrap 0.10 and later mount the overlay themselves, which works there (tested)."""
    from daprivacyscanner.tools import sandbox, trial
    from test_trial import a_trial, pairs, parts
    host = overlay_host(trial_host, native=True)
    monkeypatch.setattr(sandbox, "program", lambda h, name: name)
    t = a_trial(tmp_path, kind="deb", argv=["/usr/bin/foo"])
    (t.app / "usr/bin").mkdir(parents=True)
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    assert a[0] == "bwrap" and "--unshare-user" not in a[:3] and trial.OVERLAY not in a
    i = a.index("--ro-overlay")
    assert a[i - 4:i + 2] == ["--overlay-src", "/usr", "--overlay-src", str(t.app / "usr"), "--ro-overlay", "/usr"]
    assert a.index(("--ro-bind")) < i                                     # over the computer's /usr, bound first
    assert trial.probe_overlay(host) is None


def test_apparmor_is_named_when_it_is_why_a_package_cant_be_tried(trial_host, monkeypatch):
    from daprivacyscanner.tools import sandbox, trial
    host = overlay_host(trial_host, native=False, apparmor=True)
    monkeypatch.setattr(sandbox, "program", lambda h, name: name)
    (host.root / "sys/kernel/security/apparmor").mkdir(parents=True)
    why = trial.probe_overlay(host)
    assert why == trial.APPARMOR_BWRAP and "AppArmor" in why and "bwrap-userns-restrict" in why and "0.10" in why
    host = overlay_host(trial_host, native=False, apparmor=False)
    assert trial.probe_overlay(host).startswith("an overlay can't be mounted in a sandbox here")


# ------------------------------------------------------------------ 7. Presentation mode

def test_presentations_kept_message_is_plain_words():
    from daprivacyscanner.tools import presentation as P
    assert P.kept_text("Notification banners off") == ("Notification banners were changed meanwhile, so they are left "
                                                       "as they are now.")
    said = P.kept_text("Clipboard Indicator turned off (its clipboard history menu disappears)")
    assert "Clipboard Indicator may still be off" in said and "disabled-extensions" not in said
    assert "display-notifications" not in P.kept_text("Notification banners off (Do Not Disturb)")
