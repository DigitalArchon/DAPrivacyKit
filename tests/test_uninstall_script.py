"""packaging/uninstall.sh: removes what is the app's own (scheduled scans, the Outbox's watcher, the right-click
entries it wrote, its data), never the fixes the user applied or files of theirs. Run against a scratch home, with a
systemctl of the test's own; the helper's part (root) is left out."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "uninstall.sh"
MARK = "# Written by DA Privacy Kit. Revert it in the app's History to remove it.\n"


def _home(tmp_path: Path, applied: int = 0) -> tuple[Path, dict, Path]:
    home = tmp_path / "home"
    files = {
        ".config/systemd/user/daprivacyscanner-scan.timer": "[Timer]\n",
        ".config/systemd/user/daprivacyscanner-scan.service": "[Service]\n",
        ".config/systemd/user/timers.target.wants/daprivacyscanner-scan.timer": "",
        ".config/systemd/user/daprivacyscanner-outbox.path": "[Path]\n",
        ".config/systemd/user/daprivacyscanner-outbox.service": "[Service]\n",
        ".config/systemd/user/syncthing.service": "[Service]\n",                                  # not the app's
        ".local/share/nemo/actions/daprivacyscanner-verify.nemo_action": "[Nemo Action]\n" + MARK,
        ".local/share/nemo/actions/daprivacyscanner-mine.nemo_action": "[Nemo Action]\nName=one of the user's\n",
        ".local/share/kio/servicemenus/daprivacyscanner.desktop": "[Desktop Entry]\n" + MARK,
        ".local/share/nautilus/scripts/Verify download (DA Privacy Kit)": "#!/bin/sh\n" + MARK,
        ".local/share/applications/daprivacyscanner-box-foo.desktop": "[Desktop Entry]\n# " + MARK + "\n",
        ".local/share/applications/foo.desktop": "[Desktop Entry]\nName=Foo\n",                 # the user's own
        "Boxes/foo/home/.config/foo/data": "the boxed app's data",                                # theirs too
        ".local/state/daprivacyscanner/undo.json": json.dumps({"entries": [{"state": "applied"}] * applied
                                                              + [{"state": "reverted"}, {"state": "failed"}]}),
        ".local/state/daprivacyscanner/backups/x/file": "old",
        ".config/daprivacyscanner/ui.json": "{}",
        ".config/user-tmpfiles.d/60-daprivacyscanner-screenshots.conf": "e %h/Pictures/Screenshots - - - 30d\n",   # a fix
        "Outbox/Cleaned/photo.jpg": "x",                                                           # the user's own
    }
    for rel, text in files.items():
        f = home / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "systemctl.calls"
    (bin_dir / "systemctl").write_text(f"#!/bin/sh\necho \"$@\" >> {calls}\n")
    (bin_dir / "systemctl").chmod(0o755)
    env = {"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin", "XDG_RUNTIME_DIR": str(tmp_path / "run")}
    return home, env, calls


def _run(env, *args, stdin=""):
    return subprocess.run(["bash", str(SCRIPT), "--no-root", *args], env=env, input=stdin, capture_output=True, text=True)


def test_dry_run_removes_nothing(tmp_path):
    home, env, calls = _home(tmp_path, applied=2)
    before = sorted(p for p in home.rglob("*"))
    r = _run(env, "--dry-run")
    assert r.returncode == 0 and "2 change(s) you applied with the app are still in place" in r.stdout
    assert "daprivacyscanner-scan.timer" in r.stdout and "this was a dry run" in r.stdout
    assert sorted(p for p in home.rglob("*")) == before and not calls.exists()


def test_removes_the_apps_own_and_leaves_fixes_and_the_users_files(tmp_path):
    home, env, calls = _home(tmp_path)
    r = _run(env, "--yes")
    assert r.returncode == 0, r.stderr
    gone = [".config/systemd/user/daprivacyscanner-scan.timer", ".config/systemd/user/daprivacyscanner-scan.service",
            ".config/systemd/user/timers.target.wants/daprivacyscanner-scan.timer",
            ".config/systemd/user/daprivacyscanner-outbox.path", ".config/systemd/user/daprivacyscanner-outbox.service",
            ".local/share/nemo/actions/daprivacyscanner-verify.nemo_action",
            ".local/share/kio/servicemenus/daprivacyscanner.desktop",
            ".local/share/nautilus/scripts/Verify download (DA Privacy Kit)",
            ".local/share/applications/daprivacyscanner-box-foo.desktop",
            ".local/state/daprivacyscanner", ".config/daprivacyscanner"]
    kept = [".config/systemd/user/syncthing.service", "Outbox/Cleaned/photo.jpg",
            ".local/share/applications/foo.desktop", "Boxes/foo/home/.config/foo/data",   # a Box's data is the user's
            ".local/share/nemo/actions/daprivacyscanner-mine.nemo_action",          # no mark: not written by the app
            ".config/user-tmpfiles.d/60-daprivacyscanner-screenshots.conf"]         # a fix: it stays, and is named
    assert not [g for g in gone if (home / g).exists()] and all((home / k).exists() for k in kept)
    assert "60-daprivacyscanner-screenshots.conf" in r.stdout.split("Among what stays")[1]
    # folders it emptied go; one that still holds something of the user's stays
    assert not (home / ".local/share/kio").exists() and not (home / ".local/share/nautilus/scripts").exists()
    assert (home / ".local/share/nemo/actions").is_dir() and (home / ".config/systemd/user").is_dir()
    done = calls.read_text()
    assert "--user disable --now daprivacyscanner-scan.timer" in done and "daprivacyscanner-outbox.path" in done
    assert "delete the AppImage itself" in r.stdout and "left (--no-root)" in r.stdout


def test_asks_first_and_stops_when_fixes_are_still_applied_and_the_answer_is_no(tmp_path):
    home, env, _ = _home(tmp_path, applied=1)
    r = _run(env, stdin="n\n")
    assert r.returncode == 1 and "Nothing was removed." in r.stdout
    assert (home / ".local/state/daprivacyscanner/undo.json").exists()
    # yes to the first question only: each part is asked on its own
    r = _run(env, stdin="y\nn\nn\nn\nn\ny\n")
    assert r.returncode == 0 and (home / ".config/systemd/user/daprivacyscanner-scan.timer").exists()
    assert not (home / ".local/state/daprivacyscanner").exists()


def test_keep_data_and_what_must_be_ended_in_the_app_first(tmp_path):
    home, env, _ = _home(tmp_path, applied=3)
    r = _run(env, "--yes", "--keep-data")
    assert r.returncode == 0 and "kept (--keep-data)" in r.stdout and "still in place" not in r.stdout
    assert (home / ".local/state/daprivacyscanner/undo.json").exists() and (home / ".config/daprivacyscanner").exists()
    assert not (home / ".config/systemd/user/daprivacyscanner-scan.timer").exists()
    (home / ".local/state/daprivacyscanner/presentation.json").write_text("{}")
    r = _run(env, "--yes")
    assert r.returncode == 1 and "Presentation mode is on" in r.stdout
    assert (home / ".local/state/daprivacyscanner/undo.json").exists()


def test_refuses_options_it_does_not_know(tmp_path):
    _, env, _ = _home(tmp_path)
    r = _run(env, "--everything")
    assert r.returncode == 2 and "packaging/uninstall.sh --dry-run" in r.stdout


def test_the_script_names_what_the_app_installs():
    """It can't import the app (it runs without it), so its names are kept equal to the app's here."""
    from daprivacyscanner import app, helper
    from daprivacyscanner.tools import integration

    text = SCRIPT.read_text()
    for name in (f"{app.TIMER_UNIT}.timer", f"{app.TIMER_UNIT}.service", f"{integration.OUTBOX_UNIT}.path",
                 f"{integration.OUTBOX_UNIT}.service", os.path.dirname(helper.INSTALLED), helper.POLICY_PATH,
                 os.path.dirname(helper.CHANGES_DIR)):
        assert name in text, name
    from daprivacyscanner.tools import box
    launcher = box.launcher_path(Path("/d"), "foo").name
    assert launcher == "daprivacyscanner-box-foo.desktop" and "applications/daprivacyscanner-box-*.desktop" in text
    assert box.MARK.startswith(text.split('MARK="', 1)[1].split('"', 1)[0])
    mark = text.split('MARK="', 1)[1].split('"', 1)[0]
    assert integration.MARK.startswith(mark)
    assert all(mark in e.content for e in integration.file_manager_entries(Path("/x"), ["/usr/bin/daprivacyscanner"]))
