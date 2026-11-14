"""The app's own folders are 0700, also when they are there already (the DA apps' one security standard,
2026-11-14), and its state files are written whole, through a temporary file of each write's own, on the disk
before they are renamed into place: ui.json, presentation.json, a Box's runs.json."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from daprivacyscanner import about, paths
from daprivacyscanner.tools import owner


def mode(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def test_the_app_s_folders_are_put_back_to_0700_at_every_start(tmp_path):
    env = {"XDG_RUNTIME_DIR": str(tmp_path / "run")}
    folders = paths.own_folders(tmp_path, env)
    assert len(folders) == 5 and all(f.name == "daprivacyscanner" for f in folders)
    for f in folders:
        f.mkdir(parents=True)
        f.chmod(0o775)                               # as an older version made it under Mint's umask
    other = tmp_path / "elsewhere"
    other.mkdir(mode=0o755)
    link_home = tmp_path / "linked"
    (link_home / ".config").mkdir(parents=True)
    (link_home / ".config" / "daprivacyscanner").symlink_to(other)
    paths.keep_own_folders_private(tmp_path, env)
    assert all(mode(f) == 0o700 for f in folders)
    paths.keep_own_folders_private(link_home, {})
    assert mode(other) == 0o755                      # a link is left as it is: never followed


def test_main_keeps_them_private(tmp_path, monkeypatch):
    from daprivacyscanner import app
    monkeypatch.setattr(app, "no_core_dumps", lambda: None)      # it would set this test process's limits for good
    state = Path(os.environ["XDG_STATE_HOME"]) / "daprivacyscanner"
    state.mkdir(parents=True)
    state.chmod(0o755)
    try:
        app.main(["--version"])
    except SystemExit:
        pass
    assert mode(state) == 0o700


def test_a_folder_made_on_the_way_is_the_app_s_own_and_0700(tmp_path):
    old = os.umask(0o022)
    try:
        host = type("H", (), {"environ": {"XDG_RUNTIME_DIR": str(tmp_path)}, "sys_path": lambda self, p: Path(p)})()
        d = owner._locks(host)
        assert d == tmp_path / "daprivacyscanner" / "owners" and mode(d) == 0o700
        assert mode(tmp_path / "daprivacyscanner") == 0o700         # it was 0755, made on the way to owners/
        f = paths.make_own_folder(tmp_path / "cache" / "daprivacyscanner")
        assert mode(f) == 0o700
    finally:
        os.umask(old)


def test_ui_json_is_written_whole_through_a_temporary_file_of_its_own(tmp_path, monkeypatch):
    seen = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (seen.append(fd), real(fd))[1])
    about.hide_welcome(tmp_path, True)
    assert not about.welcome_shown(tmp_path)
    folder = tmp_path / "daprivacyscanner"
    assert sorted(p.name for p in folder.iterdir()) == ["ui.json"] and mode(folder) == 0o700
    assert mode(folder / "ui.json") == 0o600 and len(seen) >= 2          # the file and its folder
    (folder / "ui.tmp").mkdir()                       # a fixed temporary name in the way stopped it
    about.hide_welcome(tmp_path, False)
    assert about.welcome_shown(tmp_path)


def _fsynced_paths(monkeypatch) -> list[str]:
    """The paths os.fsync is called on, from here on."""
    seen, real = [], os.fsync

    def spy(fd):
        try:
            seen.append(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            pass
        return real(fd)
    monkeypatch.setattr(os, "fsync", spy)
    return seen


def test_presentation_s_record_is_written_whole_whatever_lies_where_its_temporary_file_was(tmp_path, monkeypatch):
    from conftest import make_host

    from daprivacyscanner.tools import presentation as P
    host = make_host(tmp_path)
    f = P.state_file(host)
    f.parent.mkdir(parents=True)
    (f.parent / "presentation.tmp").mkdir()            # one fixed temporary name for every writer, in the way
    seen = _fsynced_paths(monkeypatch)
    P._save(host, {"records": [{"what": "x"}]})
    assert P._load(host) == {"records": [{"what": "x"}]} and mode(f) == 0o600
    assert str(f.parent) in seen and any(p.startswith(str(f.parent) + "/.presentation.json.") for p in seen)


def test_the_rebuild_s_note_has_its_folder_synced(tmp_path, monkeypatch):
    from test_rebuild_review import note_host

    from daprivacyscanner import fix
    from daprivacyscanner.tools import rebuild as R
    host = note_host(tmp_path)
    (host.home / "Documents").mkdir(parents=True)
    synced = []
    monkeypatch.setattr(fix, "fsync_dir", lambda folder: synced.append(Path(folder)))
    with R.Note(host, {"scope": "home", "root": str(host.home)}, "Documents", "fillers"):
        assert R.note_path(host).parent in synced
