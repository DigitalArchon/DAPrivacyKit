"""The terminal side of app.py: how a scheduled scan starts this program."""

import sys

from daprivacyscanner.app import scan_command, systemd_exec


def executable(path, text="#!/bin/sh\n"):
    path.write_text(text)
    path.chmod(0o755)
    return str(path)


def test_an_appimage_is_started_by_its_file_not_its_mount(tmp_path):
    image = executable(tmp_path / "DA Privacy Kit.AppImage")
    assert scan_command({"APPIMAGE": image}, "/tmp/.mount_abc/usr/bin/daprivacyscanner") == [image]


def test_the_command_the_user_ran(tmp_path):
    cmd = executable(tmp_path / "daprivacyscanner")
    assert scan_command({}, cmd) == [cmd]


def test_python_dash_m_from_a_source_tree(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    main = tmp_path / "__main__.py"
    main.write_text("")
    assert scan_command({}, str(main)) == [sys.executable, "-m", "daprivacyscanner"]


def test_exec_lines_are_quoted_for_systemd():
    assert systemd_exec(["/opt/DA Privacy Kit.AppImage", "--scan"]) == '"/opt/DA Privacy Kit.AppImage" --scan'
    assert systemd_exec(["/home/a/50%/x$y", "--quiet"]) == '"/home/a/50%%/x$$y" --quiet'
    assert systemd_exec(["/usr/bin/daprivacyscanner", "--scan"]) == "/usr/bin/daprivacyscanner --scan"


def test_the_window_takes_the_name_of_the_installed_desktop_entry(tmp_path, monkeypatch):
    """Under Wayland the compositor finds the window's icon only through a .desktop file named like
    the window's app id; AppImage integrators rename ours."""
    from daprivacyscanner.app import desktop_id
    img = tmp_path / "Apps" / "DA Privacy Kit.AppImage"
    img.parent.mkdir()
    img.write_bytes(b"")
    (tmp_path / "link.AppImage").symlink_to(img)
    home, sys_dir = tmp_path / "home", tmp_path / "sys"
    (home / "applications" / "kde").mkdir(parents=True)
    (sys_dir / "applications").mkdir(parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(home))
    monkeypatch.setenv("XDG_DATA_DIRS", str(sys_dir))
    monkeypatch.delenv("APPIMAGE", raising=False)
    assert desktop_id() == "daprivacyscanner"                  # not an AppImage
    monkeypatch.setenv("APPIMAGE", str(img))
    (home / "applications" / "other.desktop").write_text("[Desktop Entry]\nExec=/usr/bin/other %U\n")
    assert desktop_id() == "daprivacyscanner"                  # AppImage, but not integrated
    # AppImageLauncher style: its own file name, the AppImage path quoted, reached through a link
    (home / "applications" / "appimagekit_5c1e-DA_Privacy_Kit.desktop").write_text(
        f'[Desktop Entry]\nName=DA Privacy Kit\nExec="{tmp_path / "link.AppImage"}" %U\n')
    assert desktop_id() == "appimagekit_5c1e-DA_Privacy_Kit"
    (home / "applications" / "appimagekit_5c1e-DA_Privacy_Kit.desktop").unlink()
    (home / "applications" / "kde" / "daprivacyscanner.desktop").write_text(f"[Desktop Entry]\nTryExec={img}\nExec=x\n")
    assert desktop_id() == "kde-daprivacyscanner"              # a subdirectory joins the id with "-"


def test_the_window_icon_is_a_file_gtk_can_load(monkeypatch):
    from daprivacyscanner.app import window_icon
    monkeypatch.delenv("APPDIR", raising=False)
    icon = window_icon()
    assert icon is None or icon.endswith("web/icon.svg")


def test_scheduling_says_when_the_timer_couldnt_be_turned_on(tmp_path, monkeypatch, capsys):
    import subprocess
    from daprivacyscanner import app
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    codes = {"enable": 1}
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, codes.get(argv[2], 0)))
    assert app.schedule("daily") == 1
    out = capsys.readouterr()
    assert "couldn't be turned on" in out.err and "not scheduled" in out.err and "Scans run" not in out.out
    codes.clear()
    assert app.schedule("weekly") == 0
    out = capsys.readouterr().out
    assert "Scans run weekly" in out and "a fix that was undone" in out and "starts at login" in out


def test_scheduling_off_removes_the_folders_it_made_and_keeps_others(tmp_path, monkeypatch, capsys):
    import subprocess
    from daprivacyscanner import app
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    wants = tmp_path / "systemd/user/timers.target.wants"

    def run(argv, **kw):
        if argv[2] == "enable":
            wants.mkdir(parents=True, exist_ok=True)
            if not (wants / argv[-1]).is_symlink():                               # enabled already: left as it is
                (wants / argv[-1]).symlink_to("/x")
        if argv[2] == "disable":
            (wants / argv[-1]).unlink(missing_ok=True)
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(subprocess, "run", run)
    assert app.schedule("daily") == 0 and app.schedule("weekly") == 0           # scheduled again: still known
    assert app.schedule("off") == 0
    assert not (tmp_path / "systemd").exists() and tmp_path.is_dir()
    app.schedule("daily")
    (tmp_path / "systemd/user/mine.service").write_text("[Service]\n")             # the user's own, since
    capsys.readouterr()
    app.schedule("off")
    assert (tmp_path / "systemd/user/mine.service").exists() and not wants.exists()
    assert "was left, with what is in it" in capsys.readouterr().out


def test_dry_run_builds_an_online_tests_guide_from_the_saved_report(tmp_path, capsys):
    """--dry-run on an online finding: its guide comes from the saved last report (the test isn't run);
    before it has run, the output says so."""
    from daprivacyscanner import catalogue
    from daprivacyscanner.app import dry_run
    from daprivacyscanner.history import LastReport
    from daprivacyscanner.paths import PathResolver
    from conftest import make_host
    cat = catalogue.load()
    host = make_host(tmp_path, files={"/etc/resolv.conf": "nameserver 127.0.0.53\n"})
    assert dry_run(cat, "net.dnssec_validation", host) == 0
    assert "hasn't run yet" in capsys.readouterr().out
    LastReport(PathResolver(host.home, host.environ)).save({"results": {"net.dnssec_validation": {
        "id": "net.dnssec_validation", "status": "fail", "effective_severity": 2, "summary": "not validated",
        "evidence": [], "findings": {}, "notes": [], "kind": "finding"}}, "context": {"values": {}}, "modifiers": {}})
    assert dry_run(cat, "net.dnssec_validation", host) == 0
    out = capsys.readouterr().out
    assert out.startswith("Guide for net.dnssec_validation") and "DNSSEC=allow-downgrade" in out


def test_without_its_window_the_app_says_why_and_never_opens_the_browser_unasked(monkeypatch, capsys):
    """Without WebKitGTK it used to open in the default browser, saying so only on stderr: there, extensions allowed
    on all sites read the page. It now stops, says why, and names --browser with what that exposes."""
    import pytest

    from daprivacyscanner import app as app_mod
    monkeypatch.setattr(app_mod, "window_problem", lambda: "The app window needs WebKitGTK 4.1, which isn't installed")
    monkeypatch.setattr(app_mod, "no_core_dumps", lambda: None)
    monkeypatch.setattr(app_mod.os, "geteuid", lambda: 1000)
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))
    monkeypatch.setattr(app_mod, "create_app", lambda *a, **k: (_ for _ in ()).throw(AssertionError("server started")))
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    with pytest.raises(SystemExit) as e:
        app_mod.main([])
    err = capsys.readouterr().err
    assert e.value.code == 2 and not opened
    assert "WebKitGTK" in err and "daprivacyscanner --browser" in err and "extension" in err


def test_no_window_message_uses_the_desktops_dialog_and_falls_back(monkeypatch, capsys):
    """Started from the menu without WebKitGTK: a dialog says what to install. KDE's own first on KDE; and when one
    can't run (a zenity that couldn't load its libraries, exit status 127, seen on CachyOS), the other is tried."""
    import subprocess
    import sys

    from daprivacyscanner import app

    ran = []

    def fake_run(argv, **kw):
        ran.append(argv[0])
        return subprocess.CompletedProcess(argv, status[argv[0]])
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "KDE")
    status = {"kdialog": 0, "zenity": 0}
    assert app.refuse_without_window("The app window needs WebKitGTK 4.1") == 2 and ran == ["kdialog"]
    ran.clear()
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "X-Cinnamon")
    assert app.refuse_without_window("x") == 2 and ran == ["zenity"]
    ran.clear()
    status["zenity"] = 127                                   # it couldn't even start: the other one says it
    assert app.refuse_without_window("x") == 2 and ran == ["zenity", "kdialog"]
    ran.clear()
    status["zenity"] = 1                                     # closed by its window's button: it was read
    assert app.refuse_without_window("x") == 2 and ran == ["zenity"]
    # shown in a dialog, it doesn't also go to stderr, which is then the journal or ~/.xsession-errors on the disk
    assert "doesn't open in your web browser by itself" not in capsys.readouterr().err
    ran.clear()
    status["zenity"] = status["kdialog"] = 127              # neither could show it: stderr is all there is
    assert app.refuse_without_window("x") == 2 and ran == ["zenity", "kdialog"]
    assert "doesn't open in your web browser by itself" in capsys.readouterr().err
