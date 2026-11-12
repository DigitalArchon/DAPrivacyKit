"""What running from an AppImage changes: programs the app runs get the host's environment, the
helper runs from a private copy root can read, and it can install itself root-owned (the AppImage
has no source tree to run packaging/install-helper.sh from). The build itself is
packaging/build-appimage.sh; packaging/test-appimage.sh smoke-tests the result."""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from daprivacyscanner import helper, hostenv, privileged

from fakes import FakeSystem

ROOT = Path(__file__).resolve().parents[1]


def test_programs_get_the_hosts_environment(monkeypatch):
    for k, v in {"APPIMAGE": "/x/A.AppImage", "APPDIR": "/tmp/.mount_x", "ARGV0": "a", "OWD": "/", "KEEP": "1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("GI_TYPELIB_PATH", raising=False)
    monkeypatch.setattr(hostenv, "ORIGINAL", {})
    hostenv.set_for_self("GI_TYPELIB_PATH", "/tmp/.mount_x/typelibs")
    env = hostenv.host_env(LC_ALL="C")
    assert env["KEEP"] == "1" and env["LC_ALL"] == "C"
    assert not set(hostenv.APPIMAGE_VARS) & set(env) and "GI_TYPELIB_PATH" not in env
    assert os.environ["GI_TYPELIB_PATH"] == "/tmp/.mount_x/typelibs"           # this process keeps it
    with hostenv.as_host():
        assert "APPDIR" not in os.environ and "GI_TYPELIB_PATH" not in os.environ
    assert os.environ["APPDIR"] == "/tmp/.mount_x"


def test_the_system_runner_uses_it(monkeypatch):
    from daprivacyscanner.host import SystemRunner
    monkeypatch.setenv("APPIMAGE", "/x/A.AppImage")
    assert "APPIMAGE" not in SystemRunner()._env and SystemRunner()._env["LC_ALL"] == "C"


def test_from_an_appimage_the_helper_runs_from_a_private_copy(tmp_path, monkeypatch):
    appdir = tmp_path / "mount"
    src = appdir / "usr/python/lib/python3.12/site-packages/daprivacyscanner/helper.py"
    src.parent.mkdir(parents=True)
    src.write_text("PROTOCOL = 7\n")
    monkeypatch.setenv("APPDIR", str(appdir))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    monkeypatch.setattr(helper, "__file__", str(src))
    monkeypatch.setattr(privileged, "installed_helper", lambda: None)
    cmd = privileged.fallback_command()
    copy = tmp_path / "run/daprivacyscanner/helper.py"
    # run by the loader, which checks the copy against the hash of what the app read from its own package
    assert cmd == ["pkexec", privileged.SYSTEM_PYTHON, "-I", "-c", privileged.LOADER, str(copy),
                   hashlib.sha256(b"PROTOCOL = 7\n").hexdigest()]
    assert copy.read_text() == "PROTOCOL = 7\n" and stat.S_IMODE(copy.parent.stat().st_mode) == 0o700


def test_from_a_source_tree_the_helper_runs_where_it_is(monkeypatch):
    monkeypatch.delenv("APPDIR", raising=False)
    monkeypatch.setattr(privileged, "installed_helper", lambda: None)
    cmd = privileged.fallback_command()
    assert cmd[-2] == str(Path(helper.__file__).resolve())
    assert cmd[-1] == hashlib.sha256(Path(helper.__file__).read_bytes()).hexdigest()


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(r))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    return r


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def test_the_helper_installs_and_removes_itself(root):
    r = call("install_self")
    installed = root / helper.INSTALLED.lstrip("/")
    text = installed.read_text()
    assert text.startswith("#!/usr/bin/python3 -I\n") and f"PROTOCOL = {helper.PROTOCOL}" in text
    assert text.split("\n", 1)[1] == Path(helper.__file__).read_text()               # the code running now
    assert stat.S_IMODE(installed.stat().st_mode) == 0o755
    assert (root / helper.POLICY_PATH.lstrip("/")).read_text() == helper.POLICY
    assert r["version"] == helper.PROTOCOL
    call("install_self")                                     # again: still one interpreter line
    assert installed.read_text() == text
    call("uninstall_self")
    assert not installed.exists() and not installed.parent.exists()
    assert not (root / helper.POLICY_PATH.lstrip("/")).exists()


def test_the_helper_installs_the_code_it_runs_not_the_file_as_it_is_now(root, tmp_path, monkeypatch):
    """main() reads the source as it starts (own_source); the file can be changed after that by anything running
    as the user (the uninstalled helper runs from a copy in the runtime folder), and the installed helper is still
    what was authorised and running."""
    copy = tmp_path / "helper.py"
    copy.write_text(Path(helper.__file__).read_text())
    monkeypatch.setattr(helper, "SELF", str(copy))
    monkeypatch.setattr(helper, "_SOURCE", None)
    helper.own_source()                                       # as main() does, before any request
    copy.write_text("print('swapped')\n")
    call("install_self")
    text = (root / helper.INSTALLED.lstrip("/")).read_text()
    assert f"PROTOCOL = {helper.PROTOCOL}" in text and "swapped" not in text


def test_installed_from_itself_it_stays_the_same(root, monkeypatch):
    call("install_self")
    installed = root / helper.INSTALLED.lstrip("/")
    first = installed.read_text()
    monkeypatch.setattr(helper, "SELF", str(installed))
    call("install_self")
    assert installed.read_text() == first


def test_the_built_in_policy_is_the_packaged_one():
    assert helper.POLICY == (ROOT / "packaging/au.com.digitalarchon.daprivacyscanner.policy").read_text()


def test_install_endpoint(cat, tmp_path):
    from fastapi.testclient import TestClient

    from daprivacyscanner.privileged import HelperDeclined
    from daprivacyscanner.server import create_app
    from conftest import make_host
    host = make_host(tmp_path)
    calls = []

    def install(uninstall):
        calls.append(uninstall)
        if len(calls) > 1:
            raise HelperDeclined("Authorization was cancelled.")
        return {"installed": helper.INSTALLED, "policy": helper.POLICY_PATH, "version": helper.PROTOCOL}

    c = TestClient(create_app("t", cat, make_host=lambda: host, install_helper=install))
    assert c.post("/api/helper/install").status_code == 403
    r = c.post("/api/helper/install", headers={"X-Token": "t"}, json={})
    assert r.json()["ok"] and r.json()["installed"] == helper.INSTALLED and calls == [False]
    r = c.post("/api/helper/install", headers={"X-Token": "t"}, json={"uninstall": True})
    assert r.status_code == 403 and r.json()["declined"] and calls == [False, True]


def test_install_helper_from_the_command_line(monkeypatch, capsys):
    from daprivacyscanner import app
    monkeypatch.setattr(privileged, "install_helper", lambda uninstall=False: {
        "installed": helper.INSTALLED, "policy": helper.POLICY_PATH, "version": helper.PROTOCOL})
    assert app.install_helper_cli(False) == 0 and "password prompt now names DA Privacy Kit" in capsys.readouterr().out

    def refuse(uninstall=False):
        raise privileged.HelperUnavailable("pkexec (polkit) is not installed.")
    monkeypatch.setattr(privileged, "install_helper", refuse)
    assert app.install_helper_cli(True) == 1 and "Not removed" in capsys.readouterr().err


def _repo(tmp_path, files: dict[str, str]) -> tuple[Path, dict]:
    """A scratch git repository with `files` committed, and an environment for the packaging scripts that keeps them
    in tmp_path: git's own defaults (no signing, no hooks), and podman a fake that writes down how it was called."""
    import subprocess
    repo, bin_dir = tmp_path / "repo", tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "podman").write_text(f'#!/bin/sh\necho "$@" >> {tmp_path / "podman.calls"}\n')
    (bin_dir / "podman").chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "TMPDIR": str(tmp_path),
           "XDG_CACHE_HOME": str(tmp_path / "cache"), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.org"}
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
        if rel.endswith(".sh"):
            (repo / rel).chmod(0o755)
    for argv in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "release"], ["tag", "v1.0"]):
        subprocess.run(["git", *argv], cwd=repo, env=env, check=True)
    return repo, env


def test_the_appimage_is_named_after_the_version_it_builds(tmp_path):
    """build and check build HEAD (git archive), and took the version from the working tree: with a version bump not
    yet committed, the AppImage's name, desktop entry and AppStream release said the new version, the package inside
    HEAD's, and verify-release.sh couldn't build it again. dev builds the working tree, and takes its version."""
    import subprocess
    repo, env = _repo(tmp_path, {
        "pyproject.toml": '[project]\nversion = "1.0"\n',
        "packaging/build-appimage.sh": (ROOT / "packaging/build-appimage.sh").read_text(),
        "packaging/appimage/pins.sh": (ROOT / "packaging/appimage/pins.sh").read_text(),
        "packaging/appimage/Containerfile": "FROM scratch\n"})
    (repo / "pyproject.toml").write_text('[project]\nversion = "2.0"\n')               # bumped, not committed
    head = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=repo, env=env, capture_output=True,
                          text=True).stdout.strip()
    # a dev build carries +dev.<commit>, .dirty with uncommitted changes: never a release's own name
    for mode, version in (("build", "1.0"), ("dev", f"2.0+dev.{head}.dirty")):
        r = subprocess.run(["bash", "packaging/build-appimage.sh", mode], cwd=repo, env=env, capture_output=True,
                           text=True)
        assert r.returncode == 0, r.stderr
        run = (tmp_path / "podman.calls").read_text().splitlines()[-1]
        assert run.startswith("run ") and f"VERSION={version} " in run, (mode, run)


def test_verify_release_says_it_couldnt_check_rather_than_they_differ(tmp_path):
    """Exit status 0 the same, 1 they differ, 2 it couldn't be checked: under set -e alone, any of its own steps that
    failed (here the build left no AppImage to hash) ended it with 1, "they differ"."""
    import hashlib
    import subprocess
    build = '#!/bin/bash\nmkdir -p dist\n[ -z "${OUT:-}" ] || printf %s "$OUT" > dist/DAPrivacyKit-1.0-x86_64.AppImage\n'
    repo, env = _repo(tmp_path, {"pyproject.toml": '[project]\nversion = "1.0"\n', "packaging/build-appimage.sh": build})
    same = hashlib.sha256(b"built").hexdigest()

    def verify(out: str | None) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(ROOT / "packaging/verify-release.sh"), "v1.0", same], cwd=repo,
                              env={**env, **({"OUT": out} if out is not None else {})}, capture_output=True, text=True)
    assert verify("built").returncode == 0
    r = verify("something else")
    assert r.returncode == 1 and "DIFFERENT" in r.stderr and (repo / "dist/verify/DAPrivacyKit-1.0-x86_64.AppImage").exists()
    assert verify(None).returncode == 2


def test_the_wheel_carries_the_catalogue():
    import tomllib
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "privacy-checks.yaml" in data["tool"]["setuptools"]["package-data"]["daprivacyscanner"]
    assert data["project"]["license"] == "GPL-3.0-or-later" and (ROOT / "LICENSE").read_text().lstrip().startswith(
        "GNU GENERAL PUBLIC LICENSE")
    build = (ROOT / "packaging/appimage/build.sh").read_text()
    assert 'cp "$W/src/privacy-checks.yaml" "$W/src/src/daprivacyscanner/privacy-checks.yaml"' in build
    assert 'cp "$W/src/vpn-providers.yaml" "$W/src/src/daprivacyscanner/vpn-providers.yaml"' in build
    assert "vpn-providers.yaml" in data["tool"]["setuptools"]["package-data"]["daprivacyscanner"]
    assert 'cp "$W/src/browsers.yaml" "$W/src/src/daprivacyscanner/browsers.yaml"' in build
    assert "browsers.yaml" in data["tool"]["setuptools"]["package-data"]["daprivacyscanner"]
    assert 'cp "$W/src/signing-keys.yaml" "$W/src/src/daprivacyscanner/signing-keys.yaml"' in build
    assert "signing-keys.yaml" in data["tool"]["setuptools"]["package-data"]["daprivacyscanner"]
    assert 'cp "$W/src/apps.yaml" "$W/src/src/daprivacyscanner/apps.yaml"' in build
    assert "apps.yaml" in data["tool"]["setuptools"]["package-data"]["daprivacyscanner"]
