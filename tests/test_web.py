"""Runs the front-end test (tests/web/test_app.mjs) under node with jsdom, against the state the server gives the page
after a real scan of a fixture machine (`fixture_state`, made afresh for every run from create_app: the catalogue and
the result model as they are now, never a copy that ages).

jsdom is pinned in tests/web/package.json and package-lock.json: `npm ci --prefix tests/web` installs it (or point
DAPRIVACYSCANNER_NODE_PATH at a node_modules that has it). Without node or jsdom the test is skipped, and the end of
the run says so in capitals; with DAPRIVACYSCANNER_REQUIRE_NODE=1 (packaging/check.sh sets it) it fails instead.

`python tests/test_web.py` writes the same state to tests/web/fixture-state.json (ignored by git), for running
`node tests/web/test_app.mjs` by hand."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent / "web"
TOKEN = "t0ken"


def _node_path() -> str | None:
    for p in [os.environ.get("DAPRIVACYSCANNER_NODE_PATH"), str(HERE / "node_modules")]:
        if p and (Path(p) / "jsdom").is_dir():
            return p
    return None


def _pinned_jsdom() -> str:
    return json.loads((HERE / "package.json").read_text(encoding="utf-8"))["devDependencies"]["jsdom"]


def fixture_state(tmp_path: Path) -> dict:
    """GET /api/state after a scan (without administrator access) of a GNOME machine with a partly encrypted disk and
    location services on, with that disk's finding accepted. No Easy fix applies and the administrator helper isn't
    installed: the page test sets those up itself where it tests them."""
    from fastapi.testclient import TestClient

    from daprivacyscanner import blockdev, catalogue, server
    from daprivacyscanner.server import create_app

    from conftest import make_host, sample
    from fakes import FakeGSettings

    cat = catalogue.load(Path(__file__).resolve().parents[1] / catalogue.CATALOGUE_NAME)
    gs = FakeGSettings({
        ("org.gnome.desktop.notifications", "show-in-lock-screen"): "true",
        ("org.gnome.desktop.privacy", "remember-recent-files"): "true",
        ("org.gnome.desktop.privacy", "recent-files-max-age"): "-1",
        ("org.gnome.system.location", "enabled"): "true"})
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "GNOME"},
                     commands={("lsblk", "-J", "-o", blockdev.COLUMNS): sample("lsblk/debian-12-partial.json")},
                     home_files={".bash_history": "ls\n", ".local/share/Trash/files/old.txt": "x",
                                 ".local/share/Trash/info/old.txt.trashinfo":
                                     "[Trash Info]\nPath=/home/alice/old.txt\nDeletionDate=2026-01-01T00:00:00\n"})
    host.runner.handlers["gsettings"] = gs
    for p in [host.home, *host.home.rglob("*")]:         # whatever the umask: no group-writable home to find
        p.chmod(p.stat().st_mode & ~0o022)
    # whether the helper is installed is read from this computer's /usr/libexec: never in a fixture
    saved = server.installed_helper, server.installed_helper_stale
    server.installed_helper, server.installed_helper_stale = (lambda: None), (lambda: False)
    try:
        c = TestClient(create_app(TOKEN, cat, make_host=lambda: host))
        h = {"X-Token": TOKEN}
        report = c.post("/api/scan", headers=h).json()
        assert report["results"]["enc.partial_fde"]["is_finding"]
        c.post("/api/accept", headers=h, json={"check_id": "enc.partial_fde", "accept": True, "note": "scratch disk"})
        state = c.get("/api/state", headers=h).json()
    finally:
        server.installed_helper, server.installed_helper_stale = saved
    # Checks that need administrator access say so (needs_admin) in a scan without it; the page test starts from a
    # report in which none does, and marks one itself where it tests the button that asks for it.
    for r in state["report"]["results"].values():
        r["needs_admin"] = False
    return {"state": state}


def test_the_fixture_is_what_the_page_test_needs(tmp_path):
    """What test_app.mjs takes from the state, so a change to the scan that leaves it without one says so here."""
    s = fixture_state(tmp_path)["state"]
    results = s["report"]["results"]
    assert len(s["catalogue"]) > 100 and s["version"] == __import__("daprivacyscanner").__version__
    assert results["tel.location"]["status"] == "fail" and results["tel.location"]["evidence"]
    assert results["tel.location"]["effective_severity"] >= 2
    assert any(r["status"] == "pass" and r["effective_severity"] >= 6 and r["summary"] for r in results.values())
    assert any(r["status"] in ("unknown", "error") and r["effective_severity"] > 0 for r in results.values())
    assert any(r["is_hygiene"] for r in results.values()) and s["accepted"]
    assert {"enc.tmp_on_disk", "desk.thumbnails"} <= set(results)
    assert any(c["tier"] == "feature" for c in s["catalogue"])


def test_front_end_against_the_api_state(tmp_path):
    node, node_path = shutil.which("node"), _node_path()
    if not node or not node_path:
        why = ("node isn't installed" if not node else
               f"jsdom {_pinned_jsdom()} isn't installed: npm ci --prefix tests/web")
        if os.environ.get("DAPRIVACYSCANNER_REQUIRE_NODE") == "1":
            pytest.fail(f"the front-end test can't run: {why}", pytrace=False)
        pytest.skip(f"the front-end test didn't run: {why}")
    installed = json.loads((Path(node_path) / "jsdom" / "package.json").read_text(encoding="utf-8"))["version"]
    if installed != _pinned_jsdom() and os.environ.get("DAPRIVACYSCANNER_REQUIRE_NODE") == "1":
        pytest.fail(f"jsdom {installed} is installed, not the pinned {_pinned_jsdom()}: npm ci --prefix tests/web",
                    pytrace=False)
    fixture = tmp_path / "fixture-state.json"
    fixture.write_text(json.dumps(fixture_state(tmp_path / "machine")), encoding="utf-8")
    r = subprocess.run([node, str(HERE / "test_app.mjs")], capture_output=True, text=True, timeout=300,
                       env={**os.environ, "DAPRIVACYSCANNER_NODE_PATH": node_path,
                            "DAPRIVACYSCANNER_FIXTURE": str(fixture)})
    assert r.returncode == 0, r.stdout + r.stderr


if __name__ == "__main__":
    import tempfile

    sys.path.insert(0, str(Path(__file__).parent))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    with tempfile.TemporaryDirectory() as d:
        out = HERE / "fixture-state.json"
        out.write_text(json.dumps(fixture_state(Path(d)), indent=1), encoding="utf-8")
    print(f"wrote {out}")
