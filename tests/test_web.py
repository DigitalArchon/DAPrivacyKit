"""Runs the front-end test (tests/web/test_app.mjs) under node with jsdom, when both are
available: `npm install jsdom` in tests/web, or point DAPRIVACYSCANNER_NODE_PATH at a node_modules
that has it. Skipped otherwise, so the Python suite never needs node."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).parent / "web"


def _node_path() -> str | None:
    for p in [os.environ.get("DAPRIVACYSCANNER_NODE_PATH"), str(HERE / "node_modules")]:
        if p and (Path(p) / "jsdom").is_dir():
            return p
    return None


def test_front_end_against_the_canned_api():
    node, node_path = shutil.which("node"), _node_path()
    if not node or not node_path:
        pytest.skip("node with jsdom isn't available")
    r = subprocess.run([node, str(HERE / "test_app.mjs")], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "DAPRIVACYSCANNER_NODE_PATH": node_path})
    assert r.returncode == 0, r.stdout + r.stderr
