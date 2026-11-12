"""The page in a real WebKitGTK window on a private Xvfb display (tests/web/webkit_smoke.py): a Tab cycle inside a
dialog, a press on a polled Stop that still clicks it, no breach of the page's Content-Security-Policy, and a screenshot
per theme. jsdom (tests/test_web.py) can't see layout, real Tab order, a press held across a drawing, inert, or CSP.

Opt-in: it runs when DAPRIVACYSCANNER_WEBKIT_SMOKE=1 (packaging/check.sh's webkit step sets it where Xvfb is installed)
and Xvfb, xdotool, pywebview and WebKitGTK 4.1 are all there; skipped otherwise. It never touches the user's display:
it starts its own Xvfb on a free :9x and stops it. Screenshots go to DAPRIVACYSCANNER_WEBKIT_SHOTS, else the test's
temporary folder (the path is printed)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def _missing() -> str | None:
    if os.environ.get("DAPRIVACYSCANNER_WEBKIT_SMOKE") != "1":
        return "opt-in: set DAPRIVACYSCANNER_WEBKIT_SMOKE=1 (make check does where Xvfb is installed)"
    for tool in ("Xvfb", "xdotool"):
        if shutil.which(tool) is None:
            return f"{tool} isn't installed"
    probe = subprocess.run([sys.executable, "-c", "import gi; gi.require_version('WebKit2', '4.1'); "
                            "from gi.repository import WebKit2; import webview"], capture_output=True, timeout=60)
    if probe.returncode:
        return "pywebview with WebKitGTK 4.1 isn't importable here"
    return None


def _free_display() -> int:
    for n in range(91, 100):
        if not Path(f"/tmp/.X11-unix/X{n}").exists() and not Path(f"/tmp/.X{n}-lock").exists():
            return n
    pytest.skip("no free display number from :91 to :99")


def test_the_page_in_webkitgtk(tmp_path):
    why = _missing()
    if why:
        pytest.skip(why)
    n = _free_display()
    xvfb = subprocess.Popen(["Xvfb", f":{n}", "-screen", "0", "1600x1000x24", "-nolisten", "tcp", "-nolisten", "local"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if Path(f"/tmp/.X11-unix/X{n}").exists():
                break
            time.sleep(0.1)
        out = Path(os.environ.get("DAPRIVACYSCANNER_WEBKIT_SHOTS") or tmp_path / "shots")
        env = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY", "XAUTHORITY")}
        env.update(DISPLAY=f":{n}", GDK_BACKEND="x11", NO_AT_BRIDGE="1",
                   PYTHONPATH=os.pathsep.join([str(HERE.parent / "src"), env.get("PYTHONPATH", "")]))
        r = subprocess.run([sys.executable, str(HERE / "web" / "webkit_smoke.py"), "--out", str(out)], env=env,
                           capture_output=True, text=True, timeout=240)
    finally:
        xvfb.terminate()
        xvfb.wait(10)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    assert lines, f"no result from the smoke test:\n{r.stdout[-2000:]}\n{r.stderr[-4000:]}"
    res = json.loads(lines[-1])
    print(f"screenshots: {out}: {', '.join(Path(s).name for s in res.get('shots', []))}")
    assert not res.get("error"), res
    failed = {k: v for k, v in res["checks"].items() if not v["ok"]}
    assert not failed, json.dumps(res, indent=1)
    assert {"loaded", "tab_cycle", "escape_closes", "stop_click", "csp"} <= set(res["checks"]), res
    assert len(res["shots"]) >= 4, res
