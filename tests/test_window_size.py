"""The window fits the screen it opens on (app.window_geometry, app.work_area): on KDE a 1480x940 window stayed larger
than a 1280x800 screen, and the welcome warning's "I understand" was below its edge."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from daprivacyscanner import app

ROOT = Path(__file__).resolve().parents[1]


def test_a_screen_with_room_gets_the_usual_window():
    assert app.window_geometry((1920, 1080)) == {"width": 1480, "height": 940, "min_size": (900, 600),
                                                 "maximized": False}
    assert app.window_geometry(None)["maximized"] is False                  # no display to ask: as before


@pytest.mark.parametrize("area", [(1280, 800), (1366, 768), (1440, 900), (1024, 600), (800, 480)])
def test_a_small_screen_gets_a_maximized_window_no_larger_than_it(area):
    g = app.window_geometry(area)
    assert g["maximized"] is True
    room = (area[0] - app.WINDOW_ROOM[0], area[1] - app.WINDOW_ROOM[1])
    assert g["width"] <= room[0] and g["height"] <= room[1]
    assert g["min_size"][0] <= g["width"] and g["min_size"][1] <= g["height"]   # a minimum it can keep


def test_the_window_is_made_with_it():
    src = (ROOT / "src/daprivacyscanner/app.py").read_text(encoding="utf-8")
    assert 'webview.create_window("DA Privacy Kit", url, **window_geometry(work_area()))' in src
    assert "width=1480" not in src


@pytest.mark.skipif(not shutil.which("Xvfb"), reason="Xvfb is needed")
def test_the_work_area_is_read_from_the_display(tmp_path):
    """Under a private Xvfb of 1280x800, as the KDE VM's screen: GDK reads that work area, and the window is made
    maximized and smaller than it."""
    n = next(i for i in range(97, 120) if not Path(f"/tmp/.X11-unix/X{i}").exists() and not Path(f"/tmp/.X{i}-lock").exists())
    xvfb = subprocess.Popen(["Xvfb", f":{n}", "-screen", "0", "1280x800x24", "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if Path(f"/tmp/.X11-unix/X{n}").exists():
                break
            time.sleep(0.1)
        env = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY", "XAUTHORITY")}
        env.update(DISPLAY=f":{n}", GDK_BACKEND="x11", PYTHONPATH=str(ROOT / "src"))
        code = ("from daprivacyscanner import app; a = app.work_area(); print(a); "
                "print(app.window_geometry(a)['maximized'])")
        r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
        if "Namespace Gtk not available" in r.stderr or r.stdout.startswith("None"):
            pytest.skip(f"GTK 3 isn't usable here: {r.stderr.strip()[-200:]}")
        assert r.stdout.split() == ["(1280,", "800)", "True"], r.stderr
    finally:
        xvfb.terminate()
        xvfb.wait(10)
