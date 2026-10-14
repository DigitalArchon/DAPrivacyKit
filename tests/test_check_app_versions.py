"""packaging/check-app-versions.py, the maintainer's side of apps.yaml: the parts that need no network."""

import datetime as dt
import sys

import pytest

from daprivacyscanner import appversions


def _tool():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "packaging" / "check-app-versions.py"
    spec = importlib.util.spec_from_file_location("check_app_versions", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod                    # its dataclasses look themselves up there
    spec.loader.exec_module(mod)
    return mod


def test_mark_changes_one_app_and_nothing_else():
    from pathlib import Path
    tool = _tool()
    text = (Path(__file__).resolve().parents[1] / "apps.yaml").read_text(encoding="utf-8")
    out = tool.mark(text, "vlc", "4.0.1", True, dt.date(2026, 12, 1))
    changed = [(a, b) for a, b in zip(text.splitlines(), out.splitlines()) if a != b]
    assert len(out.splitlines()) == len(text.splitlines())
    assert [b for _, b in changed] == ['    checked: "4.0.1"', "    basis: tested", "    checked_on: 2026-12-01"]
    vlc = appversions.parse(__import__("yaml").safe_load(out))["vlc"]
    assert vlc.checked == (4, 0, 1) and vlc.basis == "tested"
    with pytest.raises(SystemExit):
        tool.mark(text, "nope", "1.0", False, dt.date(2026, 12, 1))


def test_the_brief_lists_new_majors_with_their_checks():
    tool = _tool()
    apps = appversions.load()
    rows = [tool.Row(apps["firefox"], "170.0", 30), tool.Row(apps["vlc"], "3.0.99", 40), tool.Row(apps["discord"])]
    assert [r.state for r in rows] == ["new major", "newer", "untracked"]
    text = tool.brief(rows)
    assert "## Firefox (firefox): 157 -> 170.0" in text and "## VLC" not in text
    assert "- br.webrtc: WebRTC IP exposure (src/daprivacyscanner/checks/browser.py" in text
    assert "Discord (discord)" in text.split("## Not tracked on Repology")[1]
