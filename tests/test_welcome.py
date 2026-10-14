"""The welcome warning: shown at start-up until the user asks not to see it again (kept with the
warning's version), and the only pages it opens."""

from __future__ import annotations

import stat

from fastapi.testclient import TestClient

from conftest import make_host
from daprivacyscanner import about
from daprivacyscanner.paths import PathResolver
from daprivacyscanner.server import create_app

H = {"X-Token": "t0ken"}


def test_shown_until_hidden_and_again_when_the_warning_changes(cat, tmp_path, monkeypatch):
    host = make_host(tmp_path)
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    w = c.get("/api/state", headers=H).json()["welcome"]
    assert w["show"] is True and w["links"] == about.LINKS and set(w["links"]) == {"tails", "qubes", "releases", "issues"}
    assert all(u.startswith("https://") for u in w["links"].values())
    assert c.post("/api/welcome", headers=H, json={"hide": True}).json() == {"show": False}
    f = PathResolver(host.home, host.environ).config_home / "daprivacyscanner" / "ui.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert c.get("/api/state", headers=H).json()["welcome"]["show"] is False
    monkeypatch.setattr(about, "WELCOME_VERSION", about.WELCOME_VERSION + 1)       # the warning changed
    assert c.get("/api/state", headers=H).json()["welcome"]["show"] is True
    c.post("/api/welcome", headers=H, json={"hide": True})
    assert c.post("/api/welcome", headers=H, json={"hide": False}).json() == {"show": True}
    f.write_text("not json")
    assert about.welcome_shown(f.parent.parent) is True


def test_only_its_own_links_are_opened(cat, tmp_path):
    opened = []
    host = make_host(tmp_path)
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, open_url=opened.append))
    assert c.post("/api/open", headers=H, json={"link": "tails"}).json() == {"ok": True, "url": "https://tails.net/"}
    for bad in ({"link": "https://evil.example/"}, {"url": "https://tails.net/"}, {"link": ["qubes"]}, {}):
        assert c.post("/api/open", headers=H, json=bad).status_code == 400
    assert opened == ["https://tails.net/"]
    assert c.post("/api/open", json={"link": "qubes"}).status_code == 403


def test_the_app_says_when_its_own_copy_is_getting_old(cat, tmp_path, monkeypatch):
    """It never looks for a newer version of itself, so the build's date (the commit's) is what it goes by."""
    import datetime as dt

    assert about.age(built_on=None)["built"] is None or about.built() is not None        # a source tree: no date, no note
    fresh = about.age(dt.date(2026, 12, 1), dt.date(2026, 10, 12))
    assert fresh["built"] == "2026-10-12" and fresh["built_text"] == "12 October 2026" and not fresh["old"] and not fresh["text"]
    assert not about.age(dt.date(2027, 1, 10), dt.date(2026, 10, 12))["old"]              # 90 days exactly
    old = about.age(dt.date(2027, 3, 1), dt.date(2026, 10, 12))
    assert old["old"] and "built on 12 October 2026, about 4 months ago" in old["text"] and about.LINKS["releases"] in old["text"]
    assert not about.age(dt.date(2020, 1, 1), dt.date(2026, 10, 12))["old"]               # a clock set before the build
    # the page gets it with its state, and the text report says which version made it
    monkeypatch.setattr(about, "built", lambda: dt.date(2020, 1, 1))
    host = make_host(tmp_path)
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    app = c.get("/api/state", headers=H).json()["app"]
    assert app["old"] and app["version"] == about.__version__ and app["built"] == "2020-01-01"
    from daprivacyscanner import report
    lines = report.render_text({"results": {}, "context": {}}, cat, {}).splitlines()
    assert lines[1] == f"Version {about.__version__}, built 2020-01-01" and lines[2].startswith("Nothing in this report")
    assert lines[3].startswith("This copy of DA Privacy Kit was built on 1 January 2020")



def test_the_apps_own_pictures_carry_no_metadata():
    """What the app shows and ships says nothing about how it was made: a JPEG holds no APP1 to APP15
    segment (Exif with its thumbnail, XMP, a colour profile's maker) nor a comment, a PNG no text or
    Exif chunk. The first banner carried the editor's name, a date and a thumbnail."""
    import struct
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    pictures = [*(root / "src/daprivacyscanner/web").glob("*.jpg"), *(root / "src/daprivacyscanner/web").glob("*.png"),
                *(root / "packaging/appimage").glob("*.png"), *(root / "docs").glob("*.png")]
    assert pictures
    for p in pictures:
        data = p.read_bytes()
        if data[:2] == b"\xff\xd8":
            i, seen = 2, []
            while i + 4 <= len(data) and data[i] == 0xFF and data[i + 1] != 0xDA:      # up to the scan
                seen.append(data[i + 1])
                i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
            assert not [m for m in seen if 0xE1 <= m <= 0xEF or m == 0xFE], p.name
        else:
            assert data[:8] == b"\x89PNG\r\n\x1a\n", p.name
            i, kinds = 8, []
            while i + 8 <= len(data):
                size, kind = struct.unpack(">I4s", data[i:i + 8])
                kinds.append(kind)
                i += 12 + size
            assert not {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"} & set(kinds), p.name
