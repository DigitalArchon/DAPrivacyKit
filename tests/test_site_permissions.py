"""br.site_permissions: sites remembered as allowed the camera, microphone or location (counts
only), and browsers that allow every site; the guide blocks new requests and reverts."""

from __future__ import annotations

import json
import sqlite3
import time

from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from test_checks_telemetry_browser import chrome, firefox, pref
from test_guides import apply, build, options, revert, rooted, system  # noqa: F401 - the fixture

CHECK = "br.site_permissions"


def perms_db(profile, rows):
    con = sqlite3.connect(profile / "permissions.sqlite")
    con.execute("CREATE TABLE moz_perms (id INTEGER PRIMARY KEY, origin TEXT, type TEXT, permission INTEGER, "
                "expireType INTEGER, expireTime INTEGER, modificationTime INTEGER)")
    con.executemany("INSERT INTO moz_perms (origin, type, permission, expireType, expireTime, modificationTime) "
                    "VALUES (?, ?, ?, ?, ?, 0)", rows)
    con.commit()
    con.close()


def test_no_browsers(cat, tmp_path):
    assert detect(cat, CHECK, make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


def test_nothing_remembered_passes(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home)
    chrome(host.home)
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.PASS and o.findings == {"site_default_allow": False}
    assert ev(o)["Firefox profile abcd.default-release"] == "camera: 0 sites; microphone: 0 sites; location: 0 sites"


def test_firefox_rows_are_counted_never_named(cat, tmp_path):
    host = make_host(tmp_path)
    prof = firefox(host.home, prefs=pref("permissions.default.geo", 2))
    later = int(time.time() * 1000) + 86_400_000
    perms_db(prof, [("https://meet.example", "camera", 1, 0, 0), ("https://meet.example", "microphone", 1, 0, 0),
                    ("https://maps.example", "geo", 1, 2, later), ("https://old.example", "geo", 1, 2, 1000),
                    ("https://tab.example", "camera", 1, 1, 0), ("https://no.example", "camera", 2, 0, 0),
                    ("https://x.example", "desktop-notification", 1, 0, 0)])
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.FAIL and "3 permissions" in o.summary
    assert ev(o)["Firefox profile abcd.default-release"] == \
        "camera: 1 site; microphone: 1 site; location: 1 site, new requests blocked"
    assert "example" not in str(o.evidence)
    assert effective_severity(cat[CHECK], o.findings).value == 3


def test_chromium_allowing_every_site(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, prefs={"profile": {
        "default_content_setting_values": {"geolocation": 1},
        "content_settings": {"exceptions": {"media_stream_camera": {"https://a.example:443,*": {"setting": 1},
                                                                    "https://b.example:443,*": {"setting": 2}}}}}})
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.FAIL and o.findings == {"site_default_allow": True}
    assert ev(o)["Google Chrome, Default"] == \
        "camera: 1 site; microphone: 0 sites; location: 0 sites, and every other site without asking"
    assert effective_severity(cat[CHECK], o.findings).value == 6


def test_guide_blocks_new_requests_in_firefox_and_reverts(cat, tmp_path):
    host = make_host(tmp_path)
    prof = firefox(host.home)
    perms_db(prof, [("https://meet.example", "camera", 1, 0, 0)])
    g = build(cat, host, CHECK)
    assert "Settings… button" in g.steps[0].text and "camera: 1 site" in g.steps[0].text
    label = "Block new requests for the camera, microphone and location: Firefox profile abcd.default-release"
    log, res = apply(host, options(g)[label])
    prefs = (prof / "prefs.js").read_text()
    assert pref("permissions.default.camera", 2) in prefs and pref("permissions.default.geo", 2) in prefs
    revert(host, log, res)
    assert (prof / "prefs.js").read_text() == ""


def test_guide_blocks_chromium_location_by_policy(cat, tmp_path, system, monkeypatch):  # noqa: F811
    host = make_host(tmp_path)
    chrome(host.home, prefs={"profile": {"content_settings": {"exceptions": {
        "geolocation": {"https://a.example:443,*": {"setting": 1}}}}}})
    rooted(host, system, monkeypatch)
    g = build(cat, host, CHECK)
    assert "chrome://settings/content/location" in g.steps[0].text
    plan = options(g)["Block location requests: Google Chrome, for every user (policy)"]
    log, res = apply(host, plan)
    path = host.root / "etc/opt/chrome/policies/managed/daprivacyscanner.json"
    assert json.loads(path.read_text()) == {"DefaultGeolocationSetting": 2}
    o = detect(cat, CHECK, make_scan(host))
    assert "location: 1 site, new requests blocked" in ev(o)["Google Chrome, Default"]
    revert(host, log, res)
    assert not path.exists()
