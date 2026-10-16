"""apps.yaml and what the scan does with it: installed versions read offline, a note on each check that reads an
app newer than it was made for, "couldn't check" where such an app keeps nothing where it used to, and files that
aren't in the form a check expects (FormatChanged)."""

import datetime as dt
import sqlite3

import pytest

from daprivacyscanner import appversions
from daprivacyscanner.appversions import App, DataError, parse_version
from daprivacyscanner.checks import REGISTRY, load_all
from daprivacyscanner.fix import FixPlan
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status
from daprivacyscanner.runner import Runner

from conftest import make_host, make_scan
from test_runner import check, laptop_host, run


def app(**kw):
    base = dict(id="x", name="X", checked=(157,), checked_text="157", basis="current", on=dt.date(2026, 10, 8),
                checks=("br.history_retention",))
    return App(**{**base, **kw})


@pytest.mark.parametrize("text, version", [
    ("157.0.1", (157, 0, 1)), ("1:128.3.0esr-1~deb12u1", (128, 3, 0)), ("4:24.2.7-0ubuntu0.24.04.6", (24, 2, 7)),
    ("1:9.6p1-3ubuntu13.19", (9, 6)), ("1:1snap1-0ubuntu5", None), ("", None), ("git-r123", None),
])
def test_parse_version(text, version):
    assert parse_version(text) == version


def test_major_versions_and_tolerance():
    assert not app().ahead((157, 9)) and app().ahead((158,))
    rapid = app(tolerance=3)
    assert not rapid.ahead((160, 1)) and rapid.ahead((161,))
    vscode = app(checked=(1, 105), major_parts=2)
    assert not vscode.ahead((1, 105, 9)) and vscode.ahead((1, 106)) and vscode.ahead((2, 0))
    assert not app().ahead((128, 3))                        # older (an ESR) says nothing


def test_the_shipped_list_names_real_checks(cat):
    apps = appversions.load()
    assert len(apps) > 50
    assert not [(a.id, c) for a in apps for c in a.checks if c not in cat.checks]
    assert {"firefox", "chromium", "plasma", "gnome", "opensnitch"} <= set(apps.apps)
    load_all()
    assert "app.newer_than_checked" in REGISTRY


@pytest.mark.parametrize("entry, error", [
    ({"checked": "x"}, "checked must be a version"),
    ({"basis": "guessed"}, "basis must be"),
    ({"packages": None}, "needs packages, flatpak or snap"),
    ({"data": ["config:../x"]}, "relative path"),
    ({"upstream": {"notes": "http://example.com"}}, "https only"),
    ({"surprise": 1}, "unknown keys"),
    ({"checked": "0.0"}, "placeholder"),                    # Discord's, said "made for 0.0" once it reached 1.0
    ({"checked": "0.9", "major_parts": 1}, "placeholder"),
])
def test_bad_entries_are_refused(entry, error):
    good = {"id": "x", "name": "X", "packages": ["x"], "checked": "1.0", "basis": "current",
            "checked_on": dt.date(2026, 10, 8), "checks": ["br.webrtc"]}
    with pytest.raises(DataError, match=error):
        appversions.parse({"schema_version": 1, "apps": [{**good, **entry}]})


def _package_managers(host, dpkg="", flatpak="", snap=""):
    """dpkg-query, flatpak and snap answering as on a real machine, whatever packages are asked about."""
    host.runner.handlers["dpkg-query"] = lambda argv: CommandResult(argv, 1, dpkg)
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 0, flatpak)
    host.runner.handlers["snap"] = lambda argv: CommandResult(argv, 0, snap)
    return host


def test_installed_takes_the_newest_install(tmp_path):
    host = _package_managers(make_host(tmp_path),
                             dpkg="ii \tfirefox\t1:1snap1-0ubuntu5\nii \tvlc\t3.0.20-1\nrc \tmpv\t0.37.0-1\n",
                             flatpak="org.mozilla.firefox\t160.0.2\norg.videolan.VLC\t\n",
                             snap="Name  Version  Rev\nfirefox  158.0-1  6800  latest/stable  mozilla  -\n")
    have = appversions.installed(host, appversions.load())
    assert have["firefox"].version == (160, 0, 2) and have["firefox"].source == "Flatpak"
    assert have["vlc"].short == "3.0.20" and "mpv" not in have             # removed, config left (rc)


def test_pacman_and_rpm(tmp_path):
    host = make_host(tmp_path)
    host.runner.handlers["pacman"] = lambda argv: CommandResult(argv, 1, "opensnitch 1.8.0-1\n")
    host.runner.handlers["rpm"] = lambda argv: CommandResult(argv, 1, "package firefox is not installed\nvlc\t3.0.21\n")
    have = appversions.installed(host, appversions.load())
    assert have["opensnitch"].version == (1, 8, 0) and have["vlc"].version == (3, 0, 21) and "firefox" not in have


FIREFOX_PROFILE = {".mozilla/firefox/profiles.ini": "[Profile0]\nName=default\nIsRelative=1\nPath=abc.default\n",
                   ".mozilla/firefox/abc.default/prefs.js": "",
                   ".mozilla/firefox/abc.default/places.sqlite": ""}


def _firefox(tmp_path, version, profile):
    host = laptop_host(tmp_path, home_files=FIREFOX_PROFILE if profile else {})
    return _package_managers(host, dpkg=f"ii \tfirefox\t{version}\n")


def test_a_newer_app_is_noted_on_its_checks(cat, tmp_path):
    impl = load_all()["br.webrtc"]
    report = Runner(cat, _firefox(tmp_path, "999.0", profile=True), {"br.webrtc": impl}).scan(only=["br.webrtc"])
    r = report.results["br.webrtc"]
    assert r.status is not Status.UNKNOWN
    note = next(n for n in r.notes if n.title.startswith("Firefox 999.0 is newer"))
    assert "Firefox 157" in note.text and "newer version of DA Privacy Kit" in note.text
    # the version it was made for: nothing said
    report = Runner(cat, _firefox(tmp_path / "same", "157.0.1", profile=True), {"br.webrtc": impl}).scan(only=["br.webrtc"])
    assert not any("newer than this check" in n.title for n in report.results["br.webrtc"].notes)


def test_nothing_where_a_newer_app_kept_it_is_couldnt_check(cat, tmp_path):
    impl = load_all()["br.webrtc"]
    r = Runner(cat, _firefox(tmp_path, "999.0", profile=False), {"br.webrtc": impl}).scan(only=["br.webrtc"]).results["br.webrtc"]
    assert r.status is Status.UNKNOWN and r.summary.startswith("Couldn't check Firefox")
    assert r.notes[0].title == "What the check found otherwise"
    assert any("Nothing of Firefox's was found" in n.text for n in r.notes)
    # an older Firefox that was never opened: nothing to say
    r = Runner(cat, _firefox(tmp_path / "old", "150.0", profile=False), {"br.webrtc": impl}).scan(only=["br.webrtc"]).results["br.webrtc"]
    assert r.status is not Status.UNKNOWN


def test_a_problem_found_stays_a_problem(cat, tmp_path):
    host = _firefox(tmp_path, "999.0", profile=False)
    fails = check("br.webrtc", lambda s, scan: Outcome(Status.FAIL, "Leaks"))
    r = run(cat, host, fails).results["br.webrtc"]
    assert r.status is Status.FAIL and any("newer than this check" in n.title for n in r.notes)


def test_the_dry_run_says_so(cat, tmp_path):
    host = _firefox(tmp_path, "999.0", profile=True)
    scan = make_scan(host)
    plan = FixPlan("br.webrtc", "Turn it off")
    Runner(cat, host)._explain(scan, [plan], "br.webrtc")
    assert plan.side_effects[0].startswith("Firefox 999.0 is installed") and "scan again after applying" in plan.side_effects[0]


def test_the_overview(cat, tmp_path):
    impl = load_all()["app.newer_than_checked"]
    host = _package_managers(laptop_host(tmp_path), dpkg="ii \tfirefox\t999.0\nii \tvlc\t3.0.20-1\n")
    r = Runner(cat, host, {impl.id: impl}).scan(only=[impl.id]).results[impl.id]
    assert r.status is Status.WARN and r.kind == "info" and not r.is_finding
    assert r.evidence[0].label == "Firefox" and "999.0 installed" in r.evidence[0].value
    assert "nothing where the older version kept its data" in r.evidence[0].value
    host = _package_managers(laptop_host(tmp_path / "ok"), dpkg="ii \tvlc\t3.0.20-1\n")
    assert Runner(cat, host, {impl.id: impl}).scan(only=[impl.id]).results[impl.id].status is Status.PASS
    assert Runner(cat, laptop_host(tmp_path / "none"), {impl.id: impl}).scan(only=[impl.id]).results[impl.id].status \
        is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ files not in the form a check expects

def _db(path, *tables):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    for t in tables:
        con.execute(f"CREATE TABLE {t} (id INTEGER)")
    con.commit()
    con.close()


def test_a_database_without_its_table_is_couldnt_check(cat, tmp_path):
    impl = load_all()["tel.cloud_sync"]
    host = laptop_host(tmp_path)
    _db(host.home / ".config/libaccounts-glib/accounts.db", "Renamed")
    r = Runner(cat, host, {impl.id: impl}).scan(only=[impl.id]).results[impl.id]
    assert r.status is Status.UNKNOWN and "isn't in the form this check expects" in r.summary
    assert "no table Accounts" in r.notes[0].text and r.evidence[0].label == "Not in the expected form"
    # a database its app has only just made, with no tables yet: just nothing found
    host = laptop_host(tmp_path / "empty")
    _db(host.home / ".config/libaccounts-glib/accounts.db")
    assert Runner(cat, host, {impl.id: impl}).scan(only=[impl.id]).results[impl.id].status is Status.PASS


def test_an_optional_table_may_be_missing(tmp_path):
    from daprivacyscanner.checks._util import sqlite_count
    from daprivacyscanner.host import FormatChanged
    db = tmp_path / "photo.db"
    _db(db, "PhotoTable")
    assert sqlite_count(db, "SELECT count(*) FROM FaceTable", optional=True) is None
    with pytest.raises(FormatChanged):
        sqlite_count(db, "SELECT count(*) FROM FaceTable")


def test_json_that_doesnt_parse_is_couldnt_check(cat, tmp_path):
    impl = load_all()["app.messengers_mail"]
    host = laptop_host(tmp_path, home_files={".config/Signal/config.json": '{"key": "abc"'})
    r = Runner(cat, host, {impl.id: impl}).scan(only=[impl.id]).results[impl.id]
    assert r.status is Status.UNKNOWN and "config.json" in r.summary and "valid JSON" in r.notes[0].text
    # an empty file is just nothing
    host = laptop_host(tmp_path / "empty", home_files={".config/Signal/config.json": ""})
    assert Runner(cat, host, {impl.id: impl}).scan(only=[impl.id]).results[impl.id].status is not Status.UNKNOWN

