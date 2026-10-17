"""Apps, browsers, desktop, telemetry and sandbox checks corrected after the review of 2026-10-17: what a check
counts, what its fix or guide offers, and that applying it makes the check pass (or the step done)."""

import json

from daprivacyscanner.checks import load_all
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from test_checks_telemetry_browser import chrome, firefox, pref
from test_guides import apply, build, options, revert, rooted, system  # noqa: F401  (system is a fixture)


def _guide(cat, host, check_id, **kw):
    check = load_all()[check_id](cat[check_id])
    scan = make_scan(host, **kw)
    return check.plan_guide(scan, check.detect(scan))


def _step(guide, title_start):
    return next(s for s in guide.steps if s.title.startswith(title_start))


# ------------------------------------------------------------------ Chromium-based browsers: folders, policies

def test_an_empty_browser_folder_is_no_browser(cat, tmp_path):
    """Omarchy's packages make NativeMessagingHosts folders for browsers that aren't installed, and Plasma Browser
    Integration one under ~/.var/app/com.google.Chrome: none of them is a browser that has run."""
    host = make_host(tmp_path)
    for rel in (".config/BraveSoftware/Brave-Browser/NativeMessagingHosts", ".config/google-chrome/NativeMessagingHosts",
                ".config/microsoft-edge/NativeMessagingHosts",
                ".var/app/com.google.Chrome/config/google-chrome/NativeMessagingHosts"):
        (host.home / rel).mkdir(parents=True)
    scan = make_scan(host)
    from daprivacyscanner.checks._util import chromium_dirs
    assert chromium_dirs(scan.paths) == []
    assert detect(cat, "tel.browser_telemetry", scan).status is Status.NOT_APPLICABLE
    assert detect(cat, "auth.chromium_basic_store", scan).status is Status.NOT_APPLICABLE
    # one that has run: its Local State, or a profile folder
    (host.home / ".config/BraveSoftware/Brave-Browser/Local State").write_text("{}")
    assert [d.browser for d in chromium_dirs(make_scan(host).paths)] == ["Brave"]


def test_brave_telemetry_policies_are_read(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    chrome(host.home, local_state={}, root=".config/BraveSoftware/Brave-Browser")
    o = detect(cat, "tel.browser_telemetry", make_scan(host))
    assert o.status is Status.FAIL and "P3A analytics" in ev(o)["Brave"]
    g = build(cat, host, "tel.browser_telemetry")
    plan = options(g)["Turn off usage statistics: Brave, for every user (policy)"]
    log, res = apply(host, plan)
    pol = json.loads((host.root / "etc/brave/policies/managed/daprivacyscanner.json").read_text())
    assert pol == {"MetricsReportingEnabled": False, "BraveP3AEnabled": False, "BraveStatsPingEnabled": False}
    assert detect(cat, "tel.browser_telemetry", make_scan(host)).status is Status.PASS
    revert(host, log, res)


def test_a_policy_in_place_is_not_offered_again(cat, tmp_path, system, monkeypatch):
    """chromium_policy_options read the policies there: applied once, the option goes and its step is done."""
    host = rooted(make_host(tmp_path), system, monkeypatch)
    chrome(host.home, prefs={})
    plan = options(build(cat, host, "br.tracking_protection"))["Block third-party cookies: Google Chrome, for every user (policy)"]
    log, res = apply(host, plan)
    assert detect(cat, "br.tracking_protection", make_scan(host)).status is Status.PASS
    g = _guide(cat, host, "br.tracking_protection")
    step = _step(g, "Chromium-based browsers")
    assert step.done and not step.options
    revert(host, log, res)
    # only what isn't there yet: the WebRTC policy set by hand leaves nothing to offer
    d = host.root / "etc/opt/chrome/policies/managed"
    d.mkdir(parents=True, exist_ok=True)
    (d / "corp.json").write_text(json.dumps({"WebRtcIPHandling": "default_public_interface_only"}))
    assert detect(cat, "br.webrtc", make_scan(host)).status is Status.PASS
    # a profile that is fine already gets no policy option either
    chrome(host.home, prefs={"profile": {"block_third_party_cookies": True}})
    firefox(host.home)
    g = build(cat, host, "br.tracking_protection")
    assert _step(g, "Chromium-based browsers").done and not _step(g, "Chromium-based browsers").options


def test_history_retention_reads_the_cookie_policy_and_its_firefox_step_ends(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    chrome(host.home, prefs={})
    d = host.root / "etc/opt/chrome/policies/managed"
    d.mkdir(parents=True)
    (d / "corp.json").write_text(json.dumps({"DefaultCookiesSetting": 4}))
    firefox(host.home, prefs=pref("privacy.sanitize.sanitizeOnShutdown", True))
    o = detect(cat, "br.history_retention", make_scan(host))
    assert ev(o)["Google Chrome, Default"] == "cookies cleared when it closes (policy), history kept"
    g = build(cat, host, "br.history_retention")
    assert _step(g, "Firefox").done                  # Firefox clears its history already: nothing left there
    step = _step(g, "Chromium-based browsers")
    assert not step.done and [o.label for o in step.options] == [
        "Turn off sync, and clear history, downloads and cache when the browser closes: Google Chrome, for every user "
        "(policy)"]
    log, res = apply(host, step.options[0].plan)
    assert detect(cat, "br.history_retention", make_scan(host)).status is Status.PASS
    revert(host, log, res)


def test_enhanced_safe_browsing_has_a_step(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, prefs={"safebrowsing": {"enhanced": True}})
    g = build(cat, host, "br.ad_features")
    step = _step(g, "Enhanced Safe Browsing")
    assert "Security → Standard protection" in step.text and "Google Chrome, Default" in step.text
    chromium = _step(g, "Chromium-based browsers")
    assert chromium.done and not chromium.options       # the policy doesn't turn it off: no option for it


# ------------------------------------------------------------------ Firefox-family prefs

def test_thunderbird_running_holds_up_only_thunderbird(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home)
    firefox(host.home, root=".thunderbird", name="tb.default")
    (host.root / "proc/7").mkdir(parents=True)
    (host.root / "proc/7/comm").write_text("thunderbird\n")
    opts = options(build(cat, host, "tel.browser_telemetry"))
    ff = opts["Turn off telemetry and studies: Firefox profile abcd.default-release"]
    tb = opts["Turn off telemetry: Thunderbird profile tb.default"]
    assert not ff.blockers and tb.blockers == ["Close Thunderbird first: it rewrites its settings as it exits."]
    # Thunderbird gets only what the check reads there: telemetry (no studies, no usage ping)
    assert [a.key for a in tb.actions] == ["datareporting.healthreport.uploadEnabled"]


def test_browser_telemetry_options_only_where_it_is_on(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    off = pref("datareporting.healthreport.uploadEnabled", False) + pref("app.shield.optoutstudies.enabled", False) \
        + pref("datareporting.usage.uploadEnabled", False)
    firefox(host.home, prefs=off)
    firefox(host.home, root=".thunderbird", name="tb.default", prefs=pref("datareporting.healthreport.uploadEnabled", False))
    assert detect(cat, "tel.browser_telemetry", make_scan(host)).status is Status.PASS
    # telemetry on in Firefox, but the policy covers it: no per-profile option, and no policy option again
    prof = firefox(host.home)
    d = host.root / "etc/firefox/policies"
    d.mkdir(parents=True)
    (d / "policies.json").write_text(json.dumps({"policies": {"DisableTelemetry": True}}))
    g = build(cat, host, "tel.browser_telemetry")
    opts = options(g)
    plan = opts["Turn off telemetry and studies: Firefox profile abcd.default-release"]
    assert [a.key for a in plan.actions] == ["app.shield.optoutstudies.enabled"]
    pol = opts["Firefox, for every user (policy)"]
    assert pol.actions[0].args["settings"] == {"DisableFirefoxStudies": True}
    log, res = apply(host, pol)
    assert detect(cat, "tel.browser_telemetry", make_scan(host)).status is Status.PASS
    assert prof.is_dir()
    revert(host, log, res)


def test_thunderbird_remote_content_offered_only_where_it_loads(cat, tmp_path):
    host = make_host(tmp_path)
    tb = firefox(host.home, root=".thunderbird", name="tb.default",
                 prefs=pref("mailnews.message_display.disable_remote_image", False))
    g = build(cat, host, "app.mail_remote_content")
    step = _step(g, "Thunderbird")
    assert not step.done and len(step.options) == 1
    log, res = apply(host, step.options[0].plan)
    assert detect(cat, "app.mail_remote_content", make_scan(host)).status is Status.PASS
    revert(host, log, res)
    (tb / "prefs.js").write_text("")                    # the default: blocked
    assert detect(cat, "app.mail_remote_content", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ extensions removed, until the browser starts

def _grabber(prof):
    xpi = prof / "extensions" / "grabber@example.com.xpi"
    return {"id": "grabber@example.com", "type": "extension", "active": True, "location": "app-profile",
            "defaultLocale": {"name": "Page Grabber"}, "userPermissions": {"origins": ["<all_urls>"]},
            "path": str(xpi)}, xpi


def test_an_extension_removed_from_the_profile_is_not_counted_until_firefox_starts(cat, tmp_path):
    host = make_host(tmp_path)
    prof = firefox(host.home)
    addon, xpi = _grabber(prof)
    (prof / "extensions.json").write_text(json.dumps({"addons": [addon]}))
    xpi.parent.mkdir()
    xpi.write_bytes(b"PK")
    (host.root / "proc/7").mkdir(parents=True)
    (host.root / "proc/7/comm").write_text("thunderbird\n")          # not the browser: it doesn't hold it up
    g = build(cat, host, "br.extensions_broad")
    plan = options(g)["Remove it from this profile"]
    assert not plan.blockers
    apply(host, plan)
    o = detect(cat, "br.extensions_broad", make_scan(host))         # extensions.json still lists it
    assert o.status is Status.PASS and any("Page Grabber" in n.text for n in o.notes)


def test_an_extension_the_policy_blocks_is_not_offered_again(cat, tmp_path, system, monkeypatch):
    host = rooted(make_host(tmp_path), system, monkeypatch)
    prof = firefox(host.home)
    addon, _ = _grabber(prof)
    del addon["path"]
    (prof / "extensions.json").write_text(json.dumps({"addons": [addon]}))
    ext = chrome(host.home) / "Extensions" / ("a" * 32) / "1.0_0"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({"name": "Grammar Helper", "host_permissions": ["<all_urls>"]}))
    policy = "Remove it and keep it off, for every account on this computer (policy)"
    g = build(cat, host, "br.extensions_broad")
    ff = _step(g, "Page Grabber").options[0].plan
    ch = _step(g, "Grammar Helper").options[0].plan
    assert {o.label for s in g.steps for o in s.options} == {policy}
    apply(host, ff)
    apply(host, ch)
    o = detect(cat, "br.extensions_broad", make_scan(host))
    assert o.status is Status.PASS and len(o.notes) == 1 and "Grammar Helper" in o.notes[0].text
    g = _guide(cat, host, "br.extensions_broad")
    assert [s.title for s in g.steps] == ["Nothing to go through"]


# ------------------------------------------------------------------ thumbnails as Qt writes them (zTXt, iTXt)

def _chunk(kind: bytes, data: bytes) -> bytes:
    import struct
    import zlib
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def qt_png(uri: str, itxt: bool = False) -> bytes:
    """A thumbnail as Qt's PNG writer makes one: text over 40 characters compressed, zTXt (iTXt when not Latin-1)."""
    import struct
    import zlib
    text = (_chunk(b"iTXt", b"Thumb::URI\0\x01\x00\0\0" + zlib.compress(uri.encode())) if itxt else
            _chunk(b"zTXt", b"Thumb::URI\0\0" + zlib.compress(uri.encode())))
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _chunk(b"tEXt", b"Thumb::MTime\0" + b"1792247823") + text
            + _chunk(b"IDAT", zlib.compress(b"\0\0\0\0")) + _chunk(b"IEND", b""))


def test_png_text_reads_what_qt_writes():
    import zlib
    from pathlib import Path
    from daprivacyscanner.checks._util import png_text
    real = (Path(__file__).parent / "samples/thumbnails/kde-dolphin-ztxt.png").read_bytes()     # made by Dolphin
    assert png_text(real)["Thumb::URI"] == ("file:///home/test/Downloads/LongFolderNameForThumbnailTesting/"
                                            "a-picture-with-quite-a-long-name.png")
    uri = "file:///home/alice/Pictures/%C3%A9t%C3%A9/a%20long%20name%20for%20a%20picture.jpg"
    assert png_text(qt_png(uri))["Thumb::URI"] == uri
    assert png_text(qt_png("file:///home/alice/été/photo.jpg", itxt=True))["Thumb::URI"] == "file:///home/alice/été/photo.jpg"
    assert png_text(b"\x89PNG\r\n\x1a\n" + _chunk(b"iTXt", b"Thumb::URI\0\0\0\0\0file:///a.png"))["Thumb::URI"] == "file:///a.png"
    bomb = b"\x89PNG\r\n\x1a\n" + _chunk(b"zTXt", b"Thumb::URI\0\0" + zlib.compress(b"a" * (10 * 1024 * 1024)))
    assert png_text(bomb) == {}                          # inflated only so far: a path, never megabytes


def test_kde_thumbnails_are_seen_and_deleted_before_the_cache_goes_into_memory(cat, tmp_path):
    host = make_host(tmp_path)
    cache = host.home / ".cache/thumbnails/normal"
    cache.mkdir(parents=True)
    gone = f"file://{host.home}/Downloads/a-picture-deleted-since-with-a-long-name.png"
    (cache / "0123.png").write_bytes(qt_png(gone))
    (host.home / "Downloads").mkdir()
    o = detect(cat, "desk.thumbnails", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.FAIL and "of deleted files" in o.summary
    assert detect(cat, "br.private_download_leak", make_scan(host)).status is Status.FAIL
    g = build(cat, host, "desk.thumbnails", desktop=("kde",), plasma_major=6)
    plan = options(g)["Mount ~/.cache/thumbnails in memory (needs administrator access)"]
    deletions = [a for a in plan.actions if a.kind == "delete"]
    assert [f.name for d in deletions for f in d.files] == ["0123.png"]


# ------------------------------------------------------------------ KDE apps' lists: a lock that lasts

def test_a_lock_in_the_apps_own_file_isnt_taken_for_stopped(cat, tmp_path):
    """Gwenview and Okular 26.08 drop an empty [Recent Files][$i] group as they rewrite their own file (live), so
    only a lock beneath it (kdedefaults, or the system's /etc/xdg) counts as stopped."""
    host = make_host(tmp_path, home_files={".config/gwenviewrc": "[MainWindow]\nMenuBar=Disabled\n\n[Recent Files][$i]\n"})
    o = detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.WARN and "Gwenview will list" in o.summary
    g = build(cat, host, "app.kde_recent_files", desktop=("kde",), plasma_major=6)
    log, res = apply(host, options(g)["Stop these apps keeping lists"])
    assert (host.home / ".config/kdedefaults/gwenviewrc").read_text() == "[Recent Files][$i]\n"
    (host.home / ".config/gwenviewrc").write_text("[MainWindow]\nMenuBar=Disabled\n")         # Gwenview, closing
    o = detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.PASS and ev(o) == {"Gwenview: ~/.config/gwenviewrc": "stopped"}
    revert(host, log, res)


def test_a_flatpak_apps_list_is_cleared_only(cat, tmp_path):
    rc = "[Recent Files]\nFile1[$e]=$HOME/Downloads/a.pdf\nName1[$e]=a.pdf\n"
    host = make_host(tmp_path, home_files={".var/app/org.kde.okular/config/okularrc": rc})
    o = detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.FAIL and o.summary.startswith("1 file or folder you opened is listed")
    assert any("Okular (flatpak)" in n.text for n in o.notes)
    g = build(cat, host, "app.kde_recent_files", desktop=("kde",), plasma_major=6)
    assert set(options(g)) == {"Clear them"} and _step(g, "Stop them").done
    assert "Okular (flatpak) can't be stopped this way" in _step(g, "Stop them").text
    apply(host, options(g)["Clear them"])
    o = detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.PASS and o.summary == "Nothing is listed now."


def test_private_downloads_in_kde_records(cat, tmp_path):
    import sqlite3
    host = make_host(tmp_path, home_files={
        ".config/gwenviewrc": "[Recent Files]\nFile1[$e]=$HOME/Downloads/photo.png\nName1[$e]=photo.png\n",
        ".local/share/gwenview/recentfolders/gvhistoryA.rc": f"[general]\nurl=file://{tmp_path}/home/alice/Downloads/\n"})
    (host.home / "Downloads").mkdir()
    db = host.home / ".local/share/kactivitymanagerd/resources/database"
    db.parent.mkdir(parents=True)
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE ResourceEvent (usedActivity TEXT, initiatingAgent TEXT, targettedResource TEXT, start "
              "INTEGER, end INTEGER)")
    c.execute("CREATE TABLE ResourceScoreCache (usedActivity TEXT, initiatingAgent TEXT, targettedResource TEXT, "
              "scoreType INTEGER, cachedScore FLOAT, firstUpdate INTEGER, lastUpdate INTEGER)")
    for path in (f"{host.home}/Downloads/photo.png", f"{host.home}/Documents/kept.odt", f"{host.home}/Downloads/it's.pdf"):
        c.execute("INSERT INTO ResourceEvent VALUES ('a', 'org.kde.gwenview', ?, 1, 2)", (path,))
    c.commit()
    c.close()
    o = detect(cat, "br.private_download_leak", make_scan(host, desktop=("kde",), plasma_major=6))
    e = ev(o)
    assert o.status is Status.FAIL and e["Downloads in KDE apps' lists of what they opened"] == 2
    assert e["Downloads in KDE's activity history"] == 2


# ------------------------------------------------------------------ clipboard history

def test_klipper_off_with_its_old_history_is_said_as_it_is(cat, tmp_path):
    from test_fixes import plasma6, run_fix
    host, shell = plasma6(tmp_path)
    plan, res, log = run_fix(cat, host, "desk.clipboard_history", desktop=("kde",), plasma_major=6)
    assert any("old copies stay in that file until Plasma restarts at your next login" in e for e in plan.side_effects)
    o = detect(cat, "desk.clipboard_history", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.FAIL and o.summary == "Klipper is off; its old history is still on the disk."
    # Plasma writes klipperrc's Version itself meanwhile: no "settings added since" for that
    rc = host.home / ".config/klipperrc"
    rc.write_text(rc.read_text() + "\n[General]\nVersion=6.7.5\n" if "[General]" not in rc.read_text()
                  else rc.read_text().replace("[General]\n", "[General]\nVersion=6.7.5\n"))
    results = revert(host, log, res)
    assert not rc.exists() and not any("added since" in r.message for r in results)


def test_gpaste_stops_saving_and_its_file_goes_while_it_runs(cat, tmp_path):
    from fakes import FakeGSettings
    from test_fixes import revert as fix_revert, run_fix
    host = make_host(tmp_path, files={"/proc/9/comm": "gpaste-daemon\n"},
                     home_files={".local/share/gpaste/history.xml": "<history>secret</history>"})
    gs = host.runner.handlers["gsettings"] = FakeGSettings({("org.gnome.GPaste", "save-history"): "true"})
    plan, res, log = run_fix(cat, host, "desk.clipboard_history")
    assert [a.kind for a in plan.actions] == ["gsettings", "delete"] and not plan.blockers
    assert res.ok and gs.values[("org.gnome.GPaste", "save-history")] == "false"
    assert detect(cat, "desk.clipboard_history", make_scan(host)).status is Status.PASS
    fix_revert(host, log, res)
    assert gs.values[("org.gnome.GPaste", "save-history")] == "true"


def test_a_clipboard_manager_that_saves_again_says_so(cat, tmp_path):
    host = make_host(tmp_path, home_files={".cache/clipboard-indicator@tudmotu.com/registry.txt": "x"})
    check = load_all()["desk.clipboard_history"](cat["desk.clipboard_history"])
    plan = check.plan_fix(make_scan(host), None)
    assert [a.kind for a in plan.actions] == ["delete"]
    assert any("saves its history again as you copy" in e for e in plan.side_effects)


# ------------------------------------------------------------------ Baloo: stopped, waited for, started detached

def test_baloo_rebuild_waits_for_the_indexer_and_starts_it_through_its_unit(cat, tmp_path):
    """Live on Plasma 6.7: `balooctl6 disable` returned before baloo_file exited (the index was deleted under it), and
    `balooctl6 enable` started it holding the app's captured output, so the app waited 15 s and rolled back."""
    import shutil
    from daprivacyscanner.context import ContextValue
    from daprivacyscanner.fix import Command
    from daprivacyscanner.host import CommandResult
    from fakes import FakeKwriteconfig
    host = make_host(tmp_path, files={"/proc/5/comm": "baloo_file\n"},
                     home_files={".local/share/baloo/index": "x" * 100, ".local/share/baloo/index-lock": ""})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    host.runner.handlers["balooctl6"] = lambda argv: CommandResult(argv, 0, "")
    calls = []

    def systemctl(argv):
        calls.append(argv[1:])
        if argv[2] == "show":
            return CommandResult(argv, 0, "loaded\n")
        if argv[2] == "is-active":
            return CommandResult(argv, 0, "active\n")
        if argv[2] == "stop":
            shutil.rmtree(host.root / "proc/5")
        return CommandResult(argv, 0, "")
    host.runner.handlers["systemctl"] = systemctl
    g = build(cat, host, "desk.indexers", desktop=("kde",), plasma_major=6, fde=ContextValue("fde", "none", [], ""))
    plan = options(g)["Index file names only, and rebuild the index without contents"]
    cmds = [a for a in plan.actions if isinstance(a, Command)]
    assert [c.argv for c in cmds] == [["systemctl", "--user", "stop", "kde-baloo.service"],
                                      ["systemctl", "--user", "start", "kde-baloo.service"]]
    assert cmds[0].wait_gone == "baloo_file" and not cmds[1].check_ok
    log, res = apply(host, plan)
    assert not (host.home / ".local/share/baloo/index").exists()
    assert [c for c in calls if c[1] in ("stop", "start")] == [("--user", "stop", "kde-baloo.service"),
                                                               ("--user", "start", "kde-baloo.service")]
    revert(host, log, res)
    off = options(build(cat, host, "desk.indexers", desktop=("kde",), plasma_major=6,
                        fde=ContextValue("fde", "none", [], "")))
    assert not (host.home / ".local/share/baloo/index").exists()       # nothing to delete: no stop, no wait
    assert "Turn indexing off and delete the index" in off


# ------------------------------------------------------------------ Zeitgeist

def _zeitgeist_host(tmp_path, exits=True):
    from fakes import OK
    host = make_host(tmp_path, files={"/proc/9/comm": "zeitgeist-daemo\n", "/proc/10/comm": "zeitgeist-datah\n"},
                     home_files={".local/share/zeitgeist/activity.sqlite": "x"})
    import shutil

    def stops(pid):
        def run(argv):
            if exits:
                shutil.rmtree(host.root / f"proc/{pid}")
            return OK
        return run
    host.runner.handlers["zeitgeist-daemon"] = stops(9)
    host.runner.handlers["pkill"] = stops(10)
    return host


def test_zeitgeist_stops_the_logger_and_waits_for_the_daemon(cat, tmp_path):
    from daprivacyscanner.fix import Command, WriteFile
    from daprivacyscanner.undo import UndoLog
    from daprivacyscanner.fix import apply_plan
    host = _zeitgeist_host(tmp_path)
    check = load_all()["desk.zeitgeist"](cat["desk.zeitgeist"])
    scan = make_scan(host)
    plan = check.plan_fix(scan, check.detect(scan))
    cmds = [a.argv for a in plan.actions if isinstance(a, Command)]
    assert cmds == [["pkill", "-TERM", "-x", "-u", "1000", "zeitgeist-datah"], ["zeitgeist-daemon", "--quit"]]
    assert all(a.then for a in plan.actions if isinstance(a, WriteFile))          # the bus reads the overrides
    res = apply_plan(plan, host, UndoLog(host.home / ".local/state/daprivacyscanner"), confirmed_irreversible=True)
    assert res.ok and not (host.home / ".local/share/zeitgeist/activity.sqlite").exists()
    assert detect(cat, "desk.zeitgeist", make_scan(host)).status is Status.NOT_APPLICABLE


def test_zeitgeist_log_is_left_when_the_daemon_doesnt_stop(cat, tmp_path, monkeypatch):
    from daprivacyscanner.fix import Command, apply_plan
    from daprivacyscanner.undo import UndoLog
    monkeypatch.setattr(Command, "WAIT", 0.3)
    host = _zeitgeist_host(tmp_path, exits=False)
    check = load_all()["desk.zeitgeist"](cat["desk.zeitgeist"])
    scan = make_scan(host)
    res = apply_plan(check.plan_fix(scan, check.detect(scan)), host, UndoLog(host.home / ".local/state/x"),
                     confirmed_irreversible=True)
    assert not res.ok and "zeitgeist-datah was still running" in res.error
    assert (host.home / ".local/share/zeitgeist/activity.sqlite").exists()
    assert not (host.home / ".local/share/dbus-1/services/org.gnome.zeitgeist.Engine.service").exists()   # rolled back
