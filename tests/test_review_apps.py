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


def test_a_browser_never_used_isnt_said_to_block(cat, tmp_path):
    """Every fresh install: "Your browser blocks ads and trackers." with no profile to look in (live, three machines)."""
    from test_browsers import entry, machine
    host = machine(tmp_path, default="firefox.desktop", files={"/usr/share/applications/firefox.desktop": entry("Firefox")})
    o = detect(cat, "br.content_blocking", make_scan(host))
    assert o.status is Status.NOT_APPLICABLE and o.summary.startswith("Firefox hasn't been used yet")
    assert ev(o)["Firefox"] == "not used yet: no profile"


def test_choosing_a_browser_without_flatpak_installs_it_first(cat, tmp_path):
    from test_browsers import entry, machine
    host = machine(tmp_path, default="google-chrome.desktop",
                   files={"/usr/share/applications/google-chrome.desktop": entry("Google Chrome"),
                          "/etc/os-release": "ID=arch\n"})
    g = _how_to(cat, host, "br.default_browser")
    step = _step(g, "Install one built for privacy")
    assert step.commands[:2] == ["sudo pacman -Syu flatpak",
                                 "flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo"]
    assert "sudo pacman -Syu torbrowser-launcher" in step.text


# ------------------------------------------------------------------ texts

def test_location_without_a_wifi_adapter_says_what_it_sends(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/geoclue/geoclue.conf": "[wifi]\nenable=true\n",
                                      "/sys/class/net/eno1/address": "x", "/sys/class/net/lo/address": "x"})
    o = detect(cat, "tel.location", make_scan(host, desktop=("x-cinnamon",)))
    assert o.status is Status.WARN and "it has no Wi-Fi adapter" in o.summary and "Wi-Fi networks to" not in o.summary
    (host.root / "sys/class/net/wlp2s0/wireless").mkdir(parents=True)
    o = detect(cat, "tel.location", make_scan(host, desktop=("x-cinnamon",)))
    assert "nearby Wi-Fi networks and this computer's internet address" in o.summary

def test_ephemeral_folder_words(cat, tmp_path):
    """The size in words, the unencrypted-swap check named only where it fails, and only the indexers that are here."""
    from conftest import lsblk
    host = make_host(tmp_path, files={"/proc/swaps": "Filename Type Size Used Priority\n/swap.img file 999 0 -2\n",
                                      "/proc/mounts": f"tmpfs {tmp_path}/home/alice/Ephemeral tmpfs "
                                                      "rw,nosuid,nodev,noexec,size=512000k,mode=700 0 0\n"})
    (host.home / "Ephemeral").mkdir()
    scan = make_scan(host, desktop=("x-cinnamon",), devices=lsblk("ubuntu-24.04-luks-lvm.json"))
    o = detect(cat, "desk.ephemeral_folder", scan)
    assert ev(o)["Size"] == "500.0 MB"
    note = next(n for n in o.notes if n.title == "Memory can still reach the disk")
    assert "enc.swap_unencrypted" not in note.text and "enc.swap_unencrypted" not in note.related
    g = load_all()["desk.ephemeral_folder"](cat["desk.ephemeral_folder"]).plan_guide(scan, o)
    assert "Baloo" not in _step(g, "What else records").text and "indexer" not in _step(g, "What else records").text


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


def test_evolution_data_server_alone_isnt_evolution(cat, tmp_path):
    """Mint ships evolution-data-server, which makes ~/.local/share/evolution, without Evolution."""
    host = make_host(tmp_path, home_files={".local/share/evolution/addressbook/system/contacts.db": "x",
                                           ".local/share/evolution/calendar/system/calendar.ics": "x"})
    assert detect(cat, "app.mail_remote_content", make_scan(host)).status is Status.NOT_APPLICABLE
    assert detect(cat, "app.messengers_mail", make_scan(host)).status is Status.NOT_APPLICABLE
    # Evolution's own mail there, its setting unreadable (no schema here): couldn't check, never "blocked"
    (host.home / ".local/share/evolution/mail/local").mkdir(parents=True)
    o = detect(cat, "app.mail_remote_content", make_scan(host))
    assert o.status is Status.UNKNOWN and ev(o)["Evolution"] == "couldn't read its setting"


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


def test_a_thumbnail_cache_set_elsewhere_is_no_easy_fix(cat, tmp_path):
    """With XDG_CACHE_HOME elsewhere the in-memory option could never be applied, yet "Easy fixes (n)" listed it, greyed,
    for as long as the check warned: what closing an app can't clear is said in the step instead."""
    from daprivacyscanner.runner import _easy_left
    cache = tmp_path / "elsewhere"
    host = make_host(tmp_path, env={"XDG_CACHE_HOME": str(cache)})
    (cache / "thumbnails/normal").mkdir(parents=True)
    check = load_all()["desk.thumbnails"](cat["desk.thumbnails"])
    scan = make_scan(host, desktop=("kde",), plasma_major=6)
    o = check.detect(scan)
    assert o.status is Status.WARN
    g = check.plan_guide(scan, o)
    step = _step(g, "Keep the thumbnail cache in memory")
    assert not step.options and "set elsewhere" in step.text
    assert not _easy_left(check, scan, o)


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


# ------------------------------------------------------------------ screenshots

def test_spectacle_saving_to_pictures_counts_no_photos(cat, tmp_path):
    host = make_host(tmp_path, home_files={"Pictures/holiday.jpg": "x", "Pictures/cat.png": "x",
                                           "Pictures/Screenshot_20261017_101010.png": "x"})
    host.home.joinpath(".config").mkdir()
    host.home.joinpath(".config/spectaclerc").write_text(
        f"[ImageSave]\nimageSaveLocation={(host.home / 'Pictures').as_uri()}\n")
    o = detect(cat, "desk.screenshots", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.summary.startswith("1 screenshot or screen recording is kept")
    g = _guide(cat, host, "desk.screenshots", desktop=("kde",), plasma_major=6)
    step = _step(g, "Screenshots saved straight into Pictures")
    assert "Spectacle saves there now" in step.text


# ------------------------------------------------------------------ settings lines in files their apps rewrite

XCU = ('<?xml version="1.0" encoding="UTF-8"?>\n<oor:items xmlns:oor="http://openoffice.org/2001/registry" '
       'xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
       '<item oor:path="/org.openoffice.UserProfile/Data"><prop oor:name="givenname" oor:op="fuse"><value>Alice</value>'
       '</prop></item>\n'
       '<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="RemovePersonalInfoOnSaving" '
       'oor:op="fuse"><value>false</value></prop></item>\n'
       '<item oor:path="/org.openoffice.Office.Common/Misc"><prop oor:name="FirstRun" oor:op="fuse"><value>false</value>'
       '</prop></item>\n</oor:items>\n')


def test_libreoffice_and_gimp_settings_revert_alone_after_the_app_rewrote_its_file(cat, tmp_path):
    """Both apps rewrite the file as they quit: a whole-file backup conflicted with every revert, and forced, wiped
    everything changed since. Only the lines the fix changed are put back."""
    xcu = ".config/libreoffice/4/user/registrymodifications.xcu"
    rc = ".config/GIMP/3.0/gimprc"
    host = make_host(tmp_path, home_files={xcu: XCU, rc: '(theme "Dark")\n\n# end of gimprc\n'})
    g = build(cat, host, "app.shared_file_metadata")
    log1, res1 = apply(host, options(g)["Turn it on"])
    log2, res2 = apply(host, options(g)["Turn them off"])
    assert detect(cat, "app.shared_file_metadata", make_scan(host)).status is Status.PASS
    # the apps quit, rewriting their files with something new in them
    x, r = host.home / xcu, host.home / rc
    x.write_text(x.read_text().replace("</oor:items>", '<item oor:path="/x"><prop oor:name="New" oor:op="fuse">'
                                                       '<value>1</value></prop></item>\n</oor:items>'))
    r.write_text(r.read_text().replace('(theme "Dark")', '(theme "Light")'))
    revert(host, log1, res1)
    revert(host, log2, res2)
    assert x.read_text() == XCU.replace("</oor:items>", '<item oor:path="/x"><prop oor:name="New" oor:op="fuse">'
                                                        '<value>1</value></prop></item>\n</oor:items>')
    assert r.read_text() == '(theme "Light")\n\n# end of gimprc\n'


def test_a_settings_line_changed_back_is_seen_and_a_file_the_fix_made_goes(cat, tmp_path):
    from daprivacyscanner.fix import SettingLines
    rc = ".config/GIMP/2.10/gimprc"
    host = make_host(tmp_path, home_files={".config/GIMP/2.10/.keep": ""})
    g = build(cat, host, "app.shared_file_metadata")
    log, res = apply(host, options(g)["Turn them off"])
    record = log.get(res.entry_id)["records"][0]
    assert SettingLines.changed_back(record, host) is None
    f = host.home / rc
    f.write_text(f.read_text().replace("(export-metadata-exif no)", "(export-metadata-exif yes)"))
    assert "export-metadata-exif" in SettingLines.changed_back(record, host)
    assert "Image Import & Export" in SettingLines.undo_hint(record)
    f.write_text(f.read_text().replace("(export-metadata-exif yes)", "(export-metadata-exif no)"))
    revert(host, log, res)
    assert not f.exists()


# ------------------------------------------------------------------ package repositories, DNF's counter

UBUNTU_SOURCES = ("Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute resolute-updates\n"
                  "Components: main restricted\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
                  "Types: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: resolute-security\n"
                  "Components: main restricted\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n")


def _how_to(cat, host, check_id):
    check = load_all()[check_id](cat[check_id])
    scan = make_scan(host)
    return check.plan_guide(scan, check.detect(scan))


def test_every_http_mirror_of_a_deb822_file_is_found_and_switched(cat, tmp_path):
    files = {"/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES, "/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n"}
    for i in range(8):                  # enough files that the evidence is shortened for the page
        files[f"/etc/apt/sources.list.d/a-long-name-for-a-vendor-repository-{i}.list"] = \
            "deb http://archive.ubuntu.com/ubuntu resolute main\n"
    host = make_host(tmp_path, files=files)
    o = detect(cat, "tel.http_repos", make_scan(host))
    assert set(ev(o)) == {"archive.ubuntu.com", "security.ubuntu.com"}
    g = _how_to(cat, host, "tel.http_repos")
    titles = [s.title for s in g.steps]
    assert len(titles) == len(set(titles)) == 11
    step = _step(g, "Use HTTPS in /etc/apt/sources.list.d/ubuntu.sources")
    assert step.commands == ["sudo sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g' "
                             "/etc/apt/sources.list.d/ubuntu.sources",
                             "sudo sed -i 's|http://security.ubuntu.com|https://security.ubuntu.com|g' "
                             "/etc/apt/sources.list.d/ubuntu.sources"]
    assert all(c.endswith(".list") or c.endswith(".sources") for s in g.steps if s.title.startswith("Use HTTPS")
               for c in s.commands)


def test_mint_sources_go_through_software_sources(cat, tmp_path):
    official = ("deb http://packages.linuxmint.com zena main upstream import backport\n\n"
                "deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse\n")
    host = make_host(tmp_path, files={"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n",
                                      "/etc/apt/sources.list.d/official-package-repositories.list": official,
                                      "/etc/apt/sources.list.d/vendor.list": "deb http://packages.linuxmint.com x main\n"})
    g = _how_to(cat, host, "tel.http_repos")
    cmds = [c for s in g.steps for c in s.commands]
    assert not any("official-package-repositories" in c for c in cmds)              # never edited by hand
    assert not any("https://packages.linuxmint.com" in c for c in cmds)             # it has no HTTPS
    assert "Software Sources" in _step(g, "Linux Mint's own sources").text
    assert "packages.linuxmint.com has no HTTPS" in _step(g, "Use HTTPS in /etc/apt/sources.list.d/vendor.list").text


def test_countme_on_is_rewritten_as_the_check_reads_it(cat, tmp_path, system, monkeypatch):
    from test_fixes import run_fix
    host = rooted(make_host(tmp_path, files={"/etc/yum.repos.d/fedora.repo": "[fedora]\nenabled=1\ncountme=on\n"}),
                  system, monkeypatch)
    plan, res, log = run_fix(cat, host, "tel.countme")
    assert res.ok and detect(cat, "tel.countme", make_scan(host)).status is Status.PASS


def test_a_dotnet_runtime_isnt_the_sdk(cat, tmp_path):
    host = make_host(tmp_path, commands={"dotnet --list-sdks": ""})          # Omarchy: Pinta's dotnet-host
    assert detect(cat, "tel.devtools", make_scan(host)).status is Status.NOT_APPLICABLE


def test_background_callers_on_arch_and_without_a_period(cat, tmp_path):
    from daprivacyscanner.host import CommandResult
    states = {("systemctl", "is-active", "archlinux-keyring-wkd-sync.timer"): "active",
              ("systemctl", "is-enabled", "cachyos-rate-mirrors.timer"): "enabled",
              ("systemctl", "--user", "is-enabled", "arch-update.timer"): "enabled",
              ("systemctl", "is-enabled", "dnf-makecache.timer"): "enabled"}
    host = make_host(tmp_path, commands={k: CommandResult(k, 0, v + "\n") for k, v in states.items()},
                     installed=["systemctl"])
    o = detect(cat, "tel.background_callers", make_scan(host))
    e = ev(o)
    assert {"archlinux-keyring", "cachyos-rate-mirrors", "Arch-Update", "dnf"} <= set(e)
    assert "hourly" not in e["dnf"] and o.summary.startswith("4 services contact servers")
    one = make_host(tmp_path / "1", commands={("systemctl", "is-enabled", "dnf-makecache.timer"): "enabled\n"},
                    installed=["systemctl"])
    assert detect(cat, "tel.background_callers", make_scan(one)).summary.startswith("1 service contacts servers")


# ------------------------------------------------------------------ media players, photo managers

def test_smplayer_recents_are_cleared(cat, tmp_path):
    from test_fixes import run_fix
    ini = ("[%General]\nvolume=50\n\n[history]\nrecents\\1\\filename=/home/alice/Videos/a.mkv\nrecents\\1\\title=\n"
           "recents\\2\\filename=/home/alice/Videos/b.mkv\nrecents\\2\\title=\nrecents\\max_items=10\nrecents\\size=2\n\n"
           "[gui]\nstyle=Fusion\n")
    host = make_host(tmp_path, home_files={".config/smplayer/smplayer.ini": ini})
    plan, res, log = run_fix(cat, host, "app.media_players")
    assert res.ok and [a.kind for a in plan.actions] == ["clear"]
    text = (host.home / ".config/smplayer/smplayer.ini").read_text()
    assert "a.mkv" not in text and "recents\\size=0" in text and "recents\\max_items=10" in text
    assert "volume=50" in text and "style=Fusion" in text
    assert detect(cat, "app.media_players", make_scan(host)).status is Status.PASS


def test_an_empty_gthumb_cache_is_nothing(cat, tmp_path):
    host = make_host(tmp_path, home_files={".cache/gthumb/thumbnails/a.png": "x"})
    o = detect(cat, "app.photo_dbs", make_scan(host))
    assert o.status is Status.FAIL and o.summary == "gThumb keeps thumbnails of the pictures you browsed in its cache."
    apply(host, options(build(cat, host, "app.photo_dbs"))["Delete them"])
    assert detect(cat, "app.photo_dbs", make_scan(host)).status is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ editors

def test_viminfo_and_vim_state_are_cleaned_though_something_has_home_open(cat, tmp_path):
    """Live on Mint: ~/.viminfo was never deleted (its folder, the home, is always in use) and the step showed done;
    ~/.local/state/vim was counted with no way to clean it."""
    host = make_host(tmp_path, home_files={".viminfo": "# history\n", ".local/state/vim/viminfo": "x"},
                     files={"/proc/5/comm": "bash\n"}, links={"/proc/5/cwd": str(tmp_path / "home/alice")})
    g = build(cat, host, "app.editor_residue")
    plan = options(g)["Delete them"]
    assert sorted(a.label for a in plan.actions) == ["Vim history and registers", "Vim state"]
    apply(host, plan)
    assert not (host.home / ".viminfo").exists() and not (host.home / ".local/state/vim/viminfo").exists()
    assert detect(cat, "app.editor_residue", make_scan(host)).status is Status.PASS


def test_viminfo_left_while_vim_runs_says_so(cat, tmp_path):
    host = make_host(tmp_path, home_files={".viminfo": "# history\n"}, files={"/proc/5/comm": "vim\n"})
    step = _step(build(cat, host, "app.editor_residue"), "Delete editor swap")
    assert not step.done and not step.options and "Vim history and registers: close vim first" in step.text


def test_an_xdg_vimrc_is_the_one_changed(cat, tmp_path):
    """Vim 9.1.0327+ reads $XDG_CONFIG_HOME/vim/vimrc when neither ~/.vimrc nor ~/.vim/vimrc exists: a new ~/.vimrc
    would have shadowed the user's whole config."""
    host = make_host(tmp_path, installed=("vim",), home_files={".vim/swap/x.swp": "x", ".config/vim/vimrc": "set number\n"})
    plan = options(build(cat, host, "app.editor_residue"))["Keep Vim's and Neovim's swap and undo files in memory"]
    apply(host, plan)
    assert not (host.home / ".vimrc").exists()
    assert (host.home / ".config/vim/vimrc").read_text().startswith("set number\n\n\" DA Privacy Kit")


def test_no_vim_no_memory_step(cat, tmp_path):
    host = make_host(tmp_path, home_files={".vim/swap/x.swp": "x"})
    g = build(cat, host, "app.editor_residue")
    assert not any(s.title.startswith("Keep swap and undo files") for s in g.steps)


# ------------------------------------------------------------------ CUPS: documents and the job list judged apart

def test_cups_a_days_job_list_without_documents_passes(cat, tmp_path, system, monkeypatch):
    """Live on Mint: after "Keep the job list for a day, not the documents" the check still failed, saying CUPS keeps
    printed documents, and the guide offered both options again."""
    host = rooted(make_host(tmp_path, files={"/etc/cups/cupsd.conf": "LogLevel warn\n"}, installed=["lpstat"]),
                  system, monkeypatch)
    o = detect(cat, "app.cups_spool", make_scan(host))
    assert o.summary == "CUPS keeps copies of the documents you print for a day, and the list of print jobs indefinitely."
    log, res = apply(host, options(build(cat, host, "app.cups_spool"))["Keep the job list for a day, not the documents"])
    o = detect(cat, "app.cups_spool", make_scan(host))
    assert o.status is Status.PASS and o.summary == "CUPS keeps no printed documents, and the list of print jobs for a day."
    revert(host, log, res)


def test_cups_wording_by_what_is_kept(cat, tmp_path):
    for conf, status, summary in (
            ("PreserveJobFiles No\n", Status.FAIL, "CUPS keeps no printed documents, but keeps the list of print jobs, "
                                                   "with their titles, indefinitely."),
            ("PreserveJobFiles No\nPreserveJobHistory 2w\n", Status.WARN,
             "CUPS keeps no printed documents, and the list of print jobs, with their titles, for 2 weeks."),
            ("PreserveJobFiles No\nPreserveJobHistory No\n", Status.PASS,
             "CUPS keeps no printed documents, and no list of print jobs."),
            ("PreserveJobFiles Yes\nPreserveJobHistory No\n", Status.FAIL,
             "CUPS keeps copies of the documents you print indefinitely, and no list of print jobs.")):
        host = make_host(tmp_path / str(len(conf)), files={"/etc/cups/cupsd.conf": conf},
                         commands={"lpstat -W completed -o": ""})
        o = detect(cat, "app.cups_spool", make_scan(host))
        assert (o.status, o.summary) == (status, summary)


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
