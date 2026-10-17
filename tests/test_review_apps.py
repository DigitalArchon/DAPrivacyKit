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
