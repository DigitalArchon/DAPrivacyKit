"""browsers.yaml as the one registry of browser profile folders, each browser's defaults, and the settings checks
reading every browser it lists (Zen, Waterfox, Floorp, Helium, ungoogled-chromium, Cromite...) or saying which they
didn't."""

import json

import pytest

from daprivacyscanner import browsers
from daprivacyscanner.checks._util import chromium_dirs, mozilla_profiles
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from test_browsers import entry, machine
from test_checks_telemetry_browser import chrome, firefox, pref

PROFILE_CHECKS = ("br.extensions_broad", "br.history_retention", "br.tracking_protection", "br.disk_cache", "br.webrtc",
                  "br.https_only", "br.site_permissions", "br.account_sync", "br.ad_features", "br.vpn_extensions")


# ------------------------------------------------------------------ the data


def test_every_browser_has_a_reader_or_says_why_not():
    data = browsers.load()
    for b in data:
        assert b.folders or b.unchecked, b.id
        assert (b.family in browsers.FAMILIES) == bool(b.folders), b.id
    assert {b.id for b in data if b.unchecked} == {"tor_browser", "mullvad_browser"}
    raw = __import__("yaml").safe_load(browsers.default_path().read_text())
    for b in raw["browsers"]:
        b.pop("profiles", None)
        with pytest.raises(browsers.DataError, match="every browser says where its profiles are"):
            browsers.parse({"schema_version": 1, "browsers": [b]})
        break


@pytest.mark.parametrize("bid", [b.id for b in browsers.load() if b.folders])
def test_every_folder_the_registry_lists_is_read(tmp_path, bid):
    """Made where the registry says, a profile of each browser is found by the readers the checks use, natively and in
    its Flatpak."""
    b = browsers.load()[bid]
    for f in b.folders:
        for flatpak in (False, True):
            host = make_host(tmp_path / f"{f.name}-{flatpak}")
            base = host.home / ".var/app" / f.flatpak if flatpak else host.home
            if flatpak and not f.flatpak:
                continue
            if f.family == "chromium":
                folder = base / ("config" if flatpak else ".config") / f.config
                chrome(host.home, root=str(folder.relative_to(host.home)))
                found = [(d.root.install, d.ids) for d in chromium_dirs(make_scan(host).paths)]
                assert any(i == ("flatpak" if flatpak else "native") and bid in ids for i, ids in found), (f, found)
            else:
                rel = f.home or f".config/{f.config}"
                if flatpak:
                    rel = f.home or f"config/{f.config}"
                firefox(base, root=rel)
                apps = [p.app for p in mozilla_profiles(host, make_scan(host).paths, browsers.family_names("mozilla"))]
                assert apps == [f.name], (f, apps)


def test_defaults_inherit_and_unknown_is_never_upstreams():
    data = browsers.load()
    assert data.default("librewolf", "browser.cache.disk.enable") is False
    assert data.default("zen", "browser.cache.disk.enable") is True             # verified: Zen inherits Firefox's
    assert data.default("waterfox", "network.trr.mode") == 2
    assert data.default("chrome", "history_days") == 90
    assert data.default("edge", "search.suggest_enabled") is browsers.UNKNOWN   # no table: never Chromium's assumed


# ------------------------------------------------------------------ the forks are read


def test_a_zen_user_is_judged_on_zen_not_told_no_profiles(cat, tmp_path):
    """The browsers the app recommends: their profiles are read by every settings check (they were all "No browser
    profiles were found")."""
    host = make_host(tmp_path)
    firefox(host.home, root=".zen", prefs=pref("browser.contentblocking.category", "strict"))
    scan = make_scan(host)
    for check in PROFILE_CHECKS:
        o = detect(cat, check, scan)
        assert o.status is not Status.NOT_APPLICABLE, (check, o.summary)
        assert any(k.startswith("Zen profile") for k in ev(o)) or check in ("br.extensions_broad", "br.vpn_extensions"), \
            (check, ev(o))
    o = detect(cat, "br.tracking_protection", scan)
    assert o.status is Status.PASS and ev(o)["Zen profile abcd.default-release"] == "Enhanced Tracking Protection: strict"


def test_zen_in_its_xdg_folder_and_its_flatpak(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, root=".config/zen", name="a.Default (release)")
    firefox(host.home / ".var/app/app.zen_browser.zen", root=".zen", name="b.default")
    labels = set(ev(detect(cat, "br.disk_cache", make_scan(host))))
    assert {"Zen profile a.Default (release)", "Zen profile b.default, flatpak"} <= labels


def test_librewolf_is_judged_by_its_own_defaults(cat, tmp_path):
    """LibreWolf ships with the disk cache off (librewolf.cfg), so a profile that doesn't set it keeps no cache on the
    disk; its history is kept (it clears cookies, not history, as it closes)."""
    host = make_host(tmp_path)
    firefox(host.home, root=".librewolf", prefs=pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3", True))
    scan = make_scan(host)
    o = detect(cat, "br.disk_cache", scan)
    assert o.status is Status.PASS, (o.summary, ev(o))
    assert "disk cache off" in ev(o)["LibreWolf profile abcd.default-release"]
    assert ev(detect(cat, "br.history_retention", scan))["LibreWolf profile abcd.default-release"] == "kept until you clear it"
    assert detect(cat, "br.https_only", scan).status is Status.PASS


def test_firefox_policies_are_not_applied_to_its_flatpak_or_librewolf(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/firefox/policies/policies.json": json.dumps(
        {"policies": {"HttpsOnlyMode": "force_enabled", "SanitizeOnShutdown": True}})})
    firefox(host.home / ".var/app/org.mozilla.firefox", root=".mozilla/firefox")
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Firefox profile abcd.default-release, flatpak"] == "HTTPS-Only Mode off"
    host2 = make_host(tmp_path / "native", files={"/etc/firefox/policies/policies.json": json.dumps(
        {"policies": {"HttpsOnlyMode": "force_enabled"}})})
    firefox(host2.home)
    assert detect(cat, "br.https_only", make_scan(host2)).status is Status.PASS


def test_helium_and_ungoogled_chromiums_flatpak_are_read(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, root=".config/net.imput.helium")
    chrome(host.home, root=".var/app/io.github.ungoogled_software.ungoogled_chromium/config/chromium")
    o = detect(cat, "br.webrtc", make_scan(host))
    assert ev(o)["Helium, Default"] == "default_public_interface_only"
    assert ev(o)["ungoogled-chromium, flatpak, Default"] == "disable_non_proxied_udp"


def test_cromite_in_chromiums_folder_goes_by_what_is_installed(cat, tmp_path):
    """Chromium, ungoogled-chromium and Cromite share ~/.config/chromium: with only Cromite installed, its defaults
    (strict HTTPS) are the ones in force; with Chromium too, a default they don't share can't be told."""
    host = machine(tmp_path, files={"/usr/share/applications/cromite.desktop": entry("Cromite")})
    prof = chrome(host.home, root=".config/chromium")
    (prof.parent / "Last Version").write_text("153.0.8010.37")
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.PASS and ev(o)["Chromium, Default"].startswith("Always use secure connections: on")
    (host.root / "usr/share/applications/chromium.desktop").write_text(entry("Chromium"))
    assert detect(cat, "br.https_only", make_scan(host)).status is Status.UNKNOWN


# ------------------------------------------------------------------ what isn't read is said


def test_an_installed_browser_the_app_doesnt_know_is_named_never_silent(cat, tmp_path):
    host = machine(tmp_path, files={"/usr/share/applications/org.kde.falkon.desktop": entry("Falkon")})
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.UNKNOWN and "Falkon" in o.summary
    firefox(host.home, prefs=pref("dom.security.https_only_mode", True))
    o = detect(cat, "br.https_only", make_scan(host))
    assert o.status is Status.PASS and o.partial
    assert any(n.title.startswith("Not checked") and "Falkon" in n.text for n in o.notes)


def test_an_installed_browser_not_used_yet_is_said(cat, tmp_path):
    host = machine(tmp_path, files={"/usr/share/applications/zen.desktop": entry("Zen")})
    firefox(host.home, prefs=pref("dom.security.https_only_mode", True))
    o = detect(cat, "br.https_only", make_scan(host))
    note = next(n for n in o.notes if n.title == "Not used yet")
    assert "Zen (~/.zen, ~/.config/zen)" in note.text and not o.partial


def test_tor_browser_is_said_not_read(cat, tmp_path):
    host = machine(tmp_path, files={"/usr/share/applications/torbrowser.desktop": entry("Tor Browser")})
    o = detect(cat, "br.disk_cache", make_scan(host))
    assert o.status is Status.NOT_APPLICABLE and any(n.title == "Tor Browser isn't read" for n in o.notes)


# ------------------------------------------------------------------ the facts


@pytest.mark.parametrize("version, prefs, status", [
    ("157.0.8103.78", {}, Status.PASS),          # on for public sites by default from 157
    ("155.0.8059.39", {}, Status.UNKNOWN),       # Google's field trials: on for some people
    ("150.0.1", {}, Status.FAIL),
    ("157.0.8103.78", {"https_first_balanced_mode_enabled": False}, Status.FAIL),   # turned off
    (None, {}, Status.UNKNOWN),                  # which version ran can't be read
], ids=["157", "trial", "old", "turned-off", "no-version"])
def test_chrome_https_by_default(cat, tmp_path, version, prefs, status):
    host = make_host(tmp_path)
    prof = chrome(host.home, prefs=prefs)
    if version:
        (prof.parent / "Last Version").write_text(version)
    assert detect(cat, "br.https_only", make_scan(host)).status is status


def test_edge_https_without_a_setting_is_unknown_not_upstreams(cat, tmp_path):
    host = make_host(tmp_path)
    prof = chrome(host.home, root=".config/microsoft-edge")
    (prof.parent / "Last Version").write_text("157.0.1")
    assert detect(cat, "br.https_only", make_scan(host)).status is Status.UNKNOWN


@pytest.mark.parametrize("prefs, state", [
    ({"sync": {"has_setup_completed": True, "cached_passphrase_type": 2}}, "readable"),       # keystore: Google holds it
    ({"sync": {"has_setup_completed": True, "cached_passphrase_type": 4}}, "passphrase"),     # custom
    ({"sync": {"has_setup_completed": True, "cached_passphrase_type": 3}}, "passphrase"),     # frozen implicit
    ({"sync": {"has_setup_completed": True, "passphrase_type": 2}}, "readable"),              # no such pref
    ({"sync": {"has_setup_completed": True, "encryption_bootstrap_token": "x"}}, "readable"),  # obsolete, any kind
    ({"account_info": [{"x": 1}]}, "account"),                # signed in without sync: passwords etc. in the account
    ({"account_info": [{"x": 1}], "sync": {"selected_types_per_account": {"h": {
        "passwords": False, "autofill": False, "payments": False}}}}, "off"),
], ids=["keystore", "custom", "frozen", "old-pref", "old-token", "signed-in", "account-types-off"])
def test_chrome_sync_states(tmp_path, prefs, state):
    from daprivacyscanner.checks.browser import sync_states
    host = make_host(tmp_path)
    chrome(host.home, prefs=prefs)
    assert [s.state for s in sync_states(make_scan(host))] == [state]


def test_chrome_signed_in_without_sync_is_a_problem_and_edge_unknown(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, prefs={"account_info": [{"x": 1}]})
    o = detect(cat, "br.account_sync", make_scan(host))
    assert o.status is Status.FAIL and "kept in the Google Account" in ev(o)["Google Chrome, Default"]
    host = make_host(tmp_path / "edge")
    chrome(host.home, prefs={"account_info": [{"x": 1}]}, root=".config/microsoft-edge")
    assert detect(cat, "br.account_sync", make_scan(host)).status is Status.UNKNOWN


def test_make_searches_better_counts_and_suggest_online_is_a_default(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, prefs={"url_keyed_anonymized_data_collection": {"enabled": True}, "search": {"suggest_enabled": False}})
    o = detect(cat, "br.ad_features", make_scan(host))
    assert o.status is Status.FAIL and "the address of every page you visit" in ev(o)["Google Chrome, Default"]
    host = make_host(tmp_path / "ff")
    firefox(host.home, prefs=pref("browser.search.suggest.enabled", False))
    o = detect(cat, "br.ad_features", make_scan(host))
    assert o.status is Status.PASS and "sent to Mozilla for suggestions (browser default in some countries)" in \
        ev(o)["Firefox profile abcd.default-release"]
    host = make_host(tmp_path / "zen")
    firefox(host.home, root=".zen")
    o = detect(cat, "br.ad_features", make_scan(host))      # Zen ships search suggestions and Suggest off
    assert o.status is Status.PASS and "search suggestions" not in ev(o)["Zen profile abcd.default-release"]


def test_history_brave_clears_on_exit_and_chromium_keeps_90_days(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, root=".config/BraveSoftware/Brave-Browser", prefs={"browser": {"clear_data": {
        "browsing_history_on_exit": True, "cookies_on_exit": True}}})
    o = detect(cat, "br.history_retention", make_scan(host))
    assert o.status is Status.PASS and ev(o)["Brave, Default"].startswith("history, cookies and site data cleared")
    chrome(host.home)
    o = detect(cat, "br.history_retention", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Google Chrome, Default"] == \
        "history kept for 90 days, cookies and site data until they expire"
    assert "kept indefinitely" not in o.summary


@pytest.mark.parametrize("ext_id, name, status", [
    ("adguardadblocker@adguard.com", "AdGuard AdBlocker", Status.PASS),
    ("firefox@ghostery.com", "Ghostery Tracker & Ad Blocker", Status.PASS),
    ("{d10d0bf8-f5b5-c8b4-a8b2-2b3a1b6b0cc0}", "Adblock Plus - free ad blocker", Status.WARN),
    ("x@y", "Some Other Helper", Status.FAIL),
])
def test_other_blockers_are_named_not_called_none(cat, tmp_path, ext_id, name, status):
    host = machine(tmp_path, default="firefox.desktop", files={"/usr/share/applications/firefox.desktop": entry("Firefox")})
    firefox(host.home, extensions=[{"id": ext_id, "type": "extension", "active": True, "location": "app-profile",
                                    "defaultLocale": {"name": name}, "userPermissions": {"origins": ["<all_urls>"]}}])
    o = detect(cat, "br.content_blocking", make_scan(host))
    assert o.status is status, o.summary
    assert "blocks no ads" not in o.summary
