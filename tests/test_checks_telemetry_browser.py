import json
import struct
import zlib

import pytest

from daprivacyscanner.checks._util import png_text, strip_jsonc
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan

# ------------------------------------------------------------------ helpers


def firefox(home, prefs="", name="abcd.default-release", extensions=None, root=".mozilla/firefox"):
    r = home / root
    prof = r / name
    prof.mkdir(parents=True, exist_ok=True)
    (r / "profiles.ini").write_text(f"[Profile0]\nName=default\nIsRelative=1\nPath={name}\n")
    (prof / "prefs.js").write_text(prefs)
    if extensions is not None:
        (prof / "extensions.json").write_text(json.dumps({"addons": extensions}))
    return prof


def chrome(home, prefs=None, local_state=None, root=".config/google-chrome"):
    prof = home / root / "Default"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "Preferences").write_text(json.dumps(prefs or {}))
    if local_state is not None:
        (home / root / "Local State").write_text(json.dumps(local_state))
    return prof


def pref(name, value):
    return f'user_pref("{name}", {json.dumps(value)});\n'


def png(uri: str) -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"tEXt", b"Thumb::URI\0" + uri.encode()) + chunk(b"IDAT", zlib.compress(b"\0\0\0\0"))
            + chunk(b"IEND", b""))


def test_png_text():
    assert png_text(png("file:///home/alice/a%20b.jpg")) == {"Thumb::URI": "file:///home/alice/a%20b.jpg"}
    assert png_text(b"GIF89a") == {}


def test_strip_jsonc():
    text = '{\n // comment\n "a": "http://x//y", /* block */ "b": [1, 2,],\n}'
    assert json.loads(strip_jsonc(text)) == {"a": "http://x//y", "b": [1, 2]}


# ------------------------------------------------------------------ telemetry

@pytest.mark.parametrize("files, commands, status", [
    ({"/etc/default/apport": "enabled=1\n"}, {}, Status.FAIL),
    ({"/etc/default/apport": "enabled=0\n"}, {}, Status.PASS),
    ({}, {"systemctl is-enabled whoopsie": "enabled\n"}, Status.FAIL),
    ({"/etc/popularity-contest.conf": 'PARTICIPATE="yes"\n'}, {}, Status.FAIL),
    ({"/etc/abrt/abrt.conf": "AutoreportingEnabled = yes\n"}, {"systemctl is-enabled abrtd": "enabled\n"}, Status.FAIL),
    ({}, {}, Status.PASS),
])
def test_crash_reporters(cat, tmp_path, files, commands, status):
    host = make_host(tmp_path, files=files, commands=commands, installed=["systemctl"])
    assert detect(cat, "tel.crash_reporters", make_scan(host)).status is status


def test_location(cat, tmp_path):
    host = make_host(tmp_path, commands={"gsettings get org.gnome.system.location enabled": "true\n"},
                     files={"/etc/geoclue/geoclue.conf": "[wifi]\nenable=true\nurl=https://api.beacondb.net/v1/geolocate\n"})
    o = detect(cat, "tel.location", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["GeoClue Wi-Fi lookup"] == "on, via api.beacondb.net"
    assert detect(cat, "tel.location", make_scan(host, desktop=("kde",))).status is Status.WARN
    assert detect(cat, "tel.location", make_scan(make_host(tmp_path / "n"), desktop=("kde",))).status is Status.NOT_APPLICABLE


def test_browser_telemetry_firefox_defaults_and_policy(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home)
    o = detect(cat, "tel.browser_telemetry", make_scan(host))
    assert o.status is Status.FAIL and "telemetry, studies, the daily usage ping on" in ev(o).values()
    # the daily usage ping is a switch of its own (Firefox 157): off in the profile, the rest still counts
    firefox(host.home, prefs=pref("datareporting.healthreport.uploadEnabled", False) +
            pref("app.shield.optoutstudies.enabled", False))
    o = detect(cat, "tel.browser_telemetry", make_scan(host))
    assert o.status is Status.FAIL and "the daily usage ping on" in ev(o).values()
    firefox(host.home)
    host.sys_path("/etc/firefox/policies").mkdir(parents=True)
    host.sys_path("/etc/firefox/policies/policies.json").write_text(json.dumps(
        {"policies": {"DisableTelemetry": True, "DisableFirefoxStudies": True}}))
    assert detect(cat, "tel.browser_telemetry", make_scan(host)).status is Status.PASS


def test_browser_telemetry_chrome_and_brave(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, local_state={"user_experience_metrics": {"reporting_enabled": False}})
    assert detect(cat, "tel.browser_telemetry", make_scan(host)).status is Status.PASS
    chrome(host.home, local_state={}, root=".config/BraveSoftware/Brave-Browser")
    o = detect(cat, "tel.browser_telemetry", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Brave"] == "P3A analytics, daily usage ping on"


SDK = "10.0.100 [/usr/share/dotnet/sdk]\n"


def test_devtools(cat, tmp_path):
    # an SDK lists itself; the runtime alone doesn't count (the review of 2026-10-17)
    host = make_host(tmp_path, home_files={".config/Code/User/settings.json": '{\n  // mine\n  "editor.tabSize": 2,\n}'},
                     commands={"dotnet --list-sdks": SDK})
    o = detect(cat, "tel.devtools", make_scan(host))
    assert o.status is Status.FAIL and "VS Code" in o.summary and ".NET SDK" in o.summary
    host = make_host(tmp_path / "b", commands={"dotnet --list-sdks": SDK},
                     home_files={".config/Code/User/settings.json": '{"telemetry.telemetryLevel": "off"}',
                                 ".config/environment.d/50-telemetry.conf": "DOTNET_CLI_TELEMETRY_OPTOUT=1\n"})
    assert detect(cat, "tel.devtools", make_scan(host)).status is Status.PASS


def test_http_repos(cat, tmp_path):
    host = make_host(tmp_path, files={
        "/etc/apt/sources.list": "deb http://deb.debian.org/debian trixie main\n# deb http://old.example/ x\n",
        "/etc/apt/sources.list.d/vendor.sources": "Types: deb\nURIs: https://repo.vendor.com/apt\nSuites: stable\n",
        "/etc/apt/sources.list.d/other.list": "deb [arch=amd64 signed-by=/k.gpg] http://ppa.example.org/x noble main\n"})
    o = detect(cat, "tel.http_repos", make_scan(host))
    assert o.status is Status.FAIL and set(ev(o)) == {"deb.debian.org", "ppa.example.org"}
    host = make_host(tmp_path / "f", files={"/etc/yum.repos.d/fedora.repo": "[fedora]\nmetalink=https://mirrors.fedoraproject.org/x\n"})
    assert detect(cat, "tel.http_repos", make_scan(host)).status is Status.PASS


def test_http_repos_reads_the_mirror_lists_pacman_includes_and_leaves_onion_mirrors(cat, tmp_path):
    """CachyOS's and Chaotic-AUR's sections include mirror lists of their own, which were never read; and apt's
    tor+http://….onion (Debian's onion mirrors) was taken for plain HTTP, though Tor encrypts it end to end."""
    conf = ("[options]\nArchitecture = auto\n\n[cachyos-v3]\nInclude = /etc/pacman.d/cachyos-v3-mirrorlist\n\n"
            "[core]\nInclude = /etc/pacman.d/mirrorlist\n\n#[testing]\n#Include = /etc/pacman.d/testing-mirrorlist\n\n"
            "[chaotic-aur]\nInclude = /etc/pacman.d/chaotic-*\n")
    host = make_host(tmp_path, files={
        "/etc/pacman.conf": conf,
        "/etc/pacman.d/mirrorlist": "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n",
        "/etc/pacman.d/cachyos-v3-mirrorlist": "Server = http://mirror.cachyos.example/repo/$arch_v3/$repo\n",
        "/etc/pacman.d/chaotic-mirrorlist": "#Server = http://old.example/$repo\nServer = http://chaotic.example/x\n",
        "/etc/pacman.d/testing-mirrorlist": "Server = http://testing.example/$repo/os/$arch\n"})
    o = detect(cat, "tel.http_repos", make_scan(host))
    assert o.status is Status.FAIL and set(ev(o)) == {"mirror.cachyos.example", "chaotic.example"}
    onion = "deb tor+http://2s4yqjx5ul6okpp3f2gaunr2syex5jgbfpfvhxxbbjwnrsvbk5v3qbid.onion/debian trixie main\n"
    host = make_host(tmp_path / "d", files={"/etc/apt/sources.list": onion})
    assert detect(cat, "tel.http_repos", make_scan(host)).status is Status.PASS
    clearnet = "deb tor+http://deb.debian.org/debian trixie main\n"                 # plain past Tor's exit
    host = make_host(tmp_path / "e", files={"/etc/apt/sources.list": clearnet})
    assert set(ev(detect(cat, "tel.http_repos", make_scan(host)))) == {"deb.debian.org"}


def test_countme(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/yum.repos.d/fedora.repo": "[fedora]\nenabled=1\ncountme=1\n\n[fedora-debuginfo]\n"
                                                                     "enabled=0\ncountme=1\n"})
    o = detect(cat, "tel.countme", make_scan(host))
    assert o.status is Status.FAIL and ev(o) == {"countme=1": "fedora"}
    assert detect(cat, "tel.countme", make_scan(make_host(tmp_path / "d"))).status is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ browsers

def test_crashpad(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/chromium/Crash Reports/settings.dat": "x"})
    chrome(host.home, root=".config/chromium")
    assert detect(cat, "br.crashpad_dumps", make_scan(host)).status is Status.PASS
    (host.home / ".config/chromium/Crash Reports/pending").mkdir()
    (host.home / ".config/chromium/Crash Reports/pending/abc.dmp").write_text("x")
    assert detect(cat, "br.crashpad_dumps", make_scan(host)).status is Status.FAIL


def test_extensions(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, extensions=[
        {"id": "ublock@x", "type": "extension", "active": True, "location": "app-profile",
         "defaultLocale": {"name": "uBlock Origin"}, "userPermissions": {"origins": ["<all_urls>"]}},
        {"id": "screenshots@mozilla.org", "type": "extension", "active": True, "location": "app-builtin",
         "userPermissions": {"origins": ["<all_urls>"]}},
        {"id": "dict", "type": "dictionary", "active": True, "location": "app-profile"}])
    prof = chrome(host.home)
    ext = prof / "Extensions/abcdef/1.2.3_0"
    (ext / "_locales/en").mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({"name": "__MSG_appName__", "default_locale": "en",
                                                   "content_scripts": [{"matches": ["https://*/*"]}]}))
    (ext / "_locales/en/messages.json").write_text(json.dumps({"appName": {"message": "Grammar Helper"}}))
    o = detect(cat, "br.extensions_broad", make_scan(host))
    assert o.status is Status.FAIL and set(ev(o)) == {"uBlock Origin", "Grammar Helper"}


def test_extensions_skip_firefox_own_and_count_granted_mv3(cat, tmp_path):
    """Firefox 1xx's built-in add-ons (app-builtin-addons, or updated into the profile signed by
    Mozilla) aren't the user's; an MV3 extension's access to all sites is an optional permission,
    counted only while it is granted (extension-preferences.json)."""
    host = make_host(tmp_path)
    mv3 = lambda i, name: {"id": i, "type": "extension", "active": True, "location": "app-profile",  # noqa: E731
                           "manifestVersion": 3, "defaultLocale": {"name": name},
                           "optionalPermissions": {"origins": ["<all_urls>"]},
                           "requestedPermissions": {"origins": ["<all_urls>"]}}
    prof = firefox(host.home, extensions=[
        {"id": "webcompat@mozilla.org", "type": "extension", "active": True, "location": "app-builtin-addons",
         "userPermissions": {"origins": ["<all_urls>"]}},
        {"id": "newtab@mozilla.org", "type": "extension", "active": True, "location": "app-profile", "signedState": 3,
         "userPermissions": {"origins": ["<all_urls>"]}},
        mv3("granted@x", "Granted"), mv3("revoked@x", "Revoked")])
    (prof / "extension-preferences.json").write_text(json.dumps({
        "granted@x": {"permissions": ["<all_urls>"], "origins": ["<all_urls>"]},
        "revoked@x": {"permissions": [], "origins": []}}))
    o = detect(cat, "br.extensions_broad", make_scan(host))
    assert o.status is Status.FAIL and set(ev(o)) == {"Granted"}


def test_extensions_skip_disabled_and_limited_chromium(cat, tmp_path):
    host = make_host(tmp_path)
    ids = {"disabled": "a" * 32, "onclick": "b" * 32, "component": "c" * 32, "open": "d" * 32}
    prof = chrome(host.home, prefs={"extensions": {"settings": {
        ids["disabled"]: {"disable_reasons": [1]}, ids["onclick"]: {"withholding_permissions": True},
        ids["component"]: {"location": 10}}}})
    for name, i in ids.items():
        ext = prof / "Extensions" / i / "1.0_0"
        ext.mkdir(parents=True)
        (ext / "manifest.json").write_text(json.dumps({"name": name, "host_permissions": ["<all_urls>"]}))
    (prof / "Secure Preferences").write_text(json.dumps({"extensions": {"settings": {ids["open"]: {"location": 1}}}}))
    o = detect(cat, "br.extensions_broad", make_scan(host))
    assert o.status is Status.FAIL and set(ev(o)) == {"open"}


def test_history_retention(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("privacy.sanitize.sanitizeOnShutdown", True))
    assert detect(cat, "br.history_retention", make_scan(host)).status is Status.PASS
    chrome(host.home, prefs={"profile": {"default_content_setting_values": {"cookies": 4}}})
    o = detect(cat, "br.history_retention", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Google Chrome, Default"].startswith("cookies cleared")


MIGRATED3 = pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3", True)
MIGRATED2 = pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs2", True)


@pytest.mark.parametrize("prefs, state", [
    # what "Delete cookies and site data when Firefox is closed" leaves (privacy.mjs: resetCleaningPrefs): history kept,
    # though the old prefs the check read, at their defaults, said it was cleared
    (MIGRATED3 + pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", False), "kept until you clear it"),
    (MIGRATED3, "cleared when it closes"),
    (MIGRATED3 + pref("privacy.clearOnShutdown.history", False), "cleared when it closes"),     # migrated from
    (MIGRATED2 + pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", False), "kept until you clear it"),
    (MIGRATED2 + pref("privacy.clearOnShutdown.history", False), "cleared when it closes"),
    (pref("privacy.clearOnShutdown.history", False), "kept until you clear it"),                  # the old dialog's, before migrating
], ids=["v3-off", "v3-default", "v3-old-off", "v2-off", "v2-old-off", "v1-off"])
def test_firefox_history_is_judged_by_the_pref_its_shutdown_sanitizer_reads(cat, tmp_path, prefs, state):
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("privacy.sanitize.sanitizeOnShutdown", True) + prefs)
    assert ev(detect(cat, "br.history_retention", make_scan(host)))["Firefox profile abcd.default-release"] == state


@pytest.mark.parametrize("prefs, status", [
    ("", Status.FAIL), (pref("browser.contentblocking.category", "strict"), Status.PASS),
    (pref("browser.contentblocking.category", "custom"), Status.WARN),
])
def test_tracking_protection_firefox(cat, tmp_path, prefs, status):
    host = make_host(tmp_path)
    firefox(host.home, prefs=prefs)
    assert detect(cat, "br.tracking_protection", make_scan(host)).status is status


def test_tracking_protection_chromium(cat, tmp_path):
    host = make_host(tmp_path)
    chrome(host.home, prefs={"profile": {"cookie_controls_mode": 1}})
    assert detect(cat, "br.tracking_protection", make_scan(host)).status is Status.PASS
    chrome(host.home, prefs={}, root=".config/microsoft-edge")
    assert detect(cat, "br.tracking_protection", make_scan(host)).status is Status.FAIL


def test_private_download_leak(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/user-dirs.dirs": 'XDG_DOWNLOAD_DIR="$HOME/Téléchargements"\n',
                                           "Téléchargements/report.pdf": "x"})
    dl = host.home / "Téléchargements"
    (host.home / ".local/share").mkdir(parents=True, exist_ok=True)
    (host.home / ".local/share/recently-used.xbel").write_text(
        f'<xbel><bookmark href="file://{dl.as_uri()[7:]}/report.pdf" added="x"/>'
        f'<bookmark href="file:///etc/hosts"/></xbel>')
    thumbs = host.home / ".cache/thumbnails/normal"
    thumbs.mkdir(parents=True)
    (thumbs / "abc.png").write_bytes(png((dl / "report.pdf").as_uri()))
    o = detect(cat, "br.private_download_leak", make_scan(host))
    assert o.status is Status.FAIL
    assert ev(o)["Downloads in the recent files list"] == 1 and ev(o)["Thumbnails of downloads"] == 1


def test_disk_cache(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("browser.cache.disk.enable", False))
    assert detect(cat, "br.disk_cache", make_scan(host)).status is Status.PASS
    chrome(host.home)
    assert detect(cat, "br.disk_cache", make_scan(host)).status is Status.FAIL
    # profile-sync-daemon writes profiles back to the disk and leaves ~/.cache alone: it doesn't count
    host.runner.outputs[("systemctl", "--user", "is-active", "psd")] = __import__(
        "daprivacyscanner.host", fromlist=["CommandResult"]).CommandResult((), 0, "active\n")
    assert detect(cat, "br.disk_cache", make_scan(host)).status is Status.FAIL


@pytest.mark.parametrize("root, cache", [
    (".mozilla/firefox", ".cache/mozilla/firefox/abcd.default-release/cache2"),
    (".config/mozilla/firefox", ".cache/mozilla/firefox/abcd.default-release/cache2"),          # Firefox 147+
    (".librewolf", ".cache/librewolf/abcd.default-release/cache2"),
    (".var/app/org.mozilla.firefox/.mozilla/firefox", ".var/app/org.mozilla.firefox/cache/mozilla/firefox/abcd.default-release/cache2"),
    ("snap/firefox/common/.mozilla/firefox", "snap/firefox/common/.cache/mozilla/firefox/abcd.default-release/cache2"),
])
def test_disk_cache_off_but_the_old_one_left(cat, tmp_path, root, cache):
    """Turning the disk cache off leaves the cache already there: not a pass until it is gone, for every
    kind of install; the guide deletes it."""
    from test_guides import build
    host = make_host(tmp_path)
    if root.startswith("snap/"):
        (host.home / "snap/firefox/common").mkdir(parents=True)
    firefox(host.home, prefs=pref("browser.cache.disk.enable", False), root=root)
    entry = host.home / cache / "entries" / "ABC"
    entry.parent.mkdir(parents=True)
    entry.write_text("x")
    o = detect(cat, "br.disk_cache", make_scan(host))
    assert o.status is Status.FAIL and "old one is still on the disk" in o.summary, o.summary
    g = build(cat, host, "br.disk_cache")
    plan = next(o.plan for st in g.steps for o in st.options if o.label == "Delete it")
    assert any(entry in a.files for a in plan.actions)
    entry.unlink()
    o = detect(cat, "br.disk_cache", make_scan(host))
    assert o.status is Status.PASS and "session store is still written" in o.summary


def test_webrtc(cat, tmp_path):
    """Stock browsers show websites mDNS names, not local addresses, until a site is allowed the camera or microphone
    (Chromium's kWebRtcHideLocalIpsWithMdns, Firefox's obfuscate_host_addresses): only a profile set to show them, or
    one going around the proxy it was given, is a problem."""
    host = make_host(tmp_path)
    firefox(host.home, prefs=pref("media.peerconnection.ice.default_address_only", True))
    chrome(host.home, prefs={"webrtc": {"ip_handling_policy": "disable_non_proxied_udp"}})
    assert detect(cat, "br.webrtc", make_scan(host)).status is Status.PASS
    chrome(host.home, prefs={}, root=".config/vivaldi")
    o = detect(cat, "br.webrtc", make_scan(host))
    assert o.status is Status.PASS and ev(o)["Vivaldi, Default"] == "not set: the browser's own default"
    chrome(host.home, prefs={"webrtc": {"ip_handling_policy": "default_public_and_private_interfaces"}}, root=".config/vivaldi")
    assert detect(cat, "br.webrtc", make_scan(host)).status is Status.FAIL


@pytest.mark.parametrize("prefs, status", [
    ("", Status.PASS),
    (pref("media.peerconnection.ice.obfuscate_host_addresses", False), Status.FAIL),
    (pref("network.proxy.type", 1) + pref("network.proxy.socks", "10.64.0.1"), Status.FAIL),
    (pref("network.proxy.type", 1) + pref("network.proxy.socks", "10.64.0.1")
     + pref("media.peerconnection.ice.proxy_only_if_behind_proxy", True), Status.PASS),
    (pref("media.peerconnection.enabled", False) + pref("media.peerconnection.ice.obfuscate_host_addresses", False),
     Status.PASS),
], ids=["stock", "shows-local", "around-proxy", "kept-to-proxy", "off"])
def test_firefox_webrtc(cat, tmp_path, prefs, status):
    host = make_host(tmp_path)
    firefox(host.home, prefs=prefs)
    assert detect(cat, "br.webrtc", make_scan(host)).status is status


def test_flatpak_and_snap_browsers_are_found(cat, tmp_path):
    host = make_host(tmp_path)
    firefox(host.home, root=".var/app/org.mozilla.firefox/.mozilla/firefox")
    chrome(host.home, root="snap/chromium/common/chromium")
    o = detect(cat, "br.tracking_protection", make_scan(host))
    assert {"Firefox profile abcd.default-release, flatpak", "Chromium, snap, Default"} <= set(ev(o))


def test_no_browsers(cat, tmp_path):
    for check in ("br.extensions_broad", "br.history_retention", "br.webrtc", "br.disk_cache"):
        assert detect(cat, check, make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE
