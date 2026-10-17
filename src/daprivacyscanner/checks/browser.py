"""Browsers (br.*). Firefox-family profiles come from profiles.ini, Chromium-family ones from each
browser's user data directory, native, Flatpak and Snap alike."""

from __future__ import annotations

import html
import os
import re
from dataclasses import dataclass
from pathlib import Path

from ..model import Evidence, Note, Outcome
from . import Check, Scan, register
from ._util import (BrowserDir, MozProfile, Tally, absent, children, chromium_dirs, chromium_policies, chromium_profiles,
                    dig, failed, firefox_policies, firefox_prefs, isdir, isfile, mozilla_cache, mozilla_profiles, passed, read_json,
                    read_text, recent_files, recent_hrefs, tally, thumbnail_uris, unknown, uri_path, warned, xdg_user_dir)

# Firefox's own add-ons; user-installed ones are in "app-profile". Firefox 1xx keeps its built-in
# ones in "app-builtin-addons" and updates some into the profile, signed by Mozilla as privileged or
# system add-ons (signedState 3 and 4).
BUILTIN_LOCATIONS = frozenset({"app-builtin", "app-builtin-addons", "app-system-defaults", "app-system-addons",
                               "app-temporary"})
MOZILLA_SIGNED = frozenset({3, 4})
# installed for every account, by a package (or, app-system-user, for all of one account's profiles)
SYSTEM_LOCATIONS = frozenset({"app-system-share", "app-system-local", "app-global", "app-system-user"})
# Chromium's ManifestLocation: component extensions are the browser's own; policy ones can't be removed
CHROMIUM_BUILTIN = frozenset({5, 10})
CHROMIUM_POLICY = frozenset({7, 9})
BROAD = re.compile(r"^(<all_urls>|(\*|https?|wss?)://\*/.*)$")


def _browsers(scan: Scan) -> tuple[list[MozProfile], list[tuple[BrowserDir, list[Path]]]]:
    firefox = mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf"))
    chromium = [(d, chromium_profiles(d)) for d in chromium_dirs(scan.paths)]
    return firefox, [(d, p) for d, p in chromium if p]


@dataclass
class CrashDumps:
    label: str                  # "Google Chrome", "Firefox", "Slack (Electron)"
    app: str                    # what to close: "Firefox", the browser's name, the app's folder name
    root: Path                  # the folder deleted from, and checked for programs holding it
    files: list[Path]
    kind: str                   # "chromium", "mozilla" or "electron"


MOZILLA_DUMPS = re.compile(r"\.(dmp|extra|memory\.json\.gz)$")


def crash_dumps(scan: Scan) -> list[CrashDumps]:
    """Crash dumps waiting on the disk: Chromium browsers' Crashpad reports (Crash Reports/{pending,completed,new,
    attachments}), Firefox and Thunderbird's (Crash Reports/pending beside the profiles, and each profile's minidumps:
    a minidump of the process's memory and its notes; tested on Firefox 157), and Electron apps' Crashpad folders."""
    from ._util import files_under
    out = []
    for d in chromium_dirs(scan.paths, any_folder=True):
        files = []
        for sub in ("pending", "completed", "new", "attachments"):       # not Crashpad's own settings.dat
            files += files_under(d.root.path / "Crash Reports" / sub)[0]
        if files:
            out.append(CrashDumps(d.label, d.browser, d.root.path / "Crash Reports", files, "chromium"))
    roots: dict[Path, MozProfile] = {}
    for p in mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf", "Thunderbird")):
        roots.setdefault(p.path.parent, p)
        files = files_under(p.path / "minidumps", pattern=MOZILLA_DUMPS)[0]
        if files:
            out.append(CrashDumps(p.label, p.app, p.path / "minidumps", files, "mozilla"))
    for root, p in roots.items():
        files = files_under(root / "Crash Reports" / "pending", pattern=MOZILLA_DUMPS)[0]
        if files:
            how = "" if p.install == "native" else f", {p.install}"
            out.append(CrashDumps(f"{p.app}{how}", p.app, root / "Crash Reports" / "pending", files, "mozilla"))
    from .apps import BROWSER_DIRS
    apps = [(d, d.name) for d in children(scan.paths.config_home)]
    for fp in scan.paths.flatpak_apps():
        apps += [(d, fp) for d in children(scan.paths.flatpak_root / fp / "config")]
    for d, owner in apps:
        if d.name in BROWSER_DIRS or not isdir(d / "Crashpad") or not (isdir(d / "GPUCache") or isdir(d / "Code Cache")):
            continue
        files = []
        for sub in ("pending", "completed", "new", "attachments"):
            files += files_under(d / "Crashpad" / sub)[0]
        if files:
            out.append(CrashDumps(f"{d.name} (Electron)", owner, d / "Crashpad", files, "electron"))
    return out


@register
class CrashpadDumps(Check):
    id = "br.crashpad_dumps"

    def detect(self, scan: Scan) -> Outcome:
        found = crash_dumps(scan)
        if not found and not chromium_dirs(scan.paths) and not mozilla_profiles(scan.host, scan.paths):
            return absent("No browser or Electron app was found.")
        ev, total = [], 0
        for c in found:
            t = Tally()
            for f in c.files:
                try:
                    t.add(f.stat())
                except OSError:
                    continue
            total += t.files
            ev.append(Evidence.val(c.label, t.describe()))
        # VERIFY (catalogue): measure write volume before making any claim about SSD wear
        if total:
            return failed(f"{total} crash dump file{'s are' if total > 1 else ' is'} on disk.", *ev)
        return passed("No browser or app crash dumps on disk.")


def _chromium_ext_name(ext_dir: Path, manifest: dict) -> str:
    name = str(manifest.get("name") or ext_dir.parent.name)
    m = re.fullmatch(r"__MSG_(\w+)__", name)
    if m:
        locale = manifest.get("default_locale") or "en"
        for loc in (locale, "en", "en_US"):
            msgs = read_json_quiet(ext_dir / "_locales" / loc / "messages.json")
            for k, v in (msgs or {}).items():
                if k.lower() == m.group(1).lower() and isinstance(v, dict):
                    return str(v.get("message") or name)
    return name


def read_json_quiet(p: Path):
    import json
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


@register
class ExtensionsBroad(Check):
    id = "br.extensions_broad"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        pending: list[Extension] = []
        broad = broad_extensions(scan, firefox, chromium, pending=pending)
        ev = [Evidence.val(e.name[:120], e.where) for e in broad[:30]]
        notes = pending_note(pending)
        if broad:
            return failed(f"{len(broad)} extension{'s' if len(broad) > 1 else ''} can read and change every site you "
                          "visit.", *ev, notes=notes)
        return passed("No extension has access to all sites.", notes=notes)


@dataclass(frozen=True)
class Extension:
    name: str
    id: str
    where: str           # "Firefox profile abc.default" / "Google Chrome, Default"
    browser: str         # "Firefox" or the Chromium-based browser's name
    install: str         # native, flatpak or snap: only native (and Snap Firefox) installs read /etc policies
    profile: Path | None = None
    file: Path | None = None     # Firefox: its .xpi in the profile (deleted while Firefox is closed, it is removed)
    mv3: bool = False            # Manifest V3: Firefox lets its access to all sites be turned off
    managed: bool = False        # installed by a policy: the browser won't remove it
    system: str = ""             # Firefox: installed outside the profile, for every account (where)


def _granted(a: dict, granted: dict | None) -> list:
    """The origins a Firefox add-on may read: required ones, and optional ones it was granted (MV3
    host permissions are optional, granted at install and revocable, kept in extension-preferences.json)."""
    origins = list(dig(a, "userPermissions", "origins", default=[]) or [])
    if any(isinstance(o, str) and BROAD.match(o) for o in dig(a, "optionalPermissions", "origins", default=[]) or []):
        if granted is None:                  # no record of grants: Firefox grants them at install
            origins += dig(a, "requestedPermissions", "origins", default=[]) or []
        else:
            origins += dig(granted, a.get("id", ""), "origins", default=[]) or []
    return [o for o in origins if isinstance(o, str)]


def _chromium_settings(scan: Scan, prof: Path) -> dict:
    """extensions.settings from Preferences and Secure Preferences, merged."""
    out: dict = {}
    for name in ("Preferences", "Secure Preferences"):
        s = dig(read_json(scan.host, prof / name) or {}, "extensions", "settings", default={})
        for k, v in (s.items() if isinstance(s, dict) else ()):
            if isinstance(v, dict):
                out.setdefault(k, {}).update(v)
    return out


def _chromium_disabled(st: dict) -> bool:
    reasons = st.get("disable_reasons")           # a bit mask, or a list in newer versions
    return st.get("state") == 0 or bool(reasons) and reasons != [0]


def _removed_from_profile(p: MozProfile, a: dict) -> bool:
    """An add-on of the profile's own whose file is gone (deleted while Firefox was closed, as the guide does):
    Firefox drops it from extensions.json only at its next start. Judged by the file extensions.json names when it
    is in this profile, else by the profile's extensions folder (an add-on is its .xpi there, or a folder)."""
    if a.get("location") != "app-profile":
        return False
    folder = p.path / "extensions"
    path = a.get("path")
    if isinstance(path, str) and path.startswith("/"):
        f = Path(path)
        try:
            ours = f.parent.resolve() == folder.resolve()
        except OSError:
            return False
        return ours and not os.path.lexists(f)
    aid = str(a.get("id", ""))
    return bool(aid) and "/" not in aid and isdir(folder) and not os.path.lexists(folder / f"{aid}.xpi") \
        and not os.path.lexists(folder / aid)


def _firefox_blocked(scan: Scan) -> set[str]:
    """Add-on ids Firefox's policies block (ExtensionSettings, installation_mode blocked, as the guide writes): Firefox
    removes them from every profile when it next starts."""
    settings = firefox_policies(scan.host).get("ExtensionSettings")
    return {k for k, v in settings.items() if isinstance(v, dict) and v.get("installation_mode") == "blocked"} \
        if isinstance(settings, dict) else set()


def broad_extensions(scan: Scan, firefox, chromium, every: bool = False,
                     pending: list[Extension] | None = None) -> list[Extension]:
    """Enabled extensions that can read and change every site (with `every`, all enabled extensions,
    whatever their site access). Those already removed, which the browser still lists until it next starts (an add-on
    deleted from a Firefox profile, one a policy blocks), aren't counted: they go in `pending`."""
    out = []
    blocked_ff = _firefox_blocked(scan) if firefox else set()
    for p in firefox:
        data = read_json(scan.host, p.path / "extensions.json") or {}
        granted = read_json(scan.host, p.path / "extension-preferences.json")
        # Firefox reads the policies in /etc (native installs, and the Snap); LibreWolf has its own
        reads_policy = p.app == "Firefox" and p.install in ("native", "snap")
        for a in data.get("addons") or []:
            if a.get("type") != "extension" or not a.get("active") or a.get("location") in BUILTIN_LOCATIONS \
                    or a.get("signedState") in MOZILLA_SIGNED:
                continue
            if every or any(BROAD.match(o) for o in _granted(a, granted if isinstance(granted, dict) else None)):
                aid = str(a.get("id", ""))
                xpi = p.path / "extensions" / f"{aid}.xpi"
                e = Extension(
                    str(dig(a, "defaultLocale", "name", default=aid or "?")), aid, p.label, p.app, p.install, p.path,
                    xpi if a.get("location") == "app-profile" and "/" not in aid and xpi.is_file() else None,
                    a.get("manifestVersion") == 3,
                    system=str(a.get("path") or a.get("location")) if a.get("location") in SYSTEM_LOCATIONS else "")
                if _removed_from_profile(p, a) or (reads_policy and aid in blocked_ff):
                    if pending is not None:
                        pending.append(e)
                    continue
                out.append(e)
    for d, profiles in chromium:
        policy = chromium_policies(scan.host, d.browser) if d.root.install == "native" else {}
        blocklist = policy.get("ExtensionInstallBlocklist")
        blocklist = {x for x in blocklist if isinstance(x, str)} if isinstance(blocklist, list) else set()
        for prof in profiles:
            settings = _chromium_settings(scan, prof)
            for ext in children(prof / "Extensions"):
                versions = [v for v in children(ext) if (v / "manifest.json").is_file()]
                if not versions:
                    continue
                st = settings.get(ext.name, {})
                if st.get("location") in CHROMIUM_BUILTIN or _chromium_disabled(st):
                    continue
                m = read_json_quiet(versions[-1] / "manifest.json") or {}
                if st.get("withholding_permissions"):         # site access set to "on click" or chosen sites
                    patterns = [x for k in ("explicit_host", "scriptable_host")
                                for x in dig(st, "runtime_granted_permissions", k, default=[]) or []]
                else:
                    patterns = (m.get("permissions") or []) + (m.get("host_permissions") or [])
                    for cs in m.get("content_scripts") or []:
                        patterns += cs.get("matches") or []
                if every or any(isinstance(x, str) and BROAD.match(x) for x in patterns):
                    e = Extension(_chromium_ext_name(versions[-1], m), ext.name, f"{d.label}, {prof.name}",
                                  d.browser, d.root.install, prof, mv3=m.get("manifest_version") == 3,
                                  managed=st.get("location") in CHROMIUM_POLICY)
                    if ext.name in blocklist and not e.managed:     # the browser removes it as it loads the policy
                        if pending is not None:
                            pending.append(e)
                        continue
                    out.append(e)
    return out


def pending_note(pending: list[Extension]) -> list[Note]:
    """What was removed but is still listed by its browser, until the browser next starts."""
    if not pending:
        return []
    names = "; ".join(dict.fromkeys(f"{e.name[:60]} ({e.where})" for e in pending[:10]))
    return [Note("info", "Removed, until the browser next starts",
                 f"{names}: removed from the profile, or blocked by a policy, so not counted. The browser still lists "
                 "it until it next starts, and then forgets it.")]


def vpn_extensions(scan: Scan, firefox, chromium, pending: list[Extension] | None = None) -> list[tuple[Extension, object]]:
    """Enabled extensions of VPN providers in vpn-providers.yaml: (extension, provider). Those removed but still listed
    until the browser starts go in `pending`."""
    from ..vpn import load
    by_id = {x: p for p in load() for x in p.extensions}
    gone: list[Extension] = []
    found = [(e, by_id[e.id]) for e in broad_extensions(scan, firefox, chromium, every=True, pending=gone) if e.id in by_id]
    if pending is not None:
        pending += [e for e in gone if e.id in by_id]
    return found


@register
class VpnExtensions(Check):
    id = "br.vpn_extensions"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError, rate
        from .network import cite
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        pending: list[Extension] = []
        try:
            found = vpn_extensions(scan, firefox, chromium, pending)
        except DataError as e:
            return unknown(f"The app's list of VPN providers couldn't be read: {e}")
        if not found:
            return passed("No VPN extension from a provider the app knows of is installed.", notes=pending_note(pending))
        ev, notes, bad, findings = [], pending_note(pending), [], {"vpn_avoid": False, "vpn_closed_client": False,
                                                                     "vpn_ownership_concerns": False}
        for e, p in found:
            r = rate(p)
            ev.append(Evidence.val(f"{e.name[:80]} ({e.where})"[:150], f"{p.name}: {r.label}"))
            if r.concern:
                bad.append(e)
                findings = {k: v or r.findings()[k] for k, v in findings.items()}
                notes.append(Note("risk", f"{e.name[:80]}: {r.label}", " ".join(cite(f) for f in r.reasons)))
        if bad:
            return failed(f"{len(bad)} VPN extension{'s' if len(bad) > 1 else ''} from providers with a record of harm "
                          "or that can't be checked: " + ", ".join(dict.fromkeys(e.name[:60] for e in bad)) + ".",
                          *ev, notes=notes, findings=findings)
        return passed("The VPN extensions installed come from providers rated well.", *ev, findings=findings,
                      notes=notes)


def _ff_clears_history(prefs: dict, policies: dict) -> bool:
    if prefs.get("browser.privatebrowsing.autostart") is True:
        return True
    sanitize = policies.get("SanitizeOnShutdown")
    if sanitize is True or (isinstance(sanitize, dict) and sanitize.get("History")):
        return True
    if prefs.get("privacy.sanitize.sanitizeOnShutdown") is True:
        return (prefs.get("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", True) is True
                or prefs.get("privacy.clearOnShutdown.history", True) is True)
    return False


@register
class HistoryRetention(Check):
    id = "br.history_retention"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        policies = firefox_policies(scan.host)
        ev, keeping = [], []
        for p in firefox:
            clears = _ff_clears_history(firefox_prefs(scan.host, p.path), policies)
            ev.append(Evidence.val(p.label, "cleared when it closes" if clears else "kept"))
            if not clears:
                keeping.append(p.label)
        for d, profiles in chromium:
            policy = chromium_policies(scan.host, d.browser)
            for prof in profiles:
                prefs = read_json(scan.host, prof / "Preferences") or {}
                if policy.get("ClearBrowsingDataOnExitList"):
                    state = "cleared when it closes (policy)"
                elif policy.get("DefaultCookiesSetting") == 4:            # the policy wins over the profile's own
                    state = "cookies cleared when it closes (policy), history kept"
                elif dig(prefs, "profile", "default_content_setting_values", "cookies") == 4:
                    state = "cookies cleared when it closes, history kept"
                else:
                    state = "kept"
                ev.append(Evidence.val(f"{d.label}, {prof.name}", state))
                if state != "cleared when it closes (policy)":
                    keeping.append(f"{d.label}, {prof.name}")
        if keeping:
            return failed(f"Browsing history and site data are kept indefinitely in {len(keeping)} profile"
                          f"{'s' if len(keeping) > 1 else ''}.", *ev)
        return passed("Browsers clear history when they close.", *ev)


@register
class TrackingProtection(Check):
    id = "br.tracking_protection"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        ev, weak, custom = [], [], []
        for p in firefox:
            cat = firefox_prefs(scan.host, p.path).get("browser.contentblocking.category", "standard")
            ev.append(Evidence.val(p.label, f"Enhanced Tracking Protection: {cat}"))
            if cat == "custom":
                custom.append(p.label)
            elif cat != "strict" and p.app == "Firefox":
                weak.append(p.label)
        for d, profiles in chromium:
            policy = chromium_policies(scan.host, d.browser)
            for prof in profiles:
                prefs = read_json(scan.host, prof / "Preferences") or {}
                blocked = (d.browser.startswith("Brave") or policy.get("BlockThirdPartyCookies") is True
                           or dig(prefs, "profile", "block_third_party_cookies") is True
                           or dig(prefs, "profile", "cookie_controls_mode") == 1)
                ev.append(Evidence.val(f"{d.label}, {prof.name}", "third-party cookies blocked" if blocked
                                       else "third-party cookies allowed"))
                if not blocked:
                    weak.append(f"{d.label}, {prof.name}")
        if weak:
            return failed(f"Tracking protection is at its weaker default in {len(weak)} profile"
                          f"{'s' if len(weak) > 1 else ''}.", *ev)
        if custom:
            return warned("Firefox uses custom tracking protection settings.", *ev)
        return passed("Tracking protection is strict.", *ev)


@register
class PrivateDownloadLeak(Check):
    id = "br.private_download_leak"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        downloads = xdg_user_dir(host, scan.paths, "DOWNLOAD") or host.home / "Downloads"
        if not isdir(downloads):
            return absent("There is no Downloads folder.")
        prefix = str(downloads).rstrip("/") + "/"
        recent = sum(1 for x in recent_files(scan.paths) for h in recent_hrefs(host, x)
                     if (uri_path(html.unescape(h)) or "").startswith(prefix))
        uris, _ = thumbnail_uris(scan.paths)
        thumbs = sum(1 for u in uris if (uri_path(u) or "").startswith(prefix))
        ev = [Evidence.path("Downloads folder", host.display(downloads)),
              Evidence.count("Downloads in the recent files list", recent),
              Evidence.count("Thumbnails of downloads", thumbs)]
        # KDE's own records: each app's list of what it opened (Gwenview, Okular, Kate…), and the activity manager's
        from .apps import kde_activity_count, kde_recent_paths
        apps = sum(1 for p in kde_recent_paths(scan) if p.startswith(prefix))
        activity = kde_activity_count(scan, prefix) or 0
        related = ("desk.recent_files", "desk.thumbnails", "desk.indexers")
        if apps:
            ev.append(Evidence.count("Downloads in KDE apps' lists of what they opened", apps))
            related += ("app.kde_recent_files",)
        if activity:
            ev.append(Evidence.count("Downloads in KDE's activity history", activity))
            related += ("desk.kde_activities",)
        note = Note("info", "Private windows don't cover the rest of the system",
                    "A browser forgets a private window's downloads, but opening one leaves its name in the recent "
                    "files list, a thumbnail of it, and possibly an entry in the search index"
                    + (", and KDE apps and KDE's activity history note it too." if scan.context.desktop.is_kde or apps
                       or activity else "."), related)
        if recent or thumbs or apps or activity:
            return failed("Files in Downloads are recorded outside the browser.", *ev, notes=[note])
        return passed("Files in Downloads aren't recorded in the recent files list or thumbnails.", *ev, notes=[note])


@register
class DiskCache(Check):
    id = "br.disk_cache"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        # profile-sync-daemon isn't counted: it keeps profiles in memory for speed but writes them back to the
        # disk regularly, and caches (in ~/.cache) aren't part of the profiles it moves
        ev, on_disk, left = [], [], []
        for p in firefox:
            prefs = firefox_prefs(scan.host, p.path)
            cache = prefs.get("browser.cache.disk.enable", True)
            level = prefs.get("browser.sessionstore.privacy_level", 0)
            old = tally(mozilla_cache(scan.paths, p), limit=20_000) if not cache else Tally()
            ev.append(Evidence.val(p.label, f"disk cache {'on' if cache else 'off'}"
                                   + (f", but the old one is still there ({old.describe()})" if old.files else "")
                                   + f", session store privacy level {level}"))
            if cache:
                on_disk.append(p.label)
            elif old.files:
                left.append(p.label)
        for d, _ in chromium:
            ev.append(Evidence.val(d.label, "disk cache on (no setting)"))
            on_disk.append(d.label)
        notes = [Note("info", "The session store is written whatever the settings",
                      "Firefox saves the open tabs, with each tab's history, to the profile's sessionstore-backups "
                      "every few seconds; no setting stops it (tested on Firefox 157, resume_from_crash off included). "
                      "Privacy level 2 keeps form contents and cookies out of it. Private windows are never saved in it.",
                      ("br.history_retention",))] if firefox else []
        if on_disk:
            return failed(f"Browser caches and session data are written to disk in {len(on_disk)} browser profile"
                          f"{'s' if len(on_disk) > 1 else ''}.", *ev, notes=notes)
        if left:
            return failed(f"The cache is kept in memory now, but the old one is still on the disk in {', '.join(left)}.",
                          *ev, notes=notes)
        return passed("Browser caches are kept in memory; the session store is still written to the profile.", *ev,
                      notes=notes)


SAFE_WEBRTC = {"default_public_interface_only", "disable_non_proxied_udp"}


@register
class Webrtc(Check):
    id = "br.webrtc"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        ev, exposed = [], []
        for p in firefox:
            prefs = firefox_prefs(scan.host, p.path)
            ok = prefs.get("media.peerconnection.enabled", True) is False or \
                prefs.get("media.peerconnection.ice.default_address_only", False) is True
            ev.append(Evidence.val(p.label, "limited to the default route" if ok else "all local addresses"))
            if not ok:
                exposed.append(p.label)
        for d, profiles in chromium:
            policy = chromium_policies(scan.host, d.browser).get("WebRtcIPHandling")
            for prof in profiles:
                value = policy or dig(read_json(scan.host, prof / "Preferences") or {}, "webrtc", "ip_handling_policy",
                                      default="default")
                ev.append(Evidence.val(f"{d.label}, {prof.name}", value))
                if value not in SAFE_WEBRTC:
                    exposed.append(f"{d.label}, {prof.name}")
        if exposed:
            return failed("WebRTC can reveal local and VPN-bypassing IP addresses to websites.", *ev)
        return passed("WebRTC is limited to the default route.", *ev)


# ------------------------------------------------------------------ HTTPS-Only Mode

HTTPS_ONLY_PREF = "dom.security.https_only_mode"
# Brave's own setting (Shields, "Upgrade connections to HTTPS"), a content setting's default: 2 Strict (asks first),
# 1 Disabled, and no entry at all for Standard (its default: falls back to HTTP). Set through brave://settings/shields
# on Brave 1.97 (Chromium 155) and read back: profile.default_content_setting_values.httpsUpgrades. Chromium's own
# page writes https_only_mode_enabled (seen on Chromium 153, with https_first_balanced_mode_enabled beside it).
BRAVE_HTTPS_STRICT = 2


def firefox_https_only(prefs: dict, app: str, policy) -> tuple[bool, str]:
    """(asks before an unencrypted page, in words). LibreWolf ships with it on; Firefox with it off."""
    if policy in ("enabled", "force_enabled"):
        return True, "HTTPS-Only Mode on (a policy)"
    value = prefs.get(HTTPS_ONLY_PREF)
    if value is True or (value is None and app == "LibreWolf"):
        return True, "HTTPS-Only Mode on"
    if prefs.get(HTTPS_ONLY_PREF + "_pbm") is True:
        return False, "HTTPS-Only Mode in private windows only"
    return False, "HTTPS-Only Mode off"


def chromium_https_only(browser: str, prefs: dict, policy) -> tuple[bool, str]:
    if browser.startswith("Brave"):
        setting = dig(prefs, "profile", "default_content_setting_values", "httpsUpgrades")
        if setting is None:               # where its source suggests an every-site rule would be; not seen written
            setting = dig(prefs, "profile", "content_settings", "exceptions", "httpsUpgrades", "*,*", "setting")
        if setting == BRAVE_HTTPS_STRICT:
            return True, "Upgrade connections to HTTPS: Strict"
        return False, "Upgrade connections to HTTPS: " + ("off" if setting == 1 else "Standard (falls back to HTTP)")
    if policy in ("force_enabled", "force_balanced_enabled"):
        return True, "Always use secure connections: on (a policy)"
    if policy != "disallowed":
        if prefs.get("https_only_mode_enabled") is True:
            return True, "Always use secure connections: on"
        if prefs.get("https_first_balanced_mode_enabled") is True:
            return True, "Always use secure connections: on for public sites"
    return False, "Always use secure connections: off"


@register
class HttpsOnly(Check):
    id = "br.https_only"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        ev, silent = [], []
        ff_policy = firefox_policies(scan.host).get("HttpsOnlyMode")
        for p in firefox:
            ok, text = firefox_https_only(firefox_prefs(scan.host, p.path), p.app, ff_policy)
            ev.append(Evidence.val(p.label, text))
            if not ok:
                silent.append(p.label)
        for d, profiles in chromium:
            policy = chromium_policies(scan.host, d.browser).get("HttpsOnlyMode")
            for prof in profiles:
                ok, text = chromium_https_only(d.browser, read_json(scan.host, prof / "Preferences") or {}, policy)
                ev.append(Evidence.val(f"{d.label}, {prof.name}", text))
                if not ok:
                    silent.append(f"{d.label}, {prof.name}")
        if silent:
            n = len(silent)
            return failed(f"{n} browser profile{'s open' if n > 1 else ' opens'} unencrypted pages without asking "
                          "first.", *ev)
        return passed("Every browser profile asks before opening an unencrypted page.", *ev)


# ------------------------------------------------------------------ sites allowed the camera, microphone or location

SITE_PERMISSIONS = (("camera", "camera", "media_stream_camera", "Camera"),
                    ("microphone", "microphone", "media_stream_mic", "Microphone"),
                    ("location", "geo", "geolocation", "Location"))
# Firefox's permissions.default.* and Chromium's default content settings: 1 allows every site
ALLOW, BLOCK = 1, 2


def firefox_site_permissions(scan: Scan, p: MozProfile) -> tuple[dict[str, int | None], dict[str, int]]:
    """(sites allowed each permission for good, or until a date not yet passed; the default for
    each: 0 ask, 1 allow, 2 block) of a Firefox-family profile. Counted read-only in permissions.sqlite."""
    import time
    from ._util import sqlite_count
    now_ms = int(time.time() * 1000)
    prefs = firefox_prefs(scan.host, p.path)
    policy = firefox_policies(scan.host).get("Permissions") or {}
    counts, defaults = {}, {}
    db = p.path / "permissions.sqlite"
    for name, ff, _, label in SITE_PERMISSIONS:
        # no database yet: the profile has never remembered a permission
        counts[name] = sqlite_count(db, f"SELECT COUNT(*) FROM moz_perms WHERE type = '{ff}' AND permission = 1 AND "
                                        f"(expireType = 0 OR (expireType = 2 AND expireTime > {now_ms}))") \
            if isfile(db) else 0
        value = prefs.get(f"permissions.default.{ff}", 0)
        if isinstance(policy.get(label), dict) and policy[label].get("BlockNewRequests") is True:
            value = BLOCK
        defaults[name] = value if value in (0, ALLOW, BLOCK) else 0
    return counts, defaults


def chromium_site_permissions(scan: Scan, d: BrowserDir, prof: Path) -> tuple[dict[str, int], dict[str, int]]:
    prefs = read_json(scan.host, prof / "Preferences") or {}
    exceptions = dig(prefs, "profile", "content_settings", "exceptions", default={}) or {}
    policy = chromium_policies(scan.host, d.browser)
    counts, defaults = {}, {}
    for name, _, key, _ in SITE_PERMISSIONS:
        sites = exceptions.get(key) if isinstance(exceptions, dict) else None
        counts[name] = sum(1 for v in (sites or {}).values() if isinstance(v, dict) and v.get("setting") == ALLOW)
        value = dig(prefs, "profile", "default_content_setting_values", key, default=0)
        if name == "location" and policy.get("DefaultGeolocationSetting") in (ALLOW, BLOCK):
            value = policy["DefaultGeolocationSetting"]
        defaults[name] = value if value in (ALLOW, BLOCK) else 0
    return counts, defaults


def _permission_summary(counts: dict, defaults: dict) -> str:
    parts = []
    for name, *_ in SITE_PERMISSIONS:
        n = counts.get(name)
        part = f"{name}: {'?' if n is None else n} site{'' if n == 1 else 's'}"
        if defaults.get(name) == ALLOW:
            part += ", and every other site without asking"
        elif defaults.get(name) == BLOCK:
            part += ", new requests blocked"
        parts.append(part)
    return "; ".join(parts)


@register
class SitePermissions(Check):
    id = "br.site_permissions"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        ev, allowed, everyone, unread = [], 0, [], []
        rows = [(p.label, *firefox_site_permissions(scan, p)) for p in firefox]
        rows += [(f"{d.label}, {prof.name}", *chromium_site_permissions(scan, d, prof))
                 for d, profiles in chromium for prof in profiles]
        for label, counts, defaults in rows:
            ev.append(Evidence.val(label, _permission_summary(counts, defaults)))
            allowed += sum(n for n in counts.values() if n)
            if ALLOW in defaults.values():
                everyone.append(label)
            if any(n is None for n in counts.values()):
                unread.append(label)
        notes = []
        if unread:
            notes.append(Note("limitation", "A permissions database couldn't be read",
                              f"{', '.join(unread)}: permissions.sqlite couldn't be opened, so its sites aren't "
                              "counted."))
        findings = {"site_default_allow": bool(everyone)}
        if everyone:
            return failed(f"Every website can use the camera, microphone or location without asking in "
                          f"{', '.join(everyone)}.", *ev, findings=findings, notes=notes)
        if allowed:
            return failed(f"{allowed} permission{'s' if allowed > 1 else ''} for websites to use your camera, microphone "
                          "or location are remembered.", *ev, findings=findings, notes=notes)
        return passed("No website is allowed to use your camera, microphone or location without asking.", *ev,
                      findings=findings, notes=notes)


# ------------------------------------------------------------------ accounts and ad features

# Chromium browsers whose own sync is end-to-end encrypted whatever the user sets: Brave's (keys from the sync
# chain's code) and Vivaldi's (its encryption password)
E2E_SYNC_BROWSERS = ("Brave", "Vivaldi")


@dataclass
class SyncState:
    label: str          # "Firefox profile abcd.default-release", "Google Chrome, Default"
    browser: str        # "Firefox", "Google Chrome", "Brave"...
    state: str          # "readable", "passphrase", "e2e", "signed_in" (sync not set up) or "off"


def sync_states(scan: Scan) -> list[SyncState]:
    """Each browser profile's sync: whether the provider can read what it copies. Only whether an account is set
    up is read, never which."""
    firefox, chromium = _browsers(scan)
    out = []
    for p in firefox:
        signed_in = bool(firefox_prefs(scan.host, p.path).get("services.sync.username"))
        out.append(SyncState(p.label, p.label.split(" profile")[0], "e2e" if signed_in else "off"))
    for d, profiles in chromium:
        for prof in profiles:
            prefs = read_json(scan.host, prof / "Preferences") or {}
            accounts = prefs.get("account_info")
            signed_in = bool(accounts) if isinstance(accounts, list) else False
            setup = dig(prefs, "sync", "has_setup_completed") is True or dig(prefs, "sync", "requested") is True
            # VERIFY: the key for a custom passphrase across Chrome versions
            passphrase = dig(prefs, "sync", "encryption_bootstrap_token") not in (None, "") or \
                dig(prefs, "sync", "passphrase_type") in (2, 3, 4)
            state = ("e2e" if d.browser.startswith(E2E_SYNC_BROWSERS) else "passphrase" if passphrase else "readable") \
                if setup else "signed_in" if signed_in else "off"
            out.append(SyncState(f"{d.label}, {prof.name}", d.browser, state))
    return out


SYNC_WORDS = {"readable": "syncing (the provider can read what is synced)",
              "passphrase": "syncing with a sync passphrase (end-to-end encrypted)",
              "e2e": "syncing, end-to-end encrypted", "signed_in": "signed in, sync not set up", "off": "not signed in"}


@register
class AccountSync(Check):
    id = "br.account_sync"

    def detect(self, scan: Scan) -> Outcome:
        states = sync_states(scan)
        if not states:
            return absent("No browser profiles were found.")
        ev = [Evidence.val(s.label, "signed in to Firefox Sync (end-to-end encrypted)" if s.state == "e2e"
                           and s.label.startswith(("Firefox", "LibreWolf")) else SYNC_WORDS[s.state]) for s in states]
        readable = [s for s in states if s.state == "readable"]
        sealed = [s for s in states if s.state in ("e2e", "passphrase")]
        if readable:
            return failed(f"{len(readable)} profile{'s copy' if len(readable) > 1 else ' copies'} history, passwords or "
                          "tabs to an online account whose provider can read them.", *ev)
        if sealed:
            # end-to-end encrypted: the provider holds only what it can't read, so a risk, not a problem
            return warned(f"{len(sealed)} profile{'s copy' if len(sealed) > 1 else ' copies'} history, passwords or "
                          "tabs to an online account, end-to-end encrypted: the provider can't read them.", *ev,
                          notes=[Note("info", "What end-to-end encrypted sync still gives away",
                                      "The provider can't read what is synced, but it holds a copy, sees when and from "
                                      "where each device syncs, and anyone who learns the account's password (or the "
                                      "sync passphrase or code) can read everything. A strong password of its own, "
                                      "and two-step sign-in, keep it that way.")])
        return passed("No browser profile syncs to an online account.", *ev)


# Features that report what you browse: (Chromium Preferences key or Firefox pref, what it does,
# the browser's default, and for Chromium the policy that turns it off for every user).
# Only a setting that is on in the profile itself counts as a finding. A browser default is
# listed in a note: counting it would make every stock Firefox and Chrome profile a finding.
# The Privacy Sandbox keys are only written once the user answers Chrome's ad privacy notice, so
# an absent key means the feature was never turned on (and Chromium, Edge, Vivaldi and Opera
# builds don't offer it). VERIFY: the privacy_sandbox keys on current Chrome releases.
ENHANCED_SAFE_BROWSING = "enhanced Safe Browsing (sends URLs)"
CHROMIUM_AD_PREFS = (("privacy_sandbox.m1.topics_enabled", "ad topics from your history", False, "PrivacySandboxAdTopicsEnabled"),
                     ("privacy_sandbox.m1.fledge_enabled", "site-suggested ads", False, "PrivacySandboxSiteEnabledAdsEnabled"),
                     ("privacy_sandbox.m1.ad_measurement_enabled", "ad measurement", False, "PrivacySandboxAdMeasurementEnabled"),
                     ("search.suggest_enabled", "search suggestions as you type", True, "SearchSuggestEnabled"),
                     # a policy with a value rather than false: SafeBrowsingProtectionLevel 1 is standard protection
                     ("safebrowsing.enhanced", ENHANCED_SAFE_BROWSING, False, ("SafeBrowsingProtectionLevel", 1)))
REGION = "region"           # on by default in some countries only (Firefox Suggest, sponsored shortcuts)
FIREFOX_AD_PREFS = (("browser.search.suggest.enabled", "search suggestions as you type", True, None),
                    ("browser.urlbar.suggest.quicksuggest.sponsored", "sponsored address bar suggestions", REGION, None),
                    ("browser.newtabpage.activity-stream.showSponsoredTopSites", "sponsored shortcuts on the new tab page",
                     REGION, None))
AD_DEFAULTS_HOW = ("Firefox: Settings → Search → \"Show search suggestions\"; Settings → Home → \"Sponsored shortcuts\"; "
                   "Settings → Privacy & Security → Address Bar → \"Suggestions from sponsors\". Chrome: Settings → You and "
                   "Google → Sync and Google services → \"Improve search suggestions\" and \"Autocomplete searches and URLs\".")


def _ad_settings(prefs: dict, table, policy: dict, get) -> tuple[list[str], list[str]]:
    """(features turned on in the profile, features on only as the browser's default)."""
    on, defaults = [], []
    for key, what, default, policy_name in table:
        name, off = policy_name if isinstance(policy_name, tuple) else (policy_name, False)
        now = policy.get(name) if name else None
        if now is not None and type(now) is type(off) and now == off:
            continue                                        # turned off for every user
        v = get(prefs, key)
        if v is True:
            on.append(what)
        elif v is None and default is True:
            defaults.append(f"{what} (browser default)")
        elif v is None and default == REGION:
            defaults.append(f"{what} (browser default in some countries)")
    return on, defaults


def chromium_ad_states(scan: Scan, chromium) -> list[tuple[BrowserDir, Path, list[str], list[str]]]:
    """(browser folder, profile, features turned on, features on as the browser's default) of each Chromium-based
    profile but Brave's, which ships with the Privacy Sandbox and suggestions off."""
    out = []
    for d, profiles in chromium:
        if d.browser.startswith("Brave"):
            continue
        policy = chromium_policies(scan.host, d.browser)
        for prof in profiles:
            out.append((d, prof, *_ad_settings(read_json(scan.host, prof / "Preferences") or {}, CHROMIUM_AD_PREFS,
                                               policy, lambda prefs, key: dig(prefs, *key.split(".")))))
    return out


@register
class AdFeatures(Check):
    id = "br.ad_features"

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        if not firefox and not chromium:
            return absent("No browser profiles were found.")
        ev, on, by_default = [], [], []

        def add(label: str, active: list[str], defaults: list[str]) -> None:
            ev.append(Evidence.val(label, ", ".join(active + defaults) or "off"))
            if active:
                on.append(label)
            elif defaults:
                by_default.append(label)

        for p in firefox:
            add(p.label, *_ad_settings(firefox_prefs(scan.host, p.path), FIREFOX_AD_PREFS, {},
                                       lambda prefs, key: prefs.get(key)))
        for d, prof, active, defaults in chromium_ad_states(scan, chromium):
            add(f"{d.label}, {prof.name}", active, defaults)
        notes = []
        if by_default:
            notes.append(Note("info", "Some are on as the browser's default",
                              f"In {', '.join(by_default)}, features that send what you type or browse are on because "
                              "that is how the browser ships, not because they were turned on. Most people have them, "
                              f"so they aren't counted as a finding. To turn them off: {AD_DEFAULTS_HOW}"))
        if on:
            return failed(f"Ad or suggestion features that report what you browse are turned on in {len(on)} profile"
                          f"{'s' if len(on) > 1 else ''}.", *ev, notes=notes)
        return passed("Nothing that reports what you browse is turned on beyond the browsers' defaults."
                      if by_default else "Ad profiling and reporting suggestions are off.", *ev, notes=notes)


# ------------------------------------------------------------------ which browsers, and the default

# system application folders, and how what is in them was installed
SYSTEM_APP_DIRS = (("/usr/share/applications", "package"), ("/usr/local/share/applications", "installed by hand"),
                   ("/var/lib/flatpak/exports/share/applications", "Flatpak"),
                   ("/var/lib/snapd/desktop/applications", "Snap"))


@dataclass
class FoundBrowser:
    browser: object | None          # browsers.Browser, or None for one the app doesn't know
    name: str
    installs: list[str]             # "package", "Flatpak", "Snap", "AppImage", "this account", ...
    desktop_ids: list[str]
    paths: list[Path]               # menu entries or AppImage files
    pinned: list[str]               # "GNOME dash", "Cinnamon panel", ...

    @property
    def key(self) -> str:
        return self.browser.id if self.browser else self.name

    def describe(self) -> str:
        out = ", ".join(dict.fromkeys(self.installs))
        return out + (f"; pinned to the {', '.join(dict.fromkeys(self.pinned))}" if self.pinned else "")


def _app_dirs(scan: Scan) -> list[tuple[Path, str]]:
    host, paths = scan.host, scan.paths
    out = [(paths.data_home / "flatpak/exports/share/applications", "Flatpak"),
           (paths.data_home / "applications", "this account")]
    out += [(host.sys_path(d), how) for d, how in SYSTEM_APP_DIRS]
    for d in (host.environ.get("XDG_DATA_DIRS") or "").split(":"):
        if d and not any(d.rstrip("/") + "/applications" == s for s, _ in SYSTEM_APP_DIRS):
            how = "Flatpak" if "flatpak" in d else "Snap" if "snapd" in d else "package"
            out.append((host.sys_path(f"{d.rstrip('/')}/applications"), how))
    return out


def _pins(scan: Scan) -> tuple[dict[str, list[str]], list[Path]]:
    """Desktop ids pinned to a dash, panel or favourites ({id: [where]}), and launcher files and
    AppImages pinned by path."""
    pinned: dict[str, list[str]] = {}
    files: list[Path] = []
    add = lambda ids, where: [pinned.setdefault(i, []).append(where) for i in ids if isinstance(i, str)]  # noqa: E731
    for schema, where in (("org.gnome.shell", "GNOME dash"), ("org.cinnamon", "Cinnamon menu favourites")):
        v = scan.gnome.gsettings(schema, "favorite-apps")
        if isinstance(v, list):
            add(v, where)
    spices = scan.paths.config_home / "cinnamon/spices"
    for applet, key in (("grouped-window-list@cinnamon.org", "pinned-apps"), ("panel-launchers@cinnamon.org",
                                                                                "launcherList")):
        for f in children(spices / applet):
            data = read_json_quiet(f) if f.suffix == ".json" else None
            v = dig(data or {}, key, "value", default=[])
            if isinstance(v, list):
                add(v, "Cinnamon panel")
    plasma = read_text(scan.host, scan.paths.config_home / "plasma-org.kde.plasma.desktop-appletsrc") or ""
    for m in re.finditer(r"^launchers=(.*)$", plasma, re.M):
        for item in m.group(1).split(","):
            item = item.strip()
            if item.startswith("applications:"):
                add([item.split(":", 1)[1]], "KDE panel")
            elif item.startswith("file://"):
                files.append(Path(item[7:]))
    for launcher in children(scan.paths.config_home / "xfce4/panel"):
        if launcher.name.startswith("launcher-"):
            files += [f for f in children(launcher) if f.suffix == ".desktop"]
    return pinned, files


def installed_browsers(scan: Scan) -> list[FoundBrowser]:
    """Every browser on this computer: menu entries (native, Flatpak, Snap, this account's own), launchers
    and AppImages on the desktop and in the usual folders, and pins, matched against browsers.yaml."""
    from .. import browsers
    from .sandbox import APPIMAGE_DIRS
    data = browsers.load()
    found: dict[str, FoundBrowser] = {}
    pinned, pinned_files = _pins(scan)

    def add(b, name, how, desktop_id, path):
        f = found.setdefault(b.id if b else name, FoundBrowser(b, b.name if b else name, [], [], [], []))
        f.installs.append(how)
        if desktop_id:
            f.desktop_ids.append(desktop_id)
            f.pinned += pinned.get(desktop_id, [])
        f.paths.append(path)

    def entry(path: Path, how: str):
        text = read_text(scan.host, path)
        e = browsers.read_desktop_entry(path, text) if text else None
        if e is None:
            return
        b = data.by_desktop(e.id)
        appimage = e.appimage
        if appimage and b is None:
            b = data.by_appimage(Path(appimage).name)
        if b is None and not e.is_browser:
            return
        add(b, e.name, "AppImage" if appimage else how, e.id, path)

    for d, how in _app_dirs(scan):
        for f in children(d):
            if f.suffix == ".desktop":
                entry(f, how)
    desktop_dir = xdg_user_dir(scan.host, scan.paths, "DESKTOP") or scan.host.home / "Desktop"
    for f in children(desktop_dir):
        if f.suffix == ".desktop":
            entry(f, "a launcher on the desktop")
    for f in pinned_files:
        if f.suffix == ".desktop":
            entry(f, "a panel launcher")
    appimage_dirs = [scan.host.home / d for d in APPIMAGE_DIRS] + [desktop_dir]
    for d in dict.fromkeys(appimage_dirs):
        for f in children(d):
            if f.suffix.lower() == ".appimage":
                b = data.by_appimage(f.name)
                if b is not None:
                    add(b, b.name, "AppImage", None, f)
    for f in pinned_files:
        if f.suffix.lower() == ".appimage":
            b = data.by_appimage(f.name)
            if b is not None:
                add(b, b.name, "AppImage", None, f)
                found[b.id].pinned.append("KDE panel")
    return sorted(found.values(), key=lambda f: f.name.lower())


def default_browser(scan: Scan) -> tuple[str | None, str]:
    """The default browser's menu entry id and how it was found, or (None, why not)."""
    from .. import browsers
    r = scan.host.run("xdg-settings", "get", "default-web-browser")
    if r.ok and r.stdout.strip().endswith(".desktop"):
        return r.stdout.strip(), "xdg-settings"
    desktops = [d.lower() for d in (scan.host.environ.get("XDG_CURRENT_DESKTOP") or "").split(":") if d]
    candidates = [scan.paths.config_home / f"{d}-mimeapps.list" for d in desktops]
    candidates += [scan.paths.config_home / "mimeapps.list", scan.host.sys_path("/etc/xdg/mimeapps.list"),
                   scan.paths.data_home / "applications/mimeapps.list",
                   scan.host.sys_path("/usr/share/applications/mimeapps.list")]
    for p in candidates:
        found = browsers.mimeapps_default(read_text(scan.host, p) or "")
        if found:
            return found, scan.host.display(p)
    if scan.context.desktop.is_kde:
        v = scan.kde.get("kdeglobals", "General", "BrowserApplication")
        if v and v.endswith(".desktop"):
            return v.lstrip("!"), "KDE's default applications"
    return None, "neither xdg-settings nor any mimeapps.list names a browser for web links"


def _default_of(scan: Scan, found: list[FoundBrowser]) -> tuple[FoundBrowser | None, str | None, str]:
    from .. import browsers
    did, how = default_browser(scan)
    if did is None:
        return None, None, how
    for f in found:
        if did in f.desktop_ids:
            return f, did, how
    b = browsers.load().by_desktop(did)
    return (FoundBrowser(b, b.name, ["not found among installed apps"], [did], [], []) if b else None), did, how


def _cite(f) -> str:
    return f"{f.text} (Source: {f.source}, checked {f.verified.isoformat()}.)"


def browser_notes(b, kind: str = "info") -> list[Note]:
    """The app's view of a browser, then its receipts by topic."""
    from ..browsers import TOPIC_TITLES, TOPICS
    notes = [Note(kind, "DA Privacy Kit's view", b.why)] if b.why else []
    for topic in TOPICS:
        facts = [f for f in b.facts if f.topic == topic]
        if facts:
            notes.append(Note("info", TOPIC_TITLES[topic], " ".join(_cite(f) for f in facts)))
    return notes


EVERYDAY = Note("info", "Which browser to use",
                "For every day, Brave (better still, Brave Origin), LibreWolf, Waterfox or Zen, with history kept, are "
                "the most practical. Mullvad Browser and Tor Browser protect you far better, Tor Browser most of all, "
                "and best with a VPN on this computer too: your internet provider then can't see you use Tor. Never "
                "run a VPN on top of Tor.")


@register
class SurveillanceBrowsers(Check):
    id = "br.surveillance_browsers"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError
        try:
            found = installed_browsers(scan)
        except DataError as e:
            return unknown(f"The app's list of browsers couldn't be read: {e}")
        bad = [f for f in found if f.browser is not None and f.browser.cls == "surveillance"]
        default, did, how = _default_of(scan, found)
        known = did is not None
        is_bad_default = known and default is not None and default.browser is not None and \
            default.browser.cls == "surveillance"
        findings = {
            "chrome_or_edge_installed": any(f.browser.no_ublock for f in bad),
            "surveillance_default": is_bad_default if known else None,
            "chrome_or_edge_default": (is_bad_default and default.browser.no_ublock) if known else None,
        }
        ev = [Evidence.val(f.name, f.describe()) for f in bad]
        ev.append(Evidence.val("Default browser", default.name if default else (did or f"unknown ({how})")))
        if not bad:
            return passed("None of them is installed.", *ev, findings=findings)
        notes = []
        for f in bad:
            notes += [Note(n.kind if n.title != "DA Privacy Kit's view" else "risk", f"{f.name}: {n.title}", n.text)
                      for n in browser_notes(f.browser)]
        names = " and ".join(dict.fromkeys(f.name for f in bad))
        tail = f", and {default.name} is your default browser" if is_bad_default else ""
        if not known:
            notes.append(Note("limitation", "The default browser couldn't be found", how[:200]))
        return failed(f"{names} {'is' if len(bad) == 1 else 'are'} installed{tail}.", *ev, notes=notes,
                      findings=findings)


@register
class DefaultBrowser(Check):
    id = "br.default_browser"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError
        try:
            found = installed_browsers(scan)
        except DataError as e:
            return unknown(f"The app's list of browsers couldn't be read: {e}")
        default, did, how = _default_of(scan, found)
        ev = [Evidence.val(f.name, f.describe()) for f in found[:20]]
        if did is None:
            return absent("No browser is installed.", *ev) if not found else \
                unknown(f"Couldn't tell which browser is the default: {how}.", *ev)
        b = default.browser if default else None
        name = default.name if default else did
        ev.insert(0, Evidence.val("Default browser", f"{name} (from {how})"))
        if b is not None and b.cls == "surveillance":
            return absent(f"Your default browser is {name}: see “Chrome, Edge, Opera or Yandex is installed”.",
                          *ev)
        findings = {"default_closed_ui": b is not None and b.cls == "closed_ui"}
        notes = (browser_notes(b) if b else []) + [EVERYDAY]
        if b is not None and b.cls == "privacy":
            return passed(f"Your default browser, {name}, is built for privacy.", *ev, notes=notes, findings=findings)
        return failed(f"Your default browser, {name}, isn't one built for privacy.", *ev, notes=notes,
                      findings=findings)


def blocking_status(scan: Scan, b) -> list[tuple[str, str]]:
    """(profile, "uBlock Origin" | "uBlock Origin Lite" | "none") for each profile of a browser that needs an
    extension; [] when its profiles aren't known or it has none yet."""
    from ..browsers import UBO_CHROMIUM, UBO_FIREFOX, UBO_LITE
    out = []
    if "chromium" in b.profiles:
        for d in chromium_dirs(scan.paths):
            if d.browser == b.profiles["chromium"]:
                for prof in chromium_profiles(d):
                    ids = {e.id for e in broad_extensions(scan, [], [(d, [prof])], every=True)}
                    status = "uBlock Origin" if UBO_CHROMIUM in ids else "uBlock Origin Lite" if UBO_LITE in ids \
                        else "none"
                    out.append((f"{d.label}, {prof.name}", status))
    elif "mozilla" in b.profiles:
        for p in mozilla_profiles(scan.host, scan.paths, (b.profiles["mozilla"],)):
            ids = {e.id for e in broad_extensions(scan, [p], [], every=True)}
            out.append((p.label, "uBlock Origin" if UBO_FIREFOX in ids else "none"))
    return out


@register
class ContentBlocking(Check):
    id = "br.content_blocking"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError
        try:
            found = installed_browsers(scan)
        except DataError as e:
            return unknown(f"The app's list of browsers couldn't be read: {e}")
        known = [f for f in found if f.browser is not None]
        if not known:
            return absent("No browser the app knows is installed.")
        default, did, _how = _default_of(scan, found)
        ev, lacking, partial, unused, blocks = [], [], [], [], False
        for f in known:
            b = f.browser
            judged = default is not None and default.browser is b or (did is None)
            if b.blocking == "builtin":
                ev.append(Evidence.val(f.name, b.blocker))
                blocks |= judged
                continue
            if b.blocking == "none_allowed":
                ev.append(Evidence.val(f.name, "no extensions, by design"))
                blocks |= judged
                continue
            statuses = blocking_status(scan, b)
            if not statuses:
                ev.append(Evidence.val(f.name, "not used yet: no profile"))
                if judged:
                    unused.append(f.name)
            for where, status in statuses:
                ev.append(Evidence.val(where[:150], status))
            if judged and any(s == "none" for _, s in statuses):
                lacking.append(f.name)
            elif judged and any(s == "uBlock Origin Lite" for _, s in statuses):
                partial.append(f.name)
            elif judged and statuses:
                blocks = True
        notes = [Note("info", "Chrome and Edge can't block properly any more",
                      "Since 2025 Chrome and Edge can't run the full uBlock Origin, only the weaker uBlock Origin "
                      "Lite. Firefox-based browsers, ungoogled-chromium and Brave still can.")]
        if lacking:
            return failed(f"{' and '.join(dict.fromkeys(lacking))} blocks no ads or trackers: install uBlock Origin.",
                          *ev, notes=notes)
        if partial:
            return warned(f"{' and '.join(dict.fromkeys(partial))} has only uBlock Origin Lite, which blocks less.",
                          *ev, notes=notes)
        if not blocks:
            # a fresh install (no profile yet: nothing to judge, and nothing blocks either), or a default the app
            # doesn't know: never a pass that claims blocking
            if unused:
                n = len(dict.fromkeys(unused))
                return absent(f"{' and '.join(dict.fromkeys(unused))} {'hasn' if n == 1 else 'haven'}'t been used yet, "
                              "so there is nothing to check: add uBlock Origin when you first open "
                              f"{'it' if n == 1 else 'them'}.", *ev, notes=notes)
            return absent("Your default browser isn't one the app knows.", *ev, notes=notes)
        return passed("Your browser blocks ads and trackers.", *ev,
                      notes=[Note("info", "Not used yet", f"{', '.join(dict.fromkeys(unused))}: no profile yet, so "
                                  "there is nothing to check there; add uBlock Origin when you first open it.")]
                      if unused else [])
