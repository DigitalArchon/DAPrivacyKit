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


def ff_history_pref(prefs: dict) -> str:
    """The pref that says whether Firefox clears history as it closes (with privacy.sanitize.sanitizeOnShutdown on),
    each true by default: privacy.clearOnShutdown_v2.browsingHistoryAndDownloads, which its shutdown sanitizer reads
    (Sanitizer.sys.mjs, sanitizeOnShutdown), once maybeMigratePrefs("clearOnShutdown") has run (hasMigratedToNewPrefs3);
    until then the one that migration copies into it: historyFormDataAndDownloads after the earlier migration
    (hasMigratedToNewPrefs2), else the old dialog's privacy.clearOnShutdown.history. Reading either of the others
    as well, left at its default, took a profile whose "Browsing history" is unticked (as "Delete cookies and site data
    when Firefox is closed" leaves it, privacy.mjs: resetCleaningPrefs) for one that clears it."""
    if prefs.get("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3") is True:
        return "privacy.clearOnShutdown_v2.browsingHistoryAndDownloads"
    if prefs.get("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs2") is True:
        return "privacy.clearOnShutdown_v2.historyFormDataAndDownloads"
    return "privacy.clearOnShutdown.history"


def _ff_clears_history(prefs: dict, policies: dict) -> bool:
    if prefs.get("browser.privatebrowsing.autostart") is True:
        return True
    sanitize = policies.get("SanitizeOnShutdown")
    if sanitize is True or (isinstance(sanitize, dict) and sanitize.get("History")):
        return True
    if prefs.get("privacy.sanitize.sanitizeOnShutdown") is True:
        return prefs.get(ff_history_pref(prefs), True) is True
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
        if b is None and (not e.is_browser or e.no_display):        # a hidden helper entry isn't a browser to list
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


# ------------------------------------------------------------------ Tor Browser's and Mullvad Browser's start scripts

SHADER_BROWSERS = {"tor_browser": "Tor Browser", "mullvad_browser": "Mullvad Browser"}
START_SCRIPTS = {"Tor Browser": "start-tor-browser", "Mullvad Browser": "start-mullvad-browser"}
START_SCRIPT = re.compile(r"""(?:"(/[^"]+/start-(?:tor|mullvad)-browser)"|(/[^\s"']+/start-(?:tor|mullvad)-browser))(?=[\s"']|$)""")
SCRIPT_TURNS_OFF_NVIDIA = re.compile(r"^\s*export\s+__GL_SHADER_DISK_CACHE=0\s*$", re.M)
# the browser's own program, which the start script runs from the folder it is in
BROWSER_PROGRAM = re.compile(r"""(/[^\s"';|&]+)/(?:mullvadbrowser|firefox(?:\.real)?)(?=[\s"';|&]|$)""")
# where torbrowser-launcher keeps Tor Browser (in its data folder; tbb/<architecture>/tor-browser), natively and as a
# Flatpak (its id since 2023, and the earlier one); the AUR's tor-browser-bin's copy, which it starts through its
# script; where Mullvad's package and Flatpak keep Mullvad Browser
LAUNCHER_FLATPAKS = ("org.torproject.torbrowser-launcher", "com.github.micahflee.torbrowser-launcher")
TOR_BROWSER_BIN = ".local/opt/tor-browser/app/Browser/start-tor-browser"
MULLVAD_PACKAGE = "/usr/lib/mullvad-browser/start-mullvad-browser"
MULLVAD_FLATPAK = "net.mullvad.MullvadBrowser"
FLATPAK_FILES = "current/active/files/lib/mullvad-browser/start-mullvad-browser"
PROGRAM_DIRS = ("/usr/local/bin", "/usr/bin", "/bin")
# what the start scripts do that a browser started without them goes without (start-tor-browser and
# start-mullvad-browser, 15 and 16); the ones tested on the lab first
SCRIPT_PROTECTIONS = (
    "a home folder of its own, which keeps the files and caches the desktop's libraries write, the graphics driver's "
    "shader cache among them, out of yours",
    "GTK's list of recent files made impossible to write (files saved or uploaded through the browser's dialog are "
    "listed there otherwise)",
    "GTK's settings kept in memory, not written into yours (dconf)",
    "NVIDIA's shader cache turned off",
    "the browser's own messages sent nowhere, not to a terminal or the journal",
    "refusing to run as administrator",
)
SCRIPT_MARK = "# DA Privacy Kit: starts the browser through its own start script, which keeps its files out of yours"


@dataclass
class BrowserCopy:
    """A Tor Browser or Mullvad Browser on this computer, as it is started."""
    name: str                   # Tor Browser, Mullvad Browser
    script: Path | None         # its start script (None: a Flatpak whose files weren't found)
    cache: Path | None          # where the graphics drivers keep its cache: the .cache of the home folder the script
                                # gives it, or a Flatpak's own; None when it is the one every program shares
    own: Path                   # its folder, where its profile is: a program with a file open there is the browser
    launcher: Path | None = None    # a program that starts it without its script (the AUR's /usr/bin/mullvad-browser)
    entry: Path | None = None       # the menu entry that runs that program

    def turns_off_nvidia(self, host) -> bool:
        what = self.launcher or self.script
        return what is not None and bool(SCRIPT_TURNS_OFF_NVIDIA.search(read_text(host, what) or ""))


def on_host(host, path: str | Path) -> Path:
    """A path a menu entry names, on the scanned system: one in the home folder as it is, a system one under the
    host's root (the same on the real computer)."""
    p = Path(path)
    return p if p.is_relative_to(host.home) or host.root == Path("/") else host.sys_path(p)


def real_path(host, p: Path) -> str:
    """A path as the computer knows it (a fixture's system files are under its root)."""
    return str(Path("/") / p.relative_to(host.root)) if host.root != Path("/") and p.is_relative_to(host.root) else str(p)


def _browser_home(host, script: Path, name: str) -> Path:
    """The home folder the start script gives the browser: its own folder, or one in the home folder for a packaged
    copy (is-packaged-app beside the script)."""
    if (script.parent / "is-packaged-app").exists():
        return host.home / (".tor-browser" if name == "Tor Browser" else ".mullvad-browser")
    return script.parent


def _copy_from_script(scan: Scan, script: Path, name: str, flatpak: str | None = None) -> BrowserCopy:
    host = scan.host
    if flatpak:                                   # a Flatpak's XDG_CACHE_HOME is its own, whatever the session's
        own = host.home / ".var/app" / flatpak
        return BrowserCopy(name, script, own / "cache", own)
    home = _browser_home(host, script, name)
    return BrowserCopy(name, script, None if host.environ.get("XDG_CACHE_HOME") else home / ".cache", home)


def _entry_program(scan: Scan, exec_line: str) -> str | None:
    """The program a menu entry's command runs (past env and its variables), as a path on the scanned system."""
    import shlex
    try:
        words = shlex.split(exec_line)
    except ValueError:
        return None
    if words and Path(words[0]).name == "env":
        words = [w for w in words[1:] if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*|-.*", w)]
    if not words:
        return None
    prog = words[0]
    if prog.startswith("/"):
        return prog
    if "/" in prog:
        return None
    return next((f"{d}/{prog}" for d in PROGRAM_DIRS if scan.host.sys_path(f"{d}/{prog}").exists()), None)


def _linked_script(scan: Scan, prog: str | None) -> Path | None:
    """The start script a program is a link to (/usr/bin/mullvad-browser in Mullvad's package)."""
    if not prog:
        return None
    try:
        target = os.readlink(on_host(scan.host, prog))
    except OSError:
        return None
    real = os.path.normpath(os.path.join(os.path.dirname(prog), target))
    return on_host(scan.host, real) if re.search(r"/start-(tor|mullvad)-browser$", real) else None


def _skipped_script(scan: Scan, prog: str | None) -> tuple[Path, Path, str] | None:
    """(the program, the start script it skips, the browser) when `prog` is a script of a package's own that runs the
    browser's program itself, from a folder that has the browser's start script (the AUR's mullvad-browser-bin)."""
    if not prog:
        return None
    p = on_host(scan.host, prog)
    try:
        if p.is_symlink() or p.stat().st_size > 65536:
            return None
    except OSError:
        return None
    text = read_text(scan.host, p) or ""
    if not text.startswith("#!") or "start-tor-browser" in text or "start-mullvad-browser" in text:
        return None
    for m in BROWSER_PROGRAM.finditer(text):
        for name, script in START_SCRIPTS.items():
            s = on_host(scan.host, f"{m.group(1)}/{script}")
            if isfile(s):
                return p, s, name
    return None


def effective_entries(scan: Scan, found: list[FoundBrowser]) -> list[tuple[str, Path, Path | None]]:
    """(browser, the menu entry the desktop uses, the one it overrides) for each of Tor Browser's and Mullvad
    Browser's menu entry ids: the account's own (~/.local/share/applications) over the system's."""
    mine = scan.paths.data_home / "applications"
    out = []
    for f in found:
        name = SHADER_BROWSERS.get(f.key)
        by_id: dict[str, list[Path]] = {}
        for p in f.paths if name else ():
            if p.suffix == ".desktop":
                by_id.setdefault(p.name, []).append(p)
        for paths in by_id.values():
            own = [p for p in paths if p.parent == mine]
            others = [p for p in paths if p.parent != mine]
            out.append((name, own[0] if own else others[0], others[0] if own and others else None))
    return out


def _entry_exec(scan: Scan, path: Path) -> str:
    from .. import browsers
    text = read_text(scan.host, path)
    e = browsers.read_desktop_entry(path, text) if text else None
    return e.exec if e else ""


def shader_copies(scan: Scan, found: list[FoundBrowser]) -> list[BrowserCopy]:
    """Every copy of Tor Browser and Mullvad Browser the app can find, as it is started: through its start script (a
    menu entry's command, or the program it links to), started by a package's program that skips it (`launcher`),
    torbrowser-launcher's and tor-browser-bin's copies, Mullvad's package and its Flatpak. Not the app's own in
    ~/TempBrowser (they start with the caches off)."""
    host, out, seen = scan.host, [], set()

    def add(script: Path, name: str, flatpak: str | None = None, skipped: tuple | None = None, entry: Path | None = None):
        if script in seen or not isfile(script) or script.is_relative_to(host.home / "TempBrowser"):
            return
        seen.add(script)
        if skipped:                               # the real home folder, its cache the one every program shares
            out.append(BrowserCopy(name, script, None, profile_root(host, script.parent) or host.home, skipped[0], entry))
        else:
            out.append(_copy_from_script(scan, script, name, flatpak))

    for name, entry, _ in effective_entries(scan, found):
        exec_line = _entry_exec(scan, entry)
        for m in START_SCRIPT.finditer(exec_line):
            add(on_host(host, m.group(1) or m.group(2)), name)
        prog = _entry_program(scan, exec_line)
        linked = _linked_script(scan, prog)
        if linked is not None:
            add(linked, name)
        skipped = _skipped_script(scan, prog)
        if skipped is not None:
            add(skipped[1], skipped[2], skipped=skipped, entry=entry)
    for base, flatpak in [(scan.paths.data_home / "torbrowser", None)] + [
            (host.home / ".var/app" / i / "data/torbrowser", i) for i in LAUNCHER_FLATPAKS]:
        for arch in children(base / "tbb"):
            add(arch / "tor-browser/Browser/start-tor-browser", "Tor Browser", flatpak)
    add(host.home / TOR_BROWSER_BIN, "Tor Browser")
    add(host.sys_path(MULLVAD_PACKAGE), "Mullvad Browser")
    for apps in (host.sys_path("/var/lib/flatpak/app"), scan.paths.data_home / "flatpak/app"):
        add(apps / MULLVAD_FLATPAK / FLATPAK_FILES, "Mullvad Browser", MULLVAD_FLATPAK)
    return out


# ------------------------------------------------------------------ the profile a copy started without its script uses

def profile_root(host, browser_dir: Path) -> Path | None:
    """Where the browser keeps its profiles when started with the real home folder: ~/.<vendor>/<name> from its
    application.ini (Mullvad Browser: ~/.mullvad/mullvadbrowser)."""
    from .. import ini
    app = ini.parse(read_text(host, browser_dir / "application.ini") or "").get(("App",), {})
    vendor, name = app.get("Vendor", "").strip(), app.get("Name", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9 ._-]{1,40}", vendor) or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,40}", name):
        return None
    return host.home / f".{vendor.lower()}" / name.lower()


def default_profile(host, root: Path | None) -> Path | None:
    """The profile the browser opens: this install's default in profiles.ini, else the one marked default, else the
    only one; None when there is none (never started)."""
    from .. import ini
    if root is None:
        return None
    groups = ini.parse(read_text(host, root / "profiles.ini") or "")
    installs = [g for k, g in groups.items() if k and k[0].startswith("Install") and g.get("Default")]
    profiles = [g for k, g in groups.items() if k and k[0].startswith("Profile") and g.get("Path")]
    pick = installs[0].get("Default") if len(installs) == 1 else None
    if pick is None:
        marked = [g for g in profiles if g.get("Default") == "1"]
        g = marked[0] if len(marked) == 1 else profiles[0] if len(profiles) == 1 else None
        if g is None:
            return None
        pick = g["Path"] if g.get("IsRelative", "1") == "1" else None
        if pick is None:
            return Path(g["Path"]) if isdir(Path(g["Path"])) else None
    p = Path(pick) if pick.startswith("/") else root / pick
    return p if isdir(p) and not p.is_symlink() else None


def started_by_script(text: str, script: str, profile: Path | None) -> str:
    """A menu entry with each command starting the browser through its start script (`script`, as the computer knows
    it) instead of the program it ran, with the profile it used (--profile) where one is known, every other key kept;
    marked as the app's at its top."""
    import shlex

    def quote(w: str) -> str:
        return f'"{w}"' if re.search(r"[\s\"'\\$`]", w) else w

    out = [SCRIPT_MARK]
    for line in text.splitlines():
        if line.startswith(SCRIPT_MARK):
            continue
        m = re.match(r"^(Exec|TryExec)\s*=\s*(.*)$", line)
        if m and m.group(1) == "TryExec":
            line = f"TryExec={script}"
        elif m:
            try:
                words = shlex.split(m.group(2))
            except ValueError:
                words = m.group(2).split()
            i = 0
            if words and Path(words[0]).name == "env":
                i = 1
                while i < len(words) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*|-.*", words[i]):
                    i += 1
            rest = words[i + 1:]
            extra = [] if profile is None or any(w in ("-P", "--ProfileManager", "-ProfileManager", "--profile",
                                                       "-profile") for w in rest) else ["--profile", str(profile)]
            line = "Exec=" + " ".join(quote(w) for w in [*words[:i], script, *extra, *rest])
        out.append(line)
    return "\n".join(out) + "\n"


@dataclass
class SkippedScript:
    name: str
    entry: Path                 # the menu entry the desktop uses now
    source: Path                # the entry the app's own is made from: that one, or the package's under the app's
    launcher: Path | None       # the program it runs (None: the app's entry, out of date)
    script: Path
    profile: Path | None
    old_cache: Path | None      # the local cache it kept in the shared one (~/.cache/mullvad/mullvadbrowser)

    @property
    def stale(self) -> bool:
        return self.launcher is None


def skipped_scripts(scan: Scan, found: list[FoundBrowser]) -> list[SkippedScript]:
    """Tor Browser and Mullvad Browser menu entries that start the browser without its start script, and the app's own
    entries made from a package's that has changed since (out of date)."""
    host, out = scan.host, []
    for name, entry, below in effective_entries(scan, found):
        text = read_text(host, entry) or ""
        if text.startswith(SCRIPT_MARK) and below is not None:
            script = next((on_host(host, m.group(1) or m.group(2)) for m in START_SCRIPT.finditer(_entry_exec(scan, entry))),
                          None)
            if script is None or not isfile(script):
                continue
            prof = default_profile(host, profile_root(host, script.parent))
            want = started_by_script(read_text(host, below) or "", real_path(host, script), prof)
            if want != text:
                out.append(SkippedScript(name, entry, below, None, script, prof, None))
            continue
        skipped = _skipped_script(scan, _entry_program(scan, _entry_exec(scan, entry)))
        if skipped is None:
            continue
        launcher, script, name = skipped
        root = profile_root(host, script.parent)
        cache = Path(host.environ.get("XDG_CACHE_HOME") or host.home / ".cache") / root.parent.name.lstrip(".") / root.name \
            if root is not None else None
        out.append(SkippedScript(name, entry, entry, launcher, script, default_profile(host, root),
                                 cache if cache is not None and isdir(cache) and not cache.is_symlink() else None))
    return out


# where a browser keeps the graphics driver's cache itself: a Flatpak's and a Snap's in folders of their own; any other
# install (a package, an AppImage, one in the account) in the one every program shares
OWN_CACHE_INSTALLS = frozenset({"Flatpak", "Snap"})


def cache_sharing_browsers(everything: list[FoundBrowser]) -> list[str]:
    """The browsers here, other than Tor Browser and Mullvad Browser, installed so that they keep the graphics driver's
    shader cache in the folder every program shares: a website can have a shader compiled in one and time it in a
    Tor Browser or Mullvad Browser started without its script (tested on the lab against Mullvad Browser 15: Firefox ESR
    153 linked in all 6 runs, both ways; the regular Firefox 159 once in 12, Mozilla's build and CachyOS's package;
    which builds link depends on how each hands Mesa its shaders)."""
    return [f.name for f in everything if f.key not in SHADER_BROWSERS and set(f.installs) - OWN_CACHE_INSTALLS]


@register
class StartScript(Check):
    id = "br.start_script"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError
        host = scan.host
        try:
            everything = installed_browsers(scan)
        except DataError as e:
            return unknown(f"The app's list of browsers couldn't be read: {e}")
        found = [f for f in everything if f.key in SHADER_BROWSERS]
        if not found:
            return absent("Neither Tor Browser nor Mullvad Browser is installed.")
        skipped = skipped_scripts(scan, found)
        ev = []
        for name, entry, _ in effective_entries(scan, found):
            ev.append(Evidence.path(f"{name}'s menu entry", host.display(entry)))
        for s in skipped:
            if s.stale:
                ev.append(Evidence.val(f"{s.name}: the menu entry the app made", "out of date: the package's has "
                                                                                    "changed since"))
            else:
                ev.append(Evidence.val(f"{s.name} is started by", f"{host.display(s.launcher)}, which skips "
                                                                  f"{host.display(s.script)}"))
            if s.old_cache is not None:
                ev.append(Evidence.val(f"{s.name}'s cache in yours ({host.display(s.old_cache)})",
                                       tally(s.old_cache, limit=20_000).describe()))
        notes = [Note("info", "What the start script does",
                      "Tor Browser and Mullvad Browser start through a script of their own, which gives the browser "
                      + "; ".join(SCRIPT_PROTECTIONS) + ".", ("br.shader_cache", "desk.recent_files"))]
        bypass = [s for s in skipped if not s.stale]
        others = cache_sharing_browsers(everything) if bypass else []
        findings = {"shares_cache_with_browser": bool(others)}
        if bypass:
            names = " and ".join(dict.fromkeys(s.name for s in bypass))
            one = len(dict.fromkeys(s.name for s in bypass)) == 1
            if others:
                listed = ", ".join(others[:-1]) + (" and " if len(others) > 1 else "") + others[-1]
                ev.append(Evidence.val("Shares the graphics cache with", listed))
                notes.insert(0, Note("risk", "Linked with your other browsers",
                                     f"Started this way, {names} keeps the graphics driver's shader cache in the same "
                                     f"folder as {listed}. A website can have a shader of its own compiled in one "
                                     "browser and time the same shader in the other: ready much sooner, it shows the "
                                     "same computer, and links your private visits to your everyday ones. In the "
                                     "app's tests, between Mullvad Browser and Firefox ESR, a site found its shader "
                                     "ready in about 115 ms instead of 830, every time and both ways; with the "
                                     "regular Firefox release, now and then. Whether two browsers link depends on how "
                                     "each is built, so every browser that shares the cache counts."))
                return failed(f"{names} {'is' if one else 'are'} started without {'its' if one else 'their'} own start "
                              f"script: websites can link your visits in {'it' if one else 'them'} to your visits in "
                              f"{listed} through the graphics cache they share, and files you save or upload through "
                              f"{'it' if one else 'them'} are listed in your desktop's recent files.", *ev, notes=notes,
                              findings=findings)
            return failed(f"{names} {'is' if one else 'are'} started without {'its' if one else 'their'} own start "
                          "script: its shader cache is the one every program shares, where another browser could later "
                          "link your visits, and files you save or upload through it are listed in your desktop's "
                          "recent files.", *ev, notes=notes, findings=findings)
        if skipped:
            return failed(f"The menu entry the app made for {' and '.join(dict.fromkeys(s.name for s in skipped))} is "
                          "out of date: the package's own has changed since.", *ev, notes=notes, findings=findings)
        return passed("Tor Browser and Mullvad Browser start through their own start scripts.", *ev, notes=notes,
                      findings=findings)


# ------------------------------------------------------------------ the graphics drivers' shader caches

# what turns each driver's disk cache off for the whole session, and the values it reads as that: NVIDIA's
# __GL_SHADER_DISK_CACHE is a boolean (0 off); Mesa's MESA_SHADER_CACHE_DISABLE (MESA_GLSL_CACHE_DISABLE, its older
# name, which Mesa 25 still reads) is true to turn it off. The fix doesn't set them (it would cost every game and 3D
# program its cache): it blocks the cache of each browser alone
NVIDIA_CACHE, MESA_CACHE = "__GL_SHADER_DISK_CACHE", "MESA_SHADER_CACHE_DISABLE"
# Mesa's cache folders in $XDG_CACHE_HOME or $HOME/.cache (the single-file database's too): a file in a folder's
# place and Mesa runs without one ("Cannot use … for shader cache (not a directory)---disabling", Mesa 25 and 26)
MESA_CACHE_DIRS = ("mesa_shader_cache", "mesa_shader_cache_db")
SHADER_BLOCK_TEXT = ("DA Privacy Kit: while this file is here, Mesa keeps no shader cache for this browser, which "
                     "websites could time to link visits. Delete it to let Mesa keep one here again.\n")
MESA_LIBS = ("libGLX_mesa.so.0", "libEGL_mesa.so.0")
LIB_DIRS = ("/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib", "/usr/lib/aarch64-linux-gnu")
EGL_VENDORS = "/usr/share/glvnd/egl_vendor.d"


def _cache_off(env: dict[str, str], var: str) -> bool:
    v = env.get(var, "").strip().lower()
    if var == NVIDIA_CACHE:
        return v in ("0", "false", "no", "off")
    return v in ("1", "true", "yes", "y") or (var == MESA_CACHE and _cache_off(env, "MESA_GLSL_CACHE_DISABLE"))


def nvidia_loaded(host) -> bool:
    return host.sys_path("/proc/driver/nvidia/version").exists() or isdir(host.sys_path("/sys/module/nvidia"))


def mesa_installed(host) -> bool:
    if any("mesa" in p.name and p.suffix == ".json" for p in children(host.sys_path(EGL_VENDORS))):
        return True
    return any(host.sys_path(f"{d}/{lib}").exists() for d in LIB_DIRS for lib in MESA_LIBS)


def mesa_blocked(c: BrowserCopy) -> bool:
    """Whether Mesa can keep no cache for this copy: a file (or anything but a folder) where each of its cache
    folders would be, in the copy's own cache folder."""
    return c.cache is not None and all(os.path.lexists(c.cache / d) and not isdir(c.cache / d) for d in MESA_CACHE_DIRS)


def mesa_old_caches(c: BrowserCopy) -> list[tuple[Path, Tally]]:
    """Mesa's cache folders already in a copy's own cache folder (from before the session set XDG_CACHE_HOME too)."""
    out, bases = [], []
    if c.cache is not None:
        bases.append(c.cache)
    elif c.launcher is None:
        bases.append(c.own / ".cache")
    for base in bases:
        for d in MESA_CACHE_DIRS:
            root = base / d
            if isdir(root) and not root.is_symlink():
                out.append((root, tally(root, limit=20_000)))
    return out


@register
class ShaderCache(Check):
    id = "br.shader_cache"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError
        host = scan.host
        try:
            found = [f for f in installed_browsers(scan) if f.key in SHADER_BROWSERS]
        except DataError as e:
            return unknown(f"The app's list of browsers couldn't be read: {e}")
        copies = shader_copies(scan, found)
        names = list(dict.fromkeys([SHADER_BROWSERS[f.key] for f in found] + [c.name for c in copies]))
        if not names:
            return absent("Neither Tor Browser nor Mullvad Browser is installed (Tor or Mullvad Browser in memory, "
                          "in the Tools, keeps no shader cache).")
        ev = [Evidence.val(f.name, f.describe()) for f in found]
        on: list[str] = []                        # the browsers whose cache a driver keeps
        drivers_on: set[str] = set()
        old: list[tuple[BrowserCopy, Path, Tally]] = []
        mesa, nvidia = mesa_installed(host), nvidia_loaded(host)
        mesa_off, nvidia_off = _cache_off(host.environ, MESA_CACHE), _cache_off(host.environ, NVIDIA_CACHE)
        if mesa:
            ev.append(Evidence.val("Mesa (Intel and AMD graphics, and drawing in software)",
                                   f"its shader cache off for every program ({MESA_CACHE}={host.environ[MESA_CACHE]})"
                                   if mesa_off else "installed"))
        if nvidia:
            ev.append(Evidence.val("NVIDIA's driver", f"its shader cache off for every program ({NVIDIA_CACHE}="
                                                       f"{host.environ[NVIDIA_CACHE]})" if nvidia_off else "loaded"))
        for c in copies:
            where = host.display(c.script) if c.script else c.name
            states = []
            caches = mesa_old_caches(c)
            if mesa and not mesa_off:
                if c.launcher is not None:
                    states.append("Mesa's cache on, the one every program shares (started without its start script)")
                elif c.cache is None:
                    states.append("Mesa's cache on, the one every program shares (your session sets XDG_CACHE_HOME)")
                elif mesa_blocked(c):
                    states.append("Mesa's cache blocked for it")
                else:
                    states.append("Mesa's cache on, in its own folder")
                if states[-1].startswith("Mesa's cache on"):
                    on.append(c.name)
                    drivers_on.add("Mesa")
            elif caches:
                old += [(c, r, t) for r, t in caches]
            if nvidia and not nvidia_off:
                if c.turns_off_nvidia(host):
                    states.append("NVIDIA's cache off in its " + ("start script" if c.launcher is None else "package's program"))
                else:
                    states.append("NVIDIA's cache on")
                    on.append(c.name)
                    drivers_on.add("NVIDIA")
            for r, t in caches:
                ev.append(Evidence.val(f"{c.name}'s shader cache ({host.display(r)})", t.describe()))
            if states:
                ev.append(Evidence.val(f"{c.name} ({where})", "; ".join(states)))
        unplaced = [n for n in names if not any(c.name == n for c in copies)]
        if unplaced and ((mesa and not mesa_off) or (nvidia and not nvidia_off)):
            on += unplaced                        # a copy the app couldn't find: as far as it can tell, on
            drivers_on |= {d for d, used in (("Mesa", mesa and not mesa_off), ("NVIDIA", nvidia and not nvidia_off)) if used}
            ev += [Evidence.val(n, "where it is installed couldn't be found: its cache counts as on") for n in unplaced]
        notes = [Note("info", "How a cache links visits",
                      "A website can have the graphics driver compile a shader of its own and time it: one from the "
                      "cache is ready much sooner, which tells a second site, or the same one after New Identity or a "
                      "restart, that this computer has drawn it before. Tor Browser's and Mullvad Browser's start "
                      "scripts turn NVIDIA's cache off, not Mesa's. At Tor Browser's Safest level JavaScript, and "
                      "with it WebGL, is off. Tor or Mullvad Browser in memory, in the Tools, starts them with both "
                      "caches off.")]
        if any(c.launcher is not None for c in copies) and mesa and not mesa_off:
            notes.append(Note("risk", "Started without its start script",
                              "A browser started without its own start script keeps Mesa's cache with every other "
                              "program's, your other browsers included, where a website can link your visits across "
                              "them and where it can't be blocked for the browser alone. Fix that first: then this "
                              "check's fix blocks it in the browser's own folder.", ("br.start_script",)))
        if host.environ.get("XDG_CACHE_HOME") and mesa and not mesa_off and any(c.cache is None and c.launcher is None
                                                                              for c in copies):
            notes.append(Note("limitation", "Its cache is shared with your other programs",
                              "Your session sets XDG_CACHE_HOME, so Mesa keeps the browsers' shaders in "
                              f"{host.display(Path(host.environ['XDG_CACHE_HOME']))}/mesa_shader_cache with every other "
                              "program's, where the app can't block it for the browsers alone. Turning it off for every "
                              f"program is the way left: {MESA_CACHE}=true in ~/.config/environment.d (KDE Plasma, "
                              "GNOME) and `export MESA_SHADER_CACHE_DISABLE=true` in ~/.profile (Cinnamon), from your "
                              "next login; games and other 3D programs then work out their graphics again each time "
                              "they start."))
        on = list(dict.fromkeys(on))
        findings = {"old_shader_cache_only": not on and bool(old)}
        if on:
            drivers = " and ".join(d for d in ("Mesa", "NVIDIA") if d in drivers_on)
            return warned(f"Websites could link your visits in {' and '.join(on)}: the graphics driver ({drivers}) "
                          "keeps the shaders pages hand it in a cache on the disk.", *ev, notes=notes, findings=findings)
        if old:
            return warned(f"The graphics drivers' shader caches are off, but the old one is still on the disk: "
                          f"{', '.join(dict.fromkeys(c.name for c, _, _ in old))}.", *ev, notes=notes, findings=findings)
        if not (mesa or nvidia):
            return passed("No graphics driver with a shader cache was found.", *ev, notes=notes, findings=findings)
        return passed(f"The graphics drivers keep no shader cache for {' and '.join(names)}.", *ev, notes=notes,
                      findings=findings)
