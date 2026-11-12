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
    """Every Firefox-family profile and Chromium-family user data folder of the browsers in browsers.yaml's registry
    (Firefox, LibreWolf, Waterfox, Zen, Floorp; Chrome, Chromium, Brave, Edge, Vivaldi, Opera, Helium...)."""
    from ..browsers import family_names
    firefox = mozilla_profiles(scan.host, scan.paths, family_names("mozilla"))
    chromium = [(d, chromium_profiles(d)) for d in chromium_dirs(scan.paths)]
    return firefox, [(d, p) for d, p in chromium if p]


# ------------------------------------------------------------------ what the checks read, and each browser's defaults

def _browser_of(p: MozProfile | BrowserDir):
    """The browsers.yaml entry of a profile (by its folder's name), or None (Thunderbird)."""
    from ..browsers import load
    return load().by_folder(p.app if isinstance(p, MozProfile) else p.browser)


def ff_value(p: MozProfile, prefs: dict, key: str):
    """A Firefox-family pref as the profile has it: its own prefs.js/user.js value, else what this browser ships
    (browsers.yaml `defaults`, a fork's own then Firefox's where it inherits them), else browsers.UNKNOWN."""
    from ..browsers import UNKNOWN, load
    if key in prefs:
        return prefs[key]
    b = _browser_of(p)
    return load().default(b.id, key) if b else UNKNOWN


def chromium_default(d: BrowserDir, key: str, installed: set[str] | None = None):
    """What the browser using a Chromium-family folder ships a setting as (browsers.yaml `defaults`), or UNKNOWN.
    A folder several browsers share (~/.config/chromium: Chromium, ungoogled-chromium, Cromite) goes by the one
    installed here, when only one of them is; with several, a default they don't agree on is UNKNOWN."""
    from ..browsers import UNKNOWN, load
    data = load()
    ids = list(d.ids) or [b.id for b in [_browser_of(d)] if b]
    if installed is not None and len(ids) > 1:
        ids = [i for i in ids if i in installed] or ids
    values = [data.default(i, key) for i in ids]
    if not values or any(v is UNKNOWN for v in values) or any(v != values[0] for v in values):
        return UNKNOWN
    return values[0]


def ff_policies(scan: Scan, p: MozProfile) -> dict:
    """The policies a Firefox-family profile's browser obeys: /etc/firefox's and the install's own policies.json are
    Firefox's, read by its native install and its Snap; never its Flatpak's, nor LibreWolf's or another fork's."""
    return firefox_policies(scan.host) if p.app == "Firefox" and p.install in ("native", "snap") else {}


def chromium_policy(scan: Scan, d: BrowserDir) -> dict:
    """The managed policies a Chromium-family browser obeys: /etc's, for a native install only (a Flatpak or Snap
    doesn't read them)."""
    return chromium_policies(scan.host, d.browser) if d.root.install == "native" else {}


def chromium_version(d: BrowserDir) -> tuple[int, ...] | None:
    """The version that last ran in a Chromium-family user data folder: its `Last Version` file."""
    from ..appversions import parse_version
    text = read_text_quiet(d.root.path / "Last Version")
    return parse_version(text) if text else None


def read_text_quiet(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:200]
    except OSError:
        return None


def installed_ids(scan: Scan) -> set[str]:
    """The browsers.yaml ids of the browsers installed here."""
    from ..vpn import DataError
    try:
        return {f.browser.id for f in installed_browsers(scan) if f.browser is not None}
    except DataError:
        return set()


def coverage(scan: Scan, firefox: list[MozProfile], chromium) -> tuple[list[Note], bool, list[str]]:
    """What the profile checks didn't read: (notes, whether a browser here wasn't checked at all, the names of the
    installed browsers the app has no reader for). An installed browser the app doesn't know, or one with no reader,
    is never passed over in silence; one whose profiles weren't where they go hasn't been used yet, or keeps them
    elsewhere."""
    from ..vpn import DataError
    try:
        found = installed_browsers(scan)
    except DataError:
        return [], False, []
    read = {b.id for b in (_browser_of(p) for p in firefox) if b} | {i for d, _ in chromium for i in d.ids}
    unknown_names, by_design, unused = [], [], []
    for f in found:
        b = f.browser
        if b is None:
            unknown_names.append(f.name)
        elif b.unchecked:
            by_design.append((b.name, b.unchecked))
        elif b.id not in read:
            where = ", ".join(dict.fromkeys(
                "~/" + p for fo in b.folders for p in (fo.home, fo.config and f".config/{fo.config}") if p))
            unused.append(f"{b.name} ({where})" if where else b.name)
    notes = []
    if unknown_names:
        notes.append(Note("limitation", "Not checked: a browser the app doesn't know",
                          f"{', '.join(dict.fromkeys(unknown_names))}: the app doesn't know where "
                          f"{'this browser keeps' if len(unknown_names) == 1 else 'these browsers keep'} its settings, so "
                          "they aren't part of this result. Check the same setting in its own settings page."))
    if unused:
        notes.append(Note("info", "Not used yet",
                          f"{'; '.join(dict.fromkeys(unused))}: installed, but no profile was found where it keeps "
                          "them. It hasn't been opened yet, or keeps them somewhere this version of the app doesn't "
                          "look: once you use it, scan again."))
    for name, why in dict.fromkeys(by_design):
        notes.append(Note("info", f"{name} isn't read", why))
    return notes, bool(unknown_names), unknown_names


class ProfileCheck(Check):
    """A check of every browser profile's settings: `judge` sees the profiles read; what wasn't (an installed browser
    the app doesn't know, one not used yet) is said in a note, never in silence, and a pass then doesn't stand for
    a browser it didn't read."""

    def detect(self, scan: Scan) -> Outcome:
        firefox, chromium = _browsers(scan)
        notes, unread, names = coverage(scan, firefox, chromium)
        if not firefox and not chromium:
            if unread:
                return unknown(f"Couldn't check {', '.join(dict.fromkeys(names))}: the app doesn't know where "
                               f"{'it keeps' if len(names) == 1 else 'they keep'} {'its' if len(names) == 1 else 'their'} "
                               "settings.", notes=notes)
            return absent("No browser profiles were found.", notes=notes)
        out = self.judge(scan, firefox, chromium)
        out.notes = [*out.notes, *notes]
        out.partial = out.partial or unread
        return out

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        raise NotImplementedError


def default_unknown(label: str, what: str) -> Evidence:
    return Evidence.val(label, f"couldn't tell: {what} isn't set in the profile, and the app doesn't know this "
                               "browser's default")


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
    from ..browsers import family_names
    roots: dict[Path, MozProfile] = {}
    for p in mozilla_profiles(scan.host, scan.paths, (*family_names("mozilla"), "Thunderbird")):
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
class ExtensionsBroad(ProfileCheck):
    id = "br.extensions_broad"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
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
        reads_policy = bool(ff_policies(scan, p))
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
        policy = chromium_policy(scan, d)
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
class VpnExtensions(ProfileCheck):
    id = "br.vpn_extensions"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        from ..vpn import DataError, rate
        from .network import cite
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


def _ff_clears_history(prefs: dict, policies: dict, p: MozProfile | None = None) -> bool | None:
    """Whether a Firefox-family profile clears its history as it closes; None when a default it rests on isn't known
    for this browser. Without a profile, Firefox's own defaults."""
    from ..browsers import UNKNOWN, load
    get = (lambda k: ff_value(p, prefs, k)) if p is not None else \
        (lambda k: prefs[k] if k in prefs else load().default("firefox", k))  # noqa: E731
    autostart = get("browser.privatebrowsing.autostart")
    if autostart is True:
        return True
    sanitize = policies.get("SanitizeOnShutdown")
    if sanitize is True or (isinstance(sanitize, dict) and sanitize.get("History")):
        return True
    on = get("privacy.sanitize.sanitizeOnShutdown")
    if on is True:
        history = get(ff_history_pref(prefs))
        return None if history is UNKNOWN else history is True
    return None if UNKNOWN in (on, autostart) else False


# Brave's own "Clear browsing data on exit" (brave://settings/clearBrowserData, On exit), all off by default (brave-core
# chromium_src/components/browsing_data/core/pref_names.h)
BRAVE_ON_EXIT = "browser.clear_data.{}_on_exit"


@register
class HistoryRetention(ProfileCheck):
    id = "br.history_retention"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        ev, keeping, unsure = [], [], []
        installed = installed_ids(scan) if chromium else set()
        for p in firefox:
            clears = _ff_clears_history(firefox_prefs(scan.host, p.path), ff_policies(scan, p), p)
            if clears is None:
                ev.append(default_unknown(p.label, "whether it clears history as it closes"))
                unsure.append(p.label)
                continue
            ev.append(Evidence.val(p.label, "cleared when it closes" if clears else "kept until you clear it"))
            if not clears:
                keeping.append(p.label)
        for d, profiles in chromium:
            policy = chromium_policy(scan, d)
            days = chromium_default(d, "history_days", installed)
            kept = f"kept for {days} days" if isinstance(days, int) else "kept (for how long, the browser decides)"
            for prof in profiles:
                prefs = read_json(scan.host, prof / "Preferences") or {}
                brave = (lambda what, prefs=prefs: dig(prefs, *BRAVE_ON_EXIT.format(what).split(".")) is True) \
                    if d.browser.startswith("Brave") else (lambda what: False)  # noqa: E731
                if policy.get("ClearBrowsingDataOnExitList"):
                    state = "cleared when it closes (policy)"
                elif brave("browsing_history") and brave("cookies"):
                    state = "history, cookies and site data cleared when it closes"
                elif brave("browsing_history"):
                    state = "history cleared when it closes, cookies and site data kept"
                elif policy.get("DefaultCookiesSetting") == 4 or brave("cookies"):    # the policy wins over the profile
                    state = f"cookies cleared when it closes{' (policy)' if policy.get('DefaultCookiesSetting') == 4 else ''}, history {kept}"
                elif dig(prefs, "profile", "default_content_setting_values", "cookies") == 4:
                    state = f"cookies cleared when it closes, history {kept}"
                else:
                    state = f"history {kept}, cookies and site data until they expire"
                ev.append(Evidence.val(f"{d.label}, {prof.name}", state))
                if not state.startswith(("cleared when it closes", "history, cookies")) and \
                        not state.startswith("history cleared"):
                    keeping.append(f"{d.label}, {prof.name}")
        notes = [Note("info", "How long it is kept",
                      "Firefox-based browsers keep history until you clear it; Chromium-based ones delete what is older "
                      "than 90 days (Chromium's own rule), and keep cookies until each expires.")] \
            if chromium and keeping else []
        if keeping:
            return failed(f"Browsing history and site data are kept on the disk in {len(keeping)} profile"
                          f"{'s' if len(keeping) > 1 else ''}.", *ev, notes=notes)
        if unsure:
            return unknown(f"Couldn't tell whether {', '.join(unsure)} clear{'s' if len(unsure) == 1 else ''} history "
                           "as it closes.", *ev)
        return passed("Browsers clear history when they close.", *ev)


@register
class TrackingProtection(ProfileCheck):
    id = "br.tracking_protection"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        from ..browsers import UNKNOWN
        ev, weak, custom, unsure = [], [], [], []
        for p in firefox:
            cat = ff_value(p, firefox_prefs(scan.host, p.path), "browser.contentblocking.category")
            if cat is UNKNOWN:
                ev.append(default_unknown(p.label, "Enhanced Tracking Protection"))
                unsure.append(p.label)
                continue
            ev.append(Evidence.val(p.label, f"Enhanced Tracking Protection: {cat}"))
            if cat == "custom":
                custom.append(p.label)
            elif cat != "strict":
                weak.append(p.label)
        for d, profiles in chromium:
            policy = chromium_policy(scan, d)
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
        if unsure:
            return unknown(f"Couldn't tell how strict tracking protection is in {', '.join(unsure)}.", *ev)
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
class DiskCache(ProfileCheck):
    id = "br.disk_cache"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        from ..browsers import UNKNOWN
        # profile-sync-daemon isn't counted: it keeps profiles in memory for speed but writes them back to the
        # disk regularly, and caches (in ~/.cache) aren't part of the profiles it moves
        ev, on_disk, left, unsure = [], [], [], []
        for p in firefox:
            prefs = firefox_prefs(scan.host, p.path)
            cache = ff_value(p, prefs, "browser.cache.disk.enable")
            level = ff_value(p, prefs, "browser.sessionstore.privacy_level")
            level = "unknown" if level is UNKNOWN else level
            if cache is UNKNOWN:
                ev.append(default_unknown(p.label, "the disk cache"))
                unsure.append(p.label)
                continue
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
        if unsure:
            return unknown(f"Couldn't tell whether {', '.join(unsure)} keep{'s' if len(unsure) == 1 else ''} a cache on "
                           "the disk.", *ev, notes=notes)
        return passed("Browser caches are kept in memory; the session store is still written to the profile.", *ev,
                      notes=notes)


# Chromium's WebRTC IP handling policies (webrtc_ip_handling_policy.h): "default" uses every interface but shows a
# website no local address (an mDNS name instead) until it is allowed the camera or microphone; the last two keep to
# the default route, without its local address. default_public_and_private_interfaces shows that local address.
SAFE_WEBRTC = {"default", "default_public_interface_only", "disable_non_proxied_udp"}
SHOWS_LOCAL = "default_public_and_private_interfaces"
WEBRTC_WORDS = {"default": "local addresses hidden from websites (the default)",
                "default_public_interface_only": "limited to the default route",
                "disable_non_proxied_udp": "limited to the proxy or the default route",
                SHOWS_LOCAL: "shows websites this computer's local address"}


def firefox_webrtc(p: MozProfile, prefs: dict) -> tuple[bool | None, str]:
    """(whether WebRTC keeps local addresses and the proxy's way in a Firefox-family profile, in words); None when a
    default it rests on isn't known. Firefox shows a website mDNS names instead of local addresses
    (media.peerconnection.ice.obfuscate_host_addresses, on by default), and only the default route's until it is
    allowed the camera or microphone (PeerConnectionImpl.cpp); a proxy set by hand is gone round by its UDP unless
    proxy_only_if_behind_proxy keeps it to the proxy."""
    from ..browsers import UNKNOWN
    get = lambda k: ff_value(p, prefs, k)  # noqa: E731
    if get("media.peerconnection.enabled") is False:
        return True, "WebRTC off"
    proxy = prefs.get("network.proxy.type") == 1 and any(prefs.get(f"network.proxy.{k}") for k in ("socks", "http"))
    behind = get("media.peerconnection.ice.proxy_only_if_behind_proxy")
    if proxy and behind is not True:
        return (None, "a proxy is set, and whether WebRTC keeps to it couldn't be told") if behind is UNKNOWN else \
            (False, "goes around the proxy you set: websites can see your own address")
    if get("media.peerconnection.ice.default_address_only") is True:
        return True, "limited to the default route"
    hidden = get("media.peerconnection.ice.obfuscate_host_addresses")
    if hidden is UNKNOWN:
        return None, "couldn't tell whether local addresses are hidden from websites (its default isn't known)"
    return (True, "local addresses hidden from websites (the default)") if hidden else \
        (False, "shows websites this computer's local addresses")


@register
class Webrtc(ProfileCheck):
    id = "br.webrtc"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        from ..browsers import UNKNOWN
        ev, exposed, unsure = [], [], []
        for p in firefox:
            ok, text = firefox_webrtc(p, firefox_prefs(scan.host, p.path))
            ev.append(Evidence.val(p.label, text))
            if ok is False:
                exposed.append(p.label)
            elif ok is None:
                unsure.append(p.label)
        installed = installed_ids(scan) if chromium else set()
        for d, profiles in chromium:
            policy = chromium_policy(scan, d).get("WebRtcIPHandling")
            for prof in profiles:
                value = policy or dig(read_json(scan.host, prof / "Preferences") or {}, "webrtc", "ip_handling_policy")
                own = value is None
                if own:
                    value = chromium_default(d, "webrtc.ip_handling_policy", installed)
                label = f"{d.label}, {prof.name}"
                if value is UNKNOWN:
                    # every policy but one keeps local addresses from websites, and that one is never a default: what
                    # isn't set is the browser's own, which is said as it is
                    ev.append(Evidence.val(label, "not set: the browser's own default"))
                    continue
                ev.append(Evidence.val(label, value))
                if value == SHOWS_LOCAL:
                    exposed.append(label)
                elif value not in SAFE_WEBRTC:
                    unsure.append(label)
        notes = [Note("info", "What websites still see",
                      "A site you allow to use the camera or microphone sees this computer's local addresses, as a call "
                      "needs them. Every site sees the public address your traffic leaves from: the VPN's, when a VPN "
                      "carries all your traffic.", ("net.vpn_leaks",))]
        if exposed:
            return failed(f"WebRTC shows websites your local address, or goes around your proxy, in {', '.join(exposed)}.",
                          *ev, notes=notes)
        if unsure:
            return unknown(f"Couldn't tell what WebRTC shows websites in {', '.join(unsure)}.", *ev, notes=notes)
        return passed("No browser profile is set to show websites your local addresses.", *ev, notes=notes)


# ------------------------------------------------------------------ HTTPS-Only Mode

HTTPS_ONLY_PREF = "dom.security.https_only_mode"
# Brave's own setting (Shields, "Upgrade connections to HTTPS"), a content setting's default: 2 Strict (asks first),
# 1 Disabled, and no entry at all for Standard (its default: falls back to HTTP). Set through brave://settings/shields
# on Brave 1.97 (Chromium 155) and read back: profile.default_content_setting_values.httpsUpgrades. Chromium's own
# page writes https_only_mode_enabled (seen on Chromium 153, with https_first_balanced_mode_enabled beside it).
BRAVE_HTTPS_STRICT = 2


def firefox_https_only(prefs: dict, app: str | MozProfile, policy) -> tuple[bool | None, str]:
    """(asks before an unencrypted page, in words; None when this browser's default isn't known). LibreWolf ships with
    it on (its policies.json); Firefox and the other forks with it off."""
    from ..browsers import UNKNOWN, load
    if policy in ("enabled", "force_enabled"):
        return True, "HTTPS-Only Mode on (a policy)"
    if isinstance(app, MozProfile):
        value = ff_value(app, prefs, HTTPS_ONLY_PREF)
    else:
        b = load().by_folder(app)
        value = prefs[HTTPS_ONLY_PREF] if HTTPS_ONLY_PREF in prefs else load().default(b.id, HTTPS_ONLY_PREF) if b \
            else UNKNOWN
    if value is True:
        return True, "HTTPS-Only Mode on" + ("" if HTTPS_ONLY_PREF in prefs else " (as the browser ships)")
    if prefs.get(HTTPS_ONLY_PREF + "_pbm") is True:
        return False, "HTTPS-Only Mode in private windows only"
    if value is UNKNOWN:
        return None, "couldn't tell: not set in the profile, and the app doesn't know this browser's default"
    return False, "HTTPS-Only Mode off"


def chromium_https_default(d: BrowserDir, installed: set[str] | None = None) -> tuple[bool | None, str]:
    """What "Always use secure connections" is in a Chromium-family profile that hasn't set it: the browser's default
    (browsers.yaml https_upgrades), by the version that last ran there (its Last Version). Chrome 157 and Chromium 157
    turn it on for public sites by default (kHttpsFirstBalancedModeAutoEnable), without writing it into Preferences;
    Chrome 154 to 156 had it on for some people through Google's field trials."""
    from ..browsers import UNKNOWN
    table = chromium_default(d, "https_upgrades", installed)
    if table is UNKNOWN or not isinstance(table, dict):
        return None, "Always use secure connections: not set, and the app doesn't know this browser's default"
    mode = table.get("mode")
    on = "on" if mode == "strict" else "on for public sites"
    if "from" not in table:
        return mode in ("strict", "balanced"), f"Always use secure connections: {on} (as the browser ships)"
    version = chromium_version(d)
    if version is None:
        return None, "Always use secure connections: not set, and which version last ran here couldn't be read"
    major = version[0]
    if major >= table["from"]:
        return True, f"Always use secure connections: {on} (the default from version {table['from']})"
    if "trial_from" in table and major >= table["trial_from"]:
        return None, (f"Always use secure connections: not set; in version {major} its maker turns it on for some "
                      "people and not others")
    return False, "Always use secure connections: off"


def chromium_https_only(browser: str | BrowserDir, prefs: dict, policy,
                        installed: set[str] | None = None) -> tuple[bool | None, str]:
    d = browser if isinstance(browser, BrowserDir) else None
    name = d.browser if d else browser
    if name.startswith("Brave"):
        setting = dig(prefs, "profile", "default_content_setting_values", "httpsUpgrades")
        if setting is None:               # where its source suggests an every-site rule would be; not seen written
            setting = dig(prefs, "profile", "content_settings", "exceptions", "httpsUpgrades", "*,*", "setting")
        if setting == BRAVE_HTTPS_STRICT:
            return True, "Upgrade connections to HTTPS: Strict"
        return False, "Upgrade connections to HTTPS: " + ("off" if setting == 1 else "Standard (falls back to HTTP)")
    if policy in ("force_enabled", "force_balanced_enabled"):
        return True, "Always use secure connections: on (a policy)"
    if policy == "disallowed":
        return False, "Always use secure connections: off (a policy)"
    strict, balanced = prefs.get("https_only_mode_enabled"), prefs.get("https_first_balanced_mode_enabled")
    if strict is True:
        return True, "Always use secure connections: on"
    if balanced is True:
        return True, "Always use secure connections: on for public sites"
    if strict is False or balanced is False or d is None:
        return False, "Always use secure connections: off"
    return chromium_https_default(d, installed)


@register
class HttpsOnly(ProfileCheck):
    id = "br.https_only"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        ev, silent, unsure = [], [], []
        for p in firefox:
            ok, text = firefox_https_only(firefox_prefs(scan.host, p.path), p, ff_policies(scan, p).get("HttpsOnlyMode"))
            ev.append(Evidence.val(p.label, text))
            if ok is False:
                silent.append(p.label)
            elif ok is None:
                unsure.append(p.label)
        installed = installed_ids(scan) if chromium else set()
        for d, profiles in chromium:
            policy = chromium_policy(scan, d).get("HttpsOnlyMode")
            for prof in profiles:
                ok, text = chromium_https_only(d, read_json(scan.host, prof / "Preferences") or {}, policy, installed)
                ev.append(Evidence.val(f"{d.label}, {prof.name}", text))
                if ok is False:
                    silent.append(f"{d.label}, {prof.name}")
                elif ok is None:
                    unsure.append(f"{d.label}, {prof.name}")
        if silent:
            n = len(silent)
            return failed(f"{n} browser profile{'s open' if n > 1 else ' opens'} unencrypted pages without asking "
                          "first.", *ev)
        if unsure:
            return unknown(f"Couldn't tell whether {', '.join(unsure)} ask{'s' if len(unsure) == 1 else ''} before "
                           "opening an unencrypted page.", *ev)
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
    policy = ff_policies(scan, p).get("Permissions") or {}
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
    policy = chromium_policy(scan, d)
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
class SitePermissions(ProfileCheck):
    id = "br.site_permissions"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
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
    # "readable", "passphrase", "e2e", "account" (signed in without sync: Chrome keeps passwords, addresses and payment
    # methods in the account), "signed_in" (signed in, sync not set up, what it keeps there not known) or "off"
    state: str
    detail: str = ""


# sync.cached_passphrase_type: the proto's PassphraseType (components/sync/protocol/nigori_specifics.proto), which
# Chromium caches there: 1 implicit and 2 keystore (Google holds the key: it can read what is synced), 3 frozen implicit
# and 4 custom (a passphrase of the user's: end to end, IsExplicitPassphrase), 5 trusted vault (keys kept on the user's
# devices: Google calls it on-device encryption)
SYNC_PASSPHRASE = "cached_passphrase_type"
E2E_PASSPHRASES = (3, 4)
TRUSTED_VAULT = 5
# signed in without turning sync on, Chrome keeps these in the Google Account unless turned off for it (Chromium's
# IsTypeSelectedByDefaultInTransportMode: passwords, payments, addresses on; history and tabs off)
ACCOUNT_STORAGE = {"passwords": "passwords", "autofill": "addresses", "payments": "payment methods"}


def _account_types_off(prefs: dict) -> set[str]:
    """The data types turned off for the signed-in account (sync.selected_types_per_account: an entry per account,
    each type a boolean; a type missing is at its default, on)."""
    per = dig(prefs, "sync", "selected_types_per_account")
    off: set[str] = set()
    for entry in (per.values() if isinstance(per, dict) else ()):
        if isinstance(entry, dict):
            off |= {k for k in ACCOUNT_STORAGE if entry.get(k) is False}
    return off


def chromium_sync_state(d: BrowserDir, prefs: dict) -> tuple[str, str]:
    """(state, what is in words) of a Chromium-family profile's account: only whether one is signed in, never which."""
    accounts = prefs.get("account_info")
    signed_in = (bool(accounts) if isinstance(accounts, list) else False) or \
        bool(dig(prefs, "google", "services", "account_id"))
    setup = dig(prefs, "sync", "has_setup_completed") is True or dig(prefs, "sync", "requested") is True or \
        dig(prefs, "google", "services", "consented_to_sync") is True
    kind = dig(prefs, "sync", SYNC_PASSPHRASE)
    entered = dig(prefs, "sync", "encryption_bootstrap_token_per_account")
    if setup:
        if d.browser.startswith(E2E_SYNC_BROWSERS):
            return "e2e", "syncing, end-to-end encrypted"
        if kind in E2E_PASSPHRASES or (isinstance(entered, dict) and any(entered.values())):
            return "passphrase", "syncing with a sync passphrase (end-to-end encrypted)"
        if kind == TRUSTED_VAULT:
            return "readable", ("syncing (the provider can read what is synced; passwords may be kept with on-device "
                                "encryption, which it says it can't read)")
        return "readable", "syncing (the provider can read what is synced)"
    if not signed_in:
        return "off", "not signed in"
    b = _browser_of(d)
    if b is not None and b.id == "chrome" and not d.browser.startswith(E2E_SYNC_BROWSERS):
        kept = [w for k, w in ACCOUNT_STORAGE.items() if k not in _account_types_off(prefs)]
        if kept:
            return "account", (f"signed in, sync off: {', '.join(kept)} are kept in the Google Account, which Google can "
                               "read")
        return "off", "signed in, sync off, and nothing kept in the account"
    return "signed_in", "signed in, sync not set up (what the browser keeps in the account couldn't be told)"


def sync_states(scan: Scan) -> list[SyncState]:
    """Each browser profile's sync: whether the provider can read what it copies. Only whether an account is set
    up is read, never which."""
    firefox, chromium = _browsers(scan)
    out = []
    for p in firefox:
        signed_in = bool(firefox_prefs(scan.host, p.path).get("services.sync.username"))
        out.append(SyncState(p.label, p.app, "e2e" if signed_in else "off",
                             f"signed in to {'Firefox' if p.app == 'Firefox' else p.app} Sync (end-to-end encrypted)"
                             if signed_in else "not signed in"))
    for d, profiles in chromium:
        for prof in profiles:
            state, detail = chromium_sync_state(d, read_json(scan.host, prof / "Preferences") or {})
            out.append(SyncState(f"{d.label}, {prof.name}", d.browser, state, detail))
    return out


SYNC_WORDS = {"readable": "syncing (the provider can read what is synced)",
              "passphrase": "syncing with a sync passphrase (end-to-end encrypted)",
              "e2e": "syncing, end-to-end encrypted", "signed_in": "signed in, sync not set up", "off": "not signed in",
              "account": "signed in: passwords, addresses and payment methods kept in the account"}


@register
class AccountSync(ProfileCheck):
    id = "br.account_sync"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        states = sync_states(scan)
        ev = [Evidence.val(s.label, s.detail or SYNC_WORDS[s.state]) for s in states]
        readable = [s for s in states if s.state in ("readable", "account")]
        sealed = [s for s in states if s.state in ("e2e", "passphrase")]
        unsure = [s for s in states if s.state == "signed_in"]
        if readable:
            return failed(f"{len(readable)} profile{'s copy' if len(readable) > 1 else ' copies'} history, passwords or "
                          "other browsing data to an online account whose provider can read them.", *ev)
        if sealed:
            # end-to-end encrypted: the provider holds only what it can't read, so a risk, not a problem
            return warned(f"{len(sealed)} profile{'s copy' if len(sealed) > 1 else ' copies'} history, passwords or "
                          "tabs to an online account, end-to-end encrypted: the provider can't read them.", *ev,
                          notes=[Note("info", "What end-to-end encrypted sync still gives away",
                                      "The provider can't read what is synced, but it holds a copy, sees when and from "
                                      "where each device syncs, and anyone who learns the account's password (or the "
                                      "sync passphrase or code) can read everything. A strong password of its own, "
                                      "and two-step sign-in, keep it that way.")])
        if unsure:
            return unknown(f"{', '.join(s.label for s in unsure)}: signed in to an account without sync; what the "
                           "browser keeps in that account couldn't be told.", *ev)
        return passed("No browser profile syncs to an online account.", *ev)


# Features that report what you browse: (Chromium Preferences key or Firefox pref, what it does, and for Chromium the
# policy that turns it off for every user); each browser's default comes from browsers.yaml (`defaults`), or False for
# what no browser turns on by itself (the Privacy Sandbox, "Make searches and browsing better", Enhanced Safe Browsing).
# Only a setting that is on in the profile itself counts as a finding. A browser default is listed in a note: counting
# it would make every stock Firefox and Chrome profile a finding.
# The Privacy Sandbox keys are written only once the user answers Chrome's ad privacy notice; Google announced in
# October 2025 that it is retiring Topics, Protected Audience and Attribution Reporting, and Chrome 154 and later clear
# the keys (PrivacySandboxAdPrivacyUxDeprecation): they count where an older Chrome still has them on.
ENHANCED_SAFE_BROWSING = "enhanced Safe Browsing (sends URLs)"
CHROMIUM_AD_PREFS = (("privacy_sandbox.m1.topics_enabled", "ad topics from your history", "PrivacySandboxAdTopicsEnabled"),
                     ("privacy_sandbox.m1.fledge_enabled", "site-suggested ads", "PrivacySandboxSiteEnabledAdsEnabled"),
                     ("privacy_sandbox.m1.ad_measurement_enabled", "ad measurement", "PrivacySandboxAdMeasurementEnabled"),
                     # "Make searches and browsing better": the address of every page visited, sent to Google; off
                     # until turned on, and turned on with history sync (unified_consent_service.cc)
                     ("url_keyed_anonymized_data_collection.enabled", "the address of every page you visit, sent to "
                      "Google (\"Make searches and browsing better\")", "UrlKeyedAnonymizedDataCollectionEnabled"),
                     ("search.suggest_enabled", "search suggestions as you type", "SearchSuggestEnabled"),
                     # a policy with a value rather than false: SafeBrowsingProtectionLevel 1 is standard protection
                     ("safebrowsing.enhanced", ENHANCED_SAFE_BROWSING, ("SafeBrowsingProtectionLevel", 1)))
REGION = "region"           # on by default in some countries only (Firefox Suggest, sponsored shortcuts)
FIREFOX_AD_PREFS = (("browser.search.suggest.enabled", "search suggestions as you type", None),
                    ("browser.urlbar.suggest.quicksuggest.sponsored", "sponsored address bar suggestions", None),
                    ("browser.newtabpage.activity-stream.showSponsoredTopSites", "sponsored shortcuts on the new tab page",
                     None),
                    # Firefox Suggest's online part: what you type goes to Mozilla's servers (Merino)
                    ("browser.urlbar.quicksuggest.online.enabled", "what you type in the address bar, sent to Mozilla "
                     "for suggestions", None))
AD_DEFAULTS_HOW = ("Firefox: Settings → Search → \"Show search suggestions\"; Settings → Home → \"Sponsored shortcuts\"; "
                   "Settings → Privacy & Security → Address Bar → \"Suggestions from sponsors\" and \"Improve the Firefox "
                   "Suggest experience\". Chrome: Settings → You and Google → Sync and Google services → \"Improve search "
                   "suggestions\", \"Autocomplete searches and URLs\" and \"Make searches and browsing better\".")
AI_NOTE = Note("info", "AI features send what you ask, and the page",
               "Chrome's Gemini, \"Help me write\" and tab comparison, and Firefox's AI chatbot in the sidebar, send what "
               "you ask them, with the page or text you give them, to their provider when you use them. The app doesn't "
               "read their settings: to see them, type AI into the search box of the browser's settings page.")


def _ad_settings(prefs: dict, table, policy: dict, get, default) -> tuple[list[str], list[str], list[str]]:
    """(features turned on in the profile, features on only as the browser's default, features whose default isn't
    known for this browser)."""
    from ..browsers import UNKNOWN
    on, defaults, unsure = [], [], []
    for key, what, policy_name in table:
        name, off = policy_name if isinstance(policy_name, tuple) else (policy_name, False)
        now = policy.get(name) if name else None
        if now is not None and type(now) is type(off) and now == off:
            continue                                        # turned off for every user
        v = get(prefs, key)
        if v is True:
            on.append(what)
            continue
        if v is not None:
            continue
        d = default(key)
        if d is True:
            defaults.append(f"{what} (browser default)")
        elif d == REGION:
            defaults.append(f"{what} (browser default in some countries)")
        elif d is UNKNOWN:
            unsure.append(what)
    return on, defaults, unsure


# what no browser turns on by itself
CHROMIUM_OFF_UNLESS_SET = frozenset({k for k, _, _ in CHROMIUM_AD_PREFS} - {"search.suggest_enabled"})


def chromium_ad_states(scan: Scan, chromium) -> list[tuple[BrowserDir, Path, list[str], list[str]]]:
    """(browser folder, profile, features turned on, features on as the browser's default) of each Chromium-based
    profile but Brave's, which ships with the Privacy Sandbox and suggestions off."""
    return [(d, prof, on, defaults) for d, prof, on, defaults, _ in _chromium_ad_states(scan, chromium)]


def _chromium_ad_states(scan: Scan, chromium):
    out = []
    installed = installed_ids(scan) if chromium else set()
    for d, profiles in chromium:
        if d.browser.startswith("Brave"):
            continue
        policy = chromium_policy(scan, d)

        def default(key, d=d):
            return False if key in CHROMIUM_OFF_UNLESS_SET else chromium_default(d, key, installed)
        for prof in profiles:
            out.append((d, prof, *_ad_settings(read_json(scan.host, prof / "Preferences") or {}, CHROMIUM_AD_PREFS,
                                               policy, lambda prefs, key: dig(prefs, *key.split(".")), default)))
    return out


@register
class AdFeatures(ProfileCheck):
    id = "br.ad_features"

    def judge(self, scan: Scan, firefox, chromium) -> Outcome:
        ev, on, by_default, unsure = [], [], [], []

        def add(label: str, active: list[str], defaults: list[str], unknown_defaults: list[str]) -> None:
            ev.append(Evidence.val(label, ", ".join(active + defaults) or "off"))
            if active:
                on.append(label)
            elif defaults:
                by_default.append(label)
            if unknown_defaults:
                unsure.append(f"{label} ({', '.join(unknown_defaults)})")

        chat = []
        for p in firefox:
            prefs = firefox_prefs(scan.host, p.path)
            add(p.label, *_ad_settings(prefs, FIREFOX_AD_PREFS, {}, lambda prefs, key: prefs.get(key),
                                       lambda key, p=p: ff_value(p, {}, key)))
            if prefs.get("browser.ml.chat.provider"):
                chat.append(p.label)
        for d, prof, active, defaults, unknown_defaults in _chromium_ad_states(scan, chromium):
            add(f"{d.label}, {prof.name}", active, defaults, unknown_defaults)
        notes = []
        if by_default:
            notes.append(Note("info", "Some are on as the browser's default",
                              f"In {', '.join(by_default)}, features that send what you type or browse are on because "
                              "that is how the browser ships, not because they were turned on. Most people have them, "
                              f"so they aren't counted as a finding. To turn them off: {AD_DEFAULTS_HOW}"))
        if unsure:
            notes.append(Note("limitation", "Defaults the app doesn't know",
                              f"{'; '.join(unsure)}: not set in the profile, and the app doesn't know whether this browser "
                              "ships it on: look in its settings."))
        if chat:
            ev.append(Evidence.val("An AI chatbot is set up in the sidebar", ", ".join(chat)))
        notes.append(AI_NOTE)
        if on:
            return failed(f"Ad or suggestion features that report what you browse are turned on in {len(on)} profile"
                          f"{'s' if len(on) > 1 else ''}.", *ev, notes=notes)
        return passed("Nothing that reports what you browse is turned on beyond the browsers' defaults."
                      if by_default or unsure else "Ad profiling and reporting suggestions are off.", *ev, notes=notes)


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
            return passed("None of them was found on this computer.", *ev, findings=findings)
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


# other blockers people use: (name, Firefox add-on ids, Chrome Web Store ids, a pattern for its name, why it blocks
# less than uBlock Origin or "" when it blocks ads and trackers as fully)
OTHER_BLOCKERS = (
    ("AdGuard AdBlocker", ("adguardadblocker@adguard.com",), ("bgnkhhnnamicmpeenaelnjfhikgbkllg",),
     r"^AdGuard\b.*(Ad ?Blocker|Ad blocker)", ""),
    ("Ghostery", ("firefox@ghostery.com",), ("mlomiejdfkolichcflejclcbmpeaniij",), r"^Ghostery\b", ""),
    ("Privacy Badger", ("jid1-MnnxcxisBPnSXQ@jetpack",), ("pkehgijcmpdhfbdbbnkijodmdjhbjlgp",), r"^Privacy Badger\b",
     "it blocks the trackers it learns about, not ads as such"),
    ("Adblock Plus", ("{d10d0bf8-f5b5-c8b4-a8b2-2b3a1b6b0cc0}",), ("cfhdojbkjhnklbpkdaibdccddilifddb",),
     r"^Adblock Plus\b", "it lets \"acceptable ads\" through unless you turn that off in its settings"),
    ("AdBlock", ("jid1-NIfFY2CA8fy1tg@jetpack",), ("gighmmpiobklfepjocnamgkkbiglidom",), r"^AdBlock\b(?! Plus)",
     "it lets \"acceptable ads\" through unless you turn that off in its settings"),
)
NO_KNOWN_BLOCKER = "none"


def _blocker(exts: list[Extension], family: str) -> str:
    """What blocks ads and trackers in one profile: uBlock Origin, uBlock Origin Lite, another blocker the app knows
    (by its id or its name), or "none" (no blocker the app recognises)."""
    from ..browsers import UBO_CHROMIUM, UBO_FIREFOX, UBO_LITE
    ids = {e.id for e in exts}
    if (UBO_FIREFOX if family == "mozilla" else UBO_CHROMIUM) in ids:
        return "uBlock Origin"
    if family == "chromium" and UBO_LITE in ids:
        return "uBlock Origin Lite"
    for name, ff, cr, pattern, _less in OTHER_BLOCKERS:
        if ids & set(ff if family == "mozilla" else cr) or any(re.search(pattern, e.name, re.I) for e in exts):
            return name
    return NO_KNOWN_BLOCKER


def blocker_less(status: str) -> str:
    """Why a blocker blocks less than uBlock Origin, or ""."""
    if status == "uBlock Origin Lite":
        return "it can't block as much as uBlock Origin (Chrome's newer extension format limits it)"
    return next((less for name, *_, less in OTHER_BLOCKERS if name == status), "")


def blocking_status(scan: Scan, b) -> list[tuple[str, str]]:
    """(profile, "uBlock Origin" | "uBlock Origin Lite" | another blocker's name | "none") for each profile of a browser
    that needs an extension; [] when its profiles aren't known or it has none yet."""
    out = []
    if b.family == "chromium":
        for d in chromium_dirs(scan.paths):
            if b.id in d.ids:
                for prof in chromium_profiles(d):
                    out.append((f"{d.label}, {prof.name}",
                                _blocker(broad_extensions(scan, [], [(d, [prof])], every=True), "chromium")))
    elif b.family == "mozilla":
        for p in mozilla_profiles(scan.host, scan.paths, tuple(f.name for f in b.folders)):
            out.append((p.label, _blocker(broad_extensions(scan, [p], [], every=True), "mozilla")))
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
                ev.append(Evidence.val(where[:150], "no blocker the app recognises" if status == NO_KNOWN_BLOCKER
                                       else status))
            if judged and any(s == NO_KNOWN_BLOCKER for _, s in statuses):
                lacking.append(f.name)
            elif judged and any(blocker_less(s) for _, s in statuses):
                partial += [(f.name, s) for _, s in statuses if blocker_less(s)]
            elif judged and statuses:
                blocks = True
        notes = [Note("info", "Chrome and Edge can't block properly any more",
                      "Since 2025 Chrome and Edge can't run the full uBlock Origin, only the weaker uBlock Origin "
                      "Lite. Firefox-based browsers, ungoogled-chromium and Brave still can.")]
        if lacking:
            notes.append(Note("limitation", "Blockers the app recognises",
                              "uBlock Origin and Lite, AdGuard AdBlocker, Ghostery, Privacy Badger, Adblock Plus and "
                              "AdBlock, by their ids or names. If you use another blocker, it isn't counted here."))
            return failed(f"{' and '.join(dict.fromkeys(lacking))} has no ad blocker the app recognises: install uBlock "
                          "Origin.", *ev, notes=notes)
        if partial:
            name, status = partial[0]
            return warned(f"{name} blocks with {status}, which blocks less: {blocker_less(status)}.", *ev, notes=notes)
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
# Flatpak (its id since 2023, and the earlier one); where Mullvad's package and Flatpak keep Mullvad Browser
LAUNCHER_FLATPAKS = ("org.torproject.torbrowser-launcher", "com.github.micahflee.torbrowser-launcher")
# the AUR's tor-browser-bin and tor-browser-alpha-bin: their /usr/bin/tor-browser unpacks the browser into
# ~/.local/opt/<package>/app whenever the package's version changes, emptying that folder first (rm -rf app/*), then
# runs its start script there (16.0.1-1 and 16.0a13-1). What the app puts in that folder lasts until the next update
LOCAL_OPT = ".local/opt"
UNPACKED_SCRIPT = "app/Browser/start-tor-browser"
UNPACKER_NAME = re.compile(r"^_T[AB]_PKGNAME_='([A-Za-z0-9._+-]{1,60})'\s*$", re.M)
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
SHADER_ENTRY_MARK = ("# DA Privacy Kit: starts the browser with the graphics drivers' shader caches off, which its "
                     "package's updates can't undo")


@dataclass
class BrowserCopy:
    """A Tor Browser or Mullvad Browser on this computer, as it is started."""
    name: str                   # Tor Browser, Mullvad Browser
    script: Path | None         # its start script (None: a Flatpak whose files weren't found)
    cache: Path | None          # where the graphics drivers keep its cache: the .cache of the home folder the script
                                # gives it, or a Flatpak's own; None when it is the one every program shares
    own: Path                   # its folder, where its profile is: a program with a file open there is the browser
    launcher: Path | None = None    # a program that starts it without its script (the AUR's /usr/bin/mullvad-browser)
    entry: Path | None = None       # the menu entry that runs that program, or `unpacked_by`
    unpacked_by: Path | None = None  # a package's program that unpacks it again at each update, emptying its folder
                                    # (the AUR's tor-browser-bin's /usr/bin/tor-browser): a block there lasts until then
    source: Path | None = None      # the menu entry the app's own is made from (the package's)

    def turns_off_nvidia(self, host) -> bool:
        if self.unpacked_by is not None and self.menu_entry_current(host):
            return True
        what = self.launcher or self.script
        return what is not None and bool(SCRIPT_TURNS_OFF_NVIDIA.search(read_text(host, what) or ""))

    def menu_entry_current(self, host) -> bool:
        """Whether the menu entry the desktop uses is the app's own, starting the browser with the drivers' caches off,
        and made from the package's entry as it is now."""
        if self.entry is None or self.source is None:
            return False
        text = read_text(host, self.entry) or ""
        return text.startswith(SHADER_ENTRY_MARK) and text == no_shader_cache_entry(read_text(host, self.source) or "")


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


def _unpacker(scan: Scan, prog: str | None) -> tuple[Path, Path] | None:
    """(the program, the start script of the copy it unpacks) when `prog` is a package's script that unpacks Tor
    Browser into ~/.local/opt/<package>/app at each update, emptying that folder first, and starts it through its start
    script there (the AUR's tor-browser-bin and tor-browser-alpha-bin)."""
    if not prog:
        return None
    p = on_host(scan.host, prog)
    try:
        if p.is_symlink() or p.stat().st_size > 65536:
            return None
    except OSError:
        return None
    text = read_text(scan.host, p) or ""
    name = UNPACKER_NAME.search(text)
    if not text.startswith("#!") or name is None or not all(s in text for s in (".local/opt/", "/Browser/start-tor-browser",
                                                                                "tar -x")):
        return None
    return p, scan.host.home / LOCAL_OPT / name.group(1) / UNPACKED_SCRIPT


def no_shader_cache_entry(text: str) -> str:
    """A menu entry with each command run with Mesa's and NVIDIA's shader caches off (env and the two variables before
    it: what Tor or Mullvad Browser in memory sets, `sandbox.NO_SHADER_CACHE`), every other key kept; marked as the
    app's at its top. Applied to its own output, it gives the same."""
    from ..tools.sandbox import NO_SHADER_CACHE
    prefix = "env " + " ".join(f"{k}={v}" for k, v in sorted(NO_SHADER_CACHE.items())) + " "
    out = [SHADER_ENTRY_MARK]
    for line in text.splitlines():
        if line.startswith(SHADER_ENTRY_MARK):
            continue
        m = re.match(r"^Exec\s*=\s*(.*)$", line)
        if m:
            value = m.group(1)
            line = "Exec=" + (value if value.startswith(prefix) else prefix + value)
        out.append(line)
    return "\n".join(out) + "\n"


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
    torbrowser-launcher's copies, the copy the AUR's tor-browser-bin unpacks (`unpacked_by`, found through its menu
    entry even before its first start, else in ~/.local/opt), Mullvad's package and its Flatpak. Not the app's own in
    ~/TempBrowser (they start with the caches off)."""
    host, out, seen = scan.host, [], set()

    def add(script: Path, name: str, flatpak: str | None = None, skipped: tuple | None = None, entry: Path | None = None,
            unpacked: tuple[Path, Path] | None = None):
        if script in seen or not (isfile(script) or unpacked) or script.is_relative_to(host.home / "TempBrowser"):
            return
        seen.add(script)
        if skipped:                               # the real home folder, its cache the one every program shares
            out.append(BrowserCopy(name, script, None, profile_root(host, script.parent) or host.home, skipped[0], entry))
        else:
            c = _copy_from_script(scan, script, name, flatpak)
            if unpacked:
                c.unpacked_by, c.entry, c.source = unpacked[0], entry, unpacked[1]
            out.append(c)

    for name, entry, below in effective_entries(scan, found):
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
        unpacker = _unpacker(scan, prog)
        if unpacker is not None:
            mine = (read_text(host, entry) or "").startswith(SHADER_ENTRY_MARK) and below is not None
            add(unpacker[1], name, entry=entry, unpacked=(unpacker[0], below if mine else entry))
    for base, flatpak in [(scan.paths.data_home / "torbrowser", None)] + [
            (host.home / ".var/app" / i / "data/torbrowser", i) for i in LAUNCHER_FLATPAKS]:
        for arch in children(base / "tbb"):
            add(arch / "tor-browser/Browser/start-tor-browser", "Tor Browser", flatpak)
    for d in children(host.home / LOCAL_OPT):     # one whose menu entry the app didn't find: its block lasts until an update
        add(d / UNPACKED_SCRIPT, "Tor Browser")
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


def script_unusable(host, script: Path) -> str | None:
    """Why the start script can't start this copy as it is installed, or None: without is-packaged-app beside it, the
    script makes the browser's own folder its home, which must then be the user's to write to (the AUR's
    mullvad-browser-latest-bin 16.0.1-1 puts it in /opt with system-install alone)."""
    folder = script.parent
    if (folder / "is-packaged-app").exists() or os.access(folder, os.W_OK):
        return None
    return (f"its package puts it in {real_path(host, folder)} without is-packaged-app (an empty file) beside its start "
            "script, which then makes that folder, which isn't yours to write to, the browser's home: started through "
            "it, the browser couldn't save downloads or settings")


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
        lapsing: list[BrowserCopy] = []           # blocked only until the package unpacks the browser again
        lasting: list[BrowserCopy] = []           # started from the menu with the caches off, whatever the package does
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
            entry_on = c.unpacked_by is not None and c.menu_entry_current(host)
            if entry_on:
                lasting.append(c)
            if mesa and not mesa_off:
                if c.launcher is not None:
                    states.append("Mesa's cache on, the one every program shares (started without its start script)")
                elif entry_on:
                    states.append("Mesa's cache off when started from the menu, also after its package unpacks it again"
                                  + ("; blocked in its folder too" if mesa_blocked(c) else ""))
                    old += [(c, r, t) for r, t in caches]
                elif c.cache is None:
                    states.append("Mesa's cache on, the one every program shares (your session sets XDG_CACHE_HOME)")
                elif mesa_blocked(c):
                    if c.unpacked_by is not None:
                        states.append("Mesa's cache blocked for it until its package unpacks it again, at its next update")
                        lapsing.append(c)
                    else:
                        states.append("Mesa's cache blocked for it")
                elif not isfile(c.script):
                    states.append("Mesa's cache on from its first start, in its own folder (not started yet)")
                else:
                    states.append("Mesa's cache on, in its own folder")
                if states[-1].startswith("Mesa's cache on"):
                    on.append(c.name)
                    drivers_on.add("Mesa")
            elif caches:
                old += [(c, r, t) for r, t in caches]
            if nvidia and not nvidia_off:
                if entry_on:
                    states.append("NVIDIA's cache off when started from the menu")
                elif c.turns_off_nvidia(host):
                    states.append("NVIDIA's cache off in its " + ("start script" if c.launcher is None else "package's program"))
                elif c.unpacked_by is not None and not isfile(c.script):
                    states.append("NVIDIA's cache: its start script decides, from its first start (not started yet)")
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
                              "them and where it can't be blocked for the browser alone. Fix that first, where it can "
                              "be: then this check's fix blocks it in the browser's own folder.", ("br.start_script",)))
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
        for c in lasting:
            notes.append(Note("limitation", "Typed in a terminal",
                              f"{host.display(c.unpacked_by)} unpacks {c.name} again whenever its package is updated, "
                              "emptying its folder, and any block the app put there with it. Started from the menu, a "
                              "link or as your default browser, the app's menu entry keeps the drivers' caches off "
                              f"every time; typed in a terminal, {c.unpacked_by.name} starts it without that entry, and "
                              "from the next update on Mesa keeps a cache for it there. "
                              f"`MESA_SHADER_CACHE_DISABLE=true {c.unpacked_by.name}` keeps it off in a terminal too."))
        on = list(dict.fromkeys(on))
        findings = {"old_shader_cache_only": not on and not lapsing and bool(old),
                    "blocked_until_update": not on and bool(lapsing)}
        if on:
            drivers = " and ".join(d for d in ("Mesa", "NVIDIA") if d in drivers_on)
            return warned(f"Websites could link your visits in {' and '.join(on)}: the graphics driver ({drivers}) "
                          "keeps the shaders pages hand it in a cache on the disk.", *ev, notes=notes, findings=findings)
        if lapsing:
            what = " and ".join(dict.fromkeys(c.name for c in lapsing))
            return warned(f"Mesa's cache is blocked for {what} only until its package's next update, which unpacks the "
                          "browser again and removes the block.", *ev, notes=notes, findings=findings)
        if old:
            return warned(f"The graphics drivers' shader caches are off, but the old one is still on the disk: "
                          f"{', '.join(dict.fromkeys(c.name for c, _, _ in old))}.", *ev, notes=notes, findings=findings)
        if not (mesa or nvidia):
            return passed("No graphics driver with a shader cache was found.", *ev, notes=notes, findings=findings)
        return passed(f"The graphics drivers keep no shader cache for {' and '.join(names)}.", *ev, notes=notes,
                      findings=findings)
