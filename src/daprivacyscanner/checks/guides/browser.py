"""Guided fixes: browsers (see the package docstring)."""

from __future__ import annotations

from ...fix import DeleteFiles
from ...guide import Guide, Step
from .._util import chromium_dirs, files_under, mozilla_cache, mozilla_profiles
from ...helper import CLEAR_ON_EXIT
from . import guide, option, evidence, ff_prefs, chromium_policy_options, chromium_step, mozilla_open


SESSION_LOST = "Firefox no longer reopens the tabs you had open: restoring them needs the history it clears."


def _ff_keeping(prefs, p) -> bool:
    from ..browser import _ff_clears_history
    return not _ff_clears_history(prefs, {})


def _chromium_flagged(scan, outcome, bad) -> set[str]:
    """The Chromium-based browser folders (by label) with a profile whose evidence value `bad` accepts: those a policy
    option is offered for."""
    from ..browser import _browsers
    values = {e.label: e.value for e in outcome.evidence}
    return {d.label for d, profiles in _browsers(scan)[1] for prof in profiles
            if f"{d.label}, {prof.name}" in values and bad(values[f"{d.label}, {prof.name}"])}


@guide("br.history_retention")
def history_retention(check, scan, outcome):
    from .._util import chromium_policies
    from ..browser import _browsers
    opts = ff_prefs(check, scan, "Clear history, cookies and site data when Firefox closes",
                    {"privacy.sanitize.sanitizeOnShutdown": True}, want=_ff_keeping,
                    side_effects=["You're logged out of sites each time; keep the ones you want under Settings → "
                                  "Privacy & Security → Cookies and Site Data → Manage Exceptions.", SESSION_LOST],
                    recommended=True)
    opts += ff_prefs(check, scan, "Clear history only, stay logged in",
                     {"privacy.sanitize.sanitizeOnShutdown": True, "privacy.clearOnShutdown_v2.cookiesAndStorage": False,
                      "privacy.clearOnShutdown.cookies": False, "privacy.clearOnShutdown.offlineApps": False},
                     want=_ff_keeping, side_effects=[SESSION_LOST])
    # the check counts a Chromium-based profile as clearing only with the policy's list: those without it
    keeping = {d.label for d, profiles in _browsers(scan)[1]
               if not chromium_policies(scan.host, d.browser).get("ClearBrowsingDataOnExitList")}
    skip = lambda d: d.label not in keeping  # noqa: E731
    return Guide(check.id, "Clear browsing data when the browser closes", "", [
        Step("Firefox", options=opts, done=not opts),
        chromium_step(scan,
             "Settings → Privacy and security → Site settings → On-device site data → \"Delete data sites have saved "
             "to your device when you close all windows\" (Brave: Settings → Privacy → Clear browsing data → On exit).",
             chromium_policy_options(check, scan, {"DefaultCookiesSetting": 4},
                                             "Keep site data only until the browser closes", skip=skip, side_effects=[
                                                 "Every site, your Google or Microsoft account included, signs you out "
                                                 "each time the browser closes."])
             + chromium_policy_options(check, scan, {"SyncDisabled": True, "ClearBrowsingDataOnExitList": CLEAR_ON_EXIT},
                                       "Turn off sync, and clear history, downloads and cache when the browser closes",
                                       skip=skip,
                                       side_effects=["Sync stops for every profile (bookmarks, passwords, history): "
                                                     "Chromium only clears data at exit with sync off."]),
             not keeping),
        Step("About the cache", "Cleared at exit, cached pages are deleted, not wiped: they can still be recovered "
             "from the disk for a while (see enc.deleted_data_recoverable). Private windows never write their cache "
             "to the disk; for normal browsing, keeping the cache in memory (Firefox's option in the disk cache "
             "check, br.disk_cache) is a small gain on top of clearing."),
    ])


@guide("br.tracking_protection")
def tracking_protection(check, scan, outcome):
    from .._util import firefox_prefs
    opts = ff_prefs(check, scan, "Strict tracking protection", {"browser.contentblocking.category": "strict"},
                    only=("Firefox",), want=lambda prefs, p: firefox_prefs(scan.host, p.path).get(
                        "browser.contentblocking.category", "standard") not in ("strict", "custom"),
                    side_effects=["A few sites break (sign-in through another site, some embedded videos); turn it "
                                  "off for one site with the shield icon in the address bar."], recommended=True)
    weak = evidence(outcome, value="third-party cookies allowed")
    flagged = _chromium_flagged(scan, outcome, lambda v: v == "third-party cookies allowed")
    chromium = chromium_policy_options(check, scan, {"BlockThirdPartyCookies": True}, "Block third-party cookies",
                                       skip=lambda d: d.browser.startswith("Brave") or d.label not in flagged)
    return Guide(check.id, "Strengthen tracking protection", "", [
        Step("Firefox", options=opts, done=not opts),
        chromium_step(scan, "Settings → Privacy and security → Third-party cookies → Block third-party cookies."
                      + (f" Allowed now in: {'; '.join(weak)}." if weak else ""), chromium, not weak),
    ])


@guide("br.disk_cache")
def disk_cache(check, scan, outcome):
    opts = ff_prefs(check, scan, "Keep the cache in memory",
                    {"browser.cache.disk.enable": False, "browser.cache.memory.enable": True,
                     "browser.sessionstore.privacy_level": 2},
                    side_effects=["Pages load a little slower after a restart; restored tabs come back without "
                                  "form contents."], recommended=True)
    cleanup = []
    for p in mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf")):
        cache = mozilla_cache(scan.paths, p)
        files = files_under(cache)[0]
        if files:
            cleanup.append(DeleteFiles(cache, files, f"{p.label} disk cache", scan.host.display(cache)))
    running = mozilla_open(scan, ("Firefox", "LibreWolf"))
    steps = [Step("Firefox", options=opts, done=not opts)]
    if cleanup:
        steps.append(Step("Delete the cache on disk now", "Turning the disk cache off leaves the one already there.",
                          options=[option(check, "Delete it", cleanup, blockers=[
                              f"Close {' and '.join(running)} first: it holds its cache open."] if running else [])]))
    steps.append(Step("Chromium-based browsers",
                      "They have no setting to keep the cache in memory. Clearing it when the browser closes "
                      "(br.history_retention) or browsing in private windows keeps it from piling up. "
                      "profile-sync-daemon isn't a fix for this: it keeps profiles in memory for speed but writes "
                      "them back to the disk regularly, and leaves the cache in ~/.cache where it is."))
    return Guide(check.id, "Keep browser caches off the disk", "", steps)


@guide("br.ad_features")
def ad_features(check, scan, outcome):
    from ..browser import ENHANCED_SAFE_BROWSING, _browsers, chromium_ad_states
    opts = ff_prefs(check, scan, "Turn off sponsored suggestions and search suggestions",
                    {"browser.search.suggest.enabled": False, "browser.urlbar.suggest.quicksuggest.sponsored": False,
                     "browser.newtabpage.activity-stream.showSponsoredTopSites": False},
                    side_effects=["The address bar no longer suggests searches as you type (history and bookmarks "
                                  "still are)."], recommended=True)
    states = chromium_ad_states(scan, _browsers(scan)[1])
    # what the policy turns off; Enhanced Safe Browsing only the profile's own settings page does
    flagged = {d.label for d, _, active, _ in states if any(a != ENHANCED_SAFE_BROWSING for a in active)}
    enhanced = [f"{d.label}, {prof.name}" for d, prof, active, _ in states if ENHANCED_SAFE_BROWSING in active]
    chromium = chromium_policy_options(check, scan, {"PrivacySandboxAdTopicsEnabled": False,
                                                      "PrivacySandboxSiteEnabledAdsEnabled": False,
                                                      "PrivacySandboxAdMeasurementEnabled": False,
                                                      "SearchSuggestEnabled": False},
                                       "Turn off ad topics, site-suggested ads, ad measurement and search suggestions",
                                       skip=lambda d: d.browser.startswith("Brave") or d.label not in flagged)
    steps = [Step("Firefox", options=opts, done=not opts),
             Step("Chromium-based browsers", "Settings → Privacy and security → Ads privacy: turn off Ad topics, "
                  "Site-suggested ads and Ad measurement; Settings → You and Google → Sync and Google services → "
                  "\"Make searches and browsing better\" and \"Autocomplete searches and URLs\" off. Or, for every user:",
                  options=chromium, done=not flagged)]
    if enhanced:
        in_dirs = {d.label for d, _, active, _ in states if ENHANCED_SAFE_BROWSING in active}
        steps.append(Step("Enhanced Safe Browsing",
                          "It sends the address of each page you open to Google, to be checked as you browse. Standard "
                          "protection still warns about dangerous sites, from a list the browser downloads: Settings → "
                          "Privacy and security → Security → Standard protection. On now in: " + "; ".join(enhanced) + ". "
                          "Or, for every user:",
                          options=chromium_policy_options(check, scan, {"SafeBrowsingProtectionLevel": 1},
                                                          "Use standard protection",
                                                          skip=lambda d: d.label not in in_dirs)))
    return Guide(check.id, "Turn off features that report what you browse", "", steps)


@guide("br.webrtc")
def webrtc(check, scan, outcome):
    from ..browser import SAFE_WEBRTC
    opts = ff_prefs(check, scan, "Limit WebRTC to the default route",
                    {"media.peerconnection.ice.default_address_only": True},
                    side_effects=["Video calls still work; peer-to-peer connections may go through a relay more "
                                  "often."], recommended=True)
    flagged = _chromium_flagged(scan, outcome, lambda v: v not in SAFE_WEBRTC)
    chromium = chromium_policy_options(check, scan, {"WebRtcIPHandling": "default_public_interface_only"},
                                       "Limit WebRTC to the default route", skip=lambda d: d.label not in flagged)
    return Guide(check.id, "Stop WebRTC revealing local addresses",
                 "Mostly matters with a split-tunnel VPN, where WebRTC could show your real address.", [
                     Step("Firefox", options=opts, done=not opts),
                     chromium_step(scan, "Brave: Settings → Privacy → WebRTC IP handling policy → Default public "
                                   "interface only. Others: the WebRTC Network Limiter extension.", chromium,
                                   not flagged, policy="Or a policy, for every user:"),
                 ])


@guide("br.https_only", keys=("https_only",))
def https_only(check, scan, outcome):
    from ..browser import HTTPS_ONLY_PREF
    opts = ff_prefs(check, scan, "Turn on HTTPS-Only Mode", {HTTPS_ONLY_PREF: True},
                    side_effects=["A site that has no HTTPS shows a warning page first, with a button to open it "
                                  "anyway (for that site, until the browser is closed)."],
                    want=lambda prefs, p: not (p.app == "LibreWolf" and prefs.get(HTTPS_ONLY_PREF) is None),
                    recommended=True, key="https_only")
    names = sorted({d.browser for d in chromium_dirs(scan.paths)})
    where = []
    if any(n.startswith("Brave") for n in names):
        where.append("Brave: Settings → Shields → Upgrade connections to HTTPS → Strict.")
    if any(n == "Microsoft Edge" for n in names):
        where.append("Edge: open edge://settings/privacy and, under Security, turn on the switch that always uses "
                     "secure connections.")
    if any(not n.startswith("Brave") and n != "Microsoft Edge" for n in names):
        where.append("Chrome, Chromium and Vivaldi: open chrome://settings/security (paste it into the address bar) "
                     "and turn on \"Always use secure connections\".")
    pending = any("Always use secure connections: off" in str(e.value) or "Upgrade connections to HTTPS" in str(e.value)
                  and "Strict" not in str(e.value) for e in outcome.evidence)
    return Guide(check.id, "Ask before opening an unencrypted page",
                 "The browser then tries HTTPS for every page and stops with a warning where a site has none, so "
                 "nobody on the network can quietly make it load one without encryption.", [
                     Step("Firefox", options=opts, done=not opts),
                     Step("Chromium-based browsers", " ".join(where) or "None is installed.",
                          done=not names or not pending),
                 ])


# ------------------------------------------------------------------ extensions with access to every site

EXTENSION_PAGES = {"Firefox": "about:addons", "LibreWolf": "about:addons", "Google Chrome": "chrome://extensions",
                   "Chromium": "chrome://extensions", "Brave": "brave://extensions", "Microsoft Edge": "edge://extensions",
                   "Vivaldi": "vivaldi://extensions"}


def _extension_text(e, owner: str | None) -> str:
    """How to limit or remove one extension in its own browser."""
    if e.browser in ("Firefox", "LibreWolf"):
        if e.system:
            return (f"It was installed for every account on this computer ({e.system}), usually by a package, so "
                    f"{e.browser} can't remove it; it can only be turned off for you in about:addons."
                    + (f" To remove it, uninstall the package that owns it ({owner})." if owner else ""))
        limit = (f"To limit it: open about:addons in {e.browser}, choose {e.name}, open the Permissions and data tab, "
                 "and turn off \"Access your data for all websites\"; it then asks before it works on a site. "
                 if e.mv3 else "It is an older kind of extension that can't be limited to some sites: keep it or "
                 "remove it. ")
        return limit + "To remove it yourself: about:addons → the ⋯ button next to it → Remove."
    page = EXTENSION_PAGES.get(e.browser, "chrome://extensions")
    if e.managed:
        return (f"It was installed by a policy on this computer, so {e.browser} won't remove it, and neither can "
                f"you there: {page.split(':')[0]}://policy shows the policy that installs it.")
    return (f"Open {page}/?id={e.id} in {e.browser} (paste it into the address bar). To limit it: under Site access, "
            "choose \"On click\" (it works on a page only when you click its icon) or \"On specific sites\". To "
            "remove it: Remove extension, at the bottom of that page.")


def _package_owner(scan, path: str) -> str | None:
    """The command that names the package a file belongs to, for this distribution."""
    from . import family
    if not path.startswith("/") or path.startswith(str(scan.host.home)):
        return None
    cmd = {"debian": "dpkg -S", "fedora": "rpm -qf", "suse": "rpm -qf", "arch": "pacman -Qo"}.get(family(scan) or "")
    return f"{cmd} {path}" if cmd else None


def _extension_step(check, scan, e, blocked: set) -> Step:
    """Limit or remove one extension: from the profile (Firefox), or by policy for every account."""
    from ...fix import RootChange
    from ...helper import POLICY_FILES
    from . import POLICY_KEYS
    owner = _package_owner(scan, e.system) if e.system else None
    opts = []
    if e.file is not None:
        # only its own browser holds it up (Thunderbird running doesn't)
        closed = [f"Close {e.browser} first: it only forgets an extension as it starts."] \
            if mozilla_open(scan, (e.browser,)) else []
        opts.append(option(check, "Remove it from this profile", [DeleteFiles(
            e.file.parent, [e.file], f"the extension {e.name}", scan.host.display(e.file.parent), prune=False)],
            blockers=closed, recommended=True, side_effects=[
                f"{e.browser} forgets it the next time it starts, with its settings. To have it back, install it "
                "again from addons.mozilla.org."]))
    key = "firefox" if e.browser == "Firefox" else POLICY_KEYS.get(e.browser)
    # policies are read from /etc by native installs (and Snap Firefox), not by Flatpaks
    readable = e.install == "native" or (key == "firefox" and e.install == "snap")
    if key is not None and readable and not e.managed and (key, e.id) not in blocked:
        blocked.add((key, e.id))
        opts.append(option(check, "Remove it and keep it off, for every account on this computer (policy)",
                           [RootChange("block_extensions", {"browser": key, "ids": [e.id]},
                                       f"Block {e.id} in {POLICY_FILES[key]}")],
                           recommended=e.file is None, side_effects=[
                               f"{e.browser} removes it from every profile and won't let it be installed again; "
                               "its page says it is managed by your organization. Revert from History to lift the "
                               "block, then install it again if you want it."]))
    return Step(f"{e.name} ({e.where})", _extension_text(e, owner), options=opts, commands=[owner] if owner else [])


@guide("br.vpn_extensions")
def vpn_extensions(check, scan, outcome):
    from ...vpn import rate
    from ..browser import _browsers, vpn_extensions as found_vpn
    firefox, chromium = _browsers(scan)
    blocked: set = set()
    steps = [_extension_step(check, scan, e, blocked)
             for e, p in found_vpn(scan, firefox, chromium) if rate(p).concern]
    if not steps:
        steps.append(Step("Nothing to remove", "No VPN extension from a provider rated low is installed now.",
                          done=True))
    return Guide(check.id, "Remove VPN extensions you can't trust",
                 "A VPN extension sees every page you open. These come from providers with harm on record, or whose "
                 "code can't be checked: remove them. If you want a VPN in the browser, Mullvad's and IVPN's apps "
                 "cover the whole computer, browser included.", steps)


@guide("br.extensions_broad")
def extensions_broad(check, scan, outcome):
    from ..browser import _browsers, broad_extensions
    firefox, chromium = _browsers(scan)
    found = broad_extensions(scan, firefox, chromium)
    blocked: set = set()
    steps = [_extension_step(check, scan, e, blocked) for e in found]
    if not steps:
        steps.append(Step("Nothing to go through", "No enabled extension has access to every site now.", done=True))
    return Guide(check.id, "Go through extensions that can read every site",
                 "Each of these can read and change every page you open, passwords and messages included, and send "
                 "what it reads anywhere. An ad blocker or password manager needs this access to work; most other "
                 "extensions don't. For each one: keep it if you use it and trust who makes it, limit it to the sites "
                 "you choose, or remove it.", steps)


# ------------------------------------------------------------------ sites allowed the camera, microphone or location

def _content_page(browser: str, what: str) -> str:
    scheme = "brave" if browser.startswith("Brave") else "edge" if browser.startswith("Microsoft Edge") else \
        "opera" if browser.startswith("Opera") else "chrome"
    return f"{scheme}://settings/content/{what}"


@guide("br.site_permissions")
def site_permissions(check, scan, outcome):
    from .._util import chromium_dirs, chromium_profiles
    from ..browser import BLOCK, _permission_summary, chromium_site_permissions, firefox_site_permissions
    review = []
    for p in mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf")):
        counts, defaults = firefox_site_permissions(scan, p)
        review.append(f"{p.label} ({_permission_summary(counts, defaults)}): Settings → Privacy & Security → "
                      "Permissions; Camera, Microphone and Location each have a Settings… button listing the sites. "
                      "Select one and choose Remove Website.")
    chromium, asking, located = [], set(), set()
    for d in chromium_dirs(scan.paths):
        profiles = chromium_profiles(d)
        for prof in profiles:
            counts, defaults = chromium_site_permissions(scan, d, prof)
            review.append(f"{d.label}, {prof.name} ({_permission_summary(counts, defaults)}): "
                          f"{_content_page(d.browser, 'camera')}, {_content_page(d.browser, 'microphone')} and "
                          f"{_content_page(d.browser, 'location')}; remove a site with the bin icon beside it.")
            if any(v != BLOCK for v in defaults.values()):
                asking.add(d.label)               # sites can still ask for one of them (or have it without asking)
            if defaults.get("location") != BLOCK:
                located.add(d.label)
        if profiles:
            chromium.append(d)
    blocked = ["Sites you have allowed keep their permission: remove them in the step above.",
               "A site that needs it, a video call say, can't ask any more: allow it from the icon at the left of the "
               "address bar, or in the same Settings… list."]
    ff = ff_prefs(check, scan, "Block new requests for the camera, microphone and location",
                  {"permissions.default.camera": 2, "permissions.default.microphone": 2, "permissions.default.geo": 2},
                  side_effects=blocked, recommended=True)
    ff += ff_prefs(check, scan, "Block new location requests only", {"permissions.default.geo": 2},
                   side_effects=blocked)
    steps = [Step("Remove the sites you don't need", "Each browser lists the sites it remembers:\n• " + "\n• ".join(review))
             if review else Step("Remove the sites you don't need", "No browser profiles were found.", done=True)]
    if ff:
        steps.append(Step("Firefox: stop sites from asking", "The same as ticking \"Block new requests\" in each of "
                          "Firefox's permission lists. Firefox has to be closed while it is changed.", options=ff))
    if chromium:
        names = ", ".join(sorted({d.browser for d in chromium}))
        steps.append(Step(f"{names}: stop sites from asking",
                          "On each settings page above, choose \"Don't allow sites to use your camera\" (and the same "
                          "for the microphone and location). Location can also be blocked by a policy, for every "
                          "account on this computer:",
                          options=chromium_policy_options(check, scan, {"DefaultGeolocationSetting": 2},
                                                          "Block location requests",
                                                          skip=lambda d: d.label not in located),
                          done=not asking))
    return Guide(check.id, "Review the sites that can use your camera, microphone or location",
                 "A site you allowed once can use them again whenever it is open, without asking.", steps)
