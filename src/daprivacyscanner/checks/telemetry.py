"""Telemetry and phone-home (tel.*)."""

from __future__ import annotations

import re

from .. import ini
from ..host import Unreadable
from ..model import Evidence, Note, Outcome
from . import Check, Scan, register
from ._util import (absent, children, chromium_dirs, chromium_policies, dig, failed, firefox_policies, firefox_prefs,
                    installed, mozilla_profiles, passed, read_json, read_jsonc, read_text, sqlite_count, systemctl_state,
                    unknown, warned)


@register
class CrashReporters(Check):
    id = "tel.crash_reporters"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        on, ev = [], []
        apport = host.read_sys("/etc/default/apport")
        if apport is not None:
            enabled = re.search(r"^enabled\s*=\s*1", apport, re.M) and systemctl_state(host, "is-enabled", "apport") != "disabled"
            ev.append(Evidence.val("apport", "on" if enabled else "off"))
            if enabled:
                on.append("apport")
        if systemctl_state(host, "is-enabled", "whoopsie") == "enabled":
            on.append("whoopsie (uploads Ubuntu crash reports)")
            ev.append(Evidence.val("whoopsie", "enabled"))
        if systemctl_state(host, "is-enabled", "abrtd") == "enabled":
            conf = ini.parse(host.read_sys("/etc/abrt/abrt.conf") or "")
            auto = ini.truthy(ini.get(conf, (), "AutoreportingEnabled"))
            on.append("ABRT" + (" (reports automatically)" if auto else ""))
            ev.append(Evidence.val("ABRT", "enabled, " + ("reports automatically" if auto else "asks before reporting")))
        popcon = host.read_sys("/etc/popularity-contest.conf")
        if popcon and re.search(r'^PARTICIPATE\s*=\s*"?yes', popcon, re.M):
            on.append("popularity-contest")
            ev.append(Evidence.val("popularity-contest", "participating"))
        # Arch's pkgstats: its package links its timer into timers.target.wants (static: it can't be disabled, only
        # masked), and it sends the list of installed packages and the mirror (pkgstats submit --dump-json, tested)
        if host.sys_path("/usr/lib/systemd/system/pkgstats.timer").exists() and \
                systemctl_state(host, "is-enabled", "pkgstats.timer") not in ("masked", "masked-runtime"):
            on.append("pkgstats (sends the packages you have installed)")
            ev.append(Evidence.val("pkgstats", "on: sends the list of installed packages every week"))
        # Ubuntu's motd-news fetches news from motd.ubuntu.com, sending the release, kernel, processor, uptime and cloud
        # in its request; Mint ships the script empty
        motd = host.read_sys("/etc/default/motd-news") or ""
        script = host.read_sys("/etc/update-motd.d/50-motd-news") or ""
        if re.search(r"^\s*ENABLED\s*=\s*1\s*$", motd, re.M) and \
                len([ln for ln in script.splitlines() if ln.strip() and not ln.startswith("#")]) > 1:
            on.append("motd-news (sends details of this computer to Ubuntu)")
            ev.append(Evidence.val("motd-news", "on"))
        notes = []
        if scan.context.desktop.is_kde:
            notes.append(Note("info", "KDE's own reporting", "DrKonqi asks before sending a crash report; Plasma's "
                              "user feedback has its own check.", ("tel.kde_feedback",)))
        if on:
            return failed(f"Crash or usage reporting is on: {', '.join(on)}.", *ev, notes=notes)
        return passed("No crash reporter or usage survey is reporting.", *ev, notes=notes)


def wifi_adapters(scan: Scan) -> bool | None:
    """Whether this computer has a Wi-Fi adapter (a network interface with a wireless or phy80211 entry in /sys);
    None when /sys/class/net can't be read."""
    net = scan.host.sys_path("/sys/class/net")
    if not net.is_dir():
        return None
    return any((d / "wireless").exists() or (d / "phy80211").exists() for d in children(net))


@register
class Location(Check):
    id = "tel.location"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, wifi = [], False
        conf_text = host.read_sys("/etc/geoclue/geoclue.conf")
        if conf_text is not None:
            # GeoClue 2.7+ reads conf.d after it, in name order, later files winning
            layers = [ini.parse(conf_text)]
            for p in children(host.sys_path("/etc/geoclue/conf.d")):
                text = host.read_sys(f"/etc/geoclue/conf.d/{p.name}") if p.suffix == ".conf" else None
                if text:
                    layers.append(ini.parse(text))
            conf = ini.merge(*layers)
            wifi = bool(ini.truthy(ini.get(conf, "wifi", "enable")))
            url = ini.get(conf, "wifi", "url") or ""
            ev.append(Evidence.val("GeoClue Wi-Fi lookup", ("on, via " + re.sub(r"^\w+://([^/]+).*", r"\1", url))
                                   if wifi and url else "on" if wifi else "off"))
        # what the lookup sends: GeoClue asks with the Wi-Fi networks it sees, and the service always has the address
        # the request comes from; with no Wi-Fi adapter that address is all (it looks the location up by it)
        adapters = wifi_adapters(scan)
        what = ("nearby Wi-Fi networks and this computer's internet address" if adapters is not False else
                "this computer's internet address (it has no Wi-Fi adapter, so no networks)")
        if scan.context.desktop.is_gnome:
            on = scan.gnome.gsettings("org.gnome.system.location", "enabled")
            if on is None:
                return unknown("Couldn't read GNOME's location setting.", *ev)
            ev.insert(0, Evidence.val("GNOME location services", on))
            if on:
                return failed(f"Location services are on: apps that ask send {what} to an online lookup service.", *ev)
            return passed("Location services are off.", *ev)
        if conf_text is None:
            return absent("GeoClue (location services) isn't installed.")
        if wifi:
            return warned(f"Apps can ask GeoClue for your location, which sends {what} to an online lookup service. "
                          "This desktop has no central switch for it.", *ev)
        return passed("GeoClue's online lookup is off.", *ev)


MOZILLA_TELEMETRY_APPS = ("Firefox", "LibreWolf", "Thunderbird")


def mozilla_telemetry_on(app: str, prefs: dict, policies: dict) -> dict[str, str]:
    """{the pref that turns it off: what it is} for each kind of telemetry on in a Firefox-family profile (the guide
    sets those prefs to false, and only those)."""
    default = app != "LibreWolf"            # LibreWolf ships with telemetry off; Firefox and Thunderbird on
    # Firefox's policies.json doesn't govern Thunderbird, and Thunderbird runs no studies
    policy = policies if app != "Thunderbird" else {}
    out = {}
    if not policy.get("DisableTelemetry") and prefs.get("datareporting.healthreport.uploadEnabled", default) is True:
        out["datareporting.healthreport.uploadEnabled"] = "telemetry"
    if app != "Thunderbird" and not policy.get("DisableFirefoxStudies") and \
            prefs.get("app.shield.optoutstudies.enabled", default) is True:
        out["app.shield.optoutstudies.enabled"] = "studies"
    # the daily usage ping, a separate switch (on by default in Firefox 157, greprefs.js; the DisableTelemetry
    # policy locks it off too, its Policies.sys.mjs)
    if app == "Firefox" and not policy.get("DisableTelemetry") and prefs.get("datareporting.usage.uploadEnabled", True) is True:
        out["datareporting.usage.uploadEnabled"] = "the daily usage ping"
    return out


@register
class BrowserTelemetry(Check):
    id = "tel.browser_telemetry"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, on = scan.host, [], []
        policies = firefox_policies(host)
        for p in mozilla_profiles(host, scan.paths, MOZILLA_TELEMETRY_APPS):
            what = list(mozilla_telemetry_on(p.app, firefox_prefs(host, p.path), policies).values())
            ev.append(Evidence.val(p.label, ", ".join(what) + " on" if what else "off"))
            if what:
                on.append(p.app)
        for d in chromium_dirs(scan.paths):
            state = read_json(host, d.root.path / "Local State") or {}
            policy = chromium_policies(host, d.browser)
            what = []
            if policy.get("MetricsReportingEnabled") is not False and dig(state, "user_experience_metrics", "reporting_enabled"):
                what.append("usage statistics and crash reports")
            if d.browser.startswith("Brave"):
                # both are on unless turned off in Brave Browser, or by its policy (which the guide offers): the policy
                # wins over the profile's own switch. VERIFY the defaults of other Brave editions.
                for label, keys, name in (("P3A analytics", ("p3a", "enabled"), "BraveP3AEnabled"),
                                          ("daily usage ping", ("stats", "reporting_enabled"), "BraveStatsPingEnabled")):
                    if policy.get(name) is False:
                        continue
                    v = dig(state, "brave", *keys)
                    if v is True or (v is None and d.browser == "Brave"):
                        what.append(label)
                    elif v is None:
                        ev.append(Evidence.val(f"{d.label} {label}", "browser default (not confirmed for this edition)"))
            ev.append(Evidence.val(d.label, ", ".join(what) + " on" if what else "off"))
            if what:
                on.append(d.browser)
        if not ev:
            return absent("No Firefox or Chromium-based browser profiles were found.")
        if on:
            return failed(f"Browser telemetry is on: {', '.join(sorted(set(on)))}.", *ev)
        return passed("Browser telemetry is off.", *ev)


# ------------------------------------------------------------------ developer tools

VSCODE_DIRS = ("Code/User", "Code - Insiders/User", "Code - OSS/User")
# program -> (variable, what it is, the value that opts out)
TELEMETRY_OPT_OUTS = {
    "dotnet": ("DOTNET_CLI_TELEMETRY_OPTOUT", ".NET SDK", "1"),
    "brew": ("HOMEBREW_NO_ANALYTICS", "Homebrew", "1"),
    "pwsh": ("POWERSHELL_TELEMETRY_OPTOUT", "PowerShell", "1"),
    "next": ("NEXT_TELEMETRY_DISABLED", "Next.js", "1"),
    "terraform": ("CHECKPOINT_DISABLE", "Terraform (HashiCorp checkpoint)", "1"),
    "vault": ("CHECKPOINT_DISABLE", "Vault (HashiCorp checkpoint)", "1"),
    "packer": ("CHECKPOINT_DISABLE", "Packer (HashiCorp checkpoint)", "1"),
    "az": ("AZURE_CORE_COLLECT_TELEMETRY", "Azure CLI", "0"),
    "sam": ("SAM_CLI_TELEMETRY", "AWS SAM CLI", "0"),
    "gatsby": ("GATSBY_TELEMETRY_DISABLED", "Gatsby", "1"),
    "nuxt": ("NUXT_TELEMETRY_DISABLED", "Nuxt", "1"),
    "nuxi": ("NUXT_TELEMETRY_DISABLED", "Nuxt", "1"),
    "astro": ("ASTRO_TELEMETRY_DISABLED", "Astro", "1"),
    "stripe": ("STRIPE_CLI_TELEMETRY_OPTOUT", "Stripe CLI", "1"),
    "ng": ("NG_CLI_ANALYTICS", "Angular CLI", "false"),
}
JETBRAINS_DIR = "JetBrains"
COPILOT = re.compile(r"^github\.copilot(-chat)?-", re.I)


def devtool_present(host, prog: str) -> bool:
    """Whether a developer tool whose telemetry an opt-out covers is here. dotnet is also the runtime's host alone
    (dotnet-host, which Pinta pulls in: Omarchy), which sends nothing: the telemetry is the SDK's, so it counts only
    with an SDK (`dotnet --list-sdks` lists none there)."""
    if not installed(host, prog):
        return False
    if prog == "dotnet":
        r = host.run("dotnet", "--list-sdks")
        return r.ok and bool(r.stdout.strip())
    return True


def opted_out(env: dict[str, str], var: str, value: str) -> bool:
    v = env.get(var, "").strip().lower()
    return v == value or (value == "1" and v in ("true", "yes"))


def jetbrains_stats(scan: Scan) -> list[tuple[str, bool | None]]:
    """(product directory, usage statistics allowed) for each JetBrains IDE configuration.
    VERIFY: the layout of options/usage.statistics.xml."""
    out = []
    for loc in scan.paths.config(JETBRAINS_DIR, all_flatpaks=True):
        for product in children(loc.path):
            f = product / "options" / "usage.statistics.xml"
            text = read_text(scan.host, f)
            if text is None:
                if (product / "options").is_dir():
                    out.append((product.name, None))
                continue
            m = re.search(r'name="allowed"\s+value="(true|false)"', text)
            out.append((product.name, None if not m else m.group(1) == "true"))
    return out


def copilot_installed(scan: Scan) -> bool:
    for loc in scan.paths.dotdir(".vscode", flatpak=["com.visualstudio.code"], snap=["code"]) \
            + scan.paths.dotdir(".vscode-oss") + scan.paths.dotdir(".vscodium"):
        if any(COPILOT.match(p.name) for p in children(loc.path / "extensions")):
            return True
    return False
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*['\"]?([^'\"\s#]*)", re.M)


def configured_env(scan: Scan) -> dict[str, str]:
    """Environment variables set for the session or in the usual places a user sets them."""
    out = dict(scan.host.environ)
    files = [p for p in children(scan.paths.config_home / "environment.d") if p.suffix == ".conf"]
    files += [scan.host.home / f for f in (".profile", ".bashrc", ".bash_profile", ".zshrc", ".zshenv")]
    for f in files:
        for k, v in _ENV_LINE.findall(read_text(scan.host, f) or ""):
            out.setdefault(k, v)
    return out


@register
class Devtools(Check):
    id = "tel.devtools"

    def detect(self, scan: Scan) -> Outcome:
        host, ev, on = scan.host, [], []
        for rel in VSCODE_DIRS:
            for loc in scan.paths.config(rel, flatpak=["com.visualstudio.code"], snap=["code"]):
                settings = read_jsonc(host, loc.path / "settings.json") or {}
                level = settings.get("telemetry.telemetryLevel")
                if level is None and settings.get("telemetry.enableTelemetry") is False:
                    level = "off"
                ev.append(Evidence.val(f"VS Code telemetry ({host.display(loc.path)})", level or "all (default)"))
                if level != "off":
                    on.append("VS Code")
        env = configured_env(scan)
        for prog, (var, label, value) in TELEMETRY_OPT_OUTS.items():
            if devtool_present(host, prog):
                out = opted_out(env, var, value)
                ev.append(Evidence.val(label, f"{var}={value} {'set' if out else 'not set'}"))
                if not out:
                    on.append(label)
        for product, allowed in jetbrains_stats(scan):
            ev.append(Evidence.val(f"JetBrains {product} usage statistics",
                                   "off" if allowed is False else "on" if allowed else "not decided (asked at first run)"))
            if allowed:
                on.append(f"JetBrains {product}")
        if env.get("DO_NOT_TRACK") == "1":
            ev.append(Evidence.val("DO_NOT_TRACK", "1"))
        notes = []
        if copilot_installed(scan):
            ev.append(Evidence.val("GitHub Copilot", "installed"))
            notes.append(Note("info", "An AI assistant sends your code to its service",
                              "GitHub Copilot sends the code around the cursor, and with chat whole files, to GitHub's "
                              "servers while you type. Keep it disabled in projects whose code shouldn't leave the "
                              "machine (its status bar menu, per workspace)."))
        if not ev:
            return absent("No developer tools with telemetry were found.")
        if on:
            return failed(f"Developer tools send telemetry: {', '.join(dict.fromkeys(on))}.", *ev, notes=notes)
        return passed("Developer tool telemetry is off.", *ev, notes=notes)


# ------------------------------------------------------------------ package repositories

def _repo_files(scan: Scan) -> list[tuple[str, str]]:
    """(path, text) of package repository definitions."""
    host, out = scan.host, []
    for d, suffixes in (("/etc/apt/sources.list.d", (".list", ".sources")), ("/etc/yum.repos.d", (".repo",)),
                        ("/etc/zypp/repos.d", (".repo",))):
        for f in children(host.sys_path(d)):
            if f.suffix in suffixes:
                out.append((f"{d}/{f.name}", read_text(host, f) or ""))
    for f in ("/etc/apt/sources.list", "/etc/pacman.d/mirrorlist"):
        try:
            text = host.read_sys(f)
        except Unreadable:
            text = None
        if text is not None:
            out.append((f, text))
    return out


# the lines that name a mirror: apt's one-line deb entries, deb822's URIs: (several addresses on one line; [ \t] only,
# since \s crossed into the next lines and found only a file's last address: Ubuntu's ubuntu.sources has two), dnf's and
# zypper's baseurl=, pacman's Server =
_SOURCE_LINE = re.compile(r"^[ \t]*(?:deb(?:-src)?(?:[ \t]+\[[^\]\n]*\])?[ \t]+(?P<one>\S+)|URIs:[ \t]*(?P<many>[^\n]*)"
                          r"|baseurl[ \t]*=[ \t]*(?P<base>[^\n]*)|Server[ \t]*=[ \t]*(?P<server>\S+))", re.M | re.I)
_HTTP_HOST = re.compile(r"\bhttp://([^\s/]+)", re.I)
# mirrors with no HTTPS at all (port 443 refused or timing out): never offered a switch to https
NO_HTTPS = frozenset({"packages.linuxmint.com"})


def _parts_in_use(text: str) -> list[str]:
    """The parts of a repository file in use: a deb822 stanza with "Enabled: no", or a dnf or zypper section with
    enabled=0, is never contacted, and is left out."""
    if re.search(r"^\s*\[", text, re.M):                     # sections: dnf's and zypper's .repo, pacman.conf
        return [p for p in re.split(r"(?m)^(?=\s*\[)", text) if not re.search(r"^\s*enabled\s*=\s*0\s*$", p, re.M | re.I)]
    return [p for p in re.split(r"\n[ \t]*\n", text) if not re.search(r"^Enabled:[ \t]*no[ \t]*$", p, re.M | re.I)]


def http_hosts(text: str) -> list[str]:
    """The hosts of every plain-HTTP mirror a repository file names (comments and disabled sources left out)."""
    out = []
    for part in _parts_in_use(text):
        for m in _SOURCE_LINE.finditer(part):
            out += _HTTP_HOST.findall(" ".join(v for v in m.groupdict().values() if v))
    return out


@register
class HttpRepos(Check):
    id = "tel.http_repos"

    def detect(self, scan: Scan) -> Outcome:
        files = _repo_files(scan)
        if not files:
            return absent("No apt, dnf, zypper or pacman repositories were found.")
        hosts: dict[str, list[str]] = {}
        for path, text in files:
            for host in http_hosts(text):
                hosts.setdefault(host, []).append(path)
        ev = [Evidence.val(h, ", ".join(sorted(set(p)))[:200]) for h, p in sorted(hosts.items())]
        if hosts:
            return failed(f"{len(hosts)} package mirror{'s are' if len(hosts) > 1 else ' is'} used over plain HTTP, so "
                          "the network can see which packages you install.", *ev)
        return passed("Package repositories are used over HTTPS.", Evidence.count("Repository files", len(files)))


@register
class Countme(Check):
    id = "tel.countme"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        repos = [f for f in children(host.sys_path("/etc/yum.repos.d")) if f.suffix == ".repo"]
        if not repos:
            return absent("DNF isn't used on this system.")
        counting = []
        for f in repos:
            for name, keys in ini.parse(read_text(host, f) or "").items():
                if name and ini.truthy(keys.get("enabled", "1")) and ini.truthy(keys.get("countme")):
                    counting.append(name[0])
        # VERIFY: whether [main] countme=0 in dnf.conf overrides repo files on DNF4 and DNF5
        if counting:
            return failed(f"DNF's weekly anonymous counter is on for {len(counting)} repositor"
                          f"{'ies' if len(counting) > 1 else 'y'}.", *(Evidence.val("countme=1", r) for r in counting[:10]))
        return passed("DNF's countme is off.")


# ------------------------------------------------------------------ KDE user feedback

# KUserFeedback::Provider::TelemetryMode (kuserfeedback/provider.h), which Plasma's User Feedback page writes as is;
# Plasma's default is NoTelemetry. Tested on Plasma 6.7.5: 16 shows "Basic system information", 0 "Disabled".
NO_TELEMETRY = 0
FEEDBACK_LEVELS = {16: "basic system information", 32: "basic system information and usage statistics",
                   48: "detailed system information and basic usage statistics",
                   64: "detailed system information and usage statistics"}


@register
class KdeFeedback(Check):
    id = "tel.kde_feedback"

    def detect(self, scan: Scan) -> Outcome:
        rc = scan.paths.config_home / "PlasmaUserFeedback"
        if not scan.context.desktop.is_kde and not rc.is_file():
            return absent("Not a KDE Plasma session.")
        level = scan.kde.get("PlasmaUserFeedback", "Global", "FeedbackLevel")
        n = int(level) if level and level.strip().isdigit() else NO_TELEMETRY
        ev = [Evidence.val("FeedbackLevel", level if level else "not set (disabled)")]
        if n > NO_TELEMETRY:
            return failed(f"Plasma sends {FEEDBACK_LEVELS.get(n, 'usage and system statistics')} to KDE.", *ev)
        return passed("Plasma's user feedback is off.", *ev)


# ------------------------------------------------------------------ what leaves the machine by design

# (label, base, rel, flatpak id)
SYNC_CLIENTS = (
    ("Nextcloud", "config", "Nextcloud", "com.nextcloud.desktopclient.nextcloud"),
    ("ownCloud", "config", "ownCloud", "com.owncloud.desktopclient"),
    ("Dropbox", "home", ".dropbox", "com.dropbox.Client"),
    ("Insync", "config", "Insync", None),
    ("MEGAsync", "data", "Mega Limited", "nz.mega.MEGAsync"),
    ("OneDrive (abraunegg)", "config", "onedrive", None),
    ("Google Drive (GNOME Online Accounts)", None, None, None),
)


@register
class CloudSync(Check):
    id = "tel.cloud_sync"

    def detect(self, scan: Scan) -> Outcome:
        from ..paths import Base
        host, ev, found = scan.host, [], []
        goa = ini.parse(read_text(host, scan.paths.config_home / "goa-1.0" / "accounts.conf") or "")
        providers: dict[str, int] = {}
        for group, keys in goa.items():
            if group and group[0].startswith("Account ") and keys.get("Provider"):
                providers[keys["Provider"]] = providers.get(keys["Provider"], 0) + 1
        if providers:
            found.append("GNOME Online Accounts")
            ev.append(Evidence.val("GNOME Online Accounts", ", ".join(f"{p} ({n})" for p, n in sorted(providers.items()))))
        kde = sqlite_count(scan.paths.config_home / "libaccounts-glib" / "accounts.db", "SELECT count(*) FROM Accounts")
        if kde:
            found.append("KDE online accounts")
            ev.append(Evidence.count("KDE online accounts", kde))
        for label, base, rel, fp in SYNC_CLIENTS:
            if base is None:
                continue
            kind = {"config": Base.CONFIG, "data": Base.DATA, "home": Base.HOME}[base]
            for loc in scan.paths.locate(kind, rel, flatpak=[fp] if fp else []):
                found.append(label)
                ev.append(Evidence.val(label, "set up" + ("" if loc.install == "native" else f" ({loc.install})")))
        rclone = read_text(host, scan.paths.config_home / "rclone" / "rclone.conf") or ""
        remotes = len(re.findall(r"^\[[^\]]+\]", rclone, re.M))
        if remotes:
            found.append("rclone")
            ev.append(Evidence.count("rclone remotes", remotes))
        note = Note("info", "What this means",
                    "Each of these copies calendars, contacts, mail or whole folders to a provider, who can read "
                    "them unless the client encrypts end to end (Nextcloud's E2E folders, MEGA, rclone crypt). "
                    "It is a choice, not a fault; this lists it so it can be weighed.")
        if found:
            return warned(f"Data is synced to online services by {', '.join(dict.fromkeys(found))}.", *ev, notes=[note])
        return passed("No online accounts or sync clients were found.", notes=[note])


# (unit, how it counts as on, what it does, a user unit): what it does, not how often, which each distribution sets
# in its timer and changes between releases (Fedora 44's dnf-makecache.timer: OnUnitInactiveSec=3h, not hourly)
BACKGROUND_UNITS = (
    ("fwupd-refresh.timer", "is-enabled", "fwupd: fetches firmware metadata from LVFS (fwupd.org)", False),
    ("snapd.service", "is-active", "snapd: checks the Snap Store for updates several times a day", False),
    ("apt-daily.timer", "is-enabled", "apt: downloads package lists from the mirrors", False),
    ("dnf-makecache.timer", "is-enabled", "dnf: refreshes repository metadata from the mirrors", False),
    ("packagekit.service", "is-enabled", "PackageKit: refreshes package metadata for the software centre", False),
    # Arch and CachyOS, all on by default (seen on CachyOS and Omarchy): the keyring timer is static, linked in by its
    # package, so it counts while active; Arch-Update's is the user's own
    ("archlinux-keyring-wkd-sync.timer", "is-active",
     "archlinux-keyring: refreshes the packagers' signing keys from archlinux.org", False),
    ("cachyos-rate-mirrors.timer", "is-enabled", "cachyos-rate-mirrors: contacts every mirror to rank them by speed",
     False),
    ("arch-update.timer", "is-enabled", "Arch-Update: checks the mirrors (and the AUR and Flatpak, where used) for "
                                        "updates", True),
)


@register
class BackgroundCallers(Check):
    id = "tel.background_callers"

    def detect(self, scan: Scan) -> Outcome:
        host, ev = scan.host, []
        for unit, verb, text, user in BACKGROUND_UNITS:
            state = systemctl_state(host, verb, unit, user=user)
            if state in ("enabled", "active"):
                ev.append(Evidence.val(text.split(":")[0], text.split(": ", 1)[1]))
        if systemctl_state(host, "is-active", "systemd-timesyncd") == "active":
            conf = host.read_sys("/etc/systemd/timesyncd.conf") or ""
            m = re.search(r"^\s*NTP\s*=\s*(\S.*)$", conf, re.M)
            ev.append(Evidence.val("systemd-timesyncd: asks time servers", (m.group(1).strip()[:150] if m else
                                   "the distribution's default pool (from /usr/lib/systemd/timesyncd.conf)")))
        elif systemctl_state(host, "is-active", "chronyd") == "active" or systemctl_state(host, "is-active", "chrony") == "active":
            conf = host.read_sys("/etc/chrony.conf") or host.read_sys("/etc/chrony/chrony.conf") or ""
            servers = re.findall(r"^\s*(?:pool|server)\s+(\S+)", conf, re.M)
            ev.append(Evidence.val("chrony: asks time servers", ", ".join(servers[:4]) or "the distribution's default"))
        note = Note("info", "Regular, ordinary contact",
                    "None of this sends anything about you beyond your address, and each has a job: firmware and "
                    "package updates, and the clock. They are listed so that what the machine does on its own "
                    "is known, not because they should be off.")
        if ev:
            n = len(ev)
            return warned(f"{n} service{'s contact' if n > 1 else ' contacts'} servers in the background on a schedule.",
                          *ev, notes=[note])
        return passed("No scheduled background callers were found.", notes=[note])