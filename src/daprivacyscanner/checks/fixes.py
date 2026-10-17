"""Fixes for the `auto` tier checks. Each one builds a FixPlan from what is on the machine now;
building a plan changes nothing (it is the dry run). Settings changes are reversible;
clearing history and caches is not, and the plan marks it so.

Apps that hold the data open are never stopped for the user: if one is running, its part of
the fix is skipped or the fix is blocked until it is closed. Background daemons that restart
on demand (gvfsd-metadata, zeitgeist, kactivitymanagerd) are stopped as a listed step."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .. import ini
from ..desktop import parse_gvariant
from ..fix import (ClearCommand, ClearInFile, Command, CopyQCommand, CopyQTabSet, DeleteFiles, FixPlan, GSettingsSet,
                   HashKnownHosts, KConfigSet, NmSet, PlasmaTraySet, RootChange, WriteFile, XfconfSet)
from ..model import Outcome
from . import Check, No, Scan
from ._util import (children, chromium_dirs, chromium_in_use, files_under, holders, isdir, isfile, processes, read_jsonc,
                    read_text, storage_mounts, thumbnail_entries, uri_path)


@dataclass
class FixEntry:
    plan: Callable[[Check, Scan, Outcome], FixPlan]
    can: Callable[[Scan], bool] | None = None
    needs_root: bool = False


FIXES: dict[str, FixEntry] = {}


def fix(check_id: str, can: Callable[[Scan], bool] | None = None, needs_root: bool = False):
    def register(fn):
        FIXES[check_id] = FixEntry(fn, can, needs_root)
        return fn
    return register


# ------------------------------------------------------------------ helpers

def gset(scan: Scan, schema: str, key: str, value: str) -> list[GSettingsSet]:
    """A gsettings change, or nothing if the key already has the value (or doesn't exist)."""
    now = scan.gnome.gsettings(schema, key)
    if now is None or now == parse_gvariant(value):
        return []
    return [GSettingsSet(schema, key, value)]


def kset(scan: Scan, file: str, group: str, key: str, value: str, default: str | None = None,
         then: list[str] | None = None) -> list[KConfigSet]:
    """A KDE setting written to the user's file, or nothing when it already holds the value. Judged on the value the
    program reads (the user's file over the distribution's in /etc/xdg), as the checks do: a default set there would
    otherwise leave a failing check with an empty plan. `then`: the command that has the program read it again, run
    after writing and after reverting (KConfigSet)."""
    path = scan.paths.config_home / file
    current = scan.kde.get(file, group, key)
    if (current if current is not None else default) == value:
        return []
    return [KConfigSet(scan.kde.tool("kwriteconfig"), path, file, group, key, value, then=then)]


def kscreenlocker_reload(scan: Scan) -> list[str] | None:
    """The call that has Plasma's screen locker read kscreenlockerrc again, as System Settings → Screen Locking does
    when it saves: kscreenlocker reads it only when the session starts or on this call, so a setting written without it
    applies from the next login, and one put back on revert the same. None without qdbus or dbus-send."""
    return scan.kde.dbus("org.kde.screensaver", "/ScreenSaver", "org.kde.screensaver.configure")


def delete(scan: Scan, root: Path, label: str, pattern: re.Pattern | None = None) -> list[DeleteFiles]:
    files, _ = files_under(root, pattern=pattern)
    return [DeleteFiles(root, files, label, scan.host.display(root))] if files else []


def running(scan: Scan, *names: str) -> list[str]:
    procs = processes(scan.host)
    return [n for n in names if n in procs]


def in_use(scan: Scan, directory: Path, *names: str) -> list[str]:
    """Who is using `directory` now: processes with the given names, and any process of this
    user holding a file in it open (holders). Empty when it is safe to clear."""
    return sorted(set(running(scan, *names)) | holders(scan, directory))


def _gnome_family(scan: Scan) -> str | None:
    names = set(scan.context.desktop.names)
    if names & {"x-cinnamon", "cinnamon"}:
        return "cinnamon"
    if "mate" in names:
        return "mate"
    if scan.context.desktop.is_gnome or names & {"ubuntu", "budgie", "unity", "pop"}:
        return "gnome"
    return None


def _is_gnome(scan: Scan) -> bool:
    return _gnome_family(scan) == "gnome"


def _kwriteconfig(scan: Scan) -> bool:
    return scan.host.runner.which(scan.kde.tool("kwriteconfig"))


def _nmcli(scan: Scan) -> bool:
    return scan.host.runner.which("nmcli")


# `can` answers: True, or No with what the user can do instead

def _gnome_only(scan: Scan) -> bool | No:
    return _is_gnome(scan) or No(f"The fix covers GNOME's setting, and {scan.context.desktop.this}.")


def _need_kwriteconfig(scan: Scan) -> bool | No:
    tool = scan.kde.tool("kwriteconfig")
    return bool(_kwriteconfig(scan)) or No(f"Plasma's settings are changed with {tool}, which isn't installed (it comes "
                                           "with Plasma's kconfig package): change it in System Settings instead.")


def _need_nmcli(scan: Scan) -> bool | No:
    return bool(_nmcli(scan)) or No("The fix changes NetworkManager's connections with nmcli, which isn't installed: "
                                    "change it in your network manager's settings instead.")


def _xfce(scan: Scan) -> bool:
    return "xfce" in scan.context.desktop.names and bool(scan.host.runner.which("xfconf-query"))


# ------------------------------------------------------------------ encryption

@fix("enc.trash")
def trash(check, scan, outcome):
    actions = []
    roots = [scan.paths.data_home / "Trash"]
    roots += [Path(m.target) / f".Trash-{scan.host.uid}" for m in storage_mounts(scan.host)]
    roots += [Path(m.target) / ".Trash" / str(scan.host.uid) for m in storage_mounts(scan.host)]
    seen = set()
    for r in roots:
        if isdir(r / "files") and r.resolve() not in seen:
            seen.add(r.resolve())
            actions += delete(scan, r / "files", "trashed files") + delete(scan, r / "info", "trash records")
    effects = []
    family = _gnome_family(scan)
    if family in ("gnome", "cinnamon"):
        schema = "org.cinnamon.desktop.privacy" if family == "cinnamon" else "org.gnome.desktop.privacy"
        auto = gset(scan, schema, "remove-old-trash-files", "true")
        if auto:
            age = scan.gnome.gsettings(schema, "old-files-age") or 30
            actions += auto
            effects.append(f"From now on the desktop deletes files that have been in the trash for {age} days.")
    elif scan.context.desktop.is_kde and _kwriteconfig(scan):
        # VERIFY (catalogue): ktrashrc's group (the trash folder's path) and keys
        group = str(scan.paths.data_home / "Trash")
        auto = kset(scan, "ktrashrc", group, "UseTimeLimit", "true", default="false")
        if auto:
            actions += auto + kset(scan, "ktrashrc", group, "Days", "30", default="7")
            effects.append("From now on Plasma deletes files that have been in the trash for 30 days.")
    return FixPlan(check.id, "Empty the trash", actions, side_effects=effects)


# ------------------------------------------------------------------ authentication

def _screen_lock_can(scan: Scan) -> bool | No:
    if scan.context.desktop.is_kde:
        return _need_kwriteconfig(scan)
    if _gnome_family(scan) is not None or _xfce(scan):
        return True
    return No(f"The fix covers GNOME, Cinnamon, MATE, KDE Plasma and Xfce, and {scan.context.desktop.this}: "
              "set the screen lock in your desktop's settings (lock after 5 minutes idle, and on suspend).")


def _screen_lock_page(scan: Scan, family: str | None) -> str:
    """Where the user sets the screen lock on this desktop, for a plan that has nothing left to change."""
    if scan.context.desktop.is_kde:
        return "System Settings → Screen Locking"
    if family == "cinnamon":
        return "System Settings → Screensaver"
    if family == "mate":
        return "Control Center → Screensaver"
    major = scan.context.desktop.gnome_major
    return "Settings → Privacy & Security → Screen Lock" if not major or major >= 46 else "Settings → Privacy → Screen Lock"


@fix("auth.screen_lock", can=_screen_lock_can)
def screen_lock(check, scan, outcome):
    a, effects = [], []
    family = _gnome_family(scan)
    if not scan.context.desktop.is_kde and family is None and _xfce(scan):
        from .auth import XFCE_SAVER, xfconf_get
        get = lambda prop: xfconf_get(scan.host, XFCE_SAVER, prop)  # noqa: E731
        for prop, value in (("/lock/enabled", True), ("/lock/saver-activation/enabled", True),
                            ("/saver/idle-activation/enabled", True), ("/lock/sleep-activation", True)):
            if get(prop) is not value:
                a.append(XfconfSet(XFCE_SAVER, prop, "bool", "true"))
        idle = get("/saver/idle-activation/delay")
        if idle is None or idle == 0 or idle > 5:
            a.append(XfconfSet(XFCE_SAVER, "/saver/idle-activation/delay", "int", "5"))
        delay = get("/lock/saver-activation/delay")
        if delay and delay > 1:
            a.append(XfconfSet(XFCE_SAVER, "/lock/saver-activation/delay", "int", "0"))
        return FixPlan(check.id, "Lock the screen after 5 minutes idle and on suspend", a,
                       side_effects=["The screensaver starts after 5 minutes without input, and locks the screen."])
    if scan.context.desktop.is_kde:
        # Timeout 0 is "never" (the check's "never locks when idle"); a value set in /etc/xdg counts as the user's
        timeout = int(scan.kde.get("kscreenlockerrc", "Daemon", "Timeout") or 5)
        grace = int(scan.kde.get("kscreenlockerrc", "Daemon", "LockGrace") or 5)
        # kscreenlocker reads its settings when the session starts, or when asked: asked after each change and
        # after each is put back, or the old settings would stay until the next login
        reload = kscreenlocker_reload(scan)
        a += kset(scan, "kscreenlockerrc", "Daemon", "Autolock", "true", default="true", then=reload)
        a += kset(scan, "kscreenlockerrc", "Daemon", "LockOnResume", "true", default="true", then=reload)
        if timeout == 0 or timeout > 5:
            a += kset(scan, "kscreenlockerrc", "Daemon", "Timeout", "5", then=reload)
        if grace > 60:
            a += kset(scan, "kscreenlockerrc", "Daemon", "LockGrace", "5", then=reload)
        if a:
            effects.append("The screen locker uses the new settings at once, and the old ones again at once if the fix "
                           "is reverted." if reload else
                           "The screen locker uses the new settings from your next login: neither qdbus nor dbus-send is "
                           "installed to tell it now. The same goes for reverting the fix.")
    elif family == "mate":
        a += gset(scan, "org.mate.screensaver", "lock-enabled", "true")
        idle = scan.gnome.gsettings("org.mate.screensaver", "idle-delay")
        if idle is not None and (idle == 0 or idle > 5):
            a += gset(scan, "org.mate.screensaver", "idle-delay", "5")
            effects.append("The screensaver starts after 5 minutes without input.")
        delay = scan.gnome.gsettings("org.mate.screensaver", "lock-delay")          # minutes
        if delay is not None and delay > 1:
            a += gset(scan, "org.mate.screensaver", "lock-delay", "0")
    elif family:
        saver = "org.cinnamon.desktop.screensaver" if family == "cinnamon" else "org.gnome.desktop.screensaver"
        session = "org.cinnamon.desktop.session" if family == "cinnamon" else "org.gnome.desktop.session"
        a += gset(scan, saver, "lock-enabled", "true")
        idle = scan.gnome.gsettings(session, "idle-delay")
        if idle is not None and (idle == 0 or idle > 300):
            a += gset(scan, session, "idle-delay", "uint32 300")
            # the session's idle delay: GNOME blanks the screen then (Settings → Power → Screen Blank), Cinnamon
            # starts its screensaver
            effects.append("The screensaver also starts after 5 minutes without input." if family == "cinnamon" else
                           "The screen also turns off after 5 minutes without input.")
        delay = scan.gnome.gsettings(saver, "lock-delay")
        if delay is not None and delay > 60:
            a += gset(scan, saver, "lock-delay", "uint32 0")
        if family == "cinnamon":
            a += gset(scan, "org.cinnamon.settings-daemon.plugins.power", "lock-on-suspend", "true")
        else:
            a += gset(scan, "org.gnome.desktop.screensaver", "ubuntu-lock-on-suspend", "true")
    if not a:
        # an empty plan isn't offered, and this is shown as the reason
        effects = [f"The settings Fix… changes already have its values here. Set the screen lock in "
                   f"{_screen_lock_page(scan, family)}: lock after 5 minutes idle, and on suspend."]
    return FixPlan(check.id, "Lock the screen after 5 minutes idle and on suspend", a, side_effects=effects)


@fix("auth.lockscreen_notifications", can=_gnome_only)
def lockscreen_notifications(check, scan, outcome):
    return FixPlan(check.id, "Hide notifications on the lock screen",
                   gset(scan, "org.gnome.desktop.notifications", "show-in-lock-screen", "false"))


# ------------------------------------------------------------------ authentication (files)

@fix("auth.ssh_known_hosts_plain", can=lambda scan: bool(scan.host.runner.which("ssh-keygen"))
     or No("The fix hashes the file with ssh-keygen, which isn't installed (it comes with the OpenSSH client)."))
def ssh_known_hosts(check, scan, outcome):
    from .auth import known_hosts_entries, ssh_client_option
    host = scan.host
    kh = host.home / ".ssh" / "known_hosts"
    a = []
    plain, _, markers = known_hosts_entries(read_text(host, kh) or "")
    if plain:
        a.append(HashKnownHosts(kh, host.display(kh)))
    cfg = host.home / ".ssh" / "config"
    if ssh_client_option(host, "HashKnownHosts")[0] != "yes":          # not already on, here or system-wide
        a.append(WriteFile(cfg, lambda old: "# DA Privacy Kit: store new servers hashed\nHashKnownHosts yes\n\n" + (old or ""),
                           "Add HashKnownHosts yes", host.display(cfg), mode=0o600))
    return FixPlan(check.id, "Hash the server names in known_hosts", a, side_effects=[
        "ssh still recognises every server; you just can't read their names from the file any more (ssh-keygen -F "
        "host tells you whether one is known).", "It hides the list from a casual read, not every entry: someone "
        "can still test a guessed name or IP address against it.", "Tab completion of server names after ssh, "
        "which reads this file, stops offering them.", f"A plain copy of the file is kept in History's backups for "
        f"{HashKnownHosts.BACKUP_DAYS} days, so you can revert this, then deleted (History can delete it sooner): kept "
        "longer, it would be the very list this hides. After that the names can't be put back."] + ([
            f"{markers} line{'s' if markers > 1 else ''} stay{'' if markers > 1 else 's'} readable: ssh-keygen "
            "doesn't hash certificate-authority and revoked-key lines (@cert-authority, @revoked) or wildcard "
            "patterns. They name a domain or a pattern rather than a server you visited."] if markers else []))


@fix("auth.startup_files_writable")
def startup_files_writable(check, scan, outcome):
    from ..fix import ChmodPath
    from .auth import writable_startup_files
    found, _ = writable_startup_files(scan.host)
    acts = [ChmodPath(w.path, w.mode & 0o777 & ~w.bits, w.shown) for w in found if w.owned]
    others = [w.shown for w in found if not w.owned]
    effects = ["Other accounts can still read these files if they could before; only changing them is taken away."] \
        if acts else []
    if others:
        effects.append(f"Owned by another account, so only an administrator can fix: {', '.join(others)}. Make them "
                       "yours with sudo chown $USER: FILE, or remove them if you don't know where they came from.")
    return FixPlan(check.id, "Stop other accounts changing what runs as you", acts, side_effects=effects)


# ------------------------------------------------------------------ network

@fix("net.open_autoconnect", can=_need_nmcli)
def open_autoconnect_fix(check, scan, outcome):
    from .network import open_autoconnect
    a = [NmSet(uuid, name, "connection.autoconnect", "no") for uuid, name in open_autoconnect(scan.host) or []]
    return FixPlan(check.id, "Stop open networks from reconnecting by themselves", a,
                   side_effects=["You pick these networks from the Wi-Fi menu when you want them; they no longer join "
                                 "on their own."])


@fix("net.ipv6_privacy", can=_need_nmcli)
def ipv6_privacy(check, scan, outcome):
    from .guides import dropin
    from .network import NM_DEFAULT, NM_KINDS, PRIVACY_ON, ip6_privacy_defaults, nm_connections, nm_get
    a, effects = [], ["Takes effect the next time each connection connects."]
    defaults = ip6_privacy_defaults(scan.host) or {}
    # the app's default is NetworkManager's [connection] section, searched last: a section of the distribution's that
    # sets it for a kind of network comes first, and keeps its value for that kind
    reaches = {kind: d[0] == "2" or d[2] in (None, "connection") for kind, d in defaults.items()}
    if any(d[0] != "2" for d in defaults.values()):
        a.append(dropin("nm-ipv6-privacy", {"connection:ipv6.ip6-privacy": "2"},
                        "/etc/NetworkManager/conf.d/99-daprivacyscanner-ipv6-privacy.conf"))
        effects.append("For every network that doesn't set it itself, those joined later included: NetworkManager's "
                       "default, for every account on this computer.")
        effects += [f"NetworkManager's [{d[2]}] section sets it to {d[0]} for {'Wi-Fi' if k == 'wifi' else 'wired'} "
                    "networks, and comes before the app's default: those joined later keep that value until the "
                    "section is changed by hand (in /etc/NetworkManager/conf.d)." for k, d in defaults.items()
                    if not reaches[k]]
    for nm_kind, kind in NM_KINDS.items():
        for uuid in nm_connections(scan.host, nm_kind) or []:
            v = nm_get(scan.host, uuid, "connection.id", "ipv6.ip6-privacy")
            value = v["ipv6.ip6-privacy"].strip().lower()
            if value in PRIVACY_ON or (value in NM_DEFAULT and reaches.get(kind)):
                continue                                              # takes the default, which is (or becomes) 2
            a.append(NmSet(uuid, v["connection.id"] or uuid, "ipv6.ip6-privacy", "2"))
    if not a:
        effects = ["The settings are in place already: a network connected before they were uses privacy addresses "
                   "from the next time it connects (turn Wi-Fi off and on, or unplug the cable and plug it in)."]
    return FixPlan(check.id, "Prefer temporary IPv6 addresses", a, side_effects=effects)


# ------------------------------------------------------------------ telemetry

GEOCLUE_CONF, GEOCLUE_DROPINS = "/etc/geoclue/geoclue.conf", "/etc/geoclue/conf.d"
GEOCLUE_DROPIN = "/etc/geoclue/conf.d/90-daprivacyscanner.conf"


def _location_can(scan: Scan) -> bool | No:
    if _is_gnome(scan) or isfile(scan.host.sys_path(GEOCLUE_CONF)):
        return True
    return No("GeoClue's settings file isn't there to change.")


@fix("tel.location", can=_location_can)
def location(check, scan, outcome):
    effects = ["Apps such as Weather and Maps can no longer find your location automatically."]
    if _is_gnome(scan):
        return FixPlan(check.id, "Turn off location services",
                       gset(scan, "org.gnome.system.location", "enabled", "false"), side_effects=effects)
    # no desktop switch: GeoClue's own Wi-Fi lookup, for every account. GeoClue 2.7 reads conf.d
    # (later files win); older releases only geoclue.conf, edited by the helper's fixed rule.
    if isdir(scan.host.sys_path(GEOCLUE_DROPINS)):
        a = [RootChange("write_dropin", {"name": "geoclue", "settings": {"enable": "false"}},
                        f"Write {GEOCLUE_DROPIN} with [wifi] enable=false")]
    else:
        a = [RootChange("edit_config", {"target": "geoclue"}, f"Set enable=false in the [wifi] section of {GEOCLUE_CONF}")]
    effects += ["For every account on this computer: GeoClue no longer sends nearby Wi-Fi networks to an online "
                "lookup service. It applies when GeoClue next starts (it stops by itself a minute after no app uses "
                "it), or after a restart."]
    return FixPlan(check.id, "Turn off GeoClue's online location lookup", a, side_effects=effects)


def set_jsonc_key(text: str | None, key: str, value: str) -> str:
    """Set a top-level key in a JSON-with-comments file, changing nothing else in it."""
    if not text or not text.strip():
        return "{\n    " + f'"{key}": {value}' + "\n}\n"
    pattern = re.compile(r'("' + re.escape(key) + r'"\s*:\s*)("(?:[^"\\]|\\.)*"|true|false|null|-?\d+(?:\.\d+)?)')
    if pattern.search(text):
        return pattern.sub(lambda m: m.group(1) + value, text, count=1)
    i = text.index("{") + 1
    rest = text[i:]
    comma = "," if rest.strip() and not rest.strip().startswith("}") else ""
    return text[:i] + f'\n    "{key}": {value}{comma}' + rest


ENV_FILE = "60-daprivacyscanner-telemetry.conf"


@fix("tel.devtools")
def devtools(check, scan, outcome):
    from .telemetry import TELEMETRY_OPT_OUTS, VSCODE_DIRS, configured_env, jetbrains_stats, opted_out
    a, effects = [], []
    for rel in VSCODE_DIRS:
        for loc in scan.paths.config(rel, flatpak=["com.visualstudio.code"], snap=["code"]):
            settings = read_jsonc(scan.host, loc.path / "settings.json") or {}
            if settings.get("telemetry.telemetryLevel") != "off":
                a.append(WriteFile(loc.path / "settings.json",
                                   lambda old: set_jsonc_key(old, "telemetry.telemetryLevel", '"off"'),
                                   'Set "telemetry.telemetryLevel": "off"', scan.host.display(loc.path / "settings.json")))
    env = configured_env(scan)
    missing = dict.fromkeys((var, value) for prog, (var, _, value) in TELEMETRY_OPT_OUTS.items()
                            if scan.host.runner.which(prog) and not opted_out(env, var, value))
    if missing:
        path = scan.paths.config_home / "environment.d" / ENV_FILE
        lines = "".join(f"{var}={value}\n" for var, value in missing)
        a.append(WriteFile(path, lambda old: (old or "# Telemetry opt-outs (DA Privacy Kit)\n") + lines,
                           f"Add {', '.join(f'{var}={value}' for var, value in missing)}", scan.host.display(path)))
        effects.append("The environment variables apply from your next login.")
    for product, allowed in jetbrains_stats(scan):
        if allowed:
            effects.append(f"JetBrains {product}: turn off Settings → Appearance & Behavior → System Settings → "
                           "Data Sharing yourself (its settings files are only safe to edit from the IDE).")
    return FixPlan(check.id, "Turn off developer tool telemetry", a, side_effects=effects)


@fix("tel.kde_feedback", can=_need_kwriteconfig)
def kde_feedback(check, scan, outcome):
    return FixPlan(check.id, "Turn off Plasma's user feedback",
                   kset(scan, "PlasmaUserFeedback", "Global", "FeedbackLevel", "0", default="0"),
                   side_effects=["System Settings → Privacy → User Feedback shows Disabled."])


@fix("tel.countme", needs_root=True)
def countme(check, scan, outcome):
    return FixPlan(check.id, "Turn off DNF's countme", [
        RootChange("edit_config", {"target": "countme"}, "Set countme=0 wherever a repository file in "
                                                          "/etc/yum.repos.d or /etc/dnf/dnf.conf has countme=1")],
        side_effects=["Fedora's anonymous count of active systems no longer includes this machine."])


@fix("kern.dmesg_restrict", needs_root=True)
def dmesg_restrict(check, scan, outcome):
    return FixPlan(check.id, "Let only administrators read the kernel log", [
        RootChange("set_sysctl", {"key": "kernel.dmesg_restrict", "value": "1"}, "sysctl kernel.dmesg_restrict=1 (now)"),
        RootChange("write_dropin", {"name": "sysctl-dmesg", "settings": {"kernel.dmesg_restrict": "1"}},
                   "Write /etc/sysctl.d/60-daprivacyscanner-dmesg.conf with kernel.dmesg_restrict = 1 (at boot)")],
        side_effects=["`dmesg` then needs sudo; members of adm, wheel or systemd-journal can still read kernel "
                      "messages with journalctl."])


# ------------------------------------------------------------------ browsers

BROWSER_PROCESSES = {"Google Chrome": ("chrome",), "Chromium": ("chromium", "chromium-browse"), "Brave": ("brave",),
                     "Microsoft Edge": ("msedge",), "Vivaldi": ("vivaldi-bin",), "Opera": ("opera",)}


def _browser_procs(name: str) -> tuple[str, ...]:
    return next((v for k, v in BROWSER_PROCESSES.items() if name.startswith(k)), ())


@fix("br.crashpad_dumps")
def crashpad(check, scan, outcome):
    from .browser import crash_dumps
    from .guides import mozilla_open
    a, blockers = [], []
    procs = processes(scan.host)
    flatpaks = None
    for c in crash_dumps(scan):
        if c.kind == "chromium":
            busy = running(scan, *_browser_procs(c.app)) or chromium_in_use(c.root.parent) or holders(scan, c.root.parent)
        elif c.kind == "mozilla":
            busy = c.app in mozilla_open(scan, (c.app,)) or holders(scan, c.root)
        else:
            if flatpaks is None:
                flatpaks = _flatpak_running(scan)
            busy = (c.app in flatpaks if "." in c.app else _app_running(c.app, procs)) or holders(scan, c.root.parent)
        name = c.label.removesuffix(" (Electron)") if c.kind == "electron" else c.app
        if busy:
            blockers.append(f"Close {name} first.")
            continue
        a.append(DeleteFiles(c.root, c.files, f"{c.label} crash dumps", scan.host.display(c.root)))
    blockers = list(dict.fromkeys(blockers))
    return FixPlan(check.id, "Delete browser and app crash dumps", a, blockers=blockers if not a else [],
                   side_effects=[f"Skipped: {b}" for b in blockers] if a and blockers else [])


# ------------------------------------------------------------------ desktop

def thumbnail_deletions(scan: Scan, everything: bool = False, only: Path | None = None) -> list[DeleteFiles]:
    """The thumbnails that leak (of deleted files, and of files on removable or encrypted
    drives), or with `everything` all of them, as deletions per cache folder (the `fail/`
    markers count as their own); with `only`, one deletion of everything under that cache
    folder, subfolders pruned (so it can be mounted over). Used by the desk.thumbnails guide."""
    from .desktop import _exists, sensitive_place
    place_of = sensitive_place(scan)
    by_dir: dict[Path, list[Path]] = {}
    for png, uri in thumbnail_entries(scan.paths)[0]:
        path = uri_path(uri)
        if path is None and not everything:
            continue
        if everything or place_of(path) or not _exists(path):
            folder = only if only is not None and png.is_relative_to(only) else png.parent.parent
            by_dir.setdefault(folder, []).append(png)
    label = "every cached thumbnail" if everything else "thumbnails of deleted files and of removable or encrypted drives"
    return [DeleteFiles(d, files, label, scan.host.display(d), prune=everything)
            for d, files in by_dir.items() if only is None or d == only]


# VERIFY: the Plasma 6 unit name of the activity manager
KAMD_UNIT = "plasma-kactivitymanagerd.service"


@fix("desk.kde_activities")
def kde_activities(check, scan, outcome):
    data = scan.paths.data_home
    db_dir = data / "kactivitymanagerd" / "resources"
    a = delete(scan, db_dir, "KDE activity history", re.compile(r"^database(-wal|-shm)?$"))
    a += delete(scan, data / "RecentDocuments", "KDE recent documents", re.compile(r"\.desktop$"))
    blockers = []
    if any(isinstance(x, DeleteFiles) and x.root == db_dir for x in a):
        if "kactivitymanage" in processes(scan.host):
            r = scan.host.run("systemctl", "--user", "cat", KAMD_UNIT)
            if not r.ok:
                blockers.append("The activity manager is running and its service couldn't be found to stop it.")
            else:
                a += [Command(["systemctl", "--user", "stop", KAMD_UNIT], "it holds the database open"),
                      Command(["systemctl", "--user", "start", KAMD_UNIT], "start it again", after=True)]
    effects = ["Favourites and frequently used lists in the launcher start empty."]
    if _kwriteconfig(scan):         # or it fills again within a day
        a += kset(scan, "kdeglobals", "RecentDocuments", "UseRecent", "false", default="true")
        # 2 = NoApplications in kactivitymanagerd's StatsPlugin: no events, titles or file types are written
        a += kset(scan, "kactivitymanagerd-pluginsrc", "Plugin-org.kde.ActivityManager.Resources.Scoring",
                  "what-to-remember", "2", default="0")
        effects.append("From now on KDE doesn't remember the files and apps you open: Recent Documents and the "
                       "launcher's recent and frequent lists stay empty. Reverting turns it back on.")
    return FixPlan(check.id, "Clear and stop KDE's activity history and recent documents", a, blockers=blockers,
                   side_effects=effects)


KLIPPER_CLEAR = ("org.kde.klipper", "/klipper", "org.kde.klipper.klipper.clearClipboardHistory")
COPYQ_PACKAGES = {"debian": "copyq", "fedora": "copyq", "arch": "copyq", "suse": "CopyQ"}

# What Klipper's "prevent empty clipboard" does (plasma-workspace klipper/historymodel.cpp), as a CopyQ script
# command: when the app that owned the clipboard quits, the clipboard is empty, and CopyQ calls onClipboardChanged
# with no data; the newest item of its clipboard tab is put back. It carries KDE's application/x-kde-onlyReplaceEmpty,
# as Klipper's does: KWin takes it only while the clipboard is still empty (6.7), and only once the app that had
# it has quit (6.8, kwin src/wayland/seat.cpp), so it never replaces a newer copy. What a password manager marks
# as a password (x-kde-passwordManagerHint) CopyQ never keeps, so it is never put back. Tested with CopyQ 16 on
# Plasma 6.7.5: the text survived its app quitting; a marked password, cleared by its app, did not come back. Pinned
# items keep their rows and new copies go in below them (plugins/itempinned): the newest copy is the first item that
# isn't pinned (tested: with row 0 pinned, a version taking row 0 put the pinned item back).
COPYQ_KEEP_NAME = "Keep the clipboard when its app closes (DA Privacy Kit)"
COPYQ_KEEP_SCRIPT = """copyq:
// Added by DA Privacy Kit. Like Klipper: when the app you copied from quits, what you copied stays on the
// clipboard (the newest item, from memory). Remove this command to turn it off.
var onClipboardChanged_ = onClipboardChanged
onClipboardChanged = function() {
    if (isClipboard() && !hasData()) {
        var name = config("clipboard_tab")
        if (name && tab().indexOf(name) != -1) {
            tab(name)
            // the newest copy: the first item that isn't pinned (pinned items keep their place at the top)
            for (var row = 0; row < size(); ++row) {
                var item = getItem(row)
                if ("application/x-copyq-item-pinned" in item)
                    continue
                item["application/x-kde-onlyReplaceEmpty"] = "1"
                try { copy(item) } catch (e) {}
                return
            }
        }
    }
    onClipboardChanged_()
}
"""


def _klipper(scan: Scan, a: list, effects: list, blockers: list) -> None:
    from ..desktop import APPLETSRC, tray_script
    from .desktop import KLIPPER_APPLET, klipper
    k = klipper(scan)
    files = files_under(k.folder)[0]
    if not k.on and not files:
        return
    applet = scan.kde.applet(KLIPPER_APPLET)
    if not k.on:                                # already off: what it left
        users = in_use(scan, k.folder, "klipper")
        if users == ["plasmashell"]:
            blockers.append("Log out and back in first: Plasma keeps Klipper's old history file open until then "
                            "(Klipper itself is off).")
        elif users:
            blockers.append(f"Close {', '.join(users)} first: it has Klipper's old history open.")
        else:
            a += delete(scan, k.folder, "Klipper clipboard history")
        return
    a += kset(scan, "klipperrc", "General", "KeepClipboardContents", "false", default="true")
    if not k.plasma6 or not applet.trays:
        # Plasma 5 (its tray is out of the script's reach: VERIFY a way on Plasma 5), or Klipper in a widget of its own
        effects.append("Klipper's history starts empty after each login.")
        if applet.widget:
            effects.append("To turn Klipper off, remove the Clipboard widget from your panel or desktop "
                           "(right-click it → Remove).")
        if applet.tray5:
            effects.append("To turn Klipper off, right-click the clipboard icon → Configure System Tray… → Entries → "
                           "Clipboard: Disabled.")
        if in_use(scan, k.folder, "klipper"):
            effects.append("Klipper has its history file open, so the file is left for now: log out and back in, "
                           "then Fix… deletes it.")
        else:
            a += delete(scan, k.folder, "Klipper clipboard history")
        return
    if applet.widget:
        blockers.append("Remove the Clipboard widget from your panel or desktop first (right-click it → Remove): "
                        "Klipper runs in it too.")
    tray = {state: scan.kde.dbus("org.kde.plasmashell", "/PlasmaShell", "org.kde.PlasmaShell.evaluateScript",
                                 tray_script(KLIPPER_APPLET, state == "on", applet.trays)) for state in ("on", "off")}
    clear = scan.kde.dbus(*KLIPPER_CLEAR)
    why = ("Klipper is turned off through Plasma's own system tray: run Fix… again while you are logged in to Plasma."
           if "plasmashell" not in processes(scan.host) else
           "Klipper is turned off over D-Bus, and neither qdbus6 nor dbus-send is installed."
           if clear is None or None in tray.values() else None)
    if why:
        effects.append(why)
        if not in_use(scan, k.folder, "klipper"):
            a += delete(scan, k.folder, "Klipper clipboard history")
        return
    if files:
        a.append(ClearCommand(clear, "Klipper deletes its history, with what was copied, while it still runs"))
    a.append(PlasmaTraySet(KLIPPER_APPLET, "Clipboard (Klipper)", scan.paths.config_home / APPLETSRC,
                           list(applet.trays), tray, "off", phase=3))
    effects.append("Klipper stops at once and stays off. What you copy still pastes, but it goes when the app you "
                   "copied it from closes, and Meta+V no longer shows a history.")
    if files:
        effects.append("Plasma may keep Klipper's emptied history file open until you log out: if it is still there "
                       "then, Fix… deletes it after you log back in.")


def _copyq(scan: Scan, a: list, effects: list, blockers: list) -> None:
    from .desktop import copyq
    for q in copyq(scan):
        if not q.records:
            continue
        users = in_use(scan, q.config, "copyq")
        if users:
            blockers.append(f"Close {', '.join(users)} first (its tray icon → Exit): CopyQ's settings can only be "
                            "changed while it is closed.")
            continue
        shown = scan.host.display(q.config / "copyq.conf")
        if q.stores:
            a.append(CopyQTabSet(q.config / "copyq.conf", shown, q.tab, "store_items", "false",
                                 f'CopyQ keeps its tab "{q.tab}" in memory only (its "Save Items" off)'))
            commands = q.config / "copyq-commands.ini"
            ours = CopyQCommand.find(read_text(scan.host, commands), COPYQ_KEEP_NAME)
            if ours is None or ini.qsettings_value(ours.get("Command", "")) != COPYQ_KEEP_SCRIPT:   # missing, or older
                a.append(CopyQCommand(commands, scan.host.display(commands), COPYQ_KEEP_NAME, COPYQ_KEEP_SCRIPT,
                                      "CopyQ keeps what you copied on the clipboard when the app you copied it from "
                                      "closes, as Klipper does"))
                effects.append("When the app you copied from closes, CopyQ puts what you copied back on the clipboard "
                               "(from memory), as Klipper does; a password your password manager clears isn't "
                               "kept, so it doesn't come back. Removing the command in CopyQ (Commands) turns this off.")
        if q.tab_bytes and (not q.others or not q.items):
            # with no other tab, every item file is this tab's; with other tabs, they may be theirs
            for f in q.tab_files:               # beside copyq.conf (to CopyQ 16) or in its data folder (17)
                a.append(DeleteFiles(f.parent, [f], "CopyQ clipboard history", scan.host.display(f.parent)))
            if q.items and not q.others:
                a.append(DeleteFiles(q.data / "items", q.items, "CopyQ's larger copied items", scan.host.display(q.data)))
        elif q.tab_bytes:
            effects.append(f'CopyQ deletes its old history of "{q.tab}" itself the next time it starts, and the larger '
                           "items in it when it quits: they share a folder with your other tabs' items, so the app "
                           "leaves them to CopyQ.")
        effects.append("CopyQ keeps what you copy while it runs; the history is gone when it quits or the computer "
                       "restarts. Your other CopyQ tabs are kept as they are.")


@fix("desk.clipboard_history")
def clipboard(check, scan, outcome):
    from .desktop import CLIPBOARD_FILES, COPYQ_FLATPAK, copyq
    p = scan.paths
    a, effects, blockers = [], [], []
    _klipper(scan, a, effects, blockers)
    _copyq(scan, a, effects, blockers)
    for label, root, procs in (("GPaste", p.data_home / "gpaste", ("gpaste-daemon",)),
                               ("Clipman", p.cache_home / "xfce4" / "clipman", ("xfce4-clipman",)),
                               ("Clipboard Indicator", p.cache_home / "clipboard-indicator@tudmotu.com", ()),
                               ("Diodon", p.data_home / "diodon", ("diodon",))):
        files = files_under(root, pattern=CLIPBOARD_FILES)[0]
        if not files:
            continue
        users = in_use(scan, root, *procs)
        if users:
            blockers.append(f"Close {', '.join(users)} first: it keeps {label}'s history open.")
            continue
        a.append(DeleteFiles(root, files, f"{label} clipboard history", scan.host.display(root)))
        if label == "Clipboard Indicator":
            effects.append("Turn off the extension's \"cache\" option too, or it saves its history again.")
    if files_under(p.data_home / "pano@elhan.io", pattern=CLIPBOARD_FILES)[0]:
        # it runs inside GNOME Shell, which holds its database open and can't be closed
        effects.append("Pano runs inside GNOME Shell, so its history can't be deleted from outside: clear it from "
                       "Pano's own menu, and turn off its history in its settings (Extensions → Pano).")
    if any(isinstance(x, PlasmaTraySet) for x in a) and not copyq(scan):
        from .guides import install
        cmd = install(scan, **COPYQ_PACKAGES) or f"flatpak install flathub {COPYQ_FLATPAK}"
        effects.append(f"Want a clipboard history that never reaches the disk, and what you copied kept when its app "
                       f"closes, as Klipper did? Install CopyQ ({cmd}) and start it: the next scan finds it, and Fix… "
                       "sets it up that way.")
    return FixPlan(check.id, "Clear saved clipboard history and stop it being saved", a, blockers=blockers,
                   side_effects=effects)


ZEITGEIST_SERVICES = ("org.gnome.zeitgeist.Engine", "org.gnome.zeitgeist.SimpleIndexer")


@fix("desk.zeitgeist")
def zeitgeist(check, scan, outcome):
    a = delete(scan, scan.paths.data_home / "zeitgeist", "Zeitgeist activity log", re.compile(r"^activity\.sqlite"))
    system = scan.host.sys_path("/etc/xdg/autostart/zeitgeist-datahub.desktop")
    if isfile(system):
        override = scan.paths.config_home / "autostart" / "zeitgeist-datahub.desktop"
        text = read_text(scan.host, system) or ""
        a.append(WriteFile(override, lambda old: text.rstrip("\n") + "\nHidden=true\n",
                           "Stop the Zeitgeist logger from starting at login", scan.host.display(override)))
    # the daemon is started over D-Bus whenever something asks for it (apps with Zeitgeist plugins log to it
    # directly): a service file of the user's own, which wins over the system's, starts /bin/false instead
    # (tested with dbus-broker on CachyOS: a user file overrides a system one, picked up without a restart)
    for name in ZEITGEIST_SERVICES:
        f = scan.paths.data_home / "dbus-1" / "services" / f"{name}.service"
        if "Exec=/bin/false" not in (read_text(scan.host, f) or ""):
            a.append(WriteFile(f, lambda old, n=name: f"[D-BUS Service]\nName={n}\nExec=/bin/false\n",
                               f"Don't start {name} when something asks for it", scan.host.display(f)))
    if "zeitgeist-daemon" in processes(scan.host):
        a.append(Command(["zeitgeist-daemon", "--quit"], "it holds the log open", check_ok=False))
    return FixPlan(check.id, "Clear and turn off the Zeitgeist activity log", a, side_effects=[
        "Apps that show recent activity through Zeitgeist (some docks and launchers) show none. Reverting from "
        "History lets it start again."])


@fix("desk.gnome_app_usage")
def gnome_app_usage(check, scan, outcome):
    # outside GNOME only the record a GNOME session left behind is deleted
    a = gset(scan, "org.gnome.desktop.privacy", "remember-app-usage", "false") if _is_gnome(scan) else []
    state = scan.paths.data_home / "gnome-shell" / "application_state"
    if isfile(state):
        a.append(DeleteFiles(state.parent, [state], "GNOME app usage record", scan.host.display(state.parent)))
    return FixPlan(check.id, "Stop and clear GNOME's app usage tracking", a,
                   side_effects=["The Frequent apps list in the app grid stops updating."])


def _session_restore_can(scan: Scan) -> bool | No:
    if scan.context.desktop.is_kde:
        return _need_kwriteconfig(scan)
    if "xfce" in scan.context.desktop.names:
        return _xfce(scan) or No("Xfce's settings are changed with xfconf-query, which isn't installed: untick \"Save "
                                 "session for future logins\" when you log out instead.")
    return _gnome_family(scan) in ("gnome", "cinnamon", "mate") or No(
        f"The fix covers GNOME, Cinnamon, MATE, Xfce and KDE Plasma, and {scan.context.desktop.this}.")


@fix("desk.session_restore", can=_session_restore_can)
def session_restore(check, scan, outcome):
    effects = []
    if scan.context.desktop.is_kde:
        a = kset(scan, "ksmserverrc", "General", "loginMode", "emptySession", default="restorePreviousLogout")
    elif "xfce" in scan.context.desktop.names:
        from .desktop import XFCE_SESSION, xfce_session
        x = xfce_session(scan)
        a = [XfconfSet(XFCE_SESSION, "/general/SaveOnExit", "bool", "false")] if x.saves is not False else []
        a += [XfconfSet(XFCE_SESSION, "/general/ShowScreenshots", "bool", "false")] if x.screenshots else []
        if x.saved:
            a.append(DeleteFiles(x.saved[0].parent, x.saved, "saved Xfce sessions", scan.host.display(x.saved[0].parent)))
        if x.thumbs:
            a.append(DeleteFiles(x.thumbs[0].parent.parent, x.thumbs, "Xfce's logout screenshots",
                                 scan.host.display(x.thumbs[0].parent.parent)))
        effects.append("The logout dialog's \"Save session for future logins\" box starts unticked: ticking it saves the "
                       "session again. It no longer keeps a screenshot of the screen for the session list.")
    else:
        schema = {"cinnamon": "org.cinnamon.SessionManager", "mate": "org.mate.session"}.get(
            _gnome_family(scan) or "", "org.gnome.SessionManager")
        a = gset(scan, schema, "auto-save-session", "false")
    return FixPlan(check.id, "Start each login with an empty session", a, side_effects=effects)


# ------------------------------------------------------------------ apps

def _clear_vlc_recents(text: str) -> str:
    """VLC's recent media emptied: list= and times= of the [RecentsMRL] group only; every other setting kept."""
    def group(m: re.Match) -> str:
        return re.sub(r"^(list|times)=.*$", r"\1=", m.group(0), flags=re.M)
    return re.sub(r"^\[RecentsMRL\][ \t]*\n(?:(?!\[).*(?:\n|$))*", group, text, count=1, flags=re.M)


@fix("app.media_players")
def media_players(check, scan, outcome):
    from ..paths import Base
    a, effects = [], []
    mpv_dirs = [loc.path for kind in (Base.STATE, Base.CONFIG)
                for loc in scan.paths.locate(kind, "mpv/watch_later", flatpak=["io.mpv.Mpv"])]
    if running(scan, "mpv") or any(holders(scan, d) for d in mpv_dirs):
        effects.append("Skipped mpv: close it first.")
    else:
        for d in mpv_dirs:
            a += delete(scan, d, "mpv resume points")
    vlc_dirs = [loc.path for loc in scan.paths.config("vlc", flatpak=["org.videolan.VLC"], snap=["vlc"])]
    if running(scan, "vlc") or any(holders(scan, d) for d in vlc_dirs):
        effects.append("Skipped VLC: close it first.")
    else:
        for loc in scan.paths.config("vlc", flatpak=["org.videolan.VLC"], snap=["vlc"]):
            qt = loc.path / "vlc-qt-interface.conf"
            text = read_text(scan.host, qt) or ""
            if _clear_vlc_recents(text) != text:
                a.append(ClearInFile(qt, _clear_vlc_recents, "Empty VLC's list of recent media", scan.host.display(qt),
                                     settings=True))
            vlcrc = loc.path / "vlcrc"
            if isfile(vlcrc) and not re.search(r"^qt-recentplay=0", read_text(scan.host, vlcrc) or "", re.M):
                a.append(WriteFile(vlcrc, lambda old: re.sub(r"^#?\s*qt-recentplay=.*$", "qt-recentplay=0", old or "", flags=re.M)
                                   if re.search(r"^#?\s*qt-recentplay=", old or "", re.M) else (old or "") + "\n[qt]\nqt-recentplay=0\n",
                                   "Stop VLC from keeping recent media", scan.host.display(vlcrc)))
    for loc in scan.paths.config("smplayer", flatpak=["info.smplayer.SMPlayer"]):
        if in_use(scan, loc.path, "smplayer"):
            effects.append("Skipped SMPlayer: close it first.")
            continue
        a += delete(scan, loc.path / "file_settings", "SMPlayer per-file settings")
    from .apps import CELLULOID_FLATPAK, HARUNA_NEVER, haruna
    for loc in scan.paths.config("celluloid/watch_later", flatpak=[CELLULOID_FLATPAK]):
        if in_use(scan, loc.path, "celluloid"):
            effects.append("Skipped Celluloid: close it first.")
            continue
        a += delete(scan, loc.path, "Celluloid resume points")
    for h in haruna(scan):
        if running(scan, "haruna") or holders(scan, h.db.parent):
            effects.append("Skipped Haruna: close it first.")
            continue
        if (h.recent or h.positions) and h.only_history:
            a += delete(scan, h.db.parent, "Haruna's database of recent files and resume points (it holds nothing "
                        "else; Haruna makes it again)", re.compile(r"^haruna\.db(-wal|-shm|-journal)?$"))
        elif h.recent or h.positions:
            effects.append("Haruna's recent files and resume points are left: its database (haruna.db) now holds more "
                           "than those, so it isn't deleted. Clear them in Haruna instead.")
        if h.last:
            a.append(ClearInFile(h.conf, lambda t: re.sub(r"^LastPlayedFile(\[\$e\])?=.*\n?", "", t, flags=re.M),
                                 "Remove the last file Haruna played from its settings", scan.host.display(h.conf),
                                 settings=True))
        if _kwriteconfig(scan):         # or it fills again
            file = str(h.conf.relative_to(scan.paths.config_home)) if h.conf.is_relative_to(scan.paths.config_home) else None
            if file:
                a += kset(scan, file, "General", "MaxRecentFiles", "0", default="10")
                a += kset(scan, file, "Playback", "MinDurationToSavePosition", HARUNA_NEVER, default="1")
                effects.append("From now on Haruna keeps no recent files list and no resume points (only for videos "
                               "longer than 9999 minutes, the most its settings offer). Reverting turns them back on. "
                               "It still notes the last file it played: no setting stops that (tested with Haruna 1.8).")
    return FixPlan(check.id, "Clear media player history", a, side_effects=effects)


@fix("desk.folder_view_records")
def folder_view_records(check, scan, outcome):
    root = scan.paths.data_home / "dolphin" / "view_properties"
    a = delete(scan, root, "Dolphin's per-folder view records")
    # one view for every folder: Dolphin then keeps no record per folder
    a += kset(scan, "dolphinrc", "General", "GlobalViewProps", "true", default="false")
    return FixPlan(check.id, "Clear Dolphin's folder records and stop keeping them", a, side_effects=[
        "Every folder uses the same view settings (icons or details, sorting) instead of remembering its own.",
        "Any .directory files on USB drives are left alone: they are on the drive, and can hold folder icons you chose."])


def clear_kconfig_group(group: str):
    """An edit for ClearInFile: a KDE settings file with the entries of one group removed, its header kept (a
    KConfigLock may mark it next)."""
    def edit(text: str) -> str:
        return re.sub(rf"(^\[{re.escape(group)}\](?:\[\$i\])?[ \t]*\n)(?:(?!\[).*\n?)*", r"\1\n", text, count=1, flags=re.M)
    return edit


@fix("app.pdf_readers")
def pdf_readers(check, scan, outcome):
    from .apps import OKULAR_FLATPAK, zathura_history
    a, effects, blockers = [], [], []
    locs = scan.paths.data("okular/docdata", flatpak=[OKULAR_FLATPAK])
    if locs:
        if running(scan, "okular") or any(holders(scan, loc.path) for loc in locs):
            blockers.append("Close Okular first.")
        else:
            for loc in locs:
                a += delete(scan, loc.path, "Okular document history")
            effects.append("Okular forgets where you stopped reading each document. Its Open Recent list is cleared "
                           "with the other KDE apps' lists (app.kde_recent_files).")
    zfiles, zdocs, marks = zathura_history(scan)
    if zdocs:
        if running(scan, "zathura"):
            blockers.append("Close Zathura first.")
        elif marks:
            effects.append(f"Zathura's database also holds {marks} bookmark{'s' if marks > 1 else ''} of yours, so it is "
                           "left: delete it yourself if you don't need them (" + ", ".join(
                               scan.host.display(f) for f in zfiles) + "). `set database \"null\"` in zathurarc stops "
                           "it keeping anything, bookmarks included.")
        else:
            a += [DeleteFiles(f.parent, [f], "Zathura's document history", scan.host.display(f.parent)) for f in zfiles]
            effects.append("Zathura forgets the documents you opened and the page each was left at. "
                           "`set database \"null\"` in zathurarc stops it keeping them.")
    return FixPlan(check.id, "Clear PDF readers' document history", a,
                   blockers=blockers if not a else [], side_effects=effects + [f"Skipped: {b}" for b in blockers if a])


def _app_running(name: str, procs: set[str]) -> bool:
    """A process named like the app's config folder (a hint; holders() is what decides)."""
    n = name.lower().replace(" ", "")
    known = {"code": "code", "vscodium": "codium", "slack": "slack", "discord": "discord", "signal": "signal-desktop",
             "element": "element-desktop", "obsidian": "obsidian", "teams-for-linux": "teams-for-linux"}
    want = known.get(n, n)
    return any(p.lower() == want or p.lower().startswith(want[:15]) for p in procs)


@fix("app.electron_caches")
def electron_caches(check, scan, outcome):
    from .apps import BROWSER_DIRS, ELECTRON_CACHES
    procs = processes(scan.host)
    a, effects = [], []
    roots = [(d, d.name) for d in children(scan.paths.config_home)]
    flatpak_running = _flatpak_running(scan)
    for app in scan.paths.flatpak_apps():
        roots += [(d, app) for d in children(scan.paths.flatpak_root / app / "config")]
    for d, owner in roots:
        if d.name in BROWSER_DIRS or not isdir(d) or not (isdir(d / "GPUCache") or isdir(d / "Code Cache")):
            continue
        caches = [d / c for c in ELECTRON_CACHES if files_under(d / c, limit=1)[0]]
        if not caches:
            continue
        busy = (owner in flatpak_running if "." in owner else _app_running(owner, procs)) or holders(scan, d)
        if busy:
            effects.append(f"Skipped {d.name}: it is running. Close it and run the fix again.")
            continue
        for c in caches:
            a += delete(scan, c, f"{d.name} cache")
    return FixPlan(check.id, "Clear Electron app caches", a, side_effects=effects,
                   blockers=[] if a or not effects else ["Every app with a cache is running; close them first."])


def _flatpak_running(scan: Scan) -> set[str]:
    r = scan.host.run("flatpak", "ps", "--columns=application")
    return {ln.strip() for ln in r.stdout.splitlines() if ln.strip()} if r.ok else set()


@fix("sbx.flatpak_caches")
def flatpak_caches(check, scan, outcome):
    busy = _flatpak_running(scan)
    a, effects = [], []
    for app in scan.paths.flatpak_apps():
        root = scan.paths.flatpak_root / app / "cache"
        if not files_under(root, limit=1)[0]:
            continue
        if app in busy or holders(scan, root):
            effects.append(f"Skipped {app}: it is running.")
            continue
        a += delete(scan, root, f"{app} cache")
    return FixPlan(check.id, "Clear Flatpak app caches", a, side_effects=effects)
