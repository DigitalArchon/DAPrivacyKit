"""Sandboxing and permissions (sbx.*)."""

from __future__ import annotations

import os
from pathlib import Path

from .. import ini
from ..host import Host
from ..model import Evidence, Note, Outcome
from . import Check, Scan, register
from ._util import Tally, absent, failed, human_size, link_note, own_dir, passed, read_text, tally, unknown, warned

BROAD_FS = ("host", "host-os", "host-etc", "home", "~", "/", "/home", "/var/home")
# a folder the app could change its own permissions or the user's session through: Flatpak's overrides (and the apps'
# exports) are in xdg-data, autostart entries and the shell's start files run outside any sandbox at the next login
_DATA = "your programs' data, Flatpak's own permission overrides among them"
_CONFIG = "every program's settings, what starts at login among them"
ESCAPE_FS = {"xdg-data": _DATA, "~/.local/share": _DATA, "~/.local": _DATA,
             "xdg-data/flatpak": "Flatpak's own permission overrides",
             "~/.local/share/flatpak": "Flatpak's own permission overrides",
             "xdg-data/applications": "the menu's launchers", "~/.local/share/applications": "the menu's launchers",
             "xdg-config": _CONFIG, "~/.config": _CONFIG,
             "xdg-config/autostart": "what starts at login", "~/.config/autostart": "what starts at login",
             "~/.bashrc": "the shell's start file", "~/.profile": "the login shell's start file",
             "~/.zshrc": "the shell's start file", "~/.bash_profile": "the login shell's start file"}
# folders of secrets: keys, the keyring (even read-only)
SECRET_FS = {"~/.ssh": "SSH keys", "~/.gnupg": "GnuPG keys", "xdg-data/keyrings": "the login keyring",
             "~/.local/share/keyrings": "the login keyring", "~/.password-store": "pass's passwords"}
# bus names an app may talk to that reach past its sandbox: the secrets of every app, a way to run commands outside it
# (systemd starts any unit for the asker; dconf writes any setting, custom shortcuts' commands among them)
BUS_NAMES = {"org.freedesktop.Flatpak": "can run commands outside its sandbox (org.freedesktop.Flatpak)",
             "org.freedesktop.systemd1": "can start programs outside its sandbox through systemd",
             "ca.desrt.dconf": "can change any desktop setting, shortcut commands among them (dconf)",
             "org.freedesktop.secrets": "can read every saved password in the keyring (Secret Service)",
             "org.kde.kwalletd5": "can read the KDE wallet", "org.kde.kwalletd6": "can read the KDE wallet",
             "org.kde.kwalletd": "can read the KDE wallet"}
ESCAPE_NAMES = frozenset({"org.freedesktop.Flatpak", "org.freedesktop.systemd1"})


def flatpak_apps(host: Host) -> list[str] | None:
    r = host.run_flatpak("list", "--app", "--columns=application")
    if r.missing or not r.ok:
        return None
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip() and ln.strip() != "Application ID"]


def _fs_name(item: str) -> tuple[str, bool]:
    """A filesystems entry as (folder, read-only): "home:ro" -> ("home", True), "~/.ssh" -> ("~/.ssh", False)."""
    name, _, mode = item.rpartition(":")
    if name and mode in ("ro", "rw", "create"):
        return name.rstrip("/") or "/", mode == "ro"
    return item.rstrip("/") or "/", False


def _merge_list(base: str, override: str) -> list[str]:
    items = [x for x in base.split(";") if x]
    for x in (y for y in override.split(";") if y):
        if x.startswith("!"):
            items = [i for i in items if _fs_name(i)[0] != _fs_name(x[1:])[0]]
        else:
            items = [i for i in items if _fs_name(i)[0] != _fs_name(x)[0]] + [x]
    return items


def override_files(scan: Scan, app: str) -> list[tuple[str, Path]]:
    """(shown as, path) of the overrides Flatpak applies to `app`, in its order: the system's for every app (global),
    then for this one, then the user's the same way. `flatpak override --filesystem=host` with no app writes global:
    every app gets it, the check's per-app list never showed it."""
    user = scan.paths.data_home / "flatpak" / "overrides"
    return [("/var/lib/flatpak/overrides/global", scan.host.sys_path("/var/lib/flatpak/overrides/global")),
            (f"/var/lib/flatpak/overrides/{app}", scan.host.sys_path(f"/var/lib/flatpak/overrides/{app}")),
            (scan.host.display(user / "global"), user / "global"), (scan.host.display(user / app), user / app)]


def flatpak_permissions(scan: Scan, app: str) -> dict:
    """The app's permissions with the global and its own overrides applied, system then user."""
    r = scan.host.run_flatpak("info", "--show-permissions", app)
    perms = ini.parse(r.stdout) if r.ok else {}
    for _, f in override_files(scan, app):
        over = ini.parse(read_text(scan.host, f) or "")
        for group, keys in over.items():
            for k, v in keys.items():
                if group == ("Context",) and k in ("filesystems", "devices", "sockets", "shared", "features"):
                    perms.setdefault(group, {})[k] = ";".join(_merge_list(perms.get(group, {}).get(k, ""), v))
                else:
                    perms.setdefault(group, {})[k] = v
    return perms


def broad_permissions(perms: dict) -> tuple[list[str], bool]:
    """What in an app's permissions reaches past its sandbox, in words, and whether any of it lets it out (run
    commands, change its own permissions or what starts at login)."""
    ctx = perms.get(("Context",), {})
    what, escapes = [], False
    for item in (x for x in ctx.get("filesystems", "").split(";") if x and not x.startswith("!")):
        name, ro = _fs_name(item)
        if name in BROAD_FS or name.startswith(("/home/", "/var/home/")) and name.count("/") <= 2:
            what.append(item)
        elif name in ESCAPE_FS and not ro:
            what.append(f"{item} ({ESCAPE_FS[name]}: it can widen its own permissions or run things at login)")
            escapes = True
        elif name in SECRET_FS:
            what.append(f"{item} ({SECRET_FS[name]})")
    if "all" in ctx.get("devices", "").split(";"):
        what.append("all devices")
    sockets = ctx.get("sockets", "").split(";")
    if "session-bus" in sockets:
        what.append("whole session bus")
    if "system-bus" in sockets:
        what.append("whole system bus")
    for group in (("Session Bus Policy",), ("System Bus Policy",)):
        for name, policy in perms.get(group, {}).items():
            if policy in ("talk", "own") and name in BUS_NAMES:
                what.insert(0, BUS_NAMES[name] + (" on the system bus" if group[0].startswith("System") else ""))
                escapes |= name in ESCAPE_NAMES
    return what, escapes


@register
class FlatpakBroadPerms(Check):
    id = "sbx.flatpak_broad_perms"

    def detect(self, scan: Scan) -> Outcome:
        apps = flatpak_apps(scan.host)
        if apps is None:
            return absent("Flatpak isn't installed.")
        if not apps:
            return absent("No Flatpak apps are installed.")
        ev, broad, escape = [], [], []
        for shown, f in override_files(scan, "global")[::2]:            # the system's and the user's global overrides
            what, _ = broad_permissions(ini.parse(read_text(scan.host, f) or ""))
            if what:
                ev.append(Evidence.val(f"Every app ({shown})", ", ".join(what)[:200]))
        for app in apps:
            what, can_escape = broad_permissions(flatpak_permissions(scan, app))
            if can_escape:
                escape.append(app)
            if what:
                broad.append(app)
                ev.append(Evidence.val(app, ", ".join(what)[:200]))
        notes = [Note("info", "Narrowing permissions",
                      "Flatseal, or `flatpak override --user --nofilesystem=home <app>`, can take a permission away; "
                      "some apps then lose features. A permission given to every app (a global override) is taken "
                      "away with `flatpak override --user --nofilesystem=host` (no app named), or `sudo flatpak "
                      "override --nofilesystem=host` for the system's.")] if broad else []
        if escape:
            return failed(f"{', '.join(escape)} can get out of {'their' if len(escape) > 1 else 'its'} sandbox (run "
                          "commands outside it, or widen its own permissions); "
                          f"{len(broad)} of {len(apps)} Flatpak apps have broad access in all.", *ev, notes=notes)
        if broad:
            return failed(f"{len(broad)} of {len(apps)} Flatpak apps have broad access to your files or devices.",
                          *ev, notes=notes)
        return passed(f"None of the {len(apps)} Flatpak apps has broad permissions.")


@register
class FlatpakCaches(Check):
    id = "sbx.flatpak_caches"

    def detect(self, scan: Scan) -> Outcome:
        apps = scan.paths.flatpak_apps()
        if not apps:
            return absent("No Flatpak app data in ~/.var/app.")
        sizes, linked = [], []
        for app in apps:
            cache = scan.paths.flatpak_root / app / "cache"
            if not own_dir(scan.host, cache):
                # the app can write its own folder: a cache -> ~/Documents it made would be counted, and cleared, as
                # its cache. Said, so that one the user moved elsewhere with a link of their own isn't a puzzle
                if os.path.islink(cache):
                    linked.append(Note("info", "A cache reached through a link isn't counted",
                                       link_note(scan.host, cache)))
                continue
            t = tally(cache, limit=20_000)
            if t.files:
                sizes.append((app, t))
        if not sizes:
            return passed("Flatpak apps have no cached data.", notes=linked)
        sizes.sort(key=lambda x: -x[1].bytes)
        total = sum(t.bytes for _, t in sizes)
        return failed(f"{len(sizes)} Flatpak app{'s keep' if len(sizes) > 1 else ' keeps'} {human_size(total)} of "
                      "caches under ~/.var/app, which cleaners that look only at ~/.cache miss.",
                      *(Evidence.val(app, t.describe()) for app, t in sizes[:15]), notes=linked)


@register
class X11Session(Check):
    id = "sbx.x11_session"

    def detect(self, scan: Scan) -> Outcome:
        s = scan.context.values["session"]
        if s.value == "x11":
            return failed("This is an X11 session: any app can read the clipboard, see what other windows show and "
                          "record keystrokes.", *s.evidence)
        if s.value == "wayland":
            return passed("This is a Wayland session.", *s.evidence)
        return unknown(f"Couldn't tell the session type: {s.note}")


@register
class LeftoverData(Check):
    id = "sbx.leftover_data"

    def detect(self, scan: Scan) -> Outcome:
        host, ev = scan.host, []
        installed_apps = flatpak_apps(host)
        if installed_apps is not None:
            for app in scan.paths.flatpak_apps():
                if app not in installed_apps:
                    ev.append(Evidence.val(f"~/.var/app/{app}", tally(scan.paths.flatpak_root / app).describe()))
        r = host.run("snap", "list")
        if r.ok:
            snaps = {ln.split()[0] for ln in r.stdout.splitlines()[1:] if ln.split()}
            for name in scan.paths.snaps():
                if name not in snaps:
                    ev.append(Evidence.val(f"~/snap/{name}", tally(scan.paths.snap_root / name).describe()))
        if installed_apps is None and not r.ok:
            return absent("Neither Flatpak nor Snap is installed.")
        limit = Note("limitation", "Native apps aren't checked",
                     "Leftover folders of uninstalled native apps in ~/.config and ~/.local/share can't be matched to "
                     "packages reliably, so they aren't listed.")
        if ev:
            return failed(f"{len(ev)} uninstalled app{'s' if len(ev) > 1 else ''} left data behind.", *ev[:20], notes=[limit])
        return passed("No data left by uninstalled Flatpak or Snap apps.", notes=[limit])


PORTAL_TABLES = {"devices": "device", "location": "location", "screenshot": "screenshot", "background": "background"}
# what the location portal stores for an app: the accuracy it may have, then when it was granted ("EXACT,1792247823");
# NONE is a refusal (xdg-desktop-portal's location.c)
LOCATION_DENIED = ("NONE", "")


def portal_grants(text: str) -> list[tuple[str, str, str]]:
    """(table, object, app) of each remembered grant of the camera, microphone, location or screenshots in `flatpak
    permissions`' table: Table, Object, App, then the permissions, comma-separated, then data. The devices and
    screenshot portals store yes or no; the location portal an accuracy (and a time). Running in the background, or
    playing sound, isn't a privacy grant."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[0] not in PORTAL_TABLES or f[0] == "background" or (f[0], f[1]) == ("devices", "speakers"):
            continue
        perms = [p.strip().upper() for p in f[3].split(",")]
        if (f[0] == "location" and perms[0] not in LOCATION_DENIED) or (f[0] != "location" and "YES" in perms):
            out.append((f[0], f[1], f[2]))
    return out


@register
class PortalPermissions(Check):
    id = "sbx.portal_permissions"

    def detect(self, scan: Scan) -> Outcome:
        r = scan.host.run_flatpak("permissions")
        if r.missing:
            return absent("Flatpak isn't installed.")
        if not r.ok:
            return unknown("Couldn't list portal permissions.")
        ev = [Evidence.val(app, obj if table == "devices" else PORTAL_TABLES[table])
              for table, obj, app in portal_grants(r.stdout)]
        if ev:
            return failed(f"{len(ev)} remembered grant{'s' if len(ev) > 1 else ''} for the camera, microphone, location "
                          "or screenshots.", *ev[:20])
        return passed("No remembered camera, microphone, location or screenshot grants.")


@register
class Snap(Check):
    id = "sbx.snap"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        r = host.run("snap", "list", "--all")
        if r.missing:
            return absent("Snap isn't installed.")
        if not r.ok:
            return unknown("Couldn't list snaps.")
        disabled, classic = [], []
        for line in r.stdout.splitlines()[1:]:
            f = line.split()
            if len(f) >= 6:
                notes = f[-1]
                if "disabled" in notes:
                    disabled.append(f"{f[0]} {f[2]}")
                if "classic" in notes and "disabled" not in notes:
                    classic.append(f[0])
        old_data = Tally()
        for name in scan.paths.snaps():
            for root in scan.paths.snap_roots(name):
                if root.revision != "common" and not root.current:
                    old_data += tally(root.path, limit=20_000)
        ev = [Evidence.count("Disabled (retained) revisions", len(disabled)),
              Evidence.val("Your data in old revisions", old_data.describe())]
        ev += [Evidence.val("Classic (unconfined) snap", c) for c in classic[:10]]
        notes = [Note("info", "Classic snaps aren't sandboxed",
                      f"{', '.join(classic[:5])} run{'s' if len(classic) == 1 else ''} with the same access as any "
                      "other program.")] if classic else []
        if disabled or old_data.files:
            return failed("Old snap revisions keep copies of apps and of your data in them.", *ev, notes=notes)
        return passed("No old snap revisions are kept.", *ev, notes=notes)


APPIMAGE_DIRS = ("Applications", "Downloads", "bin", ".local/bin", "AppImages", "apps")


@register
class AppImages(Check):
    id = "sbx.appimages"

    def detect(self, scan: Scan) -> Outcome:
        import re
        from ._util import tally, xdg_user_dir
        host = scan.host
        dirs = [host.home / d for d in APPIMAGE_DIRS]
        downloads = xdg_user_dir(host, scan.paths, "DOWNLOAD")
        if downloads:
            dirs.append(downloads)
        t = Tally()
        for d in dict.fromkeys(dirs):
            t += tally(d, pattern=re.compile(r"\.appimage$", re.I), max_depth=2, limit=5000)
        if not t.files:
            return absent("No AppImages were found in the usual folders.")
        return warned(f"{t.files} AppImage{'s' if t.files > 1 else ''} installed; they run with full access to your files.",
                      Evidence.val("AppImages", t.describe()),
                      notes=[Note("info", "Nothing confines an AppImage",
                                  "Unlike a Flatpak, an AppImage is an ordinary program: it can read every file you "
                                  "can. Use the Flatpak where the app offers one, and only AppImages from the app's "
                                  "own site.")])