"""Sandboxing and permissions (sbx.*)."""

from __future__ import annotations

from .. import ini
from ..host import Host
from ..model import Evidence, Note, Outcome
from . import Check, Scan, register
from ._util import Tally, absent, failed, human_size, passed, read_text, tally, unknown, warned

BROAD_FS = ("host", "host-os", "host-etc", "home")


def flatpak_apps(host: Host) -> list[str] | None:
    r = host.run_flatpak("list", "--app", "--columns=application")
    if r.missing or not r.ok:
        return None
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip() and ln.strip() != "Application ID"]


def _merge_list(base: str, override: str) -> list[str]:
    items = [x for x in base.split(";") if x]
    for x in (y for y in override.split(";") if y):
        if x.startswith("!"):
            items = [i for i in items if i.split(":")[0] != x[1:].split(":")[0]]
        else:
            items.append(x)
    return items


def flatpak_permissions(scan: Scan, app: str) -> dict:
    """The app's permissions with user and system overrides applied."""
    r = scan.host.run_flatpak("info", "--show-permissions", app)
    perms = ini.parse(r.stdout) if r.ok else {}
    for f in (scan.host.sys_path(f"/var/lib/flatpak/overrides/{app}"), scan.paths.data_home / "flatpak" / "overrides" / app):
        over = ini.parse(read_text(scan.host, f) or "")
        for group, keys in over.items():
            for k, v in keys.items():
                if group == ("Context",) and k in ("filesystems", "devices", "sockets", "shared"):
                    perms.setdefault(group, {})[k] = ";".join(_merge_list(perms.get(group, {}).get(k, ""), v))
                else:
                    perms.setdefault(group, {})[k] = v
    return perms


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
        for app in apps:
            perms = flatpak_permissions(scan, app)
            ctx = perms.get(("Context",), {})
            fs = [x for x in ctx.get("filesystems", "").split(";") if x.split(":")[0] in BROAD_FS]
            devices = "all" in ctx.get("devices", "").split(";")
            bus = "session-bus" in ctx.get("sockets", "").split(";")
            can_escape = perms.get(("Session Bus Policy",), {}).get("org.freedesktop.Flatpak") == "talk"
            what = fs + (["all devices"] if devices else []) + (["whole session bus"] if bus else [])
            if can_escape:
                escape.append(app)
                what.insert(0, "can run commands outside its sandbox (org.freedesktop.Flatpak)")
            if what:
                broad.append(app)
                ev.append(Evidence.val(app, ", ".join(what)[:200]))
        notes = [Note("info", "Narrowing permissions",
                      "Flatseal, or `flatpak override --user --nofilesystem=home <app>`, can take a permission away; "
                      "some apps then lose features.")] if broad else []
        if escape:
            return failed(f"{', '.join(escape)} can run commands outside {'their' if len(escape) > 1 else 'its'} "
                          f"sandbox; {len(broad)} of {len(apps)} Flatpak apps have broad access in all.", *ev, notes=notes)
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
        sizes = []
        for app in apps:
            t = tally(scan.paths.flatpak_root / app / "cache", limit=20_000)
            if t.files:
                sizes.append((app, t))
        if not sizes:
            return passed("Flatpak apps have no cached data.")
        sizes.sort(key=lambda x: -x[1].bytes)
        total = sum(t.bytes for _, t in sizes)
        return failed(f"{len(sizes)} Flatpak app{'s keep' if len(sizes) > 1 else ' keeps'} {human_size(total)} of "
                      "caches under ~/.var/app, which cleaners that look only at ~/.cache miss.",
                      *(Evidence.val(app, t.describe()) for app, t in sizes[:15]))


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