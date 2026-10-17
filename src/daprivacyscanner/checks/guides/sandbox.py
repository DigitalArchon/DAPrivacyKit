"""Guided fixes: sandbox (see the package docstring)."""

from __future__ import annotations

from ...fix import Command, DeleteFiles, FileCommand
from ...guide import Guide, Step
from .._util import files_under
from . import guide, option, evidence


@guide("sbx.flatpak_broad_perms")
def flatpak_broad(check, scan, outcome):
    from ..sandbox import BROAD_FS, flatpak_permissions
    steps = []
    for app in evidence(outcome, value=""):
        perms = flatpak_permissions(scan, app)
        ctx = perms.get(("Context",), {})
        flags = sorted({f"--nofilesystem={x.split(':')[0]}" for x in ctx.get("filesystems", "").split(";")
                        if x.split(":")[0] in BROAD_FS})
        if perms.get(("Session Bus Policy",), {}).get("org.freedesktop.Flatpak") == "talk":
            flags.append("--no-talk-name=org.freedesktop.Flatpak")
        if not flags:
            continue
        overrides = scan.paths.data_home / "flatpak" / "overrides" / app
        steps.append(Step(app, options=[option(check, f"Take away {', '.join(f.split('=')[1] for f in flags)}", [FileCommand(
            ["flatpak", "override", "--user", *flags, app], overrides, "narrow its permissions",
            scan.host.display(overrides))], side_effects=[
            "The app can still open files you pick in its file dialog, but can't browse your folders itself. Some "
            "apps (IDEs, games launchers) stop working properly: revert it from History if so.",
            "Takes effect the next time the app starts."])]))
    steps.append(Step("Other broad permissions",
                      "Access to all devices or the whole session bus can be narrowed too, but often breaks apps; "
                      "Flatseal shows every permission with a switch.",
                      commands=["flatpak install flathub com.github.tchx84.Flatseal"]))
    return Guide(check.id, "Narrow Flatpak apps' permissions", "", steps)


@guide("sbx.leftover_data")
def leftover_data(check, scan, outcome):
    opts = []
    for label in evidence(outcome, value=""):
        if label.startswith("~/.var/app/"):
            root = scan.paths.flatpak_root / label.removeprefix("~/.var/app/")
        elif label.startswith("~/snap/"):
            root = scan.paths.snap_root / label.removeprefix("~/snap/")
        else:
            continue
        files = files_under(root)[0]
        opts.append(option(check, f"Delete {label}", [DeleteFiles(root, files, "data of an uninstalled app", label,
                                                                  remove_root=True)]))
    return Guide(check.id, "Remove data left by uninstalled apps", "Apps leave their settings and data behind "
                 "when uninstalled. Only Flatpak and Snap folders are listed: they belong to one app for sure.", [
                     Step("Choose what to delete", "Each is that app's own folder; reinstalling the app starts afresh.",
                          options=opts),
                     Step("Native apps", "Folders in ~/.config and ~/.local/share of apps you've removed aren't listed; "
                          "check them yourself."),
                 ])


@guide("sbx.portal_permissions")
def portal_permissions(check, scan, outcome):
    from ..sandbox import PORTAL_TABLES, portal_grants
    r = scan.host.run("flatpak", "permissions")
    grants = portal_grants(r.stdout) if r.ok else []
    opts = [option(check, f"{app}: forget {PORTAL_TABLES[t] if t != 'devices' else i}", [Command(
        ["flatpak", "permission-remove", t, i, app], "the app asks again the next time it needs it")])
        for t, i, app in grants]
    if len(grants) > 1:
        opts.insert(0, option(check, f"Forget all {len(grants)} grants", [Command(
            ["flatpak", "permission-remove", t, i, app], "the app asks again") for t, i, app in grants]))
    return Guide(check.id, "Review remembered portal grants", "Once you allow an app the camera, microphone or "
                 "location, it keeps that permission without asking again.", [
                     Step("Choose which to forget", options=opts,
                          side_effects=["Forgetting isn't recorded for undo: the app simply asks again."])])


@guide("sbx.snap")
def snap(check, scan, outcome):
    r = scan.host.run("snap", "list", "--all")
    disabled = []
    for line in r.stdout.splitlines()[1:] if r.ok else []:
        f = line.split()
        if len(f) >= 6 and "disabled" in f[-1]:
            disabled.append((f[0], f[2]))
    old = []
    for name in scan.paths.snaps():
        for root in scan.paths.snap_roots(name):
            if root.revision != "common" and not root.current:
                files = files_under(root.path)[0]
                if files:
                    old.append(DeleteFiles(root.path, files, f"{name} data of revision {root.revision}",
                                           scan.host.display(root.path), remove_root=True))
    steps = [Step("Remove disabled revisions", "snapd keeps the previous versions of each snap, to roll back to.",
                  commands=[f"sudo snap remove {n} --revision={rev}" for n, rev in disabled]
                  + ["sudo snap set system refresh.retain=2     # keep fewer in future"])]
    if old:
        steps.append(Step("Delete your data in old revisions", "snapd copies your data for each revision.",
                          options=[option(check, "Delete it", old, side_effects=[
                              "Rolling a snap back to one of these revisions then starts without your data."])]))
    classic = evidence(outcome, "Classic (unconfined) snap")
    if classic:
        steps.append(Step("Classic snaps", f"{', '.join(classic)} run without a sandbox, like any other program. "
                          "That's a property of the snap, not something to switch off."))
    return Guide(check.id, "Remove old snap revisions", "", steps)
