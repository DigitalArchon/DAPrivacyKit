"""Guided fixes: desktop (see the package docstring)."""

from __future__ import annotations

import re
from pathlib import Path

from ...context import read_swaps
from ...fix import Command, DeleteFiles, MakeDir, RootChange, WriteFile, shell
from ...guide import Guide, Input, Step
from .._util import (files_under, isdir, isfile, processes, read_text, recent_files, recent_hrefs,
                     systemctl_state)
from ..fixes import _gnome_family, gset, kset, thumbnail_deletions
from . import evidence, guide, option, expire_actions, tmpfiles_available, tmpfiles_path, unit_exists


THUMBNAILS_IN_MEMORY_MB = 200
BALOO_UNIT, BALOO_PROCESS = "kde-baloo.service", "baloo_file"       # Plasma 6 starts the indexer through the unit
METADATA_IN_MEMORY_MB = 50
EPHEMERAL_MB = 500
THUMBNAIL_SCHEMAS = {"gnome": "org.gnome.desktop.thumbnail-cache", "cinnamon": "org.cinnamon.desktop.thumbnail-cache",
                     "mate": "org.mate.thumbnail-cache"}
PRIVACY_SCHEMAS = {"gnome": "org.gnome.desktop.privacy", "cinnamon": "org.cinnamon.desktop.privacy"}


@guide("desk.thumbnails", keys=("in_memory",))
def thumbnails(check, scan, outcome):
    from ..desktop import ThumbnailMount
    steps = [Step("Delete the thumbnails that leak",
                  "A thumbnail is a small copy of the picture with the original's full path inside it. It stays "
                  "after the picture is deleted or the drive it was on is unplugged.", options=[
                      option(check, "Delete thumbnails of deleted files and of removable or encrypted drives",
                             thumbnail_deletions(scan), recommended=True),
                      option(check, "Delete every cached thumbnail", thumbnail_deletions(scan, everything=True),
                             detail="They are made again as you browse."),
                  ])]
    tm = ThumbnailMount(scan)
    schema = THUMBNAIL_SCHEMAS.get(_gnome_family(scan) or "")
    if schema:
        age = scan.gnome.gsettings(schema, "maximum-age")
        if age is not None and (age == -1 or age > 30):
            steps.append(Step("Let the desktop drop old thumbnails", options=[
                option(check, "Delete thumbnails older than 30 days automatically",
                       gset(scan, schema, "maximum-age", "30"), recommended=True)]))
    elif not tm.in_memory and tmpfiles_available(scan):
        rule = f"e {tmpfiles_path(tm.path)} - - - 30d"
        acts = expire_actions(scan, "thumbnails", [rule], f"Delete thumbnails not used for 30 days ({rule})")
        steps.append(Step("Drop old thumbnails automatically",
                          "This desktop has no setting for it, so a rule of the app's own does it: systemd's daily "
                          "clean-up of your files deletes thumbnails nobody has looked at for 30 days.",
                          options=[option(check, "Delete thumbnails not used for 30 days", acts, recommended=True,
                                          side_effects=["Thumbnails you still browse are kept; the rest are made again "
                                                        "if you open their folder."])], done=not acts))
    cache, shown = tm.path, scan.host.display(tm.path)
    # what stops it that closing an app can't clear is said in the step, never as a blocked option: an Easy fix
    # counts a blocked option as one still to apply, and listed it greyed for as long as the check warned
    cant = ""
    # the helper only ever mounts the asking user's own ~/.cache/thumbnails, from their account
    if cache != scan.host.home / ".cache" / "thumbnails":
        cant = (f" Your cache folder is set elsewhere ({shown}, by XDG_CACHE_HOME); only ~/.cache/thumbnails can be "
                "kept in memory this way.")
    elif tm.unit_exists and not tm.in_memory:
        cant = (f" It is set up ({tm.unit_file}) but isn't mounted now: the check says why. Revert it from History to "
                "start over.")
    actions = [] if tm.in_memory or cant else thumbnail_deletions(scan, everything=True, only=cache) + [
        RootChange("mount_tmpfs", {"size_mb": THUMBNAILS_IN_MEMORY_MB},
                   f"Add the systemd mount unit {tm.unit_file}, keeping {shown} in memory (tmpfs, "
                   f"{THUMBNAILS_IN_MEMORY_MB} MB, noexec,nosuid,nodev), and mount it now", phase=3)]
    steps.append(Step("Keep the thumbnail cache in memory",
                      "Mounted as tmpfs, the cache lives in RAM: it is empty again at every boot, and nothing about "
                      "what you looked at is written to disk." + (" It is set up that way now." if tm.in_memory else cant),
                      options=[] if tm.in_memory or cant else [option(
                          check, f"Mount {shown} in memory (needs administrator access)", actions, key="in_memory",
                                      detail="Deletes the thumbnails cached now first: a mount over the folder would hide "
                                             "them on disk, not remove them.",
                                      side_effects=[
                                          "Thumbnails are made again after every reboot, so the first look at a folder of "
                                          "pictures is slower.",
                                          f"The cache is capped at {THUMBNAILS_IN_MEMORY_MB} MB of RAM; when it is full, new "
                                          "thumbnails aren't kept until older ones are deleted.",
                                          f"The mount is a systemd unit of its own ({tm.unit_file}); /etc/fstab isn't "
                                          "touched. A failure never holds up booting, and at every boot the mount is "
                                          "skipped, never redirected, if ~/.cache or ~/.cache/thumbnails has become a "
                                          "link or is missing.",
                                          "Reverting stops and deletes the unit, or leaves the cache in memory until the "
                                          "next reboot if a program is using the folder.",
                                          "Flatpak apps keep their own thumbnail caches; those aren't covered.",
                                      ])], done=tm.in_memory))
    return Guide(check.id, "Thumbnails that outlive their pictures",
                 "Each cached thumbnail shows what a picture looked like and where it was, long after it is gone.",
                 steps)


@guide("desk.indexers")
def indexers(check, scan, outcome):
    from ..desktop import INDEXER_SCHEMA
    host, steps = scan.host, []
    baloo = scan.paths.data_home / "baloo"
    tool = "balooctl6" if host.runner.which("balooctl6") else "balooctl"
    state = (evidence(outcome, "Baloo") or [""])[0]
    if state:
        index = files_under(baloo, pattern=re.compile(r"^index"))[0]
        delete = [DeleteFiles(baloo, index, "Baloo's index", host.display(baloo))] if index else []
        # disable returns before baloo_file has exited (tested on Plasma 6.7): the index is deleted only once it has
        stop = [Command([tool, "disable"], "stop the indexer, which holds the index open", check_ok=False,
                        wait_gone=BALOO_PROCESS)]
        off = kset(scan, "baloofilerc", "Basic Settings", "Indexing-Enabled", "false", default="true")
        opts = [option(check, "Turn indexing off and delete the index", off + (stop + delete if off or delete else []),
                       recommended=True, key="baloo_off", side_effects=[
                           "Dolphin still finds files by name, more slowly, but no longer by what's inside them; KRunner "
                           "and the application launcher stop listing your files.",
                           # VERIFY (catalogue): tags:/ and Elisa without Baloo
                           "Dolphin's Tags place and searches by tag or rating stop working; the tags stay on the files.",
                           "Elisa, KDE's music player, may show no music until it is set to scan your music folders "
                           "itself, in its settings.",
                           "Turned back on (System Settings → Search → File Search), it reads every document again "
                           "to rebuild the index, which takes a while."])]
        if state.startswith("file contents"):
            names = kset(scan, "baloofilerc", "General", "only basic indexing", "true", default="false")
            # what it has indexed stays in the index until it is rebuilt, without contents this time. Stopped without
            # `disable` (which turns indexing off, outside this plan's record), and started again detached from this
            # app: `balooctl6 enable` starts baloo_file holding the app's captured output, and the app waited for it
            # until its timeout (both tested on Plasma 6.7). The unit starts it as at login.
            unit = unit_exists(scan, BALOO_UNIT, user=True)
            halt = []
            if BALOO_PROCESS in processes(host, own=True):
                halt = [Command(["systemctl", "--user", "stop", BALOO_UNIT], "stop the indexer, which holds the index "
                                "open", check_ok=False, wait_gone=BALOO_PROCESS)] \
                    if unit and systemctl_state(host, "is-active", BALOO_UNIT, user=True) == "active" else \
                    [Command(["pkill", "-TERM", "-x", "-u", str(host.uid), BALOO_PROCESS], "stop the indexer, which "
                             "holds the index open", check_ok=False, wait_gone=BALOO_PROCESS)]
            # a failed start isn't rolled back (the index is gone by then): Baloo starts at the next login, names only
            start = Command(["systemctl", "--user", "start", BALOO_UNIT] if unit else
                            ["sh", "-c", 'exec "$0" enable </dev/null >/dev/null 2>&1', tool],
                            "start it again; it rebuilds the index with names only", check_ok=False, after=True)
            rebuild = halt + delete + [start] if delete else []
            opts.append(option(check, "Index file names only, and rebuild the index without contents", names + rebuild,
                               side_effects=["Searching inside documents stops working; KRunner and Dolphin still find "
                                             "files by name. The index still lists every file name in your home folder.",
                                             "Takes full effect at your next login."]))
        steps.append(Step("Baloo (KDE): stop keeping what's inside your files",
                          "Baloo reads every document in your home folder and keeps its words in "
                          f"{host.display(baloo)}. Turning it off stops that; the index it made has to be deleted too. "
                          "Excluding folders isn't enough: what it indexed from a folder stays in its index after the "
                          "folder is excluded, even across restarts (tested), so don't rely on it to forget.",
                          options=opts))
    cmd = scan.gnome.indexer_command()
    if cmd:
        name = "LocalSearch" if cmd == "localsearch" else "Tracker"
        unit = "localsearch-3.service" if cmd == "localsearch" else "tracker-miner-fs-3.service"
        acts = gset(scan, INDEXER_SCHEMA, "index-recursive-directories", "@as []")
        acts += gset(scan, INDEXER_SCHEMA, "index-single-directories", "@as []")
        acts += gset(scan, INDEXER_SCHEMA, "index-removable-devices", "false")
        store = [d for d in (scan.paths.cache_home / "localsearch", scan.paths.cache_home / "tracker3" / "files")
                 if files_under(d, limit=1)[0]]
        if store:
            was_running = systemctl_state(host, "is-active", unit, user=True) == "active"
            acts.append(Command(["systemctl", "--user", "stop", unit], "it holds its database open", check_ok=False))
            acts += [DeleteFiles(d, files_under(d)[0], f"{name}'s database", host.display(d)) for d in store]
            if was_running:
                acts.append(Command(["systemctl", "--user", "start", unit], "start it again, with nothing to index",
                                    after=True, check_ok=False))
        steps.append(Step(f"{name} (GNOME): stop keeping what's inside your files",
                          f"{name} reads the documents in your main folders (Desktop, Documents, Music, Pictures, "
                          "Videos, Downloads) and keeps their words in a database. Giving it no folders stops that; "
                          "the database has to be deleted too.",
                          options=[option(check, "Index no folders and delete its database", acts, recommended=True,
                                          side_effects=[
                                              "Files still finds files by name, more slowly, but no longer by what's "
                                              "inside them; the Activities overview stops showing files.",
                                              # VERIFY (catalogue): GNOME Music's library without LocalSearch folders
                                              "GNOME Music finds your music through it, and shows an empty library.",
                                              "Settings → Search → Search Locations turns folders back on; it reads "
                                              "their documents again then."])]))
    from ..desktop import recoll_index
    recoll = recoll_index(scan)
    if recoll is not None:
        conf = recoll[0]
        db = conf / "xapiandb"
        acts = [DeleteFiles(db, files_under(db)[0], "Recoll's index", host.display(db))]
        auto = scan.paths.config_home / "autostart" / "recollindex.desktop"
        text = read_text(host, auto)
        if text is not None and not re.search(r"^Hidden\s*=\s*true", text, re.M):
            acts.insert(0, WriteFile(auto, lambda old: (old or "").rstrip("\n") + "\nHidden=true\n",
                                     "Don't start Recoll's real-time indexer at login", host.display(auto)))
        running = "recollindex" in processes(host)
        steps.append(Step("Recoll: delete its index",
                          f"Recoll keeps the words of every document under the folders it indexes in {host.display(db)}. "
                          "Deleting the index removes them; Recoll makes it again the next time it indexes (from its "
                          "window, at login if its real-time indexer is set to start then, or from a crontab line, "
                          "which crontab -e shows and can remove).",
                          options=[option(check, "Delete Recoll's index", acts, recommended=True,
                                          blockers=["Close Recoll first: its indexer (recollindex) is running."]
                                          if running else [],
                                          side_effects=["Recoll finds nothing until it indexes again."])]))
    return Guide(check.id, "Stop indexing what's inside your files",
                 "A content index keeps the words of your documents, and details such as where photos were taken, "
                 "in a database of its own: searchable at once by anything running as you, often included in "
                 "backups, and kept for a while after a document is deleted.", steps)


# ------------------------------------------------------------------ recent files

def set_gtk_setting(text: str | None, key: str, value: str) -> str:
    """A GTK settings.ini with `key` set in its [Settings] group, nothing else changed."""
    lines = (text or "").splitlines()
    out, current, done = [], None, False
    for line in lines:
        m = re.match(r"^\s*\[([^\]]+)\]\s*$", line)
        if m:
            if current == "Settings" and not done:
                out.append(f"{key}={value}")
                done = True
            current = m.group(1)
        elif current == "Settings" and re.match(rf"^\s*{re.escape(key)}\s*=", line):
            if not done:
                out.append(f"{key}={value}")
                done = True
            continue
        out.append(line)
    if not done:
        if current == "Settings":
            out.append(f"{key}={value}")
        else:
            out += ([""] if out else []) + ["[Settings]", f"{key}={value}"]
    return "\n".join(out) + "\n"


@guide("desk.recent_files", keys=("max_age",))
def recent(check, scan, outcome):
    host = scan.host
    clear = [DeleteFiles(x.parent, [x], "the recent files list", host.display(x.parent))
             for x in recent_files(scan.paths) if not x.is_dir() and recent_hrefs(host, x)]
    steps = [Step("Clear the list", "Open Recent menus and the Recent place in file managers start empty.",
                  options=[option(check, "Clear it", clear)] if clear else [], done=not clear)]
    schema = PRIVACY_SCHEMAS.get(_gnome_family(scan) or "")
    if schema:
        remember = scan.gnome.gsettings(schema, "remember-recent-files")
        age = scan.gnome.gsettings(schema, "recent-files-max-age")
        keep = gset(scan, schema, "remember-recent-files", "true") if remember is False else []
        if age is not None and (age == -1 or age > 30):
            keep += gset(scan, schema, "recent-files-max-age", "30")
        steps.append(Step("From now on", options=[
            option(check, "Keep recent files for at most 30 days", keep, recommended=True, key="max_age"),
            option(check, "Stop remembering recent files", gset(scan, schema, "remember-recent-files", "false"),
                   side_effects=["Open Recent stays empty in every app, and so does Recent in the file manager."]),
        ], done=remember is False))
    elif not scan.context.desktop.is_kde or recent_files(scan.paths):
        acts = []
        for v in ("gtk-3.0", "gtk-4.0"):
            f = scan.paths.config_home / v / "settings.ini"
            text = read_text(host, f)
            if not re.search(r"^\s*gtk-recent-files-enabled\s*=\s*(false|0)\s*$", text or "", re.M):
                acts.append(WriteFile(f, lambda old: set_gtk_setting(old, "gtk-recent-files-enabled", "false"),
                                      "Set gtk-recent-files-enabled=false", host.display(f)))
        steps.append(Step("Stop GTK apps remembering recent files",
                          "This desktop has no setting for it, but GTK apps read it from their settings file." +
                          (" KDE's own list is a separate check (desk.kde_activities)." if scan.context.desktop.is_kde else ""),
                          options=[option(check, "Stop remembering recent files in GTK apps", acts,
                                          side_effects=["Open Recent stays empty in GTK apps; takes effect as each app "
                                                        "starts."])] if acts else [], done=not acts))
    # stop every app writing it: KDE apps (KIO) honour a setting the System Settings page doesn't
    # set (bug 501802); GTK apps honour only their own, and replace a read-only file anyway (they
    # save by renaming a new file over it). A folder where the file goes stops both. Flatpak and Snap
    # apps keep a list of their own in their folder (~/.var/app/ID/data, ~/snap/NAME/...), blocked the same way.
    xbel = scan.paths.data_home / "recently-used.xbel"
    kde = scan.context.desktop.is_kde
    block = []
    for x in [xbel] + [p for p in recent_files(scan.paths) if p != xbel]:
        if x.is_dir():
            continue
        block += ([DeleteFiles(x.parent, [x], "the recent files list", host.display(x.parent))] if isfile(x) else [])
        block.append(MakeDir(x, host.display(x), mode=0o500, phase=4, note="an empty, read-only folder in its place"))
    if kde:
        block += kset(scan, "kdeglobals", "RecentDocuments", "UseRecent", "false", default="true")
    sandboxed = [p for p in recent_files(scan.paths) if p != xbel]
    steps.append(Step("Stop every app writing it",
                      "Settings don't reach every app: KDE apps write it unless a hidden setting is off (System "
                      "Settings' \"Do not remember\" doesn't set it, KDE bug 501802), and GTK apps (Firefox, GIMP, GTK "
                      "file dialogs) write it whatever the desktop says. Making the file read-only isn't enough: KDE "
                      "apps respect that, but GTK apps replace the file and make it writable again. An empty folder "
                      "where the file goes stops them all." + (
                          " Flatpak and Snap apps keep a list of their own in their folder: those found are blocked "
                          "the same way." if sandboxed else ""),
                      options=[option(check, "Put a folder where the list is kept", block, recommended=kde,
                                      side_effects=["Recent files stay empty in every app and file dialog, KDE and GTK "
                                                    "alike. Apps may log a warning that they couldn't save the list.",
                                                    "A Flatpak or Snap app that hasn't saved a list yet starts one in "
                                                    "its own folder: the check finds it, and this step blocks it too.",
                                                    "Reverting removes the folders; apps then start new lists."])]
                      if block else [], done=not block))
    return Guide(check.id, "Keep the recent files list short", "", steps)


# ------------------------------------------------------------------ GVFS metadata

@guide("desk.gvfs_metadata")
def gvfs_metadata(check, scan, outcome):
    from ..desktop import MemoryMount
    from ..fixes import delete
    host = scan.host
    d = scan.paths.data_home / "gvfs-metadata"
    mm = MemoryMount(scan, "gvfs-metadata", d)
    stop = [Command(["pkill", "-TERM", "-x", "-u", str(host.uid), "gvfsd-metadata"],
                    "it holds the metadata open; it restarts when needed", check_ok=False)] \
        if "gvfsd-metadata" in processes(host) else []
    clear = delete(scan, d, "GVFS file metadata")
    effects = ["Document viewers forget where you stopped reading; custom folder icons and emblems are reset."]
    steps = [Step("Clear it", options=[option(check, "Clear GVFS file metadata", clear + stop if clear else [],
                                              side_effects=effects)] if clear else [], done=not clear or mm.in_memory)]
    blockers = []
    if d != mm.expected:
        blockers.append(f"Your data folder is set elsewhere ({host.display(d)}); only ~/.local/share/gvfs-metadata "
                        "can be kept in memory this way.")
    elif mm.unit_exists and not mm.in_memory:
        blockers.append(f"It is set up ({mm.unit_file}) but isn't mounted now. Revert it from History to start over.")
    files = files_under(d)[0]
    acts = [] if mm.in_memory or blockers else (
        ([DeleteFiles(d, files, "GVFS file metadata", host.display(d), prune=True)] if files else []) + stop + [
            RootChange("mount_tmpfs", {"target": "gvfs-metadata", "size_mb": METADATA_IN_MEMORY_MB},
                       f"Add the systemd mount unit {mm.unit_file}, keeping {host.display(d)} in memory (tmpfs, "
                       f"{METADATA_IN_MEMORY_MB} MB, noexec,nosuid,nodev), and mount it now", phase=3)])
    steps.append(Step("Keep it in memory",
                      "Mounted as tmpfs, the metadata works as usual during a session and is forgotten at every boot: "
                      "nothing about the files you opened is written to disk." + (" It is set up that way now." if mm.in_memory else ""),
                      options=[option(check, f"Mount {host.display(d)} in memory (needs administrator access)", acts,
                                      blockers=blockers, recommended=True,
                                      detail="Deletes the metadata kept now first: a mount over the folder would hide "
                                             "it on disk, not remove it.",
                                      side_effects=effects[:1] + [
                                          "Reading positions and folder settings last until the next reboot.",
                                          f"The mount is a systemd unit of its own ({mm.unit_file}); /etc/fstab isn't "
                                          "touched. At every boot it is skipped, never redirected, if a folder on the "
                                          "way has become a link or is missing.",
                                          "Reverting stops and deletes the unit."])],
                      done=mm.in_memory))
    return Guide(check.id, "Stop file metadata piling up",
                 "GVFS keeps notes about the files you open, such as the page each document was left on.", steps)


# ------------------------------------------------------------------ screenshots

GNOME_SCREENSHOT = "org.gnome.gnome-screenshot"          # Cinnamon's and older GNOME's screenshot tool


@guide("desk.screenshots", can=tmpfiles_available)
def screenshots(check, scan, outcome):
    import time
    from ...fix import MakeDir
    from ..desktop import screenshot_dirs
    host = scan.host
    dirs = [d for d in screenshot_dirs(scan) if isdir(d)]
    steps = []
    # gnome-screenshot saves into Pictures itself unless told otherwise; a rule can't expire loose
    # files there, so it gets a folder of its own first
    if not dirs and scan.gnome.gsettings(GNOME_SCREENSHOT, "auto-save-directory") == "":
        target = screenshot_dirs(scan)[0]
        move = [MakeDir(target, host.display(target)),
                *gset(scan, GNOME_SCREENSHOT, "auto-save-directory", f"'{target.as_uri()}'")]
        steps.append(Step("Save screenshots in a folder of their own",
                          f"They are saved straight into your Pictures folder now, where a rule can't tell them from "
                          f"your photos. New ones then go to {host.display(target)}.",
                          options=[option(check, f"Save new screenshots to {host.display(target)}", move,
                                          recommended=True, side_effects=[
                                              "Screenshots already in Pictures stay where they are: move the ones you "
                                              "want gone into the new folder, or delete them."])]))
        dirs = [target]
    opts = []
    for days, rec in ((30, True), (90, False)):
        cutoff = time.time() - days * 86400
        acts = []
        for d in dirs:
            old = []
            for f in files_under(d)[0]:
                try:
                    st = f.lstat()
                except OSError:
                    continue
                if max(st.st_mtime, st.st_ctime) < cutoff:
                    old.append(f)
            if old:
                acts.append(DeleteFiles(d, old, f"screenshots older than {days} days", host.display(d), prune=False))
        rules = [f"e {tmpfiles_path(d)} - - - cmM:{days}d" for d in dirs]
        acts += expire_actions(scan, "screenshots", rules, f"Delete what is in {', '.join(host.display(d) for d in dirs)} "
                                                           f"once it is {days} days old")
        opts.append(option(check, f"Keep screenshots for {days} days", acts, recommended=rec, side_effects=[
            "Checked daily. Age counts from when a screenshot was taken or last changed, not when you last looked at it: "
            "move one you want to keep somewhere else.",
            "Only the screenshots folder: screenshots saved elsewhere are left alone.",
            "What the rule deletes is deleted for good; reverting stops the rule, it doesn't bring anything back."]))
    from .._util import uri_path, xdg_user_dir
    pictures = xdg_user_dir(host, scan.paths, "PICTURES") or host.home / "Pictures"
    loose = [f for f in files_under(pictures)[0] if f.parent == pictures
             and re.match(r"^(Screenshot|Screen ?shot|Bildschirmfoto|Capture).*\.(png|jpe?g)$", f.name, re.I)]
    if loose:
        spectacle = scan.kde.get("spectaclerc", "ImageSave", "imageSaveLocation") or \
            scan.kde.get("spectaclerc", "General", "defaultSaveLocation")
        to_pictures = spectacle and Path(uri_path(spectacle) or spectacle) == pictures
        steps.append(Step("Screenshots saved straight into Pictures",
                          f"{len(loose)} screenshot{'s are' if len(loose) != 1 else ' is'} in {host.display(pictures)} "
                          "itself, where a rule can't tell them from your photos, so they are kept for good: move the "
                          f"ones to let expire into {host.display(screenshot_dirs(scan)[0])}, and delete the rest."
                          + (" Spectacle saves there now: in Spectacle, Configure… → Save → Save location, choose "
                             f"{host.display(screenshot_dirs(scan)[0])}." if to_pictures else "")))
    return Guide(check.id, "Let screenshots expire",
                 "Screenshots often catch what was on screen by accident: messages, account pages, documents.", steps + [
                     Step("Choose how long to keep them", options=opts if dirs else [],
                          text="" if dirs else "Your screenshots aren't saved in a folder of their own, so there is "
                          "nothing a rule could safely expire.", done=not dirs),
                     Step("Review them", "Before choosing, look through " +
                          ", ".join(host.display(d) for d in dirs or screenshot_dirs(scan)) + " for anything to keep."),
                 ])


# ------------------------------------------------------------------ right-click entries

@guide("desk.file_manager_actions")
def file_manager_actions(check, scan, outcome):
    from ...tools import integration as I
    from .._util import installed
    host = scan.host
    command = I.program(host.environ)
    entries = [e for e in I.file_manager_entries(scan.paths.data_home, command) if installed(host, e.program)]
    acts = [WriteFile(e.path, lambda old, t=e.content: t, f"{e.manager}: write {e.path.name}", host.display(e.path), e.mode)
            for e in entries if read_text(host, e.path) != e.content]
    managers = sorted({e.manager for e in entries})
    blockers = [] if I.command_exists(command) else [
        "This copy of the app can't be found where it runs from now, so the menu entries couldn't start it."]
    return Guide(check.id, "Verify and Remove metadata in the right-click menu", "", [
        Step(f"Add the entries to {' and '.join(managers)}",
             "Right-click a file and choose \"Verify download…\" (for one file) or \"Remove metadata…\" (for one or "
             "more files, or folders); the app opens on that tool with the files chosen." + (" In Dolphin they are under \"DA Privacy "
             "Kit\"." if "Dolphin" in managers else "") + (" In Nautilus they are under Scripts." if "Nautilus" in
                                                                managers else ""),
             options=[option(check, "Add them", acts, blockers=blockers, recommended=True, side_effects=[
                 "They start this copy of the app (" + shell(command) + "): if you move it, Set up… writes them "
                 "again for the new place.",
                 "A file manager that is open may need to be closed and opened again to show them.",
                 "Reverting removes them."])],
             done=not acts),
    ])


# ------------------------------------------------------------------ ~/Ephemeral

def swap_unencrypted(scan) -> bool:
    """Whether a swap on the disk is known not to be encrypted: only then does the unencrypted-swap check fail, and is
    it worth sending the user to (it passes with the swap inside LUKS)."""
    from ... import blockdev
    devices = scan.context.devices
    if devices is None:
        return False                                    # can't tell: that check says it couldn't
    for name, kind, _ in read_swaps(scan.host):
        if name.startswith("/dev/zram"):
            continue
        dev = blockdev.find(devices, scan.host, name) if kind == "partition" else blockdev.holding(devices, name)
        if dev is not None and not dev.encrypted:
            return True
    return False


def memory_leaks_to_disk(scan) -> list[str]:
    """Why a tmpfs may still end up on disk: swap on disk, zram writing back, hibernation."""
    from ..encryption import zram_backing
    out = []
    disk = [n for n, _, _ in read_swaps(scan.host) if not n.startswith("/dev/zram")]
    if disk:
        out.append(f"Swap on disk ({', '.join(disk)}): under memory pressure, the kernel moves parts of memory there, "
                   "the folder's files included, and they stay on the disk after a reboot (see enc.swap_persistent"
                   + (" and enc.swap_unencrypted)." if swap_unencrypted(scan) else ")."))
    back = [n for n, _, _ in read_swaps(scan.host) if n.startswith("/dev/zram") and zram_backing(scan.host, n)]
    if back:
        out.append("zram writes pages back to a disk (a writeback device): the same as swap on disk.")
    if scan.context["hibernation"]:
        out.append("Hibernation writes all of memory, the folder included, to the disk.")
    return out


CRYPTOMATOR_FLATPAK = "org.cryptomator.Cryptomator"


def cryptomator_step(scan) -> Step:
    """The alternative when files should last: an encrypted vault of its own (Cryptomator)."""
    from .._util import installed
    have = installed(scan.host, "cryptomator") or any(
        (d / CRYPTOMATOR_FLATPAK).exists() for d in (scan.host.home / ".local/share/flatpak/app",
                                                     scan.host.sys_path("/var/lib/flatpak/app")))
    flatpak = installed(scan.host, "flatpak")
    return Step(
        "Or, for files that should last: an encrypted vault (Cryptomator)",
        "If you want a folder that stays after a restart, but whose files, while it is locked, can't be opened "
        "without a password of its own, even by someone who can open your other files (another account with "
        "administrator rights, a copy of your home in a backup, a program running as you), use Cryptomator: free, open source, "
        "independently audited and well established. It makes a vault: a folder you unlock with its own password, "
        "whose files (and their names) are stored encrypted, and which you lock again when you are done. "
        "It is also a good way to keep files in a cloud-synced folder (Dropbox, Google Drive, OneDrive, iCloud) safe "
        "from the sync company: those services hold the keys to what you upload, and can read it. Put the vault "
        "inside the synced folder and only encrypted files leave this computer. A service with true client-side "
        "encryption, where only you hold the key, doesn't need it."
        + (" Cryptomator is installed here." if have else
           "" if flatpak else " Download it from cryptomator.org (an AppImage), or install it with your package manager."),
        commands=[] if have or not flatpak else [f"flatpak install flathub {CRYPTOMATOR_FLATPAK}"])


@guide("desk.ephemeral_folder")
def ephemeral(check, scan, outcome):
    from ..desktop import MemoryMount
    host = scan.host
    mm = MemoryMount(scan, "ephemeral")
    m = re.search(r"^MemTotal:\s+(\d+) kB", host.read_sys("/proc/meminfo") or "", re.M)
    high = min(65536, int(m.group(1)) // 1024 // 2) if m else 4096
    p = scan.params
    size = Input.read(p, "size_mb", "number", min(EPHEMERAL_MB, high), 50, high)
    until = Input.read(p, "until", "choice", "reboot", choices=("reboot", "logout"))
    noexec = Input.read(p, "noexec", "bool", True)
    inputs = [
        Input("size_mb", "Size", "number", size, min(EPHEMERAL_MB, high), min=50, max=high, unit="MB",
              help="The most it can hold. It only takes memory for what is in it."),
        Input("until", "Empty it", "choice", until, "reboot",
              choices=[("reboot", "At every reboot"), ("logout", "When you log out, and at every reboot")]),
        Input("noexec", "Don't let programs run from it (noexec)", "bool", noexec, True,
              help="Safer: a program or script saved in it can't be started from there. For documents, images and "
                   "downloads, keep this on; turn it off only to run things from it, which won't work otherwise."),
    ]
    leaks = memory_leaks_to_disk(scan)
    steps = [Step("First: swap and hibernation",
                  ("Much of the benefit is lost until this is fixed: " + " ".join(leaks) + " Fix swap first; the folder "
                   "can still be set up meanwhile.") if leaks else
                  "Swap stays in memory and hibernation is off, so the folder's files never reach the disk.",
                  done=not leaks)]
    folder = mm.expected
    blockers = []
    if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
        blockers.append("~/Ephemeral exists but isn't a folder (or is a link): rename it first.")
    elif not mm.in_memory and isdir(folder) and files_under(folder, limit=1)[0]:
        blockers.append("~/Ephemeral already has files in it: move them out first (a mount would hide them, not remove "
                        "them).")
    if mm.unit_exists and not mm.in_memory:
        blockers.append(f"It is set up ({mm.unit_file}) but isn't mounted now. Revert it from History to start over.")
    when = "when you log out and at every reboot" if until == "logout" else "at every reboot"
    acts = [] if mm.in_memory else [RootChange(
        "mount_tmpfs", {"target": "ephemeral", "size_mb": size, "noexec": noexec, "until": until},
        f"Add the systemd mount unit {mm.unit_file}, keeping ~/Ephemeral in memory (tmpfs, {size} MB, "
        f"{'noexec,' if noexec else ''}nosuid,nodev, only you can open it), emptied {when}, and mount it now", phase=3)]
    effects = [
        f"Everything in ~/Ephemeral is gone {when}, for good: keep nothing there you need later.",
        f"It holds at most {size} MB, and takes memory only for what is in it: while files are there, that memory "
        "isn't free for programs.",
        "If the mount is ever missing (a folder on the way became a link, or the unit failed), the folder on disk "
        "underneath is read-only, so nothing is saved there by mistake.",
        "Reverting from History unmounts it and deletes the unit; it refuses while files are in it, unless you choose "
        "to revert anyway.",
        "Flatpak apps see it only if they have access to your home folder.",
    ]
    if until == "logout":
        effects.append("With lingering on (loginctl enable-linger), your session manager keeps running after you log "
                       "out, so the folder is only emptied at reboot.")
    if not noexec:
        effects.append("Programs can run from it: anything you download there can be started directly.")
    steps.append(Step("Set up ~/Ephemeral", "A folder in your home that is kept in memory: what you put in it is "
                      "never written to the disk.", inputs=inputs if not mm.in_memory else [],
                      options=[option(check, "Set it up (needs administrator access)", acts, blockers=blockers,
                                      recommended=True, side_effects=effects)],
                      done=mm.in_memory))
    from .._util import installed
    from ..desktop import ThumbnailMount, recoll_dir
    tm_note = "" if ThumbnailMount(scan).in_memory else " Keep the thumbnail cache in memory too (desk.thumbnails)."
    # only the indexers that are here: KDE's steps on Cinnamon, with none installed, were noise
    indexers = []
    if installed(host, "balooctl", "balooctl6") or isfile(scan.paths.config_home / "baloofilerc"):
        indexers.append("Baloo: System Settings → Search → File Search → exclude ~/Ephemeral")
    if scan.gnome.indexer_command():
        indexers.append("GNOME's search: Settings → Search → Search Locations, ~/Ephemeral off")
    if installed(host, "recoll", "recollindex") or isdir(recoll_dir(scan)):
        indexers.append("Recoll: Preferences → Index configuration → Skipped paths, add ~/Ephemeral")
    steps.append(Step("What else records the files you open",
                      "The folder keeps its files off the disk, but other parts of the desktop note what you open: "
                      "thumbnails of pictures and documents in it are cached in ~/.cache/thumbnails." + tm_note +
                      " The recent files list records their names (desk.recent_files)."
                      + (f" A file indexer here may index it ({'; '.join(indexers)})." if indexers else "")
                      + " Backups of your home may copy it while it is mounted: exclude it there. To download into it, "
                      "choose ~/Ephemeral in the browser's download settings, or when it asks where to save."))
    steps.append(cryptomator_step(scan))
    return Guide(check.id, "A folder in memory for temporary work",
                 "For downloads, scans and working copies that shouldn't outlive the task.", steps)
