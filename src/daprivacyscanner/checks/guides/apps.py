"""Guided fixes: apps (see the package docstring)."""

from __future__ import annotations

from pathlib import Path

from ...fix import DeleteFiles, RootChange, WriteFile, shell
from ...guide import Guide, Step
from .. import Scan
from .._util import children, files_under, installed, isdir, isfile, read_text
from ..fixes import gset, in_use
from . import evidence, guide, option, install, ff_prefs


@guide("app.photo_dbs")
def photo_dbs(check, scan, outcome):
    from ...paths import Base
    host, steps = scan.host, []
    caches = []
    for loc in scan.paths.locate(Base.CACHE, "gthumb", flatpak=["org.gnome.gThumb"]):
        if not in_use(scan, loc.path, "gthumb"):
            caches.append(DeleteFiles(loc.path, files_under(loc.path)[0], "gThumb cache", host.display(loc.path)))
    for loc in scan.paths.locate(Base.CACHE, "shotwell", flatpak=["org.gnome.Shotwell"]):
        if not in_use(scan, loc.path, "shotwell"):
            caches.append(DeleteFiles(loc.path, files_under(loc.path)[0], "Shotwell thumbnails", host.display(loc.path)))
    caches = [c for c in caches if c.files]
    if caches:
        steps.append(Step("Delete thumbnail caches", "The apps make them again as you browse.",
                          options=[option(check, "Delete them", caches)]))
    if any("digiKam" in e.label for e in outcome.evidence):
        steps.append(Step("digiKam", "Its thumbnail and similarity databases can go (Settings → Maintenance rebuilds "
                          "them); face data lives in recognition.db and the main database. To drop faces: People → "
                          "right-click a person → Remove; and Settings → Configure digiKam → Metadata to stop "
                          "writing face tags into the photos themselves."))
    if any("Shotwell" in e.label for e in outcome.evidence):
        steps.append(Step("Shotwell", "Faces → select a person → Delete removes their face data."))
    fde = scan.context["fde"] == "full"
    steps.append(Step("Keep the library on encrypted storage",
                      "The databases hold an index of every photo, often with places and dates; full-disk encryption "
                      "protects them when the machine is off." + (" This disk is encrypted." if fde else
                                                                    " See the disk encryption checks (enc.fde_missing)."),
                      done=fde))
    return Guide(check.id, "Reduce what photo managers keep", "", steps)


def _residue(scan: Scan) -> list[tuple[str, Path, tuple[str, ...]]]:
    h, s = scan.host.home, scan.paths.state_home
    return [("Vim swap files", h / ".vim" / "swap", ("vim", "gvim")), ("Vim undo files", h / ".vim" / "undo", ("vim", "gvim")),
            ("Vim state", s / "vim", ("vim", "gvim")),
            ("Neovim swap files", s / "nvim" / "swap", ("nvim",)), ("Neovim undo files", s / "nvim" / "undo", ("nvim",)),
            ("Emacs auto-saves", h / ".emacs.d" / "auto-save-list", ("emacs",)),
            ("Kate swap files", scan.paths.data_home / "kate" / "swap", ("kate",))]


@guide("app.editor_residue")
def editor_residue(check, scan, outcome):
    from ..apps import RESIDUE
    from ..auth import SKIP_DIRS
    host = scan.host
    acts, skipped = [], []
    for label, d, procs in _residue(scan):
        files = files_under(d)[0]
        if not files:
            continue
        if in_use(scan, d, *procs):
            skipped.append(f"{label}: close {procs[0]} first.")
            continue
        acts.append(DeleteFiles(d, files, label, host.display(d), prune=False))
    from ..fixes import running
    from .._util import holders
    for label, p, procs in (("Vim history and registers", host.home / ".viminfo", ("vim", "gvim")),
                            ("Neovim history and registers", scan.paths.state_home / "nvim" / "shada", ("nvim",))):
        files = files_under(p)[0] if isdir(p) else [p] if isfile(p) else []
        if not files:
            continue
        # the editor itself, or whatever holds these files: never their folder (~/.viminfo's is the home folder, which
        # something always has open, so it was never deleted, and silently)
        users = sorted(set(running(scan, *procs)) | holders(scan, p))
        if users:
            skipped.append(f"{label}: close {', '.join(users)} first (it writes them as it quits).")
            continue
        acts.append(DeleteFiles(p if isdir(p) else p.parent, files, label, host.display(p if isdir(p) else p.parent),
                                prune=False))
    stray, stack = [], [(host.home, 0)]
    while stack:
        d, depth = stack.pop()
        for p in children(d):
            if p.is_symlink():
                continue
            if isdir(p):
                if depth < 3 and p.name not in SKIP_DIRS:
                    stack.append((p, depth + 1))
            elif RESIDUE.match(p.name):
                stray.append(p)
    steps = [Step("Delete editor swap, undo and history files",
                  "Swap files of documents open now are in use: close the editor first. " + " ".join(skipped),
                  options=[option(check, "Delete them", acts, side_effects=skipped)] if acts else [],
                  done=not acts and not skipped)]
    if stray:
        n = len(stray)
        steps.append(Step("Backup files next to your documents",
                          f"{n} file{'s' if n != 1 else ''} named like name~, #name# or .name.swp, in your folders: "
                          f"{'each is' if n != 1 else 'it is'} listed with where it is, so you can look first. Some may "
                          "be backups you want; they are deleted for good.",
                          options=[option(check, f"Delete {n} backup file{'s' if n != 1 else ''}",
                                          [DeleteFiles(host.home, stray, "editor backup files", "~", prune=False)])]))
    from ..apps import VSCODE_PROCESSES, editor_histories
    from ..fixes import set_jsonc_key
    for h in editor_histories(scan):
        files = files_under(h.folder)[0]
        settings = h.settings and (read_text(host, h.settings) or "")
        off = h.settings is not None and '"workbench.localHistory.enabled": false' not in (settings or "")
        acts = ([DeleteFiles(h.folder, files, h.label, host.display(h.folder), prune=False,
                             about=_history_sources(host, h.folder))] if files else []) + (
            [WriteFile(h.settings, lambda old: set_jsonc_key(old, "workbench.localHistory.enabled", "false"),
                       'Set "workbench.localHistory.enabled": false', host.display(h.settings))] if off else [])
        if not acts:
            continue
        users = in_use(scan, h.owner, *(VSCODE_PROCESSES if h.settings else ()))
        steps.append(Step(f"{h.label[0].upper() + h.label[1:]}",
                          "A copy of each version of a file is kept every time you save it, deleted files' included"
                          + (": turned off in its settings, it keeps no more." if h.settings else
                             ". The IDE's own setting (Settings → Advanced Settings → Local History) limits how long."),
                          options=[option(check, "Delete it" + (" and stop keeping it" if off else ""), acts,
                                          blockers=[f"Close {', '.join(users)} first."] if users else [],
                                          side_effects=["The Timeline view's (or Local History's) earlier versions of "
                                                        "your files are gone; files themselves aren't touched."])]))
    keep = _editor_memory_options(check, scan)
    if any(host.runner.which(e) for e in ("vim", "gvim", "nvim")):       # nothing to set up without either
        steps.append(Step("Keep swap and undo files in memory from now on",
                          "$XDG_RUNTIME_DIR is a folder in memory that only you can open, emptied when you log out. Vim "
                          "and Neovim can keep their swap and undo files there instead of on the disk.",
                          options=keep, done=not keep))
    steps.append(Step("History and other editors",
                      "Vim: set viminfo= turns off its history of commands, searches and registers; Neovim: set "
                      "shadafile=NONE. Emacs: (setq make-backup-files nil auto-save-default nil)."))
    return Guide(check.id, "Clean up editor leftovers", "", steps)


def _history_sources(host, folder: Path) -> dict[Path, str]:
    """VS Code's Local History keeps each file's versions in a folder named by a hash, with an entries.json naming
    the file ("resource", a file:// address): for the dry run, so the user sees whose versions go."""
    import json
    from urllib.parse import unquote, urlparse
    out = {}
    for d in children(folder):
        try:
            raw = json.loads(read_text(host, d / "entries.json") or "null")
        except ValueError:
            continue
        uri = raw.get("resource") if isinstance(raw, dict) else None
        if isinstance(uri, str):
            u = urlparse(uri)        # file://, or vscode-userdata: for its own settings
            local = u.scheme in ("file", "vscode-userdata") and u.path.startswith("/")
            out[d] = f"earlier versions of {host.display(Path(unquote(u.path))) if local else uri}"
    return out


VIM_MARK = '" DA Privacy Kit: swap and undo files in memory'
LUA_MARK = "-- DA Privacy Kit: swap and undo files in memory"
VIM_BLOCK = (VIM_MARK + " ($XDG_RUNTIME_DIR, emptied at logout)\n"
             "if !empty($XDG_RUNTIME_DIR)\n  set directory^=$XDG_RUNTIME_DIR//\n  set undodir^=$XDG_RUNTIME_DIR//\nendif\n")
LUA_BLOCK = (LUA_MARK + " ($XDG_RUNTIME_DIR, emptied at logout)\n"
             "if vim.env.XDG_RUNTIME_DIR then\n  vim.opt.directory:prepend(vim.env.XDG_RUNTIME_DIR .. \"//\")\n"
             "  vim.opt.undodir:prepend(vim.env.XDG_RUNTIME_DIR .. \"//\")\nend\n")
# a user vimrc turns off Vim's defaults.vim (syntax, mouse, ...): a new one loads it, as Vim did before
VIM_DEFAULTS = "unlet! skip_defaults_vim\nsource $VIMRUNTIME/defaults.vim\n\n"


def _vimrcs(scan) -> list[Path]:
    """Where Vim looks for the user's vimrc, in its order; it reads the first that exists ($XDG_CONFIG_HOME/vim/vimrc
    from Vim 9.1.0327). A new ~/.vimrc beside an XDG one would take its place, and the whole config be ignored."""
    h = scan.host.home
    return [h / ".vimrc", h / ".vim" / "vimrc", scan.paths.config_home / "vim" / "vimrc"]


def _append(block: str, new_file_prefix: str = ""):
    return lambda old: (new_file_prefix + block) if old is None else old.rstrip("\n") + "\n\n" + block


def _editor_memory_options(check, scan) -> list:
    from ...fix import WriteFile
    host, acts = scan.host, []
    h, nvim = host.home, scan.paths.config_home / "nvim"
    if host.runner.which("vim") or host.runner.which("gvim"):
        rc = next((f for f in _vimrcs(scan) if isfile(f)), None)
        if rc is None:
            acts.append(WriteFile(h / ".vimrc", _append(VIM_BLOCK, VIM_DEFAULTS),
                                  "Create it, loading Vim's defaults, with swap and undo files in $XDG_RUNTIME_DIR",
                                  host.display(h / ".vimrc")))
        elif VIM_MARK not in (read_text(host, rc) or ""):
            acts.append(WriteFile(rc, _append(VIM_BLOCK), "Add swap and undo files in $XDG_RUNTIME_DIR", host.display(rc)))
    if host.runner.which("nvim"):
        lua, vim = nvim / "init.lua", nvim / "init.vim"
        if isfile(vim) and not isfile(lua):
            if VIM_MARK not in (read_text(host, vim) or ""):
                acts.append(WriteFile(vim, _append(VIM_BLOCK), "Add swap and undo files in $XDG_RUNTIME_DIR",
                                      host.display(vim)))
        elif LUA_MARK not in (read_text(host, lua) or ""):
            acts.append(WriteFile(lua, _append(LUA_BLOCK), "Add swap and undo files in $XDG_RUNTIME_DIR" +
                                  ("" if isfile(lua) else " (a new init.lua)"), host.display(lua)))
    if not acts:
        return []
    return [option(check, "Keep Vim's and Neovim's swap and undo files in memory", acts, recommended=True, side_effects=[
        "Swap files still recover your work after the editor crashes, but not after a power cut or a reboot.",
        "Undo history kept in files (with undofile on) lasts until you log out.",
        "Applies to editors started from now on."])]


@guide("app.office")
def office(check, scan, outcome):
    host, acts, blockers = scan.host, [], []
    busy = False
    for loc in scan.paths.config("libreoffice/4/user", flatpak=["org.libreoffice.LibreOffice"], snap=["libreoffice"]):
        files = files_under(loc.path / "backup")[0]
        if files:
            acts.append(DeleteFiles(loc.path / "backup", files, "LibreOffice backup copies", host.display(loc.path / "backup")))
            busy |= bool(in_use(scan, loc.path, "soffice.bin", "soffice"))
    if acts and busy:
        blockers.append("Close LibreOffice first: it keeps copies of open documents there.")
    return Guide(check.id, "Clear office apps' recent lists and copies", "", [
        Step("Delete LibreOffice's backup copies",
             options=[option(check, "Delete them", acts, blockers=blockers)] if acts else [], done=not acts),
        Step("Clear the recent documents list", "LibreOffice: File → Recent Documents → Clear List. ONLYOFFICE: the "
             "Recent files tab → right-click → Clear. (Editing their settings files directly is fragile.)"),
        Step("Stop keeping backup copies", "LibreOffice: Tools → Options → Load/Save → General → turn off \"Always "
             "create backup copy\"; keep AutoRecovery if you want crash protection."),
    ])


@guide("app.mail_remote_content")
def mail_remote_content(check, scan, outcome):
    # only profiles that load it: a missing pref is Thunderbird's default, blocked
    opts = ff_prefs(check, scan, "Block remote content in Thunderbird",
                    {"mailnews.message_display.disable_remote_image": True}, only=("Thunderbird",),
                    want=lambda prefs, p: prefs.get("mailnews.message_display.disable_remote_image", True) is False,
                    side_effects=["Images in mail show after you click \"Show remote content\"; senders you trust can "
                                  "be allowed one by one."], recommended=True)
    evo = gset(scan, "org.gnome.evolution.mail", "image-loading-policy", "'never'")
    steps = [Step("Thunderbird", options=opts, done=not opts)]
    if any(e.label == "Evolution" for e in outcome.evidence):
        unread = scan.gnome.gsettings("org.gnome.evolution.mail", "image-loading-policy") is None
        steps.append(Step("Evolution", "Its setting couldn't be read here (a Flatpak keeps it in its own sandbox): in "
                          "Evolution, Edit → Preferences → Mail Preferences → HTML Messages, choose \"Never load remote "
                          "content\"." if unread else "",
                          options=[option(check, "Never load remote images", evo, recommended=True,
                                          side_effects=["Load them per message with the bar above it."])]
                          if evo else [], done=not evo and not unread))
    return Guide(check.id, "Stop mail from loading remote content",
                 "A one-pixel image fetched from the sender's server reports the moment, address and device a "
                 "message was opened on.", steps)


LO_REMOVE_ITEM = ('<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name='
                  '"RemovePersonalInfoOnSaving" oor:op="fuse"><value>true</value></prop></item>')
# LibreOffice writes each setting as one <item> line; this finds RemovePersonalInfoOnSaving's, whatever its value
LO_REMOVE_LINE = (r'<item oor:path="/org\.openoffice\.Office\.Common/Security/Scripting"><prop '
                  r'oor:name="RemovePersonalInfoOnSaving"')
LO_NEW_FILE = ('<?xml version="1.0" encoding="UTF-8"?>\n<oor:items xmlns:oor="http://openoffice.org/2001/registry" '
               'xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
               '</oor:items>\n')


def _lo_remove_personal_info(xcu: Path, display: str):
    """RemovePersonalInfoOnSaving=true, its one line set and put back alone: LibreOffice rewrites the rest of the file
    every time it quits."""
    from ...fix import SettingLines
    return SettingLines(xcu, display, "Set RemovePersonalInfoOnSaving to true", [(LO_REMOVE_LINE, LO_REMOVE_ITEM)],
                        anchor="</oor:items>", new_file=LO_NEW_FILE,
                        by_hand="Tools → Options → LibreOffice → Security → Options: untick \"Remove personal information "
                                "on saving\"")


def _gimp_no_export(rc: Path, display: str, label: str):
    """The three export-metadata options off, each line set and put back alone (GIMP rewrites gimprc as it quits),
    changed where they are and added otherwise, before GIMP's closing comment when it has one."""
    import re
    from ...fix import SettingLines
    from ..apps import GIMP_EXPORT_KEYS
    return SettingLines(rc, display, f"{label}: set export-metadata-exif, -xmp and -iptc to no",
                        [(rf"^\({re.escape(k)}\s+\w+\)", f"({k} no)") for k in GIMP_EXPORT_KEYS],
                        anchor="# end of gimprc",
                        by_hand="Edit → Preferences → Image Import & Export: tick the three \"Export … metadata by "
                                "default\" boxes")


@guide("app.shared_file_metadata")
def shared_file_metadata(check, scan, outcome):
    from ..apps import GIMP_PROCESSES, LO_REMOVE_INFO, gimp_exported, gimp_rcs, libreoffice_profiles
    host = scan.host
    acts, blockers = [], []
    for loc in libreoffice_profiles(scan):
        xcu = loc.path / "registrymodifications.xcu"
        m = LO_REMOVE_INFO.search(read_text(host, xcu) or "")
        if m and m.group(1) == "true":
            continue
        acts.append(_lo_remove_personal_info(xcu, host.display(xcu)))
        if in_use(scan, loc.path, "soffice.bin", "soffice"):
            blockers.append("Close LibreOffice first: it rewrites its settings as it exits.")
    steps = [Step("LibreOffice: remove personal information when saving",
                  "Tools → Options → LibreOffice → Security → Options → \"Remove personal information on saving\" "
                  "does the same from inside the app.",
                  options=[option(check, "Turn it on", acts, blockers=blockers, recommended=True, side_effects=[
                      "Documents no longer record who wrote or edited them, nor when; track changes still work "
                      "but show no names."])] if acts else [], done=not acts)]
    gimps = gimp_rcs(scan)
    if gimps:
        gacts, gblock = [], []
        for label, rc in gimps:
            if gimp_exported(read_text(host, rc) or ""):
                gacts.append(_gimp_no_export(rc, host.display(rc), label))
                if in_use(scan, rc.parent, *GIMP_PROCESSES) and not gblock:
                    gblock.append("Close GIMP first: it rewrites its settings as it exits.")
        steps.append(Step("GIMP: don't copy a photo's details into exported images",
                          "Edit → Preferences → Image Import & Export → untick \"Export Exif metadata by default\", "
                          "\"Export XMP metadata by default\" and \"Export IPTC metadata by default\" does the same. "
                          "Each export dialog can still turn them on for one image.",
                          options=[option(check, "Turn them off", gacts, blockers=gblock, recommended=True, side_effects=[
                              "Exported images no longer carry the original's camera, date or location; the colour "
                              "profile and the image itself are unchanged."])] if gacts else [], done=not gacts))
    steps.append(Step("Photos and other files you already have",
                      "Tools → Remove metadata shows what a file carries and makes a clean copy beside it, and the "
                      "Outbox (app.metadata_outbox) does it for every file you put in ~/Outbox. Both use mat2:",
                      commands=[c for c in [install(scan, debian="mat2", fedora="mat2", arch="mat2", suse="mat2")] if c]
                      if not installed(host, "mat2") else []))
    return Guide(check.id, "Keep your name and location out of shared files", "", steps)


@guide("app.metadata_outbox")
def metadata_outbox(check, scan, outcome):
    from ...fix import MakeDir, UserUnitSet
    from ...tools import integration as I
    host = scan.host
    mat2 = installed(host, "mat2")
    command = I.program(host.environ)
    units = I.outbox_units(scan.paths.config_home, command)
    acts = []
    outbox = host.home / "Outbox"
    if not outbox.exists():
        acts.append(MakeDir(outbox, "~/Outbox", 0o700))
    for path, text in units.items():
        if read_text(host, path) != text:
            acts.append(WriteFile(path, lambda old, t=text: t, f"Write the user unit {path.name}", host.display(path), 0o644))
    from .._util import systemctl_state
    if acts or systemctl_state(host, "is-enabled", f"{I.OUTBOX_UNIT}.path", user=True) != "enabled":
        acts.append(UserUnitSet(f"{I.OUTBOX_UNIT}.path", True, "watch ~/Outbox from now on, and at every login"))
    blockers = [] if outbox.is_dir() or not outbox.exists() else ["~/Outbox exists but isn't a folder: rename it first."]
    if not I.command_exists(command):
        blockers.append("This copy of the app can't be found where it runs from now, so the Outbox couldn't start it.")
    steps = [Step("Install mat2", "The Outbox uses mat2 to clean the files.",
                  commands=[c for c in [install(scan, debian="mat2", fedora="mat2", arch="mat2", suse="mat2")] if c],
                  done=mat2),
             Step("Set up ~/Outbox", "A folder in your home: put a copy of a photo or document in it, and within a few "
                  "seconds a copy without its hidden details appears in ~/Outbox/Cleaned.",
                  options=[option(check, "Set it up", acts, blockers=blockers, recommended=True, side_effects=[
                      "The original goes to ~/Outbox/Originals, never deleted: clear it out yourself when you're done.",
                      "A file mat2 can't clean is moved to ~/Outbox/Not cleaned, and a notification says so.",
                      "It starts this copy of the app (" + shell(command) + "): if you move or delete it, the "
                      "app says so here and Set up… points the Outbox at the new one.",
                      "Reverting stops it and removes its units; ~/Outbox and what is in it stay."])],
                  done=not acts),
             Step("Using it", "Copy, don't move, what you want to share into ~/Outbox, then send the copy from "
                  "~/Outbox/Cleaned. What mat2 removes and can't remove: it strips metadata (location, author, camera, "
                  "software, dates); it can't change what is visible in the file itself (faces, text, a reflection), "
                  "and for PDFs it redraws each page as an image, so text can no longer be selected.")]
    return Guide(check.id, "An Outbox that removes metadata", "For photos and documents you are about to share.", steps)


@guide("app.boxes")
def boxes(check, scan, outcome):
    from ...fix import CopyTree, MakeDir
    from ...guide import Input
    from ...tools import box as B
    from ...tools import integration as I
    from ...tools import menu, trial
    from ...tools.viewer import _program
    host = scan.host
    params = getattr(scan, "params", None) or {}
    existing = {b.slug: b for b in B.every(host)}
    cur = trial.CURRENT
    from_trial = cur is not None and cur.kind not in ("installed", "flatpak") and bool(cur.argv) and cur.state in ("ready", "ended")
    apps = {a.id: a for a in menu.apps(host) if not a.terminal and (
        (a.kind == "flatpak" and a.flatpak) or (a.kind == "native" and _program(host, a.argv[0])))
        and not a.id.startswith("daprivacyscanner-box-")}
    choices = ([("trial", f"The program on trial now: {cur.name}")] if from_trial else []) + \
        [(aid, a.name + (" (Flatpak)" if a.kind == "flatpak" else "")) for aid, a in apps.items()]
    command = I.program(host.environ)
    steps = [Step("What a Box is", parts=[
        ("A home of its own", "The app runs in a sandbox whose home folder is ~/Boxes/NAME/home. It can read and write "
         "there and nowhere else of yours: not your documents, your keys, your browser's profile or other apps' data."),
        ("Giving it files", "Each Box has an Exchange folder (~/Boxes/NAME/Exchange), which the app sees as ~/Exchange (a "
         "Flatpak app at that same path, ~/Boxes/NAME/Exchange). Put a file there to give it to the app; what the app "
         "saves there, you can take out. Nothing else is shared."),
        ("What it doesn't do", "A sandbox isn't a guarantee: it keeps an app from your files, not an app built to break "
         "out through a flaw in the kernel. On an X11 session an app with a window can still read other windows and "
         "what you type into them. It can read what the system tells any program about this computer: the kernel's "
         "command line (which often names your disks' ids), an id that stays the same until a restart, the processor "
         "and the disks' partitions; hiding them would stop apps that start a sandbox of their own (GNOME's "
         "thumbnails, web pages in GNOME apps). And an app in a Box can't use the desktop's password store, so it may "
         "ask you to sign in again or keep its login in its own home."),
        ("Each run in numbers", "While a Box runs it is watched as a trial is, and what is kept is numbers: when, how "
         "long, how many files it wrote, how many hosts it contacted and how many of those were new. No names of files "
         "are kept. Sites aren't kept by name either, but each as a code (a salted hash), so the next run can count the "
         "new ones: anyone who can read the Box's folder could check whether it contacted a site they have in mind. "
         "The app's own files in its home can say more anyway (a browser's history). Nothing watches while it isn't "
         "running.")], done=bool(existing))]
    if not choices:
        steps.append(Step("Choose the app", "No app here can be put in a Box: the menu has no app whose program is in the "
                          "system's folders, and no Flatpak app. A program you downloaded can be: open Tools → Try an app, "
                          "prepare it, then come back here."))
        return Guide(check.id, "A Box for an app", "", steps)
    ids = tuple(c[0] for c in choices)
    source = Input.read(params, "source", "choice", ids[0], choices=ids)
    if source == "trial":
        name, kind, argv, env, flat, host_opt = cur.name, cur.kind, list(cur.argv), dict(cur.env), None, False
        name = B.clean_name(Path(name).stem if kind != "installed" else name)
    else:
        a = apps[source]
        name, env, flat = B.clean_name(a.name), dict(a.env), a.flatpak if a.kind == "flatpak" else None
        if flat:
            kind, host_opt = "flatpak", False
            argv = [x for x in a.argv if x.startswith(("--branch=", "--arch=", "--command="))] + [flat]
        else:
            prog = _program(host, a.argv[0])
            kind, argv = "installed", [prog, *a.argv[1:]]
            host_opt = prog.startswith("/opt/") or any(x.startswith("/opt/") for x in a.argv)
    nets = ("off", "on") if kind == "flatpak" else ("off", "observed")
    network = Input.read(params, "network", "choice", "off", choices=nets)
    gpu = Input.read(params, "gpu", "bool", True)
    sound = Input.read(params, "sound", "bool", False)
    box = B.Box(B.slug_of(name), name, kind, argv, env, flat, host_opt, network, gpu, sound)
    f = B.folder(host, box.slug)
    shown = host.display(f)
    acts, blockers = [], []
    had = existing.get(box.slug)
    if f.exists() and had is None:
        blockers.append(f"{shown} is there already and isn't a Box this app made: move it away first.")
    if had is not None and (had.kind, had.argv, had.flatpak) != (box.kind, box.argv, box.flatpak):
        blockers.append(f"A Box named {box.slug} is there already for another program: revert it in History first.")
    if not (host.home / B.BOXES).exists():
        acts.append(MakeDir(host.home / B.BOXES, "~/" + B.BOXES, 0o700))
    # the app's own names in them go with them on revert: the runs it recorded, and the empty folder bubblewrap makes in
    # the home to mount Exchange on
    for sub, label, owned in ((f, shown, ("runs.json",)), (f / "home", f"{shown}/home", ("Exchange/",)),
                              (f / "Exchange", f"{shown}/Exchange", ())):
        if not sub.exists():
            acts.append(MakeDir(sub, label, 0o700, owned=owned))
    newer = False
    if source == "trial" and not (f / "app").exists():
        acts.append(CopyTree(cur.app, f / "app", f"{shown}/app", f"{cur.name}, as prepared for its trial"))
    elif source == "trial" and had is not None and not blockers and not B.same_program(cur.app, f / "app"):
        # the same program by name, but another copy of it (a newer release, downloaded again): it replaces the one in
        # the Box, which History keeps to put back (found in the 2026-10-17 review: it was silently not copied)
        newer = True
        acts.append(CopyTree(cur.app, f / "app", f"{shown}/app", f"{cur.name}, as prepared for its trial, in place of "
                             "the copy in the Box now", replace=True))
    if read_text(host, f / "box.json") != B.config_text(box):
        acts.append(WriteFile(f / "box.json", lambda old, t=B.config_text(box): t, "Write the Box's settings (box.json)",
                              f"{shown}/box.json", 0o600))
    launcher = B.launcher_path(scan.paths.data_home, box.slug)
    text = B.launcher_text(box, command)
    if read_text(host, launcher) != text:
        acts.append(WriteFile(launcher, lambda old, t=text: t, f"Write the menu entry “{box.name} (in its Box)”",
                              host.display(launcher), 0o644))
    if not I.command_exists(command):
        blockers.append("This copy of the app can't be found where it runs from now, so the menu entry couldn't start it.")
    pasta = installed(host, "pasta")
    net_help = ("None: it reaches nothing. Its usual network: as Flatpak gives it; what it contacts isn't observed."
                if kind == "flatpak" else
                "None: it reaches nothing. Its own, observed: the internet only, your local network fenced off, and "
                "each run counts the hosts it contacted" + ("." if pasta else "; this needs pasta, which isn't installed ("
                + (install(scan, debian="passt", fedora="passt", arch="passt", suse="passt") or "the passt package") + ")."))
    effects = [f"It starts from the menu as “{box.name} (in its Box)”, and from Tools → the Box's row.",
               f"Its data lives in {shown}/home. What it has in your real home folder, if you used it before, isn't "
               "copied in: it starts fresh.",
               "It starts this copy of the app (" + shell(command) + "): if you move or delete it, the scan says so and "
               "Set up… writes the menu entry again.",
               "Reverting removes the menu entry, its settings, the record of its runs and a program copied from a "
               "trial. The Box's home and "
               "Exchange folders stay when they hold anything, and the message says so: delete them yourself when you "
               "no longer want its data (deleting doesn't erase it from the disk; encryption is what protects it)."]
    if kind == "flatpak":
        effects.append("It runs in Flatpak's own sandbox with the permissions it declares for itself dropped. It can still "
                       "ask the desktop through its portals: a file chooser that you answer, notifications, opening a link. "
                       "And it can ask Flatpak to start another copy of itself, as apps do to draw pictures: that copy gets "
                       "its real data in ~/.var/app (not the Box's), though not your files, the desktop services it "
                       "declares or a network the Box doesn't give; it is ended when the Box's app ends.")
        effects.append(f"Flatpak shares a folder at its own path, so the app finds the Exchange folder at {shown}/Exchange, "
                       "not at ~/Exchange.")
    if source == "trial" and kind == "deb":
        effects.append("The package stays unpacked, not installed: what it depends on must be installed already.")
    if newer:
        effects.insert(0, f"The Box already holds another copy of {cur.name} (an earlier release, or a different file "
                       "of the same name). This one takes its place; its home and Exchange folders, with the app's "
                       "data, stay as they are. The copy there now is kept in History, and put back if you revert this.")
    steps.append(Step(
        "Choose the app and what it gets", "The app to keep in a Box. An installed app stays installed as it is; only "
        "the copy started from the Box's menu entry is sandboxed.",
        inputs=[Input("source", "App", "choice", source, ids[0], choices=choices),
                Input("network", "Network", "choice", network, "off",
                      choices=[("off", "None")] + ([("on", "Its usual network")] if kind == "flatpak"
                                                    else [("observed", "Its own, observed")]), help=net_help),
                Input("gpu", "The graphics card", "bool", gpu, True,
                      help="So it draws as it would outside. Its drivers then handle what the app sends them."),
                Input("sound", "Sound", "bool", sound, False,
                      help="This computer's sound server, which runs outside the sandbox: with it the app could also "
                           "record from the microphone, read your user name, this computer's name and which other "
                           "programs use sound, and ask the server to connect to any address or listen for "
                           "connections, on this computer's own network, so it could reach the internet and your local "
                           "network even with no network of its own.")],
        options=[option(check, f"Set up a Box for {box.name}", acts, blockers=blockers, recommended=True,
                        side_effects=effects)],
        done=not acts and not blockers))
    steps.append(Step("Using it", "Start it from the menu, or from Tools, where each Box shows its last runs in numbers. "
                      "To give it a file, put the file in its Exchange folder; inside, the app finds it in ~/Exchange. To "
                      "remove a Box, revert it in History."))
    return Guide(check.id, "A Box for an app", "An app kept in a sandbox with a home folder of its own, for good."
                 + (f" Set up now: {', '.join(b.name for b in existing.values())}." if existing else ""), steps)


@guide("app.cups_spool")
def cups_spool(check, scan, outcome):
    # cupsd works out each finished job's expiry from the limits when it loads it (load_job_cache,
    # cupsdLoadJob), so jobs kept under the old ones expire at the restart (cupsdCleanJobs)
    from ..apps import cups_seconds
    effects = ["CUPS restarts to apply it; a job printing at that moment may be interrupted."]
    # what is set now (the check's evidence: "No", "1d", "86400 (default: one day)"): an option already in place, or
    # one that would keep more than now, isn't offered (applied again, it was an empty History entry: live on Mint)
    now = {k: cups_seconds(str(v).split()[0]) for k in ("PreserveJobFiles", "PreserveJobHistory")
           for v in evidence(outcome, k)[:1]}
    files, history = now.get("PreserveJobFiles", -1), now.get("PreserveJobHistory", -1)
    opts = []
    if not (files == 0 and history == 0):
        opts.append(option(check, "Keep neither documents nor job history", [RootChange(
            "edit_config", {"target": "cups", "values": {"PreserveJobFiles": "No", "PreserveJobHistory": "No"}},
            "Set PreserveJobFiles No and PreserveJobHistory No in /etc/cups/cupsd.conf")],
            side_effects=effects, recommended=True))
    day = files == 0 and history is not None and 0 <= history <= 86400
    if not day:
        opts.append(option(check, "Keep the job list for a day, not the documents", [RootChange(
            "edit_config", {"target": "cups", "values": {"PreserveJobFiles": "No", "PreserveJobHistory": "1d"}},
            "Set PreserveJobFiles No and PreserveJobHistory 1d in /etc/cups/cupsd.conf")], side_effects=effects))
    return Guide(check.id, "Stop CUPS keeping printed documents", "", [
        Step("Choose what CUPS keeps", options=opts, done=day,
             text=("It keeps no documents now, and the job list for a day at most." if day and history else
                   "It keeps neither now." if day else "")
                  + (" When CUPS restarts, it applies the new limits to the jobs it already keeps: the documents of "
                     "finished jobs are deleted"
                     + (", and with the first option their history too." if len(opts) > 1 else ".") if opts else "")),
    ])


# ------------------------------------------------------------------ KDE apps' own recent lists

@guide("app.kde_recent_files")
def kde_recent_files(check, scan, outcome):
    from ...fix import ClearInFile, KConfigLock, MakeDir
    from ..apps import kde_recent_lists
    from ..fixes import clear_kconfig_group, running
    host = scan.host
    lists = kde_recent_lists(scan)
    busy = list(dict.fromkeys(x.app for x in lists if running(scan, x.program)))
    blockers = [f"Close {', '.join(busy)} first: {'it writes its list' if len(busy) == 1 else 'they write their lists'} "
                "as it closes."] if busy else []

    def clear(x) -> list:
        if not x.entries:
            return []
        if x.kind == "kconfig":
            return [ClearInFile(x.path, clear_kconfig_group(x.group), f"Clear {x.label}'s recent files ({x.entries})",
                                host.display(x.path), settings=True)]
        if x.kind == "folder":
            return [DeleteFiles(x.path, [f for f in children(x.path) if f.is_file()], f"{x.label}'s recent folders",
                                host.display(x.path), prune=False)]
        return [DeleteFiles(x.path.parent, [x.path], f"{x.label}'s recent files", host.display(x.path.parent), prune=False)]

    def stop(x) -> list:
        if x.kind == "kconfig":
            # the lock goes beneath the app's own file (kdedefaults), which it reads but never writes: in its own file,
            # the app dropped the marker as it rewrote the file, and the list came back (Gwenview, Okular 26.08)
            return clear(x) + [KConfigLock(x.lock, host.display(x.lock), x.group, f"Stop {x.label} listing what you open")]
        acts = []
        if x.kind == "folder" and x.path.is_dir():
            acts.append(DeleteFiles(x.path, [f for f in children(x.path) if f.is_file()], f"{x.label}'s recent folders",
                                    host.display(x.path), prune=False, remove_root=True))
        elif x.path.is_file():
            acts += clear(x)
        missing = [d for d in x.path.parents if not d.is_dir() and d.is_relative_to(host.home)]
        acts += [MakeDir(d, host.display(d), mode=0o700, phase=4) for d in reversed(missing)]
        acts.append(MakeDir(x.path, host.display(x.path), mode=0o500, phase=4))      # empty and read-only
        return acts

    listed = [x for x in lists if x.entries]
    cleared = [a for x in listed for a in clear(x)]
    sessions = [x.app for x in lists if x.program in ("kate", "kwrite") and not x.stopped]
    steps = [Step("Clear the lists", "Open Recent in these apps starts empty."
                  + (" Kate and KWrite also forget the documents that were open when they last closed." if any(
                      x.program in ("kate", "kwrite") and x.entries for x in listed) else ""),
                  options=[option(check, "Clear them", cleared, blockers=blockers)] if cleared else [],
                  done=not cleared)]
    todo = [x for x in lists if not x.stopped and x.stoppable]
    unstoppable = list(dict.fromkeys(x.label for x in lists if not x.stoppable))
    acts = [a for x in todo for a in stop(x)]
    effects = [f"Open Recent stays empty in {', '.join(dict.fromkeys(x.app for x in todo))}."]
    if sessions:
        effects.append(f"{' and '.join(dict.fromkeys(sessions))} no longer reopen the documents that were open when "
                       "they last closed (a session you named and saved yourself still works).")
    if any(x.program == "gwenview" for x in todo):
        effects.append("Gwenview no longer lists the folders you browsed.")
    effects.append("A KDE app installed later, or one that keeps its list some other way, isn't covered: scan again "
                   "after installing one. Reverting lets them keep lists again.")
    steps.append(Step("Stop them listing what you open",
                      "None of these apps has a setting for it, and System Settings' \"Do not remember\" doesn't reach "
                      "them. For apps that keep the list in their settings file, the list's group is locked ([Recent "
                      "Files][$i], KDE's own way of locking a setting) in a file of the same name in "
                      "~/.config/kdedefaults: Plasma has its apps read that folder beneath your own settings, and they "
                      "never write to it, so the lock holds however often the app rewrites its own file. For Ark, "
                      "Kate, KWrite and Gwenview's folders, which are files of their own, an empty read-only folder "
                      "goes where they would be. Anything already listed is cleared first."
                      + (f" {', '.join(unstoppable)} can't be stopped this way (a Flatpak app reads no settings of yours "
                         "beneath its own, and a list in a state file is read alone): clear it from time to time."
                         if unstoppable else ""),
                      options=[option(check, "Stop these apps keeping lists", acts, blockers=blockers, recommended=True,
                                      side_effects=effects)] if acts else [], done=not acts))
    return Guide(check.id, "KDE apps' lists of what you opened",
                 "Beside the shared recent files list (desk.recent_files), many KDE apps keep a list of their own of "
                 "the files you opened, with their full paths: KolourPaint and Okular in their settings, Ark, Kate and "
                 "KWrite in a file of their own, Gwenview a record of each folder you browsed.", steps)
