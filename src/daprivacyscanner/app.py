"""Entry point: start the local server and open the desktop window, or run a scan from the
terminal (--scan). The app always runs as the user; root work goes through a small polkit
helper (docs/TECHNICAL.md, design rule 3)."""

from __future__ import annotations

import argparse
import os
import secrets
import shlex
import signal
import socket
import sys
import threading
import time

from pathlib import Path

import uvicorn

from . import catalogue
from .hostenv import host_env, set_for_self
from .model import STATUS_WORD
from .launch import scan_command, systemd_exec  # noqa: F401 - the timer, units and right-click entries use them
from .server import create_app

WEBKIT_INSTALL = ("Ubuntu, Mint, Debian: sudo apt install gir1.2-webkit2-4.1 · Fedora: sudo dnf install webkit2gtk4.1 · "
                  "Arch: sudo pacman -Syu webkit2gtk-4.1 · openSUSE: sudo zypper install typelib-1_0-WebKit2-4_1")
HELPER_NOTE = ("The administrator helper isn't installed root-owned, so the password prompt names /usr/bin/python3 "
               "rather than DA Privacy Kit. Install it from the app, or with: daprivacyscanner --install-helper")
TIMER_UNIT = "daprivacyscanner-scan"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


HOST_TYPELIB_DIRS = ("/usr/lib64/girepository-1.0", "/usr/lib/x86_64-linux-gnu/girepository-1.0",
                     "/usr/lib/girepository-1.0")


def _bundled_girepository() -> None:
    """Fill gaps in the host's GObject introspection, from copies bundled in the AppImage (outside
    it there are none, and this does nothing). The host's own always win:
    - PyGObject is built against girepository-2.0, which Fedora and Arch ship inside GLib but
      Debian and Ubuntu package separately (libgirepository-2.0-0) and don't always install. If
      the host has none, the bundled copy is loaded under the same soname, so PyGObject's import
      finds it already loaded.
    - GTK's typelibs refer to base ones (xlib, cairo, freetype, ...) that Arch ships separately
      (gobject-introspection-runtime). Only those the host lacks are added to the search path,
      for this process only (programs it runs get the original, see hostenv)."""
    import ctypes

    fallback = Path(sys.executable).resolve().parents[2] / "lib/girepository-fallback"
    if not fallback.is_dir():
        return
    try:
        ctypes.CDLL("libgirepository-2.0.so.0")
    except OSError:
        ctypes.CDLL(str(fallback / "libgirepository-2.0.so.0"), mode=ctypes.RTLD_GLOBAL)
    missing = [str(d) for d in sorted((fallback / "typelibs").glob("*"))
               if not any(os.path.exists(f"{h}/{d.name}.typelib") for h in HOST_TYPELIB_DIRS)]
    if missing:
        current = os.environ.get("GI_TYPELIB_PATH")
        set_for_self("GI_TYPELIB_PATH", ":".join(missing + ([current] if current else [])))


def window_problem() -> str | None:
    """Why the app window can't open here (no WebKitGTK, no display), or None if it can."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return "There is no graphical display."
    try:
        _bundled_girepository()
        import importlib

        import gi

        gi.require_version("Gtk", "3.0")
        gi.require_version("WebKit2", "4.1")
        for lib in ("Gtk", "WebKit2"):                 # loading them is the test
            importlib.import_module(f"gi.repository.{lib}")
    except Exception as e:  # noqa: BLE001 - a missing typelib, an old GLib, a broken install: all mean "no window"
        return f"The app window needs WebKitGTK 4.1, which isn't installed ({e}). Install it ({WEBKIT_INSTALL})"
    return None


# What running in the user's own browser gives away, said wherever the app does it or offers to
BROWSER_EXPOSES = ("In your web browser the page, with your findings, file names and whatever the tools show, can be read "
                   "by any browser extension allowed on all sites, and the browser may spell-check what you type with "
                   "an online service, sync its history, or keep what is typed in its session files.")


def refuse_without_window(problem: str) -> int:
    """The app window can't open: say why and how to fix it, in a desktop dialog when started from the menu
    (nobody sees stderr then), and stop. It never opens in the browser unasked (BROWSER_EXPOSES)."""
    return show_error(f"{problem.rstrip('.')}.\n\nDA Privacy Kit doesn't open in your web browser by itself. "
                      f"{BROWSER_EXPOSES} If you accept that, start it with: daprivacyscanner --browser")


def show_error(text: str) -> int:
    """Says `text` on stderr in a terminal and, when started from the menu, in a desktop dialog only: stderr is then
    the journal or ~/.xsession-errors, kept on the disk, and the text can name a Box (a downloaded file's name).
    Only when no dialog could show it does it go to stderr there. Returns the exit status for it (2)."""
    import shutil
    import subprocess

    from .hostenv import as_host

    def to_stderr() -> int:
        try:
            print(text, file=sys.stderr)
        except OSError:                             # closed (a pipe whose reader has gone): nothing more to do
            pass
        return 2
    if sys.stderr.isatty() or not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return to_stderr()
    dialogs = [["zenity", "--error", "--title=DA Privacy Kit", "--no-markup", "--width=520", f"--text={text}"],
               ["kdialog", "--title", "DA Privacy Kit", "--error", text]]
    if "kde" in os.environ.get("XDG_CURRENT_DESKTOP", "").lower():
        dialogs.reverse()                          # the desktop's own first
    for argv in dialogs:
        if shutil.which(argv[0]):
            with as_host():
                shown = subprocess.run(argv, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            # closed by its button (0) or its window (1): it was read. Anything else and the program didn't work
            # (seen on CachyOS: a zenity that couldn't load its libraries, exit status 127): try the other one
            if shown in (0, 1):
                return 2
    return to_stderr()                              # no dialog could show it: stderr is all there is


def dry_run(cat, check_id: str, host=None) -> int:
    """Print the plans fixes would follow on this machine, and the steps of guided fixes
    (docs/TECHNICAL.md, design rule 7). Changes nothing; runs without root, so system checks may be partial. An online
    test's guide is built from its result in the saved last report (the test isn't run), when it ran."""
    from .catalogue import Scope
    from .guide import Guide
    from .history import LastReport
    from .host import Host
    from .paths import PathResolver
    from .runner import Runner

    host = host or Host.local()
    runner = Runner(cat, host)
    saved = None

    def stored(cid: str) -> dict | None:
        nonlocal saved
        if cat[cid].scope is not Scope.ONLINE:
            return None
        if saved is None:
            saved = LastReport(PathResolver(host.home, host.environ)).load(set(cat.checks)) or {}
        return (saved.get("results") or {}).get(cid)
    if check_id == "easy":
        items = runner.plan_easy()
        if not items:
            print("No Easy fixes apply here now.")
        for result, plans in items:
            spec = cat[result.id]
            print(f"Easy fix for {result.id}: {spec.title}" + (f"\n  What it costs: {spec.easy.cost}" if spec.easy.cost else ""))
            for plan in plans:
                print(plan.dry_run("    "))
            print()
        return 0
    if check_id == "all":
        ids = [k for k, r in runner.scan().results.items() if r.fixable]
    elif check_id in cat.checks:
        ids = [check_id]
    else:
        print(f"No check {check_id}", file=sys.stderr)
        return 2
    for cid in ids:
        kept = stored(cid)
        result, plan = runner.plan_fix(cid, stored=kept)
        if plan is None and kept is None and cat[cid].scope is Scope.ONLINE:
            print(f"{cid}: an online test; its guide is built from its last result, and it hasn't run yet "
                  "(the app's Online tests, or daprivacyscanner --online)\n")
        elif plan is None:
            print(f"{cid}: can't be fixed automatically here ({STATUS_WORD[result.status.value].lower()}: {result.summary})\n")
        elif isinstance(plan, Guide):
            print(plan.dry_run(), end="\n\n")
        else:
            print(plan.dry_run() if not plan.empty or plan.blockers else f"{cid}: nothing to change", end="\n\n")
    return 0


def scan_cli(cat, as_json: bool, notify: bool, admin: bool, quiet: bool, redact: bool) -> int:
    """A read-only scan from the terminal. Exit status: 0 nothing found, 1 findings, 2 couldn't
    scan. With --notify, a desktop notification when there are findings new since the last scan, or
    worse (a warning then, failing now)."""
    from . import report as report_mod
    from .history import Accepted, Baseline, LastReport, hidden
    from .host import Host
    from .paths import PathResolver
    from .privileged import HelperUnavailable, PkexecHelper
    from .runner import Runner
    from .undo import UndoLog

    host = Host.local()
    helper = None
    if admin:
        try:
            helper = host.privileged = PkexecHelper.start()
        except HelperUnavailable as e:
            print(f"Scanning without administrator access: {e}", file=sys.stderr)
    try:
        report = Runner(cat, host).scan().to_dict()
    finally:
        if helper is not None:
            helper.close()
    paths = PathResolver(host.home, host.environ)
    changes = Baseline(paths).record(report)
    report["changes"] = changes
    accepted = Accepted(paths).all()
    results = report["results"]
    started = time.time()
    log = UndoLog.for_user(paths)
    log.expire_backups()                            # backups kept only for a while (known_hosts'): scheduled scans too
    report["undone"] = log.undone(results, accepted, host)
    LastReport(paths).save(report)                   # the app opens on this scan next time
    findings = [cid for cid, r in results.items() if r["is_finding"] and not hidden(accepted, cid, r)]
    if not quiet:
        try:
            print(report_mod.export(report, cat, "json" if as_json else "text", host, redact, accepted))
            if changes and not as_json:
                fresh_items = sum(len(v) for v in (changes.get("new_items") or {}).values())
                # nothing the user accepted (and that is still hidden), as on the page
                shown = lambda ids: [c for c in ids if not hidden(accepted, c, results.get(c) or {})]  # noqa: E731
                print(f"Since the last scan: {len(shown(changes['new']))} new, {len(shown(changes['resolved']))} resolved, "
                      f"{len(shown(c['id'] for c in changes['changed']))} changed in severity"
                      + (f", {fresh_items} new in what starts by itself." if fresh_items else "."))
                unchecked = shown(u["id"] for u in changes["unchecked"])
                if unchecked:                         # a problem before, not checked now: never "resolved"
                    n = len(unchecked)
                    print(f"{n} problem{'s' if n > 1 else ''} from an earlier scan couldn't be checked this time "
                          "(not resolved): see \"Couldn't be checked\".")
            sys.stdout.flush()                        # so a closed pipe shows up here, not at exit
        except BrokenPipeError:                       # piped into head or less and closed early
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    # Notifications count and never name, not even a finding's title ("Passwordless sudo"): the lock screen can
    # show them to whoever holds the computer, and a notification daemon's history can keep them on the disk
    fresh = [u for u in report["undone"] if u["undone_since"] >= started]
    if notify and fresh:                              # louder than anything else: a fix the user made was undone
        host.run("notify-send", "--app-name=DA Privacy Kit", "--icon=dialog-warning", "--urgency=critical",
                 f"DA Privacy Kit: {len(fresh)} fix{'es' if len(fresh) > 1 else ''} undone",
                 "Something changed back what you fixed. Open the app to see which, and to fix it again.")
    if notify and changes:
        new = [c for c in changes["new"] if results[c]["is_finding"] and not hidden(accepted, c, results[c])]
        # accepted findings whose severity has just risen above the one they were accepted at
        again = [c["id"] for c in changes["changed"] if c["id"] in accepted
                 and isinstance(accepted[c["id"]].get("severity"), int) and c["from"] <= accepted[c["id"]]["severity"] < c["to"]]
        # findings that got worse: a warning before (thumbnails on disk), failing now and more severe
        # (thumbnails of deleted pictures). Not every rise: a context such as the VPN being off moves
        # severities up and down without the problem changing
        worse = [c["id"] for c in changes["changed"] if c["id"] not in accepted and c.get("was") == "warn"
                 and c.get("now") == "fail" and c["to"] > c["from"] and results[c["id"]]["is_finding"]]
        if new or again or worse:
            parts = [f"{len(new)} new finding{'s' if len(new) > 1 else ''}"] if new else []
            if worse:
                parts.append(f"{len(worse)} finding{'s' if len(worse) > 1 else ''} got worse")
            if again:
                parts.append(f"{len(again)} accepted finding{'s' if len(again) > 1 else ''} rose in severity")
            host.run("notify-send", "--app-name=DA Privacy Kit", "--icon=security-medium",
                     f"DA Privacy Kit: {', '.join(parts)}", "Open the app to see which.")
    new_items = (changes or {}).get("new_items") or {}
    if notify and new_items:                          # an inventory (what starts at login) has new entries
        # counts only, never the names: a notification daemon's history can keep them on the disk (Xfce's
        # notifyd logs to ~/.cache), and the lock screen can show them
        names = [i for items in new_items.values() for i in items]
        titles = ", ".join(cat[c].title.lower() for c in new_items if c in cat.checks)   # the inventory's own title
        host.run("notify-send", "--app-name=DA Privacy Kit", "--icon=security-medium",
                 f"DA Privacy Kit: {len(names)} new in {titles}",
                 f"{len(names)} new {'entry' if len(names) == 1 else 'entries'} since the last scan. Open the app to "
                 "see which: if you didn't add it, find out what it is.")
    return 1 if findings else 0


def schedule(mode: str) -> int:
    """A systemd user timer that runs `daprivacyscanner --scan --notify --quiet` daily or weekly,
    or removes it (off). Written under ~/.config/systemd/user; nothing needs root."""
    import shutil
    import subprocess
    from pathlib import Path

    unit_dir = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user"
    service, timer = unit_dir / f"{TIMER_UNIT}.service", unit_dir / f"{TIMER_UNIT}.timer"
    if not shutil.which("systemctl"):
        print("systemd's user manager isn't available here.", file=sys.stderr)
        return 2
    made_mark = "# Folders made for this timer, removed with it while empty: "
    try:                                           # the folders an earlier --schedule made, kept across a new one
        earlier = [ln[len(made_mark):].strip() for ln in timer.read_text().splitlines() if ln.startswith(made_mark)]
    except OSError:
        earlier = []
    if mode == "off":
        made = earlier
        subprocess.run(["systemctl", "--user", "disable", "--now", f"{TIMER_UNIT}.timer"], check=False, env=host_env())
        for p in (service, timer):
            p.unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False, env=host_env())
        from .fix import remove_made_dirs
        notes = remove_made_dirs([d for d in made if d.startswith(str(unit_dir.parent))])
        print("Scheduled scans are off." + "".join(f"\n{n}." for n in notes))
        return 0
    command = systemd_exec(scan_command() + ["--scan", "--notify", "--quiet"])
    wants = unit_dir / "timers.target.wants"
    had = {d for d in (unit_dir.parent, unit_dir, wants) if d.is_dir()}
    unit_dir.mkdir(parents=True, exist_ok=True)
    service.write_text("[Unit]\nDescription=DA Privacy Kit scan (read-only; notifies on new findings)\n\n"
                       f"[Service]\nType=oneshot\nExecStart={command}\nNice=10\n")
    timer.write_text(f"[Unit]\nDescription=Run a DA Privacy Kit scan {mode}\n\n[Timer]\nOnCalendar={mode}\n"
                     "Persistent=true\nRandomizedDelaySec=1h\n\n[Install]\nWantedBy=timers.target\n")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False, env=host_env())
    r = subprocess.run(["systemctl", "--user", "enable", "--now", f"{TIMER_UNIT}.timer"], check=False, env=host_env())
    made = list(dict.fromkeys(earlier + [str(d) for d in (unit_dir.parent, unit_dir, wants) if d.is_dir() and d not in had]))
    if made:                                       # so that --schedule off removes them again
        with timer.open("a") as f:
            f.write("".join(f"{made_mark}{d}\n" for d in made))
    if r.returncode != 0:
        print(f"The timer was written ({timer}) but couldn't be turned on: systemctl --user enable --now "
              f"{TIMER_UNIT}.timer failed (exit status {r.returncode}). Scans are not scheduled.", file=sys.stderr)
        return r.returncode
    print(f"Scans run {mode} ({timer}, turned on with systemctl --user enable --now {TIMER_UNIT}.timer). They change "
          "nothing, and a desktop notification appears only when something needs you: a new finding, one that got "
          "worse, a fix that was undone, or something new that starts at login. "
          "`daprivacyscanner --schedule off` removes the timer.")
    return 0


def online_cli(cat, ids: str, yes: bool) -> int:
    """Run online tests from the terminal, after listing who each contacts and asking."""
    from . import online
    from .checks.online import online_checks
    from .host import Host
    from .paths import PathResolver
    from .runner import Runner

    host = Host.local()
    try:
        settings = online.load_settings(PathResolver(host.home, host.environ).config_home)
    except online.SettingsError as e:
        print(e, file=sys.stderr)
        return 2
    impl = online_checks()
    wanted = [s for s in cat if s.scope.value == "online" and (ids == "default" and s.id in online.DEFAULT_ON
                                                                or ids == "all" or s.id in ids.split(","))]
    if not wanted:
        print(f"No online tests match {ids!r}. They are: {', '.join(impl)}", file=sys.stderr)
        return 2
    print("These online tests contact other machines. Each one sees your IP address.\n")
    proxies = online.proxy_vars(host.environ)
    if proxies:
        print(f"Your proxy settings ({', '.join(proxies)}) are not used: the tests connect directly, so the hosts "
              "listed see this computer's own address, not the proxy's.\n")
    for s in wanted:
        on, why = online.DEFAULTS_WHY.get(s.id, (False, ""))
        print(f"  {s.id}: {s.title}\n    contacts: {'; '.join(impl[s.id](s).hosts(settings)) or 'nobody'}"
              f"\n    {'in' if on else 'not in'} the default set: {why}")
        if s.id in online.WITH_ADMIN:
            print(f"    with administrator access (the app's Online tests, not this command): {online.WITH_ADMIN[s.id]}")
    if not yes:
        if input("\nRun them? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1
    print("\nRunning (without administrator access; the app can use it for the traffic test)...\n")
    report = Runner(cat, host, net=online.RealNet(), online=settings).scan_online([s.id for s in wanted])
    for cid, r in report.results.items():
        print(f"{cat[cid].title} ({cid}): {STATUS_WORD[r.status.value]} (severity {r.effective_severity}). {r.summary}")
        for e in r.evidence:
            print(f"    {e.label}: {e.value}" if e.value not in (None, "") else f"    {e.label}")
        for n in r.notes:
            print(f"    [{n.kind}] {n.title}: {n.text}")
        if r.is_finding:                            # what to do, as the report says it; the app's buttons are named
            print(f"    What to do: {' '.join(cat[cid].remedy.split())}")
        print()
    return 0


def install_helper_cli(uninstall: bool) -> int:
    from .privileged import HelperError, HelperUnavailable, install_helper

    print("Asking for administrator access…", flush=True)
    try:
        r = install_helper(uninstall)
    except (HelperUnavailable, HelperError) as e:
        print(f"Not {'removed' if uninstall else 'installed'}: {e}", file=sys.stderr)
        return 1
    if uninstall:
        print("Removed the helper and its polkit action. Changes it made are still recorded in "
              "/var/lib/daprivacyscanner/changes and can be reverted from the app.")
    else:
        print(f"Installed {r['installed']} and {r['policy']}: the password prompt now names DA Privacy Kit.")
    return 0


def export_cli(cat, path: str, redact: bool) -> int:
    """Everything the app keeps, to a file (0600: it describes this machine)."""
    from . import report
    from .history import Accepted, LastReport
    from .host import Host
    from .paths import PathResolver
    from .undo import UndoLog

    host = Host.local()
    paths = PathResolver(host.home, host.environ)
    last = LastReport(paths).load(set(cat.checks))
    text = report.export_all(last, cat, UndoLog.for_user(paths).entries(), Accepted(paths).all(),
                             "json" if path.endswith(".json") else "text", host, redact)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")
    print(f"Written to {path}" + (" (redacted)" if redact else "") + ".")
    return 0


def verify_cli(path: str, keys: list[str], checksum: str) -> int:
    """Verify a download from the terminal. Exit status: 0 verified, 1 anything less, 2 couldn't."""
    from .host import Host
    from .tools import verify as V
    from .tools.keys import DataError
    from .tools.pick import PathRefused, checked

    host = Host.local()
    try:
        target = checked(os.path.abspath(path) if not path.startswith("~") else path, host.home)
        key_files = [checked(os.path.abspath(k), host.home) for k in keys]
        v = V.verify(host, target, key_files, checksum, given=True)
    except (PathRefused, DataError, OSError) as e:
        print(e, file=sys.stderr)
        return 2
    print(v.text_report())
    return 0 if v.level == "verified" else 1


def box_cli(slug: str) -> int:
    """`--box NAME`: what a Box's menu entry runs. Starts the Box's app in its sandbox, stays until it has ended
    and records the run in numbers. No window of the app's own; a problem is said in a dialog."""
    from .host import Host
    from .tools import box, sandbox, trial
    host = Host.local()
    try:
        b = box.read(host, slug)
        if b is None:
            return show_error(f"There is no Box named {slug} here (or its settings can't be read). Set it up in DA "
                              "Privacy Kit: Tools → A Box for an app.")
        box.run_to_end(host, b)
    except (trial.TrialError, sandbox.SandboxError) as e:
        return show_error(str(e))
    except OSError as e:
        return show_error(f"The Box couldn't be started: {e.strerror or type(e).__name__}.")
    return 0


def outbox_cli() -> int:
    """What the Outbox's user unit runs: clean what is waiting in ~/Outbox, then say so. Its output goes to the
    journal, which most distributions keep on the disk: counts only there, as in its notification, never the names
    of the files the user is about to share. A terminal gets the names (someone ran it by hand)."""
    from .host import Host
    from .tools import metadata

    host = Host.local()
    tty = sys.stdout.isatty()
    try:
        run = metadata.run_outbox_settled(host)    # stays until what just landed has settled and is cleaned
    except Exception as e:  # noqa: BLE001 - its kind only: an error about a file names it (a path)
        if sys.stderr.isatty():
            raise
        print(f"The Outbox couldn't be emptied: {type(e).__name__}", file=sys.stderr)
        return 1
    metadata.notify_outbox(host, run)
    if tty:
        for name in run.cleaned:
            print(f"cleaned: {name}")
        for name, why in run.not_cleaned:
            print(f"not cleaned: {name} ({why})")
    elif run.cleaned or run.not_cleaned:
        print(f"Outbox: {len(run.cleaned)} cleaned, {len(run.not_cleaned)} not cleaned.")
    return 0


def _presentation_off() -> None:
    """Presentation mode is for while the app runs: quitting puts the settings back."""
    from .host import Host
    from .tools import presentation
    try:
        host = Host.local()
        if presentation.is_on(host):
            presentation.turn_off(host)
    except Exception as e:  # noqa: BLE001 - the page says it is still on next time
        print(f"Presentation mode couldn't be turned off: {e}", file=sys.stderr)


def desktop_id() -> str:
    """The name the window identifies itself by (X11 WM_CLASS, Wayland app_id). Desktops find the
    window's icon by matching it to an installed .desktop file: KWin on Wayland only by exact file
    name, and a window that matches none gets the generic Wayland icon. AppImage integrators
    (AppImageLauncher, Gear Lever, ...) install our daprivacyscanner.desktop under a name of their
    own, so when running from an AppImage, use the name of the installed entry that launches this
    AppImage; otherwise "daprivacyscanner". As DAToolkit does."""
    appimage = os.environ.get("APPIMAGE")
    if not appimage:
        return "daprivacyscanner"
    target = os.path.realpath(appimage)
    data_home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    dirs = [data_home] + (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":")
    for base in dict.fromkeys(d for d in dirs if d):
        apps = Path(base) / "applications"
        try:
            entries = sorted(apps.rglob("*.desktop"))
        except OSError:
            continue
        for f in entries:
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if key == "TryExec" and value:
                    program = value                       # a plain path
                elif key == "Exec" and value:
                    try:
                        program = shlex.split(value)[0]   # a command line, the path maybe quoted
                    except (ValueError, IndexError):
                        continue
                else:
                    continue
                if os.path.realpath(os.path.expanduser(program)) == target:
                    # a desktop-file id: the path under applications/, with "/" as "-"
                    return str(f.relative_to(apps))[:-len(".desktop")].replace("/", "-")
    return "daprivacyscanner"


def window_icon() -> str | None:
    """The icon file for the window itself (X11 shows it; Wayland takes the desktop entry's)."""
    appdir = os.environ.get("APPDIR")
    for path in ([Path(appdir) / "daprivacyscanner.png"] if appdir else []) + [Path(__file__).parent / "web" / "icon.svg"]:
        if not path.is_file():
            continue
        try:
            import gi
            gi.require_version("GdkPixbuf", "2.0")
            from gi.repository import GdkPixbuf
            GdkPixbuf.Pixbuf.new_from_file(str(path))    # GTK would refuse a file it can't load
            return str(path)
        except Exception:  # noqa: BLE001 - no loader for it: try the next, or go without
            continue
    return None


def no_core_dumps() -> None:
    """Nothing the app holds reaches a crash dump, nor the journal's record of one: it and WebKit's processes hold what
    the page shows (downloads' names, where a photo was taken, deleted files' names), and the programs it starts (mat2,
    a viewer, the file chooser) the user's files. A core size limit of 1 makes the kernel skip the dump altogether
    (sandbox.NO_CORE: at 0, systemd-coredump still wrote the command line, the environment and the open files' paths
    into the journal, tested); memory is left out too, where the limit can't be raised (coredump_filter 0). Both are
    inherited by every program the app starts."""
    import resource
    try:
        with open("/proc/self/coredump_filter", "w") as f:
            f.write("0")
    except OSError:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (1, 1))
    except (ValueError, OSError):
        pass


def quiet_tracebacks() -> None:
    """When stderr isn't a terminal (a unit, a timer, a menu entry, a file manager's right-click entry), an error
    nothing caught is said by its kind only: stderr is then the journal or ~/.xsession-errors, kept on the disk, and
    a traceback's values and messages can name a file, a finding or a host (as the server does for its routes)."""
    import threading as _threading

    def hook(kind, value, tb):
        if issubclass(kind, KeyboardInterrupt):
            return
        print(f"DA Privacy Kit stopped on an error it didn't expect ({kind.__name__}).", file=sys.stderr)

    sys.excepthook = hook
    _threading.excepthook = lambda a: hook(a.exc_type, a.exc_value, a.exc_traceback) \
        if a.exc_type is not SystemExit else None


def main(argv: list[str] | None = None) -> None:
    no_core_dumps()
    if not sys.stderr.isatty():
        quiet_tracebacks()
    ap = argparse.ArgumentParser(
        prog="daprivacyscanner", description="Linux privacy auditor",
        epilog="Without options, the app's window opens: that is how it is meant to be used. The options here are for "
               "testing, and for what the app itself sets up (scheduled scans, the file manager's right-click "
               "entries, the Outbox). Fixes are applied and reverted only in the window.")
    ap.add_argument("--browser", action="store_true", help="open in the default web browser instead of the app window")
    ap.add_argument("--no-open", action="store_true", help="with the browser: only print the URL")
    ap.add_argument("--port", type=int, default=0, help="port to listen on (default: random)")
    ap.add_argument("--dev", action="store_true", help="show detection hints, unverified notes and timings in the app")
    ap.add_argument("--scan", action="store_true", help="scan from the terminal (no window) and print the report; "
                    "exit status 1 when there are findings")
    ap.add_argument("--json", action="store_true", help="with --scan: print the report as JSON")
    ap.add_argument("--redact", action="store_true", help="with --scan: redact names, hosts and addresses in the report")
    ap.add_argument("--admin", action="store_true", help="with --scan: ask for administrator access (polkit) first")
    ap.add_argument("--notify", action="store_true", help="with --scan: a desktop notification when findings are new or worse")
    ap.add_argument("--quiet", action="store_true", help="with --scan: print nothing (for timers)")
    ap.add_argument("--schedule", choices=["daily", "weekly", "off"],
                    help="run a scan daily or weekly with a systemd user timer, notifying on new or worse findings")
    ap.add_argument("--capture", metavar="DIR", help="write sanitised samples of the commands the parsers read into DIR, "
                    "to contribute as test fixtures")
    ap.add_argument("--export", metavar="FILE", help="write everything the app keeps (the last report, accepted findings "
                    "and every change made, with how to undo it) to FILE, as JSON if it ends in .json; --redact applies")
    ap.add_argument("--install-helper", action="store_true", help="install this version's administrator helper "
                    "root-owned, with its polkit action (asks for your password)")
    ap.add_argument("--uninstall-helper", action="store_true", help="remove the installed administrator helper")
    ap.add_argument("--dry-run", metavar="CHECK", nargs="?", const="all",
                    help="print what the fix for CHECK (or every fixable check; 'easy': the Easy fixes) would do, "
                         "change nothing, and exit")
    ap.add_argument("--online", metavar="TESTS", nargs="?", const="default",
                    help="run online tests from the terminal: 'default', 'all' or comma-separated ids "
                         "(lists who each contacts and asks first)")
    ap.add_argument("--yes", action="store_true", help="with --online: don't ask before running")
    ap.add_argument("--verify", metavar="FILE", help="Verify a download: is FILE the one its makers published? Uses the "
                    "signature or checksum list next to it; exit status 0 when verified")
    ap.add_argument("--key", metavar="KEYFILE", action="append", default=[],
                    help="with --verify: a public key file to check the signature with (repeatable)")
    ap.add_argument("--checksum", metavar="HEX", default="", help="with --verify: a checksum from the download page")
    ap.add_argument("--tool", nargs="+", metavar=("TOOL", "FILE"),
                    help="open the app on a tool (verify or metadata) with these files, as the file managers' "
                         "right-click entries do")
    ap.add_argument("--outbox", action="store_true", help="clean the files waiting in ~/Outbox (its user unit runs this)")
    ap.add_argument("--box", metavar="NAME", help="start the app kept in the Box NAME (its menu entry runs this)")
    ap.add_argument("--probe", metavar="ADDRESS", help="from another machine: which TCP ports of ADDRESS answer")
    ap.add_argument("--ports", help="with --probe: comma-separated ports or ranges")
    args = ap.parse_args(argv)

    if args.probe:
        from . import probe
        raise SystemExit(probe.main([args.probe] + (["--ports", args.ports] if args.ports else [])))

    if os.geteuid() == 0:
        raise SystemExit("Run DA Privacy Kit as your normal user, not as root. "
                         "It asks for administrator access only for the specific checks that need it.")

    if args.schedule:
        raise SystemExit(schedule(args.schedule))
    if args.install_helper or args.uninstall_helper:
        raise SystemExit(install_helper_cli(args.uninstall_helper))

    try:
        cat = catalogue.load()
    except catalogue.CatalogueError as e:
        raise SystemExit(str(e))

    if args.capture:
        from pathlib import Path

        from . import capture
        from .host import Host

        print(f"Capturing sanitised samples into {args.capture}:")
        capture.capture(Host.local(), Path(args.capture))
        raise SystemExit(0)
    if args.dry_run:
        raise SystemExit(dry_run(cat, args.dry_run))
    if args.export:
        raise SystemExit(export_cli(cat, args.export, args.redact))
    if args.scan:
        raise SystemExit(scan_cli(cat, args.json, args.notify, args.admin, args.quiet, args.redact))
    if args.online:
        raise SystemExit(online_cli(cat, args.online, args.yes))
    if args.verify:
        raise SystemExit(verify_cli(args.verify, args.key, args.checksum))
    if args.outbox:
        raise SystemExit(outbox_cli())
    if args.box:
        raise SystemExit(box_cli(args.box))
    open_tool = None
    if args.tool:
        if args.tool[0] not in ("verify", "metadata"):
            raise SystemExit(f"No tool {args.tool[0]!r}: verify or metadata.")
        open_tool = {"tool": args.tool[0], "paths": [os.path.abspath(p) for p in args.tool[1:] if p]}

    use_browser = args.browser or args.no_open
    if not use_browser:
        problem = window_problem()
        if problem:
            raise SystemExit(refuse_without_window(problem))

    from .privileged import STALE_HELPER, installed_helper, installed_helper_stale

    if installed_helper() is None:
        print(HELPER_NOTE, file=sys.stderr)
    elif installed_helper_stale():
        print(STALE_HELPER, file=sys.stderr)

    token = secrets.token_urlsafe(32)              # the session (cookie) token: never leaves the process
    launch = secrets.token_urlsafe(32)             # in the URL once; exchanged for the cookie, then forgotten
    port = args.port or _free_port()
    windows: list = []                         # the app window, once made: its file dialog serves the tools

    def window_pick(kind: str, multiple: bool, start: str):
        if not windows:
            return None
        import webview
        kind_ = webview.FileDialog.FOLDER if kind == "folder" else webview.FileDialog.OPEN
        return list(windows[0].create_file_dialog(kind_, directory=start, allow_multiple=multiple) or [])

    app = create_app(token, cat, on_quit=(lambda: setattr(server, "should_exit", True)) if use_browser else None,
                     launch_token=launch, allowed_hosts={f"127.0.0.1:{port}", f"localhost:{port}"},
                     dev=args.dev or os.environ.get("DAPRIVACYSCANNER_DEV") == "1",
                     pick=None if use_browser else window_pick, open_tool=open_tool, watch_outbox=True)
    # no WebSockets: the page only makes plain requests, and uvicorn's auto-detection can pick
    # up an incompatible system copy of the websockets package
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", ws="none"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        if not thread.is_alive():
            raise SystemExit("Server failed to start.")
        time.sleep(0.05)

    url = f"http://127.0.0.1:{port}/?t={launch}"
    try:
        if use_browser:
            print(f"DA Privacy Kit running in your web browser. {BROWSER_EXPOSES}\n"
                  f"Open this link once (it works a single time):\n{url}", flush=True)
            if not args.no_open:
                import webbrowser

                from .hostenv import as_host

                with as_host():                 # the browser gets the host's environment, not the AppImage's
                    webbrowser.open(url)
            while thread.is_alive():  # until Quit in the page, or Ctrl+C
                thread.join(0.5)
        else:
            import webview
            from gi.repository import GLib

            # the window's class, which desktops match to the .desktop file (and its icon)
            GLib.set_prgname(desktop_id())
            GLib.set_application_name("DA Privacy Kit")
            webview.settings["ALLOW_DOWNLOADS"] = True       # the report export
            window = webview.create_window("DA Privacy Kit", url, width=1480, height=940, min_size=(900, 600))
            windows.append(window)

            def on_started():
                def close(*_):
                    window.destroy()
                    return False

                def no_recent_files():
                    # GTK's file chooser adds every file chosen to the desktop's recent files list on the disk
                    # (tested): never for the tools' files. The app's own setting outranks the desktop's.
                    from gi.repository import Gtk
                    settings = Gtk.Settings.get_default()
                    if settings is not None:
                        settings.set_property("gtk-recent-files-enabled", False)
                    return False

                GLib.idle_add(no_recent_files)

                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, close)

            webview.start(on_started, gui="gtk", private_mode=True, icon=window_icon())
    except KeyboardInterrupt:
        pass
    finally:
        app.state.close_browser_disk()  # the browser's RAM disk is for while the app runs
        app.state.admin.drop()          # the root helper ends with the app
        _presentation_off()             # and so does Presentation mode
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
