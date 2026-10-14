"""Presentation mode (docs/TECHNICAL.md, Tools): before sharing the screen, notification banners and clipboard
history are turned off together, and put back together afterwards.

What it changes, on this desktop:

- GNOME: org.gnome.desktop.notifications show-banners (Do Not Disturb); clipboard-history
  extensions are added to org.gnome.shell disabled-extensions; GPaste stops tracking
  (org.gnome.GPaste track-changes).
- Cinnamon: org.cinnamon.desktop.notifications display-notifications.
- KDE Plasma: Do Not Disturb through the notification server's own Inhibit call on D-Bus, held by
  this process: it ends when Presentation mode is turned off, and by itself if the app stops. Klipper
  (Plasma's clipboard history, which records what is copied whether or not it is shown) is turned off
  for the duration through Plasma 6's system tray (PlasmaTraySet, the clipboard fix's step) and on
  again afterwards; where that isn't possible (Plasma 5, a Clipboard widget of its own, Plasma not
  running) a note says it keeps recording.
- Xfce: xfce4-notifyd's /do-not-disturb (xfconf).
- CopyQ, wherever it runs: `copyq disable` (it stops storing what is copied), `copyq enable` after.

Each change is a reversible action of fix.py's kind, recording the value before and after; the
records are kept in a state file of their own ($XDG_STATE_HOME/daprivacyscanner/presentation.json,
0600) only while it is on, so a crash or a reboot still leaves a way back (the page shows it is
still on, and says when KDE's Do Not Disturb, which ended with the process that held it, needs
taking up again: renew). It isn't a fix: nothing goes in History. Turning it off puts each value back unless the
user changed it meanwhile (theirs is kept, and said so); quitting the app turns it off."""

from __future__ import annotations

import json
import os
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..desktop import GNOME, DesktopInfo, detect_desktop
from ..fix import ACTION_KINDS, Action, FixContext, FixError, GSettingsSet, RevertResult, action, shell
from ..host import Host
from ..paths import PathResolver

# GNOME Shell extensions that keep a clipboard history and show it in a panel menu.
# VERIFY: the UUIDs on extensions.gnome.org (Clipboard Indicator, Pano, Clipboard History).
CLIPBOARD_EXTENSIONS = {"clipboard-indicator@tudmotu.com": "Clipboard Indicator", "pano@elhan.io": "Pano",
                        "clipboard-history@alexsaveau.dev": "Clipboard History"}
XFCE_DND = ["xfconf-query", "-c", "xfce4-notifyd", "-p", "/do-not-disturb"]


# ------------------------------------------------------------------ actions of its own

@action
class CommandSetting(Action):
    """A setting read and written through a program (xfconf-query, copyq): `get` prints the value
    ("" when it isn't set); `set` maps each value to the command that sets it ("" resets it).
    VERIFY: xfconf-query's output for a bool, CopyQ's `monitoring` output, on real systems."""
    kind = "cmdsetting"

    def __init__(self, label: str, get: list[str], set_: dict[str, list[str]], value: str):
        self.label, self.get, self.set, self.value = label, get, set_, value

    def describe(self) -> str:
        return shell(self.set[self.value])

    @staticmethod
    def _read(host: Host, get: list[str]) -> str:
        r = host.run(*get)
        return r.stdout.strip().lower() if r.ok else ""

    def apply(self, ctx: FixContext) -> dict:
        before = self._read(ctx.host, self.get)
        r = ctx.host.run(*self.set[self.value])
        if not r.ok:
            raise FixError(f"{shell(self.set[self.value])} failed: {(r.stderr or r.stdout).strip()[:200]}")
        return {"kind": self.kind, "label": self.label, "get": self.get, "set": self.set, "before": before,
                "after": self.value, "text": f"{self.label}: {before or '(not set)'} → {self.value}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(record["set"][record["after"]])] if record["after"] in record.get("set", {}) else []

    @staticmethod
    def undo_hint(record: dict) -> str:
        argv = record["set"].get(record["before"]) or record["set"].get("")
        return " ".join(shlex.quote(a) for a in argv) if argv else ""

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        now = CommandSetting._read(ctx.host, record["get"])
        if now != record["after"] and not force:
            return RevertResult(False, f"{record['label']} has changed since (now {now or 'not set'})", True)
        argv = record["set"].get(record["before"]) or record["set"].get("")
        if not argv:
            return RevertResult(False, f"{record['label']} can't be put back to {record['before'] or 'not set'}")
        r = ctx.host.run(*argv)
        if not r.ok:
            return RevertResult(False, f"{record['label']} couldn't be put back: {(r.stderr or r.stdout).strip()[:200]}")
        return RevertResult(True, f"{record['label']} back to {record['before'] or 'not set'}")


class Inhibitor(Protocol):
    def inhibit(self, reason: str) -> int: ...
    def release(self, cookie: int) -> None: ...
    def holds(self, cookie: int) -> bool: ...


class GioInhibitor:
    """KDE Plasma's notification server: Inhibit(desktop_entry, reason, hints) -> cookie turns Do Not
    Disturb on for as long as the caller's D-Bus connection lives (or until UnInhibit). The
    connection is kept here, so it lasts while the app runs. VERIFY on Plasma 5 and 6: that
    popups stay hidden and the applet shows the reason."""

    def __init__(self):
        self.bus = None
        self.held: set[int] = set()         # cookies this process holds: a crash or restart ends the rest

    def _call(self, method: str, args):
        from gi.repository import Gio, GLib
        if self.bus is None:
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        return self.bus.call_sync("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                                  "org.freedesktop.Notifications", method, GLib.Variant(*args) if args else None,
                                  None, Gio.DBusCallFlags.NONE, 5000, None)

    def inhibit(self, reason: str) -> int:
        cookie = int(self._call("Inhibit", ("(ssa{sv})", ("daprivacyscanner", reason, {}))).unpack()[0])
        self.held.add(cookie)
        return cookie

    def release(self, cookie: int) -> None:
        self.held.discard(cookie)
        self._call("UnInhibit", ("(u)", (cookie,)))

    def holds(self, cookie: int) -> bool:
        return cookie in self.held


INHIBITOR: Inhibitor = GioInhibitor()


@action
class NotificationInhibit(Action):
    kind = "notify-inhibit"

    def describe(self) -> str:
        return "Do Not Disturb, held by the app (org.freedesktop.Notifications Inhibit)"

    def apply(self, ctx: FixContext) -> dict:
        try:
            cookie = INHIBITOR.inhibit("Presentation mode")
        except Exception as e:  # noqa: BLE001 - D-Bus errors come in several types
            raise FixError(f"The notification server didn't accept Do Not Disturb: {e}") from None
        return {"kind": self.kind, "cookie": cookie, "text": "Do Not Disturb (held by the app)"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        return "It ends by itself when DA Privacy Kit stops."

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        try:
            INHIBITOR.release(int(record["cookie"]))
        except Exception:  # noqa: BLE001 - after a restart the server has forgotten it already
            pass
        return RevertResult(True, "Do Not Disturb ended")


# ------------------------------------------------------------------ what it would change here

@dataclass
class Plan:
    desktop: str
    changes: list[tuple[str, Action]] = field(default_factory=list)       # (what, in words; the action)
    notes: list[str] = field(default_factory=list)


def _gvariant_list(items: list[str]) -> str:
    return "[" + ", ".join("'" + x.replace("\\", "\\\\").replace("'", "\\'") + "'" for x in items) + "]" \
        if items else "@as []"


def _klipper(host: Host, info: DesktopInfo, p: Plan) -> None:
    """Klipper records every copy as it is made, shown or not: on Plasma 6 its system-tray entry is turned off
    through plasmashell's own scripting (as the clipboard fix does), which stops it at once, and turned on again
    when Presentation mode ends. What it kept before stays. Where the app can't reach it, the note says so."""
    from ..checks._util import processes
    from ..checks.desktop import KLIPPER_APPLET
    from ..desktop import APPLETSRC, KDE, tray_script
    from ..fix import PlasmaTraySet
    paths = PathResolver(host.home, host.environ)
    kde = KDE(host, paths, info)
    applet = kde.applet(KLIPPER_APPLET)
    if not applet.on:
        return
    if (kde.major or 0) >= 6 and applet.trays and not applet.widget and "plasmashell" in processes(host):
        tray = {state: kde.dbus("org.kde.plasmashell", "/PlasmaShell", "org.kde.PlasmaShell.evaluateScript",
                                tray_script(KLIPPER_APPLET, state == "on", applet.trays)) for state in ("on", "off")}
        if None not in tray.values():
            p.changes.append(("Klipper (Plasma's clipboard history) turned off; on again afterwards",
                              PlasmaTraySet(KLIPPER_APPLET, "Clipboard (Klipper)", paths.config_home / APPLETSRC,
                                            list(applet.trays), tray, "off")))
            p.notes.append("What Klipper kept before stays, hidden while it is off: clear it from its menu first if you "
                           "might open it while sharing.")
            return
    p.notes.append("Klipper (Plasma's clipboard history) keeps recording what you copy: the app can only turn it off "
                   "through Plasma 6's system tray while Plasma runs"
                   + (" (a Clipboard widget of its own is out of its reach)" if applet.widget else "")
                   + ". Don't copy anything you wouldn't show, and clear its history from its menu afterwards.")


def plan(host: Host, info: DesktopInfo | None = None) -> Plan:
    """What turning it on would change on this desktop now. Changes nothing."""
    info = info or detect_desktop(host)
    gnome = GNOME(host, info)
    p = Plan(info.label)
    banners = False
    if info.is_gnome:
        if gnome.gsettings("org.gnome.desktop.notifications", "show-banners") is True:
            p.changes.append(("Notification banners off (Do Not Disturb)",
                              GSettingsSet("org.gnome.desktop.notifications", "show-banners", "false")))
        banners = True
        enabled = gnome.gsettings("org.gnome.shell", "enabled-extensions") or []
        disabled = gnome.gsettings("org.gnome.shell", "disabled-extensions") or []
        clip = [u for u in CLIPBOARD_EXTENSIONS if u in enabled and u not in disabled]
        if clip:
            names = ", ".join(CLIPBOARD_EXTENSIONS[u] for u in clip)
            p.changes.append((f"{names} turned off (its clipboard history menu disappears)",
                              GSettingsSet("org.gnome.shell", "disabled-extensions", _gvariant_list(disabled + clip))))
    if "x-cinnamon" in info.names or "cinnamon" in info.names:
        if gnome.gsettings("org.cinnamon.desktop.notifications", "display-notifications") is True:
            p.changes.append(("Notification banners off",
                              GSettingsSet("org.cinnamon.desktop.notifications", "display-notifications", "false")))
        banners = True
    if info.is_kde:
        p.changes.append(("Do Not Disturb on", NotificationInhibit()))
        banners = True
        _klipper(host, info, p)
    if "xfce" in info.names:
        r = host.run(*XFCE_DND)
        if not (r.ok and r.stdout.strip().lower() == "true"):
            p.changes.append(("Do Not Disturb on", CommandSetting(
                "Xfce Do Not Disturb", XFCE_DND, {"true": XFCE_DND + ["--create", "-t", "bool", "-s", "true"],
                                                  "false": XFCE_DND + ["-s", "false"], "": XFCE_DND + ["-r"]}, "true")))
        banners = True
    if gnome.gsettings("org.gnome.GPaste", "track-changes") is True:      # VERIFY: GPaste's key on GPaste 45
        p.changes.append(("GPaste stops recording what you copy",
                          GSettingsSet("org.gnome.GPaste", "track-changes", "false")))
    if host.runner.which("copyq"):
        r = host.run("copyq", "monitoring", timeout=3)
        if r.ok and r.stdout.strip().lower() == "true":
            p.changes.append(("CopyQ stops recording what you copy", CommandSetting(
                "CopyQ clipboard monitoring", ["copyq", "monitoring"],
                {"false": ["copyq", "disable"], "true": ["copyq", "enable"]}, "false")))
    if not banners:
        p.notes.append(f"The app can't turn notification banners off on this desktop ({info.label}): GNOME, Cinnamon, "
                       "KDE Plasma and Xfce are the ones it knows. Use the desktop's own Do Not Disturb.")
    p.notes.append("Programs that show messages inside their own window (a chat app's preview, an email client's "
                   "list) aren't covered: close or minimise them before sharing.")
    return p


# ------------------------------------------------------------------ on and off

def state_file(host: Host) -> Path:
    return PathResolver(host.home, host.environ).state_home / "daprivacyscanner" / "presentation.json"


def _load(host: Host) -> dict | None:
    try:
        data = json.loads(state_file(host).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("records"), list) else None


def _save(host: Host, data: dict) -> None:
    f = state_file(host)
    f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = f.with_suffix(".tmp")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
        json.dump(data, out, indent=1)
    os.replace(tmp, f)


def _ctx(host: Host) -> FixContext:
    return FixContext(host, state_file(host).parent / "presentation-backups")       # no action here writes backups


def _lapsed(recs: list[dict]) -> list[dict]:
    """KDE's Do Not Disturb records whose hold ended: it lives only as long as the process that
    asked for it, so after a crash or a restart the state file says on while notifications are back."""
    out = []
    for r in recs:
        if r.get("kind") == NotificationInhibit.kind:
            try:
                held = INHIBITOR.holds(int(r["cookie"]))
            except (KeyError, TypeError, ValueError):
                held = False
            if not held:
                out.append(r)
    return out


def status(host: Host) -> dict:
    """{"on", "since", "changed": what it changed (while on), "plan": what it would change (when
    off), "undo": how to put each back by hand, "notes", "lapsed": what it turned on that has
    ended by itself since (KDE's Do Not Disturb after the app stopped)}."""
    data = _load(host)
    if data is not None:
        recs = data["records"]
        lapsed = [r.get("what", r.get("text", "")) for r in _lapsed(recs)]
        notes = ["Do Not Disturb ended when the app stopped (it lasts only while the app runs), so notifications show "
                 "again although Presentation mode is on. Turn it on again before you share your screen."] if lapsed else []
        return {"on": True, "since": data.get("since"), "changed": [r.get("what", r.get("text", "")) for r in recs],
                "ran": [c for r in recs for c in ACTION_KINDS[r["kind"]].ran(r)],    # the commands it ran, to learn from
                "undo": [h for r in recs if (h := ACTION_KINDS[r["kind"]].undo_hint(r))], "plan": [], "notes": notes,
                "desktop": data.get("desktop", ""), "lapsed": lapsed}
    p = plan(host)
    return {"on": False, "since": None, "changed": [], "ran": [], "undo": [], "desktop": p.desktop,
            "plan": [{"what": what, "text": a.describe()} for what, a in p.changes], "notes": p.notes, "lapsed": []}


class AlreadyOn(Exception):
    pass


def turn_on(host: Host) -> dict:
    """Applies every change of the plan; if one fails, those already made are put back and the
    error is raised (FixError)."""
    if _load(host) is not None:
        raise AlreadyOn("Presentation mode is already on.")
    p = plan(host)
    ctx, records = _ctx(host), []
    try:
        for what, a in p.changes:
            rec = a.apply(ctx)
            rec["what"] = what
            records.append(rec)
            _save(host, {"since": time.time(), "desktop": p.desktop, "records": records})   # kept as it goes
    except Exception as e:
        for rec in reversed(records):
            ACTION_KINDS[rec["kind"]].revert(rec, ctx, force=True)
        state_file(host).unlink(missing_ok=True)
        raise e if isinstance(e, FixError) else FixError(f"{type(e).__name__}: {e}") from None
    if not records:
        _save(host, {"since": time.time(), "desktop": p.desktop, "records": []})
    return status(host)


def renew(host: Host) -> dict:
    """Takes up again what ended by itself while Presentation mode stayed on (KDE's Do Not Disturb,
    after the app stopped). Raises FixError if the notification server refuses."""
    data = _load(host)
    if data is None:
        return status(host)
    for rec in _lapsed(data["records"]):
        try:
            rec["cookie"] = INHIBITOR.inhibit("Presentation mode")
        except Exception as e:  # noqa: BLE001 - D-Bus errors come in several types
            raise FixError(f"The notification server didn't accept Do Not Disturb: {e}") from None
    _save(host, data)
    return status(host)


def turn_off(host: Host) -> dict:
    """Puts back what it changed. A setting the user changed meanwhile keeps their value (said in
    `kept`). What couldn't be put back (`failed`) stays in the state file, so it is still shown as
    on and can be tried again; the rest is forgotten."""
    data = _load(host)
    if data is None:
        return {**status(host), "messages": [], "kept": [], "failed": []}
    ctx, messages, kept, failed, left = _ctx(host), [], [], [], []
    for rec in reversed(data["records"]):
        try:
            res = ACTION_KINDS[rec["kind"]].revert(rec, ctx, force=False)
        except Exception as e:  # noqa: BLE001 - one failing doesn't stop the others
            res = RevertResult(False, str(e) if isinstance(e, FixError) else f"{type(e).__name__}: {e}")
        if res.ok:
            messages.append(res.message)
        elif res.conflict:
            kept.append(res.message)
        else:
            failed.append(res.message)
            left.insert(0, rec)
    if left:
        _save(host, {**data, "records": left})
    else:
        state_file(host).unlink(missing_ok=True)
    return {**status(host), "messages": messages, "kept": kept, "failed": failed}


def is_on(host: Host) -> bool:
    return _load(host) is not None
