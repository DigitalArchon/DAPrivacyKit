"""Fixes: a plan of actions shown to the user first (the dry run), applied after one
confirmation, and recorded in the undo log so every reversible change can be reverted from the UI.

Rules (docs/TECHNICAL.md, design rules 5 to 8):
- Every setting is read before it is changed; the undo record keeps the value before and after.
  A revert only puts the old value back if the setting still has the value the fix gave it,
  so a later change by the user is never silently overwritten (unless they force it).
- Deleting caches and history is the exception: it can't be undone, the plan says so, and the
  user confirms it separately. Deleted paths are not written to the log (that would keep the
  very history being removed); only how many files and from where.
- Plain unlink only: no shred or overwrite. Encryption is what protects deleted data.
- Reversible actions come first and deletions last, so a failure part-way can roll back fully.
- Root changes go through the privileged helper, which journals what was there before on its
  side; the undo record here only keeps the helper's change id (RootChange).
"""

from __future__ import annotations

import contextvars
import errno
import hashlib
import json
import os
import re
import shlex
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, ClassVar

from .host import Host

if TYPE_CHECKING:
    from .undo import UndoLog


class FixError(Exception):
    """A step that failed. `record`: the undo record of what it changed before failing (a root change the helper
    journalled part way), which apply_plan keeps with the attempt and puts back like the steps before it."""

    def __init__(self, message: str = "", record: dict | None = None, data: dict | None = None):
        super().__init__(message)
        self.record = record
        self.data = dict(data or {})


@dataclass
class FixContext:
    host: Host
    backups: Path                       # where this entry's file backups go


@dataclass
class RevertResult:
    ok: bool
    message: str = ""
    conflict: bool = False
    ran: list[str] = field(default_factory=list)        # what putting it back ran as root (the helper's answer)


CHANGED_LINES = 40                                      # lines of a file's change shown, the rest counted


def made_dirs(path: Path) -> list[str]:
    """The folders on the way to `path` that aren't there yet, outermost first: what writing it makes,
    and what reverting removes again (remove_made_dirs)."""
    out, d = [], path.parent
    while d != d.parent and not os.path.lexists(d):
        out.append(str(d))
        d = d.parent
    return out[::-1]


def _shown(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + "/") else path


def remove_made_dirs(dirs: list[str]) -> list[str]:
    """The folders a fix made, removed again deepest first, each only while it is empty: one that holds
    anything added since stays, with everything in it, and the note says what (a folder that has become a
    link or a file is left alone too). Returns the notes, for the revert's message."""
    notes, kept = [], []
    for d in sorted(dict.fromkeys(dirs), key=lambda x: x.count("/"), reverse=True):
        if any(k.startswith(d + "/") for k in kept):
            kept.append(d)                                  # holds a folder that stays: said once, for that one
            continue
        try:
            st = os.lstat(d)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            notes.append(f"{_shown(d)} was left as it is: it isn't the folder this fix made any more")
            kept.append(d)
            continue
        try:
            os.rmdir(d)
            did(shell(["rmdir", d]))
        except OSError as e:
            kept.append(d)
            if e.errno in (errno.ENOTEMPTY, errno.EEXIST):
                try:
                    names = sorted(os.listdir(d))
                except OSError:
                    names = []
                listed = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
                notes.append(f"{_shown(d)} was left, with what is in it: this fix made it, but it now holds what was "
                             f"added since ({listed})")
            else:
                notes.append(f"{_shown(d)} was left: {e.strerror}")
    return notes


def _with_notes(message: str, notes: list[str]) -> str:
    return message + (". " + "; ".join(notes) if notes else "")


def changed_lines(old: str | None, new: str) -> list[str]:
    """What writing `new` over `old` changes, line by line: "+ line" added, "- line" removed (a diff
    without context), at most CHANGED_LINES of them."""
    import difflib
    out = [f"{ln[0]} {ln[1:]}"[:300] for ln in difflib.unified_diff((old or "").splitlines(), new.splitlines(),
                                                                       lineterm="", n=0)
           if not ln.startswith(("+++", "---", "@@"))]
    if len(out) > CHANGED_LINES:
        out = out[:CHANGED_LINES] + [f"… and {len(out) - CHANGED_LINES} more changed lines"]
    return out


# ------------------------------------------------------------------ actions

class Action:
    kind: ClassVar[str]
    reversible: ClassVar[bool] = True
    destructive: ClassVar[bool] = False         # deletes data: confirmed separately, can't be undone
    needs_root: ClassVar[bool] = False          # goes through the privileged helper
    # order in a plan: 0 settings, 1 commands before deleting (stop a daemon), 2 deletions,
    # 3 commands after (start it again)
    phase: int = 0

    def describe(self) -> str:
        """One line of the dry run: exactly what apply() does."""
        raise NotImplementedError

    def commands(self) -> list[str]:
        """The commands apply() runs besides the one describe() shows (the restarts a root change sets
        off), for the dry run."""
        return []

    def preview(self) -> list[str]:
        """The lines apply() would write into a file (changed_lines), for the dry run; [] when it
        writes none, or they can't be known yet."""
        return []

    @staticmethod
    def ran(record: dict) -> list[str]:
        """The commands applying ran, as History shows them, quoted for a shell. Rebuilt from the record,
        so entries made before this was kept show them too."""
        return list(record.get("ran") or [])

    def apply(self, ctx: FixContext) -> dict:
        """Make the change; return the undo record (JSON-able, includes "kind")."""
        raise NotImplementedError

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        raise NotImplementedError

    @staticmethod
    def describe_record(record: dict, host: Host | None = None) -> str:
        """The undo record as shown in History. `host` lets it look up names that are
        deliberately not written to the log."""
        return record.get("text", record["kind"])

    @staticmethod
    def undo_hint(record: dict) -> str:
        """How to put the change back by hand, without the app (for the export): a command, or
        what to do. Empty when there is nothing to undo."""
        return ""

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        """What this step's setting holds now, in words, when it no longer holds what the fix set
        (someone or something changed it back); None while it still does, or when that can't be
        read. Reads only."""
        return None


ACTION_KINDS: dict[str, type[Action]] = {}
IRREVERSIBLE_KINDS = frozenset({"delete", "clear", "command", "clear-command", "root-clear"})   # nothing to revert in the undo log
ROOT_KINDS = frozenset({"root"})                                                 # reverting needs the helper


def action(cls):
    ACTION_KINDS[cls.kind] = cls
    return cls


def bus_reload(host: Host) -> list[str]:
    """The command that has the session bus read its configuration and service files again. dbus-broker (Arch,
    CachyOS, Fedora) watches only the service folders that existed when it started: a service file of the user's own
    in a folder made since (an override starting /bin/false) is otherwise never seen, and the service starts on
    demand as before (tested with KDE Connect on CachyOS: it started again when Dolphin's context menu opened)."""
    if host.runner.which("busctl"):
        return ["busctl", "--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "ReloadConfig"]
    return ["dbus-send", "--session", "--type=method_call", "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus.ReloadConfig"]


def shell(argv: list[str] | tuple[str, ...]) -> str:
    """A command as it can be pasted into a shell: every argument quoted where it needs to be. Paths shown
    as ~/... keep the ~ outside the quotes, so the shell still expands it."""
    return " ".join(shell_path(a) if a.startswith("~/") else shlex.quote(a) for a in argv)


def shell_path(shown: str) -> str:
    """A path as the page shows it (~/...) quoted for a shell, the ~ left outside the quotes."""
    return "~/" + shlex.quote(shown[2:]) if shown.startswith("~/") else shlex.quote(shown)


def _run(host: Host, *argv: str) -> str:
    r = host.run(*argv)
    if not r.ok:
        raise FixError(f"{shell(argv)} failed: {(r.stderr or r.stdout).strip()[:200]}")
    return r.stdout


# What applying or reverting one step did, as History shows it: every command that changed something, quoted
# for a shell, and the file operations as the commands that do the same (cp from the backup, rm, rmdir). Reads
# (gsettings get, is-enabled) aren't listed. Collected by apply_plan and revert_entry around each step.
_DID: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar("fix_did", default=None)


def did(command: str) -> None:
    got = _DID.get()
    if got is not None:
        got.append(command)


def _change(host: Host, *argv: str) -> str:
    """_run for a command that changes something: listed in what the step did."""
    out = _run(host, *argv)
    did(shell(argv))
    return out


def _doing(fn):
    """fn() with what it does collected: (its result, the commands)."""
    token = _DID.set([])
    try:
        return fn(), _DID.get()
    finally:
        _DID.reset(token)


@action
class GSettingsSet(Action):
    kind = "gsettings"

    @staticmethod
    def undo_hint(record: dict) -> str:
        if record.get("was_default"):
            return shell(["gsettings", "reset", record['schema'], record['key']])
        return shell(["gsettings", "set", record['schema'], record['key'], record['before']])

    def __init__(self, schema: str, key: str, value: str):
        self.schema, self.key, self.value = schema, key, value       # value in GVariant text, e.g. "true", "uint32 300"

    def describe(self) -> str:
        return shell(["gsettings", "set", self.schema, self.key, self.value])

    @staticmethod
    def was_default(host: Host, schema: str, key: str) -> bool | None:
        """Whether the key holds its default (nothing in the user's dconf database), so that reverting resets it
        rather than writing the default in as a value of the user's: None when that can't be told (no dconf,
        a schema without a fixed path)."""
        if not host.runner.which("dconf"):
            return None
        r = host.run("gsettings", "list-schemas", "--print-paths")
        path = next((ln.split(" ", 1)[1].strip() for ln in r.stdout.splitlines() if r.ok and ln.split(" ", 1)[0] == schema
                     and " " in ln), "")
        if not path.startswith("/") or not path.endswith("/"):
            return None
        got = host.run("dconf", "read", path + key)
        return got.stdout.strip() == "" if got.ok else None

    def apply(self, ctx: FixContext) -> dict:
        before = _run(ctx.host, "gsettings", "get", self.schema, self.key).strip()
        default = self.was_default(ctx.host, self.schema, self.key)
        _change(ctx.host, "gsettings", "set", self.schema, self.key, self.value)
        after = _run(ctx.host, "gsettings", "get", self.schema, self.key).strip()
        return {"kind": self.kind, "schema": self.schema, "key": self.key, "before": before, "after": after,
                "was_default": default, "text": f"{self.schema} {self.key}: {before}{' (its default)' if default else ''} → {after}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(["gsettings", "set", record["schema"], record["key"], record["after"]])]

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        r = host.run("gsettings", "get", record["schema"], record["key"])
        now = r.stdout.strip()
        return f"{record['schema']} {record['key']} is {now} again (the fix set {record['after']})" \
            if r.ok and now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        now = ctx.host.run("gsettings", "get", record["schema"], record["key"]).stdout.strip()
        if now not in (record["after"], record["before"]) and not force:     # already back by hand: nothing to resolve
            return RevertResult(False, f"{record['schema']} {record['key']} has changed since (now {now})", True)
        if record.get("was_default"):
            _change(ctx.host, "gsettings", "reset", record["schema"], record["key"])
            return RevertResult(True, f"{record['schema']} {record['key']} back to its default ({record['before']})")
        _change(ctx.host, "gsettings", "set", record["schema"], record["key"], record["before"])
        return RevertResult(True, f"{record['schema']} {record['key']} back to {record['before']}")


@action
class XfconfSet(Action):
    """An Xfce setting, through xfconf-query (running apps are notified). "Before" is None when the
    property wasn't set (Xfce's default): reverting removes it again."""
    kind = "xfconf"

    @staticmethod
    def undo_hint(record: dict) -> str:
        base = ["xfconf-query", "-c", record['channel'], "-p", record['property']]
        return shell(base + ["-r"]) if record["before"] is None else shell(base + ["-s", record['before']])

    def __init__(self, channel: str, prop: str, type_: str, value: str):
        self.channel, self.prop, self.type, self.value = channel, prop, type_, value       # type: bool, int

    def describe(self) -> str:
        return shell(["xfconf-query", "-c", self.channel, "-p", self.prop, "-n", "-t", self.type, "-s", self.value])

    @staticmethod
    def _get(host: Host, channel: str, prop: str) -> str | None:
        r = host.run("xfconf-query", "-c", channel, "-p", prop)
        return r.stdout.strip() if r.ok else None

    def apply(self, ctx: FixContext) -> dict:
        before = self._get(ctx.host, self.channel, self.prop)
        if before is None:
            _change(ctx.host, "xfconf-query", "-c", self.channel, "-p", self.prop, "-n", "-t", self.type, "-s", self.value)
        else:
            _change(ctx.host, "xfconf-query", "-c", self.channel, "-p", self.prop, "-s", self.value)
        after = self._get(ctx.host, self.channel, self.prop)
        return {"kind": self.kind, "channel": self.channel, "property": self.prop, "before": before, "after": after,
                "type": self.type, "value": self.value,
                "text": f"{self.channel} {self.prop}: {before if before is not None else '(default)'} → {after}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        base = ["xfconf-query", "-c", record["channel"], "-p", record["property"]]
        value = record.get("value", record["after"])
        new = ["-n", "-t", record["type"]] if record["before"] is None and record.get("type") else []
        return [shell(base + new + ["-s", value])] if value is not None else []

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = XfconfSet._get(host, record["channel"], record["property"])
        return f"{record['channel']} {record['property']} is {now if now is not None else 'its default'} again " \
               f"(the fix set {record['after']})" if now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        now = XfconfSet._get(ctx.host, record["channel"], record["property"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{record['channel']} {record['property']} has changed since (now {now})", True)
        if record["before"] is None:
            _change(ctx.host, "xfconf-query", "-c", record["channel"], "-p", record["property"], "-r")
            return RevertResult(True, f"{record['channel']} {record['property']} back to its default")
        _change(ctx.host, "xfconf-query", "-c", record["channel"], "-p", record["property"], "-s", record["before"])
        return RevertResult(True, f"{record['channel']} {record['property']} back to {record['before']}")


# keys KDE writes into a settings file on its own: the version that last wrote it, and kconf_update's record
KDE_OWN_KEYS = frozenset({("General", "Version"), ("$Version", "update_info")})


@action
class KConfigSet(Action):
    """A KDE setting, written with kwriteconfig so running apps are notified. "Before" is the
    value in the user's file; a key that wasn't there (the default) is deleted again on revert.
    `then`: a command that has a program which reads its settings only when it starts, or when asked,
    read them again (kscreenlocker's configure call), run after writing and again after reverting, as
    WriteFile's; its failure doesn't fail the step."""
    kind = "kconfig"

    @staticmethod
    def undo_hint(record: dict) -> str:
        base = [record['tool'], "--file", record['file'], "--group", record['group'], "--key", record['key'], "--notify"]
        cmd = shell(base + ["--delete"]) if record["before"] is None else shell(base + [record['before']])
        return f"{cmd}; {shell(record['then'])}" if record.get("then") else cmd

    def __init__(self, tool: str, path: Path, file: str, group: str, key: str, value: str,
                 then: list[str] | None = None):
        self.tool, self.path, self.file, self.group, self.key, self.value = tool, path, file, group, key, value
        self.then = then

    def describe(self) -> str:
        return shell([self.tool, "--file", self.file, "--group", self.group, "--key", self.key, "--notify", self.value])

    def commands(self) -> list[str]:
        return [shell(self.then)] if self.then else []

    def _current(self, host: Host) -> str | None:
        from . import ini
        return ini.get(ini.parse(Host.read_file(self.path) or "", kde=True), self.group, self.key)

    def apply(self, ctx: FixContext) -> dict:
        before = self._current(ctx.host)
        created = not os.path.lexists(self.path)
        dirs = made_dirs(self.path)
        _change(ctx.host, self.tool, "--file", self.file, "--group", self.group, "--key", self.key, "--notify", self.value)
        if self.then:
            ctx.host.run(*self.then)
            did(shell(self.then))
        return {"kind": self.kind, "tool": self.tool, "path": str(self.path), "file": self.file, "group": self.group,
                "key": self.key, "before": before, "after": self.value, "created_file": created, "dirs": dirs,
                **({"then": self.then} if self.then else {}),
                "text": f"{self.file} [{self.group}] {self.key}: {before if before is not None else '(default)'} → {self.value}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell([record["tool"], "--file", record["file"], "--group", record["group"], "--key", record["key"],
                       "--notify", record["after"]])] + ([shell(record["then"])] if record.get("then") else [])

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        from . import ini
        now = ini.get(ini.parse(Host.read_file(Path(record["path"])) or "", kde=True), record["group"], record["key"])
        return f"{record['file']} {record['key']} is {now if now is not None else 'its default'} again " \
               f"(the fix set {record['after']})" if now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        from . import ini
        now = ini.get(ini.parse(Host.read_file(Path(record["path"])) or "", kde=True), record["group"], record["key"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{record['file']} {record['key']} has changed since (now {now})", True)
        base = [record["tool"], "--file", record["file"], "--group", record["group"], "--key", record["key"], "--notify"]
        if record["before"] is None:
            _change(ctx.host, *base, "--delete")
        else:
            _change(ctx.host, *base, record["before"])
        message = (f"{record['file']} {record['key']} back to "
                   f"{record['before'] if record['before'] is not None else 'its default'}")
        notes = []
        if record.get("created_file"):                  # kwriteconfig made the file: it goes, unless it holds more now
            p = Path(record["path"])
            left = ini.parse(Host.read_file(p) or "", kde=True)
            # what KDE writes into a settings file by itself isn't a setting of the user's: Plasma 6.7 left klipperrc
            # holding [General] Version=6.7.5 alone, which made this say "settings added since"
            if any(k for g, keys in left.items() for k in keys if (g[-1] if g else "", k) not in KDE_OWN_KEYS):
                notes.append(f"{_shown(str(p))} was left: the fix made it, but it now holds settings added since")
            elif p.is_file() and not p.is_symlink():
                p.unlink()
                did(shell(["rm", str(p)]))
                message += f"; {_shown(str(p))} removed (the fix made it)"
            notes += remove_made_dirs(record.get("dirs") or [])
        if record.get("then"):                          # the program reads the setting put back, now
            ctx.host.run(*record["then"])
            did(shell(record["then"]))
        return RevertResult(True, _with_notes(message, notes))


@action
class PlasmaTraySet(Action):
    """An entry of Plasma's system tray turned off or on through plasmashell's own scripting
    (desktop.tray_script, run with evaluateScript over D-Bus), as System Tray Settings → Entries does: the tray
    unloads or loads it at once and plasmashell writes its applets file, which is where "before" is read. `set`
    is the command for each state, built when the plan is ("on", "off"); `trays` are the tray applets' ids."""
    kind = "plasmatray"

    def __init__(self, plugin: str, label: str, path: Path, trays: list[str], set_: dict[str, list[str]], value: str,
                 phase: int = 0):
        self.plugin, self.label, self.path, self.trays, self.set, self.value = plugin, label, path, trays, set_, value
        self.phase = phase

    def describe(self) -> str:
        return f"Turn {self.value} {self.label} in the system tray: {shell(self.set[self.value])}"

    @staticmethod
    def _state(path: Path, plugin: str, trays: list[str]) -> str:
        from .desktop import tray_applet
        listed = tray_applet(Host.read_file(path) or "", plugin).trays
        return "on" if any(t in listed for t in trays) else "off"

    @staticmethod
    def _run_set(host: Host, argv: list[str], trays: list[str]) -> None:
        r = host.run(*argv)
        changed = set(re.findall(r"ok:(\d+)", r.stdout)) if r.ok else set()
        if not r.ok or not set(trays) <= changed:
            raise FixError(f"Plasma's system tray didn't take the change ({(r.stderr or r.stdout).strip()[:200] or 'no answer'})"
                           " — is Plasma running?")
        did(shell(argv))

    def apply(self, ctx: FixContext) -> dict:
        before = self._state(self.path, self.plugin, self.trays)
        self._run_set(ctx.host, self.set[self.value], self.trays)
        return {"kind": self.kind, "plugin": self.plugin, "label": self.label, "path": str(self.path), "trays": self.trays,
                "set": self.set, "before": before, "after": self.value,
                "text": f"{self.label} in the system tray: {before} → {self.value}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(record["set"][record["after"]])]

    @staticmethod
    def undo_hint(record: dict) -> str:
        return (f"System Tray Settings → Entries → {record['label']}: "
                f"{'Shown when relevant' if record['before'] == 'on' else 'Disabled'}; "
                f"or {shell(record['set'][record['before']])}")

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = PlasmaTraySet._state(Path(record["path"]), record["plugin"], record["trays"])
        return f"{record['label']} is {now} in the system tray again" if now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        now = PlasmaTraySet._state(Path(record["path"]), record["plugin"], record["trays"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{record['label']} in the system tray has changed since (now {now})", True)
        if now != record["before"]:
            PlasmaTraySet._run_set(ctx.host, record["set"][record["before"]], record["trays"])
        return RevertResult(True, f"{record['label']} is {record['before']} in the system tray again")


def copyq_tab_prop(text: str | None, tab: str, prop: str) -> str | None:
    """A property of a CopyQ tab in copyq.conf's [Tabs] array, as stored; None when it isn't set (its default)."""
    from . import ini
    entry = next((e for e in ini.qsettings_array(ini.parse(text or ""), "Tabs")
                  if ini.qsettings_value(e.get("name", "")) == tab), {})
    return entry.get(prop)


def copyq_set_tab_prop(text: str | None, tab: str, prop: str, value: str | None) -> str:
    """copyq.conf with a tab's property set (None: removed, and the tab's entry with it once only its name is
    left). Only the [Tabs] array is rewritten; CopyQ writes the same layout (tested with CopyQ 16)."""
    from . import ini
    entries = ini.qsettings_array(ini.parse(text or ""), "Tabs")
    entry = next((e for e in entries if ini.qsettings_value(e.get("name", "")) == tab), None)
    if entry is None:
        if value is None:
            return text or ""
        entry = {"name": ini.qsettings_quote(tab)}
        entries.append(entry)
    if value is None:
        entry.pop(prop, None)
        if set(entry) == {"name"}:
            entries.remove(entry)
    else:
        entry[prop] = value
    return ini.qsettings_set_array(text, "Tabs", entries)


@action
class CopyQCommand(Action):
    """A command of the app's own added to CopyQ (copyq-commands.ini, its [Commands] array: the layout CopyQ
    writes, tested with CopyQ 16), while CopyQ is closed. Known by its name: an older version of it is replaced.
    Reverting removes it, or puts the older version back, unless it was edited since."""
    kind = "copyq-command"

    def __init__(self, path: Path, display: str, name: str, script: str, label: str):
        self.path, self.display, self.name, self.script, self.label = path, display, name, script, label

    @staticmethod
    def _entries(text: str | None) -> list[dict[str, str]]:
        from . import ini
        return ini.qsettings_array(ini.parse(text or ""), "Commands")

    @staticmethod
    def find(text: str | None, name: str) -> dict[str, str] | None:
        from . import ini
        return next((e for e in CopyQCommand._entries(text) if ini.qsettings_value(e.get("Name", "")) == name), None)

    def _added(self, old: str | None) -> str:
        from . import ini
        entries = self._entries(old)
        mine = {"Command": ini.qsettings_quote(self.script), "IsScript": "true", "Name": ini.qsettings_quote(self.name)}
        at = next((i for i, e in enumerate(entries) if ini.qsettings_value(e.get("Name", "")) == self.name), None)
        if at is None:
            entries.append(mine)
        else:
            entries[at] = {**entries[at], "Command": mine["Command"]}
        return ini.qsettings_set_array(old, "Commands", entries)

    def describe(self) -> str:
        return f"{self.label} ({self.display})"

    def preview(self) -> list[str]:
        old = Host.read_file(self.path)
        return changed_lines(old, self._added(old))

    def apply(self, ctx: FixContext) -> dict:
        old = Host.read_file(self.path)
        before = self.find(old, self.name)
        new = self._added(old)
        _write_atomic(self.path, new.encode(), None if old is not None else 0o644)
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "name": self.name,
                "script_sha": _sha(self.script.encode()), "created_file": old is None,
                "before": before.get("Command") if before else None,
                "lines": changed_lines(old, new), "text": f"{self.label} ({self.display})"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        return f"In CopyQ: Commands → remove \"{record['name']}\"; or remove its lines from {record['display']}"

    @staticmethod
    def _now(record: dict) -> tuple[str | None, dict[str, str] | None]:
        text = Host.read_file(Path(record["path"]))
        return text, CopyQCommand.find(text, record["name"])

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        _, entry = CopyQCommand._now(record)
        return f"CopyQ's command \"{record['name']}\" was removed" if entry is None else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        from . import ini
        p = Path(record["path"])
        text, entry = CopyQCommand._now(record)
        if entry is None:
            return RevertResult(True, f"CopyQ's command \"{record['name']}\" was already removed")
        if _sha(ini.qsettings_value(entry.get("Command", "")).encode()) != record["script_sha"] and not force:
            return RevertResult(False, f"CopyQ's command \"{record['name']}\" has been edited since", True)
        entries = CopyQCommand._entries(text)
        at = entries.index(entry)
        if record.get("before") is not None:            # it replaced an older version: that comes back
            entries[at] = {**entry, "Command": record["before"]}
        else:
            del entries[at]
        new = ini.qsettings_set_array(text, "Commands", entries)
        if record.get("created_file") and not new.strip():
            p.unlink()
            did(shell(["rm", str(p)]))
            return RevertResult(True, f"{record['display']} removed (the fix made it)")
        _write_atomic(p, new.encode())
        return RevertResult(True, f"CopyQ's command \"{record['name']}\" "
                                  + ("back to its older version" if record.get("before") is not None else "removed"))


@action
class CopyQTabSet(Action):
    """A property of one CopyQ tab (store_items: "Save Items" in its Preferences → Tabs), in copyq.conf while
    CopyQ is closed. Like a KDE setting, not the file: CopyQ rewrites the rest of copyq.conf as it runs (its
    tab list, tested), which mustn't stop the revert. "Before" is the property as stored, None for its default."""
    kind = "copyq-tab"

    def __init__(self, path: Path, display: str, tab: str, prop: str, value: str, label: str):
        self.path, self.display, self.tab, self.prop, self.value, self.label = path, display, tab, prop, value, label

    def describe(self) -> str:
        return f"{self.label} ({self.display})"

    def preview(self) -> list[str]:
        old = Host.read_file(self.path)
        return changed_lines(old, copyq_set_tab_prop(old, self.tab, self.prop, self.value))

    def apply(self, ctx: FixContext) -> dict:
        old = Host.read_file(self.path)
        before = copyq_tab_prop(old, self.tab, self.prop)
        new = copyq_set_tab_prop(old, self.tab, self.prop, self.value)
        _write_atomic(self.path, new.encode(), None if old is not None else 0o644)
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "tab": self.tab, "prop": self.prop,
                "before": before, "after": self.value, "created_file": old is None, "lines": changed_lines(old, new),
                "text": f"{self.label} ({self.display}): {self.prop} {before or '(default)'} → {self.value}"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        return (f"In CopyQ: Preferences → Tabs → {record['tab']} → Save Items back as it was "
                f"({record['before'] or 'its default, on'}); or set {record['prop']} back in {record['display']}")

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = copyq_tab_prop(Host.read_file(Path(record["path"])), record["tab"], record["prop"])
        return f"CopyQ's tab {record['tab']} has {record['prop']} {now or 'at its default'} again" \
            if now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        p = Path(record["path"])
        old = Host.read_file(p)
        now = copyq_tab_prop(old, record["tab"], record["prop"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"CopyQ's tab {record['tab']} {record['prop']} has changed since (now {now})", True)
        new = copyq_set_tab_prop(old, record["tab"], record["prop"], record["before"])
        if record.get("created_file") and not new.strip():
            p.unlink()
            did(shell(["rm", str(p)]))
            return RevertResult(True, f"{record['display']} removed (the fix made it)")
        _write_atomic(p, new.encode())
        return RevertResult(True, f"CopyQ's tab {record['tab']} {record['prop']} back to {record['before'] or 'its default'}")


@action
class QSettingsSet(Action):
    """One key of a Qt program's settings file (QSettings' INI format: OpenSnitch's window keeps its own in
    ~/.config/opensnitch/settings.conf), written while the program is closed (it reads them when it starts). Like a
    KDE setting, not the file: the program rewrites the rest of the file as it runs (its window's size), which
    mustn't stop the revert. "Before" is the key as stored, None when it wasn't set."""
    kind = "qsettings"

    def __init__(self, path: Path, display: str, group: str, key: str, value: str, label: str, by_hand: str = ""):
        self.path, self.display, self.group, self.key, self.value = path, display, group, key, value
        self.label, self.by_hand = label, by_hand

    def describe(self) -> str:
        return f"{self.label} ({self.display}: [{self.group}] {self.key}={self.value})"

    def _new(self, old: str | None) -> str:
        from . import ini
        return ini.qsettings_set(old, self.group, self.key, self.value)

    def preview(self) -> list[str]:
        old = Host.read_file(self.path)
        return changed_lines(old, self._new(old))

    def apply(self, ctx: FixContext) -> dict:
        from . import ini
        old = Host.read_file(self.path)
        before = ini.qsettings_get(old, self.group, self.key)
        new = self._new(old)
        dirs = made_dirs(self.path)
        for d in dirs:
            did(shell(["mkdir", d]))
        _write_atomic(self.path, new.encode(), None if old is not None else 0o600)
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "group": self.group,
                "key": self.key, "before": before, "after": self.value, "created_file": old is None, "dirs": dirs,
                "lines": changed_lines(old, new), "by_hand": self.by_hand,
                "text": f"{self.label} ({self.display}: {self.key} {before if before is not None else '(not set)'} → {self.value})"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        back = record["before"] if record["before"] is not None else "(remove the line)"
        return ((record.get("by_hand") + "; or " if record.get("by_hand") else "")
                + f"in {record['display']}, under [{record['group']}]: {record['key']}={back}, with the program closed")

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        from . import ini
        now = ini.qsettings_get(Host.read_file(Path(record["path"])), record["group"], record["key"])
        return f"{record['display']} has {record['key']} {now if now is not None else 'unset'} again" \
            if now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        from . import ini
        p = Path(record["path"])
        old = Host.read_file(p)
        now = ini.qsettings_get(old, record["group"], record["key"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{record['display']}: {record['key']} has changed since (now {now})", True)
        new = ini.qsettings_set(old, record["group"], record["key"], record["before"])
        if record.get("created_file") and not new.strip():
            p.unlink()
            did(shell(["rm", str(p)]))
            return RevertResult(True, _with_notes(f"{record['display']} removed (the fix made it)",
                                                  remove_made_dirs(record.get("dirs") or [])))
        _write_atomic(p, new.encode())
        return RevertResult(True, f"{record['display']}: {record['key']} back to "
                                  + (record["before"] if record["before"] is not None else "not set"))


@action
class SettingLines(Action):
    """Settings that are whole lines of a file its program rewrites as it quits (LibreOffice's registrymodifications.xcu,
    an <item> a line; GIMP's gimprc): each line is set, and put back, on its own, never the whole file. A whole-file
    backup (WriteFile) conflicted with every revert, the program having rewritten the file, and forced it put back an
    old file over everything changed since. Each entry: a pattern that finds its line, and the line to set; a line
    that isn't there yet goes before the first line holding `anchor`, else at the end. `new_file` is the file made
    when there is none (with `anchor` in it); reverting removes it again while it holds nothing more."""
    kind = "setting_lines"

    def __init__(self, path: Path, display: str, label: str, entries: list[tuple[str, str]], anchor: str = "",
                 new_file: str = "", by_hand: str = ""):
        self.path, self.display, self.label, self.entries = path, display, label, entries
        self.anchor, self.new_file, self.by_hand = anchor, new_file, by_hand

    def describe(self) -> str:
        return f"{self.label} ({self.display}: {len(self.entries)} line{'s' if len(self.entries) != 1 else ''})"

    @staticmethod
    def _find(lines: list[str], pattern: str) -> int | None:
        rx = re.compile(pattern)
        return next((i for i, ln in enumerate(lines) if rx.search(ln)), None)

    @staticmethod
    def _put(text: str, pattern: str, line: str | None, anchor: str) -> tuple[str, str | None]:
        """`text` with the line `pattern` finds set to `line` (removed for None): (the new text, the line before)."""
        lines = text.split("\n")
        i = SettingLines._find(lines, pattern)
        before = lines[i] if i is not None else None
        if i is not None:
            if line is None:
                del lines[i]
            else:
                lines[i] = line
        elif line is not None:
            at = next((j for j, ln in enumerate(lines) if anchor and anchor in ln), None)
            if at is None:
                at = len(lines) - 1 if lines and lines[-1] == "" else len(lines)
            lines.insert(at, line)
        return "\n".join(lines), before

    def _new(self, old: str | None) -> str:
        text = old if old is not None else self.new_file
        for pattern, line in self.entries:
            text = self._put(text, pattern, line, self.anchor)[0]
        return text

    def preview(self) -> list[str]:
        old = Host.read_file(self.path)
        return changed_lines(old, self._new(old))

    def apply(self, ctx: FixContext) -> dict:
        old = Host.read_file(self.path)
        text, entries = old if old is not None else self.new_file, []
        for pattern, line in self.entries:
            text, before = self._put(text, pattern, line, self.anchor)
            entries.append({"pattern": pattern, "line": line, "before": before})
        dirs = made_dirs(self.path)
        for d in dirs:
            did(shell(["mkdir", d]))
        _write_atomic(self.path, text.encode(), None if old is not None else 0o600)
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "entries": entries,
                "anchor": self.anchor, "new_file": self.new_file if old is None else None, "created_file": old is None,
                "dirs": dirs, "by_hand": self.by_hand, "lines": changed_lines(old, text),
                "text": f"{self.label} ({self.display})"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        parts = [f"put back {e['before']}" if e["before"] is not None else f"delete the line {e['line']}"
                 for e in record["entries"]]
        return ((record.get("by_hand") + "; or " if record.get("by_hand") else "")
                + f"in {record['display']}, with the program closed: " + "; ".join(parts))

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        lines = (Host.read_file(Path(record["path"])) or "").split("\n")
        for e in record["entries"]:
            i = SettingLines._find(lines, e["pattern"])
            if (lines[i] if i is not None else None) != e["line"]:
                return f"{record['display']} no longer has {e['line']}"
        return None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        p = Path(record["path"])
        text = Host.read_file(p)
        if text is None:
            return RevertResult(True, f"{record['display']} isn't there any more: nothing to put back")
        for e in reversed(record["entries"]):
            i = SettingLines._find(text.split("\n"), e["pattern"])
            now = text.split("\n")[i] if i is not None else None
            if now not in (e["line"], e["before"]) and not force:
                return RevertResult(False, f"{record['display']}: {e['line']} has changed since (now {now})", True)
        for e in reversed(record["entries"]):
            text = SettingLines._put(text, e["pattern"], e["before"], record.get("anchor") or "")[0]
        if record.get("created_file") and text.strip() == (record.get("new_file") or "").strip():
            p.unlink()
            did(shell(["rm", str(p)]))
            return RevertResult(True, _with_notes(f"{record['display']} removed (the fix made it)",
                                                  remove_made_dirs(record.get("dirs") or [])))
        _write_atomic(p, text.encode())
        return RevertResult(True, f"{record['display']}: {len(record['entries'])} line"
                                  f"{'s' if len(record['entries']) != 1 else ''} put back")


@action
class KConfigLock(Action):
    """Marks one group of a KDE settings file immutable (`[Recent Files][$i]`, KConfig's Kiosk marker), so the program
    can't write it: an app's own list of recently opened files stays empty (tested on KDE Gear 26.08 with KolourPaint
    and Okular). Only the group's header line changes, and only it is put back: the program rewrites the rest of the
    file as it runs. Its entries are cleared first by a ClearInFile of the plan (`phase=4` puts this after it), so the
    record holds no file names."""
    kind = "kconfig_lock"

    def __init__(self, path: Path, display: str, group: str, label: str, phase: int = 4):
        self.path, self.display, self.group, self.label, self.phase = path, display, group, label, phase

    def describe(self) -> str:
        return f"{self.label} ({self.display}: [{self.group}][$i])"

    @staticmethod
    def _header(group: str) -> re.Pattern:
        return re.compile(rf"^\[{re.escape(group)}\](\[\$i\])?[ \t]*$", re.M)

    @classmethod
    def state(cls, text: str | None, group: str) -> str:
        """locked | unlocked | absent (no such group, or no file)."""
        m = cls._header(group).search(text or "")
        return "absent" if not m else "locked" if m.group(1) else "unlocked"

    def _new(self, old: str | None) -> str:
        text = old or ""
        if self.state(text, self.group) == "unlocked":
            return self._header(self.group).sub(f"[{self.group}][$i]", text, count=1)
        if self.state(text, self.group) == "absent":
            return text + ("\n" if text and not text.endswith("\n") else "") + ("\n" if text.strip() else "") \
                + f"[{self.group}][$i]\n"
        return text

    def preview(self) -> list[str]:
        old = Host.read_file(self.path)
        return changed_lines(old, self._new(old))

    def apply(self, ctx: FixContext) -> dict:
        old = Host.read_file(self.path)
        before = "absent" if old is None else self.state(old, self.group)
        new = self._new(old)
        dirs = made_dirs(self.path)
        for d in dirs:
            did(shell(["mkdir", d]))
        if new != (old or ""):
            _write_atomic(self.path, new.encode(), None if old is not None else 0o600)
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "group": self.group,
                "before": before, "created_file": old is None, "dirs": dirs, "lines": changed_lines(old, new),
                "text": f"{self.label} ({self.display}: [{self.group}] marked so the app can't write it)"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        if record["before"] == "absent":
            return f"in {record['display']}, delete the line [{record['group']}][$i]"
        return f"in {record['display']}, change the line [{record['group']}][$i] to [{record['group']}]"

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = KConfigLock.state(Host.read_file(Path(record["path"])), record["group"])
        return f"{record['display']}: [{record['group']}] can be written again" if now != "locked" else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        p, group = Path(record["path"]), record["group"]
        old = Host.read_file(p)
        if KConfigLock.state(old, group) != "locked":
            return RevertResult(True, f"{record['display']}: [{group}] isn't marked any more")
        if record["before"] == "locked":
            return RevertResult(True, "Nothing to undo")
        header = KConfigLock._header(group)
        if record["before"] == "absent":
            # the group the fix added, while it is still empty: removed with the blank line before it
            body = re.search(rf"{header.pattern}\n((?:(?!\[).*\n?)*)", old, re.M)
            if body and not body.group(2).strip():
                new = old[:body.start()].rstrip("\n") + ("\n" if old[:body.start()].strip() else "") + old[body.end():]
            else:
                new = header.sub(f"[{group}]", old, count=1)
        else:
            new = header.sub(f"[{group}]", old, count=1)
        if record.get("created_file") and not new.strip():
            p.unlink()
            did(shell(["rm", str(p)]))
            return RevertResult(True, _with_notes(f"{record['display']} removed (the fix made it)",
                                                  remove_made_dirs(record.get("dirs") or [])))
        _write_atomic(p, new.encode())
        return RevertResult(True, f"{record['display']}: the app can write [{group}] again")


@action
class NmSet(Action):
    kind = "nmcli"

    @staticmethod
    def undo_hint(record: dict) -> str:
        return shell(["nmcli", "connection", "modify", record['uuid'], record['prop'], record['before'] or ""])

    def __init__(self, uuid_: str, name: str, prop: str, value: str):
        self.uuid, self.name, self.prop, self.value = uuid_, name, prop, value

    def describe(self) -> str:
        return f"{shell(['nmcli', 'connection', 'modify', self.uuid, self.prop, self.value])}   ({self.name})"

    def _get(self, host: Host, uuid_: str, prop: str) -> str:
        return _run(host, "nmcli", "-g", prop, "connection", "show", uuid_).strip()

    def apply(self, ctx: FixContext) -> dict:
        before = self._get(ctx.host, self.uuid, self.prop)
        _change(ctx.host, "nmcli", "connection", "modify", self.uuid, self.prop, self.value)
        after = self._get(ctx.host, self.uuid, self.prop)
        # the connection's name (usually the Wi-Fi network's) is not written to the log: it is a
        # record of where this machine has been. History looks it up by UUID when shown.
        return {"kind": self.kind, "uuid": self.uuid, "prop": self.prop, "before": before, "after": after,
                "value": self.value, "text": f"Saved connection: {self.prop} {before or '(default)'} → {after}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(["nmcli", "connection", "modify", record["uuid"], record["prop"],
                       record.get("value", record["after"])])]

    @staticmethod
    def name_of(host: Host | None, uuid_: str) -> str:
        if host is not None:
            r = host.run("nmcli", "-g", "connection.id", "connection", "show", uuid_)
            if r.ok and r.stdout.strip():
                return r.stdout.strip()
        return "Saved connection"

    @staticmethod
    def describe_record(record: dict, host: Host | None = None) -> str:
        return f"{NmSet.name_of(host, record['uuid'])}: {record['prop']} {record['before'] or '(default)'} → {record['after']}"

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        r = host.run("nmcli", "-g", record["prop"], "connection", "show", record["uuid"])
        if not r.ok or r.stdout.strip() == record["after"]:
            return None
        return f"{NmSet.name_of(host, record['uuid'])}: {record['prop']} is {r.stdout.strip() or 'the default'} again " \
               f"(the fix set {record['after']})"

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        r = ctx.host.run("nmcli", "-g", record["prop"], "connection", "show", record["uuid"])
        if not r.ok:
            return RevertResult(False, "That saved connection no longer exists")
        name = NmSet.name_of(ctx.host, record["uuid"])
        if r.stdout.strip() not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{name} {record['prop']} has changed since", True)
        _change(ctx.host, "nmcli", "connection", "modify", record["uuid"], record["prop"], record["before"])
        return RevertResult(True, f"{name}: {record['prop']} back to {record['before'] or 'the default'}")


@action
class BluetoothSet(Action):
    """bluetoothctl settings: discoverable on/off, power on/off, alias."""
    kind = "bluetooth"
    FIELDS = {"discoverable": "Discoverable", "power": "Powered", "alias": "Alias"}

    @staticmethod
    def undo_hint(record: dict) -> str:
        if record["what"] == "alias":
            return "bluetoothctl reset-alias" if record.get("default_alias") else "bluetoothctl system-alias OLDNAME"
        return shell(["bluetoothctl", record['what'], record['before']])

    def __init__(self, what: str, value: str):
        self.what, self.value = what, value

    def describe(self) -> str:
        return shell(["bluetoothctl", "system-alias" if self.what == "alias" else self.what, self.value])

    @staticmethod
    def _show(host: Host) -> dict[str, str]:
        out = _run(host, "bluetoothctl", "show")
        return {k: v.strip() for k, v in re.findall(r"^\s*(\w+):\s*(.*)$", out, re.M)}

    @classmethod
    def _value(cls, show: dict, what: str) -> str:
        v = show.get(cls.FIELDS[what], "")
        return {"yes": "on", "no": "off"}.get(v, v) if what != "alias" else v

    def apply(self, ctx: FixContext) -> dict:
        show = self._show(ctx.host)
        before = self._value(show, self.what)
        default_alias = self.what == "alias" and show.get("Alias") == show.get("Name")
        _change(ctx.host, "bluetoothctl", "system-alias" if self.what == "alias" else self.what, self.value)
        # the old alias is needed to put it back, but it isn't repeated in the shown text
        return {"kind": self.kind, "what": self.what, "before": before, "after": self.value,
                "default_alias": default_alias,
                "text": f"Bluetooth {self.what}: {before} → {self.value}" if self.what != "alias"
                else f"Bluetooth name: changed to {self.value}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(["bluetoothctl", "system-alias" if record["what"] == "alias" else record["what"], record["after"]])]

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = BluetoothSet._value(BluetoothSet._show(host), record["what"])
        if now is None or now == record["after"]:
            return None
        return f"Bluetooth {record['what']} is {now} again" if record["what"] != "alias" else "The Bluetooth name was changed"

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        now = BluetoothSet._value(BluetoothSet._show(ctx.host), record["what"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"Bluetooth {record['what']} has changed since", True)
        if record["what"] == "alias":
            if record.get("default_alias"):
                _change(ctx.host, "bluetoothctl", "reset-alias")
            else:
                _change(ctx.host, "bluetoothctl", "system-alias", record["before"])
        else:
            _change(ctx.host, "bluetoothctl", record["what"], record["before"])
        return RevertResult(True, f"Bluetooth {record['what']} back to {record['before']}")


@action
class UserUnitSet(Action):
    """A systemd user unit of the user's own session enabled and started, or disabled and stopped
    (e.g. systemd's daily user clean-up timer). Reverting puts back whether it was enabled."""
    kind = "userunit"

    @staticmethod
    def undo_hint(record: dict) -> str:
        if record["before"] not in ("enabled", "disabled"):
            return ""
        return shell(["systemctl", "--user", "enable" if record['before'] == "enabled" else "disable", "--now", record['unit']])

    def __init__(self, unit: str, enable: bool, why: str = ""):
        self.unit, self.enable, self.why = unit, enable, why

    def describe(self) -> str:
        return shell(["systemctl", "--user", "enable" if self.enable else "disable", "--now", self.unit]) + (
            f"   ({self.why})" if self.why else "")

    @staticmethod
    def _state(host: Host, unit: str) -> str:
        r = host.run("systemctl", "--user", "is-enabled", unit)
        return (r.stdout.strip().splitlines() or ["unknown"])[0]

    @staticmethod
    def _unit_dirs(host: Host) -> set[str]:
        """The folders of the user's own systemd configuration (~/.config/systemd/user and the .wants folders
        in it): enabling a unit makes the ones it needs, and disabling it leaves them, empty."""
        base = Path(host.environ.get("XDG_CONFIG_HOME") or host.home / ".config") / "systemd"
        out = {str(d) for d in (base, base / "user") if d.is_dir() and not d.is_symlink()}
        try:
            out |= {str(d) for d in (base / "user").iterdir() if d.is_dir() and not d.is_symlink()}
        except OSError:
            pass
        return out

    def apply(self, ctx: FixContext) -> dict:
        before = self._state(ctx.host, self.unit)
        had = self._unit_dirs(ctx.host)
        _change(ctx.host, "systemctl", "--user", "enable" if self.enable else "disable", "--now", self.unit)
        after = self._state(ctx.host, self.unit)
        return {"kind": self.kind, "unit": self.unit, "before": before, "after": after, "enable": self.enable,
                "dirs": sorted(self._unit_dirs(ctx.host) - had), "text": f"{self.unit}: {before} → {after}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        enable = record.get("enable", record["after"] == "enabled")
        return [shell(["systemctl", "--user", "enable" if enable else "disable", "--now", record["unit"]])]

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = UserUnitSet._state(host, record["unit"])
        return f"{record['unit']} is {now} again (the fix left it {record['after']})" \
            if now not in ("unknown", record["after"]) else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        now = UserUnitSet._state(ctx.host, record["unit"])
        if now != record["after"] and not force:
            return RevertResult(False, f"{record['unit']} has been changed since (now {now})", True)
        if record["before"] in ("enabled", "disabled") and record["before"] != now:
            verb = "enable" if record["before"] == "enabled" else "disable"
            _change(ctx.host, "systemctl", "--user", verb, "--now", record["unit"])
        return RevertResult(True, _with_notes(f"{record['unit']} back to {record['before']}",
                                              remove_made_dirs(record.get("dirs") or [])))


def _sha(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def _read_bytes(p: Path) -> bytes | None:
    try:
        return p.read_bytes()
    except FileNotFoundError:
        return None


def _umask() -> int:
    """The process's umask, read without changing it (os.umask would, for every thread at once)."""
    try:
        m = re.search(r"^Umask:\s*([0-7]+)", Path("/proc/self/status").read_text(), re.M)
    except OSError:
        m = None
    return int(m.group(1), 8) if m else 0o022


def _write_atomic(p: Path, data: bytes, mode: int | None = None) -> None:
    """Writes `p` whole, through a temporary file renamed over it. A link (a dotfiles manager's) stays a
    link: the file it points to is written, as an editor would. The temporary file is the user's alone until
    it has the final mode (a shell history being cleaned is never readable by others on the way), and one
    left by an interrupted write is replaced, never followed."""
    if p.is_symlink():
        p = p.resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.daprivacyscanner-tmp")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    final = mode if mode is not None else (p.stat().st_mode & 0o7777 if p.exists() else None)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with open(fd, "wb") as f:
            f.write(data)
        if final is None:                       # a new file: what the umask gives, as any program would make it
            final = 0o666 & ~_umask()
        os.chmod(tmp, final)
        os.replace(tmp, p)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


@action
class WriteFile(Action):
    """Create or change a config file. The old content is backed up for the undo log; a file
    that didn't exist is removed again on revert."""
    kind = "file"

    @staticmethod
    def undo_hint(record: dict) -> str:
        if record.get("backup"):
            return f"{shell(['cp', record['backup'], record['path']])}   (the copy is kept until the entry is forgotten)"
        dirs = sorted(record.get("dirs") or [], key=lambda d: d.count("/"), reverse=True)
        return f"{shell(['rm', record['path']])}" + "".join(f"; {shell(['rmdir', d])}" for d in dirs) + (
            "   (it didn't exist before" + (", nor did the folders, removed only if empty)" if dirs else ")"))

    def __init__(self, path: Path, content: Callable[[str | None], str], text: str, display: str,
                 mode: int | None = None, lines: list[str] | None = None, then: list[str] | None = None):
        self.path, self.content, self.text, self.display = path, content, text, display
        self.mode = mode                    # for a file created new (an existing file keeps its mode)
        # what the dry run and History show of the change in place of its lines, for a line that names someone
        # (an authorized key's comment is often an email address): the log is a record too
        self.lines = lines
        # a command that has the program reading the file notice it, run after writing and again after reverting
        # (bus_reload: the session bus reads its service files again); its failure doesn't fail the step
        self.then = then

    def describe(self) -> str:
        # an existing file is copied into History's backups first, and the user should know the copy is there (a
        # shell profile can hold a token; the copy is 0600, like the undo log, and goes when the entry is forgotten)
        kept = (", its current contents kept in History's backups until the entry is forgotten"
                if _read_bytes(self.path) is not None else "")
        if self.path.is_symlink():
            real = str(self.path.resolve())
            home = os.path.expanduser("~")
            real = "~" + real[len(home):] if real.startswith(home + "/") else real
            return f"{self.text} ({self.display}, a link: the file it points to, {real}, is the one changed{kept})"
        return f"{self.text} ({self.display}{kept})"

    def _old_new(self) -> tuple[bytes | None, str | None, str]:
        old = _read_bytes(self.path)
        old_text = None if old is None else old.decode("utf-8", errors="surrogateescape")
        return old, old_text, self.content(old_text)

    def commands(self) -> list[str]:
        return [shell(["mkdir", d]) for d in made_dirs(self.path.resolve() if self.path.is_symlink() else self.path)] + \
            ([shell(self.then)] if self.then else [])

    def noop(self) -> bool:
        """Whether writing would leave the file exactly as it is (an option applied before): FixPlan leaves such a
        step out, so a guide doesn't offer again, nor History record, a change that changes nothing."""
        try:
            old, old_text, new_text = self._old_new()
        except Exception:  # noqa: BLE001 - unreadable or odd: apply() says what is wrong
            return False
        return old is not None and new_text == old_text

    def preview(self) -> list[str]:
        if self.lines is not None:
            return list(self.lines)
        try:
            _, old_text, new_text = self._old_new()
        except (OSError, ValueError):
            return []
        return changed_lines(old_text, new_text)

    def apply(self, ctx: FixContext) -> dict:
        old, old_text, new_text = self._old_new()
        new = new_text.encode("utf-8", errors="surrogateescape")
        dirs = made_dirs(self.path.resolve() if self.path.is_symlink() else self.path)
        for d in dirs:
            did(shell(["mkdir", d]))                   # _write_atomic makes them, outermost first
        backup = old_mode = None
        if old is not None:
            ctx.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
            backup = ctx.backups / f"{uuid.uuid4().hex}-{self.path.name}"
            _write_atomic(backup, old, 0o600)
            old_mode = self.path.stat().st_mode & 0o7777
        _write_atomic(self.path, new, None if old is not None else self.mode)
        if self.then:
            ctx.host.run(*self.then)
            did(shell(self.then))
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "backup": str(backup) if backup else None,
                "mode": old_mode, **({"then": self.then} if self.then else {}),
                "after_sha": _sha(new), "text": f"{self.text} ({self.display})",
                "lines": list(self.lines) if self.lines is not None else changed_lines(old_text, new_text),
                "dirs": dirs}

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = _read_bytes(Path(record["path"]))
        if _sha(now) == record["after_sha"]:
            return None
        return f"{record['display']} was removed" if now is None else f"{record['display']} was edited since"

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        p = Path(record["path"])
        now = _read_bytes(p)
        if _sha(now) != record["after_sha"] and not force:
            return RevertResult(False, f"{record['display']} has been edited since", True)
        if record["backup"]:
            data = _read_bytes(Path(record["backup"]))
            if data is None:
                return RevertResult(False, f"The backup of {record['display']} is missing")
            # the file's own mode, also when it was removed since (a backup is 0600 and a new file gets the umask's)
            _write_atomic(p, data, None if p.exists() or record.get("mode") is None else record["mode"])
            did(shell(["cp", record["backup"], record["path"]]))
            WriteFile._then(record, ctx)
            return RevertResult(True, f"{record['display']} restored")
        if now is not None:
            p.unlink()
            did(shell(["rm", record["path"]]))
        WriteFile._then(record, ctx)
        return RevertResult(True, _with_notes(f"{record['display']} removed", remove_made_dirs(record.get("dirs") or [])))

    @staticmethod
    def _then(record: dict, ctx: FixContext) -> None:
        if record.get("then"):
            ctx.host.run(*record["then"])
            did(shell(record["then"]))


@action
class DeleteFiles(Action):
    """Deletes exactly the files listed in the plan (as shown in the dry run), each of which
    must be a regular file inside `root`. Irreversible by design."""
    kind = "delete"
    reversible = False
    destructive = True
    phase = 2

    def __init__(self, root: Path, files: list[Path], label: str, display_root: str, prune: bool = True,
                 remove_root: bool = False, about: dict[Path, str] | None = None):
        self.root, self.files, self.label, self.display_root = root, files, label, display_root
        self.prune = prune              # remove subfolders the deletion leaves empty
        self.remove_root = remove_root  # and the root itself (an uninstalled app's folder)
        self.about = about or {}        # what a folder's files are, for the dry run (VS Code's: the file they copy)

    @property
    def size(self) -> int:
        total = 0
        for f in self.files:
            try:
                total += f.lstat().st_size
            except OSError:
                pass
        return total

    def describe(self) -> str:
        from .checks._util import human_size
        n = len(self.files)
        return f"Delete {n} file{'s' if n != 1 else ''} ({human_size(self.size)}) of {self.label} in {self.display_root}"

    LISTED = 25                         # files named one by one up to this many; beyond it, their folders

    def preview(self) -> list[str]:
        """Where the files are, for the dry run, so the user can look before deleting: each file when there are
        few, else each folder with how many are in it, the fullest first. Shown on this machine only: the undo log
        keeps the count and the folder the plan named, never these."""
        root = self.display_root.rstrip("/")
        def shown(p: Path) -> str:
            try:
                rel = p.relative_to(self.root)
            except ValueError:
                return str(p)
            return root + "/" + str(rel) if str(rel) != "." else root
        if len(self.files) <= self.LISTED and not self.about:
            return [shown(f) for f in sorted(self.files)]
        counts: dict[Path, int] = {}
        for f in self.files:
            counts[f.parent] = counts.get(f.parent, 0) + 1
        folders = sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))
        out = [f"{shown(d)}/  ({n} file{'s' if n != 1 else ''}" + (f": {self.about[d]}" if d in self.about else "") + ")"
               for d, n in folders[:self.LISTED]]
        if len(folders) > self.LISTED:
            rest = sum(n for _, n in folders[self.LISTED:])
            out.append(f"… and {rest} more files in {len(folders) - self.LISTED} more folders")
        return out

    def apply(self, ctx: FixContext) -> dict:
        root = self.root.resolve()
        deleted = skipped = 0
        dirs = set()
        for f in self.files:
            try:
                parent = f.parent.resolve()
                if not (parent == root or parent.is_relative_to(root)) or f.is_symlink() or not f.is_file():
                    skipped += 1
                    continue
                f.unlink()
                deleted += 1
                dirs.add(parent)
            except FileNotFoundError:
                skipped += 1
            except OSError:
                skipped += 1
        if self.remove_root:            # symlinks (never their targets) and empty folders below the root, then the root
            for d, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
                for name in filenames + dirnames:
                    p = Path(d) / name
                    try:
                        if p.is_symlink():
                            p.unlink()
                        elif p.is_dir():
                            p.rmdir()
                    except OSError:
                        pass
            try:
                root.rmdir()
            except OSError:
                pass
        for d in sorted(dirs if self.prune else (), key=lambda p: len(p.parts), reverse=True):  # tidy empty subfolders
            while d != root and d.is_relative_to(root):
                try:
                    d.rmdir()
                except OSError:
                    break
                d = d.parent
        return {"kind": self.kind, "label": self.label, "root": self.display_root, "deleted": deleted, "skipped": skipped,
                "text": f"Deleted {deleted} file{'s' if deleted != 1 else ''} of {self.label} in {self.display_root}"
                        + (f" ({skipped} skipped)" if skipped else "")}

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        return RevertResult(False, f"Deleted files can't be restored ({record['label']})")


@action
class Command(Action):
    """A command with no lasting state of its own, e.g. stopping a daemon that restarts on
    demand. Not undone; the plan lists it as a side effect."""
    kind = "command"
    reversible = False

    WAIT = 20.0                         # seconds a stopped program is given to exit (wait_gone)

    def __init__(self, argv: list[str], why: str, check_ok: bool = True, after: bool = False,
                 wait_gone: str | None = None):
        self.argv, self.why, self.check_ok = argv, why, check_ok
        self.phase = 3 if after else 1
        # a process name (comm, at most 15 characters) of the user's that must have exited before the plan goes on:
        # a daemon told to stop (balooctl6 disable, zeitgeist-daemon --quit) returns before it has, and what comes
        # next deletes the files it holds
        self.wait_gone = wait_gone

    def describe(self) -> str:
        return f"{shell(self.argv)}   ({self.why})"

    def apply(self, ctx: FixContext) -> dict:
        r = ctx.host.run(*self.argv)
        if self.check_ok and not r.ok:
            raise FixError(f"{shell(self.argv)} failed: {(r.stderr or r.stdout).strip()[:200]}")
        did(shell(self.argv))
        if self.wait_gone:
            self._wait(ctx.host, self.wait_gone, self.WAIT)
        return {"kind": self.kind, "argv": self.argv, "text": f"Ran {shell(self.argv)} ({self.why})"}

    @staticmethod
    def _wait(host: Host, name: str, seconds: float) -> None:
        from .checks._util import processes
        deadline = time.monotonic() + seconds
        while name in processes(host, own=True):
            if time.monotonic() > deadline:
                raise FixError(f"{name} was still running {seconds:g} seconds after it was asked to stop, so nothing "
                               "after this step was done (what it holds open would have been deleted under it). Try "
                               "again in a moment.")
            time.sleep(0.2)

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(record["argv"])] if record.get("argv") else []

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        return RevertResult(True, "Nothing to undo")


@action
class ClearCommand(Command):
    """Deleting what a running program keeps, through the program itself (Klipper's clearClipboardHistory over
    D-Bus), where deleting its files would pull them out from under it. Irreversible: confirmed like a deletion."""
    kind = "clear-command"
    destructive = True


# ------------------------------------------------------------------ plans

@dataclass
class FixPlan:
    check_id: str
    title: str
    actions: list[Action] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)       # why it can't be applied now ("Close Firefox first")
    side_effects: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: float = field(default_factory=time.time)
    # how the plan was offered, kept with the History entry so it says where the change came from: a guide's
    # step and option ({"guide", "step", "step_title", "option", "options"}), an Easy fix ({"easy": True}); {}
    # for an auto fix opened from its row (Runner.plan_fix and plan_easy fill it)
    via: dict = field(default_factory=dict)

    def __post_init__(self):
        # a file write that changes nothing isn't a step (an option applied before would be offered for ever)
        self.actions = [a for a in self.actions if not (isinstance(a, WriteFile) and a.noop())]
        # reversible changes first, deletions last (see the module docstring); stable within a phase
        self.actions.sort(key=lambda a: a.phase)

    def step_commands(self) -> list[list[str]]:
        """Each step's commands for the dry run, without the mkdir of a folder an earlier step makes: applying makes
        it once, at the first step that needs it."""
        made: set[str] = set()
        out = []
        for a in self.actions:
            cmds = [c for c in a.commands() if c not in made]
            made.update(c for c in cmds if c.startswith("mkdir "))
            if isinstance(a, MakeDir):
                made.add(shell(["mkdir", str(a.path)]))
            out.append(cmds)
        return out

    @property
    def irreversible(self) -> list[Action]:
        return [a for a in self.actions if a.destructive]

    @property
    def needs_root(self) -> bool:
        return any(a.needs_root for a in self.actions)

    @property
    def empty(self) -> bool:
        return not self.actions

    def dry_run(self, indent: str = "  ") -> str:
        lines = [f"Fix for {self.check_id}: {self.title}"]
        for b in self.blockers:
            lines.append(f"{indent}BLOCKED: {b}")
        for a, cmds in zip(self.actions, self.step_commands()):
            tag = "can be undone" if a.reversible else "CANNOT be undone" if a.destructive else "side effect"
            lines.append(f"{indent}[{tag}{', as root' if a.needs_root else ''}] {a.describe()}")
            lines += [f"{indent}    also runs: {c}" for c in cmds]
            lines += [f"{indent}    {ln}" for ln in a.preview()]
        for s in self.side_effects:
            lines.append(f"{indent}Note: {s}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"id": self.id, "check_id": self.check_id, "title": self.title, "blockers": self.blockers,
                "side_effects": self.side_effects, "needs_root": self.needs_root, "via": dict(self.via),
                "steps": [{"kind": a.kind, "text": a.describe(), "reversible": a.reversible,
                           "irreversible": a.destructive, "needs_root": a.needs_root, "commands": cmds,
                           "lines": a.preview()} for a, cmds in zip(self.actions, self.step_commands())],
                "irreversible_files": sum(len(a.files) for a in self.irreversible if isinstance(a, DeleteFiles))}


@dataclass
class ApplyResult:
    ok: bool
    entry_id: str | None
    applied: list[str]
    error: str = ""
    rolled_back: list[str] = field(default_factory=list)


def apply_plan(plan: FixPlan, host: Host, log: "UndoLog", confirmed_irreversible: bool = False) -> ApplyResult:
    if plan.blockers:
        return ApplyResult(False, None, [], "Can't apply: " + "; ".join(plan.blockers))
    if plan.irreversible and not confirmed_irreversible:
        return ApplyResult(False, None, [], "This fix deletes files permanently; confirm that first.")
    entry_id = uuid.uuid4().hex
    ctx = FixContext(host, log.backup_dir(entry_id))
    records: list[dict] = []
    failed_at = None
    try:
        for a in plan.actions:
            failed_at = a
            rec, ran = _doing(lambda: a.apply(ctx))
            if ran and not rec.get("ran"):
                rec["ran"] = ran
            records.append(rec)
    except Exception as e:  # noqa: BLE001 - roll back whatever was changed, then report
        error = f"{type(e).__name__}: {e}" if not isinstance(e, FixError) else str(e)
        if isinstance(e, FixError) and e.record:       # the failing step had changed something: kept, and put back
            records.append(e.record)
        rolled = []
        for rec in reversed(records):
            # each step that ran is put back, and what putting it back ran is kept with it, as a revert's is
            try:
                res, ran = _doing(lambda: ACTION_KINDS[rec["kind"]].revert(rec, ctx, force=True))
            except Exception as e2:  # noqa: BLE001 - one step that can't be put back doesn't stop the others
                res, ran = RevertResult(False, str(e2) if isinstance(e2, FixError) else f"{type(e2).__name__}: {e2}"), []
            if rec["kind"] in IRREVERSIBLE_KINDS:
                continue
            rec["reverted"] = res.ok
            if res.ok and (res.ran or ran):
                rec["revert_ran"] = res.ran or ran
            rolled.append(res.message if res.ok else f"NOT put back: {res.message}")
        if records:
            # the attempt changed something: History keeps it, as failed, with what each step did and what
            # putting it back did, so the user can see what happened (and revert a step that couldn't be)
            log.add(entry_id, plan.check_id, plan.title, records, state="failed",
                    extra={"via": dict(plan.via) or {"fix": True}, "error": error,
                           "failed_step": failed_at.describe() if failed_at is not None else ""})
            return ApplyResult(False, entry_id, [], error, rolled)
        return ApplyResult(False, None, [], error, rolled)
    log.add(entry_id, plan.check_id, plan.title, records, extra={"via": dict(plan.via) or {"fix": True}})
    return ApplyResult(True, entry_id, [r["text"] for r in records])


def revert_entry(entry: dict, host: Host, log: "UndoLog", force: bool = False) -> list[RevertResult]:
    ctx = FixContext(host, log.backup_dir(entry["id"]))
    results = []
    for rec in reversed(entry["records"]):
        if rec.get("reverted") or rec["kind"] in IRREVERSIBLE_KINDS:
            continue
        if rec.get("backup_dropped"):              # kept only for a while, and gone: said, and left as it is
            results.append(RevertResult(True, ACTION_KINDS[rec["kind"]].undo_hint(rec)))
            continue
        try:
            res, ran = _doing(lambda: ACTION_KINDS[rec["kind"]].revert(rec, ctx, force))
        except Exception as e:  # noqa: BLE001 - one step failing doesn't stop the others
            res, ran = RevertResult(False, str(e) if isinstance(e, FixError) else f"{type(e).__name__}: {e}"), []
        rec["reverted"] = res.ok
        if res.ok and (res.ran or ran):
            rec["revert_ran"] = res.ran or ran
        results.append(res)
    log.update(entry)
    return results


@action
class ClearInFile(Action):
    """Removes history from inside a file that also holds settings (e.g. a media player's recent
    list). Like deleting, it isn't backed up: a backup would keep the history being removed."""
    kind = "clear"
    reversible = False
    destructive = True
    phase = 2

    def __init__(self, path: Path, edit: Callable[[str], str], text: str, display: str, settings: bool = False):
        self.path, self.edit, self.text, self.display = path, edit, text, display
        # a settings file (key=value lines): the dry run shows which keys change, never their values. Off for
        # anything else, such as a shell history, whose lines can hold what is being removed.
        self.settings = settings

    def describe(self) -> str:
        what = f"{self.text}, in {self.display}"
        if self.path.is_symlink():
            real = str(self.path.resolve())
            home = os.path.expanduser("~")
            real = "~" + real[len(home):] if real.startswith(home + "/") else real
            what += f" (a link: the file it points to, {real}, is the one changed)"
        return what + ": only these lines change, the file and the rest of it stay"

    def preview(self) -> list[str]:
        """The keys whose lines change, values hidden ("- list=…", "+ list="): the history being cleared isn't shown.
        Lines that aren't a plain key=value are counted, never shown."""
        if not self.settings:
            return []
        old = _read_bytes(self.path)
        if old is None:
            return []
        text = old.decode("utf-8", errors="surrogateescape")
        out, other = [], 0
        for ln in changed_lines(text, self.edit(text)):
            m = re.match(r"([+-]) ([A-Za-z0-9_.\-\[\]\$/\\]+)=(.*)$", ln)
            if m:
                out.append(f"{m.group(1)} {m.group(2)}=" + ("…" if m.group(3) else ""))
            elif ln.startswith(("+ ", "- ")):
                other += 1
            else:
                out.append(ln)
        if other:
            out.append(f"… and {other} other line{'s' if other != 1 else ''}")
        return out

    def apply(self, ctx: FixContext) -> dict:
        old = _read_bytes(self.path)
        if old is not None:
            _write_atomic(self.path, self.edit(old.decode("utf-8", errors="surrogateescape")).encode(
                "utf-8", errors="surrogateescape"))
        return {"kind": self.kind, "text": f"{self.text} ({self.display})"}

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        return RevertResult(False, "Cleared history can't be restored")


@action
class ChmodPath(Action):
    """A file or folder's permissions."""
    kind = "chmod"

    @staticmethod
    def undo_hint(record: dict) -> str:
        return shell(["chmod", f"{record['before']:o}", record['path']])

    def __init__(self, path: Path, mode: int, display: str):
        self.path, self.mode, self.display = path, mode, display

    def describe(self) -> str:
        return shell(["chmod", f"{self.mode:o}", self.display])

    def apply(self, ctx: FixContext) -> dict:
        before = stat.S_IMODE(os.lstat(self.path).st_mode)
        os.chmod(self.path, (before & ~0o777) | self.mode)
        did(shell(["chmod", f"{self.mode:o}", str(self.path)]))
        after = stat.S_IMODE(os.lstat(self.path).st_mode)
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "before": before, "after": after,
                "text": f"{self.display}: mode {before:o} → {after:o}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(["chmod", f"{record['after'] & 0o777:o}", record["path"]])]

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        try:
            now = stat.S_IMODE(os.lstat(Path(record["path"])).st_mode)
        except FileNotFoundError:
            return f"{record['display']} no longer exists"
        return f"{record['display']} is mode {now:o} again (the fix set {record['after']:o})" \
            if now != record["after"] else None

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        p = Path(record["path"])
        try:
            now = stat.S_IMODE(os.lstat(p).st_mode)
        except FileNotFoundError:
            return RevertResult(False, f"{record['display']} no longer exists")
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{record['display']}'s permissions have changed since (now {now:o})", True)
        os.chmod(p, record["before"])
        did(shell(["chmod", f"{record['before']:o}", record["path"]]))
        return RevertResult(True, f"{record['display']} back to mode {record['before']:o}")


@action
class MakeDir(Action):
    """A folder of the user's, created if missing (e.g. one for screenshots to go in). Reverting
    removes it if it is still empty, and leaves it, saying so, if not. `phase=4` creates it after
    the plan's deletions (a folder put where a file was, so nothing can write that file)."""
    kind = "mkdir"

    def __init__(self, path: Path, display: str, mode: int = 0o755, phase: int = 0, note: str = "",
                 owned: tuple[str, ...] = ()):
        self.path, self.display, self.mode, self.phase = path, display, mode, phase
        self.note = note                # what the folder is for, beside the command (never in it: it can be pasted)
        # names in it that are the app's own, not the user's (a Box's runs.json, the empty mount point bubblewrap
        # makes for its Exchange folder): reverting removes them first, a regular file or an empty folder only
        self.owned = tuple(owned)

    def describe(self) -> str:
        cmd = shell(["mkdir", *(["-m", f"{self.mode:o}"] if self.mode != 0o755 else []), self.display])
        return f"{cmd}   ({self.note})" if self.note else cmd

    @staticmethod
    def undo_hint(record: dict) -> str:
        if not record.get("created"):
            return ""
        first = [shell(["rmdir" if folder else "rm", os.path.join(record["path"], name)])
                 for name, folder in MakeDir._owned(record)]
        return "; ".join(first + [shell(["rmdir", record["path"]])]) + "   (if empty" + (
            ": the app's own files in it go first)" if first else ")")

    @staticmethod
    def _owned(record: dict) -> list[tuple[str, bool]]:
        """(name, is a folder) for each of the app's own names in it: "name/" is an empty folder, "name" a file."""
        out = []
        for entry in record.get("owned") or []:
            name = entry.rstrip("/")
            if isinstance(entry, str) and name and "/" not in name and name not in (".", ".."):
                out.append((name, entry.endswith("/")))
        return out

    def apply(self, ctx: FixContext) -> dict:
        created = not self.path.exists()
        if created:
            self.path.mkdir(parents=False, mode=self.mode)
            os.chmod(self.path, self.mode)                  # mkdir's mode is filtered by the umask
            did(shell(["mkdir", "-m", f"{self.mode:o}", str(self.path)]))
        elif not self.path.is_dir() or self.path.is_symlink():
            raise FixError(f"{self.display} exists and isn't a folder")
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "created": created,
                "mode": self.mode, "text": f"Created {self.display}" if created else f"{self.display} (already there)",
                **({"owned": list(self.owned)} if self.owned and created else {})}

    @staticmethod
    def ran(record: dict) -> list[str]:
        if not record.get("created"):
            return []
        return [shell(["mkdir", "-m", f"{record.get('mode', 0o755):o}", record["path"]])]

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        p = Path(record["path"])
        return None if p.is_dir() and not p.is_symlink() else f"{record['display']} is no longer a folder"

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        if not record.get("created"):
            return RevertResult(True, "Nothing to undo")
        for name, folder in MakeDir._owned(record):
            p = os.path.join(record["path"], name)
            try:
                st = os.lstat(p)
                if folder and stat.S_ISDIR(st.st_mode):
                    os.rmdir(p)                           # only while empty: what is in it is someone's
                    did(shell(["rmdir", p]))
                elif not folder and stat.S_ISREG(st.st_mode):
                    os.unlink(p)
                    did(shell(["rm", p]))
            except OSError:
                pass
        notes = remove_made_dirs([record["path"]])
        return RevertResult(True, "; ".join(notes) if notes else f"{record['display']} removed")


@action
class CopyTree(Action):
    """A folder copied to a new place of the user's (the program of a trial, kept in its Box). The place must
    not exist yet; links in it are copied as links. Reverting removes the copy, which is the fix's own: nothing
    of the user's is in it (a Box's data is in its home, another folder)."""
    kind = "copytree"

    def __init__(self, source: Path, dest: Path, display: str, what: str):
        self.source, self.dest, self.display, self.what = source, dest, display, what

    def describe(self) -> str:
        return f"{shell(['cp', '-a', str(self.source), self.display])}   ({self.what})"

    @staticmethod
    def undo_hint(record: dict) -> str:
        return shell(["rm", "-r", record["path"]])

    def apply(self, ctx: FixContext) -> dict:
        import shutil
        if self.dest.exists() or self.dest.is_symlink():
            raise FixError(f"{self.display} is already there")
        if not self.source.is_dir() or self.source.is_symlink():
            raise FixError(f"{self.what} isn't there any more")
        shutil.copytree(self.source, self.dest, symlinks=True)
        os.chmod(self.dest, 0o700)
        did(shell(["cp", "-a", str(self.source), str(self.dest)]))
        return {"kind": self.kind, "path": str(self.dest), "display": self.display,
                "text": f"Copied {self.what} to {self.display}"}

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        p = Path(record["path"])
        return None if p.is_dir() and not p.is_symlink() else f"{record['display']} is gone"

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        import shutil
        p = Path(record["path"])
        if p.is_symlink() or not p.exists():
            return RevertResult(True, f"{record['display']} was already gone")
        shutil.rmtree(p, ignore_errors=True)
        if p.exists():
            return RevertResult(False, f"{record['display']} couldn't be removed completely")
        return RevertResult(True, f"{record['display']} removed")


@action
class FileCommand(Action):
    """A command whose only lasting effect is on one of the user's files (e.g. `flatpak override
    --user` writing ~/.local/share/flatpak/overrides/<app>). The file is backed up first and put
    back on revert, as WriteFile does."""
    kind = "filecmd"

    def __init__(self, argv: list[str], path: Path, text: str, display: str):
        self.argv, self.path, self.text, self.display = argv, path, text, display

    def describe(self) -> str:
        return f"{shell(self.argv)}   ({self.text})"

    def apply(self, ctx: FixContext) -> dict:
        old = _read_bytes(self.path)
        dirs = made_dirs(self.path)
        backup = old_mode = None
        if old is not None:
            ctx.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
            backup = ctx.backups / f"{uuid.uuid4().hex}-{self.path.name}"
            _write_atomic(backup, old, 0o600)
            old_mode = self.path.stat().st_mode & 0o7777
        _change(ctx.host, *self.argv)
        after = _read_bytes(self.path)
        dec = lambda b: None if b is None else b.decode("utf-8", errors="surrogateescape")  # noqa: E731
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "backup": str(backup) if backup else None,
                "mode": old_mode, "after_sha": _sha(after), "text": f"{self.text} ({shell(self.argv)})", "argv": self.argv,
                "lines": changed_lines(dec(old), dec(after) or ""), "dirs": dirs}

    @staticmethod
    def ran(record: dict) -> list[str]:
        return [shell(record["argv"])] if record.get("argv") else []

    revert = WriteFile.revert
    undo_hint = WriteFile.undo_hint


@action
class HashKnownHosts(Action):
    """`ssh-keygen -H` on a known_hosts file: the server names are replaced by hashes that ssh
    can still match. The plain copy ssh-keygen leaves beside it (known_hosts.old) is removed;
    the original is kept in the undo backups for BACKUP_DAYS, so revert can put the names back
    meanwhile, and then deleted (`UndoLog.expire_backups`): kept for good, it would be the very list
    the fix hides. History can delete it sooner (`UndoLog.drop_backups`)."""
    kind = "hashkh"
    BACKUP_DAYS = 7

    def __init__(self, path: Path, display: str):
        self.path, self.display = path, display

    def describe(self) -> str:
        return (f"{shell(['ssh-keygen', '-H', '-f', self.display])}, then delete the plain copy {self.display}.old; "
                f"a plain copy is kept in History's backups for {self.BACKUP_DAYS} days, so this can be reverted, "
                "then deleted")

    @staticmethod
    def undo_hint(record: dict) -> str:
        if record.get("backup_dropped"):
            return "Can't be undone: the plain copy kept for revert was deleted, and hashed names can't be turned back."
        until = time.strftime("%Y-%m-%d", time.localtime(record["backup_expires"])) if record.get("backup_expires") else ""
        if not until or not record.get("backup"):
            return WriteFile.undo_hint(record)
        # said once: the plain copy is kept only until then (not "until the entry is forgotten", as other backups are)
        return f"{shell(['cp', record['backup'], record['path']])}   (the plain copy is kept until {until}, then deleted)"

    def apply(self, ctx: FixContext) -> dict:
        old = _read_bytes(self.path)
        if old is None:
            raise FixError(f"{self.display} no longer exists")
        ctx.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup = ctx.backups / f"{uuid.uuid4().hex}-{self.path.name}"
        _write_atomic(backup, old, 0o600)
        _change(ctx.host, "ssh-keygen", "-H", "-f", str(self.path))
        plain = self.path.with_name(self.path.name + ".old")
        try:
            plain.unlink()
            did(shell(["rm", str(plain)]))
        except FileNotFoundError:
            pass
        return {"kind": self.kind, "path": str(self.path), "display": self.display, "backup": str(backup),
                "backup_expires": time.time() + self.BACKUP_DAYS * 86400, "mode": stat.S_IMODE(os.stat(self.path).st_mode),
                "after_sha": _sha(_read_bytes(self.path)), "text": f"Hashed the server names in {self.display}"}

    @staticmethod
    def ran(record: dict) -> list[str]:
        # the file's lines aren't shown: they are the server names this hides
        return [shell(["ssh-keygen", "-H", "-f", record["path"]]), shell(["rm", "-f", record["path"] + ".old"])]

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        if record.get("backup_dropped"):
            return RevertResult(False, f"The server names in {record['display']} can't be put back: the plain copy kept "
                                       "for revert was deleted, as planned")
        return WriteFile.revert(record, ctx, force)


_PREF_LINE = re.compile(r'^\s*user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;\s*$')


def read_prefs(path: Path) -> dict:
    out = {}
    for line in (Host.read_file(path) or "").splitlines():
        m = _PREF_LINE.match(line)
        if m:
            try:
                out[m.group(1)] = json.loads(m.group(2))
            except ValueError:
                out[m.group(1)] = m.group(2)
    return out


def set_pref(text: str, key: str, value) -> str:
    """prefs.js with `key` set to `value` (None removes it), changing no other line."""
    lines = text.splitlines(keepends=True)
    out, done = [], False
    for line in lines:
        m = _PREF_LINE.match(line)
        if m and m.group(1) == key:
            if value is not None and not done:
                out.append(f'user_pref("{key}", {json.dumps(value)});\n')
            done = True
            continue
        out.append(line)
    if value is not None and not done:
        if out and not out[-1].endswith("\n"):
            out[-1] += "\n"
        out.append(f'user_pref("{key}", {json.dumps(value)});\n')
    return "".join(out)


@action
class FirefoxPref(Action):
    """One preference in a Firefox or Thunderbird profile's prefs.js, changed while the app is
    closed (it rewrites prefs.js as it exits). Reverting puts back that one preference, leaving
    the rest of prefs.js as the browser has since written it."""
    kind = "ffpref"

    @staticmethod
    def undo_hint(record: dict) -> str:
        to = json.dumps(record["before"]) if record["before"] is not None else "its default (Reset)"
        return f"{record['label']}: about:config, set {record['key']} to {to} (with the browser open)"

    def __init__(self, profile: Path, label: str, key: str, value, display: str):
        self.profile, self.label, self.key, self.value, self.display = profile, label, key, value, display

    def describe(self) -> str:
        return f'{self.label}: set {self.key} to {json.dumps(self.value)} ({self.display}/prefs.js)'

    def preview(self) -> list[str]:
        return [f'+ user_pref("{self.key}", {json.dumps(self.value)});']

    def apply(self, ctx: FixContext) -> dict:
        path = self.profile / "prefs.js"
        if _profile_in_use(ctx.host, self.profile):
            raise FixError(f"{self.label} is open; close it first")
        before = read_prefs(path).get(self.key)
        created = not os.path.lexists(path)
        _write_atomic(path, set_pref(Host.read_file(path) or "", self.key, self.value).encode())
        did(f'# {self.key} set to {json.dumps(self.value)} in {self.profile}/prefs.js (with {self.label} closed)')
        return {"kind": self.kind, "profile": str(self.profile), "label": self.label, "key": self.key,
                "before": before, "after": self.value, "created_file": created,
                "text": f"{self.label}: {self.key} {json.dumps(before) if before is not None else '(default)'} → "
                        f"{json.dumps(self.value)}",
                "lines": ([f'- user_pref("{self.key}", {json.dumps(before)});'] if before is not None else [])
                + [f'+ user_pref("{self.key}", {json.dumps(self.value)});']}

    @staticmethod
    def changed_back(record: dict, host: Host) -> str | None:
        now = read_prefs(Path(record["profile"]) / "prefs.js").get(record["key"])
        if now == record["after"]:
            return None
        shown = json.dumps(now) if now is not None else "its default"
        return f"{record['label']}: {record['key']} is {shown} again (the fix set {json.dumps(record['after'])})"

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        profile = Path(record["profile"])
        if _profile_in_use(ctx.host, profile):
            return RevertResult(False, f"{record['label']} is open; close it and revert again")
        path = profile / "prefs.js"
        now = read_prefs(path).get(record["key"])
        if now not in (record["after"], record["before"]) and not force:
            return RevertResult(False, f"{record['label']}: {record['key']} has changed since", True)
        _write_atomic(path, set_pref(Host.read_file(path) or "", record["key"], record["before"]).encode())
        did(f'# {record["key"]} back to {json.dumps(record["before"]) if record["before"] is not None else "its default"} '
            f'in {record["profile"]}/prefs.js (with {record["label"]} closed)')
        if record.get("created_file") and not read_prefs(path) and not path.is_symlink():
            path.unlink()                               # the fix made prefs.js, and nothing else is in it
            did(shell(["rm", str(path)]))
        return RevertResult(True, f"{record['label']}: {record['key']} back to "
                                  f"{json.dumps(record['before']) if record['before'] is not None else 'its default'}")


FIREFOX_PROCESSES = frozenset({"firefox", "firefox-bin", "firefox-esr", "librewolf", "thunderbird", "thunderbird-bin",
                               "GeckoMain"})


def _profile_in_use(host: Host, profile: Path) -> bool:
    """Whether a Firefox-family program has this profile open: it keeps a `lock` symlink in the
    profile while it runs (left behind after a crash, so alone it isn't enough), and then either
    a known program is running or some process of the user's holds a file in the profile (what
    fuser would show: a fork under another name, Waterfox or Zen say, counts the same)."""
    from .checks._util import open_files, processes
    try:
        if not (profile / "lock").is_symlink():
            return False
    except OSError:
        return False
    if processes(host) & FIREFOX_PROCESSES:
        return True
    root = str(profile.resolve()).rstrip("/") + "/"
    return any(any(p.startswith(root) for p in paths) for _, paths in open_files(host))


def _helper(ctx: FixContext):
    if ctx.host.privileged is None:
        raise FixError("This step needs administrator access, which wasn't granted.")
    return ctx.host.privileged


def _call(ctx: FixContext, request: str, args: dict):
    from .privileged import HelperError
    try:
        return _helper(ctx).call(request, args)
    except HelperError as e:
        raise FixError(f"The administrator helper refused: {e}", data=getattr(e, "data", None)) from None


@action
class RootChange(Action):
    """A change made as root by the privileged helper, which keeps what was there before in its
    own journal. The undo record only holds the helper's change id."""
    kind = "root"
    needs_root = True

    @staticmethod
    def undo_hint(record: dict) -> str:
        if not record.get("change_id"):
            return ""
        return ("Revert it in the app; what was there before is kept in "
                f"/var/lib/daprivacyscanner/changes/{record['change_id']}.json (root only)")

    def __init__(self, request: str, args: dict, text: str, phase: int = 0):
        self.request, self.args, self.text = request, args, text
        self.phase = phase              # 3: only after the plan's deletions (a mount over a folder hides its files)

    def describe(self) -> str:
        return self.text

    def commands(self) -> list[str]:
        return planned_as_root(self.request, self.args)

    def preview(self) -> list[str]:
        from . import helper
        try:
            files = helper.planned_files(self.request, self.args, home=os.path.realpath(os.path.expanduser("~")))
        except Exception:  # noqa: BLE001 - a dry run's extra detail, never a reason the plan fails
            return []
        if len(files) == 1:
            return changed_lines(files[0][1], files[0][2])
        return [ln for path, old, new in files for ln in [f"# {path}", *changed_lines(old, new)]]

    def apply(self, ctx: FixContext) -> dict:
        lines = self.preview()                          # what the drop-in will hold, read before it is written
        try:
            r = _call(ctx, self.request, self.args)
        except FixError as e:
            if e.data.get("change_id"):                 # it changed something before failing, and the helper kept it
                e.record = {"kind": self.kind, "change_id": e.data["change_id"], "text": f"{self.text} (failed part way)",
                            "ran": list(e.data.get("ran") or []), "files": [], "lines": [], "dirs": []}
            raise
        warn = "; ".join(r.get("warnings") or [])
        if not r.get("changed"):
            return {"kind": self.kind, "change_id": None, "text": f"{self.text} (already so)"}
        return {"kind": self.kind, "change_id": r["change_id"],
                "text": self.text + (f" (warning: {warn})" if warn else ""),
                "ran": list(r.get("ran") or []), "files": list(r.get("files") or []), "lines": lines,
                "dirs": list(r.get("dirs") or [])}

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        if not record.get("change_id"):
            return RevertResult(True, "Nothing to undo")
        r = _call(ctx, "revert", {"change_id": record["change_id"], "force": force})
        return RevertResult(bool(r.get("ok")), r.get("message", ""), bool(r.get("conflict")), list(r.get("ran") or []))


def planned_as_root(request: str, args: dict) -> list[str]:
    """What the helper will run for this change (helper.planned), for the dry run."""
    from . import helper
    return helper.planned(request, args, os.path.realpath(os.path.expanduser("~")))


@action
class RootClear(Action):
    """Deleting as root (old crash dumps, journal files). Irreversible, confirmed separately."""
    kind = "root-clear"
    reversible = False
    destructive = True
    needs_root = True
    phase = 2

    def __init__(self, request: str, args: dict, text: str):
        self.request, self.args, self.text = request, args, text

    def describe(self) -> str:
        return self.text

    def commands(self) -> list[str]:
        return planned_as_root(self.request, self.args)

    def apply(self, ctx: FixContext) -> dict:
        r = _call(ctx, self.request, self.args)
        done = f"{r['deleted']} files deleted" if "deleted" in r else f"{r.get('freed', '0B')} freed" if "freed" in r else "done"
        if r.get("emptied"):
            done = f"{r['emptied']} emptied, {done}"
        return {"kind": self.kind, "text": f"{self.text}: {done}", "ran": list(r.get("ran") or [])}

    @staticmethod
    def revert(record: dict, ctx: FixContext, force: bool = False) -> RevertResult:
        return RevertResult(False, "Deleted files can't be restored")
