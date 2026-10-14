"""The apps in the desktop's menu (docs/TECHNICAL.md, Tools): what "What does this app keep?" and "Try an app"
let the user choose from. Read from the .desktop files in the data folders (the system's, the user's, Flatpak's
exports), as the menu does: an entry that is hidden there is left out here. Nothing is started from here."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

from ..host import Host
from .viewer import FIELD_DROP, FIELD_FILE, _data_dirs, desktop_entry

APPS_MAX = 600


@dataclass
class App:
    id: str                                      # its .desktop file's name
    name: str
    argv: list[str]                              # its command, the menu's placeholders (%f, %U…) taken out
    kind: str                                    # native, flatpak, snap
    comment: str = ""
    flatpak: str | None = None                   # its Flatpak app id
    snap: str | None = None                      # its Snap's name
    terminal: bool = False
    env: dict[str, str] = field(default_factory=dict)   # what its command set with `env NAME=value`

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "kind": self.kind, "comment": self.comment,
                "command": shlex.join(self.argv), "terminal": self.terminal}


def _from(desktop_id: str, entry: dict[str, str]) -> App | None:
    if entry.get("Type", "Application") != "Application" or entry.get("Hidden", "").lower() == "true":
        return None
    try:
        argv = shlex.split(entry.get("Exec", ""))
    except ValueError:
        return None
    env = {}
    while argv and (argv[0] == "env" or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", argv[0])):
        if argv[0] != "env":
            k, v = argv[0].split("=", 1)
            env[k] = v
        argv = argv[1:]
    argv = [a.replace("%%", "%") for a in argv if a not in FIELD_FILE and a not in FIELD_DROP]
    if not argv:
        return None
    base = os.path.basename(argv[0])
    flatpak = entry.get("X-Flatpak") or (next((a for a in argv[2:] if not a.startswith("-")), None)
                                         if base == "flatpak" and "run" in argv[:3] else None)
    snap = entry.get("X-SnapInstanceName") or (argv[0].split("/")[3] if argv[0].startswith("/snap/bin/") else None)
    kind = "flatpak" if flatpak else "snap" if snap or base == "snap" else "native"
    return App(desktop_id, entry.get("Name", desktop_id[:-8]), argv, kind, entry.get("Comment", ""),
               flatpak if kind == "flatpak" else None, snap if kind == "snap" else None,
               entry.get("Terminal", "").lower() == "true", env)


def app(host: Host, desktop_id: str) -> App | None:
    """The menu's entry `desktop_id`, or None when there is none that can be started."""
    found = desktop_entry(host, desktop_id) if isinstance(desktop_id, str) else None
    return _from(desktop_id, found[1]) if found else None


def apps(host: Host) -> list[App]:
    """Every app the menu shows (not NoDisplay), by name. The first data folder that has an entry wins, as in
    the menu."""
    seen: dict[str, App | None] = {}
    for d in _data_dirs(host):
        folder = d / "applications"
        folder = folder if str(folder).startswith(str(host.home)) else host.sys_path(str(folder))
        try:
            names = sorted(n for n in os.listdir(folder) if n.endswith(".desktop"))
        except OSError:
            continue
        for name in names:
            if name in seen or len(seen) >= APPS_MAX or not re.fullmatch(r"[\w.+-]+\.desktop", name):
                continue
            found = desktop_entry(host, name)
            if not found:
                continue
            entry = found[1]
            seen[name] = None if entry.get("NoDisplay", "").lower() == "true" else _from(name, entry)
    return sorted((a for a in seen.values() if a is not None), key=lambda a: (a.name.lower(), a.id))
