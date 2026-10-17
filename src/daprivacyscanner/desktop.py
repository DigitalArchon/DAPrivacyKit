"""Desktop environment detection and the version differences checks must not handle themselves:

- KDE Plasma 5 vs 6: kreadconfig5/kreadconfig6, balooctl/balooctl6, and some state that moved
  from ~/.config to ~/.local/state. A missing KDE config key means "default", never "off".
- GNOME 47+ renamed Tracker to LocalSearch (`localsearch` vs `tracker3`).
- gsettings values, parsed from GVariant text; a missing schema or key is None, not False."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path

from . import ini
from .host import Host
from .paths import PathResolver

_VERSION = re.compile(r"(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class DesktopInfo:
    names: tuple[str, ...]           # $XDG_CURRENT_DESKTOP, lower case, e.g. ("ubuntu", "gnome")
    plasma_major: int | None = None
    gnome_major: int | None = None

    @property
    def is_kde(self) -> bool:
        return "kde" in self.names

    @property
    def is_gnome(self) -> bool:
        return "gnome" in self.names

    @property
    def session(self) -> bool:
        """Whether the scan runs in a desktop session: a scan from a terminal or over SSH has none ($XDG_CURRENT_DESKTOP
        unset), so which desktop the user logs in to can't be told."""
        return bool(self.names)

    @property
    def label(self) -> str:
        if self.is_kde:
            return f"KDE Plasma {self.plasma_major}" if self.plasma_major else "KDE Plasma"
        if self.is_gnome:
            return f"GNOME {self.gnome_major}" if self.gnome_major else "GNOME"
        return self.names[0].removeprefix("x-").capitalize() if self.names else "no desktop session"

    @property
    def this(self) -> str:
        """The desktop in a sentence saying what a fix covers: "this is KDE Plasma 6", or "this scan ran without a
        desktop session" (from a terminal or over SSH)."""
        return f"this is {self.label}" if self.names else "this scan ran without a desktop session"

    def to_dict(self) -> dict:
        return {"names": list(self.names), "plasma_major": self.plasma_major, "gnome_major": self.gnome_major,
                "label": self.label}


def _major(text: str) -> int | None:
    m = _VERSION.search(text or "")
    return int(m.group(1)) if m else None


def detect_desktop(host: Host) -> DesktopInfo:
    names = tuple(n.strip().lower() for n in host.environ.get("XDG_CURRENT_DESKTOP", "").split(":") if n.strip())
    plasma = gnome = None
    if "kde" in names:
        plasma = _major(host.environ.get("KDE_SESSION_VERSION", ""))
        if plasma is None:
            r = host.run("plasmashell", "--version")
            plasma = _major(r.stdout) if r.ok else None
    if "gnome" in names:
        r = host.run("gnome-shell", "--version")
        gnome = _major(r.stdout.replace("GNOME Shell", "")) if r.ok else None
    return DesktopInfo(names, plasma, gnome)


# ------------------------------------------------------------------ KDE

class KDE:
    """Reads KConfig files directly (not through kreadconfig), so checks behave the same against
    fixture homes: the user file layered over $XDG_CONFIG_DIRS defaults."""

    # Plasma 6 moved these from $XDG_CONFIG_HOME to $XDG_STATE_HOME. VERIFY on each Plasma
    # release before relying on the list; kconfig_path() looks in both places regardless.
    STATE_FILES = frozenset({"dolphinstaterc", "katestaterc", "kwritestaterc", "okularstaterc",
                             "gwenviewstaterc", "konsolestaterc", "plasmashellstaterc"})

    def __init__(self, host: Host, paths: PathResolver, info: DesktopInfo):
        self.host, self.paths, self.info = host, paths, info

    @property
    def major(self) -> int | None:
        if self.info.plasma_major:
            return self.info.plasma_major
        if self.host.runner.which("kreadconfig6"):
            return 6
        if self.host.runner.which("kreadconfig5"):
            return 5
        return None

    def tool(self, name: str) -> str:
        """The command for this Plasma version: tool("kreadconfig") -> "kreadconfig6",
        tool("balooctl") -> "balooctl6" on Plasma 6 and "balooctl" on Plasma 5."""
        major = self.major or 6
        if name == "balooctl":
            return "balooctl6" if major >= 6 else "balooctl"
        if name in ("kreadconfig", "kwriteconfig"):
            return f"{name}{major}"
        return name

    def kconfig_path(self, filename: str) -> Path | None:
        """The user's copy of a KConfig file, wherever this Plasma version keeps it."""
        candidates = [self.paths.state_home / filename, self.paths.config_home / filename]
        if filename not in self.STATE_FILES:
            candidates.reverse()
        return next((p for p in candidates if p.is_file()), None)

    def read(self, filename: str) -> dict[ini.Group, dict[str, str]]:
        layers = []
        for d in reversed(self.paths.config_dirs()):
            text = self.host.read_file(self.host.sys_path(d / filename))
            if text is not None:
                layers.append(ini.parse(text, kde=True))
        user = self.kconfig_path(filename)
        if user is not None:
            text = self.host.read_file(user)
            if text is not None:
                layers.append(ini.parse(text, kde=True))
        return ini.merge(*layers)

    def get(self, filename: str, group: str | ini.Group, key: str) -> str | None:
        """A key's value, or None when it isn't set (the app's built-in default applies)."""
        return ini.get(self.read(filename), group, key)

    def applet(self, plugin: str) -> TrayApplet:
        """Where Plasma runs an applet: the system trays that list it, and anywhere else."""
        return tray_applet(self.host.read_file(self.paths.config_home / APPLETSRC) or "", plugin)

    def dbus(self, dest: str, path: str, method: str, *args: str) -> list[str] | None:
        """A call on the session bus as a command, with string arguments: Qt's qdbus (named differently by
        each distribution), else dbus-send. None when neither is installed."""
        for tool in ("qdbus6", "qdbus-qt6", "qdbus", "qdbus-qt5"):
            if self.host.runner.which(tool):
                return [tool, dest, path, method, *args]
        if self.host.runner.which("dbus-send"):
            return ["dbus-send", "--session", "--print-reply", f"--dest={dest}", path, method,
                    *(f"string:{a}" for a in args)]
        return None


# Plasma's panels, desktops and their applets, written by plasmashell
APPLETSRC = "plasma-org.kde.plasma.desktop-appletsrc"
SYSTRAY = "org.kde.plasma.systemtray"
SYSTRAY_5 = "org.kde.plasma.private.systemtray"     # Plasma 5: the tray's own containment


@dataclass(frozen=True)
class TrayApplet:
    trays: tuple[str, ...] = ()     # the Plasma 6 system tray applets (their ids) that list it: tray_script() reaches them
    tray5: bool = False             # a Plasma 5 tray lists it
    widget: bool = False            # a widget of its own, on a panel or the desktop

    @property
    def on(self) -> bool:
        return bool(self.trays) or self.tray5 or self.widget


def tray_applet(text: str, plugin: str) -> TrayApplet:
    """Where an applet is in Plasma's applets file. A Plasma 6 tray is an applet of a panel
    ([Containments][P][Applets][T], its entries in [General] extraItems, each loaded one under it); a Plasma 5
    tray is a containment of its own ([Containments][N], plugin org.kde.plasma.private.systemtray). Turning an
    entry off in System Tray Settings takes it out of extraItems and removes the applet under the tray
    (tested on Plasma 6.7)."""
    groups = ini.parse(text, kde=True)
    trays, tray5, widget = [], False, False

    def listed(g: ini.Group) -> bool:
        return plugin in [x.strip() for x in groups.get(g + ("General",), {}).get("extraItems", "").split(",")]

    for g, keys in groups.items():
        kind = keys.get("plugin")
        if kind == SYSTRAY and len(g) == 4 and g[0] == "Containments" and g[2] == "Applets":
            if listed(g) or any(len(h) == 6 and h[:4] == g and groups[h].get("plugin") == plugin for h in groups):
                trays.append(g[3])
        elif kind == SYSTRAY_5 and listed(g):
            tray5 = True
        elif kind == plugin:
            parent = groups.get(g[:-2], {}).get("plugin")
            tray5 |= parent == SYSTRAY_5
            widget |= parent not in (SYSTRAY, SYSTRAY_5)
    return TrayApplet(tuple(trays), tray5, widget)


def tray_script(plugin: str, on: bool, trays: list[str] | tuple[str, ...]) -> str:
    """plasmashell's own script (org.kde.PlasmaShell.evaluateScript) that turns an entry of the given Plasma 6
    system trays on or off, as System Tray Settings → Entries does: the tray loads or unloads it at once.
    It prints "ok:ID" for each tray changed, "empty:ID" for one whose list it couldn't read (it is left
    alone: writing a list read as empty would take every entry out). Tested on Plasma 6.7."""
    ids = ",".join(f'"{t}"' for t in trays if t.isdigit())
    return ("var P=%s,ON=%s,IDS=[%s],r=[];desktops().concat(panels()).forEach(function(c){"
            "c.widgets(%s).forEach(function(w){if(IDS.indexOf(String(w.id))<0)return;"
            "w.currentConfigGroup=[\"General\"];var s=String(w.readConfig(\"extraItems\",\"\"));"
            "if(!s){r.push(\"empty:\"+w.id);return}var i=s.split(\",\").filter(function(x){return x&&x!=P});"
            "if(ON)i.push(P);w.writeConfig(\"extraItems\",i);w.reloadConfig();r.push(\"ok:\"+w.id)})});"
            "print(r.join(\" \"))") % (f'"{plugin}"', "true" if on else "false", ids, f'"{SYSTRAY}"')


# ------------------------------------------------------------------ GNOME

class GNOME:
    def __init__(self, host: Host, info: DesktopInfo):
        self.host, self.info = host, info
        # schema -> {key: GVariant text}, read once with `gsettings list-recursively` (one process per
        # schema instead of one per key); None when that isn't possible and keys are read one by one
        self._schemas: dict[str, dict[str, str] | None] = {}
        self._lock = threading.Lock()

    def indexer_command(self) -> str | None:
        """`localsearch` (GNOME 47+) or `tracker3` (older), whichever this system has."""
        prefer = ("localsearch", "tracker3") if (self.info.gnome_major or 47) >= 47 else ("tracker3", "localsearch")
        return next((c for c in prefer if self.host.runner.which(c)), None)

    def _schema(self, schema: str) -> dict[str, str] | None:
        with self._lock:
            if schema not in self._schemas:
                r = self.host.run("gsettings", "list-recursively", schema)
                values = None
                if r.ok and r.stdout.strip():
                    values = {}
                    for line in r.stdout.splitlines():
                        f = line.split(" ", 2)
                        if len(f) == 3 and f[0] == schema:
                            values[f[1]] = f[2].strip()
                self._schemas[schema] = values
            return self._schemas[schema]

    def gsettings(self, schema: str, key: str):
        """A gsettings value as Python (bool, int, float, str, list), or None if gsettings, the
        schema or the key is missing. Values are what the schema held when first read in this
        scan: a scan reads, so nothing changes them meanwhile."""
        values = self._schema(schema)
        if values is not None:
            return parse_gvariant(values[key]) if key in values else None
        r = self.host.run("gsettings", "get", schema, key)
        if not r.ok:
            return None
        return parse_gvariant(r.stdout.strip())


_TYPED = re.compile(r"^(?:u?int(?:16|32|64)|byte|double|@[a-z]+)\s+")


def parse_gvariant(text: str):
    """The subset of GVariant text format gsettings prints: booleans, numbers (with an optional
    type prefix such as "uint32 300"), quoted strings and arrays of those."""
    t = _TYPED.sub("", text.strip())
    if t in ("true", "false"):
        return t == "true"
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        return [parse_gvariant(item) for item in _split_array(inner)] if inner else []
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
        return re.sub(r"\\(.)", r"\1", t[1:-1])
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        return t


def _split_array(s: str) -> list[str]:
    items, depth, quote, cur = [], 0, None, []
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c in "[(":
            depth += 1
            cur.append(c)
        elif c in "])":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        items.append("".join(cur).strip())
    return items
