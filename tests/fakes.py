"""Stateful stand-ins for the tools fixes use, so a test can apply a fix, see the setting
change, revert it and see the old value back."""

from __future__ import annotations

import re
from pathlib import Path

from daprivacyscanner import ini
from daprivacyscanner.host import CommandResult

OK = CommandResult((), 0, "")


def fail(msg: str) -> CommandResult:
    return CommandResult((), 1, "", msg)


class FakeGSettings:
    def __init__(self, values: dict[tuple[str, str], str]):
        self.values = dict(values)              # (schema, key) -> GVariant text

    def __call__(self, argv):
        if argv[1] == "get" and len(argv) == 4:
            v = self.values.get((argv[2], argv[3]))
            return CommandResult(argv, 0, v + "\n") if v is not None else fail("No such key")
        if argv[1] == "set" and len(argv) == 5:
            if (argv[2], argv[3]) not in self.values:
                return fail("No such key")
            old = self.values[(argv[2], argv[3])]
            prefix = re.match(r"^(uint32|int32|int64) ", old)
            self.values[(argv[2], argv[3])] = argv[4] if not prefix or argv[4].startswith(prefix.group(0)) else \
                f"{prefix.group(1)} {argv[4]}"
            return OK
        return fail("bad gsettings call")


class FakeKwriteconfig:
    """kwriteconfig6 writing into the fixture's ~/.config, as the real one does."""

    def __init__(self, config_home: Path):
        self.config_home = config_home

    def __call__(self, argv):
        args = list(argv[1:])
        opts, value, delete = {}, None, False
        while args:
            a = args.pop(0)
            if a in ("--file", "--group", "--key", "--type"):
                opts[a] = args.pop(0)
            elif a == "--notify":
                continue
            elif a == "--delete":
                delete = True
            else:
                value = a
        path = self.config_home / opts["--file"]
        groups = ini.parse(path.read_text() if path.exists() else "", kde=True)
        groups.pop((), None)
        g = groups.setdefault((opts["--group"],), {})
        key = opts["--key"]
        g.pop(key, None)                    # KConfig reads and writes the key with its [$e] mark as the same key
        g.pop(key + "[$e]", None)
        if not delete and opts.get("--type") == "path":
            home = str(self.config_home.parent)     # as kwriteconfig6 does (tested): $HOME for the home folder at the start
            g[key + "[$e]"] = "$HOME" + value[len(home):] if value.startswith(home + "/") else value
        elif not delete:
            g[key] = value
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"[{']['.join(k)}]\n" + "".join(f"{a}={b}\n" for a, b in v.items()) + "\n"
                                for k, v in groups.items()))
        return OK


class FakeNmcli:
    def __init__(self, connections: dict[str, dict[str, str]]):
        self.connections = connections          # uuid -> {"type": ..., "connection.id": ..., prop: value}

    def __call__(self, argv):
        a = list(argv[1:])
        if a[:4] == ["-t", "-f", "UUID,TYPE", "connection"]:
            return CommandResult(argv, 0, "".join(f"{u}:{c['type']}\n" for u, c in self.connections.items()))
        if a[0] == "-g" and a[2:4] == ["connection", "show"]:
            c = self.connections.get(a[4])
            if c is None:
                return fail("no such connection profile")
            return CommandResult(argv, 0, "".join(c.get(f, "") + "\n" for f in a[1].split(",")))
        if a[:2] == ["connection", "modify"]:
            self.connections[a[2]][a[3]] = a[4]
            return OK
        return fail("bad nmcli call")


class FakeBluetoothctl:
    def __init__(self, powered="yes", discoverable="no", alias="laptop", name="laptop"):
        self.state = {"Powered": powered, "Discoverable": discoverable, "Alias": alias, "Name": name}

    def __call__(self, argv):
        cmd = argv[1]
        if cmd == "show":
            return CommandResult(argv, 0, "Controller 00:11:22:33:44:55 (public)\n" +
                                 "".join(f"\t{k}: {v}\n" for k, v in self.state.items()))
        if cmd in ("discoverable", "power"):
            self.state["Discoverable" if cmd == "discoverable" else "Powered"] = "yes" if argv[2] == "on" else "no"
            return OK
        if cmd == "system-alias":
            self.state["Alias"] = argv[2]
            return OK
        if cmd == "reset-alias":
            self.state["Alias"] = self.state["Name"]
            return OK
        return fail("bad bluetoothctl call")


def recorder(calls: list):
    """For commands with no state worth faking (pkill, systemctl, zeitgeist-daemon)."""
    def run(argv):
        calls.append(argv)
        return OK
    return run


class FakeSystem:
    """systemctl, ufw, journalctl and sshd, as the helper (helper.RUN) and the app (host.run, via
    `handler`) both call them, sharing one state."""

    def __init__(self, units=None, ufw_active=False, sshd_ok=True):
        self.units = {u: list(v) for u, v in (units or {}).items()}       # unit -> [enabled, active]
        self.ufw_active, self.ufw_rules, self.sshd_ok = ufw_active, [], sshd_ok
        self.calls = []
        self.mounted, self.busy = set(), set()        # mount units mounted; those that can't unmount (busy)
        self.linked = set()                           # unit files linked in with `systemctl enable /path`

    def __call__(self, argv):
        self.calls.append(list(argv))
        a = list(argv)
        if a[0] == "snapper":                          # its clean-up: nothing to delete in a fixture
            return 0, "", ""
        if a[0] == "systemctl":
            verb, unit = a[1], a[-1]
            if verb == "daemon-reload":
                return 0, "", ""
            if verb == "enable" and unit.startswith("/"):
                # `systemctl enable /path/x.mount`: links the file in, then enables it
                name = unit.rsplit("/", 1)[1]
                self.units[name] = ["enabled", "inactive"]
                self.linked.add(name)
                return 0, "", ""
            if verb == "disable" and unit in self.linked:
                del self.units[unit]                    # disable undoes the link too
                self.linked.discard(unit)
                return 0, "", ""
            if unit.endswith(".mount") and verb in ("enable", "disable"):
                # a mount unit the helper wrote: --now mounts (enable) or unmounts (disable) it
                u = self.units.setdefault(unit, ["disabled", "inactive"])
                u[0] = verb + "d"
                if "--now" in a and verb == "enable":
                    u[1] = "active"
                    self.mounted.add(unit)
                elif "--now" in a:
                    if unit in self.busy:
                        return 1, "", f"Job for {unit} failed: umount: target is busy."
                    u[1] = "inactive"
                    self.mounted.discard(unit)
                return 0, "", ""
            if verb == "show":
                return 0, "loaded\n" if unit in self.units else "not-found\n", ""
            names = [x for x in a[2:] if not x.startswith("--")]      # systemctl takes several units in one call
            if verb in ("mask", "unmask"):
                # masked: a link to /dev/null that nothing can start; unmasked, what its install links say (disabled,
                # as the helper disables before it masks)
                for n in names:
                    if n in self.units:
                        self.units[n][0] = "masked" if verb == "mask" else "disabled"
                return 0, "", ""
            if verb in ("enable", "disable", "start", "stop") and len(names) > 1 or "--now" in a:
                missing = [n for n in names if n not in self.units]
                if missing:
                    return 5, "", f"Unit {missing[0]} not loaded."
                for n in names:
                    u = self.units[n]
                    if verb in ("enable", "disable"):
                        u[0] = verb + "d"
                        if "--now" in a:
                            u[1] = "active" if verb == "enable" else "inactive"
                    else:
                        u[1] = "active" if verb == "start" else "inactive"
                return 0, "", ""
            if unit not in self.units:
                return 5, "", f"Unit {unit} not loaded."
            u = self.units[unit]
            if verb == "is-enabled":
                return (0 if u[0] == "enabled" else 1), u[0] + "\n", ""
            if verb == "is-active":
                return (0 if u[1] == "active" else 3), u[1] + "\n", ""
            if verb in ("enable", "disable"):
                u[0] = verb + "d"
            elif verb in ("start", "stop"):
                u[1] = "active" if verb == "start" else "inactive"
            return 0, "", ""
        if a[0] == "ufw":
            if a[1] == "status":
                return 0, f"Status: {'active' if self.ufw_active else 'inactive'}\n", ""
            if a[1:] == ["show", "added"]:
                return 0, "Added user rules (see 'ufw status' for running firewall):\n" + "".join(
                    f"ufw allow {r}\n" for r in self.ufw_rules), ""
            if a[1] == "allow":
                self.ufw_rules.append(a[2])
                return 0, "Rules updated\n", ""
            if a[1:3] == ["delete", "allow"]:
                self.ufw_rules.remove(a[3])
                return 0, "Rule deleted\n", ""
            if a[1:] == ["--force", "enable"]:
                self.ufw_active = True
                return 0, "", ""
            if a[1:] == ["--force", "disable"]:
                self.ufw_active = False
                return 0, "", ""
        if a[0] == "journalctl":
            return 0, "Vacuuming done, freed 120.0M of archived journals from /var/log/journal.\n", ""
        if a[0] == "sshd":
            return (0, "", "") if self.sshd_ok else (255, "", "line 3: Bad configuration option")
        return 127, "", f"{a[0]}: not found"

    def handler(self, argv):
        code, out, err = self(argv)
        return CommandResult(tuple(argv), code, out, err)


class FakeUserSystemctl:
    """`systemctl --user` for the units of the user's own session: show, is-enabled, enable/disable --now."""

    def __init__(self, units: dict[str, str] | None = None):
        self.units = dict(units or {})              # unit -> "enabled" | "disabled" | ...
        self.calls = []

    def __call__(self, argv):
        a = list(argv)
        self.calls.append(a)
        if a[1] != "--user":
            return fail("not a user call")
        verb, unit = a[2], a[-1]
        if verb == "show":
            return CommandResult(argv, 0, "loaded\n" if unit in self.units else "not-found\n")
        if unit not in self.units:
            return CommandResult(argv, 1, "", f"Unit {unit} not found.")
        if verb == "is-enabled":
            return CommandResult(argv, 0 if self.units[unit] == "enabled" else 1, self.units[unit] + "\n")
        if verb in ("enable", "disable"):
            self.units[unit] = verb + "d"
            return OK
        return fail("bad systemctl --user call")


# Plasma 6's applets file as plasmashell writes it (modelled on Plasma 6.7.5's): a panel with a system tray,
# whose Clipboard entry (Klipper) is on
APPLETSRC_6 = """[Containments][23]
formfactor=2
location=4
plugin=org.kde.panel

[Containments][23][Applets][24]
plugin=org.kde.plasma.kickoff

[Containments][23][Applets][28]
immutability=1
plugin=org.kde.plasma.systemtray

[Containments][23][Applets][28][Applets][29]
immutability=1
plugin=org.kde.kdeconnect

[Containments][23][Applets][28][Applets][31]
immutability=1
plugin=org.kde.plasma.clipboard

[Containments][23][Applets][28][General]
extraItems=org.kde.kscreen,org.kde.plasma.battery,org.kde.plasma.clipboard,org.kde.plasma.volume
knownItems=org.kde.kscreen,org.kde.plasma.battery,org.kde.plasma.clipboard,org.kde.plasma.volume
"""


class FakePlasmaShell:
    """qdbus6 against Plasma 6, as it behaved on Plasma 6.7.5: evaluateScript runs desktop.tray_script(), which
    takes the entry out of the tray's extraItems and removes its applet under the tray (or puts both back) and
    prints ok:ID; Klipper's clearClipboardHistory empties its history and deletes its data/ files (its database
    stays). Nothing answers when Plasma isn't running."""

    def __init__(self, config_home: Path, data_home: Path, running: bool = True):
        self.appletsrc = config_home / "plasma-org.kde.plasma.desktop-appletsrc"
        self.klipper = data_home / "klipper"
        self.running = running
        self.cleared = 0

    def __call__(self, argv):
        if not self.running:
            return fail("Service 'org.kde.plasmashell' does not exist.")
        method, args = argv[3], argv[4:]
        if method == "org.kde.klipper.klipper.clearClipboardHistory":
            self.cleared += 1
            for f in (self.klipper / "data").rglob("*"):
                if f.is_file():
                    f.unlink()
            return OK
        if method != "org.kde.PlasmaShell.evaluateScript":
            return fail("No such method")
        script = args[0]
        plugin = re.search(r'var P="([^"]+)"', script).group(1)
        on = "ON=true" in script
        ids = re.findall(r'"(\d+)"', re.search(r"IDS=\[([^\]]*)\]", script).group(1))
        text = self.appletsrc.read_text()
        for tray in ids:
            def items(m):
                listed = [x for x in m.group(2).split(",") if x and x != plugin] + ([plugin] if on else [])
                return m.group(1) + ",".join(listed)
            text = re.sub(rf"(\[Containments\]\[\d+\]\[Applets\]\[{tray}\]\[General\]\n(?:.*\n)*?extraItems=)(.*)",
                          items, text)
            text = re.sub(rf"\[Containments\]\[\d+\]\[Applets\]\[{tray}\]\[Applets\]\[\d+\]\n(?:[^\[\n].*\n)*?"
                          rf"plugin={re.escape(plugin)}\n\n?", "", text)
            if on:
                panel = re.search(rf"\[Containments\]\[(\d+)\]\[Applets\]\[{tray}\]\n", text).group(1)
                text += f"\n[Containments][{panel}][Applets][{tray}][Applets][90]\nplugin={plugin}\n"
        self.appletsrc.write_text(text)
        return CommandResult(argv, 0, " ".join(f"ok:{t}" for t in ids) + "\n")
