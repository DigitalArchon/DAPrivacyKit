"""OpenSnitch, the outgoing firewall (net.outgoing_firewall): what is installed and how it is set, read as the user.
Its daemon's settings (/etc/opensnitchd/default-config.json) and the names in its rules folder can be read by every
account, its window's settings are the user's own (~/.config/opensnitch/settings.conf). Never what a rule allows or
blocks: the files OpenSnitch saves are named after the website or program, so only the app's own are told apart, by
name, and the rest counted.

Facts this relies on, tested on CachyOS with OpenSnitch 1.7.2 and read in 1.5.8's source (Ubuntu 24.04, Mint 22):
- The window's setting for a question nobody answers is global/default_action, 1 for allow; on its first start it
  writes 0 (deny; 1.5.8 writes "allow", which it then reads as a number, fails, and takes as 0: deny too). The
  daemon's DefaultAction applies only while the window isn't connected.
- At LogLevel 2 (the shipped default) each answer, whatever its duration, each unanswered question and each deleted
  rule is a line in /var/log/opensnitchd.log naming the website or program; at 3 the log stays empty. The daemon's
  own default when LogLevel isn't set is 1 (info), which logs them too.
- The window's list of connections is in memory unless database/type is 1 (a file)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import ini
from .host import Host, Unreadable
from .paths import PathResolver

CONFIG = "/etc/opensnitchd/default-config.json"
RULES = "/etc/opensnitchd/rules"
LOG = "/var/log/opensnitchd.log"
PREFIX = "000-daprivacyscanner-"
SHIPPED = {"000-allow-localhost", "000-allow-localhost6"}               # what upstream's package comes with (1.8.0's .deb)
UNITS = ("opensnitchd.service", "opensnitch.service")      # upstream and Arch; Debian and Ubuntu
UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")
DAEMONS = ("/usr/bin/opensnitchd", "/usr/sbin/opensnitchd")
WINDOWS = ("/usr/bin/opensnitch-ui",)
VERSION_FILES = ("/usr/lib/python3/dist-packages/opensnitch/version.py",)
VERSION_GLOBS = ("usr/lib/python3*/site-packages/opensnitch/version.py", "usr/lib64/python3*/site-packages/opensnitch/version.py")
DEFAULT_LOG_LEVEL = 1                   # the daemon's own when its settings don't say (log.MinLevel = INFO)
LOG_LEVELS = {0: "debug", 1: "info", 2: "important", 3: "warning", 4: "error"}


def settings_file(paths: PathResolver) -> Path:
    return paths.config_home / "opensnitch" / "settings.conf"


@dataclass
class OpenSnitch:
    daemon: bool = False                    # the daemon is installed
    window: bool = False                    # its window (opensnitch-ui) is installed
    version: str | None = None
    unit: str | None = None
    active: bool = False
    enabled: bool = False
    config: dict | None = None              # the daemon's settings; None when missing or unreadable
    config_unreadable: bool = False
    rules: list[str] | None = None          # names of the rule files (.json); None when the folder can't be listed
    settings: str | None = None             # the window's settings file
    window_running: bool = False
    autostart: bool = False
    log_size: int | None = None             # bytes in /var/log/opensnitchd.log
    old_logs: int = 0                       # its rotated copies
    notes: list[str] = field(default_factory=list)

    @property
    def log_level(self) -> int | None:
        if self.config is None:
            return None
        v = self.config.get("LogLevel")
        return v if isinstance(v, int) and not isinstance(v, bool) else DEFAULT_LOG_LEVEL if v is None else None

    @property
    def daemon_action(self) -> str | None:
        v = (self.config or {}).get("DefaultAction")
        return v if v in ("allow", "deny", "reject") else None

    @property
    def window_action(self) -> str:
        """What the window does with a question nobody answers: allow only when it says 1 (see the module's notes)."""
        v = ini.qsettings_get(self.settings, "global", "default_action")
        return "allow" if v is not None and v.strip() == "1" else "deny"

    @property
    def window_timeout(self) -> int | None:
        v = ini.qsettings_get(self.settings, "global", "default_timeout")
        return int(v) if v is not None and v.strip().isdigit() else None

    @property
    def database_file(self) -> str | None:
        """Where the window keeps its list of connections when that is a file; None when it is in memory."""
        if (ini.qsettings_get(self.settings, "database", "type") or "").strip() != "1":
            return None
        return ini.qsettings_value(ini.qsettings_get(self.settings, "database", "file") or "") or "a file"

    @property
    def loggers(self) -> bool:
        server = (self.config or {}).get("Server")
        return isinstance(server, dict) and bool(server.get("Loggers"))

    @property
    def queue_bypass(self) -> bool | None:
        fw = (self.config or {}).get("FwOptions")
        v = fw.get("QueueBypass") if isinstance(fw, dict) else None
        return v if isinstance(v, bool) else None

    @property
    def deny_mode(self) -> bool:
        return self.daemon_action in ("deny", "reject") and self.window_action == "deny"

    @property
    def own_rules(self) -> list[str]:
        return [n for n in self.rules or [] if n.startswith(PREFIX)]

    @property
    def other_rules(self) -> int:
        """The user's own rules: not the app's, nor the two for loopback that upstream's package comes with."""
        return len([n for n in self.rules or [] if not n.startswith(PREFIX) and n not in SHIPPED])


def _exists(host: Host, *paths: str) -> bool:
    return any(host.sys_path(p).is_file() for p in paths)


def read(host: Host, paths: PathResolver, procs: set[str] | None = None) -> OpenSnitch:
    from .checks._util import processes, systemctl_state
    s = OpenSnitch(daemon=_exists(host, *DAEMONS), window=_exists(host, *WINDOWS))
    for f in [*VERSION_FILES, *(("/" + str(p.relative_to(host.root))) for g in VERSION_GLOBS for p in sorted(host.root.glob(g)))]:
        try:
            text = host.read_file(host.sys_path(f))
        except Unreadable:
            text = None
        m = re.search(r"""^version\s*=\s*['"]([0-9][0-9A-Za-z.+~-]{0,30})['"]""", text or "", re.M)
        if m:
            s.version = m.group(1)
            break
    s.unit = next((u for u in UNITS for d in UNIT_DIRS if host.sys_path(f"{d}/{u}").is_file()), None)
    if s.unit:
        s.active = systemctl_state(host, "is-active", s.unit) == "active"
        s.enabled = systemctl_state(host, "is-enabled", s.unit) == "enabled"
    try:
        text = host.read_file(host.sys_path(CONFIG))
    except Unreadable:
        text, s.config_unreadable = None, True
    if text is not None:
        try:
            data = json.loads(text)
            s.config = data if isinstance(data, dict) else None
        except ValueError:
            s.config = None
    try:
        s.rules = sorted(p.name[:-5] for p in host.sys_path(RULES).iterdir() if p.name.endswith(".json"))
    except OSError:
        s.rules = None
    try:
        s.settings = host.read_file(settings_file(paths))
    except Unreadable:
        s.settings = None
    s.window_running = "opensnitch-ui" in (processes(host) if procs is None else procs)
    s.autostart = (paths.config_home / "autostart" / "opensnitch_ui.desktop").is_file() or \
        host.sys_path("/etc/xdg/autostart/opensnitch_ui.desktop").is_file()
    try:
        s.log_size = host.sys_path(LOG).stat().st_size
    except OSError:
        s.log_size = None
    try:
        s.old_logs = len([p for p in host.sys_path("/var/log").iterdir() if re.fullmatch(
            r"opensnitchd\.log(\.[0-9]+(\.(gz|xz|zst|bz2))?|-[0-9]{8}(\.(gz|xz|zst|bz2))?|\.old)", p.name)])
    except OSError:
        s.old_logs = 0
    return s


def starter_state(host: Host, s: OpenSnitch, which: str = "starter") -> str:
    """"missing", "current", or "outdated" (programs installed or removed since, or a file edited) for one of the
    app's rule sets, compared with what the helper would write now on this system."""
    from . import helper
    want = helper.opensnitch_rule_files(which, root=str(host.root))
    names = {Path(p).name[:-5] for p in want}
    if not names & set(s.own_rules):
        return "missing"
    for path, content in want.items():
        try:
            have = host.sys_path(path).read_bytes()
        except OSError:
            return "outdated"
        if have != content:
            return "outdated"
    return "current"
