"""`daprivacyscanner --capture DIR`: collect sanitised samples of the command output the parsers
consume, in the layout of tests/samples, so testers on other distributions can contribute
fixtures without hand-writing them. Each file written is listed on the terminal, to review before
sharing; the sanitising replaces the user name, host name, MAC and non-loopback IP addresses."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .blockdev import COLUMNS
from .host import Host
from .report import UUID, replace_addresses

# (sample path relative to DIR/<distro>/, argv)
COMMANDS = [
    ("lsblk/lsblk.json", ("lsblk", "-J", "-o", COLUMNS)),
    ("ss/ss.txt", ("ss", "-tulpnH")),
    ("misc/os-release.txt", ("cat", "/etc/os-release")),
    ("misc/systemctl-version.txt", ("systemctl", "--version")),
    ("misc/hostnamectl-chassis.txt", ("hostnamectl", "chassis")),
    ("misc/proc-swaps.txt", ("cat", "/proc/swaps")),
    ("misc/resolvectl-status.txt", ("resolvectl", "status")),
    ("ip/link.txt", ("ip", "-d", "-o", "link", "show")),
    ("ip/rule.txt", ("ip", "rule", "show")),
    ("ip/route-get-4.txt", ("ip", "-4", "route", "get", "1.1.1.1")),
    ("ip/route-get-6.txt", ("ip", "-6", "route", "get", "2606:4700:4700::1111")),
    ("misc/nmcli-active.txt", ("nmcli", "-t", "-f", "TYPE", "connection", "show", "--active")),
    ("misc/networkmanager-config.txt", ("NetworkManager", "--print-config")),
    ("misc/gsettings-privacy.txt", ("gsettings", "list-recursively", "org.gnome.desktop.privacy")),
    ("misc/flatpak-list.txt", ("flatpak", "list", "--app", "--columns=application")),
    ("misc/snap-list.txt", ("snap", "list", "--all")),
    ("misc/bluetoothctl-show.txt", ("bluetoothctl", "show")),
    ("misc/ufw-status.txt", ("ufw", "status", "verbose")),
    ("misc/firewall-cmd-zones.txt", ("firewall-cmd", "--get-active-zones")),
]

MAC = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")


class Sanitiser:
    def __init__(self, host: Host):
        from .checks._util import user_names
        self.login, self.words = user_names(host)
        self.hostname = (host.read_sys("/proc/sys/kernel/hostname") or "").strip()
        self.home = str(host.home)

    def __call__(self, text: str) -> str:
        text = text.replace(self.home, "/home/user")
        for n in [self.hostname, self.login, *self.words]:
            if len(n) >= 3:
                text = re.sub(re.escape(n), "user", text, flags=re.I)
        text = MAC.sub("00:11:22:33:44:55", text)
        # a disk's UUID (luks-<UUID> device names) identifies it
        text = UUID.sub("12345678-1234-4321-8765-123456789abc", text)
        text = replace_addresses(text, "192.0.2.10", "2001:db8::10")
        # resolvectl's search domains name the network (corp.example.com); NetworkManager's config can carry them too
        text = re.sub(r"(?im)^(\s*DNS Domain:\s*).*$", r"\1example.net", text)
        text = re.sub(r"(?im)^(\s*(?:dns-search|domain-search|search)\s*[=:]\s*).*$", r"\1example.net", text)
        text = re.sub(r'pid=\d+', "pid=1000", text)
        return text


_MOUNTED_AS = re.compile(r"^((?:/run/media/[^/]+|/media/[^/]+|/mnt)/)[^/]+")


def _generic_labels(data) -> None:
    """Drive labels can name people or what a drive holds: each becomes LABEL, except the boot-stick
    labels the app looks for, and so does the folder a drive is mounted on by its label."""
    from .blockdev import BOOT_STICK_LABELS
    if isinstance(data, dict):
        if data.get("label") and data["label"] not in BOOT_STICK_LABELS:
            data["label"] = "LABEL"
        for key in ("mountpoints", "mountpoint"):
            m = data.get(key)
            if isinstance(m, str):
                data[key] = _MOUNTED_AS.sub(r"\1LABEL", m)
            elif isinstance(m, list):
                data[key] = [_MOUNTED_AS.sub(r"\1LABEL", x) if isinstance(x, str) else x for x in m]
        for v in data.values():
            _generic_labels(v)
    elif isinstance(data, list):
        for v in data:
            _generic_labels(v)


def distro_name(host: Host) -> str:
    text = host.read_sys("/etc/os-release") or ""
    get = lambda k: (re.search(rf'^{k}="?([^"\n]*)', text, re.M) or [None, ""])[1]  # noqa: E731
    name = f"{get('ID') or 'linux'}-{get('VERSION_ID') or 'rolling'}".lower()
    return re.sub(r"[^a-z0-9.-]+", "-", name)


def capture(host: Host, directory: Path, out=sys.stdout) -> list[Path]:
    clean = Sanitiser(host)
    target = directory / distro_name(host)
    written = []
    for rel, argv in COMMANDS:
        r = host.run(*argv)
        if r.missing or (not r.ok and not r.stdout):
            print(f"  skipped {' '.join(argv)}: {'not installed' if r.missing else r.stderr.strip()[:80]}", file=out)
            continue
        text = clean(r.stdout)
        if rel.endswith(".json"):
            try:
                data = json.loads(text)
                if rel.startswith("lsblk/"):
                    _generic_labels(data)
                text = json.dumps(data, indent=1) + "\n"
            except ValueError:
                pass
        p = target / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        written.append(p)
        print(f"  wrote {p} ({len(text.splitlines())} lines)", file=out)
    readme = target / "README.md"
    readme.write_text(f"# Samples captured on {distro_name(host)}\n\nSanitised with `daprivacyscanner --capture`: user and "
                      "host names, drive labels (and the folders drives are mounted on by them), disk UUIDs, MAC and non-loopback IP "
                      "addresses and PIDs are replaced. Review each file before "
                      "sharing it, then copy what is useful into tests/samples and add it to its README table.\n")
    written.append(readme)
    return written
