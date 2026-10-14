"""What a scan reads, in plain words, for the "What a scan reads" panel: the user sees this
before the first scan. Every item is read-only; nothing here is sent anywhere.

Also the welcome warning's settings: whether the user asked not to see it again (kept in
$XDG_CONFIG_HOME/daprivacyscanner/ui.json, with the version of the warning they saw, so a warning
that changes is shown once more), and the pages it links to. The page asks the server to open a
link by its name; the server opens only these, in the user's default browser."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

from . import __version__

# Bump when the welcome warning's substance changes: it is then shown again to everyone.
WELCOME_VERSION = 3                 # 3: the public beta notice
LINKS = {"tails": "https://tails.net/", "qubes": "https://www.qubes-os.org/",
         "releases": "https://github.com/DigitalArchon/DAPrivacyKit/releases",
         "issues": "https://github.com/DigitalArchon/DAPrivacyKit/issues"}

# The app never looks for a newer version of itself (no network), so it says when its own copy is getting old:
# checks are written for the versions of apps current when it was built, and bugs are fixed in later ones.
OLD_AFTER_DAYS = 90


def built() -> dt.date | None:
    """The date of the commit this copy was built from: the AppImage's build writes it (_built.py, from
    SOURCE_DATE_EPOCH, so the same commit gives the same file). None from a source tree."""
    try:
        from ._built import BUILT
        return dt.date.fromisoformat(BUILT)
    except (ImportError, ValueError, TypeError):
        return None


def age(today: dt.date | None = None, built_on: dt.date | None = None) -> dict:
    """What the page and the report say about this copy: its version, when it was built, and, once it is more than
    OLD_AFTER_DAYS old, that a newer one is probably out. A clock set before the build date says nothing."""
    built_on = built_on or built()
    out = {"version": __version__, "built": None, "days": None, "old": False, "text": ""}
    if built_on is None:
        return out
    days = ((today or dt.date.today()) - built_on).days
    when = f"{built_on.day} {built_on:%B %Y}"
    out.update(built=built_on.isoformat(), built_text=when, days=days, old=days > OLD_AFTER_DAYS)
    if out["old"]:
        out["text"] = (f"This copy of DA Privacy Kit was built on {when}, about {days // 30} months ago. A newer one "
                       "probably fixes bugs and knows newer versions of your apps. The app never looks for updates by "
                       f"itself: the latest is at {LINKS['releases']}")
    return out


def _ui_file(config_home: Path) -> Path:
    return config_home / "daprivacyscanner" / "ui.json"


def _ui(config_home: Path) -> dict:
    try:
        data = json.loads(_ui_file(config_home).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def welcome_shown(config_home: Path) -> bool:
    """Whether to show the welcome warning at start-up."""
    seen = _ui(config_home).get("welcome_hidden_version")
    return not (isinstance(seen, int) and seen >= WELCOME_VERSION)


def hide_welcome(config_home: Path, hide: bool) -> None:
    data = _ui(config_home)
    if hide:
        data["welcome_hidden_version"] = WELCOME_VERSION
    else:
        data.pop("welcome_hidden_version", None)
    f = _ui_file(config_home)
    f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = f.with_suffix(".tmp")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
        json.dump(data, out)
    os.replace(tmp, f)

READS: list[dict] = [
    {"what": "Disks, partitions and swap", "why": "To tell which filesystems and swap are encrypted, where a "
     "hibernation image would go, whether zram writes back to a disk, and whether freed space is trimmed.",
     "how": "lsblk, /proc/swaps, /proc/mounts, /sys/power, /sys/block (SSD or not, TRIM, zram's backing device), "
     "zram-generator's configuration, /etc/crypttab; LUKS headers only with administrator access, through the helper "
     "(versions and key-slot types, never keys or salts)."},
    {"what": "Login and session settings", "why": "Automatic login, screen lock, notifications on the lock screen.",
     "how": "Display manager files under /etc, gsettings, KDE's kscreenlockerrc; /etc/shadow only with administrator "
     "access, and only whether an account's password field is empty."},
    {"what": "Keys, keyrings and credential files", "why": "To find secrets stored without a passphrase or in plain text.",
     "how": "The first bytes of ~/.ssh keys, keyring and GnuPG files (to see whether they are encrypted); whether "
     "~/.netrc, ~/.aws/credentials, ~/.git-credentials, ~/.docker/config.json and similar hold a credential. "
     "SSH: the client's settings (~/.ssh/config, /etc/ssh/ssh_config), the type and size of each key in "
     "~/.ssh/authorized_keys (never their comments, which often hold an email address), and how many keys the SSH "
     "agent holds (ssh-add -l). GnuPG: your keys' type, size and expiry (gpg --list-keys, which doesn't start "
     "gpg-agent), and gpg-agent.conf's cache times. "
     "KDE wallets (~/.local/share/kwalletd) are tried with an empty password, in memory: a wallet with a blank "
     "password is still encrypted, so trying is the only way to tell. "
     "Their contents never appear in the report: only that they do, and their permissions."},
    {"what": "Files that run as you", "why": "To find login files and programs other accounts could change.",
     "how": "The owner and permissions (never the contents) of ~/.bashrc, ~/.profile, ~/.zshrc and the other login "
     "files, the folders on your PATH under your home and the programs in them; /etc/passwd and /etc/group, to "
     "tell whether a group has anyone else in it."},
    {"what": "Shell and REPL history", "why": "To count lines that look like passwords or tokens.",
     "how": "~/.bash_history, ~/.zsh_history, fish, Python, psql and MySQL histories. The report holds counts, "
     "never the lines."},
    {"what": "Browser profiles", "why": "Telemetry, tracking protection, history retention, extensions, sync, crash dumps.",
     "how": "prefs.js, Preferences, Local State and extension manifests of Firefox-family and Chromium-family profiles; "
     "Login Data and Cookies are opened read-only to count entries encrypted with the built-in key. No URLs, cookies "
     "or passwords are read into the report. permissions.sqlite and each Chromium profile's site settings are read "
     "to count the sites allowed the camera, microphone or location, never to name them."},
    {"what": "Desktop activity records", "why": "Thumbnails, recent files, KDE activity and clipboard histories.",
     "how": "The thumbnail cache (each PNG's embedded path, to see which drive it came from), recently-used.xbel, "
     "kactivitymanagerd's database (counts), clipboard managers' folders (sizes), screenshots (counts and age), "
     "and this app's own rules and mount units that expire or keep them in memory."},
    {"what": "Browsers", "why": "Which browsers are installed, which is the default, and whether it blocks ads.",
     "how": "Menu entries in the application folders (packages, Flatpak, Snap and your own), AppImages in the usual "
     "folders and on the desktop, apps pinned to panels and docks, xdg-settings and mimeapps.list for the default, "
     "and the list of extensions in each profile (names and ids only)."},
    {"what": "Apps' data folders", "why": "Caches, histories and backups that outlive the files they came from.",
     "how": "Sizes and counts under ~/.config, ~/.local/share, ~/.cache, ~/.var/app and ~/snap; LibreOffice, "
     "media players, PDF readers, editors, messengers and mail clients; GIMP's settings (whether it copies a photo's "
     "details into what it exports); git's settings (whether commits carry your own email address, never the address); "
     "and whether this app's Outbox and right-click entries are set up."},
    {"what": "What starts at login", "why": "To list what runs by itself, and mark what is new since the last scan.",
     "how": "Autostart entries (~/.config/autostart, /etc/xdg/autostart: the program each starts, never its "
     "arguments), user services enabled for your account, Plasma's login scripts, ~/.xprofile, crontab -l (entries "
     "counted, never shown: they can hold passwords) and programs on your PATH that share a system program's name. "
     "The app remembers a hash of each entry, not its name, to tell what is new."},
    {"what": "Network state", "why": "Exposed services, firewall, DNS, Wi-Fi settings, Bluetooth, VPN.",
     "how": "ss, nmcli (saved connections' settings and last-used times, never passwords), resolvectl, bluetoothctl, "
     "/proc/net and /sys/class/net, ip route get (which interface would carry traffic to the internet: a lookup "
     "in the routing tables, nothing is sent); VPN apps' interface and process names, and a VPN app's own status "
     "command, which asks only the app running on this computer; ufw's rules only with administrator access; OpenSnitch's "
     "settings (/etc/opensnitchd/default-config.json, ~/.config/opensnitch/settings.conf) and the names of its rule "
     "files, never what they allow or block."},
    {"what": "System configuration", "why": "Crash reporting, journal retention, updates, kernel hardening, sandboxing.",
     "how": "systemd and apt/dnf settings under /etc, /proc/sys, package lists already on disk (nothing is "
     "downloaded), the package managers' repository settings (whether signature checks are turned off: apt, dnf, "
     "zypper, pacman and Flatpak), flatpak and snap listings, and whether USB devices are let in at once "
     "(/sys/bus/usb, USBGuard's service)."},
    {"what": "App versions", "why": "To say when an app is newer than the checks that read it were made for: apps "
     "move their data most often in a major release.", "how": "The installed version of each app the checks read "
     "(apps.yaml, shipped with the app): dpkg-query, rpm -q or pacman -Q for its package names, flatpak list and snap "
     "list. Compared on this computer only; nothing is looked up online."},
    {"what": "Processes", "why": "To skip apps that are running when a fix would clear their data, and to spot "
     "guest agents, indexers and remote desktop servers.", "how": "Process names from /proc, and which of your "
     "own processes hold a file open under a folder a fix would clear."},
    {"what": "Programs the scan asks", "why": "Some things only the program that owns them can tell.",
     "how": "sudo -n -l (whether sudo works without a password; like any use of sudo, it leaves a line in the "
     "system's authentication log each time), docker ps (which starts the Docker service when it is set up to start "
     "on demand), tracker3 or localsearch status (which may start the indexer's own service for a moment), nmcli, "
     "resolvectl, bluetoothctl, grdctl, flatpak, ssh-add -l (how many keys your SSH agent holds) and crontab -l. "
     "None of them changes a setting."},
]

NEVER = [
    "Nothing is sent anywhere during a scan. The online tests are separate, run only when you start them, and each "
    "says who it contacts first.",
    "File contents are never copied into the report: it holds paths, counts and settings. Names and addresses the "
    "report lists (what starts at login, saved Wi-Fi networks, the addresses the online tests saw) are shown while the "
    "app runs and "
    "aren't kept in the saved report.",
    "Scans change no setting and no file. A few of the programs a scan asks leave a trace of their own, listed "
    "under “Programs the scan asks”: sudo -n -l writes a line to the authentication log, and docker ps or the "
    "indexer's status command can start that service for a moment. Fixes show exactly what they will do first, and "
    "settings changes can be reverted from History.",
    "The tools (Verify a download, Remove metadata, the RAM disk) run only when you start them, on the files you choose; "
    "they send nothing anywhere and keep nothing afterwards. The one that downloads (Tor or Mullvad Browser in memory) "
    "names the project's servers it contacts before it starts.",
]
