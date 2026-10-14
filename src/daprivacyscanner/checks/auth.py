"""Authentication, sessions and secrets (auth.*)."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .. import ini, kwallet
from ..host import Unreadable
from ..model import Evidence, Note, Outcome
from ..privileged import HelperError
from . import Check, Scan, register
from ._util import (absent, children, chromium_dirs, chromium_profiles, failed, isdir, isfile, mode_of,
                    mozilla_profiles, needs_root, passed, processes, read_json, read_text, sqlite_count, unknown,
                    warned)


@register
class Autologin(Check):
    id = "auth.autologin"

    def detect(self, scan: Scan) -> Outcome:
        a = scan.context.values["autologin"]
        if a.value is True:
            return failed("Automatic login is on.", *a.evidence)
        if a.value is False:
            return passed("Automatic login is off.", *a.evidence)
        return unknown(f"Couldn't check: {a.note}", *a.evidence)


@register
class EmptyPassword(Check):
    id = "auth.empty_password"

    def detect(self, scan: Scan) -> Outcome:
        if scan.privileged is None:
            return needs_root("Reading /etc/shadow")
        try:
            names = scan.privileged.empty_password_accounts()
        except HelperError as e:
            return unknown(f"Couldn't read /etc/shadow: {e}")
        if names:
            return failed(f"{len(names)} account{'s have' if len(names) > 1 else ' has'} an empty password.",
                          *(Evidence.val("Empty password", n) for n in names[:20]))
        return passed("No account has an empty password.")


# ------------------------------------------------------------------ screen lock

def _min(seconds: int) -> str:
    return "never" if seconds == 0 else f"{seconds // 60} min {seconds % 60} s" if seconds % 60 else f"{seconds // 60} min"


@register
class ScreenLock(Check):
    id = "auth.screen_lock"
    LIMIT = 300                 # seconds idle before the screen blanks; it should lock within a minute of that

    def detect(self, scan: Scan) -> Outcome:
        d = scan.context.desktop
        if d.is_kde:
            return self._kde(scan)
        names = set(d.names)
        if names & {"x-cinnamon", "cinnamon"}:
            return self._gsettings(scan, "Cinnamon", "org.cinnamon.desktop.screensaver", "org.cinnamon.desktop.session",
                                   ("org.cinnamon.settings-daemon.plugins.power", "lock-on-suspend"))
        if "mate" in names:
            return self._gsettings(scan, "MATE", "org.mate.screensaver", "org.mate.screensaver", None, minutes=True)
        if d.is_gnome or names & {"ubuntu", "budgie", "unity", "pop"}:
            return self._gsettings(scan, "GNOME", "org.gnome.desktop.screensaver", "org.gnome.desktop.session",
                                   ("org.gnome.desktop.screensaver", "ubuntu-lock-on-suspend"))
        if "xfce" in names:
            return self._xfce(scan)
        return unknown(f"Screen lock settings for {d.label} aren't supported yet.")

    def _judge(self, desktop: str, enabled, idle: int | None, delay: int, on_suspend, ev: list[Evidence]) -> Outcome:
        if enabled is False:
            return failed(f"{desktop} never locks the screen.", *ev)
        if idle == 0:
            return failed(f"{desktop} never locks the screen when idle.", *ev)
        if on_suspend is False:
            return failed(f"{desktop} doesn't lock the screen on suspend.", *ev)
        if idle is None or enabled is None:
            return unknown(f"Couldn't read all of {desktop}'s screen lock settings.", *ev)
        total = idle + delay
        if idle > self.LIMIT or delay > 60:
            return warned(f"The screen locks after {_min(total)} idle; 5 minutes or less is safer.", *ev)
        return passed(f"The screen locks after {_min(total)} idle.", *ev)

    def _gsettings(self, scan: Scan, desktop: str, saver: str, session: str, suspend, minutes: bool = False) -> Outcome:
        g = scan.gnome
        enabled = g.gsettings(saver, "lock-enabled")
        idle = g.gsettings(session, "idle-delay")
        delay = g.gsettings(saver, "lock-delay") or 0
        if minutes:
            idle = None if idle is None else idle * 60
            delay *= 60
        on_suspend = g.gsettings(*suspend) if suspend else None
        ev = [Evidence.val("Lock enabled", enabled), Evidence.val("Idle delay", None if idle is None else _min(idle)),
              Evidence.val("Lock delay after blanking", f"{delay} s")]
        if suspend and on_suspend is not None:
            ev.append(Evidence.val("Lock on suspend", on_suspend))
        return self._judge(desktop, enabled, idle, delay, on_suspend, ev)

    def _kde(self, scan: Scan) -> Outcome:
        # KDE writes only changed values: a missing key is the default, not "off"
        k = scan.kde
        def b(key, default):
            v = k.get("kscreenlockerrc", "Daemon", key)
            return default if v is None else ini.truthy(v)
        autolock, on_resume = b("Autolock", True), b("LockOnResume", True)
        timeout = int(k.get("kscreenlockerrc", "Daemon", "Timeout") or 5) * 60
        grace = int(k.get("kscreenlockerrc", "Daemon", "LockGrace") or 5)
        ev = [Evidence.val("Lock automatically", autolock), Evidence.val("After", _min(timeout)),
              Evidence.val("Lock on resume", on_resume), Evidence.val("Grace period", f"{grace} s")]
        return self._judge("KDE Plasma", autolock, timeout if autolock else 0, grace, on_resume, ev)

    def _xfce(self, scan: Scan) -> Outcome:
        host = scan.host
        if not (host.runner.which("xfconf-query") and host.runner.which("xfce4-screensaver")):
            return unknown("Couldn't read xfce4-screensaver's settings (light-locker isn't supported yet).")
        get = lambda prop: xfconf_get(host, XFCE_SAVER, prop)  # noqa: E731
        enabled, with_saver = get("/lock/enabled"), get("/lock/saver-activation/enabled")
        idle_on, idle, delay = get("/saver/idle-activation/enabled"), get("/saver/idle-activation/delay"), \
            get("/lock/saver-activation/delay")
        on_suspend = get("/lock/sleep-activation")
        idle = 0 if idle_on is False or with_saver is False else None if idle is None else int(idle) * 60
        delay = int(delay or 0) * 60
        ev = [Evidence.val("Lock enabled", enabled), Evidence.val("Lock when the screensaver starts", with_saver),
              Evidence.val("Screensaver after", "never" if idle_on is False else None if idle is None else _min(idle)),
              Evidence.val("Lock delay after the screensaver", f"{delay} s"), Evidence.val("Lock on suspend", on_suspend)]
        return self._judge("Xfce", enabled, idle, delay, on_suspend, ev)


# xfce4-screensaver's settings and its defaults, for properties never set (xfconf keeps only those
# changed). VERIFY (catalogue): the property names and defaults in xfce4-screensaver 4.18 / 4.20
# (src/gs-prefs.c), and that the idle delay is in minutes.
XFCE_SAVER = "xfce4-screensaver"
XFCE_SAVER_DEFAULTS = {"/lock/enabled": True, "/lock/saver-activation/enabled": True, "/lock/saver-activation/delay": 0,
                       "/lock/sleep-activation": True, "/saver/idle-activation/enabled": True,
                       "/saver/idle-activation/delay": 5}


def xfconf_get(host, channel: str, prop: str):
    """A property's value (bool or int), or the default for one never set (XFCE_SAVER_DEFAULTS)."""
    r = host.run("xfconf-query", "-c", channel, "-p", prop)
    if not r.ok:
        return XFCE_SAVER_DEFAULTS.get(prop) if channel == XFCE_SAVER else None
    v = r.stdout.strip()
    return {"true": True, "false": False}.get(v.lower(), int(v) if v.lstrip("-").isdigit() else None)


@register
class LockscreenNotifications(Check):
    id = "auth.lockscreen_notifications"

    def detect(self, scan: Scan) -> Outcome:
        if scan.context.desktop.is_gnome:
            v = scan.gnome.gsettings("org.gnome.desktop.notifications", "show-in-lock-screen")
            if v is None:
                return unknown("Couldn't read GNOME's notification settings.")
            if not v:
                return passed("Notifications aren't shown on the lock screen.", Evidence.val("show-in-lock-screen", False))
            # with it on, GNOME Shell shows which apps sent notifications and how many; the text only for
            # apps whose details-in-lock-screen is on (off by default, per app in Settings → Notifications)
            detailed, unread = gnome_lockscreen_details(scan)
            ev = [Evidence.val("show-in-lock-screen", True),
                  Evidence.val("Apps whose message text is shown", ", ".join(detailed[:10]) or "none")]
            if detailed:
                return failed(f"{len(detailed)} app{'s show' if len(detailed) > 1 else ' shows'} the text of "
                              "notifications on the lock screen.", *ev)
            if unread:
                return unknown("Couldn't read every app's notification settings.", *ev)
            return passed("The lock screen shows which apps sent notifications, never what they say.", *ev,
                          notes=[Note("info", "Which apps, not what they say",
                                      "Anyone at the locked screen sees that, say, a messenger has three new "
                                      "notifications. Settings → Notifications → Lock Screen Notifications hides "
                                      "even that.")])
        names = set(scan.context.desktop.names)
        if scan.context.desktop.is_kde:
            # Plasma's lock screen (plasma-desktop's lockscreen/LockScreenUi.qml, 6.7) shows no
            # notifications: its only messages are the unlock prompt's own. It does show what is
            # playing, by default, from [Greeter][LnF][General] showMediaControls in kscreenlockerrc.
            media = ini.truthy(scan.kde.get("kscreenlockerrc", ("Greeter", "LnF", "General"), "showMediaControls"))
            media = True if media is None else media
            notes = [Note("info", "It shows what is playing",
                          "Plasma's lock screen shows the music or video playing (its title and artist) with controls, "
                          "to anyone at the screen. To hide it: System Settings → Screen Locking → Appearance → "
                          "untick Show media controls.")] if media else []
            return passed("Plasma's lock screen doesn't show notifications.",
                          Evidence.val("Media playing shown on the lock screen", media), notes=notes)
        if names & {"x-cinnamon", "cinnamon"}:
            # cinnamon-screensaver (6.6) counts the notifications that arrive while locked and shows
            # only that number; Cinnamon's own pop-ups are drawn beneath the lock screen. (Its
            # show-notifications setting isn't read by the lock screen at all.)
            return passed("Cinnamon's lock screen shows only how many notifications arrived, never what they say.",
                          Evidence.val("Shown on the lock screen", "a count of notifications"))
        return unknown(f"Not checked on {scan.context.desktop.label} yet: its setting is still to be confirmed.")


GNOME_APP_NOTIFICATIONS = "org.gnome.desktop.notifications.application"


def gnome_lockscreen_details(scan: Scan) -> tuple[list[str], bool]:
    """(apps whose notification text GNOME shows on the lock screen, whether some couldn't be read).
    Each app has a relocatable schema of its own, listed in application-children."""
    apps = scan.gnome.gsettings("org.gnome.desktop.notifications", "application-children")
    detailed, unread = [], False
    for app in apps if isinstance(apps, list) else []:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", str(app)):
            continue
        r = scan.host.run("gsettings", "get", f"{GNOME_APP_NOTIFICATIONS}:/org/gnome/desktop/notifications/application/"
                          f"{app}/", "details-in-lock-screen")
        if not r.ok:
            unread = True
        elif r.stdout.strip() == "true":
            detailed.append(str(app))
    return detailed, unread or not isinstance(apps, list)


# ------------------------------------------------------------------ keyrings

KEYRING_MAGIC = b"GnomeKeyring\n\r\0\n"


@register
class KeyringBlank(Check):
    id = "auth.keyring_blank"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        rings = [p for p in children(scan.paths.data_home / "keyrings") if p.suffix == ".keyring"]
        wallets = [p for p in children(scan.paths.data_home / "kwalletd") if p.suffix == ".kwl"]
        if not rings and not wallets:
            return absent("No GNOME keyring or KWallet files were found.")
        ev, plain, unsure = [], [], []
        for r in rings:
            try:
                head = host.read_head(r, 32) or b""
            except Unreadable:
                unsure.append(r.name)
                ev.append(Evidence.val(r.name, "couldn't check: unreadable", named=True))
                continue
            if head.startswith(KEYRING_MAGIC):
                ev.append(Evidence.val(r.name, "encrypted", named=True))
            elif head.lstrip().startswith(b"[keyring]"):
                plain.append(r.name)
                ev.append(Evidence.val(r.name, "stored unencrypted (blank password)", named=True))
            else:
                unsure.append(r.name)
                ev.append(Evidence.val(r.name, "couldn't check: not a format the app knows", named=True))
        # a KDE wallet with a blank password is still encrypted, with a key made from the empty
        # password: the only test is to try it (in memory; nothing from inside is kept)
        for w in wallets:
            try:
                state = kwallet.check_blank(w)
            except kwallet.Unsure as e:
                state = f"couldn't check: {e}"
            except OSError:
                state = "couldn't check: unreadable"
            if state.startswith("couldn't"):
                unsure.append(w.name)
                ev.append(Evidence.val(w.name, state, named=True))
                continue
            if state == kwallet.BLANK:
                plain.append(w.name)
                ev.append(Evidence.val(w.name, "opens without a password (KDE wallet)", named=True))
            else:
                ev.append(Evidence.val(w.name, "protected by a GPG key (KDE wallet)" if state == kwallet.GPG
                                       else "has a password (KDE wallet)", named=True))
        if plain:
            return failed(f"{'These open' if len(plain) > 1 else 'This opens'} without a password: {', '.join(plain)}.", *ev)
        if unsure:
            return unknown(f"Couldn't tell whether {', '.join(unsure)} {'have' if len(unsure) > 1 else 'has'} a password.", *ev)
        return passed("Keyrings and KDE wallets have a password." if rings and wallets else
                      "KDE wallets have a password." if wallets else "GNOME keyrings are encrypted.", *ev)


# ------------------------------------------------------------------ Chromium password store

# values encrypted with Chromium's built-in key start with "v10" (the keyring's key gives "v11")
V10 = "hex(substr({}, 1, 3)) = '763130'"


def basic_store_flags(scan: Scan) -> list[tuple[Path, bool]]:
    """Files that start a Chromium browser or an Electron app with --password-store=basic: any ~/.config/*-flags.conf
    (Arch's chromium-flags.conf, code-flags.conf, electron*-flags.conf...) and any menu entry, the user's own, the
    system's or a Flatpak's: (file, whether it is the user's own)."""
    host, paths = scan.host, scan.paths
    out = []
    for f in children(paths.config_home):
        if f.name.endswith("-flags.conf") and "--password-store=basic" in (read_text(host, f) or ""):
            out.append((f, True))
    for d, own in ((paths.data_home / "applications", True), (host.sys_path("/usr/share/applications"), False),
                   (host.sys_path("/var/lib/flatpak/exports/share/applications"), False),
                   (paths.data_home / "flatpak/exports/share/applications", False)):
        for f in children(d):
            if f.suffix == ".desktop" and "--password-store=basic" in (read_text(host, f) or ""):
                out.append((f, own))
    return out


def electron_plain_cookies(scan: Scan) -> list[tuple[str, int]]:
    """(app, cookies stored unencrypted) for each Electron app: Electron leaves its cookie store unencrypted unless the
    app turns that on (its EnableCookieEncryption fuse; tested with Electron 44: the value is in plain text). Counted,
    never read."""
    from .apps import BROWSER_DIRS
    roots = [(d, d.name) for d in children(scan.paths.config_home)]
    for app in scan.paths.flatpak_apps():
        roots += [(d, f"{d.name} ({app})") for d in children(scan.paths.flatpak_root / app / "config")]
    out = []
    for d, name in roots:
        if d.name in BROWSER_DIRS or not isdir(d) or not (isdir(d / "GPUCache") or isdir(d / "Code Cache")):
            continue
        for db in (d / "Network" / "Cookies", d / "Cookies"):
            n = sqlite_count(db, "SELECT count(*) FROM cookies WHERE length(value) > 0")
            if n:
                out.append((name, n))
                break
    return out


@register
class ChromiumBasicStore(Check):
    id = "auth.chromium_basic_store"

    def detect(self, scan: Scan) -> Outcome:
        host, paths = scan.host, scan.paths
        dirs = chromium_dirs(paths)
        ev, problems = [], []
        for f, _ in basic_store_flags(scan):
            problems.append(f.name)
            ev.append(Evidence.path("--password-store=basic in", host.display(f)))
        plain = electron_plain_cookies(scan)
        if not dirs and not problems and not plain:
            return absent("No Chromium-based browser or Electron app profiles were found.")

        v10 = 0
        for d in dirs:
            for prof in chromium_profiles(d):
                counts = [sqlite_count(prof / "Login Data",
                                        f"SELECT count(*) FROM logins WHERE {V10.format('password_value')}"),
                          sqlite_count(prof / "Network" / "Cookies",
                                        f"SELECT count(*) FROM cookies WHERE {V10.format('encrypted_value')}")
                          or sqlite_count(prof / "Cookies",
                                           f"SELECT count(*) FROM cookies WHERE {V10.format('encrypted_value')}")]
                n = sum(c or 0 for c in counts)
                if n:
                    v10 += n
                    ev.append(Evidence.count(f"Secrets under the built-in key ({d.label}, {prof.name})", n))
        notes = []
        if plain:
            ev += [Evidence.count(f"Cookies kept unencrypted by {name}", n) for name, n in plain[:10]]
            notes.append(Note("risk", "Electron apps that keep their logins unencrypted",
                              f"{', '.join(name for name, _ in plain[:5])} keep{'s' if len(plain) == 1 else ''} the "
                              "cookies that keep you signed in unencrypted, whatever keyring there is: that is how the "
                              "app was built (Electron leaves cookie encryption off unless an app turns it on). Anyone "
                              "who copies the folder is signed in as you. Nothing on this computer changes that: "
                              "full-disk encryption protects it from someone who takes the disk, and signing out of an "
                              "app you no longer use deletes its session.", ("enc.fde_missing",)))

        r = host.run("busctl", "--user", "list")
        secret_service = None if not r.ok else "org.freedesktop.secrets" in r.stdout
        if secret_service is not None:
            ev.append(Evidence.val("Secret Service on the session bus", secret_service))
        if problems or v10:
            return failed("Chromium-based browsers or Electron apps store passwords or cookies under a built-in key, "
                          "which is effectively unencrypted.", *ev, notes=notes)
        if secret_service is False and (dirs or plain):
            return failed("No keyring (Secret Service) is available, so Chromium-based browsers and Electron apps fall "
                          "back to the built-in key.", *ev, notes=notes)
        return passed("Chromium-based browsers and Electron apps use the keyring for passwords and cookies." if dirs
                      else "Electron apps use the keyring for the secrets they keep there.", *ev, notes=notes)


# ------------------------------------------------------------------ remote desktop

REMOTE_PORTS = {3389: "RDP", **{p: "VNC" for p in range(5900, 5911)}}
# GNOME Remote Desktop's daemon (gnome-remote-desktop-daemon, "gnome-remote-de" in /proc) and its user
# service run on every GNOME desktop since 42, with sharing off: only grdctl says whether it is on
REMOTE_PROCESSES = {"krdpserver": "KDE remote desktop", "krfb": "KDE desktop sharing (VNC)", "x11vnc": "x11vnc",
                    "xrdp": "xrdp", "vino-server": "Vino (VNC)", "wayvnc": "wayvnc", "Xvnc": "VNC server",
                    "x0vncserver": "TigerVNC", "rustdesk": "RustDesk", "anydesk": "AnyDesk", "teamviewerd": "TeamViewer",
                    # by their programs' names as /proc shows them (cut to 15 characters). VERIFY (catalogue): these
                    # three, which listen on no fixed port (Chrome Remote Desktop connects out, through Google)
                    "remoting_me2me_": "Chrome Remote Desktop", "chrome-remote-d": "Chrome Remote Desktop",
                    "nxserver.bin": "NoMachine", "nxnode.bin": "NoMachine", "sunshine": "Sunshine (game streaming)"}


@register
class RemoteDesktop(Check):
    id = "auth.remote_desktop"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        found: dict[str, str] = {}
        for s in scan.context.listeners or []:
            if s.port in REMOTE_PORTS and s.proto == "tcp" and not s.host_part.startswith(("127.", "[::1]")):
                found[f"{REMOTE_PORTS[s.port]} port {s.port}"] = "listening" + (" on all interfaces" if s.wildcard else "")
        procs = processes(host)
        for p, label in REMOTE_PROCESSES.items():
            if p in procs:
                found[label] = "running"
        r = host.run("grdctl", "status")
        notes = []
        if r.ok:
            for section, body in re.findall(r"^(RDP|VNC):\n((?:\s+.*\n?)*)", r.stdout, re.M):
                if re.search(r"Status:\s*enabled", body):
                    found[f"GNOME Remote Desktop ({section})"] = "enabled"
        elif "gnome-remote-de" in procs:
            notes.append(Note("limitation", "GNOME Remote Desktop",
                              "Its daemon runs (it does on every GNOME desktop), but grdctl status couldn't say whether "
                              "sharing is turned on; a listening RDP or VNC port above would show it."))
        ev = [Evidence.val(k, v) for k, v in found.items()]
        if found:
            return failed("A remote desktop or screen sharing server is running.", *ev, notes=notes)
        return passed("No remote desktop or screen sharing server is running.", notes=notes)


# ------------------------------------------------------------------ SSH and GPG keys

@register
class SshKeyNoPassphrase(Check):
    id = "auth.ssh_key_no_passphrase"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        keys = []
        for f in children(host.home / ".ssh"):
            if f.suffix == ".pub" or not isfile(f):
                continue
            try:
                head = host.read_head(f, 64) or b""
            except Unreadable:
                continue
            if head.startswith(b"-----BEGIN") and b"PRIVATE KEY" in head:
                keys.append(f)
        if not keys:
            return absent("No SSH private keys in ~/.ssh.")
        if not host.runner.which("ssh-keygen"):
            return unknown("ssh-keygen isn't installed, so key passphrases can't be checked.")
        ev, bare, loose, unsure = [], [], [], []
        for k in keys:
            mode = mode_of(k)
            others = f", readable by other users (mode {mode:o})" if mode is not None and mode & 0o044 else ""
            if others:
                loose.append(k.name)
            # an empty passphrase opens it: no passphrase. -P never prompts.
            r = host.run("ssh-keygen", "-y", "-P", "", "-f", str(k))
            if r.ok:
                state = "sk" if r.stdout.startswith("sk-") else "none"
            elif re.search(r"bad permissions|too open", r.stderr + r.stdout, re.I):
                # ssh-keygen won't load a key others can read, passphrase or not: read the key itself
                state = key_protection(read_text(host, k) or "")
            else:
                state = "encrypted"
            if state == "sk":
                ev.append(Evidence.val(k.name, "hardware key (needs the security key)" + others, named=True))
            elif state == "none":
                bare.append(k.name)
                ev.append(Evidence.val(k.name, "no passphrase" + others, named=True))
            elif state == "encrypted":
                ev.append(Evidence.val(k.name, "protected by a passphrase" + others, named=True))
            else:
                unsure.append(k.name)
                ev.append(Evidence.val(k.name, "couldn't check: a key format the app doesn't know" + others, named=True))
        notes = [Note("risk", "Private keys other users can read",
                      f"{', '.join(loose)}: ssh refuses to use a private key that other accounts can read. "
                      "chmod 600 makes it yours alone.")] if loose else []
        if bare:
            return failed(f"SSH key{'s' if len(bare) > 1 else ''} without a passphrase: {', '.join(bare)}.", *ev,
                          notes=notes)
        if unsure:
            return unknown(f"Couldn't tell whether {', '.join(unsure)} {'have' if len(unsure) > 1 else 'has'} a "
                           "passphrase.", *ev, notes=notes)
        return passed("Every SSH private key has a passphrase.", *ev, notes=notes)


def key_protection(text: str) -> str | None:
    """How an SSH private key file is protected, read from the file itself: "none" (no passphrase),
    "encrypted", "sk" (a security key's handle), or None for a format this doesn't know. The
    openssh-key-v1 format names its cipher ("none" when there is no passphrase) in the clear."""
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        try:
            raw = base64.b64decode("".join(ln.strip() for ln in text.splitlines() if ln and not ln.startswith("-----")))
        except ValueError:
            return None
        magic = b"openssh-key-v1\0"
        if not raw.startswith(magic):
            return None
        pos = len(magic)

        def field() -> bytes:
            nonlocal pos
            n = int.from_bytes(raw[pos:pos + 4], "big")
            pos += 4 + n
            return raw[pos - n:pos]
        cipher = field()
        field(), field()                       # kdf name and options
        pos += 4                               # number of keys
        public = field()
        kind = public[4:4 + int.from_bytes(public[:4], "big")]
        return "sk" if kind.startswith(b"sk-") else "none" if cipher == b"none" else "encrypted"
    if "BEGIN ENCRYPTED PRIVATE KEY" in text or re.search(r"^Proc-Type:\s*4,ENCRYPTED", text, re.M):
        return "encrypted"
    if re.search(r"BEGIN (RSA |EC |DSA )?PRIVATE KEY", text):
        return "none"
    return None


@register
class GpgNoPassphrase(Check):
    id = "auth.gpg_no_passphrase"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        home = Path(host.environ.get("GNUPGHOME") or host.home / ".gnupg")
        keys = [p for p in children(home / "private-keys-v1.d") if p.suffix == ".key"]
        if not keys:
            return absent("No GnuPG secret keys.")
        bare = card = 0
        for k in keys:
            try:
                head = (host.read_head(k, 512) or b"").decode("latin-1")
            except Unreadable:
                continue
            if "shadowed-private-key" in head:
                card += 1
            elif "protected-private-key" not in head and "private-key" in head:
                bare += 1
        ev = [Evidence.count("Secret keys", len(keys)), Evidence.count("Without a passphrase", bare)]
        if card:
            ev.append(Evidence.count("On a smartcard", card))
        if bare:
            return failed(f"{bare} GnuPG secret key{'s have' if bare > 1 else ' has'} no passphrase.", *ev)
        return passed("Every GnuPG secret key has a passphrase or lives on a smartcard.", *ev)


GPG_TTL_DEFAULTS = {"default-cache-ttl": 600, "max-cache-ttl": 7200, "default-cache-ttl-ssh": 1800,
                    "max-cache-ttl-ssh": 7200}


def gpg_agent_conf(text: str) -> dict[str, int]:
    """The cache times set in gpg-agent.conf (seconds); the last line for an option wins."""
    out = {}
    for line in text.splitlines():
        w = line.split("#", 1)[0].split()
        if len(w) >= 2 and w[0] in GPG_TTL_DEFAULTS and w[1].isdigit():
            out[w[0]] = int(w[1])
    return out


GPG_LIST = ("gpg", "--batch", "--no-tty", "--no-auto-check-trustdb", "--trust-model", "always", "--lock-never",
            "--with-colons", "--with-keygrip", "--fixed-list-mode", "--list-keys")
GPG_ALGOS = {"1": "RSA", "2": "RSA", "3": "RSA", "16": "Elgamal", "17": "DSA", "18": "ECDH", "19": "ECDSA",
             "20": "Elgamal", "22": "EdDSA"}
# passphrase cache times worth a word: past these, a key stays unlocked for most of a working day
GPG_LONG_TTL = {"default-cache-ttl": 3600, "max-cache-ttl": 43200}


def gpg_cache(conf: dict[str, int]) -> tuple[int, int]:
    """(how long gpg-agent keeps a passphrase after the key's last use, the longest it keeps it):
    max-cache-ttl caps default-cache-ttl."""
    longest = conf.get("max-cache-ttl", GPG_TTL_DEFAULTS["max-cache-ttl"])
    return min(conf.get("default-cache-ttl", GPG_TTL_DEFAULTS["default-cache-ttl"]), longest), longest


@dataclass
class GpgKey:
    fingerprint: str
    algo: str                   # "RSA", "DSA", ...
    bits: int
    expired: bool
    revoked: bool
    weak_parts: list[str]       # "RSA 1024-bit" for the primary key or a subkey that is weak


def _weak_gpg(algo: str, bits: int) -> bool:
    return algo == "DSA" or (algo in ("RSA", "Elgamal") and bits < 2048)


def gpg_secret_keys(listing: str, keygrips: set[str], now: float) -> list[GpgKey]:
    """Keys of the user's own (a secret part, matched by keygrip to private-keys-v1.d) in
    `gpg --with-colons --with-keygrip --list-keys` output. Someone else's public keys are left out."""
    keys: list[GpgKey] = []
    current: GpgKey | None = None
    last: tuple[str, str, int, str] | None = None     # (record, algo, bits, validity) waiting for its fpr/grp
    for line in listing.splitlines():
        f = line.split(":")
        kind = f[0]
        if kind in ("pub", "sub") and len(f) > 6:
            algo, bits = GPG_ALGOS.get(f[3], f"algorithm {f[3]}"), int(f[2]) if f[2].isdigit() else 0
            expired = f[1] == "e" or (f[6].isdigit() and int(f[6]) < now)
            if kind == "pub":
                current = GpgKey("", algo, bits, expired, f[1] == "r", [])
            last = (kind, algo, bits, f[1])
        elif kind == "fpr" and last and last[0] == "pub" and current is not None and not current.fingerprint:
            current.fingerprint = f[9]
        elif kind == "grp" and last and current is not None and len(f) > 9:
            rec, algo, bits, validity = last
            if f[9] in keygrips:
                if current not in keys:
                    keys.append(current)
                if validity not in ("r", "e") and _weak_gpg(algo, bits):
                    current.weak_parts.append(f"{algo} {bits}-bit" + (" subkey" if rec == "sub" else ""))
            last = None
    return [k for k in keys if not k.revoked]


@register
class GpgKeys(Check):
    id = "auth.gpg_keys"

    def detect(self, scan: Scan) -> Outcome:
        import time
        host = scan.host
        home = Path(host.environ.get("GNUPGHOME") or host.home / ".gnupg")
        grips = {p.stem.upper() for p in children(home / "private-keys-v1.d") if p.suffix == ".key"}
        if not grips:
            return absent("No GnuPG secret keys.")
        ev, notes = [], []
        conf = gpg_agent_conf(read_text(host, home / "gpg-agent.conf") or "")
        after_use, longest = gpg_cache(conf)
        long_ttl = after_use > GPG_LONG_TTL["default-cache-ttl"] or longest > GPG_LONG_TTL["max-cache-ttl"]
        for k in ("default-cache-ttl", "max-cache-ttl"):
            v = conf.get(k)
            ev.append(Evidence.val(k, f"{_duration(v)} (gpg-agent.conf)" if v is not None else
                                   f"{_duration(GPG_TTL_DEFAULTS[k])} (GnuPG's default)"))
        r = host.run(*GPG_LIST, timeout=30)
        if r.missing:
            keys = None
            notes.append(Note("limitation", "gpg isn't installed",
                              "Without it the keys themselves (their type, size and expiry) can't be read."))
        else:
            keys = gpg_secret_keys(r.stdout, grips, time.time()) if r.ok else None
        weak = [k for k in keys or [] if k.weak_parts and not k.expired]
        expired = [k for k in keys or [] if k.expired]
        if keys is not None:
            ev.append(Evidence.count("Your keys (with a secret part here)", len(keys)))
            parts: dict[str, int] = {}
            for k in weak:
                for w in k.weak_parts:
                    parts[w] = parts.get(w, 0) + 1
            ev += [Evidence.count(f"Weak: {w}", n) for w, n in sorted(parts.items())]
            if expired:
                ev.append(Evidence.count("Expired", len(expired)))
        findings = {"gpg_weak_key": bool(weak) if keys is not None else None}
        if weak:
            return failed(f"{len(weak)} of your GnuPG keys {'are' if len(weak) > 1 else 'is'} weak: "
                          f"{', '.join(sorted({w for k in weak for w in k.weak_parts}))}.", *ev, findings=findings,
                          notes=notes)
        if expired:                              # no risk of its own: nobody can encrypt to it or trust new signatures
            n = len(expired)
            notes.append(Note("info", f"{n} expired key{'s' if n > 1 else ''}",
                              f"{n} of your keys {'have' if n > 1 else 'has'} expired: nobody can encrypt to "
                              f"{'them' if n > 1 else 'it'} any more. Renew it to keep using it, or delete its secret part "
                              "if you don't need it (keep a backup if old mail was encrypted to it). The guide has the "
                              "commands."))
        if long_ttl:
            return warned(f"Your GnuPG passphrase is remembered for {_duration(after_use)} after each use, and up to "
                          f"{_duration(longest)} in all.", *ev, findings=findings, notes=notes)
        if keys is None:
            return unknown("Couldn't list the GnuPG keys" + (": gpg isn't installed." if r.missing else "."), *ev,
                           notes=notes)
        return passed("Your GnuPG keys are strong, and the passphrase cache is short.", *ev,
                      findings=findings, notes=notes)


# ------------------------------------------------------------------ credential files

def _has(pattern: str):
    rx = re.compile(pattern, re.M | re.I)
    return lambda text: bool(rx.search(text))


def _docker(text: str) -> bool:
    try:
        auths = json.loads(text).get("auths") or {}
    except (ValueError, AttributeError):
        return False
    return any(isinstance(v, dict) and v.get("auth") for v in auths.values())


CREDENTIAL_FILES = (
    (".git-credentials", "Git credentials", _has(r"^\w+://[^:\s]+:[^@\s]+@")),
    (".netrc", "netrc", _has(r"\bpassword\s+\S")),
    (".aws/credentials", "AWS credentials", _has(r"^\s*aws_secret_access_key\s*=\s*\S")),
    (".docker/config.json", "Docker registry logins", _docker),
    (".pgpass", "PostgreSQL passwords", _has(r"^[^#\s].*:.*:.*:.*:.+")),
    (".my.cnf", "MySQL password", _has(r"^\s*password\s*=\s*\S")),
    (".config/rclone/rclone.conf", "rclone passwords and tokens (obscured, not encrypted)",
     _has(r"^\s*(pass|password|token|secret_access_key|client_secret)\s*=\s*\S")),
    (".config/gh/hosts.yml", "GitHub CLI token", _has(r"^\s*oauth_token:\s*\S")),
    (".npmrc", "npm token", _has(r"_authToken\s*=\s*\S")),
    (".pypirc", "PyPI password", _has(r"^\s*password\s*[=:]\s*\S")),
    (".kube/config", "Kubernetes credentials", _has(r"^\s*(token|client-key-data|password):\s*\S")),
)
SKIP_DIRS = frozenset({"node_modules", ".git", ".cache", ".local", ".var", "snap", ".npm", ".cargo", ".rustup",
                       ".venv", "venv", ".tox", ".mozilla", ".config", "go", ".m2", ".gradle", "Trash", ".steam"})
ENV_FILE = re.compile(r"^\.env(\.(?!example$|sample$|template$|dist$)[\w.-]+)?$")
ENV_LINE = re.compile(r"""^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*['"]?([^'"\s#]*)""", re.M)
# a variable is a secret when a word of its name says so (DB_PASSWORD, STRIPE_SECRET_KEY, GITHUB_TOKEN)
SECRET_WORDS = frozenset({"SECRET", "SECRETS", "TOKEN", "PASSWORD", "PASSWD", "PASS", "PWD", "KEY", "APIKEY", "AUTH",
                          "CREDENTIAL", "CREDENTIALS", "PRIVATE"})
NOT_SECRET_WORDS = frozenset({"PUBLIC", "PUBLISHABLE", "ID", "URL", "FILE", "PATH", "NAME", "USER", "USERNAME"})
PLACEHOLDER = re.compile(r"^(|changeme|change_me|secret|password|xxx+|\*+|<.*|\$\{.*\}|\$\w+|your[_-].*|example.*|"
                         r"todo|none|null|true|false|0|1)$", re.I)
URL_WITH_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{3,}@", re.I)


def env_secrets(text: str) -> int:
    """How many variables in a .env file hold what looks like a real secret (not an empty value or a
    placeholder), counting connection URLs with a password in them."""
    n = 0
    for name, value in ENV_LINE.findall(text):
        words = set(name.upper().split("_"))
        if (words & SECRET_WORDS and not words & NOT_SECRET_WORDS and not PLACEHOLDER.match(value)) \
                or URL_WITH_PASSWORD.search(value):
            n += 1
    return n


def find_env_files(home: Path, max_depth: int = 4, limit: int = 20_000) -> list[Path]:
    out, seen, stack = [], 0, [(home, 0)]
    while stack:
        d, depth = stack.pop()
        for p in children(d):
            seen += 1
            if seen > limit:
                return out
            if p.is_symlink():
                continue
            if isdir(p):
                if depth < max_depth and p.name not in SKIP_DIRS:
                    stack.append((p, depth + 1))
            elif ENV_FILE.match(p.name):
                out.append(p)
    return sorted(out)


@register
class PlaintextCredentials(Check):
    id = "auth.plaintext_credentials"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, found, loose = [], [], []
        for rel, label, holds_secret in CREDENTIAL_FILES:
            p = host.home / rel
            text = read_text(host, p)
            if not text or not holds_secret(text):
                continue
            found.append(label)
            mode = mode_of(p)
            perms = f", readable by {'everyone' if mode & 0o004 else 'its group'} ({mode:o})" if mode and mode & 0o044 else ""
            if perms:
                loose.append(rel)
            ev.append(Evidence.path(label + perms, host.display(p)))
        envs = [p for p in find_env_files(host.home) if env_secrets(read_text(host, p) or "")]
        if envs:
            found.append(".env files")
            ev.append(Evidence.count(".env files with passwords or keys in your home", len(envs)))
            ev += [Evidence.path(".env file", host.display(p)) for p in envs[:5]]
        if found:
            extra = f" {len(loose)} of them can be read by other users." if loose else ""
            return failed(f"Credentials stored in plain text: {', '.join(found)}.{extra}", *ev)
        return passed("No plaintext credential files were found.")


# ------------------------------------------------------------------ history

HISTORY_FILES = (".bash_history", ".zsh_history", ".zhistory", ".local/share/fish/fish_history", ".python_history",
                 ".psql_history", ".mysql_history", ".sqlite_history", ".node_repl_history", ".lesshst",
                 ".local/state/zsh/history", ".local/share/zsh/history", ".cache/zsh/history", ".config/zsh/.zsh_history",
                 ".local/state/bash/history", ".histfile", ".config/nushell/history.txt", ".rediscli_history",
                 ".mongosh/mongosh_repl_history", ".dbshell", ".irb_history", ".local/share/irb/irb_history",
                 ".julia/logs/repl_history.jl", ".Rhistory", ".viminfo")
# a shell profile's HISTFILE= or ZDOTDIR= (zsh keeps HISTFILE as a shell variable, not exported: the app's own
# environment rarely has it)
_SHELL_VAR = re.compile(r"""^\s*(?:export\s+)?(HISTFILE|ZDOTDIR)=["']?([^"'\s;#]+)""", re.M)


def _expand(value: str, host, env: dict[str, str]) -> Path | None:
    home = str(host.home)
    out = value.replace("${HOME}", home).replace("$HOME", home)
    if out.startswith("~/"):
        out = home + out[1:]
    for var, default in (("XDG_STATE_HOME", ".local/state"), ("XDG_DATA_HOME", ".local/share"),
                         ("XDG_CACHE_HOME", ".cache"), ("XDG_CONFIG_HOME", ".config"), ("ZDOTDIR", "")):
        val = env.get(var) or (f"{home}/{default}" if default else home)
        out = out.replace("${" + var + "}", val).replace("$" + var, val)
    return Path(out) if out.startswith("/") and "$" not in out else None


def zdotdir(host) -> Path | None:
    """Where zsh reads its files from: $ZDOTDIR, from the environment or as ~/.zshenv sets it."""
    env = dict(host.environ)
    for var, value in _SHELL_VAR.findall(read_text(host, host.home / ".zshenv") or ""):
        if var == "ZDOTDIR" and "ZDOTDIR" not in env:
            p = _expand(value, host, env)
            if p is not None:
                env["ZDOTDIR"] = str(p)
    return Path(env["ZDOTDIR"]) if env.get("ZDOTDIR", "").startswith("/") else None


def history_files(host) -> list[Path]:
    """Shell and REPL history files: the usual places, $ZDOTDIR's (from the environment or ~/.zshenv), and HISTFILE
    as the environment or the shell profiles set it. Existing ones only, each once."""
    env = dict(host.environ)
    files: list[Path] = []
    zdot = zdotdir(host)
    if zdot is not None:
        env["ZDOTDIR"] = str(zdot)
    profiles = [host.home / f for f in (".zshenv", ".zshrc", ".bashrc", ".bash_profile", ".profile")]
    if zdot is not None:
        profiles += [zdot / ".zshenv", zdot / ".zshrc"]
        files += [zdot / ".zsh_history", zdot / ".zhistory", zdot / ".histfile"]
    for f in profiles:
        for var, value in _SHELL_VAR.findall(read_text(host, f) or ""):
            if var == "HISTFILE":
                p = _expand(value, host, env)
                if p is not None:
                    files.append(p)
    histfile = env.get("HISTFILE")
    if histfile and Path(histfile).is_absolute():
        files.insert(0, Path(histfile))
    files += [host.home / f for f in HISTORY_FILES]
    out, seen = [], set()
    for f in files:
        try:
            if not isfile(f) or f.resolve() in seen:
                continue
        except OSError:
            continue
        seen.add(f.resolve())
        out.append(f)
    return out


SECRET_PATTERNS = re.compile("|".join([
    r"(?i:\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*['\"]?[^\s'\"$]{4,})",
    r"(?i:authorization:\s*\S{8,})",
    r"(?i:\bbearer\s+[A-Za-z0-9._~+/=-]{16,})",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{40,}",
    r"\bxox[abpr]-[A-Za-z0-9-]{10,}",
    r"\bglpat-[A-Za-z0-9_-]{20}",
    r"\bsk-[A-Za-z0-9_-]{20,}",
    r"\b(?:mysql|mariadb|mysqldump)\b.*\s-p[^\s-]\S*",
    r"\bsshpass\s+-p\s*\S+",
    r"\bcurl\b.*\s-u\s*[^\s:]+:\S+",
    r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{3,}@",
]))
MAX_HISTORY = 8 * 1024 * 1024


@register
class ShellHistorySecrets(Check):
    id = "auth.shell_history_secrets"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, total, seen = [], 0, set()
        for f in history_files(host):
            seen.add(f)
            try:
                with open(f, "rb") as fh:
                    text = fh.read(MAX_HISTORY).decode("utf-8", errors="replace")
            except OSError:
                continue
            n = sum(1 for line in text.splitlines() if SECRET_PATTERNS.search(line))
            if n:
                total += n
                ev.append(Evidence.count(f"Lines that look like secrets in {host.display(f)}", n))
        if not seen:
            return absent("No shell or REPL history files were found.")
        notes = [Note("info", "Keep secrets out of history",
                      "In bash, HISTCONTROL=ignorespace (in ~/.bashrc) skips commands typed with a leading space; "
                      "in zsh, setopt HIST_IGNORE_SPACE does the same.")]
        if total:
            return failed(f"{total} history line{'s look' if total > 1 else ' looks'} like {'they contain' if total > 1 else 'it contains'} "
                          "passwords or tokens.", *ev, notes=notes)
        return passed("No secrets were spotted in shell or REPL history.", Evidence.count("History files checked", len(seen)))


# ------------------------------------------------------------------ sudo

# Commands that hand out a root shell when run with sudo (from the GTFOBins list): a NOPASSWD rule
# for any of them is as good as NOPASSWD: ALL.
SHELL_CAPABLE = frozenset({"ALL", "bash", "sh", "zsh", "fish", "dash", "su", "env", "sudo", "vi", "vim", "nvim", "nano",
                           "emacs", "less", "more", "man", "python", "python3", "perl", "ruby", "lua", "find", "awk",
                           "gawk", "tee", "cp", "mv", "dd", "chmod", "chown", "tar", "zip", "rsync", "git", "docker",
                           "podman", "systemctl", "journalctl", "apt", "apt-get", "dnf", "pacman", "zypper", "pkexec",
                           "nmap", "ed", "script", "xargs", "busybox", "node", "php", "visudo", "crontab"})


# With sudo, these hand out a shell whatever arguments a rule fixes: an editor's :!sh, a pager's !sh
# (journalctl, git and systemctl page their output through less)
ESCAPE_WITH_ANY_ARGS = frozenset({"vi", "vim", "nvim", "nano", "emacs", "ed", "less", "more", "man", "journalctl", "git",
                                  "script", "busybox", "visudo", "crontab"})
# systemctl verbs that act and print little: no pager, no editor
SYSTEMCTL_SAFE = frozenset({"start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "enable", "disable",
                            "is-active", "is-enabled", "is-failed", "daemon-reload", "kill", "mask", "unmask", "suspend",
                            "hibernate", "suspend-then-hibernate", "poweroff", "reboot", "halt"})


def _writable(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _broad(commands: str) -> bool:
    """A sudoers command list that gives a root shell. With arguments, sudo allows only those: a
    program that can't escape to a shell stays narrow, unless it runs a file this user can change."""
    for cmd in commands.split(","):
        words = cmd.strip().split()
        if not words:
            continue
        prog, args = words[0].rsplit("/", 1)[-1], words[1:]
        if prog == "ALL":
            return True
        if prog not in SHELL_CAPABLE:
            continue
        if not args or any(c in a for a in args for c in "*?["):
            return True                                   # any arguments at all
        if args == ['""']:
            continue                                      # none allowed
        if prog in ESCAPE_WITH_ANY_ARGS:
            return True
        if prog == "systemctl" and (args[0] not in SYSTEMCTL_SAFE and "--no-pager" not in args):
            return True
        if any(a.startswith("/") and _writable(a) for a in args):
            return True                                   # a script this user can rewrite
    return False


@register
class SudoNopasswd(Check):
    id = "auth.sudo_nopasswd"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, broad, narrow = [], [], []
        if host.runner.which("sudo"):
            # -n never prompts. Like any sudo use it may leave a line in the auth log; it changes nothing.
            r = host.run("sudo", "-n", "-l")
            if r.ok:
                for line in r.stdout.splitlines():
                    if "NOPASSWD:" in line:
                        rule = line.strip()
                        (broad if _broad(rule.split("NOPASSWD:", 1)[1]) else narrow).append(rule)
            elif "password is required" not in (r.stderr + r.stdout):
                ev.append(Evidence.val("sudo -n -l", (r.stderr or r.stdout).strip()[:150]))
        try:
            doas = host.read_sys("/etc/doas.conf")
        except Unreadable:
            doas = None
            ev.append(Evidence.path("Needs administrator access", "/etc/doas.conf"))
        for line in (doas or "").splitlines():
            m = re.match(r"^\s*permit\b([^#]*)", line)
            if m and re.search(r"\bnopass\b", m.group(1)):
                cmd = re.search(r"\bcmd\s+(\S+)", m.group(1))
                (narrow if cmd and cmd.group(1).rsplit("/", 1)[-1] not in SHELL_CAPABLE else broad).append(
                    "doas: " + line.strip())
        if not host.runner.which("sudo") and doas is None:
            return absent("Neither sudo nor doas is set up.")
        ev += [Evidence.val("Passwordless rule", r[:150]) for r in broad[:5]]
        notes = []
        if narrow:
            ev.append(Evidence.count("Passwordless rules for specific commands", len(narrow)))
            notes.append(Note("info", "Some specific commands run as root without a password",
                              f"{len(narrow)} rule{'s let' if len(narrow) > 1 else ' lets'} particular programs run as "
                              "root without a password, e.g. " + narrow[0].split("NOPASSWD:")[-1].strip()[:100] +
                              ". Distributions ship rules like these for their own tools; they are only a risk if "
                              "the program can be made to run other commands."))
        if broad:
            return failed("Commands can be run as root without a password.", *ev, notes=notes)
        return passed("Running arbitrary commands as root asks for a password.", *ev, notes=notes)


# ------------------------------------------------------------------ Firefox / Thunderbird primary password

# Runs in its own process: NSS can be initialised once per process. Reads key4.db read-only and
# prints 1 if a Primary Password is set, 0 if not. `has password` is what Firefox itself uses:
# PK11_NeedLogin && !PK11_NeedUserInit on the internal key slot.
NSS_SCRIPT = r"""
import ctypes, ctypes.util, sys
lib = ctypes.util.find_library("nss3") or "libnss3.so"
nss = ctypes.CDLL(lib)
nss.NSS_Initialize.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
nss.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
nss.PK11_NeedLogin.argtypes = [ctypes.c_void_p]
nss.PK11_NeedUserInit.argtypes = [ctypes.c_void_p]
nss.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
if nss.NSS_Initialize(b"sql:" + sys.argv[1].encode(), b"", b"", b"secmod.db", 0x1) != 0:
    print("error"); sys.exit(2)
slot = nss.PK11_GetInternalKeySlot()
print(1 if nss.PK11_NeedLogin(slot) and not nss.PK11_NeedUserInit(slot) else 0)
nss.PK11_FreeSlot(slot)
nss.NSS_Shutdown()
"""


def has_primary_password(scan: Scan, profile: Path) -> bool | None:
    r = scan.host.run(sys.executable, "-I", "-c", NSS_SCRIPT, str(profile))
    out = r.stdout.strip()
    return True if out == "1" else False if out == "0" else None


@register
class FirefoxNoPrimaryPassword(Check):
    id = "auth.firefox_no_primary_password"

    def detect(self, scan: Scan) -> Outcome:
        profiles = mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf", "Thunderbird"))
        if not profiles:
            return absent("No Firefox or Thunderbird profiles were found.")
        ev, exposed, unsure = [], [], []
        for p in profiles:
            logins = read_json(scan.host, p.path / "logins.json")
            n = len(logins.get("logins") or []) if isinstance(logins, dict) else 0
            if not n:
                continue
            has = has_primary_password(scan, p.path)
            if has is None:
                unsure.append(p.label)
                ev.append(Evidence.val(p.label, f"{n} saved passwords; couldn't check (NSS unavailable)"))
            elif has:
                ev.append(Evidence.val(p.label, f"{n} saved passwords, Primary Password set"))
            else:
                exposed.append(p.label)
                ev.append(Evidence.val(p.label, f"{n} saved passwords, no Primary Password"))
        if exposed:
            return failed(f"Saved passwords without a Primary Password: {', '.join(exposed)}.", *ev)
        if unsure:
            return unknown("Couldn't check whether a Primary Password is set.", *ev)
        if not ev:
            return passed("No saved passwords in Firefox or Thunderbird.",
                          Evidence.count("Profiles checked", len(profiles)))
        return passed("Saved passwords are protected by a Primary Password.", *ev)


# ------------------------------------------------------------------ permissions

ACL_USER, ACL_GROUP, ACL_MASK = 0x02, 0x08, 0x10


def acl_others(path: Path) -> list[tuple[str, int]]:
    """Named users and groups a POSIX ACL lets open a folder (read or search, within its mask), from the
    system.posix_acl_access attribute: (\"user\" | \"group\", id)."""
    try:
        raw = os.getxattr(path, "system.posix_acl_access")
    except OSError:
        return []
    entries = [(int.from_bytes(raw[i:i + 2], "little"), int.from_bytes(raw[i + 2:i + 4], "little"),
                int.from_bytes(raw[i + 4:i + 8], "little")) for i in range(4, len(raw) - 7, 8)]
    mask = next((perm for tag, perm, _ in entries if tag == ACL_MASK), 7)
    return [("user" if tag == ACL_USER else "group", ident) for tag, perm, ident in entries
            if tag in (ACL_USER, ACL_GROUP) and perm & mask & 0o5]


def home_group_others(host) -> tuple[str, int] | None:
    """(the home folder's group, how many other accounts are in it) when that group may open it and isn't the
    user's alone."""
    try:
        st = host.home.stat()
    except OSError:
        return None
    if not st.st_mode & 0o050:
        return None
    login, members, names = _accounts(host)
    others = members.get(st.st_gid, set()) - {login}
    return (names.get(st.st_gid, str(st.st_gid)), len(others)) if others else None


@register
class HomeWorldReadable(Check):
    id = "auth.home_world_readable"

    def detect(self, scan: Scan) -> Outcome:
        mode = mode_of(scan.host.home)
        if mode is None:
            return unknown("Couldn't read the home directory's permissions.")
        ev = [Evidence.val("Home directory mode", f"{mode:o}")]
        if mode & 0o007:
            return failed(f"Other users can open your home directory (mode {mode:o}).", *ev)
        group = home_group_others(scan.host)
        acl = acl_others(scan.host.home)
        if group:
            ev.append(Evidence.val("Its group", f"{group[0]}, with {group[1]} other account{'s' if group[1] != 1 else ''}"))
        if acl:
            ev.append(Evidence.count("Other users and groups an access list (ACL) lets in", len(acl)))
        if group or acl:
            who = " and ".join(([f"the {group[1]} other member{'s' if group[1] != 1 else ''} of its group {group[0]}"]
                                if group else []) + (["those an access list (ACL) names"] if acl else []))
            return failed(f"Your home directory can be opened by {who} (mode {mode:o}).", *ev)
        return passed(f"Other users can't open your home directory (mode {mode:o}).", *ev)


# ------------------------------------------------------------------ files that run at login

STARTUP_FILES = (".profile", ".bash_profile", ".bash_login", ".bashrc", ".bash_logout", ".zshenv", ".zprofile", ".zshrc",
                 ".zlogin", ".zlogout", ".xprofile", ".xsessionrc", ".pam_environment", ".config/fish/config.fish")
STARTUP_DIRS = (".config/fish/conf.d", ".config/environment.d")
MAX_PROGRAMS = 2000


@dataclass
class Writable:
    path: Path                  # the real file or folder (a link's target)
    shown: str                  # as the user knows it: "~/.bashrc", or "~/.bashrc (→ ~/dotfiles/bashrc)"
    mode: int
    why: str                    # who can change it, in words
    bits: int                   # the write bits that let them (0o002, 0o020), for chmod to take away
    owned: bool                 # the user owns it (chmod works); otherwise another account does


def _accounts(host) -> tuple[str | None, dict[int, set[str]], dict[int, str]]:
    """(this user's login name, each group's members, each group's name) from /etc/passwd and
    /etc/group: members listed in the group plus accounts whose primary group it is."""
    login, members, names = None, {}, {}
    for line in (host.read_sys("/etc/passwd") or "").splitlines():
        f = line.split(":")
        if len(f) >= 4 and f[2].isdigit() and f[3].isdigit():
            members.setdefault(int(f[3]), set()).add(f[0])
            if int(f[2]) == host.uid:
                login = f[0]
    for line in (host.read_sys("/etc/group") or "").splitlines():
        f = line.split(":")
        if len(f) >= 4 and f[2].isdigit():
            names[int(f[2])] = f[0]
            members.setdefault(int(f[2]), set()).update(m for m in f[3].split(",") if m)
    return login, members, names


def others_can_write(host, path: Path, accounts) -> Writable | None:
    """Whether an account other than this user can change `path` (followed through links): write
    permission for everyone, or for a group with someone else in it (or one that can't be looked
    up), or another owner. A sticky bit doesn't help: others can still create a file that is missing."""
    login, members, names = accounts
    try:
        real = path.resolve(strict=True)
        st = real.stat()
    except (OSError, RuntimeError):
        return None
    mode = st.st_mode & 0o7777
    shown = host.display(path) + (f" (→ {host.display(real)})" if real != path else "")
    if st.st_uid not in (host.uid, 0):
        return Writable(real, shown, mode, "another account owns it", 0, False)
    bits, why = 0, []
    if mode & 0o002:
        bits |= 0o002
        why.append("every account")
    if mode & 0o020:
        others = members.get(st.st_gid, set()) - {login}
        if others or st.st_gid not in members:
            bits |= 0o020
            group = names.get(st.st_gid, str(st.st_gid))
            why.append(f"group {group} ({len(others)} other account{'s' if len(others) != 1 else ''})" if others
                       else f"group {group}")
    if not bits:
        return None
    return Writable(real, shown, mode, " and ".join(why) + " can change it", bits, st.st_uid == host.uid)


def user_path_dirs(host) -> list[Path]:
    """Folders on PATH (this session's) that are under the home folder."""
    out = []
    for d in (host.environ.get("PATH") or "").split(":"):
        p = Path(d)
        if d and p.is_absolute() and p.is_relative_to(host.home) and p not in out:
            out.append(p)
    return out


def writable_startup_files(host) -> tuple[list[Writable], int]:
    """Login files, folders on PATH under home and the programs in them, and the folders holding
    them (home, ~/.config), that other accounts can change; and how many were looked at."""
    accounts = _accounts(host)
    paths = [host.home, host.home / ".config", host.home / ".config" / "fish"]
    paths += [host.home / f for f in STARTUP_FILES]
    for d in STARTUP_DIRS:
        paths += [host.home / d] + [f for f in children(host.home / d)]
    for d in user_path_dirs(host):
        paths.append(d)
        paths += [f for f in children(d)][:MAX_PROGRAMS]
    out, seen, looked = [], set(), 0
    for p in paths:
        try:
            if not p.exists():
                continue
        except OSError:
            continue
        looked += 1
        w = others_can_write(host, p, accounts)
        if w is not None and w.path not in seen:
            seen.add(w.path)
            out.append(w)
    return out, looked


@register
class StartupFilesWritable(Check):
    id = "auth.startup_files_writable"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        found, looked = writable_startup_files(host)
        dirs = user_path_dirs(host)
        ev = [Evidence.count("Files and folders checked", looked),
              Evidence.val("Folders on PATH under your home", ", ".join(host.display(d) for d in dirs) or "none")]
        ev += [Evidence.val(w.shown, f"mode {w.mode:o}: {w.why}") for w in found[:30]]
        if len(found) > 30:
            ev.append(Evidence.count("More", len(found) - 30))
        if found:
            return failed(f"Other accounts can change {len(found)} file{'s' if len(found) > 1 else ''} or folder"
                          f"{'s' if len(found) > 1 else ''} that run{'' if len(found) > 1 else 's'} as you when you log "
                          "in or type a command.", *ev)
        return passed("Only you can change the files that run when you log in or type a command.", *ev)


UMASK_LINE = re.compile(r"^\s*umask\s+([0-7]{3,4})\b", re.M)
PROFILE_FILES = (".profile", ".bash_profile", ".bash_login", ".bashrc", ".zprofile", ".zshrc", ".config/fish/config.fish")


def shell_umask(scan: Scan) -> tuple[int | None, str | None]:
    """The umask a login shell would end up with: the last `umask` line in the user's profiles
    (over the system-wide ones), and the file it came from."""
    host = scan.host
    found: tuple[int | None, str | None] = (None, None)
    for path, display in [(host.sys_path("/etc/profile"), "/etc/profile"), (host.sys_path("/etc/bash.bashrc"), "/etc/bash.bashrc")] \
            + [(host.home / f, "~/" + f) for f in PROFILE_FILES]:
        for m in UMASK_LINE.finditer(read_text(host, path) or ""):
            found = (int(m.group(1), 8), display)
    return found


@register
class Umask(Check):
    id = "auth.umask"

    def detect(self, scan: Scan) -> Outcome:
        status = scan.host.read_sys("/proc/self/status") or ""
        m = re.search(r"^Umask:\s*([0-7]+)", status, re.M)
        session = int(m.group(1), 8) if m else None
        shell, where = shell_umask(scan)
        ev = []
        if session is not None:
            ev.append(Evidence.val("Umask of this session (what apps started from the desktop get)", f"{session:04o}"))
        ev.append(Evidence.val("umask set in a shell profile", f"{shell:04o} ({where})" if shell is not None else "none"))
        # the shell's umask is what the user's own commands create files with; the session's
        # covers everything started from the desktop
        values = [v for v in (session, shell) if v is not None]
        if not values:
            return unknown("Couldn't read the umask.", *ev)
        loose = [v for v in values if not v & 0o004]
        if loose:
            which = "the shell profile" if shell in loose and session not in loose else \
                "the desktop session" if session in loose and shell not in loose else "both the session and the shell"
            home_mode = mode_of(scan.host.home)
            ev.append(Evidence.val("Home directory mode", f"{home_mode:o}" if home_mode is not None else "unknown"))
            if home_mode is not None and not home_mode & 0o001:
                # other accounts can't enter the home folder, so the umask only matters outside it
                return passed("New files would be readable by other users, but they can't get into your home folder.",
                              *ev, notes=[Note("info", "Outside your home folder",
                                               f"The umask ({loose[0]:04o}) still makes files you create in /tmp or in "
                                               "folders you share with other accounts readable by them.")])
            return failed(f"New files are readable by other users (umask {loose[0]:04o}, from {which}), and they can "
                          "get into your home folder.", *ev)
        return passed("New files aren't readable by other users.", *ev)


# ------------------------------------------------------------------ known_hosts and login records

def known_hosts_entries(text: str) -> tuple[int, int, int]:
    """(plain, hashed, markers) entries in a known_hosts file: servers listed by name that
    ssh-keygen -H would hash, hashed ones, and lines it leaves as they are (@cert-authority and
    @revoked lines, and wildcard patterns, which it can't hash)."""
    plain = hashed = markers = 0
    for line in text.splitlines():
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if f[0].startswith("@") and len(f) > 1:          # @cert-authority / @revoked: ssh-keygen -H keeps them
            markers += 1
        elif f[0].startswith("|1|"):
            hashed += 1
        elif "*" not in f[0] and "?" not in f[0]:         # a wildcard pattern can't be hashed
            plain += 1
        else:
            markers += 1
    return plain, hashed, markers


@dataclass(frozen=True)
class SshLine:
    """One option line of the SSH client's configuration, in the order ssh reads them."""
    path: Path                  # the file as read on this host
    display: str
    index: int                  # line number in that file, from 0
    key: str                    # lower case
    args: tuple[str, ...]
    every: bool                 # applies to every server: outside Host blocks, in `Host *` or `Match all`
    user: bool                  # in the user's own files (~/.ssh), which ssh reads before /etc

    @property
    def value(self) -> str:
        return self.args[0].lower() if self.args else ""


def _ssh_scope(key: str, arg: str) -> bool:
    return arg.split() == ["*"] if key == "host" else arg.strip().lower() == "all"


def ssh_config_lines(host) -> list[SshLine]:
    """Every option line of ~/.ssh/config, then /etc/ssh/ssh_config, following Include (Debian and
    Ubuntu include ssh_config.d/*.conf) where ssh would: an Include inside a Host block that isn't
    `Host *` is read only for those servers, so all its lines count as for some servers only."""
    out: list[SshLine] = []

    def read(path: Path, display: str, base: Path, user: bool, every_start: bool, depth: int = 0) -> None:
        text = read_text(host, path)
        if text is None or depth > 8:
            return
        every = every_start
        for i, line in enumerate(text.splitlines()):
            words = line.strip().replace("=", " ", 1).split(None, 1)
            if not words or words[0].startswith("#"):
                continue
            key, arg = words[0].lower(), (words[1].strip() if len(words) > 1 else "")
            if key in ("host", "match"):
                every = every_start and _ssh_scope(key, arg)
            elif key == "include":
                for pattern in arg.split():
                    p = Path(pattern.replace("~", str(host.home), 1)) if pattern.startswith("~") else \
                        Path(pattern) if pattern.startswith("/") else base / pattern
                    real = p if str(p).startswith(str(host.home)) else host.sys_path(str(p))
                    for f in sorted(real.parent.glob(real.name)):
                        shown = host.display(f) if str(p).startswith(str(host.home)) else str(p.parent / f.name)
                        read(f, shown, base, user, every, depth + 1)
            else:
                out.append(SshLine(path, display, i, key, tuple(arg.split()), every, user))

    read(host.home / ".ssh" / "config", "~/.ssh/config", host.home / ".ssh", True, True)
    read(host.sys_path("/etc/ssh/ssh_config"), "/etc/ssh/ssh_config", Path("/etc/ssh"), False, True)
    return out


def ssh_setting(lines: list[SshLine], name: str) -> SshLine | None:
    """The line ssh takes an option's value from for every server: the first one, as in ssh."""
    name = name.lower()
    return next((ln for ln in lines if ln.key == name and ln.every), None)


def ssh_client_option(host, name: str) -> tuple[str | None, str | None]:
    """The value ssh uses for a client option for every host, and the file it comes from:
    ~/.ssh/config, then /etc/ssh/ssh_config, following Include, the first value found winning as
    in ssh. Only lines outside Host blocks, or in `Host *` / `Match all`, count: others apply to
    some servers only."""
    ln = ssh_setting(ssh_config_lines(host), name)
    return (ln.value or None, ln.display) if ln else (None, None)


@register
class SshKnownHostsPlain(Check):
    id = "auth.ssh_known_hosts_plain"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        kh = host.home / ".ssh" / "known_hosts"
        text = read_text(host, kh)
        if text is None:
            return absent("No ~/.ssh/known_hosts.")
        plain, hashed, markers = known_hosts_entries(text)
        value, where = ssh_client_option(host, "HashKnownHosts")
        hashing = value == "yes"
        ev = [Evidence.count("Servers listed by name", plain), Evidence.count("Hashed entries", hashed),
              Evidence.val("HashKnownHosts", f"{value} ({where})" if value else "not set (ssh's default: no)")]
        if markers:
            ev.append(Evidence.count("Lines ssh-keygen can't hash (@cert-authority, @revoked, wildcards)", markers))
        if plain:
            return failed(f"{plain} server{'s are' if plain > 1 else ' is'} listed by name in ~/.ssh/known_hosts.", *ev)
        if not hashing and hashed:
            return warned("Entries are hashed now, but new servers will be written by name: HashKnownHosts isn't on.", *ev)
        return passed("Known SSH servers are stored hashed." if hashed else "~/.ssh/known_hosts is empty.", *ev)


# ------------------------------------------------------------------ SSH client settings and the agent

# ssh's safe values, written by the guide where a setting weakens every connection
SSH_SAFE = {"forwardagent": "no", "stricthostkeychecking": "accept-new",
            "userknownhostsfile": "~/.ssh/known_hosts ~/.ssh/known_hosts2"}
SSH_NAMES = {"forwardagent": "ForwardAgent", "stricthostkeychecking": "StrictHostKeyChecking",
             "userknownhostsfile": "UserKnownHostsFile", "addkeystoagent": "AddKeysToAgent"}


def ssh_weak_settings(lines: list[SshLine]) -> dict[str, SshLine]:
    """The settings, for every server, that weaken every SSH connection: agent forwarding (any
    value but no: yes, or a socket path), host keys never checked, and a known-hosts file that
    forgets every server."""
    out = {}
    fa = ssh_setting(lines, "ForwardAgent")
    if fa is not None and fa.value != "no":
        out["forwardagent"] = fa
    shk = ssh_setting(lines, "StrictHostKeyChecking")
    if shk is not None and shk.value in ("no", "off"):
        out["stricthostkeychecking"] = shk
    ukh = ssh_setting(lines, "UserKnownHostsFile")
    if ukh is not None and ukh.args and all(a == "/dev/null" for a in ukh.args):
        out["userknownhostsfile"] = ukh
    return out


@dataclass
class SshAgent:
    kind: str | None            # which program serves $SSH_AUTH_SOCK, in words; None: no agent
    keys: int | None            # keys loaded (ssh-add -l); None when it couldn't be asked
    lifetime: str | None        # its default time limit for keys, in words; "" for none; None unknown
    preloads: bool = False      # it lists the keys in ~/.ssh before they are unlocked (GNOME's agents): a count
                                # isn't how many are unlocked. VERIFY on GNOME 46+ and Mint 22.3 (ssh-add -l at login)


def ssh_agent(scan: Scan) -> SshAgent:
    host = scan.host
    sock = host.environ.get("SSH_AUTH_SOCK") or ""
    if not sock:
        return SshAgent(None, None, None)
    if "/keyring/ssh" in sock:
        kind, lifetime = "GNOME Keyring", ""
    elif "/gcr/ssh" in sock:
        kind, lifetime = "GNOME's SSH agent (gcr-ssh-agent)", ""
    elif "S.gpg-agent.ssh" in sock:
        kind = "gpg-agent"
        home = Path(host.environ.get("GNUPGHOME") or host.home / ".gnupg")
        conf = gpg_agent_conf(read_text(host, home / "gpg-agent.conf") or "")
        ttl = conf.get("max-cache-ttl-ssh", 7200)
        lifetime = _duration(ttl)
    else:
        kind, lifetime = "ssh-agent", ""
        for p in children(host.sys_path("/proc")):
            if not p.name.isdigit():
                continue
            try:
                if host.root == Path("/") and p.stat().st_uid != host.uid:
                    continue
                if (p / "comm").read_text().strip() != "ssh-agent":
                    continue
                argv = (p / "cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            for i, a in enumerate(argv):
                if a == b"-t" and i + 1 < len(argv):
                    lifetime = argv[i + 1].decode(errors="replace")
                elif a.startswith(b"-t") and len(a) > 2:
                    lifetime = a[2:].decode(errors="replace")
            if lifetime:
                lifetime = _duration(int(lifetime)) if lifetime.isdigit() else lifetime
                break
    r = host.run("ssh-add", "-l")
    keys = len([ln for ln in r.stdout.splitlines() if ln.strip()]) if r.ok else 0 if r.returncode == 1 else None
    return SshAgent(kind, keys, lifetime, preloads=kind is not None and kind.startswith("GNOME"))


def _duration(seconds: int) -> str:
    if seconds >= 86400 and seconds % 86400 == 0:
        return f"{seconds // 86400} day{'s' if seconds > 86400 else ''}"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    return f"{seconds // 60} min" if seconds % 60 == 0 else f"{seconds} s"


@register
class SshClientSettings(Check):
    id = "auth.ssh_client_settings"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        lines = ssh_config_lines(host)
        if not lines and not host.runner.which("ssh"):
            return absent("The SSH client isn't installed.")
        weak = ssh_weak_settings(lines)
        ev = []
        for key in ("forwardagent", "stricthostkeychecking", "userknownhostsfile"):
            ln = weak.get(key) or ssh_setting(lines, key)
            shown = f"{' '.join(ln.args)} ({ln.display})" if ln else "not set (ssh's default)"
            ev.append(Evidence.val(SSH_NAMES[key], shown + (" — for every server" if key in weak else "")))
        some = len({(ln.path, ln.index) for ln in lines if ln.key == "forwardagent" and not ln.every and ln.value != "no"})
        notes = []
        if some:
            notes.append(Note("info", "Agent forwarding to some servers",
                              f"{some} setting{'s' if some > 1 else ''} turn{'' if some > 1 else 's'} agent forwarding on "
                              "for particular servers. Each of them can use your keys while you are logged in to it: "
                              "keep it to servers you trust, or use ProxyJump instead, which never hands them your "
                              "agent."))
        add = ssh_setting(lines, "AddKeysToAgent")
        if add is not None:
            ev.append(Evidence.val("AddKeysToAgent", f"{' '.join(add.args)} ({add.display})"))
        agent = ssh_agent(scan)
        unlimited: bool | None = None
        if agent.kind is not None:
            ev.append(Evidence.val("SSH agent", agent.kind))
            if agent.keys is not None:
                ev.append(Evidence.count("Keys the agent offers (unlocked or not)" if agent.preloads else
                                         "Keys loaded in the agent", agent.keys))
            if agent.lifetime is not None:
                ev.append(Evidence.val("The agent's time limit for keys", agent.lifetime or "none: until you log out"))
            unlimited = None if agent.keys is None or agent.lifetime is None else bool(agent.keys and not agent.lifetime)
            if agent.preloads and agent.keys:
                unlimited = None                 # it can't be told which of them are unlocked
                notes.append(Note("info", "Keys stay unlocked until you log out once used",
                                  f"{agent.kind} offers every key in ~/.ssh with a .pub file, and asks for its passphrase "
                                  "the first time one is used. From then on the key stays unlocked until you log out: "
                                  "it has no time limit. Which keys are unlocked now can't be seen from outside."))
            elif agent.keys:
                notes.append(Note("limitation", "Keys added with their own limit",
                                  "A key added with ssh-add -t (a time limit) or -c (confirm each use) keeps that limit; "
                                  "the agent doesn't tell other programs, so the app can't see it."))
        else:
            unlimited = False
        findings = {"agent_forwarded_everywhere": "forwardagent" in weak,
                    "host_keys_unchecked": "stricthostkeychecking" in weak or "userknownhostsfile" in weak,
                    "agent_keys_unlimited": unlimited}
        problems = []
        if "forwardagent" in weak:
            problems.append("every server you log in to can use your SSH keys while you are connected")
        if "stricthostkeychecking" in weak:
            problems.append("ssh connects even when a server's key has changed")
        if "userknownhostsfile" in weak:
            problems.append("ssh forgets every server, so it can't notice one being impersonated")
        if problems:
            return failed(problems[0][0].upper() + "; ".join(problems)[1:] + ".", *ev, findings=findings, notes=notes)
        if unlimited:
            return warned(f"{agent.keys} key{'s stay' if agent.keys > 1 else ' stays'} unlocked in the SSH agent until "
                          "you log out.", *ev, findings=findings, notes=notes)
        return passed("ssh checks every server and doesn't hand your keys to them.", *ev, findings=findings, notes=notes)


# ------------------------------------------------------------------ keys that can log in as you

SSH_KEY_TYPES = {"ssh-rsa": "RSA", "ssh-dss": "DSA", "ssh-ed25519": "Ed25519", "ecdsa-sha2-nistp256": "ECDSA P-256",
                 "ecdsa-sha2-nistp384": "ECDSA P-384", "ecdsa-sha2-nistp521": "ECDSA P-521",
                 "sk-ssh-ed25519@openssh.com": "Ed25519 security key",
                 "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA security key"}
AUTHORIZED_KEYS = (".ssh/authorized_keys", ".ssh/authorized_keys2")


@dataclass
class AuthorizedKey:
    path: Path
    line: str                   # the whole line, to find it again for removal: never shown or logged
    kind: str                   # "Ed25519", "RSA", ...
    bits: int | None
    fingerprint: str            # SHA256:..., as ssh-keygen -l prints it
    restricted: bool            # from=, command= or restrict
    authority: bool             # cert-authority: trusts every key a CA signs

    @property
    def weak(self) -> bool:
        return self.kind.startswith("DSA") or (self.kind.startswith("RSA") and (self.bits or 0) < 2048)

    def describe(self) -> str:
        return f"{self.kind}{f' {self.bits}-bit' if self.bits and not self.kind.startswith(('Ed', 'ECDSA')) else ''}"


def _key_options(line: str) -> tuple[str, str]:
    """(options, the rest) of an authorized_keys line: options run to the first space outside quotes."""
    quoted = False
    for i, c in enumerate(line):
        if c == '"':
            quoted = not quoted
        elif c.isspace() and not quoted:
            return line[:i], line[i:].strip()
    return line, ""


def _ssh_string(blob: bytes, pos: int) -> tuple[bytes, int]:
    n = int.from_bytes(blob[pos:pos + 4], "big")
    return blob[pos + 4:pos + 4 + n], pos + 4 + n


def parse_authorized_key(path: Path, line: str) -> AuthorizedKey | None:
    import hashlib

    text = line.strip()
    if not text or text.startswith("#"):
        return None
    options = ""
    first = text.split(None, 1)[0]
    if first not in SSH_KEY_TYPES and not first.endswith("-cert-v01@openssh.com"):
        options, text = _key_options(text)
    words = text.split()
    if len(words) < 2:
        return None
    ktype, b64 = words[0], words[1]
    cert = ktype.endswith("-cert-v01@openssh.com")
    base = ktype.replace("-cert-v01@openssh.com", "")
    kind = SSH_KEY_TYPES.get(base, base) + (" certificate" if cert else "")
    try:
        blob = base64.b64decode(b64, validate=True)
    except ValueError:
        return None
    bits = None
    try:
        name, pos = _ssh_string(blob, 0)
        if cert:
            _, pos = _ssh_string(blob, pos)                       # the certificate's nonce
        if base == "ssh-rsa":
            _, pos = _ssh_string(blob, pos)                       # e
            n, _ = _ssh_string(blob, pos)
            bits = int.from_bytes(n, "big").bit_length()
        elif base == "ssh-dss":
            p, _ = _ssh_string(blob, pos)
            bits = int.from_bytes(p, "big").bit_length()
    except (IndexError, ValueError):
        bits = None
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    opts = options.lower()
    return AuthorizedKey(path, line.rstrip("\n"), kind, bits, fp,
                         bool(re.search(r'(^|,)(from=|command=|restrict\b)', opts)),
                         bool(re.search(r"(^|,)cert-authority\b", opts)))


def authorized_keys(host) -> list[AuthorizedKey]:
    out = []
    for rel in AUTHORIZED_KEYS:
        path = host.home / rel
        for line in (read_text(host, path) or "").splitlines():
            k = parse_authorized_key(path, line)
            if k is not None:
                out.append(k)
    return out


def sshd_ports(host) -> set[int]:
    ports = set()
    files = [host.sys_path("/etc/ssh/sshd_config")] + sorted(host.sys_path("/etc/ssh/sshd_config.d").glob("*.conf"))
    for f in files:
        try:
            text = host.read_file(f) or ""
        except Unreadable:
            continue
        ports |= {int(m) for m in re.findall(r"^\s*Port\s+(\d+)\s*$", text, re.M | re.I)}
    return ports or {22}


def ssh_server_reachable(scan: Scan) -> bool | None:
    """Whether an SSH server listens on an address other machines can reach (sshd itself, or
    systemd's ssh.socket on Ubuntu 24.04 and later); None when the listening sockets couldn't be read."""
    listeners = scan.context.listeners
    if listeners is None:
        return None
    ports = sshd_ports(scan.host)
    return any(s.proto == "tcp" and s.port in ports and not s.host_part.startswith(("127.", "[::1]", "::1"))
               for s in listeners)


@register
class SshAuthorizedKeys(Check):
    id = "auth.ssh_authorized_keys"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        keys = authorized_keys(host)
        if not keys:
            return absent("No key can log in to this account over SSH (no keys in ~/.ssh/authorized_keys).")
        kinds: dict[str, int] = {}
        for k in keys:
            label = k.describe() + (" (weak)" if k.weak else "")
            kinds[label] = kinds.get(label, 0) + 1
        ev = [Evidence.count("Keys that can log in as you", len(keys))]
        ev += [Evidence.count(label, n) for label, n in sorted(kinds.items())]
        restricted = sum(k.restricted for k in keys)
        if restricted:
            ev.append(Evidence.count("Limited to some addresses or one command", restricted))
        notes = []
        authority = sum(k.authority for k in keys)
        if authority:
            notes.append(Note("info", "A certificate authority is trusted",
                              f"{authority} line{'s' if authority > 1 else ''} trust{'' if authority > 1 else 's'} a "
                              "certificate authority: any key it signs can log in as you, not just the ones listed."))
        for rel in (".ssh", *AUTHORIZED_KEYS):
            mode = mode_of(host.home / rel)
            if mode is not None and mode & 0o022:
                ev.append(Evidence.val(f"~/{rel}", f"mode {mode:o}: other accounts can change it"))
        reachable = ssh_server_reachable(scan)
        weak = [k for k in keys if k.weak]
        ev.append(Evidence.val("SSH server", "listening for connections from other machines" if reachable else
                               "not listening for other machines" if reachable is False else "couldn't tell"))
        findings = {"sshd_reachable": reachable, "weak_authorized_keys": bool(weak)}
        n = len(keys)
        if weak:
            return failed(f"{len(weak)} weak key{'s' if len(weak) > 1 else ''} ({', '.join(sorted({k.describe() for k in weak}))}) "
                          "can log in as you" + (" over the network." if reachable else "."), *ev, findings=findings,
                          notes=notes)
        if reachable is False:
            return passed(f"{n} key{'s' if n > 1 else ''} could log in as you, but no SSH server is listening for other "
                          "machines.", *ev, findings=findings, notes=notes + [Note(
                              "risk", "If an SSH server is started",
                              "These keys would let their holders log in as you as soon as one runs (installing "
                              "openssh-server starts it on Debian and Ubuntu). Remove those you no longer use.")])
        return warned(f"{n} key{'s' if n > 1 else ''} can log in as you over SSH. Check that you know whose each one is.",
                      *ev, findings=findings, notes=notes)


LOGIN_RECORDS = ("/var/log/wtmp", "/var/log/lastlog", "/var/log/btmp", "/var/lib/wtmpdb/wtmp.db",
                 "/var/lib/lastlog/lastlog2.db")


@register
class LoginHistory(Check):
    id = "auth.login_history"

    def detect(self, scan: Scan) -> Outcome:
        ev, readable, found = [], [], []
        for f in LOGIN_RECORDS:
            mode = mode_of(scan.host.sys_path(f))
            if mode is None:
                continue
            found.append(f)
            ev.append(Evidence.val(f, f"mode {mode:o}" + (" (anyone can read it)" if mode & 0o004 else "")))
            if mode & 0o004:
                readable.append(f)
        if not found:
            return absent("No login records (wtmp, lastlog) on this system.")
        notes = []
        if "/var/log/btmp" in readable:
            notes.append(Note("risk", "btmp is readable by everyone",
                              "It records failed logins, including passwords typed into the user-name field by "
                              "mistake. It should be mode 600 (sudo chmod 600 /var/log/btmp)."))
        if readable:
            return failed(f"{len(readable)} login record file{'s' if len(readable) > 1 else ''} can be read by every "
                          "account on this machine.", *ev, notes=notes)
        return passed("Login records are only readable by administrators.", *ev)