"""Guided fixes: authentication (see the package docstring)."""

from __future__ import annotations

import re
from pathlib import Path

from ...fix import ChmodPath, ClearInFile, RootChange, WriteFile
from ...guide import Guide, Input, Step
from ...host import Unreadable
from .._util import children, isdir, isfile, mode_of, processes, read_text
from ..fixes import gset
from . import guide, option, evidence, service_off, install, dropin, remote_session


@guide("auth.autologin")
def autologin(check, scan, outcome):
    ev = scan.context.values["autologin"].evidence
    manual = [e for e in ev if e.label.startswith(("greetd", "Console autologin"))]
    steps = []
    if any(not e.label.startswith(("greetd", "Console autologin", "Display manager", "Needs")) for e in ev):
        steps.append(Step("Turn off automatic login", options=[option(check, "Turn off automatic login", [RootChange(
            "edit_config", {"target": "autologin"},
            "Comment out the automatic login lines in the display manager's configuration under /etc, and override "
            "those in its packaged files (/usr/lib, /usr/share) with a file of the app's own")],
            recommended=True)],
            side_effects=["Takes effect at the next boot or logout.",
                          "Make sure you know your login password first: lock the screen and unlock it with the "
                          "password. Without it, you can't get back to your desktop after the next restart."]))
    if manual:
        steps.append(Step("Automatic login set up elsewhere",
                          "These need editing by hand: remove the [initial_session] section from "
                          "/etc/greetd/config.toml, or the console autologin override files listed below.",
                          commands=[f"sudo rm {e.value}" for e in manual if e.label == "Console autologin"]
                          + (["sudoedit /etc/greetd/config.toml"] if any(e.label.startswith("greetd") for e in manual)
                             else [])))
    return Guide(check.id, "Turn off automatic login",
                 "With automatic login, anyone who turns the machine on is logged in as you. Without it, you type "
                 "your password at boot, and that same password then unlocks your keyring (GNOME Keyring or KWallet) "
                 "automatically, if they match; with automatic login it couldn't, so apps either asked for it or the "
                 "keyring was left without a password.", steps)


@guide("auth.empty_password")
def empty_password(check, scan, outcome):
    names = evidence(outcome, "Empty password")
    return Guide(check.id, "Give every account a password",
                 "An account with an empty password can be logged in to without one, wherever password logins "
                 "are allowed.", [
                     Step("Set a password",
                          "For accounts that people log in to. You'll be asked for the new password twice.",
                          commands=[f"sudo passwd {n}" for n in names]),
                     Step("Or lock the account", "For accounts nobody should log in to with a password.",
                          commands=[f"sudo passwd -l {n}" for n in names]),
                 ])


def _program(scan, names: tuple[str, ...], packages: dict[str, str], what: str) -> list[str]:
    """The command that opens a program, or, when it isn't installed, the one that installs it first (Fedora
    Workstation and Omarchy come without Seahorse)."""
    have = next((n for n in names if scan.host.runner.which(n)), None)
    if have:
        return [have]
    cmd = install(scan, **packages)
    return [f"{cmd}     # {what} isn't installed", names[-1]] if cmd else []


@guide("auth.keyring_blank")
def keyring_blank(check, scan, outcome):
    """One step per kind of store found blank, whatever the desktop: GNOME keyrings in Passwords and Keys, KDE wallets
    in KDE Wallet Manager (a Plasma user can have a blank GNOME keyring, and Cinnamon both)."""
    from ..auth import KEYRING_MAGIC, keyring_name
    host = scan.host
    rings = []                                          # (file, the name Passwords and Keys shows) of blank keyrings
    for p in children(scan.paths.data_home / "keyrings"):
        if p.suffix != ".keyring":
            continue
        try:
            head = host.read_head(p, 512) or b""
        except Unreadable:
            continue
        if not head.startswith(KEYRING_MAGIC) and head.lstrip().startswith(b"[keyring]"):
            rings.append((p, keyring_name(head) or p.stem))
    wallets = [w.removesuffix(".kwl") for w in evidence(outcome, value="opens without a password")]
    autologin = ["With automatic login on, nothing types that password for you, so it is asked for after login. See "
                 "auth.autologin."]
    steps = []
    if rings:
        names = ", ".join(f"“{n}”" for _, n in rings)
        login = any(p.name == "login.keyring" for p, _ in rings)
        steps.append(Step(
            f"Set a password for the GNOME keyring{'s' if len(rings) > 1 else ''}",
            f"Open Passwords and Keys (Seahorse), right-click the keyring {names} under Passwords and choose Change "
            "Password. Leave the old password empty and type the new one twice."
            + (" For the Login keyring use your login password: it then unlocks when you log in." if login else
               " Your login password unlocks only the Login keyring at login: this one asks for its own password when "
               "an app first needs it."),
            commands=_program(scan, ("seahorse",), dict(debian="seahorse", fedora="seahorse", arch="seahorse",
                                                        suse="seahorse"), "Passwords and Keys"),
            side_effects=autologin if login else []))
    if wallets:
        names = ", ".join(f"“{w}”" for w in wallets)
        default = "kdewallet" in wallets
        steps.append(Step(
            f"Set a password for the KDE wallet{'s' if len(wallets) > 1 else ''}",
            f"Open KDE Wallet Manager, select the wallet {names} and choose Change Password."
            + (" For kdewallet use your login password: Plasma then opens it when you log in." if default
               else " This wallet asks for its own password when an app first needs it."),
            commands=_program(scan, ("kwalletmanager6", "kwalletmanager5"),
                              dict(debian="kwalletmanager", fedora="kwalletmanager5", arch="kwalletmanager",
                                   suse="kwalletmanager"), "KDE Wallet Manager"),
            side_effects=autologin if default else []))
    if not steps:
        steps.append(Step("Your keyrings", "None opens without a password now.", done=True))
    return Guide(check.id, "Give your keyring a password",
                 "A keyring with a blank password is stored unencrypted: anyone who can read your files can read "
                 "the passwords in it.", steps)


@guide("auth.chromium_basic_store")
def chromium_basic_store(check, scan, outcome):
    from ..auth import basic_store_flags
    host, paths = scan.host, scan.paths
    strip = lambda old: re.sub(r"[ \t]*--password-store=basic\b", "", old or "")  # noqa: E731
    actions = []
    for f, own in basic_store_flags(scan):
        if own:
            actions.append(WriteFile(f, strip, "Remove --password-store=basic", host.display(f)))
        elif f.suffix == ".desktop":
            # an installed launcher: a copy of the user's own, without the flag, takes its place in the menu
            local = paths.data_home / "applications" / f.name
            if not isfile(local):
                actions.append(WriteFile(local, lambda old, t=read_text(host, f) or "": strip(t),
                                         f"Override the installed launcher {f.name} without --password-store=basic",
                                         host.display(local)))
    steps = [Step("Stop forcing the built-in key",
                  "Browsers and Electron apps started with --password-store=basic keep secrets under a key built into them.",
                  options=[option(check, "Remove the flag", actions, recommended=True,
                                  side_effects=["Takes effect the next time the browser starts."])] if actions else [],
                  done=not actions)]
    if any(e.label == "Secret Service on the session bus" and e.value is False for e in outcome.evidence):
        steps.append(_keyring_step(scan))
    steps.append(_resave_step(scan))
    return Guide(check.id, "Keep browser passwords in the keyring", "", steps)


def _keyring_step(scan) -> Step:
    """The keyring this desktop's browsers use: KDE Wallet on Plasma (Chromium uses it there, other apps reach it as the
    Secret Service), GNOME Keyring elsewhere."""
    if scan.context.desktop.is_kde:
        off = scan.kde.get("kwalletrc", "Wallet", "Enabled") == "false"
        # KDE Wallet Manager brings the settings page and the wallet's daemon with it
        cmds = [c for c in _program(scan, ("kwalletmanager6", "kwalletmanager5"),
                                    dict(debian="kwalletmanager", fedora="kwalletmanager5", arch="kwalletmanager",
                                         suse="kwalletmanager"), "KDE Wallet Manager") if " install " in c]
        if off:
            cmds.append(f"{scan.kde.tool('kwriteconfig')} --file kwalletrc --group Wallet --key Enabled true")
        return Step("Turn on KDE Wallet",
                    "No keyring answered on the session bus, so browsers fall back to the built-in key. Plasma's "
                    "keyring is KDE Wallet (KWallet): Chromium-based browsers use it on Plasma, and other apps reach it "
                    "as the Secret Service. " + ("It is turned off here: turn it on in System Settings → KDE Wallet "
                                                 "(Enable the KDE wallet subsystem), or with the command below, "
                                                 if off else "Check that System Settings → KDE Wallet has Enable the "
                                                 "KDE wallet subsystem ticked, ")
                    + "then log out and back in.", commands=cmds)
    if scan.host.runner.which("gnome-keyring-daemon"):
        return Step("Start GNOME Keyring",
                    "No keyring answered on the session bus, so browsers fall back to the built-in key. GNOME Keyring "
                    "is installed but isn't running in this session: GNOME, Cinnamon and MATE start it at login. Log "
                    "out and back in; on another desktop, start it at login with this command:",
                    commands=["gnome-keyring-daemon --start --components=secrets"])
    cmd = install(scan, debian="gnome-keyring", fedora="gnome-keyring", arch="gnome-keyring", suse="gnome-keyring")
    return Step("Install GNOME Keyring",
                "No keyring answered on the session bus, so browsers fall back to the built-in key. GNOME, Cinnamon "
                "and MATE use GNOME Keyring, which isn't installed: install it, then log out and back in.",
                commands=[cmd] if cmd else [])


def _resave_step(scan) -> Step:
    """What the check still counts once the flag is gone: values saved under the built-in key stay so (the browser
    reads them with it and doesn't encrypt them again), and keep the check failing until they are gone."""
    from ..auth import builtin_key_secrets
    found = builtin_key_secrets(scan)
    if not found:
        return Step("Re-save what is already stored", "Nothing is stored under the built-in key now.", done=True)
    pw, ck = sum(f[2] for f in found), sum(f[3] for f in found)
    where = ", ".join(sorted({f[0] for f in found}))
    counted = " and ".join(x for x in (f"{pw} saved password{'s' if pw != 1 else ''}" if pw else "",
                                       f"{ck} cookie{'s' if ck != 1 else ''}" if ck else "") if x)
    text = (f"The scan counts {counted} kept under the built-in key ({where}). The browser still reads them with it "
            "and doesn't encrypt them again once the keyring is used, so this check keeps reporting them until they "
            "are gone.")
    if pw:
        text += (" Passwords: export them from the browser's password manager, delete them there, import the file "
                 "again (now under the keyring's key), then delete the exported file.")
    if ck:
        text += (" Cookies are replaced only when their site sets them again, which for one that keeps you signed in "
                 "can take months. To be rid of them now, delete the browser's cookies: Ctrl+Shift+Delete in the "
                 "browser, All time, Cookies and other site data. That signs you out of sites.")
    return Step("Re-save what is already stored", text)


REMOTE_SERVICES = {"xrdp": ("xrdp.service", "xrdp-sesman.service"), "TeamViewer": ("teamviewerd.service",),
                   "AnyDesk": ("anydesk.service",), "RustDesk": ("rustdesk.service",)}


@guide("auth.remote_desktop")
def remote_desktop(check, scan, outcome):
    found = {e.label: e.value for e in outcome.evidence}
    steps = []
    if any(k.startswith("GNOME Remote Desktop") for k in found):
        acts = gset(scan, "org.gnome.desktop.remote-desktop.rdp", "enable", "false")
        acts += gset(scan, "org.gnome.desktop.remote-desktop.vnc", "enable", "false")
        steps.append(Step("Turn off GNOME desktop sharing", options=[option(check, "Turn off desktop sharing", acts)],
                          text="Remote Login (the system-wide RDP server of GNOME 46 and later) is a separate switch: "
                               "Settings → System → Remote Desktop → Remote Login."))
    for label, units in REMOTE_SERVICES.items():
        if any(k.startswith(label) for k in found):
            acts = service_off(scan, *units)
            effects = [f"Anyone connected through {label} is disconnected at once, you included if you are using "
                       f"this machine remotely now, and can't connect again until it is started."]
            blockers = [f"You are using this machine over {label} now: turning it off would end this session. Do it "
                        "from the machine itself."] if label == "xrdp" and "xrdp" in remote_session(scan) else []
            steps.append(Step(f"Turn off {label}", options=[option(check, f"Stop and disable {label}", acts,
                                                                   side_effects=effects, blockers=blockers)]
                              if acts else [], text="" if acts else f"Stop {label} and remove it from startup."))
    # a listening port is only worth naming when no process explains it
    named = [k for k in found if not re.match(r"^(RDP|VNC) port ", k)]
    other = [k for k in found if not k.startswith(("GNOME Remote Desktop", *REMOTE_SERVICES))
             and not (named and re.match(r"^(RDP|VNC) port ", k))]
    if other:
        steps.append(_other_remote(scan, other))
    steps.append(Step("If you do need it",
                      "Use a strong, unique password, and reach it over a VPN (e.g. WireGuard or Tailscale) rather "
                      "than exposing it to every network you join."))
    return Guide(check.id, "Turn off remote desktop servers you don't use",
                 "A screen-sharing server lets anyone with the password, or an exploit, see and control your session.",
                 steps)


# where a remote access program's systemd unit is found by name, when its process name doesn't say
REMOTE_UNITS = {"remoting_me2me_": "chrome-remote-desktop", "chrome-remote-d": "chrome-remote-desktop",
                "nxserver.bin": "nxserver", "nxnode.bin": "nxserver", "Xvnc": "vnc", "x0vncserver": "vnc",
                "vino-server": "vino", "teamviewerd": "teamviewer"}


def _other_remote(scan, other: list[str]) -> Step:
    """Remote access the app has no option for: where this desktop starts programs at login, and the commands that
    show each one (what runs, the unit that starts it, if any), stop it now, or name the program behind a port."""
    from ..auth import REMOTE_PROCESSES
    d, names, running = scan.context.desktop, set(scan.context.desktop.names), processes(scan.host)
    procs = [p for label in other for p, shown in REMOTE_PROCESSES.items() if shown == label and p in running]
    ports = [m.group(1) for k in other for m in [re.match(r"^(?:RDP|VNC) port (\d+)", k)] if m]
    if d.is_kde:
        text = ("Stop them if you don't use them, and keep them from starting again: System Settings → Autostart lists "
                "what starts at login" + ("; KDE's RDP server is turned off in System Settings → Remote Desktop"
                                          if "krdpserver" in procs else "")
                + ("; Desktop Sharing (krfb) is quit from its own window, and taken out of Autostart" if "krfb" in procs
                   else "") + ".")
        cmds = ["systemsettings kcm_autostart"] + (["systemsettings kcm_krdpserver"] if "krdpserver" in procs else [])
    elif names & {"x-cinnamon", "cinnamon"}:
        text = ("Stop them if you don't use them, and keep them from starting again: System Settings → Startup "
                "Applications lists what starts at login.")
        cmds = ["cinnamon-settings startup"]
    else:
        text = ("Stop them if you don't use them, and keep them from starting again: your desktop's list of startup "
                "applications, or the systemd unit below.")
        cmds = []
    text += " Programs a service starts come back when stopped by hand: disable the service, as root for a system one."
    for p in procs:
        unit = REMOTE_UNITS.get(p, p.removesuffix(".bin"))
        cmds += [f"pgrep -ax {p}     # what runs, with its command line",
                 f"systemctl list-unit-files '*{unit}*'; systemctl --user list-unit-files '*{unit}*'     # a service "
                 "that starts it",
                 f"pkill -x {p}     # stop it now"]
    cmds += [f"sudo ss -tlnp 'sport = :{port}'     # which program listens on port {port}" for port in ports]
    return Step("Other remote access", f"Found: {', '.join(other)}. {text}", commands=cmds)


@guide("auth.ssh_key_no_passphrase")
def ssh_keys(check, scan, outcome):
    shown = {e.label: e.value for e in outcome.evidence if isinstance(e.value, str) and "no passphrase" in e.value}
    usable = [k for k, v in shown.items() if "can't load it" not in v]
    dropped = [k for k, v in shown.items() if "can't load it" in v]
    cmds = []
    for k in usable:
        mode = mode_of(scan.host.home / ".ssh" / k)
        if mode is not None and mode & 0o077:
            # ssh-keygen refuses a key its group or others can read ("bad permissions"), -p included
            cmds.append(f"chmod 600 ~/.ssh/{k}     # ssh-keygen won't open it while others can read it (mode {mode:o})")
        cmds.append(f"ssh-keygen -p -f ~/.ssh/{k}")
    steps = []
    if usable:
        steps.append(Step("Set a passphrase on each key", "ssh-keygen asks for the new passphrase twice. The key "
                          "itself doesn't change, so servers that trust it keep doing so.", commands=cmds))
    if dropped:
        steps.append(Step("Replace the keys this ssh can't use",
                          f"This OpenSSH can't load {', '.join(dropped)}: a key type it no longer supports (DSA was "
                          "removed in OpenSSH 10), or a damaged file. It can't add a passphrase either, but the key "
                          "still works for anyone with an ssh that loads it. Make "
                          "a new key, put its .pub file on the servers that trusted the old one, then delete the old "
                          "key and its .pub file.",
                          commands=["ssh-keygen -t ed25519"] + [f"rm ~/.ssh/{k} ~/.ssh/{k}.pub     # once the new key "
                                                                f"works everywhere" for k in dropped]))
    steps.append(Step("Type it once per session",
                      "An agent remembers the unlocked key: GNOME Keyring and KDE's ssh-agent do it at login, or "
                      "run ssh-add. KeePassXC can hold keys too.", commands=["ssh-add"]))
    return Guide(check.id, "Add passphrases to SSH keys",
                 "A key without a passphrase works for anyone who copies the file.", steps)


@guide("auth.plaintext_credentials")
def plaintext_credentials(check, scan, outcome):
    from ..auth import CREDENTIAL_FILES
    host = scan.host
    chmods, found = [], []
    for rel, label, holds_secret in CREDENTIAL_FILES:
        p = host.home / rel
        text = read_text(host, p)
        if not text or not holds_secret(text):
            continue
        found.append(rel)
        mode = mode_of(p)
        if mode is not None and mode & 0o077:
            chmods.append(ChmodPath(p, 0o600, host.display(p)))
    steps = [Step("Make them readable only by you",
                  "At minimum, other users on this machine shouldn't be able to read them.",
                  options=[option(check, "Restrict to you (chmod 600)", chmods, recommended=True)] if chmods else [],
                  done=not chmods)]
    helpers = {
        ".git-credentials": ("Git", "Use a credential helper that stores in the keyring, then delete ~/.git-credentials.",
                             ["git credential-libsecret     # must not say it isn't a git command; else install it first",
                              "git config --global credential.helper libsecret",
                              "git fetch     # in a repository that needs the password: enter it once, and it is "
                              "kept in the keyring",
                              "rm ~/.git-credentials     # only once that worked: its token is then only in the keyring"]),
        ".docker/config.json": ("Docker", "Set \"credsStore\": \"secretservice\" (docker-credential-secretservice) "
                                "and log in again.", ["docker logout", "docker login"]),
        ".config/gh/hosts.yml": ("GitHub CLI", "gh stores its token in the keyring when one is available.",
                                 ["gh auth logout", "gh auth login"]),
        ".aws/credentials": ("AWS", "aws-vault keeps keys in the keyring.", []),
        ".npmrc": ("npm", "Keep the token in an environment variable instead of the file: in ~/.npmrc write "
                   "//registry.npmjs.org/:_authToken=${NPM_TOKEN} in place of the token, and npm reads NPM_TOKEN when "
                   "it runs. Set it when you need it, from the keyring:",
                   ["secret-tool store --label='npm token' service npm     # once: paste the token when asked",
                    'export NPM_TOKEN="$(secret-tool lookup service npm)"     # in the terminal, before npm needs it']),
    }
    for rel in found:
        if rel in helpers:
            name, text, cmds = helpers[rel]
            steps.append(Step(f"{name}: keep the secret in the keyring", text, commands=cmds))
    if any(e.label == ".env files with passwords or keys in your home" for e in outcome.evidence):
        steps.append(Step(".env files", "Project .env files often hold API keys. Keep them out of backups and "
                          "repositories, and use real secrets only where you need them."))
    return Guide(check.id, "Protect credential files", "", steps)


def _strip_secrets(text: str, fish: bool) -> str:
    from ..auth import SECRET_PATTERNS
    lines, out, skip = text.split("\n"), [], False
    for line in lines:
        if fish:
            if line.startswith("- cmd:"):
                skip = bool(SECRET_PATTERNS.search(line))
            if skip:
                continue
            out.append(line)
        elif not SECRET_PATTERNS.search(line):
            out.append(line)
    return "\n".join(out)


@guide("auth.shell_history_secrets")
def shell_history(check, scan, outcome):
    from ..auth import SECRET_PATTERNS, history_files
    host = scan.host
    actions = []
    for f in history_files(host):
        text = read_text(host, f) or ""
        n = sum(1 for line in text.splitlines() if SECRET_PATTERNS.search(line))
        if n:
            fish = f.name == "fish_history"
            actions.append(ClearInFile(f, lambda t, fish=fish: _strip_secrets(t, fish),
                                       f"Remove {n} line{'s' if n > 1 else ''} that look like secrets", host.display(f)))
    steps = [Step("Remove the lines that look like secrets",
                  "Only the matching lines are removed; the rest of your history stays. Change any password or "
                  "token that was in them too: it may have been copied elsewhere already.",
                  options=[option(check, "Remove them", actions, recommended=True, side_effects=[
                      "Terminals that are open keep their history in memory and may write it back when they close: "
                      "close them first, or run `history -c` in each."])] if actions else [], done=not actions)]
    bashrc = host.home / ".bashrc"
    text = read_text(host, bashrc) or ""
    settings = []
    if isfile(bashrc) and not re.search(r"^\s*(export\s+)?HISTCONTROL=\S*(ignorespace|ignoreboth)", text, re.M):
        settings.append(WriteFile(bashrc, lambda old: (old or "").rstrip("\n") + "\n\n# DA Privacy Kit: commands typed "
                                  "with a leading space aren't saved\nHISTCONTROL=ignoreboth\n",
                                  "Add HISTCONTROL=ignoreboth", host.display(bashrc)))
    from ..auth import zdotdir
    zshrc = (zdotdir(host) or host.home) / ".zshrc"
    if isfile(zshrc) and "HIST_IGNORE_SPACE" not in (read_text(host, zshrc) or "").upper():
        settings.append(WriteFile(zshrc, lambda old: (old or "").rstrip("\n") + "\n\n# DA Privacy Kit: commands typed "
                                  "with a leading space aren't saved\nsetopt HIST_IGNORE_SPACE\n",
                                  "Add setopt HIST_IGNORE_SPACE", host.display(zshrc)))
    steps.append(Step("Keep secrets out from now on",
                      "Then a command typed with a space in front of it isn't saved in history.",
                      options=[option(check, "Turn it on", settings, side_effects=["Applies to new terminals."])]
                      if settings else [], done=not settings))
    return Guide(check.id, "Clean secrets out of shell history", "", steps)


@guide("auth.sudo_nopasswd")
def sudo_nopasswd(check, scan, outcome):
    rules = evidence(outcome, "Passwordless rule")
    noauth = any("Defaults !authenticate" in r for r in rules)
    doas = any(r.startswith("doas: ") for r in rules)
    return Guide(check.id, "Ask for a password for sudo",
                 "A passwordless rule lets any program running as you become root without asking.", [
                     Step("Find the rules", "The rules found: " + "; ".join(rules) if rules else "",
                          commands=["sudo grep -rnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d/"]
                          + (["grep -n nopass /etc/doas.conf"] if doas else [])),
                     Step("Edit them with visudo",
                          "Remove NOPASSWD: from the rule (or delete the rule)"
                          + (", and delete the Defaults line with !authenticate, which lets every rule run without a "
                             "password" if noauth else "")
                          + ". visudo checks the syntax before saving. Keep a root shell open (sudo -i) in another "
                          "terminal while you do this, so a mistake can't lock you out.",
                          commands=["sudo visudo -f /etc/sudoers.d/FILE     # the file grep found"]
                          + (["sudoedit /etc/doas.conf                # for doas: remove nopass"] if doas else [])),
                 ])


@guide("auth.firefox_no_primary_password")
def primary_password(check, scan, outcome):
    exposed = evidence(outcome, value="no Primary Password")
    return Guide(check.id, "Protect saved passwords with a Primary Password",
                 "Without one, anyone who copies the profile folder can read every saved password.", [
                     Step("Set a Primary Password in each profile",
                          "Firefox: Settings → Privacy & Security → Passwords → Use a Primary Password. "
                          "Thunderbird: Settings → Privacy & Security → Passwords → Use a Primary Password. "
                          f"Profiles: {', '.join(exposed)}.",
                          side_effects=["The browser asks for it once per session, the first time a saved password "
                                        "is needed."]),
                 ])


@guide("auth.home_world_readable")
def home_readable(check, scan, outcome):
    home = scan.host.home
    effects = []
    if isdir(home / "public_html"):
        effects.append("~/public_html exists: a web server serving it from your home folder will stop working.")
    effects.append("Other users' access to files you've shared from your home folder stops.")
    from ..auth import acl_others, home_group_others
    shared = home_group_others(scan.host) is not None or bool(acl_others(home))
    opts = [] if shared else [
        option(check, "Only you, and members of your own group (750)", [ChmodPath(home, 0o750, "~")],
               detail="Most distributions give each user a group of their own, so this is usually just you.",
               side_effects=effects, recommended=True)]
    opts.append(option(check, "Only you (700)", [ChmodPath(home, 0o700, "~")], recommended=shared,
                       detail="Its group or an access list (ACL) lets other accounts in: 700 closes both (an ACL's "
                              "named entries count only within the group bits, which 700 sets to none)." if shared else "",
                       side_effects=effects))
    return Guide(check.id, "Close your home folder to other users", "", [Step("Choose the permissions", options=opts)])


@guide("auth.gpg_no_passphrase")
def gpg(check, scan, outcome):
    return Guide(check.id, "Add a passphrase to GnuPG keys", "A secret key without a passphrase works for anyone "
                 "who copies ~/.gnupg.", [
                     Step("Find the keys", commands=["gpg --list-secret-keys --keyid-format long"]),
                     Step("Set a passphrase on each", "pinentry asks for the new passphrase.",
                          commands=["gpg --change-passphrase KEYID     # the ID after sec, e.g. rsa4096/ABCD1234…"]),
                 ])


WTMP_DROPIN = "/etc/tmpfiles.d/00-daprivacyscanner-wtmp.conf"


@guide("auth.login_history")
def login_history(check, scan, outcome):
    from ..auth import ROTATED_RECORD, wtmp_rotation
    readable = [e.label for e in outcome.evidence if isinstance(e.value, str) and "anyone can read it" in e.value]
    files = {f: "0660" for f in ("/var/log/wtmp", "/var/log/lastlog") if f in readable}
    acts = [dropin("tmpfiles-wtmp", files, WTMP_DROPIN)] if files else []
    # logrotate makes a new wtmp each month with its rule's create mode: the rule is where the distribution put it
    rule = wtmp_rotation(scan.host)
    loose_rule = rule is not None and rule[1] is not None and bool(re.match(r"create\s+0?[0-7][0-7][4-7]\b", rule[1]))
    by_hand = None
    if "/var/log/wtmp" in files and loose_rule:
        if rule[0] in ("/etc/logrotate.d/wtmp", "/etc/logrotate.conf") and \
                re.fullmatch(r"create\s+0?664\s+root\s+utmp", rule[1]):
            acts.append(RootChange("edit_config", {"target": "logrotate-wtmp"},
                                   f"Set logrotate's mode for a new wtmp to 0660 (create 0660 root utmp in {rule[0]})"))
        else:
            by_hand = rule                              # a file or a line the helper doesn't edit
    steps = [Step("Make them readable by administrators only",
                  "A chmod alone doesn't last: at every boot systemd-tmpfiles sets the mode again, and logrotate "
                  "makes a new wtmp each month. A rule of the app's own fixes both, and is applied at once.",
                  options=[option(check, "Keep login records from other users", acts, recommended=True, side_effects=[
                      "`last` and `lastlog` then need sudo, except for administrators.",
                      f"systemd-tmpfiles notes at each boot that it skipped its own line for these files ({WTMP_DROPIN} "
                      "comes first).", "Reverting puts back the distribution's 0664 at once."])] if acts else [],
                  done=not acts)]
    if by_hand:
        steps.append(Step("Logrotate's rule for wtmp",
                          f"logrotate makes a new wtmp each month with the mode of its rule in {by_hand[0]} "
                          f"(\"{by_hand[1]}\"), which lets everyone read it. Change that line to create 0660 root utmp.",
                          commands=[f"sudoedit {by_hand[0]}"]))
    name = lambda f: f.rsplit("/", 1)[-1]                                      # noqa: E731
    rotated = [f for f in readable if f.startswith("/var/log/") and ROTATED_RECORD.fullmatch(name(f))]
    old_wtmp = [f for f in rotated if name(f).startswith("wtmp")]
    if old_wtmp:
        steps.append(Step("Last month's records",
                          "logrotate keeps the previous wtmp beside it with the mode it had, so it stays readable until "
                          "it is rotated away. Once the rule above is in place, the next ones are made readable by "
                          "administrators only.", commands=[f"sudo chmod o-r {f}" for f in old_wtmp]))
    others = [f for f in readable if f not in files and not name(f).startswith("btmp") and f not in rotated]
    if others:
        # wtmpdb and lastlog2 (Debian 13, openSUSE): databases the app's tmpfiles rule doesn't cover
        steps.append(Step("Login databases (wtmpdb, lastlog2)",
                          "These newer login records aren't covered by the rule above. This makes them readable by "
                          "administrators only; a package update may reset it, so scan again after updates.",
                          commands=[f"sudo chmod o-r {f}" for f in others]))
    btmp = [f for f in readable if name(f).startswith("btmp")]
    if btmp:
        steps.append(Step("Failed logins (btmp)", "It should never be readable by everyone:",
                          commands=[f"sudo chmod 600 {f}" for f in btmp]))
    return Guide(check.id, "Keep login history from other users", "", steps)


# ------------------------------------------------------------------ umask

UMASK_MARK = "# DA Privacy Kit: new files readable by you only (revert the fix in the app to remove)"
UMASK_CHOICES = (("027", "027: you can read and write; your own group can read"),
                 ("077", "077: you only"))


def _with_umask(line: str):
    """The file with the app's umask block at its end (replacing an earlier one of its own)."""
    def content(old: str | None) -> str:
        kept = re.sub(rf"\n*{re.escape(UMASK_MARK)}\n[^\n]*\n?", "\n", old or "").rstrip("\n")
        return (kept + "\n\n" if kept else "") + f"{UMASK_MARK}\n{line}\n"
    return content


def _login_shell(scan) -> str:
    from .._util import user_names
    login, _ = user_names(scan.host)
    for row in (scan.host.read_sys("/etc/passwd") or "").splitlines():
        f = row.split(":")
        if len(f) >= 7 and f[0] == login:
            return Path(f[6]).name
    return Path(scan.host.environ.get("SHELL", "bash")).name


@guide("auth.umask")
def umask(check, scan, outcome):
    host, h = scan.host, scan.host.home
    value = Input.read(scan.params, "umask", "choice", "027", choices=tuple(c for c, _ in UMASK_CHOICES))
    pick = Input("umask", "New files are readable by", "choice", value, "027", choices=list(UMASK_CHOICES),
                 help="Other accounts can't read your new files either way. 027 keeps files readable by your own "
                      "group, which on most systems has only you in it; 077 is stricter and can trouble programs "
                      "that share files through a group.")
    files = [h / ".profile"]                      # sh, and the X11 session script (lightdm, SDDM and GDM's Xsession)
    bash_login = next((h / f for f in (".bash_profile", ".bash_login") if isfile(h / f)), None)
    if bash_login:                                # bash reads it instead of ~/.profile
        files.append(bash_login)
    shell = _login_shell(scan)
    if shell == "zsh":
        files.append(h / ".zprofile")
    elif shell == "fish":
        files.append(scan.paths.config_home / "fish" / "config.fish")
    line = f"umask {value}"
    shells = [WriteFile(f, _with_umask(line), f"Set {line} at login", host.display(f)) for f in files
              if f"{UMASK_MARK}\n{line}\n" not in (read_text(host, f) or "")]
    unit = f"/etc/systemd/system/user@{host.uid}.service.d/60-daprivacyscanner-umask.conf"
    manager_done = f"UMask=0{value}" in (read_text(host, host.sys_path(unit)) or "")
    caveat = ("Commands you run with sudo get this umask too: a file you create with sudo (say, a config file copied "
              "into /etc) may then be unreadable by the service that needs it; check with ls -l and fix with chmod.")
    manager = f"user@{host.uid}.service"
    steps = [
        Step("Login shells, and Cinnamon, Xfce and MATE on X11",
             "Login shells read these files (the text console, SSH), and so does the script that starts Cinnamon, Xfce "
             "or MATE on X11: what you start from those gets the new umask, terminal windows included. A new login "
             "shell has it at once; the desktop from your next login.", inputs=[pick],
             options=[option(check, f"Set umask {value} in your login files", shells, recommended=True,
                             side_effects=[caveat])] if shells else [], done=not shells),
        Step("GNOME and KDE Plasma, on Wayland and X11",
             "GNOME and Plasma start their shell, and the apps and terminals you open from it, through your systemd "
             "user manager, on X11 as on Wayland, and it doesn't read the files above. This gives it the same umask "
             f"(UMask= in a drop-in for {manager}, your account only). ~/.config/environment.d can't do this: it sets "
             "environment variables, and the umask isn't one. It takes effect when your user manager starts again: "
             "after a restart of the computer, or once you have logged out of every session (SSH included) and "
             "nothing of yours is left running. A logout alone often isn't enough: the user manager stays while any "
             "program of yours still runs. To see the umask it runs with now:",
             commands=[f"grep Umask /proc/$(systemctl show -p MainPID --value {manager})/status"],
             options=[] if manager_done else [option(check, f"Set umask {value} for your user manager",
                                                         [dropin("user-umask", {"UMask": "0" + value}, unit)],
                                                         recommended=True, side_effects=[caveat])],
             done=manager_done),
    ]
    return Guide(check.id, "Make new files private by default",
                 "The umask decides who can read the files you create. Right now other accounts on this computer "
                 "can read new files wherever they can reach them (shared folders, /tmp, removable drives).", steps)


# ------------------------------------------------------------------ SSH settings and authorized keys

SSH_OVERRIDE = ("# Added by DA Privacy Kit: for every server not set otherwise above. It overrides\n"
                "# /etc/ssh/ssh_config; revert the fix in the app's History to remove it.\n")


def _ssh_edit(changes: dict[str, str]):
    """A file of the user's SSH configuration with the first line setting each option for every
    server changed to the safe value, its indentation kept. Found again when applied: a file
    changed since so that the line is gone stops the fix."""
    from ...fix import FixError
    from ..auth import SSH_NAMES, _ssh_scope

    def content(old: str | None) -> str:
        lines = (old or "").splitlines(keepends=True)
        todo, every = dict(changes), True
        for i, line in enumerate(lines):
            words = line.strip().replace("=", " ", 1).split(None, 1)
            if not words or words[0].startswith("#"):
                continue
            key, arg = words[0].lower(), (words[1].strip() if len(words) > 1 else "")
            if key in ("host", "match"):
                every = _ssh_scope(key, arg)
            elif every and key in todo:
                indent = line[:len(line) - len(line.lstrip())]
                lines[i] = f"{indent}{SSH_NAMES[key]} {todo.pop(key)}\n"
        if todo:
            raise FixError("The SSH configuration was changed since the plan was made; open the guide again.")
        return "".join(lines)
    return content


def _ssh_append(changes: dict[str, str]):
    from ..auth import SSH_NAMES
    block = SSH_OVERRIDE + "Host *\n" + "".join(f"    {SSH_NAMES[k]} {v}\n" for k, v in changes.items())

    def content(old: str | None) -> str:
        kept = (old or "").rstrip("\n")
        return (kept + "\n\n" if kept else "") + block
    return content


SSH_EFFECTS = {
    "forwardagent": "Servers no longer get your agent. To use it on one server deliberately, connect with ssh -A; "
                    "to reach servers behind another, use ProxyJump (ssh -J), which never hands the agent over.",
    "stricthostkeychecking": "ssh still remembers new servers by itself (accept-new), but refuses to connect when a "
                             "known server's key has changed. If one was reinstalled, remove its old key with "
                             "ssh-keygen -R NAME and connect again.",
    "userknownhostsfile": "Servers are remembered in ~/.ssh/known_hosts again; the first connection to each one adds it.",
}


@guide("auth.ssh_client_settings")
def ssh_client_settings(check, scan, outcome):
    from ...fix import MakeDir
    from ..auth import SSH_NAMES, SSH_SAFE, added_keys_limit, ssh_agent, ssh_config_lines, ssh_weak_settings
    host = scan.host
    weak = ssh_weak_settings(ssh_config_lines(host))
    by_file: dict = {}
    system: dict[str, str] = {}
    for key, ln in weak.items():
        if ln.user:
            by_file.setdefault((ln.path, ln.display), {})[key] = SSH_SAFE[key]
        else:
            system[key] = ln.display
    acts = [WriteFile(path, _ssh_edit(ch), "Change " + ", ".join(f"{SSH_NAMES[k]} to {v}" for k, v in ch.items()),
                      display) for (path, display), ch in by_file.items()]
    if system:
        ssh_dir, cfg = host.home / ".ssh", host.home / ".ssh" / "config"
        if not isdir(ssh_dir):
            acts.append(MakeDir(ssh_dir, "~/.ssh", 0o700))
        acts.append(WriteFile(cfg, _ssh_append({k: SSH_SAFE[k] for k in system}),
                              "Add a Host * block with " + ", ".join(f"{SSH_NAMES[k]} {SSH_SAFE[k]}" for k in system),
                              "~/.ssh/config", mode=0o600))
    steps = []
    if weak:
        steps.append(Step("Change them for your account",
                          "Settings you made for particular servers (Host blocks above) stay as they are and still "
                          "win for those servers.",
                          options=[option(check, "Change them for every server", acts, recommended=True,
                                          side_effects=[SSH_EFFECTS[k] for k in weak])]))
    if system:
        files = sorted(set(system.values()))
        steps.append(Step("Or for every account on this computer",
                          f"The setting{'s come' if len(system) > 1 else ' comes'} from {', '.join(files)}. Change "
                          + ", ".join(f"{SSH_NAMES[k]} to {SSH_SAFE[k]}" for k in system)
                          + " there, or delete the line to get ssh's default.",
                          commands=[f"sudoedit {f}" for f in files]))
    agent = ssh_agent(scan)
    # AddKeysToAgent with a time already makes the keys ssh adds leave the agent: the advice below is in place
    limited = agent.kind == "ssh-agent" and added_keys_limit(ssh_config_lines(host)) is not None
    if agent.kind and agent.keys and not agent.lifetime and not limited:
        if agent.kind == "ssh-agent":
            text = ("ssh-agent keeps keys until you log out unless they are added with a time limit. ssh-add -t sets one "
                    "for the keys you add by hand. For keys ssh adds as you connect, add the line AddKeysToAgent 1h to "
                    "~/.ssh/config, under Host * at the end: they then leave the agent after an hour.")
            cmds = ["ssh-add -D     # remove every key from the agent now", "ssh-add -t 1h     # add your keys for one hour"]
        else:
            text = (f"{agent.kind} unlocks a key the first time you use it and keeps it unlocked until you log out; it "
                    "has no time limit. Remove them when you are done, or hold your keys in KeePassXC (its SSH agent "
                    "integration removes them after a time you choose, or when the database locks).")
            cmds = ["ssh-add -D     # remove every key from the agent now"]
        steps.append(Step("Let keys leave the agent", text, commands=cmds))
    if not steps:
        steps.append(Step("Your SSH settings", "Nothing in them weakens every connection now.", done=True))
    return Guide(check.id, "Make SSH check servers and keep your keys to itself",
                 "ssh reads ~/.ssh/config first and then /etc/ssh/ssh_config, and the first value it finds for a "
                 "setting wins. The app changes only your own file.", steps)


@guide("auth.ssh_authorized_keys")
def ssh_authorized_keys(check, scan, outcome):
    from ...fix import FixError
    from ..auth import authorized_keys, ssh_server_reachable
    from . import family
    host = scan.host
    keys = authorized_keys(host)

    def without(line: str):
        def content(old: str | None) -> str:
            lines = (old or "").splitlines(keepends=True)
            kept = [ln for ln in lines if ln.rstrip("\n") != line]
            if len(kept) == len(lines):
                raise FixError("That key is no longer in the file.")
            return "".join(kept)
        return content

    opts = []
    for i, k in enumerate(keys, 1):
        shown = host.display(k.path)
        extra = ", limited to some addresses or a command" if k.restricted else ""
        extra += ", a certificate authority" if k.authority else ""
        opts.append(option(check, f"Remove key {i}: {k.describe()}{' (weak)' if k.weak else ''}, {k.fingerprint}{extra}",
                           [WriteFile(k.path, without(k.line), f"Remove key {i} ({k.describe()}, {k.fingerprint})", shown,
                                      lines=[f"- the line of key {i} ({k.describe()}, {k.fingerprint}); not repeated "
                                             "here, since its comment often holds an email address"])],
                           side_effects=["Whoever holds this key can no longer log in as you over SSH. If it is your "
                                         "own key on another computer, make sure you have another way in first."],
                           recommended=k.weak))
    steps = [Step("Remove the keys you don't recognise or no longer use",
                  "To find out which key is which, run this on each computer you log in from and compare the "
                  "fingerprint with the list:", options=opts, commands=["ssh-keygen -lf ~/.ssh/id_ed25519.pub     # "
                                                                         "or the .pub file of the key it uses"])]
    if any(k.weak for k in keys):
        steps.append(Step("Replace weak keys", "On the computer that uses a weak key, make a new key and add it here; "
                          "then remove the old one above.",
                          commands=["ssh-keygen -t ed25519", "ssh-copy-id -i ~/.ssh/id_ed25519.pub YOU@THIS-COMPUTER"]))
    if ssh_server_reachable(scan):
        unit = "ssh" if family(scan) == "debian" else "sshd"
        steps.append(Step("Turn the SSH server off if you don't log in remotely",
                          "With no server listening, none of these keys can be used. See net.exposed_services for "
                          "the other services listening.",
                          commands=[f"sudo systemctl disable --now {unit}.service"
                                    + (" ssh.socket" if unit == "ssh" else "")]))
    return Guide(check.id, "Check the keys that can log in as you",
                 "Each key in ~/.ssh/authorized_keys lets whoever holds its private half log in as you, without "
                 "your password. Keep the ones you know; you can also limit a key to your own network by putting "
                 'from="192.168.1.0/24" in front of it.', steps)


# ------------------------------------------------------------------ GnuPG keys and the passphrase cache

def _gpg_ttl(values: dict[str, int]):
    """gpg-agent.conf with these cache options set: their lines changed in place (the last one
    for an option is the one gpg-agent uses), missing ones added at the end."""
    def content(old: str | None) -> str:
        lines = (old or "").splitlines(keepends=True)
        todo = dict(values)
        for i in range(len(lines) - 1, -1, -1):
            w = lines[i].split("#", 1)[0].split()
            if w and w[0] in todo:
                lines[i] = f"{w[0]} {todo.pop(w[0])}\n"
        text = "".join(lines)
        if todo:
            text = (text if not text or text.endswith("\n") else text + "\n") + "".join(f"{k} {v}\n" for k, v in todo.items())
        return text
    return content


@guide("auth.gpg_keys")
def gpg_keys(check, scan, outcome):
    import time
    from ...fix import Command
    from ..auth import GPG_LIST, GPG_LONG_TTL, gpg_agent_conf, gpg_cache, gpg_secret_keys
    host = scan.host
    home = Path(host.environ.get("GNUPGHOME") or host.home / ".gnupg")
    grips = {p.stem.upper() for p in children(home / "private-keys-v1.d") if p.suffix == ".key"}
    r = host.run(*GPG_LIST, timeout=30)
    keys = gpg_secret_keys(r.stdout, grips, time.time()) if r.ok and grips else []
    steps = []
    weak = [k for k in keys if k.weak_parts and not k.expired]
    if weak:
        # future-default: an Ed25519 signing key with a Curve25519 encryption subkey. Naming an algorithm
        # instead makes the primary key only (gpg(1)), which nobody could encrypt to.
        cmds = ["gpg --quick-gen-key 'YOUR NAME <YOU@EXAMPLE.COM>' future-default default 2y     # the new key"]
        for k in weak:
            short = k.fingerprint[-8:]
            cmds += [f"gpg --output revoke-{short}.asc --gen-revoke {k.fingerprint}     # once you have moved to the new key",
                     f"gpg --import revoke-{short}.asc"]
        steps.append(Step("Replace weak keys",
                          "Make a new key, give it to the people and services that use the old one (and sign it with "
                          "the old one, so they can tell it is yours), then revoke the old key. A weak subkey only "
                          "needs a new subkey: gpg --quick-add-key FINGERPRINT cv25519 encr 2y, then revoke the old "
                          "subkey in gpg --edit-key.", commands=cmds))
    expired = [k for k in keys if k.expired]
    if expired:
        cmds = []
        for k in expired:
            cmds += [f"gpg --quick-set-expire {k.fingerprint} 2y", f"gpg --quick-set-expire {k.fingerprint} 2y '*'"]
        steps.append(Step("Renew or remove expired keys",
                          "To keep using a key, give it (and its subkeys) a new expiry date and publish it again. If you "
                          "no longer need it, delete its secret part: keep a backup first if old mail was encrypted "
                          "to it, since that mail can't be read without it.",
                          commands=cmds + [f"gpg --delete-secret-keys {k.fingerprint}     # or, to remove it"
                                           for k in expired]))
    conf_path = home / "gpg-agent.conf"
    after_use, longest = gpg_cache(gpg_agent_conf(read_text(host, conf_path) or ""))
    long_ttl = after_use > GPG_LONG_TTL["default-cache-ttl"] or longest > GPG_LONG_TTL["max-cache-ttl"]
    if long_ttl:
        reload = Command(["gpgconf", "--reload", "gpg-agent"], "gpg-agent reads its settings again", check_ok=False,
                         after=True)
        effects = ["You type the passphrase more often.", "Reverting puts the file back; gpg-agent reads it at the next "
                   "login, or after gpgconf --reload gpg-agent."]
        opts = [option(check, label, [WriteFile(conf_path, _gpg_ttl(vals), f"Set {', '.join(f'{k} {v}' for k, v in vals.items())}",
                                                host.display(conf_path)), reload],
                       side_effects=effects, recommended=rec)
                for label, vals, rec in (("GnuPG's defaults: 10 minutes after last use, at most 2 hours",
                                          {"default-cache-ttl": 600, "max-cache-ttl": 7200}, True),
                                         ("1 hour after last use, at most 8 hours",
                                          {"default-cache-ttl": 3600, "max-cache-ttl": 28800}, False))]
        steps.append(Step("Remember the passphrase for less time",
                          "default-cache-ttl is how long gpg-agent keeps the passphrase after the key was last used; "
                          "max-cache-ttl is the longest it keeps it at all. If pinentry offers to save the passphrase "
                          "in your keyring, leave that unticked: it is then kept for as long as the keyring is open.",
                          options=opts))
    if not steps:
        steps.append(Step("Your GnuPG keys", "Nothing to change now.", done=True))
    return Guide(check.id, "Strengthen your GnuPG keys", "Commands that change your keys are yours to run: they "
                 "ask for the passphrase, and their results have to be published to the people who use the keys.",
                 steps)
