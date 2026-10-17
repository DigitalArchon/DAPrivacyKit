"""Authentication checks and fixes corrected after the review of 2026-10-17."""

from daprivacyscanner.checks import load_all
from daprivacyscanner.fix import KConfigSet
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan
from fakes import FakeGSettings, FakeKwriteconfig
from test_checks_auth import BUS, _wallets, chrome_profile
from test_guides import apply, build, options, revert

KDE = dict(desktop=("kde",), plasma_major=6)
RELOAD = ("qdbus6", "org.kde.screensaver", "/ScreenSaver", "org.kde.screensaver.configure")


def _plan(cat, host, check_id, **kw):
    check = load_all()[check_id](cat[check_id])
    scan = make_scan(host, **kw)
    outcome = check.detect(scan)
    return check, outcome, check.plan_fix(scan, outcome)


# ------------------------------------------------------------------ screen lock on KDE Plasma

def _kde_host(tmp_path, **kw):
    host = make_host(tmp_path, **kw)
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    seen = []                                   # kscreenlockerrc as the screen locker reads it at each reload

    def qdbus(argv):
        rc = host.home / ".config/kscreenlockerrc"
        seen.append(rc.read_text() if rc.exists() else "")
        return CommandResult(argv, 0, "")
    host.runner.handlers["qdbus6"] = qdbus
    return host, seen


def test_kde_screen_locker_reads_the_change_now_and_on_revert(cat, tmp_path):
    """kscreenlocker reads kscreenlockerrc at login or on its configure call: without the call the old settings stay
    until the next login, after the fix and after reverting it."""
    host, seen = _kde_host(tmp_path, home_files={".config/kscreenlockerrc": "[Daemon]\nAutolock=false\nTimeout=30\n"})
    check, outcome, plan = _plan(cat, host, "auth.screen_lock", **KDE)
    assert outcome.status is Status.FAIL
    assert all(isinstance(a, KConfigSet) and a.then == list(RELOAD) for a in plan.actions)
    assert all(c[-1].startswith("qdbus6 org.kde.screensaver /ScreenSaver") for c in plan.step_commands())
    assert "at once" in " ".join(plan.side_effects) and "turns off" not in " ".join(plan.side_effects)
    log, res = apply(host, plan)
    assert len(seen) == 2 and "Timeout=5" in seen[-1] and "Autolock=true" in seen[-1]
    record = log.get(res.entry_id)["records"][0]
    assert KConfigSet.ran(record)[-1] == "qdbus6 org.kde.screensaver /ScreenSaver org.kde.screensaver.configure"
    assert KConfigSet.undo_hint(record).endswith("; qdbus6 org.kde.screensaver /ScreenSaver org.kde.screensaver.configure")
    assert check.detect(make_scan(host, **KDE)).status is Status.PASS
    revert(host, log, res)
    # the last reload comes after the last setting was put back: the locker reads the old settings, both of them
    assert len(seen) == 4 and "Autolock=false" in seen[-1] and "Timeout=30" in seen[-1]


def test_kde_screen_lock_without_qdbus_says_it_applies_at_next_login(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/kscreenlockerrc": "[Daemon]\nAutolock=false\n"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    _, _, plan = _plan(cat, host, "auth.screen_lock", **KDE)
    assert plan.actions and all(a.then is None for a in plan.actions)
    assert "next login" in " ".join(plan.side_effects)


def test_kde_screen_lock_set_off_in_etc_xdg(cat, tmp_path):
    """A distribution's /etc/xdg/kscreenlockerrc with Timeout=0 (never) or Autolock=false gave an empty plan, whose
    reason was a side effect that isn't even true on KDE ("the screen turns off after 5 minutes")."""
    for rc in ("[Daemon]\nTimeout=0\n", "[Daemon]\nAutolock=false\n", "[Daemon]\nTimeout=0\nAutolock=false\n"):
        host, seen = _kde_host(tmp_path / str(len(rc)), files={"/etc/xdg/kscreenlockerrc": rc})
        check, outcome, plan = _plan(cat, host, "auth.screen_lock", **KDE)
        assert outcome.status is Status.FAIL and not plan.empty, rc
        log, res = apply(host, plan)
        assert check.detect(make_scan(host, **KDE)).status is Status.PASS, rc
        revert(host, log, res)
        assert check.detect(make_scan(host, **KDE)).status is Status.FAIL
    # a timeout of 0 in the user's own file too
    host, _ = _kde_host(tmp_path / "own", home_files={".config/kscreenlockerrc": "[Daemon]\nTimeout=0\n"})
    _, _, plan = _plan(cat, host, "auth.screen_lock", **KDE)
    assert [a.key for a in plan.actions] == ["Timeout"]


def test_screen_lock_side_effects_are_the_desktops_own(cat, tmp_path):
    gs = FakeGSettings({("org.cinnamon.desktop.screensaver", "lock-enabled"): "true",
                        ("org.cinnamon.desktop.session", "idle-delay"): "uint32 0",
                        ("org.cinnamon.desktop.screensaver", "lock-delay"): "uint32 0",
                        ("org.cinnamon.settings-daemon.plugins.power", "lock-on-suspend"): "true"})
    host = make_host(tmp_path)
    host.runner.handlers["gsettings"] = gs
    _, _, plan = _plan(cat, host, "auth.screen_lock", desktop=("x-cinnamon",))
    assert plan.side_effects == ["The screensaver also starts after 5 minutes without input."]
    # nothing about the idle time changes: nothing said about it
    gs = FakeGSettings({("org.gnome.desktop.screensaver", "lock-enabled"): "false",
                        ("org.gnome.desktop.session", "idle-delay"): "uint32 300",
                        ("org.gnome.desktop.screensaver", "lock-delay"): "uint32 0"})
    host = make_host(tmp_path / "g")
    host.runner.handlers["gsettings"] = gs
    _, _, plan = _plan(cat, host, "auth.screen_lock")
    assert len(plan.actions) == 1 and plan.side_effects == []


def test_an_empty_screen_lock_plan_names_the_settings_page(cat, tmp_path):
    """The check fails while the keys the fix changes already hold its values (a value it can't see, a lock): the
    reason given is where to set it, not a side effect."""
    from daprivacyscanner.checks.fixes import FIXES
    from daprivacyscanner.model import Outcome
    gs = FakeGSettings({("org.cinnamon.desktop.screensaver", "lock-enabled"): "true",
                        ("org.cinnamon.desktop.session", "idle-delay"): "uint32 300",
                        ("org.cinnamon.desktop.screensaver", "lock-delay"): "uint32 0",
                        ("org.cinnamon.settings-daemon.plugins.power", "lock-on-suspend"): "true"})
    host = make_host(tmp_path)
    host.runner.handlers["gsettings"] = gs
    check = load_all()["auth.screen_lock"](cat["auth.screen_lock"])
    plan = FIXES["auth.screen_lock"].plan(check, make_scan(host, desktop=("x-cinnamon",)), Outcome(Status.FAIL, "x"))
    assert plan.empty and plan.side_effects == [
        "The settings Fix… changes already have its values here. Set the screen lock in System Settings → Screensaver: "
        "lock after 5 minutes idle, and on suspend."]


def test_mate_lock_delay_is_changed_too(cat, tmp_path):
    """MATE isn't supported, but the fix left a lock delay of minutes, which the check warns about, as it was."""
    gs = FakeGSettings({("org.mate.screensaver", "lock-enabled"): "true", ("org.mate.screensaver", "idle-delay"): "5",
                        ("org.mate.screensaver", "lock-delay"): "10"})
    host = make_host(tmp_path)
    host.runner.handlers["gsettings"] = gs
    check, outcome, plan = _plan(cat, host, "auth.screen_lock", desktop=("mate",))
    assert outcome.status is Status.WARN
    log, res = apply(host, plan)
    assert gs.values[("org.mate.screensaver", "lock-delay")] == "0"
    assert check.detect(make_scan(host, desktop=("mate",))).status is Status.PASS
    revert(host, log, res)
    assert gs.values[("org.mate.screensaver", "lock-delay")] == "10"


def test_no_desktop_session_is_said_in_words(cat, tmp_path):
    """A scan from a terminal or over SSH: "Screen lock settings for unknown aren't supported yet" before."""
    host = make_host(tmp_path)
    scan = make_scan(host, desktop=())
    texts = [detect(cat, i, scan).summary for i in ("auth.screen_lock", "auth.lockscreen_notifications",
                                                     "desk.session_restore")]
    assert all("without a desktop session" in t and "unknown" not in t for t in texts), texts
    assert scan.context.desktop.label == "no desktop session"
    from daprivacyscanner.checks.fixes import FIXES
    why = FIXES["auth.screen_lock"].can(scan)
    assert not why and "this scan ran without a desktop session" in why
    assert "this is Sway" in FIXES["auth.screen_lock"].can(make_scan(host, desktop=("sway",)))


# ------------------------------------------------------------------ Chromium's basic store

NO_BUS = {"busctl --user list": "NAME PID PROCESS\n"}


def test_basic_store_guide_makes_the_check_pass(cat, tmp_path):
    """The guide's copy of a system menu entry, without the flag, hides the system's: the check read the hidden one and
    kept failing while the step showed done."""
    host = make_host(tmp_path, commands=BUS, files={"/usr/share/applications/google-chrome.desktop":
                                                    "[Desktop Entry]\nExec=/usr/bin/google-chrome-stable --password-store=basic %U\n"})
    chrome_profile(host.home)
    g = build(cat, host, "auth.chromium_basic_store")
    log, res = apply(host, options(g)["Remove the flag"])
    assert detect(cat, "auth.chromium_basic_store", make_scan(host)).status is Status.PASS
    revert(host, log, res)
    assert detect(cat, "auth.chromium_basic_store", make_scan(host)).status is Status.FAIL


def test_basic_store_reads_the_entry_the_menu_uses(cat, tmp_path):
    """The first file of a name wins, in the menu's order: the user's, Flatpak's exports, /usr/local/share, /usr/share."""
    from daprivacyscanner.checks.auth import basic_store_flags
    flagged = "[Desktop Entry]\nExec=app --password-store=basic\n"
    host = make_host(tmp_path, commands=BUS,
                     home_files={".local/share/flatpak/exports/share/applications/com.brave.Browser.desktop":
                                 "[Desktop Entry]\nExec=brave\n"},
                     files={"/var/lib/flatpak/exports/share/applications/com.brave.Browser.desktop": flagged,
                            "/usr/local/share/applications/code.desktop": flagged,
                            "/usr/share/applications/code.desktop": "[Desktop Entry]\nExec=code\n"})
    found = [(f.relative_to(host.root).as_posix(), own) for f, own in basic_store_flags(make_scan(host))]
    assert found == [("usr/local/share/applications/code.desktop", False)]


def test_basic_store_keyring_step_is_the_desktops_own(cat, tmp_path):
    host = make_host(tmp_path, commands=NO_BUS, files={"/etc/os-release": "ID=fedora\n"},
                     home_files={".config/kwalletrc": "[Wallet]\nEnabled=false\n"})
    chrome_profile(host.home)
    g = build(cat, host, "auth.chromium_basic_store", **KDE)
    step = next(s for s in g.steps if "KDE Wallet" in s.title)
    assert "gnome-keyring" not in " ".join(step.commands) + step.text
    assert step.commands == ["sudo dnf install kwalletmanager5     # KDE Wallet Manager isn't installed",
                             "kwriteconfig6 --file kwalletrc --group Wallet --key Enabled true"]
    g = build(cat, host, "auth.chromium_basic_store", desktop=("x-cinnamon",))
    assert next(s for s in g.steps if "Keyring" in s.title).commands == ["sudo dnf install gnome-keyring"]
    host.runner.installed.add("gnome-keyring-daemon")
    g = build(cat, host, "auth.chromium_basic_store", desktop=("x-cinnamon",))
    assert next(s for s in g.steps if "Keyring" in s.title).title == "Start GNOME Keyring"


def test_basic_store_resave_step_counts_what_keeps_it_failing(cat, tmp_path):
    """Values saved under the built-in key stay so once the keyring is used, cookies until their site sets them
    again: the step says what the check counts, and how to be rid of each."""
    host = make_host(tmp_path, commands=BUS)
    chrome_profile(host.home, cookies_prefix=b"v10", login_prefix=b"v11")
    g = build(cat, host, "auth.chromium_basic_store")
    step = next(s for s in g.steps if s.title == "Re-save what is already stored")
    assert step.text.startswith("The scan counts 2 cookies kept under the built-in key (Google Chrome).")
    assert "Ctrl+Shift+Delete" in step.text and "Passwords:" not in step.text and not step.done


# ------------------------------------------------------------------ blank keyrings

def _blank_ring(host, file="Default_keyring.keyring", name="Default keyring"):
    d = host.home / ".local/share/keyrings"
    d.mkdir(parents=True, exist_ok=True)
    (d / file).write_text(f"[keyring]\ndisplay-name={name}\nctime=0\nmtime=0\nlock-on-idle=false\nlock-after=false\n")


def test_keyring_guide_follows_the_store_found_not_the_desktop(cat, tmp_path):
    """Plasma with a blank GNOME keyring was sent to KDE Wallet Manager; Cinnamon with both blank only to Seahorse."""
    host = make_host(tmp_path, files={"/etc/os-release": "ID=fedora\n"})
    _blank_ring(host)
    g = build(cat, host, "auth.keyring_blank", **KDE)
    assert [s.title for s in g.steps] == ["Set a password for the GNOME keyring"]
    assert "“Default keyring”" in g.steps[0].text and "Default_keyring.keyring" not in g.steps[0].text
    assert g.steps[0].commands == ["sudo dnf install seahorse     # Passwords and Keys isn't installed", "seahorse"]
    assert "only the Login keyring" in g.steps[0].text and not g.steps[0].side_effects
    _wallets(host, ("blank", "kdewallet"))
    host.runner.installed.update({"seahorse", "kwalletmanager5"})
    g = build(cat, host, "auth.keyring_blank", desktop=("x-cinnamon",))
    assert [s.title for s in g.steps] == ["Set a password for the GNOME keyring", "Set a password for the KDE wallet"]
    assert g.steps[0].commands == ["seahorse"] and g.steps[1].commands == ["kwalletmanager5"]
    assert "“kdewallet”" in g.steps[1].text and g.steps[1].side_effects


def test_keyring_evidence_names_the_keyring(cat, tmp_path):
    from daprivacyscanner.checks.auth import KEYRING_MAGIC, keyring_name
    host = make_host(tmp_path)
    _blank_ring(host, "login.keyring", "Login")
    o = detect(cat, "auth.keyring_blank", make_scan(host))
    assert ev(o) == {"Login (login.keyring)": "stored unencrypted (blank password)"}
    g = build(cat, host, "auth.keyring_blank")
    assert "“Login”" in g.steps[0].text and "unlocks when you log in" in g.steps[0].text
    # an encrypted keyring's name follows its header: version, cipher and hash bytes, then a length and the name
    head = KEYRING_MAGIC + bytes(4) + len("Login").to_bytes(4, "big") + b"Login" + b"\x00" * 40
    assert keyring_name(head) == "Login" and keyring_name(KEYRING_MAGIC + b"\x00\x01binary") is None


# ------------------------------------------------------------------ SSH keys without a passphrase

def _keys_host(tmp_path, keys: dict, results: dict, modes: dict | None = None):
    import os
    host = make_host(tmp_path, home_files={f".ssh/{k}": text for k, text in keys.items()})
    for k in keys:
        os.chmod(host.home / ".ssh" / k, (modes or {}).get(k, 0o600))
        host.runner.outputs[("ssh-keygen", "-y", "-P", "", "-f", str(host.home / ".ssh" / k))] = results[k]
    host.runner.installed.add("ssh-keygen")
    return host


def test_a_key_this_ssh_cant_load_is_never_called_protected(cat, tmp_path):
    """Any ssh-keygen error counted as "protected by a passphrase": an unencrypted id_dsa on OpenSSH 10, which dropped
    DSA, passed. Only "incorrect passphrase" means it asks for one; otherwise the key file itself says, or it is
    couldn't check."""
    from test_checks_auth import openssh_key
    gone = CommandResult((), 255, "", 'Load key "/home/alice/.ssh/id_dsa": invalid format\n')
    host = _keys_host(tmp_path, {"id_dsa": "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQ\n-----END DSA PRIVATE KEY-----\n",
                                 "work": openssh_key(b"aes256-ctr"), "odd": "-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64 at all\n"},
                      {"id_dsa": gone, "work": CommandResult((), 255, "", 'Load key "x": incorrect passphrase supplied '
                                                             "to decrypt private key\n"), "odd": gone})
    o = detect(cat, "auth.ssh_key_no_passphrase", make_scan(host))
    assert o.status is Status.FAIL and o.summary.endswith("id_dsa.")
    assert ev(o)["id_dsa"] == "no passphrase; this ssh-keygen can't load it (invalid format)"
    assert ev(o)["work"] == "protected by a passphrase" and ev(o)["odd"].startswith("couldn't check")
    assert "/home/alice" not in repr(o.evidence)
    g = build(cat, host, "auth.ssh_key_no_passphrase")
    assert [s.title for s in g.steps] == ["Replace the keys this ssh can't use", "Type it once per session"]
    # unknown alone is unknown, not a pass
    host = _keys_host(tmp_path / "b", {"odd": "-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64 at all\n"}, {"odd": gone})
    assert detect(cat, "auth.ssh_key_no_passphrase", make_scan(host)).status is Status.UNKNOWN


def test_passphrase_command_for_a_key_others_can_read_starts_with_chmod(cat, tmp_path):
    from test_checks_auth import openssh_key
    refused = CommandResult((), 255, "", "Permissions 0644 for 'x' are too open.\nLoad key: bad permissions\n")
    host = _keys_host(tmp_path, {"id_ed25519": openssh_key(), "id_rsa": openssh_key()},
                      {"id_ed25519": refused, "id_rsa": CommandResult((), 0, "ssh-rsa AAAA\n")},
                      modes={"id_ed25519": 0o644})
    g = build(cat, host, "auth.ssh_key_no_passphrase")
    assert g.steps[0].commands == [
        "chmod 600 ~/.ssh/id_ed25519     # ssh-keygen won't open it while others can read it (mode 644)",
        "ssh-keygen -p -f ~/.ssh/id_ed25519", "ssh-keygen -p -f ~/.ssh/id_rsa"]


# ------------------------------------------------------------------ the SSH agent

def _agent_host(tmp_path, config):
    agent = CommandResult(("ssh-add", "-l"), 0, "256 SHA256:x me (ED25519)\n")
    host = make_host(tmp_path, home_files={".ssh/config": config}, installed=("ssh",),
                     env={"SSH_AUTH_SOCK": "/tmp/ssh-XXXX/agent.99"},
                     files={"/proc/100/comm": "ssh-agent\n", "/proc/100/cmdline": "ssh-agent\0"})
    host.runner.handlers["ssh-add"] = lambda argv: agent
    return host


def test_add_keys_to_agent_with_a_lifetime_is_a_limit(cat, tmp_path):
    """The guide's own advice, AddKeysToAgent 1h, still counted as keys kept until logout, and was given again."""
    for value in ("1h", "3600", "1h30m", "confirm 10m", "confirm"):
        host = _agent_host(tmp_path / value.replace(" ", "_"), f"Host *\n    AddKeysToAgent {value}\n")
        o = detect(cat, "auth.ssh_client_settings", make_scan(host))
        assert o.status is Status.PASS and o.findings["agent_keys_unlimited"] is False, value
        assert any(n.title == "Keys added by hand" for n in o.notes)
        g = load_all()["auth.ssh_client_settings"](cat["auth.ssh_client_settings"]).plan_guide(make_scan(host), o)
        assert [s.title for s in g.steps] == ["Your SSH settings"] and g.steps[0].done
    for value in ("yes", "ask", "no"):
        host = _agent_host(tmp_path / value, f"AddKeysToAgent {value}\n")
        o = detect(cat, "auth.ssh_client_settings", make_scan(host))
        assert o.status is Status.WARN and o.findings["agent_keys_unlimited"], value
        g = build(cat, host, "auth.ssh_client_settings")
        assert any(s.title == "Let keys leave the agent" for s in g.steps)
    # only for every server: one server's setting doesn't cover the others
    host = _agent_host(tmp_path / "one", "Host pi\n    AddKeysToAgent 1h\n")
    assert detect(cat, "auth.ssh_client_settings", make_scan(host)).status is Status.WARN


# ------------------------------------------------------------------ the SSH server's port

from daprivacyscanner.network import parse_ss            # noqa: E402
from daprivacyscanner.privileged import FakePrivileged    # noqa: E402

from conftest import skip_if_root                         # noqa: E402

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFQsIvI0z3bygb1udZnZw4BxHi8M+W0EHgBYsNZSaeIv alice@example.com"
ON_2222 = parse_ss("tcp   LISTEN 0      128          [::]:2222        [::]:*\n")


@skip_if_root
def test_sshd_port_root_only_as_on_fedora(cat, tmp_path):
    """Fedora's sshd_config is 0600 and its drop-in folder 0700: a Port 2222 was never read, and the check said no
    server was listening (a lower severity). Through the helper, sshd -T says; without it the port couldn't be read."""
    import os
    host = make_host(tmp_path, home_files={".ssh/authorized_keys": ED + "\n"},
                     files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 2222\n",
                            "/etc/ssh/sshd_config.d/50-redhat.conf": "SyslogFacility AUTHPRIV\n"})
    cfg, folder = host.sys_path("/etc/ssh/sshd_config"), host.sys_path("/etc/ssh/sshd_config.d")
    os.chmod(cfg, 0)
    os.chmod(folder, 0)
    try:
        o = detect(cat, "auth.ssh_authorized_keys", make_scan(host, listeners=ON_2222))
        assert o.findings["sshd_reachable"] is None and o.status is Status.WARN
        assert ev(o)["SSH server"] == "couldn't tell: its port couldn't be read"
        assert any(n.title == "The SSH server's port couldn't be read" for n in o.notes)
        # something on 22, the default, still counts
        o = detect(cat, "auth.ssh_authorized_keys",
                   make_scan(host, listeners=parse_ss("tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n")))
        assert o.findings["sshd_reachable"] is True
        host.privileged = FakePrivileged(sshd={"port": ["2222"], "listenaddress": ["[::]:2222", "0.0.0.0:2222"]})
        o = detect(cat, "auth.ssh_authorized_keys", make_scan(host, listeners=ON_2222))
        assert o.findings["sshd_reachable"] is True and ev(o)["SSH server"].startswith("listening")
    finally:
        os.chmod(folder, 0o755)
        os.chmod(cfg, 0o644)


def test_sshd_port_from_listen_address_and_equals(cat, tmp_path):
    from daprivacyscanner.checks.auth import sshd_ports
    host = make_host(tmp_path, files={"/etc/ssh/sshd_config": "Port=2200\nListenAddress 10.0.0.5:2201\nListenAddress ::\n"
                                                              "ListenAddress [::1]:2202\n"})
    assert sshd_ports(make_scan(host)) == {2200, 2201, 2202}
    assert sshd_ports(make_scan(make_host(tmp_path / "none"))) == {22}
