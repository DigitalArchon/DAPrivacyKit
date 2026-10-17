import json
import os
import sqlite3
import sys

import pytest

from daprivacyscanner.checks.auth import NSS_SCRIPT
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.network import Listener
from daprivacyscanner.privileged import FakePrivileged

from conftest import SAMPLES, detect, ev, make_host, make_scan


@pytest.mark.parametrize("value, status", [(True, Status.FAIL), (False, Status.PASS), (None, Status.UNKNOWN)])
def test_autologin(cat, tmp_path, value, status):
    assert detect(cat, "auth.autologin", make_scan(make_host(tmp_path), autologin=value)).status is status


def test_empty_password(cat, tmp_path):
    host = make_host(tmp_path)
    assert detect(cat, "auth.empty_password", make_scan(host)).partial
    host.privileged = FakePrivileged(empty_passwords=["guest"])
    o = detect(cat, "auth.empty_password", make_scan(host))
    assert o.status is Status.FAIL and ev(o) == {"Empty password": "guest"}
    host.privileged = FakePrivileged()
    assert detect(cat, "auth.empty_password", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ screen lock

def gs(schema, key):
    return f"gsettings get {schema} {key}"


GNOME_OK = {gs("org.gnome.desktop.screensaver", "lock-enabled"): "true\n",
            gs("org.gnome.desktop.session", "idle-delay"): "uint32 300\n",
            gs("org.gnome.desktop.screensaver", "lock-delay"): "uint32 0\n"}


@pytest.mark.parametrize("changes, status", [
    ({}, Status.PASS),
    ({gs("org.gnome.desktop.screensaver", "lock-enabled"): "false\n"}, Status.FAIL),
    ({gs("org.gnome.desktop.session", "idle-delay"): "uint32 0\n"}, Status.FAIL),
    ({gs("org.gnome.desktop.session", "idle-delay"): "uint32 900\n"}, Status.WARN),
    ({gs("org.gnome.desktop.screensaver", "lock-delay"): "uint32 120\n"}, Status.WARN),    # 5 + 2 minutes
    ({gs("org.gnome.desktop.screensaver", "ubuntu-lock-on-suspend"): "false\n"}, Status.FAIL),
])
def test_screen_lock_gnome(cat, tmp_path, changes, status):
    host = make_host(tmp_path, commands={**GNOME_OK, **changes})
    assert detect(cat, "auth.screen_lock", make_scan(host, desktop=("ubuntu", "gnome"))).status is status


def test_screen_lock_cinnamon(cat, tmp_path):
    host = make_host(tmp_path, commands={gs("org.cinnamon.desktop.screensaver", "lock-enabled"): "true\n",
                                         gs("org.cinnamon.desktop.session", "idle-delay"): "uint32 0\n"})
    o = detect(cat, "auth.screen_lock", make_scan(host, desktop=("x-cinnamon",)))
    assert o.status is Status.FAIL and "when idle" in o.summary


@pytest.mark.parametrize("rc, status", [
    (None, Status.PASS),                                               # no file at all: KDE's defaults lock after 5 min
    ("[Daemon]\nTimeout=3\n", Status.PASS),
    ("[Daemon]\nAutolock=false\n", Status.FAIL),
    ("[Daemon]\nLockOnResume=false\n", Status.FAIL),
    ("[Daemon]\nTimeout=30\n", Status.WARN),
])
def test_screen_lock_kde_defaults(cat, tmp_path, rc, status):
    host = make_host(tmp_path, home_files={".config/kscreenlockerrc": rc} if rc else {})
    assert detect(cat, "auth.screen_lock", make_scan(host, desktop=("kde",), plasma_major=6)).status is status


def test_screen_lock_unknown_desktop(cat, tmp_path):
    assert detect(cat, "auth.screen_lock", make_scan(make_host(tmp_path), desktop=("sway",))).partial


APP = "org.gnome.desktop.notifications.application:/org/gnome/desktop/notifications/application/{}/"


def test_lockscreen_notifications(cat, tmp_path):
    """GNOME's lock screen shows which apps sent notifications; their text only for apps allowed to show it."""
    on = {gs("org.gnome.desktop.notifications", "show-in-lock-screen"): "true\n",
          gs("org.gnome.desktop.notifications", "application-children"): "['org-gnome-chat', 'firefox']\n",
          gs(APP.format("firefox"), "details-in-lock-screen"): "false\n"}
    host = make_host(tmp_path, commands={**on, gs(APP.format("org-gnome-chat"), "details-in-lock-screen"): "true\n"})
    o = detect(cat, "auth.lockscreen_notifications", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Apps whose message text is shown"] == "org-gnome-chat"
    host = make_host(tmp_path / "b", commands={**on, gs(APP.format("org-gnome-chat"), "details-in-lock-screen"): "false\n"})
    assert detect(cat, "auth.lockscreen_notifications", make_scan(host)).status is Status.PASS
    host = make_host(tmp_path / "c", commands={gs("org.gnome.desktop.notifications", "show-in-lock-screen"): "true\n"})
    assert detect(cat, "auth.lockscreen_notifications", make_scan(host)).status is Status.UNKNOWN
    assert detect(cat, "auth.lockscreen_notifications", make_scan(host, desktop=("sway",))).partial


def test_lockscreen_notifications_kde_shows_none_but_media(cat, tmp_path):
    """Plasma's lock screen shows no notifications; it shows what is playing unless turned off."""
    o = detect(cat, "auth.lockscreen_notifications", make_scan(make_host(tmp_path / "a"), desktop=("kde",)))
    assert o.status is Status.PASS and ev(o)["Media playing shown on the lock screen"] is True
    assert o.notes[0].title == "It shows what is playing"
    host = make_host(tmp_path / "b", home_files={".config/kscreenlockerrc": "[Greeter][LnF][General]\nshowMediaControls=false\n"})
    o = detect(cat, "auth.lockscreen_notifications", make_scan(host, desktop=("kde",)))
    assert o.status is Status.PASS and ev(o)["Media playing shown on the lock screen"] is False and not o.notes


def test_lockscreen_notifications_cinnamon_shows_a_count(cat, tmp_path):
    o = detect(cat, "auth.lockscreen_notifications", make_scan(make_host(tmp_path), desktop=("x-cinnamon",)))
    assert o.status is Status.PASS and ev(o)["Shown on the lock screen"] == "a count of notifications"


# ------------------------------------------------------------------ keyrings

def test_keyrings(cat, tmp_path):
    host = make_host(tmp_path)
    rings = host.home / ".local/share/keyrings"
    rings.mkdir(parents=True)
    (rings / "login.keyring").write_bytes(b"GnomeKeyring\n\r\0\n\x00\x01binary")
    assert detect(cat, "auth.keyring_blank", make_scan(host)).status is Status.PASS
    (rings / "Default_keyring.keyring").write_text("[keyring]\ndisplay-name=Default keyring\n")
    o = detect(cat, "auth.keyring_blank", make_scan(host))
    assert o.status is Status.FAIL and "Default_keyring.keyring" in o.summary


def _wallets(host, *names, salt=True):
    """Real wallets made by KWallet 6.30 (tests/samples/kwallet), as ~/.local/share/kwalletd/kdewallet.kwl etc."""
    import shutil
    d = host.home / ".local/share/kwalletd"
    d.mkdir(parents=True, exist_ok=True)
    for sample_name, as_name in names:
        shutil.copy(SAMPLES / "kwallet" / f"{sample_name}.kwl", d / f"{as_name}.kwl")
        if salt:
            shutil.copy(SAMPLES / "kwallet" / f"{sample_name}.salt", d / f"{as_name}.salt")
    return d


def test_kwallet_with_a_blank_password(cat, tmp_path):
    host = make_host(tmp_path)
    _wallets(host, ("blank", "kdewallet"))
    o = detect(cat, "auth.keyring_blank", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and o.summary == "This opens without a password: kdewallet.kwl."
    assert ev(o)["kdewallet.kwl"] == "opens without a password (KDE wallet)"


def test_kwallet_with_a_password(cat, tmp_path):
    host = make_host(tmp_path)
    _wallets(host, ("protected", "kdewallet"))
    o = detect(cat, "auth.keyring_blank", make_scan(host, desktop=("kde",)))
    assert o.status is Status.PASS and ev(o)["kdewallet.kwl"] == "has a password (KDE wallet)"


def test_kwallet_that_cant_be_judged_is_unknown(cat, tmp_path):
    host = make_host(tmp_path)
    d = _wallets(host, ("protected", "kdewallet"), salt=False)
    o = detect(cat, "auth.keyring_blank", make_scan(host, desktop=("kde",)))
    assert o.status is Status.UNKNOWN and "kdewallet.salt) is missing" in ev(o)["kdewallet.kwl"]
    (d / "kdewallet.kwl").write_bytes(b"not a wallet")
    assert detect(cat, "auth.keyring_blank", make_scan(host)).status is Status.UNKNOWN
    (d / "kdewallet.kwl").write_bytes(b"KWALLET\n\r\0\r\n" + bytes([0, 1, 2, 0]))      # GPG
    o = detect(cat, "auth.keyring_blank", make_scan(host))
    assert o.status is Status.PASS and ev(o)["kdewallet.kwl"] == "protected by a GPG key (KDE wallet)"


# ------------------------------------------------------------------ Chromium

def chrome_profile(home, cookies_prefix=b"v11", login_prefix=b"v11"):
    prof = home / ".config/google-chrome/Default"
    (prof / "Network").mkdir(parents=True)
    (prof / "Preferences").write_text("{}")
    con = sqlite3.connect(prof / "Login Data")
    con.execute("CREATE TABLE logins (origin_url TEXT, password_value BLOB)")
    con.execute("INSERT INTO logins VALUES ('https://example.org', ?)", (login_prefix + b"\x00secret",))
    con.commit(); con.close()
    con = sqlite3.connect(prof / "Network/Cookies")
    con.execute("CREATE TABLE cookies (host_key TEXT, encrypted_value BLOB)")
    con.executemany("INSERT INTO cookies VALUES (?, ?)", [("a", cookies_prefix + b"x"), ("b", cookies_prefix + b"y")])
    con.commit(); con.close()


BUS = {"busctl --user list": "NAME PID PROCESS\norg.freedesktop.secrets 1234 gnome-keyring-d\n"}


def test_chromium_with_keyring(cat, tmp_path):
    host = make_host(tmp_path, commands=BUS)
    chrome_profile(host.home)
    assert detect(cat, "auth.chromium_basic_store", make_scan(host)).status is Status.PASS


def test_chromium_basic_store_secrets(cat, tmp_path):
    host = make_host(tmp_path, commands=BUS)
    chrome_profile(host.home, cookies_prefix=b"v10", login_prefix=b"v10")
    o = detect(cat, "auth.chromium_basic_store", make_scan(host))
    assert o.status is Status.FAIL
    assert ev(o)["Secrets under the built-in key (Google Chrome, Default)"] == 3


def test_chromium_flag_file(cat, tmp_path):
    host = make_host(tmp_path, commands=BUS, home_files={".config/brave-flags.conf": "--password-store=basic\n"})
    assert detect(cat, "auth.chromium_basic_store", make_scan(host)).status is Status.FAIL


def test_chromium_without_secret_service(cat, tmp_path):
    host = make_host(tmp_path, commands={"busctl --user list": "NAME PID PROCESS\n"})
    chrome_profile(host.home)
    assert detect(cat, "auth.chromium_basic_store", make_scan(host)).status is Status.FAIL


def test_no_chromium(cat, tmp_path):
    assert detect(cat, "auth.chromium_basic_store", make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ remote desktop

def test_remote_desktop(cat, tmp_path):
    rdp = [Listener("tcp", "*", 3389), Listener("tcp", "127.0.0.1", 5901)]
    o = detect(cat, "auth.remote_desktop", make_scan(make_host(tmp_path), listeners=rdp))
    assert o.status is Status.FAIL and "RDP port 3389" in ev(o)
    assert "VNC port 5901" not in ev(o)                                    # loopback only

    host = make_host(tmp_path / "g", commands={"grdctl status": "Overlay:\nRDP:\n\tStatus: enabled\n\tPort: 3389\nVNC:\n\tStatus: disabled\n"})
    assert ev(detect(cat, "auth.remote_desktop", make_scan(host))) == {"GNOME Remote Desktop (RDP)": "enabled"}
    assert detect(cat, "auth.remote_desktop", make_scan(make_host(tmp_path / "n"), listeners=[])).status is Status.PASS


def test_gnome_remote_desktop_daemon_alone_is_not_sharing(cat, tmp_path):
    """Its daemon and user service run on every GNOME desktop since 42 with sharing off: only
    grdctl's status counts (and a listening port), or the finding could never be cleared."""
    off = "Overlay:\nRDP:\n\tStatus: disabled\nVNC:\n\tStatus: disabled\n"
    host = make_host(tmp_path, files={"/proc/501/comm": "gnome-remote-de\n"},
                     commands={"grdctl status": off, "systemctl --user is-active gnome-remote-desktop": "active\n"})
    o = detect(cat, "auth.remote_desktop", make_scan(host, listeners=[]))
    assert o.status is Status.PASS and not o.notes
    # grdctl missing or failing while the daemon runs: not a finding, but said
    host = make_host(tmp_path / "x", files={"/proc/501/comm": "gnome-remote-de\n"})
    o = detect(cat, "auth.remote_desktop", make_scan(host, listeners=[]))
    assert o.status is Status.PASS and o.notes and "grdctl status couldn't say" in o.notes[0].text


# ------------------------------------------------------------------ SSH and GPG

def test_ssh_keys(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\n", ".ssh/id_ed25519.pub": "ssh-ed25519 AAA",
        ".ssh/work": "-----BEGIN OPENSSH PRIVATE KEY-----\nBBB\n", ".ssh/yubi": "-----BEGIN OPENSSH PRIVATE KEY-----\nCCC\n",
        ".ssh/known_hosts": "x", ".ssh/config": "Host *"},
        commands={})
    k = host.home / ".ssh"
    for name in ("id_ed25519", "work", "yubi"):
        os.chmod(k / name, 0o600)
    host.runner.outputs = {
        ("ssh-keygen", "-y", "-P", "", "-f", str(k / "id_ed25519")): CommandResult((), 0, "ssh-ed25519 AAAA\n"),
        ("ssh-keygen", "-y", "-P", "", "-f", str(k / "work")): CommandResult((), 255, "", "incorrect passphrase"),
        ("ssh-keygen", "-y", "-P", "", "-f", str(k / "yubi")): CommandResult((), 0, "sk-ssh-ed25519@openssh.com AAAA\n"),
    }
    host.runner.installed.add("ssh-keygen")
    o = detect(cat, "auth.ssh_key_no_passphrase", make_scan(host))
    assert o.status is Status.FAIL and o.summary.endswith("id_ed25519.")
    assert ev(o)["work"] == "protected by a passphrase" and ev(o)["yubi"].startswith("hardware")


def test_gpg_keys(cat, tmp_path):
    d = ".gnupg/private-keys-v1.d/"
    host = make_host(tmp_path, home_files={d + "A.key": "Created: 2024\nKey: (protected-private-key (ecc", d + "B.key":
                                           "(11:private-key(3:ecc", d + "C.key": "Key: (shadowed-private-key (rsa"})
    o = detect(cat, "auth.gpg_no_passphrase", make_scan(host))
    assert o.status is Status.FAIL and ev(o) == {"Secret keys": 3, "Without a passphrase": 1, "On a smartcard": 1}


# ------------------------------------------------------------------ credential files

def test_plaintext_credentials(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".git-credentials": "https://alice:ghp_secret@github.com\n",
        ".docker/config.json": json.dumps({"auths": {"registry.example": {"auth": "YWxpY2U6cHc="}}}),
        ".config/gh/hosts.yml": "github.com:\n    user: alice\n    git_protocol: https\n",       # token in keyring
        "code/app/.env": "DB_PASSWORD=x\n", "code/app/.env.example": "DB_PASSWORD=\n",
        "code/app/node_modules/x/.env": "IGNORED=1\n",
    })
    os.chmod(host.home / ".git-credentials", 0o644)
    o = detect(cat, "auth.plaintext_credentials", make_scan(host))
    assert o.status is Status.FAIL
    assert "Git credentials, readable by everyone (644)" in ev(o)
    assert "GitHub CLI token" not in o.summary and ev(o)[".env files with passwords or keys in your home"] == 1


@pytest.mark.parametrize("text, n", [
    ("DB_PASSWORD=hunter22\nSTRIPE_SECRET_KEY='sk_live_abc'\nPORT=3000\n", 2),
    ("DEBUG=true\nPORT=3000\nNODE_ENV=production\n", 0),                    # configuration, no secrets
    ("API_KEY=\nDB_PASSWORD=changeme\nTOKEN=${TOKEN}\nSECRET=<your secret>\n", 0),      # placeholders
    ("STRIPE_PUBLISHABLE_KEY=pk_live_1\nGOOGLE_CLIENT_ID=abc.apps\n", 0),       # meant to be public
    ("DATABASE_URL=postgres://app:s3cretpw@db:5432/app\n", 1),                  # a password in a URL
    ("export GITHUB_TOKEN=ghp_abcdef\n", 1),
])
def test_env_secrets(text, n):
    from daprivacyscanner.checks.auth import env_secrets
    assert env_secrets(text) == n


def test_docker_with_credential_helper_is_fine(cat, tmp_path):
    host = make_host(tmp_path, home_files={".docker/config.json": json.dumps({"auths": {"x": {}}, "credsStore": "secretservice"})})
    assert detect(cat, "auth.plaintext_credentials", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ history

def test_history_secrets(cat, tmp_path):
    host = make_host(tmp_path, home_files={".bash_history": "\n".join([
        "ls -la", "passwd", "export API_KEY=abcd1234efgh", "mysql -u root -pHunter2 db",
        "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' https://api", "git push",
        "git clone https://alice:hunter22@git.example/repo", "echo AKIAABCDEFGHIJKLMNOP"]) + "\n",
        ".python_history": "import os\n"})
    o = detect(cat, "auth.shell_history_secrets", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Lines that look like secrets in ~/.bash_history"] == 5


def test_history_clean(cat, tmp_path):
    host = make_host(tmp_path, home_files={".zsh_history": ": 1700000000:0;ls\n: 1700000001:0;passwd\n"})
    assert detect(cat, "auth.shell_history_secrets", make_scan(host)).status is Status.PASS
    assert detect(cat, "auth.shell_history_secrets", make_scan(make_host(tmp_path / "e"))).status is Status.NOT_APPLICABLE


# ------------------------------------------------------------------ sudo

@pytest.mark.parametrize("out, status", [
    ("User alice may run the following commands:\n    (ALL : ALL) NOPASSWD: ALL\n", Status.FAIL),
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/mintdrivers-remove-live-media\n", Status.PASS),
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/vim /etc/hosts\n", Status.FAIL),       # vim opens a shell
    # fixed arguments: sudo allows only these, and restarting a service opens no pager or editor
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/systemctl restart nginx\n", Status.PASS),
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/systemctl status nginx\n", Status.FAIL),    # pages with less
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/systemctl *\n", Status.FAIL),               # any arguments
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/apt-get update\n", Status.PASS),
    ("User alice may run:\n    (root) NOPASSWD: /usr/bin/journalctl -u ssh\n", Status.FAIL),
    (CommandResult((), 1, "", "sudo: a password is required\n"), Status.PASS),
])
def test_sudo(cat, tmp_path, out, status):
    host = make_host(tmp_path, commands={"sudo -n -l": out})
    o = detect(cat, "auth.sudo_nopasswd", make_scan(host))
    assert o.status is status


def test_sudo_rule_running_a_script_the_user_can_change(cat, tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/sh\n")
    host = make_host(tmp_path, commands={"sudo -n -l": f"    (root) NOPASSWD: /usr/bin/bash {script}\n"})
    assert detect(cat, "auth.sudo_nopasswd", make_scan(host)).status is Status.FAIL


def test_narrow_sudo_rules_get_a_note(cat, tmp_path):
    host = make_host(tmp_path, commands={"sudo -n -l": "    (root) NOPASSWD: /usr/bin/mint-refresh-cache\n"})
    o = detect(cat, "auth.sudo_nopasswd", make_scan(host))
    assert o.notes and "mint-refresh-cache" in o.notes[0].text


def test_doas_nopass(cat, tmp_path):
    # the rule is for wheel: alice is in it (it counted for every account before)
    host = make_host(tmp_path, files={"/etc/doas.conf": "permit nopass :wheel\n",
                                      "/etc/passwd": "alice:x:1000:1000::/home/alice:/bin/bash\n",
                                      "/etc/group": "wheel:x:10:alice\n"})
    assert detect(cat, "auth.sudo_nopasswd", make_scan(host)).status is Status.FAIL


# ------------------------------------------------------------------ Firefox primary password

def ff_profile(home, logins=1):
    root = home / ".mozilla/firefox"
    (root / "abcd.default-release").mkdir(parents=True)
    (root / "profiles.ini").write_text("[Install4F96D1932A9F858E]\nDefault=abcd.default-release\n\n"
                                       "[Profile0]\nName=default-release\nIsRelative=1\nPath=abcd.default-release\n")
    (root / "abcd.default-release/logins.json").write_text(json.dumps({"logins": [{}] * logins}))
    return root / "abcd.default-release"


@pytest.mark.parametrize("nss, status", [("0\n", Status.FAIL), ("1\n", Status.PASS), ("error\n", Status.UNKNOWN)])
def test_firefox_primary_password(cat, tmp_path, nss, status):
    host = make_host(tmp_path)
    prof = ff_profile(host.home)
    host.runner.outputs[(sys.executable, "-I", "-c", NSS_SCRIPT, str(prof))] = CommandResult((), 0, nss)
    assert detect(cat, "auth.firefox_no_primary_password", make_scan(host)).status is status


def test_firefox_without_saved_logins_does_not_need_nss(cat, tmp_path):
    host = make_host(tmp_path)
    ff_profile(host.home, logins=0)
    assert detect(cat, "auth.firefox_no_primary_password", make_scan(host)).status is Status.PASS
    assert host.runner.calls == []


def test_firefox_snap_profile_is_found(cat, tmp_path):
    host = make_host(tmp_path)
    root = host.home / "snap/firefox/common/.mozilla/firefox"
    (root / "x.default").mkdir(parents=True)
    (root / "profiles.ini").write_text("[Profile0]\nPath=x.default\nIsRelative=1\n")
    (root / "x.default/logins.json").write_text(json.dumps({"logins": [{}]}))
    host.runner.outputs[(sys.executable, "-I", "-c", NSS_SCRIPT, str(root / "x.default"))] = CommandResult((), 0, "0\n")
    o = detect(cat, "auth.firefox_no_primary_password", make_scan(host))
    assert o.status is Status.FAIL and "snap" in o.summary


MAKE_NSS_DB = r"""
import ctypes, ctypes.util, sys
nss = ctypes.CDLL(ctypes.util.find_library("nss3"))
nss.NSS_Initialize.argtypes = [ctypes.c_char_p] * 4 + [ctypes.c_uint32]
assert nss.NSS_Initialize(b"sql:" + sys.argv[1].encode(), b"", b"", b"secmod.db", 0) == 0
nss.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
slot = ctypes.c_void_p(nss.PK11_GetInternalKeySlot())
nss.PK11_InitPin.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
assert nss.PK11_InitPin(slot, b"", sys.argv[2].encode()) == 0
nss.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
nss.PK11_FreeSlot(slot)
nss.NSS_Shutdown()
"""


@pytest.mark.parametrize("password, expected", [("", "0"), ("hunter2", "1")])
def test_nss_probe_against_a_real_key_database(tmp_path, password, expected):
    """The NSS probe itself, where libnss3 is installed."""
    import ctypes.util
    import subprocess
    if not ctypes.util.find_library("nss3"):
        pytest.skip("libnss3 is not installed")
    subprocess.run([sys.executable, "-c", MAKE_NSS_DB, str(tmp_path), password], check=True)
    out = subprocess.run([sys.executable, "-I", "-c", NSS_SCRIPT, str(tmp_path)], capture_output=True, text=True)
    assert out.stdout.strip() == expected


# ------------------------------------------------------------------ permissions

def test_home_and_umask(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/self/status": "Name:\tpython3\nUmask:\t0022\n"})
    os.chmod(host.home, 0o755)
    assert detect(cat, "auth.home_world_readable", make_scan(host)).status is Status.FAIL
    assert detect(cat, "auth.umask", make_scan(host)).status is Status.FAIL     # others can get in, and read
    os.chmod(host.home, 0o750)
    assert detect(cat, "auth.home_world_readable", make_scan(host)).status is Status.PASS
    o = detect(cat, "auth.umask", make_scan(host))                               # they can't get into home
    assert o.status is Status.PASS and o.notes[0].title == "Outside your home folder"
    host.sys_path("/proc/self/status").write_text("Umask:\t0077\n")
    assert detect(cat, "auth.umask", make_scan(host)).status is Status.PASS


def openssh_key(cipher: bytes = b"none", kind: bytes = b"ssh-ed25519") -> str:
    """An openssh-key-v1 file: its cipher name and public key type are in the clear."""
    import base64
    s = lambda b: len(b).to_bytes(4, "big") + b                                  # noqa: E731
    raw = (b"openssh-key-v1\0" + s(cipher) + s(b"none" if cipher == b"none" else b"bcrypt") + s(b"")
           + (1).to_bytes(4, "big") + s(s(kind) + s(b"\0" * 32)) + s(b"private part"))
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(raw).decode() + "\n-----END OPENSSH PRIVATE KEY-----\n"


def test_ssh_key_others_can_read_is_still_checked(cat, tmp_path):
    """ssh-keygen refuses a key with loose permissions, passphrase or not: the key file itself says."""
    host = make_host(tmp_path, home_files={".ssh/id_ed25519": openssh_key(), ".ssh/work": openssh_key(b"aes256-ctr")})
    k = host.home / ".ssh"
    refused = CommandResult((), 255, "", "Permissions 0644 for 'x' are too open.\nLoad key: bad permissions\n")
    for name in ("id_ed25519", "work"):
        os.chmod(k / name, 0o644)
        host.runner.outputs[("ssh-keygen", "-y", "-P", "", "-f", str(k / name))] = refused
    host.runner.installed.add("ssh-keygen")
    o = detect(cat, "auth.ssh_key_no_passphrase", make_scan(host))
    assert o.status is Status.FAIL and o.summary.endswith("id_ed25519.")
    assert ev(o)["id_ed25519"] == "no passphrase, readable by other users (mode 644)"
    assert ev(o)["work"].startswith("protected by a passphrase") and o.notes[0].title == "Private keys other users can read"


@pytest.mark.parametrize("text, state", [
    (openssh_key(), "none"), (openssh_key(b"aes256-ctr"), "encrypted"), (openssh_key(kind=b"sk-ssh-ed25519@openssh.com"), "sk"),
    ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n", "encrypted"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n", "none"), ("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "encrypted"),
    ("PuTTY-User-Key-File-3: ssh-ed25519\n", None),
])
def test_key_protection(text, state):
    from daprivacyscanner.checks.auth import key_protection
    assert key_protection(text) == state


def test_basic_store_forced_for_an_electron_app_and_its_plain_cookies(cat, tmp_path):
    """Any *-flags.conf or menu entry with --password-store=basic counts, an Electron app's included; an Electron
    app's unencrypted cookies (Electron leaves cookie encryption off unless the app turns it on) are counted in a
    note, never read."""
    import sqlite3
    from daprivacyscanner.model import Status
    from conftest import detect, ev, make_host, make_scan
    host = make_host(tmp_path, home_files={".config/code-flags.conf": "--password-store=basic\n",
                                           ".config/Slack/GPUCache/data_0": "x"},
                     files={"/usr/share/applications/signal-desktop.desktop":
                            "[Desktop Entry]\nExec=signal-desktop --password-store=basic %U\n"})
    (host.home / ".config/Slack/Network").mkdir(parents=True)
    db = sqlite3.connect(host.home / ".config/Slack/Network/Cookies")
    db.executescript("CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB);"
                     "INSERT INTO cookies VALUES ('.slack.com', 'd', 'xoxd-secret', x'');")
    db.commit()
    db.close()
    o = detect(cat, "auth.chromium_basic_store", make_scan(host))
    assert o.status.name == "FAIL"
    shown = [e.value for e in o.evidence if e.label == "--password-store=basic in"]
    assert shown == ["~/.config/code-flags.conf", "/usr/share/applications/signal-desktop.desktop"]
    assert ev(o)["Cookies kept unencrypted by Slack"] == 1 and "xoxd" not in repr(o)
    assert any(n.title == "Electron apps that keep their logins unencrypted" for n in o.notes)


def test_shell_history_found_where_the_profiles_put_it(cat, tmp_path):
    """zsh's ZDOTDIR from ~/.zshenv and its HISTFILE from $ZDOTDIR/.zshrc (a shell variable, not in the app's
    environment), and REPLs beyond the usual list; the guide cleans those files too."""
    from conftest import detect, ev, make_host, make_scan
    from test_guides import apply, build, options
    secret = "curl -u admin:hunter2secret https://example.com\n"
    host = make_host(tmp_path, home_files={
        ".zshenv": 'export ZDOTDIR="$HOME/.config/zsh"\n',
        ".config/zsh/.zshrc": "HISTFILE=$XDG_STATE_HOME/zsh/hist\nsetopt share_history\n",
        ".local/state/zsh/hist": ": 1700000000:0;ls\n: 1700000001:0;" + secret,
        ".rediscli_history": "AUTH password=supersecret1\n"})
    o = detect(cat, "auth.shell_history_secrets", make_scan(host))
    assert o.status.name == "FAIL"
    assert ev(o)["Lines that look like secrets in ~/.local/state/zsh/hist"] == 1
    assert ev(o)["Lines that look like secrets in ~/.rediscli_history"] == 1
    g = build(cat, host, "auth.shell_history_secrets")
    apply(host, options(g)["Remove them"])
    assert "hunter2" not in (host.home / ".local/state/zsh/hist").read_text()
    apply(host, options(g)["Turn it on"])
    assert "HIST_IGNORE_SPACE" in (host.home / ".config/zsh/.zshrc").read_text()


def test_home_opened_by_a_shared_group_or_an_acl(cat, tmp_path):
    """Closed to others but open to a group with other accounts in it (openSUSE's users), or to someone an ACL names:
    still open to other users, and the guide recommends 700 then."""
    import struct
    from conftest import detect, make_host, make_scan
    from test_guides import build, options
    gid, uid = os.getgid(), os.getuid()
    host = make_host(tmp_path, files={"/etc/passwd": f"alice:x:{uid}:{gid}::/home/alice:/bin/bash\n",
                                      "/etc/group": f"users:x:{gid}:bob\n"})
    os.chmod(host.home, 0o750)
    o = detect(cat, "auth.home_world_readable", make_scan(host))
    assert o.status.name == "FAIL" and "1 other member of its group users" in o.summary
    opts = options(build(cat, host, "auth.home_world_readable"))
    assert list(opts) == ["Only you (700)"]
    host.sys_path("/etc/group").write_text(f"alice:x:{gid}:\n")
    assert detect(cat, "auth.home_world_readable", make_scan(host)).status.name == "PASS"
    # user::rwx, user:1234:r-x, group::r-x, mask::r-x, other::---
    acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in (
        (0x01, 7, 0xFFFFFFFF), (0x02, 5, 1234), (0x04, 5, 0xFFFFFFFF), (0x10, 5, 0xFFFFFFFF), (0x20, 0, 0xFFFFFFFF)))
    try:
        os.setxattr(host.home, "system.posix_acl_access", acl)
    except OSError:
        pytest.skip("no POSIX ACLs here")
    o = detect(cat, "auth.home_world_readable", make_scan(host))
    assert o.status.name == "FAIL" and "access list (ACL)" in o.summary


def test_remote_access_that_listens_on_no_port(cat, tmp_path):
    """Chrome Remote Desktop connects out through Google and listens on nothing: only its process shows it."""
    from conftest import detect, make_host, make_scan
    host = make_host(tmp_path, files={"/proc/42/comm": "remoting_me2me_\n"})
    o = detect(cat, "auth.remote_desktop", make_scan(host, listeners=[]))
    assert o.status.name == "FAIL" and {e.label for e in o.evidence} == {"Chrome Remote Desktop"}
