"""Decoy files for a trial's throwaway home (docs/TECHNICAL.md, Tools: Try an app): what a program that goes
looking would look for: SSH and GnuPG keys, browsers' saved logins and cookies, a keyring, wallets, cloud
credentials, a shell history, a few documents and a photo. A program that has no business with them and opens
them anyway shows what it is; tools/homewatch.py reports each one listed or opened.

All of it is made up here, new for each trial, from random bytes: nothing of the user's is copied, and what a
program takes of it is worth nothing. The files have the right names and first bytes (a real SQLite database
where one is expected), not working contents."""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def _hex(n: int) -> str:
    return os.urandom(n).hex()


def _key() -> bytes:
    body = _b64(240)
    lines = "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}\n-----END OPENSSH PRIVATE KEY-----\n".encode()


def _pdf() -> bytes:
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")


def _jpeg() -> bytes:
    return (bytes.fromhex("ffd8ffe000104a46494600010100000100010000ffdb004300") + bytes([8] * 64)
            + bytes.fromhex("ffc0000b080001000101011100ffc4001400010000000000000000000000000000000000"
                            "ffc40014100100000000000000000000000000000000ffda0008010100003f00d2cf20ffd9"))


def _sqlite(path: Path, table: str, columns: str, row: tuple) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute(f"CREATE TABLE {table} ({columns})")
        con.execute(f"INSERT INTO {table} VALUES ({','.join('?' * len(row))})", row)
        con.commit()
    finally:
        con.close()


def _files() -> list[tuple[str, str, object]]:
    """(path under the home, what it stands for, its contents: bytes, or a callable given the path)."""
    ff, tb = f"{_hex(4)}.default-release", f"{_hex(4)}.default"
    host, user = f"srv-{_hex(2)}.example.net", f"user{_hex(2)}"
    logins = ('{"nextId":2,"logins":[{"id":1,"hostname":"https://%s","encryptedUsername":"%s","encryptedPassword":"%s"}]}'
              % (host, _b64(48), _b64(64))).encode()
    return [
        (".ssh/id_ed25519", "an SSH private key", _key()),
        (".ssh/id_ed25519.pub", "an SSH public key", f"ssh-ed25519 {_b64(51)} {user}@laptop\n".encode()),
        (".ssh/known_hosts", "the list of SSH servers used", f"{host} ssh-ed25519 {_b64(51)}\n".encode()),
        (".ssh/config", "SSH settings", f"Host work\n  HostName {host}\n  User {user}\n".encode()),
        (".gnupg/pubring.kbx", "the GnuPG keyring", b"\x00\x00\x00\x20\x01\x01\x00\x00KBXf" + os.urandom(400)),
        (f".gnupg/private-keys-v1.d/{_hex(20).upper()}.key", "a GnuPG private key", os.urandom(600)),
        (".local/share/keyrings/login.keyring", "the login keyring (saved passwords)", b"GnomeKeyring\n\r\0\n" + os.urandom(900)),
        (".mozilla/firefox/profiles.ini", "Firefox's profile list",
         f"[Profile0]\nName=default-release\nIsRelative=1\nPath={ff}\nDefault=1\n".encode()),
        (f".mozilla/firefox/{ff}/logins.json", "Firefox's saved logins", logins),
        (f".mozilla/firefox/{ff}/key4.db", "the key to Firefox's saved logins",
         lambda p: _sqlite(p, "metaData", "id TEXT, item1 BLOB, item2 BLOB", ("password", os.urandom(20), os.urandom(64)))),
        (f".mozilla/firefox/{ff}/cookies.sqlite", "Firefox's cookies",
         lambda p: _sqlite(p, "moz_cookies", "id INTEGER, name TEXT, value TEXT, host TEXT", (1, "session", _hex(24), host))),
        (f".mozilla/firefox/{ff}/places.sqlite", "Firefox's history and bookmarks",
         lambda p: _sqlite(p, "moz_places", "id INTEGER, url TEXT, title TEXT", (1, f"https://{host}/", "Home"))),
        (".config/google-chrome/Local State", "the key to Chrome's saved logins",
         ('{"os_crypt":{"encrypted_key":"%s"}}' % _b64(64)).encode()),
        (".config/google-chrome/Default/Login Data", "Chrome's saved logins",
         lambda p: _sqlite(p, "logins", "origin_url TEXT, username_value TEXT, password_value BLOB", (f"https://{host}/", user, os.urandom(48)))),
        (".config/google-chrome/Default/Cookies", "Chrome's cookies",
         lambda p: _sqlite(p, "cookies", "host_key TEXT, name TEXT, encrypted_value BLOB", (host, "sid", os.urandom(48)))),
        (".config/google-chrome/Default/History", "Chrome's history",
         lambda p: _sqlite(p, "urls", "id INTEGER, url TEXT, title TEXT", (1, f"https://{host}/", "Home"))),
        (".thunderbird/profiles.ini", "Thunderbird's profile list", f"[Profile0]\nName=default\nIsRelative=1\nPath={tb}\n".encode()),
        (f".thunderbird/{tb}/logins.json", "Thunderbird's saved mail passwords", logins),
        (".config/discord/Local Storage/leveldb/000003.log", "Discord's login token", os.urandom(300)),
        (".local/share/TelegramDesktop/tdata/key_datas", "Telegram's session key", b"TDF$" + os.urandom(300)),
        (".bitcoin/wallet.dat", "a Bitcoin wallet", os.urandom(4096)),
        (".electrum/wallets/default_wallet", "an Electrum wallet", ('{"keystore":{"xprv":"%s"}}' % _b64(78)).encode()),
        (".config/Exodus/exodus.wallet/seed.seco", "an Exodus wallet's seed", os.urandom(512)),
        (".aws/credentials", "cloud credentials (AWS)",
         f"[default]\naws_access_key_id = AKIA{_hex(8).upper()}\naws_secret_access_key = {_b64(30)}\n".encode()),
        (".kube/config", "cluster credentials (Kubernetes)", f"apiVersion: v1\nusers:\n- name: {user}\n  user:\n    token: {_b64(40)}\n".encode()),
        (".netrc", "saved logins (.netrc)", f"machine {host} login {user} password {_b64(12)}\n".encode()),
        (".git-credentials", "saved Git logins", f"https://{user}:{_hex(20)}@{host}\n".encode()),
        (".bash_history", "the shell's history", f"ssh {user}@{host}\ncd Documents\nls\n".encode()),
        ("Documents/Passwords.txt", "a document named Passwords", f"bank: {_b64(9)}\nmail: {_b64(9)}\n".encode()),
        ("Documents/Passwords.kdbx", "a password database (KeePass)", bytes.fromhex("03d9a29a67fb4bb5") + os.urandom(700)),
        ("Documents/Tax return 2025.pdf", "a document", _pdf()),
        ("Documents/Bank statement.csv", "a document", b"date,description,amount\n2026-09-30,Salary,3120.00\n"),
        ("Pictures/IMG_2231.jpg", "a photo", _jpeg()),
        ("Desktop/notes.txt", "a note on the desktop", b"call the bank on Monday\n"),
    ]


def plant(home: Path) -> dict[str, str]:
    """Writes the decoys under `home` (a new, empty folder of the trial's) and returns what each is, by its
    path under the home; their folders are listed too ("the folder ~/.ssh"), so a program that only lists one
    is seen. Files 0600, folders 0700."""
    made: dict[str, str] = {}
    for rel, what, content in _files():
        path = home / rel
        for parent in reversed(path.relative_to(home).parents[:-1]):
            (home / parent).mkdir(mode=0o700, exist_ok=True)
        if callable(content):
            content(path)
            os.chmod(path, 0o600)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(content)
        made[rel] = what
    for rel in list(made):
        folder = str(Path(rel).parent)
        top = rel.split("/")[0]
        # not the folders every program uses (~/.config, ~/.local): being listed says nothing there
        if folder != "." and top.startswith(".") and top not in made and top not in (".config", ".local", ".cache"):
            made[top] = f"the folder ~/{top}"
    return made
