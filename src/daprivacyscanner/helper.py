"""DA Privacy Kit's privileged helper (docs/TECHNICAL.md, design rule 3).

Started through pkexec, so it runs as root after the user authorizes it; the app itself never
does. It exposes a few named actions and validates every argument itself: the unprivileged app
is not trusted to send only sensible requests. It never writes content the app sends: every
file it writes is generated here from validated settings, and every change it makes is
recorded in its own root-owned journal, so reverting means "put back what the journal holds"
rather than "write what the app says".

Self-contained on purpose: standard library only, no imports from the package, so it can run
as `python3 -I helper.py` (no user site-packages, no script directory on sys.path) and be
installed root-owned on its own.

Protocol: one JSON object per line on stdin, {"id": n, "action": "...", "args": {...}}; one
reply per line on stdout, {"id": n, "ok": true, "result": ...} or {"id": n, "ok": false,
"error": "..."}. stdin and stdout are one end of a socket pair the app holds the other end of: a
pipe's end can be opened again by any process of the same user through /proc/<app>/fd, a socket's
can't. A request line is at most MAX_REQUEST bytes. The helper exits at end of input, after
HELPER_IDLE seconds without a request (the app sends "keepalive" while long work holds the access),
and after HELPER_LIFETIME however it is used. {"action": "cancel", "args": {"id": n}} stops request
n while it runs (it answers "Stopped."); it is never answered itself.

Consent: one polkit prompt (pkexec's) starts the helper for a session of reads and reversible, journalled
changes. What can't be undone, what returns other accounts' data, installing or removing the helper, and a
revert that turns remote access back on (CONSENT, revert) ask polkit again, each time, for SENSITIVE_ACTION
(auth_admin, never kept), with pkcheck on the app's own process; declined, nothing is done. Started with
--install-only (privileged.install_helper: a copy that isn't installed yet), it does nothing but install or
remove itself, which that start's own prompt was for.

Journal: a change request may carry "change_id" (32 lowercase hex, never used before), which the journal
entry then has; without one the helper makes one. Before anything changes, the entry is written (state
"intent", what was there before), then marked "applied", or "failed" (with what was put back); every write is
fsynced, and its folder. Entries are the caller's (their uid is in each).

Detection (read-only):
    hello                      -> {"version", "uid", "mode"}
    keepalive                  -> {"alive": true}: nothing but a request, so the helper doesn't end for being idle
    list_changes               -> {"changes": [{"change_id", "state", "action", "time", "text"}]}: the caller's journal
    luks_dump   {device}       -> parsed `cryptsetup luksDump`: version, keyslots, tokens (no salts or digests)
    clevis_list {device}       -> [{"slot", "pin", "config"}] from `clevis luks list`
    read_file   {path}         -> {"text"} or {"missing": true}, for an allowlisted config file
    empty_password_accounts    -> account names whose /etc/shadow password field is empty (never hashes)
    sshd_settings              -> a few `sshd -T` values (passwordauthentication, permitrootlogin, ...)
    firewall_summary           -> counts of nftables tables and rules, and `ufw status` (never the rules)
    ufw_status                 -> `ufw status verbose` (which ports are allowed in; ufw's rules file is root-only)
    observe_traffic {seconds}  -> DNS names looked up (resolvectl monitor) and connections with their program
                                  (ss samples) for a few seconds: the online traffic test. Changes nothing.

Changes (each returns {"changed": bool, "change_id"}; the journal keeps what was there before):
    write_dropin {name, settings}   a config drop-in of the app's own, from DROPINS (settings null removes it)
    edit_config  {target, values}   targeted line edits in a distro config file, from EDITS
    set_service  {unit|units, enable, start}   systemctl enable/disable, start/stop, for SERVICES only (units together
                                    in one call; a change that fails part way is journalled first)
    set_sysctl   {key, value}       a live kernel setting, from SYSCTLS
    ufw_enable   {allow}            turn ufw on, first allowing the given ports, and ufw.service with it (boot)
    browser_policy {browser, settings}   enterprise policies, from POLICIES
    mount_tmpfs  {target, size_mb, noexec, until}   keep one of the calling user's folders (IN_MEMORY) in memory
                                    with a systemd mount unit of the helper's own
    enable_tmp_mount                link and enable the distribution's own tmp.mount (/usr/share/systemd), from
                                    the next boot
    opensnitch_rules {set}          OpenSnitch rule files of the app's own ("starter": the system's essentials
                                    allowed, phone-home hosts denied; "connectivity": the connectivity checks
                                    denied), generated here from fixed lists, then the daemon restarted

The RAM disk (a tool: mounted on demand, nothing journalled, nothing written to /etc; a reboot ends it):
    ramdisk_open  {size_mb, noexec, name} mount the calling user's ~/RAMDisk or ~/TempBrowser (tmpfs, noswap where the kernel has it)
    ramdisk_close {name}            unmount it (the app has overwritten its files first) and put the folder back

Swap for a session (for the browser in memory: nothing journalled, nothing in /etc; a reboot turns it on):
    swap_off                        turn off every swap that reaches a disk (not zram without writeback), if
                                    memory can take back what is in it; what was turned off is kept in /run
    swap_on                         turn those back on, with their priorities

The TRIM test (a tool: reads only, writes nothing; the run lives in this process):
    trim_begin   {mount}            start a run on /, the caller's home filesystem or another ext4 or btrfs
                                    filesystem they can write to: run ID, device, what its drives say about
                                    themselves
    trim_scan    {pass, offset, length}   read part of that device and count the run's records and names in it
                                    (counts and offsets only; nothing read leaves the helper)
    trim_result  {pass}             what a pass found
    trim_fstrim                     fstrim -v on the run's filesystem
    trim_end                        forget the run

Deleted file names (a tool: reads only, writes nothing; the names live in this process until names_end):
    names_begin  {mount}            start looking for names of deleted files on a filesystem the TRIM test may run
                                    on: the caller's own folders under their home on the home's filesystem, the
                                    folders the caller can open on another (ext4: the folders' blocks, then the
                                    journal's copies of folder blocks; btrfs: its tree blocks)
    names_step                      the next part of that
    names_result                    the names found whose files are gone, by folder (once)
    names_orphans                   ext4: the names in the journal's copies of folder blocks that are no listed
                                    folder's (folders that are gone, other accounts', the system's): only when the
                                    user asks for them
    names_journal_clear             ext4: has the kernel write the journal out and zero it (EXT4_IOC_CHECKPOINT),
                                    on the filesystem listed
    names_folder {path}             ext4: which of a listed folder's names its blocks still hold (between fillers)
    names_check  {paths}            ext4, after a clean-up: the listed names left in those folders, in the blocks
                                    they had when listed, and in the journal's copies of either
    names_fstrim {mount}            fstrim -v on a filesystem the names can be listed on
    names_end                       forget the names

What does this app keep? (a tool: reads only; what it sees lives in a child of this process until watch_end):
    watch_begin  {units}            start watching the files the caller's processes in those units (the scope an
                                    app was started in, under the caller's own user slice) open, change, create,
                                    delete and run, and which files the caller's other programs write meanwhile:
                                    fanotify on the filesystems holding the caller's home, the temporary folders
                                    and /; nothing of another account's is kept
    watch_poll                      how much it has seen (counts)
    watch_end                       end it and hand over what it saw, once

Retire a drive (a tool: reads only; erasing is done by the user's own commands, never here):
    erase_facts  {disk}             what a whole drive says about erasing itself: ATA security (supported,
                                    enabled, locked, frozen, enhanced erase, its time estimates), the Sanitize
                                    feature set, NVMe sanitize and format capabilities. Identify data only
Installing itself (for the AppImage, which has no source tree to run packaging/install-helper.sh from):
    install_self                    copy this running helper root-owned to INSTALLED, with its polkit action
    uninstall_self                  remove both again
    revert       {change_id, force} put a journalled change back; refuses if it was changed since, unless forced

Deleting (irreversible, the app confirms first):
    clear_crash_dumps               core dumps and crash reports in /var/lib/systemd/coredump and /var/crash
    vacuum_journal {time}           journalctl --vacuum-time
    clear_journal_files             the journal files left in /var/log/journal once journald keeps it in memory
    clear_syslog                    the text logs a syslog daemon wrote in /var/log (SYSLOG_FILES), once it is stopped
    clear_opensnitch_log            OpenSnitch's log emptied and its rotated copies deleted
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fnmatch
import hashlib
import json
import os
import pwd
import re
import select
import shlex
import stat
import struct as _struct
import subprocess
import sys
import time
import uuid

# Bumped whenever the actions or their arguments change: an installed (root-owned) copy from an
# older version is then refused with a clear message instead of failing on an unknown action. Also
# bumped when an action's answer is corrected, so an installed copy is named out of date and replaced.
PROTOCOL = 31
# Prefix for every path the helper writes or journals. Empty in use; tests point it at a fixture
# tree (and replace RUN), so nothing in the test suite touches the real system.
ROOT = ""
STATE_DIR = "/var/lib/daprivacyscanner"
CHANGES_DIR = "/var/lib/daprivacyscanner/changes"
RUN_DIR = "/run/daprivacyscanner"
# what was put back, or failed with nothing left changed: no copy of anything, so in /run (gone at a reboot), and the
# journal's own folders still go once nothing is left to put back
DONE_DIR = "/run/daprivacyscanner/done"
DONE_KEEP = 7 * 86400
# the helper's own folders, and the mode each is kept at (an older helper made some under the user's umask)
OWN_DIRS = {STATE_DIR: 0o700, CHANGES_DIR: 0o700, RUN_DIR: 0o755, DONE_DIR: 0o700,
            "/run/daprivacyscanner/ramdisk": 0o700}
MAX_FILE = 256 * 1024
COMMAND_TIMEOUT = 20
MAX_REQUEST = 4 << 20                          # one request line at most (names_check's 500 paths fit many times)
HELPER_IDLE = 6 * 60                           # seconds without a request before the helper ends (the app ends its own
                                               # access after 5 minutes unused, and sends keepalive while work holds it)
HELPER_LIFETIME = 12 * 3600                    # and at most this long, however it is used
MODE = "session"                               # "install": started only to install or remove itself (main)
# what polkit is asked for, each time, before what can't be undone or reaches beyond the caller's account
SENSITIVE_ACTION = "au.com.digitalarchon.daprivacyscanner.sensitive"
CONSENT_WAIT = 300                             # seconds the password prompt may stand
# Root-only (on some distros) config files that detection needs. Exact paths or fnmatch
# patterns; a path must also be itself (no symlink, no ..) to be read.
READABLE = (
    "/etc/crypttab",
    "/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf", "/etc/gdm/custom.conf",
    "/etc/sddm.conf", "/etc/sddm.conf.d/*.conf", "/usr/lib/sddm/sddm.conf.d/*.conf",
    "/etc/plasmalogin.conf", "/etc/plasmalogin.conf.d/*.conf", "/usr/lib/plasmalogin/defaults.conf",
    "/usr/lib/plasmalogin/plasmalogin.conf.d/*.conf",
    "/etc/lightdm/lightdm.conf", "/etc/lightdm/lightdm.conf.d/*.conf", "/usr/share/lightdm/lightdm.conf.d/*.conf",
    "/etc/greetd/config.toml", "/etc/lxdm/lxdm.conf",
    "/etc/cups/cupsd.conf", "/etc/snapper/configs/*", "/etc/doas.conf",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf",
    # the firmware's Secure Boot setting, where efivarfs lets only root read it
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
)
SSHD_KEYS = ("passwordauthentication", "permitrootlogin", "permitemptypasswords", "kbdinteractiveauthentication",
             "pubkeyauthentication", "port", "listenaddress")
_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._/-]+$")
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}


class Refused(Exception):
    """A request refused, or a change that failed. `data` goes into the answer beside the error: a change that failed
    part way, having changed something, is journalled first and its "change_id" sent, so the app records the attempt
    and can put it back (a failure that left a unit disabled with no History entry: Avahi on Mint)."""

    def __init__(self, message: str = "", data: dict | None = None):
        super().__init__(message)
        self.data = dict(data or {})


def readable(path: str) -> bool:
    """On the list: each path component matches the pattern's (a * never spans a /)."""
    parts = path.split("/")
    return any(len(parts) == len(pp) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(parts, pp))
               for pp in (p.split("/") for p in READABLE))


# ------------------------------------------------------------------ validation

def _block_device(device) -> str:
    if not isinstance(device, str) or not _DEVICE.match(device) or ".." in device.split("/"):
        raise Refused("not a device path")
    real = os.path.realpath(device)
    if not real.startswith("/dev/"):
        raise Refused("not a device path")
    try:
        if not stat.S_ISBLK(os.stat(real).st_mode):
            raise Refused("not a block device")
    except FileNotFoundError:
        raise Refused("no such device") from None
    return real


def _system(argv: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=COMMAND_TIMEOUT,
                           stdin=subprocess.DEVNULL, env=_ENV)
    except FileNotFoundError:
        return 127, "", f"{argv[0]} is not installed"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} timed out"
    return p.returncode, p.stdout, p.stderr


RUN = _system       # (argv) -> (returncode, stdout, stderr); tests replace it


def _run(argv: list[str]) -> str:
    code, out, err = RUN(argv)
    if code == 127:
        raise Refused(f"{argv[0]} is not installed")
    if code != 0:
        raise Refused(f"{argv[0]} failed: {(err or out).strip()[:200]}")
    return out


# What a request changed, for the app to show (History, and the result of a tool): every command it ran to
# make a change or put one back, as a shell would take it, in order. Reads (systemctl show, is-enabled) aren't
# listed. A setting written straight to its file is listed as the command that does the same (sysctl -w, mount,
# chmod). Emptied for each request (handle), which adds it to the answer as "ran".
DID: list[str] = []


def _did(argv: list[str]) -> None:
    DID.append(" ".join(shlex.quote(a) for a in argv))


def _do(argv: list[str]) -> str:
    """_run, listed in DID."""
    _did(argv)
    return _run(argv)


def _do_code(argv: list[str]) -> tuple[int, str, str]:
    """RUN, listed in DID."""
    _did(argv)
    return RUN(argv)


# ------------------------------------------------------------------ parsing

_ENTRY = re.compile(r"^\s+(\d+): (\S+)")
_LUKS1_SLOT = re.compile(r"^Key Slot (\d+): (ENABLED|DISABLED)")
_PROP = re.compile(r"^\s+([A-Za-z0-9 _-]+?):\s*(.*)$")


def parse_luks_dump(text: str) -> dict:
    """The parts of `cryptsetup luksDump` detection needs. Salts, digests and key material
    descriptions are left out."""
    out: dict = {"version": None, "keyslots": [], "tokens": [], "flags": None}
    section, entry = None, None
    for line in text.splitlines():
        m = re.match(r"^Version:\s*(\d+)", line)
        if m:
            out["version"] = int(m.group(1))
            continue
        m = re.match(r"^Flags:\s*(.*)$", line)                  # LUKS2's persistent activation flags
        if m:
            value = m.group(1).strip()
            out["flags"] = [] if value in ("", "(no flags)") else [f for f in value.split() if re.fullmatch(r"[a-z-]+", f)]
            continue
        m = _LUKS1_SLOT.match(line)
        if m:
            entry = None
            if m.group(2) == "ENABLED":
                out["keyslots"].append({"id": int(m.group(1)), "type": "luks1", "pbkdf": "pbkdf2"})
            continue
        if line and not line[0].isspace():
            section = line.rstrip(":").strip() if line.rstrip().endswith(":") else None
            entry = None
            continue
        m = _ENTRY.match(line)
        if m and section in ("Keyslots", "Tokens"):
            entry = {"id": int(m.group(1)), "type": m.group(2)}
            if section == "Keyslots":
                entry["pbkdf"] = None
                out["keyslots"].append(entry)
            else:
                entry["keyslots"] = []
                entry["tpm2_pin"] = None
                out["tokens"].append(entry)
            continue
        m = _PROP.match(line)
        if not (m and entry is not None):
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if section == "Keyslots" and key == "PBKDF":
            entry["pbkdf"] = value
        elif section == "Tokens" and key == "tpm2-pin":
            entry["tpm2_pin"] = value == "true"
        elif section == "Tokens" and key == "Keyslot":
            entry["keyslots"] += [int(x) for x in value.split() if x.isdigit()]
        elif section == "Tokens":
            # a token plugin (systemd's) printed what it knows: without one only Keyslot is, and no tpm2-pin line
            # then says nothing about a PIN
            entry["described"] = True
            if key in TOKEN_FLAGS:
                entry.setdefault("auth", {})[key] = value == "true"
    return out


# what a token's JSON says about how it unlocks, kept as booleans (never its key material): systemd's tpm2 and fido2
# tokens (systemd-cryptenroll), and whether Ubuntu's TPM-backed encryption (snapd's secboot, token ubuntu-fde) asks
# for a passphrase or PIN (its KeyData has passphrase_params or pin_params; secboot keydata.go, AuthMode)
TOKEN_FLAGS = ("tpm2-pin", "fido2-clientPin-required", "fido2-up-required", "fido2-uv-required")


def parse_luks_json(text: str, out: dict) -> dict:
    """Adds to parse_luks_dump's tokens what `cryptsetup luksDump --dump-json-metadata` says about each (LUKS2 only;
    cryptsetup 2.4+), which needs no token plugin: `auth` with TOKEN_FLAGS as booleans (tpm2-pin missing from a
    systemd-tpm2 token: enrolled before systemd 251, which had no PINs), and for ubuntu-fde tokens `ubuntu_auth`:
    "passphrase", "pin" or "none"."""
    try:
        tokens = json.loads(text).get("tokens") or {}
    except (ValueError, AttributeError):
        return out
    by_id = {t["id"]: t for t in out["tokens"]}
    for tid, tok in tokens.items() if isinstance(tokens, dict) else ():
        if not (isinstance(tok, dict) and str(tid).isdigit() and int(tid) in by_id):
            continue
        entry = by_id[int(tid)]
        flags = {k: tok[k] for k in TOKEN_FLAGS if isinstance(tok.get(k), bool)}
        if tok.get("type") == "systemd-tpm2":
            flags.setdefault("tpm2-pin", False)
            entry["tpm2_pin"] = flags["tpm2-pin"]
        entry["auth"] = {**entry.get("auth", {}), **flags}
        entry["described"] = True
        data = tok.get("ubuntu_fde_data")
        if tok.get("type") == "ubuntu-fde" and isinstance(data, dict):
            entry["ubuntu_auth"] = ("passphrase" if data.get("passphrase_params") else
                                    "pin" if data.get("pin_params") else "none")
    return out


_CLEVIS = re.compile(r"^(\d+): (\S+) '(.*)'$")


def parse_clevis_list(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _CLEVIS.match(line.strip())
        if m:
            out.append({"slot": int(m.group(1)), "pin": m.group(2), "config": m.group(3)[:500]})
    return out


# ------------------------------------------------------------------ actions

def hello(args: dict) -> dict:
    return {"version": PROTOCOL, "uid": os.geteuid(), "mode": MODE}


def keepalive(args: dict) -> dict:
    """Nothing but a request: the helper doesn't end for being idle while the app's long work holds the access
    (between the TRIM test's reads, a watch's polls)."""
    return {"alive": True}


def luks_dump(args: dict) -> dict:
    device = _block_device(args.get("device"))
    out = parse_luks_dump(_run(["cryptsetup", "luksDump", device]))
    if out["version"] == 2 and out["tokens"]:
        try:
            parse_luks_json(_run(["cryptsetup", "luksDump", "--dump-json-metadata", device]), out)
        except Refused:                     # cryptsetup before 2.4: the text dump is all there is
            pass
    return out


def clevis_list(args: dict) -> list[dict]:
    return parse_clevis_list(_run(["clevis", "luks", "list", "-d", _block_device(args.get("device"))]))


def read_file(args: dict) -> dict:
    path = args.get("path")
    if not isinstance(path, str) or not path.startswith("/") or not readable(path):
        raise Refused("that file is not on the helper's list")
    if os.path.realpath(path) != path:
        raise Refused("symlinks are not followed")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {"missing": True}
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused("not a regular file")
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise Refused("file too large")
    return {"text": data.decode("utf-8", errors="replace")}


def empty_password_accounts(args: dict) -> list[str]:
    out = []
    with open("/etc/shadow", encoding="utf-8", errors="replace") as f:
        for line in f:
            fields = line.rstrip("\n").split(":")
            if len(fields) >= 2 and fields[0] and fields[1] == "":
                out.append(fields[0])
    return out


def sshd_settings(args: dict) -> dict:
    out: dict[str, list[str]] = {}
    for line in _run(["sshd", "-T"]).splitlines():
        key, _, value = line.partition(" ")
        if key in SSHD_KEYS:
            out.setdefault(key, []).append(value.strip()[:100])
    return out


def nft_input_filters(ruleset: str) -> int:
    """Chains hooked on input that drop or reject (a drop policy, or drop/reject rules): what filters
    connections coming in. Docker, libvirt and Tailscale add NAT and forward rules that don't."""
    count, hooked, drops = 0, False, False
    for ln in ruleset.splitlines():
        s = ln.strip()
        if ln.startswith("\tchain "):
            hooked = drops = False
        elif ln.startswith("\t}"):
            count += hooked and drops
            hooked = drops = False
        elif ln.startswith("\t\t"):
            hooked |= bool(re.search(r"\bhook input\b", s))
            drops |= bool(re.search(r"\bpolicy drop\b|(^|\s)(drop|reject)\b", s))
    return count


def firewall_summary(args: dict) -> dict:
    out: dict = {}
    try:
        ruleset = _run(["nft", "list", "ruleset"])
        out["nft_tables"] = sum(1 for ln in ruleset.splitlines() if ln.startswith("table "))
        out["nft_rules"] = sum(1 for ln in ruleset.splitlines()
                               if ln.startswith("\t\t") and not ln.strip().startswith(("type ", "policy ", "}")))
        out["nft_input_filters"] = nft_input_filters(ruleset)
    except Refused as e:
        out["nft_error"] = str(e)
    try:
        out["ufw"] = _run(["ufw", "status"]).splitlines()[0].strip()[:60]
    except (Refused, IndexError):
        pass
    return out


# ------------------------------------------------------------------ changes: files

def _p(path: str) -> str:
    return ROOT + path


def _check_path(path: str) -> str:
    """The real path for a logical one (/etc/...), refusing symlinks anywhere on the way: a
    write must land exactly where the table says."""
    real = _p(path)
    if os.path.realpath(real) != os.path.normpath(real):
        raise Refused(f"{path} goes through a symlink")
    return real


def _owner() -> int:
    """Who the helper's own files and folders must belong to: root (in a fixture tree, the tests' own account)."""
    return os.geteuid() if ROOT else 0


def _read(path: str, trusted: bool = False) -> bytes | None:
    """A file's content (None when it isn't there), never through a link. `trusted`: one of the helper's own state
    files (its journal, what it turned off), which must be root's, writable by no one else and have one name: an
    older helper started under a user's umask 000 left its folders writable by every account, and an entry planted
    there would have been put back as root."""
    real = _check_path(path)
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise Refused(f"{path} is not a regular file")
        if trusted and (st.st_uid != _owner() or st.st_mode & 0o022 or st.st_nlink != 1):
            raise Refused(f"{path} isn't the helper's own (it must be root's, and writable by root alone)")
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise Refused(f"{path} is too large")
    return data


def _fsync_dir(real: str) -> None:
    try:
        fd = os.open(real, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _makedirs(path: str, mode: int = 0o755) -> list[str]:
    """The folders on the way to `path` (a logical path) that are missing, made one at a time with `mode` set on each
    (os.makedirs sets it on the last alone: the others got the umask's, 0777 under umask 000), never through a
    link. Returns the ones it made, outermost first."""
    made = []
    for d in _missing_dirs(path + "/x"):
        real = _p(d)
        try:
            os.mkdir(real, mode)
        except FileExistsError:
            pass
        else:
            made.append(d)
        st = os.lstat(real)
        if not stat.S_ISDIR(st.st_mode):
            raise Refused(f"{d} goes through a symlink" if stat.S_ISLNK(st.st_mode) else f"{d} isn't a folder")
        if d in made:
            os.chmod(real, mode)
    _check_path(path)
    return made


def _own_dir(path: str) -> str:
    """One of the helper's own folders (OWN_DIRS), there and as it must be: made with its mode where it is missing
    (and the helper's folders above it), and where it is there, root's (else refused: what it holds can't be trusted),
    never a link, its mode set again (an older helper made /var/lib/daprivacyscanner under the user's umask: 0775,
    or 0777 under umask 000). Returns its real path."""
    chain = [d for d in OWN_DIRS if path == d or path.startswith(d + "/")]
    for d in sorted(chain, key=len):
        parent = os.path.dirname(d)
        if not os.path.isdir(_p(parent)):
            _makedirs(parent, 0o755)
        real = _check_path(d)
        try:
            os.mkdir(real, OWN_DIRS[d])
        except FileExistsError:
            pass
        st = os.lstat(real)
        if not stat.S_ISDIR(st.st_mode):
            raise Refused(f"{d} isn't a folder")
        if st.st_uid != _owner():
            raise Refused(f"{d} isn't root's, so what it holds can't be trusted: remove it (sudo rm -r {d})")
        if stat.S_IMODE(st.st_mode) != OWN_DIRS[d]:
            os.chmod(real, OWN_DIRS[d])
    return _check_path(path)


def _write(path: str, data: bytes | None, mode: int = 0o644) -> None:
    """Atomically replace (or with None, remove) a file, keeping an existing file's mode and owner. What is written
    is on the disk when this returns (the file and its folder fsynced): a change journalled first must find its
    record there after a crash."""
    real = _check_path(path)
    parent = os.path.dirname(real)
    if data is None:
        try:
            os.unlink(real)
        except FileNotFoundError:
            return
        _fsync_dir(parent)
        return
    if not os.path.isdir(parent):
        _makedirs(os.path.dirname(path), 0o755)
    try:
        st = os.lstat(real)
        mode, owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
    except FileNotFoundError:
        owner = None
    tmp = os.path.join(parent, f".{os.path.basename(real)}.daprivacyscanner-{uuid.uuid4().hex[:8]}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            if owner is not None and os.geteuid() == 0:
                os.fchown(f.fileno(), *owner)
            os.fsync(f.fileno())
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(parent)


def _sha(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def _must_be_root() -> None:
    if not ROOT and os.geteuid() != 0:
        raise Refused("changes need root")


# ------------------------------------------------------------------ changes: the journal

_CHANGE_ID = re.compile(r"^[0-9a-f]{32}$")
# the requests that make a change the journal records: only these may carry the app's "change_id"
JOURNALLED = frozenset({"write_dropin", "edit_config", "set_service", "set_sysctl", "ufw_enable", "browser_policy",
                        "block_extensions", "mount_tmpfs", "enable_tmp_mount", "opensnitch_rules"})
REQUEST_ID: str | None = None                  # the change id the request in hand brought (handle), used once
ACTION = ""                                    # the request in hand's action, for its journal entry


def _caller_uid() -> int | None:
    """The calling user's uid where it is known (pkexec's PKEXEC_UID, or a test's CALLER), for the journal."""
    if CALLER is not None:
        return CALLER[0]
    try:
        return int(os.environ["PKEXEC_UID"])
    except (KeyError, ValueError):
        return None


def _change_known(change_id: str) -> bool:
    return any(os.path.lexists(_p(f"{d}/{change_id}.json")) for d in (CHANGES_DIR, DONE_DIR))


def _change_text(change: dict) -> str:
    """What a journal entry changed, in a line (list_changes): the files, units and settings, never their content."""
    parts = []
    if change.get("files"):
        parts.append("files " + ", ".join(f["path"] for f in change["files"]))
    services = change.get("services") or ([change["service"]] if change.get("service") else [])
    if services:
        parts.append("units " + ", ".join(s["unit"] for s in services))
    if change.get("sysctl"):
        parts.append(f"the kernel setting {change['sysctl']['key']}")
    if change.get("ufw"):
        parts.append("the firewall (ufw)")
    if change.get("mount_unit"):
        parts.append(f"{change['mount_unit']['path']} kept in memory")
    if change.get("linked_unit"):
        parts.append(f"{change['linked_unit']['unit']} enabled")
    return "; ".join(parts) or change.get("action", "")


def _journal_begin(change: dict) -> str:
    """The intent record, written (and fsynced) before anything is changed: what the request is about to do and what
    was there before, so a crash, a full disk or a limit on file sizes part way leaves a change that can be put back.
    Its id is the one the request brought (REQUEST_ID), else a new one."""
    global REQUEST_ID
    change_id, REQUEST_ID = REQUEST_ID or uuid.uuid4().hex, None
    change.update(id=change_id, created=time.time(), state="intent", action=ACTION, uid=_caller_uid())
    change["text"] = _change_text(change)
    _own_dir(CHANGES_DIR)
    _write(f"{CHANGES_DIR}/{change_id}.json", json.dumps(change).encode(), 0o600)
    return change_id


def _journal_save(change: dict, **fields) -> None:
    change.update(fields)
    change["text"] = _change_text(change)
    _write(f"{CHANGES_DIR}/{change['id']}.json", json.dumps(change).encode(), 0o600)


def _journal_forget(change: dict) -> None:
    """A record of what turned out to change nothing (a unit already so): gone, as if never made."""
    _write(f"{CHANGES_DIR}/{change['id']}.json", None)
    _rmdir_empty(CHANGES_DIR, STATE_DIR)


def _journal_close(change: dict, state: str, **fields) -> None:
    """A record with nothing left to put back ("reverted", or "failed" with everything put back): out of the journal,
    its folders removed once empty, and a line of it kept in /run (no copy of anything, gone at a reboot), so
    list_changes can still say what became of it."""
    _write(f"{CHANGES_DIR}/{change['id']}.json", None)
    _rmdir_empty(CHANGES_DIR, STATE_DIR)
    done = {"id": change["id"], "state": state, "action": change.get("action", ""), "uid": change.get("uid"),
            "created": change.get("created"), "time": time.time(), "text": change.get("text") or _change_text(change),
            **{k: v for k, v in fields.items() if k in ("failed",)}}
    try:
        _own_dir(DONE_DIR)
        _write(f"{DONE_DIR}/{change['id']}.json", json.dumps(done).encode(), 0o600)
        now = time.time()
        for name in os.listdir(_p(DONE_DIR)):
            m = re.fullmatch(r"([0-9a-f]{32})\.json", name)
            if m and m[1] != change["id"]:
                try:
                    old = json.loads(_read(f"{DONE_DIR}/{name}", trusted=True) or b"{}")
                    if now - float(old.get("time") or 0) > DONE_KEEP:
                        _write(f"{DONE_DIR}/{name}", None)
                except (Refused, OSError, ValueError, TypeError):
                    continue
    except (Refused, OSError):
        pass                                       # only list_changes' answer for it is lost


def _load_change(change_id) -> dict:
    if not isinstance(change_id, str) or not _CHANGE_ID.match(change_id):
        raise Refused("bad change id")
    data = _read(f"{CHANGES_DIR}/{change_id}.json", trusted=True)
    if data is None:
        raise Refused("that change isn't in the helper's journal (already reverted?)")
    _own_dir(CHANGES_DIR)                          # and its folders are root's alone
    change = json.loads(data)
    if not isinstance(change, dict) or change.get("id") != change_id:
        raise Refused("that change's record isn't one the helper wrote")
    return change


def list_changes(args: dict) -> dict:
    """The calling user's changes in the journal, and what became of those put back or failed lately: {"change_id",
    "state" (intent, applied, failed, reverted), "action", "time", "text"}. An app whose request timed out learns
    from it whether the change was made."""
    uid = _caller()[0]
    out = []
    for d in (CHANGES_DIR, DONE_DIR):
        try:
            names = sorted(os.listdir(_p(d)))
        except OSError:
            continue
        for name in names:
            m = re.fullmatch(r"([0-9a-f]{32})\.json", name)
            if not m:
                continue
            try:
                c = json.loads(_read(f"{d}/{name}", trusted=True) or b"{}")
            except (Refused, OSError, ValueError):
                continue
            if not isinstance(c, dict) or c.get("uid") != uid:
                continue
            out.append({"change_id": m[1], "state": c.get("state", "applied"), "action": c.get("action", ""),
                        "time": c.get("time") or c.get("created"), "text": c.get("text") or _change_text(c)})
    out.sort(key=lambda c: c["time"] or 0)
    return {"changes": out[-1000:]}


def _file_record(path: str, before: bytes | None, after: bytes | None) -> dict:
    return {"path": path, "before": None if before is None else base64.b64encode(before).decode(),
            "after_sha": _sha(after)}


# Commands run after a change and after reverting it, so the change takes effect. Named here,
# never sent by the app. "validate" runs first and undoes the write if it fails.
HOOKS = {
    "journald": {"run": [["systemctl", "restart", "systemd-journald.service"]]},
    "resolved": {"run": [["systemctl", "try-restart", "systemd-resolved.service"]]},
    "networkmanager": {"run": [["systemctl", "try-reload-or-restart", "NetworkManager.service"]]},
    "cups": {"run": [["systemctl", "try-restart", "cups.service"]]},
    "sshd": {"validate": ["sshd", "-t"],
             "run": [["systemctl", "try-reload-or-restart", "ssh.service"],
                     ["systemctl", "try-reload-or-restart", "sshd.service"]]},
    # the generator makes dev-zram0.swap from the config; reverting leaves zram on until the next boot
    # (turning swap off could run out of memory)
    "zram": {"run": [["systemctl", "daemon-reload"], ["systemctl", "start", "dev-zram0.swap"]],
             "revert_run": [["systemctl", "daemon-reload"]]},
    "logind": {"run": [["systemctl", "kill", "-s", "HUP", "systemd-logind.service"]]},       # logind.conf(5)
    "tmpfiles-wtmp": {"run": [["systemd-tmpfiles", "--create", "--prefix=/var/log/wtmp", "--prefix=/var/log/lastlog"]]},
    "daemon-reload": {"run": [["systemctl", "daemon-reload"]]},
    # OpenSnitch's daemon (opensnitchd.service upstream and on Arch, opensnitch.service on Debian and Ubuntu), only
    # if it runs: it reads its settings and rules when it starts
    "opensnitch": {"run": [["systemctl", "try-restart", "opensnitchd.service"],
                           ["systemctl", "try-restart", "opensnitch.service"]]},
}


def _hooks(names: list[str], reverting: bool = False) -> list[str]:
    """Runs each hook's commands; returns their failures (the change itself stands)."""
    problems = []
    for name in names:
        hook = HOOKS[name]
        for argv in hook.get("revert_run", hook.get("run", [])) if reverting else hook.get("run", []):
            code, out, err = _do_code(argv)
            if code not in (0, 5):                      # 5: unit not loaded (e.g. sshd.service on Debian)
                problems.append(f"{' '.join(argv)}: {(err or out).strip()[:120]}")
    return problems


def _validate(names: list[str]) -> str | None:
    for name in names:
        argv = HOOKS[name].get("validate")
        if argv:
            code, out, err = _do_code(argv)
            if code != 0:
                return (err or out).strip()[:200] or f"{argv[0]} failed"
    return None


def _missing_dirs(path: str) -> list[str]:
    """The folders on the way to `path` (a logical path) that aren't there yet, outermost first: what
    writing it creates, and what putting it back removes again."""
    out, d = [], os.path.dirname(path)
    while d not in ("", "/") and not os.path.lexists(_p(d)):
        out.append(d)
        d = os.path.dirname(d)
    return out[::-1]


def _listing(real: str, limit: int = 5) -> str:
    try:
        names = sorted(os.listdir(real))
    except OSError:
        return "it can't be listed"
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _unit_dirs() -> set[str]:
    """The folders in /etc/systemd/system (the .wants and .requires folders enabling a unit makes, and that
    disabling it leaves): compared before and after, they are the ones a change made."""
    base = "/etc/systemd/system"
    try:
        names = os.listdir(_p(base))
    except OSError:
        return set()
    return {f"{base}/{n}" for n in names if os.path.isdir(_p(f"{base}/{n}")) and not os.path.islink(_p(f"{base}/{n}"))}


def _journal_add_dirs(change_id: str, dirs: list[str], **fields) -> None:
    """Folders a change made after its journal entry was written (enabling its unit), added to it, with `fields`
    (its state once done)."""
    if dirs or fields:
        change = _load_change(change_id)
        if dirs:
            change["dirs"] = list(dict.fromkeys([*change.get("dirs", []), *dirs]))
        _journal_save(change, **fields)


def _rmdir_empty(*dirs: str) -> None:
    """The helper's own state folders, in order, removed while empty (the first that isn't stops it)."""
    for d in dirs:
        try:
            os.rmdir(_check_path(d))
        except (OSError, Refused):
            return


def _remove_dirs(dirs: list[str]) -> list[str]:
    """The folders a change created, removed again deepest first, each only while it is empty: a folder that
    holds anything added since (by a package, an admin, another program) stays, with everything in it, and
    the note says why. Never through a link, never anything but an empty folder. Returns the notes."""
    notes, kept = [], []
    for d in sorted(dict.fromkeys(dirs), key=lambda x: x.count("/"), reverse=True):
        if any(k.startswith(d + "/") for k in kept):
            kept.append(d)                        # holds a folder that stays: it stays too, said once
            continue
        real = _p(d)
        try:
            st = os.lstat(real)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(st.st_mode) or os.path.realpath(real) != os.path.normpath(real):
            notes.append(f"{d} was left as it is: it isn't the folder this change made any more")
            kept.append(d)
            continue
        try:
            os.rmdir(real)
            _did(["rmdir", d])
        except OSError as e:
            kept.append(d)
            if e.errno in (errno.ENOTEMPTY, errno.EEXIST):
                notes.append(f"{d} was left, with what is in it: this change made it, but it now holds what was "
                             f"added since ({_listing(real)})")
            else:
                notes.append(f"{d} was left: {e.strerror}")
    return notes


def _why(e: BaseException) -> str:
    return str(e) if isinstance(e, Refused) else getattr(e, "strerror", None) or type(e).__name__


def _apply_files(files: dict[str, bytes | None], hooks: list[str], extra: dict | None = None,
                 more: bool = False) -> dict:
    """Journals what is there now and what it will write (the intent record), then writes the files (path -> new
    content, None removes), with the folders writing them makes, validates and runs the hooks. Unchanged files are
    left alone. A failure puts back what was written; the record is then closed as failed, or kept (and its id sent)
    where something couldn't be put back. `more`: the caller has more to do, and marks the record applied itself."""
    befores = {p: _read(p) for p in files}
    changed = {p: new for p, new in files.items() if befores[p] != new}
    if not changed:
        return {"changed": False}
    dirs = list(dict.fromkeys(d for p, new in changed.items() if new is not None for d in _missing_dirs(p)))
    change = {"files": [_file_record(p, befores[p], new) for p, new in changed.items()], "hooks": hooks,
              **({"dirs": dirs} if dirs else {}), **(extra or {})}
    change_id = _journal_begin(change)
    for d in dirs:
        _did(["mkdir", d])                         # _write makes them, outermost first
    done = []
    try:
        for p, new in changed.items():
            _write(p, new)
            done.append(p)
        problem = _validate(hooks)
        if problem:
            raise Refused(f"the new configuration was rejected, so nothing was changed: {problem}")
    except BaseException as e:
        left = []
        for p in done:
            try:
                _write(p, befores[p])
            except (OSError, Refused):
                left.append(p)
        _remove_dirs(dirs)
        if left:
            _journal_save(change, state="failed", failed=_why(e))
            raise Refused(f"{_why(e)}; {', '.join(left)} couldn't be put back as it was (what it changed is recorded, "
                          "so it can be put back)", {"change_id": change_id}) from None
        _journal_close(change, "failed", failed=_why(e))
        raise
    if not more:
        _journal_save(change, state="applied")
    problems = _hooks(hooks)
    return {"changed": True, "change_id": change_id, "warnings": problems, "files": sorted(changed), "dirs": dirs}


# ------------------------------------------------------------------ drop-ins

def _keys(**allowed: str) -> dict[str, re.Pattern]:
    return {k.replace("__", "."): re.compile(v) for k, v in allowed.items()}


DOT_PROVIDERS = {
    "quad9": "9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net",
    "cloudflare": "1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com "
                  "2606:4700:4700::1001#cloudflare-dns.com",
    "mullvad": "194.242.2.2#dns.mullvad.net 2a07:e340::2#dns.mullvad.net",
}
_DOT_VALUES = "|".join(re.escape(v) for v in DOT_PROVIDERS.values())

# name -> (path, format, section, allowed keys and values, hooks). The app's own files: each is
# generated here from settings, so its content is always known.
DROPINS = {
    "coredump": ("/etc/systemd/coredump.conf.d/60-daprivacyscanner.conf", "ini", "Coredump",
                 _keys(Storage="none|external|journal", ProcessSizeMax="0|[1-9][0-9]{0,5}[KMG]?"), []),
    "journald": ("/etc/systemd/journald.conf.d/60-daprivacyscanner.conf", "ini", "Journal",
                 _keys(Storage="volatile|persistent|auto", MaxRetentionSec="[1-9][0-9]{0,2}(day|week|month)"),
                 ["journald"]),
    "resolved-dot": ("/etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf", "ini", "Resolve",
                     _keys(DNS=_DOT_VALUES, DNSOverTLS="yes|opportunistic", Domains="~\\."), ["resolved"]),
    "resolved-llmnr": ("/etc/systemd/resolved.conf.d/60-daprivacyscanner-llmnr.conf", "ini", "Resolve",
                       _keys(LLMNR="no|resolve", MulticastDNS="no|resolve"), ["resolved"]),
    "nm-connectivity": ("/etc/NetworkManager/conf.d/60-daprivacyscanner-connectivity.conf", "ini", "connectivity",
                        _keys(enabled="false"), ["networkmanager"]),
    "sleep": ("/etc/systemd/sleep.conf.d/60-daprivacyscanner.conf", "ini", "Sleep",
              _keys(AllowHibernation="no", AllowSuspendThenHibernate="no", AllowHybridSleep="no"), []),
    "sysctl": ("/etc/sysctl.d/60-daprivacyscanner.conf", "sysctl", None, _keys(kernel__yama__ptrace_scope="[12]"), []),
    "sysctl-dmesg": ("/etc/sysctl.d/60-daprivacyscanner-dmesg.conf", "sysctl", None, _keys(kernel__dmesg_restrict="1"), []),
    # sshd keeps the first value it reads; Debian/Ubuntu/Fedora include sshd_config.d before their
    # own settings, and a low number comes before cloud-init's 50-cloud-init.conf
    "sshd": ("/etc/ssh/sshd_config.d/10-daprivacyscanner.conf", "sshd", None,
             _keys(PasswordAuthentication="no", KbdInteractiveAuthentication="no", PermitRootLogin="no"), ["sshd"]),
    "apt-auto": ("/etc/apt/apt.conf.d/52daprivacyscanner-auto-upgrades", "apt", None,
                 _keys(**{"APT::Periodic::Update-Package-Lists": "1", "APT::Periodic::Unattended-Upgrade": "1"}), []),
    # NetworkManager's defaults for every connection, including those made later ("section:key"); a
    # name after the distribution's numbered files, so these win over theirs (Ubuntu and Mint turn
    # scan randomisation off in NetworkManager.conf, which conf.d overrides). A file read later wins
    # over every section of earlier files, driver-specific ones included (man NetworkManager.conf:
    # "sections from files that are read later have higher priority"), so the drivers the
    # distribution's own files exempt are exempted again in this file (_nm_mac_exceptions).
    "nm-mac": ("/etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf", "nm", None,
               _keys(**{"connection:wifi.cloned-mac-address": "stable|random", "device:wifi.scan-rand-mac-address": "yes"}),
               ["networkmanager"]),
    "nm-mac-ethernet": ("/etc/NetworkManager/conf.d/99-daprivacyscanner-mac-ethernet.conf", "nm", None,
                        _keys(**{"connection:ethernet.cloned-mac-address": "stable|random"}), ["networkmanager"]),
    # defaults for connections that don't set these themselves, those joined later included (NetworkManager.conf(5));
    # dhcp-send-hostname is read from here only by NetworkManager 1.52 and later (a connection's own value then shows -1)
    "nm-ipv6-privacy": ("/etc/NetworkManager/conf.d/99-daprivacyscanner-ipv6-privacy.conf", "nm", None,
                        _keys(**{"connection:ipv6.ip6-privacy": "2"}), ["networkmanager"]),
    "nm-hostname": ("/etc/NetworkManager/conf.d/99-daprivacyscanner-hostname.conf", "nm", None,
                    _keys(**{"connection:ipv4.dhcp-send-hostname": "0", "connection:ipv6.dhcp-send-hostname": "0"}),
                    ["networkmanager"]),
    # zram-generator's own file: only written when there is none (write_dropin checks), never with a
    # writeback device
    "zram": ("/etc/systemd/zram-generator.conf", "ini", "zram0", _keys(**{"zram-size": r"min\(ram / 2, 8192\)"}), ["zram"]),
    "logind-sleep": ("/etc/systemd/logind.conf.d/60-daprivacyscanner.conf", "ini", "Login",
                     _keys(HandleLidSwitch="suspend-then-hibernate", HandleSuspendKey="suspend-then-hibernate"), ["logind"]),
    "sleep-delay": ("/etc/systemd/sleep.conf.d/60-daprivacyscanner-delay.conf", "ini", "Sleep",
                    _keys(HibernateDelaySec="30min|[1-9]h|1[0-2]h"), []),
    # an earlier name than the distribution's var.conf: for the same path, the earliest file wins
    "tmpfiles-wtmp": ("/etc/tmpfiles.d/00-daprivacyscanner-wtmp.conf", "tmpfiles", None,
                      _keys(**{"/var/log/wtmp": "0660|0640", "/var/log/lastlog": "0660|0640"}), ["tmpfiles-wtmp"]),
    # the calling user's own service manager ({uid} from pkexec, never the request): what it starts
    # (GNOME's and Plasma's shells, and the apps they launch) gets this umask, from the next login
    "user-umask": ("/etc/systemd/system/user@{uid}.service.d/60-daprivacyscanner-umask.conf", "ini", "Service",
                   _keys(UMask="0027|0077"), ["daemon-reload"]),
    # GeoClue 2.7+ reads conf.d after geoclue.conf, later files winning: its online Wi-Fi lookup off
    "geoclue": ("/etc/geoclue/conf.d/90-daprivacyscanner.conf", "ini", "wifi", _keys(enable="false"), []),
    # DNF5 adjusts every repository's settings with the override files after reading the repository files, a section
    # name being a glob of repository ids (dnf5-config-manager(8): "Override files also support globs"; the last file
    # read wins): countme off for every repository, those added later too, with the repository files left as their
    # packages installed them (rpm keeps a package's new version of an edited one beside it, as .rpmnew)
    "dnf-countme": ("/etc/dnf/repos.override.d/60-daprivacyscanner-countme.repo", "ini", "*", _keys(countme="0"), []),
}
ZRAM_GENERATOR = "/usr/lib/systemd/system-generators/zram-generator"
DROPIN_HEADER = "# Written by DA Privacy Kit. Revert the fix in the app to remove it.\n"

# NetworkManager's configuration files, in the order it reads them (later ones win)
NM_CONF_FILES = ("/usr/lib/NetworkManager/conf.d/*.conf", "/run/NetworkManager/conf.d/*.conf",
                 "/etc/NetworkManager/NetworkManager.conf", "/etc/NetworkManager/conf.d/*.conf")
# upstream's own list of drivers that can't change their address (no-mac-addr-change.conf,
# https://bugzilla.gnome.org/show_bug.cgi?id=777523): always exempted, whatever this machine's files say
NM_NO_MAC_CHANGE = "driver:eagle_sdio,driver:wl"
_DEVICE_SPEC = re.compile(r"[A-Za-z0-9_.:,;*/+=!~ -]+")       # a match-device value, as the man page's forms


def _nm_mac_exceptions() -> str:
    """Sections that exempt the devices NetworkManager's own files say can't change their address
    (a [device-...] section with match-device and wifi.scan-rand-mac-address=no: Broadcom's wl,
    eagle_sdio), placed before the generic sections of the app's file. Within a file the first
    matching section wins and the generic one is considered last, so these drivers keep the
    hardware address: with the app's defaults they would fail to scan or to connect."""
    specs = [NM_NO_MAC_CHANGE]
    for pattern in NM_CONF_FILES:
        for path in _expand(pattern):
            if "daprivacyscanner" in path:
                continue
            try:
                data = _read(path)
            except Refused:
                continue
            if data is None:
                continue
            section, match, off = "", None, False
            for line in _lines(data) + ["[end]"]:
                s = line.strip()
                if s.startswith("["):
                    if section.startswith("device") and match and off and match not in specs:
                        specs.append(match)
                    section, match, off = s.strip("[]").strip(), None, False
                    continue
                key, _, value = s.partition("=")
                key, value = key.strip(), value.strip()
                if key == "match-device" and _DEVICE_SPEC.fullmatch(value):
                    match = value
                elif key == "wifi.scan-rand-mac-address" and value.lower() in ("no", "false", "0"):
                    off = True
    out = ["# Drivers that can't change their address (NetworkManager's own list, and this machine's files)\n"
           "# keep the hardware one: the first matching section wins, and [device] and [connection] come last.\n"]
    for i, spec in enumerate(specs, 1):
        out.append(f"[device-daprivacyscanner-{i}]\nmatch-device={spec}\nwifi.scan-rand-mac-address=no\n\n"
                   f"[connection-daprivacyscanner-{i}]\nmatch-device={spec}\nwifi.cloned-mac-address=preserve\n\n")
    return "".join(out)


def _render(fmt: str, section: str | None, settings: dict[str, str]) -> bytes:
    if fmt == "ini":
        body = f"[{section}]\n" + "".join(f"{k}={v}\n" for k, v in settings.items())
    elif fmt == "sysctl":
        body = "".join(f"{k} = {v}\n" for k, v in settings.items())
    elif fmt == "sshd":
        body = "".join(f"{k} {v}\n" for k, v in settings.items())
    elif fmt == "nm":                                                # "section:key" -> [section] key=value
        sections: dict[str, list[str]] = {}
        for k, v in settings.items():
            sec, _, key = k.partition(":")
            sections.setdefault(sec, []).append(f"{key}={v}\n")
        body = "".join(f"[{sec}]\n" + "".join(lines) for sec, lines in sections.items())
    elif fmt == "tmpfiles":                                          # path -> mode of a file kept as root:utmp
        body = "".join(f"f {k} {v} root utmp -\n" for k, v in settings.items())
    else:                                                            # apt
        body = "".join(f'{k} "{v}";\n' for k, v in settings.items())
    return (DROPIN_HEADER + body).encode()


def write_dropin(args: dict) -> dict:
    _must_be_root()
    name, settings = args.get("name"), args.get("settings")
    if name not in DROPINS:
        raise Refused("unknown drop-in")
    path, fmt, section, allowed, hooks = DROPINS[name]
    if "{uid}" in path:
        path = path.format(uid=_caller()[0])
    if settings is not None:
        if not isinstance(settings, dict) or not settings:
            raise Refused("bad settings")
        for k, v in settings.items():
            if k not in allowed or not isinstance(v, str) or not allowed[k].fullmatch(v):
                raise Refused(f"{k}={v!r} isn't allowed in this drop-in")
    if name == "sshd":
        main = (_read("/etc/ssh/sshd_config") or b"").decode("utf-8", "replace")
        if not re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf", main, re.M | re.I):
            raise Refused("sshd_config doesn't read /etc/ssh/sshd_config.d, so a drop-in would have no effect")
    if name == "geoclue" and settings is not None and not os.path.isdir(_p("/etc/geoclue/conf.d")):
        raise Refused("this GeoClue doesn't read /etc/geoclue/conf.d, so a drop-in would have no effect")
    if name == "dnf-countme" and settings is not None and not os.path.exists(_p("/usr/bin/dnf5")):
        raise Refused("DNF5 isn't installed: only it reads /etc/dnf/repos.override.d, so the file would have no effect")
    if name == "zram" and settings is not None:
        if not os.path.exists(_p(ZRAM_GENERATOR)):
            raise Refused("zram-generator isn't installed")
        old = _read(path)
        if old is not None and not old.startswith(DROPIN_HEADER.encode()):
            raise Refused(f"{path} already exists: it is someone else's configuration")
    return _apply_files({path: dropin_content(name, settings)}, hooks)


def dropin_content(name: str, settings: dict[str, str] | None) -> bytes | None:
    """What write_dropin writes into the drop-in `name` (None: it removes it). Settings already checked."""
    path, fmt, section, _, _ = DROPINS[name]
    content = None if settings is None else _render(fmt, section, settings)
    if name == "nm-mac" and content is not None:
        content = DROPIN_HEADER.encode() + _nm_mac_exceptions().encode() + content[len(DROPIN_HEADER):]
    return content


# ------------------------------------------------------------------ line edits in distro files

def _lines(data: bytes) -> list[str]:
    return data.decode("utf-8", "surrogateescape").split("\n")


def _join(lines: list[str]) -> bytes:
    return "\n".join(lines).encode("utf-8", "surrogateescape")


def _comment_out(pattern: str, section: str | None = None):
    """Comments out lines matching `pattern` (inside [section] only, when given)."""
    rx = re.compile(pattern, re.I)

    def edit(lines: list[str], values: dict) -> list[str]:
        out, current = [], None
        for line in lines:
            m = re.match(r"^\s*\[([^\]]+)\]", line)
            if m:
                current = m.group(1)
            if rx.match(line) and (section is None or current == section):
                line = "#" + line
            out.append(line)
        return out
    return edit


def _replace(pattern: str, new: str):
    rx = re.compile(pattern, re.I)
    return lambda lines, values: [new if rx.match(line) else line for line in lines]


def _in_section(section: str, pattern: str, new: str):
    """Replaces the lines matching `pattern` inside [section] only."""
    rx = re.compile(pattern, re.I)

    def edit(lines: list[str], values: dict) -> list[str]:
        out, current = [], None
        for line in lines:
            m = re.match(r"^\s*\[([^\]]+)\]", line)
            if m:
                current = m.group(1).strip()
            out.append(new if current == section and rx.match(line) else line)
        return out
    return edit


def _cups(lines: list[str], values: dict) -> list[str]:
    out = list(lines)
    for key, value in values.items():
        depth, found = 0, False
        for i, line in enumerate(out):
            s = line.strip()
            if s.startswith("</"):
                depth -= 1
            elif s.startswith("<"):
                depth += 1
            elif depth == 0 and re.match(rf"^{key}\s", s, re.I):
                out[i] = f"{key} {value}"
                found = True
                break
        if not found:
            if out and out[-1] == "":
                out.insert(len(out) - 1, f"{key} {value}")
            else:
                out.append(f"{key} {value}")
    return out


# what snapper keeps for a key its config leaves out (snapper-configs(5)), and Timeshift for a count its
# timeshift.json leaves out (the default.json it ships)
SNAPPER_DEFAULTS = {"NUMBER_LIMIT": "50", "NUMBER_LIMIT_IMPORTANT": "10", "TIMELINE_CREATE": "yes",
                    "TIMELINE_LIMIT_HOURLY": "10", "TIMELINE_LIMIT_DAILY": "10", "TIMELINE_LIMIT_WEEKLY": "0",
                    "TIMELINE_LIMIT_MONTHLY": "10", "TIMELINE_LIMIT_QUARTERLY": "0", "TIMELINE_LIMIT_YEARLY": "10"}
TIMESHIFT_DEFAULTS = {"count_hourly": "6", "count_daily": "5", "count_weekly": "3", "count_monthly": "2",
                      "count_boot": "5"}


def lowered(target: str, now: dict, values: dict) -> dict:
    """The values of a snapper or Timeshift edit that keep fewer snapshots than a config does now (`now`, its values; a
    key it leaves out has the program's default): the only ones the edit writes, so a limit already lower is never
    raised (a home config keeping 5 update snapshots was set to 10). A count is compared by its top ("2-10" keeps up
    to 10; one that isn't a count is replaced); "no" and "false" are lower than anything else, and "yes" and "true"
    are never written."""
    defaults = SNAPPER_DEFAULTS if target == "snapper" else TIMESHIFT_DEFAULTS

    def top(v) -> int | None:
        m = re.fullmatch(r"\s*(?:[0-9]+-)?([0-9]+)\s*", str(v))
        return int(m.group(1)) if m else None
    out = {}
    for key, value in values.items():
        was = now.get(key, defaults.get(key))
        if value in ("no", "false"):
            lower = was is None or str(was).strip().lower() not in ("no", "false")
        else:
            lower = value not in ("yes", "true") and (was is None or top(was) is None or top(value) < top(was))
        if lower:
            out[key] = value
    return out


def _assign(lines: list[str], values: dict) -> list[str]:
    """Shell-style KEY="value" lines (snapper's configs): each key set where it is, or added, where that keeps fewer
    snapshots (`lowered`)."""
    now = {}
    for line in lines:
        m = re.match(r'^\s*([A-Z_]+)\s*=\s*"?([^"\n]*)"?', line)
        if m:
            now[m.group(1)] = m.group(2)
    out = list(lines)
    for key, value in lowered("snapper", now, values).items():
        for i, line in enumerate(out):
            if re.match(rf"^\s*{key}\s*=", line):
                out[i] = f'{key}="{value}"'
                break
        else:
            out.insert(len(out) - 1 if out and out[-1] == "" else len(out), f'{key}="{value}"')
    return out


def _json_keys(lines: list[str], values: dict) -> list[str]:
    """Top-level string values of a JSON object (Timeshift's timeshift.json keeps every value as a
    string), where that keeps fewer snapshots (`lowered`); a file that isn't a JSON object, or where
    nothing would be lower, is left as it is."""
    try:
        data = json.loads("\n".join(lines))
    except ValueError:
        return lines
    lower = lowered("timeshift", data, values) if isinstance(data, dict) else {}
    if not lower:
        return lines
    data.update(lower)
    return (json.dumps(data, indent=2) + "\n").split("\n")


_LIGHTDM_AUTOLOGIN = r"^\s*autologin-(user\s*=\s*\S|guest\s*=\s*(true|yes|1)\b)"
_DM = {
    "/etc/lightdm/lightdm.conf": _comment_out(_LIGHTDM_AUTOLOGIN),
    "/etc/lightdm/lightdm.conf.d/*.conf": _comment_out(_LIGHTDM_AUTOLOGIN),
    "/etc/gdm3/custom.conf": _comment_out(r"^\s*(AutomaticLoginEnable|TimedLoginEnable)\s*=\s*(true|1|yes)\b"),
    "/etc/gdm3/daemon.conf": _comment_out(r"^\s*(AutomaticLoginEnable|TimedLoginEnable)\s*=\s*(true|1|yes)\b"),
    "/etc/gdm/custom.conf": _comment_out(r"^\s*(AutomaticLoginEnable|TimedLoginEnable)\s*=\s*(true|1|yes)\b"),
    "/etc/sddm.conf": _comment_out(r"^\s*User\s*=\s*\S", "Autologin"),
    "/etc/sddm.conf.d/*.conf": _comment_out(r"^\s*User\s*=\s*\S", "Autologin"),
    "/etc/plasmalogin.conf": _comment_out(r"^\s*User\s*=\s*\S", "Autologin"),
    "/etc/plasmalogin.conf.d/*.conf": _comment_out(r"^\s*User\s*=\s*\S", "Autologin"),
    "/etc/lxdm/lxdm.conf": _comment_out(r"^\s*autologin\s*=\s*\S", "base"),
}

# Packaged files the display managers read before /etc (which the edits above can't touch): when
# one sets automatic login, a file of the app's own, read after it, sets the user to none.
# SDDM reads /usr/lib/sddm/sddm.conf.d, then /etc/sddm.conf.d, then /etc/sddm.conf (Plasma Login Manager, its fork,
# /usr/lib/plasmalogin's defaults.conf and plasmalogin.conf.d, then /etc's); LightDM reads
# /usr/share/lightdm/lightdm.conf.d, then /etc/lightdm/lightdm.conf.d, then lightdm.conf; in both
# a later file's value replaces an earlier one's, and an empty user means no automatic login.
# (packaged file pattern, section prefix, line pattern) -> (override file, its content)
_AUTOLOGIN_OVERRIDES = {
    ("/usr/lib/sddm/sddm.conf.d/*.conf", "Autologin", r"^\s*User\s*=\s*\S"):
        ("/etc/sddm.conf.d/99-daprivacyscanner-autologin.conf", "[Autologin]\nUser=\n"),
    ("/usr/lib/plasmalogin/defaults.conf", "Autologin", r"^\s*User\s*=\s*\S"):
        ("/etc/plasmalogin.conf.d/99-daprivacyscanner-autologin.conf", "[Autologin]\nUser=\n"),
    ("/usr/lib/plasmalogin/plasmalogin.conf.d/*.conf", "Autologin", r"^\s*User\s*=\s*\S"):
        ("/etc/plasmalogin.conf.d/99-daprivacyscanner-autologin.conf", "[Autologin]\nUser=\n"),
    ("/usr/share/lightdm/lightdm.conf.d/*.conf", "Seat", _LIGHTDM_AUTOLOGIN):
        ("/etc/lightdm/lightdm.conf.d/99-daprivacyscanner-autologin.conf", "[Seat:*]\nautologin-user=\nautologin-guest=false\n"),
}


def _sets(data: bytes, section_prefix: str, pattern: str) -> bool:
    """Whether a file has a line matching `pattern` in a section whose name starts with the prefix."""
    rx, current = re.compile(pattern, re.I), None
    for line in _lines(data):
        m = re.match(r"^\s*\[([^\]]+)\]", line)
        if m:
            current = m.group(1)
        elif rx.match(line) and current is not None and current.startswith(section_prefix):
            return True
    return False


def _autologin_overrides() -> dict[str, bytes]:
    out = {}
    for (pattern, prefix, line_rx), (override, content) in _AUTOLOGIN_OVERRIDES.items():
        for path in _expand(pattern):
            try:
                data = _read(path)
            except Refused:
                continue
            if data is not None and _sets(data, prefix, line_rx):
                out[override] = (DROPIN_HEADER + content).encode()
                break
    return out

# target -> (file patterns -> edit function, allowed values, hooks)
_SNAP_COUNT = "[0-9]{1,3}(-[0-9]{1,3})?"
EDITS = {
    "countme": ({"/etc/yum.repos.d/*.repo": _replace(r"^\s*countme\s*=\s*(1|true|yes|on)\s*$", "countme=0"),
                 "/etc/dnf/dnf.conf": _replace(r"^\s*countme\s*=\s*(1|true|yes|on)\s*$", "countme=0")}, {}, []),
    "autologin": (_DM, {}, []),
    "cups": ({"/etc/cups/cupsd.conf": _cups},
             _keys(PreserveJobFiles="No|Yes|[1-9][0-9]{0,6}[mhdw]?", PreserveJobHistory="No|Yes|[1-9][0-9]{0,6}[mhdw]?"),
             ["cups"]),
    # GeoClue before 2.7, which reads no drop-ins: its online Wi-Fi lookup off in its own file
    "geoclue": ({"/etc/geoclue/geoclue.conf": _in_section("wifi", r"^\s*enable\s*=\s*(true|1|yes)\s*$", "enable=false")},
                {}, []),
    "apport": ({"/etc/default/apport": _replace(r"^\s*enabled\s*=\s*1\s*$", "enabled=0")}, {}, []),
    "motd-news": ({"/etc/default/motd-news": _replace(r"^\s*ENABLED\s*=\s*1\s*$", "ENABLED=0")}, {}, []),
    "popcon": ({"/etc/popularity-contest.conf": _replace(r'^\s*PARTICIPATE\s*=\s*"?yes"?\s*$', 'PARTICIPATE="no"')},
               {}, []),
    # the mode logrotate gives a new wtmp (Debian and Ubuntu keep the rule in logrotate.d/wtmp, older
    # releases in logrotate.conf); only lines creating a file for the utmp group are touched
    "logrotate-wtmp": ({"/etc/logrotate.d/wtmp": _replace(r"^\s*create\s+0?664\s+root\s+utmp\s*$", "    create 0660 root utmp"),
                        "/etc/logrotate.conf": _replace(r"^\s*create\s+0?664\s+root\s+utmp\s*$", "    create 0660 root utmp")},
                       {}, []),
    # how many snapshots snapper keeps, in every config it has (applied by its daily clean-up, or
    # at once by snapper_cleanup)
    "snapper": ({"/etc/snapper/configs/*": _assign},
                _keys(NUMBER_LIMIT=_SNAP_COUNT, NUMBER_LIMIT_IMPORTANT=_SNAP_COUNT, TIMELINE_CREATE="yes|no",
                      TIMELINE_LIMIT_HOURLY=_SNAP_COUNT, TIMELINE_LIMIT_DAILY=_SNAP_COUNT, TIMELINE_LIMIT_WEEKLY=_SNAP_COUNT,
                      TIMELINE_LIMIT_MONTHLY=_SNAP_COUNT, TIMELINE_LIMIT_QUARTERLY=_SNAP_COUNT,
                      TIMELINE_LIMIT_YEARLY=_SNAP_COUNT), []),
    # Timeshift's schedule, how many of each kind it keeps, and whether it snapshots @home
    "timeshift": ({"/etc/timeshift/timeshift.json": _json_keys},
                  _keys(count_hourly="[0-9]{1,2}", count_daily="[0-9]{1,2}", count_weekly="[0-9]{1,2}",
                        count_monthly="[0-9]{1,2}", count_boot="[0-9]{1,2}", schedule_hourly="true|false",
                        schedule_daily="true|false", schedule_weekly="true|false", schedule_monthly="true|false",
                        schedule_boot="true|false", include_btrfs_home_for_backup="true|false"), []),
}


def _expand(pattern: str) -> list[str]:
    if "*" not in pattern:
        return [pattern]
    d, _, glob_part = pattern.rpartition("/")
    real = _p(d)
    try:
        names = sorted(os.listdir(real))
    except OSError:
        return []
    return [f"{d}/{n}" for n in names if fnmatch.fnmatchcase(n, glob_part) and not os.path.islink(os.path.join(real, n))]


def edit_config(args: dict) -> dict:
    _must_be_root()
    target, values = args.get("target"), args.get("values") or {}
    if target not in EDITS:
        raise Refused("unknown config target")
    patterns, allowed, hooks = EDITS[target]
    if not isinstance(values, dict) or any(k not in allowed or not isinstance(v, str) or not allowed[k].fullmatch(v)
                                           for k, v in values.items()):
        raise Refused("those values aren't allowed")
    files: dict[str, bytes | None] = {}
    for pattern, edit in patterns.items():
        for path in _expand(pattern):
            data = _read(path)
            if data is None:
                continue
            new = _join(edit(_lines(data), values))
            if new != data:
                files[path] = new
    if target == "autologin":
        for path, content in _autologin_overrides().items():
            if _read(path) != content:
                files[path] = content
    if not files:
        return {"changed": False}
    result = _apply_files(files, hooks)
    result["files"] = sorted(files)
    return result


# ------------------------------------------------------------------ services

# Each unit the app turns on or off, and only the way it does (enable, start, mask): what its guides offer
# (checks/guides: service_off turns units off, mask for Avahi, which cups-browsed starts again; the firewall, OpenSnitch,
# the weekly TRIM timer and /tmp in memory are turned on). A remote-access service is never turned on here, nor a
# firewall off: a revert puts back what the journal recorded, asking again for a remote-access one (_revert_consent).
_OFF = frozenset({(False, False, False)})
_OFF_MASK = _OFF | {(False, False, True)}
_ON = frozenset({(True, True, False)})
SERVICES = {
    **dict.fromkeys(("ssh.service", "ssh.socket", "sshd.service", "xrdp.service", "xrdp-sesman.service",
                     "smbd.service", "nmbd.service", "rpcbind.service", "rpcbind.socket", "cockpit.socket",
                     "teamviewerd.service", "anydesk.service", "rustdesk.service",
                     "apport.service", "whoopsie.service", "whoopsie.path", "abrtd.service", "abrt-journal-core.service",
                     "abrt-oops.service", "abrt-xorg.service", "abrt-vmcore.service",
                     "rsyslog.service", "syslog-ng.service", "syslog-ng@default.service", "motd-news.timer"), _OFF),
    "avahi-daemon.service": _OFF_MASK, "avahi-daemon.socket": _OFF_MASK,
    "firewalld.service": _ON, "fstrim.timer": _ON, "opensnitchd.service": _ON, "opensnitch.service": _ON,
    "tmp.mount": frozenset({(True, None, False)}),          # from the next boot: mounting over /tmp now hides its files
}
# what lets someone reach this computer from elsewhere: turned on again only by a revert, and only after the password
# is asked for again (the guides turn them off)
REMOTE_ACCESS = frozenset({"ssh.service", "ssh.socket", "sshd.service", "xrdp.service", "xrdp-sesman.service",
                           "smbd.service", "nmbd.service", "cockpit.socket", "teamviewerd.service", "anydesk.service",
                           "rustdesk.service"})


def _unit_state(unit: str) -> tuple[str, str]:
    code, out, _ = RUN(["systemctl", "show", "--property=LoadState", "--value", unit])
    if code != 0 or out.strip() in ("", "not-found"):
        raise Refused(f"{unit} isn't installed")
    _, enabled, _ = RUN(["systemctl", "is-enabled", unit])
    _, active, _ = RUN(["systemctl", "is-active", unit])
    return enabled.strip().splitlines()[0] if enabled.strip() else "unknown", active.strip() or "unknown"


def _set_units(want: dict[str, tuple[bool | None, bool | None]], now: dict[str, tuple[str, str]]) -> None:
    """Each unit to (enabled?, running?), None for leave as it is, in as few systemctl calls as it takes: units turned
    off together are disabled and stopped in one call (`disable --now`), and turned on together in one (`enable
    --now`). Avahi on Mint shows why: its socket stopped on its own, avahi-daemon.service, still enabled, was started
    again on demand over D-Bus by cups-browsed, which cancelled the socket's stop job. Disabling the service removes the
    name D-Bus starts it by (its dbus-org.freedesktop.Avahi.service alias), and both then stop in the same call."""
    units = list(want)
    for on in (False, True):
        flip = [u for u in units if want[u][0] is on and now[u][0] in ("enabled", "disabled")
                and (now[u][0] == "enabled") != on]
        together = bool(flip) and all(want[u][1] is on for u in flip)
        if flip:
            _do(["systemctl", "enable" if on else "disable", *(["--now"] if together else []), *flip])
        if together:
            now = {**now, **{u: (now[u][0], "active" if on else "inactive") for u in flip}}
    for on in (False, True):
        run = [u for u in units if want[u][1] is on and (now[u][1] == "active") != on]
        if run:
            _do(["systemctl", "start" if on else "stop", *run])


def _set_unit(unit: str, enable: bool | None, start: bool | None, now: tuple[str, str]) -> None:
    _set_units({unit: (enable, start)}, {unit: now})


# what a unit's enablement says when it can't be turned on here: set_service refuses, saying why, rather than run a
# systemctl that fails part way (or does nothing and reports "already so")
CANT_ENABLE = {
    "masked": "it is masked (switched off for good with systemctl mask): undo that first, with sudo systemctl unmask {u}",
    "masked-runtime": "it is masked until the next restart (systemctl mask --runtime)",
    "static": "it is static: it has no [Install] section, so it can't be enabled, and starts only when another unit "
              "or a socket needs it",
    "generated": "it is generated at boot from another file (such as /etc/fstab), so it can't be enabled here",
    "transient": "it was made for this boot only, so it can't be enabled",
    "bad": "its unit file can't be read",
}


def set_service(args: dict) -> dict:
    """{"unit"} or {"units"} (up to 4, turned on or off together), "enable", "start": True, False or None (leave).
    A change that fails part way (one unit disabled, the stop cancelled) is journalled before the error goes back, so
    it is recorded and can be put back."""
    _must_be_root()
    units, enable, start = args.get("units", [args.get("unit")]), args.get("enable"), args.get("start")
    # mask: turned off for good, so that nothing starts them again (cups-browsed's Wants=avahi-daemon.service started
    # a disabled Avahi at every boot, and at every restart of cups-browsed: Mint 22.3)
    mask = args.get("mask", False)
    if not isinstance(units, list) or not 1 <= len(units) <= 4 or not all(isinstance(u, str) for u in units) or \
            len(set(units)) != len(units) or any(u not in SERVICES for u in units):
        raise Refused("that unit isn't on the helper's list")
    if enable not in (True, False, None) or start not in (True, False, None) or (enable is None and start is None) or \
            mask not in (True, False) or (mask and (enable is not False or start is not False)):
        raise Refused("bad request")
    for u in units:
        if (enable, start, mask) not in SERVICES[u]:
            raise Refused(f"the helper doesn't turn {u} {'on' if enable or start else 'off'} that way")
    before = {u: _unit_state(u) for u in units}
    for u in units:
        why = CANT_ENABLE.get(before[u][0]) if enable is True or (start is True and before[u][0].startswith("masked")) \
            else None
        if why:
            raise Refused(f"{u} can't be turned on: " + why.format(u=u))
    had = _unit_dirs()
    want = "masked" if mask else "enabled" if enable else "disabled"
    change = {"services": [{"unit": u, "before": before[u],
                            "after": [want if enable is not None else before[u][0],
                                      ("active" if start else "inactive") if start is not None else before[u][1]]}
                           for u in units]}
    _journal_begin(change)
    try:
        _set_units({u: (enable, start) for u in units}, before)
        if mask:
            _do(["systemctl", "mask", *[u for u in units if not before[u][0].startswith("masked")]])
        # what systemctl answered isn't what happened: stopped alone, avahi-daemon.socket was started again at once
        # by D-Bus activation and systemctl still answered 0 (Mint 22.3, systemd 255). The states decide.
        now = {u: _unit_state(u) for u in units}
        for u in units:
            if start is False and now[u][1] == "active":
                raise Refused(f"{u} was started again at once, by something that asked for it")
            if start is True and now[u][1] != "active":
                raise Refused(f"{u} didn't stay running (systemctl status {u} says why)")
            if enable is not None and (before[u][0] in ("enabled", "disabled") or mask) and now[u][0] != want:
                raise Refused(f"{u} is {now[u][0]} now, not {want}")
    except Refused as e:
        try:
            after = {u: _unit_state(u) for u in units}
        except Refused:
            after = before
        if after == before:
            _journal_close(change, "failed", failed=str(e))
            raise
        made = sorted(_unit_dirs() - had)
        _journal_save(change, services=[{"unit": u, "before": before[u], "after": after[u]} for u in units],
                      state="failed", failed=str(e), **({"dirs": made} if made else {}))
        raise Refused(f"{e} (what it had changed by then is recorded, so it can be put back)",
                      {"change_id": change["id"]}) from None
    after = {u: _unit_state(u) for u in units}
    if after == before:
        _journal_forget(change)
        return {"changed": False}
    made = sorted(_unit_dirs() - had)
    _journal_save(change, services=[{"unit": u, "before": before[u], "after": after[u]} for u in units],
                  state="applied", **({"dirs": made} if made else {}))
    return {"changed": True, "change_id": change["id"], "warnings": [], "dirs": made}


# ------------------------------------------------------------------ sysctl

SYSCTLS = {"kernel.yama.ptrace_scope": re.compile("[12]"),     # 3 can't be lowered again without a reboot
           "kernel.dmesg_restrict": re.compile("1")}


def _sysctl_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def set_sysctl(args: dict) -> dict:
    _must_be_root()
    key, value = args.get("key"), args.get("value")
    if key not in SYSCTLS or not isinstance(value, str) or not SYSCTLS[key].fullmatch(value):
        raise Refused("that kernel setting isn't allowed")
    path = _check_path(_sysctl_path(key))
    with open(path) as f:
        before = f.read().strip()
    if before == value:
        return {"changed": False}
    change = {"sysctl": {"key": key, "before": before, "after": value}}
    change_id = _journal_begin(change)
    try:
        with open(path, "w") as f:
            f.write(value)
    except OSError as e:
        _journal_close(change, "failed", failed=_why(e))
        raise Refused(f"the kernel refused {key}={value}: {e.strerror}") from None
    _did(["sysctl", "-w", f"{key}={value}"])
    _journal_save(change, state="applied")
    return {"changed": True, "change_id": change_id, "warnings": []}


# ------------------------------------------------------------------ ufw

_PORT = re.compile(r"^[0-9]{1,5}/(tcp|udp)$")


def _ufw_added() -> set[str]:
    out = _run(["ufw", "show", "added"])
    return {m.group(1) for m in re.finditer(r"^ufw allow (\S+)$", out, re.M)}


UFW_UNIT = "ufw.service"


def _ufw_unit_state() -> tuple[str, str] | None:
    """ufw.service's (enabled, active) state, or None when there is no such unit (no systemd, or ufw without it)."""
    try:
        return _unit_state(UFW_UNIT)
    except Refused:
        return None


def ufw_enable(args: dict) -> dict:
    """ufw turned on, the given ports allowed first. `ufw enable` writes ENABLED=yes and loads the rules, but at boot
    ufw.service loads them: Arch's package enables no unit, so there the rules were gone after a restart (and
    `systemctl is-active ufw` said inactive). The unit is enabled and started too where it isn't, journalled as a
    service change, which the revert puts back."""
    _must_be_root()
    allow = args.get("allow") or []
    if not isinstance(allow, list) or len(allow) > 20 or not all(isinstance(a, str) and _PORT.match(a) for a in allow):
        raise Refused("bad port list")
    active = _run(["ufw", "status"]).strip().startswith("Status: active")
    existing = _ufw_added()
    unit_before = _ufw_unit_state()
    # a unit that is masked, static or generated is left as it is: only one that can be enabled is
    unit_needed = unit_before is not None and unit_before[0] in ("enabled", "disabled") and unit_before != ("enabled", "active")
    had = _unit_dirs()
    to_add = [a for a in dict.fromkeys(allow) if a not in existing]
    if active and not to_add and not unit_needed:
        return {"changed": False}
    change = {"ufw": {"was_active": active, "added": to_add},
              **({"service": {"unit": UFW_UNIT, "before": unit_before, "after": ["enabled", "active"]}}
                 if unit_needed else {})}
    _journal_begin(change)
    added, turned_on = [], False
    try:
        for a in to_add:
            _do(["ufw", "allow", a])
            added.append(a)
        if not active:
            _do(["ufw", "--force", "enable"])
            turned_on = True
        if unit_needed:
            _set_unit(UFW_UNIT, True, True, unit_before)
    except Refused as e:
        now = _ufw_unit_state()
        if unit_needed and now is not None and now != unit_before:
            _set_unit(UFW_UNIT, unit_before[0] == "enabled", unit_before[1] == "active", now)
        if turned_on:
            _do_code(["ufw", "--force", "disable"])
        for a in added:
            _do_code(["ufw", "delete", "allow", a])
        _remove_dirs(sorted(_unit_dirs() - had))
        _journal_close(change, "failed", failed=str(e))
        raise
    unit_after = _ufw_unit_state() if unit_needed else unit_before
    unit_changed = unit_needed and unit_after != unit_before
    if active and not added and not unit_changed:
        _journal_forget(change)
        return {"changed": False}
    made = sorted(_unit_dirs() - had)
    change.pop("service", None)
    _journal_save(change, ufw={"was_active": active, "added": added}, state="applied",
                  **({"service": {"unit": UFW_UNIT, "before": unit_before, "after": unit_after}} if unit_changed else {}),
                  **({"dirs": made} if made else {}))
    return {"changed": True, "change_id": change["id"], "warnings": [], "dirs": made}


# ------------------------------------------------------------------ browser policies

_BOOL = (True, False)
CLEAR_ON_EXIT = ["browsing_history", "download_history", "cached_images_and_files"]
POLICY_FILES = {
    "firefox": "/etc/firefox/policies/policies.json",
    "chrome": "/etc/opt/chrome/policies/managed/daprivacyscanner.json",
    "chromium": "/etc/chromium/policies/managed/daprivacyscanner.json",
    "brave": "/etc/brave/policies/managed/daprivacyscanner.json",
    "edge": "/etc/opt/edge/policies/managed/daprivacyscanner.json",
    "vivaldi": "/etc/vivaldi/policies/managed/daprivacyscanner.json",
}
POLICIES = {
    "firefox": {"DisableTelemetry": _BOOL, "DisableFirefoxStudies": _BOOL},
    "chromium": {"MetricsReportingEnabled": _BOOL, "BlockThirdPartyCookies": _BOOL,
                 "WebRtcIPHandling": ("default_public_interface_only", "disable_non_proxied_udp"),
                 # VERIFY: the Privacy Sandbox policy names on current Chromium releases
                 "PrivacySandboxAdTopicsEnabled": _BOOL, "PrivacySandboxSiteEnabledAdsEnabled": _BOOL,
                 "PrivacySandboxAdMeasurementEnabled": _BOOL, "SearchSuggestEnabled": _BOOL,
                 # VERIFY: Brave's policy names for P3A and the usage ping
                 "BraveP3AEnabled": _BOOL, "BraveStatsPingEnabled": _BOOL,
                 # 4: site data kept only until the browser closes ("session only")
                 "DefaultCookiesSetting": (4,),
                 # 2: no site may ask for the location
                 "DefaultGeolocationSetting": (2,),
                 # 1: standard protection, not Enhanced Safe Browsing (which sends each page's address to Google)
                 "SafeBrowsingProtectionLevel": (1,),
                 # VERIFY: Chromium honours the list only with SyncDisabled
                 "SyncDisabled": _BOOL, "ClearBrowsingDataOnExitList": (CLEAR_ON_EXIT,)},
}


def browser_policy(args: dict) -> dict:
    _must_be_root()
    browser, settings = args.get("browser"), args.get("settings")
    if browser not in POLICY_FILES:
        raise Refused("unknown browser")
    allowed = POLICIES["firefox" if browser == "firefox" else "chromium"]
    if not isinstance(settings, dict) or not settings or any(k not in allowed or v not in allowed[k] or type(v) is not type(allowed[k][0])
                                                              for k, v in settings.items()):
        raise Refused("those policies aren't allowed")
    path = POLICY_FILES[browser]
    old = _read(path)
    try:
        data = json.loads(old) if old else {}
    except ValueError:
        raise Refused(f"{path} isn't valid JSON; edit it by hand") from None
    if not isinstance(data, dict):
        raise Refused(f"{path} isn't a JSON object")
    if browser == "firefox":
        pol = data.setdefault("policies", {})
        if not isinstance(pol, dict):
            raise Refused(f"{path} has no policies object")
        pol.update(settings)
    else:
        data.update(settings)
    return _apply_files({path: (json.dumps(data, indent=2) + "\n").encode()}, [])


_EXT_IDS = {"firefox": re.compile(r"^(\{[0-9a-fA-F-]{36}\}|[A-Za-z0-9._+-]{1,80}@[A-Za-z0-9._-]{1,80})$"),
            "chromium": re.compile(r"^[a-p]{32}$")}


def block_extensions(args: dict) -> dict:
    """Blocks named extensions by policy, for every user: the browser removes them and won't let
    them be installed again until the policy is reverted. Only exact extension ids (Firefox's
    "*" would block every extension, and isn't one)."""
    _must_be_root()
    browser, ids = args.get("browser"), args.get("ids")
    if browser not in POLICY_FILES:
        raise Refused("unknown browser")
    kind = "firefox" if browser == "firefox" else "chromium"
    if not isinstance(ids, list) or not ids or len(ids) > 50 or not all(isinstance(i, str) and _EXT_IDS[kind].match(i)
                                                                         for i in ids):
        raise Refused("those aren't extension ids")
    path = POLICY_FILES[browser]
    old = _read(path)
    try:
        data = json.loads(old) if old else {}
    except ValueError:
        raise Refused(f"{path} isn't valid JSON; edit it by hand") from None
    if not isinstance(data, dict):
        raise Refused(f"{path} isn't a JSON object")
    if kind == "firefox":
        pol = data.setdefault("policies", {})
        ext = pol.setdefault("ExtensionSettings", {}) if isinstance(pol, dict) else None
        if not isinstance(ext, dict):
            raise Refused(f"{path} has ExtensionSettings the app doesn't understand; edit it by hand")
        for i in ids:
            ext[i] = {"installation_mode": "blocked"}
    else:
        block = data.setdefault("ExtensionInstallBlocklist", [])
        if not isinstance(block, list):
            raise Refused(f"{path} has an ExtensionInstallBlocklist the app doesn't understand; edit it by hand")
        block += [i for i in ids if i not in block]
    return _apply_files({path: (json.dumps(data, indent=2) + "\n").encode()}, [])


# ------------------------------------------------------------------ OpenSnitch (net.outgoing_firewall)
# Rule files of the app's own in OpenSnitch's rules folder, generated here from the lists below: the request
# names a set, never a host or a program. Named 000-… so they come first: OpenSnitch checks rules in name
# order, a matching deny wins at once and an allow only when it has precedence (these allows have none, so
# the user's own deny rules still win over them). The daemon is restarted after a change: in 1.7.2 it notices
# new rule files only on some starts (tested), and a restart also re-reads its settings.

OPENSNITCH_RULES = "/etc/opensnitchd/rules"
OPENSNITCH_CONFIG = "/etc/opensnitchd/default-config.json"
OPENSNITCH_PREFIX = "000-daprivacyscanner-"
OPENSNITCH_DATE = "2026-10-07T00:00:00Z"        # when these lists were written: the same in every dry run
# what the starter rules allow (each program by its real path, the one OpenSnitch sees, where it is installed):
# without them, unanswered prompts for DNS or NetworkManager cut the network (tested on CachyOS)
OPENSNITCH_PROGRAMS = (
    ("DNS lookups (systemd-resolved)", ("/usr/lib/systemd/systemd-resolved", "/lib/systemd/systemd-resolved")),
    ("DNS lookups (dnsmasq)", ("/usr/sbin/dnsmasq", "/usr/bin/dnsmasq")),
    ("The clock (systemd-timesyncd)", ("/usr/lib/systemd/systemd-timesyncd", "/lib/systemd/systemd-timesyncd")),
    ("The clock (chrony)", ("/usr/sbin/chronyd", "/usr/bin/chronyd")),
    ("The clock (ntpd)", ("/usr/sbin/ntpd", "/usr/bin/ntpd")),
    ("Network connections (NetworkManager)", ("/usr/sbin/NetworkManager", "/usr/bin/NetworkManager")),
    ("Network connections (systemd-networkd)", ("/usr/lib/systemd/systemd-networkd", "/lib/systemd/systemd-networkd")),
    ("Network addresses (dhclient)", ("/usr/sbin/dhclient", "/sbin/dhclient")),
    ("Network addresses (dhcpcd)", ("/usr/sbin/dhcpcd", "/usr/bin/dhcpcd")),
    ("Updates (apt's downloads)", ("/usr/lib/apt/methods/http", "/usr/lib/apt/methods/https")),
    ("Updates (pacman)", ("/usr/bin/pacman",)),
    ("Updates (dnf5)", ("/usr/bin/dnf5",)),
    ("Updates (zypper)", ("/usr/bin/zypper",)),
    ("Updates (PackageKit)", ("/usr/libexec/packagekitd", "/usr/lib/packagekitd", "/usr/lib/packagekit/packagekitd")),
    ("Updates (Flatpak)", ("/usr/bin/flatpak", "/usr/libexec/flatpak-system-helper", "/usr/lib/flatpak-system-helper")),
    ("Updates (snapd)", ("/usr/lib/snapd/snapd",)),
    ("Firmware updates (fwupd)", ("/usr/libexec/fwupd/fwupd", "/usr/lib/fwupd/fwupd", "/usr/bin/fwupdmgr")),
    # a VPN's service: denied, it can't connect, and its kill switch then blocks everything (tested with Mullvad VPN
    # 2026.5: its daemon reaches its API and, for quantum-resistant tunnels, 10.64.0.1:1337 inside the tunnel)
    ("VPN (Mullvad VPN's service)", ("/usr/bin/mullvad-daemon",)),
    ("VPN (OpenVPN)", ("/usr/sbin/openvpn", "/usr/bin/openvpn")),
)
# what OpenSnitch calls a connection no program made: the kernel's own, a WireGuard tunnel's packets (Mullvad's,
# NetworkManager's, wg-quick's) and network shares. eBPF finds the kernel thread that sent them, and OpenSnitch asks
# about them like a program; in deny mode they were dropped and the tunnel with them (1.7.2, tested)
OPENSNITCH_KERNEL = ("Connections the kernel makes itself: a WireGuard VPN's tunnel, network shares", "Kernel connection")
# what the starter rules block: phone-home hosts whose blocking breaks nothing (a test keeps them in step with
# the online traffic test's list); a name starting with "." stands for the names under it
OPENSNITCH_TELEMETRY = (
    ("incoming.telemetry.mozilla.org", "Firefox telemetry"),
    ("normandy.cdn.mozilla.net", "Firefox studies"),
    ("p3a-json.brave.com", "Brave's P3A analytics"),
    (".p3a.brave.com", "Brave's P3A analytics"),
    ("usage-ping.brave.com", "Brave's daily usage ping"),
    ("daisy.ubuntu.com", "Ubuntu's crash report upload"),
    ("metrics.ubuntu.com", "Ubuntu's usage report"),
    ("popcon.debian.org", "popularity-contest (Debian)"),
    ("popcon.ubuntu.com", "popularity-contest (Ubuntu)"),
    ("dc.services.visualstudio.com", "Microsoft / VS Code telemetry"),
    ("mobile.events.data.microsoft.com", "Microsoft / VS Code telemetry"),
    ("default.exp-tas.com", "VS Code experiments"),
    ("motd.ubuntu.com", "Ubuntu's message-of-the-day news"),
)
# the connectivity checks (an option of its own: blocking them makes NetworkManager report limited
# connectivity, tested); Fedora's goes to fedoraproject.org, its website too, so it isn't here
OPENSNITCH_CONNECTIVITY = (
    ("connectivity-check.ubuntu.com", "Ubuntu and Linux Mint"),
    ("nmcheck.gnome.org", "GNOME"),
    ("networkcheck.kde.org", "KDE"),
    ("ping.archlinux.org", "Arch Linux and CachyOS"),
    ("conncheck.opensuse.org", "openSUSE"),
    ("detectportal.firefox.com", "Firefox's captive-portal check"),
)
_OS_NAME = re.compile(r"^\.?[a-z0-9-]+(\.[a-z0-9-]+)+$")
OPENSNITCH_LOG = "/var/log/opensnitchd.log"
OPENSNITCH_LOGS = re.compile(r"^opensnitchd\.log(\.[0-9]+(\.(gz|xz|zst|bz2))?|-[0-9]{8}(\.(gz|xz|zst|bz2))?|\.old)$")


def _os_real_program(path: str, root: str) -> str | None:
    """A program's real path (OpenSnitch matches what /proc/PID/exe names, links resolved) when it is a regular
    file under /usr; None when it isn't installed. `root`: the system's root (ROOT, or the app's fixture)."""
    real = os.path.realpath(root + path)
    if root:
        base = os.path.realpath(root)
        if not real.startswith(base + "/"):
            return None
        real = real[len(base):]
    if not real.startswith("/usr/") or not re.fullmatch(r"[A-Za-z0-9._/+-]+", real) or not os.path.isfile(root + real):
        return None
    return real


def _os_hosts(hosts) -> str:
    """A regular expression matching exactly these names (and the names under a ".name")."""
    parts = [(r".+\." + h[1:].replace(".", r"\.")) if h.startswith(".") else h.replace(".", r"\.") for h in hosts]
    return "^(" + "|".join(parts) + ")$"


def _os_rule(name: str, description: str, action: str, operand: str, data: str) -> bytes:
    return (json.dumps({"created": OPENSNITCH_DATE, "updated": OPENSNITCH_DATE, "name": name, "description": description,
                        "enabled": True, "precedence": False, "nolog": False, "action": action, "duration": "always",
                        "operator": {"type": "regexp", "operand": operand, "sensitive": False, "data": data, "list": []}},
                       indent=2) + "\n").encode()


def opensnitch_programs(root: str | None = None) -> list[tuple[str, str]]:
    """(what it is, real path) for each program the starter rules allow that is installed here, each path once.
    `root`: the system's root, for the app's dry run (the helper uses its own)."""
    root = ROOT if root is None else root.rstrip("/")
    out, seen = [], set()
    for what, paths in OPENSNITCH_PROGRAMS:
        for path in paths:
            real = _os_real_program(path, root)
            if real and real not in seen:
                seen.add(real)
                out.append((what, real))
    return out


def opensnitch_rule_files(which: str, root: str | None = None) -> dict[str, bytes]:
    """The rule files of a set ("starter" or "connectivity"): path -> content."""
    out = {}
    if which == "starter":
        allowed = [p for _, p in opensnitch_programs(root)] + [OPENSNITCH_KERNEL[1]]
        name = OPENSNITCH_PREFIX + "allow-system"
        data = "^(" + "|".join(p.replace(".", r"\.").replace("+", r"\+") for p in allowed) + ")$"
        out[f"{OPENSNITCH_RULES}/{name}.json"] = _os_rule(
            name, "DA Privacy Kit's starter rules: what keeps this computer online and up to date (DNS, the "
            "clock, network connections, updates, a VPN and its tunnel). Undo it from the app's History.", "allow",
            "process.path", data)
        name = OPENSNITCH_PREFIX + "deny-telemetry"
        out[f"{OPENSNITCH_RULES}/{name}.json"] = _os_rule(
            name, "DA Privacy Kit's starter rules: phone-home hosts whose blocking breaks nothing. Undo it from the "
            "app's History.", "deny", "dest.host", _os_hosts(h for h, _ in OPENSNITCH_TELEMETRY))
    elif which == "connectivity":
        name = OPENSNITCH_PREFIX + "deny-connectivity-checks"
        out[f"{OPENSNITCH_RULES}/{name}.json"] = _os_rule(
            name, "DA Privacy Kit: the desktops' and Firefox's connectivity checks, blocked. Undo it from the app's "
                  "History.", "deny", "dest.host", _os_hosts(h for h, _ in OPENSNITCH_CONNECTIVITY))
    return out


def opensnitch_rules(args: dict) -> dict:
    """Writes one of the app's rule sets into OpenSnitch's rules folder, then restarts the daemon."""
    _must_be_root()
    which = args.get("set")
    if which not in ("starter", "connectivity"):
        raise Refused("unknown rule set")
    real = _check_path(OPENSNITCH_RULES)
    if not os.path.isdir(real) or os.path.islink(real):
        raise Refused("OpenSnitch isn't installed here (it has no rules folder, /etc/opensnitchd/rules)")
    return _apply_files(opensnitch_rule_files(which), ["opensnitch"])


def _opensnitch_config(lines: list[str], values: dict) -> list[str]:
    """OpenSnitch's daemon settings (default-config.json): LogLevel a number, DefaultAction a string, both at the
    top level. Each is changed on its own line, so the rest of the file stays as it was; a key that isn't there is
    added. A file that isn't a JSON object is left as it is."""
    want = {k: int(v) if k == "LogLevel" else v for k, v in values.items()}
    try:
        data = json.loads("\n".join(lines))
    except ValueError:
        return lines
    if not isinstance(data, dict) or all(data.get(k) == v for k, v in want.items()):
        return lines
    out = list(lines)
    for k, v in want.items():
        pattern = re.compile(rf'^(\s*"{k}"\s*:\s*)("[^"]*"|-?[0-9]+)(\s*,?\s*)$')
        hits = [i for i, line in enumerate(out) if pattern.match(line)]
        if len(hits) == 1:
            out[hits[0]] = pattern.sub(lambda m: m.group(1) + json.dumps(v) + m.group(3), out[hits[0]])
    try:
        edited = json.loads("\n".join(out))
    except ValueError:
        edited = None
    if not isinstance(edited, dict) or {k: x for k, x in edited.items() if k not in want} != \
            {k: x for k, x in data.items() if k not in want} or any(edited.get(k) != v for k, v in want.items()):
        data.update(want)                   # the line edit didn't do it alone: the whole file, written again
        return (json.dumps(data, indent=4) + "\n").split("\n")
    return out


# how much the daemon logs (never below 2: the levels under it log every connection) and what it does with a
# connection nobody answers for
EDITS["opensnitch"] = ({OPENSNITCH_CONFIG: _opensnitch_config}, _keys(LogLevel="[234]", DefaultAction="allow|deny"),
                       ["opensnitch"])


def _opensnitch_log_command() -> str:
    return f"truncate -s 0 {OPENSNITCH_LOG}; rm -f /var/log/opensnitchd.log{{.[0-9]*,-[0-9]*,.old}}"


def clear_opensnitch_log(args: dict) -> dict:
    """OpenSnitch's log emptied (the daemon keeps it open and goes on writing to it) and its rotated copies
    deleted, by fixed names, never through a link."""
    _must_be_root()
    emptied = 0
    try:
        fd = os.open(_check_path(OPENSNITCH_LOG), os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        fd = None
    if fd is not None:
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"{OPENSNITCH_LOG} is not a regular file")
            if st.st_size:
                os.ftruncate(fd, 0)
                emptied = 1
        finally:
            os.close(fd)
    deleted = _delete_files("/var/log", OPENSNITCH_LOGS)
    if emptied or deleted:
        DID.append(_opensnitch_log_command())
    return {"emptied": emptied, "deleted": deleted}


# ------------------------------------------------------------------ revert

def _unit_state_or_none(unit: str) -> tuple[str, str] | None:
    """A unit's state, or None once it isn't installed (its package removed since)."""
    try:
        return _unit_state(unit)
    except Refused:
        return None


def _revert_consent(services: list[dict], now: dict) -> None:
    """Putting back a remote-access service that was on (ssh, a remote desktop, file sharing) lets others reach this
    computer again: the password is asked for again first, each time (_consent)."""
    on = [s["unit"] for s in services if s["unit"] in REMOTE_ACCESS and now.get(s["unit"]) is not None
          and (s["before"][0] == "enabled" or s["before"][1] == "active")
          and not (now[s["unit"]][0] == s["before"][0] and (now[s["unit"]][1] == "active") == (s["before"][1] == "active"))]
    if on:
        _consent(f"turn {' and '.join(on)} back on, as before its fix: {'they let' if len(on) > 1 else 'it lets'} "
                 "others reach this computer")


def revert(args: dict) -> dict:
    _must_be_root()
    change = _load_change(args.get("change_id"))
    uid = _caller_uid()
    if change.get("uid") is not None and uid is not None and change["uid"] != uid:
        raise Refused("that change was made for another account")
    force = args.get("force") is True
    # what was put back by hand already (a file deleted, a setting changed back) is no conflict: as before is the aim
    conflicts = []
    for f in change.get("files", []):
        before = None if f["before"] is None else base64.b64decode(f["before"])
        f["_back"] = _read(f["path"]) == before
        if not f["_back"] and _sha(_read(f["path"])) != f["after_sha"]:
            conflicts.append(f"{f['path']} has been edited since")
    # one unit (journals before protocol 28) or several turned on or off together; a unit whose package was removed
    # since is a conflict, and a forced revert puts back the rest (its own files above all)
    services = change.get("services") or ([change["service"]] if change.get("service") else [])
    units_now = {s["unit"]: _unit_state_or_none(s["unit"]) for s in services}
    gone = [s["unit"] for s in services if units_now[s["unit"]] is None]
    for svc in services:
        now = units_now[svc["unit"]]
        if now is None:
            conflicts.append(f"{svc['unit']} isn't installed any more, so it can't be put back")
        elif change.get("state") != "intent" and tuple(now) not in (tuple(svc["after"]), tuple(svc["before"])):
            conflicts.append(f"{svc['unit']} has been changed since")
    sc = change.get("sysctl")
    if sc:
        with open(_check_path(_sysctl_path(sc["key"]))) as fh:
            if fh.read().strip() not in (sc["after"], sc["before"]):
                conflicts.append(f"{sc['key']} has been changed since")
    mount_unit, linked = change.get("mount_unit"), change.get("linked_unit")
    if mount_unit and mount_unit.get("target") == "ephemeral" and _ephemeral_has_files(mount_unit):
        conflicts.append("~/Ephemeral still has files in it: reverting unmounts it, and they are gone with it. "
                         "Move what you want to keep out first")
    if linked:
        _, state, _ = RUN(["systemctl", "is-enabled", linked["unit"]])
        if state.strip() not in ("enabled", "linked"):
            conflicts.append(f"{linked['unit']} has been changed since")
    if conflicts and not force:
        return {"ok": False, "conflict": True, "message": "; ".join(conflicts)}
    _revert_consent(services, units_now)
    said: list[str] = []                # what was put back, by kind of change: the revert's message
    problems: list[str] = [f"{u} isn't installed any more, so it was left as it is" for u in gone]
    services = [s for s in services if s["unit"] not in gone]
    if mount_unit:
        still, problems = _remove_mount_unit(mount_unit)
        said.append(f"{mount_unit['path']} stays in memory until the next restart, with its mount unit removed" if still
                    else f"{mount_unit['path']} is no longer kept in memory (its mount unit removed)")
    for f in change.get("files", []):
        if f.get("_back"):              # as it was already: nothing to write
            if not mount_unit:
                said.append(f"{f['path']} was already as it was before")
            continue
        _write(f["path"], None if f["before"] is None else base64.b64decode(f["before"]))
        if f["before"] is None:
            _did(["rm", f["path"]])
        else:                           # put back whole from the journal's copy: no command does the same
            DID.append(f"# {f['path']} put back as it was before the change (from the helper's journal)")
        if not mount_unit:              # the mount unit's own file is said above
            said.append(f"{f['path']} removed" if f["before"] is None else f"{f['path']} put back as it was")
    if services:
        masked = [s["unit"] for s in services if str(s["after"][0]).startswith("masked")
                  and not str(s["before"][0]).startswith("masked") and _unit_state(s["unit"])[0].startswith("masked")]
        if masked:                      # unmasked first: a masked unit can't be enabled or started
            _do(["systemctl", "unmask", *masked])
        now = {s["unit"]: _unit_state(s["unit"]) for s in services}
        _set_units({s["unit"]: (s["before"][0] == "enabled" if s["before"][0] in ("enabled", "disabled") else None,
                                s["before"][1] == "active") for s in services}, now)
        said += _units_said(services)
    if sc:
        with open(_check_path(_sysctl_path(sc["key"])), "w") as fh:
            fh.write(sc["before"])
        _did(["sysctl", "-w", f"{sc['key']}={sc['before']}"])
        said.append(f"the kernel setting {sc['key']} back to {sc['before']}")
    ufw = change.get("ufw")
    if ufw:
        for a in ufw["added"]:
            _do_code(["ufw", "delete", "allow", a])
        if not ufw["was_active"]:
            _do(["ufw", "--force", "disable"])
        said.append("the firewall turned off again" if not ufw["was_active"] else
                    f"the firewall's rules it added removed ({', '.join(ufw['added'])})")
    if linked:
        code, out, err = _do_code(["systemctl", "disable", linked["unit"]])
        if code != 0:
            problems.append(f"systemctl disable {linked['unit']}: {(err or out).strip()[:120]}")
        _do_code(["systemctl", "daemon-reload"])
        said.append(f"{linked['unit']} disabled: /tmp is no longer kept in memory from the next restart")
    problems += _remove_dirs(change.get("dirs", []))     # last: what was in them is gone by now
    problems += _hooks(change.get("hooks", []), reverting=True)
    if mount_unit:
        _do_code(["systemctl", "daemon-reload"])
        # a stop that failed (busy) leaves the unit listed as failed, and the system "degraded", after its file is gone
        _, failed, _ = RUN(["systemctl", "is-failed", mount_unit["name"]])
        if failed.strip() == "failed":
            _do_code(["systemctl", "reset-failed", mount_unit["name"]])
    _journal_close(change, "reverted")          # the journal's own folders go once nothing is in them
    message = "; ".join(said) or "Put back as it was"
    if message.startswith("the "):                 # a sentence; a unit's or a file's name keeps its own case
        message = "The" + message[3:]
    message += f". {'; '.join(problems)}" if problems else ""
    return {"ok": True, "conflict": False, "message": message,
            "warnings": problems, "files": [f["path"] for f in change.get("files", [])]}


def _units_said(services: list[dict]) -> list[str]:
    """What putting units back did, in words, units in the same state together ("avahi-daemon.socket and
    avahi-daemon.service enabled and running again")."""
    def words(before) -> str:
        en, active = before[0], before[1] == "active"
        if en == "enabled":
            return "enabled and running again" if active else "enabled again"
        if en == "disabled":
            return "disabled and stopped again" if not active else "disabled again, and running"
        return "running again" if active else "stopped again"
    groups: dict[str, list[str]] = {}
    for s in services:
        groups.setdefault(words(s["before"]), []).append(s["unit"])
    return [f"{' and '.join(units)} {w}" for w, units in groups.items()]


# ------------------------------------------------------------------ folders kept in memory
# A tmpfs on one of the calling user's folders (the thumbnail cache, GVFS metadata, ~/Ephemeral),
# so what lands there is gone at every reboot (or logout). The helper writes a systemd mount unit
# of its own and never edits /etc/fstab: the folder is built from the home of the user pkexec
# names (PKEXEC_UID), never taken from the request, and the unit's conditions make systemd skip the
# mount at boot if a folder on the way has since become a symlink or gone missing, so the mount can
# never land anywhere else.

UNIT_DIR = "/etc/systemd/system"
# target -> (folders under the home, what it is). The request names only the target.
IN_MEMORY = {
    "thumbnails": ((".cache", "thumbnails"), "the thumbnail cache"),
    "gvfs-metadata": ((".local", "share", "gvfs-metadata"), "GVFS file metadata"),
    "ephemeral": (("Ephemeral",), "~/Ephemeral, a folder for temporary work"),
}
MOUNT_SIZE_MB = (50, 4096)
EPHEMERAL_SIZE_MB = (50, 65536)                # and at most half of the memory
UNIT_MARK = "# Created by DA Privacy Kit: {what} kept in memory (tmpfs), empty at every {when}.\n" \
            "# Revert the fix in the app's History to remove it."
_HOME = re.compile(r"^/[A-Za-z0-9._@+/-]+$")    # plain characters only: the path goes into a unit file
CALLER = None                                  # (uid, gid, home) of the user asking; tests set it


def unit_name(path: str, suffix: str = "mount") -> str:
    """systemd's name for the unit of a path, as `systemd-escape --path --suffix=mount` gives it:
    "/home/jo-anne/.cache/thumbnails" -> "home-jo\\x2danne-.cache-thumbnails.mount"."""
    p = re.sub("/+", "/", path).strip("/")
    if not p:
        return f"-.{suffix}"
    out = []
    for i, ch in enumerate(p):
        if ch == "/":
            out.append("-")
        elif ch.isascii() and (ch.isalnum() or ch in ":_.") and not (i == 0 and ch == "."):
            out.append(ch)
        else:
            out += [f"\\x{b:02x}" for b in ch.encode()]
    return "".join(out) + "." + suffix


def in_memory_path(home: str, target: str = "thumbnails") -> str:
    return home.rstrip("/") + "/" + "/".join(IN_MEMORY[target][0])


def _caller() -> tuple[int, int, str]:
    """The user on whose behalf pkexec started us (never trusted from the request), with the
    real path of their home (Fedora Atomic's /home is a link to /var/home)."""
    if CALLER is not None:
        uid, gid, home = CALLER
    else:
        try:
            uid = int(os.environ["PKEXEC_UID"])
            pw = pwd.getpwuid(uid)
        except (KeyError, ValueError):
            raise Refused("can't tell which user is asking (the helper wasn't started by pkexec)") from None
        uid, gid, home = uid, pw.pw_gid, pw.pw_dir
    root = os.path.realpath(ROOT) if ROOT else ""
    real = os.path.realpath(_p(home))
    if root and not real.startswith(root + "/"):
        raise Refused("the home folder is outside the system")
    home = real[len(root):] if root else real
    if not _HOME.match(home):
        raise Refused("the home folder's path has characters this can't put in a unit file")
    return uid, gid, home


RENAME_NOREPLACE = 1


def _renameat2(olddir: int, old: str, newdir: int, new: str, flags: int) -> None:
    """renameat2(2), which the os module doesn't have; OSError as os.rename raises it."""
    libc = ctypes.CDLL(None, use_errno=True)
    fn = getattr(libc, "renameat2", None)
    if fn is None:
        raise OSError(errno.ENOSYS, "renameat2 isn't available")
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if fn(olddir, os.fsencode(old), newdir, os.fsencode(new), flags) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def _new_folder(fd: int, name: str, uid: int, gid: int) -> int:
    """A folder for the user, made in the folder open at `fd` (theirs) under a random name, opened, checked to be the
    empty one just made, given to them by its descriptor and only then renamed to `name`, never over anything there:
    made under its own name and given away by name, the user (who owns the folder it is in) could have put in its place
    something of root's to receive. Returns its descriptor."""
    tmp = f".daprivacyscanner-{uuid.uuid4().hex[:12]}"
    os.mkdir(tmp, 0o700, dir_fd=fd)
    try:
        nfd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    except OSError:
        raise Refused("the folder couldn't be made: it was changed as it was being made") from None
    try:
        st = os.fstat(nfd)
        with os.scandir(nfd) as entries:
            empty = next(entries, None) is None
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700 or not empty:
            raise Refused("the folder couldn't be made: it was changed as it was being made")
        os.fchown(nfd, uid, gid)
        try:
            _renameat2(fd, tmp, fd, name, RENAME_NOREPLACE)
        except OSError as e:
            if e.errno not in (errno.EINVAL, errno.ENOSYS):        # EEXIST: made meanwhile, and left as it is
                raise
            if os.path.lexists(os.path.join(f"/proc/self/fd/{fd}", name)):   # a filesystem without it: by hand
                raise OSError(errno.EEXIST, "File exists") from None
            os.rename(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        return nfd
    except BaseException:
        os.close(nfd)
        try:
            os.rmdir(tmp, dir_fd=fd)
        except OSError:
            pass
        raise


def _folder_fd(home: str, parts: tuple[str, ...], uid: int, gid: int, create: bool = True) -> tuple[int, bool]:
    """Opens the folder under the home one folder at a time without following links, so what is
    checked is what gets mounted: each must be a real folder owned by the user. The last is created
    for the user if missing (with `create`, _new_folder). Returns its descriptor and whether it was created."""
    fd = os.open(_p(home), os.O_RDONLY | os.O_DIRECTORY)
    created = False
    try:
        for i, name in enumerate(parts):
            shown = "~/" + "/".join(parts[:i + 1])
            try:
                nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if i < len(parts) - 1 or not create:
                    raise Refused(f"{shown} doesn't exist") from None
                try:
                    nfd = _new_folder(fd, name, uid, gid)
                except FileExistsError:                            # made meanwhile: taken as it is, and checked below
                    try:
                        nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    except OSError:
                        raise Refused(f"{shown} is a link or not a folder") from None
                else:
                    _did(["install", "-d", "-m", "700", "-o", str(uid), "-g", str(gid),
                          home + "/" + "/".join(parts[:i + 1])])
                    created = True
            except OSError:
                raise Refused(f"{shown} is a link or not a folder") from None
            os.close(fd)
            fd = nfd
            if os.fstat(fd).st_uid != uid:
                raise Refused(f"{shown} isn't owned by the user asking")
        return fd, created
    except BaseException:
        os.close(fd)
        raise


def _has_files(fd: int) -> bool:
    """Anything in the folder but empty subfolders (links count as content)."""
    for entry in os.scandir(fd):
        if not entry.is_dir(follow_symlinks=False):
            return True
        sub = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if _has_files(sub):
                return True
        finally:
            os.close(sub)
    return False


def _proc_mounts() -> list[list[str]]:
    """The mount table, one split line per mount. /proc/mounts is a link the kernel makes (to
    self/mounts), so it is read where it is rather than through _read, which refuses any path that
    goes through a link; nothing is ever written there."""
    try:
        with open(_p("/proc/mounts"), "rb") as f:
            text = f.read(16 * MAX_FILE).decode(errors="replace")
    except FileNotFoundError:
        return []
    return [ln.split() for ln in text.splitlines() if len(ln.split()) > 3]


def _mounted_at(path: str) -> bool:
    return any(f[1] == path for f in _proc_mounts())


def _fstype_at(path: str) -> str | None:
    """The type of what is mounted at `path` last (the one visible), or None."""
    types = [f[2] for f in _proc_mounts() if f[1] == path]
    return types[-1] if types else None


def _memory_mb() -> int | None:
    m = re.search(rb"^MemTotal:\s+(\d+) kB", _read("/proc/meminfo") or b"", re.M)
    return int(m.group(1)) // 1024 if m else None


def mount_unit_text(path: str, home: str, uid: int, gid: int, size: int, target: str = "thumbnails",
                    noexec: bool = True, until: str = "reboot") -> str:
    parts, what = IN_MEMORY[target]
    conditions = []
    for i in range(len(parts)):
        p = home + "/" + "/".join(parts[:i + 1])
        conditions += [f"ConditionPathIsDirectory={p}", f"ConditionPathIsSymbolicLink=!{p}"]
    if until == "logout":
        # mounted while the user's service manager runs: it starts at their first login and stops
        # after their last session ends, and the mount (bound to it) goes with it. Before it, as the RAM disk's
        # drop-in is: systemd mounts it before the manager starts anything of the user's (so no program of theirs
        # runs while the path is looked up), and unmounts it after the manager has stopped, every program of theirs
        # ended
        manager = f"user@{uid}.service"
        order = ["DefaultDependencies=no", "Conflicts=umount.target", "Before=umount.target",
                 "After=local-fs.target", f"Before={manager}", f"BindsTo={manager}"]
        install = ["# mounted when you log in, unmounted (and emptied) when your last session ends", f"WantedBy={manager}"]
    else:
        order = []
        install = ["# wanted, not required: a failure never holds up booting (fstab's nofail)", "WantedBy=local-fs.target"]
    options = f"size={size}M,mode=0700,uid={uid},gid={gid}," + ("noexec," if noexec else "") + "nosuid,nodev"
    return "\n".join([
        UNIT_MARK.format(what=what, when="boot" if until == "reboot" else "logout and boot"), "", "[Unit]",
        f"Description={what[0].upper() + what[1:]}, kept in memory (DA Privacy Kit)", *order,
        "# skipped at boot, never redirected, if a folder on the way is now a link or missing", *conditions, "",
        "[Mount]", "What=tmpfs", f"Where={path}", "Type=tmpfs", f"Options={options}",
        # detached at once even while a program still holds a file in it, so logout isn't held up: that
        # program keeps its own open file until it closes it, but nothing else can reach the folder's
        # contents any more, and the memory goes when the last one is closed
        *(["LazyUnmount=yes"] if target == "ephemeral" else []), "",
        "[Install]", *install, ""])


def mount_tmpfs(args: dict) -> dict:
    """{"target", "size_mb", "noexec", "until"}: keeps one of the calling user's folders in memory
    from now on. Only ~/Ephemeral may be executable or emptied at logout; its folder on disk is made
    read-only for its owner, so nothing is saved there by mistake if the mount is ever missing."""
    _must_be_root()
    target = args.get("target", "thumbnails")
    if target not in IN_MEMORY:
        raise Refused("that folder can't be kept in memory")
    ephemeral = target == "ephemeral"
    size, noexec, until = args.get("size_mb"), args.get("noexec", True), args.get("until", "reboot")
    low, high = EPHEMERAL_SIZE_MB if ephemeral else MOUNT_SIZE_MB
    if not isinstance(size, int) or isinstance(size, bool) or not low <= size <= high:
        raise Refused("bad size")
    memory = _memory_mb() if ephemeral else None
    if memory and size > memory // 2:
        raise Refused("bad size: at most half of the memory")
    if noexec not in (True, False) or until not in ("reboot", "logout") or (not ephemeral and (not noexec or until != "reboot")):
        raise Refused("bad request")
    uid, gid, home = _caller()
    path = in_memory_path(home, target)
    name = unit_name(path)
    unit = f"{UNIT_DIR}/{name}"
    if _read(unit) is not None:
        raise Refused(f"{unit} already exists")
    if _mounted_at(path):
        raise Refused("something is already mounted on that folder")
    parts = IN_MEMORY[target][0]
    fd, created = _folder_fd(home, parts, uid, gid)
    try:
        if _has_files(fd):
            raise Refused("the folder still has files in it: a mount would hide them, not remove them")
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        record = {"name": name, "path": path, "target": target, "home": home, "uid": uid, "created": created}
        had = _unit_dirs()
        if ephemeral:
            record.update(folder_mode=None if created else mode)
        r = _apply_files({unit: mount_unit_text(path, home, uid, gid, size, target, noexec, until).encode()}, [],
                         extra={"mount_unit": record}, more=True)
        if ephemeral:
            os.fchmod(fd, 0o500)        # the folder under the mount: nothing can be saved in it unmounted
            _did(["chmod", "500", path])
        _do_code(["systemctl", "daemon-reload"])
        # mounted here, on the folder opened above one name at a time (/proc/self/fd), never by systemd now: it would
        # hand the path to mount(8), which looks it up again while the user's programs run, and a folder on the way
        # replaced by a link at that moment would put the mount somewhere else. systemd takes up a mount at its
        # unit's path as that unit, active (tested on Ubuntu 26.04 and Fedora 44). At boot (or, for "until logout", as
        # the user's manager starts) it mounts it itself, before anything of the user's runs.
        flags = MS_NOSUID | MS_NODEV | (MS_NOEXEC if noexec else 0)
        options = f"size={size}M,mode=0700,uid={uid},gid={gid}"
        err = MOUNT(f"/proc/self/fd/{fd}", flags, options)
        if not err:
            _did(["mount", "-t", "tmpfs", "-o", ",".join([options, *(["noexec"] if noexec else []), "nosuid", "nodev"]),
                  "tmpfs", path])
    finally:
        os.close(fd)
    code, out, e2 = _do_code(["systemctl", "enable", name])
    made = sorted(_unit_dirs() - had)              # the target's .wants folder, where it wasn't there yet
    _journal_add_dirs(r["change_id"], made, state="applied")
    r["dirs"] = r.get("dirs", []) + made
    r["unit"], r["path"] = unit, path
    r["mounted"] = not err
    if err:
        r["warnings"].append(f"not mounted now ({os.strerror(err)}); it is tried again at every "
                             + ("login" if until == "logout" else "boot"))
    if code != 0:
        r["warnings"].append(f"systemctl enable {name}: {(e2 or out).strip()[:120]}")
    return r


def _ephemeral_has_files(mu: dict) -> bool:
    if not _mounted_at(mu["path"]):
        return False
    try:
        fd, _ = _folder_fd(mu["home"], IN_MEMORY["ephemeral"][0], mu["uid"], 0, create=False)
    except Refused:
        return False
    try:
        return _has_files(fd)
    finally:
        os.close(fd)


def _stop_metadata_daemon(uid) -> None:
    """GVFS's metadata daemon of that user holds its folder open (its database mapped): stopped before the folder is
    unmounted, as applying stops it (as the user) before the folder is emptied. It starts again on demand, so this is
    the one program stopped here."""
    if not isinstance(uid, int) or isinstance(uid, bool) or uid < 1:
        return
    code, _, _ = _do_code(["pkill", "-TERM", "-x", "-u", str(uid), "gvfsd-metadata"])
    if code != 0:                                   # 1: none was running
        return
    for _ in range(20):                             # gone within 2 s
        code, _, _ = RUN(["pgrep", "-x", "-u", str(uid), "gvfsd-metadata"])
        if code != 0:
            return
        time.sleep(0.1)


def _mount_dev(path: str) -> tuple[str | None, int | None]:
    """The type and device number of what is mounted at `path` last (the one visible), from mountinfo; (None, None)
    when nothing is (or the type from /proc/mounts alone, in a fixture tree without mountinfo)."""
    found = None
    for m in _watch_mountinfo():
        if m["mount"] == path:
            found = m
    if found is None:
        return _fstype_at(path), None
    major, _, minor = found["dev"].partition(":")
    try:
        return found["fstype"], os.makedev(int(major), int(minor))
    except ValueError:
        return found["fstype"], None


def _unmount_in_home(mu: dict) -> None:
    """Unmounts the app's tmpfs on a folder in the user's home, reached as applying reached it: the folder above it
    opened one name at a time without following links (_folder_fd), the mount checked to be a tmpfs of the user's
    there, then umount2 on /proc/self/fd/<that folder>/<name>, never following a link at the end. Given the path,
    umount(8) would look it up again as root while the user's programs run. ~/Ephemeral goes as its unit says
    (LazyUnmount: detached even while a program still holds a file in it). Nothing (and nothing said) when it isn't
    mounted or isn't the app's."""
    target = mu.get("target", "thumbnails")
    if target not in IN_MEMORY or "home" not in mu or not _mounted_at(mu["path"]):
        return
    parts = IN_MEMORY[target][0]
    try:
        if len(parts) > 1:
            pfd, _ = _folder_fd(mu["home"], parts[:-1], mu["uid"], 0, create=False)
        else:
            pfd = os.open(_p(mu["home"]), os.O_RDONLY | os.O_DIRECTORY)
    except (OSError, Refused):
        return
    try:
        try:
            cfd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
        except OSError:
            return
        try:
            st = os.fstat(cfd)
        finally:
            os.close(cfd)
        fstype, dev = _mount_dev(mu["path"])
        if fstype != "tmpfs" or (dev is not None and st.st_dev != dev) or st.st_uid != mu["uid"]:
            return
        err = UMOUNT(f"/proc/self/fd/{pfd}/{parts[-1]}", UMOUNT_NOFOLLOW | (MNT_DETACH if target == "ephemeral" else 0))
        if not err:
            _did(["umount", *(["--lazy"] if target == "ephemeral" else []), mu["path"]])
    finally:
        os.close(pfd)


def _remove_mount_unit(mu: dict) -> tuple[bool, list[str]]:
    """Before the unit file goes: disable it and stop it, which unmounts. Whether it unmounted is read from the mount
    table, never from systemctl's exit status: systemd 255 answers 0 for `disable --now` when the stop job failed
    (umount: target is busy), and the revert said "Put back" over a folder still in memory (GVFS metadata, held by
    gvfsd-metadata). A folder still busy stays mounted until the next restart (the unit is gone by then).
    ~/Ephemeral's folder on disk gets its permissions back, or goes if the helper made it (and it is empty).
    Returns (still mounted, notes)."""
    target = mu.get("target", "thumbnails")
    if target == "gvfs-metadata":
        _stop_metadata_daemon(mu.get("uid"))
    _unmount_in_home(mu)
    if _mounted_at(mu["path"]) and target == "gvfs-metadata":
        _stop_metadata_daemon(mu.get("uid"))        # started again meanwhile (a file manager asked): once more
        _unmount_in_home(mu)
    _do_code(["systemctl", "disable", mu["name"]])
    if _mounted_at(mu["path"]):                     # systemctl's own words ("Job failed. See journalctl -xe") say less
        return True, [f"A program still has a file in {mu['path']} open, so it couldn't be unmounted now"]
    if target not in IN_MEMORY or "home" not in mu:
        return False, []
    ephemeral = target == "ephemeral"
    # made by the helper: ~/Ephemeral's records from before say so with folder_mode None, the others with created
    made = mu.get("folder_mode") is None if ephemeral and "created" not in mu else bool(mu.get("created"))
    parts = IN_MEMORY[target][0]
    try:
        if made:
            if len(parts) > 1:
                pfd, _ = _folder_fd(mu["home"], parts[:-1], mu["uid"], 0, create=False)
            else:
                pfd = os.open(_p(mu["home"]), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.rmdir(parts[-1], dir_fd=pfd)
                _did(["rmdir", mu["path"]])
            except OSError as e:
                if e.errno in (errno.ENOTEMPTY, errno.EEXIST):
                    real = _p(mu["path"])
                    return False, [f"{mu['path']} was left, with what is in it: the app made it, but it now holds "
                                   f"what was saved there since ({_listing(real)})"]
                raise
            finally:
                os.close(pfd)
        elif ephemeral and mu.get("folder_mode") is not None:
            fd, _ = _folder_fd(mu["home"], parts, mu["uid"], 0, create=False)
            try:
                os.fchmod(fd, mu["folder_mode"])
                _did(["chmod", f"{mu['folder_mode']:o}", mu["path"]])
            finally:
                os.close(fd)
    except (OSError, Refused) as e:
        return False, [f"{mu['path']} was left as it is ({getattr(e, 'strerror', None) or e})"]
    return False, []


# ------------------------------------------------------------------ the RAM disk (a tool, on demand)
# ~/RAMDisk (the RAM disk tool's) and ~/TempBrowser (the browser in memory's, its own so closing one
# never touches the other): a tmpfs mounted when the user opens it and unmounted when they close it, with nothing
# written to /etc (a reboot ends it). The folder is opened one step at a time without following links,
# as for mount units, and the mount goes through /proc/self/fd/N, the folder actually opened, so
# nothing can redirect it between the check and the mount. The app overwrites the files before
# asking for ramdisk_close (as the user: they are the user's); the helper only unmounts, never lazily,
# and puts the folder underneath back as it was. What it did is kept in RAMDISK_STATE (/run: gone at
# a reboot, with the mount).

RAMDISKS = {"RAMDisk": ("RAMDisk",), "TempBrowser": ("TempBrowser",)}        # name -> the folder under home
RAMDISK_SIZE_MB = (50, 65536)                  # and at most half of the memory
RAMDISK_STATE = "/run/daprivacyscanner/ramdisk"
# on the folder under the mount: whether the helper made it and its mode before, so that closing after a reboot
# (when /run, with the state above, is empty) still puts it back rather than guessing
RAMDISK_XATTR = "user.daprivacyscanner.ramdisk"
MS_NOSUID, MS_NODEV, MS_NOEXEC = 2, 4, 8
UMOUNT_NOFOLLOW, MNT_DETACH = 8, 2


def _libc():
    import ctypes
    import ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    return libc, ctypes


def _mount(target: str, flags: int, options: str) -> int:
    """mount(2) of a tmpfs; 0, or the errno."""
    libc, ctypes = _libc()
    return 0 if libc.mount(b"tmpfs", target.encode(), b"tmpfs", flags, options.encode()) == 0 else ctypes.get_errno()


def _umount(target: str, flags: int = UMOUNT_NOFOLLOW) -> int:
    """umount2(2) without following a link at the end, never lazily unless `flags` say so; 0, or the errno."""
    libc, ctypes = _libc()
    return 0 if libc.umount2(target.encode(), flags) == 0 else ctypes.get_errno()


MOUNT, UMOUNT = _mount, _umount                # tests replace them


def _kernel_has_noswap(release: str | None = None) -> bool:
    """tmpfs's noswap option arrived in Linux 6.4."""
    m = re.match(r"^(\d+)\.(\d+)", release or os.uname().release)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (6, 4)


# systemd makes a mount unit of every mount it sees, and logs "<unit>: Deactivated successfully." at every unmount, in
# a journal kept on the disk: a timeline of the RAM disk's sessions, ~/TempBrowser's named (found in the review of
# 2026-10-17). A drop-in of the helper's in /run (gone at a reboot, as the mount is) gives that unit LogLevelMax=notice,
# so only its warnings and errors are logged. systemd reads it when it makes the unit, at the mount, with no
# daemon-reload, whose own lines would say as much (tested on Mint 22.3, systemd 255: the line is gone).
# ~/TempBrowser's also ends with the user's session (`ends_with`: the owner's decision of 2026-10-17): BindsTo= the
# user's manager, user@UID.service, which stops once their last session has ended, and Before= it, so that systemd
# unmounts it after the manager has stopped, every program of theirs ended and the app's overwrite on its SIGTERM done.
# At a logout the app can't ask for the password: Plasma's polkit agent is stopped as the logout begins (tested on
# CachyOS). Only the unmount is systemd's, never a path to chmod or remove as root: the folder underneath is put back
# by the app, as the user, at its next start (ramdisk.put_back).
DROPIN_DIR = "/run/systemd/system"
DROPIN_FILE = "50-daprivacyscanner.conf"
QUIET_SETTING = "[Mount]\nLogLevelMax=notice\n"


def dropin_setting(uid: int | None) -> str:
    """The drop-in's settings: quiet, and for ~/TempBrowser (`uid`, its owner's) ended with the owner's session."""
    ends = f"[Unit]\nBindsTo=user@{uid}.service\nBefore=user@{uid}.service\n" if uid is not None else ""
    return ends + QUIET_SETTING


def dropin_paths(path: str) -> tuple[str, str]:
    """(the drop-in's folder, the drop-in) for the mount unit of `path`."""
    folder = f"{DROPIN_DIR}/{unit_name(path)}.d"
    return folder, f"{folder}/{DROPIN_FILE}"


def dropin_commands(path: str, on: bool, uid: int | None = None) -> list[str]:
    """What writing (or removing) the drop-in does, as the commands that do the same."""
    folder, file = dropin_paths(path)
    if on:
        return [f"mkdir -p {shlex.quote(folder)}",
                f"printf {shlex.quote(dropin_setting(uid).replace(chr(10), chr(92) + 'n'))} > {shlex.quote(file)}"]
    return [f"rm -f {shlex.quote(file)}", f"rmdir {shlex.quote(folder)}"]


def _dropin(path: str, on: bool, uid: int | None = None) -> bool:
    """Writes (or removes) the RAM disk's mount unit's drop-in (dropin_setting). Best effort: a computer without
    systemd's runtime folder, or a failure, costs only the line in the journal (and for ~/TempBrowser, its unmount
    at a logout). Whether it did it (the caller lists dropin_commands then)."""
    if not os.path.isdir(_p(DROPIN_DIR)):
        return False
    folder, file = dropin_paths(path)
    try:
        if on:
            _write(file, ("# Written by DA Privacy Kit for the RAM disk it opened here: nothing but warnings and errors "
                          "about it in the journal" + (", and unmounted when its owner's session has ended"
                                                       if uid is not None else "") + ".\n"
                          + dropin_setting(uid)).encode(), 0o644)
            return True
        if not os.path.lexists(_check_path(file)):
            return False
        _write(file, None)
    except (OSError, Refused):
        return False
    try:
        os.rmdir(_check_path(folder))           # only while empty: a drop-in of someone else's stays
    except (OSError, Refused):
        pass
    return True


def _remember_folder(fd: int, created: bool, mode: int, path: str) -> None:
    """Keeps on the folder itself (an extended attribute) whether the helper made it and what its mode was. A
    filesystem without them leaves the state in /run alone, as before."""
    value = json.dumps({"created": created, "folder_mode": None if created else mode})
    try:
        os.setxattr(fd, RAMDISK_XATTR, value.encode())
    except OSError:
        return
    _did(["setfattr", "-n", RAMDISK_XATTR, "-v", value, path])


def _forget_folder(fd: int) -> None:
    try:
        os.removexattr(fd, RAMDISK_XATTR)
    except OSError:
        pass


def _record_of(fd: int) -> dict | None:
    """What the folder open at `fd` says about itself (_remember_folder), checked (it is the user's folder: they can
    write the attribute too, and get only what they could do themselves, chmod or rmdir of an empty folder of theirs)."""
    try:
        d = json.loads(os.getxattr(fd, RAMDISK_XATTR))
    except (OSError, ValueError):
        return None
    mode = d.get("folder_mode") if isinstance(d, dict) else None
    if not isinstance(d, dict) or d.get("created") not in (True, False) or not (
            mode is None or (isinstance(mode, int) and not isinstance(mode, bool) and 0 <= mode <= 0o7777)):
        return None
    return {"created": d["created"], "folder_mode": mode}


def _remembered_folder(home: str, parts: tuple[str, ...], uid: int) -> dict | None:
    """What the folder says about itself (_record_of), opened without following links."""
    try:
        fd, _ = _folder_fd(home, parts, uid, 0, create=False)
    except (Refused, OSError):
        return None
    try:
        return _record_of(fd)
    finally:
        os.close(fd)


def _ramdisk(args: dict) -> tuple[str, tuple[str, ...], str]:
    """(name, folder parts under home, state file) for the request's RAM disk (RAMDisk by default)."""
    name = args.get("name", "RAMDisk")
    if name not in RAMDISKS:
        raise Refused("unknown RAM disk")
    uid = _caller()[0]
    return name, RAMDISKS[name], f"{RAMDISK_STATE}/{uid}.json" if name == "RAMDisk" else \
        f"{RAMDISK_STATE}/{uid}-{name}.json"


def ramdisk_open(args: dict) -> dict:
    """{"size_mb", "noexec", "name"}: mount ~/RAMDisk (or ~/TempBrowser) for the calling user now.
    Refused if it is open already, or if the folder on disk has files in it (a mount would hide
    them, not remove them)."""
    import errno
    _must_be_root()
    name, parts, state_file = _ramdisk(args)
    size, noexec = args.get("size_mb"), args.get("noexec", True)
    if not isinstance(size, int) or isinstance(size, bool) or not RAMDISK_SIZE_MB[0] <= size <= RAMDISK_SIZE_MB[1]:
        raise Refused("bad size")
    memory = _memory_mb()
    if memory and size > memory // 2:
        raise Refused("bad size: at most half of the memory")
    if noexec not in (True, False):
        raise Refused("bad request")
    uid, gid, home = _caller()
    path = home + "/" + "/".join(parts)
    if _mounted_at(path):
        raise Refused(f"~/{name} is open already")
    fd, created = _folder_fd(home, parts, uid, gid)
    try:
        if _has_files(fd):
            raise Refused(f"~/{name} has files in it on the disk: move them out first (a mount would hide them, "
                          "not remove them)")
        before = stat.S_IMODE(os.fstat(fd).st_mode)
        undo = (before, None)                   # what a failed mount puts back: the mode, and the record that was there
        earlier = None if created else _record_of(fd)
        if earlier is not None:
            # left by an open whose mount a restart ended (the folder read-only, 0500): its record still says what the
            # folder was before that open, which this open's 0500 would otherwise replace, so the folder stayed
            # empty and read-only for good after the close (found in the review of 2026-10-17)
            undo = (before, earlier)
            created, before = earlier["created"], earlier["folder_mode"] if earlier["created"] is False else before
        _remember_folder(fd, created, before, path)
        os.fchmod(fd, 0o500)            # the folder under the mount: nothing can be saved in it while closed
        flags = MS_NOSUID | MS_NODEV | (MS_NOEXEC if noexec else 0)
        options = f"size={size}M,mode=0700,uid={uid},gid={gid}"
        noswap = _kernel_has_noswap()
        ends = uid if name == "TempBrowser" else None      # the browser's ends with the session (dropin_setting)
        quiet = _dropin(path, True, ends)       # systemd logs nothing about its mount unit but warnings and errors
        err = MOUNT(f"/proc/self/fd/{fd}", flags, options + (",noswap" if noswap else ""))
        if err == errno.EINVAL and noswap:          # a kernel built without it
            noswap = False
            err = MOUNT(f"/proc/self/fd/{fd}", flags, options)
        if err:
            os.fchmod(fd, undo[0])
            if undo[1] is None:
                _forget_folder(fd)
            else:
                _remember_folder(fd, undo[1]["created"], undo[1]["folder_mode"], path)
            if quiet:
                _dropin(path, False)
            raise Refused(f"the mount failed: {os.strerror(err)}")
        _did(["chmod", "500", path])
        if quiet:
            DID.extend(dropin_commands(path, True, ends))
        _did(["mount", "-t", "tmpfs", "-o", ",".join(["nosuid", "nodev", *(["noexec"] if noexec else []), options,
                                                      *(["noswap"] if noswap else [])]), "tmpfs", path])
    finally:
        os.close(fd)
    state = {"path": path, "uid": uid, "size_mb": size, "noexec": noexec, "noswap": noswap,
             "created": created, "folder_mode": None if created else before, "opened": time.time()}
    _own_dir(RAMDISK_STATE)
    _write(state_file, json.dumps(state).encode(), 0o600)
    return {"path": path, "size_mb": size, "noexec": noexec, "noswap": noswap}


def ramdisk_close(args: dict) -> dict:
    """{"name"}: unmount the calling user's ~/RAMDisk or ~/TempBrowser (the app has overwritten its files first) and put the
    folder underneath back: removed if the helper made it, its permissions back otherwise. Refused
    while a program has a file open in it; never a lazy unmount, which would leave the files
    reachable through what holds them."""
    import errno
    _must_be_root()
    name, parts, state_file = _ramdisk(args)
    uid, gid, home = _caller()
    path = home + "/" + "/".join(parts)
    try:
        raw = _read(state_file, trusted=True)
        state = json.loads(raw) if raw else None
    except (Refused, ValueError):                # not the helper's own: what the folder says decides instead
        state = None
    if not isinstance(state, dict):
        state = None
    fstype = _fstype_at(path)
    was_open = fstype is not None
    if was_open:
        if fstype != "tmpfs":
            raise Refused(f"something other than the RAM disk is mounted on ~/{name}")
        err = UMOUNT(_p(path))
        if err == errno.EBUSY:
            raise Refused(f"a program still has a file or folder open in ~/{name}: close it first")
        if err:
            raise Refused(f"unmounting failed: {os.strerror(err)}")
        _did(["umount", path])
    if _dropin(path, False):                     # read when the unit was made: removing it now changes nothing logged
        DID.extend(dropin_commands(path, False))
    if state is None:                            # after a reboot /run is empty: the folder itself says what to put back
        state = _remembered_folder(home, parts, uid)
    if state is None:
        # nothing records that the helper opened a RAM disk here: the folder is the user's own (an empty ~/RAMDisk they
        # made), never removed or changed on a guess
        _write(state_file, None)
        _rmdir_empty(RAMDISK_STATE, os.path.dirname(RAMDISK_STATE))
        return {"closed": True, "was_open": was_open}
    try:
        if state.get("created") is True:
            hfd = os.open(_p(home), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.rmdir(parts[-1], dir_fd=hfd)
            finally:
                os.close(hfd)
            _did(["rmdir", path])
        else:
            fd, _ = _folder_fd(home, parts, uid, gid, create=False)
            try:
                os.fchmod(fd, state.get("folder_mode") or 0o700)
                _forget_folder(fd)
            finally:
                os.close(fd)
            _did(["chmod", f"{state.get('folder_mode') or 0o700:o}", path])
    except (OSError, Refused):
        pass                                     # left as it is: empty, and read-only for its owner
    _write(state_file, None)
    _rmdir_empty(RAMDISK_STATE, os.path.dirname(RAMDISK_STATE))
    return {"closed": True, "was_open": was_open}


# ------------------------------------------------------------------ swap, for a session
# Swap that reaches a disk keeps pieces of memory there, a browser's pages included. For the browser in
# memory the user can turn it off for the session and back on after (a tool's passing state: nothing in
# /etc, nothing journalled; a reboot turns it back on anyway). Only swap that reaches a disk: zram without
# a writeback device stays. The devices come from /proc/swaps, never from the request; what was turned
# off is kept in SWAP_STATE (in /run, readable by the app: device names only), so turning it back on
# puts back those, with their priorities.

SWAP_STATE = "/run/daprivacyscanner/swap.json"
SWAP_MARGIN_MB = 512                    # memory left free after taking back what is in swap


def _unescape_swap(name: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), name)


def swaps_on_disk() -> list[dict]:
    """The active swaps that reach a disk: every one but zram without a writeback (backing) device."""
    out = []
    for ln in (_read("/proc/swaps") or b"").decode(errors="replace").splitlines()[1:]:
        f = ln.split()
        if len(f) < 5:
            continue
        name = _unescape_swap(f[0])
        m = re.fullmatch(r"/dev/(zram\d+)", name)
        if m:
            backing = (_read(f"/sys/block/{m.group(1)}/backing_dev") or b"none").decode(errors="replace").strip()
            if backing in ("", "none"):
                continue
        try:
            out.append({"name": name, "used_kb": int(f[3]), "priority": int(f[4])})
        except ValueError:
            continue
    return out


def _swap_state() -> dict | None:
    """What swap_off turned off, when the file is the helper's own (root's, writable by root alone: an older helper
    made /run/daprivacyscanner under the user's umask, and a list planted there would have had swapon take a file of
    the planter's); None otherwise."""
    try:
        raw = _read(SWAP_STATE, trusted=True)
        state = json.loads(raw) if raw else None
    except (Refused, ValueError):
        return None
    if not isinstance(state, dict) or not isinstance(state.get("devices"), list):
        return None
    return state


def _swap_target(name: str) -> bool:
    """A swap swap_on may turn on again: a block device, or a swap file of root's that only root can write."""
    try:
        st = os.stat(_p(name))
    except OSError:
        return False
    return IS_BLOCK(st) or (stat.S_ISREG(st.st_mode) and st.st_uid == _owner() and not st.st_mode & 0o022)


def swap_off(args: dict) -> dict:
    """Turn off every swap that reaches a disk, if memory can take back what is in it."""
    _must_be_root()
    disk = swaps_on_disk()
    if not disk:
        return {"off": [], "failed": []}
    avail = re.search(rb"^MemAvailable:\s+(\d+) kB", _read("/proc/meminfo") or b"", re.M)
    used_mb = sum(s["used_kb"] for s in disk) // 1024
    if avail and int(avail.group(1)) // 1024 < used_mb + SWAP_MARGIN_MB:
        raise Refused(f"there isn't enough free memory to take back the {used_mb} MB in swap now: close some "
                      "programs first")
    state = _swap_state() or {"devices": [], "since": time.time()}
    off, failed = [], []
    for s in disk:
        code, out, err = _do_code(["swapoff", s["name"]])
        if code == 0:
            off.append(s["name"])
            if s["name"] not in [d["name"] for d in state["devices"]]:
                state["devices"].append({"name": s["name"], "priority": s["priority"]})
        else:
            failed.append(f"{s['name']}: {(err or out).strip()[:200]}")
    if state["devices"]:
        _own_dir(RUN_DIR)
        _write(SWAP_STATE, json.dumps(state).encode(), 0o644)
    return {"off": off, "failed": failed}


def swap_on(args: dict) -> dict:
    """Turn back on the swaps swap_off turned off (and only those), with their priorities."""
    _must_be_root()
    state = _swap_state() or {"devices": []}
    active = {s["name"] for s in swaps_on_disk()}
    on, failed = [], []
    for dev in state.get("devices", []):
        name, prio = (dev.get("name"), dev.get("priority")) if isinstance(dev, dict) else (None, None)
        if not isinstance(name, str) or not name.startswith("/") or "\0" in name or not _swap_target(name):
            continue
        if name in active:
            on.append(name)
            continue
        code, out, err = _do_code(["swapon", *(["-p", str(prio)] if isinstance(prio, int) and prio >= 0 else []), name])
        (on if code == 0 else failed).append(name if code == 0 else f"{name}: {(err or out).strip()[:200]}")
    _write(SWAP_STATE, None)
    _rmdir_empty(os.path.dirname(SWAP_STATE))
    return {"on": on, "failed": failed}


# ------------------------------------------------------------------ the TRIM test
# A tool (docs/TECHNICAL.md, Tools): the app writes test files through the filesystem, as the user, and
# deletes them; the helper reads the filesystem's own block device (the decrypted one under LUKS)
# from start to end, read-only, and counts the test's records in it. It returns counts and
# offsets only: what it reads never leaves this process, and a record counts only when its run ID
# (chosen here) and checksum match, so the scan can't be used to look for anything else on the
# disk. The device is the one holding / or the caller's home, worked out here, never taken from
# the request. Nothing is written anywhere; the run lives in this process and ends with it.

TRIM_FSTYPES = ("ext4", "btrfs")
TRIM_RECORD = 512
TRIM_MAX_RECORDS = 1 << 20
TRIM_NAME_HEX = 16                             # the run's tag in file names, then 4 hex digits: the file number
TRIM_READ = 4 << 20                            # one read
TRIM_OVERLAP = 4096                            # reads overlap, so a record across two of them is seen whole
TRIM_CALL_MAX = 1 << 30                        # one trim_scan request at most
TRIM_ALIGN = 1 << 20
TRIM_PASSES = ("baseline", "after", "later")
TRIM_OFFSETS = 200
# Every record begins with these 16 bytes, then the run ID. Kept as hex so the bytes themselves
# aren't in this file (or its .pyc) on the disk being scanned.
TRIM_MAGIC = bytes.fromhex("c5a1e2793d0b48f6a9175ee03c6d2b84")
NVME_IOCTL_ID = 0x4E40
NVME_IOCTL_ADMIN_CMD = 0xC0484E41
_TRIM: dict = {}                               # the run: one at a time, for this helper's session


def trim_record(run: bytes, index: int, file: int, payload: bytes) -> bytes:
    """One record: magic, run ID, its index and file number, 440 bytes of payload (random, so
    compression can't shrink it) and a SHA-256 of all that."""
    head = TRIM_MAGIC + run + index.to_bytes(4, "little") + file.to_bytes(2, "little") + b"\0\0" + payload
    return head + hashlib.sha256(head).digest()


TRIM_PAYLOAD = TRIM_RECORD - 40 - 32


def _unescape(target: str) -> str:
    """A path from /proc/mounts or mountinfo: the kernel writes space, tab, newline and backslash as \\ooo. With only
    the space undone, a disk mounted at a path with one of the others couldn't be chosen, and the btrfs walk, for
    which this path is the only sign of another filesystem mounted inside, went into it."""
    return _unescape_swap(target)


def _holding(table: list[list[str]], path: str) -> list[str] | None:
    best = None
    for f in table:
        t = _unescape(f[1])
        if path == t or path.startswith(t.rstrip("/") + "/"):
            if best is None or len(t) >= len(_unescape(best[1])):
                best = f
    return best


def _caller_groups(uid: int, gid: int) -> set[int]:
    try:
        return set(os.getgrouplist(pwd.getpwuid(uid).pw_name, gid))
    except (KeyError, OSError):
        return {gid}


class _as_caller:
    """Within it, the kernel checks the helper's file access as the caller's (fsuid, fsgid and their groups): a walk
    of the caller's folders opens only what they could open themselves, access control lists included, which the
    permission bits read alone get wrong (a group's bits are an ACL's mask). Capabilities that bypass permissions go
    with the fsuid and come back with it. As anyone but root (tests), nothing changes."""

    def __init__(self, uid: int, gid: int, groups: set[int]):
        self.uid, self.gid, self.groups, self.saved = uid, gid, sorted(groups), None

    def __enter__(self):
        if os.geteuid() != 0:
            return self
        libc = ctypes.CDLL(None, use_errno=True)
        self.saved = os.getgroups()
        os.setgroups(self.groups)
        libc.setfsgid(self.gid)
        libc.setfsuid(self.uid)
        self.libc = libc
        return self

    def __exit__(self, *exc):
        if self.saved is not None:
            self.libc.setfsuid(0)
            self.libc.setfsgid(0)
            os.setgroups(self.saved)
        return False


def _caller_may(st: os.stat_result, uid: int, groups: set[int], bits: int) -> bool:
    """Whether the caller's permission bits on this file include `bits` (5: open a folder, 3:
    create in it), as owner, group or other, the way the kernel picks one."""
    mode = st.st_mode
    if st.st_uid == uid:
        return (mode >> 6) & bits == bits
    if st.st_gid in groups:
        return (mode >> 3) & bits == bits
    return mode & bits == bits


def _trim_mount(mount) -> list[str]:
    """The mount table line for "/", the filesystem holding the caller's home, or another ext4 or
    btrfs filesystem on a device whose top folder the caller can create files in (a second SSD,
    an external one): the test writes its files there as the caller."""
    uid, gid, home = _caller()
    table = _proc_mounts()
    if not isinstance(mount, str):
        raise Refused("bad request")
    allowed = {"/": _holding(table, "/")}
    h = _holding(table, home)
    if h is not None:
        allowed[_unescape(h[1])] = h
    if allowed.get(mount) is not None:
        return allowed[mount]
    line = next((f for f in reversed(table) if _unescape(f[1]) == mount), None)     # the one visible there
    if line is not None and line[2] in TRIM_FSTYPES and line[0].startswith("/dev/"):
        try:
            st = os.stat(_p(mount))
        except OSError:
            st = None
        if st is not None and _caller_may(st, uid, _caller_groups(uid, gid), 0o3):
            return line
    raise Refused("only /, the filesystem holding your home folder, or another ext4 or btrfs filesystem you can "
                  "write to can be tested")


def _sysblock(name: str) -> str:
    return _p(f"/sys/class/block/{name}")


def _trim_disks(name: str, depth: int = 0) -> list[str]:
    """The drives under a block device: through device-mapper and md layers (slaves) and from a
    partition to its disk."""
    if depth > 8 or not re.match(r"^[A-Za-z0-9._-]+$", name):
        return []
    base = _sysblock(name)
    try:
        slaves = sorted(os.listdir(base + "/slaves"))
    except OSError:
        slaves = []
    if slaves:
        return sorted({d for s in slaves for d in _trim_disks(s, depth + 1)})
    if os.path.exists(base + "/partition"):
        return [os.path.basename(os.path.dirname(os.path.realpath(base)))]
    return [name]


def _nvme_admin(path: str, opcode: int, cdw10: int, cdw11: int = 0, length: int = 4096,
                namespace: bool = True) -> bytes | None:
    """One read-only NVMe admin command (Identify, Security Receive) through the passthrough ioctl
    on the namespace's block device, so nvme-cli needn't be installed. None if it fails."""
    import ctypes
    import fcntl
    import struct
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        nsid = fcntl.ioctl(fd, NVME_IOCTL_ID) if namespace else 0
        buf = ctypes.create_string_buffer(length)
        cmd = bytearray(struct.pack("<BBHIIIQQII6III", opcode, 0, 0, nsid, 0, 0, 0, ctypes.addressof(buf), 0, length,
                                    cdw10, cdw11, 0, 0, 0, 0, 0, 0))
        fcntl.ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd, True)
        return buf.raw
    except OSError:
        return None
    finally:
        os.close(fd)


NVME_ADMIN = _nvme_admin                       # tests replace it
NVME_IDENTIFY, NVME_SECURITY_RECEIVE = 0x06, 0x82
# TCG storage: the Security Subsystem Classes a Level 0 Discovery lists. Opal, Enterprise, Opalite
# and Ruby come with an encryption engine; Pyrite gives locking without encryption.
TCG_SSC = {0x0100: "Enterprise", 0x0200: "Opal 1", 0x0203: "Opal 2", 0x0301: "Opalite", 0x0302: "Pyrite 1",
           0x0303: "Pyrite 2", 0x0304: "Ruby"}
TCG_ENCRYPTING = {0x0100, 0x0200, 0x0203, 0x0301, 0x0304}


def parse_level0(data: bytes | None) -> dict | None:
    """A TCG Level 0 Discovery response: the SSCs it lists, and the Locking feature's Media
    Encryption and Locking Enabled bits (None without one). None if it lists nothing."""
    if not data or len(data) < 48:
        return None
    end = min(len(data), 4 + int.from_bytes(data[0:4], "big"))
    feats, pos = {}, 48
    while pos + 4 <= end:
        code, size = int.from_bytes(data[pos:pos + 2], "big"), data[pos + 3]
        feats[code] = bytes(data[pos + 4:pos + 4 + size])
        pos += 4 + size
    if not feats:
        return None
    lock = feats.get(0x0002)
    return _tcg(set(feats), bool(lock[0] & 0x08) if lock else None, bool(lock[0] & 0x02) if lock else None)


def _tcg(codes: set[int], media: bool | None, enabled: bool | None) -> dict:
    return {"ssc": [n for c, n in TCG_SSC.items() if c in codes], "encrypting_ssc": bool(codes & TCG_ENCRYPTING),
            "media_encryption": media, "locking_enabled": enabled}


def parse_sedutil_query(text: str) -> dict | None:
    """`sedutil-cli --query`: the feature codes it names "(0x0203)" and "MediaEncrypt = Y".
    VERIFY the wording against sedutil on a real Opal drive."""
    codes = {int(c, 16) for c in re.findall(r"\(0x([0-9a-fA-F]{4})\)", text)}
    if not codes:
        return None
    media = re.search(r"MediaEncrypt\s*=\s*([YN])", text)
    enabled = re.search(r"LockingEnabled\s*=\s*([YN])", text)
    return _tcg(codes, media.group(1) == "Y" if media else None, enabled.group(1) == "Y" if enabled else None)


def parse_smartctl_identify(text: str) -> dict[int, int]:
    """`smartctl --identify=wn`: word number -> value. VERIFY the layout against smartctl on a
    real SATA drive."""
    return {int(m.group(1)): int(m.group(2), 16)
            for m in re.finditer(r"^\s*(\d{1,3})\s+-\s+0x([0-9a-fA-F]{4})\b", text, re.M)}


def parse_hdparm_trim(text: str) -> str | None:
    """What `hdparm -I` says a trimmed block reads back as: "zeros" (RZAT), "deterministic"
    (DRAT: the same every time, but unspecified), "unreported", or None if it lists no TRIM.
    VERIFY the wording against hdparm on a real SATA SSD."""
    if not re.search(r"Data Set Management TRIM supported", text):
        return None
    if re.search(r"Deterministic read ZEROs after TRIM", text):
        return "zeros"
    if re.search(r"Deterministic read data after TRIM", text):
        return "deterministic"
    return "unreported"


def _ata_facts(disk: str) -> dict:
    """A SATA drive's IDENTIFY data, from smartctl (hdparm when smartmontools is missing): word 69
    has DRAT (bit 14), RZAT (bit 5) and "encrypts all user data" (bit 4); word 59 the Sanitize
    feature set (bit 12) with CRYPTO SCRAMBLE (bit 13); word 169 bit 0 is TRIM."""
    out = {"disk": disk, "behaviour": None, "source": "", "why": "",
           "encryption": {"encrypts_all": None, "crypto_erase": None, "tcg": None, "notes": []}}
    enc = out["encryption"]
    code, text, _ = RUN(["smartctl", "--identify=wn", f"/dev/{disk}"])
    words = parse_smartctl_identify(text) if code != 127 else {}
    if 69 in words or 169 in words:
        w59, w69, w169 = words.get(59, 0), words.get(69, 0), words.get(169, 0)
        out["source"] = "smartctl --identify, words 69 and 169"
        if not w169 & 1:
            out["why"] = "the drive doesn't report TRIM"
        else:
            out["behaviour"] = "zeros" if w69 & 0x20 else "deterministic" if w69 & 0x4000 else "unreported"
        enc["encrypts_all"] = bool(w69 & 0x10)
        enc["crypto_erase"] = bool(w59 & 0x1000 and w59 & 0x2000)
    else:
        enc["notes"].append("smartmontools isn't installed, so the drive's “encrypts all user data” flag couldn't be "
                            "read" if code == 127 else "smartctl couldn't read the drive's identify data")
        hcode, htext, _ = RUN(["hdparm", "-I", f"/dev/{disk}"])
        b = parse_hdparm_trim(htext) if hcode == 0 else None
        out["source"] = "hdparm -I, DRAT and RZAT"
        if b is None:
            out["why"] = ("neither smartctl nor hdparm is installed" if hcode == 127 and code == 127 else
                          "the drive didn't report TRIM (through a USB bridge or as a SCSI disk, it often can't)")
        out["behaviour"] = b
        if hcode == 0 and re.search(r"SANITIZE feature set", htext):
            enc["crypto_erase"] = bool(re.search(r"CRYPTO_SCRAMBLE_EXT command", htext))
    scode, stext, _ = RUN(["sedutil-cli", "--query", f"/dev/{disk}"])
    if scode == 127:
        enc["notes"].append("sedutil isn't installed, so TCG Opal support couldn't be asked")
    else:
        enc["tcg"] = parse_sedutil_query(stext)
        if enc["tcg"] is None:
            enc["notes"].append("the TCG query got no answer (Linux passes it to SATA drives only when started with "
                                "libata.allow_tpm=1)")
    return out


def _nvme_facts(disk: str) -> dict:
    """An NVMe drive's Identify Namespace (DLFEAT: what a deallocated block reads back as) and
    Identify Controller (OACS bit 0: security commands; SANICAP bit 0: sanitize crypto erase; FNA
    bit 2: format with crypto erase), and a TCG Level 0 Discovery when it has security commands.
    NVMe has no flag like ATA's "encrypts all user data". VERIFY on real drives."""
    dev = _p(f"/dev/{disk}")
    out = {"disk": disk, "behaviour": None, "source": "NVMe identify data, DLFEAT", "why": "",
           "encryption": {"encrypts_all": None, "crypto_erase": None, "tcg": None, "notes": []}}
    enc = out["encryption"]
    ns = NVME_ADMIN(dev, NVME_IDENTIFY, 0)
    if not ns or len(ns) < 64:
        out["why"] = "the drive didn't answer the identify command"
    else:
        out["behaviour"] = {1: "zeros", 2: "ones"}.get(ns[33] & 0x7, "unreported")
        out["value"] = ns[33] & 0x7
    ctrl = NVME_ADMIN(dev, NVME_IDENTIFY, 1, namespace=False)
    if ctrl and len(ctrl) >= 528:
        sanicap, fna = int.from_bytes(ctrl[328:332], "little"), ctrl[524]
        enc["crypto_erase"] = bool(sanicap & 0x1 or fna & 0x4)
        enc["crypto_erase_by"] = [x for x, ok in (("sanitize", sanicap & 0x1), ("format", fna & 0x4)) if ok]
        if int.from_bytes(ctrl[256:258], "little") & 0x1:
            enc["tcg"] = parse_level0(NVME_ADMIN(dev, NVME_SECURITY_RECEIVE, 0x01000100, 2048, 2048, namespace=False))
    else:
        enc["notes"].append("the drive didn't answer the identify-controller command")
    return out


def _drive_facts(disk: str) -> dict:
    """What a drive says about itself: what a trimmed block reads back as ("zeros", "ones",
    "deterministic", "unreported", or None: couldn't tell, with why) and whether it encrypts what
    it stores (each signal None when it couldn't be read)."""
    if re.match(r"^nvme\d+n\d+$", disk):
        return _nvme_facts(disk)
    if re.match(r"^sd[a-z]+$", disk):
        return _ata_facts(disk)
    return {"disk": disk, "behaviour": None, "source": "", "why": "this kind of drive doesn't report it",
            "encryption": {"encrypts_all": None, "crypto_erase": None, "tcg": None, "notes": []}}


_ERASE_DISK = re.compile(r"^(sd[a-z]{1,3}|nvme\d{1,3}n\d{1,3}|mmcblk\d{1,3}|vd[a-z]{1,3}|hd[a-z])$")


def parse_hdparm_security(text: str) -> dict | None:
    """`hdparm -I`'s Security section and Sanitize commands. VERIFY the wording against hdparm on real
    drives (frozen and not frozen)."""
    m = re.search(r"^Security:\s*\n((?:[ \t]+.*\n?)*)", text, re.M)
    if not m:
        return None
    sec = m.group(1)
    flag = lambda word: (None if not re.search(rf"^\s*(?:not\s+)?{word}\b", sec, re.M)  # noqa: E731
                         else not re.search(rf"^\s*not\s+{word}\b", sec, re.M))
    times = re.search(r"(\d+)min for SECURITY ERASE UNIT\.\s*(?:(\d+)min for ENHANCED SECURITY ERASE UNIT)?", sec)
    return {"supported": bool(re.search(r"^\s*supported\s*$", sec, re.M)), "enabled": flag("enabled"),
            "locked": flag("locked"), "frozen": flag("frozen"),
            "enhanced": bool(re.search(r"supported: enhanced erase", sec)),
            "erase_minutes": int(times.group(1)) if times else None,
            "enhanced_minutes": int(times.group(2)) if times and times.group(2) else None,
            "sanitize": {"supported": "SANITIZE feature set" in text, "crypto": "CRYPTO_SCRAMBLE_EXT" in text,
                         "block": "BLOCK_ERASE_EXT" in text, "overwrite": "OVERWRITE_EXT" in text}}


def ata_security_words(words: dict[int, int]) -> dict | None:
    """The same from IDENTIFY words: 128 (security status: bit 0 supported, 1 enabled, 2 locked, 3
    frozen, 5 enhanced erase), 89 and 90 (erase times, in units of 2 minutes), 59 (Sanitize: bit 12
    supported, 13 crypto scramble, 14 overwrite, 15 block erase)."""
    if 128 not in words:
        return None
    w = words[128]
    mins = lambda v: (v & 0x7FFF) * 2 if v and v & 0x7FFF not in (0, 0x7FFF) else None  # noqa: E731
    w59 = words.get(59, 0)
    return {"supported": bool(w & 1), "enabled": bool(w & 2), "locked": bool(w & 4), "frozen": bool(w & 8),
            "enhanced": bool(w & 0x20), "erase_minutes": mins(words.get(89, 0)),
            "enhanced_minutes": mins(words.get(90, 0)),
            "sanitize": {"supported": bool(w59 & 0x1000), "crypto": bool(w59 & 0x2000),
                         "overwrite": bool(w59 & 0x4000), "block": bool(w59 & 0x8000)}}


def erase_facts(args: dict) -> dict:
    disk = args.get("disk")
    if not isinstance(disk, str) or not _ERASE_DISK.match(disk):
        raise Refused("not a whole drive")
    base = _sysblock(disk)
    if not os.path.isdir(base) or os.path.exists(base + "/partition"):
        raise Refused("not a whole drive")
    out = {"disk": disk, "ata": None, "nvme": None, "source": "", "notes": []}
    if disk.startswith("nvme"):
        ctrl = NVME_ADMIN(_p(f"/dev/{disk}"), NVME_IDENTIFY, 1, namespace=False)
        if not ctrl or len(ctrl) < 528:
            out["notes"].append("the drive didn't answer the identify-controller command")
            return out
        oacs, sanicap, fna = int.from_bytes(ctrl[256:258], "little"), int.from_bytes(ctrl[328:332], "little"), ctrl[524]
        out["source"] = "NVMe Identify Controller (OACS, FNA, SANICAP)"
        out["nvme"] = {"format": bool(oacs & 0x2), "format_crypto": bool(fna & 0x4), "format_all_namespaces": bool(fna & 0x1),
                       "sanitize": {"crypto": bool(sanicap & 0x1), "block": bool(sanicap & 0x2),
                                    "overwrite": bool(sanicap & 0x4)}}
        return out
    if not disk.startswith(("sd", "hd")):
        out["notes"].append("this kind of drive doesn't report erase features")
        return out
    code, text, _ = RUN(["smartctl", "--identify=wn", f"/dev/{disk}"])
    sec = ata_security_words(parse_smartctl_identify(text)) if code != 127 else None
    if sec is not None:
        out["source"], out["ata"] = "smartctl --identify, words 59, 89, 90 and 128", sec
        return out
    hcode, htext, _ = RUN(["hdparm", "-I", f"/dev/{disk}"])
    sec = parse_hdparm_security(htext) if hcode == 0 else None
    if sec is not None:
        out["source"], out["ata"] = "hdparm -I", sec
    else:
        out["notes"].append("neither smartctl nor hdparm is installed" if code == 127 and hcode == 127 else
                            "the drive didn't give its identify data (through a USB adapter it often can't)")
    return out


def _is_block(st: os.stat_result) -> bool:
    return stat.S_ISBLK(st.st_mode)


IS_BLOCK = _is_block                           # tests use a regular file as the device


def _trim_open(path: str) -> int:
    """The device, read-only and with O_DIRECT (straight from the drive, past the page cache). A
    regular file (tests) is opened without it where its filesystem refuses it."""
    import errno
    try:
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECT)
    except OSError as e:
        if e.errno != errno.EINVAL or _is_block(os.stat(path)):
            raise Refused(f"the device can't be read directly: {e.strerror}") from None
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC)


TRIM_PIECE = 64 << 10                          # a failed read is retried in pieces this big, to find the bad part
TRIM_BAD_RANGES = 1000                         # unreadable ranges kept per pass (bytes are always counted)


def _read_window(fd: int, buf, pos: int, want: int) -> tuple[int, list[list[int]]]:
    """Reads `want` bytes at `pos` into buf. Where the drive answers with an I/O error (a failing
    sector), the read is retried in pieces of TRIM_PIECE and the pieces it can't read are zero-filled
    and returned as [offset, length] ranges: nothing stale from an earlier read is left in them to be
    counted. Returns (bytes covered, unreadable ranges). Any other error is raised."""
    import errno
    with memoryview(buf) as view:                # released on every path: an exported view keeps the mmap from closing
        try:
            return os.preadv(fd, [view[:want]], pos), []
        except OSError as e:
            if e.errno != errno.EIO:
                raise Refused(f"the device couldn't be read: {e.strerror}") from None
        n, bad = 0, []
        for q in range(0, want, TRIM_PIECE):
            k = min(TRIM_PIECE, want - q)
            try:
                r = os.preadv(fd, [view[q:q + k]], pos + q)
            except OSError as e:
                if e.errno != errno.EIO:
                    raise Refused(f"the device couldn't be read: {e.strerror}") from None
                view[q:q + k] = bytes(k)
                if bad and bad[-1][0] + bad[-1][1] == pos + q:
                    bad[-1][1] += k
                else:
                    bad.append([pos + q, k])
                r = k
            n += r
            if r < k:
                break
        return n, bad


def _note_bad(p: dict, bad: list[list[int]]) -> None:
    """Adds unreadable ranges to a pass (merged with the last one when they touch)."""
    for off, length in bad:
        p["bad_bytes"] += length
        ranges = p["bad"]
        if ranges and ranges[-1][0] + ranges[-1][1] == off:
            ranges[-1][1] += length
        elif len(ranges) < TRIM_BAD_RANGES:
            ranges.append([off, length])
        else:
            p["bad_more"] = True


def _fs_device(f: list[str]) -> tuple[str, os.stat_result]:
    """The block device a mount table line's filesystem is on (ext4, or btrfs on one device)."""
    fstype, source = f[2], f[0]
    if fstype not in TRIM_FSTYPES:
        raise Refused(f"only ext4 and btrfs can be read (this is {fstype})")
    if not _DEVICE.match(source) or ".." in source.split("/"):
        raise Refused("the filesystem isn't on a device")
    real = os.path.realpath(_p(source))
    if not real.startswith(_p("/dev/")):
        raise Refused("the filesystem isn't on a device")
    st = os.stat(real)
    if not IS_BLOCK(st):
        raise Refused("the filesystem isn't on a block device")
    if fstype == "btrfs":
        name = os.path.basename(real)
        for fs in os.listdir(_p("/sys/fs/btrfs")) if os.path.isdir(_p("/sys/fs/btrfs")) else []:
            try:
                devs = os.listdir(_p(f"/sys/fs/btrfs/{fs}/devices"))
            except OSError:
                continue
            if name in devs and len(devs) > 1:
                raise Refused("btrfs on more than one device can't be read")
    return real, st


def _device_size(real: str) -> int:
    fd = _trim_open(real)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def trim_begin(args: dict) -> dict:
    """{"mount"}: starts a run on / or the filesystem holding the caller's home (ext4 or a
    single-device btrfs). Returns the run ID the app writes its records with, the tag its file
    names carry, the device and its size, and what each drive under it says about itself: what a
    trimmed block reads back as, and whether it encrypts what it stores."""
    _must_be_root()
    f = _trim_mount(args.get("mount"))
    real, st = _fs_device(f)
    size = _device_size(real)
    run = os.urandom(16)
    _TRIM.clear()
    _TRIM.update({"mount": f[1], "device": real, "rdev": st.st_rdev, "ino": st.st_ino, "size": size, "run": run,
                  "tag": os.urandom(TRIM_NAME_HEX // 2).hex(), "passes": {}, "uid": _caller()[0]})
    return {"run": run.hex(), "tag": _TRIM["tag"], "device": real[len(ROOT):], "size": size, "fstype": f[2],
            "mount": _unescape(f[1]), "drives": [_drive_facts(d) for d in _trim_disks(os.path.basename(real))]}


def _trim_run() -> dict:
    if not _TRIM or _TRIM.get("uid") != _caller()[0]:
        raise Refused("no TRIM test is running")
    return _TRIM


def _scan_window(buf, n: int, base: int, counted: int, run: dict, p: dict, keep_offsets: bool) -> None:
    """Counts what lies in buf[:n] (read at device offset `base`) and ends past `counted`:
    records whose run ID and checksum match, and the run's tag in file names."""
    needle = TRIM_MAGIC + run["run"]
    start = max(0, counted - base - TRIM_RECORD + 1)
    i = buf.find(needle, start, n)
    while i != -1:
        if i + TRIM_RECORD <= n and base + i + TRIM_RECORD > counted:
            rec = buf[i:i + TRIM_RECORD]
            if hashlib.sha256(rec[:TRIM_RECORD - 32]).digest() == rec[TRIM_RECORD - 32:]:
                index = int.from_bytes(rec[32:36], "little")
                if index < TRIM_MAX_RECORDS:
                    p["copies"] += 1
                    byte, bit = divmod(index, 8)
                    if not p["bits"][byte] & (1 << bit):
                        p["bits"][byte] |= 1 << bit
                        p["found"] += 1
                        if keep_offsets and len(p["offsets"]) < TRIM_OFFSETS:
                            p["offsets"].append([index, base + i])
        i = buf.find(needle, i + 1, n)
    tag = run["tag"].encode()
    width = TRIM_NAME_HEX + 4
    i = buf.find(tag, max(0, counted - base - width + 1), n)
    while i != -1:
        if i + width <= n and base + i + width > counted:
            digits = bytes(buf[i + TRIM_NAME_HEX:i + width])
            if re.fullmatch(rb"[0-9a-f]{4}", digits):
                file = int(digits, 16)
                p["names"][file] = p["names"].get(file, 0) + 1
        i = buf.find(tag, i + 1, n)


def trim_scan(args: dict) -> dict:
    """{"pass", "offset", "length"}: reads that part of the device (offset aligned to 1 MiB, at
    most 1 GiB) and adds what it finds to the pass. Returns how far it read and the pass's counts
    so far: distinct records, all copies of them, distinct names."""
    import mmap
    _must_be_root()
    run = _trim_run()
    name, off, length = args.get("pass"), args.get("offset"), args.get("length")
    if name not in TRIM_PASSES:
        raise Refused("bad request")
    for v in (off, length):
        if not isinstance(v, int) or isinstance(v, bool):
            raise Refused("bad request")
    if off < 0 or off % TRIM_ALIGN or not 0 < length <= TRIM_CALL_MAX or off >= run["size"]:
        raise Refused("bad range")
    p = run["passes"].setdefault(name, {"bits": bytearray(TRIM_MAX_RECORDS // 8), "found": 0, "copies": 0,
                                        "names": {}, "offsets": [], "read": 0, "bad": [], "bad_bytes": 0,
                                        "bad_more": False})
    end = min(off + length, run["size"])
    fd = _trim_open(run["device"])
    buf = mmap.mmap(-1, TRIM_READ)               # page-aligned, as O_DIRECT needs
    try:
        st = os.fstat(fd)
        if (st.st_rdev, st.st_ino) != (run["rdev"], run["ino"]):
            raise Refused("the device changed since the test started")
        pos, counted = max(0, off - TRIM_OVERLAP), off
        while counted < end:
            _check_cancel()
            want = min(TRIM_READ, end - pos)
            n, bad = _read_window(fd, buf, pos, want)
            if n <= 0:
                break
            _note_bad(p, [[max(o, counted), o + k - max(o, counted)] for o, k in bad if o + k > counted])
            _scan_window(buf, n, pos, counted, run, p, name != "baseline")
            counted = pos + n
            if pos + n >= end:
                break
            pos = pos + n - TRIM_OVERLAP
        p["read"] += counted - off
    finally:
        buf.close()
        os.close(fd)
    return {"read": counted - off, "found": p["found"], "copies": p["copies"], "names": len(p["names"]),
            "size": run["size"], "unreadable": p["bad_bytes"]}


def trim_result(args: dict) -> dict:
    """{"pass"}: what the pass found: which records (a bitmap by index, base64), how many copies,
    up to TRIM_OFFSETS of them with their device offset, each file number's name count, and the
    parts of the device that couldn't be read (bytes, and up to TRIM_BAD_RANGES [offset, length])."""
    _must_be_root()
    run = _trim_run()
    p = run["passes"].get(args.get("pass"))
    if p is None:
        raise Refused("that pass hasn't run")
    return {"bits": base64.b64encode(bytes(p["bits"])).decode(), "found": p["found"], "copies": p["copies"],
            "offsets": p["offsets"], "names": {str(k): v for k, v in sorted(p["names"].items())}, "read": p["read"],
            "unreadable": p["bad_bytes"], "unreadable_ranges": p["bad"], "unreadable_more": p["bad_more"]}


def _trim_command(argv: list[str]) -> tuple[int, str, str]:
    """fstrim can take minutes on a large filesystem."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=900,
                           stdin=subprocess.DEVNULL, env=_ENV)
    except FileNotFoundError:
        return 127, "", f"{argv[0]} is not installed"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} timed out"
    return p.returncode, p.stdout, p.stderr


TRIM_RUN = _trim_command                       # tests replace it


def trim_fstrim(args: dict) -> dict:
    """Trims the free space of the run's filesystem (`fstrim -v`, as the weekly timer does)."""
    _must_be_root()
    run = _trim_run()
    code, out, err = TRIM_RUN(["fstrim", "-v", _unescape(run["mount"])])
    if code == 127:
        raise Refused("fstrim is not installed")
    if code != 0:
        raise Refused(f"fstrim failed: {(err or out).strip()[:200]}")
    m = re.search(r"\((\d+) bytes\) trimmed", out)
    return {"trimmed": int(m.group(1)) if m else None}


def trim_end(args: dict) -> dict:
    _must_be_root()
    _TRIM.clear()
    return {"ended": True}


# ------------------------------------------------------------------ names of deleted files
# The Deleted file names tool: which names of deleted files can still be read from a filesystem the
# TRIM test may run on. On the filesystem holding the caller's home, only folders under the home that
# the caller owns; on another (a second SSD, an external one), every folder on it the caller's
# permission bits allow them to open (read and search, as owner, group member or other; access control
# lists aren't consulted), so a shared disk doesn't show them what they couldn't list. Reached without
# following links, never into another mount. The system disk outside the home isn't listed. The names go
# to the caller, who sees them once (names_result); the helper keeps them, in this process's memory only,
# for the checks that follow a clean-up (names_folder, names_check), until names_end, the next
# names_begin, or the end of the helper's session. Parts of the device the drive can't read (I/O
# errors: failing sectors) are skipped and counted, as in the TRIM test's scans.
#
# ext4 keeps a folder's entries in the folder's own blocks, and deleting one left its name there until
# Linux 5.13 (in the space the entry before it grows over, or with its inode zeroed when first): each
# folder's blocks are read (FIEMAP gives where they are) and parsed. Copies of those blocks are also in
# the journal (jbd2 writes every changed metadata block there before its home), until it wraps; the
# descriptor blocks say which filesystem block each copy is of, so names_check reads the copies of
# the folders it is asked about and nothing else.
#
# Since Linux 5.13 ext4 overwrites an entry in its folder's block as the file is deleted, so there the names
# of deleted files are in the journal's copies alone (seen on kernel 7.0: 403 names deleted, none left in the
# folders, all in the journal). The listing therefore reads the whole journal after the folders. A copy is
# tied to its folder by the folder block's own checksum, not by where it says it belongs (a block changes
# hands, and a descriptor can outlive its copies): with metadata_csum every folder block ends in a checksum
# over the block seeded with the folder's inode number and generation, so a block whose checksum fits a listed
# folder was that very folder's. crc32c is linear, so one pass over the block (with seed 0) gives what the seed
# must have been, looked up among the listed folders' (`_ext4_seed_key`). The checksum has 32 bits, and a full
# journal read against 200,000 folders would let a few foreign blocks through by chance, so a second thing must
# agree: the journal's descriptor says the copy is of a block that folder has now, or the block names the folder
# as itself ("."), or an entry in it is a file the folder holds now under that name and inode. A folder that is
# gone is tied the same way through its place in a listed folder: a copy of that folder names it as a
# subfolder; its inode's generation gives the seed, read from the inode table and from the journal's copies of
# that part of the table (an inode freed by rm -r is often used again within the second, with a new generation:
# seen on the first real run, where a folder just deleted wasn't found); the kernel says that no inode of that
# number and generation exists now (open_by_handle_at, as an NFS server asks: "stale" for one deleted or used
# again), so it is no live folder the listing doesn't cover; and its own first block names itself and that
# parent. Blocks tied to no listed folder (other accounts', the system's, folders
# whose inode was reused) are counted, never named, unless the user asks for them (names_orphans); without
# metadata_csum nothing can be tied, so every folder block in the journal is one of those. The journal is
# cleared by the kernel's own call (EXT4_IOC_CHECKPOINT with zero-out, Linux 5.14: it writes everything in the
# journal to its place, then zeroes it, the fast-commit area too; tested on kernel 7.0).
#
# btrfs keeps entries as items in its tree: deleting
# copies the tree block without the item and frees the old copy, which stays in free space until
# trimmed or reused, and live blocks can keep stale item headers past their last item. The whole device
# is read for tree blocks of the home's subvolume (checksum checked).

NAMES_MAX = 50000                              # names returned at most
NAMES_DIRS_MAX = 200000
NAMES_DEPTH = 64
NAMES_DIR_BYTES = 16 << 20                     # of one folder's blocks
NAMES_STEP_DIRS = 2000
NAMES_CHECK_MAX = 500                          # folders one names_check covers
NAMES_JOURNAL_STEP = 256 << 20                 # of the journal, one names_step
NAMES_JOURNAL_NAMES = 500000                   # names kept from the journal at most
NAMES_ORPHANS_MAX = 100000                     # journal blocks remembered that are no listed folder's
NAMES_GONE_MAX = 1000                          # deleted subfolders looked up
NAMES_WEAK_MAX = 2000                          # copies kept until the journal is read, to be tied by their entries
NAMES_ITABLE_MAX = 50000                       # copies of inode table blocks remembered (where, not what)
NAMES_INODE_COPIES = 64                        # of those, read for one inode at most (the latest)
NAMES_GONE_READS = 20000                       # journal blocks read to tie folders that are gone, in all
NAMES_GONE_PER_KEY = 256                       # of those, for one folder's checksum at most
FS_IOC_GETFLAGS, FS_IOC_FIEMAP = 0x80086601, 0xC020660B
FS_IOC_GETVERSION = 0x80087601
EXT4_IOC_CHECKPOINT = 0x4004662B
EXT4_CHECKPOINT_ZEROOUT, EXT4_CHECKPOINT_DRY_RUN = 0x2, 0x4
EXT4_DIR_TAIL = b"\0\0\0\0\x0c\0\0\xde"          # a folder block's last entry with metadata_csum, before its checksum
FS_INDEX_FL, FS_ENCRYPT_FL = 0x1000, 0x800
BTRFS_IOC_INO_LOOKUP = 0xD0009412
BTRFS_SUPER = 65536
BTRFS_DIR_ITEM, BTRFS_DIR_INDEX = 84, 96
EXT4_SUPER = 1024
EXT4_EXTENT_MAGIC = 0xF30A
EXT4_EXTENTS_MAX = 4096           # a journal is a few extents (one, made by mke2fs); more is a crafted tree (ext4_extents)
JBD2_MAGIC = 0xC03B3998
JBD2_MAGIC_BYTES = JBD2_MAGIC.to_bytes(4, "big")
JBD2_DESCRIPTOR = 1
JBD2_64BIT, JBD2_CSUM_V2, JBD2_CSUM_V3, JBD2_FAST_COMMIT = 0x2, 0x8, 0x10, 0x20
JBD2_SAME_UUID, JBD2_LAST_TAG = 0x2, 0x8
_NAMES: dict = {}


def _dir_flags(fd: int) -> int:
    import fcntl
    buf = bytearray(8)
    try:
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
    except OSError:
        return 0
    return int.from_bytes(buf[:4], sys.byteorder)


def _fiemap(fd: int, count: int = 64) -> list[tuple[int, int]] | None:
    """Where a file's (or folder's) blocks are on the device: [(offset, length)], leaving out
    extents that aren't plain blocks (inline, encrypted, unwritten). None if it can't be mapped."""
    import fcntl
    import struct
    buf = bytearray(32 + 56 * count)
    struct.pack_into("<QQIIII", buf, 0, 0, 0xFFFFFFFFFFFFFFFF, 1, 0, count, 0)
    try:
        fcntl.ioctl(fd, FS_IOC_FIEMAP, buf, True)
    except OSError:
        return None
    out = []
    for i in range(struct.unpack_from("<I", buf, 20)[0]):
        _, phys, length = struct.unpack_from("<QQQ", buf, 32 + 56 * i)
        if not struct.unpack_from("<I", buf, 32 + 56 * i + 40)[0] & 0xB8A:
            out.append((phys, length))
    return out


FIEMAP = _fiemap                               # tests replace it


def _dir_generation(fd: int) -> int | None:
    """The inode's generation (FS_IOC_GETVERSION), which ext4 mixes into its folder blocks' checksums."""
    import fcntl
    buf = bytearray(8)
    try:
        fcntl.ioctl(fd, FS_IOC_GETVERSION, buf, True)
    except OSError:
        return None
    return int.from_bytes(buf[:4], sys.byteorder)


GENERATION = _dir_generation                   # tests replace it


def _good_name(name: bytes) -> bool:
    if not name or b"/" in name or b"\0" in name or name in (b".", b".."):
        return False
    try:
        text = name.decode()
    except UnicodeDecodeError:
        return False
    return all(ord(c) >= 0x20 and c != "\x7f" for c in text)


def parse_ext4_dir_block(block: bytes, skip_index: bool = False, live: bool = False) -> set[bytes]:
    """Names of deleted entries in one ext4 folder block: entries with their inode zeroed, and
    whole entries left in the space past a live entry's own (the one before a deleted entry grows
    over it). `skip_index`: the folder's first block in an indexed (htree) folder, where what follows
    ".." is the index, not entries. Index blocks further on (an empty entry over the whole block)
    have none. `live`: the live entries' names too (an old copy of the block, in the journal or
    freed, holds the names of files deleted since as live entries)."""
    size, out, pos = len(block), set(), 0
    first = True
    while pos + 8 <= size:
        ino, rec_len, name_len, ftype = int.from_bytes(block[pos:pos + 4], "little"), \
            int.from_bytes(block[pos + 4:pos + 6], "little"), block[pos + 6], block[pos + 7]
        if rec_len in (0, 65535) and size == 65536:
            rec_len = 65536
        if rec_len < 8 or rec_len % 4 or pos + rec_len > size:
            break
        if first and ino == 0 and name_len == 0 and rec_len == size:
            return out                                   # an index block
        name = bytes(block[pos + 8:pos + 8 + name_len])
        if (live or ino == 0) and name_len and 0 < ftype < 8 and 8 + name_len <= rec_len and _good_name(name):
            out.add(name)
        own = (8 + name_len + 3) & ~3
        if not (skip_index and name == b".."):
            q, end = pos + own, pos + rec_len
            while q + 8 <= end:
                sino, srec, snl, sft = int.from_bytes(block[q:q + 4], "little"), \
                    int.from_bytes(block[q + 4:q + 6], "little"), block[q + 6], block[q + 7]
                sname = bytes(block[q + 8:q + 8 + snl])
                if (sino and snl and 0 < sft < 8 and srec >= 8 + snl and srec % 4 == 0 and q + 8 + snl <= end
                        and q + srec <= size and _good_name(sname)):
                    out.add(sname)
                    q += (8 + snl + 3) & ~3
                else:
                    q += 4
        pos += rec_len
        first = False
    return out


def ext4_dir_entries(block: bytes) -> list[tuple[int, int, bytes]] | None:
    """(inode, type, name) of the live entries of an ext4 folder block (without its checksum tail), or None
    if it isn't one: the entries must lead exactly to its end."""
    size, pos, out = len(block), 0, []
    while pos + 8 <= size:
        ino, rec = int.from_bytes(block[pos:pos + 4], "little"), int.from_bytes(block[pos + 4:pos + 6], "little")
        name_len, ftype = block[pos + 6], block[pos + 7]
        if rec < 8 or rec % 4 or pos + rec > size or 8 + name_len > rec or ftype > 7:
            return None
        if ino and name_len:
            out.append((ino, ftype, bytes(block[pos + 8:pos + 8 + name_len])))
        pos += rec
    return out if pos == size else None


_CRC32C: list[int] = []


def _crc32c_raw(crc: int, data: bytes) -> int:
    """crc32c from the state `crc`, without the inversions at either end (as ext4 chains its checksums)."""
    if not _CRC32C:
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            _CRC32C.append(c)
    t = _CRC32C
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def _crc32c(data: bytes) -> int:
    return _crc32c_raw(0xFFFFFFFF, data) ^ 0xFFFFFFFF


class _Crc0:
    """crc32c from state 0 of many blocks: by the kernel (its hash interface, AF_ALG) where it answers as the
    table does, else by the table."""

    def __init__(self):
        import socket
        self.op = self.sock = None
        try:
            self.sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
            self.sock.bind(("hash", "crc32c"))
            self.sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, b"\0\0\0\0")
            self.op, _ = self.sock.accept()
            if self(b"123456789") != _crc32c_raw(0, b"123456789"):
                self.close()
        except (OSError, AttributeError):
            self.close()

    def __call__(self, data) -> int:
        if self.op is None:
            return _crc32c_raw(0, data)
        self.op.sendall(data)
        return ~int.from_bytes(self.op.recv(4), "little") & 0xFFFFFFFF

    def close(self) -> None:
        for x in (self.op, self.sock):
            if x is not None:
                x.close()
        self.op = self.sock = None


def _ext4_seed_key(basis: list[int], fs_seed: int, ino: int, gen: int) -> int:
    """What a folder block's stored checksum, XORed with the block's crc32c from state 0, comes to when the
    block is this inode's: its checksum seed (the filesystem's, then the inode number, then its generation)
    run through as many zero bytes as the block has (`basis`: that for each single bit, crc32c being linear)."""
    seed = _crc32c_raw(_crc32c_raw(fs_seed, ino.to_bytes(4, "little")), gen.to_bytes(4, "little"))
    out, i = 0, 0
    while seed:
        if seed & 1:
            out ^= basis[i]
        seed >>= 1
        i += 1
    return out


_XX1, _XX2, _XX3, _XX4, _XX5 = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x85EBCA77C2B2AE63,
                                0x27D4EB2F165667C5)
_U64 = (1 << 64) - 1


def _xx_round(acc: int, value: int) -> int:
    acc = (acc + value * _XX2) & _U64
    acc = ((acc << 31) | (acc >> 33)) & _U64
    return (acc * _XX1) & _U64


def xxhash64(data: bytes, seed: int = 0) -> int:
    """XXH64, which btrfs can checksum its blocks with, in Python: the standard library doesn't have it."""
    n, p = len(data), 0
    rotl = lambda x, r: ((x << r) | (x >> (64 - r))) & _U64  # noqa: E731
    if n >= 32:
        v = [(seed + _XX1 + _XX2) & _U64, (seed + _XX2) & _U64, seed & _U64, (seed - _XX1) & _U64]
        words = _struct.unpack_from(f"<{n // 32 * 4}Q", data)
        for i in range(0, len(words), 4):
            v = [_xx_round(v[0], words[i]), _xx_round(v[1], words[i + 1]), _xx_round(v[2], words[i + 2]),
                 _xx_round(v[3], words[i + 3])]
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & _U64
        for x in v:
            h = ((h ^ _xx_round(0, x)) * _XX1 + _XX4) & _U64
        p = n // 32 * 32
    else:
        h = (seed + _XX5) & _U64
    h = (h + n) & _U64
    while p + 8 <= n:
        h = (rotl(h ^ _xx_round(0, int.from_bytes(data[p:p + 8], "little")), 27) * _XX1 + _XX4) & _U64
        p += 8
    if p + 4 <= n:
        h = (rotl(h ^ (int.from_bytes(data[p:p + 4], "little") * _XX1 & _U64), 23) * _XX2 + _XX3) & _U64
        p += 4
    while p < n:
        h = (rotl(h ^ (data[p] * _XX5 & _U64), 11) * _XX1) & _U64
        p += 1
    h = ((h ^ (h >> 33)) * _XX2) & _U64
    h = ((h ^ (h >> 29)) * _XX3) & _U64
    return h ^ (h >> 32)


def _btrfs_csum_ok(block: bytes, kind: int) -> bool:
    """The tree block's checksum (over all but its first 32 bytes), of whichever kind the filesystem uses: crc32c,
    xxhash64, sha256 or blake2b-256. A kind it doesn't know is never taken for a good checksum."""
    body = block[32:]
    if kind == 0:
        return _crc32c(body).to_bytes(4, "little") == block[:4]
    if kind == 1:
        return xxhash64(body).to_bytes(8, "little") == block[:8]
    if kind == 2:
        return hashlib.sha256(body).digest() == block[:32]
    if kind == 3:
        return hashlib.blake2b(body, digest_size=32).digest() == block[:32]
    return False


BTRFS_CHUNK_ITEM = 228
BTRFS_BG_DATA, BTRFS_BG_SYSTEM, BTRFS_BG_METADATA, BTRFS_BG_DUP = 0x1, 0x2, 0x4, 0x20
BTRFS_BG_PROFILES = 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400
BTRFS_MIXED_GROUPS = 1 << 2                    # incompat: files' data and the trees in the same chunks
BTRFS_CHUNK_NODES = 4096                       # of the chunk tree, read at most


def parse_btrfs_superblock(sb: bytes) -> dict | None:
    """What the scan needs of a btrfs superblock: the fsid its tree blocks carry, sector and node sizes (their own
    bounds: powers of two, 4 KiB to 64 KiB nodes, a node a whole number of sectors), the checksum kind, and where the
    chunk tree is (the bootstrap chunks it is in, its root, this device's id), from which the scan learns where
    tree blocks can be at all."""
    if len(sb) < 0x32b or sb[0x40:0x48] != b"_BHRfS_M":
        return None
    incompat = int.from_bytes(sb[0xbc:0xc4], "little")
    fsid = sb[0x23b:0x24b] if incompat & (1 << 10) else sb[0x20:0x30]       # METADATA_UUID
    sector, node = int.from_bytes(sb[0x90:0x94], "little"), int.from_bytes(sb[0x94:0x98], "little")
    if sector & (sector - 1) or not 512 <= sector <= 65536 or node & (node - 1) or not node or node % sector:
        return None
    array = min(int.from_bytes(sb[0xa0:0xa4], "little"), 2048)
    return {"fsid": bytes(fsid), "sectorsize": sector, "nodesize": node, "csum": int.from_bytes(sb[0xc4:0xc6], "little"),
            "incompat": incompat, "chunk_root": int.from_bytes(sb[0x58:0x60], "little"), "chunk_level": sb[0xc7],
            "devid": int.from_bytes(sb[0xc9:0xd1], "little"), "sys_chunks": bytes(sb[0x32b:0x32b + array])}


def _btrfs_chunk(data: bytes, p: int, logical: int) -> tuple[tuple, int] | None:
    """One btrfs_chunk at `p`: ((logical start, length, type, [(devid, offset)]), its size), or None."""
    if p + 48 > len(data):
        return None
    length, _, _, kind = _struct.unpack_from("<QQQQ", data, p)
    stripes = _struct.unpack_from("<H", data, p + 44)[0]
    size = 48 + 32 * stripes
    if not 0 < stripes <= 16 or p + size > len(data) or not length:
        return None
    return (logical, length, kind, [_struct.unpack_from("<QQ", data, p + 48 + 32 * i) for i in range(stripes)]), size


def _btrfs_sys_chunks(array: bytes) -> list[tuple]:
    """The bootstrap chunks the superblock lists (the system chunks, where the chunk tree is)."""
    out, p = [], 0
    while p + 17 <= len(array):
        _, kind, logical = _struct.unpack_from("<QBQ", array, p)
        if kind != BTRFS_CHUNK_ITEM:
            break
        got = _btrfs_chunk(array, p + 17, logical)
        if got is None:
            break
        out.append(got[0])
        p += 17 + got[1]
    return out


def _btrfs_place(chunks: list[tuple], logical: int, devid: int) -> int | None:
    """Where on this device a logical address is (the first copy of a single or DUP chunk), or None."""
    for start, length, kind, stripes in chunks:
        if start <= logical < start + length and not kind & BTRFS_BG_PROFILES & ~BTRFS_BG_DUP:
            for dev, offset in stripes:
                if dev == devid:
                    return offset + logical - start
    return None


def btrfs_chunk_map(read, fs: dict) -> list[tuple] | None:
    """Every chunk of a single-device btrfs, from its chunk tree (`read(offset, length)` reads the device): the tree
    found through the superblock's bootstrap chunks, each of its blocks checked as the scan checks a leaf (fsid, its
    own address, checksum). None when it can't be read."""
    boot = _btrfs_sys_chunks(fs["sys_chunks"])
    node = fs["nodesize"]
    chunks: dict[int, tuple] = {c[0]: c for c in boot}
    todo, seen, uuid_ = [(fs["chunk_root"], fs["chunk_level"])], set(), None
    while todo:
        logical, level = todo.pop()
        if logical in seen or len(seen) >= BTRFS_CHUNK_NODES or level > 7:
            return None
        seen.add(logical)
        where = _btrfs_place(boot, logical, fs["devid"])
        if where is None:
            return None
        block = read(where, node)
        if len(block) < node or block[32:48] != fs["fsid"] or int.from_bytes(block[48:56], "little") != logical or \
                block[100] != level or not _btrfs_csum_ok(block, fs["csum"]):
            return None
        if uuid_ is None:
            uuid_ = bytes(block[64:80])
        elif bytes(block[64:80]) != uuid_:
            return None
        count = int.from_bytes(block[96:100], "little")
        if level:
            if count > (node - 101) // 33:
                return None
            for i in range(count):
                child = _struct.unpack_from("<Q", block, 101 + 33 * i + 17)[0]
                todo.append((child, level - 1))
            continue
        if count > (node - 101) // 25:
            return None
        for i in range(count):
            _, kind, offset, at, size = _struct.unpack_from("<QBQII", block, 101 + 25 * i)
            if kind != BTRFS_CHUNK_ITEM or at + size > node - 101:
                continue
            got = _btrfs_chunk(block[101 + at:101 + at + size], 0, offset)
            if got is not None:
                chunks[offset] = got[0]
    fs["chunk_uuid"] = uuid_
    return sorted(chunks.values())


def btrfs_tree_places(chunks: list[tuple], devid: int) -> list[tuple[int, int, int]]:
    """Where tree blocks can be on this device: (first byte, byte after the last, logical address of the first) of
    every copy of the metadata and system chunks, sorted. Chunks that hold files' data are left out, mixed ones too:
    a block found anywhere else is a file's content shaped like a tree block."""
    out = []
    for start, length, kind, stripes in chunks:
        if not kind & (BTRFS_BG_METADATA | BTRFS_BG_SYSTEM) or kind & BTRFS_BG_DATA or \
                kind & BTRFS_BG_PROFILES & ~BTRFS_BG_DUP:
            continue
        out += [(offset, offset + length, start) for dev, offset in stripes if dev == devid]
    return sorted(out)


def btrfs_names_at(block: bytes, where: int, fs: dict, owners: set[int]) -> list[tuple[int, int, bytes, int]]:
    """The folder entries of a block found at byte `where` of the device (parse_btrfs_leaf), only if it is a tree block
    btrfs wrote there: inside a metadata or system chunk, carrying the logical address that place has and the
    chunk tree's UUID. Another account can write a file shaped as a leaf, checksum and all (fsid is in /sys/fs/btrfs),
    and have names planted in the caller's list; a file's data is never in those chunks."""
    import bisect
    places = fs.get("places") or []
    i = bisect.bisect_right(places, (where, float("inf"), 0)) - 1
    if i < 0 or not places[i][0] <= where < places[i][1] or where + fs["nodesize"] > places[i][1]:
        return []
    if int.from_bytes(block[48:56], "little") != places[i][2] + where - places[i][0]:
        return []
    if fs.get("chunk_uuid") is not None and bytes(block[64:80]) != fs["chunk_uuid"]:
        return []
    return parse_btrfs_leaf(block, fs, owners)


def parse_btrfs_leaf(block: bytes, fs: dict, owners: set[int]) -> list[tuple[int, int, bytes, int]]:
    """(tree, folder inode, name, transid) for every folder entry a leaf of one of the `owners` trees holds,
    in its items and in stale item headers past them; transid is the transaction that made the entry (its
    btrfs_dir_item's). [] if it isn't such a leaf or its checksum is wrong. Every offset is checked against the
    block: nothing it says can make it read past its end."""
    import struct
    n = fs["nodesize"]
    if len(block) < n or block[32:48] != fs["fsid"] or block[100] != 0:
        return []
    owner = int.from_bytes(block[88:96], "little")
    if owner not in owners:
        return []
    if not _btrfs_csum_ok(block[:n], fs["csum"]):
        return []
    nritems = int.from_bytes(block[96:100], "little")
    if nritems > (n - 101) // 25:
        return []
    data_end = n - 101
    low = min((struct.unpack_from("<I", block, 101 + 25 * i + 17)[0] for i in range(nritems)), default=data_end)
    low = max(min(low, data_end), 25 * nritems)
    out = []
    # the item headers, then the slots after them up to the items' data: stale headers left there
    for i in range(low // 25):
        obj, typ, _, off, size = struct.unpack_from("<QBQII", block, 101 + 25 * i)
        if typ not in (BTRFS_DIR_ITEM, BTRFS_DIR_INDEX) or size <= 30 or off + size > data_end:
            continue
        p, end = 101 + off, 101 + off + size
        while p + 30 <= end:
            transid, data_len, name_len = struct.unpack_from("<QHH", block, p + 17)
            if not name_len or p + 30 + name_len + data_len > end:
                break
            name = bytes(block[p + 30:p + 30 + name_len])
            if _good_name(name):
                out.append((owner, obj, name, transid))
            p += 30 + name_len + data_len
    return out


# ext4's journal: where it is (the superblock keeps a copy of the journal inode's extent tree), and
# which filesystem block each block in it is a copy of (jbd2 descriptor blocks)

def parse_ext4_superblock(sb: bytes) -> dict | None:
    """The block size and where the journal is: {"block_size", "journal"}, journal being "none",
    "external" (on another device), "unknown" (no copy of its inode in the superblock), or the
    60 bytes of the journal inode's block map (`journal_map`)."""
    if len(sb) < 1024 or int.from_bytes(sb[0x38:0x3A], "little") != 0xEF53:
        return None
    out = {"block_size": 1024 << min(int.from_bytes(sb[0x18:0x1C], "little"), 6), "journal": "unknown"}
    compat, incompat = int.from_bytes(sb[0x5C:0x60], "little"), int.from_bytes(sb[0x60:0x64], "little")
    # folder blocks' checksums (metadata_csum; the seed is stored, or made from the UUID), fast commits, and
    # where the inode table is (not with meta_bg, whose group descriptors are spread over the disk)
    out["csum"] = bool(int.from_bytes(sb[0x64:0x68], "little") & 0x400)
    out["seed"] = (int.from_bytes(sb[0x270:0x274], "little") if incompat & 0x2000
                   else _crc32c_raw(0xFFFFFFFF, sb[0x68:0x78])) if out["csum"] else None
    out["fast_commit"] = bool(compat & 0x400)
    per_group, inode_size = int.from_bytes(sb[0x28:0x2C], "little"), int.from_bytes(sb[0x58:0x5A], "little")
    desc = int.from_bytes(sb[0xFE:0x100], "little") if incompat & 0x80 else 32
    if desc & (desc - 1) or not 32 <= desc <= 1024:        # ext4's own bounds (a power of two, 32 to 1024 bytes)
        desc = 0
    blocks = int.from_bytes(sb[0x04:0x08], "little") | (int.from_bytes(sb[0x150:0x154], "little") << 32 if incompat & 0x80 else 0)
    per_group_blocks, first = int.from_bytes(sb[0x20:0x24], "little"), int.from_bytes(sb[0x14:0x18], "little")
    out["inodes"] = None if incompat & 0x10 or not per_group or inode_size < 128 or desc < 32 else {
        "per_group": per_group, "size": inode_size, "desc": desc, "gdt": first + 1,
        "groups": -(-(blocks - first) // per_group_blocks) if per_group_blocks and blocks > first else 0}
    if not compat & 0x4:
        out["journal"] = "none"
    elif incompat & 0x8 or int.from_bytes(sb[0xE0:0xE4], "little") == 0:
        out["journal"] = "external"
    elif sb[0xFD] == 1:                                  # EXT3_JNL_BACKUP_BLOCKS: s_jnl_blocks holds i_block
        out["journal"] = "inode"
        out["journal_map"] = bytes(sb[0x10C:0x10C + 60])
    return out


def ext4_extents(node: bytes, read_block, depth_left: int = 3, _seen: set | None = None) -> list[tuple[int, int, int]] | None:
    """(first logical block, count, first physical block) of an extent tree whose root is `node`
    (an inode's 60-byte block map, or a tree block); `read_block(n)` reads tree blocks further down.
    None if it isn't an extent tree or can't be read. The journal's root is the superblock's copy of its
    map, which the kernel never reads, so a disk that mounts can carry any tree there: one whose index
    entries point at the same block again and again made the root helper list millions of extents (157
    million at worst), so a tree block reached twice, or more than EXT4_EXTENTS_MAX extents, isn't a tree."""
    import struct
    if len(node) < 12:
        return None
    magic, entries, _, depth = struct.unpack_from("<HHHH", node, 0)
    if magic != EXT4_EXTENT_MAGIC or 12 + 12 * entries > len(node) or depth > 5:
        return None
    seen = set() if _seen is None else _seen
    out = []
    for i in range(entries):
        p = 12 + 12 * i
        if depth == 0:
            lblk, length, hi, lo = struct.unpack_from("<IHHI", node, p)
            out.append((lblk, length - 32768 if length > 32768 else length, hi << 32 | lo))
        else:
            if depth_left <= 0:
                return None
            _, lo, hi = struct.unpack_from("<IIH", node, p)
            if hi << 32 | lo in seen:
                return None
            seen.add(hi << 32 | lo)
            child = read_block(hi << 32 | lo)
            sub = ext4_extents(child, read_block, depth_left - 1, seen) if child is not None else None
            if sub is None:
                return None
            out += sub
        if len(out) > EXT4_EXTENTS_MAX:
            return None
    return sorted(out)


def _extent_at(extents: list[tuple[int, int, int]], lblk: int) -> tuple[int, int, int] | None:
    """The extent holding a logical block, from extents sorted by it and not overlapping."""
    import bisect
    i = bisect.bisect_right(extents, (lblk, float("inf"), float("inf"))) - 1
    if i >= 0 and extents[i][0] <= lblk < extents[i][0] + extents[i][1]:
        return extents[i]
    return None


def parse_jbd2_superblock(block: bytes) -> dict | None:
    import struct
    if len(block) < 64:
        return None
    magic, kind = struct.unpack_from(">II", block, 0)
    if magic != JBD2_MAGIC or kind not in (3, 4):
        return None
    bsize, maxlen, first = struct.unpack_from(">III", block, 12)
    incompat = struct.unpack_from(">I", block, 40)[0] if kind == 4 else 0
    if not 1024 <= bsize <= 65536 or not 0 < first < maxlen:
        return None
    return {"block_size": bsize, "maxlen": maxlen, "first": first, "incompat": incompat,
            # the fast-commit area at the journal's end, which the log doesn't wrap into (256 blocks when not said)
            "fast_commit": struct.unpack_from(">I", block, 0x54)[0] or 256 if len(block) >= 0x58 else 256}


def parse_jbd2_descriptor(block: bytes, incompat: int) -> list[int] | None:
    """The filesystem block numbers a descriptor block lists, in the order their copies follow it
    in the journal. None if it isn't a descriptor block."""
    import struct
    if len(block) < 12 or struct.unpack_from(">II", block, 0) != (JBD2_MAGIC, JBD2_DESCRIPTOR):
        return None
    v3, v2, wide = incompat & JBD2_CSUM_V3, incompat & JBD2_CSUM_V2, incompat & JBD2_64BIT
    size = 16 if v3 else (12 + (2 if v2 else 0)) - (0 if wide else 4)
    end = len(block) - (4 if v2 or v3 else 0)    # the checksum tail
    p, out = 12, []
    while p + size <= end:
        if v3:
            lo, flags, hi = struct.unpack_from(">III", block, p)
        else:
            lo, _, flags = struct.unpack_from(">IHH", block, p)
            hi = struct.unpack_from(">I", block, p + 8)[0] if wide else 0
        out.append((hi << 32 | lo) if wide else lo)
        p += size + (0 if flags & JBD2_SAME_UUID else 16)
        if flags & JBD2_LAST_TAG:
            break
    return out


def _aligned_read(fd: int, offset: int, length: int) -> tuple[bytes, int]:
    """`length` bytes at `offset`, read in 4 KiB-aligned pieces as O_DIRECT needs; the unreadable
    bytes (zero-filled) are counted."""
    import mmap
    lo = offset - offset % 4096
    span = (offset + length - lo + 4095) // 4096 * 4096
    buf = mmap.mmap(-1, span)
    try:
        n, bad = _read_window(fd, buf, lo, span)
        data = bytes(buf[offset - lo:offset - lo + length]) if n > offset - lo else b""
        return data, sum(k for _, k in bad)
    finally:
        buf.close()


def _ext4_journal(fd: int, bsize: int) -> tuple[str, list[tuple[int, int, int]], dict | None, int]:
    """Where the ext4 journal is on the device: (state, its extents, its superblock, unreadable
    bytes); state "read" when it was found, otherwise why not ("none", "external", "unknown")."""
    sb, bad = _aligned_read(fd, EXT4_SUPER, 1024)
    fs = parse_ext4_superblock(sb)
    if fs is None or fs["block_size"] != bsize:
        return "unknown", [], None, bad
    if fs["journal"] != "inode":
        return fs["journal"], [], None, bad

    def read_block(n: int) -> bytes | None:
        nonlocal bad
        data, b = _aligned_read(fd, n * bsize, bsize)
        bad += b
        return data or None
    extents = ext4_extents(fs["journal_map"], read_block)
    if not extents or any(a[0] + a[1] > b[0] for a, b in zip(extents, extents[1:])):     # overlapping: not a file's
        return "unknown", [], None, bad
    # nor where they lie on the device: a crafted map could name the same blocks over and over (up to ~512 GiB read
    # for a journal of a few), or blocks past the device's end
    try:
        blocks = os.lseek(fd, 0, os.SEEK_END) // bsize
    except OSError:
        blocks = None
    phys = sorted((p, n) for _, n, p in extents)
    if any(n <= 0 for _, n in phys) or any(a[0] + a[1] > b[0] for a, b in zip(phys, phys[1:])) or (
            blocks is not None and phys[-1][0] + phys[-1][1] > blocks):
        return "unknown", [], None, bad
    jsb = read_block(extents[0][2]) if extents[0][0] == 0 else None
    jsb = parse_jbd2_superblock(jsb or b"")
    if jsb is None or jsb["block_size"] != bsize:
        return "unknown", [], None, bad
    return "read", extents, jsb, bad


def _journal_copies(fd: int, bsize: int, homes: set[int]) -> tuple[str, dict[int, list[bytes]], int, int]:
    """The copies the ext4 journal holds of the filesystem blocks `homes`: (state, home block ->
    copies, journal bytes read, unreadable bytes). Every descriptor in the journal counts, old ones
    too (a copy stays until the journal wraps over it); where a later transaction has since written
    over a copy, what is there now is read, which is what someone with the disk would find."""
    import mmap
    state, extents, jsb, bad = _ext4_journal(fd, bsize)
    if state != "read":
        return state, {}, 0, bad
    first, incompat = jsb["first"], jsb["incompat"]
    maxlen = jsb["maxlen"] - (jsb["fast_commit"] if incompat & JBD2_FAST_COMMIT and jsb["fast_commit"] < jsb["maxlen"] - first else 0)

    def phys(lblk: int) -> int | None:
        e = _extent_at(extents, lblk)
        return None if e is None else e[2] + lblk - e[0]
    wanted: dict[int, int] = {}                          # journal block -> the home block it is a copy of
    read = 0
    buf = mmap.mmap(-1, TRIM_READ)
    try:
        for start, count, p in extents:
            done = 0
            while done < count:
                _check_cancel()
                k = min(count - done, TRIM_READ // bsize)
                n, b = _read_window(fd, buf, (p + done) * bsize, k * bsize)
                bad += sum(x for _, x in b)
                read += n
                for i in range(n // bsize):
                    lblk = start + done + i
                    if not first <= lblk < maxlen:
                        continue
                    tags = parse_jbd2_descriptor(buf[i * bsize:(i + 1) * bsize], incompat)
                    for j, home in enumerate(tags or []):
                        if home in homes:
                            at = lblk + 1 + j
                            wanted[first + (at - first) % (maxlen - first)] = home
                if n < k * bsize:
                    break
                done += k
    finally:
        buf.close()
    copies: dict[int, list[bytes]] = {}
    for lblk, home in sorted(wanted.items()):
        where = phys(lblk)
        if where is None:
            continue
        data, b = _aligned_read(fd, where * bsize, bsize)
        bad += b
        if data:
            copies.setdefault(home, []).append(data)
    return "read", copies, read, bad


def _walk_folders(root: str, uid: int, groups: set[int], own_only: bool, ext4: bool) -> tuple[dict, list, bool, dict]:
    """The folders under `root` the listing may cover: (tree, inode) -> path under root (tree 0 on
    ext4; on btrfs each subvolume's id), for ext4 each folder's blocks, and each folder's generation (ext4:
    by inode; btrfs: by (tree, inode)). Never through a link, never into another mount; with `own_only`, only
    the caller's own folders, otherwise those the caller can open."""
    with _as_caller(uid, _caller()[1], groups):     # and the kernel's own check of the caller's access
        return _walk_folders_as(root, uid, groups, own_only, ext4)


def _walk_folders_as(root: str, uid: int, groups: set[int], own_only: bool, ext4: bool) -> tuple[dict, list, bool, dict]:
    dirs: dict[tuple[int, int], str] = {}
    blocks: list = []
    gens: dict = {}
    trees: dict[int, int] = {}                  # st_dev -> btrfs tree id
    mounts = {_unescape(f[1]) for f in _proc_mounts()}
    full = False
    try:
        rfd = os.open(_p(root), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return dirs, blocks, full, gens

    def allowed(st) -> bool:
        return st.st_uid == uid if own_only else _caller_may(st, uid, groups, 0o5)

    def visit(fd: int, rel: str, depth: int) -> None:
        nonlocal full
        st = os.fstat(fd)
        if ext4:
            tree = 0
        else:
            if st.st_dev not in trees:
                trees[st.st_dev] = BTRFS_TREE_ID(fd)
            tree = trees[st.st_dev]
            if tree is None:
                return
        dirs[(tree, st.st_ino)] = rel
        if not ext4:
            gen = GENERATION(fd)
            if gen is not None:
                gens[(tree, st.st_ino)] = gen       # btrfs: the transaction that made it (see names_step)
        if ext4:
            flags = _dir_flags(fd)
            if not flags & FS_ENCRYPT_FL:
                ext = FIEMAP(fd)
                if ext:
                    blocks.append(((0, st.st_ino), bool(flags & FS_INDEX_FL), ext))
                gen = GENERATION(fd)
                if gen is not None:
                    gens[st.st_ino] = gen
        if depth >= NAMES_DEPTH:
            return
        try:
            entries = [e.name for e in os.scandir(fd) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return
        for name in entries:
            if len(dirs) >= NAMES_DIRS_MAX:
                full = True
                return
            child = f"{rel}/{name}" if rel else name
            if (root.rstrip("/") + "/" + child) in mounts:
                continue                                 # another filesystem mounted here
            try:
                cfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                continue
            try:
                cst = os.fstat(cfd)
                if (not ext4 or cst.st_dev == dev) and allowed(cst):
                    visit(cfd, child, depth + 1)
            finally:
                os.close(cfd)
    try:
        st = os.fstat(rfd)
        dev = st.st_dev
        if allowed(st):
            visit(rfd, "", 0)
        return dirs, blocks, full, gens
    finally:
        os.close(rfd)


def _btrfs_tree_id(fd: int) -> int | None:
    """The id of the subvolume holding this folder (BTRFS_IOC_INO_LOOKUP)."""
    import fcntl
    try:
        args = bytearray(4096)
        args[8:16] = (256).to_bytes(8, "little")
        fcntl.ioctl(fd, BTRFS_IOC_INO_LOOKUP, args, True)
        return int.from_bytes(args[0:8], "little")
    except OSError:
        return None


BTRFS_TREE_ID = _btrfs_tree_id                 # tests replace it


# ext4: the names in the journal's copies of folder blocks (see the notes above)

def _journal_left(j: dict) -> bool:
    return j["state"] == "read" and j["pos"] < j["total"]


def _ext4_checkpoint(s: dict, flags: int) -> None:
    """EXT4_IOC_CHECKPOINT on the filesystem listed: with the zero-out flag the kernel writes everything in
    the journal to its place and then zeroes the journal; with the dry-run flag it only says whether it can."""
    import fcntl
    try:
        fd = os.open(_p(_unescape(s["mount"])), os.O_RDONLY | os.O_DIRECTORY)
    except OSError as e:
        raise Refused(f"the filesystem couldn't be opened: {e.strerror}") from None
    try:
        if os.fstat(fd).st_dev != s["rdev"]:
            raise Refused("another filesystem is mounted there now")
        fcntl.ioctl(fd, EXT4_IOC_CHECKPOINT, flags.to_bytes(4, sys.byteorder))
    except OSError as e:
        if e.errno in (errno.ENOTTY, errno.EINVAL, errno.EOPNOTSUPP):
            raise Refused("this kernel can't clear the journal (Linux 5.14 and later can)") from None
        raise Refused(f"the kernel refused to clear the journal: {e.strerror}") from None
    finally:
        os.close(fd)


CHECKPOINT = _ext4_checkpoint                  # tests replace it


def _names_journal_begin(s: dict, gens: dict[int, int]) -> dict:
    """Where the journal is, what ties a folder block in it to a listed folder (each folder's key, see
    _ext4_seed_key), and whether this kernel can clear it."""
    bsize = os.statvfs(_p(s["home"])).f_bsize
    j = {"state": "unknown", "extents": [], "bsize": bsize, "pos": 0, "total": 0, "csum": False, "seed": None,
         "fast_commit": False, "inodes": None, "keys": {}, "basis": [], "orphans": {}, "norphans": 0, "kids": {},
         "names": 0, "full": False, "clearable": False, "pending": {}, "wrapped": {}, "weak": [], "owner": {},
         "first": 1, "last": 0, "incompat": 0, "itable": [], "icopies": {}, "nicopies": 0}
    s["jfound"] = {}
    fd = _names_device(s)
    try:
        sb, _ = _aligned_read(fd, EXT4_SUPER, 1024)
        fs = parse_ext4_superblock(sb)
        state, extents, jsb, _ = _ext4_journal(fd, bsize)
        if state == "read" and fs is not None and fs["csum"] and fs["inodes"]:
            j["itable"] = _ext4_inode_tables(fd, fs["inodes"], bsize, s.get("size"))
    finally:
        os.close(fd)
    j["state"] = state
    if state != "read" or fs is None:
        return j
    fast = fs["fast_commit"] or bool(jsb["incompat"] & JBD2_FAST_COMMIT)
    j.update(extents=extents, total=max(a + n for a, n, _ in extents), csum=fs["csum"] and bsize > 12, seed=fs["seed"],
             fast_commit=fast, inodes=fs["inodes"], first=jsb["first"], incompat=jsb["incompat"],
             last=jsb["maxlen"] - (jsb["fast_commit"] if fast and jsb["fast_commit"] < jsb["maxlen"] - jsb["first"] else 0))
    if j["csum"]:
        j["basis"] = [_crc32c_raw(1 << i, bytes(bsize - 12)) for i in range(32)]
        j["keys"] = {_ext4_seed_key(j["basis"], fs["seed"], ino, gen): ino for ino, gen in gens.items()}
        for key, _, ext in s["blocks"]:
            for phys, length in ext:
                for b in range(phys // bsize, (phys + min(length, NAMES_DIR_BYTES)) // bsize):
                    j["owner"][b] = key[1]
    try:
        CHECKPOINT(s, EXT4_CHECKPOINT_DRY_RUN)
        j["clearable"] = True
    except Refused:
        pass
    return j


def _journal_folder_block(s: dict, ino: int, block: bytes) -> None:
    """A copy of one of the listed folder's blocks: its names (those of files deleted since are live entries
    in it), and the subfolders it names."""
    j = s["j"]
    if j["names"] >= NAMES_JOURNAL_NAMES:
        j["full"] = True
        return
    found = s["jfound"].setdefault((0, ino), set())
    before = len(found)
    found |= parse_ext4_dir_block(block, live=True)
    j["names"] += len(found) - before
    for cino, ftype, name in ext4_dir_entries(block[:-12]) or []:
        if ftype == 2 and name not in (b".", b".."):
            j["kids"].setdefault(ino, {})[name] = cino


def _names_journal_step(s: dict, fd: int) -> None:
    """Reads the next part of the journal for folder blocks. With metadata_csum: the blocks ending in a
    folder block's tail; one whose checksum fits a listed folder is that folder's, the others are remembered
    by where they are (for folders that are gone, and names_orphans). Without: every block that is laid out
    as a folder block, none of which can be tied to a folder."""
    import mmap
    j = s["j"]
    bsize, n = j["bsize"], j["bsize"] - 12
    crc = _Crc0() if j["csum"] else None
    buf = mmap.mmap(-1, TRIM_READ)
    budget = NAMES_JOURNAL_STEP // bsize
    try:
        while budget > 0 and _journal_left(j):
            _check_cancel()
            ext = _extent_at(j["extents"], j["pos"])
            if ext is None:                              # a hole in the journal's file
                j["pos"] = min((a for a, _, _ in j["extents"] if a > j["pos"]), default=j["total"])
                continue
            a, c, p = ext
            k = min(a + c - j["pos"], TRIM_READ // bsize, budget)
            got, bad = _read_window(fd, buf, (p + j["pos"] - a) * bsize, k * bsize)
            s["unreadable"] += sum(x for _, x in bad)
            for i in range(max(got, 0) // bsize):
                at, blk = i * bsize, j["pos"] + i
                if j["csum"]:
                    home = j["pending"].pop(blk, None)
                    if buf[at:at + 4] == JBD2_MAGIC_BYTES:           # the journal's own block: a descriptor says
                        for t, of in enumerate(parse_jbd2_descriptor(buf[at:at + bsize], j["incompat"]) or []):
                            to = j["first"] + (blk + 1 + t - j["first"]) % max(j["last"] - j["first"], 1)
                            (j["pending"] if to > blk else j["wrapped"])[to] = of     # which block each copy is of
                            if j["nicopies"] < NAMES_ITABLE_MAX and _in_ranges(j["itable"], of):
                                j["icopies"].setdefault(of, []).append(to)            # a copy of part of the inode table
                                j["nicopies"] += 1
                        continue
                    if buf[at + n:at + n + 8] != EXT4_DIR_TAIL:
                        continue
                    key = int.from_bytes(buf[at + bsize - 4:at + bsize], "little") ^ crc(buf[at:at + n])
                    ino = j["keys"].get(key)
                    if ino is not None and home is not None and j["owner"].get(home) == ino:
                        _journal_folder_block(s, ino, buf[at:at + bsize])
                        continue
                    if ino is not None and len(j["weak"]) < NAMES_WEAK_MAX:      # decided once the journal is read
                        j["weak"].append((blk, ino, key, buf[at:at + bsize]))
                        continue
                else:
                    entries = ext4_dir_entries(buf[at:at + bsize])
                    if not entries or not all(_good_name(name) or name in (b".", b"..") for _, _, name in entries):
                        continue
                    key = 0
                if j["norphans"] < NAMES_ORPHANS_MAX:
                    j["orphans"].setdefault(key, []).append(j["pos"] + i)
                j["norphans"] += 1
            j["pos"] += k
            budget -= k
    finally:
        buf.close()
        if crc is not None:
            crc.close()


def _names_journal_weak(s: dict) -> None:
    """The copies whose checksum fits a listed folder, but which the journal didn't say are of a block that
    folder has now (a block it gave up, or a descriptor whose copies wrapped to the journal's start): the
    folder's when a wrapped descriptor says so after all, when the block names the folder as itself, or
    when an entry in it is a file the folder holds now, under that name and inode; else no folder's."""
    j = s["j"]
    mounts = {_unescape(f[1]) for f in _proc_mounts()}
    for blk, ino, key, block in j.pop("weak", []):
        rel = s["dirs"].get((0, ino))
        tied = rel is not None and j["owner"].get(j["wrapped"].get(blk)) == ino
        if rel is not None and not tied:
            entries = ext4_dir_entries(block[:-12]) or []
            tied = any(cino == ino for cino, _, name in entries if name == b".")
            if not tied:
                # looked up in the folder as the listing reached it, never by a path that root would follow through
                # a link put on the way (_live)
                try:
                    fd = _open_kept(s, rel, mounts)
                except Refused:
                    fd = None
                if fd is not None:
                    try:
                        if os.fstat(fd).st_ino == ino:
                            tied = any(name not in (b".", b"..") and _entry_ino(fd, name) == cino
                                       for cino, _, name in entries)
                    finally:
                        os.close(fd)
        if tied:
            _journal_folder_block(s, ino, block)
        else:
            if j["norphans"] < NAMES_ORPHANS_MAX:
                j["orphans"].setdefault(key, []).append(blk)
            j["norphans"] += 1


def _journal_block(fd: int, j: dict, lblk: int) -> bytes | None:
    e = _extent_at(j["extents"], lblk)
    if e is None:
        return None
    a, _, p = e
    data, bad = _aligned_read(fd, (p + lblk - a) * j["bsize"], j["bsize"])
    return data if len(data) == j["bsize"] and not bad else None


def _ext4_group_table(desc: bytes, size: int) -> int:
    return int.from_bytes(desc[8:12], "little") | (int.from_bytes(desc[0x28:0x2C], "little") << 32 if size >= 64 else 0)


def _ext4_inode_tables(fd: int, g: dict, bsize: int, dev_size: int | None = None) -> list[tuple[int, int]]:
    """Where the inode tables are: [(first block, block after the last)], sorted and joined, from the group
    descriptors. [] when they can't be read (the journal's copies of them then go unused). The descriptors are
    read a few MiB at a time, and never more of them than the device can hold (the superblock's counts are the
    disk's word, which nothing checks before this reads them)."""
    if not 0 < g["groups"] <= 1 << 20:
        return []
    if dev_size is not None and (g["gdt"] * bsize + g["groups"] * g["desc"] > dev_size
                                 or g["groups"] * g["per_group"] * g["size"] > dev_size):
        return []
    tables, step = [], max(1, (4 << 20) // g["desc"])
    for first in range(0, g["groups"], step):
        count = min(step, g["groups"] - first)
        data, bad = _aligned_read(fd, g["gdt"] * bsize + first * g["desc"], count * g["desc"])
        if bad or len(data) < count * g["desc"]:
            return []
        tables += [_ext4_group_table(data[i * g["desc"]:(i + 1) * g["desc"]], g["desc"]) for i in range(count)]
    length = -(-g["per_group"] * g["size"] // bsize)
    out: list[tuple[int, int]] = []
    for table in sorted(tables):
        if not table:
            continue
        if out and table <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], table + length))
        else:
            out.append((table, table + length))
    return out


def _in_ranges(ranges: list[tuple[int, int]], n: int) -> bool:
    import bisect
    i = bisect.bisect_right(ranges, (n, float("inf"))) - 1
    return i >= 0 and ranges[i][0] <= n < ranges[i][1]


def _ext4_inode_gens(fd: int, j: dict, ino: int) -> dict[int, tuple[bool, set[tuple[int, int, int]]]]:
    """Each generation an inode number is on record with: whether a record has it deleted then (a deletion
    time, no links), and the owner, group and mode each record gives it (uid, gid, mode): the inode table as it
    is, and the journal's copies of that block of it. The generation changes whenever the number is used
    again, so an older one is a file or folder that is gone."""
    g = j["inodes"]
    if not g or ino < 1:
        return {}
    group, index = divmod(ino - 1, g["per_group"])
    desc, bad = _aligned_read(fd, g["gdt"] * j["bsize"] + group * g["desc"], g["desc"])
    if bad or len(desc) < g["desc"] or not _ext4_group_table(desc, g["desc"]):
        return {}
    block, at = divmod(index * g["size"], j["bsize"])
    block += _ext4_group_table(desc, g["desc"])
    home, bad = _aligned_read(fd, block * j["bsize"], j["bsize"])
    out: dict[int, tuple[bool, set[tuple[int, int, int]]]] = {}
    # the latest copies of that part of the table, a bounded number: a journal crafted to hold the same block
    # thousands of times made every folder looked up read all of them
    copies = j["icopies"].get(block, [])[-NAMES_INODE_COPIES:]
    for data in [None if bad else home] + [_journal_block(fd, j, lblk) for lblk in copies]:
        if data is None or len(data) < at + 128:
            continue
        raw = data[at:at + 128]
        gen = int.from_bytes(raw[0x64:0x68], "little")
        deleted = bool(int.from_bytes(raw[0x14:0x18], "little")) and not int.from_bytes(raw[0x1A:0x1C], "little")
        # i_uid and i_gid: the low halves, and the high ones in osd2 (l_i_uid_high, l_i_gid_high); a deleted
        # inode keeps them
        uid = int.from_bytes(raw[0x02:0x04], "little") | int.from_bytes(raw[0x78:0x7A], "little") << 16
        gid = int.from_bytes(raw[0x18:0x1A], "little") | int.from_bytes(raw[0x7A:0x7C], "little") << 16
        was, owners = out.get(gen, (False, set()))
        out[gen] = (was or deleted, owners | {(uid, gid, int.from_bytes(raw[0x00:0x02], "little"))})
    return out


def _inode_live(s: dict, ino: int, gen: int) -> bool | None:
    """Whether the filesystem has an inode of this number and generation in use now, asked of the kernel as
    an NFS server asks (open_by_handle_at with ext4's handle of the two): it says "stale" for one that was
    deleted or used again. None when it can't be asked."""
    import struct
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        handle = ctypes.create_string_buffer(struct.pack("=IiII", 8, 1, ino & 0xFFFFFFFF, gen))     # FILEID_INO32_GEN
        mfd = os.open(_p(_unescape(s["mount"])), os.O_RDONLY | os.O_DIRECTORY)
    except (ImportError, OSError, AttributeError):
        return None
    try:
        if os.fstat(mfd).st_dev != s["rdev"]:
            return None
        fd = libc.open_by_handle_at(mfd, handle, os.O_PATH)
        if fd >= 0:
            os.close(fd)
            return True
        return False if ctypes.get_errno() == errno.ESTALE else None
    except (OSError, AttributeError):
        return None
    finally:
        os.close(mfd)


INODE_LIVE = _inode_live                       # tests replace it


def _names_gone_folders(s: dict, fd: int) -> list[tuple[str, set[bytes]]]:
    """Folders that are gone, with the names their blocks in the journal hold: (path under the top, names).
    One counts when a copy of a listed folder (or of a gone folder found this way) names it as a subfolder,
    no inode of that number and generation exists now (the kernel says; where it can't be asked, a record
    of the inode table must have it deleted), blocks in the journal carry that inode's checksum, and one of
    them is its first block, naming itself and that parent. And it must have been a folder the listing would
    have covered while it was there, by the same rule (the caller's own, or one they could open: every record
    of its inode says so): another account's private folder deleted from a shared one stays tied to nothing,
    counted, and named only when asked for (names_orphans). Their blocks leave the ones tied to no folder."""
    j = s["j"]
    if not j["csum"] or not j["inodes"] or not j["orphans"]:
        return []
    n = j["bsize"] - 12
    uid = s["uid"]
    groups = s.get("groups", set())

    def covered(owner: tuple[int, int, int]) -> bool:
        o_uid, o_gid, mode = owner
        if s["own_only"]:
            return o_uid == uid
        st = os.stat_result((mode, 0, 0, 0, o_uid, o_gid, 0, 0, 0, 0))
        return _caller_may(st, uid, groups, 0o5)

    out, seen, looked = [], set(), 0
    budget = [NAMES_GONE_READS]                     # journal blocks read for this, all folders together
    queue = [(ino, s["dirs"][(0, ino)], kids) for ino, kids in j["kids"].items() if (0, ino) in s["dirs"]]
    while queue:
        _check_cancel()
        parent, rel, kids = queue.pop()
        for name, ino in kids.items():
            if (0, ino) in s["dirs"] or ino in seen or looked >= NAMES_GONE_MAX:
                continue
            seen.add(ino)
            looked += 1
            key, blocks = None, []
            for gen, (deleted, owners) in _ext4_inode_gens(fd, j, ino).items():
                key = _ext4_seed_key(j["basis"], j["seed"], ino, gen)
                if key not in j["orphans"]:
                    continue
                if not all(covered(o) for o in owners):              # not the caller's to see: stays untied
                    continue
                live = INODE_LIVE(s, ino, gen)
                if live or (live is None and not deleted):           # a folder there now, which the listing doesn't cover
                    continue
                blocks = []
                for lblk in j["orphans"][key][-NAMES_GONE_PER_KEY:]:
                    if budget[0] <= 0:
                        break
                    budget[0] -= 1
                    b = _journal_block(fd, j, lblk)
                    if b is not None and b[n:n + 8] == EXT4_DIR_TAIL and \
                            int.from_bytes(b[-4:], "little") ^ _crc32c_raw(0, b[:n]) == key:  # still what it was
                        blocks.append((b, ext4_dir_entries(b[:n]) or []))
                if any(len(e) >= 2 and e[0][0] == ino and e[0][2] == b"." and e[1][0] == parent and e[1][2] == b".."
                       for _, e in blocks):
                    break
                blocks = []
            if not blocks:
                continue
            j["norphans"] -= len(j["orphans"].pop(key))
            names, sub = set(), {}
            for b, entries in blocks:
                names |= parse_ext4_dir_block(b, live=True)
                sub.update({x: i for i, ftype, x in entries if ftype == 2 and x not in (b".", b"..")})
            child = (rel + "/" if rel else "") + os.fsdecode(name)
            out.append((child, names))
            queue.append((ino, child, sub))
    return out


def names_begin(args: dict) -> dict:
    """{"mount"}: starts looking for names of deleted files on a filesystem the TRIM test may run
    on: the caller's own folders under their home on the home's filesystem, every folder the
    caller can open on another. Returns how much there is to do first (folders on ext4, bytes on btrfs);
    on ext4 the journal follows, and names_step says when there is no more."""
    import mmap
    _must_be_root()
    uid, gid, home = _caller()
    f = _trim_mount(args.get("mount"))
    target = _unescape(f[1])
    h = _holding(_proc_mounts(), home)
    if h is not None and (_unescape(h[1]) == target or h[0] == f[0]):
        root, own_only = home, True              # the home's own filesystem, or a subvolume of the one named
    elif target == "/":
        raise Refused("on the system disk, only your home folder's names are listed, and it is on another filesystem")
    else:
        root, own_only = target, False
    real, st = _fs_device(f)
    ext4 = f[2] == "ext4"
    _NAMES.clear()
    groups = _caller_groups(uid, gid)
    dirs, blocks, full, gens = _walk_folders(root, uid, groups, own_only, ext4)
    state = {"uid": uid, "gid": gid, "home": root, "scope": "home" if own_only else "mount", "fstype": f[2], "device": real,
             "rdev": st.st_rdev, "ino": st.st_ino, "size": _device_size(real), "dirs": dirs, "blocks": blocks,
             "done": 0, "found": {}, "full": full, "trees": {k[0] for k in dirs}, "unreadable": 0, "mount": f[1],
             "own_only": own_only, "groups": groups}
    if ext4:
        state["total"] = len(blocks)
        state["j"] = _names_journal_begin(state, gens)
    else:
        state["gens"] = gens
        fd = _trim_open(real)
        buf = mmap.mmap(-1, 4096)
        try:
            n = os.preadv(fd, [buf], BTRFS_SUPER)
            fs = parse_btrfs_superblock(bytes(buf[:n]))
            # each cause said apart (the page shows it after "The helper refused: "), never one message for three
            if fs is None:
                raise Refused("the btrfs filesystem's superblock (the record of where everything on it is) couldn't "
                              "be read")
            if not 4096 <= fs["nodesize"] <= 65536:
                raise Refused(f"the btrfs filesystem uses a node size of {fs['nodesize']} bytes, which the tool "
                              "doesn't read")
            if fs["incompat"] & BTRFS_MIXED_GROUPS:
                raise Refused("this btrfs filesystem keeps files' contents and its own records in the same places "
                              "(mixed block groups, as small filesystems have), so names can't be told from what a "
                              "file holds")
            chunks = btrfs_chunk_map(lambda at, length: _aligned_read(fd, at, length)[0], fs)
        finally:
            buf.close()
            os.close(fd)
        if chunks is None:
            raise Refused("the btrfs filesystem's chunk tree (the record of where its own records can be) couldn't be "
                          "read")
        fs["places"] = btrfs_tree_places(chunks, fs["devid"])
        if not state["trees"]:
            raise Refused("none of the btrfs filesystem's folders is yours to list")
        state.update(fs=fs, total=state["size"])
    _NAMES.update(state)
    return {"fstype": f[2], "folders": len(dirs), "total": state["total"], "unit": "folders" if ext4 else "bytes",
            "scope": state["scope"], "root": root,
            "journal": {"state": state["j"]["state"], "bytes": state["j"]["total"] * state["j"]["bsize"]} if ext4 else None}


def _names_state() -> dict:
    if not _NAMES or _NAMES.get("uid") != _caller()[0]:
        raise Refused("not looking for names")
    return _NAMES


def _names_device(s: dict) -> int:
    fd = _trim_open(s["device"])
    st = os.fstat(fd)
    if (st.st_rdev, st.st_ino) != (s["rdev"], s["ino"]):
        os.close(fd)
        raise Refused("the device changed")
    return fd


def _add_name(s: dict, key: tuple[int, int], name: bytes) -> None:
    if key in s["dirs"]:
        s["found"].setdefault(key, set()).add(name)


def _dir_names(fd: int, buf, ext: list, indexed: bool, bsize: int, live: bool = False, tie: int | None = None,
               crc=None) -> tuple[set[bytes], int]:
    """The names in a folder's blocks at `ext` (deleted ones; with `live`, all): (names, unreadable bytes). `tie`:
    the folder's checksum key (_ext4_seed_key), which each block must carry to be read as the folder's."""
    names, bad, first = set(), 0, True
    n_tail = bsize - 12
    for phys, length in ext:
        length = min(length, NAMES_DIR_BYTES)
        if phys % 4096 or length % bsize:
            continue
        n, b = _read_window(fd, buf, phys, length)
        bad += sum(k for _, k in b)
        for at in range(0, n - bsize + 1, bsize):
            block = buf[at:at + bsize]
            if tie is not None and (block[n_tail:n_tail + 8] != EXT4_DIR_TAIL or
                                    int.from_bytes(block[-4:], "little") ^ (crc or _crc32c_raw_0)(block[:n_tail]) != tie):
                first = False
                continue                               # not that folder's block now (its index, or another's)
            names |= parse_ext4_dir_block(block, skip_index=indexed and first, live=live)
            first = False
    return names, bad


def _crc32c_raw_0(data) -> int:
    return _crc32c_raw(0, data)


def names_step(args: dict) -> dict:
    """Does the next part: up to NAMES_STEP_DIRS folders (ext4) or a gibibyte of the device (btrfs)."""
    import mmap
    _must_be_root()
    s = _names_state()
    if s.get("handed"):
        raise Refused("this listing is done")
    fd = _names_device(s)
    try:
        if s["fstype"] == "ext4" and s["done"] >= len(s["blocks"]):
            _names_journal_step(s, fd)
        elif s["fstype"] == "ext4":
            bsize = os.statvfs(_p(s["home"])).f_bsize
            buf = mmap.mmap(-1, NAMES_DIR_BYTES)
            j = s["j"]
            # a folder's blocks were found at names_begin, and are read now: by then the folder may be gone and its
            # blocks another account's. With metadata_csum each block must still carry that folder's checksum (its
            # inode number and generation); without, the folder is opened again as the listing reached it and its
            # blocks asked for again
            keys = {ino: key for key, ino in j.get("keys", {}).items()} if j.get("csum") else {}
            crc = _Crc0() if keys else None
            mounts = {_unescape(f[1]) for f in _proc_mounts()}
            try:
                for key, indexed, ext in s["blocks"][s["done"]:s["done"] + NAMES_STEP_DIRS]:
                    if s["done"] % 64 == 0:
                        _check_cancel()
                    tie = keys.get(key[1])
                    if tie is None:
                        ext = _extents_now(s, key, mounts)
                    names, bad = _dir_names(fd, buf, ext or [], indexed, bsize, tie=tie, crc=crc)
                    s["unreadable"] += bad
                    for name in names:
                        _add_name(s, key, name)
                    s["done"] += 1
            finally:
                buf.close()
                if crc is not None:
                    crc.close()
        else:
            fs, node = s["fs"], s["fs"]["nodesize"]
            buf = mmap.mmap(-1, TRIM_READ)
            try:
                start = s["done"]
                end = min(start + TRIM_CALL_MAX, s["size"])
                pos = covered = start
                while pos < end:
                    _check_cancel()
                    want = min(TRIM_READ, s["size"] - pos)
                    n, bad = _read_window(fd, buf, pos, want)
                    if n <= 0:
                        break
                    s["unreadable"] += sum(o + k - max(o, covered) for o, k in bad if o + k > covered)
                    covered = pos + n
                    i = buf.find(fs["fsid"], 0, n)
                    while i != -1:
                        at = i - 32
                        if at >= 0 and (pos + at) % fs["sectorsize"] == 0 and at + node <= n:
                            try:
                                found = btrfs_names_at(bytes(buf[at:at + node]), pos + at, fs, s["trees"])
                            except (_struct.error, ValueError, IndexError, KeyError):
                                found = []                 # a block that only looked like one: never stops the listing
                                s["bad_blocks"] = s.get("bad_blocks", 0) + 1
                            for tree, ino, name, transid in found:
                                # an entry older than the folder of that number is a previous holder's: btrfs
                                # uses an inode number again (the highest ones, after a remount), and a stale
                                # block of another account's deleted folder would be tied to the caller's
                                # folder by tree and number alone. A folder's generation is the transaction
                                # that made it (FS_IOC_GETVERSION: 32 bits), and every entry in it is newer.
                                if transid & 0xFFFFFFFF < s["gens"].get((tree, ino), 0):
                                    continue
                                _add_name(s, (tree, ino), name)
                        i = buf.find(fs["fsid"], i + 1, n)
                    # overlap, so a block across two reads is seen whole; a short read (the end) moves on by itself
                    pos += n if pos + n >= s["size"] or n <= node else n - node
                s["done"] = min(pos, s["size"])
            finally:
                buf.close()
    finally:
        os.close(fd)
    if s["fstype"] == "ext4":
        j = s["j"]
        if s["done"] < len(s["blocks"]) or not j["pos"]:
            return {"done": s["done"], "total": s["total"], "unit": "folders", "phase": "folders",
                    "more": s["done"] < len(s["blocks"]) or _journal_left(j)}
        return {"done": j["pos"] * j["bsize"], "total": j["total"] * j["bsize"], "unit": "bytes", "phase": "journal",
                "more": _journal_left(j)}
    return {"done": s["done"], "total": s["total"], "unit": "bytes", "phase": "disk", "more": s["done"] < s["total"]}


def _live(s: dict, rel: str, names) -> set[bytes]:
    """Those of `names` that a file in the folder at `rel` has now: looked up in that folder as the listing reached
    it (_open_kept), never by a path, which root would follow through a link the caller put on the way (a guess
    at every name in /root/.ssh, answered)."""
    try:
        fd = _open_kept(s, rel)
    except Refused:
        return set()
    try:
        return {n for n in names if _entry_ino(fd, n) is not None}
    finally:
        os.close(fd)


def _entry_ino(fd: int, name: bytes) -> int | None:
    """The inode of the entry `name` in the folder open at `fd` (never following it, if it is a link), or None."""
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False).st_ino
    except (OSError, ValueError):
        return None


def _extents_now(s: dict, key: tuple[int, int], mounts: set[str] | None = None) -> list | None:
    """A listed folder's blocks as they are now (FIEMAP), the folder opened as the listing reached it and checked to
    be the same one (its inode); None when it isn't there any more."""
    rel = s["dirs"].get(key)
    if rel is None:
        return None
    try:
        fd = _open_kept(s, rel, mounts)
    except Refused:
        return None
    try:
        if os.fstat(fd).st_ino != key[1]:
            return None
        return FIEMAP(fd)
    finally:
        os.close(fd)


def names_result(args: dict) -> dict:
    """The names found whose file is gone from its folder now, by folder. Handed over once: the
    heavy state goes, and what the checks after a clean-up need (each folder's names and where its
    blocks were) stays until names_end."""
    _must_be_root()
    s = _names_state()
    if s.get("handed"):
        raise Refused("the names were handed over already")
    folders, count, more = [], 0, False
    blocks = {key: (indexed, ext) for key, indexed, ext in s["blocks"]}
    kept: dict[str, dict] = {}
    gone_folders: list[tuple[str, set[bytes]]] = []
    j = s.get("j")
    if j is not None:
        fd = _names_device(s)
        try:
            while _journal_left(j):                      # a caller that stopped stepping after the folders
                _names_journal_step(s, fd)
            _names_journal_weak(s)
            gone_folders = _names_gone_folders(s, fd)
        finally:
            os.close(fd)
    jfound = s.get("jfound", {})
    rows = []                                            # (path, key, names in its blocks, names in the journal)
    for key in set(s["found"]) | set(jfound):
        rel = s["dirs"][key]
        own, old = s["found"].get(key, set()), jfound.get(key, set())
        live = _live(s, rel, own | old)
        rows.append((rel, key, own - live, old - live))
    rows += [(rel, None, set(), names) for rel, names in gone_folders]
    only = 0
    for rel, key, own, old in sorted(rows, key=lambda r: (r[0], r[1] is None)):
        gone = sorted(own | old)
        if not gone:
            continue
        if count + len(gone) > NAMES_MAX:
            gone, more = gone[:NAMES_MAX - count], True
        shown = os.fsencode(rel).decode(errors="replace")
        entry = {"path": shown, "names": [n.decode() for n in gone]}
        journal = [n.decode() for n in gone if n not in own]
        if journal:                                      # the names only the journal holds
            entry["journal"] = journal
            only += len(journal)
        if key is None:
            entry["gone"] = True                         # the folder itself is gone: nothing of it to clean
        else:
            indexed, ext = blocks.get(key, (False, []))
            kept[shown] = {"rel": rel, "names": set(gone), "ext": ext, "indexed": indexed}
        folders.append(entry)
        count += len(gone)
        if more:
            break
    result = {"folders": folders, "count": count, "truncated": more or s["full"] or bool(j and j["full"]),
              "fstype": s["fstype"], "scope": s["scope"], "root": s["home"], "unreadable": s["unreadable"]}
    if j is not None:
        result["journal"] = {"state": j["state"], "bytes": j["total"] * j["bsize"], "names": only,
                             "orphans": j["norphans"], "clearable": j["clearable"], "fast_commit": j["fast_commit"],
                             "checksums": j["csum"]}
        for k in ("keys", "kids", "basis", "pending", "wrapped", "owner", "itable", "icopies"):
            j.pop(k, None)
    for k in ("dirs", "blocks", "found", "trees", "jfound"):
        s.pop(k, None)
    s.update(handed=True, kept=kept)
    return result


def _kept(s: dict, path) -> dict:
    if not s.get("handed"):
        raise Refused("the names haven't been listed yet")
    if not isinstance(path, str) or path not in s["kept"]:
        raise Refused("that folder isn't in the list")
    return s["kept"][path]


def _open_kept(s: dict, rel: str, mounts: set[str] | None = None) -> int:
    """The folder at `rel` under the listing's top, opened as the listing reached it: one name at a
    time, never through a link, never into another mount or filesystem, each folder one the
    listing may cover, and opened with the caller's own file access (_as_caller)."""
    if s.get("gid") is not None and s.get("groups") is not None:     # the listing's own, looked up once
        uid, gid, groups = s["uid"], s["gid"], s["groups"]
    else:
        uid, gid, _ = _caller()
        groups = _caller_groups(uid, gid)
    if mounts is None:
        mounts = {_unescape(f[1]) for f in _proc_mounts()}
    with _as_caller(uid, gid, groups):
        return _open_kept_as(s, rel, uid, groups, mounts)


def _open_kept_as(s: dict, rel: str, uid: int, groups: set[int], mounts: set[str]) -> int:
    try:
        fd = os.open(_p(s["home"]), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise Refused("that folder can't be read") from None
    try:
        dev = os.fstat(fd).st_dev
        path = s["home"].rstrip("/")
        parts = [x for x in rel.split("/") if x] if rel else []
        for part in [None] + parts:
            if part is not None:
                path += "/" + part
                if part in (".", "..") or path in mounts:
                    raise Refused("that folder can't be read")
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nfd
            st = os.fstat(fd)
            if st.st_dev != dev or not (st.st_uid == uid if s["own_only"] else _caller_may(st, uid, groups, 0o5)):
                raise Refused("that folder can't be read")
        return fd
    except OSError:
        os.close(fd)
        raise Refused("that folder isn't there any more") from None
    except BaseException:
        os.close(fd)
        raise


def names_folder(args: dict) -> dict:
    """{"path"}: reads one listed folder's blocks again (ext4) and returns which of the names
    listed for it are still there: after each filler the app writes into it."""
    import mmap
    _must_be_root()
    s = _names_state()
    k = _kept(s, args.get("path"))
    if s["fstype"] != "ext4":
        raise Refused("only on ext4")
    dfd = _open_kept(s, k["rel"])
    try:
        ext = FIEMAP(dfd) or []
        indexed = bool(_dir_flags(dfd) & FS_INDEX_FL)
    finally:
        os.close(dfd)
    fd = _names_device(s)
    buf = mmap.mmap(-1, NAMES_DIR_BYTES)
    try:
        names, bad = _dir_names(fd, buf, ext, indexed, os.statvfs(_p(s["home"])).f_bsize)
    finally:
        buf.close()
        os.close(fd)
    left = (names & k["names"]) - _live(s, k["rel"], k["names"])
    return {"left": sorted(n.decode() for n in left), "unreadable": bad}


def names_check(args: dict) -> dict:
    """{"paths"}: after a clean-up of these listed folders (ext4), where their listed names can
    still be read: in the folder's blocks now, in the blocks it had when it was listed (freed by a
    rebuild: trimmed, reused or still there), and in the journal's copies of either. Counts per
    place and the names left, per folder."""
    import mmap
    _must_be_root()
    s = _names_state()
    paths = args.get("paths")
    if s["fstype"] != "ext4":
        raise Refused("only on ext4")
    if not isinstance(paths, list) or not 0 < len(paths) <= NAMES_CHECK_MAX:
        raise Refused("bad request")
    kept = [(p, _kept(s, p)) for p in dict.fromkeys(paths)]
    bsize = os.statvfs(_p(s["home"])).f_bsize
    now: dict[str, tuple[list, bool]] = {}
    there: set[str] = set()
    for p, k in kept:
        try:
            dfd = _open_kept(s, k["rel"])
        except Refused:
            now[p] = ([], False)
            continue
        try:
            now[p] = (FIEMAP(dfd) or [], bool(_dir_flags(dfd) & FS_INDEX_FL))
            there.add(p)
        finally:
            os.close(dfd)
    fd = _names_device(s)
    buf = mmap.mmap(-1, NAMES_DIR_BYTES)
    unreadable = 0
    try:
        homes: dict[int, tuple[str, bool]] = {}         # filesystem block -> (folder, its first block in an index)
        for p, k in kept:
            for ext, indexed in ((k["ext"], k["indexed"]), now[p]):
                first = True
                for phys, length in ext:
                    for b in range(phys // bsize, (phys + min(length, NAMES_DIR_BYTES)) // bsize):
                        homes.setdefault(b, (p, indexed and first))
                        first = False
        journal, copies, journal_bytes, bad = _journal_copies(fd, bsize, set(homes))
        unreadable += bad
        out = []
        for p, k in kept:
            ext, indexed = now[p]
            # by block, not by extent: a folder that grew (fillers) has a longer extent over the same blocks
            current = {b for phys, length in ext for b in range(phys // bsize, (phys + min(length, NAMES_DIR_BYTES)) // bsize)}
            freed = [(b * bsize, bsize) for phys, length in k["ext"]
                     for b in range(phys // bsize, (phys + min(length, NAMES_DIR_BYTES)) // bsize) if b not in current]
            in_folder, b1 = _dir_names(fd, buf, ext, indexed, bsize)
            in_freed, b2 = _dir_names(fd, buf, freed, False, bsize, live=True)
            in_journal: set[bytes] = set()
            for home, (q, skip) in homes.items():
                if q == p:
                    for copy in copies.get(home, []):
                        in_journal |= parse_ext4_dir_block(copy, skip_index=skip, live=True)
            unreadable += b1 + b2
            live = _live(s, k["rel"], k["names"])
            sets = [(x & k["names"]) - live for x in (in_folder, in_freed, in_journal)]
            out.append({"path": p, "there": p in there, "folder": len(sets[0]), "freed": len(sets[1]),
                        "journal": len(sets[2]), "left": sorted(n.decode() for n in set().union(*sets)),
                        "listed": len(k["names"])})
    finally:
        buf.close()
        os.close(fd)
    return {"folders": out, "journal": journal, "journal_bytes": journal_bytes, "unreadable": unreadable}


def names_orphans(args: dict) -> dict:
    """The names in the journal's copies of folder blocks that are no listed folder's: folders that are
    gone, other accounts', the system's (and, without metadata_csum, every folder's). Never part of the
    listing: only when the user, as administrator, asks for them. Whether their files still exist can't be
    told, since their folders aren't known."""
    _must_be_root()
    s = _names_state()
    if s["fstype"] != "ext4" or not s.get("handed"):
        raise Refused("the names haven't been listed yet")
    j = s["j"]
    n = j["bsize"] - 12
    names: set[bytes] = set()
    records = 0
    fd = _names_device(s)
    try:
        for key, lblks in j["orphans"].items():
            _check_cancel()
            for lblk in lblks:
                if len(names) > NAMES_MAX:
                    break
                b = _journal_block(fd, j, lblk)
                if b is None:
                    continue
                if j["csum"]:                            # still the block it was when the journal was read
                    if b[n:n + 8] != EXT4_DIR_TAIL or int.from_bytes(b[-4:], "little") ^ _crc32c_raw(0, b[:n]) != key:
                        continue
                elif not ext4_dir_entries(b):
                    continue
                records += 1
                names |= parse_ext4_dir_block(b, live=True)
    finally:
        os.close(fd)
    out = sorted(x.decode() for x in names)
    return {"names": out[:NAMES_MAX], "truncated": len(out) > NAMES_MAX or j["norphans"] > NAMES_ORPHANS_MAX,
            "records": records}


def names_journal_clear(args: dict) -> dict:
    """Clears the journal of the filesystem listed: the kernel writes what the journal holds to its place,
    then zeroes it (EXT4_IOC_CHECKPOINT, zero-out), every folder's and every account's names in it at once.
    Nothing is lost by it, and there is nothing to undo."""
    _must_be_root()
    s = _names_state()
    if s["fstype"] != "ext4" or not s.get("handed"):
        raise Refused("the names haven't been listed yet")
    started = time.monotonic()
    CHECKPOINT(s, EXT4_CHECKPOINT_ZEROOUT)
    s["j"]["orphans"].clear()
    s["j"]["norphans"] = 0
    return {"cleared": True, "seconds": round(time.monotonic() - started, 1)}


def names_fstrim(args: dict) -> dict:
    """{"mount"}: trims the free space of a filesystem the names can be listed on (`fstrim -v`, as
    the weekly timer does): the clean-up's last step on ext4, the whole of it on btrfs."""
    _must_be_root()
    f = _trim_mount(args.get("mount"))
    code, out, err = TRIM_RUN(["fstrim", "-v", _unescape(f[1])])
    if code == 127:
        raise Refused("fstrim is not installed")
    if code != 0:
        raise Refused(f"fstrim failed: {(err or out).strip()[:200]}")
    m = re.search(r"\((\d+) bytes\) trimmed", out)
    return {"trimmed": int(m.group(1)) if m else None}


def names_end(args: dict) -> dict:
    _must_be_root()
    _NAMES.clear()
    return {"ended": True}


# ------------------------------------------------------------------ /tmp in memory
# Debian, Ubuntu and Mint ship systemd's tmp.mount in /usr/share/systemd without installing it.
# `systemctl enable <path>` links it into /etc/systemd/system and enables it; `systemctl disable`
# undoes both. It takes effect at the next boot: mounting over /tmp now would hide the files (and
# sockets) of running programs.

SHIPPED_TMP_MOUNT = "/usr/share/systemd/tmp.mount"


def enable_tmp_mount(args: dict) -> dict:
    _must_be_root()
    code, out, _ = RUN(["systemctl", "show", "--property=LoadState", "--value", "tmp.mount"])
    if code == 0 and out.strip() not in ("", "not-found"):
        raise Refused("tmp.mount is installed already: it is enabled like any other unit")
    try:
        st = os.lstat(_check_path(SHIPPED_TMP_MOUNT))
    except FileNotFoundError:
        raise Refused("this distribution doesn't ship tmp.mount") from None
    if not stat.S_ISREG(st.st_mode) or (not ROOT and st.st_uid != 0):
        raise Refused(f"{SHIPPED_TMP_MOUNT} isn't a root-owned file")
    had = _unit_dirs()
    change = {"linked_unit": {"unit": "tmp.mount", "file": SHIPPED_TMP_MOUNT}}
    _journal_begin(change)
    try:
        _do(["systemctl", "enable", SHIPPED_TMP_MOUNT])
    except Refused as e:
        _, state, _ = RUN(["systemctl", "is-enabled", "tmp.mount"])
        if state.strip() in ("enabled", "linked"):           # it got that far: recorded, so it can be put back
            _journal_save(change, state="failed", failed=str(e), **({"dirs": d} if (d := sorted(_unit_dirs() - had)) else {}))
            raise Refused(f"{e} (what it had changed by then is recorded, so it can be put back)",
                          {"change_id": change["id"]}) from None
        _journal_close(change, "failed", failed=str(e))
        raise
    _do_code(["systemctl", "daemon-reload"])
    made = sorted(_unit_dirs() - had)
    _journal_save(change, state="applied", **({"dirs": made} if made else {}))
    return {"changed": True, "change_id": change["id"], "warnings": [], "dirs": made}


# ------------------------------------------------------------------ installing itself
# What packaging/install-helper.sh does from a source tree, for the AppImage: the code installed is
# the code running now (this file, as root has just read and run it), and the polkit action is a
# constant here, so nothing the app sends is written.

INSTALLED = "/usr/libexec/daprivacyscanner/daprivacyscanner-helper"
POLICY_PATH = "/usr/share/polkit-1/actions/au.com.digitalarchon.daprivacyscanner.policy"
# the same as packaging/au.com.digitalarchon.daprivacyscanner.policy (a test keeps them equal)
POLICY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<!-- DA Privacy Kit's administrator helper: only this root-owned program, and the password is
     asked every time it starts (auth_admin, not auth_admin_keep). What can't be undone, what reaches
     other accounts' data, installing or removing the helper, and turning remote access back on ask
     again, each time (the helper checks the second action itself, with pkcheck). -->
<policyconfig>
  <vendor>DA Privacy Kit</vendor>
  <action id="au.com.digitalarchon.daprivacyscanner.helper">
    <description>Run DA Privacy Kit's administrator helper</description>
    <message>DA Privacy Kit needs administrator access to check or change system privacy settings</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/daprivacyscanner/daprivacyscanner-helper</annotate>
  </action>
  <action id="au.com.digitalarchon.daprivacyscanner.sensitive">
    <description>Let DA Privacy Kit do something that can't be undone, or that reaches beyond your account</description>
    <message>DA Privacy Kit asks for your password again, because it wants to $(what).</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
  </action>
</policyconfig>
"""
SELF = __file__                                 # tests point it at a copy
_SOURCE: tuple[str, bytes] | None = None        # (SELF, what it held): read once, at start (main), before any request
# the bytes privileged.install_helper's loader checked against the hash it was given and is running (it passes them
# here): what install_self installs, never the file read again
_LOADED = globals().get("__daprivacyscanner_source__")


def own_source() -> bytes:
    """This program's source, read once, when it starts: what install_self installs is the code that was running
    then, not what the file holds when the request comes. The helper that isn't installed yet runs from a copy in
    the user's runtime folder, which the user, or anything running as them, can change after it was authorised:
    started by the loader, it is the bytes the loader checked and ran."""
    global _SOURCE
    if isinstance(_LOADED, bytes) and SELF == __file__:
        return _LOADED
    if _SOURCE is None or _SOURCE[0] != SELF:
        with open(SELF, "rb") as f:
            _SOURCE = (SELF, f.read())
    return _SOURCE[1]


def install_self(args: dict) -> dict:
    _must_be_root()
    source = own_source()
    if source.startswith(b"#!"):                # installed already: its first line is the interpreter
        source = source.split(b"\n", 1)[1]
    d = os.path.dirname(INSTALLED)
    _makedirs(d, 0o755)
    os.chmod(_check_path(d), 0o755)
    _write(INSTALLED, b"#!/usr/bin/python3 -I\n" + source, 0o755)
    os.chmod(_p(INSTALLED), 0o755)
    _write(POLICY_PATH, POLICY.encode(), 0o644)
    return {"installed": INSTALLED, "policy": POLICY_PATH, "version": PROTOCOL}


def uninstall_self(args: dict) -> dict:
    _must_be_root()
    _write(INSTALLED, None)
    _write(POLICY_PATH, None)
    try:
        os.rmdir(_p(os.path.dirname(INSTALLED)))
    except OSError:
        pass
    return {"removed": [INSTALLED, POLICY_PATH]}


# ------------------------------------------------------------------ deleting

def _delete_files(directory: str, pattern: re.Pattern) -> int:
    real = _check_path(directory)
    n = 0
    try:
        names = os.listdir(real)
    except FileNotFoundError:
        return 0
    for name in names:
        p = os.path.join(real, name)
        if pattern.search(name) and not os.path.islink(p) and os.path.isfile(p):
            os.unlink(p)
            n += 1
    return n


CRASH_DUMPS = (("/var/lib/systemd/coredump", re.compile(r"^core\."), "core.*"),
               ("/var/crash", re.compile(r"\.(crash|upload|uploaded)$"), "*.crash *.upload *.uploaded"))


def _crash_dump_commands() -> list[str]:
    """The deletions as commands, by pattern: the files' names are never listed (they name the programs
    that crashed)."""
    return [f"rm -f {' '.join(f'{d}/{g}' for g in globs.split())}" for d, _, globs in CRASH_DUMPS]


def clear_crash_dumps(args: dict) -> dict:
    _must_be_root()
    n = 0
    for (directory, pattern, _), command in zip(CRASH_DUMPS, _crash_dump_commands()):
        deleted = _delete_files(directory, pattern)
        if deleted:
            DID.append(command)
        n += deleted
    return {"deleted": n}


# the text logs rsyslog and syslog-ng write with their distributions' rules (Debian and Ubuntu, Fedora and RHEL, and
# Arch's syslog-ng.conf, whose destinations ship commented out), and logrotate's copies (name.1, name.2.gz, Fedora's
# name-20261007, name.old)
SYSLOG_NAMES = ("syslog", "messages", "auth.log", "kern.log", "user.log", "daemon.log", "debug", "secure", "maillog",
                "spooler", "mail.log", "mail.err", "mail.warn", "mail.info", "cron", "cron.log",
                "syslog.log", "messages.log", "messages-kv.log", "everything.log", "kernel.log", "crond.log", "debug.log",
                "errors.log", "acpid.log", "iptables.log", "lpr.log", "news.log", "ppp.log", "uucp.log")
SYSLOG_FILES = re.compile(r"^(" + "|".join(re.escape(n) for n in SYSLOG_NAMES) + r")"
                          r"(\.[0-9]+(\.(gz|xz|zst|bz2))?|-[0-9]{8}(\.(gz|xz|zst|bz2))?|\.old)?$")
SYSLOG_DAEMONS = ("rsyslog.service", "syslog-ng.service", "syslog-ng@default.service")


def _syslog_command() -> str:
    return "rm -f /var/log/{" + ",".join(SYSLOG_NAMES) + "}{,.[0-9]*,-[0-9]*,.old}"


def clear_syslog(args: dict) -> dict:
    """The text logs in /var/log a syslog daemon wrote, by fixed names: refused while one runs (it would write them
    again at once, into files already unlinked)."""
    _must_be_root()
    for unit in SYSLOG_DAEMONS:
        _, active, _ = RUN(["systemctl", "is-active", unit])
        if active.strip() == "active":
            raise Refused(f"{unit} is running: stop it first")
    n = _delete_files("/var/log", SYSLOG_FILES)
    if n:
        DID.append(_syslog_command())
    return {"deleted": n}


_SNAPPER_CONFIG = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def snapper_cleanup(args: dict) -> dict:
    """Snapper's own clean-up, now, for every config: deletes the snapshots beyond its limits."""
    _must_be_root()
    try:
        names = sorted(n for n in os.listdir(_p("/etc/snapper/configs")) if _SNAPPER_CONFIG.match(n))
    except OSError:
        raise Refused("snapper has no configs") from None
    problems = []
    for name in names:
        for algorithm in ("number", "timeline"):
            code, out, err = _do_code(["snapper", "--no-dbus", "-c", name, "cleanup", algorithm])
            if code != 0:
                problems.append(f"{name} {algorithm}: {(err or out).strip()[:120]}")
    if problems:
        raise Refused("snapper's clean-up failed: " + "; ".join(problems))
    return {"configs": names}


JOURNAL_DIR = "/var/log/journal"
_JOURNAL_FILE = re.compile(r"\.journal~?$")
_JOURNAL_FOLDER = re.compile(r"^[0-9a-f]{32}(\.[A-Za-z0-9_.-]+)?$")     # the machine id, a namespace after a dot


def _journald_writes_to(prefix: str) -> bool:
    """Whether systemd-journald (its comm is "systemd-journal") has a file under `prefix` open."""
    for pid in os.listdir(_p("/proc")):
        if not pid.isdigit():
            continue
        try:
            with open(_p(f"/proc/{pid}/comm"), errors="replace") as f:     # any account can name its process anything
                if f.read().strip() != "systemd-journal":
                    continue
            fds = os.listdir(_p(f"/proc/{pid}/fd"))
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(_p(f"/proc/{pid}/fd/{fd}")).startswith(prefix + "/"):
                    return True
            except OSError:
                continue
    return False


def _journal_files_command() -> str:
    return f"rm -f {JOURNAL_DIR}/*/*.journal {JOURNAL_DIR}/*/*.journal~"


def clear_journal_files(args: dict) -> dict:
    """The journal files left in /var/log/journal once the journal is kept in memory (Storage=volatile: journald then
    writes only to /run/log/journal): its folders stay, so reverting that setting keeps the journal on the disk again.
    --vacuum-time deletes archived files only, never system.journal or user-*.journal. Refused while journald has one
    of them open: it is still writing there, so they are the journal itself."""
    _must_be_root()
    if _journald_writes_to(JOURNAL_DIR):
        raise Refused("journald is writing to /var/log/journal: keep the journal in memory first")
    real = _check_path(JOURNAL_DIR)
    try:
        folders = sorted(os.listdir(real))
    except FileNotFoundError:
        return {"deleted": 0}
    n = 0
    for name in folders:
        p = os.path.join(real, name)
        if _JOURNAL_FOLDER.match(name) and not os.path.islink(p) and os.path.isdir(p):
            n += _delete_files(f"{JOURNAL_DIR}/{name}", _JOURNAL_FILE)
    if n:
        DID.append(_journal_files_command())
    return {"deleted": n}


_VACUUM = re.compile(r"^[1-9][0-9]{0,2}(weeks|days)$")


def vacuum_journal(args: dict) -> dict:
    _must_be_root()
    t = args.get("time")
    if not isinstance(t, str) or not _VACUUM.match(t):
        raise Refused("bad time")
    out = _do(["journalctl", f"--vacuum-time={t}"])
    m = re.search(r"freed ([0-9.]+\s*\S+)", out)
    return {"freed": m.group(1) if m else "0B"}


class _Monitor:
    """`resolvectl monitor` for the window, writing into a memory file of its own (root's): a pipe no one read
    until the window ended filled with a burst of lookups bigger than it (a browser starting), resolvectl then
    blocked, and the lookups behind it were lost. Never a file in /tmp, which is on the disk on Debian, Ubuntu and
    Mint: every account's lookups would have been left in its free space."""

    def __init__(self):
        self.out = os.fdopen(os.memfd_create("daprivacyscanner-lookups", os.MFD_CLOEXEC), "w+b")
        try:
            self.proc = subprocess.Popen(["resolvectl", "monitor", "--json=short"], stdout=self.out,
                                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=_ENV)
        except OSError:
            self.out.close()
            raise

    def stop(self) -> str:
        """Ends it (killed when it won't end, reaped either way) and gives what it wrote."""
        self.proc.terminate()
        try:
            self.proc.wait(timeout=MONITOR_END_WAIT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        with self.out:
            self.out.seek(0)
            return self.out.read(MONITOR_MAX).decode(errors="replace")


MONITOR_MAX = 64 << 20                        # what is read of the monitor's output (the queries are capped anyway)
MONITOR_END_WAIT = 5                          # seconds it is given to end before it is killed


def _monitor():
    return _Monitor()


MONITOR = _monitor          # tests replace it, and SLEEP
SLEEP = time.sleep


def _walk(obj, names: list, addrs: list) -> None:
    if isinstance(obj, dict):
        n = obj.get("name")
        if isinstance(n, str):
            names.append(n.rstrip(".").lower())
        a = obj.get("address")
        if isinstance(a, list) and len(a) in (4, 16) and all(isinstance(x, int) for x in a):
            import ipaddress
            addrs.append(str(ipaddress.ip_address(bytes(a))))
        for v in obj.values():
            _walk(v, names, addrs)
    elif isinstance(obj, list):
        for v in obj:
            _walk(v, names, addrs)


def parse_monitor(text: str) -> list[dict]:
    """resolvectl monitor --json=short: one lookup per line -> [{"name", "addresses"}]."""
    out = []
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        names, addrs = [], []
        _walk(obj.get("question", []), names, addrs)
        _walk(obj.get("answer", []), [], addrs)
        if names:
            out.append({"name": names[0], "addresses": sorted(set(addrs))})
    return out


def _ss_peers(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] not in ("tcp", "udp"):
            continue
        m = re.search(r'\(\("([^"]+)"', line)
        out.append({"process": m.group(1) if m else "", "peer": f[5].rpartition(":")[0].strip("[]").split("%")[0],
                    "proto": f[0]})
    return out


def observe_traffic(args: dict) -> dict:
    seconds = args.get("seconds")
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 5 <= seconds <= 300:
        raise Refused("seconds must be 5-300")
    try:
        mon = MONITOR()
    except OSError:
        mon = None
    conns, seen = [], set()
    try:
        for _ in range(seconds):
            _check_cancel()
            code, out, _ = RUN(["ss", "-tunpH"])
            for c in _ss_peers(out) if code == 0 else []:
                key = (c["process"], c["peer"], c["proto"])
                if key not in seen:
                    seen.add(key)
                    conns.append(c)
            SLEEP(1)
    finally:
        text = mon.stop() if mon is not None else ""
    return {"queries": parse_monitor(text)[:10000], "connections": conns[:10000], "monitor": mon is not None}


def ufw_status(args: dict) -> dict:
    return {"text": _run(["ufw", "status", "verbose"])[:MAX_FILE]}


def planned(request: str, args: dict, home: str | None = None) -> list[str]:
    """The commands a change request runs, for the app's dry run, before any administrator access: the
    restarts a config file's change sets off (HOOKS), and the systemctl, sysctl, ufw, snapper and journalctl
    commands. The same ones come back, as run, in the answer ("ran"); a command whose state is already so
    (a unit enabled already) is skipped then. `home`: the user's, for the unit of a folder kept in memory.
    Reads nothing as root and never raises: a request it doesn't know plans nothing."""
    q = lambda argv: " ".join(shlex.quote(a) for a in argv)  # noqa: E731
    out: list[str] = []
    try:
        path = (DROPINS[args["name"]][0] if request == "write_dropin" and args.get("settings") is not None
                else POLICY_FILES.get(args.get("browser")) if request in ("browser_policy", "block_extensions") else None)
        paths = [path.format(uid=os.getuid()) if "{uid}" in path else path] if path else []
        if request == "edit_config" and args.get("target") == "autologin":
            paths = list(_autologin_overrides())
        out += [q(["mkdir", d]) for d in dict.fromkeys(d for p in paths for d in _missing_dirs(p))]
        if request in ("write_dropin", "edit_config"):
            hooks = DROPINS[args["name"]][4] if request == "write_dropin" else EDITS[args["target"]][2]
            for name in hooks:
                hook = HOOKS[name]
                out += [q(hook["validate"])] if hook.get("validate") else []
                out += [q(argv) for argv in hook.get("run", [])]
        elif request == "set_service":
            units = args.get("units") or [args["unit"]]
            enable, start = args.get("enable"), args.get("start")
            if enable is not None:          # turned on or off together: one call (_set_units)
                out.append(q(["systemctl", "enable" if enable else "disable", *(["--now"] if start is enable else []),
                              *units]))
            if start is not None and start is not enable:
                out.append(q(["systemctl", "start" if start else "stop", *units]))
            if args.get("mask"):
                out.append(q(["systemctl", "mask", *units]))
        elif request == "set_sysctl":
            out.append(q(["sysctl", "-w", f"{args['key']}={args['value']}"]))
        elif request == "ufw_enable":
            out += [q(["ufw", "allow", a]) for a in args.get("allow") or []] + [q(["ufw", "--force", "enable"])]
            # ufw.service, where it is installed and not enabled (read from its .wants link: no root, no systemctl)
            if any(os.path.exists(_p(f"{d}/{UFW_UNIT}")) for d in ("/usr/lib/systemd/system", "/lib/systemd/system")) \
                    and not os.path.lexists(_p(f"/etc/systemd/system/multi-user.target.wants/{UFW_UNIT}")):
                out.append(q(["systemctl", "enable", "--now", UFW_UNIT]))
        elif request == "mount_tmpfs" and home:
            target = args.get("target", "thumbnails")
            path = in_memory_path(home, target)
            uid = os.getuid()
            gid = pwd.getpwuid(uid).pw_gid
            if not os.path.lexists(_p(path)):
                out.append(q(["install", "-d", "-m", "700", "-o", str(uid), "-g", str(gid), path]))
            out += [q(["chmod", "500", path])] if target == "ephemeral" else []
            options = f"size={args['size_mb']}M,mode=0700,uid={uid},gid={gid}"
            noexec = args.get("noexec", True) is not False
            out += [q(["systemctl", "daemon-reload"]),
                    q(["mount", "-t", "tmpfs", "-o", ",".join([options, *(["noexec"] if noexec else []), "nosuid",
                                                               "nodev"]), "tmpfs", path]),
                    q(["systemctl", "enable", unit_name(path)])]
        elif request == "enable_tmp_mount":
            out += [q(["systemctl", "enable", SHIPPED_TMP_MOUNT]), q(["systemctl", "daemon-reload"])]
        elif request == "vacuum_journal":
            out.append(q(["journalctl", f"--vacuum-time={args['time']}"]))
        elif request == "clear_journal_files":
            out.append(_journal_files_command())
        elif request == "clear_crash_dumps":
            out += _crash_dump_commands()
        elif request == "clear_syslog":
            out.append(_syslog_command())
        elif request == "clear_opensnitch_log":
            out.append(_opensnitch_log_command())
        elif request == "opensnitch_rules":
            out += [q(argv) for argv in HOOKS["opensnitch"]["run"]]
        elif request == "snapper_cleanup":
            try:
                names = sorted(n for n in os.listdir(_p("/etc/snapper/configs")) if _SNAPPER_CONFIG.match(n))
            except OSError:
                names = ["CONFIG"]
            out += [q(["snapper", "--no-dbus", "-c", n, "cleanup", a]) for n in names for a in ("number", "timeline")]
    except (KeyError, TypeError):
        return []
    return out


def planned_files(request: str, args: dict, uid: int | None = None, home: str | None = None) -> list[tuple[str, str | None, str]]:
    """For the app's dry run: (path, what is there now, what the change writes there) for each file a drop-in or a
    line edit writes, so the page can show the lines; files the user can't read (cupsd.conf on some systems) are
    left out, as are requests that write no file of these kinds. Reads nothing that needs root; never raises."""
    dec = lambda b: None if b is None else b.decode("utf-8", "replace")  # noqa: E731
    try:
        if request == "write_dropin" and args.get("name") in DROPINS:
            name, settings = args["name"], args.get("settings")
            path, _, _, allowed, _ = DROPINS[name]
            if settings is not None and (not isinstance(settings, dict) or not settings or any(
                    k not in allowed or not isinstance(v, str) or not allowed[k].fullmatch(v) for k, v in settings.items())):
                return []
            path = path.format(uid=os.getuid() if uid is None else uid) if "{uid}" in path else path
            try:
                old = _read(path)
            except (Refused, OSError):
                old = None
            return [(path, dec(old), dec(dropin_content(name, settings)) or "")]
        if request == "mount_tmpfs" and home and args.get("target", "thumbnails") in IN_MEMORY:
            target, size = args.get("target", "thumbnails"), args.get("size_mb")
            noexec, until = args.get("noexec", True), args.get("until", "reboot")
            if not isinstance(size, int) or noexec not in (True, False) or until not in ("reboot", "logout"):
                return []
            uid = os.getuid() if uid is None else uid
            gid = pwd.getpwuid(uid).pw_gid
            path = in_memory_path(home, target)
            return [(f"{UNIT_DIR}/{unit_name(path)}", None,
                     mount_unit_text(path, home, uid, gid, size, target, noexec, until))]
        if request == "opensnitch_rules" and args.get("set") in ("starter", "connectivity"):
            out = []
            for path, new in opensnitch_rule_files(args["set"]).items():
                try:
                    old = _read(path)
                except (Refused, OSError):
                    old = None
                if old != new:
                    out.append((path, dec(old), dec(new)))
            return out
        if request == "edit_config" and args.get("target") in EDITS:
            patterns, allowed, _ = EDITS[args["target"]]
            values = args.get("values") or {}
            if not isinstance(values, dict) or any(k not in allowed or not isinstance(v, str) or not allowed[k].fullmatch(v)
                                                   for k, v in values.items()):
                return []
            out = []
            if args["target"] == "autologin":
                for path, content in _autologin_overrides().items():
                    try:
                        old = _read(path)
                    except (Refused, OSError):
                        old = None
                    if old != content:
                        out.append((path, dec(old), dec(content)))
            for pattern, edit in patterns.items():
                for path in _expand(pattern):
                    try:
                        data = _read(path)
                    except (Refused, OSError):
                        continue
                    if data is not None:
                        new = _join(edit(_lines(data), values))
                        if new != data:
                            out.append((path, dec(data), dec(new)))
            return out
    except (Refused, OSError, KeyError, TypeError, ValueError):
        return []
    return []


# ------------------------------------------------------------------ What does this app keep? (the watch)
#
# One app of the caller's, watched for as long as the user leaves it on: which files its processes open, change,
# create, delete and run, and which files the caller's other programs write meanwhile (a thumbnailer, a recent-files
# list: where what the app opened gets recorded). fanotify, on the whole filesystem (FAN_MARK_FILESYSTEM), so a
# Flatpak app in its own mount namespace is seen too, with the folder and name of each file (FAN_REPORT_DFID_NAME),
# turned into a path of this namespace through open_by_handle_at.
#
# Whose event it is comes from the process's cgroup when the event is read: the units the request names (the scope
# the app was started in, or Flatpak's or Snap's own scope for it), which must be under the caller's own user slice.
# Anything by another account is dropped at once, uncounted but for a total; a process that ended before it could
# be looked up is counted per folder under the caller's home, never named. Everything is held in this process's
# memory, in a child of the helper (it needs a mount namespace of its own to reach a btrfs filesystem through its
# top level: the kernel refuses a filesystem mark made through a subvolume), and handed over once, at watch_end.
# Tested on ext4 (Mint 22.3, kernel 7.0) and btrfs with /home on a subvolume (CachyOS, kernel 7.2).

# never user@UID.service or a session scope, which hold the whole session: every process would count as the app's
WATCH_UNIT = re.compile(r"(?!user@|session-)[A-Za-z0-9_.:@\\-]{1,200}\*?\.(scope|service)")
WATCH_UNITS_MAX = 8
WATCH_FILES_MAX = 60000                        # the app's files kept one by one; past that, counted per folder
WATCH_OTHERS_MAX = 30000                       # files the caller's other programs wrote (in programs' data, temporary)
WATCH_FOLDERS_MAX = 5000                       # folders their other writes are counted under
WATCH_PID_TTL = 10.0                           # seconds a process's lookup is trusted once it is the app's
WATCH_OTHER_TTL = 2.0                          # and when it isn't: a program is moved into its scope as it starts
WATCH_HANDLES_MAX = 20000                      # folder handles remembered as paths
WATCH_MOUNT_DIR = "/run/daprivacyscanner-watch"
WATCH_START_WAIT = 20.0
WATCH_REPLAN = 3.0                             # seconds between reads of the mount table
WATCH_FSTYPES_TOP = ("btrfs",)                 # reached through a private mount of the top level
# network shares: looking at one (its mount point's stat, the mark) waits for as long as the computer it is on can't
# be reached, which held up the watch's start until it gave up (a laptop away from its NAS)
WATCH_FSTYPES_NET = ("nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "afs", "fuse.sshfs",
                     "fuse.rclone", "davfs", "fuse.davfs2")
W_OPENED, W_WRITTEN, W_CREATED, W_DELETED, W_RAN, W_MOVED, W_DIR = 1, 2, 4, 8, 16, 32, 64
FAN_CLOEXEC, FAN_NONBLOCK, FAN_UNLIMITED_QUEUE, FAN_UNLIMITED_MARKS = 0x1, 0x2, 0x10, 0x20
FAN_REPORT_DIR_FID, FAN_REPORT_NAME = 0x400, 0x800
FAN_MARK_ADD, FAN_MARK_FILESYSTEM = 0x1, 0x100
FAN_MODIFY, FAN_OPEN, FAN_MOVED_FROM, FAN_MOVED_TO = 0x2, 0x20, 0x40, 0x80
FAN_CREATE, FAN_DELETE, FAN_OPEN_EXEC, FAN_Q_OVERFLOW, FAN_ONDIR = 0x100, 0x200, 0x1000, 0x4000, 0x40000000
FAN_WATCHED = FAN_MODIFY | FAN_OPEN | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CREATE | FAN_DELETE | FAN_OPEN_EXEC
WATCH_INIT_FLAGS = FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_MARKS | FAN_REPORT_DIR_FID | FAN_REPORT_NAME
FAN_FOLDERS_MOVED = FAN_MOVED_FROM | FAN_MOVED_TO | FAN_DELETE | FAN_ONDIR
FAN_INFO_DFID_NAME, FAN_INFO_DFID, FAN_INFO_OLD_DFID_NAME, FAN_INFO_NEW_DFID_NAME = 2, 3, 10, 12
_WATCH: dict = {}                              # the running watch: its child process and who asked


def _watch_units(units) -> list[str]:
    if (not isinstance(units, list) or not 0 < len(units) <= WATCH_UNITS_MAX
            or not all(isinstance(u, str) and WATCH_UNIT.fullmatch(u) for u in units)):
        raise Refused("which app to watch isn't named as this expects")
    return units


def _watch_in_units(cgroup: str, uid: int, units: list[str]) -> bool:
    """Whether a process's cgroup is one of the units, under the caller's own slice (never another account's)."""
    prefix = f"/user.slice/user-{uid}.slice/"
    if not cgroup.startswith(prefix):
        return False
    parts = [p for p in cgroup[len(prefix):].split("/") if not p.startswith(("user@", "session-"))]
    return any(fnmatch.fnmatchcase(part, u) for part in parts for u in units)


def _watch_proc(pid: int) -> tuple[int, str, str] | None:
    """(uid, cgroup, name) of a process, or None when it has ended."""
    try:
        uid = os.stat(f"/proc/{pid}").st_uid
        with open(f"/proc/{pid}/cgroup", "rb") as f:
            lines = f.read(8192).decode(errors="replace").splitlines()
        with open(f"/proc/{pid}/comm", "rb") as f:
            comm = f.read(64).decode(errors="replace").strip()
    except OSError:
        return None
    cg = next((ln[3:] for ln in lines if ln.startswith("0::")), None) \
        or next((ln.split(":", 2)[2] for ln in lines if ":name=systemd:" in ln), "")
    return uid, cg, comm


def _watch_keep(uid: int, home: str) -> tuple[str, ...]:
    """Where a file is kept by its path; elsewhere (the system's folders) it is only counted."""
    return (home, "/tmp", "/var/tmp", "/dev/shm", f"/run/user/{uid}", "/media", "/mnt", "/run/media")


def _watch_inside(path: str, bases: tuple[str, ...]) -> bool:
    return any(path == b or path.startswith(b + "/") for b in bases)


class _Tally:
    """What the watch has seen, in memory: the app's files one by one (WATCH_FILES_MAX, then per folder), the
    files the caller's other programs wrote, and counts for the rest."""

    def __init__(self, uid: int, home: str, units: list[str], proc=_watch_proc, clock=time.monotonic):
        self.uid, self.home, self.units, self.proc, self.clock = uid, home, units, proc, clock
        self.keep = _watch_keep(uid, home)
        self.pids: dict[int, tuple[float, tuple[str, str] | None]] = {}
        self.app: dict[str, list] = {}             # path -> [flags, opens, writes, minutes, last minute]
        self.others: dict[str, list] = {}          # path -> [flags, writes, minutes, last minute, who]
        self.folded: dict[str, int] = {}           # the app's files past the limit, per folder
        self.system: dict[str, int] = {}           # the app's files outside `keep`, per folder two deep
        self.gone: dict[str, int] = {}             # by a process that had ended: per folder under the home
        # what the other programs changed in the user's own folders and on other disks (never searched for records:
        # a build's thousands of files filled the 30,000 and later records were lost, D8), and past the limit:
        # changes per program and folder
        self.others_folded: dict[tuple[str, str], int] = {}
        self.events = self.foreign = self.overflow = self.unresolved = self.others_left = 0

    def who(self, pid: int, fresh: bool = False) -> tuple[str, str] | None:
        """("app", name), ("other", name), ("gone", "") or None for another account's process. `fresh`: looked up
        again whatever is remembered (it has just run a program: systemd-run and flatpak run move themselves into
        the app's scope first, then run it, tested)."""
        now = self.clock()
        got = self.pids.get(pid)
        if got is not None and not fresh and now - got[0] < (
                WATCH_PID_TTL if got[1] is None or got[1][0] == "app" else WATCH_OTHER_TTL):
            return got[1]
        p = self.proc(pid)
        if p is None:
            return ("gone", "")                    # not remembered: the number may be another process's next time
        uid, cgroup, comm = p
        w = None if uid != self.uid else (("app" if _watch_in_units(cgroup, uid, self.units) else "other"), comm)
        if len(self.pids) > 20000:
            self.pids.clear()
        self.pids[pid] = (now, w)
        return w

    def add(self, mask: int, pid: int, path: str | None) -> None:
        self.events += 1
        w = self.who(pid, fresh=bool(mask & FAN_OPEN_EXEC))
        if w is None:
            self.foreign += 1
            return
        if path is None:
            self.unresolved += 1
            return
        flags = 0
        if mask & FAN_OPEN_EXEC:
            flags |= W_RAN | W_OPENED
        if mask & FAN_OPEN:
            flags |= W_OPENED
        if mask & FAN_MODIFY:
            flags |= W_WRITTEN
        if mask & FAN_CREATE:
            flags |= W_CREATED
        if mask & FAN_DELETE:
            flags |= W_DELETED
        if mask & FAN_MOVED_FROM:
            flags |= W_DELETED | W_MOVED
        if mask & FAN_MOVED_TO:
            flags |= W_MOVED
        if mask & FAN_ONDIR:
            flags |= W_DIR
        if not flags:
            return
        kept = _watch_inside(path, self.keep)
        if w[0] == "gone":
            if _watch_inside(path, (self.home,)):       # counted under its folder, two deep at most: never named
                folder = "/".join(path.split("/")[:-1][:len(self.home.split("/")) + 2])
                self.gone[folder] = self.gone.get(folder, 0) + 1
            return
        minute = int(self.clock() // 60)
        if w[0] == "other":
            if not kept or not flags & (W_WRITTEN | W_CREATED | W_MOVED) or flags & W_DIR:
                return
            rec = self.others.get(path)
            if rec is None:
                folder = self._own_folder(path)
                if folder is None and len(self.others) >= WATCH_OTHERS_MAX:
                    self.others_left += 1               # ~/.cache/thumbnails/normal, /tmp/foo/bar
                    deep = len(self.home.split("/")) + 3 if _watch_inside(path, (self.home,)) else 4
                    folder = "/".join(path.split("/")[:-1][:deep])
                if folder is not None:
                    key = (w[1], folder)
                    if key not in self.others_folded and len(self.others_folded) >= WATCH_FOLDERS_MAX:
                        key = (w[1], "")                # past that many folders: counted for the program alone
                    self.others_folded[key] = self.others_folded.get(key, 0) + 1
                    return
                rec = self.others[path] = [0, 0, 0, -1, w[1]]
            self._count(rec, 1, flags, minute)
            return
        if not kept:
            folder = "/" + "/".join(path.strip("/").split("/")[:-1][:2])
            self.system[folder] = self.system.get(folder, 0) + 1
            return
        rec = self.app.get(path)
        if rec is None:
            if len(self.app) >= WATCH_FILES_MAX:
                folder = os.path.dirname(path)
                if folder not in self.folded and len(self.folded) >= WATCH_FOLDERS_MAX:
                    folder = ""                         # past that many folders too: counted, in no folder
                self.folded[folder] = self.folded.get(folder, 0) + 1
                return
            rec = self.app[path] = [0, 0, 0, 0, -1]
        if flags & W_OPENED:
            rec[1] += 1
        self._count(rec, 2, flags, minute)

    def _own_folder(self, path: str) -> str | None:
        """For a file in the user's own folders (under the home, not hidden) or on another disk: the folder it is
        counted under (two deep under the home, three under the disks' folder); None for programs' data and the
        temporary folders, which are kept file by file."""
        parts = path.split("/")[:-1]
        if _watch_inside(path, (self.home,)):
            depth = len(self.home.split("/"))
            first = path.split("/")[depth:depth + 1]        # the folder (or file) right under the home
            return None if not first or first[0].startswith(".") else "/".join(parts[:depth + 2])
        base = next((b for b in ("/media", "/mnt", "/run/media") if _watch_inside(path, (b,))), None)
        return "/".join(parts[:len(base.split("/")) + 3]) if base else None

    @staticmethod
    def _count(rec: list, at: int, flags: int, minute: int) -> None:
        """Adds the flags; a write counts, and counts its minute once. A file made again isn't deleted any more."""
        if flags & (W_CREATED | W_MOVED) and not flags & W_DELETED:
            rec[0] &= ~W_DELETED
        rec[0] |= flags
        if flags & (W_WRITTEN | W_MOVED) and not flags & W_DELETED:
            rec[at] += 1
            if rec[at + 2] != minute:
                rec[at + 2] = minute
                rec[at + 1] += 1

    def counts(self) -> dict:
        return {"events": self.events, "files": len(self.app) + sum(self.folded.values()),
                "others": len(self.others) + sum(self.others_folded.values()), "overflow": self.overflow}

    def result(self) -> dict:
        """The records as tools/activity.py reads them: [path, flags, opens, writes, minutes, who]."""
        files = [[p, r[0], r[1], r[2], r[3], ""] for p, r in self.app.items()]
        files += [[p, r[0], 0, r[1], r[2], r[4]] for p, r in self.others.items()]
        return {"files": files, "folded": self.folded, "system": self.system, "gone": self.gone,
                "others_folded": sorted(([who, folder, n] for (who, folder), n in self.others_folded.items()),
                                        key=lambda o: -o[2]),
                "events": self.events, "foreign": self.foreign, "overflow": self.overflow,
                "unresolved": self.unresolved, "others_left": self.others_left}


def _fan_events(buf: bytes):
    """Each event in what a fanotify descriptor returned: (mask, pid, [(info type, handle type, handle, name)])."""
    i, size = 0, len(buf)
    while i + 24 <= size:
        length, _vers, _res, meta, mask, fd, pid = _struct.unpack_from("=IBBHQii", buf, i)
        if length < 24 or i + length > size:
            return
        if fd >= 0:                                 # not in this mode, but never left open
            try:
                os.close(fd)
            except OSError:
                pass
        infos, j, end = [], i + meta, i + length
        while j + 4 <= end:
            kind, _pad, n = _struct.unpack_from("=BBH", buf, j)
            if n < 4 or j + n > end:
                break
            if kind in (FAN_INFO_DFID_NAME, FAN_INFO_DFID, FAN_INFO_OLD_DFID_NAME, FAN_INFO_NEW_DFID_NAME) and n >= 20:
                hbytes, htype = _struct.unpack_from("=Ii", buf, j + 12)
                start = j + 20
                if start + hbytes <= j + n:
                    name = bytes(buf[start + hbytes:j + n]).split(b"\0", 1)[0] if kind != FAN_INFO_DFID else b""
                    infos.append((kind, htype, bytes(buf[start:start + hbytes]), name))
            j += n
        yield mask, pid, infos
        i += length


def _watch_mountinfo() -> list[dict]:
    out = []
    try:
        with open(_p("/proc/self/mountinfo"), "rb") as f:
            text = f.read(64 * MAX_FILE).decode(errors="surrogateescape")
    except OSError:
        return out
    for ln in text.splitlines():
        left, sep, right = ln.partition(" - ")
        a, b = left.split(), right.split()
        if sep and len(a) >= 5 and len(b) >= 2:
            out.append({"dev": a[2], "root": _unescape(a[3]), "mount": _unescape(a[4]), "fstype": b[0],
                        "source": _unescape(b[1])})
    return out


def _watch_plan(uid: int, home: str) -> tuple[list[dict], list[list[str]]]:
    """The filesystems to watch: those holding the caller's home, the temporary folders, the caller's runtime
    folder and /, and whatever is mounted inside any of those or under /media, /mnt and /run/media (a disk at
    ~/Data, a tmpfs at ~/.cache/thumbnails, ~/RAMDisk, the document portal in the runtime folder: they weren't
    watched, nor said not to be); each once, by its device number (`dev`). A btrfs one is reached through its top
    level (`top`: through the system's own mount of it, `at`, or a private one), with where each of its subvolumes
    is mounted (`subvolumes`); any other through a mount that shows all of it. Returns (the plan, [[mount point,
    why not]])."""
    table = [m for m in _watch_mountinfo() if not _watch_inside(m["mount"], (WATCH_MOUNT_DIR,))]   # not its own
    base = [home, "/", "/tmp", "/var/tmp", "/dev/shm", f"/run/user/{uid}"]
    wanted = base + [m["mount"] for m in table if _watch_inside(m["mount"], _watch_keep(uid, home))]
    plan, skipped, seen = [], [], set()
    for i, path in enumerate(wanted):
        held = [m for m in table if path == m["mount"] or path.startswith(m["mount"].rstrip("/") + "/")]
        if not held:
            continue
        m = max(reversed(held), key=lambda x: len(x["mount"]))     # the one visible there
        if i >= len(base) and m["fstype"] in WATCH_FSTYPES_NET:     # a share mounted in the home or under /mnt
            if not any(sk[0] == m["mount"] for sk in skipped):
                skipped.append([m["mount"], "a network share: its files are on another computer, and asking about "
                                            "it waits for as long as that computer can't be reached"])
            continue
        key = m["dev"]                                 # one filesystem, wherever else it is mounted (a btrfs's
        if key in seen:                                # subvolumes share it; each tmpfs has its own)
            continue
        seen.add(key)
        same = [x for x in table if x["dev"] == key]
        whole = next((x for x in same if x["root"] == "/"), None)
        if m["fstype"] in WATCH_FSTYPES_TOP:
            if whole is None and not _DEVICE.match(m["source"]):
                skipped.append([m["mount"], "its device can't be told"])
                continue
            # named by the shortest place it is mounted at (/ rather than /home, when both are subvolumes of it);
            # where its top level is mounted already (a disk at /run/media/…), through that: nothing of its own to
            # mount, which would keep the disk busy after it is unmounted
            plan.append({"mount": min((x["mount"] for x in same), key=len), "fstype": m["fstype"], "source": m["source"],
                         "top": True, "at": whole["mount"] if whole else None, "dev": key,
                         "subvolumes": sorted(([x["root"], x["mount"]] for x in same), key=lambda s: -len(s[0]))})
            continue
        if whole is None:
            skipped.append([m["mount"], "only part of that filesystem is mounted here"])
            continue
        plan.append({"mount": whole["mount"], "fstype": m["fstype"], "source": m["source"], "top": False, "dev": key})
    return plan, skipped


def _watch_why(fs: dict, uid: int, e: OSError) -> str:
    """Why a filesystem can't be watched, in words."""
    mount, kind = fs["mount"], fs["fstype"]
    if mount == f"/run/user/{uid}/doc" or kind == "fuse.portal":
        return ("the document portal, through which Flatpak apps open the files you choose: the portal opens them for "
                "the app, so those files aren't counted as the app's")
    if mount == f"/run/user/{uid}/gvfs" or kind.startswith("fuse.gvfs"):
        return "the desktop's view of network shares and devices (GVFS), which administrator access can't look into"
    if kind.startswith("fuse") and os.path.basename(mount).startswith(".mount_"):
        return "a running AppImage's own files (read-only)"
    if kind.startswith("fuse"):
        return "a filesystem run by a program of yours (FUSE), which administrator access can't look into"
    return f"{e.strerror} ({errno.errorcode.get(e.errno, e.errno)})"


class _FileHandle(ctypes.Structure):
    _fields_ = [("handle_bytes", ctypes.c_uint), ("handle_type", ctypes.c_int), ("f_handle", ctypes.c_ubyte * 128)]


class _Watched:
    """One filesystem under watch: its fanotify descriptors, the mount to open handles through (`at`), and how to
    turn what that gives into a path of the caller's (a btrfs subvolume's mount point)."""

    def __init__(self, libc, fs: dict, index: int, private: bool = True):
        self.libc, self.fs, self.paths = libc, fs, {}
        self.fan = self.dirs = self.mfd = -1
        self.strip = self.made = self.at = ""
        self.dev = -1
        try:
            self._start(fs, index, private)
        except OSError:
            self.close()
            raise

    def _start(self, fs: dict, index: int, private: bool) -> None:
        libc, at = self.libc, fs["mount"]
        if fs["top"] and fs.get("at"):
            at = self.strip = fs["at"]                  # its top level is mounted: looked through there
        elif fs["top"]:
            if not private:
                raise OSError(errno.EXDEV, "its top level can't be reached here")
            # named by this process: another copy's watch has a child of its own, whose folders are no one else's
            # to remove (_watch_forget)
            at = self.made = f"{WATCH_MOUNT_DIR}/{os.getpid()}-{index}"
            os.makedirs(at, mode=0o700, exist_ok=True)
            # nosuid, nodev, noexec, noatime: it is only looked through
            if libc.mount(fs["source"].encode(), at.encode(), fs["fstype"].encode(), 2 | 4 | 8 | 1024, b"subvolid=5"):
                raise OSError(ctypes.get_errno(), "its top level couldn't be mounted")
            self.strip = at
        self.at, self.dev = at, os.stat(at).st_dev
        # the kernel's own queue limit (fs.fanotify.max_queued_events), never FAN_UNLIMITED_QUEUE: with it, a
        # reader that fell behind under six busy programs let the kernel's queue grow from 470 MB to 1.7 GB in 25
        # seconds, never said so, and by the time the events were read their processes had ended (tested on
        # Mint). A full queue drops what comes next and says so (FAN_Q_OVERFLOW): counted, and the page says some
        # of what happened is missing.
        self.fan = libc.fanotify_init(WATCH_INIT_FLAGS, os.O_RDONLY | os.O_CLOEXEC)
        if self.fan < 0:
            raise OSError(ctypes.get_errno(), "fanotify isn't available")
        if libc.fanotify_mark(self.fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_WATCHED, -100, at.encode()):
            raise OSError(ctypes.get_errno(), "this kind of filesystem can't be watched")
        # folders renamed, moved or removed, by anyone: the paths remembered for folders' handles are out of date
        # then (files made in ~/d2 were reported under ~/d1, its name before: tested on Mint). In a group of its
        # own, since FAN_ONDIR on the main one would also report every folder opened to be listed. Without it, what
        # is remembered is forgotten at every poll instead.
        self.dirs = libc.fanotify_init(WATCH_INIT_FLAGS, os.O_RDONLY | os.O_CLOEXEC)
        if self.dirs >= 0 and libc.fanotify_mark(self.dirs, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_FOLDERS_MOVED,
                                                 -100, at.encode()):
            os.close(self.dirs)
            self.dirs = -1
        if self.made:                                   # its own mount: held open (nothing else uses it)
            self.mfd = os.open(at, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def _mount_fd(self) -> int:
        """A descriptor of the mount to open handles through: its own private mount's, or the system's mount opened
        for the moment (held open, it kept a disk from being unmounted until the watch ended), and only while that
        is still this filesystem (-1 once it is gone or something else is mounted there)."""
        if self.mfd >= 0:
            return os.dup(self.mfd)
        try:
            fd = os.open(self.at, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            return -1
        if os.fstat(fd).st_dev != self.dev:
            os.close(fd)
            return -1
        return fd

    def close(self) -> None:
        """Its descriptors closed, and a top level it mounted unmounted and its folder removed (it was left in /run
        after the access was dropped or the app quit: tested on CachyOS)."""
        for fd in (self.fan, self.dirs, self.mfd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.fan = self.dirs = self.mfd = -1
        if self.made:
            if self.strip:
                self.libc.umount2(self.made.encode(), 2)        # MNT_DETACH: nothing of it is in use any more
            try:
                os.rmdir(self.made)
            except OSError:
                pass
            self.made = self.strip = ""

    def moved(self) -> None:
        """Reads what the folders' group has: a folder renamed, moved or removed makes every remembered path of
        this filesystem's suspect, so they are forgotten (looked up again as they come)."""
        while self.dirs >= 0:
            try:
                buf = os.read(self.dirs, 1 << 16)
            except BlockingIOError:
                return
            except OSError:
                os.close(self.dirs)
                self.dirs = -1
                self.paths.clear()
                return
            if any(mask & (FAN_ONDIR | FAN_Q_OVERFLOW) for mask, _pid, _infos in _fan_events(buf)):
                self.paths.clear()

    def folder(self, htype: int, handle: bytes) -> str | None:
        """The folder a handle names, as a path of the caller's, or None (gone, or not mounted anywhere)."""
        key = (htype, handle)
        if key in self.paths:
            return self.paths[key]
        path = None
        mfd = self._mount_fd() if len(handle) <= 128 else -1
        if mfd >= 0:
            fh = _FileHandle(len(handle), htype)
            ctypes.memmove(fh.f_handle, handle, len(handle))
            fd = self.libc.open_by_handle_at(mfd, ctypes.byref(fh), os.O_PATH | os.O_CLOEXEC)
            os.close(mfd)
            if fd >= 0:
                try:
                    path = self._mapped(os.readlink(f"/proc/self/fd/{fd}"))
                except OSError:
                    path = None
                finally:
                    os.close(fd)
        if len(self.paths) >= WATCH_HANDLES_MAX:
            self.paths.clear()
        self.paths[key] = path
        return path

    def _mapped(self, path: str) -> str | None:
        if path.endswith(" (deleted)"):
            return None
        if not self.strip:
            return path
        rel = path if self.strip == "/" else path[len(self.strip):] or "/"
        if not path.startswith(self.strip) or not rel.startswith("/"):
            return None
        for root, mount in self.fs["subvolumes"]:   # the deepest subvolume first
            if rel == root or rel.startswith(root.rstrip("/") + "/"):
                return (mount.rstrip("/") + rel[len(root.rstrip("/")):]) or "/"
        return None


def _watch_child() -> None:
    """The watch itself: `helper.py --watch`, started by watch_begin with the units on its first line. Checks the
    request again itself (who is asking comes from pkexec, as for every action), answers "poll" with counts and
    "end" with everything, and ends when its input does."""
    out = os.fdopen(os.dup(1), "w")
    pending = b""
    try:
        # the first line, read unbuffered: what follows it ("poll", "end") is read with os.read below, and a
        # buffered reader could have taken it along with the first line
        while b"\n" not in pending and len(pending) < 65536:
            chunk = os.read(0, 4096)
            if not chunk:
                break
            pending += chunk
        first_line, _nl, pending = pending.partition(b"\n")
        conf = json.loads(first_line or b"{}")
        uid, _gid, home = _caller()
        if os.geteuid() != 0:
            raise Refused("the watch needs root")
        units = _watch_units(conf.get("units"))
        plan, skipped = _watch_plan(uid, home)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
        libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
        libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
        # SIGTERM (the helper ended: PR_SET_PDEATHSIG below) ends it through its clean-up, as the end of its input does
        import signal
        signal.signal(signal.SIGTERM, lambda _sig, _frame: sys.exit(0))
        libc.prctl(1, 15, 0, 0, 0)                  # PR_SET_PDEATHSIG, SIGTERM: never outlives the helper
        # a mount namespace of its own, for the top-level mounts of btrfs filesystems: seen by nothing else, gone
        # with this process. A slave of the system's, so what is mounted later (a USB disk, ~/RAMDisk) shows here
        # too, and is watched (it wasn't before); what it mounts itself never goes the other way.
        private = not (libc.unshare(0x20000) or libc.mount(b"none", b"/", None, 0x4000 | (1 << 19), None))
        fss = _Filesystems(libc, uid, home, private)
        fss.add(plan, skipped)
        if not fss.watched:
            raise Refused("no filesystem here can be watched: " + "; ".join(f"{m}: {why}" for m, why in fss.skipped))
    except Refused as e:
        out.write(json.dumps({"error": str(e)}) + "\n")
        out.flush()
        return
    try:
        out.write(json.dumps(fss.names()) + "\n")
        out.flush()
        _watch_loop(fss, _Tally(uid, home, units), out, pending)
    finally:
        fss.close()


class _Filesystems:
    """The filesystems under watch, as the mount table changes: one mounted during the watch is added (or said not
    to be), one unmounted is let go (closed, so nothing of it is held), a btrfs's subvolumes followed."""

    def __init__(self, libc, uid: int, home: str, private: bool):
        self.libc, self.uid, self.home, self.private = libc, uid, home, private
        self.watched: list[_Watched] = []
        self.names_watched: list[str] = []           # every filesystem watched at some point, by its mount point
        self.skipped: list[list[str]] = []
        self.tried: set[str] = set()                 # devices already watched or said not to be
        self.index = 0

    def add(self, plan: list[dict], skipped: list[list[str]], late: bool = False) -> None:
        for fs in plan:
            if fs["dev"] in self.tried:
                continue
            self.tried.add(fs["dev"])
            try:
                w = _Watched(self.libc, fs, self.index, self.private)
            except OSError as e:
                if not any(s[0] == fs["mount"] for s in self.skipped):
                    why = _watch_why(fs, self.uid, e)
                    self.skipped.append([fs["mount"], why + (", mounted during the watch" if late else "")])
                continue
            finally:
                self.index += 1
            self.watched.append(w)
            if fs["mount"] not in self.names_watched:
                self.names_watched.append(fs["mount"])
        for mount, why in skipped:
            if not any(s[0] == mount for s in self.skipped):
                self.skipped.append([mount, why])

    def replan(self) -> None:
        plan, skipped = _watch_plan(self.uid, self.home)
        now = {fs["dev"]: fs for fs in plan}
        for w in list(self.watched):
            fs = now.get(w.fs["dev"])
            # unmounted: let go, so the disk can go too; a btrfs whose top level is mounted elsewhere now (or no
            # longer): let go, and taken up again below the way it can be reached now
            if fs is None or fs.get("at") != w.fs.get("at"):
                w.close()
                self.watched.remove(w)
                self.tried.discard(w.fs["dev"])
            elif fs.get("subvolumes") != w.fs.get("subvolumes"):
                w.fs["subvolumes"] = fs["subvolumes"]
                w.paths.clear()
        self.tried &= set(now) | {w.fs["dev"] for w in self.watched}   # mounted again later: tried again
        self.add(plan, skipped, late=True)

    def names(self) -> dict:
        return {"watched": list(self.names_watched), "skipped": [list(s) for s in self.skipped]}

    def close(self) -> None:
        for w in self.watched:
            w.close()
        self.watched = []
        try:
            os.rmdir(WATCH_MOUNT_DIR)
        except OSError:
            pass


def _watch_loop(fss: _Filesystems, tally: _Tally, out, pending: bytes) -> None:
    """Reads the filesystems' events into the tally and answers the helper's words, until "end" or the end of
    its input. Every WATCH_REPLAN seconds, the mount table is read again."""
    import select
    started = replanned = time.monotonic()
    while True:
        if time.monotonic() - replanned > WATCH_REPLAN:
            fss.replan()
            replanned = time.monotonic()
        by_fd = {w.fan: w for w in fss.watched}
        dirs = {w.dirs: w for w in fss.watched if w.dirs >= 0}
        try:
            ready = select.select([0, *by_fd, *dirs], [], [], 1.0)[0]
        except InterruptedError:
            continue
        for fd in ready:
            if fd in dirs:
                dirs[fd].moved()
                continue
            if fd not in by_fd:
                continue
            w = by_fd[fd]
            w.moved()                                   # a folder renamed before these events: its old path forgotten
            try:
                buf = os.read(fd, 1 << 20)
            except BlockingIOError:
                continue
            except OSError:
                w.close()
                fss.watched.remove(w)
                continue
            for mask, pid, infos in _fan_events(buf):
                if mask & FAN_Q_OVERFLOW:
                    tally.overflow += 1
                    continue
                if not infos:
                    tally.add(mask, pid, None)
                    continue
                # a rename comes as two events (moved from, moved to), each with the folder and name it is about
                for kind, htype, handle, name in infos[:1]:
                    folder = w.folder(htype, handle)
                    text = name.decode("utf-8", "surrogateescape")
                    if folder is None or kind == FAN_INFO_DFID or text in ("", "."):
                        tally.add(mask, pid, None)          # a folder itself, or a file whose folder can't be told
                    else:
                        tally.add(mask, pid, folder.rstrip("/") + "/" + text)
        if 0 in ready:
            chunk = os.read(0, 4096)
            if not chunk:
                return
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                word, _, n = line.strip().partition(b" ")
                seq = int(n) if n.isdigit() else None   # given back, so the helper knows which word this answers
                if word == b"poll":
                    for w in fss.watched:
                        if w.dirs < 0:                  # no word of folders renamed: what is remembered may be old
                            w.paths.clear()
                    out.write(json.dumps({**tally.counts(), **fss.names(), "seconds": time.monotonic() - started,
                                          "seq": seq}) + "\n")
                    out.flush()
                elif word == b"end":
                    out.write(json.dumps({**tally.result(), **fss.names(), "seconds": time.monotonic() - started,
                                          "seq": seq}) + "\n")
                    out.flush()
                    return


def _watch_running() -> dict:
    w = _WATCH
    if not w or w.get("uid") != _caller()[0]:
        raise Refused("no watch is running")
    if w["proc"].poll() is not None:
        _watch_forget()
        raise Refused("the watch has stopped")
    return w


def _watch_forget() -> None:
    proc = _WATCH.get("proc")
    _WATCH.clear()
    if proc is not None:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    # the folders its private mounts were made on (never the mounts, which ended with it), and those of any watch
    # whose process has ended (killed before it could remove them). Never the folders of a watch still running (another
    # copy's, with a helper of its own): rmdir doesn't refuse a mount point that is one only in another mount namespace,
    # it detaches the mount there (Linux 3.18 and later), and that watch would no longer see the paths under it
    try:
        names = os.listdir(WATCH_MOUNT_DIR)
    except OSError:
        return
    for name in names:
        m = re.fullmatch(r"(\d+)-\d+", name)
        if m is None:
            continue
        if proc is None or int(m[1]) != proc.pid:
            try:
                os.kill(int(m[1]), 0)
                continue                                # its watch is running
            except ProcessLookupError:
                pass
            except OSError:
                continue
        try:
            os.rmdir(os.path.join(WATCH_MOUNT_DIR, name))
        except OSError:
            pass
    try:
        os.rmdir(WATCH_MOUNT_DIR)
    except OSError:
        pass


def _watch_ask(w: dict, word: str, timeout: float) -> dict:
    """Asks the watch (`word`: "poll", "end"; "" for its first line) and returns its answer. Each word goes with a
    number the answer gives back: one that comes after its question timed out is passed over, never taken for the
    answer to the next (an "end" got a late poll's counts, and the watch's result was lost)."""
    import select
    proc = w["proc"]
    seq = None
    if word:
        seq = w["seq"] = w.get("seq", 0) + 1
        try:
            proc.stdin.write(f"{word} {seq}\n")
            proc.stdin.flush()
        except (OSError, ValueError):
            raise Refused("the watch has stopped") from None
    # read from the pipe itself, lines split here: a file object's readline buffers what follows the line, which
    # select then doesn't see
    fd, pending, until = proc.stdout.fileno(), w.setdefault("pending", bytearray()), time.monotonic() + timeout
    while True:
        while b"\n" not in pending:
            left = until - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise Refused("the watch didn't answer")
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                raise Refused("the watch has stopped")
            pending += chunk
        end = pending.index(b"\n")
        line = bytes(pending[:end])
        del pending[:end + 1]
        reply = json.loads(line)
        if reply.pop("seq", None) == seq:
            return reply


def watch_begin(args: dict) -> dict:
    """{"units"}: starts watching the caller's processes in those units (scopes or services under the caller's
    own user slice; a trailing * for the part Flatpak or Snap adds). Returns the filesystems watched and the
    ones that can't be, with why. One watch at a time."""
    _must_be_root()
    uid = _caller()[0]
    units = _watch_units(args.get("units"))
    if _WATCH:
        if _WATCH["proc"].poll() is None:
            raise Refused("a watch is already running")
    if ROOT:
        raise Refused("the watch runs on the real system only")
    _watch_forget()                                 # and the folders an earlier one left, if it was killed
    # the child runs the code this helper read as it started (own_source), from a memory file only root holds, never
    # this file as it is now: until the helper is installed that is a copy in the user's runtime folder, which the
    # user, anything running as them, or another copy of the app (another version) can have changed since
    try:
        code = os.memfd_create("daprivacyscanner-watch", os.MFD_CLOEXEC)
    except (AttributeError, OSError):
        raise Refused("the watch couldn't be started") from None
    try:
        with os.fdopen(os.dup(code), "wb") as f:
            f.write(own_source())
        proc = subprocess.Popen([sys.executable, "-I", f"/proc/self/fd/{code}", "--watch"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, close_fds=True,
                                pass_fds=(code,))
    finally:
        os.close(code)
    _WATCH.update({"proc": proc, "uid": uid})
    try:
        proc.stdin.write(json.dumps({"units": units}) + "\n")
        proc.stdin.flush()
        first = _watch_ask(_WATCH, "", WATCH_START_WAIT)
    except Refused:
        _watch_forget()
        raise
    if "error" in first:
        _watch_forget()
        raise Refused(first["error"])
    return {"watched": first["watched"], "skipped": first["skipped"], "units": units}


def watch_poll(args: dict) -> dict:
    """How much the watch has seen so far: counts only."""
    return _watch_ask(_watch_running(), "poll", 10)


def watch_end(args: dict) -> dict:
    """Ends the watch and hands over what it saw, once: the app's files and the files the caller's other
    programs wrote, as records, and counts for the rest. Nothing of it stays here."""
    w = _watch_running()
    try:
        return _watch_ask(w, "end", 120)
    finally:
        _watch_forget()


ACTIONS = {"hello": hello, "keepalive": keepalive, "list_changes": list_changes,
           "ufw_status": ufw_status, "observe_traffic": observe_traffic, "luks_dump": luks_dump, "clevis_list": clevis_list, "read_file": read_file,
           "empty_password_accounts": empty_password_accounts, "sshd_settings": sshd_settings,
           "firewall_summary": firewall_summary,
           "write_dropin": write_dropin, "edit_config": edit_config, "set_service": set_service,
           "set_sysctl": set_sysctl, "ufw_enable": ufw_enable, "browser_policy": browser_policy,
           "block_extensions": block_extensions, "mount_tmpfs": mount_tmpfs,
           "enable_tmp_mount": enable_tmp_mount, "install_self": install_self, "uninstall_self": uninstall_self,
           "ramdisk_open": ramdisk_open, "ramdisk_close": ramdisk_close, "swap_off": swap_off, "swap_on": swap_on,
           "trim_begin": trim_begin, "trim_scan": trim_scan, "trim_result": trim_result, "trim_fstrim": trim_fstrim,
           "trim_end": trim_end, "names_begin": names_begin, "names_step": names_step, "names_result": names_result,
           "names_end": names_end, "names_folder": names_folder, "names_check": names_check,
           "names_fstrim": names_fstrim, "names_orphans": names_orphans, "names_journal_clear": names_journal_clear,
           "erase_facts": erase_facts, "watch_begin": watch_begin, "watch_poll": watch_poll, "watch_end": watch_end,
           "revert": revert,
           "clear_crash_dumps": clear_crash_dumps, "vacuum_journal": vacuum_journal, "snapper_cleanup": snapper_cleanup,
           "clear_journal_files": clear_journal_files,
           "clear_syslog": clear_syslog, "opensnitch_rules": opensnitch_rules,
           "clear_opensnitch_log": clear_opensnitch_log}


# ------------------------------------------------------------------ asking again (consent)
# The session's prompt (pkexec's, for the helper's own polkit action) covers reads and reversible, journalled changes.
# These ask polkit again, each time, for SENSITIVE_ACTION (auth_admin, never kept): what the request does, in the
# prompt's own words ($(what) in the action's message). Declined, nothing is done.
CONSENT = {
    "clear_crash_dumps": "delete the crash dumps and crash reports the system keeps (this can't be undone)",
    "vacuum_journal": "delete the system journal's older records (this can't be undone)",
    "clear_journal_files": "delete the system journal's files on the disk (this can't be undone)",
    "clear_syslog": "delete the text logs in /var/log (this can't be undone)",
    "clear_opensnitch_log": "empty OpenSnitch's log and delete its older copies (this can't be undone)",
    "snapper_cleanup": "delete the snapshots beyond snapper's limits (this can't be undone)",
    "observe_traffic": "watch, for a short while, which sites every account on this computer looks up and connects to",
    "names_orphans": "show names of deleted files that may be other accounts' or the system's",
    "install_self": "install its administrator helper (/usr/libexec/daprivacyscanner) and its polkit actions",
    "uninstall_self": "remove its administrator helper and its polkit actions",
}
CONSENT_ACTIONS = frozenset(CONSENT) | {"revert"}      # the requests that may ask (revert: for remote access)
SUBJECT: tuple[int, int, int] | None = None            # (pid, start time, uid) of the app that started the helper
ASK = None                                             # tests replace it: (what) -> bool


def _proc_start(pid: int) -> int | None:
    """A process's start time (/proc/PID/stat, field 22: clock ticks since boot), which polkit pairs with its pid."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            text = f.read(4096).decode(errors="replace")
        return int(text.rpartition(")")[2].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _remember_subject() -> None:
    """The app's own process (pkexec runs the helper in its place, so the app is its parent), with its start time and
    the user pkexec names: whom polkit asks for the password again, and on whose desktop the prompt comes up."""
    global SUBJECT
    try:
        uid = int(os.environ["PKEXEC_UID"])
    except (KeyError, ValueError):
        return
    pid = os.getppid()
    start = _proc_start(pid)
    if start is not None and pid > 1:
        SUBJECT = (pid, start, uid)


def _pkcheck(what: str) -> bool:
    """polkit asked, with the app's process as the subject, for SENSITIVE_ACTION: the password prompt comes up on the
    user's desktop, through their session's agent. True when it was given."""
    if SUBJECT is None:
        raise Refused("the helper can't tell which program to ask for the password (it wasn't started by pkexec)")
    pid, start, uid = SUBJECT
    if os.getppid() != pid or _proc_start(pid) != start:
        raise Refused("the app that started the helper has ended")
    try:
        p = subprocess.run(["pkcheck", "--action-id", SENSITIVE_ACTION, "--process", f"{pid},{start},{uid}",
                            "--allow-user-interaction", "--detail", "what", what], capture_output=True, text=True,
                           errors="replace", timeout=CONSENT_WAIT, stdin=subprocess.DEVNULL, env=_ENV)
    except FileNotFoundError:
        raise Refused("pkcheck (polkit) isn't installed, so the helper can't ask for the password again") from None
    except subprocess.TimeoutExpired:
        return False
    if p.returncode == 2:
        raise Refused("no password prompt can be shown here (no polkit agent is running in the desktop session)",
                      {"declined": True})
    if p.returncode not in (0, 1, 3):
        raise Refused(f"polkit couldn't be asked: {(p.stderr or p.stdout).strip()[:200]}")
    return p.returncode == 0


def _consent(what: str) -> None:
    """Asks for the password again before `what` (CONSENT); refused, nothing is done. In a fixture tree (tests) there
    is no polkit: granted, unless a test's ASK says otherwise."""
    ask = ASK or (None if ROOT else _pkcheck)
    if ask is not None and not ask(what):
        raise Refused(f"This wasn't done, since your password wasn't given for it: DA Privacy Kit wanted to {what}.",
                      {"declined": True})


# ------------------------------------------------------------------ the session: requests, cancel, idle end

class Stopped(Refused):
    """The request in hand was cancelled by the app (the user stopped it, or closed its panel)."""


_TOO_LONG = object()


class _Input:
    """The app's requests, read from the socket here (never by a buffered reader), one line at a time and at most
    MAX_REQUEST bytes each, so a long request can look for a cancel meant for it without losing what follows."""

    def __init__(self, fd: int = 0):
        self.fd, self.buf, self.eof, self.skipping = fd, bytearray(), False, False

    def _read(self, timeout: float) -> bool:
        if self.eof:
            return False
        try:
            if not select.select([self.fd], [], [], max(timeout, 0))[0]:
                return False
            chunk = os.read(self.fd, 1 << 16)
        except InterruptedError:
            return True
        except OSError:
            chunk = b""
        if not chunk:
            self.eof = True
            return False
        self.buf += chunk
        if b"\n" not in chunk and len(self.buf) > MAX_REQUEST:    # far too long: dropped up to its end
            self.buf.clear()
            self.skipping = True
        return True

    def line(self, timeout: float):
        """The next line (bytes); _TOO_LONG for one past MAX_REQUEST; None at the end of input or after `timeout`."""
        until = time.monotonic() + timeout
        while True:
            i = self.buf.find(b"\n")
            if i >= 0:
                line = bytes(self.buf[:i])
                del self.buf[:i + 1]
                if self.skipping or len(line) > MAX_REQUEST:
                    self.skipping = False
                    return _TOO_LONG
                return line
            if not self._read(until - time.monotonic()):
                if self.eof or time.monotonic() >= until:
                    return None

    def cancelled(self, rid) -> bool:
        """Whether a cancel for request `rid` has come (taken out of what is waiting; other lines stay, in order)."""
        while self._read(0):
            pass
        if b'"cancel"' not in self.buf:
            return False
        lines = self.buf.split(b"\n")
        tail, found, keep = lines.pop(), False, []
        for ln in lines:
            if b'"cancel"' in ln and _cancel_of(ln) == rid and rid is not None:
                found = True
                continue
            keep.append(ln)
        self.buf = bytearray(b"\n".join(keep + [tail]))
        return found


def _cancel_of(line: bytes):
    """The id a cancel request names, or None if the line isn't one."""
    try:
        req = json.loads(line)
    except ValueError:
        return None
    if isinstance(req, dict) and req.get("action") == "cancel" and isinstance(req.get("args"), dict):
        return req["args"].get("id")
    return None


INPUT: _Input | None = None                    # the session's input (main); None when called in-process (tests)
CURRENT = None                                 # the id of the request in hand


def _check_cancel() -> None:
    """Called in the long loops: stops the request in hand when the app has cancelled it."""
    if INPUT is not None and INPUT.cancelled(CURRENT):
        raise Stopped("Stopped.", {"stopped": True})


INSTALL_ACTIONS = frozenset({"hello", "install_self", "uninstall_self"})


def handle(line: str) -> dict:
    global REQUEST_ID, ACTION, CURRENT
    rid = None
    try:
        req = json.loads(line)
        rid = req.get("id") if isinstance(req, dict) else None
        if not isinstance(req, dict) or req.get("action") not in ACTIONS or not isinstance(req.get("args", {}), dict):
            return {"id": rid, "ok": False, "error": "unknown action"}
        action, args = req["action"], dict(req.get("args") or {})
        DID.clear()
        REQUEST_ID, ACTION, CURRENT = None, action, rid
        if MODE == "install" and action not in INSTALL_ACTIONS:
            raise Refused("this copy of the helper only installs or removes itself")
        # (revert names the change it puts back by its own "change_id")
        change_id = args.pop("change_id", None) if action in JOURNALLED else None
        if change_id is not None:
            if not isinstance(change_id, str) or not _CHANGE_ID.match(change_id):
                raise Refused("bad change id")
            if _change_known(change_id):
                raise Refused("that change id has been used already")
            REQUEST_ID = change_id
        # what can't be undone, what reaches beyond the caller's account, and installing or removing the helper: the
        # password again (not for the install-only copy, whose own start asked for exactly that)
        if action in CONSENT and not (MODE == "install" and action in INSTALL_ACTIONS):
            _consent(CONSENT[action])
        result = ACTIONS[action](args)
        if DID and isinstance(result, dict):
            result = {**result, "ran": list(DID)}
        return {"id": rid, "ok": True, "result": result}
    except Refused as e:
        # what it had run before it failed, and a change it journalled on the way (Refused.data)
        return {"id": rid, "ok": False, "error": str(e), **({"ran": list(DID)} if DID else {}),
                **{k: v for k, v in e.data.items() if k in ("change_id", "message", "declined", "stopped")}}
    except json.JSONDecodeError:
        return {"id": None, "ok": False, "error": "bad request"}
    except Exception as e:  # noqa: BLE001 - report, never crash mid-session
        return {"id": rid, "ok": False, "error": f"{type(e).__name__}"}
    finally:
        REQUEST_ID, CURRENT = None, None


OUT = 1                                        # where answers go (serve)


def _send(reply: dict) -> bool:
    data = (json.dumps(reply) + "\n").encode()
    while data:
        try:
            n = os.write(OUT, data)
        except InterruptedError:
            continue
        except OSError:
            return False
        data = data[n:]
    return True


def _boottime() -> float:
    """Seconds since boot, the time asleep included (the lifetime counts it; idle time is measured while awake)."""
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


def serve(fd: int = 0, out: int = 1) -> None:
    """The session: requests on `fd` (answers on `out`) until the end of input, HELPER_IDLE seconds without one, or
    HELPER_LIFETIME."""
    global INPUT, OUT
    INPUT, OUT = _Input(fd), out
    started = _boottime()
    try:
        while True:
            left = HELPER_LIFETIME - (_boottime() - started)
            if left <= 0:
                return
            line = INPUT.line(min(HELPER_IDLE, left))
            if line is None:
                return                                 # the app is gone, or hasn't asked for anything in a while
            if line is _TOO_LONG:
                if not _send({"id": None, "ok": False, "error": "request too long"}):
                    return
                continue
            if not line.strip() or (b'"cancel"' in line and _cancel_of(line) is not None):
                continue                               # a cancel for a request already answered
            if not _send(handle(line.decode("utf-8", "replace"))):
                return
    finally:
        INPUT = None
        if _WATCH:                                     # the access dropped, or the app gone, with a watch on
            _watch_forget()


def main() -> None:
    global MODE
    _harden()
    if sys.argv[1:] == ["--watch"]:                    # the watch's own process (watch_begin starts it)
        _watch_child()
        return
    if sys.argv[1:] == ["--install-only"]:             # privileged.install_helper's loader starts it so
        MODE = "install"
    try:
        own_source()                                   # now, before any request: what install_self installs
    except OSError:
        pass
    _remember_subject()
    serve(0)


def _harden() -> None:
    """What the helper inherits from whoever ran pkexec, put right before anything is done: the umask (pkexec keeps
    the user's: under 000 the helper's own folders were made writable by every account, under 077 the services
    couldn't read the drop-ins it wrote), the working folder, resource limits that would cut a write or a read short
    (a file size limit truncating a config file, or the journal entry recording it), and crash dumps."""
    os.umask(0o022)
    try:
        os.chdir("/")
    except OSError:
        pass
    try:
        import resource
        inf = resource.RLIM_INFINITY
        for name in ("RLIMIT_FSIZE", "RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_CPU"):
            try:
                resource.setrlimit(getattr(resource, name), (inf, inf))
            except (ValueError, OSError, AttributeError):
                pass
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != inf and soft < 4096:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (4096, max(hard, 4096) if hard != inf else inf))
            except (ValueError, OSError):
                pass
    except ImportError:
        pass
    _no_dumps()


def _no_dumps() -> None:
    # what it holds (deleted files' names, a drive's identify data) never reaches a crash dump or the journal's record
    # of one: at a core size limit of 1 the kernel skips the dump altogether (the app's no_core_dumps, tested)
    try:
        with open("/proc/self/coredump_filter", "w") as f:
            f.write("0")
    except OSError:
        pass
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (1, 1))
    except (ImportError, ValueError, OSError):
        pass


if __name__ == "__main__":
    main()
