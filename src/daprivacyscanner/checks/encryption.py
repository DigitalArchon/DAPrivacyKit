"""Encryption and data at rest (enc.*)."""

from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .. import blockdev, ini
from ..context import read_swaps
from ..desktop import parse_gvariant
from ..host import Host, Unreadable
from ..model import Evidence, Note, Outcome, Status
from ..privileged import HelperError
from . import Check, Scan, register
from ._util import (ON_ENCRYPTED_DISK, Tally, absent, children, failed, human_size, isdir, mounts, needs_root,
                    on_encrypted_disk, passed, read_json, read_text, sqlite_count, storage_mounts, systemctl_state,
                    tally, unknown, uri_path, warned)


def _devices(scan: Scan) -> list[blockdev.Device] | None:
    return scan.context.devices


@register
class FdeMissing(Check):
    id = "enc.fde_missing"

    def detect(self, scan: Scan) -> Outcome:
        fde = scan.context.values["fde"]
        if fde.value is None:
            return unknown(f"Couldn't tell whether the disk is encrypted: {fde.note}", *fde.evidence)
        if fde.value == "none":
            return failed("The root filesystem is not encrypted.", *fde.evidence, findings={"home_ecryptfs": False})
        if fde.value == "home":
            from ..context import home_encryption
            method, _ = home_encryption(scan.host, _devices(scan))
            return failed(HOME_ONLY_SUMMARY.get(method, "Only the home folder is encrypted; the rest of the disk isn't."),
                          *fde.evidence, notes=home_only_notes(method), findings={"home_ecryptfs": method == "ecryptfs"})
        return passed("The root filesystem is encrypted.", *fde.evidence, findings={"home_ecryptfs": False})


HOME_ONLY_SUMMARY = {
    "ecryptfs": "Only the home folder is encrypted, with eCryptfs, which is no longer recommended; the rest of the disk "
                "isn't.",
    "fscrypt": "Only the home folder is encrypted (fscrypt); the rest of the disk isn't.",
    "luks": "Only the home folder's volume is encrypted; the system disk isn't.",
}


def home_only_notes(method: str | None) -> list[Note]:
    """What encrypting only the home folder leaves open, by how it is done."""
    notes = [Note("risk", "What home folder encryption leaves open",
                  "Everything outside your home folder is readable from the disk: system logs, saved Wi-Fi passwords, "
                  "/tmp, and swap, which can hold pieces of your files and passwords. And since the system itself is "
                  "unencrypted, someone with the computer for a few minutes can change it to record your password "
                  "the next time you log in. Full-disk encryption covers all of it.",
                  ("enc.swap_unencrypted", "net.wifi_history"))]
    if method == "ecryptfs":
        notes.append(Note("risk", "eCryptfs is no longer recommended",
                          "It encrypts files one by one on top of the real filesystem. It is barely maintained, Ubuntu "
                          "dropped it from its installer in 18.04, and it shows file sizes, timestamps and the folder "
                          "layout. Plan a move to full-disk encryption; don't set it up again."))
    elif method == "fscrypt":
        notes.append(Note("info", "What fscrypt protects",
                          "The filesystem's own encryption covers the contents and names of your files, but not their "
                          "sizes, timestamps or how many there are in each folder. It is better than eCryptfs; "
                          "full-disk encryption is still the goal."))
    return notes


@register
class PartialFde(Check):
    id = "enc.partial_fde"

    def detect(self, scan: Scan) -> Outcome:
        fde = scan.context.values["fde"]
        if fde.value is None:
            return unknown(f"Couldn't tell which filesystems are encrypted: {fde.note}", *fde.evidence)
        if fde.value in ("none", "home"):
            return absent("The system disk isn't encrypted: see full-disk encryption.", *fde.evidence)
        if fde.value == "partial":
            return failed("Some fixed, mounted filesystems are not encrypted.", *fde.evidence)
        return passed("Every fixed, mounted data filesystem is encrypted.", *fde.evidence)


# ------------------------------------------------------------------ partitions nothing uses

# filesystems that hold files; what another system made is named for it
UNUSED_FSTYPES = {"ntfs": "Windows (NTFS)", "refs": "Windows (ReFS)", "exfat": "exFAT, shared between systems",
                "vfat": "FAT, shared between systems", "apfs": "macOS (APFS)", "hfsplus": "macOS (HFS+)",
                "hfs": "macOS (HFS)", **{fs: f"Linux ({fs})" for fs in ("ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs",
                                                                         "jfs", "reiserfs", "nilfs2")}}
LOCKED_FSTYPES = {"bitlocker": "BitLocker", "crypto_luks": "LUKS"}
# EFI system, Microsoft reserved, Windows recovery, BIOS boot, extended boot loader; MBR: EFI, hidden recovery, OEM
NOT_DATA_PARTTYPES = frozenset({
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "e3c9e316-0b5c-4db8-817d-f92df00215ae", "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
    "21686148-6449-6e6f-744e-656564454649", "bc13c2ff-59e6-4262-a352-b275fd6f7172", "0xef", "0x27", "0x12", "0xde"})
RECOVERY_LABEL = re.compile(r"recovery|winre|restore|reserved|diag", re.I)
SMALLEST_DATA_PARTITION = 2 * 1024 ** 3


def unused_partitions(devices: list[blockdev.Device]) -> tuple[list[blockdev.Device], list[blockdev.Device]]:
    """(unencrypted, encrypted) filesystems on the fixed drives that this system has not mounted: another system's,
    an earlier install's, a data disk not in use. Boot, recovery and reserved partitions hold nothing of the user's."""
    in_use = {d.uuid for d in devices if d.mountpoints and d.uuid}
    plain, locked, seen = [], [], set()
    for d in devices:
        fs = (d.fstype or "").lower()
        if (d.name in seen or d.removable or d.mountpoints or d.children or d.name.startswith("zram")
                or blockdev.disk_of(d).type in ("loop", "rom")):
            continue
        seen.add(d.name)
        if fs in LOCKED_FSTYPES:
            locked.append(d)
        elif (fs in UNUSED_FSTYPES and not d.encrypted and not (d.uuid and d.uuid in in_use)
              and d.parttype not in NOT_DATA_PARTTYPES and not (d.label and RECOVERY_LABEL.search(d.label))
              and (d.size is None or d.size >= SMALLEST_DATA_PARTITION)):
            plain.append(d)
    return plain, locked


def partition_text(d: blockdev.Device) -> str:
    fs = (d.fstype or "").lower()
    kind = UNUSED_FSTYPES.get(fs) or LOCKED_FSTYPES.get(fs) or fs
    return f"{kind}, {human_size(d.size)}" if d.size else kind


@register
class UnmountedUnencrypted(Check):
    id = "enc.unmounted_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        if scan.context["virtualization"] == "container":
            return absent("A container sees its host's drives, not ones of its own.")
        try:
            devices = blockdev.read_partitions(scan.host)
        except blockdev.LsblkError as e:
            return unknown(f"Couldn't list the partitions: {e}.")
        plain, locked = unused_partitions(devices)
        ev = [Evidence.val(d.path, f"not encrypted: {partition_text(d)}") for d in plain]
        ev += [Evidence.val(d.path, f"encrypted ({partition_text(d)})") for d in locked]
        if not plain:
            return passed("No unencrypted partition was found beside the ones this system uses.", *ev)
        other = sorted({UNUSED_FSTYPES[d.fstype.lower()].split(" (")[0].split(",")[0] for d in plain})
        n = len(plain)
        return failed(f"{n} partition{'s' if n > 1 else ''} this system doesn't use {'are' if n > 1 else 'is'}n't "
                      f"encrypted ({', '.join(other)}): anyone with the computer or the drive can read "
                      f"{'them' if n > 1 else 'it'}.", *ev)


# ------------------------------------------------------------------ swap and hibernation

def zram_backing(host, name: str) -> str | None:
    """The device a zram swap writes idle or incompressible pages back to, if any."""
    zram = name.removeprefix("/dev/")
    backing = (host.read_sys(f"/sys/block/{zram}/backing_dev") or "none").strip()
    return None if backing in ("", "none") else backing


ZRAM_CONFIGS = ("/etc/systemd/zram-generator.conf", "/run/systemd/zram-generator.conf", "/usr/lib/systemd/zram-generator.conf")


def zram_writeback_configured(host) -> list[str]:
    """writeback-device= in zram-generator's configuration: the first main file found (/etc over
    /run over /usr/lib) and every drop-in. Set up there, zram writes back from the next boot."""
    files = [next((f for f in ZRAM_CONFIGS if host.sys_path(f).is_file()), None)]
    for d in ("/etc/systemd/zram-generator.conf.d", "/run/systemd/zram-generator.conf.d",
              "/usr/lib/systemd/zram-generator.conf.d"):
        files += [str(Path(d) / c.name) for c in children(host.sys_path(d)) if c.name.endswith(".conf")]
    out = []
    for f in filter(None, files):
        for m in re.finditer(r"^\s*writeback-device\s*=\s*(\S+)", read_text(host, host.sys_path(f)) or "", re.M):
            out.append(m.group(1))
    return out


def _swap_device(scan: Scan, name: str, kind: str) -> blockdev.Device | None:
    devices = _devices(scan) or []
    if kind == "partition":
        return blockdev.find(devices, scan.host, name)
    return blockdev.holding(devices, name)


@register
class SwapUnencrypted(Check):
    id = "enc.swap_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        swaps = read_swaps(scan.host)
        if not swaps:
            return passed("No swap is in use.")
        if _devices(scan) is None:
            return unknown("Couldn't list block devices (lsblk) to check where swap lives.")
        ev, bad, unsure = [], [], []
        devices = _devices(scan) or []
        for name, kind, size in swaps:
            if name.startswith("/dev/zram"):
                backing = zram_backing(scan.host, name)
                if backing is None:
                    ev.append(Evidence.val(name, "in memory (zram)"))
                    continue
                dev = blockdev.find(devices, scan.host, backing)
                if dev is None:
                    unsure.append(name)
                    ev.append(Evidence.val(name, f"zram writing back to {backing}: couldn't find that device"))
                elif dev.encrypted:
                    ev.append(Evidence.val(name, f"zram writing back to {backing}, encrypted ({dev.name})"))
                else:
                    bad.append(name)
                    ev.append(Evidence.val(name, f"zram writing back to {backing}, not encrypted"))
                continue
            dev = _swap_device(scan, name, kind)
            if dev is None:
                unsure.append(name)
                ev.append(Evidence.val(name, "couldn't find its device"))
            elif dev.encrypted:
                ev.append(Evidence.val(name, f"encrypted ({dev.name})"))
            else:
                bad.append(name)
                ev.append(Evidence.val(name, f"not encrypted ({dev.name})"))
        for dev_name in zram_writeback_configured(scan.host):
            d = blockdev.find(devices, scan.host, dev_name)
            if d is not None and not d.encrypted and not bad:      # (an active writeback is reported already)
                bad.append(f"zram writeback set up to {dev_name}")
                ev.append(Evidence.val("zram-generator", f"writeback-device={dev_name}, not encrypted"))
        if bad:
            return failed(f"Swap is written to unencrypted storage: {', '.join(bad)}.", *ev)
        if unsure:
            return unknown("Couldn't tell whether some swap is encrypted.", *ev)
        return passed("All swap is encrypted or in memory.", *ev)


def hibernation_targets(scan: Scan) -> list[tuple[str, blockdev.Device | None]] | None:
    """Where a hibernation image would be written: the resume device, or (with none fixed, as
    systemd picks one at hibernation time) every disk swap. None without lsblk."""
    devices = _devices(scan)
    if devices is None:
        return None
    resume = (scan.host.read_sys("/sys/power/resume") or "").strip()
    if resume and resume != "0:0":
        node = scan.host.sys_path(f"/sys/dev/block/{resume}")
        name = node.resolve().name if node.exists() else resume
        return [(f"resume device {resume}", blockdev.find(devices, scan.host, f"/dev/{name}"))]
    return [(name, _swap_device(scan, name, kind)) for name, kind, _ in read_swaps(scan.host)
            if not name.startswith("/dev/zram")]


def hibernation_encrypted(scan: Scan) -> bool | None:
    """Whether hibernating works and its image goes to encrypted storage (None: can't tell)."""
    if scan.context["hibernation"] is not True:
        return False if scan.context["hibernation"] is False else None
    targets = hibernation_targets(scan)
    if not targets or any(d is None for _, d in targets):
        return None
    return all(d.encrypted for _, d in targets)


@register
class HibernateUnencrypted(Check):
    id = "enc.hibernate_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        hib = scan.context.values["hibernation"]
        if hib.value is False:
            why = hib.note[:1].lower() + hib.note[1:] if hib.note else ""
            return passed("Hibernation isn't possible on this machine" + (f": {why}." if why else "."), *hib.evidence,
                          notes=hib.notes)
        if hib.value is None:
            return unknown(f"Couldn't tell whether this machine can hibernate: {hib.note}")
        targets = hibernation_targets(scan)
        if targets is None:
            return unknown("Couldn't list block devices (lsblk) to check where the image would go.")
        ev = [Evidence.val(what, "unknown" if d is None else f"{d.name}, {'encrypted' if d.encrypted else 'not encrypted'}")
              for what, d in targets]
        if any(d is not None and not d.encrypted for _, d in targets):
            return failed("The hibernation image would be written to unencrypted storage.", *ev)
        if any(d is None for _, d in targets) or not targets:
            return unknown("Couldn't find the device the hibernation image is written to.", *ev)
        return passed("The hibernation image is written to encrypted storage.", *ev)


@register
class SwapPersistent(Check):
    id = "enc.swap_persistent"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        swaps = read_swaps(host)
        if not swaps:
            return passed("No swap is in use.")
        try:
            crypttab = host.read_sys("/etc/crypttab") or ""
        except Unreadable:
            crypttab = None
        random_key = set()
        for line in (crypttab or "").splitlines():
            f = line.split()
            if len(f) >= 3 and not f[0].startswith("#") and f[2] in ("/dev/urandom", "/dev/random"):
                random_key.add(f[0])

        devices = _devices(scan) or []

        def how_kept(dev: blockdev.Device | None) -> tuple[bool, str]:
            """(persists across reboots, in words) for the device swapped-out pages land on."""
            if dev is None:
                return True, "couldn't find its device"
            if dev.type == "crypt" and dev.name in random_key:
                return False, "encrypted with a new random key each boot"
            if dev.encrypted:
                return True, "encrypted, with the same key every boot"
            return True, "not encrypted"

        ev, persistent, partial, encrypted_kept = [], [], False, False
        for name, kind, _ in swaps:
            if name.startswith("/dev/zram"):
                backing = zram_backing(host, name)
                if backing is None:
                    ev.append(Evidence.val(name, "zram (memory only)"))
                    continue
                dev = blockdev.find(devices, host, backing)
                kept, words = how_kept(dev)
                partial |= dev is not None and dev.type == "crypt" and crypttab is None
                ev.append(Evidence.val(name, f"zram writing back to {backing}: {words}"))
            else:
                dev = _swap_device(scan, name, kind)
                kept, words = how_kept(dev)
                if dev is not None and dev.type == "crypt" and kind == "partition":
                    partial |= crypttab is None
                ev.append(Evidence.val(name, "kept on disk, " + words if kept else words))
            if kept:
                persistent.append(name)
                encrypted_kept |= dev is not None and dev.encrypted
        configured = zram_writeback_configured(host)
        if configured and not any(n.startswith("/dev/zram") and zram_backing(host, n) for n, _, _ in swaps):
            dev = blockdev.find(devices, host, configured[0])
            kept, words = how_kept(dev)
            ev.append(Evidence.val("zram-generator", f"writeback-device={', '.join(configured)}: {words}"))
            if kept:
                persistent.append("zram writeback (from the next boot)")
                encrypted_kept |= dev is not None and dev.encrypted
        if persistent:
            notes = [Note("risk", "Earlier sessions' swap can be read back",
                          "Swapped-out pages (pieces of documents, passwords, keys) stay on the disk after a reboot "
                          "until they happen to be overwritten. "
                          + ("Encrypted with the same key at every boot, they are safe from someone who takes the "
                             "machine while it is off, but not from anyone with administrator access while it is "
                             "unlocked (or malware running as root), who can read the raw device, nor from anyone who "
                             "later learns, or is made to give up, the passphrase. " if encrypted_kept else "")
                          + "A new random key at each boot, or zram without writeback, leaves nothing from earlier "
                          "sessions.", ("enc.swap_unencrypted",))]
            return failed(f"Swap persists across reboots: {', '.join(persistent)}.", *ev, partial=partial, notes=notes)
        return passed("Swap is in memory or re-encrypted with a random key at each boot.", *ev)


# ------------------------------------------------------------------ LUKS headers

@register
class LuksWeakKdf(Check):
    id = "enc.luks_weak_kdf"

    def detect(self, scan: Scan) -> Outcome:
        devices = _devices(scan)
        if devices is None:
            return unknown("Couldn't list block devices (lsblk).")
        luks = blockdev.luks_devices(devices)
        if not luks:
            return absent("No encrypted volumes are open.")
        if scan.privileged is None:
            return needs_root("Reading the LUKS headers")
        ev, weak, unsure = [], [], []
        for dev in luks:
            try:
                dump = scan.privileged.luks_dump(dev.path)
            except HelperError as e:
                unsure.append(dev.name)
                ev.append(Evidence.val(f"{dev.name}", f"couldn't read the header: {str(e)[:100]}"))
                continue
            # keyslots that hold a TPM or FIDO2 key are random, high-entropy keys: the KDF doesn't matter
            token_slots = {k for t in dump["tokens"] for k in t["keyslots"]}
            if dump["version"] == 1:
                weak.append(dev.name)
                ev.append(Evidence.val(dev.name, "LUKS1 (PBKDF2 only)"))
                continue
            soft = [k for k in dump["keyslots"] if k["id"] not in token_slots
                    and (k["pbkdf"] or "").lower() not in ("argon2id", "argon2i")]
            kinds = {"systemd-fido2": "security key", "systemd-tpm2": "TPM", "systemd-recovery": "recovery key",
                     "systemd-pkcs11": "smart card", "clevis": "Clevis"}
            for t in dump["tokens"]:
                for k in t["keyslots"]:
                    ev.append(Evidence.val(f"{dev.name} keyslot {k}", f"{kinds.get(t['type'], t['type'])}: a long random "
                                           "key, so its key derivation doesn't matter"))
            if soft:
                weak.append(dev.name)
                ev.append(Evidence.val(dev.name, "keyslot " + ", ".join(f"{k['id']} uses {k['pbkdf']}" for k in soft)))
            else:
                ev.append(Evidence.val(dev.name, "LUKS2, passphrase keyslots use Argon2"))
        if weak:
            return failed(f"Weak key derivation on {', '.join(weak)}.", *ev)
        if unsure:
            return unknown("Some LUKS headers couldn't be read.", *ev)
        return passed("Every passphrase keyslot uses Argon2.", *ev)


@register
class TpmNoPin(Check):
    id = "enc.tpm_no_pin"

    def detect(self, scan: Scan) -> Outcome:
        tpm = scan.context.values["tpm_unlock_no_pin"]
        devices = _devices(scan)
        if devices is not None and not blockdev.luks_devices(devices):
            return absent("No encrypted volumes are open.")
        if tpm.value is True:
            return failed("A volume unlocks from the TPM without a PIN.", *tpm.evidence)
        if tpm.value is False:
            return passed(tpm.note, *tpm.evidence)
        o = unknown(f"Couldn't check: {tpm.note}", *tpm.evidence, notes=tpm.notes)
        o.needs_admin = scan.privileged is None and "administrator access" in (tpm.note or "")   # "Scan with …" offers it
        return o


# ------------------------------------------------------------------ backups

def _by_uuid(scan: Scan, uuid: str) -> blockdev.Device | None:
    if not uuid or "/" in uuid:
        return None
    try:
        target = scan.host.sys_path(f"/dev/disk/by-uuid/{uuid}").readlink()
    except OSError:
        return None
    return blockdev.find(_devices(scan) or [], scan.host, f"/dev/{target.name}")


def _dejadup(scan: Scan, schema: str, key: str):
    v = scan.gnome.gsettings(schema, key)
    if v is not None:
        return v
    # the Flatpak keeps its settings in a keyfile of its own
    keyfile = scan.paths.flatpak_root / "org.gnome.DejaDup/config/glib-2.0/settings/keyfile"
    sub = schema.removeprefix("org.gnome.DejaDup").lstrip(".").lower()
    group = "org/gnome/deja-dup" + (f"/{sub}" if sub else "")
    raw = ini.get(ini.parse(read_text(scan.host, keyfile) or ""), group, key)
    return parse_gvariant(raw) if raw is not None else None


def _encrypted_drive(d: blockdev.Device) -> bool:
    """A backup drive given by UUID is encrypted when it is (or sits on) dm-crypt, or is the LUKS
    container itself (the UUID a tool may record for an encrypted drive)."""
    return d.encrypted or d.fstype == "crypto_LUKS"


# borg's modes that store the data unencrypted ("authenticated" only checks it hasn't been changed)
BORG_PLAIN = frozenset({"none", "authenticated", "authenticated-blake2"})


def _destination(scan: Scan, path: str) -> tuple[str, str]:
    """("ok" | "bad" | "unsure", in words) for a backup tool that doesn't encrypt, by the drive its folder is on."""
    st = storage_of(scan, path)
    if st.encrypted is None:
        return "unsure", "couldn't tell whether its drive is encrypted"
    return ("ok", "on an encrypted drive") if st.encrypted else ("bad", "on an unencrypted drive")


def other_backups(scan: Scan) -> list[tuple[str, str, str]]:
    """(tool, "ok" | "bad" | "unsure", in words) for each backup set up in Back In Time, Kup, Vorta or Pika Backup.
    Read from their own settings: Back In Time's profileN.snapshots.mode (local, ssh, and the encrypting
    local_encfs/ssh_encfs or, in newer releases, local_gocryptfs/ssh_gocryptfs) and snapshots.path; Kup's
    kuprc [Plan/N] (it never encrypts: Destination type 0, a folder, or 1, an external drive by UUID); Vorta's
    settings.db repomodel.encryption and Pika Backup's config.json encryption_mode (borg's modes; tested on
    CachyOS: Vorta 0.11.6's table, Pika Backup 0.8.4's field)."""
    host, out = scan.host, []
    for loc in scan.paths.config("backintime/config"):
        conf = dict(line.split("=", 1) for line in (read_text(host, loc.path) or "").splitlines() if "=" in line)
        for n in (conf.get("profiles") or "1").split(":"):
            path = conf.get(f"profile{n}.snapshots.path", "")
            mode = conf.get(f"profile{n}.snapshots.mode", "local")
            if not path and not mode.startswith("ssh"):
                continue
            if mode.endswith(("_encfs", "_gocryptfs")):
                out.append(("Back In Time", "ok", f"profile {n}: encrypted ({mode})"))
            elif mode.startswith("ssh"):
                out.append(("Back In Time", "bad", f"profile {n}: copies on a server over SSH, not encrypted"))
            else:
                state, words = _destination(scan, path)
                out.append(("Back In Time", state, f"profile {n}: not encrypted by Back In Time, {words}"))
    for loc in scan.paths.config("kuprc"):
        conf = ini.parse(read_text(host, loc.path) or "", kde=True)
        for group, keys in conf.items():
            if not group or not re.fullmatch(r"Plan/\d+", group[0]):
                continue
            n = group[0].split("/")[1]
            if keys.get("Destination type", "1") == "0":
                path = uri_path(keys.get("Filesystem destination path", "")) or keys.get("Filesystem destination path", "")
                state, words = _destination(scan, path) if path else ("unsure", "its folder isn't set")
            else:
                dev = _by_uuid(scan, keys.get("External drive UUID", ""))
                state, words = ("unsure", "its drive isn't attached") if dev is None else \
                    ("ok", "on an encrypted drive") if _encrypted_drive(dev) else ("bad", "on an unencrypted drive")
            out.append(("Kup", state, f"plan {n}: Kup doesn't encrypt; {words}"))
    for loc in scan.paths.data("Vorta/settings.db", flatpak=["com.borgbase.Vorta"]):
        total = sqlite_count(loc.path, "SELECT count(*) FROM repomodel")
        if total is None:
            out.append(("Vorta", "unsure", "its settings couldn't be read"))
            continue
        quoted = ", ".join(f"'{m}'" for m in sorted(BORG_PLAIN))
        plain = sqlite_count(loc.path, f"SELECT count(*) FROM repomodel WHERE encryption IN ({quoted})") or 0
        if total:
            out.append(("Vorta", "bad" if plain else "ok",
                        f"{plain} of {total} repositor{'ies' if total > 1 else 'y'} not encrypted" if plain
                        else f"{total} repositor{'ies' if total > 1 else 'y'}, encrypted"))
    for loc in scan.paths.config("pika-backup/config.json", flatpak=["org.gnome.World.PikaBackup"]):
        data = read_json(host, loc.path)
        backups = data if isinstance(data, list) else []
        modes = [str(b.get("encryption_mode") or "") for b in backups if isinstance(b, dict)]
        if modes:
            plain = sum(1 for m in modes if m in BORG_PLAIN)
            out.append(("Pika Backup", "bad" if plain else "ok",
                        f"{plain} of {len(modes)} backup{'s' if len(modes) > 1 else ''} not encrypted" if plain
                        else f"{len(modes)} backup{'s' if len(modes) > 1 else ''}, encrypted"))
    return out


@register
class BackupsUnencrypted(Check):
    id = "enc.backups_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, bad, ok, unsure = [], [], [], []

        try:
            ts = json.loads(host.read_sys("/etc/timeshift/timeshift.json") or "null")
        except (ValueError, Unreadable):
            ts = None
        if isinstance(ts, dict) and ts.get("backup_device_uuid"):
            dev = _by_uuid(scan, ts["backup_device_uuid"])
            mode = "btrfs snapshots" if str(ts.get("btrfs_mode")).lower() == "true" else "rsync"
            if dev is None:
                unsure.append("Timeshift")
                ev.append(Evidence.val("Timeshift", f"{mode}; its drive isn't attached"))
            elif _encrypted_drive(dev):
                ok.append("Timeshift")
                ev.append(Evidence.val("Timeshift", f"{mode} on encrypted {dev.name}"))
            else:
                bad.append("Timeshift")
                ev.append(Evidence.val("Timeshift", f"{mode} on unencrypted {dev.name} (Timeshift doesn't encrypt)"))

        last = _dejadup(scan, "org.gnome.DejaDup", "last-backup") or _dejadup(scan, "org.gnome.DejaDup", "last-run")
        if last:
            tool = _dejadup(scan, "org.gnome.DejaDup", "tool") or "duplicity"
            backend = _dejadup(scan, "org.gnome.DejaDup", "backend") or ""
            if tool == "restic":
                ok.append("Déjà Dup")
                ev.append(Evidence.val("Déjà Dup", "restic (always encrypted)"))
            else:
                folder = None
                if backend == "local":
                    f = _dejadup(scan, "org.gnome.DejaDup.Local", "folder") or ""
                    folder = Path(f) if f.startswith("/") else host.home / f
                elif backend == "drive":
                    dev = _by_uuid(scan, _dejadup(scan, "org.gnome.DejaDup.Drive", "uuid") or "")
                    mounted = next((d for d in ([dev] + blockdev.descendants(dev) if dev else []) if d.mountpoints), None)
                    if mounted is not None:
                        folder = Path(mounted.mountpoints[0]) / (_dejadup(scan, "org.gnome.DejaDup.Drive", "folder") or "")
                if folder is None or not isdir(folder):
                    unsure.append("Déjà Dup")
                    ev.append(Evidence.val("Déjà Dup", f"{backend or 'unknown'} backend; backup files not reachable"))
                else:
                    names = [p.name for p in children(folder)]
                    plain = sum(1 for n in names if n.startswith("duplicity-") and n.endswith((".gz", ".tar")))
                    enc = sum(1 for n in names if n.startswith("duplicity-") and n.endswith(".gpg"))
                    if plain:
                        bad.append("Déjà Dup")
                        ev.append(Evidence.count(f"Unencrypted Déjà Dup volumes in {host.display(folder)}", plain))
                    elif enc:
                        ok.append("Déjà Dup")
                        ev.append(Evidence.count("Encrypted Déjà Dup volumes", enc))
                    else:
                        unsure.append("Déjà Dup")

        for name, state, text in other_backups(scan):
            {"ok": ok, "bad": bad, "unsure": unsure}[state].append(name)
            ev.append(Evidence.val(name, text))
        limit = Note("limitation", "Some backup tools aren't checked",
                     "Borg and restic run by hand or from scripts, rsync scripts and cloud backup apps keep their "
                     "settings in places the app doesn't read. If you use one, check that it encrypts.")
        if bad:
            return failed(f"Unencrypted backups: {', '.join(dict.fromkeys(bad))}.", *ev, notes=[limit])
        if unsure:
            return unknown(f"Couldn't check: {', '.join(dict.fromkeys(unsure))}.", *ev, notes=[limit])
        if ok:
            return passed("Backups found are encrypted.", *ev, notes=[limit])
        return passed("No backups set up with Timeshift, Déjà Dup, Back In Time, Kup, Vorta or Pika Backup.",
                      notes=[limit])


# ------------------------------------------------------------------ removable drives

DATA_FSTYPES = frozenset({"vfat", "exfat", "ntfs", "ntfs3", "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "hfsplus",
                          "apfs", "udf"})


@register
class RemovableUnencrypted(Check):
    id = "enc.removable_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        devices = _devices(scan)
        if devices is None:
            return unknown("Couldn't list block devices (lsblk).")
        sticks = sorted({blockdev.disk_of(d).name for d in devices
                         if d.removable and blockdev.disk_of(d).type != "rom" and blockdev.boot_stick(d)})   # not CD drives
        plain = [d for d in devices if d.removable and not d.is_image and d.fstype in DATA_FSTYPES and not d.encrypted
                 and blockdev.disk_of(d).name not in sticks]
        luks = [d for d in devices if d.removable and d.fstype == "crypto_LUKS"]
        note = Note("limitation", "Only drives attached now are checked",
                    "Plug in your USB sticks and external drives and scan again to check them.")
        ev = [Evidence.val("Not encrypted", f"{d.name} ({d.fstype}" + (f", at {d.mountpoints[0]})" if d.mountpoints else ")"))
              for d in plain]
        ev += [Evidence.val("Encrypted", d.name) for d in luks]
        ev += [Evidence.val("Installer or boot stick, left out", s) for s in sticks]
        if plain:
            return failed(f"{len(plain)} attached removable drive{'s are' if len(plain) > 1 else ' is'} not encrypted.",
                          *ev, notes=[note])
        if luks:
            return passed("Attached removable drives are encrypted.", *ev, notes=[note])
        if sticks:
            return passed("The only removable drives attached are installer or boot sticks.", *ev, notes=[note])
        return passed("No removable drives are attached.", notes=[note])


# ------------------------------------------------------------------ crash dumps

def _layered(host: Host, main: str, dropin: str = "") -> dict:
    """A systemd config file and its drop-ins, in systemd's order (context.systemd_config)."""
    from ..context import systemd_config
    return systemd_config(host, main)[0]


PAGE = 4096                     # the kernel writes no core file under a page (binfmt min_coredump), nor does
                                # systemd-coredump store one ("Resource limits disable core dumping")
# crash handlers that keep nothing (kernel.core_pattern=|/bin/false is a common way to turn core files off)
NOTHING_KEPT = re.compile(r"^\|\s*(/usr)?/bin/(false|true)(\s|$)")


def _soft_core_limit(text: str | None) -> int | None:
    """The soft core size limit in bytes from a /proc/PID/limits text (None: not there; unlimited: a big number)."""
    m = re.search(r"^Max core file size\s+(\S+)", text or "", re.M)
    if not m:
        return None
    return 2**63 if m.group(1) == "unlimited" else int(m.group(1)) if m.group(1).isdigit() else None


def user_core_limit(host: Host) -> tuple[int | None, str]:
    """The soft core size limit the programs this user runs get, and where it was read: the session's (this app's
    parent's /proc/PID/limits: the desktop, the terminal's shell or the user's service manager that started it; never
    the app's own, which app.no_core_dumps sets to 1), and the user service manager's DefaultLimitCORESoft for what it
    starts. The higher of the two; None when neither could be read."""
    found = []
    m = re.search(r"^PPid:\s*(\d+)", host.read_sys("/proc/self/status") or "", re.M)
    if m and m.group(1) != "0":
        limit = _soft_core_limit(host.read_sys(f"/proc/{m.group(1)}/limits"))
        if limit is not None:
            found.append(limit)
    r = host.run("systemctl", "--user", "show", "-p", "DefaultLimitCORESoft")
    value = r.stdout.strip().partition("=")[2] if r.ok else ""
    if value:
        found.append(2**63 if value == "infinity" else int(value) if value.isdigit() else 0)
    if not found:
        return None, ""
    limit = max(found)
    return limit, ("unlimited" if limit >= 2**62 else f"{limit} bytes") + (" (no core files)" if limit < PAGE else "")


def crash_dumps(host: Host) -> tuple[bool | None, int, list[Evidence]]:
    """(whether crashes are kept on disk, None when that can't be told; how many are there now; evidence):
    systemd-coredump's Storage, apport, a handler that keeps nothing (|/bin/false), or a plain core file, which the
    kernel writes only up to the core size limit of the programs the user runs (user_core_limit). Also used by the
    browser panel's risks (tools/browser.py)."""
    pattern = (host.read_sys("/proc/sys/kernel/core_pattern") or "").strip()
    ev = [Evidence.val("core_pattern", pattern[:120] or "unknown")]
    retained: bool | None = False
    existing = 0
    if pattern.startswith("|") and "systemd-coredump" in pattern:
        cfg = _layered(host, "coredump.conf", "coredump.conf.d")
        storage = (ini.get(cfg, "Coredump", "Storage") or "external").lower()
        size_max = (ini.get(cfg, "Coredump", "ProcessSizeMax") or "").strip()
        retained = storage != "none" and size_max not in ("0", "0B")
        ev.append(Evidence.val("systemd-coredump Storage", storage + ("" if ini.get(cfg, "Coredump", "Storage") else " (default)")))
        if retained and "%c" in pattern.split():
            # handed the crashing program's own limit (Fedora, Arch): under a page, it stores nothing (Ubuntu and Mint
            # hand it a fixed one instead)
            limit, said = user_core_limit(host)
            if limit is not None:
                ev.append(Evidence.val("Core file size limit of the programs you run", said))
                retained = limit >= PAGE
        dumps = tally(host.sys_path("/var/lib/systemd/coredump"))
        existing = dumps.files
        ev.append(Evidence.count("Dumps in /var/lib/systemd/coredump", dumps.files))
    elif "apport" in pattern:
        text = host.read_sys("/etc/default/apport") or ""
        m = re.search(r"^enabled\s*=\s*(\d)", text, re.M)
        retained = not m or m.group(1) == "1"
        ev.append(Evidence.val("apport", "enabled" if retained else "disabled"))
        crashes = tally(host.sys_path("/var/crash"), pattern=re.compile(r"\.crash$"))
        existing = crashes.files
        ev.append(Evidence.count("Crash reports in /var/crash", crashes.files))
    elif NOTHING_KEPT.match(pattern):
        ev.append(Evidence.val("Crash handler", "keeps nothing"))
    elif pattern.startswith("|"):
        retained = None                                  # a handler the app doesn't know: can't tell what it keeps
        ev.append(Evidence.val("Crash handler", "a program the app doesn't know"))
    elif pattern:
        limit, said = user_core_limit(host)
        retained = None if limit is None else limit >= PAGE
        ev.append(Evidence.val("Core file size limit of the programs you run", said or "unknown"))
    return retained, existing, ev


@register
class CoredumpsRetained(Check):
    id = "enc.coredumps_retained"

    def detect(self, scan: Scan) -> Outcome:
        retained, existing, ev = crash_dumps(scan.host)
        if retained and existing:
            return failed(f"Crash dumps are kept on disk: {existing} {'is' if existing == 1 else 'are'} there now.", *ev)
        if existing:
            return failed("Old crash dumps are still on disk.", *ev)
        if retained:
            return warned("A program that crashes would leave a copy of its memory on disk (none is there now).", *ev)
        if retained is None:
            return unknown("Couldn't tell whether crash dumps would be kept: "
                           + ("crashes are handed to a program the app doesn't know." if ev[-1].label == "Crash handler"
                              else "the core size limit of the programs you run couldn't be read."), *ev)
        return passed("Crash dumps aren't kept.", *ev)


# ------------------------------------------------------------------ snapshots

HOME_OUT = Note("risk", "Keep your home folder out of them",
                "Your home folder isn't in these snapshots. Keep it that way: it is where most of your personal data is "
                "(documents, photos, browser profiles, chats), and a file you delete there would stay in every snapshot "
                "taken before it. Don't tick \"Include @home\" in Timeshift, or add a snapper or btrbk config for it.")


@register
class SnapshotsRetainDeleted(Check):
    id = "enc.snapshots_retain_deleted"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, found, long_kept = [], [], []
        kept_on: list[str | None] = []                  # the filesystems the long-kept snapshots are of (and on)
        configs, partial = snapper_configs(scan)
        for name, cfg in configs:
            found.append(f"Snapper ({name})")
            if not snapper_short(cfg):
                long_kept.append(f"Snapper ({name})")
                kept_on.append(cfg.get("SUBVOLUME"))
            ev.append(Evidence.val(f"Snapper config {name}", f"{cfg.get('SUBVOLUME', '?')}: {snapper_keeps(cfg)}"))
        ts = timeshift_settings(scan)
        if not timeshift_btrfs(ts):
            ts = None
        if ts is not None:
            home = str(ts.get("include_btrfs_home_for_backup")).lower() == "true"
            found.append("Timeshift (btrfs)")
            if not timeshift_short(ts):
                long_kept.append("Timeshift (btrfs)")
                kept_on += ["/"] + ([str(host.home)] if home else [])
            ev.append(Evidence.val("Timeshift btrfs snapshots", ("include /home" if home else "system only")
                                   + f": {timeshift_keeps(ts)}"))
        bt = btrbk_retention(host)
        if bt is not None:
            found.append("btrbk")
            if not bt[0]:
                long_kept.append("btrbk")
                kept_on += btrbk_volumes(host) or [None]
            ev.append(Evidence.val("btrbk snapshots", bt[1]))
        r = host.run("zfs", "list", "-H", "-t", "snapshot", "-o", "name")
        zfs = r.stdout if r.ok and r.stdout.strip() else ""
        if zfs:
            n = len(zfs.strip().splitlines())
            found.append("ZFS")
            long_kept.append("ZFS")                      # its retention is some other tool's: can't tell
            kept_on += zfs_snapshot_mounts(host, zfs) or [None]
            ev.append(Evidence.count("ZFS snapshots", n))
        if not found:
            return passed("No filesystem snapshots are configured.")
        home_in, home_unknown = home_snapshotted(scan, configs, ts, zfs)
        ev.append(Evidence.val("Home folder in them", ", ".join(home_in) if home_in
                               else "couldn't be told" if home_unknown else "no"))
        notes = [] if home_in or home_unknown else [HOME_OUT]
        if home_unknown and not home_in:
            notes.append(Note("limitation", "Whether your home folder is in them couldn't be told",
                              "The mount table didn't say which subvolume or dataset holds it. If it is in them, every "
                              "personal file you delete stays in each snapshot taken before."))
        if home_in:
            encrypted = None if None in kept_on else on_encrypted_disk(scan, *kept_on, str(host.home))
            how_long = "for a long time" if long_kept else "until they expire"
            return failed(f"Filesystem snapshots include your home folder: every personal file you delete stays in them "
                          f"{how_long} ({', '.join(home_in)}).", *ev, partial=partial, notes=notes,
                          findings={ON_ENCRYPTED_DISK: encrypted})
        if long_kept:
            encrypted = None if None in kept_on else on_encrypted_disk(scan, *kept_on)
            out = "" if home_unknown else " Your home folder isn't in them."
            return failed(f"Filesystem snapshots keep deleted files for a long time: {', '.join(long_kept)}.{out}", *ev,
                          partial=partial, notes=notes, findings={ON_ENCRYPTED_DISK: encrypted})
        return passed(f"Snapshots are kept for a short time only: {', '.join(found)}.", *ev, partial=partial,
                      notes=[Note("info", "Deleted files still linger for a few days",
                                  "A file you delete stays in the snapshots taken before, until they are cleaned "
                                  "up: with these limits, for days rather than months."), *notes])


def _mount_of(ms: list, path: str):
    return max((m for m in ms if path == m.target or path.startswith(m.target.rstrip("/") + "/")),
               key=lambda m: len(m.target), default=None)


def _subvol(m) -> str | None:
    """The btrfs subvolume a mount shows (its subvol= option, which the kernel lists since 4.x), or None."""
    opt = re.search(r"(?:^|,)subvol=([^,]*)", m.options)
    return opt.group(1).replace("\\040", " ") if opt else None


def _btrfs_place(ms: list, path: str) -> tuple[str, str] | None:
    """(the filesystem's device, the path within it from its top level) of a path on btrfs: what a subvolume at that
    path is called whichever mount it is reached through. None when it isn't on btrfs or the mount doesn't say."""
    m = _mount_of(ms, path)
    sv = _subvol(m) if m is not None and m.fstype == "btrfs" else None
    if sv is None:
        return None
    rel = path[len(m.target.rstrip("/")):].lstrip("/")
    return m.source, posixpath.normpath(posixpath.join(sv, rel) if rel else sv)


def home_subvolume(host: Host, ms: list) -> tuple[str, str] | None | bool:
    """The btrfs subvolume holding the home folder, as _btrfs_place names it; False when the home folder isn't on
    btrfs, None when that can't be told. A subvolume nested inside another (the home folder made one, or /home inside
    @ without a mount of its own) isn't in the outer one's snapshots: each subvolume has a device number of its own, so
    its top is the highest folder above the home folder, up to the mount, with the home folder's st_dev."""
    home = str(host.home)
    m = _mount_of(ms, home)
    if m is None:
        return None
    if m.fstype != "btrfs":
        return False
    top = Path(home)
    try:
        dev = top.stat().st_dev
        while str(top) != m.target and top.parent != top and top.parent.stat().st_dev == dev:
            top = top.parent
    except OSError:
        top = Path(m.target)
    return _btrfs_place(ms, str(top))


def timeshift_btrfs(ts: dict | None) -> bool:
    return ts is not None and str(ts.get("btrfs_mode")).lower() == "true" and bool(ts.get("backup_device_uuid"))


def home_snapshotted(scan: Scan, configs: list[tuple[str, dict[str, str]]], ts: dict | None,
                     zfs: str) -> tuple[list[str], bool]:
    """Which of the snapshot tools set up here include the home folder (["Snapper (home)", "Timeshift"...]), and
    whether that couldn't be told for one of them. `ts` is Timeshift's settings when it takes btrfs snapshots; `zfs`
    the names `zfs list -t snapshot` gave."""
    host = scan.host
    ms = mounts(host)
    home = str(host.home).rstrip("/")
    sv = home_subvolume(host, ms)
    hits, unknown = [], False

    def covers(path: str) -> bool | None:
        if (path.rstrip("/") + "/").startswith(home + "/"):
            return True                                  # a subvolume inside the home folder: its files
        if sv is False:
            return False
        place = _btrfs_place(ms, path)
        if sv is None or place is None:
            return None
        return place[0] == sv[0] and fnmatch.fnmatchcase(sv[1], place[1])

    def tally(name: str, paths: list[str]) -> None:
        nonlocal unknown
        answers = [covers(p) for p in paths]
        if True in answers:
            hits.append(name)
        elif None in answers:
            unknown = True

    for name, cfg in configs:
        if cfg.get("SUBVOLUME"):
            tally(f"Snapper ({name})", [cfg["SUBVOLUME"]])
    if ts is not None:
        if str(ts.get("include_btrfs_home_for_backup")).lower() == "true":
            hits.append("Timeshift")                     # its @home
        else:
            tally("Timeshift", ["/"])                    # its @: the home folder too, without an @home of its own
    volume, subs = None, []
    for words in _btrbk_conf(host) or []:
        if len(words) >= 2 and words[0] == "volume":
            volume = words[1]
        elif len(words) >= 2 and words[0] == "subvolume" and volume:
            subs.append(posixpath.join(volume, words[1]))
    if subs:
        tally("btrbk", subs)
    if zfs:
        datasets = {ln.split("@", 1)[0] for ln in zfs.split() if "@" in ln}
        r = host.run("zfs", "list", "-H", "-t", "filesystem", "-o", "name,mountpoint")
        where = dict(ln.split("\t", 1) for ln in r.stdout.splitlines() if "\t" in ln) if r.ok else {}
        m = _mount_of(ms, home)
        if (m is None or m.fstype == "zfs") and not where:
            unknown = True
        elif m is None or m.fstype == "zfs":
            # the dataset the home folder is in (mounted at or above it), and any mounted inside it
            above = max((d for d, mp in where.items() if mp.startswith("/")
                         and (home + "/").startswith(mp.rstrip("/") + "/")), key=lambda d: len(where[d]), default=None)
            mine = [d for d in sorted(datasets) if d == above or (where.get(d, "").rstrip("/") + "/").startswith(home + "/")]
            if mine:
                hits.append(f"ZFS ({', '.join(mine)})")
    return hits, unknown


def _btrbk_conf(host) -> list[list[str]] | None:
    """/etc/btrbk/btrbk.conf (or /etc/btrbk.conf) as each line's words, comments left out; None when btrbk isn't set up."""
    for path in ("/etc/btrbk/btrbk.conf", "/etc/btrbk.conf"):
        try:
            text = host.read_sys(path)
        except Unreadable:
            text = None
        if text:
            return [ln.split("#", 1)[0].split() for ln in text.splitlines()]
    return None


def btrbk_volumes(host) -> list[str]:
    """The btrfs volumes btrbk snapshots (its `volume` lines): the snapshots are kept inside them."""
    return [w[1] for w in _btrbk_conf(host) or [] if len(w) >= 2 and w[0] == "volume"]


def zfs_snapshot_mounts(host, snapshots: str) -> list[str]:
    """Where the datasets with snapshots (`zfs list -t snapshot -o name` lines) are mounted: their snapshots are
    kept in the same pool. Empty when that can't be told for every one of them."""
    datasets = {ln.split("@", 1)[0] for ln in snapshots.split() if "@" in ln}
    r = host.run("zfs", "list", "-H", "-t", "filesystem", "-o", "name,mountpoint")
    where = dict(ln.split("\t", 1) for ln in r.stdout.splitlines() if "\t" in ln) if r.ok else {}
    out = [where.get(d, "") for d in sorted(datasets)]
    return out if out and all(m.startswith("/") for m in out) else []


def btrbk_retention(host) -> tuple[bool, str] | None:
    """(short, in words) for btrbk's snapshots, from /etc/btrbk/btrbk.conf (or /etc/btrbk.conf): snapshot_preserve_min
    is "all" unless set (keep every snapshot for ever, btrbk.conf(5), btrbk 0.32), and a retention in weeks, months or
    years is long. None when btrbk isn't set up."""
    lines = _btrbk_conf(host)
    if lines is None:
        return None
    mins = [" ".join(w[1:]) for w in lines if w and w[0] == "snapshot_preserve_min"]
    keeps = [" ".join(w[1:]) for w in lines if w and w[0] == "snapshot_preserve"]
    long_unit = re.compile(r"\d+[wmy]\b|\*[wmy]")
    long = not mins or any(m == "all" or long_unit.search(m) for m in mins) or any(long_unit.search(k) for k in keeps)
    words = f"snapshot_preserve_min {', '.join(mins) or 'all (its default: every snapshot, for ever)'}"
    if keeps:
        words += f"; snapshot_preserve {', '.join(keeps)}"
    return not long, words


SNAPPER_TIMELINE = ("HOURLY", "DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "YEARLY")
# snapper's own defaults for keys a config leaves out (snapper-configs(5))
SNAPPER_DEFAULTS = {"NUMBER_LIMIT": "50", "NUMBER_LIMIT_IMPORTANT": "10", "TIMELINE_CREATE": "yes",
                    "TIMELINE_LIMIT_HOURLY": "10", "TIMELINE_LIMIT_DAILY": "10", "TIMELINE_LIMIT_WEEKLY": "0",
                    "TIMELINE_LIMIT_MONTHLY": "10", "TIMELINE_LIMIT_QUARTERLY": "0", "TIMELINE_LIMIT_YEARLY": "10"}


def snapper_configs(scan: Scan) -> tuple[list[tuple[str, dict[str, str]]], bool]:
    """Snapper's configs as {KEY: value}, and whether any couldn't be read."""
    out, partial = [], False
    for f in children(scan.host.sys_path("/etc/snapper/configs")):
        try:
            text = scan.host.read_sys(f"/etc/snapper/configs/{f.name}") or ""
        except Unreadable:
            partial, text = True, ""
        out.append((f.name, {m.group(1): m.group(2) for m in re.finditer(r'^\s*([A-Z_]+)\s*=\s*"?([^"\n]*)"?', text, re.M)}))
    return out, partial


def snapper_keeps(cfg: dict[str, str]) -> str:
    """What a snapper config keeps, in words ("up to 50 update snapshots, timeline: 10 hourly, ...")."""
    cfg = {**SNAPPER_DEFAULTS, **cfg}
    parts = [f"up to {cfg['NUMBER_LIMIT']} numbered (update) snapshots"]
    if cfg["TIMELINE_CREATE"].lower() == "yes":
        kept = [f"{cfg[f'TIMELINE_LIMIT_{k}']} {k.lower()}" for k in SNAPPER_TIMELINE
                if cfg[f"TIMELINE_LIMIT_{k}"] not in ("0", "")]
        parts.append("timeline: " + (", ".join(kept) or "none kept"))
    else:
        parts.append("no timeline")
    return "; ".join(parts)


SNAPPER_SHORT_MAX = 20      # update snapshots kept at most for a short retention: the guide's input goes no higher


def snapper_short(cfg: dict[str, str]) -> bool:
    """Short retention: no weekly or longer timeline snapshots, and at most SNAPPER_SHORT_MAX update snapshots."""
    cfg = {**SNAPPER_DEFAULTS, **cfg}

    def top(v: str) -> int:
        return int(v.split("-")[-1]) if re.fullmatch(r"\d+(-\d+)?", v) else 999
    long_timeline = cfg["TIMELINE_CREATE"].lower() == "yes" and any(
        top(cfg[f"TIMELINE_LIMIT_{k}"]) for k in ("WEEKLY", "MONTHLY", "QUARTERLY", "YEARLY"))
    return (not long_timeline and top(cfg["NUMBER_LIMIT"]) <= SNAPPER_SHORT_MAX
            and top(cfg["NUMBER_LIMIT_IMPORTANT"]) <= SNAPPER_SHORT_MAX)


def timeshift_short(ts: dict) -> bool:
    on = lambda k: str(ts.get(f"schedule_{k}")).lower() == "true"    # noqa: E731
    return not on("weekly") and not on("monthly")


def timeshift_settings(scan: Scan) -> dict | None:
    try:
        ts = json.loads(scan.host.read_sys("/etc/timeshift/timeshift.json") or "null")
    except (ValueError, Unreadable):
        return None
    return ts if isinstance(ts, dict) else None


def timeshift_keeps(ts: dict) -> str:
    kinds = [(k, ts.get(f"count_{k}", "?")) for k in ("boot", "hourly", "daily", "weekly", "monthly")
             if str(ts.get(f"schedule_{k}")).lower() == "true"]
    return ", ".join(f"{n} {k}" for k, n in kinds) or "no schedule"


# ------------------------------------------------------------------ journal

# systemd.time(7) time span units, in seconds
_SPAN_UNITS = {"us": 1e-6, "usec": 1e-6, "ms": 1e-3, "msec": 1e-3, "s": 1, "sec": 1, "second": 1, "seconds": 1,
               "m": 60, "min": 60, "minute": 60, "minutes": 60, "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
               "d": 86400, "day": 86400, "days": 86400, "w": 604800, "week": 604800, "weeks": 604800,
               "M": 2629800, "month": 2629800, "months": 2629800, "y": 31557600, "year": 31557600, "years": 31557600}


def timespan(text: str) -> float | None:
    """A systemd time span ("2week", "1month 2d", "3600") in seconds, or None if it isn't one."""
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)", text.strip())
    if not parts or re.sub(r"[0-9.\sA-Za-z]", "", text):
        return None
    total = 0.0
    for number, unit in parts:
        if unit and unit not in _SPAN_UNITS and unit.lower() not in _SPAN_UNITS:
            return None
        total += float(number) * (_SPAN_UNITS.get(unit) or _SPAN_UNITS.get(unit.lower(), 1) if unit else 1)
    return total


def _days(seconds: float) -> str:
    d = seconds / 86400
    return f"{d / 365.25:.0f} year{'s' if d >= 1.5 * 365.25 else ''}" if d >= 365 else \
        f"{d / 30.44:.0f} month{'s' if d >= 1.5 * 30.44 else ''}" if d >= 60 else f"{d:.0f} day{'s' if round(d) != 1 else ''}"


JOURNAL_LIMIT = 31 * 86400          # kept longer than about a month: still a finding
SYSLOG_UNITS = (("rsyslog.service", "rsyslog"), ("syslog-ng.service", "syslog-ng"), ("syslog-ng@default.service", "syslog-ng"))


def syslog_daemon(host: Host) -> tuple[str | None, str | None, Tally]:
    """(the syslog daemon running, its unit, the text logs in /var/log it and logrotate keep: SYSLOG_FILES)."""
    from ..helper import SYSLOG_FILES
    logs = tally(host.sys_path("/var/log"), pattern=SYSLOG_FILES, max_depth=0)
    for unit, name in SYSLOG_UNITS:
        if systemctl_state(host, "is-active", unit) == "active":
            return name, unit, logs
    return None, None, logs


def syslog_names(host: Host) -> list[str]:
    """The text logs a syslog daemon writes on this machine, by name, rotated copies left out: syslog and auth.log on
    Debian and Ubuntu, messages, secure, maillog and cron on Fedora."""
    from ..helper import SYSLOG_FILES, SYSLOG_NAMES
    names = {m.group(1) for p in children(host.sys_path("/var/log")) if (m := SYSLOG_FILES.match(p.name)) and p.is_file()}
    return sorted(names, key=SYSLOG_NAMES.index)


def syslog_listed(names: list[str], most: int = 3) -> str:
    """"syslog, auth.log and kern.log", or the first few "and others"."""
    if not names:
        return "the text logs"
    if len(names) > most:
        return ", ".join(names[:most]) + " and others"
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


_NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine",
                 10: "ten"}


def plain_span(seconds: float) -> str:
    """A systemd time span in words: "two weeks", "one month", "10 days", "12 hours"."""
    for unit, size in (("year", _SPAN_UNITS["y"]), ("month", _SPAN_UNITS["M"]), ("week", _SPAN_UNITS["w"]),
                       ("day", 86400), ("hour", 3600), ("minute", 60)):
        n = seconds / size
        if n >= 1 and abs(n - round(n)) < 1e-6:
            n = round(n)
            return f"{_NUMBER_WORDS.get(n, str(n))} {unit}{'s' if n != 1 else ''}"
    return _days(seconds)


def journal_usage(path: Path, pattern: re.Pattern = re.compile(r"\.journal~?$"),
                  older_than: float | None = None) -> tuple[int, int]:
    """(journal files, bytes they take on the disk) under `path`, links not followed: a journal file's size is mostly holes,
    so its length says more than it holds (352 MB long, 219 MB on the disk, seen on Mint). `older_than` (seconds):
    only the files last written longer ago, which a time limit that long deletes whole (journald deletes a file once
    its newest entry is older than the limit)."""
    files = used = 0
    cutoff = time.time() - older_than if older_than is not None else None
    for d, _, names in os.walk(path, followlinks=False):
        for n in names:
            try:
                st = os.lstat(os.path.join(d, n))
            except OSError:
                continue
            if cutoff is not None and st.st_mtime >= cutoff:
                continue
            if stat.S_ISREG(st.st_mode) and pattern.search(n):
                files += 1
                used += st.st_blocks * 512
    return files, used


def journal_in_memory(host: Host) -> bool:
    """journald keeps the journal in memory only: Storage=volatile or none, or auto without /var/log/journal."""
    cfg = _layered(host, "journald.conf", "journald.conf.d")
    storage = (ini.get(cfg, "Journal", "Storage") or "auto").lower()
    return storage in ("volatile", "none") or (storage == "auto" and not isdir(host.sys_path("/var/log/journal")))


@register
class JournalPersistent(Check):
    id = "enc.journal_persistent"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        cfg = _layered(scan.host, "journald.conf", "journald.conf.d")
        storage = (ini.get(cfg, "Journal", "Storage") or "auto").lower()
        on_disk = storage == "persistent" or (storage == "auto" and isdir(host.sys_path("/var/log/journal")))
        ev = [Evidence.val("Storage", storage + ("" if ini.get(cfg, "Journal", "Storage") else " (default)"))]
        daemon, unit, logs = syslog_daemon(host)
        notes, syslog_problem = [], None
        if daemon and not logs.files:
            # Arch's syslog-ng.conf ships with every destination commented out: running, it writes nothing
            ev.append(Evidence.val(daemon, "running, but no text logs of its own in /var/log"))
        elif daemon:
            ev.append(Evidence.val(f"{daemon} (writes text logs in /var/log)", f"running, {logs.describe()}"))
            syslog_problem = (f"{daemon} also writes the system's messages to text files in /var/log "
                              f"({syslog_listed(syslog_names(host))}), whatever the journal is set to")
            notes.append(Note("risk", f"{daemon} keeps its own copy",
                              "It reads every message the journal gets and writes them to text files: logins and sudo "
                              "commands, USB devices, Wi-Fi networks. logrotate keeps them for weeks where it runs (four "
                              "weekly copies on Debian and Ubuntu), and nothing deletes them where it doesn't. Limiting "
                              "the journal doesn't touch them."))
        elif logs.files:
            ev.append(Evidence.val("Text logs a syslog daemon left in /var/log", logs.describe()))
        if not on_disk:
            files, used = journal_usage(host.sys_path("/var/log/journal"))
            old = Tally(files=files, bytes=used)
            if old.files:
                ev.append(Evidence.val("Old journal files on disk", old.describe()))
            if syslog_problem:
                return failed(f"The journal is kept in memory, but {syslog_problem}.", *ev, notes=notes)
            if old.files:
                return warned("The journal is kept in memory now, but older logs are still on disk in /var/log/journal.",
                              *ev)
            if logs.files:
                return warned("The journal is kept in memory, but text logs a syslog daemon wrote are still in /var/log.",
                              *ev)
            return passed("The system journal is kept in memory only.", *ev)
        retention = (ini.get(cfg, "Journal", "MaxRetentionSec") or "").strip()
        max_use = (ini.get(cfg, "Journal", "SystemMaxUse") or "").strip()
        ev.insert(1, Evidence.val("MaxRetentionSec", retention or "not set"))
        ev.insert(2, Evidence.val("SystemMaxUse", max_use or "default (10% of the filesystem, at most 4 GB)"))
        files, used = journal_usage(host.sys_path("/var/log/journal"))
        if files:
            ev.insert(3, Evidence.val("Journal on disk", Tally(files=files, bytes=used).describe() + " on the disk"))
        span = timespan(retention) if retention else None
        if retention and span is None:
            notes.append(Note("limitation", "MaxRetentionSec couldn't be read", f"\"{retention[:40]}\" isn't a time "
                              "span the app understands, so the journal is taken as kept until its size limit."))
        if span and span <= JOURNAL_LIMIT:
            if syslog_problem:
                return failed(f"The journal is kept for at most {plain_span(span)}, but {syslog_problem}.", *ev,
                              notes=notes)
            return passed(f"The journal is kept on disk for at most {plain_span(span)}.", *ev, notes=notes)
        kept = f"for {_days(span)}" if span else "until it reaches its size limit"
        return failed(f"The system journal is kept on disk {kept}" + (f", and {syslog_problem}." if syslog_problem else "."),
                      *ev, notes=notes)


# ------------------------------------------------------------------ trash

@register
class Trash(Check):
    id = "enc.trash"

    def detect(self, scan: Scan) -> Outcome:
        host, uid = scan.host, scan.host.uid
        dirs = [scan.paths.data_home / "Trash"]
        for m in storage_mounts(host):
            mp = Path(m.target)
            dirs += [mp / f".Trash-{uid}", mp / ".Trash" / str(uid)]
        ev, total = [], 0
        seen = set()
        for d in dirs:
            files = d / "files"
            if not isdir(files) or files.resolve() in seen:
                continue
            seen.add(files.resolve())
            items = len(children(files))
            if items:
                t = tally(files)
                total += items
                ev.append(Evidence.val(host.display(d), f"{items} item{'s' if items > 1 else ''}, {human_size(t.bytes)}"))
        notes = []
        if scan.context.desktop.is_gnome and scan.gnome.gsettings("org.gnome.desktop.privacy", "remove-old-trash-files") is False:
            notes.append(Note("info", "GNOME can empty old trash for you",
                              "Settings → Privacy → File History & Trash → Automatically Delete Trash Content."))
        if total:
            return failed(f"{total} item{'s are' if total > 1 else ' is'} in the trash.", *ev, notes=notes)
        return passed("The trash is empty.", notes=notes)


# ------------------------------------------------------------------ boot

# EFI_GLOBAL_VARIABLE, the UEFI specification's vendor GUID of SecureBoot, SetupMode, BootOrder... (seen on a P330:
# SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c; a wrong one made every UEFI machine "not supported")
EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_SECURE_BOOT = f"/sys/firmware/efi/efivars/SecureBoot-{EFI_GLOBAL}"
EFI_SECURE_BOOT_OLD = f"/sys/firmware/efi/vars/SecureBoot-{EFI_GLOBAL}/data"   # old sysfs interface


NEEDS_ADMIN = "needs administrator access"


def secure_boot(scan: Scan) -> tuple[bool | None, str]:
    """Whether Secure Boot is on, and where that was read. The firmware's SecureBoot variable
    (usually readable by everyone); on UEFI firmware without one, Secure Boot isn't supported,
    so it is off. Then mokutil, the kernel's own boot message, and (when the variable is there
    but only root may read it) the helper. None with NEEDS_ADMIN when only root could tell."""
    host = scan.host
    if not isdir(host.sys_path("/sys/firmware/efi")):
        return False, "not available with legacy BIOS boot"
    unreadable = False
    for path, offset in ((EFI_SECURE_BOOT, 4), (EFI_SECURE_BOOT_OLD, 0)):   # efivarfs: 4 bytes of attributes first
        try:
            data = host.read_head(host.sys_path(path), 8)
        except Unreadable:
            unreadable, data = True, None
        if data and len(data) > offset:
            return data[offset] == 1, "the firmware's SecureBoot setting"
    if not unreadable and children(host.sys_path("/sys/firmware/efi/efivars")):
        # the firmware's settings are visible, and it has no SecureBoot one: VMs and older PCs
        return False, "the firmware doesn't support Secure Boot"
    r = host.run("mokutil", "--sb-state")
    said = (r.stdout + r.stderr).lower()
    if "secureboot enabled" in said or "secureboot disabled" in said:
        return "secureboot enabled" in said, "mokutil"
    if "doesn't support secure boot" in said or ("not supported" in said and "efi variables" not in said):
        return False, "the firmware doesn't support Secure Boot"
    from .kernel import _kernel_log
    m = re.search(r"secureboot: Secure boot (enabled|disabled)", _kernel_log(scan) or "", re.I)
    if m:
        return m.group(1).lower() == "enabled", "the kernel's boot messages"
    if unreadable:
        # there, but only root may read it: the helper can, with administrator access
        try:
            text = host.read_sys(EFI_SECURE_BOOT)
        except Unreadable:
            return None, NEEDS_ADMIN
        if text and len(text) > 4:
            return text[4] == "\x01", "the firmware's SecureBoot setting"
    return None, ""


@register
class BootNoSecureboot(Check):
    id = "enc.boot_no_secureboot"

    def detect(self, scan: Scan) -> Outcome:
        devices = _devices(scan)
        if devices is None:
            return unknown("Couldn't list block devices (lsblk).")
        places = boot_places(scan, devices)
        notes = _lockdown_notes(scan)
        if places and all(d is not None and d.encrypted for _, d in places):
            if [w for w, _ in places] == ["/boot"]:
                return passed("/boot is on encrypted storage.", Evidence.val("/boot", places[0][1].name), notes=notes)
            return passed("The kernel and initramfs are on encrypted storage.",
                          *(Evidence.val(w, d.name) for w, d in places), notes=notes)
        sb, how = secure_boot(scan)
        ev = [Evidence.val(w, f"{d.name} ({d.fstype}), {'encrypted' if d.encrypted else 'not encrypted'}" if d else
                           "not found") for w, d in places] or [Evidence.val("/boot", "not found")]
        plain = [w for w, d in places if d is None or not d.encrypted]
        where = plain[0] if len(plain) == 1 else " and ".join(plain)
        efi = isdir(scan.host.sys_path("/sys/firmware/efi"))
        ev.append(Evidence.val("Firmware", "UEFI" if efi else "legacy BIOS"))
        if sb is None and how == NEEDS_ADMIN:
            o = needs_root("Reading the firmware's Secure Boot setting", *ev)
            o.notes = notes
            return o
        if sb is None:
            return unknown("Couldn't read the Secure Boot state: the firmware's settings aren't visible here, and "
                           "mokutil and the kernel's boot messages didn't say.", *ev, notes=notes)
        ev.append(Evidence.val("Secure Boot", ("on" if sb else "off") + f" ({how})"))
        if not sb:
            return failed(f"{where} isn't encrypted and Secure Boot is off." if where == "/boot" else
                          f"The kernel and initramfs on {where} aren't encrypted, and Secure Boot is off.", *ev, notes=notes)
        uki = booted_uki(scan)
        ev.append(Evidence.val("Booted a unified kernel image (UKI)", "yes" if uki else "no"))
        if uki:
            return passed(f"{where} isn't encrypted, but Secure Boot is on and checks the whole boot image (a UKI).",
                          *ev, notes=notes)
        return warned(f"Secure Boot is on, but the initramfs on the unencrypted {where} isn't checked by it.", *ev,
                      notes=notes + [Note("risk", "What Secure Boot checks here, and what it doesn't",
                                          "The firmware checks the bootloader, and the bootloader the kernel. The "
                                          "initramfs, which asks for the disk passphrase, and GRUB's configuration "
                                          "aren't signed, so a changed one still runs. A unified kernel image (UKI) "
                                          "puts the kernel and initramfs in one signed file.")])


ESP_MOUNTS = ("/efi", "/boot/efi", "/boot")                    # where an EFI system partition (or XBOOTLDR) is mounted
KERNEL_FILES = re.compile(r"^(vmlinuz|vmlinux|bzImage|initrd|initramfs)")


def _boot_files_on(scan: Scan, mp: str) -> bool | None:
    """Whether kernels or initramfs images are stored on the filesystem mounted at `mp`: vmlinuz-* or initrd* at its
    top (GRUB, Limine), unified kernel images in EFI/Linux, or what systemd-boot's entries (loader/entries/*.conf, their
    linux and initrd lines, paths from the partition's top) name. None when it can't be listed (an EFI partition is
    often 0700, or mounted with umask=0077)."""
    host, root = scan.host, scan.host.sys_path(mp)
    try:
        names = [p.name for p in root.iterdir()]
    except PermissionError:
        return None
    except OSError:
        return False
    if any(KERNEL_FILES.match(n) for n in names):
        return True
    try:
        if any(p.suffix.lower() == ".efi" for p in (root / "EFI" / "Linux").iterdir()):
            return True
    except PermissionError:
        return None
    except OSError:
        pass
    for entry in children(root / "loader" / "entries"):
        for m in re.finditer(r"^\s*(?:linux|initrd|efi)\s+(\S+)", read_text(host, entry) or "", re.M):
            if (root / m.group(1).lstrip("/")).exists():
                return True
    return False


def boot_places(scan: Scan, devices: list[blockdev.Device]) -> list[tuple[str, blockdev.Device | None]]:
    """Where the kernels and their initramfs are stored, with the device each is on: /boot (its own partition, or the
    root filesystem's folder) when it holds them, and an EFI partition mounted at /efi, /boot/efi or /boot that holds
    them (systemd-boot copies them there, and unified kernel images live in its EFI/Linux). A booted unified kernel
    image came from the EFI partition, even where that can't be listed. Without any of that, the device holding /boot,
    as before: the root filesystem's when /boot is a folder of it."""
    places: list[tuple[str, blockdev.Device | None]] = []
    mounted = {mp: d for mp, d in blockdev.mounted(devices)}
    unlisted = []
    for mp in ESP_MOUNTS:
        d = mounted.get(mp)
        if d is None or mp == "/boot" and (d.fstype or "").lower() != "vfat":
            continue
        found = _boot_files_on(scan, mp)
        if found:
            places.append((mp, d))
        elif found is None:
            unlisted.append((mp, d))
    if not any(mp == "/boot" for mp, _ in places) and _boot_files_on(scan, "/boot"):
        places.insert(0, ("/boot", blockdev.holding(devices, "/boot")))
    if booted_uki(scan) and unlisted and not any(d is not None and not d.encrypted for _, d in places):
        places.append(unlisted[0])                      # the image this boot started from was on it
    return places or [("/boot", blockdev.holding(devices, "/boot"))]


SYSTEMD_VENDOR_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"


def booted_uki(scan: Scan) -> bool:
    """This boot came from a unified kernel image: systemd-stub, the part of a UKI that starts the kernel,
    leaves the StubInfo EFI variable. Signed as a whole, a UKI brings the initramfs under Secure Boot."""
    return any(p.name == f"StubInfo-{SYSTEMD_VENDOR_GUID}" for p in children(scan.host.sys_path("/sys/firmware/efi/efivars")))


def _lockdown_notes(scan: Scan) -> list[Note]:
    """Kernel lockdown in confidentiality mode, when it is on. Off (and integrity mode, which
    comes with Secure Boot on many distributions) is the norm and needs no word: it would only
    matter against malware that already has root, which can read your files anyway."""
    text = read_text(scan.host, scan.host.sys_path("/sys/kernel/security/lockdown"))
    if "[confidentiality]" not in (text or ""):
        return []
    return [Note("info", "Kernel lockdown is on", "Even an administrator can't read the computer's memory, so the "
                 "disk's unlock key can't be lifted out of it while the computer runs.")]


@register
class TmpOnDisk(Check):
    id = "enc.tmp_on_disk"

    def stored_at(self, scan: Scan) -> list[str]:
        return ["/tmp"]

    def detect(self, scan: Scan) -> Outcome:
        tmp = next((m for m in reversed(mounts(scan.host)) if m.target == "/tmp"), None)
        if tmp is not None and tmp.fstype == "tmpfs":
            return passed("/tmp is in memory (tmpfs).", Evidence.val("/tmp", "tmpfs"))
        where = f"{tmp.fstype} ({tmp.source})" if tmp else "the root filesystem"
        if systemctl_state(scan.host, "is-enabled", "tmp.mount") == "enabled":
            return warned(f"/tmp is on disk ({where}) until the next boot: tmp.mount is enabled.",
                          Evidence.val("/tmp", where), Evidence.val("tmp.mount", "enabled, from the next boot"))
        return failed(f"/tmp is on disk: {where}.", Evidence.val("/tmp", where))


@register
class TrimThroughLuks(Check):
    id = "enc.trim_through_luks"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        devices = _devices(scan)
        if devices is None:
            return unknown("Couldn't list block devices (lsblk).")
        crypt = {d.name for d in devices if d.type == "crypt"}
        if not crypt:
            return absent("No encrypted volumes are open.")
        ev, on = [], []
        for dm in children(host.sys_path("/sys/block")):
            if not dm.name.startswith("dm-"):
                continue
            name = (read_text(host, dm / "dm" / "name") or "").strip()
            if name in crypt:
                maxb = (read_text(host, dm / "queue" / "discard_max_bytes") or "0").strip()
                passes = maxb.isdigit() and int(maxb) > 0
                ev.append(Evidence.val(name, "TRIM passed through" if passes else "no TRIM"))
                if passes:
                    on.append(name)
        if on:
            return passed(f"TRIM is passed through {', '.join(on)}, which is the usual, acceptable trade-off.", *ev,
                          notes=[Note("info", "What TRIM through LUKS reveals, and what it protects",
                                      "Someone reading the raw disk can see which blocks are in use, and so roughly "
                                      "how full the volume is and which filesystem it holds; not what the blocks hold. "
                                      "In return, the SSD stays fast and wears less, and deleted files are cleared "
                                      "from it: most SSDs read trimmed blocks back as zeros, so someone using this "
                                      "machine while it is unlocked can't simply undelete them (not guaranteed: some "
                                      "drives return old data, and the flash itself may keep it until reused). Leaving "
                                      "it on is usually best. To hide even the usage pattern, turn it off: remove "
                                      "the discard option from /etc/crypttab and, on LUKS2, run sudo cryptsetup "
                                      "--persistent refresh with the volume's name, which clears the setting kept in "
                                      "its header.", ("enc.deleted_data_recoverable",))])
        return passed("TRIM isn't passed through encrypted volumes.", *ev,
                      notes=[Note("info", "Without TRIM, deleted files stay on the SSD",
                                  "Nothing about disk usage shows through the encryption, but the blocks of deleted "
                                  "files keep their contents until they are reused: while the volume is unlocked, "
                                  "recovery tools can bring them back. TRIM also keeps the SSD fast; most installers "
                                  "turn it on, and the guide of “Deleted data isn't trimmed from the SSD” does it here.",
                                  ("enc.deleted_data_recoverable", "enc.trim_off"))])


# ------------------------------------------------------------------ TRIM: does it reach the drive, and run?

def trim_timer(host) -> str:
    """fstrim.timer: "enabled", "disabled" (or masked, missing), or "" when systemctl can't say."""
    state = systemctl_state(host, "is-enabled", "fstrim.timer")
    return "" if not state else "enabled" if state == "enabled" else "disabled"


@register
class TrimOff(Check):
    id = "enc.trim_off"
    # what the guide can turn on, from the last detect: "luks" (TRIM stops at LUKS), "raid" (RAID 4/5/6),
    # "never_runs" (no discard option and the fstrim timer off). Not findings: no severity depends on them.
    blocked: frozenset[str] = frozenset()

    def detect(self, scan: Scan) -> Outcome:
        from ..storage import stacks, stop_reason
        host = scan.host
        self.blocked = frozenset()
        if scan.context["virtualization"] == "vm":
            return absent("Inside a virtual machine, TRIM reaches a virtual disk, not a drive: what happens to deleted "
                          "data depends on how the host stores it.")
        ev, stopped, untrimmed = [], [], []
        timer = None
        for st in stacks(host):
            if st.hard_disk:
                ev.append(Evidence.val(st.mount, "hard disk (no TRIM)"))
                continue
            stop = st.stop
            if stop is not None:
                stopped.append((st, stop))
                ev.append(Evidence.val(st.mount, f"TRIM stops at {stop.label or stop.name}"))
                continue
            if st.continuous:
                ev.append(Evidence.val(st.mount, "trimmed as files are deleted (discard)"))
                continue
            timer = trim_timer(host) if timer is None else timer
            ev.append(Evidence.val(st.mount, {"enabled": "trimmed weekly (fstrim.timer)", "disabled": "never trimmed",
                                              "": "fstrim timer unknown"}[timer]))
            if timer != "enabled":
                untrimmed.append(st)
        if not ev:
            return unknown("Couldn't tell where / and the home folder are stored.")
        if not stopped and not untrimmed and all("hard disk" in e.value for e in ev):
            return absent("Only hard disks here: they have no TRIM.", *ev)
        never_runs = bool(untrimmed) and timer == "disabled"
        # every layer that takes no TRIM, deepest first, counts: a logical volume over LUKS without discards says 0
        # too, and was all the guide saw ("The guide doesn't cover this machine")
        layers = [x for st, _ in stopped for x in reversed(st.stops)]
        self.blocked = frozenset(k for k, on in (
            ("luks", any(x.kind == "crypt" for x in layers)),
            ("raid", any(x.kind == "md" and x.label in ("raid4", "raid5", "raid6") for x in layers)),
            ("refresh", any(x.kind == "lvm" for _, x in stopped)),      # the volume hasn't taken it up yet
            ("never_runs", never_runs)) if on)
        problems = [f"{st.mount}: TRIM doesn't reach the drive ({stop_reason(x, st.drives)})" for st, x in stopped]
        if never_runs:
            problems.append(f"{', '.join(s.mount for s in untrimmed)}: TRIM never runs (no discard mount option, and "
                            "the fstrim timer is off)")
        if problems:
            return failed("; ".join(problems) + ".", *ev)
        if untrimmed:
            return unknown("Couldn't tell whether the fstrim timer runs (systemctl).", *ev)
        return passed("Deleted data is trimmed from the SSD.", *ev)

    def can_fix(self, scan: Scan, outcome: Outcome) -> bool:
        """The guide can do something: allow discards through LUKS (or RAID 4/5/6, with care), or
        turn on the weekly timer. A USB adapter or a drive without TRIM: nothing to do here."""
        return outcome.status is Status.PASS or bool(self.blocked)


# ------------------------------------------------------------------ deleted files on the disk

_DM_TYPES = ("crypt", "lvm", "dm", "mpath", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10")


@dataclass
class Storage:
    """Where a path's files are stored, as far as deleting goes."""
    mount: str | None = None
    fstype: str | None = None
    ssd: bool | None = None                 # None: couldn't tell
    trim: str | None = None                 # "continuous" (discard), "weekly" (fstrim.timer), "no"; None: unknown
    encrypted: bool | None = None


def _sysblock(host, d: blockdev.Device) -> Path | None:
    """/sys/block/<name> of a device-mapper device (found by its mapper name) or a disk."""
    if d.type in _DM_TYPES or d.type.startswith("dm"):
        for dm in children(host.sys_path("/sys/block")):
            if dm.name.startswith("dm-") and (read_text(host, dm / "dm" / "name") or "").strip() == d.name:
                return dm
        return None
    while d.parent is not None:
        d = d.parent
    return host.sys_path(f"/sys/block/{d.name}")


def storage_of(scan: Scan, path: str) -> Storage:
    host = scan.host
    m = max((m for m in mounts(host) if path == m.target or path.startswith(m.target.rstrip("/") + "/")),
            key=lambda m: len(m.target), default=None)
    st = Storage(m.target if m else None, m.fstype if m else None)
    d = blockdev.holding(_devices(scan) or [], path)
    if d is None:
        return st
    st.encrypted = d.encrypted
    disk = d
    while disk.parent is not None:
        disk = disk.parent
    rota = (read_text(host, host.sys_path(f"/sys/block/{disk.name}/queue/rotational")) or "").strip()
    # a virtual disk's flag says nothing about the host's drive
    st.ssd = None if scan.context["virtualization"] == "vm" else {"0": True, "1": False}.get(rota)
    top = _sysblock(host, d)
    maxb = (read_text(host, top / "queue" / "discard_max_bytes") or "").strip() if top is not None else ""
    if maxb == "0":
        st.trim = "no"                                       # the device (or a layer under it) takes no TRIM
    elif m is not None and re.search(r"(^|,)discard(=async|=sync)?(,|$)", m.options):
        st.trim = "continuous"
    elif systemctl_state(host, "is-enabled", "fstrim.timer") == "enabled":
        st.trim = "weekly"
    elif maxb.isdigit():
        st.trim = "no"
    return st


def deleted_data_note(scan: Scan) -> str:
    """What deleting (unlinking, rule 8) does and doesn't do on this machine, for plans that delete."""
    st = storage_of(scan, str(scan.host.home))
    parts = ["Deleted, not wiped: like any file manager, this unlinks the files, and their contents stay on the disk "
             "until the space is reused"]
    if st.ssd and st.trim in ("continuous", "weekly"):
        parts[0] += (" or trimmed (" + ("at once" if st.trim == "continuous" else "by the weekly fstrim timer")
                     + "; most SSDs then read the blocks back as zeros, though that isn't guaranteed)")
    elif st.ssd and st.trim == "no":
        parts[0] += " (TRIM is off here, so the SSD keeps them until it reuses the space)"
    if st.fstype == "btrfs":
        parts[0] += ". btrfs is copy-on-write: snapshots, partly rewritten files and recent copies of its own " \
                    "index can keep older versions"
    if st.encrypted:
        parts.append("Disk encryption keeps what is left unreadable to anyone who takes the disk, not to someone "
                     "using this machine while it is unlocked.")
    elif st.encrypted is False:
        parts.append("Without disk encryption, recovery tools can often bring them back: encryption is what protects "
                     "deleted data (enc.fde_missing).")
    else:
        parts.append("Disk encryption is what keeps deleted data unreadable to someone who has the disk.")
    return ". ".join(p.rstrip(".") for p in parts) + "."


@register
class DeletedDataRecoverable(Check):
    id = "enc.deleted_data_recoverable"

    def detect(self, scan: Scan) -> Outcome:
        if _devices(scan) is None:
            return unknown("Couldn't list block devices (lsblk).")
        seen, ev, btrfs, untrimmed, plain = set(), [], [], [], []
        for where in ("/", str(scan.host.home)):
            st = storage_of(scan, where)
            if st.mount is None or st.mount in seen:
                continue
            seen.add(st.mount)
            kind = "SSD" if st.ssd else "hard disk" if st.ssd is False else \
                "virtual disk" if scan.context["virtualization"] == "vm" else "disk of unknown type"
            trim = {"continuous": "trimmed at once (discard)", "weekly": "trimmed weekly (fstrim.timer)",
                    "no": "not trimmed", None: "trimming unknown"}[st.trim] if st.ssd else ""
            ev.append(Evidence.val(st.mount, ", ".join(x for x in (st.fstype or "?", kind, trim,
                      "encrypted" if st.encrypted else "not encrypted" if st.encrypted is False else "") if x)))
            if st.fstype == "btrfs":
                btrfs.append(st.mount)
            if st.ssd and st.trim == "no":
                untrimmed.append(st.mount)
            if st.encrypted is False:
                plain.append(st.mount)
        if not ev:
            return unknown("Couldn't tell where / and the home folder are stored.")
        notes = [Note("info", "Encryption is what protects deleted data",
                      "Deleting a file unlinks it; its contents stay on the disk until the space is reused. Overwriting "
                      "it first doesn't help on SSDs or copy-on-write filesystems, which write elsewhere. Full-disk "
                      "encryption keeps all of it unreadable to anyone who takes the disk; it doesn't protect against "
                      "someone (or something) using this machine while it is unlocked, who could run recovery tools.",
                      ("enc.fde_missing",))]
        if btrfs:
            notes.append(Note("info", "btrfs keeps older copies of files",
                              "btrfs never overwrites in place. Snapshots keep deleted files whole; when part of a "
                              "file is rewritten, the old part stays as long as the rest of its extent is in use; and "
                              "recent copies of the filesystem's own trees let tools like btrfs restore bring back "
                              "files deleted a little while ago. Trimming clears freed space, inside allocated chunks "
                              "too; deleting snapshots you don't need (enc.snapshots_retain_deleted) and "
                              "defragmenting (btrfs filesystem defragment, which also unshares data held by "
                              "snapshots) release more; a balance moves data but guarantees nothing.",
                              ("enc.snapshots_retain_deleted",)))
        if scan.context["virtualization"] == "vm":
            notes.append(Note("limitation", "Inside a virtual machine",
                              "What happens to deleted data on the real drive depends on the host: whether the virtual "
                              "disk passes TRIM on, and whether the host's own disk is encrypted."))
        if untrimmed:
            notes.append(Note("info", "TRIM: a small leak, a useful clearing",
                              "With TRIM, an SSD clears the blocks of deleted files (most read back as zeros), which "
                              "stops simple undeleting on an unlocked machine; it isn't guaranteed. Through "
                              "encryption it shows which blocks are in use, but not their contents. It also keeps the "
                              "SSD fast, so leaving it on (the fstrim timer) is usually best.", ("enc.trim_through_luks",)))
        what = []
        if plain:
            what.append(f"{', '.join(plain)} {'is' if len(plain) == 1 else 'are'} not encrypted")
        if btrfs:
            what.append("btrfs keeps older copies")
        if untrimmed:
            what.append("freed space on the SSD isn't trimmed")
        if what:
            return warned("Deleted files can be recovered from this disk: " + "; ".join(what) + ".", *ev, notes=notes)
        return passed("Deleted files are unlinked, as everywhere; the disk encryption is what protects them.", *ev,
                      notes=notes)
