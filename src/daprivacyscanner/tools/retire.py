"""Retire a drive (docs/TECHNICAL.md, Tools): erasing a whole drive before it is sold, given away or thrown out.
Commands only, for the user to run: the app erases nothing itself, and shows the commands only once
the user has typed the drive's name.

What works depends on the drive, and the guide says so plainly:

- A hard disk (rotational, and known to be one): one full overwrite works, apart from sectors the
  drive has remapped; ATA Secure Erase reaches those too. Rule 8's exception: overwriting is offered
  for hard disks and nothing else. Drive-managed SMR disks hide a translation layer, so even an
  overwrite may leave old copies: they don't say so, and the guide names the models known to be SMR.
- An SSD or NVMe drive: the firmware's own erase (ATA Secure Erase or Sanitize, NVMe sanitize or
  format) can be used, but never as proof: published tests (Wei et al., FAST 2011, and later ones)
  found drives that left data behind. Crypto-erase is the honest strong option for a drive that was
  encrypted from the start (`cryptsetup erase` destroys the keyslots). Physical destruction for one
  that held secrets and wasn't.
- USB sticks and SD cards: there is no reliable erase.
- A virtual disk: erasing it from inside says nothing about where the host keeps it.

Refused for a drive that holds the running system (/, /boot, /home, swap in use); a drive with
something mounted gets unmounting as its first step. ATA's "frozen" security state, enhanced erase
and Sanitize, and NVMe's sanitize and format capabilities come from the helper's erase_facts
(identify data, read-only) when the user grants administrator access."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from .. import blockdev
from ..guide import Guide, Step
from ..host import Host, Unreadable

SYSTEM_MOUNTS = ("/", "/boot", "/boot/efi", "/efi", "/home", "/usr", "/var", "/sysroot")
VIRTUAL_VENDORS = ("QEMU", "VBOX", "VMware", "Msft", "Xen", "Red Hat")
# Hard disks their makers list as drive-managed SMR (they don't say so themselves). VERIFY against the
# makers' current lists (WD, Seagate and Toshiba published theirs in 2020) before adding to it.
DM_SMR = re.compile(r"WD(20|30|40|60)EFAX|WD(20|40|60)EZAZ|WD(10|20)SPZX|ST(2000|4000|5000|6000|8000)DM00[4-8]|"
                    r"ST(1000|2000)LM0(48|49)|ST(2000|4000|5000)LM0(07|15|24)|HDWD(220|240|260)|DT02ABA", re.I)

KIND_TITLE = {"hdd": "Hard disk", "ssd": "SSD", "nvme": "NVMe SSD", "flash": "USB stick or card reader",
              "card": "SD card", "emmc": "Built-in flash (eMMC)", "usb-disk": "External USB disk",
              "virtual": "Virtual disk", "unknown": "Drive"}


class Refused(Exception):
    pass


@dataclass
class Disk:
    name: str
    model: str = ""
    serial: str = ""
    size: int = 0
    transport: str = ""
    rotational: bool | None = None
    removable: bool = False
    zoned: str = "none"
    kind: str = "unknown"
    system: list[str] = field(default_factory=list)       # what of the running system it holds
    mounted: list[str] = field(default_factory=list)      # other mount points on it
    open_crypt: list[str] = field(default_factory=list)   # LUKS volumes on it that are open
    volume_groups: list[str] = field(default_factory=list)  # LVM volume groups active on it
    luks: list[str] = field(default_factory=list)         # partitions (or the disk) that are LUKS
    plain: list[str] = field(default_factory=list)        # partitions with a filesystem that isn't encrypted
    smr: bool = False                                     # known drive-managed SMR model

    @property
    def path(self) -> str:
        return f"/dev/{self.name}"

    @property
    def controller(self) -> str:
        """NVMe: the controller's device (sanitize works on it), /dev/nvme0 for nvme0n1."""
        return "/dev/" + re.sub(r"n\d+$", "", self.name) if self.kind == "nvme" else self.path

    def to_dict(self) -> dict:
        return {"name": self.name, "path": self.path, "model": self.model, "serial": self.serial, "size": self.size,
                "transport": self.transport, "rotational": self.rotational, "removable": self.removable,
                "zoned": self.zoned, "kind": self.kind, "kind_title": KIND_TITLE[self.kind], "system": self.system,
                "mounted": self.mounted, "open_crypt": self.open_crypt, "volume_groups": self.volume_groups,
                "luks": self.luks, "plain": self.plain, "smr": self.smr, "blocked": blocked(self)}


def blocked(d: Disk) -> str:
    if d.system:
        return (f"This drive holds the running system ({', '.join(d.system)}): it can't be erased while the computer "
                "runs from it. Erase it from another computer, or from a live USB.")
    return ""


def _sys(host: Host, path: str) -> str:
    try:
        return (host.read_sys(path) or "").strip()
    except Unreadable:
        return ""


def _serial(host: Host, name: str) -> str:
    """From udev's database (readable without root), or the NVMe controller's own file."""
    devno = _sys(host, f"/sys/block/{name}/dev")
    if re.fullmatch(r"\d+:\d+", devno):
        m = re.search(r"^E:ID_SERIAL_SHORT=(.+)$", _sys(host, f"/run/udev/data/b{devno}"), re.M)
        if m:
            return m.group(1).strip()
    return _sys(host, f"/sys/block/{name}/device/serial")


def _kind(host: Host, d: Disk, vendor: str) -> str:
    if d.name.startswith(("vd", "xvd")) or d.transport == "virtio" or vendor.startswith(VIRTUAL_VENDORS) \
            or d.model.startswith(("QEMU", "VBOX", "VMware Virtual", "Virtual disk")):
        return "virtual"
    if d.name.startswith("mmcblk"):
        return "card" if _sys(host, f"/sys/block/{d.name}/device/type") == "SD" else "emmc"
    if d.name.startswith("nvme"):
        return "nvme"
    if d.transport == "usb":
        if d.removable:
            return "flash"
        return "usb-disk" if d.rotational is not False else "ssd"
    if d.rotational is True:
        return "hdd"
    if d.rotational is False:
        return "ssd"
    return "unknown"


def _swaps(host: Host) -> list[str]:
    return [ln.split()[0] for ln in _sys(host, "/proc/swaps").splitlines()[1:] if ln.split()]


def btrfs_mounts(host: Host, devices: list[blockdev.Device]) -> dict[str, list[str]]:
    """Device name (as lsblk names it) -> the mount points of the btrfs filesystem it belongs to, for
    every device of a mounted btrfs (/sys/fs/btrfs/<uuid>/devices). lsblk shows a filesystem spread
    over several drives as mounted on one of them only; the others hold it just as much."""
    out: dict[str, list[str]] = {}
    try:
        filesystems = list(host.sys_path("/sys/fs/btrfs").iterdir())
    except OSError:
        return out
    for fs in filesystems:
        try:
            kernel = [x.name for x in (fs / "devices").iterdir()]
        except OSError:
            continue
        names = {(_sys(host, f"/sys/block/{k}/dm/name") or k) if k.startswith("dm-") else k for k in kernel}
        mps = sorted({mp for d in devices if d.name in names for mp in d.mountpoints if mp.startswith("/")})
        if mps:
            for n in names:
                out[n] = mps
    return out


def volume_group(dm_name: str) -> str:
    """The volume group of an LVM device-mapper name ("vg-lv"; a dash in either is doubled)."""
    m = re.match(r"^((?:[^-]|--)+)-(?!-)", dm_name)
    return (m.group(1) if m else dm_name).replace("--", "-")


def _tree(devices: list[blockdev.Device], name: str) -> list[blockdev.Device]:
    top = next((x for x in devices if x.name == name and x.type == "disk"), None)
    return [top, *blockdev.descendants(top)] if top else []


def disks(host: Host) -> list[Disk]:
    """Every whole drive (not loop, RAM, zram or optical devices), with what is on it."""
    try:
        devices = blockdev.read_devices(host)
    except blockdev.LsblkError:
        devices = []
    swaps = {(found.name if (found := blockdev.find(devices, host, s)) else s) for s in _swaps(host)}
    btrfs = btrfs_mounts(host, devices)
    home = str(host.home)
    out = []
    try:
        names = sorted(p.name for p in host.sys_path("/sys/block").iterdir())
    except OSError:
        names = []
    for name in names:
        # not drives: virtual and optical devices, eMMC's boot and RPMB areas (parts of the chip, listed
        # apart), and an NVMe namespace's per-controller paths under native multipath
        if re.match(r"^(loop|ram|zram|dm-|md|sr|fd|nbd)", name) or re.match(r"^mmcblk\d+(boot\d+|rpmb)$", name) \
                or re.match(r"^nvme\d+c\d+n\d+$", name):
            continue
        base = f"/sys/block/{name}"
        sectors = _sys(host, f"{base}/size")
        rota = _sys(host, f"{base}/queue/rotational")
        real = str(host.sys_path(base).resolve())
        vendor = _sys(host, f"{base}/device/vendor")
        d = Disk(name, model=_sys(host, f"{base}/device/model"), serial=_serial(host, name),
                 size=int(sectors) * 512 if sectors.isdigit() else 0,
                 transport="usb" if "/usb" in real else "nvme" if name.startswith("nvme") else
                 "virtio" if name.startswith("vd") else "mmc" if name.startswith("mmcblk") else
                 "sata" if vendor == "ATA" else "scsi",
                 rotational={"0": False, "1": True}.get(rota), removable=_sys(host, f"{base}/removable") == "1",
                 zoned=_sys(host, f"{base}/queue/zoned") or "none")
        d.kind = _kind(host, d, vendor)
        d.smr = d.zoned != "none" or bool(DM_SMR.search(d.model))
        tree = _tree(devices, name)
        for x in tree:
            for mp in set(x.mountpoints) | set(btrfs.get(x.name, []) if x.fstype == "btrfs" else []):
                if mp in SYSTEM_MOUNTS or home == mp or home.startswith(mp.rstrip("/") + "/"):
                    d.system.append(mp)
                elif mp.startswith("/"):
                    d.mounted.append(mp)
            if x.name in swaps:
                d.system.append(f"swap on {x.path}")
            if x.type == "crypt":
                d.open_crypt.append(x.name)
            if x.type == "lvm":
                d.volume_groups.append(volume_group(x.name))
            if x.fstype == "crypto_LUKS":
                d.luks.append(x.path)
            elif x.fstype and x.fstype not in ("swap",) and x.type in ("part", "disk") \
                    and not (x.parent and x.parent.fstype == "crypto_LUKS"):
                d.plain.append(x.path)
        d.system, d.mounted = sorted(set(d.system)), sorted(set(d.mounted))
        d.open_crypt, d.volume_groups = sorted(set(d.open_crypt)), sorted(set(d.volume_groups))
        out.append(d)
    return out


def find(host: Host, name: str) -> Disk:
    d = next((x for x in disks(host) if x.name == name), None)
    if d is None:
        raise Refused("That drive isn't connected now.")
    return d


# ------------------------------------------------------------------ the guide

def _size(n: int) -> str:
    for unit, div in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} bytes"


def guide(host: Host, name: str, typed: str, kind: str | None = None, from_start: bool = False,
          facts: dict | None = None) -> Guide:
    """The steps for this drive, with its exact device in every command. `typed`: what the user typed
    (must be the drive's name). `kind`: the user's answer for an external disk the app can't tell
    ("hdd" or "ssd"). `from_start`: the user says everything on it was encrypted from its first use.
    `facts`: the helper's erase_facts for it, when read."""
    d = find(host, name)
    if blocked(d):
        raise Refused(blocked(d))
    if typed.strip().removeprefix("/dev/") != d.name:
        raise Refused(f"Type the drive's name, {d.name}, to show the commands.")
    kind = kind if d.kind == "usb-disk" and kind in ("hdd", "ssd") else d.kind
    who = " ".join(x for x in (d.model, f"serial {d.serial}" if d.serial else "", _size(d.size)) if x)
    g = Guide("tool.retire", f"Erase {d.path}", advice=True,
              intro=f"Every command below erases {d.path} ({who}). Run them yourself, in a terminal, in order; the "
                    "app erases nothing. Check the model and serial against the label on the drive before you start: "
                    "the name (sdb, nvme1n1) can change when drives are plugged in or the computer restarts.")
    if d.mounted or d.open_crypt or d.volume_groups:
        g.steps.append(Step("Unmount it", f"Parts of it are in use ({', '.join(d.mounted + d.open_crypt)}): unmount "
                            "them first, and close what is open on it, in this order.", commands=_unmount_commands(host, d)))
    if facts and facts.get("ata", {}) and facts["ata"].get("frozen"):
        g.steps.append(Step("Unfreeze it", "The drive's security commands are frozen: most computers freeze them at "
                            "start-up. Suspending and waking the computer usually unfreezes them; then read what the "
                            "drive says again here.", commands=["systemctl suspend"]))
    crypto = _crypto_erase(d, from_start)
    if kind == "virtual":
        g.steps.append(Step("Delete it on the host", "This is a virtual disk: whatever erases it from inside, the "
                            "host may keep copies (snapshots, the image file's old blocks). Delete the disk image on "
                            "the host, and rely on the host's own disk encryption for what was freed."))
        return g
    if kind == "hdd":
        if crypto:
            g.steps.append(crypto)
        g.steps += _hdd_steps(d, facts)
    elif kind in ("ssd", "nvme", "emmc"):
        if crypto:
            g.steps.append(crypto)
        g.steps += _flash_firmware_steps(d, kind, facts)
        g.steps.append(_destroy(d, encrypted=bool(crypto)))
    else:                                       # USB sticks, SD cards, an external disk it can't tell, unknown
        g.steps.append(Step("There is no reliable erase", (
            "USB sticks and memory cards keep spare blocks their controller manages out of sight, and they take no "
            "erase command the computer can check. Deleting or overwriting what you can reach isn't proof." if
            kind in ("flash", "card") else
            "The app can't tell whether this is a hard disk or an SSD (through USB the drive often doesn't say). If "
            "you know it is a hard disk (it spins), say so above for the overwrite. Until then, treat it as flash."
            if d.kind == "usb-disk" else
            "The app can't tell what kind of drive this is: the computer doesn't say whether it is a hard disk or "
            "flash. Treat it as flash: no erase can be checked.")))
        if crypto:
            g.steps.append(crypto)
        g.steps.append(_destroy(d, encrypted=bool(crypto)))
    return g


def _unmount_commands(host: Host, d: Disk) -> list[str]:
    """What is on the drive, closed from the top down: every mounted filesystem (on a partition, the
    whole disk, an encrypted volume or LVM inside it), the mount points a btrfs spread over this and
    another drive is mounted on, then its LVM volume groups, then its open encrypted volumes."""
    try:
        devices = blockdev.read_devices(host)
    except blockdev.LsblkError:
        devices = []
    tree = _tree(devices, d.name)
    cmds = [f"udisksctl unmount -b {x.path}" for x in reversed(tree) if any(m.startswith("/") for m in x.mountpoints)]
    shown = {m for x in tree for m in x.mountpoints}
    cmds += [f"sudo umount {shlex.quote(mp)}" for mp in d.mounted if mp not in shown]
    cmds += [f"sudo vgchange -an {shlex.quote(vg)}" for vg in d.volume_groups]
    cmds += [f"sudo cryptsetup close {shlex.quote(x.name)}" for x in reversed(tree) if x.type == "crypt"]
    return cmds


def _crypto_erase(d: Disk, from_start: bool) -> Step | None:
    if not d.luks:
        return None
    cmds = [f"sudo cryptsetup erase {p}" for p in d.luks] + [f"sudo cryptsetup luksDump {p}" for p in d.luks]
    text = ("Destroy the encryption keys: without them, what is on the drive is unreadable, wherever the drive keeps "
            "it. `cryptsetup erase` asks you to type YES, then removes every keyslot; luksDump afterwards should list "
            "none.")
    effects = ["A header backup (cryptsetup luksHeaderBackup) or a recovery key saved elsewhere would still open it "
               "with the old passphrase: delete those too."]
    if not from_start:
        effects.append("This protects only what was written after the drive was encrypted: if it held the same data "
                       "unencrypted before, copies may remain in places only the drive can see.")
    if d.plain:
        effects.append(f"{', '.join(d.plain)} {'isn' if len(d.plain) == 1 else 'aren'}'t encrypted: this doesn't "
                       "cover them.")
    return Step("Destroy the keys (crypto-erase)" + (" — the strong option here" if from_start and not d.plain else ""),
                text, commands=cmds, side_effects=effects)


def _hdd_steps(d: Disk, facts: dict | None) -> list[Step]:
    steps = []
    ata = (facts or {}).get("ata") or {}
    if d.smr:
        steps.append(Step("A drive-managed SMR disk", (
            "This disk shingles its tracks and moves data through a cache of its own (its model is listed as SMR, or "
            "it says it is zoned), so an overwrite may not reach every old copy. ATA Secure Erase, which the drive "
            "carries out on all of itself, is the better choice; for a disk that held secrets, destroy it.")))
    if ata.get("supported") and not ata.get("frozen") and d.transport != "usb":
        enhanced = ata.get("enhanced")
        mins = ata.get("enhanced_minutes" if enhanced else "erase_minutes")
        verb = "--security-erase-enhanced" if enhanced else "--security-erase"
        steps.append(Step("ATA Secure Erase (reaches remapped sectors too)", (
            "The disk erases itself, including sectors it has set aside after errors, which no overwrite reaches. It "
            "first needs a temporary password (Eins below; any word works), which the erase removes again."
            + (f" The drive estimates {mins} minutes." if mins else "")),
            commands=[f"sudo hdparm --user-master u --security-set-pass Eins {d.path}",
                      f"sudo hdparm --user-master u {verb} Eins {d.path}"],
            side_effects=["Don't interrupt it, or unplug the drive, until it finishes: an interrupted erase can leave the "
                          f"drive locked with that password (sudo hdparm --user-master u --security-disable Eins {d.path} "
                          "unlocks it)."]))
    steps.append(Step("Overwrite it once with zeros", (
        "One full pass is enough on a hard disk: data overwritten on its platters can't be read back. It takes "
        "hours on a large disk (about 2 to 3 hours per TB). It doesn't reach sectors the drive has remapped after "
        "errors; ATA Secure Erase does."),
        commands=[f"sudo dd if=/dev/zero of={d.path} bs=16M oflag=direct status=progress",
                  f"sudo cmp {d.path} /dev/zero"],
        side_effects=["dd ends with \"No space left on device\": that is the end of the disk, as expected.",
                      f"cmp checks the result: \"EOF on {d.path}\" means every byte is zero; \"differ\" means it isn't."]))
    return steps


def _flash_firmware_steps(d: Disk, kind: str, facts: dict | None) -> list[Step]:
    caveat = ("The drive's firmware does this: the app (and you) can't check that it really erased everything. "
              "Published tests found drives whose erase left data behind, so treat it as a clean-up, not proof.")
    if kind == "nvme":
        nv = (facts or {}).get("nvme") or {}
        san = nv.get("sanitize") or {}
        cmds = []
        if san.get("crypto"):
            cmds.append(f"sudo nvme sanitize {d.controller} --sanact=4")
        if san.get("block"):
            cmds.append(f"sudo nvme sanitize {d.controller} --sanact=2")
        if cmds:
            cmds.append(f"sudo nvme sanitize-log {d.controller}")
        fmt = f"sudo nvme format {d.path} --ses={'2' if nv.get('format_crypto') else '1'}"
        return [Step("The drive's own erase (NVMe)", (
            ("Sanitize erases every part of the drive, including blocks it keeps out of sight; sanitize-log shows its "
             "progress. Format with secure erase is the older command." if cmds else
             "Format with secure erase (--ses=2 erases the drive's key where it encrypts, 1 erases user data).")
            + ("" if facts else " Read what the drive says (above) to see which kinds it supports.")),
            commands=cmds + [fmt], side_effects=[caveat, "Needs nvme-cli (the nvme command)."])]
    if kind == "emmc":
        return [Step("The drive's own erase (eMMC)", "blkdiscard's secure mode asks the chip to erase every block.",
                     commands=[f"sudo blkdiscard --secure {d.path}"], side_effects=[caveat])]
    ata = (facts or {}).get("ata") or {}
    san = ata.get("sanitize") or {}
    cmds = []
    if san.get("crypto"):
        cmds.append(f"sudo hdparm --yes-i-know-what-i-am-doing --sanitize-crypto-scramble {d.path}")
    if san.get("block"):
        cmds.append(f"sudo hdparm --yes-i-know-what-i-am-doing --sanitize-block-erase {d.path}")
    if cmds:
        cmds.append(f"sudo hdparm --sanitize-status {d.path}")
    if not facts or ata.get("supported"):
        verb = "--security-erase-enhanced" if ata.get("enhanced") else "--security-erase"
        cmds += [f"sudo hdparm --user-master u --security-set-pass Eins {d.path}",
                 f"sudo hdparm --user-master u {verb} Eins {d.path}"]
    if not cmds:
        return [Step("The drive's own erase (SATA SSD)", (
            "This drive says it has neither Sanitize nor ATA Secure Erase, so there is no erase it can be asked to do. "
            "Use the encryption keys step above if it was encrypted; otherwise see the last step."))]
    effects = [caveat]
    if ata.get("frozen"):
        effects.append("It is frozen now: unfreeze it first (the step above).")
    if d.transport == "usb":
        effects.append("Through a USB adapter these commands often fail, or leave the drive locked: connect it to a "
                       "SATA port inside a computer if you can.")
    return [Step("The drive's own erase (SATA SSD)", (
        "Sanitize (where the drive has it) or ATA Secure Erase asks the drive to erase all of itself, including blocks "
        "it keeps out of sight. Secure Erase first needs a temporary password (Eins; any word works), which it removes."
        + ("" if facts else " Read what the drive says (above) to see which it supports.")),
        commands=cmds, side_effects=effects)]


def _destroy(d: Disk, encrypted: bool) -> Step:
    return Step("If it held secrets", (
        ("If anything on it was ever stored unencrypted and must never be read, destroy the drive: drill through it "
         "or have it shredded. For an SSD or card, the memory chips are what must be broken.") if not encrypted else
        ("Encrypted from the start and its keys destroyed, it can be passed on. If you aren't sure everything on it "
         "was always encrypted, destroy it instead: drill through the memory chips, or have it shredded.")))
