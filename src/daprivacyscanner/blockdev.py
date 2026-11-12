"""Block devices from `lsblk -J`, with what each sits on top of: shared by the fde context key
and the encryption checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .host import Host

COLUMNS = "NAME,TYPE,FSTYPE,MOUNTPOINTS,RM,HOTPLUG,TRAN,LABEL"
# util-linux before 2.37 has only MOUNTPOINT (one per device)
COLUMNS_OLD = "NAME,TYPE,FSTYPE,MOUNTPOINT,RM,HOTPLUG,TRAN,LABEL"
# for the partitions nothing uses (enc.unmounted_unencrypted): sizes in bytes (-b), what kind of partition, which
# filesystem (the devices of one btrfs share its UUID)
COLUMNS_PARTITIONS = COLUMNS + ",SIZE,PARTTYPE,UUID"
# Transports of drives that are plugged in from outside. SATA ports report HOTPLUG when the firmware
# allows hot-swapping, which many desktops and laptops do for their internal drives: not removable.
EXTERNAL_TRANSPORTS = frozenset({"usb", "ieee1394"})
INTERNAL_HOTPLUG = frozenset({"sata", "ata"})
# what installer and boot sticks carry: their drive is for booting, not for files
BOOT_STICK_LABELS = frozenset({"VTOYEFI", "Ventoy"})

# not user data: the boot partitions and the EFI system partition
BOOT_MOUNTS = frozenset({"/boot", "/boot/efi", "/efi"})
# read-only images (snaps, live media) hold no user data
IMAGE_FSTYPES = frozenset({"squashfs", "erofs", "iso9660", "udf"})
# filesystems that can encrypt without dm-crypt (ZFS roots don't show up in lsblk at all).
# VERIFY: how an encrypted bcachefs root appears in lsblk.
NATIVE_ENCRYPTION_FSTYPES = frozenset({"bcachefs", "zfs_member"})
# lsblk calls every device-mapper device whose DM UUID starts with CRYPT- "crypt" (its type is the prefix): dm-verity
# (veritysetup: CRYPT-VERITY-), standalone dm-integrity (CRYPT-INTEGRITY-) and the integrity layer under LUKS2's
# authenticated encryption (CRYPT-SUBDEV-) check what is stored, and encrypt nothing
NOT_ENCRYPTING_DM = ("CRYPT-VERITY-", "CRYPT-INTEGRITY-", "CRYPT-SUBDEV-")
# partitions that hold no one's data, whatever they are mounted as: the EFI system partition (an ESP mounted outside
# /boot/efi and /efi), the extended boot partition, BIOS boot, Microsoft's reserved and recovery partitions, and MBR's ESP
NOT_DATA_PARTTYPES = frozenset({"c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "bc13c2ff-59e6-4262-a352-b275fd6f7172",
                                "21686148-6449-6e6f-744e-656564454649", "e3c9e316-0b5c-4db8-817d-f92df00215ae",
                                "de94bba4-06d1-4d40-a16a-bfd50179d6ac", "0xef"})
# mount points of system images, not data: Pop!_OS's recovery partition (vfat, the installer)
NOT_DATA_MOUNTS = {"/recovery": "vfat"}


@dataclass
class Device:
    name: str
    type: str                        # disk, part, crypt, lvm, raid1, loop, rom, ...
    fstype: str | None
    mountpoints: list[str]
    removable: bool                  # RM, an external transport, or HOTPLUG (not SATA's), here or on a parent
    parent: "Device | None" = field(default=None, repr=False)
    transport: str | None = None     # TRAN of the disk it is on: usb, sata, nvme...
    label: str | None = None
    children: list["Device"] = field(default_factory=list, repr=False)
    size: int | None = None          # bytes; with parttype and uuid, only in a listing that asked for them
    parttype: str | None = None      # the partition type's GUID, or 0x.. on an MBR disk
    uuid: str | None = None
    dm_uuid: str | None = None       # a device-mapper device's DM UUID (read_devices, from /sys/block/dm-N/dm/uuid)
    backing_file: str | None = None  # a loop device's file (read_devices, from /sys/block/loopN/loop/backing_file)

    @property
    def encrypting(self) -> bool:
        """This device is a dm-crypt mapping that encrypts (not dm-verity or dm-integrity, which lsblk also calls
        crypt)."""
        return self.type == "crypt" and not (self.dm_uuid or "").upper().startswith(NOT_ENCRYPTING_DM)

    @property
    def encrypted(self) -> bool:
        """This device is, or sits on top of, a dm-crypt mapping that encrypts."""
        d: Device | None = self
        while d is not None:
            if d.encrypting:
                return True
            d = d.parent
        return False

    @property
    def path(self) -> str:
        """The device node. lsblk names device-mapper devices (crypt, LVM) by their mapper name."""
        if self.type in ("crypt", "lvm", "dm", "mpath") or self.type.startswith("dm"):
            return f"/dev/mapper/{self.name}"
        return f"/dev/{self.name}"

    @property
    def is_image(self) -> bool:
        return self.fstype in IMAGE_FSTYPES or self.type == "rom"


def _flag(v) -> bool:
    if isinstance(v, str):
        return v.strip() in ("1", "true")
    return bool(v)


def parse_lsblk(text: str) -> list[Device]:
    """Every device in `lsblk -J` output, parents before children. A device shared by several
    parents (an LVM volume spanning two PVs, RAID) appears once per parent."""
    data = json.loads(text)
    out: list[Device] = []

    def walk(node: dict, parent: Device | None):
        mps = node.get("mountpoints")
        if mps is None:
            mps = [node.get("mountpoint")]
        tran = (node.get("tran") or "").lower() or (parent.transport if parent else None)
        hotplug = _flag(node.get("hotplug")) and tran not in INTERNAL_HOTPLUG
        dev = Device(
            name=node.get("name", "?"), type=(node.get("type") or "").lower(), fstype=node.get("fstype") or None,
            mountpoints=[m for m in mps if m],
            removable=_flag(node.get("rm")) or tran in EXTERNAL_TRANSPORTS or hotplug or bool(parent and parent.removable),
            parent=parent, transport=tran or None, label=node.get("label") or None,
            size=node["size"] if isinstance(node.get("size"), int) else None,
            parttype=(node.get("parttype") or "").lower() or None, uuid=node.get("uuid") or None,
        )
        if parent:
            parent.children.append(dev)
        out.append(dev)
        for child in node.get("children") or []:
            walk(child, dev)

    for top in data.get("blockdevices") or []:
        walk(top, None)
    return out


class LsblkError(RuntimeError):
    pass


def read_devices(host: Host) -> list[Device]:
    r = host.run("lsblk", "-J", "-o", COLUMNS)
    if not r.ok and not r.missing:
        r = host.run("lsblk", "-J", "-o", COLUMNS_OLD)
    if r.missing:
        raise LsblkError("lsblk is not installed")
    if not r.ok:
        raise LsblkError(f"lsblk failed: {r.stderr.strip()[:200]}")
    try:
        devices = parse_lsblk(r.stdout)
    except (ValueError, AttributeError) as e:
        raise LsblkError(f"could not parse lsblk output: {e}") from e
    add_sysfs_facts(host, devices)
    return devices


def _sys_text(host: Host, path: str) -> str:
    try:
        return (host.read_file(host.sys_path(path)) or "").strip()
    except Exception:  # noqa: BLE001 - sysfs and udev's database are readable; anything else is just not known
        return ""


def add_sysfs_facts(host: Host, devices: list[Device]) -> None:
    """What lsblk's columns leave out, from /sys and udev's database (both readable without root): each
    device-mapper device's DM UUID (dm-verity and dm-integrity are "crypt" to lsblk), each loop device's backing file,
    and a mounted partition's type (ID_PART_ENTRY_TYPE) where the listing didn't ask for it."""
    by_name: dict[str, list[Device]] = {}
    for d in devices:
        by_name.setdefault(d.name, []).append(d)
    try:
        blocks = [p.name for p in host.sys_path("/sys/block").iterdir()]
    except OSError:
        blocks = []
    for b in blocks:
        if b.startswith("dm-"):
            name, uuid = _sys_text(host, f"/sys/block/{b}/dm/name"), _sys_text(host, f"/sys/block/{b}/dm/uuid")
            for d in by_name.get(name, []):
                d.dm_uuid = uuid or None
        elif b.startswith("loop"):
            backing = _sys_text(host, f"/sys/block/{b}/loop/backing_file")
            for d in by_name.get(b, []):
                d.backing_file = backing.removesuffix(" (deleted)") or None
    for d in devices:
        if d.type == "part" and d.parttype is None and d.mountpoints:
            devno = _sys_text(host, f"/sys/class/block/{d.name}/dev")
            udev = _sys_text(host, f"/run/udev/data/b{devno}") if devno else ""
            m = next((ln[len("E:ID_PART_ENTRY_TYPE="):] for ln in udev.splitlines()
                      if ln.startswith("E:ID_PART_ENTRY_TYPE=")), None)
            d.parttype = m.lower() if m else None


def read_partitions(host: Host) -> list[Device]:
    """The same listing with each device's size, partition type and filesystem UUID."""
    r = host.run("lsblk", "-J", "-b", "-o", COLUMNS_PARTITIONS)
    if r.missing:
        raise LsblkError("lsblk is not installed")
    if not r.ok:
        raise LsblkError(f"lsblk failed: {r.stderr.strip()[:200]}")
    try:
        return parse_lsblk(r.stdout)
    except (ValueError, AttributeError) as e:
        raise LsblkError(f"could not parse lsblk output: {e}") from e


def disk_of(d: Device) -> Device:
    while d.parent is not None:
        d = d.parent
    return d


def descendants(d: Device) -> list[Device]:
    return [x for c in d.children for x in [c, *descendants(c)]]


def boot_stick(d: Device) -> bool:
    """The drive holds an installer or boot image (a hybrid ISO, Ventoy): it is for booting."""
    disk = disk_of(d)
    return any(x.is_image or x.label in BOOT_STICK_LABELS for x in [disk, *descendants(disk)])


def luks_devices(devices: list[Device]) -> list[Device]:
    """The LUKS containers behind every open dm-crypt mapping (what `cryptsetup luksDump` reads)."""
    out: dict[str, Device] = {}
    for d in devices:
        if d.type == "crypt" and d.parent is not None and d.parent.fstype == "crypto_LUKS":
            out.setdefault(d.parent.path, d.parent)
    return list(out.values())


def find(devices: list[Device], host: Host, node: str) -> Device | None:
    """The lsblk device for a device node as the kernel names it in /proc/swaps or
    /sys/power/resume: /dev/sda2, /dev/dm-1 (looked up in /sys/block), /dev/mapper/name."""
    name = node.removeprefix("/dev/").removeprefix("mapper/")
    if name.startswith("dm-"):
        try:
            name = (host.read_sys(f"/sys/block/{name}/dm/name") or name).strip()
        except Exception:  # noqa: BLE001 - unreadable sysfs: keep the kernel name
            pass
    return next((d for d in devices if d.name == name), None)


def holding(devices: list[Device], path: str) -> Device | None:
    """The device whose mounted filesystem contains `path` (longest mountpoint wins)."""
    best, best_len = None, -1
    for mp, d in mounted(devices):
        if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) > best_len:
            best, best_len = d, len(mp)
    return best


def mounted(devices: list[Device]) -> list[tuple[str, Device]]:
    """(mountpoint, device) for every mounted filesystem, swap excluded."""
    return [(mp, d) for d in devices for mp in d.mountpoints if mp.startswith("/")]


@dataclass
class FdeAssessment:
    value: str | None                       # 'none' | 'partial' | 'full', None if it can't be told
    root: Device | None = None
    unencrypted: list[str] = field(default_factory=list)   # mountpoints holding data, not encrypted
    reason: str = ""


def holds_data(devices: list[Device], d: Device, mp: str) -> bool:
    """Whether a mounted filesystem holds anyone's data: not a boot or EFI system partition (by where it is mounted or
    by its partition type, an ESP mounted elsewhere included), a recovery partition, a removable drive or a read-only
    image; a loop device's data is where its file is, and counts only when that isn't encrypted (Waydroid's ext4
    image on the encrypted root is as encrypted as the root)."""
    if mp in BOOT_MOUNTS or d.removable or d.is_image or mp.startswith("/sysroot/ostree/"):
        return False
    if (d.parttype or "") in NOT_DATA_PARTTYPES or NOT_DATA_MOUNTS.get(mp) == d.fstype:
        return False
    if d.type == "loop" and d.backing_file:
        host_fs = holding(devices, d.backing_file)
        return host_fs is None or host_fs is d or not host_fs.encrypted
    return True


def plain_data_mounts(devices: list[Device]) -> list[str]:
    """The mounted filesystems holding data that aren't encrypted."""
    return sorted({mp for mp, d in mounted(devices) if not d.encrypted and holds_data(devices, d, mp)})


def assess_fde(devices: list[Device]) -> FdeAssessment:
    """'none' if / is not on dm-crypt; 'partial' if / is but another fixed, mounted data
    filesystem isn't (boot partitions, removable drives and read-only images don't count);
    'full' otherwise. None when / isn't a block device lsblk knows (a container, ZFS or
    bcachefs native encryption): the app can't tell, so it doesn't guess."""
    mounts = mounted(devices)
    # ostree systems (Fedora Silverblue, Kinoite, Bazzite...) mount the real root at /sysroot; / is a composefs overlay
    roots = [d for mp, d in mounts if mp == "/"] or [d for mp, d in mounts if mp == "/sysroot"]
    if not roots:
        return FdeAssessment(None, reason="/ is not on a block device lsblk reports (container, ZFS, or similar)")
    root = roots[0]
    if not root.encrypted and root.fstype in NATIVE_ENCRYPTION_FSTYPES:
        return FdeAssessment(None, root, reason=f"/ is {root.fstype}, whose own encryption lsblk can't see")
    if not root.encrypted:
        return FdeAssessment("none", root, ["/"], "/ is not on an encrypted (dm-crypt) device")
    plain = plain_data_mounts(devices)
    if plain:
        return FdeAssessment("partial", root, plain, "/ is encrypted; some other mounted filesystems are not")
    return FdeAssessment("full", root, [], "/ and every other fixed data filesystem are encrypted")
