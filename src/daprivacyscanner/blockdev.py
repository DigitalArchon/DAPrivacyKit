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

    @property
    def encrypted(self) -> bool:
        """This device is, or sits on top of, a dm-crypt mapping."""
        d: Device | None = self
        while d is not None:
            if d.type == "crypt":
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
        return parse_lsblk(r.stdout)
    except (ValueError, AttributeError) as e:
        raise LsblkError(f"could not parse lsblk output: {e}") from e


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
    plain = sorted({mp for mp, d in mounts
                    if mp not in BOOT_MOUNTS and not d.removable and not d.is_image and not d.encrypted
                    and not mp.startswith("/sysroot/ostree/")})
    if plain:
        return FdeAssessment("partial", root, plain, "/ is encrypted; some other mounted filesystems are not")
    return FdeAssessment("full", root, [], "/ and every other fixed data filesystem are encrypted")
