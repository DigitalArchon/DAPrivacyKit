"""The storage stack under a filesystem, from /sys (unprivileged): each layer from the
filesystem's own device down to the drives (device-mapper: LUKS, LVM; md RAID; a partition; the
disk), how much one discard may cover at each (0: TRIM stops there), and each drive's model,
firmware, transport and kind. Used by enc.trim_off and the TRIM test (tools/trimtest.py)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from pathlib import Path

from .host import Host, Unreadable


def read_text(host: Host, path: Path) -> str | None:
    try:
        return host.read_file(path)
    except Unreadable:
        return None


def children(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir())
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []


@dataclass
class Layer:
    name: str                               # dm-0, nvme0n1p2, nvme0n1
    kind: str                               # crypt, lvm, dm, md, partition, disk
    label: str = ""                         # the device-mapper name; for md, the RAID level (raid5)
    discard_max: int | None = None          # bytes one discard may cover; 0: takes no TRIM; None: not reported


@dataclass
class Drive:
    name: str
    model: str = ""
    firmware: str = ""
    transport: str = ""                     # nvme, sata, usb, virtio, mmc, scsi
    rotational: bool | None = None


def num(text: str | None) -> int | None:
    t = (text or "").strip()
    return int(t) if t.isdigit() else None


def dev_name(host: Host, source: str) -> str:
    """dm-0 for /dev/mapper/luks-…, nvme0n1p2 for /dev/nvme0n1p2."""
    p = host.sys_path(source)
    if p.is_symlink():
        return os.path.basename(os.readlink(p))
    return os.path.basename(source)


def layers(host: Host, name: str, depth: int = 0) -> list[Layer]:
    if depth > 8:
        return []
    base = host.sys_path(f"/sys/class/block/{name}")
    label = (read_text(host, base / "dm" / "name") or read_text(host, base / "md" / "level") or "").strip()
    uuid = (read_text(host, base / "dm" / "uuid") or "").strip()
    part = (base / "partition").exists()
    kind = ("crypt" if uuid.startswith("CRYPT-") else "lvm" if uuid.startswith("LVM-") else "md" if name.startswith("md")
            else "dm" if label else "partition" if part else "disk")
    layer = Layer(name, kind, label, num(read_text(host, base / "queue" / "discard_max_bytes")))
    below = [s.name for s in children(base / "slaves")]
    if part:
        below = [os.path.basename(os.path.dirname(os.path.realpath(base)))]
    return [layer] + [x for b in below for x in layers(host, b, depth + 1)]


def drive(host: Host, name: str) -> Drive:
    base = host.sys_path(f"/sys/block/{name}")
    dev = base / "device"
    vendor = (read_text(host, dev / "vendor") or "").strip()
    real = os.path.realpath(base)
    transport = ("usb" if "/usb" in real else "nvme" if name.startswith("nvme") else "virtio" if name.startswith("vd")
                 else "mmc" if name.startswith("mmcblk") else "sata" if vendor == "ATA" else "scsi")
    rota = (read_text(host, base / "queue" / "rotational") or "").strip()
    return Drive(name, (read_text(host, dev / "model") or "").strip(),
                 (read_text(host, dev / "firmware_rev") or read_text(host, dev / "rev") or "").strip(),
                 transport, {"0": False, "1": True}.get(rota))


def device_stats(host: Host, name: str) -> tuple[int | None, int | None]:
    """Sectors written and sectors discarded since boot (/sys/class/block/<name>/stat; discards
    from Linux 4.18). None where not reported."""
    f = (read_text(host, host.sys_path(f"/sys/class/block/{name}/stat")) or "").split()
    return (int(f[6]) if len(f) > 6 and f[6].isdigit() else None,
            int(f[13]) if len(f) > 13 and f[13].isdigit() else None)


def logical(host: Host, path: Path | str) -> str:
    """A path as the system sees it (fixture trees: without the fixture root)."""
    real = os.path.realpath(path)
    root = os.path.realpath(host.root)
    return real[len(root):] if root != "/" and real.startswith(root + "/") else real


@dataclass
class Stack:
    """A filesystem holding / or the home folder, and what is under it."""
    mount: str
    fstype: str
    source: str
    options: str
    layers: list[Layer]
    drives: list[Drive]

    @property
    def stops(self) -> list[Layer]:
        """Every layer that takes no TRIM, from the filesystem down."""
        return [x for x in self.layers if x.discard_max == 0]

    @property
    def stop(self) -> Layer | None:
        """Where TRIM stops: the deepest layer that takes none, if any. A layer above one that takes none reports none
        either: a logical volume on LUKS opened without discards says 0 because LUKS does (the first one from the
        top would name the volume, not the cause). A volume that still says 0 over layers that pass hasn't taken up
        a change below it yet (lvchange --refresh)."""
        zero = self.stops
        return zero[-1] if zero else None

    @property
    def hard_disk(self) -> bool:
        return bool(self.drives) and all(d.rotational for d in self.drives)

    @property
    def continuous(self) -> bool:
        """Mounted with discard: trimmed as files are deleted (btrfs sets discard=async itself on SSDs from Linux 6.2)."""
        return any(o == "discard" or o.startswith("discard=") and o != "discard=off" for o in self.options.split(","))


def stacks(host: Host) -> list[Stack]:
    """The filesystems holding / and the home folder, once each, with their stacks. Only those on
    a block device."""
    table = []
    for line in (host.read_sys("/proc/mounts") or "").splitlines():
        f = line.split()
        if len(f) >= 4:
            table.append((f[0], f[1].replace("\\040", " "), f[2], f[3]))
    out: list[Stack] = []
    for where in ("/", logical(host, host.home)):
        best = None
        for m in table:
            if where == m[1] or where.startswith(m[1].rstrip("/") + "/"):
                if best is None or len(m[1]) >= len(best[1]):
                    best = m
        if best is None or not best[0].startswith("/dev/") or any(s.source == best[0] for s in out):
            continue
        ls = layers(host, dev_name(host, best[0]))
        out.append(Stack(best[1], best[2], best[0], best[3], ls, [drive(host, x.name) for x in ls if x.kind == "disk"]))
    return out


def stop_reason(layer: Layer, drives: list[Drive], vm: bool = False) -> str:
    """Why TRIM stops at this layer, in plain words."""
    if layer.kind == "crypt":
        return f"the encrypted volume {layer.label} isn't opened with discards allowed"
    if layer.kind == "md":
        return (f"the {layer.label or 'software'} RAID array {layer.name} drops TRIM"
                + (" (Linux does for RAID 4, 5 and 6 unless told it is safe)" if layer.label in ("raid4", "raid5", "raid6")
                   else ""))
    if layer.kind == "disk" and any(d.transport == "usb" for d in drives):
        return "the USB connection doesn't pass TRIM on (many USB adapters don't)"
    if layer.kind == "disk" and vm:
        return "the virtual disk doesn't take TRIM"
    if layer.kind == "disk":
        return "the drive doesn't take TRIM"
    if layer.kind == "lvm":
        # the deepest layer that takes none (Stack.stop): those below it pass TRIM, it hasn't taken that up yet
        return (f"the logical volume {layer.label} hasn't taken up TRIM from the layers below it yet (it does after "
                "sudo lvchange --refresh, or a restart)")
    return f"a layer of the storage ({layer.label or layer.name}) doesn't pass TRIM on"


def luks_version(host: Host, layer: Layer) -> int | None:
    """The LUKS version of the device under a crypt layer, from udev's database (readable without
    root: ID_FS_VERSION), or None."""
    import re
    for slave in children(host.sys_path(f"/sys/class/block/{layer.name}/slaves")):
        devno = (read_text(host, host.sys_path(f"/sys/class/block/{slave.name}/dev")) or "").strip()
        if re.fullmatch(r"\d+:\d+", devno):
            m = re.search(r"^E:ID_FS_VERSION=(\d+)", read_text(host, host.sys_path(f"/run/udev/data/b{devno}")) or "",
                          re.M)
            if m:
                return int(m.group(1))
    return None


def underlying(host: Host, layer: Layer) -> str | None:
    """The device a crypt layer opens (/dev/nvme0n1p3)."""
    slaves = children(host.sys_path(f"/sys/class/block/{layer.name}/slaves"))
    return f"/dev/{slaves[0].name}" if slaves else None
