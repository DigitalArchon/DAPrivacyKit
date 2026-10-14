"""Before you hand over a drive (docs/TECHNICAL.md, Tools): what a USB stick, SD card or external disk carries
besides the files on it, cleaned before it is given to someone.

- Only drives the kernel reports as removable or external (blockdev's `removable`: RM, a USB or
  FireWire transport, hot-pluggable other than SATA), mounted, chosen by their mount point from the
  list this module makes; never the system's or the home's filesystem, never a read-only one.
- The residue is found by exact names, never patterns deleted recursively: trash folders
  (.Trash-UID at the top, .Trash/UID, .Trashes, $RECYCLE.BIN, RECYCLER), thumbnails (.sh_thumbnails,
  .thumbnails, Thumbs.db), folder view settings (Dolphin's .directory, macOS's .DS_Store), macOS
  metadata (AppleDouble ._ files, checked by their magic number; .Spotlight-V100, .fseventsd...),
  Windows' System Volume Information, and lock or owner files that name the user (LibreOffice's
  .~lock.NAME#, Office's ~$NAME). The walk stays on the drive's filesystem and follows no links.
- The plan lists every file it would delete (DeleteFiles: each a regular file inside its group's
  folder), and deleting needs the user's confirmation. It is a tool, not a fix: nothing goes in
  History.
- Rule 8: the page says plainly that deleting doesn't erase. On flash storage, deleted files (these,
  and whatever was deleted from the drive before) usually stay recoverable with free tools: what
  protects them is encrypting the drive, or erasing all of it (Retire a drive)."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .. import blockdev
from ..fix import DeleteFiles, FixContext
from ..host import Host

WALK_LIMIT = 200_000
LIST_LIMIT = 5_000              # paths listed per group (the rest are counted)
APPLEDOUBLE_MAGIC = b"\x00\x05\x16\x07"
SYSTEM_MOUNTS = frozenset({"/", "/home", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/tmp"})

GROUPS = {
    "own_trash": ("Your trash on this drive",
                  "Files you deleted from this drive in the file manager: they are still on it, whole, in its trash folder."),
    "other_trash": ("Trash from other computers or accounts",
                    "Files deleted on another computer or by another account (macOS, Windows, other Linux users), kept "
                    "whole in their trash folders."),
    "thumbnails": ("Thumbnails",
                   "Small copies of pictures and videos made when someone browsed the drive, often including ones "
                   "deleted since."),
    "views": ("Folder view settings",
              "Dolphin's .directory and macOS's .DS_Store files: how folders were shown, and for .DS_Store the names of "
              "files in them, deleted ones included."),
    "mac": ("macOS file metadata",
            "AppleDouble (._) files carry a file's extra attributes, such as the address it was downloaded from; "
            "Spotlight's index and the file-system event log list what was on the drive."),
    "windows": ("Windows system folder",
                "System Volume Information: Windows' index and restore data for the drive; Windows makes it again "
                "when the drive is next plugged in."),
    "owners": ("Lock and owner files",
               "Left by office programs that didn't close cleanly: they hold your user name and the computer's name."),
}

# folders deleted whole, at the drive's top only
TOP_FOLDERS = {".Trashes": "other_trash", "$RECYCLE.BIN": "other_trash", "RECYCLER": "other_trash",
               ".Spotlight-V100": "mac", ".fseventsd": "mac", ".TemporaryItems": "mac",
               ".DocumentRevisions-V100": "mac", "System Volume Information": "windows"}
TRASH_UID = re.compile(r"^\.Trash-(\d+)$")
# folders deleted whole, wherever they are
ANY_FOLDERS = {".sh_thumbnails": "thumbnails", ".thumbnails": "thumbnails"}
# single files, wherever they are
ANY_FILES = {".directory": "views", ".DS_Store": "views", "Thumbs.db": "thumbnails", "ehthumbs.db": "thumbnails",
             "ehthumbs_vista.db": "thumbnails"}
TOP_FILES = {".apdisk": "mac"}
LIBREOFFICE_LOCK = re.compile(r"^\.~lock\..+#$")
OFFICE_OWNER = re.compile(r"^~\$.+\.(docx?|docm|xlsx?|xlsm|pptx?|pptm|odt|ods|odp)$", re.I)
# files Remove metadata can show (photos, video, documents)
MEDIA = re.compile(r"\.(jpe?g|heic|heif|png|tiff?|webp|dng|cr2|nef|arw|mp4|mov|m4v|avi|mkv|pdf|docx|xlsx|pptx|odt|ods|"
                   r"odp|mp3|m4a|flac|ogg)$", re.I)


class Refused(Exception):
    pass


@dataclass
class Drive:
    mount: str
    device: str
    fstype: str
    label: str
    transport: str
    readonly: bool = False
    blocked: str = ""

    def to_dict(self) -> dict:
        return {"mount": self.mount, "device": self.device, "fstype": self.fstype, "label": self.label,
                "transport": self.transport, "readonly": self.readonly, "blocked": self.blocked}


def _mount_options(host: Host) -> dict[str, str]:
    try:
        text = host.read_sys("/proc/mounts") or ""
    except Exception:  # noqa: BLE001 - no mount table: options unknown
        text = ""
    out = {}
    for ln in text.splitlines():
        f = ln.split()
        if len(f) > 3:
            out[f[1].replace("\\040", " ")] = f[3]
    return out


def drives(host: Host) -> list[Drive]:
    """Mounted filesystems on removable or external drives."""
    try:
        devices = blockdev.read_devices(host)
    except blockdev.LsblkError:
        return []
    opts = _mount_options(host)
    home = str(host.home)
    out = []
    for mp, d in blockdev.mounted(devices):
        if not d.removable or d.is_image or mp in SYSTEM_MOUNTS:
            continue
        drv = Drive(mp, d.path, d.fstype or "", d.label or "", (blockdev.disk_of(d).transport or ""))
        drv.readonly = "ro" in (opts.get(mp, "").split(","))
        if home == mp or home.startswith(mp.rstrip("/") + "/"):
            drv.blocked = "Your home folder is on this drive."
        elif drv.readonly:
            drv.blocked = "It is mounted read-only, so nothing on it can be deleted."
        out.append(drv)
    return out


@dataclass
class Group:
    id: str
    folders: list[str] = field(default_factory=list)      # folders removed whole (relative to the drive)
    files: list[Path] = field(default_factory=list)       # every file to delete
    actions: list[DeleteFiles] = field(default_factory=list)
    bytes: int = 0

    def to_dict(self, top: Path) -> dict:
        title, text = GROUPS[self.id]
        rel = [str(f.relative_to(top)) for f in self.files[:LIST_LIMIT]]
        return {"id": self.id, "title": title, "text": text, "count": len(self.files), "bytes": self.bytes,
                "folders": self.folders, "files": rel, "more": max(0, len(self.files) - LIST_LIMIT)}


@dataclass
class Plan:
    drive: Drive
    top: Path
    groups: list[Group] = field(default_factory=list)
    media: list[str] = field(default_factory=list)          # files Remove metadata can show
    media_count: int = 0
    truncated: bool = False
    in_use: list[str] = field(default_factory=list)         # programs holding a file this would delete
    ids: dict[str, tuple[int, int]] = field(default_factory=dict)   # each folder deleted from: (device, inode)

    @property
    def actions(self) -> list[DeleteFiles]:
        return [a for g in self.groups for a in g.actions]

    def to_dict(self) -> dict:
        return {"drive": self.drive.to_dict(), "groups": [g.to_dict(self.top) for g in self.groups],
                "files": sum(len(g.files) for g in self.groups), "bytes": sum(g.bytes for g in self.groups),
                "media": self.media, "media_count": self.media_count, "truncated": self.truncated,
                "in_use": self.in_use,
                "steps": [a.describe() for a in self.actions]}


def find(host: Host, mount: str) -> Drive:
    """The drive mounted at `mount`, from the list (the page's choice is never trusted further)."""
    d = next((x for x in drives(host) if x.mount == mount), None)
    if d is None:
        raise Refused("That isn't a removable or external drive mounted now.")
    if d.blocked:
        raise Refused(d.blocked)
    return d


def _files_in(folder: Path, dev: int, budget: list[int]) -> tuple[list[Path], int]:
    """Regular files under `folder`, on the same filesystem, following no links."""
    files, size = [], 0
    for top, dirs, names, dfd in os.fwalk(folder, follow_symlinks=False):
        for d in list(dirs):
            try:
                if os.stat(d, dir_fd=dfd, follow_symlinks=False).st_dev != dev:
                    dirs.remove(d)
            except OSError:
                dirs.remove(d)
        for n in names:
            budget[0] -= 1
            if budget[0] < 0:
                return files, size
            try:
                st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_dev == dev:
                files.append(Path(top) / n)
                size += st.st_size
    return files, size


def _identity(folder: Path) -> tuple[int, int]:
    """(device, inode) of a real folder, never through a link: the same folder when deleting, or not."""
    st = os.stat(folder, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(f"{folder} isn't a folder")
    return st.st_dev, st.st_ino


def _same_folders(p: Plan) -> bool:
    for folder, ident in p.ids.items():
        try:
            if _identity(Path(folder)) != ident:
                return False
        except FileNotFoundError:
            continue                             # gone since: nothing in it to delete
        except OSError:
            return False
    return True


def _appledouble(path: Path) -> bool:
    try:
        with open(path, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as fh:
            return fh.read(4) == APPLEDOUBLE_MAGIC
    except OSError:
        return False


def plan(host: Host, mount: str) -> Plan:
    """What cleaning the drive would delete now: every file, by group. Changes nothing."""
    drive = find(host, mount)
    top = host.sys_path(drive.mount)
    try:
        dev = os.stat(top, follow_symlinks=False).st_dev
    except OSError as e:
        raise Refused(f"{drive.mount} can't be read: {e.strerror or e}") from None
    p = Plan(drive, top)
    p.ids[str(top)] = _identity(top)
    groups: dict[str, Group] = {}
    budget = [WALK_LIMIT]
    uid = str(host.uid)
    singles: dict[str, list[Path]] = {}

    def whole(folder: Path, gid: str) -> None:
        p.ids[str(folder)] = _identity(folder)
        files, size = _files_in(folder, dev, budget)
        g = groups.setdefault(gid, Group(gid))
        g.folders.append(str(folder.relative_to(top)))
        g.files += files
        g.bytes += size
        g.actions.append(DeleteFiles(folder, files, GROUPS[gid][0].lower(), f"{drive.mount}/{folder.relative_to(top)}",
                                     prune=True, remove_root=True))

    for here, dirs, names, dfd in os.fwalk(top, follow_symlinks=False):
        at_top = Path(here) == top
        for d in sorted(dirs):
            path = Path(here) / d
            try:
                st = os.stat(d, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                dirs.remove(d)
                continue
            if st.st_dev != dev or not stat.S_ISDIR(st.st_mode):
                dirs.remove(d)
                continue
            gid = None
            if at_top and (m := TRASH_UID.match(d)):
                gid = "own_trash" if m.group(1) == uid else "other_trash"
            elif at_top and d in TOP_FOLDERS:
                gid = TOP_FOLDERS[d]
            elif at_top and d == ".Trash":                    # the shared trash: one folder per user inside
                for sub in sorted(os.listdir(path)) if os.access(path, os.R_OK | os.X_OK) else []:
                    if sub.isdigit() and (path / sub).is_dir() and not (path / sub).is_symlink():
                        whole(path / sub, "own_trash" if sub == uid else "other_trash")
                dirs.remove(d)
                continue
            elif d in ANY_FOLDERS:
                gid = ANY_FOLDERS[d]
            if gid is not None:
                whole(path, gid)
                dirs.remove(d)
        for n in names:
            budget[0] -= 1
            if budget[0] < 0:
                p.truncated = True
                break
            try:
                st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            path = Path(here) / n
            gid = ANY_FILES.get(n) or (TOP_FILES.get(n) if at_top else None)
            if gid is None and (LIBREOFFICE_LOCK.match(n) or (OFFICE_OWNER.match(n) and st.st_size < 4096)):
                gid = "owners"
            if gid is None and n.startswith("._") and _appledouble(path):
                gid = "mac"
            if gid is not None:
                singles.setdefault(gid, []).append(path)
                g = groups.setdefault(gid, Group(gid))
                g.files.append(path)
                g.bytes += st.st_size
            elif MEDIA.search(n):
                p.media_count += 1
                if len(p.media) < 50:
                    p.media.append(str(path))
        if budget[0] < 0:
            p.truncated = True
            break
    for gid, files in singles.items():
        groups[gid].actions.append(DeleteFiles(top, files, GROUPS[gid][0].lower(), drive.mount, prune=False))
    p.groups = [groups[g] for g in GROUPS if g in groups]          # in GROUPS' order
    p.in_use = _in_use(host, p)
    return p


def _in_use(host: Host, p: Plan) -> list[str]:
    """Programs of the user's holding a file (or working directory) this would delete."""
    from ..checks._util import open_files
    targets = {os.path.realpath(f) for g in p.groups for f in g.files}
    folders = [os.path.realpath(p.top / f).rstrip("/") + "/" for g in p.groups for f in g.folders]
    if not targets and not folders:
        return []
    return sorted({name for name, paths in open_files(host)
                   if any(x in targets or any(x.startswith(f) or x + "/" == f for f in folders) for x in paths)})


@dataclass
class Done:
    deleted: int = 0
    skipped: int = 0
    lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"deleted": self.deleted, "skipped": self.skipped, "lines": self.lines}


def clean(host: Host, p: Plan) -> Done:
    """Deletes what the plan lists (each file checked again by DeleteFiles), then syncs."""
    find(host, p.drive.mount)                       # still the same, still mounted, still allowed
    if not _same_folders(p):                        # another drive mounted there, or a folder replaced by a link
        raise Refused("The drive or its folders changed since the list was made: look at the drive again.")
    busy = _in_use(host, p)
    if busy:
        raise Refused(f"Close {', '.join(busy)} first: {'it is' if len(busy) == 1 else 'they are'} using files "
                      "that would be deleted.")
    ctx = FixContext(host, Path(os.devnull))        # DeleteFiles keeps no backups
    out = Done()
    for a in p.actions:
        rec = a.apply(ctx)
        out.deleted += rec["deleted"]
        out.skipped += rec["skipped"]
        out.lines.append(rec["text"])
    os.sync()
    return out
