"""Deleted file names (docs/TECHNICAL.md, Tools): which names of deleted files can still be read from a
filesystem, and what can be done about them.

The helper reads them (helper.names_begin): on ext4, each folder's own blocks (where kernels before
Linux 5.13 left a deleted file's name until a new entry reused the space) and then the journal, whose
copies of the folders' blocks as they were before are where the names are on a current kernel; on
btrfs, the whole device, for freed and stale copies of the folders' records. On the home's filesystem
only the user's own folders under their home; on another disk, every folder they can open. What the
journal holds of folders that are no listed folder's (gone, another account's, the system's) is
counted, and named only when the user asks as administrator (orphans). The list goes to the page once
and is never kept, logged or exported.

What can be done: on btrfs, trim (fstrim) and look again, since the old copies are free space; on
ext4, clear the journal (clear_journal: the kernel writes it out and zeroes it, every folder's names
at once), and for names in a folder's own blocks (rebuild.py does it) fillers: files with names of the
same length written into the folder until they take the deleted entries' places, then deleted (the
folder stays the same folder); or, for a large (indexed) folder, where fillers may not reach every
name, a rebuild (a new folder, every entry renamed into it, the old one removed: its blocks, names and
all, become free space for TRIM). Synced folders get neither: the provider keeps its own record of
what was deleted there."""

from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Callable

from ..checks._util import mounts
from ..host import Host
from ..paths import PathResolver
from . import trimtest as T

NAMES_TIMEOUT = 600
STEP_TIMEOUT = 300
CLEAR_TIMEOUT = 900                            # zeroing a journal: a second on an SSD, a hard disk's takes longer
PHASES = {"folders": "Reading the folders' records", "journal": "Reading the journal for copies of the folders' records",
          "disk": "Reading the whole disk for btrfs's records of the folders"}

# names made from a hash of something: Firefox's cache entries (SHA-1 of the cache key, 40 hex
# digits), other caches' MD5 and SHA-256 names, Chromium's simple cache entries (64 bits of the key)
HASH_NAME = re.compile(r"^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|[0-9a-f]{16}_[01s])$")
# browsers' disk caches, whose entries are named after the address they hold
BROWSER_CACHE = re.compile(r"(?:^|/)(?:cache2/(?:entries|doomed)|Cache/Cache_Data|Code Cache/(?:js|wasm))$")

# what the clean-ups leave in folders' records: fillers' names (rebuild.filler_names) and the
# temporary name a rebuilt folder had, in the folder above it
FILLER = re.compile(r"^_+[0-9]*$")
REBUILT = re.compile(r"^\.+(?:.+\.)?rebuild-[0-9a-f]{8}(?:-old)?$|^\.old-[0-9a-f]{8}$")

# what marks a folder a sync client keeps (in it or above it): Dropbox, Nextcloud and ownCloud's
# sync journal, Syncthing, MEGA
SYNC_MARKERS = ((re.compile(r"^\.dropbox(\.cache)?$"), "Dropbox"),
                (re.compile(r"^\.?_?\.sync_[0-9a-f]+\.db$"), "Nextcloud or ownCloud"),
                (re.compile(r"^\.owncloudsync\.log$"), "Nextcloud or ownCloud"),
                (re.compile(r"^\.stfolder$"), "Syncthing"),
                (re.compile(r"^\.debris$"), "MEGA"))


class Stopped(Exception):
    """The user stopped it, or administrator access ended."""


# ------------------------------------------------------------------ where

def targets(host: Host) -> list[dict]:
    """The filesystems the names can be listed on: the home's (its folders under the home), and
    other disks the TRIM test offers (every folder the user can open there); never the system disk
    outside the home. Whether TRIM reaches the drive decides what the clean-up can do."""
    table = mounts(host)
    home_fs = T.holding(table, T.logical(host, host.home))
    out = []
    for t in T.targets(host):
        here = home_fs is not None and home_fs.source == t.source
        if t.mount == "/" and not here:
            continue
        blocked = t.blocked if t.unreadable else ""
        if not blocked and not here and not os.access(host.sys_path(t.mount), os.W_OK | os.X_OK):
            blocked = (f"You can't create files at the top of {t.mount}, so its names can't be listed for you: on "
                       "another disk, the list is for disks you use.")
        lo, hi = (round(t.size / 1e12 * m) for m in T.MINUTES_PER_TB)
        out.append({"mount": t.mount, "fstype": t.fstype, "size": t.size, "scope": "home" if here else "mount",
                    "blocked": blocked, "encrypted": t.encrypted, "trim": t.trim, "no_trim": t.no_trim,
                    "guide": t.guide, "minutes": [max(1, lo), max(1, hi)], "source": t.source})
    return out


def target(host: Host, mount: str) -> dict | None:
    return next((t for t in targets(host) if t["mount"] == mount), None)


# ------------------------------------------------------------------ the list

def scan(host: Host, mount: str, privileged: Callable[[], object | None], job: dict,
         trim_passed: bool | None = None) -> dict:
    """The names of deleted files the helper can still read on the filesystem at `mount`, by folder
    (helper.names_begin), annotated for the page (view). For the page to show once: never kept,
    here or anywhere. The helper keeps them for the checks after a clean-up until names_end."""
    t = target(host, mount)
    if t is None or t["blocked"]:
        raise ValueError(t["blocked"] if t else "The names on that filesystem can't be listed.")

    def helper():
        h = privileged()
        if h is None:
            raise Stopped("Administrator access ended, so it stopped.")
        return h

    job.update(phase="Listing the folders", done=0, total=0, phase_started=time.time())
    b = helper().call("names_begin", {"mount": mount}, NAMES_TIMEOUT)
    job.update(phase=PHASES["folders" if b["unit"] == "folders" else "disk"], total=b["total"], unit=b["unit"],
               phase_started=time.time())
    try:
        while True:
            if job.get("cancel"):
                raise Stopped("Stopped.")
            step = helper().call("names_step", {}, STEP_TIMEOUT)
            if PHASES[step["phase"]] != job["phase"]:        # ext4: the folders, then the journal
                job.update(phase=PHASES[step["phase"]], phase_started=time.time())
            job.update(done=step["done"], total=step["total"], unit=step["unit"])
            if not step["more"]:
                break
        r = helper().call("names_result", {}, NAMES_TIMEOUT)
    except BaseException:
        try:
            h = privileged()
            if h is not None:
                h.call("names_end", {})
        except Exception:  # noqa: BLE001
            pass
        raise
    return view(host, t, r, trim_passed)


def top_of(host: Host, r: dict) -> Path:
    """The folder the listing's paths are under: the home, or the other disk's top."""
    return host.home if r["scope"] == "home" else host.sys_path(r["root"])


def view(host: Host, t: dict, r: dict, trim_passed: bool | None = None) -> dict:
    top = "~" if r["scope"] == "home" else r["root"].rstrip("/") or "/"
    base = top_of(host, r)
    data = PathResolver(host.home, host.environ).data_home / "daprivacyscanner"
    folders = []
    seen = Seen(host)
    for f in r["folders"]:
        rel = f["path"]
        hashes = [n for n in f["names"] if HASH_NAME.match(n)]
        names = [n for n in f["names"] if not HASH_NAME.match(n)]
        if len(hashes) < 3:                          # a couple of them read as well in the list
            names, hashes = f["names"], []
        path = base / rel if rel else base
        notes = []
        cache = bool(BROWSER_CACHE.search(rel))
        if path == data and T.FOLDER in f["names"]:
            notes.append(f"{T.FOLDER} is the TRIM test's own folder: its test files are deleted before the trim, so "
                         "their names go with it, but the folder itself is removed afterwards, so its name stays until "
                         "the next trim.")
        fill = [n for n in f["names"] if FILLER.match(n)]
        if fill:
            notes.append(f"{', '.join(fill[:3])}{'…' if len(fill) > 3 else ''}: names like these are what fillers leave "
                         "where they took deleted names' places. They hold nothing.")
        built = [n for n in f["names"] if REBUILT.match(n)]
        if built:
            notes.append(f"{built[0]}{'…' if len(built) > 1 else ''}: the temporary name a folder here had while it was "
                         "rebuilt. It holds nothing; a rebuild of this folder clears it too.")
        only = len(f.get("journal", []))                 # names the journal alone holds: nothing in the folder to clean
        if r["fstype"] != "ext4":
            what = None
        elif f.get("gone"):
            what = {"method": "none", "journal": True,
                    "why": "This folder is gone. Its names are in the journal only: clearing the journal removes them."}
        elif only == len(f["names"]):
            what = {"method": "none", "journal": True,
                    "why": "These names are in the journal only: clearing the journal removes them. Nothing of them is "
                           "left in the folder itself."}
        else:
            what = remedy(host, t, r, rel, seen)
        folders.append({"path": f"{top}/{rel}" if rel else top, "rel": rel, "names": names, "hashes": hashes,
                        "browser_cache": cache, "notes": notes, "gone": bool(f.get("gone")), "journal_only": only,
                        "hidden": any(part.startswith(".") for part in rel.split("/") if part),
                        "remedy": what})
    journal = dict(r["journal"], command=clear_command(t["mount"])) if r.get("journal") else None
    return {"folders": folders, "count": r["count"], "truncated": r["truncated"], "fstype": r["fstype"],
            "scope": r["scope"], "root": top, "mount": t["mount"], "unreadable": r.get("unreadable", 0),
            "facts": facts(t, trim_passed, ext4_wipes_names(host) if r["fstype"] == "ext4" else None, journal),
            "trim": t["trim"], "no_trim": t["no_trim"], "guide": t["guide"], "journal": journal,
            "encrypted": t["encrypted"], "commands": e2fsck_commands(host, t) if r["fstype"] == "ext4" else [],
            "trim_passed": trim_passed}


def clear_command(mount: str) -> str:
    """The same call as helper.names_journal_clear, for a terminal: no program on the system makes it, so
    it is a line of Python. Shown beside the button, to learn from; the app never runs it."""
    code = (f"import fcntl, os, struct; fcntl.ioctl(os.open({json.dumps(mount)}, os.O_RDONLY), 0x4004662B, "
            'struct.pack("I", 2))')
    return "sudo python3 -c " + shlex.quote(code)


def clear_journal(privileged: Callable[[], object | None]) -> dict:
    """Has the kernel write the listed filesystem's journal out and zero it (helper.names_journal_clear):
    the names in it, every folder's and every account's, are gone from it at once. Only while the helper
    holds a listing; nothing is kept of it, and there is nothing to undo."""
    h = privileged()
    if h is None:
        raise Stopped("Administrator access ended: list the names again first.")
    return h.call("names_journal_clear", {}, CLEAR_TIMEOUT)


def orphans(privileged: Callable[[], object | None]) -> dict:
    """The names in the journal's records of folders that are no listed folder's (helper.names_orphans),
    hash-like ones apart: shown only when the user asks for them."""
    h = privileged()
    if h is None:
        raise Stopped("Administrator access ended: list the names again first.")
    r = h.call("names_orphans", {}, NAMES_TIMEOUT)
    hashes = [n for n in r["names"] if HASH_NAME.match(n)]
    return {"names": [n for n in r["names"] if not HASH_NAME.match(n)], "hashes": hashes, "truncated": r["truncated"],
            "records": r["records"]}


def ext4_wipes_names(host: Host) -> bool | None:
    """Since Linux 5.13 ext4 overwrites a deleted file's entry in its folder's block as it deletes it ("ext4: wipe
    ext4_dir_entry2 upon file deletion"). Seen on Mint 22.3 (kernel 7.0, a LUKS ext4 home): of 403 names just deleted
    none was left in the folders' blocks, and all were still in the journal. None: the kernel's version can't be read."""
    m = re.match(r"(\d+)\.(\d+)", (host.read_sys("/proc/sys/kernel/osrelease") or "").strip())
    return (int(m.group(1)), int(m.group(2))) >= (5, 13) if m else None


JOURNAL_UNREAD = {"none": "This filesystem has no journal, so there are no copies of the folders' records to look in.",
                  "external": "The journal is on another device, which the list doesn't read: names of files deleted "
                              "lately may be in it.",
                  "unknown": "The journal couldn't be found, so the list holds only what the folders' own records hold: "
                             "names of files deleted lately may be in the journal."}


def facts(t: dict, trim_passed: bool | None, wipes: bool | None = None, journal: dict | None = None) -> list[str]:
    """What the list means on this filesystem, said by the tool itself (there is no TRIM result to
    lean on). `wipes`: this kernel's ext4 overwrites a name as its file is deleted. `journal`: what the
    helper said of the journal (its state, whether folder records carry checksums, fast commits)."""
    out = []
    if t["fstype"] == "ext4":
        if wipes:
            out.append("This kernel's ext4 (Linux 5.13 and later) overwrites a file's name in its folder's own records "
                       "as the file is deleted. What stays is in the journal: it keeps copies of the folders' records "
                       "as they were before, names and all, until it has wrapped round (minutes to hours on a busy "
                       "system, days on an idle one) or is cleared. This list reads both. TRIM doesn't reach either: "
                       "they aren't free space.")
        else:
            out.append("ext4 keeps a deleted file's name in its folder's own records until a new entry reuses the space, "
                       "and copies of those records in its journal until the journal wraps (minutes to hours on a busy "
                       "system, longer on an idle one) or is cleared. This list reads both. TRIM doesn't reach them: "
                       "they aren't free space.")
        state = (journal or {}).get("state", "read")
        if state in JOURNAL_UNREAD:
            out.append(JOURNAL_UNREAD[state])
        elif journal and not journal["checksums"]:
            out.append("This filesystem keeps no checksums on its folders' records (metadata_csum, the default since "
                       "2016), and a checksum is what ties a copy in the journal to its folder. So none of the "
                       "journal's names is listed under a folder here: they are counted below.")
        if journal and journal["fast_commit"] and state == "read":
            out.append("This filesystem uses fast commits, which keep names in records of their own at the journal's "
                       "end. The list doesn't read those; clearing the journal removes them with the rest.")
    else:
        out.append("btrfs never changes its records in place: deleting a file writes a new copy of the folder's "
                   "records without it, and the old copy stays in free space until it is trimmed or reused. Live "
                   "records can also keep a stale entry past their end.")
        if t["trim"] == "continuous":
            if trim_passed:
                out.append("This filesystem trims as files are deleted (the discard option), and the TRIM test passed "
                           "on this drive: freed copies are trimmed within minutes, so this list holds only what was "
                           "deleted in the last few minutes. On a running desktop that is the folders that change all the "
                           "time, such as browser caches: the mechanism working, not a leak to fix.")
            else:
                out.append("This filesystem trims as files are deleted (the discard option): if TRIM works on this drive "
                           "(the TRIM test shows it), freed copies are trimmed within minutes, and this list holds only "
                           "what was deleted in the last few minutes, mostly folders that change all the time, such as "
                           "browser caches.")
    out.append("Encryption is what protects names from someone who has the disk: "
               + ("this disk is encrypted, so they need your passphrase too." if t["encrypted"] else
                  "this disk isn't encrypted, so anyone with it can read them."))
    return out


# ------------------------------------------------------------------ what can be done for each folder

class Seen:
    """What remedy() looks at more than once for one listing: the mount table, and which sync
    client's marker each folder holds."""

    def __init__(self, host: Host):
        self.host, self._mounts, self._markers = host, None, {}

    def mounts(self) -> list:
        if self._mounts is None:
            self._mounts = mounts(self.host)
        return self._mounts

    def marker(self, folder: Path) -> str | None:
        if folder not in self._markers:
            try:
                names = os.listdir(folder)
            except OSError:
                names = []
            self._markers[folder] = next((client for n in names for pattern, client in SYNC_MARKERS
                                          if pattern.match(n)), None)
        return self._markers[folder]


def synced_by(path: Path, top: Path, seen: Seen) -> str | None:
    """The sync client that keeps this folder, recognised by its marker in the folder or one above
    it up to `top`; None if none is recognised (the page then asks)."""
    p = path
    while True:
        client = seen.marker(p)
        if client:
            return client
        if p == top or p.parent == p or top not in p.parents:
            return None
        p = p.parent


def has_mount_in(host: Host, path: Path, seen: Seen) -> bool:
    """Whether another filesystem is mounted on a folder in it (renaming it would fail)."""
    inside = T.logical(host, path).rstrip("/") + "/"
    return any(m.target.startswith(inside) and "/" not in m.target[len(inside):] for m in seen.mounts())


FS_IOC_GETFLAGS, FS_INDEX_FL = 0x80086601, 0x1000


def indexed(path: Path) -> bool:
    """Whether ext4 keeps this folder as a hash tree (dir_index: more than one block of entries)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        buf = bytearray(8)
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
        return bool(int.from_bytes(buf[:4], sys.byteorder) & FS_INDEX_FL)
    except OSError:
        return False
    finally:
        os.close(fd)


FILLERS_WHY = ("Fillers take the deleted names' places in the folder's own records. It stays the same folder, so a "
               "sync client, a backup or an index that looks at it later finds nothing changed but its date.")


def remedy(host: Host, t: dict, r: dict, rel: str, seen: Seen | None = None, prefer: str = "") -> dict:
    """{"method": "rebuild" | "fillers" | "none", "why": ...} for an ext4 folder in the list: fillers
    for a small folder (a new entry goes in the first gap that fits, where the deleted one was, so they
    are sure to reach it), a rebuild for a large one (a hash of the name picks the block, so fillers
    could take thousands of files and still miss some), or when `prefer` is "rebuild" (fillers left
    names). What changes from moment to moment (programs using or watching it) is checked when the
    clean-up is planned."""
    seen = seen or Seen(host)
    top = top_of(host, r)
    path = top / rel if rel else top
    try:
        st = os.lstat(path)
    except OSError:
        return {"method": "none", "why": "It isn't there any more."}
    if st.st_uid != host.uid:
        return {"method": "none", "why": "It isn't your folder, so it is left to its owner."}
    client = synced_by(path, top, seen)
    if client:
        return {"method": "none", "synced": client,
                "why": f"{client} keeps this folder, and its deleted files (names and contents) in its own history: "
                       f"delete them permanently there (on its website or in its app). Anything done here would be "
                       "uploaded and recorded too."}
    if not rel:
        why = ("Your home folder can't be swapped for a new one while you are logged in, so fillers take the deleted "
               "names' places instead." if r["scope"] == "home" else
               f"The top folder of {t['mount']} can't be swapped for a new one, so fillers take the deleted names' places "
               "instead.")
        return {"method": "fillers", "why": why}
    if has_mount_in(host, path, seen):
        return {"method": "fillers", "why": "Another disk is mounted in it, so it can't be swapped for a new folder: "
                                            "fillers take the deleted names' places instead."}
    if t["no_trim"] in ("hdd", "layer"):
        return {"method": "fillers", "why": "TRIM doesn't reach this drive, so a rebuilt folder's old records would "
                                            "stay readable in free space: fillers write over the deleted names where "
                                            "they are instead."}
    if prefer == "rebuild":
        return {"method": "rebuild", "why": "Rebuilt, as you asked: every entry is moved into a new folder and the old "
                                            "one removed, so its records, deleted names included, become free space for "
                                            "TRIM."}
    if indexed(path):
        return {"method": "rebuild", "why": "A large folder: ext4 places a new entry where a hash of its name points, so "
                                            "fillers could take thousands of files and still miss some. Rebuilt instead: "
                                            "every entry is moved into a new folder and the old one removed, so its "
                                            "records, deleted names included, become free space for TRIM."}
    return {"method": "fillers", "why": FILLERS_WHY}


def e2fsck_commands(host: Host, t: dict) -> list[str]:
    """For every folder at once, from a live USB (the filesystem unmounted): e2fsck -fD compacts
    every folder, dropping what deleted entries left. The device as a live system would see it."""
    from ..storage import dev_name, layers
    stack = layers(host, dev_name(host, t["source"]))
    cmds = []
    crypt = next((i for i, x in enumerate(stack) if x.kind == "crypt"), None)
    if crypt is not None and crypt + 1 < len(stack):
        name = stack[crypt].label or "data"
        cmds.append(f"sudo cryptsetup open /dev/{stack[crypt + 1].name} {name}")
    if any(x.kind == "lvm" for x in stack):
        cmds.append("sudo vgchange -ay")
    cmds.append(f"sudo e2fsck -fD {t['source']}")
    return cmds
