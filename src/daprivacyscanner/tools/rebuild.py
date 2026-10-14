"""Clearing the names of deleted files from ext4 folders (docs/TECHNICAL.md, Tools; names.py lists them).

Done as the user, on folders the list showed that are the user's own; the helper only reads (each
folder again between rounds of fillers, then the folders, the blocks they had and the journal's copies
of them) and trims. Nothing is kept: no undo log entry (entries are moved, not changed, so there is
nothing to put back), no paths written anywhere.

Rebuilding a folder: a new folder beside it with the same permissions, group, access control lists,
extended attributes and attribute flags; every entry renamed into it (the same filesystem, so nothing
is copied; links, hard links and special files move the same way); the two swapped in one step
(renameat2 RENAME_EXCHANGE, so the path never goes missing) and the old one, now empty, removed. Its
blocks, the deleted names in them included, become free space, which fstrim then trims. Refused while
any program has something in it open (holders: "Close X first"), with a socket in it (a program
listens there), or when it is immutable. Watchers (sync clients, file managers, indexers) follow the
old folder and lose track until they look again.

Fillers, the default for a small folder (one block of entries, not indexed) and for folders that
can't be renamed (the home itself, a disk's top folder, one with a disk mounted in it) or where TRIM
never reaches the drive: ext4 puts a new entry in the first gap that fits from the start of a block
(in an indexed folder, in the block its name's hash picks), so empty files with names of the same
length as the deleted ones (underscores and a counter) are created a round at a time, and after each
round the helper reads the folder's blocks again, until the deleted names are gone or the cap is
reached; then the files are deleted. Their names stay where the deleted ones were, and the list says
what they are. The folder stays the same folder (its inode): a sync client, backup or index that
wasn't running sees nothing changed but its date, where a rebuilt folder is a new one at the same
path. Fillers write over the names in place, so they don't depend on TRIM either. A large (indexed)
folder is rebuilt, since fillers there may not reach every name; so is one the user asks to rebuild
after fillers left names.

Before either, the programs watching the folder (inotify or fanotify marks on it, from
/proc/PID/fdinfo) are named: file managers, desktops and indexers only in a note; anything else stops
it ("Quit X first"), since a program that syncs, backs up or acts on what it watches (a systemd path
unit, a sync client the app doesn't recognise) would see the fillers come and go, or the folder
replaced. A rebuild is also refused while another program has the folder bind-mounted in a view of
its own (a Flatpak app given that folder, a container): it would keep the old, removed folder."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..checks._util import children, holders, open_files
from ..host import Host
from . import names as N
from . import trimtest as T

FILLERS_MAX = 4000                          # files written into one folder at most
FILLER_ROUNDS = 60
RENAME_NOREPLACE, RENAME_EXCHANGE = 1, 2
FS_IOC_GETFLAGS, FS_IOC_SETFLAGS = 0x80086601, 0x40086602
FS_IMMUTABLE_FL, FS_APPEND_FL, FS_INDEX_FL, FS_CASEFOLD_FL = 0x10, 0x20, 0x1000, 0x40000000
# attribute flags a folder's owner may set, copied to the rebuilt folder: sync, compression, nodump,
# noatime, nocompress, journal data, dirsync, topdir, nocow, project inherit, casefold
COPIED_FLAGS = 0x8 | 0x4 | 0x40 | 0x80 | 0x400 | 0x4000 | 0x10000 | 0x20000 | 0x800000 | 0x20000000 | FS_CASEFOLD_FL
CHECK_TIMEOUT = 600
FSTRIM_TIMEOUT = 900


class Refused(Exception):
    """This folder can't be done now (the reason is for the user)."""


class Incomplete(Exception):
    """A rebuild that stopped part-way and left entries in a second folder beside the first: nothing
    was lost, but they have to be moved back. `folder` is that folder's name, in the same parent."""

    def __init__(self, reason: str, folder: str, count: int):
        super().__init__(reason)
        self.reason, self.folder, self.count = reason, folder, count


# programs that watch folders only to show or index them: named in a note, never a reason to stop
QUIET_WATCHERS = frozenset({
    "nemo", "nemo-desktop", "nautilus", "nautilus-deskto", "dolphin", "caja", "thunar", "pcmanfm", "pcmanfm-qt",
    "spacefm", "konqueror", "gnome-shell", "plasmashell", "cinnamon", "xfdesktop", "kded5", "kded6", "kiod5", "kiod6",
    "kioworker", "xdg-desktop-por", "xdg-document-po", "gvfsd-metadata", "tracker-miner-f", "localsearch-3",
    "baloo_file", "gsd-housekeepin", "csd-housekeepin", "gnome-software"})
WATCH_MARK = re.compile(r"\bino:([0-9a-f]+) sdev:([0-9a-f]+)")


def _user_pids(host: Host) -> list[Path]:
    out = []
    for p in children(host.sys_path("/proc")):
        if not p.name.isdigit():
            continue
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def _comm(p: Path) -> str:
    try:
        return (p / "comm").read_text().strip() or p.name
    except OSError:
        return p.name


def watchers(host: Host, path: Path) -> list[str]:
    """This user's programs with an inotify or fanotify mark on the folder itself (the kernel's
    fdinfo gives the watched inode and its filesystem's device, MAJOR << 20 | MINOR)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return []
    want = (st.st_ino, os.major(st.st_dev), os.minor(st.st_dev))
    out = set()
    for p in _user_pids(host):
        try:
            fds = os.listdir(p / "fd")
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(p / "fd" / fd) not in ("anon_inode:inotify", "anon_inode:[fanotify]"):
                    continue
                info = (p / "fdinfo" / fd).read_text()
            except OSError:
                continue
            for m in WATCH_MARK.finditer(info):
                dev = int(m.group(2), 16)
                if (int(m.group(1), 16), dev >> 20, dev & 0xFFFFF) == want:
                    out.add(_comm(p))
    return sorted(out)


def _mountinfo(text: str) -> list[tuple[str, str, str]]:
    """(major:minor, root inside the filesystem, mount point) of each line, \040-style escapes undone."""
    unesc = lambda x: re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), x)  # noqa: E731
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) > 4:
            out.append((f[2], unesc(f[3]), unesc(f[4])))
    return out


def bind_users(host: Host, path: Path) -> list[str]:
    """Programs that have this folder (or something in it) mounted in a view of the files of their
    own (another mount namespace: a Flatpak app given the folder, a container), and other places it
    is mounted in this view. After a rebuild those would still show the old, removed folder."""
    try:
        st = os.stat(path, follow_symlinks=False)
        own = _mountinfo(host.sys_path("/proc/self/mountinfo").read_text())
        own_ns = os.readlink(host.sys_path("/proc/self/ns/mnt"))
    except OSError:
        return []
    dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    shown = T.logical(host, path).rstrip("/")
    best = max(((r, mp) for d, r, mp in own if d == dev and (shown == mp or shown.startswith(mp.rstrip("/") + "/"))),
               key=lambda x: len(x[1]), default=None)
    if best is None:
        return []
    root, mp = best
    rel = (root.rstrip("/") + "/" + shown[len(mp):].lstrip("/")).rstrip("/") or "/"
    inside = lambda r: r == rel or r.startswith(rel + "/")  # noqa: E731
    out, seen_ns = set(), {own_ns}
    for d, r, m in own:
        if d == dev and inside(r) and m != shown:
            out.add(f"a mount at {m}")
    for p in _user_pids(host):
        try:
            ns = os.readlink(p / "ns" / "mnt")
            if ns in seen_ns:
                continue
            seen_ns.add(ns)
            lines = _mountinfo((p / "mountinfo").read_text())
        except OSError:
            continue
        if any(d == dev and inside(r) for d, r, _ in lines):
            out.add(_comm(p))
    return sorted(out)


class _Procs:
    """What holders() needs: this user's processes' open files, read once."""

    def __init__(self, host: Host):
        self.host, self._files = host, None

    def open_files(self):
        if self._files is None:
            self._files = open_files(self.host)
        return self._files


# ------------------------------------------------------------------ the plan (the dry run)

@dataclass
class Item:
    rel: str
    path: Path
    display: str
    method: str                             # rebuild, fillers, none
    why: str = ""
    blockers: list[str] = field(default_factory=list)
    entries: int = 0
    indexed: bool = False
    synced: str = ""
    watching: list[str] = field(default_factory=list)      # file managers and indexers watching it

    def to_dict(self) -> dict:
        return {"rel": self.rel, "path": self.display, "method": self.method, "why": self.why,
                "blockers": self.blockers, "entries": self.entries, "indexed": self.indexed, "synced": self.synced,
                "watching": self.watching}


def listing(host: Host, mount: str) -> tuple[dict, dict]:
    """The target, and what view()/remedy() need of a listing, for the filesystem at `mount`."""
    t = N.target(host, mount)
    if t is None or t["blocked"]:
        raise Refused(t["blocked"] if t else "The names on that filesystem can't be listed.")
    if t["fstype"] != "ext4":
        raise Refused("Folders are cleaned only on ext4; on btrfs, trimming is what clears the names.")
    return t, {"scope": t["scope"], "root": mount}


def _flags(fd: int) -> int:
    buf = bytearray(8)
    try:
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
    except OSError:
        return 0
    return int.from_bytes(buf[:4], sys.byteorder)


def open_folder(top: Path, rel: str) -> tuple[int | None, int]:
    """(its parent, the folder) opened one name at a time from `top`, never through a link; the
    parent is None for `top` itself."""
    parent, fd = None, os.open(top, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in [x for x in rel.split("/") if x]:
            if part in (".", ".."):
                raise Refused("That isn't a folder in the list.")
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            if parent is not None:
                os.close(parent)
            parent, fd = fd, nfd
    except OSError:
        for x in (parent, fd):
            if x is not None:
                os.close(x)
        raise Refused("It isn't there any more, or something on the way to it is a link.") from None
    return parent, fd


def item(host: Host, t: dict, r: dict, rel: str, procs: _Procs, seen: N.Seen, prefer: str = "") -> Item:
    top = N.top_of(host, r)
    path = top / rel if rel else top
    shown = ("~" if r["scope"] == "home" else r["root"].rstrip("/")) + (f"/{rel}" if rel else "")
    rem = N.remedy(host, t, r, rel, seen, prefer)
    it = Item(rel, path, shown, rem["method"], rem["why"], synced=rem.get("synced", ""))
    if it.method == "none":
        it.blockers.append(rem["why"])
        return it
    try:
        parent, fd = open_folder(top, rel)
    except Refused as e:
        it.blockers.append(str(e))
        return it
    try:
        st = os.fstat(fd)
        flags = _flags(fd)
        it.indexed = bool(flags & FS_INDEX_FL)
        entries = os.listdir(fd)
        it.entries = len(entries)
        if st.st_uid != host.uid:
            it.blockers.append("It isn't your folder.")
        if flags & (FS_IMMUTABLE_FL | FS_APPEND_FL):
            it.blockers.append("It is marked immutable or append-only (chattr), so nothing in it can be changed.")
        if not os.access(".", os.W_OK | os.X_OK, dir_fd=fd):
            it.blockers.append("You can't write to it.")
        if it.method == "rebuild":
            if parent is None or not os.access(".", os.W_OK | os.X_OK, dir_fd=parent):
                it.blockers.append("You can't create a folder beside it.")
            users = sorted(holders(procs, path))
            if users:
                it.blockers.append(f"Close {', '.join(users)} first: {'it is' if len(users) == 1 else 'they are'} using "
                                   "files in it, and moving them out from under a running program can break it.")
            if any(stat.S_ISSOCK(os.lstat(path / e).st_mode) for e in entries):
                it.blockers.append("A program listens on a socket in it, so it is left alone.")
            binds = bind_users(host, path)
            if binds:
                it.blockers.append(f"It is also mounted in another view of your files ({', '.join(binds)}): after a "
                                   "rebuild that would still show the old, removed folder. Close it first.")
        watching = watchers(host, path)
        loud = [w for w in watching if w not in QUIET_WATCHERS]
        it.watching = [w for w in watching if w in QUIET_WATCHERS]
        if loud:
            what = ("would see the fillers being made and deleted, and could upload them or act on them"
                    if it.method == "fillers" else "would see the folder disappear and a new one appear")
            it.blockers.append(f"Quit {', '.join(loud)} first: {'it is' if len(loud) == 1 else 'they are'} watching this "
                               f"folder. A program that syncs, backs up or acts on what it watches {what}.")
    except OSError as e:
        it.blockers.append(f"It couldn't be read: {e.strerror or e}.")
    finally:
        for x in (parent, fd):
            if x is not None:
                os.close(x)
    return it


def plan(host: Host, mount: str, rels: list[str], rebuild_rels: list[str] = ()) -> dict:
    """What cleaning these folders would do, for this machine as it is now: each folder's method
    and what stops it, the steps, and what it does and doesn't reach. `rebuild_rels`: folders the
    user asked to rebuild (fillers left names). Changes nothing."""
    t, r = listing(host, mount)
    procs, seen = _Procs(host), N.Seen(host)
    items = [item(host, t, r, rel, procs, seen, "rebuild" if rel in rebuild_rels else "") for rel in dict.fromkeys(rels)]
    ok = [i for i in items if not i.blockers]
    steps = []
    for i in ok:
        if i.method == "rebuild":
            steps.append(f"Rebuild {i.display}: make a new folder beside it with the same permissions, group, access "
                         f"control lists and extended attributes, move its {i.entries} "
                         f"{'entry' if i.entries == 1 else 'entries'} into it (renamed: nothing is copied), swap the two "
                         "in one step and remove the old one, now empty.")
        else:
            steps.append(f"Fillers in {i.display}: write empty files named with underscores and a number, as long as the "
                         "deleted names, a round at a time, reading the folder's records after each round, until the "
                         f"deleted names' places are taken (at most {FILLERS_MAX} files); then delete them.")
    trims = t["no_trim"] not in ("hdd", "layer")
    if ok and trims:
        steps.append(f"Trim the free space of {t['mount']} (fstrim, as administrator, as the weekly timer does).")
    if ok:
        steps.append("Read the folders, the records they had and the journal's copies of them again for the names, and "
                     "show what is left.")
    effects = []
    if any(i.method == "rebuild" for i in ok):
        effects.append("A rebuilt folder is a new folder at the same place: programs that watch folders (sync clients, "
                       "file managers, search indexers) may lose track of it until they look again, and an open file "
                       "manager window may need refreshing. The temporary name it had (.name.rebuild-…) stays in the "
                       "folder above as a deleted name, and the list says so when it shows it.")
    if any(i.method == "fillers" for i in ok):
        effects.append("Files appear in the folder for a moment and are deleted again; file managers and indexers may "
                       "notice them. Their names (such as ___12) then stay where the deleted names were, and the list "
                       "says so when it shows them. A sync client or backup that isn't running meanwhile sees nothing "
                       "of them: the folder is the same folder afterwards.")
    quiet = sorted({w for i in ok for w in i.watching})
    if quiet:
        effects.append(f"Watching {'this folder' if len(ok) == 1 else 'these folders'} now: {', '.join(quiet)} (file "
                       "managers, the desktop, search indexers). They see the change; an indexer may record the "
                       "fillers' names, which hold nothing.")
        if any(i.indexed for i in ok if i.method == "fillers"):
            effects.append("In a large folder (an indexed one) a file's place depends on a hash of its name, so it can "
                           "take many files to reach every deleted name, and some may stay when the cap is reached.")
    if not trims and ok:
        effects.append({"hdd": "This is a hard disk: there is no TRIM, so what is freed stays readable until it is "
                               "overwritten.",
                        "layer": "TRIM doesn't reach this drive, so what is freed stays readable until it is "
                                 "overwritten."}[t["no_trim"]])
    if ok:
        effects.append("What it doesn't reach: copies in the journal (the check afterwards reads them, and Clear "
                       "the journal removes them); "
                       "the deleted files' own records (sizes and times, until reused); the flash chips themselves; "
                       "snapshots (LVM); and names recorded elsewhere: recent files, thumbnails, search indexes, shell "
                       "history, the trash, backups.")
        effects.append("Nothing is kept: it isn't in History and can't be undone, but nothing needs undoing (entries "
                       "are moved, not changed).")
    return {"mount": t["mount"], "folders": [i.to_dict() for i in items], "steps": steps, "side_effects": effects,
            "needs_root": bool(ok), "trims": trims, "ask_synced": any(not i.synced for i in ok)}


# ------------------------------------------------------------------ rebuilding a folder

def _renameat2(src: int, a: str, dst: int, b: str, flags: int) -> bool:
    """renameat2(2); False where the C library or the filesystem doesn't have it (or that flag)."""
    try:
        fn = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        return False
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if fn(src, os.fsencode(a), dst, os.fsencode(b), flags) == 0:
        return True
    e = ctypes.get_errno()
    if e in (errno.ENOSYS, errno.EINVAL):
        return False
    raise OSError(e, os.strerror(e), a)


def _exchange(parent: int, a: str, b: str) -> bool:
    """Swaps two names in one step (renameat2 RENAME_EXCHANGE); False where it isn't available."""
    return _renameat2(parent, a, parent, b, RENAME_EXCHANGE)


def _move(src: int, name: str, dst: int) -> None:
    """Renames `name` from folder `src` into folder `dst`, never over an entry already there: a file
    a program saved meanwhile must not be replaced by an older one (FileExistsError instead)."""
    if _renameat2(src, name, dst, name, RENAME_NOREPLACE):
        return
    try:                                         # no RENAME_NOREPLACE: look first (a narrow race, not a blind replace)
        os.lstat(name, dir_fd=dst)
    except FileNotFoundError:
        os.rename(name, name, src_dir_fd=src, dst_dir_fd=dst)
        return
    raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), name)


EXCHANGE = _exchange                           # tests replace them
MOVE = _move


def _move_all(src: int, dst: int) -> int:
    """Renames every entry of `src` into `dst`, until `src` stays empty. Returns how many. An entry
    whose name is already taken in `dst` stops it (FileExistsError): nothing is replaced."""
    moved = 0
    for _ in range(5):
        names = os.listdir(src)
        if not names:
            return moved
        for n in names:
            MOVE(src, n, dst)
            moved += 1
    if os.listdir(src):
        raise OSError(errno.EBUSY, "entries keep appearing in it")
    return moved


def _why(e: BaseException) -> str:
    if isinstance(e, FileExistsError):
        return f"a program created {e.filename or 'an entry'} in it meanwhile"
    return e.strerror if isinstance(e, OSError) and e.strerror else str(e) or type(e).__name__


def _entries(parent: int, name: str) -> int:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except OSError:
        return 0
    try:
        return len(os.listdir(fd))
    finally:
        os.close(fd)


def _prepare(old: int, new: int, st: os.stat_result) -> list[str]:
    """Before the moves: the group, and the attribute flags (casefolding can only be set on an empty
    folder). Raises Refused where a difference would matter; returns notes for the rest."""
    notes = []
    if os.fstat(new).st_gid != st.st_gid:
        try:
            os.fchown(new, -1, st.st_gid)
        except OSError:
            raise Refused("its group couldn't be given to the new folder") from None
    want = _flags(old) & COPIED_FLAGS
    if want & ~_flags(new):
        try:
            fcntl.ioctl(new, FS_IOC_SETFLAGS, (_flags(new) | want).to_bytes(8, sys.byteorder))
        except OSError:
            if want & FS_CASEFOLD_FL:
                raise Refused("it ignores the case of names (casefold), which the new folder couldn't be set to do") \
                    from None
            notes.append("its attribute flags (chattr) couldn't all be copied")
    return notes


def _finish(old: int, new: int, st: os.stat_result) -> list[str]:
    """After the moves (so a mode without write for its owner can't stop them): the permission
    bits, then the extended attributes, access control lists among them, and none it didn't have (a
    default ACL of the folder above is inherited at mkdir). Raises Refused where a difference would
    matter (ACLs, the mode); returns notes for the rest."""
    notes = []
    os.fchmod(new, stat.S_IMODE(st.st_mode))
    had = set(os.listxattr(old))
    for name in set(os.listxattr(new)) - had:
        try:
            os.removexattr(new, name)
        except OSError:
            if name.startswith("system.posix_acl"):
                raise Refused("the new folder took an access control list from the folder above that couldn't be "
                              "removed") from None
    for name in sorted(had):
        try:
            os.setxattr(new, name, os.getxattr(old, name))
        except OSError:
            if name.startswith("system.posix_acl"):
                raise Refused("its access control list couldn't be copied") from None
            notes.append(f"the extended attribute {name} couldn't be copied")
    if stat.S_IMODE(os.fstat(new).st_mode) != stat.S_IMODE(st.st_mode):
        raise Refused("its permissions couldn't be given to the new folder")
    return notes


def rebuild(top: Path, rel: str) -> dict:
    """Rebuilds the folder at `rel` under `top` (see the module docstring). Returns {"moved", "notes"}.
    On a failure before the swap, everything is moved back and the new folder removed. Where that
    can't be done, or something fails after the swap, entries left in the second folder raise
    Incomplete, which names it: no entry is ever replaced or deleted."""
    parent, old = open_folder(top, rel)
    if parent is None:
        os.close(old)
        raise Refused("That folder can't be rebuilt.")
    name = rel.rsplit("/", 1)[-1]
    tag = secrets.token_hex(4)
    tmp = f".{name}.rebuild-{tag}" if len(os.fsencode(name)) <= 230 else f".rebuild-{tag}"
    try:
        st = os.fstat(old)
        if st.st_uid != os.geteuid() or _flags(old) & (FS_IMMUTABLE_FL | FS_APPEND_FL):
            raise Refused("That folder can't be rebuilt.")
        os.mkdir(tmp, 0o700, dir_fd=parent)
        new = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        moved = 0
        try:
            notes = _prepare(old, new, st)
            moved = _move_all(old, new)
            notes += _finish(old, new, st)
            os.fsync(new)
        except BaseException as e:
            back = None                          # why moving the entries back stopped, if it did
            try:
                _move_all(new, old)
                os.rmdir(tmp, dir_fd=parent)
            except OSError as b:
                back = b
            count = _entries(parent, tmp)
            if count:
                raise Incomplete(_why(e) + (f"; moving its entries back, {_why(back)}" if back else ""), tmp, count) from e
            raise
        finally:
            os.close(new)
        if EXCHANGE(parent, name, tmp):
            gone = tmp
        else:                                    # no RENAME_EXCHANGE: the name is missing for a moment
            gone = f".{tmp}-old" if len(os.fsencode(tmp)) < 250 else f".old-{tag}"
            os.rename(name, gone, src_dir_fd=parent, dst_dir_fd=parent)
            try:
                os.rename(tmp, name, src_dir_fd=parent, dst_dir_fd=parent)
            except OSError as e:                 # put the old one back where it was
                os.rename(gone, name, src_dir_fd=parent, dst_dir_fd=parent)
                raise Incomplete(_why(e), tmp, _entries(parent, tmp)) from e
        # anything created in the old folder after the moves follows into the new one
        try:
            left = os.open(gone, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                now = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    moved += _move_all(left, now)
                    os.fsync(now)
                finally:
                    os.close(now)
            finally:
                os.close(left)
            os.rmdir(gone, dir_fd=parent)
        except OSError as e:
            raise Incomplete(_why(e), gone, _entries(parent, gone)) from e
        os.utime(name, ns=(st.st_atime_ns, st.st_mtime_ns), dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
        return {"moved": moved, "notes": notes}
    finally:
        os.close(old)
        os.close(parent)


# ------------------------------------------------------------------ fillers

def filler_names(length: int):
    """The names fillers of this length take, in order: underscores, then a counter ("____",
    "___0" ... "___9", "__10" ...). Recognisable afterwards (FILLER in names.py) and saying nothing;
    in an indexed folder each lands where its name's hash puts it, which the counter varies."""
    yield "_" * length
    i = 0
    while len(str(i)) < length:
        yield "_" * (length - len(str(i))) + str(i)
        i += 1


def fillers(top: Path, rel: str, left: list[str], recheck: Callable[[], list[str]],
            cancelled: Callable[[], bool] = lambda: False) -> dict:
    """Writes fillers into the folder until the names in `left` are gone from its records
    (`recheck` reads them again through the helper) or the cap is reached, then deletes them.
    Returns {"written", "rounds", "left"}."""
    parent, fd = open_folder(top, rel)
    if parent is not None:
        os.close(parent)
    made: list[str] = []
    rounds = 0
    pools: dict[int, object] = {}
    try:
        def make(length: int) -> str | None:
            for f in pools.setdefault(length, filler_names(length)):
                try:
                    os.close(os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                     dir_fd=fd))
                    return f
                except FileExistsError:
                    continue                     # a file of the user's has that name: the next one
            return None
        while left and len(made) < FILLERS_MAX and rounds < FILLER_ROUNDS:
            if cancelled():
                break
            for n in left:
                if len(made) >= FILLERS_MAX:
                    break
                f = make(len(os.fsencode(n)))
                if f is not None:
                    made.append(f)
            os.fsync(fd)
            os.sync()                            # the folder's blocks home, so the helper reads what is there now
            rounds += 1
            left = recheck()
    finally:
        for f in made:
            try:
                os.unlink(f, dir_fd=fd)
            except FileNotFoundError:
                pass
        os.fsync(fd)
        os.close(fd)
        os.sync()
    return {"written": len(made), "rounds": rounds, "left": left}


# ------------------------------------------------------------------ the whole clean-up

def run(host: Host, mount: str, rels: list[str], privileged: Callable[[], object | None], job: dict,
        rebuild_rels: list[str] = ()) -> dict:
    """Cleans the folders `rels` (those the plan allows now), trims, and checks; `job` is updated
    as it goes (steps, phase) and its "cancel" stops it between folders and rounds."""
    t, r = listing(host, mount)
    top = N.top_of(host, r)
    procs, seen = _Procs(host), N.Seen(host)
    items = [item(host, t, r, rel, procs, seen, "rebuild" if rel in rebuild_rels else "") for rel in dict.fromkeys(rels)]
    todo = [i for i in items if not i.blockers]
    trims = t["no_trim"] not in ("hdd", "layer")
    job["steps"] = steps = (
        [{"id": f"f{n}", "label": f"{'Rebuilding' if i.method == 'rebuild' else 'Fillers in'} {i.display}",
          "state": "pending", "started": None, "finished": None} for n, i in enumerate(todo)]
        + ([{"id": "trim", "label": f"Trimming {t['mount']}", "state": "pending", "started": None, "finished": None}]
           if trims and todo else [])
        + ([{"id": "check", "label": "Reading the folders, their old records and the journal again", "state": "pending",
             "started": None, "finished": None}] if todo else []))
    by_id = {s["id"]: s for s in steps}

    def helper():
        h = privileged()
        if h is None:
            raise N.Stopped("Administrator access ended, so it stopped.")
        return h

    def begin(sid: str) -> None:
        now = time.time()
        for s in steps:
            if s["state"] == "running":
                s.update(state="done", finished=now)
        by_id[sid].update(state="running", started=now)
        job["phase"] = by_id[sid]["label"]

    done: list[dict] = [{"path": i.display, "rel": i.rel, "method": i.method, "skipped": " ".join(i.blockers)}
                        for i in items if i.blockers]
    treated = []
    try:
        for n, i in enumerate(todo):
            if job.get("cancel"):
                raise N.Stopped("Stopped.")
            begin(f"f{n}")
            out = {"path": i.display, "rel": i.rel, "method": i.method}
            try:
                if i.method == "rebuild":
                    try:
                        out.update(rebuild(top, i.rel))
                    except Incomplete as e:
                        above = i.display.rsplit("/", 1)[0] if "/" in i.display else i.display
                        out.update(error=e.reason, leftover=f"{above}/{e.folder}", leftover_count=e.count)
                else:
                    first = helper().call("names_folder", {"path": i.rel}, CHECK_TIMEOUT)["left"]
                    out.update(fillers(top, i.rel, first,
                                       lambda rel=i.rel: helper().call("names_folder", {"path": rel}, CHECK_TIMEOUT)["left"],
                                       lambda: bool(job.get("cancel"))))
                    out["listed_left"] = len(first)
                    # fillers that left names: a rebuild reaches them, where one is possible here
                    out["can_rebuild"] = bool(out["left"]) and \
                        N.remedy(host, t, r, i.rel, seen, "rebuild")["method"] == "rebuild"
                treated.append(i.rel)
            except Refused as e:
                out["error"] = str(e)
            except OSError as e:
                out["error"] = f"{e.strerror or e}"
            done.append(out)
        os.sync()
        trimmed = None
        if treated and trims:
            begin("trim")
            trimmed = helper().call("names_fstrim", {"mount": t["mount"]}, FSTRIM_TIMEOUT).get("trimmed")
        check = None
        if treated:
            begin("check")
            check = helper().call("names_check", {"paths": treated}, CHECK_TIMEOUT)
        return result(t, done, check, trimmed, trims)
    finally:
        for s in steps:
            if s["state"] == "running":
                s.update(state="done", finished=time.time())


def recheck(host: Host, mount: str, rels: list[str], privileged: Callable[[], object | None]) -> dict:
    """Reads the folders cleaned before, the records they had and the journal again (helper.names_check):
    the journal's copies go as it wraps."""
    t, r = listing(host, mount)
    h = privileged()
    if h is None:
        raise N.Stopped("Administrator access ended: list the names again first.")
    check = h.call("names_check", {"paths": list(dict.fromkeys(rels))}, CHECK_TIMEOUT)
    shown = "~" if r["scope"] == "home" else r["root"].rstrip("/")
    done = [{"path": shown + (f"/{c['path']}" if c["path"] else ""), "rel": c["path"], "method": "check"}
            for c in check["folders"]]
    return result(t, done, check, None, t["no_trim"] not in ("hdd", "layer"))


def _shell(shown: str) -> str:
    """A path as the page shows it (~/...) quoted for a shell, the ~ left outside the quotes."""
    import shlex
    return "~/" + shlex.quote(shown[2:]) if shown.startswith("~/") else shlex.quote(shown)


def _leftover_commands(leftover: str, folder: str, count: int) -> list[str]:
    src, dst = _shell(leftover), _shell(folder)
    return ([f"find {src} -mindepth 1 -maxdepth 1 -exec mv -n -t {dst} {{}} +"] if count else []) + [f"rmdir {src}"]


def result(t: dict, done: list[dict], check: dict | None, trimmed: int | None, trims: bool) -> dict:
    by_rel = {c["path"]: c for c in (check or {}).get("folders", [])}
    folders = []
    for d in done:
        c = by_rel.get(d["rel"])
        f = {"path": d["path"], "rel": d["rel"], "method": d["method"]}
        if d.get("skipped"):
            f["state"], f["text"] = "skipped", d["skipped"]
        elif d.get("leftover"):
            n = d["leftover_count"]
            f["state"] = "failed"
            f["text"] = (f"It stopped part-way ({d['error']}). Nothing was deleted or replaced, but "
                         + (f"{n} of its {'entry is' if n == 1 else 'entries are'} in {d['leftover']}, beside it: move "
                            f"{'it' if n == 1 else 'them'} back, then remove that folder (the commands below don't "
                            "replace anything of the same name)." if n else
                            f"an empty folder, {d['leftover']}, was left beside it: remove it."))
            f["commands"] = _leftover_commands(d["leftover"], d["path"], n)
        elif d.get("error"):
            f["state"], f["text"] = "failed", f"It couldn't be done: {d['error']}. Nothing in it was lost: its entries are " \
                                              "where they were."
        else:
            f["state"] = "done" if c is not None and not c["left"] else "partly"
            bits = []
            if d["method"] == "rebuild":
                bits.append(f"Rebuilt ({d['moved']} {'entry' if d['moved'] == 1 else 'entries'} moved).")
            elif d["method"] == "fillers":
                bits.append(f"{d['written']} fillers written in {d['rounds']} "
                            f"{'round' if d['rounds'] == 1 else 'rounds'}, then deleted.")
            if d.get("notes"):
                bits.append("Not copied: " + "; ".join(d["notes"]) + ".")
            if d.get("can_rebuild") and c is not None and c["folder"]:
                f["rebuild_offer"] = True
                bits.append("Fillers couldn't reach every place in this folder: Rebuild instead moves every entry into a "
                            "new folder, which leaves none of its old records in it.")
            if c is not None:
                f.update(folder=c["folder"], freed=c["freed"], journal=c["journal"], left=c["left"], listed=c["listed"])
                if not c["left"]:
                    bits.append("None of its deleted names can be read any more, in the folder, in the records it had, "
                                "or in the journal.")
                else:
                    where = [x for x, k in (("in the folder's records", "folder"),
                                            ("in the records it had, which aren't trimmed yet", "freed"),
                                            ("in the journal", "journal")) if c[k]]
                    bits.append(f"{len(c['left'])} of its {c['listed']} deleted names can still be read: "
                                + ", ".join(where) + ".")
            f["text"] = " ".join(bits)
        folders.append(f)
    explanation = []
    journal = (check or {}).get("journal")
    if any(f.get("journal") for f in folders):
        explanation.append("The journal keeps copies of folders' records until it wraps, which takes minutes to hours on "
                           "a busy system and longer on an idle one. Clear the journal removes them now, where this "
                           "kernel can (Linux 5.14 and later); otherwise check again later: they go as new changes are "
                           "written over them.")
    if journal in ("unknown", "external"):
        explanation.append("The journal couldn't be read" + (" (it is on another device)" if journal == "external" else "")
                           + ", so copies of the names in it couldn't be looked for. It wraps on its own, from minutes "
                           "to hours.")
    if any(f.get("freed") for f in folders):
        explanation.append("The records a rebuilt folder had are free space now, but still readable"
                           + (": TRIM didn't clear them. The TRIM test shows whether this drive drops what is trimmed."
                              if trims else ": TRIM doesn't reach this drive, so they stay until something overwrites "
                                            "them."))
    if not trims:
        explanation.append({"hdd": "This is a hard disk: there is no TRIM.",
                            "layer": "TRIM doesn't reach this drive."}.get(t["no_trim"], ""))
    if (check or {}).get("unreadable"):
        explanation.append("The drive couldn't read some parts of the disk (failing sectors, usually): names in them "
                           "couldn't be looked for. Back the drive up and check its health (smartctl -a).")
    explanation.append("Encryption is what protects names from someone with the disk: "
                       + ("this disk is encrypted." if t["encrypted"] else "this disk isn't encrypted."))
    return {"folders": folders, "trimmed": trimmed, "journal": journal, "explanation": [e for e in explanation if e],
            "mount": t["mount"], "finished": time.time()}
