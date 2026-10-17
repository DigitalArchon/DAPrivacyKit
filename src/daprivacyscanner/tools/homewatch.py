"""A folder watched for what a program does in it (docs/TECHNICAL.md, Tools: Try an app): the throwaway home a
trial runs with. inotify, as the user, no administrator access: a watch on every folder under the home, added
for each new one as it appears. It records each file opened, read, changed, made, deleted or renamed, in the
records tools/activity.py sums up, and which of the decoy files (tools/bait.py) were listed or opened, with
when.

inotify says what happened to a file, not who did it: nothing else may touch the folder while it is watched
(the app made it for this trial, nobody else knows it is there, and the app itself only looks once the watch
has stopped). A folder made and filled within an instant may be watched a moment late: what is in it by then is
picked up as present, and the walk afterwards (`left`) lists everything that is there at the end, so nothing
written stays unseen; only reads in that instant can be missed. Standard library only (inotify through libc)."""

from __future__ import annotations

import ctypes
import os
import select
import stat
import struct
import threading
import time
from pathlib import Path

from .activity import CREATED, DELETED, DIR, MOVED, OPENED, WRITTEN

IN_ACCESS, IN_MODIFY, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO = 0x1, 0x2, 0x20, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF = 0x100, 0x200, 0x400, 0x800
IN_Q_OVERFLOW, IN_IGNORED = 0x4000, 0x8000
IN_ONLYDIR, IN_DONT_FOLLOW, IN_ISDIR = 0x01000000, 0x02000000, 0x40000000
IN_NONBLOCK, IN_CLOEXEC = 0o4000, 0o2000000
MASK = IN_ACCESS | IN_MODIFY | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_ONLYDIR | IN_DONT_FOLLOW
# a decoy file's own watch: on its inode, so it is seen however it is reached. A folder's watch reports a file by the
# name it was opened under in that folder: a decoy linked (ln) into another folder and read there, or its folder
# renamed first, went unseen (the review of 2026-10-17)
DECOY_MASK = IN_MODIFY | IN_OPEN | IN_MOVE_SELF | IN_DELETE_SELF | IN_DONT_FOLLOW
FILES_MAX = 50000
FOLDERS_MAX = 20000


class WatchError(OSError):
    pass


class HomeWatch:
    """Watches `root` and every folder in it from start() to stop(). `bait`: decoy files and folders by their
    path relative to `root`, each with what it stands for; `ignore`: folders (relative) not to go into."""

    def __init__(self, root: Path, bait: dict[str, str] | None = None, ignore: tuple[str, ...] = ()):
        self.root, self.bait, self.ignore = str(root), dict(bait or {}), ignore
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = -1
        self.wds: dict[int, str] = {}
        self.decoy_wds: dict[int, str] = {}         # a decoy file's own watch -> its relative path (DECOY_MASK)
        self.files: dict[str, list] = {}            # path -> [flags, opens, writes, minutes, last minute]
        self.hits: dict[str, dict] = {}             # a decoy's relative path -> {"listed", "opened", "changed", "first"}
        self.overflow = self.left_out = 0
        self.mine: dict[str, int] = {}              # folders this watch listed itself: that many openings aren't the program's
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.stopping = threading.Event()

    def start(self) -> None:
        self.fd = self.libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise WatchError(ctypes.get_errno(), "inotify isn't available")
        self._watch_tree(self.root, seen=False)
        for rel in self.bait:
            path = os.path.join(self.root, rel)
            if os.path.isfile(path) and not os.path.islink(path):
                wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), DECOY_MASK)
                if wd >= 0:
                    self.decoy_wds[wd] = rel
        self._drain()                                  # its own look through the folders: nothing of the program's yet
        with self.lock:
            self.files.clear()
            self.hits.clear()
            self.mine.clear()
        self.thread = threading.Thread(target=self._run, name="homewatch", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
        if self.fd >= 0:
            self._drain()
            os.close(self.fd)
            self.fd = -1

    # ------------------------------------------------------------------ watching

    def _rel(self, path: str) -> str:
        return path[len(self.root) + 1:] if path != self.root else ""

    def _watch(self, path: str) -> bool:
        if len(self.wds) >= FOLDERS_MAX:
            self.left_out += 1
            return False
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), MASK)
        if wd < 0:
            return False                               # gone again, not a folder, or the user's watch limit
        self.wds[wd] = path
        return True

    def _watch_tree(self, top: str, seen: bool) -> None:
        """Watches `top` and the folders in it. `seen`: it appeared while watching, so what is in it by now is
        recorded as made (it was written before the watch reached it)."""
        stack = [top]
        while stack:
            folder = stack.pop()
            rel = self._rel(folder)
            if rel and any(rel == i or rel.startswith(i + "/") for i in self.ignore):
                continue
            if not self._watch(folder):
                continue
            self.mine[folder] = self.mine.get(folder, 0) + 1
            try:
                with os.scandir(folder) as entries:
                    for e in entries:
                        try:
                            is_dir = e.is_dir(follow_symlinks=False)
                        except OSError:
                            continue
                        if is_dir:
                            stack.append(e.path)
                        if seen:
                            self._note(e.path, CREATED | (DIR if is_dir else WRITTEN))
            except OSError:
                continue

    def _note(self, path: str, flags: int, opened: bool = False, written: bool = False) -> None:
        rel = self._rel(path)
        if any(rel == i or rel.startswith(i + "/") for i in self.ignore):
            return
        with self.lock:
            rec = self.files.get(path)
            if rec is None:
                if len(self.files) >= FILES_MAX:
                    self.left_out += 1
                    return
                rec = self.files[path] = [0, 0, 0, 0, -1]
            if flags & (CREATED | MOVED) and not flags & DELETED:
                rec[0] &= ~DELETED
            rec[0] |= flags
            if opened:
                rec[1] += 1
            if written:
                rec[2] += 1
                minute = int(time.monotonic() // 60)
                if rec[4] != minute:
                    rec[4] = minute
                    rec[3] += 1
            if rel in self.bait:
                own = rel in self.decoy_wds.values()       # its own watch counts its openings (_decoy)
                if flags & DIR:
                    if opened:
                        self._hit(rel)["listed"] += 1
                elif flags & (WRITTEN | DELETED | MOVED):
                    self._hit(rel)["changed"] += 1
                elif opened and not own:
                    self._hit(rel)["opened"] += 1

    def _hit(self, rel: str) -> dict:
        return self.hits.setdefault(rel, {"listed": 0, "opened": 0, "changed": 0, "first": time.time()})

    def _decoy(self, wd: int, mask: int) -> None:
        """An event on a decoy file's own watch: its inode, whatever name or folder it was reached through."""
        rel = self.decoy_wds[wd]
        if mask & IN_IGNORED:
            del self.decoy_wds[wd]
            return
        with self.lock:
            if mask & IN_OPEN:
                self._hit(rel)["opened"] += 1
            if mask & (IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF):
                self._hit(rel)["changed"] += 1

    def _event(self, wd: int, mask: int, name: str) -> None:
        if mask & IN_Q_OVERFLOW:
            self.overflow += 1
            return
        if wd in self.decoy_wds:
            self._decoy(wd, mask)
            return
        folder = self.wds.get(wd)
        if folder is None:
            return
        if mask & IN_IGNORED:
            del self.wds[wd]
            return
        is_dir = bool(mask & IN_ISDIR)
        path = os.path.join(folder, name) if name else folder
        d = DIR if is_dir or not name else 0
        if is_dir and mask & (IN_OPEN | IN_ACCESS):
            # a folder being listed is told twice, by its own watch and by the one on the folder it is in: the
            # first is the one counted, and not when this watch did the listing (a new folder looked through)
            if name:
                return
            if mask & IN_OPEN and self.mine.get(path, 0) > 0:
                self.mine[path] -= 1
                return
            if not mask & IN_OPEN:
                return
        if mask & IN_CREATE:
            self._note(path, CREATED | d)
            if is_dir:
                self._watch_tree(path, seen=True)
        if mask & IN_MOVED_TO:
            self._note(path, MOVED | d, written=not is_dir)
            if is_dir:
                self._watch_tree(path, seen=True)
        if mask & IN_MOVED_FROM:
            self._note(path, DELETED | MOVED | d)
        if mask & IN_DELETE:
            self._note(path, DELETED | d)
        if mask & IN_MODIFY:
            self._note(path, WRITTEN | d, written=True)
        if mask & IN_OPEN:
            self._note(path, OPENED | d, opened=True)
        elif mask & IN_ACCESS and not is_dir:
            self._note(path, OPENED | d)

    def _drain(self) -> None:
        while True:
            try:
                buf = os.read(self.fd, 1 << 16)
            except (BlockingIOError, OSError):
                return
            if not buf:
                return
            i = 0
            while i + 16 <= len(buf):
                wd, mask, _cookie, n = struct.unpack_from("iIII", buf, i)
                name = buf[i + 16:i + 16 + n].split(b"\0", 1)[0]
                self._event(wd, mask, os.fsdecode(name))
                i += 16 + n

    def _run(self) -> None:
        while not self.stopping.is_set():
            try:
                if select.select([self.fd], [], [], 0.5)[0]:
                    self._drain()
            except (OSError, ValueError):
                return

    # ------------------------------------------------------------------ what it saw

    def counts(self) -> dict:
        with self.lock:
            files = [r for r in self.files.values() if not r[0] & DIR]
            made = sum(1 for r in files if r[0] & (CREATED | WRITTEN | MOVED))
            looked = sum(1 for h in self.hits.values() if h["opened"] or h["changed"] or h["listed"])
            return {"files": len(files), "written": made, "decoys": looked, "overflow": self.overflow}

    def records(self) -> list[list]:
        """What happened, for activity.summarise: [path, flags, opens, writes, minutes, ""]. The decoys the
        app didn't change are left out (they are the trial's, not the app's)."""
        with self.lock:
            out = []
            for path, r in self.files.items():
                if self._rel(path) in self.bait and not r[0] & (WRITTEN | DELETED | MOVED | CREATED):
                    continue
                out.append([path, r[0], r[1], r[2], r[3], ""])
            return out

    def decoys(self) -> list[dict]:
        """The decoys the program looked at: {"path", "what", "listed", "opened", "changed", "first"}, files
        opened or changed first."""
        with self.lock:
            out = [{"path": "~/" + rel, "what": self.bait[rel], **h} for rel, h in self.hits.items()
                   if h["listed"] or h["opened"] or h["changed"]]
        return sorted(out, key=lambda d: (not (d["opened"] or d["changed"]), d["first"]))


def left(root: Path, bait: dict[str, str] | None = None, ignore: tuple[str, ...] = (), limit: int = FILES_MAX) -> dict:
    """What is in the folder now that isn't an untouched decoy: {"files", "bytes", "folders"}. Only looks at names and
    sizes (run it once the watch has stopped: opening the folders would count as listing them)."""
    bait = bait or {}
    own = {str(parent) for rel in bait for parent in Path(rel).parents}      # the decoys' own folders
    files = size = folders = 0
    stack, base = [str(root)], str(root)
    while stack and files < limit:
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            rel = e.path[len(base) + 1:]
            if any(rel == i or rel.startswith(i + "/") for i in ignore):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(e.path)
                folders += rel not in bait and rel not in own
            elif rel not in bait:
                files += 1
                size += st.st_size if stat.S_ISREG(st.st_mode) else 0
    return {"files": files, "bytes": size, "folders": folders}
