"""Which copy of the app owns what it opened (the owner's decision, 2026-10-17). Every right-click entry
("Verify download…", "Remove metadata…") starts a copy of the app of its own, and quitting one closed
~/TempBrowser under another, a download not saved yet with it (tested on p330). So a RAM disk the app
closes when it quits belongs to the copy that opened it: only that copy closes it then, empties its
TempOutboxes, and an explicit Close… from any copy ends its ownership.

A claim is a token written into the disk itself (TOKEN, at its top, which no sandbox is given) and a lock
held on a file of that token's name in the runtime folder (flock, released by the kernel when the copy
holding it ends, however it ends). A disk closed and opened again has no token, so a copy that owned the
old one owns nothing of the new one. A token whose lock nobody holds is a disk whose owner has ended: the
next copy to show the browser panel takes it over (`claim`), never a copy quitting without having shown it."""

from __future__ import annotations

import errno
import fcntl
import os
import threading
from pathlib import Path

from ..host import Host

TOKEN = ".daprivacyscanner-owner"

_HELD: dict[str, tuple[int, str]] = {}       # disk name -> (lock's descriptor, token)
_LOCK = threading.Lock()


def _locks(host: Host) -> Path:
    runtime = host.environ.get("XDG_RUNTIME_DIR") or ""
    base = Path(runtime) if runtime and os.path.isdir(runtime) else Path(host.environ.get("XDG_CACHE_HOME") or
                                                                         host.home / ".cache")
    d = base / "daprivacyscanner" / "owners"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if d.is_symlink() or d.stat().st_uid != os.getuid():
        raise OSError(errno.EPERM, "the app's folder for its locks isn't its own")
    return d


def _token(path: Path) -> str | None:
    try:
        fd = os.open(path / TOKEN, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        text = os.read(fd, 64).decode("ascii", "replace").strip()
    finally:
        os.close(fd)
    return text if len(text) == 32 and all(c in "0123456789abcdef" for c in text) else None


def _try_lock(host: Host, token: str) -> int | None:
    fd = os.open(_locks(host) / f"{token}.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _drop(host: Host, name: str) -> None:
    fd, token = _HELD.pop(name, (None, None))
    if fd is None:
        return
    try:
        (_locks(host) / f"{token}.lock").unlink(missing_ok=True)
    except OSError:
        pass
    os.close(fd)


def owns(host: Host, name: str, path: Path) -> bool:
    """Whether this copy owns the disk mounted at `path` now (and not an earlier one of that name)."""
    with _LOCK:
        held = _HELD.get(name)
        return held is not None and _token(path) == held[1]


def claim(host: Host, name: str, path: Path) -> bool:
    """This copy owns the disk at `path` once this returns True: it did, or no live copy does (a new disk, or one
    whose owner has ended). False: another copy that is running owns it."""
    with _LOCK:
        held = _HELD.get(name)
        current = _token(path)
        if held is not None and current == held[1]:
            return True
        if held is not None:                            # ours was closed, and this is a disk opened since
            _drop(host, name)
        if current is not None:
            fd = _try_lock(host, current)
            if fd is None:
                return False                            # its owner is running
            _HELD[name] = (fd, current)
            return True
        token = os.urandom(16).hex()
        fd = _try_lock(host, token)
        if fd is None:
            return False
        try:
            out = os.open(path / TOKEN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError:                                 # another copy wrote one meanwhile: theirs
            os.close(fd)
            (_locks(host) / f"{token}.lock").unlink(missing_ok=True)
            return False
        with os.fdopen(out, "w") as f:
            f.write(token + "\n")
        _HELD[name] = (fd, token)
        return True


def release(host: Host, name: str) -> None:
    """Ends this copy's ownership (the disk was closed)."""
    with _LOCK:
        _drop(host, name)


def unmark(path: Path) -> None:
    """The disk at `path` is being closed: its mark goes, so no copy owns it (nor a disk opened there later)."""
    try:
        os.unlink(path / TOKEN)
    except OSError:
        pass


def owner_running(host: Host, path: Path) -> bool:
    """Whether a copy of the app that is running owns the disk at `path` (this one included)."""
    current = _token(path)
    if current is None:
        return False
    with _LOCK:
        if any(token == current for _, token in _HELD.values()):
            return True
    fd = _try_lock(host, current)
    if fd is None:
        return True
    os.close(fd)
    return False


_BUSY: dict[int, str] = {}                  # lock's descriptor -> key, for what this copy holds now


def hold(host: Host, key: str) -> int | None:
    """Work one copy of the app at a time may do (setting a browser up or starting it): the lock's descriptor
    while this copy holds it, None while another does (or this one, in another thread). let_go() ends it; so does
    the copy ending."""
    try:
        fd = os.open(_locks(host) / f"{key}.busy", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return -1                                       # no folder for locks: one copy's own checks still hold
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    with _LOCK:
        _BUSY[fd] = key
    return fd


def let_go(fd: int | None) -> None:
    if fd is not None and fd >= 0:
        with _LOCK:
            _BUSY.pop(fd, None)
        os.close(fd)


def held_here(key: str) -> bool:
    """Whether this copy holds `key` now (a set-up or a start of its own under way)."""
    with _LOCK:
        return key in _BUSY.values()
