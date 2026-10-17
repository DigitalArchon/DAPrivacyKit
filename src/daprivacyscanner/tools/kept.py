"""Kept downloads of Tor Browser and Mullvad Browser (the owner's request, 2026-10-17): when the user ticks it, a
downloaded archive and its signature stay in the app's cache folder, so the next set-up needn't download them again.

Only after the download was verified and unpacked: the archive is copied from the verified file in ~/TempBrowser
(never fetched again) into a folder beside the kept one, verified there once more, and only then put in place of the
older copy. One kept copy per browser. Setting up from it is setting up from an archive the user picked: it is copied
into ~/TempBrowser first, the project's index is asked whether it is the latest (refused when a newer one is out),
its signature is checked with the app's own keys, the version inside it against its name, and where the index can't
be reached it is accepted only when its signature is recent (browser.accept_unchecked).

Kept copies are on the disk, in $XDG_CACHE_HOME/daprivacyscanner/browsers (0700, files 0600): they tell anyone who
looks at the computer that the browser was set up here (nothing of the browsing is in them), and deleting them
doesn't erase them from the disk (rule 8). The page says both before anything is kept. They aren't in History,
reports or exports; packaging/uninstall.sh removes the folder."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Callable

from ..host import Host

FOLDER = "browsers"                     # in the app's cache folder: $XDG_CACHE_HOME/daprivacyscanner/browsers
ROOM = 64 * 1024 * 1024                 # left free on the disk beyond the copy


class KeepError(ValueError):
    pass


def folder(host: Host) -> Path:
    from ..paths import PathResolver
    return PathResolver(host.home, host.environ).cache_home / "daprivacyscanner" / FOLDER


def _own_folder(host: Host, path: Path) -> bool:
    """A real folder of the user's (not a link)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == host.uid


def kept(host: Host, b) -> dict | None:
    """The kept copy of browser `b`: {"browser", "name", "version", "kept", "size", "archive"}, or None. Exactly one
    archive of the project's own name, with its signature beside it, both regular files, in folders of the user's."""
    from .browser import version_of
    base, d = folder(host), folder(host) / b.id
    if not (_own_folder(host, base) and _own_folder(host, d)):
        return None
    try:
        archives = [n for n in os.listdir(d) if b.archive_name(n)]
    except OSError:
        return None
    if len(archives) != 1:
        return None
    archive = d / archives[0]
    try:
        st, sig = os.lstat(archive), os.lstat(archive.with_name(archive.name + ".asc"))
    except OSError:
        return None
    if not (stat.S_ISREG(st.st_mode) and stat.S_ISREG(sig.st_mode)):
        return None
    return {"browser": b.id, "name": b.name, "version": version_of(archive.name), "kept": int(st.st_mtime),
            "size": st.st_size + sig.st_size, "archive": archive}


def view(host: Host, browsers) -> dict:
    """What the panel shows: the kept copies, and where they are."""
    out = []
    for b in browsers:
        k = kept(host, b)
        if k is not None:
            out.append({key: v for key, v in k.items() if key != "archive"} | {"file": k["archive"].name})
    return {"folder": host.display(folder(host)), "copies": out}


def _make(host: Host, path: Path) -> None:
    """The app's cache folder and its browsers folder, owner-only, made when missing; refused when either isn't a
    folder of the user's."""
    for p in (path.parent, path):
        try:
            p.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            pass
        if not _own_folder(host, p):
            raise KeepError(f"{host.display(p)} isn't a folder of yours (it may be a link), so nothing was kept there.")
        os.chmod(p, 0o700)


def _copy(src: Path, dest: Path) -> None:
    """A regular file copied, owner-only, never through a link at either end."""
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise KeepError(f"{src.name} isn't a file.")
        out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(out, "wb") as w, os.fdopen(os.dup(fd), "rb") as r:
            shutil.copyfileobj(r, w, 1024 * 1024)
            w.flush()
            os.fsync(w.fileno())
    finally:
        os.close(fd)


def _remove(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def keep(host: Host, b, archive: Path, verify: Callable[[Host, Path], dict]) -> dict:
    """`archive` (in ~/TempBrowser, verified and unpacked) and its signature kept in place of an older kept copy of
    `b`: copied into a new folder beside it, verified there (`verify` raises unless it is: never an unverified file
    kept), then swapped in. Returns kept()'s answer; raises KeepError (or what `verify` raises)."""
    base = folder(host)
    _make(host, base)
    sig = archive.with_name(archive.name + ".asc")
    try:
        size = os.stat(archive).st_size + os.stat(sig).st_size
    except OSError:
        raise KeepError("The download isn't there any more, so it wasn't kept.") from None
    if shutil.disk_usage(base).free < size + ROOM:
        raise KeepError(f"There isn't room for it on the disk ({size // 2**20} MB), so it wasn't kept.")
    tidy(host, b)
    staging = base / f".{b.id}.new-{os.urandom(4).hex()}"
    staging.mkdir(mode=0o700)
    old = None
    try:
        for src in (sig, archive):
            _copy(src, staging / src.name)
        verify(host, staging / archive.name)
        place = base / b.id
        if place.exists() or place.is_symlink():
            old = base / f".{b.id}.old-{os.urandom(4).hex()}"
            os.rename(place, old)                       # never a mix of the old archive and the new signature
        os.rename(staging, place)
        staging = None
    finally:
        if staging is not None:
            _remove(staging)
        if old is not None:
            _remove(old)
    got = kept(host, b)
    if got is None:
        raise KeepError("It couldn't be kept.")
    return got


def delete(host: Host, b) -> bool:
    """The kept copy of `b` deleted (and what an interrupted keep left of it). Whether there was one."""
    base = folder(host)
    if not _own_folder(host, base):
        return False
    place = base / b.id
    there = place.exists() or place.is_symlink()
    _remove(place)
    tidy(host, b)
    for p in (base, base.parent):                       # the folders go once empty (the cache's may hold more)
        try:
            p.rmdir()
        except OSError:
            break
    return there


def tidy(host: Host, b) -> None:
    """What a keep of `b` interrupted midway left beside the kept copy (a copy of the app killed meanwhile)."""
    base = folder(host)
    if not _own_folder(host, base):
        return
    for p in base.iterdir():
        if p.name.startswith((f".{b.id}.new-", f".{b.id}.old-")):
            _remove(p)
