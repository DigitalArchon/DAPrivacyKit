"""Files in and out of the browser in the RAM disk (docs/TECHNICAL.md, Tools). The sandboxed browser sees
only its own folder, so the app moves files across, and the browser never learns where yours are:

- Uploads: a file the user chooses is copied (never moved, never linked) into the browser's
  "To upload" folder, which the sandbox gives it read-only: it can pick the file in its own Browse…
  dialog, but can't change or replace anything there. Photos and documents can be cleaned of their
  metadata on the way (mat2, as Remove metadata does), so a picture uploaded through Tor doesn't
  give away where it was taken; the cleaning happens in a folder of the app's own, out of the
  browser's sight, and only the cleaned copy goes into To upload. The file's name goes with it
  (sites see it): the page says so.
- Downloads: the browser saves into its own Downloads folder, which a compromised browser could
  fill with anything: a link to ~/.ssh/id_ed25519 leads nowhere inside the sandbox but to the real
  key outside it. So the app reads the folder one name at a time without following links (every
  folder from the RAM disk down), takes regular files on the RAM disk only, each with one link,
  finished ones only (no .part, unchanged for a moment), and writes a new file where the user
  chooses, never over an existing one and never executable. Each is judged by its content
  (tools/sniff.py) before it is listed: a program named like a document is named as a program.
  The browser can still change a file after it is listed, or while it is copied (the folder is its
  own): so Save… and View offline… first copy it where no sandbox reaches (snapshot), judge that
  copy, and go on only when it is what the page showed (`check`: its size and what it is), saving or
  opening that copy, never the browser's file.
  A document or picture can be opened with View offline… (tools/viewer.py): the user's own viewer
  in a sandbox with no network, so it can't fetch anything.

- The TempOutbox: a folder per browser at the RAM disk's top, "~/TempBrowser/Outbox for Tor Browser",
  which no sandbox is given. The user copies files into it (with the file manager, like the permanent
  ~/Outbox); the app, while it runs, cleans each of metadata (as Add a file to upload… does) and puts
  the clean copy in that browser's To upload, moving the original into Originals inside it (it may be
  the user's only copy, if they moved it in) and a file mat2 can't clean into "Not cleaned", never into
  To upload. Made with the browser, on by default, unless the permanent Outbox is set up: then the page
  says to use that one and copy from ~/Outbox/Cleaned. No desktop notification (a notification
  history can keep the names on the disk): the panel lists what happened.

Both stay in the RAM disk until it is closed. Nothing is recorded."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from ..host import Host
from . import ramdisk, sniff
from .sandbox import DOWNLOADS, UPLOADS

SETTLE = 2.0                    # seconds a download must be unchanged to count as finished
MAX_LISTED = 200
MAX_CACHED = 500


class TransferError(ValueError):
    pass


class Changed(TransferError):
    """A download isn't what the page showed any more (it was changed after it was listed)."""


def _browser_home(host: Host, folder: str) -> Path:
    return ramdisk.folder(host, ramdisk.BROWSER) / folder / "Browser"


def uploads_dir(host: Host, folder: str) -> Path:
    return _browser_home(host, folder) / UPLOADS


def downloads_dir(host: Host, folder: str) -> Path:
    return _browser_home(host, folder) / DOWNLOADS


def prepare(host: Host, folder: str) -> None:
    """The two folders, made before the browser starts (the sandbox binds "To upload" read-only).
    Refuses when either is a link or not a folder: the browser could have put it there."""
    for d in (uploads_dir(host, folder), downloads_dir(host, folder)):
        try:
            d.mkdir(mode=0o700)
        except FileExistsError:
            pass
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != host.uid:
            raise TransferError(f"{d.name} in the browser's folder isn't a folder of yours any more. Close ~/TempBrowser "
                                "and set the browser up again.")


def _open_dir(host: Host, path: Path) -> int:
    """`path` (under the RAM disk) opened one name at a time from the RAM disk, never through a link."""
    base = ramdisk.folder(host, ramdisk.BROWSER)
    rel = path.relative_to(base)
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in rel.parts:
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nfd
    except OSError:
        os.close(fd)
        raise TransferError(f"{path.name} in the browser's folder isn't a folder any more (or is a link).") from None
    return fd


def _ramdisk_dev(host: Host) -> int:
    return os.stat(ramdisk.folder(host, ramdisk.BROWSER), follow_symlinks=False).st_dev


def safe_name(name: str) -> str:
    """A name to save as: no control characters or slashes, not hidden, not starting with a dash,
    at most 200 bytes."""
    name = "".join("_" if unicodedata.category(c).startswith("C") or c in "/\\" else c for c in name).strip()
    name = name.lstrip(".-") or "download"
    while len(name.encode()) > 200:
        stem, ext = os.path.splitext(name)
        name = stem[:-1] + ext if len(stem) > 1 else name[:-1]
    return name


_SEEN: dict[tuple[int, int, int, int], tuple[sniff.Inspection, str]] = {}   # (dev, inode, size, mtime) -> (what it is, digest)
_SEEN_LOCK = threading.Lock()


def digest(fd: int) -> str:
    """SHA-256 of what `fd` holds, read from the start."""
    h = hashlib.sha256()
    offset = 0
    while chunk := os.pread(fd, 1 << 20, offset):
        h.update(chunk)
        offset += len(chunk)
    return h.hexdigest()


def inspect(dirfd: int, name: str) -> tuple[os.stat_result, sniff.Inspection, str] | None:
    """A file in the Downloads folder opened by name without following a link, what it is (tools/sniff.py)
    and its digest, remembered while it is unchanged; None if it isn't a plain file there."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        with _SEEN_LOCK:
            got = _SEEN.get(key)
        if got is None:
            got = (sniff.inspect(fd, name, st.st_size), digest(fd))
            with _SEEN_LOCK:
                if len(_SEEN) >= MAX_CACHED:
                    _SEEN.clear()
                _SEEN[key] = got
        return st, *got
    finally:
        os.close(fd)


def warnings(name: str) -> list[str]:
    """What the name alone says (a file not read yet)."""
    return sniff.inspect(-1, name, 0).warnings


@dataclass
class Entry:
    name: str
    size: int
    mtime: float
    warnings: list[str]
    kind: str = "unknown"
    what: str = ""
    viewable: bool = False
    check: str = ""                     # check_of: sent back with Save… and View offline…

    def to_dict(self) -> dict:
        return {"name": self.name, "size": self.size, "mtime": self.mtime, "warnings": self.warnings,
                "kind": self.kind, "what": self.what, "viewable": self.viewable, "check": self.check}


def check_of(size: int, ins: sniff.Inspection, content: str) -> str:
    """What the page shows of a download (its size and what it is) and its content's digest, as a short
    digest: Save… and View offline… send it back, and go on only when the copy they make is the same file."""
    text = json.dumps([size, ins.kind, ins.what, sorted(ins.warnings), ins.viewable, content])
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def downloads(host: Host, folder: str) -> tuple[list[Entry], int]:
    """(finished downloads, how many other things are in the folder: links, folders, partial files).
    Never follows a link. Each is judged by its content (tools/sniff.py), not only its name."""
    d = downloads_dir(host, folder)
    try:
        fd = _open_dir(host, d)
    except (TransferError, ValueError, OSError):
        return [], 0
    try:
        dev, names = _ramdisk_dev(host), os.listdir(fd)
        out, other, now = [], 0, time.time()
        for name in sorted(names):
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            partial = name.endswith(".part") or f"{name}.part" in names
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_dev != dev or partial
                    or now - st.st_mtime < SETTLE):
                other += 1
                continue
            if len(out) >= MAX_LISTED:
                continue
            got = inspect(fd, name)
            if got is None:
                other += 1
                continue
            ins = got[1]
            out.append(Entry(name, st.st_size, st.st_mtime, list(ins.warnings), ins.kind, ins.what, ins.viewable,
                             check_of(got[0].st_size, ins, got[2])))
        return out, other
    finally:
        os.close(fd)


def _free(dirfd: int, name: str) -> str:
    stem, ext = os.path.splitext(name)
    for i in range(1, 1000):
        candidate = name if i == 1 else f"{stem} ({i}){ext}"
        try:
            os.stat(candidate, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            return candidate
    raise TransferError(f"There are too many files named like {name} there already.")


def _copy(src_fd: int, dst_dir: int, name: str, mode: int) -> str:
    """A new file in `dst_dir` with what `src_fd` holds; never over an existing one."""
    for _ in range(5):
        target = _free(dst_dir, name)
        try:
            out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                          dir_fd=dst_dir)
        except FileExistsError:
            continue
        try:
            with os.fdopen(out, "wb") as w, os.fdopen(os.dup(src_fd), "rb") as r:
                r.seek(0)
                shutil.copyfileobj(r, w, 1024 * 1024)
                w.flush()
                os.fsync(w.fileno())
        except BaseException:
            try:
                os.unlink(target, dir_fd=dst_dir)
            except OSError:
                pass
            raise
        return target
    raise TransferError(f"{name} couldn't be given a free name there.")


@dataclass
class Snapshot:
    """A copy of a finished download in a folder of the app's own at the RAM disk's top, which no sandbox
    is given, and what that copy is."""
    folder: Path
    name: str
    size: int
    inspection: sniff.Inspection

    @property
    def path(self) -> Path:
        return self.folder / self.name

    def remove(self) -> None:
        ramdisk.wipe(self.folder)
        shutil.rmtree(self.folder, ignore_errors=True)


def _stage(host: Host, prefix: str) -> tuple[Path, int]:
    """A new folder `prefix`<random> at the RAM disk's top, opened without following links: (path, fd)."""
    base = ramdisk.folder(host, ramdisk.BROWSER)
    bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        name = f"{prefix}{os.urandom(6).hex()}"
        os.mkdir(name, 0o700, dir_fd=bfd)
        return base / name, os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=bfd)
    finally:
        os.close(bfd)


def snapshot(host: Host, folder: str, name: str, check: str | None, stage: tuple[Path, int] | None = None,
             mode: int = 0o600) -> Snapshot:
    """The finished download `name` copied out of the browser's reach (into `stage`, a folder and its fd,
    or a new .checking- folder), and judged again there. Raises Changed when that copy isn't what the page
    showed (`check`, from the listing): the browser changed it after it was listed."""
    if not isinstance(name, str) or not name or "/" in name or name in (".", "..") or "\0" in name:
        raise TransferError("That isn't one of the browser's downloads.")
    if not isinstance(check, str) or not check:
        raise TransferError("The list of downloads is out of date: refresh it and try again.")
    if name not in {e.name for e in downloads(host, folder)[0]}:
        raise TransferError(f"{name} isn't a finished download in the browser's folder.")
    dfd = _open_dir(host, downloads_dir(host, folder))
    try:
        try:
            src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
        except OSError:
            raise TransferError(f"{name} can't be read (it may have just changed).") from None
    finally:
        os.close(dfd)
    own = stage is None
    try:
        st = os.fstat(src)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_dev != _ramdisk_dev(host):
            raise TransferError(f"{name} isn't a plain file in ~/TempBrowser.")
        free = os.statvfs(ramdisk.folder(host, ramdisk.BROWSER))
        if st.st_size + (16 << 20) > free.f_bavail * free.f_frsize:
            raise TransferError(f"There isn't room in ~/TempBrowser to check a copy of {name} first.")
        path, sfd = _stage(host, ".checking-") if own else stage
        try:
            copied = _copy(src, sfd, safe_name(name), mode)
            cfd = os.open(copied, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=sfd)
        finally:
            if own:
                os.close(sfd)
    finally:
        os.close(src)
    try:
        size = os.fstat(cfd).st_size
        snap = Snapshot(path, copied, size, sniff.inspect(cfd, name, size))
        content = digest(cfd)
    finally:
        os.close(cfd)
    if check_of(size, snap.inspection, content) != check:
        if own:
            snap.remove()
        else:
            (path / copied).unlink(missing_ok=True)
        now = snap.inspection.what or ", ".join(snap.inspection.warnings) or "something else"
        raise Changed(f"{name} changed after it was listed (it is now {now}, {size} bytes, and not the same file), "
                      "so nothing was done with it. Look at it again in the list, which shows what it is now.")
    return snap


def save(host: Host, folder: str, name: str, dest: Path, check: str | None) -> Path:
    """Copies the finished download `name` into the folder `dest`, from a copy made out of the browser's
    reach and judged again (snapshot): only when it is what the page showed (`check`). Returns the new
    file's path."""
    snap = snapshot(host, folder, name, check)
    try:
        real = Path(os.path.realpath(dest))
        try:
            out_dir = os.open(real, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            raise TransferError(f"{dest} isn't a folder you can open.") from None
        try:
            if not os.access(".", os.W_OK, dir_fd=out_dir):
                raise TransferError(f"You can't write to {dest}.")
            cfd = os.open(snap.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                target = _copy(cfd, out_dir, safe_name(name), 0o666)     # the umask applies; never executable
            finally:
                os.close(cfd)
        finally:
            os.close(out_dir)
    finally:
        snap.remove()
    return real / target


def add(host: Host, folder: str, src: Path, clean: bool) -> dict:
    """Copies `src` into the browser's "To upload" folder, cleaned of metadata first when asked
    (mat2, on the copy). The original is never changed."""
    if clean and not host.runner.which("mat2"):
        raise TransferError("Removing metadata needs mat2, which isn't installed.")
    try:
        sfd = os.open(src, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as e:
        raise TransferError(f"{src.name} can't be read: {e.strerror or e}.") from None
    try:
        return _add_fd(host, folder, sfd, src.name, clean)
    finally:
        os.close(sfd)


def _add_fd(host: Host, folder: str, sfd: int, src_name: str, clean: bool) -> dict:
    from . import metadata
    st = os.fstat(sfd)
    if not stat.S_ISREG(st.st_mode):
        raise TransferError(f"{src_name} isn't a file.")
    free = os.statvfs(ramdisk.folder(host, ramdisk.BROWSER))
    if st.st_size * (2 if clean else 1) + (16 << 20) > free.f_bavail * free.f_frsize:
        raise TransferError(f"There isn't room for {src_name} in ~/TempBrowser.")
    ufd = _open_dir(host, uploads_dir(host, folder))
    try:
        name = safe_name(src_name)
        if not clean:
            return {"name": _copy(sfd, ufd, name, 0o600), "cleaned": False, "message": ""}
        # mat2 writes its cleaned copy beside the file it is given: a staging folder of the app's own,
        # at the RAM disk's top, which no sandbox is given (in To upload the browser could read the
        # original, metadata and all, while mat2 works)
        stage_path, sdir = _stage(host, ".adding-")
        try:
            try:
                _copy(sfd, sdir, name, 0o600)
            finally:
                os.close(sdir)
            res = metadata.clean(host, stage_path / name, check_after=False)
            if not res.ok:
                raise TransferError(f"{src_name} couldn't be cleaned: {res.message}")
            cfd = os.open(res.output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                final = _copy(cfd, ufd, name, 0o600)
            finally:
                os.close(cfd)
            return {"name": final, "cleaned": True, "message": res.message}
        finally:
            shutil.rmtree(stage_path, ignore_errors=True)
    finally:
        os.close(ufd)


# ------------------------------------------------------------------ the TempOutbox

OUTBOX = "Outbox for {name}"
OUTBOX_ORIGINALS, OUTBOX_NOT_CLEANED = "Originals", "Not cleaned"
RECENT = 20
_RECENT: dict[str, list[dict]] = {}         # browser folder -> what the TempOutbox did lately (this run of the app)
_RECENT_LOCK = threading.Lock()
OUTBOX_LOCK = threading.Lock()              # held while the TempOutboxes are emptied, and while ~/TempBrowser is wiped
WATCHED = {"on": False}                     # whether this app watches them (server.create_app's watch_outbox)


def outbox_dir(host: Host, name: str) -> Path:
    """~/TempBrowser/Outbox for NAME (a browser's name)."""
    return ramdisk.folder(host, ramdisk.BROWSER) / OUTBOX.format(name=name)


def permanent_outbox(host: Host) -> bool:
    """Whether the permanent Outbox (app.metadata_outbox) is set up and watching ~/Outbox: its path unit
    is there and enabled (linked from default.target.wants). Read from the files, so it can be asked often."""
    from . import integration
    d = Path(host.environ.get("XDG_CONFIG_HOME") or host.home / ".config") / "systemd" / "user"
    unit = f"{integration.OUTBOX_UNIT}.path"
    return (d / unit).is_file() and os.path.lexists(d / "default.target.wants" / unit)


def make_outbox(host: Host, name: str) -> Path:
    """The TempOutbox for the browser called `name`, with its two folders; every folder opened from the
    RAM disk without following links."""
    box = outbox_dir(host, name)
    base = ramdisk.folder(host, ramdisk.BROWSER)
    bfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            os.mkdir(box.name, 0o700, dir_fd=bfd)
        except FileExistsError:
            pass
    finally:
        os.close(bfd)
    fd = _open_dir(host, box)
    try:
        if os.fstat(fd).st_uid != host.uid:
            raise TransferError(f"{box.name} in ~/TempBrowser isn't a folder of yours.")
        for sub in (OUTBOX_ORIGINALS, OUTBOX_NOT_CLEANED):
            try:
                os.mkdir(sub, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
    finally:
        os.close(fd)
    return box


def _outbox_files(fd: int) -> list[str]:
    out = []
    for n in sorted(os.listdir(fd)):
        try:
            if not n.startswith(".") and stat.S_ISREG(os.stat(n, dir_fd=fd, follow_symlinks=False).st_mode):
                out.append(n)
        except OSError:
            continue
    return out


def remove_outbox(host: Host, name: str) -> None:
    """Turns the TempOutbox off: removes its folder, refused while it holds files (an original there may be
    the user's only copy)."""
    box = outbox_dir(host, name)
    try:
        fd = _open_dir(host, box)
    except TransferError:
        return
    try:
        left = [*_outbox_files(fd)]
        for sub in (OUTBOX_ORIGINALS, OUTBOX_NOT_CLEANED):
            try:
                sfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                continue
            try:
                left += [f"{sub}/{n}" for n in os.listdir(sfd)]
            finally:
                os.close(sfd)
        others = [n for n in os.listdir(fd) if n not in (OUTBOX_ORIGINALS, OUTBOX_NOT_CLEANED) and n not in left]
        if left or others:
            shown = (left + others)[:5]
            raise TransferError(f"{box.name} still holds {', '.join(shown)}{'…' if len(left + others) > 5 else ''}: "
                                "move what you want to keep out of it first.")
        for sub in (OUTBOX_ORIGINALS, OUTBOX_NOT_CLEANED):
            try:
                os.rmdir(sub, dir_fd=fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(fd)
    os.rmdir(box)


def _note(folder: str, what: str, name: str, detail: str = "") -> None:
    with _RECENT_LOCK:
        got = _RECENT.setdefault(folder, [])
        got.insert(0, {"what": what, "name": name, "detail": detail, "when": time.time()})
        del got[RECENT:]


def recent(folder: str) -> list[dict]:
    with _RECENT_LOCK:
        return list(_RECENT.get(folder, []))


def forget_recent() -> None:
    with _RECENT_LOCK:
        _RECENT.clear()


def outbox_view(host: Host, folder: str, name: str) -> dict:
    """What the panel shows of a browser's TempOutbox."""
    box = outbox_dir(host, name)
    view = {"folder": f"~/{ramdisk.BROWSER}/{box.name}", "on": False, "waiting": 0, "originals": 0, "not_cleaned": [],
            "permanent": permanent_outbox(host), "recent": recent(folder), "watched": WATCHED["on"],
            "mat2": bool(host.runner.which("mat2"))}
    try:
        fd = _open_dir(host, box)
    except (TransferError, ValueError, OSError):
        return view
    try:
        view.update(on=True, waiting=len(_outbox_files(fd)))
        for sub, key in ((OUTBOX_ORIGINALS, "originals"), (OUTBOX_NOT_CLEANED, "not_cleaned")):
            try:
                sfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except OSError:
                continue
            try:
                names = sorted(n for n in os.listdir(sfd) if not n.startswith("."))
            finally:
                os.close(sfd)
            view[key] = len(names) if key == "originals" else names[:MAX_LISTED]
    finally:
        os.close(fd)
    return view


def run_outbox(host: Host, folder: str, name: str, settle: float = SETTLE) -> dict:
    """Each file put directly in the browser's TempOutbox: cleaned of metadata into its To upload
    (`_add_fd`, as Add a file to upload… with the box ticked), the original moved into Originals; a file
    that couldn't be cleaned (a format mat2 doesn't know, no room) into "Not cleaned", never into To upload.
    Hidden files, partial downloads and files changed in the last `settle` seconds (still being copied in)
    wait. Folders put there are left as they are. Does nothing without mat2 (the panel says so).
    Returns {"cleaned": [...], "not_cleaned": [(name, why)]}."""
    from . import metadata
    done: dict = {"cleaned": [], "not_cleaned": []}
    if not host.runner.which("mat2"):
        return done
    try:
        fd = _open_dir(host, outbox_dir(host, name))
    except (TransferError, ValueError, OSError):
        return done
    try:
        if os.fstat(fd).st_dev != _ramdisk_dev(host):
            return done
        for entry in _outbox_files(fd):
            if metadata.SKIP_NAMES.search(entry):
                continue
            try:
                st = os.stat(entry, dir_fd=fd, follow_symlinks=False)
                if time.time() - st.st_mtime < settle or not stat.S_ISREG(st.st_mode):
                    continue
                sfd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            except OSError:
                continue
            try:
                got = _add_fd(host, folder, sfd, entry, True)
                sub, why = OUTBOX_ORIGINALS, ""
            except (TransferError, OSError) as e:
                sub = OUTBOX_NOT_CLEANED
                why = str(e) if isinstance(e, TransferError) else f"{entry} couldn't be copied: {e.strerror or e}"
                got = None
            finally:
                os.close(sfd)
            try:
                tfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(sub, 0o700, dir_fd=fd)
                tfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                os.rename(entry, _free(tfd, entry), src_dir_fd=fd, dst_dir_fd=tfd)
            finally:
                os.close(tfd)
            if got is not None:
                done["cleaned"].append(got["name"])
                _note(folder, "cleaned", entry, got["name"])
            else:
                done["not_cleaned"].append((entry, why))
                _note(folder, "not_cleaned", entry, why)
    finally:
        os.close(fd)
    return done


def uploads(host: Host, folder: str) -> list[dict]:
    d = uploads_dir(host, folder)
    try:
        fd = _open_dir(host, d)
    except (TransferError, ValueError, OSError):
        return []
    try:
        out = []
        for name in sorted(os.listdir(fd)):
            if name.startswith("."):
                continue
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                out.append({"name": name, "size": st.st_size})
        return out[:MAX_LISTED]
    finally:
        os.close(fd)


def remove_upload(host: Host, folder: str, name: str) -> None:
    if not isinstance(name, str) or not name or "/" in name or name.startswith(".") or "\0" in name:
        raise TransferError("That isn't one of the files to upload.")
    fd = _open_dir(host, uploads_dir(host, folder))
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise TransferError(f"{name} isn't a file.")
        os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        pass
    finally:
        os.close(fd)
