"""Choosing files for a tool. A web page can't see the paths of files the user picks, so the server
asks: in the app window, pywebview's own dialog (app.py passes it in); in the browser, zenity or
kdialog when one is installed; otherwise the page asks for a typed path. Paths that come back, or
are typed, are checked before a tool reads them (`checked`)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable

from ..host import Host

# (kind: "open" or "folder", multiple, start folder) -> paths, [] when the user cancels, None when there
# is no dialog
Picker = Callable[[str, bool, str], "list[str] | None"]
DIALOG_TIMEOUT = 3600


def downloads(host: Host) -> Path:
    from ..checks._util import xdg_user_dir
    from ..paths import PathResolver
    d = xdg_user_dir(host, PathResolver(host.home, host.environ), "DOWNLOAD")
    return d if d and d.is_dir() else host.home


def dialog(host: Host) -> Picker | None:
    """zenity or kdialog, for the browser."""
    def zenity(kind: str, multiple: bool, start: str) -> list[str] | None:
        if kind == "folder":
            argv = ["zenity", "--file-selection", "--directory", "--title=Choose a folder", f"--filename={start.rstrip('/')}/"]
            r = host.run(*argv, timeout=DIALOG_TIMEOUT)
            return [p for p in r.stdout.splitlines() if p][:1] if r.ok else []
        argv = ["zenity", "--file-selection", "--title=Choose " + ("files" if multiple else "a file"),
                f"--filename={start.rstrip('/')}/"] + (["--multiple", "--separator=\n"] if multiple else [])
        r = host.run(*argv, timeout=DIALOG_TIMEOUT)
        return [p for p in r.stdout.splitlines() if p] if r.ok else []

    def kdialog(kind: str, multiple: bool, start: str) -> list[str] | None:
        if kind == "folder":
            r = host.run("kdialog", "--title", "Choose a folder", "--getexistingdirectory", start, timeout=DIALOG_TIMEOUT)
            return [p for p in r.stdout.splitlines() if p][:1] if r.ok else []
        argv = ["kdialog", "--title", "Choose " + ("files" if multiple else "a file"), "--getopenfilename", start]
        if multiple:
            argv += ["--multiple", "--separate-output"]
        r = host.run(*argv, timeout=DIALOG_TIMEOUT)
        return [p for p in r.stdout.splitlines() if p] if r.ok else []

    if host.runner.which("kdialog") and "KDE" in host.environ.get("XDG_CURRENT_DESKTOP", "").upper():
        return kdialog
    if host.runner.which("zenity"):
        return zenity
    if host.runner.which("kdialog"):
        return kdialog
    return None


class PathRefused(ValueError):
    pass


MAX_LINKS = 40                          # as the kernel's limit on links followed in one path


def _within(path: Path, top: Path) -> bool:
    return path == top or top in path.parents


def resolved(p: Path, home: Path) -> Path:
    """`p`'s real path, resolved one name at a time as the kernel would. Refuses (PathRefused) a path that goes
    through a link inside ~/TempBrowser: the browser in memory writes there (its Downloads folder, its profile),
    and a link it planted, Downloads/notes.txt pointing at ~/.ssh/id_ed25519, made Add a file to upload… copy the
    key into To upload, where the browser reads it (found in the 2026-10-17 review, live on Mint). Links anywhere
    else are the user's own, and followed. A name that isn't there ends the walk: the rest is returned as it is,
    for the caller to find missing."""
    from .ramdisk import BROWSER
    browser = Path(os.path.realpath(home)) / BROWSER
    todo = [x for x in str(p).split("/") if x][::-1]          # the names still to walk, the next one last
    cur, links = Path("/"), 0
    while todo:
        name = todo.pop()
        if name == ".":
            continue
        if name == "..":
            cur = cur.parent
            continue
        nxt = cur / name
        try:
            st = os.lstat(nxt)
        except OSError:
            return nxt.joinpath(*reversed(todo))
        if not stat.S_ISLNK(st.st_mode):
            cur = nxt
            continue
        if _within(nxt, browser):
            raise PathRefused(f"{p} is reached through a link in ~/{BROWSER} ({nxt.name}), which the browser there "
                              "could have made to point at a file of yours: it isn't used. Choose the file itself.")
        links += 1
        if links > MAX_LINKS:
            raise PathRefused(f"{p} goes through too many links.")
        target = os.readlink(nxt)
        if target.startswith("/"):
            cur = Path("/")
        todo.extend(x for x in reversed(target.split("/")) if x)
    return cur


def checked(raw, home: Path, folders: bool = False) -> Path:
    """A path the page sent: absolute (or ~/...), an existing regular file the user can read (or, with
    `folders`, a folder they can open and list), not under /proc, /sys or /dev, and not reached through a link
    inside ~/TempBrowser (`resolved`)."""
    if not isinstance(raw, str) or not raw.strip() or "\0" in raw:
        raise PathRefused("No file given.")
    text = raw.strip()
    if text.startswith("file://"):
        from urllib.parse import unquote
        text = unquote(text[7:])
    if text == "~" or text.startswith("~/"):
        text = str(home) + text[1:]
    p = Path(text)
    if not p.is_absolute():
        raise PathRefused("Give the whole path of the file, starting with / or ~/.")
    real = resolved(p, home)
    if any(str(x) == d or str(x).startswith(d + "/") for x in (real, Path(os.path.normpath(p)))
           for d in ("/proc", "/sys", "/dev")):
        raise PathRefused("That isn't a file the tools work on.")
    if folders and real.is_dir():
        if not os.access(real, os.R_OK | os.X_OK):
            raise PathRefused(f"{p} can't be opened.")
        return p
    if not real.is_file():
        raise PathRefused(f"{p} isn't a {'file or folder' if folders else 'file'} (or doesn't exist).")
    if not os.access(real, os.R_OK):
        raise PathRefused(f"{p} can't be read.")
    return p


def recent_downloads(host: Host, limit: int = 15) -> list[dict]:
    """The newest files in the Downloads folder (not companions like .asc or SHA256SUMS), to pick from."""
    from .verify import SIG_SUFFIXES, SUMS_NAME
    d = downloads(host)
    out = []
    try:
        with os.scandir(d) as it:
            for e in it:
                if e.name.startswith(".") or e.name.endswith(SIG_SUFFIXES) or SUMS_NAME.search(e.name):
                    continue
                try:
                    if e.is_file():
                        st = e.stat()
                        out.append((st.st_mtime, e.path, st.st_size))
                except OSError:
                    continue
    except OSError:
        return []
    out.sort(reverse=True)
    return [{"path": p, "name": os.path.basename(p), "size": s, "mtime": t} for t, p, s in out[:limit]]
