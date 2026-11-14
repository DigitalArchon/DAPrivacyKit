"""The one place per-app data locations are resolved: the XDG base directories (honouring
$XDG_*_HOME with the spec's defaults), and the same data for Flatpak and Snap installs.

    native:  $XDG_CONFIG_HOME (~/.config), $XDG_DATA_HOME (~/.local/share),
             $XDG_CACHE_HOME (~/.cache), $XDG_STATE_HOME (~/.local/state)
    flatpak: ~/.var/app/<app-id>/{config,data,cache,.local/state}
    snap:    ~/snap/<name>/{common,<revision>...}, each with the XDG layout under it
             ("current" is a symlink to one revision and is not listed twice)

A check asks for "Signal's config directory" once and gets every place it may be."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Literal, Mapping


class Base(str, Enum):
    CONFIG = "config"
    DATA = "data"
    CACHE = "cache"
    STATE = "state"
    HOME = "home"        # dot-directories straight in the home directory, e.g. ~/.mozilla


XDG_ENV = {Base.CONFIG: "XDG_CONFIG_HOME", Base.DATA: "XDG_DATA_HOME",
           Base.CACHE: "XDG_CACHE_HOME", Base.STATE: "XDG_STATE_HOME"}
XDG_DEFAULT = {Base.CONFIG: ".config", Base.DATA: ".local/share", Base.CACHE: ".cache", Base.STATE: ".local/state"}
# inside ~/.var/app/<id>: Flatpak points the app's XDG variables at these
FLATPAK_DIR = {Base.CONFIG: "config", Base.DATA: "data", Base.CACHE: "cache", Base.STATE: ".local/state", Base.HOME: ""}
# inside ~/snap/<name>/<revision|common>: snapd sets HOME there, so apps use the default layout
SNAP_DIR = {**XDG_DEFAULT, Base.HOME: ""}
SNAP_REVISION = re.compile(r"^x?\d+$")

Install = Literal["native", "flatpak", "snap"]


@dataclass(frozen=True)
class Location:
    path: Path
    install: Install
    app: str | None = None           # Flatpak app id or snap name
    revision: str | None = None      # snap: a revision, or "common"
    current: bool = True             # snap: False for a retained, inactive revision

    def to_dict(self) -> dict:
        return {"path": str(self.path), "install": self.install, "app": self.app,
                "revision": self.revision, "current": self.current}


class PathResolver:
    def __init__(self, home: Path, environ: Mapping[str, str]):
        self.home = home
        self.environ = environ

    # ------------------------------------------------------------ XDG

    def base(self, kind: Base) -> Path:
        """The native base directory. Per the spec, a relative $XDG_*_HOME is invalid and ignored."""
        if kind is Base.HOME:
            return self.home
        value = self.environ.get(XDG_ENV[kind], "")
        return Path(value) if value and Path(value).is_absolute() else self.home / XDG_DEFAULT[kind]

    @property
    def config_home(self) -> Path:
        return self.base(Base.CONFIG)

    @property
    def data_home(self) -> Path:
        return self.base(Base.DATA)

    @property
    def cache_home(self) -> Path:
        return self.base(Base.CACHE)

    @property
    def state_home(self) -> Path:
        return self.base(Base.STATE)

    @property
    def runtime_dir(self) -> Path | None:
        value = self.environ.get("XDG_RUNTIME_DIR", "")
        return Path(value) if value and Path(value).is_absolute() else None

    def config_dirs(self) -> list[Path]:
        """$XDG_CONFIG_DIRS (system-wide defaults, most important first)."""
        value = self.environ.get("XDG_CONFIG_DIRS", "") or "/etc/xdg"
        return [Path(p) for p in value.split(":") if p and Path(p).is_absolute()]

    # ------------------------------------------------------------ Flatpak and Snap

    @property
    def flatpak_root(self) -> Path:
        return self.home / ".var" / "app"

    @property
    def snap_root(self) -> Path:
        return self.home / "snap"

    def flatpak_apps(self) -> list[str]:
        """App ids with a data directory under ~/.var/app (installed or not)."""
        return _subdirs(self.flatpak_root)

    def snaps(self) -> list[str]:
        """Snap names with a data directory under ~/snap (installed or not)."""
        return _subdirs(self.snap_root)

    def snap_roots(self, name: str) -> list[Location]:
        """~/snap/<name>/common and every revision directory, the current one marked."""
        top = self.snap_root / name
        current = None
        link = top / "current"
        if link.is_symlink():
            current = Path(_readlink(link)).name
        roots = [Location(top / rev, "snap", name, rev, current is None or rev == current)
                 for rev in _subdirs(top) if SNAP_REVISION.match(rev)]
        if (top / "common").is_dir():
            roots.insert(0, Location(top / "common", "snap", name, "common", True))
        return roots

    # ------------------------------------------------------------ lookups

    def locate(self, kind: Base, rel: str | Path = "", *, flatpak: Iterable[str] = (), snap: Iterable[str] = (),
               all_flatpaks: bool = False, all_snaps: bool = False, existing: bool = True) -> list[Location]:
        """Every place `<kind>/<rel>` may be: native, then the named Flatpak apps and snaps (or
        all of them). With `existing` (the default) only paths that exist are returned. The
        same directory reached twice (a symlink, or an XDG variable pointing into a sandbox)
        is listed once."""
        rel = Path(rel)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"locate() takes a relative path, not {rel}")
        found = [Location(self.base(kind) / rel, "native")]
        for app in (self.flatpak_apps() if all_flatpaks else flatpak):
            found.append(Location(self.flatpak_root / app / FLATPAK_DIR[kind] / rel, "flatpak", app))
        for name in (self.snaps() if all_snaps else snap):
            for root in self.snap_roots(name):
                found.append(Location(root.path / SNAP_DIR[kind] / rel, "snap", name, root.revision, root.current))
        return _dedupe(found, existing)

    def config(self, rel: str | Path = "", **kw) -> list[Location]:
        return self.locate(Base.CONFIG, rel, **kw)

    def data(self, rel: str | Path = "", **kw) -> list[Location]:
        return self.locate(Base.DATA, rel, **kw)

    def cache(self, rel: str | Path = "", **kw) -> list[Location]:
        return self.locate(Base.CACHE, rel, **kw)

    def state(self, rel: str | Path = "", **kw) -> list[Location]:
        return self.locate(Base.STATE, rel, **kw)

    def dotdir(self, rel: str | Path, **kw) -> list[Location]:
        """A dot-directory in home (~/.mozilla, ~/.thunderbird) and its sandboxed equivalents."""
        return self.locate(Base.HOME, rel, **kw)


def _subdirs(p: Path) -> list[str]:
    try:
        return sorted(c.name for c in p.iterdir() if c.is_dir() and not c.is_symlink())
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []


def _readlink(p: Path) -> str:
    try:
        return str(p.readlink())
    except OSError:
        return ""


def _dedupe(locs: list[Location], existing: bool) -> list[Location]:
    out, seen = [], set()
    for loc in locs:
        if existing and not loc.path.exists():
            continue
        try:
            key = loc.path.resolve()
        except OSError:
            key = loc.path
        if key in seen:
            continue
        seen.add(key)
        out.append(loc)
    return out


# ------------------------------------------------------------ the app's own folders

APP_FOLDER = "daprivacyscanner"


def own_folders(home: Path, environ: Mapping[str, str]) -> list[Path]:
    """The app's own folders: daprivacyscanner in the config, state, cache and data homes and the runtime folder."""
    r = PathResolver(home, environ)
    out = [r.config_home / APP_FOLDER, r.state_home / APP_FOLDER, r.cache_home / APP_FOLDER, r.data_home / APP_FOLDER]
    if r.runtime_dir is not None:
        out.append(r.runtime_dir / APP_FOLDER)
    return out


def owner_only(folder: Path) -> None:
    """`folder` put back to 0700 when it is a folder of this account's with more (one made under the umask, by an
    older version or a write that made it on the way to a folder inside it). Opened without following a link: a link,
    or another account's folder, is left as it is (whoever uses it refuses it). Best effort, never raises."""
    import os
    import stat
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return
    try:
        st = os.fstat(fd)
        if st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) & 0o077:
            os.fchmod(fd, 0o700)
    except OSError:
        pass
    finally:
        os.close(fd)


def make_own_folder(folder: Path) -> Path:
    """One of the app's own folders, made 0700 when missing (its parent, an XDG folder, as the umask makes it) and
    kept 0700 when it is there: what it holds is this account's alone."""
    import os
    folder.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(folder, 0o700)
    except FileExistsError:
        pass
    owner_only(folder)
    return folder


def keep_own_folders_private(home: Path, environ: Mapping[str, str]) -> None:
    """At every start: each of the app's own folders that is there kept 0700 (the DA apps' one security standard,
    2026-11-14: data, config and state folders 0700, also when they already exist)."""
    for folder in own_folders(home, environ):
        owner_only(folder)
