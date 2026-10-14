"""The apps whose files the checks read (apps.yaml): the version each check was made for, and the
version installed here. Apps change where and how they keep their data, most often in a major
release, so a check reading an app newer than it was made for says so (a note on the result, and
a line in its fix's dry run), and one that found nothing of an app that is newer and keeps nothing
where it used to says it couldn't check rather than passing.

Installed versions are read offline, as the user: the package managers (dpkg-query, rpm, pacman),
`flatpak list` and `snap list`, each run once per scan. An app installed some other way (a tarball,
an AppImage) has no version here and gets no note. packaging/check-app-versions.py compares the
list with the latest releases upstream, for the maintainer."""

from __future__ import annotations

import datetime as dt
import functools
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from .model import Note, Outcome, Status
from .paths import Base

if TYPE_CHECKING:
    from .checks import Scan
    from .host import Host
    from .paths import PathResolver

DATA_NAME = "apps.yaml"
SCHEMA_VERSION = 1
BASES = {"config": Base.CONFIG, "data": Base.DATA, "cache": Base.CACHE, "state": Base.STATE, "home": Base.HOME}
BASIS = {"tested": "tested with", "current": "the release current when it was written"}
_KEYS = {"id", "name", "packages", "flatpak", "snap", "checked", "basis", "checked_on", "major_parts", "tolerance", "checks",
         "data", "relies_on", "upstream", "verify"}
_UPSTREAM = {"repology", "notes", "source"}


class DataError(ValueError):
    pass


@dataclass(frozen=True)
class App:
    id: str
    name: str
    checked: tuple[int, ...]
    checked_text: str
    basis: str
    on: dt.date
    checks: tuple[str, ...]
    packages: tuple[str, ...] = ()
    flatpak: tuple[str, ...] = ()
    snap: tuple[str, ...] = ()
    major_parts: int = 1            # how many of the version's numbers make its major version (VS Code: 1.105)
    tolerance: int = 0              # major versions ahead before it is said (rapid releases: a new major monthly)
    data: tuple[tuple[str, str], ...] = ()      # (base, path) where it keeps what the checks read
    relies_on: str = ""
    upstream: tuple[tuple[str, str], ...] = ()
    verify: str = ""

    def major(self, version: tuple[int, ...]) -> tuple[int, ...]:
        return tuple((list(version) + [0] * self.major_parts)[:self.major_parts])

    def ahead(self, version: tuple[int, ...]) -> bool:
        """A newer major version than the one the checks were made for, by more than `tolerance`."""
        mine, made = self.major(version), self.major(self.checked)
        if mine[:-1] != made[:-1]:
            return mine > made
        return mine[-1] > made[-1] + self.tolerance

    @property
    def checked_major(self) -> str:
        return ".".join(map(str, self.major(self.checked)))

    def up(self, key: str) -> str:
        return dict(self.upstream).get(key, "")

    def data_found(self, paths: "PathResolver") -> bool:
        """Whether anything is where it keeps its data, natively, in its Flatpak or its Snap."""
        return any(paths.locate(BASES[base], rel, flatpak=self.flatpak, snap=self.snap) for base, rel in self.data)

    def data_text(self) -> str:
        return ", ".join(("~/" if base == "home" else f"{base}: ") + rel for base, rel in self.data)


def parse_version(text: str) -> tuple[int, ...] | None:
    """The numbers at the start of a version ("1:128.3.0esr-1" -> (128, 3, 0)), or None. Ubuntu's
    transitional packages that install a snap ("1:1snap1-0ubuntu5") have no version of their own."""
    text = re.sub(r"^\d+:", "", (text or "").strip())
    m = re.match(r"\d+(?:\.\d+)*", text)
    if not m or re.match(r"\d+snap", text):
        return None
    return tuple(int(n) for n in m.group(0).split("."))


def _strs(v: Any, where: str) -> tuple[str, ...]:
    if v is None:
        return ()
    if isinstance(v, str):
        return (v,)
    if isinstance(v, list) and all(isinstance(x, str) and x for x in v):
        return tuple(v)
    raise DataError(f"{where}: needs a string or a list of strings")


def default_path() -> Path:
    repo = Path(__file__).resolve().parents[2] / DATA_NAME
    if repo.is_file():
        return repo
    return Path(str(resources.files(__package__) / DATA_NAME))


@functools.lru_cache(maxsize=4)
def load(path: Path | str | None = None) -> "Apps":
    path = Path(path) if path else default_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise DataError(f"cannot read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise DataError(f"{path} is not valid YAML: {e}") from e
    return parse(data)


def parse(data: Any) -> "Apps":
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise DataError(f"{DATA_NAME}: unsupported schema_version")
    out: dict[str, App] = {}
    for i, a in enumerate(data.get("apps") or []):
        if not isinstance(a, dict) or not isinstance(a.get("id"), str) or not isinstance(a.get("name"), str):
            raise DataError(f"apps[{i}]: needs an id and a name")
        where = f"apps.{a['id']}"
        if set(a) - _KEYS:
            raise DataError(f"{where}: unknown keys {', '.join(sorted(set(a) - _KEYS))}")
        if a["id"] in out:
            raise DataError(f"{where}: duplicate id")
        checked = parse_version(str(a.get("checked", "")))
        if checked is None:
            raise DataError(f"{where}: checked must be a version")
        if a.get("basis") not in BASIS:
            raise DataError(f"{where}: basis must be one of {', '.join(BASIS)}")
        if not isinstance(a.get("checked_on"), dt.date):
            raise DataError(f"{where}: checked_on must be a date (YYYY-MM-DD)")
        packages, flatpak, snap = (_strs(a.get(k), f"{where}.{k}") for k in ("packages", "flatpak", "snap"))
        if not (packages or flatpak or snap):
            raise DataError(f"{where}: needs packages, flatpak or snap to read the installed version from")
        checks = _strs(a.get("checks"), f"{where}.checks")
        if not checks:
            raise DataError(f"{where}: needs the checks that read its files")
        parts, tol = a.get("major_parts", 1), a.get("tolerance", 0)
        if not (isinstance(parts, int) and 1 <= parts <= 3 and isinstance(tol, int) and 0 <= tol <= 12):
            raise DataError(f"{where}: major_parts is 1 to 3, tolerance 0 to 12")
        data_ = []
        for d in _strs(a.get("data"), f"{where}.data"):
            base, _, rel = d.partition(":")
            if base not in BASES or not rel or rel.startswith("/") or ".." in rel.split("/"):
                raise DataError(f"{where}.data: {d!r} must be <{'|'.join(BASES)}>:<relative path>")
            data_.append((base, rel))
        up = a.get("upstream") or {}
        if not isinstance(up, dict) or set(up) - _UPSTREAM or not all(isinstance(v, str) for v in up.values()):
            raise DataError(f"{where}.upstream: a mapping of {', '.join(sorted(_UPSTREAM))}")
        for k in ("notes", "source"):
            if up.get(k) and not up[k].startswith("https://"):
                raise DataError(f"{where}.upstream.{k}: https only")
        out[a["id"]] = App(a["id"], a["name"], checked, str(a["checked"]), a["basis"], a["checked_on"], checks, packages,
                           flatpak, snap, parts, tol, tuple(data_), " ".join(str(a.get("relies_on") or "").split()),
                           tuple(sorted(up.items())), " ".join(str(a.get("verify") or "").split()))
    return Apps(out)


class Apps:
    def __init__(self, apps: dict[str, App]):
        self.apps = apps
        self.by_check: dict[str, list[App]] = {}
        for app in apps.values():
            for cid in app.checks:
                self.by_check.setdefault(cid, []).append(app)

    def __iter__(self):
        return iter(self.apps.values())

    def __len__(self) -> int:
        return len(self.apps)

    def __getitem__(self, app_id: str) -> App:
        return self.apps[app_id]


# ------------------------------------------------------------------ what is installed

@dataclass(frozen=True)
class Installed:
    version: tuple[int, ...]
    text: str               # as the source gives it
    source: str             # "package firefox", "Flatpak", "Snap"

    @property
    def short(self) -> str:
        return re.sub(r"^\d+:", "", self.text).split("-")[0].split("+")[0]


def _packages(host: "Host", names: list[str]) -> dict[str, str]:
    """{package: version} of those installed, from every package manager there is."""
    out: dict[str, str] = {}
    if not names:
        return out
    if host.runner.which("dpkg-query"):
        r = host.run("dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n", *names)
        for line in r.stdout.splitlines():
            f = line.split("\t")
            if len(f) == 3 and f[0].startswith("ii"):
                out[f[1]] = f[2]
    if host.runner.which("rpm"):
        r = host.run("rpm", "-q", "--qf", "%{NAME}\t%{VERSION}\n", *names)
        for line in r.stdout.splitlines():
            f = line.split("\t")
            if len(f) == 2 and f[0] in names:
                out.setdefault(f[0], f[1])
    if host.runner.which("pacman"):
        r = host.run("pacman", "-Q", *names)
        for line in r.stdout.splitlines():
            f = line.split()
            if len(f) == 2 and f[0] in names:
                out.setdefault(f[0], f[1])
    return out


def _flatpaks(host: "Host") -> dict[str, str]:
    if not host.runner.which("flatpak"):
        return {}
    r = host.run("flatpak", "list", "--app", "--columns=application,version")
    return {f[0]: f[1] for f in (ln.split("\t") for ln in r.stdout.splitlines()) if len(f) == 2 and f[1].strip()}


def _snaps(host: "Host") -> dict[str, str]:
    if not host.runner.which("snap"):
        return {}
    r = host.run("snap", "list")
    out = {}
    for line in r.stdout.splitlines()[1:]:
        f = line.split()
        if len(f) >= 2:
            out[f[0]] = f[1]
    return out


def installed(host: "Host", apps: Apps) -> dict[str, Installed]:
    """The newest version of each app installed here, however it was installed. Read-only; offline."""
    pkgs = _packages(host, sorted({p for a in apps for p in a.packages}))
    flat = _flatpaks(host) if any(a.flatpak for a in apps) else {}
    snaps = _snaps(host) if any(a.snap for a in apps) else {}
    out: dict[str, Installed] = {}
    for app in apps:
        found = [(v, f"package {p}") for p in app.packages if (v := pkgs.get(p))]
        found += [(v, "Flatpak") for f in app.flatpak if (v := flat.get(f))]
        found += [(v, "Snap") for s in app.snap if (v := snaps.get(s))]
        best = None
        for text, source in found:
            v = parse_version(text)
            if v is not None and (best is None or v > best.version):
                best = Installed(v, text, source)
        if best is not None:
            out[app.id] = best
    return out


# ------------------------------------------------------------------ on a check's result

@dataclass(frozen=True)
class Ahead:
    app: App
    installed: Installed
    data_missing: bool      # it keeps data and none is where this version of the app kept it


def ahead_for(check_id: str, scan: "Scan") -> list[Ahead]:
    """The apps a check reads that are installed here in a major version newer than it was made for."""
    apps = load().by_check.get(check_id)
    if not apps:
        return []
    have = scan.installed_apps()
    out = []
    for app in apps:
        inst = have.get(app.id)
        if inst is not None and app.ahead(inst.version):
            out.append(Ahead(app, inst, bool(app.data) and not app.data_found(scan.paths)))
    return out


def _made_for(app: App) -> str:
    how = "tested with" if app.basis == "tested" else "made when the current release was"
    return f"{how} {app.name} {app.checked_text}"


def note(a: Ahead) -> Note:
    app, inst = a.app, a.installed
    text = (f"This check was {_made_for(app)} ({app.on.isoformat()}); {app.name} {inst.short} is installed here "
            f"({inst.source}). A new major version is more likely to change where and how an app keeps its data, so "
            "this result may miss something: after a fix, scan again to see that it worked, and look for a newer "
            f"version of DA Privacy Kit made for {app.name} {'.'.join(map(str, app.major(inst.version)))}.")
    if a.data_missing:
        text += (f" Nothing of {app.name}'s was found where version {app.checked_major} keeps it ({app.data_text()}): "
                 "if you have used it, it may keep its data somewhere else now.")
    return Note("limitation", f"{app.name} {inst.short} is newer than this check was made for", text)


def annotate(check_id: str, scan: "Scan", outcome: Outcome) -> Outcome:
    """Adds a note for each app the check reads that is newer than it was made for. A pass, or nothing found, can't
    be trusted for an app that is newer and keeps nothing where it used to: that becomes "couldn't check"."""
    hits = ahead_for(check_id, scan)
    if not hits:
        return outcome
    outcome.notes = [*outcome.notes, *(note(a) for a in hits)]
    missing = [a.app.name for a in hits if a.data_missing]
    if missing and outcome.status in (Status.PASS, Status.NOT_APPLICABLE):
        was = outcome.summary
        names = " and ".join(missing)
        outcome.status = Status.UNKNOWN
        outcome.summary = (f"Couldn't check {names}: installed in a newer version than this check was made for, "
                           f"with nothing where the older version kept {'its' if len(missing) == 1 else 'their'} data.")
        if was:
            outcome.notes.insert(0, Note("info", "What the check found otherwise", was))
    return outcome


def plan_note(check_id: str, scan: "Scan") -> str | None:
    """For a fix's dry run: the apps it changes that are newer than it was made for."""
    hits = ahead_for(check_id, scan)
    if not hits:
        return None
    parts = [f"{a.app.name} {a.installed.short} is installed (this fix was {_made_for(a.app)})" for a in hits]
    return ("; ".join(parts) + ". A new major version may keep its settings differently: scan again after applying, "
            "to see that the fix worked.")
