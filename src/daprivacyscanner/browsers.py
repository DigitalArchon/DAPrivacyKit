"""Web browsers: the data in browsers.yaml (how each is recognised, how it is judged, the receipts),
and reading which browsers this computer has and which one is the default. Nothing here touches
the network."""

from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import ini
from .vpn import DataError, Fact, _facts, _strs

DATA_NAME = "browsers.yaml"
SCHEMA_VERSION = 1
TOPICS = ("record", "code", "maker", "blocking", "security", "use")
TOPIC_TITLES = {"record": "On the record", "code": "Its code", "maker": "Who makes it",
                "blocking": "Ad and tracker blocking", "security": "Security", "use": "Using it well"}
CLASSES = ("surveillance", "closed_ui", "privacy", "other")
BLOCKING = ("builtin", "extension", "none_allowed")
# uBlock Origin: Firefox's add-on id, and the Chromium web store's ids of the full version and of Lite
UBO_FIREFOX = "uBlock0@raymondhill.net"
UBO_CHROMIUM = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
UBO_LITE = "ddkjiahejlhfcafbddmgiahcphecmpfh"


@dataclass(frozen=True)
class Browser:
    id: str
    name: str
    cls: str
    blocking: str
    facts: tuple[Fact, ...] = ()
    blocker: str = ""
    no_ublock: bool = False
    desktop: tuple[str, ...] = ()
    appimage: tuple[re.Pattern, ...] = ()
    profiles: dict = field(default_factory=dict)
    why: str = ""
    verify: str = ""

    def matches_appimage(self, filename: str) -> bool:
        return any(p.search(filename) for p in self.appimage)


@dataclass(frozen=True)
class BrowserData:
    browsers: dict[str, Browser]

    def __iter__(self):
        return iter(self.browsers.values())

    def __getitem__(self, bid: str) -> Browser:
        return self.browsers[bid]

    def by_desktop(self, desktop_id: str) -> Browser | None:
        return next((b for b in self if desktop_id in b.desktop), None)

    def by_appimage(self, filename: str) -> Browser | None:
        return next((b for b in self if b.matches_appimage(filename)), None)


def default_path() -> Path:
    env = os.environ.get("DAPRIVACYSCANNER_BROWSERS")
    if env:
        return Path(env)
    repo = Path(__file__).resolve().parents[2] / DATA_NAME
    if repo.is_file():
        return repo
    return Path(str(resources.files(__package__) / DATA_NAME))


@functools.lru_cache(maxsize=4)
def load(path: Path | str | None = None) -> BrowserData:
    path = Path(path) if path else default_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise DataError(f"cannot read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise DataError(f"{path} is not valid YAML: {e}") from e
    return parse(data)


_KEYS = {"id", "name", "class", "blocking", "blocker", "no_ublock", "profiles", "detect", "facts", "why", "verify"}


def parse(data: Any) -> BrowserData:
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise DataError(f"{DATA_NAME}: unsupported schema_version")
    out: dict[str, Browser] = {}
    seen_desktop: dict[str, str] = {}
    for i, b in enumerate(data.get("browsers") or []):
        if not isinstance(b, dict) or not isinstance(b.get("id"), str) or not isinstance(b.get("name"), str):
            raise DataError(f"browsers[{i}]: needs an id and a name")
        where = f"browsers.{b['id']}"
        if set(b) - _KEYS:
            raise DataError(f"{where}: unknown keys {', '.join(sorted(set(b) - _KEYS))}")
        if b["id"] in out:
            raise DataError(f"{where}: duplicate id")
        if b.get("class") not in CLASSES:
            raise DataError(f"{where}: class must be one of {', '.join(CLASSES)}")
        if b.get("blocking") not in BLOCKING:
            raise DataError(f"{where}: blocking must be one of {', '.join(BLOCKING)}")
        if b["blocking"] == "builtin" and not b.get("blocker"):
            raise DataError(f"{where}: a built-in blocker needs a name (blocker)")
        if b["class"] in ("surveillance", "closed_ui") and not b.get("facts"):
            raise DataError(f"{where}: a browser judged {b['class']} needs facts that show why")
        d = b.get("detect") or {}
        if not isinstance(d, dict) or set(d) - {"desktop", "appimage"}:
            raise DataError(f"{where}.detect: only desktop and appimage")
        desktop = _strs(d.get("desktop"), f"{where}.detect.desktop")
        for name in desktop:
            if name in seen_desktop:
                raise DataError(f"{where}: {name} is also {seen_desktop[name]}'s")
            seen_desktop[name] = b["id"]
        try:
            appimage = tuple(re.compile(p, re.I) for p in _strs(d.get("appimage"), f"{where}.detect.appimage"))
        except re.error as e:
            raise DataError(f"{where}.detect.appimage: {e}") from None
        prof = b.get("profiles") or {}
        if not isinstance(prof, dict) or set(prof) - {"chromium", "mozilla"} or len(prof) > 1:
            raise DataError(f"{where}.profiles: {{chromium: <name>}} or {{mozilla: <name>}}")
        out[b["id"]] = Browser(
            id=b["id"], name=b["name"], cls=b["class"], blocking=b["blocking"],
            facts=_facts(b["facts"], where, TOPICS) if b.get("facts") else (),
            blocker=str(b.get("blocker") or ""), no_ublock=bool(b.get("no_ublock")), desktop=desktop,
            appimage=appimage, profiles=dict(prof), why=" ".join(str(b.get("why") or "").split()),
            verify=" ".join(str(b.get("verify") or "").split()))
    if not out:
        raise DataError(f"{DATA_NAME}: no browsers")
    return BrowserData(out)


# ------------------------------------------------------------------ menu entries

@dataclass(frozen=True)
class DesktopEntry:
    id: str                   # the file name: firefox.desktop
    path: Path
    name: str
    exec: str
    categories: tuple[str, ...]
    mimetypes: tuple[str, ...]
    no_display: bool = False  # NoDisplay=true: not in the menu (a helper, such as Fedora's installer's "Browser External")

    @property
    def is_browser(self) -> bool:
        return "WebBrowser" in self.categories or "x-scheme-handler/https" in self.mimetypes

    @property
    def appimage(self) -> str | None:
        """The AppImage this entry starts, if it starts one."""
        m = re.search(r"""(?:^|\s|["'])(/\S+?\.appimage)\b""", self.exec, re.I)
        return m.group(1) if m else None


def read_desktop_entry(path: Path, text: str) -> DesktopEntry | None:
    groups = ini.parse(text)
    e = groups.get(("Desktop Entry",)) or {}
    if not e or e.get("Type", "Application") != "Application" or e.get("Hidden", "").lower() == "true":
        return None
    split = lambda v: tuple(x for x in (v or "").split(";") if x)  # noqa: E731
    return DesktopEntry(path.name, path, e.get("Name", path.stem), e.get("Exec", ""), split(e.get("Categories")),
                        split(e.get("MimeType")), e.get("NoDisplay", "").lower() == "true")


def mimeapps_default(text: str) -> str | None:
    """The https handler in a mimeapps.list: the first entry of [Default Applications]."""
    groups = ini.parse(text)
    for key in ("x-scheme-handler/https", "x-scheme-handler/http"):
        v = (groups.get(("Default Applications",)) or {}).get(key)
        if v:
            return v.split(";")[0].strip() or None
    return None
