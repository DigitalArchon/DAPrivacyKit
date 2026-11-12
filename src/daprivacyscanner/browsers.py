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


FAMILIES = ("chromium", "mozilla")
# a default the browser's table doesn't give: the checks say they couldn't tell, never assume upstream's
UNKNOWN = object()
# a default that depends on the country or language the browser runs in (Firefox Suggest, sponsored shortcuts)
REGION = "region"


@dataclass(frozen=True)
class ProfileFolder:
    """Where one browser (or one edition of it: Chrome Beta, Brave Nightly) keeps its profiles, natively, in its Flatpak
    and in its Snap. The one registry of browser profile locations: the checks read every browser listed here."""
    name: str                   # as the checks show it: "Google Chrome Beta", "Zen"
    family: str                 # chromium (a user data folder) or mozilla (a profiles.ini root)
    browser: str                # its browsers.yaml id
    home: str = ""              # a folder in the home folder (Firefox-family dot folders: .mozilla/firefox)
    config: str = ""            # a folder in ~/.config (a Chromium user data folder; the XDG root of Firefox 147+)
    flatpak: str = ""           # its Flatpak id: the same folders in the Flatpak's own home and config
    snap: str = ""              # its snap name
    snap_dir: str = ""          # a Chromium snap's user data folder inside the snap's folders


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
    family: str = ""                    # chromium | mozilla: the profiles the checks read; "" when they read none
    folders: tuple[ProfileFolder, ...] = ()
    unchecked: str = ""                 # why the checks don't read its profiles (shown to the user)
    defaults: dict = field(default_factory=dict)    # the settings the checks read, as the browser ships them
    inherits: str = ""                  # the browser whose defaults fill in the rest of this one's (a fork's upstream)
    defaults_source: str = ""
    why: str = ""
    verify: str = ""

    def matches_appimage(self, filename: str) -> bool:
        return any(p.search(filename) for p in self.appimage)

    @property
    def profiles(self) -> dict[str, list[str]]:
        """{family: the names of its profile folders}, {} when its profiles aren't read."""
        return {self.family: [f.name for f in self.folders]} if self.family else {}


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

    def folders(self, family: str) -> list[ProfileFolder]:
        """Every profile folder of a family, in the file's order (the first of those sharing a folder names it)."""
        return [f for b in self for f in b.folders if f.family == family]

    def by_folder(self, name: str) -> Browser | None:
        """The browser a profile folder (by its name: "Brave Beta", "Zen") belongs to."""
        return next((b for b in self for f in b.folders if f.name == name), None)

    def default(self, bid: str, key: str):
        """What a browser ships a setting the checks read as: its own table, then the one it inherits from;
        UNKNOWN when neither gives it (a fork whose defaults weren't read, a setting not in its table)."""
        seen = set()
        while bid and bid in self.browsers and bid not in seen:
            seen.add(bid)
            b = self.browsers[bid]
            if key in b.defaults:
                return b.defaults[key]
            bid = b.inherits
        return UNKNOWN


def family_names(family: str, data: BrowserData | None = None) -> tuple[str, ...]:
    """The names of every profile folder of a family ("Firefox", "LibreWolf", "Zen"...), for the readers."""
    data = data or load()
    return tuple(dict.fromkeys(f.name for f in data.folders(family)))


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


_KEYS = {"id", "name", "class", "blocking", "blocker", "no_ublock", "profiles", "defaults", "detect", "facts", "why",
         "verify"}
_FOLDER_KEYS = {"name", "home", "config", "flatpak", "snap", "snap_dir"}
_REL = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._ /-]{1,80}$")


def _profiles(raw: Any, where: str, bid: str) -> tuple[str, tuple[ProfileFolder, ...], str]:
    """(family, folders, why unchecked) from a browser's `profiles`: {family, folders} or {unchecked: why}."""
    if not isinstance(raw, dict) or not raw:
        raise DataError(f"{where}.profiles: {{family, folders}} or {{unchecked: why}}: every browser says where its "
                        "profiles are, or why the checks don't read them")
    if set(raw) == {"unchecked"}:
        why = " ".join(str(raw["unchecked"] or "").split())
        if not why:
            raise DataError(f"{where}.profiles.unchecked: say why")
        return "", (), why
    if set(raw) - {"family", "folders"} or raw.get("family") not in FAMILIES:
        raise DataError(f"{where}.profiles: family must be one of {', '.join(FAMILIES)}, with folders")
    folders = []
    for i, f in enumerate(raw.get("folders") or []):
        w = f"{where}.profiles.folders[{i}]"
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or set(f) - _FOLDER_KEYS:
            raise DataError(f"{w}: a name and some of {', '.join(sorted(_FOLDER_KEYS - {'name'}))}")
        vals = {k: str(f.get(k) or "") for k in _FOLDER_KEYS}
        for k in ("home", "config", "snap_dir"):
            if vals[k] and not _REL.match(vals[k]):
                raise DataError(f"{w}.{k}: a relative path")
        if not (vals["home"] or vals["config"]):
            raise DataError(f"{w}: needs home or config")
        if raw["family"] == "chromium" and (vals["home"] or not vals["config"]):
            raise DataError(f"{w}: a Chromium user data folder is in ~/.config (config)")
        folders.append(ProfileFolder(vals["name"], raw["family"], bid, vals["home"], vals["config"], vals["flatpak"],
                                     vals["snap"], vals["snap_dir"]))
    if not folders:
        raise DataError(f"{where}.profiles: needs folders")
    return raw["family"], tuple(folders), ""


def _defaults(raw: Any, where: str) -> tuple[dict, str, str]:
    """(settings, the browser it inherits the rest from, where they were read) from a browser's `defaults`."""
    if raw is None:
        return {}, "", ""
    if not isinstance(raw, dict) or set(raw) - {"inherits", "source", "verified", "settings"}:
        raise DataError(f"{where}.defaults: inherits, settings, source, verified")
    if not str(raw.get("source", "")).startswith("https://") or not raw.get("verified"):
        raise DataError(f"{where}.defaults: needs the source it was read from (https) and the date (verified)")
    settings = raw.get("settings") or {}
    if not isinstance(settings, dict):
        raise DataError(f"{where}.defaults.settings: a mapping")
    return dict(settings), str(raw.get("inherits") or ""), str(raw["source"])


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
        family, folders, unchecked = _profiles(b.get("profiles"), where, b["id"])
        defaults, inherits, source = _defaults(b.get("defaults"), where)
        out[b["id"]] = Browser(
            id=b["id"], name=b["name"], cls=b["class"], blocking=b["blocking"],
            facts=_facts(b["facts"], where, TOPICS) if b.get("facts") else (),
            blocker=str(b.get("blocker") or ""), no_ublock=bool(b.get("no_ublock")), desktop=desktop,
            appimage=appimage, family=family, folders=folders, unchecked=unchecked, defaults=defaults,
            inherits=inherits, defaults_source=source, why=" ".join(str(b.get("why") or "").split()),
            verify=" ".join(str(b.get("verify") or "").split()))
    if not out:
        raise DataError(f"{DATA_NAME}: no browsers")
    names: dict[str, str] = {}
    for b in out.values():
        if b.inherits and (b.inherits not in out or out[b.inherits].family != b.family):
            raise DataError(f"browsers.{b.id}.defaults.inherits: a browser of the same family")
        for f in b.folders:
            if f.name in names:
                raise DataError(f"browsers.{b.id}: the profile folder name {f.name} is also {names[f.name]}'s")
            names[f.name] = b.id
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
