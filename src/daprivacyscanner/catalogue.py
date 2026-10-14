"""Loads and validates privacy-checks.yaml, the catalogue of every check, and computes
effective severity from a check's modifiers."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

import yaml

from . import expr
from .model import KINDS

CATALOGUE_NAME = "privacy-checks.yaml"
SCHEMA_VERSION = 1

# The context keys of the catalogue header: allowed literal values for the enumerated ones,
# None for booleans. Kept in step with context.detect_context.
CONTEXT_KEYS: dict[str, frozenset[str] | None] = {
    "fde": frozenset({"none", "home", "partial", "full"}),
    "virtualization": frozenset({"none", "vm", "container"}),
    "device": frozenset({"laptop", "desktop"}),
    "multi_user": None,
    "session": frozenset({"wayland", "x11"}),
    "hibernation": None,
    "tpm_unlock_no_pin": None,
    "autologin": None,
    "exposed_services": None,
    "vpn_active": None,
    "ipv6_global": None,
}

# How the context keys and checks' own findings are named to the user, e.g. in the reason a
# check is not applicable ("disk encryption is none"). The page uses the same words.
CONTEXT_LABEL = {
    "fde": "disk encryption", "virtualization": "virtual machine or container", "device": "device type",
    "multi_user": "several user accounts", "session": "display session", "hibernation": "hibernation possible",
    "tpm_unlock_no_pin": "TPM unlock without a PIN", "autologin": "automatic login",
    "exposed_services": "services exposed to the network", "vpn_active": "VPN connected",
    "ipv6_global": "public IPv6 address",
    "firewall_blocks_exposed": "the firewall blocks the exposed services",
    "thumbnails_reference_removable_or_container": "thumbnails show files from removable or encrypted drives",
    "thumbnails_on_disk_none_leaking": "no thumbnail leaks yet, but the cache is on disk",
    "thumbnails_expire": "the desktop deletes thumbnails within 30 days",
    "security_updates_pending": "security updates are waiting",
    "kernel_update_pending": "a kernel or microcode update is waiting",
    "kernel_restart_pending": "a newer kernel is installed than the one running",
    "signature_checks_off": "a package manager doesn't check signatures for some repositories",
    "unsigned_over_http": "one of them is used over plain HTTP",
    "home_ecryptfs": "the home folder is encrypted with eCryptfs",
    "indexes_outside_home": "file search indexes removable drives or other volumes",
    "index_on_unencrypted_disk": "the file search index is on an unencrypted disk",
    "data_on_encrypted_disk": "it is kept on an encrypted disk",
    "vpn_avoid": "the VPN provider has harm on record",
    "vpn_closed_client": "the VPN's Linux app is closed source",
    "vpn_ownership_concerns": "the VPN's owner has a record that is hard to trust",
    "chrome_or_edge_installed": "Chrome or Edge is installed",
    "surveillance_default": "the default browser is Chrome, Edge, Opera or Yandex",
    "chrome_or_edge_default": "the default browser is Chrome or Edge",
    "default_closed_ui": "the default browser's interface is closed source",
    "agent_forwarded_everywhere": "every server you log in to gets your SSH agent",
    "host_keys_unchecked": "ssh doesn't check that servers are who they claim",
    "agent_keys_unlimited": "keys stay in the SSH agent until you log out",
    "sshd_reachable": "an SSH server is listening for other machines",
    "weak_authorized_keys": "a weak key can log in as you",
    "gpg_weak_key": "one of your GnuPG keys is weak",
    "site_default_allow": "a browser lets every website use the camera, microphone or location",
}

CATEGORY_PREFIX = {
    "encryption": "enc", "auth": "auth", "network": "net", "telemetry": "tel", "browser": "br",
    "desktop": "desk", "apps": "app", "sandbox": "sbx", "kernel": "kern",
}
CATEGORY_TITLE = {
    "encryption": "Encryption and data at rest", "auth": "Authentication, sessions and secrets",
    "network": "Network exposure and tracking", "telemetry": "Telemetry and phone-home",
    "browser": "Browsers", "desktop": "Desktop activity tracking", "apps": "Applications",
    "sandbox": "Sandboxing and permissions", "kernel": "Kernel and physical attack surface",
}


class Scope(str, Enum):
    USER = "user"
    SYSTEM = "system"
    ONLINE = "online"          # contacts other machines: only run when the user starts online tests


class Tier(str, Enum):
    AUTO = "auto"
    GUIDED = "guided"
    ADVICE = "advice"
    FEATURE = "feature"


class CatalogueError(ValueError):
    pass


@dataclass(frozen=True)
class Modifier:
    when: expr.Expr
    severity: int


@dataclass(frozen=True)
class Easy:
    """An Easy fix (the catalogue's `easy`): applied with the others after one confirmation."""
    option: str = ""                         # guided: the key of the guide's option(s) it applies
    cost: str = ""                           # what the user gives up, in plain words ("" = nothing worth saying)

    def to_dict(self) -> dict:
        return {"option": self.option, "cost": self.cost}


@dataclass(frozen=True)
class Meanwhile:
    """What to do until a check the app can't fix is fixed (the catalogue's `meanwhile`)."""
    text: str
    checks: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"text": self.text, "checks": list(self.checks)}


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    category: str
    severity: int
    scope: Scope
    tier: Tier
    detect: tuple[str, ...]
    fix: str                                 # how the fix works: developer notes (shown with --dev)
    remedy: str = ""                         # what to do, in plain words, for the user
    modifiers: tuple[Modifier, ...] = ()
    applies_to: tuple[str, ...] = ()
    why: str = ""
    related: tuple[str, ...] = ()
    verify: str = ""
    contacts: tuple[str, ...] = ()           # online checks: who they contact and what that one learns
    kind: str = "finding"                    # finding | hygiene | info (model.KINDS)
    easy: Easy | None = None
    meanwhile: Meanwhile | None = None
    # a warning (a Risk on the page: possible, partial or not yet happened) is this much lower than the
    # same check failing (a Problem) in the same context, never below 1 (as_warning)
    warn_lower: int = 2

    @property
    def finding_names(self) -> frozenset[str]:
        """Names in `when` expressions that are produced by the check itself."""
        names: set[str] = set()
        for m in self.modifiers:
            names |= m.when.names
        return frozenset(names - CONTEXT_KEYS.keys())

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "category": self.category, "severity": self.severity,
            "scope": self.scope.value, "tier": self.tier.value, "detect": list(self.detect), "fix": self.fix,
            "remedy": self.remedy,
            "modifiers": [{"when": m.when.source, "when_text": describe_when(m.when), "severity": m.severity}
                          for m in self.modifiers],
            "applies_to": list(self.applies_to), "why": self.why, "related": list(self.related),
            "warn_lower": self.warn_lower,
            "verify": self.verify, "contacts": list(self.contacts), "kind": self.kind,
            "easy": self.easy.to_dict() if self.easy else None,
            "meanwhile": self.meanwhile.to_dict() if self.meanwhile else None,
        }


@dataclass(frozen=True)
class Catalogue:
    schema_version: int
    checks: dict[str, CheckSpec]            # in file order
    source: str = ""

    def __iter__(self):
        return iter(self.checks.values())

    def __len__(self):
        return len(self.checks)

    def __getitem__(self, check_id: str) -> CheckSpec:
        return self.checks[check_id]


@dataclass(frozen=True)
class Severity:
    """A check's effective severity. `uncertain_on` lists the names whose unknown value could
    have changed it (a modifier after the deciding one couldn't be evaluated)."""
    value: int
    base: int
    modifier: str | None = None              # the `when` that decided it, None for the base
    uncertain_on: tuple[str, ...] = ()
    as_warning: bool = False                 # lowered because the check warned rather than failed

    @property
    def not_applicable(self) -> bool:
        return self.value == 0 and not self.uncertain_on


def effective_severity(spec: CheckSpec, values: Mapping[str, Any]) -> Severity:
    """Base severity, overridden by the LAST matching modifier. A modifier whose condition is
    unknown is not applied: severity then stays what the known values give, and the result
    says which names it was uncertain on."""
    value, decided_by, unknown_after = spec.severity, None, set()
    for m in spec.modifiers:
        hit = m.when.evaluate(values)
        if hit is True:
            value, decided_by, unknown_after = m.severity, m.when.source, set()
        elif hit is None:
            unknown_after |= {n for n in m.when.names if values.get(n) is None}
    return Severity(value, spec.severity, decided_by, tuple(sorted(unknown_after)))


def as_warning(spec: CheckSpec, sev: Severity) -> Severity:
    """The severity of a warning: what the same check failing would have here, lowered by its
    `warn_lower` (at least 2), never below 1. Not applicable stays not applicable. A warning is
    a risk (possible, partial, or not yet happened); a failure is the problem itself, so a risk is
    always rated below the problem it could become, and the one number ranks both."""
    if sev.value <= 0:
        return sev
    return replace(sev, value=max(1, sev.value - spec.warn_lower), as_warning=True)


# the values a context key takes, in words (the page's ENUM_LABEL says the same)
VALUE_LABEL = {"none": "none", "home": "home folder only", "partial": "partial", "full": "full", "laptop": "laptop",
               "desktop": "desktop", "wayland": "Wayland", "x11": "X11", "vm": "a virtual machine", "container": "a container"}


def describe_when(e: expr.Expr) -> str:
    """A `when` expression in words: "device == 'desktop' and not multi_user" ->
    "device type is desktop and not several user accounts"."""
    def word(n: expr.Node) -> str:
        if n.kind == "name":
            return CONTEXT_LABEL.get(n.value, n.value.replace("_", " "))
        if n.kind == "lit":
            return str(n.value).lower() if isinstance(n.value, bool) else VALUE_LABEL.get(str(n.value), str(n.value))
        if n.kind == "not":
            return "not " + word(n.args[0])
        if n.kind == "ne" and n.args[1].kind == "lit" and n.args[1].value == "none":
            return word(n.args[0])                        # "virtualization != 'none'": "virtual machine or container"
        if n.kind in ("eq", "ne"):
            return f"{word(n.args[0])} {'is' if n.kind == 'eq' else 'is not'} {word(n.args[1])}"
        return f"({word(n.args[0])} {n.kind} {word(n.args[1])})"
    text = word(e.root)
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def modifier_states(spec: CheckSpec, values: Mapping[str, Any]) -> list[bool | None]:
    """Each modifier's condition: True, False, or None when unknown."""
    return [m.when.evaluate(values) for m in spec.modifiers]


# ------------------------------------------------------------------ loading

_ID = re.compile(r"^([a-z]+)\.([a-z0-9_]+)$")
_REQUIRED = ("id", "title", "category", "severity", "scope", "tier", "detect", "fix", "remedy")
_OPTIONAL = ("modifiers", "applies_to", "why", "related", "verify", "contacts", "kind", "easy", "meanwhile", "warn_lower")
_KEY = re.compile(r"^[a-z0-9_]+$")


def default_path() -> Path:
    """$DAPRIVACYSCANNER_CATALOGUE, else the copy at the repository root (development), else
    one packaged with the module."""
    env = os.environ.get("DAPRIVACYSCANNER_CATALOGUE")
    if env:
        return Path(env)
    repo = Path(__file__).resolve().parents[2] / CATALOGUE_NAME
    if repo.is_file():
        return repo
    return Path(str(resources.files(__package__) / CATALOGUE_NAME))


def load(path: Path | str | None = None) -> Catalogue:
    path = Path(path) if path else default_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise CatalogueError(f"cannot read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise CatalogueError(f"{path} is not valid YAML: {e}") from e
    return parse(data, source=str(path))


def parse(data: Any, source: str = "") -> Catalogue:
    if not isinstance(data, dict):
        raise CatalogueError("catalogue must be a mapping")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise CatalogueError(f"unsupported schema_version {data.get('schema_version')!r} (expected {SCHEMA_VERSION})")
    raw = data.get("checks")
    if not isinstance(raw, list) or not raw:
        raise CatalogueError("`checks` must be a non-empty list")

    errors: list[str] = []
    checks: dict[str, CheckSpec] = {}
    for i, entry in enumerate(raw):
        where = f"checks[{i}]" + (f" ({entry.get('id')})" if isinstance(entry, dict) and entry.get("id") else "")
        try:
            spec = _parse_check(entry)
        except CatalogueError as e:
            errors.append(f"{where}: {e}")
            continue
        if spec.id in checks:
            errors.append(f"{where}: duplicate id {spec.id}")
        checks[spec.id] = spec

    for spec in checks.values():
        for rel in spec.related:
            if rel not in checks:
                errors.append(f"{spec.id}: related id {rel!r} is not in the catalogue")
        for other in spec.meanwhile.checks if spec.meanwhile else ():
            if other not in checks:
                errors.append(f"{spec.id}: meanwhile id {other!r} is not in the catalogue")
            elif other == spec.id:
                errors.append(f"{spec.id}: meanwhile lists the check itself")
    if errors:
        raise CatalogueError("invalid catalogue:\n  " + "\n  ".join(errors))
    return Catalogue(data["schema_version"], checks, source)


def _parse_check(e: Any) -> CheckSpec:
    if not isinstance(e, dict):
        raise CatalogueError("entry must be a mapping")
    missing = [k for k in _REQUIRED if k not in e]
    if missing:
        raise CatalogueError(f"missing {', '.join(missing)}")
    unknown = sorted(set(e) - set(_REQUIRED) - set(_OPTIONAL))
    if unknown:
        raise CatalogueError(f"unknown field(s) {', '.join(unknown)}")

    check_id, category = e["id"], e["category"]
    m = _ID.match(str(check_id))
    if not m:
        raise CatalogueError(f"id {check_id!r} is not '<prefix>.<name>'")
    if category not in CATEGORY_PREFIX:
        raise CatalogueError(f"unknown category {category!r}")
    if m.group(1) != CATEGORY_PREFIX[category]:
        raise CatalogueError(f"id prefix {m.group(1)!r} does not match category {category!r}")
    severity = _severity(e["severity"], "severity")
    try:
        scope, tier = Scope(e["scope"]), Tier(e["tier"])
    except ValueError as err:
        raise CatalogueError(str(err)) from None

    modifiers = []
    for j, mod in enumerate(e.get("modifiers") or []):
        if not isinstance(mod, dict) or set(mod) != {"when", "severity"}:
            raise CatalogueError(f"modifiers[{j}] must have exactly `when` and `severity`")
        try:
            when = expr.parse(str(mod["when"]))
        except expr.ExprError as err:
            raise CatalogueError(f"modifiers[{j}].when: {err}") from None
        for name, literal in when.comparisons():
            allowed = CONTEXT_KEYS.get(name)
            if name in CONTEXT_KEYS and (allowed is None or literal not in allowed):
                raise CatalogueError(f"modifiers[{j}].when compares {name} with {literal!r}, "
                                     f"which it can never be")
        modifiers.append(Modifier(when, _severity(mod["severity"], f"modifiers[{j}].severity")))

    contacts = tuple(_text(c) for c in _list(e.get("contacts"), "contacts"))
    if (scope is Scope.ONLINE) != bool(contacts):
        raise CatalogueError("online checks must list who they contact (`contacts`), and only they may")
    kind = e.get("kind", "finding")
    if kind not in KINDS:
        raise CatalogueError(f"kind must be one of {', '.join(KINDS)}, not {kind!r}")

    easy = _easy(e.get("easy"), tier)
    warn_lower = e.get("warn_lower", 2)
    if not isinstance(warn_lower, int) or isinstance(warn_lower, bool) or not 2 <= warn_lower <= 10:
        raise CatalogueError(f"warn_lower must be a whole number from 2 to 10, not {warn_lower!r}")
    meanwhile = None
    if e.get("meanwhile") is not None:
        mw = e["meanwhile"]
        if not isinstance(mw, dict) or set(mw) != {"text", "checks"}:
            raise CatalogueError("meanwhile must have exactly `text` and `checks`")
        if tier is not Tier.ADVICE:
            raise CatalogueError("meanwhile is for advice checks, which the app can't fix")
        ids = tuple(str(c) for c in _list(mw["checks"], "meanwhile.checks"))
        if not ids or len(set(ids)) != len(ids):
            raise CatalogueError("meanwhile.checks must list checks, each once")
        meanwhile = Meanwhile(_text(mw["text"]), ids)

    return CheckSpec(
        id=check_id, title=_text(e["title"]), category=category, severity=severity, scope=scope, tier=tier,
        detect=tuple(_text(d) for d in _list(e["detect"], "detect")), fix=_text(e["fix"]), remedy=_text(e["remedy"]),
        modifiers=tuple(modifiers), applies_to=tuple(_text(a) for a in _list(e.get("applies_to"), "applies_to")),
        why=_text(e.get("why") or ""), related=tuple(_list(e.get("related"), "related")),
        verify=_text(e.get("verify") or ""), contacts=contacts, kind=kind, easy=easy, meanwhile=meanwhile,
        warn_lower=warn_lower,
    )


def _easy(v: Any, tier: Tier) -> Easy | None:
    if v is None or v is False:
        return None
    if tier not in (Tier.AUTO, Tier.GUIDED):
        raise CatalogueError("easy is for auto and guided checks only")
    if v is True:
        v = {}
    if not isinstance(v, dict) or set(v) - {"option", "cost"}:
        raise CatalogueError("easy must be true, or have only `option` and `cost`")
    option, cost = str(v.get("option") or ""), _text(v.get("cost") or "")
    if tier is Tier.GUIDED and not _KEY.match(option):
        raise CatalogueError("easy on a guided check must name the guide's option key (`option`)")
    if tier is Tier.AUTO and option:
        raise CatalogueError("easy on an auto check applies its fix: it takes no `option`")
    return Easy(option, cost)


def _severity(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 10:
        raise CatalogueError(f"{what} must be an integer 0-10, not {v!r}")
    return v


def _list(v: Any, what: str) -> list:
    if v is None:
        return []
    if not isinstance(v, list):
        raise CatalogueError(f"{what} must be a list")
    return v


def _text(v: Any) -> str:
    return " ".join(str(v).split()) if isinstance(v, str) and "\n" in v else str(v).strip()
