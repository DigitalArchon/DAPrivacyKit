"""VPN providers: the data in vpn-providers.yaml, and recognising the provider in use from this
machine alone (its interfaces, its daemon, the DNS server it sets in the tunnel, and its own status
command, which asks only the local daemon). Nothing here touches the network."""

from __future__ import annotations

import datetime as dt
import functools
import os
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import network
from .host import Host

DATA_NAME = "vpn-providers.yaml"
SCHEMA_VERSION = 1
TOPICS = ("harm", "client", "owner", "jurisdiction", "account", "payment", "features", "audit", "legal")
TOPIC_TITLES = {"owner": "Who runs it", "jurisdiction": "Where it is based", "account": "Accounts",
                "payment": "Paying", "client": "Its Linux app", "features": "Features",
                "audit": "Independent audits", "legal": "Tested by the courts and police",
                "harm": "Harm on record"}
# what a fact can be evidence for in the rating (vpn-providers.yaml, RATING)
SUPPORTS = ("open_client", "closed_client", "linux_flaw", "harm", "ownership")
CAPS = ("ownership",)
# tiers, best first: key -> what the user sees
TIERS = {"recommended": "Recommended", "good": "Good", "acceptable": "Acceptable",
         "ownership": "Ownership concerns", "closed": "Closed client", "avoid": "Avoid"}
RATED = ("recommended", "good", "acceptable")          # set in the data; the rest follow from gates
STALE_DAYS = 365
# exit checks the online tests know how to ask (vpn-providers.yaml `exit_check`)
EXIT_CHECKS = ("mullvad", "ivpn")


class DataError(ValueError):
    pass


@dataclass(frozen=True)
class Fact:
    topic: str
    text: str
    source: str
    verified: dt.date
    supports: tuple[str, ...] = ()


@dataclass(frozen=True)
class BrowserProxy:
    """The SOCKS5 proxy inside the provider's tunnel that Mullvad Browser's extension is set to when the
    browser tool sets it up for this VPN (vpn-providers.yaml `browser_proxy`)."""
    hostname: str
    address: str
    port: int
    city: str
    country: str
    country_code: str
    source: str
    verified: dt.date

    @property
    def server(self) -> str:
        """As the extension names it: the hostname without "socks5-" and the relays' domain."""
        return self.hostname.replace("socks5-", "").removesuffix(".relays.mullvad.net")


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    facts: tuple[Fact, ...] = ()
    group: str | None = None
    group_name: str | None = None
    group_facts: tuple[Fact, ...] = ()
    interfaces: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()
    resolvers: tuple[str, ...] = ()
    status: tuple[str, ...] = ()
    exit_networks: tuple[str, ...] = ()
    exit_check: str | None = None
    leak_test: str | None = None
    leak_test_verified: dt.date | None = None
    verify: str = ""
    group_cap: str | None = None
    tier: str | None = None             # rating.tier, for one that passes every gate
    why: str = ""                       # rating.why: the app's reasoning, shown as such
    extensions: tuple[str, ...] = ()
    browser_proxy: BrowserProxy | None = None

    def supporting(self, what: str) -> list[Fact]:
        return [f for f in self.all_facts() if what in f.supports]

    def all_facts(self) -> list[Fact]:
        return list(self.facts) + list(self.group_facts)

    def oldest_check(self) -> dt.date | None:
        dates = [f.verified for f in self.all_facts()]
        return min(dates) if dates else None

    def matches_interface(self, name: str) -> bool:
        return any(name.startswith(p[:-1]) if p.endswith("*") else name == p for p in self.interfaces)

    def owns_network(self, holder: str) -> bool:
        h = holder.lower()
        return any(n.lower() in h for n in self.exit_networks)


@dataclass(frozen=True)
class ProviderData:
    providers: dict[str, Provider]
    datacentres: tuple[str, ...]
    public_dns: tuple[str, ...] = ()

    def __iter__(self):
        return iter(self.providers.values())

    def __getitem__(self, pid: str) -> Provider:
        return self.providers[pid]

    def network_owner(self, holder: str) -> Provider | None:
        """The provider that runs the network named `holder` (from an address-owner lookup)."""
        return next((p for p in self if p.owns_network(holder)), None)

    def is_datacentre(self, holder: str) -> bool:
        h = holder.lower()
        return any(d.lower() in h for d in self.datacentres)

    def is_public_dns(self, holder: str) -> bool:
        h = holder.lower()
        return any(d.lower() in h for d in self.public_dns)


# ------------------------------------------------------------------ loading

def default_path() -> Path:
    """$DAPRIVACYSCANNER_VPN_PROVIDERS, else the copy at the repository root (development), else one
    packaged with the module."""
    env = os.environ.get("DAPRIVACYSCANNER_VPN_PROVIDERS")
    if env:
        return Path(env)
    repo = Path(__file__).resolve().parents[2] / DATA_NAME
    if repo.is_file():
        return repo
    return Path(str(resources.files(__package__) / DATA_NAME))


@functools.lru_cache(maxsize=4)
def load(path: Path | str | None = None) -> ProviderData:
    path = Path(path) if path else default_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise DataError(f"cannot read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise DataError(f"{path} is not valid YAML: {e}") from e
    return parse(data)


def _strs(v: Any, where: str) -> tuple[str, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise DataError(f"{where} must be a list of strings")
    return tuple(v)


def _date(v: Any, where: str) -> dt.date:
    if isinstance(v, dt.date):
        return v
    raise DataError(f"{where}: verified must be a date (YYYY-MM-DD)")


def _facts(raw: Any, where: str, topics: tuple[str, ...] = TOPICS) -> tuple[Fact, ...]:
    if not isinstance(raw, list) or not raw:
        raise DataError(f"{where}: facts must be a non-empty list")
    out = []
    for i, f in enumerate(raw):
        w = f"{where}.facts[{i}]"
        if not isinstance(f, dict) or not {"topic", "text", "source", "verified"} <= set(f) \
                or set(f) - {"topic", "text", "source", "verified", "supports"}:
            raise DataError(f"{w}: needs exactly topic, text, source and verified (and optionally supports)")
        if f["topic"] not in topics:
            raise DataError(f"{w}: topic must be one of {', '.join(topics)}")
        if not isinstance(f["text"], str) or not f["text"].strip():
            raise DataError(f"{w}: text is empty")
        if not isinstance(f["source"], str) or not f["source"].startswith("https://"):
            raise DataError(f"{w}: source must be an https:// URL")
        supports = _strs(f.get("supports"), f"{w}.supports")
        if set(supports) - set(SUPPORTS):
            raise DataError(f"{w}: supports only {', '.join(SUPPORTS)}")
        out.append(Fact(f["topic"], " ".join(f["text"].split()), f["source"], _date(f["verified"], w), supports))
    return tuple(out)


_PROVIDER_KEYS = {"id", "name", "group", "facts", "rating", "detect", "exit_networks", "exit_check", "leak_test",
                  "verify", "browser_proxy"}
_PROXY_KEYS = {"hostname", "address", "port", "city", "country", "country_code", "source", "verified"}


def _browser_proxy(raw: Any, where: str) -> BrowserProxy | None:
    if raw is None:
        return None
    import ipaddress
    if not isinstance(raw, dict) or set(raw) != _PROXY_KEYS:
        raise DataError(f"{where}: needs exactly {', '.join(sorted(_PROXY_KEYS))}")
    try:
        private = ipaddress.IPv4Address(str(raw["address"])).is_private
    except ValueError:
        private = False
    if not private:
        raise DataError(f"{where}.address: a private IPv4 address, inside the tunnel")
    if not isinstance(raw["port"], int) or not 0 < raw["port"] < 65536:
        raise DataError(f"{where}.port: a port number")
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", str(raw["hostname"])) or \
            not re.fullmatch(r"[a-z]{2}", str(raw["country_code"])) or \
            not all(isinstance(raw[k], str) and raw[k] for k in ("city", "country")):
        raise DataError(f"{where}: hostname, city, country and a two-letter country_code")
    if not str(raw["source"]).startswith("https://"):
        raise DataError(f"{where}.source: an https:// page")
    return BrowserProxy(raw["hostname"], str(raw["address"]), raw["port"], raw["city"], raw["country"],
                        raw["country_code"], raw["source"], _date(raw["verified"], where))
_DETECT_KEYS = {"interfaces", "processes", "resolvers", "status", "extensions"}


def parse(data: Any) -> ProviderData:
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise DataError(f"{DATA_NAME}: unsupported schema_version")
    groups: dict[str, tuple[str, tuple[Fact, ...], str | None]] = {}
    for gid, g in (data.get("groups") or {}).items():
        if not isinstance(g, dict) or not isinstance(g.get("name"), str):
            raise DataError(f"groups.{gid}: needs a name")
        if g.get("cap") is not None and g["cap"] not in CAPS:
            raise DataError(f"groups.{gid}: cap must be one of {', '.join(CAPS)}")
        facts = _facts(g.get("facts"), f"groups.{gid}")
        if g.get("cap") and not any(g["cap"] in f.supports for f in facts):
            raise DataError(f"groups.{gid}: a cap needs facts that support it")
        groups[gid] = (g["name"], facts, g.get("cap"))
    providers: dict[str, Provider] = {}
    for i, p in enumerate(data.get("providers") or []):
        where = f"providers[{i}]"
        if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not isinstance(p.get("name"), str):
            raise DataError(f"{where}: needs an id and a name")
        where = f"providers.{p['id']}"
        unknown = set(p) - _PROVIDER_KEYS
        if unknown:
            raise DataError(f"{where}: unknown keys {', '.join(sorted(unknown))}")
        if p["id"] in providers:
            raise DataError(f"{where}: duplicate id")
        gid = p.get("group")
        if gid is not None and gid not in groups:
            raise DataError(f"{where}: group {gid!r} isn't in groups")
        d = p.get("detect") or {}
        if not isinstance(d, dict) or set(d) - _DETECT_KEYS:
            raise DataError(f"{where}.detect: only {', '.join(sorted(_DETECT_KEYS))}")
        leak = p.get("leak_test")
        if leak is not None and (not isinstance(leak, dict) or not str(leak.get("url", "")).startswith("https://")):
            raise DataError(f"{where}.leak_test: needs an https:// url and verified")
        if p.get("exit_check") is not None and p["exit_check"] not in EXIT_CHECKS:
            raise DataError(f"{where}.exit_check: one of {', '.join(EXIT_CHECKS)}")
        rating = p.get("rating") or {}
        if not isinstance(rating, dict) or set(rating) - {"tier", "why"} or \
                rating.get("tier") not in (None, *RATED):
            raise DataError(f"{where}.rating: {{tier: {' | '.join(RATED)}, why: text}}")
        providers[p["id"]] = Provider(
            id=p["id"], name=p["name"], facts=_facts(p.get("facts"), where), group=gid,
            group_name=groups[gid][0] if gid else None, group_facts=groups[gid][1] if gid else (),
            group_cap=groups[gid][2] if gid else None, tier=rating.get("tier"),
            why=" ".join(str(rating.get("why") or "").split()),
            extensions=_strs(d.get("extensions"), f"{where}.detect.extensions"),
            interfaces=_strs(d.get("interfaces"), f"{where}.detect.interfaces"),
            processes=_strs(d.get("processes"), f"{where}.detect.processes"),
            resolvers=_strs(d.get("resolvers"), f"{where}.detect.resolvers"),
            status=_strs(d.get("status"), f"{where}.detect.status"),
            exit_networks=_strs(p.get("exit_networks"), f"{where}.exit_networks"),
            exit_check=p.get("exit_check"),
            leak_test=leak["url"] if leak else None,
            leak_test_verified=_date(leak.get("verified"), f"{where}.leak_test") if leak else None,
            verify=" ".join(str(p.get("verify") or "").split()),
            browser_proxy=_browser_proxy(p.get("browser_proxy"), f"{where}.browser_proxy"))
    if not providers:
        raise DataError(f"{DATA_NAME}: no providers")
    for p in providers.values():
        _check_rating(p)
    return ProviderData(providers, _strs(data.get("datacentres"), "datacentres"),
                        _strs(data.get("public_dns"), "public_dns"))


# ------------------------------------------------------------------ rating

@dataclass(frozen=True)
class Rating:
    tier: str                           # a TIERS key, or "unrated"
    reasons: tuple[Fact, ...] = ()      # the facts that decided it (gates), or that it rests on (rated tiers)
    closed: bool = False
    capped: bool = False
    harm: bool = False
    owner: str | None = None            # the capped owner's name (Kape Technologies)

    @property
    def label(self) -> str:
        """The tier, naming every gate that applies: "Closed client, and owned by Kape Technologies"."""
        base = TIERS.get(self.tier, "Not rated")
        also = []
        if self.closed and self.tier == "avoid":
            also.append("a closed client")
        if self.capped and self.tier != "ownership":
            also.append(f"owned by {self.owner}")
        if self.tier == "ownership":
            return f"{base}: owned by {self.owner}"
        return base + (f", and {' and '.join(also)}" if also and self.tier == "closed" else
                       f" (also {' and '.join(also)})" if also else "")

    @property
    def concern(self) -> bool:
        """Low enough to count as a finding."""
        return self.tier in ("ownership", "closed", "avoid")

    def findings(self) -> dict[str, bool]:
        """The names the catalogue's severity modifiers use."""
        return {"vpn_avoid": self.harm, "vpn_closed_client": self.closed, "vpn_ownership_concerns": self.capped}


def rate(p: Provider) -> Rating:
    """Gates first (harm, a closed Linux client, an owner capped for its record), then the tier the data
    gives one that passes them all."""
    harm, closed = p.supporting("harm"), p.supporting("closed_client")
    capped = p.supporting("ownership") if p.group_cap == "ownership" else []
    flags = dict(closed=bool(closed), capped=bool(capped), harm=bool(harm), owner=p.group_name if capped else None)
    if harm:
        return Rating("avoid", tuple(harm + closed + capped), **flags)
    if closed:
        return Rating("closed", tuple(closed + capped), **flags)
    if capped:
        return Rating("ownership", tuple(capped), **flags)
    if p.tier:
        return Rating(p.tier, tuple(p.supporting("open_client") + p.supporting("linux_flaw")), **flags)
    return Rating("unrated", (), **flags)


def _check_rating(p: Provider) -> None:
    """The rules in vpn-providers.yaml's RATING, so the data can't contradict them."""
    gated = p.supporting("harm") or p.supporting("closed_client") or p.group_cap
    where = f"providers.{p.id}.rating"
    if p.tier and gated:
        raise DataError(f"{where}: a tier is set, but a gate decides this provider's rating")
    if p.tier and not p.supporting("open_client"):
        raise DataError(f"{where}: a tier needs a fact supporting open_client")
    if p.tier == "recommended" and p.supporting("linux_flaw"):
        raise DataError(f"{where}: recommended, with a fact supporting linux_flaw")
    if p.supporting("open_client") and p.supporting("closed_client"):
        raise DataError(f"providers.{p.id}: facts support both open_client and closed_client")


# ------------------------------------------------------------------ recognising the provider in use

# how sure each kind of sign is, strongest first
SIGNS = ("interface", "resolver", "process")


@dataclass
class Match:
    provider: Provider
    signs: list[tuple[str, str]] = field(default_factory=list)     # (kind, what): ("interface", "wg0-mullvad")
    relay: str | None = None           # the server its own status command names

    @property
    def strength(self) -> int:
        return min((SIGNS.index(k) for k, _ in self.signs), default=len(SIGNS))

    @property
    def in_use(self) -> bool:
        """Its tunnel or in-tunnel DNS is there, not just its daemon."""
        return self.strength < SIGNS.index("process")


def tunnel_resolvers(host: Host, tunnels: list[str]) -> dict[str, list[str]]:
    """DNS servers systemd-resolved has on each tunnel interface (resolvectl status)."""
    r = host.run("resolvectl", "status")
    out: dict[str, list[str]] = {}
    if not r.ok:
        return out
    link = None
    for line in r.stdout.splitlines():
        m = re.match(r"^(Global|Link \d+ \((\S+)\))", line)
        if m:
            link = m.group(2)
            continue
        m = re.search(r"(?:Current )?DNS Servers?:\s*(.+)", line)
        if link in tunnels and m:
            addrs = out.setdefault(link, [])
            addrs += [a for a in (x.split("#")[0] for x in m.group(1).split()) if a not in addrs]
    return out


RELAY = re.compile(r"\b([a-z]{2}-[a-z]{3}-(?:wg|ovpn|br)-\d{3}[a-z]?)\b")


def identify(host: Host, data: ProviderData, processes: set[str] | None = None) -> list[Match]:
    """Providers whose signs are on this machine, the most certain first. Only their own status
    command is run, and only for a provider already recognised another way."""
    ifaces = network._ifaces(host)
    tunnels = network.vpn_links(host)
    resolvers = tunnel_resolvers(host, tunnels) if tunnels else {}
    if processes is None:
        from .checks._util import processes as running
        processes = running(host)
    found: list[Match] = []
    for p in data:
        m = Match(p)
        m.signs += [("interface", i) for i in ifaces if p.matches_interface(i)]
        m.signs += [("resolver", f"{a} on {link}") for link, addrs in resolvers.items() for a in addrs
                    if a in p.resolvers]
        m.signs += [("process", n) for n in p.processes if n[:15] in processes]
        if not m.signs:
            continue
        if p.status and host.runner.which(p.status[0]):
            r = host.run(*p.status, timeout=5)
            relay = RELAY.search(r.stdout) if r.ok else None
            m.relay = relay.group(1) if relay else None
        found.append(m)
    return sorted(found, key=lambda m: (m.strength, m.provider.name))


def stale(p: Provider, today: dt.date | None = None) -> dt.date | None:
    """The oldest date a fact was checked, when it is more than a year ago."""
    oldest = p.oldest_check()
    today = today or dt.date.today()
    return oldest if oldest and (today - oldest).days > STALE_DAYS else None
