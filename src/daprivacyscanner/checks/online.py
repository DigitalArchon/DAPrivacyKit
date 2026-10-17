"""Online tests (scope: online). They run only when the user starts them, after seeing every host
each one contacts (`hosts()`, from the settings in use), and reach the network only through
scan.net. Results never leave the machine."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import urllib.parse
import xml.etree.ElementTree as ET
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

from .. import network as net
from .. import vpn
from ..model import Evidence, Note, Outcome, Status
from ..online import host_of, is_lan
from ..privileged import HelperError
from . import Check, Scan, register
from .network import local_roots  # noqa: F401 (the guide imports it from here too)
from .kernel import (DNF5_NO_RUNTIME, dnf5_away_from_home, dnf_security, is_dnf5, kernel_restart,
                     no_pass_when_unsupported, package_names, updates_outcome)
from ._util import absent, children, failed, installed, passed, unknown, warned


class OnlineCheck(Check):
    def hosts(self, settings: dict) -> list[str]:
        """Who this test contacts with these settings, shown before it runs."""
        return []

    def detect(self, scan: Scan) -> Outcome:
        if scan.net is None or scan.online is None:
            return unknown("Online tests run only when you start them.")
        return self.detect_online(scan)

    def detect_online(self, scan: Scan) -> Outcome:
        raise NotImplementedError


def _resolved_dot(scan: Scan) -> str | None:
    """systemd-resolved's DNSOverTLS mode when it is the system resolver and DoT is on."""
    from .network import resolved_links
    servers = re.findall(r"^\s*nameserver\s+(\S+)", scan.host.read_sys("/etc/resolv.conf") or "", re.M)
    if not any(s.startswith("127.0.0.53") for s in servers):
        return None
    modes = {s["dot"] for s in resolved_links(scan.host).values() if s["dot"] and s["dot"] != "no"}
    return "yes" if "yes" in modes else "opportunistic" if modes else None


# ------------------------------------------------------------------ observed traffic

# known phone-home hosts: (name, or a suffix starting with ".", what it is, the check that turns it off)
# VERIFY: keep this list current
PHONE_HOME = (
    ("incoming.telemetry.mozilla.org", "Firefox telemetry", "tel.browser_telemetry"),
    ("normandy.cdn.mozilla.net", "Firefox studies", "tel.browser_telemetry"),
    ("detectportal.firefox.com", "Firefox captive-portal check", "net.connectivity_check"),
    ("p3a-json.brave.com", "Brave P3A analytics", "tel.browser_telemetry"),
    (".p3a.brave.com", "Brave P3A analytics", "tel.browser_telemetry"),
    ("usage-ping.brave.com", "Brave daily usage ping", "tel.browser_telemetry"),
    ("connectivity-check.ubuntu.com", "Ubuntu connectivity check", "net.connectivity_check"),
    ("nmcheck.gnome.org", "GNOME connectivity check", "net.connectivity_check"),
    ("networkcheck.kde.org", "KDE connectivity check", "net.connectivity_check"),
    ("ping.archlinux.org", "Arch Linux connectivity check", "net.connectivity_check"),
    ("conncheck.opensuse.org", "openSUSE connectivity check", "net.connectivity_check"),
    ("daisy.ubuntu.com", "Ubuntu crash report upload", "tel.crash_reporters"),
    ("metrics.ubuntu.com", "Ubuntu usage report", "tel.crash_reporters"),
    ("popcon.debian.org", "popularity-contest", "tel.crash_reporters"),
    ("popcon.ubuntu.com", "popularity-contest", "tel.crash_reporters"),
    ("dc.services.visualstudio.com", "Microsoft / VS Code telemetry", "tel.devtools"),
    ("mobile.events.data.microsoft.com", "Microsoft / VS Code telemetry", "tel.devtools"),
    ("default.exp-tas.com", "VS Code experiments", "tel.devtools"),
    ("beacondb.net", "Location lookup (GeoClue)", "tel.location"),
    ("api.beacondb.net", "Location lookup (GeoClue)", "tel.location"),
    ("location.services.mozilla.com", "Location lookup (GeoClue)", "tel.location"),
    ("motd.ubuntu.com", "Ubuntu message-of-the-day news", None),
)
OBSERVE_CHUNK = 5        # seconds per helper request, so a stop takes effect quickly
TELEMETRY_LIKE = re.compile(r"(^|\.)(telemetry|metrics|analytics|crashreports?|stats)[.-]", re.I)


def phone_home(name: str) -> tuple[str, str | None] | None:
    name = name.rstrip(".").lower()
    for pattern, label, check in PHONE_HOME:
        if name == pattern or (pattern.startswith(".") and name.endswith(pattern)):
            return label, check
    return None


def _peer(addr: str) -> str | None:
    host = addr.rpartition(":")[0].strip("[]").split("%")[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_private or ip.is_unspecified:
        return None
    return str(ip)


def ss_connections(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] not in ("tcp", "udp"):
            continue
        peer = _peer(f[5])
        if peer is None:
            continue
        proc = re.search(r'\(\("([^"]+)"', line)
        out.append({"process": proc.group(1) if proc else "", "peer": peer, "proto": f[0]})
    return out


@register
class ObservedTraffic(OnlineCheck):
    id = "tel.observed_traffic"

    def hosts(self, settings):
        return ["nobody (it watches); without administrator access, your DNS resolver sees lookups of the known "
                "phone-home host names"]

    def detect_online(self, scan: Scan) -> Outcome:
        seconds = int(scan.online.get("observe_seconds", 60))
        names_by_ip: dict[str, set[str]] = {}
        asked: dict[str, int] = {}
        conns: list[dict] = []
        partial = False
        if scan.privileged is not None:
            # in chunks, so stopping the tests ends this within a few seconds
            chunks = [OBSERVE_CHUNK] * (seconds // OBSERVE_CHUNK)
            chunks[-1] += seconds % OBSERVE_CHUNK               # the helper watches 5 s at least
            for chunk in chunks:
                if scan.stopped():
                    break
                try:
                    seen = scan.privileged.observe_traffic(chunk)
                except HelperError as e:
                    return unknown(f"Couldn't watch the traffic: {e}")
                for q in seen.get("queries", []):
                    name = str(q.get("name", "")).rstrip(".").lower()
                    if name:
                        asked[name] = asked.get(name, 0) + 1
                        for a in q.get("addresses", []):
                            names_by_ip.setdefault(a, set()).add(name)
                known = {(c["process"], c["peer"]) for c in conns}
                conns += [c for c in seen.get("connections", []) if (c["process"], c["peer"]) not in known]
        else:
            partial = True
            for name, _, _ in PHONE_HOME:
                if not name.startswith("."):
                    for a in scan.net.resolve(name).addresses:
                        names_by_ip.setdefault(a, set()).add(name)
            for _ in range(seconds):
                if scan.stopped():
                    break
                r = scan.host.run("ss", "-tunpH")
                conns += ss_connections(r.stdout) if r.ok else []
                scan.net.sleep(1)

        hits: dict[str, dict] = {}            # label -> {"names", "processes", "asked", "related"}
        for name, n in asked.items():
            ph = phone_home(name)
            if ph:
                h = hits.setdefault(ph[0], {"names": set(), "processes": set(), "asked": 0, "related": ph[1]})
                h["names"].add(name)
                h["asked"] += n
        other: dict[str, set[str]] = {}
        for c in conns:
            names = names_by_ip.get(c["peer"], set())
            matched = {phone_home(n) for n in names if phone_home(n)}
            if matched:
                # an address several services share (a CDN) can't be pinned on one of them
                labels = sorted({m[0] for m in matched})
                label = labels[0] if len(labels) == 1 else "One of: " + " / ".join(labels)
                h = hits.setdefault(label, {"names": set(), "processes": set(), "asked": 0,
                                            "related": next(iter(matched))[1] if len(labels) == 1 else None})
                h["names"] |= {n for n in names if phone_home(n)}
                if c["process"]:
                    h["processes"].add(c["process"])
            else:
                other.setdefault(c["process"] or "other users' programs", set()).add(c["peer"])
        suspicious = sorted(n for n in asked if not phone_home(n) and TELEMETRY_LIKE.search(n))

        ev = [Evidence.val("Watched for", f"{seconds} seconds" + ("" if not partial else ", your own programs only"))]
        notes, related = [], set()
        for label, h in sorted(hits.items()):
            who = f"by {', '.join(sorted(h['processes']))}" if h["processes"] else "looked up"
            ev.append(Evidence.val(label, f"{', '.join(sorted(h['names']))[:150]} ({who})"))
            if h["related"]:
                related.add(h["related"])
        if suspicious:
            ev.append(Evidence.count("Other names that look like telemetry", len(suspicious)))
            ev += [Evidence.val("Looks like telemetry", n[:120]) for n in suspicious[:8]]
        if other:
            ev.append(Evidence.val("Other connections (not listed: they'd be your browsing)",
                                   ", ".join(f"{p}: {len(ips)}" for p, ips in sorted(other.items()))[:280]))
        notes.append(Note("limitation", f"Only {seconds} seconds were watched",
                          "Something that reports once a day, or only at start-up, won't show. Run it again after "
                          "starting the browser, or for longer (online.json, observe_seconds)."))
        if partial:
            notes.append(Note("limitation", "Without administrator access, only your own programs are seen",
                              "Connections are matched to known phone-home hosts by address, which misses hosts that "
                              "share addresses (CDNs). Run the online tests with administrator access to see the "
                              "names every program looks up."))
        if hits:
            notes.append(Note("info", "Where to turn these off", "See the related checks.", tuple(sorted(related))))
            if not any(h["asked"] for h in hits.values()):
                # matched by address only: many hosts share CDN addresses, so this is a lead, not proof
                return warned(f"Possibly phone-home traffic (matched by address only, which CDNs share): "
                              f"{', '.join(sorted(hits))}.", *ev, notes=notes, partial=partial)
            return failed(f"Known phone-home traffic: {', '.join(sorted(hits))}.", *ev, notes=notes, partial=partial)
        if suspicious:
            return warned("No known phone-home hosts, but some names look like telemetry.", *ev, notes=notes,
                          partial=partial)
        return passed(f"No known phone-home traffic in {seconds} seconds.", *ev, notes=notes, partial=partial)


# ------------------------------------------------------------------ DNS

@register
class DnsEncryptionInUse(OnlineCheck):
    id = "net.dns_encryption_in_use"

    def hosts(self, settings):
        return ["your DNS server"]

    def detect_online(self, scan: Scan) -> Outcome:
        mode = _resolved_dot(scan)
        if mode is None:
            return absent("DNS over TLS isn't configured (see net.dns_unencrypted).")
        probe = scan.online["dot_probe"]
        r = scan.host.run("resolvectl", "query", "--cache=no", probe, timeout=20)
        m = re.search(r"acquired via local or encrypted transport:\s*(yes|no)", r.stdout)
        ev = [Evidence.val("DNSOverTLS", mode)]
        if not r.ok:
            return unknown(f"The test lookup of {probe} failed: {(r.stderr or r.stdout).strip()[:150]}", *ev)
        if not m:
            return unknown("This version of resolvectl doesn't say whether an answer came over an encrypted "
                           "transport.", *ev)
        ev.append(Evidence.val(f"Lookup of {probe} came over", "an encrypted (or local) transport" if m.group(1) == "yes"
                               else "plain, unencrypted DNS"))
        if m.group(1) == "yes":
            return passed("DNS answers arrive encrypted.", *ev)
        if mode == "opportunistic":
            return warned("DNS over TLS is set to opportunistic and falls back to plain DNS here: your server doesn't "
                          "support it.", *ev)
        return failed("DNS over TLS is on, but this lookup went out unencrypted.", *ev)


LEAK_TEST_ID = re.compile(r"^[a-z0-9]{1,63}$")


def _leak_entries(data) -> tuple[dict | None, list[dict], str]:
    if not isinstance(data, list):
        return None, [], ""
    you = next((e for e in data if isinstance(e, dict) and e.get("type") == "ip"), None)
    resolvers = [e for e in data if isinstance(e, dict) and e.get("type") == "dns"]
    conclusion = next((str(e.get("ip", "")) for e in data if isinstance(e, dict) and e.get("type") == "conclusion"), "")
    return you, resolvers, conclusion


def _who(e: dict) -> str:
    org = e.get("asn") or e.get("isp") or "unknown network"
    return f"{e.get('ip', '?')} ({org}, {e.get('country_name') or '?'})"[:150]


@register
class DnsLeak(OnlineCheck):
    id = "net.dns_leak"

    def hosts(self, settings):
        return [host_of(settings["dns_leak"]), "your DNS resolvers"]

    def detect_online(self, scan: Scan) -> Outcome:
        base = scan.online["dns_leak"].rstrip("/")
        domain = host_of(base)
        r = scan.net.http_get(f"{base}/id")
        if not r.ok:
            return unknown(f"The leak-test service ({domain}) didn't answer: {r.error or f'HTTP {r.status}'}.")
        test_id = r.text().strip().lower()
        # once digits, now letters and digits (2026): anything that makes one DNS label
        if not LEAK_TEST_ID.match(test_id):
            return unknown(f"The leak-test service ({domain}) answered with something the app doesn't recognise as a "
                           "test id; its service may have changed.")
        for i in range(1, 11):
            if scan.stopped():
                return unknown("Stopped.")
            scan.net.resolve(f"{i}.{test_id}.{domain}")              # failures are expected: only the asking counts
        r = scan.net.http_get(f"{base}/dnsleak/test/{test_id}?json")
        try:
            you, resolvers, conclusion = _leak_entries(json.loads(r.text()) if r.ok else None)
        except ValueError:
            you, resolvers, conclusion = None, [], ""
        if you is None or not resolvers:
            return unknown(f"The leak-test service ({domain}) gave no result.")
        ev = [Evidence.val("Websites see you as", _who(you))]
        ev += [Evidence.val("Resolver", _who(e)) for e in resolvers[:10]]
        if not scan.context["vpn_active"]:
            return passed(f"Your DNS is answered by {len(resolvers)} resolver{'s' if len(resolvers) > 1 else ''}; "
                          "with no VPN on, there is nothing to leak around.", *ev,
                          notes=[Note("info", "Who sees your lookups", "The networks listed under Resolver see every "
                                      "name you look up. Run this again with your VPN on to check it.")])
        if conclusion:
            ev.append(Evidence.val("The service's conclusion", conclusion[:200]))
        try:
            data = vpn.load()
        except vpn.DataError as e:
            return unknown(f"The app's list of VPN providers couldn't be read: {e}", *ev)
        kinds = {}
        for e in resolvers:
            kinds.setdefault(_resolver_kind(e, you, data), []).append(e)
        if "other" in kinds:
            nets = sorted({e.get("asn") or e.get("isp") or "an unknown network" for e in kinds["other"]})
            return failed(f"DNS is leaking: resolvers in {', '.join(nets)[:150]} answered your lookups. That isn't the "
                          "VPN's network, a hosting network or a public DNS service: most likely your internet "
                          "provider, which then sees every site you look up.", *ev,
                          notes=[Note("info", "How resolvers are judged",
                                      "Fine: the network your traffic exits from, the VPN provider's own, a hosting "
                                      "network (VPNs often rent their DNS servers from another hosting company than "
                                      "their exits), or a public DNS service. Anything else is an ordinary internet "
                                      "provider's network.")])
        notes = []
        if "public" in kinds:
            notes.append(Note("info", "A public DNS service answers inside the tunnel",
                              "Your VPN sends lookups to a public DNS service "
                              f"({', '.join(sorted({e.get('asn') or '?' for e in kinds['public']}))[:120]}). It sees the "
                              "names you look up, but not your own address: the VPN's comes with them."))
        if "hosting" in kinds:
            notes.append(Note("info", "Resolvers in another hosting network",
                              "Some resolvers are in a different hosting network than your exit. VPNs often rent "
                              "their DNS servers separately, so this is usual."))
        return passed("DNS goes through the VPN: no resolver in an ordinary internet provider's network answered.",
                      *ev, notes=notes)


def _resolver_kind(e: dict, you: dict, data) -> str:
    """exit (the exit's own network), vpn (a provider's), hosting, public (a public DNS service) or other."""
    asn = lambda d: (re.match(r"AS\d+", str(d.get("asn") or "")) or [None])[0]  # noqa: E731
    name = str(e.get("asn") or e.get("isp") or "")
    if asn(e) and asn(e) == asn(you):
        return "exit"
    if not name:
        return "other"
    if data.network_owner(name):
        return "vpn"
    if data.is_public_dns(name):
        return "public"
    return "hosting" if data.is_datacentre(name) else "other"


@register
class DnssecValidation(OnlineCheck):
    id = "net.dnssec_validation"

    def hosts(self, settings):
        return ["your DNS resolver", settings["dnssec_failed"]]

    def detect_online(self, scan: Scan) -> Outcome:
        good, bad = scan.online["dnssec_valid"], scan.online["dnssec_failed"]
        if not scan.net.resolve(good).addresses:
            return unknown(f"DNS isn't working ({good} didn't resolve), so this couldn't be tested.")
        r = scan.net.resolve(bad)
        ev = [Evidence.val(f"{bad} (deliberately broken signature)", "resolved" if r.addresses else "refused")]
        if r.addresses:
            return failed("DNS answers aren't validated: a name with a broken DNSSEC signature resolved.", *ev)
        return passed("DNS answers are validated with DNSSEC (a broken signature was refused).", *ev)


@register
class NxdomainRewrite(OnlineCheck):
    id = "net.nxdomain_rewrite"

    def hosts(self, settings):
        return ["your DNS resolver"]

    def detect_online(self, scan: Scan) -> Outcome:
        name = f"daps-{secrets.token_hex(10)}.com"
        r = scan.net.resolve(name)
        if r.error and r.error != "not found":
            scan.net.sleep(1)
            r = scan.net.resolve(name)
        if r.error and r.error != "not found":
            # Some resolvers (routers, VPN and filtering DNS) answer a name that doesn't exist with
            # "server failure" rather than "doesn't exist"; Python calls that a temporary failure.
            # No address came back, so nothing was rewritten, as long as DNS works at all.
            known = scan.online.get("dnssec_valid") or "example.com"
            if not scan.net.resolve(known).addresses:
                return unknown(f"DNS isn't working: neither a test name nor {known} could be looked up ({r.error[:100]}).")
            return passed("Names that don't exist aren't answered with an address.",
                          Evidence.val("A random name that doesn't exist", f"failed: {r.error[:100]}"),
                          notes=[Note("info", "Your resolver reports a failure instead",
                                      "Asked for a name that doesn't exist, your DNS resolver answers that the lookup "
                                      f"failed rather than that the name doesn't exist, while {known} resolves "
                                      "normally. That is unusual but harmless here: nothing was redirected.")])
        ev = [Evidence.val("A random name that doesn't exist", "answered with an address" if r.addresses else "not found")]
        if r.addresses:
            return failed("Lookups of names that don't exist are answered with someone's server: your DNS is being "
                          "rewritten.", *ev, Evidence.val("Answered with", ", ".join(r.addresses[:3])))
        return passed("Names that don't exist are reported as not found.", *ev)


# ------------------------------------------------------------------ VPN and addresses

@register
class VpnIpv6Leak(OnlineCheck):
    id = "net.vpn_ipv6_leak"

    def hosts(self, settings):
        return [host_of(settings["ip_echo_v4"]), host_of(settings["ip_echo_v6"])]

    def detect_online(self, scan: Scan) -> Outcome:
        vpns = set(net.carrying_vpn_links(scan.host))
        v4 = scan.net.http_get(scan.online["ip_echo_v4"])
        v6 = scan.net.http_get(scan.online["ip_echo_v6"])
        ev = [Evidence.val("Public IPv4 address websites see", v4.text().strip()[:45] if v4.ok else "none"),
              Evidence.val("Public IPv6 address websites see", v6.text().strip()[:45] if v6.ok else "none (no IPv6)")]
        v6_routes = net.internet_route(scan.host, 6)
        outside = sorted(r for r in v6_routes if r not in vpns)
        ev.append(Evidence.val("IPv6 internet traffic goes via", ", ".join(sorted(v6_routes)) or "none"))
        kill = Note("info", "Testing the kill switch",
                    "Whether traffic stops when the tunnel drops can't be seen from settings. To test it: start a "
                    "download, then stop the tunnel from outside the VPN app (e.g. turn the network off and on) and "
                    "watch whether traffic carries on without it.")
        if not vpns:
            return passed("No VPN is connected.", *ev, notes=[kill])
        if not v6.ok:
            return passed("IPv6 doesn't reach the internet, so it can't bypass the VPN.", *ev, notes=[kill])
        seen = v6.text().strip()
        local = {a for iface, addrs in net.global_ipv6(scan.host).items() if iface not in vpns for a in addrs}
        try:
            seen_ip = ipaddress.ip_address(seen)
            leaked = any(ipaddress.ip_address(a) == seen_ip for a in local)
        except ValueError:
            leaked = False
        if leaked or (outside and not any(r in vpns for r in v6_routes)):
            return failed("IPv6 traffic goes around the VPN: websites reachable over IPv6 see your real address.",
                          *ev, notes=[kill])
        return passed("IPv6 traffic goes through the VPN.", *ev, notes=[kill])


# the providers' own exit checks (vpn-providers.yaml `exit_check`): (IPv4 URL, IPv6 URL or None)
# VERIFY: field names (am.i.mullvad.net: ip, organization, mullvad_exit_ip, mullvad_exit_ip_hostname;
# api.ivpn.net: ip_address, isp, isIvpnServer)
PROVIDER_CHECKS = {
    "mullvad": ("https://ipv4.am.i.mullvad.net/json", "https://ipv6.am.i.mullvad.net/json"),
    "ivpn": ("https://api.ivpn.net/v4/geo-lookup", None),
}


@dataclass
class Exit:
    """Where one IP version's traffic leaves for the internet, as the outside sees it."""
    family: int
    address: str | None = None          # None: no internet over this version
    owner: str = ""                     # the network that owns the address, as the lookup names it
    provider: "vpn.Provider | None" = None   # the VPN provider whose network that is
    kind: str = "unknown"               # vpn | datacentre | other (an ordinary provider) | unknown
    provider_says: bool | None = None   # the provider's own check: is this one of its exits?
    relay: str | None = None            # the server the provider's check names
    answers: int = 0                    # address services that answered

    @property
    def via_vpn(self) -> bool:
        return self.kind in ("vpn", "datacentre") or bool(self.provider_says)

    @property
    def name(self) -> str:
        """The owner as people know it: RIPEstat's "AS9009 M247 M247 Europe SRL" (number, the network's
        handle, the company) becomes "M247 Europe SRL (AS9009)"; a provider's own wording is kept."""
        m = re.match(r"^AS(\d+) (\S+)(?: -)? (.+)$", self.owner)
        return f"{m.group(3)} (AS{m.group(1)})" if m else self.owner

    def network(self) -> str:
        return self.provider.name if self.kind == "vpn" and self.provider else self.name or "an unknown network"


def _address(text: str, family: int) -> str | None:
    try:
        a = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return str(a) if a.version == family else None


def _echo(scan: Scan, url: str, family: int) -> str | None:
    r = scan.net.http_get(url)
    return _address(r.text(), family) if r.ok else None


def _json(r) -> dict:
    try:
        d = json.loads(r.text()) if r.ok else {}
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def _owner(scan: Scan, address: str) -> str:
    """Who owns an address, from RIPEstat's prefix overview: "AS1221 ASN-TELSTRA Telstra Limited"."""
    r = scan.net.http_get(f"{scan.online['ip_owner']}?{urllib.parse.urlencode({'resource': address})}")
    asns = (_json(r).get("data") or {}).get("asns") or []
    first = asns[0] if asns and isinstance(asns[0], dict) else {}
    return f"AS{first.get('asn')} {first.get('holder') or ''}".strip()[:120] if first.get("asn") else ""


@register
class VpnExit(OnlineCheck):
    id = "net.vpn_exit"

    def hosts(self, settings):
        return [host_of(settings[k]) for k in ("ip_echo_v4", "ip_echo_v6", "ip_echo_v4b", "ip_echo_v6b", "ip_owner")] + [
            "am.i.mullvad.net, only if Mullvad is your VPN", "api.ivpn.net, only if IVPN is your VPN"]

    def exit(self, scan: Scan, data, family: int, check: str | None) -> Exit | str:
        """One IP version's exit, or why it couldn't be told."""
        e = Exit(family)
        a = _echo(scan, scan.online[f"ip_echo_v{family}"], family)
        if check:
            info = _json(scan.net.http_get(check))
            b = _address(str(info.get("ip") or info.get("ip_address") or ""), family)
            e.owner = str(info.get("organization") or info.get("isp") or "")[:120]
            flag = info.get("mullvad_exit_ip", info.get("isIvpnServer"))
            e.provider_says = flag if isinstance(flag, bool) else None
            e.relay = str(info.get("mullvad_exit_ip_hostname") or "")[:40] or None
        else:
            b = _echo(scan, scan.online[f"ip_echo_v{family}b"], family)
        if a and b and a != b:
            return (f"The two services asked for your public IPv{family} address gave different answers ({a} and {b}), "
                    "so neither can be trusted.")
        e.address, e.answers = a or b, (a is not None) + (b is not None)
        if e.address is None:
            return e
        if not e.owner:
            e.owner = _owner(scan, e.address)
        owner = data.network_owner(e.owner) if e.owner else None
        if e.provider_says or owner:
            e.kind, e.provider = "vpn", owner
        elif e.owner and data.is_datacentre(e.owner):
            e.kind = "datacentre"
        elif e.owner:
            e.kind = "other"
        return e

    def detect_online(self, scan: Scan) -> Outcome:
        try:
            data = vpn.load()
        except vpn.DataError as e:
            return unknown(f"The app's list of VPN providers couldn't be read: {e}")
        host = scan.host
        tunnels = net.vpn_links(host)
        carrying = net.carrying_vpn_links(host, tunnels)
        matches = [m for m in vpn.identify(host, data) if m.in_use] if carrying else []
        mine = matches[0] if matches else None
        checks = PROVIDER_CHECKS.get(mine.provider.exit_check or "") if mine else None
        exits: dict[int, Exit] = {}
        for i, family in enumerate((4, 6)):
            if scan.stopped():
                return unknown("Stopped.")
            e = self.exit(scan, data, family, checks[i] if checks else None)
            if isinstance(e, str):
                return unknown(e)
            if mine and e.kind == "vpn" and e.provider is None:
                e.provider = mine.provider
            exits[family] = e
        v4, v6 = exits[4], exits[6]
        present = [e for e in (v4, v6) if e.address]
        if not present:
            return unknown("No address service answered, over IPv4 or IPv6: is this computer online?")
        ev = []
        for e in (v4, v6):
            ev.append(Evidence.val(f"Public IPv{e.family} address websites see", e.address or "none"))
            if e.address:
                ev.append(Evidence.val(f"IPv{e.family} exit network", e.network() if e.kind == "vpn" and e.provider
                                       else e.name or "couldn't be looked up"))
        if mine:
            ev.append(Evidence.val("VPN in use", mine.provider.name))
            if mine.relay:
                ev.append(Evidence.val(f"Server {mine.provider.name}'s app reports", mine.relay))
        relays = {e.relay for e in present if e.relay}
        if relays:
            ev.append(Evidence.val("Server the exit belongs to", ", ".join(sorted(relays))))
        notes = [Note("info", "Asked twice", "Each address came from two services that had to agree, so one "
                      "misbehaving service can't fool the result.")] if all(e.answers == 2 for e in present) else [
            Note("limitation", "Only one service answered", "One of the address services didn't answer, so the "
                 "address rests on a single service's word.")]
        if all(e.kind == "unknown" for e in present):
            return unknown("Who owns your public address couldn't be looked up, so where it exits can't be told.",
                           *ev, notes=notes)
        bypass = [(a, b) for a, b in ((v4, v6), (v6, v4)) if a.address and b.address and a.via_vpn and b.kind == "other"]
        if carrying:
            name = mine.provider.name if mine else "the VPN"
            refused = [e for e in present if e.provider_says is False]
            if refused:
                return failed(f"{name}'s own check says your IPv{refused[0].family} traffic doesn't leave through "
                              f"{name}: websites see {refused[0].name or refused[0].address}.", *ev, notes=notes)
            if bypass:
                a, b = bypass[0]
                return failed(f"IPv{a.family} goes through the VPN, but IPv{b.family} leaves through {b.name}: "
                              f"websites reachable over IPv{b.family} see your real address.", *ev, notes=notes)
            if mine and mine.relay and relays and mine.relay not in relays:
                return warned(f"{name}'s app reports server {mine.relay}, but traffic leaves through "
                              f"{', '.join(sorted(relays))}: a stale connection, or traffic going another way. "
                              "Reconnect the VPN and test again.", *ev, notes=notes)
            if all(e.kind == "other" for e in present):
                return warned(f"A VPN is connected, but traffic leaves through {present[0].name}, which isn't a known "
                              "VPN or hosting network.", *ev, notes=notes + [Note(
                                  "info", "Is that your internet provider?",
                                  "If it is, the VPN isn't carrying your traffic: reconnect it and check its settings. "
                                  "A VPN you run yourself, at home or at work, leaves through that network's provider, "
                                  "which is expected.")])
            e = present[0]
            if mine and e.kind == "datacentre":
                return passed(f"Traffic leaves through {name}: websites see an address in {e.name}, a hosting network "
                              f"{name} rents servers from.", *ev, notes=notes)
            if e.kind == "vpn" and e.provider:
                return passed(f"Traffic leaves through {e.provider.name}" + (", as its own check confirms."
                              if e.provider_says else "'s own network."), *ev, notes=notes)
            return passed(f"Traffic leaves through {name}: websites see {e.network()}.", *ev, notes=notes)
        upstream = [e for e in present if e.via_vpn]
        if upstream:
            where = ("the router, or the computer this virtual machine runs on"
                     if scan.context["virtualization"] == "vm" else "likely the router")
            notes.append(Note("info", "This describes only this computer",
                              "A router can send some devices through its VPN and not others, or switch it off when "
                              "the VPN drops: check from each device that matters."))
            if upstream[0].kind == "datacentre":
                notes.append(Note("limitation", "A hint, not proof",
                                  f"{upstream[0].name} rents servers to VPN providers, but also to proxies and "
                                  "companies: an address there is typical of a VPN, not proof of one."))
            if bypass:
                a, b = bypass[0]
                return failed(f"IPv{a.family} goes through a VPN upstream of this computer ({where}), but "
                              f"IPv{b.family} leaves through {b.name}: websites reachable over IPv{b.family} see your "
                              "real address.", *ev, notes=notes)
            return passed(f"Traffic goes through a VPN upstream of this computer ({where}): websites see "
                          f"{upstream[0].network()}.", *ev, notes=notes)
        return passed(f"No VPN: websites see your internet provider, {present[0].name or present[0].address}.", *ev,
                      notes=notes)


def local_ipv4(scan: Scan) -> set[str]:
    r = scan.host.run("ip", "-4", "-o", "addr", "show")
    return set(re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)/", r.stdout)) if r.ok else set()


# ------------------------------------------------------------------ UPnP

IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
SOAP = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry '
        'xmlns:u="{svc}"><NewPortMappingIndex>{i}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body>'
        '</s:Envelope>')
MAX_MAPPINGS = 128


def _same_lan_host(url: str, host: str) -> bool:
    u = urllib.parse.urlsplit(url)
    return u.scheme == "http" and u.hostname == host and is_lan(host)


def upnp_controls(description: str, location: str) -> list[tuple[str, str]]:
    """(service type, control URL) of the WAN connection services in an IGD description."""
    try:
        root = ET.fromstring(description)
    except ET.ParseError:
        return []
    base = next((e.text for e in root.iter() if e.tag.endswith("URLBase") and e.text), location)
    out = []
    for svc in (e for e in root.iter() if e.tag.endswith("}service") or e.tag == "service"):
        kind = next((c.text or "" for c in svc if c.tag.endswith("serviceType")), "")
        ctrl = next((c.text or "" for c in svc if c.tag.endswith("controlURL")), "")
        if any(w in kind for w in WAN_SERVICES) and ctrl:
            out.append((kind.strip(), urllib.parse.urljoin(base, ctrl.strip())))
    return out


def _soap_field(body: str, name: str) -> str:
    m = re.search(rf"<(?:\w+:)?{name}>([^<]*)</", body)
    return m.group(1).strip() if m else ""


@register
class UpnpForwards(OnlineCheck):
    id = "net.upnp_forwards"

    def hosts(self, settings):
        return ["your router (local network only)"]

    def detect_online(self, scan: Scan) -> Outcome:
        replies = scan.net.ssdp_search(IGD)
        locations = []
        for rep in replies:
            loc = rep.get("location", "")
            if _same_lan_host(loc, rep.get("_from", "")) and loc not in locations:
                locations.append(loc)
        if not locations:
            return passed("No router answers UPnP requests on this network.",
                          Evidence.val("UPnP Internet Gateway Device", "none found"))
        mine = local_ipv4(scan)
        forwards, all_count = [], 0
        for loc in locations:
            host = urllib.parse.urlsplit(loc).hostname
            d = scan.net.http_get(loc, timeout=5)
            for kind, ctrl in upnp_controls(d.text(), loc) if d.ok else []:
                if not _same_lan_host(ctrl, host):
                    continue
                for i in range(MAX_MAPPINGS):
                    if scan.stopped():
                        return unknown("Stopped.")
                    r = scan.net.http_post(ctrl, SOAP.format(svc=kind, i=i).encode(), {
                        "Content-Type": 'text/xml; charset="utf-8"',
                        "SOAPAction": f'"{kind}#GetGenericPortMappingEntry"'}, timeout=5)
                    if not r.ok:
                        break
                    body = r.text()
                    all_count += 1
                    if _soap_field(body, "NewInternalClient") in mine and _soap_field(body, "NewEnabled") != "0":
                        forwards.append((_soap_field(body, "NewExternalPort"), _soap_field(body, "NewInternalPort"),
                                         _soap_field(body, "NewProtocol"), _soap_field(body, "NewPortMappingDescription")))
        ev = [Evidence.val("UPnP router", ", ".join(urllib.parse.urlsplit(x).hostname for x in locations)),
              Evidence.count("Port forwards on the router", all_count)]
        ev += [Evidence.val(f"Internet port {ext}/{proto}", f"→ this machine's port {port}" + (f" ({desc[:60]})" if desc else ""))
               for ext, port, proto, desc in forwards[:15]]
        risk = Note("risk", "The router lets any program open ports",
                    "With UPnP on, any program on any device in your network can open a port to itself from the "
                    "internet without asking. Turn UPnP off in the router if nothing needs it.")
        self.notes_for_others = {}
        if forwards:
            listed = ", ".join(f"{p}/{proto.lower()}" for _, p, proto, _ in forwards[:8])
            self.notes_for_others["net.exposed_services"] = [Note(
                "risk", "The router forwards ports to this machine (UPnP)",
                f"Ports {listed} on this machine are reachable from the internet through the router, not just from "
                "the local network.", ("net.upnp_forwards",))]
            return failed(f"The router forwards {len(forwards)} internet port{'s' if len(forwards) > 1 else ''} to this "
                          "machine.", *ev, notes=[risk])
        return passed("The router answers UPnP, but forwards nothing to this machine.", *ev, notes=[risk])


# ------------------------------------------------------------------ TLS interception

# VERIFY: keep both lists current
PUBLIC_CA = re.compile(r"Let's Encrypt|Internet Security Research Group|DigiCert|Google Trust Services|Sectigo|COMODO|"
                       r"GlobalSign|Amazon|Microsoft|Entrust|GoDaddy|Starfield|Buypass|ZeroSSL|HARICA|Certainly|"
                       r"SSL Corporation|SSL\.com|Actalis|IdenTrust|QuoVadis|Certum|Asseco|Telia|SwissSign|T-Systems|"
                       r"Deutsche Telekom|Thawte|GeoTrust|RapidSSL|Cloudflare|Apple|TrustAsia|Fastly|Baltimore",
                       re.I)
INTERCEPTOR = re.compile(r"Kaspersky|Avast|AVG|ESET|Bitdefender|Norton|Symantec Web|Zscaler|Fortinet|FortiGate|"
                         r"Palo Alto|Netskope|Sophos|Cisco Umbrella|OpenDNS|Blue ?Coat|mitmproxy|Charles Proxy|"
                         r"Fiddler|Do_Not_Trust|PortSwigger|Burp|Untangle|SonicWall|WatchGuard|Barracuda|Forcepoint|"
                         r"Websense|Check ?Point|McAfee Web|Smoothwall|Lightspeed|Securly|GoGuardian|iboss|"
                         r"Menlo|Cato Networks|Proxyman|Surfshark|NordVPN Threat", re.I)
@register
class TlsInterception(OnlineCheck):
    id = "net.tls_interception"

    def hosts(self, settings):
        return list(settings["tls_sites"])

    def detect_online(self, scan: Scan) -> Outcome:
        ev, intercepted, untrusted, unknown_issuer, reached = [], [], [], [], 0
        for site in scan.online["tls_sites"]:
            if scan.stopped():
                return unknown("Stopped.")
            peer = scan.net.tls_peer(site)
            issuer = " / ".join(v for v in (peer.issuer.get("organizationName"), peer.issuer.get("commonName")) if v)
            if peer.verified:
                reached += 1
                ev.append(Evidence.val(site, f"issued by {issuer or 'unknown'}"[:150]))
                if INTERCEPTOR.search(issuer):
                    intercepted.append(issuer)
                elif not PUBLIC_CA.search(issuer):
                    unknown_issuer.append(f"{site}: {issuer or 'no issuer name'}")
            elif peer.error.startswith("no connection"):
                ev.append(Evidence.val(site, "couldn't connect"))
            else:
                reached += 1
                untrusted.append(site)
                ev.append(Evidence.val(site, f"certificate not trusted: {peer.error[:100]}"))
        notes = []
        roots = local_roots(scan)
        if roots:
            notes.append(Note("risk", f"{len(roots)} root certificate{'s were' if len(roots) > 1 else ' was'} added locally",
                              "Whoever holds the key of an added root certificate can impersonate any website to "
                              "this machine: " + ", ".join(roots[:6]) + ". Remove those you don't recognise."))
        if not reached:
            return unknown("None of the test sites could be reached.", *ev, notes=notes)
        if intercepted:
            return failed(f"HTTPS is decrypted on the way: certificates are issued by {intercepted[0]}.", *ev, notes=notes)
        if untrusted:
            return warned(f"Certificates of {', '.join(untrusted)} aren't trusted: something in between may be "
                          "intercepting (or a Wi-Fi sign-in page is in the way).", *ev, notes=notes)
        if unknown_issuer:
            return warned("Some certificates come from issuers the app doesn't recognise as public; check they aren't "
                          "an interception product.", *ev, Evidence.val("Unrecognised", "; ".join(unknown_issuer)[:250]),
                          notes=notes)
        return passed("HTTPS connections reach the real sites.", *ev, notes=notes)


# ------------------------------------------------------------------ updates with fresh lists

@register
class UpdatesRefreshed(OnlineCheck):
    id = "kern.updates_refreshed"

    def hosts(self, settings):
        return ["your distribution's package mirrors", "Flathub / the Snap Store, if used"]

    def _apt(self, scan: Scan) -> tuple[list[str] | None, int, str]:
        """apt's lists downloaded afresh into a folder of the test's own, never the system's (no root), and not kept:
        in the runtime folder, in memory, removed at once (they took 269 MB in ~/.cache on Ubuntu 26.04, for good)."""
        import shutil
        import tempfile
        own = scan.paths.cache_home / "daprivacyscanner"
        shutil.rmtree(own / "apt", ignore_errors=True)    # where 0.1.0b2 and earlier kept them, for good (269 MB)
        runtime = scan.host.environ.get("XDG_RUNTIME_DIR") or ""
        # the lists take about 170 MB while they download (Ubuntu 26.04), and the runtime folder is a tenth of memory:
        # with too little room there they go in the app's cache folder, on the disk, and are removed all the same
        try:
            room = os.statvfs(runtime).f_bavail * os.statvfs(runtime).f_frsize if runtime else 0
        except OSError:
            room = 0
        if room >= 400 * 2**20:
            base = runtime
        else:
            own.mkdir(parents=True, exist_ok=True)
            base = str(own)
        d = Path(tempfile.mkdtemp(prefix="daprivacyscanner-apt.", dir=base))
        try:
            for sub in ("lists/partial", "cache/archives/partial"):
                (d / sub).mkdir(parents=True, exist_ok=True)
            opts = ["-o", f"Dir::State::Lists={d / 'lists'}", "-o", f"Dir::Cache={d / 'cache'}", "-o", "Debug::NoLocking=1"]
            r = scan.host.run("apt-get", "update", "-q", *opts, timeout=600)
            if not r.ok:
                return None, 0, f"apt-get update failed: {(r.stderr or r.stdout).strip()[-150:]}"
            r = scan.host.run("apt", "list", "--upgradable", *opts, timeout=120)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        lines = [ln for ln in r.stdout.splitlines() if "/" in ln and "[upgradable" in ln]
        return package_names("apt", r.stdout), sum(1 for ln in lines if "-security" in ln), ""

    def detect_online(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, names, security, why = [], None, None, ""
        if installed(host, "apt-get"):
            names, security, why = self._apt(scan)
            pm = "apt"
        elif installed(host, "dnf"):
            pm = "dnf"
            # dnf5 downloads the lists into a folder of its own in memory, never ~/.cache/libdnf5 (100 MB and more)
            with dnf5_away_from_home(host, cache_only=False) if is_dnf5(host) else nullcontext(()) as opts:
                program = "dnf5" if opts else "dnf"
                if opts is None:
                    why = DNF5_NO_RUNTIME
                else:
                    r = host.run(program, *opts, "-q", "check-update", "--refresh", timeout=600)
                    if r.returncode in (0, 100):
                        names, security = package_names("dnf", r.stdout), dnf_security(scan, *opts, program=program)
                    else:
                        why = f"dnf check-update failed: {(r.stderr or r.stdout).strip()[-150:]}"
        elif installed(host, "pacman"):
            pm = "pacman"
            if installed(host, "checkupdates"):
                r = host.run("checkupdates", timeout=600)
                if r.returncode in (0, 2):
                    names = package_names("pacman", r.stdout)
                    if installed(host, "arch-audit"):
                        a = host.run("arch-audit", "-u", timeout=300)
                        security = len(a.stdout.splitlines()) if a.ok else None
                else:
                    why = f"checkupdates failed: {(r.stderr or r.stdout).strip()[-150:]}"
            else:
                why = "checkupdates (pacman-contrib) isn't installed; it refreshes lists without root"
        elif installed(host, "zypper"):
            pm, why = "zypper", "zypper can only refresh its lists as root"
        else:
            return unknown("No supported package manager (apt, dnf, pacman, zypper) was found.")
        extra = 0
        if installed(host, "flatpak"):
            r = host.run_flatpak("remote-ls", "--updates", "--columns=application", timeout=300)
            if r.ok:
                n = len([ln for ln in r.stdout.splitlines() if ln.strip()])
                extra += n
                ev.append(Evidence.count("Pending Flatpak updates", n))
        if installed(host, "snap"):
            r = host.run("snap", "refresh", "--list", timeout=300)
            if r.ok:
                n = max(0, len(r.stdout.splitlines()) - 1)
                extra += n
                ev.append(Evidence.count("Pending snap updates", n))
        if names is None:
            return unknown(f"Couldn't refresh the {pm} package lists: {why}.", *ev)
        restart, kev = kernel_restart(scan)
        o = updates_outcome(pm, names, security, ev + kev, restart, fresh=True, extra=extra)
        if o.status is not Status.PASS:
            o.notes.append(Note("info", "Install them", "See kern.updates for how.", ("kern.updates",)))
        return no_pass_when_unsupported(scan, o)


# ------------------------------------------------------------------ reachable over IPv6

def _v6_listeners(scan: Scan) -> list:
    """Exposed services that also listen on IPv6 (net.exposed keeps one socket per port, which
    may be the IPv4 one)."""
    listeners = scan.context.listeners or []
    v6 = {(s.proto, s.port) for s in listeners if s.wildcard and s.host_part in ("[::]", "*")}
    return [s for s in net.exposed(listeners, net.ephemeral_range(scan.host)) if (s.proto, s.port) in v6]


@register
class Ipv6Reachable(OnlineCheck):
    id = "net.ipv6_reachable"

    def hosts(self, settings):
        return [host_of(settings["port_probe"])] if settings.get("port_probe") else []

    def detect_online(self, scan: Scan) -> Outcome:
        from .network import firewall_rules
        if not scan.context["ipv6_global"]:
            return absent("This machine has no public IPv6 address.")
        candidates = _v6_listeners(scan)
        if not candidates:
            return passed("No service listens on IPv6 on all interfaces.")
        tool, rules, why = firewall_rules(scan)
        ev = [Evidence.val("Host firewall", tool or "none")]
        if rules is not None:
            candidates = [s for s in candidates if rules.allows(s.port, s.proto) is not False]
            if not candidates:
                return passed(f"{tool} blocks every service listening on IPv6.", *ev)
        # this computer's own addresses, as the ipv6_global context counts them: not a VPN tunnel's (the provider's,
        # shared, reached only through it), the interface IPv6 traffic leaves by first
        v6, tunnels = net.global_ipv6(scan.host), set(net.vpn_links(scan.host))
        routed = net.internet_route(scan.host, 6)
        addrs = [str(ipaddress.ip_address(a)) for iface in sorted((i for i in v6 if i not in tunnels),
                                                                   key=lambda i: (i not in routed, i))
                 for a in v6[iface]]
        probe = scan.online.get("port_probe")
        if probe and addrs:
            open_, closed = [], []
            for s in candidates:
                if s.proto != "tcp":
                    continue
                r = scan.net.http_get(f"{probe}?{urllib.parse.urlencode({'host': addrs[0], 'port': s.port})}")
                try:
                    is_open = bool(json.loads(r.text()).get("open")) if r.ok else None
                except (ValueError, AttributeError):
                    is_open = None
                (open_ if is_open else closed).append(s.label())
            ev += [Evidence.val("Reachable from outside", ", ".join(open_) or "none"),
                   Evidence.val("Not reachable from outside", ", ".join(closed) or "none")]
            if open_:
                return failed(f"Reachable from the internet over IPv6: {', '.join(open_)}.", *ev)
            return passed("Your port probe couldn't reach any service over IPv6.", *ev)
        ev.append(Evidence.val("Listening on IPv6 and not blocked here", ", ".join(s.label() for s in candidates)))
        return warned("These services are likely reachable from the internet over IPv6, unless your router blocks "
                      "incoming IPv6.", *ev,
                      notes=[Note("info", "Confirm it from outside",
                                  "From a device on another network (a phone hotspot, a server), run "
                                  f"`daprivacyscanner --probe {addrs[0] if addrs else 'ADDRESS'}`, or set a port probe "
                                  "server of your own in online.json." + (f" ({why})" if why else ""))])


def online_checks() -> dict[str, type[OnlineCheck]]:
    from . import REGISTRY
    return {k: v for k, v in REGISTRY.items() if isinstance(v, type) and issubclass(v, OnlineCheck)}

