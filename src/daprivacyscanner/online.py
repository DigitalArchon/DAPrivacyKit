"""Online tests' access to the network (docs/TECHNICAL.md, design rule 10: a normal scan never uses it).

Online checks reach other machines only through a Net, as other checks reach the system only
through Host: tests replace it with FakeNet, so the test suite never touches the network.
Endpoints are the defaults below unless the user sets others in
$XDG_CONFIG_HOME/daprivacyscanner/online.json; every host contacted is listed to the user before
anything runs. Requests carry no identifier of this machine or of the app."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "Mozilla/5.0"        # generic: nothing that singles out this app or machine
MAX_BODY = 2 * 1024 * 1024

DEFAULTS: dict = {
    "ip_echo_v4": "https://api.ipify.org",
    "ip_echo_v6": "https://api6.ipify.org",
    # a second opinion, so one misbehaving echo service can't fool the exit test
    "ip_echo_v4b": "https://ipv4.icanhazip.com",
    "ip_echo_v6b": "https://ipv6.icanhazip.com",
    # who owns an address: RIPEstat's prefix-overview (?resource=<address>), run by the RIPE NCC registry
    "ip_owner": "https://stat.ripe.net/data/prefix-overview/data.json",
    # the bash.ws DNS leak API: /id (letters and digits), then <n>.<id>.bash.ws lookups, then
    # /dnsleak/test/<id>?json (checked by hand 2026-10-03)
    "dns_leak": "https://bash.ws",
    "dnssec_failed": "dnssec-failed.org",
    "dnssec_valid": "example.com",
    "dot_probe": "example.com",
    "tls_sites": ["www.wikipedia.org", "www.mozilla.org", "letsencrypt.org", "www.debian.org"],
    # a server of your own: GET <url>?host=<address>&port=<n> answers {"open": true|false}
    "port_probe": "",
    "observe_seconds": 60,
}
# Whether each test is ticked by default, and why, as shown to the user. The rule: ticked when it
# only talks to your own DNS resolver or router, to well-known sites, or to nobody; not ticked when
# it uses a third-party test service, or downloads a lot.
DEFAULTS_WHY: dict[str, tuple[bool, str]] = {
    "tel.observed_traffic": (True, "Contacts nobody: it only watches. (Without administrator access it also looks "
                                   "up a few known host names through your own DNS resolver.)"),
    "net.dns_encryption_in_use": (True, "One ordinary lookup through your own DNS server."),
    "net.dnssec_validation": (True, "Two ordinary lookups through your own DNS resolver."),
    "net.nxdomain_rewrite": (True, "One ordinary lookup through your own DNS resolver (and up to two more if it fails)."),
    "net.upnp_forwards": (True, "Talks only to your router, on the local network."),
    "net.tls_interception": (True, "Connects to four well-known sites, as opening them in a browser would."),
    "net.ipv6_reachable": (True, "Contacts nobody, unless you've set up a port probe server of your own."),
    "net.dns_leak": (False, "Uses a third-party test service (bash.ws), which sees your IP address and your DNS "
                            "resolvers. Only meaningful with a VPN connected."),
    "net.vpn_ipv6_leak": (False, "Asks third-party services (ipify) for your public addresses. Only meaningful with "
                                 "a VPN connected."),
    "net.vpn_exit": (False, "Asks third-party services (ipify, icanhazip, RIPEstat) for your public addresses and "
                            "who owns them. Worth running with a VPN on this computer or on your router."),
    "kern.updates_refreshed": (False, "Downloads your distribution's package lists (tens of MB for apt), which takes "
                                      "a while."),
}
DEFAULT_ON = frozenset(k for k, (on, _) in DEFAULTS_WHY.items() if on)


def contact_group(test_id: str, settings: dict) -> str:
    """How far a test reaches, for grouping in the dialog: "nobody", "own" (your DNS resolver,
    router or server, or well-known sites), or "third" (a third-party service, or big downloads)."""
    if test_id == "tel.observed_traffic":
        return "nobody"
    if test_id == "net.ipv6_reachable":
        return "own" if settings.get("port_probe") else "nobody"
    return "own" if DEFAULTS_WHY.get(test_id, (False, ""))[0] else "third"
VPN_TESTS = frozenset({"net.dns_leak", "net.vpn_ipv6_leak", "net.vpn_exit"})

# What administrator access adds. Tests not listed run the same either way.
WITH_ADMIN: dict[str, str] = {
    "tel.observed_traffic": "Sees every program, not just yours, and the names they look up, so a match is certain. "
                            "Without it, connections are matched by address only, which CDNs share: a lead, not proof.",
    "net.ipv6_reachable": "Reads ufw's rules (root-only) to leave out services the firewall blocks. Not needed with "
                          "firewalld.",
}
_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
PROXY_VARS = ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")


def proxy_vars(environ) -> list[str]:
    """The proxy variables set in `environ`, which the online tests don't use (RealNet goes out directly: a test
    of what this network does must see it, not the proxy's). The page says so before they run, since someone
    who routes everything through a local Tor or SOCKS proxy would otherwise expect it to cover these too."""
    return [v for v in PROXY_VARS if (environ.get(v) or "").strip()]


class SettingsError(ValueError):
    pass


def settings_path(config_home: Path) -> Path:
    return config_home / "daprivacyscanner" / "online.json"


def load_settings(config_home: Path) -> dict:
    """The defaults, with the user's online.json on top (validated: https URLs, plain host names)."""
    out = json.loads(json.dumps(DEFAULTS))
    p = settings_path(config_home)
    try:
        user = json.loads(p.read_text())
    except FileNotFoundError:
        return out
    except (OSError, ValueError) as e:
        raise SettingsError(f"{p} couldn't be read: {e}") from None
    if not isinstance(user, dict):
        raise SettingsError(f"{p} must be a JSON object")
    for k, v in user.items():
        if k not in DEFAULTS:
            raise SettingsError(f"{p}: unknown setting {k!r}")
        if k in ("ip_echo_v4", "ip_echo_v6", "ip_echo_v4b", "ip_echo_v6b", "ip_owner", "dns_leak", "port_probe"):
            if not isinstance(v, str) or (v and not v.startswith("https://")):
                raise SettingsError(f"{p}: {k} must be an https:// URL (or empty)")
        elif k in ("dnssec_failed", "dnssec_valid", "dot_probe"):
            if not isinstance(v, str) or not _HOST.match(v):
                raise SettingsError(f"{p}: {k} must be a host name")
        elif k == "tls_sites":
            if not isinstance(v, list) or not v or not all(isinstance(x, str) and _HOST.match(x) for x in v):
                raise SettingsError(f"{p}: tls_sites must be a list of host names")
        elif k == "observe_seconds":
            if not isinstance(v, int) or not 5 <= v <= 300:
                raise SettingsError(f"{p}: observe_seconds must be 5-300")
        out[k] = v
    return out


def host_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or url


# ------------------------------------------------------------------ results

@dataclass(frozen=True)
class HttpResult:
    status: int | None                  # None: no answer (network error, timeout)
    body: bytes = b""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Resolved:
    addresses: tuple[str, ...] = ()
    error: str = ""                     # "not found", or another failure


@dataclass(frozen=True)
class TlsPeer:
    host: str
    verified: bool
    issuer: dict = field(default_factory=dict)      # organizationName, commonName of the leaf's issuer
    error: str = ""


# ------------------------------------------------------------------ the network

class Net:
    """Redirects are followed only to the host asked (http to https there, never back), or to one of
    `hosts` where a call names them: every host contacted is one the page named first (rule 10)."""

    def http_get(self, url: str, timeout: float = DEFAULT_TIMEOUT, hosts: tuple[str, ...] = ()) -> HttpResult:
        raise NotImplementedError

    def http_post(self, url: str, body: bytes, headers: dict[str, str], timeout: float = DEFAULT_TIMEOUT) -> HttpResult:
        raise NotImplementedError

    def resolve(self, name: str) -> Resolved:
        raise NotImplementedError

    def tls_peer(self, host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> TlsPeer:
        raise NotImplementedError

    def ssdp_search(self, target: str, timeout: float = 3.0) -> list[dict[str, str]]:
        raise NotImplementedError

    def download(self, url: str, dest: Path, progress: Callable[[int, int | None], None] | None = None,
                 stop: Callable[[], bool] | None = None, limit: int = 0, timeout: float = 60.0,
                 hosts: tuple[str, ...] = ()) -> HttpResult:
        """A file, written to `dest` as it arrives (never held in memory whole): for a tool the user
        starts (the browser in the RAM disk), not for online tests. `progress(done, total or None)`;
        `stop()` ends it early (the result then has status None); `limit` caps the size."""
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _name(parts) -> dict:
    out = {}
    for rdn in parts or ():
        for k, v in rdn:
            out[k] = v
    return out


class Redirected(urllib.error.URLError):
    pass


class ConfinedRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to the request's own host, or to one in its `allowed_hosts`; never
    from https to http. Anything else stops the request (Redirected) instead of reaching a host the
    user wasn't told about."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        allowed = {old.hostname} | set(getattr(req, "allowed_hosts", ()))
        if new.hostname not in allowed or (old.scheme == "https" and new.scheme != "https") \
                or new.scheme not in ("http", "https"):
            raise Redirected(f"it redirected to {new.scheme}://{new.hostname}, which isn't one of the hosts named, "
                             "so it was stopped there")
        out = super().redirect_request(req, fp, code, msg, headers, newurl)
        if out is not None:
            out.allowed_hosts = getattr(req, "allowed_hosts", ())
        return out


class RealNet(Net):
    def __init__(self):
        # no proxies from the environment: a test of what the network does should see it directly (the page and
        # --online say so when one is set: proxy_vars)
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ConfinedRedirects())

    def _request(self, req: urllib.request.Request, timeout: float) -> HttpResult:
        req.add_header("User-Agent", USER_AGENT)
        try:
            with self._opener.open(req, timeout=timeout) as r:
                return HttpResult(r.status, r.read(MAX_BODY))
        except urllib.error.HTTPError as e:
            return HttpResult(e.code, e.read(MAX_BODY) if e.fp else b"", str(e))
        except (urllib.error.URLError, OSError, ValueError) as e:
            return HttpResult(None, b"", str(getattr(e, "reason", e)))

    def http_get(self, url, timeout=DEFAULT_TIMEOUT, hosts=()):
        req = urllib.request.Request(url)
        req.allowed_hosts = tuple(hosts)
        return self._request(req, timeout)

    def http_post(self, url, body, headers, timeout=DEFAULT_TIMEOUT):
        return self._request(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout)

    def resolve(self, name):
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            return Resolved((), "not found" if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5))
                            else str(e))
        return Resolved(tuple(dict.fromkeys(i[4][0] for i in infos)))

    def tls_peer(self, host, port=443, timeout=DEFAULT_TIMEOUT):
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return TlsPeer(host, True, _name(tls.getpeercert().get("issuer")))
        except ssl.SSLCertVerificationError as e:
            return TlsPeer(host, False, {}, e.verify_message or str(e))
        except (OSError, ssl.SSLError) as e:
            return TlsPeer(host, False, {}, f"no connection: {e}")

    def download(self, url, dest, progress=None, stop=None, limit=0, timeout=60.0, hosts=()):
        req = urllib.request.Request(url)
        req.allowed_hosts = tuple(hosts)
        req.add_header("User-Agent", USER_AGENT)
        try:
            with self._opener.open(req, timeout=timeout) as r, open(dest, "wb") as out:
                total = int(r.headers.get("Content-Length") or 0) or None
                if limit and total and total > limit:
                    return HttpResult(None, b"", f"the file is larger than expected ({total} bytes)")
                done = 0
                while True:
                    if stop is not None and stop():
                        return HttpResult(None, b"", "stopped")
                    chunk = r.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    if limit and done > limit:
                        return HttpResult(None, b"", "the file is larger than expected")
                    if progress is not None:
                        progress(done, total)
                if total is not None and done != total:
                    return HttpResult(None, b"", f"the download stopped early ({done} of {total} bytes)")
                return HttpResult(r.status)
        except urllib.error.HTTPError as e:
            return HttpResult(e.code, b"", str(e))
        except (urllib.error.URLError, OSError, ValueError) as e:
            return HttpResult(None, b"", str(getattr(e, "reason", e)))

    def ssdp_search(self, target, timeout=3.0):
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               f"MX: 2\r\nST: {target}\r\n\r\n").encode()
        out = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(0.5)
            s.sendto(msg, ("239.255.255.250", 1900))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = s.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                headers = {"_from": addr[0]}
                for line in data.decode("latin-1").split("\r\n")[1:]:
                    k, sep, v = line.partition(":")
                    if sep:
                        headers[k.strip().lower()] = v.strip()
                out.append(headers)
        return out


def is_lan(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback


# ------------------------------------------------------------------ for tests

class FakeNet(Net):
    """Canned answers: `http` maps a URL (or a URL prefix ending in *) to an HttpResult or a
    callable(url, body) -> HttpResult; `dns` a name to addresses (a missing name is "not found",
    or `resolver(name)` decides); `tls` a host to a TlsPeer; `ssdp` the replies to a search;
    `files` a URL to the bytes a download gets."""

    def __init__(self, http=None, dns=None, tls=None, ssdp=None, resolver: Callable[[str], Resolved] | None = None,
                 files=None):
        self.http, self.dns, self.tls, self.ssdp = dict(http or {}), dict(dns or {}), dict(tls or {}), list(ssdp or [])
        self.files = dict(files or {})
        self.resolver = resolver
        self.contacted: list[str] = []

    def _http(self, url, body=None):
        self.contacted.append(url)
        handler = self.http.get(url) or next((v for k, v in self.http.items()
                                              if k.endswith("*") and url.startswith(k[:-1])), None)
        if handler is None:
            return HttpResult(None, b"", "no route to host")
        return handler(url, body) if callable(handler) else handler

    def http_get(self, url, timeout=DEFAULT_TIMEOUT, hosts=()):
        return self._http(url)

    def http_post(self, url, body, headers, timeout=DEFAULT_TIMEOUT):
        return self._http(url, body)

    def resolve(self, name):
        self.contacted.append(f"dns:{name}")
        if self.resolver is not None:
            return self.resolver(name)
        if name in self.dns:
            return Resolved(tuple(self.dns[name]))
        return Resolved((), "not found")

    def tls_peer(self, host, port=443, timeout=DEFAULT_TIMEOUT):
        self.contacted.append(f"tls:{host}")
        return self.tls.get(host) or TlsPeer(host, False, {}, "no connection: unreachable")

    def ssdp_search(self, target, timeout=3.0):
        self.contacted.append("ssdp")
        return list(self.ssdp)

    def download(self, url, dest, progress=None, stop=None, limit=0, timeout=60.0, hosts=()):
        """`files` maps a URL to the bytes it serves (or an HttpResult for a failure)."""
        self.contacted.append(url)
        data = self.files.get(url)
        if data is None:
            return HttpResult(None, b"", "no route to host")
        if isinstance(data, HttpResult):
            return data
        if stop is not None and stop():
            return HttpResult(None, b"", "stopped")
        Path(dest).write_bytes(data)
        if progress is not None:
            progress(len(data), len(data))
        return HttpResult(200)

    def sleep(self, seconds):
        pass
