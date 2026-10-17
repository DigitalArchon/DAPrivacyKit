"""Network exposure and tracking (net.*)."""

from __future__ import annotations

import re
import time
from pathlib import Path

from .. import ini
from .. import network as net
from ..host import Host, Unreadable
from ..model import Evidence, Note, Outcome
from ..network import carrying_vpn_links, vpn_links
from ..privileged import HelperError
from . import Check, Scan, register
from ._util import (absent, children, failed, installed, isdir, mentions_name, passed, processes, read_text,
                    removed_while_running, systemctl_state, unknown, user_names, warned)


# ------------------------------------------------------------------ NetworkManager

def nm_connections(host: Host, kind: str | None = None) -> list[str] | None:
    """UUIDs of saved NetworkManager connections (of one type, e.g. "802-11-wireless"), or None
    without nmcli."""
    r = host.run("nmcli", "-t", "-f", "UUID,TYPE", "connection", "show")
    if r.missing or not r.ok:
        return None
    out = []
    for line in r.stdout.splitlines():
        uuid, _, typ = line.partition(":")
        if uuid and (kind is None or typ == kind):
            out.append(uuid)
    return out


def nm_get(host: Host, uuid: str, *fields: str) -> dict[str, str]:
    r = host.run("nmcli", "-g", ",".join(fields), "connection", "show", uuid)
    lines = r.stdout.splitlines() if r.ok else []
    return {f: (lines[i].replace("\\:", ":") if i < len(lines) else "") for i, f in enumerate(fields)}


def nm_config(host: Host) -> dict:
    """NetworkManager's merged configuration (`NetworkManager --print-config`)."""
    r = host.run("NetworkManager", "--print-config")
    return ini.parse(r.stdout) if r.ok else {}


def wifi_hardware(host: Host) -> bool:
    return any(isdir(p / "wireless") or isdir(p / "phy80211") for p in children(host.sys_path("/sys/class/net")))


# ------------------------------------------------------------------ exposed services

def sshd_config(host: Host) -> dict[str, str] | None:
    """The first value of each keyword in sshd_config (sshd keeps the first one it reads),
    following Include, stopping at the first Match block. None when the main file can't be
    read without root (Fedora and RHEL keep it root-only): nothing is assumed then."""
    out: dict[str, str] = {}
    unreadable = []

    def read(path: str, depth: int = 0):
        try:
            text = host.read_sys(path) or ""
        except Unreadable:
            unreadable.append(path)
            return False
        for line in text.splitlines():
            words = line.split(None, 1)
            if not words or words[0].startswith("#"):
                continue
            key, value = words[0].lower(), (words[1].strip() if len(words) > 1 else "")
            if key == "match":
                return True
            if key == "include" and depth < 4:
                for pattern in value.split():
                    pattern = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                    d, _, glob = pattern.rpartition("/")
                    for f in sorted(p.name for p in children(host.sys_path(d)) if Path(p.name).match(glob)):
                        if read(f"{d}/{f}", depth + 1):
                            return True
                continue
            out.setdefault(key, value)
        return False

    read("/etc/ssh/sshd_config")
    return None if unreadable else out


def ufw_active(host: Host) -> bool:
    conf = host.read_sys("/etc/ufw/ufw.conf") or ""
    return bool(re.search(r"^\s*ENABLED\s*=\s*yes", conf, re.M)) and systemctl_state(host, "is-active", "ufw") == "active"


def _firewalld_rules(host: Host) -> net.FirewallRules | None:
    r = host.run("firewall-cmd", "--get-active-zones")
    zones = [ln.strip() for ln in r.stdout.splitlines() if ln.strip() and not ln[0].isspace()] if r.ok else []
    if not zones:
        d = host.run("firewall-cmd", "--get-default-zone")
        zones = [d.stdout.strip()] if d.ok and d.stdout.strip() else []
    merged = None
    for zone in zones:
        z = host.run("firewall-cmd", f"--zone={zone}", "--list-all")
        if not z.ok:
            return None
        m = re.search(r"^\s*services:[ \t]*(.*)$", z.stdout, re.M)
        ports = {}
        for svc in (m.group(1).split() if m else []):
            info = host.run("firewall-cmd", f"--info-service={svc}")
            pm = re.search(r"^\s*ports:[ \t]*(.*)$", info.stdout, re.M) if info.ok else None
            ports[svc] = pm.group(1).split() if pm else []
            if pm and not ports[svc]:
                ports[svc] = ["0/none"]                 # a service with no ports (e.g. mdns helper only): opens nothing
        rules = net.parse_firewalld_zone(z.stdout, ports)
        rules.open_ports = [p for p in rules.open_ports if p[2] != "none"]
        if merged is None:
            merged = rules
        else:
            merged.default_allows = merged.default_allows or rules.default_allows
            merged.open_ports += rules.open_ports
            merged.unparsed += rules.unparsed
    return merged


def firewall_rules(scan: Scan) -> tuple[str | None, net.FirewallRules | None, str]:
    """The active host firewall, what it lets in (None if that can't be read) and why not."""
    host = scan.host
    if ufw_active(host):
        if scan.privileged is None:
            return "ufw", None, "ufw's rules can only be read with administrator access"
        try:
            rules = net.parse_ufw_status(scan.privileged.ufw_status())
        except HelperError as e:
            return "ufw", None, f"couldn't read ufw's rules: {e}"
        return ("ufw", rules, "") if rules else (None, None, "")
    if systemctl_state(host, "is-active", "firewalld") == "active":
        rules = _firewalld_rules(host)
        return "firewalld", rules, "" if rules else "couldn't read firewalld's zones"
    for unit in ("nftables", "netfilter-persistent", "iptables"):
        if systemctl_state(host, "is-active", unit) == "active":
            return unit, None, f"{unit} rules aren't read by the app yet"
    return None, None, ""


@register
class ExposedServices(Check):
    id = "net.exposed_services"
    FINDING = "firewall_blocks_exposed"

    def detect(self, scan: Scan) -> Outcome:
        c = scan.context.values["exposed_services"]
        if c.value is None:
            return unknown(f"Couldn't list listening services: {c.note}")
        ev, notes = list(c.evidence), list(c.notes)
        exposed = net.exposed(scan.context.listeners or [], net.ephemeral_range(scan.host))
        findings: dict[str, bool | None] = {self.FINDING: False}
        reachable = exposed
        if exposed:
            tool, rules, why = firewall_rules(scan)
            if tool and rules is None:
                findings[self.FINDING] = None
                notes.append(Note("limitation", f"A firewall ({tool}) is active",
                                  f"It may block these services, but {why}. Scan with administrator access to see "
                                  "which of them it lets through.", ("net.firewall_off",)))
            elif tool and rules:
                verdict = {s: rules.allows(s.port, s.proto) for s in exposed}
                blocked = [s for s, v in verdict.items() if v is False]
                unsure = [s for s, v in verdict.items() if v is None]
                reachable = [s for s, v in verdict.items() if v is not False]
                ev.append(Evidence.val(f"Blocked by {tool}", ", ".join(s.label() for s in blocked) or "none"))
                if unsure:
                    ev.append(Evidence.val(f"Not sure whether {tool} lets in", ", ".join(s.label() for s in unsure)))
                allowed = [s for s, v in verdict.items() if v]
                # all blocked: lower severity; some let in: as before; only unsure ones left: can't tell
                findings[self.FINDING] = False if allowed else None if unsure else True
                if blocked:
                    them = "them" if len(blocked) > 1 else "it"
                    notes.append(Note("info", f"{tool} blocks {len(blocked)} of them",
                                      f"{', '.join(s.label() for s in blocked)}: listening, but the firewall doesn't "
                                      f"let other machines reach {them}. They become reachable if the firewall is "
                                      "turned off or a rule opens their port, so stop the ones you don't use anyway.",
                                      ("net.firewall_off",)))
        partial = False
        if any(s.port == 22 and s.proto == "tcp" for s in exposed) or any(s.process == "sshd" for s in exposed):
            settings: dict[str, str] | None = {}
            if scan.privileged is not None:
                try:
                    settings = {k: v[0] for k, v in scan.privileged.sshd_settings().items()}
                except HelperError:
                    settings = {}
            if not settings:
                settings = sshd_config(scan.host)
            if settings is None:
                # the config is root-only here: say so rather than claim the defaults
                partial = True
                ev += [Evidence.val("SSH password logins", "unknown (sshd_config needs administrator access)"),
                       Evidence.val("SSH root login", "unknown (sshd_config needs administrator access)")]
                notes.append(Note("limitation", "SSH settings couldn't be read",
                                  "Whether sshd accepts passwords and root logins is in /etc/ssh/sshd_config, which "
                                  "only an administrator can read on this system. Scan with administrator access."))
            else:
                pw = settings.get("passwordauthentication", "yes (default)")
                root = settings.get("permitrootlogin", "prohibit-password (default)")
                ev += [Evidence.val("SSH password logins", pw), Evidence.val("SSH root login", root)]
                if pw.startswith("yes"):
                    notes.append(Note("risk", "SSH accepts passwords",
                                      "Anyone who can reach port 22 can try to guess passwords. Use SSH keys and set "
                                      "PasswordAuthentication no in /etc/ssh/sshd_config.d/."))
        r = scan.host.run("cupsctl")
        if r.ok and "_share_printers=1" in r.stdout:
            ev.append(Evidence.val("CUPS printer sharing", "on"))
        if not c.value:
            return passed("No services listen on all interfaces.", *ev, notes=notes, findings=findings)
        if findings[self.FINDING]:
            return warned(f"{len(exposed)} service{'s listen' if len(exposed) != 1 else ' listens'} on all interfaces, "
                          "but the firewall blocks them.", *ev, notes=notes, findings=findings, partial=partial)
        if len(reachable) < len(exposed):
            return failed(f"{len(reachable)} of {len(exposed)} services listening on all interfaces "
                          f"{'are' if len(reachable) != 1 else 'is'} reachable through the firewall.", *ev,
                          notes=notes, findings=findings, partial=partial)
        return failed(f"{len(exposed)} service{'s are' if len(exposed) != 1 else ' is'} reachable from other "
                      "machines.", *ev, notes=notes, findings=findings, partial=partial)


@register
class DockerBypass(Check):
    id = "net.docker_bypass"

    def detect(self, scan: Scan) -> Outcome:
        r = scan.host.run("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
        if r.missing:
            return absent("Docker isn't installed.")
        if not r.ok:
            if "permission denied" in r.stderr.lower():
                return unknown("Couldn't list containers: you aren't in the docker group.")
            return unknown(f"Couldn't list containers: {r.stderr.strip()[:150]}")
        ev, public = [], []
        for line in r.stdout.splitlines():
            name, _, ports = line.partition("\t")
            for mapping in ports.split(","):
                m = re.match(r"\s*(0\.0\.0\.0|\[?::\]?):(\d+)->(\S+)", mapping)
                if m:
                    public.append(f"{name}:{m.group(2)}")
                    ev.append(Evidence.val(name, f"{m.group(2)} → {m.group(3)} on all interfaces"))
        ev = list({(e.label, e.value): e for e in ev}.values())   # IPv4 and IPv6 bindings of one port
        if public:
            # VERIFY: rootful Podman (netavark) isn't listed by `docker ps`, and may bypass the firewall too
            return failed("Containers publish ports on all interfaces, past the host firewall.", *ev,
                          notes=[Note("info", "Rootless containers are different",
                                      "Rootless Docker and Podman bind ports as your user, so they show up with the "
                                      "other listening services instead.")])
        return passed("No container publishes a port on all interfaces.")


@register
class FirewallOff(Check):
    id = "net.firewall_off"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, active = [], []
        ufw_conf = host.read_sys("/etc/ufw/ufw.conf") or ""
        if re.search(r"^\s*ENABLED\s*=\s*yes", ufw_conf, re.M) and systemctl_state(host, "is-active", "ufw") == "active":
            active.append("ufw")
        for unit, label in (("firewalld", "firewalld"), ("nftables", "nftables"), ("netfilter-persistent", "iptables rules"),
                            ("iptables", "iptables rules")):
            if systemctl_state(host, "is-active", unit) == "active":
                active.append(label)
        if scan.privileged is not None:
            try:
                fw = scan.privileged.firewall_summary()
            except HelperError:
                fw = {}
            if fw.get("nft_rules") is not None:
                ev.append(Evidence.count("nftables rules loaded", fw["nft_rules"]))
            # only chains that filter what comes in count: Docker's, libvirt's and Tailscale's rules don't.
            # (A helper from before this was counted doesn't say: then rules alone aren't taken as a firewall.)
            if fw.get("nft_input_filters") is not None:
                ev.append(Evidence.count("nftables chains filtering incoming connections", fw["nft_input_filters"]))
                if fw["nft_input_filters"] > 0 and not active:
                    active.append("nftables rules")
            if fw.get("ufw"):
                ev.append(Evidence.val("ufw", fw["ufw"]))
                if fw["ufw"].endswith("inactive"):
                    active = [a for a in active if a != "ufw"]
        ev.insert(0, Evidence.val("Active firewall", ", ".join(active) or "none found"))
        if active:
            return passed(f"A host firewall is active ({', '.join(active)}).", *ev)
        return failed("No host firewall is active.", *ev, partial=scan.privileged is None)


# ------------------------------------------------------------------ Wi-Fi

RANDOM_MACS = ("stable", "random", "stable-ssid")


@register
class MacPermanent(Check):
    id = "net.mac_permanent"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        wifi = nm_connections(host, "802-11-wireless")
        if wifi is None:
            return unknown("NetworkManager (nmcli) isn't available; other network managers aren't supported yet.") \
                if wifi_hardware(host) else absent("No Wi-Fi hardware.")
        if not wifi:
            return absent("No saved Wi-Fi networks.")
        cfg = nm_config(host)
        default = (ini.get(cfg, "connection", "wifi.cloned-mac-address") or "").strip()
        scan_rand = (ini.get(cfg, "device", "wifi.scan-rand-mac-address") or "").strip().lower()
        ev = [Evidence.val("Default for Wi-Fi", default or "not set (the hardware address)"),
              Evidence.val("Random address while scanning for networks", "no" if scan_rand in ("no", "false", "0")
                           else "yes (default)")]
        permanent = []
        for uuid in wifi:
            v = nm_get(host, uuid, "connection.id", "802-11-wireless.cloned-mac-address")
            value = v["802-11-wireless.cloned-mac-address"] or "default"
            effective = default if value == "default" and default else value
            if effective in ("default", "preserve", "permanent", ""):
                permanent.append(v["connection.id"])
            ev.append(Evidence.val(v["connection.id"] or uuid, value))
        problems = []
        if permanent:
            problems.append(f"{len(permanent)} of {len(wifi)} saved Wi-Fi network{'s use' if len(wifi) > 1 else ' uses'} "
                            "the device's permanent MAC address")
        if default not in RANDOM_MACS:
            problems.append("networks joined from now on will too (no default is set for new connections)" if permanent
                            else "networks joined from now on will use the device's permanent MAC address (no default "
                                 "is set for new connections)")
        if scan_rand in ("no", "false", "0"):
            problems.append("scanning for networks uses the permanent address (wifi.scan-rand-mac-address=no), "
                            "which is what trackers see most")
        if problems:
            text = "; ".join(problems)
            return failed(text[0].upper() + text[1:] + ".", *ev[:22])
        return passed("Wi-Fi networks, saved and new, use a random or per-network MAC address.", *ev[:22])


@register
class HiddenSsid(Check):
    id = "net.hidden_ssid"

    def detect(self, scan: Scan) -> Outcome:
        wifi = nm_connections(scan.host, "802-11-wireless")
        if wifi is None:
            return unknown("NetworkManager (nmcli) isn't available.") if wifi_hardware(scan.host) else absent("No Wi-Fi hardware.")
        hidden = []
        for uuid in wifi:
            v = nm_get(scan.host, uuid, "connection.id", "802-11-wireless.hidden")
            if v["802-11-wireless.hidden"] == "yes":
                hidden.append(v["connection.id"])
        if hidden:
            return failed(f"Saved hidden networks are probed for everywhere: {', '.join(hidden[:10])}.",
                          *(Evidence.val("Hidden network", h) for h in hidden[:20]))
        return passed("No saved hidden networks.") if wifi else absent("No saved Wi-Fi networks.")


# ------------------------------------------------------------------ names on the network

DHCP_HOSTNAME = ("ipv4.dhcp-send-hostname", "ipv6.dhcp-send-hostname")
NM_DEFAULT = ("-1", "default", "unknown", "")


def dhcp_hostname(host: Host) -> tuple[int, bool, bool] | None:
    """NetworkManager and the hostname in DHCP requests: (saved Wi-Fi and Ethernet connections that send it,
    whether a network joined from now on would, whether NetworkManager takes a default for it from its
    configuration: 1.52 and later, where a connection that doesn't set it shows -1). None without nmcli.
    Tested on NetworkManager 1.58: with [connection] ipv4.dhcp-send-hostname=0, the request carried no hostname."""
    conns = [(u, nm_get(host, u, *DHCP_HOSTNAME)) for kind in ("802-11-wireless", "802-3-ethernet")
             for u in nm_connections(host, kind) or []]
    if nm_connections(host) is None:
        return None
    cfg = nm_config(host)
    default = {p: (ini.get(cfg, "connection", p) or "").strip().lower() for p in DHCP_HOSTNAME}
    supported = any(v.strip().lower() in ("-1", "default") for _, values in conns for v in values.values())

    def sends(prop: str, value: str) -> bool:
        value = value.strip().lower()
        if value in NM_DEFAULT:
            return not supported or default[prop] not in ("0", "false", "no")
        return value not in ("no", "false", "0")
    sending = sum(1 for _, values in conns if any(sends(p, v) for p, v in values.items()))
    future = not supported or any(default[p] not in ("0", "false", "no") for p in DHCP_HOSTNAME)
    return sending, future, supported


NETWORKD_DIRS = ("/usr/lib/systemd/network", "/run/systemd/network", "/etc/systemd/network")


def dhcp_hostname_elsewhere(host: Host) -> list[str]:
    """DHCP clients other than NetworkManager's that send the hostname: systemd-networkd, for a .network file with
    DHCP= on and [DHCPv4] SendHostname not off (on by default, systemd.network(5)); dhcpcd, whose dhcpcd.conf has
    a hostname line (Arch's has one)."""
    out = []
    if systemctl_state(host, "is-active", "systemd-networkd") == "active":
        files: dict[str, Path] = {}
        for d in NETWORKD_DIRS:                                   # a file of the same name in a later folder wins
            for f in children(host.sys_path(d)):
                if f.suffix == ".network":
                    files[f.name] = f
        for f in files.values():
            conf = ini.parse(read_text(host, f) or "")
            dhcp = (ini.get(conf, "Network", "DHCP") or "no").strip().lower()
            if dhcp in ("yes", "true", "ipv4", "1") and ini.truthy(ini.get(conf, "DHCPv4", "SendHostname")) is not False:
                out.append("systemd-networkd")
                break
    if systemctl_state(host, "is-active", "dhcpcd") == "active":
        try:
            conf = host.read_sys("/etc/dhcpcd.conf") or ""
        except Unreadable:
            conf = ""
        if re.search(r"^\s*hostname\b", conf, re.M):
            out.append("dhcpcd")
    return out


@register
class HostnameBroadcast(Check):
    id = "net.hostname_broadcast"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        hostname = (host.read_sys("/proc/sys/kernel/hostname") or "").strip()
        login, words = user_names(host)
        named = mentions_name(hostname, login, words)
        ev = [Evidence.val("Hostname", hostname or "unknown")]
        if named:
            ev.append(Evidence.val("Contains your name", named))
        channels = []
        # Wi-Fi and Ethernet only, as the guide changes: DHCP never runs on VPN tunnels, a VPN app's dummy
        # interfaces or loopback, whatever their (default) setting says
        dhcp = dhcp_hostname(host)
        if dhcp is not None:
            sending, future, supported = dhcp
            if sending:
                channels.append("DHCP")
                ev.append(Evidence.count("Connections that send the hostname over DHCP", sending))
            if future:
                if not sending:
                    channels.append("DHCP (networks joined from now on)")
                ev.append(Evidence.val("Networks joined from now on", "send the hostname" + (
                    "" if supported else " (this NetworkManager has no default for it: before 1.52)")))
        other = dhcp_hostname_elsewhere(host)
        if other:
            channels.append(f"DHCP ({', '.join(other)})")
        if systemctl_state(host, "is-active", "avahi-daemon") == "active":
            conf = ini.parse(host.read_sys("/etc/avahi/avahi-daemon.conf") or "")
            if not ini.truthy(ini.get(conf, "publish", "disable-publishing")):
                channels.append("mDNS (Avahi)")
        if any(s.get("mdns") == "yes" for name, s in resolved_links(host).items() if name != "Global"):
            channels.append("mDNS (systemd-resolved)")
        if any(s.port == 5355 and s.wildcard for s in scan.context.listeners or []):
            channels.append("LLMNR")
        ev.append(Evidence.val("Announced via", ", ".join(channels) or "nothing found"))
        if named and channels:
            return failed(f"The hostname contains your name and is announced via {', '.join(channels)}.", *ev)
        if named:
            return passed("The hostname contains your name, but it doesn't seem to be announced.", *ev)
        return passed("The hostname doesn't contain your name.", *ev)


@register
class KdeConnect(Check):
    id = "net.kdeconnect"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, active, notes = [], [], []
        # the user's own daemon: another account's is theirs to stop (the fixes act on this user's alone)
        mine = "kdeconnectd" in processes(host, own=True)
        if not mine and "kdeconnectd" in processes(host):
            notes.append(Note("info", "Another account has KDE Connect running",
                              "Someone else logged in to this computer has KDE Connect running, and it listens on the "
                              "local network for their paired phones. It stops when they log out; removing KDE Connect "
                              "keeps it from starting again for every account."))
        if mine:
            active.append("KDE Connect")
            text = read_text(host, scan.paths.config_home / "kdeconnect" / "trusted_devices") or ""
            ev.append(Evidence.count("Paired devices", len(re.findall(r"^\[", text, re.M))))
        r = host.run("gnome-extensions", "list", "--enabled")
        if r.ok and "gsconnect@andyholmes.github.io" in r.stdout:
            active.append("GSConnect")
        ports = sorted({s.port for s in scan.context.listeners or [] if 1714 <= s.port <= 1764})
        if ports:
            ev.append(Evidence.val("Listening on", ", ".join(map(str, ports))))
        if active == ["KDE Connect"] and removed_while_running(host, "kdeconnectd"):
            # removing the package left the daemon running from memory: still listening, until logout
            return failed("KDE Connect was removed, but the copy started before that is still running and reachable "
                          "on the local network until you log out or stop it.", *ev)
        if active:
            return failed(f"{' and '.join(active)} {'is' if len(active) == 1 else 'are'} running and reachable on the "
                          "local network.", *ev)
        if installed(host, "kdeconnectd", "kdeconnect-cli"):
            return passed("KDE Connect is installed but not running for you.", *ev, notes=notes)
        if notes:
            return passed("KDE Connect isn't running for you.", *ev, notes=notes)
        return absent("Neither KDE Connect nor GSConnect is in use.")


# ------------------------------------------------------------------ VPN and DNS

def resolved_links(host: Host) -> dict[str, dict]:
    """Per-link DNS state from `resolvectl status`: {"Global" | link: {"servers", "default_route", "dot"}}."""
    r = host.run("resolvectl", "status")
    if not r.ok:
        return {}
    out, name = {}, None
    for line in r.stdout.splitlines():
        m = re.match(r"^(Global|Link \d+ \((\S+)\))", line)
        if m:
            name = m.group(2) or "Global"
            out[name] = {"servers": False, "default_route": False, "route_all": False, "dot": None, "mdns": None}
            continue
        if name is None:
            continue
        s = out[name]
        if re.search(r"DNS Servers?:\s*\S", line) or re.search(r"Current DNS Server:\s*\S", line):
            s["servers"] = True
        if "+DefaultRoute" in line or re.search(r"Default Route:\s*yes", line) or re.search(r"DNS Domain:.*~\.", line):
            s["default_route"] = True
        if re.search(r"DNS Domain:(.*\s)?~\.(\s|$)", line):
            s["route_all"] = True                  # "~.": every query goes here, and not to other links
        m = re.search(r"([+-])DNSOverTLS", line)
        if m:
            s["dot"] = "yes" if m.group(1) == "+" else "no"
        m = re.search(r"DNSOverTLS=(\w+)", line)
        if m:
            s["dot"] = m.group(1)
        # mDNS: "+mDNS" (answers and announces, or resolve-only: the setting line says which),
        # "-mDNS", or "MulticastDNS setting: yes|no|resolve" in older output
        m = re.search(r"([+-])mDNS\b", line)
        if m:
            s["mdns"] = "yes" if m.group(1) == "+" else "no"
        m = re.search(r"MulticastDNS setting:\s*(\w+)", line)
        if m:
            s["mdns"] = m.group(1)
    return out


def resolved_answers(host: Host) -> bool | None:
    """Whether programs' lookups go through systemd-resolved: /etc/resolv.conf names its stub (127.0.0.53, or
    127.0.0.54), or nsswitch.conf's hosts line asks it (nss-resolve); None when resolv.conf can't be read."""
    conf = host.read_sys("/etc/resolv.conf")
    if conf is None:
        return None
    servers = re.findall(r"^\s*nameserver\s+(\S+)", conf, re.M)
    if any(s.startswith(("127.0.0.53", "127.0.0.54")) for s in servers):
        return True
    hosts = re.search(r"^\s*hosts:(.*)$", host.read_sys("/etc/nsswitch.conf") or "", re.M)
    return bool(hosts and re.search(r"\bresolve\b", hosts.group(1)))


def route_link(host: Host, address: str) -> str | None:
    """The interface the kernel would send a packet to `address` through (`ip route get`, which follows policy
    routing; it sends nothing), or None."""
    r = host.run("ip", "route", "get", address)
    first = r.stdout.strip().splitlines()[0] if r.ok and r.stdout.strip() else ""
    m = re.search(r"\bdev (\S+)", first)
    return m.group(1) if m else None


def _protection_notes(host: Host, prov) -> list[Note]:
    """What the VPN app in use does about leaks on its own, and its lockdown setting, in place of the general note
    that kill switches can't be seen."""
    from ..vpn import lockdown_on
    lp = prov.leak_protection
    notes = [Note("info", f"{prov.name} blocks leaks itself",
                  f"{lp.text} (Source: {lp.source}, checked {lp.verified.isoformat()}.)")]
    if lp.lockdown:
        on = lockdown_on(host, prov)
        state = {True: "on here", False: "off here", None: "its state couldn't be read"}[on]
        notes.append(Note("info", f"Lockdown mode is {state}" if on is not None else "Lockdown mode",
                          f"Lockdown mode ({lp.lockdown.where}) also blocks the internet after you disconnect or quit "
                          f"the app; without it, traffic goes out directly then. Turning it on: {lp.lockdown.where}, or "
                          f"the command {lp.lockdown.command}. What it costs: {lp.lockdown.cost}"))
    return notes


@register
class VpnLeaks(Check):
    id = "net.vpn_leaks"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError, load, protecting
        host = scan.host
        vpns = vpn_links(host)
        try:
            match = protecting(host, load(), processes(host))
        except DataError:
            match = None
        prov = match.provider if match else None
        limit = Note("limitation", "Kill switches aren't checked",
                     "Whether traffic stops when the VPN drops depends on the VPN app and can't be seen from its "
                     "configuration. Check your VPN client's kill switch setting.")
        notes = _protection_notes(host, prov) if prov else [limit]
        if not vpns:
            return absent("No VPN is connected now. Connect it and scan again to check for DNS leaks.", notes=notes)
        full = carrying_vpn_links(host, vpns)
        ev = [Evidence.val("VPN interfaces", ", ".join(vpns)), Evidence.val("Carrying all traffic", ", ".join(full) or "none")]
        if not full:
            return passed("The VPN only carries traffic for some networks (split tunnel), so DNS leaks don't apply.",
                          *ev, notes=notes)
        mine = prov is not None and any(prov.matches_interface(t) for t in full)
        if mine:
            ev.append(Evidence.val("VPN app", prov.name))
        leaking = self._leaking(host, vpns, full, ev)
        if leaking is None and not mine:
            return unknown("Couldn't tell where DNS lookups go: neither systemd-resolved's settings nor the servers in "
                           "/etc/resolv.conf could be read.", *ev, notes=notes)
        if mine:
            # its daemon's firewall rejects every lookup but to the servers it set, whatever the resolver would ask
            if leaking:
                notes.insert(1, Note("info", f"{prov.name} rejects lookups that would leave outside it",
                                     f"Left to itself, this computer's resolver would also ask {', '.join(leaking)}: "
                                     f"{prov.name}'s app rejects those lookups while it is connected, so they never "
                                     "leave. The online DNS leak test confirms it."))
            return passed(f"{prov.name} is connected, and its app keeps DNS lookups inside the tunnel.", *ev, notes=notes)
        if leaking:
            return failed(f"DNS queries can go out via {', '.join(leaking)} instead of the VPN.", *ev, notes=notes)
        return passed("DNS queries go through the VPN.", *ev, notes=notes)

    @staticmethod
    def _leaking(host: Host, vpns: list[str], full: list[str], ev: list) -> list[str] | None:
        """The links (or the servers, by the link they are reached through) lookups can go out by, other than the
        VPN's; None when that can't be told."""
        if resolved_answers(host) is False:
            # lookups go to the servers in /etc/resolv.conf, not through systemd-resolved, whatever its settings say
            servers = re.findall(r"^\s*nameserver\s+(\S+)", host.read_sys("/etc/resolv.conf") or "", re.M)
            if not servers:
                return None
            ev.append(Evidence.val("Nameservers in /etc/resolv.conf", ", ".join(servers[:4])))
            out, unknown_route = [], False
            for a in servers:
                link = route_link(host, a.split("%")[0])
                if link is None:
                    unknown_route = True
                elif link not in vpns and link != "lo":
                    out.append(f"{a} (through {link})")
            ev.append(Evidence.val("Nameservers reached outside the VPN", ", ".join(out) or "none"))
            return None if unknown_route and not out else out
        links = resolved_links(host)
        if not links:
            return None
        # A "~." routing domain on the VPN's link (or the global settings) sends every query there and keeps the
        # other links out, unless they carry "~." too (systemd-resolved(8)); without one, every link with
        # DefaultRoute is asked as well.
        captured = [name for name, s in links.items() if (name in full or name == "Global") and s["route_all"]]
        leaking = [name for name, s in links.items() if name not in vpns and name != "Global" and s["servers"]
                   and (s["route_all"] if captured else s["default_route"])]
        if captured:
            ev.append(Evidence.val("Every lookup routed to", ", ".join("the global DNS settings" if n == "Global" else n
                                                                      for n in captured) + " (~.)"))
        ev.append(Evidence.val("Other links answering any DNS query", ", ".join(leaking) or "none"))
        return leaking


# local resolvers that always encrypt what they send out, and ones that may not (unbound resolves
# recursively in plain DNS by default; the others forward to whatever upstream they are given)
ENCRYPTING_RESOLVERS = {"dnscrypt-proxy", "stubby", "cloudflared"}
LOCAL_RESOLVERS = ENCRYPTING_RESOLVERS | {"unbound", "AdGuardHome", "dnsproxy", "blocky", "kresd"}


def cite(f) -> str:
    """A fact with its receipt."""
    return f"{f.text} (Source: {f.source}, checked {f.verified.isoformat()}.)"


def rating_note(p) -> Note:
    from ..vpn import rate
    r = rate(p)
    why = p.why or ("The app has no rating for it yet: the facts below are what is on record." if r.tier == "unrated"
                    else "")
    return Note("info" if not r.concern else "risk", f"DA Privacy Kit's rating: {r.label}", why,
                ("net.vpn_trust",) if r.concern else ())


def provider_notes(p) -> list[Note]:
    """The app's rating of a VPN provider, then what is publicly known about it, by topic, each fact with its
    source and date."""
    from ..vpn import TOPIC_TITLES, TOPICS, stale
    notes = [rating_note(p)]
    for topic in TOPICS:
        facts = [f for f in p.facts if f.topic == topic]
        if facts:
            notes.append(Note("info", TOPIC_TITLES[topic], " ".join(cite(f) for f in facts)))
    if p.group_facts:
        notes.append(Note("info", f"Its owner, {p.group_name}", " ".join(cite(f) for f in p.group_facts)))
    if p.leak_test:
        notes.append(Note("info", f"{p.name}'s own connection check",
                          f"With the VPN on, open {p.leak_test} to see whether {p.name} sees your traffic as its own."))
    old = stale(p)
    if old:
        notes.append(Note("limitation", "These facts may be out of date",
                          f"Some were last checked on {old.isoformat()}. Ownership in this industry changes often: "
                          "follow the sources to see whether they still hold."))
    return notes


def vpn_state(scan: Scan):
    """(the provider data, tunnels, those carrying traffic, providers recognised, the one in use or running)."""
    from ..vpn import identify, load
    data = load()
    tunnels = vpn_links(scan.host)
    carrying = carrying_vpn_links(scan.host, tunnels)
    matches = identify(scan.host, data, processes(scan.host))
    in_use = [m for m in matches if m.in_use]
    if in_use and (carrying or not tunnels):
        current = in_use[0]
    elif matches and not carrying:
        current = matches[0]
    else:
        current = None
    return data, tunnels, carrying, matches, current


@register
class VpnProvider(Check):
    id = "net.vpn_provider"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError, rate
        try:
            data, tunnels, carrying, matches, current = vpn_state(scan)
        except DataError as e:
            return unknown(f"The app's list of VPN providers couldn't be read: {e}")
        ev = []
        if tunnels:
            ev.append(Evidence.val("VPN interfaces", ", ".join(tunnels)))
            ev.append(Evidence.val("Carrying internet traffic", ", ".join(carrying) or "none"))
        for m in matches:
            ev.append(Evidence.val(f"{m.provider.name} recognised by",
                                   ", ".join(f"{k} {w}" for k, w in m.signs)[:200]))
            if m.relay:
                ev.append(Evidence.val(f"{m.provider.name} server in use", m.relay))
        if current is not None:
            p = current.provider
            ev.append(Evidence.val("DA Privacy Kit's rating", rate(p).label))
            if current.in_use:
                owner = f", owned by {p.group_name}" if p.group_name else ""
                return passed(f"Your VPN is {p.name}{owner}.", *ev, notes=provider_notes(p))
            return passed(f"{p.name}'s app is installed and running, but not connected now.", *ev,
                          notes=provider_notes(p))
        if carrying:
            return passed(f"A VPN carries this computer's traffic ({', '.join(carrying)}); its provider wasn't "
                          "recognised.", *ev,
                          notes=[Note("info", "Finding out who runs it",
                                      "The app recognises the Linux apps of the best-known providers. A tunnel set up "
                                      "by hand (WireGuard or OpenVPN files) carries no name: the provider is whoever "
                                      "gave you its configuration. The online test \u201cTraffic doesn't leave "
                                      "through the VPN\u201d shows which network your traffic exits from.",
                                      ("net.vpn_exit",))])
        return absent("No VPN is in use.", *ev)


@register
class VpnTrust(Check):
    id = "net.vpn_trust"

    def detect(self, scan: Scan) -> Outcome:
        from ..vpn import DataError, rate
        try:
            _data, _tunnels, carrying, _matches, current = vpn_state(scan)
        except DataError as e:
            return unknown(f"The app's list of VPN providers couldn't be read: {e}")
        if current is None:
            return (passed("The VPN in use wasn't recognised, so it isn't rated.") if carrying
                    else absent("No VPN is in use."))
        p, r = current.provider, rate(current.provider)
        state = "Your VPN" if current.in_use else "The VPN app running here"
        ev = [Evidence.val("Provider", p.name), Evidence.val("Rating", r.label)]
        if not r.concern:
            return passed(f"{state}, {p.name}, is rated {r.label}.", *ev, notes=[rating_note(p)],
                          findings=r.findings())
        reasons = []
        for title, what in (("Harm on record", "harm"), ("Its Linux app is closed source", "closed_client"),
                            (f"Its owner, {r.owner}", "ownership")):
            facts = [f for f in r.reasons if what in f.supports]
            if facts:
                reasons.append(Note("risk", title, " ".join(cite(f) for f in facts)))
        if p.why:
            reasons.append(Note("info", "DA Privacy Kit's view", p.why))
        reasons.append(rated_providers_note(_data))
        return failed(f"{state}, {p.name}, is rated {r.label}.", *ev, notes=reasons, findings=r.findings())


def rated_providers_note(data) -> Note:
    """The providers rated Recommended and Good, from the data as shipped (never a list written into the
    catalogue's text, which would go stale as the ratings change)."""
    from ..vpn import rate
    tiers: dict[str, list[str]] = {"recommended": [], "good": []}
    for p in data:
        r = rate(p)
        if r.tier in tiers:
            tiers[r.tier].append(p.name)
    parts = [f"{label}: {', '.join(sorted(names)) or 'none'}"
             for label, names in (("Recommended", tiers["recommended"]), ("Good", tiers["good"]))]
    return Note("info", "Providers rated Recommended or Good",
                ". ".join(parts) + ". Only the Linux app is judged; the facts behind each rating are under "
                "“Which VPN this computer uses, and who runs it” once that provider is in use, and in the app's "
                "vpn-providers.yaml with each fact's source and date.")


@register
class DnsUnencrypted(Check):
    id = "net.dns_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        servers = re.findall(r"^\s*nameserver\s+(\S+)", host.read_sys("/etc/resolv.conf") or "", re.M)
        ev = [Evidence.val("Nameservers in /etc/resolv.conf", ", ".join(servers[:4]) or "none")]
        doh = Note("limitation", "Browsers may encrypt DNS themselves",
                   "Firefox and Chromium-based browsers can send DNS over HTTPS on their own; the app can't see that "
                   "setting yet. Only the system's own DNS is judged here.")
        if any(s.startswith("127.0.0.53") for s in servers):
            links = resolved_links(host)
            dot = [s["dot"] for s in links.values() if s["dot"]]
            ev.append(Evidence.val("systemd-resolved DNSOverTLS", ", ".join(sorted(set(dot))) or "unknown"))
            if any(d == "yes" for d in dot):
                return passed("DNS is encrypted (DNS over TLS).", *ev, notes=[doh])
            if any(d == "opportunistic" for d in dot):
                return warned("DNS over TLS is opportunistic: it falls back to plain DNS without telling you.",
                              *ev, notes=[doh])
            if not links:
                return unknown("Couldn't read systemd-resolved's settings.", *ev, notes=[doh])
            return failed("DNS queries are sent unencrypted.", *ev, notes=[doh])
        local = processes(host) & LOCAL_RESOLVERS
        if servers and all(s.startswith(("127.", "::1")) for s in servers) and local & ENCRYPTING_RESOLVERS:
            return passed(f"DNS goes through a local encrypting resolver ({', '.join(sorted(local))}).", *ev, notes=[doh])
        if servers and all(s.startswith(("127.", "::1")) for s in servers) and local:
            return unknown(f"DNS goes through a local resolver ({', '.join(sorted(local))}), which encrypts only if it "
                           "is set to: check that its upstream servers use DNS over TLS or HTTPS.", *ev, notes=[doh])
        if servers and all(s.startswith(("127.", "::1")) for s in servers):
            return unknown("DNS goes through a local resolver the app doesn't recognise.", *ev, notes=[doh])
        return failed("DNS queries are sent unencrypted.", *ev, notes=[doh])


def ip6_privacy_default(host: Host) -> tuple[str, str] | None:
    """What a NetworkManager connection that doesn't set ipv6.ip6-privacy gets (NetworkManager.conf(5)): its
    [connection] default, else the kernel's default for new interfaces. (value, where from); None without nmcli."""
    if nm_connections(host) is None:
        return None
    v = (ini.get(nm_config(host), "connection", "ipv6.ip6-privacy") or "").strip()
    if v and v != "-1":
        return v, "NetworkManager's default"
    return (host.read_sys("/proc/sys/net/ipv6/conf/default/use_tempaddr") or "").strip(), "the kernel's default"


@register
class Ipv6Privacy(Check):
    id = "net.ipv6_privacy"
    FUTURE = "ipv6_privacy_default_off"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        ev, off = [], []
        for p in children(host.sys_path("/sys/class/net")):
            if p.name == "lo" or not (p / "device").exists():          # physical interfaces only
                continue
            conf = f"/proc/sys/net/ipv6/conf/{p.name}"
            if (host.read_sys(f"{conf}/disable_ipv6") or "0").strip() == "1":
                ev.append(Evidence.val(p.name, "IPv6 off"))
                continue
            temp = (host.read_sys(f"{conf}/use_tempaddr") or "").strip()
            ev.append(Evidence.val(f"{p.name} use_tempaddr", temp or "unknown"))
            if temp in ("0", "1", "-1"):
                off.append(p.name)
        if not ev:
            return absent("No physical network interfaces.")
        default = ip6_privacy_default(host)
        later = default is not None and default[0] not in ("2", "")
        if default is not None:
            ev.append(Evidence.val("Networks joined from now on", (default[0] or "unknown") + f" ({default[1]})"))
        if off:
            return failed(f"IPv6 privacy addresses aren't used on {', '.join(off)}: on a network that offers IPv6, "
                          "every site you visit sees the same address for as long as you stay on it (and on every "
                          "network, where the address is made from the hardware address).", *ev)
        if later:
            return failed("IPv6 privacy addresses are used now, but networks joined from now on won't use them: "
                          f"{default[1]} is {default[0]}.", *ev)
        return passed("IPv6 privacy addresses are preferred, on networks joined from now on too.", *ev)


@register
class Bluetooth(Check):
    id = "net.bluetooth"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        if not children(host.sys_path("/sys/class/bluetooth")):
            return absent("No Bluetooth adapter.")
        if systemctl_state(host, "is-active", "bluetooth") != "active":
            return passed("The Bluetooth service isn't running.")
        r = host.run("bluetoothctl", "show", timeout=5)
        if not r.ok or "No default controller" in r.stdout:
            return unknown("Couldn't read the Bluetooth adapter's state.")
        def field(name):
            m = re.search(rf"^\s*{name}:\s*(.+)$", r.stdout, re.M)
            return m.group(1).strip() if m else ""
        powered, discoverable, alias = field("Powered") == "yes", field("Discoverable") == "yes", field("Alias")
        login, words = user_names(host)
        named = mentions_name(alias, login, words)
        ev = [Evidence.val("Powered", powered), Evidence.val("Discoverable", discoverable), Evidence.val("Name", alias)]
        problems = (["discoverable"] if discoverable else []) + ([f"named after you ({named})"] if named and powered else [])
        if problems:
            return failed(f"Bluetooth is {' and '.join(problems)}.", *ev)
        if powered:
            return passed("Bluetooth is on, but hidden from devices nearby and not named after you.", *ev,
                          notes=[Note("info", "While it is connected",
                                      "When it is talking to headphones or a mouse, its address can be picked up by "
                                      "someone nearby with the right equipment. Turning it off when you don't use it "
                                      "stops that.")])
        return passed("Bluetooth is off.", *ev)


@register
class ConnectivityCheck(Check):
    id = "net.connectivity_check"

    def detect(self, scan: Scan) -> Outcome:
        if not installed(scan.host, "NetworkManager"):
            return absent("NetworkManager isn't installed.")
        cfg = nm_config(scan.host)
        uri = ini.get(cfg, "connectivity", "uri")
        enabled = ini.truthy(ini.get(cfg, "connectivity", "enabled"))
        if uri and enabled is not False:
            host = re.sub(r"^\w+://([^/]+).*", r"\1", uri)
            return failed(f"NetworkManager checks connectivity by contacting {host}.", Evidence.val("URI", uri[:150]))
        return passed("NetworkManager's connectivity check is off.")


# ------------------------------------------------------------------ saved Wi-Fi networks

STALE_DAYS = 90


def wifi_last_used(host: Host) -> list[tuple[str, str, float | None]] | None:
    """(uuid, name, days since last used or None) per saved Wi-Fi network, or None without nmcli."""
    wifi = nm_connections(host, "802-11-wireless")
    if wifi is None:
        return None
    out, now = [], time.time()
    for uuid in wifi:
        v = nm_get(host, uuid, "connection.id", "connection.timestamp")
        ts = v["connection.timestamp"]
        out.append((uuid, v["connection.id"] or uuid, (now - int(ts)) / 86400 if ts.isdigit() and int(ts) > 0 else None))
    return out


@register
class WifiHistory(Check):
    id = "net.wifi_history"

    def detect(self, scan: Scan) -> Outcome:
        nets = wifi_last_used(scan.host)
        if nets is None:
            return unknown("NetworkManager (nmcli) isn't available.") if wifi_hardware(scan.host) else absent("No Wi-Fi hardware.")
        if not nets:
            return absent("No saved Wi-Fi networks.")
        ages = [a for _, _, a in nets if a is not None]
        stale = [n for _, n, a in nets if a is not None and a >= STALE_DAYS]
        ev = [Evidence.count("Saved Wi-Fi networks", len(nets)), Evidence.count("With a last-used time", len(ages))]
        if ages:
            ev.append(Evidence.val("Longest ago used", f"{max(ages):.0f} days"))
        ev.append(Evidence.count(f"Not used for {STALE_DAYS} days or more", len(stale)))
        note = Note("info", "Where the passwords live",
                    "Saved Wi-Fi passwords are in /etc/NetworkManager/system-connections, readable by root and by "
                    "anyone who boots the disk elsewhere unless it is encrypted.", ("enc.fde_missing",))
        if stale:
            return failed(f"{len(stale)} saved network{'s' if len(stale) > 1 else ''} haven't been used for "
                          f"{STALE_DAYS} days or more; together, saved networks are a history of places.", *ev, notes=[note])
        return passed(f"Every saved network was used in the last {STALE_DAYS} days.", *ev, notes=[note])


def open_autoconnect(host: Host) -> list[tuple[str, str]] | None:
    """(uuid, name) of saved networks without a password that connect on their own."""
    wifi = nm_connections(host, "802-11-wireless")
    if wifi is None:
        return None
    out = []
    for uuid in wifi:
        v = nm_get(host, uuid, "connection.id", "802-11-wireless-security.key-mgmt", "connection.autoconnect")
        if not v["802-11-wireless-security.key-mgmt"] and v["connection.autoconnect"] not in ("no", "false"):
            out.append((uuid, v["connection.id"] or uuid))
    return out


@register
class OpenAutoconnect(Check):
    id = "net.open_autoconnect"

    def detect(self, scan: Scan) -> Outcome:
        found = open_autoconnect(scan.host)
        if found is None:
            return unknown("NetworkManager (nmcli) isn't available.") if wifi_hardware(scan.host) else absent("No Wi-Fi hardware.")
        if not nm_connections(scan.host, "802-11-wireless"):
            return absent("No saved Wi-Fi networks.")
        ev = [Evidence.val("Open network that reconnects by itself", n) for _, n in found[:20]]
        if found:
            return failed(f"{len(found)} saved open network{'s' if len(found) > 1 else ''} reconnect{'' if len(found) > 1 else 's'} "
                          "automatically: any hotspot with the same name is joined without asking.", *ev)
        return passed("No saved open network connects on its own.")

# ------------------------------------------------------------------ the outgoing firewall (a feature)

def opensnitch_notes(s) -> list[Note]:
    """What OpenSnitch, as it is set here, keeps on the disk or lets through: shown with the feature, and its guide
    deals with each."""
    from ..opensnitch import LOG_LEVELS
    notes = []
    if s.config is not None and (s.log_level is None or s.log_level < 3):
        level = "isn't set (so 1, info)" if s.config.get("LogLevel") is None else \
            f"is {s.log_level} ({LOG_LEVELS.get(s.log_level, '?')})" if s.log_level is not None else "isn't a number"
        notes.append(Note("risk", "Your answers are written to a log",
                          f"OpenSnitch's log level {level}: every question you answer, every one left unanswered and "
                          "every rule you delete is a line in /var/log/opensnitchd.log naming the website or program, "
                          "kept for weeks and readable by every account on this computer. Connections a rule decides "
                          "aren't logged. The guide sets the level to 3 (warnings only)."))
    if s.database_file:
        notes.append(Note("risk", "Every connection is saved to a file",
                          f"OpenSnitch's window keeps its list of connections in {s.database_file} rather than in "
                          "memory: every program and website, with the time. The guide puts it back in memory."))
    if s.loggers:
        notes.append(Note("risk", "Connections are sent to another log",
                          "OpenSnitch's settings forward its events (Server.Loggers) to syslog or a log server, which "
                          "keeps every connection it reports."))
    return notes


@register
class OutgoingFirewall(Check):
    id = "net.outgoing_firewall"

    def detect(self, scan: Scan) -> Outcome:
        from .. import opensnitch
        s = opensnitch.read(scan.host, scan.paths)
        if not s.daemon:
            return warned("Not set up: OpenSnitch, an outgoing firewall that asks you before a program connects out, "
                          "isn't installed.",
                          notes=[Note("info", "What it is for",
                                      "Most firewalls stop other computers connecting in. OpenSnitch watches the other "
                                      "way: it asks you, program by program, before anything on this computer connects "
                                      "out, so you see what phones home and can stop it, even in programs with no "
                                      "setting for it. The guide explains it, gives the commands to install it and sets "
                                      "up a gentle start.")])
        starter = opensnitch.starter_state(scan.host, s)
        ev = [Evidence.val("Version", s.version or "unknown"),
              Evidence.val("Daemon", ("running" if s.active else "not running")
                           + (", starts at boot" if s.enabled else ", doesn't start at boot")),
              Evidence.val("Its window", "running" if s.window_running else "not running"),
              Evidence.val("A question nobody answers", s.window_action),
              Evidence.val("A connection while the window isn't running", s.daemon_action or "unknown"),
              Evidence.val("Log level", s.log_level if s.log_level is not None else "unknown"),
              Evidence.val("Its list of connections", "in a file" if s.database_file else "in memory"),
              Evidence.val("The app's starter rules", {"current": "in place", "outdated": "in place, out of date",
                                                       "missing": "not added"}[starter]),
              Evidence.val("Connectivity checks", "blocked" if opensnitch.PREFIX + "deny-connectivity-checks"
                           in s.own_rules else "allowed")]
        if s.rules is not None:
            ev.append(Evidence.count("Rules of your own", s.other_rules))
        notes = opensnitch_notes(s)
        if not s.window_running and s.active:
            notes.append(Note("info", "Nobody is asked",
                              f"OpenSnitch's window isn't running, so a connection without a rule is "
                              f"{'blocked' if s.daemon_action in ('deny', 'reject') else 'allowed'} without asking. It "
                              "can start at login: its tray menu's Autostart."))
        if s.queue_bypass and s.active:
            notes.append(Note("info", "If OpenSnitch stops",
                              "Connections then flow unchecked until it is back (QueueBypass, its default): a crash "
                              "doesn't cut the network, and doesn't block anything either."))
        if s.config is None:
            what = "can't be read" if s.config_unreadable else "isn't there or isn't valid JSON"
            return unknown(f"OpenSnitch is installed, but its settings ({opensnitch.CONFIG}) {what}.", *ev, notes=notes)
        if not s.active:
            return warned("OpenSnitch is installed, but its daemon isn't running: nothing is filtered.", *ev, notes=notes)
        if s.deny_mode:
            return passed("OpenSnitch is on, in deny mode: nothing without a rule gets out unless you allow it.",
                          *ev, notes=notes)
        notes.insert(0, Note("risk", "Allow mode",
                             "A connection you don't answer for, whatever else connects while a question is open, "
                             "and every connection while OpenSnitch's window isn't running, is allowed. Good while you learn what your programs do; once questions have "
                             "become rare, turn on deny mode in the guide (Set up…)."))
        return warned("OpenSnitch is on, in allow mode: what you don't answer for is let through.", *ev, notes=notes)


# ------------------------------------------------------------------ root certificates added to the system's store

LOCAL_ANCHORS = ("/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors",
                 "/etc/ca-certificates/trust-source/anchors", "/etc/pki/trust/anchors")
# `trust anchor FILE` (p11-kit: Arch's documented way, and Fedora's and openSUSE's tool too) writes NAME.p11-kit
# beside the anchors folder, not in it (seen on CachyOS). Only files directly there: blocklist/ holds distrust.
LOCAL_SOURCES = ("/etc/ca-certificates/trust-source", "/etc/pki/ca-trust/source", "/etc/pki/trust")
ROOT_SUFFIXES = (".crt", ".pem", ".cer", ".p11-kit")


def local_roots(scan: Scan) -> list[str]:
    """The certificate files an administrator added to the system's trust store, as paths on the system."""
    host, out = scan.host, []
    for d in LOCAL_ANCHORS:
        stack = [host.sys_path(d)]
        while stack:
            for p in children(stack.pop()):
                if p.is_dir():
                    stack.append(p)
                elif p.suffix in ROOT_SUFFIXES:
                    out.append(f"{d}/{p.relative_to(host.sys_path(d))}")
    for d in LOCAL_SOURCES:
        for p in children(host.sys_path(d)):
            if p.is_file() and p.suffix in ROOT_SUFFIXES and "x-distrusted: true" not in (read_text(host, p) or ""):
                out.append(f"{d}/{p.name}")
    return sorted(out)


def root_subject(scan: Scan, path: str) -> str:
    """Who a certificate says it is (its common name, else its organisation), when openssl is there to read it."""
    if not installed(scan.host, "openssl"):
        return ""
    r = scan.host.run("openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253", "-in", str(scan.host.sys_path(path)))
    if not r.ok:
        return ""
    m = re.search(r"(?:^|[=,])CN=((?:\\.|[^,])+)", r.stdout) or re.search(r"(?:^|[=,])O=((?:\\.|[^,])+)", r.stdout)
    return m.group(1).replace("\\", "").strip()[:80] if m else ""


@register
class LocalRootCerts(Check):
    id = "net.local_root_certs"

    def detect(self, scan: Scan) -> Outcome:
        roots = local_roots(scan)
        limit = Note("limitation", "Browsers' own lists aren't read",
                     "Firefox and the Chromium family keep certificates added inside the browser in stores of "
                     "their own (Firefox: Settings, Privacy & Security, Certificates, View Certificates, "
                     "Authorities). This check reads the system's store, which every program uses.")
        if not roots:
            return passed("No root certificate was added to this computer's store.", notes=[limit])
        ev = []
        for path in roots[:20]:
            who = root_subject(scan, path)
            ev.append(Evidence.val(path, f"issued to {who}" if who else "a certificate file", named=True))
        n = len(roots)
        return warned(f"{n} root certificate{'s were' if n > 1 else ' was'} added to this computer's store: whoever "
                      f"holds {'their keys' if n > 1 else 'its key'} can read and change what you send to any website, "
                      "with no warning. Fine if you know what each is for.",
                      Evidence.count("Added root certificates", n), *ev, notes=[limit])

