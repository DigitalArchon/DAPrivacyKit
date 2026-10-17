"""Network exposure and tracking (net.*)."""

from __future__ import annotations

import os
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


NM_TYPES = {"wifi": ("wifi", "802-11-wireless"), "ethernet": ("ethernet", "802-3-ethernet")}


def _nm_spec_covers(spec: str, kind: str) -> bool:
    """Whether a match-device value (NetworkManager.conf(5), "Device List Format") covers every device of a kind
    ("wifi", "ethernet"): "*", "type:KIND", or only negative specs ("except:...") that don't leave the kind out.
    A spec naming particular devices (interface-name:, driver:, mac:) covers those alone, not the kind."""
    specs = [s.strip() for s in re.split(r"(?<!\\)[,;]", spec) if s.strip()]
    types = NM_TYPES[kind]
    negative = [s[len("except:"):] for s in specs if s.startswith("except:")]
    positive = [s for s in specs if not s.startswith("except:")]
    if any(n == "*" or (n.startswith("type:") and n[5:] in types) for n in negative):
        return False
    return not positive or any(p == "*" or (p.startswith("type:") and p[5:] in types) for p in positive)


def nm_default(cfg: dict, key: str, kind: str, prefix: str = "connection") -> tuple[str | None, str | None]:
    """The default NetworkManager gives a connection of a kind ("wifi", "ethernet") that doesn't set `key` itself
    (with `prefix` "device": a device's setting): (value, the section it comes from), or (None, None) when no section
    sets it. The [connection*] sections are searched in NetworkManager's order (NetworkManager.conf(5)): later files'
    first, top to bottom within a file, as --print-config lists them, and [connection] last; the first that applies to
    the kind and has the key wins, and one that applies with stop-match=yes ends the search. Fedora 40 and later set
    Wi-Fi's MAC address default in [connection.22-wifi-mac-addr] (match-device=type:wifi), not in [connection]."""
    named = [g[0] for g in cfg if len(g) == 1 and g[0].startswith(prefix) and g[0] != prefix]
    for section in named + [prefix]:
        values = cfg.get((section,))
        if values is None:
            continue
        spec = values.get("match-device")
        if spec is not None and not _nm_spec_covers(spec, kind):
            continue
        if values.get(key, "").strip():
            return values[key].strip(), section
        if ini.truthy(values.get("stop-match")):
            return None, section
    return None, None


def nm_version(host: Host) -> tuple[int, int] | None:
    """NetworkManager's version (major, minor): the daemon's (`NetworkManager --version`), else nmcli's."""
    for argv in (("NetworkManager", "--version"), ("nmcli", "--version")):
        r = host.run(*argv)
        m = re.search(r"(\d+)\.(\d+)\.\d+", r.stdout) if r.ok else None
        if m:
            return int(m.group(1)), int(m.group(2))
    return None


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
            # sshd splits a keyword from its value at white space or one "=" ("PasswordAuthentication=no",
            # "PasswordAuthentication = no"); keywords and yes/no values are read regardless of case
            m = re.match(r"\s*([^\s=#]\S*?)(?:\s*=\s*|\s+|$)(.*)$", line)
            if not m or not m.group(1):
                continue
            key, value = m.group(1).lower(), m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
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


def _firewall_cmd_error(r) -> str:
    """What firewall-cmd said when it failed, in a few words (polkit's "Authorization failed", INVALID_ZONE...)."""
    text = (r.stderr or r.stdout or "").strip().splitlines()
    return text[0].strip()[:120] if text else f"exit status {r.returncode}"


def _firewalld_service_ports(host: Host, svc: str, seen: set[str] | None = None) -> list[str] | None:
    """The ports a firewalld service opens (`firewall-cmd --info-service`), with those of the services it includes
    (samba-client includes netbios-ns, 137/udp); ["0/none"] for a service that opens none, None when it can't be
    read."""
    seen = set() if seen is None else seen
    if svc in seen or len(seen) > 20:
        return []
    seen.add(svc)
    info = host.run("firewall-cmd", f"--info-service={svc}")
    if not info.ok:
        return None
    pm = re.search(r"^\s*ports:[ \t]*(.*)$", info.stdout, re.M)
    if pm is None:
        return None
    ports = pm.group(1).split()
    im = re.search(r"^\s*includes:[ \t]*(.*)$", info.stdout, re.M)
    for inc in (im.group(1).split() if im else []):
        more = _firewalld_service_ports(host, inc, seen)
        if more is None:
            return None
        ports += [p for p in more if p != "0/none"]
    return ports or ["0/none"]                          # a service with no ports (e.g. a helper only): opens nothing


def _firewalld_rules(host: Host) -> tuple[net.FirewallRules | None, str]:
    """What firewalld's active zones let in, and why not when that couldn't be read. firewalld 2.x marks the
    default zone in `--get-active-zones` ("FedoraWorkstation (default)"): a zone's name is the first word."""
    r = host.run("firewall-cmd", "--get-active-zones")
    if r.missing:
        return None, "firewall-cmd isn't installed"
    zones = [ln.split()[0] for ln in r.stdout.splitlines() if ln.strip() and not ln[0].isspace()] if r.ok else []
    if not zones:
        d = host.run("firewall-cmd", "--get-default-zone")
        zones = d.stdout.split()[:1] if d.ok else []
        if not zones:
            return None, f"firewall-cmd didn't name its zones ({_firewall_cmd_error(d if not d.ok else r)})"
    merged = None
    for zone in zones:
        z = host.run("firewall-cmd", f"--zone={zone}", "--list-all")
        if not z.ok:
            return None, f"firewall-cmd couldn't list the zone {zone} ({_firewall_cmd_error(z)})"
        m = re.search(r"^\s*services:[ \t]*(.*)$", z.stdout, re.M)
        ports = {}
        for svc in (m.group(1).split() if m else []):
            ports[svc] = _firewalld_service_ports(host, svc) or []       # [] when unreadable: counted as unparsed
        rules = net.parse_firewalld_zone(z.stdout, ports)
        rules.open_ports = [p for p in rules.open_ports if p[2] != "none"]
        if merged is None:
            merged = rules
        else:
            merged.default_allows = merged.default_allows or rules.default_allows
            merged.open_ports += rules.open_ports
            merged.unparsed += rules.unparsed
    return merged, ""


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
        rules, why = _firewalld_rules(host)
        return "firewalld", rules, "" if rules else f"its zones couldn't be read: {why}"
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
                # only ufw's rules are read through the helper: for the others administrator access changes nothing
                text = (f"It may block these services, but {why}. Scan with administrator access to see which of them "
                        "it lets through." if tool == "ufw" and scan.privileged is None else
                        f"It may block these services, but {why}, so the app can't tell which of them it lets through.")
                notes.append(Note("limitation", f"A firewall ({tool}) is active", text, ("net.firewall_off",)))
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
                if pw.lower().startswith("yes"):
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

    ROOTLESS = Note("info", "Rootless containers are different",
                    "Rootless Docker and Podman bind ports as your user, so they show up with the other listening "
                    "services instead, where the host firewall filters them.", ("net.exposed_services",))

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        if not installed(host, "docker"):
            return absent("Docker isn't installed.")
        podman = self._podman(host)                     # `docker --version` asks the program, not the daemon
        if podman is not None:
            return self._podman_outcome(host, podman)
        if not self._docker_running(host):
            # never `docker ps` then: through docker.socket it would start the service (and the containers set to
            # restart with it), and a scan changes nothing
            return passed("Docker's service isn't running, so no container is running and no port is published. It "
                          "starts the first time something uses Docker (docker.socket starts it), with the containers "
                          "set to restart: scan again after using Docker.",
                          Evidence.val("docker.service", systemctl_state(host, "is-active", "docker.service")))
        r = host.run("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
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
        if public and self._rootless_docker(host):
            return passed("Docker here is rootless: the ports its containers publish are ordinary listening sockets, "
                          "which the host firewall filters.", *ev, notes=[self.ROOTLESS])
        if public:
            # VERIFY: rootful Podman (netavark) isn't listed by `docker ps`, and may bypass the firewall too
            return failed("Containers publish ports on all interfaces, past the host firewall.", *ev,
                          notes=[self.ROOTLESS, self.DOCKER_USER])
        return passed("No container publishes a port on all interfaces.")

    DOCKER_USER = Note("limitation", "Rules in DOCKER-USER aren't read",
                       "Firewall rules you add to Docker's DOCKER-USER chain apply before Docker's own, but reading "
                       "them needs administrator access and what they block depends on what they match, so the app "
                       "keeps listing these ports. Once your rules cover them, accept this finding (with a note naming "
                       "the rules).")

    @staticmethod
    def _docker_running(host: Host) -> bool:
        """Whether Docker's daemon runs, or containers it left running do (live-restore keeps them when it stops:
        their containerd shims run on). Unknown is taken as running."""
        state = systemctl_state(host, "is-active", "docker.service")
        if state in ("", "active", "activating", "reloading", "deactivating"):
            return True
        return any(p.startswith(("dockerd", "containerd-shim", "com.docker")) for p in processes(host))

    @staticmethod
    def _podman(host: Host) -> str | None:
        """When `docker` is Podman (podman-docker's shim, which prints Podman's version): "rootless", "root" or ""
        (it couldn't say); None when it is Docker or isn't installed."""
        r = host.run("docker", "--version")
        if not r.ok or not r.stdout.lower().startswith("podman"):
            return None
        info = host.run("docker", "info", "--format", "{{.Host.Security.Rootless}}")
        if not info.ok:
            return ""
        return {"true": "rootless", "false": "root"}.get(info.stdout.strip().lower(), "")

    def _podman_outcome(self, host: Host, mode: str) -> Outcome:
        ev = [Evidence.val("docker", "Podman (podman-docker)"),
              Evidence.val("Runs containers", {"rootless": "without root (rootless)", "root": "as root"}.get(mode, "unknown"))]
        if mode == "rootless":
            return passed("docker here is Podman, running your containers without root: their published ports are "
                          "ordinary listening sockets, which the host firewall filters.", *ev, notes=[self.ROOTLESS])
        if mode == "root":
            return unknown("docker here is Podman running as root, whose containers' firewall rules the app doesn't "
                           "read yet: check where they publish ports with sudo podman ps.", *ev)
        return unknown("docker here is Podman, which couldn't say how it runs containers (podman info failed).", *ev)

    @staticmethod
    def _rootless_docker(host: Host) -> bool:
        """Whether the Docker daemon `docker` talks to is rootless Docker (its security options name rootless)."""
        r = host.run("docker", "info", "--format", "{{json .SecurityOptions}}")
        return r.ok and "rootless" in r.stdout


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
        default, where = nm_default(cfg, "wifi.cloned-mac-address", "wifi")
        default = default or ""
        scan_rand = (nm_default(cfg, "wifi.scan-rand-mac-address", "wifi", "device")[0] or "").lower()
        ev = [Evidence.val("Default for Wi-Fi", (f"{default} (from NetworkManager's [{where}] section)" if where != "connection"
                                                 else default) if default else "not set (the hardware address)"),
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


NM_KINDS = {"802-11-wireless": "wifi", "802-3-ethernet": "ethernet"}
NM_HOSTNAME_DEFAULT = (1, 52)       # the first NetworkManager that takes dhcp-send-hostname's default from its config


def nm_reads_hostname_default(host: Host, values=()) -> bool:
    """Whether this NetworkManager takes a default for dhcp-send-hostname from its configuration (1.52 and later):
    by its version, else by a saved connection showing -1 (older ones have only yes and no)."""
    version = nm_version(host)
    if version is not None:
        return version >= NM_HOSTNAME_DEFAULT
    return any(v.strip().lower() in ("-1", "default") for v in values)


def dhcp_hostname(host: Host) -> tuple[int, bool, bool] | None:
    """NetworkManager and the hostname in DHCP requests: (saved Wi-Fi and Ethernet connections that send it,
    whether a network joined from now on would, whether NetworkManager takes a default for it from its
    configuration: 1.52 and later, where a connection that doesn't set it shows -1). None without nmcli.
    Tested on NetworkManager 1.58: with [connection] ipv4.dhcp-send-hostname=0, the request carried no hostname."""
    conns = [(NM_KINDS[kind], u, nm_get(host, u, *DHCP_HOSTNAME)) for kind in NM_KINDS
             for u in nm_connections(host, kind) or []]
    if nm_connections(host) is None:
        return None
    cfg = nm_config(host)
    default = {(kind, p): (nm_default(cfg, p, kind)[0] or "").lower() for kind in NM_TYPES for p in DHCP_HOSTNAME}
    supported = nm_reads_hostname_default(host, [v for _, _, values in conns for v in values.values()])

    def sends(kind: str, prop: str, value: str) -> bool:
        value = value.strip().lower()
        if value in NM_DEFAULT:
            return not supported or default[(kind, prop)] not in ("0", "false", "no")
        return value not in ("no", "false", "0")
    sending = sum(1 for kind, _, values in conns if any(sends(kind, p, v) for p, v in values.items()))
    future = not supported or any(v not in ("0", "false", "no") for v in default.values())
    return sending, future, supported


# lowest priority first: a file of the same name in a later folder replaces an earlier one (systemd.network(5))
NETWORKD_DIRS = ("/usr/lib/systemd/network", "/usr/local/lib/systemd/network", "/run/systemd/network",
                 "/etc/systemd/network")
CONTAINER_VIRT = ("container", "docker", "podman", "lxc", "lxc-libvirt", "systemd-nspawn", "openvz", "rkt", "wsl",
                  "proot", "pouch")


def _networkd_conf(host: Host, path: Path) -> dict:
    """A .network file with its drop-ins (NAME.network.d/*.conf in each folder, by name; a later folder's file of the
    same name replaces an earlier one's), each read over what came before."""
    conf = ini.parse(read_text(host, path) or "")
    dropins: dict[str, Path] = {}
    for d in NETWORKD_DIRS:
        for f in children(host.sys_path(d) / f"{path.name}.d"):
            if f.suffix == ".conf":
                dropins[f.name] = f
    for name in sorted(dropins):
        conf = ini.merge(conf, ini.parse(read_text(host, dropins[name]) or ""))
    return conf


def _virt_matches(value: str, virt: str | None) -> bool:
    """systemd.network's [Match] Virtualization= against the context's virtualization ('none', 'vm', 'container');
    unknown: it may match."""
    value = value.strip().lower()
    invert = value.startswith("!")
    value = value.lstrip("!")
    if virt is None:
        return True
    if value in ("yes", "true", "1", "on"):
        hit = virt != "none"
    elif value in ("no", "false", "0", "off"):
        hit = virt == "none"
    else:
        hit = virt == ("container" if value in CONTAINER_VIRT else "vm")
    return hit != invert


def _networkd_matches(conf: dict, ifname: str, virt: str | None) -> bool:
    """Whether a .network file's [Match] section takes this interface: Name= (shell globs, "!" inverting the list)
    and Virtualization= are judged; other conditions are taken as met."""
    from fnmatch import fnmatchcase
    m = conf.get(("Match",), {})
    names = (m.get("Name") or "").split()
    if names:
        invert = names[0].startswith("!")
        hit = any(fnmatchcase(ifname, n.lstrip("!")) for n in names)
        if hit == invert:
            return False
    if m.get("Virtualization") and not _virt_matches(m["Virtualization"], virt):
        return False
    return True


def networkd_sending(host: Host, virt: str | None = None) -> list[tuple[str, str]]:
    """The .network files systemd-networkd applies to this computer's interfaces that run DHCP and send the hostname
    ([DHCPv4] SendHostname, on by default, systemd.network(5)): (file name, its folder). Each interface takes the
    first file, by name, whose [Match] takes it, so systemd's own 80-container-host0.network ([Match] Name=host0,
    Virtualization=container) applies inside a container alone."""
    files: dict[str, tuple[str, Path]] = {}
    for d in NETWORKD_DIRS:
        for f in children(host.sys_path(d)):
            if f.suffix == ".network":
                files[f.name] = (d, f)
    confs = [(name, files[name][0], _networkd_conf(host, files[name][1])) for name in sorted(files)]
    out: list[tuple[str, str]] = []
    for iface in sorted(p.name for p in children(host.sys_path("/sys/class/net")) if p.name != "lo"):
        name, folder, conf = next(((n, d, c) for n, d, c in confs if _networkd_matches(c, iface, virt)),
                                  (None, None, None))
        if conf is None or (name, folder) in out:
            continue
        dhcp = (ini.get(conf, "Network", "DHCP") or "no").strip().lower()
        if dhcp in ("yes", "true", "ipv4", "1", "on") and \
                ini.truthy(ini.get(conf, "DHCPv4", "SendHostname")) is not False:
            out.append((name, folder))
    return out


def dhcp_hostname_elsewhere(host: Host, virt: str | None = None) -> list[str]:
    """DHCP clients other than NetworkManager's that send the hostname: systemd-networkd, for a .network file it
    applies with DHCP= on and [DHCPv4] SendHostname not off (on by default, systemd.network(5)); dhcpcd, whose
    dhcpcd.conf has a hostname line (Arch's has one)."""
    out = []
    if systemctl_state(host, "is-active", "systemd-networkd") == "active" and networkd_sending(host, virt):
        out.append("systemd-networkd")
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
        other = dhcp_hostname_elsewhere(host, scan.context["virtualization"])
        if other:
            channels.append(f"DHCP ({', '.join(other)})")
        if systemctl_state(host, "is-active", "avahi-daemon") == "active":
            conf = ini.parse(host.read_sys("/etc/avahi/avahi-daemon.conf") or "")
            if not ini.truthy(ini.get(conf, "publish", "disable-publishing")):
                channels.append("mDNS (Avahi)")
        links = resolved_links(host)
        if resolved_announces(links, "mdns"):
            channels.append("mDNS (systemd-resolved)")
        # LLMNR: systemd-resolved's own word where it answers (with LLMNR=resolve, Fedora's default, it listens on
        # port 5355 but only asks, announcing nothing); the listening port where resolvectl can't say
        if resolved_announces(links, "llmnr") if links else \
                any(s.port == 5355 and s.wildcard for s in scan.context.listeners or []):
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
            out[name] = {"servers": False, "default_route": False, "route_all": False, "dot": None, "mdns": None,
                         "llmnr": None}
            continue
        if name is None:
            continue
        s = out[name]
        # LLMNR and mDNS: "+LLMNR" (answers, announcing the hostname), "-LLMNR", "LLMNR=resolve" (asks only); older
        # output has "LLMNR setting: yes|no|resolve" and "MulticastDNS setting: ..."
        for proto, key, setting in (("LLMNR", "llmnr", "LLMNR"), ("mDNS", "mdns", "MulticastDNS")):
            m = re.search(rf"(?:^|\s)([+-]){proto}\b", line)
            if m:
                s[key] = "yes" if m.group(1) == "+" else "no"
            m = re.search(rf"(?:^|\s){proto}=(\w+)", line) or re.search(rf"{setting} setting:\s*(\w+)", line)
            if m:
                s[key] = m.group(1).lower()
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
    return out


def resolved_announces(links: dict[str, dict], proto: str) -> bool:
    """Whether systemd-resolved answers LLMNR ("llmnr") or mDNS ("mdns") queries for this computer's name on a
    network link: its per-link state is the one in effect (the global setting caps it: Fedora's LLMNR=resolve shows
    on each link as LLMNR=resolve), and "resolve" only asks."""
    return any(s.get(proto) == "yes" for name, s in links.items() if name != "Global")


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


def dns_in_tunnel(host: Host) -> list[str]:
    """The VPN tunnels every DNS lookup goes into, when a tunnel carries this computer's traffic and no lookup can
    go out another way (as net.vpn_leaks judges it: a "~." routing domain on the tunnel's link, as Mullvad VPN's app
    sets, or nameservers reached only through it); empty otherwise, or when it can't be told."""
    vpns = vpn_links(host)
    full = carrying_vpn_links(host, vpns) if vpns else []
    if not full:
        return []
    if resolved_answers(host) is False:
        # the nameservers in /etc/resolv.conf, each by the interface it is reached through; a local resolver's
        # (loopback) own lookups aren't followed
        servers = re.findall(r"^\s*nameserver\s+(\S+)", host.read_sys("/etc/resolv.conf") or "", re.M)
        through = [route_link(host, a.split("%")[0]) for a in servers]
        return sorted(set(through)) if servers and all(t in vpns for t in through) else []
    links = resolved_links(host)
    if not links or VpnLeaks._leaking(host, vpns, full, []) != []:
        return []
    return [n for n in full if links.get(n, {}).get("servers")]


def firefox_doh(scan: Scan) -> tuple[int, list[str]]:
    """Firefox-family profiles (Firefox, LibreWolf), and those that encrypt their own lookups with DNS over HTTPS
    (network.trr.mode 2, falling back to the system's DNS, or 3, only): (profiles, those using it, by label)."""
    from ._util import firefox_prefs, mozilla_profiles
    profiles = mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf"))
    return len(profiles), [p.label for p in profiles if firefox_prefs(scan.host, p.path).get("network.trr.mode") in (2, 3)]


@register
class DnsUnencrypted(Check):
    id = "net.dns_unencrypted"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        servers = re.findall(r"^\s*nameserver\s+(\S+)", host.read_sys("/etc/resolv.conf") or "", re.M)
        ev = [Evidence.val("Nameservers in /etc/resolv.conf", ", ".join(servers[:4]) or "none")]
        profiles, doh = firefox_doh(scan)
        if profiles:
            ev.append(Evidence.val("Firefox profiles using DNS over HTTPS", ", ".join(doh) if doh else
                                   f"none of {profiles}"))
        notes = [Note("limitation", "Browsers can encrypt their own lookups",
                      "Firefox's DNS over HTTPS setting is read from each profile (above): it covers Firefox's own "
                      "lookups, not other programs'. Chromium-based browsers have one too (Settings → Privacy and "
                      "security → Security → Use secure DNS), which the app doesn't read. Only the system's DNS, which "
                      "every program uses, decides this result.")]
        tunnel = dns_in_tunnel(host)
        tunnel_note = Note("info", "Lookups go inside the VPN",
                           f"Every lookup goes into the VPN tunnel ({', '.join(tunnel)}), encrypted with the rest of "
                           "the traffic, so the network you're on and your internet provider can't read them; the VPN "
                           "provider can, as it sees your traffic. If the VPN drops, they go out unencrypted unless its "
                           "kill switch stops them.", ("net.vpn_leaks",))

        def unencrypted(text: str, warn: bool = False) -> Outcome:
            # in the VPN's tunnel, lookups are encrypted on the way like the rest of the traffic
            if tunnel:
                return passed(f"DNS lookups go inside the VPN tunnel ({', '.join(tunnel)}), encrypted on their way.",
                              *ev, Evidence.val("Every lookup goes into", ", ".join(tunnel)), notes=[tunnel_note, *notes])
            if not warn and profiles and len(doh) == profiles:
                # what a browser looks up is the most of it: a risk, below the problem
                return warned("Firefox encrypts its own lookups (DNS over HTTPS), but other programs' are sent "
                              "unencrypted.", *ev, notes=notes)
            return (warned if warn else failed)(text, *ev, notes=notes)

        if any(s.startswith("127.0.0.53") for s in servers):
            links = resolved_links(host)
            dot = [s["dot"] for s in links.values() if s["dot"]]
            ev.append(Evidence.val("systemd-resolved DNSOverTLS", ", ".join(sorted(set(dot))) or "unknown"))
            if any(d == "yes" for d in dot):
                return passed("DNS is encrypted (DNS over TLS).", *ev, notes=notes)
            if any(d == "opportunistic" for d in dot):
                return unencrypted("DNS over TLS is opportunistic: it falls back to plain DNS without telling you.",
                                   warn=True)
            if not links:
                return unknown("Couldn't read systemd-resolved's settings.", *ev, notes=notes)
            return unencrypted("DNS queries are sent unencrypted.")
        local = processes(host) & LOCAL_RESOLVERS
        if servers and all(s.startswith(("127.", "::1")) for s in servers) and local & ENCRYPTING_RESOLVERS:
            return passed(f"DNS goes through a local encrypting resolver ({', '.join(sorted(local))}).", *ev, notes=notes)
        if servers and all(s.startswith(("127.", "::1")) for s in servers) and local:
            return unknown(f"DNS goes through a local resolver ({', '.join(sorted(local))}), which encrypts only if it "
                           "is set to: check that its upstream servers use DNS over TLS or HTTPS.", *ev, notes=notes)
        if servers and all(s.startswith(("127.", "::1")) for s in servers):
            return unknown("DNS goes through a local resolver the app doesn't recognise.", *ev, notes=notes)
        return unencrypted("DNS queries are sent unencrypted.")


PRIVACY_ON = ("2", "enabled (prefer temporary address)")


def ip6_privacy_defaults(host: Host) -> dict[str, tuple[str, str, str | None]] | None:
    """What a NetworkManager connection of each kind ("wifi", "ethernet") that doesn't set ipv6.ip6-privacy gets
    (NetworkManager.conf(5)): the [connection*] sections' default, else the kernel's default for new interfaces.
    {kind: (value, where from, the section)}; None without nmcli."""
    if nm_connections(host) is None:
        return None
    cfg = nm_config(host)
    kernel = (host.read_sys("/proc/sys/net/ipv6/conf/default/use_tempaddr") or "").strip()
    out = {}
    for kind in NM_TYPES:
        v, section = nm_default(cfg, "ipv6.ip6-privacy", kind)
        if v and v != "-1":
            out[kind] = (v, "NetworkManager's default" if section == "connection" else
                         f"NetworkManager's [{section}] section", section)
        else:
            out[kind] = (kernel, "the kernel's default", None)
    return out


def _defaults_text(defaults: dict[str, tuple[str, str, str | None]]) -> str:
    values = {(v, w) for v, w, _ in defaults.values()}
    if len(values) == 1:
        v, w = values.pop()
        return f"{v or 'unknown'} ({w})"
    return "; ".join(f"{'Wi-Fi' if k == 'wifi' else 'wired'}: {v or 'unknown'} ({w})" for k, (v, w, _) in defaults.items())


@register
class Ipv6Privacy(Check):
    id = "net.ipv6_privacy"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        defaults = ip6_privacy_defaults(host)
        connected = net.global_ipv6(host)
        ev, off = [], []
        for p in children(host.sys_path("/sys/class/net")):
            if p.name == "lo" or not (p / "device").exists():          # physical interfaces only
                continue
            conf = f"/proc/sys/net/ipv6/conf/{p.name}"
            if (host.read_sys(f"{conf}/disable_ipv6") or "0").strip() == "1":
                ev.append(Evidence.val(p.name, "IPv6 off"))
                continue
            in_use = (read_text(host, p / "operstate") or "").strip() == "up" and p.name in connected
            if defaults is not None and not in_use:
                # NetworkManager sets it as the interface connects, from the connection or its default (below): an
                # unplugged port keeps the kernel's value until then, which says nothing
                ev.append(Evidence.val(p.name, "not on an IPv6 network now (it takes the setting below when it "
                                               "connects)"))
                continue
            temp = (host.read_sys(f"{conf}/use_tempaddr") or "").strip()
            ev.append(Evidence.val(f"{p.name} use_tempaddr", temp or "unknown"))
            if temp in ("0", "1", "-1"):
                off.append(p.name)
        if not ev:
            return absent("No physical network interfaces.")
        saved_off = []
        if defaults is not None:
            for kind in NM_KINDS:
                for uuid in nm_connections(host, kind) or []:
                    v = nm_get(host, uuid, "ipv6.ip6-privacy")["ipv6.ip6-privacy"].strip().lower()
                    if v not in NM_DEFAULT and v not in PRIVACY_ON:
                        saved_off.append(uuid)
            ev.append(Evidence.count("Saved networks that turn them off", len(saved_off)))
            ev.append(Evidence.val("Networks joined from now on", _defaults_text(defaults)))
        later = [d for d in (defaults or {}).values() if d[0] not in ("2", "")]
        if off:
            return failed(f"IPv6 privacy addresses aren't used on {', '.join(off)}: on a network that offers IPv6, "
                          "every site you visit sees the same address for as long as you stay on it (and on every "
                          "network, where the address is made from the hardware address).", *ev)
        n = len(saved_off)
        saved = (f"{n} saved network{'s turn' if n != 1 else ' turns'} them off for {'themselves' if n != 1 else 'itself'}"
                 if n else "")
        if later:
            text = ("IPv6 privacy addresses are used now, but networks joined from now on won't use them"
                    if any(e.label.endswith(" use_tempaddr") for e in ev) else
                    "No network in use now has IPv6, but networks joined from now on won't use IPv6 privacy addresses")
            return failed(f"{text}: {later[0][1]} is {later[0][0]}" + (f"; and {saved}." if saved else "."), *ev)
        if saved:
            return failed(f"{saved[0].upper()}{saved[1:].replace('them off', 'IPv6 privacy addresses off')}: on "
                          f"{'those networks' if n != 1 else 'that network'}, every site you visit sees the same address "
                          "for as long as you stay.", *ev)
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
        # interval=0 turns checking off too (NetworkManager.conf(5))
        if (ini.get(cfg, "connectivity", "interval") or "").strip() == "0":
            return passed("NetworkManager's connectivity check is off (interval=0).")
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
                             "Three kinds of connection are allowed: one whose question you don't answer, anything new "
                             "that connects while a question is open, and any connection while OpenSnitch's window "
                             "isn't running. Good while you learn what your programs do; once questions have become "
                             "rare, turn on deny mode in the guide (Set up…)."))
        return warned("OpenSnitch is on, in allow mode: what you don't answer for is let through.", *ev, notes=notes)


# ------------------------------------------------------------------ root certificates added to the system's store

LOCAL_ANCHORS = ("/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors",
                 "/etc/ca-certificates/trust-source/anchors", "/etc/pki/trust/anchors")
# `trust anchor FILE` (p11-kit: Arch's documented way, and Fedora's and openSUSE's tool too) writes NAME.p11-kit
# beside the anchors folder, not in it (seen on CachyOS). Only files directly there: blocklist/ holds distrust.
LOCAL_SOURCES = ("/etc/ca-certificates/trust-source", "/etc/pki/ca-trust/source", "/etc/pki/trust")
ROOT_SUFFIXES = (".crt", ".pem", ".cer", ".p11-kit")
# update-ca-certificates takes only *.crt from /usr/local/share/ca-certificates (update-ca-certificates(8))
DEBIAN_LOCAL = "/usr/local/share/ca-certificates"


def _added_file(host: Host, p: Path) -> Path | None:
    """The file a trust-store entry is, its links followed within the scanned system (a few deep); None when a link
    leads into /usr, where the distribution's packages keep their files (Fedora's
    /etc/pki/ca-trust/source/ca-bundle.legacy.crt, a link to ca-certificates' empty legacy bundle), or nowhere."""
    for _ in range(8):
        if not p.is_symlink():
            return p
        target = Path(os.readlink(p))
        on_system = Path(os.path.normpath(target if target.is_absolute()
                                          else Path("/") / p.parent.relative_to(host.root) / target))
        if on_system.parts[1:2] == ("usr",):
            return None
        p = host.sys_path(on_system)
    return None


def _holds_certificate(p: Path) -> bool:
    """Whether a file holds a certificate p11-kit would load: PEM (BEGIN CERTIFICATE, OpenSSL's BEGIN TRUSTED
    CERTIFICATE), DER (an ASN.1 sequence) or a p11-kit object. An empty file (Fedora's legacy bundle) holds none;
    one that can't be read is counted."""
    try:
        head = Host.read_head(p, 1 << 20)
    except Unreadable:
        return True
    if not head or not head.strip():
        return False
    return (b"-----BEGIN CERTIFICATE-----" in head or b"-----BEGIN TRUSTED CERTIFICATE-----" in head
            or b"[p11-kit-object-v1]" in head or head[:1] == b"\x30")


def local_roots(scan: Scan) -> list[str]:
    """The certificate files an administrator added to the system's trust store, as paths on the system: not the
    distribution's own (links into /usr), nor files holding no certificate."""
    host, out = scan.host, []
    for d in LOCAL_ANCHORS:
        stack = [host.sys_path(d)]
        while stack:
            for p in children(stack.pop()):
                if p.is_dir():
                    stack.append(p)
                elif (p.suffix == ".crt" if d == DEBIAN_LOCAL else p.suffix in ROOT_SUFFIXES) and \
                        (f := _added_file(host, p)) is not None and _holds_certificate(f):
                    out.append(f"{d}/{p.relative_to(host.sys_path(d))}")
    for d in LOCAL_SOURCES:
        for p in children(host.sys_path(d)):
            f = _added_file(host, p) if p.suffix in ROOT_SUFFIXES else None
            if f is not None and f.is_file() and _holds_certificate(f) and \
                    "x-distrusted: true" not in (read_text(host, f) or ""):
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

