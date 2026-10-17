"""Guided fixes: network (see the package docstring)."""

from __future__ import annotations

import re

from .. import No
from ... import network as net
from ...fix import BluetoothSet, Command, GSettingsSet, NmSet, RootChange, WriteFile, bus_reload, shell
from ...guide import Guide, Option, Step
from .._util import human_size, installed, isfile, processes, read_text, removed_while_running, systemctl_state
from . import guide, option, evidence, unit_exists, service_off, dropin, install, remove, remote_session


LLMNR_DROPIN = "/etc/systemd/resolved.conf.d/60-daprivacyscanner-llmnr.conf"


def _llmnr_off(check, scan) -> Option:
    return option(check, "Turn off LLMNR in systemd-resolved", [dropin("resolved-llmnr", {"LLMNR": "no"}, LLMNR_DROPIN)],
                  side_effects=["Windows-style name lookups of other machines on the local network stop; mDNS "
                                "(.local names) is unaffected."])


MAC_DROPIN = "/etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf"
MAC_DROPIN_ETHERNET = "/etc/NetworkManager/conf.d/99-daprivacyscanner-mac-ethernet.conf"
MAC_MODES = (("stable", "A random address for each network, kept for it (stable)",
              "Each network sees its own made-up address, the same at every visit, so you stay signed in to "
              "captive portals and keep your usual IP address at home.", True),
             ("random", "A new random address at every connection (random)",
              "No network recognises the machine between connections; captive portals ask you to sign in each "
              "time and a router hands out a new IP address each time.", False))


@guide("net.mac_permanent", can=lambda scan: bool(scan.host.runner.which("nmcli")) or No(
    "The guide changes NetworkManager's settings with nmcli, which isn't installed."), keys=("stable",))
def mac_permanent(check, scan, outcome):
    from ... import ini
    from ..network import RANDOM_MACS, nm_config, nm_connections, nm_get
    host = scan.host
    cfg = nm_config(host)
    default = (ini.get(cfg, "connection", "wifi.cloned-mac-address") or "").strip()
    scan_rand = (ini.get(cfg, "device", "wifi.scan-rand-mac-address") or "").strip().lower()
    eth_default = (ini.get(cfg, "connection", "ethernet.cloned-mac-address") or "").strip()
    saved = []
    for uuid in nm_connections(host, "802-11-wireless") or []:
        v = nm_get(host, uuid, "connection.id", "802-11-wireless.cloned-mac-address")
        saved.append((uuid, v["connection.id"] or uuid, v["802-11-wireless.cloned-mac-address"] or "default"))
    effects = ["NetworkManager reloads its settings; connections stay up. Each network sees the new address the next "
               "time it connects: you may need to sign in to a captive portal again, and networks that only let in "
               "known devices (MAC filtering) need the new address.",
               "Wi-Fi drivers that can't change their address (Broadcom's wl and eagle_sdio, the ones NetworkManager's "
               "own files list) are left out and keep the hardware one, so Wi-Fi keeps working on them.",
               "If Wi-Fi stops finding networks or connecting after this, the driver can't change its address and "
               "isn't on that list: revert this from History, and it works again."]
    opts = []
    for mode, label, detail, rec in MAC_MODES:
        acts = []
        if default != mode or scan_rand in ("no", "false", "0"):
            acts.append(dropin("nm-mac", {"connection:wifi.cloned-mac-address": mode,
                                          "device:wifi.scan-rand-mac-address": "yes"}, MAC_DROPIN))
        # a saved network that sets the hardware address itself doesn't follow the default
        acts += [NmSet(uuid, name, "802-11-wireless.cloned-mac-address", mode)
                 for uuid, name, value in saved if value in ("preserve", "permanent")]
        opts.append(option(check, label, acts, detail=detail, recommended=rec, side_effects=effects,
                           key="stable" if mode == "stable" else ""))
    steps = [Step("Wi-Fi: every network, including the ones you join later",
                  "The default for new connections is set for the whole machine, and scanning for networks uses random "
                  "addresses too. Saved networks that use the default follow it; those set to the hardware address "
                  "are changed one by one.", options=opts,
                  done=default in RANDOM_MACS and scan_rand not in ("no", "false", "0")
                  and not any(v in ("preserve", "permanent") for _, _, v in saved))]
    eth = [option(check, f"Wired networks too: {label[0].lower() + label[1:]}",
                  [dropin("nm-mac-ethernet", {"connection:ethernet.cloned-mac-address": mode}, MAC_DROPIN_ETHERNET)],
                  detail=detail, side_effects=[
                      "Your router sees a new device: an address it reserves for this machine (DHCP reservation), port "
                      "forwarding to it and wired networks that check MAC addresses (802.1X, MAC filtering) need "
                      "updating."]) for mode, label, detail, _ in MAC_MODES if eth_default != mode]
    steps.append(Step("Optional: wired networks",
                      "Mostly matters for networks you plug into away from home (hotels, offices). Leave it if this "
                      "machine only ever plugs into your own router.", options=eth, done=eth_default in RANDOM_MACS))
    return Guide(check.id, "Use made-up MAC addresses on every network",
                 "The hardware (MAC) address is the same everywhere, so every network and its operator can recognise "
                 "this machine across visits.", steps)


def _unit_of(scan, pid: int) -> tuple[str, str] | None:
    """("user" or "system", unit) of the systemd service a process runs in, from /proc/PID/cgroup;
    None for programs started from the desktop or a terminal (a scope, not a service)."""
    text = scan.host.read_sys(f"/proc/{pid}/cgroup") or ""
    m = re.search(r"^0::(\S*)$", text, re.M)
    parts = (m.group(1) if m else "").split("/")
    unit = parts[-1]                  # its own cgroup: user@UID.service above it is the user manager
    if not unit.endswith(".service") or unit.startswith("user@"):
        return None
    return ("user" if any(p.startswith("user@") for p in parts[:-1]) else "system", unit)


def _other_service(scan, s) -> Step:
    """What a listening program is, and how to stop it."""
    title = f"Port {s.port}/{s.proto}" + (f" ({s.process})" if s.process else "")
    tail = (" If you need it only on this computer, its settings may let it listen on 127.0.0.1 (localhost) only, "
            "which other machines can't reach.")
    unit = _unit_of(scan, s.pid) if s.pid else None
    if unit and unit[0] == "user":
        return Step(title, f"{s.process} runs as your own service {unit[1]}. If you don't use it, stop it and keep it "
                    "from starting at login." + tail, commands=[f"systemctl --user disable --now {unit[1]}"])
    if unit:
        return Step(title, f"It is the system service {unit[1]}. If you don't use it, stop it and keep it from starting "
                    "at boot." + tail, commands=[f"sudo systemctl disable --now {unit[1]}"])
    if s.pid:
        return Step(title, f"{s.process} is a program you started (from the desktop or a terminal). Close it if you "
                    "don't need it; a development server can usually be started on 127.0.0.1 instead (for example "
                    "--host 127.0.0.1).")
    return Step(title, "A program of another account (usually a system service) is listening; the app can't see which "
                "without administrator access. The first command shows the program and its process number (pid=); the "
                "second shows which service it belongs to (the first line); the third stops that service, if you don't "
                "use it." + tail,
                commands=[f"sudo ss -l{'t' if s.proto == 'tcp' else 'u'}np 'sport = :{s.port}'",
                          "systemctl status PID     # the number after pid=",
                          "sudo systemctl disable --now SERVICE.service"])


@guide("net.dns_encryption_in_use")
def dns_encryption_in_use(check, scan, outcome):
    """DNS over TLS is set, but the server doesn't speak it: the same choice of providers as net.dns_unencrypted's
    guide, with their drop-in. The test only ever finds this with systemd-resolved in use."""
    g = dns_unencrypted(check, scan, outcome, resolved=True)
    g.intro = ("DNS over TLS is turned on, but the server it is pointed at doesn't answer over TLS, so lookups go out "
               "unencrypted anyway. Choose a provider that does: the same setting as “Encrypt DNS”, written for "
               "that provider. Then run the online test again.")
    return g


@guide("net.ipv6_reachable")
def ipv6_reachable(check, scan, outcome):
    """The services the internet reaches over IPv6 are the ones listening on all interfaces that the host firewall
    lets through: net.exposed_services' guide closes each, and applies here as it is."""
    g = exposed_services(check, scan, outcome)
    g.title = "Close the services the internet reaches over IPv6"
    g.intro = ("With a public IPv6 address there is no home router's NAT in the way: each service below listens on "
               "every interface, so anyone on the internet can reach it unless the router blocks incoming IPv6. "
               "Turn off what you don't use, or keep it to this computer; a host firewall (net.firewall_off) covers "
               "the rest. Then run the online test again.")
    return g


@guide("net.exposed_services")
def exposed_services(check, scan, outcome):
    listeners = net.exposed(scan.context.listeners or [], net.ephemeral_range(scan.host))
    steps = []
    ports = lambda *ps: [s for s in listeners if s.port in ps]  # noqa: E731
    procs = lambda *ns: [s for s in listeners if s.process in ns]  # noqa: E731
    if ports(22) or procs("sshd"):
        opts = []
        off = service_off(scan, "ssh.socket", "ssh.service", "sshd.service")
        if off:
            opts.append(option(check, "Turn off the SSH server", off,
                               side_effects=["You can no longer log in to this machine over SSH.",
                                             "Anyone logged in over SSH right now is cut off."],
                               blockers=["You are connected over SSH now: turning it off would cut this connection. "
                                         "Do it from the machine itself."] if "ssh" in remote_session(scan) else []))
        opts.append(option(check, "Keep SSH, but only with keys", [dropin(
            "sshd", {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "PermitRootLogin": "no"},
            "/etc/ssh/sshd_config.d/10-daprivacyscanner.conf")],
            side_effects=["Check you can log in with a key first (ssh -o PasswordAuthentication=no you@this-machine): "
                          "passwords stop working for everyone.", "Root can no longer log in over SSH."]))
        steps.append(Step("SSH server (port 22)", "Anyone who can reach port 22 can try passwords.", options=opts))
    xrdp_effect = ("Anyone connected over RDP is disconnected at once, you included if you are using this machine "
                   "remotely now, and can't connect again until xrdp is started.")
    xrdp_blockers = ["You are using this machine over xrdp now: turning it off would end this session. Do it from "
                     "the machine itself."] if "xrdp" in remote_session(scan) else []
    for label, match, units, effect in (
            ("Remote desktop (xrdp, port 3389)", ports(3389) + procs("xrdp"), ("xrdp.service", "xrdp-sesman.service"),
             xrdp_effect),
            ("Windows file sharing (Samba)", ports(139, 445) + procs("smbd", "nmbd"), ("smbd.service", "nmbd.service"),
             "Folders you share from this machine are no longer reachable."),
            ("rpcbind (NFS)", ports(111) + procs("rpcbind"), ("rpcbind.socket", "rpcbind.service"),
             "Older (v3) NFS mounts need it."),
            ("Cockpit web console (port 9090)", ports(9090), ("cockpit.socket",), ""),
            ("Avahi (mDNS)", procs("avahi-daemon"), ("avahi-daemon.socket", "avahi-daemon.service"),
             "Printers and shares on the local network are no longer found automatically.")):
        if match:
            acts = service_off(scan, *units)
            steps.append(Step(label, options=[option(check, f"Turn off {label.split(' (')[0]}", acts,
                                                     side_effects=[effect] if effect else [],
                                                     blockers=xrdp_blockers if "xrdp" in units[0] else [])]
                              if acts else [], text="" if acts else "Stop it, or uninstall it, if you don't use it."))
    if ports(5355):
        steps.append(Step("LLMNR (port 5355)", "systemd-resolved answers Windows-style name queries from the whole "
                          "network, which announces this machine's name.", options=[_llmnr_off(check, scan)]))
    if ports(631) or procs("cupsd"):
        steps.append(Step("CUPS printing (port 631)", "CUPS listens on the network, e.g. to share printers.",
                          commands=["sudo cupsctl --no-share-printers --no-remote-admin --no-remote-any"]))
    known = {22, 3389, 139, 445, 111, 9090, 5355, 631}
    other_listeners = [s for s in listeners if s.port not in known and not 1714 <= s.port <= 1764
                       and s.process not in ("sshd", "xrdp", "smbd", "nmbd", "rpcbind", "avahi-daemon", "cupsd")]
    for s in other_listeners:
        steps.append(_other_service(scan, s))
    steps.append(Step("Firewall", "A host firewall blocks what you didn't mean to expose; see net.firewall_off."))
    return Guide(check.id, "Close services other machines can reach", "", steps)


@guide("net.bluetooth", can=lambda scan: bool(scan.host.runner.which("bluetoothctl")) or No(
    "The guide changes the adapter with bluetoothctl, which isn't installed (it comes with BlueZ)."), keys=("hide",))
def bluetooth(check, scan, outcome):
    from .._util import mentions_name, user_names
    r = scan.host.run("bluetoothctl", "show", timeout=5)
    show = dict(re.findall(r"^\s*(\w+):\s*(.*)$", r.stdout, re.M)) if r.ok else {}
    login, words = user_names(scan.host)
    acts, effects = [], []
    if show.get("Discoverable") == "yes":
        acts.append(BluetoothSet("discoverable", "off"))
        effects.append("New devices can't find this computer until you make it discoverable again while pairing.")
    if show.get("Alias") and mentions_name(show["Alias"], login, words):
        acts.append(BluetoothSet("alias", "Computer"))
        effects.append("Paired devices will show this computer as \"Computer\".")
    steps = [Step("Stop advertising this machine",
                  "A discoverable adapter answers anyone scanning nearby, and a name like yours ties it to you.",
                  options=[option(check, "Turn off discoverable mode and use a generic name", acts,
                                  side_effects=effects, recommended=True, key="hide")] if acts else [],
                  done=not acts)]
    if show.get("Powered") == "yes":
        steps.append(Step("Turn Bluetooth off when you don't use it",
                          "Even non-discoverable, a powered adapter can be tracked by its address. This is your call: "
                          "it disconnects whatever is connected now.",
                          options=[option(check, "Turn Bluetooth off now", [BluetoothSet("power", "off")], side_effects=[
                              "Connected Bluetooth devices (headphones, mouse, keyboard) disconnect at once.",
                              "The desktop's Bluetooth switch turns it back on; so does revert from History."])]))
    return Guide(check.id, "Make Bluetooth harder to track",
                 "Phones and shops track Bluetooth adapters that announce themselves.", steps)


@guide("net.docker_bypass")
def docker_bypass(check, scan, outcome):
    return Guide(check.id, "Keep container ports private",
                 "Docker writes its own firewall rules, so published ports are reachable even when ufw or "
                 "firewalld would block them.", [
                     Step("Publish on 127.0.0.1",
                          "In docker run or compose, write the port as 127.0.0.1:8080:80 instead of 8080:80, then "
                          "recreate the container.", commands=["docker compose up -d --force-recreate"]),
                     Step("Or filter in DOCKER-USER",
                          "Rules in the DOCKER-USER chain apply before Docker's own (ufw-docker sets this up for ufw)."),
                 ])


@guide("net.firewall_off")
def firewall_off(check, scan, outcome):
    host = scan.host
    exposed = net.exposed(scan.context.listeners or [], net.ephemeral_range(host))
    steps = []
    has_ufw = isfile(host.sys_path("/usr/sbin/ufw")) or isfile(host.sys_path("/etc/ufw/ufw.conf"))
    has_firewalld = unit_exists(scan, "firewalld.service")
    # with both installed, the one the machine already uses (running, or set to start) is the one to turn
    # on: two firewalls with different defaults would get in each other's way
    firewalld_first = has_firewalld and (systemctl_state(host, "is-active", "firewalld.service") == "active"
                                         or systemctl_state(host, "is-enabled", "firewalld.service") == "enabled"
                                         or not has_ufw)
    if has_ufw and not firewalld_first:
        default = read_text(host, host.sys_path("/etc/default/ufw")) or ""
        effects = ["Incoming connections are blocked; outgoing ones are unaffected."]
        if re.search(r'^DEFAULT_INPUT_POLICY="?ACCEPT', default, re.M):
            effects = ["ufw's default incoming policy is set to ACCEPT here, so it won't block anything until "
                       "you run: sudo ufw default deny incoming"]
        if has_firewalld:
            effects.append("firewalld is installed too, but off: leave it off. Two firewalls with different "
                           "defaults get in each other's way.")
        # ufw's rules are loaded at boot by ufw.service; Arch's package enables nothing, so the helper enables it too
        enabled = systemctl_state(host, "is-enabled", "ufw.service")      # "" without systemd or the unit
        unit = (", and start ufw.service now and at every boot (systemctl enable --now ufw), which loads its rules"
                if enabled == "disabled" or (enabled == "enabled"
                                             and systemctl_state(host, "is-active", "ufw.service") != "active") else "")
        if unit:
            effects.append("ufw.service isn't set to start at boot here: without it ufw's rules are gone after a "
                           "restart, so it is turned on too, and turned off again by a revert.")
        opts = [option(check, "Turn on ufw", [RootChange("ufw_enable", {"allow": []}, "ufw --force enable" + unit)],
                       side_effects=effects + ([f"These stop being reachable: {', '.join(s.label() for s in exposed)}."]
                                               if exposed else []), recommended=not exposed)]
        if exposed:
            allow = [f"{s.port}/{s.proto}" for s in exposed][:20]
            opts.append(option(check, "Turn on ufw, still allowing " + ", ".join(s.label() for s in exposed),
                               [RootChange("ufw_enable", {"allow": allow},
                                           f"ufw allow {', '.join(allow)}, then ufw --force enable" + unit)],
                               side_effects=effects, recommended=True))
        steps.append(Step("Turn on ufw", options=opts))
    elif firewalld_first:
        steps.append(Step("Turn on firewalld", options=[option(check, "Start and enable firewalld", [RootChange(
            "set_service", {"unit": "firewalld.service", "enable": True, "start": True},
            "systemctl enable --now firewalld")], recommended=True)],
            side_effects=["Fedora Workstation's default zone still allows ports 1025-65535; for a stricter one: "
                          "sudo firewall-cmd --set-default-zone=public"]
            + (["ufw is installed too: leave it off. Two firewalls with different defaults get in each other's way."]
               if has_ufw else [])))
    else:
        cmd = install(scan, debian="ufw", arch="ufw", fedora="firewalld", suse="firewalld")
        steps.append(Step("Install a firewall", "ufw is the simplest (Gufw gives it a window); Fedora and openSUSE "
                          "use firewalld. Then scan again and come back here.", commands=[cmd] if cmd else []))
    return Guide(check.id, "Turn on the firewall", "", steps)


@guide("net.hostname_broadcast")
def hostname_broadcast(check, scan, outcome):
    from ..network import DHCP_HOSTNAME, NM_DEFAULT, dhcp_hostname, nm_connections, nm_get
    host = scan.host
    steps = []
    acts = []
    dhcp = dhcp_hostname(host)
    supported = bool(dhcp and dhcp[2])
    if dhcp and dhcp[1] and supported:
        acts.append(dropin("nm-hostname", {f"connection:{p}": "0" for p in DHCP_HOSTNAME},
                           "/etc/NetworkManager/conf.d/99-daprivacyscanner-hostname.conf"))
    for kind in ("802-11-wireless", "802-3-ethernet"):
        for uuid in nm_connections(host, kind) or []:
            v = nm_get(host, uuid, "connection.id", *DHCP_HOSTNAME)
            for prop in DHCP_HOSTNAME:
                value = v[prop].strip().lower()
                if value not in ("no", "false", "0") and not (supported and value in NM_DEFAULT):
                    acts.append(NmSet(uuid, v["connection.id"] or uuid, prop, "no"))
    if acts:
        effects = ["Routers list this machine without a name; local names served by the router's DNS for it stop "
                   "working.", "Takes effect when each network reconnects."]
        effects.append("Networks joined later don't send it either: NetworkManager's default, for every account on "
                       "this computer." if supported else
                       "This NetworkManager (before 1.52) has no default for it, so a network joined later sends the "
                       "hostname until it is changed here too: renaming the machine (below) covers those.")
        steps.append(Step("Don't send the hostname over DHCP", options=[option(check, "Stop sending it", acts,
                          side_effects=effects)]))
    from ..network import dhcp_hostname_elsewhere
    other = dhcp_hostname_elsewhere(host)
    if "systemd-networkd" in other:
        steps.append(Step("systemd-networkd: don't send the hostname",
                          "In each .network file in /etc/systemd/network that has DHCP=yes (copy one from "
                          "/usr/lib/systemd/network to /etc/systemd/network to change it), add the two lines "
                          "\"[DHCPv4]\" and \"SendHostname=no\", then reload its settings.",
                          commands=["sudoedit /etc/systemd/network/NAME.network", "sudo networkctl reload"]))
    if "dhcpcd" in other:
        steps.append(Step("dhcpcd: don't send the hostname",
                          "Comment out the hostname line in /etc/dhcpcd.conf (put # in front of it), then restart dhcpcd.",
                          commands=["sudoedit /etc/dhcpcd.conf", "sudo systemctl restart dhcpcd"]))
    if systemctl_state(host, "is-active", "avahi-daemon") == "active":
        acts = service_off(scan, "avahi-daemon.socket", "avahi-daemon.service")
        steps.append(Step("Stop announcing it with mDNS (Avahi)", options=[option(check, "Turn off Avahi", acts,
                          side_effects=["Printers and shares on the local network are no longer found "
                                        "automatically."])] if acts else []))
    if any(s.port == 5355 and s.wildcard for s in scan.context.listeners or []):
        steps.append(Step("Stop answering LLMNR", options=[_llmnr_off(check, scan)]))
    steps.append(Step("Or rename the machine", "A name that doesn't identify you (like \"laptop\") makes all of the "
                      "above harmless. Update the 127.0.1.1 line in /etc/hosts to match, if there is one.",
                      commands=["sudo hostnamectl set-hostname NEWNAME", "sudoedit /etc/hosts"],
                      side_effects=["Log out and back in afterwards: until then, some apps (X11 ones especially) may "
                                    "fail to open new windows, since their access is tied to the old name."]))
    return Guide(check.id, "Stop announcing your name on networks", "", steps)


DOT_PROVIDERS = (("quad9", "Quad9", "Non-profit, blocks known malicious domains."),
                 ("cloudflare", "Cloudflare (1.1.1.1)", "Fast; logs are kept for 25 hours."),
                 ("mullvad", "Mullvad DNS", "Run by the VPN provider; no logging."))


@guide("net.dns_unencrypted")
def dns_unencrypted(check, scan, outcome, resolved: bool | None = None):
    from ...helper import DOT_PROVIDERS as SERVERS
    # what encrypted DNS doesn't hide, said wherever it is offered: users take it for hiding their browsing
    limits = (" Encrypting it hides the names you look up, not which sites you visit: the network and your internet "
              "provider still see the address of every server you connect to and, for most sites, its name, which "
              "the browser sends unencrypted as each connection starts (Encrypted Client Hello hides it, where both "
              "the site and the browser use it). A VPN or Tor hides those too.")
    if resolved is None:
        resolved = any(str(v).startswith("127.0.0.53") for v in evidence(outcome, "Nameservers in /etc/resolv.conf"))
    path = "/etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf"
    if not resolved:
        return Guide(check.id, "Encrypt DNS", "Plain DNS shows the name of every site you look up to the network "
                     "and your internet provider." + limits + " This computer doesn't use systemd-resolved, which can "
                     "encrypt it for every program; browsers can encrypt their own.", _dns_without_resolved(check, scan))
    effects = ["The provider sees every name you look up, instead of your internet provider, which still sees the "
               "addresses you connect to and most sites' names (see above).",
               "Names only your router knows (printer.lan, a NAS) may stop resolving, unless the router announces "
               "that local domain.",
               "Some hotel and airport Wi-Fi sign-in pages don't load until this is reverted.",
               "With a VPN on, lookups go to this provider (through the tunnel) instead of the VPN's own DNS; VPN apps "
               "that block other DNS servers stop lookups working until this is reverted."]
    opts = [option(check, f"Encrypt DNS, using {label}", [dropin(
        "resolved-dot", {"DNS": SERVERS[key], "DNSOverTLS": "yes", "Domains": "~."}, path)], detail=detail,
        side_effects=effects, recommended=key == "quad9") for key, label, detail in DOT_PROVIDERS]
    opts.append(option(check, "Encrypt only when your current DNS server supports it (opportunistic)", [dropin(
        "resolved-dot", {"DNSOverTLS": "opportunistic"}, path)],
        side_effects=["Falls back to unencrypted DNS without saying so; most home routers don't support it."]))
    return Guide(check.id, "Encrypt DNS", "Plain DNS shows the name of every site you look up to the network and your "
                 "internet provider." + limits + " systemd-resolved can send DNS over TLS instead.", [
                     Step("Choose a DNS-over-TLS provider", options=opts,
                          text="Every name is looked up through the provider, not the servers each network hands "
                               "out; only names under a local domain a network announces (such as .lan) still go "
                               "to its own server.")])


FIREFOX_DOH = "https://dns.quad9.net/dns-query"


def _dns_without_resolved(check, scan) -> list[Step]:
    from .._util import mozilla_profiles
    from . import ff_prefs
    steps = []
    if unit_exists(scan, "systemd-resolved.service"):
        steps.append(Step("Switch to systemd-resolved, for every program",
                          "It comes with systemd but isn't in use here. These commands start it, point "
                          "/etc/resolv.conf at it (NetworkManager then hands it each network's DNS servers), and "
                          "restart NetworkManager. Then scan again: this guide then offers encrypted DNS for the whole "
                          "computer.",
                          commands=["sudo systemctl enable --now systemd-resolved",
                                    "sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf",
                                    "sudo systemctl restart NetworkManager",
                                    "resolvectl status     # shows each network's DNS servers"],
                          side_effects=["To go back: sudo systemctl disable --now systemd-resolved; sudo rm "
                                        "/etc/resolv.conf; sudo systemctl restart NetworkManager (it writes the file "
                                        "again)."]))
    else:
        steps.append(Step("An encrypting resolver, for every program",
                          "dnscrypt-proxy runs on this computer and encrypts every DNS lookup; its documentation "
                          "covers pointing /etc/resolv.conf at it.",
                          commands=[c for c in [install(scan, debian="dnscrypt-proxy", arch="dnscrypt-proxy",
                                                        fedora="dnscrypt-proxy", suse="dnscrypt-proxy")] if c]))
    opts = ff_prefs(check, scan, "Use DNS over HTTPS (Quad9) in Firefox",
                    {"network.trr.mode": 2, "network.trr.uri": FIREFOX_DOH, "network.trr.custom_uri": FIREFOX_DOH},
                    want=lambda prefs, p: prefs.get("network.trr.mode") not in (2, 3),
                    side_effects=["Only Firefox's own lookups are encrypted. If Quad9 can't be reached, Firefox falls "
                                  "back to the normal DNS, so sites keep working (Settings → Privacy & Security → DNS "
                                  "over HTTPS → Max Protection never falls back)."], recommended=True)
    if opts or mozilla_profiles(scan.host, scan.paths, ("Firefox", "LibreWolf")):
        steps.append(Step("Firefox", options=opts, done=not opts))
    steps.append(Step("Chromium-based browsers", "Settings → Privacy and security → Security → Use secure DNS: "
                      "choose a provider (Quad9, Cloudflare). Brave: Settings → Privacy and security → Security."))
    return steps


@guide("net.hidden_ssid")
def hidden_ssid(check, scan, outcome):
    from ..network import nm_connections, nm_get
    opts, names = [], []
    for uuid in nm_connections(scan.host, "802-11-wireless") or []:
        v = nm_get(scan.host, uuid, "connection.id", "802-11-wireless.hidden")
        if v["802-11-wireless.hidden"] == "yes":
            names.append(v["connection.id"])
            opts.append(option(check, f"{v['connection.id']}: stop probing for it",
                               [NmSet(uuid, v["connection.id"], "802-11-wireless.hidden", "no")],
                               side_effects=["Only once the network is made visible on its router: otherwise this "
                                             "machine no longer finds it."]))
    return Guide(check.id, "Stop probing for hidden networks",
                 "A hidden network's name is called out wherever you go, so others can see which networks you use.", [
                     Step("Make the network visible", "In the router's Wi-Fi settings, turn off \"hide SSID\". Then "
                          "this machine can stop calling it out.", options=opts),
                     Step("Or forget networks you no longer use",
                          commands=[f'nmcli connection delete id "{n}"' for n in names]),
                 ])


@guide("net.wifi_history")
def wifi_history(check, scan, outcome):
    from ..network import STALE_DAYS, wifi_last_used
    nets = wifi_last_used(scan.host) or []
    stale = sorted(((a, u, n) for u, n, a in nets if a is not None and a >= STALE_DAYS), reverse=True)
    steps = []
    if stale:
        steps.append(Step(f"Forget networks not used for {STALE_DAYS} days or more",
                          "Forgetting a network also deletes its saved password, so this is for you to run. From "
                          f"longest ago: {', '.join(f'{n} ({a:.0f} days)' for a, _, n in stale[:8])}"
                          + (" and more." if len(stale) > 8 else "."),
                          commands=[f"nmcli connection delete {u}     # {n}" for _, u, n in stale],
                          side_effects=["Each must be chosen again, with its password, the next time you use it."]))
    steps.append(Step("Keep the list short from now on",
                      "Public networks you won't see again can be forgotten right after use (the Wi-Fi settings' "
                      "Forget button). Networks that matter stay."))
    steps.append(Step("Protect what stays", "Saved passwords live in /etc/NetworkManager/system-connections. With "
                      "the disk encrypted, only root reads them; without, anyone with the drive does.",
                      done=scan.context["fde"] in ("full", "partial")))
    return Guide(check.id, "Thin out saved Wi-Fi networks",
                 "Each saved network keeps the time it was last used, and the list as a whole says where this "
                 "machine has been.", steps)


@guide("net.connectivity_check")
def connectivity_check(check, scan, outcome):
    return Guide(check.id, "Turn off the connectivity check",
                 "NetworkManager contacts a distribution server every few minutes to see whether you're online.", [
                     Step("Turn it off", options=[option(check, "Turn off the connectivity check", [dropin(
                         "nm-connectivity", {"enabled": "false"},
                         "/etc/NetworkManager/conf.d/60-daprivacyscanner-connectivity.conf")])],
                         side_effects=["Hotel and airport Wi-Fi sign-in pages no longer open by themselves; open "
                                       "any http:// site to reach them."])])


# ------------------------------------------------------------------ KDE Connect and GSConnect

GSCONNECT = "gsconnect@andyholmes.github.io"
# KDE Connect's daemon is started at login (XDG autostart) and on demand (D-Bus activation, when
# the panel applet or Dolphin asks): both are overridden for this user, so it stays off
KDECONNECT_AUTOSTART = "org.kde.kdeconnect.daemon.desktop"
KDECONNECT_DBUS = "org.kde.kdeconnect.service"


def _gvariant_list(items) -> str:
    return "[" + ", ".join("'" + i.replace("\\", "\\\\").replace("'", "\\'") + "'" for i in items) + "]"


@guide("net.kdeconnect")
def kdeconnect(check, scan, outcome):
    host, paths = scan.host, scan.paths
    running = "kdeconnectd" in processes(host, own=True)
    enabled = scan.gnome.gsettings("org.gnome.shell", "enabled-extensions")
    gsconnect = isinstance(enabled, list) and GSCONNECT in enabled
    steps = []
    stop = ["pkill", "-TERM", "-x", "-u", str(host.uid), "kdeconnectd"]
    if running and removed_while_running(host, "kdeconnectd"):
        # removed, and the daemon the session started before that still listens: nothing starts it again
        steps.append(Step("Stop the copy that is still running",
                          "KDE Connect has been removed, but removing a program doesn't stop it where it is already "
                          "running: the copy your session started keeps listening until you log out. Once stopped, "
                          "nothing starts it again. Other accounts logged in now keep theirs until they log out.",
                          options=[option(check, "Stop it now", [Command(stop, "stop KDE Connect's daemon, left running "
                                                                          "from before it was removed", check_ok=False)],
                                          recommended=True, side_effects=[
                                              "Phones can no longer connect. Install KDE Connect again to use it."])]))
    elif running:
        autostart = paths.config_home / "autostart" / KDECONNECT_AUTOSTART
        dbus = paths.data_home / "dbus-1" / "services" / KDECONNECT_DBUS
        off = [WriteFile(autostart, lambda old: "[Desktop Entry]\nType=Application\nName=KDE Connect\n"
                         "Exec=kdeconnectd\nHidden=true\n", "Don't start KDE Connect at login", host.display(autostart)),
               WriteFile(dbus, lambda old: "[D-BUS Service]\nName=org.kde.kdeconnect\nExec=/bin/false\n",
                         "Don't start it when something asks for it", host.display(dbus), then=bus_reload(host)),
               Command(stop, "stop it now: the override above keeps it from starting again on demand",
                       check_ok=False)]
        steps.append(Step("Check which phones are paired",
                          "If you use KDE Connect, keep only phones you own, and turn off plugins you don't use "
                          "(running commands, sharing the clipboard, reading notifications).",
                          commands=["kdeconnect-app"]))
        steps.append(Step("Or turn KDE Connect off", options=[option(
            check, "Turn KDE Connect off for you", off, recommended=True, side_effects=[
                "Phones can no longer connect: file sharing, notifications and the remote control stop.",
                "The KDE Connect icon in the panel shows it as not running. Revert from History to use it again."])]))
        cmd = remove(scan, debian="kdeconnect", fedora="kdeconnectd", arch="kdeconnect", suse="kdeconnect-kde")
        if cmd:
            steps.append(Step("Or remove it for every account",
                              "If nobody on this computer uses it. Removing it doesn't stop the copy already running in "
                              "each account's session, which keeps listening until that account logs out: the second "
                              "command stops yours now.", commands=[cmd, shell(stop)]))
    if gsconnect:
        disabled = scan.gnome.gsettings("org.gnome.shell", "disabled-extensions")
        disabled = disabled if isinstance(disabled, list) else []
        acts = [GSettingsSet("org.gnome.shell", "enabled-extensions", _gvariant_list([e for e in enabled if e != GSCONNECT]))]
        if GSCONNECT not in disabled:
            acts.append(GSettingsSet("org.gnome.shell", "disabled-extensions", _gvariant_list([*disabled, GSCONNECT])))
        steps.append(Step("Check which phones are paired",
                          "If you use GSConnect, keep only phones you own, and turn off plugins you don't use.",
                          commands=[f"gnome-extensions prefs {GSCONNECT}"]))
        steps.append(Step("Or turn GSConnect off", options=[option(
            check, "Turn the GSConnect extension off", acts, recommended=True, side_effects=[
                "Phones can no longer connect. Turn it back on in Extensions, or revert from History."])]))
    return Guide(check.id, "Stop phones connecting over the network",
                 "KDE Connect and GSConnect listen on the local network for paired phones, and paired phones can "
                 "send files, read notifications and, with the plugin on, run commands here.", steps)


# ------------------------------------------------------------------ the outgoing firewall (OpenSnitch, a feature)
# As much an explanation as a set-up: each step says what that part of OpenSnitch does, and the app's changes (rule
# files, two settings) are reverted from History. Installing, and the practice, are commands the user runs. Steps
# refer to each other by title: which are done varies.

OPENSNITCH_RELEASES = "https://github.com/evilsocket/opensnitch/releases"
STARTER = "Start with rules that keep the computer working"
DENY_MODE = "Deny mode, once you're confident"


def _home_display(scan, p) -> str:
    try:
        return "~/" + str(p.relative_to(scan.host.home))
    except ValueError:
        return str(p)


def _os_window_setting(scan, key: str, value: str, label: str, by_hand: str, group: str = "global"):
    from ...fix import QSettingsSet
    from ...opensnitch import settings_file
    p = settings_file(scan.paths)
    return QSettingsSet(p, _home_display(scan, p), group, key, value, label, by_hand)


def _os_close_window(s) -> list[str]:
    return ["Close OpenSnitch's window first: right-click its icon in the system tray and choose Close (or run: "
            "pkill -x opensnitch-ui). It reads this setting when it starts: start it again afterwards."] \
        if s.window_running else []


def _os_browser(scan) -> tuple[str, str | None, str | None]:
    """(the browser, how to install it, how to remove it) for the practice."""
    from . import os_release
    if installed(scan.host, "flatpak"):
        app = "io.github.ungoogled_software.ungoogled_chromium"
        return ("Ungoogled Chromium (Chromium without Google's services, from Flathub)",
                f"flatpak install flathub {app}", f"flatpak uninstall {app}")
    if os_release(scan)[0] == "ubuntu":
        return "Chromium", "sudo snap install chromium", "sudo snap remove chromium"
    return ("Chromium", install(scan, debian="chromium", arch="chromium", fedora="chromium", suse="chromium"),
            remove(scan, debian="chromium", arch="chromium", fedora="chromium", suse="chromium"))


@guide("net.outgoing_firewall")
def outgoing_firewall(check, scan, outcome):
    from ... import helper
    from ... import opensnitch as osn
    from ...fix import RootClear, shell
    from ..network import nm_config
    from . import family
    from ... import ini
    host = scan.host
    s = osn.read(host, scan.paths)
    fam = family(scan)
    unit = s.unit or ("opensnitch.service" if fam == "debian" else "opensnitchd.service")
    daemon = unit.removesuffix(".service")
    first = [] if s.daemon else ["Install OpenSnitch first (the step “Install OpenSnitch”), then press Check again."]
    unreadable = [] if s.config is not None or not s.daemon else [
        f"OpenSnitch's settings ({osn.CONFIG}) can't be read, so the app can't change them."]
    restart = ("OpenSnitch restarts to apply it: for a few seconds connections pass unchecked, and answers you gave for "
               "a while or until reboot are forgotten (rules you made forever stay). It then asks again, also about this "
               "app's own window reaching the app on 127.0.0.1 (WebKitNetworkProcess, or your web browser): allow it, "
               "or the page waits until the question times out.") if s.active else \
        "OpenSnitch isn't running: this applies from when it starts."
    starter = osn.starter_state(host, s) if s.daemon else "missing"
    steps = []

    # 1. what it is
    steps.append(Step("What OpenSnitch is, and what it can and can't do", parts=[
        ("What it does", "Most firewalls, ufw for one, stop other computers connecting in. OpenSnitch watches the other "
         "way. Each time a program on this computer opens a new connection out, OpenSnitch checks its rules; when none "
         "matches, a window asks you whether to allow or deny it, once, for a while, or for ever. It works for every "
         "program, including the ones with no privacy settings at all."),
        ("How it helps your privacy", "You see which programs contact which servers, and how often: telemetry, crash "
         "reports, update checks, trackers built into apps. You can block what has no setting to turn off (closed-source "
         "and Electron apps, games), notice a program connecting that shouldn't, and check that a setting you turned "
         "off really stopped the traffic."),
        ("What it can't do", "It doesn't hide your address from the sites you visit: that is a VPN's or Tor's job. It "
         "can't see inside encrypted connections, so a program you allow to reach a server can send it anything. A "
         "browser using DNS over HTTPS hides the names it looks up, so rules by website don't work for it: allow or "
         "deny a browser as a whole, and block trackers inside it (br.content_blocking). python3, bash, node and java "
         "are each one program to OpenSnitch: allowing one allows every script it runs. And anything running as root "
         "can turn it off."),
        ("What it costs", "A service running as root that sees every connection. At first it asks a lot, and the usual "
         "way it fails is people clicking Allow on everything to make the questions stop: the starter rules below take "
         "the system's own questions away. A program you deny may fail without saying why: OpenSnitch's Events tab is "
         "where to look."),
        ("Settings first, blocking second", "Where a program has a setting for it, turning the setting off is better "
         "than blocking it: a blocked program keeps trying, and its setting is still wrong. The scan's own checks do "
         "that (tel.browser_telemetry, tel.crash_reporters, tel.devtools); OpenSnitch is for everything else."),
    ]))

    # 2. install
    if s.daemon and s.window:
        steps.append(Step("Install OpenSnitch", f"OpenSnitch {s.version or ''} is installed: its daemon and its window."
                          .replace("  ", " "), done=True))
    else:
        missing_window = s.daemon and not s.window
        cmd = install(scan, debian="python3-opensnitch-ui" if missing_window else "opensnitch python3-opensnitch-ui",
                      arch="opensnitch", suse="opensnitch")
        text = ("Its daemon is installed, but not its window, which asks the questions. " if missing_window else
                "OpenSnitch is two parts: a daemon that filters (it runs as root) and a window that asks you. ")
        if cmd:
            text += "Install them in a terminal (the app never runs your package manager), then press Check again."
            if fam == "debian":
                text += (" Ubuntu 24.04 and Linux Mint 22 install version 1.5.8, older but fine for everything here. The "
                         "package starts the daemon at once; nothing is asked until its window runs.")
        else:
            text += (f"This distribution's repositories don't carry it: download the packages for it from the project's "
                     f"releases page, {OPENSNITCH_RELEASES} (check them with Verify a download), and install both, "
                     "opensnitch and opensnitch-ui; then press Check again.")
        cmds = [cmd] if cmd else (["sudo dnf install ./opensnitch-*.rpm ./opensnitch-ui-*.rpm"] if fam == "fedora" else [])
        steps.append(Step("Install OpenSnitch", text, commands=cmds))

    # 3. the starter rules, and allow mode
    programs = helper.opensnitch_programs(str(host.root))
    acts = []
    if starter != "current":
        acts.append(RootChange("opensnitch_rules", {"set": "starter"},
                               "Add the starter rules to /etc/opensnitchd/rules (000-daprivacyscanner-allow-system and "
                               "000-daprivacyscanner-deny-telemetry)" + (", up to date with the programs installed now"
                                                                         if starter == "outdated" else "")))
    if s.window_action != "allow":
        acts.append(_os_window_setting(scan, "default_action", "1", "A question you don't answer is allowed",
                                       "In OpenSnitch: Preferences → Pop-ups, its default action back to deny"))
    steps.append(Step(STARTER,
                      "Before OpenSnitch starts asking, these rules answer the questions about the system's own services, "
                      "and block phone-home servers whose blocking breaks nothing. Without them the first questions are "
                      "about DNS and NetworkManager, and OpenSnitch's window denies a question you don't answer (for 12 "
                      "hours in version 1.7): every program loses the internet. That happened in the app's own tests.",
                      parts=[("Allowed, by program (found on this computer)",
                              "\n".join([f"{what}: {', '.join(p for w, p in programs if w == what)}"
                                         for what in dict.fromkeys(w for w, _ in programs)]
                                        + [f"{helper.OPENSNITCH_KERNEL[0]} (OpenSnitch shows them as "
                                           f"“{helper.OPENSNITCH_KERNEL[1]}”)"])),
                             ("Blocked, by website", "\n".join(f"{h} ({what})" for h, what in helper.OPENSNITCH_TELEMETRY)
                              + "\nA name starting with a dot stands for every name under it."),
                             ("A question you don't answer", "OpenSnitch's window denies it, by its own default, and "
                              "with it whatever connects while a question is open. This step makes it allow them: allow "
                              "mode, so a question you miss changes nothing while you learn. "
                              f"“{DENY_MODE}” turns that around later."),
                             ("Undoing it", "From History: the rule files are removed and the window's setting put back. "
                              "The rules appear in OpenSnitch's Rules tab named 000-daprivacyscanner-…; you can edit them "
                              "there, and History then asks before undoing.")],
                      options=[option(check, "Add the starter rules, and allow what you don't answer", acts,
                                      blockers=first + (_os_close_window(s) if any(a.kind == "qsettings" for a in acts) else []),
                                      side_effects=[restart] if starter != "current" else [], recommended=True)]
                      if acts else [],
                      done=not acts))

    # 4. turn it on
    if s.active and s.enabled:
        steps.append(Step("Turn it on", f"OpenSnitch's daemon ({unit}) is running, and starts at every boot.", done=True))
    else:
        steps.append(Step("Turn it on",
                          "OpenSnitch's daemon does the filtering. "
                          + ("" if starter != "missing" else f"Add the starter rules first (“{STARTER}”), so its first "
                             "questions aren't about the network itself."),
                          options=[option(check, "Start OpenSnitch, and at every boot", [RootChange(
                              "set_service", {"unit": unit, "enable": True, "start": True},
                              f"systemctl enable --now {daemon}")], blockers=first, recommended=True,
                              side_effects=["Undo it from History: OpenSnitch is stopped and no longer starts at boot."])],
                          commands=[f"sudo systemctl enable --now {daemon}"]))

    # 5. its window, part by part
    steps.append(Step("Open OpenSnitch's window, and what each part is for",
                      "The window asks the questions and shows what is happening. Open it from the menu (OpenSnitch) "
                      "or with the command below; it then sits in the system tray, and clicking its icon shows the main "
                      "window. Its tray menu's Autostart starts it at every login: without the window nobody is asked, "
                      "and the daemon's own default decides.",
                      parts=[("The question", "Appears when a program with no rule connects. It names the program, its "
                              "command line, where it is connecting (website, address, port) and the user. Along the "
                              "bottom: what the rule matches (from this executable, from this command line, this "
                              "destination port, this user, this destination ip, from this PID, or the website itself), "
                              "for how long (once, 30s to 1h, until reboot, forever), Deny (the arrow beside it gives "
                              "Reject) and Allow; the default button counts down. Deny drops the connection silently, so "
                              "the program waits and gives up; Reject refuses it at once, so it fails fast. Narrow rules "
                              "mean more questions, each answer meaning more. Only forever is saved to the disk."),
                             ("While a question is open", "The connection that asked waits for your answer, or until the "
                              "question times out (30 seconds), its retries with it. Anything else new, from another "
                              "program or the same program's tries at another address, gets the default straight away: "
                              "in allow mode it goes through, so a program reaching a website with several addresses "
                              "may connect before you answer; in deny mode nothing gets out until you answer. (Version "
                              "1.7.2, tested.)"),
                             ("Events", "Every connection, as it happens, with the rule that decided it. Look here first "
                              "when something stops working."),
                             ("Rules", "Your decisions, and the starter rules (000-daprivacyscanner-…). Double-click one to "
                              "edit it; delete one to be asked again."),
                             ("Hosts, Applications, Addresses, Ports, Users", "The same connections grouped five ways. "
                              "Applications shows which program talks to which servers: the place to see what phones "
                              "home."),
                             ("Nodes", "The computers this window shows: just this one, unless you set up more."),
                             ("Preferences", "Pop-ups: how long a question waits and what happens when you don't answer. "
                              "Nodes: the daemon's own settings, its log level among them. Database: where the window "
                              "keeps its list of connections (In memory: leave it there)."),
                             ("Firewall", "OpenSnitch's own rules for connections coming in, apart from the rules for "
                              "programs. If ufw or firewalld is on (net.firewall_off), leave it alone: two firewalls "
                              "with different defaults get in each other's way.")],
                      commands=["opensnitch-ui &"] if s.window else [], done=s.window_running))

    # 6. what it keeps on the disk: the log level
    level = s.log_level
    level_text = "can't be read" if s.config is None else \
        f"isn't set, so 1 ({osn.LOG_LEVELS[1]})" if s.config.get("LogLevel") is None else \
        f"is {level} ({osn.LOG_LEVELS.get(level, '?')})" if level is not None else "isn't a number"
    low = s.config is not None and (level is None or level < 3)
    steps.append(Step("What OpenSnitch keeps on the disk, and the log level",
                      f"Here, OpenSnitch's log level {level_text}." if s.daemon else "",
                      parts=[("Kept in memory only", "The list of connections in the window (Events and the tabs "
                              "beside it), at its default, In memory: gone when the window closes or the computer "
                              "restarts. A connection a rule decides, allowed or blocked, is written nowhere else."),
                             ("Kept on the disk", "Each rule you make forever is a file in /etc/opensnitchd/rules named "
                              "after the website or program (deny-always-simple-www-example-org.json): only root can "
                              "read what is in it, but every account on this computer can list the names. And at the "
                              "log level OpenSnitch ships with (2), every answer you give, for whatever time (once "
                              "included: each later attempt asks, and is logged, again), every question left unanswered "
                              "and every rule you delete is a line in /var/log/opensnitchd.log naming the website or "
                              "program. The log is kept about seven weeks and every account can read it."),
                             ("Log level 3", "Warnings and errors only. In the app's tests the log stayed empty while "
                              "OpenSnitch blocked, allowed and saved rules, and the rules worked as before. If OpenSnitch "
                              "misbehaves, Preferences → Nodes → Log level IMPORTANT brings those lines back while you "
                              "look into it."),
                             ("Elsewhere", "A question that times out is also a desktop notification naming the "
                              "program and its command line (which can hold a web address): Plasma 6.7 kept no copy on "
                              "the disk in the app's tests, and Presentation mode turns banners off while you share "
                              "your screen. Snapshots (Snapper, Timeshift) keep rule files you delete later.")],
                      options=[option(check, "Set the log level to 3 (warnings only)", [RootChange(
                          "edit_config", {"target": "opensnitch", "values": {"LogLevel": "3"}},
                          f'Set "LogLevel": 3 in {osn.CONFIG}')], blockers=first + unreadable, recommended=True,
                          side_effects=[restart, "Undo it from History to put the level back."])] if low else [],
                      commands=[f"sudoedit {osn.CONFIG}", f"sudo systemctl restart {daemon}"] if low else [],
                      side_effects=['By hand: in the file, set the line "LogLevel": 3, then restart OpenSnitch (the '
                                    "commands below); or in OpenSnitch: Preferences → Nodes → Log level, WARNING."]
                      if low else [],
                      done=s.daemon and s.config is not None and not low))

    # 7. what the log already holds
    held = (s.log_size or 0) > 0 or s.old_logs > 0
    what = " and ".join(x for x in (f"{human_size(s.log_size)} in its log" if s.log_size else "",
                                    f"{s.old_logs} older cop{'ies' if s.old_logs != 1 else 'y'}" if s.old_logs else "") if x)
    steps.append(Step("Delete what the log already holds",
                      (f"OpenSnitch has {what}, written before the log level was raised: they can name websites and "
                       "programs you answered for." if held else "OpenSnitch's log is empty.") if s.daemon else
                      "OpenSnitch isn't installed: its log holds nothing yet.",
                      options=[option(check, "Empty the log and delete its older copies", [RootClear(
                          "clear_opensnitch_log", {}, "Empty /var/log/opensnitchd.log and delete its older copies")],
                          side_effects=(["Set the log level to 3 first (the step above), or the log fills again."]
                                        if low else []) + ["OpenSnitch keeps writing to the same file; at log level 3 "
                                                           "it stays empty."])] if held else [],
                      done=not held))

    # 8. the window's list of connections
    if s.database_file:
        steps.append(Step("Keep the list of connections in memory",
                          f"OpenSnitch's window saves every connection it shows to {s.database_file}: each program and "
                          "website, with the time, kept until it is purged.",
                          options=[option(check, "Keep it in memory", [
                              _os_window_setting(scan, "type", "0", "The list of connections in memory", "In OpenSnitch: "
                                                 "Preferences → Database, File", group="database"),
                              _os_window_setting(scan, "file", "file::memory:", "Not in a file", "", group="database")],
                              blockers=_os_close_window(s), recommended=True,
                              side_effects=[f"The file {s.database_file} stays until you delete it, once the window is "
                                            f"closed: {shell(['rm', s.database_file])}"])]))

    # 9. practice
    browser, get, drop = _os_browser(scan)
    steps.append(Step("Try it: watch OpenSnitch ask",
                      "With the window running, a few things to try. Nothing here changes the app's set-up; delete the "
                      "rules you make at the end.",
                      parts=[("A command that connects", "In a terminal, run the first command below. OpenSnitch asks "
                              "about curl. example.com has more than one address: in allow mode curl gets through on "
                              "the next one while the first waits for you, so it has usually finished before you answer "
                              "(see “While a question is open” above). Choose from this executable, 30s, and Deny. Run it again within the 30 seconds: "
                              "now curl waits and gives up after 10 seconds, because Deny drops the connection without a "
                              "word. Next time choose Reject (the arrow beside Deny): curl fails at once. Then find them "
                              "all in the Events tab."),
                             ("A browser you haven't used yet", f"Install {browser} with the second command, start it "
                              "and open a page. It connects to several servers at once: allow it from this executable, "
                              "until reboot. Then try a rule for one website only and watch it ask again for the next "
                              "one, and the next: browsers contact dozens of servers, so allow a browser as a whole and "
                              "block trackers inside it (br.content_blocking)."),
                             ("The starter rules at work", "In the Events tab, a connection the starter rules blocked "
                              "shows the rule's name, 000-daprivacyscanner-deny-telemetry."),
                             ("Clean up", "In the Rules tab, delete the rules you made for curl and the browser, then "
                              "remove the browser with the last command.")],
                      commands=["curl -4 -m 10 https://example.com"] + [c for c in (get, drop) if c]))

    # 10. connectivity checks
    uri = ini.get(nm_config(host), "connectivity", "uri") if installed(host, "NetworkManager") else None
    nm_host = re.sub(r"^\w+://([^/:]+).*", r"\1", uri).lower() if uri else None
    listed = [h for h, _ in helper.OPENSNITCH_CONNECTIVITY]
    conn = osn.PREFIX + "deny-connectivity-checks" in s.own_rules
    here = (f" This computer's NetworkManager checks with {nm_host}, " + ("which the rule covers." if nm_host in listed
            else "which the rule doesn't cover: it serves a website too, so blocking it would block that." if nm_host ==
            "fedoraproject.org" else "which the rule doesn't cover.")) if nm_host else ""
    steps.append(Step("Connectivity checks: allowed unless you choose",
                      "Desktops and Firefox fetch a small page from a fixed server every few minutes to see whether "
                      "you're online and whether a Wi-Fi login page is in the way: that server, and your network, see "
                      "when this computer is online. They're allowed unless you block them here." + here
                      + (" Blocked now: undo it from History to allow them again." if conn else ""),
                      parts=[("Blocking them", "\n".join(f"{h} ({what})" for h, what in helper.OPENSNITCH_CONNECTIVITY)
                              + "\nThe dry run shows the rule file exactly as it is written.")] if not conn else [],
                      options=[option(check, "Block the connectivity checks", [RootChange(
                          "opensnitch_rules", {"set": "connectivity"},
                          "Add 000-daprivacyscanner-deny-connectivity-checks to /etc/opensnitchd/rules")],
                          blockers=first, side_effects=[
                              "NetworkManager then reports limited connectivity (a warning on the network icon), and "
                              "programs that ask it whether you're online may act as if you weren't (tested).",
                              "Wi-Fi login pages (hotels, trains) aren't detected: open any http:// page to reach one.",
                              "Turning NetworkManager's check off instead (net.connectivity_check) stops it without "
                              "the limited warning; this rule also covers Firefox's.", restart])] if not conn else [],
                      done=conn))

    # 11. deny mode
    acts = []
    if s.daemon_action not in ("deny", "reject"):
        acts.append(RootChange("edit_config", {"target": "opensnitch", "values": {"DefaultAction": "deny"}},
                               f'Set "DefaultAction": "deny" in {osn.CONFIG} (while the window isn\'t running)'))
    if s.window_action != "deny":
        acts.append(_os_window_setting(scan, "default_action", "0", "A question you don't answer is denied",
                                       "In OpenSnitch: Preferences → Pop-ups, its default action back to allow"))
    blockers = first + unreadable
    if s.daemon and starter == "missing":
        blockers.append(f"Add the starter rules first (“{STARTER}”): without them deny mode cuts DNS and the network "
                        "the first time a question about them goes unanswered.")
    elif s.daemon and starter == "outdated":
        blockers.append(f"Bring the starter rules up to date first (“{STARTER}”): programs they allow were installed or "
                        "removed since, and one installed since, a VPN's service say, would be cut off in deny mode.")
    if any(a.kind == "qsettings" for a in acts):
        blockers += _os_close_window(s)
    steps.append(Step(DENY_MODE,
                      ("Deny mode is on: nothing without a rule gets out unless you allow it. Undo it from History to go "
                       "back to allow mode." if s.deny_mode else
                       ("Now: allow mode." if s.daemon else "The starter rules leave OpenSnitch in allow mode.")
                       + " A question you don't answer, whatever else connects while a question is open, "
                       "about included), and any connection while OpenSnitch's window isn't running, is let through. "
                       "Deny mode blocks them instead. Turn it on once questions have become rare: a week or two of "
                       "normal use, answering forever for what you use every day."),
                      options=[option(check, "Turn on deny mode", acts, blockers=blockers, side_effects=[
                          "Until OpenSnitch's window is running after you log in, every connection without a rule is "
                          "blocked: your browser, mail, anything you haven't made a rule for."
                          + ("" if s.autostart else " Its tray menu's Autostart starts the window at login."),
                          "A question you miss blocks that connection: the program may fail without saying why "
                          "(look in the Events tab).",
                          "A VPN's service with no rule can't connect, and its kill switch then blocks everything: the "
                          "starter rules allow Mullvad's and OpenVPN; give another VPN's service a rule first (“Living "
                          "with it”, With a VPN).", restart, "Undo it from History to go back to allow mode."])]
                      if acts else [],
                      done=not acts))

    # 12. living with it
    gone = remove(scan, debian="opensnitch python3-opensnitch-ui", arch="opensnitch", suse="opensnitch")
    steps.append(Step("Living with it", parts=[
        ("When something stops working", "Look in the Events tab for a denied connection and the rule that denied it; "
         "edit or delete that rule in the Rules tab."),
        ("After an update", "A program that moves, or (with checksums on) changes, may be asked about again: answer as "
         "before."),
        ("Pausing it", f"sudo systemctl stop {daemon}: connections then flow unchecked until it starts again "
         f"(sudo systemctl start {daemon})."),
        ("Removing it", "Undo the app's changes in History first (the rule files, the settings), then remove the "
         "package" + (f": {gone}" if gone else "") + "."),
        ("With a VPN", "Tested with Mullvad VPN. OpenSnitch decides before the VPN's own firewall, so the VPN's kill "
         "switch and lockdown mode work as before, also when OpenSnitch stops or crashes. The VPN's service and its "
         "tunnel need rules: the starter rules allow Mullvad's service and OpenVPN, and the kernel's connections, which "
         "is what a WireGuard tunnel is to OpenSnitch. Without them deny mode stopped Mullvad connecting, and its kill "
         "switch then kept the computer offline. Another VPN's service needs a rule (from this executable, forever) "
         "before you turn on deny mode. While the VPN itself blocks traffic (reconnecting, or lockdown mode while "
         "disconnected) OpenSnitch can still ask, and the Events tab shows as allowed a connection the VPN then "
         "dropped. Split tunnelling works as before: the programs it keeps out of the tunnel are asked about like any "
         "other. A website blocked by a rule is blocked at its lookup too, inside the tunnel: the program waits a few "
         "seconds for the lookup to time out rather than failing at once (Mullvad's own DNS blockers answer at once)."),
        ("Tor or Mullvad Browser in memory", "The app's own browsers run in a sandbox. Tor Browser reaches the "
         "internet only through tor, its own program, so tor is what OpenSnitch asks about. Mullvad Browser's "
         "connections, when its panel runs it through pasta (its sandbox's network), come from pasta: the question "
         "names /usr/bin/passt.avx2 (or passt), the program pasta runs, with pasta's command line, never the browser "
         "(tested). Allowing it allows whatever else runs through pasta (Podman's containers, for one), so allow it "
         "until reboot rather than forever; a rule for one website still works."),
    ]))

    state = ("" if not s.daemon else
             " It is in deny mode now." if s.deny_mode else
             " It is in allow mode now: what you don't answer for is let through, until you turn on deny mode (the "
             "step near the end).")
    return Guide(check.id, "Set up OpenSnitch, an outgoing firewall",
                 "OpenSnitch asks you before a program on this computer connects out. This guide explains it as it goes, "
                 "part by part. The app installs nothing itself (the commands are yours to run), and what it changes "
                 "here, rule files and two settings, is undone from History." + state, steps)
