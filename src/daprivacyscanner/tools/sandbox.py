"""The browser in the RAM disk, run inside a sandbox (docs/TECHNICAL.md, Tools): bubblewrap, the host's own
program, never bundled. Tor Browser's and Mullvad Browser's own sandbox keeps web pages from the
browser; this one keeps the browser, if a page gets past that, from the rest of the account, and
from the network outside Tor.

Inside it the browser sees:
- /usr read-only (and /bin, /lib… as the host has them), /proc, a minimal /dev (no camera, sound card
  or GPU: pages draw with the processor, through Mesa's software renderer, software_gl), the CPU list in
  /sys, an empty /tmp. The graphics card only when the user allows it (gpu(): its render nodes and NVIDIA's
  device files), which puts its drivers, in the kernel and in the browser, within reach of a page that got
  past the browser, for the speed and the fingerprint of the browser outside;
- an /etc of its own (ETC_KEPT): only what the browser, GTK, fontconfig, Mesa, the C library and tor's
  pluggable transports read (the library cache, name service, certificates, fonts, GTK and sound
  settings), with files of the sandbox's own for those that say whose computer it is: passwd and group
  name only "user", hostname and hosts only "localhost", machine-id one that every copy of the app
  shares (Whonix's), and the clock on UTC. Nothing else of the computer's settings is there: not the
  disk and RAID ids (fstab, crypttab, the kernel command line in /etc/kernel or /etc/default/grub,
  mdadm.conf, zpool.cache, hostid), network, VPN, mail and proxy settings, the time zone, keyboard
  layout or package mirrors (which say where the computer is), nor a Firefox policy the computer sets
  (/etc/firefox). The computer's own files are never changed;
- in /proc, a kernel command line and a boot id of the sandbox's own (proc_masks): the real ones name
  the disks' UUIDs and stay the same for every session (the boot id until a restart), which could link
  sessions; and nothing of the disks, swap, input devices or drivers (PROC_OWN, PROC_EMPTIED). Only in
  the innermost sandbox: the kernel lets nothing inside mount a /proc of its own once a file of one is
  covered (tested; Firefox's own sandbox doesn't);
- its own folder in the RAM disk at /home/user/<folder>, read-only, except its profile and its
  Downloads folder: a browser that was taken over can't change its own program files, which it would
  otherwise run again (unsandboxed, if the user unticked the sandbox later); its "To upload" folder is
  read-only like the rest. The real path, which names the user, isn't used inside;
- the display: on Wayland only a socket of the compositor's (no X11, so it runs as a Wayland client, not
  through XWayland where X11 programs can watch each other): where the compositor has the security-context
  protocol, a socket it marks as a sandbox's (tools/wayland.py), whose clients don't get the privileged
  protocols (recording the screen, reading the clipboard in the background), held open by bubblewrap's
  --sync-fd for as long as the sandbox runs; else the compositor's own. On X11 the X server's socket,
  under a display number nobody else uses, with an X authority file of its own;
- sound, only when the user allows it: PulseAudio's (or pipewire-pulse's) socket. It gives more than
  sound (tested from a sandbox holding only that socket, PipeWire 1.0): the microphone, the real user and
  host names (the server's info), the other programs using sound, and modules loaded on request: the
  server, outside the sandbox and on the computer's network, connected out to an address it was given
  (module-tunnel-sink) and opened a TCP listener (module-native-protocol-tcp). Under Tor Browser that
  connection reveals the real address. The page lists this under the box, and asks before Tor Browser
  starts with sound.
Nothing else: no home folder, no session D-Bus (so no keyring, portals or notifications), no SSH
or GPG agent, an environment built from scratch. It has its own user (always uid 1000, "user"), PID,
IPC, UTS and cgroup namespaces, a new session (no typing into the terminal that started it, TIOCSTI),
and no capabilities. Nested user namespaces stay allowed, so Firefox's own sandbox keeps working.

The network:
- Tor Browser has none of its own. Two sandboxes, one inside the other: the outer one shares the
  computer's network and runs tor (Tor Browser's own, from its folder, with its pluggable transports in
  a sandbox of their own, without the display, sound or the browser's profile the outer one holds) and
  a filter on tor's control port (tools/torgate.py, run by the host's python3); the inner one, with only a loopback interface,
  runs the browser, which reaches tor through two Unix sockets: SOCKS, and the filtered control port.
  So a browser that was taken over can't connect around Tor (revealing the address), nor to services
  on this computer or the local network, nor to the session's abstract sockets (they belong to the
  network namespace), and the filter refuses anything that would change tor's settings (a proxy or a
  bridge of its choosing would reveal the address just the same). Tor Browser turns its own Connect
  page and bridge settings off when it doesn't start tor (TOR_SKIP_LAUNCH): the app's panel chooses
  bridges instead.
- Mullvad Browser needs the network. With pasta (the passt package) it gets a network namespace of
  its own, connected to the internet through pasta: not to services on this computer's loopback
  (--no-map-gw, no ports forwarded), and not to the session's abstract sockets; with addresses, an
  interface name and a gateway of its own, never the computer's nor its router's hardware address
  (pasta_opts). pasta connects anywhere the computer can, so before bubblewrap starts, routing rules in
  that namespace refuse the local and private ranges (FENCE: the router, printers, a NAS, Docker's and
  libvirt's bridges, Tailscale's) and the computer's own networks, listed on the computer just before
  (host_networks: its addresses on every interface, the networks they are on, a VPN's routes), as root
  of pasta's namespace, which the sandbox inside isn't (tested: the local network refused, the internet
  reached). Mullvad VPN's own SOCKS5 proxies inside its tunnel are
  let through (FENCE_ALLOWED, TCP to port 1080 only): Mullvad Browser's extension uses them to change the
  browser's country while the VPN stays where it is. Its DNS goes to pasta's forwarder (DNS_FORWARD),
  named in a resolv.conf of the sandbox's own. Without pasta it shares the computer's network, which
  shows it this computer's and the router's hardware (MAC) addresses (netlink and the neighbour table,
  no /sys needed: tested), and every device on the network: the page says so, prominently.

Where the kernel has Landlock ABI 6 (Linux 6.12), whatever shares the computer's network is also kept
from abstract Unix sockets and from signalling programs outside the sandbox (LANDLOCK_SCOPE_ABSTRACT_
UNIX_SOCKET, LANDLOCK_SCOPE_SIGNAL): Mullvad Browser without pasta, and tor's sandbox. It is applied
inside the sandbox by the host's python3 just before the program runs. The X server's socket is bound
under an unused display number because libxcb tries the abstract socket of its display first and falls
back to the path only when nobody listens there, not when Landlock refuses it.

On X11 the sandbox keeps the browser from your files, not from the screen: any X11 program can read
what other windows show and what is typed into them, and type into them (a terminal included), so
a compromised browser could do that, and so could any other program to the browser. The page says
so, with the Wayland check's guide.

VERIFY: on Ubuntu 24.04 with apparmor_restrict_unprivileged_userns=1, bubblewrap without a profile
of its own can't set up its namespaces: probe() finds that and the page says why; on Fedora, Arch,
openSUSE and Debian, that the probe passes and the browser starts (Wayland and X11); that pasta
(Debian 12's and Ubuntu's AppArmor profile for it included) starts bubblewrap inside its namespace."""

from __future__ import annotations

import ctypes
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from ..host import Host

BWRAP = "bwrap"
PASTA = "pasta"
PYTHON = "/usr/bin/python3"
SYS_LANDLOCK_CREATE_RULESET = 444          # the same number on every architecture
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_SCOPES_ABI = 6
FAMILY_WILD = 0xFFFF                       # an X authority entry for any host
UPLOADS, DOWNLOADS = "To upload", "Downloads"   # in the browser's own folder (its HOME)

# inside the sandbox: nothing that names the user or the computer
HOME_IN, USER_IN, UID_IN = "/home/user", "user", 1000
RUNTIME_IN = f"/run/user/{UID_IN}"
SESSION_IN = f"{HOME_IN}/.session"
TOR_DIR_IN = f"{RUNTIME_IN}/tor"
SOCKS_IN, CONTROL_IN = f"{TOR_DIR_IN}/socks", f"{TOR_DIR_IN}/control"
MACHINE_ID = "b08dfa6083e7567a1921a715000001fb"     # Whonix's, the same for everyone: it says nothing
DNS_FORWARD = "169.254.0.1"                          # pasta forwards DNS sent here to the computer's resolver
# the sandbox's resolv.conf under pasta: its forwarder, with EDNS0 so that a large answer comes over UDP rather than
# needing TCP, which pasta 2024-02-20 (Mint 22.3, Ubuntu 24.04) doesn't forward (_DNS_TCP)
FORWARD_RESOLV = f"nameserver {DNS_FORWARD}\noptions edns0\n"
# whether pasta's forwarder takes DNS over TCP, by pasta's program, as probe_fence found (connecting from inside):
# pasta 2026-01-20 forwards it to the computer's resolver, 2024-02-20 sent the connection on to the address itself,
# where it timed out (tested). The fence lets TCP to the forwarder through only where it works; elsewhere it is
# refused at once, and nothing goes out towards 169.254.0.1 on the local network.
_DNS_TCP: dict[str, bool] = {}
DNS_TCP_MARK = "dns-over-tcp"
# pasta's namespace gets addresses of its own, never the computer's (pasta_opts). By default pasta copies the
# computer's: its interface's name, its addresses (the global IPv6 one, which a VPN hides and whose EUI-64 form
# holds the hardware address), its routes, and the gateway's address, whose hardware address it then shows: the
# computer's own (pasta 2024-02-20, Mint 22.3) or, mirroring the computer's neighbour table, the router's (pasta
# 2026-01-20, Fedora 44), which public Wi-Fi maps can place (both tested). So: pasta's hardware address the same for
# everyone (PASTA_MAC, newer pasta's own default), the interface eth0, IPv4 10.0.2.15/24 through 10.0.2.2 (what
# VirtualBox and QEMU give their guests: common), IPv6 fd00::15/64 through the link-local address of PASTA_MAC. The
# gateways must be addresses the computer has no neighbour at, or newer pasta shows that neighbour's hardware address
# (tested, with fe80::1, a common router address, and 10.0.2.2): the IPv4 network moves to the next of PASTA_V4 where
# one of the computer's networks overlaps it, and only pasta's own MAC makes the IPv6 one.
PASTA_MAC = "9a:55:9a:55:9a:55"
PASTA_IF = "eth0"
PASTA_V4 = (("10.0.2.15", "10.0.2.2"), ("10.0.3.15", "10.0.3.2"), ("172.31.250.15", "172.31.250.2"))   # each a /24
PASTA_V6 = ("fd00::15", "fe80::9855:9aff:fe55:9a55")
PASTA_OPTS = ("--config-net", "--quiet", "--no-map-gw", "-t", "none", "-u", "none", "-T", "none", "-U", "none",
              "--dns-forward", DNS_FORWARD, "-M", PASTA_MAC, "-I", PASTA_IF)
# refused inside pasta's namespace (prohibit rules ahead of the main table, so no route can be more specific):
# this network, private and shared address space (CGNAT, Tailscale), link-local, benchmarking, multicast and
# reserved; IPv6 unique local, link-local and multicast; then, at each start, the computer's own networks
# (host_networks) and every route pasta copied but the default one (fence). pasta's DNS forwarder is let through first.
FENCE_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
            "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3")
FENCE_V6 = ("fc00::/7", "fe80::/10", "ff00::/8")
# The computer's own networks, listed on the computer just before pasta starts (pasta connects from the computer's
# side, so the namespace's own routes say nothing of them): every address of the computer's, on every interface, and
# the network each is on, and the routes to particular networks, from every routing table. Without them the browser
# reached services on the computer's addresses on other interfaces (a second network card, a VPN's), the ranges a
# split VPN routes, Docker's and libvirt's public IPv6 networks, and the local network's IPv6 prefix while a VPN held
# the default route (found in the review of 2026-10-17, in throwaway namespaces). Not the default routes, nor the
# routes through one interface that between them cover a large part of the internet (INTERNET_SHARE: a sixteenth of
# IPv4, or of IPv6's global 2000::/3): a VPN that carries everything but the local network does it with a few dozen
# broad routes in place of a default one (WireGuard's "exclude private IPs", OpenVPN's 0.0.0.0/1 and 128.0.0.0/1), and
# refusing them would leave the browser without most of the internet. Routes added after the start (a VPN connected
# later) are fenced from the next start.
INTERNET_SHARE = {4: 2 ** 28, 6: 2 ** 121}
FENCE_MAX = 4096                    # networks: a computer with more isn't fenced (the panel says so), never half-fenced
# let through first, TCP to that port only: Mullvad VPN's SOCKS5 proxies inside its tunnel, which Mullvad Browser's
# extension uses to change the country of the browser alone while the VPN stays where it is (mullvad.net/help/
# socks5-proxy: 10.64.0.1 is the connected server's, the others' in 10.124.0.0/22, all on 1080: its list at
# api.mullvad.net/network/v1-beta1/socks-proxies had 93 of 553 in 10.124.2.x on 2026-10-11, past the /23 the help
# page implied). The
# rule lets the addresses and port through, not Mullvad's servers as such: on a network that happens to use those
# addresses, a SOCKS proxy on 1080 there would be reachable too; anything else in 10.0.0.0/8 stays refused.
FENCE_ALLOWED = (("10.64.0.1", 1080), ("10.124.0.0/22", 1080))
# addresses the fence must refuse, checked from inside (probe_fence): one in the fence, the DNS forwarder's on
# anything but DNS, and Mullvad's proxy address on anything but its port (a route lookup: no packet is sent)
FENCE_PROBE = ("192.0.0.8", DNS_FORWARD, "10.64.0.1")

# /etc entries that say whose computer this is, covered in the viewer's sandbox (tools/viewer.py: it keeps the
# computer's /etc, since a viewer may read anything there, and has no network to send anything with):
# files replaced by an empty one, folders by an empty tmpfs.
EMPTIED_FILES = ("fstab", "crypttab", "subuid", "subgid", "mailname", "machine-info", "krb5.conf", "adjtime")
EMPTIED_DIRS = ("ssh", "NetworkManager", "wireguard", "openvpn", "cups", "sssd", "samba", "ppp",
                "wpa_supplicant", "netplan")

# The browser's /etc: these, as the computer has them (a missing one is left out), and ETC_OWN, the sandbox's own.
# A link is kept as a link when what it points to is in the sandbox (/usr, /proc, or a kept entry), else the file
# it points to is bound in its place.
ETC_KEPT = ("ld.so.cache", "ld.so.conf", "ld.so.conf.d", "nsswitch.conf", "host.conf", "gai.conf", "protocols",
            "services", "mime.types", "os-release", "mtab", "alternatives", "fonts", "ssl", "pki", "ca-certificates",
            "crypto-policies", "gtk-2.0", "gtk-3.0", "gtk-4.0", "xdg", "pulse", "alsa", "asound.conf", "drirc",
            "vulkan", "glvnd", "locale.alias")
ETC_OWN = ("passwd", "group", "hostname", "hosts", "machine-id", "timezone")
UTC = ("/usr/share/zoneinfo/Etc/UTC", "/usr/share/zoneinfo/UTC")
IDENTITY_IN = "/run/identity"           # in Tor Browser's outer sandbox: the sandbox's own files, for the inner one
# /proc's files that say whose computer it is, covered in the innermost sandbox (proc_masks): the kernel command line
# (the disks' UUIDs) and the boot id (the same for every session until a restart) by files of the sandbox's own; the
# disks' names, sizes and models (/proc/partitions, /proc/scsi), and swap's file or device and its size (/proc/swaps)
# by empty ones; the input devices' list (/proc/bus/input/devices: a Bluetooth keyboard's or mouse's hardware address,
# a device's serial number), PCI's, and the drivers' files (/proc/driver/nvidia/gpus/*/information: the graphics
# card's serial number, readable whether or not the card was given; matched nvidia-smi's on the lab) by an empty
# folder, /proc/driver only while the card isn't given (NVIDIA's driver reads its files there). Found in the review of
# 2026-10-17. Not hidden, and said on the page: when the computer was started (/proc/stat's btime, /proc/uptime, and
# the clocks every program reads, which a time namespace would shift; bubblewrap has none, 0.9 to 0.13), the names of
# the devices the sandbox's folders come from (/proc/self/mountinfo: vgmint-root, Fedora's luks-<UUID>, Debian's
# <hostname>-vg), and the login session's number (/proc/self/sessionid), all three the same for every session until a
# restart or a new login.
PROC_OWN = {"cmdline": "/proc/cmdline", "boot_id": "/proc/sys/kernel/random/boot_id", "partitions": "/proc/partitions",
            "swaps": "/proc/swaps"}
PROC_EMPTIED = ("bus", "scsi")                # folders of /proc covered by an empty one; "driver" too without the card

# runs inside the sandbox: Landlock's scopes (abstract Unix sockets, signals), then the program
LANDLOCK = """\
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
class Attr(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]
a = Attr(0, 0, 3)
fd = libc.syscall(444, ctypes.byref(a), ctypes.sizeof(a), 0)
if fd < 0 or libc.prctl(38, 1, 0, 0, 0) or libc.syscall(446, fd, 0):
    sys.exit("Landlock could not be applied (%d)" % ctypes.get_errno())
os.execv(sys.argv[1], sys.argv[1:])
"""
# The sandbox's command, around the start script, lasts as long as the browser does. Firefox restarts itself as
# a new process (about:profiles' Restart normally…, an add-on or a language that asks for it, the Troubleshoot
# Mode question after crashes) and the old one ends, so the start script returns; bubblewrap returns with its
# command, while what is left runs on under the sandbox's init. Tor Browser's gate took that for the browser
# closing and stopped tor (tested with Tor Browser 15.0.24: firefox.real alone with the two inits, tor's sockets
# gone, every page failing), and pasta, ending with its command, would take Mullvad Browser's network. So: a
# subreaper, to which the sandbox's orphans come, that waits until the start script has ended and no program from
# the browser's folder is left (by /proc/PID/exe: what else lingers, from /usr, isn't waited for), then ends
# with the script's status.
STAY = """\
import ctypes, os, sys
folder, prog = sys.argv[1] + "/", sys.argv[2:]
ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)
first = os.fork()
if not first:
    os.execv(prog[0], prog)
def left():
    for p in os.listdir("/proc"):
        if p.isdigit() and int(p) != os.getpid():
            try:
                if os.readlink("/proc/" + p + "/exe").startswith(folder):
                    return True
            except OSError:
                pass
    return False
status = None
while True:
    try:
        pid, st = os.wait()
    except ChildProcessError:
        break
    if pid == first:
        status = os.waitstatus_to_exitcode(st)
    if status is not None and not left():
        break
status = status or 0
sys.exit(status if status >= 0 else 128 - status)
"""
# the browser's own output goes nowhere: only the sandbox's set-up errors reach the start log
QUIET = ["/bin/sh", "-c", 'exec "$0" "$@" </dev/null >/dev/null 2>&1']     # stdin too: under pasta it is the sync pipe

# runs on the computer just before the sandbox (bwrap, or pasta around it, or a Flatpak viewer):
# - leaves its memory out of crash dumps: coredump_filter 0 (inherited by every process it starts, kept across
#   exec) leaves no memory in a dump, and a core size limit of 1 (NO_CORE, below), at which the kernel skips the
#   dump altogether. The filter is there for where the limit can't be set: at 0 systemd-coredump, handed a fixed
#   limit by the kernel's core_pattern, kept the dump whatever the process's own limit was (tested on Mint 22: a
#   35 MB core with the limit at 0, 48 KB without memory with the filter), and wrote the crash's command line,
#   environment and open files into the journal;
# - joins a new, empty session keyring, so nothing started from here can reach the kernel keyring of the login
#   session (where eCryptfs keeps the key to an encrypted home, some Kerberos setups their tickets: no password
#   guards it, only belonging to the session, which every program started from it inherits). The user keyring
#   is already the sandbox's own (user namespaces have their own). keyctl's number differs between
#   architectures; libkeyutils is tried where it isn't listed. Where keyctl is refused (EPERM, ENOSYS: a
#   container's seccomp) the session's keyring is usually out of reach too, but that is checked rather than
#   assumed (KEYCTL_GET_KEYRING_ID of the session keyring): reachable still, the program doesn't start.
# The core size limit every start gets: 1, not 0. With a pipe in core_pattern (systemd-coredump) the kernel ignores 0
# and runs the handler, which kept a dump and wrote the crashed program's command line, environment and the paths of
# the files it had open into the journal, a file in ~/TempBrowser among them (tested); at 1 it skips the dump
# altogether, logging only the process's number and name. A file pattern skips it too (smaller than a page).
NO_CORE = 1
KEYRING = """\
import ctypes, errno, os, platform, resource, sys
try:
    with open("/proc/self/coredump_filter", "w") as f:
        f.write("0")
except OSError:
    pass
try:                                                  # 1: the kernel skips the dump altogether (NO_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (1, 1))
except (ValueError, OSError):                         # a hard limit of 0 already: it can't be raised
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
KEYCTL = {"x86_64": 250, "amd64": 250, "i386": 288, "i486": 288, "i586": 288, "i686": 288, "aarch64": 219,
          "arm64": 219, "riscv64": 219, "armv7l": 311, "armv6l": 311, "ppc64le": 287, "s390x": 280}
libc = ctypes.CDLL(None, use_errno=True)
nr = KEYCTL.get(platform.machine())
if nr is not None:
    keyctl = lambda *a: libc.syscall(nr, *a)
else:
    try:
        keyctl = ctypes.CDLL("libkeyutils.so.1", use_errno=True).keyctl
    except (OSError, AttributeError):
        keyctl = None
r = keyctl(1, None) if keyctl else -1                 # KEYCTL_JOIN_SESSION_KEYRING, a new anonymous one
e = ctypes.get_errno() if keyctl else errno.ENOSYS
if r < 0 and e not in (errno.EPERM, errno.ENOSYS, 0):
    sys.exit("A keyring of its own could not be made (%s)" % os.strerror(e))
if r < 0 and keyctl and keyctl(0, -3, 0) >= 0:        # KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING: still there
    sys.exit("A keyring of its own could not be made (%s), and the login session's stays reachable" % os.strerror(e))
os.execv(sys.argv[1], sys.argv[1:])
"""


# What bubblewrap (and pasta, and the wrappers before them) are started with: nothing of the app's environment. A
# process outside the sandbox's own PID namespace is out of its sight, but bubblewrap's init is the sandbox's PID 1,
# whose environment (the user, the home folder, SESSION_MANAGER with the computer's name, any token exported in the
# session), command line (every folder it binds, in the user's home) and open files (the start log's path) every
# program in it could read (found in the 2026-10-17 review, tested on p330 and CachyOS). So: this environment, the
# sandbox's own command as PID 1 where it is a reaper (--as-pid-1: STAY), bubblewrap's options read from a descriptor
# where it can't be (--args, sealed()), and logs that are memory files, not paths (log_file()).
SPAWN_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}


def sealed(argv: list[str]) -> tuple[list[str], int]:
    """bubblewrap's options (everything before `--`) read from a memory file (--args N), so its init's command line,
    which the sandbox can read as /proc/1/cmdline, is `bwrap --args N -- COMMAND`: bubblewrap closes the descriptor
    once it has read it (tested with 0.9), and the command names only paths inside the sandbox. Returns the
    command and the descriptor to pass to it (the caller closes its own copy)."""
    end = argv.index("--")
    fd = os.memfd_create("bwrap-args")
    os.write(fd, b"".join(a.encode() + b"\0" for a in argv[1:end]))
    os.lseek(fd, 0, os.SEEK_SET)
    return [argv[0], "--args", str(fd), *argv[end:]], fd


def log_file(name: str) -> int:
    """A log a sandbox's processes write their errors to: a memory file, so what the sandbox can see of it (the
    descriptor's link in /proc) names no path, and nothing of it is on a disk."""
    return os.memfd_create(name)


def read_log(fd: int, limit: int = 4000) -> str:
    try:
        size = os.fstat(fd).st_size
        return os.pread(fd, limit, max(0, size - limit)).decode("utf-8", "replace")
    except OSError:
        return ""


def fresh_keyring(host: Host, argv: list[str]) -> list[str]:
    """`argv` started with a new, empty session keyring and its memory left out of crash dumps (KEYRING),
    by the computer's python3. Where there is no python3: only the core size limit, through prlimit
    (the page doesn't promise the keyring then)."""
    if not host.sys_path(PYTHON).exists():
        prlimit = program(host, "prlimit")
        return [prlimit, f"--core={NO_CORE}:{NO_CORE}", "--", *argv] if prlimit else argv
    prog = argv[0] if argv[0].startswith("/") else (program(host, argv[0]) or argv[0])
    return [PYTHON, "-I", "-c", KEYRING, prog, *argv[1:]]


def landlock_abi_errno() -> tuple[int | None, int]:
    """(the kernel's Landlock ABI version, 0) or (None, errno): EOPNOTSUPP when it is built in but
    not turned on at boot, ENOSYS when the kernel doesn't have it."""
    import errno
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        v = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    except (OSError, AttributeError):
        return None, errno.ENOSYS
    return (v, 0) if v > 0 else (None, ctypes.get_errno() or errno.ENOSYS)


def landlock_abi() -> int:
    """The kernel's Landlock ABI version, 0 without it."""
    return landlock_abi_errno()[0] or 0


def landlock_usable(host: Host) -> bool:
    return landlock_abi() >= LANDLOCK_SCOPES_ABI and host.sys_path(PYTHON).exists()


class SandboxError(Exception):
    """The sandbox can't be built as the panel said it would be: nothing is started."""


def program(host: Host, name: str) -> str | None:
    """The host's program by its full path, so the sandbox's command never looks it up through PATH
    later (a folder early in PATH that the user can write to, ~/.local/bin, could hold another).
    None when it isn't installed in a system folder (one in the home folder doesn't count); on a
    fixture system, its bare name."""
    if not host.runner.which(name):
        return None
    if host.root != Path("/"):
        return name
    import shutil
    path = os.environ.get("PATH") if host.environ.get("PATH") is None else host.environ["PATH"]
    return shutil.which(name, path=":".join(d for d in (path or os.defpath).split(":") if d.startswith("/")
                                            and not d.startswith(str(host.home))))


def _need(host: Host, name: str) -> str:
    """`program`, or SandboxError: a sandbox is never built around a program found through PATH."""
    found = program(host, name)
    if not found:
        raise SandboxError(f"{name} isn't installed in a system folder, so the sandbox can't be built.")
    return found


# ------------------------------------------------------------------ the pieces of a sandbox

def _inside(host: Host, path: str) -> str:
    """A path as the system sees it (a fixture tree's root taken off)."""
    root = os.path.realpath(host.root)
    return path[len(root):] if root != "/" and path.startswith(root + "/") else path


def _etc_target(host: Host, name: str) -> tuple[str, bool] | None:
    """Where /etc/<name> really is, as the system sees it, and whether it is a folder; None when
    there is nothing there (nothing to cover). A link's target is covered, wherever it is."""
    p = host.sys_path(f"/etc/{name}")
    if p.is_symlink():
        real = _inside(host, os.path.realpath(p))
        rp = host.sys_path(real)
        if real.startswith("/etc/") and not rp.exists():
            return None                             # a dangling link inside /etc: nothing to cover
        return real, rp.is_dir()
    if p.exists():
        return f"/etc/{name}", p.is_dir()
    return None


def identity_files(etc: Path, resolv: str | None) -> dict[str, Path]:
    """Writes the sandbox's own /etc and /proc files into `etc` (a folder of the app's in the RAM disk,
    never shown to the browser): name -> file. The boot id is new at every start."""
    import uuid
    etc.mkdir(mode=0o700, exist_ok=True)
    files = {"passwd": f"root:x:0:0:root:/root:/bin/sh\n{USER_IN}:x:{UID_IN}:{UID_IN}::{HOME_IN}:/bin/sh\n"
                       "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
             "group": f"root:x:0:\n{USER_IN}:x:{UID_IN}:\nnogroup:x:65534:\n",
             "hostname": "localhost\n", "hosts": "127.0.0.1 localhost\n::1 localhost\n",
             "machine-id": MACHINE_ID + "\n", "timezone": "Etc/UTC\n", "empty": "",
             "cmdline": "ro quiet\n", "boot_id": f"{uuid.uuid4()}\n", "partitions": "major minor  #blocks  name\n\n",
             "swaps": "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"}
    if resolv is not None:
        files["resolv.conf"] = resolv
    out = {}
    for name, text in files.items():
        path = etc / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        out[name] = path
    return out


def system(host: Host, etc: bool = True) -> list[str]:
    """What every sandbox has: the system read-only, /proc, a minimal /dev, an empty /tmp; the
    computer's /etc unless `etc` is False (the browser's sandbox makes its own: etc_argv)."""
    argv = ["--ro-bind", "/usr", "/usr"]
    for d in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
        p = host.sys_path(d)
        if p.is_symlink():
            argv += ["--symlink", os.readlink(p), d]
        elif p.is_dir():
            argv += ["--ro-bind", d, d]
    return argv + (["--ro-bind", "/etc", "/etc"] if etc else []) + [
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--ro-bind-try", "/sys/devices/system/cpu", "/sys/devices/system/cpu"]


def resolver(host: Host) -> str | None:
    """The computer's resolv.conf with only its nameserver and options lines: its search domains (often the
    network's name, a company's or a university's, from DHCP) and comments stay out of the sandbox. None when
    it can't be read or names no server."""
    try:
        text = host.sys_path("/etc/resolv.conf").read_text(errors="replace")[:65536]
    except OSError:
        return None
    kept = [ln.strip() for ln in text.splitlines() if re.match(r"\s*(nameserver|options)\s", ln)]
    return "\n".join(kept) + "\n" if any(k.startswith("nameserver") for k in kept) else None


def etc_argv(host: Host, files: dict[str, Path], resolv: str | None, inner: bool = False) -> list[str]:
    """The browser's /etc: a tmpfs with ETC_KEPT as the computer has them and ETC_OWN from `files`
    (identity_files), the clock on UTC, then made read-only. `resolv`: "own" (files["resolv.conf"]:
    pasta's forwarder), "host" (the computer's resolver) or None (none: Tor Browser's inner sandbox,
    which has no network to use one). `inner`: for the sandbox inside Tor Browser's outer one, every
    file taken from the outer one's /etc."""
    argv = ["--tmpfs", "/etc"]
    for name in ETC_KEPT:
        p = host.sys_path(f"/etc/{name}")
        if p.is_symlink():
            real = _inside(host, os.path.realpath(p))
            if real.startswith(("/usr/", "/proc/")) or (real.startswith("/etc/") and real.split("/")[2] in ETC_KEPT):
                argv += ["--symlink", os.readlink(p), f"/etc/{name}"]
            elif host.sys_path(real).exists():
                argv += ["--ro-bind", f"/etc/{name}" if inner else real, f"/etc/{name}"]
        elif p.exists():
            argv += ["--ro-bind", f"/etc/{name}", f"/etc/{name}"]
    for name in ETC_OWN:
        argv += ["--ro-bind", f"/etc/{name}" if inner else str(files[name]), f"/etc/{name}"]
    utc = next((z for z in UTC if host.sys_path(z).exists()), None)
    if utc:
        argv += ["--symlink", utc, "/etc/localtime"]
    if resolv == "own":
        argv += ["--ro-bind", str(files["resolv.conf"]), "/etc/resolv.conf"]
    elif resolv == "host":
        t = _etc_target(host, "resolv.conf")
        if t and not t[1]:
            argv += ["--ro-bind", t[0], "/etc/resolv.conf"]
    return argv + ["--remount-ro", "/etc"]


def proc_masks(src: str, gpu: bool = False, host: Host | None = None) -> list[str]:
    """/proc's identifying files covered (PROC_OWN, from the folder `src` holding identity_files' files; PROC_EMPTIED,
    and /proc/driver unless `gpu`: the graphics card was given), each where this kernel has it (a mount point must
    be there already: bubblewrap can't make one in /proc), as `host` sees /proc (the computer's when None). After
    --proc, in the innermost sandbox only (see the module's notes)."""
    exists = (lambda path: host.sys_path(path).exists()) if host is not None else os.path.exists  # noqa: E731
    out: list[str] = []
    for name, target in PROC_OWN.items():
        if name in ("cmdline", "boot_id") or exists(target):
            out += ["--ro-bind", f"{src}/{name}", target]
    for name in (*PROC_EMPTIED, *(() if gpu else ("driver",))):
        if exists(f"/proc/{name}"):
            out += ["--tmpfs", f"/proc/{name}", "--remount-ro", f"/proc/{name}"]
    return out


def identity(host: Host, files: dict[str, Path] | None, own_dns: bool) -> list[str]:
    """For the viewer's sandbox, which keeps the computer's /etc: its identifying files covered by the
    sandbox's own (`files`, from identity_files), and the resolver: the sandbox's own resolv.conf when
    `own_dns`, else the computer's, whose /etc/resolv.conf is often a link into /run (systemd-resolved,
    NetworkManager)."""
    argv: list[str] = []
    if files:
        for name in ("passwd", "group", "hostname", "hosts", "machine-id", *EMPTIED_FILES):
            t = _etc_target(host, name)
            if t and not t[1]:
                argv += ["--ro-bind", str(files.get(name, files["empty"])), t[0]]
        for name in EMPTIED_DIRS:
            t = _etc_target(host, name)
            if t and t[1]:
                argv += ["--tmpfs", t[0]]
    t = _etc_target(host, "resolv.conf")
    if own_dns and files and "resolv.conf" in files:
        target = t[0] if t else "/etc/resolv.conf"
        if t or host.sys_path("/etc/resolv.conf").is_symlink():
            argv += ["--ro-bind", str(files["resolv.conf"]), target]
    elif t and t[0].startswith("/run/"):
        argv += ["--ro-bind-try", t[0], t[0]]
    return argv


def namespaces(share_net: bool) -> list[str]:
    return ["--unshare-all", *(["--share-net"] if share_net else []), "--new-session", "--cap-drop", "ALL",
            "--uid", str(UID_IN), "--gid", str(UID_IN), "--hostname", "localhost", "--clearenv"]


def probe(host: Host) -> str | None:
    """Why the sandbox can't be used here, or None. Runs a sandbox like the browser's around `true`."""
    bwrap = program(host, BWRAP)
    if not bwrap:
        return "bubblewrap (bwrap) isn't installed" + (" in a system folder." if host.runner.which(BWRAP) else ".")
    r = host.run(bwrap, *namespaces(True), *system(host), "--", "/usr/bin/true", timeout=20)
    if r.ok:
        return None
    err = (r.stderr or r.stdout).strip().splitlines()
    detail = err[-1][:200] if err else f"exit status {r.returncode}"
    if re.search(r"uid map|Permission denied|Operation not permitted|No permissions to creat", detail, re.I):
        return (f"bubblewrap can't set up a sandbox here ({detail}). On Ubuntu 24.04 and later, AppArmor stops "
                "programs without a profile of their own from doing that.")
    return f"bubblewrap can't set up a sandbox here ({detail})."


def probe_pasta(host: Host) -> str | None:
    """Why Mullvad Browser can't have a network of its own here, or None: pasta tried around a
    sandbox like the browser's."""
    pasta, bwrap = program(host, PASTA), program(host, BWRAP)
    if not pasta:
        return "pasta isn't installed (the passt package)."
    if not bwrap:
        return "bubblewrap isn't installed."
    r = host.run(pasta, *pasta_opts(host), "--", bwrap, *namespaces(True), *system(host), "--", "/usr/bin/true", timeout=20)
    if r.ok:
        return None
    err = [ln for ln in (r.stderr or r.stdout).strip().splitlines() if not quiet_line(ln)]
    return f"pasta couldn't start a sandbox here ({err[-1][:200] if err else f'exit status {r.returncode}'})."


@dataclass
class Computer:
    """The computer's own networks, as `ip -j` lists them on the computer (computer())."""
    addresses: list = field(default_factory=list)       # ipaddress interfaces: every address but loopback's
    peers: list = field(default_factory=list)           # ipaddress networks: point-to-point links' far ends
    routes: list = field(default_factory=list)          # (ipaddress network, interface): unicast, every table
    defaults: set = field(default_factory=set)          # the IP versions with a default route, in any table


def computer(host: Host) -> Computer:
    """The computer's addresses and routes, listed with iproute2's ip as the app runs (on the computer: pasta's
    namespace has only its own). Raises SandboxError when ip isn't installed, or its listing fails or can't be
    read: whatever relies on it fails closed."""
    import ipaddress
    import json
    ip = program(host, "ip")
    if not ip:
        raise SandboxError("iproute2's ip isn't installed.")

    def listing(*args: str, optional: bool = False) -> list:
        r = host.run(ip, "-j", *args, timeout=10)
        if not r.ok and optional:
            return []
        try:
            data = json.loads(r.stdout) if r.ok else None
        except ValueError:
            data = None
        if not isinstance(data, list):
            why = ((r.stderr or "").strip()[:200] or f"exit status {r.returncode}") if not r.ok else "not in the form expected"
            raise SandboxError(f"this computer's networks couldn't be listed ({why}).")
        return data

    c = Computer()
    try:
        for link in listing("address", "show"):
            for a in (link.get("addr_info") or []) if isinstance(link, dict) else []:
                if not isinstance(a, dict) or not a.get("local") or a.get("scope") == "host":
                    continue
                c.addresses.append(ipaddress.ip_interface(f"{a['local']}/{a.get('prefixlen', 128 if ':' in a['local'] else 32)}"))
                if a.get("address"):                           # the far end of a point-to-point link
                    c.peers.append(ipaddress.ip_network(a["address"], strict=False))
        # IPv6's listing is let off only where the kernel has no IPv6 at all
        no_ipv6 = not host.sys_path("/proc/net/if_inet6").exists()
        for version in (4, 6):
            for r in listing(f"-{version}", "route", "show", "table", "all", "type", "unicast",
                             optional=version == 6 and no_ipv6):
                dst = r.get("dst") if isinstance(r, dict) else None
                if not dst:
                    continue
                net = None if dst == "default" else ipaddress.ip_network(dst, strict=False)
                if net is None or net.prefixlen == 0:
                    c.defaults.add(version)
                    continue
                dev = r.get("dev") or ",".join(sorted(str(h.get("dev")) for h in r.get("nexthops") or []
                                                      if isinstance(h, dict)))
                c.routes.append((net, dev))
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise SandboxError(f"this computer's networks couldn't be read ({e}).") from None
    return c


def pasta_opts(host: Host, c: Computer | None = None) -> list[str]:
    """pasta's options (PASTA_OPTS) with the namespace's own addresses: IPv4 from the first of PASTA_V4 that no
    network of the computer's overlaps, IPv6 PASTA_V6. Only the IP versions the computer has a default route for:
    without one, newer pasta makes a network up for its namespace (IPv6 through fe80::1, a common router address,
    tested on Fedora 44), so -4 or -6 leaves it out. Where the computer's networks can't be listed, the first
    candidate and both versions (pasta leaves out one it has no route for)."""
    import ipaddress
    try:
        c = c or computer(host)
    except SandboxError:
        c = None
    taken = [a.network for a in c.addresses if a.version == 4] if c else []
    addr, gw = next(((a, g) for a, g in PASTA_V4
                     if not any(ipaddress.ip_network(f"{a}/24", strict=False).overlaps(n) for n in taken)), PASTA_V4[0])
    four, six = ["-a", addr, "-n", "24", "-g", gw], ["-a", PASTA_V6[0], "-g", PASTA_V6[1]]
    if c is not None and c.defaults == {4}:
        return [*PASTA_OPTS, *four, "-4"]
    if c is not None and c.defaults == {6}:
        return [*PASTA_OPTS, *six, "-6"]
    return [*PASTA_OPTS, *four, *six]


def host_networks(host: Host, c: Computer | None = None) -> tuple[list[str], list[str]]:
    """The computer's own networks for the fence to refuse (see INTERNET_SHARE): (IPv4, IPv6) prefixes, merged,
    those inside FENCE_V4 and FENCE_V6 left out: every address on every interface (but loopback's) and the network
    it is on, a point-to-point link's far end, and the unicast routes of every table but the default ones and those
    carrying the internet. Raises SandboxError when they can't be listed or read (computer()), or are more than
    FENCE_MAX: the fence fails closed."""
    import ipaddress
    c = c or computer(host)
    nets = {n for a in c.addresses for n in (ipaddress.ip_network(a.ip), a.network)} | set(c.peers)
    through: dict[tuple[str, int], list] = {}                  # (interface, IP version) -> its routes
    for net, dev in c.routes:
        through.setdefault((dev, net.version), []).append(net)
    for (_dev, version), routes in through.items():
        merged = list(ipaddress.collapse_addresses(routes))
        if sum(n.num_addresses for n in merged) < INTERNET_SHARE[version]:
            nets.update(merged)
    fenced = [ipaddress.ip_network(n) for n in (*FENCE_V4, *FENCE_V6)]
    left = [n for n in nets if not any(n.version == f.version and n.subnet_of(f) for f in fenced)]
    v4 = [str(n) for n in ipaddress.collapse_addresses(n for n in left if n.version == 4)]
    v6 = [str(n) for n in ipaddress.collapse_addresses(n for n in left if n.version == 6)]
    if len(v4) + len(v6) > FENCE_MAX:
        raise SandboxError(f"this computer has more networks than can be refused one by one ({len(v4) + len(v6)}).")
    return v4, v6


def fence(host: Host, proxies: bool = True, networks: tuple[list[str], list[str]] | None = None,
          dns_tcp: bool | None = None) -> list[str] | None:
    """What runs first in pasta's namespace, as its root: the FENCE rules, the computer's own networks (host_networks,
    listed now, before pasta starts: the local networks' prefixes, which on IPv6, and on some IPv4 networks, are
    public addresses no fixed list covers, the computer's addresses on every interface, a VPN's routes), and every
    route pasta copied into its namespace but the default one, then the command after it ("$0" "$@"). None without
    iproute2's ip; SandboxError when the computer's networks can't be listed. Fails closed (nothing starts): any
    rule that can't be set stops it, but for a copied route's that is there already, and the IPv6 ones where the
    kernel has no IPv6 at all (no /proc/net/if_inet6: nothing to fence then). pasta's DNS forwarder is let through
    for DNS alone (port 53: UDP, and TCP where `dns_tcp`, by default where probe_fence found pasta's forwarder
    takes it), not for anything else at its address; a route listing that fails counts as a failure too (it isn't
    hidden by the pipe). `proxies`: FENCE_ALLOWED is let through (Mullvad Browser's; not for a program on trial).
    `networks`: host_networks' answer, when the caller has it already."""
    ip = program(host, "ip")
    if not ip:
        return None
    host4, host6 = networks or host_networks(host)
    if dns_tcp is None:
        dns_tcp = _DNS_TCP.get(program(host, PASTA) or "", False)
    fail = "{ echo 'The local network could not be fenced off' >&2; exit 1; }"
    dns = " && ".join(f"{ip} rule add lookup main to {DNS_FORWARD} ipproto {proto} dport 53 pref 50"
                      for proto in (("udp", "tcp") if dns_tcp else ("udp",)))
    v4 = " && ".join(f"{ip} rule add prohibit to {n} pref 100" for n in FENCE_V4)
    v6 = " && ".join(f"{ip} -6 rule add prohibit to {n} pref 100" for n in FENCE_V6)
    allowed = "; ".join(f"{ip} rule add lookup main to {n} ipproto tcp dport {port} pref 40 2>/dev/null"
                        for n, port in FENCE_ALLOWED) if proxies else ":"   # an iproute2 without dport: they stay fenced off
    # the computer's own networks (prefixes ipaddress wrote: digits, dots, colons and a slash, nothing a shell reads)
    refuse = lambda family, nets: (f"for n in {' '.join(nets)}; do {ip} -{family} rule add prohibit to \"$n\" "  # noqa: E731
                                   f"pref 100 || {fail}; done; ") if nets else ""
    own = (f'own() {{ routes=$({ip} -"$1" -o route show table main type unicast) || return 1; '
           f'printf "%s\\n" "$routes" | while read -r net rest; do '
           f'[ -z "$net" ] || [ "$net" = default ] && continue; '
           f'out=$({ip} -"$1" rule add prohibit to "$net" pref 100 2>&1) || case "$out" in *"File exists"*) ;; '
           f'*) echo "$out" >&2; exit 1;; esac; done; }}')
    script = (f"{dns} && {v4} || {fail}; {allowed}; {own}; {refuse(4, host4)}own 4 || {fail}; "
              f"if [ -e /proc/net/if_inet6 ]; then {v6} || {fail}; {refuse(6, host6)}own 6 || {fail}; fi; "
              'exec "$0" "$@"')
    return ["/bin/sh", "-c", script]


def fence_check(host: Host, also: tuple[str, ...] = (), dns_tcp: bool = False) -> list[str]:
    """Run inside the sandbox by probe_fence: a route lookup of each FENCE_PROBE address, and of the addresses
    `also` (one of the computer's own networks of each IP version), must be refused (no packet is sent), or the
    fence isn't in place. `dns_tcp`: then whether pasta's forwarder takes a TCP connection on port 53 (the
    computer's python3 connecting, for 2 seconds at most), said on stdout as DNS_TCP_MARK."""
    ip = program(host, "ip") or "ip"
    loop = (f"for a in {' '.join((*FENCE_PROBE, *also))}; do {ip} route get \"$a\" >/dev/null 2>&1 && "
            '{ echo "$a is reachable: the fence is not in place" >&2; exit 1; }; done; ')
    if dns_tcp:
        loop += (f"{PYTHON} -I -c 'import socket; socket.create_connection((\"{DNS_FORWARD}\", 53), 2).close()' "
                 f">/dev/null 2>&1 && echo {DNS_TCP_MARK}; ")
    return ["/bin/sh", "-c", loop + "exit 0"]


def probe_fence(host: Host) -> str | None:
    """Why pasta's namespace can't be fenced off from the local network here (fence), or None: tried
    around a sandbox like the browser's, which then checks from inside that the fence refuses what it
    should (fence_check: route lookups, no packets), the computer's own networks included."""
    import ipaddress
    pasta, bwrap = program(host, PASTA), program(host, BWRAP)
    if not (pasta and bwrap):
        return "pasta or bubblewrap isn't installed."
    if not program(host, "ip"):
        return "iproute2's ip isn't installed."
    try:
        c = computer(host)
        host4, host6 = host_networks(host, c)
        f = fence(host, networks=(host4, host6), dns_tcp=True) or []
    except SandboxError as e:
        return str(e)
    also = tuple(str(next(iter(ipaddress.ip_network(nets[0]).hosts()), ipaddress.ip_network(nets[0]).network_address))
                 for nets in (host4, host6) if nets)
    r = host.run(pasta, *pasta_opts(host, c), "--", *f, bwrap, *namespaces(True), *system(host), "--",
                 *fence_check(host, also, dns_tcp=True), timeout=25)
    if r.ok:
        _DNS_TCP[pasta] = DNS_TCP_MARK in (r.stdout or "").split()
        return None
    err = [ln for ln in (r.stderr or r.stdout).strip().splitlines() if not quiet_line(ln)]
    return f"its rules couldn't be set ({err[-1][:200] if err else f'exit status {r.returncode}'})."


def quiet_line(line: str) -> bool:
    """pasta's notices that aren't errors (it says them even with --quiet)."""
    return bool(re.match(r"(No routable interface for IPv[46]|Couldn't get any nameserver address)", line.strip()))


# ------------------------------------------------------------------ the display and sound

@dataclass
class Display:
    kind: str                                   # wayland, x11, none
    binds: list[tuple[str, str]] = field(default_factory=list)    # read-only: (outside, inside)
    env: dict[str, str] = field(default_factory=dict)
    note: str = ""
    network: bool = False                       # reached over the network (an X display over SSH)


def _xauth_entries(data: bytes) -> list[tuple[int, bytes, bytes, bytes, bytes]]:
    out, i = [], 0
    try:
        while i < len(data):
            family = struct.unpack_from(">H", data, i)[0]
            i += 2
            fields = []
            for _ in range(4):
                n = struct.unpack_from(">H", data, i)[0]
                fields.append(data[i + 2:i + 2 + n])
                i += 2 + n
            out.append((family, *fields))
    except struct.error:
        pass
    return out


def xauth_for(data: bytes, number: str, new_number: str) -> bytes:
    """The user's X authority entries for display `number`, for any host and display `new_number`:
    what the sandbox needs to reach the same server under another number."""
    out = b""
    for family, _addr, num, name, cookie in _xauth_entries(data):
        if num.decode(errors="replace") != number:
            continue
        nn = new_number.encode()
        out += struct.pack(">H", FAMILY_WILD) + struct.pack(">H", 0)
        out += struct.pack(">H", len(nn)) + nn + struct.pack(">H", len(name)) + name
        out += struct.pack(">H", len(cookie)) + cookie
    return out


def _free_display(host: Host) -> str:
    """A display number with no X server: neither its socket file nor its abstract socket exists."""
    try:
        listening = host.read_sys("/proc/net/unix") or ""
    except Exception:  # noqa: BLE001
        listening = ""
    for n in range(99, 200):
        if not host.sys_path(f"/tmp/.X11-unix/X{n}").exists() and f"@/tmp/.X11-unix/X{n}" not in listening:
            return str(n)
    return "99"


def display(host: Host, private: Path, landlock: bool) -> Display:
    """How the browser reaches the screen from inside the sandbox; writes the X authority file
    into `private` (the app's folder in the RAM disk, never shown to the browser) when it needs one."""
    env = host.environ
    runtime = env.get("XDG_RUNTIME_DIR", f"/run/user/{host.uid}")
    wl = env.get("WAYLAND_DISPLAY", "")
    if wl:                                         # a Wayland session: never X11 (XWayland) in its place
        sock = wl if wl.startswith("/") else f"{runtime}/{wl}"
        if not host.sys_path(sock).exists():
            return Display("none", note=f"The Wayland socket this session names ({sock}) isn't there.")
        return Display("wayland", [(sock, f"{RUNTIME_IN}/wayland-0")],
                       {"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland", "MOZ_ENABLE_WAYLAND": "1",
                        "GDK_BACKEND": "wayland"})
    disp = env.get("DISPLAY", "")
    m = re.fullmatch(r"(?:unix)?:(\d+)(?:\.\d+)?", disp)
    auth_src = env.get("XAUTHORITY") or str(host.home / ".Xauthority")
    try:
        auth = Path(auth_src).read_bytes()
    except OSError:
        auth = b""
    if m:
        sock = f"/tmp/.X11-unix/X{m.group(1)}"
        if not host.sys_path(sock).exists():
            return Display("none", note=f"The X server's socket ({sock}) isn't there.")
        number = _free_display(host) if landlock else m.group(1)
        binds = [(sock, f"/tmp/.X11-unix/X{number}")]
        xenv = {"DISPLAY": f":{number}", "XDG_SESSION_TYPE": "x11"}
        entries = xauth_for(auth, m.group(1), number)
        if entries:
            path = private / "Xauthority"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(entries)
            binds.append((str(path), "/tmp/.Xauthority"))
            xenv["XAUTHORITY"] = "/tmp/.Xauthority"
        return Display("x11", binds, xenv)
    if disp:                                       # a TCP display (SSH forwarding): it needs the network
        binds, xenv = [], {"DISPLAY": disp, "XDG_SESSION_TYPE": "x11"}
        if auth:
            binds = [(auth_src, "/tmp/.Xauthority")]
            xenv["XAUTHORITY"] = "/tmp/.Xauthority"
        return Display("x11", binds, xenv, network=True,
                       note="This display is reached over the network (SSH forwarding)")
    return Display("none", note="There is no display to show the browser on.")


# ------------------------------------------------------------------ a display of its own (X11)

XEPHYR = "Xephyr"
XEPHYR_TITLE = "{name}, in a display of its own"
TERMINATE_AFTER = 10                   # seconds without a client before Xephyr ends: the browser's start runs short-lived
                                       # X clients (its GL test) before its window, and restarts itself after an update


@dataclass
class Nested:
    """Xephyr, a nested X server, in a sandbox of its own: the only thing with the computer's X server.
    The browser's sandbox gets Xephyr's socket alone, with a cookie of its own, so on X11 too the browser
    can't see or type into other windows. Not the other way round: Xephyr's window is a window on the
    computer's X server like any other, which any program there can read and type into (the page says so)."""
    argv: list[str]                             # Xephyr in its sandbox
    socket: Path                                # where its socket appears (the app's private folder)
    display: Display                            # what the browser's sandbox gets


def _xauth_entry(number: str, cookie: bytes) -> bytes:
    name, num = b"MIT-MAGIC-COOKIE-1", number.encode()
    return (struct.pack(">HH", FAMILY_WILD, 0) + struct.pack(">H", len(num)) + num + struct.pack(">H", len(name)) + name
            + struct.pack(">H", len(cookie)) + cookie)


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


NESTED_MAX = (1400, 1100)               # the largest page the browsers open (1400x900) and their toolbars (about 155 px:
                                        # 1060 was enough, tested): no window manager there to stretch the browser's
                                        # window, so a bigger display is a black margin
PANEL = 48                              # room for a panel when the desktop doesn't say where its panels are


def screen_size(host: Host) -> str:
    """A size for the nested display: the room the browser's window would have on this screen, so that its
    page is the size it would be outside. resistFingerprinting opens the page at what that room leaves under
    the toolbars, in steps of 200x100 (on a 1440x870 work area, 1400x700, tested), so a smaller display puts
    the browser in a smaller, rarer group: 85% of the screen did (1400x700 where it opens at 1400x800 on a
    1920x1080 screen, tested). The room is the work area (_NET_WORKAREA: the screen less its panels); Xephyr
    is resizeable, so a window manager that keeps windows inside the work area (Cinnamon's, tested) takes its
    title bar off the display, as it would off the browser's window that didn't fit. Without the work area,
    the screen (xdpyinfo) less room for a panel; at most NESTED_MAX; else 1280x800."""
    room = None
    if host.runner.which("xprop"):
        r = host.run("xprop", "-root", "-notype", "_NET_WORKAREA")
        m = re.search(r"_NET_WORKAREA = \d+, \d+, (\d+), (\d+)", r.stdout if r.ok else "")
        room = (int(m.group(1)), int(m.group(2))) if m else None
    if room is None and host.runner.which("xdpyinfo"):
        r = host.run("xdpyinfo")
        m = re.search(r"dimensions:\s+(\d+)x(\d+) pixels", r.stdout if r.ok else "")
        room = (int(m.group(1)), int(m.group(2)) - PANEL) if m else None
    if room is None:
        return "1280x800"
    return f"{min(NESTED_MAX[0], max(800, room[0]))}x{min(NESTED_MAX[1], max(600, room[1]))}"


def nested(host: Host, private: Path, title: str, size: str) -> Nested | None:
    """Xephyr's sandbox and the display the browser then gets; None outside a local X11 session. Writes its
    authority files and socket folder into `private` (the app's folder in the RAM disk, never shown to the
    browser). Xephyr reaches the computer's X server by its socket's path (no network of its own, so not
    its abstract socket), listens only on its socket file (-nolisten tcp, -nolisten local) with a cookie of
    its own, and ends when the browser's last connection closes (-terminate)."""
    m = re.fullmatch(r"(?:unix)?:(\d+)(?:\.\d+)?", host.environ.get("DISPLAY", ""))
    if not m or not host.sys_path(f"/tmp/.X11-unix/X{m.group(1)}").exists():
        return None
    outer = m.group(1)
    inner = "1" if outer != "1" else "2"                     # Xephyr's own number, inside its sandbox
    seen = _free_display(host)                               # the browser's: nobody listens there
    auth_src = host.environ.get("XAUTHORITY") or str(host.home / ".Xauthority")
    try:
        computer_auth = xauth_for(Path(auth_src).read_bytes(), outer, outer)
    except OSError:
        computer_auth = b""
    cookie = os.urandom(16)
    x11 = private / "x11"
    x11.mkdir(mode=0o700, exist_ok=True)
    for old in x11.iterdir():
        old.unlink()
    files = {"xauth-computer": computer_auth, "xauth-xephyr": _xauth_entry(inner, cookie),
             "xauth-browser": _xauth_entry(seen, cookie)}
    for name, data in files.items():
        _write_private(private / name, data)
    xephyr, bwrap = _need(host, XEPHYR), _need(host, BWRAP)
    argv = [bwrap, *namespaces(False), *system(host), "--bind", str(x11), "/tmp/.X11-unix",
            "--ro-bind", f"/tmp/.X11-unix/X{outer}", f"/tmp/.X11-unix/X{outer}",
            "--ro-bind", str(private / "xauth-xephyr"), "/tmp/.xephyr-auth",
            "--setenv", "DISPLAY", f":{outer}", "--setenv", "HOME", "/tmp"]
    for k, v in software_gl(host).items():
        argv += ["--setenv", k, v]
    if computer_auth:
        argv += ["--ro-bind", str(private / "xauth-computer"), "/tmp/.Xauthority", "--setenv", "XAUTHORITY", "/tmp/.Xauthority"]
    # under the focus keeper (tools/xfocus.py, by the computer's python3): without a window manager in Xephyr the
    # focus follows the pointer, and the browser's menus closed as soon as it moved onto them
    keeper = [PYTHON, "-I", "-c", Path(__file__).with_name("xfocus.py").read_text()] \
        if host.sys_path(PYTHON).exists() else []
    argv += ["--", *keeper, xephyr, f":{inner}", "-auth", "/tmp/.xephyr-auth", "-nolisten", "tcp", "-nolisten", "local",
             "-terminate", str(TERMINATE_AFTER), "-no-host-grab", "-resizeable", "-screen", size, "-title", title]
    disp = Display("x11", [(str(x11 / f"X{inner}"), f"/tmp/.X11-unix/X{seen}"),
                           (str(private / "xauth-browser"), "/tmp/.Xauthority")],
                   {"DISPLAY": f":{seen}", "XDG_SESSION_TYPE": "x11", "XAUTHORITY": "/tmp/.Xauthority"})
    return Nested(argv, x11 / f"X{inner}", disp)


def sound(host: Host) -> tuple[str, str] | None:
    """PulseAudio's socket (pipewire-pulse's on PipeWire systems): (outside, inside), or None."""
    runtime = host.environ.get("XDG_RUNTIME_DIR", f"/run/user/{host.uid}")
    sock = f"{runtime}/pulse/native"
    return (sock, f"{RUNTIME_IN}/pulse/native") if host.sys_path(sock).exists() else None


# ------------------------------------------------------------------ the whole command

SESSION_DIRS = {"XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache", "XDG_DATA_HOME": "data",
                "XDG_STATE_HOME": "state", "TMPDIR": "tmp"}
# the language and the characters' encoding, nothing more: not the regional formats (LC_TIME, LC_NUMERIC,
# LC_MONETARY, LC_PAPER, LC_MEASUREMENT…), which say the country where the language doesn't (a Romanian date
# format under English, while the clock is UTC: seen on the lab), nor LC_ALL, which would carry them too, nor TZ
PASSED_ENV = ("LANG", "LANGUAGE", "LC_CTYPE", "LC_MESSAGES")


@dataclass
class Layout:
    """One browser's places: `folder`, `session` and `private` are real paths in the RAM disk (the
    app has checked each is a folder of the user's there, not a link); `writable` and `hidden` are
    paths inside the folder (the browser's profile and Downloads; tor's data, which the browser
    needn't see)."""
    name: str                                   # the folder's name: tor-browser, mullvad-browser
    folder: Path
    session: Path
    private: Path
    script: str                                 # inside the folder: Browser/start-tor-browser
    writable: tuple[str, ...]
    hidden: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()      # added to the browser's environment (browser.browser_env)

    @property
    def inside(self) -> str:
        return f"{HOME_IN}/{self.name}"


EGL_VENDORS = "/usr/share/glvnd/egl_vendor.d"     # GLVND's EGL vendor files, the same place on every distribution


def software_gl(host: Host) -> dict[str, str]:
    """What makes OpenGL draw with Mesa's software renderer (llvmpipe) in a sandbox without the GPU's devices.
    GLVND picks NVIDIA's libraries when the X server is NVIDIA's (GLX) or its vendor file sorts first (EGL),
    and they fail there without /dev/nvidia* and never fall back to Mesa: the browser had no WebGL at all and
    Xephyr crashed in libEGL_nvidia (tested on a Quadro P620 with driver 580, X11). With these both work, and
    WebGL answers as llvmpipe does, as it already did on Mesa hosts (one value differs from the stock browser's:
    the extension list against NVIDIA's on X11, SUBPIXEL_BITS against Intel's)."""
    env = {"__GLX_VENDOR_LIBRARY_NAME": "mesa", "LIBGL_ALWAYS_SOFTWARE": "1"}
    try:
        mesa = sorted(p.name for p in host.sys_path(EGL_VENDORS).iterdir() if "mesa" in p.name and p.suffix == ".json")
    except OSError:
        mesa = []
    if mesa:
        env["__EGL_VENDOR_LIBRARY_FILENAMES"] = f"{EGL_VENDORS}/{mesa[0]}"
    return env


NVIDIA_DEVICE = re.compile(r"nvidia(ctl|\d+)")


def gpu(host: Host) -> list[str]:
    """The graphics card's device files, for a browser the user allowed it: the render nodes (/dev/dri/renderD*,
    what Mesa draws through) and NVIDIA's control and card files (its driver needs those, not the render node:
    tested on X11 with driver 580, where they were all it needed). Never the primary nodes (/dev/dri/card*, which
    set the screen's modes), nvidia-modeset or nvidia-uvm (CUDA). Empty when there are none.
    VERIFY: that Mesa (Intel, AMD) draws through the render node alone, without the card's /sys entries."""
    found: list[str] = []
    for folder, keep in (("/dev/dri", lambda n: n.startswith("renderD")), ("/dev", NVIDIA_DEVICE.fullmatch)):
        try:
            found += sorted(f"{folder}/{p.name}" for p in host.sys_path(folder).iterdir() if keep(p.name))
        except OSError:
            pass
    return found


def _gpu_argv(devices: tuple[str, ...] | list[str]) -> list[str]:
    return [x for d in devices for x in ("--dev-bind", d, d)]


def _env(host: Host, disp: Display, with_sound: bool, extra: dict[str, str] | None = None, gpu: bool = False) -> list[str]:
    env = {"HOME": HOME_IN, "USER": USER_IN, "LOGNAME": USER_IN, "PATH": "/usr/local/bin:/usr/bin:/bin",
           "XDG_RUNTIME_DIR": RUNTIME_IN, **({} if gpu else software_gl(host)),
           **{k: host.environ[k] for k in PASSED_ENV if host.environ.get(k)}, "TZ": "UTC",
           **{k: f"{SESSION_IN}/{v}" for k, v in SESSION_DIRS.items()},
           **disp.env, **(extra or {})}
    if with_sound:
        env["PULSE_SERVER"] = f"unix:{RUNTIME_IN}/pulse/native"
    out: list[str] = []
    for k, v in env.items():
        if v:
            out += ["--setenv", k, v]
    return out


def _desktop(disp: Display, snd: tuple[str, str] | None, inside: bool) -> list[str]:
    """The display's and sound's sockets: from the computer, or (`inside`, for the inner sandbox)
    from where the outer one put them."""
    argv: list[str] = []
    for src, dst in disp.binds + ([snd] if snd else []):
        argv += ["--ro-bind", dst if inside else src, dst]
    return argv


def _folder(lay: Layout, outer: bool, inside: bool) -> list[str]:
    """The browser's folder read-only, its profile and Downloads writable; tor's data hidden from
    the browser, writable for tor (`outer`). `inside`: binding from where the outer sandbox put it."""
    src = lambda rel: f"{lay.inside}/{rel}" if inside else str(lay.folder / rel)   # noqa: E731
    argv = ["--ro-bind", lay.inside if inside else str(lay.folder), lay.inside]
    for rel in lay.writable:
        argv += ["--bind", src(rel), f"{lay.inside}/{rel}"]
    for rel in lay.hidden:
        argv += ["--bind", str(lay.folder / rel), f"{lay.inside}/{rel}"] if outer else ["--tmpfs", f"{lay.inside}/{rel}"]
    return argv


def _program(lay: Layout, landlock: bool, stay: bool = True) -> list[str]:
    """What the sandbox runs: the start script, quiet, under Landlock's scopes when asked, and under STAY
    (`stay`: where the computer has python3), which itself stays outside those scopes."""
    prog = [*QUIET, f"{lay.inside}/{lay.script}"]
    if landlock:
        prog = [PYTHON, "-I", "-c", LANDLOCK, *prog]
    return [PYTHON, "-I", "-c", STAY, lay.inside, *prog] if stay else prog


def browser_argv(host: Host, lay: Layout, disp: Display, with_sound: bool, landlock: bool,
                 etc: dict[str, Path], pasta: str | None, fenced: bool = True, sync_fd: int | None = None,
                 gpu: tuple[str, ...] = (), stay: bool = True) -> list[str]:
    """Mullvad Browser's sandbox (or Tor Browser's when it is started by itself, which isn't done):
    one bubblewrap, in pasta's network namespace when `pasta` is its path (fenced off from the local
    network first, `fenced`), else on the computer's network. `etc`: identity_files' files. `sync_fd`:
    held open by bubblewrap for as long as the sandbox runs (the Wayland security context's pipe; under pasta,
    which passes its command nothing but stdin, stdout and stderr (tested), it must come as stdin: 0). `gpu`: the
    graphics card's device files (gpu()) when the user allowed it, else it draws in software. In the
    foreground, never --detach: bubblewrap, and pasta around it, end with their command, so the command is
    STAY around the start script (`stay`; without python3 the script alone, and a browser that restarts
    itself is then left without pasta's network)."""
    bwrap = _need(host, BWRAP)
    a = [bwrap, *namespaces(True), *system(host, etc=False), *etc_argv(host, etc, "own" if "resolv.conf" in etc else "host"),
         *proc_masks(str(etc["cmdline"].parent), bool(gpu), host), *_gpu_argv(gpu)]
    a += _folder(lay, outer=False, inside=False)
    a += ["--bind", str(lay.session), SESSION_IN, "--perms", "0700", "--dir", RUNTIME_IN]
    a += _desktop(disp, sound(host) if with_sound else None, inside=False)
    a += _env(host, disp, with_sound, dict(lay.env), gpu=bool(gpu))
    a += ["--sync-fd", str(sync_fd)] if sync_fd is not None else []
    a += ["--as-pid-1"] if stay else []                 # STAY reaps: bubblewrap's own process stays out of sight
    a += ["--chdir", f"{lay.inside}/{Path(lay.script).parent}", "--", *_program(lay, landlock, stay)]
    if not pasta:
        return a
    f = fence(host) if fenced else None
    if fenced and f is None:
        raise SandboxError("The local network can't be fenced off (iproute2's ip isn't installed), as the panel said "
                           "it would be: Mullvad Browser wasn't started. Open the panel again to see what changed.")
    return [pasta, *pasta_opts(host), "--", *(f or []), *a]


TOR_ENV = {"TOR_SKIP_LAUNCH": "1", "TOR_SOCKS_IPC_PATH": SOCKS_IN, "TOR_CONTROL_IPC_PATH": CONTROL_IN}


def tor_argv(host: Host, lay: Layout, tor_dir: Path, disp: Display, with_sound: bool, landlock: bool,
             etc: dict[str, Path], gate: str, sync_fd: int | None = None, gpu: tuple[str, ...] = ()) -> list[str]:
    """Tor Browser's two sandboxes: the outer one, on the computer's network, runs `gate`
    (tools/torgate.py's source) in the host's python3, which starts tor (in a sandbox of its own, inside the
    outer one) and the control-port filter, then the inner sandbox, with no network, around the browser. `tor_dir` (in the app's private
    folder) holds tor's sockets, its control cookie, the torrc with the bridges and the status. `etc`:
    identity_files' files: the outer sandbox has the computer's resolver (tor and its pluggable transports
    need it), the inner one none; the inner one, the innermost, has /proc's own files (proc_masks). `gpu`: the
    graphics card's device files when the user allowed it, in both (the inner one binds them from the outer's /dev).
    The inner sandbox's command is STAY, so the gate keeps tor for as long as a browser process runs, and it
    dies with the gate (--die-with-parent: its init too, once its command is over): a browser is never left
    running with tor gone."""
    import json
    bwrap = _need(host, BWRAP)
    snd = sound(host) if with_sound else None
    data = f"{lay.inside}/Browser/TorBrowser/Data/Tor"
    programs = f"{lay.inside}/Browser/TorBrowser/Tor"
    # tor and its pluggable transports in a sandbox of their own, inside the outer one (the review of 2026-10-17): the
    # outer one holds what the inner one binds from it, the display's socket and X cookie, sound's socket, the
    # browser's profile and Downloads, and sees the browser's processes, none of which tor needs; and a bridge's
    # program parses what the network sends it (Snowflake's: WebRTC from volunteers' proxies). In tor's own: the
    # system, the outer sandbox's /etc (the resolver, certificates), tor's programs read-only, its data and its
    # sockets' folder; a PID namespace of its own, so it no longer watches the gate by its PID
    # (__OwningControllerProcess): it dies with the gate (--die-with-parent), which stops it over its control port
    # first (torgate.halt), so that it saves its state.
    box = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
           "--unshare-cgroup-try", "--new-session", "--cap-drop", "ALL", *system(host, etc=False),
           "--ro-bind", "/etc", "/etc", "--ro-bind", programs, programs, "--bind", data, data,
           "--bind", TOR_DIR_IN, TOR_DIR_IN, "--chdir", f"{lay.inside}/Browser", "--"]
    tor = [*box, f"{programs}/tor", "--defaults-torrc", f"{data}/torrc-defaults",
           "-f", f"{TOR_DIR_IN}/torrc", "DataDirectory", data, "ClientOnionAuthDir", f"{data}/onion-auth",
           "GeoIPFile", f"{data}/geoip", "GeoIPv6File", f"{data}/geoip6",
           "+__ControlPort", f"unix:{TOR_DIR_IN}/tor-control",
           "+__SocksPort", f"unix:{SOCKS_IN} IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth",
           "CookieAuthentication", "1", "CookieAuthFile", f"{TOR_DIR_IN}/control_auth_cookie"]
    inner = [bwrap, "--die-with-parent", *namespaces(False), *system(host, etc=False),
             *etc_argv(host, etc, None, inner=True), *proc_masks(IDENTITY_IN, bool(gpu), host), *_gpu_argv(gpu)]
    inner += _folder(lay, outer=False, inside=True)
    inner += ["--bind", SESSION_IN, SESSION_IN, "--perms", "0700", "--dir", RUNTIME_IN,
              "--ro-bind", SOCKS_IN, SOCKS_IN, "--ro-bind", CONTROL_IN, CONTROL_IN]
    inner += _desktop(disp, snd, inside=True)
    inner += _env(host, disp, with_sound, TOR_ENV, gpu=bool(gpu))
    inner += ["--as-pid-1", "--chdir", f"{lay.inside}/{Path(lay.script).parent}", "--", *_program(lay, False)]
    config = {"landlock": landlock, "tor": tor, "cwd": f"{lay.inside}/Browser",
              "tor_env": {"HOME": HOME_IN, "PATH": "/usr/bin:/bin",
                          "LD_LIBRARY_PATH": f"{lay.inside}/Browser/TorBrowser/Tor"},
              "dir": TOR_DIR_IN, "upstream": f"{TOR_DIR_IN}/tor-control", "control": CONTROL_IN, "socks": SOCKS_IN,
              "cookie": f"{TOR_DIR_IN}/control_auth_cookie", "status": f"{TOR_DIR_IN}/status.json", "inner": inner}
    a = [bwrap, *namespaces(True), *system(host, etc=False), *etc_argv(host, etc, "host"), *_gpu_argv(gpu)]
    a += _folder(lay, outer=True, inside=False)
    a += ["--bind", str(lay.session), SESSION_IN, "--perms", "0700", "--dir", RUNTIME_IN,
          "--bind", str(tor_dir), TOR_DIR_IN, "--ro-bind", str(etc["cmdline"].parent), IDENTITY_IN]
    a += _desktop(disp, snd, inside=False)
    a += _env(host, disp, with_sound)
    a += ["--sync-fd", str(sync_fd)] if sync_fd is not None else []
    a += ["--chdir", f"{lay.inside}/Browser", "--", PYTHON, "-I", "-c", gate, json.dumps(config)]
    return a
