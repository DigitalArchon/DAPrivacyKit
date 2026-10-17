"""The context keys, computed once per scan before any check runs (docs/TECHNICAL.md, design rule 1).

Each key is a value plus the evidence it came from. A key that can't be determined (a
command is missing, a file needs root) is None, never a guess: severity modifiers that
depend on it are then not applied, and results say they are uncertain."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import blockdev, ini, network
from .catalogue import CONTEXT_KEYS
from .desktop import DesktopInfo, detect_desktop
from .host import Host, Unreadable
from .model import Evidence, Note


@dataclass
class ContextValue:
    key: str
    value: str | bool | None
    evidence: list[Evidence] = field(default_factory=list)
    note: str = ""            # how it was determined, or why it is unknown
    partial: bool = False     # some sources couldn't be read without root
    notes: list[Note] = field(default_factory=list)   # information for the user beyond the value

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "evidence": [e.to_dict() for e in self.evidence],
                "note": self.note, "partial": self.partial, "notes": [n.to_dict() for n in self.notes]}


@dataclass
class Context:
    values: dict[str, ContextValue]
    desktop: DesktopInfo
    devices: list[blockdev.Device] | None = None     # from lsblk, for checks that need it again
    listeners: list[network.Listener] | None = None  # from ss, likewise

    def __getitem__(self, key: str) -> str | bool | None:
        return self.values[key].value

    def vars(self) -> dict[str, Any]:
        """Values for `when` expressions."""
        return {k: v.value for k, v in self.values.items()}

    def to_dict(self) -> dict:
        return {"values": {k: v.to_dict() for k, v in self.values.items()}, "desktop": self.desktop.to_dict()}


def detect_context(host: Host) -> Context:
    devices, lsblk_error = None, ""
    try:
        devices = blockdev.read_devices(host)
    except blockdev.LsblkError as e:
        lsblk_error = str(e)

    values: dict[str, ContextValue] = {}

    def add(key: str, fn: Callable[[], ContextValue]):
        try:
            values[key] = fn()
        except Exception as e:  # noqa: BLE001 - one broken detector must not stop the scan
            values[key] = ContextValue(key, None, note=f"Detection failed: {type(e).__name__}: {e}")

    add("fde", lambda: detect_fde(devices, lsblk_error, host))
    add("virtualization", lambda: detect_virtualization(host))
    add("device", lambda: detect_device(host, values["virtualization"].value))
    add("multi_user", lambda: detect_multi_user(host))
    add("session", lambda: detect_session(host))
    add("hibernation", lambda: detect_hibernation(host))
    add("tpm_unlock_no_pin", lambda: detect_tpm_unlock_no_pin(host, devices, lsblk_error))
    add("autologin", lambda: detect_autologin(host))
    listeners: list[network.Listener] = []
    add("exposed_services", lambda: detect_exposed_services(host, listeners))
    add("vpn_active", lambda: detect_vpn_active(host))
    add("ipv6_global", lambda: detect_ipv6_global(host))
    assert set(values) == set(CONTEXT_KEYS)
    return Context(values, detect_desktop(host), devices, listeners if values["exposed_services"].value is not None else None)


# ------------------------------------------------------------------ fde

def detect_fde(devices: list[blockdev.Device] | None, lsblk_error: str = "", host: Host | None = None) -> ContextValue:
    """'none', 'home' (/ isn't encrypted, the home folder is), 'partial' or 'full'."""
    if devices is None:
        return ContextValue("fde", None, note=lsblk_error or "lsblk gave no devices")
    a = blockdev.assess_fde(devices)
    ev = []
    if a.root is not None:
        ev.append(Evidence.val("Root filesystem device", f"{a.root.name} ({a.root.fstype or 'unknown'})"))
    if a.value == "none" and host is not None:
        method, home_ev = home_encryption(host, devices)
        if method:
            return ContextValue("fde", "home", ev + home_ev,
                                f"/ is not encrypted; the home folder is ({HOME_ENCRYPTION[method]})")
    for mp in a.unencrypted:
        ev.append(Evidence.path("Not encrypted", mp))
    return ContextValue("fde", a.value, ev, a.reason)


# how a home folder can be encrypted on a disk that isn't, best first
HOME_ENCRYPTION = {
    "luks": "a LUKS-encrypted volume of its own: a /home partition, or a systemd-homed image",
    "fscrypt": "fscrypt, the filesystem's own per-folder encryption",
    "ecryptfs": "eCryptfs, a stacked filesystem that is no longer recommended",
}


def home_encryption(host: Host, devices: list[blockdev.Device] | None) -> tuple[str | None, list[Evidence]]:
    """How the user's home folder is encrypted, if it is: "luks" (on dm-crypt), "fscrypt" (ext4 or F2FS
    native encryption: lsattr shows E), "ecryptfs" (mounted over it at login), or None."""
    home = str(host.home)
    m = max((ln.split() for ln in (host.read_sys("/proc/mounts") or "").splitlines() if len(ln.split()) >= 3
             and (home == ln.split()[1].replace("\\040", " ") or home.startswith(ln.split()[1].rstrip("/") + "/"))),
            key=lambda f: len(f[1]), default=None)
    if m is not None and m[2] == "ecryptfs":
        return "ecryptfs", [Evidence.val("Home folder", "eCryptfs, mounted at login")]
    d = blockdev.holding(devices or [], home)
    if d is not None and d.encrypted:
        return "luks", [Evidence.val("Home folder", f"on encrypted {d.name}")]
    r = host.run("lsattr", "-d", home)
    flags = r.stdout.split()[0] if r.ok and r.stdout.split() else ""
    if "E" in flags:
        return "fscrypt", [Evidence.val("Home folder", "fscrypt (the filesystem's own encryption)")]
    return None, []


# ------------------------------------------------------------------ virtualization

# DMI vendor and product strings of common hypervisors, for when systemd-detect-virt is absent
VM_DMI = {"qemu": "QEMU/KVM", "kvm": "KVM", "vmware": "VMware", "virtualbox": "VirtualBox", "innotek": "VirtualBox",
          "xen": "Xen", "parallels": "Parallels", "bochs": "Bochs", "bhyve": "bhyve",
          "microsoft corporation virtual machine": "Hyper-V"}
# processes that connect the guest to the host, and what each lets the host do
GUEST_AGENTS = {
    "qemu-ga": "QEMU guest agent (the host can run commands and read and write files in this VM, if allowed)",
    "spice-vdagent": "SPICE agent (shared clipboard with the host)",
    "spice-vdagentd": "SPICE agent (shared clipboard with the host)",
    "VBoxService": "VirtualBox Guest Additions (shared folders; guest control lets the host run commands)",
    "VBoxClient": "VirtualBox Guest Additions (shared clipboard and drag and drop)",
    "vmtoolsd": "VMware Tools (guest operations let the host run commands and copy files)",
    "hv_kvp_daemon": "Hyper-V key-value exchange (the host can read system details)",
}
SHARED_FS = {"vboxsf", "9p", "virtiofs", "fuse.vmhgfs-fuse", "vmhgfs"}


def detect_virtualization(host: Host) -> ContextValue:
    r = host.run("systemd-detect-virt", "--container")
    if r.ok and r.stdout.strip() not in ("", "none"):
        return _container(r.stdout.strip())
    if not r.missing:
        r = host.run("systemd-detect-virt", "--vm")
        tech = r.stdout.strip()
        if r.ok and tech not in ("", "none"):
            return _vm(host, tech)
        if tech == "none":
            return ContextValue("virtualization", "none", [Evidence.val("systemd-detect-virt", "none")],
                                "Running directly on hardware")
    # no systemd-detect-virt: look for the signs ourselves
    for marker in ("/run/.containerenv", "/.dockerenv", "/run/systemd/container"):
        if host.sys_path(marker).exists():
            return _container(marker)
    if "microsoft" in (host.read_sys("/proc/version") or "").lower():
        return _vm(host, "wsl")
    dmi = " ".join((host.read_sys(f"/sys/class/dmi/id/{f}") or "").strip().lower()
                   for f in ("sys_vendor", "product_name"))
    for needle, name in VM_DMI.items():
        if needle in dmi:
            return _vm(host, name)
    if re.search(r"^flags\s*:.*\bhypervisor\b", host.read_sys("/proc/cpuinfo") or "", re.M):
        return _vm(host, "unknown hypervisor")
    return ContextValue("virtualization", "none", [Evidence.note("No hypervisor or container found")],
                        "No sign of a virtual machine or container")


def _container(tech: str) -> ContextValue:
    return ContextValue("virtualization", "container", [Evidence.val("Container", tech)], "Running inside a container",
                        notes=[Note("limitation", "The scan sees the container, not the computer",
             "Disk encryption, firmware, the kernel's settings, other users and most system services belong to the "
             "host and can't be checked from in here. Run the scan on the host for those.")])


def _vm(host: Host, tech: str) -> ContextValue:
    ev = [Evidence.val("Hypervisor", tech)]
    agents = _guest_agents(host)
    shared = _shared_folders(host)
    ev += [Evidence.val("Guest agent running", a) for a in agents]
    ev += [Evidence.path("Folder shared with the host", m) for m in shared]

    notes = [
        Note("risk", "The host can see everything in this VM",
             "Whoever controls the host (its administrator, or the cloud provider) can read this VM's memory and "
             "disks while it runs, including disk encryption keys and unlocked passwords. Encryption inside the VM "
             "protects its disk image when the VM is off and the image is copied; it doesn't protect against the host."),
        Note("risk", "Saved states and snapshots contain memory",
             "Suspending (saving) a VM, or taking a snapshot that includes its running state, writes all of its memory "
             "to files on the host: disk encryption keys, open documents and unlocked secrets, like hibernation does. "
             "Those files are only as safe as the host's own disk.",
             ("enc.hibernate_unencrypted",)),
    ]
    if agents or shared:
        what = list(dict.fromkeys(GUEST_AGENTS[a] for a in agents)) + ([f"shared folders ({', '.join(shared)})"] if shared else [])
        notes.append(Note("risk", "Channels between this VM and the host",
                          "These let data cross between the VM and the host: " + "; ".join(what) + ". "
                          "Turn off what you don't use in the VM's settings on the host."))
    notes.append(Note("limitation", "What a scan inside a VM can't see",
                      "The host's disk encryption, its backups and snapshots of this VM, and its own settings are "
                      "invisible from in here. Secure Boot, the TPM and Thunderbolt are virtual devices: their "
                      "protection depends on how the host provides them. Whether the host is a laptop is unknown.",
                      ("enc.boot_no_secureboot", "enc.tpm_no_pin", "kern.dma")))
    return ContextValue("virtualization", "vm", ev, "Running in a virtual machine", notes=notes)


def _guest_agents(host: Host) -> list[str]:
    found = set()
    try:
        procs = [p for p in host.sys_path("/proc").iterdir() if p.name.isdigit()]
    except OSError:
        return []
    for p in procs:
        try:
            name = (p / "comm").read_text().strip()
        except OSError:
            continue
        if name in GUEST_AGENTS:
            found.add(name)
    return sorted(found)


def _shared_folders(host: Host) -> list[str]:
    out = []
    for line in (host.read_sys("/proc/mounts") or "").splitlines():
        f = line.split()
        if len(f) >= 3 and f[2] in SHARED_FS:
            out.append(f[1].replace("\\040", " "))
    return out[:10]


# ------------------------------------------------------------------ device

# SMBIOS chassis types (DMTF DSP0134, 7.4.1)
LAPTOP_CHASSIS = frozenset({8, 9, 10, 11, 14, 30, 31, 32})
DESKTOP_CHASSIS = frozenset({3, 4, 5, 6, 7, 13, 15, 16, 17, 23, 24, 25, 28, 33, 34, 35, 36})
LAPTOP_HOSTNAMECTL = frozenset({"laptop", "convertible", "tablet", "handset", "watch"})
DESKTOP_HOSTNAMECTL = frozenset({"desktop", "server", "vm", "container", "embedded"})


def detect_device(host: Host, virtualization: str | None = None) -> ContextValue:
    if virtualization == "vm":
        # the virtual chassis says nothing about the computer the VM runs on
        return ContextValue("device", None, [Evidence.note("Running in a virtual machine")],
                            "Inside a VM the host computer's form factor can't be seen, so laptop-level "
                            "severities apply. If the host is a desktop, some findings matter less.")
    raw = (host.read_sys("/sys/class/dmi/id/chassis_type") or "").strip()
    if raw.isdigit():
        n = int(raw)
        if n in LAPTOP_CHASSIS:
            return ContextValue("device", "laptop", [Evidence.val("SMBIOS chassis type", n)], "From the firmware's chassis type")
        if n in DESKTOP_CHASSIS:
            return ContextValue("device", "desktop", [Evidence.val("SMBIOS chassis type", n)], "From the firmware's chassis type")
    r = host.run("hostnamectl", "chassis")
    chassis = r.stdout.strip().lower() if r.ok else ""
    if chassis in LAPTOP_HOSTNAMECTL:
        return ContextValue("device", "laptop", [Evidence.val("hostnamectl chassis", chassis)], "From systemd's chassis type")
    if chassis in DESKTOP_HOSTNAMECTL - {"vm", "container"}:
        return ContextValue("device", "desktop", [Evidence.val("hostnamectl chassis", chassis)],
                            "From systemd's chassis type")
    if _has_system_battery(host):
        return ContextValue("device", "laptop", [Evidence.note("A system battery is present")], "From the battery")
    return ContextValue("device", None, [Evidence.val("SMBIOS chassis type", raw or "unavailable")],
                        "The chassis type doesn't say whether this is a laptop")


def _has_system_battery(host: Host) -> bool:
    base = host.sys_path("/sys/class/power_supply")
    try:
        supplies = list(base.iterdir())
    except OSError:
        return False
    for s in supplies:
        kind = (host.read_file(s / "type") or "").strip()
        scope = (host.read_file(s / "scope") or "System").strip()  # "Device": a mouse or headset battery
        if kind == "Battery" and scope == "System":
            return True
    return False


# ------------------------------------------------------------------ multi_user

NO_LOGIN = re.compile(r"(?:^|/)(?:nologin|false|sync|shutdown|halt)$")


def detect_multi_user(host: Host) -> ContextValue:
    r = host.run("getent", "passwd")
    source = "getent passwd"
    text = r.stdout if r.ok else None
    if text is None:
        text, source = host.read_sys("/etc/passwd"), "/etc/passwd"
    if text is None:
        return ContextValue("multi_user", None, note="Neither getent nor /etc/passwd is available")
    uid_min, uid_max = _uid_range(host)
    humans = []
    for line in text.splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[2].isdigit():
            continue
        uid, shell = int(f[2]), f[6].strip()
        if uid_min <= uid <= uid_max and uid != 65534 and not NO_LOGIN.search(shell):
            humans.append(f[0])
    humans = sorted(set(humans))
    ev = [Evidence.count("Accounts with a login shell", len(humans))]
    if humans:
        ev.append(Evidence.val("Accounts", ", ".join(humans)[:200]))
    return ContextValue("multi_user", len(humans) > 1, ev,
                        f"User accounts (UID {uid_min}-{uid_max}) with a login shell, from {source}")


def _uid_range(host: Host) -> tuple[int, int]:
    lo, hi = 1000, 60000
    try:
        text = host.read_sys("/etc/login.defs") or ""
    except Unreadable:
        text = ""
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 2 and f[1].isdigit():
            if f[0] == "UID_MIN":
                lo = int(f[1])
            elif f[0] == "UID_MAX":
                hi = int(f[1])
    return lo, hi


# ------------------------------------------------------------------ session

def detect_session(host: Host) -> ContextValue:
    env = host.environ
    t = env.get("XDG_SESSION_TYPE", "").strip().lower()
    if t in ("wayland", "x11"):
        return ContextValue("session", t, [Evidence.val("XDG_SESSION_TYPE", t)], "From the session type")
    if env.get("WAYLAND_DISPLAY"):
        return ContextValue("session", "wayland", [Evidence.val("WAYLAND_DISPLAY", "set")], "From the display variables")
    if env.get("DISPLAY"):
        return ContextValue("session", "x11", [Evidence.val("DISPLAY", "set")], "From the display variables")
    return ContextValue("session", None, [Evidence.val("XDG_SESSION_TYPE", t or "unset")], "No graphical session found")


# ------------------------------------------------------------------ hibernation

_RESUME = re.compile(r"(?:^|\s)resume=(\S+)")
# systemd's configuration folders, highest precedence first (systemd.syntax(7): a drop-in of the same name in an earlier
# one hides the later ones'; the main file is the first one found)
SYSTEMD_CONF_DIRS = ("/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd")


def systemd_config(host: Host, name: str) -> tuple[dict, list[str]]:
    """A systemd configuration file (sleep.conf, journald.conf, coredump.conf...) as systemd reads it: the first of
    /etc, /run, /usr/local/lib and /usr/lib that has NAME, then every NAME.d/*.conf in file name order whatever its
    folder (one of the same name in /etc hides /run's, which hides /usr/lib's), later ones winning. With the files that
    were read, in that order. Unreadable files are left out."""
    def text(path: str) -> str | None:
        try:
            return host.read_sys(path)
        except Unreadable:
            return None
    used, layers = [], []
    main = next((f"{d}/{name}" for d in SYSTEMD_CONF_DIRS if host.sys_path(f"{d}/{name}").is_file()), None)
    dropins: dict[str, str] = {}
    for d in reversed(SYSTEMD_CONF_DIRS):                       # later (higher precedence) folders replace
        try:
            found = sorted(p.name for p in host.sys_path(f"{d}/{name}.d").iterdir() if p.name.endswith(".conf"))
        except OSError:
            found = []
        for f in found:
            dropins[f] = f"{d}/{name}.d/{f}"
    for path in ([main] if main else []) + [dropins[f] for f in sorted(dropins)]:
        t = text(path)
        if t is not None:
            layers.append(ini.parse(t))
            used.append(path)
    return ini.merge(*layers), used


def _sd_bool(value: str | None) -> bool | None:
    """systemd's booleans (parse_boolean): yes/no, true/false, on/off, 1/0, y/n, t/f."""
    v = (value or "").strip().lower()
    return True if v in ("1", "yes", "y", "true", "t", "on") else False if v in ("0", "no", "n", "false", "f", "off") \
        else None


# systemd's sleep modes that write memory to the disk, by their sleep.conf switch and logind's method
HIBERNATING_MODES = (("AllowHibernation", "CanHibernate", "hibernate"),
                     ("AllowSuspendThenHibernate", "CanSuspendThenHibernate", "suspend-then-hibernate"),
                     ("AllowHybridSleep", "CanHybridSleep", "hybrid sleep"))


def sleep_modes(host: Host) -> tuple[list[str], list[str]]:
    """Which of hibernate, suspend-then-hibernate and hybrid sleep systemd's sleep.conf (and its drop-ins) allows, as
    logind's methods (CanHibernate...); with the files that turned the others off. sleep.conf(5): every mode is allowed
    unless switched off; AllowHibernation=no or AllowSuspend=no also turns the other two off, unless they are set to
    yes themselves."""
    cfg, used = systemd_config(host, "sleep.conf")
    get = lambda k: _sd_bool(ini.get(cfg, "Sleep", k))       # noqa: E731
    both = get("AllowHibernation") is not False and get("AllowSuspend") is not False
    allowed = {"AllowHibernation": get("AllowHibernation") is not False}
    for key in ("AllowSuspendThenHibernate", "AllowHybridSleep"):
        allowed[key] = get(key) if get(key) is not None else both
    return [method for key, method, _ in HIBERNATING_MODES if allowed[key]], used


LOGIND = ("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager")


def logind_can(host: Host, method: str) -> str | None:
    """logind's answer to CanHibernate (or CanSuspendThenHibernate, CanHybridSleep) for this user: "yes", "challenge"
    (with an administrator's password), "no" (the system's policy refuses it: Ubuntu's com.ubuntu.desktop.rules does for
    hibernating, tested on 26.04), "na" (not available: sleep.conf, not enough swap, no resume device). Asked on the
    system bus with busctl, gdbus or dbus-send, which only reads. None when it can't be asked."""
    dest, path, iface = LOGIND
    for argv in (("busctl", "--system", "call", dest, path, iface, method),
                 ("gdbus", "call", "--system", "--dest", dest, "--object-path", path, "--method", f"{iface}.{method}"),
                 ("dbus-send", "--system", "--print-reply", f"--dest={dest}", path, f"{iface}.{method}")):
        if not host.runner.which(argv[0]):
            continue
        r = host.run(*argv, timeout=10)
        m = re.search(r"""["'](yes|no|na|challenge)["']""", r.stdout) if r.ok else None
        if m:
            return m.group(1)
    return None


def detect_hibernation(host: Host) -> ContextValue:
    """Hibernation is possible: the kernel supports it, it isn't locked out, systemd's sleep settings allow it, a resume
    device is configured, disk-backed swap can hold the image, and logind lets this user do it (Ubuntu's policy refuses
    it: then it is one step away, as an administrator can still hibernate). When logind can't be asked, a machine that
    could hibernate as far as the rest goes is unknown, never a guess.
    VERIFY: the size test uses /sys/power/image_size (the kernel's target image size, 2/5 of
    RAM by default) as the threshold; confirm against real hibernation attempts."""
    state = host.read_sys("/sys/power/state")
    if state is None:
        return ContextValue("hibernation", None, note="/sys/power/state is not available")
    ev = []
    if "disk" not in state.split():
        return ContextValue("hibernation", False, [Evidence.val("/sys/power/state", state.strip())],
                            "The kernel doesn't support hibernation")
    disk = (host.read_sys("/sys/power/disk") or "").strip()
    if "[disabled]" in disk:
        return ContextValue("hibernation", False, [Evidence.val("/sys/power/disk", disk)],
                            "Hibernation is disabled (kernel lockdown, usually Secure Boot)")

    swap_bytes = sum(size for name, kind, size in read_swaps(host) if not _is_zram(name))
    ev.append(Evidence.val("Disk-backed swap", _gib(swap_bytes)))
    if swap_bytes == 0:
        return ContextValue("hibernation", False, ev, "No disk-backed swap to write the image to")

    methods, sleep_files = sleep_modes(host)
    if not methods:
        where = ", ".join(f for f in sleep_files if "sleep.conf" in f)
        return ContextValue("hibernation", False, ev + [Evidence.val(
            "systemd's sleep settings", "hibernate, suspend-then-hibernate and hybrid sleep turned off"
            + (f" ({where})" if where else ""))], "Hibernation is turned off in systemd's sleep settings")
    own = _hibernation_by_config(host, ev, swap_bytes)
    answers = {m: logind_can(host, m) for m in methods}
    if any(a is None for a in answers.values()):
        if own.value is True:
            return ContextValue("hibernation", None, own.evidence,
                                "Couldn't ask the system's login manager (logind) whether hibernating is allowed "
                                "here", notes=[Note("limitation", "Whether this computer may hibernate couldn't be told",
                                                    "The kernel, the swap and the resume settings allow it, but the "
                                                    "login manager (logind) that decides who may couldn't be asked "
                                                    "(busctl, gdbus or dbus-send on the system bus).",
                                                    ("enc.hibernate_unencrypted",))])
        return own
    ev = own.evidence + [Evidence.val(f"logind {m}", a) for m, a in answers.items()]
    if any(a in ("yes", "challenge") for a in answers.values()):
        # logind knows best what systemctl hibernate would do (its own resume and swap checks)
        how = own.note if own.value is True else "The system's login manager (logind) says it is available"
        return ContextValue("hibernation", True, ev, how + (", with an administrator's password"
                                                             if "yes" not in answers.values() else ""))
    if "no" in answers.values():
        return ContextValue("hibernation", False, ev, "The system's policy doesn't let users hibernate (logind says no)",
                            notes=[_one_step_away(
                                "The kernel, the swap and the resume settings allow hibernating, but the system's policy "
                                "refuses it to users (Ubuntu's does). An administrator can still hibernate the computer "
                                "(sudo systemctl hibernate), and a change of policy would allow it: then")]
                            if own.value is True else own.notes)
    if own.value is True or own.value is None:
        return ContextValue("hibernation", False, ev, "The system's login manager (logind) says hibernation isn't "
                            "available here")
    return ContextValue("hibernation", False, ev, own.note, notes=own.notes)


def _hibernation_by_config(host: Host, ev: list[Evidence], swap_bytes: int) -> ContextValue:
    """Whether the resume settings and the size of the swap allow hibernating (logind not asked)."""
    ev = list(ev)

    cmdline = host.read_sys("/proc/cmdline") or ""
    resume_dev = (host.read_sys("/sys/power/resume") or "").strip()
    m = _RESUME.search(cmdline)
    configured, how = False, ""
    if m:
        configured, how = True, "resume= on the kernel command line"
        ev.append(Evidence.val("Kernel resume=", m.group(1)[:120]))
    elif resume_dev and resume_dev != "0:0":
        configured, how = True, "a resume device is set"
        ev.append(Evidence.val("/sys/power/resume", resume_dev))
    elif _systemd_version(host) >= 255 and host.sys_path("/sys/firmware/efi").is_dir():
        # systemd 255+ finds the resume swap itself through the HibernateLocation EFI variable
        configured, how = True, "systemd 255+ on EFI can resume without resume="
        ev.append(Evidence.note("systemd 255+ on an EFI system"))
    image = _int(host.read_sys("/sys/power/image_size"))
    if image is None:
        mem = _meminfo_bytes(host)
        image = mem * 2 // 5 if mem else None
    if image is not None:
        ev.append(Evidence.val("Hibernation image size", _gib(image)))

    if not configured:
        notes = []
        if image is not None and swap_bytes >= image:
            notes.append(_one_step_away(
                f"Swap ({_gib(swap_bytes)}) is large enough to hold a hibernation image, but no resume device "
                "is configured, so hibernation isn't set up. If it is set up later"))
        return ContextValue("hibernation", False, ev, "No resume device is configured", notes=notes)
    if image is None:
        return ContextValue("hibernation", None, ev, "Couldn't tell how big the hibernation image would be")
    if swap_bytes < image:
        return ContextValue("hibernation", False, ev, f"Resume is configured ({how}) but swap is smaller than the image",
                            notes=[_one_step_away(
                                f"Hibernation is configured ({how}), but swap ({_gib(swap_bytes)}) is smaller than "
                                f"the hibernation image ({_gib(image)}), so hibernating would fail today. If swap "
                                f"grows to {_gib(image)} or more")])
    return ContextValue("hibernation", True, ev, f"Resume is configured ({how}) and swap is large enough")


def _one_step_away(condition: str) -> Note:
    return Note("risk", "Hibernation is one step away",
                f"{condition}, each hibernation writes a copy of all memory to swap: disk encryption keys, open "
                "documents and unlocked passwords. Make sure swap is on an encrypted device before that happens.",
                ("enc.hibernate_unencrypted", "enc.swap_unencrypted"))


def read_swaps(host: Host) -> list[tuple[str, str, int]]:
    """(name, type, bytes) from /proc/swaps."""
    out = []
    for line in (host.read_sys("/proc/swaps") or "").splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[2].isdigit():
            out.append((f[0].replace("\\040", " "), f[1], int(f[2]) * 1024))
    return out


def _is_zram(name: str) -> bool:
    return name.startswith("/dev/zram")


def _systemd_version(host: Host) -> int:
    r = host.run("systemctl", "--version")
    m = re.match(r"systemd (\d+)", r.stdout) if r.ok else None
    return int(m.group(1)) if m else 0


def _meminfo_bytes(host: Host) -> int | None:
    m = re.search(r"^MemTotal:\s+(\d+) kB", host.read_sys("/proc/meminfo") or "", re.M)
    return int(m.group(1)) * 1024 if m else None


def _int(text: str | None) -> int | None:
    try:
        return int((text or "").strip())
    except ValueError:
        return None


def _gib(n: int) -> str:
    return f"{n / 2**30:.1f} GiB"


# ------------------------------------------------------------------ tpm_unlock_no_pin

def detect_tpm_unlock_no_pin(host: Host, devices: list[blockdev.Device] | None, lsblk_error: str = "") -> ContextValue:
    """Whether an encrypted volume unlocks from the TPM alone. TPM tokens (systemd-cryptenroll)
    and Clevis bindings live in the LUKS header, which only root can read: without the
    privileged helper this is unknown on any machine with encrypted volumes."""
    key = "tpm_unlock_no_pin"
    if devices is None:
        return ContextValue(key, None, note=lsblk_error or "lsblk gave no devices")
    luks = blockdev.luks_devices(devices)
    if not luks:
        return ContextValue(key, False, [Evidence.note("No open encrypted volumes")], "No encrypted volumes, so no TPM unlock")

    ev, partial = [], False
    try:
        crypttab = host.read_sys("/etc/crypttab")
    except Unreadable:
        crypttab, partial = None, True
        ev.append(Evidence.path("Needs administrator access", "/etc/crypttab"))
    if crypttab is not None:
        tpm = [ln.split()[0] for ln in crypttab.splitlines()
               if ln.strip() and not ln.lstrip().startswith("#") and "tpm2-device=" in ln]
        ev.append(Evidence.count("Volumes with tpm2-device= in /etc/crypttab", len(tpm)))

    if host.privileged is None:
        return ContextValue(key, None, ev, "Needs administrator access to read the LUKS headers, where TPM unlock "
                            "and PINs are recorded", partial, notes=[Note(
                                "limitation", "Scan with administrator access to check TPM unlock",
                                "Whether this disk unlocks from the TPM alone, with no PIN, is recorded in the LUKS "
                                "header, which only an administrator can read. Until then, findings that depend on it "
                                "(such as automatic login) show their lower severity.",
                                ("enc.tpm_no_pin", "auth.autologin"))])

    from .privileged import HelperError

    no_pin, unknown = [], []
    for dev in luks:
        try:
            verdict = _tpm_without_pin(host, dev.path)
        except HelperError as e:
            unknown.append(dev.name)
            ev.append(Evidence.val(f"Couldn't read the LUKS header of {dev.name}", str(e)[:120]))
            continue
        if verdict:
            no_pin.append(dev.name)
            ev.append(Evidence.val("Unlocks from the TPM without a PIN", f"{dev.name} ({verdict})"))
    ev.append(Evidence.count("Encrypted volumes checked", len(luks) - len(unknown)))
    if no_pin:
        return ContextValue(key, True, ev, "From the LUKS headers (read with administrator access)")
    if unknown:
        return ContextValue(key, None, ev, "Some LUKS headers couldn't be read", True)
    return ContextValue(key, False, ev, "No volume unlocks from the TPM alone (from the LUKS headers)")


def _tpm_without_pin(host: Host, device: str) -> str | None:
    """How `device` unlocks from the TPM with no PIN, or None if it doesn't."""
    dump = host.privileged.luks_dump(device)
    for token in dump["tokens"]:
        # tpm2-pin is printed since systemd 251; older tokens could not have a PIN
        if token["type"] == "systemd-tpm2" and not token.get("tpm2_pin"):
            return f"systemd-tpm2 token {token['id']}"
    if any(t["type"] == "clevis" for t in dump["tokens"]):
        from .privileged import HelperError

        try:
            bindings = host.privileged.clevis_list(device)
        except HelperError:
            return None
        for b in bindings:
            # Clevis has no TPM PIN; an sss policy with a TPM pin may still need the other pins
            if b["pin"] == "tpm2" or (b["pin"] == "sss" and '"tpm2"' in b["config"] and '"t":1' in b["config"].replace(" ", "")):
                return f"Clevis {b['pin']} binding in keyslot {b['slot']}"
    return None


# ------------------------------------------------------------------ autologin

DM_UNITS = {"gdm": "gdm", "gdm3": "gdm", "sddm": "sddm", "plasmalogin": "plasmalogin", "lightdm": "lightdm",
            "greetd": "greetd", "lxdm": "lxdm"}


def active_display_manager(host: Host) -> str | None:
    link = host.sys_path("/etc/systemd/system/display-manager.service")
    try:
        target = link.readlink()
    except OSError:
        return None
    return DM_UNITS.get(target.name.removesuffix(".service"), target.name.removesuffix(".service"))


class _Reader:
    """Reads config files for one detection, remembering which needed root."""

    def __init__(self, host: Host):
        self.host = host
        self.unreadable: list[str] = []

    def text(self, path: str | Path) -> str | None:
        try:
            return self.host.read_sys(path)
        except Unreadable:
            self.unreadable.append(str(path))
            return None

    def glob(self, directory: str, pattern: str) -> list[str]:
        d = self.host.sys_path(directory)
        try:
            return sorted(str(Path(directory) / p.name) for p in d.glob(pattern) if p.is_file())
        except OSError:
            return []

    def layered(self, paths: list[str]) -> tuple[dict, list[str]]:
        layers, used = [], []
        for p in paths:
            t = self.text(p)
            if t is not None:
                layers.append(ini.parse(t))
                used.append(p)
        return ini.merge(*layers), used


def _gdm(r: _Reader) -> list[Evidence]:
    ev = []
    for p in ("/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf", "/etc/gdm/custom.conf"):
        t = r.text(p)
        if t is None:
            continue
        cfg = ini.parse(t)
        for key in ("AutomaticLoginEnable", "TimedLoginEnable"):
            if ini.truthy(ini.get(cfg, "daemon", key)):
                user = ini.get(cfg, "daemon", "AutomaticLogin" if key.startswith("Automatic") else "TimedLogin")
                ev.append(Evidence.val(f"GDM {key} ({p})", user or "enabled"))
    return ev


def _sddm(r: _Reader) -> list[Evidence]:
    paths = (r.glob("/usr/lib/sddm/sddm.conf.d", "*.conf") + r.glob("/etc/sddm.conf.d", "*.conf") + ["/etc/sddm.conf"])
    cfg, _ = r.layered(paths)
    user = ini.get(cfg, "Autologin", "User")
    return [Evidence.val("SDDM [Autologin] User", user)] if user else []


def _plasmalogin(r: _Reader) -> list[Evidence]:
    """Plasma Login Manager (KDE's successor to SDDM, a fork of it): SDDM's [Autologin] User=, in its own files,
    read in SDDM's order (the packaged defaults, the drop-ins, then the main file)."""
    paths = (["/usr/lib/plasmalogin/defaults.conf"] + r.glob("/usr/lib/plasmalogin/plasmalogin.conf.d", "*.conf")
             + r.glob("/etc/plasmalogin.conf.d", "*.conf") + ["/etc/plasmalogin.conf"])
    cfg, _ = r.layered(paths)
    user = ini.get(cfg, "Autologin", "User")
    return [Evidence.val("Plasma Login [Autologin] User", user)] if user else []


def _lightdm(r: _Reader) -> list[Evidence]:
    paths = (r.glob("/usr/share/lightdm/lightdm.conf.d", "*.conf") + r.glob("/etc/lightdm/lightdm.conf.d", "*.conf")
             + ["/etc/lightdm/lightdm.conf"])
    cfg, _ = r.layered(paths)
    ev = []
    for group, keys in cfg.items():
        if group and group[0].startswith("Seat") and keys.get("autologin-user"):
            ev.append(Evidence.val(f"LightDM [{group[0]}] autologin-user", keys["autologin-user"]))
        if group and group[0].startswith("Seat") and ini.truthy(keys.get("autologin-guest")):
            ev.append(Evidence.val(f"LightDM [{group[0]}] autologin-guest", keys["autologin-guest"]))
    return ev


def _greetd(r: _Reader) -> list[Evidence]:
    t = r.text("/etc/greetd/config.toml")
    if not t:
        return []
    try:
        cfg = tomllib.loads(t)
    except tomllib.TOMLDecodeError:
        return [Evidence.note("/etc/greetd/config.toml could not be parsed")]
    session = cfg.get("initial_session")
    if isinstance(session, dict):
        return [Evidence.val("greetd [initial_session] user", str(session.get("user", "set")))]
    return []


def _lxdm(r: _Reader) -> list[Evidence]:
    t = r.text("/etc/lxdm/lxdm.conf")
    user = ini.get(ini.parse(t), "base", "autologin") if t else None
    return [Evidence.val("LXDM autologin", user)] if user else []


def _getty(r: _Reader) -> list[Evidence]:
    ev = []
    for unit in ("getty@*.service.d", "autovt@*.service.d", "serial-getty@*.service.d"):
        base = r.host.sys_path("/etc/systemd/system")
        try:
            dirs = sorted(base.glob(unit))
        except OSError:
            dirs = []
        for d in dirs:
            for conf in sorted(d.glob("*.conf")):
                t = r.text(Path("/etc/systemd/system") / d.name / conf.name) or ""
                for line in t.splitlines():
                    if line.strip().startswith("ExecStart=") and re.search(r"\s(--autologin|-a)(\s|=)", line + " "):
                        ev.append(Evidence.path("Console autologin", f"/etc/systemd/system/{d.name}/{conf.name}"))
    return ev


AUTOLOGIN_SOURCES: dict[str, Callable[[_Reader], list[Evidence]]] = {
    "gdm": _gdm, "sddm": _sddm, "plasmalogin": _plasmalogin, "lightdm": _lightdm, "greetd": _greetd, "lxdm": _lxdm,
}


def detect_autologin(host: Host) -> ContextValue:
    r = _Reader(host)
    dm = active_display_manager(host)
    ev: list[Evidence] = []
    if dm in AUTOLOGIN_SOURCES:
        ev.append(Evidence.val("Display manager", dm))
        found = AUTOLOGIN_SOURCES[dm](r)
        note = f"From {dm}'s configuration and console getty overrides"
    else:
        # unknown or no display manager unit: look at every one we know
        if dm:
            ev.append(Evidence.val("Display manager", dm))
        found = [e for fn in AUTOLOGIN_SOURCES.values() for e in fn(r)]
        note = "From every known display manager's configuration and console getty overrides"
    found += _getty(r)
    ev += found
    for p in r.unreadable:
        ev.append(Evidence.path("Needs administrator access", p))
    if found:
        return ContextValue("autologin", True, ev, note, bool(r.unreadable))
    if r.unreadable:
        return ContextValue("autologin", None, ev, "Some display manager files need administrator access", True)
    return ContextValue("autologin", False, ev, note)


# ------------------------------------------------------------------ exposed_services

def detect_exposed_services(host: Host, listeners: list | None = None) -> ContextValue:
    """`listeners`, if given, is filled with every listening socket ss reported."""
    r = host.run(*network.SS_ARGS)
    if r.missing:
        return ContextValue("exposed_services", None, note="ss (iproute2) is not installed")
    if not r.ok:
        return ContextValue("exposed_services", None, note=f"ss failed: {r.stderr.strip()[:200]}")
    parsed = network.parse_ss(r.stdout)
    if listeners is not None:
        listeners[:] = parsed
    found = network.exposed(parsed, network.ephemeral_range(host))
    ev = [Evidence.count("Services listening on all interfaces", len(found))]
    ev += [Evidence.val("Listening", s.label()) for s in found[:20]]
    notes = []
    if any(s.port == 5355 for s in found):
        notes.append(Note(
            "risk", "LLMNR answers name queries from any network",
            "systemd-resolved listens for LLMNR (Link-Local Multicast Name Resolution) on port 5355 on every network "
            "this machine joins, a questionable default on Fedora and some other distributions. Anyone on the same "
            "network can learn the machine's name, and on networks with Windows machines LLMNR is a well-known "
            "target for name-spoofing attacks. mDNS covers the same need. It can be turned off with LLMNR=no in a "
            "drop-in under /etc/systemd/resolved.conf.d/.",
            ("net.hostname_broadcast", "net.exposed_services")))
    return ContextValue("exposed_services", bool(found), ev,
                        "Sockets bound to all interfaces (DHCP, mDNS and ephemeral UDP ports aside)", notes=notes)


# ------------------------------------------------------------------ vpn_active, ipv6_global

def detect_vpn_active(host: Host) -> ContextValue:
    tunnels = network.vpn_links(host)
    if not tunnels:
        return ContextValue("vpn_active", False, [], "No WireGuard or tun interface is up")
    carrying = network.carrying_vpn_links(host, tunnels)
    ev = [Evidence.val("VPN interfaces", ", ".join(tunnels)),
          Evidence.val("Carrying internet traffic", ", ".join(carrying) or "none")]
    nm = host.run("nmcli", "-t", "-f", "TYPE", "connection", "show", "--active")
    if nm.ok:
        kinds = [t for t in nm.stdout.split() if t in ("vpn", "wireguard")]
        if kinds:
            ev.append(Evidence.count("VPN connections active in NetworkManager", len(kinds)))
    if carrying:
        return ContextValue("vpn_active", True, ev, "A VPN tunnel carries this machine's internet traffic")
    notes = [Note("info", "A tunnel is up but carries only some traffic",
                  "The tunnels listed carry traffic for some networks only (a split tunnel, or a mesh network such as "
                  "Tailscale or ZeroTier without an exit node). Websites see this machine's own internet connection, "
                  "so the checks for VPN leaks treat it as having no VPN.")]
    return ContextValue("vpn_active", False, ev, "A tunnel is up, but internet traffic doesn't go through it", notes=notes)


def detect_ipv6_global(host: Host) -> ContextValue:
    addrs = network.global_ipv6(host)
    if host.read_sys("/proc/net/if_inet6") is None:
        return ContextValue("ipv6_global", False, [], "IPv6 is off")
    # a VPN's address inside its tunnel (Proton gives one) is shared by its users and reached only through the
    # provider, which doesn't pass incoming connections on unless it forwards ports
    tunnels = set(network.vpn_links(host)) & set(addrs)
    addrs = {k: v for k, v in addrs.items() if k not in tunnels}
    if not addrs:
        ev = [Evidence.val("VPN interfaces with an IPv6 address", ", ".join(sorted(tunnels)))] if tunnels else []
        return ContextValue("ipv6_global", False, ev, "No internet-routable IPv6 address" +
                            (" outside the VPN tunnel" if tunnels else ""))
    notes = [Note("info", "This machine has a public IPv6 address",
                  "Unlike IPv4 behind a home router, a public IPv6 address can usually be reached from the internet "
                  "directly, unless the router's own firewall blocks incoming connections. The host firewall is "
                  "what's left between your services and the internet.", ("net.exposed_services", "net.firewall_off"))]
    return ContextValue("ipv6_global", True, [Evidence.val("Interfaces with a public IPv6 address",
                                                           ", ".join(sorted(addrs)))],
                        "An internet-routable IPv6 address is assigned", notes=notes)
