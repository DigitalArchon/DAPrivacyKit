"""Kernel and physical attack surface (kern.*)."""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import json
import re
import time
from dataclasses import dataclass

from .. import ini
from ..host import Unreadable
from ..model import Evidence, Note, Outcome, Status
from . import Check, Scan, register
from ._util import absent, children, failed, installed, mounts, passed, read_text, unknown, warned


# The packages the running system's core is made of: the kernel (on Debian and Ubuntu a meta package
# such as linux-generic moves to the new one) and CPU microcode, which fixes the processor's own flaws.
KERNEL_PACKAGE = re.compile(
    r"^(?!.*-(?:headers|docs)$)(?:"
    r"linux-(?:image|generic|signed-image|modules|virtual|lowlatency|oem)\S*"      # Debian, Ubuntu, Mint
    r"|linux(?:-lts|-zen|-hardened|-rt|-rt-lts|-cachyos[\w-]*)?"                   # Arch, CachyOS
    r"|kernel(?:-core|-default|-modules\S*)?"                                      # Fedora, openSUSE
    r"|intel-microcode|amd64-microcode|intel-ucode|amd-ucode|microcode_ctl|ucode-intel|ucode-amd)$")


def package_names(pm: str, out: str) -> list[str]:
    """The names of the packages in `apt list --upgradable`, `dnf check-update`, `pacman -Qu` or
    `zypper list-updates` output."""
    if pm == "apt":
        return [ln.split("/", 1)[0] for ln in out.splitlines() if "/" in ln and "[upgradable" in ln]
    if pm == "dnf":
        return [ln.split()[0].rsplit(".", 1)[0] for ln in out.splitlines() if re.match(r"^\S+\.\S+\s+\S+\s+\S+$", ln)]
    if pm == "pacman":
        return [ln.split()[0] for ln in out.splitlines() if ln.strip()]
    if pm == "zypper":
        return [f[2].strip() for f in (ln.split("|") for ln in out.splitlines() if ln.startswith("v ")) if len(f) > 2]
    return []


def _release_key(release: str) -> tuple:
    return tuple(int(t) if t.isdigit() else t for t in re.findall(r"\d+|[^\d.\-_+~]+", release))


def kernel_restart(scan: Scan) -> tuple[bool | None, list[Evidence]]:
    """Whether a newer kernel is installed than the one running (it takes a restart), from the
    kernels in /usr/lib/modules: one of the same build (generic, arch, fc41...) with a higher
    version, or the running one's modules gone (updated in place, as on Arch). None when there
    is no kernel of the machine's own to compare with (a container)."""
    host = scan.host
    if scan.context["virtualization"] == "container":
        return False, []
    running = (host.read_sys("/proc/sys/kernel/osrelease") or "").strip()
    dirs = {d.name: d for base in ("/usr/lib/modules", "/lib/modules") for d in children(host.sys_path(base))
            if d.is_dir()}
    kernels = [n for n, d in dirs.items() if (d / "vmlinuz").is_file() or host.sys_path(f"/boot/vmlinuz-{n}").exists()]
    if not running or not kernels:
        return None, []
    ev = [Evidence.val("Running kernel", running)]
    if running not in dirs:
        return True, ev + [Evidence.val("Its modules", "gone: the kernel was updated since it started")]
    shape = re.sub(r"\d+", "#", running)
    try:
        newest = max((k for k in kernels if re.sub(r"\d+", "#", k) == shape), key=_release_key, default=None)
        newer = newest is not None and _release_key(newest) > _release_key(running)
    except TypeError:
        return None, ev
    if newer:
        return True, ev + [Evidence.val("Newest installed kernel", newest)]
    return False, ev


def updates_outcome(pm: str, names: list[str] | None, security: int | None, ev: list[Evidence],
                    restart: bool | None, *, fresh: bool = False, extra: int = 0, notes=()) -> Outcome:
    """kern.updates and kern.updates_refreshed: what is waiting, graded by what it is. A kernel
    (or microcode) update, or a newer kernel installed than the one running, matters most:
    everything else, including the isolation between programs and accounts, runs on it. Then
    updates marked as security fixes. Other updates are worth installing, but rarely urgent.
    The severity comes from the catalogue's modifiers on the findings set here."""
    notes = list(notes)
    if names is None:
        return unknown(f"Couldn't list pending updates with {pm}.", *ev, notes=notes)
    kernel = sorted({n for n in names if KERNEL_PACKAGE.match(n)})
    total = len(names) + extra
    ev = [Evidence.count("Pending updates", len(names)), *ev]
    if security is None:
        ev.insert(1, Evidence.val("Security updates", f"{pm} doesn't say which updates are security fixes"))
    else:
        ev.insert(1, Evidence.count("Security updates", security))
    if kernel:
        ev.insert(2, Evidence.val("Kernel or microcode updates", ", ".join(kernel[:6])))
    findings = {"kernel_update_pending": bool(kernel), "kernel_restart_pending": restart,
                "security_updates_pending": (security > 0) if security is not None else (None if names else False)}
    plural = lambda n, word: f"{n} {word}{'s are' if n > 1 else ' is'}"   # noqa: E731
    if kernel:
        head = "A kernel update is waiting to be installed"
    elif security:
        head = plural(security, "security update") + " waiting to be installed"
    elif total:
        head = plural(total, "update") + " waiting to be installed"
    else:
        head = ""
    more = []
    if (kernel and total > 1) or (security and not kernel and total > security):
        more.append(f"{total} updates in all")
    if kernel and security:
        more.append(f"{security} of them security fixes" if total > 1 else "marked as a security fix")
    if more:
        head += f" ({', '.join(more)})"
    summary = head + "." if head else ""
    if head and not (kernel or security):
        summary += " None is marked as a security fix." if security == 0 else \
            f" {pm} doesn't say whether any are security fixes."
    if restart:
        summary = "A newer kernel is installed than the one running: restart to use it." + (" " + summary if summary else "")
    if fresh and summary:
        summary += " Checked against fresh package lists."
    if not summary:
        return passed("Everything is up to date" + (", checked against fresh package lists." if fresh else "."),
                      *ev, findings=findings, notes=notes)
    if kernel or restart or security:
        return failed(summary, *ev, findings=findings, notes=notes)
    return warned(summary, *ev, findings=findings, notes=notes)


def _pending(scan: Scan) -> tuple[str, list[str] | None, int | None, list[Evidence]] | None:
    """(package manager, names of the pending updates, how many are security fixes (None: the
    package manager doesn't say), evidence) from the package lists already on disk: nothing is
    downloaded (the app never goes online)."""
    host = scan.host
    if installed(host, "apt"):
        r = host.run("apt", "list", "--upgradable")
        lines = [ln for ln in r.stdout.splitlines() if "/" in ln and "[upgradable" in ln]
        security = sum(1 for ln in lines if "-security" in ln)
        lists = [p.stat().st_mtime for p in children(host.sys_path("/var/lib/apt/lists")) if p.is_file()]
        ev = []
        if lists:
            ev.append(Evidence.val("Package lists last refreshed", f"{int((time.time() - max(lists)) / 86400)} days ago"))
        ev.append(Evidence.val("Automatic security updates", "on" if apt_unattended(scan) else "off"))
        return ("apt", package_names("apt", r.stdout) if r.ok else None, security, ev)
    if installed(host, "dnf"):
        r = host.run("dnf", "-C", "-q", "check-update")
        timer = host.run("systemctl", "is-enabled", "dnf-automatic.timer", "dnf5-automatic.timer").stdout
        ev = [Evidence.val("Automatic updates", "on" if "enabled" in timer else "off")]
        return ("dnf", package_names("dnf", r.stdout) if r.returncode in (0, 100) else None, dnf_security(scan, "-C"), ev)
    if installed(host, "pacman"):
        r = host.run("pacman", "-Qu")
        # pacman marks nothing as a security fix (arch-audit would, but it goes online)
        return ("pacman", package_names("pacman", r.stdout) if r.returncode in (0, 1) else None, None, [])
    if installed(host, "zypper"):
        r = host.run("zypper", "--non-interactive", "--no-refresh", "list-updates")
        p = host.run("zypper", "--non-interactive", "--no-refresh", "list-patches", "--category", "security")
        security = len([ln for ln in p.stdout.splitlines() if re.search(r"\|\s*security\s*\|", ln)]) if p.ok else None
        return ("zypper", package_names("zypper", r.stdout) if r.ok else None, security, [])
    return None


def firmware_updates(scan: Scan) -> list[str] | None:
    """The devices with a firmware update waiting, from the metadata fwupd already has (nothing is refreshed);
    None where it can't be asked: no fwupd, or a virtual machine, which has no firmware of its own to update."""
    host = scan.host
    if scan.context["virtualization"] != "none" or not installed(host, "fwupdmgr"):
        return None
    r = host.run("fwupdmgr", "get-updates", "--json", "--no-metadata-check", "--no-unreported-check",
                 "--no-reboot-check", timeout=30)
    try:
        data = json.loads(r.stdout[r.stdout.index("{"):])
    except ValueError:
        return None
    devices = data.get("Devices") if isinstance(data, dict) else None
    if not isinstance(devices, list):
        return None
    return [str(d.get("Name") or "a device") for d in devices if isinstance(d, dict) and d.get("Releases")]


def apt_unattended(scan: Scan) -> bool:
    """APT::Periodic::Unattended-Upgrade as apt sees it: apt.conf, then apt.conf.d in name order, the
    last value winning (so the app's own 52daprivacyscanner-auto-upgrades counts as well as 20auto-upgrades)."""
    host, value = scan.host, None
    files = ["/etc/apt/apt.conf"] + [f"/etc/apt/apt.conf.d/{p.name}" for p in children(host.sys_path("/etc/apt/apt.conf.d"))
                                     if not p.name.endswith((".dpkg-old", ".dpkg-dist", ".bak", "~"))]
    for f in files:
        try:
            text = host.read_sys(f) or ""
        except Unreadable:
            continue
        for m in re.finditer(r'^\s*APT::Periodic::Unattended-Upgrade\s+"(\w+)"', text, re.M):
            value = m.group(1)
    return value not in (None, "0", "false")


def dnf_security(scan: Scan, *opts: str) -> int | None:
    """How many pending updates dnf's advisories mark as security fixes, or None when it can't say
    (no advisory data in its cache)."""
    r = scan.host.run("dnf", *opts, "-q", "updateinfo", "list", "--security", timeout=300)
    if not r.ok:
        return None
    return len({ln.split()[-1] for ln in r.stdout.splitlines() if re.search(r"/Sec\.|\bsecurity\b", ln, re.I)})


def no_pass_when_unsupported(scan: Scan, o: Outcome) -> Outcome:
    """On a release that no longer gets security updates, "nothing is waiting" isn't a pass: there is nothing left
    to wait for. What is waiting is still worth installing, and says so."""
    ended = support_ended(scan)
    if not ended:
        return o
    if o.status is Status.PASS:
        return unknown(f"No updates are waiting, but that says nothing here: {ended}, so fixes for what has been "
                       "found since never arrive (see kern.release_unsupported).", *o.evidence, notes=o.notes)
    o.notes.append(Note("risk", "These are the last updates this release gets",
                        f"{ended}. Installing what is waiting doesn't bring it up to date.",
                        related=("kern.release_unsupported",)))
    return o


@register
class Updates(Check):
    id = "kern.updates"

    def detect(self, scan: Scan) -> Outcome:
        result = _pending(scan)
        if result is None:
            return unknown("No supported package manager (apt, dnf, pacman, zypper) was found.")
        pm, names, security, ev = result
        restart, kev = kernel_restart(scan)
        note = Note("limitation", "Based on the package lists already on this machine",
                    "The app never goes online, so it doesn't refresh the lists first; updates published since your "
                    "last refresh aren't counted. Flatpak and Snap updates aren't checked for the same reason.")
        firmware = firmware_updates(scan) or []
        if firmware:
            ev.append(Evidence.val("Firmware updates", ", ".join(firmware[:6])))
        o = updates_outcome(pm, names, security, ev + kev, restart, extra=len(firmware), notes=[note])
        if firmware and o.status in (Status.FAIL, Status.WARN):
            n = len(firmware)
            o.summary += f" {n} of them {'are' if n > 1 else 'is'} firmware, which the system's updater may not install."
        return no_pass_when_unsupported(scan, o)


# ------------------------------------------------------------------ the release's end of support

SOON_DAYS = 90
ROLLING = frozenset({"arch", "opensuse-tumbleweed", "opensuse-slowroll", "void", "gentoo", "solus"})
DISTRO_INFO = "/usr/share/distro-info"


def _today() -> dt.date:
    return dt.date.today()


def _date(text: str | None) -> dt.date | None:
    try:
        return dt.date.fromisoformat((text or "").strip())
    except ValueError:
        return None


def long_date(d: dt.date) -> str:
    return f"{d.day} {d:%B %Y}"


def os_release_fields(host) -> dict[str, str]:
    text = host.read_sys("/etc/os-release") or host.read_sys("/usr/lib/os-release") or ""
    out = {}
    for ln in text.splitlines():
        k, sep, v = ln.partition("=")
        if sep and re.fullmatch(r"[A-Z0-9_]+", k.strip()):
            out[k.strip()] = v.strip().strip("\"'")
    return out


@dataclass(frozen=True)
class Support:
    """Until when a release gets security updates, as this computer's own records say."""
    name: str                           # "Linux Mint 22.3", as os-release names it
    end: dt.date | None = None          # the distribution's own security support
    source: str = ""                    # where the date was read
    base: str = ""                      # "Ubuntu 24.04 LTS", for what is built on another's release
    family: str = ""                    # ubuntu | debian | devuan, when read from distro-info
    own: bool = True                    # the distribution itself, not one built on it
    extended: dt.date | None = None     # Ubuntu Pro's ESM, Debian's LTS
    applies: bool = True                # False: a rolling or development release
    why: str = ""                       # for `applies` False, or no `end`: what to tell the user


def release_support(host) -> Support:
    """SUPPORT_END from os-release where the distribution sets it; for Ubuntu, Debian, Devuan and what is built on
    them, the release's row in distro-info-data. Never a date of the app's own: one that isn't on the machine is
    unknown."""
    rel = os_release_fields(host)
    ident, like = rel.get("ID", "").lower(), set(rel.get("ID_LIKE", "").lower().split())
    name = rel.get("PRETTY_NAME") or rel.get("NAME") or ident or "This system"
    if not rel:
        return Support(name, why="/etc/os-release couldn't be read, so the app can't tell which release this is.")
    end = _date(rel.get("SUPPORT_END"))
    if end:
        return Support(name, end, "SUPPORT_END in /etc/os-release")
    if rel.get("BUILD_ID", "").lower() == "rolling" or ident in ROLLING or "arch" in like:
        return Support(name, applies=False, why=f"{name} is a rolling release: it has no end of support, only updates "
                       "to keep installing.")
    for key, family in (("UBUNTU_CODENAME", "ubuntu"), ("DEBIAN_CODENAME", "debian"),
                        ("VERSION_CODENAME", ident if ident in ("ubuntu", "debian", "devuan") else "")):
        series = rel.get(key, "").lower()
        if not (series and family):
            continue
        path = f"{DISTRO_INFO}/{family}.csv"
        text = host.read_sys(path)
        if text is None:
            # Debian 13's GNOME, KDE and Xfce desktops don't install it (its Cinnamon one does, and Debian 12's did;
            # Ubuntu and Mint have it): the package is small and the distribution's own
            return Support(name, why=f"The list of {family.capitalize()} releases and their end dates ({path}) isn't on "
                           "this computer, so the app can't tell when support for this one ends. It comes with a small "
                           "package of the distribution's own: sudo apt install distro-info-data, then scan again.")
        row = next((r for r in csv.DictReader(io.StringIO(text)) if (r.get("series") or "").lower() == series), None)
        if row is None:
            return Support(name, why=f"{path} doesn't list this release ({series}), so the app can't tell when its "
                           "support ends.")
        own = ident == family
        base = f"{family.capitalize()} {row.get('version') or series}".strip()
        released = _date(row.get("release"))
        if series in ("sid", "testing", "unstable", "ceres") or released is None or released > _today():
            return Support(name, applies=False, base="" if own else base,
                           why=f"{name if own else base} is a development release: it has no end of support of its "
                           "own, and gets its fixes as they arrive.")
        end = _date(row.get("eol"))
        if end is None:
            return Support(name, base="" if own else base, why=f"{path} gives no end date for {base}.")
        # Ubuntu Pro is for Ubuntu itself, not for what is built on it; Debian's LTS comes through the same archive
        extended = _date(row.get("eol-lts") if family == "debian" else row.get("eol-esm") if own else None)
        return Support(name, end, path, "" if own else base, family, own,
                       extended if extended and extended > end else None)
    if not rel.get("VERSION_ID"):
        return Support(name, applies=False, why=f"{name} has no numbered releases: it has no end of support, only "
                       "updates to keep installing.")
    return Support(name, why=f"Nothing on this computer says when {name} stops getting security updates. Look for "
                   "its end of support (end of life) date on the distribution's site.")


def ubuntu_pro(host) -> bool:
    """Ubuntu Pro's extended security updates in use: its apt source is written when the machine is attached."""
    return any(host.sys_path(f"/etc/apt/sources.list.d/ubuntu-esm-infra.{ext}").is_file() for ext in ("list", "sources"))


def support_ended(scan: Scan) -> str:
    """For the update checks: "X stopped getting security updates on ..." when nothing more will come, else ""."""
    s = release_support(scan.host)
    if not (s.applies and s.end) or _today() <= s.end:
        return ""
    if s.extended and _today() <= s.extended and (s.family == "debian" or (s.own and ubuntu_pro(scan.host))):
        return ""
    return f"{s.base or s.name} stopped getting security updates on {long_date(s.end)}"


@register
class ReleaseUnsupported(Check):
    id = "kern.release_unsupported"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        s = release_support(host)
        ev = [Evidence.val("Release", s.name)]
        if s.base:
            ev.append(Evidence.val("Built on", s.base))
        if not s.applies:
            return absent(s.why, *ev)
        if s.end is None:
            return unknown(s.why, *ev)
        today = _today()
        what = s.base or s.name
        built = f"{s.name} is built on {s.base}, and gets its security updates for as long as it does. " if s.base else ""
        ev += [Evidence.val("Security updates until", long_date(s.end)), Evidence.val("Read from", s.source)]
        if s.extended:
            ev.append(Evidence.val("Ubuntu Pro's updates until" if s.family == "ubuntu" else "Long Term Support until",
                                   long_date(s.extended)))
        if today <= s.end:
            left = (s.end - today).days
            if left <= SOON_DAYS:
                when = "today" if left == 0 else f"on {long_date(s.end)}, in {left} day{'' if left == 1 else 's'}"
                return warned(f"{built}{what} stops getting security updates {when}. Plan the move to a newer "
                              "release.", *ev)
            return passed(f"{built}{what} gets security updates until {long_date(s.end)}.", *ev)
        ended = f"{built}{what} stopped getting security updates on {long_date(s.end)}."
        if s.extended and today <= s.extended:
            if s.family == "debian":
                return warned(f"{ended} Until {long_date(s.extended)} it gets Debian's Long Term Support: security fixes "
                              "from a separate team, for fewer packages and often later. Plan the move to a newer "
                              "release.", *ev)
            if s.own and ubuntu_pro(host):
                ev.append(Evidence.val("Ubuntu Pro", "in use"))
                return passed(f"{what}'s own updates ended on {long_date(s.end)}, and this computer gets Ubuntu Pro's "
                              f"security updates instead, until {long_date(s.extended)}.", *ev)
            if s.own:
                return failed(ended, *ev, notes=[Note(
                    "info", "Ubuntu Pro would extend it",
                    f"Ubuntu Pro (free for personal use on up to five computers) keeps security updates coming for "
                    f"this release until {long_date(s.extended)}. It needs an Ubuntu account, and the computer is "
                    "registered with Canonical. Moving to a newer release needs neither.")])
        return failed(ended, *ev)


@register
class PtraceScope(Check):
    id = "kern.ptrace_scope"

    def detect(self, scan: Scan) -> Outcome:
        v = (scan.host.read_sys("/proc/sys/kernel/yama/ptrace_scope") or "").strip()
        if not v:
            return failed("The Yama security module isn't active, so any process can read the memory of others you run.",
                          Evidence.val("ptrace_scope", "not available"))
        ev = [Evidence.val("ptrace_scope", v)]
        if v == "0":
            return failed("Any process you run can read the memory of your other processes.", *ev)
        return passed("Processes can't read each other's memory unless one started the other.", *ev)


def _kernel_option(scan: Scan, param: str, config: str) -> tuple[bool | None, Evidence]:
    cmdline = scan.host.read_sys("/proc/cmdline") or ""
    m = re.search(rf"(?:^|\s){param}=(\S+)", cmdline)
    if m:
        return m.group(1) in ("1", "on", "y"), Evidence.val(f"{param} on the command line", m.group(1))
    release = (scan.host.read_sys("/proc/sys/kernel/osrelease") or "").strip()
    text = None
    try:
        text = scan.host.read_sys(f"/boot/config-{release}") if release else None
    except Unreadable:
        text = None
    if text is None:
        try:
            with gzip.open(scan.host.sys_path("/proc/config.gz"), "rt") as f:
                text = f.read()
        except OSError:
            text = None
    if text is None:
        return None, Evidence.val("Kernel config", "not readable")
    on = re.search(rf"^{config}=y", text, re.M) is not None
    return on, Evidence.val(config, "y" if on else "not set")


class _InitOn(Check):
    param = config = on_text = off_text = cost_title = cost_text = ""

    def detect(self, scan: Scan) -> Outcome:
        on, ev = _kernel_option(scan, self.param, self.config)
        if on is None:
            return unknown(f"Couldn't tell whether {self.param} is on.", ev)
        if on:
            return passed(f"{self.param} is on: {self.on_text}.", ev)
        if ev.label.endswith("on the command line"):
            why = (f" Here a boot option turns it off ({self.param}={ev.value}); look in /etc/default/grub "
                   "(GRUB_CMDLINE_LINUX) or /etc/kernel/cmdline for where it is set.")
        else:
            why = f" Here the kernel is built with {self.config} off, so it is off unless the command line turns it on."
        return failed(f"{self.param} is off: {self.off_text}.", ev,
                      notes=[Note("info", self.cost_title, f"Adding {self.param}=1 to the kernel command line "
                                  + self.cost_text + why)])


@register
class InitOnFree(_InitOn):
    id = "kern.init_on_free"
    param, config = "init_on_free", "CONFIG_INIT_ON_FREE_DEFAULT_ON"
    on_text, off_text = "freed memory is wiped", "freed memory keeps its old contents until reused"
    cost_title = "Off by default almost everywhere"
    cost_text = ("wipes memory as it is freed. It costs noticeably more than init_on_alloc (several percent on "
                 "memory-heavy workloads), which is why distributions leave it off; worth it mainly on machines "
                 "that hold high-value secrets.")


@register
class InitOnAlloc(_InitOn):
    id = "kern.init_on_alloc"
    param, config = "init_on_alloc", "CONFIG_INIT_ON_ALLOC_DEFAULT_ON"
    on_text, off_text = "kernel memory is zeroed when allocated", "kernel memory isn't zeroed when allocated"
    cost_title = "Unusual to find off"
    cost_text = ("turns it back on. Being off isn't a serious threat in itself, but almost every distribution "
                 "kernel enables it: it costs almost nothing and meaningfully improves security. Off usually means a "
                 "custom kernel or a boot option (init_on_alloc=0) turned it off; worth finding out which.")


LANDLOCK_SCOPES = 6                     # Landlock ABI with scopes (abstract sockets, signals): Linux 6.12


def landlock_state(scan: Scan) -> tuple[str, int | None, list[Evidence]]:
    """("scopes" | "old" | "off" | "missing" | "unknown", ABI, evidence): whether this kernel's Landlock
    can keep a sandbox from abstract sockets and signals outside it. On the running system the kernel
    is asked (the ABI, or EOPNOTSUPP when it is built in but not turned on at boot); otherwise the
    active security modules and the kernel's version decide."""
    import errno
    from pathlib import Path
    host = scan.host
    release = (host.read_sys("/proc/sys/kernel/osrelease") or "").strip()
    lsm_text = host.read_sys("/sys/kernel/security/lsm")
    lsm = [m for m in (lsm_text or "").strip().split(",") if m] if lsm_text is not None else None
    ev = [Evidence.val("Running kernel", release or "unknown")]
    if lsm is not None:
        ev.append(Evidence.val("Active security modules", ",".join(lsm)))
    abi = None
    if host.root == Path("/"):
        from ..tools.sandbox import landlock_abi_errno
        abi, err = landlock_abi_errno()
        if abi is None and err == errno.EOPNOTSUPP:
            return "off", None, ev + [Evidence.val("Landlock", "built in, not turned on at boot")]
        if abi is None and err == errno.ENOSYS:
            return "missing", None, ev + [Evidence.val("Landlock", "not in this kernel")]
    if abi is None and lsm is not None and "landlock" not in lsm:
        built, cev = _kernel_option(scan, "landlock", "CONFIG_SECURITY_LANDLOCK")
        if built:
            return "off", None, ev + [Evidence.val("Landlock", "built in, not turned on at boot")]
        return ("missing" if built is False else "unknown"), None, ev + [cev]
    if abi is None:
        m = re.match(r"(\d+)\.(\d+)", release)
        if not m or lsm is None:
            return "unknown", None, ev
        abi = LANDLOCK_SCOPES if (int(m.group(1)), int(m.group(2))) >= (6, 12) else 1
        ev.append(Evidence.val("Landlock", "on" + (", with scopes (6.12 or later)" if abi >= LANDLOCK_SCOPES
                                                 else ", without scopes (before 6.12)")))
    else:
        ev.append(Evidence.val("Landlock ABI", abi))
    return ("scopes" if abi >= LANDLOCK_SCOPES else "old"), abi, ev


@register
class Landlock(Check):
    id = "kern.landlock"

    def detect(self, scan: Scan) -> Outcome:
        if scan.context["virtualization"] == "container":
            return absent("In a container the host's kernel decides.")
        state, abi, ev = landlock_state(scan)
        if state == "scopes":
            return passed("Sandboxes can be kept from other programs' hidden sockets and signals (Landlock).", *ev)
        if state == "unknown":
            return unknown("Couldn't tell what this kernel's Landlock can do.", *ev)
        summary = {"old": "This kernel's Landlock is too old to keep a sandbox from the session's hidden sockets "
                          "(that needs Linux 6.12).",
                   "off": "Landlock is built into this kernel but not turned on at boot.",
                   "missing": "This kernel has no Landlock."}[state]
        return failed(summary, *ev)


# ------------------------------------------------------------------ kernel log and /proc

def _kernel_log(scan: Scan) -> str | None:
    """This boot's kernel messages, if this user may read them (dmesg, or the journal for members
    of adm / systemd-journal)."""
    r = scan.host.run("dmesg")
    if r.ok and r.stdout:
        return r.stdout
    r = scan.host.run("journalctl", "-k", "-b", "-q", "--no-pager", "-o", "cat")
    return r.stdout if r.ok and r.stdout else None


@register
class DmesgRestrict(Check):
    id = "kern.dmesg_restrict"

    def detect(self, scan: Scan) -> Outcome:
        v = (scan.host.read_sys("/proc/sys/kernel/dmesg_restrict") or "").strip()
        if not v:
            return unknown("Couldn't read kernel.dmesg_restrict.")
        ev = [Evidence.val("dmesg_restrict", v)]
        notes = []
        groups = _groups_of(scan)
        log_groups = sorted(groups & {"adm", "systemd-journal", "wheel"})       # journald's ACL names adm and wheel
        if log_groups:
            notes.append(Note("info", "You can read it through the journal anyway",
                              f"As a member of {', '.join(log_groups)}, you can read kernel messages with journalctl "
                              "whatever this setting says; it is about other accounts and programs that aren't."))
        if v == "0":
            return failed("Every account and program can read the kernel log, which records devices plugged in "
                          "and drives mounted.", *ev, notes=notes)
        return passed("Only administrators can read the kernel log.", *ev, notes=notes)


def _groups_of(scan: Scan) -> set[str]:
    from ._util import user_names
    login, _ = user_names(scan.host)
    out = set()
    for line in (scan.host.read_sys("/etc/group") or "").splitlines():
        f = line.split(":")
        if len(f) >= 4 and login and login in f[3].split(","):
            out.add(f[0])
    return out


HIDDEN = {"1", "2", "noaccess", "invisible"}


@register
class ProcHidepid(Check):
    id = "kern.proc_hidepid"

    def detect(self, scan: Scan) -> Outcome:
        proc = next((m for m in reversed(mounts(scan.host)) if m.target == "/proc" and m.fstype == "proc"), None)
        if proc is None:
            return unknown("Couldn't find the /proc mount.")
        opts = dict(o.partition("=")[::2] for o in proc.options.split(","))
        hidepid = opts.get("hidepid", "0")
        ev = [Evidence.val("/proc hidepid", hidepid + ("" if "hidepid" in opts else " (default)"))]
        if hidepid in HIDDEN:
            return passed("Other users can't see your processes or their command lines.", *ev)
        return failed("Every account can list the programs you run, with their full command lines.", *ev,
                      notes=[Note("info", "Why the app doesn't change this",
                                  "hidepid is a mount option for /proc in /etc/fstab (hidepid=invisible,gid=proc). "
                                  "systemd-logind, polkit and monitoring tools then need to be in that group, or "
                                  "logins and admin prompts can break, so it is left to you. Meanwhile, avoid "
                                  "passing passwords as command arguments.", ("auth.shell_history_secrets",))])


# ------------------------------------------------------------------ memory encryption

def memory_encryption(scan: Scan) -> tuple[str, str] | None:
    """(name, state) when the CPU can encrypt memory: state "on", "off" or "unknown". None when it
    can't, or in a VM (the host's memory is what matters)."""
    if scan.context["virtualization"] == "vm":
        return None
    flags = set()
    for line in (scan.host.read_sys("/proc/cpuinfo") or "").splitlines():
        if line.startswith("flags"):
            flags = set(line.split(":", 1)[1].split())
            break
    if "sme" in flags:
        cmdline = scan.host.read_sys("/proc/cmdline") or ""
        m = re.search(r"(?:^|\s)mem_encrypt=(\S+)", cmdline)
        if m:
            return "AMD SME", "on" if m.group(1) == "on" else "off"
        on, _ = _kernel_option(scan, "mem_encrypt", "CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT")
        return "AMD SME", "unknown" if on is None else "on" if on else "off"
    if "tme" in flags:
        log = _kernel_log(scan) or ""
        if "x86/tme: enabled by BIOS" in log:
            return "Intel TME", "on"
        if "x86/tme: not enabled by BIOS" in log:
            return "Intel TME", "off"
        return "Intel TME", "unknown"
    return None


def memory_encryption_note(scan: Scan, for_dma: bool = False) -> Note | None:
    me = memory_encryption(scan)
    if me is None:
        return None
    name, state = me
    if for_dma:
        return Note("info", f"Memory encryption ({name}) doesn't stop this",
                    "It protects what can be read off the memory chips; a device with DMA access reads memory "
                    "through the memory controller instead. The IOMMU is what stops that.")
    if state == "on":
        return Note("info", f"Memory is encrypted ({name})",
                    "Reading the memory chips directly (a cold-boot attack) gets only ciphertext.")
    how = ("add mem_encrypt=on to the kernel command line; a few older devices and drivers don't work with it, "
           "so try it before relying on it" if name.startswith("AMD") else
           "turn it on in the firmware settings (often called Total Memory Encryption)")
    if state == "off":
        return Note("risk", f"This CPU can encrypt memory, but {name} is off",
                    f"With it on, reading the memory chips of a sleeping or just-switched-off machine gets only "
                    f"ciphertext. To use it, {how}.", ("kern.init_on_free",))
    return Note("info", f"This CPU can encrypt memory ({name})",
                f"Whether it is on couldn't be seen (the kernel log isn't readable). If it isn't, {how}.")


@register
class SuspendKeysInRam(Check):
    id = "kern.suspend_keys_in_ram"

    def detect(self, scan: Scan) -> Outcome:
        state = (scan.host.read_sys("/sys/power/state") or "").split()
        if "mem" not in state:
            return passed("This machine can't suspend to RAM.")
        me = memory_encryption_note(scan)
        return failed("While suspended, disk encryption keys stay in memory.",
                      Evidence.val("Sleep states", " ".join(state)),
                      notes=[Note("info", "Shut down when travelling",
                                  "A stolen laptop that is asleep can have its keys read from memory by DMA or "
                                  "cold-boot attacks. Shutting down (or hibernating to encrypted swap) clears them.",
                                  ("kern.dma",))] + ([me] if me else []))


@register
class Dma(Check):
    id = "kern.dma"

    def detect(self, scan: Scan) -> Outcome:
        host = scan.host
        domains = [d for d in children(host.sys_path("/sys/bus/thunderbolt/devices")) if d.name.startswith("domain")]
        if not domains:
            return absent("No Thunderbolt or USB4 controller.")
        iommu = bool(children(host.sys_path("/sys/class/iommu")))
        ev, weak = [Evidence.val("IOMMU", "active" if iommu else "not active")], []
        for d in domains:
            sec = (read_text(host, d / "security") or "unknown").strip()
            prot = (read_text(host, d / "iommu_dma_protection") or "0").strip() == "1"
            ev.append(Evidence.val(d.name, f"security level {sec}, DMA protection {'on' if prot else 'off'}"))
            if not prot and sec in ("none", "unknown", "dponly", "usbonly") and sec != "usbonly":
                weak.append(d.name)
            elif not prot and not iommu:
                weak.append(d.name)
        if weak:
            me = memory_encryption_note(scan, for_dma=True)
            return failed("Thunderbolt devices can read memory directly (no DMA protection).", *ev,
                          notes=[me] if me else [])
        return passed("Thunderbolt DMA is protected.", *ev)


# ------------------------------------------------------------------ USB devices

USBGUARD_DAEMONS = ("/usr/sbin/usbguard-daemon", "/usr/bin/usbguard-daemon")


@register
class UsbTrusted(Check):
    id = "kern.usb_trusted"

    def detect(self, scan: Scan) -> Outcome:
        from ._util import systemctl_state
        host = scan.host
        hubs = [d for d in children(host.sys_path("/sys/bus/usb/devices")) if re.match(r"^usb\d+$", d.name)]
        if not hubs:
            return absent("No USB controllers.")
        ev = []
        policy = {(read_text(host, d / "authorized_default") or "").strip() for d in hubs}
        names = {"1": "every device", "0": "no device until allowed", "2": "built-in devices only", "-1": "every device "
                 "except wireless ones"}
        ev.append(Evidence.val("The kernel authorises", ", ".join(sorted(names.get(v, v or "unknown") for v in policy))))
        daemon = any(host.sys_path(d).exists() for d in USBGUARD_DAEMONS) or installed(host, "usbguard")
        state = systemctl_state(host, "is-active", "usbguard.service") if daemon else ""
        ev.append(Evidence.val("USBGuard", "running" if state == "active" else
                               f"installed, not running ({state or 'unknown'})" if daemon else "not installed"))
        notes = []
        if scan.context.desktop.is_gnome:
            on = scan.gnome.gsettings("org.gnome.desktop.privacy", "usb-protection")
            level = scan.gnome.gsettings("org.gnome.desktop.privacy", "usb-protection-level")
            if on is not None:
                ev.append(Evidence.val("GNOME's USB protection", f"on ({level})" if on else "off"))
                if on and state != "active":
                    notes.append(Note("limitation", "GNOME's USB protection needs USBGuard",
                                      "It is switched on, but does nothing until the USBGuard service runs."))
        if state == "active":
            return passed("USBGuard decides which USB devices may connect.", *ev, notes=notes)
        if policy and policy <= {"0", "2"}:
            return passed("The kernel doesn't let new USB devices in until they are allowed.", *ev, notes=notes)
        return warned("Any USB device plugged in is trusted at once, keyboards included.", *ev, notes=notes)


# ------------------------------------------------------------------ package signatures

@dataclass(frozen=True)
class Unsigned:
    """One place where a package manager has been told not to check signatures."""
    path: str                   # the file, as on the system
    what: str                   # the setting, as written ("trusted=yes", "gpgcheck=0", "SigLevel = Never")
    name: str = ""              # the repository or remote, when the file names it
    http: bool = False          # its address is plain http://
    manager: str = ""           # apt | dnf | zypper | pacman | flatpak


_APT_OPTS = ("trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure")
_APT_822 = {"trusted": "Trusted", "allow-insecure": "Allow-Insecure", "allow-weak": "Allow-Weak",
            "allow-downgrade-to-insecure": "Allow-Downgrade-To-Insecure"}
_APT_CONF = re.compile(r'^\s*(?!//|#)[^\n]*?\b(AllowUnauthenticated|AllowInsecureRepositories|'
                       r'AllowDowngradeToInsecureRepositories|AllowWeakRepositories)\b\s*"?\s*(true|yes|1|on)\b',
                       re.M | re.I)
_DEB_LINE = re.compile(r"^\s*deb(?:-src)?\s+\[([^\]]*)\]\s+(\S+)", re.M)
_FALSE = ("0", "false", "no", "off")


def _sys_text(scan: Scan, path: str) -> tuple[str | None, bool]:
    """(text or None, whether it couldn't be read)."""
    try:
        return scan.host.read_sys(path), False
    except Unreadable:
        return None, True


def _sys_files(scan: Scan, folder: str, suffixes: tuple[str, ...]) -> list[str]:
    return sorted(f"{folder}/{f.name}" for f in children(scan.host.sys_path(folder)) if f.name.endswith(suffixes))


def apt_unsigned(scan: Scan) -> tuple[list[Unsigned], bool, bool]:
    """(apt's settings that skip signature checks, whether the legacy shared keyring holds keys,
    whether a file couldn't be read)."""
    out, unreadable = [], False
    for path in ["/etc/apt/sources.list"] + _sys_files(scan, "/etc/apt/sources.list.d", (".list", ".sources")):
        text, bad = _sys_text(scan, path)
        unreadable |= bad
        if not text:
            continue
        if path.endswith(".sources"):
            for stanza in re.split(r"\n\s*\n", text):
                fields = {m.group(1).lower(): m.group(2).strip() for m in re.finditer(r"^([A-Za-z-]+):\s*(.*)$", stanza, re.M)}
                if not fields or ini.truthy(fields.get("enabled", "yes")) is False:
                    continue
                for key, title in _APT_822.items():
                    if ini.truthy(fields.get(key)):
                        uris = fields.get("uris", "")
                        out.append(Unsigned(path, f"{title}: yes", uris.split()[0] if uris else "",
                                            "http://" in uris, "apt"))
            continue
        for m in _DEB_LINE.finditer(text):
            opts = dict((o.split("=", 1) + [""])[:2] for o in m.group(1).split())
            for key in _APT_OPTS:
                if ini.truthy(opts.get(key)):
                    out.append(Unsigned(path, f"{key}=yes", m.group(2), m.group(2).startswith("http://"), "apt"))
    for path in ["/etc/apt/apt.conf"] + _sys_files(scan, "/etc/apt/apt.conf.d", ("",)):
        text, bad = _sys_text(scan, path)
        unreadable |= bad
        for m in _APT_CONF.finditer(text or ""):
            out.append(Unsigned(path, f"{m.group(1)} true", manager="apt"))
    legacy = scan.host.sys_path("/etc/apt/trusted.gpg")
    try:
        has_legacy = legacy.is_file() and legacy.stat().st_size > 0
    except OSError:
        has_legacy = False
    return out, has_legacy, unreadable


# packages that ship a distribution's own archive keys into /etc/apt/trusted.gpg.d
DISTRO_KEYRINGS = frozenset({"ubuntu-keyring", "ubuntu-dbgsym-keyring", "ubuntu-cloud-keyring", "debian-archive-keyring",
                             "debian-ports-archive-keyring", "linuxmint-keyring", "neon-archive-keyring",
                             "raspberrypi-archive-keyring", "devuan-keyring", "kali-archive-keyring", "pureos-keyring",
                             "pop-default-settings", "elementary-os-keyring", "zorin-os-keyring", "tuxedo-archive-keyring"})


def apt_shared_keys(scan: Scan) -> list[str]:
    """Keys in /etc/apt/trusted.gpg.d that aren't the distribution's: apt trusts each for every repository that names
    no signed-by key, as it does /etc/apt/trusted.gpg. The distribution's are owned by its keyring package, or named
    after it (Mint's installer leaves linuxmint.key.asc, which no package owns; seen on Mint 22)."""
    from .guides import os_release
    ident, like = os_release(scan)
    prefixes = tuple(x for x in {ident, *like} if x)
    out = []
    for f in children(scan.host.sys_path("/etc/apt/trusted.gpg.d")):
        if f.suffix not in (".gpg", ".asc") or (prefixes and f.name.lower().startswith(prefixes)):
            continue
        r = scan.host.run("dpkg-query", "-S", f"/etc/apt/trusted.gpg.d/{f.name}")
        owner = r.stdout.split(":", 1)[0].strip() if r.ok else ""
        if owner not in DISTRO_KEYRINGS:
            out.append(f.name)
    return out


def _rpm_repos(scan: Scan, folder: str, main_files: tuple[str, ...], manager: str) -> tuple[list[Unsigned], bool]:
    """dnf/yum and zypper: gpgcheck (or pkg_gpgcheck) off in an enabled repository, or in [main]."""
    out, unreadable = [], False
    main_off = None
    for path in main_files:
        text, bad = _sys_text(scan, path)
        unreadable |= bad
        keys = ini.parse(text or "").get(("main",), {})
        for k in ("gpgcheck", "pkg_gpgcheck"):
            if keys.get(k, "").strip().lower() in _FALSE:
                main_off = (path, f"{k} = {keys[k]}")
    if main_off:
        out.append(Unsigned(main_off[0], main_off[1] + " (for every repository that doesn't set it)", manager=manager))
    for path in _sys_files(scan, folder, (".repo",)):
        text, bad = _sys_text(scan, path)
        unreadable |= bad
        for group, keys in ini.parse(text or "").items():
            if not group or ini.truthy(keys.get("enabled", "1")) is False:
                continue
            off = next((k for k in ("gpgcheck", "pkg_gpgcheck") if keys.get(k, "").strip().lower() in _FALSE), None)
            if off:
                url = keys.get("baseurl", "") or keys.get("mirrorlist", "") or keys.get("metalink", "")
                out.append(Unsigned(path, f"{off}={keys[off]}", group[0], url.strip().startswith("http://"), manager))
    return out, unreadable


def pacman_unsigned(scan: Scan) -> tuple[list[Unsigned], bool]:
    text, bad = _sys_text(scan, "/etc/pacman.conf")
    out = []
    for group, keys in ini.parse(text or "").items():
        level = keys.get("SigLevel")
        if not group or level is None:
            continue
        words = set(level.split())
        if words & {"Never", "PackageNever", "Optional", "PackageOptional"}:
            out.append(Unsigned("/etc/pacman.conf", f"SigLevel = {level}", "" if group[0] == "options" else group[0],
                                keys.get("Server", "").startswith("http://"), "pacman"))
    return out, bad


def flatpak_unsigned(scan: Scan) -> list[Unsigned]:
    out = []
    for path, shown in ((scan.host.sys_path("/var/lib/flatpak/repo/config"), "/var/lib/flatpak/repo/config"),
                        (scan.paths.data_home / "flatpak" / "repo" / "config", None)):
        for group, keys in ini.parse(read_text(scan.host, path) or "").items():
            m = re.match(r'^remote "(.+)"$', group[0]) if group else None
            if m and ini.truthy(keys.get("gpg-verify")) is False:
                out.append(Unsigned(shown or scan.host.display(path), "gpg-verify=false", m.group(1),
                                    keys.get("url", "").startswith("http://"), "flatpak"))
    return out


def unsigned_repositories(scan: Scan) -> tuple[list[Unsigned], bool, bool, bool]:
    """(where checks are off, the legacy apt keyring holds keys, a file couldn't be read, any package
    manager was found)."""
    apt, legacy, bad1 = apt_unsigned(scan)
    dnf, bad2 = _rpm_repos(scan, "/etc/yum.repos.d", ("/etc/dnf/dnf.conf", "/etc/yum.conf"), "dnf")
    zyp, bad3 = _rpm_repos(scan, "/etc/zypp/repos.d", ("/etc/zypp/zypp.conf",), "zypper")
    pac, bad4 = pacman_unsigned(scan)
    found = any(scan.host.sys_path(p).exists() for p in ("/etc/apt", "/etc/yum.repos.d", "/etc/zypp", "/etc/pacman.conf",
                                                         "/var/lib/flatpak/repo"))
    return apt + dnf + zyp + pac + flatpak_unsigned(scan), legacy, bad1 or bad2 or bad3 or bad4, found


@register
class PackageSignatures(Check):
    id = "kern.package_signatures"

    def detect(self, scan: Scan) -> Outcome:
        found, legacy, unreadable, any_manager = unsigned_repositories(scan)
        if not any_manager and not found:
            return absent("No apt, dnf, zypper, pacman or Flatpak configuration was found.")
        ev = [Evidence.val(f"{u.path}" + (f" ({u.name})" if u.name else ""), u.what + (", over plain HTTP" if u.http else ""))
              for u in found[:20]]
        if legacy:
            ev.append(Evidence.path("Keys in apt's old shared keyring, trusted for every repository", "/etc/apt/trusted.gpg"))
        shared = apt_shared_keys(scan)
        ev += [Evidence.path("Key in /etc/apt/trusted.gpg.d, trusted for every repository", f"/etc/apt/trusted.gpg.d/{n}")
               for n in shared[:10]]
        findings = {"signature_checks_off": bool(found), "unsigned_over_http": any(u.http for u in found)}
        if unreadable and not found:
            findings = {"signature_checks_off": None, "unsigned_over_http": None}
        if found:
            n = len(found)
            return failed(f"Signature checks are off in {n} place{'s' if n > 1 else ''}: packages from there are "
                          "installed without checking who made them.", *ev, findings=findings, partial=unreadable)
        if legacy or shared:
            return warned(("apt's old shared keyring (/etc/apt/trusted.gpg) holds keys" if legacy else
                           f"{len(shared)} key{'s' if len(shared) > 1 else ''} of other publishers in /etc/apt/trusted.gpg.d "
                           f"{'are' if len(shared) > 1 else 'is'}") + " trusted for every repository.", *ev,
                          findings=findings, partial=unreadable)
        if unreadable:
            return unknown("Some package manager settings couldn't be read, so this couldn't be checked fully.")
        return passed("Package managers check signatures for every repository.", findings=findings)
