"""Guided fixes for the `guided` tier checks, one module per category (as the checks) (and the explanations that go with them). Each guide
is built from the machine as it is now; building it changes nothing. Options the app can apply
are FixPlans, so they have a dry run, go in the undo log and can be reverted like any fix.
Changes as root go through the privileged helper (RootChange); changes that need the user's own
input (passphrases, PINs) or are too risky to automate (sudoers, fstab, crypttab) are given as
commands for the user to run.

As with auto fixes, apps the user runs are never stopped: a step that needs one closed is
blocked until it is ("Close Firefox first")."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ...context import read_swaps
from ...fix import FIREFOX_PROCESSES, FirefoxPref, FixPlan, RootChange
from ...guide import Guide, Option, Step
from ...model import Outcome
from .. import Check, No, Scan
from .._util import chromium_dirs, mozilla_profiles, processes, read_text, systemctl_state


@dataclass
class GuideEntry:
    plan: Callable[[Check, Scan, Outcome], Guide]
    can: Callable[[Scan], bool] | None = None
    keys: frozenset[str] = frozenset()       # the option keys the guide gives (the catalogue's easy.option)


GUIDES: dict[str, GuideEntry] = {}


def guide(check_id: str, can: Callable[[Scan], bool] | None = None, keys: tuple[str, ...] = ()):
    def register(fn):
        GUIDES[check_id] = GuideEntry(fn, can, frozenset(keys))
        return fn
    return register


# ------------------------------------------------------------------ helpers

def option(check: Check, label: str, actions: list, detail: str = "", side_effects=(), blockers=(),
           recommended: bool = False, key: str = "") -> Option:
    return Option(label, FixPlan(check.id, label, list(actions), list(blockers), list(side_effects)), detail, recommended,
                  key)


def evidence(outcome: Outcome, label: str | None = None, value: str | None = None) -> list:
    """Evidence values (or labels, with `value`) of the check's own outcome."""
    if value is not None:
        return [e.label for e in outcome.evidence if isinstance(e.value, str) and value in e.value]
    return [e.value for e in outcome.evidence if e.label == label]


def unit_exists(scan: Scan, unit: str, user: bool = False) -> bool:
    r = scan.host.run("systemctl", *(["--user"] if user else []), "show", "--property=LoadState", "--value", unit)
    return r.ok and r.stdout.strip() not in ("", "not-found")


def service_off(scan: Scan, *units: str) -> list[RootChange]:
    """Stop and disable the units that exist and are enabled or running, together in one step and one systemctl call:
    stopped one at a time, a socket's service could be started again on demand in between (Avahi on Mint, by
    cups-browsed over D-Bus, cancelled the socket's stop), and disabling the service too removes the name it is
    started by. One unit keeps the request's earlier form."""
    on = [u for u in units if unit_exists(scan, u) and (systemctl_state(scan.host, "is-enabled", u) == "enabled"
                                                       or systemctl_state(scan.host, "is-active", u) == "active")]
    if not on:
        return []
    return [RootChange("set_service", {**({"unit": on[0]} if len(on) == 1 else {"units": on}), "enable": False,
                                       "start": False},
                       f"Stop and disable {' and '.join(on)} (systemctl disable --now {' '.join(on)})")]


def dropin(name: str, settings: dict[str, str], path: str) -> RootChange:
    shown = ", ".join(f"{k}={v}" for k, v in settings.items())
    return RootChange("write_dropin", {"name": name, "settings": settings}, f"Write {path} with {shown}")


def os_release(scan: Scan) -> tuple[str, set[str]]:
    text = scan.host.read_sys("/etc/os-release") or ""
    get = lambda k: (re.search(rf'^{k}="?([^"\n]*)', text, re.M) or [None, ""])[1].lower()  # noqa: E731
    return get("ID"), set(get("ID_LIKE").split())


def family(scan: Scan) -> str | None:
    i, like = os_release(scan)
    for fam, names in (("debian", {"debian", "ubuntu", "linuxmint"}), ("fedora", {"fedora", "rhel", "centos"}),
                       ("arch", {"arch"}), ("suse", {"suse", "opensuse", "opensuse-tumbleweed", "opensuse-leap"})):
        if i in names or like & names:
            return fam
    return None


def install(scan: Scan, **packages: str) -> str | None:
    """The command that installs a package on this distribution (packages by family)."""
    fam = family(scan)
    pkg = packages.get(fam or "")
    cmd = {"debian": "sudo apt install", "fedora": "sudo dnf install", "arch": "sudo pacman -S",
           "suse": "sudo zypper install"}.get(fam or "")
    return f"{cmd} {pkg}" if cmd and pkg else None


def remove(scan: Scan, **packages: str) -> str | None:
    """The command that removes a package on this distribution (packages by family)."""
    fam = family(scan)
    pkg = packages.get(fam or "")
    cmd = {"debian": "sudo apt remove", "fedora": "sudo dnf remove", "arch": "sudo pacman -R",
           "suse": "sudo zypper remove"}.get(fam or "")
    return f"{cmd} {pkg}" if cmd and pkg else None


def firefox_open(scan: Scan) -> bool:
    return bool(processes(scan.host) & FIREFOX_PROCESSES)


MOZILLA_PROGRAMS = {"firefox": "Firefox", "firefox-bin": "Firefox", "firefox-esr": "Firefox", "librewolf": "LibreWolf",
                    "thunderbird": "Thunderbird", "thunderbird-bin": "Thunderbird"}


def mozilla_open(scan: Scan, only=("Firefox", "LibreWolf", "Thunderbird")) -> list[str]:
    """Which of these Firefox-family programs are running, by name; a GeckoMain process whose
    program isn't known counts as all of them (it rewrites its prefs.js as it exits, whichever it is)."""
    procs = processes(scan.host)
    names = [n for n in only if any(label == n and p in procs for p, label in MOZILLA_PROGRAMS.items())]
    if not names and "GeckoMain" in procs:
        names = list(only)
    return names


def remote_session(scan: Scan) -> set[str]:
    """How the user reached this session from another machine, when they did: "xrdp" (xrdp-sesman
    sets XRDP_SESSION in the session), "ssh" (ssh sets SSH_CONNECTION), possibly both. Turning off
    the service that carries the session would cut it mid-step, so such an option is blocked."""
    env = scan.host.environ
    return ({"xrdp"} if env.get("XRDP_SESSION") else set()) | \
        ({"ssh"} if env.get("SSH_CONNECTION") or env.get("SSH_TTY") else set())


def ff_prefs(check: Check, scan: Scan, label: str, prefs: dict | Callable, side_effects=(), only=("Firefox", "LibreWolf"),
             want: Callable | None = None, recommended: bool = False, key: str = "") -> list[Option]:
    """One option per Firefox-family profile that doesn't have these prefs yet (prefs.js,
    changed while the browser is closed). `prefs` may be a function of the profile and its prefs
    giving the ones that matter for it (Thunderbird's differ from Firefox's). An option is blocked
    only while its own program runs: a running Thunderbird doesn't hold up Firefox's profiles."""
    from .._util import firefox_prefs
    out = []
    running = mozilla_open(scan, only)
    for p in mozilla_profiles(scan.host, scan.paths, only):
        current = firefox_prefs(scan.host, p.path)
        if want is not None and not want(current, p):
            continue
        wanted = prefs(p, current) if callable(prefs) else prefs
        actions = [FirefoxPref(p.path, p.label, k, v, scan.host.display(p.path))
                   for k, v in wanted.items() if current.get(k) != v]
        blockers = [f"Close {p.app} first: it rewrites its settings as it exits."] if p.app in running else []
        user_js = read_text(scan.host, p.path / "user.js") or ""
        clash = [k for k in wanted if f'"{k}"' in user_js]
        effects = list(side_effects) + ([f"user.js in this profile also sets {', '.join(clash)}, and wins at "
                                         "startup: edit it there too."] if clash else [])
        if actions:
            out.append(option(check, f"{label}: {p.label}", actions, side_effects=effects, blockers=blockers,
                              recommended=recommended, key=key))
    return out


POLICY_KEYS = {"Google Chrome": "chrome", "Chromium": "chromium", "Brave": "brave", "Microsoft Edge": "edge",
               "Vivaldi": "vivaldi"}


def chromium_policy_options(check: Check, scan: Scan, settings: dict, label: str, skip=None,
                            side_effects=()) -> list[Option]:
    """A policy file per natively installed Chromium-based browser (Flatpak and Snap installs
    don't read /etc), with only the settings its policies don't have yet: a browser whose policies
    already have them all (applied before, or set by someone else) gets no option, so a step is
    offered once, not again after it was applied. `skip` leaves out browsers that don't need it."""
    from .._util import chromium_policies
    out, seen = [], set()
    for d in chromium_dirs(scan.paths):
        key = next((v for k, v in POLICY_KEYS.items() if d.browser == k), None)
        if key is None or d.root.install != "native" or key in seen or (skip and skip(d)):
            continue
        seen.add(key)
        s = dict(settings)
        if key != "brave":
            s = {k: v for k, v in s.items() if not k.startswith("Brave")}
        have = chromium_policies(scan.host, d.browser)
        s = {k: v for k, v in s.items() if have.get(k) != v}
        if not s:
            continue
        from ...helper import POLICY_FILES
        out.append(option(check, f"{label}: {d.browser}, for every user (policy)",
                          [RootChange("browser_policy", {"browser": key, "settings": s},
                                      f"Write {POLICY_FILES[key]} with " + ", ".join(f"{k}={v}" for k, v in s.items()))],
                          side_effects=[*side_effects, f"{d.browser} shows \"Managed by your organization\" and the "
                                        "setting can no longer be changed in its settings page until this is "
                                        "reverted."]))
    return out


# ------------------------------------------------------------------ expiring files (user tmpfiles.d)
# A rule of the app's own in ~/.config/user-tmpfiles.d, applied by systemd's daily clean-up timer of
# the user's session (`systemd-tmpfiles --user --clean`). Mint and others ship the timer disabled:
# it is enabled as a listed, reversible step.

TMPFILES_TIMER = "systemd-tmpfiles-clean.timer"
TMPFILES_HEADER = "# Written by DA Privacy Kit. Revert the fix in the app's History to remove it.\n"


def tmpfiles_path(path) -> str:
    """A path as a tmpfiles.d field: specifiers escaped, quoted when it has spaces or quotes."""
    p = str(path).replace("%", "%%")
    if re.search(r'[\s"\\]', p):
        p = '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return p


def tmpfiles_available(scan: Scan) -> bool | No:
    return (bool(scan.host.runner.which("systemd-tmpfiles")) and unit_exists(scan, TMPFILES_TIMER, user=True)) or No(
        f"Files are set to expire with systemd's user clean-up timer ({TMPFILES_TIMER}), which this system doesn't "
        "have: delete old ones by hand from time to time.")


def expire_actions(scan: Scan, name: str, lines: list[str], text: str) -> list:
    """Writes ~/.config/user-tmpfiles.d/60-daprivacyscanner-<name>.conf with `lines` (unless it has
    them already) and enables the daily clean-up timer if it isn't."""
    from ...fix import UserUnitSet, WriteFile
    path = scan.paths.config_home / "user-tmpfiles.d" / f"60-daprivacyscanner-{name}.conf"
    content = TMPFILES_HEADER + "".join(ln + "\n" for ln in lines)
    acts = []
    if read_text(scan.host, path) != content:
        acts.append(WriteFile(path, lambda old: content, text, scan.host.display(path)))
    if systemctl_state(scan.host, "is-enabled", TMPFILES_TIMER, user=True) != "enabled":
        acts.append(UserUnitSet(TMPFILES_TIMER, True, "systemd's daily clean-up of your files, which applies the rule"))
    return acts


def expire_rule(scan: Scan, name: str) -> str | None:
    """The app's rule of that name, as written (None if there is none)."""
    return read_text(scan.host, scan.paths.config_home / "user-tmpfiles.d" / f"60-daprivacyscanner-{name}.conf")


SWAP_SIZE_NOTE = "Without swap on disk, hibernation isn't possible."
ZRAM_GENERATOR = "/usr/lib/systemd/system-generators/zram-generator"


def _zram_commands(scan: Scan) -> list[str]:
    pkg = install(scan, debian="systemd-zram-generator", arch="zram-generator", suse="zram-generator")
    cmds = [pkg] if pkg else []
    if family(scan) != "fedora":
        cmds += ["printf '[zram0]\\nzram-size = min(ram / 2, 8192)\\n' | sudo tee /etc/systemd/zram-generator.conf",
                 "sudo systemctl daemon-reload && sudo systemctl start /dev/zram0"]
    return cmds


def _zram_option(check: Check, scan: Scan) -> list[Option]:
    """zram-generator's configuration, written by the helper: only when zram-generator is installed,
    no zram is in use, and there is no configuration already (someone else's). Never with a
    writeback device."""
    host = scan.host
    if not host.sys_path(ZRAM_GENERATOR).exists() or any(n.startswith("/dev/zram") for n, _, _ in read_swaps(host)):
        return []
    if any(host.sys_path(f).exists() for f in ("/etc/systemd/zram-generator.conf", "/usr/lib/systemd/zram-generator.conf")):
        return []
    return [option(check, "Turn on zram (half of the memory, at most 8 GB)", [dropin(
        "zram", {"zram-size": "min(ram / 2, 8192)"}, "/etc/systemd/zram-generator.conf")],
        detail="zram-generator makes a compressed swap in memory, now and at every boot, and is used before the "
               "disk swap (it has the higher priority). Pages never go from it to the disk: no writeback device.",
        side_effects=["The disk swap stays set up until you take it out (the commands below): until then it is "
                      "still used once zram is full.", "Reverting leaves zram on until the next reboot."],
        recommended=True)]


def _swap_steps(check: Check, scan: Scan) -> list[Step]:
    swaps = [(n, k) for n, k, _ in read_swaps(scan.host) if not n.startswith("/dev/zram")]
    if not swaps:
        return []
    zram = _zram_option(check, scan)
    steps = [Step("Use compressed memory (zram) instead of swap on disk",
                  "zram keeps swapped-out pages compressed in RAM, so nothing is written to the disk. Then turn "
                  "the disk swap off and take it out of /etc/fstab so it isn't used again at the next boot.",
                  options=zram,
                  commands=(_zram_commands(scan) if not zram else []) + [f"sudo swapoff {n}" for n, _ in swaps]
                  + ["sudoedit /etc/fstab     # put a # in front of the swap line"],
                  side_effects=[SWAP_SIZE_NOTE, "Memory-hungry workloads have less room than with a large swap "
                                "partition.", "Never configure zram with a writeback device (writeback-device=): it "
                                "writes pages back to a disk, which is what this avoids."])]
    parts = [(n, k) for n, k in swaps if k == "partition"]
    if parts:
        cmds = []
        for n, _ in parts:
            r = scan.host.run("lsblk", "-no", "PARTUUID", n)
            partuuid = r.stdout.strip() if r.ok and r.stdout.strip() else "<PARTUUID of " + n + ">"
            cmds += [f"sudo swapoff {n}",
                     f"echo 'cryptswap PARTUUID={partuuid} /dev/urandom swap,cipher=aes-xts-plain64,size=512,"
                     "sector-size=4096' | sudo tee -a /etc/crypttab",
                     "sudoedit /etc/fstab     # replace the swap line with: /dev/mapper/cryptswap none swap defaults 0 0"]
        steps.append(Step("Or: encrypt the swap partition with a new random key at each boot",
                          "The partition is set up afresh with a random key every time the machine starts, so "
                          "what was swapped out before a reboot can never be read again. Check the PARTUUID "
                          "really is the swap partition: it is overwritten at every boot.",
                          commands=cmds, side_effects=[SWAP_SIZE_NOTE]))
    return steps


def _hibernate_off(check: Check, scan: Scan, recommended: bool = True) -> Step:
    return Step("Turn hibernation off",
                "Stops the machine from ever writing its memory to the swap device. Suspend (sleep) still works.",
                options=[option(check, "Turn hibernation off", [dropin(
                    "sleep", {"AllowHibernation": "no", "AllowSuspendThenHibernate": "no", "AllowHybridSleep": "no"},
                    "/etc/systemd/sleep.conf.d/60-daprivacyscanner.conf")], recommended=recommended)],
                side_effects=["Hibernate stops working and leaves the power menu (on some desktops only after "
                              "you log in again); a laptop whose battery runs flat while suspended loses unsaved "
                              "work."])




# the guides themselves, one module per category; importing them registers them
from . import advice, apps, auth, browser, desktop, encryption, kernel, network, sandbox, telemetry  # noqa: E402


MODULES = (advice, apps, auth, browser, desktop, encryption, kernel, network, sandbox, telemetry)
