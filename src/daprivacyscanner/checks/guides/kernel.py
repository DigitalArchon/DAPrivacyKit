"""Guided fixes: kernel (see the package docstring)."""

from __future__ import annotations

from ...fix import RootChange
from ...guide import Guide, Step
from .._util import isfile
from . import guide, option, dropin, os_release, family, install


@guide("kern.updates")
def updates(check, scan, outcome):
    fam, (os_id, _) = family(scan), os_release(scan)
    cmd = {"debian": "sudo apt update && sudo apt upgrade", "fedora": "sudo dnf upgrade --refresh",
           "arch": "sudo pacman -Syu", "suse": "sudo zypper update"}.get(fam or "")
    steps = [Step("Install the updates", "Mint's Update Manager does the same." if os_id == "linuxmint" else "",
                  commands=[cmd] if cmd else [])]
    found = getattr(outcome, "findings", {}) or {}
    if found.get("kernel_update_pending") or found.get("kernel_restart_pending"):
        steps.append(Step("Restart", "A new kernel (or CPU microcode) is only put to work by a restart: until then "
                          "the old one keeps running, with the flaws the update fixes."))
    if any(e.label == "Firmware updates" for e in outcome.evidence):
        steps.append(Step("Install the firmware updates",
                          "Firmware is the software inside the computer's own parts (the mainboard, the drive, a "
                          "dock): its updates come through fwupd, not the package manager. Keep a laptop plugged "
                          "in; some are installed during a restart, which the command asks for. The desktop's "
                          "software centre (GNOME Software, Discover) or Firmware app does the same.",
                          commands=["fwupdmgr get-updates", "fwupdmgr update"]))
    if os_id == "linuxmint":
        steps.append(Step("Install updates automatically", "Update Manager → Edit → Preferences → Automation → "
                          "Automatic updates."))
    elif fam == "debian":
        auto = any(e.label == "Automatic security updates" and e.value == "on" for e in outcome.evidence)
        if isfile(scan.host.sys_path("/usr/bin/unattended-upgrade")):
            steps.append(Step("Install security updates automatically", options=[option(
                check, "Turn on unattended-upgrades", [dropin("apt-auto", {"APT::Periodic::Update-Package-Lists": "1",
                                                                           "APT::Periodic::Unattended-Upgrade": "1"},
                                                              "/etc/apt/apt.conf.d/52daprivacyscanner-auto-upgrades")],
                side_effects=["Security updates are downloaded and installed daily in the background."])],
                done=auto))
        else:
            steps.append(Step("Install security updates automatically",
                              commands=["sudo apt install unattended-upgrades",
                                        "sudo dpkg-reconfigure -plow unattended-upgrades"], done=auto))
    elif fam == "fedora":
        steps.append(Step("Install updates automatically", "DNF5 (Fedora 41 and later): install the plugin, set "
                          "apply_updates = yes in /etc/dnf/automatic.conf, enable the timer. DNF4: the -install timer.",
                          commands=["sudo dnf install dnf5-plugin-automatic",
                                    "sudo systemctl enable --now dnf5-automatic.timer",
                                    "sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer"]))
    return Guide(check.id, "Install pending updates", "", steps)


@guide("kern.ptrace_scope", keys=("scope_1",))
def ptrace(check, scan, outcome):
    return Guide(check.id, "Stop processes reading each other's memory", "", [
        Step("Restrict ptrace to a process's own children", options=[option(check, "Set ptrace_scope to 1", [
            RootChange("set_sysctl", {"key": "kernel.yama.ptrace_scope", "value": "1"},
                       "sysctl kernel.yama.ptrace_scope=1 (now)"),
            dropin("sysctl", {"kernel.yama.ptrace_scope": "1"}, "/etc/sysctl.d/60-daprivacyscanner.conf")],
            recommended=True, key="scope_1")],
            side_effects=["Debuggers (gdb, strace) can only attach to programs they start, unless run with sudo."]),
    ])


SLEEP_DELAY_DROPIN = "/etc/systemd/sleep.conf.d/60-daprivacyscanner-delay.conf"
LOGIND_DROPIN = "/etc/systemd/logind.conf.d/60-daprivacyscanner.conf"


@guide("kern.suspend_keys_in_ram")
def suspend_keys(check, scan, outcome):
    from ... import blockdev
    from .._util import read_text
    from ..encryption import hibernation_encrypted
    from ..kernel import sleep_setup
    steps = [Step("Shut down when you travel",
                  "A machine that is off has no keys in memory. Asleep, it keeps the disk unlocked in RAM, where "
                  "someone holding it can try to read them (DMA through a port, or chilling and moving the memory).")]
    off = read_text(scan.host, scan.host.sys_path("/etc/systemd/sleep.conf.d/60-daprivacyscanner.conf")) or ""
    ok = hibernation_encrypted(scan)
    how, where, _ = sleep_setup(scan)
    desk = scan.context.desktop
    cinnamon = bool(set(desk.names) & {"x-cinnamon", "cinnamon"})
    later = ("If hibernation later stops working (the swap made smaller or removed, the swap file moved, Secure Boot's "
             "kernel lockdown turned on), closing the lid quietly goes back to plain suspend, keys in memory and all: "
             "only a line in the system log says so. This check shows it at the next scan.")
    if how in ("hibernate", "suspend-then-hibernate") and ok:
        steps.append(Step("Hibernate after a while asleep", f"Set up in {where}: closing the lid "
                          + ("hibernates the computer." if how == "hibernate" else "suspends it, then hibernates it."),
                          done=True))
    elif "AllowHibernation=no" in off:
        steps.append(Step("Hibernate after a while asleep",
                          "Hibernation was turned off by this app (enc.hibernate_unencrypted): revert that from History "
                          "first, if you want this.", done=False))
    elif ok and desk.is_kde:
        # PowerDevil handles the lid itself (it holds logind's lid inhibitor): logind's HandleLidSwitch doesn't apply
        steps.append(Step("Hibernate after a while asleep",
                          "Hibernation works here and writes to encrypted storage, so a sleeping laptop can go on to "
                          "hibernate, which leaves nothing readable in memory. Plasma decides what closing the lid does: "
                          "in System Settings → Power Management, on the On Battery tab (and On AC Power, if you like), "
                          "set When laptop lid closed to Sleep, and When sleeping, enter to Standby, then hibernate. "
                          "How long it stays asleep first is systemd's setting, below.",
                          options=[option(check, f"Hibernate {label} asleep", [
                              dropin("sleep-delay", {"HibernateDelaySec": delay}, SLEEP_DELAY_DROPIN)],
                              recommended=rec, side_effects=["Waking from hibernation takes longer and asks for the "
                                                             "disk passphrase again.", later])
                              for delay, label, rec in (("1h", "after 1 hour", True), ("3h", "after 3 hours", False))]))
    elif ok and cinnamon:
        # Cinnamon's settings daemon handles the lid itself and has no suspend-then-hibernate: hibernate on the lid
        steps.append(Step("Hibernate when the lid is closed",
                          "Hibernation works here and writes to encrypted storage. Cinnamon decides what closing the lid "
                          "does, and has no \"suspend, then hibernate\": in System Settings → Power Management, set When "
                          "the lid is closed to Hibernate (on battery, and on AC power if you like). The keys then leave "
                          "memory as soon as the lid closes.",
                          side_effects=["Waking takes longer and asks for the disk passphrase again.", later]))
    elif ok:
        opts = []
        for delay, label, rec in (("1h", "after 1 hour", True), ("3h", "after 3 hours", False)):
            opts.append(option(check, f"Suspend, then hibernate {label}", [
                dropin("sleep-delay", {"HibernateDelaySec": delay}, SLEEP_DELAY_DROPIN),
                dropin("logind-sleep", {"HandleLidSwitch": "suspend-then-hibernate",
                                        "HandleSuspendKey": "suspend-then-hibernate"}, LOGIND_DROPIN)],
                recommended=rec, side_effects=[
                    "Closing the lid or pressing the suspend key suspends as before; if the machine is still asleep "
                    f"{label}, it hibernates and powers off, and the keys leave memory.",
                    "Waking from hibernation takes longer and asks for the disk passphrase again.",
                    "Suspend from the power menu still only suspends. A desktop that handles the lid itself (KDE "
                    "Plasma, Cinnamon) has its own setting for it, in its power settings.", later]))
        steps.append(Step("Hibernate after a while asleep",
                          "Hibernation works here and writes to encrypted storage, so a sleeping machine can go on to "
                          "hibernate, which leaves nothing readable in memory.", options=opts))
    else:
        steps.append(Step("Hibernate after a while asleep",
                          "Needs hibernation to work, with its image on encrypted storage" +
                          (" (see enc.hibernate_unencrypted)." if ok is False and scan.context["hibernation"] else
                           "; it isn't set up that way here.")))
    root = blockdev.holding(scan.context.devices or [], "/")
    if family(scan) == "debian" and root is not None and root.encrypted:
        cmd = install(scan, debian="cryptsetup-suspend")
        installed = how == "cryptsetup-suspend"
        steps.append(Step("Or: lock the disk while asleep (cryptsetup-suspend)",
                          "It is installed: on suspend it locks the encrypted disk and wipes its key from memory." if
                          installed else
                          "Debian and Ubuntu package it: on suspend it locks the encrypted disk and wipes its key from "
                          "memory, and on resume it asks for the passphrase before the desktop comes back.",
                          done=installed, commands=[cmd] if cmd and not installed else [], side_effects=[
                              "You type the disk passphrase at every resume.",
                              "It needs the root filesystem on LUKS unlocked by passphrase (not by TPM), and "
                              "initramfs-tools."]))
    return Guide(check.id, "Get the disk keys out of memory while asleep", "", steps)
