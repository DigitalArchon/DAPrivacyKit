"""How-to guides for advice checks: what to do, for this machine, as steps and commands the user
runs. The app makes none of these changes itself (rule 5), so these guides never offer options;
the runner refuses one that does."""

from __future__ import annotations

import re
import shlex

from ...guide import Guide, Step
from .._util import isfile, read_text
from . import FLATHUB_ADD, evidence, family, guide, install, os_release


# ------------------------------------------------------------------ kernel boot options

def kernel_option_steps(scan, args: str) -> list[Step]:
    """How to set `args` (param=value) on the kernel command line with this machine's bootloader, then restart. The
    kernel uses the last param= it is given, so an existing one is taken out and the new one goes at the end: adding a
    copy in front of an old init_on_alloc=0 changed nothing."""
    host = scan.host
    fam = family(scan)
    param = args.split("=", 1)[0]
    has = lambda p: isfile(host.sys_path(p))          # noqa: E731
    if has("/usr/bin/limine-update"):                 # CachyOS and others with limine-entry-tool
        # /etc/default/limine is read last: a plain "=" there replaces what drop-ins add ("+=" lines are
        # joined with a space, as the tool's own examples show)
        default = read_text(host, host.sys_path("/etc/default/limine")) or ""
        if re.search(r"^\s*KERNEL_CMDLINE\[default\]\s*=", default, re.M):
            text = ("Limine's entries are made by limine-entry-tool, from the KERNEL_CMDLINE[default]= line in "
                    f"/etc/default/limine: add {args} inside its quotes, after the other options (and delete any other "
                    f"{param}= there), then write the entries again.")
            cmds = ["sudoedit /etc/default/limine", "sudo limine-update"]
        else:
            text = ("Limine's entries are made by limine-entry-tool: a drop-in file adds the option to every kernel's "
                    "entry, after the others (the kernel uses the last one given), and limine-update writes them "
                    "again.")
            cmds = ["sudo mkdir -p /etc/limine-entry-tool.d",
                    f"echo 'KERNEL_CMDLINE[default]+={args}' | sudo tee /etc/limine-entry-tool.d/60-daprivacyscanner.conf",
                    "sudo limine-update"]
    elif has("/etc/sdboot-manage.conf"):
        text = ("sdboot-manage writes the systemd-boot entries: add the option at the end of the LINUX_OPTIONS line of "
                f"/etc/sdboot-manage.conf (and delete any other {param}= on it), then write the entries again.")
        cmds = ["sudoedit /etc/sdboot-manage.conf", "sudo sdboot-manage gen"]
    elif fam == "fedora" and host.runner.which("grubby"):
        text = ("Fedora keeps the kernel options with grubby, for every installed kernel and future ones: it takes out "
                f"any {param}= there is, then adds this one.")
        cmds = [f'sudo grubby --update-kernel=ALL --remove-args="{param}" --args="{args}"']
    elif has("/etc/kernel/cmdline"):
        text = ("The kernel options are in /etc/kernel/cmdline (systemd-boot or unified kernel images): the first "
                f"command takes out any {param}= on its line and adds the option at the end, the second installs the "
                "kernels again so their entries pick it up.")
        cmds = [f"sudo sed -i -E '1s/(^| ){re.escape(param)}=[^ ]*//g; 1s/$/ {args}/' /etc/kernel/cmdline",
                "sudo kernel-install add-all"]
    elif has("/etc/default/grub"):
        regen = {"debian": "sudo update-grub", "arch": "sudo grub-mkconfig -o /boot/grub/grub.cfg",
                 "suse": "sudo grub2-mkconfig -o /boot/grub2/grub.cfg",
                 "fedora": "sudo grub2-mkconfig -o /boot/grub2/grub.cfg"}.get(fam or "", "sudo update-grub")
        text = ("GRUB reads the kernel options from GRUB_CMDLINE_LINUX and GRUB_CMDLINE_LINUX_DEFAULT in "
                f"/etc/default/grub. The first command takes out any {param}= on those lines and adds the option at "
                "the end of the second (the kernel uses the last one given); the next rebuilds GRUB's menu.")
        cmds = ["sudo sed -i -E -e '/^GRUB_CMDLINE_LINUX(_DEFAULT)?=/s/(\"| )" + re.escape(param) + "=[^\" ]*/\\1/g' "
                f"-e 's/^(GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*)\"/\\1 {args}\"/' /etc/default/grub", regen]
    else:
        text = (f"Add {args} to the kernel command line in your bootloader's configuration; the app couldn't tell "
                "which bootloader this computer uses.")
        cmds = []
    return [Step(f"Add {args} to the kernel options", text, commands=cmds),
            Step("Restart and check", "After a restart the option shows in the kernel's command line.",
                 commands=["cat /proc/cmdline"])]


@guide("kern.init_on_free")
def init_on_free(check, scan, outcome):
    return Guide(check.id, "Wipe memory as it is freed", "This costs a few percent of speed on memory-heavy work, in "
                 "exchange for freed memory not keeping its old contents.", kernel_option_steps(scan, "init_on_free=1"))


@guide("kern.init_on_alloc")
def init_on_alloc(check, scan, outcome):
    return Guide(check.id, "Zero kernel memory when it is handed out", "Almost free, and on by default in nearly "
                 "every distribution's kernel.", kernel_option_steps(scan, "init_on_alloc=1"))


@guide("kern.dma")
def dma(check, scan, outcome):
    intel = "GenuineIntel" in (scan.host.read_sys("/proc/cpuinfo") or "")[:2000]
    iommu_off = any(e.label == "IOMMU" and e.value == "not active" for e in outcome.evidence)
    steps = [Step("Turn on the IOMMU and DMA protection in the firmware",
                  "Restart into the firmware setup and look for VT-d (Intel) or IOMMU / AMD-Vi (AMD), and for "
                  "Thunderbolt security or \"Kernel DMA protection\". Turn them on. The command restarts straight "
                  "into the firmware setup on most computers.", commands=["systemctl reboot --firmware-setup"])]
    if iommu_off and intel:
        steps += kernel_option_steps(scan, "intel_iommu=on")
    steps.append(Step("Only allow devices you know",
                      "With a Thunderbolt security level of \"user\" or \"secure\" (set in the firmware), new devices "
                      "must be approved before they get access. bolt lists them; forget any you don't recognise.",
                      commands=["boltctl list", "boltctl forget DEVICE-UUID"]))
    return Guide(check.id, "Protect memory from Thunderbolt and USB4 devices", "", steps)


@guide("kern.usb_trusted")
def usb_trusted(check, scan, outcome):
    pkg = install(scan, debian="usbguard", fedora="usbguard", arch="usbguard", suse="usbguard")
    group = "sudo" if family(scan) == "debian" else "wheel"
    steps = [Step("Install USBGuard", "It is in every major distribution's packages.",
                  commands=[pkg or "Install the usbguard package with your package manager"]),
             Step("Allow what is plugged in now, then start it",
                  "Plug in everything you use first: keyboard, mouse, dock, security key, phone cable. The policy "
                  "lists the devices connected at this moment; anything else is blocked once it runs, including a "
                  "USB keyboard plugged in later.",
                  commands=["sudo sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'",
                            "sudo chmod 600 /etc/usbguard/rules.conf",
                            "sudo systemctl enable --now usbguard.service"]),
             Step("Allow a new device", "A device plugged in later stays blocked until you allow it; -p keeps it "
                  "allowed after a restart.",
                  commands=["sudo usbguard list-devices --blocked", "sudo usbguard allow-device -p ID     # ID from the list"])]
    if scan.context.desktop.is_gnome:
        steps.append(Step("Or, on GNOME: block new devices only while the screen is locked",
                          f"GNOME Shell asks USBGuard to let devices in while you are logged in and the screen is "
                          f"unlocked. It needs permission to talk to USBGuard: add your administrators' group "
                          f"(IPCAllowedGroups={group}) to its settings, restart it, then switch GNOME's protection on.",
                          commands=["sudoedit /etc/usbguard/usbguard-daemon.conf     # IPCAllowedGroups=" + group,
                                    "sudo systemctl restart usbguard.service",
                                    "gsettings set org.gnome.desktop.privacy usb-protection true",
                                    "gsettings set org.gnome.desktop.privacy usb-protection-level lockscreen"]))
    return Guide(check.id, "Only let in the USB devices you allow",
                 "If USBGuard blocks your keyboard you can't type your password, so make the policy with it plugged "
                 "in. Undo: sudo systemctl disable --now usbguard.service.", steps)


def _home_quote(shown: str) -> str:
    """A path as shown (~/...) quoted for a shell, leaving the ~ outside the quotes so it still expands."""
    return "~/" + shlex.quote(shown[2:]) if shown.startswith("~/") else shlex.quote(shown)


@guide("app.login_items")
def login_items(check, scan, outcome):
    from ..apps import autostart_entries, crontab_entries, enabled_user_units, path_shadows
    names = set(scan.context.desktop.names)
    if names & {"x-cinnamon", "cinnamon"}:
        where = ("Cinnamon: Menu → Preferences → Startup Applications; switch an entry off there, or remove one you "
                 "added.", ["cinnamon-settings startup"])
    elif scan.context.desktop.is_kde:
        where = ("Plasma: System Settings → Autostart (or Startup and Shutdown → Autostart) lists programs and scripts; "
                 "select one and Remove it.", ["systemsettings kcm_autostart"])
    elif "xfce" in names:
        where = ("Xfce: Settings → Session and Startup → Application Autostart; untick an entry.",
                 ["xfce4-session-settings"])
    elif scan.context.desktop.is_gnome:
        where = ("GNOME: Tweaks → Startup Applications (install GNOME Tweaks if it's missing), or Settings → Apps, "
                 "where an app may have \"Run in background\" switched on. To stop an entry from the system, copy it "
                 "into ~/.config/autostart and add Hidden=true.", ["gnome-tweaks"])
    else:
        where = ("Your desktop's startup settings list them. An entry from the system can be turned off for you by "
                 "copying it into ~/.config/autostart and adding Hidden=true.", [])
    steps = [Step("Programs that start with your desktop", where[0], commands=where[1])]
    units = [i for i in enabled_user_units(scan) if i.yours]
    if units:
        steps.append(Step("User services", "These run under your account's systemd. Turn one off (and stop it now):",
                          commands=[f"systemctl --user disable --now {i.item.removeprefix('user unit ')}"
                                    for i in units[:10]]))
    cron, _, _ = crontab_entries(scan)
    if cron:
        steps.append(Step("Your crontab", "Opens it in an editor; delete a line, or put a # in front of it, to stop "
                          "it running.", commands=["crontab -e"]))
    _, shadows = path_shadows(scan)
    if shadows:
        steps.append(Step("Programs that take the place of the system's",
                          "A program in your own folder runs instead of the system's of the same name. If you didn't "
                          "put one there yourself (a tool you installed with pip, cargo or npm does), delete it:",
                          commands=[f"rm {_home_quote(i.item.split('(', 1)[1].rstrip(')'))}" for i in shadows[:10]]))
    autostart = [i for i in autostart_entries(scan) if i.yours]
    if autostart:
        steps.append(Step("Or remove an autostart entry by hand", "Deleting the file stops it starting; the program "
                          "itself stays installed.",
                          commands=[f"rm {_home_quote(i.item)}" for i in autostart[:10]]))
    return Guide(check.id, "Turn off what you don't want starting by itself",
                 "Look at each entry marked new since the last scan first. If you don't know a program, search for its "
                 "name before removing it: some belong to your desktop or your hardware.", steps)


@guide("kern.proc_hidepid")
def proc_hidepid(check, scan, outcome):
    return Guide(check.id, "Hide your programs from other accounts",
                 "/proc can hide each account's processes from the others (hidepid=invisible). Some system services "
                 "need to see every process, so they are given a group that can. Test it with a second terminal open "
                 "as root, so a mistake can be undone.", [
                     Step("Create the group that may see every process, and give it to logind and polkit",
                          "systemd-logind needs to see sessions' processes, or logins can break; polkit needs to see "
                          "the program asking for administrator access, or every admin prompt (pkexec, this app's "
                          "included) is refused.",
                          commands=["getent group proc || sudo groupadd -r proc",
                                    "sudo mkdir -p /etc/systemd/system/systemd-logind.service.d "
                                    "/etc/systemd/system/polkit.service.d",
                                    "printf '[Service]\\nSupplementaryGroups=proc\\n' | sudo tee "
                                    "/etc/systemd/system/systemd-logind.service.d/hidepid.conf "
                                    "/etc/systemd/system/polkit.service.d/hidepid.conf",
                                    "sudo systemctl daemon-reload"]),
                     Step("Restart the computer", "logind and polkit only get the group when they start again; "
                          "trying hidepid before that can break logins and admin prompts."),
                     Step("Try it now", "Takes effect at once, until the next restart. Log out and in, and use an "
                          "administrator prompt, before making it last.",
                          commands=["sudo mount -o remount,hidepid=invisible,gid=proc /proc"]),
                     Step("Make it last", "Add this line to /etc/fstab.",
                          commands=["echo 'proc /proc proc defaults,hidepid=invisible,gid=proc 0 0' | sudo tee -a "
                                    "/etc/fstab"]),
                     Step("If something breaks", "Monitoring tools, polkit prompts or a desktop component that can't "
                          "see processes are the usual suspects. Undo it now, then remove the line from /etc/fstab.",
                          commands=["sudo mount -o remount,hidepid=off /proc"]),
                 ])


# ------------------------------------------------------------------ encryption

INSTALLER_OPTION = {
    "ubuntu": "In the installer, choose Advanced features, then \"Use LVM and encryption\".",
    "linuxmint": "In the installer, choose \"Advanced features\" and tick \"Encrypt the new Linux Mint installation\".",
    "fedora": "In the installer's Installation Destination, tick \"Encrypt my data\".",
    "debian": "In the installer's partitioning step, choose \"Guided - use entire disk and set up encrypted LVM\".",
    "cachyos": "In the installer's partitioning step, tick \"Encrypt system\".",
    "arch": "With archinstall, choose disk encryption in the Disk configuration; or follow the wiki's dm-crypt guide.",
    "opensuse-tumbleweed": "In the installer's Suggested Partitioning, choose Guided Setup and tick \"Enable Disk Encryption\".",
}


@guide("enc.fde_missing")
def fde_missing(check, scan, outcome):
    os_id, like = os_release(scan)
    how = INSTALLER_OPTION.get(os_id) or next((INSTALLER_OPTION[i] for i in like if i in INSTALLER_OPTION),
                                              "In the installer, look for the option to encrypt the disk.")
    steps = []
    if scan.context["fde"] == "home":
        from ...context import home_encryption
        method, _ = home_encryption(scan.host, scan.context.devices)
        if method == "ecryptfs":
            text = ("Your home folder is encrypted with eCryptfs. It still protects your files' contents for now, but "
                    "it is barely maintained and no longer recommended: move to full-disk encryption at the next "
                    "reinstall below, and don't choose \"encrypt my home folder\" again. Until then, keep it.")
        elif method == "fscrypt":
            text = ("Your home folder is encrypted with fscrypt, the filesystem's own encryption: better than eCryptfs, "
                    "but the rest of the system isn't covered. Keep it until you reinstall with full-disk encryption.")
        else:
            text = ("Your home folder's volume is encrypted, but the system disk isn't: its logs, swap and /tmp are "
                    "readable, and it can be changed to record your password. Full-disk encryption covers both.")
        steps.append(Step("Your encrypted home folder", text))
    steps += [Step("Back up everything", "Copy your files to another drive (and check the copy opens). Note the apps "
                   "you use; settings in your home folder come back with the files."),
             Step("Reinstall with encryption", how + " Choose a long passphrase: five or more random words. Then "
                  "restore your files."),
             Step("Or convert the disk in place (risky)",
                  "cryptsetup can encrypt an existing filesystem from a live USB, after shrinking it to make room. A "
                  "power cut or mistake loses everything on it, the boot setup (crypttab, initramfs, bootloader) has "
                  "to be changed by hand afterwards, and the old unencrypted data stays readable in places it never "
                  "overwrites. Only with a full backup, and only if reinstalling isn't possible.",
                  commands=["sudo cryptsetup reencrypt --encrypt --reduce-device-size 32M /dev/PARTITION"])]
    if scan.context["virtualization"] == "vm":
        steps.append(Step("Inside a virtual machine", "Encrypt the host's disk too: whoever has the host's disk has "
                          "this machine's disk image."))
    return Guide(check.id, "Encrypt the whole disk", "", steps)


@guide("enc.partial_fde")
def partial_fde(check, scan, outcome):
    plain = [e.value for e in outcome.evidence if "not encrypted" in str(e.label).lower() or "Not encrypted" in str(e.label)]
    return Guide(check.id, "Encrypt the rest of the disk", "", [
        Step("Which filesystems", ("Not encrypted: " + ", ".join(map(str, plain)) + ".") if plain else
             "The evidence lists the filesystems that aren't encrypted."),
        Step("Back up what is on them", "Copy the files elsewhere and check the copy."),
        Step("Format each with encryption",
             "For a data partition: in Disks (GNOME) or KDE Partition Manager, format it with \"Password protect volume "
             "(LUKS)\", then copy the files back. To unlock it at boot with the rest, add it to /etc/crypttab. For "
             "/home or the system itself, reinstalling with full-disk encryption is the safer route "
             "(see enc.fde_missing).", commands=["gnome-disks", "partitionmanager"]),
    ])


@guide("enc.unmounted_unencrypted")
def unmounted_unencrypted(check, scan, outcome):
    """What to do with each partition this system doesn't use: encrypt it where it belongs, or clear it."""
    from ... import blockdev
    from ..encryption import partition_text, unused_partitions
    try:
        plain, _ = unused_partitions(blockdev.read_partitions(scan.host))
    except blockdev.LsblkError:
        plain = []
    fs = lambda d: (d.fstype or "").lower()                                   # noqa: E731
    windows = [d for d in plain if fs(d) in ("ntfs", "refs")]
    mac = [d for d in plain if fs(d) in ("apfs", "hfsplus", "hfs")]
    rest = [d for d in plain if d not in windows and d not in mac]
    listed = "; ".join(f"{d.path} ({partition_text(d)})" for d in plain)
    steps = [Step("Which partitions",
                  (f"Not encrypted, and not in use by this system: {listed}. " if listed else
                   "The evidence lists the partitions. ")
                  + "To see what is on one, open it in the file manager (it is listed under the other drives), or "
                  "look at the drive in Disks or KDE Partition Manager.", commands=["gnome-disks", "partitionmanager"])]
    if windows:
        steps.append(Step(
            "A Windows partition: encrypt it from Windows",
            "Start Windows and open Settings → Privacy & security → Device encryption (on Home editions, where the "
            "computer supports it) or BitLocker Drive Encryption (Pro). Windows offers to keep the recovery key in "
            "your Microsoft account, where Microsoft can read it: choose to print it or save it to a file on another "
            "drive instead. Where neither is offered, VeraCrypt can encrypt the Windows system drive. Afterwards "
            "this system reads the partition only with that key (cryptsetup's BitLocker support, or Disks), and this "
            "check counts it as encrypted. Windows' own drive (" + ", ".join(d.path for d in windows[:4])
            + ") holds its hibernation and page files too: what was in memory when it last slept."))
    if mac:
        steps.append(Step("A macOS partition: turn on FileVault",
                          "Start macOS and open System Settings → Privacy & Security → FileVault."))
    if rest:
        steps.append(Step(
            "A partition you still use: encrypt it here",
            "Copy its files to another drive and check the copy. Then format the partition with a password (Disks: "
            "the gear menu → Format Partition → \"Password protect volume (LUKS)\"; KDE Partition Manager: delete it, "
            "create a new one and tick Encrypt with LUKS) and copy the files back. A partition shared with Windows "
            "or macOS can't be LUKS: VeraCrypt works on all three."
            + (" These: " + ", ".join(d.path for d in rest[:6]) + "." if rest else ""),
            commands=["gnome-disks", "partitionmanager"]))
    steps.append(Step(
        "A partition you no longer need: clear it",
        "Deleting or formatting a partition doesn't erase what it held: the files stay readable in the unused space "
        "until something else is written there. Formatting it with a password (LUKS), as above, and using it from "
        "then on protects what is written afterwards. On an SSD or NVMe drive, \"sudo blkdiscard\" followed by the "
        "partition's device tells the drive to drop everything on that partition at once: run it only on a partition "
        "you have checked twice, since nothing on it can be had back. For a whole drive you are parting with, see "
        "Retire a drive in Tools."))
    steps.append(Step("Check again", "Scan again: an encrypted partition is listed as encrypted, and the finding "
                      "goes when none is left."))
    return Guide(check.id, "Protect the partitions this system doesn't use",
                 "Disk encryption covers only the partitions it was set up on. Each one here belongs to something "
                 "else: another operating system, an earlier installation, or a disk that isn't in use.", steps)


@guide("net.local_root_certs")
def local_root_certs(check, scan, outcome):
    """What each added root certificate is, and the commands that remove one and rebuild the store."""
    from ..network import local_roots
    roots = local_roots(scan)
    fam = family(scan)
    remove = {"debian": "sudo rm {f} && sudo update-ca-certificates --fresh",
              "fedora": "sudo rm {f} && sudo update-ca-trust", "arch": "sudo trust anchor --remove {f}",
              "suse": "sudo rm {f} && sudo update-ca-certificates"}.get(fam or "")
    steps = [
        Step("See what each one is",
             "The subject and issuer name who made it, the dates say for how long it counts. Ones you may know: a "
             "workplace's or school's (their proxy reads your HTTPS traffic by design), an antivirus or \"web "
             "protection\" product's, a developer tool's (mitmproxy, Charles, mkcert), or one you made yourself.",
             commands=[f"openssl x509 -noout -subject -issuer -dates -in {shlex.quote(f)}" for f in roots[:6]]
             or ["trust list --filter=ca-anchors"]),
        Step("Remove the ones you don't know or no longer need",
             "The command deletes the file and rebuilds the store, so programs stop trusting it from their next "
             "start. If a program on this computer installed it (an antivirus, a proxy tool), turn off its HTTPS "
             "scanning or uninstall it first, or it puts the certificate back. One your workplace installed on its "
             "own computer is theirs to remove.",
             commands=[remove.format(f=shlex.quote(f)) for f in roots[:6]] if remove else []),
        Step("Look in the browsers too",
             "Firefox: Settings → Privacy & Security → Certificates → View Certificates → Authorities; entries you "
             "added show under their own name and can be deleted there. Chromium-based browsers: "
             "chrome://certificate-manager, under the certificates you installed."),
        Step("See whether one is in use right now", "The online test net.tls_interception connects to a few known "
             "sites and says who issued the certificates this computer was shown."),
    ]
    return Guide(check.id, "Review the root certificates added to this computer",
                 "A root certificate vouches for every website. One that was added here lets whoever holds its key "
                 "stand in between, unseen.", steps)


@guide("enc.removable_unencrypted")
def removable_unencrypted(check, scan, outcome):
    return Guide(check.id, "Encrypt a removable drive", "", [
        Step("Copy its files off", "Formatting erases the drive."),
        Step("Format it with encryption",
             "Disks (GNOME): select the drive, then the partition, the gear menu, Format Partition, and choose "
             "\"Internal disk for use with Linux systems only\" with \"Password protect volume (LUKS)\". KDE Partition "
             "Manager: delete the partition, create a new one and tick Encrypt with LUKS.",
             commands=["gnome-disks", "partitionmanager"]),
        Step("If it must also work on Windows or macOS",
             "They can't open LUKS drives. VeraCrypt works on all three, or keep sensitive files in an encrypted "
             "archive on the drive."),
        Step("Copy the files back", "The desktop asks for the passphrase each time you plug it in."),
    ])


# Where the key that signs the drivers built on this machine (DKMS, akmods) is kept, by the tool that makes it: shim-signed
# on Debian, Ubuntu and Mint (seen on Mint 22.3: NVIDIA's DKMS module signed by it), dkms 3 elsewhere (DER, whatever its
# name says), Fedora's akmods
MOK_KEYS = ("/var/lib/shim-signed/mok/MOK.der", "/var/lib/dkms/mok.pub", "/etc/pki/akmods/certs/public_key.der")


def mok_state(scan) -> tuple[str, str | None]:
    """("enrolled" | "queued" | "missing" | "unknown" | "none", the key file) for the key that signs the drivers this
    machine builds itself: whether the firmware's shim will trust them once Secure Boot is on. mokutil --test-key reads
    the enrolled and pending lists, which every account may read (tested on Mint 22.3)."""
    key = next((k for k in MOK_KEYS if isfile(scan.host.sys_path(k))), None)
    if key is None:
        return "none", None
    r = scan.host.run("mokutil", "--test-key", key)
    said = r.stdout + r.stderr
    for words, state in (("is already enrolled", "enrolled"), ("already in the enrollment request", "queued"),
                         ("is not enrolled", "missing")):
        if words in said:
            return state, key
    return "unknown", key


def built_modules(scan) -> list[str]:
    """The drivers built on this machine for the running kernel (DKMS's updates/dkms, akmods' extra), by name."""
    release = (scan.host.read_sys("/proc/sys/kernel/osrelease") or "").strip()
    if not release:
        return []
    names = set()
    for base in (f"/usr/lib/modules/{release}/updates/dkms", f"/lib/modules/{release}/updates/dkms",
                 f"/usr/lib/modules/{release}/extra", f"/lib/modules/{release}/extra"):
        for p in scan.host.sys_path(base).rglob("*.ko*") if scan.host.sys_path(base).is_dir() else []:
            names.add(p.name.split(".ko")[0])
    return sorted(names)


def _mok_step(scan) -> tuple[str, Step | None]:
    """What turning Secure Boot on means for the drivers built here: a sentence for the firmware step, and a step that
    enrols their key first when the firmware doesn't trust it yet (they wouldn't load: NVIDIA's driver among them)."""
    state, key = mok_state(scan)
    modules = built_modules(scan)
    which = (f" ({', '.join(modules[:4])}{', …' if len(modules) > 4 else ''})" if modules else "")
    if state == "enrolled":
        return (f" The key that signs the drivers built on this machine{which} is enrolled already, so they keep "
                "loading."), None
    if state == "queued":
        return (f" The key that signs the drivers built on this machine{which} is waiting to be enrolled: at the next "
                "restart a blue screen (MokManager) asks for it. Choose Enroll MOK, Continue, Yes, and type the password "
                "chosen when it was imported."), None
    if state == "missing":
        return "", Step("First: enrol the key that signs the drivers built on this machine",
                        f"This computer builds some drivers itself{which} and signs them with a key of its own ({key}), "
                        "which the firmware doesn't trust yet: with Secure Boot on they wouldn't load (without NVIDIA's "
                        "driver, the screen falls back to a basic one). The first command asks you to choose a one-time "
                        "password. At the next restart a blue screen (MokManager) appears: choose Enroll MOK, Continue, "
                        "Yes, and type that password. The second command then says it is enrolled; turn Secure Boot on "
                        "only after that.",
                        commands=[f"sudo mokutil --import {key}", f"mokutil --test-key {key}"],
                        side_effects=["The blue screen waits about ten seconds for a key press, then starts the "
                                      "computer without enrolling: import it again then."])
    return (" If you use drivers built on this machine (NVIDIA's, VirtualBox's), their signing key has to be enrolled "
            "first (sudo mokutil --import with the key's file, then a blue screen at the next restart), or they won't "
            "load."), None


@guide("enc.boot_no_secureboot")
def boot_no_secureboot(check, scan, outcome):
    signed = family(scan) in ("debian", "fedora", "suse")          # shim and GRUB signed by the distribution
    steps = []
    if signed:
        mok, first = _mok_step(scan)
        if first is not None:
            steps.append(first)
        steps.append(Step("Turn it on in the firmware",
                          "Your distribution's boot files are already signed. Restart into the firmware setup, find "
                          "Secure Boot (often under Boot or Security) and enable it with the standard keys." + mok,
                          commands=["systemctl reboot --firmware-setup", "mokutil --sb-state"],
                          side_effects=["This stops a changed bootloader or kernel from starting, not a changed "
                                        "initramfs: with shim and GRUB the initramfs isn't signed. The firmware "
                                        "password below, and not leaving the computer alone where it matters, cover "
                                        "the rest."]))
    elif isfile(scan.host.sys_path("/usr/bin/limine-update")):
        # Limine (CachyOS): signing the bootloader isn't enough; it must also carry its config's hash, or a
        # changed limine.conf would boot anything (wiki.cachyos.org/configuration/secure_boot_setup)
        batch = isfile(scan.host.sys_path("/usr/bin/sbctl-batch-sign"))
        steps.append(Step("Sign the boot files with your own keys (sbctl and Limine)",
                          "Limine isn't signed by your distribution, so you create keys and sign it. First put the "
                          "firmware in Setup Mode (in its Secure Boot settings: \"Reset to setup mode\" or \"Clear "
                          "keys\"); the first command restarts into it. Then create and enrol keys, keeping "
                          "Microsoft's (graphics cards and other firmware need them). Limine must also carry a "
                          "checksum of its configuration, or a changed configuration could boot anything: "
                          "ENABLE_ENROLL_LIMINE_CONFIG does that at every update. Then sign what sbctl verify lists.",
                          commands=[c for c in [
                              "systemctl reboot --firmware-setup", install(scan, arch="sbctl"), "sudo sbctl status",
                              "sudo sbctl create-keys", "sudo sbctl enroll-keys --microsoft",
                              "echo 'ENABLE_ENROLL_LIMINE_CONFIG=yes' | sudo tee -a /etc/default/limine",
                              "sudo limine-enroll-config", "sudo limine-update", "sudo sbctl verify",
                              "sudo sbctl-batch-sign" if batch else "sudo sbctl sign -s FILE     # each file sbctl verify lists",
                              "sudo sbctl verify"] if c],
                          side_effects=["If /boot/limine.conf shows a wallpaper (a splash image), its path needs its "
                                        "checksum after a # (sudo b2sum /boot/limine-splash.png), as the CachyOS "
                                        "wiki's Secure Boot page shows: otherwise Limine refuses to load it.",
                                        "Sign everything sbctl verify lists before turning Secure Boot on: an unsigned "
                                        "file won't start. sbctl signs new kernels after updates by itself."]))
        steps.append(Step("Turn it on in the firmware", "Restart into the firmware setup and enable Secure Boot.",
                          commands=["systemctl reboot --firmware-setup"]))
    else:
        steps.append(Step("Sign the boot files with your own keys (sbctl)",
                          "Arch-based distributions don't sign their boot files, so you create keys and sign them. "
                          "First put the firmware in Setup Mode (in its Secure Boot settings: \"Reset to setup mode\" "
                          "or \"Clear keys\"). Then create and enrol keys, keeping Microsoft's (-m: graphics cards and "
                          "other firmware need them), and sign what boots. sbctl signs new kernels automatically "
                          "after updates.",
                          commands=["sudo sbctl status", "sudo sbctl create-keys", "sudo sbctl enroll-keys -m",
                                    "sudo sbctl verify", "sudo sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI"],
                          side_effects=["Sign every file sbctl verify lists as unsigned (the bootloader and each "
                                        "kernel or UKI), with sbctl sign -s, before turning Secure Boot on: an "
                                        "unsigned one won't start."]))
        steps.append(Step("Turn it on in the firmware", "Restart into the firmware setup and enable Secure Boot.",
                          commands=["systemctl reboot --firmware-setup"]))
    steps.append(Step("Also: a firmware password",
                      "Set a firmware (BIOS) password and disable booting from USB without it, so Secure Boot can't "
                      "simply be turned off."))
    steps.append(Step("Further: a signed unified kernel image (UKI)",
                      "A UKI puts the kernel and the initramfs in one file, signed as a whole, so Secure Boot checks "
                      "the initramfs too. It takes systemd-boot (or a bootloader that starts UKIs) and a kernel "
                      "install that builds them (ukify, dracut --uefi or mkinitcpio presets), signed with your own "
                      "keys: a larger change, best made when reinstalling. A TPM unlock tied only to Secure Boot's "
                      "state (PCR 7) doesn't notice a changed initramfs either: whoever changes it can record the "
                      "PIN (enc.tpm_no_pin) as you type it."))
    return Guide(check.id, "Stop the boot files being tampered with",
                 "The boot files (bootloader, kernel, initramfs) sit unencrypted so the computer can start. Someone "
                 "with a few minutes alone with it could change them to record your disk passphrase. With Secure "
                 "Boot, the firmware only runs a bootloader and kernel signed with a trusted key. The initramfs is "
                 "only checked when it is part of a signed unified kernel image (UKI), which most distributions "
                 "don't use yet.",
                 steps)


# ------------------------------------------------------------------ sessions, browsers, network

@guide("sbx.x11_session")
def x11_session(check, scan, outcome):
    desk = scan.context.desktop
    names = set(desk.names)
    if desk.is_kde:
        where = "On the login screen (SDDM), pick \"Plasma (Wayland)\" in the session menu at the bottom left."
    elif desk.is_gnome:
        where = "On the login screen, choose your name, then the gear button at the bottom right, and pick \"GNOME\" (not \"GNOME on Xorg\")."
    elif names & {"x-cinnamon", "cinnamon"}:
        where = ("Cinnamon's Wayland session is still experimental: on the login screen it is \"Cinnamon on Wayland\" "
                 "in the session menu. If something you need doesn't work in it, switch back the same way. Full "
                 "Wayland support in Cinnamon will hopefully arrive by the end of 2026; until then, a desktop with "
                 "full Wayland support (GNOME or KDE Plasma, both installable beside Cinnamon) is the alternative.")
    else:
        where = ("On the login screen, look for a Wayland session in the session menu, if your desktop offers one. If "
                 "it doesn't, a desktop with full Wayland support (GNOME, KDE Plasma) can be installed beside it and "
                 "chosen there.")
    return Guide(check.id, "Use a Wayland session",
                 "On X11, every program you run can read the clipboard, see what every other window shows and "
                 "record what you type, with no permission asked: one compromised app, or one browser exploit, "
                 "reaches everything on the screen. Wayland keeps programs to their own windows, and asks you "
                 "before one records the screen.", [
        Step("Log in to a Wayland session", where),
        Step("If it doesn't work", "Older NVIDIA drivers, screen sharing in old apps and some remote-desktop and "
             "automation tools are the usual troubles. Updating the NVIDIA driver (555 or later) fixes most; otherwise "
             "go back to the X11 session the same way."),
    ])


@guide("kern.landlock")
def landlock(check, scan, outcome):
    from ..kernel import landlock_state
    state, _, _ = landlock_state(scan)
    host = scan.host
    i, like = os_release(scan)
    version = (re.search(r'^VERSION_ID="?([^"\n]*)', host.read_sys("/etc/os-release") or "", re.M) or [None, ""])[1]
    check_step = Step("Restart and check", "After a restart into the new kernel, the version is 6.12 or later and "
                      "landlock is in the list of active security modules. Then Check again here, and the browser "
                      "in memory says Landlock protects it.",
                      commands=["uname -r", "cat /sys/kernel/security/lsm"])
    intro = ("Landlock lets a sandbox fence itself. From Linux 6.12 it also keeps a sandbox from other programs' "
             "hidden (abstract) sockets, such as XWayland's, and from signalling them. Nothing changes for "
             "programs that aren't sandboxed. A new kernel comes from your distribution, like any update; if the "
             "computer doesn't start with it, choose the previous one in the boot menu (hold Shift or press Esc "
             "while it starts).")
    if state == "off":
        lsm = [m for m in (host.read_sys("/sys/kernel/security/lsm") or "").strip().split(",")
               if m and m != "capability"]
        wanted = "lsm=" + ",".join(["landlock", *[m for m in lsm if m != "landlock"]])
        return Guide(check.id, "Turn on Landlock", intro + " This kernel has Landlock built in, but it isn't in the "
                     "list of security modules started at boot. lsm= replaces that list, so the option keeps every "
                     "module active now and adds landlock.",
                     [*kernel_option_steps(scan, wanted)[:1], check_step])
    if state == "missing":
        return Guide(check.id, "Use a kernel with Landlock", intro, [
            Step("Install your distribution's standard kernel", "This kernel was built without Landlock: it is "
                 "probably a custom one. Every major distribution's own kernel has it; install that one and choose "
                 "it in the boot menu."), check_step])
    ubuntu_like = i in ("ubuntu", "linuxmint", "pop", "zorin", "elementary") or "ubuntu" in like
    if ubuntu_like and (version.startswith("24.04") or (i == "linuxmint" and version.startswith("22"))):
        where = ("In Linux Mint, Update Manager → View → Linux kernels lists the newer kernels too: pick the "
                 "newest 6.14 or later and Install. Or, in a terminal: " if i == "linuxmint" else
                 "Ubuntu 24.04's hardware enablement (HWE) kernel is 6.14 or later, supported for as long as "
                 "24.04: ")
        steps = [Step("Install the hardware enablement kernel", where + "the command installs it, and it then "
                      "follows the updates as usual.",
                      commands=["sudo apt update", "sudo apt install --install-recommends linux-generic-hwe-24.04"]),
                 check_step]
    elif ubuntu_like:
        steps = [Step("Upgrade to a release with Linux 6.12 or later", "This release's kernels, even its newest "
                      "hardware enablement one, are older than 6.12. Ubuntu 24.04 (with its HWE kernel) and later, "
                      "and Linux Mint 22 and later, have one: upgrade with the distribution's upgrade tool.",
                      commands=["sudo do-release-upgrade" if i != "linuxmint" else
                                "mintupgrade     # Linux Mint's upgrade tool, from Update Manager's Edit menu"]),
                 check_step]
    elif i == "debian" and version.startswith("12"):
        steps = [Step("Install the kernel from bookworm-backports", "Debian 12's own kernel is 6.1; the "
                      "backports archive, from the Debian project, carries a newer one (6.12 or later) built for "
                      "Debian 12. The first command adds the archive; nothing else is taken from it unless you "
                      "ask for it.",
                      commands=["echo 'deb https://deb.debian.org/debian bookworm-backports main' | sudo tee "
                                "/etc/apt/sources.list.d/bookworm-backports.list",
                                "sudo apt update",
                                "sudo apt install -t bookworm-backports linux-image-amd64"]), check_step]
    elif family(scan) == "suse" and "leap" in i:
        steps = [Step("Upgrade to openSUSE Leap 16, or use Tumbleweed", "Leap 15's kernel is 6.4; Leap 16 and "
                      "Tumbleweed have 6.12 or later."), check_step]
    else:
        update = {"debian": "sudo apt update && sudo apt full-upgrade", "fedora": "sudo dnf upgrade --refresh",
                  "arch": "sudo pacman -Syu", "suse": "sudo zypper dup"}.get(family(scan) or "")
        steps = [Step("Update to a kernel 6.12 or later", "Your distribution has one: install the updates, "
                      "kernel included, and restart into it.", commands=[update] if update else []), check_step]
    return Guide(check.id, "Get a kernel with Landlock 6.12", intro, steps)


@guide("br.account_sync")
def account_sync(check, scan, outcome):
    from ..browser import sync_states
    syncing = [s for s in sync_states(scan) if s.state in ("readable", "passphrase", "e2e")]
    steps = []
    for browser in dict.fromkeys(s.browser for s in syncing):
        mine = [s for s in syncing if s.browser == browser]
        profiles = ", ".join(s.label for s in mine)
        if browser in ("Firefox", "LibreWolf"):
            steps.append(Step(f"{browser}: Sync is end-to-end encrypted",
                              f"{profiles}. Mozilla can't read what is synced; your Mozilla account's password is what "
                              "protects it, so give it one of its own and turn on two-step authentication. To sync less, "
                              "or sign out: Settings → Sync.", commands=["firefox about:preferences#sync"]
                              if browser == "Firefox" else []))
        elif any(s.state == "e2e" for s in mine):
            steps.append(Step(f"{browser}: sync is end-to-end encrypted",
                              f"{profiles}. {browser} can't read what is synced; whoever has the sync code or "
                              "encryption password can, on a new device. Keep it as you would a password, and to sync "
                              "less or leave, open Settings → Sync."))
        elif all(s.state == "passphrase" for s in mine):
            steps.append(Step(f"{browser}: synced with a sync passphrase",
                              f"{profiles}. The provider can't read what is synced; the passphrase is what protects it."))
        else:
            cmds = ["google-chrome chrome://settings/syncSetup"] if browser == "Google Chrome" else []
            text = (f"{profiles}. In {browser}'s settings, open the Sync section (Chrome: You and Google → Sync; Edge: "
                    "Profiles → Sync). Either turn sync off, untick what you don't need (history, open tabs)"
                    + (", or under Encryption options choose \"Encrypt synced data with your own sync passphrase\" so "
                       "Google can't read it." if browser.startswith("Google Chrome") else
                       ", or set a sync passphrase where it offers one."))
            steps.append(Step(f"{browser}: the provider can read what is synced", text, commands=cmds))
    if not steps:
        steps.append(Step("Nothing syncs", "No browser profile here syncs to an online account now.", done=True))
    return Guide(check.id, "Keep your browsing data from the provider", "Sync copies history, passwords and open "
                 "tabs to the provider's servers. End-to-end encrypted sync keeps them unreadable there; the rest the "
                 "provider can read.", steps)


@guide("net.vpn_leaks")
def vpn_leaks(check, scan, outcome):
    from ... import vpn
    try:
        found = [m for m in vpn.identify(scan.host, vpn.load()) if m.in_use]
    except vpn.DataError:
        found = []
    p = found[0].provider if found else None
    check_text = "With the VPN on, run the online tests net.dns_leak and net.vpn_exit."
    commands = []
    if p and p.leak_test:
        check_text += f" {p.name} also has a page of its own that says whether it sees your traffic as its own."
        commands = [f"xdg-open {p.leak_test}"]
    if p and p.leak_protection:
        # its app has no switch for it: say what it does, and the one setting there is
        return Guide(check.id, "Keep DNS inside the VPN", "", [
            _protection_step(p, f"In {p.name}"),
            Step("Check", check_text, commands=commands),
        ])
    app = (f"In {p.name}'s app, turn on its DNS leak protection and kill switch (\"block connections without VPN\")."
           if p else "Turn on its DNS leak protection and kill switch (\"block connections without VPN\"). Most "
           "commercial VPN apps have both.")
    return Guide(check.id, "Keep DNS inside the VPN", "", [
        Step(f"In {p.name}" if p else "In your VPN app", app),
        Step("For a VPN set up in NetworkManager (WireGuard, OpenVPN)",
             "Give the VPN's DNS priority over every other network's, so all lookups go through it while it is on. "
             "Replace VPN with the connection's name, then reconnect.",
             commands=["nmcli connection modify VPN ipv4.dns-priority -50 ipv6.dns-priority -50 ipv4.dns-search '~.'",
                       "nmcli connection up VPN"]),
        Step("Check", check_text, commands=commands),
    ])


def _protection_step(p, title: str, leaking: bool = False) -> Step:
    """For a VPN app that keeps traffic and lookups in its tunnel with no setting for it (vpn-providers.yaml
    `leak_protection`): what it does, what to look at when a test found a leak anyway, and its lockdown setting."""
    lp = p.leak_protection
    text = "There is nothing to turn on for this. " + lp.text + (" " + lp.if_leaking if leaking else "")
    commands = []
    if lp.lockdown:
        text += (f" Lockdown mode ({lp.lockdown.where}) also blocks the internet after you disconnect or quit the "
                 f"app; the command below turns it on. What it costs: {lp.lockdown.cost}")
        commands = [lp.lockdown.command]
    return Step(title, text, commands=commands)


MINT_OFFICIAL = "/etc/apt/sources.list.d/official-package-repositories.list"


@guide("tel.http_repos")
def http_repos(check, scan, outcome):
    from ..telemetry import NO_HTTPS, _repo_files, http_hosts
    # the files read again here: the evidence is shortened for the page, and a path cut there broke the command
    files = [(path, sorted(set(http_hosts(text)))) for path, text in _repo_files(scan)]
    files = [(path, hosts) for path, hosts in files if hosts]
    # Linux Mint's own sources are written by Software Sources (mintsources), which writes them again whenever a
    # setting changes there, and its default, packages.linuxmint.com, has no HTTPS: a sed there broke apt (live)
    mint = os_release(scan)[0] == "linuxmint" or isfile(scan.host.sys_path(MINT_OFFICIAL))
    by_hand = [(p, hosts) for p, hosts in files if not (mint and p == MINT_OFFICIAL)]
    checked = sorted({h for _, hosts in by_hand for h in hosts} - NO_HTTPS)
    steps = []
    if checked:
        steps.append(Step("Check each mirror answers over HTTPS", "Most do. If one doesn't, choose another mirror in "
                          "your software sources settings.",
                          commands=[f"curl -sfI https://{h} >/dev/null && echo ok: {h}" for h in checked]))
    if mint and any(p == MINT_OFFICIAL for p, _ in files):
        steps.append(Step("Linux Mint's own sources: choose HTTPS mirrors",
                          "These are written by Software Sources, which writes them again whenever a setting changes "
                          "there, so editing the file by hand doesn't last; and Mint's default server, "
                          "packages.linuxmint.com, has no HTTPS. Open Software Sources (Menu → Administration → Software "
                          "Sources) → Mirrors, and for both Main and Base choose a mirror whose address starts with "
                          "https://; it refreshes the package lists itself."))
    for path, hosts in by_hand:
        good, none = [h for h in hosts if h not in NO_HTTPS], [h for h in hosts if h in NO_HTTPS]
        steps.append(Step(f"Use HTTPS in {path}",
                          (f"Switch {', '.join(good)} to HTTPS in this file." if good else "")
                          + (f" {', '.join(none)} has no HTTPS: choose another mirror for it." if none else ""),
                          commands=[f"sudo sed -i 's|http://{h}|https://{h}|g' {shlex.quote(path)}" for h in good]))
    steps.append(Step("Refresh the package lists", commands=["sudo apt update" if family(scan) == "debian" else
                                                             "sudo dnf makecache" if family(scan) == "fedora" else
                                                             "sudo zypper refresh" if family(scan) == "suse" else
                                                             "sudo pacman -Syu     # never -Sy alone: a partial upgrade breaks Arch"]))
    return Guide(check.id, "Download packages over HTTPS", "", steps)


@guide("br.private_download_leak")
def private_download_leak(check, scan, outcome):
    kde = scan.context.desktop.is_kde or any(e.label.startswith("Downloads in KDE") for e in outcome.evidence)
    return Guide(check.id, "Leave no trace of private downloads", "", [
        Step("Clear what is already recorded", "Thumbnails (desk.thumbnails), recent files (desk.recent_files) and "
             "file search (desk.indexers) each have a guide that clears them and stops them coming back."
             + (" On KDE, so do the apps' own lists of what they opened (app.kde_recent_files) and the activity "
                "history (desk.kde_activities)." if kde else "")),
        Step("Download private files somewhere that is forgotten",
             "Save them to ~/Ephemeral (desk.ephemeral_folder): a folder in memory, emptied at logout or restart. "
             "Leave it out of file search."),
    ])


# ------------------------------------------------------------------ browsers

def _package_name(scan, path) -> str | None:
    """The package a file belongs to, asked of this distribution's package manager (reads only)."""
    fam = family(scan)
    argv = {"debian": ("dpkg-query", "-S", str(path)), "fedora": ("rpm", "-qf", "--qf", "%{NAME}", str(path)),
            "suse": ("rpm", "-qf", "--qf", "%{NAME}", str(path)), "arch": ("pacman", "-Qoq", str(path))}.get(fam or "")
    if argv is None:
        return None
    r = scan.host.run(*argv)
    if not r.ok or not r.stdout.strip():
        return None
    out = r.stdout.strip().splitlines()[0]
    return out.split(":")[0].strip() if fam == "debian" else out.strip()


# where Chrome's and Edge's packages leave their software repositories
VENDOR_REPOS = {"chrome": ("/etc/apt/sources.list.d/google-chrome.list", "/etc/apt/sources.list.d/google-chrome.sources",
                           "/etc/yum.repos.d/google-chrome.repo"),
                "edge": ("/etc/apt/sources.list.d/microsoft-edge.list", "/etc/apt/sources.list.d/microsoft-edge.sources",
                         "/etc/yum.repos.d/microsoft-edge.repo")}


def _removal_commands(scan, f) -> list[str]:
    """How to remove one found browser, for each way it is installed here."""
    fam = family(scan)
    remove_cmd = {"debian": "sudo apt purge", "fedora": "sudo dnf remove", "arch": "sudo pacman -Rns",
                  "suse": "sudo zypper remove"}.get(fam or "")
    cmds = []
    for path, how, did in zip(f.paths, f.installs, f.desktop_ids + [None] * len(f.paths)):
        if how == "package":
            pkg = _package_name(scan, path)
            if pkg and remove_cmd:
                cmds.append(f"{remove_cmd} {pkg}")
        elif how == "Flatpak" and did:
            user = str(path).startswith(str(scan.host.home))
            cmds.append(f"flatpak uninstall {'--user ' if user else ''}{did.removesuffix('.desktop')}")
        elif how == "Snap" and did:
            cmds.append(f"sudo snap remove {did.split('_')[0]}")
        elif how == "AppImage":
            cmds.append(f"rm {shlex.quote(scan.host.display(path))}")
        elif how in ("this account", "a launcher on the desktop", "a panel launcher"):
            cmds.append(f"rm {shlex.quote(scan.host.display(path))}")
    for repo in VENDOR_REPOS.get(f.browser.id if f.browser else "", ()):
        if isfile(scan.host.sys_path(repo)):
            cmds.append(f"sudo rm {repo}")
    return list(dict.fromkeys(cmds))


@guide("br.surveillance_browsers")
def surveillance_browsers(check, scan, outcome):
    from ..browser import installed_browsers
    bad = [f for f in installed_browsers(scan) if f.browser is not None and f.browser.cls == "surveillance"]
    steps = [Step(f"Remove {f.name} ({f.describe()})",
                  f"Close {f.name} first. Its profile (history, passwords, cookies) stays in your home folder after the "
                  "program is gone; delete it too once you've copied anything you want to keep."
                  + (" Removing the package also takes away the software repository its maker added." if f.browser.id in
                     VENDOR_REPOS else ""),
                  commands=_removal_commands(scan, f)) for f in bad]
    if not steps:
        steps.append(Step("Nothing to remove", "None of them is installed now.", done=True))
    return Guide(check.id, "Remove Chrome, Edge, Opera and Yandex",
                 "Keep one only if you need it: to test websites you build, or for a bank or government site that "
                 "refuses every other browser (try Brave or ungoogled-chromium first: they run the same engine). If you "
                 "keep one, accept the finding instead; it comes back if that browser becomes your default.", steps)


# where to get the privacy browsers, as Flatpaks (Flathub ids)
FLATHUB = (("Brave", "com.brave.Browser"), ("LibreWolf", "io.gitlab.librewolf-community"),
           ("Mullvad Browser", "net.mullvad.MullvadBrowser"), ("Tor Browser (launcher)", "org.torproject.torbrowser-launcher"))


@guide("br.default_browser")
def default_browser_guide(check, scan, outcome):
    from ..browser import installed_browsers
    good = [f for f in installed_browsers(scan) if f.browser is not None and f.browser.cls == "privacy"
            and f.desktop_ids]
    steps = []
    if good:
        steps.append(Step("Make one of these your default",
                          "Run the line for the browser you choose. "
                          "Your desktop's own settings (Default Applications, or Preferred Applications) do the same.",
                          commands=[f"xdg-settings set default-web-browser {f.desktop_ids[0]}    # {f.name}"
                                    for f in good]))
    else:
        from .._util import installed
        flatpak = installed(scan.host, "flatpak")
        # Flathub added also where Flatpak is installed: Fedora without third-party repositories has only its own
        setup = ([] if flatpak else [c for c in [install(scan, debian="flatpak", fedora="flatpak", arch="flatpak",
                                                          suse="flatpak")] if c]) + [FLATHUB_ADD]
        tor = install(scan, debian="torbrowser-launcher", fedora="torbrowser-launcher", arch="torbrowser-launcher",
                      suse="torbrowser-launcher")
        steps.append(Step("Install one built for privacy",
                          "None is installed yet. Brave Origin is free on Linux: brave.com/origin explains how to install "
                          "it for your distribution. These are on Flathub"
                          + (": the first line adds Flathub where it isn't there yet" if flatpak else
                             ", which needs Flatpak: the first lines install it and add Flathub")
                          + (f". Tor Browser's launcher is also a package of your distribution's own ({tor})." if tor
                             else ":"),
                          commands=setup + [f"flatpak install flathub {fid}    # {name}" for name, fid in FLATHUB]))
        steps.append(Step("Then make it your default", "Open the new browser; it offers to become the default. Or "
                          "use your desktop's Default Applications settings."))
    steps.append(Step("Which to choose", "For every day, Brave (Brave Origin is better still), LibreWolf, Waterfox or "
                      "Zen, with history kept. For real privacy, Mullvad Browser, or Tor Browser at the top, with a VPN "
                      "on this computer too so your internet provider can't see you use Tor. Never the other way round."))
    return Guide(check.id, "Choose a default browser built for privacy", "", steps)


UBO_PAGES = {"firefox": "https://addons.mozilla.org/firefox/addon/ublock-origin/",
             "lite": "https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh",
             "manual": "https://github.com/gorhill/uBlock/releases"}


@guide("br.content_blocking")
def content_blocking(check, scan, outcome):
    from ..browser import blocking_status, installed_browsers
    steps = []
    for f in installed_browsers(scan):
        b = f.browser
        if b is None or b.blocking != "extension":
            continue
        statuses = blocking_status(scan, b)
        if not any(s == "none" or s == "uBlock Origin Lite" for _, s in statuses):
            continue
        if "mozilla" in b.profiles:
            text = f"In {f.name}, open this page and choose Add to {f.name}:"
            cmds = [UBO_PAGES["firefox"]]
        elif b.id in ("chrome", "edge", "chromium", "vivaldi", "opera"):
            text = (f"{f.name} can't run the full uBlock Origin any more; uBlock Origin Lite blocks less but is what it "
                    f"can do. Open this page in {f.name}:" if b.no_ublock or b.id == "chromium" else
                    f"Open this page in {f.name} (it has a blocker of its own in its privacy settings too):")
            cmds = [UBO_PAGES["lite"]]
        else:
            text = (f"{f.name} still runs the full uBlock Origin, installed by hand from its releases (the .crx or the "
                    "chromium zip), following the browser's own instructions for extensions:")
            cmds = [UBO_PAGES["manual"]]
        steps.append(Step(f"{f.name}: add uBlock Origin", text, commands=cmds))
    if not steps:
        steps.append(Step("Nothing to add", "Every browser here blocks ads and trackers already.", done=True))
    steps.append(Step("Not in Tor Browser", "Leave Tor Browser as it is: the Tor Project advises adding no extensions, "
                      "as they make your browser stand out."))
    return Guide(check.id, "Add uBlock Origin", "", steps)


# ------------------------------------------------------------------ package signatures

@guide("kern.package_signatures")
def package_signatures(check, scan, outcome):
    from ..kernel import unsigned_repositories
    found, legacy, _, _ = unsigned_repositories(scan)
    steps = []
    by_file: dict[str, list] = {}
    for u in found:
        by_file.setdefault(u.path, []).append(u)
    for path, items in by_file.items():
        u = items[0]
        what = ", ".join(sorted({i.what for i in items}))
        names = ", ".join(i.name for i in items if i.name)
        q = shlex.quote(path)
        if u.manager == "apt" and "/apt.conf" in path:
            text = (f"{path} tells apt to accept {what}. Delete that line (or the whole file, if it holds nothing "
                    "else), then refresh the package lists.")
            cmds = [f"sudoedit {q}", "sudo apt update"]
        elif u.manager == "apt":
            text = (f"Remove {what} from the entry for {names or 'the repository'}. apt then checks the "
                    "repository's signature again: if `apt update` now refuses it, install its signing key as the "
                    "repository's own instructions say (a key file in /etc/apt/keyrings, named with signed-by=), and "
                    "if it has no valid signature at all, stop using it.")
            cmds = [f"sudoedit {q}", "sudo apt update"]
        elif u.manager in ("dnf", "zypper"):
            repos = [i.name for i in items if i.name]
            text = (f"Set gpgcheck=1 for {', '.join(repos) if repos else 'every repository'} in {path}. If the "
                    "repository then fails, import its key as its own instructions say; if it isn't signed at all, "
                    "stop using it.")
            cmds = [f"sudoedit {q}     # gpgcheck=1"]
            if u.manager == "zypper" and repos:
                cmds = [f"sudo zypper modifyrepo --gpgcheck {shlex.quote(r)}" for r in repos] + ["sudo zypper refresh"]
            elif u.manager == "dnf":
                cmds.append("sudo dnf makecache")
        elif u.manager == "pacman":
            text = (f"{path} has {what}: packages are accepted without a valid signature. Put back Arch's default "
                    "in that section, SigLevel = Required DatabaseOptional, then update.")
            cmds = [f"sudoedit {q}     # SigLevel = Required DatabaseOptional",
                    "sudo pacman -Syu     # never -Sy alone: a partial upgrade breaks Arch"]
        else:
            system = path.startswith("/var/")
            text = ("Turn signature checks back on for this Flatpak remote. If Flatpak then reports a missing key, "
                    "add the remote again from its .flatpakrepo file, which carries the key (for Flathub: "
                    "https://dl.flathub.org/repo/flathub.flatpakrepo).")
            cmds = [f"{'sudo ' if system else ''}flatpak remote-modify {'--system' if system else '--user'} --gpg-verify "
                    f"{shlex.quote(i.name)}" for i in items if i.name]
        steps.append(Step(path + (f" ({names})" if names else ""), text, commands=cmds))
    if legacy:
        steps.append(Step("apt's old shared keyring", "Keys added with apt-key went into /etc/apt/trusted.gpg, and apt "
                          "trusts each of them for every repository. For each third-party repository, export its key "
                          "into /etc/apt/keyrings and name it with signed-by= in that repository's entry, then delete "
                          "it from the shared keyring. List the keys first:",
                          commands=["gpg --no-default-keyring --keyring /etc/apt/trusted.gpg --list-keys",
                                    "sudo gpg --no-default-keyring --keyring /etc/apt/trusted.gpg --export KEYID "
                                    "| sudo tee /etc/apt/keyrings/NAME.gpg >/dev/null",
                                    "sudo apt-key del KEYID     # or remove it with gpg as above, once signed-by is set"]))
    from ..kernel import apt_shared_keys
    shared = apt_shared_keys(scan)
    if shared:
        steps.append(Step("Keys of other publishers in /etc/apt/trusted.gpg.d",
                          f"{', '.join(shared[:5])}: apt trusts each of these for every repository, the distribution's "
                          "own included. Move each into /etc/apt/keyrings and name it with signed-by= in its "
                          "repository's entry (a .sources file: Signed-By: /etc/apt/keyrings/NAME), so it is trusted for "
                          "that repository only:",
                          commands=[f"sudo mv /etc/apt/trusted.gpg.d/{shared[0]} /etc/apt/keyrings/",
                                    "sudoedit /etc/apt/sources.list.d/THE-REPOSITORY.list     # add [signed-by=/etc/apt/"
                                    f"keyrings/{shared[0]}] after deb", "sudo apt update     # it must still verify"]))
    steps.append(Step("Check by hand", "Lists every line in the package managers' settings that turns signature "
                      "checks off or weakens them; nothing printed means none is left.",
                      commands=["grep -rnE 'trusted=yes|Trusted: *yes|allow-insecure|Allow-Insecure|AllowUnauthenticated"
                                "|AllowInsecureRepositories|gpgcheck *= *(0|false|no|off)|SigLevel.*(Never|Optional)"
                                "|gpg-verify=false' /etc/apt /etc/yum.repos.d /etc/dnf /etc/zypp /etc/pacman.conf "
                                "/var/lib/flatpak/repo/config ~/.local/share/flatpak/repo/config 2>/dev/null"]))
    return Guide(check.id, "Make the package manager check signatures again",
                 "The app doesn't change these files itself: a mistake in them stops updates. Each step names the file "
                 "and the change.", steps)


# ------------------------------------------------------------------ online findings
# What the online tests find, the scan can't: their guides are built from the test's own result (the issuer seen,
# the ports the router forwards, the resolver that answered), never by running the test again (Runner.plan_fix
# takes the kept result), and from the machine as it is now (its VPN, its connections, its router's address).

def _nm_active(scan) -> list[tuple[str, str, str]]:
    """NetworkManager's active connections: (name, type, device)."""
    r = scan.host.run("nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active")
    out = []
    for line in (r.stdout if r.ok else "").splitlines():
        f = re.split(r"(?<!\\):", line.strip())
        if len(f) >= 3 and f[0]:
            out.append((f[0].replace("\\:", ":"), f[1], f[2]))
    return out


def _gateway_v4(scan) -> str | None:
    """The IPv4 default gateway (the router, at home), from the kernel's route table."""
    import ipaddress
    for line in (scan.host.read_sys("/proc/net/route") or "").splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000" and f[2] != "00000000":
            try:
                return str(ipaddress.ip_address(int.from_bytes(bytes.fromhex(f[2]), "little")))
            except ValueError:
                continue
    return None


def _nameservers(scan) -> list[str]:
    return re.findall(r"^\s*nameserver\s+(\S+)", scan.host.read_sys("/etc/resolv.conf") or "", re.M)


def _resolved_in_use(scan) -> bool:
    return any(s.startswith("127.0.0.53") for s in _nameservers(scan))


def _vpn_provider(scan):
    from ... import vpn
    try:
        found = [m for m in vpn.identify(scan.host, vpn.load()) if m.in_use]
    except vpn.DataError:
        found = []
    return found[0].provider if found else None


def _protected(p) -> bool:
    """Its app keeps traffic and lookups inside the tunnel with no setting for it (vpn-providers.yaml)."""
    return bool(p and p.leak_protection)


def _router_step(scan, title: str, text: str) -> Step:
    gw = _gateway_v4(scan)
    where = (f" Your router's settings page is usually at its address, http://{gw}/." if gw
             else " The router's address is printed on it, or shown in the network's settings as the gateway.")
    return Step(title, text + where, commands=[f"xdg-open http://{gw}/"] if gw else [])


def _check_again(check_id: str, text: str = "") -> Step:
    return Step("Check again", f"Run the online test {check_id} again. {text}".strip())


def _ipv6_outside_steps(scan) -> list[Step]:
    """IPv6 leaves through a connection outside the VPN tunnel: the commands that turn IPv6 off on that
    connection, for this machine (NetworkManager's connection by name; else the kernel setting, until a restart)."""
    from ... import network as net
    host = scan.host
    tunnels = set(net.vpn_links(host))
    outside = sorted(d for d in net.internet_route(host, 6) if d not in tunnels)
    if not outside:
        return []
    by_device = {d: n for n, _, d in _nm_active(scan) if d}
    cmds, named = [], []
    for d in outside:
        if d in by_device:
            q = shlex.quote(by_device[d])
            named.append(by_device[d])
            cmds += [f"nmcli connection modify {q} ipv6.method disabled", f"nmcli connection up {q}"]
        else:
            cmds.append(f"sudo sysctl -w net.ipv6.conf.{d}.disable_ipv6=1")
    lasting = (f"It stays off until you set ipv6.method back to auto on {', '.join(named)}." if named
               else "The kernel setting lasts until a restart; NetworkManager wasn't found managing the connection.")
    return [Step("Turn IPv6 off on the connection that goes around the VPN",
                 f"IPv6 internet traffic leaves through {', '.join(outside)}, not through the tunnel. Until the VPN "
                 f"carries IPv6, turn it off there: websites then see only the VPN's IPv4 address. {lasting}",
                 commands=cmds,
                 side_effects=["The few sites reachable over IPv6 only can't be reached while it is off."])]


@guide("kern.release_unsupported")
def release_unsupported(check, scan, outcome):
    """The distribution's own route to a supported release, as commands the user runs."""
    from ..kernel import _today, long_date, os_release_fields, release_support
    s, rel, fam = release_support(scan.host), os_release_fields(scan.host), family(scan)
    ident = rel.get("ID", "").lower()
    steps = [Step("Back up your files first", "An upgrade replaces most of the system's software in one go. Copy what "
                  "you can't lose to another drive, and check the copy opens, before starting.")]
    if ident == "linuxmint":
        steps.append(Step(
            "Upgrade Linux Mint",
            "Mint moves to its next major version with its own upgrade tool, which checks the computer first and "
            "says what it will change. Install the waiting updates, then run it. Mint's blog (blog.linuxmint.com) "
            "has the instructions for each version; a fresh install of the current Mint, with your files copied "
            "back, is the other way and often the quicker one.",
            commands=["sudo apt update && sudo apt full-upgrade", "sudo apt install mintupgrade", "sudo mintupgrade"]))
    elif ident == "ubuntu":
        steps.append(Step(
            "Upgrade Ubuntu",
            "Install the waiting updates, restart, then start the upgrade to the next release. From a release long "
            "out of support the upgrade can refuse, because its packages have moved to Ubuntu's archive of old "
            "releases: then a fresh install of the current Ubuntu, with your files copied back, is the way.",
            commands=["sudo apt update && sudo apt full-upgrade", "sudo do-release-upgrade"]))
        if s.extended and s.extended >= _today():
            steps.append(Step(
                "Or keep this release with Ubuntu Pro",
                f"Ubuntu Pro keeps security updates coming for this release until {long_date(s.extended)}, free for "
                "personal use on up to five computers. It needs an Ubuntu account (the token is on ubuntu.com/pro), "
                "and the computer is registered with Canonical.",
                commands=["sudo pro attach", "sudo pro status"]))
    elif fam == "debian":
        steps.append(Step(
            "Upgrade to the next release",
            "Debian upgrades in place, one release at a time: the release notes of the next release (on debian.org, "
            "the chapter on upgrades) give the steps, which come down to installing the waiting updates, pointing "
            "the package sources in /etc/apt at the next release's name, then a full upgrade and a restart."
            + (f" {s.name} follows {s.base}: use its own instructions where it has them." if s.base else ""),
            commands=["sudo apt update && sudo apt full-upgrade"]))
    elif ident == "fedora" and rel.get("VERSION_ID", "").isdigit():
        nxt = int(rel["VERSION_ID"]) + 1
        steps.append(Step(
            "Upgrade Fedora",
            f"Install the waiting updates, download Fedora {nxt}, then restart into the upgrade. Fedora supports "
            f"going up two releases at once (--releasever={nxt + 1}), not more: from an older one, repeat it. The "
            "last command is for DNF5 (Fedora 41 and later); before that it is \"sudo dnf system-upgrade reboot\".",
            commands=["sudo dnf upgrade --refresh", f"sudo dnf system-upgrade download --releasever={nxt}",
                      "sudo dnf5 offline reboot"]))
    else:
        steps.append(Step(
            "Move to a supported release",
            f"Use {s.name}'s own upgrade tool, as its site describes, or install its current release afresh and "
            "copy your files back."))
    steps.append(Step("If this computer can't run a newer release",
                      "A release without security updates isn't safe to browse the web or read mail with, however "
                      "carefully it is used. Another distribution that is still supported and runs on older hardware "
                      "is the answer, not staying."))
    steps.append(Step("Check again", "Scan again after the upgrade: this check and kern.updates then say where "
                      "things stand."))
    return Guide(check.id, "Move to a release that gets security updates", "", steps)


@guide("kern.updates_refreshed")
def updates_refreshed(check, scan, outcome):
    """The same commands as kern.updates' guide: an online test's guide gives steps, never options."""
    from .kernel import updates
    g = updates(check, scan, outcome)
    steps = [Step(s.title, s.text, commands=list(s.commands), side_effects=list(s.side_effects), done=s.done)
             for s in g.steps if s.commands or s.text]
    if not steps:                           # no package manager the app knows: still say what to do
        steps = [Step(g.steps[0].title if g.steps else "Install the updates",
                      "Install them with your distribution's update tool; the app couldn't tell which package "
                      "manager this computer uses.")]
    return Guide(check.id, g.title, "With the package lists just refreshed, these updates are waiting. The commands "
                 "install them, as kern.updates' guide does, Flatpak and Snap apps included.", steps)


@guide("net.dns_leak")
def dns_leak(check, scan, outcome):
    from ... import network as net
    p = _vpn_provider(scan)
    seen = [str(v) for v in evidence(outcome, "Resolver")]
    intro = ("Lookups go to a resolver outside the VPN" + (f": {'; '.join(seen[:3])}" if seen else "") + ". Whoever "
             "runs it sees every site you look up, VPN or not. Make every lookup go through the tunnel.")
    if _protected(p):
        steps = [_protection_step(p, f"In {p.name}'s app", leaking=True)]
    else:
        steps = [Step(f"In {p.name}'s app" if p else "In your VPN app",
                      "Turn on its DNS leak protection (\"use the VPN's DNS servers\", \"block DNS outside the tunnel\") "
                      "and its kill switch, then reconnect. Most VPN apps have both; without them the app leaves the "
                      "network's own DNS servers in place.")]
    vpns = [(n, t) for n, t, _ in _nm_active(scan) if t in ("vpn", "wireguard")]
    if vpns:
        cmds = []
        for n, _ in vpns:
            q = shlex.quote(n)
            cmds += [f"nmcli connection modify {q} ipv4.dns-priority -50 ipv6.dns-priority -50 ipv4.dns-search '~.' "
                     "ipv6.dns-search '~.'", f"nmcli connection up {q}"]
        steps.append(Step("Your VPN connection in NetworkManager",
                          f"The VPN connection{'s' if len(vpns) > 1 else ''} {', '.join(n for n, _ in vpns)} "
                          f"{'are' if len(vpns) > 1 else 'is'} set up in NetworkManager. Give its DNS servers priority "
                          "over every other network's, so that all lookups go through the tunnel while it is on; "
                          "the second command reconnects it with the new setting.", commands=cmds,
                          side_effects=["Names only your home network knows (printer.lan, a NAS) may stop resolving "
                                        "while the VPN is on."]))
    elif not _protected(p) and _resolved_in_use(scan) and (tunnels := net.carrying_vpn_links(scan.host)):
        steps.append(Step("Route every lookup into the tunnel (systemd-resolved)",
                          f"The tunnel {', '.join(tunnels)} isn't a NetworkManager connection. systemd-resolved can "
                          "be told to send every lookup through it, until it is reconnected (then the VPN's own "
                          "start-up script must do it: wg-quick does with a DNS= line in its config).",
                          commands=[f"resolvectl domain {t} '~.'" for t in tunnels] + ["resolvectl status"]))
    steps.append(_check_again(check.id, "Every resolver listed should then be in the VPN's network."))
    return Guide(check.id, "Keep DNS inside the VPN", intro, steps)


@guide("net.vpn_ipv6_leak")
def vpn_ipv6_leak(check, scan, outcome):
    p = _vpn_provider(scan)
    steps = [_protection_step(p, f"In {p.name}'s app", leaking=True) if _protected(p) else
             Step(f"In {p.name}'s app" if p else "In your VPN app",
                  "Turn on its IPv6 support, or its leak protection (\"block IPv6\", \"disable IPv6 while connected\"), "
                  "then reconnect. A VPN that carries no IPv6 should block it; one that does should route it.")]
    steps += _ipv6_outside_steps(scan)
    steps.append(_check_again(check.id, "The IPv6 address websites see should be the VPN's, or none."))
    return Guide(check.id, "Keep IPv6 inside the VPN",
                 "Websites reachable over IPv6 see this computer's own address, because IPv6 traffic doesn't go "
                 "through the tunnel. Either the VPN carries IPv6 too, or IPv6 is off while it is on.", steps)


@guide("net.vpn_exit")
def vpn_exit(check, scan, outcome):
    from ... import network as net
    p = _vpn_provider(scan)
    seen = [f"{e.label}: {e.value}" for e in outcome.evidence if str(e.label).startswith("Public IPv")]
    intro = ("Websites don't see the VPN's address for all your traffic" + (f" ({'; '.join(seen)})" if seen else "")
             + ".")
    steps = []
    on_this = bool(net.carrying_vpn_links(scan.host))
    if _protected(p):
        steps.append(_protection_step(p, f"In {p.name}'s app", leaking=True))
    elif on_this or p:
        steps.append(Step(f"In {p.name}'s app" if p else "In your VPN app",
                          "Reconnect it, and turn on its leak protection and kill switch (\"block connections outside "
                          "the VPN\"). If the provider's own check says traffic doesn't leave through it, the app "
                          "isn't routing everything: its support pages say which setting."))
    steps += _ipv6_outside_steps(scan)
    if not on_this:
        steps.append(_router_step(scan, "If the VPN runs on your router",
                                  "No tunnel on this computer carries its traffic, so the VPN is upstream: on the "
                                  "router, or further up. In the router's VPN settings, make the tunnel carry IPv6 "
                                  "too, or turn IPv6 off for the home network, so nothing goes around it."))
    steps.append(_check_again(check.id, "Both addresses websites see should be the VPN's."))
    return Guide(check.id, "Make all traffic leave through the VPN", intro, steps)


@guide("net.dnssec_validation")
def dnssec_validation(check, scan, outcome):
    path = "/etc/systemd/resolved.conf.d/60-daprivacyscanner-dnssec.conf"
    if _resolved_in_use(scan):
        steps = [Step("Turn on validation in systemd-resolved",
                      "systemd-resolved can check the signatures itself, whatever server it asks. allow-downgrade "
                      "validates where the server passes the records through and falls back, saying nothing, where it "
                      "doesn't (many home routers' DNS breaks DNSSEC); yes refuses to answer then.",
                      commands=["sudo mkdir -p /etc/systemd/resolved.conf.d",
                                f"printf '[Resolve]\\nDNSSEC=allow-downgrade\\n' | sudo tee {path}",
                                "sudo systemctl restart systemd-resolved"],
                      side_effects=["With a server that doesn't support DNSSEC (the router's, often), allow-downgrade "
                                    "validates nothing and says nothing: use a server that does (the next step)."]),
                 Step("Use a server that supports it", "Quad9 and Cloudflare pass the DNSSEC records through and "
                      "validate themselves: the Guide… of net.dns_unencrypted sets one, encrypted too.")]
    else:
        steps = [Step("Use a resolver that validates", "This computer doesn't use systemd-resolved, so validation "
                      "must come from the DNS provider. Quad9 and Cloudflare validate every answer: the Guide… of "
                      "net.dns_unencrypted sets one, encrypted too; a browser's own encrypted DNS does the same for "
                      "the browser alone.")]
    steps.append(_check_again(check.id, "A name with a broken signature should then be refused; from a terminal: "
                              "resolvectl query dnssec-failed.org fails with a validation error."))
    return Guide(check.id, "Check DNS answers with DNSSEC", "A forged DNS answer sends you to the wrong server "
                 "without any warning. DNSSEC signatures let the resolver refuse forged answers for the domains that "
                 "sign (banks and governments often do; most sites don't).", steps)


@guide("net.nxdomain_rewrite")
def nxdomain_rewrite(check, scan, outcome):
    import ipaddress
    answered = [str(v) for v in evidence(outcome, "Answered with")]
    servers = [s for s in _nameservers(scan) if not s.startswith("127.")]
    private = []
    for s in servers:
        try:
            if ipaddress.ip_address(s.split("%")[0]).is_private:
                private.append(s)
        except ValueError:
            pass
    intro = ("A name that doesn't exist was answered with " + (", ".join(answered) if answered else "an address")
             + ": whoever answers your lookups" + (f" ({', '.join(servers)})" if servers else "") + " sends mistyped "
             "addresses to a server of its own, usually a page of advertisements, and sees what you mistyped.")
    steps = [Step("Use a DNS provider that doesn't rewrite", "Quad9, Cloudflare and Mullvad answer \"no such name\" "
                  "as the standard says. The Guide… of net.dns_unencrypted switches to one of them, over TLS, so "
                  "nothing on the way can rewrite the answers either.")]
    if private:
        steps.append(_router_step(scan, "Or turn the redirection off in the router",
                                  f"Your lookups go to {', '.join(private)}, on your own network: the router answers "
                                  "them, forwarding to your internet provider. Its own setting is often called "
                                  "\"DNS assist\", \"search help\" or \"web address redirection\"; the provider's "
                                  "account page may have the same."))
    else:
        steps.append(Step("Or turn it off at the provider", "The setting is in your internet provider's account page, "
                          "often called \"DNS assist\", \"search help\" or \"web address error redirection\"."))
    steps.append(_check_again(check.id, "A random name should then be reported as not found."))
    return Guide(check.id, "Stop DNS rewriting", intro, steps)


@guide("net.tls_interception")
def tls_interception(check, scan, outcome):
    from ..online import INTERCEPTOR, local_roots
    issuers = []
    for e in outcome.evidence:
        m = re.search(r"issued by (.+)$", str(e.value or ""))
        if m and m.group(1) not in issuers and (INTERCEPTOR.search(m.group(1)) or not issuers):
            issuers.append(m.group(1))
    m = re.search(r"issued by (.+?)\.?$", outcome.summary or "")
    if m and m.group(1) not in issuers:
        issuers.insert(0, m.group(1))
    issuer = next((i for i in issuers if INTERCEPTOR.search(i)), issuers[0] if issuers else "")
    word = re.split(r"[\s/,]+", issuer)[0] if issuer else ""
    roots = local_roots(scan)
    fam = family(scan)
    remove = {"debian": ("sudo rm {f} && sudo update-ca-certificates --fresh", "/usr/local/share/ca-certificates/NAME.crt"),
              "fedora": ("sudo rm {f} && sudo update-ca-trust", "/etc/pki/ca-trust/source/anchors/NAME.crt"),
              "arch": ("sudo trust anchor --remove {f}", "/etc/ca-certificates/trust-source/anchors/NAME.crt"),
              "suse": ("sudo rm {f} && sudo update-ca-certificates", "/etc/pki/trust/anchors/NAME.crt")}.get(fam or "")
    intro = ("Certificates of the sites tested are issued by " + (issuer or "something other than their real "
             "issuers") + ": something between this computer and the internet decrypts your HTTPS traffic, reads it "
             "and re-encrypts it with a certificate of its own, which this computer has been told to trust.")
    find = Step("Find what intercepts", "The issuer names the product. Antivirus suites (Kaspersky, ESET, "
                "Bitdefender, Avast…) do it with their \"HTTPS scanning\" or \"web protection\"; workplace and school "
                "networks with a proxy (Zscaler, Fortinet, Netskope…); a developer's own tool (mitmproxy, Charles) "
                "left on. The command lists the root certificate on this computer that makes it trusted"
                + (f"; the ones added locally here: {', '.join(roots[:6])}." if roots else "."),
                commands=[f"trust list | grep -i -B2 -A8 {shlex.quote(word)}"] if word else ["trust list"])
    cmds = []
    if remove:
        targets = roots[:3] or [remove[1]]
        cmds = [remove[0].format(f=f) for f in targets]
    program = Step("If it is a program on this computer",
                   "Turn off its HTTPS (SSL, TLS) scanning in its settings, or uninstall it; then remove its root "
                   "certificate from the system's store" + (" (replace NAME with the file the command above shows)"
                                                           if remove and not roots else "")
                   + ". Firefox keeps a store of its own: Settings → Privacy & Security → Certificates → View "
                   "Certificates → Authorities, delete the product's entry (with its scanning off first, or it adds it "
                   "back).", commands=cmds)
    network = Step("If it is the network's", "A proxy on a workplace, school or hotel network reads your HTTPS "
                   "traffic by design, and the certificate was installed by whoever manages this computer. Nothing on "
                   "this computer undoes that: use another network for anything private, and treat what you do on "
                   "this one as read by its owner. Tor Browser (Tools…) tunnels past a proxy that lets it through.")
    return Guide(check.id, "Stop HTTPS interception", intro, [find, program, network, _check_again(check.id)])


@guide("net.upnp_forwards")
def upnp_forwards(check, scan, outcome):
    forwards = []
    for e in outcome.evidence:
        m = re.match(r"Internet port (\d+)/(\w+)", str(e.label))
        n = re.search(r"this machine's port (\d+)(?: \((.*)\))?", str(e.value or ""))
        if m and n:
            forwards.append((int(m.group(1)), m.group(2).lower(), int(n.group(1)), n.group(2) or ""))
    listeners = scan.context.listeners or []
    lines, cmds = [], []
    for ext, proto, port, desc in forwards:
        who = next((s.process for s in listeners if s.port == port and s.proto == proto and s.process), None)
        lines.append(f"port {port}/{proto} (internet port {ext}): " + (who or desc or "no program the scan could name"))
        cmds.append(f"ss -lnp{proto[0]} 'sport = :{port}'")
    intro = ("A program on this computer asked the router to open " + (f"{len(forwards)} port{'s' if len(forwards) > 1 else ''}"
             if forwards else "ports") + " to it from the internet, and the router did, without asking you.")
    steps = [Step("Which program asked", ("The forwards lead to: " + "; ".join(lines) + ". " if lines else "")
                  + "BitTorrent clients, game launchers, media servers (Plex, Jellyfin) and Syncthing do this: turn "
                  "off \"UPnP\", \"NAT-PMP\" or \"port mapping\" in that program's connection settings. The commands "
                  "show what listens on each port now.", commands=cmds or ["ss -lntup"]),
             _router_step(scan, "Remove the forwards and turn UPnP off in the router",
                          "The router keeps the forwards until they expire or it is told to drop them. In its "
                          "settings, delete them (\"port forwarding\" or \"UPnP\" page) and turn UPnP off, so no "
                          "program on any device can open a port from the internet again."),
             Step("Keep a firewall", "A host firewall (net.firewall_off) blocks what the router lets through, "
                  "whatever a program asks for."),
             _check_again(check.id)]
    return Guide(check.id, "Close the ports the router opened", intro, steps)
