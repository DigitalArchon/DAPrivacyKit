"""Guided fixes: encryption (see the package docstring)."""

from __future__ import annotations

import shlex

from ... import blockdev
from ...context import read_swaps
from ...fix import RootChange, RootClear
from ...guide import Guide, Step
from .._util import isfile
from . import guide, option, unit_exists, service_off, dropin, _swap_steps, _hibernate_off


@guide("enc.swap_unencrypted")
def swap_unencrypted(check, scan, outcome):
    steps = _swap_steps(check, scan)
    if scan.context["hibernation"]:
        steps.append(_hibernate_off(check, scan, recommended=False))
    if scan.context["fde"] == "none":
        intro = ("Swap holds whatever didn't fit in memory, passwords and keys included, which no file on the disk "
                 "holds: on an unencrypted disk anyone who has it can read them. Until the disk is encrypted "
                 "(enc.fde_missing), keep swap in memory (zram) or encrypt it with a new key at every boot.")
    else:
        intro = ("Swap holds whatever didn't fit in memory, including documents and passwords from encrypted "
                 "volumes. Either keep it in memory (zram) or encrypt it.")
    return Guide(check.id, "Keep swapped-out memory off unencrypted disk", intro, steps)


@guide("enc.hibernate_unencrypted")
def hibernate_unencrypted(check, scan, outcome):
    return Guide(check.id, "Stop hibernation writing memory to unencrypted disk",
                 "A hibernation image is a full copy of memory, including the keys of other encrypted volumes.",
                 [_hibernate_off(check, scan),
                  Step("Or: keep hibernation and encrypt swap",
                       "Hibernation needs a swap device that survives a reboot, so a random-key swap won't do: it "
                       "has to sit inside a LUKS volume unlocked at boot (e.g. LVM on LUKS, as encrypted installs "
                       "set up). On an unencrypted system that means reinstalling with encryption; see "
                       "enc.fde_missing.")])


def _zram_writeback_step(scan) -> list[Step]:
    """zram writing back to a disk: the line is in zram-generator's configuration, which is the
    distribution's or the user's, so taking it out is for the user to do."""
    from .._util import read_text
    from ..encryption import ZRAM_CONFIGS, zram_backing, zram_writeback_configured
    host = scan.host
    active = [n for n, _, _ in read_swaps(host) if n.startswith("/dev/zram") and zram_backing(host, n)]
    if not active and not zram_writeback_configured(host):
        return []
    files = [f for f in ZRAM_CONFIGS if "writeback-device" in (read_text(host, host.sys_path(f)) or "")]
    for d in ("/etc/systemd/zram-generator.conf.d", "/usr/lib/systemd/zram-generator.conf.d"):
        files += [f"{d}/{c.name}" for c in sorted(host.sys_path(d).glob("*.conf"))
                  if "writeback-device" in (read_text(host, c) or "")]
    cmds = []
    for f in files:
        # the distribution's own file is overridden by one of the same name in /etc, not edited
        target = f.replace("/usr/lib/", "/etc/", 1) if f.startswith("/usr/lib/") else f
        if target != f:
            cmds.append(f"sudo cp {f} {target}")
        cmds.append(f"sudoedit {target}     # delete the writeback-device line")
    cmds.append("sudo reboot     # a zram device's writeback can only be turned off when it is set up again")
    return [Step("Turn off zram writeback",
                  "zram is meant to keep swap in memory, but with writeback it moves idle or incompressible pages to a "
                  "disk, where they stay after a reboot. Without it, nothing leaves memory. (Or encrypt the writeback "
                  "device with a new random key at each boot, in /etc/crypttab, as for a swap partition.)",
                  commands=cmds, side_effects=["zram can then hold less: what doesn't fit goes to any disk swap "
                                               "you still have, or memory runs out sooner."])]


@guide("enc.swap_persistent")
def swap_persistent(check, scan, outcome):
    steps = _zram_writeback_step(scan) + _swap_steps(check, scan)
    return Guide(check.id, "Make swap forget its contents at shutdown",
                 "Swap on disk keeps old memory pages after a reboot (even if encrypted, under a key that is "
                 "unlocked every boot). zram without writeback, or a random-key swap, leaves nothing behind.", steps
                 + [Step("Hibernation", "Both options rule out hibernation, which needs swap that survives a reboot.")])


@guide("enc.tpm_no_pin")
def tpm_no_pin(check, scan, outcome):
    devices = [d.path for d in blockdev.luks_devices(scan.context.devices or [])] or ["<your LUKS partition>"]
    return Guide(check.id, "Add a PIN to TPM unlocking",
                 "With TPM-only unlocking, anyone who has the machine boots straight to the login screen with the "
                 "disk unlocked. A PIN makes the TPM release the key only after it is typed.", [
                     Step("Make sure you can still unlock without the TPM",
                          "Re-enrolling replaces the TPM key slot. Check a passphrase slot exists (look for a "
                          "keyslot not used by a token), or add a recovery key and write it down.",
                          commands=[c for d in devices for c in (f"sudo cryptsetup luksDump {d}",
                                                                 f"sudo systemd-cryptenroll --recovery-key {d}")]),
                     Step("Enrol the TPM again, with a PIN",
                          "You will be asked for the PIN twice. If the TPM was set up with Clevis, remove its "
                          "binding first (sudo clevis luks list -d DEVICE, then sudo clevis luks unbind -d DEVICE "
                          "-s SLOT).",
                          commands=[f"sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-with-pin=yes {d}"
                                    for d in devices],
                          side_effects=["You type the PIN at every boot. Too many wrong PINs and the TPM locks you "
                                        "out for a while (use the passphrase then)."]),
                 ])


@guide("enc.backups_unencrypted")
def backups(check, scan, outcome):
    steps = []
    labels = {e.label for e in outcome.evidence}
    if any(lbl.startswith("Unencrypted Déjà Dup") or lbl == "Déjà Dup" for lbl in labels):
        steps.append(Step("Déjà Dup: start an encrypted backup",
                          "Déjà Dup can't encrypt a backup it has already made. In Backups → Preferences, choose a "
                          "new (empty) folder or drive, and set an encryption password when it asks. Once the first "
                          "encrypted backup has finished, delete the old, unencrypted backup files yourself.",
                          commands=["deja-dup --backup"]))
    if "Timeshift" in labels:
        steps.append(Step("Timeshift: keep its snapshots on an encrypted drive",
                          "Timeshift doesn't encrypt. Point it at a LUKS-encrypted drive, or leave your home folder "
                          "out of its snapshots (Settings → Users → Exclude All).",
                          side_effects=["Timeshift is meant for system files; use an encrypting tool for your own "
                                        "files."]))
    steps.append(Step("Encrypting backup tools",
                      "restic and Borg always encrypt; Déjà Dup can use restic. For example:",
                      commands=["restic -r /media/backup/restic init", "borg init --encryption=repokey /media/backup/borg"]))
    return Guide(check.id, "Encrypt your backups",
                 "A backup drive is as sensitive as the disk it copies, and easier to lose.", steps)


@guide("enc.coredumps_retained", keys=("turn_off",))
def coredumps(check, scan, outcome):
    from ..encryption import NOTHING_KEPT, crash_dumps
    steps = []
    pattern = (scan.host.read_sys("/proc/sys/kernel/core_pattern") or "").strip()
    retained, _, _ = crash_dumps(scan.host)
    done = retained is False
    if "systemd-coredump" in pattern:
        steps.append(Step("Don't keep core dumps",
                          "systemd-coredump logs that a program crashed, but doesn't store its memory." if done else
                          "systemd-coredump still logs that a program crashed, but no longer stores its memory.",
                          options=[] if done else [option(check, "Stop storing core dumps", [dropin(
                              "coredump", {"Storage": "none", "ProcessSizeMax": "0"},
                              "/etc/systemd/coredump.conf.d/60-daprivacyscanner.conf")], recommended=True,
                              key="turn_off")],
                          side_effects=[] if done else ["Developers lose the dumps they'd use to debug a crash."],
                          done=done))
    elif "apport" in pattern:
        steps.append(Step("Turn off apport",
                          "apport is turned off." if done else
                          "apport writes crash reports, including memory, to /var/crash.",
                          options=[] if done else [option(check, "Turn off apport", [
                              RootChange("edit_config", {"target": "apport"}, "Set enabled=0 in /etc/default/apport"),
                              *service_off(scan, "apport.service")], recommended=True, key="turn_off")],
                          side_effects=[] if done else ["Ubuntu no longer offers to report crashes."], done=done))
    elif pattern and not NOTHING_KEPT.match(pattern) and not pattern.startswith("|"):
        steps.append(Step("Stop programs writing core files",
                          "The programs you run get a core size limit under a page: the kernel writes no core file."
                          if done else
                          "The kernel writes core files next to crashing programs. Limit their size to zero for "
                          "every login:",
                          commands=[] if done else ["echo '* hard core 0' | sudo tee /etc/security/limits.d/60-no-core.conf"],
                          done=done))
    existing = sum(e.value for e in outcome.evidence if e.kind == "count" and isinstance(e.value, int))
    if existing:
        steps.append(Step("Delete the dumps already on disk",
                          f"{existing} dump{'s are' if existing > 1 else ' is'} stored now.",
                          options=[option(check, "Delete existing core dumps and crash reports", [RootClear(
                              "clear_crash_dumps", {},
                              "Delete core dumps in /var/lib/systemd/coredump and crash reports in /var/crash")])]))
    return Guide(check.id, "Stop keeping crash dumps",
                 "A core dump is a copy of a crashed program's memory: whatever it had open, including passwords.",
                 steps)


@guide("enc.journal_persistent", keys=("two_weeks",))
def journal(check, scan, outcome):
    from ... import ini
    from .._util import human_size
    from ..encryption import (JOURNAL_LIMIT, _layered, journal_in_memory, journal_usage, plain_span, syslog_daemon,
                              syslog_listed, syslog_names, timespan)
    path = "/etc/systemd/journald.conf.d/60-daprivacyscanner.conf"
    host = scan.host
    in_memory = journal_in_memory(host)
    retention = (ini.get(_layered(host, "journald.conf"), "Journal", "MaxRetentionSec") or "").strip()
    span = timespan(retention) if retention else None
    memory = option(check, "Keep it in memory only (lost at every reboot)",
                    [dropin("journald", {"Storage": "volatile"}, path)],
                    side_effects=["Logs of a crash or failed boot are gone after the reboot that follows, when you'd "
                                  "want them.",
                                  "The logs already on the disk stay until deleted: this guide then offers to delete "
                                  "them."])
    if in_memory:
        # a time limit would only weaken it (one drop-in holds both: "two weeks" replaced Storage=volatile)
        steps = [Step("Choose how long to keep it", "The journal is kept in memory only, and gone at every restart: a "
                      "time limit has nothing to add.", done=True)]
    else:
        weaker = lambda limit: span is not None and span <= limit          # noqa: E731 - already as short, or shorter
        opts = ([] if weaker(14 * 86400) else [option(
                    check, "Keep two weeks", [dropin("journald", {"MaxRetentionSec": "2week"}, path)],
                    detail="Roughly: journald deletes a whole file at a time, when it starts a new one (monthly by "
                           "default), so some entries stay a while longer. The next step deletes the older ones now.",
                    recommended=True, key="two_weeks")]) + \
               ([] if weaker(7 * 86400) else [option(
                    check, "Keep one week", [dropin("journald", {"MaxRetentionSec": "1week"}, path)],
                    detail="Roughly, as above: entries older than a week go when their file is rotated.")]) + [memory]
        done = span is not None and span <= JOURNAL_LIMIT
        steps = [Step("Choose how long to keep it",
                      f"It is kept for at most {plain_span(span)} now; keeping it in memory only goes further." if done
                      else "", options=opts, done=done,
                      side_effects=["journald restarts to apply it; older logs are no longer there for "
                                    "troubleshooting."])]
    files, used = journal_usage(host.sys_path("/var/log/journal"))
    if in_memory and files:
        steps.append(Step("Delete the journal files left on the disk",
                          f"journald keeps the journal in memory now, but the files it wrote to the disk before are "
                          f"still in /var/log/journal ({files} file{'s' if files != 1 else ''}, {human_size(used)}): "
                          "logins, USB devices, Wi-Fi networks. journalctl --vacuum-time never deletes the files "
                          "journald was last writing to, so this deletes them all. Its folders stay, so reverting the "
                          "setting keeps the journal on the disk again.",
                          options=[option(check, "Delete the journal files in /var/log/journal", [RootClear(
                              "clear_journal_files", {}, "Delete the journal files in /var/log/journal")])]))
    elif not in_memory:
        steps.append(Step("Delete older entries now", "Without this, old journal files stay until journald rotates "
                          "them, which the time limit above only applies at.",
                          options=[option(check, "Delete journal entries older than two weeks", [RootClear(
                              "vacuum_journal", {"time": "2weeks"}, "journalctl --vacuum-time=2weeks")]),
                                   option(check, "Delete journal entries older than one week", [RootClear(
                                       "vacuum_journal", {"time": "1weeks"}, "journalctl --vacuum-time=1weeks")])]))
    daemon, unit, logs = syslog_daemon(host)
    names = syslog_names(host)
    clear = RootClear("clear_syslog", {}, f"Delete the text logs in /var/log the syslog daemon wrote "
                      f"({syslog_listed(names, 4)}, with their rotated copies)")
    if daemon and logs.files:
        readers = " or ".join(f"/var/log/{n}" for n in names[:2]) or "the text logs in /var/log"
        steps.append(Step(f"Stop {daemon} keeping a copy of its own",
                          f"{daemon} writes every message the journal gets to text files in /var/log, kept for weeks or "
                          "longer whatever the journal is set to. On a systemd system the journal already "
                          "has them all, so it isn't needed unless something reads those files.",
                          options=[option(check, f"Turn off {daemon} and delete its text logs",
                                          service_off(scan, unit) + [clear], recommended=True,
                                          side_effects=[
                                              f"Programs that read {readers} (fail2ban, logwatch) need to read the "
                                              "journal instead (journalctl).",
                                              f"Reverting from History starts {daemon} again; the deleted logs stay "
                                              "deleted."])]))
    elif logs.files and not daemon:
        steps.append(Step("Delete the text logs left in /var/log",
                          f"A syslog daemon isn't running, but the text logs one wrote are still there ({logs.describe()}).",
                          options=[option(check, "Delete them", [clear])]))
    return Guide(check.id, "Limit how long the system's logs are kept",
                 "The journal records logins, USB devices, Wi-Fi networks and app activity.", steps)


@guide("enc.tmp_on_disk", keys=("tmp_mount",))
def tmp_on_disk(check, scan, outcome):
    effects = ["/tmp is emptied at every boot and limited in size (half of RAM by default); a program that puts "
               "large files in /tmp may run out of room.",
               "Takes effect after a reboot: mounting it now would hide the files of programs that are running.",
               "What is in /tmp on the disk at that reboot stays there, hidden under the mount (the distribution "
               "normally clears it at boot, so it is one session's worth)."]
    from .._util import systemctl_state
    if unit_exists(scan, "tmp.mount") and systemctl_state(scan.host, "is-enabled", "tmp.mount") == "enabled":
        step = Step("Mount /tmp in memory", "tmp.mount is enabled: /tmp is in memory from the next boot.", done=True)
    elif unit_exists(scan, "tmp.mount"):
        step = Step("Mount /tmp in memory", options=[option(check, "Enable tmp.mount", [RootChange(
            "set_service", {"unit": "tmp.mount", "enable": True, "start": None},
            "Enable tmp.mount (systemctl enable tmp.mount) from the next boot")], recommended=True, key="tmp_mount")],
            side_effects=effects)
    elif isfile(scan.host.sys_path("/usr/share/systemd/tmp.mount")):
        step = Step("Mount /tmp in memory", "Your distribution ships systemd's tmp.mount but doesn't install it; "
                    "enabling it from where it is links it in.", options=[option(check, "Enable tmp.mount", [RootChange(
                        "enable_tmp_mount", {}, "Link and enable the distribution's tmp.mount "
                        "(systemctl enable /usr/share/systemd/tmp.mount), from the next boot")], recommended=True,
                        key="tmp_mount")],
                    side_effects=effects)
    else:
        step = Step("Mount /tmp in memory", "Add this line to /etc/fstab:",
                    commands=["echo 'tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,mode=1777,size=50% 0 0' | "
                              "sudo tee -a /etc/fstab"], side_effects=effects)
    return Guide(check.id, "Keep /tmp in memory", "Temporary files then never reach the disk.", [step])


# ------------------------------------------------------------------ LUKS key derivation

def _grub_unlocks(scan, devices, container) -> bool:
    """GRUB opens this container itself at boot (/boot is inside it and GRUB_ENABLE_CRYPTODISK is on):
    GRUB as most distributions ship it reads only PBKDF2 keyslots."""
    import re
    from .._util import read_text
    cfg = read_text(scan.host, scan.host.sys_path("/etc/default/grub")) or ""
    if not re.search(r'^\s*GRUB_ENABLE_CRYPTODISK="?y', cfg, re.M):
        return False
    d = blockdev.holding(devices, "/boot")
    while d is not None:
        if d.path == container.path:
            return True
        d = d.parent
    return False


@guide("enc.luks_weak_kdf")
def luks_weak_kdf(check, scan, outcome):
    from ...privileged import HelperError
    devices = scan.context.devices or []
    steps, unread = [], []
    for dev in blockdev.luks_devices(devices):
        try:
            dump = scan.privileged.luks_dump(dev.path) if scan.privileged else None
        except HelperError:
            dump = None
        if dump is None:
            unread.append(dev)
            continue
        token_slots = {k for t in dump["tokens"] for k in t["keyslots"]}
        backup = [f"sudo cryptsetup luksHeaderBackup {dev.path} --header-backup-file luks-header-{dev.name}.img"]
        keep_backup = ("Keep the header backup on a USB stick until you've restarted and unlocked the disk, then delete "
                       "it: it still holds the old keyslots.")
        grub = _grub_unlocks(scan, devices, dev)
        if dump["version"] == 1 and grub:
            # the usual reason for LUKS1: GRUB opens /boot from it, and most GRUB builds can't open Argon2 keyslots
            steps.append(Step(f"{dev.path}: GRUB unlocks it at boot",
                              "This disk is LUKS1 because GRUB opens it to read /boot, and GRUB as most distributions "
                              "ship it can't open the Argon2 keyslots LUKS2 would bring: converting it would leave the "
                              "computer unable to boot. Use a long passphrase (five or more random words) instead, or "
                              "move /boot to a partition of its own (when reinstalling is the safest time) before "
                              "converting."))
            continue
        if dump["version"] == 1:
            steps.append(Step(f"{dev.path}: upgrade LUKS1 to LUKS2 first",
                              "LUKS1 only knows PBKDF2. Converting the header to LUKS2 has to be done while the disk is "
                              "closed: for the disk the system runs from, start from a live USB. Back up the header "
                              "first; then convert, and convert each keyslot to Argon2id (the commands below, for "
                              "keyslot 0; repeat for each).",
                              commands=backup + [f"sudo cryptsetup convert --type luks2 {dev.path}",
                                                 f"sudo cryptsetup luksConvertKey {dev.path} --key-slot 0 --pbkdf argon2id"],
                              side_effects=[keep_backup]))
            continue
        weak = [k for k in dump["keyslots"] if k["id"] not in token_slots
                and (k["pbkdf"] or "").lower() not in ("argon2id", "argon2i")]
        if not weak:
            continue
        if grub:
            steps.append(Step(f"{dev.path}: GRUB unlocks it at boot",
                              "/boot is on this encrypted disk, and GRUB asks for the passphrase. GRUB as most "
                              "distributions ship it can only open PBKDF2 keyslots, so converting the one it uses would "
                              "leave the computer unable to boot. Use a long passphrase (five or more random words) "
                              "for that keyslot instead, or move /boot to its own partition (see "
                              "enc.boot_no_secureboot for what protects it there) before converting."))
            continue
        cmds = [f"sudo cryptsetup luksConvertKey {dev.path} --key-slot {k['id']} --pbkdf argon2id" for k in weak]
        steps.append(Step(f"{dev.path}: convert {'keyslots' if len(weak) > 1 else 'keyslot'} "
                          f"{', '.join(str(k['id']) for k in weak)} to Argon2id",
                          "First back up the header, then convert. Each command asks for that keyslot's passphrase "
                          "(if you have one passphrase, it is keyslot " + str(weak[0]["id"]) + "). Then press Check "
                          "again.", commands=backup + cmds, side_effects=[
                              keep_backup, "Unlocking takes about two seconds and briefly uses up to 1 GB of memory, "
                              "by design."]))
    if unread:
        # the headers couldn't be read now (administrator access ended): the same steps, keyslot by hand
        steps.append(Step("Find the weak keyslots", "Each keyslot is listed with its PBKDF: the ones that say pbkdf2 "
                          "and aren't used by a token (FIDO2, TPM, recovery key) are the ones to convert.",
                          commands=[f"sudo cryptsetup luksDump {d.path}" for d in unread]))
        steps.append(Step("Back up the header, then convert each one",
                          "Replace 0 with the keyslot's number. Each command asks for that keyslot's passphrase. If "
                          "GRUB asks for the passphrase before the boot menu (/boot is on the encrypted disk), don't "
                          "convert the keyslot it uses: GRUB can't open Argon2id keyslots.",
                          commands=[c for d in unread for c in (
                              f"sudo cryptsetup luksHeaderBackup {d.path} --header-backup-file luks-header-{d.name}.img",
                              f"sudo cryptsetup luksConvertKey {d.path} --key-slot 0 --pbkdf argon2id")]))
    return Guide(check.id, "Protect disk passphrases with Argon2id",
                 "Each passphrase of an encrypted disk unlocks a keyslot, and the keyslot's key derivation decides how "
                 "expensive each guess is for someone trying passphrases. PBKDF2 can be run fast on graphics cards; "
                 "Argon2id needs a lot of memory for every guess, which those can't supply cheaply. Converting a "
                 "keyslot keeps its passphrase: you type it once, and it takes a few seconds. Keyslots used by a "
                 "security key (FIDO2), the TPM or a recovery key hold long random keys: they use PBKDF2 on purpose, "
                 "since no one can guess them, and are left as they are.", steps)


# ------------------------------------------------------------------ snapshots

SNAPSHOT_HOOKS = (   # what makes a snapshot at every package change: (file it installs, package, family)
    ("/usr/share/libalpm/hooks/05-snap-pac-pre.hook", "snap-pac", "arch"),
    ("/usr/lib/zypp/plugins/commit/snapper.py", "snapper-zypp-plugin", "suse"),
    ("/etc/apt/apt.conf.d/80snapper", None, "debian"),
)


@guide("enc.snapshots_retain_deleted")
def snapshots(check, scan, outcome):
    from ...fix import RootChange, RootClear
    from ...guide import Input
    from ..encryption import snapper_configs, snapper_keeps, timeshift_keeps, timeshift_settings
    from . import family, remove
    host = scan.host
    keep = Input.read(scan.params, "keep", "number", 10, 2, 50)
    pick = Input("keep", "Snapshots to keep", "number", keep, 10, min=2, max=50, unit="per kind",
                 help="The most recent update snapshots, and at most this many hourly and daily ones (no weekly, "
                      "monthly or yearly ones). Ten is enough to undo a bad update from the last few days.")
    lose = ("A snapshot is how a bad update is undone: on CachyOS, openSUSE and Fedora with snapper, you can boot an "
            "earlier snapshot from the boot menu and roll back. Without them, a broken update means repairing from a "
            "live USB.")
    configs, _ = snapper_configs(scan)
    steps = _home_out_steps(check, scan, configs)
    if configs:
        names = ", ".join(n for n, _ in configs)
        now = "; ".join(f"{n}: {snapper_keeps(c)}" for n, c in configs)
        fewer = {"NUMBER_LIMIT": str(keep), "NUMBER_LIMIT_IMPORTANT": str(min(keep, 5)),
                 "TIMELINE_LIMIT_HOURLY": str(min(keep, 5)), "TIMELINE_LIMIT_DAILY": str(min(keep, 7)),
                 "TIMELINE_LIMIT_WEEKLY": "0", "TIMELINE_LIMIT_MONTHLY": "0", "TIMELINE_LIMIT_QUARTERLY": "0",
                 "TIMELINE_LIMIT_YEARLY": "0"}
        off = {"TIMELINE_CREATE": "no", "NUMBER_LIMIT": "0", "NUMBER_LIMIT_IMPORTANT": "0",
               **{f"TIMELINE_LIMIT_{k}": "0" for k in ("HOURLY", "DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "YEARLY")}}
        cleanup = RootClear("snapper_cleanup", {}, "Run snapper's clean-up now, deleting the snapshots beyond the new limits")
        steps.append(Step(f"Snapper ({names}): keep fewer", f"Now: {now}.", inputs=[pick], options=[option(
            check, f"Keep at most {keep} of each", [RootChange("edit_config", {"target": "snapper", "values": fewer},
                                                                "Set snapper's limits in /etc/snapper/configs/*"), cleanup],
            recommended=True, side_effects=["Snapshots beyond the new limits are deleted now; they can't be brought "
                                            "back. Undoing a bad update still works within the ones kept."])]))
        hook = next(((f, pkg, fam) for f, pkg, fam in SNAPSHOT_HOOKS if isfile(host.sys_path(f))), None)
        cmds = []
        if hook and hook[1] and family(scan) == hook[2]:
            cmds.append(remove(scan, **{hook[2]: hook[1]}))
        elif hook:
            cmds.append(f"sudo mv {hook[0]} {hook[0]}.disabled")
        steps.append(Step(f"Snapper ({names}): or turn snapshots off",
                          "Stops the timeline and keeps no update snapshots: each is deleted at snapper's next clean-up. "
                          + ("Updates still make a snapshot pair while the package hook is installed; the command "
                             "below removes it." if cmds else ""),
                          options=[option(check, "Turn snapper's snapshots off and delete them",
                                          [RootChange("edit_config", {"target": "snapper", "values": off},
                                                      "Turn the timeline off and keep no snapshots in /etc/snapper/configs/*"),
                                           cleanup],
                                          side_effects=["Not recommended. " + lose, "Every existing snapshot is deleted "
                                                        "now (those under an hour old at the next clean-up); they can't "
                                                        "be brought back."])],
                          commands=cmds))
    ts = timeshift_settings(scan)
    if ts is not None and str(ts.get("btrfs_mode")).lower() == "true" and ts.get("backup_device_uuid"):
        fewer = {"count_hourly": str(min(keep, 5)), "count_daily": str(min(keep, 7)), "count_boot": str(min(keep, 3)),
                 "count_weekly": "0", "count_monthly": "0", "schedule_weekly": "false", "schedule_monthly": "false"}
        steps.append(Step("Timeshift: keep fewer", f"Now: {timeshift_keeps(ts)}. Timeshift deletes the extra snapshots "
                          "at its next scheduled run.", inputs=[] if configs else [pick], options=[option(
                              check, f"Keep at most {min(keep, 7)} daily and no weekly or monthly snapshots",
                              [RootChange("edit_config", {"target": "timeshift", "values": fewer},
                                          "Set Timeshift's schedule and counts in /etc/timeshift/timeshift.json")],
                              recommended=True)]))
        steps.append(Step("Timeshift: or turn it off", "Stops scheduled snapshots. Existing ones stay until you delete "
                          "them; the command deletes every Timeshift snapshot.", options=[option(
                              check, "Stop Timeshift's scheduled snapshots",
                              [RootChange("edit_config", {"target": "timeshift", "values": {
                                  f"schedule_{k}": "false" for k in ("hourly", "daily", "weekly", "monthly", "boot")}},
                                  "Turn off every schedule in /etc/timeshift/timeshift.json")],
                              side_effects=["Not recommended. " + lose])],
                          commands=["sudo timeshift --delete-all"]))
    from ..encryption import btrbk_retention
    bt = btrbk_retention(scan.host)
    if bt is not None and not bt[0]:
        steps.append(Step("btrbk: keep fewer", f"Now: {bt[1]}. In /etc/btrbk/btrbk.conf set snapshot_preserve_min 2d and "
                          "snapshot_preserve 7d (a week of daily snapshots); btrbk deletes the older ones the next time "
                          "it runs. Backups it sends to another drive (target_preserve) are kept as that line says.",
                          commands=["sudoedit /etc/btrbk/btrbk.conf", "sudo btrbk run --dry-run     # shows what it would delete"]))
    if any(e.label == "ZFS snapshots" for e in outcome.evidence):
        steps.append(Step("ZFS", "List the snapshots, and destroy the ones you don't need (that can't be undone). If a "
                          "tool takes them on a schedule (zfs-auto-snapshot, sanoid, zrepl), lower its retention in its "
                          "own settings.", commands=["zfs list -t snapshot -o name,creation,used",
                                                     "sudo zfs destroy pool/dataset@snapshot-name"]))
    return Guide(check.id, "Keep fewer snapshots of deleted files",
                 "A snapshot freezes the filesystem as it was. A file you delete afterwards stays in every snapshot "
                 "taken before, readable by an administrator, until that snapshot is deleted: with monthly and yearly "
                 "snapshots, that is up to a year. Keeping fewer, shorter-lived snapshots shortens that. Your home "
                 "folder is where most of your personal data is: keep it out of snapshots altogether, and back it up "
                 "with a backup program that encrypts instead.", steps)


def _home_out_steps(check, scan, configs) -> list[Step]:
    """Taking the home folder out of the snapshots that include it (enc.snapshots_retain_deleted's home_snapshotted)."""
    from .._util import mounts
    from ..encryption import _btrfs_place, home_snapshotted, home_subvolume, timeshift_btrfs, timeshift_settings
    host = scan.host
    ts = timeshift_settings(scan)
    ts = ts if timeshift_btrfs(ts) else None
    r = host.run("zfs", "list", "-H", "-t", "snapshot", "-o", "name")
    hits, _ = home_snapshotted(scan, configs, ts, r.stdout if r.ok else "")
    if not hits:
        return []
    ms = mounts(host)
    sv = home_subvolume(host, ms)
    in_system = bool(sv) and sv == _btrfs_place(ms, "/")      # no subvolume of its own: it is in @ with the system
    steps = []
    if ts is not None and str(ts.get("include_btrfs_home_for_backup")).lower() == "true":
        steps.append(Step("Timeshift: leave your home folder out", "Timeshift takes snapshots of @home too (\"Include "
                          "@home\" in its settings). It is meant for undoing a bad update, which never needs your files. "
                          "Its snapshots already taken keep their copy of @home until Timeshift deletes them on its "
                          "schedule; the command deletes every Timeshift snapshot now, system ones included.",
                          options=[option(check, "Leave @home out of Timeshift's snapshots",
                                           [RootChange("edit_config", {"target": "timeshift",
                                                                       "values": {"include_btrfs_home_for_backup": "false"}},
                                                       "Turn off \"Include @home\" in /etc/timeshift/timeshift.json")],
                                           recommended=True,
                                           side_effects=["Timeshift can no longer restore your home folder: back it up "
                                                         "with a backup program that encrypts (Pika Backup, Vorta, Déjà "
                                                         "Dup)."])],
                          commands=["sudo timeshift --delete-all"]))
    if in_system:
        home = str(host.home)
        q, old = shlex.quote(home), shlex.quote(home + ".old")
        steps.append(Step("Give your home folder a subvolume of its own",
                          f"Your home folder ({home}) is in the same btrfs subvolume as the system, so every snapshot "
                          "of the system has your files in it too. A subvolume of its own isn't in the system's "
                          "snapshots. Log out first, then do this from a text console (Ctrl+Alt+F3) logged in as root "
                          "or another administrator: your files are copied into the new subvolume (instantly: btrfs "
                          "shares the data, nothing is written twice), and the old folder deleted once you have checked "
                          "everything is there. Snapshots taken before keep their copy until they expire.",
                          commands=[f"sudo mv {q} {old}", f"sudo btrfs subvolume create {q}",
                                    f"sudo chown --reference={old} {q}", f"sudo chmod --reference={old} {q}",
                                    f"sudo cp -a --reflink=always {old}/. {q}/",
                                    f"sudo rm -rf {old}     # once you have logged in and checked your files"],
                          side_effects=["Your home folder is then not in any snapshot: back it up with a backup program "
                                        "that encrypts (Pika Backup, Vorta, Déjà Dup)."]))
    own = [n[len("Snapper ("):-1] for n in hits if n.startswith("Snapper (")]
    own = [n for n in own if not (in_system and _btrfs_place(ms, dict(configs)[n].get("SUBVOLUME", "")) == sv)]
    if own:
        steps.append(Step("Snapper: stop snapshotting your home folder",
                          f"Snapper's {', '.join(own)} config takes snapshots of the subvolume your home folder is in. "
                          "Deleting the config stops them and deletes every snapshot it took (that can't be undone); "
                          "the system's own config, which undoes bad updates, stays.",
                          commands=[f"sudo snapper -c {shlex.quote(n)} delete-config" for n in own]))
    if "btrbk" in hits and not in_system:
        steps.append(Step("btrbk: stop snapshotting your home folder",
                          f"In /etc/btrbk/btrbk.conf, remove the subvolume line that names your home folder's subvolume "
                          f"({sv[1] if sv else 'the one it is in'}). btrbk then leaves its snapshots alone: delete them "
                          "with btrfs subvolume delete, from the snapshot folder that config names.",
                          commands=["sudoedit /etc/btrbk/btrbk.conf", "sudo btrbk list snapshots",
                                    "sudo btrfs subvolume delete /path/of/snapshot"]))
    for name in hits:
        if name.startswith("ZFS ("):
            datasets = name[len("ZFS ("):-1].split(", ")
            steps.append(Step("ZFS: stop snapshotting your home folder",
                              f"The datasets {', '.join(datasets)} hold your home folder and have snapshots. Turn off "
                              "the snapshot tool's schedule for them (the command does it for zfs-auto-snapshot; sanoid "
                              "and zrepl have it in their own settings), then destroy the snapshots you don't need (that "
                              "can't be undone).",
                              commands=[*(f"sudo zfs set com.sun:auto-snapshot=false {shlex.quote(d)}" for d in datasets),
                                        *(f"zfs list -t snapshot -o name,creation,used {shlex.quote(d)}" for d in datasets),
                                        "sudo zfs destroy pool/dataset@snapshot-name"]))
    return steps


# ------------------------------------------------------------------ TRIM

def _initramfs_command(scan) -> str | None:
    which = scan.host.runner.which
    for tool, cmd in (("update-initramfs", "sudo update-initramfs -u -k all"),
                      ("dracut", "sudo dracut -f --regenerate-all"), ("mkinitcpio", "sudo mkinitcpio -P")):
        if which(tool):
            return cmd
    return None


def _grub_update_command(scan) -> str:
    which = scan.host.runner.which
    if which("update-grub"):
        return "sudo update-grub"
    if which("grub2-mkconfig"):
        return "sudo grub2-mkconfig -o /boot/grub2/grub.cfg"
    return "sudo grub-mkconfig -o /boot/grub/grub.cfg"


def _cmdline_steps(scan, param: str, new: str) -> tuple[str, list[str]]:
    """How to change one kernel command line parameter on this machine: text and commands."""
    host = scan.host
    if host.runner.which("grubby"):
        return (f"Change {param} to {new} on the kernel command line (grubby does it for every installed kernel):",
                [f"sudo grubby --update-kernel=ALL --remove-args='{param}' --args='{new}'"])
    if isfile(host.sys_path("/etc/default/grub")):
        return (f"In /etc/default/grub, change {param} to {new} (on the GRUB_CMDLINE_LINUX line), then rebuild GRUB's "
                "menu:", ["sudoedit /etc/default/grub", _grub_update_command(scan)])
    return (f"Change {param} to {new} where your boot loader keeps the kernel command line (systemd-boot: the options "
            "line of the entries in /boot/loader/entries or /efi/loader/entries).", [])


def _crypttab_line(scan, name: str) -> str | None:
    from ...host import Unreadable
    try:
        text = scan.host.read_sys("/etc/crypttab") or ""
    except Unreadable:
        return None
    for line in text.splitlines():
        f = line.split()
        if f and not f[0].startswith("#") and f[0] == name:
            return line.strip()
    return None


def _with_discard(line: str) -> str:
    f = line.split()
    while len(f) < 3:
        f.append("none")
    opts = [o for o in (f[3].split(",") if len(f) > 3 else []) if o]
    if "discard" not in opts:
        opts.append("discard")
    return " ".join(f[:3] + [",".join(opts)] + f[4:])


def _luks1_step(scan, name: str, device: str | None, root: bool) -> Step:
    import re
    cmdline = scan.host.read_sys("/proc/cmdline") or ""
    commands = [f"sudo cryptsetup --allow-discards refresh {name}"]
    text = [f"LUKS1 can't keep the setting in the disk's header. The first command allows TRIM through {name} now "
            "(it asks for a passphrase), until the next restart; then it has to be set where this system unlocks the "
            "disk at boot."]
    cryptdevice = re.search(r"(?:^|\s)(cryptdevice=(\S+))", cmdline)
    rd_options = re.search(r"(?:^|\s)(rd\.luks\.options=(\S+))", cmdline)
    if root and cryptdevice:                        # Arch's encrypt hook: the kernel command line, crypttab unused
        parts = cryptdevice.group(2).split(":")
        if len(parts) == 2:
            parts.append("allow-discards")
        elif "allow-discards" not in parts[2].split(","):
            parts[2] = ",".join([p for p in parts[2].split(",") if p] + ["allow-discards"])
        how, cmds = _cmdline_steps(scan, cryptdevice.group(1), "cryptdevice=" + ":".join(parts))
        text.append("It is unlocked by the initramfs from the kernel command line (cryptdevice=), which doesn't read "
                    "/etc/crypttab. " + how)
        commands += cmds
    elif root and rd_options:                       # dracut and systemd's sd-encrypt: these override crypttab
        value = rd_options.group(2)
        new = value if "discard" in re.split(r"[,=]", value) else value + ",discard"
        how, cmds = _cmdline_steps(scan, rd_options.group(1), "rd.luks.options=" + new)
        text.append("The kernel command line sets its unlock options (rd.luks.options), which take the place of "
                    "/etc/crypttab's at boot. " + how)
        commands += cmds
    else:
        line = _crypttab_line(scan, name)
        if line:
            text.append(f"In /etc/crypttab, change its line\n  {line}\nto\n  {_with_discard(line)}")
        else:
            text.append(f"Add discard to the options (the fourth column) of {name}'s line in /etc/crypttab.")
        commands.append("sudoedit /etc/crypttab")
        if root:
            regen = _initramfs_command(scan)
            text.append("The disk is unlocked by the initramfs, which keeps its own copy of crypttab: rebuild it."
                        if regen else "The disk is unlocked by the initramfs, which keeps its own copy of crypttab: "
                        "rebuild it the way this distribution does.")
            if regen:
                commands.append(regen)
    return Step(f"Allow TRIM through {name} (LUKS1)", "\n".join(text), commands=commands)


@guide("enc.trim_off", keys=("weekly_timer",))
def trim_off(check, scan, outcome):
    from ...storage import luks_version, stacks, underlying
    from ..encryption import trim_timer
    host = scan.host
    steps: list[Step] = []
    usage = ("Through encryption, TRIM shows which parts of the disk are in use (roughly how full it is, and which "
             "filesystem it holds), not what they hold.")
    all_stacks = stacks(host)
    root_layers = {x.name for st in all_stacks if st.mount == "/" for x in st.layers}
    seen = set()
    for st in all_stacks:
        if st.hard_disk:
            continue
        for layer in st.layers:
            if layer.discard_max != 0 or layer.name in seen:
                continue
            seen.add(layer.name)
            if layer.kind == "crypt":
                version = luks_version(host, layer)
                device = underlying(host, layer)
                if version is None and device and scan.privileged is not None:
                    try:
                        version = scan.privileged.luks_dump(device)["version"]
                    except Exception:  # noqa: BLE001 - asked for the version below instead
                        version = None
                if version == 1:
                    steps.append(_luks1_step(scan, layer.label, device, layer.name in root_layers))
                else:
                    cmd = f"sudo cryptsetup --allow-discards --persistent refresh {layer.label}"
                    steps.append(Step(
                        f"Allow TRIM through {layer.label}",
                        "This keeps the setting in the encrypted disk's own header (LUKS2), so it works at once and "
                        "at every start, however this system unlocks the disk; nothing in /etc/crypttab or the "
                        "initramfs needs changing. It asks for one of the disk's passphrases (a recovery key works "
                        "too)." + ("" if version == 2 else " (If it answers that the device is LUKS1, run "
                                   f"sudo cryptsetup luksDump {device or '/dev/…'} | head to check, and scan again "
                                   "with administrator access for the LUKS1 steps.)"),
                        commands=[cmd], side_effects=[usage]))
            elif layer.kind == "md" and layer.label in ("raid4", "raid5", "raid6"):
                regen = _initramfs_command(scan)
                steps.append(Step(
                    f"RAID array {layer.name}: only if every drive in it reads zeros after TRIM",
                    f"Linux drops TRIM on RAID 4, 5 and 6 ({layer.name} is {layer.label}) unless told every member "
                    "drive reads trimmed blocks back as zeros: the array's parity is computed over those blocks, and "
                    "a drive that returned anything else after TRIM would make a rebuild produce wrong data. The TRIM "
                    "test (Tools…) shows what each drive reports. If every one reports zeros, this allows it from the "
                    "next start:",
                    commands=["echo 'options raid456 devices_handle_discard_safely=Y' | sudo tee "
                              "/etc/modprobe.d/raid456-discard.conf"] + ([regen] if regen else []),
                    side_effects=["Wrong when a drive doesn't really read zeros after TRIM: the array can then lose "
                                  "data on a rebuild. When in doubt, leave it."]))
    timer = trim_timer(host)
    if any(not st.hard_disk and not st.continuous for st in all_stacks):
        if timer == "enabled":
            pass
        elif unit_exists(scan, "fstrim.timer"):
            steps.append(Step("Trim every week",
                              "Nothing runs TRIM here yet. The fstrim timer trims every filesystem on an SSD once a "
                              "week, as most distributions set up by default.",
                              options=[option(check, "Turn on the weekly TRIM timer", [RootChange(
                                  "set_service", {"unit": "fstrim.timer", "enable": True, "start": True},
                                  "Enable and start fstrim.timer (systemctl enable --now fstrim.timer)")],
                                  recommended=True, key="weekly_timer")]))
        else:
            steps.append(Step("Trim every week", "This system has no fstrim timer (it comes with util-linux on most "
                              "distributions). Trim by hand when you want instead:", commands=["sudo fstrim -av"]))
    steps.append(Step("Check that it works",
                      "Restarting isn't needed for the steps above unless they say so. The TRIM test (Tools…) then "
                      "shows whether deleted data really is dropped by the drive. To trim at once at any time:",
                      commands=["sudo fstrim -av"]))
    return Guide(check.id, "Turn on TRIM",
                 "TRIM tells the SSD which blocks deleted files used, and most drives then stop returning their old "
                 "data. It has to reach the drive through every layer (an encrypted disk has to allow it) and "
                 "something has to run it: the fstrim timer once a week is enough. /etc/fstab doesn't need changing: "
                 "its discard option trims at every delete, which the timer makes unnecessary and which slows some "
                 "drives (btrfs turns on a background version of it by itself on SSDs since Linux 6.2). Volume "
                 "managers (LVM) pass TRIM on as they are.", steps)
