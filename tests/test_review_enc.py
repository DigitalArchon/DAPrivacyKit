"""Encryption and kernel checks corrected after the review of 2026-10-17 (what a P330 with Mint 22.3, the Ubuntu 26.04,
Fedora 44 and Omarchy VMs showed, and what reading the checks against their fixes found)."""

import pytest

from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status

from conftest import detect, ev, lsblk, make_host, make_scan
from test_guides import _advice, system  # noqa: F401 - the root helper on the fixture tree

UBUNTU = lsblk("ubuntu-24.04-luks-lvm.json")
EFIVARS = "/sys/firmware/efi/efivars"
GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


# ------------------------------------------------------------------ Secure Boot

def _efi(host, secure_boot: bytes | None):
    host.sys_path(EFIVARS).mkdir(parents=True)
    host.sys_path(f"{EFIVARS}/SetupMode-{GLOBAL}").write_bytes(b"\x06\x00\x00\x00\x00")
    if secure_boot is not None:
        host.sys_path(f"{EFIVARS}/SecureBoot-{GLOBAL}").write_bytes(b"\x06\x00\x00\x00" + secure_boot)


@pytest.mark.parametrize("value, said", [(b"\x00", "off (the firmware's SecureBoot setting)"),
                                         (b"\x01", "on (the firmware's SecureBoot setting)"),
                                         (None, "off (the firmware doesn't support Secure Boot)")])
def test_the_secure_boot_variable_is_read_under_the_efi_global_guid(cat, tmp_path, value, said):
    """The variable is SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c (seen on the P330, where mokutil says
    "SecureBoot disabled"): a wrong GUID made every UEFI machine "doesn't support Secure Boot"."""
    host = make_host(tmp_path)
    _efi(host, value)
    assert ev(detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=UBUNTU)))["Secure Boot"] == said


def test_the_helper_may_read_the_right_variable():
    from daprivacyscanner import helper
    assert helper.readable(f"{EFIVARS}/SecureBoot-{GLOBAL}")
    assert not helper.readable(f"{EFIVARS}/SecureBoot-8be4df61-93ca-11d2-aa0d-e39e1ffa9b81")


MOK = "/var/lib/shim-signed/mok/MOK.der"
MINT = {"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", MOK: "der",
        "/proc/sys/kernel/osrelease": "7.0.0-38-generic\n",
        "/usr/lib/modules/7.0.0-38-generic/updates/dkms/nvidia.ko.zst": "",
        "/usr/lib/modules/7.0.0-38-generic/updates/dkms/nvidia-drm.ko.zst": ""}


def test_secure_boot_guide_enrols_the_drivers_key_first_where_it_isnt(cat, tmp_path):
    """On the P330 NVIDIA's DKMS module is signed by a key of the machine's own that is neither enrolled nor waiting:
    turning Secure Boot on would leave the driver unloaded, so its enrolment comes first."""
    said = CommandResult((), 1, "", f"Failed to accesss kernel trusted keyring: Required key not available\n"
                                    f"{MOK} is not enrolled\n")
    host = make_host(tmp_path, files=MINT, commands={("mokutil", "--test-key", MOK): said})
    g = _advice(cat, host, "enc.boot_no_secureboot")
    first, firmware = g.steps[0], g.steps[1]
    assert first.title.startswith("First: enrol the key")
    assert first.commands == [f"sudo mokutil --import {MOK}", f"mokutil --test-key {MOK}"]
    assert "nvidia, nvidia-drm" in first.text and "wouldn't load" in first.text
    assert "MOK" not in firmware.text and "enrolled" not in firmware.text


@pytest.mark.parametrize("answer, words", [(f"{MOK} is already enrolled\n", "is enrolled already"),
                                           (f"{MOK} is already in the enrollment request\n", "waiting to be enrolled")])
def test_secure_boot_guide_says_where_the_drivers_key_stands(cat, tmp_path, answer, words):
    host = make_host(tmp_path, files=MINT, commands={("mokutil", "--test-key", MOK): answer})
    g = _advice(cat, host, "enc.boot_no_secureboot")
    assert g.steps[0].title == "Turn it on in the firmware" and words in g.steps[0].text


def test_secure_boot_guide_without_a_drivers_key_says_what_would_be_needed(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": "ID=fedora\n"})
    step = _advice(cat, host, "enc.boot_no_secureboot").steps[0]
    assert step.title == "Turn it on in the firmware" and "has to be enrolled first" in step.text


# ------------------------------------------------------------------ where the kernels really are

def _no_boot_partition(devices):
    out = [d for d in devices if "/boot" not in d.mountpoints]
    for d in out:
        d.mountpoints = ["/efi" if m == "/boot/efi" else m for m in d.mountpoints]
    return out


def test_kernels_on_the_efi_partition_are_not_on_encrypted_storage(cat, tmp_path):
    """systemd-boot with unified kernel images: no /boot partition, the root encrypted, the ESP at /efi holding the
    kernels. "/boot is on encrypted storage" was a false pass."""
    host = make_host(tmp_path, files={"/efi/EFI/Linux/arch-linux.efi": "MZ", "/efi/EFI/systemd/systemd-bootx64.efi": "MZ"})
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=_no_boot_partition(lsblk("ubuntu-24.04-luks-lvm.json"))))
    assert o.status is Status.FAIL and "/efi" in o.summary
    assert ev(o)["/efi"].endswith("not encrypted")


def test_systemd_boot_entries_name_kernels_on_the_efi_partition(cat, tmp_path):
    host = make_host(tmp_path, files={
        "/efi/loader/entries/abc-6.12.conf": "title Linux\nlinux /abc/6.12/linux\ninitrd /abc/6.12/initrd\n",
        "/efi/abc/6.12/linux": "MZ", "/efi/abc/6.12/initrd": "x"})
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=_no_boot_partition(lsblk("ubuntu-24.04-luks-lvm.json"))))
    assert o.status is not Status.PASS


def test_grub_with_boot_on_the_encrypted_root_still_passes(cat, tmp_path):
    """Only GRUB's own program is on the EFI partition; the kernels are in /boot on the encrypted root."""
    host = make_host(tmp_path, files={"/boot/vmlinuz-6.8.0": "x", "/boot/initrd.img-6.8.0": "x",
                                      "/efi/EFI/ubuntu/grubx64.efi": "MZ"})
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=_no_boot_partition(lsblk("ubuntu-24.04-luks-lvm.json"))))
    assert o.status is Status.PASS and o.summary == "/boot is on encrypted storage."


# ------------------------------------------------------------------ hibernation

def _hib_host(tmp_path, files=None, logind=None):
    base = {"/sys/power/state": "freeze mem disk\n", "/sys/power/disk": "[platform] shutdown reboot\n",
            "/proc/swaps": "Filename Type Size Used Priority\n/swap.img file 4194300 0 -1\n",
            "/proc/cmdline": "ro quiet resume=UUID=x\n", "/sys/power/resume": "0:0\n",
            "/sys/power/image_size": str(2 * 2**30)}
    host = make_host(tmp_path, files={**base, **(files or {})})
    asked = []
    if logind is not None:
        def busctl(argv):
            asked.append(argv[-1])
            said = logind.get(argv[-1], "na") if isinstance(logind, dict) else logind
            return CommandResult(argv, 0, f's "{said}"\n')
        host.runner.handlers["busctl"] = busctl
    return host, asked


def test_hibernation_turned_off_in_sleep_conf_is_off(cat, tmp_path):
    """The guide's "Turn hibernation off" writes this drop-in; it was never read, so the check never passed and swap
    stayed at severity 9."""
    from daprivacyscanner.context import detect_hibernation
    dropin = "[Sleep]\nAllowHibernation=no\nAllowSuspendThenHibernate=no\nAllowHybridSleep=no\n"
    host, asked = _hib_host(tmp_path, {"/etc/systemd/sleep.conf.d/60-daprivacyscanner.conf": dropin}, logind="yes")
    v = detect_hibernation(host)
    assert v.value is False and "sleep settings" in v.note and asked == []
    o = detect(cat, "enc.hibernate_unencrypted", make_scan(host, hibernation=v))
    assert o.status is Status.PASS and "turned off in systemd's sleep settings" in o.summary


def test_a_mode_switched_back_on_still_hibernates(tmp_path):
    """sleep.conf(5): AllowHibernation=no turns suspend-then-hibernate and hybrid sleep off too, unless they say yes."""
    from daprivacyscanner.context import detect_hibernation
    host, asked = _hib_host(tmp_path, {"/etc/systemd/sleep.conf": "[Sleep]\nAllowHibernation=no\nAllowHybridSleep=yes\n"},
                            logind={"CanHybridSleep": "yes"})
    assert detect_hibernation(host).value is True and asked == ["CanHybridSleep"]


def test_a_dropin_of_the_same_name_in_etc_hides_the_vendors(tmp_path):
    from daprivacyscanner import ini
    from daprivacyscanner.context import systemd_config
    host = make_host(tmp_path, files={"/usr/lib/systemd/sleep.conf.d/10-x.conf": "[Sleep]\nAllowHibernation=no\n",
                                      "/etc/systemd/sleep.conf.d/10-x.conf": "[Sleep]\nAllowSuspend=yes\n",
                                      "/usr/lib/systemd/sleep.conf.d/20-y.conf": "[Sleep]\nHibernateDelaySec=1h\n"})
    cfg, used = systemd_config(host, "sleep.conf")
    assert ini.get(cfg, "Sleep", "AllowHibernation") is None and ini.get(cfg, "Sleep", "HibernateDelaySec") == "1h"
    assert used == ["/etc/systemd/sleep.conf.d/10-x.conf", "/usr/lib/systemd/sleep.conf.d/20-y.conf"]


def test_ubuntus_policy_refusing_hibernation_makes_it_one_step_away(tmp_path):
    """Ubuntu's com.ubuntu.desktop.rules refuses login1.hibernate to users and logind's CanHibernate answers "no" (seen
    on 26.04): a Problem 9 on a stock install was wrong. An administrator can still hibernate: a risk note says so."""
    from daprivacyscanner.context import detect_hibernation
    host, _ = _hib_host(tmp_path, logind="no")
    v = detect_hibernation(host)
    assert v.value is False and "policy" in v.note
    [note] = v.notes
    assert note.title == "Hibernation is one step away" and "sudo systemctl hibernate" in note.text
    host, _ = _hib_host(tmp_path / "b", logind="challenge")
    assert detect_hibernation(host).value is True


def test_without_logind_a_hibernation_the_rest_allows_is_unknown(cat, tmp_path):
    from daprivacyscanner.context import detect_hibernation
    host, _ = _hib_host(tmp_path)
    v = detect_hibernation(host)
    assert v.value is None and v.notes[0].kind == "limitation"
    assert detect(cat, "enc.hibernate_unencrypted", make_scan(host, hibernation=v)).status is Status.UNKNOWN


FEDORA = lsblk("fedora-40-btrfs-luks.json")
SWAPFILE = {"/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n/home/swapfile file 8388604 0 -2\n",
            "/sys/power/resume": "0:0\n", "/sys/power/state": "freeze mem disk\n", "/etc/os-release": "ID=fedora\n"}


def test_suspend_then_hibernate_set_up_by_the_guide_passes(cat, tmp_path, system, monkeypatch):
    """The check read only /sys/power/state, so neither of the guide's fixes was recognised, and its "this check shows
    it at the next scan" was wrong."""
    from daprivacyscanner.checks import load_all
    from test_guides import apply, options, revert, rooted
    host = make_host(tmp_path, files=SWAPFILE)
    rooted(host, system, monkeypatch)
    scan = make_scan(host, devices=FEDORA, hibernation=True, fde="full")
    assert detect(cat, "kern.suspend_keys_in_ram", scan).status is Status.FAIL
    check = load_all()["kern.suspend_keys_in_ram"](cat["kern.suspend_keys_in_ram"])
    log, res = apply(host, options(check.plan_guide(scan, Outcome(Status.FAIL, "x")))["Suspend, then hibernate after 1 hour"])
    o = detect(cat, "kern.suspend_keys_in_ram", scan)
    assert o.status is Status.PASS and "hibernates after 1 hour" in o.summary
    assert next(s for s in check.plan_guide(scan, o).steps if s.title.startswith("Hibernate")).done
    o = detect(cat, "kern.suspend_keys_in_ram", make_scan(host, devices=FEDORA, hibernation=False, fde="full"))
    assert o.status is Status.FAIL and "hibernation doesn't work here" in o.summary       # gone back to plain suspend
    revert(host, log, res)


def test_plasma_and_cinnamon_decide_the_lid_themselves(cat, tmp_path):
    """PowerDevil and Cinnamon's settings daemon hold logind's lid inhibitor: their own settings count, and the guide
    says where they are."""
    from daprivacyscanner.checks import load_all
    from fakes import FakeGSettings
    check = load_all()["kern.suspend_keys_in_ram"](cat["kern.suspend_keys_in_ram"])
    host = make_host(tmp_path, files=SWAPFILE,
                     home_files={".config/powerdevilrc": "[Battery][SuspendAndShutdown]\nSleepMode=3\n"})
    kde = make_scan(host, devices=FEDORA, hibernation=True, fde="full", desktop=("kde",), plasma_major=6)
    assert detect(cat, "kern.suspend_keys_in_ram", kde).status is Status.PASS
    (host.home / ".config/powerdevilrc").write_text("[Battery][SuspendAndShutdown]\nSleepMode=1\n")
    step = next(s for s in check.plan_guide(kde, Outcome(Status.FAIL, "x")).steps if s.title.startswith("Hibernate"))
    assert "System Settings → Power Management" in step.text and "Standby, then hibernate" in step.text
    assert [a.args["name"] for o in step.options for a in o.plan.actions] == ["sleep-delay", "sleep-delay"]

    gs = FakeGSettings({("org.cinnamon.settings-daemon.plugins.power", "lid-close-battery-action"): "'suspend'",
                        ("org.cinnamon.settings-daemon.plugins.power", "inhibit-lid-switch"): "true"})
    host = make_host(tmp_path / "c", files={**SWAPFILE, "/etc/systemd/logind.conf.d/60-x.conf":
                                            "[Login]\nHandleLidSwitch=suspend-then-hibernate\n"})
    host.runner.handlers["gsettings"] = gs
    cin = make_scan(host, devices=FEDORA, hibernation=True, fde="full", desktop=("x-cinnamon",))
    assert detect(cat, "kern.suspend_keys_in_ram", cin).status is Status.FAIL      # Cinnamon holds the lid: logind's isn't used
    step = next(s for s in check.plan_guide(cin, Outcome(Status.FAIL, "x")).steps if "lid" in s.title.lower())
    assert "When the lid is closed to Hibernate" in step.text and not step.options
    gs.values[("org.cinnamon.settings-daemon.plugins.power", "lid-close-battery-action")] = "'hibernate'"
    cin = make_scan(host, devices=FEDORA, hibernation=True, fde="full", desktop=("x-cinnamon",))
    o = detect(cat, "kern.suspend_keys_in_ram", cin)
    assert o.status is Status.PASS and "closing the lid hibernates" in o.summary


def test_cryptsetup_suspend_installed_passes(cat, tmp_path):
    host = make_host(tmp_path, files={**SWAPFILE, "/usr/lib/systemd/system/systemd-suspend.service.d/"
                                                  "cryptsetup-suspend.conf": "[Service]\n"})
    o = detect(cat, "kern.suspend_keys_in_ram", make_scan(host, devices=FEDORA, hibernation=False, fde="full"))
    assert o.status is Status.PASS and "cryptsetup-suspend" in o.summary


# ------------------------------------------------------------------ crash dumps

LIMITS = "Limit                     Soft Limit           Hard Limit           Units     \nMax core file size        {} unlimited bytes\n"


def _core_host(tmp_path, pattern, parent_limit="0", files=None):
    return make_host(tmp_path, files={"/proc/sys/kernel/core_pattern": pattern + "\n",
                                      "/proc/self/limits": LIMITS.format("1"),           # the app's own (no_core_dumps)
                                      "/proc/self/status": "Name:\tpython3\nPPid:\t4242\n",
                                      "/proc/4242/limits": LIMITS.format(parent_limit), **(files or {})})


@pytest.mark.parametrize("pattern, parent, status", [
    ("core", "0", Status.PASS),                    # Debian, or Ubuntu after apport is off: the session's limit is 0
    ("core", "unlimited", Status.WARN),            # would be kept: a risk while none is there
    ("|/bin/false", "unlimited", Status.PASS),     # a handler that keeps nothing
    ("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F", "0", Status.PASS),   # %c under a page: not stored
    ("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F", "unlimited", Status.WARN),
    ("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h %d", "0", Status.WARN),  # Mint: fixed
    ("|/usr/libexec/some-handler %p", "0", Status.UNKNOWN),
])
def test_crash_dumps_go_by_the_limit_of_the_programs_you_run(cat, tmp_path, pattern, parent, status):
    """It read /proc/self/limits, the app's own, which app.no_core_dumps sets to 1: always "kept" where core_pattern is
    a plain file (Debian; Ubuntu after the apport fix; |/bin/false too)."""
    o = detect(cat, "enc.coredumps_retained", make_scan(_core_host(tmp_path, pattern, parent)))
    assert o.status is status, o.summary


def test_crash_dumps_kept_but_none_there_is_a_risk(cat, tmp_path):
    """"Crash dumps are kept on disk" at severity 5 with none there: now a risk, rated below the problem."""
    host = _core_host(tmp_path, "|/usr/share/apport/apport -p%p -s%s -c%c", files={"/etc/default/apport": "enabled=1\n"})
    host.sys_path("/var/crash").mkdir(parents=True)
    o = detect(cat, "enc.coredumps_retained", make_scan(host))
    assert o.status is Status.WARN and "none is there now" in o.summary
    (host.sys_path("/var/crash") / "_usr_bin_x.1000.crash").write_text("x")
    o = detect(cat, "enc.coredumps_retained", make_scan(host))
    assert o.status is Status.FAIL and "1 is there now" in o.summary


def test_crash_dump_guide_marks_storing_off_as_done(cat, tmp_path):
    """No done=: Easy fixes offered "Stop storing core dumps" again after it was applied."""
    from daprivacyscanner.checks import load_all
    pattern = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h %d"
    host = _core_host(tmp_path, pattern, files={
        "/etc/systemd/coredump.conf.d/60-daprivacyscanner.conf": "[Coredump]\nStorage=none\nProcessSizeMax=0\n"})
    check = load_all()["enc.coredumps_retained"](cat["enc.coredumps_retained"])
    scan = make_scan(host)
    o = check.detect(scan)
    assert o.status is Status.PASS
    [step] = check.plan_guide(scan, o).steps
    assert step.done and not step.options


def test_the_browser_panel_uses_the_same_answer(tmp_path):
    from daprivacyscanner.tools import browser as B
    assert B.risks(_core_host(tmp_path, "core", "0"))["crash_dumps"]["kept"] is False


# ------------------------------------------------------------------ the journal

MID = "0123456789abcdef0123456789abcdef"
VOLATILE = {"/etc/systemd/journald.conf.d/60-daprivacyscanner.conf": "[Journal]\nStorage=volatile\n"}


def _journal_guide(cat, host):
    from daprivacyscanner.checks import load_all
    check = load_all()["enc.journal_persistent"](cat["enc.journal_persistent"])
    scan = make_scan(host)
    o = check.detect(scan)
    return o, check.plan_guide(scan, o)


def test_easy_never_turns_a_journal_in_memory_into_two_weeks(cat, tmp_path):
    """After "Keep it in memory only", Easy fixes offered "Keep two weeks", which replaced Storage=volatile in the same
    drop-in: a downgrade."""
    host = make_host(tmp_path, files={**VOLATILE, f"/var/log/journal/{MID}/system.journal": "x"})
    o, g = _journal_guide(cat, host)
    first = g.steps[0]
    assert first.done and not first.options
    assert not any(opt.key == "two_weeks" for s in g.steps for opt in s.options)


def test_a_shorter_limit_isnt_lengthened(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/systemd/journald.conf.d/50-x.conf": "[Journal]\nMaxRetentionSec=1week\n"})
    host.sys_path("/var/log/journal").mkdir(parents=True)
    o, g = _journal_guide(cat, host)
    assert o.status is Status.PASS and o.summary == "The journal is kept on disk for at most one week."
    first = g.steps[0]
    assert first.done and [opt.label for opt in first.options] == ["Keep it in memory only (lost at every reboot)"]


def test_journal_files_left_on_disk_are_deleted_by_the_helper(cat, tmp_path, monkeypatch):
    """Once in memory, the only deletion was --vacuum-time, which leaves system.journal and user-*.journal: the check
    kept warning. The helper deletes them, keeps the folders, and refuses while journald still writes there."""
    from daprivacyscanner import helper
    from daprivacyscanner.fix import apply_plan
    from daprivacyscanner.privileged import FakePrivileged
    from daprivacyscanner.undo import UndoLog
    from fakes import FakeSystem
    host = make_host(tmp_path, files={**VOLATILE, f"/var/log/journal/{MID}/system.journal": "x" * 5000,
                                      f"/var/log/journal/{MID}/user-1000.journal": "x",
                                      f"/var/log/journal/{MID}/system@abc-0001-0002.journal~": "x",
                                      f"/var/log/journal/{MID}/notes.txt": "kept"})
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    host.privileged = FakePrivileged()
    o, g = _journal_guide(cat, host)
    assert o.status is Status.WARN
    step = next(s for s in g.steps if s.title == "Delete the journal files left on the disk")
    plan = step.options[0].plan
    assert plan.irreversible and plan.to_dict()["steps"][0]["commands"] == [
        "rm -f /var/log/journal/*/*.journal /var/log/journal/*/*.journal~"]
    # journald writing there: refused
    host.sys_path("/proc/77/fd").mkdir(parents=True)
    host.sys_path("/proc/77/comm").write_text("systemd-journal\n")
    os_link = host.sys_path("/proc/77/fd/5")
    os_link.symlink_to(f"/var/log/journal/{MID}/system.journal")
    res = apply_plan(plan, host, UndoLog(host.home / ".local/state/daprivacyscanner"), confirmed_irreversible=True)
    assert not res.ok and "journald is writing" in res.error
    os_link.unlink()
    res = apply_plan(plan, host, UndoLog(host.home / ".local/state/daprivacyscanner"), confirmed_irreversible=True)
    assert res.ok, res.error
    left = sorted(p.name for p in host.sys_path(f"/var/log/journal/{MID}").iterdir())
    assert left == ["notes.txt"]
    assert detect(cat, "enc.journal_persistent", make_scan(host)).status is Status.PASS


def test_journal_size_is_what_it_takes_on_the_disk(cat, tmp_path):
    host = make_host(tmp_path)
    f = host.sys_path(f"/var/log/journal/{MID}/system.journal")
    f.parent.mkdir(parents=True)
    with open(f, "wb") as fh:
        fh.seek(300 * 1024 * 1024)
        fh.write(b"x")                                      # 300 MB long, a few KB on the disk
    o = detect(cat, "enc.journal_persistent", make_scan(host))
    assert "300" not in ev(o)["Journal on disk"] and ev(o)["Journal on disk"].endswith("on the disk")


def test_syslog_files_are_named_as_this_machine_has_them(cat, tmp_path):
    """"(syslog, auth.log and others)" is Debian's; Fedora's rsyslog writes messages, secure, maillog and cron."""
    from daprivacyscanner.checks import load_all
    host = make_host(tmp_path, files={"/var/log/messages": "x", "/var/log/secure": "x", "/var/log/messages-20261011": "x",
                                      "/var/log/cron": "x", "/etc/systemd/journald.conf": "[Journal]\n"})
    host.runner.handlers["systemctl"] = lambda argv: CommandResult(
        argv, 0, "active\n" if argv[1:] == ("is-active", "rsyslog.service") else "inactive\n")
    host.sys_path("/var/log/journal").mkdir(parents=True)
    o = detect(cat, "enc.journal_persistent", make_scan(host))
    assert "(messages, secure and cron)" in o.summary and "syslog" not in o.summary.replace("rsyslog", "")
    check = load_all()["enc.journal_persistent"](cat["enc.journal_persistent"])
    g = check.plan_guide(make_scan(host), o)
    opt = next(opt for s in g.steps for opt in s.options if opt.label.startswith("Turn off rsyslog"))
    assert "/var/log/messages or /var/log/secure" in " ".join(opt.plan.side_effects)


# ------------------------------------------------------------------ the trash

def test_clean_deletes_trashed_folders_and_links_whole(cat, tmp_path):
    """Clean… deleted regular files only: empty folders, folders of empty folders and links stayed in Trash/files while
    their records went, the check kept failing, and with only those left it said "no fix here"."""
    import os
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.fix import apply_plan
    from daprivacyscanner.undo import UndoLog
    host = make_host(tmp_path, home_files={".local/share/Trash/files/report.pdf": "x",
                                           ".local/share/Trash/files/project/src/main.c": "int",
                                           ".local/share/Trash/info/report.pdf.trashinfo": "[Trash Info]",
                                           ".local/share/Trash/info/project.trashinfo": "[Trash Info]",
                                           ".local/share/Trash/info/empty.trashinfo": "[Trash Info]",
                                           ".local/share/Trash/info/link.trashinfo": "[Trash Info]",
                                           "Documents/keep.txt": "mine"})
    files = host.home / ".local/share/Trash/files"
    (files / "empty" / "inner").mkdir(parents=True)                       # a folder of empty folders
    os.symlink(host.home / "Documents", files / "link")                   # a link to a folder of the user's
    check = load_all()["enc.trash"](cat["enc.trash"])
    scan = make_scan(host, desktop=("kde",))
    o = check.detect(scan)
    assert o.status is Status.FAIL and o.summary.startswith("4 items")
    plan = check.plan_fix(scan, o)
    shown = plan.dry_run()
    assert "Delete 4 items" in shown and "(a link: the link only)" in shown and "project/  (a folder" in shown
    res = apply_plan(plan, host, UndoLog(host.home / ".local/state/daprivacyscanner"), confirmed_irreversible=True)
    assert res.ok, res.error
    assert list(files.iterdir()) == [] and list((host.home / ".local/share/Trash/info").iterdir()) == []
    assert (host.home / "Documents/keep.txt").read_text() == "mine"           # never through the link
    assert check.detect(make_scan(host, desktop=("kde",))).status is Status.PASS


def test_trash_only_folders_left_can_still_be_cleaned(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    host = make_host(tmp_path)
    (host.home / ".local/share/Trash/files/old").mkdir(parents=True)
    check = load_all()["enc.trash"](cat["enc.trash"])
    scan = make_scan(host, desktop=("kde",))
    plan = check.plan_fix(scan, check.detect(scan))
    assert not plan.empty and plan.actions[0].whole


# ------------------------------------------------------------------ swap

MINT_LVM = {"blockdevices": [{"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoints": [None], "children": [
    {"name": "nvme0n1p2", "type": "part", "fstype": "ext4", "mountpoints": ["/boot"]},
    {"name": "nvme0n1p3", "type": "part", "fstype": "crypto_LUKS", "mountpoints": [None], "children": [
        {"name": "nvme0n1p3_crypt", "type": "crypt", "fstype": "LVM2_member", "mountpoints": [None], "children": [
            {"name": "vgmint-root", "type": "lvm", "fstype": "ext4", "mountpoints": ["/"]},
            {"name": "vgmint-swap_1", "type": "lvm", "fstype": "swap", "mountpoints": ["[SWAP]"]}]}]}]}]}
OMARCHY = {"blockdevices": [{"name": "vda", "type": "disk", "fstype": None, "mountpoints": [None], "children": [
    {"name": "vda1", "type": "part", "fstype": "vfat", "mountpoints": ["/boot"]},
    {"name": "vda2", "type": "part", "fstype": "btrfs", "mountpoints": ["/", "/home", "/swap"]}]},
    {"name": "zram0", "type": "disk", "fstype": "swap", "mountpoints": ["[SWAP]"]}]}


def _guide(cat, check_id, host, devices, **ctx):
    from daprivacyscanner.checks import load_all
    check = load_all()[check_id](cat[check_id])
    return check.plan_guide(make_scan(host, devices=devices, **ctx), Outcome(Status.FAIL, "x"))


def test_random_key_swap_on_lvm_inside_luks_names_the_volume(cat, tmp_path):
    """The P330: swap on a logical volume inside LUKS. The step printed "cryptswap PARTUUID=<PARTUUID of /dev/dm-2>":
    a logical volume has no PARTUUID."""
    import json
    from daprivacyscanner import blockdev
    host = make_host(tmp_path, files={"/proc/swaps": "Filename Type Size Used Priority\n/dev/dm-2 partition 2002940 0 -1\n",
                                      "/sys/block/dm-2/dm/name": "vgmint-swap_1\n", "/etc/os-release": "ID=linuxmint\n"})
    g = _guide(cat, "enc.swap_persistent", host, blockdev.parse_lsblk(json.dumps(MINT_LVM)), hibernation=False)
    step = next(s for s in g.steps if s.title.startswith("Or: encrypt the swap"))
    joined = "\n".join(step.commands)
    assert "PARTUUID" not in joined and "/dev/dm-2" not in joined
    assert step.commands[0] == "sudo swapoff /dev/mapper/vgmint-swap_1"
    assert "cryptswap /dev/mapper/vgmint-swap_1 /dev/urandom" in joined
    assert "inside the encrypted disk" in step.text and "encrypted while the computer is off already" in step.text
    zram = g.steps[0]
    assert "sudo swapoff /dev/mapper/vgmint-swap_1" in zram.commands
    assert g.steps[-1].text.startswith("Both options rule out")


def test_zram_already_on_isnt_set_up_again(cat, tmp_path):
    """Omarchy: /dev/zram0 in use beside /swap/swapfile. The guide printed zram-generator's install and a config that
    would overwrite its configuration; and the swap file stayed on the disk with old memory pages."""
    import json
    from daprivacyscanner import blockdev
    host = make_host(tmp_path, files={"/proc/swaps": "Filename Type Size Used Priority\n/swap/swapfile file 6052928 0 0\n"
                                                     "/dev/zram0 partition 6052860 0 100\n",
                                      "/usr/lib/systemd/system-generators/zram-generator": "",
                                      "/etc/os-release": "ID=omarchy\nID_LIKE=arch\n"})
    g = _guide(cat, "enc.swap_persistent", host, blockdev.parse_lsblk(json.dumps(OMARCHY)), hibernation=False)
    step = g.steps[0]
    assert "zram is on already (/dev/zram0)" in step.text and not step.options
    assert not any("zram-generator" in c or "pacman" in c for c in step.commands)
    assert step.commands == ["sudo swapoff /swap/swapfile", "sudoedit /etc/fstab     # put a # in front of the swap line",
                             "sudo rm /swap/swapfile     # once it is off and out of /etc/fstab"]
    assert any("deleting it doesn't erase them" in e for e in step.side_effects)
    assert g.steps[-1].text.startswith("Keeping swap in memory rules out")     # only zram is offered


def test_zram_generator_configured_but_not_running_is_started_not_rewritten(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/swaps": "Filename Type Size Used Priority\n/swap.img file 4194300 0 -1\n",
                                      "/usr/lib/systemd/system-generators/zram-generator": "",
                                      "/usr/lib/systemd/zram-generator.conf": "[zram0]\n", "/etc/os-release": "ID=fedora\n"})
    g = _guide(cat, "enc.swap_persistent", host, UBUNTU, hibernation=False)
    step = g.steps[0]
    assert not step.options and "sudo systemctl start /dev/zram0" in step.commands
    assert not any("tee /etc/systemd/zram-generator.conf" in c for c in step.commands)


# ------------------------------------------------------------------ TRIM through LVM on LUKS

def _lvm_on_luks(r, crypt="0", lv="0"):
    """/ on the logical volume vgmint-root (dm-1) inside LUKS (dm-0), as Mint and Ubuntu install it."""
    import os
    from test_trimtest import link, make_storage, write
    make_storage(r, luks="no-discards")
    write(r / "sys/devices/virtual/block/dm-0/queue/discard_max_bytes", crypt + "\n")
    dm = r / "sys/devices/virtual/block/dm-1"
    write(dm / "dm/name", "vgmint-root\n")
    write(dm / "dm/uuid", "LVM-abcdef\n")
    write(dm / "queue/discard_max_bytes", lv + "\n")
    write(dm / "stat", " ".join(["0"] * 17) + "\n")
    link(dm / "slaves/dm-0", "../../dm-0")
    link(r / "sys/class/block/dm-1", "../../devices/virtual/block/dm-1")
    link(r / "dev/mapper/vgmint-root", "../dm-1")
    (r / "proc/self/mounts").write_text("/dev/mapper/vgmint-root / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n")
    write(r / "sys/devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p2/dev", "259:2\n")
    write(r / "run/udev/data/b259:2", "E:ID_FS_TYPE=crypto_LUKS\nE:ID_FS_VERSION=2\n")
    assert os.path.exists(r / "sys/class/block/dm-1/slaves/dm-0/dm/name")


def _trim(cat, r, privileged=None):
    from daprivacyscanner.checks import load_all
    from test_trim_guide import host_for
    host = host_for(r)
    host.privileged = privileged
    check = load_all()["enc.trim_off"](cat["enc.trim_off"])
    scan = make_scan(host, fde="full")
    o = check.detect(scan)
    return check, scan, o


def test_lvm_on_luks_without_discards_gets_the_luks_step_and_the_volume_refresh(cat, tmp_path, monkeypatch):
    """storage.Stack.stop found the logical volume, not the crypt layer: blocked stayed empty and the user saw "The
    guide doesn't cover this machine". After the refresh the volume keeps discard_max_bytes 0 until lvchange --refresh
    or a restart, yet the guide said it "works at once"."""
    from daprivacyscanner import helper
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    _lvm_on_luks(r)
    check, scan, o = _trim(cat, r)
    assert o.status is Status.FAIL and "encrypted volume luks-1 isn't opened with discards allowed" in o.summary
    assert check.blocked == {"luks"} and check.can_fix(scan, o)
    luks = check.plan_guide(scan, o).steps[0]
    assert luks.commands == ["sudo cryptsetup --allow-discards --persistent refresh luks-1",
                             "sudo lvchange --refresh vgmint"]
    assert "works at once" not in luks.text and "vgmint" in luks.text and "luksDump" in luks.text


def test_a_volume_not_refreshed_since_the_luks_change_gets_its_refresh(cat, tmp_path, monkeypatch):
    from daprivacyscanner import helper
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    _lvm_on_luks(r, crypt="2199023255040", lv="0")
    check, scan, o = _trim(cat, r)
    assert o.status is Status.FAIL and "lvchange --refresh" in o.summary and check.blocked == {"refresh"}
    [step, _] = check.plan_guide(scan, o).steps
    assert step.commands == ["sudo lvchange --refresh vgmint"]


def test_the_luks_refresh_keeps_the_flags_already_in_the_header(cat, tmp_path, monkeypatch):
    """cryptsetup refresh --persistent stores exactly the options given: no-read-workqueue would have been dropped."""
    from daprivacyscanner import helper
    from daprivacyscanner.privileged import FakePrivileged
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    _lvm_on_luks(r)
    dump = {"version": 2, "keyslots": [], "tokens": [], "flags": ["no-read-workqueue", "no-write-workqueue"]}
    priv = FakePrivileged()
    priv.luks_dump = lambda device: dump
    check, scan, o = _trim(cat, r, priv)
    luks = check.plan_guide(scan, o).steps[0]
    assert luks.commands[0] == ("sudo cryptsetup --allow-discards --perf-no_read_workqueue --perf-no_write_workqueue "
                                "--persistent refresh luks-1")


def test_the_helper_reads_luks2_flags():
    from daprivacyscanner.helper import parse_luks_dump
    assert parse_luks_dump("LUKS header information\nVersion:       \t2\nFlags:       \t(no flags)\n")["flags"] == []
    assert parse_luks_dump("Version: 2\nFlags:       \tallow-discards no-read-workqueue \n")["flags"] == [
        "allow-discards", "no-read-workqueue"]


@pytest.mark.parametrize("name, vg", [("vgmint-root", "vgmint"), ("my--vg-swap_1", "my-vg"), ("luks-1", "luks"),
                                      ("plain", None)])
def test_volume_group_from_its_device_mapper_name(name, vg):
    from daprivacyscanner.checks.guides.encryption import volume_group
    assert volume_group(name) == vg


# ------------------------------------------------------------------ masked units

def test_a_masked_tmp_mount_isnt_offered_enabling(cat, tmp_path):
    """The helper said "already so", the check still failed, and Easy offered it for ever."""
    from daprivacyscanner.checks import load_all
    host = make_host(tmp_path, files={"/proc/mounts": "/dev/sda2 / ext4 rw 0 0\n"},
                     commands={"systemctl is-enabled tmp.mount": "masked\n",
                               "systemctl show --property=LoadState --value tmp.mount": "masked\n"})
    check = load_all()["enc.tmp_on_disk"](cat["enc.tmp_on_disk"])
    scan = make_scan(host)
    [step] = check.plan_guide(scan, check.detect(scan)).steps
    assert not step.options and step.commands == ["sudo systemctl unmask tmp.mount"]
    host = make_host(tmp_path / "g", files={"/proc/mounts": "/dev/sda3 /tmp ext4 rw 0 0\n"},
                     commands={"systemctl is-enabled tmp.mount": "generated\n",
                               "systemctl show --property=LoadState --value tmp.mount": "loaded\n"})
    scan = make_scan(host)
    [step] = check.plan_guide(scan, check.detect(scan)).steps
    assert not step.options and "replace the line for /tmp" in step.text


def test_a_masked_fstrim_timer_isnt_offered_enabling(cat, tmp_path, monkeypatch):
    from daprivacyscanner import helper
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.host import FakeRunner, Host
    from test_trimtest import make_storage
    r = tmp_path / "root"
    (r / "home/alice").mkdir(parents=True)
    monkeypatch.setattr(helper, "ROOT", str(r))
    make_storage(r)
    home = r / "home/alice"
    host = Host(home=home, environ={"HOME": str(home)}, root=r, uid=1000,
                runner=FakeRunner({"systemctl is-enabled fstrim.timer": "masked\n",
                                   "systemctl show --property=LoadState --value fstrim.timer": "masked\n"}))
    check = load_all()["enc.trim_off"](cat["enc.trim_off"])
    scan = make_scan(host, fde="full")
    o = check.detect(scan)
    week = next(s for s in check.plan_guide(scan, o).steps if s.title == "Trim every week")
    assert not week.options and week.commands[0] == "sudo systemctl unmask fstrim.timer"


# ------------------------------------------------------------------ snapshots and backups

def test_the_snapshot_count_the_guide_allows_passes_the_check(cat, tmp_path, system, monkeypatch):
    """The input allowed up to 50, the check wanted 20 or fewer: 30 still failed. And "at most N of each" was wrong:
    hourly snapshots are capped at 5 and daily ones at 7."""
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.checks.encryption import SNAPPER_SHORT_MAX
    from test_guides import SNAPPER_ROOT, apply, options, rooted
    host = rooted(make_host(tmp_path, files={"/etc/snapper/configs/root": SNAPPER_ROOT}), system, monkeypatch)
    check = load_all()["enc.snapshots_retain_deleted"](cat["enc.snapshots_retain_deleted"])
    scan = make_scan(host)
    scan.params = {"keep": 30}                                       # over the most: the default, never a failing one
    g = check.plan_guide(scan, check.detect(scan))
    [pick] = [i for s in g.steps for i in s.inputs]
    assert pick.max == SNAPPER_SHORT_MAX
    scan.params = {"keep": SNAPPER_SHORT_MAX}
    g = check.plan_guide(scan, check.detect(scan))
    label = f"Keep at most {SNAPPER_SHORT_MAX} update snapshots, 5 hourly and 7 daily"
    apply(host, options(g)[label])
    assert check.detect(make_scan(host)).status is Status.PASS


def test_timeshift_is_judged_by_its_drive_and_the_guide_says_only_that(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.model import Evidence
    check = load_all()["enc.backups_unencrypted"](cat["enc.backups_unencrypted"])
    o = Outcome(Status.FAIL, "x", [Evidence.val("Timeshift", "rsync on unencrypted sdb1 (Timeshift doesn't encrypt)")])
    step = next(s for s in check.plan_guide(make_scan(make_host(tmp_path)), o).steps if s.title.startswith("Timeshift"))
    assert "LUKS-encrypted drive" in step.text and ", or leave your home folder" not in step.text


# ------------------------------------------------------------------ kernel options

@pytest.mark.parametrize("cmdline, status", [
    ("ro init_on_alloc=0 quiet init_on_alloc=1", Status.PASS),      # the kernel uses the last one
    ("ro init_on_alloc=1 quiet init_on_alloc=0", Status.FAIL),
    ("ro init_on_alloc=Y", Status.PASS), ("ro init_on_alloc=yes", Status.PASS), ("ro init_on_alloc=true", Status.PASS),
    ("ro init_on_alloc=on", Status.PASS), ("ro init_on_alloc=off", Status.FAIL), ("ro init_on_alloc=N", Status.FAIL),
])
def test_init_on_alloc_is_read_as_the_kernel_reads_it(cat, tmp_path, cmdline, status):
    """The first init_on_alloc= was read, and Y, yes and true counted as off."""
    host = make_host(tmp_path, files={"/proc/cmdline": cmdline + "\n"})
    assert detect(cat, "kern.init_on_alloc", make_scan(host)).status is status


def test_a_value_the_kernel_doesnt_take_leaves_its_default(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/cmdline": "ro init_on_free=maybe\n",
                                      "/proc/sys/kernel/osrelease": "7.0.0\n",
                                      "/boot/config-7.0.0": "CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n"})
    o = detect(cat, "kern.init_on_free", make_scan(host))
    assert o.status is Status.PASS and ev(o) == {"CONFIG_INIT_ON_FREE_DEFAULT_ON": "y"}


@pytest.mark.parametrize("cmdline, state", [("mem_encrypt=off mem_encrypt=on", "on"), ("mem_encrypt=on mem_encrypt=off", "off")])
def test_mem_encrypt_takes_the_last_value(tmp_path, cmdline, state):
    from daprivacyscanner.checks.kernel import memory_encryption
    host = make_host(tmp_path, files={"/proc/cmdline": cmdline + "\n", "/proc/cpuinfo": "flags\t\t: fpu sme sev\n"})
    assert memory_encryption(make_scan(host, virtualization="none")) == ("AMD SME", state)


def test_how_to_replaces_an_existing_option_rather_than_adding_a_copy(cat, tmp_path):
    """The How to… put init_on_alloc=1 in front of the line, where an init_on_alloc=0 later on it still won."""
    import subprocess
    host = make_host(tmp_path, files={"/etc/default/grub": 'GRUB_CMDLINE_LINUX_DEFAULT="quiet init_on_alloc=0 splash"\n'
                                                          'GRUB_CMDLINE_LINUX="init_on_alloc=0"\n',
                                      "/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n"})
    sed = _advice(cat, host, "kern.init_on_alloc").steps[0].commands[0]
    assert sed.startswith("sudo sed -i -E ")
    grub = tmp_path / "grub"
    grub.write_text(host.sys_path("/etc/default/grub").read_text())
    subprocess.run(sed.removeprefix("sudo ").replace("/etc/default/grub", str(grub)), shell=True, check=True)
    assert grub.read_text() == ('GRUB_CMDLINE_LINUX_DEFAULT="quiet  splash init_on_alloc=1"\nGRUB_CMDLINE_LINUX=""\n')
    host = make_host(tmp_path / "k", files={"/etc/kernel/cmdline": "root=/dev/x init_on_alloc=0 quiet\n"})
    sed = _advice(cat, host, "kern.init_on_alloc").steps[0].commands[0]
    line = tmp_path / "cmdline"
    line.write_text("root=/dev/x init_on_alloc=0 quiet\n")
    subprocess.run(sed.removeprefix("sudo ").replace("/etc/kernel/cmdline", str(line)), shell=True, check=True)
    assert line.read_text() == "root=/dev/x quiet init_on_alloc=1\n"
    host = make_host(tmp_path / "f", files={"/etc/os-release": "ID=fedora\n"}, installed=("grubby",))
    assert _advice(cat, host, "kern.init_on_alloc").steps[0].commands == [
        'sudo grubby --update-kernel=ALL --remove-args="init_on_alloc" --args="init_on_alloc=1"']


def test_hidepid_ptraceable_hides_and_the_undo_command_is_valid(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/mounts": "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=ptraceable 0 0\n"})
    assert detect(cat, "kern.proc_hidepid", make_scan(host)).status is Status.PASS
    g = _advice(cat, make_host(tmp_path / "b"), "kern.proc_hidepid")
    assert g.steps[-1].commands == ["sudo mount -o remount,hidepid=off /proc"]       # "default" is refused by mount


def test_debian_backports_over_https_and_usbguard_with_sudo(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": 'ID=debian\nVERSION_ID="12"\n',
                                      "/proc/sys/kernel/osrelease": "6.1.0-18-amd64\n",
                                      "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n"})
    cmds = [c for s in _advice(cat, host, "kern.landlock").steps for c in s.commands]
    assert any("deb https://deb.debian.org/debian bookworm-backports main" in c for c in cmds)
    assert not any("http://" in c for c in cmds)
    cmds = [c for s in _advice(cat, make_host(tmp_path / "u"), "kern.usb_trusted").steps for c in s.commands]
    assert "sudo usbguard list-devices --blocked" in cmds and "usbguard list-devices --blocked" not in cmds


# ------------------------------------------------------------------ updates

DNF5_SECURITY = """Name                   Type     Severity                                                      Package              Issued
FEDORA-2026-001de57d4f security Moderate                gdk-pixbuf2-2.44.6^really2.44.4-3.fc44.x86_64 2026-09-02 01:32:36
FEDORA-2026-00901a5e8f security Important                                ipp-usb-0.9.34-2.fc44.x86_64 2026-09-02 01:32:36
FEDORA-2026-044e56d9ff security Moderate                                     tar-2:1.35-9.fc44.x86_64 2026-09-09 04:47:08
"""


def _dnf5_host(tmp_path, runtime=True):
    calls = []

    def dnf5(argv):
        calls.append(argv)
        cache = next(a.split("=", 1)[1] for a in argv if a.startswith("--setopt=cachedir="))
        os.makedirs(cache, exist_ok=True)                 # dnf5 copies the system's metadata into it
        if "check-update" in argv:
            return CommandResult(argv, 100, "\ngdk-pixbuf2.x86_64 2.44.6-3.fc44 updates\nipp-usb.x86_64 0.9.34-2.fc44 updates\n"
                                            "tar.x86_64 2:1.35-9.fc44 updates\nmpv.x86_64 0.39-1.fc44 updates\n")
        return CommandResult(argv, 0, DNF5_SECURITY)
    import os
    env = {"XDG_RUNTIME_DIR": str(tmp_path / "run")} if runtime else {}
    (tmp_path / "run").mkdir(parents=True)
    host = make_host(tmp_path, env=env, files={"/proc/sys/kernel/osrelease": "6.17.1-300.fc44.x86_64\n"})
    host.runner.handlers["dnf5"] = dnf5
    return host, calls


def test_dnf5_counts_security_packages_not_issue_times(cat, tmp_path):
    """DNF5's updateinfo list ends each line with the issue time: two advisories issued the same second counted as one
    (244 package lines counted as 60 on the Fedora VM)."""
    host, _ = _dnf5_host(tmp_path)
    o = detect(cat, "kern.updates", make_scan(host))
    assert ev(o)["Security updates"] == 3 and ev(o)["Pending updates"] == 4


def test_dnf5_never_writes_to_the_home_folder(cat, tmp_path):
    """dnf -C as the user copied about 105 MB into ~/.cache/libdnf5 at every scan, scheduled ones too (rule 4)."""
    host, calls = _dnf5_host(tmp_path)
    detect(cat, "kern.updates", make_scan(host))
    assert calls and all(any(a.startswith(f"--setopt=cachedir={tmp_path}/run/") for a in c) and
                         any(a.startswith(f"--setopt=logdir={tmp_path}/run/") for a in c) and "-C" in c for c in calls)
    assert list((tmp_path / "run").iterdir()) == []                    # removed at once
    assert not (host.home / ".cache").exists() and not (host.home / ".local").exists()
    host, calls = _dnf5_host(tmp_path / "b", runtime=False)
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.UNKNOWN and "runtime folder" in o.summary and not calls


def test_dnf4_beside_an_installed_dnf5_keeps_its_own_cache(cat, tmp_path):
    """Before Fedora 41, dnf5 could be installed beside DNF4, whose cache it doesn't read: which one dnf is comes from
    its link, never from running it (even `dnf --version` writes dnf5's log in the home folder, seen on Fedora 44)."""
    import os
    host, calls = _dnf5_host(tmp_path)
    host.sys_path("/usr/bin").mkdir(parents=True)
    host.sys_path("/usr/bin/dnf-3").write_text("#!/usr/bin/python3\n")
    os.symlink("dnf-3", host.sys_path("/usr/bin/dnf"))
    host.runner.outputs[("dnf", "-C", "-q", "check-update")] = CommandResult((), 0, "")
    host.runner.installed.add("dnf")
    o = detect(cat, "kern.updates", make_scan(host))
    assert not calls and ("dnf", "-C", "-q", "check-update") in host.runner.calls and o.status is not Status.UNKNOWN
    assert ("dnf", "--version") not in host.runner.calls
    os.remove(host.sys_path("/usr/bin/dnf"))
    os.symlink("dnf5", host.sys_path("/usr/bin/dnf"))
    host.sys_path("/usr/bin/dnf5").write_text("")
    detect(cat, "kern.updates", make_scan(host))
    assert calls


def test_pacman_without_its_lists_couldnt_check(cat, tmp_path):
    """A fresh Omarchy has only sync/offline.db: pacman -Qu warned and exited 1, which passed as "up to date"."""
    warn = ("warning: database file for 'core' does not exist (use '-Sy' to download)\n"
            "warning: database file for 'extra' does not exist (use '-Sy' to download)\n")
    host = make_host(tmp_path, installed=["pacman"], commands={"pacman -Qu": CommandResult((), 1, "", warn)},
                     files={"/etc/pacman.conf": "[options]\nHoldPkg = pacman\n[core]\nInclude = x\n[extra]\nInclude = x\n",
                            "/var/lib/pacman/sync/offline.db": "x"})
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.UNKNOWN and "core, extra" in o.summary and "never been downloaded" in o.summary
    host = make_host(tmp_path / "b", installed=["pacman"], commands={"pacman -Qu": CommandResult((), 1, "", "")},
                     files={"/etc/pacman.conf": "[options]\n[core]\n", "/var/lib/pacman/sync/core.db": "x"})
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.PASS and ev(o)["Package lists last refreshed"] == "0 days ago"


def test_install_on_arch_refreshes_and_upgrades(tmp_path):
    from daprivacyscanner.checks.guides import install
    host = make_host(tmp_path, files={"/etc/os-release": "ID=omarchy\nID_LIKE=arch\n"})
    assert install(make_scan(host), arch="usbguard") == "sudo pacman -Syu usbguard"


def test_mints_update_manager_automation_counts(cat, tmp_path):
    host = make_host(tmp_path, commands={"apt list --upgradable": "Listing...\n",
                                         "systemctl is-enabled mintupdate-automation-upgrade.timer": "enabled\n"},
                     files={"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"})
    o = detect(cat, "kern.updates", make_scan(host))
    assert ev(o)["Automatic security updates"] == "on"
    g = _guide_with(cat, "kern.updates", host, o)
    step = next(s for s in g.steps if s.title == "Install updates automatically")
    assert step.done


@pytest.mark.parametrize("timers, conf, on", [
    ({"dnf-automatic-install.timer": "enabled"}, "", True),
    ({"dnf5-automatic.timer": "enabled"}, "[commands]\napply_updates = yes\n", True),
    ({"dnf5-automatic.timer": "enabled"}, "[commands]\napply_updates = no\n", False),           # downloads only
    ({}, "", False)])
def test_dnf_automatic_as_set_up(tmp_path, timers, conf, on):
    from daprivacyscanner.checks.kernel import dnf_automatic
    def systemctl(argv):
        return CommandResult(argv, 0, timers.get(argv[-1], "disabled") + "\n")
    host = make_host(tmp_path, files={"/etc/dnf/automatic.conf": conf} if conf else {})
    host.runner.handlers["systemctl"] = systemctl
    assert dnf_automatic(host) is on


def test_fedora_dnf5_guide_gives_dnf5_commands_only(cat, tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": "ID=fedora\n"}, installed=("dnf5",))
    o = Outcome(Status.WARN, "x", [])
    from daprivacyscanner.model import Evidence
    o.evidence = [Evidence.count("Pending updates", 2), Evidence.val("Automatic updates", "off")]
    g = _guide_with(cat, "kern.updates", host, o)
    step = next(s for s in g.steps if s.title == "Install updates automatically")
    assert step.commands[-1] == "sudo systemctl enable --now dnf5-automatic.timer"
    assert not any("dnf-automatic-install" in c for c in step.commands)


def test_nothing_to_install_and_ubuntus_own_automatic_updates_are_done(cat, tmp_path):
    from daprivacyscanner.model import Evidence
    host = make_host(tmp_path, files={"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n", "/usr/bin/unattended-upgrade": ""})
    o = Outcome(Status.FAIL, "x", [Evidence.count("Pending updates", 0), Evidence.val("Automatic security updates", "on"),
                                   Evidence.val("Firmware updates", "System Firmware")])
    g = _guide_with(cat, "kern.updates", host, o)
    first = g.steps[0]
    assert first.title == "Install the updates" and first.done and not first.commands
    auto = next(s for s in g.steps if s.title == "Install security updates automatically")
    assert auto.done and not auto.options                    # no "Apply this step" for what is there already


def test_refreshed_updates_guide_installs_flatpak_and_snap_too(cat, tmp_path):
    from daprivacyscanner.model import Evidence
    host = make_host(tmp_path, files={"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n"})
    o = Outcome(Status.WARN, "x", [Evidence.count("Pending updates", 1), Evidence.count("Pending Flatpak updates", 3),
                                   Evidence.count("Pending snap updates", 1)])
    g = _guide_with(cat, "kern.updates_refreshed", host, o)
    cmds = [c for s in g.steps for c in s.commands]
    assert "flatpak update" in cmds and "sudo snap refresh" in cmds
    assert "security updates" not in g.intro


def _guide_with(cat, check_id, host, outcome):
    from daprivacyscanner.checks import load_all
    return load_all()[check_id](cat[check_id]).plan_guide(make_scan(host), outcome)


# ------------------------------------------------------------------ ptrace and dmesg

def test_without_yama_nothing_is_offered_that_would_fail(cat, tmp_path):
    """Guide… and the Easy fix offered "Set ptrace_scope to 1", which failed in the helper (no such file)."""
    host = make_host(tmp_path, files={"/sys/kernel/security/lsm": "capability,lockdown,landlock,apparmor\n",
                                      "/proc/sys/kernel/osrelease": "6.12.0\n", "/boot/config-6.12.0": "CONFIG_SECURITY_YAMA=y\n",
                                      "/etc/kernel/cmdline": "root=/dev/x quiet\n"})
    g = _guide_with(cat, "kern.ptrace_scope", host, detect(cat, "kern.ptrace_scope", make_scan(host)))
    assert not any(s.options for s in g.steps) and "lsm=lockdown,landlock,apparmor,yama" in " ".join(g.steps[0].commands)
    host = make_host(tmp_path / "b", files={"/sys/kernel/security/lsm": "capability,apparmor\n",
                                            "/proc/sys/kernel/osrelease": "6.12.0\n", "/boot/config-6.12.0": "\n"})
    g = _guide_with(cat, "kern.ptrace_scope", host, detect(cat, "kern.ptrace_scope", make_scan(host)))
    assert not any(s.options for s in g.steps) and g.steps[0].title == "Use a kernel with the Yama security module"


def test_a_sysctl_file_read_later_sets_ptrace_back(cat, tmp_path, system, monkeypatch):
    """The app's 60-…conf is read before /etc/sysctl.conf (and 99-… files): one setting 0 there undid the fix at the
    next start, shown then as "fix undone"."""
    from test_guides import apply, options, rooted
    host = make_host(tmp_path, files={"/proc/sys/kernel/yama/ptrace_scope": "0\n",
                                      "/etc/sysctl.conf": "kernel.yama.ptrace_scope = 0\n"})
    rooted(host, system, monkeypatch)
    o = detect(cat, "kern.ptrace_scope", make_scan(host))
    g = _guide_with(cat, "kern.ptrace_scope", host, o)
    plan = options(g)["Set ptrace_scope to 1"]
    assert any("/etc/sysctl.conf sets kernel.yama.ptrace_scope = 0" in e for e in plan.side_effects)
    apply(host, plan)
    o = detect(cat, "kern.ptrace_scope", make_scan(host))
    assert o.status is Status.WARN and "at the next start" in o.summary
    [step] = _guide_with(cat, "kern.ptrace_scope", host, o).steps
    assert not step.options and step.commands[0].startswith("sudoedit /etc/sysctl.conf")


def test_dmesg_fix_says_which_later_file_undoes_it(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    host = make_host(tmp_path, files={"/proc/sys/kernel/dmesg_restrict": "1\n",
                                      "/etc/sysctl.d/60-daprivacyscanner-dmesg.conf": "kernel.dmesg_restrict = 1\n",
                                      "/etc/sysctl.d/99-local.conf": "kernel.dmesg_restrict=0\n"})
    check = load_all()["kern.dmesg_restrict"](cat["kern.dmesg_restrict"])
    scan = make_scan(host)
    o = check.detect(scan)
    assert o.status is Status.WARN
    plan = check.plan_fix(scan, o)
    assert plan.empty and "/etc/sysctl.d/99-local.conf sets kernel.dmesg_restrict = 0" in plan.side_effects[0]


def test_the_panels_say_what_the_scan_says(tmp_path):
    """The RAM disk and browser panels said "this computer can hibernate" where the scan said it can't."""
    from daprivacyscanner.tools import ramdisk as R
    host, _ = _hib_host(tmp_path, logind="no")
    assert R.hibernation_possible(host) is False
    assert not any("Hibernating" in n or "hibernate" in n for n in R.memory_notes(host, R.status(host)))
