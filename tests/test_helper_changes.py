"""The helper's change actions, run in this process against a fixture tree (helper.ROOT) with
fake systemctl, ufw and journalctl (helper.RUN). Nothing here touches the real system."""

import json
import os
import shutil
import stat
import subprocess

import pytest

from daprivacyscanner import helper

from fakes import FakeSystem


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(r))
    system = FakeSystem()
    monkeypatch.setattr(helper, "RUN", system)
    return r


def write(root, path, text):
    p = root / path.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


# ------------------------------------------------------------------ drop-ins and the journal

def test_dropin_written_journalled_and_reverted(root):
    r = call("write_dropin", name="coredump", settings={"Storage": "none", "ProcessSizeMax": "0"})
    f = root / "etc/systemd/coredump.conf.d/60-daprivacyscanner.conf"
    assert r["changed"] and f.read_text().endswith("[Coredump]\nStorage=none\nProcessSizeMax=0\n")
    journal = root / f"var/lib/daprivacyscanner/changes/{r['change_id']}.json"
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600 and stat.S_IMODE(journal.parent.stat().st_mode) == 0o700
    assert call("revert", change_id=r["change_id"])["ok"] and not f.exists() and not journal.exists()


def test_dropin_settings_are_checked_by_the_helper(root):
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="coredump", settings={"Storage": "none\nExecStart=/bin/sh"})
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="journald", settings={"ForwardToWall": "yes"})
    with pytest.raises(helper.Refused, match="unknown drop-in"):
        call("write_dropin", name="../../etc/shadow", settings={"x": "y"})
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="resolved-dot", settings={"DNS": "6.6.6.6#evil.example", "DNSOverTLS": "yes"})
    assert not (root / "etc").exists()


def test_revert_refuses_a_file_changed_since_unless_forced(root):
    r = call("write_dropin", name="journald", settings={"MaxRetentionSec": "2week"})
    f = root / "etc/systemd/journald.conf.d/60-daprivacyscanner.conf"
    f.write_text(f.read_text() + "SystemMaxUse=1G\n")
    out = call("revert", change_id=r["change_id"])
    assert not out["ok"] and out["conflict"] and f.exists()
    assert call("revert", change_id=r["change_id"], force=True)["ok"] and not f.exists()
    assert ["systemctl", "restart", "systemd-journald.service"] in helper.RUN.calls


def test_revert_puts_back_what_was_there(root):
    old = write(root, "/etc/systemd/sleep.conf.d/60-daprivacyscanner.conf", "# by hand\n[Sleep]\nAllowHibernation=yes\n")
    r = call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    assert "AllowHibernation=no" in old.read_text()
    back = call("revert", change_id=r["change_id"])
    assert old.read_text() == "# by hand\n[Sleep]\nAllowHibernation=yes\n"
    assert back["ran"][0] == "# /etc/systemd/sleep.conf.d/60-daprivacyscanner.conf put back as it was before the change " \
                             "(from the helper's journal)"


def test_unchanged_is_not_journalled(root):
    call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    assert call("write_dropin", name="sleep", settings={"AllowHibernation": "no"}) == {"changed": False}


@pytest.mark.parametrize("change_id", ["../../../etc/passwd", "x" * 32, 7, None])
def test_revert_only_takes_journal_ids(root, change_id):
    with pytest.raises(helper.Refused):
        call("revert", change_id=change_id)


def test_writes_never_follow_symlinks(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "etc/systemd").mkdir(parents=True)
    os.symlink(outside, root / "etc/systemd/sleep.conf.d")
    with pytest.raises(helper.Refused, match="symlink"):
        call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    assert list(outside.iterdir()) == []


def test_sshd_dropin_needs_include_and_a_valid_config(root):
    with pytest.raises(helper.Refused, match="doesn't read"):
        call("write_dropin", name="sshd", settings={"PasswordAuthentication": "no"})
    write(root, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
    helper.RUN.sshd_ok = False
    with pytest.raises(helper.Refused, match="rejected"):
        call("write_dropin", name="sshd", settings={"PasswordAuthentication": "no"})
    assert not (root / "etc/ssh/sshd_config.d/10-daprivacyscanner.conf").exists()
    helper.RUN.sshd_ok = True
    r = call("write_dropin", name="sshd", settings={"PasswordAuthentication": "no"})
    assert r["changed"] and ["systemctl", "try-reload-or-restart", "ssh.service"] in helper.RUN.calls


def test_apt_dropin_format(root):
    call("write_dropin", name="apt-auto", settings={"APT::Periodic::Unattended-Upgrade": "1"})
    assert (root / "etc/apt/apt.conf.d/52daprivacyscanner-auto-upgrades").read_text().endswith(
        'APT::Periodic::Unattended-Upgrade "1";\n')


# ------------------------------------------------------------------ edits in distro files

def test_countme(root):
    repo = write(root, "/etc/yum.repos.d/fedora.repo", "[fedora]\nenabled=1\ncountme=1\n\n[fedora-debuginfo]\ncountme=1\n")
    other = write(root, "/etc/yum.repos.d/rpmfusion.repo", "[rpmfusion]\nenabled=1\n")
    r = call("edit_config", target="countme")
    assert repo.read_text().count("countme=0") == 2 and r["files"] == ["/etc/yum.repos.d/fedora.repo"]
    assert other.read_text() == "[rpmfusion]\nenabled=1\n"
    call("revert", change_id=r["change_id"])
    assert repo.read_text() == "[fedora]\nenabled=1\ncountme=1\n\n[fedora-debuginfo]\ncountme=1\n"


def test_autologin_lines_are_commented_out(root):
    lightdm = write(root, "/etc/lightdm/lightdm.conf.d/70-linuxmint.conf",
                    "[Seat:*]\nuser-session=cinnamon\nautologin-user=alice\n#autologin-user-timeout=0\nautologin-guest=true\n")
    sddm = write(root, "/etc/sddm.conf.d/kde_settings.conf",
                 "[Autologin]\nRelogin=false\nUser=alice\n\n[Users]\nUser=ignored-elsewhere\n")
    gdm = write(root, "/etc/gdm3/custom.conf", "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=alice\n")
    r = call("edit_config", target="autologin")
    assert "#autologin-user=alice" in lightdm.read_text() and "user-session=cinnamon" in lightdm.read_text()
    assert "\n#autologin-guest=true" in lightdm.read_text()
    assert "#User=alice" in sddm.read_text() and "\nUser=ignored-elsewhere" in sddm.read_text()
    assert "#AutomaticLoginEnable=True" in gdm.read_text()
    assert not (root / "etc/sddm.conf.d/99-daprivacyscanner-autologin.conf").exists()     # nothing packaged set it
    call("revert", change_id=r["change_id"])
    assert "\nautologin-user=alice" in lightdm.read_text() and "\nAutomaticLoginEnable=True" in gdm.read_text()


def test_autologin_in_packaged_files_is_overridden(root):
    """A file under /usr/lib or /usr/share can't be edited: a file of the app's own, read after
    it, sets the user to none; reverting removes it."""
    write(root, "/usr/lib/sddm/sddm.conf.d/default.conf", "[Autologin]\nUser=alice\nSession=plasma\n")
    write(root, "/usr/share/lightdm/lightdm.conf.d/50-guest.conf", "[Seat:*]\nautologin-guest=true\n")
    write(root, "/usr/share/lightdm/lightdm.conf.d/40-other.conf", "[Seat:*]\ngreeter-session=slick\n[Users]\nautologin-user=no\n")
    r = call("edit_config", target="autologin")
    sddm = root / "etc/sddm.conf.d/99-daprivacyscanner-autologin.conf"
    lightdm = root / "etc/lightdm/lightdm.conf.d/99-daprivacyscanner-autologin.conf"
    assert sddm.read_text().endswith("[Autologin]\nUser=\n")
    assert lightdm.read_text().endswith("[Seat:*]\nautologin-user=\nautologin-guest=false\n")
    assert sorted(r["files"]) == [str(p) for p in ("/etc/lightdm/lightdm.conf.d/99-daprivacyscanner-autologin.conf",
                                                  "/etc/sddm.conf.d/99-daprivacyscanner-autologin.conf")]
    assert (root / "usr/lib/sddm/sddm.conf.d/default.conf").read_text() == "[Autologin]\nUser=alice\nSession=plasma\n"
    assert call("edit_config", target="autologin") == {"changed": False}
    call("revert", change_id=r["change_id"])
    assert not sddm.exists() and not lightdm.exists()
    # a packaged file whose line isn't under a seat or autologin section sets nothing
    (root / "usr/share/lightdm/lightdm.conf.d/50-guest.conf").unlink()
    (root / "usr/lib/sddm/sddm.conf.d/default.conf").unlink()
    assert call("edit_config", target="autologin") == {"changed": False}


def test_cups_directives_replaced_or_added(root):
    conf = write(root, "/etc/cups/cupsd.conf", "LogLevel warn\n<Policy default>\n  PreserveJobFiles Yes\n</Policy>\n"
                 "PreserveJobHistory Yes\n")
    r = call("edit_config", target="cups", values={"PreserveJobFiles": "No", "PreserveJobHistory": "No"})
    text = conf.read_text()
    assert "\nPreserveJobHistory No\n" in text and "  PreserveJobFiles Yes" in text and "PreserveJobFiles No" in text
    assert ["systemctl", "try-restart", "cups.service"] in helper.RUN.calls
    call("revert", change_id=r["change_id"])
    assert "PreserveJobFiles No" not in conf.read_text()


def test_cups_values_are_checked(root):
    write(root, "/etc/cups/cupsd.conf", "")
    for values in ({"PreserveJobFiles": "No\nListen 0.0.0.0:631"}, {"Listen": "*:631"}):
        with pytest.raises(helper.Refused):
            call("edit_config", target="cups", values=values)


def test_config_edits_skip_symlinked_files(root, tmp_path):
    target = tmp_path / "elsewhere.conf"
    target.write_text("[Seat:*]\nautologin-user=alice\n")
    (root / "etc/lightdm/lightdm.conf.d").mkdir(parents=True)
    os.symlink(target, root / "etc/lightdm/lightdm.conf.d/50-link.conf")
    assert call("edit_config", target="autologin") == {"changed": False}
    assert target.read_text() == "[Seat:*]\nautologin-user=alice\n"


# ------------------------------------------------------------------ services, sysctl, ufw

def test_service_off_and_back(root):
    helper.RUN.units = {"avahi-daemon.service": ["enabled", "active"]}
    r = call("set_service", unit="avahi-daemon.service", enable=False, start=False)
    assert helper.RUN.units["avahi-daemon.service"] == ["disabled", "inactive"]
    call("revert", change_id=r["change_id"])
    assert helper.RUN.units["avahi-daemon.service"] == ["enabled", "active"]


def test_service_revert_conflict(root):
    helper.RUN.units = {"ssh.service": ["enabled", "active"]}
    r = call("set_service", unit="ssh.service", enable=False, start=False)
    helper.RUN.units["ssh.service"] = ["enabled", "active"]                     # turned back on by hand
    assert call("revert", change_id=r["change_id"])["conflict"]


@pytest.mark.parametrize("unit", ["dbus.service", "sshd.service; reboot", "../ssh.service"])
def test_only_listed_services(root, unit):
    with pytest.raises(helper.Refused, match="list"):
        call("set_service", unit=unit, enable=False, start=False)


def test_missing_unit_is_refused(root):
    with pytest.raises(helper.Refused, match="isn't installed"):
        call("set_service", unit="xrdp.service", enable=False, start=False)


def test_sysctl(root):
    p = write(root, "/proc/sys/kernel/yama/ptrace_scope", "0\n")
    r = call("set_sysctl", key="kernel.yama.ptrace_scope", value="1")
    assert p.read_text() == "1"
    call("revert", change_id=r["change_id"])
    assert p.read_text() == "0"
    for key, value in (("kernel.yama.ptrace_scope", "0"), ("kernel.yama.ptrace_scope", "3"), ("kernel.modprobe", "1")):
        with pytest.raises(helper.Refused):
            call("set_sysctl", key=key, value=value)


def test_ufw_enable_with_allowed_ports_and_back(root):
    r = call("ufw_enable", allow=["22/tcp", "3389/tcp"])
    assert helper.RUN.ufw_active and helper.RUN.ufw_rules == ["22/tcp", "3389/tcp"]
    call("revert", change_id=r["change_id"])
    assert not helper.RUN.ufw_active and helper.RUN.ufw_rules == []
    with pytest.raises(helper.Refused, match="port"):
        call("ufw_enable", allow=["22/tcp from any; reboot"])


# ------------------------------------------------------------------ browser policies

def test_firefox_policy_merges_into_existing(root):
    f = write(root, "/etc/firefox/policies/policies.json", json.dumps({"policies": {"DisableAppUpdate": True}}))
    r = call("browser_policy", browser="firefox", settings={"DisableTelemetry": True, "DisableFirefoxStudies": True})
    assert json.loads(f.read_text())["policies"] == {"DisableAppUpdate": True, "DisableTelemetry": True,
                                                    "DisableFirefoxStudies": True}
    call("revert", change_id=r["change_id"])
    assert json.loads(f.read_text()) == {"policies": {"DisableAppUpdate": True}}


def test_chromium_policy_is_a_file_of_its_own(root):
    r = call("browser_policy", browser="brave", settings={"MetricsReportingEnabled": False, "BraveP3AEnabled": False})
    f = root / "etc/brave/policies/managed/daprivacyscanner.json"
    assert json.loads(f.read_text()) == {"MetricsReportingEnabled": False, "BraveP3AEnabled": False}
    call("revert", change_id=r["change_id"])
    assert not f.exists()


@pytest.mark.parametrize("settings", [{"ExtensionInstallForcelist": ["evil"]}, {"MetricsReportingEnabled": 0},
                                      {"WebRtcIPHandling": "default"}, {}])
def test_only_listed_policies(root, settings):
    with pytest.raises(helper.Refused):
        call("browser_policy", browser="chrome", settings=settings)


# ------------------------------------------------------------------ deleting

def test_clear_crash_dumps_deletes_only_dumps(root, tmp_path):
    write(root, "/var/lib/systemd/coredump/core.firefox.1000.abc.123.zst", "x")
    write(root, "/var/crash/_usr_bin_x.1000.crash", "x")
    keep = write(root, "/var/crash/README", "x")
    secret = tmp_path / "secret.crash"
    secret.write_text("keep")
    os.symlink(secret, root / "var/crash/link.crash")
    # what it ran, by pattern (the files' names say which programs crashed, and aren't listed), as the dry run showed
    assert call("clear_crash_dumps") == {"deleted": 2, "ran": helper.planned("clear_crash_dumps", {})}
    assert helper.planned("clear_crash_dumps", {}) == ["rm -f /var/lib/systemd/coredump/core.*",
                                                        "rm -f /var/crash/*.crash /var/crash/*.upload /var/crash/*.uploaded"]
    assert keep.exists() and secret.exists()
    assert call("clear_crash_dumps") == {"deleted": 0}                            # nothing deleted: nothing ran


def test_clear_syslog_only_its_files_and_never_while_it_runs(root, tmp_path):
    for name in ("syslog", "syslog.1", "syslog.2.gz", "auth.log", "messages-20261001", "kern.log.old"):
        write(root, f"/var/log/{name}", "x")
    keep = [write(root, f"/var/log/{n}", "x") for n in ("Xorg.0.log", "syslog.bak", "dpkg.log", "apt/history.log")]
    secret = tmp_path / "secret"
    secret.write_text("keep")
    os.symlink(secret, root / "var/log/kern.log")
    helper.RUN.units["rsyslog.service"] = ["enabled", "active"]
    with pytest.raises(helper.Refused, match="rsyslog.service is running"):
        call("clear_syslog")
    helper.RUN.units["rsyslog.service"] = ["disabled", "inactive"]
    assert call("clear_syslog") == {"deleted": 6, "ran": helper.planned("clear_syslog", {})}
    assert all(k.exists() for k in keep) and secret.exists()
    assert call("clear_syslog") == {"deleted": 0}


def test_vacuum_journal(root):
    assert call("vacuum_journal", time="2weeks") == {"freed": "120.0M", "ran": ["journalctl --vacuum-time=2weeks"]}
    with pytest.raises(helper.Refused):
        call("vacuum_journal", time="1s --rotate")


def test_changes_need_root_outside_tests(monkeypatch):
    monkeypatch.setattr(helper, "ROOT", "")
    if os.geteuid() != 0:
        with pytest.raises(helper.Refused, match="need root"):
            call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})


# ------------------------------------------------------------------ the thumbnail cache in memory

UNIT = "etc/systemd/system/home-alice-.cache-thumbnails.mount"
ME = (os.geteuid(), os.getegid())


@pytest.fixture
def caller(root, monkeypatch):
    """alice is the user pkexec names: her home and ~/.cache exist and are hers."""
    (root / "home/alice/.cache").mkdir(parents=True)
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))


def test_mount_tmpfs_writes_its_own_mount_unit_mounts_and_reverts(root, caller):
    r = call("mount_tmpfs", size_mb=200)
    assert r["changed"] and r["mounted"] and r["warnings"] == []
    assert r["path"] == "/home/alice/.cache/thumbnails" and r["unit"] == "/" + UNIT
    unit = (root / UNIT).read_text()
    assert unit.startswith("# Created by DA Privacy Kit")
    for line in ("ConditionPathIsDirectory=/home/alice/.cache", "ConditionPathIsSymbolicLink=!/home/alice/.cache",
                 "ConditionPathIsDirectory=/home/alice/.cache/thumbnails",
                 "ConditionPathIsSymbolicLink=!/home/alice/.cache/thumbnails",
                 "What=tmpfs", "Where=/home/alice/.cache/thumbnails", "Type=tmpfs",
                 f"Options=size=200M,mode=0700,uid={ME[0]},gid={ME[1]},noexec,nosuid,nodev",
                 "WantedBy=local-fs.target"):
        assert line in unit.splitlines(), line
    folder = root / "home/alice/.cache/thumbnails"
    assert folder.is_dir() and stat.S_IMODE(folder.stat().st_mode) == 0o700             # created for the user
    name = "home-alice-.cache-thumbnails.mount"
    assert helper.RUN.calls[-2:] == [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", name]]
    assert name in helper.RUN.mounted
    assert not (root / "etc/fstab").exists()                                          # fstab is never touched
    journal = json.loads((root / f"var/lib/daprivacyscanner/changes/{r['change_id']}.json").read_text())
    assert journal["mount_unit"] == {"name": name, "path": "/home/alice/.cache/thumbnails", "target": "thumbnails",
                                     "home": "/home/alice", "uid": ME[0], "created": True}
    with pytest.raises(helper.Refused, match="already exists"):
        call("mount_tmpfs", size_mb=200)
    rv = call("revert", change_id=r["change_id"])
    assert rv["ok"] and not (root / UNIT).exists() and name not in helper.RUN.mounted
    assert not folder.exists() and "rmdir /home/alice/.cache/thumbnails" in rv["ran"]   # the helper made it: it goes
    calls = helper.RUN.calls
    assert calls.index(["systemctl", "disable", "--now", name]) < len(calls) - 1 and calls[-1] == ["systemctl", "daemon-reload"]


def test_the_folder_is_the_callers_never_the_requests(root, caller):
    r = call("mount_tmpfs", size_mb=200, path="/home/bob/.cache/thumbnails")
    assert r["path"] == "/home/alice/.cache/thumbnails" and not (root / "home/bob").exists()


def test_a_home_reached_through_a_link_is_mounted_by_its_real_path(root, monkeypatch):
    """Fedora Atomic: /home is a link to var/home. The unit names the real path, which is what
    systemd requires (a mount point can't go through a link)."""
    (root / "var/home/alice/.cache").mkdir(parents=True)
    os.symlink("var/home", root / "home")
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    r = call("mount_tmpfs", size_mb=200)
    assert r["path"] == "/var/home/alice/.cache/thumbnails"
    assert "Where=/var/home/alice/.cache/thumbnails" in (root / "etc/systemd/system/var-home-alice-.cache-thumbnails.mount").read_text()


def test_mount_tmpfs_busy_at_revert_is_a_warning(root, caller):
    """Whether it unmounted is read from the mount table: systemd 255 answers 0 for `disable --now` even when the
    stop job failed (target is busy), and the revert said "Put back" over a folder still in memory."""
    r = call("mount_tmpfs", size_mb=100)
    helper.RUN.busy.add("home-alice-.cache-thumbnails.mount")
    write(root, "/proc/mounts", "tmpfs /home/alice/.cache/thumbnails tmpfs rw 0 0\n")       # still mounted
    rv = call("revert", change_id=r["change_id"])
    assert rv["ok"] and "stays in memory until the next restart" in rv["message"] and not (root / UNIT).exists()
    assert "Put back" not in rv["message"] and "a program still has a file" in rv["message"]


@pytest.mark.parametrize("size", [10, 5000, "200", True])
def test_mount_tmpfs_refuses_bad_sizes(root, caller, size):
    with pytest.raises(helper.Refused, match="bad size"):
        call("mount_tmpfs", size_mb=size)
    assert not (root / UNIT).exists()


def test_mount_tmpfs_refuses_a_folder_with_files_or_another_owner(root, caller, monkeypatch):
    write(root, "/home/alice/.cache/thumbnails/normal/a.png", "x")
    with pytest.raises(helper.Refused, match="still has files"):
        call("mount_tmpfs", size_mb=200)
    os.remove(root / "home/alice/.cache/thumbnails/normal/a.png")
    os.symlink("/etc/passwd", root / "home/alice/.cache/thumbnails/normal/link")    # a link is content too
    with pytest.raises(helper.Refused, match="still has files"):
        call("mount_tmpfs", size_mb=200)
    os.remove(root / "home/alice/.cache/thumbnails/normal/link")
    monkeypatch.setattr(helper, "CALLER", (ME[0] + 1, ME[1], "/home/alice"))         # the folders are ours, not theirs
    with pytest.raises(helper.Refused, match="isn't owned by the user asking"):
        call("mount_tmpfs", size_mb=200)
    assert not (root / UNIT).exists()


@pytest.mark.parametrize("link", [".cache", ".cache/thumbnails"])
def test_mount_tmpfs_refuses_a_link_on_the_way(root, caller, link):
    """A link would send the mount somewhere else: nothing is written or created."""
    (root / "elsewhere").mkdir()
    target = root / "home/alice" / link
    if target.exists():
        target.rmdir()
    target.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(root / "elsewhere", target)
    with pytest.raises(helper.Refused, match="is a link or not a folder"):
        call("mount_tmpfs", size_mb=200)
    assert not (root / UNIT).exists() and not any((root / "elsewhere").iterdir())


def test_mount_tmpfs_refuses_without_a_cache_folder_or_when_something_is_mounted(root, caller):
    (root / "home/alice/.cache").rmdir()
    with pytest.raises(helper.Refused, match="doesn't exist"):
        call("mount_tmpfs", size_mb=200)
    (root / "home/alice/.cache").mkdir()
    write(root, "/proc/mounts", "tmpfs /home/alice/.cache/thumbnails tmpfs rw 0 0\n")
    with pytest.raises(helper.Refused, match="already mounted"):
        call("mount_tmpfs", size_mb=200)


def test_mount_tmpfs_refuses_a_home_path_it_cant_write_into_a_unit(root, monkeypatch):
    (root / "home/al ice/.cache").mkdir(parents=True)
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/al ice"))
    with pytest.raises(helper.Refused, match="characters"):
        call("mount_tmpfs", size_mb=200)


def test_mount_tmpfs_needs_pkexec_to_say_who_asks(root, monkeypatch):
    monkeypatch.setattr(helper, "CALLER", None)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    with pytest.raises(helper.Refused, match="pkexec"):
        call("mount_tmpfs", size_mb=200)


@pytest.mark.skipif(not shutil.which("systemd-escape"), reason="systemd-escape isn't installed")
@pytest.mark.parametrize("path", ["/home/user/.cache/thumbnails", "/home/jo-anne/.cache/thumbnails",
                                  "/var/home/a.b/.cache/thumbnails", "/home/x@y+z/.cache/thumbnails", "/.hidden/x"])
def test_unit_names_are_systemds(path):
    want = subprocess.run(["systemd-escape", "--path", "--suffix=mount", path], capture_output=True, text=True).stdout.strip()
    assert helper.unit_name(path) == want


def test_user_umask_dropin_is_for_the_caller_only(root, monkeypatch):
    """The unit is the calling user's own service manager: the uid comes from pkexec, never the
    request, and only the umasks on the list are written."""
    monkeypatch.setattr(helper, "CALLER", (1234, 1234, "/home/alice"))
    os.makedirs(root / "home/alice", exist_ok=True)
    r = call("write_dropin", name="user-umask", settings={"UMask": "0027"})
    path = root / "etc/systemd/system/user@1234.service.d/60-daprivacyscanner-umask.conf"
    assert path.read_text().endswith("[Service]\nUMask=0027\n")
    assert ["systemctl", "daemon-reload"] in helper.RUN.calls
    with pytest.raises(helper.Refused):
        call("write_dropin", name="user-umask", settings={"UMask": "0000"})
    call("revert", change_id=r["change_id"])
    assert not path.exists()


def test_geoclue_dropin_only_where_geoclue_reads_it(root):
    with pytest.raises(helper.Refused, match="doesn't read /etc/geoclue/conf.d"):
        call("write_dropin", name="geoclue", settings={"enable": "false"})
    (root / "etc/geoclue/conf.d").mkdir(parents=True)
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="geoclue", settings={"enable": "true"})
    r = call("write_dropin", name="geoclue", settings={"enable": "false"})
    f = root / "etc/geoclue/conf.d/90-daprivacyscanner.conf"
    assert f.read_text().endswith("[wifi]\nenable=false\n")
    assert call("revert", change_id=r["change_id"])["ok"] and not f.exists()


def test_geoclue_edit_touches_the_wifi_section_only(root):
    conf = "[agent]\nwhitelist=gnome-shell\n\n[3g]\nenable=true\n\n[wifi]\n# comment\nenable=true\nurl=https://x/\n"
    f = write(root, "/etc/geoclue/geoclue.conf", conf)
    r = call("edit_config", target="geoclue")
    assert f.read_text() == conf.replace("[wifi]\n# comment\nenable=true", "[wifi]\n# comment\nenable=false")
    assert call("revert", change_id=r["change_id"])["ok"] and f.read_text() == conf


def test_plasma_login_s_autologin_is_turned_off(root):
    """Plasma Login Manager (KDE's fork of SDDM): its /etc files' User= lines commented out, a packaged one overridden."""
    write(root, "/etc/plasmalogin.conf", "[Autologin]\nSession=plasma\nUser=alice\n")
    write(root, "/usr/lib/plasmalogin/plasmalogin.conf.d/10-vendor.conf", "[Autologin]\nUser=alice\n")
    # the dry run names the override, the folder it makes, and every line, before anything is written
    assert helper.planned("edit_config", {"target": "autologin"}) == ["mkdir /etc/plasmalogin.conf.d"]
    planned = {path: new for path, old, new in helper.planned_files("edit_config", {"target": "autologin"})}
    assert planned["/etc/plasmalogin.conf.d/99-daprivacyscanner-autologin.conf"].endswith("[Autologin]\nUser=\n")
    assert "#User=alice" in planned["/etc/plasmalogin.conf"]
    r = call("edit_config", target="autologin")
    assert (root / "etc/plasmalogin.conf").read_text() == "[Autologin]\nSession=plasma\n#User=alice\n"
    override = root / "etc/plasmalogin.conf.d/99-daprivacyscanner-autologin.conf"
    assert override.read_text().endswith("[Autologin]\nUser=\n") and r["ran"] == ["mkdir /etc/plasmalogin.conf.d"]
    call("revert", change_id=r["change_id"])
    assert (root / "etc/plasmalogin.conf").read_text().endswith("User=alice\n") and not override.exists()
    assert not (root / "etc/plasmalogin.conf.d").exists()                         # the folder it made goes too


# ------------------------------------------------------------------ what a change ran, in History

class InProcess:
    """The helper as the app talks to it, run here through handle()."""
    def call(self, action, args, timeout=None):
        return call(action, **args)


def test_history_shows_what_a_root_change_ran_and_wrote_and_what_reverting_ran(root, tmp_path):
    from conftest import make_host
    from daprivacyscanner.fix import FixPlan, RootChange, apply_plan, revert_entry
    from daprivacyscanner.undo import UndoLog
    host = make_host(tmp_path / "h")
    host.privileged = InProcess()
    log = UndoLog(tmp_path / "state")
    (root / "etc/systemd").mkdir(parents=True)                 # as on every system: only resolved.conf.d is new
    step = RootChange("write_dropin", {"name": "resolved-dot", "settings": {"DNSOverTLS": "yes"}}, "Write the drop-in")
    planned = step.commands()
    assert planned == ["mkdir /etc/systemd/resolved.conf.d",                       # known before root access
                       "systemctl try-restart systemd-resolved.service"]
    assert FixPlan("net.x", "t", [step]).to_dict()["steps"][0]["commands"] == planned
    res = apply_plan(FixPlan("net.x", "t", [step]), host, log)
    assert res.ok
    shown = UndoLog.summary(log.get(res.entry_id))["steps"][0]
    assert shown["as_root"] and shown["commands"] == planned                         # what ran is what was planned
    assert shown["files"] == ["/etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf"]
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok
    shown = UndoLog.summary(log.get(res.entry_id))["steps"][0]
    assert shown["reverted"] and shown["revert_ran"] == ["rm /etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf",
                                                         "rmdir /etc/systemd/resolved.conf.d",
                                                         "systemctl try-restart systemd-resolved.service"]
    assert shown["undo"] == ""                                                       # nothing left to undo


def test_planned_commands_match_what_each_change_runs(root, caller):
    for request, args in (("set_sysctl", {"key": "kernel.dmesg_restrict", "value": "1"}),
                          ("vacuum_journal", {"time": "2weeks"})):
        if request == "set_sysctl":
            write(root, "/proc/sys/kernel/dmesg_restrict", "0\n")
        assert call(request, **args)["ran"] == helper.planned(request, args, "/home/alice")
    (root / "etc/systemd/system").mkdir(parents=True)
    (root / "home/alice/.cache/thumbnails").mkdir()
    planned = helper.planned("mount_tmpfs", {"size_mb": 200}, "/home/alice")       # before, as the dry run is
    assert call("mount_tmpfs", size_mb=200)["ran"] == planned
    assert helper.planned("no_such", {}) == [] and helper.planned("write_dropin", {}) == []


def test_the_dry_run_shows_the_lines_a_root_change_writes(root):
    from daprivacyscanner.fix import RootChange
    write(root, "/etc/cups/cupsd.conf", "LogLevel warn\nPreserveJobFiles Yes\n")
    step = RootChange("edit_config", {"target": "cups", "values": {"PreserveJobFiles": "No", "PreserveJobHistory": "No"}},
                      "Set them in cupsd.conf")
    lines = step.preview()
    assert "- PreserveJobFiles Yes" in lines and "+ PreserveJobFiles No" in lines
    assert (root / "etc/cups/cupsd.conf").read_text() == "LogLevel warn\nPreserveJobFiles Yes\n"     # nothing written
    drop = RootChange("write_dropin", {"name": "sysctl-dmesg", "settings": {"kernel.dmesg_restrict": "1"}}, "x").preview()
    assert drop[-1] == "+ kernel.dmesg_restrict = 1"
    assert RootChange("write_dropin", {"name": "sysctl-dmesg", "settings": {"kernel.dmesg_restrict": "0; rm"}}, "x").preview() == []


def test_the_dry_run_shows_the_mount_unit_the_helper_writes(root, caller):
    import pwd
    if pwd.getpwuid(ME[0]).pw_gid != ME[1]:
        pytest.skip("this account's group differs from its primary one")
    [(path, old, text)] = helper.planned_files("mount_tmpfs", {"size_mb": 200}, uid=ME[0], home="/home/alice")
    assert path == "/" + UNIT and old is None
    call("mount_tmpfs", size_mb=200)
    assert (root / UNIT).read_text() == text


# ------------------------------------------------------------------ reverting removes the folders a change made

def test_a_revert_removes_the_folders_the_change_made_and_nothing_else(root):
    write(root, "/etc/systemd/journald.conf", "")                                # /etc/systemd is there already
    r = call("write_dropin", name="resolved-dot", settings={"DNSOverTLS": "yes"})
    d = root / "etc/systemd/resolved.conf.d"
    assert helper._load_change(r["change_id"])["dirs"] == ["/etc/systemd/resolved.conf.d"]
    rv = call("revert", change_id=r["change_id"])
    assert rv["ok"] and not d.exists() and (root / "etc/systemd").is_dir() and rv["warnings"] == []
    assert not (root / "var/lib/daprivacyscanner").exists()                       # the journal's own folders go when empty


def test_a_folder_that_holds_what_was_added_since_stays_and_the_revert_says_why(root):
    write(root, "/etc/systemd/journald.conf", "")
    r = call("write_dropin", name="resolved-dot", settings={"DNSOverTLS": "yes"})
    other = write(root, "/etc/systemd/resolved.conf.d/50-vpn.conf", "[Resolve]\nDNS=10.0.0.1\n")   # added since
    rv = call("revert", change_id=r["change_id"])
    assert rv["ok"] and other.read_text() == "[Resolve]\nDNS=10.0.0.1\n"
    assert not (root / "etc/systemd/resolved.conf.d/60-daprivacyscanner-dot.conf").exists()
    assert "/etc/systemd/resolved.conf.d was left" in rv["message"] and "50-vpn.conf" in rv["message"]
    assert not any(c.startswith("rmdir") for c in rv.get("ran", []))


def test_a_folder_that_was_there_before_is_never_removed(root):
    write(root, "/etc/systemd/resolved.conf.d/README", "")
    (root / "etc/systemd/resolved.conf.d/README").unlink()                        # there, and empty
    r = call("write_dropin", name="resolved-dot", settings={"DNSOverTLS": "yes"})
    assert "dirs" not in helper._load_change(r["change_id"])
    call("revert", change_id=r["change_id"])
    assert (root / "etc/systemd/resolved.conf.d").is_dir()


def test_a_folder_that_became_a_link_is_left_alone(root, tmp_path):
    write(root, "/etc/systemd/journald.conf", "")
    r = call("write_dropin", name="resolved-dot", settings={"DNSOverTLS": "yes"})
    d = root / "etc/systemd/resolved.conf.d"
    (d / "60-daprivacyscanner-dot.conf").unlink()
    d.rmdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    d.symlink_to(elsewhere)
    with pytest.raises(helper.Refused, match="symlink"):                         # nothing is written through it
        call("revert", change_id=r["change_id"], force=True)
    assert d.is_symlink() and elsewhere.is_dir()
    assert helper._remove_dirs(["/etc/systemd/resolved.conf.d"]) == [
        "/etc/systemd/resolved.conf.d was left as it is: it isn't the folder this change made any more"]
    assert d.is_symlink() and elsewhere.is_dir()


def test_the_wants_folder_enabling_a_unit_made_goes_when_it_is_put_back(root, monkeypatch):
    """systemctl enable makes /etc/systemd/system/<target>.wants when it isn't there; disable leaves it."""
    system = FakeSystem(units={"fstrim.timer": ["disabled", "inactive"]})
    wants = root / "etc/systemd/system/timers.target.wants"
    (root / "etc/systemd/system").mkdir(parents=True)

    def run(argv):
        if argv[:2] == ["systemctl", "enable"]:
            wants.mkdir(exist_ok=True)
            (wants / argv[-1]).symlink_to("/usr/lib/systemd/system/" + argv[-1])
        elif argv[:2] == ["systemctl", "disable"]:
            (wants / argv[-1]).unlink(missing_ok=True)
        return system(argv)
    monkeypatch.setattr(helper, "RUN", run)
    r = call("set_service", unit="fstrim.timer", enable=True, start=True)
    assert r["dirs"] == ["/etc/systemd/system/timers.target.wants"]
    rv = call("revert", change_id=r["change_id"])
    assert rv["ok"] and not wants.exists() and "rmdir /etc/systemd/system/timers.target.wants" in rv["ran"]
    # a timer enabled there since keeps the folder, and the revert says so
    r = call("set_service", unit="fstrim.timer", enable=True, start=True)
    (wants / "other.timer").symlink_to("/usr/lib/systemd/system/other.timer")
    rv = call("revert", change_id=r["change_id"])
    assert rv["ok"] and (wants / "other.timer").is_symlink() and not (wants / "fstrim.timer").exists()
    assert "timers.target.wants was left" in rv["message"] and "other.timer" in rv["message"]
