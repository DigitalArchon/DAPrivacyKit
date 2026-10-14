"""Fixes that last: defaults for every network, rules that expire files, folders kept in memory,
/tmp in memory, login records kept private, suspend-then-hibernate, zram without writeback, what
deleting does on this disk, and the export of everything the app keeps. Root changes run the
real helper code in this process, against the fixture tree (helper.ROOT, helper.RUN)."""

import json
import os
import stat
import time

import pytest

from daprivacyscanner import helper, report
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.encryption import deleted_data_note
from daprivacyscanner.checks.guides.desktop import set_gtk_setting
from daprivacyscanner.fix import ACTION_KINDS, UserUnitSet, apply_plan
from daprivacyscanner.guide import Input
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status
from daprivacyscanner.undo import UndoLog

from conftest import detect, ev, lsblk, make_host, make_scan
from fakes import FakeGSettings, FakeKwriteconfig, FakeNmcli, FakeSystem, FakeUserSystemctl, recorder
from test_guides import apply, build, home_on_the_system, options, revert, rooted

FEDORA = lsblk("fedora-40-btrfs-luks.json")
MINT = lsblk("mint-22-ext4-plain.json")
ME = (os.geteuid(), os.getegid())
SWAPS = "Filename\tType\tSize\tUsed\tPriority\n"


@pytest.fixture
def system(monkeypatch):
    s = FakeSystem()
    monkeypatch.setattr(helper, "RUN", s)
    return s


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


@pytest.fixture
def root(tmp_path, monkeypatch, system):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(r))
    return r


# ------------------------------------------------------------------ the helper: new drop-ins and edits

def test_networkmanager_mac_dropin_has_both_sections_and_reverts(root, system):
    r = call("write_dropin", name="nm-mac", settings={"connection:wifi.cloned-mac-address": "stable",
                                                       "device:wifi.scan-rand-mac-address": "yes"})
    f = root / "etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf"
    assert f.read_text().endswith("[connection]\nwifi.cloned-mac-address=stable\n[device]\nwifi.scan-rand-mac-address=yes\n")
    assert ["systemctl", "try-reload-or-restart", "NetworkManager.service"] in system.calls
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="nm-mac", settings={"connection:wifi.cloned-mac-address": "permanent"})
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="nm-mac", settings={"main:plugins": "keyfile"})
    assert call("revert", change_id=r["change_id"])["ok"] and not f.exists()


def test_zram_config_only_with_the_generator_never_over_someone_elses(root, system):
    with pytest.raises(helper.Refused, match="isn't installed"):
        call("write_dropin", name="zram", settings={"zram-size": "min(ram / 2, 8192)"})
    gen = root / "usr/lib/systemd/system-generators/zram-generator"
    gen.parent.mkdir(parents=True)
    gen.write_text("")
    conf = root / "etc/systemd/zram-generator.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("[zram0]\nwriteback-device=/dev/sda4\n")
    with pytest.raises(helper.Refused, match="someone else's"):
        call("write_dropin", name="zram", settings={"zram-size": "min(ram / 2, 8192)"})
    conf.unlink()
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="zram", settings={"writeback-device": "/dev/sda4"})
    r = call("write_dropin", name="zram", settings={"zram-size": "min(ram / 2, 8192)"})
    assert conf.read_text().endswith("[zram0]\nzram-size=min(ram / 2, 8192)\n") and "writeback" not in conf.read_text()
    assert system.calls[-1] == ["systemctl", "start", "dev-zram0.swap"]
    system.calls.clear()
    assert call("revert", change_id=r["change_id"])["ok"] and not conf.exists()
    assert system.calls == [["systemctl", "daemon-reload"]]           # zram stays on until the next boot


def test_login_records_rule_and_logrotate(root, system):
    rot = root / "etc/logrotate.d/wtmp"
    rot.parent.mkdir(parents=True)
    rot.write_text("/var/log/wtmp {\n    missingok\n    monthly\n    create 0664 root utmp\n    rotate 1\n}\n")
    r1 = call("write_dropin", name="tmpfiles-wtmp", settings={"/var/log/wtmp": "0660", "/var/log/lastlog": "0660"})
    f = root / "etc/tmpfiles.d/00-daprivacyscanner-wtmp.conf"
    assert f.read_text().endswith("f /var/log/wtmp 0660 root utmp -\nf /var/log/lastlog 0660 root utmp -\n")
    assert system.calls[-1] == ["systemd-tmpfiles", "--create", "--prefix=/var/log/wtmp", "--prefix=/var/log/lastlog"]
    r2 = call("edit_config", target="logrotate-wtmp")
    assert "    create 0660 root utmp\n" in rot.read_text() and "missingok" in rot.read_text()
    with pytest.raises(helper.Refused, match="isn't allowed"):
        call("write_dropin", name="tmpfiles-wtmp", settings={"/etc/shadow": "0666"})
    call("revert", change_id=r2["change_id"])
    call("revert", change_id=r1["change_id"])
    assert "create 0664 root utmp" in rot.read_text() and not f.exists()
    assert system.calls[-1][0] == "systemd-tmpfiles"                  # the distribution's mode, at once


def test_suspend_then_hibernate_dropins(root, system):
    call("write_dropin", name="sleep-delay", settings={"HibernateDelaySec": "1h"})
    call("write_dropin", name="logind-sleep", settings={"HandleLidSwitch": "suspend-then-hibernate"})
    assert (root / "etc/systemd/logind.conf.d/60-daprivacyscanner.conf").read_text().endswith(
        "[Login]\nHandleLidSwitch=suspend-then-hibernate\n")
    assert system.calls[-1] == ["systemctl", "kill", "-s", "HUP", "systemd-logind.service"]
    with pytest.raises(helper.Refused):
        call("write_dropin", name="sleep-delay", settings={"HibernateDelaySec": "0"})


def test_chromium_clear_on_exit_policies(root):
    call("browser_policy", browser="chrome", settings={"DefaultCookiesSetting": 4})
    call("browser_policy", browser="chrome", settings={"SyncDisabled": True,
                                                         "ClearBrowsingDataOnExitList": helper.CLEAR_ON_EXIT})
    data = json.loads((root / "etc/opt/chrome/policies/managed/daprivacyscanner.json").read_text())
    assert data == {"DefaultCookiesSetting": 4, "SyncDisabled": True, "ClearBrowsingDataOnExitList": helper.CLEAR_ON_EXIT}
    for bad in ({"DefaultCookiesSetting": 1}, {"DefaultCookiesSetting": True},
                {"ClearBrowsingDataOnExitList": ["passwords"]}):
        with pytest.raises(helper.Refused, match="aren't allowed"):
            call("browser_policy", browser="chrome", settings=bad)


def test_tmp_mount_linked_from_the_distribution_and_unlinked(root, system):
    with pytest.raises(helper.Refused, match="doesn't ship"):
        call("enable_tmp_mount")
    shipped = root / "usr/share/systemd/tmp.mount"
    shipped.parent.mkdir(parents=True)
    shipped.write_text("[Mount]\nWhere=/tmp\n")
    r = call("enable_tmp_mount")
    assert ["systemctl", "enable", "/usr/share/systemd/tmp.mount"] in system.calls
    assert system.units["tmp.mount"] == ["enabled", "inactive"]           # from the next boot, not started now
    with pytest.raises(helper.Refused, match="installed already"):
        call("enable_tmp_mount")
    assert call("revert", change_id=r["change_id"])["ok"] and "tmp.mount" not in system.units


def test_tmp_mount_changed_since_is_a_conflict(root, system):
    shipped = root / "usr/share/systemd/tmp.mount"
    shipped.parent.mkdir(parents=True)
    shipped.write_text("[Mount]\n")
    r = call("enable_tmp_mount")
    system.units["tmp.mount"][0] = "masked"
    assert call("revert", change_id=r["change_id"])["conflict"]


# ------------------------------------------------------------------ the helper: folders in memory

@pytest.fixture
def alice(root, monkeypatch):
    (root / "home/alice/.cache").mkdir(parents=True)
    (root / "home/alice/.local/share").mkdir(parents=True)
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    return root / "home/alice"


def test_ephemeral_until_reboot_executable_folder_read_only_underneath(root, system, alice):
    r = call("mount_tmpfs", target="ephemeral", size_mb=500, noexec=False)
    name = "home-alice-Ephemeral.mount"
    unit = (root / "etc/systemd/system" / name).read_text()
    for line in ("Where=/home/alice/Ephemeral", f"Options=size=500M,mode=0700,uid={ME[0]},gid={ME[1]},nosuid,nodev",
                 "LazyUnmount=yes", "WantedBy=local-fs.target", "ConditionPathIsSymbolicLink=!/home/alice/Ephemeral"):
        assert line in unit.splitlines(), line
    assert "noexec" not in unit and "BindsTo" not in unit and "empty at every boot" in unit
    folder = alice / "Ephemeral"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o500                  # nothing saved there if unmounted
    assert name in system.mounted
    assert call("revert", change_id=r["change_id"])["ok"]
    assert not folder.exists() and name not in system.mounted            # it made the folder: it goes


def test_ephemeral_until_logout_is_bound_to_the_users_session_manager(root, system, alice):
    (alice / "Ephemeral").mkdir(mode=0o755)
    r = call("mount_tmpfs", target="ephemeral", size_mb=1000, until="logout")
    unit = (root / "etc/systemd/system/home-alice-Ephemeral.mount").read_text().splitlines()
    manager = f"user@{ME[0]}.service"
    for line in ("DefaultDependencies=no", f"BindsTo={manager}", f"After=local-fs.target {manager}",
                 f"WantedBy={manager}", "Conflicts=umount.target"):
        assert line in unit, line
    assert any(ln.startswith("Options=") and ",noexec," in ln for ln in unit)
    call("revert", change_id=r["change_id"])
    assert stat.S_IMODE((alice / "Ephemeral").stat().st_mode) == 0o755        # its own mode back


def test_ephemeral_revert_refuses_while_it_holds_files(root, system, alice):
    r = call("mount_tmpfs", target="ephemeral", size_mb=500)
    folder = alice / "Ephemeral"
    folder.chmod(0o700)                                   # as the mounted tmpfs is
    (folder / "draft.odt").write_text("x")
    (root / "proc").mkdir()
    (root / "proc/mounts").write_text("tmpfs /home/alice/Ephemeral tmpfs rw 0 0\n")
    rv = call("revert", change_id=r["change_id"])
    assert rv["conflict"] and "still has files" in rv["message"]
    assert call("revert", change_id=r["change_id"], force=True)["ok"]


@pytest.mark.parametrize("args, match", [
    ({"target": "ephemeral", "size_mb": 40}, "bad size"),
    ({"target": "ephemeral", "size_mb": 70000}, "bad size"),
    ({"target": "ephemeral", "size_mb": 500, "until": "never"}, "bad request"),
    ({"target": "thumbnails", "size_mb": 200, "noexec": False}, "bad request"),
    ({"target": "thumbnails", "size_mb": 200, "until": "logout"}, "bad request"),
    ({"target": "../../etc", "size_mb": 200}, "can't be kept in memory"),
])
def test_mount_tmpfs_arguments(root, alice, args, match):
    with pytest.raises(helper.Refused, match=match):
        call("mount_tmpfs", **args)


def test_ephemeral_size_at_most_half_the_memory(root, alice):
    (root / "proc").mkdir()
    (root / "proc/meminfo").write_text("MemTotal:        2048000 kB\n")
    with pytest.raises(helper.Refused, match="half of the memory"):
        call("mount_tmpfs", target="ephemeral", size_mb=1500)
    assert call("mount_tmpfs", target="ephemeral", size_mb=900)["changed"]


def test_gvfs_metadata_in_memory(root, system, alice):
    r = call("mount_tmpfs", target="gvfs-metadata", size_mb=50)
    assert r["path"] == "/home/alice/.local/share/gvfs-metadata"
    unit = (root / "etc/systemd/system/home-alice-.local-share-gvfs\\x2dmetadata.mount").read_text()
    assert "ConditionPathIsSymbolicLink=!/home/alice/.local/share" in unit and "noexec" in unit
    assert stat.S_IMODE((alice / ".local/share/gvfs-metadata").stat().st_mode) == 0o700   # not made read-only
    rv = call("revert", change_id=r["change_id"])
    assert not (alice / ".local/share/gvfs-metadata").exists() and (alice / ".local/share").is_dir()   # it made it
    # one that was there before stays, and one that holds what was saved there since stays and says so
    (alice / ".local/share/gvfs-metadata").mkdir()
    r = call("mount_tmpfs", target="gvfs-metadata", size_mb=50)
    call("revert", change_id=r["change_id"])
    assert (alice / ".local/share/gvfs-metadata").is_dir()
    (alice / ".local/share/gvfs-metadata").rmdir()
    r = call("mount_tmpfs", target="gvfs-metadata", size_mb=50)
    (alice / ".local/share/gvfs-metadata/home").write_text("x")                       # saved there, unmounted
    rv = call("revert", change_id=r["change_id"])
    assert (alice / ".local/share/gvfs-metadata/home").read_text() == "x" and "now holds" in rv["message"]


# ------------------------------------------------------------------ MAC addresses for every network

# NetworkManager's own file exempting drivers that can't change their address (Mint 22's copy)
NO_MAC_CHANGE = ("# https://bugzilla.gnome.org/show_bug.cgi?id=777523\n[device-31-mac-addr-change]\n"
                 "match-device=driver:eagle_sdio,driver:wl\nwifi.scan-rand-mac-address=no\n")


def nm_world(tmp_path, monkeypatch, system, saved, files=None):
    """NetworkManager whose merged config is read as the real one reads its files (man
    NetworkManager.conf): /usr/lib/NetworkManager/conf.d, then NetworkManager.conf, then
    /etc/NetworkManager/conf.d, each by name; a later file's value replaces an earlier one's in
    the generic [device] and [connection] sections, and every other section is kept under its
    own name, as `NetworkManager --print-config` shows them."""
    host = make_host(tmp_path, files={"/etc/NetworkManager/NetworkManager.conf": "[device]\nwifi.scan-rand-mac-address=no\n",
                                      **(files or {})})
    nm = FakeNmcli(saved)
    host.runner.handlers["nmcli"] = nm
    rooted(host, system, monkeypatch)

    def print_config(argv):
        from daprivacyscanner import ini
        order = [*sorted((host.root / "usr/lib/NetworkManager/conf.d").glob("*.conf")),
                 host.root / "etc/NetworkManager/NetworkManager.conf",
                 *sorted((host.root / "etc/NetworkManager/conf.d").glob("*.conf"))]
        merged = ini.merge(*(ini.parse(p.read_text()) for p in order if p.exists()))
        text = "".join(f"[{g[0]}]\n" + "".join(f"{k}={v}\n" for k, v in keys.items()) for g, keys in merged.items() if g)
        return CommandResult(tuple(argv), 0, text)
    host.runner.handlers["NetworkManager"] = print_config
    return host, nm


def test_mac_check_counts_networks_joined_later(cat, tmp_path):
    nm = FakeNmcli({"u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": "stable"}})
    host = make_host(tmp_path)
    host.runner.handlers["nmcli"] = nm
    o = detect(cat, "net.mac_permanent", make_scan(host))
    assert o.status is Status.FAIL and o.summary.startswith("Networks joined from now on")


def test_mac_guide_sets_the_default_for_every_network(cat, tmp_path, monkeypatch, system):
    host, nm = nm_world(tmp_path, monkeypatch, system, {
        "u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": ""},
        "u2": {"type": "802-11-wireless", "connection.id": "Office", "802-11-wireless.cloned-mac-address": "permanent"}})
    o = detect(cat, "net.mac_permanent", make_scan(host))
    assert o.status is Status.FAIL and "joined from now on will too" in o.summary and "scanning" in o.summary
    g = build(cat, host, "net.mac_permanent")
    plan = options(g)["A random address for each network, kept for it (stable)"]
    assert [a.kind for a in plan.actions] == ["root", "nmcli"] and plan.actions[1].name == "Office"
    log, res = apply(host, plan)
    assert nm.connections["u2"]["802-11-wireless.cloned-mac-address"] == "stable"
    assert nm.connections["u1"]["802-11-wireless.cloned-mac-address"] == ""        # follows the default
    assert detect(cat, "net.mac_permanent", make_scan(host)).status is Status.PASS
    revert(host, log, res)
    assert nm.connections["u2"]["802-11-wireless.cloned-mac-address"] == "permanent"
    assert not (host.root / "etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf").exists()


def test_mac_dropin_keeps_the_distributions_driver_exceptions(cat, tmp_path, monkeypatch, system):
    """A later file wins over every section of earlier ones, so the app's file must exempt the
    drivers NetworkManager's own file exempts (they can't change their address: with the app's
    defaults they would fail to scan or connect), and any this machine's files add."""
    host, _ = nm_world(tmp_path, monkeypatch, system,
                       {"u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": ""}},
                       files={"/usr/lib/NetworkManager/conf.d/no-mac-addr-change.conf": NO_MAC_CHANGE,
                              "/etc/NetworkManager/conf.d/10-site.conf":
                                  "[device-site]\nmatch-device=interface-name:wlp3s0\nwifi.scan-rand-mac-address=no\n"})
    g = build(cat, host, "net.mac_permanent")
    plan = options(g)["A random address for each network, kept for it (stable)"]
    assert any("left out and keep the hardware one" in s for s in plan.side_effects)
    assert any("revert this from History" in s for s in plan.side_effects)
    log, res = apply(host, plan)
    text = (host.root / "etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf").read_text()
    exempt = text.index("[device-daprivacyscanner-1]")
    assert exempt < text.index("[connection]\nwifi.cloned-mac-address=stable") < text.index("[device]\nwifi.scan-rand-mac-address=yes")
    assert ("[device-daprivacyscanner-1]\nmatch-device=driver:eagle_sdio,driver:wl\nwifi.scan-rand-mac-address=no\n\n"
            "[connection-daprivacyscanner-1]\nmatch-device=driver:eagle_sdio,driver:wl\nwifi.cloned-mac-address=preserve\n") in text
    assert "[device-daprivacyscanner-2]\nmatch-device=interface-name:wlp3s0\n" in text   # this machine's own exception
    assert text.count("match-device=driver:eagle_sdio,driver:wl") == 2                  # not repeated for the same file
    assert detect(cat, "net.mac_permanent", make_scan(host)).status is Status.PASS       # the generic sections still win
    revert(host, log, res)


def test_mac_dropin_exempts_upstreams_drivers_even_without_the_file(root, system):
    """Upstream's list is the floor, whatever this machine ships; a generic [device] section
    turning scan randomisation off (Ubuntu's NetworkManager.conf) is not an exception."""
    (root / "etc/NetworkManager").mkdir(parents=True)
    (root / "etc/NetworkManager/NetworkManager.conf").write_text("[device]\nwifi.scan-rand-mac-address=no\n")
    call("write_dropin", name="nm-mac", settings={"connection:wifi.cloned-mac-address": "random",
                                                   "device:wifi.scan-rand-mac-address": "yes"})
    text = (root / "etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf").read_text()
    assert text.count("match-device=") == 2 and "match-device=driver:eagle_sdio,driver:wl" in text
    assert text.endswith("[connection]\nwifi.cloned-mac-address=random\n[device]\nwifi.scan-rand-mac-address=yes\n")
    (root / "usr/lib/NetworkManager/conf.d").mkdir(parents=True)
    (root / "usr/lib/NetworkManager/conf.d/odd.conf").write_text("[device-odd]\nmatch-device=driver:x\n]bad\nwifi.scan-rand-mac-address=no\n"
                                                                 "[device-bad]\nmatch-device=driver:x\n[Service]\nExecStart=/bin/sh\n"
                                                                 "wifi.scan-rand-mac-address=no\n")
    call("write_dropin", name="nm-mac", settings={"connection:wifi.cloned-mac-address": "stable",
                                                   "device:wifi.scan-rand-mac-address": "yes"})
    text = (root / "etc/NetworkManager/conf.d/99-daprivacyscanner-mac.conf").read_text()
    assert "match-device=driver:x\nwifi.scan-rand-mac-address=no" in text and "ExecStart" not in text


def test_mac_guide_offers_wired_networks_separately(cat, tmp_path, monkeypatch, system):
    host, _ = nm_world(tmp_path, monkeypatch, system, {
        "u1": {"type": "802-11-wireless", "connection.id": "Home", "802-11-wireless.cloned-mac-address": "random"}})
    g = build(cat, host, "net.mac_permanent")
    wired = g.steps[1]
    assert wired.title == "Optional: wired networks" and not any(o.recommended for o in wired.options)
    plan = wired.options[0].plan
    log, res = apply(host, plan)
    assert (host.root / "etc/NetworkManager/conf.d/99-daprivacyscanner-mac-ethernet.conf").read_text().endswith(
        "[connection]\nethernet.cloned-mac-address=stable\n")


# ------------------------------------------------------------------ recent files, GTK settings

def test_set_gtk_setting_changes_only_its_key():
    assert set_gtk_setting(None, "gtk-recent-files-enabled", "false") == "[Settings]\ngtk-recent-files-enabled=false\n"
    text = "[Settings]\ngtk-theme-name=Mint-Y\ngtk-recent-files-enabled=true\n[Other]\nx=1\n"
    assert set_gtk_setting(text, "gtk-recent-files-enabled", "false") == \
        "[Settings]\ngtk-theme-name=Mint-Y\ngtk-recent-files-enabled=false\n[Other]\nx=1\n"
    assert set_gtk_setting("[Settings]\na=1\n[Other]\nx=1\n", "k", "v") == "[Settings]\na=1\nk=v\n[Other]\nx=1\n"


def recent_xbel():
    return {".local/share/recently-used.xbel": '<xbel><bookmark href="file:///a"/></xbel>'}


@pytest.mark.parametrize("desktop, schema", [(("gnome",), "org.gnome.desktop.privacy"),
                                             (("x-cinnamon",), "org.cinnamon.desktop.privacy")])
def test_recent_files_keep_a_month_or_stop(cat, tmp_path, desktop, schema):
    gs = FakeGSettings({(schema, "remember-recent-files"): "true", (schema, "recent-files-max-age"): "-1"})
    host = make_host(tmp_path, home_files=recent_xbel())
    host.runner.handlers["gsettings"] = gs
    g = build(cat, host, "desk.recent_files", desktop=desktop)
    opts = options(g)
    log, res = apply(host, opts["Stop remembering recent files"])
    assert gs.values[(schema, "remember-recent-files")] == "false"
    revert(host, log, res)
    log, res = apply(host, opts["Keep recent files for at most 30 days"])
    assert gs.values[(schema, "recent-files-max-age")] == "30"
    log, res = apply(host, opts["Clear it"])
    assert detect(cat, "desk.recent_files", make_scan(host, desktop=desktop)).status is Status.PASS


def test_recent_files_elsewhere_through_gtk_settings(cat, tmp_path):
    host = make_host(tmp_path, home_files={**recent_xbel(), ".config/gtk-3.0/settings.ini": "[Settings]\ngtk-theme-name=X\n"})
    g = build(cat, host, "desk.recent_files", desktop=("xfce",))
    plan = options(g)["Stop remembering recent files in GTK apps"]
    log, res = apply(host, plan)
    assert (host.home / ".config/gtk-3.0/settings.ini").read_text() == \
        "[Settings]\ngtk-theme-name=X\ngtk-recent-files-enabled=false\n"
    assert (host.home / ".config/gtk-4.0/settings.ini").exists()
    revert(host, log, res)
    assert (host.home / ".config/gtk-3.0/settings.ini").read_text() == "[Settings]\ngtk-theme-name=X\n"
    assert not (host.home / ".config/gtk-4.0/settings.ini").exists()


# ------------------------------------------------------------------ expiring files (user tmpfiles.d)

def user_host(tmp_path, timer="disabled", **kw):
    host = make_host(tmp_path, installed=("systemd-tmpfiles",), **kw)
    sc = FakeUserSystemctl({"systemd-tmpfiles-clean.timer": timer})
    host.runner.handlers["systemctl"] = sc
    return host, sc


def test_user_unit_set_applies_and_reverts(tmp_path):
    host, sc = user_host(tmp_path)
    log = UndoLog(host.home / ".state")
    from daprivacyscanner.fix import FixPlan
    res = apply_plan(FixPlan("x", "t", [UserUnitSet("systemd-tmpfiles-clean.timer", True)]), host, log)
    assert res.ok and sc.units["systemd-tmpfiles-clean.timer"] == "enabled"
    assert ["systemctl", "--user", "enable", "--now", "systemd-tmpfiles-clean.timer"] in sc.calls
    revert(host, log, res)
    assert sc.units["systemd-tmpfiles-clean.timer"] == "disabled"


def test_screenshots_expire_by_a_rule_of_the_apps_own(cat, tmp_path):
    host, sc = user_host(tmp_path, home_files={"Pictures/Screenshots/new.png": "x", "Pictures/Screenshots/old.png": "x",
                                               "Pictures/Screenshots/older.png": "x", "Pictures/Screenshot keep.png": "x"})
    shots = host.home / "Pictures/Screenshots"
    past = time.time() - 60 * 86400
    for name in ("old.png", "older.png"):
        os.utime(shots / name, (past, past))
    o = detect(cat, "desk.screenshots", make_scan(host))
    assert o.status is Status.WARN
    g = build(cat, host, "desk.screenshots")
    plan = options(g)["Keep screenshots for 30 days"]
    # ctime can't be set back in a test, so nothing here is old by both clocks: no deletion now, the
    # rule does the rest
    assert [a.kind for a in plan.actions] == ["file", "userunit"]
    rule = (plan.actions[0].content(None))
    assert f"e {shots} - - - cmM:30d" in rule
    log, res = apply(host, plan)
    conf = host.home / ".config/user-tmpfiles.d/60-daprivacyscanner-screenshots.conf"
    assert conf.read_text() == rule and sc.units["systemd-tmpfiles-clean.timer"] == "enabled"
    o = detect(cat, "desk.screenshots", make_scan(host))
    assert o.status is Status.PASS and ev(o)["Deleted after"].startswith("30 days")
    revert(host, log, res)
    assert not conf.exists() and sc.units["systemd-tmpfiles-clean.timer"] == "disabled"


def test_screenshots_rule_never_covers_pictures_itself(cat, tmp_path):
    from daprivacyscanner.checks.desktop import screenshot_dirs
    host, _ = user_host(tmp_path, home_files={".config/spectaclerc": "[General]\ndefaultSaveLocation=file://HOME/Pictures\n"})
    (host.home / ".config/spectaclerc").write_text(f"[General]\ndefaultSaveLocation=file://{host.home}/Pictures\n")
    assert host.home / "Pictures" not in screenshot_dirs(make_scan(host, desktop=("kde",)))


def test_tmpfiles_paths_are_quoted():
    from daprivacyscanner.checks.guides import tmpfiles_path
    assert tmpfiles_path("/home/a/Pictures/Screenshots") == "/home/a/Pictures/Screenshots"
    assert tmpfiles_path('/home/a/My "Shots" 100%') == '"/home/a/My \\"Shots\\" 100%%"'


def test_thumbnails_expire_on_desktops_without_a_setting(cat, tmp_path):
    from test_checks_telemetry_browser import png
    host, sc = user_host(tmp_path)
    d = host.home / ".cache/thumbnails/normal"
    d.mkdir(parents=True)
    (d / "gone.png").write_bytes(png((host.home / "deleted.jpg").as_uri()))
    g = build(cat, host, "desk.thumbnails", desktop=("kde",), devices=[])
    plan = options(g)["Delete thumbnails not used for 30 days"]
    assert f"e {host.home}/.cache/thumbnails - - - 30d" in plan.actions[0].content(None)
    apply(host, plan)
    o = detect(cat, "desk.thumbnails", make_scan(host, desktop=("kde",), devices=[]))
    assert ev(o)["Deleted when unused for"].startswith("30 days")


# ------------------------------------------------------------------ GVFS metadata, the Ephemeral folder

def test_gvfs_metadata_cleared_or_kept_in_memory(cat, tmp_path, system, monkeypatch):
    host, _ = home_on_the_system(tmp_path, system, monkeypatch)
    meta = host.home / ".local/share/gvfs-metadata"
    meta.mkdir(parents=True)
    (meta / "home").write_text("x")
    (host.root / "proc/9").mkdir(parents=True)
    (host.root / "proc/9/comm").write_text("gvfsd-metadata\n")
    calls = []
    host.runner.handlers["pkill"] = recorder(calls)
    g = build(cat, host, "desk.gvfs_metadata")
    plan = options(g)[f"Mount {host.display(meta)} in memory (needs administrator access)"]
    assert [a.kind for a in plan.actions] == ["command", "delete", "root"]
    assert plan.actions[2].args == {"target": "gvfs-metadata", "size_mb": 50}
    log, res = apply(host, plan)
    assert calls and not any(meta.iterdir())
    (host.root / "proc/mounts").write_text(f"tmpfs {meta} tmpfs rw 0 0\n".replace(str(host.root), ""))
    o = detect(cat, "desk.gvfs_metadata", make_scan(host))
    assert o.status is Status.PASS and "in memory" in o.summary
    revert(host, log, res)


def test_ephemeral_is_a_feature_set_up_with_the_users_choices(cat, tmp_path, system, monkeypatch):
    host, _ = home_on_the_system(tmp_path, system, monkeypatch)
    (host.root / "proc").mkdir(exist_ok=True)
    (host.root / "proc/swaps").write_text(SWAPS + "/swapfile file 2097148 0 -2\n")
    (host.root / "proc/meminfo").write_text("MemTotal:        8000000 kB\n")
    check = load_all()["desk.ephemeral_folder"](cat["desk.ephemeral_folder"])
    scan = make_scan(host, hibernation=False)
    o = check.detect(scan)
    assert o.status is Status.WARN and o.summary.startswith("Not set up")
    assert any(n.title == "Memory can still reach the disk" for n in o.notes)
    g = check.plan_guide(scan, o)
    first, setup = g.steps[0], g.steps[1]
    assert not first.done and "Much of the benefit is lost" in first.text and "/swapfile" in first.text
    assert {i.name: i.value for i in setup.inputs} == {"size_mb": 500, "until": "reboot", "noexec": True}
    vault = g.steps[-1]
    assert vault.title.startswith("Or, for files that should last") and "Cryptomator" in vault.text
    assert "cloud-synced folder" in vault.text and not vault.options
    assert setup.options[0].plan.actions[0].args == {"target": "ephemeral", "size_mb": 500, "noexec": True,
                                                     "until": "reboot"}
    scan.params = {"size_mb": 750, "until": "logout", "noexec": False, "extra": "ignored"}
    plan = check.plan_guide(scan, o).steps[1].options[0].plan
    assert plan.actions[0].args == {"target": "ephemeral", "size_mb": 750, "noexec": False, "until": "logout"}
    assert any("Programs can run from it" in e for e in plan.side_effects)
    scan.params = {"size_mb": 999999, "until": "never", "noexec": "yes"}          # not allowed: the defaults
    assert check.plan_guide(scan, o).steps[1].options[0].plan.actions[0].args["size_mb"] == 500
    log, res = apply(host, plan)
    assert "BindsTo=user@" in (host.root / "etc/systemd/system/home-alice-Ephemeral.mount").read_text()
    (host.root / "proc/mounts").write_text("tmpfs /home/alice/Ephemeral tmpfs rw,nosuid,nodev,size=768000k 0 0\n")
    o = check.detect(make_scan(host, hibernation=False))
    assert o.status is Status.PASS and ev(o)["Programs can run from it"] == "yes"
    assert ev(o)["Emptied"] == "at logout and every reboot"
    revert(host, log, res, force=True)


def test_ephemeral_refuses_a_folder_with_files(cat, tmp_path, system, monkeypatch):
    host, _ = home_on_the_system(tmp_path, system, monkeypatch)
    (host.home / "Ephemeral").mkdir()
    (host.home / "Ephemeral/notes.txt").write_text("x")
    g = build(cat, host, "desk.ephemeral_folder", hibernation=False)
    plan = g.steps[1].options[0].plan
    assert plan.blockers and "already has files" in plan.blockers[0]


def test_input_read_checks_values():
    assert Input.read({"n": 5}, "n", "number", 1, 0, 10) == 5
    assert Input.read({"n": True}, "n", "number", 1, 0, 10) == 1
    assert Input.read({"n": "5"}, "n", "number", 1, 0, 10) == 1
    assert Input.read({"c": "x"}, "c", "choice", "a", choices=("a", "b")) == "a"
    assert Input.read({}, "b", "bool", True) is True


# ------------------------------------------------------------------ /tmp, login records, suspend

def test_tmp_on_disk_links_the_distributions_unit(cat, tmp_path, system, monkeypatch):
    host = make_host(tmp_path, files={"/usr/share/systemd/tmp.mount": "[Mount]\n", "/proc/mounts": "/dev/sda3 / ext4 rw 0 0\n"})
    rooted(host, system, monkeypatch)
    g = build(cat, host, "enc.tmp_on_disk")
    plan = g.steps[0].options[0].plan
    assert plan.actions[0].request == "enable_tmp_mount"
    assert any("hidden under the mount" in e for e in g.steps[0].side_effects)
    log, res = apply(host, plan)
    o = detect(cat, "enc.tmp_on_disk", make_scan(host))
    assert o.status is Status.WARN and "next boot" in o.summary
    assert build(cat, host, "enc.tmp_on_disk").steps[0].done
    revert(host, log, res)
    assert "tmp.mount" not in system.units


def test_login_records_guide(cat, tmp_path, system, monkeypatch):
    host = make_host(tmp_path, files={"/var/log/wtmp": "", "/var/log/lastlog": "",
                                      "/etc/logrotate.d/wtmp": "/var/log/wtmp {\n    create 0664 root utmp\n}\n"})
    for f in ("wtmp", "lastlog"):
        (host.root / "var/log" / f).chmod(0o664)
    rooted(host, system, monkeypatch)
    g = build(cat, host, "auth.login_history", multi_user=True)
    plan = g.steps[0].options[0].plan
    assert [a.request for a in plan.actions] == ["write_dropin", "edit_config"]
    assert plan.actions[0].args["settings"] == {"/var/log/wtmp": "0660", "/var/log/lastlog": "0660"}
    log, res = apply(host, plan)
    assert (host.root / "etc/tmpfiles.d/00-daprivacyscanner-wtmp.conf").exists()
    assert "create 0660 root utmp" in (host.root / "etc/logrotate.d/wtmp").read_text()
    revert(host, log, res)


def test_suspend_then_hibernate_offered_only_with_an_encrypted_image(cat, tmp_path, system, monkeypatch):
    check = load_all()["kern.suspend_keys_in_ram"](cat["kern.suspend_keys_in_ram"])
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/home/swapfile file 8388604 0 -2\n",
                                      "/sys/power/resume": "0:0\n", "/etc/os-release": "ID=fedora\n"})
    rooted(host, system, monkeypatch)
    g = check.plan_guide(make_scan(host, devices=FEDORA, hibernation=True), Outcome(Status.FAIL, "x"))
    opts = options(g)
    plan = opts["Suspend, then hibernate after 1 hour"]
    assert [a.args["name"] for a in plan.actions] == ["sleep-delay", "logind-sleep"]
    log, res = apply(host, plan)
    assert "HibernateDelaySec=1h" in (host.root / "etc/systemd/sleep.conf.d/60-daprivacyscanner-delay.conf").read_text()
    revert(host, log, res)
    g = check.plan_guide(make_scan(host, devices=MINT, hibernation=True), Outcome(Status.FAIL, "x"))
    assert not options(g)


def test_cryptsetup_suspend_for_debian_with_root_on_luks(cat, tmp_path):
    from conftest import lsblk as lb
    check = load_all()["kern.suspend_keys_in_ram"](cat["kern.suspend_keys_in_ram"])
    host = make_host(tmp_path, files={"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n"})
    g = check.plan_guide(make_scan(host, devices=lb("ubuntu-24.04-luks-lvm.json"), hibernation=False),
                         Outcome(Status.FAIL, "x"))
    step = next(s for s in g.steps if "cryptsetup-suspend" in s.title)
    assert step.commands == ["sudo apt install cryptsetup-suspend"]


# ------------------------------------------------------------------ editors, KDE, trash, Chromium

def test_vim_swap_and_undo_in_memory_with_defaults_kept(cat, tmp_path):
    host = make_host(tmp_path, installed=("vim", "nvim"), home_files={".vim/swap/x.swp": "x",
                                                                      ".config/nvim/init.lua": "vim.o.number = true\n"})
    g = build(cat, host, "app.editor_residue")
    plan = options(g)["Keep Vim's and Neovim's swap and undo files in memory"]
    log, res = apply(host, plan)
    vimrc = (host.home / ".vimrc").read_text()
    assert vimrc.startswith("unlet! skip_defaults_vim\nsource $VIMRUNTIME/defaults.vim\n")
    assert "set directory^=$XDG_RUNTIME_DIR//" in vimrc
    lua = (host.home / ".config/nvim/init.lua").read_text()
    assert lua.startswith("vim.o.number = true\n\n-- DA Privacy Kit") and 'vim.opt.directory:prepend' in lua
    assert not any(o.label.startswith("Keep Vim") for s in build(cat, host, "app.editor_residue").steps for o in s.options)
    revert(host, log, res)
    assert not (host.home / ".vimrc").exists()
    assert (host.home / ".config/nvim/init.lua").read_text() == "vim.o.number = true\n"


def test_kde_activities_stops_recording(cat, tmp_path):
    host = make_host(tmp_path, installed=("kwriteconfig6",),
                     home_files={".local/share/RecentDocuments/a.desktop": "[Desktop Entry]\n"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    check = load_all()["desk.kde_activities"](cat["desk.kde_activities"])
    scan = make_scan(host, desktop=("kde",), plasma_major=6)
    plan = check.plan_fix(scan, check.detect(scan))
    log, res = apply(host, plan)
    assert "UseRecent=false" in (host.home / ".config/kdeglobals").read_text()
    assert "what-to-remember=2" in (host.home / ".config/kactivitymanagerd-pluginsrc").read_text()
    revert(host, log, res)
    assert not (host.home / ".config/kdeglobals").exists()                    # the fix made it: it goes


def test_trash_expires_on_cinnamon_and_kde(cat, tmp_path):
    gs = FakeGSettings({("org.cinnamon.desktop.privacy", "remove-old-trash-files"): "false",
                        ("org.cinnamon.desktop.privacy", "old-files-age"): "uint32 30"})
    host = make_host(tmp_path / "c", home_files={".local/share/Trash/files/a": "x", ".local/share/Trash/info/a.trashinfo": "x"})
    host.runner.handlers["gsettings"] = gs
    check = load_all()["enc.trash"](cat["enc.trash"])
    scan = make_scan(host, desktop=("x-cinnamon",))
    plan = check.plan_fix(scan, check.detect(scan))
    assert any(getattr(a, "schema", "") == "org.cinnamon.desktop.privacy" for a in plan.actions)
    host = make_host(tmp_path / "k", installed=("kwriteconfig6",),
                     home_files={".local/share/Trash/files/a": "x", ".local/share/Trash/info/a.trashinfo": "x"})
    host.runner.handlers["kwriteconfig6"] = FakeKwriteconfig(host.home / ".config")
    scan = make_scan(host, desktop=("kde",), plasma_major=6)
    plan = check.plan_fix(scan, check.detect(scan))
    log, res = apply(host, plan)
    text = (host.home / ".config/ktrashrc").read_text()
    assert f"[{host.home}/.local/share/Trash]" in text and "UseTimeLimit=true" in text and "Days=30" in text


def test_chromium_clear_on_exit_by_policy(cat, tmp_path):
    from test_checks_telemetry_browser import chrome
    host = make_host(tmp_path)
    chrome(host.home)
    check = load_all()["br.history_retention"](cat["br.history_retention"])
    g = check.plan_guide(make_scan(host), Outcome(Status.WARN, "x"))
    labels = list(options(g))
    assert "Keep site data only until the browser closes: Google Chrome, for every user (policy)" in labels
    plan = options(g)["Turn off sync, and clear history, downloads and cache when the browser closes: Google Chrome, "
                      "for every user (policy)"]
    assert plan.actions[0].args["settings"] == {"SyncDisabled": True, "ClearBrowsingDataOnExitList": helper.CLEAR_ON_EXIT}
    assert any("Sync stops" in s for s in plan.side_effects)
    signed_out = options(g)["Keep site data only until the browser closes: Google Chrome, for every user (policy)"]
    assert any("signs you out" in s for s in signed_out.side_effects)
    assert any(s.title == "About the cache" for s in g.steps)


# ------------------------------------------------------------------ zram writeback, deleted data

def test_zram_writing_back_to_an_unencrypted_disk_is_unencrypted_swap(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/dev/zram0 partition 8388604 0 100\n",
                                      "/sys/block/zram0/backing_dev": "/dev/sda1\n"})
    o = detect(cat, "enc.swap_unencrypted", make_scan(host, devices=MINT))
    assert o.status is Status.FAIL and "not encrypted" in ev(o)["/dev/zram0"]


def test_zram_writeback_set_up_in_the_generator_config(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/dev/zram0 partition 8388604 0 100\n",
                                      "/sys/block/zram0/backing_dev": "none\n",
                                      "/etc/systemd/zram-generator.conf": "[zram0]\nwriteback-device = /dev/sda3\n"})
    o = detect(cat, "enc.swap_persistent", make_scan(host, devices=MINT))
    assert o.status is Status.FAIL and ev(o)["zram-generator"] == "writeback-device=/dev/sda3: not encrypted"
    assert detect(cat, "enc.swap_unencrypted", make_scan(host, devices=MINT)).status is Status.FAIL


def test_zram_option_written_by_the_helper(cat, tmp_path, system, monkeypatch):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/swapfile file 2097148 0 -2\n",
                                      "/usr/lib/systemd/system-generators/zram-generator": ""})
    rooted(host, system, monkeypatch)
    g = build(cat, host, "enc.swap_persistent", devices=MINT)
    plan = options(g)["Turn on zram (half of the memory, at most 8 GB)"]
    assert plan.actions[0].args == {"name": "zram", "settings": {"zram-size": "min(ram / 2, 8192)"}}
    assert "sudo swapoff /swapfile" in g.steps[0].commands and not any("apt install" in c for c in g.steps[0].commands)


def test_deleted_data_on_encrypted_btrfs_ssd_trimmed_weekly(cat, tmp_path):
    host = make_host(tmp_path, files={
        "/proc/mounts": "/dev/mapper/luks-0f2c4e5a-1b2c-4d3e-8f90-123456789abc / btrfs rw,ssd,space_cache=v2 0 0\n",
        "/sys/block/nvme0n1/queue/rotational": "0\n",
        "/sys/block/dm-0/dm/name": "luks-0f2c4e5a-1b2c-4d3e-8f90-123456789abc\n",
        "/sys/block/dm-0/queue/discard_max_bytes": "4294966784\n"},
        commands={("systemctl", "is-enabled", "fstrim.timer"): "enabled\n"})
    scan = make_scan(host, devices=FEDORA)
    note = deleted_data_note(scan)
    assert "weekly fstrim timer" in note and "btrfs is copy-on-write" in note and "while it is unlocked" in note
    o = detect(cat, "enc.deleted_data_recoverable", scan)
    assert o.status is Status.WARN and "btrfs keeps older copies" in o.summary
    assert {n.title for n in o.notes} >= {"Encryption is what protects deleted data", "btrfs keeps older copies of files"}
    assert "SSD, trimmed weekly (fstrim.timer), encrypted" in ev(o)["/"]


def test_deleted_data_on_an_unencrypted_disk(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/mounts": "/dev/sda3 / ext4 rw,relatime 0 0\n",
                                      "/sys/block/sda/queue/rotational": "1\n"})
    scan = make_scan(host, devices=MINT)
    assert "Without disk encryption, recovery tools" in deleted_data_note(scan)
    o = detect(cat, "enc.deleted_data_recoverable", scan)
    assert o.status is Status.WARN and "not encrypted" in o.summary


def test_plans_that_delete_say_what_deleting_does(cat, tmp_path, monkeypatch):
    from daprivacyscanner import runner as runner_mod
    from daprivacyscanner.runner import Runner
    host = make_host(tmp_path, home_files={".local/share/Trash/files/a": "x", ".local/share/Trash/info/a.trashinfo": "x"})
    monkeypatch.setattr(runner_mod, "detect_context", lambda h: make_scan(h, devices=MINT).context)
    result, plan = Runner(cat, host).plan_fix("enc.trash")
    assert plan.irreversible and any(e.startswith("Deleted, not wiped") for e in plan.side_effects)


# ------------------------------------------------------------------ export everything

def test_undo_hints():
    assert ACTION_KINDS["gsettings"].undo_hint({"schema": "a.b", "key": "k", "before": "uint32 300"}) == \
        "gsettings set a.b k 'uint32 300'"
    assert ACTION_KINDS["file"].undo_hint({"path": "/h/.vimrc", "backup": None}).startswith("rm /h/.vimrc")
    assert ACTION_KINDS["root"].undo_hint({"change_id": "ab" * 16}).endswith(f"{'ab' * 16}.json (root only)")
    assert ACTION_KINDS["delete"].undo_hint({}) == ""
    assert ACTION_KINDS["userunit"].undo_hint({"unit": "t.timer", "before": "disabled"}) == \
        "systemctl --user disable --now t.timer"


def test_export_everything(cat, tmp_path):
    host = make_host(tmp_path, env={"USER": "alice"})
    entries = [{"id": "e1", "check_id": "desk.recent_files", "title": "Stop remembering recent files",
                "applied": 1_700_000_000, "state": "applied", "records": [
                    {"kind": "gsettings", "schema": "org.gnome.desktop.privacy", "key": "remember-recent-files",
                     "before": "true", "after": "false", "text": "remember-recent-files: true → false"},
                    {"kind": "file", "path": f"{host.home}/.vimrc", "display": "~/.vimrc", "backup": None,
                     "after_sha": "x", "text": "Add it (~/.vimrc)"},
                    {"kind": "delete", "label": "recent", "root": "~", "deleted": 1, "skipped": 0,
                     "text": "Deleted 1 file"}]}]
    accepted = {"net.firewall_off": {"severity": 3, "note": "behind my router"}}
    text = report.export_all(None, cat, entries, accepted, "text", host)
    assert "== Changes made by DA Privacy Kit (1)" in text
    assert "undo by hand: gsettings set org.gnome.desktop.privacy remember-recent-files true" in text
    assert f"undo by hand: rm {host.home}/.vimrc" in text and "(permanent) Deleted 1 file" in text
    assert "net.firewall_off: accepted at severity 3: behind my router" in text and "No scan is saved" in text
    data = json.loads(report.export_all(None, cat, entries, accepted, "json", host, redact=True))
    assert data["format"] == "daprivacyscanner-export" and data["redacted"]
    assert str(host.home) not in json.dumps(data) and data["changes"][0]["steps"][2]["undo_by_hand"] == ""
    assert data["not_included"]


def test_export_from_the_command_line(cat, tmp_path, monkeypatch):
    from daprivacyscanner import app
    from daprivacyscanner.host import Host
    host = make_host(tmp_path)
    monkeypatch.setattr(Host, "local", staticmethod(lambda: host))
    out = tmp_path / "everything.json"
    assert app.export_cli(cat, str(out), False) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and json.loads(out.read_text())["changes"] == []


def test_screenshots_saved_into_pictures_get_a_folder_first(cat, tmp_path):
    host, sc = user_host(tmp_path, home_files={"Pictures/Screenshot from 2026-10-03.png": "x"})
    gs = FakeGSettings({("org.gnome.gnome-screenshot", "auto-save-directory"): "''"})
    host.runner.handlers["gsettings"] = gs
    g = build(cat, host, "desk.screenshots", desktop=("x-cinnamon",))
    target = host.home / "Pictures/Screenshots"
    plan = options(g)["Save new screenshots to ~/Pictures/Screenshots"]
    assert [a.kind for a in plan.actions] == ["mkdir", "gsettings"]
    assert f"e {target} - - - cmM:30d" in options(g)["Keep screenshots for 30 days"].actions[0].content(None)
    log, res = apply(host, plan)
    assert target.is_dir() and gs.values[("org.gnome.gnome-screenshot", "auto-save-directory")] == f"'{target.as_uri()}'"
    revert(host, log, res)
    assert not target.exists() and gs.values[("org.gnome.gnome-screenshot", "auto-save-directory")] == "''"


def test_zram_writing_back_to_an_encrypted_disk_still_keeps_earlier_sessions(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/dev/zram0 partition 8388604 0 100\n",
                                      "/sys/block/zram0/backing_dev": "/dev/dm-0\n",
                                      "/sys/block/dm-0/dm/name": "luks-0f2c4e5a-1b2c-4d3e-8f90-123456789abc\n",
                                      "/etc/crypttab": ""})
    o = detect(cat, "enc.swap_persistent", make_scan(host, devices=FEDORA))
    assert o.status is Status.FAIL
    assert ev(o)["/dev/zram0"] == "zram writing back to /dev/dm-0: encrypted, with the same key every boot"
    [note] = o.notes
    assert note.title == "Earlier sessions' swap can be read back" and "administrator access while it is unlocked" in note.text
    # the encrypted case isn't unencrypted swap
    assert detect(cat, "enc.swap_unencrypted", make_scan(host, devices=FEDORA)).status is Status.PASS


def test_zram_writing_back_to_a_random_key_device_leaves_nothing(cat, tmp_path):
    import daprivacyscanner.blockdev as b
    devices = b.parse_lsblk(json.dumps({"blockdevices": [
        {"name": "zram0", "type": "disk", "fstype": None, "mountpoints": ["[SWAP]"]},
        {"name": "sda", "type": "disk", "children": [
            {"name": "sda2", "type": "part", "fstype": None, "children": [
                {"name": "zback", "type": "crypt", "fstype": None, "mountpoints": [None]}]}]}]}))
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/dev/zram0 partition 8388604 0 100\n",
                                      "/sys/block/zram0/backing_dev": "/dev/dm-1\n",
                                      "/sys/block/dm-1/dm/name": "zback\n",
                                      "/etc/crypttab": "zback /dev/sda2 /dev/urandom plain,cipher=aes-xts-plain64\n"})
    o = detect(cat, "enc.swap_persistent", make_scan(host, devices=devices))
    assert o.status is Status.PASS and "new random key each boot" in ev(o)["/dev/zram0"]


def test_turning_off_zram_writeback_is_a_step(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/swaps": SWAPS + "/dev/zram0 partition 8388604 0 100\n",
                                      "/sys/block/zram0/backing_dev": "/dev/sda1\n",
                                      "/usr/lib/systemd/zram-generator.conf": "[zram0]\nwriteback-device=/dev/sda1\n"})
    g = build(cat, host, "enc.swap_persistent", devices=MINT)
    step = g.steps[0]
    assert step.title == "Turn off zram writeback"
    assert step.commands[:2] == ["sudo cp /usr/lib/systemd/zram-generator.conf /etc/systemd/zram-generator.conf",
                                 "sudoedit /etc/systemd/zram-generator.conf     # delete the writeback-device line"]


def test_the_vault_step_gives_the_install_command_only_where_it_helps(tmp_path):
    from daprivacyscanner.checks.guides.desktop import CRYPTOMATOR_FLATPAK, cryptomator_step
    st = cryptomator_step(make_scan(make_host(tmp_path / "a", installed=("flatpak",))))
    assert st.commands == [f"flatpak install flathub {CRYPTOMATOR_FLATPAK}"]
    st = cryptomator_step(make_scan(make_host(tmp_path / "b")))
    assert not st.commands and "cryptomator.org" in st.text
    host = make_host(tmp_path / "c", installed=("flatpak",))
    (host.home / ".local/share/flatpak/app" / CRYPTOMATOR_FLATPAK).mkdir(parents=True)
    st = cryptomator_step(make_scan(host))
    assert not st.commands and "installed here" in st.text
