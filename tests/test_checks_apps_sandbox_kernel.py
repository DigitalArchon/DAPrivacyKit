import gzip
import os
import json
import sqlite3

import pytest

from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan, skip_if_root

# ------------------------------------------------------------------ apps


def test_photo_dbs_with_faces(cat, tmp_path):
    host = make_host(tmp_path)
    db = host.home / ".local/share/shotwell/data/photo.db"
    db.parent.mkdir(parents=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE FaceTable (id INTEGER, name TEXT)")
    con.execute("INSERT INTO FaceTable VALUES (1, 'Bob')")
    con.commit(); con.close()
    o = detect(cat, "app.photo_dbs", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Named faces"] == 1 and o.notes
    assert detect(cat, "app.photo_dbs", make_scan(make_host(tmp_path / "n"))).status is Status.NOT_APPLICABLE


def test_signal_plaintext_key(cat, tmp_path):
    host = make_host(tmp_path, home_files={".var/app/org.signal.Signal/config/Signal/config.json":
                                           json.dumps({"key": "00112233"})})
    o = detect(cat, "app.messengers_mail", make_scan(host))
    assert o.status is Status.FAIL and "Signal (flatpak)" in o.summary
    host = make_host(tmp_path / "b", home_files={".config/Signal/config.json": json.dumps({"encryptedKey": "v11..."})})
    assert detect(cat, "app.messengers_mail", make_scan(host)).status is Status.PASS        # small and keyring-backed


def test_large_message_store_is_a_warning(cat, tmp_path):
    host = make_host(tmp_path)
    d = host.home / ".local/share/TelegramDesktop/tdata"
    d.mkdir(parents=True)
    (d / "cache").write_bytes(b"x" * (2 * 1024 * 1024))
    assert detect(cat, "app.messengers_mail", make_scan(host)).status is Status.WARN


def test_editor_residue(cat, tmp_path):
    host = make_host(tmp_path, home_files={".viminfo": "# viminfo", "Documents/.notes.txt.swp": "x",
                                           "Documents/letter.txt~": "x", "code/node_modules/.x.swp": "ignored"})
    o = detect(cat, "app.editor_residue", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Swap and backup files next to documents"].startswith("2 files")
    assert detect(cat, "app.editor_residue", make_scan(make_host(tmp_path / "c"))).status is Status.PASS


def test_libreoffice(cat, tmp_path):
    xcu = ('<item oor:path="/org.openoffice.Office.Histories/Histories/org.openoffice.Office.Histories:HistoryInfo'
           "['PickList']/ItemList/org.openoffice.Office.Histories:HistoryItem['file:///home/a/x.odt']\">"
           '<prop oor:name="Title"><value>x</value></prop></item>\n')
    host = make_host(tmp_path, home_files={".var/app/org.libreoffice.LibreOffice/config/libreoffice/4/user/"
                                           "registrymodifications.xcu": xcu * 2})
    o = detect(cat, "app.office", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["LibreOffice recent documents (flatpak)"] == 1


def test_media_players(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/state/mpv/watch_later/ABC123": "start=12.3",
                                           ".config/vlc/vlc-qt-interface.conf": "[RecentsMRL]\nlist=file:///a.mkv, file:///b.mkv\n"})
    o = detect(cat, "app.media_players", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["VLC recent media"] == 2


@pytest.mark.parametrize("conf, status", [
    (None, Status.FAIL),                                          # CUPS defaults keep files and history
    ("PreserveJobFiles No\nPreserveJobHistory No\n", Status.PASS),
])
def test_cups(cat, tmp_path, conf, status):
    files = {"/etc/cups/cupsd.conf": conf} if conf else {"/etc/cups/printers.conf": ""}
    host = make_host(tmp_path, files=files, commands={"lpstat -W completed -o": "HP-1 alice 1024 Mon\n"})
    assert detect(cat, "app.cups_spool", make_scan(host)).status is status


@skip_if_root
def test_cups_unreadable_config_is_never_assumed(cat, tmp_path):
    """Fedora keeps cupsd.conf root-only: CUPS's defaults aren't assumed for it."""
    host = make_host(tmp_path, files={"/etc/cups/cupsd.conf": "PreserveJobFiles No\nPreserveJobHistory No\n"},
                     commands={"lpstat -W completed -o": ""})
    os.chmod(host.sys_path("/etc/cups/cupsd.conf"), 0)
    o = detect(cat, "app.cups_spool", make_scan(host))
    assert o.status is Status.UNKNOWN and o.needs_admin


def test_okular(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/okular/docdata/123.report.pdf.xml": "<documentInfo/>"})
    assert detect(cat, "app.pdf_readers", make_scan(host, desktop=("kde",))).status is Status.FAIL


def test_electron_caches(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/Slack/Cache/Cache_Data/f_0001": "x" * 100,
                                           ".config/Slack/GPUCache/data_0": "x",
                                           ".config/google-chrome/GPUCache/data_0": "browser, not counted"})
    o = detect(cat, "app.electron_caches", make_scan(host))
    assert o.status is Status.FAIL and list(ev(o)) == ["Slack"]


def test_package_logs(cat, tmp_path):
    host = make_host(tmp_path, files={"/var/log/apt/history.log": "x", "/var/log/apt/history.log.1.gz": "x"})
    o = detect(cat, "app.package_logs", make_scan(host))
    os.chmod(host.sys_path("/var/log/apt/history.log"), 0o640)
    o = detect(cat, "app.package_logs", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["/var/log/apt/history.log"].endswith("plus 1 older")
    os.chmod(host.sys_path("/var/log/apt/history.log"), 0o644)                 # as apt leaves it
    o = detect(cat, "app.package_logs", make_scan(host))
    assert ev(o)["/var/log/apt/history.log"].endswith("readable by every account") and "every account" in o.summary


def test_shared_file_metadata_without_libreoffice(cat, tmp_path):
    o = detect(cat, "app.shared_file_metadata", make_scan(make_host(tmp_path, installed=["mat2"])))
    assert o.status is Status.NOT_APPLICABLE and ev(o)["Metadata tools installed"] == "mat2"


LO_XCU = ('<?xml version="1.0" encoding="UTF-8"?>\n<oor:items xmlns:oor="http://openoffice.org/2001/registry">\n'
          '<item oor:path="/org.openoffice.UserProfile/Data"><prop oor:name="givenname" oor:op="fuse"><value>Alice</value></prop></item>\n'
          '{extra}</oor:items>\n')


def test_shared_file_metadata_libreoffice(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/libreoffice/4/user/registrymodifications.xcu": LO_XCU.format(extra="")})
    o = detect(cat, "app.shared_file_metadata", make_scan(host))
    assert o.status is Status.FAIL and "Alice" not in str(o.evidence)
    strip = ('<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="RemovePersonalInfoOnSaving" '
             'oor:op="fuse"><value>true</value></prop></item>\n')
    host = make_host(tmp_path / "b", home_files={".config/libreoffice/4/user/registrymodifications.xcu": LO_XCU.format(extra=strip)})
    assert detect(cat, "app.shared_file_metadata", make_scan(host)).status is Status.PASS


# ------------------------------------------------------------------ sandbox

PERMS = {
    "org.mozilla.firefox": "[Context]\nshared=network;ipc;\nsockets=x11;wayland;\ndevices=dri;\n"
                           "filesystems=xdg-download;\n",
    "org.remmina.Remmina": "[Context]\nfilesystems=home;\ndevices=all;\n\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\n",
    "com.example.Editor": "[Context]\nfilesystems=host;\n",
}


def flatpak_host(tmp_path, **kw):
    commands = {("flatpak", "list", "--app", "--columns=application"): "\n".join(PERMS) + "\n"}
    commands.update({("flatpak", "info", "--show-permissions", a): p for a, p in PERMS.items()})
    return make_host(tmp_path, commands=commands, **kw)


def test_flatpak_broad_perms(cat, tmp_path):
    o = detect(cat, "sbx.flatpak_broad_perms", make_scan(flatpak_host(tmp_path)))
    assert o.status is Status.FAIL and o.summary.startswith("org.remmina.Remmina can run commands outside its sandbox")
    assert set(ev(o)) == {"org.remmina.Remmina", "com.example.Editor"}


def test_flatpak_user_override_narrows(cat, tmp_path):
    host = flatpak_host(tmp_path, home_files={".local/share/flatpak/overrides/com.example.Editor": "[Context]\nfilesystems=!host;\n"})
    assert "com.example.Editor" not in ev(detect(cat, "sbx.flatpak_broad_perms", make_scan(host)))


def test_flatpak_caches_and_leftovers(cat, tmp_path):
    host = flatpak_host(tmp_path, home_files={".var/app/org.mozilla.firefox/cache/x": "x" * 10,
                                              ".var/app/org.old.App/data/y": "y"})          # no snap installed
    assert detect(cat, "sbx.flatpak_caches", make_scan(host)).status is Status.FAIL
    o = detect(cat, "sbx.leftover_data", make_scan(host))
    assert o.status is Status.FAIL and list(ev(o)) == ["~/.var/app/org.old.App"]


@pytest.mark.parametrize("session, status", [("x11", Status.FAIL), ("wayland", Status.PASS), (None, Status.UNKNOWN)])
def test_x11(cat, tmp_path, session, status):
    assert detect(cat, "sbx.x11_session", make_scan(make_host(tmp_path), session=session)).status is status


def test_portal_permissions(cat, tmp_path):
    # the location portal stores an accuracy and the time it was granted, never "yes" (the review of 2026-10-17: the
    # fixture had "yes", which the portal never writes, so real location grants were never found)
    out = ("devices\tcamera\torg.gnome.Snapshot\tyes\t\n"
           "background\tbackground\torg.mozilla.firefox\tyes\t0x00\n"
           "location\tlocation\torg.gnome.Weather\tEXACT,1792247823\t0x0\n"
           "location\tlocation\torg.gnome.Maps\tNONE,1792247000\t0x0\n"
           "devices\tmicrophone\torg.example.App\tno\t\n"
           "devices\tspeakers\torg.example.Music\tyes\t\n")      # playing sound grants nothing private
    host = make_host(tmp_path, commands={"flatpak permissions": out})
    o = detect(cat, "sbx.portal_permissions", make_scan(host))
    assert o.status is Status.FAIL and ev(o) == {"org.gnome.Snapshot": "camera", "org.gnome.Weather": "location"}


def test_snap(cat, tmp_path):
    out = ("Name      Version   Rev    Tracking       Publisher   Notes\n"
           "firefox   130.0     4793   latest/stable  mozilla**   -\n"
           "firefox   129.0     4650   latest/stable  mozilla**   disabled\n"
           "code      1.93      170    latest/stable  vscode**    classic\n")
    host = make_host(tmp_path, commands={"snap list --all": out})
    o = detect(cat, "sbx.snap", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Disabled (retained) revisions"] == 1 and o.notes


# ------------------------------------------------------------------ kernel

def _severity(cat, check_id, o):
    from daprivacyscanner.catalogue import CONTEXT_KEYS, effective_severity

    return effective_severity(cat[check_id], {**{k: None for k in CONTEXT_KEYS}, **o.findings})


def _kernels(running, *installed, arch=False):
    """/proc and /usr/lib/modules (+ /boot on Debian-likes) with these kernels installed."""
    files = {"/proc/sys/kernel/osrelease": running + "\n"}
    for k in installed:
        files[f"/usr/lib/modules/{k}/modules.dep"] = ""
        files[f"/usr/lib/modules/{k}/vmlinuz" if arch else f"/boot/vmlinuz-{k}"] = ""
    return files


def test_updates_apt(cat, tmp_path):
    out = ("Listing...\nlibssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]\n"
           "firefox/noble-updates 130.0 amd64 [upgradable from: 129.0]\n")
    host = make_host(tmp_path, commands={"apt list --upgradable": out},
                     files={"/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";\n',
                            **_kernels("6.8.0-45-generic", "6.8.0-45-generic")})
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.FAIL and o.summary == "1 security update is waiting to be installed (2 updates in all)."
    assert ev(o)["Automatic security updates"] == "on" and o.notes[0].kind == "limitation"
    assert _severity(cat, "kern.updates", o).value == 6


def test_updates_count_firmware_on_real_hardware_only(cat, tmp_path):
    from test_guides import build
    fw = ('Idle\n{"Devices": [{"Name": "System Firmware", "Releases": [{"Version": "1.2"}]},'
          ' {"Name": "UEFI dbx", "Releases": [{"Version": "371"}]}, {"Name": "Dock", "Releases": []}]}')
    cmds = {"apt list --upgradable": "Listing...\n",
            "fwupdmgr get-updates --json --no-metadata-check --no-unreported-check --no-reboot-check": fw}
    host = make_host(tmp_path, commands=cmds, files=_kernels("6.8.0-45-generic", "6.8.0-45-generic"))
    o = detect(cat, "kern.updates", make_scan(host, virtualization="none"))
    assert o.status is Status.WARN and ev(o)["Firmware updates"] == "System Firmware, UEFI dbx"
    assert o.summary == ("2 updates are waiting to be installed. None is marked as a security fix. 2 of them are "
                         "firmware, which the system's updater may not install.")
    g = build(cat, host, "kern.updates", virtualization="none")
    assert "fwupdmgr update" in next(s for s in g.steps if s.title == "Install the firmware updates").commands
    # a virtual machine has no firmware of its own; nothing waiting, or an answer that isn't JSON, adds nothing
    assert detect(cat, "kern.updates", make_scan(host, virtualization="vm")).status is Status.PASS
    for out in ('{"Devices": []}', "No updates available"):
        cmds["fwupdmgr get-updates --json --no-metadata-check --no-unreported-check --no-reboot-check"] = out
        host = make_host(tmp_path / out[:3].strip('{"'), commands=cmds, files=_kernels("6.8.0-45-generic", "6.8.0-45-generic"))
        assert detect(cat, "kern.updates", make_scan(host, virtualization="none")).status is Status.PASS


# ------------------------------------------------------------------ the release's end of support

UBUNTU_CSV = ("version,codename,series,created,release,eol,eol-server,eol-esm,eol-legacy\n"
              "20.04 LTS,Focal Fossa,focal,2019-10-17,2020-04-23,2025-05-29,2025-05-29,2030-04-23,2035-04-26\n"
              "24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-05-31,2029-05-31,2034-04-25,2039-04-28\n"
              "25.04,Plucky Puffin,plucky,2024-10-10,2025-04-17,2026-01-15\n")
DEBIAN_CSV = ("version,codename,series,created,release,eol,eol-lts,eol-elts\n"
              "11,Bullseye,bullseye,2019-07-06,2021-08-14,2024-08-14,2026-08-31,2031-06-30\n"
              "13,Trixie,trixie,2023-06-10,2025-08-09,2028-08-09,2030-06-30,2035-06-30\n"
              "14,Forky,forky,2025-08-09\n,Sid,sid,1993-08-16\n")
OS = {"mint": 'NAME="Linux Mint"\nID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 22.3"\n'
              'VERSION_ID="22.3"\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=noble\n',
      "mint20": 'ID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 20.3"\nVERSION_ID="20.3"\n'
                "VERSION_CODENAME=una\nUBUNTU_CODENAME=focal\n",
      "focal": 'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\nVERSION_ID="20.04"\n'
               "VERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n",
      "bullseye": 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nVERSION_ID="11"\nVERSION_CODENAME=bullseye\n',
      "forky": 'ID=debian\nPRETTY_NAME="Debian GNU/Linux forky/sid"\nVERSION_CODENAME=forky\n',
      "fedora": 'ID=fedora\nPRETTY_NAME="Fedora Linux 43 (Workstation Edition)"\nVERSION_ID=43\nSUPPORT_END=2026-12-02\n',
      "cachyos": 'ID=cachyos\nID_LIKE=arch\nPRETTY_NAME="CachyOS"\nBUILD_ID=rolling\n',
      "leap": 'ID="opensuse-leap"\nID_LIKE="suse opensuse"\nPRETTY_NAME="openSUSE Leap 15.6"\nVERSION_ID="15.6"\n'}
DISTRO_INFO = {"/usr/share/distro-info/ubuntu.csv": UBUNTU_CSV, "/usr/share/distro-info/debian.csv": DEBIAN_CSV}


def _release(cat, tmp_path, monkeypatch, name, today, files=None, info=True):
    import datetime as dt
    from daprivacyscanner.checks import kernel

    monkeypatch.setattr(kernel, "_today", lambda: dt.date.fromisoformat(today))
    host = make_host(tmp_path, files={"/etc/os-release": OS[name], **(DISTRO_INFO if info else {}), **(files or {})})
    return detect(cat, "kern.release_unsupported", make_scan(host)), host


def test_release_supported_names_what_it_is_built_on(cat, tmp_path, monkeypatch):
    o, _ = _release(cat, tmp_path, monkeypatch, "mint", "2026-10-12")
    assert o.status is Status.PASS and "gets security updates until 31 May 2029" in o.summary
    assert ev(o)["Built on"] == "Ubuntu 24.04 LTS" and ev(o)["Read from"] == "/usr/share/distro-info/ubuntu.csv"
    assert "Ubuntu Pro's updates until" not in ev(o)            # Pro is for Ubuntu itself


@pytest.mark.parametrize("name, today, status, text", [
    ("mint20", "2026-10-12", Status.FAIL, "Ubuntu 20.04 LTS stopped getting security updates on 29 May 2025"),
    ("focal", "2026-10-12", Status.FAIL, "stopped getting security updates on 29 May 2025"),
    ("focal", "2031-01-01", Status.FAIL, "stopped getting security updates"),          # Pro's own end has passed too
    ("bullseye", "2026-01-01", Status.WARN, "Long Term Support"),
    ("bullseye", "2026-10-12", Status.FAIL, "stopped getting security updates on 14 August 2024"),
    ("fedora", "2026-10-12", Status.WARN, "on 2 December 2026, in 51 days"),
    ("fedora", "2026-12-02", Status.WARN, "stops getting security updates today"),
    ("fedora", "2026-12-03", Status.FAIL, "stopped getting security updates on 2 December 2026"),
    ("fedora", "2026-06-01", Status.PASS, "until 2 December 2026"),
    ("cachyos", "2026-10-12", Status.NOT_APPLICABLE, "rolling release"),
    ("forky", "2026-10-12", Status.NOT_APPLICABLE, "development release"),
    ("leap", "2026-10-12", Status.UNKNOWN, "Nothing on this computer says"),
])
def test_release_end_of_support(cat, tmp_path, monkeypatch, name, today, status, text):
    o, _ = _release(cat, tmp_path, monkeypatch, name, today)
    assert o.status is status and text in o.summary, o.summary


def test_release_unsupported_is_never_a_pass_without_the_dates(cat, tmp_path, monkeypatch):
    o, _ = _release(cat, tmp_path, monkeypatch, "focal", "2026-10-12", info=False)
    assert o.status is Status.UNKNOWN and "sudo apt install distro-info-data, then scan again" in o.summary
    o, _ = _release(cat, tmp_path / "b", monkeypatch, "focal", "2026-10-12",
                    files={"/usr/share/distro-info/ubuntu.csv": UBUNTU_CSV.replace("focal", "other")})
    assert o.status is Status.UNKNOWN and "doesn't list this release" in o.summary


def test_release_ubuntu_pro_counts_for_ubuntu_only(cat, tmp_path, monkeypatch):
    esm = {"/etc/apt/sources.list.d/ubuntu-esm-infra.sources": "Types: deb\n"}
    o, _ = _release(cat, tmp_path, monkeypatch, "focal", "2026-10-12", files=esm)
    assert o.status is Status.PASS and "Ubuntu Pro's security updates instead, until 23 April 2030" in o.summary
    plain, _ = _release(cat, tmp_path / "b", monkeypatch, "focal", "2026-10-12")
    assert plain.status is Status.FAIL and plain.notes[0].title == "Ubuntu Pro would extend it"
    mint, _ = _release(cat, tmp_path / "c", monkeypatch, "mint20", "2026-10-12", files=esm)
    assert mint.status is Status.FAIL and not mint.notes
    assert _severity(cat, "kern.release_unsupported", plain).value == 8


def test_updates_nothing_waiting_is_no_pass_on_an_unsupported_release(cat, tmp_path, monkeypatch):
    import datetime as dt
    from daprivacyscanner.checks import kernel

    monkeypatch.setattr(kernel, "_today", lambda: dt.date(2026, 10, 12))
    files = {"/etc/os-release": OS["mint20"], **DISTRO_INFO, **_kernels("5.4.0-200-generic", "5.4.0-200-generic")}
    host = make_host(tmp_path, commands={"apt list --upgradable": "Listing...\n"}, files=files)
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.UNKNOWN and "Ubuntu 20.04 LTS stopped getting security updates on 29 May 2025" in o.summary
    out = "Listing...\nfirefox/focal-updates 130.0 amd64 [upgradable from: 129.0]\n"
    host = make_host(tmp_path / "b", commands={"apt list --upgradable": out}, files=files)
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.WARN and o.notes[-1].related == ("kern.release_unsupported",)
    # a supported release passes as before
    files["/etc/os-release"] = OS["mint"]
    host = make_host(tmp_path / "c", commands={"apt list --upgradable": "Listing...\n"}, files=files)
    assert detect(cat, "kern.updates", make_scan(host)).status is Status.PASS


@pytest.mark.parametrize("confs, on", [
    ({"20auto-upgrades": '"0"', "52daprivacyscanner-auto-upgrades": '"1"'}, True),     # the app's own drop-in counts
    ({"20auto-upgrades": '"1"', "99local": '"0"'}, False),                              # the last file read wins
    ({}, False),
])
def test_updates_apt_automatic_setting_as_apt_reads_it(cat, tmp_path, confs, on):
    files = {f"/etc/apt/apt.conf.d/{name}": f"APT::Periodic::Unattended-Upgrade {v};\n" for name, v in confs.items()}
    host = make_host(tmp_path, commands={"apt list --upgradable": "Listing...\n"},
                     files={**files, **_kernels("6.8.0-45-generic", "6.8.0-45-generic")}, installed=["apt"])
    assert ev(detect(cat, "kern.updates", make_scan(host)))["Automatic security updates"] == ("on" if on else "off")


def test_updates_ordinary_ones_are_low(cat, tmp_path):
    """mpv a version behind is not a security update: worth installing, rarely urgent."""
    out = "Listing...\nmpv/noble-updates 0.38.0-1ubuntu1 amd64 [upgradable from: 0.37.0-1]\n"
    host = make_host(tmp_path, commands={"apt list --upgradable": out}, files=_kernels("6.8.0-45-generic", "6.8.0-45-generic"))
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.WARN and "None is marked as a security fix" in o.summary
    sev = _severity(cat, "kern.updates", o)
    assert sev.value == 2 and not sev.uncertain_on


def test_updates_kernel_package_is_highest(cat, tmp_path):
    out = ("Listing...\nlinux-generic/noble-updates 6.8.0.47.47 amd64 [upgradable from: 6.8.0.45.45]\n"
           "linux-image-generic/noble-updates 6.8.0.47.47 amd64 [upgradable from: 6.8.0.45.45]\n"
           "linux-headers-generic/noble-updates 6.8.0.47.47 amd64 [upgradable from: 6.8.0.45.45]\n"
           "mpv/noble-updates 0.38.0-1ubuntu1 amd64 [upgradable from: 0.37.0-1]\n")
    host = make_host(tmp_path, commands={"apt list --upgradable": out}, files=_kernels("6.8.0-45-generic", "6.8.0-45-generic"))
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.summary == "A kernel update is waiting to be installed (4 updates in all)."
    assert ev(o)["Kernel or microcode updates"] == "linux-generic, linux-image-generic"     # not the headers
    assert _severity(cat, "kern.updates", o).value == 7


def test_updates_new_kernel_installed_but_not_running(cat, tmp_path):
    host = make_host(tmp_path, commands={"apt list --upgradable": "Listing...\n"},
                     files=_kernels("6.8.0-45-generic", "6.8.0-45-generic", "6.8.0-47-generic", "6.8.0-49-lowlatency"))
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.FAIL and o.summary.startswith("A newer kernel is installed than the one running")
    assert ev(o)["Newest installed kernel"] == "6.8.0-47-generic"      # the same build, not the lowlatency one
    assert _severity(cat, "kern.updates", o).value == 7


def test_updates_arch_kernel_replaced_in_place(cat, tmp_path):
    """pacman replaces the kernel: the running one's modules are gone until a restart. pacman marks
    nothing as a security fix, so the severity says it could be higher."""
    host = make_host(tmp_path, installed=["pacman"], commands={"pacman -Qu": CommandResult((), 0, "mpv 1:0.38-1 -> 1:0.39-1\n")},
                     files=_kernels("6.10.1-arch1-1", "6.10.2-arch1-1", arch=True))
    o = detect(cat, "kern.updates", make_scan(host))
    assert ev(o)["Its modules"].startswith("gone") and _severity(cat, "kern.updates", o).value == 7
    host = make_host(tmp_path / "b", installed=["pacman"], commands={"pacman -Qu": CommandResult((), 0, "mpv 1:0.38-1 -> 1:0.39-1\n")},
                     files=_kernels("6.10.2-arch1-1", "6.10.2-arch1-1", arch=True))
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.status is Status.WARN and "pacman doesn't say" in o.summary
    sev = _severity(cat, "kern.updates", o)
    assert sev.value == 2 and sev.uncertain_on == ("security_updates_pending",)


def test_updates_in_a_container_ignore_the_kernel(cat, tmp_path):
    host = make_host(tmp_path, commands={"apt list --upgradable": "Listing...\n"},
                     files=_kernels("6.8.0-45-generic", "6.8.0-47-generic"))
    o = detect(cat, "kern.updates", make_scan(host, virtualization="container"))
    assert o.status is Status.PASS and o.findings["kernel_restart_pending"] is False


def test_updates_dnf_cache_only(cat, tmp_path):
    host = make_host(tmp_path, commands={
        ("dnf", "-C", "-q", "check-update"): CommandResult((), 100, "\nkernel.x86_64    6.11.4-301.fc41    updates\n"),
        ("dnf", "-C", "-q", "updateinfo", "list", "--security"): "FEDORA-2024-1a2b Important/Sec. kernel-6.11.4-301.fc41.x86_64\n"},
        files=_kernels("6.11.3-300.fc41.x86_64", "6.11.3-300.fc41.x86_64"))
    o = detect(cat, "kern.updates", make_scan(host))
    assert o.summary == "A kernel update is waiting to be installed (marked as a security fix)."
    assert ev(o)["Security updates"] == 1
    assert ("dnf", "check-update") not in host.runner.calls             # never refreshes metadata online


@pytest.mark.parametrize("name, kernel", [
    ("linux-image-amd64", True), ("linux-generic-hwe-24.04", True), ("linux-modules-extra-6.8.0-47-generic", True),
    ("linux", True), ("linux-lts", True), ("linux-cachyos", True), ("linux-cachyos-headers", False),
    ("kernel-core", True), ("kernel-default", True), ("intel-microcode", True), ("amd-ucode", True),
    ("linux-firmware", False), ("linux-libc-dev", False), ("linux-headers-generic", False), ("linux-api-headers", False),
    ("linux-tools-common", False), ("kernelshark", False), ("mpv", False)])
def test_kernel_packages(name, kernel):
    from daprivacyscanner.checks.kernel import KERNEL_PACKAGE

    assert bool(KERNEL_PACKAGE.match(name)) is kernel


@pytest.mark.parametrize("value, status", [("0", Status.FAIL), ("1", Status.PASS), (None, Status.FAIL)])
def test_ptrace(cat, tmp_path, value, status):
    files = {"/proc/sys/kernel/yama/ptrace_scope": value} if value else {}
    assert detect(cat, "kern.ptrace_scope", make_scan(make_host(tmp_path, files=files))).status is status


def test_init_on_free_from_cmdline_and_config(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/cmdline": "ro init_on_free=1", "/proc/sys/kernel/osrelease": "6.8.0-45\n"})
    assert detect(cat, "kern.init_on_free", make_scan(host)).status is Status.PASS
    host = make_host(tmp_path / "b", files={"/proc/cmdline": "ro quiet", "/proc/sys/kernel/osrelease": "6.8.0-45\n",
                                            "/boot/config-6.8.0-45": "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\n"
                                                                     "# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"})
    assert detect(cat, "kern.init_on_free", make_scan(host)).status is Status.FAIL
    assert detect(cat, "kern.init_on_alloc", make_scan(host)).status is Status.PASS


def test_kernel_config_gz(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/cmdline": "ro"})
    with gzip.open(host.sys_path("/proc/config.gz"), "wt") as f:
        f.write("CONFIG_INIT_ON_FREE_DEFAULT_ON=y\n")
    assert detect(cat, "kern.init_on_free", make_scan(host)).status is Status.PASS


def test_suspend(cat, tmp_path):
    host = make_host(tmp_path, files={"/sys/power/state": "freeze mem disk\n"})
    assert detect(cat, "kern.suspend_keys_in_ram", make_scan(host)).status is Status.FAIL


@pytest.mark.parametrize("security, protection, iommu, status", [
    ("user", "1", True, Status.PASS), ("none", "0", False, Status.FAIL), ("user", "0", False, Status.FAIL),
])
def test_dma(cat, tmp_path, security, protection, iommu, status):
    files = {"/sys/bus/thunderbolt/devices/domain0/security": security + "\n",
             "/sys/bus/thunderbolt/devices/domain0/iommu_dma_protection": protection + "\n"}
    if iommu:
        files["/sys/class/iommu/dmar0/uevent"] = ""
    assert detect(cat, "kern.dma", make_scan(make_host(tmp_path, files=files))).status is status
    assert detect(cat, "kern.dma", make_scan(make_host(tmp_path / "n"))).status is Status.NOT_APPLICABLE


def test_init_on_alloc_note_says_what_turned_it_off(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/cmdline": "ro quiet init_on_alloc=0"})
    o = detect(cat, "kern.init_on_alloc", make_scan(host))
    assert o.status is Status.FAIL and "boot option turns it off (init_on_alloc=0)" in o.notes[0].text
    host = make_host(tmp_path / "b", files={"/proc/cmdline": "ro", "/proc/sys/kernel/osrelease": "6.8.0\n",
                                            "/boot/config-6.8.0": "# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set\n"})
    assert "built with CONFIG_INIT_ON_ALLOC_DEFAULT_ON off" in detect(cat, "kern.init_on_alloc", make_scan(host)).notes[0].text


# ------------------------------------------------------------------ kernel log, /proc, memory encryption, lockdown

GROUPS = "adm:x:4:syslog,alice\nsudo:x:27:alice\n"


def test_dmesg_restrict(cat, tmp_path):
    host = make_host(tmp_path, files={"/proc/sys/kernel/dmesg_restrict": "0\n", "/etc/group": GROUPS}, env={"USER": "alice"})
    o = detect(cat, "kern.dmesg_restrict", make_scan(host))
    assert o.status is Status.FAIL and o.notes[0].title == "You can read it through the journal anyway"
    host = make_host(tmp_path / "b", files={"/proc/sys/kernel/dmesg_restrict": "1\n"})
    assert detect(cat, "kern.dmesg_restrict", make_scan(host)).status is Status.PASS


def test_dmesg_restrict_fix_applies_and_reverts(cat, tmp_path, monkeypatch):
    from daprivacyscanner import helper
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.fix import apply_plan, revert_entry
    from daprivacyscanner.privileged import FakePrivileged
    from daprivacyscanner.undo import UndoLog
    from fakes import FakeSystem

    host = make_host(tmp_path, files={"/proc/sys/kernel/dmesg_restrict": "0\n"})
    monkeypatch.setattr(helper, "ROOT", str(host.root))
    monkeypatch.setattr(helper, "RUN", FakeSystem())
    host.privileged = FakePrivileged()
    check = load_all()["kern.dmesg_restrict"](cat["kern.dmesg_restrict"])
    scan = make_scan(host)
    plan = check.plan_fix(scan, check.detect(scan))
    log = UndoLog(host.home / "undo")
    res = apply_plan(plan, host, log)
    assert res.ok and check.detect(make_scan(host)).status is Status.PASS
    assert (host.root / "etc/sysctl.d/60-daprivacyscanner-dmesg.conf").read_text().endswith("kernel.dmesg_restrict = 1\n")
    assert all(r.ok for r in revert_entry(log.get(res.entry_id), host, log))
    assert check.detect(make_scan(host)).status is Status.FAIL
    assert not (host.root / "etc/sysctl.d/60-daprivacyscanner-dmesg.conf").exists()


@pytest.mark.parametrize("options, status", [
    ("rw,nosuid,nodev,noexec,relatime", Status.FAIL),
    ("rw,nosuid,nodev,noexec,relatime,hidepid=invisible,gid=26", Status.PASS),
    ("rw,relatime,hidepid=2", Status.PASS),
])
def test_proc_hidepid(cat, tmp_path, options, status):
    host = make_host(tmp_path, files={"/proc/mounts": f"proc /proc proc {options} 0 0\n"})
    assert detect(cat, "kern.proc_hidepid", make_scan(host)).status is status


def test_proc_hidepid_only_matters_with_other_accounts(cat):
    from daprivacyscanner.catalogue import effective_severity
    assert effective_severity(cat["kern.proc_hidepid"], {"multi_user": False}).value == 0
    assert effective_severity(cat["kern.proc_hidepid"], {"multi_user": True}).value == 4


def _sleepy(tmp_path, cpu_flags, cmdline="ro quiet", **kw):
    return make_host(tmp_path, files={"/sys/power/state": "freeze mem disk\n", "/proc/cmdline": cmdline,
                                      "/proc/cpuinfo": f"processor\t: 0\nflags\t\t: fpu sse2 {cpu_flags}\n"}, **kw)


def test_memory_encryption_notes(cat, tmp_path):
    def notes(host, **ctx):
        return {n.title: n for n in detect(cat, "kern.suspend_keys_in_ram", make_scan(host, **ctx)).notes}
    off = notes(_sleepy(tmp_path / "a", "sme", "ro mem_encrypt=off"))
    assert "This CPU can encrypt memory, but AMD SME is off" in off
    assert "mem_encrypt=on" in off["This CPU can encrypt memory, but AMD SME is off"].text
    assert "Memory is encrypted (AMD SME)" in notes(_sleepy(tmp_path / "b", "sme", "ro mem_encrypt=on"))
    tme = _sleepy(tmp_path / "c", "tme", commands={"dmesg": "[0.0] x86/tme: enabled by BIOS\n"})
    assert "Memory is encrypted (Intel TME)" in notes(tme)
    assert "This CPU can encrypt memory (Intel TME)" in notes(_sleepy(tmp_path / "d", "tme"))   # log unreadable
    assert len(notes(_sleepy(tmp_path / "e", ""))) == 1                                          # no support: no note
    assert len(notes(_sleepy(tmp_path / "f", "sme"), virtualization="vm")) == 1                 # the host's matters


def test_dma_note_says_memory_encryption_is_no_substitute(cat, tmp_path):
    host = _sleepy(tmp_path, "tme")
    d = host.root / "sys/bus/thunderbolt/devices/domain0"
    d.mkdir(parents=True)
    (d / "security").write_text("none\n")
    o = detect(cat, "kern.dma", make_scan(host))
    assert o.status is Status.FAIL and o.notes[0].title == "Memory encryption (Intel TME) doesn't stop this"


@pytest.mark.parametrize("lockdown, titles", [
    ("[none] integrity confidentiality\n", []),                 # the norm: nothing to say
    ("none [integrity] confidentiality\n", []),
    ("none integrity [confidentiality]\n", ["Kernel lockdown is on"]),
])
def test_lockdown_note_on_the_secure_boot_check(cat, tmp_path, lockdown, titles):
    from conftest import lsblk
    host = make_host(tmp_path, files={"/sys/kernel/security/lockdown": lockdown},
                     commands={("mokutil", "--sb-state"): "SecureBoot enabled\n"})
    (host.root / "sys/firmware/efi").mkdir(parents=True)
    o = detect(cat, "enc.boot_no_secureboot", make_scan(host, devices=lsblk("ubuntu-24.04-luks-lvm.json")))
    assert [n.title for n in o.notes if n.kind == "info"] == titles


@pytest.mark.parametrize("files, status, says", [
    ({"/proc/sys/kernel/osrelease": "6.14.0-29-generic\n",
      "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n"}, Status.PASS, "Landlock"),
    ({"/proc/sys/kernel/osrelease": "6.8.0-45-generic\n",
      "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n"}, Status.FAIL, "6.12"),
    ({"/proc/sys/kernel/osrelease": "6.12.9-amd64\n", "/sys/kernel/security/lsm": "capability,yama,apparmor\n",
      "/boot/config-6.12.9-amd64": "CONFIG_SECURITY_LANDLOCK=y\n"}, Status.FAIL, "not turned on at boot"),
    ({"/proc/sys/kernel/osrelease": "6.12.9-custom\n", "/sys/kernel/security/lsm": "capability,yama\n",
      "/boot/config-6.12.9-custom": "# CONFIG_SECURITY_LANDLOCK is not set\n"}, Status.FAIL, "no Landlock"),
    ({"/proc/sys/kernel/osrelease": "6.12.9\n"}, Status.UNKNOWN, "Couldn't tell"),
])
def test_landlock(cat, tmp_path, files, status, says):
    o = detect(cat, "kern.landlock", make_scan(make_host(tmp_path, files=files)))
    assert o.status is status and says in o.summary
    assert detect(cat, "kern.landlock", make_scan(make_host(tmp_path / "c", files=files),
                                                   virtualization="container")).status is Status.NOT_APPLICABLE
