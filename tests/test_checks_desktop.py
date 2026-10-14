import os
import sqlite3

import pytest

from daprivacyscanner.context import ContextValue
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status

from conftest import detect, ev, lsblk, make_host, make_scan
from test_checks_telemetry_browser import png

FEDORA = lsblk("fedora-40-btrfs-luks.json")      # has a USB stick at /run/media/alice/STICK


def thumbs(home, *uris):
    d = home / ".cache/thumbnails/large"
    d.mkdir(parents=True, exist_ok=True)
    for i, u in enumerate(uris):
        (d / f"{i}.png").write_bytes(png(u))


def test_thumbnails_of_removable_drives_raise_severity(cat, tmp_path):
    host = make_host(tmp_path, home_files={"photo.jpg": "x"})
    thumbs(host.home, (host.home / "photo.jpg").as_uri(), "file:///run/media/alice/STICK/secret%20plan.png",
           "file:///run/media/alice/STICK/b.png")
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=FEDORA))
    assert o.status is Status.FAIL and o.findings["thumbnails_reference_removable_or_container"] is True
    assert ev(o)["Of files on removable drives or other encrypted volumes"] == 2
    assert ev(o)["From"] == "/run/media/alice/STICK"


def _devs(*children):
    import json
    from daprivacyscanner import blockdev
    return blockdev.parse_lsblk(json.dumps({"blockdevices": [
        {"name": "nvme0n1", "type": "disk", "tran": "nvme", "children": [
            {"name": "nvme0n1p2", "type": "part", "fstype": "ext4", "mountpoints": ["/"]}]},
        {"name": "sda", "type": "disk", "tran": "sata", "hotplug": True, "children": list(children)}]}))


@pytest.mark.parametrize("child, crypttab, sensitive", [
    # an internal drive, plain or unlocked at boot with the system: as protected as the cache
    ({"name": "sda1", "type": "part", "fstype": "ext4", "mountpoints": ["/mnt/data"]}, "", False),
    ({"name": "sda1", "type": "part", "fstype": "crypto_LUKS", "children": [
        {"name": "data", "type": "crypt", "fstype": "ext4", "mountpoints": ["/mnt/data"]}]},
     "data UUID=1 none luks\n", False),
    # an encrypted volume opened on demand: its pictures shouldn't be readable outside it
    ({"name": "sda1", "type": "part", "fstype": "crypto_LUKS", "children": [
        {"name": "data", "type": "crypt", "fstype": "ext4", "mountpoints": ["/mnt/data"]}]},
     "data UUID=1 none luks,noauto\n", True),
])
def test_thumbnails_of_internal_drives(cat, tmp_path, child, crypttab, sensitive):
    host = make_host(tmp_path, files={"/etc/crypttab": crypttab, "/proc/mounts": "/dev/sda1 /mnt/data ext4 rw 0 0\n"})
    thumbs(host.home, "file:///mnt/data/photos/a.jpg")
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=_devs(child)))
    assert o.findings["thumbnails_reference_removable_or_container"] is sensitive


def test_thumbnails_from_a_drive_that_is_gone(cat, tmp_path):
    """Nothing is mounted where the picture was: the drive it came from has been unplugged."""
    host = make_host(tmp_path, files={"/proc/mounts": "/dev/nvme0n1p2 / ext4 rw 0 0\n"})
    thumbs(host.home, "file:///media/alice/OLDSTICK/x.jpg")
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=_devs()))
    assert o.findings["thumbnails_reference_removable_or_container"] is True and ev(o)["From"] == "/media/alice/OLDSTICK"


def test_thumbnails_of_deleted_files(cat, tmp_path):
    host = make_host(tmp_path)
    thumbs(host.home, (host.home / "gone.jpg").as_uri())
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=FEDORA))
    assert o.status is Status.FAIL and o.findings["thumbnails_reference_removable_or_container"] is False


def test_thumbnails_in_flatpak_caches(cat, tmp_path):
    host = make_host(tmp_path)
    thumbs(host.home)
    d = host.home / ".var/app/org.gnome.Loupe/cache/thumbnails/normal"
    d.mkdir(parents=True)
    (d / "x.png").write_bytes(png("file:///media/alice/USB/x.jpg"))
    assert detect(cat, "desk.thumbnails", make_scan(host, devices=[])).findings[
        "thumbnails_reference_removable_or_container"]


def test_thumbnails_in_memory_but_flatpak_caches_on_disk(cat, tmp_path):
    """The desktop's cache in memory doesn't cover the caches Flatpak apps keep for themselves: a leak
    there is still a finding, not "gone at the next reboot"."""
    host = make_host(tmp_path)
    cache = host.home / ".cache/thumbnails"
    (host.root / "proc").mkdir(exist_ok=True)
    (host.root / "proc/mounts").write_text(f"tmpfs {cache} tmpfs rw,size=200m 0 0\n")
    thumbs(host.home, "file:///media/alice/USB/in-memory.jpg")
    d = host.home / ".var/app/org.gnome.Loupe/cache/thumbnails/normal"
    d.mkdir(parents=True)
    (d / "x.png").write_bytes(png("file:///media/alice/USB/x.jpg"))
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=[]))
    assert o.status is Status.FAIL and "apps' own caches" in o.summary
    assert o.findings["thumbnails_reference_removable_or_container"] is True
    assert ev(o)["Of those, in apps' own caches on the disk"] == 1
    (d / "x.png").write_bytes(png((host.home / "here.jpg").as_uri()))
    (host.home / "here.jpg").write_text("x")
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=[]))
    assert o.status is Status.PASS and "would leak, but the cache is in memory" in o.summary
    assert any(n.title == "Apps' own thumbnail caches are on the disk" for n in o.notes)


def test_no_thumbnails_yet_on_a_new_install(cat, tmp_path):
    """Nothing leaks yet, but the cache is on disk: a low warning, so it can be kept in memory
    before the first USB stick is browsed."""
    o = detect(cat, "desk.thumbnails", make_scan(make_host(tmp_path)))
    assert o.status is Status.WARN and o.summary.startswith("Nothing leaks now: no thumbnails are cached yet")
    assert "the next picture you download and delete" in o.summary and "Scan again later" in o.summary
    assert o.findings == {"thumbnails_reference_removable_or_container": False, "thumbnails_on_disk_none_leaking": True,
                          "thumbnails_expire": None}         # GNOME's maximum-age couldn't be read: not assumed
    assert detect(cat, "desk.thumbnails", make_scan(make_host(tmp_path / "s"), desktop=())).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("age, expire, severity", [(30, True, 1), (7, True, 1), (180, False, 3), (-1, False, 3)])
def test_thumbnails_deleted_within_30_days_are_the_lowest_warning(cat, tmp_path, age, expire, severity):
    """Kept on disk but deleted after at most 30 days: still a finding, the lowest; kept longer
    (GNOME's default is 180 days) or for ever, higher."""
    from daprivacyscanner.catalogue import as_warning, effective_severity
    host = make_host(tmp_path, commands={("gsettings", "list-recursively", "org.gnome.desktop.thumbnail-cache"):
                                         f"org.gnome.desktop.thumbnail-cache maximum-age {age}\n"})
    o = detect(cat, "desk.thumbnails", make_scan(host))
    assert o.status is Status.WARN and o.findings["thumbnails_expire"] is expire
    assert ("for up to 30 days" in o.summary) is expire
    spec = cat["desk.thumbnails"]
    assert as_warning(spec, effective_severity(spec, o.findings)).value == severity      # as the runner rates a warning


def test_thumbnails_that_dont_leak_are_still_on_disk(cat, tmp_path):
    host = make_host(tmp_path, home_files={"photo.jpg": "x"})
    thumbs(host.home, (host.home / "photo.jpg").as_uri())
    o = detect(cat, "desk.thumbnails", make_scan(host, devices=FEDORA))
    assert o.status is Status.WARN and o.findings["thumbnails_on_disk_none_leaking"] is True


def test_runner_applies_the_thumbnail_finding(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.runner import Runner
    from daprivacyscanner import blockdev
    from conftest import sample

    host = make_host(tmp_path, commands={("lsblk", "-J", "-o", blockdev.COLUMNS): sample("lsblk/fedora-40-btrfs-luks.json")})
    thumbs(host.home, "file:///run/media/alice/STICK/a.png")
    r = Runner(cat, host, {"desk.thumbnails": load_all()["desk.thumbnails"]}).scan(only=["desk.thumbnails"])
    assert r.results["desk.thumbnails"].effective_severity == 6         # 7, one lower on an encrypted disk


def test_thumbnail_guide_after_the_leaks_are_deleted(cat, tmp_path):
    """Once its first step deletes the leaking thumbnails, the check is a low warning (still on
    disk) and the guide still offers keeping the cache in memory."""
    from daprivacyscanner.runner import Runner
    from daprivacyscanner import blockdev
    from conftest import sample

    host = make_host(tmp_path, home_files={"photo.jpg": "x"},
                     commands={("lsblk", "-J", "-o", blockdev.COLUMNS): sample("lsblk/fedora-40-btrfs-luks.json")})
    thumbs(host.home, (host.home / "photo.jpg").as_uri(), (host.home / "gone.jpg").as_uri())
    result, g = Runner(cat, host).plan_fix("desk.thumbnails")
    assert result.status is Status.FAIL and result.effective_severity == 3 and g.steps[0].options   # 4, encrypted
    (host.home / ".cache/thumbnails/large/1.png").unlink()          # what the first step deletes
    result, g = Runner(cat, host).plan_fix("desk.thumbnails")
    assert result.status is Status.WARN and result.effective_severity == 2 and result.fixable     # 4 encrypted, a risk 2 lower
    assert [o.label for o in g.steps[0].options] == ["Delete every cached thumbnail"]
    assert g.steps[-1].title == "Keep the thumbnail cache in memory" and g.steps[-1].options


def test_a_guide_stays_open_once_its_check_passes(cat, tmp_path):
    """The page reloads a guide after each step it applies; a check that passes then (here Baloo
    indexing names only) still gives its guide, with what is left to do."""
    from daprivacyscanner.runner import Runner

    host = make_host(tmp_path, installed=["balooctl6"],
                     home_files={".config/baloofilerc": "[General]\nonly basic indexing=true\n"})
    host.environ["XDG_CURRENT_DESKTOP"] = "KDE"
    result, g = Runner(cat, host).plan_fix("desk.indexers")
    assert result.status is Status.PASS and not result.fixable
    assert g is not None and [o.label for s in g.steps for o in s.options] == ["Turn indexing off and delete the index"]


def test_recent_files(cat, tmp_path):
    host = make_host(tmp_path, home_files={
        ".local/share/recently-used.xbel": '<xbel><bookmark href="file:///a" /><bookmark href="file:///b&amp;c" /></xbel>',
        ".var/app/org.gnome.TextEditor/data/recently-used.xbel": '<xbel><bookmark href="file:///c"/></xbel>'})
    o = detect(cat, "desk.recent_files", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and o.summary.startswith("3 recently")
    assert detect(cat, "desk.recent_files", make_scan(make_host(tmp_path / "e"))).status is Status.PASS


def test_kde_activities(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/RecentDocuments/report.pdf.desktop": "[Desktop Entry]"})
    db = host.home / ".local/share/kactivitymanagerd/resources/database"
    db.parent.mkdir(parents=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE ResourceEvent (usedActivity TEXT, initiatingAgent TEXT, targettedResource TEXT)")
    con.execute("CREATE TABLE ResourceScoreCache (targettedResource TEXT)")
    con.executemany("INSERT INTO ResourceEvent VALUES ('a', 'okular', ?)", [("f1",), ("f2",)])
    con.commit(); con.close()
    o = detect(cat, "desk.kde_activities", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and ev(o)["Recorded file and app events"] == 2 and ev(o)["Recent documents"] == 1
    assert detect(cat, "desk.kde_activities", make_scan(make_host(tmp_path / "g"))).status is Status.NOT_APPLICABLE


def fde(value):
    return ContextValue("fde", value, [], "")


@pytest.mark.parametrize("rc, index, disk, status, unencrypted", [
    (None, False, "none", Status.WARN, True),        # KDE default: contents indexed, a copy on an unencrypted disk
    (None, False, "full", Status.WARN, False),       # encrypted, but searchable at once and outliving deleted files
    (None, False, "home", Status.WARN, False),
    (None, False, None, Status.WARN, None),          # unknown disk: the severity says it is uncertain
    ("[General]\nfolders[$e]=$HOME/,/run/media/alice/Stick/\n", False, "full", Status.FAIL, False),  # a drive's text
    ("[General]\nonly basic indexing=true\n", False, "none", Status.PASS, False),
    ("[Basic Settings]\nIndexing-Enabled=false\n", False, "none", Status.PASS, False),
    ("[Basic Settings]\nIndexing-Enabled=false\n", True, "none", Status.WARN, True),     # off, its index left behind
])
def test_baloo(cat, tmp_path, rc, index, disk, status, unencrypted):
    files = {".config/baloofilerc": rc} if rc else {}
    if index:
        files[".local/share/baloo/index"] = "x" * 100
    host = make_host(tmp_path, installed=["balooctl6"], home_files=files)
    o = detect(cat, "desk.indexers", make_scan(host, desktop=("kde",), plasma_major=6, fde=fde(disk)))
    assert o.status is status and o.findings["indexes_outside_home"] is (status is Status.FAIL)
    assert o.findings["index_on_unencrypted_disk"] is unencrypted


def test_localsearch(cat, tmp_path):
    host = make_host(tmp_path, commands={"localsearch status": "Currently indexed: 12,345 files, 678 folders\n"})
    o = detect(cat, "desk.indexers", make_scan(host, gnome_major=47, fde=fde("none")))
    assert o.status is Status.WARN and ev(o)["GNOME LocalSearch"].startswith("12,345 files")
    host.runner.outputs[("gsettings", "get", "org.freedesktop.Tracker3.Miner.Files", "index-removable-devices")] = \
        CommandResult((), 0, "true\n")
    o = detect(cat, "desk.indexers", make_scan(host, gnome_major=47, fde=fde("full")))
    assert o.status is Status.FAIL and ev(o)["Also indexes"] == "removable drives"
    assert detect(cat, "desk.indexers", make_scan(make_host(tmp_path / "n"))).status is Status.NOT_APPLICABLE


def test_localsearch_with_no_folders_indexes_nothing(cat, tmp_path):
    host = make_host(tmp_path, commands={"localsearch status": "Currently indexed: 0 files, 0 folders\n"})
    for key in ("index-recursive-directories", "index-single-directories"):
        host.runner.outputs[("gsettings", "get", "org.freedesktop.Tracker3.Miner.Files", key)] = CommandResult((), 0, "@as []\n")
    o = detect(cat, "desk.indexers", make_scan(host, gnome_major=47, fde=fde("none")))
    assert o.status is Status.PASS and ev(o)["GNOME LocalSearch"].startswith("no folders")


def test_localsearch_with_no_folders_but_files_still_indexed(cat, tmp_path):
    """Emptying the lists drops what was indexed (LocalSearch 3.11, tested); if files are still counted, they are
    left behind, not "indexes nothing"."""
    host = make_host(tmp_path, commands={"localsearch status": "Currently indexed: 2,869 files, 316 folders\n"})
    for key in ("index-recursive-directories", "index-single-directories"):
        host.runner.outputs[("gsettings", "get", "org.freedesktop.Tracker3.Miner.Files", key)] = CommandResult((), 0, "@as []\n")
    o = detect(cat, "desk.indexers", make_scan(host, gnome_major=47, fde=fde("none")))
    assert o.status is Status.WARN and o.summary.startswith("Indexing is off, but the index LocalSearch made")


def test_recoll(cat, tmp_path):
    host = make_host(tmp_path, home_files={".recoll/xapiandb/postlist.glass": "x" * 50})
    o = detect(cat, "desk.indexers", make_scan(host, fde=fde("full")))
    assert o.status is Status.WARN and "Recoll keeps a searchable copy" in o.summary
    (host.home / ".recoll/recoll.conf").write_text("topdirs = ~ /run/media/alice/Stick\n")
    o = detect(cat, "desk.indexers", make_scan(host, fde=fde("full")))
    assert o.status is Status.FAIL and ev(o)["Also indexes"] == "/run/media/alice/Stick"
    from test_guides import build, options, apply
    (host.home / ".config/autostart").mkdir(parents=True)
    auto = host.home / ".config/autostart/recollindex.desktop"
    auto.write_text("[Desktop Entry]\nExec=recollindex -m\n")
    apply(host, options(build(cat, host, "desk.indexers", fde=fde("full")))["Delete Recoll's index"])
    assert not (host.home / ".recoll/xapiandb/postlist.glass").exists() and "Hidden=true" in auto.read_text()
    assert detect(cat, "desk.indexers", make_scan(host, fde=fde("full"))).status is Status.NOT_APPLICABLE


KLIPPER_DB = {".local/share/klipper/history3.sqlite": "x", ".local/share/klipper/data/ab/ab": "copied"}


def clip(cat, host, **kw):
    return detect(cat, "desk.clipboard_history", make_scan(host, **kw))


def test_clipboard_plasma6_klipper_on_records_whatever_its_setting(cat, tmp_path):
    from fakes import APPLETSRC_6
    files = {".config/plasma-org.kde.plasma.desktop-appletsrc": APPLETSRC_6, **KLIPPER_DB}
    host = make_host(tmp_path, home_files=files)
    o = clip(cat, host, desktop=("kde",), plasma_major=6)
    assert o.status is Status.FAIL and ev(o)["Klipper"].startswith("on: what you copy is written to disk")
    # tested on Plasma 6.7.5: with this off, every copy still goes into its database while it runs
    (host.home / ".config/klipperrc").write_text("[General]\nKeepClipboardContents=false\n")
    assert clip(cat, host, desktop=("kde",), plasma_major=6).status is Status.FAIL
    # on a new install, before anything was copied: it will be
    host = make_host(tmp_path / "new", home_files={".config/plasma-org.kde.plasma.desktop-appletsrc": APPLETSRC_6})
    assert clip(cat, host, desktop=("kde",), plasma_major=6).status is Status.FAIL


def test_clipboard_klipper_off(cat, tmp_path):
    from fakes import APPLETSRC_6
    off = APPLETSRC_6.replace("org.kde.plasma.clipboard,", "").replace(
        "[Containments][23][Applets][28][Applets][31]\nimmutability=1\nplugin=org.kde.plasma.clipboard\n\n", "")
    host = make_host(tmp_path, home_files={".config/plasma-org.kde.plasma.desktop-appletsrc": off, **KLIPPER_DB})
    o = clip(cat, host, desktop=("kde",), plasma_major=6)
    assert o.status is Status.FAIL and ev(o)["Klipper"].startswith("off, but its old history is still on disk")
    for f in KLIPPER_DB:
        (host.home / f).unlink()
    assert clip(cat, host, desktop=("kde",), plasma_major=6).status is Status.PASS


def test_clipboard_plasma5_keeps_its_setting(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/klipper/history2.lst": "secret"}, files={"/proc/5/comm": "klipper\n"})
    assert clip(cat, host, desktop=("kde",), plasma_major=5).status is Status.FAIL
    (host.home / ".config").mkdir(exist_ok=True)
    (host.home / ".config/klipperrc").write_text("[General]\nKeepClipboardContents=false\n")
    (host.home / ".local/share/klipper/history2.lst").unlink()
    o = clip(cat, host, desktop=("kde",), plasma_major=5)
    assert o.status is Status.PASS and ev(o)["Klipper"] == "history isn't kept across sessions"
    host = make_host(tmp_path / "g", home_files={".cache/clipboard-indicator@tudmotu.com/registry.txt": "[]x"})
    assert clip(cat, host).status is Status.FAIL


def test_tray_applet():
    from daprivacyscanner.desktop import tray_applet
    from fakes import APPLETSRC_6
    assert tray_applet(APPLETSRC_6, "org.kde.plasma.clipboard").trays == ("28",)
    assert not tray_applet(APPLETSRC_6, "org.kde.plasma.weather").on
    plasma5 = ("[Containments][1][Applets][5]\nplugin=org.kde.plasma.systemtray\n\n"
               "[Containments][1][Applets][5][Configuration]\nSystrayContainmentId=8\n\n"
               "[Containments][8]\nplugin=org.kde.plasma.private.systemtray\n\n"
               "[Containments][8][Applets][9]\nplugin=org.kde.plasma.clipboard\n\n"
               "[Containments][8][General]\nextraItems=org.kde.plasma.clipboard\n")
    t = tray_applet(plasma5, "org.kde.plasma.clipboard")
    assert t.tray5 and not t.trays and not t.widget
    widget = "[Containments][1]\nplugin=org.kde.panel\n\n[Containments][1][Applets][3]\nplugin=org.kde.plasma.clipboard\n"
    assert tray_applet(widget, "org.kde.plasma.clipboard").widget


COPYQ_CONF = "[Options]\ntabs=&clipboard, Notes\n"


def test_clipboard_copyq(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": COPYQ_CONF})
    o = clip(cat, host)                                          # saves copies, though none yet
    assert o.status is Status.FAIL and ev(o)["CopyQ"] == 'saves what you copy to disk (its tab "&clipboard")'
    (host.home / ".config/copyq/copyq.conf").write_text(COPYQ_CONF + "\n[Tabs]\n1\\name=&clipboard\n1\\store_items=false\nsize=1\n")
    (host.home / ".config/copyq/copyq_tab_Tm90ZXM=.dat").write_text("my notes")     # the user's own tab
    o = clip(cat, host)
    assert o.status is Status.PASS and ev(o)["CopyQ"] == "keeps its history in memory only"
    (host.home / ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat").write_text("old")
    assert ev(clip(cat, host))["CopyQ"].startswith("keeps its history in memory, but its old file is still on disk")
    (host.home / ".config/copyq/copyq.conf").write_text("[Options]\nclipboard_tab=\n")  # stores nothing it is copied
    host = make_host(tmp_path / "f", home_files={
        ".var/app/com.github.hluk.copyq/config/copyq/copyq.conf": "[Options]\nclipboard_tab=\n"})
    o = clip(cat, host)
    assert o.status is Status.PASS and ev(o)["CopyQ (Flatpak)"] == "doesn't keep what you copy"


def test_clipboard_copyq_17_keeps_its_tabs_in_the_data_folder(cat, tmp_path):
    """CopyQ 17 moved the tab files from beside copyq.conf into its data folder: read in both places."""
    off = COPYQ_CONF + "\n[Tabs]\n1\\name=&clipboard\n1\\store_items=false\nsize=1\n"
    host = make_host(tmp_path, home_files={".config/copyq/copyq.conf": off,
                                           ".local/share/copyq/copyq/copyq_tab_Tm90ZXM=.dat": "my notes"})
    o = clip(cat, host)
    assert o.status is Status.PASS and ev(o)["CopyQ"] == "keeps its history in memory only"
    # while it runs, a tab that isn't stored has a file with a count of no items: not history (CopyQ 16 and 17)
    tab = host.home / ".local/share/copyq/copyq/copyq_tab_JmNsaXBib2FyZA==.dat"
    tab.write_bytes(b"\0\0\0\0")
    (host.home / ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat").write_bytes(b"\0\0\0\0")
    o = clip(cat, host)
    assert o.status is Status.PASS and ev(o)["CopyQ"] == "keeps its history in memory only"
    (host.home / ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat").unlink()
    tab.write_text("old history")
    o = clip(cat, host)
    assert o.status is not Status.PASS and "its old file is still on disk (11 bytes)" in ev(o)["CopyQ"]
    (host.home / ".config/copyq/copyq_tab_JmNsaXBib2FyZA==.dat").write_text("older")    # one a move left behind
    assert "(16 bytes)" in ev(clip(cat, host))["CopyQ"]
    flat = make_host(tmp_path / "f", home_files={
        ".var/app/com.github.hluk.copyq/config/copyq/copyq.conf": COPYQ_CONF,
        ".var/app/com.github.hluk.copyq/data/copyq/copyq/copyq_tab_JmNsaXBib2FyZA==.dat": "copied"})
    assert ev(clip(cat, flat))["CopyQ (Flatpak)"] == 'saves what you copy to disk (its tab "&clipboard"), 6 bytes so far'


def test_copyq_clipboard_tab_and_file():
    from pathlib import Path
    from daprivacyscanner import ini
    from daprivacyscanner.checks.desktop import copyq_clipboard_tab, copyq_tab_file
    assert ini.qsettings_list('&clipboard, "a, b", Notes') == ["&clipboard", "a, b", "Notes"]
    assert copyq_clipboard_tab(ini.parse("[Options]\ntabs=&vágólap, Jegyzetek\n")) == "&vágólap"   # its language's
    assert copyq_clipboard_tab(ini.parse("[Options]\ntabs=Notes, &clipboard\n")) == "&clipboard"
    assert copyq_tab_file(Path("/c"), "&clipboard").name == "copyq_tab_JmNsaXBib2FyZA==.dat"         # as CopyQ 16 named it
    assert "/" not in copyq_tab_file(Path("/c"), "??>").name[len("copyq_tab_"):]


def test_zeitgeist_and_gvfs(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/zeitgeist/activity.sqlite": "x",
                                           ".local/share/gvfs-metadata/home": "x"})
    assert detect(cat, "desk.zeitgeist", make_scan(host)).status is Status.FAIL
    assert detect(cat, "desk.gvfs_metadata", make_scan(host)).status is Status.FAIL
    empty = make_host(tmp_path / "e")
    assert detect(cat, "desk.zeitgeist", make_scan(empty)).status is Status.NOT_APPLICABLE
    assert detect(cat, "desk.gvfs_metadata", make_scan(empty)).status is Status.NOT_APPLICABLE


def test_screenshots(cat, tmp_path):
    host = make_host(tmp_path, home_files={"Pictures/Screenshots/Screenshot From 2026-01-01.png": "x",
                                           "Pictures/Screenshot_2025.png": "x", "Pictures/holiday.jpg": "x"})
    old = host.home / "Pictures/Screenshot_2025.png"
    os.utime(old, (old.stat().st_atime, old.stat().st_mtime - 40 * 86400))
    o = detect(cat, "desk.screenshots", make_scan(host))
    assert o.status is Status.WARN and o.summary.startswith("2 screenshots and screen recordings are kept; the oldest is 40 days")


def test_spectacle_location(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/spectaclerc": "[ImageSave]\nimageSaveLocation=file:///tmp/x/shots\n"})
    shots = tmp_path / "x/shots"
    shots.mkdir(parents=True)
    (shots / "a.png").write_text("x")
    host.home.joinpath(".config/spectaclerc").write_text(f"[ImageSave]\nimageSaveLocation={shots.as_uri()}\n")
    assert detect(cat, "desk.screenshots", make_scan(host, desktop=("kde",))).status is Status.WARN


def test_gnome_app_usage(cat, tmp_path):
    host = make_host(tmp_path, commands={"gsettings get org.gnome.desktop.privacy remember-app-usage": "true\n"})
    assert detect(cat, "desk.gnome_app_usage", make_scan(host)).status is Status.FAIL
    assert detect(cat, "desk.gnome_app_usage", make_scan(host, desktop=("kde",))).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("rc, status", [(None, Status.FAIL), ("[General]\nloginMode=emptySession\n", Status.PASS)])
def test_session_restore_kde(cat, tmp_path, rc, status):
    host = make_host(tmp_path, home_files={".config/ksmserverrc": rc} if rc else {})
    assert detect(cat, "desk.session_restore", make_scan(host, desktop=("kde",))).status is status


def test_session_restore_gnome(cat, tmp_path):
    host = make_host(tmp_path, commands={"gsettings get org.gnome.SessionManager auto-save-session": "false\n"})
    assert detect(cat, "desk.session_restore", make_scan(host)).status is Status.PASS


def test_folder_view_records(cat, tmp_path):
    host = make_host(tmp_path, home_files={".local/share/dolphin/view_properties/global/.directory": "[Dolphin]"})
    assert detect(cat, "desk.folder_view_records", make_scan(host, desktop=("kde",))).status is Status.FAIL
    assert detect(cat, "desk.folder_view_records", make_scan(make_host(tmp_path / "n"))).status is Status.NOT_APPLICABLE


def test_dolphin_view_settings_kept_in_extended_attributes(cat, tmp_path):
    """Dolphin 24.08+ attaches a folder's view settings to the folder itself (an extended attribute), so a USB drive
    carries them without any .directory file."""
    host = make_host(tmp_path, installed=["dolphin"])
    stick = host.root / "run/media/alice/STICK"
    (stick / "Holiday").mkdir(parents=True)
    try:
        os.setxattr(stick / "Holiday", "user.kde.fm.viewproperties#1", b"[Dolphin]\nViewMode=1\n")
    except OSError:
        pytest.skip("no user extended attributes here")
    (host.root / "proc").mkdir(exist_ok=True)
    (host.root / "proc/mounts").write_text("/dev/sdb1 /run/media/alice/STICK ext4 rw 0 0\n")
    o = detect(cat, "desk.folder_view_records", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and ev(o)["Folders on removable drives with Dolphin's view settings attached"] == 1


def test_screen_recordings_and_translated_folders(cat, tmp_path):
    """Videos/Screencasts (GNOME, Spectacle) and the folders Spectacle names in the user's language."""
    host = make_host(tmp_path, home_files={
        "Videos/Screencasts/Screencast from 2026-10-01.webm": "v",
        "Pictures/Képernyőképek/Képernyőkép_20261001.png": "p",
        ".config/spectaclerc": "[ImageSave]\ntranslatedScreenshotsFolder=Képernyőképek\n"})
    o = detect(cat, "desk.screenshots", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.WARN and o.summary.startswith("2 screenshots and screen recordings are kept")
