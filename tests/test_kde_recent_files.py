"""app.kde_recent_files: KDE apps' own lists of what was opened (KolourPaint and Okular in their settings, Ark, Kate
and KWrite in a file of their own, Gwenview's recent folders), cleared and stopped; and KConfigLock, the [$i] marker
that stops a KConfig group being written (tested with KDE Gear 26.08.1 on Plasma 6.7.5)."""

import os

import pytest

from daprivacyscanner.fix import KConfigLock
from daprivacyscanner.model import Status

from conftest import make_host, make_scan
from test_guides import apply, build, options, revert
from test_checks_encryption import detect, ev

KOLOURPAINTRC = ("[General Settings]\nFirst Time=false\n\n[Recent Files]\nFile1[$e]=$HOME/Pictures/secret.png\n"
                 "Name1[$e]=secret.png\nFile2[$e]=$HOME/Pictures/b.png\nName2[$e]=b.png\n\n[Tool Settings]\nLast Used Tool=5\n")
ARK = ("[RecentFiles]\nfiles\\1\\displayName=secret.zip\nfiles\\1\\url=@Variant(\\0\\0\\0\\x11\\0\\0\\0.file:///home/a/secret.zip)\n"
       "files\\size=1\n")
SESSION = ("[Document 0]\nURL=file:///home/a/notes/secret.txt\n\n[MainWindow0 Settings]\nx=1\n\n[Recent Files]\n"
           "File1[$e]=$HOME/notes/secret.txt\n")


def host_with(tmp_path, installed=(), **files):
    return make_host(tmp_path, home_files=files, installed=installed)


def test_lists_are_found_and_counted(cat, tmp_path):
    host = host_with(tmp_path, **{".config/kolourpaintrc": KOLOURPAINTRC, ".local/share/ark/ark_recentfiles": ARK,
                                  ".local/share/kwrite/anonymous.katesession": SESSION,
                                  ".local/share/gwenview/recentfolders/gvhistoryA.rc": "[general]\nurl=file:///home/a/x/\n"})
    o = detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",)))
    assert o.status is Status.FAIL and o.summary.startswith("6 files and folders you opened are listed by")
    e = {k.split(":")[0]: v for k, v in ev(o).items()}
    assert e == {"KolourPaint": "2 listed", "Ark": "1 listed", "KWrite": "2 listed", "Gwenview": "1 listed"}
    assert "secret" not in str(o.evidence)                 # counts, never the file names


def test_installed_apps_that_will_record_are_a_warning(cat, tmp_path):
    host = host_with(tmp_path, installed=("kolourpaint", "ark"))
    o = detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",)))
    assert o.status is Status.WARN and "KolourPaint, Ark will list" in o.summary
    assert detect(cat, "app.kde_recent_files", make_scan(host_with(tmp_path / "none"))).status is Status.NOT_APPLICABLE


def test_clear_then_stop_then_revert(cat, tmp_path):
    host = host_with(tmp_path, installed=("kolourpaint", "ark", "gwenview", "kwrite"),
                     **{".config/kolourpaintrc": KOLOURPAINTRC, ".local/share/ark/ark_recentfiles": ARK,
                        ".local/share/kwrite/anonymous.katesession": SESSION,
                        ".local/share/gwenview/recentfolders/gvhistoryA.rc": "[general]\nurl=file:///home/a/x/\n"})
    g = build(cat, host, "app.kde_recent_files", desktop=("kde",))
    stop = options(g)["Stop these apps keeping lists"]
    assert "Kate" not in str(stop.side_effects) and any("KWrite no longer reopen" in x for x in stop.side_effects)
    log, res = apply(host, stop)
    rc = (host.home / ".config/kolourpaintrc").read_text()
    assert "secret" not in rc and "Last Used Tool=5" in rc and "First Time=false" in rc
    # the lock goes beneath the app's own file, where it can't drop it (the review of 2026-10-17)
    assert "[$i]" not in rc and (host.home / ".config/kdedefaults/kolourpaintrc").read_text() == "[Recent Files][$i]\n"
    for rel in ("ark/ark_recentfiles", "kwrite/anonymous.katesession", "gwenview/recentfolders"):
        p = host.home / ".local/share" / rel
        assert p.is_dir() and not any(p.iterdir()) and (p.stat().st_mode & 0o777) == 0o500, rel
    assert not (host.home / ".local/share/kate").exists()   # Kate isn't installed: nothing made for it
    assert detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",))).status is Status.PASS
    # the log holds no file names: the lists were cleared, not backed up
    kept = [f for f in (host.home / ".local/state/daprivacyscanner").rglob("*") if f.is_file()]
    assert kept and not [f for f in kept if b"secret" in f.read_bytes()]
    # the app rewrites its own file meanwhile (dropping the empty group, as Gwenview does): the lock holds, and the
    # revert removes the lock it made, leaving the app's file as the app left it
    (host.home / ".config/kolourpaintrc").write_text("[General Settings]\nFirst Time=false\n\n[Tool Settings]\n"
                                                     "Last Used Tool=7\n")
    assert detect(cat, "app.kde_recent_files", make_scan(host, desktop=("kde",))).status is Status.PASS
    revert(host, log, res)
    rc = (host.home / ".config/kolourpaintrc").read_text()
    assert "[$i]" not in rc and "Last Used Tool=7" in rc
    assert not (host.home / ".config/kdedefaults").exists()  # the folder the fix made goes with the lock
    assert not (host.home / ".local/share/ark/ark_recentfiles").exists()
    assert not (host.home / ".local/share/gwenview/recentfolders").exists()


def test_an_app_never_run_is_stopped_before_it_lists_anything(cat, tmp_path):
    host = host_with(tmp_path, installed=("okular", "ark"))
    (host.home / ".config/kdedefaults").mkdir(parents=True)          # Plasma makes it
    g = build(cat, host, "app.kde_recent_files", desktop=("kde",))
    log, res = apply(host, options(g)["Stop these apps keeping lists"])
    assert (host.home / ".config/kdedefaults/okularrc").read_text() == "[Recent Files][$i]\n"
    assert not (host.home / ".config/okularrc").exists()
    assert (host.home / ".local/share/ark/ark_recentfiles").is_dir()
    # Okular writes its own settings file meanwhile; reverting removes only the lock
    (host.home / ".config/okularrc").write_text("[General]\nShowSidebar=true\n")
    revert(host, log, res)
    assert (host.home / ".config/okularrc").read_text() == "[General]\nShowSidebar=true\n"
    assert not (host.home / ".config/kdedefaults/okularrc").exists() and (host.home / ".config/kdedefaults").is_dir()
    assert not (host.home / ".local/share/ark").exists()      # the folders the fix made go with it


def test_a_running_app_blocks(cat, tmp_path):
    host = host_with(tmp_path, installed=("kolourpaint",), **{".config/kolourpaintrc": KOLOURPAINTRC})
    os.makedirs(host.root / "proc/4242", exist_ok=True)
    (host.root / "proc/4242/comm").write_text("kolourpaint\n")
    g = build(cat, host, "app.kde_recent_files", desktop=("kde",))
    assert all(o.plan.blockers == ["Close KolourPaint first: it writes its list as it closes."]
               for s in g.steps for o in s.options)


@pytest.mark.parametrize("text, state", [
    (None, "absent"), ("[General]\nx=1\n", "absent"), ("[Recent Files]\nFile1=a\n", "unlocked"),
    ("[Recent Files][$i]\n", "locked"), ("[Recent Files Extra]\n", "absent"),
])
def test_kconfig_lock_state(text, state):
    assert KConfigLock.state(text, "Recent Files") == state
