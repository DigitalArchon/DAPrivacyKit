import os

import pytest

from daprivacyscanner.paths import Base, PathResolver


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


def mk(p):
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_spec_defaults(home):
    r = PathResolver(home, {})
    assert r.config_home == home / ".config"
    assert r.data_home == home / ".local/share"
    assert r.cache_home == home / ".cache"
    assert r.state_home == home / ".local/state"
    assert r.config_dirs()[0].as_posix() == "/etc/xdg"


def test_honours_xdg_variables(home, tmp_path):
    r = PathResolver(home, {"XDG_CONFIG_HOME": str(tmp_path / "cfg"), "XDG_CACHE_HOME": str(tmp_path / "c")})
    assert r.config_home == tmp_path / "cfg"
    assert r.cache_home == tmp_path / "c"
    assert r.data_home == home / ".local/share"


def test_relative_xdg_variables_are_invalid_and_ignored(home):
    r = PathResolver(home, {"XDG_DATA_HOME": "relative/share", "XDG_STATE_HOME": ""})
    assert r.data_home == home / ".local/share"
    assert r.state_home == home / ".local/state"


def test_locate_native_flatpak_and_snap(home):
    mk(home / ".config/Signal")
    mk(home / ".var/app/org.signal.Signal/config/Signal")
    mk(home / "snap/signal-desktop/common")
    mk(home / "snap/signal-desktop/612/.config/Signal")
    mk(home / "snap/signal-desktop/650/.config/Signal")
    os.symlink("650", home / "snap/signal-desktop/current")
    r = PathResolver(home, {})

    locs = r.config("Signal", flatpak=["org.signal.Signal"], snap=["signal-desktop"])
    assert [(l.install, l.app, l.revision, l.current) for l in locs] == [
        ("native", None, None, True),
        ("flatpak", "org.signal.Signal", None, True),
        ("snap", "signal-desktop", "612", False),
        ("snap", "signal-desktop", "650", True),
    ]
    assert locs[1].path == home / ".var/app/org.signal.Signal/config/Signal"


def test_snap_current_symlink_is_not_listed_twice(home):
    mk(home / "snap/firefox/common/.mozilla/firefox")
    mk(home / "snap/firefox/4793")
    os.symlink("4793", home / "snap/firefox/current")
    roots = PathResolver(home, {}).snap_roots("firefox")
    assert [l.revision for l in roots] == ["common", "4793"]


def test_home_dotdirs_in_sandboxes(home):
    mk(home / ".mozilla/firefox")
    mk(home / ".var/app/org.mozilla.firefox/.mozilla/firefox")
    mk(home / "snap/firefox/common/.mozilla/firefox")
    locs = PathResolver(home, {}).dotdir(".mozilla/firefox", flatpak=["org.mozilla.firefox"], snap=["firefox"])
    assert [l.install for l in locs] == ["native", "flatpak", "snap"]


def test_all_flatpaks(home):
    mk(home / ".var/app/org.gnome.Loupe/cache/thumbnails")
    mk(home / ".var/app/org.gnome.Papers/cache")            # no thumbnails
    mk(home / ".cache/thumbnails")
    locs = PathResolver(home, {}).cache("thumbnails", all_flatpaks=True)
    assert [(l.install, l.app) for l in locs] == [("native", None), ("flatpak", "org.gnome.Loupe")]


def test_flatpak_state_dir(home):
    mk(home / ".var/app/io.mpv.Mpv/.local/state/mpv/watch_later")
    locs = PathResolver(home, {}).state("mpv/watch_later", flatpak=["io.mpv.Mpv"])
    assert locs[0].path == home / ".var/app/io.mpv.Mpv/.local/state/mpv/watch_later"


def test_existing_false_lists_candidates(home):
    locs = PathResolver(home, {}).data("recently-used.xbel", flatpak=["org.gnome.TextEditor"], existing=False)
    assert [l.path for l in locs] == [home / ".local/share/recently-used.xbel",
                                      home / ".var/app/org.gnome.TextEditor/data/recently-used.xbel"]


def test_same_directory_reached_twice_is_listed_once(home):
    target = mk(home / ".var/app/com.example.App/config")
    r = PathResolver(home, {"XDG_CONFIG_HOME": str(target)})
    assert len(r.config("", flatpak=["com.example.App"])) == 1


def test_enumeration(home):
    mk(home / ".var/app/b.App")
    mk(home / ".var/app/a.App")
    mk(home / "snap/chromium")
    r = PathResolver(home, {})
    assert r.flatpak_apps() == ["a.App", "b.App"]
    assert r.snaps() == ["chromium"]
    assert PathResolver(home / "nowhere", {}).flatpak_apps() == []


@pytest.mark.parametrize("rel", ["/etc/passwd", "../.ssh"])
def test_rejects_escaping_paths(home, rel):
    with pytest.raises(ValueError):
        PathResolver(home, {}).locate(Base.CONFIG, rel)


def test_sqlite_count_sees_what_is_still_in_the_write_ahead_log(tmp_path):
    """An app's newest records can be only in its -wal file (KDE's activity database, Klipper's history, Vorta's
    settings): an immutable reader doesn't see them. They are counted, with the app still writing, after a crash left
    no -shm file, and with characters a URI would misread in the name; nothing is written to the database."""
    import sqlite3
    from daprivacyscanner.checks._util import sqlite_count
    db = tmp_path / "a?b#c.sqlite"
    con = sqlite3.connect(db)
    con.execute("pragma journal_mode=wal")
    con.execute("pragma wal_autocheckpoint=0")
    con.execute("create table t (a)")
    con.executemany("insert into t values (?)", [(i,) for i in range(5)])
    con.commit()
    before = db.read_bytes()
    assert sqlite_count(db, "select count(*) from t") == 5
    (tmp_path / "a?b#c.sqlite-shm").unlink()
    assert sqlite_count(db, "select count(*) from t") == 5
    con.close()
    assert sqlite_count(tmp_path / "missing.sqlite", "select 1") is None
