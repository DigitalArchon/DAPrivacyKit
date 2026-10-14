import pytest

from daprivacyscanner import ini
from daprivacyscanner.desktop import GNOME, KDE, DesktopInfo, detect_desktop, parse_gvariant
from daprivacyscanner.host import CommandResult
from daprivacyscanner.paths import PathResolver

from conftest import make_host


def kde_for(host, plasma=6):
    info = DesktopInfo(("kde",), plasma_major=plasma)
    return KDE(host, PathResolver(host.home, host.environ), info)


def test_detect_desktop_versions(tmp_path):
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "ubuntu:GNOME"},
                     commands={"gnome-shell --version": "GNOME Shell 46.0\n"})
    info = detect_desktop(host)
    assert info.is_gnome and info.gnome_major == 46 and info.label == "GNOME 46"

    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "KDE", "KDE_SESSION_VERSION": "6"})
    assert detect_desktop(host).label == "KDE Plasma 6"

    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "KDE"}, commands={"plasmashell --version": "plasmashell 5.27.11\n"})
    assert detect_desktop(host).plasma_major == 5


def test_kde_tools_by_version(tmp_path):
    host = make_host(tmp_path)
    assert kde_for(host, 6).tool("balooctl") == "balooctl6"
    assert kde_for(host, 5).tool("balooctl") == "balooctl"
    assert kde_for(host, 5).tool("kreadconfig") == "kreadconfig5"
    assert kde_for(host, 6).tool("kreadconfig") == "kreadconfig6"


def test_kde_major_from_installed_tools(tmp_path):
    host = make_host(tmp_path, installed=["kreadconfig5"])
    assert kde_for(host, None).major == 5


def test_missing_kde_key_is_default_not_off(tmp_path):
    host = make_host(tmp_path, home_files={".config/kscreenlockerrc": "[Daemon]\nTimeout=10\n"})
    k = kde_for(host)
    assert k.get("kscreenlockerrc", "Daemon", "Timeout") == "10"
    assert k.get("kscreenlockerrc", "Daemon", "Autolock") is None
    assert k.get("nosuchrc", "Daemon", "Autolock") is None


def test_kde_user_file_overrides_system_defaults(tmp_path):
    host = make_host(tmp_path, files={"/etc/xdg/kdeglobals": "[RecentDocuments]\nUseRecent=false\nMaxEntries=5\n"},
                     home_files={".config/kdeglobals": "[RecentDocuments]\nUseRecent[$i]=true\n"})
    k = kde_for(host)
    assert k.get("kdeglobals", "RecentDocuments", "UseRecent") == "true"
    assert k.get("kdeglobals", "RecentDocuments", "MaxEntries") == "5"


def test_kde_state_files_in_plasma6_location(tmp_path):
    host = make_host(tmp_path, home_files={".local/state/dolphinstaterc": "[MainWindow]\nState=x\n",
                                           ".config/dolphinstaterc": "[MainWindow]\nState=old\n"})
    k = kde_for(host)
    assert k.kconfig_path("dolphinstaterc") == host.home / ".local/state/dolphinstaterc"
    assert k.get("dolphinstaterc", "MainWindow", "State") == "x"


def test_kde_nested_groups_and_escapes():
    cfg = ini.parse("[Containments][1][General]\nname=a\\sb\\tc\n", kde=True)
    assert ini.get(cfg, ("Containments", "1", "General"), "name") == "a b\tc"


def test_ini_last_wins_and_comments():
    cfg = ini.parse("# c\n[Seat:*]\n#autologin-user=bob\nautologin-user=\nautologin-user=alice\n")
    assert ini.get(cfg, "Seat:*", "autologin-user") == "alice"


@pytest.mark.parametrize("text, value", [
    ("true", True), ("false", False), ("uint32 300", 300), ("0", 0), ("'stable'", "stable"),
    ("@as []", []), ("['a', 'b,c']", ["a", "b,c"]), ("int64 -1", -1), ("1.5", 1.5),
])
def test_parse_gvariant(text, value):
    assert parse_gvariant(text) == value


def test_gsettings_missing_schema_is_none(tmp_path):
    host = make_host(tmp_path, commands={
        "gsettings get org.gnome.desktop.screensaver lock-enabled": "true\n",
        ("gsettings", "get", "org.gnome.nope", "x"): CommandResult(("gsettings",), 1, "", "No such schema"),
    })
    g = GNOME(host, DesktopInfo(("gnome",), gnome_major=46))
    assert g.gsettings("org.gnome.desktop.screensaver", "lock-enabled") is True
    assert g.gsettings("org.gnome.nope", "x") is None


@pytest.mark.parametrize("major, installed, expected", [
    (47, ["localsearch", "tracker3"], "localsearch"),
    (46, ["localsearch", "tracker3"], "tracker3"),
    (47, ["tracker3"], "tracker3"),
    (46, [], None),
])
def test_indexer_command(tmp_path, major, installed, expected):
    host = make_host(tmp_path, installed=installed)
    assert GNOME(host, DesktopInfo(("gnome",), gnome_major=major)).indexer_command() == expected
