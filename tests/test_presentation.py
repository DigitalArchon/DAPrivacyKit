"""Presentation mode (tools/presentation.py): what it changes per desktop, on and off again, a
setting the user changed meanwhile, a failure part-way, and the endpoints (Quit turns it off)."""

from __future__ import annotations

import stat

import pytest
from fastapi.testclient import TestClient

from conftest import make_host
from daprivacyscanner.host import CommandResult, FakeRunner
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import presentation as P

from fakes import FakeGSettings, OK, fail

H = {"X-Token": "t0ken"}
NOTIF = ("org.gnome.desktop.notifications", "show-banners")
ENABLED = ("org.gnome.shell", "enabled-extensions")
DISABLED = ("org.gnome.shell", "disabled-extensions")


def gnome_host(tmp_path, values=None, desktop="ubuntu:GNOME", extra=None):
    gs = FakeGSettings(values if values is not None else {
        NOTIF: "true", ENABLED: "['clipboard-indicator@tudmotu.com', 'dash-to-dock@micxgx.gmail.com']",
        DISABLED: "@as []", ("org.cinnamon.desktop.notifications", "display-notifications"): "true"})
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": desktop})
    host.runner = FakeRunner(handlers={"gsettings": gs, **(extra or {})})
    return host, gs


def test_gnome_plan_on_and_off(tmp_path):
    host, gs = gnome_host(tmp_path)
    st = P.status(host)
    assert st["on"] is False and st["desktop"] == "GNOME"
    assert [c["what"] for c in st["plan"]] == ["Notification banners off (Do Not Disturb)",
                                               "Clipboard Indicator turned off (its clipboard history menu disappears)"]
    assert gs.values[NOTIF] == "true"                       # planning changes nothing
    on = P.turn_on(host)
    assert on["on"] and gs.values[NOTIF] == "false"
    assert gs.values[DISABLED] == "['clipboard-indicator@tudmotu.com']"
    assert stat.S_IMODE(P.state_file(host).stat().st_mode) == 0o600
    assert any("show-banners" in u for u in on["undo"])
    assert on["ran"][0] == "gsettings set org.gnome.desktop.notifications show-banners false"    # what it ran, shown
    with pytest.raises(P.AlreadyOn):
        P.turn_on(host)
    off = P.turn_off(host)
    assert off["on"] is False and not P.state_file(host).exists() and off["kept"] == [] and off["failed"] == []
    assert gs.values[NOTIF] == "true" and gs.values[DISABLED] == "@as []"


def test_a_setting_the_user_changed_meanwhile_is_kept(tmp_path):
    host, gs = gnome_host(tmp_path)
    P.turn_on(host)
    gs.values[NOTIF] = "true"                               # they turned banners back on themselves
    gs.values[DISABLED] = "['clipboard-indicator@tudmotu.com', 'other@x']"
    off = P.turn_off(host)
    assert len(off["kept"]) == 2 and not P.state_file(host).exists()
    assert gs.values[DISABLED] == "['clipboard-indicator@tudmotu.com', 'other@x']"


def test_cinnamon(tmp_path):
    host, gs = gnome_host(tmp_path, desktop="X-Cinnamon")
    assert [c["text"] for c in P.status(host)["plan"]] == [
        "gsettings set org.cinnamon.desktop.notifications display-notifications false"]
    P.turn_on(host)
    assert gs.values[("org.cinnamon.desktop.notifications", "display-notifications")] == "false"
    P.turn_off(host)
    assert gs.values[("org.cinnamon.desktop.notifications", "display-notifications")] == "true"


def test_nothing_to_change_can_still_be_on(tmp_path):
    host, _ = gnome_host(tmp_path, values={NOTIF: "false", ENABLED: "@as []", DISABLED: "@as []"})
    assert P.status(host)["plan"] == []
    assert P.turn_on(host)["on"] and P.is_on(host)
    assert P.turn_off(host)["on"] is False


class FakeInhibitor:
    def __init__(self):
        self.active, self.next = set(), 7

    def inhibit(self, reason):
        self.next += 1
        self.active.add(self.next)
        return self.next

    def release(self, cookie):
        self.active.discard(cookie)

    def holds(self, cookie):
        return cookie in self.active


def test_kde_do_not_disturb_is_held_and_released(tmp_path, monkeypatch):
    fake = FakeInhibitor()
    monkeypatch.setattr(P, "INHIBITOR", fake)
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "KDE", "KDE_SESSION_VERSION": "6"})
    st = P.status(host)
    assert [c["what"] for c in st["plan"]] == ["Do Not Disturb on"]
    assert not any("Klipper" in n for n in st["notes"])             # no Klipper here: nothing to say about it
    P.turn_on(host)
    assert fake.active == {8}
    assert P.status(host)["lapsed"] == []
    P.turn_off(host)
    assert fake.active == set()


def test_kde_klipper_is_turned_off_while_on_and_back_afterwards(tmp_path, monkeypatch):
    """Klipper records every copy whether or not it is shown: on Plasma 6 its tray entry goes off through
    plasmashell (as the clipboard fix does) and comes back when Presentation mode ends."""
    from daprivacyscanner.desktop import tray_applet
    from fakes import APPLETSRC_6, FakePlasmaShell
    monkeypatch.setattr(P, "INHIBITOR", FakeInhibitor())
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "KDE", "KDE_SESSION_VERSION": "6"},
                     home_files={".config/plasma-org.kde.plasma.desktop-appletsrc": APPLETSRC_6},
                     files={"/proc/3/comm": "plasmashell\n"})
    host.runner.handlers["qdbus6"] = FakePlasmaShell(host.home / ".config", host.home / ".local/share")
    appletsrc = host.home / ".config/plasma-org.kde.plasma.desktop-appletsrc"
    st = P.status(host)
    assert [c["what"] for c in st["plan"]] == ["Do Not Disturb on",
                                               "Klipper (Plasma's clipboard history) turned off; on again afterwards"]
    assert tray_applet(appletsrc.read_text(), "org.kde.plasma.clipboard").on          # planning changes nothing
    on = P.turn_on(host)
    assert not tray_applet(appletsrc.read_text(), "org.kde.plasma.clipboard").on
    assert any("evaluateScript" in r for r in on["ran"]) and any("System Tray Settings" in u for u in on["undo"])
    off = P.turn_off(host)
    assert off["failed"] == [] and tray_applet(appletsrc.read_text(), "org.kde.plasma.clipboard").on
    # Plasma not running: nothing to do but say so
    quiet = make_host(tmp_path / "q", env={"XDG_CURRENT_DESKTOP": "KDE", "KDE_SESSION_VERSION": "6"},
                      home_files={".config/plasma-org.kde.plasma.desktop-appletsrc": APPLETSRC_6})
    st = P.status(quiet)
    assert [c["what"] for c in st["plan"]] == ["Do Not Disturb on"]
    assert any("keeps recording" in n for n in st["notes"])


def test_kde_do_not_disturb_that_ended_with_the_app_is_said_and_taken_up_again(tmp_path, monkeypatch):
    """The hold dies with the process: after a crash the state file says on, but notifications are
    back. The page must say so, and renew takes it up again with a new cookie."""
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "KDE", "KDE_SESSION_VERSION": "6"})
    monkeypatch.setattr(P, "INHIBITOR", FakeInhibitor())
    P.turn_on(host)
    restarted = FakeInhibitor()                          # a new process: it holds nothing
    restarted.next = 20
    monkeypatch.setattr(P, "INHIBITOR", restarted)
    st = P.status(host)
    assert st["on"] and st["lapsed"] == ["Do Not Disturb on"]
    assert any("ended when the app stopped" in n for n in st["notes"])
    st = P.renew(host)
    assert restarted.active == {21} and st["lapsed"] == []
    assert P.turn_off(host)["on"] is False and restarted.active == set()


def test_xfce_and_copyq(tmp_path):
    xf = {"value": None}
    copyq = {"on": True}

    def xfconf(argv):
        if "-s" in argv:
            xf["value"] = argv[-1]
        elif "-r" in argv:
            xf["value"] = None
        return CommandResult(argv, 0, f"{xf['value']}\n") if xf["value"] is not None and "-s" not in argv else \
            OK if "-s" in argv or "-r" in argv else fail("Property does not exist")

    def cq(argv):
        if argv[1] == "monitoring":
            return CommandResult(argv, 0, "true\n" if copyq["on"] else "false\n")
        copyq["on"] = argv[1] == "enable"
        return OK

    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "XFCE"})
    host.runner = FakeRunner(handlers={"xfconf-query": xfconf, "copyq": cq})
    st = P.status(host)
    assert [c["what"] for c in st["plan"]] == ["Do Not Disturb on", "CopyQ stops recording what you copy"]
    on = P.turn_on(host)
    assert xf["value"] == "true" and copyq["on"] is False
    assert "copyq enable" in on["undo"] and any(u.endswith("/do-not-disturb -r") for u in on["undo"])
    P.turn_off(host)
    assert xf["value"] is None and copyq["on"] is True


def test_a_failure_part_way_puts_back_what_was_changed(tmp_path):
    def cq(argv):
        return CommandResult(argv, 0, "true\n") if argv[1] == "monitoring" else fail("CopyQ isn't running")

    host, gs = gnome_host(tmp_path, extra={"copyq": cq})
    with pytest.raises(P.FixError, match="CopyQ isn't running"):
        P.turn_on(host)
    assert gs.values[NOTIF] == "true" and gs.values[DISABLED] == "@as []" and not P.is_on(host)


def test_unknown_desktop_says_so(tmp_path):
    host = make_host(tmp_path, env={"XDG_CURRENT_DESKTOP": "sway"})
    st = P.status(host)
    assert st["plan"] == [] and any("can't turn notification banners off on this desktop (Sway)" in n for n in st["notes"])


def test_endpoints_and_quit_turns_it_off(cat, tmp_path):
    host, gs = gnome_host(tmp_path)
    quit_called = []
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, on_quit=lambda: quit_called.append(1)))
    assert c.get("/api/state", headers=H).json()["presentation"] == {"on": False, "since": None, "lapsed": []}
    assert c.get("/api/tools/presentation", headers=H).json()["plan"]
    r = c.post("/api/tools/presentation/on", headers=H).json()
    assert r["on"] and gs.values[NOTIF] == "false"
    assert c.post("/api/tools/presentation/on", headers=H).status_code == 409
    assert c.get("/api/state", headers=H).json()["presentation"]["on"] is True
    c.post("/api/quit", headers=H)
    assert gs.values[NOTIF] == "true" and not P.is_on(host)
