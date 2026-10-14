import copy
import json

import pytest
import yaml

from daprivacyscanner import browsers
from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.checks import load_all
from daprivacyscanner.model import Outcome, Status
from daprivacyscanner.vpn import DataError

from conftest import detect, ev, make_host, make_scan
from test_checks_telemetry_browser import firefox


def entry(name, exec_="/usr/bin/x %U", web=True):
    return (f"[Desktop Entry]\nType=Application\nName={name}\nExec={exec_}\n"
            + ("Categories=Network;WebBrowser;\nMimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;\n"
               if web else "Categories=Utility;\n"))


def machine(tmp_path, default=None, files=None, home_files=None, commands=None):
    """A Mint-like machine: the given menu entries, and xdg-settings naming `default`."""
    cmds = {"xdg-settings get default-web-browser": f"{default}\n"} if default else {}
    cmds.update(commands or {})
    return make_host(tmp_path, files={"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", **(files or {})},
                     home_files=home_files, commands=cmds)


def guide(cat, host, check_id):
    check = load_all()[check_id](cat[check_id])
    return check.plan_guide(make_scan(host), Outcome(Status.FAIL, "x"))


# ------------------------------------------------------------------ the data

def test_every_judgement_has_receipts():
    data = browsers.load()
    for b in data:
        if b.cls in ("surveillance", "closed_ui"):
            assert b.facts and b.why, b.id
        for f in b.facts:
            assert f.source.startswith("https://") and f.verified
    assert {b.id for b in data if b.no_ublock} == {"chrome", "edge"}
    assert {b.id for b in data if b.cls == "surveillance"} == {"chrome", "edge", "opera", "yandex"}
    privacy = {b.id for b in data if b.cls == "privacy"}
    assert {"brave", "brave_origin", "librewolf", "waterfox", "zen", "floorp", "helium", "ungoogled_chromium",
            "cromite", "mullvad_browser", "tor_browser"} == privacy
    assert data["tor_browser"].blocking == "none_allowed"


def _raw():
    return yaml.safe_load(browsers.default_path().read_text())


@pytest.mark.parametrize("mangle, said", [
    (lambda d: d["browsers"][1]["detect"]["desktop"].append("google-chrome.desktop"), "also chrome's"),
    (lambda d: d["browsers"][0].pop("facts"), "needs facts that show why"),
    (lambda d: d["browsers"][0].update({"class": "evil"}), "class must be one of"),
    (lambda d: d["browsers"][0]["facts"][0].pop("source"), "needs exactly topic"),
])
def test_the_data_cant_judge_without_receipts(mangle, said):
    d = copy.deepcopy(_raw())
    mangle(d)
    with pytest.raises(DataError, match=said):
        browsers.parse(d)


# ------------------------------------------------------------------ finding browsers

def test_browsers_are_found_however_they_were_installed(cat, tmp_path):
    host = machine(tmp_path, default="google-chrome.desktop", files={
        "/usr/share/applications/google-chrome.desktop": entry("Google Chrome"),
        "/usr/share/applications/org.x.editor.desktop": entry("Text Editor", web=False),
        "/var/lib/snapd/desktop/applications/firefox_firefox.desktop": entry("Firefox"),
        "/usr/share/applications/org.gnome.Epiphany.desktop": entry("Web"),
    }, home_files={
        ".local/share/flatpak/exports/share/applications/com.brave.Browser.desktop": entry("Brave"),
        ".local/share/applications/helium.desktop": entry("Helium", "/home/alice/Applications/Helium-0.14.AppImage %U"),
        "Applications/zen-x86_64.AppImage": "",
        ".config/cinnamon/spices/grouped-window-list@cinnamon.org/2.json":
            json.dumps({"pinned-apps": {"value": ["google-chrome.desktop", "nemo.desktop"]}}),
    })
    from daprivacyscanner.checks.browser import installed_browsers
    found = {f.name: f.describe() for f in installed_browsers(make_scan(host))}
    assert found == {"Brave": "Flatpak", "Firefox": "Snap", "Google Chrome": "package; pinned to the Cinnamon panel",
                     "Helium": "AppImage", "Web": "package", "Zen": "AppImage"}


def test_the_default_comes_from_mimeapps_when_xdg_settings_is_missing(cat, tmp_path):
    host = machine(tmp_path, files={"/usr/share/applications/brave-origin.desktop": entry("Brave Origin")},
                   home_files={".config/mimeapps.list": "[Default Applications]\nx-scheme-handler/https=brave-origin."
                                                       "desktop;firefox.desktop;\n"})
    o = detect(cat, "br.default_browser", make_scan(host))
    assert o.status is Status.PASS and o.summary == "Your default browser, Brave Origin, is built for privacy."
    assert ev(o)["Default browser"].startswith("Brave Origin (from ~/.config/mimeapps.list")


# ------------------------------------------------------------------ Chrome, Edge, Opera, Yandex

@pytest.mark.parametrize("installed, default, severity", [
    ({"opera.desktop": "Opera"}, "firefox.desktop", 3),
    ({"google-chrome.desktop": "Google Chrome"}, "firefox.desktop", 4),
    ({"opera.desktop": "Opera"}, "opera.desktop", 5),
    ({"opera.desktop": "Opera", "microsoft-edge.desktop": "Microsoft Edge"}, "opera.desktop", 5),
    ({"microsoft-edge.desktop": "Microsoft Edge"}, "microsoft-edge.desktop", 6),
])
def test_surveillance_browsers_by_severity(cat, tmp_path, installed, default, severity):
    files = {f"/usr/share/applications/{k}": entry(v) for k, v in installed.items()}
    files["/usr/share/applications/firefox.desktop"] = entry("Firefox")
    o = detect(cat, "br.surveillance_browsers", make_scan(machine(tmp_path, default=default, files=files)))
    assert o.status is Status.FAIL
    values = {"chrome_or_edge_installed": False, "surveillance_default": False, "chrome_or_edge_default": False,
              **o.findings}
    assert effective_severity(cat["br.surveillance_browsers"], values).value == severity


def test_surveillance_browsers_bring_their_receipts(cat, tmp_path):
    host = machine(tmp_path, default="microsoft-edge.desktop",
                   files={"/usr/share/applications/microsoft-edge.desktop": entry("Microsoft Edge")})
    o = detect(cat, "br.surveillance_browsers", make_scan(host))
    assert o.summary == "Microsoft Edge is installed, and Microsoft Edge is your default browser."
    notes = {n.title: n.text for n in o.notes}
    assert "called it a bug each time" in notes["Microsoft Edge: DA Privacy Kit's view"]
    assert "1999" in notes["Microsoft Edge: On the record"] and "Source: https://" in notes["Microsoft Edge: On the record"]
    assert "uBlock Origin" in notes["Microsoft Edge: Ad and tracker blocking"]


def test_unknown_default_leaves_the_severity_uncertain(cat, tmp_path):
    host = machine(tmp_path, files={"/usr/share/applications/google-chrome.desktop": entry("Google Chrome")})
    o = detect(cat, "br.surveillance_browsers", make_scan(host))
    assert o.findings["surveillance_default"] is None and o.findings["chrome_or_edge_installed"] is True


def test_removal_guide_names_the_package_and_the_repository(cat, tmp_path):
    host = machine(tmp_path, default="firefox.desktop", files={
        "/usr/share/applications/google-chrome.desktop": entry("Google Chrome"),
        "/etc/apt/sources.list.d/google-chrome.list": "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main\n",
    }, home_files={".local/share/flatpak/exports/share/applications/com.microsoft.Edge.desktop": entry("Microsoft Edge")},
        commands={"dpkg-query -S " + str(tmp_path / "root/usr/share/applications/google-chrome.desktop"):
                  "google-chrome-stable: /usr/share/applications/google-chrome.desktop\n"})
    g = guide(cat, host, "br.surveillance_browsers")
    cmds = {s.title.split(" (")[0]: s.commands for s in g.steps}
    assert cmds["Remove Google Chrome"] == ["sudo apt purge google-chrome-stable",
                                           "sudo rm /etc/apt/sources.list.d/google-chrome.list"]
    assert cmds["Remove Microsoft Edge"] == ["flatpak uninstall --user com.microsoft.Edge"]


# ------------------------------------------------------------------ the default browser

@pytest.mark.parametrize("desktop, name, status, closed", [
    ("firefox.desktop", "Firefox", Status.FAIL, False),
    ("vivaldi-stable.desktop", "Vivaldi", Status.FAIL, True),
    ("org.gnome.Epiphany.desktop", "Web", Status.FAIL, False),          # one the app doesn't know: level 2
    ("librewolf.desktop", "LibreWolf", Status.PASS, False),
    ("torbrowser.desktop", "Tor Browser", Status.PASS, False),
    ("google-chrome.desktop", "Google Chrome", Status.NOT_APPLICABLE, False),   # the other check reports it
])
def test_default_browser(cat, tmp_path, desktop, name, status, closed):
    host = machine(tmp_path, default=desktop, files={f"/usr/share/applications/{desktop}": entry(name)})
    o = detect(cat, "br.default_browser", make_scan(host))
    assert o.status is status
    if status is not Status.NOT_APPLICABLE:
        assert o.findings == {"default_closed_ui": closed}
        assert any(n.title == "Which browser to use" for n in o.notes)


def test_default_browser_guide_offers_the_ones_installed(cat, tmp_path):
    host = machine(tmp_path, default="firefox.desktop", files={
        "/usr/share/applications/firefox.desktop": entry("Firefox"),
        "/usr/share/applications/brave-origin.desktop": entry("Brave Origin")})
    g = guide(cat, host, "br.default_browser")
    assert g.steps[0].commands == ["xdg-settings set default-web-browser brave-origin.desktop    # Brave Origin"]


def test_brave_mentions_origin(tmp_path):
    b = browsers.load()["brave"]
    assert "free on Linux" in b.why and "compiled out" in b.why and "one by one" in b.why


# ------------------------------------------------------------------ content blocking

def ff_machine(tmp_path, default, extensions):
    host = machine(tmp_path, default=default, files={"/usr/share/applications/firefox.desktop": entry("Firefox"),
                                                     "/usr/share/applications/torbrowser.desktop": entry("Tor Browser")})
    firefox(host.home, extensions=extensions)
    return host


UBO = {"id": "uBlock0@raymondhill.net", "type": "extension", "active": True, "location": "app-profile",
       "defaultLocale": {"name": "uBlock Origin"}, "userPermissions": {"origins": ["<all_urls>"]}}


def test_default_browser_without_a_blocker(cat, tmp_path):
    o = detect(cat, "br.content_blocking", make_scan(ff_machine(tmp_path / "a", "firefox.desktop", [])))
    assert o.status is Status.FAIL and o.summary.startswith("Firefox blocks no ads")
    g = guide(cat, ff_machine(tmp_path / "a", "firefox.desktop", []), "br.content_blocking")
    assert g.steps[0].commands == ["https://addons.mozilla.org/firefox/addon/ublock-origin/"]
    assert g.steps[-1].title == "Not in Tor Browser"
    o = detect(cat, "br.content_blocking", make_scan(ff_machine(tmp_path / "b", "firefox.desktop", [UBO])))
    assert o.status is Status.PASS and ev(o)["Firefox profile abcd.default-release"] == "uBlock Origin"


def test_tor_browser_as_default_needs_nothing_added(cat, tmp_path):
    o = detect(cat, "br.content_blocking", make_scan(ff_machine(tmp_path, "torbrowser.desktop", [])))
    assert o.status is Status.PASS and ev(o)["Tor Browser"] == "no extensions, by design"


def test_chrome_with_ublock_lite_is_partial(cat, tmp_path):
    host = machine(tmp_path, default="google-chrome.desktop",
                   files={"/usr/share/applications/google-chrome.desktop": entry("Google Chrome")})
    prof = host.home / ".config/google-chrome/Default"
    ext = prof / f"Extensions/{browsers.UBO_LITE}/2026.1_0"
    ext.mkdir(parents=True)
    (prof / "Preferences").write_text("{}")
    (ext / "manifest.json").write_text(json.dumps({"name": "uBlock Origin Lite", "manifest_version": 3}))
    o = detect(cat, "br.content_blocking", make_scan(host))
    assert o.status is Status.WARN and "only uBlock Origin Lite" in o.summary
