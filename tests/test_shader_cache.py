"""br.shader_cache and br.start_script: the graphics drivers' shader caches, which websites can time to link Tor
Browser's and Mullvad Browser's visits (tor-browser#40054), blocked for each browser alone; and a browser started
without its own start script (the AUR's mullvad-browser-bin), given a menu entry that starts it through it. Each fix
applied, then reverted."""

from daprivacyscanner.catalogue import as_warning, effective_severity
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.browser import (SCRIPT_MARK, SHADER_BLOCK_TEXT, default_profile, mesa_blocked,
                                             shader_copies, started_by_script)
from daprivacyscanner.fix import apply_plan
from daprivacyscanner.model import Status
from daprivacyscanner.undo import UndoLog

from conftest import detect, make_host, make_scan
from test_fixes import redetect, revert

TOR_SCRIPT = "#!/bin/bash\nHOME=\"$browser_home\"\nexport HOME\n# tor-browser-build#41017\nexport __GL_SHADER_DISK_CACHE=0\n"
OLD_SCRIPT = "#!/bin/bash\nHOME=\"$browser_home\"\nexport HOME\n"
MESA = {"/usr/share/glvnd/egl_vendor.d/50_mesa.json": "{}"}
NVIDIA = {"/proc/driver/nvidia/version": "NVRM version: NVIDIA UNIX x86_64 Kernel Module  580.178.04\n"}
MESA_LABEL = "Mesa (Intel and AMD graphics, and drawing in software)"
# the AUR's mullvad-browser-bin 16.0.1-1, as installed (its program, its menu entry) beside Mullvad's own files
AUR_WRAPPER = """#!/bin/sh
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
USER_FLAGS_FILE="$XDG_CONFIG_HOME/mullvad-browser-flags.conf"
unset SESSION_MANAGER
export FONTCONFIG_PATH="/opt/mullvad-browser/fonts"
# tor-browser-build#41017: Nvidia drivers create a shader cache by default in
export __GL_SHADER_DISK_CACHE=0

exec /opt/mullvad-browser/mullvadbrowser "$@" $USER_FLAGS
"""
AUR_ENTRY = """[Desktop Entry]
Type=Application
Name=Mullvad Browser
Exec=mullvad-browser %u
Icon=mullvad-browser
Categories=Network;WebBrowser;
MimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;
Actions=new-window;new-private-window;profile-manager-window;

[Desktop Action new-window]
Name=New Window
Exec=mullvad-browser --new-window %u

[Desktop Action new-private-window]
Name=New Private Window
Exec=mullvad-browser --private-window %u

[Desktop Action profile-manager-window]
Name=Open Profile Manager
Exec=mullvad-browser --ProfileManager
"""
AUR_FILES = {"/usr/bin/mullvad-browser": AUR_WRAPPER, "/usr/share/applications/mullvad-browser.desktop": AUR_ENTRY,
             "/opt/mullvad-browser/start-mullvad-browser": TOR_SCRIPT, "/opt/mullvad-browser/is-packaged-app": "",
             "/opt/mullvad-browser/mullvadbrowser": "#!/bin/sh\nexec ./mullvadbrowser.real \"$@\"\n",
             "/opt/mullvad-browser/application.ini": "[App]\nVendor=Mullvad\nName=MullvadBrowser\nVersion=140.5.0\n"}
AUR_HOME = {".mullvad/mullvadbrowser/profiles.ini": "[InstallC25F7AA9AE98B831]\nDefault=hwtycokh.default-release\n"
                                                    "Locked=1\n\n[Profile0]\nName=default-release\nIsRelative=1\n"
                                                    "Path=hwtycokh.default-release\n\n[General]\nStartWithLastProfile=1\n",
            ".mullvad/mullvadbrowser/hwtycokh.default-release/prefs.js": "// prefs\n",
            ".cache/mullvad/mullvadbrowser/hwtycokh.default-release/cache2/entries/AB12": "x",
            ".cache/mesa_shader_cache/0a/" + "c" * 38: "shader of every program's"}


def tor_tarball(script=TOR_SCRIPT, cache_files=2):
    """A Tor Browser tarball registered in the menu (its own start-tor-browser.desktop), as the start script writes
    the entry, with Mesa's cache in its Browser folder (the HOME the script gives it)."""
    files = {"tor-browser/Browser/start-tor-browser": script,
             ".local/share/applications/start-tor-browser.desktop":
                 "[Desktop Entry]\nType=Application\nName=Tor Browser\nCategories=Network;WebBrowser;\n"
                 "Exec=sh -c '\"/home/alice/tor-browser/Browser/start-tor-browser\" || ([ !  -x "
                 "\"/home/alice/tor-browser/Browser/start-tor-browser\" ] && \"$(dirname \"$*\")\"/Browser/start-tor-browser)'"
                 " dummy %k\n"}
    for i in range(cache_files):
        files[f"tor-browser/Browser/.cache/mesa_shader_cache/a{i}/{i:040x}"] = "shader"
    return files


def host_with(tmp_path, home_files, files=None, **kw):
    host = make_host(tmp_path, home_files=home_files, files=files, **kw)
    # the fixture's menu entry names /home/alice; the fixture home is elsewhere: point the command at it
    entry = host.home / ".local/share/applications/start-tor-browser.desktop"
    if entry.exists():
        entry.write_text(entry.read_text().replace("/home/alice", str(host.home)))
    return host


def check(cat, cid="br.shader_cache"):
    return load_all()[cid](cat[cid])


def ev(o):
    return {e.label: e.value for e in o.evidence}


def apply(cat, host, cid):
    c = check(cat, cid)
    scan = make_scan(host)
    plan = c.plan_fix(scan, c.detect(scan))
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(plan, host, log, confirmed_irreversible=True)
    assert res.ok, res
    return plan, res, log


def test_not_applicable_without_either_browser(cat, tmp_path):
    host = make_host(tmp_path, files=MESA)
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.NOT_APPLICABLE and "in memory" in o.summary
    assert detect(cat, "br.start_script", make_scan(host)).status is Status.NOT_APPLICABLE


def test_mesa_s_cache_is_a_risk_of_seven_and_nvidia_s_is_turned_off_by_the_start_script(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(), files={**MESA, **NVIDIA})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": False, "blocked_until_update": False}
    assert o.summary.startswith("Websites could link your visits in Tor Browser: the graphics driver (Mesa)")
    e = ev(o)
    assert e["Tor Browser (~/tor-browser/Browser/start-tor-browser)"] == \
        "Mesa's cache on, in its own folder; NVIDIA's cache off in its start script"
    assert e["Tor Browser's shader cache (~/tor-browser/Browser/.cache/mesa_shader_cache)"].startswith("2 files")
    spec = cat["br.shader_cache"]
    sev = effective_severity(spec, o.findings)
    assert (sev.value, as_warning(spec, sev).value) == (9, 7)            # only ever a risk: 7


def test_nvidia_s_cache_counts_for_a_copy_whose_script_doesn_t_turn_it_off(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(OLD_SCRIPT, cache_files=0), files=NVIDIA)
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and "(NVIDIA)" in o.summary
    assert ev(o)["Tor Browser (~/tor-browser/Browser/start-tor-browser)"] == "NVIDIA's cache on"


def test_the_fix_blocks_mesa_for_the_browser_alone_then_reverts(cat, tmp_path):
    """The old cache deleted, a file put where each of Mesa's cache folders would be, in the browser's own folder:
    nothing in the session's environment, nothing for any other program."""
    host = host_with(tmp_path, tor_tarball(), files={**MESA, **NVIDIA})
    (host.home / ".profile").write_text("# mine\n")
    plan, res, log = apply(cat, host, "br.shader_cache")
    assert [a.kind for a in plan.actions] == ["delete", "file", "file"] and not plan.blockers
    assert any("next start" in s and "every other program" in s for s in plan.side_effects)
    cache = host.home / "tor-browser/Browser/.cache"
    for d in ("mesa_shader_cache", "mesa_shader_cache_db"):
        assert (cache / d).is_file() and (cache / d).read_text() == SHADER_BLOCK_TEXT
    assert (host.home / ".profile").read_text() == "# mine\n" and not (host.home / ".config/environment.d").exists()
    o = redetect(cat, host, "br.shader_cache")
    assert o.status is Status.PASS and o.summary == "The graphics drivers keep no shader cache for Tor Browser."
    assert ev(o)["Tor Browser (~/tor-browser/Browser/start-tor-browser)"].startswith("Mesa's cache blocked for it")
    c, scan = check(cat), make_scan(host)
    assert c.plan_fix(scan, c.detect(scan)).actions == []                 # nothing left to do
    assert all(r.ok for r in revert(host, log, res))
    assert not (cache / "mesa_shader_cache").exists() and not (cache / "mesa_shader_cache_db").exists()
    assert redetect(cat, host, "br.shader_cache").status is Status.WARN    # the deletion stays; the block is gone


def test_it_is_an_easy_fix_with_nothing_given_up(cat):
    assert cat["br.shader_cache"].easy is not None and cat["br.shader_cache"].easy.cost == ""
    assert cat["br.start_script"].easy is None                              # downloads move: not an easy one


def test_off_in_the_session_passes_and_an_old_cache_left_is_a_small_risk(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(cache_files=0), files={**MESA, **NVIDIA},
                     env={"__GL_SHADER_DISK_CACHE": "0", "MESA_SHADER_CACHE_DISABLE": "true"})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.PASS and ev(o)[MESA_LABEL] == "its shader cache off for every program " \
                                                            "(MESA_SHADER_CACHE_DISABLE=true)"
    host = host_with(tmp_path / "b", tor_tarball(), files=MESA, env={"MESA_SHADER_CACHE_DISABLE": "1"})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": True, "blocked_until_update": False}
    assert o.summary.endswith("the old one is still on the disk: Tor Browser.")
    spec = cat["br.shader_cache"]
    assert as_warning(spec, effective_severity(spec, o.findings)).value == 2
    plan, _, _ = apply(cat, host, "br.shader_cache")
    assert [a.kind for a in plan.actions] == ["delete"]                     # the old cache only: nothing to block


def test_a_running_browser_s_old_cache_waits(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(), files={**MESA, "/proc/7/comm": "firefox.real\n"})
    profile = host.home / "tor-browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite"
    profile.parent.mkdir(parents=True)
    profile.write_text("")
    (host.root / "proc/7/fd").mkdir(parents=True)
    (host.root / "proc/7/fd/4").symlink_to(profile)
    c, scan = check(cat), make_scan(host)
    plan = c.plan_fix(scan, c.detect(scan))
    assert plan.actions == [] and plan.blockers == ["Close Tor Browser first."]


def test_mullvad_s_package_and_torbrowser_launcher_s_flatpak(cat, tmp_path):
    """Mullvad's .deb: /usr/bin/mullvad-browser links to its script, which keeps the browser in ~/.mullvad-browser
    (is-packaged-app); torbrowser-launcher's Flatpak: its data folder, and Mesa's cache in the Flatpak's own."""
    flat = ".var/app/org.torproject.torbrowser-launcher"
    host = make_host(tmp_path, files={**MESA, "/usr/lib/mullvad-browser/start-mullvad-browser": TOR_SCRIPT,
                                      "/usr/lib/mullvad-browser/is-packaged-app": "",
                                      "/usr/share/applications/mullvad-browser.desktop":
                                          "[Desktop Entry]\nType=Application\nName=Mullvad Browser\nExec=mullvad-browser %u\n"
                                          "Categories=Network;WebBrowser;\n"},
                     links={"/usr/bin/mullvad-browser": "../lib/mullvad-browser/start-mullvad-browser"},
                     home_files={".mullvad-browser/.cache/mesa_shader_cache/index": "x",
                                 f"{flat}/data/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser": TOR_SCRIPT,
                                 f"{flat}/cache/mesa_shader_cache_db/part0/mesa_cache.db": "x"})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and "Mullvad Browser and Tor Browser" in o.summary
    e = ev(o)
    assert e["Mullvad Browser's shader cache (~/.mullvad-browser/.cache/mesa_shader_cache)"].startswith("1 file")
    assert e[f"Tor Browser's shader cache (~/{flat}/cache/mesa_shader_cache_db)"].startswith("1 file")
    plan, _, _ = apply(cat, host, "br.shader_cache")
    assert sorted(str(a.path.relative_to(host.home)) for a in plan.actions if a.kind == "file") == [
        ".mullvad-browser/.cache/mesa_shader_cache", ".mullvad-browser/.cache/mesa_shader_cache_db",
        f"{flat}/cache/mesa_shader_cache", f"{flat}/cache/mesa_shader_cache_db"]
    assert redetect(cat, host, "br.shader_cache").status is Status.PASS


def test_a_cache_the_session_shares_with_every_program_can_t_be_blocked_alone(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(cache_files=0), files=MESA, env={"XDG_CACHE_HOME": str(tmp_path / "xdg")})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and "Its cache is shared with your other programs" in {n.title for n in o.notes}
    c, scan = check(cat), make_scan(host)
    plan = c.plan_fix(scan, o)
    assert plan.actions == [] and "XDG_CACHE_HOME" in " ".join(plan.side_effects)


# ------------------------------------------------------------------ started without its start script

def test_the_aur_package_skips_the_start_script(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **AUR_FILES}, home_files=AUR_HOME)
    o = detect(cat, "br.start_script", make_scan(host))
    assert o.status is Status.FAIL and o.summary.startswith("Mullvad Browser is started without its own start script")
    e = ev(o)
    assert e["Mullvad Browser is started by"] == "/usr/bin/mullvad-browser, which skips /opt/mullvad-browser/start-mullvad-browser"
    assert e["Mullvad Browser's cache in yours (~/.cache/mullvad/mullvadbrowser)"].startswith("1 file")
    assert o.findings == {"shares_cache_with_browser": False}
    spec = cat["br.start_script"]
    assert effective_severity(spec, o.findings).value == 7
    # its shader cache is the shared one: nothing to block for it alone until it starts through its script
    s = detect(cat, "br.shader_cache", make_scan(host))
    assert s.status is Status.WARN and ev(s)["Mullvad Browser (/opt/mullvad-browser/start-mullvad-browser)"] == \
        "Mesa's cache on, the one every program shares (started without its start script)"
    assert "Started without its start script" in {n.title for n in s.notes}
    c, scan = check(cat), make_scan(host)
    plan = c.plan_fix(scan, s)
    assert plan.actions == [] and "br.start_script" in " ".join(plan.side_effects)


FIREFOX_ENTRY = "[Desktop Entry]\nType=Application\nName=Firefox\nExec=firefox %u\nCategories=Network;WebBrowser;\n"


def test_another_browser_sharing_the_cache_is_named_and_raises_it_to_eight(cat, tmp_path):
    """Firefox installed as a package keeps its graphics cache where the AUR's Mullvad Browser does: a website can link
    visits across the two (measured on the lab); a Flatpak keeps its own, and doesn't count."""
    host = make_host(tmp_path, files={**MESA, **AUR_FILES, "/usr/share/applications/firefox.desktop": FIREFOX_ENTRY},
                     home_files=AUR_HOME)
    o = detect(cat, "br.start_script", make_scan(host))
    assert o.status is Status.FAIL and o.findings == {"shares_cache_with_browser": True}
    assert o.summary.startswith("Mullvad Browser is started without its own start script: websites can link your "
                                "visits in it to your visits in Firefox through the graphics cache they share")
    assert ev(o)["Shares the graphics cache with"] == "Firefox"
    assert o.notes[0].title == "Linked with your other browsers" and o.notes[0].kind == "risk"
    assert effective_severity(cat["br.start_script"], o.findings).value == 8
    flat = make_host(tmp_path / "f", files={**MESA, **AUR_FILES}, home_files={
        **AUR_HOME, ".local/share/flatpak/exports/share/applications/org.mozilla.firefox.desktop": FIREFOX_ENTRY})
    o = detect(cat, "br.start_script", make_scan(flat))
    assert o.findings == {"shares_cache_with_browser": False} and "Shares the graphics cache with" not in ev(o)


def test_the_menu_entry_fix_starts_it_through_its_script_with_its_profile_then_reverts(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **AUR_FILES}, home_files=AUR_HOME)
    plan, res, log = apply(cat, host, "br.start_script")
    assert [a.kind for a in plan.actions] == ["file", "delete"] and plan.also == ["br.shader_cache"]
    assert any("~/.mullvad-browser/Downloads" in x for x in plan.side_effects)
    assert any("typed in a terminal" in x for x in plan.side_effects)
    mine = host.home / ".local/share/applications/mullvad-browser.desktop"
    text = mine.read_text()
    profile = host.home / ".mullvad/mullvadbrowser/hwtycokh.default-release"
    assert text.startswith(SCRIPT_MARK + "\n[Desktop Entry]\n")
    assert f"Exec=/opt/mullvad-browser/start-mullvad-browser --profile {profile} %u\n" in text
    assert f"Exec=/opt/mullvad-browser/start-mullvad-browser --profile {profile} --new-window %u\n" in text
    assert "Exec=/opt/mullvad-browser/start-mullvad-browser --ProfileManager\n" in text   # the profile manager chooses
    assert "Name=Mullvad Browser\n" in text and "MimeType=text/html;" in text
    assert not (host.home / ".cache/mullvad/mullvadbrowser").exists()
    assert (host.home / ".cache/mesa_shader_cache").is_dir()              # every program's: left alone
    assert redetect(cat, host, "br.start_script").status is Status.PASS
    # now its cache is its own, in ~/.mullvad-browser: the shader fix blocks it there
    assert [c.cache for c in shader_copies(make_scan(host), [])] == []   # found through the menu entry only
    s = detect(cat, "br.shader_cache", make_scan(host))
    assert s.status is Status.WARN and ev(s)["Mullvad Browser (/opt/mullvad-browser/start-mullvad-browser)"].startswith(
        "Mesa's cache on, in its own folder")
    splan, sres, slog = apply(cat, host, "br.shader_cache")
    assert all(a.path.parent == host.home / ".mullvad-browser/.cache" for a in splan.actions if a.kind == "file")
    assert redetect(cat, host, "br.shader_cache").status is Status.PASS
    assert all(r.ok for r in revert(host, slog, sres)) and all(r.ok for r in revert(host, log, res))
    assert not mine.exists() and redetect(cat, host, "br.start_script").status is Status.FAIL


def test_the_app_s_entry_is_redone_when_the_package_s_changes(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **AUR_FILES}, home_files=AUR_HOME)
    apply(cat, host, "br.start_script")
    system = host.root / "usr/share/applications/mullvad-browser.desktop"
    system.write_text(system.read_text().replace("Icon=mullvad-browser", "Icon=mullvad-browser-2"))
    o = detect(cat, "br.start_script", make_scan(host))
    assert o.status is Status.FAIL and "out of date" in o.summary
    plan, _, _ = apply(cat, host, "br.start_script")
    assert [a.kind for a in plan.actions] == ["file"]
    assert "Icon=mullvad-browser-2" in (host.home / ".local/share/applications/mullvad-browser.desktop").read_text()
    assert redetect(cat, host, "br.start_script").status is Status.PASS


def test_a_copy_started_through_its_script_passes(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(cache_files=0), files=MESA)
    assert detect(cat, "br.start_script", make_scan(host)).status is Status.PASS


def test_started_by_script_keeps_the_entry_and_quotes_paths():
    text = "[Desktop Entry]\nName=X\nTryExec=mullvad-browser\nExec=env A=1 mullvad-browser %u\n"
    out = started_by_script(text, "/opt/m b/start-mullvad-browser", None)
    assert out == (f"{SCRIPT_MARK}\n[Desktop Entry]\nName=X\nTryExec=/opt/m b/start-mullvad-browser\n"
                   "Exec=env A=1 \"/opt/m b/start-mullvad-browser\" %u\n")
    assert started_by_script(out, "/opt/m b/start-mullvad-browser", None).count(SCRIPT_MARK) == 1


def test_the_default_profile(tmp_path):
    host = make_host(tmp_path, home_files={"p/profiles.ini": "[Profile0]\nPath=a.default\nIsRelative=1\n\n"
                                                             "[Profile1]\nPath=b.other\nIsRelative=1\nDefault=1\n",
                                           "p/a.default/prefs.js": "", "p/b.other/prefs.js": ""})
    assert default_profile(host, host.home / "p") == host.home / "p/b.other"
    assert default_profile(host, host.home / "none") is None


def test_mesa_blocked_needs_a_file_where_each_folder_would_be(tmp_path):
    from daprivacyscanner.checks.browser import BrowserCopy
    c = BrowserCopy("Tor Browser", None, tmp_path, tmp_path)
    (tmp_path / "mesa_shader_cache").write_text("x")
    assert not mesa_blocked(c)
    (tmp_path / "mesa_shader_cache_db").mkdir()
    assert not mesa_blocked(c)
    (tmp_path / "mesa_shader_cache_db").rmdir()
    (tmp_path / "mesa_shader_cache_db").symlink_to("/dev/null")
    assert mesa_blocked(c)


# ------------------------------------------------------------------ the AUR's tor-browser-bin, unpacked again at updates

from pathlib import Path  # noqa: E402

from daprivacyscanner.checks.browser import SHADER_ENTRY_MARK, installed_browsers, no_shader_cache_entry  # noqa: E402

TOR_BIN = (Path(__file__).parent / "samples/aur/tor-browser-bin-16.0.1-1.sh").read_text()
# tor-browser-alpha-bin 16.0a13-1's: the same script, its variables renamed and its own package name
TOR_ALPHA = TOR_BIN.replace("_TB_", "_TA_").replace("_TA_PKGNAME_='tor-browser'", "_TA_PKGNAME_='tor-browser-alpha-bin'")
TOR_BIN_ENTRY = ("[Desktop Entry]\nVersion=1.0\nType=Application\nName=Tor Browser\nExec=tor-browser %u\nIcon=tor-browser\n"
                 "Categories=Network;WebBrowser;Security;\nStartupWMClass=tor-browser\n")
TOR_BIN_FILES = {"/usr/bin/tor-browser": TOR_BIN, "/usr/share/applications/tor-browser.desktop": TOR_BIN_ENTRY,
                 "/opt/tor-browser/tor-browser-linux-x86_64-16.0.1.tar.xz": "x"}
APP = ".local/opt/tor-browser/app"


def unpacked(cache_files=2, name="tor-browser"):
    """What tor-browser.in leaves in the home folder after a start: VERSION, LOG and the browser in app/."""
    files = {f".local/opt/{name}/VERSION": "16.0.1\n", f".local/opt/{name}/LOG": "",
             f".local/opt/{name}/app/Browser/start-tor-browser": TOR_SCRIPT}
    for i in range(cache_files):
        files[f".local/opt/{name}/app/Browser/.cache/mesa_shader_cache/a{i}/{i:040x}"] = "shader"
    return files


def update(host, name="tor-browser"):
    """What tor-browser.in does at the first start after an update: app/ emptied (rm -rf app/*), the new version
    unpacked into it."""
    import shutil
    app = host.home / f".local/opt/{name}/app"
    for p in app.iterdir():
        shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
    (app / "Browser").mkdir()
    (app / "Browser/start-tor-browser").write_text(TOR_SCRIPT)


def test_tor_browser_bin_is_tor_browser_and_its_copy_is_the_one_it_unpacks(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **NVIDIA, **TOR_BIN_FILES}, home_files=unpacked())
    scan = make_scan(host)
    found = [f for f in installed_browsers(scan) if f.name == "Tor Browser"]
    assert [f.key for f in found] == ["tor_browser"]                     # not a browser the app doesn't know
    [c] = shader_copies(scan, found)
    assert (c.script, c.cache) == (host.home / APP / "Browser/start-tor-browser", host.home / APP / "Browser/.cache")
    assert c.unpacked_by == host.root / "usr/bin/tor-browser" and c.entry.name == "tor-browser.desktop"
    o = detect(cat, "br.shader_cache", scan)
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": False, "blocked_until_update": False}
    assert ev(o)[f"Tor Browser (~/{APP}/Browser/start-tor-browser)"] == \
        "Mesa's cache on, in its own folder; NVIDIA's cache off in its start script"
    assert detect(cat, "br.start_script", scan).status is Status.PASS     # it runs its start script


def test_its_fix_adds_a_menu_entry_its_updates_can_t_undo_then_reverts(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **TOR_BIN_FILES}, home_files=unpacked())
    plan, res, log = apply(cat, host, "br.shader_cache")
    assert [a.kind for a in plan.actions] == ["file", "delete", "file", "file"]
    assert any("Typed in a terminal, tor-browser starts it as before" in s for s in plan.side_effects)
    mine = host.home / ".local/share/applications/tor-browser.desktop"
    text = mine.read_text()
    assert text.startswith(SHADER_ENTRY_MARK + "\n[Desktop Entry]\n")
    assert "\nExec=env MESA_SHADER_CACHE_DISABLE=true __GL_SHADER_DISK_CACHE=0 tor-browser %u\n" in text
    assert "\nName=Tor Browser\n" in text and "\nIcon=tor-browser\n" in text
    o = redetect(cat, host, "br.shader_cache")
    assert o.status is Status.PASS and "Typed in a terminal" in {n.title for n in o.notes}
    assert ev(o)[f"Tor Browser (~/{APP}/Browser/start-tor-browser)"] == \
        "Mesa's cache off when started from the menu, also after its package unpacks it again; blocked in its folder too"
    # the package's next update empties app/, the block with it: started from the menu the cache stays off
    update(host)
    assert not (host.home / APP / "Browser/.cache").exists()
    o = redetect(cat, host, "br.shader_cache")
    assert o.status is Status.PASS and ev(o)[f"Tor Browser (~/{APP}/Browser/start-tor-browser)"] == \
        "Mesa's cache off when started from the menu, also after its package unpacks it again"
    # started from a terminal since, Mesa made a cache there: an old one, and the fix blocks it again
    (host.home / APP / "Browser/.cache/mesa_shader_cache/a0").mkdir(parents=True)
    (host.home / APP / "Browser/.cache/mesa_shader_cache/a0/f").write_text("shader")
    o = redetect(cat, host, "br.shader_cache")
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": True, "blocked_until_update": False}
    assert as_warning(cat["br.shader_cache"], effective_severity(cat["br.shader_cache"], o.findings)).value == 2
    assert all(r.ok for r in revert(host, log, res))
    assert not mine.exists() and redetect(cat, host, "br.shader_cache").status is Status.WARN


def test_a_block_alone_lasts_until_the_next_update_and_the_fix_adds_the_entry(cat, tmp_path):
    """As 0.1.0b7's fix left it: the block in app/, no menu entry of the app's."""
    home = {**unpacked(cache_files=0), f"{APP}/Browser/.cache/mesa_shader_cache": SHADER_BLOCK_TEXT,
            f"{APP}/Browser/.cache/mesa_shader_cache_db": SHADER_BLOCK_TEXT}
    host = make_host(tmp_path, files={**MESA, **TOR_BIN_FILES}, home_files=home)
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": False, "blocked_until_update": True}
    assert o.summary == ("Mesa's cache is blocked for Tor Browser only until its package's next update, which unpacks "
                         "the browser again and removes the block.")
    spec = cat["br.shader_cache"]
    assert as_warning(spec, effective_severity(spec, o.findings)).value == 4
    plan, _, _ = apply(cat, host, "br.shader_cache")
    assert [a.kind for a in plan.actions] == ["file"]                     # the entry: the block is there already
    assert redetect(cat, host, "br.shader_cache").status is Status.PASS


def test_one_not_started_yet_gets_the_entry_before_its_first_start(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **NVIDIA, **TOR_BIN_FILES})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and ev(o)[f"Tor Browser (~/{APP}/Browser/start-tor-browser)"] == (
        "Mesa's cache on from its first start, in its own folder (not started yet); NVIDIA's cache: its start script "
        "decides, from its first start (not started yet)")
    plan, _, _ = apply(cat, host, "br.shader_cache")
    assert [a.kind for a in plan.actions] == ["file"] and not (host.home / ".local/opt").exists()
    o = redetect(cat, host, "br.shader_cache")
    assert o.status is Status.PASS and ev(o)[f"Tor Browser (~/{APP}/Browser/start-tor-browser)"] == (
        "Mesa's cache off when started from the menu, also after its package unpacks it again; NVIDIA's cache off when "
        "started from the menu")


def test_the_alpha_package_s_copy(cat, tmp_path):
    entry = TOR_BIN_ENTRY.replace("Name=Tor Browser", "Name=Tor Browser Alpha")
    host = make_host(tmp_path, files={**MESA, "/usr/bin/tor-browser": TOR_ALPHA,
                                      "/usr/share/applications/tor-browser-alpha-bin.desktop": entry},
                     home_files=unpacked(name="tor-browser-alpha-bin"))
    [c] = shader_copies(make_scan(host), [f for f in installed_browsers(make_scan(host)) if f.key == "tor_browser"])
    assert c.script == host.home / ".local/opt/tor-browser-alpha-bin/app/Browser/start-tor-browser"
    plan, _, _ = apply(cat, host, "br.shader_cache")
    assert (host.home / ".local/share/applications/tor-browser-alpha-bin.desktop").read_text().startswith(SHADER_ENTRY_MARK)
    assert redetect(cat, host, "br.shader_cache").status is Status.PASS


def test_the_app_s_entry_is_redone_when_the_package_s_changes_and_a_copy_without_one_is_still_found(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **TOR_BIN_FILES}, home_files=unpacked())
    apply(cat, host, "br.shader_cache")
    system = host.root / "usr/share/applications/tor-browser.desktop"
    system.write_text(system.read_text().replace("Icon=tor-browser", "Icon=tor-browser-2"))
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and o.findings["blocked_until_update"]  # out of date: the block alone lasts
    plan, _, _ = apply(cat, host, "br.shader_cache")
    assert [a.kind for a in plan.actions] == ["file"]
    assert "Icon=tor-browser-2" in (host.home / ".local/share/applications/tor-browser.desktop").read_text()
    assert redetect(cat, host, "br.shader_cache").status is Status.PASS
    # no menu entry: the copy in ~/.local/opt is still found, and blocked in its folder only
    bare = make_host(tmp_path / "b", files=MESA, home_files=unpacked())
    [c] = shader_copies(make_scan(bare), [])
    assert c.unpacked_by is None and c.script == bare.home / APP / "Browser/start-tor-browser"


def test_tor_browser_bin_doesn_t_share_mullvad_browser_s_cache(cat, tmp_path):
    host = make_host(tmp_path, files={**MESA, **AUR_FILES, **TOR_BIN_FILES}, home_files={**AUR_HOME, **unpacked()})
    o = detect(cat, "br.start_script", make_scan(host))
    assert o.status is Status.FAIL and o.findings == {"shares_cache_with_browser": False}


def test_mullvad_browser_latest_bin_skips_the_script_and_leaves_nvidia_s_cache_on(cat, tmp_path):
    """The AUR's mullvad-browser-latest-bin 16.0.1-1: its program runs the browser's own, without the start script,
    and doesn't turn NVIDIA's cache off either."""
    wrapper = ('#!/bin/sh\n\nXDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"\n\n'
               'USER_FLAGS_FILE="$XDG_CONFIG_HOME/mullvad-browser-flags.conf"\n\n'
               'exec /opt/mullvad-browser/mullvadbrowser "$@" $USER_FLAGS\n')
    files = {**MESA, **NVIDIA, **AUR_FILES, "/usr/bin/mullvad-browser": wrapper}
    files.pop("/opt/mullvad-browser/is-packaged-app")
    host = make_host(tmp_path, files={**files, "/opt/mullvad-browser/system-install": ""}, home_files=AUR_HOME)
    o = detect(cat, "br.start_script", make_scan(host))
    assert o.status is Status.FAIL and ev(o)["Mullvad Browser is started by"] == \
        "/usr/bin/mullvad-browser, which skips /opt/mullvad-browser/start-mullvad-browser"
    s = detect(cat, "br.shader_cache", make_scan(host))
    assert ev(s)["Mullvad Browser (/opt/mullvad-browser/start-mullvad-browser)"].endswith("NVIDIA's cache on")
    # without is-packaged-app the script makes /opt/mullvad-browser, root's, the browser's home: no fix through it
    folder = host.root / "opt/mullvad-browser"
    folder.chmod(0o555)
    try:
        for cid, said in (("br.start_script", "without is-packaged-app"), ("br.shader_cache", "can't be started through")):
            c, scan = check(cat, cid), make_scan(host)
            plan = c.plan_fix(scan, c.detect(scan))
            assert plan.actions == [] and said in " ".join(plan.side_effects), (cid, plan.side_effects)
    finally:
        folder.chmod(0o755)
    # a copy of the user's own there (the folder theirs to write to): through the script, which turns NVIDIA's off
    plan, _, _ = apply(cat, host, "br.start_script")
    assert "start-mullvad-browser --profile" in (host.home / ".local/share/applications/mullvad-browser.desktop").read_text()
    assert ev(redetect(cat, host, "br.shader_cache"))["Mullvad Browser (/opt/mullvad-browser/start-mullvad-browser)"] \
        .endswith("NVIDIA's cache off in its start script")


def test_no_shader_cache_entry_runs_each_command_through_env_once():
    text = "[Desktop Entry]\nName=X\nTryExec=tor-browser\nExec=tor-browser %u\n\n[Desktop Action w]\nExec=env A=1 x -w\n"
    out = no_shader_cache_entry(text)
    pre = "env MESA_SHADER_CACHE_DISABLE=true __GL_SHADER_DISK_CACHE=0 "
    assert out == (f"{SHADER_ENTRY_MARK}\n[Desktop Entry]\nName=X\nTryExec=tor-browser\nExec={pre}tor-browser %u\n\n"
                   f"[Desktop Action w]\nExec={pre}env A=1 x -w\n")
    assert no_shader_cache_entry(out) == out
