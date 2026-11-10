"""br.shader_cache: the graphics drivers' shader caches, which websites can time to link Tor Browser's and Mullvad
Browser's visits (tor-browser#40054); the Easy fix that turns them off and deletes the old one, then reverted."""

from daprivacyscanner.catalogue import as_warning, effective_severity
from daprivacyscanner.checks import load_all
from daprivacyscanner.checks.browser import SHADER_ENV_FILE, SHADER_LINE, SHADER_MARK, with_shader_block
from daprivacyscanner.fix import apply_plan
from daprivacyscanner.model import Status
from daprivacyscanner.undo import UndoLog

from conftest import detect, make_host, make_scan
from test_fixes import redetect, revert

TOR_SCRIPT = "#!/bin/bash\nHOME=\"$browser_home\"\nexport HOME\n# tor-browser-build#41017\nexport __GL_SHADER_DISK_CACHE=0\n"
OLD_SCRIPT = "#!/bin/bash\nHOME=\"$browser_home\"\nexport HOME\n"
MESA = {"/usr/share/glvnd/egl_vendor.d/50_mesa.json": "{}"}
NVIDIA = {"/proc/driver/nvidia/version": "NVRM version: NVIDIA UNIX x86_64 Kernel Module  580.178.04\n"}
PROFILE = "# ~/.profile: executed by the command interpreter for login shells.\nexport PATH=\"$HOME/bin:$PATH\"\n"


def tor_tarball(script=TOR_SCRIPT, cache_files=2):
    """A Tor Browser tarball registered in the menu (its own start-tor-browser.desktop), as the start script writes
    the entry, with Mesa's cache in its Browser folder (the HOME the script gives it)."""
    files = {"tor-browser/Browser/start-tor-browser": script,
             ".local/share/applications/start-tor-browser.desktop":
                 "[Desktop Entry]\nType=Application\nName=Tor Browser\nCategories=Network;WebBrowser;\n"
                 "Exec=sh -c '\"/home/alice/tor-browser/Browser/start-tor-browser\" || ([ !  -x "
                 "\"/home/alice/tor-browser/Browser/start-tor-browser\" ] && \"$(dirname \"$*\")\"/Browser/start-tor-browser)'"
                 " dummy %k\n",
             ".profile": PROFILE}
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


def check(cat):
    return load_all()["br.shader_cache"](cat["br.shader_cache"])


def ev(o):
    return {e.label: e.value for e in o.evidence}


def test_not_applicable_without_either_browser(cat, tmp_path):
    o = detect(cat, "br.shader_cache", make_scan(make_host(tmp_path, files=MESA)))
    assert o.status is Status.NOT_APPLICABLE and "in memory" in o.summary


def test_mesa_s_cache_is_a_risk_of_seven_and_nvidia_s_is_turned_off_by_the_start_script(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(), files={**MESA, **NVIDIA})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": False}
    assert o.summary.startswith("Websites could link your visits in Tor Browser: the graphics driver (Mesa)")
    e = ev(o)
    assert e["Mesa's shader cache (Intel and AMD graphics, and drawing in software)"] == "on"
    assert e["NVIDIA's shader cache"] == "on, but Tor Browser turns it off in the start script"
    assert e["Tor Browser's old shader cache (~/tor-browser/Browser/.cache/mesa_shader_cache)"].startswith("2 files")
    spec = cat["br.shader_cache"]
    sev = effective_severity(spec, o.findings)
    assert (sev.value, as_warning(spec, sev).value) == (9, 7)            # only ever a risk: 7


def test_nvidia_s_cache_counts_for_a_copy_whose_script_doesn_t_turn_it_off(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(OLD_SCRIPT, cache_files=0), files=NVIDIA)
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and "(NVIDIA)" in o.summary and ev(o)["NVIDIA's shader cache"] == "on"


def test_off_in_the_session_passes(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(cache_files=0), files={**MESA, **NVIDIA},
                     env={"__GL_SHADER_DISK_CACHE": "0", "MESA_SHADER_CACHE_DISABLE": "true"})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.PASS and o.summary == "The graphics drivers keep no shader cache for Tor Browser."
    assert ev(o)["Mesa's shader cache (Intel and AMD graphics, and drawing in software)"] == \
        "off (MESA_SHADER_CACHE_DISABLE=true)"


def test_only_an_old_cache_left_is_a_small_risk(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(), files=MESA, env={"MESA_SHADER_CACHE_DISABLE": "1"})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and o.findings == {"old_shader_cache_only": True}
    assert o.summary.endswith("the old one is still on the disk: Tor Browser.")
    spec = cat["br.shader_cache"]
    assert as_warning(spec, effective_severity(spec, o.findings)).value == 2


def test_fix_turns_both_off_for_every_session_and_deletes_the_old_cache_then_reverts(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(), files={**MESA, **NVIDIA})
    c = check(cat)
    scan = make_scan(host)
    plan = c.plan_fix(scan, c.detect(scan))
    assert [a.kind for a in plan.actions] == ["file", "file", "delete"] and not plan.blockers
    assert any("next login" in s for s in plan.side_effects) and any("stutter" in s for s in plan.side_effects)
    log = UndoLog(host.home / ".local/state/daprivacyscanner")
    res = apply_plan(plan, host, log, confirmed_irreversible=True)
    assert res.ok, res
    env_file = host.home / ".config/environment.d" / SHADER_ENV_FILE
    assert "__GL_SHADER_DISK_CACHE=0\nMESA_SHADER_CACHE_DISABLE=true\n" in env_file.read_text()
    profile = (host.home / ".profile").read_text()
    assert profile.startswith(PROFILE) and profile.endswith(f"\n{SHADER_MARK}\n{SHADER_LINE}\n")
    assert not list((host.home / "tor-browser/Browser/.cache/mesa_shader_cache").rglob("*0*"))
    o = redetect(cat, host, "br.shader_cache")
    assert o.status is Status.PASS and "From your next login" in {n.title for n in o.notes}
    assert ev(o)["Mesa's shader cache (Intel and AMD graphics, and drawing in software)"] == "off from your next login"
    # applied again (the next login not yet come): nothing left to do
    scan = make_scan(host)
    assert c.plan_fix(scan, c.detect(scan)).actions == []
    assert all(r.ok for r in revert(host, log, res))
    assert (host.home / ".profile").read_text() == PROFILE and not env_file.exists()


def test_the_profile_block_replaces_its_own_and_keeps_the_rest():
    once = with_shader_block(PROFILE)
    assert with_shader_block(once) == once and once.count(SHADER_MARK) == 1
    assert with_shader_block(None) == f"{SHADER_MARK}\n{SHADER_LINE}\n"


def test_a_running_browser_s_old_cache_waits(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(), files={**MESA, "/proc/7/comm": "firefox.real\n"},
                     env={"__GL_SHADER_DISK_CACHE": "0", "MESA_SHADER_CACHE_DISABLE": "true"})
    profile = host.home / "tor-browser/Browser/TorBrowser/Data/Browser/profile.default/places.sqlite"
    profile.parent.mkdir(parents=True)
    profile.write_text("")
    (host.root / "proc/7/fd").mkdir(parents=True)
    (host.root / "proc/7/fd/4").symlink_to(profile)
    c = check(cat)
    scan = make_scan(host)
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
    assert e["Mullvad Browser's start script"] == "/usr/lib/mullvad-browser/start-mullvad-browser"
    assert e["Mullvad Browser's old shader cache (~/.mullvad-browser/.cache/mesa_shader_cache)"].startswith("1 file")
    assert e[f"Tor Browser's old shader cache (~/{flat}/cache/mesa_shader_cache_db)"].startswith("1 file")


def test_a_cache_the_session_shares_with_every_program_is_named_not_deleted(cat, tmp_path):
    host = host_with(tmp_path, tor_tarball(cache_files=0), files=MESA, env={"XDG_CACHE_HOME": str(tmp_path / "xdg")})
    o = detect(cat, "br.shader_cache", make_scan(host))
    assert o.status is Status.WARN and "Its cache is shared with your other programs" in {n.title for n in o.notes}
