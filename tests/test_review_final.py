"""What was left after the area fixes of the review of 2026-10-17: the online dnf test kept away from the home folder,
LLMNR's note only where resolved answers, sleep states, npm's passwords, disabled repositories, KDE Wallet."""

from daprivacyscanner import network
from daprivacyscanner.context import detect_exposed_services
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan, sample
from test_online import FakeNet, run
from test_review_enc import _dnf5_host
from test_review_net import RESOLVED_MDNS
from test_box import host  # noqa: F401  (a fixture: a machine with a Box's apps)


def test_the_online_dnf_test_downloads_into_memory_not_the_home_folder(cat, tmp_path):
    """dnf5 --refresh as the user downloads the lists into ~/.cache/libdnf5 (100 MB and more), and they stay there."""
    host, calls = _dnf5_host(tmp_path)
    host.runner.installed.update({"dnf", "dnf5"})           # no /usr/bin/dnf link to say otherwise: DNF5
    run(cat, "kern.updates_refreshed", host, FakeNet())
    assert calls and all(c[0] == "dnf5" and any(a.startswith(f"--setopt=cachedir={tmp_path}/run/") for a in c)
                         and "-C" not in c for c in calls)
    assert "--refresh" in calls[0]
    assert list((tmp_path / "run").iterdir()) == [] and not (host.home / ".cache").exists()


def test_llmnr_that_only_asks_gets_no_warning(tmp_path):
    """Fedora's LLMNR=resolve listens on 5355 and answers no one: the context's note said it answers any network."""
    host = make_host(tmp_path, commands={network.SS_ARGS: sample("ss/fedora-40.txt"), "resolvectl status": RESOLVED_MDNS})
    assert not any(n.title.startswith("LLMNR") for n in detect_exposed_services(host).notes)
    host = make_host(tmp_path / "b", commands={network.SS_ARGS: sample("ss/fedora-40.txt"),
                                               "resolvectl status": RESOLVED_MDNS.replace("LLMNR=resolve", "+LLMNR")})
    assert detect_exposed_services(host).notes[0].title.startswith("LLMNR")


def test_suspend_to_idle_keeps_the_keys_in_memory_too(cat, tmp_path):
    host = make_host(tmp_path, files={"/sys/power/state": "freeze disk\n"})
    o = detect(cat, "kern.suspend_keys_in_ram", make_scan(host))
    assert o.status is Status.FAIL
    host = make_host(tmp_path / "b", files={"/sys/power/state": "disk\n"})
    assert detect(cat, "kern.suspend_keys_in_ram", make_scan(host)).status is Status.PASS


def test_npm_passwords_count_as_well_as_tokens(cat, tmp_path):
    for line, found in (("//registry.example/:_auth=dXNlcjpwYXNz\n", True), ("_password=c2VjcmV0\n", True),
                        ("//registry.example/:_password=${NPM_PASSWORD}\n", False)):
        host = make_host(tmp_path / str(hash(line)), home_files={".npmrc": line})
        o = detect(cat, "auth.plaintext_credentials", make_scan(host))
        assert (o.status is Status.FAIL) is found, line
        if found:
            assert any(k.startswith("npm token or password") for k in ev(o))


def test_disabled_repositories_are_never_contacted(cat, tmp_path):
    deb822 = ("Types: deb\nURIs: https://archive.example/ubuntu\nSuites: noble\nComponents: main\n\n"
              "Types: deb\nURIs: http://old.example/ubuntu\nSuites: noble\nComponents: main\nEnabled: no\n")
    host = make_host(tmp_path, files={"/etc/apt/sources.list.d/ubuntu.sources": deb822})
    assert detect(cat, "tel.http_repos", make_scan(host)).status is Status.PASS
    repo = "[on]\nbaseurl=https://a.example/\nenabled=1\n\n[off]\nbaseurl=http://b.example/\nenabled=0\n"
    host = make_host(tmp_path / "b", files={"/etc/yum.repos.d/x.repo": repo})
    assert detect(cat, "tel.http_repos", make_scan(host)).status is Status.PASS


def test_kde_wallet_is_a_keyring_for_chromium_on_plasma(cat, tmp_path):
    """On Plasma, Chromium keeps its key in KDE Wallet through kwalletd's own name, Secret Service or not."""
    from test_checks_telemetry_browser import chrome
    bus = ":1.2 123 kwalletd6 user :1.2 session - -\norg.kde.kwalletd6 123 kwalletd6 user :1.2 session - -\n"
    host = make_host(tmp_path, commands={"busctl --user list": bus})
    chrome(host.home)
    o = detect(cat, "auth.chromium_basic_store", make_scan(host, desktop=("kde",), plasma_major=6))
    assert o.status is Status.PASS and ev(o)["KDE Wallet on the session bus"] is True
    o = detect(cat, "auth.chromium_basic_store", make_scan(host, desktop=("x-cinnamon",)))
    assert o.status is Status.FAIL and "KDE Wallet on Plasma" in o.summary


def test_a_change_two_checks_offer_is_listed_once_in_easy_fixes(cat, tmp_path, monkeypatch):
    """Ubuntu: turning apport off is the Easy fix of crash dumps and of crash reporting. Applied twice it was two
    History entries, and reverting one had the other reported undone: it is listed once, the other check saying so."""
    from test_easy import H, easy_client
    from daprivacyscanner.runner import Runner
    c, host, gs = easy_client(cat, tmp_path)
    real = Runner.plan_easy

    def twice(self, check_ids=None):
        items = real(self, check_ids)
        items[1][1][0].actions = list(items[0][1][0].actions)        # the same change, offered by both
        return items
    monkeypatch.setattr(Runner, "plan_easy", twice)
    items = c.post("/api/easy/plan", headers=H).json()["items"]
    first, second = items[0], items[1]
    assert second["plans"] == [] and second["covered_by"] == first["title"] and not second["blockers"]
    assert any(second["title"] in s for s in first["plans"][0]["side_effects"])


def test_a_root_change_put_back_by_hand_reverts_without_a_conflict(tmp_path, monkeypatch):
    """dmesg_restrict set back with sysctl -w, a drop-in deleted by hand: reverting said "changed since" and needed
    force (live on Mint), though everything was already as before."""
    import json as _json
    from daprivacyscanner import helper
    from fakes import FakeSystem
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(root))
    monkeypatch.setattr(helper, "RUN", FakeSystem())

    def call(action, **args):
        return helper.handle(_json.dumps({"id": 1, "action": action, "args": args}))["result"]
    knob = root / "proc/sys/kernel/dmesg_restrict"
    knob.parent.mkdir(parents=True)
    knob.write_text("0\n")
    r = call("set_sysctl", key="kernel.dmesg_restrict", value="1")
    knob.write_text("0")                                                # put back by hand
    back = call("revert", change_id=r["change_id"])
    assert back["ok"] and not back.get("conflict") and knob.read_text().strip() == "0"
    r = call("write_dropin", name="coredump", settings={"Storage": "none"})
    f = root / "etc/systemd/coredump.conf.d/60-daprivacyscanner.conf"
    f.unlink()                                                          # deleted by hand
    back = call("revert", change_id=r["change_id"])
    assert back["ok"] and not back.get("conflict") and "already as it was before" in back["message"] and not f.exists()
    r = call("set_sysctl", key="kernel.dmesg_restrict", value="1")
    knob.write_text("2")                                                # changed to something else: still a conflict
    assert call("revert", change_id=r["change_id"]).get("conflict")


def test_avahi_is_masked_so_cups_browsed_cant_start_it_again(cat, tmp_path, monkeypatch):
    """Mint: cups-browsed's Wants=avahi-daemon.service started a disabled Avahi at every boot and restart of cups-browsed;
    the guide offered it again, and the revert then saw a conflict. Masked, nothing starts it; reverting unmasks it."""
    import json as _json
    from daprivacyscanner import helper
    from fakes import FakeSystem
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(root))
    system = FakeSystem(units={"avahi-daemon.socket": ["enabled", "active"], "avahi-daemon.service": ["enabled", "active"]})
    monkeypatch.setattr(helper, "RUN", system)

    def call(action, **args):
        return helper.handle(_json.dumps({"id": 1, "action": action, "args": args}))
    r = call("set_service", units=["avahi-daemon.socket", "avahi-daemon.service"], enable=False, start=False, mask=True)
    assert r["ok"], r
    assert system.units["avahi-daemon.service"] == ["masked", "inactive"]
    assert ["systemctl", "mask", "avahi-daemon.socket", "avahi-daemon.service"] in system.calls
    back = call("revert", change_id=r["result"]["change_id"])["result"]
    assert back["ok"] and system.units["avahi-daemon.service"] == ["enabled", "active"]
    assert not call("set_service", unit="avahi-daemon.service", enable=True, start=None, mask=True)["ok"]   # mask turns off only
    assert "systemctl mask avahi-daemon.socket avahi-daemon.service" in helper.planned(
        "set_service", {"units": ["avahi-daemon.socket", "avahi-daemon.service"], "enable": False, "start": False,
                        "mask": True})


def test_cups_offers_only_what_changes_something_and_a_noop_leaves_no_entry(cat, tmp_path):
    """After "Keep neither", both options were offered again, and applying one made an empty History entry."""
    from daprivacyscanner.fix import FixPlan, RootChange, apply_plan
    from daprivacyscanner.model import Evidence, Outcome
    from daprivacyscanner.privileged import FakePrivileged
    from daprivacyscanner.undo import UndoLog
    from test_guides import options
    from daprivacyscanner.checks import load_all
    check = load_all()["app.cups_spool"](cat["app.cups_spool"])
    scan = make_scan(make_host(tmp_path))

    def guide(files, history):
        o = Outcome(Status.PASS, "", [Evidence.val("PreserveJobFiles", files), Evidence.val("PreserveJobHistory", history)])
        return check.plan_guide(scan, o)
    g = guide("No", "No")
    assert not options(g) and g.steps[0].done
    g = guide("No", "1d")
    assert list(options(g)) == ["Keep neither documents nor job history"] and g.steps[0].done
    g = guide("86400 (default: one day)", "Yes (default)")
    assert len(options(g)) == 2 and not g.steps[0].done

    class AlreadySo(FakePrivileged):
        def call(self, action, args, timeout=None):
            return {"changed": False}
    host = make_host(tmp_path / "b")
    host.privileged = AlreadySo()
    log = UndoLog(host.home / "log")
    res = apply_plan(FixPlan("app.cups_spool", "t", [RootChange("edit_config", {"target": "cups", "values": {}}, "Set")]),
                     host, log)
    assert res.ok and res.entry_id is None and log.entries() == []


def test_a_box_launcher_told_to_end_records_the_run_and_cleans_up(host, monkeypatch):
    """At logout the launcher gets SIGTERM: Python's default skipped the clean-up and the run's record (live on Mint).
    box_cli turns it into SystemExit, which run_to_end lets through only after stopping, recording and cleaning up."""
    from types import SimpleNamespace
    import pytest
    from daprivacyscanner.tools import box as B, trial
    from test_box import a_box, set_up
    set_up(host, a_box())
    box = B.read(host, "chat-app")
    calls = []

    def told(h, t):
        calls.append(1)
        raise SystemExit(143)
    monkeypatch.setattr(trial, "poll", told)
    with pytest.raises(SystemExit):
        B.run_to_end(host, box, lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None, poll=lambda: None),
                     wait=0.01)
    assert calls and len(B.runs(host, "chat-app")["runs"]) == 1
    assert not B.running(host, "chat-app")


# an empty GVFS metadata database, as gvfsd-metadata writes one as it starts (from Mint): a root "/", no files, no keys
GVFS_EMPTY_DB = bytes.fromhex("da1a6d657461010000000000" "56f7b6a5" "0000002400000020" "0000000000000000"
                              "00000000" "00000034000000380000003c" "00000000" "2f000000" "0000000000000000")
GVFS_JOURNAL = lambda n: bytes.fromhex("da1a6a6f75720100" + "4e91bf3b" + "00008000") + n.to_bytes(4, "big") + bytes(32748)  # noqa: E731


def test_an_empty_gvfs_database_is_no_metadata_kept(cat, tmp_path):
    """After the in-memory folder was reverted, gvfsd-metadata wrote an empty database and journal: the next scan said
    "GVFS keeps per-file metadata", as new (live on Mint)."""
    from daprivacyscanner.checks.desktop import gvfs_entries
    host = make_host(tmp_path)
    d = host.home / ".local/share/gvfs-metadata"
    d.mkdir(parents=True)
    (d / "home").write_bytes(GVFS_EMPTY_DB)
    (d / "home-4e91bf3b.log").write_bytes(GVFS_JOURNAL(0))
    assert gvfs_entries(d / "home") == 0 and gvfs_entries(d / "home-4e91bf3b.log") == 0
    o = detect(cat, "desk.gvfs_metadata", make_scan(host))
    assert o.status is Status.PASS and "no entries" in ev(o)["Metadata"]
    (d / "home-4e91bf3b.log").write_bytes(GVFS_JOURNAL(3))                  # three changes waiting: kept
    assert detect(cat, "desk.gvfs_metadata", make_scan(host)).status is Status.FAIL


def test_evolution_data_servers_own_folder_isnt_evolution(cat, tmp_path):
    """evolution-data-server alone (Mint, Fedora, Ubuntu) makes ~/.local/share/evolution with an empty mail/trash."""
    host = make_host(tmp_path)
    (host.home / ".local/share/evolution/mail/trash").mkdir(parents=True)
    (host.home / ".local/share/evolution/addressbook").mkdir(parents=True)
    assert detect(cat, "app.mail_remote_content", make_scan(host)).status is Status.NOT_APPLICABLE
    (host.home / ".local/share/evolution/mail/local").mkdir()                   # Evolution's own Local Folders
    assert detect(cat, "app.mail_remote_content", make_scan(host)).status is not Status.NOT_APPLICABLE


def test_flatpak_gets_folders_of_its_own_when_the_user_has_no_installation(tmp_path):
    """flatpak run as a user without ~/.local/share/flatpak makes an empty repository there (Fedora, an empty home)."""
    host = make_host(tmp_path, env={"XDG_RUNTIME_DIR": str(tmp_path / "run")})
    (tmp_path / "run").mkdir()
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 0, "")
    host.run_flatpak("list", "--app")
    env = host.runner.envs[-1]
    assert env["XDG_DATA_HOME"].startswith(f"{tmp_path}/run/") and env["XDG_CACHE_HOME"].startswith(f"{tmp_path}/run/")
    assert list((tmp_path / "run").iterdir()) == []                             # removed at once
    (host.home / ".local/share/flatpak").mkdir(parents=True)                    # the user's own: used as it is
    host.run_flatpak("list", "--app")
    assert host.runner.envs[-1] == {}


def test_netplans_connections_are_changed_through_netplan(cat, tmp_path):
    """Ubuntu: netplan-enp1s0 is netplan's (ip6-privacy=0 by default); an nmcli change there is merged into netplan's
    files beside the installer's definition of the interface, and reverting leaves that file: netplan's command."""
    from daprivacyscanner.checks import load_all
    from test_fixes import nm_host
    host, nm = nm_host(tmp_path)
    nm.connections["u3"]["connection.id"] = "netplan-enp1s0"
    (host.root / "proc/sys/net/ipv6/conf/default").mkdir(parents=True)
    (host.root / "proc/sys/net/ipv6/conf/default/use_tempaddr").write_text("2\n")
    check = load_all()["net.ipv6_privacy"](cat["net.ipv6_privacy"])
    scan = make_scan(host)
    plan = check.plan_fix(scan, check.detect(scan))
    assert not any(getattr(a, "name", "") == "netplan-enp1s0" for a in plan.actions)
    assert any("sudo netplan set ethernets.enp1s0.ipv6-privacy=true" in e for e in plan.side_effects)


def test_folded_and_disabled_repository_entries(cat, tmp_path):
    folded = "Types: deb\nURIs: https://a.example/ubuntu\n http://b.example/ubuntu\nSuites: noble\n"
    off = "Types: deb\nURIs: http://c.example/\nEnabled: false\n"
    host = make_host(tmp_path, files={"/etc/apt/sources.list.d/a.sources": folded,
                                      "/etc/apt/sources.list.d/c.sources": off,
                                      "/etc/pacman.conf": "[options]\n\n[mine]\nServer = http://d.example/$arch\n",
                                      "/etc/yum.repos.d/e.repo": "[e]\nbaseurl=http://e.example/\nenabled=no\n"})
    o = detect(cat, "tel.http_repos", make_scan(host))
    assert o.status is Status.FAIL and set(ev(o)) == {"b.example", "d.example"}


def test_localsearch_out_of_reach_is_judged_by_its_settings(cat, tmp_path):
    """Over SSH, `localsearch status` can't reach it: "Indexing is off" was said while it indexes the home folder."""
    from fakes import FakeGSettings
    gs = FakeGSettings({("org.freedesktop.Tracker3.Miner.Files", "index-recursive-directories"): "['$HOME']",
                        ("org.freedesktop.Tracker3.Miner.Files", "index-single-directories"): "@as []",
                        ("org.freedesktop.Tracker3.Miner.Files", "index-removable-devices"): "false"})
    host = make_host(tmp_path, commands={"localsearch status": CommandResult(("localsearch", "status"), 1, "", "Timeout")})
    host.runner.handlers["gsettings"] = gs
    host.runner.installed.add("gsettings")
    o = detect(cat, "desk.indexers", make_scan(host))
    assert "Indexing is off" not in o.summary and o.status is Status.WARN
    assert "couldn't be asked" in " ".join(str(e.value) for e in o.evidence)


def test_a_chromium_step_without_chromium_says_none_is_installed(cat, tmp_path):
    from test_checks_telemetry_browser import firefox
    from test_guides import build
    host = make_host(tmp_path)
    firefox(host.home, prefs='user_pref("privacy.sanitize.sanitizeOnShutdown", false);\n')
    g = build(cat, host, "br.history_retention")
    step = next(s for s in g.steps if s.title == "Chromium-based browsers")
    assert step.text == "None is installed." and step.done and not step.options


def test_a_hidden_helper_entry_isnt_a_browser(cat, tmp_path):
    """Fedora's installer ships "Browser External" (extlinks.desktop, NoDisplay=true, WebBrowser)."""
    from test_browsers import entry, machine
    hidden = "[Desktop Entry]\nType=Application\nName=Browser External\nExec=x %u\nCategories=WebBrowser;\nNoDisplay=true\n"
    host = machine(tmp_path, default="firefox.desktop", files={"/usr/share/applications/firefox.desktop": entry("Firefox"),
                                                               "/usr/share/applications/extlinks.desktop": hidden})
    o = detect(cat, "br.default_browser", make_scan(host))
    assert not any("Browser External" in str(e.label) + str(e.value) for e in o.evidence)


def test_a_minisign_signature_without_key_or_program_says_both(tmp_path):
    from daprivacyscanner.tools import verify
    host = make_host(tmp_path, files={"/etc/os-release": "ID=linuxmint\nID_LIKE=ubuntu debian\n"})
    sig = host.home / "x.minisig"
    sig.write_text("untrusted comment: x\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n")
    s = verify.check_minisign(host, verify.KeySet(host, []), sig, host.home / "x")
    assert s.status == "no_key" and "isn't installed" in s.detail and s.install == "sudo apt install minisign"
