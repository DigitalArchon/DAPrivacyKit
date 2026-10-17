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
