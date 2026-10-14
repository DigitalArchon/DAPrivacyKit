"""kern.package_signatures: package managers told not to check signatures, on fake /etc trees."""

from __future__ import annotations

from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.model import Status

from conftest import detect, ev, make_host, make_scan

CHECK = "kern.package_signatures"

DEBIAN_OK = {"/etc/apt/sources.list.d/ubuntu.sources":
             "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\n"
             "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"}


def run(cat, tmp_path, files, home_files=None):
    return detect(cat, CHECK, make_scan(make_host(tmp_path, files=files, home_files=home_files)))


def test_signed_repositories_pass(cat, tmp_path):
    o = run(cat, tmp_path, {**DEBIAN_OK, "/etc/apt/sources.list": "deb [signed-by=/etc/apt/keyrings/x.gpg] https://x.org stable main\n"})
    assert o.status is Status.PASS and o.findings == {"signature_checks_off": False, "unsigned_over_http": False}


def test_nothing_to_check(cat, tmp_path):
    assert run(cat, tmp_path, {"/etc/hostname": "x\n"}).status is Status.NOT_APPLICABLE


def test_apt_one_line_trusted_over_http(cat, tmp_path):
    o = run(cat, tmp_path, {**DEBIAN_OK, "/etc/apt/sources.list.d/vendor.list":
                            "# deb [trusted=yes] http://commented.example/ ./\n"
                            "deb [arch=amd64 trusted=yes] http://repo.example.com/debian stable main\n"})
    assert o.status is Status.FAIL
    assert o.findings == {"signature_checks_off": True, "unsigned_over_http": True}
    assert ev(o) == {"/etc/apt/sources.list.d/vendor.list (http://repo.example.com/debian)": "trusted=yes, over plain HTTP"}
    sev = effective_severity(cat[CHECK], o.findings)
    assert sev.value == 9


def test_deb822_stanzas_and_disabled_ones(cat, tmp_path):
    o = run(cat, tmp_path, {"/etc/apt/sources.list.d/x.sources":
                            "Types: deb\nURIs: https://a.example/\nSuites: s\nAllow-Insecure: yes\n\n"
                            "Types: deb\nURIs: http://b.example/\nSuites: s\nTrusted: yes\nEnabled: no\n"})
    assert o.status is Status.FAIL and len(o.evidence) == 1
    assert o.findings["unsigned_over_http"] is False
    assert effective_severity(cat[CHECK], o.findings).value == 7


def test_apt_conf_options(cat, tmp_path):
    o = run(cat, tmp_path, {**DEBIAN_OK, "/etc/apt/apt.conf.d/99insecure":
                            '// APT::Get::AllowUnauthenticated "true";\nAcquire::AllowInsecureRepositories "true";\n'})
    assert o.status is Status.FAIL
    assert list(ev(o).values()) == ["AllowInsecureRepositories true"]


def test_the_legacy_shared_keyring_is_a_warning(cat, tmp_path):
    o = run(cat, tmp_path, {**DEBIAN_OK, "/etc/apt/trusted.gpg": "\x99binary key"})
    assert o.status is Status.WARN and o.findings["signature_checks_off"] is False
    assert effective_severity(cat[CHECK], o.findings).value == 3


def test_dnf_repos_and_main(cat, tmp_path):
    o = run(cat, tmp_path, {"/etc/yum.repos.d/vendor.repo":
                            "[vendor]\nname=V\nbaseurl=http://rpm.example/\ngpgcheck=0\n\n"
                            "[vendor-off]\nbaseurl=https://x/\ngpgcheck=0\nenabled=0\n",
                            "/etc/yum.repos.d/fedora.repo": "[fedora]\nmetalink=https://m/\ngpgcheck=1\n"})
    assert o.status is Status.FAIL and len(o.evidence) == 1 and o.findings["unsigned_over_http"] is True
    o = run(cat, tmp_path / "b", {"/etc/dnf/dnf.conf": "[main]\ngpgcheck=False\n"})
    assert o.status is Status.FAIL and "every repository" in list(ev(o).values())[0]


def test_zypper_and_pacman(cat, tmp_path):
    o = run(cat, tmp_path, {"/etc/zypp/repos.d/x.repo": "[x]\nenabled=1\nbaseurl=https://x/\ngpgcheck=0\n"})
    assert o.status is Status.FAIL
    default = "[options]\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\n[core]\nInclude = /etc/pacman.d/mirrorlist\n"
    assert run(cat, tmp_path / "b", {"/etc/pacman.conf": default}).status is Status.PASS
    o = run(cat, tmp_path / "c", {"/etc/pacman.conf": default + "[custom]\nSigLevel = Never\nServer = http://repo.example/$arch\n"})
    assert o.status is Status.FAIL and o.findings["unsigned_over_http"] is True


def test_flatpak_remotes(cat, tmp_path):
    o = run(cat, tmp_path, {"/var/lib/flatpak/repo/config": '[core]\nmode=bare-user-only\n\n[remote "flathub"]\n'
                            "url=https://dl.flathub.org/repo/\ngpg-verify=true\n"},
            home_files={".local/share/flatpak/repo/config": '[remote "side"]\nurl=http://side.example/\ngpg-verify=false\n'})
    assert o.status is Status.FAIL
    assert ev(o) == {"~/.local/share/flatpak/repo/config (side)": "gpg-verify=false, over plain HTTP"}


def test_the_how_to_names_each_file_and_change(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.checks.guides import GUIDES

    scan = make_scan(make_host(tmp_path, files={
        "/etc/os-release": "ID=ubuntu\n",
        "/etc/apt/sources.list.d/vendor.list": "deb [trusted=yes] http://repo.example.com/debian stable main\n",
        "/etc/apt/trusted.gpg": "key",
        "/etc/zypp/repos.d/x.repo": "[x]\nbaseurl=https://x/\ngpgcheck=0\n",
        "/var/lib/flatpak/repo/config": '[remote "side"]\nurl=https://s/\ngpg-verify=false\n'}))
    check = load_all()[CHECK](cat[CHECK])
    g = GUIDES[CHECK].plan(check, scan, check.detect(scan))
    cmds = [c for s in g.steps for c in s.commands]
    assert "sudoedit /etc/apt/sources.list.d/vendor.list" in cmds
    assert "sudo zypper modifyrepo --gpgcheck x" in cmds
    assert "sudo flatpak remote-modify --system --gpg-verify side" in cmds
    assert any("trusted.gpg" in s.text for s in g.steps) and not any(s.options for s in g.steps)


def test_keys_of_other_publishers_in_trusted_gpg_d(cat, tmp_path):
    """Keys in /etc/apt/trusted.gpg.d are trusted for every repository: the distribution's own (its keyring package's,
    or named after it, as Mint's unowned linuxmint.key.asc) are left out, others are named."""
    from conftest import detect, make_host, make_scan
    from daprivacyscanner.model import Status
    host = make_host(tmp_path, files={"/etc/os-release": 'ID=linuxmint\nID_LIKE="ubuntu debian"\n',
                                      "/etc/apt/sources.list": "deb https://packages.linuxmint.com wilma main\n",
                                      "/etc/apt/trusted.gpg.d/linuxmint.key.asc": "k",
                                      "/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg": "k",
                                      "/etc/apt/trusted.gpg.d/google-chrome.gpg": "k"},
                     commands={"dpkg-query -S /etc/apt/trusted.gpg.d/google-chrome.gpg": "google-chrome-stable: x\n"})
    o = detect(cat, "kern.package_signatures", make_scan(host))
    assert o.status is Status.WARN and o.summary.startswith("1 key of other publishers in /etc/apt/trusted.gpg.d is")
    assert [e.value for e in o.evidence] == ["/etc/apt/trusted.gpg.d/google-chrome.gpg"]
