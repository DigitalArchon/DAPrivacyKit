"""Check for updates… (update.py): versions as PEP 440 orders them, GitHub's answer read strictly, the download beside
the AppImage through the network the page named, verification with the app's own release key alone (throwaway keys
stand in for it), the version read from the file itself, the replacement that keeps the old copy until the new one
has started, and the routes the page uses. The network is FakeNet's: nothing here goes online."""

from __future__ import annotations

import contextlib
import datetime as dt
import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from daprivacyscanner import online, update as U
from daprivacyscanner.host import CommandResult, FakeRunner, Host, SystemRunner
from daprivacyscanner.online import FakeNet, HttpResult
from daprivacyscanner.tools import keys as K

needs_gpg = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("gpgv")), reason="gpg and gpgv are needed")
NEW = "9.1.0"
NAME = f"DAPrivacyKit-{NEW}-x86_64.AppImage"
DL = f"https://github.com/DigitalArchon/DAPrivacyKit/releases/download/v{NEW}/"
SIG = b"0123456789"                       # what a_release() says the signature's size is


@pytest.fixture(autouse=True)
def safe_above(tmp_path, monkeypatch):
    """pytest's own folders, above tmp_path, are in /tmp, which anyone may write to: seen as a home's folders are
    (root's, 0755), so what the tests make below them decides (as test_server_shell.py does)."""
    import stat as st_
    from daprivacyscanner import launch
    real, above = launch._status, {str(p) for p in tmp_path.parents}

    def status(p, follow):
        st = real(p, follow)
        if p in above:
            return os.stat_result((st_.S_IFDIR | 0o755, st.st_ino, st.st_dev, st.st_nlink, 0, 0, st.st_size,
                                   int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
        return st
    monkeypatch.setattr(launch, "_status", status)
    tmp_path.chmod(0o755)


# ------------------------------------------------------------------ versions

@pytest.mark.parametrize("lower, higher", [("0.1.0b8", "0.1.0b9"), ("0.1.0b9", "0.1.0b10"), ("0.1.0b10", "0.1.0rc1"),
                                           ("0.1.0rc1", "0.1.0"), ("0.1.0", "0.1.0.post1"), ("0.1.0.post1", "0.1.1"),
                                           ("1.0.dev1", "1.0a1"), ("1.0a1.dev2", "1.0a1"), ("0.9", "0.10"),
                                           ("1.0", "1!0.1"), ("0.1.0b8", "0.1.0b8+dev.abc")])
def test_versions_are_ordered_as_pep_440_orders_them(lower, higher):
    assert U.version(lower) < U.version(higher) and U.compare(higher, lower) == "newer"
    assert U.compare(lower, higher) == "older"


def test_versions_equal_and_unreadable():
    assert U.version("1.0") == U.version("1.0.0") and U.compare("0.1.0b8", "0.1.0b8") == "same"
    assert U.version("0.1.0b8+dev.abc123.dirty").local == "dev.abc123.dirty"
    for bad in ("", "v1.0", "1.0-beta", "1.0b", "latest", "1.0 ", "1..0"):
        assert U.version(bad) is None, bad
    assert U.compare("nonsense", "0.1") == "older"          # what can't be read is never offered


# ------------------------------------------------------------------ the latest release

def release_json(version=NEW, *, tag=None, assets=None, **extra) -> dict:
    tag = tag or f"v{version}"
    name = f"DAPrivacyKit-{version}-x86_64.AppImage"
    base = f"https://github.com/DigitalArchon/DAPrivacyKit/releases/download/{tag}/"
    if assets is None:
        assets = [{"name": n, "size": s, "state": "uploaded", "browser_download_url": base + n,
                   **({"digest": d} if d else {})}
                  for n, s, d in ((name, 1000, "sha256:" + "ab" * 32), (name + ".asc", 228, None),
                                  (name + ".sha256", 103, None), (name + ".zsync", 300, None))]
    return {"tag_name": tag, "name": f"DA Privacy Kit {tag}", "draft": False, "prerelease": False,
            "published_at": "2026-12-01T10:00:00Z", "assets": assets, **extra}


def answering(data, status=200) -> FakeNet:
    body = data if isinstance(data, bytes) else json.dumps(data).encode()
    return FakeNet(http={U.LATEST: HttpResult(status, body)})


def test_the_latest_release_is_read_from_githubs_api():
    net = answering(release_json())
    rel = U.latest(net)
    assert net.contacted == [U.LATEST] and U.LATEST.startswith("https://api.github.com/")
    assert (rel.version, rel.tag, rel.name, rel.size, rel.sig_size) == (NEW, f"v{NEW}", NAME, 1000, 228)
    assert rel.url == DL + NAME and rel.sig_url == DL + NAME + ".asc" and rel.sha256 == "ab" * 32
    assert rel.published == "2026-12-01" and rel.page.endswith(f"/releases/tag/v{NEW}")


@pytest.mark.parametrize("data, said", [
    (release_json(tag="9.1.0"), "isn't v<version>"),
    (release_json(tag="vlatest"), "isn't v<version>"),
    (release_json(tag="v9.1.0+dev.1"), "isn't v<version>"),
    (release_json(draft=True), "draft or a pre-release"),
    (release_json(prerelease=True), "draft or a pre-release"),
    (release_json(assets=[]), "has no DAPrivacyKit-9.1.0-x86_64.AppImage"),
    ({"tag_name": "v9.1.0"}, "couldn't be read"),
    (b"<html>", "couldn't be read"),
])
def test_a_release_the_app_cant_take_is_refused(data, said):
    with pytest.raises(U.UpdateError, match=said.replace("+", r"\+").replace("(", r"\(")):
        U.latest(answering(data))


def _asset(**change):
    data = release_json()
    data["assets"][0].update(change)
    return data


@pytest.mark.parametrize("data, said", [
    (_asset(browser_download_url="https://evil.example/" + NAME), "an address the app doesn't expect"),
    (_asset(browser_download_url="http://github.com/DigitalArchon/DAPrivacyKit/releases/download/v9.1.0/" + NAME),
     "an address the app doesn't expect"),
    (_asset(size=U.MAX_APPIMAGE + 1), "the size the app expects"),
    (_asset(size=0), "the size the app expects"),
    (_asset(size="1000"), "the size the app expects"),
    (_asset(state="starter"), "the size the app expects"),
])
def test_an_asset_at_another_address_or_of_another_size_is_refused(data, said):
    with pytest.raises(U.UpdateError, match=said):
        U.latest(answering(data))


def test_only_the_assets_named_exactly_count():
    data = release_json()
    data["assets"] = [dict(a, name=a["name"].replace("x86_64", "aarch64")) for a in data["assets"]]
    with pytest.raises(U.UpdateError, match="has no"):
        U.latest(answering(data))
    data = release_json()
    data["assets"].insert(0, {"name": "DAPrivacyKit-9.1.0-x86_64.AppImage.asc.exe", "size": 5, "state": "uploaded",
                              "browser_download_url": "https://evil.example/x"})
    assert U.latest(answering(data)).sig_url == DL + NAME + ".asc"


@pytest.mark.parametrize("status, said", [(403, "60 an hour"), (429, "60 an hour"), (404, "no release yet"),
                                          (500, "couldn't be asked")])
def test_githubs_refusals_are_said(status, said):
    with pytest.raises(U.UpdateError, match=said):
        U.latest(answering(b"{}", status))
    with pytest.raises(U.UpdateError, match="couldn't be asked"):
        U.latest(FakeNet())                                          # no answer at all


def test_the_hosts_named_are_githubs_and_redirects_go_only_to_its_file_servers():
    import io
    import urllib.request
    from email.message import Message
    assert U.CHECK_HOSTS == ("api.github.com",)
    assert U.DOWNLOAD_HOSTS == ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")

    def follow(to):
        req = urllib.request.Request(DL + NAME)
        req.allowed_hosts = U.ASSET_HOSTS
        return online.ConfinedRedirects().redirect_request(req, io.BytesIO(), 302, "Found", Message(), to)
    assert follow("https://release-assets.githubusercontent.com/github-production-release-asset/1/x?sp=r") is not None
    for to in ("https://evil.example/x", "http://release-assets.githubusercontent.com/x",
               "https://release-assets.githubusercontent.com:8443/x"):
        with pytest.raises(online.Redirected):
            follow(to)
    with pytest.raises(online.NotHttps):
        online.check_url("http://api.github.com/repos/DigitalArchon/DAPrivacyKit/releases/latest")


# ------------------------------------------------------------------ this copy

def appimage_host(tmp_path, mode=0o755, folder_mode=0o700, runner=None, **env) -> tuple[Host, Path]:
    home = tmp_path / "home"
    apps = home / "Applications"
    apps.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o755)
    os.chmod(home, 0o700)
    f = apps / "DAPrivacyKit-0.1.0b9-x86_64.AppImage"
    f.write_bytes(b"#!/bin/sh\necho 'DA Privacy Kit 0.1.0b9'\n")
    os.chmod(f, mode)
    os.chmod(apps, folder_mode)
    environ = {"HOME": str(home), "PATH": "/usr/bin:/bin", "APPIMAGE": str(f), "XDG_STATE_HOME": str(home / ".state"),
               **env}
    return Host(home=home, environ=environ, runner=runner or SystemRunner(environ)), f


def test_how_each_kind_of_copy_updates(tmp_path):
    host, f = appimage_host(tmp_path)
    s = U.situation(host, "0.1.0b9")
    assert s["mode"] == "appimage" and s["path"] == str(f) and s["problem"] == ""
    assert s["hosts"] == {"check": ["api.github.com"], "download": list(U.DOWNLOAD_HOSTS)}
    # a dev build: by its local version, its name, or no update information
    assert U.situation(host, "0.1.0b9+dev.abc")["mode"] == "dev"
    dev = f.with_name("DAPrivacyKit-0.1.0b9+dev.0123456789ab-x86_64.AppImage")
    f.rename(dev)
    host.environ["APPIMAGE"] = str(dev)
    assert U.situation(host, "0.1.0b9")["mode"] == "dev"
    # not an AppImage: a source tree (git, or not), or a package
    bare = Host(home=host.home, environ={"HOME": str(host.home)}, runner=FakeRunner())
    repo = tmp_path / "repo"
    (repo / "src" / "daprivacyscanner").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\n")
    s = U.situation(bare, "0.1.0b9", repo=repo)
    assert s["mode"] == "source" and not s["commands"] and "isn't a git clone" in s["how"][0]
    (repo / ".git").mkdir()
    s = U.situation(bare, "0.1.0b9", repo=repo)
    assert s["mode"] == "source" and s["commands"] == [f"git -C {repo} pull --ff-only"]
    s = U.situation(bare, "0.1.0b9", repo=tmp_path / "site-packages")
    assert s["mode"] == "package" and "package manager" in s["how"][0]


def test_a_build_that_records_a_dev_version_is_a_dev_build(monkeypatch):
    import types
    from daprivacyscanner import __version__
    built = types.ModuleType("daprivacyscanner._built")
    built.BUILT, built.VERSION = "2026-11-12", f"{__version__}+dev.0123456789ab"
    monkeypatch.setitem(sys.modules, "daprivacyscanner._built", built)
    assert U.dev_build({"APPIMAGE": "/a/renamed.AppImage"}, __version__)
    built.VERSION = __version__
    assert not U.dev_build({"APPIMAGE": "/a/renamed.AppImage"}, __version__)


def test_a_copy_where_others_could_change_it_or_that_isnt_yours_to_change_is_refused(tmp_path):
    host, f = appimage_host(tmp_path, folder_mode=0o777)
    assert "can be changed by anyone" in U.situation(host, "0.1.0b9")["problem"]
    host, f = appimage_host(tmp_path / "b", folder_mode=0o500)
    if os.access(f.parent, os.W_OK):
        pytest.skip("running as root")
    assert "can't change the folder" in U.situation(host, "0.1.0b9")["problem"]
    os.chmod(f.parent, 0o700)
    link = f.with_name("link.AppImage")
    link.symlink_to(f)
    assert U.replace_problem(host, link).endswith("isn't a plain file, so it isn't replaced.")


def test_the_version_option_prints_the_line_read_version_reads():
    from daprivacyscanner import __version__
    r = subprocess.run([sys.executable, "-m", "daprivacyscanner", "--version"], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(Path(U.__file__).parents[1])}, timeout=60)
    assert r.returncode == 0 and r.stdout == f"DA Privacy Kit {__version__}\n"


# ------------------------------------------------------------------ downloading

def a_release(size=None, digest="", data=b"new release") -> U.Release:
    return U.Release(NEW, f"v{NEW}", "2026-12-01", NAME, DL + NAME, len(data) if size is None else size, digest,
                     DL + NAME + ".asc", 10)


def test_the_download_goes_into_a_hidden_folder_of_its_own_beside_the_appimage(tmp_path):
    host, f = appimage_host(tmp_path)
    data = b"new release"
    net = FakeNet(files={DL + NAME: data, DL + NAME + ".asc": b"0123456789"})
    job: dict = {}
    staged = U.download(host, net, a_release(digest=hashlib.sha256(data).hexdigest()), job, lambda: False)
    assert net.contacted == [DL + NAME + ".asc", DL + NAME]               # the signature first: it is small
    assert staged.folder.parent == f.parent and staged.folder.name.startswith(".DAPrivacyKit-update-")
    assert os.stat(staged.folder).st_mode & 0o777 == 0o700
    assert staged.file.read_bytes() == data and staged.signature.read_bytes() == b"0123456789"
    assert sorted(os.listdir(staged.folder)) == [NAME, NAME + ".asc"]
    assert staged.target == f and staged.target_id[1] == os.stat(f).st_ino
    U.discard(staged)
    assert not staged.folder.exists() and f.exists()


@pytest.mark.parametrize("files, release, said", [
    ({DL + NAME: HttpResult(404, b"", "Not Found"), DL + NAME + ".asc": b"0123456789"}, a_release(),
     "couldn't be downloaded"),
    ({DL + NAME: b"shorter", DL + NAME + ".asc": b"0123456789"}, a_release(size=11), "arrived with 7 bytes"),
    ({DL + NAME: b"new release", DL + NAME + ".asc": b"0123456789"}, a_release(digest="00" * 32),
     "damaged on the way"),
])
def test_a_download_that_fails_leaves_nothing(tmp_path, files, release, said):
    host, f = appimage_host(tmp_path)
    with pytest.raises(U.UpdateError, match=said):
        U.download(host, FakeNet(files=files), release, {}, lambda: False)
    assert sorted(os.listdir(f.parent)) == [f.name]


def test_stop_ends_the_download_and_leaves_nothing(tmp_path):
    host, f = appimage_host(tmp_path)
    net = FakeNet(files={DL + NAME: b"new release", DL + NAME + ".asc": b"0123456789"})
    with pytest.raises(U.Stopped):
        U.download(host, net, a_release(), {}, lambda: True)
    assert sorted(os.listdir(f.parent)) == [f.name]


def test_without_room_beside_it_nothing_is_downloaded(tmp_path, monkeypatch):
    host, f = appimage_host(tmp_path)
    monkeypatch.setattr(U.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10**9, 10**9, 1024))
    net = FakeNet(files={DL + NAME: b"x"})
    with pytest.raises(U.UpdateError, match="There isn't room"):
        U.download(host, net, a_release(), {}, lambda: False)
    assert net.contacted == [] and sorted(os.listdir(f.parent)) == [f.name]


def test_nothing_is_downloaded_where_it_couldnt_be_replaced(tmp_path):
    host, f = appimage_host(tmp_path, folder_mode=0o777)
    net = FakeNet(files={DL + NAME: b"x"})
    with pytest.raises(U.UpdateError, match="can be changed by anyone"):
        U.download(host, net, a_release(), {}, lambda: False)
    assert net.contacted == []


def test_leftover_folders_are_tidied_by_the_names_the_app_gave_only(tmp_path):
    host, f = appimage_host(tmp_path)
    left = f.parent / ".DAPrivacyKit-update-0123456789abcdef"
    left.mkdir(mode=0o700)
    (left / NAME).write_bytes(b"x")
    (left / (NAME + ".asc.part")).write_bytes(b"x")
    other = f.parent / ".DAPrivacyKit-update-fedcba9876543210"
    other.mkdir(mode=0o700)
    (other / "notes.txt").write_text("mine")                          # not a name the app gives: stays, and its folder
    unrelated = f.parent / ".DAPrivacyKit-update-mine"
    unrelated.mkdir()
    (unrelated / NAME).write_bytes(b"x")
    assert U.tidy(host) == 1
    assert not left.exists() and (other / "notes.txt").exists() and (unrelated / NAME).exists()


# ------------------------------------------------------------------ verifying, with throwaway keys

class Keys:
    """A GnuPG home of its own: a certify-only primary key with a signing subkey (the release key as it is to be),
    and `other`, someone else's key."""

    def __init__(self, home: Path):
        self.home = home
        home.mkdir(mode=0o700)
        self.primary, self.sub = self._make("Test Release <release@example.org>")
        self.other, self.other_sub = self._make("Someone Else <else@example.org>")

    def gpg(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["gpg", "--homedir", str(self.home), "--batch", "--quiet", "--pinentry-mode", "loopback",
                               "--passphrase", "", *args], check=True, capture_output=True)

    def _make(self, uid: str) -> tuple[str, str]:
        self.gpg("--quick-gen-key", uid, "ed25519", "cert", "never")
        fprs = [ln.split(":")[9] for ln in self.gpg("--with-colons", "--list-keys", uid).stdout.decode().splitlines()
                if ln.startswith("fpr")]
        self.gpg("--quick-add-key", fprs[0], "ed25519", "sign", "never")
        fprs = [ln.split(":")[9] for ln in self.gpg("--with-colons", "--list-keys", uid).stdout.decode().splitlines()
                if ln.startswith("fpr")]
        return fprs[0], fprs[1]

    def project(self, *primaries: str, pid: str = "digitalarchon") -> K.Project:
        block = self.gpg("--armor", "--export-options", "export-minimal", "--export", *primaries).stdout.decode()
        return K.parse({"schema_version": 1, "projects": [{
            "id": pid, "name": "Digital Archon" if pid == "digitalarchon" else "Someone Else", "signs": "releases",
            "source": "https://example.org", "key_from": "https://example.org/key.asc", "checked": dt.date(2026, 11, 12),
            "files": ["DAPrivacyKit-*.AppImage"], "how": "the .asc",
            "keys": [{"fingerprint": f, "name": "Release key"} for f in primaries], "key": block}]})[0]

    def sign(self, path: Path, signer: str) -> None:
        self.gpg("--yes", "--local-user", signer + "!", "--armor", "--detach-sign", "--output", f"{path}.asc", str(path))


@pytest.fixture
def keys(tmp_path):
    k = Keys(tmp_path / "gnupg")
    yield k
    subprocess.run(["gpgconf", "--homedir", str(k.home), "--kill", "all"], capture_output=True)


def new_copy(says: str = f"DA Privacy Kit {NEW}", code: int = 0) -> bytes:
    """A stand-in for the new AppImage: a script that says its version as app.py's --version does."""
    return f"#!/bin/sh\n[ \"$1\" = --version ] && echo '{says}'\nexit {code}\n".encode()


def staged_copy(tmp_path, keys, data: bytes, signer: str | None = None) -> tuple[Host, Path, U.Staged]:
    host, f = appimage_host(tmp_path)
    net = FakeNet(files={DL + NAME: data, DL + NAME + ".asc": SIG})
    staged = U.download(host, net, a_release(data=data), {}, lambda: False)
    keys.sign(staged.file, signer or keys.sub)
    return host, f, staged


@needs_gpg
def test_a_release_signed_by_the_apps_own_key_and_saying_its_version_is_verified(tmp_path, keys):
    host, f, staged = staged_copy(tmp_path, keys, new_copy())
    job: dict = {}
    verdict = U.verify(host, staged, "0.1.0b9", projects=[keys.project(keys.primary)], job=job)
    assert verdict["title"] == "Verified: made by Digital Archon" and verdict["fingerprint"] == keys.primary
    assert verdict["version"] == NEW and staged.inside == NEW
    assert staged.sha256 == hashlib.sha256(staged.file.read_bytes()).hexdigest()
    assert verdict["signed_at"] and abs(verdict["signed_at"] - time.time()) < 600
    # a successor pinned now verifies too
    host, f, staged = staged_copy(tmp_path / "s", keys, new_copy(), keys.other_sub)
    p = K.parse({"schema_version": 1, "projects": [{
        "id": "digitalarchon", "name": "Digital Archon", "signs": "r", "source": "https://example.org",
        "key_from": "https://example.org/k", "checked": dt.date(2026, 11, 12), "files": ["DAPrivacyKit-*.AppImage"],
        "how": "x", "keys": [{"fingerprint": keys.primary, "name": "a"},
                             {"fingerprint": keys.other, "name": "b", "role": "successor"}],
        "key": keys.gpg("--armor", "--export", keys.primary, keys.other).stdout.decode()}]})[0]
    assert U.verify(host, staged, "0.1.0b9", projects=[p])["version"] == NEW


@needs_gpg
def test_only_the_apps_own_release_key_counts(tmp_path, keys):
    """Signed by a key the app lists for another project, or by one it doesn't list: never this app's release."""
    ours, theirs = keys.project(keys.primary), keys.project(keys.other, pid="someone")
    host, f, staged = staged_copy(tmp_path, keys, new_copy(), keys.other_sub)
    with pytest.raises(U.UpdateError, match="isn't verified"):
        U.verify(host, staged, "0.1.0b9", projects=[ours, theirs])
    with pytest.raises(U.UpdateError, match="own release key isn't in its list"):
        U.verify(host, staged, "0.1.0b9", projects=[theirs])
    # the user's own keyring is never asked: a key there that signed it changes nothing
    host.environ["GNUPGHOME"] = str(keys.home)
    with pytest.raises(U.UpdateError, match="isn't verified"):
        U.verify(host, staged, "0.1.0b9", projects=[ours])


@needs_gpg
def test_a_file_changed_after_it_was_signed_is_refused(tmp_path, keys):
    host, f, staged = staged_copy(tmp_path, keys, new_copy())
    staged.file.write_bytes(new_copy() + b"# changed\n")
    with pytest.raises(U.UpdateError, match="Don't use this file"):
        U.verify(host, staged, "0.1.0b9", projects=[keys.project(keys.primary)])


@needs_gpg
@pytest.mark.parametrize("says, code, current, said", [
    ("DA Privacy Kit 9.0.0", 0, "0.1.0b9", "says it is version 9.0.0, not 9.1.0"),        # an older one, renamed
    (f"DA Privacy Kit {NEW}", 0, NEW, "isn't newer than this copy"),                       # the same version
    (f"DA Privacy Kit {NEW}", 0, "10.0", "isn't newer than this copy"),                    # a downgrade
    ("usage: daprivacyscanner [-h]", 2, "0.1.0b9", "couldn't be read from the file itself"),  # no --version
    ("DA Privacy Kit", 0, "0.1.0b9", "couldn't be read from the file itself"),
])
def test_the_version_inside_must_be_the_releases_and_newer(tmp_path, keys, says, code, current, said):
    host, f, staged = staged_copy(tmp_path, keys, new_copy(says, code))
    with pytest.raises(U.UpdateError, match=said):
        U.verify(host, staged, current, projects=[keys.project(keys.primary)])


@needs_gpg
def test_a_file_that_changes_while_it_is_checked_is_refused(tmp_path, keys):
    """What is verified, run for its version and put in place must be the same bytes: a file that changed itself as it
    was run (or was changed meanwhile) is refused."""
    host, f, staged = staged_copy(tmp_path, keys, f"#!/bin/sh\necho 'DA Privacy Kit {NEW}'\necho >> \"$0\"\n".encode())
    with pytest.raises(U.UpdateError, match="changed while it was checked"):
        U.verify(host, staged, "0.1.0b9", projects=[keys.project(keys.primary)])
    assert not staged.sha256


def test_a_copy_whose_appimage_another_window_replaced_doesnt_update_it_again(tmp_path):
    host, f = appimage_host(tmp_path)
    started = U.started_from(host.environ)
    assert U.situation(host, "0.1.0b9", started=started)["problem"] == ""
    f.unlink()
    f.write_bytes(b"#!/bin/sh\necho 'DA Privacy Kit 9.1.0'\n#")
    assert "has been replaced since this window started" in U.situation(host, "0.1.0b9", started=started)["problem"]
    # without the identity, the record another window left says so too
    from daprivacyscanner.history import write_json
    write_json(U._record_path(host), {"path": str(f), "keep": str(f.with_name(".x.old")), "from": "0.1.0b9",
                                      "to": NEW, "keep_id": [], "new_id": []})
    s = U.situation(host, "0.1.0b9")
    assert "replaced since this window started, by version 9.1.0" in s["problem"] and "start the app again" in s["problem"]
    assert U.situation(host, NEW)["problem"] == ""                   # the new copy itself


def test_the_version_is_read_by_running_the_file_with_the_hosts_environment(tmp_path):
    seen = []

    def run(argv):
        seen.append(argv)
        return CommandResult(argv, 0, "DA Privacy Kit 9.1.0\n")
    runner = FakeRunner(handlers={})
    host, f = appimage_host(tmp_path, runner=runner, APPIMAGE_EXTRACT_AND_RUN="1")
    target = f.parent / "x.AppImage"
    target.write_bytes(b"x")
    runner.handlers[str(target)] = run
    runner.installed.add(str(target))
    assert U.read_version(host, target) == "9.1.0"
    assert seen == [(str(target), "--version")]
    assert runner.envs[-1] == {"APPIMAGE_EXTRACT_AND_RUN": "1", "APPIMAGELAUNCHER_DISABLE": "1"}
    assert os.stat(target).st_mode & 0o777 == 0o700


# ------------------------------------------------------------------ replacing, and finishing at the new copy's start

def verified_copy(tmp_path, mode=0o750) -> tuple[Host, Path, U.Staged]:
    """A staged download as verify leaves it (sha256 and version set), for the replacement alone."""
    host, f = appimage_host(tmp_path, mode=mode)
    data = new_copy()
    staged = U.download(host, FakeNet(files={DL + NAME: data, DL + NAME + ".asc": SIG}), a_release(data=data), {},
                        lambda: False)
    staged.sha256, staged.inside = hashlib.sha256(data).hexdigest(), NEW
    return host, f, staged


def test_replacing_keeps_the_path_and_mode_and_the_old_copy_until_the_new_one_starts(tmp_path):
    host, f, staged = verified_copy(tmp_path)
    old = f.read_bytes()
    old_inode = os.stat(f).st_ino
    p = U.plan(staged, "0.1.0b9")
    keep = f.with_name(f".{f.name}.0.1.0b9.old")
    assert p["path"] == str(f) and p["keep"] == str(keep) and p["mode"] == "0750"
    assert p["commands"] == [f"chmod 0750 {staged.file}", f"ln {f} {keep}", f"mv -f {staged.file} {f}"]
    assert p["back"] == [f"mv -f {keep} {f}"] and p["check"][1] == f"{staged.file} --version"
    out = U.replace(host, staged, "0.1.0b9")
    assert f.read_bytes() == new_copy() and os.stat(f).st_mode & 0o777 == 0o750
    assert keep.read_bytes() == old and os.stat(keep).st_ino == old_inode
    assert out["back"] == [f"mv -f {keep} {f}"] and out["to"] == NEW and not out["note"]
    assert not staged.folder.exists()
    rec = U.load_pending(host)
    assert rec["path"] == str(f) and rec["keep"] == str(keep) and rec["from"] == "0.1.0b9" and rec["to"] == NEW
    assert os.stat(U._record_path(host)).st_mode & 0o777 == 0o600
    # the old copy, still running (Later): its start removes nothing
    assert U.finish_pending(host, "0.1.0b9") is None and keep.exists()
    # another AppImage starting: not its to do
    other = Host(home=host.home, environ={**host.environ, "APPIMAGE": str(keep)}, runner=host.runner)
    assert U.finish_pending(other, NEW) is None and keep.exists()
    # the new copy's start: the old copy goes, that file alone, and the record with it
    done = U.finish_pending(host, NEW)
    assert done == {"from": "0.1.0b9", "to": NEW, "kept": str(keep), "removed": True}
    assert not keep.exists() and f.exists() and U.load_pending(host) is None
    assert sorted(os.listdir(f.parent)) == [f.name]


def test_a_file_put_where_the_old_copy_was_is_never_removed(tmp_path):
    host, f, staged = verified_copy(tmp_path)
    keep = Path(U.replace(host, staged, "0.1.0b9")["keep"])
    keep.unlink()
    keep.write_bytes(b"someone else's file")                    # same name: another file, maybe the same inode number
    assert U.finish_pending(host, NEW)["removed"] is False and keep.read_bytes() == b"someone else's file"
    assert U.load_pending(host) is None


def test_putting_the_old_copy_back_by_hand_ends_the_record(tmp_path):
    host, f, staged = verified_copy(tmp_path)
    out = U.replace(host, staged, "0.1.0b9")
    os.replace(out["keep"], out["path"])                         # the hand undo it shows
    assert f.read_bytes().startswith(b"#!/bin/sh\necho 'DA Privacy Kit 0.1.0b9'")
    assert U.finish_pending(host, "0.1.0b9") is None and U.load_pending(host) is None


def test_without_hard_links_it_renames_twice(tmp_path, monkeypatch):
    host, f, staged = verified_copy(tmp_path)

    def no_link(*a, **kw):
        raise OSError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(U.os, "link", no_link)
    out = U.replace(host, staged, "0.1.0b9")
    assert f.read_bytes() == new_copy() and Path(out["keep"]).read_bytes().startswith(b"#!/bin/sh\necho 'DA Privacy")


@pytest.mark.parametrize("change, said", [
    (lambda f, s: f.write_bytes(b"changed meanwhile"), "has changed since the download began"),
    (lambda f, s: s.file.write_bytes(b"changed meanwhile"), "has changed since it was verified"),
    (lambda f, s: s.file.unlink(), "The download is gone"),
    (lambda f, s: f.with_name(f".{f.name}.0.1.0b9.old").write_bytes(b"x"), "is there already"),
    (lambda f, s: os.chmod(f.parent, 0o777), "can be changed by anyone"),
])
def test_replacing_is_refused_when_anything_changed_since_it_was_checked(tmp_path, change, said):
    host, f, staged = verified_copy(tmp_path)
    before = f.read_bytes()
    time.sleep(0.01)
    change(f, staged)
    with pytest.raises(U.UpdateError, match=said):
        U.replace(host, staged, "0.1.0b9")
    assert U.load_pending(host) is None
    if f.read_bytes() != b"changed meanwhile":
        assert f.read_bytes() == before
    os.chmod(f.parent, 0o700)


def test_a_failed_rename_leaves_everything_as_it_was(tmp_path, monkeypatch):
    host, f, staged = verified_copy(tmp_path)
    before = sorted(os.listdir(f.parent))

    def fail(*a):
        raise OSError(errno.EIO, "Input/output error")
    monkeypatch.setattr(U.os, "replace", fail)
    with pytest.raises(OSError):
        U.replace(host, staged, "0.1.0b9")
    assert sorted(os.listdir(f.parent)) == before and U.load_pending(host) is None


class FakeProc:
    def __init__(self, code=None):
        self.code = code

    def poll(self):
        return self.code


def test_restart_starts_the_new_copy_by_its_path_with_the_hosts_environment(tmp_path, monkeypatch):
    monkeypatch.setattr(U, "RESTART_WATCH", 0.05)
    host, f, staged = verified_copy(tmp_path, mode=0o755)
    with pytest.raises(U.UpdateError, match="No update is waiting"):
        U.restart(host, lambda *a, **kw: FakeProc())
    U.replace(host, staged, "0.1.0b9")
    spawned = []

    def spawn(argv, **kw):
        spawned.append((argv, kw))
        return FakeProc()
    U.restart(host, spawn, browser=True)
    argv, kw = spawned[0]
    assert argv == [str(f), "--browser"] and "APPIMAGE" not in kw["env"] and kw["start_new_session"]
    with pytest.raises(U.UpdateError, match="stopped at once \\(exit status 2\\)"):
        U.restart(host, lambda *a, **kw: FakeProc(2))
    f.unlink()
    f.write_bytes(b"something else")
    with pytest.raises(U.UpdateError, match="isn't the file the update put there"):
        U.restart(host, spawn)


# ------------------------------------------------------------------ the page's routes

H = {"X-Token": "t0ken"}


@contextlib.contextmanager
def client(cat, host, net=None, spawn=None):
    """The app's API with one event loop for the whole test (`with`): a job's task lives on it."""
    from fastapi.testclient import TestClient

    from daprivacyscanner.server import create_app
    nets = []

    def make_net():
        nets.append(net)
        return net or FakeNet()
    with TestClient(create_app("t0ken", cat, make_host=lambda: host, make_net=make_net,
                               spawn_app=spawn or (lambda *a, **kw: FakeProc()))) as c:
        yield c, nets


def wait_job(c) -> dict:
    for _ in range(300):
        d = c.get("/api/update", headers=H).json()
        if d["job"] and d["job"]["state"] not in ("running", "starting"):
            return d
        time.sleep(0.02)
    raise AssertionError("the job didn't end")


def test_nothing_is_contacted_until_the_user_checks_and_a_source_tree_isnt_updated_this_way(cat, tmp_path):
    bare = Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner())
    with client(cat, bare) as (c, nets):
        d = c.get("/api/update", headers=H).json()
        assert d["mode"] in ("source", "package") and d["hosts"]["check"] == ["api.github.com"] and not nets
        r = c.post("/api/update/check", headers=H)
        assert r.status_code == 409 and not nets
        assert c.post("/api/update/download", headers=H).status_code == 409 and not nets
        c.get("/api/state", headers=H)
        assert not nets                                                  # starting the page asks nothing either


@needs_gpg
def test_the_whole_way_through_the_api(cat, tmp_path, keys, monkeypatch):
    monkeypatch.setattr(U, "RESTART_WATCH", 0.05)
    project = keys.project(keys.primary)
    monkeypatch.setattr(K, "load", lambda *a, **kw: (project,))
    host, f = appimage_host(tmp_path)
    data = new_copy()
    sig_dir = tmp_path / "sig"
    sig_dir.mkdir()
    (sig_dir / NAME).write_bytes(data)
    keys.sign(sig_dir / NAME, keys.sub)
    rel = release_json(assets=None)
    for a in rel["assets"]:
        a["size"] = len(data) if a["name"] == NAME else (sig_dir / (NAME + ".asc")).stat().st_size \
            if a["name"] == NAME + ".asc" else a["size"]
        a.pop("digest", None)
    net = FakeNet(http={U.LATEST: HttpResult(200, json.dumps(rel).encode())},
                  files={DL + NAME: data, DL + NAME + ".asc": (sig_dir / (NAME + ".asc")).read_bytes()})
    spawned = []
    with client(cat, host, net, spawn=lambda argv, **kw: spawned.append(argv) or FakeProc()) as (c, nets):
        d = c.get("/api/update", headers=H).json()
        assert d["mode"] == "appimage" and d["path"] == str(f) and d["problem"] == "" and net.contacted == []
        assert c.post("/api/update/download", headers=H).status_code == 409          # check first
        d = c.post("/api/update/check", headers=H).json()
        assert d["release"]["version"] == NEW and d["compare"] == "newer" and net.contacted == [U.LATEST]
        r = c.post("/api/update/download", headers=H)
        assert r.status_code == 200 and r.json()["job"]["version"] == NEW            # a job; it may be done already
        d = wait_job(c)
        assert d["job"]["state"] == "done", d["job"]
        plan = d["plan"]
        assert plan["version"] == NEW and plan["verdict"]["title"] == "Verified: made by Digital Archon"
        assert plan["path"] == str(f) and Path(plan["staged"]).is_file() and plan["keep"].endswith(".old")
        assert c.post("/api/update/replace", headers=H, json={}).status_code == 400   # needs the user's yes
        d = c.post("/api/update/replace", headers=H, json={"confirm": True}).json()
        assert d["replaced"]["to"] == NEW and f.read_bytes() == data and Path(d["replaced"]["keep"]).exists()
        assert d["plan"] is None
        assert c.post("/api/update/restart", headers=H).json() == {"started": True} and spawned == [[str(f)]]
    # the new copy's first page: the old one goes
    monkeypatch.setattr(U, "finish_pending", lambda h, current=NEW, f=U.finish_pending: f(h, current))
    with client(cat, host) as (c2, _):
        c2.get("/api/state", headers=H)
        assert not Path(d["replaced"]["keep"]).exists() and f.exists()
        assert c2.get("/api/update", headers=H).json()["updated"]["removed"] is True


def test_a_download_that_fails_says_why_and_leaves_nothing(cat, tmp_path):
    host, f = appimage_host(tmp_path)
    rel = release_json()
    net = FakeNet(http={U.LATEST: HttpResult(200, json.dumps(rel).encode())},
                  files={DL + NAME: HttpResult(None, b"", "Connection reset by peer"), DL + NAME + ".asc": b"x" * 228})
    with client(cat, host, net) as (c, _):
        c.post("/api/update/check", headers=H)
        c.post("/api/update/download", headers=H)
        d = wait_job(c)
        assert d["job"]["state"] == "failed" and "couldn't be downloaded (Connection reset by peer)" in d["job"]["error"]
        assert sorted(os.listdir(f.parent)) == [f.name] and d["plan"] is None
        # the lock was let go: another try may start (a job of its own)
        r = c.post("/api/update/download", headers=H)
        assert r.status_code == 200 and r.json()["job"]["id"] != d["job"]["id"]
        wait_job(c)


def test_the_same_or_an_older_release_is_never_downloaded(cat, tmp_path):
    from daprivacyscanner import __version__
    host, f = appimage_host(tmp_path)
    net = FakeNet(http={U.LATEST: HttpResult(200, json.dumps(release_json(__version__)).encode())})
    with client(cat, host, net) as (c, _):
        assert c.post("/api/update/check", headers=H).json()["compare"] == "same"
        r = c.post("/api/update/download", headers=H)
        assert r.status_code == 409 and "No newer release" in r.json()["error"] and net.contacted == [U.LATEST]


def test_githubs_refusal_reaches_the_page(cat, tmp_path):
    host, f = appimage_host(tmp_path)
    with client(cat, host, FakeNet(http={U.LATEST: HttpResult(403, b"{}")})) as (c, _):
        r = c.post("/api/update/check", headers=H)
        assert r.status_code == 502 and "60 an hour" in r.json()["error"]


def test_quitting_deletes_a_download_not_put_in_place(cat, tmp_path):
    host, f, staged = verified_copy(tmp_path)
    with client(cat, host) as (c, _):
        c.app.state.update["staged"] = staged
        c.app.state.shutdown(wait=0, changes_wait=0)
        assert not staged.folder.exists() and f.exists()
