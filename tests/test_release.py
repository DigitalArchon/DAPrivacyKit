"""The release process and what ties it together: the version, the counts the docs give, the licences and update
information the AppImage carries, the release key's successor and signing subkeys (tools/keys.py), and the scripts
that build, check and sign a release (packaging/*.sh), run against scratch repositories with throwaway keys made
here, and a fake podman."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

from daprivacyscanner import catalogue
from daprivacyscanner.tools import keys as K
from daprivacyscanner.tools import verify as V

ROOT = Path(__file__).resolve().parents[1]
needs_gpg = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("gpgv") and shutil.which("git")),
                               reason="gpg, gpgv and git are needed")


# ------------------------------------------------------------------ what the docs and the package say

def test_the_version_is_the_same_in_pyproject_and_the_package():
    import daprivacyscanner
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert daprivacyscanner.__version__ == version


def test_the_counts_the_docs_give_are_the_catalogues():
    """The README said 125 checks when there were 127, and TECHNICAL.md 133 entries when there were 143."""
    cat = catalogue.load(ROOT / catalogue.CATALOGUE_NAME)
    features = [s for s in cat if s.tier is catalogue.Tier.FEATURE]
    online = [s for s in cat if s.scope is catalogue.Scope.ONLINE and s not in features]
    checks = len(cat) - len(features) - len(online)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"\*\* (\d+) checks of", readme).group(1) == str(checks)
    assert re.search(r"\*\*(\d+) online tests\*\*", readme).group(1) == str(len(online))
    technical = (ROOT / "docs/TECHNICAL.md").read_text(encoding="utf-8")
    m = re.search(r"source of truth: (\d+) entries in (\w+) categories .*?of which (\d+) are online tests and (\d+) "
                  r"are features", technical, re.S)
    assert m and (int(m.group(1)), int(m.group(3)), int(m.group(4))) == (len(cat), len(online), len(features))
    words = {9: "nine", 10: "ten", 11: "eleven"}
    assert m.group(2) == words.get(len({s.category for s in cat}))


def test_the_release_key_file_is_the_key_the_app_pins():
    """docs/release-key.asc is what verify-tag.sh and sign-release.sh check with; signing-keys.yaml what the app
    verifies its own releases with: the same keys, subkeys included."""
    data = yaml.safe_load((ROOT / "signing-keys.yaml").read_text(encoding="utf-8"))
    entry = next(p for p in data["projects"] if p["id"] == "digitalarchon")
    pinned = {k["fingerprint"] for k in entry["keys"]}
    in_yaml = {(k.fingerprint, k.subkeys) for k in K.parse_keys(entry["key"])}
    in_docs = {(k.fingerprint, k.subkeys) for k in K.parse_keys((ROOT / "docs/release-key.asc").read_bytes())}
    assert in_docs == in_yaml and {f for f, _ in in_yaml} == pinned
    assert "3AA5C06133BBC05A4151EA415B5948EB785ED3AF" in pinned


def test_the_licences_name_the_releases_pinned():
    pins = (ROOT / "packaging/appimage/pins.sh").read_text(encoding="utf-8")
    sources = (ROOT / "packaging/appimage/licenses/SOURCES").read_text(encoding="utf-8")
    pbs_release, cpython = re.search(r"download/(\d+)/cpython-([\d.]+)%2B", pins).groups()
    runtime = re.search(r"type2-runtime/releases/download/(\d+)/", pins).group(1)
    assert f"python-build-standalone {pbs_release}, CPython {cpython}" in sources
    assert f"type2-runtime {runtime}," in sources
    for path in re.findall(r"^  (LICENSE\.[\w.-]+\.txt)", sources, re.M):
        assert (ROOT / "packaging/appimage/licenses/python" / path).is_file(), path
    for folder in ("libfuse", "squashfuse", "zstd", "zlib", "mimalloc", "musl"):
        assert any((ROOT / "packaging/appimage/licenses/runtime" / folder).iterdir()), folder
    build = (ROOT / "packaging/appimage/build.sh").read_text(encoding="utf-8")
    assert 'cp -r "$P/licenses/." "$D/"' in build and "sbom.py" in build and "fallbacks/SOURCES" in build


def test_the_appimage_names_its_updates_and_the_zsync_carries_nothing_of_this_machine():
    build = (ROOT / "packaging/appimage/build.sh").read_text(encoding="utf-8")
    assert '"gh-releases-zsync|DigitalArchon|DAPrivacyKit|latest|DAPrivacyKit-*-x86_64.AppImage.zsync"' in build
    assert 'touch -d "@$SOURCE_DATE_EPOCH" "/out/$NAME"' in build            # zsyncmake writes the file's mtime
    assert 'zsyncmake -u "$NAME" -o "$NAME.zsync" "$NAME"' in build            # the URL is the file's own name
    assert "zsync" in (ROOT / "packaging/appimage/Containerfile").read_text(encoding="utf-8")
    wrapper = (ROOT / "packaging/build-appimage.sh").read_text(encoding="utf-8")
    assert 'cmp -s "$WORK"/a/*.zsync "$WORK"/b/*.zsync' in wrapper              # check compares it too
    assert "hostca.crt:ro,Z" not in wrapper and 'install -m 0644 "$ca" "$WORK/context/hostca.crt"' in wrapper


def test_the_sbom_is_made_from_what_was_installed(tmp_path):
    import json
    import sys
    site = tmp_path / "site"
    (site / "fastapi-0.142.2.dist-info").mkdir(parents=True)
    (site / "fastapi-0.142.2.dist-info/METADATA").write_text("Name: fastapi\nVersion: 0.142.2\nLicense-Expression: MIT\n")
    (site / "pycairo-1.29.1.dist-info").mkdir()
    (site / "pycairo-1.29.1.dist-info/METADATA").write_text(
        "Name: pycairo\nVersion: 1.29.1\nClassifier: License :: OSI Approved :: GNU Lesser General Public License v2 "
        "(LGPLv2)\n")
    (tmp_path / "dl").mkdir()
    (tmp_path / "dl/fastapi-0.142.2-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "sd").mkdir()
    (tmp_path / "sd/pycairo-1.29.1.tar.gz").write_bytes(b"sdist")
    (tmp_path / "debs.txt").write_text("libgirepository-2.0-0\t2.80.0-6ubuntu3.10\tglib2.0 2.80.0-6ubuntu3.10\n")
    pins = (ROOT / "packaging/appimage/pins.sh").read_text(encoding="utf-8")
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1790000000",
           **{k: v for k, v in re.findall(r'^(\w+)="([^"]*)"', pins, re.M)}}
    out = tmp_path / "sbom.json"
    argv = [sys.executable, "-I", str(ROOT / "packaging/appimage/sbom.py"), str(out), "1.0", "c0ffee", str(site),
            str(tmp_path / "dl"), str(tmp_path / "sd"), str(tmp_path / "debs.txt")]
    subprocess.run(argv, env=env, check=True)
    first = out.read_bytes()
    subprocess.run(argv, env=env, check=True)
    assert out.read_bytes() == first                                          # the same inputs, the same bytes
    bom = json.loads(first)
    assert bom["metadata"]["timestamp"] == "2026-09-21T14:13:20Z"
    by = {c["name"]: c for c in bom["components"]}
    assert by["fastapi"]["hashes"][0]["content"] == hashlib.sha256(b"wheel").hexdigest()
    assert by["fastapi"]["licenses"] == [{"expression": "MIT"}]
    assert by["pycairo"]["hashes"][0]["content"] == hashlib.sha256(b"sdist").hexdigest()
    assert "built from this source archive" in by["pycairo"]["properties"][0]["value"]
    assert by["AppImage type2-runtime"]["version"] == "20251108"
    assert by["libgirepository-2.0-0"]["purl"].startswith("pkg:deb/ubuntu/libgirepository-2.0-0@2.80.0")


# ------------------------------------------------------------------ throwaway release keys

class Keys:
    """A GnuPG home of its own with a certify-only primary key and a signing subkey (the release key as it is to be:
    the primary offline, the subkey on a token), and `other`, a second primary key with a signing subkey."""

    def __init__(self, home: Path):
        self.home = home
        home.mkdir(mode=0o700)
        self.primary, self.sub = self._make("Test Release <release@example.org>")
        self.other, self.other_sub = self._make("Someone Else <else@example.org>")

    def gpg(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return subprocess.run(["gpg", "--homedir", str(self.home), "--batch", "--quiet", "--pinentry-mode", "loopback",
                               "--passphrase", "", *args], check=True, capture_output=True, **kw)

    def _make(self, uid: str) -> tuple[str, str]:
        self.gpg("--quick-gen-key", uid, "ed25519", "cert", "never")
        fprs = [ln.split(":")[9] for ln in self.gpg("--with-colons", "--list-keys", uid).stdout.decode().splitlines()
                if ln.startswith("fpr")]
        self.gpg("--quick-add-key", fprs[0], "ed25519", "sign", "never")
        lines = self.gpg("--with-colons", "--list-keys", uid).stdout.decode().splitlines()
        fprs = [ln.split(":")[9] for ln in lines if ln.startswith("fpr")]
        return fprs[0], fprs[1]

    def public(self, *fprs: str) -> bytes:
        return self.gpg("--armor", "--export-options", "export-minimal", "--export", *fprs).stdout

    def sign(self, path: Path, *signers: str) -> Path:
        users = [a for s in signers for a in ("--local-user", s + "!")]
        self.gpg("--yes", *users, "--armor", "--detach-sign", "--output", f"{path}.asc", str(path))
        return Path(f"{path}.asc")

    def close(self) -> None:
        subprocess.run(["gpgconf", "--homedir", str(self.home), "--kill", "all"], capture_output=True)


@pytest.fixture
def keys(tmp_path):
    k = Keys(tmp_path / "gnupg")
    yield k
    k.close()


def _project(block: bytes, pins: list[dict]) -> K.Project:
    return K.parse({"schema_version": 1, "projects": [{
        "id": "digitalarchon", "name": "Digital Archon", "signs": "releases", "source": "https://example.org",
        "key_from": "https://example.org/key.asc", "checked": __import__("datetime").date(2026, 11, 12),
        "files": ["DAPrivacyKit-*.AppImage"], "how": "the .asc", "keys": pins, "key": block.decode()}]})[0]


def _host(tmp_path):
    from daprivacyscanner.host import Host, SystemRunner
    home = tmp_path / "vhome"
    home.mkdir(exist_ok=True)
    environ = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    return Host(home=home, environ=environ, runner=SystemRunner(environ))


@needs_gpg
def test_a_release_signed_by_the_pinned_keys_subkey_is_verified(tmp_path, keys):
    """The release key is to become a certify-only primary kept offline, with its signing subkey on a token: only the
    primary is pinned, and a file the subkey signed is the project's."""
    p = _project(keys.public(keys.primary), [{"fingerprint": keys.primary, "name": "Test release key"}])
    assert p.subkeys == (keys.sub,) and K.owner([p], keys.sub)[0] is p
    f = tmp_path / "DAPrivacyKit-9.0-x86_64.AppImage"
    f.write_bytes(b"the release")
    keys.sign(f, keys.sub)
    v = V.verify(_host(tmp_path), f, projects=[p])
    assert v.level == "verified" and v.signatures[0].project is p
    # signed by the old key and the new subkey together (a key change): verified by either alone
    keys.sign(f, keys.sub, keys.other_sub)
    assert V.verify(_host(tmp_path), f, projects=[p]).level == "verified"
    q = _project(keys.public(keys.other), [{"fingerprint": keys.other, "name": "The old key"}])
    assert V.verify(_host(tmp_path), f, projects=[q]).level == "verified"


@needs_gpg
def test_a_subkey_spliced_in_from_another_key_is_never_the_projects(tmp_path, keys):
    """A subkey counts when its primary key binds it. One copied into the key block from another key (its packet and
    that key's binding) is left out, and gpgv doesn't take its signatures either."""
    ours = K.dearmor(keys.public(keys.primary))
    theirs = list(K.packets(K.dearmor(keys.public(keys.other))))
    spliced = b"".join(_packet(t, b) for t, b in theirs[next(i for i, (t, _) in enumerate(theirs)
                                                              if t == K.PUBLIC_SUBKEY):])
    info = K.parse_keys(ours + spliced)[0]
    assert info.subkeys == (keys.sub,) and info.unbound == (keys.other_sub,)
    p = _project(_armor(ours + spliced), [{"fingerprint": keys.primary, "name": "Test release key"}])
    assert p.subkeys == (keys.sub,) and K.owner([p], keys.other_sub) is None
    f = tmp_path / "file"
    f.write_bytes(b"x")
    keys.sign(f, keys.other_sub)
    assert V.verify(_host(tmp_path), f, projects=[p]).level != "verified"


def _packet(tag: int, body: bytes) -> bytes:
    return bytes([0xC0 | tag, 255]) + len(body).to_bytes(4, "big") + body


def _armor(data: bytes) -> bytes:
    import base64
    b64 = base64.b64encode(data).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{lines}\n-----END PGP PUBLIC KEY BLOCK-----\n".encode()


@needs_gpg
def test_a_successor_key_pinned_now_verifies_and_is_marked(tmp_path, keys):
    block = keys.public(keys.primary, keys.other)
    p = _project(block, [{"fingerprint": keys.primary, "name": "Release key"},
                         {"fingerprint": keys.other, "name": "Release key (successor)", "role": "successor"}])
    assert p.successors == (keys.other,) and p.key_name(keys.other) == "Release key (successor)"
    f = tmp_path / "file"
    f.write_bytes(b"x")
    keys.sign(f, keys.other_sub)
    assert V.verify(_host(tmp_path), f, projects=[p]).level == "verified"
    with pytest.raises(K.DataError, match="role current or successor"):
        _project(block, [{"fingerprint": keys.primary, "name": "a"}, {"fingerprint": keys.other, "name": "b",
                                                                        "role": "spare"}])
    with pytest.raises(K.DataError, match="needs a current one"):
        _project(keys.public(keys.other), [{"fingerprint": keys.other, "name": "b", "role": "successor"}])


def test_the_bundled_keys_still_load_with_every_subkey_bound():
    projects = K.load(ROOT / "signing-keys.yaml")
    assert all(not k.unbound for p in projects if p.key for k in K.parse_keys(p.key))
    assert sum(len(p.subkeys) for p in projects) >= 30


# ------------------------------------------------------------------ the scripts

def _git_env(tmp_path: Path, gnupg: Path | None = None) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    # podman: writes down how it was called; `run` leaves a fake build in the folder mounted at /out
    (bin_dir / "podman").write_text(f"""#!/bin/bash
echo "$@" >> {tmp_path / "podman.calls"}
if [ "$1" = image ] && [ "$2" = inspect ]; then cat {tmp_path / "image.id"} 2>/dev/null || exit 1; exit 0; fi
if [ "$1" = build ]; then echo "sha256:made-by-build" > {tmp_path / "image.id"}; fi
if [ "$1" = image ] && [ "$2" = rm ]; then rm -f {tmp_path / "image.id"}; fi
if [ "$1" = run ]; then
  for a in "$@"; do case "$a" in *:/out:Z) out="${{a%:/out:Z}}";; VERSION=*) v="${{a#VERSION=}}";; esac; done
  n="DAPrivacyKit-$v-x86_64.AppImage"; mkdir -p "$out"; printf 'appimage %s' "$v" > "$out/$n"
  printf 'zsync %s' "$v" > "$out/$n.zsync"; (cd "$out" && sha256sum "$n" > "$n.sha256")
fi
""")
    (bin_dir / "podman").chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "TMPDIR": str(tmp_path),
           "XDG_CACHE_HOME": str(tmp_path / "cache"), "XDG_STATE_HOME": str(tmp_path / "state"),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
           "GIT_AUTHOR_EMAIL": "t@example.org", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
    if gnupg:
        env["GNUPGHOME"] = str(gnupg)
    return env


def _repo(tmp_path: Path, env: dict, key: bytes, version: str = "1.0") -> Path:
    repo = tmp_path / "repo"
    for rel, text in {"pyproject.toml": f'[project]\nversion = "{version}"\n',
                      "packaging/appimage/pins.sh": (ROOT / "packaging/appimage/pins.sh").read_text(encoding="utf-8"),
                      "packaging/appimage/Containerfile": "FROM scratch\n"}.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs/release-key.asc").write_bytes(key)
    for argv in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "release"]):
        subprocess.run(["git", *argv], cwd=repo, env=env, check=True)
    return repo


def _sh(script: str, *args: str, cwd: Path, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(ROOT / "packaging" / script), *args], cwd=cwd, env=env, capture_output=True,
                          text=True, timeout=120)


def _tag(repo: Path, env: dict, signer: str | None, name: str = "v1.0") -> None:
    argv = ["tag", "-s", "-u", signer + "!", "-m", name, name] if signer else ["tag", "-a", "-m", name, name]
    subprocess.run(["git", "-c", "gpg.program=gpg", *argv], cwd=repo, env=env, check=True, capture_output=True)


@needs_gpg
def test_verify_tag_accepts_only_a_tag_signed_by_a_pinned_key(tmp_path, keys):
    env = _git_env(tmp_path, keys.home)
    repo = _repo(tmp_path, env, keys.public(keys.primary))
    _tag(repo, env, keys.sub)
    r = _sh("verify-tag.sh", "v1.0", cwd=repo, env=env)
    assert r.returncode == 0 and keys.primary in r.stdout
    _tag(repo, env, keys.other_sub, "v1.1")                      # a good signature, by a key the file doesn't hold
    assert _sh("verify-tag.sh", "v1.1", cwd=repo, env=env).returncode == 1
    _tag(repo, env, None, "v1.2")                                # annotated, unsigned: what tags before 0.1.0b9 are
    r = _sh("verify-tag.sh", "v1.2", cwd=repo, env=env)
    assert r.returncode == 3 and "not signed" in r.stderr
    assert _sh("verify-tag.sh", "v9", cwd=repo, env=env).returncode == 2


def _release_dir(repo: Path, env: dict, *, second: str | None = None) -> tuple[Path, str]:
    """dist/release/v1.0 as build-appimage.sh release and second-build.sh leave it."""
    r = _sh("build-appimage.sh", "release", "v1.0", cwd=repo, env=env)
    assert r.returncode == 0, r.stderr
    d = repo / "dist/release/v1.0"
    info = dict(ln.split("=", 1) for ln in (d / "BUILD-INFO").read_text().splitlines() if "=" in ln)
    commit = subprocess.run(["git", "rev-parse", "v1.0^{commit}"], cwd=repo, env=env, capture_output=True,
                            text=True).stdout.strip()
    assert info["commit"] == commit and info["kind"] == "tag"
    sha = second or info["appimage_sha256"]
    r = _sh("second-build.sh", "v1.0", "--record", sha, info["zsync_sha256"], "a test machine", cwd=repo, env=env)
    assert (r.returncode == 0) == (second is None), r.stdout + r.stderr
    return d, info["appimage_sha256"]


@needs_gpg
def test_a_release_is_signed_only_as_built_from_its_signed_tag_and_built_again_elsewhere(tmp_path, keys):
    env = _git_env(tmp_path, keys.home)
    repo = _repo(tmp_path, env, keys.public(keys.primary))
    _tag(repo, env, keys.sub)
    d, sha = _release_dir(repo, env)
    name = "DAPrivacyKit-1.0-x86_64.AppImage"
    assert _sh("sign-release.sh", "--check", "v1.0", cwd=repo, env=env).returncode == 0
    r = _sh("sign-release.sh", "v1.0", cwd=repo, env={**env, "DAPS_SIGNING_KEYS": keys.sub + "!"})
    assert r.returncode == 0, r.stderr
    (tmp_path / "pub.asc").write_bytes(keys.public(keys.primary))
    ring = tmp_path / "pub.gpg"
    ring.write_bytes(K.dearmor((tmp_path / "pub.asc").read_bytes()))
    for f in (name, f"{name}.sha256", f"{name}.zsync"):
        v = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", str(ring), str(d / f"{f}.asc"), str(d / f)],
                           capture_output=True, text=True)
        assert v.returncode == 0 and f"VALIDSIG {keys.sub}" in v.stdout and v.stdout.split()[-1] == keys.primary
    # a key change: the new subkey and the old key sign together, and the tag's keys must hold both (here they don't)
    r = _sh("sign-release.sh", "v1.0", cwd=repo, env={**env, "DAPS_SIGNING_KEYS": f"{keys.sub}! {keys.other_sub}!"})
    assert r.returncode == 1 and "1 good of 2" in r.stderr and not (d / f"{name}.asc").exists()

    # what it refuses
    def refused(why: str, **extra) -> None:
        r = _sh("sign-release.sh", "v1.0", cwd=repo, env={**env, "DAPS_SIGNING_KEYS": keys.sub + "!", **extra})
        assert r.returncode == 1 and why in r.stderr, r.stderr
    (d / f"{name}").write_bytes(b"changed after the build")
    refused("doesn't match the AppImage")
    (d / f"{name}").write_bytes(b"appimage 1.0")
    (d / "DAPrivacyKit-1.0+dev.abc-x86_64.AppImage").write_bytes(b"a dev build")
    refused("other builds are in")
    (d / "DAPrivacyKit-1.0+dev.abc-x86_64.AppImage").unlink()
    (d / "second-build.txt").unlink()
    refused("no second build")


@needs_gpg
def test_a_release_whose_second_build_differs_is_never_recorded_or_signed(tmp_path, keys):
    env = _git_env(tmp_path, keys.home)
    repo = _repo(tmp_path, env, keys.public(keys.primary))
    _tag(repo, env, keys.sub)
    d, _ = _release_dir(repo, env, second="0" * 64)
    assert not (d / "second-build.txt").exists()
    r = _sh("sign-release.sh", "v1.0", cwd=repo, env={**env, "DAPS_SIGNING_KEYS": keys.sub + "!"})
    assert r.returncode == 1 and "no second build" in r.stderr


@needs_gpg
def test_an_unsigned_tag_is_neither_built_as_a_release_nor_signed(tmp_path, keys):
    env = _git_env(tmp_path, keys.home)
    repo = _repo(tmp_path, env, keys.public(keys.primary))
    _tag(repo, env, None)
    r = _sh("build-appimage.sh", "release", "v1.0", cwd=repo, env=env)
    assert r.returncode == 1 and "isn't signed by a pinned release key" in r.stderr
    r = _sh("sign-release.sh", "v1.0", cwd=repo, env={**env, "DAPS_SIGNING_KEYS": keys.sub + "!"})
    assert r.returncode == 1 and "must be a tag signed" in r.stderr


@needs_gpg
def test_a_tag_naming_another_version_isnt_built(tmp_path, keys):
    env = _git_env(tmp_path, keys.home)
    repo = _repo(tmp_path, env, keys.public(keys.primary), version="1.1")
    _tag(repo, env, keys.sub)
    r = _sh("build-appimage.sh", "release", "v1.0", cwd=repo, env=env)
    assert r.returncode == 1 and "version is 1.1" in r.stderr


def test_a_dev_build_never_takes_a_releases_name_or_place(tmp_path):
    env = _git_env(tmp_path)
    repo = _repo(tmp_path, env, b"")
    commit = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=repo, env=env, capture_output=True,
                            text=True).stdout.strip()
    assert _sh("build-appimage.sh", "dev", cwd=repo, env=env).returncode == 0
    assert (repo / f"dist/dev/DAPrivacyKit-1.0+dev.{commit}-x86_64.AppImage").is_file()
    assert not list((repo / "dist").glob("*.AppImage"))
    run = (tmp_path / "podman.calls").read_text().splitlines()[-1]
    assert "UPDATE_INFO=0" in run                                              # no update information
    (repo / "pyproject.toml").write_text('[project]\nversion = "1.0"\n# changed\n')
    assert _sh("build-appimage.sh", "dev", cwd=repo, env=env).returncode == 0
    assert (repo / f"dist/dev/DAPrivacyKit-1.0+dev.{commit}.dirty-x86_64.AppImage").is_file()
    assert _sh("build-appimage.sh", "build", cwd=repo, env=env).returncode == 0
    assert "UPDATE_INFO=1" in (tmp_path / "podman.calls").read_text().splitlines()[-1]


def test_a_builder_image_this_script_didnt_make_is_made_again(tmp_path):
    """build-appimage.sh trusted any local image carrying the expected tag."""
    env = _git_env(tmp_path)
    repo = _repo(tmp_path, env, b"")
    assert _sh("build-appimage.sh", "build", cwd=repo, env=env).returncode == 0
    calls = (tmp_path / "podman.calls").read_text()
    assert calls.count("build --no-cache") == 1                               # made, and its ID recorded
    assert _sh("build-appimage.sh", "build", cwd=repo, env=env).returncode == 0
    assert (tmp_path / "podman.calls").read_text().count("build --no-cache") == 1      # the recorded one is used
    (tmp_path / "image.id").write_text("sha256:someone-elses\n")              # the tag now names another image
    r = _sh("build-appimage.sh", "build", cwd=repo, env=env)
    assert r.returncode == 0 and "isn't the one this script made" in r.stderr
    assert (tmp_path / "podman.calls").read_text().count("build --no-cache") == 2
    # the build context holds a copy of the CA bundle, never a mount of the host's own file
    assert ":Z" not in next(ln for ln in (tmp_path / "podman.calls").read_text().splitlines() if ln.startswith("build"))
