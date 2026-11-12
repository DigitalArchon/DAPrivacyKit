# Packaging: the AppImage

DA Privacy Kit ships as a single AppImage for x86-64 Linux, built so that anyone can rebuild
a release from its commit and get the same file, byte for byte. The build follows DAToolkit's
(same pins, same container), adapted for the administrator helper.

## What's in it, and what comes from the system

| In the AppImage | From the system |
|---|---|
| Python 3.12 ([python-build-standalone](https://github.com/astral-sh/python-build-standalone)) | GTK 3 and **WebKitGTK 4.1** (the app window) |
| Every Python dependency, pinned with hashes | `/usr/bin/python3` and `pkexec` (the administrator helper) |
| PyGObject and pycairo, built from pinned sources | The tools a scan reads with (`lsblk`, `nmcli`, `gsettings`, `systemctl`, ...) |
| A fallback `libgirepository-2.0` and base typelibs for hosts that lack them | |
| The catalogue (`privacy-checks.yaml`) and the data beside it (`vpn-providers.yaml`, `browsers.yaml`, `signing-keys.yaml`, `apps.yaml`), copied into the package | |

WebKitGTK is not bundled, so it gets the distribution's security updates. Without it the app says
what to install and stops (`--browser` opens it in the web browser, for those who accept that browser
extensions can read the page):

| Distribution | Install the app window's engine |
|---|---|
| Ubuntu 24.04+, Mint 22+, Debian 13+ | `sudo apt install gir1.2-webkit2-4.1` |
| Fedora | `sudo dnf install webkit2gtk4.1` |
| Arch, CachyOS | `sudo pacman -S webkit2gtk-4.1` |

The bundled PyGObject needs GLib 2.80 or newer, which sets the oldest supported systems:
Ubuntu 24.04 / Mint 22, Debian 13, and current Fedora and Arch. The AppImage uses the static
type 2 runtime, so it doesn't need `libfuse2`.

## The administrator helper

Root work goes through `helper.py`, run by the **system's** `/usr/bin/python3` under pkexec. An
AppImage's files are on a FUSE mount that only the user who started it can open (root included),
so until the helper is installed the app copies it to a private folder first
(`$XDG_RUNTIME_DIR/daprivacyscanner`, 0700) and runs that copy. The password prompt then names
python3, as it does from a source tree.

Installing it root-owned, with its own polkit action, is one click in the app (the "helper not
installed" note) or `DAPrivacyKit-*.AppImage --install-helper`. History offers to remove it
again while it is installed (or `--uninstall-helper`); the changes it made stay revertible. The
helper installs itself: what it writes is the code it is running, and its polkit action is a
constant in it (kept equal to `au.com.digitalarchon.daprivacyscanner.policy` by a test). A new
AppImage whose helper protocol differs says the installed one is out of date and offers to
install its own. From a source tree, `sudo packaging/install-helper.sh` does the same.

## Removing the app

`packaging/uninstall.sh` removes what is the app's own from an account: scheduled scans, the Outbox's watcher and
the right-click entries (which run the app), its data and settings, and, as administrator, the helper with its
journal. It never touches the fixes the user applied or their files, needs nothing from the app (it works after
the AppImage is gone), asks before each part, and has `--dry-run`, `--yes`, `--keep-data` and `--no-root`. The
manual's section 12 is what users are pointed at. Keep it in step with what the app installs
(`tests/test_uninstall_script.py` runs it against a scratch home).

## Building

You need rootless [Podman](https://podman.io) (`sudo apt install podman`).

```bash
packaging/build-appimage.sh build        # dist/DAPrivacyKit-<version>-x86_64.AppImage (+ .sha256, .zsync)
packaging/build-appimage.sh check        # build twice from scratch, compare: must be identical
packaging/build-appimage.sh release TAG  # a release: its signed tag, twice, into dist/release/TAG (below)
packaging/build-appimage.sh dev          # the working tree, uncommitted changes included: never a release
packaging/verify-release.sh TAG          # build a release's tag afresh and compare with its published checksum
packaging/test-appimage.sh               # smoke-test it, extracted, on Ubuntu, Debian, Fedora, Arch, CachyOS
packaging/test-appimage.sh --mounted     # the same, run as users do: the AppImage file, mounted with FUSE
packaging/build-appimage.sh lock         # re-resolve the dependency locks (review the diff, commit)
```

`build`, `check` and `release` build only committed files: the commit's tree as git stores it, whatever this
machine's git settings (line endings, the archive's umask); `dev` and `lock` read the working tree. Every timestamp
is the commit's time (`SOURCE_DATE_EPOCH`). Builds run in `packaging/appimage/Containerfile` (the one of the commit
built): Ubuntu 24.04 pinned by digest, with packages from the Ubuntu archive as it was at a fixed moment
([snapshot.ubuntu.com](https://snapshot.ubuntu.com)). The host's CA bundle, which apt needs to reach the snapshot,
goes into the builder as a copy, never a mount (on an SELinux host a mount needs `:Z`, and nothing should relabel
the system's bundle). The builder image is trusted only when its ID is the one the script recorded when it made it
(in `~/.local/state/daprivacyscanner-appimage`, which the build container can't write); otherwise it is made again
from nothing, as it is with `FRESH=1`, which also downloads everything again. Downloads are cached in
`~/.cache/daprivacyscanner-appimage` and verified against the pins on every build.

A `dev` build is named `DAPrivacyKit-<version>+dev.<commit>[.dirty]-x86_64.AppImage` and goes into `dist/dev/`: it
can never take a release's name or place, or be signed, and it carries no update information.

The smoke test runs as an ordinary user in each container (the app refuses to run as root):
a terminal scan in which no check may fail with an error; without WebKitGTK, the app refusing to
open and saying why, then with `--browser` scanning and exporting through its API; then, with WebKitGTK, the app
window, and a screenshot of the page after a scan in `dist/test/<distro>.png` (CachyOS on
Wayland, the rest on X). By default it runs the extracted AppImage; `--mounted` runs the AppImage file itself, which
its runtime mounts with FUSE every time (the container gets `/dev/fuse` and the right to mount in its own user
namespace), and checks what only happens there: root can't read a FUSE mount, so the app copies `helper.py` into
the runtime folder, and root runs that copy with the system's python3, which must answer as this version's helper.

## What the AppImage carries besides the app

- `usr/share/licenses/daprivacyscanner/`: the app's licence; the bundled Python's and the AppImage runtime's
  licence texts, with the libraries built into each (OpenSSL, SQLite, libfuse, zstd...), from
  `appimage/licenses/` (its `SOURCES` says which archive each came from, with its checksum); pycairo's, from its
  source; the Ubuntu copyright file of each package the fallback `libgirepository-2.0` and typelibs came from, with
  where their source is (`fallbacks/SOURCES`: the pinned snapshot, and the `apt-get source` lines); and
  `sbom.cdx.json`, a CycloneDX SBOM of every component, made from the pins and locks with the hash of each file
  the build used (`appimage/sbom.py`). The build fails if a Python package ships without a licence.
- Update information in the runtime's `.upd_info` section:
  `gh-releases-zsync|DigitalArchon|DAPrivacyKit|latest|DAPrivacyKit-*-x86_64.AppImage.zsync`. AppImageUpdate, Gear
  Lever and AppImageLauncher read it when the user asks them to update, fetch the latest release's `.zsync` (made
  by the build with the snapshot's `zsyncmake`, dated to the commit, its URL the file's own name, so it is
  reproducible too) and then only the blocks that changed, checked against it. The app itself never looks for
  updates by itself: its own **Check for updates…** (`update.py`, only when the user clicks it) reads GitHub's API
  for the latest release and takes its AppImage and `.asc` (not the `.zsync`), verified with the release key the
  copy carries and asked its version (`--version`) before it replaces the copy at the same path.

## What is pinned, and where

| What | Pinned in |
|---|---|
| Base image (digest), apt snapshot, Python build, AppImage runtime | `appimage/pins.sh` |
| Runtime Python packages (wheels, with hashes) | `appimage/requirements.lock` |
| PyGObject, pycairo (source archives, with hashes) | `appimage/sdists.lock` |
| meson, meson-python, ninja, setuptools (with hashes) | `appimage/build-requirements.lock` |
| The builder's own tools (gcc, mksquashfs, zsyncmake, desktop-file-validate), by the apt snapshot | `appimage/pins.sh`, `appimage/Containerfile` |
| The local CI's tools: ruff, mypy, coverage, shellcheck, pytest, httpx, hypothesis (with hashes) | `ci/requirements.lock` (from `ci/requirements.in`) |
| jsdom, for the front-end test (with integrity hashes) | `../tests/web/package-lock.json` |

Changing any of these changes the AppImage, which is the point: an update is a reviewed commit.
Runtime packages are installed only as prebuilt wheels, except `proxy-tools` (pywebview's, which
publishes none: `SDIST_ONLY` in `appimage/build.sh`), built from its pinned source.

## Verifying a release

Each release comes with its AppImage and the AppImage's `.sha256`.

```bash
sha256sum -c DAPrivacyKit-<version>-x86_64.AppImage.sha256     # the download isn't damaged
packaging/verify-release.sh v<version>                          # the release is what its source builds to
packaging/verify-release.sh v<version> DAPrivacyKit-<version>-x86_64.AppImage    # ... and so is your file
```

`verify-release.sh` first checks the tag's own signature (`verify-tag.sh`: a good signature whose primary key is in
`docs/release-key.asc` of your clone, never the tag's own copy; tags before 0.1.0b9 carry none, and it says so),
and that the tag is `v<version>` of the commit it names. Then it checks the tag out beside your working tree (which
it doesn't touch), builds it as `build-appimage.sh build` does, and compares the result with the published checksum
(fetched over HTTPS from the release page), with a `.sha256` file or checksum you give it, or with the AppImage you
downloaded. It exits 0 when they are the same; when they differ it keeps its build in `dist/verify/`, and
`diffoscope` on the two files shows where. Run it from a clone with the tag fetched (`git fetch --tags`); it needs
rootless Podman.

The `.sha256` alone only shows the download wasn't damaged: whoever could change the AppImage on the release
page could change the checksum next to it. Rebuilding is what ties the file to the source. The signature does
it without a rebuild: the app's own Verify a download (`daprivacyscanner --verify`, with the `.asc` beside the
file) or `gpg --verify` with the release key (below).

## Releasing

A signature says "this is what the tag builds to", so it is made only once that is shown, and never on a file that
could be anything else:

1. Update the version in `pyproject.toml` and `src/daprivacyscanner/__init__.py` (a test ties them), commit.
2. `.venv/bin/python packaging/check-signing-keys.py`: every fingerprint in `signing-keys.yaml` is
   still on its project's page (re-export a key whose subkeys have changed, and commit).
3. `.venv/bin/python packaging/check-app-versions.py --brief review.md`: every app in `apps.yaml` against its
   latest release (Repology). It exits 1 when an app has a new major version: review those with the brief (what
   each check relies on, where its code is, what to read upstream; hand it to Claude Code), fix what changed, and
   record each with `--mark APP VERSION [--tested]`. `--installed` compares this computer's versions instead.
4. `make release-check` (`packaging/check.sh --release`): on a clean tree, every check and suite, the AppImage
   built twice and compared, and the smoke test extracted and mounted on every distribution.
5. A signed tag: `git tag -s v<version> -m 'DA Privacy Kit <version>'` (with `user.signingkey` the release key's
   signing (sub)key, `<fingerprint>!`).
6. `packaging/build-appimage.sh release v<version>`: refuses a tag that isn't signed by a pinned key or isn't
   `v<version>` of its commit; builds it twice, compared, into `dist/release/v<version>/` with `BUILD-INFO`.
7. `packaging/second-build.sh v<version> HOST`: another machine (git and rootless Podman, e.g. a second PC of your own) gets a
   bundle of that one commit, builds it with a builder image and downloads of its own (`FRESH=1`), and its AppImage
   and `.zsync` must be the same bytes; only then is `second-build.txt` written. A machine you can't reach over ssh:
   run `packaging/verify-release.sh v<version> <the SHA-256 here>` there, and record what it printed with
   `packaging/second-build.sh v<version> --record SHA256 ZSYNC_SHA256 "that machine"`.
8. Sign: `DAPS_SIGNING_KEYS='<signing key fingerprint>!' packaging/sign-release.sh v<version>` (below).
9. Attach the AppImage, its `.sha256`, its `.zsync` and the three `.asc` files to the release (the `.zsync` must be
   on the latest release for AppImage updaters). Publish it as a release, neither a draft nor a pre-release, tagged
   `v<version>`, with the AppImage and its `.asc` under exactly those names: Check for updates… in every copy takes
   GitHub's latest release only in that form, and only with an `.asc` signature by a key that copy pins (during a
   key change, the old key's too: docs/RELEASE-KEYS.md). Its notes end with the Verify section sign-release.sh prints:
   `gpg --verify` on the `.asc` with the key's fingerprint, `sha256sum -c` on the `.sha256`, the SHA-256 itself, and
   `packaging/verify-release.sh v<version>` for anyone who wants to rebuild it from the tag and compare.
10. After publishing, run `packaging/verify-release.sh v<version>` yourself: it fetches the published checksum and
   builds the tag again, so what is on the release page is known to be what the tag builds to.

The build writes the date of the release's commit into the package (`_built.py`, from `SOURCE_DATE_EPOCH`, so it
doesn't break reproducibility). The app never looks for a newer version of itself by itself (Check for updates…
asks only when clicked); from that date it says, once its copy is more than 90 days old (`about.OLD_AFTER_DAYS`),
that a newer one is probably out and where (`about.LINKS["releases"]`): at the top of the page, with Check for
updates…, and in the text report, which also carries the version.

Signing: `DAPS_SIGNING_KEYS='<fingerprint>! [<fingerprint>!...]' packaging/sign-release.sh TAG` signs only
`dist/release/TAG/` as step 6 built it: the tag verified again, `BUILD-INFO` of the tag's commit, the AppImage,
its `.sha256` and its `.zsync` unchanged since (their hashes), no other AppImage beside them, and the second
machine's hashes the same. Each file gets one `.asc` holding a signature by every key named (during a key change,
the new signing subkey and the old key), each checked with gpgv against the tag's own `docs/release-key.asc`: it
refuses a key the release doesn't pin. `--check TAG` runs every check without a key.

The release key today is Digital Archon Release Signing, `3AA5 C061 33BB C05A 4151  EA41 5B59 48EB 785E D3AF`, an
ed25519 key used only for this: its public half is `docs/release-key.asc`, the `digitalarchon` entry of
`signing-keys.yaml` (so Verify a download recognises the app's own releases) and the README; the private half and
its revocation certificate are kept by its owner, backed up offline, never on a machine where automated agents
run. It has no expiry on purpose: every copy of the app carries the public key and never fetches keys, so an
extended expiry would never reach old copies, which would then call new releases signed by an expired key. For the
same reason a lost or stolen key can't be revoked in copies already out, so it is to be replaced by a certify-only
primary key kept offline, its signing subkey on a hardware token and a successor key pinned now:
[docs/RELEASE-KEYS.md](../docs/RELEASE-KEYS.md) is the owner's procedure, with every command. The app is ready for
it: only primary keys are pinned, subkeys count when their primary binds them, and a key marked `role: successor`
verifies too (`tools/keys.py`).

Rebuild and re-release when a pinned dependency has a security fix: the locks don't move by
themselves. WebKitGTK and GTK update with the system.
