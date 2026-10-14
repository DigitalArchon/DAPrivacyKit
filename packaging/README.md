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
packaging/build-appimage.sh build    # dist/DAPrivacyKit-<version>-x86_64.AppImage (+ .sha256)
packaging/build-appimage.sh check    # build twice from scratch, compare: must be identical
packaging/build-appimage.sh dev      # the working tree, uncommitted changes included (not a release)
packaging/verify-release.sh TAG      # build a release's tag afresh and compare with its published checksum
packaging/test-appimage.sh           # smoke-test it on Ubuntu, Debian, Fedora, Arch, CachyOS
packaging/build-appimage.sh lock     # re-resolve the dependency locks (review the diff, commit)
```

`build` and `check` build only committed files (`git archive HEAD`); `dev` and `lock` read the
working tree. Every timestamp is HEAD's commit time (`SOURCE_DATE_EPOCH`). Builds run in
`packaging/appimage/Containerfile`: Ubuntu 24.04 pinned by digest, with packages from the Ubuntu
archive as it was at a fixed moment ([snapshot.ubuntu.com](https://snapshot.ubuntu.com)).
Downloads are cached in `~/.cache/daprivacyscanner-appimage` and verified on every build.

The smoke test runs as an ordinary user in each container (the app refuses to run as root):
a terminal scan in which no check may fail with an error; without WebKitGTK, the app refusing to
open and saying why, then with `--browser` scanning and exporting through its API; then, with WebKitGTK, the app
window, and a screenshot of the page after a scan in `dist/test/<distro>.png` (CachyOS on
Wayland, the rest on X).

## What is pinned, and where

| What | Pinned in |
|---|---|
| Base image (digest), apt snapshot, Python build, AppImage runtime | `appimage/pins.sh` |
| Runtime Python packages (wheels, with hashes) | `appimage/requirements.lock` |
| PyGObject, pycairo (source archives, with hashes) | `appimage/sdists.lock` |
| meson, meson-python, ninja, setuptools (with hashes) | `appimage/build-requirements.lock` |

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

`verify-release.sh` checks the release's tag out beside your working tree (which it doesn't touch), builds it
as `build-appimage.sh build` does, and compares the result with the published checksum (fetched over HTTPS from
the release page), with a `.sha256` file or checksum you give it, or with the AppImage you downloaded. It exits 0
when they are the same; when they differ it keeps its build in `dist/verify/`, and `diffoscope` on the two files
shows where. Run it from a clone with the tag fetched (`git fetch --tags`); it needs rootless Podman.

The `.sha256` alone only shows the download wasn't damaged: whoever could change the AppImage on the release
page could change the checksum next to it. Rebuilding is what ties the file to the source. The signature does
it without a rebuild: the app's own Verify a download (`daprivacyscanner --verify`, with the `.asc` beside the
file) or `gpg --verify` with the release key (below).

## Releasing

1. Update the version in `pyproject.toml` and `src/daprivacyscanner/__init__.py`, commit, tag (`v<version>`).
2. `.venv/bin/python packaging/check-signing-keys.py`: every fingerprint in `signing-keys.yaml` is
   still on its project's page (re-export a key whose subkeys have changed, and commit).
3. `.venv/bin/python packaging/check-app-versions.py --brief review.md`: every app in `apps.yaml` against its
   latest release (Repology). It exits 1 when an app has a new major version: review those with the brief (what
   each check relies on, where its code is, what to read upstream; hand it to Claude Code), fix what changed, and
   record each with `--mark APP VERSION [--tested]`. `--installed` compares this computer's versions instead.
4. `packaging/build-appimage.sh check` (reproducible), then `packaging/test-appimage.sh`.
5. Sign: `DAPS_SIGNING_KEY=3AA5C06133BBC05A4151EA415B5948EB785ED3AF packaging/sign-release.sh` (below).
6. Attach the AppImage, its `.sha256` and the two `.asc` files to the release. Its notes end with a Verify
   section: `gpg --verify` on the `.asc` with the key's fingerprint, `sha256sum -c` on the `.sha256`, the SHA-256
   itself, and `packaging/verify-release.sh v<version>` for anyone who wants to rebuild it from the tag and compare.
7. After publishing, run `packaging/verify-release.sh v<version>` yourself: it fetches the published checksum and
   builds the tag again, so what is on the release page is known to be what the tag builds to.

The build writes the date of the release's commit into the package (`_built.py`, from `SOURCE_DATE_EPOCH`, so it
doesn't break reproducibility). The app never looks for a newer version of itself; from that date it says, once
its copy is more than 90 days old (`about.OLD_AFTER_DAYS`), that a newer one is probably out and where
(`about.LINKS["releases"]`): at the top of the page, and in the text report, which also carries the version.

Signing: `DAPS_SIGNING_KEY=<fingerprint> packaging/sign-release.sh` makes a detached `.asc` for the AppImage and
its `.sha256`, checked with gpgv before it finishes; attach both. The release key is Digital Archon Release Signing,
`3AA5 C061 33BB C05A 4151  EA41 5B59 48EB 785E D3AF`, an ed25519 key used only for this: its public half is `docs/release-key.asc`, the
`digitalarchon` entry of `signing-keys.yaml` (so Verify a download recognises the app's own releases) and the README;
the private half and its revocation certificate are kept by its owner, backed up offline, never on a machine where
automated agents run. It has no expiry on purpose: every copy of the app carries the public key and never fetches
keys, so an extended expiry would never reach old copies, which would then call new releases signed by an expired
key. If it is ever lost or compromised, publish the revocation certificate, make a new key and release with it,
and say so on the release page: copies already out trust the old key until they are updated.
On a machine without the repository: check the files' SHA-256 against the build, then `gpg --local-user
<fingerprint> --armor --detach-sign FILE` for each.

Rebuild and re-release when a pinned dependency has a security fix: the locks don't move by
themselves. WebKitGTK and GTK update with the system.
