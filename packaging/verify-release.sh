#!/bin/bash
# Check that a release's AppImage is what its source builds to: build the release's tag from a clean checkout
# (rootless Podman, as packaging/build-appimage.sh does) and compare the result with the published SHA-256.
#   packaging/verify-release.sh v0.1.0b1                 the checksum from the release page (fetched over HTTPS)
#   packaging/verify-release.sh v0.1.0b1 FILE.AppImage   the file you downloaded: is it this build, byte for byte?
#   packaging/verify-release.sh v0.1.0b1 FILE.sha256     a checksum file you already have (nothing is fetched)
#   packaging/verify-release.sh v0.1.0b1 HEX             a checksum, 64 hex digits (nothing is fetched)
# Run it from a clone of the repository, with the tag fetched (git fetch --tags). Your working tree isn't
# touched: the tag is checked out beside it, built there, and removed. Exit status 0 when they are the same,
# 1 when they differ, 2 when it couldn't be checked.
set -euo pipefail
RELEASES="https://github.com/DigitalArchon/DAPrivacyKit/releases/download"

die() { echo "$*" >&2; exit 2; }
[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 TAG [FILE.AppImage | FILE.sha256 | SHA256]"
tag="$1"; given="${2:-}"
cd "$(git rev-parse --show-toplevel 2>/dev/null)" || die "Run this from a clone of the repository."
commit="$(git rev-parse --verify --quiet "$tag^{commit}")" \
    || die "There is no '$tag' here. Fetch the tags first: git fetch --tags"

WORK="$(mktemp -d)"
cleanup() { git worktree remove --force "$WORK/src" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
git worktree add --quiet --detach "$WORK/src" "$commit"
version="$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
    "$WORK/src/pyproject.toml")"
name="DAPrivacyKit-$version-x86_64.AppImage"

# what it should be
if [ -z "$given" ]; then
    url="$RELEASES/$tag/$name.sha256"
    echo "Fetching the published checksum: $url"
    expected="$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$url" | cut -d' ' -f1)" \
        || die "The checksum couldn't be fetched. Download $name.sha256 from the release page and pass it."
    from="the release page"
elif [[ "$given" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    expected="$given"; from="the checksum you gave"
elif [ -f "$given" ] && [[ "$given" == *.sha256 ]]; then
    expected="$(cut -d' ' -f1 "$given")"; from="$given"
elif [ -f "$given" ]; then
    expected="$(sha256sum "$given" | cut -d' ' -f1)"; from="$given"
else
    die "'$given' is neither a file nor a SHA-256 checksum."
fi
expected="${expected,,}"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "No SHA-256 checksum in $from."

echo "Building $tag ($(git rev-parse --short "$commit"), version $version) from a clean checkout..."
(cd "$WORK/src" && packaging/build-appimage.sh build) || die "The build failed."
built="$(sha256sum "$WORK/src/dist/$name" | cut -d' ' -f1)"

echo
echo "Built here:  $built"
echo "Expected:    $expected  ($from)"
if [ "$built" = "$expected" ]; then
    echo "The same: $name of $tag is what this source builds to."
else
    mkdir -p dist/verify
    cp "$WORK/src/dist/$name" "dist/verify/$name"
    echo "DIFFERENT: the release is not what this source builds to here." >&2
    echo "The build is kept in dist/verify/$name: diffoscope on the two files shows where they differ." >&2
    exit 1
fi
