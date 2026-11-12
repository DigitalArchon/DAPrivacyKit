#!/bin/bash
# Sign a release: a detached, armoured OpenPGP signature for each AppImage in dist/ and its .sha256,
# made with the release key named by DAPS_SIGNING_KEY (its fingerprint), then checked with gpgv
# against that key alone. Users verify with Verify a download, once the key's fingerprint is in
# signing-keys.yaml (and on the project's page), or by hand:
#     gpg --verify DAPrivacyKit-<version>-x86_64.AppImage.asc
# The private key never leaves your keyring; nothing here goes online.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DAPS_SIGNING_KEY:?set DAPS_SIGNING_KEY to the fingerprint of the release key (40 hex digits)}"
if [[ ! "$DAPS_SIGNING_KEY" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    echo "DAPS_SIGNING_KEY must be the full fingerprint, not a short id or a name" >&2
    exit 2
fi
shopt -s nullglob
files=(dist/DAPrivacyKit-*-x86_64.AppImage dist/DAPrivacyKit-*-x86_64.AppImage.sha256)
if [ ${#files[@]} -eq 0 ]; then
    echo "nothing to sign in dist/: build first (packaging/build-appimage.sh build)" >&2
    exit 2
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gpg --export "$DAPS_SIGNING_KEY" > "$tmp/release.gpg"
[ -s "$tmp/release.gpg" ] || { echo "the key $DAPS_SIGNING_KEY isn't in your keyring" >&2; exit 2; }
for f in "${files[@]}"; do
    gpg --batch --yes --local-user "$DAPS_SIGNING_KEY" --armor --detach-sign --output "$f.asc" "$f"
    gpgv --keyring "$tmp/release.gpg" "$f.asc" "$f" 2>/dev/null || { echo "the signature of $f doesn't check" >&2; exit 1; }
    echo "signed: $f.asc"
done
