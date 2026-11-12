#!/bin/bash
# Sign a release, and nothing else: the build of one signed tag, which a second machine has built to the same bytes.
#   DAPS_SIGNING_KEYS="<fingerprint>! [<fingerprint>...]" packaging/sign-release.sh TAG
#   packaging/sign-release.sh --check TAG        every check below, nothing signed (no key needed)
# What it refuses, so that a signature only ever vouches for what the tag builds to:
#   - a TAG that isn't a tag signed by a release key the app pins (packaging/verify-tag.sh), or isn't v<version> of
#     the commit it names;
#   - anything but dist/release/TAG/ as `packaging/build-appimage.sh release TAG` made it: that commit (BUILD-INFO),
#     the AppImage, its .sha256 and its .zsync, and no other AppImage beside them;
#   - a build no second machine reproduced: dist/release/TAG/second-build.txt (packaging/second-build.sh) must give
#     the same SHA-256 for the AppImage and the .zsync as this build and the files as they are now.
# Each of the three files gets a detached, armoured signature (.asc) by every key in DAPS_SIGNING_KEYS (during a key
# change, the new signing subkey and the old key, so copies that know only the old key still verify), checked with
# gpgv against the public keys of the tag itself (docs/release-key.asc, which a test keeps equal to signing-keys.yaml,
# what the released app will verify its successors with): every signature good, each by a pinned primary key.
# A fingerprint ending in "!" makes gpg use exactly that (sub)key: the signing subkey on the hardware token. The
# private keys never leave the owner's keyring and token; nothing here goes online.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
check_only=0
if [ "${1:-}" = --check ]; then check_only=1; shift; fi
[ $# -eq 1 ] || { echo "usage: DAPS_SIGNING_KEYS=... $0 [--check] TAG" >&2; exit 2; }
tag="$1"
die() { echo "Not signing: $*" >&2; exit 1; }

packaging/verify-tag.sh "$tag" || die "$tag must be a tag signed by a pinned release key (git tag -s)."
commit="$(git rev-parse "refs/tags/$tag^{commit}")"
version="$(git show "$commit:pyproject.toml" | python3 -c 'import sys, tomllib; print(tomllib.load(sys.stdin.buffer)["project"]["version"])')"
[ "$tag" = "v$version" ] || die "the tag $tag names version $version (a release's tag is v<version>)."
dir="dist/release/$tag"
name="DAPrivacyKit-$version-x86_64.AppImage"
[ -f "$dir/BUILD-INFO" ] || die "no $dir/BUILD-INFO: build it first (packaging/build-appimage.sh release $tag)."
info() { sed -n "s/^$2=//p" "$1" | tail -1; }
[ "$(info "$dir/BUILD-INFO" commit)" = "$commit" ] || die "$dir was built from $(info "$dir/BUILD-INFO" commit), not $tag ($commit)."
[ "$(info "$dir/BUILD-INFO" kind)" = tag ] || die "$dir wasn't built from the tag."
for f in "$name" "$name.sha256" "$name.zsync"; do
    [ -f "$dir/$f" ] && [ ! -L "$dir/$f" ] || die "$dir/$f is missing (or is a link)."
done
others="$(find "$dir" -maxdepth 1 -type f \( -name '*.AppImage' -o -name '*.zsync' \) ! -name "$name" ! -name "$name.zsync")"
[ -z "$others" ] || die "other builds are in $dir: $others"
sum="$(sha256sum "$dir/$name" | cut -d' ' -f1)"
zsum="$(sha256sum "$dir/$name.zsync" | cut -d' ' -f1)"
[ "$(cut -d' ' -f1 "$dir/$name.sha256")" = "$sum" ] || die "$name.sha256 doesn't match the AppImage."
[ "$(info "$dir/BUILD-INFO" appimage_sha256)" = "$sum" ] || die "the AppImage changed since it was built ($sum)."
[ "$(info "$dir/BUILD-INFO" zsync_sha256)" = "$zsum" ] || die "the .zsync changed since it was built."
second="$dir/second-build.txt"
[ -f "$second" ] || die "no second build: packaging/second-build.sh $tag HOST (or --record), then sign."
[ "$(info "$second" commit)" = "$commit" ] || die "the second build was of another commit."
[ "$(info "$second" appimage_sha256)" = "$sum" ] || die "the second machine's AppImage is $(info "$second" appimage_sha256), not $sum."
[ "$(info "$second" zsync_sha256)" = "$zsum" ] || die "the second machine's .zsync differs."
echo "$tag ($commit): $name, $sum"
echo "  built twice here and once on $(info "$second" host) ($(info "$second" date)): the same bytes."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# the keys the released app pins, from the tag itself: what its successors will be verified with
git show "$commit:docs/release-key.asc" > "$tmp/release-key.asc"
mkdir -m 700 "$tmp/g"
gpg --homedir "$tmp/g" --batch --quiet --import "$tmp/release-key.asc"
gpg --homedir "$tmp/g" --batch --export > "$tmp/release.gpg"
pinned="$(gpg --homedir "$tmp/g" --batch --with-colons --list-keys | awk -F: '$1 == "fpr" && last == "pub" {print $10} {last = $1}')"
gpgconf --homedir "$tmp/g" --kill all >/dev/null 2>&1 || true
if [ "$check_only" = 1 ]; then
    echo "--check: everything is in order to sign $tag (pinned keys: $(echo "$pinned" | tr '\n' ' '))"
    exit 0
fi

: "${DAPS_SIGNING_KEYS:?set DAPS_SIGNING_KEYS to the fingerprint of the signing key (40 hex digits, ending in ! for that subkey)}"
signers=()
for k in $DAPS_SIGNING_KEYS; do
    [[ "$k" =~ ^[0-9A-Fa-f]{40}!?$ ]] || die "DAPS_SIGNING_KEYS takes full fingerprints, not a short id or a name: $k"
    signers+=(--local-user "$k")
done
want=${#signers[@]}; want=$((want / 2))
for f in "$name" "$name.sha256" "$name.zsync"; do
    gpg --batch --yes "${signers[@]}" --armor --detach-sign --output "$dir/$f.asc" "$dir/$f"
    status="$(gpgv --status-fd 1 --keyring "$tmp/release.gpg" "$dir/$f.asc" "$dir/$f" 2>/dev/null || true)"
    good="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" {print $NF}')"
    n="$(printf '%s\n' "$good" | grep -c . || true)"
    if [ "$n" != "$want" ] || printf '%s\n' "$status" | grep -qE ' (BADSIG|ERRSIG|REVKEYSIG|EXPKEYSIG) '; then
        rm -f "$dir/$f.asc"
        die "the signature of $f doesn't check against the tag's release keys ($n good of $want)"
    fi
    while read -r p; do
        printf '%s\n' "$pinned" | grep -qxF "$p" || { rm -f "$dir/$f.asc"; die "$f was signed by $p, which the app doesn't pin"; }
    done <<< "$good"
    echo "signed: $dir/$f.asc"
done
cat <<EOF

For the release notes (Verify):
  sha256sum -c $name.sha256
  gpg --verify $name.asc $name          (the key: $(echo "$pinned" | head -1))
  SHA-256 $sum
  Rebuild it from the tag and compare: packaging/verify-release.sh $tag
Attach: $name, $name.sha256, $name.zsync and the three .asc files.
EOF
