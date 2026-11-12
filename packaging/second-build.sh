#!/bin/bash
# The second build a release needs before it is signed: another machine builds the same commit from a clean copy of
# it, with a builder image and downloads of its own, and its AppImage and .zsync must be this machine's, byte for byte.
#   packaging/second-build.sh REF HOST                  over ssh: HOST needs git and rootless Podman
#   packaging/second-build.sh REF --record SHA256 ZSYNC_SHA256 "where it was built"
#                                                       a build made elsewhere by hand: on that machine, in a clone
#                                                       with the tag, `packaging/verify-release.sh REF` builds it
#                                                       (and prints both checksums) without fetching anything else
# REF is what `packaging/build-appimage.sh release REF` built into dist/release/REF/ (a tag, or a commit to try the
# steps). The result is dist/release/REF/second-build.txt, which packaging/sign-release.sh requires; nothing is
# written when the hashes differ (exit status 1). Over ssh, only the commit's own objects are copied (a git bundle of
# that one ref, history included), cloned into ~/daprivacyscanner-second-build on HOST, built there with FRESH=1 (the
# builder image made again from nothing, every download fetched again and checked against the pins), and the clone
# removed after; HOST's builder image and download cache stay for the next time. FRESH=0 reuses the builder image
# HOST made itself last time (a retry after a failed build: it is still that machine's own, never this one's).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
[ $# -ge 2 ] || { echo "usage: $0 REF HOST | $0 REF --record SHA256 ZSYNC_SHA256 DESCRIPTION" >&2; exit 2; }
ref="$1"; shift
dir="dist/release/$ref"
info() { sed -n "s/^$2=//p" "$1" | tail -1; }
commit="$(git rev-parse --verify --quiet "$ref^{commit}")" || { echo "There is no commit '$ref' here." >&2; exit 2; }
version="$(git show "$commit:pyproject.toml" | python3 -c 'import sys, tomllib; print(tomllib.load(sys.stdin.buffer)["project"]["version"])')"
name="DAPrivacyKit-$version-x86_64.AppImage"
# this machine's build (packaging/build-appimage.sh release REF) is compared with at the end: it may still be
# running here while the other machine builds
if [ "$1" = --record ]; then
    [ $# -eq 4 ] || { echo "usage: $0 REF --record SHA256 ZSYNC_SHA256 DESCRIPTION" >&2; exit 2; }
    got="${2,,}" got_z="${3,,}" where="$4"
else
    host="$1"
    command -v ssh >/dev/null || { echo "ssh is needed" >&2; exit 2; }
    WORK="$(mktemp -d)"
    trap 'git update-ref -d refs/daprivacyscanner/second-build 2>/dev/null || true; rm -rf "$WORK"' EXIT
    git update-ref refs/daprivacyscanner/second-build "$commit"       # a bundle carries refs: this one, for a moment
    git bundle create -q "$WORK/src.bundle" refs/daprivacyscanner/second-build
    # shellcheck disable=SC2088  # expanded on HOST, in the commands below
    remote='~/daprivacyscanner-second-build'
    # shellcheck disable=SC2029  # $remote and $commit are meant to expand here, $HOME on the other side
    ssh "$host" "command -v git >/dev/null && command -v podman >/dev/null || { echo 'git and podman are needed on $host' >&2; exit 2; }
                 rm -rf $remote && mkdir -p $remote"
    scp -q "$WORK/src.bundle" "$host:daprivacyscanner-second-build/src.bundle"
    echo "Building $ref ($commit) on $host: a fresh builder image and every download again, so a while."
    # shellcheck disable=SC2029
    ssh "$host" "set -e; cd $remote && git init -q src && cd src
                 git fetch -q ../src.bundle refs/daprivacyscanner/second-build && git checkout -q --detach $commit
                 FRESH=${FRESH:-1} DIST=\$HOME/daprivacyscanner-second-build/out packaging/build-appimage.sh build" \
        > "$WORK/remote.log" 2>&1 || { tail -30 "$WORK/remote.log" >&2; echo "The build on $host failed." >&2; exit 2; }
    # shellcheck disable=SC2029
    got="$(ssh "$host" "sha256sum $remote/out/$name | cut -d' ' -f1")"
    # shellcheck disable=SC2029
    got_z="$(ssh "$host" "sha256sum $remote/out/$name.zsync | cut -d' ' -f1")"
    where="$host ($(ssh "$host" '. /etc/os-release; printf "%s, %s, " "$PRETTY_NAME" "$(uname -r)"; podman --version'))"
    # shellcheck disable=SC2029
    ssh "$host" "rm -rf $remote"
fi
[[ "$got" =~ ^[0-9a-f]{64}$ ]] && [[ "$got_z" =~ ^[0-9a-f]{64}$ ]] || { echo "Not a SHA-256: $got / $got_z" >&2; exit 2; }
if [ ! -f "$dir/BUILD-INFO" ]; then
    echo "The second build ($where): $got, .zsync $got_z. No build here to compare with yet:" \
         "packaging/build-appimage.sh release $ref, then $0 $ref --record $got $got_z \"$where\"" >&2
    exit 2
fi
[ "$(info "$dir/BUILD-INFO" commit)" = "$commit" ] || { echo "$dir was built from another commit." >&2; exit 2; }
want="$(info "$dir/BUILD-INFO" appimage_sha256)"
want_z="$(info "$dir/BUILD-INFO" zsync_sha256)"
echo "Here:          $want  $name"
echo "Second build:  $got  ($where)"
echo "  .zsync here $want_z, there $got_z"
if [ "$got" != "$want" ] || [ "$got_z" != "$want_z" ]; then
    echo "DIFFERENT: the second machine's build isn't this one. Nothing recorded; don't sign. Compare the two" \
         "AppImages with diffoscope." >&2
    exit 1
fi
{
    echo "# packaging/second-build.sh: the same commit built on another machine"
    echo "ref=$ref"
    echo "commit=$commit"
    echo "host=$where"
    echo "date=$(date -u +%F)"
    echo "appimage=$name"
    echo "appimage_sha256=$got"
    echo "zsync_sha256=$got_z"
} > "$dir/second-build.txt"
echo "The same: recorded in $dir/second-build.txt."
