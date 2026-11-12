#!/bin/bash
# Build DA Privacy Kit's AppImage reproducibly with rootless Podman (see packaging/README.md).
#   packaging/build-appimage.sh build         AppImage of HEAD -> dist/ (+ .sha256, .zsync)
#   packaging/build-appimage.sh check         build HEAD twice from scratch and compare the hashes
#   packaging/build-appimage.sh release REF   a release: REF (its signed tag, v<version>) built from its own commit,
#                                             twice, compared -> dist/release/REF/ with BUILD-INFO; what
#                                             packaging/second-build.sh and packaging/sign-release.sh work from.
#                                             REF may be any commit, to try it: such a build can't be signed
#   packaging/build-appimage.sh dev           AppImage of the working tree (tracked and new, unignored files) ->
#                                             dist/dev/DAPrivacyKit-<version>+dev.<commit>[.dirty]-x86_64.AppImage,
#                                             for trying changes before committing them: never a release's name,
#                                             never in dist/ beside one, and no update information
#   packaging/build-appimage.sh lock          re-resolve packaging/appimage/*.lock (review, then commit)
# FRESH=1: the builder image is made again from nothing and every download fetched again (what a second machine
# does; packaging/second-build.sh sets it). DIST=dir puts build and check results somewhere other than dist/.
# Only committed files are built (the commit's tree, as git stores it), except by dev and lock; SOURCE_DATE_EPOCH
# is the commit's time. The builder image is made from the Containerfile and pins.sh of what is built.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"         # verify-tag.sh is beside it
cd "$(git rev-parse --show-toplevel)"
mode="${1:-build}"
ref="${2:-HEAD}"
case "$mode" in
    build|check|dev|lock) [ $# -le 1 ] || { echo "usage: $0 build|check|dev|lock|release REF" >&2; exit 2; } ;;
    release) [ $# -eq 2 ] || { echo "usage: $0 release REF (a tag, v<version>)" >&2; exit 2; } ;;
    *) echo "usage: $0 build|check|dev|lock|release REF" >&2; exit 2 ;;
esac

command -v podman >/dev/null || { echo "Podman is needed: sudo apt install podman (or dnf/pacman)" >&2; exit 1; }
commit="$(git rev-parse --verify --quiet "$ref^{commit}")" || { echo "There is no commit '$ref' here." >&2; exit 2; }
if [ "$mode" = build ] || [ "$mode" = check ]; then
    [ -z "$(git status --porcelain --untracked-files=no)" ] \
        || echo "Note: uncommitted changes are not built; this builds HEAD ($(git rev-parse --short HEAD))." >&2
fi
if [ "$mode" = release ]; then
    if git rev-parse -q --verify "refs/tags/$ref" >/dev/null; then
        # a release's tag must be signed by a release key the app pins (docs/release-key.asc of this checkout)
        "$HERE/verify-tag.sh" "$ref" || { echo "Not building $ref: its tag isn't signed by a pinned release key." >&2
                                          exit 1; }
        kind="tag"
    else
        echo "Note: $ref is not a tag: built to try the release steps, it can't be signed." >&2
        kind="commit"
    fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/context"
# The source: the commit's tree as git stores it, whatever this machine's git settings (line endings, the archive's
# umask), so a second machine gets the same bytes; dev and lock take the working tree.
if [ "$mode" = dev ] || [ "$mode" = lock ]; then     # a lock is made before it is committed
    git ls-files -z --cached --others --exclude-standard | tar --null -T - --format=gnu -cf "$WORK/src.tar"
    cp packaging/appimage/Containerfile packaging/appimage/pins.sh "$WORK/context/"
else
    git -c core.autocrlf=false -c core.eol=lf -c tar.umask=0022 archive --format=tar "$commit" > "$WORK/src.tar"
    git show "$commit:packaging/appimage/Containerfile" > "$WORK/context/Containerfile"
    git show "$commit:packaging/appimage/pins.sh" > "$WORK/context/pins.sh"
fi
# shellcheck source=packaging/appimage/pins.sh
. "$WORK/context/pins.sh"
EPOCH="$(git log -1 --format=%ct "$commit")"
# the version of what is built, from its own pyproject.toml (from the working tree, an uncommitted version bump named
# the AppImage, its desktop entry and its AppStream release after a version the package inside wasn't)
VERSION="$(tar -xOf "$WORK/src.tar" pyproject.toml \
    | python3 -c 'import sys, tomllib; print(tomllib.load(sys.stdin.buffer)["project"]["version"])')"
update_info=1
if [ "$mode" = dev ]; then
    VERSION="$VERSION+dev.$(git rev-parse --short=12 HEAD)"
    [ -z "$(git status --porcelain)" ] || VERSION="$VERSION.dirty"
    update_info=0
fi
if [ "$mode" = release ] && [ "$kind" = tag ] && [ "$ref" != "v$VERSION" ]; then
    echo "The tag $ref names a commit whose version is $VERSION: a release's tag is v<version>." >&2; exit 1
fi

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/daprivacyscanner-appimage"
# which builder image this script made, by its ID: kept outside the cache, which the build container can write to
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/daprivacyscanner-appimage"
mkdir -p "$CACHE" "$STATE"
TAG="daprivacyscanner-appimage-builder:$(cat "$WORK/context/Containerfile" "$WORK/context/pins.sh" | sha256sum | cut -c1-12)"
RECORD="$STATE/${TAG#*:}.id"
if [ "${FRESH:-0}" = 1 ]; then
    echo "FRESH=1: the builder image is made again from nothing, and every download fetched again." >&2
    podman image rm -f "$TAG" >/dev/null 2>&1 || true
    rm -f "$RECORD"
    rm -rf "$CACHE" && mkdir -p "$CACHE"
fi
have="$(podman image inspect --format '{{.Id}}' "$TAG" 2>/dev/null || true)"
if [ -n "$have" ] && [ "$have" != "$(cat "$RECORD" 2>/dev/null)" ]; then
    # an image with the expected name that this script didn't make (or made before it kept records): never trusted
    echo "The local image $TAG isn't the one this script made: making it again, from nothing." >&2
    podman image rm -f "$TAG" >/dev/null
    have=""
fi
if [ -z "$have" ]; then
    # The host's CA bundle, for apt in the builder to reach the snapshot over https: the first of these this machine
    # has. It goes in as a copy in the build context, never a mount: on an SELinux host a mount needs :Z, which
    # rootless Podman can't apply to a file root owns (and rootful Podman would relabel the system's bundle).
    ca=""
    for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem \
             /etc/pki/tls/cert.pem /etc/ssl/cert.pem; do
        [ -f "$c" ] && { ca="$c"; break; }
    done
    [ -n "$ca" ] || { echo "No CA bundle on this machine: install the distribution's ca-certificates." >&2; exit 1; }
    install -m 0644 "$ca" "$WORK/context/hostca.crt"        # readable by apt's own user, whatever the umask
    # The packages apt fetched are kept in the cache between attempts: snapshot.ubuntu.com answers 503 when busy,
    # and a retry goes on from where the last one stopped. apt checks each against the snapshot's signed lists, so
    # a kept one is as good as a fresh one; FRESH=1 empties the cache first.
    mkdir -p "$CACHE/apt"
    podman build --no-cache --pull=missing -t "$TAG" -v "$CACHE/apt:/var/cache/apt/archives:Z" \
        --build-arg BASE_IMAGE="$BASE_IMAGE" --build-arg APT_SNAPSHOT="$APT_SNAPSHOT" \
        -f "$WORK/context/Containerfile" "$WORK/context"
    podman image inspect --format '{{.Id}}' "$TAG" > "$RECORD"
fi

run() {  # out-dir mode
    mkdir -p "$1"
    podman run --rm -v "$WORK/src.tar:/src.tar:ro,Z" -v "$CACHE:/cache:Z" -v "$1:/out:Z" \
        -e SOURCE_DATE_EPOCH="$EPOCH" -e VERSION="$VERSION" -e COMMIT="$commit" -e UPDATE_INFO="$update_info" "$TAG" \
        bash -c 'tar -xOf /src.tar packaging/appimage/build.sh > /tmp/build.sh && bash /tmp/build.sh "$0"' "$2"
}

twice() {  # dest: build twice from scratch and compare the AppImage and its .zsync; the result in dest
    run "$WORK/a" build
    rm -rf "$CACHE/pip"          # the second build downloads its wheels again
    run "$WORK/b" build
    local a b
    a=$(cut -d' ' -f1 "$WORK"/a/*.sha256); b=$(cut -d' ' -f1 "$WORK"/b/*.sha256)
    if [ "$a" = "$b" ] && cmp -s "$WORK"/a/*.zsync "$WORK"/b/*.zsync; then
        mkdir -p "$1" && cp "$WORK"/a/* "$1"/
        echo "Reproducible: both builds are $a"
    else
        echo "NOT reproducible: $a vs $b (compare with diffoscope; copies in $1/check-a, $1/check-b)" >&2
        mkdir -p "$1" && rm -rf "$1/check-a" "$1/check-b" && cp -r "$WORK/a" "$1/check-a" && cp -r "$WORK/b" "$1/check-b"
        exit 1
    fi
}

DIST="${DIST:-dist}"
case "$mode" in
    build)
        run "$(mkdir -p "$DIST" && cd "$DIST" && pwd)" build ;;
    check)
        twice "$(mkdir -p "$DIST" && cd "$DIST" && pwd)" ;;
    dev)
        run "$PWD/dist/dev" build
        echo "A dev build, not a release: dist/dev/DAPrivacyKit-$VERSION-x86_64.AppImage" ;;
    release)
        out="$PWD/dist/release/$ref"
        rm -rf "$out"
        twice "$out"
        name="DAPrivacyKit-$VERSION-x86_64.AppImage"
        {
            echo "# packaging/build-appimage.sh release: what was built, and from what"
            echo "ref=$ref"
            echo "kind=$kind"
            echo "commit=$commit"
            echo "version=$VERSION"
            echo "source_date_epoch=$EPOCH"
            echo "builder=$TAG $(cat "$RECORD")"
            echo "appimage=$name"
            echo "appimage_sha256=$(sha256sum "$out/$name" | cut -d' ' -f1)"
            echo "zsync_sha256=$(sha256sum "$out/$name.zsync" | cut -d' ' -f1)"
            echo "reproduced=twice here"
        } > "$out/BUILD-INFO"
        echo "Built $ref ($commit) into dist/release/$ref. Next: packaging/second-build.sh $ref HOST (another" \
             "machine builds it too), then packaging/sign-release.sh $ref." ;;
    lock)
        run "$WORK/lock" lock
        cp "$WORK"/lock/*.lock packaging/appimage/
        git --no-pager diff --stat -- packaging/appimage/*.lock ;;
esac
