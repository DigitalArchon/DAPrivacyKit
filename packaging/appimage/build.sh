#!/bin/bash
# Runs inside the build container (see Containerfile); started by packaging/build-appimage.sh.
#   build.sh build   /src.tar (git archive of the commit) -> /out/DAPrivacyKit-<version>-x86_64.AppImage, its
#                    .sha256 and its .zsync (from which an AppImage updater fetches only the blocks that changed)
#   build.sh lock    re-resolve the *.lock files into /out (review, then commit them)
# Inputs are pinned (pins.sh, *.lock with hashes) and every timestamp is SOURCE_DATE_EPOCH, so the
# same commit gives the same AppImage, byte for byte. VERSION names the file (a dev build's carries +dev.<commit>);
# COMMIT is the commit built (for the SBOM); UPDATE_INFO=0 leaves the update information out (dev builds).
set -euo pipefail
umask 022
export LC_ALL=C.UTF-8 TZ=UTC PYTHONHASHSEED=0 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
    PIP_CACHE_DIR=/cache/pip
: "${SOURCE_DATE_EPOCH:?}"

mode="${1:-build}"
W=/work
rm -rf "$W" && mkdir -p "$W/src" "$W/wheels" "$W/sdists" "$W/AppDir/usr"
tar -xf /src.tar -C "$W/src"
P="$W/src/packaging/appimage"
# shellcheck source=pins.sh
. "$P/pins.sh"

fetch() {  # url sha256 dest: download once into the cache, always verify
    local url=$1 sum=$2 dest=$3
    if [ ! -f "$dest" ] || ! echo "$sum  $dest" | sha256sum -c --quiet - 2>/dev/null; then
        curl -fsSL --retry 3 -o "$dest.part" "$url"
        echo "$sum  $dest.part" | sha256sum -c --quiet -
        mv "$dest.part" "$dest"
    fi
}
mkdir -p /cache
fetch "$PBS_URL" "$PBS_SHA256" /cache/python.tar.gz
fetch "$RUNTIME_URL" "$RUNTIME_SHA256" /cache/runtime-x86_64

# a Python for building (with the build tools) and a clean copy that becomes the AppImage's
mkdir -p "$W/buildpy"
tar -xzf /cache/python.tar.gz -C "$W/buildpy" --strip-components=1 --no-same-owner
tar -xzf /cache/python.tar.gz -C "$W/AppDir/usr" --no-same-owner        # -> usr/python
"$W/buildpy/bin/python3" -m venv "$W/venv"
V="$W/venv/bin"
export PATH="$V:$PATH"      # meson and ninja for the source builds

if [ "$mode" = lock ]; then
    # The resolver's own TLS trust while it reads PyPI: the container's CA store (the snapshot's
    # ca-certificates, which blacklists emSign ECC Root CA - G3 since 20260816ubuntu0.24.04.1),
    # never pip's vendored certifi, which pip reads beside the system store; pip 26.2.2 is the
    # first with the root gone from its own copy too. The build itself needs none of this: every
    # package it installs is checked against the lock's hashes.
    export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
    "$V/pip" install -q "pip==26.2.2" "pip-tools==7.6.1"
    cd "$P"
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --no-strip-extras --output-file /out/requirements.lock \
        "$W/src/pyproject.toml"
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --output-file /out/build-requirements.lock build-requirements.in
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --output-file /out/sdists.lock sdists.in
    sed -i "s#$W/src/#./#g; s#/out/#packaging/appimage/#g" /out/*.lock
    exit 0
fi

: "${VERSION:?}"
"$V/pip" install -q --require-hashes --no-deps -r "$P/build-requirements.lock"

# PyGObject and pycairo have no Linux wheels: build them from their pinned sources against the
# GLib 2.80 / girepository-2.0 headers. They load the host's GLib, GTK and WebKitGTK at run time.
# Locked runtime packages that publish no wheel at all, built the same way (pure Python).
SDIST_ONLY="proxy-tools"
fetch_sdists() {  # lock [names...]: fetch pinned source archives from PyPI, checked against the lock
    "$W/buildpy/bin/python3" - "$W/sdists" "$@" <<'PY'
import hashlib, json, re, sys, urllib.request
dest, lockfile, names = sys.argv[1], sys.argv[2], set(sys.argv[3:])
lock = open(lockfile).read()
for name, version, hashes in re.findall(r"^([\w.-]+)==([\w.]+)((?:\s*\\\s*--hash=sha256:\w+)+)", lock, re.M):
    if names and name not in names:
        continue
    meta = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json"))
    sdist = next(u for u in meta["urls"] if u["packagetype"] == "sdist")
    data = urllib.request.urlopen(sdist["url"]).read()
    if hashlib.sha256(data).hexdigest() not in re.findall(r"sha256:(\w+)", hashes):
        sys.exit(f"{sdist['filename']}: its hash isn't in {lockfile}")
    # saved under a normalised name, which the build steps below look for
    open(f"{dest}/{name.lower().replace('-', '_')}-{version}.tar.gz", "wb").write(data)
PY
}
fetch_sdists "$P/sdists.lock"
# shellcheck disable=SC2086
fetch_sdists "$P/requirements.lock" $SDIST_ONLY
# Source paths end up in compiled code (__FILE__ in assertion messages), so each source is unpacked
# into a fixed directory (pip would use a random one) and the build path is mapped out entirely.
export CFLAGS="-ffile-prefix-map=$W/=" CXXFLAGS="-ffile-prefix-map=$W/="
unpack() {  # name -> fixed source directory
    mkdir -p "$W/srcs/$1"
    tar -xzf "$W/sdists/$1"-*.tar.gz -C "$W/srcs/$1" --strip-components=1 --no-same-owner
    echo "$W/srcs/$1"
}
build_sdist() {  # name: fixed source and build directories, stripped
    "$V/pip" wheel -q --no-build-isolation --no-deps -w "$W/wheels" \
        -Cbuild-dir="$W/build-$1" -Cinstall-args=--strip "$(unpack "$1")"
}
build_sdist pycairo
"$V/pip" install -q --no-deps "$W/wheels"/pycairo-*.whl     # PyGObject builds its cairo support against it
build_sdist pygobject
for name in $SDIST_ONLY; do
    "$V/pip" wheel -q --no-build-isolation --no-deps -w "$W/wheels" "$(unpack "${name//-/_}")"
done
# the catalogue, the VPN provider data and the browser data live at the top of the source tree; the wheel carries
# copies inside the package
cp "$W/src/privacy-checks.yaml" "$W/src/src/daprivacyscanner/privacy-checks.yaml"
cp "$W/src/vpn-providers.yaml" "$W/src/src/daprivacyscanner/vpn-providers.yaml"
cp "$W/src/browsers.yaml" "$W/src/src/daprivacyscanner/browsers.yaml"
cp "$W/src/signing-keys.yaml" "$W/src/src/daprivacyscanner/signing-keys.yaml"
cp "$W/src/apps.yaml" "$W/src/src/daprivacyscanner/apps.yaml"
# when this copy was made, for the app's own "this copy is getting old" note (about.built): the commit's date, so
# the same commit gives the same file
printf '"""Written by the AppImage build: the date of the commit this copy was built from."""\n\nBUILT = "%s"\n' \
    "$(date -u -d "@$SOURCE_DATE_EPOCH" +%F)" > "$W/src/src/daprivacyscanner/_built.py"
"$V/pip" wheel -q --no-build-isolation --no-deps -w "$W/wheels" "$W/src"     # DA Privacy Kit itself
# the rest of the runtime lock: wheels only
"$W/buildpy/bin/python3" - "$P/requirements.lock" "$W/binary.lock" $SDIST_ONLY <<'PY'
import re, sys
text, skip = open(sys.argv[1]).read(), set(sys.argv[3:])
blocks = re.split(r"(?m)^(?=[\w.-]+==)", text)
open(sys.argv[2], "w").write("".join(b for b in blocks if b.split("==", 1)[0] not in skip))
PY

# the AppImage's Python: locked wheels only (downloaded and hash-checked first, so the SBOM can name the very files),
# then the ones built here
PY="$W/AppDir/usr/python/bin/python3"
"$PY" -m pip download -q --no-deps --require-hashes --only-binary :all: -d "$W/dl" -r "$W/binary.lock"
"$PY" -m pip install -q --no-compile --no-deps --no-index "$W/dl"/*.whl
"$PY" -m pip install -q --no-compile --no-deps "$W/wheels"/*.whl
"$PY" -m pip uninstall -q -y pip                  # nothing is installed at run time
# girepository-2.0 for hosts that don't have it (Debian/Ubuntu split it out of GLib); loaded only
# when missing (app._bundled_girepository), so Fedora and Arch use their own
install -D -m 644 "$(readlink -f /usr/lib/x86_64-linux-gnu/libgirepository-2.0.so.0)" \
    "$W/AppDir/usr/lib/girepository-fallback/libgirepository-2.0.so.0"
# the base typelibs GTK's refer to (xlib, cairo, freetype, ...): Arch ships them separately
# (gobject-introspection-runtime), and WebKitGTK doesn't pull them in. One directory each, so only
# the ones a host lacks are added to its search path.
for t in $(dpkg -L gir1.2-freedesktop | grep '\.typelib$'); do
    install -D -m 644 "$t" "$W/AppDir/usr/lib/girepository-fallback/typelibs/$(basename "$t" .typelib)/$(basename "$t")"
done

# Licences, in usr/share/licenses/daprivacyscanner: DA Privacy Kit's; the bundled Python's and the runtime's, with
# those of the libraries built into each, from packaging/appimage/licenses (its SOURCES says where each came from);
# pycairo's, from its sdist, since the wheel built from it carries none; and the copyright file of each Ubuntu package
# a fallback came from, with where their source is (the LGPL asks that whoever gets the binary can get it). Every
# other Python package carries its licence in its dist-info, checked below.
D="$W/AppDir/usr/share/licenses/daprivacyscanner"
install -D -m 644 "$W/src/LICENSE" "$D/LICENSE"
cp -r "$P/licenses/." "$D/"
install -D -m 644 -t "$D/pycairo" "$W/srcs/pycairo/COPYING" "$W/srcs/pycairo/COPYING-LGPL-2.1" \
    "$W/srcs/pycairo/COPYING-MPL-1.1"
F="$W/AppDir/usr/lib/girepository-fallback"
packages="$(find "$F" -type f -printf '%f\n' | sort | while read -r f; do
                dpkg -S "*/$f" | cut -d: -f1 | tr "," " "; done | tr ' ' '\n' | sed '/^$/d' | sort -u)"
mkdir -p "$D/fallbacks"
for pkg in $packages; do
    install -m 644 "/usr/share/doc/$pkg/copyright" "$D/fallbacks/$pkg.copyright"
done
# shellcheck disable=SC2086
dpkg-query -W -f='${Package}\t${Version}\t${source:Package} ${source:Version}\n' $packages | sort > "$W/debs.txt"
{
    printf '%s\n' \
        "The fallback library and typelibs in usr/lib/girepository-fallback are these packages of Ubuntu 24.04, as" \
        "the Ubuntu archive had them at $APT_SNAPSHOT. Their source is in the same snapshot of the archive:" \
        "" \
        "  https://snapshot.ubuntu.com/ubuntu/$APT_SNAPSHOT/" \
        "  suites noble, noble-updates and noble-security; components main and universe" \
        "" \
        "On a system with apt, a file in /etc/apt/sources.list.d ending .sources holding" \
        "" \
        "  Types: deb-src" \
        "  URIs: https://snapshot.ubuntu.com/ubuntu/$APT_SNAPSHOT/" \
        "  Suites: noble noble-updates noble-security" \
        "  Components: main universe" \
        "  Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" \
        "" \
        "then apt-get update, and apt-get source <source package>=<version> fetches one." \
        "Each package's copyright file is beside this one, as <package>.copyright." \
        ""
    printf '%-34s %-26s %s\n' "package" "version" "source package and version"
    while IFS=$'\t' read -r name version source; do
        printf '%-34s %-26s %s\n' "$name" "$version" "$source"
    done < "$W/debs.txt"
} > "$D/fallbacks/SOURCES"
"$PY" - "$D" "$W"/AppDir/usr/python/lib/python3.*/site-packages <<'PY'
import pathlib, re, sys

licenses, folder = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
bare = []
for info in sorted(folder.glob("*.dist-info")):
    name = re.sub(r"[-_.]+", "-", info.name[:-len(".dist-info")].rpartition("-")[0]).lower()
    carried = [p for p in info.rglob("*") if p.is_file() and re.match(r"(LICEN[CS]E|COPYING|NOTICE)", p.name, re.I)]
    if not carried and not (licenses / name).is_dir():
        bare.append(info.name)
if bare:
    sys.exit("No licence in the image for " + ", ".join(bare) + ": add it to packaging/appimage/licenses, and say "
             "in its SOURCES where it came from")
PY
# what is in it, from the pins and the locks, each with the hash of the file used (packaging/appimage/sbom.py)
PBS_URL="$PBS_URL" PBS_SHA256="$PBS_SHA256" RUNTIME_URL="$RUNTIME_URL" RUNTIME_SHA256="$RUNTIME_SHA256" \
APT_SNAPSHOT="$APT_SNAPSHOT" BASE_IMAGE="$BASE_IMAGE" "$W/buildpy/bin/python3" -I "$P/sbom.py" "$D/sbom.cdx.json" \
    "$VERSION" "${COMMIT:-unknown}" "$W"/AppDir/usr/python/lib/python3.*/site-packages "$W/dl" "$W/sdists" "$W/debs.txt"

find "$W/AppDir" -name direct_url.json -delete    # build paths
find "$W/AppDir" -name __pycache__ -type d -prune -exec rm -rf {} +
# bytecode keyed to the source's hash, not its timestamp: reproducible, and valid on a read-only mount
"$PY" -m compileall -q -j1 --invalidation-mode unchecked-hash "$W/AppDir/usr/python/lib" >/dev/null

# AppDir layout (AppImage spec): entry point, desktop entry, icon, AppStream metadata
install -m 755 "$P/AppRun" "$W/AppDir/AppRun"
install -m 644 "$P/daprivacyscanner.desktop" "$P/daprivacyscanner.png" "$W/AppDir/"
ln -s daprivacyscanner.png "$W/AppDir/.DirIcon"
install -D -m 644 "$P/au.com.digitalarchon.daprivacyscanner.appdata.xml" \
    "$W/AppDir/usr/share/metainfo/au.com.digitalarchon.daprivacyscanner.appdata.xml"
# the version where AppImage managers look: the desktop entry (X-AppImage-Version) and AppStream
sed -i "s/@VERSION@/$VERSION/; s/@DATE@/$(date -u -d "@$SOURCE_DATE_EPOCH" +%F)/" \
    "$W/AppDir/daprivacyscanner.desktop" "$W/AppDir/usr/share/metainfo/au.com.digitalarchon.daprivacyscanner.appdata.xml"
grep -qx "X-AppImage-Version=$VERSION" "$W/AppDir/daprivacyscanner.desktop"
grep -q "<release version=\"$VERSION\"" "$W/AppDir/usr/share/metainfo/au.com.digitalarchon.daprivacyscanner.appdata.xml"
# also where the AppStream launchable (desktop-id daprivacyscanner.desktop) is looked up
install -d "$W/AppDir/usr/share/applications"
ln -s ../../../daprivacyscanner.desktop "$W/AppDir/usr/share/applications/daprivacyscanner.desktop"
desktop-file-validate "$W/AppDir/daprivacyscanner.desktop"

chmod -R u+rwX,go+rX,go-w "$W/AppDir"
find "$W/AppDir" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
# (mksquashfs takes every timestamp from SOURCE_DATE_EPOCH by itself)
mksquashfs "$W/AppDir" "$W/app.squashfs" -quiet -noappend -root-owned -no-xattrs \
    -comp zstd -Xcompression-level 19 -b 1M

NAME="DAPrivacyKit-$VERSION-x86_64.AppImage"
# Update information, in the runtime's .upd_info section, where AppImageUpdate, Gear Lever and AppImageLauncher read
# it: the latest GitHub release's .zsync, made below, from which an updater fetches only the blocks that changed and
# checks the result against the SHA-1 the .zsync carries. Reading it is theirs to do, when the user asks; the app
# itself never looks for updates. Left out of a dev build, which no release replaces.
cp /cache/runtime-x86_64 "$W/runtime"
if [ "${UPDATE_INFO:-1}" = 1 ]; then
    "$W/buildpy/bin/python3" - "$W/runtime" \
        "gh-releases-zsync|DigitalArchon|DAPrivacyKit|latest|DAPrivacyKit-*-x86_64.AppImage.zsync" <<'PY'
import re, subprocess, sys
path, info = sys.argv[1], sys.argv[2].encode()
sections = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True, check=True).stdout
found = re.search(r"\.upd_info\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)", sections)
if not found:
    sys.exit("the runtime has no .upd_info section")
offset, size = int(found.group(1), 16), int(found.group(2), 16)
if len(info) >= size:
    sys.exit("update information too long for .upd_info")
with open(path, "r+b") as runtime:
    runtime.seek(offset)
    if runtime.read(size).strip(b"\0"):
        sys.exit("the runtime's .upd_info isn't empty")
    runtime.seek(offset)
    runtime.write(info + b"\0" * (size - len(info)))
PY
fi
cat "$W/runtime" "$W/app.squashfs" > "/out/$NAME"
chmod 755 "/out/$NAME"
# zsyncmake writes the file's modification time into the .zsync (MTime): the commit's, like everything else. The URL
# is the file's name, relative to where the .zsync is (the release page), so nothing of this machine goes in.
touch -d "@$SOURCE_DATE_EPOCH" "/out/$NAME"
(cd /out && rm -f "$NAME.zsync" && zsyncmake -u "$NAME" -o "$NAME.zsync" "$NAME" >/dev/null)
(cd /out && sha256sum "$NAME" > "$NAME.sha256" && cat "$NAME.sha256")
