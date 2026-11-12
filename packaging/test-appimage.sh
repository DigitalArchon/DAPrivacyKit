#!/bin/bash
# Smoke-test the AppImage in clean containers of the distros DA Privacy Kit targets, under a
# virtual display (X, or Wayland for CachyOS, which is used with KDE Plasma on Wayland): with
# WebKitGTK missing (a terminal scan with no check failing; the app refusing to start without its
# window and saying why; then, with --browser, the app in the browser, scanning and exporting through its API), then with it installed (the app window, and a
# screenshot of the page after a scan in dist/test/<distro>.png).
#   packaging/test-appimage.sh [--mounted] [ubuntu debian fedora arch cachyos]   (default: all)
#   APPIMAGE=path picks the AppImage (default: the newest in dist/, dist/release/*/ or dist/dev/)
# By default the AppImage is extracted (--appimage-extract) and run from the folder. --mounted runs it as users do:
# the AppImage file itself, which its runtime mounts with FUSE (the container gets /dev/fuse and, in its own user
# namespace, the right to mount), and checks the path that only exists there: root can't read a FUSE mount, so the
# app copies helper.py into the runtime folder before pkexec runs it with the system's python3, which is then
# started as root from that copy and must answer as the helper of this version.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
how=extracted
if [ "${1:-}" = --mounted ]; then how=mounted; shift; fi
if [ -z "${APPIMAGE:-}" ]; then
    APPIMAGE="$(find dist -maxdepth 3 -name 'DAPrivacyKit-*-x86_64.AppImage' -printf '%T@ %p\n' 2>/dev/null \
                | sort -rn | head -1 | cut -d' ' -f2-)"
    [ -n "$APPIMAGE" ] || { echo "no AppImage in dist/: build one first (packaging/build-appimage.sh build)" >&2; exit 2; }
fi
APPIMAGE="$(realpath "$APPIMAGE")"
echo "testing $APPIMAGE ($how)"
mkdir -p dist/test

declare -A IMAGE BASE WEBKIT FUSE
IMAGE[ubuntu]=docker.io/library/ubuntu:24.04;     BASE[ubuntu]="apt-get update -qq && apt-get install -y -qq xvfb >/dev/null";  WEBKIT[ubuntu]="apt-get install -y -qq gir1.2-webkit2-4.1 >/dev/null"
IMAGE[debian]=docker.io/library/debian:trixie;    BASE[debian]="${BASE[ubuntu]}";                                              WEBKIT[debian]="${WEBKIT[ubuntu]}"
IMAGE[fedora]=registry.fedoraproject.org/fedora:latest; BASE[fedora]="dnf install -y -q xorg-x11-server-Xvfb >/dev/null";       WEBKIT[fedora]="dnf install -y -q webkit2gtk4.1 >/dev/null"
IMAGE[arch]=docker.io/library/archlinux:latest;   BASE[arch]="pacman -Syu --noconfirm -q xorg-server-xvfb >/dev/null";         WEBKIT[arch]="pacman -S --noconfirm -q webkit2gtk-4.1 >/dev/null"
IMAGE[cachyos]=docker.io/cachyos/cachyos:latest;  BASE[cachyos]="pacman -Syu --noconfirm -q weston ttf-dejavu >/dev/null"
# CachyOS's pacman won't run its install hooks in a container (sandbox vs network access): do what a
# real install's hooks do for GTK (image loaders, schemas, MIME database)
WEBKIT[cachyos]="${WEBKIT[arch]} 2>/dev/null; gdk-pixbuf-query-loaders --update-cache; glib-compile-schemas /usr/share/glib-2.0/schemas; update-mime-database /usr/share/mime"
# --mounted: fusermount3 for the runtime, and the system's python3 that runs the helper
FUSE[ubuntu]="apt-get install -y -qq fuse3 python3 >/dev/null"; FUSE[debian]="${FUSE[ubuntu]}"
FUSE[fedora]="dnf install -y -q fuse3 python3 >/dev/null"
FUSE[arch]="pacman -S --noconfirm -q fuse3 python >/dev/null"; FUSE[cachyos]="${FUSE[arch]}"
# how the display is provided: an X server, or a headless Wayland compositor (no X at all); started
# by the test user, and stopped when its run ends. Single quotes: these expand in the test user's script.
# shellcheck disable=SC2016
XSERVER='Xvfb :99 -screen 0 1600x1000x24 >/dev/null 2>&1 & trap "kill $!" EXIT; export DISPLAY=:99; sleep 1'
# shellcheck disable=SC2016
WAYLAND='mkdir -p -m 700 /tmp/xdg-$1 && export XDG_RUNTIME_DIR=/tmp/xdg-$1 && unset DISPLAY
  weston --backend=headless --socket=wayland-1 --width=1600 --height=1000 >/dev/null 2>&1 & trap "kill $!" EXIT
  export WAYLAND_DISPLAY=wayland-1 GDK_BACKEND=wayland; sleep 2'
declare -A SCREEN=([cachyos]="$WAYLAND")

if [ "$how" = mounted ]; then
    PODMAN_OPTS=(--device /dev/fuse --cap-add SYS_ADMIN)
    # the smoke user mounts it (its runtime, --appimage-mount) for the Python that runs smoke.py, which itself runs
    # the AppImage file each time, mounted again by its runtime
    # shellcheck disable=SC2016
    PREPARE='/app/DAPrivacyKit.AppImage --appimage-mount > /tmp/mount.txt 2>&1 & MOUNTER=$!
for _ in $(seq 50); do [ -s /tmp/mount.txt ] && break; sleep 0.2; done
A=$(head -1 /tmp/mount.txt); [ -d "$A" ] || { echo "FAIL the AppImage did not mount: $(cat /tmp/mount.txt)"; exit 1; }
echo "PASS mounted by its runtime at $A (mounter $MOUNTER)"
PROG=/app/DAPrivacyKit.AppImage'
else
    PODMAN_OPTS=()
    PREPARE='A=/tmp/squashfs-root PROG=/tmp/squashfs-root/AppRun'
fi
# --mounted: the helper's copy, made as the app makes it, then run by root as pkexec would run it
# shellcheck disable=SC2016
HELPER_COPY='APPDIR=$A $A/usr/python/bin/python3 -I -c "from daprivacyscanner import privileged; print(privileged.fallback_command()[-1])" > /tmp/helper-path.txt
P=$(cat /tmp/helper-path.txt)
case "$P" in "$XDG_RUNTIME_DIR"/daprivacyscanner/helper.py) echo "PASS the helper is copied out of the FUSE mount into the runtime folder";;
  *) echo "FAIL the helper copy is $P, not in $XDG_RUNTIME_DIR/daprivacyscanner"; exit 1;; esac
cmp -s "$P" "$A/usr/python/lib/python3.12/site-packages/daprivacyscanner/helper.py" && echo "PASS the copy is the mount'"'"'s helper.py" || { echo "FAIL the copy differs"; exit 1; }'

status=0
for d in "${@:-ubuntu debian fedora arch cachyos}"; do
  for name in $d; do
    echo "== $name (${IMAGE[$name]})"
    extra=""
    [ "$how" = mounted ] && extra="${FUSE[$name]}"
    # the app refuses to run as root, as it should: the smoke test runs as an ordinary user
    podman run --rm "${PODMAN_OPTS[@]}" -v "$APPIMAGE:/app/DAPrivacyKit.AppImage:ro,Z" \
        -v "$PWD/packaging/appimage/smoke.py:/app/smoke.py:ro,Z" -v "$PWD/dist/test:/out:Z" "${IMAGE[$name]}" bash -c "
      set -e
      ${BASE[$name]}
      $extra
      useradd -m smoke
      install -d -o smoke -m 700 /run/user/1000-smoke
      if [ $how = extracted ]; then
        cd /tmp && /app/DAPrivacyKit.AppImage --appimage-extract >/dev/null && chmod -R a+rX /tmp/squashfs-root
      fi
      mkdir -p /tmp/shots && chown smoke /tmp/shots
      cat > /tmp/smoke.sh <<'SH'
#!/bin/bash
set -e
export XDG_RUNTIME_DIR=/run/user/1000-smoke
$PREPARE
if [ \"\$1\" = helper ]; then
$HELPER_COPY
  exit 0
fi
${SCREEN[$name]:-$XSERVER}
BROWSER=echo \$A/usr/python/bin/python3 -I /app/smoke.py \$A /tmp/shots $name \$1 \$PROG
SH
      chmod 755 /tmp/smoke.sh
      if [ $how = mounted ]; then
        runuser -u smoke -- /tmp/smoke.sh helper
        # root runs the copy as pkexec would (pkexec itself needs a polkit agent): it must answer as this version's
        reply=\$(printf '%s\n' '{\"id\": 1, \"action\": \"hello\", \"args\": {}}' | /usr/bin/python3 -I /run/user/1000-smoke/daprivacyscanner/helper.py)
        case \"\$reply\" in *'\"uid\": 0'*) echo \"PASS root runs the copy with the system's python3: \$reply\";;
          *) echo \"FAIL the copy didn't answer as the helper: \$reply\"; exit 1;; esac
      fi
      runuser -u smoke -- /tmp/smoke.sh fallback
      ${WEBKIT[$name]}
      runuser -u smoke -- /tmp/smoke.sh full
      cp /tmp/shots/* /out/ 2>/dev/null || true
    " 2>&1 | grep -E '^(PASS|FAIL)|^  \| |Traceback|Error:' | grep -vE 'libEGL|MESA-EGL' || status=1
  done
done
exit $status
