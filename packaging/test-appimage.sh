#!/bin/bash
# Smoke-test the AppImage in clean containers of the distros DA Privacy Kit targets, under a
# virtual display (X, or Wayland for CachyOS, which is used with KDE Plasma on Wayland): with
# WebKitGTK missing (a terminal scan with no check failing; the app refusing to start without its
# window and saying why; then, with --browser, the app in the browser, scanning and exporting through its API), then with it installed (the app window, and a
# screenshot of the page after a scan in dist/test/<distro>.png).
#   packaging/test-appimage.sh [ubuntu debian fedora arch cachyos]   (default: all)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
APPIMAGE="$(realpath "${APPIMAGE:-$(ls -t dist/DAPrivacyKit-*-x86_64.AppImage | head -1)}")"   # or APPIMAGE=path
mkdir -p dist/test

declare -A IMAGE BASE WEBKIT
IMAGE[ubuntu]=docker.io/library/ubuntu:24.04;     BASE[ubuntu]="apt-get update -qq && apt-get install -y -qq xvfb >/dev/null";  WEBKIT[ubuntu]="apt-get install -y -qq gir1.2-webkit2-4.1 >/dev/null"
IMAGE[debian]=docker.io/library/debian:trixie;    BASE[debian]="${BASE[ubuntu]}";                                              WEBKIT[debian]="${WEBKIT[ubuntu]}"
IMAGE[fedora]=registry.fedoraproject.org/fedora:latest; BASE[fedora]="dnf install -y -q xorg-x11-server-Xvfb >/dev/null";       WEBKIT[fedora]="dnf install -y -q webkit2gtk4.1 >/dev/null"
IMAGE[arch]=docker.io/library/archlinux:latest;   BASE[arch]="pacman -Syu --noconfirm -q xorg-server-xvfb >/dev/null";         WEBKIT[arch]="pacman -S --noconfirm -q webkit2gtk-4.1 >/dev/null"
IMAGE[cachyos]=docker.io/cachyos/cachyos:latest;  BASE[cachyos]="pacman -Syu --noconfirm -q weston ttf-dejavu >/dev/null"
# CachyOS's pacman won't run its install hooks in a container (sandbox vs network access): do what a
# real install's hooks do for GTK (image loaders, schemas, MIME database)
WEBKIT[cachyos]="${WEBKIT[arch]} 2>/dev/null; gdk-pixbuf-query-loaders --update-cache; glib-compile-schemas /usr/share/glib-2.0/schemas; update-mime-database /usr/share/mime"
# how the display is provided: an X server, or a headless Wayland compositor (no X at all); started
# by the test user, and stopped when its run ends
XSERVER='Xvfb :99 -screen 0 1600x1000x24 >/dev/null 2>&1 & trap "kill $!" EXIT; export DISPLAY=:99; sleep 1'
WAYLAND='mkdir -p -m 700 /tmp/xdg-$1 && export XDG_RUNTIME_DIR=/tmp/xdg-$1 && unset DISPLAY
  weston --backend=headless --socket=wayland-1 --width=1600 --height=1000 >/dev/null 2>&1 & trap "kill $!" EXIT
  export WAYLAND_DISPLAY=wayland-1 GDK_BACKEND=wayland; sleep 2'
declare -A SCREEN=([cachyos]="$WAYLAND")

status=0
for d in "${@:-ubuntu debian fedora arch cachyos}"; do
  for name in $d; do
    echo "== $name (${IMAGE[$name]})"
    # the app refuses to run as root, as it should: the smoke test runs as an ordinary user
    podman run --rm -v "$APPIMAGE:/app/DAPrivacyKit.AppImage:ro,Z" -v "$PWD/packaging/appimage/smoke.py:/app/smoke.py:ro,Z" \
        -v "$PWD/dist/test:/out:Z" "${IMAGE[$name]}" bash -c "
      set -e
      ${BASE[$name]}
      useradd -m smoke
      cd /tmp && /app/DAPrivacyKit.AppImage --appimage-extract >/dev/null && chmod -R a+rX /tmp/squashfs-root
      mkdir -p /tmp/shots && chown smoke /tmp/shots
      cat > /tmp/smoke.sh <<'SH'
#!/bin/bash
set -e
${SCREEN[$name]:-$XSERVER}
A=/tmp/squashfs-root
BROWSER=echo \$A/usr/python/bin/python3 -I /app/smoke.py \$A /tmp/shots $name \$1
SH
      chmod 755 /tmp/smoke.sh
      runuser -u smoke -- /tmp/smoke.sh fallback
      ${WEBKIT[$name]}
      runuser -u smoke -- /tmp/smoke.sh full
      cp /tmp/shots/* /out/ 2>/dev/null || true
    " 2>&1 | grep -E '^(PASS|FAIL)|^  \| |Traceback|Error:' | grep -vE 'libEGL|MESA-EGL' || status=1
  done
done
exit $status
