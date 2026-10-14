#!/bin/sh
# Installs DA Privacy Kit's administrator helper root-owned, with its own polkit action, so that
# what runs as root can't be changed by anything running as you. Run it with sudo from the
# source tree: sudo packaging/install-helper.sh   (and with --uninstall to remove it).
set -eu

DEST=/usr/libexec/daprivacyscanner
HELPER="$DEST/daprivacyscanner-helper"
POLICY=/usr/share/polkit-1/actions/au.com.digitalarchon.daprivacyscanner.policy
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root: sudo $0" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$HELPER" "$POLICY"
    rmdir "$DEST" 2>/dev/null || true
    echo "Removed. Changes the helper made are still recorded in /var/lib/daprivacyscanner/changes."
    exit 0
fi

install -d -m 0755 -o root -g root "$DEST"
# the stdlib-only helper, run by the system Python in isolated mode (no user site-packages)
{ echo '#!/usr/bin/python3 -I'; tail -n +1 "$HERE/../src/daprivacyscanner/helper.py"; } > "$HELPER.new"
chown root:root "$HELPER.new"
chmod 0755 "$HELPER.new"
mv -f "$HELPER.new" "$HELPER"
install -m 0644 -o root -g root "$HERE/au.com.digitalarchon.daprivacyscanner.policy" "$POLICY"
echo "Installed $HELPER and $POLICY."
