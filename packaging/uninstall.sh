#!/bin/bash
# Remove DA Privacy Kit from this account: what is the app's own, and what would be left calling an app that
# is gone. It needs nothing from the app, so it works after the AppImage has been deleted.
#   packaging/uninstall.sh              show each part, and ask before removing it
#   packaging/uninstall.sh --dry-run    only show what it would remove
#   packaging/uninstall.sh --yes        don't ask
#   packaging/uninstall.sh --keep-data  keep History, the accepted findings and the settings (for a later reinstall)
#   packaging/uninstall.sh --no-root    leave the administrator helper (no password asked)
#
# Removed: scheduled scans, the Outbox's watcher, the file manager's right-click entries and the menu entries of
# Boxes (they run the app), the app's data and settings, and, as administrator, the helper and its record of root
# changes.
# Never removed: the fixes you applied. Settings the app changed, and files it wrote for them in /etc, protect
# this computer without the app, and stay. To undo one, revert it in the app's History BEFORE running this:
# afterwards it can only be undone by hand. Your own files (~/Outbox and what is in it, ~/Ephemeral, ~/Boxes with
# the data of the apps kept in them) stay too.
set -u

ask=1; dry=0; keep=0; noroot=0
for a in "$@"; do
    case "$a" in
        --dry-run) dry=1 ;;
        --yes) ask=0 ;;
        --keep-data) keep=1 ;;
        --no-root) noroot=1 ;;
        *) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done
[ "$(id -u)" -ne 0 ] || { echo "Run this as yourself, not as root: it asks for administrator access where it needs it." >&2; exit 2; }

CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}"
UNITS="$CONFIG/systemd/user"
MARK="Written by DA Privacy Kit."
HELPER_DIR=/usr/libexec/daprivacyscanner
POLICY=/usr/share/polkit-1/actions/au.com.digitalarchon.daprivacyscanner.policy
JOURNAL=/var/lib/daprivacyscanner

say() { printf '%s\n' "$*"; }
confirm() {  # question: yes when --yes, never when --dry-run
    [ "$dry" -eq 0 ] || return 1
    [ "$ask" -eq 1 ] || return 0
    printf '%s [y/N] ' "$1"
    read -r answer || return 1
    [ "$answer" = y ] || [ "$answer" = Y ]
}
remove() { for f in "$@"; do [ -e "$f" ] || [ -L "$f" ] || continue; rm -rf -- "$f" && say "  removed $f"; done; }
user_unit_off() { systemctl --user disable --now "$1" >/dev/null 2>&1 || true; }

# ------------------------------------------------------------------ things to deal with in the app first
stop=0
if [ -e "$STATE/daprivacyscanner/presentation.json" ]; then
    say "Presentation mode is on: notification banners and clipboard history are off, and only the app knows what to"
    say "put back. Start the app and turn it off first."
    stop=1
fi
for d in "$HOME/RAMDisk" "$HOME/TempBrowser"; do
    if mountpoint -q "$d" 2>/dev/null; then
        say "$d is open: close it in the app first (Tools), or restart the computer, which ends it."
        stop=1
    fi
done
[ "$stop" -eq 0 ] || exit 1

applied=0
if [ -f "$STATE/daprivacyscanner/undo.json" ] && command -v python3 >/dev/null; then
    applied="$(python3 -I -c '
import json, sys
try:
    entries = json.load(open(sys.argv[1])).get("entries", [])
except (OSError, ValueError, AttributeError):
    entries = []
print(sum(1 for e in entries if isinstance(e, dict) and e.get("state") not in ("reverted", "failed")))
' "$STATE/daprivacyscanner/undo.json" 2>/dev/null || echo 0)"
fi
if [ "$applied" -gt 0 ] && [ "$keep" -eq 0 ]; then
    say "$applied change(s) you applied with the app are still in place. They keep working without it, and stay."
    say "This removes History, though: afterwards they can only be undone by hand. To undo any of them, cancel now"
    say "and revert them in the app's History; \"Export everything\" there writes down how to undo each by hand."
    if [ "$dry" -eq 0 ] && ! confirm "Go on, and keep those changes as they are?"; then
        say "Nothing was removed."; exit 1
    fi
    say
fi

# ------------------------------------------------------------------ what runs the app by itself
say "Scheduled scans (a timer of your account):"
timer=("$UNITS/daprivacyscanner-scan.timer" "$UNITS/daprivacyscanner-scan.service")
if [ -e "${timer[0]}" ] || [ -e "${timer[1]}" ]; then
    say "  ${timer[0]}"
    if confirm "  Turn them off and remove the timer?"; then
        user_unit_off daprivacyscanner-scan.timer
        remove "${timer[@]}" "$UNITS/timers.target.wants/daprivacyscanner-scan.timer"
    fi
else
    say "  none"
fi

say "The Outbox's watcher (it runs the app when a file lands in ~/Outbox; the folder and its files stay):"
outbox=("$UNITS/daprivacyscanner-outbox.path" "$UNITS/daprivacyscanner-outbox.service")
if [ -e "${outbox[0]}" ] || [ -e "${outbox[1]}" ]; then
    say "  ${outbox[0]}"
    if confirm "  Stop watching ~/Outbox and remove it?"; then
        user_unit_off daprivacyscanner-outbox.path
        remove "${outbox[@]}" "$UNITS/default.target.wants/daprivacyscanner-outbox.path"
    fi
else
    say "  none"
fi
[ "$dry" -eq 1 ] || systemctl --user daemon-reload >/dev/null 2>&1 || true

say "Right-click entries in the file manager (Verify download…, Remove metadata…):"
entries=()
for f in "$DATA"/nemo/actions/daprivacyscanner-*.nemo_action "$DATA"/kio/servicemenus/daprivacyscanner*.desktop \
         "$DATA"/nautilus/scripts/*"(DA Privacy Kit)"; do
    # only the ones the app wrote: each carries its mark
    [ -f "$f" ] && grep -qF "$MARK" "$f" 2>/dev/null && entries+=("$f")
done
if [ "${#entries[@]}" -gt 0 ]; then
    printf '  %s\n' "${entries[@]}"
    confirm "  Remove them?" && remove "${entries[@]}"
else
    say "  none"
fi

say "Menu entries of Boxes (apps kept in a sandbox: each entry starts the app with --box):"
boxes=()
for f in "$DATA"/applications/daprivacyscanner-box-*.desktop; do
    [ -f "$f" ] && grep -qF "$MARK" "$f" 2>/dev/null && boxes+=("$f")
done
if [ "${#boxes[@]}" -gt 0 ]; then
    printf '  %s\n' "${boxes[@]}"
    say "  The Boxes themselves (~/Boxes, with their apps' data) stay: delete them yourself if you don't want them."
    confirm "  Remove the menu entries?" && remove "${boxes[@]}"
else
    say "  none"
fi

# folders left empty by the above go too, as a revert in the app removes the ones it made (rmdir takes only empty ones)
if [ "$dry" -eq 0 ]; then
    rmdir "$UNITS/timers.target.wants" "$UNITS/default.target.wants" "$UNITS" "$CONFIG/systemd" \
          "$DATA/nemo/actions" "$DATA/nemo" "$DATA/kio/servicemenus" "$DATA/kio" "$DATA/nautilus/scripts" 2>/dev/null || true
fi

# ------------------------------------------------------------------ the app's own data
say "The app's data (History and its backups, the last report, accepted findings) and settings:"
data=()
# the cache: package lists an older version's online update test kept there, and trials kept on the disk
for d in "$STATE/daprivacyscanner" "$CONFIG/daprivacyscanner" "$CACHE/daprivacyscanner" "$CACHE/daprivacyscanner-trial" \
         "${XDG_RUNTIME_DIR:-/nonexistent}/daprivacyscanner"; do
    [ -e "$d" ] && data+=("$d")
done
if [ "$keep" -eq 1 ]; then
    say "  kept (--keep-data)"
elif [ "${#data[@]}" -gt 0 ]; then
    printf '  %s\n' "${data[@]}"
    confirm "  Remove them?" && remove "${data[@]}"
else
    say "  none"
fi

# ------------------------------------------------------------------ the helper, as administrator
say "The administrator helper, and its record of the root changes it made (needs your password):"
root=()
for f in "$HELPER_DIR" "$POLICY"; do [ -e "$f" ] && root+=("$f"); done
[ "$keep" -eq 1 ] || { [ -e "$JOURNAL" ] && root+=("$JOURNAL"); }
if [ "$noroot" -eq 1 ]; then
    say "  left (--no-root)"
elif [ "${#root[@]}" -gt 0 ]; then
    printf '  %s\n' "${root[@]}"
    if confirm "  Remove them?"; then
        if command -v sudo >/dev/null; then
            sudo rm -rf -- "${root[@]}" && printf '  removed %s\n' "${root[@]}"
        elif command -v pkexec >/dev/null; then
            pkexec rm -rf -- "${root[@]}" && printf '  removed %s\n' "${root[@]}"
        else
            say "  Neither sudo nor pkexec is here. As root: rm -rf ${root[*]}"
        fi
    fi
else
    say "  none"
fi

# ------------------------------------------------------------------ what stays
left="$(find /etc "$CONFIG/user-tmpfiles.d" -maxdepth 4 -name '*daprivacyscanner*' 2>/dev/null | sort)"
say
if [ -n "$left" ]; then
    say "Among what stays, these files were written for fixes you applied (they don't need the app):"
    printf '%s\n' "$left" | sed 's/^/  /'
fi
say "Settings the app changed for you (the desktop's, a browser's, NetworkManager's) stay as they are."
[ "$dry" -eq 0 ] || { say; say "Nothing was removed: this was a dry run."; exit 0; }
say
say "What is left to do by hand: delete the AppImage itself (DAPrivacyKit-*.AppImage), and its menu entry if"
say "an AppImage manager (Gear Lever, AppImageLauncher) made one."
