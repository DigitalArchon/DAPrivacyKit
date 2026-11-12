#!/bin/bash
# Make git run the local CI (packaging/check.sh) before every push: an optional pre-push hook, installed only when
# asked. `git push --no-verify` skips it for one push.
#   packaging/install-hooks.sh            install it (or say what is in the way)
#   packaging/install-hooks.sh --quick    the hook runs packaging/check.sh --quick (lint, types, the dev venv's suite)
#   packaging/install-hooks.sh --remove   remove it again (only the hook this script wrote)
# The hooks folder is shared by every worktree of the clone, so one hook serves them all; it runs the checks of the
# worktree being pushed from.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
hooks="$(git rev-parse --git-path hooks)"
hook="$hooks/pre-push"
MARK="# written by packaging/install-hooks.sh"
args=""
case "${1:-}" in
    --remove)
        if [ -f "$hook" ] && grep -qxF "$MARK" "$hook"; then rm "$hook"; echo "removed $hook"
        elif [ -e "$hook" ]; then echo "$hook isn't this script's: left as it is" >&2; exit 1
        else echo "no pre-push hook"; fi
        exit 0 ;;
    --quick) args=" --quick" ;;
    "") ;;
    *) echo "usage: $0 [--quick | --remove]" >&2; exit 2 ;;
esac
if [ -e "$hook" ] && ! grep -qxF "$MARK" "$hook"; then
    echo "$hook is already there and isn't this script's: add 'packaging/check.sh$args' to it yourself" >&2
    exit 1
fi
mkdir -p "$hooks"
cat > "$hook" <<EOF
#!/bin/sh
$MARK
# The local CI before every push (git push --no-verify skips it once; packaging/install-hooks.sh --remove removes it).
cd "\$(git rev-parse --show-toplevel)" || exit 1
exec packaging/check.sh$args
EOF
chmod 755 "$hook"
echo "installed $hook: git push now runs packaging/check.sh$args first"
