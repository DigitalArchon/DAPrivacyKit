#!/bin/bash
# Is this tag signed by a release key DA Privacy Kit pins?
#   packaging/verify-tag.sh TAG [KEYS.asc]
# KEYS.asc defaults to docs/release-key.asc of this checkout (the public release keys, kept equal to
# signing-keys.yaml's digitalarchon entry by a test): never the tag's own copy, which whoever made the tag chose. Only
# a good signature whose primary key is one of the keys in that file counts; the user's own keyring is never read
# (gpg runs with a temporary home). Exit status 0 signed by a pinned key, 1 a bad signature or another key's, 3 not
# signed at all (releases before 0.1.0b9 had annotated tags without a signature), 2 it couldn't be checked.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: $0 TAG [KEYS.asc]" >&2; exit 2; }
tag="$1"; keys="${2:-docs/release-key.asc}"
[ -f "$keys" ] || { echo "No key file $keys." >&2; exit 2; }
command -v gpg >/dev/null || { echo "gpg is needed (gnupg)." >&2; exit 2; }
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "There is no tag '$tag' (git fetch --tags)." >&2; exit 2; }
if [ "$(git cat-file -t "refs/tags/$tag")" != tag ] \
        || ! git cat-file tag "refs/tags/$tag" | grep -q -- '-----BEGIN PGP SIGNATURE-----'; then
    echo "The tag $tag is not signed." >&2
    exit 3
fi
home="$(mktemp -d)"
trap 'gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; rm -rf "$home"' EXIT
chmod 700 "$home"
gpg --homedir "$home" --batch --quiet --import "$keys" 2>/dev/null
# the primary keys' fingerprints: an fpr record right after a pub record
pinned="$(gpg --homedir "$home" --batch --with-colons --list-keys \
          | awk -F: '$1 == "fpr" && last == "pub" {print $10} {last = $1}')"
[ -n "$pinned" ] || { echo "No key in $keys." >&2; exit 2; }
status="$(GNUPGHOME="$home" git -c gpg.program=gpg -c gpg.format=openpgp verify-tag --raw "$tag" 2>&1 >/dev/null || true)"
primary="$(printf '%s\n' "$status" | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print $NF}')"
if printf '%s\n' "$status" | grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|REVKEYSIG|EXPKEYSIG|EXPSIG|KEYREVOKED)' \
        || ! printf '%s\n' "$status" | grep -q '^\[GNUPG:\] GOODSIG' || [ -z "$primary" ]; then
    echo "The tag $tag's signature is not good, or not by a key in $keys:" >&2
    printf '%s\n' "$status" | grep -E '^\[GNUPG:\] (BADSIG|ERRSIG|REVKEYSIG|EXPKEYSIG|EXPSIG|KEYREVOKED|NO_PUBKEY|GOODSIG|VALIDSIG)' >&2 || true
    exit 1
fi
if ! printf '%s\n' "$pinned" | grep -qxF "$primary"; then
    echo "The tag $tag is signed by $primary, which isn't a primary key in $keys." >&2
    exit 1
fi
echo "The tag $tag is signed by a pinned release key ($primary)."
