# The release keys: moving to an offline primary key, a signing subkey on a token and a pinned successor

This is the owner's procedure, decided on 2026-11-12. The private keys are the owner's alone: nothing here is ever
run on a machine where automated agents or the development tools run, and no private key or revocation certificate
is ever put in this repository.

## Why

Today every release is signed by one key, *Digital Archon Release Signing*,
`3AA5 C061 33BB C05A 4151  EA41 5B59 48EB 785E D3AF`: an ed25519 primary key that certifies and signs, with no
subkeys and no expiry. Every copy of the app carries its public half (`signing-keys.yaml`) and never fetches keys,
so that copies don't go online. That has a cost: if the key were stolen, whoever has it could sign a release that
every copy out there calls *Verified: made by Digital Archon*, and no revocation would ever reach those copies.

The change makes a theft unlikely rather than recoverable, which is the most a key that is never fetched again can
get:

- a new **primary key** that only certifies (makes and revokes subkeys), generated and kept on an offline machine;
- the **signing subkey** on a hardware token (an OpenPGP card: YubiKey 5, Nitrokey 3), where it can't be copied off,
  with a touch required for every signature, and a **second signing subkey on a backup token**, kept elsewhere;
- a **successor key**, made now and pinned now (`role: successor` in `signing-keys.yaml`), kept offline apart from
  the others, for the day the new primary key has to be retired: only a key already in a copy can ever verify there;
- revocation certificates for all of them, kept offline.

What the app does with it (`tools/keys.py`, tested with throwaway keys in `tests/test_release.py`): only primary
keys are pinned; a subkey in the key block counts when its primary key binds it (a subkey binding signature it
made, which gpgv and sqv check); a subkey spliced in from another key never counts; a successor verifies like any
listed key; a file signed by several keys (the old one and the new subkey) is verified by any one the copy knows.

## Before you start

- An offline machine: a live system started from USB with networking off (Tails with no network, or a Debian live
  image with the network cable out and Wi-Fi off), GnuPG 2.4 and `paperkey`; nothing of it is kept.
- Two encrypted USB drives for the offline GnuPG home and its backup (LUKS), and paper for `paperkey` and the
  revocation certificates.
- Three OpenPGP tokens: A (everyday signing), B (backup signing, kept elsewhere), C (the successor's signing key,
  kept in a third place). Set each one's user PIN and admin PIN first (`gpg --card-edit`, `admin`, `passwd`), and on
  a YubiKey require a touch to sign: `ykman openpgp keys set-touch sig on`.
- The current key's private half (3AA5…), on the machine it lives on now: it signs the transition statement and,
  for a while, the releases too.

## 1. The new primary key and its two signing subkeys (offline)

```sh
export GNUPGHOME=/media/release-keys/gnupg            # on the encrypted USB drive, never the live system's disk
mkdir -m 700 -p "$GNUPGHOME"
gpg --quick-gen-key 'Digital Archon Release Signing 2026 <releases@digitalarchon.com.au>' ed25519 cert never
N=$(gpg --with-colons --list-keys 'Digital Archon Release Signing 2026' | awk -F: '$1 == "fpr" {print $10; exit}')
gpg --quick-add-key "$N" ed25519 sign never           # for token A
gpg --quick-add-key "$N" ed25519 sign never           # for token B
gpg --with-colons --list-keys "$N" | awk -F: '$1 == "fpr" {print $10}'   # N, then the subkeys A and B
```

No expiry on any of them, on purpose: copies never fetch keys, so an extended expiry would never reach them, and
they would call new releases signed by an expired key.

Back everything up before a subkey goes to a token (moving one replaces it on disk by a stub):

```sh
gpg --armor --export-secret-keys "$N" > /media/release-keys-backup/N-secret.asc
paperkey --secret-key /media/release-keys-backup/N-secret.asc --output N-paperkey.txt      # print it
cp "$GNUPGHOME/openpgp-revocs.d/$N.rev" /media/release-keys-backup/                       # and print it
```

Then each subkey onto its token: `gpg --edit-key "$N"`, `key 1`, `keytocard` (as the signature key), `save`, with
token A inserted; then `key 2`, `keytocard`, `save` with token B. Check: `gpg --card-status` shows the signature
key's fingerprint, and `gpg -K "$N"` marks both subkeys `ssb>` (on a card) and the primary `sec` (here, offline).

## 2. The successor key (offline, kept apart)

The same, with its own GnuPG home on a third encrypted drive, one signing subkey onto token C:

```sh
export GNUPGHOME=/media/successor-key/gnupg
gpg --quick-gen-key 'Digital Archon Release Signing successor <releases@digitalarchon.com.au>' ed25519 cert never
S=$(gpg --with-colons --list-keys 'Digital Archon Release Signing successor' | awk -F: '$1 == "fpr" {print $10; exit}')
gpg --quick-add-key "$S" ed25519 sign never
gpg --armor --export-secret-keys "$S" > /media/successor-key-backup/S-secret.asc   # and paperkey, and its .rev
```

`keytocard` its subkey onto token C. The successor is never used while N is sound.

## 3. The public keys, and a statement both keys sign

On the offline machine, export the public halves, minimal, into one file (with `GNUPGHOME` pointing at each home in
turn, or after importing S's public key into N's home):

```sh
gpg --armor --export-options export-minimal,export-clean --export "$N" "$S" > new-release-keys.asc
```

On the machine with the current key, import that file and make the transition statement, signed by the old key
(and, on the offline machine, by N):

```sh
gpg --import new-release-keys.asc
gpg --armor --export-options export-minimal,export-clean \
    --export 3AA5C06133BBC05A4151EA415B5948EB785ED3AF "$N" "$S" > release-key.asc
cat > transition.txt <<EOF
From DA Privacy Kit <version> on, releases are signed by the signing subkeys of
  $N (Digital Archon Release Signing 2026),
whose primary key is kept offline. $S is its successor, pinned in the app from <version> on and used only if
the 2026 key has to be retired. Until <date>, releases are also signed by 3AA5C06133BBC05A4151EA415B5948EB785ED3AF.
EOF
gpg --local-user 3AA5C06133BBC05A4151EA415B5948EB785ED3AF --clearsign transition.txt
```

Then sign the same text with the new key, on a machine with token A: `gpg --local-user '<subkey A>!' --clearsign
transition.txt` (N's primary can only certify, so its token's subkey speaks for it). Publish both signed copies.
Where the old key lives, also certify the new keys with it, for people who follow certifications:
`gpg --local-user 3AA5C06133BBC05A4151EA415B5948EB785ED3AF --quick-sign-key "$N"` (and `"$S"`), and publish those
certified keys on keys.openpgp.org; the app's own copy stays minimal.

## 4. Into the repository

- `docs/release-key.asc` becomes `release-key.asc` from step 3: all three keys.
- `signing-keys.yaml`, the `digitalarchon` entry: `key:` the same block; `keys:` all three primaries:

  ```yaml
      keys:
        - fingerprint: 3AA5C06133BBC05A4151EA415B5948EB785ED3AF
          name: Digital Archon Release Signing (2026-10)
        - fingerprint: <N>
          name: Digital Archon Release Signing 2026
        - fingerprint: <S>
          name: Digital Archon Release Signing (successor)
          role: successor
  ```

  and `checked:` the day, `note:` where the fingerprints were confirmed (both channels below).
- The README's fingerprint block lists N (and S, as the successor), and says until when 3AA5 also signs.
- `.venv/bin/python -m pytest tests/test_release.py tests/test_verify.py` (the key file and the YAML hold the same
  keys, every subkey bound), then `make check`.

## 5. Publishing the fingerprints, on two channels

Copies of the app trust what is in them, but people choosing to trust the app compare fingerprints, so the
fingerprints must be somewhere an attacker of one channel can't also change:

1. **GitHub**: the README, `docs/release-key.asc`, `signing-keys.yaml`, and the transition statement in the release
   notes of the first release that pins the new keys.
2. **A second channel, not the GitHub account**: a page on digitalarchon.com.au (HTTPS) with the three fingerprints
   and the signed transition statement; the keys in Web Key Directory on that domain
   (`gpg --locate-keys releases@digitalarchon.com.au` then finds them); and the public keys on keys.openpgp.org
   (verify the address so the user ID is shown). Point `source:` of the `digitalarchon` entry at the
   digitalarchon.com.au page, so `packaging/check-signing-keys.py` checks the fingerprints there before each release.

## 6. Releasing during the change

```sh
git config user.signingkey '<subkey A>!'               # tags are signed by the token's subkey
git tag -s v<version> -m 'DA Privacy Kit <version>'
packaging/build-appimage.sh release v<version>         # two builds here, compared
packaging/second-build.sh v<version> <host>            # a third on another machine, compared
DAPS_SIGNING_KEYS='<subkey A>! 3AA5C06133BBC05A4151EA415B5948EB785ED3AF!' packaging/sign-release.sh v<version>
```

The first release that pins the new keys, and the ones after it, carry both signatures in each `.asc`: copies made
before it know only 3AA5 and verify by it; copies from it on verify by either. Keep signing with both until the
copies that know only 3AA5 are long out of date (the app says so at 90 days: two such windows, about six months,
are plenty), then sign with the subkey alone, and in a later release take 3AA5 out of `signing-keys.yaml`, so that
nothing it might sign after its key is retired is trusted by new copies. `sign-release.sh` checks every signature
against the tag's own `docs/release-key.asc`, so it refuses a key the release doesn't pin.

## If something goes wrong

- **Token A lost, or stolen with its PIN**: on the offline machine, revoke subkey A (`gpg --edit-key "$N"`, `key 1`,
  `revkey`, `save`), export the block again into `docs/release-key.asc` and `signing-keys.yaml` (a revoked subkey's
  signatures are then refused by new copies: gpgv reads the revocation from the bundled block; check that the
  export carries it, `gpg --list-packets` showing a signature of class 0x28 after that subkey), and sign with
  token B, whose subkey every copy that pins N already has. Add a new subkey for a new token the same way as in
  step 1; it verifies only in copies made after it.
- **The offline primary key N compromised or lost**: release with the successor's subkey (token C), which every copy
  since the change already pins; publish N's revocation certificate, take N out of the pins in that release, and
  say so on both channels. Copies made before the change know only 3AA5.
- **3AA5 compromised before the change is complete**: the same, with N in place of S: publish its revocation, release
  signed by N's subkey only, and say so on both channels, with the date: copies made before the change still trust
  3AA5, and only updating them ends that.

What none of this can do: reach a copy already out there. A revocation, a new subkey or a new successor counts only
in copies made after it, so keeping the primary keys offline and the signing key on a token, where it can't be
copied, is what protects the copies that exist.
