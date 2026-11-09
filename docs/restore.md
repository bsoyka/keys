# Restore and recovery

The secrets live in `~/doomsday/` (backed up by Sirloin); everything else is in this
repo. Each doomsday folder has a short RESTORE.md listing its files.

| Secret | Where | Unlocks with |
|---|---|---|
| PGP primary + subkeys | `doomsday/pgp-keys/current-83D68D89/secret-master-….asc` | passphrase (memorized) |
| PGP revocation cert | same folder, plus an off-site copy | nothing needed |
| Root CA key | `doomsday/pki/root.key.asc` | YubiKey, or the PGP master backup |
| Personal CA key | `doomsday/pki/personal-ca.key.asc` | YubiKey, or the PGP master backup |
| PIV 9c signing key | YubiKey only (not exportable, by design) | PIN + touch |

Tools (macOS): `brew install gnupg pinentry-mac ykman openssl@3`

## Working with the PGP primary key

Use a throwaway keyring so the primary key never lands in the everyday one:

```sh
export GNUPGHOME=$(mktemp -d)
gpg --import ~/doomsday/pgp-keys/current-83D68D89/secret-master-BC4876BDC8AB5AB8C9CB81659497E30583D68D89.asc
gpg --import public/pgp/BC4876BDC8AB5AB8C9CB81659497E30583D68D89.asc   # newest public sigs
# ...do the task...
gpgconf --kill all; rm -rf "$GNUPGHOME"; unset GNUPGHOME
```

(`scripts/ca.sh notation` does the same on a RAM disk.)

## A. New computer, YubiKey still works

No secrets needed.

```sh
gpg --import public/pgp.asc
gpg --card-status        # with the YubiKey plugged in; creates the card stubs
gpg -K                   # expect: sec#  and ssb> on all three subkeys
gpg --edit-key BC4876BDC8AB5AB8C9CB81659497E30583D68D89   # trust → 5 → save
```

Then the usual config: `gpg-agent.conf` with `enable-ssh-support` and Homebrew's
`pinentry-mac`; fish exports `GPG_TTY` and `SSH_AUTH_SOCK`; Git uses
`user.signingkey` = the primary fingerprint and `commit.gpgsign true`.

For PDF signing in Acrobat, see [acrobat.md](acrobat.md).

## B. YubiKey lost or dead

**PGP subkeys**: load them onto a new YubiKey from the backup.

1. Throwaway keyring with the secret key imported (above).
2. New card's PINs: `gpg --card-edit` → `admin` → `passwd` (User PIN from 123456, Admin PIN from 12345678).
3. Move each subkey: `gpg --edit-key BC48…8D89`, then `key 1` → `keytocard` → `1`, `key 1` (deselect);
   `key 2` → `keytocard` → `2`, `key 2`; `key 3` → `keytocard` → `3`; `save`.
4. Touch on all three: `ykman openpgp keys set-touch sig on` (and `enc`, `aut`).
5. Delete the throwaway keyring, then follow **A**.
6. If the old YubiKey was *lost* (not broken), it's PIN-locked after 3 tries, so the risk is low.
   To be thorough, revoke those subkeys (`key N` → `revkey`), create new ones, publish (**E**).

**PIV 9c signing cert**: the key died with the YubiKey (it can't be backed up, on purpose).

1. `scripts/ca.sh revoke personal <old serial>` if the YubiKey was lost (not just broken).
2. `scripts/ca.sh issue-docsign` with the new YubiKey.
3. Update `data/keys.toml` (move the old cert to retired/compromised), `make sign deploy`.

Anyone who trusts the root keeps trusting the new cert; nothing to redistribute.

## C. Decrypt old data without a YubiKey

Throwaway keyring with the secret key, then `gpg -d file.gpg`.
For data encrypted to the previous key, first decrypt `old-A65228EA.secret.asc.gpg`
the same way and import it.

## D. Extend PGP subkey expiry (before 2029-08-20)

```sh
# in a throwaway keyring with the secret key imported:
gpg --quick-set-expire BC4876BDC8AB5AB8C9CB81659497E30583D68D89 3y '*'
gpg --armor --export BC4876BDC8AB5AB8C9CB81659497E30583D68D89 > public/pgp/BC4876BDC8AB5AB8C9CB81659497E30583D68D89.asc
gpg --armor --export-secret-keys BC4876BDC8AB5AB8C9CB81659497E30583D68D89 \
  > ~/doomsday/pgp-keys/current-83D68D89/secret-master-BC4876BDC8AB5AB8C9CB81659497E30583D68D89.asc
cp public/pgp/BC48*.asc ~/doomsday/pgp-keys/current-83D68D89/
```

Then `make sign deploy` and publish (**E**). The YubiKey doesn't change.

## E. Publish an updated PGP key

```sh
make sign deploy                                   # keys.bensoyka.com + WKD
gpg --keyserver hkps://keys.openpgp.org --send-keys BC4876BDC8AB5AB8C9CB81659497E30583D68D89
```

Also replace it at https://github.com/settings/keys.

## F. Revoke the whole PGP key (compromised, or primary key / passphrase lost)

```sh
gpg --import public/pgp.asc
gpg --import ~/doomsday/pgp-keys/current-83D68D89/secret-revoke-BC4876BDC8AB5AB8C9CB81659497E30583D68D89.asc
```

Publish (**E**). Revoking is permanent. Then make a new key, re-encrypt both CA
keys to it (`gpg -d` with the old key first, before revoking, if you still can),
update `PGP_FPR` in `scripts/ca.sh` and the Makefile, and re-sign `keys.txt`.

## G. Personal CA key compromised or lost

This is what the two-level setup is for: the root stays trusted.

1. `scripts/ca.sh revoke root <personal CA serial>` (serial from `pki/ca/root/index.txt`).
   The root's revocation list now says the personal CA is dead, and validators that
   check it will reject everything it issued.
2. Move `pki/ca/personal/` aside, then `scripts/ca.sh new-intermediate personal "Benjamin Soyka Personal CA"`
   and `scripts/ca.sh issue-docsign`.
3. Mark the old personal CA and its certs compromised (or retired, if the key was
   only lost) in `data/keys.toml`; `make sign deploy`. Nobody needs to re-trust anything.

## H. Root CA key compromised or lost

A self-signed root can't be revoked in a way validators will notice, so:

1. Move the root and everything under it to *compromised* in `data/keys.toml`;
   `make sign deploy`. The signed manifest is the revocation notice.
2. If the key was *lost* but not exposed, existing signatures stay trustworthy;
   say that instead and mark them *retired*.
3. Move `pki/ca/` aside, then run `scripts/ca.sh ceremony` again (it also redoes
   the UID notation, which must change).
4. Tell anyone who trusted the old root.
