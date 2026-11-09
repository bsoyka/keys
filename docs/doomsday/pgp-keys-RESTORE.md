# PGP keys: what's in this folder

Everything about these keys (what each is, how to restore, renew, revoke) lives in
**https://github.com/bsoyka/keys**: see `docs/restore.md`. A clone of that repo is
also in my backups. This folder holds only what can't be published.

| File | What it is |
|---|---|
| `current-83D68D89/secret-master-BC48…8D89.asc` | Current key: primary + all subkeys. Passphrase-protected. |
| `current-83D68D89/secret-revoke-BC48…8D89.asc` | Revocation certificate for the current key. Can only revoke, nothing else. |
| `current-83D68D89/pub-BC48…8D89.asc` | Current public key (same as the repo's copy). |
| `old-A65228EA.secret.asc.gpg` | Previous key (revoked 2026-08-21), encrypted to the current key. Only for decrypting old data. |
| `old-A65228EA.pub.asc` | Previous key's public key, with its revocation. |
| `old-147A3418.asc` | Original key (revoked 2025), passphrase-protected. |
| `wikipedia-F9A524BC.asc` | Wikipedia key, passphrase-protected. Still in use. |

The passphrases and YubiKey PINs are memorized only. Without them, the only thing
here anyone else can use is the revocation certificate.

**If someone other than me is reading this:** don't revoke unless I've asked you to,
or you have clear reason to believe the key was compromised.
