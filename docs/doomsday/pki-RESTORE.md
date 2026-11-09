# Certificate authority and Keyoxide keys: what's in this folder

Everything about the CA (certs, configs, procedures) lives in
**https://github.com/bsoyka/keys**: see `docs/restore.md` and `scripts/ca.sh`.
A clone of that repo is also in my backups. This folder holds only the secrets.

| File | What it is |
|---|---|
| `root.key.asc` | Root CA private key (P-384). Only used to create or revoke CAs under it and to re-sign its revocation list. |
| `personal-ca.key.asc` | Personal CA private key (P-384). Issues my own certificates. |
| `keyoxide-asp.key.asc` | Keyoxide profile key (Ed25519). Signs my Keyoxide profile. |

All are encrypted to my PGP key BC48…8D89: they decrypt with the YubiKey, or with
the PGP master backup in `../pgp-keys/` if the YubiKey is gone.

Never decrypt these onto a normal disk. `scripts/ca.sh` decrypts them onto a RAM disk
and destroys that when it exits.
