# Personal root CA: what's in this folder

Everything about the CA (certs, configs, procedures) lives in
**https://github.com/bsoyka/keys**: see `docs/restore.md` and `scripts/ca.sh`.
A clone of that repo is also in my backups. This folder holds only the one secret.

| File | What it is |
|---|---|
| `root-ca.key.asc` | Root CA private key (P-384), encrypted to my PGP key BC48…8D89. Decrypts with the YubiKey, or with the PGP master backup in `../pgp-keys/` if the YubiKey is gone. |

Never decrypt this onto a normal disk. `scripts/ca.sh` decrypts it onto a RAM disk
and destroys that when it exits.
