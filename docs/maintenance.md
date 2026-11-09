# Maintenance

| When | Task | How |
|---|---|---|
| Every October | Re-sign the CRL (it's valid ~400 days, so a year plus slack) | Wi-Fi off, `scripts/ca.sh crl`, Wi-Fi on, `make sign deploy` |
| Every October | Renew `security.txt` on bensoyka.com (expires each Nov 1; RFC 9116 wants under a year) | bump `Expires` in bsoyka/website's `security.txt.in`, re-sign, deploy |
| Before 2029-08-20 | Extend PGP subkeys | [restore.md § D](restore.md#d-extend-pgp-subkey-expiry-before-2029-08-20) |
| Before late 2031 | Renew the 9c document-signing cert | `scripts/ca.sh issue-docsign` (new key on the YubiKey), retire the old one in `keys.toml` |
| Any key change | Re-sign and redeploy the manifest | `make sign deploy` |

`make check` fails if `public/keys.txt` is unsigned or no longer matches what
`scripts/build.py` generates, so a stale manifest can't be deployed.

## Adding or retiring a key or cert

1. Put the public file under `public/pgp/` (named by full fingerprint) or `public/pki/`.
2. Add or edit its entry in `data/keys.toml` (`status`: current, revoked, retired, compromised).
3. `make sign deploy`.

## First-time setup (once)

1. `cd terraform && terraform init && terraform apply -var cloudflare_zone_id=…`
   (needs AWS credentials and `CLOUDFLARE_API_TOKEN` with DNS edit on bensoyka.com).
2. The ceremony: Wi-Fi off, YubiKey in, `scripts/ca.sh ceremony`. Creates the root,
   issues the 9c cert with attestation, signs the first CRL, adds the root fingerprint
   to the PGP UID, and installs the short RESTORE.md files in `~/doomsday/`.
3. Wi-Fi on. `make sign deploy`, then publish the PGP key (restore.md § E) since the
   notation changed it.
4. Acrobat: [acrobat.md](acrobat.md).
