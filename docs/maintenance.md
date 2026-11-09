# Maintenance

| When | Task | How |
|---|---|---|
| Every October | Re-sign both revocation lists (root and personal CA; each is valid ~400 days, so a year plus slack) | Wi-Fi off, `scripts/ca.sh crl`, Wi-Fi on, `make sign deploy` |
| Every October | Renew `security.txt` on bensoyka.com (expires each Nov 1; RFC 9116 wants under a year) | bump `Expires` in bsoyka/website's `security.txt.in`, re-sign, deploy |
| Before 2029-08-20 | Extend PGP subkeys | [restore.md § D](restore.md#d-extend-pgp-subkey-expiry-before-2029-08-20) |
| Before late 2031 | Renew the 9c document-signing cert | `scripts/ca.sh issue-docsign` (new key on the YubiKey), retire the old one in `keys.toml` |
| Before late 2036 | Renew the personal CA (10-year cert) | `scripts/ca.sh new-intermediate personal …` after moving the old one aside; reissue 9c |
| Any key change | Re-sign and redeploy the manifest | `make sign deploy` |

`make check` fails if `public/keys.txt` is unsigned or no longer matches what
`scripts/build.py` generates, so a stale manifest can't be deployed.

## Adding or retiring a key or cert

1. Put the public file under `public/pgp/` (named by full fingerprint) or `public/pki/`.
2. Add or edit its entry in `data/keys.toml` (`status`: current, revoked, retired, compromised).
3. `make sign deploy`.

## First-time setup (once)

1. Hosting: [terraform/README.md](../terraform/README.md) (two phases, with the
   DNS records added in bsoyka/infra in between).
2. The ceremony: Wi-Fi off, YubiKey in, `scripts/ca.sh ceremony`. Creates the root
   and the personal CA under it, issues the 9c cert with attestation, signs both
   revocation lists, adds the root fingerprint to the PGP UID, and installs the
   short RESTORE.md files in `~/doomsday/`.
3. Wi-Fi on. `make sign deploy`, then publish the PGP key (restore.md § E) since the
   notation changed it.
4. Acrobat: [acrobat.md](acrobat.md).

## Adding another CA under the root (e.g. for friends)

The root is built for this (`pathlen:1`), but nothing exists yet and nothing is
published for it. When the time comes:

1. Add a `[ friends_ca ]` section to `pki/openssl.cnf` (copy `personal_ca`, change
   `dir`) and a leaf profile with its own CRL/AIA URLs.
2. `scripts/ca.sh new-intermediate friends "Benjamin Soyka Friends CA"`.
3. Add it to `data/keys.toml` and decide how the page should explain it: anyone
   trusting the root will trust certificates it issues.
4. Friends generate their own keys (ideally on a hardware key, with attestation)
   and send a signing request; never make keys for them.
