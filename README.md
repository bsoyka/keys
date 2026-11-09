# keys

Single source of truth for my public keys and certificates, served at
**https://keys.bensoyka.com**. DNS for it (and WKD, via keys.openpgp.org) lives in bsoyka/infra.

```
PGP primary BC48…8D89 (offline)        ← root of trust
├─ clearsigns keys.txt                   (the manifest: every key, its status, how to verify)
├─ UID notation x509-root-sha256@bensoyka.com
└─ subkeys S/E/A on YubiKey (touch)
Root CA (P-384, offline, pathlen:1)    ← what people trust in Acrobat
└─ Personal CA (P-384, offline, pathlen:0)
   └─ document-signing certs in PIV 9c on each YubiKey, primary and backup
      (on-device keys, attested; RSA-3072 where the firmware allows)
   (room for more CAs under the root later; none exist yet)
```

Only secrets live outside this repo, in `~/doomsday/` (see [docs/restore.md](docs/restore.md)).
Keep a clone of this repo in backups so recovery doesn't depend on GitHub.

## Layout

| Path | What |
|---|---|
| `data/keys.toml` | What each key is and its status. Edit this, not the outputs. |
| `public/` | Exactly what's deployed. `pgp/`, `pki/` are source files; `style.css` (matched to bensoyka.com) and `verify.js` (the in-page checker) are hand-written; `index.html`, `keys.json`, `ssh.txt`, `pgp.asc` are generated; `keys.txt` is generated then signed. `vendor/` is a pinned OpenPGP.js (`scripts/vendor.sh` updates it). |
| `pki/` | OpenSSL config and the CA database (public by nature). |
| `scripts/build.py` | Generates the derived files; fingerprints are computed, never typed. |
| `scripts/ca.sh` | Root CA operations, on a RAM disk, offline. |
| `scripts/deploy.sh` | S3 upload with correct content types + CloudFront invalidation. |
| `terraform/` | S3, CloudFront, ACM (state in `bsoyka-tfstate`, like infra). See [terraform/README.md](terraform/README.md). |
| `docs/` | [restore](docs/restore.md) · [maintenance](docs/maintenance.md) · [acrobat](docs/acrobat.md) · [keyoxide](docs/keyoxide.md) |

## Everyday

```sh
make build    # regenerate after editing keys.toml or adding a file
make sign     # clearsign keys.txt (YubiKey touch)
make deploy   # refuses unless keys.txt is signed and current
make check-expiry   # anything expiring within 60 days?
```
