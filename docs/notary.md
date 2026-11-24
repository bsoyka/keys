# Notary signing certificate

For electronic notarial acts in Acrobat (Minn. Stat. §§ 358.69, 359.01 subd. 5; remote
acts under § 358.645). Separate from my personal signing certs on purpose.

```
Root CA
└─ Notary CA (P-384, offline)          ← what recipients trust, not the root
   └─ notary cert (P-256, this Mac's Secure Enclave, Touch ID, not exportable)
```

Key decisions:

- **Own CA under the root.** Recipients trust `notary-ca.crt` only, so trusting my
  notary seal never extends to anything else I issue.
- **Secure Enclave key, not the YubiKey.** YubiKey retired slots (82–95) show up in
  macOS as decrypt-only and Acrobat can't sign with them (tested 2026-11-24).
- **No backup.** New Mac or wipe: revoke, then issue again.
- **Expires with the commission** (2031-01-31). Name and commission number are set
  at the top of `scripts/ca.sh`; update them on recommission.

## Rehearsed 2026-11-24 (throwaway keys and CA, nothing real involved)

What the rehearsal settled about `sc_auth`, which documents none of it:

- `create-ctk-csr` writes a PEM request.
- `import-ctk-certificate` replaces the identity's self-made cert with the CA-issued
  one; Acrobat (after a restart) then signs with it and shows the CA as issuer.
- The issued cert must be a normal v3 cert with key usage. A bare cert with no
  extensions made Acrobat crash on signing and leave an empty signature. The
  `v3_notary` profile has the same extensions as the cert that worked.

To repeat it: make an identity (`sc_auth create-ctk-identity -l test -k p-256-ne -t bio -N "Test"`),
sign a request from it with any throwaway CA using the `v3_notary` extensions,
import, sign a PDF, then `sc_auth delete-ctk-identity -h <hash>`.

## Setup (once, Wi-Fi off, same session as other root work)

1. `scripts/ca.sh new-intermediate notary "Benjamin Soyka Notary CA"`
2. `scripts/ca.sh issue-notary` (Touch ID twice)
3. `scripts/ca.sh crl`
4. Add the notary CA and notary cert to `data/keys.toml` (done 2026-11-24; on a
   reissue only the cert file changes, the entries stay).
5. Wi-Fi on. `make sign deploy`.
6. Acrobat: import `public/pki/notary-ca.crt` under Trusted Certificates and tick
   "Use this certificate as a trusted root" for signed documents only. Build the
   signature appearance (handwritten signature + official stamp image at legal size).
   When signing as a notary, tick **Lock document after signing**.

## Each October

`scripts/ca.sh crl` already re-signs every CA's list, this one included.

## Ending it (commission ends, registration terminated, new Mac, or key in doubt)

1. Wi-Fi off. `scripts/ca.sh revoke notary <serial> cessationOfOperation`
   (`keyCompromise` if the Mac was lost or the key is in doubt).
2. `sc_auth list-ctk-identities`, then `sc_auth delete-ctk-identity -h <hash>`.
   This is the destruction § 358.645 subd. 8 requires; certify it to the Secretary of
   State through the online commission record.
3. Mark the cert retired or compromised in `data/keys.toml`; `make sign deploy`.
4. Loss or unauthorized use: report to the Commissioner of Commerce (theft: law
   enforcement too), § 358.645 subd. 6.
