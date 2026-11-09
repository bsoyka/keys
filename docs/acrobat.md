# Acrobat

## Signing with the YubiKey (my machine)

macOS doesn't expose PIV slot 9c to Acrobat by itself; Acrobat talks to it through
Yubico's PKCS#11 module.

1. Install the module (Yubico PIV Tool / ykcs11). On this Mac it's at
   `/usr/local/lib/libykcs11.dylib`.
2. Acrobat → Settings → Signatures → Identities & Trusted Certificates → More →
   Digital IDs → PKCS#11 Modules and Tokens → Attach Module → that path.
3. Log in to the token with the PIV PIN; the 9c cert appears as a digital ID.
4. Settings → Signatures → Document Timestamping → add a timestamp server
   (e.g. `http://timestamp.digicert.com`) and set it as default. Timestamped
   signatures stay valid after the cert expires.
5. Trust my own root on this machine too (below), so my own signatures show as valid.
6. Also import `public/pki/personal-ca.crt` under Trusted Certificates (no trust
   boxes ticked). The YubiKey only holds my own cert, so this is how Acrobat finds
   the middle of the chain and embeds it in each signature. Recipients' Acrobat can
   also fetch it from the URL inside my cert, but embedding works offline.

After a new 9c cert (`scripts/ca.sh issue-docsign`), refresh the token in step 3.

## Trusting my root (anyone)

This is also on https://keys.bensoyka.com.

1. Open a PDF I signed → click the signature → Signature Properties → Show Signer's Certificate.
2. Select the top of the chain (my root CA) and check its SHA-1 against `keys.txt`.
3. Trust tab → Add to Trusted Certificates → tick **Use this certificate as a trusted
   root** for signed documents. Leave certified documents and dynamic content unticked.

Or import `public/pki/root.crt` under Identities & Trusted Certificates → Trusted Certificates → Import.

## One-click trust file (optional)

Acrobat can export a trusted certificate as an `.fdf` that others double-click to
import: Identities & Trusted Certificates → Trusted Certificates → select the root →
Export → "Save the data to a file". Save it as `public/pki/root.fdf`, then
`make sign deploy`. The page links it automatically once the file exists.
