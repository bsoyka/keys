#!/usr/bin/env bash
# Personal root CA operations. macOS, run from the repo root with Wi-Fi off.
#
#   scripts/ca.sh init-root       create the root CA (once, ever)
#   scripts/ca.sh issue-docsign   new on-device key in PIV slot 9c + root-issued cert
#   scripts/ca.sh crl             re-sign the revocation list (yearly)
#   scripts/ca.sh revoke SERIAL   revoke an issued cert, then re-sign the CRL
#   scripts/ca.sh notation        add root fingerprint to the PGP UID (needs PGP master)
#   scripts/ca.sh ceremony        init-root + issue-docsign + crl + notation, in order
#
# Key decisions:
# - Plaintext private keys only ever exist on a RAM disk that's destroyed on exit,
#   so they never touch the SSD, Time Machine or Spotlight.
# - The root key at rest is encrypted to my PGP key (encryption subkey on the
#   YubiKey; the doomsday master backup can also decrypt it). No extra passphrase
#   to remember, and it's recoverable by the same path as everything else.
# - The 9c key is generated on the YubiKey and never exported. Its attestation is
#   published so anyone can check that against Yubico's CA.

set -euo pipefail

PGP_FPR=BC4876BDC8AB5AB8C9CB81659497E30583D68D89
DOOMSDAY="${DOOMSDAY:-$HOME/doomsday}"
ROOT_KEY_ENC="$DOOMSDAY/pki/root-ca.key.asc"
SUBJ_DOCSIGN="/CN=Benjamin Soyka/emailAddress=ben@bensoyka.com/C=US"
ROOT_DAYS=7305   # 20 years

export KEYS_REPO="$PWD"
CNF="$KEYS_REPO/pki/openssl.cnf"
[[ -f "$CNF" ]] || { echo "run from the repo root" >&2; exit 1; }

# Homebrew OpenSSL 3; macOS's /usr/bin/openssl is LibreSSL and lacks pieces we use.
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"
[[ -x "$OPENSSL" ]] || { echo "brew install openssl@3" >&2; exit 1; }
for t in ykman gpg; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }; done

say()   { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pause() { read -r -p "$* [enter to continue] " _; }

check_offline() {
  if route -n get default >/dev/null 2>&1; then
    echo "A default network route exists. Turn Wi-Fi off (and unplug Ethernet) first." >&2
    exit 1
  fi
}

RAM=""
ramdisk_up() {
  local dev
  dev=$(hdiutil attach -nomount ram://65536 | awk '{print $1}')   # 32 MB
  diskutil erasevolume APFS PKIRAM "$dev" >/dev/null
  RAM=/Volumes/PKIRAM
  chmod 700 "$RAM"
  mdutil -i off "$RAM" >/dev/null 2>&1 || true
  trap ramdisk_down EXIT
}
ramdisk_down() {
  [[ -n "$RAM" && -d "$RAM" ]] || return 0
  # Throwaway GnuPG home (notation step) has its own agent; stop it first.
  [[ -d "$RAM/gnupg" ]] && GNUPGHOME="$RAM/gnupg" gpgconf --kill all 2>/dev/null || true
  hdiutil detach "$RAM" -force >/dev/null && echo "RAM disk destroyed."
  RAM=""
}

# Decrypt the root key onto the RAM disk (YubiKey PIN + touch).
load_root_key() {
  [[ -f "$ROOT_KEY_ENC" ]] || { echo "no $ROOT_KEY_ENC" >&2; exit 1; }
  export ROOT_KEY="$RAM/root.key"
  gpg --quiet --decrypt --output "$ROOT_KEY" "$ROOT_KEY_ENC"
  chmod 600 "$ROOT_KEY"
}

der() { "$OPENSSL" "$1" -in "$2" -outform DER -out "$3"; }

cmd_init_root() {
  [[ -e pki/ca/root.pem ]] && { echo "root already exists; refusing to overwrite" >&2; exit 1; }
  say "Creating root CA key (P-384) on the RAM disk"
  export ROOT_KEY="$RAM/root.key"
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$ROOT_KEY"
  "$OPENSSL" req -config "$CNF" -new -x509 -key "$ROOT_KEY" -sha384 -days "$ROOT_DAYS" \
    -set_serial "0x$("$OPENSSL" rand -hex 16)" -out pki/ca/root.pem
  der x509 pki/ca/root.pem public/pki/root.crt
  "$OPENSSL" x509 -in pki/ca/root.pem -noout -subject -enddate -fingerprint -sha256

  say "Encrypting root key to PGP key $PGP_FPR"
  mkdir -p "$DOOMSDAY/pki"
  gpg --batch --yes --trust-model always --armor -r "$PGP_FPR" \
    --output "$ROOT_KEY_ENC" --encrypt "$ROOT_KEY"

  say "Test-decrypting the backup (YubiKey PIN + touch) before going further"
  local check="$RAM/check.key"
  gpg --quiet --decrypt --output "$check" "$ROOT_KEY_ENC"
  cmp -s "$ROOT_KEY" "$check" || { echo "BACKUP MISMATCH, stop here" >&2; exit 1; }
  rm -f "$check"
  cp docs/doomsday/pki-RESTORE.md "$DOOMSDAY/pki/RESTORE.md"
  echo "Root key backup verified: $ROOT_KEY_ENC"
}

cmd_issue_docsign() {
  [[ -n "${ROOT_KEY:-}" && -f "$ROOT_KEY" ]] || load_root_key
  say "Generating RSA-3072 key ON the YubiKey in slot 9c (replaces what's there)"
  echo "This destroys the current 9c key. Signatures already made with it stay valid."
  pause "Plug in the YubiKey."
  ykman piv keys generate --algorithm RSA3072 --pin-policy ALWAYS --touch-policy ALWAYS \
    9c "$RAM/9c.pub"
  say "Creating a signing request with the new key (PIN + touch)"
  ykman piv certificates request 9c "$RAM/9c.pub" "$RAM/9c.csr" -s "CN=Benjamin Soyka"

  say "Exporting attestation"
  ykman piv keys attest 9c "$RAM/attest.pem"
  ykman piv certificates export f9 "$RAM/f9.pem"
  local a b
  a=$("$OPENSSL" x509 -in "$RAM/attest.pem" -noout -pubkey | "$OPENSSL" sha256)
  b=$("$OPENSSL" pkey -pubin -in "$RAM/9c.pub" | "$OPENSSL" sha256)
  [[ "$a" == "$b" ]] || { echo "attestation doesn't match generated key" >&2; exit 1; }
  "$OPENSSL" verify -partial_chain -CAfile "$RAM/f9.pem" "$RAM/attest.pem"

  say "Signing the certificate with the root"
  "$OPENSSL" ca -config "$CNF" -batch -notext -extensions v3_docsign \
    -subj "$SUBJ_DOCSIGN" -in "$RAM/9c.csr" -out "$RAM/leaf.pem"
  local serial
  serial=$("$OPENSSL" x509 -in "$RAM/leaf.pem" -noout -serial | cut -d= -f2)
  mkdir -p public/pki/certs public/pki/attestation
  cp "$RAM/leaf.pem"   "public/pki/certs/$serial.crt"
  cp "$RAM/leaf.pem"   public/pki/certs/docsign-current.crt
  cp "$RAM/attest.pem" "public/pki/attestation/$serial-attest.crt"
  cp "$RAM/f9.pem"     "public/pki/attestation/$serial-f9.crt"
  cp "$RAM/attest.pem" public/pki/attestation/docsign-current-attest.crt
  cp "$RAM/f9.pem"     public/pki/attestation/docsign-current-f9.crt

  say "Importing the certificate into slot 9c"
  ykman piv certificates import 9c "$RAM/leaf.pem"
  "$OPENSSL" x509 -in "$RAM/leaf.pem" -noout -subject -issuer -enddate -ext keyUsage,extendedKeyUsage
  echo "Issued serial $serial. Add a line to data/keys.toml history if you want it named."
}

cmd_crl() {
  [[ -n "${ROOT_KEY:-}" && -f "$ROOT_KEY" ]] || load_root_key
  say "Signing the revocation list (valid ~400 days)"
  "$OPENSSL" ca -config "$CNF" -gencrl -out "$RAM/root.crl.pem"
  der crl "$RAM/root.crl.pem" public/pki/root.crl
  "$OPENSSL" crl -in public/pki/root.crl -inform DER -noout -lastupdate -nextupdate
}

cmd_revoke() {
  local serial="${1:?serial}"
  load_root_key
  "$OPENSSL" ca -config "$CNF" -revoke "pki/ca/newcerts/$serial.pem" -crl_reason keyCompromise
  cmd_crl
}

cmd_notation() {
  local sha
  sha=$("$OPENSSL" x509 -in pki/ca/root.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)
  say "Adding root CA fingerprint to the PGP UID (needs the master key backup)"
  export GNUPGHOME="$RAM/gnupg"; mkdir -m 700 "$GNUPGHOME"
  gpg --quiet --import "$DOOMSDAY/pgp-keys/current-83D68D89/secret-master-$PGP_FPR.asc"
  gpg --quiet --import public/pgp/$PGP_FPR.asc   # bring in any newer public sigs
  cat <<EOF

In the gpg prompt that opens, type exactly:
  uid 1
  notation
  x509-root-sha256@bensoyka.com=$sha
  save
(You'll be asked for the master key passphrase.)
EOF
  pause "Ready?"
  gpg --edit-key "$PGP_FPR"
  gpg --armor --export "$PGP_FPR" > public/pgp/$PGP_FPR.asc
  cp public/pgp/$PGP_FPR.asc "$DOOMSDAY/pgp-keys/current-83D68D89/pub-$PGP_FPR.asc"
  gpg --list-sigs --list-options show-notations "$PGP_FPR" | grep -i notation || true
  unset GNUPGHOME
}

main() {
  local cmd="${1:-}"; shift || true
  check_offline
  ramdisk_up
  case "$cmd" in
    init-root)     cmd_init_root ;;
    issue-docsign) cmd_issue_docsign ;;
    crl)           cmd_crl ;;
    revoke)        cmd_revoke "$@" ;;
    notation)      cmd_notation ;;
    ceremony)      cmd_init_root; cmd_issue_docsign; cmd_crl; cmd_notation
                   cp docs/doomsday/pgp-keys-RESTORE.md "$DOOMSDAY/pgp-keys/RESTORE.md" ;;
    *) sed -n '2,10p' "$0"; exit 1 ;;
  esac
  say "Done. Turn Wi-Fi back on, then: make build sign deploy"
}
main "$@"
