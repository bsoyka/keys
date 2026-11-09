#!/usr/bin/env bash
# CA operations. macOS, run from the repo root with Wi-Fi off.
#
#   scripts/ca.sh ceremony            first-time setup: root, personal CA, 9c cert, CRLs, notation
#   scripts/ca.sh issue-docsign LABEL new on-device key in PIV slot 9c + cert from the personal CA,
#                                     for one YubiKey: LABEL is primary (USB-C) or backup (USB-A)
#   scripts/ca.sh issue-login LABEL   new on-device macOS login keys in 9a + 9d, certs from the
#                                     personal CA (then pair with sc_auth; docs/macos-login.md)
#   scripts/ca.sh yubikey LABEL       issue-docsign + issue-login for one YubiKey
#   scripts/ca.sh crl                 re-sign every CA's revocation list (yearly)
#   scripts/ca.sh revoke CA SERIAL [REASON]
#                                     revoke a cert issued by CA (root|personal), then re-sign CRLs;
#                                     REASON: keyCompromise (default), superseded, cessationOfOperation
#   scripts/ca.sh new-intermediate NAME "Common Name"
#                                     another CA under the root (needs a [NAME_ca] section in pki/openssl.cnf)
#   scripts/ca.sh notation            add the root fingerprint, the Keyoxide profile link and
#                                     data/notations.txt to the PGP key (needs the PGP master key);
#                                     safe to re-run
#   scripts/ca.sh asp-init            create the Keyoxide profile key and sign data/asp.toml (once)
#   scripts/ca.sh asp-sign            re-sign the Keyoxide profile after editing data/asp.toml
#   scripts/ca.sh paper               build the printable paper backup set (scripts/paper.py) on
#                                     the RAM disk, open it to print, then destroy it
#
# Hierarchy: Root CA (offline, signs only intermediates)
#            └─ Personal CA (offline, signs only my certs) └─ 9c document-signing cert
#
# Key decisions:
# - Plaintext CA keys only ever exist on a RAM disk that's destroyed on exit,
#   so they never touch the SSD, Time Machine or Spotlight.
# - CA keys at rest are encrypted to my PGP key (encryption subkey on the
#   YubiKey; the doomsday master backup can also decrypt them). Nothing extra
#   to memorize, and they're recoverable the same way as everything else.
# - Every new encrypted key is test-decrypted and compared before going on.
# - The 9c key is generated on the YubiKey and never exported; its attestation
#   is published so anyone can check that against Yubico's CA.

set -euo pipefail

PGP_FPR=BC4876BDC8AB5AB8C9CB81659497E30583D68D89
DOOMSDAY="${DOOMSDAY:-$HOME/doomsday}"
SUBJ_DOCSIGN="/CN=Benjamin Soyka/emailAddress=ben@bensoyka.com/C=US"
ROOT_DAYS=7305           # 20 years
INTERMEDIATE_DAYS=3653   # 10 years

export KEYS_REPO="$PWD"
CNF="$KEYS_REPO/pki/openssl.cnf"
[[ -f "$CNF" ]] || { echo "run from the repo root" >&2; exit 1; }

# Homebrew OpenSSL 3; macOS's /usr/bin/openssl is LibreSSL and lacks pieces we use.
OPENSSL="${OPENSSL:-$(brew --prefix openssl@3 2>/dev/null)/bin/openssl}"
[[ -x "$OPENSSL" ]] || { echo "brew install openssl@3" >&2; exit 1; }
for t in ykman gpg; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }; done
# The Python scripts need 3.11+ (tomllib) and macOS's own python3 is older, so
# run them through uv, which finds or downloads a new enough Python.
command -v uv >/dev/null || { echo "brew install uv" >&2; exit 1; }
py() { uv run --quiet --no-project --python '>=3.11' python3 "$@"; }

say()   { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pause() { read -r -p "$* [enter to continue] " _; }

pubname() { [[ "$1" == root ]] && echo root || echo "$1-ca"; }   # public/pki/<this>.crt/.crl
enc_path() {   # encrypted backup of a key in doomsday
  if [[ "$1" == asp ]]; then echo "$DOOMSDAY/pki/keyoxide-asp.key.asc"
  else echo "$DOOMSDAY/pki/$(pubname "$1").key.asc"; fi
}

check_offline() {
  if nc -z -G 3 1.1.1.1 443 >/dev/null 2>&1; then
    echo "This Mac can still reach the internet. Turn Wi-Fi off (and unplug Ethernet, quit VPNs) first." >&2
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
  [[ -d "$RAM/gnupg" ]] && GNUPGHOME="$RAM/gnupg" gpgconf --kill all 2>/dev/null || true
  hdiutil detach "$RAM" -force >/dev/null && echo "RAM disk destroyed."
  RAM=""
}

# Path of a CA's plaintext key on the RAM disk, decrypting it first if needed
# (YubiKey PIN + touch).
ca_key() {
  local name="$1" k="$RAM/$1.key"
  if [[ ! -f "$k" ]]; then
    [[ -f "$(enc_path "$name")" ]] || { echo "no $(enc_path "$name")" >&2; exit 1; }
    echo "Decrypting the $name key (YubiKey PIN + touch)…" >&2
    gpg --quiet --decrypt --output "$k" "$(enc_path "$name")"
    chmod 600 "$k"
  fi
  echo "$k"
}

# Encrypt a freshly generated CA key to the PGP key, then prove the backup opens.
backup_key() {
  local name="$1" k="$RAM/$1.key" out
  out="$(enc_path "$name")"
  mkdir -p "$DOOMSDAY/pki"
  [[ -e "$out" ]] && { echo "$out already exists; refusing to overwrite" >&2; exit 1; }
  gpg --batch --yes --trust-model always --armor -r "$PGP_FPR" --output "$out" --encrypt "$k"
  echo "Test-decrypting the $name backup (YubiKey PIN + touch)…"
  gpg --quiet --decrypt --output "$RAM/check.key" "$out"
  cmp -s "$k" "$RAM/check.key" || { echo "BACKUP MISMATCH for $name, stop here" >&2; exit 1; }
  rm -f "$RAM/check.key"
  echo "Backup verified: $out"
}

init_db() {
  local d="pki/ca/$1"
  mkdir -p "$d/newcerts"
  [[ -f "$d/index.txt" ]] || : > "$d/index.txt"
  [[ -f "$d/crlnumber" ]] || echo 01 > "$d/crlnumber"
}

der() { "$OPENSSL" "$1" -in "$2" -outform DER -out "$3"; }

cmd_init_root() {
  [[ -e pki/ca/root/cert.pem ]] && { echo "root already exists; refusing to overwrite" >&2; exit 1; }
  say "Creating the root CA (P-384, ${ROOT_DAYS} days)"
  init_db root
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$RAM/root.key"
  "$OPENSSL" req -config "$CNF" -new -x509 -key "$RAM/root.key" -sha384 -days "$ROOT_DAYS" \
    -set_serial "0x$("$OPENSSL" rand -hex 16)" -out pki/ca/root/cert.pem
  der x509 pki/ca/root/cert.pem public/pki/root.crt
  "$OPENSSL" x509 -in pki/ca/root/cert.pem -noout -subject -enddate -fingerprint -sha256
  backup_key root
  cp docs/doomsday/pki-RESTORE.md "$DOOMSDAY/pki/RESTORE.md"
}

cmd_new_intermediate() {
  local name="${1:?name}" cn="${2:?common name}"
  grep -q "^\[ ${name}_ca \]" "$CNF" || { echo "add a [ ${name}_ca ] section to $CNF first" >&2; exit 1; }
  [[ -e "pki/ca/$name/cert.pem" ]] && { echo "$name CA already exists" >&2; exit 1; }
  say "Creating the $name CA under the root"
  init_db "$name"
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$RAM/$name.key"
  "$OPENSSL" req -new -key "$RAM/$name.key" -subj "/CN=$cn/O=Benjamin Soyka/C=US" -out "$RAM/$name.csr"
  CA_KEY="$(ca_key root)" "$OPENSSL" ca -config "$CNF" -name root_ca -batch -notext \
    -extensions v3_intermediate -days "$INTERMEDIATE_DAYS" \
    -subj "/CN=$cn/O=Benjamin Soyka/C=US" -in "$RAM/$name.csr" -out "pki/ca/$name/cert.pem"
  der x509 "pki/ca/$name/cert.pem" "public/pki/$(pubname "$name").crt"
  "$OPENSSL" verify -CAfile pki/ca/root/cert.pem "pki/ca/$name/cert.pem"
  backup_key "$name"
}

one_yubikey() {   # sets serial_no to the single plugged-in YubiKey
  [[ $(ykman list --serials | wc -l) -eq 1 ]] || { echo "exactly one YubiKey must be plugged in" >&2; exit 1; }
  serial_no=$(ykman list --serials)
}

cmd_issue_login() {
  local label="${1:?primary or backup}" key serial_no s prof
  key="$(ca_key personal)"
  say "Issuing macOS login keys (9a + 9d) for the $label YubiKey"
  echo "Unpair macOS from this YubiKey first (sudo sc_auth unpair -u \$USER -h <hash>)."
  pause "Plug in ONLY the $label YubiKey."
  one_yubikey
  local Y=(ykman --device "$serial_no")
  for s in 9a 9d; do
    [[ $s == 9a ]] && prof=v3_login_auth || prof=v3_login_km
    # PIN once per session and touch cached for 15 s: login and unlock stay usable.
    "${Y[@]}" piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy CACHED \
      "$s" "$RAM/$s.pub"
    "${Y[@]}" piv certificates request "$s" "$RAM/$s.pub" "$RAM/$s.csr" -s "CN=Benjamin Soyka"
    CA_KEY="$key" "$OPENSSL" ca -config "$CNF" -name personal_ca -batch -notext \
      -extensions "$prof" -subj "/CN=Benjamin Soyka/emailAddress=ben@bensoyka.com/C=US" \
      -in "$RAM/$s.csr" -out "$RAM/$s.pem"
    "${Y[@]}" piv certificates import "$s" "$RAM/$s.pem"
    echo "  slot $s: serial $("$OPENSSL" x509 -in "$RAM/$s.pem" -noout -serial | cut -d= -f2)"
  done
  echo "Pair macOS after the ceremony: docs/macos-login.md"
}

cmd_issue_docsign() {
  local label="${1:?primary or backup}" key serial_no fw alg
  key="$(ca_key personal)"
  say "Issuing a document-signing cert for the $label YubiKey"
  echo "This replaces that YubiKey's slot 9c key. Signatures already made with it stay valid."
  pause "Plug in ONLY the $label YubiKey."
  one_yubikey
  # P-384: what macOS's built-in smart-card support (which Acrobat signs
  # through) can use; it can't sign with RSA-3072. Same curve as the CAs.
  alg=ECCP384
  fw=$(ykman info | awk -F': ' '/Firmware version/ {print $2}')
  echo "YubiKey $serial_no, firmware $fw: using $alg"
  local Y=(ykman --device "$serial_no")
  # PIN once per session, touch on every signature. PIN-every-time ("ALWAYS")
  # breaks signing through macOS's built-in smart-card support, which Acrobat
  # uses; the touch still means nothing signs without a finger on the key.
  "${Y[@]}" piv keys generate --algorithm "$alg" --pin-policy ONCE --touch-policy ALWAYS \
    9c "$RAM/9c.pub"
  say "Creating a signing request with the new key (PIN + touch)"
  "${Y[@]}" piv certificates request 9c "$RAM/9c.pub" "$RAM/9c.csr" -s "CN=Benjamin Soyka"

  say "Exporting attestation"
  "${Y[@]}" piv keys attest 9c "$RAM/attest.pem"
  "${Y[@]}" piv certificates export f9 "$RAM/f9.pem"
  local a b
  a=$("$OPENSSL" x509 -in "$RAM/attest.pem" -noout -pubkey | "$OPENSSL" sha256)
  b=$("$OPENSSL" pkey -pubin -in "$RAM/9c.pub" | "$OPENSSL" sha256)
  [[ "$a" == "$b" ]] || { echo "attestation doesn't match generated key" >&2; exit 1; }
  "$OPENSSL" verify -partial_chain -CAfile "$RAM/f9.pem" "$RAM/attest.pem"

  say "Signing the certificate with the personal CA"
  CA_KEY="$key" "$OPENSSL" ca -config "$CNF" -name personal_ca -batch -notext \
    -extensions v3_docsign -subj "$SUBJ_DOCSIGN" -in "$RAM/9c.csr" -out "$RAM/leaf.pem"
  "$OPENSSL" verify -CAfile pki/ca/root/cert.pem -untrusted pki/ca/personal/cert.pem "$RAM/leaf.pem"
  local serial
  serial=$("$OPENSSL" x509 -in "$RAM/leaf.pem" -noout -serial | cut -d= -f2)
  mkdir -p public/pki/certs public/pki/attestation
  cp "$RAM/leaf.pem"   "public/pki/certs/$serial.crt"
  cp "$RAM/leaf.pem"   "public/pki/certs/docsign-$label.crt"
  cp "$RAM/attest.pem" "public/pki/attestation/$serial-attest.crt"
  cp "$RAM/f9.pem"     "public/pki/attestation/$serial-f9.crt"
  cp "$RAM/attest.pem" "public/pki/attestation/docsign-$label-attest.crt"
  cp "$RAM/f9.pem"     "public/pki/attestation/docsign-$label-f9.crt"

  say "Importing the certificate into slot 9c"
  "${Y[@]}" piv certificates import 9c "$RAM/leaf.pem"
  "$OPENSSL" x509 -in "$RAM/leaf.pem" -noout -subject -issuer -enddate -ext keyUsage,extendedKeyUsage
  echo "Issued serial $serial."
}

cmd_crl() {
  local d name
  for d in pki/ca/*/; do
    name=$(basename "$d")
    [[ -f "$d/cert.pem" ]] || continue
    say "Signing the $name CA's revocation list (valid ~400 days)"
    CA_KEY="$(ca_key "$name")" "$OPENSSL" ca -config "$CNF" -name "${name}_ca" -gencrl -out "$RAM/$name.crl.pem"
    der crl "$RAM/$name.crl.pem" "public/pki/$(pubname "$name").crl"
    "$OPENSSL" crl -in "public/pki/$(pubname "$name").crl" -inform DER -noout -nextupdate
  done
}

cmd_revoke() {
  local ca="${1:?ca}" serial="${2:?serial}" reason="${3:-keyCompromise}"
  CA_KEY="$(ca_key "$ca")" "$OPENSSL" ca -config "$CNF" -name "${ca}_ca" \
    -revoke "pki/ca/$ca/newcerts/$serial.pem" -crl_reason "$reason"
  cmd_crl
}

cmd_asp_init() {
  [[ -e data/asp-public.json ]] && { echo "Keyoxide profile key already exists" >&2; exit 1; }
  say "Creating the Keyoxide profile key (Ed25519)"
  "$OPENSSL" genpkey -algorithm ed25519 -out "$RAM/asp.key"
  py scripts/asp.py init "$RAM/asp.key" "$OPENSSL"
  backup_key asp
  py scripts/asp.py sign "$RAM/asp.key" "$OPENSSL"
}

cmd_asp_sign() {
  py scripts/asp.py sign "$(ca_key asp)" "$OPENSSL"
  echo "Now: make sign deploy"
}

cmd_notation() {
  # Root CA fingerprint plus everything in data/notations.txt, on the primary UID.
  # Already-present notations are skipped, so this is safe to re-run (e.g. after
  # adding a Keyoxide proof). Scripted through gpg's command interface; the
  # passphrase still comes from pinentry.
  local want=() have
  if [[ -f pki/ca/root/cert.pem ]]; then
    want+=("x509-root-sha256@bensoyka.com=$("$OPENSSL" x509 -in pki/ca/root/cert.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)")
  fi
  if [[ -f data/asp-public.json ]]; then   # link the key to the Keyoxide profile
    want+=("proof@ariadne.id=$(py -c 'import json;print(json.load(open("data/asp-public.json"))["uri"])')")
  fi
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] || want+=("$line")
  done < data/notations.txt

  say "Updating notations on the PGP key (needs the master key backup)"
  export GNUPGHOME="$RAM/gnupg"; mkdir -m 700 "$GNUPGHOME"
  # Reuse the everyday pinentry (pinentry-mac) so the passphrase prompt appears.
  grep -h '^pinentry-program' "$HOME/.gnupg/gpg-agent.conf" > "$GNUPGHOME/gpg-agent.conf" 2>/dev/null || true
  gpg --quiet --import "$DOOMSDAY/pgp-keys/current-83D68D89/secret-master-$PGP_FPR.asc"
  gpg --quiet --import "public/pgp/$PGP_FPR.asc"   # bring in any newer public sigs
  have=$(gpg --list-options show-notations --list-sigs "$PGP_FPR" | sed -n 's/^ *Signature notation: //p')

  local cmds="uid 1"$'\n' n added=0
  for n in "${want[@]}"; do
    grep -qxF "$n" <<< "$have" && continue
    cmds+="notation"$'\n'"$n"$'\n'; added=$((added + 1)); echo "  + $n"
  done
  if (( added == 0 )); then echo "Nothing new to add."; unset GNUPGHOME; return; fi
  printf '%ssave\n' "$cmds" | gpg --batch --command-fd 0 --edit-key "$PGP_FPR" >/dev/null

  gpg --armor --export "$PGP_FPR" > "public/pgp/$PGP_FPR.asc"
  cp "public/pgp/$PGP_FPR.asc" "$DOOMSDAY/pgp-keys/current-83D68D89/pub-$PGP_FPR.asc"
  gpg --list-options show-notations --list-sigs "$PGP_FPR" | grep 'Signature notation' | sort -u
  echo "Publish the updated key: make sign deploy, then send it to keys.openpgp.org."
  unset GNUPGHOME
}

cmd_paper() {
  for t in paperkey qrencode zbarimg; do
    command -v "$t" >/dev/null || { echo "brew install ${t/zbarimg/zbar}" >&2; exit 1; }
  done
  local page
  page=$(py scripts/paper.py "$DOOMSDAY" "$RAM/paper")
  say "Print it: 2 copies of pages 1-4 (cover, master key, revocation, CA keys), 1 copy of page 5 (Proton)"
  echo "Safari: File > Print, Letter, scale 100%, no headers/footers. Don't save a PDF."
  open -a Safari "$page"
  pause "When the printer has finished,"
  osascript -e 'tell application "Safari" to close (every tab of every window whose URL contains "PKIRAM")' 2>/dev/null || true
  cancel -a -x 2>/dev/null || true   # drop any job data CUPS kept
}

main() {
  local cmd="${1:-}"; shift || true
  # Keyoxide profile edits don't touch a CA key, and printing needs the
  # (Wi-Fi) printer, so neither needs Wi-Fi off. Nothing paper prints is
  # usable without a passphrase or the PGP key.
  [[ "$cmd" == asp-sign || "$cmd" == paper ]] || check_offline
  ramdisk_up
  case "$cmd" in
    issue-docsign)    cmd_issue_docsign "$@" ;;
    issue-login)      cmd_issue_login "$@" ;;
    yubikey)          cmd_issue_docsign "$@"; cmd_issue_login "$@" ;;
    crl)              cmd_crl ;;
    revoke)           cmd_revoke "$@" ;;
    new-intermediate) cmd_new_intermediate "$@" ;;
    notation)         cmd_notation ;;
    asp-init)         cmd_asp_init ;;
    asp-sign)         cmd_asp_sign ;;
    paper)            cmd_paper; exit 0 ;;
    ceremony)
      cmd_init_root
      cmd_new_intermediate personal "Benjamin Soyka Personal CA"
      cmd_issue_docsign primary
      cmd_issue_login primary
      cmd_issue_docsign backup
      cmd_issue_login backup
      cmd_crl
      cmd_asp_init
      cmd_notation
      cp docs/doomsday/pgp-keys-RESTORE.md "$DOOMSDAY/pgp-keys/RESTORE.md" ;;
    *) sed -n '2,22p' "$0"; exit 1 ;;
  esac
  say "Done. Turn Wi-Fi back on, then: make sign deploy"
}
main "$@"
