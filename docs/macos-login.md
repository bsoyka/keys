# macOS login with a YubiKey

Slots 9a (signs the login challenge) and 9d (unwraps the login keychain) hold
on-device P-256 keys with certificates from the personal CA, made by
`scripts/ca.sh issue-login primary|backup` (part of the ceremony). PIN once per
session, touch cached for 15 seconds.

## Pairing (after the ceremony)

1. Unpair anything old: `sc_auth list`, then `sudo sc_auth unpair -u $USER -h <hash>`.
2. Plug in the primary YubiKey. macOS usually offers to pair; or run
   `sc_auth identities`, take the hash next to "PIV Authentication", and
   `sudo sc_auth pair -u $USER -h <hash>`. Enter your password when asked: that's
   what lets the new 9d key unlock the login keychain.
3. Pair the **backup** YubiKey the same way, then unpair and re-pair the **primary**
   last. Any paired card can log in, but only the most recently paired one also
   unlocks the login keychain (found 2026-11-09). With the primary paired last it
   does everything with just the PIN; the backup logs in but asks for the password
   once to unlock the keychain.
4. Lock the screen and unlock with the YubiKey to test.

## If a password prompt still appears after the PIN

The old setup had this. Likely causes, in order:

- **Another card was paired after this one.** Only the last-paired card unlocks
  the keychain; re-pair the one you use day to day (step 3).
- **Keychain not unlocked by the card.** The old 9d certificate was a bare
  self-signed one without Key Agreement, which macOS needs to use an EC key to
  unwrap the keychain. The new 9d cert has it. Re-pair (step 1–2) if it persists.
- **FileVault.** The first login after a restart unlocks the disk, and that always
  takes the password. Smart-card unlock applies after that (screen lock, logout).
- **Keychain password differs from login password.** Keychain Access → Change
  Password for Keychain "login", set it to the login password.

## Undo

`sudo sc_auth unpair -u $USER -h <hash>` for each paired YubiKey. The password always
keeps working either way.
