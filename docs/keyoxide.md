# Keyoxide

Keyoxide (https://keyoxide.org) shows, and checks live, that my domains and
accounts belong to me. My profile is an ASP (Ariadne Signature Profile): a small
file signed with its own Ed25519 key and served from this site, so editing it
never needs the PGP master key.

- Profile source: `data/asp.toml` (name, description, claims)
- Public key and identifier: `data/asp-public.json` (created by `scripts/ca.sh asp-init`)
- Signed profile: `public/.well-known/aspe/id/<fingerprint>`
- Identifier: `aspe:keys.bensoyka.com:<fingerprint>`
- Private key: `~/doomsday/pki/keyoxide-asp.key.asc`, encrypted to my PGP key

Every link has two halves that point at each other: a **claim** in the profile, and
a **proof** on the account that contains the profile's identifier. The PGP key is
linked both ways too: the profile claims `openpgp4fpr:bc48…`, and the key carries a
`proof@ariadne.id=aspe:keys.bensoyka.com:<fp>` notation (added once by
`scripts/ca.sh notation`).

## Current links

| Account | Claim in data/asp.toml | Proof on the account |
|---|---|---|
| Main PGP key | `openpgp4fpr:bc4876bdc8ab5ab8c9cb81659497e30583d68d89` | notation on the key (automatic) |
| bensoyka.com | `dns:bensoyka.com?type=TXT` | apex TXT `aspe:keys.bensoyka.com:<fp>`, in bsoyka/infra |
| bsoyka.me | `dns:bsoyka.me?type=TXT` | apex TXT `aspe:keys.bensoyka.com:<fp>`, in bsoyka/infra |
| GitHub | `https://gist.github.com/bsoyka/cba00e8777bcccad246129bcb2e7e15d` | public gist with `proof.md` |

## Setting up GitHub

1. Create a **public** gist with one file named `proof.md` containing:
   `[Verifying my Keyoxide profile: aspe:keys.bensoyka.com:<fp>]`
2. Uncomment the gist line in `data/asp.toml` with the gist's ID.
3. `scripts/ca.sh asp-sign`, then `make sign deploy`.

## Adding, changing or removing a link

1. Edit `claims` in `data/asp.toml`. Each service's claim format and proof
   location: https://docs.keyoxide.org/wiki/for-service-providers/
2. Put the proof on the account (it must contain `aspe:keys.bensoyka.com:<fp>`).
3. `scripts/ca.sh asp-sign` (YubiKey touch to decrypt the profile key; Wi-Fi can
   stay on), then `make sign deploy`.

Removing a claim works the same way and leaves nothing behind on the PGP key.

## If the profile key is lost or exposed

Make a new one (move `data/asp-public.json` aside, `scripts/ca.sh asp-init`). The
identifier changes, so update every account proof and the DNS TXT records, run
`scripts/ca.sh notation` to point the PGP key at the new identifier, and note the
old identifier as retired in `data/keys.toml`.
