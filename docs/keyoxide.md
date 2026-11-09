# Keyoxide

Keyoxide (https://keyoxide.org) links accounts and domains to the main PGP key.
Each link has two halves, and Keyoxide checks that they point at each other:

1. **On the key:** a notation `proof@ariadne.id=<where to look>`, listed in
   `data/notations.txt` and added by `scripts/ca.sh notation` (needs the master key;
   safe to re-run, it only adds what's missing).
2. **On the account:** something that names the key's fingerprint,
   `openpgp4fpr:bc4876bdc8ab5ab8c9cb81659497e30583d68d89`.

Keyoxide reads the key from keys.openpgp.org (or WKD), so after changing notations,
re-upload the key there (docs/restore.md § E).

Profile: https://keyoxide.org/BC4876BDC8AB5AB8C9CB81659497E30583D68D89
(or https://keyoxide.org/wkd/ben%40bensoyka.com).

## Current proofs

| Proof | Account side | Key side |
|---|---|---|
| bensoyka.com | apex TXT `openpgp4fpr:…` in bsoyka/infra | `proof@ariadne.id=dns:bensoyka.com?type=TXT` |
| bsoyka.me | apex TXT `openpgp4fpr:…` in bsoyka/infra | `proof@ariadne.id=dns:bsoyka.me?type=TXT` |

## Adding one

- **GitHub:** create a public gist named `openpgp.md` containing
  `[Verifying my OpenPGP key: openpgp4fpr:bc4876bdc8ab5ab8c9cb81659497e30583d68d89]`,
  then add `proof@ariadne.id=https://gist.github.com/bsoyka/<gist id>` to
  `data/notations.txt`.
- **Anything else** (Mastodon, Bluesky, Reddit, Hacker News, …): each service's
  instructions are at https://docs.keyoxide.org/service-providers/. Same pattern:
  fingerprint on the account, notation on the key.

Then `scripts/ca.sh notation`, `make sign deploy`, and re-upload to keys.openpgp.org.
Add the proof to the table above.
