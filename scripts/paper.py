#!/usr/bin/env python3
"""Printable paper backups: build one HTML page set from ~/doomsday + this repo.

Usage (via scripts/ca.sh paper, which runs this on a RAM disk):
  python3 scripts/paper.py DOOMSDAY_DIR OUT_DIR

Sheets:
  0. Cover: what this set is, public identifiers, checksums of every sheet
  1. PGP master key (paperkey: only the secret parts, still passphrase-protected)
  2. PGP revocation certificate
  3. CA and Keyoxide keys (each already encrypted to the PGP key)
  4. Proton access (blank lines, filled in by hand; never printed with values)
  5. My copy (A-2) of the split-key letter, if the private bsoyka/sirloin repo is
     at $SIRLOIN_DIR (default ~/personal/sirloin). With a third argument
     "letters", letters.html also gets the friends' letters, their outer envelope
     notes, and their key cards with labels for the small sealed inner envelopes.

The letter template lives in bsoyka/sirloin, not here, because it has personal
details (family phone numbers, friends' names) and this repo is public.

Key decisions:
- Nothing printed is usable on its own: the master key needs its memorized
  passphrase, the CA keys need the PGP key, and the Proton login is written by
  hand. The worst thing on these pages (and in the Wi-Fi printer's path) is the
  revocation certificate, which can only revoke.
- The age paper key is deliberately not part of this set; it stays a separate,
  separately stored piece of paper.
- Every block is printed twice: as a QR code and as text to type in, with a
  short SHA-256 to confirm either way that what came back is right. paperkey's
  text form also has a checksum on every line.
- Each QR code is decoded again with zbarimg (when installed) before anything
  is written, so a bad code is caught on screen rather than in a disaster.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import html
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PGP_FPR = "BC4876BDC8AB5AB8C9CB81659497E30583D68D89"
e = html.escape


def run(*args: str, input: bytes | None = None) -> bytes:
    return subprocess.run(args, input=input, capture_output=True, check=True).stdout


def short_sha(data: bytes) -> str:
    h = hashlib.sha256(data).hexdigest()[:16].upper()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def group4(s: str) -> str:
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4))


def qr_svg(payload: str) -> str:
    payload = payload.rstrip("\n")  # zbarimg adds one trailing newline of its own
    svg = run("qrencode", "-t", "SVG", "-l", "M", "-m", "2", "--svg-path", "-o", "-",
              input=payload.encode()).decode()
    if shutil.which("zbarimg"):  # round-trip check
        with tempfile.TemporaryDirectory() as d:
            png = Path(d) / "q.png"
            run("qrencode", "-t", "PNG", "-l", "M", "-s", "6", "-o", str(png), input=payload.encode())
            back = run("zbarimg", "--raw", "-q", str(png)).decode().rstrip("\n")
            if back != payload:
                sys.exit("QR round-trip failed; not printing")
    return svg[svg.index("<svg"):]


def block(label: str, text: str, qr_payload: str, digest_of: bytes) -> str:
    return f"""<section class="block">
  <h3>{e(label)} <span class="sha">SHA-256 {short_sha(digest_of)}…</span></h3>
  <div class="pair"><div class="qr">{qr_svg(qr_payload)}</div>
  <pre class="text">{e(text.strip())}</pre></div>
</section>"""


def sheet(title: str, keep: str, body: str) -> str:
    return f"""<article class="sheet">
<header><span>Ben Soyka · {e(title)}</span><span>printed {datetime.date.today()}</span></header>
<p class="keep"><b>Keep:</b> {keep}</p>
{body}
</article>"""


def main() -> None:
    doomsday, out = Path(sys.argv[1]), Path(sys.argv[2])
    for t in ("gpg", "paperkey", "qrencode"):
        if not shutil.which(t):
            sys.exit(f"missing {t} (brew install {'gnupg' if t == 'gpg' else t})")
    pgpdir = doomsday / "pgp-keys" / "current-83D68D89"
    pki = doomsday / "pki"
    sheets: list[tuple[str, str, bytes]] = []  # (title, html, digest source) for the cover

    # 1. PGP master key
    binary = run("gpg", "--dearmor", input=(pgpdir / f"secret-master-{PGP_FPR}.asc").read_bytes())
    raw = run("paperkey", "--output-type", "raw", input=binary)
    text = run("paperkey", "--output-type", "base16", input=binary).decode()
    b64 = base64.b64encode(raw).decode()
    sheets.append(("PGP master key", sheet("PGP master key", "fireproof folder (apartment) and El Paso. Never with friends.", f"""
<h2>PGP master key {group4(PGP_FPR)[-19:]}</h2>
<p>The secret parts of my main PGP key, extracted with <code>paperkey</code>. They're
still protected by the key's passphrase, which is memorized only. Rebuilding the key
also needs the public key, from keys.bensoyka.com/pgp.asc or keys.openpgp.org.</p>
{block("Secret key data (QR: base64 of paperkey raw output)", text, b64, raw)}
<h3>Restore</h3>
<pre class="cmd">curl -s https://keys.bensoyka.com/pgp.asc | gpg --dearmor &gt; pub.gpg
# from the QR code (photo or scan saved as scan.png):
zbarimg --raw -q scan.png | base64 -d &gt; secrets.bin
paperkey --pubring pub.gpg --secrets secrets.bin --input-type raw | gpg --import
# or type the text into secrets.txt (each line's last 6 characters are a checksum):
paperkey --pubring pub.gpg --secrets secrets.txt | gpg --import</pre>
<p class="fine">Then follow restore.md in github.com/bsoyka/keys. Reprint this sheet
whenever the key gets a new subkey.</p>"""), raw))

    # 2. Revocation certificate
    rev = (pgpdir / f"secret-revoke-{PGP_FPR}.asc").read_text()
    sheets.append(("PGP revocation certificate", sheet("PGP revocation certificate",
        "fireproof folder (apartment) and El Paso. Not with friends.", f"""
<h2>Revocation certificate for {group4(PGP_FPR)}</h2>
<p>Revokes my main PGP key: anyone who imports this and publishes the key tells the
world to stop trusting it. It can't sign, decrypt or impersonate anything. Use it
only if I've lost the key and its backups, or the key was compromised.</p>
{block("Revocation certificate", rev, rev, rev.encode())}
<h3>Use</h3>
<pre class="cmd"># if a line starts with ":-----BEGIN", delete that leading colon first
gpg --import revoke.asc
gpg --keyserver hkps://keys.openpgp.org --send-keys {PGP_FPR}</pre>
<p class="fine">Then mark the key revoked in data/keys.toml in github.com/bsoyka/keys
and redeploy keys.bensoyka.com.</p>"""), rev.encode()))

    # 3. CA + Keyoxide keys (already PGP-encrypted)
    blocks = []
    digest = b""
    for name, label in (("root.key.asc", "Root CA key"), ("personal-ca.key.asc", "Personal CA key"),
                        ("keyoxide-asp.key.asc", "Keyoxide profile key")):
        data = (pki / name).read_text()
        digest += data.encode()
        blocks.append(block(f"{label} ({name})", data, data, data.encode()))
    sheets.append(("CA and Keyoxide keys", sheet("CA and Keyoxide keys",
        "fireproof folder (apartment) and El Paso.", f"""
<h2>Certificate authority and Keyoxide keys</h2>
<p>Each is encrypted to my main PGP key, so it's useless without that key (from the
YubiKey or the master key sheet). Decrypt only onto a RAM disk; see scripts/ca.sh.</p>
{''.join(blocks)}
<pre class="cmd">gpg --decrypt root.key.asc &gt; /Volumes/PKIRAM/root.key</pre>"""), digest))

    # 4. Proton access (blank)
    line = '<div class="blank"></div>'
    sheets.append(("Proton access", sheet("Proton access",
        "one copy, fireproof folder (apartment). <b>Never in the same place as the paper age key.</b>", f"""
<h2>Proton account (Sirloin backup location)</h2>
<p>Fill this in by hand; it was printed blank on purpose. This login has never been in
my password manager, so it still works if that's gone. With it, anyone can download
my encrypted backups, but not decrypt them without one of the age keys.</p>
<dl class="form"><dt>Email</dt><dd>{line}</dd><dt>Password</dt><dd>{line}{line}</dd>
<dt>Recovery phrase</dt><dd>{line * 4}</dd><dt>2FA backup codes</dt><dd>{line * 3}</dd>
<dt>Last checked</dt><dd>{line}</dd></dl>
<p class="fine">Files: doomsday.tar.gz.age and vault.tar.gz.age in Proton Drive's root.
Decrypt: <code>age -d -i KEY doomsday.tar.gz.age | tar xz</code></p>"""), None))

    # 5. Split-key letters (templates and copies from the private sirloin repo).
    # My copy keeps its half in a handwritten box on the letter (it lives in the
    # fireproof folder with this set). Friends' letters can be read any time; their
    # half goes on a card in a small sealed envelope inside, so a disturbed seal
    # shows if it was looked at.
    letters: list[str] = []
    sirloin = Path(os.environ.get("SIRLOIN_DIR", Path.home() / "personal" / "sirloin")) / "letter"
    if (sirloin / "letter.html").exists():
        today = str(datetime.date.today())

        def tpl(name: str) -> str | None:
            f = sirloin / name
            if not f.exists():
                return None
            t = f.read_text()
            return t[t.index("-->") + 3:] if t.lstrip().startswith("<!--") else t

        def fill(t: str, c: dict, **extra: str) -> str:
            for k, v in {"COPY": c["id"], "HALF": c["half"], "UPDATED": today,
                         "TO": e(c.get("to", c["holder"])), **extra}.items():
                t = t.replace("{{" + k + "}}", v)
            return t

        letter, outer, inner = tpl("letter.html"), tpl("envelope.html"), tpl("inner.html")
        copies = tomllib.loads((sirloin / "copies.toml").read_text())["copy"]
        friends = [c for c in copies if not c.get("mine")]
        col = lambda h: "".join(f"<li>{e(c['holder'])} ({c['id']})</li>" for c in copies if c["half"] == h)  # noqa: E731
        table = (f'<table class="halves"><tr><th>Has the first half</th><th>Has the second half</th></tr>'
                 f'<tr><td><ul>{col("first")}</ul></td><td><ul>{col("second")}</ul></td></tr></table>')
        for c in copies:
            keypart = (f'<div class="keybox"><span>{c["half"]} half, written by hand</span></div>' if c.get("mine")
                       else f'<p class="keyptr">Your half is on a card in the <b>small sealed envelope</b> inside, '
                            f'labeled {c["id"]}. Keep it sealed until it\'s needed.</p>')
            body = fill(letter, c, TABLE=table, KEYPART=keypart)
            if c.get("mine"):
                sheets.append((f"Split-key letter, my copy ({c['id']})", sheet(
                    f"Split-key letter ({c['id']})",
                    f"one copy, fireproof folder (apartment) only. Write the {c['half']} half in by hand, "
                    "then cover it. <b>Not in the El Paso set.</b>",
                    f'<div class="letter">{body}</div>'), None))
            else:
                letters.append(f'<article class="sheet letter">{body}</article>')
        if outer:  # outer envelope notes, three to a page
            letters.append('<article class="sheet envelopes">'
                           + "".join(f'<div class="env">{fill(outer, c)}</div>' for c in friends) + "</article>")
        if inner:  # per friend: the key card, and the label for the small envelope it goes in
            rows = "".join(
                f'<div class="inner-row"><div class="slip"><p class="env-to">Copy {c["id"]} <span>{c["half"]} half · {today}</span></p>'
                f'<div class="keybox"><span>{c["half"]} half, written by hand</span></div>'
                f'<p class="fine">Join with the other half as the letter explains. Useless on its own.</p></div>'
                f'<div class="label">{fill(inner, c)}</div></div>' for c in friends)
            letters.append(f'<article class="sheet inners">{rows}</article>')
    else:
        print(f"note: no letter template at {sirloin}; skipping the split-key letter", file=sys.stderr)

    # 0. Cover
    # root.crt is published as DER; hash the bytes directly (no openssl variant quirks).
    h = hashlib.sha256((ROOT / "public/pki/root.crt").read_bytes()).hexdigest().upper()
    root_sha = ":".join(h[k:k + 2] for k in range(0, 64, 2))
    ages = [l.strip() for l in (ROOT / "public/age/backups.txt").read_text().splitlines() if l.startswith("age1")]
    rows = "".join(f"<tr><td>{i}</td><td>{e(t)}</td><td><code>{short_sha(d) if d is not None else 'handwritten'}</code></td></tr>"
                   for i, (t, _, d) in enumerate(sheets, 1))
    cover = sheet("Paper backup set", "with every copy of this set.", f"""
<h2>Paper backup set</h2>
<p>Printed copies of what's needed to recover my keys if every computer, hardware
key and cloud account is gone. Each sheet is explained on its face. Everything here
also lives, digitally, in my encrypted backups; full details are at
<b>keys.bensoyka.com</b> and <b>github.com/bsoyka/keys</b> (docs/restore.md).</p>
<p><b>If someone other than me is reading this:</b> please keep it safe and don't
use it unless I've asked you to.</p>
<h3>Sheets</h3>
<table><tr><th>#</th><th>Sheet</th><th>Checksum (SHA-256, first 16)</th></tr>{rows}</table>
<h3>Public identifiers (to check against)</h3>
<dl class="ids">
<dt>Main PGP key</dt><dd><code>{group4(PGP_FPR)}</code></dd>
<dt>Root CA SHA-256</dt><dd><code>{e(root_sha)}</code></dd>
<dt>Backup age keys</dt><dd>{'<br>'.join(f'<code>{k[:15]}…{k[-8:]}</code>' for k in ages)}</dd>
</dl>
<p class="fine">Reprint this set when a key changes, and check it yearly: inkjet
fades and runs when wet, so keep the pages in plastic sleeves.</p>""")

    out.mkdir(parents=True, exist_ok=True)
    page = out / "paper.html"
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Paper backup set</title>
<style>
@page {{ size: letter; margin: 0.55in; }}
body {{ font: 10.5pt/1.4 -apple-system, "Helvetica Neue", sans-serif; color: #000; margin: 0; }}
.sheet {{ break-after: page; }}
.sheet:last-child {{ break-after: auto; }}
header {{ display: flex; justify-content: space-between; font-size: 8.5pt; border-bottom: 1px solid #000; padding-bottom: 3pt; }}
h2 {{ font-size: 15pt; margin: 10pt 0 4pt; }} h3 {{ font-size: 11pt; margin: 10pt 0 3pt; }}
.keep {{ font-size: 9pt; border: 1px solid #000; padding: 3pt 6pt; }}
code, pre {{ font-family: "JetBrains Mono", Menlo, monospace; }}
pre {{ font-size: 7.6pt; line-height: 1.3; white-space: pre-wrap; word-break: break-all; margin: 0; }}
.pair {{ display: flex; gap: 12pt; align-items: flex-start; break-inside: avoid; }}
.qr svg {{ width: 2.1in; height: 2.1in; }}
.text {{ flex: 1; }}
.block {{ break-inside: avoid; }}
.sha {{ font-weight: 400; font-size: 8.5pt; font-family: Menlo, monospace; }}
.cmd {{ border-left: 2px solid #000; padding-left: 6pt; font-size: 8.2pt; }}
.fine {{ font-size: 8.5pt; }}
table {{ border-collapse: collapse; width: 100%; }} td, th {{ border-bottom: 1px solid #999; text-align: left; padding: 3pt; font-size: 9.5pt; }}
dl.ids dt, dl.form dt {{ font-weight: 600; margin-top: 6pt; }} dl.ids dd, dl.form dd {{ margin: 0; }}
.blank {{ border-bottom: 1px solid #000; height: 26pt; }}
.letter {{ font-size: 9.5pt; line-height: 1.22; }}
.letter h2 {{ font-size: 13pt; margin: 3pt 0; }} .letter h3 {{ font-size: 10.5pt; margin: 7pt 0 2pt; }}
.letter p, .letter ul, .letter ol {{ margin: 3pt 0; }} .letter li {{ margin: 1pt 0; }}
.letter pre {{ font-size: 8.5pt; margin: 3pt 0; }}
.eyebrow {{ font-size: 8.5pt; margin: 0; }}
.urls code {{ font-size: 9pt; }}
.keybox {{ border: 1.5px dashed #000; height: 0.75in; margin: 5pt 0; position: relative; }}
.keybox span {{ position: absolute; left: 6pt; top: 3pt; font-size: 7.5pt; }}
table.halves th, table.halves td {{ border: 1px solid #000; width: 50%; vertical-align: top; }}
table.halves ul {{ margin: 0; padding-left: 14pt; }}
.envelopes .env {{ border: 1px dashed #000; height: 2.25in; padding: 10pt 14pt; margin-bottom: 0.12in; box-sizing: border-box; font-size: 9.5pt; line-height: 1.3; }}
.env p {{ margin: 3pt 0; }}
.env-to {{ font-size: 13pt; font-weight: 700; display: flex; justify-content: space-between; }}
.env-to span {{ font-size: 8pt; font-weight: 400; }}
.keyptr {{ border-left: 3px solid #000; padding-left: 6pt; }}
.inner-row {{ display: flex; gap: 0.15in; margin-bottom: 0.15in; }}
.slip, .label {{ border: 1px dashed #000; width: 3.5in; height: 2.9in; padding: 8pt 10pt; box-sizing: border-box; font-size: 8.5pt; line-height: 1.3; }}
.slip .keybox {{ height: 1.3in; }} .label p, .slip p {{ margin: 3pt 0; }}
@media screen {{ body {{ max-width: 7.4in; margin: 20px auto; }} .sheet {{ border-bottom: 3px dashed #999; padding-bottom: 20px; margin-bottom: 20px; }} }}
</style></head><body>
<!--BODY-->
</body></html>
"""
    page.write_text(html_doc.replace("<!--BODY-->", cover + "".join(h for _, h, _ in sheets)))
    if len(sys.argv) > 3 and sys.argv[3] == "letters" and letters:
        (out / "letters.html").write_text(html_doc.replace("<!--BODY-->", "".join(letters)))
        print(out / "letters.html")
    print(page)


if __name__ == "__main__":
    main()
