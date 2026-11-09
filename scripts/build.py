#!/usr/bin/env python3
"""Generate everything derived from data/keys.toml + the key/cert files.

Outputs (all deterministic, safe to re-run):
  build/keys.txt                      unsigned manifest (make sign clearsigns it into public/)
  public/index.html                   human-readable page
  public/ssh.txt                      SSH public key from the PGP auth subkey
  public/pgp.asc                      stable alias for the current primary key
  public/.well-known/openpgpkey/...   WKD (advanced method, served on openpgpkey.<domain>)

Key decision: fingerprints are always computed from the files with gpg/openssl,
never typed, so the manifest can't drift from what's actually published.
Stdlib only (Python 3.11+), so it runs with plain `python3` or `uv run`.
"""

from __future__ import annotations

import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
BUILD = ROOT / "build"

# ------------------------------------------------------------------ helpers


def run(*args: str, env: dict | None = None, input: bytes | None = None) -> str:
    out = subprocess.run(args, check=True, capture_output=True, env=env, input=input)
    return out.stdout.decode()


def group4(fp: str) -> str:
    """BC4876BD... -> 'BC48 76BD ... ' with the usual double space in the middle."""
    parts = [fp[i : i + 4] for i in range(0, len(fp), 4)]
    half = len(parts) // 2
    return " ".join(parts[:half]) + "  " + " ".join(parts[half:])


def zbase32(data: bytes) -> str:
    alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(alphabet[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))


def wkd_hash(local_part: str) -> str:
    return zbase32(hashlib.sha1(local_part.lower().encode()).digest())


CAPS = {"s": "Sign", "e": "Encrypt", "a": "Auth", "c": "Certify"}

# ------------------------------------------------------------------ PGP


@dataclass
class SubKey:
    fpr: str
    algo: str
    caps: str
    created: str
    expires: str | None


@dataclass
class PgpKey:
    meta: dict
    fpr: str = ""
    algo: str = ""
    created: str = ""
    expires: str | None = None
    revoked: str | None = None
    uids: list[tuple[str, bool]] = field(default_factory=list)  # (uid, revoked)
    subkeys: list[SubKey] = field(default_factory=list)


ALGOS = {"1": "rsa", "18": "cv25519", "19": "ecdsa", "22": "ed25519"}


def ts(s: str) -> str | None:
    if not s:
        return None
    import datetime as dt

    return dt.datetime.fromtimestamp(int(s), dt.UTC).strftime("%Y-%m-%d")


def load_pgp(meta: dict, gnupghome: str) -> PgpKey:
    path = PUBLIC / meta["file"]
    env = {**os.environ, "GNUPGHOME": gnupghome}
    run("gpg", "--batch", "--quiet", "--import", str(path), env=env)
    fp_from_name = path.stem
    colons = run(
        "gpg", "--batch", "--with-colons", "--fixed-list-mode",
        "--list-keys", fp_from_name, env=env,
    )
    human = run("gpg", "--batch", "--list-keys", fp_from_name, env=env)
    key = PgpKey(meta=meta)
    current: PgpKey | SubKey | None = None
    for line in colons.splitlines():
        f = line.split(":")
        if f[0] == "pub":
            key.algo = ALGOS.get(f[3], f[3]) + (f[2] if f[3] == "1" else "")
            key.created, key.expires = ts(f[5]), ts(f[6])
            current = key
        elif f[0] == "sub":
            sk = SubKey("", ALGOS.get(f[3], f[3]) + (f[2] if f[3] == "1" else ""),
                        f[11].lower(), ts(f[5]), ts(f[6]))
            key.subkeys.append(sk)
            current = sk
        elif f[0] == "fpr" and current is not None and not current.fpr:
            current.fpr = f[9]
        elif f[0] == "uid":
            uid = re.sub(r"\\x([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), f[9])
            key.uids.append((uid, f[1] == "r"))
    m = re.search(r"^pub .*\[revoked: (\d{4}-\d{2}-\d{2})\]", human, re.M)
    key.revoked = m.group(1) if m else None
    if key.fpr != fp_from_name:
        sys.exit(f"{path}: file name doesn't match fingerprint {key.fpr}")
    return key


# ------------------------------------------------------------------ X.509


@dataclass
class Cert:
    meta: dict
    present: bool
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    sha256: str = ""
    sha1: str = ""


def readable_dn(rfc2253: str) -> str:
    """'C=US,emailAddress=x@y,CN=Name' -> 'Name <x@y>' (country dropped: it's always US)."""
    parts = dict(p.split("=", 1) for p in re.split(r"(?<!\\),", rfc2253))
    out = parts.get("CN", rfc2253)
    return out + (f" <{parts['emailAddress']}>" if "emailAddress" in parts else "")


def iso(openssl_date: str) -> str:
    import datetime as dt

    return dt.datetime.strptime(openssl_date, "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")


def load_cert(meta: dict) -> Cert:
    path = PUBLIC / meta["file"]
    if not path.exists():
        return Cert(meta, present=False)
    p = str(path)
    # root.crt is DER (what the AIA URL serves); other certs are PEM.
    fmt = "PEM" if path.read_bytes().startswith(b"-----BEGIN") else "DER"

    def x(*a: str) -> str:
        return run("openssl", "x509", "-inform", fmt, "-in", p, "-noout", *a).strip()

    fp = lambda alg: x("-fingerprint", f"-{alg}").split("=", 1)[1]  # noqa: E731
    return Cert(
        meta,
        present=True,
        subject=readable_dn(x("-subject", "-nameopt", "RFC2253").split("=", 1)[1]),
        issuer=readable_dn(x("-issuer", "-nameopt", "RFC2253").split("=", 1)[1]),
        serial=x("-serial").split("=", 1)[1],
        not_before=iso(x("-startdate").split("=", 1)[1]),
        not_after=iso(x("-enddate").split("=", 1)[1]),
        sha256=fp("sha256"),
        sha1=fp("sha1"),
    )


# ------------------------------------------------------------------ outputs


def write_wkd(key: PgpKey, gnupghome: str, domain: str, local: str, email: str) -> None:
    env = {**os.environ, "GNUPGHOME": gnupghome}
    base = PUBLIC / ".well-known" / "openpgpkey" / domain
    if base.exists():
        shutil.rmtree(base)
    (base / "hu").mkdir(parents=True)
    (base / "policy").write_text("")  # required to exist; empty = defaults
    data = subprocess.run(
        ["gpg", "--batch", "--export", "--export-options", "export-minimal",
         "--export-filter", f"keep-uid=mbox = {email}", key.fpr],
        check=True, capture_output=True, env=env,
    ).stdout
    (base / "hu" / wkd_hash(local)).write_bytes(data)


def ssh_line(fpr: str, gnupghome: str) -> str:
    env = {**os.environ, "GNUPGHOME": gnupghome}
    return run("gpg", "--batch", "--export-ssh-key", fpr + "!", env=env).strip()


def indent(text: str, n: int = 2) -> str:
    return "\n".join(" " * n + l if l else "" for l in text.strip().splitlines())


def manifest(cfg, pgp: list[PgpKey], root: Cert, certs: list[Cert], ssh: str) -> str:
    o = cfg["owner"]
    site = o["site"]
    primary = next(k for k in pgp if k.meta.get("alias"))
    L: list[str] = []
    a = L.append
    a(f"Key manifest: {o['name']} <{o['email']}>")
    a(f"{site}/keys.txt")
    a("")
    a("This file is clearsigned with my primary PGP key:")
    a(f"  {group4(primary.fpr)}")
    a("It is the authoritative list of my keys and certificates. If something")
    a("claims to be my key and isn't listed here as current, don't trust it.")
    a("The signature date is the date of this version.")
    a("")

    def pgp_block(k: PgpKey) -> None:
        a(f"[PGP] {k.meta['title']}")
        a(f"  Fingerprint: {group4(k.fpr)}")
        status = f"revoked {k.revoked}" if k.revoked else k.meta["status"]
        a(f"  Type:        {k.algo}, created {k.created}" + (f", expires {k.expires}" if k.expires else "") + f" ({status})")
        for uid, rev in k.uids:
            a(f"  UID:         {uid}" + ("  [revoked]" if rev else ""))
        for s in k.subkeys:
            caps = "/".join(CAPS[c] for c in s.caps if c in CAPS)
            a(f"  Subkey:      {s.fpr}  {caps}, {s.algo}" + (f", expires {s.expires}" if s.expires else ""))
        a(f"  Download:    {site}/{k.meta['file']}")
        if k.meta.get("alias"):
            a(f"               {site}/{k.meta['alias']}")
        if k.meta.get("wkd"):
            a(f"  Lookup:      gpg --locate-keys {k.meta['wkd']}   (WKD)")
        a(indent(k.meta["use"]))
        a("")

    def cert_block(c: Cert, label: str) -> None:
        a(f"[{label}] {c.meta.get('title', 'Root CA')}")
        if not c.present:
            a("  (not issued yet)")
            a("")
            return
        a(f"  Subject:     {c.subject}")
        if c.issuer != c.subject:
            a(f"  Issuer:      {c.issuer}")
        a(f"  Serial:      {c.serial}")
        a(f"  Valid:       {c.not_before} to {c.not_after}")
        a(f"  SHA-256:     {c.sha256}")
        a(f"  SHA-1:       {c.sha1}   (what Acrobat shows)")
        a(f"  Download:    {site}/{c.meta['file']}")
        for k in ("attestation", "attestation_intermediate"):
            if c.meta.get(k) and (PUBLIC / c.meta[k]).exists():
                a(f"  {'Attestation:' if k == 'attestation' else '  via f9:'}  {site}/{c.meta[k]}")
        a(indent(c.meta.get("use", "")))
        a("")

    a("=" * 70)
    a("CURRENT")
    a("=" * 70)
    a("")
    for k in pgp:
        if k.meta["status"] == "current":
            pgp_block(k)
    a("[SSH] Authentication subkey of the primary PGP key")
    a(f"  {ssh}")
    a(f"  Download:    {site}/ssh.txt")
    a("")
    root_meta = {"file": cfg["pki"]["root"], "title": "Personal root CA", "use": cfg["pki"]["root_use"]}
    cert_block(root, "X.509 ROOT")
    if root.present:
        a(f"  Revocation list: {site}/{cfg['pki']['crl']}")
        a("")
    for c in certs:
        if c.meta["status"] == "current":
            cert_block(c, "X.509")

    a("=" * 70)
    a("RETIRED OR REVOKED (history only; don't encrypt to or newly trust)")
    a("=" * 70)
    a("")
    for k in pgp:
        if k.meta["status"] == "revoked":
            pgp_block(k)
    for c in certs:
        if c.meta["status"] == "retired":
            cert_block(c, "X.509")

    a("=" * 70)
    a("COMPROMISED (do not trust anything signed by these)")
    a("=" * 70)
    a("")
    for c in certs:
        if c.meta["status"] == "compromised":
            cert_block(c, "X.509")

    a("=" * 70)
    a("LEGACY")
    a("=" * 70)
    a("")
    for item in cfg.get("legacy", []):
        a(f"[LEGACY] {item['title']}")
        a(indent(item["use"]))
        a("")
    return "\n".join(L).rstrip() + "\n"


def ssh_fingerprint(line: str) -> str:
    import base64

    blob = base64.b64decode(line.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def keys_json(cfg, pgp: list[PgpKey], root: Cert, certs: list[Cert], ssh: str) -> dict:
    """Machine-readable twin of keys.txt, used by the in-page checker (verify.js)."""
    primary = next(k for k in pgp if k.meta.get("alias"))
    status = lambda k: k.meta["status"]  # noqa: E731

    def cert(c: Cert, status: str, title: str) -> dict | None:
        if not c.present:
            return None
        return {"title": title, "status": status, "file": c.meta["file"], "subject": c.subject,
                "issuer": c.issuer, "not_before": c.not_before, "not_after": c.not_after,
                "sha256": c.sha256.replace(":", ""), "sha1": c.sha1.replace(":", "")}

    return {
        "primary": primary.fpr,
        "pgp": [{"fpr": k.fpr, "title": k.meta["title"], "status": status(k), "file": k.meta["file"],
                 "revoked": k.revoked, "created": k.created,
                 "uids": [u for u, _ in k.uids],
                 "subkeys": [{"fpr": s.fpr, "caps": s.caps, "expires": s.expires} for s in k.subkeys]}
                for k in pgp],
        "x509": [c for c in [cert(root, "current", "My certificate authority (root)")]
                 + [cert(c, c.meta["status"], c.meta["title"]) for c in certs] if c],
        "ssh": {"line": ssh, "blob": ssh.split()[1], "fingerprint": ssh_fingerprint(ssh)},
    }


STATUS_LABEL = {"current": "In use", "revoked": "Retired", "retired": "Retired", "compromised": "Compromised"}


def page(cfg, pgp: list[PgpKey], root: Cert, certs: list[Cert], ssh: str) -> str:
    """The human page. Styling lives in public/style.css (matched to bensoyka.com),
    behaviour in public/verify.js; this only fills in the data."""
    e = html.escape
    o = cfg["owner"]
    primary = next(k for k in pgp if k.meta.get("alias"))
    wiki = next((k for k in pgp if k is not primary and k.meta["status"] == "current"), None)
    docsign = next((c for c in certs if c.meta["status"] == "current"), None)

    def fp(s: str) -> str:
        return f'<code class="fp">{e(s)}</code>'

    def row(label: str, value: str) -> str:
        return f"<dt>{label}</dt><dd>{value}</dd>"

    def pill(status: str) -> str:
        return f'<span class="pill {status}">{STATUS_LABEL[status]}</span>'

    def pgp_item(k: PgpKey) -> str:
        st = k.meta["status"]
        rows = [row("Fingerprint", fp(group4(k.fpr)))]
        rows.append(row("Identities", "<br>".join(e(u) for u, _ in k.uids)))
        when = f"Created {k.created}"
        if k.revoked:
            when += f", retired {k.revoked}"
        elif k.subkeys and k.subkeys[0].expires:
            when += f", renewed before {k.subkeys[0].expires}"
        rows.append(row("Dates", when))
        rows.append(row("Download", f'<a href="/{k.meta["file"]}">{k.fpr[-16:]}.asc</a>'))
        return item(k.meta["title"], st, k.meta["use"], rows)

    def cert_item(c: Cert, title: str, use: str, status: str, extra: list[str] = ()) -> str:
        if not c.present:
            return item(title, status, use, [row("Status", "Not issued yet")])
        rows = [row("SHA-256", fp(c.sha256)), row("SHA-1", fp(c.sha1)),
                row("Valid", f"{c.not_before} to {c.not_after}"),
                row("Download", f'<a href="/{c.meta["file"]}">{e(c.meta["file"].split("/")[-1])}</a>' + "".join(extra))]
        return item(title, status, use, rows)

    def item(title: str, status: str, use: str, rows: list[str]) -> str:
        return (f'<article class="key"><h3>{e(title)} {pill(status)}</h3>'
                f'<p>{e(" ".join(use.split()))}</p><dl>{"".join(rows)}</dl></article>')

    attest = []
    if docsign:
        for k, label in (("attestation", "attestation"), ("attestation_intermediate", "attestation chain")):
            if docsign.meta.get(k) and (PUBLIC / docsign.meta[k]).exists():
                attest.append(f' · <a href="/{docsign.meta[k]}">{label}</a>')

    current = [pgp_item(primary)]
    current.append(cert_item(root, "My certificate authority", cfg["pki"]["root_use"], "current",
                             [f' · <a href="/{cfg["pki"]["crl"]}">revocation list</a>'] if root.present else []))
    if docsign:
        current.append(cert_item(docsign, docsign.meta["title"], docsign.meta["use"], "current", attest))
    current.append(item("SSH key", "current", "The authentication part of my main PGP key.",
                        [row("Key", f'<code class="fp">{e(ssh)}</code>'),
                         row("Fingerprint", fp(ssh_fingerprint(ssh))),
                         row("Download", '<a href="/ssh.txt">ssh.txt</a>')]))
    if wiki:
        current.append(pgp_item(wiki))
    old = [pgp_item(k) for k in pgp if k.meta["status"] == "revoked"]
    old += [cert_item(c, c.meta["title"], c.meta["use"], c.meta["status"]) for c in certs
            if c.meta["status"] in ("retired", "compromised")]
    old += [item(i["title"], "retired", i["use"], []) for i in cfg.get("legacy", [])]

    root_sha1 = fp(root.sha1) if root.present else "<em>(listed below once issued)</em>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keys — Ben Soyka</title>
<meta name="description" content="Check that a signature, key or document really came from {e(o['name'])}.">
<link rel="canonical" href="{e(o['site'])}/">
<link rel="preconnect" href="https://fonts.bunny.net">
<link rel="stylesheet" href="https://fonts.bunny.net/css?family=ibm-plex-sans:400,500,600,700|ibm-plex-mono:400">
<link rel="stylesheet" href="/style.css">
<script type="module" src="/verify.js"></script>
</head>
<body>
<main class="grid">

<section class="card span-2 intro">
  <p class="eyebrow"><a href="https://bensoyka.com">Ben Soyka</a></p>
  <h1>Keys</h1>
  <p>These are the digital keys I use to sign and protect things. If you've got
  something that says it's from me, like a signed PDF, a signed email or a code
  commit, this page helps you check that it's genuine and hasn't been changed.</p>
</section>

<section class="card downloads">
  <h2>Downloads</h2>
  <ul class="links">
    <li><a href="/pgp.asc">PGP key</a> <span>for email and files</span></li>
    <li><a href="/{e(cfg['pki']['root'])}">Root certificate</a> <span>for PDFs</span></li>
    <li><a href="/ssh.txt">SSH key</a> <span>for servers</span></li>
    <li><a href="/keys.txt">keys.txt</a> <span>signed list of everything</span></li>
  </ul>
</section>

<section class="card span-3" id="check">
  <h2>Check something</h2>
  <p>Paste a signed message, a signature, a key, a certificate or a fingerprint,
  or drop a file here. It's checked in your browser; nothing is uploaded.</p>
  <form id="checker" class="checker">
    <label class="drop">
      <textarea id="input" rows="6" spellcheck="false" autocomplete="off"
        placeholder="-----BEGIN PGP SIGNED MESSAGE-----&#10;…or a fingerprint like BC48 76BD …, or drop a .asc / .sig / .crt file"></textarea>
    </label>
    <div id="signed-wrap" class="signed" hidden>
      <p><b>That's a signature on its own.</b> Add what was signed, as text or a file:</p>
      <textarea id="signed" rows="4" spellcheck="false" placeholder="Paste the signed text"></textarea>
      <input type="file" id="signed-file">
    </div>
    <div class="actions">
      <button type="submit" class="btn">Check</button>
      <input type="file" id="file" accept=".asc,.sig,.gpg,.pgp,.crt,.cer,.pem,.der,.txt,.pub">
    </div>
    <div id="result" class="result" role="status" aria-live="polite" hidden></div>
  </form>
  <p class="fine">This is a convenience. If you need certainty, verify
  <a href="/keys.txt">keys.txt</a> yourself with my PGP key from another source
  (see <a href="#trust">how to trust this page</a>).</p>
</section>

<section class="card task">
  <h2>Signed PDFs</h2>
  <p>Adobe Acrobat may say my signature's identity is unknown. That's expected:
  my certificate comes from my own certificate authority rather than a paid one.
  To trust it once for every document I sign:</p>
  <ol>
    <li>Click my signature, then <b>Signature Properties</b> → <b>Show Signer's Certificate</b>.</li>
    <li>Select the top certificate and check its SHA-1 matches {root_sha1}.</li>
    <li>On the <b>Trust</b> tab, choose <b>Add to Trusted Certificates</b> and tick
    <b>Use this certificate as a trusted root</b>.</li>
  </ol>
</section>

<section class="card task">
  <h2>Email and files</h2>
  <p>Use my <a href="/pgp.asc">PGP key</a> to send me something encrypted or to
  check something I've signed. Most PGP tools can fetch it from my email address:</p>
  <pre>gpg --locate-keys {e(primary.meta['wkd'])}</pre>
  <p>Its fingerprint is {fp(group4(primary.fpr))}</p>
</section>

<section class="card task">
  <h2>Code and servers</h2>
  <p>My Git commits are signed with my PGP key, so GitHub marks them
  <b>Verified</b>. To give me SSH access, add my <a href="/ssh.txt">SSH key</a>:</p>
  <pre>curl -s {e(o['site'])}/ssh.txt &gt;&gt; ~/.ssh/authorized_keys</pre>
</section>

<section class="card span-3" id="keys">
  <h2>All my keys</h2>
  <div class="keys">{''.join(current)}</div>
  <details>
    <summary>Retired and compromised ({len(old)})</summary>
    <p>Kept so old signatures can still be checked. Don't encrypt to these or
    start trusting them.</p>
    <div class="keys">{''.join(old)}</div>
  </details>
</section>

<section class="card span-2" id="trust">
  <h2>How to trust this page</h2>
  <p>Everything here comes from <a href="/keys.txt">keys.txt</a>, which is signed
  with my main PGP key. A website can be tampered with, so for anything important,
  get my key from somewhere else too (<a href="https://keys.openpgp.org/search?q={e(primary.fpr)}">keys.openpgp.org</a>,
  <a href="https://github.com/bsoyka.gpg">GitHub</a>, or me in person) and check:</p>
  <pre>curl -s {e(o['site'])}/keys.txt | gpg --verify</pre>
  <p>The signature should come from {fp(group4(primary.fpr))}.</p>
</section>

<section class="card legal">
  <ul>
    <li>&copy; 2026 Ben Soyka</li>
    <li><a href="https://bensoyka.com">bensoyka.com</a></li>
    <li><a href="https://github.com/bsoyka/keys">Source</a></li>
    <li><a href="mailto:{e(o['email'])}">Email me</a></li>
  </ul>
</section>

</main>
</body>
</html>
"""


def main() -> None:
    cfg = tomllib.loads((ROOT / "data" / "keys.toml").read_text())
    BUILD.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as gh:
        os.chmod(gh, 0o700)
        pgp = [load_pgp(m, gh) for m in cfg["pgp"]]
        primary = next(k for k in pgp if k.meta.get("alias"))
        email = primary.meta["wkd"]
        local, domain = email.split("@")
        write_wkd(primary, gh, domain, local, email)
        ssh = ssh_line(primary.meta["ssh_subkey"], gh)
    shutil.copyfile(PUBLIC / primary.meta["file"], PUBLIC / primary.meta["alias"])
    (PUBLIC / "ssh.txt").write_text(ssh + "\n")
    root = load_cert({"file": cfg["pki"]["root"], "title": "Personal root CA", "use": cfg["pki"]["root_use"]})
    certs = [load_cert(m) for m in cfg["x509"]]
    (BUILD / "keys.txt").write_text(manifest(cfg, pgp, root, certs, ssh))
    (PUBLIC / "index.html").write_text(page(cfg, pgp, root, certs, ssh))
    import json

    (PUBLIC / "keys.json").write_text(json.dumps(keys_json(cfg, pgp, root, certs, ssh), indent=1) + "\n")
    print("built: build/keys.txt (unsigned), public/index.html, keys.json, ssh.txt, pgp.asc, WKD")


if __name__ == "__main__":
    main()
