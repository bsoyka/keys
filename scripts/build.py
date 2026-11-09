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


PAGE_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a64;--card:#fff;--line:#e4e1d8;--accent:#2f5d50;--warn:#9a3b1c;--code:#f2f0ea}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--muted:#9c9a92;--card:#1d1d1b;--line:#2e2d29;--accent:#7fb8a4;--warn:#e08a66;--code:#25241f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 ui-sans-serif,system-ui,-apple-system,sans-serif}
main{max-width:760px;margin:0 auto;padding:48px 16px 80px}h1{font-size:1.9rem;margin:0 0 .3rem}h2{font-size:1.1rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:2.5rem 0 1rem}
p{margin:.5rem 0}a{color:var(--accent)}.lede{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:0 0 14px}
.card h3{margin:0 0 .4rem;font-size:1.05rem}.tag{font-size:.75rem;padding:1px 8px;border-radius:99px;border:1px solid var(--line);color:var(--muted);margin-left:6px;vertical-align:2px}
.tag.compromised{color:var(--warn);border-color:var(--warn)}
code,pre{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);border-radius:6px}
code{padding:1px 5px;word-break:break-all}pre{padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:.6rem 0}dt{color:var(--muted)}dd{margin:0;min-width:0;overflow-wrap:anywhere}
ol li{margin:.3rem 0}
.quick{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:1.4rem 0}
.quick a{display:block;text-decoration:none;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.quick a:hover{border-color:var(--accent)}.quick b{display:block;color:var(--accent)}.quick span{font-size:.88rem;color:var(--muted)}
details{margin:2.5rem 0 0}summary{cursor:pointer;font-size:1.1rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:1rem}
details[open] summary{margin-bottom:1rem}
"""


def page(cfg, pgp: list[PgpKey], root: Cert, certs: list[Cert], ssh: str) -> str:
    e = html.escape
    o = cfg["owner"]
    primary = next(k for k in pgp if k.meta.get("alias"))

    def pgp_card(k: PgpKey) -> str:
        tag = f"revoked {k.revoked}" if k.revoked else k.meta["status"]
        rows = [("Fingerprint", f"<code>{group4(k.fpr)}</code>"), ("Created", k.created)]
        if k.expires:
            rows.append(("Expires", k.expires))
        rows.append(("UIDs", "<br>".join(e(u) + (" <em>(revoked)</em>" if r else "") for u, r in k.uids)))
        if k.subkeys:
            rows.append(("Subkeys", "<br>".join(
                f"{'/'.join(CAPS[c] for c in s.caps if c in CAPS)}: <code>{s.fpr}</code>" for s in k.subkeys)))
        links = [f'<a href="/{k.meta["file"]}">{k.meta["file"].split("/")[-1]}</a>']
        if k.meta.get("alias"):
            links.insert(0, f'<a href="/{k.meta["alias"]}">{k.meta["alias"]}</a>')
        rows.append(("Download", " · ".join(links)))
        return card(k.meta["title"], tag, k.meta["use"], rows)

    def cert_card(c: Cert, title: str | None = None, use: str | None = None) -> str:
        title = title or c.meta["title"]
        use = use if use is not None else c.meta.get("use", "")
        if not c.present:
            return card(title, "not issued yet", use, [])
        rows = [("Subject", e(c.subject))]
        if c.issuer != c.subject:
            rows.append(("Issuer", e(c.issuer)))
        rows += [("Valid", f"{e(c.not_before)} → {e(c.not_after)}"),
                 ("SHA-256", f"<code>{c.sha256}</code>"),
                 ("SHA-1", f"<code>{c.sha1}</code>"),
                 ("Download", f'<a href="/{c.meta["file"]}">{c.meta["file"].split("/")[-1]}</a>')]
        for k, label in (("attestation", "Attestation"), ("attestation_intermediate", "Attestation (f9)")):
            if c.meta.get(k) and (PUBLIC / c.meta[k]).exists():
                rows.append((label, f'<a href="/{c.meta[k]}">{c.meta[k].split("/")[-1]}</a>'))
        return card(title, c.meta.get("status", "current"), use, rows)

    def card(title: str, tag: str, use: str, rows: list[tuple[str, str]]) -> str:
        cls = "tag compromised" if tag == "compromised" else "tag"
        dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
        body = " ".join(use.split())
        return (f'<div class="card"><h3>{e(title)}<span class="{cls}">{e(tag)}</span></h3>'
                f"<p>{e(body)}</p>{f'<dl>{dl}</dl>' if dl else ''}</div>")

    root_meta = {"file": cfg["pki"]["root"]}
    root.meta = {**root_meta, "status": "current"}
    cur = [pgp_card(k) for k in pgp if k.meta["status"] == "current"]
    cur.append(card("SSH key", "current", "Authentication subkey of the primary PGP key.",
                    [("Key", f"<code>{e(ssh)}</code>"), ("Download", '<a href="/ssh.txt">ssh.txt</a>')]))
    cur.append(cert_card(root, "Personal root CA", cfg["pki"]["root_use"]))
    cur += [cert_card(c) for c in certs if c.meta["status"] == "current"]
    old = [pgp_card(k) for k in pgp if k.meta["status"] == "revoked"]
    old += [cert_card(c) for c in certs if c.meta["status"] == "retired"]
    bad = [cert_card(c) for c in certs if c.meta["status"] == "compromised"]
    legacy = [card(i["title"], "legacy", i["use"], []) for i in cfg.get("legacy", [])]

    root_fp = f"<code>{root.sha1}</code>" if root.present else "listed above"
    fdf = (', or open <a href="/pki/root.fdf">root.fdf</a> in Acrobat to import it in one step'
           if (PUBLIC / "pki" / "root.fdf").exists() else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Keys · {e(o['name'])}</title>
<meta name="description" content="Public keys and certificates for {e(o['name'])}, and how to verify them.">
<style>{PAGE_CSS}</style></head><body><main>
<h1>Keys &amp; certificates</h1>
<p class="lede">{e(o['name'])} · <a href="mailto:{e(o['email'])}">{e(o['email'])}</a></p>
<p>Everything I use to sign, encrypt and authenticate, in one place. The signed
<a href="/keys.txt">keys.txt</a> is the authoritative version of this page.</p>
<nav class="quick">
<a href="/pgp.asc"><b>PGP key</b><span>Encrypt to me or check my signatures</span></a>
<a href="/ssh.txt"><b>SSH key</b><span>For authorized_keys</span></a>
<a href="#acrobat"><b>PDF signatures</b><span>Trust my root in Acrobat</span></a>
<a href="/keys.txt"><b>keys.txt</b><span>Signed list of everything here</span></a>
</nav>

<h2>Verify this page</h2>
<pre>gpg --locate-keys {e(primary.meta['wkd'])}
curl -s {e(o['site'])}/keys.txt | gpg --verify</pre>
<p>The signature should come from <code>{group4(primary.fpr)}</code>. Check that
fingerprint against another source you trust (my GitHub profile, a business card, me in person).</p>

<h2>Current</h2>
{''.join(cur)}

<h2 id="acrobat">Trust my document signatures in Acrobat</h2>
<ol>
<li>Open a PDF I signed, click the signature, then <b>Signature Properties → Show Signer's Certificate</b>.</li>
<li>Select the top certificate in the chain (my root CA) and check its SHA-1 fingerprint matches {root_fp}.</li>
<li>On the <b>Trust</b> tab, click <b>Add to Trusted Certificates</b> and tick <b>Use this certificate as a trusted root</b>
for signed documents. Leave certified documents and dynamic content unticked.</li>
</ol>
<p>Or download <a href="/{e(cfg['pki']['root'])}">root.crt</a> and import it under
<b>Preferences → Signatures → Identities &amp; Trusted Certificates</b>{fdf}. My root can only issue certificates
for me and can't create other CAs, and its key is kept offline.</p>

<details><summary>Retired or revoked ({len(old)})</summary>
<p>Kept for verifying old signatures. Don't encrypt to these or newly trust them.</p>
{''.join(old)}</details>

<details><summary>Compromised ({len(bad)})</summary>
<p>Don't trust anything signed by these.</p>
{''.join(bad)}</details>

<details><summary>Legacy ({len(legacy)})</summary>
{''.join(legacy)}</details>
</main></body></html>
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
    print("built: build/keys.txt (unsigned), public/index.html, public/ssh.txt, public/pgp.asc, WKD")


if __name__ == "__main__":
    main()
