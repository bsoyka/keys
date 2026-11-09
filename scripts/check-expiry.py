#!/usr/bin/env python3
"""Warn about anything in the key setup that expires soon.

Checks, from the repo (no secrets needed):
  - each CA's revocation list (public/pki/*.crl): next update date
  - every current certificate in data/keys.toml: not-after date
  - every current PGP key in data/keys.toml: primary and subkey expiry
  - bensoyka.com's security.txt: its Expires field (fetched live; skipped offline)

Exit status 1 if anything is expired or within --days (default 60), so it can
drive a scheduled task or CI. Stdlib only, plus the gpg and openssl CLIs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
SECURITY_TXT = "https://bensoyka.com/.well-known/security.txt"
TODAY = dt.datetime.now(dt.UTC).date()


def run(*args: str, **kw) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout


def openssl_date(s: str) -> dt.date:
    return dt.datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z").date()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=60, help="warn this many days ahead")
    args = ap.parse_args()
    cfg = tomllib.loads((ROOT / "data" / "keys.toml").read_text())
    items: list[tuple[dt.date, str, str]] = []  # (date, what, how to fix)

    for crl in sorted((PUBLIC / "pki").glob("*.crl")):
        nxt = run("openssl", "crl", "-inform", "DER", "-in", str(crl), "-noout", "-nextupdate").split("=", 1)[1]
        items.append((openssl_date(nxt), f"revocation list {crl.name}", "scripts/ca.sh crl, then make sign deploy"))

    for c in cfg["x509"]:
        path = PUBLIC / c["file"]
        if c["status"] != "current" or not path.exists():
            continue
        fmt = "PEM" if path.read_bytes().startswith(b"-----BEGIN") else "DER"
        end = run("openssl", "x509", "-inform", fmt, "-in", str(path), "-noout", "-enddate").split("=", 1)[1]
        fix = {"signing": "scripts/ca.sh issue-docsign …", "ca": "scripts/ca.sh new-intermediate …"}.get(
            c.get("role"), "new root ceremony")
        items.append((openssl_date(end), c["title"], fix))

    with tempfile.TemporaryDirectory() as gh:
        env = {**os.environ, "GNUPGHOME": gh}
        for k in cfg["pgp"]:
            if k["status"] != "current":
                continue
            run("gpg", "--batch", "--quiet", "--import", str(PUBLIC / k["file"]), env=env)
            fpr = Path(k["file"]).stem
            for line in run("gpg", "--batch", "--with-colons", "--fixed-list-mode", "--list-keys", fpr, env=env).splitlines():
                f = line.split(":")
                if f[0] in ("pub", "sub") and f[6]:
                    part = "primary" if f[0] == "pub" else f"{f[11]} subkey"
                    items.append((dt.datetime.fromtimestamp(int(f[6]), dt.UTC).date(),
                                  f"{k['title']} ({part})", "docs/restore.md § D"))

    try:
        with urllib.request.urlopen(SECURITY_TXT, timeout=10) as r:
            m = re.search(r"^Expires:\s*(\S+)", r.read().decode(), re.M)
        if m:
            items.append((dt.date.fromisoformat(m.group(1)[:10]), "bensoyka.com security.txt",
                          "bump Expires in bsoyka/website security.txt.in, re-sign, deploy"))
    except Exception as e:  # offline or blocked: say so, don't fail
        print(f"(skipped security.txt: {e})")

    soon = TODAY + dt.timedelta(days=args.days)
    bad = 0
    for date, what, fix in sorted(items):
        left = (date - TODAY).days
        if date < TODAY:
            flag, bad = "EXPIRED", bad + 1
        elif date <= soon:
            flag, bad = "SOON", bad + 1
        else:
            flag = "ok"
        line = f"{flag:8} {date}  ({left:>5} days)  {what}"
        print(line + (f"  ->  {fix}" if flag != "ok" else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
