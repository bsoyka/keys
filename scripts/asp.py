#!/usr/bin/env python3
"""Build and sign my Keyoxide ASP (Ariadne Signature Profile) as a static file.

  asp.py init KEY.pem   record the public key: writes data/asp-public.json
  asp.py sign KEY.pem   sign data/asp.toml into public/.well-known/aspe/id/<FP>

KEY.pem is the Ed25519 private key, which only ever exists on scripts/ca.sh's
RAM disk (ca.sh asp-init / asp-sign call this). Keyoxide fetches the result from
https://keys.bensoyka.com/.well-known/aspe/id/<FP>, so the profile's identifier
is aspe:keys.bensoyka.com:<FP>.

Key decisions:
- Ed25519 (EdDSA), which the spec recommends over P-256.
- Fingerprint per the ASP spec: RFC 7638 JWK thumbprint with SHA-512, first 16
  bytes, base32 without padding, uppercase (also what Keyoxide's doipjs does).
- Stdlib + the openssl CLI only, so no Python packages to install; openssl
  signs Ed25519 over the raw JWS signing input.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENSSL = Path(sys.argv[3]) if len(sys.argv) > 3 else "openssl"
PUBLIC_JWK = ROOT / "data" / "asp-public.json"
HOST = "keys.bensoyka.com"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_from_private(pem: Path) -> dict:
    der = subprocess.run([str(OPENSSL), "pkey", "-in", str(pem), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    if len(der) != 44:  # 12-byte SubjectPublicKeyInfo prefix + 32-byte Ed25519 key
        sys.exit("not an Ed25519 key")
    return {"crv": "Ed25519", "kty": "OKP", "x": b64url(der[-32:])}


def fingerprint(jwk: dict) -> str:
    # RFC 7638: required members only, lexicographic order, no whitespace.
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"))
    return base64.b32encode(hashlib.sha512(canon.encode()).digest()[:16]).decode().rstrip("=")


def cmd_init(pem: Path) -> None:
    jwk = jwk_from_private(pem)
    fp = fingerprint(jwk)
    PUBLIC_JWK.write_text(json.dumps({"jwk": jwk, "fingerprint": fp, "uri": f"aspe:{HOST}:{fp}"}, indent=1) + "\n")
    print(f"aspe:{HOST}:{fp}")


def cmd_sign(pem: Path) -> None:
    pub = json.loads(PUBLIC_JWK.read_text())
    jwk = jwk_from_private(pem)
    if jwk != pub["jwk"]:
        sys.exit("this key doesn't match data/asp-public.json")
    fp = pub["fingerprint"]
    cfg = tomllib.loads((ROOT / "data" / "asp.toml").read_text())
    payload = {
        "http://ariadne.id/version": 0,
        "http://ariadne.id/type": "profile",
        "http://ariadne.id/name": cfg["name"],
        "http://ariadne.id/claims": cfg["claims"],
    }
    for k in ("description", "avatar_url", "email", "color"):
        if cfg.get(k):
            payload[f"http://ariadne.id/{k}"] = cfg[k]
    header = {"alg": "EdDSA", "typ": "JWT", "kid": fp, "jwk": jwk}
    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    with tempfile.NamedTemporaryFile() as f:
        f.write(signing_input.encode())
        f.flush()
        sig = subprocess.run([str(OPENSSL), "pkeyutl", "-sign", "-rawin", "-inkey", str(pem), "-in", f.name],
                             check=True, capture_output=True).stdout
    out = ROOT / "public" / ".well-known" / "aspe" / "id" / fp
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"{signing_input}.{b64url(sig)}")
    print(f"signed {len(cfg['claims'])} claims -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("init", "sign"):
        sys.exit(__doc__)
    {"init": cmd_init, "sign": cmd_sign}[sys.argv[1]](Path(sys.argv[2]))
