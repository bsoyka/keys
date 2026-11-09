#!/usr/bin/env bash
# Update the vendored OpenPGP.js used by public/verify.js.
# Usage: scripts/vendor.sh 6.3.2   (then update the import path in verify.js)
# Vendored rather than loaded from a CDN so nobody else controls what the
# checker runs; the npm tarball's integrity is checked by npm itself.
set -euo pipefail
cd "$(dirname "$0")/.."
v="${1:?version}"
tmp=$(mktemp -d)
(cd "$tmp" && npm pack "openpgp@$v" --silent >/dev/null && tar xzf openpgp-*.tgz)
cp "$tmp/package/dist/openpgp.min.mjs" "public/vendor/openpgp-$v.min.mjs"
cp "$tmp/package/LICENSE" public/vendor/openpgp-LICENSE.txt
shasum -a 256 "public/vendor/openpgp-$v.min.mjs"
rm -rf "$tmp"
