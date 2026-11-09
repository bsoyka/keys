#!/usr/bin/env bash
# Upload public/ to the S3 origin with correct content types, then invalidate.
# Bucket and distribution come from Terraform outputs, so nothing is hardcoded.
set -euo pipefail
cd "$(dirname "$0")/.."

BUCKET=$(terraform -chdir=terraform output -raw bucket)
DIST=$(terraform -chdir=terraform output -raw distribution_id)
S3="s3://$BUCKET"
CC="public, max-age=3600"

# One pass per content type. S3 would otherwise guess (badly) for .asc/.crl/.crt. Later passes only touch their own patterns.
up() { # content-type, then include globs
  local ct="$1"; shift
  local args=(--exclude '*')
  for g in "$@"; do args+=(--include "$g"); done
  aws s3 sync public/ "$S3" "${args[@]}" --content-type "$ct" --cache-control "$CC"
}
up "text/html; charset=utf-8"  '*.html'
up "text/css; charset=utf-8"   '*.css'
up "text/javascript; charset=utf-8" '*.js' '*.mjs'
up "application/json"          '*.json'
up "text/plain; charset=utf-8" '*.txt' '*.asc'
up "application/pkix-cert"     '*.crt'
up "application/pkix-crl"      '*.crl'
up "application/vnd.fdf"       '*.fdf'
up "application/jose"          '.well-known/aspe/id/*'

# Remove objects that no longer exist in public/. Done by hand rather than
# `sync --delete`, which would re-upload unmatched files with guessed types.
comm -13 <(cd public && find . -type f | sed 's|^\./||' | sort) \
         <(aws s3api list-objects-v2 --bucket "$BUCKET" --query 'Contents[].Key' --output text | tr '\t' '\n' | grep -v '^None$' | sort) |
while read -r key; do
  echo "removing stale $key"; aws s3 rm "$S3/$key"
done

aws cloudfront create-invalidation --distribution-id "$DIST" --paths '/*' \
  --query 'Invalidation.Id' --output text
echo "Deployed to https://keys.bensoyka.com"
