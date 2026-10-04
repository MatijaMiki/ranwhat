#!/usr/bin/env bash
# Stamp each asset's content hash into the URLs that reference it, so a changed
# file is a new URL and no cache anywhere can serve it stale. Unchanged files
# keep their hash and stay cached.
#
# Runs in both CI paths: the GitHub Actions workflow and the Cloudflare Pages
# build. Keep it here rather than inline in either, so the two cannot drift.
set -euo pipefail

for asset in styles.css copy.js contact.js consent.js theme.js subscribe.js; do
  [ -f "site/$asset" ] || continue
  hash=$(sha256sum "site/$asset" | cut -c1-10)
  grep -rlF "/$asset\"" site --include='*.html' \
    | xargs -r sed -i "s|/$asset\"|/$asset?v=$hash\"|g"
  echo "  $asset -> $hash"
done

echo "--- stamped references:"
grep -rho '/[a-z.]*\.\(css\|js\)?v=[a-f0-9]*' site --include='*.html' | sort | uniq -c
