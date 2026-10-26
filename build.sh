#!/usr/bin/env bash
# Stamp each asset's content hash into the URLs that reference it, so a changed
# file is a new URL and no cache anywhere can serve it stale. Unchanged files
# keep their hash and stay cached.
#
# Runs in both CI paths: the GitHub Actions workflow and the Cloudflare Pages
# build. Keep it here rather than inline in either, so the two cannot drift.
set -euo pipefail

# Minify first, so the hash below is of what is served. Only where the build
# runs on a throwaway checkout (CI, Cloudflare Pages): running this on your own
# machine would overwrite the readable sources. esbuild is pinned.
if [ -n "${CI:-}${CF_PAGES:-}" ]; then
  for asset in styles.css copy.js contact.js consent.js theme.js subscribe.js; do
    [ -f "site/$asset" ] || continue
    npx --yes esbuild@0.25.10 "site/$asset" --minify --log-level=warning --allow-overwrite --outfile="site/$asset"
  done
  echo "--- minified"
fi

for asset in styles.css copy.js contact.js consent.js theme.js subscribe.js; do
  [ -f "site/$asset" ] || continue
  hash=$(sha256sum "site/$asset" | cut -c1-10)
  grep -rlF "/$asset\"" site --include='*.html' \
    | xargs -r sed -i "s|/$asset\"|/$asset?v=$hash\"|g"
  echo "  $asset -> $hash"
done

echo "--- stamped references:"
grep -rho '/[a-z.]*\.\(css\|js\)?v=[a-f0-9]*' site --include='*.html' | sort | uniq -c

# A markdown twin of every page for AI agents, plus /llms-full.txt and
# /md-catalog.json, all derived from the pages just stamped (scripts/build_md.py).
# Generated here, never committed, so they cannot drift from the HTML.
python3 scripts/build_md.py
