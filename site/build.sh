#!/usr/bin/env bash
# Build the crap.donto.org static site from the repo's own markdown.
# Usage: site/build.sh [outdir]   (default /srv/crap-site)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-/srv/crap-site}"

mkdir -p "$OUT/problems" "$OUT/rels"
cp "$REPO/site/style.css" "$OUT/style.css"

render() { # <src.md> <dest.html> <title>
  pandoc "$1" \
    -f gfm-tex_math_dollars -t html5 --standalone \
    --toc --toc-depth=2 \
    --metadata title="$3" \
    --template "$REPO/site/template.html" \
    -o "$2"
}

render "$REPO/README.md" "$OUT/index.html" "CRAP — Conditional Resource Access Protocol"
render "$REPO/SPEC.md"   "$OUT/spec.html"   "CRAP v0.1 — Specification"

# The problem type URI must resolve to something that explains it (RFC 9457).
render "$REPO/site/problem-input-required.md" "$OUT/problems/input-required.html" \
  "Problem type: input-required"
cp "$OUT/problems/input-required.html" "$OUT/problems/index.html"

# Machine-readable descriptors.
cp "$REPO/site/well-known-crap.json" "$OUT/crap.json"

echo "built $(find "$OUT" -type f | wc -l) files → $OUT"
