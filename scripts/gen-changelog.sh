#!/usr/bin/env bash
# Regenerate CHANGELOG.md from git history.
#
# Each release commit (subject starting `v<version>:`) becomes one line
# in the changelog with date and a hash link. For the body of any given
# release click through to the linked commit on GitHub.
#
# Why one-line entries? With 500+ release commits, including full bodies
# would produce a six-figure-line file nobody reads. The commits
# themselves are the source of truth — the changelog is an index into
# them.
#
# Run from repo root. Output defaults to ./CHANGELOG.md, override with
# `scripts/gen-changelog.sh path/to/out.md`.

set -euo pipefail

REPO_URL="https://github.com/wolfsoftwaresystemsltd/WolfStack"
OUT="${1:-CHANGELOG.md}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: must be run from inside the WolfStack git repository" >&2
  exit 1
fi

{
  cat <<'HEAD'
# Changelog

All notable changes to WolfStack. Each entry is a release commit whose
subject begins `v<version>:`. Click the hash for the full commit body
and diff.

_Regenerated from git history by `scripts/gen-changelog.sh`. Do not
edit this file by hand — your changes will be overwritten on the next
release._

HEAD
  git log --grep='^v[0-9]' \
    --pretty=format:"- **%s** _(%ad — [\`%h\`](${REPO_URL}/commit/%H))_" \
    --date=short
  echo
} > "$OUT"

LINES=$(wc -l < "$OUT" | tr -d ' ')
ENTRIES=$(grep -c '^- \*\*' "$OUT" || true)
echo "Wrote $LINES lines ($ENTRIES release entries) to $OUT"
