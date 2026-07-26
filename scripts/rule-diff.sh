#!/usr/bin/env bash
#
# Scan a corpus of real repositories with two nox builds and diff the findings.
#
# WHY: nox's corpus precision is measured at 1.00, and that number does not
# predict behaviour on real repositories. A sweep of ~270 baselined findings
# across the fleet found secret and AI rules producing 13 false positives out of
# 13, while VULN-001 and IAC-013 were 21 real out of 23. Synthetic fixtures
# cannot show that, because they contain exactly what the rule author expected.
#
# So this runs both builds over pinned real repositories and reports what
# CHANGED per rule. A rule that starts firing 40 more times, or stops firing
# entirely, is the signal -- neither is inherently wrong, but neither should
# reach a release unexplained.
#
# Usage:
#   scripts/rule-diff.sh <baseline-nox> <candidate-nox> [corpus.json]
#
# Exits 0 when there is no delta, 1 when rules changed. The caller decides
# whether a delta blocks; on a PR it is informational, at release it should be
# read by a human.
set -euo pipefail

BASE_BIN="${1:?usage: rule-diff.sh <baseline-nox> <candidate-nox> [corpus.json]}"
CAND_BIN="${2:?usage: rule-diff.sh <baseline-nox> <candidate-nox> [corpus.json]}"
CORPUS="${3:-$(dirname "$0")/rule-diff-corpus.json}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
[ -f "$CORPUS" ] || { echo "corpus manifest not found: $CORPUS" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Scan one checkout and emit "RULEID<TAB>count" lines. Output goes OUTSIDE the
# tree being scanned: writing results into the checkout makes the next scan
# ingest the previous scan's own findings.json.
scan_counts() {
  local bin="$1" src="$2" out="$3"
  if ! "$bin" scan "$src" -format json -output "$out" >/dev/null 2>&1; then
    : # findings present is a non-zero exit; a real failure surfaces as no JSON
  fi
  if [ ! -s "$out/findings.json" ]; then
    echo "::error::$bin produced no findings.json for $src -- the scan did not run" >&2
    return 1
  fi
  jq -r '.findings[]?.RuleID' "$out/findings.json" | sort | uniq -c \
    | awk '{print $2"\t"$1}' | sort
}

total_delta=0
repo_count=0

while read -r name url sha; do
  [ -n "$name" ] || continue
  repo_count=$((repo_count + 1))
  echo "── $name @ ${sha:0:8}"
  src="$work/src-$name"
  git clone -q --filter=blob:none "$url" "$src" 2>/dev/null || {
    echo "   SKIP: clone failed (network or repo moved)"; continue; }
  git -C "$src" checkout -q "$sha" 2>/dev/null || {
    echo "   SKIP: pinned sha $sha not found -- repo history rewritten?"; continue; }
  rm -rf "$src/.git"

  # A scan that does not run is FATAL, never a skip. Skipping here would turn
  # "nox is broken" into a quiet "no change" -- the exact failure this whole
  # harness exists to make visible.
  scan_counts "$BASE_BIN" "$src" "$work/out-base-$name" > "$work/base-$name.tsv" || exit 2
  scan_counts "$CAND_BIN" "$src" "$work/out-cand-$name" > "$work/cand-$name.tsv" || exit 2

  # join on rule id, showing 0 where a side is absent
  delta="$(join -t"$(printf '\t')" -a1 -a2 -e0 -o '0,1.2,2.2' \
            "$work/base-$name.tsv" "$work/cand-$name.tsv" \
          | awk -F'\t' '$2 != $3 {print "   "$1": "$2" -> "$3}')"

  if [ -z "$delta" ]; then
    echo "   no change ($(wc -l < "$work/base-$name.tsv" | tr -d ' ') rules fired)"
  else
    echo "$delta"
    total_delta=$((total_delta + $(printf '%s\n' "$delta" | wc -l)))
  fi
done < <(jq -r '.repos[] | "\(.name) \(.url) \(.sha)"' "$CORPUS")

echo
if [ "$repo_count" -eq 0 ]; then
  echo "::error::corpus is empty -- this check verified nothing"
  exit 2
fi
if [ "$total_delta" -eq 0 ]; then
  echo "no rule-level change across $repo_count repo(s)"
  exit 0
fi
echo "$total_delta rule(s) changed across $repo_count repo(s) -- each needs an explanation"
exit 1
