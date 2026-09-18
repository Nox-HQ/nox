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
# A corpus entry may set "path" to scan ONE subdirectory of the repository
# instead of the whole checkout. That exists for a surface worth gating whose
# repository is not: crewAI's recorded cassettes are 20M of 370M, and carry the
# opaque base64 that the entropy and vendor-keyword rules over-fire on.
#
# Exits 0 when there is no delta, 1 when rules changed. The caller decides
# whether a delta blocks; on a PR it is informational, at release it should be
# read by a human.
set -euo pipefail

BASE_BIN="${1:?usage: rule-diff.sh <baseline-nox> <candidate-nox> [corpus.json]}"
CAND_BIN="${2:?usage: rule-diff.sh <baseline-nox> <candidate-nox> [corpus.json]}"
CORPUS="${3:-$(dirname "$0")/rule-diff-corpus.json}"
LEDGER="${4:-$(dirname "$0")/rule-deltas.json}"
# Whether this run used the committed corpus. The stale-entry check below asks
# "does this entry still describe a real drop?", and only a full run of the
# default corpus can answer no: on a reduced corpus an entry looks stale
# whenever the repo that witnessed it was left out, which is missing evidence
# rather than a stale reason.
FULL_CORPUS=1
[ -n "${3:-}" ] && FULL_CORPUS=0
BASELINE_TAG="${RULE_DIFF_BASELINE_TAG:-}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
[ -f "$CORPUS" ] || { echo "corpus manifest not found: $CORPUS" >&2; exit 2; }
[ -f "$LEDGER" ] || { echo "delta ledger not found: $LEDGER" >&2; exit 2; }

# The ledger is only meaningful against the release it was written for. If the
# caller knows which release the baseline binary came from and it disagrees,
# every entry describes a comparison nobody is making. Report that as a stale
# ledger rather than letting entries silently match, or silently rot.
ledger_release="$(jq -r '.nox_release // ""' "$LEDGER")"
ledger_entries="$(jq -r '(.entries // []) | length' "$LEDGER")"

# A ROLLED ledger -- empty, and naming a release ahead of the baseline -- means
# this is the commit that cuts that release, and this check has nothing left to
# ask.
#
# The two gates want opposite things of that one commit. rule-diff compares
# against the LAST release and needs the entries present to explain the drops
# since it. TestTheReleaseInvariant requires nox_release to equal the tag being
# cut and entries to be EMPTY, because cutting the tag makes those drops part of
# the new baseline. Both are right; they just cannot both hold at once here.
#
# It is answered by noticing that the question was already asked. Every drop the
# ledger explained was gated on the pull request that introduced it, with the
# entry written there and reviewed there. The roll archives those explanations
# because the new baseline absorbs them. Re-asking on the release commit
# re-litigates a decision already made, against a baseline that is about to stop
# being the baseline.
#
# So this skips, loudly, and only for that exact shape: empty AND ahead. A
# non-empty ledger naming the wrong release is still the stale ledger this was
# written to catch, and still fails.
#
# Unnoticed until now because no release had ever rolled the ledger: v1.35.0
# shipped with sixteen entries still explaining drops from v1.34.0 -- the
# incident that caused the invariant to be written. v1.36.0 is the first release
# to satisfy it and the first to meet this.
if [ -n "$BASELINE_TAG" ] && [ -n "$ledger_release" ] \
   && [ "$BASELINE_TAG" != "$ledger_release" ] && [ "$ledger_entries" -eq 0 ]; then
  echo "::notice::rule-deltas.json is rolled for $ledger_release and the baseline is $BASELINE_TAG."
  echo "This is the commit cutting $ledger_release. Every drop the cleared entries explained was"
  echo "gated on the pull request that introduced it; the roll archives those explanations because"
  echo "$ledger_release becomes the baseline. Nothing to diff against a baseline being replaced."
  exit 0
fi

if [ -n "$BASELINE_TAG" ] && [ -n "$ledger_release" ] && [ "$BASELINE_TAG" != "$ledger_release" ]; then
  echo "::error::rule-deltas.json declares nox_release $ledger_release but the baseline is $BASELINE_TAG."
  echo "A release was cut since the ledger was written. Clear the entries it explains, then set nox_release to $BASELINE_TAG."
  exit 3
fi
# An entry with no reason, or naming a classification nobody defined, explains
# nothing. Checking it here means a malformed ledger cannot pass by matching a
# rule ID and contributing an empty sentence.
# Note the `. as $e` binding: inside `has(...)` the input is the
# classifications object, so a bare `.classification` there resolves against
# THAT and matches nothing -- a check that flags every entry, which is as
# broken as one that flags none. Verified against a known-good and two
# known-bad ledgers before it was trusted.
malformed="$(jq -r '
  . as $l
  | [ ($l.entries // [])[]
      | . as $e
      | select((($e.rule // "") == "")
            or (($e.reason // "") == "")
            or (($l.classifications // {}) | has($e.classification // "") | not))
      | ($e.rule // "(entry with no rule)") ]
  | join(", ")' "$LEDGER")"
if [ -n "$malformed" ]; then
  echo "::error::rule-deltas.json entries are malformed: $malformed"
  echo "Every entry needs a rule, a non-empty reason, and a classification listed under .classifications."
  exit 3
fi

# explained <RULE> -- does the ledger account for a drop in this rule?
explained() {
  jq -e --arg r "$1" '[.entries[] | select(.rule == $r)] | length > 0' "$LEDGER" >/dev/null 2>&1
}

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
skipped=0
dropped_rules=""   # rules whose count FELL somewhere; newline-separated, deduped at the end

while read -r name url sha path; do
  [ -n "$name" ] || continue
  repo_count=$((repo_count + 1))
  echo "── $name @ ${sha:0:8}${path:+ /$path}"
  src="$work/src-$name"
  git clone -q --filter=blob:none --no-checkout "$url" "$src" 2>/dev/null || {
    echo "   SKIP: clone failed (network or repo moved)"; skipped=$((skipped + 1)); continue; }
  # An entry that pins a subdirectory fetches only that tree. crewAI's
  # cassettes are 20M of a 370M repository, and materialising the other 350M
  # to scan none of it would cost more than the scan does.
  if [ -n "$path" ]; then
    git -C "$src" sparse-checkout set --no-cone "$path" >/dev/null 2>&1 || {
      echo "::error::$name pins $path but sparse-checkout failed -- is the git here older than 2.25?" >&2
      exit 2; }
  fi
  git -C "$src" checkout -q "$sha" 2>/dev/null || {
    echo "   SKIP: pinned sha $sha not found -- repo history rewritten?"; skipped=$((skipped + 1)); continue; }
  rm -rf "$src/.git"

  # What gets scanned: the whole checkout, or the one subdirectory the entry
  # pinned. A pinned path that is not there is FATAL for the same reason a
  # failed scan is -- the repo moved the tree, the scan covers nothing, and a
  # skip would report that as "no change".
  scan_root="$src"
  if [ -n "$path" ]; then
    scan_root="$src/$path"
    [ -d "$scan_root" ] || {
      echo "::error::$name pins subdirectory $path, which does not exist at $sha" >&2
      exit 2; }
  fi

  # A scan that does not run is FATAL, never a skip. Skipping here would turn
  # "nox is broken" into a quiet "no change" -- the exact failure this whole
  # harness exists to make visible.
  scan_counts "$BASE_BIN" "$scan_root" "$work/out-base-$name" > "$work/base-$name.tsv" || exit 2
  scan_counts "$CAND_BIN" "$scan_root" "$work/out-cand-$name" > "$work/cand-$name.tsv" || exit 2

  # join on rule id, showing 0 where a side is absent
  delta="$(join -t"$(printf '\t')" -a1 -a2 -e0 -o '0,1.2,2.2' \
            "$work/base-$name.tsv" "$work/cand-$name.tsv" \
          | awk -F'\t' '$2 != $3 {print "   "$1": "$2" -> "$3}')"

  if [ -z "$delta" ]; then
    echo "   no change ($(wc -l < "$work/base-$name.tsv" | tr -d ' ') rules fired)"
  else
    echo "$delta"
    total_delta=$((total_delta + $(printf '%s\n' "$delta" | wc -l)))
    # A rule whose count FELL removed findings from a real repository. That is
    # the direction that can hide a vulnerability, so it is the direction the
    # ledger has to account for. Rising counts are reported and not gated:
    # a new false positive is visible in the output and costs nobody a
    # vulnerability.
    dropped_rules="$dropped_rules$(join -t"$(printf '\t')" -a1 -a2 -e0 -o '0,1.2,2.2' \
        "$work/base-$name.tsv" "$work/cand-$name.tsv" \
      | awk -F'\t' '$3 < $2 {print $1}')
"
  fi
done < <(jq -r '.repos[] | "\(.name) \(.url) \(.sha) \(.path // "")"' "$CORPUS")

echo
if [ "$repo_count" -eq 0 ]; then
  echo "::error::corpus is empty -- this check verified nothing"
  exit 2
fi
if [ "$total_delta" -eq 0 ]; then
  echo "no rule-level change across $repo_count repo(s)"
  exit 0
fi
echo "$total_delta rule(s) changed across $repo_count repo(s)"
echo

# ---------------------------------------------------------------------------
# Milestone 0.4 -- negative deltas are auditable.
#
# Up to here this script was a report: it printed what moved and left "is that
# correct?" to whoever read the summary. A drop and a correct narrowing look
# identical in that output, so the answer was whatever the reader assumed.
# ---------------------------------------------------------------------------
dropped="$(printf '%s' "$dropped_rules" | grep -v '^$' | sort -u || true)"

unexplained=""
for rule in $dropped; do
  explained "$rule" || unexplained="$unexplained $rule"
done

# The other half: an entry describing a drop that no longer happens. Without
# this the ledger only ever grows, and a stale reason reads exactly like a
# current one -- the failure mode this whole harness exists to make visible.
stale=""
for rule in $(jq -r '.entries[].rule' "$LEDGER" | sort -u); do
  printf '%s\n' "$dropped" | grep -qx "$rule" || stale="$stale $rule"
done

if [ -n "$unexplained" ]; then
  echo "::error title=Unexplained narrowing::These rules removed findings from real repositories with no entry in scripts/rule-deltas.json:$unexplained"
  echo
  echo "A rule that reports less is either a fix or a hidden vulnerability, and the"
  echo "count alone cannot tell you which. Add an entry per rule with a"
  echo "classification and a reason, or explain in review why the drop is correct"
  echo "and the ledger is the wrong place to say so."
  exit 3
fi

if [ -n "$stale" ]; then
  if [ "$skipped" -gt 0 ] || [ "$FULL_CORPUS" -eq 0 ]; then
    echo "::warning::ledger entries with no matching drop:$stale -- but this run skipped $skipped repo(s) or used a reduced corpus, so it is missing evidence rather than a stale entry"
  else
    echo "::error title=Stale ledger entry::These rules have an entry in scripts/rule-deltas.json but no longer drop anything:$stale"
    echo
    echo "Either the change was reverted, or a release was cut and the entries it"
    echo "explained should have been cleared. A ledger nothing validates rots into"
    echo "decoration, which is worse than no ledger."
    exit 3
  fi
fi

if [ -n "$dropped" ]; then
  echo "every negative delta is accounted for in scripts/rule-deltas.json:"
  for rule in $dropped; do
    printf '   %-10s %s\n' "$rule" "$(jq -r --arg r "$rule" '[.entries[] | select(.rule==$r) | "\(.classification) (#\(.pr))"] | join(", ")' "$LEDGER")"
  done
fi
exit 1
