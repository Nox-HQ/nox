#!/usr/bin/env python3
"""Corpus-wide metamorphic sweep — the production rule-bug oracle for `nox`.

Where `harness.py` is the per-PR gate (does *this change* break the metamorphic
relation on the PR's own testdata + the synthetic seeds), `sweep.py` is the
standing corpus-wide oracle: it hunts the *next* rule bug across a curated,
diverse corpus of real-world-shaped inputs, and it ranks *suspicious* rules even
when nothing has hard-failed yet.

Metamorphic relation under test (identical to harness.py):
    A *semantics-preserving* edit to a source file must not change nox's finding
    set. Any finding that appears or disappears under such an edit is a rule bug.

The sweep does three things beyond the gate:

  1. VIOLATIONS (hard). It reuses the harness engine — the same mutation set,
     line-shift-invariant equivalence, adversarial re-verification, and ddmin
     minimisation — across the whole corpus. A verified violation is a bug.

  2. KNOWN-ISSUES BASELINE. A verified violation that matches a documented entry
     in `known_issues.json` (a specific rule + seed + mutation class we have
     already triaged and accepted as a pre-existing, separately-tracked nox
     defect) is reported but does NOT fail the sweep. This mirrors nox's own
     `baseline` concept: the gate stays green on today's known state and goes
     red only on a NEW, un-triaged violation. Run `--no-known-issues` to see the
     raw, unsuppressed set (used to confirm a baselined bug still reproduces).

  3. TRIAGE (soft, informational). It scans every corpus file once to build a
     per-rule coverage map, then ranks SUSPICIOUS rules the maintainer should
     look at next:
        * flips_under_edit — a rule with a NEW (un-baselined) verified violation
          (a confirmed bug shape; risk high).
        * single_construct — a rule that fires on exactly ONE distinct construct
          across the entire corpus, so the metamorphic check only ever exercised
          it in one place. Not a bug: a fragility / under-coverage signal that
          says "we cannot yet tell if this rule is precise or merely overfit —
          add a construct or review it" (risk medium).

Only a NEW verified violation fails the sweep (exit non-zero). The triage report
is uploaded as an audit artifact and is the maintainer's worklist.

Determinism: seeds are sorted, mutation order is fixed, there is no randomness,
nox runs with --offline, and the report contains NO wall-clock and NO absolute
paths. Same repo state => byte-identical report.

Run:  python3 scripts/metamorphic/sweep.py --bin ./nox --results sweep-out
See scripts/metamorphic/README.md for the full write-up.
"""
import argparse
import json
import os
import sys
import tempfile

import harness as H

HERE = os.path.dirname(os.path.abspath(__file__))
# The curated multi-sample corpus is the default sweep target. Operators can add
# more roots with --seeds (e.g. the per-PR synthetic seeds) for a wider hunt.
DEFAULT_CORPUS_ROOTS = [
    os.path.join(H.REPO_ROOT, "testdata", "metamorphic-corpus"),
]
DEFAULT_KNOWN_ISSUES = os.path.join(HERE, "known_issues.json")

TRIAGE_SCHEMA = "nox-metamorphic-triage/v1"
RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


# ---------------------------------------------------------------------------
# Known-issues baseline
# ---------------------------------------------------------------------------


def load_known_issues(path):
    """Load and validate the known-issues baseline. Returns a list of entries.

    Each entry MUST scope itself with non-empty `ruleids` and `seeds` so a
    baseline can never blanket-suppress a whole class of future bugs. Optional
    `mutation_classes` and `directions` narrow it further (default: match any).
    """
    if not path or not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    issues = data.get("known_issues", [])
    for it in issues:
        if not it.get("ruleids") or not it.get("seeds"):
            sys.exit(f"known_issues entry {it.get('id')!r} must set non-empty "
                     f"'ruleids' and 'seeds'")
    return issues


def match_known(violation, known_issues):
    """Return the id of the first known-issue entry matching `violation`, else None."""
    mclass = violation["mutation"].split("[")[0]
    for it in known_issues:
        if violation["ruleid"] not in it["ruleids"]:
            continue
        if violation["seed"] not in it["seeds"]:
            continue
        mcs = it.get("mutation_classes")
        if mcs and mclass not in mcs:
            continue
        dirs = it.get("directions")
        if dirs and violation["direction"] not in dirs:
            continue
        return it.get("id", "unknown")
    return None


def partition_known(violations, known_issues):
    """Split verified violations into (new, known). Tags known ones with their id."""
    new, known = [], []
    for c in violations:
        kid = match_known(c, known_issues)
        if kid:
            c["known_issue_id"] = kid
            known.append(c)
        else:
            new.append(c)
    return new, known


# ---------------------------------------------------------------------------
# Coverage — one scan per corpus file, tally what each rule reacts to
# ---------------------------------------------------------------------------


def collect_coverage(seeds, nox):
    """Scan each seed original once; return per-rule coverage.

    Returns: {ruleid: {"seeds": set(display), "constructs": set(anchor),
                       "fires": int}}. A "construct" is the whitespace-normalised
    anchor text the finding points at (the same line-shift-invariant identity the
    diff uses), so two findings on identically-shaped lines count as one
    construct even across files.
    """
    coverage = {}
    for path, display in seeds:
        filename = os.path.basename(path)
        lines, tnl = H.read_seed(path)
        text = H.join_lines(lines, tnl)
        findings = nox.scan_one_file(filename, text.encode("utf-8"))
        flines = text.split("\n")
        for fi in findings:
            rid = fi.get("RuleID")
            if not rid:
                continue
            entry = coverage.setdefault(
                rid, {"seeds": set(), "constructs": set(), "fires": 0})
            entry["seeds"].add(display)
            entry["constructs"].add(H.anchor_for(fi, flines)[1])
            entry["fires"] += 1
    return coverage


# ---------------------------------------------------------------------------
# Triage ranking — pure function of (coverage, new violations)
# ---------------------------------------------------------------------------


def rank_suspicious(coverage, new_violations):
    """Rank suspicious rules. Pure + deterministic (sorted output).

    A rule is listed if it has at least one signal:
      * flips_under_edit  (=> risk high)   — has a NEW verified violation.
      * single_construct  (=> risk medium) — fires on exactly one distinct
                                             construct across the whole corpus.
    seed_count is reported as context but is not, by itself, a listing trigger.
    """
    violating = {}  # ruleid -> set(direction)
    for v in new_violations:
        violating.setdefault(v["ruleid"], set()).add(v["direction"])

    suspects = []
    for rid in sorted(set(coverage) | set(violating)):
        entry = coverage.get(
            rid, {"seeds": set(), "constructs": set(), "fires": 0})
        constructs = len(entry["constructs"])
        signals = []
        if rid in violating:
            signals.append("flips_under_edit")
        if constructs == 1:
            signals.append("single_construct")
        if not signals:
            continue
        risk = "high" if "flips_under_edit" in signals else "medium"
        suspects.append({
            "ruleid": rid,
            "risk": risk,
            "signals": signals,
            "fire_count": entry["fires"],
            "distinct_constructs": constructs,
            "seed_count": len(entry["seeds"]),
            "seeds": sorted(entry["seeds"]),
            "violation_directions": sorted(violating.get(rid, set())),
        })
    suspects.sort(key=lambda s: (RISK_ORDER[s["risk"]], s["ruleid"]))
    return suspects


# ---------------------------------------------------------------------------
# Violation collection (reuses the harness engine verbatim)
# ---------------------------------------------------------------------------


def _violation_sort_key(c):
    return (c["ruleid"], c["direction"], c["seed"], c["mutation"])


def collect_violations(seeds, nox, results_dir):
    """Run the harness invariance engine over `seeds`; return sorted unique list.

    Identical pipeline to harness.main: run -> adversarial verify + ddmin ->
    de-duplicate -> write minimal repros.
    """
    candidates, stats = H.run(seeds, nox)
    survivors = H.verify_and_minimize(candidates, nox)

    seen = set()
    unique = []
    for c in survivors:
        key = (c["seed"], c["ruleid"], c["direction"],
               c["mutation"].split("[")[0])
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    unique.sort(key=_violation_sort_key)
    for i, c in enumerate(unique):
        c["repro_dir"] = os.path.relpath(
            H.write_repro(results_dir, c, i), results_dir)
    return unique, stats


# ---------------------------------------------------------------------------
# Report building (deterministic — no wall-clock, no absolute paths)
# ---------------------------------------------------------------------------


def _violation_view(c, extra_keys=()):
    keys = ("seed", "filename", "mutation", "direction",
            "ruleid", "anchor", "message", "repro_dir") + tuple(extra_keys)
    view = {k: c[k] for k in keys if k in c}
    view["minimal_edit_count"] = len(c["minimal_edits"])
    return view


def build_triage(corpus_roots, seed_count, stats, total_scans,
                 coverage, new_violations, known_violations):
    suspects = rank_suspicious(coverage, new_violations)
    return {
        "schema": TRIAGE_SCHEMA,
        "corpus_roots": sorted(
            os.path.relpath(r, H.REPO_ROOT)
            for r in corpus_roots if os.path.isdir(r)),
        "seed_file_count": seed_count,
        "mutations_applied": stats.get("mutations_applied", 0),
        "total_nox_scans": total_scans,
        "rules_exercised": len(coverage),
        "verified_violation_count": len(new_violations),
        "verified_violations": [_violation_view(c) for c in new_violations],
        "known_violation_count": len(known_violations),
        "known_violations": [
            _violation_view(c, ("known_issue_id",)) for c in known_violations],
        "suspicious_rule_count": len(suspects),
        "high_risk_count": sum(1 for s in suspects if s["risk"] == "high"),
        "medium_risk_count": sum(1 for s in suspects if s["risk"] == "medium"),
        "suspicious_rules": suspects,
        "coverage": {
            rid: {
                "seeds": sorted(entry["seeds"]),
                "distinct_constructs": len(entry["constructs"]),
                "fires": entry["fires"],
            }
            for rid, entry in sorted(coverage.items())
        },
    }


def render_summary(report):
    """Deterministic human-readable Markdown summary (no timestamps)."""
    out = []
    out.append("# Metamorphic corpus sweep — triage summary\n")
    out.append(f"- corpus roots: {', '.join(report['corpus_roots'])}")
    out.append(f"- seed files: {report['seed_file_count']}")
    out.append(f"- rules exercised: {report['rules_exercised']}")
    out.append(f"- mutations applied: {report['mutations_applied']}")
    out.append(f"- total nox scans: {report['total_nox_scans']}")
    out.append(f"- new verified violations: {report['verified_violation_count']}")
    out.append(f"- known (baselined) violations: {report['known_violation_count']}")
    out.append(
        f"- suspicious rules: {report['suspicious_rule_count']} "
        f"(high {report['high_risk_count']}, medium {report['medium_risk_count']})\n")

    if report["verified_violations"]:
        out.append("## NEW verified violations (BUGS — sweep fails)\n")
        out.append("| rule | direction | seed | mutation | repro |")
        out.append("|---|---|---|---|---|")
        for v in report["verified_violations"]:
            kind = ("false negative" if v["direction"] == "disappeared"
                    else "false positive")
            out.append(
                f"| `{v['ruleid']}` | {v['direction']} ({kind}) | "
                f"`{v['seed']}` | `{v['mutation']}` | `{v['repro_dir']}` |")
        out.append("")
    else:
        out.append("## NEW verified violations\n\nNone. No un-baselined "
                   "metamorphic violation across the corpus.\n")

    if report["known_violations"]:
        out.append("## Known (baselined) violations — see known_issues.json\n")
        out.append("| rule | direction | seed | mutation | known-issue id |")
        out.append("|---|---|---|---|---|")
        for v in report["known_violations"]:
            out.append(
                f"| `{v['ruleid']}` | {v['direction']} | `{v['seed']}` | "
                f"`{v['mutation']}` | `{v.get('known_issue_id','')}` |")
        out.append("")

    if report["suspicious_rules"]:
        out.append("## Suspicious rules (review — does not fail CI)\n")
        out.append("| risk | rule | signals | fires | constructs | seeds |")
        out.append("|---|---|---|---|---|---|")
        for s in report["suspicious_rules"]:
            out.append(
                f"| {s['risk']} | `{s['ruleid']}` | {', '.join(s['signals'])} | "
                f"{s['fire_count']} | {s['distinct_constructs']} | "
                f"{s['seed_count']} |")
        out.append("")
        out.append(
            "`single_construct` = the rule only ever fired on one distinct "
            "construct across the corpus, so the sweep could not cross-check its "
            "robustness. It is a coverage/fragility signal, not a bug: add a "
            "second construct to the corpus for that rule, or review the rule "
            "for over-fitting.\n")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def sweep(seed_roots, nox, results_dir, known_issues=None):
    """End-to-end sweep. Returns the triage report dict."""
    known_issues = known_issues or []
    seeds = H.discover_seeds(seed_roots)
    if not seeds:
        sys.exit(f"no corpus files found under: {seed_roots}")
    coverage = collect_coverage(seeds, nox)
    violations, stats = collect_violations(seeds, nox, results_dir)
    new_v, known_v = partition_known(violations, known_issues)
    return build_triage(seed_roots, len(seeds), stats, nox.scans,
                        coverage, new_v, known_v)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=H.DEFAULT_BIN,
                    help="path to the nox binary (default: repo ./nox)")
    ap.add_argument("--seeds", action="append", default=None,
                    help="corpus root to walk (repeatable; default: "
                         "testdata/metamorphic-corpus)")
    ap.add_argument("--results", default=None,
                    help="directory for the triage report + repros "
                         "(default: a temp dir)")
    ap.add_argument("--known-issues", default=DEFAULT_KNOWN_ISSUES,
                    help="path to the known-issues baseline JSON "
                         "(default: scripts/metamorphic/known_issues.json)")
    ap.add_argument("--no-known-issues", action="store_true",
                    help="ignore the baseline; report every verified violation "
                         "as new (use to confirm a baselined bug still repros)")
    ap.add_argument("--limit", type=int, default=None,
                    help="limit number of corpus files (for a quick run)")
    args = ap.parse_args()

    seed_roots = args.seeds if args.seeds else DEFAULT_CORPUS_ROOTS
    seeds = H.discover_seeds(seed_roots)
    if not seeds:
        sys.exit(f"no corpus files found under: {seed_roots}")
    if args.limit:
        seeds = seeds[:args.limit]

    known_issues = [] if args.no_known_issues else load_known_issues(
        args.known_issues)

    nox = H.Nox(args.bin)
    results_dir = args.results or tempfile.mkdtemp(prefix="nox-metamorphic-sweep-")
    os.makedirs(results_dir, exist_ok=True)

    coverage = collect_coverage(seeds, nox)
    violations, stats = collect_violations(seeds, nox, results_dir)
    new_v, known_v = partition_known(violations, known_issues)
    report = build_triage(seed_roots, len(seeds), stats, nox.scans,
                         coverage, new_v, known_v)

    report_path = os.path.join(results_dir, "triage_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    summary = render_summary(report)
    summary_path = os.path.join(results_dir, "triage_summary.md")
    with open(summary_path, "w") as f:
        f.write(summary)
        f.write("\n")

    print(summary)
    print(f"\ntriage report:  {report_path}")
    print(f"triage summary: {summary_path}")

    if report["verified_violation_count"]:
        print(f"\nFAIL: {report['verified_violation_count']} NEW verified "
              f"metamorphic violation(s). See repros under "
              f"{results_dir}/repros/.", file=sys.stderr)
        sys.exit(1)
    print(f"\nOK: no NEW metamorphic violations "
          f"({report['known_violation_count']} known/baselined).")
    sys.exit(0)


if __name__ == "__main__":
    main()
