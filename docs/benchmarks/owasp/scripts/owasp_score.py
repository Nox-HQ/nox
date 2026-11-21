#!/usr/bin/env python3
"""Score a scan against OWASP Benchmark the way OWASP's scorecard does.

Usage:
  owasp_score.py expected <expectedresults.csv> <findings.json> [--json out.json]
  owasp_score.py replay   <scorecard.csv>     # recompute a published scorecard

A test case is one file (BenchmarkTest00001.java / .py). The tool "identified"
it when it reports, anywhere in that file, a finding whose CWE is the test's
CWE. Per category: TPR = TP/(TP+FN), FPR = FP/(FP+TN), score = TPR - FPR. The
overall TPR, FPR and score are the unweighted means over categories, as the
scorecard states ("add up all the TPR, FPR, and Score values, and then divide
by the number of vulnerability categories").

This reimplements OWASP's published formula rather than running BenchmarkUtils
(a Maven project that would build and execute downloaded code). `replay`
recomputes a scorecard OWASP published from its own per-test CSV, which is how
the formula here is checked against theirs.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict

TEST_RE = re.compile(r"(BenchmarkTest\d{5})")


def summarize(rows):
    """rows: (category, cwe, real, identified). Returns per-category and overall."""
    cats = defaultdict(lambda: {"TP": 0, "FN": 0, "TN": 0, "FP": 0, "cwe": None})
    for cat, cwe, real, ident in rows:
        c = cats[cat]
        c["cwe"] = cwe
        c["TP" if real and ident else "FN" if real else "FP" if ident else "TN"] += 1
    out = {}
    for cat, c in sorted(cats.items()):
        tpr = c["TP"] / max(c["TP"] + c["FN"], 1)
        fpr = c["FP"] / max(c["FP"] + c["TN"], 1)
        out[cat] = {**c, "TPR": round(tpr * 100, 2), "FPR": round(fpr * 100, 2), "score": round((tpr - fpr) * 100, 2)}
    n = max(len(out), 1)
    overall = {k: round(sum(v[k] for v in out.values()) / n, 2) for k in ("TPR", "FPR", "score")}
    return out, overall


def lower_keys(d):
    return {str(k).lower(): v for k, v in d.items()} if isinstance(d, dict) else {}


def finding_cwes(f):
    """The CWEs a finding states, from the finding or its metadata, under any
    key casing (nox writes Metadata.cwe)."""
    f = lower_keys(f)
    meta = lower_keys(f.get("metadata"))
    vals = []
    for key in ("cwe", "cwes"):
        for v in (f.get(key), meta.get(key)):
            if v:
                vals.extend(v if isinstance(v, list) else [v])
    out = set()
    for v in vals:
        m = re.search(r"(\d+)", str(v))
        if m:
            out.add(int(m.group(1)))
    return out


def load_findings(path):
    data = json.load(open(path))
    fs = data.get("findings", data) if isinstance(data, dict) else data
    hits = defaultdict(set)
    for f in fs:
        loc = lower_keys(lower_keys(f).get("location"))
        fp = loc.get("filepath") or loc.get("file") or loc.get("path") or lower_keys(f).get("file") or ""
        m = TEST_RE.search(fp)
        if m:
            hits[m.group(1)] |= finding_cwes(f)
    return hits


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("expected")
    e.add_argument("expected")
    e.add_argument("findings")
    e.add_argument("--json")
    r = sub.add_parser("replay")
    r.add_argument("scorecard")
    a = ap.parse_args()

    rows = []
    if a.cmd == "replay":
        for ln in open(a.scorecard):
            if ln.startswith("#") or not ln.strip():
                continue
            name, cat, cwe, real, ident, _ = [x.strip() for x in ln.split(",")]
            rows.append((cat, int(cwe), real == "true", ident == "true"))
    else:
        hits = load_findings(a.findings)
        for ln in open(a.expected):
            if ln.startswith("#") or not ln.strip():
                continue
            name, cat, real, cwe = [x.strip() for x in ln.split(",")[:4]]
            rows.append((cat, int(cwe), real == "true", int(cwe) in hits.get(name, set())))
    per, overall = summarize(rows)
    for cat, c in per.items():
        print(f"{cat:12s} CWE-{c['cwe']:<4} TP {c['TP']:4d} FN {c['FN']:4d} TN {c['TN']:4d} FP {c['FP']:4d}  TPR {c['TPR']:6.2f}  FPR {c['FPR']:6.2f}  score {c['score']:7.2f}")
    print(f"{'overall':12s} TPR {overall['TPR']:.2f}  FPR {overall['FPR']:.2f}  score {overall['score']:.2f}")
    if getattr(a, "json", None):
        json.dump({"categories": per, "overall": overall}, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
