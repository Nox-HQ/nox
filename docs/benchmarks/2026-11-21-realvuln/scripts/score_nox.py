#!/usr/bin/env python3
"""Score nox findings.json files against RealVuln ground truth.

A re-implementation of RealVuln's scorer/matcher.py (v3.1.1): file + CWE in
acceptable_cwes + line within [start-10, end+10], also against
acceptable_locations; prefer vulnerable entries; each GT entry consumed once;
an unmatched finding landing on a non_scoring entry (file + line only, needs a
line) is withheld; other unmatched findings are FPs. A finding carrying N CWEs
becomes N normalised findings, as RealVuln's semgrep parser does.

Usage: score_nox.py <rvb dir> <results dir> <repos.tsv> <out.json> [nox|semgrep]
nox:     <results>/<repo_id>/findings.json
semgrep: <results>/<repo_id>/semgrep/results.json (RealVuln's published runs)
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict

TOL = 10
CWE_RE = re.compile(r"CWE-\d+")


def norm_path(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def within(line, start, end) -> bool:
    if line is None or start is None:
        return True
    return start - TOL <= line <= (end if end is not None else start) + TOL


def in_locations(f, e) -> bool:
    loc = e.get("location", {})
    if f["file"] == e["file"] and within(f["line"], loc.get("start_line"), loc.get("end_line")):
        return True
    for a in e.get("acceptable_locations", []):
        if f["file"] == a.get("file") and within(f["line"], a.get("start_line"), a.get("end_line")):
            return True
    return False


def load_gt(path):
    gt = json.load(open(path))
    for e in gt["findings"]:
        e["file"] = norm_path(e["file"])
        for a in e.get("acceptable_locations", []):
            if "file" in a:
                a["file"] = norm_path(a["file"])
    return gt


def nox_findings(path, root):
    """One normalised finding per (nox finding, CWE); paths made repo-relative."""
    raw = json.load(open(path))
    items = raw.get("findings", raw) if isinstance(raw, dict) else raw
    out = []
    for it in items or []:
        md = it.get("Metadata") or {}
        cwes = sorted(set(CWE_RE.findall(md.get("cwe", "") or "")))
        loc = it.get("Location") or {}
        f = loc.get("FilePath") or ""
        if f.startswith(root + "/"):
            f = f[len(root) + 1:]
        f = norm_path(f)
        for c in cwes:
            out.append({"file": f, "line": loc.get("StartLine"), "cwe": c, "rule": it.get("RuleID")})
    return out


def semgrep_findings(path):
    """RealVuln's semgrep parser: one finding per leading CWE in metadata.cwe."""
    out = []
    for r in json.load(open(path)).get("results", []):
        f = norm_path(r.get("path", ""))
        if not f:
            continue
        raw = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        for c in [raw] if isinstance(raw, str) else raw:
            m = re.match(r"(CWE-\d+)", str(c))
            if m:
                out.append({"file": f, "line": r.get("start", {}).get("line"),
                            "cwe": m.group(1), "rule": r.get("check_id")})
    return out


def match(findings, gt):
    scored = [e for e in gt["findings"] if e.get("scoring", "scored") != "non_scoring"]
    ns = [e for e in gt["findings"] if e.get("scoring", "scored") == "non_scoring"]
    used, res = set(), []
    for f in findings:
        cands = [e for e in scored if e["id"] not in used
                 and f["cwe"] in e["acceptable_cwes"] and in_locations(f, e)]
        if cands:
            cands.sort(key=lambda e: not e["is_vulnerable"])
            b = cands[0]
            used.add(b["id"])
            res.append(("TP" if b["is_vulnerable"] else "FP", f, b))
            continue
        if f["line"] is not None and any(in_locations(f, e) for e in ns):
            res.append(("NS", f, None))
            continue
        res.append(("FP", f, None))
    for e in scored:
        if e["id"] not in used:
            res.append(("FN" if e["is_vulnerable"] else "TN", None, e))
    return res


def fbeta(p, r, b):
    return 0.0 if p + r == 0 else (1 + b * b) * p * r / (b * b * p + r)


def card(c):
    tp, fp, fn = c["TP"], c["FP"], c["FN"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": c["TN"], "precision": round(p, 3),
            "recall": round(r, 3), "f2": round(100 * fbeta(p, r, 2), 1),
            "f3": round(100 * fbeta(p, r, 3), 1)}


def main():
    rvb, results, tsv, outp = sys.argv[1:5]
    fmt = sys.argv[5] if len(sys.argv) > 5 else "nox"
    repos_root = sys.argv[6] if len(sys.argv) > 6 else ""
    lang = {}
    for ln in open(tsv):
        rid, _, _, lg = ln.split()
        lang[rid] = "tsjs" if lg in ("javascript", "typescript") else lg
    gts = {r: load_gt(f"{rvb}/ground-truth/{r}/ground-truth.json") for r in lang}
    gt_cwes = {c for g in gts.values() for e in g["findings"] for c in e["acceptable_cwes"]}

    agg = defaultdict(Counter)
    by_rule = defaultdict(Counter)
    fn_cwes = Counter()
    missing = []
    for rid, g in gts.items():
        try:
            fs = (semgrep_findings(f"{results}/{rid}/semgrep/results.json") if fmt == "semgrep"
                  else nox_findings(f"{results}/{rid}/findings.json", f"{repos_root}/{rid}"))
        except (OSError, ValueError):
            missing.append(rid)
            continue
        for view, sub in (("all", fs), ("in_scope", [f for f in fs if f["cwe"] in gt_cwes])):
            for cls, f, e in match(sub, g):
                for tab in ("all", lang[rid]):
                    agg[(view, tab)][cls] += 1
                if view == "all" and f is not None:
                    by_rule[f["rule"]][cls] += 1
                if view == "all" and cls == "FN":
                    fn_cwes[e["primary_cwe"]] += 1
    out = {
        "repos_scored": len(gts) - len(missing), "missing": missing,
        "cards": {f"{v}:{t}": card(c) for (v, t), c in sorted(agg.items())},
        "top_rules": sorted(({"rule": k, **v} for k, v in by_rule.items()),
                            key=lambda d: -(d.get("TP", 0) + d.get("FP", 0)))[:40],
        "top_fn_cwes": fn_cwes.most_common(25),
    }
    json.dump(out, open(outp, "w"), indent=1)
    for k, v in out["cards"].items():
        print(f"{k:16s} {v}")
    print("repos scored", out["repos_scored"], "missing", len(missing))


if __name__ == "__main__":
    main()
