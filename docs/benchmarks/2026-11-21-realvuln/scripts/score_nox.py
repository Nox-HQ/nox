#!/usr/bin/env python3
"""Score nox findings.json files against RealVuln ground truth.

A re-implementation of RealVuln's scorer/matcher.py (v3.1.1): file + CWE in
acceptable_cwes + line within [start-10, end+10], also against
acceptable_locations; prefer vulnerable entries; each GT entry consumed once;
an unmatched finding landing on a non_scoring entry (file + line only, needs a
line) is withheld; other unmatched findings are FPs. A finding carrying N CWEs
becomes N normalised findings, as RealVuln's semgrep parser does.

Usage: score_nox.py <rvb dir> <results dir> <repos.tsv> <out.json> [format] [repos root]
                    [--split split.tsv --side dev|holdout] [--by-class]
format nox (default):  <results>/<repo_id>/findings.json
format semgrep:        <results>/<repo_id>/semgrep/results.json
format published:TOOL: <rvb>/scan-results/<repo_id>/TOOL/{run-1,results}.json,
                       any tool whose run RealVuln publishes (semgrep-shaped);
                       <results> is ignored
--split/--side score one side of the frozen split (split.tsv); held-out labels
are scored only at milestone gates. --by-class adds recall per vulnerability
class (CLASSES below) to the output and prints it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
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


def published_findings(rvb, rid, tool):
    """A tool's published RealVuln run: the semgrep shape, under either name."""
    for name in ("run-1.json", "results.json"):
        p = f"{rvb}/scan-results/{rid}/{tool}/{name}"
        if os.path.exists(p):
            return semgrep_findings(p)
    raise OSError(f"no published {tool} run for {rid}")


# Vulnerability classes by primary CWE, for --by-class. "other" is the rest.
CLASSES = {
    "injection": ["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-918", "CWE-94", "CWE-502", "CWE-611",
                  "CWE-601", "CWE-90", "CWE-643", "CWE-917", "CWE-1336", "CWE-943", "CWE-77", "CWE-73",
                  "CWE-117", "CWE-113", "CWE-93", "CWE-95"],
    "crypto_secrets_config": ["CWE-798", "CWE-328", "CWE-327", "CWE-330", "CWE-338", "CWE-916", "CWE-326",
                              "CWE-321", "CWE-259", "CWE-522", "CWE-614", "CWE-1004", "CWE-942", "CWE-16",
                              "CWE-693", "CWE-1021", "CWE-295", "CWE-489", "CWE-319", "CWE-312"],
    "authentication_session": ["CWE-307", "CWE-287", "CWE-288", "CWE-290", "CWE-384", "CWE-613", "CWE-620",
                               "CWE-640", "CWE-521", "CWE-306", "CWE-352", "CWE-1275", "CWE-345", "CWE-347"],
    "authorization": ["CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-269", "CWE-266",
                      "CWE-732", "CWE-566"],
    "information_exposure": ["CWE-200", "CWE-209", "CWE-532", "CWE-215", "CWE-359", "CWE-497", "CWE-201"],
    "business_logic": ["CWE-840", "CWE-841", "CWE-837", "CWE-799", "CWE-770", "CWE-400", "CWE-362",
                       "CWE-367", "CWE-20", "CWE-1284"],
    "mass_assignment": ["CWE-915"],
}
CLASS_OF = {c: k for k, cs in CLASSES.items() for c in cs}


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
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rvb")
    ap.add_argument("results")
    ap.add_argument("tsv")
    ap.add_argument("out")
    ap.add_argument("fmt", nargs="?", default="nox")
    ap.add_argument("repos_root", nargs="?", default="")
    ap.add_argument("--split")
    ap.add_argument("--side", choices=("dev", "holdout"))
    ap.add_argument("--by-class", action="store_true")
    a = ap.parse_args()
    if bool(a.split) != bool(a.side):
        ap.error("--split and --side go together")

    lang = {}
    for ln in open(a.tsv):
        rid, _, _, lg = ln.split()
        lang[rid] = "tsjs" if lg in ("javascript", "typescript") else lg
    if a.split:
        side = {ln.split("\t")[0]: ln.split("\t")[1] for ln in open(a.split) if not ln.startswith("#")}
        lang = {r: lg for r, lg in lang.items() if side.get(r) == a.side}
    gts = {r: load_gt(f"{a.rvb}/ground-truth/{r}/ground-truth.json") for r in lang}

    agg = defaultdict(Counter)
    by_rule = defaultdict(Counter)
    by_class = defaultdict(Counter)
    fn_cwes = Counter()
    missing = []
    for rid, g in gts.items():
        try:
            if a.fmt == "semgrep":
                fs = semgrep_findings(f"{a.results}/{rid}/semgrep/results.json")
            elif a.fmt.startswith("published:"):
                fs = published_findings(a.rvb, rid, a.fmt.split(":", 1)[1])
            else:
                fs = nox_findings(f"{a.results}/{rid}/findings.json", f"{a.repos_root}/{rid}")
        except (OSError, ValueError):
            missing.append(rid)
            continue
        gt_cwes = {c for e in g["findings"] for c in e["acceptable_cwes"]}
        for view, sub in (("all", fs), ("in_scope", [f for f in fs if f["cwe"] in gt_cwes])):
            for cls, f, e in match(sub, g):
                for tab in ("all", lang[rid]):
                    agg[(view, tab)][cls] += 1
                if view == "all" and f is not None:
                    by_rule[f["rule"]][cls] += 1
                if view == "all" and e is not None and e["is_vulnerable"] and cls in ("TP", "FN"):
                    by_class[CLASS_OF.get(e["primary_cwe"], "other")][cls] += 1
                if view == "all" and cls == "FN":
                    fn_cwes[e["primary_cwe"]] += 1
    out = {
        "repos_scored": len(gts) - len(missing), "missing": missing,
        "side": a.side or "all",
        "cards": {f"{v}:{t}": card(c) for (v, t), c in sorted(agg.items())},
        "top_rules": sorted(({"rule": k, **v} for k, v in by_rule.items()),
                            key=lambda d: -(d.get("TP", 0) + d.get("FP", 0)))[:40],
        "top_fn_cwes": fn_cwes.most_common(25),
    }
    if a.by_class:
        out["by_class"] = {k: {"labels": c["TP"] + c["FN"], "found": c["TP"],
                               "recall": round(c["TP"] / max(c["TP"] + c["FN"], 1), 3)}
                           for k, c in sorted(by_class.items())}
    json.dump(out, open(a.out, "w"), indent=1)
    for k, v in out["cards"].items():
        if k.startswith("all:"):
            print(f"{k:16s} {v}")
    if a.by_class:
        for k, v in out["by_class"].items():
            print(f"  {k:24s} {v['found']:5d}/{v['labels']:5d}  recall {v['recall']:.3f}")
    print("side", out["side"], "repos scored", out["repos_scored"], "missing", len(missing))


if __name__ == "__main__":
    main()
