#!/usr/bin/env python3
"""Positive controls for the metamorphic harness AND the corpus sweep.

A green run is only trustworthy if we can show the tooling would have gone red on
a real bug. These controls exercise every piece a false "no violations" could
hide, for both the per-PR gate (harness.py) and the corpus oracle (sweep.py):

  PC1  detection      — a genuinely finding-removing edit MUST be reported.
  PC2  line-shift      — a pure blank-line shift MUST NOT be reported.
  PC3  verify+minimize — the adversarial re-verifier confirms a real delta and
                         ddmin reduces it to the single responsible edit.
  PC4  synthetic FN bug — emulates the historical "comment mentioning
                          HEALTHCHECK hides IAC-121" bug by hand and shows the
                          diff logic flags it as a disappeared finding.
  PC5  sweep coverage  — collect_coverage tallies real rules from a real scan.
  PC6  sweep triage red — a planted verified violation is ranked high-risk
                          (flips_under_edit); the sweep provably goes red.
  PC7  sweep line-shift — an end-to-end sweep over a clean file yields ZERO new
                          verified violations (the core invariance, at sweep scope).
  PC8  known-issues    — the baseline suppresses a matching violation but a
                         NON-matching (new) violation survives to fail.

A gate that cannot go red is worthless — this is mandatory and runs in CI.

Run:  python3 scripts/metamorphic/selftest.py --bin ./nox   (exit 0 = all pass)
"""
import argparse
import os
import shutil
import sys
import tempfile

import harness as H
import sweep as S

ap = argparse.ArgumentParser()
ap.add_argument("--bin", default=H.DEFAULT_BIN)
args = ap.parse_args()

nox = H.Nox(args.bin)
# Drive PC1–PC3 off the real corpus seed, not a copy.
SEED = os.path.join(H.REPO_ROOT, "testdata", "precision-suite", "tp_injection.py")
fails = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}  {detail}")
    if not cond:
        fails.append(name)


# PC1 — deleting the os.system sink removes TAINT-002.
lines, tnl = H.read_seed(SEED)
orig = H.join_lines(lines, tnl)
mut = H.join_lines([l for i, l in enumerate(lines) if i != 3], tnl)
b = nox.scan_one_file("tp_injection.py", orig.encode())
a = nox.scan_one_file("tp_injection.py", mut.encode())
v = H.diff_findings(b, orig, a, mut)
check("PC1 detection",
      any(x["direction"] == "disappeared" and x["ruleid"] == "TAINT-002" for x in v),
      str([(x["direction"], x["ruleid"]) for x in v]))

# PC2 — a 5-blank-line shift must produce no violations.
shift = H.join_lines([""] * 5 + lines, tnl)
a2 = nox.scan_one_file("tp_injection.py", shift.encode())
v2 = H.diff_findings(b, orig, a2, shift)
check("PC2 line-shift invariance", v2 == [],
      f"(startlines {sorted(f['Location']['StartLine'] for f in a2)})")

# PC3 — verify + minimize a real delta down to one atomic edit.
cand = [{
    "seed": "tp_injection.py", "filename": "tp_injection.py", "mutation": "control",
    "direction": "disappeared", "ruleid": "TAINT-002", "anchor": "", "message": "",
    "edits": [{"op": "replace", "idx": 3, "text": ""}],
    "_orig_lines": lines, "_trailing_nl": tnl,
}]
surv = H.verify_and_minimize(cand, nox)
check("PC3 verify+minimize",
      len(surv) == 1 and surv[0]["verified"] and len(surv[0]["minimal_edits"]) == 1)

# PC4 — synthetic HEALTHCHECK-comment false negative. We hand-fake the *buggy*
# scanner output (IAC-121 absent after inserting a "# HEALTHCHECK" comment) and
# confirm the diff logic reports it as a disappeared finding, i.e. the harness
# WOULD catch that historical bug were it still present.
before_fp = [{"RuleID": "IAC-121", "Fingerprint": "fp121",
              "Location": {"StartLine": 1}, "Message": "missing HEALTHCHECK"}]
btext = "FROM alpine:3.19\nCOPY app /app\n"
after_fp = []  # buggy scanner drops IAC-121
atext = "FROM alpine:3.19\n# HEALTHCHECK\nCOPY app /app\n"
v4 = H.diff_findings(before_fp, btext, after_fp, atext)
check("PC4 synthetic HEALTHCHECK FN caught",
      any(x["direction"] == "disappeared" and x["ruleid"] == "IAC-121" for x in v4))

# ---------------------------------------------------------------------------
# Sweep-mode controls (the corpus oracle).
# ---------------------------------------------------------------------------

# PC5 — coverage collection tallies real rules off a real scan. TAINT-002 is the
# os.system sink in the corpus seed; it must appear with a real construct count.
cov = S.collect_coverage([(SEED, "tp_injection.py")], nox)
check("PC5 sweep coverage",
      "TAINT-002" in cov and cov["TAINT-002"]["fires"] >= 1,
      f"(rules={sorted(cov)})")

# PC6 — a planted verified violation MUST rank as high-risk (flips_under_edit).
# This is the sweep's own "goes red": a rule whose finding flips under a trivial
# edit is surfaced at the top of the triage, not silently dropped.
planted = [{"ruleid": "IAC-121", "direction": "disappeared"}]
suspects = S.rank_suspicious({"IAC-121": {"seeds": {"x"}, "constructs": {"a"},
                                          "fires": 1}}, planted)
top = suspects[0] if suspects else {}
check("PC6 sweep triage flags planted FN as high-risk",
      top.get("ruleid") == "IAC-121" and top.get("risk") == "high"
      and "flips_under_edit" in top.get("signals", []),
      str(suspects[:1]))

# PC7 — an end-to-end sweep over a single CLEAN corpus file must yield zero NEW
# verified violations (pure line-shift invariance holds at sweep scope). Uses a
# secrets file that fires findings but has no line-shift bug.
clean = os.path.join(H.REPO_ROOT, "testdata", "metamorphic-corpus",
                     "python", "config_secrets.py")
_tmp_root = tempfile.mkdtemp(prefix="nox-sweep-selftest-")
_results = tempfile.mkdtemp(prefix="nox-sweep-selftest-out-")
try:
    shutil.copy(clean, os.path.join(_tmp_root, "config_secrets.py"))
    rep = S.sweep([_tmp_root], nox, _results, known_issues=[])
    check("PC7 sweep line-shift invariance (clean file, 0 new violations)",
          rep["verified_violation_count"] == 0 and rep["rules_exercised"] > 0,
          f"(rules_exercised={rep['rules_exercised']}, "
          f"new={rep['verified_violation_count']})")
finally:
    shutil.rmtree(_tmp_root, ignore_errors=True)
    shutil.rmtree(_results, ignore_errors=True)

# PC8 — the known-issues baseline suppresses exactly what it names and nothing
# more. A matching violation is moved to `known`; a violation of the SAME rule on
# a DIFFERENT seed stays `new` (so a regression elsewhere still fails).
known = [{
    "id": "TEST-ENTRY", "ruleids": ["IAC-001"],
    "seeds": ["seed/known.Dockerfile"],
    "mutation_classes": ["blank_line_before_each"],
}]
viol_known = {"ruleid": "IAC-001", "seed": "seed/known.Dockerfile",
              "direction": "disappeared", "mutation": "blank_line_before_each"}
viol_new = {"ruleid": "IAC-001", "seed": "seed/other.Dockerfile",
            "direction": "disappeared", "mutation": "blank_line_before_each"}
new_v, known_v = S.partition_known([dict(viol_known), dict(viol_new)], known)
check("PC8 known-issues baseline suppresses only the named violation",
      len(known_v) == 1 and known_v[0]["seed"] == "seed/known.Dockerfile"
      and len(new_v) == 1 and new_v[0]["seed"] == "seed/other.Dockerfile",
      f"(new={[x['seed'] for x in new_v]}, known={[x['seed'] for x in known_v]})")

print()
if fails:
    print(f"{len(fails)} control(s) FAILED: {fails}")
    sys.exit(1)
print("all positive controls passed")
sys.exit(0)
