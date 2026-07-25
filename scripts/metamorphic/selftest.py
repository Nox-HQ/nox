#!/usr/bin/env python3
"""Positive controls for the metamorphic harness.

A green run of harness.py is only trustworthy if we can show the harness would
have gone red on a real bug. These controls exercise the three pieces that a
false "no violations" could hide:

  PC1  detection      — a genuinely finding-removing edit MUST be reported.
  PC2  line-shift      — a pure blank-line shift MUST NOT be reported.
  PC3  verify+minimize — the adversarial re-verifier confirms a real delta and
                         ddmin reduces it to the single responsible edit.
  PC4  synthetic FN bug — emulates the historical "comment mentioning
                          HEALTHCHECK hides IAC-121" bug by hand and shows the
                          diff logic flags it as a disappeared finding.

A gate that cannot go red is worthless — this is mandatory and runs in CI.

Run:  python3 scripts/metamorphic/selftest.py --bin ./nox   (exit 0 = all pass)
"""
import argparse
import os
import sys

import harness as H

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

print()
if fails:
    print(f"{len(fails)} control(s) FAILED: {fails}")
    sys.exit(1)
print("all positive controls passed")
sys.exit(0)
