#!/usr/bin/env python3
"""Weekly dependency-CVE audit verdict.

Reads a nox scan (findings.json) and the plan `nox fix --dry-run
--include-major` made from the same findings, and fails only on an advisory
nox would actually upgrade.

It used to fail on any VULN-001 carrying a fixed_in. nox fix refuses some of
those: a fixed_in that is a pre-release when the installed version is stable
(grpc 1.84.0's fix exists only as a 1.85.0-dev pseudo-version), or one that
would be a downgrade. The audit then demanded a fix the fixer would not make,
and the weekly job stayed red with nothing anyone could apply. The planner is
the one place that decides what is applicable, so the audit asks it.

Usage: deps-audit.py FINDINGS_JSON FIX_PLAN_TXT
"""

import json
import re
import sys

# `plan: <command> <package> -> <version>  (VULN-001) in <dir>`
PLAN_LINE = re.compile(r"^plan: \S+(?: \S+)* (\S+) -> (\S+)\s+\(VULN-001\)")


def planned_packages(plan_text):
    out = set()
    for line in plan_text.splitlines():
        m = PLAN_LINE.match(line)
        if m:
            out.add(m.group(1))
    return out


def main(findings_path, plan_path):
    findings = json.load(open(findings_path)).get("findings", [])
    cves = [f for f in findings
            if f.get("RuleID") == "VULN-001"
            and f.get("Status", "new") in ("new", "")]
    planned = planned_packages(open(plan_path).read())

    fixable, not_applicable, unfixable = [], [], []
    for f in cves:
        meta = f.get("Metadata", {}) or {}
        if not meta.get("fixed_in"):
            unfixable.append(f)
        elif meta.get("package") in planned:
            fixable.append(f)
        else:
            not_applicable.append(f)

    for f in unfixable:
        print("::warning::no fix available — " + f.get("Message", ""))
    for f in not_applicable:
        print("::warning::fixed_in exists but nox fix will not apply it "
              "(see the plan's skip lines) — " + f.get("Message", ""))
    for f in fixable:
        print("::error::fix available — " + f.get("Message", ""))
    print(f"dependency CVEs: {len(fixable)} fixable, "
          f"{len(not_applicable)} fix not applicable, {len(unfixable)} awaiting-fix")
    if fixable:
        print("Run `nox fix --input findings.json` to apply the planned upgrades.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
