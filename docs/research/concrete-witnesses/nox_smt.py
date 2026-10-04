"""SMT search against nox, with every witness replayed through the binary.

The detector side is a HAND TRANSLATION of a rule's regex into z3's regex
language, i.e. a model of the rule, which is in turn a model of nox (nox also
has keyword pre-filters, refiners, dedup and placeholder logic that no
translation here contains). The reference side is the same constraints as
refs/, restricted to what z3's string theory states directly; the GitHub
reference has no checksum to drop, so it is complete.

Per exact length, ask for  model(x) & !ref(x)  (FP) and  ref(x) & !model(x)
(FN); then embed each witness as  value = "<x>"  in a .py file and scan it.

    python3 nox_smt.py <nox binary> <out dir>
"""
import json
import os
import subprocess
import sys
import time

from z3 import (And, Concat, InRe, Length, Loop, Not, Or, Plus, PrefixOf, Range,
                Re, Solver, Star, String, StringVal, SubString, Union, sat)

ALNUM = Union(Range("a", "z"), Range("A", "Z"), Range("0", "9"))
HEX = Union(Range("a", "f"), Range("A", "F"), Range("0", "9"))
ASCII = Range("!", "~")


def lit_union(*xs):
    return Union(*[Re(x) for x in xs]) if len(xs) > 1 else Re(xs[0])


# The candidate x is the whole quoted value, so "contains a match" is
# Concat(Star(any), rule, Star(any)) — and \b is NOT modelled. That omission
# is deliberate and recorded: it is exactly the kind of gap a replay exposes.
def contains(rule_re):
    return Concat(Star(ASCII), rule_re, Star(ASCII))


RULES = {
    # SEC-003  \bgh[pso]_[A-Za-z0-9_]{36,}
    "SEC-003": contains(Concat(Re("gh"), lit_union("p", "s", "o"), Re("_"),
                               Loop(Union(ALNUM, Re("_")), 36, 36), Star(Union(ALNUM, Re("_"))))),
    # SEC-057  SK[0-9a-fA-F]{32}
    "SEC-057": contains(Concat(Re("SK"), Loop(HEX, 32, 32))),
    # SEC-519  arn:aws:sns:   (keyword pre-filter aws_sns not modelled)
    "SEC-519": contains(Re("arn:aws:sns:")),
}


def ref_github(x):
    return And(Length(x) == 40,
               InRe(x, Concat(Re("gh"), lit_union("p", "o", "u", "s", "r"), Re("_"), Loop(ALNUM, 36, 36))))


def ref_twilio(x):
    return InRe(x, Concat(Re("SK"), Loop(HEX, 32, 32)))


def ref_sns(x):
    part = lit_union("aws", "aws-cn", "aws-us-gov")
    region = Plus(Union(Range("a", "z"), Range("0", "9"), Re("-")))
    name = Plus(Union(ALNUM, Re("_"), Re("-")))
    return InRe(x, Concat(Re("arn:"), part, Re(":sns:"), region, Re(":"),
                          Loop(Range("0", "9"), 12, 12), Re(":"), name))


CASES = [("SEC-003", ref_github, range(38, 45)),
         ("SEC-057", ref_twilio, range(33, 38)),
         ("SEC-519", ref_sns, range(40, 52))]


def solve(rule, ref, lengths, direction, timeout_ms=15000):
    out, stats = [], {}
    for n in lengths:
        x = String("x")
        s = Solver()
        s.set(timeout=timeout_ms)
        s.add(Length(x) == n, InRe(x, Star(ASCII)))
        m, r = InRe(x, RULES[rule]), ref(x)
        s.add(And(m, Not(r)) if direction == "fp" else And(r, Not(m)))
        t = time.time()
        st = str(s.check())
        stats[st] = stats.get(st, 0) + 1
        if st == "sat":
            out.append((n, s.model()[x].as_string(), round(time.time() - t, 2)))
    return out, stats


def replay(nox, out_dir, idx, x):
    d = os.path.join(out_dir, f"r{idx:03d}")
    os.makedirs(os.path.join(d, "t"), exist_ok=True)
    with open(os.path.join(d, "t", "w.py"), "w") as f:
        f.write('value = "' + x.replace("\\", "\\\\").replace('"', '\\"') + '"\n')
    subprocess.run([nox, "scan", os.path.join(d, "t"), "--offline", "-output", os.path.join(d, "o"), "-q"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    with open(os.path.join(d, "o", "findings.json")) as f:
        return sorted({x["RuleID"] for x in json.load(f)["findings"]})


if __name__ == "__main__":
    nox, out_dir = sys.argv[1], sys.argv[2]
    rows, i = [], 0
    for rule, ref, lengths in CASES:
        for direction in ("fp", "fn"):
            ws, stats = solve(rule, ref, lengths, direction)
            print(rule, direction, stats, file=sys.stderr, flush=True)
            for n, x, secs in ws:
                got = replay(nox, out_dir, i, x)
                i += 1
                # FP replays if the rule (or nothing claiming it) reports x;
                # FN replays if NOTHING reports x.
                ok = rule in got if direction == "fp" else not got
                rows.append({"rule": rule, "direction": direction, "len": n, "input": x,
                             "seconds": secs, "nox_rules": got, "replayed": ok})
                print(f"  {direction} len={n} replayed={ok} nox={got} {x!r}", file=sys.stderr, flush=True)
    with open(os.path.join(out_dir, "smt_witnesses.json"), "w") as f:
        json.dump(rows, f, indent=1)
