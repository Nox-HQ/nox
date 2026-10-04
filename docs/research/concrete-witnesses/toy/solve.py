"""SMT search for disagreement between toy.Validate and toy.Reference.

Each function is MODELLED here in z3's string theory. The model is not the
code: every witness z3 returns is written to witnesses.json and replayed
through the real Go functions by TestReplaySolverWitnesses. A witness that
does not replay is a fact about this file, not about Validate.

Two models of Validate are searched:
  faithful   - prefix compared after ASCII case-folding, as the code does
  simplified - prefix compared exactly; the kind of abstraction that is easy
               to write and wrong (it forgets strings.ToLower)

Model scope: ASCII strings of length <= 40; z3 strings are sequences of
Unicode code points, Go strings are bytes, so non-ASCII input is outside it.

    python3 solve.py [per-length|any-length] > witnesses.json
"""
import json
import sys
import time
from z3 import (String, Solver, And, Or, Not, Length, SubString, PrefixOf,
                SuffixOf, InRe, Re, Union, Range, Star, Plus, Loop, Concat,
                StringVal, sat, Full, ReSort, StringSort)

B32 = Union(Range("a", "z"), Range("2", "7"))
ANYCASE_PREFIX = Concat(Union(Re("a"), Re("A")), Union(Re("c"), Re("C")),
                        Union(Re("m"), Re("M")), Union(Re("e"), Re("E")), Re("_"))
ASCII = Range(" ", "~")


def body_ok(b):
    return InRe(b, Star(B32))


def validate(s, faithful):
    pre = SubString(s, 0, 5)
    pre_ok = InRe(pre, ANYCASE_PREFIX) if faithful else pre == StringVal("acme_")
    rest = SubString(s, 5, Length(s) - 5)
    body_sfx = SubString(rest, 0, Length(rest) - 3)
    with_sfx = And(SuffixOf(StringVal(".v2"), rest),
                   Or(Length(rest) - 2 == 25, Length(body_sfx) == 25),
                   body_ok(body_sfx))
    plain = And(Not(SuffixOf(StringVal(".v2"), rest)),
                Length(rest) == 24, body_ok(rest))
    return And(Length(s) >= 5, pre_ok, Or(with_sfx, plain))


def reference(s):
    rest = SubString(s, 5, Length(s) - 5)
    return And(Length(s) >= 5, InRe(SubString(s, 0, 5), ANYCASE_PREFIX),
               InRe(rest, Concat(Loop(B32, 24, 24),
                                 Union(Re(""), Re(".v2")))))


def search_per_length(model, direction, max_len=40, timeout_ms=20000):
    """One query per exact length. Each is a much smaller problem for z3's
    sequence solver than "some length <= 40", and UNSAT per length is a
    bounded proof that no witness of that length exists in the model."""
    out, checks = [], []
    for n in range(5, max_len + 1):
        s = String("s")
        solver = Solver()
        solver.set(timeout=timeout_ms)
        solver.add(Length(s) == n, InRe(s, Star(ASCII)))
        v, r = validate(s, model == "faithful"), reference(s)
        solver.add(And(v, Not(r)) if direction == "fp" else And(r, Not(v)))
        t = time.time()
        status = solver.check()
        checks.append({"len": n, "status": str(status), "seconds": round(time.time() - t, 2)})
        if status == sat:
            out.append(solver.model()[s].as_string())
    return out, checks


def search(model, direction, block_limit=3, timeout_ms=60000):
    """Up to block_limit witnesses, each blocked by length once found.

    Every check is recorded with its status, including the last one, which
    is UNSAT (no further witness in scope) or UNKNOWN (z3 gave up). An
    UNKNOWN is not an absence of disagreement.
    """
    out, checks = [], []
    s = String("s")
    solver = Solver()
    solver.set(timeout=timeout_ms)
    solver.add(InRe(s, Star(ASCII)), Length(s) <= 40)
    v, r = validate(s, model == "faithful"), reference(s)
    solver.add(And(v, Not(r)) if direction == "fp" else And(r, Not(v)))
    while len(out) < block_limit:
        t = time.time()
        status = solver.check()
        checks.append({"status": str(status), "seconds": round(time.time() - t, 2)})
        if status != sat:
            break
        w = solver.model()[s].as_string()
        out.append(w)
        solver.add(Length(s) != len(w))
    return out, checks


if __name__ == "__main__":
    strategy = sys.argv[1] if len(sys.argv) > 1 else "per-length"
    fn = search_per_length if strategy == "per-length" else search
    res = {"strategy": strategy, "witnesses": [], "checks": []}
    for model in ("faithful", "simplified"):
        for direction in ("fp", "fn"):
            ws, checks = fn(model, direction)
            res["checks"].append({"model": model, "direction": direction, "checks": checks})
            for w in ws:
                res["witnesses"].append({"model": model, "direction": direction, "input": w})
            summary = {}
            for c in checks:
                summary[c["status"]] = summary.get(c["status"], 0) + 1
            print(model, direction, summary, round(sum(c["seconds"] for c in checks), 1), "s", ws, file=sys.stderr, flush=True)
    print(json.dumps(res, indent=1))
