#!/usr/bin/env python3
"""Freeze the RealVuln development / held-out split.

Usage: split.py <rvb dir> <out.tsv>

Run once; the output (split.tsv beside this script) is committed and never
regenerated. Development labels may be read to find defects. Held-out labels
are only scored, at milestone gates (docs/plans/2026-11-deterministic-lead.md).

The split is by FAMILY, not by repository. The generated applications come in
families: the same application (crm-saas-nestjs-angular) written by three to
five models. Splitting them by repository would put near-identical code on
both sides, and tuning on one copy would improve the held-out copy. A family,
and a fork with its upstream (juice-shop-goof with juice-shop), always lands on
one side.

Families are stratified by language group (python, tsjs, java) and authorship
(the manifest's llm_generated, or not) and, within each stratum, taken in a
seeded random order until 30% of the stratum's repositories are held out.
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import defaultdict

SEED = 20261121
HELD_OUT = 0.30
FORK_SUFFIXES = ("-goof", "-swagger")


def family(repo_id: str) -> str:
    m = re.match(r"^vc-.*-seeded-v\d+-(.+)$", repo_id)
    if m:
        return "generated:" + m.group(1)
    name = repo_id.removeprefix("realvuln-")
    for suffix in FORK_SUFFIXES:
        name = name.removesuffix(suffix)
    return "repo:" + name


def lang_group(language: str) -> str:
    return "tsjs" if language in ("javascript", "typescript") else language


def main() -> None:
    rvb, out = sys.argv[1:3]
    repos = json.load(open(f"{rvb}/benchmark-manifest.json"))["repos"]
    strata: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for rid, r in sorted(repos.items()):
        authored = "generated" if r.get("authorship") == "llm_generated" else "other"
        strata[(lang_group(r["language"]), authored)][family(rid)].append(rid)

    rng = random.Random(SEED)
    side: dict[str, str] = {}
    for key in sorted(strata):
        fams = strata[key]
        total = sum(len(v) for v in fams.values())
        order = sorted(fams)
        rng.shuffle(order)
        held = 0
        for fam in order:
            take = held < HELD_OUT * total and held + len(fams[fam]) <= HELD_OUT * total + 2
            for rid in fams[fam]:
                side[rid] = "holdout" if take else "dev"
            if take:
                held += len(fams[fam])

    with open(out, "w") as f:
        f.write("# repo\tside\tfamily  (frozen 2026-11-21, seed %d; do not regenerate)\n" % SEED)
        for rid in sorted(side):
            f.write(f"{rid}\t{side[rid]}\t{family(rid)}\n")
    counts = defaultdict(lambda: defaultdict(int))
    for rid, s in side.items():
        r = repos[rid]
        counts[(lang_group(r["language"]), "generated" if r.get("authorship") == "llm_generated" else "other")][s] += 1
    for key in sorted(counts):
        c = counts[key]
        print(f"{key[0]:6s} {key[1]:9s} dev {c['dev']:3d}  holdout {c['holdout']:3d}")


if __name__ == "__main__":
    main()
