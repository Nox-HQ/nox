# Current-state baseline — 2026-09

Milestone 0.1 of the refutation-safe roadmap
(`docs/design/roadmap-refutation-safe.md`): *measure the current scanner after
all recent rule and plugin changes*, so that every later refutation has one
authoritative set of numbers to be judged against.

Measured on `78439de`, core-only, offline, no plugins in `plugins.required`.
Supersedes `docs/benchmarks/2026-Q3` (`5848369`, 2026-08-30), which stays as
the historical record.

## Reproducing

```bash
go build -o /tmp/nox ./cli
for d in testdata/precision-corpus testdata/precision-suite testdata/precision-suite-*; do
  /tmp/nox bench --precision "$d" --json
done
/tmp/nox bench --precision testdata/refutation-suite --json
/tmp/nox analysis-capabilities
```

Machine-readable: `precision.json`.

## Detection — does nox report too much?

| Corpus | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| precision-corpus | 5 | 0 | 0 | 1.000 | 1.000 |
| precision-suite | 52 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-clojure | 20 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-cpp | 7 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-csharp | 6 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-dart | 6 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-elixir | 14 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-groovy | 7 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-java | 6 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-kotlin | 7 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-lua | 11 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-objc | 7 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-perl | 12 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-php | 9 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-powershell | 8 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-ruby | 17 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-rust | 6 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-scala | 7 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-shell | 16 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-swift | 7 | 0 | 0 | 1.000 | 1.000 |
| **Total** | **230** | **0** | **0** | **1.000** | **1.000** |

### The seven false negatives are closed, and they were closed the right way

The Q3 baseline carried seven FNs — TAINT-002 and TAINT-006 in Clojure, Dart
and Shell — recorded as *"the recall debt the programme must not make worse."*
This run reports zero.

Recall 1.000 is the number a corpus can most easily fake, so it was checked
rather than accepted. `git diff 5848369..HEAD` over the three affected corpora
shows the `nox-expect` annotations **unchanged and still on the same
statements** — `echo "$urls" | xargs curl -fsSL # nox-expect: TAINT-006` is
byte-identical across the range. Only the surrounding prose changed, from
*"honest false negative, the engine cannot follow this"* to a description of
the shared-state join and pipeline model that now can. The expectations were
not moved to meet the engine; the engine was moved to meet them (#564).

Three corpora also grew: `precision-suite` 37 → 52, clojure 13 → 20,
dart 4 → 6, shell 13 → 16. **A total that rises while recall rises is the
combination that hides a withdrawal**, so the per-corpus columns above matter
more than the total, and no corpus lost an expectation.

## Refutation — does nox report too little?

This is the half the roadmap adds, and the half nothing else watches.

| Corpus | Cases | Result | Guard | Gate |
|---|---:|---|---|---|
| `refutation-suite` | 10 | 10 TP / 0 FP / 0 FN — recall **1.000** | `TestRefutationSuiteRecall` | A |
| `refutation-hard` | 5 | not precision-scored by design | — | A |
| `reachability-suite` | 5 | 1 case may suppress, by name | `TestGateB` | B |

`refutation-hard` and `reachability-suite` are deliberately **not** scored for
fire-rate: a finding in `refutation-hard` is neither a true nor a false
positive, and `reachability-suite` scores `(reachable, determined)` pairs out
of each case's `expect.json`. Running `bench --precision` against either
produces a meaningless FP — one each on this run (CRYPTO-001 and TAINT-002).
That is an artefact of pointing the wrong harness at them, not a regression;
it is recorded here so the next person does not rediscover it as a defect.

## Capability coverage

`nox analysis-capabilities` declares nine and provides seven:

```
call_graph             — not provided
entry_point            — not provided
```

Both are prerequisites for the reachability propositions in Phase 7. Neither
appears in `findings.json`: the scan's `meta` block carries `degradations` and
`sast_languages`, and nothing about which capabilities were unavailable. A
consumer reading only the canonical output cannot tell that two of nine
questions were never asked — which is Milestone 1.2, stated as a measurement
rather than as an intention.

## Scale and cost

| | |
|---|---:|
| Distinct rule IDs | ~1,600 (SEC 913, IAC 500, AI 50, CWE 44, MCP 21, DATA 12, rest ≤6 each, a few of them test fixtures) |
| `bench --precision` per corpus | 53–101 ms |
| Full self-scan (`nox scan .`) | 6.1–7.4 s |
| `go test ./...` | 76 packages ok, 0 failed |

Self-scan of this repo: 62 findings, **55 unique fingerprints — 7 duplicates**,
60 carrying a `suppressed` status. The duplicate count is the Phase 5.2
structural-deduplication number; it is not zero today and it is worth watching
as flow identity spreads beyond `core/attack`.

## What this baseline does not measure

Recorded explicitly, because a baseline whose gaps are unstated reads as
completeness:

1. **Rule-level narrowing has no refutation corpus.** Every case in
   `refutation-suite` guards a *refiner* — lexical context, constant analysis,
   sanitizer recognition, flow identity, wrapper reachability, value semantics.
   None guards a *rule* being narrowed by its own applicability conditions, and
   the corpus contains no IaC sample at all. The three refutations merged in
   the week before this run — #582 replica preconditions (65 findings), #583
   probes off batch workloads (14), #585 `@sh` as a shell sanitizer (a taint
   class no pinned repo contains) — **none of them could have been caught by
   Gate A**, and #583 and #585 could not be witnessed by the rule-diff corpus
   either at the moment they merged. Milestone 0.3.
2. **Negative deltas are reported, not accounted for.** `scripts/rule-diff.sh`
   prints per-rule before/after counts across ten pinned repos and exits 1 as a
   `::notice`. Nothing requires a reason for a drop, and nothing fails when one
   is unexplained. Milestone 0.4.
3. **Plugin matrix not re-run.** The Q3 figure — 0.771 with `api-abuse` 0.2.3,
   whose API-ABUSE-001 has never scored a true positive on any corpus — stands
   unremeasured. It should be re-measured, not re-quoted.
4. **No unevaluated rate.** There is no denominator today for "what fraction of
   propositions this scan did not evaluate", because the scan output carries no
   proposition-level evaluation state. Phase 1.
5. **Path coherence is unguarded but currently clean.** A probe over
   `builtinBaseIaCRules()` counted 185 rules, 31 reaching the structural
   absence path, and **0 setting a structural-only field while falling through
   to the regex path**. Nothing at load time would reject one. Milestone 0.5.
6. **No wrong-PREVENTED rate.** `PREVENTED` is reachable only through Gate B's
   single suppressible case; the metric exists but has one observation.
