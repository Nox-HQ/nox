# Precision baseline — 2026-Q3

The authoritative baseline for the evidence-native programme
(`docs/design/evidence-native-nox.md`, Track A / milestone A1). Every later
milestone is measured against these numbers.

It exists because the numbers everyone still quotes — 1.000 → 0.407 → 0.597 —
describe an architecture that no longer exists. They were measured when
`threat-enrich` and `triage-agent` emitted findings of their own. Both were
converted to enrichment-only in 0.3.0, and this run is the first measurement
taken with those releases actually installed.

## Reproducing

```bash
go build -o /tmp/nox ./cli
for d in testdata/precision-*; do /tmp/nox bench --precision "$d" --json; done
```

The plugin matrix uses a copy of `testdata/precision-suite` with a `.nox.yaml`
declaring `plugins.required`; plugins are opt-in per project, so the corpus as
committed measures core alone.

Machine-readable results: `precision.json`.

## Core engine, all corpora

No plugins. Offline. `nox bench --precision <corpus>` per directory.

| Corpus | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| precision-corpus | 5 | 0 | 0 | 1.000 | 1.000 |
| precision-suite | 37 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-clojure | 13 | 0 | 3 | 1.000 | 0.812 |
| precision-suite-cpp | 7 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-csharp | 6 | 0 | 0 | 1.000 | 1.000 |
| precision-suite-dart | 4 | 0 | 2 | 1.000 | 0.667 |
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
| precision-suite-shell | 13 | 0 | 2 | 1.000 | 0.867 |
| precision-suite-swift | 7 | 0 | 0 | 1.000 | 1.000 |
| **Total** | **203** | **0** | **7** | **1.000** | **0.967** |

Wall clock is 27–62 ms per corpus, single-run, including process start. The
corpora are small by design; they measure quality, not throughput. Throughput
lives in `docs/benchmarks/2026-Q2`.

### The seven misses

Every false negative is a taint-engine gap in one of three languages:

| Corpus | Rule | FN |
|---|---|---:|
| clojure | TAINT-002 | 2 |
| clojure | TAINT-006 | 1 |
| dart | TAINT-006 | 2 |
| shell | TAINT-002 | 1 |
| shell | TAINT-006 | 1 |

No other rule in any corpus misses anything, and no rule anywhere produces a
false positive. These seven are the recall debt the programme must not make
worse — Track A's refutation corpus (A2) exists so that later refinement
cannot quietly add to this column.

## Plugin matrix

Measured on `testdata/precision-suite` (37 expectations), one configuration at
a time.

| Configuration | TP | FP | Precision | Recall |
|---|---:|---:|---:|---:|
| core only | 37 | 0 | 1.000 | 1.000 |
| + threat-enrich 0.3.0, triage-agent 0.3.0 | 37 | 0 | **1.000** | 1.000 |
| + api-abuse 0.2.2 | 37 | 18 | 0.673 | 1.000 |
| + api-abuse 0.2.3 | 37 | 11 | 0.771 | 1.000 |
| all three (0.3.0 / 0.3.0 / 0.2.3) | 37 | 11 | **0.771** | 1.000 |

Recall is 1.000 in every configuration. No plugin has ever cost a true
positive; the entire question is noise.

## What this run establishes

**1. The enrichment conversion worked completely.** `threat-enrich` 0.3.0 and
`triage-agent` 0.3.0 together contribute **zero** false positives and zero
findings — precision stays at 1.000 with both installed. The plugins that
caused the 0.407 collapse no longer participate in scoring at all. This closes
the re-measurement the spec has been waiting on.

**2. Every remaining false positive is `api-abuse`.** It is a genuine detector,
deliberately kept as a `scan` tool rather than converted, so it is the only
plugin that can still move precision. Overall precision with the full plugin
set is **0.771**, against 0.597 previously.

**3. A correction to the record.** The spec states of the #28 fix: *"Its corpus
FPs went 17 -> 0."* That is not what 0.2.3 measures. API-ABUSE-001 fires 17
times on 0.2.2 and **10** times on 0.2.3 — the fix roughly halved the noise, it
did not eliminate it. API-ABUSE-002 adds one more in both versions. The rule's
precision is still 0.000: it has never scored a true positive on this corpus.

That gap between the recorded claim and the measurement is exactly the failure
mode the programme is built to remove. A rule at precision 0.000 is not
detecting anything — and under the target architecture it would not be silently
carried as a detector, it would be a candidate generator whose output has to
survive refutation before it reaches a finding. `api-abuse` is therefore a
first-order candidate for Track J's migration list, and API-ABUSE-001 should be
re-measured — not re-described — before any further claim is made about it.
