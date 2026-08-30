# Evidence ledger cardinality budget — A3

Milestone A3 of `docs/design/evidence-native-nox.md`. It answers the one
question that had to be settled **before** the kernel work starts, because it
decides the shape of what gets built: can an evidence ledger be carried inline
on every `Finding`, or must it live out-of-band and be referenced?

The roadmap budgets per-stage analysis cost. Nothing budgeted the ledger. At
the scale nox has actually reached, that omission decides the architecture.

## Method

`TestLedgerCardinalityBudget` in `core/findings/ledgercost_test.go`. It builds
200,000 findings shaped like real secrets-rule output — rule ID, a realistic
path, message, fingerprint, and the `cwe`/`owasp` metadata nearly every finding
carries — and measures live heap with and without a three-claim ledger
attached.

Three claims is the **floor**, not a worst case: the observation that produced
the finding, the lexical context that survived refutation, and one refuting
claim that lost. A dependency finding carrying an advisory, a version match and
a reachability path will hold more.

Projections use 5,698,790 findings — the `llama_index` run in
`docs/benchmarks/2026-Q2`. That is not a round number chosen for effect; it is
the largest single-project result nox has produced.

```bash
go test ./core/findings/ -run TestLedgerCardinalityBudget -v
```

## Result

| | Bare finding | + 3-claim ledger | Delta |
|---|---:|---:|---:|
| Live heap, per finding | 656 B | 1,248 B | +592 B (1.90×) |
| Projected at 5,698,790 findings | 3.48 GiB | **6.62 GiB** | +3.14 GiB |
| Serialized (JSON) | 385 B | 964 B | 2.50× on disk |

## The budgets, and why there are two

**Ratio ≤ 4.0× — passes at 1.90×.** This catches an order-of-magnitude mistake
in the ledger's own representation. A ledger costing several times the finding
it annotates is not an enrichment, it is the payload. The current model is not
that; the kernel's `Claim` and `Provenance` are reasonably shaped.

**Absolute projection ≤ 6.0 GiB — fails at 6.62 GiB.** This is the one that
binds, and it is why the ratio alone is misleading. nox has already scanned a
project where the *bare* finding set projects to 3.48 GiB. A 1.9× multiplier on
an already-large number is what pushes a scan past the memory of an ordinary CI
runner: a hosted GitHub runner offers 7 GB, less whatever the OS and Go
toolchain hold.

## Decision

**The ledger is not carried inline on `Finding` unconditionally.** Track C
(C1) is designed against a reference, not a value.

Two acceptable shapes, in preference order:

1. **Out-of-band, keyed by fingerprint.** The ledger lives in a side store the
   `Finding` references. Peak memory is bounded by what a consumer actually
   asks for rather than by the finding count, and `findings.json` keeps its
   current size for consumers that do not want reasoning.

2. **Dropped above a threshold, and the drop recorded as a degradation.** If a
   scan is large enough that even a side store is unaffordable, ledgers may be
   omitted — but never silently. `degrade.Kind` exists for exactly this, and
   the doctrine is already written into it: *reporting an unverified run as
   verified is the same error as reporting an unexercised check as an
   all-clear*. A finding whose reasoning was discarded must not read like one
   that never had any.

What is **not** an acceptable answer is shrinking the ledger until the number
fits. The claims are the product.

## The gate arms itself

The absolute budget is not enforced today, because `Finding` carries no ledger
and nothing is broken. But it is not a comment either.

`findingCarriesLedger()` inspects `findings.Finding` by reflection for a field
of type `evidence.Ledger`. While there is none, the test logs the constraint
and passes. The moment that field appears, the budget becomes a hard failure —
on the commit that introduces it, not on a later one where someone remembers to
turn the check on.

Verified both ways: adding the field temporarily makes the test fail with the
projection and the reason; removing it returns to green.

## What this does not measure

Wall-clock. The spike measures memory because memory is what forces the design
decision; a per-stage latency budget is Track E's instrumentation (E4), against
the real pipeline rather than a synthetic one. Serialized size is reported here
because `findings.json` round-trips through the scan cache, but it is a
secondary constraint — disk is not what runs out at six million findings.
