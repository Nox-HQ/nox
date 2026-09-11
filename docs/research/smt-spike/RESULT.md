# Milestone I — result: do not adopt SMT

First measured 2026-08-31; **re-measured 2026-09-11** after six taint-recall
changes landed (#560, #561, #564, #566, #585, #616). The recommendation is
unchanged. Both measurements are recorded below, because the interesting thing
is which numbers moved and which did not.

## The number that settles it

| | 2026-08-31 | 2026-09-11 |
|---|---|---|
| repositories and corpora | 27 | 27 |
| findings of every kind | 2,151 | 1,683 |
| **taint flows** | **22 (1.0%)** | **39 (2.3%)** |
| flows with any guard between source and sink | 5 (23%) | 7 (18%) |
| guards found | 19 | 21 |
| languages producing flows | 2 | **7** |
| guards needing string theory or regex reasoning | **0** | **0** |

## Re-measured 2026-09-11

The first result closed with a re-run trigger: *"If the flow count rises by an
order of magnitude, re-run this measurement."* Six taint-recall changes landed
in the following ten days, so it was re-run. Flows rose **1.8×**, not 10×.

Two independent movements produce the 1.0% → 2.3% share, and they should not be
read as one:

- **Flows rose 77%** (22 → 39), from the recall work — composite literals,
  import and alias resolution, the argv exemption, same-statement sanitizers.
- **Findings fell 22%** (2,151 → 1,683), from the noise work over the same
  period. A smaller denominator flatters the ratio without any flow being found.

The change that matters more than either is **breadth**. The first measurement
found flows in two languages, Go and Python, and said so as a caveat: *"the
sample is Go and Python heavy — that is where nox's taint engine is strongest,
so it is the favourable case."* It is now seven: Go 15, Python 12, Shell 4,
Clojure 3, JavaScript 3, C# 1, Elixir 1. Go and Python are unchanged in absolute
terms (15 and 12 against 15 and 7); every additional flow came from a language
that previously produced none.

**And the guards are still not solver-shaped.** 21 guards, and the hardest thing
in the set is one interprocedural call:

| class | count | needs |
|---|---|---|
| equality | 13 (62%) | equality reasoning |
| length | 3 (14%) | interval reasoning |
| unclassified | 2 (10%) | `if !ok` — a boolean from a call the window cannot see |
| call | 1 (5%) | an interprocedural summary |
| interval | 1 (5%) | interval reasoning |
| environment | 1 (5%) | a model of the filesystem, not of strings |
| **string** | **0** | — |
| **regex** | **0** | — |

H3 — that the hard guards need modelling larger than the solving — remains
untested for lack of instances, now across **3,834 findings and two independent
measurements ten days apart**, spanning seven languages rather than two. Zero
string-theory guards and zero regex guards.

**Recommendation unchanged: do not adopt SMT.** Re-run again if flows reach the
low hundreds.

### Two defects in the instrument, found by re-running it

Neither changes the conclusion; both would have made the next re-run wrong.

- **59% of guards landed in `unclassified`.** The 2026-08-31 write-up had
  already reclassified the same samples in prose — *"`if i > 8` is an integer
  comparison; `switch`/`case` on a string is equality"* — which meant the
  instrument could not answer its own question without a human pass. A
  measurement kept executable so the question can be re-asked rather than
  re-argued has to be able to answer it. Three classes were added (`interval`,
  `environment`, and `switch`/`case` folded into `equality`) and the classifier
  is now asserted directly by `TestGuardClassificationIsExercised`, so it cannot
  drift into a shifting `unclassified` bucket that a reader attributes to the
  corpus. Unclassified fell from 13 to 2.
- **A comment was counted as a guard.** `condRe` matches the word `if` anywhere
  on a line, so `#   (b) Heuristic: if a Pod's env / configmap references
  another` scored as a conditional. Prose about a condition is not a condition —
  the same mistake nox fixed in its own IaC rules in #599, sitting in the
  instrument that measures them. Removing it dropped the guarded-flow share from
  21% to 18%.

---

## The original measurement, 2026-08-31

| | |
|---|---|
| findings of every kind | 2,151 |
| **taint flows** | **22 (1.0%)** |
| flows with any guard between source and sink | 5 (23%) |
| guards found | 19 |
| guards needing string theory or regex reasoning | **0** |

A constraint solver operates on flows. Across every corpus and 25 real
repositories, nox produced **22 of them**. Even a perfect solver, resolving
every flow it was handed, would be operating on one percent of nox's output.

That reframes the milestone's question. The bottleneck is not deciding whether
a path is feasible. It is that nox finds almost nothing to decide about.

## Against the hypotheses

**H1 — a minority of flows have guards. Confirmed, more strongly than
expected.** 17 of 22 flows (77%) have no conditional between source and sink at
all. For those, path feasibility is not what stands between the finding and a
verdict; nothing does.

**H2 — the guards that exist are simple. Confirmed.** Reclassifying the samples
the pattern set missed (`if i > 8` is an integer comparison; `switch`/`case` on
a string is equality), every guard found is an equality or an interval
comparison. Both are decidable by reasoning that is days of work, not a
dependency.

**H3 — the hard guards need modelling larger than the solving. Untested, for
lack of instances.** Zero string-theory guards and zero regex guards appeared in
2,151 findings across 27 codebases. The class of problem SMT is uniquely good at
did not occur.

## Against the milestone's success criteria

> vulnerability classes where constraint solving materially helps

None observed. The only class producing flows at all is command and prompt
injection, and 77% of those flows are straight-line.

> languages where modelling is practical

Go (15 flows) and Python (7). Both already first-class in the taint engine, so
this is a statement about where the engine works rather than where modelling
would be practical. A language with weaker support produces *fewer* flows, not
more, so this does not improve elsewhere.

> frequency of UNKNOWN

Not measurable without a solver, but bounded from above by the input: with 77%
of flows carrying no constraint, a solver asked about them returns UNKNOWN or
trivially SAT for reasons that have nothing to do with its power.

> modelling completeness requirements

The blocking one. `taint.Flow` records source, sink, file, function, language,
via-chain and sink role. It records **no path constraints, no guards, no
conditions**. A solver has no input today, and producing that input is
path-sensitive analysis — a larger project than the solver, undertaken to feed a
stage that runs on 1% of findings.

> cost per resolved hypothesis · false refutation rate

Not measurable without a solver in place. The spike declines to estimate them.
What it can say is that building one to measure them is not warranted by the
five criteria above.

> whether simpler approaches outperform SMT for common nox cases

Yes, decisively. Every guard observed is equality or interval. Interval and
equality reasoning covers the measured ground completely, with no dependency, no
modelling layer, and no unsoundness surface.

## Recommendation

**Do not adopt SMT.** Not because solving is not powerful, but because nox does
not currently have the problem it solves.

The honest next investment is **recall in the taint engine** — 22 flows across
27 codebases is the finding worth acting on. Constraint solving decides among
paths; nox's difficulty is finding paths at all. Milestone J (directed active
verification) rests on the hypothesis artifact rather than on a solver, and is
unaffected by this result.

If the flow count rises by an order of magnitude, re-run this measurement. The
test that produced it is committed, so the question can be re-asked rather than
re-argued. *(Done on 2026-09-11 — see above. It rose 1.8×.)*

## What was NOT built, and why that is the result

The milestone proposes a tiny verifier returning SAT / UNSAT / UNKNOWN
translated into nox propositions. It was not built.

The translation layer it describes — SAT supports feasibility of a path under a
model; UNSAT refutes a path under a model, abstraction and bounds, never a
finding — **already exists**, as `core/verify` from Milestone E. The domain model
is ready for a solver. What the measurement says is that there is not yet a
question for one to answer.

Building the solver first would have produced a working component with nothing
to consume it, and a number for cost-per-hypothesis computed over 22
hypotheses. Measuring first cost one afternoon and answered the question the
milestone actually asked.

## Caveats

- **The guard window is a heuristic**: conditionals in the 40 lines above the
  sink, not a real path. It both over-counts (branches not on the path) and
  under-counts (guards in a caller). It is good enough to establish that string
  and regex guards are absent, not to price them precisely.
- **22 flows is small in absolute terms.** The percentages are directional. The
  headline — that flows are 1% of findings — does not depend on the window
  heuristic at all.
- **The sample is Go and Python heavy.** That is where nox's taint engine is
  strongest, so it is the favourable case.
