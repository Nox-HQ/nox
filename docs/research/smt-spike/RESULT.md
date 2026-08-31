# Milestone I — result: do not adopt SMT

Measured 2026-08-31 over **27 repositories and corpora**, **2,151 findings**.

## The number that settles it

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
re-argued.

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
