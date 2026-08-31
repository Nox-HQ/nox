# The verification chain — evaluation and plan

An evaluation of the proposed milestones A–M against what is on `main` as of
2026-08-30, in the same form as `docs/design/evidence-native-nox.md`: what
already holds, what is genuinely new, what I checked rather than assumed, and
where the plan and the code disagree.

## The invariant, stated first

> Evidence about an earlier proposition must never establish a later one.

The chain:

```
affected package → affected symbol → referenced by build → reachable from an
entry point → reachable from an ATTACKER-controlled entry point →
attacker-controlled data reaches the condition → trigger condition satisfiable
→ security invariant violated → effect reproducible → exploitability
demonstrated
```

Ten propositions. `applicability.Rung` currently has five — `present`,
`affected_version`, `symbol_used`, `call_reachable`, `attacker_reachable` —
and stops where the interesting half begins. Everything from "trigger condition
satisfiable" onward has no representation at all.

This invariant is not new to the codebase, and that is the strongest argument
for it. Typed subjects (Track B) exist because claims about different things
were aggregating into one bag. Track C5 found the same shape from the other
end: a `controlled_reproduction` claim is about what was reproduced, and letting
it speak for a whole finding is the error the type system was added to prevent.
Milestone G is the general form of what C5 hit specifically.

## What already holds

**K — the passive/active boundary.** Already an invariant. `nox scan` executes
nothing; `nox attack run/replay/regress` are ACTIVE, require `--authorize`, and
are never reachable from a scan. The `safe` profile selects an adapter with no
network capability, so the boundary is enforced by wiring rather than by policy.
The milestone's work is to make that permanent and tested, not to build it.

**F — the ControlledReproduction contract.** Four of the five conditions are in
`evidence.DeriveExploitability`: CONFIRMED needs an observed violation, a sound
control environment and a deterministic claim; an unreproducible or
unsound-environment violation is INCONCLUSIVE; a budget-exhausted run can never
be PREVENTED. What is missing is the acceptance criterion itself — a test
asserting that removing any ONE of the five prevents CONFIRMED. That is cheap
and worth having: the conditions are currently correct by construction and
nothing would notice if one were relaxed.

**B — refutation safety, mostly.** `capability.State.SuppressesFinding()`
returns true only for `Negative`, so `not_evaluated`, `unsupported`,
`timed_out` and `unknown` cannot suppress anything — that is "timeout ≠ safe"
and "analysis ran ≠ analysis was competent" already enforced at the one place
they could go wrong. `applicability.Refuted` requires `capability.Negative` and
downgrades everything else to Undetermined, constructed that way rather than
checked afterwards.

**C's stated acceptance criterion** — "capability status can differ per
proposition inside the same scan" — already holds. `Coverage` is keyed on
`(subject, capability)`, so two findings in one scan can and do carry different
states for the same capability.

## Four gaps I verified

**1. `reachable: false` is still a bare boolean.** Milestone A's acceptance
criterion is violated on `main` today. `core/analyzers/deps/deps.go` writes
`meta["reachable"] = "false"` with no scope, no entry-point set and no analysis
identity. Track G added a scoped representation beside it —
`applicability`, `applicability_reached`, `applicability_stopped_at`,
`applicability_because` — but did not remove the unscoped one, and the bare
boolean is what capability coverage reads. Two representations of the same fact,
one of them exactly the thing the milestone forbids.

**1b. The invariant is already violated on `main`, and I found it by running
the chain end to end against the live intelligence service rather than by
reading.**

`goVulnReachable` establishes one thing: the advisory's affected import path is
in the build's linked package set. On the ladder that is `symbol_used`. It is
written to `meta["reachable"]`, a name that reads as `call_reachable`, and then
`recordCapabilityCoverage` maps that boolean onto `capability.Reachability`.

So evidence about `symbol_used` establishes the `reachability` capability, which
is exactly what the invariant forbids. Two consequences, both live:

- A project declaring `require_capabilities: [reachability]` is told the
  question was answered when a weaker one was. The gate added in Track H reads
  `Coverage.Answered()`, and this counts.
- `reachable=false` sets the finding's severity to `info`, so the misnamed
  boolean drives severity directly.

Scanning a module with one vulnerable dependency through
`https://intel.klarlabs.de` produced 54 findings including this, on the same
finding, at the same time:

```
reachable              = true
applicability          = undetermined
applicability_reached  = symbol_used
```

The scoped representation Track G added is honest — it says it got to
`symbol_used` and stopped. The unscoped boolean beside it says `reachable=true`,
and that is the field a dashboard or a triage script sorts on.

This is the strongest argument for doing A first, and for starting it by
deleting the boolean rather than adding scope beside it: Track G already added
the scoped form and left the unscoped one in place, and the two now disagree in
production.

**2. The refutation corpus has none of the hard cases.** Seven samples, all
lexical: comments, banners, constants, a sanitizer on another variable, two
distinct values, a wrapper, a placeholder. Nothing involving reflection, dynamic
dispatch, FFI, dynamic loading, or bounded analysis — which is precisely the set
B's acceptance criterion names, and precisely where a refutation is most likely
to be wrong. The corpus cannot currently fail in the way it exists to fail.

**3. A capability cannot say why it could not tell.** Six states, and `Unknown`
collapses every reason into one: unresolved dispatch, reflection, FFI, a bounded
loop, a solver limit, an unsupported framework. `nox why` therefore reports "the
analysis ran and could not determine anything" and stops, when the useful
sentence is "unresolved interface dispatch on flow 931". This is Milestone C's
real content — not the per-proposition structure, which exists, but the reason.

**4. Two commands are called replay and guarantee different things.**
`nox attack replay` re-runs an attack against a target; `nox replay` (Track I,
landed today) re-derives verdicts from an evidence artifact and touches nothing.
The first is best-effort because nox does not control target state; the second is
deterministic. Milestone H's acceptance criterion — never claim execution
reproducibility where only adjudication reproducibility is guaranteed — has a
naming collision working against it before the audit even starts.

## What the end-to-end campaign established

Run on five repositories across four languages (Go, Python, Rust, TypeScript),
plus a module with a real vulnerable dependency against the live intelligence
service.

- **Determinism holds.** Fifteen scans, three per repository: `findings.json`
  and the evidence artifact are byte-identical within each repository once the
  generation timestamp is excluded.
- **Replay reproduces every verdict** on every repository, before and after two
  rule changes.
- **The MCP surface works on real code.** `why` answers all eight questions and
  the twelve-character fingerprint selector resolves; `analysis_capabilities`
  reports five to six capabilities per repository that were provided and never
  asked — which is the number an agent previously had no way to see.
- **The intelligence path works end to end.** `/v1/querybatch` against the live
  service returns advisories carrying `ecosystem_specific.imports`, the
  applicability ladder engages on them, and a genuinely unaffected advisory
  reaches `not_impacting` with the reason recorded.

**Subject isolation holds**, which matters for Milestone G. `Ledger.counted`
requires exact subject equality including `Kind`, so a claim about a flow cannot
contribute to a verdict about a candidate. G therefore needs new subject kinds
for the reproduction levels, not new aggregation rules.

## Three cautions on the plan itself

**E's vocabulary must be a separate axis, not a widening of Exploitability.**
`FEASIBLE / INFEASIBLE_WITHIN_SCOPE / OBSERVED / VIOLATED / REPRODUCED /
UNKNOWN` describes what a verification PRODUCER established. `Exploitability`
describes where a finding sits in its validation lifecycle. Track C3 rejected
folding conflict into Exploitability for exactly this reason: INCONCLUSIVE means
"execution occurred and could not decide", and giving one state two meanings
leaves a reader unable to tell which applies — across a repository boundary,
since the intelligence service derives from the same function. Verification
results should follow conflict's precedent and get their own field.

**G is C5's finding generalised, and C5's measurement should inform it.** C5
measured that adjudicated confidence caps at MEDIUM for a static scan, because
`HIGH` needs strength 70 and nothing static reaches it. The reproduction
hierarchy has the same shape one level up: `KindControlledReproduction` at 85
should confirm the proposition it is attached to and nothing above it. The
mechanism already exists — typed subjects — so G is largely a matter of minting
the subject kinds (`TriggerCondition`, `InvariantViolation`, `Crash`,
`SecurityEffect`, `Exploit`) and refusing to aggregate across them.

**A before everything else, because four later milestones depend on its
vocabulary.** D's hypothesis carries a candidate path; E's results are scoped to
a model; I's UNSAT refutes a path "under model M, abstraction A, bounds B"; L
reasons about which evidence is missing. None of those can be expressed without
A's scope object. Building them first would mean four places inventing their own
notion of scope, which is the cross-adapter duplication problem in a new
costume.

## Milestone A — landed

`core/reach` is the vocabulary: six levels from `package_in_closure` to
`runtime_path_observed`, a `Scope` carrying the analysis, capability,
entry-point set, build identity and limitations, and three outcomes.

**The asymmetry is enforced at construction, not checked after.** `Establish`
requires a witness — a reachability claim with nothing to point at is an
assertion. `Refute` requires a scope with no limitations and *refuses* otherwise,
returning `Undetermined` carrying the same limitations. An analysis that hit
unresolved dispatch, reflection, FFI or a budget has not shown that nothing
reaches the sink; it has shown it did not find one. That is "UNSAT on path P ≠
all paths impossible", held where the value is built, because a `Result` in the
wrong state is a value something can read.

**Milestone C is folded in**, as planned. `Limitation` names ten reasons an
analysis stops being able to speak for a whole program, each with a sentence an
operator can act on. A capability state of `unknown` collapsed all ten into one
word.

**The violation is closed.** `meta["reachable"]` is gone. The deps analyzer
emits `reach_level` / `reach_outcome` / `reach_scope`, and coverage is recorded
against `symbol_resolution` — the level `go list -deps` can speak for — rather
than `reachability`. Nothing in nox builds a call graph, so `call_path_exists`
is now unevaluated for every finding and reads that way in `nox why` and in the
capability gate.

Measured against the live intelligence service afterwards: of 54 dependency
findings, 29 carry `symbol_referenced` (18 established, 11 refuted) with the
scope travelling alongside, and none carries an unscoped boolean.

**Two tests were vacuous and the falsifications found them.** The first version
of the invariant test scanned a fixture module with no dependencies, so no
VULN finding existed, the mapping never ran, and it passed with the defect
restored. It now drives `recordCapabilityCoverage` directly. A third test
asserted nothing at all and was deleted rather than shipped.

## Milestone B — landed, with the caveat stated

`testdata/refutation-hard` holds five cases where a real flow exists and a
static analysis cannot follow it: reflection through `MethodByName`, dynamic
dispatch chosen from request data, a flow that only occurs after the eighth
loop iteration, a closure fetched from a map, and `plugin.Open`.

**The criterion is met.** Zero refutations, zero `capability.Negative`
conclusions, zero refuted reach outcomes across the corpus. nox states no
negative it has not earned.

**It is met by silence, not by design, and that distinction is the finding.**
One of the five produces a finding — the bounded loop, which the taint engine
handles. The other four produce nothing at all: no candidate, no claim, no
capability state. nox does not recognise that reflection defeated it; it never
formed a candidate. Milestone A shipped the `Limitation` vocabulary and nothing
emits it yet, so `nox why` cannot say "the analysis stopped at an unresolved
dispatch" and says nothing instead.

That matters for what a better engine would do. One that followed *part* of
these flows could conclude "no path" where it owes the reader "could not resolve
the callee", and the corpus would not catch it, because the claim would be about
a subject that exists. Emitting limitations is the remaining half of C and the
natural next step.

**The corpus was vacuous on its first build**, and the guard against that is now
the first test in the file. The initial fixtures used a bare function parameter
as the tainted value; nox produced zero subjects, so the acceptance criterion
passed while testing nothing. Giving them a real source made the engine reach
them, and one case firing is the proof that it does.

## Milestone C — landed in two halves

The first half shipped with A: `reach.Limitation` names ten reasons an analysis
stops being able to speak for a whole program, each with a sentence an operator
can act on.

The second half is `reach.Detect`, which makes something actually speak it.
Milestone B measured the gap precisely: four of five hard cases produced
complete silence, so nox had nothing to attach an explanation to and a reader
could not tell those files from clean ones.

**It is lexical, and that is a considered limit rather than a shortcut.**
Recognising these constructs properly means resolving types, which is the
analysis the construct defeats — the detector cannot be stronger than the thing
it reports on. What makes it safe is the direction of its error: a marker only
ever ADDS a limitation, which only ever weakens a claim. A false positive means
nox says "I may have missed something" when it did not, and a scope carrying a
spurious limitation can still `Establish`; it just cannot `Refute`.

**Dynamic dispatch is deliberately not detected.** `interface{}` and `any`
appear in ordinary Go constantly, so a marker for them fires on nearly every
file — and a limitation reported everywhere carries no information and trains a
reader to skip the field. That was measured, not assumed: the first version of
the marker list included `interface{}` and a bare `import (`, and reported
`dynamic_loading` on all five hard cases including the three that contain none,
because Go's own import block matched.

Measured after the fix: reflection and dynamic loading detected on the two cases
that have them, silence on the three that cannot be detected lexically, and
**21 of 794** of nox's own Go files flagged — 2.6%, quiet enough to mean
something. `TestDetectIsQuietOnNoxItself` keeps that executable with a ceiling
of 15%.

**The remaining limit, stated:** only findings are annotated. A file with no
finding gets no annotation, so B's four-of-five silence is only partly
addressed. Attaching limitations to files rather than findings needs a per-file
record the scan result does not carry, which is a larger change than this one.

**A usability bug surfaced while testing it.** `nox why . --offline` reported
`no active finding matches "--offline"`: Go's flag package stops parsing at the
first positional, so the flag became a selector. `nox show` splits flags from
positionals first for exactly this reason; `nox why` now does too. Found by
using the command, not by reading it.

## Milestone F — landed, and one condition rejected on the evidence

Four of the five conditions are enforced by `evidence.DeriveExploitability`, and
the kernel already walks them as a full cross product of every `RunOutcome`
boolean. Removing real execution, a violation, repeatability, sound control or
a deterministic oracle each prevents CONFIRMED.

**The fifth — "completed run" — was implemented, tested, and reverted.** Adding
`BudgetExhausted` as a sixth bar makes nox *less* accurate rather than safer: a
genuinely reproduced exploit would be downgraded to INCONCLUSIVE because the
runner later hit a time limit. Budget exhaustion says the run stopped early; it
does not say that what it already observed was wrong. That is precisely why the
kernel bars it for PREVENTED, where "we saw nothing" IS the claim and an
unfinished search is exactly why you might see nothing.

The kernel's existing cross-product test states the rule as
`Executed && Violated && Reproduced && ControlSound && deterministic` —
deliberately four conditions, not five — and it was right.

**The condition is satisfied structurally instead**, and that is now pinned
where the guarantee is actually made. `Reproduced` cannot be true unless the
determinism gate ran to completion, and every runner sets `BudgetExhausted`
only on a path that leaves before reaching that gate. Both runners are written
that way and neither said so, which is the same shape this programme has now
found five times: a rule enforced by the control flow of the current callers
rather than by the type, and therefore invisible to the next one.

This is the second time the roadmap's literal text has been wrong against
measurement, after C5. Both times the plan was right about the concern and
wrong about the remedy.

## Proposed order

The proposed A→M sequence is sound. Two adjustments, both from the gaps above:

1. **A first, and start by deleting the unscoped `reachable` boolean.** The gap
   is live, the fix is small, and it forces the scope object into existence
   against a real caller rather than a design.
2. **C's reason field early, folded into A.** Scope and incompleteness are the
   same conversation — "what did this analysis cover, and what defeated it" —
   and `nox why` already has the surface to report both. Splitting them means
   touching every analysis result twice.

Then B (the hard-case corpus), F (the five-condition test), G (subject kinds),
D, E, H, K as written. I, J, L, M after, in the proposed order.

**H should run before D**, not after. The hypothesis artifact is the handoff
between scan and attack, and designing it without knowing what `core/attack`
already persists risks a second artifact that overlaps the first — with two
things called replay already in the tree, that is a live risk rather than a
hypothetical one.

## What this does not change

Tracks A–I of the evidence-native programme stand. This roadmap extends the
chain past reachability; it does not revisit the propositions below it. The
decisions that cost measurement to reach — two confidence scales (C5), conflict
as its own axis (C3), the fingerprint contract (C4), capability gating on the
run rather than the installation (H) — are all upstream of this work and remain.
