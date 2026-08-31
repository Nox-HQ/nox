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

## Milestones H and K — landed

### H, the artifact audit

The attack artifact turned out to be in better shape than expected. Hypothesis
identity, the action sequence with the exact payload sent, resolved
nondeterministic values, target identity, oracle result, determinism-gate tally,
termination status, profile and the evidence ledger are all persisted. What is
thin: the oracle DEFINITION is recorded only on a reproduced violation, control
attempts are not distinguishable from attack attempts within `Attempts`, and
environment assumptions and target *state* are absent.

**The acceptance criterion was violated, in its most literal form.** Every
trace carried a `ReplayCommand` — including hypotheses that never executed —
while `attack.Replay` refuses any trace without recorded evidence. The artifact
advertised a reproduction the tool declines. It is now set only where a winning
probe exists, and a `ReplayNote` says why not otherwise.

**The two replays are now distinguished where a reader meets them.** `nox
replay` re-derives verdicts from a stored ledger and touches nothing:
deterministic, because the ledger is the whole input. `nox attack replay`
re-fires the winning probe at a live target: best-effort, because nox does not
control target state, so a failed replay may mean the bug was fixed, the data
changed, or the service moved. A trace that cannot be re-fired now says the
verdict is still re-derivable, which is the distinction stated in the place it
matters.

### K, the boundary

Already enforced by wiring, and now by test. Three properties: every exported
entry point that takes a context and a run config refuses an unauthorized
non-safe profile; the safe profile allows no network and demands no
authorization it does not need; and **`core` — the scan pipeline — carries no
import of `core/attack`**, checked by parsing its imports rather than by
convention, because a convention is what a refactor does not consult.

The entry points are enumerated from the source rather than listed by hand, and
the count is asserted, so a fifth arrives as a failure rather than as silence.

## Milestones E and L — landed

### E, the verification vocabulary

`core/verify` is what a verification producer speaks: `FEASIBLE`,
`INFEASIBLE_WITHIN_SCOPE`, `OBSERVED`, `VIOLATED`, `REPRODUCED`, `UNKNOWN`. A
constraint solver is one producer; so is a fuzzer, a symbolic executor, an
attack adapter, a harness, a PoC runner, a property checker. Coupling the domain
model to SAT/UNSAT would make it a hostage to a tool choice that has not been
made.

**It is a separate axis, following C3's precedent.** `Exploitability` is a
lifecycle; a verification result is what one producer established about one
proposition under one model. Folding them would give `INCONCLUSIVE` a second
meaning, which is the mistake C3 declined.

The rules E states are structural rather than documented. The only refuting
outcome is named `INFEASIBLE_WITHIN_SCOPE` — there is no way to spell
"infeasible" without saying within what — and it refuses to be stated from a
scope with limitations, the same asymmetry `core/reach` enforces. A `Subject` is
required, so a result cannot be filed against nothing and reach everything by
sharing the zero subject, which is how a solver's answer about a path would
otherwise become a statement about a finding. And no outcome a solver can
produce maps to `KindControlledReproduction`: only something that ran and
recurred earns the kind that carries CONFIRMED.

It reuses `reach.Scope` rather than defining its own. A verification answer and
a reachability answer are bounded by the same kinds of thing, and two scope
types would drift. If Milestone M needs this in the kernel, that is the moment
to promote both — with a real second consumer, rather than guessing now.

### L, the verification-aware adjudicator

`adjudicate.MissingEvidence` answers the other half of the adjudicator's job:
not what the evidence supports, but what is absent. A verdict that stops
somewhere is not a dead end; it is a question with an unknown, and naming the
unknown turns a report into a next step.

The ordering is the substance — lexical context, constants, symbols, taint, call
graph, entry points, reachability, attacker reachability, dynamic verification —
cheapest first, because a multi-stage architecture spends cheap evidence first
and escalates only on what survives. Not every hypothesis should reach the
bottom.

Two distinctions it keeps. A capability that ran and could not tell leaves its
question **open**, because "somebody asked once" is not an answer. And
availability is part of the answer rather than a filter: a gap nothing on this
installation can fill is real and belongs in the list — it is why the verdict
stops where it does — but recommending it would send a reader to do something
they cannot. `nox why` now closes with the cheapest question something here
could actually answer.

## Milestone I — measured, and the recommendation is not to adopt

`docs/research/smt-spike/` carries the design, written before the measurement,
and the result.

Measured over 27 repositories and corpora, 2,151 findings: **22 taint flows,
1.0% of output.** A constraint solver operates on flows. Even a perfect one
would be working on one percent of what nox reports.

77% of those flows have no conditional between source and sink at all. Every
guard that does exist is an equality or an interval comparison. **Zero string-
theory guards and zero regex guards appeared anywhere** — the class of problem
SMT is uniquely good at did not occur.

The blocking criterion is modelling completeness: `taint.Flow` records no path
constraints, no guards, no conditions. A solver has no input today, and
producing it is path-sensitive analysis — a larger project than the solver,
undertaken to feed a stage that runs on 1% of findings.

**Recommendation: do not adopt SMT.** Not because solving is weak, but because
nox does not currently have the problem it solves. The honest next investment is
recall in the taint engine; constraint solving decides among paths, and nox's
difficulty is finding paths at all.

The verifier the milestone describes was deliberately not built. Its translation
layer — SAT supports feasibility of a path under a model, UNSAT refutes a path
under a model and never a finding — already exists as `core/verify` from
Milestone E. The domain model is ready for a solver; there is not yet a question
for one to answer. Building it first would have produced a working component
with nothing to consume it. Measuring first cost an afternoon.

The measurement is committed and re-runnable, so if the flow count rises by an
order of magnitude the question can be re-asked rather than re-argued.

## Milestone D — landed

The scan produces the hypothesis; the attack fills in the observation. Before
this, the attack rediscovered it, and badly: the runner seeded its ledger with a
single heuristic claim restating the rationale, while the scan had already
gathered better evidence and thrown it away — the ledger is out-of-band and dies
with the scan.

`Hypothesis` now carries the subject, the scan's ledger, the attacker-controlled
input, a suspected trigger condition, the expected oracle, the assumptions, and
the open questions. `groundingLedger` uses what it was handed instead of
rebuilding a thinner version, and carried claims keep their own subjects — they
are evidence about a candidate or a flow, not about this hypothesis's invariant,
and re-attributing them would be exactly the promotion G exists to prevent.

**The handoff is the Track I artifact.** `nox attack plan --evidence
evidence.json` reads what `nox scan --evidence-out` kept. That was not planned:
the artifact was built for replay, and it turns out to hold precisely what D
asks to cross the boundary — input identity, claims with provenance, subjects,
capability state. Measured on the `core/confirm` fixtures: without it a
hypothesis carries no subject, no claims and no unknowns; with it, a typed
subject, the scan's claims, six open questions and three assumptions.

**Assumptions are the part worth arguing with.** They name what nox did NOT
establish — that the entry point is attacker-reachable, that the static path is
the one that executes, that nothing showed the code reachable at runtime, that
the file carried an analysis limitation. Stating them is what lets a reader
disagree with the hypothesis rather than only with its result.

Everything is optional. A caller with no artifact gets what it had before, which
keeps `attack plan` usable from a findings file alone — its offline case.

The `trigger_condition` says "suspected" in the string, deliberately. nox
records no path constraints at all (see the SMT spike), so this is what the
scenario believes rather than something derived, and it should not read as a
precision nox does not have.

## Milestone M — the client half landed; the service half is a conversation

M's shape: intel should say more than "CVE-X affects package@version". It can
carry the affected symbol, a trigger condition, an affected configuration, known
entry points, a PoC hypothesis, an oracle, reproduction evidence, known
refutations and maintainer evidence — and **local nox then determines whether
those propositions apply here**.

That last clause is the whole milestone, and it was already half-built. The
reasoning shim refuses to record an advisory as evidence about a candidate, with
a comment saying why — an advisory is about a PACKAGE, and a finding is about a
CANDIDATE — and it closes "the package subject and its advisory claim belong to
Track G". That side was never built. `core/intel.ResearchProposition` is it.

**Three properties, each enforced rather than documented:**

Every claim is filed against `SubjectPackage`, and aggregation is per-subject,
so a maintainer-grade intel claim about a library leaves confidence about a
local candidate at LOW. That is the mechanism, not a convention: intel cannot
decide what affects a repository it has never seen.

The maturity ladder maps to evidence kinds, and an **unrecognised rung maps to
`KindHeuristic`** rather than to something in the middle. A vocabulary this
build does not understand is not evidence of anything, and reading it generously
is how a source's words become a consumer's verdict.

**Refutations survive transport.** A source that forwards only what supports its
conclusion cannot be checked. `nox-intelligence` currently has no way to record
a dispute — verified twice earlier in this programme — so this is the receiving
end being ready before the sending end exists.

`AppliesLocally` returns **questions, not answers**: does this build reference
the symbol, is this deployment configured that way, does this application expose
that entry point. Intel can say a symbol is dangerous; only the local build can
say whether it is referenced.

**The receiving loop is now closed** (`intel.FromRecord`): a served intelligence record becomes a `ResearchProposition`, its maturity read from the ledger's strongest live claim, its refutations carried across, its affected imports mapped into the local applicability questions. So what the service already sends — the evidence ledger, the corroboration count, the advisory's affected imports — is consumed as research the local scan tests, not as an opaque advisory it can only trust or ignore.

**Still not built, deliberately:** the researcher-intake side. Emitting the richer fields — a trigger condition, a PoC hypothesis, known entry points — means
extending the query payload and the disclosure model in a private repository,
and it is a design conversation before it is code — what a researcher may
assert, what publication requires, how an unpublished hypothesis reaches a user
without becoming a claim nox cannot support. The client is ready to receive
them, which is the half that can be got right in the open.

## Milestone J — landed on existing primitives, measured by the right metric

The milestone is explicit that this does not need a new fuzzer: *initially this
can work with existing attack primitives.* It does. `Run` already consumes a
plan of grounded hypotheses and directs probes toward each — the direction is
there. What was missing is the metric, and the metric is the milestone's real
content: **hypotheses resolved per unit of verification effort, not coverage.**

A coverage number cannot distinguish a harness that fired a million probes and
confirmed nothing from one that fired three and confirmed one. `Efficiency` can:
it reports hypotheses, attempts, and resolutions, and `AttemptsPerResolution` is
the headline — lower is a harness that decides more per probe.

**Resolution is three-plus-one-valued, and the shape is load-bearing.**
Confirmed, refuted, inconclusive, not-run. Only CONFIRMED is confirmed. PREVENTED
is refuted — the objective was not reachable — but the wording stays short of
"the target is secure". Inconclusive is the honest majority, not a harness
failure, and counting only confirmations would make the harness look worse the
more careful it was. Not-run cost nothing and must not dilute the denominator.

**A run that decides nothing says so.** `AttemptsPerResolution` returns zero when
`Resolved` is zero, and the CLI prints "this run decided nothing" rather than a
divided value a reader might take for a clean result — the same failure shape as
a regression suite printing "fix holds" for a target it never reached.

Measured end to end against the real HTTP harness: the vulnerable route resolves
2 hypotheses in 30 attempts, 15.0 attempts per resolution; the non-existent
route resolves nothing and reports it. The safe profile simulates, sends
nothing, and reports 0 attempts and "decided nothing", which is the honest
reading of a run that executed against no target.

**What this is not.** It is not an autonomous fuzzer firing at arbitrary
targets. It rests entirely on the existing `Run`, which requires `--authorize`
for any non-safe profile and selects a network-less adapter for the safe one —
the passive/active boundary K pins. J adds accounting and a metric on top of
that boundary, not a new way through it.

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
