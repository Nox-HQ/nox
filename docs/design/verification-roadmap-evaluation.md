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
