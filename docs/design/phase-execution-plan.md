# Phases 1–12 — execution plan

Companion to `docs/design/roadmap-refutation-safe.md`, which owns the ordering
and the principles. This document owns the work: for each phase, what already
exists in the tree, what is actually missing, the milestones that close the
gap, and the gate each must clear.

Written 2026-09-07, against `418d37a`. Every "what exists" claim below was
checked in the tree rather than carried over from an earlier plan.

---

## The finding that shapes this plan

**The primitives for most of Phases 1–12 are already built.** They were built
by the evidence-native programme (`docs/design/evidence-native-nox.md`), and
they work. What is missing is that the scan pipeline runs them in **shadow**:
the ledger is derived and discarded, the adjudicator's verdict is computed and
compared rather than published, capability coverage is held on `ScanResult` and
never reaches the artifact.

So this is not twelve phases of construction. It is mostly a **promotion
sequence** — turning machinery that already runs into output that is
authoritative — with three genuine build-outs (Phase 6 stage accounting,
Phase 7 beyond Go, Phase 9 trigger solving).

That changes the risk profile completely. Promotion is where a scanner starts
removing findings, which is why Phase 0 had to come first and why every step
below names the gate it must clear before it ships.

---

## Phase 0 — complete

| | | |
|---|---|---|
| 0.1 | current-state baseline | #586 |
| 0.2 | refutation corpus covering rule narrowing | #589 |
| 0.3 | semantic corpus coverage | #589 |
| 0.4 | negative-delta accountability | #592 |
| 0.5 | path-coherence validation | #593 |

Standing at `418d37a`: **231 TP / 0 FP / 0 FN** detection across 21 corpora,
**37 TP / 0 FP / 0 FN** refutation, **18 of 18** branches covered, 16 negative
deltas each with a recorded reason, 1,531 rules with 0 incoherent.

Three narrowings have since gone through the completed instrument (#591, #599,
#600). It caught all three, and in #599 it caught a filter that would have
shipped as a no-op.

---

## Phase 1 — Explicit evaluation state

**Exists.** `core/capability` already has the whole vocabulary: six states —
`not_evaluated`, `unsupported`, `timed_out`, `unknown`, `negative`, `positive`
— plus `Registry`, `Coverage`, and nine declared capabilities of which seven
are provided (`call_graph` and `entry_point` are not). `ScanResult` carries
`Coverage` and `Capabilities`. `policy.require_capabilities` and
`--fail-on-degraded` already fail a scan that lost a capability at runtime.

**Missing.** 1.3 only. `report.Meta` now carries the capability matrix (#602).

| Milestone | Work | Exit | |
|---|---|---|---|
| **1.1** | Nothing — the states exist and are used | already met | ✅ |
| **1.2** | `capabilities` on `report.Meta` from `ScanResult.Coverage`; SARIF `invocations[].toolExecutionNotifications` for the same | two scans differing only by analyzer availability are not byte-identical | ✅ #602 |
| **1.3** | Default `policy.uncertainty` to a value that does not treat unevaluated as clean | uninstalling an analyzer cannot turn a failing scan green **by default**, not only when configured | ⚠️ partial #618 |

1.2 landed larger than "a struct field and a serializer" for one reason worth
carrying forward: the four adapter sites each set `Degradations` by hand, and
the MCP server had already shipped three that forgot. Adding capability coverage
as a fifth field to remember would have re-run that experiment with a worse
payload — an omitted degradation list reads as missing information, an omitted
capability matrix reads as a scan that asked everything. So the derivation moved
into `ScanResult.JSONReporter` / `.SARIFReporter`, and the conformance guard now
pins the constructor rather than the assignments.

**Size:** 1.3 is a default flip and needs a deprecation note — it can fail scans
that pass today.

**1.3 shipped the half that is defensible, and its stated exit is not met.**

`policy.uncertainty` now defaults to `fail` where a requirement is declared,
which §1.5.3 specified as legitimate "only after a release where the warning
names the flag" — that was 1.32.0, and two releases have shipped since. The
premise the code gave for waiting is also gone: it named three capabilities with
no implementation, and `core/callgraph` filled the last of them.

**It does not meet the exit, and cannot.** The exit says "by default, not only
when configured", and this gate reads `require_capabilities`, which is empty by
default — so flipping the mode is a no-op for every repository that has not
opted in. Meeting the exit literally needs something that acts with no
configuration at all, and the code argues persuasively against the obvious
version: "fail on any gap" turns every build red, and a gate everybody disables
protects nothing.

What would meet it is a comparison against history — a capability that answered
last time and does not now — which nox has nowhere to keep except the baseline.
That is a design, not a default, and it is not this milestone.

**Gate:** B (unevaluated honesty). The corpus case 1.3 asked for —
a capability removed, the scan going pass to fail — exists as
`TestUnmetRequirementFailsByDefaultAndNamesTheFlag` for the declared case only. 1.2's own Gate B case
is `TestLosingAProviderChangesTheArtifact`: an installation without the taint
engine used to write a byte-identical `findings.json` to one that had it and
found nothing.

---

## Phase 2 — Competence moves into core

**Exists.** `core/degrade` (11 kinds, thread-safe collector) and
`core/capability` are both core-owned, so CLI, MCP and LSP already inherit the
same semantics for "did not run".

**Missing.** The *gate* logic still lives in workflow YAML — the shared
`klarlabs-studio/.github` gate computes degradation checks, net-new
critical/high, and baseline-present-but-dead detection in bash. Every consumer
that is not that workflow re-implements or omits it. And competence is
per-scan, not per-claim: one scan cannot yet say "taint ran, but hit an
unmodelled construct on *this* path".

| Milestone | Work | Exit | |
|---|---|---|---|
| **2.1** | Move degradation/baseline-drift/capability-loss gating into `core/policy`; the workflow calls it | all consumers inherit identical semantics; the bash shrinks to an invocation | |
| **2.2** | Per-claim competence: `capability.State` + `reach.Limitation` on the claim, not the run | one scan legitimately holds different competence states for different findings | ✅ #605 |
| **2.3** | A negative claim that met an unmodelled construct cannot render unqualified | reports and API expose scope on every negative | |

2.2 landed as competence **profiles**: every finding names the set of questions
that went unanswered about it, and the sets are grouped because competence
varies by (language × analyses) class rather than by finding — measured, 53
findings resolve to 4 profiles and 62 to 3.

It also surfaced a live defect (#603). `goSymbolReferenced` returns `ok=false` for
every UNDETERMINED outcome, and the deps analyzer wrote its reach metadata only
when `ok` was true. So an advisory with no `ecosystem_specific.imports` — the
common case, since only the Go vulndb populates it — produced a finding with no
reach annotation at all, the capability matrix read it as never-evaluated, and
the `Undetermined` arm of the switch that maps it was unreachable code. The
reachability suite had declared `want_state` in every fixture since it was
written, and nothing asserted it.

**Size:** medium. 2.2 touched the deps analyzer, `core/capability`, the finding
schema and both reporters.

**Gate:** B, and D for 2.3 — an unqualified negative is how absence of evidence
becomes evidence of absence.

---

## Phase 3 — Typed propositions

3.1 audits **thirteen** kinds, not eight — the kernel grew
`SubjectTriggerCondition`, `SubjectInvariantViolation`, `SubjectCrash`,
`SubjectSecurityEffect` and `SubjectExploit` for the reproduction hierarchy
since the plan was written. nox constructs five of them. The audit is pairwise
across all thirteen with a shared ID, because two subjects differing only by
kind are the case a string-keyed implementation gets wrong, and the count is
pinned so a kind added upstream must be examined rather than inherited.

**Exists, in the kernel.** `nox-core/evidence` v0.2.1 already ships
`SubjectKind`, `Subject`, `Relation`, `Polarity` (`SUPPORTS`/`REFUTES`/
`UNKNOWN`), `Status` (supersession, retraction) and `Authority`. Eight subject
kinds including `SubjectCandidate`. Aggregation is subject-partitioned, and
`failclosed_test.go` pins that no quantity of non-deterministic claims reaches
`ConfidenceConfirmed`.

**Missing.** Use. The scan pipeline derives a shadow ledger, and `core/scan.go`
computes subjects via `SubjectForFinding` — but the finding a user reads is
still authored by an analyzer, and nothing downstream reasons over the
proposition chain.

| Milestone | Work | Exit | |
|---|---|---|---|
| **3.1** | Audit the subject kinds against Gate C: every subject needs a case distinguishing it from its neighbours | no subject survives without a distinguishing case | ✅ #607 |
| **3.2** | Subject-scoped adjudication across the scan and attack paths | an advisory about a package cannot become the strongest evidence for exploitability | ✅ #607 |
| **3.3** | Polarity already exists; wire `REFUTES` from the refiners that currently record `Unknown` | missing evidence is never `REFUTES` |
| **3.4** | Lifecycle is shipped (#H); verify retraction reaches the scan path, not only intel | a withdrawn claim stops contributing |

3.2 landed as the exit property rather than as the secrets refactor that was
its proposed vehicle. Every derivation in `core/adjudicate` and `core/attack`
now names the proposition it decides, and a guard refuses the subject-blind
form. The secrets ledger becoming the authority for what is reported is a
user-visible change to what a scan outputs and belongs with 4.1, not ahead of it.

**Size:** the property was small; the promotion it guards is not.

**Gate:** C. Also the first point where Gate A earns its keep on a
non-rule refutation.

---

## Phase 4 — Central adjudication

**Exists.** `core/adjudicate` is built and runs **shadow-only**, producing a
divergence report: on the precision suite, **17 of 53 findings diverge — 16
over-claimed and one under** (re-measured 2026-09-07). Exploitability is now
derived subject-scoped (#607), which is the 3.2 exit property. `findings.Finding.Exploitability` already exists in the output
schema. The package's own doc is explicit that the judgement is by explicit
state transitions rather than a risk score, "because a verdict a developer can
dispute is worth more than one they can only accept".

**Missing.** It is not authoritative. Nothing gates on it.

| Milestone | Work | Exit | |
|---|---|---|---|
| **4.1** | `Exploitability` populated on every finding | analyzers no longer independently decide final truth | ✅ |
| **4.2** | `PREVENTED` reachable only from positive, deterministic, scope-sound refutation | absence of evidence cannot produce `PREVENTED` | ✅ |
| **4.3** | CI gates on adjudicated state alongside severity | a scan cannot go greener by losing capability | deferred, see below |

4.1 turned out small, and the reason is worth recording because it also corrects
the plan. Exploitability is **not** derived from the evidence: the kernel
reaches POTENTIAL from the empty `RunOutcome` and returns before it consults the
ledger. So the value is a constant for any static scan, costs nothing to
compute, and gating it on `RecordReasoning` bought a distinction it could not
express. Measured across all three corpora: `POTENTIAL` on 95 of 95 findings.

What the gate cost was the thing that mattered — an ordinary `nox scan` wrote no
state at all, and a finding silent about never having been validated reads as a
stronger claim than it is.

`EvidenceConfidence` stays conditional, and the asymmetry is deliberate: it IS
derived from the ledger, and an empty ledger aggregates to LOW. Writing that
would assert nox weighed evidence it never collected.

Two documented claims were wrong and are corrected in place:

- `Finding.Exploitability` said POTENTIAL meant "static evidence exists and no
  attack path was constructed". The first half was never carried by the value.
- `ScanOptions.RecordReasoning` said a scan with it off produces byte-identical
  results to one with it on. That was already untrue when written — both
  adjudicated fields were gated on the flag.

**4.3 is deferred, and not for scheduling reasons.** Gating CI on the
adjudicated state is meaningless while the state is a constant: every finding on
every scan is POTENTIAL, so a gate on it either fails every build or none. It
becomes real when Phase 8 emits hypotheses (PLAUSIBLE) and Phase 10 runs them
(CONFIRMED / PREVENTED / INCONCLUSIVE). Until then the capability gate —
`policy.require_capabilities` and `--fail-on-degraded`, both shipped — is what
stops a scan going greener by losing capability, which is 4.3's actual exit.

**Size:** 4.1 and 4.2 were small. The promotion they were expected to require —
the ledger becoming authoritative for what is REPORTED — is the part that
changes findings and has not been done.

**Gate:** D. Gate A was expected to earn its keep here, and did not need to:
nothing in 4.1 or 4.2 removes a finding. Detection stayed 231/0/0 and refutation
37/0/0. It will be needed for the reporting promotion above.

**Warning carried from C5:** the plan's instinct here is to retire
analyzer-authored confidence entirely. Measured, that takes
`--min-confidence high` to zero findings on every project forever, because the
kernel's HIGH needs strength 70 and a static scan tops out at 40. The two
scales stay separate. See `nox-two-confidence-scales`.

---

## Phase 5 — Graph and flow identity

**Exists.** `findings.FlowID` is shipped and 18 flows are identified on the
corpus, every edge evidence-backed. `core/attack/graph.go` has a typed security
graph with path search.

**Missing.** The graph is confined to `core/attack`; the scan pipeline has no
graph identity beyond `FlowID`.

| Milestone | Work | Exit | |
|---|---|---|---|
| **5.1** | Bind findings to symbols/nodes/edges/paths, not just flows | a finding can reference the path that established it | |
| **5.2** | Identity, not deletion, decides what is one finding | TRIAGE-002 solved by identity, never by deleting a detector | ✅ #610 |

**5.2's stated target was a mismeasurement, and chasing it would have deleted
real findings.** "7 duplicate fingerprints out of 62 findings" counts
**suppressed** findings — 60 of the 62 on the self-scan are waived. Among active
findings there are **zero** duplicates. And of the seven, four are IAC-018 on
four *different* workflow steps: genuinely distinct findings sharing one digest,
because the v2 fingerprint is `sha256(rule_id, path, message)` and that rule's
message is a static description. Deduplicating them to zero would have deleted
three real findings — the exact failure the milestone's own exit criterion
names.

`FindingSet.Deduplicate` already implements the right rule and documents this
hazard: it keys on fingerprint **plus position**, because "two findings at
different positions are never duplicates".

What the measurement did surface is that the same hazard was unfixed one layer
over, where it is worse. `Baseline.Match` looked up by fingerprint alone, so
accepting one finding accepted every other occurrence in that file — including
ones added *after* the baseline was written. A newly introduced problem was born
baselined and `nox scan` reported `0 findings`. Fixed in #610 by consuming one
entry per finding, which keeps what v2 bought: a finding that moves still
matches.

**Size:** small, once measured. The lesson is the plan's, not the code's — the
number had never been read past its total.

**Gate:** A — `r5_two_distinct.py` exists precisely because two sinks sharing a
source are two vulnerabilities. 5.2 ADDED findings rather than removing them, so
Gate A was not the binding constraint; the release note is.

---

## Phase 6 — Progressive semantic refinement

**Exists.** `core/lexctx` (22 language scanners), `core/consteval`, and six
secrets refiners that record why they drop a candidate. #599 extended lexical
refinement to the IaC path.

**Missing.** Stage accounting. Nobody can currently say how many candidates a
rule family generated, how many were refuted, and at what cost — which is both
the milestone and, as it turns out, the prerequisite for choosing a family to
reclassify at all.

| Milestone | Work | Exit | |
|---|---|---|---|
| **6.1** | Reclassify the noisiest regex families as candidate generators | a rule at precision 0.000 is not carried as a detector | blocked, see below |
| **6.2** | Extend cheap refutation to the families that lack it | measured precision gain per family | ✅ #616, #617 |
| **6.3** | Stage accounting: candidates in, refuted, promoted, unknown | precision improves with no refutation-caused recall loss | ✅ #615 |

**6.1's named target is not in this repository, and there is no core substitute
to reach for.** Both halves of that matter.

`api-abuse` is `nox-plugin-api-abuse`, a separate repo, and
`docs/design/rule-family-migration.md` already records the boundary: its
API-ABUSE-001 sits at precision 0.000 and "cannot be fixed from this
repository". Naming it as the first target of a milestone in this plan was an
error — the work belongs to that repo, or to the plugin contract that decides
what a plugin may emit.

Nor can a core family be substituted by picking one. Core scores **231 TP / 0 FP
/ 0 FN** across the detection corpora and 37/0/0 on refutation; the only two FPs
in the 2026-09 benchmark are artefacts of pointing `bench --precision` at
corpora that are deliberately not fire-rate scored, and that page already says
so. **No core rule is measurably a non-detector on any data nox currently
has.** Choosing one anyway would be choosing by intuition, which is the thing
this programme replaced.

So 6.1 is blocked on a measurement rather than on implementation, and the
measurement is named: per-rule precision on real repositories. `scripts/rule-diff.sh`
already scans ten pinned repos and reports per-rule counts, but counts are
density, not precision — nothing there says which of those findings are true.
Item 3 of the 2026-09 gap list makes the same point about the plugin matrix:
"it should be re-measured, not re-quoted".

**6.3 landed, and it named the families 6.2 is about.** Stage accounting needs
no precision labels, because it counts what the pipeline did rather than judging
it. On the precision suite:

| family | candidates | promoted | refuted | withheld |
|---|---:|---:|---:|---:|
| SEC | 52 | 12 | 8 | 32 |
| IAC | 6 | 3 | 3 | 0 |
| AI | 2 | 1 | 1 | 0 |
| TAINT | 30 | 30 | **0** | 0 |
| DATA / SLOP / VARIANT | 7 | 7 | **0** | 0 |

So **6.2's list is measured rather than guessed**: TAINT, DATA, SLOP and
VARIANT recorded no refutations at all.

**TAINT is answered (#616), and it was the second half of the question.** The
engine refines and recorded none of it — true of the ledger, false of the
engine. It now files a refutation for every sanitized flow it clears: 30
candidates and 0 refuted became **36 and 6** on the precision suite.

That change also cost a claim, which is the more useful half of the story. Three
sites suppress a flow, and only two of them are refutations. A sanitizer acting
on the VALUE is positive evidence that travels with it. An argument SHAPE that
is not dangerous — an argv exec, a parameterized query — says only that THIS
CALL is safe; the value is untouched and just as tainted. Recording the second
as a refutation conflated them, and
`TestNoUnearnedNegativeOnTheHardCorpus` caught it on `h2_dynamic_dispatch.go`:
an argv `exec.Command("echo", s)` on one line, an `sh -c` on another, and the
choice made by data the engine cannot follow. Refuting the first reads as
resolving the file. Only the two value-clearing sites record.

**The other three are done, and one of them by explanation rather than by code
(#617).**

**SLOP refutes six times more often than it reports.** SLOP-001 fires on an
import that resolves to nothing, so every check that RESOLVES one — standard
library, first-party module, private module, declared in a manifest — is a
refutation. Precision suite: 3 promoted, **18 refuted**. Refutation suite: 0
promoted, 5 refuted. None of it was recorded, so a family doing almost nothing
but refining looked like one doing none.

**VARIANT has exactly one refinement** — a signature's counter-pattern, which
drops a line carrying the shape of the fix rather than of the CVE. No committed
corpus exercises it, so it is asserted directly rather than from a corpus that
would report zero either way.

**DATA refines nothing, and that is the answer.** It is a pass-through to the
rules engine: every match becomes a finding, with no filter, exclusion or
counter-pattern anywhere in the analyzer. A family that genuinely refines
nothing SHOULD report zero, and the accounting reporting zero for it is the
instrument working rather than a family still to instrument. Pinned, so that if
DATA ever grows a refinement it fails rather than dropping silently.

The distinction that ran through all four: a `continue` for SCOPE — an
extension that does not match, a vendored path, an ecosystem with no extractor —
produced no candidate and refutes nothing. Only a drop that acts on a candidate
is a refutation.

The first thing it found was in IaC, and it was mine. Three filters added in
#599 and #600 — comments, kind references, artifacts-always — dropped findings
with a bare `continue`, which is exactly the pattern `core/reasoning` was built
to end: "the finding and the reason for dropping it both discarded in the same
statement". They removed findings on every scan while the accounting reported
IaC as refuting nothing. Fixed by handing each filter a recorder rather than
letting it reach for the store, so the recording cannot be present at one call
site and forgotten at another.

**Latency was dropped from the milestone deliberately.** It cannot go in the
artifact: `findings.json` is byte-identical across runs by contract, and a
duration is different every time. Cost belongs on stderr or in a benchmark, and
`TestNoTimingInTheAccounting` keeps it out.

**Size:** 6.1 remains unsized — it needs per-rule precision on real repositories,
which nothing yet produces. 6.2 and 6.3 are done.

**Gate:** A on every family reclassified.

---

## Phase 7 — Reachability and applicability

**Exists.** `core/reach` already models the full ladder — `package_in_closure`,
`symbol_referenced`, `call_path_exists`, `attacker_entry_path_exists`,
`attacker_controlled_flow_exists`, `runtime_path_observed` — with a
`Limitation` type naming why a search stopped. Gate B has a corpus
(`testdata/reachability-suite`, exactly one suppressible case, asserted by
name).

**Missing.** 7.2 and 7.3.

| Milestone | Work | Exit | |
|---|---|---|---|
| **7.1** | Implement `call_graph` and `entry_point` | `analysis-capabilities` reports 9 of 9 for that language | ✅ #613 |
| **7.2** | Every negative reachability claim records entry-point scope | no unqualified "unreachable" | already met |
| **7.3** | Applicability composition into the ladder, surfaced per finding | one dependency CVE demonstrated present-but-non-impacting with scope-sound evidence, and one genuinely impacting | |

**The plan's premise for 7.1 was wrong.** It read "one *more* ecosystem", but
`call_graph` and `entry_point` were provided by **nothing** — there was no
first. `core/callgraph` is it, for Go, in `core/callgraph`.

The design decision that matters is what it refuses to do. A syntactic graph
cannot see interface dispatch, function values, generics, embedding, reflection
or generated code, so **it never refutes**. Every `reach.Scope` it builds carries
a limitation, which makes `reach.Refute` decline to construct a negative from it.
Reporting "no call path" from a graph like that would be reporting a blind spot
as an all-clear — the one failure this whole model exists to prevent.

Measured on nox's own tree: 7,655 functions, **6** concrete entry points, and
witness paths that are real chains of call expressions, verified edge by edge
against the source. Two earlier versions were wrong and the measurement caught
both: counting every exported function as an entry point made 5,088 of 7,652
functions "entries" and every answer a trivial length-1 path; and treating a
length-1 path as `CallPathExists` turned "no caller found" into "a route
exists".

7.2 is met by construction rather than by new work: this analysis produces no
negative reachability claims at all, and the one that exists (`goSymbolReferenced`)
already refuses an incomplete scope and records `reach_limitations` since #605.

**Consequence to watch.** Every defined capability now has an implementation, so
`Registry.Missing()` is empty. That is true of the *installation* and misleading
alone — seven tests asserted "something must be missing" and each had to move to
asserting the property it actually cared about. `nox analysis-capabilities` now
prints its standing limits unconditionally, guarded by
`TestAFullMatrixStillStatesItsLimits`, because a full matrix with no caveat
reads as a full answer.

**Size:** large. This is the phase with the most build and the most product
value — it is the SCA differentiator.

**Gate:** B. `TestCallGraphNeverSuppressesAFinding` is the scan-level form: the
call graph may never reach a state that hides a finding, in any language. Per
finding, a language it cannot read reports `unsupported` rather than
`not_evaluated` — declaring a capability at installation level must not make a
Python finding read as a gap somebody could close.

---

## Phase 8 — Verification hypothesis

**Exists.** `core/attack` has `Hypothesis`, `oracle.go`, a typed graph, and
`nox attack plan|run|replay|regress` with `--authorize` on the active verbs.

**Missing.** `nox scan` cannot emit a hypothesis. The handoff exists inside
`attack`, not across the passive/active boundary.

| Milestone | Work | Exit | |
|---|---|---|---|
| **8.1** | `nox scan --emit-hypotheses`: subject, entry point, flow, attacker input, trigger condition, assumptions, oracle, missing evidence | a scan produces a structured active-testing question | ✅ #612 |
| **8.2** | Reproduction hierarchy: trigger / invariant / crash / security effect / exploit | a reproduced overflow does not claim RCE | already met |
| **8.3** | Controlled-reproduction contract | removing any of the five conditions prevents `CONFIRMED` | already met |

8.2 and 8.3 were already in the tree before this milestone started. The
hierarchy is enforced per subject by `evidence.DeriveExploitabilityAbout` and
audited across all thirteen kinds by #607; the five-condition contract is
`TestFailClosed_ConfirmedOnlyFromTheExactIntendedCombination` in the kernel plus
`TestACompletedRunIsSubsumedByReproduction` at the producer, with the PREVENTED
half added in #608.

8.1's value turned out not to be the fields — `nox attack plan` already built
every one of them — but **where** they come from. Getting the scan's evidence
onto a hypothesis previously meant `nox scan --evidence-out`, then
`nox attack plan --evidence`, rejoined by fingerprint. The artifact records
capability counts per SCAN, so `unknownsFromArtifact` hands every hypothesis the
same scan-wide list and says so in its own comment. In-process the coverage is
per-subject — what 2.2 built — so each hypothesis states the questions open
about ITS OWN subject. "Nothing established taint for this finding" is
actionable; "taint answered 30 subjects somewhere in this scan" is not.

**Gate E held, and cost a redesign.** The first implementation put the method on
`ScanResult`, which made `core` import `core/attack` — the exact thing
`TestTheScanCannotReachTheAttackPackage` forbids, in the same change that added
a test asserting Gate E. The guard caught it. The wiring moved to
`core/hypothesize`, a package ABOVE the pipeline that takes a finished
`ScanResult`, and the guard was extended to reject importing that from `core/`
too — otherwise it would have been a transitive route past a check that reads
only direct imports.

**Size:** small, given what existed.

**Gate:** E (active consent) — `nox scan` stays read-only throughout, and the
guarantee is structural: the pipeline cannot import the code that touches a
target, so it cannot execute one by accident.

---

## Phase 9 — Directed verification R&D

Nothing exists, and nothing should until Phase 8 emits hypotheses to direct.

| Milestone | Work | Exit |
|---|---|---|
| **9.1** | Lightweight trigger solving (input-to-state, taint-guided) | hypotheses resolved per unit compute, measured |
| **9.2** | Property-based typed generation | measured against 9.1, not assumed better |
| **9.3** | SMT spike **only** if a meaningful residual class survives | SMT demonstrates value over simpler techniques before becoming architecture |

**Size:** research. `core/smt_spike_measurement_test.go` already exists as the
measurement harness for 9.3.

**Gate:** F — agent or solver output creates hypotheses, never verdicts.

---

## Phase 10 — Active verification

Largely built: `nox attack` is the authorized half and `core/confirm` is the
earlier narrow loop. The work is joining it to Phase 8's hypothesis and keeping
one ledger.

| Milestone | Exit |
|---|---|
| **10.1** | passive/active boundary preserved — already true, keep it true |
| **10.2** | `nox attack` consumes a scan-emitted hypothesis |
| **10.3** | verification evidence enters the same ledger; no separate attack truth |

**Size:** small-medium, and mostly plumbing once 8.1 lands.

---

## Phase 11 — Replay and explainability

**Exists.** `core/replay` (artifact, build, replay) and `nox why`. 37/37
verdicts reproduced from the stored ledger.

**Missing.** Full scan reproducibility (9.4 in the old plan) is explicitly out
of scope: it needs the rule set, analyzer versions and advisory data
snapshotted, and each is its own problem.

| Milestone | Exit |
|---|---|
| **11.1** | adjudication replay — **already met** for the shadow ledger; must hold after Phase 4 promotion |
| **11.2** | execution replay, best-effort, with environment assumptions stated |
| **11.3** | every important result answers the six questions (observed / supports / refutes / not evaluated / means here / would change it) |

**Size:** small, if Phase 4 keeps the ledger intact.

---

## Phase 12 — Intel evidence network

**Exists.** `core/intel` and the vulnsource abstraction; intel is the default
on online scans, verified against OSV.

**Missing.** Intel distributes package/version records. The proposition model
is shared in `nox-core` but the wire format carries no affected symbol, trigger
condition, or reproduction evidence.

| Milestone | Exit |
|---|---|
| **12.1** | intel and local nox use compatible proposition semantics |
| **12.2** | structured research artifacts: affected symbols, trigger conditions, PoV metadata, refutations |
| **12.3** | publication safety — no quantity of heuristic observation substitutes for deterministic evidence |

**Size:** large, and cross-repo (nox, nox-core, nox-intelligence).

**Gate:** D and F. 12.3 is already enforced in the service's disclosure
statechart; the work is keeping it true as artifact types multiply.

---

## Sequencing

The critical path is **1.2 → 2.2 → 3.2 → 4.1**, because everything downstream
reads an adjudicated finding.

```
1.2  artifact carries capability coverage        DONE     unblocks 2.x
 └─ 2.2  per-claim competence                    DONE     unblocks 3.3, 4.2
     └─ 3.2  subject-scoped adjudication         DONE     unblocks 4.1
         └─ 4.1  adjudicator authoritative       DONE     small, not large
             ├─ 4.2  safe PREVENTED              DONE
             ├─ 5.2  identity, not deletion      DONE     target was a mismeasurement
             └─ 11.1 replay holds post-promotion small
```

Independent of that path, and startable now:

- ~~**6.1** reclassify `api-abuse`~~ — **not in this repository**, and no core
  family is measurably noisy on any data nox has. 6.3 landed as the instrument;
  **6.2 is the actionable successor**, with its four families now named by
  measurement
- **7.1** `call_graph` + `entry_point` for a second ecosystem — the largest product value, no dependency on the flip
- **8.1** emit hypotheses from scan — read-only, additive

Deliberately last: **9.3** (SMT), **12.2** (intel artifacts).

## What this plan does not claim

- No sizing here is a schedule. "Large" means it changes user-visible output or
  spans repos, not a week count.
- ~~The 15 shadow divergences were measured on 2026-08-30 and have not been
  re-measured.~~ **Done (#607).** The count moved to 17 of 53 and the "all
  over-claimed" half stopped being true: IaC rules author LOW while their static
  evidence aggregates to MEDIUM, so 1 of 17 on the precision suite and 14 of 19
  on the refutation suite run the other way. Phase 4.1 must handle both
  directions; a flip that only lowers confidence would hold those findings down.
  The numbers are now pinned by `TestDivergenceShapeIsMeasuredNotRemembered`,
  which fails when they move and says to re-measure rather than edit the
  constant.
- Phases 9 and 12 are the least grounded sections here, because the least
  exists to check them against.
