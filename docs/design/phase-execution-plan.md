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
| **1.3** | Default `policy.uncertainty` to a value that does not treat unevaluated as clean | uninstalling an analyzer cannot turn a failing scan green **by default**, not only when configured | |

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

**Gate:** B (unevaluated honesty). 1.3 must ship with a corpus case where a
capability is removed and the scan goes from pass to fail. 1.2's own Gate B case
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

| Milestone | Work | Exit |
|---|---|---|
| **2.1** | Move degradation/baseline-drift/capability-loss gating into `core/policy`; the workflow calls it | all consumers inherit identical semantics; the bash shrinks to an invocation |
| **2.2** | Per-claim competence: attach `capability.State` + `reach.Limitation` to the claim, not the run | one scan legitimately holds different competence states for different findings |
| **2.3** | A negative claim that met an unmodelled construct cannot render unqualified | reports and API expose scope on every negative |

**Size:** medium. 2.2 touches every refiner that records a claim.

**Gate:** B, and D for 2.3 — an unqualified negative is how absence of evidence
becomes evidence of absence.

---

## Phase 3 — Typed propositions

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

| Milestone | Work | Exit |
|---|---|---|
| **3.1** | Audit the eight kinds against Gate C: every subject needs a fixture distinguishing it from its neighbours | no subject survives without a distinguishing case |
| **3.2** | Make the ledger authoritative for one family end to end — secrets is the candidate, it has the most refiners already recording | an advisory about a package cannot become the strongest evidence for exploitability |
| **3.3** | Polarity already exists; wire `REFUTES` from the refiners that currently record `Unknown` | missing evidence is never `REFUTES` |
| **3.4** | Lifecycle is shipped (#H); verify retraction reaches the scan path, not only intel | a withdrawn claim stops contributing |

**Size:** medium-large. 3.2 is the first real promotion and the first place a
user-visible finding changes shape.

**Gate:** C. Also the first point where Gate A earns its keep on a
non-rule refutation.

---

## Phase 4 — Central adjudication

**Exists.** `core/adjudicate` is built and runs **shadow-only**, producing a
divergence report: on the precision suite, 15 of 37 findings diverge, all
over-claimed. `findings.Finding.Exploitability` already exists in the output
schema. The package's own doc is explicit that the judgement is by explicit
state transitions rather than a risk score, "because a verdict a developer can
dispute is worth more than one they can only accept".

**Missing.** It is not authoritative. Nothing gates on it.

| Milestone | Work | Exit |
|---|---|---|
| **4.1** | Promote the adjudicator: `Exploitability` populated on every finding, analyzers stop deciding | analyzers no longer independently decide final truth |
| **4.2** | `PREVENTED` reachable only from positive, deterministic, scope-sound refutation | absence of evidence cannot produce `PREVENTED` |
| **4.3** | CI gates on adjudicated state alongside severity | a scan cannot go greener by losing capability |

**Size:** large — this is the flip. The 15 known divergences must each be
explained before promotion, not after.

**Gate:** D, and this is the phase Gate A was built for. Every divergence
resolved downward is a finding a user stops seeing.

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
graph identity beyond `FlowID`. Structural deduplication is partial — the
2026-09 self-scan still shows **7 duplicate fingerprints out of 62 findings**.

| Milestone | Work | Exit |
|---|---|---|
| **5.1** | Bind findings to symbols/nodes/edges/paths, not just flows | a finding can reference the path that established it |
| **5.2** | Structural dedup over flow identity | TRIAGE-002 solved by identity, never by deleting a detector |

**Size:** medium. 5.2 has a measurable target already: 7 → 0 duplicates on the
self-scan.

**Gate:** A — `r5_two_distinct.py` exists precisely because two sinks sharing a
source are two vulnerabilities.

---

## Phase 6 — Progressive semantic refinement

**Exists.** `core/lexctx` (22 language scanners), `core/consteval`, and six
secrets refiners that record why they drop a candidate. #599 extended lexical
refinement to the IaC path.

**Missing.** Stage accounting. Nobody can currently say how many candidates a
rule family generated, how many were refuted, and at what cost.

| Milestone | Work | Exit |
|---|---|---|
| **6.1** | Reclassify the noisiest regex families as candidate generators | a rule at precision 0.000 is not carried as a detector |
| **6.2** | Extend cheap refutation to the families that lack it | measured precision gain per family |
| **6.3** | Stage accounting: candidates in, refuted, promoted, unknown, latency | precision improves with no refutation-caused recall loss |

**Size:** medium. 6.1 has a named first target: `api-abuse` API-ABUSE-001 has
never scored a true positive on any corpus.

**Gate:** A on every family reclassified.

---

## Phase 7 — Reachability and applicability

**Exists.** `core/reach` already models the full ladder — `package_in_closure`,
`symbol_referenced`, `call_path_exists`, `attacker_entry_path_exists`,
`attacker_controlled_flow_exists`, `runtime_path_observed` — with a
`Limitation` type naming why a search stopped. Gate B has a corpus
(`testdata/reachability-suite`, exactly one suppressible case, asserted by
name).

**Missing.** One implementation, Go-only (`goVulnReachable`). No other
ecosystem has an equivalent, and `call_graph` / `entry_point` are the two
capabilities the installation reports as **not provided**.

| Milestone | Work | Exit |
|---|---|---|
| **7.1** | Implement `call_graph` and `entry_point` for one more ecosystem | `analysis-capabilities` reports 9 of 9 for that language |
| **7.2** | Every negative reachability claim records entry-point scope | no unqualified "unreachable" |
| **7.3** | Applicability composition into the ladder, surfaced per finding | one dependency CVE demonstrated present-but-non-impacting with scope-sound evidence, and one genuinely impacting |

**Size:** large per ecosystem. This is the phase with the most build and the
most product value — it is the SCA differentiator.

**Gate:** B, and each new ecosystem arrives with its unsupported case converted
to a determined one (the reachability-suite's own rule 4).

---

## Phase 8 — Verification hypothesis

**Exists.** `core/attack` has `Hypothesis`, `oracle.go`, a typed graph, and
`nox attack plan|run|replay|regress` with `--authorize` on the active verbs.

**Missing.** `nox scan` cannot emit a hypothesis. The handoff exists inside
`attack`, not across the passive/active boundary.

| Milestone | Work | Exit |
|---|---|---|
| **8.1** | `nox scan --emit-hypotheses`: subject, entry point, flow, attacker input, trigger condition, assumptions, oracle, missing evidence | a scan produces a structured active-testing question |
| **8.2** | Reproduction hierarchy: trigger / invariant / crash / security effect / exploit | a reproduced overflow does not claim RCE |
| **8.3** | Controlled-reproduction contract | removing any of the five conditions prevents `CONFIRMED` |

**Size:** medium. 8.3 is mostly assertion work over the existing evidence
kernel, which already enforces the deterministic gate.

**Gate:** E (active consent) — `nox scan` stays read-only throughout.

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
 └─ 2.2  per-claim competence                    medium   unblocks 3.3, 4.2
     └─ 3.2  ledger authoritative for one family medium   unblocks 4.1
         └─ 4.1  adjudicator authoritative       large    THE FLIP
             ├─ 4.2  safe PREVENTED              medium
             ├─ 5.2  structural dedup (7 → 0)    medium   independent after 4.1
             └─ 11.1 replay holds post-promotion small
```

Independent of that path, and startable now:

- **6.1** reclassify `api-abuse` — measured, self-contained, immediate precision gain
- **7.1** `call_graph` + `entry_point` for a second ecosystem — the largest product value, no dependency on the flip
- **8.1** emit hypotheses from scan — read-only, additive

Deliberately last: **9.3** (SMT), **12.2** (intel artifacts).

## What this plan does not claim

- No sizing here is a schedule. "Large" means it changes user-visible output or
  spans repos, not a week count.
- The 15 shadow divergences were measured on 2026-08-30 and have not been
  re-measured since #591, #599 and #600 changed IaC output. **Phase 4.1 must
  begin by re-measuring them**, not by reading that number.
- Phases 9 and 12 are the least grounded sections here, because the least
  exists to check them against.
