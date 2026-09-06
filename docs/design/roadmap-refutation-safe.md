# Best-in-class roadmap — refutation-safe revision

**Status: authoritative for roadmap ordering.** Where this document conflicts
with the sequence in `docs/design/evidence-native-nox.md` or `docs/roadmap.md`,
this one wins. Those two stay as, respectively, the record of what the
evidence-native programme built and found, and the release history.

Revision trigger: *The Refutation Gap*, 2026-09-06.

## North star

> Nox is a deterministic, evidence-driven security engine that detects broadly,
> progressively determines whether a condition actually impacts the
> application, preserves uncertainty, and can reproduce why every conclusion
> was reached.

Operating principle:

> **Analyzers observe. Evidence supports or refutes. Core adjudicates. Findings
> explain.**

Safety principle added by this revision:

> **Measure refutation before empowering refutation.**

## Why the ordering changed

The revision does not overturn the evidence-driven thesis. It supplies
production evidence for two failure modes the thesis predicted:

1. **Proposition confusion** — evidence about one fact silently establishes a
   broader conclusion.
2. **Absence reported as success** — an evaluation that never ran appears
   identical to a clean result.

Both were found repeatedly in nox and adjacent code: IaC rule applicability,
taint sanitization semantics, structurally ignored rule fields, matcher types
that loaded and matched nothing, corpus branches claimed but not exercised,
disabled CI whose checks stayed required, and empty-set success conditions.

The correction:

> **Ground-truth refutation measurement moves from a later validation
> investment to Investment 0.**

Before nox expands machine refutation through typed propositions, reachability,
negative evidence or automated `PREVENTED`, it must have instrumentation
capable of detecting a deliberately wrong negative conclusion.

A second north-star question joins the first:

> **How often did nox conclude that a security condition did not matter here —
> and was that negative conclusion correct?**

---

## Phase 0 — Refutation observability and benchmark safety

**Complete.** Ground-truth refutation measurement, a corpus that covers rule
narrowing as well as refiners, coverage that fails when a branch loses its last
fixture, negative deltas that must be argued in writing, and a loader that
refuses a rule whose declared semantics nothing reads.

| Milestone | Exit criterion | State on 2026-09-06 |
|---|---|---|
| **0.1** Current-state baseline | one authoritative baseline exists | **done** — `docs/benchmarks/2026-09` |
| **0.2** Refutation corpus | a deliberately wrong refutation fails CI | **done** — 23 cases over 11 branches, refiners *and* rule narrowing |
| **0.3** Semantic corpus coverage | removing the only fixture for a branch fails coverage | **done** — `bench.RefutationBranches`, 16 branches, `TestRefutationBranchCoverage` |
| **0.4** Negative-delta accountability | unexplained narrowing is rejected or reviewed | **done** — `scripts/rule-deltas.json`; rule-diff exits 3 and fails the job |
| **0.5** Path-coherence validation | no rule loads with behaviourally inert mandatory fields | **done** — `Rule.CheckCoherence`, wired into `validateRule` and guarded over all 1,531 built-ins |

### 0.1 — Current-state baseline

Precision, recall, findings added, findings removed, removals by reason,
duplicate findings, false-negative rate, rule-family coverage, scan latency.

Measured at `78439de`: **230 TP / 0 FP / 0 FN** across twenty detection
corpora, **10 TP / 0 FP / 0 FN** on the refutation suite, seven duplicate
fingerprints on a self-scan, seven of nine analysis capabilities provided.
The Q3 baseline's seven false negatives are closed, and the corpus annotations
that scored them are unchanged — the engine moved, not the ground truth.

### 0.2 — Refutation corpus

`testdata/refutation-suite` (10 cases, `TestRefutationSuiteRecall`),
`testdata/refutation-hard` (5 cases that must never reach `PREVENTED`), and
`testdata/reachability-suite` (Gate B, exactly one suppressible case).

**The gap, and its closure.** Every case used to guard a *refiner*. None
guarded a *rule* narrowed by its own applicability conditions, and there was no
IaC case at all — so #582, #583 and #585 each removed real findings with
nothing able to catch an over-narrowing. Milestone 0.3 added four rule-level
fixtures (`r8`–`r11`) covering the replica precondition, the workload-kind
narrowing, the kinds that stay governed, and the pipeline quoting producer.
The suite is 27 cases over 11 branches; `refutation-hard` contributes 5 more.

### 0.3 — Semantic corpus coverage

Corpus metadata asserts what is exercised: rule family, matcher path,
proposition, refutation branch, and the wrong reasoning the fixture catches.

The universe of branches lives in `core/bench.RefutationBranches` — in code,
where deleting a testdata file cannot reach it — and each fixture claims one
with a `nox-cover:` annotation. `TestRefutationBranchCoverage` fails when a
registered branch has no witness, when a claim names an unregistered branch,
and when a fixture sits in a corpus other than the one its branch declares. An
empty registry is an error rather than a pass.

**Falsified, not asserted:** deleting `r11_pipeline_unquoted.sh` leaves
`TestRefutationSuiteRecall` passing at 1.000 and fails coverage naming
`sanitizer-pipeline-producer`. That difference is the whole milestone.

### 0.4 — Negative-delta accountability

`scripts/rule-diff.sh` reported per-rule before/after counts across ten pinned
repos and exited 1 as a `::notice`. Reporting is not accountability: a drop and
a correct narrowing print identically, so the answer to "is that right?" was
whatever the reader assumed.

`scripts/rule-deltas.json` is the other half. Every rule whose count **falls**
needs an entry with a classification from a fixed vocabulary and a reason.
Rising counts stay reported and ungated — a new false positive is visible in
the output and costs nobody a vulnerability.

Four ways the harness now fails (exit 3, and the job goes red):

1. a rule dropped findings with no entry;
2. an entry describes a drop that no longer happens — checked only on a full
   run of the committed corpus, because a reduced corpus or a skipped repo is
   missing evidence rather than a stale reason;
3. an entry has no reason, or names a classification nobody defined;
4. the ledger's `nox_release` disagrees with the baseline the harness resolved,
   which means a release was cut and the entries it explained were never
   cleared.

**Falsified, not asserted.** All five paths were exercised against the real
`v1.34.0` baseline: the committed ledger passes at exit 1 with seven accounted
deltas, and deleting an entry, corrupting one, mis-declaring the release, and
adding a phantom each produce exit 3 naming the rule.

One flaw surfaced while testing and was fixed rather than lived with. The
stale-entry check is corpus-dependent, so on a reduced corpus every entry whose
witnessing repo was left out looked stale. It is an error only on a full
committed-corpus run with nothing skipped, and a warning otherwise.

### 0.5 — Path-coherence validation

At rule load time, reject declared semantics the chosen matcher or evaluation
path cannot consume. `jsonpath`, `yamlpath` and `heuristic` were removed from
`ValidMatcherTypes` for exactly this reason: they validated at load and matched
nothing at runtime.

`validateRule` (`core/rules/loader.go:79`) checks three things: a non-empty ID,
a known matcher type, a known severity. It cannot see the asymmetry that
matters. `structuralAbsence` reads `AbsenceResourceTypes`,
`AbsencePropertyPath`, `AbsenceRequireAll`, `AbsenceCompanion*` and
`AbsenceSubjectMinInt`, and returns `(nil, false)` unless resource types are
set *and* one of companion types or property path is; everything else falls
through to the regex path, which reads `AbsenceAnchor`, `AbsenceProperty`,
`AbsenceSpan` and `AbsenceRequire` and ignores the first group entirely. A rule
declaring `absence_subject_min_int` without a property path therefore loads,
lists, and applies no precondition at all.

**Measured 2026-09-06: 1,531 built-in rules, 55 on the absence matcher, 31 of
those structural, 2 carrying a subject precondition — 0 incoherent.** A latent
hazard, not a live defect, which is the right time to close it and the reason
0.5 is a gate rather than a bug fix.

`Rule.CheckCoherence` refuses six shapes, each of which loads silently today:

1. a structural-only field on a rule that never reaches `structuralAbsence`
   (the `absence_subject_min_int` case);
2. `absence_resource_types` with neither a property path nor companion types,
   so the descriptor is never consulted;
3. `absence_companion_link`/`path` without `absence_companion_types`, which
   select the companion branch;
4. an `absence_span` nobody implements — `absenceSpan()` falls to its default,
   returns nil for every anchor, and the rule cannot fire;
5. an absence rule missing an anchor or a property with no structural
   descriptor to answer instead — `compile("")` returns a nil regexp and
   `Match` gives up before looking at anything;
6. absence fields on a `regex` or `entropy` rule, where nothing reads them.

It runs in `validateRule` for YAML rules and in a catalog test for the
built-ins, which never pass through the loader and so were previously validated
by nothing at all. A custom rule declaring `absence_subject_min_int` without a
property path now fails the scan with exit 2 and a message naming the inert
field, instead of scanning with no precondition.

---

## Phase 1 — Explicit evaluation state

- **1.1** Results become at least `MATCH` / `CLEAN` / `UNEVALUATED`, with a
  reason: `parse_error`, `unsupported_construct`, `capability_unavailable`,
  `timeout`, `path_incomplete`, `not_applicable`. Malformed input must not look
  identical to a hardened result.
- **1.2** That state reaches canonical scan output. Today `findings.json` meta
  carries `degradations` and `sast_languages` and says nothing about the two
  unprovided capabilities; two scans differing only by analyzer availability
  are byte-identical.
- **1.3** Default CI policy must not treat unevaluated as safe. Uninstalling an
  analyzer cannot turn a failing scan green.

## Phase 2 — Competence moves into core

- **2.1** Degradation, baseline drift, baseline-absent-vs-zero-match, capability
  loss and scan competence move out of workflow YAML into core, so CLI, MCP and
  LSP inherit identical semantics.
- **2.2** Per-claim competence: capability used, scope, limitations, unmodelled
  constructs, budget state. One scan may hold different competence states for
  different findings.
- **2.3** A negative claim that met relevant unmodelled behaviour is never
  presented unqualified.

## Phase 3 — Typed propositions, earned incrementally

- **3.1** Minimal subject vocabulary: `package_version`, `symbol`, `flow`,
  `call_path`, `input`, `trigger_condition`, `exploit_hypothesis`. No subject
  enters without a fixture distinguishing it from adjacent propositions.
- **3.2** Subject-bound evidence: an advisory about a package cannot become the
  strongest evidence for exploitability.
- **3.3** Polarity `SUPPORTS` / `REFUTES` / `UNKNOWN`, behind the refutation
  benchmark. Missing evidence is never `REFUTES`.
- **3.4** Lifecycle: supersession, retraction, invalidation.

## Phase 4 — Central adjudication

- **4.1** One adjudicator composes `POTENTIAL`, `PLAUSIBLE`, `PREVENTED`,
  `INCONCLUSIVE`, `CONFIRMED`.
- **4.2** `PREVENTED` requires positive, deterministic, scope-sound refuting
  evidence. Absence of evidence cannot produce it.
- **4.3** CI gates on adjudicated state. A scan cannot become greener by losing
  capability.

## Phase 5 — Graph and flow identity

Bind findings and claims to symbols, nodes, edges, flows, source/sink and call
paths; recognise several observations as one security condition. TRIAGE-002 is
solved through flow identity, never by deleting a detector.

## Phase 6 — Progressive semantic refinement

Noisy regex families become candidate generators; cheap semantic refutation
(lexer context, constants, AST node type, value semantics) decides survival.
Stage accounting measures candidates in, refuted, promoted, unknown, latency.
Precision improves without refutation-caused recall loss.

## Phase 7 — Reachability and applicability

Core owns what reachability means and distinguishes dependency reachability,
symbol usage, call reachability, attacker-entry reachability,
attacker-controlled flow and runtime observed path. Every negative claim
records entry-point scope and model limitations. The ladder runs `PRESENT` →
`APPLICABLE` → `REACHABLE` → `ATTACKER-REACHABLE` → `PREVENTED` → `CONFIRMED`.

## Phase 8 — Verification hypothesis and reproduction semantics

`ExploitHypothesis` as an emitted artifact; a reproduction hierarchy from
trigger through invariant violation, crash, security effect and exploit; a
controlled-reproduction contract requiring real execution, a deterministic
oracle, repeatability, a benign control and a completed run. Removing any
condition prevents a `CONFIRMED` transition.

## Phase 9 — Directed verification R&D

Lightweight trigger solving first (input-to-state correspondence, taint-guided
search), then property-based typed generation, and SMT only if a meaningful
residual class survives. SMT must demonstrate measurable value over simpler
techniques before becoming architecture.

## Phase 10 — Active verification

`nox scan` stays read-only; `nox attack` stays explicit and authorized. The
handoff is a typed hypothesis, and verification evidence enters the same
ledger — no separate attack truth system.

## Phase 11 — Replay and explainability

Adjudication replay is exact: ledger plus adjudicator version reproduces the
verdict. Execution replay is best-effort with stated environment assumptions.
Every important result answers what was observed, what supports it, what
refutes it, what was not evaluated, what it means here, and what evidence would
change the conclusion.

## Phase 12 — Nox Intel evidence network

A shared proposition and evidence model; structured research artifacts
(affected symbols, trigger conditions, configurations, PoV metadata,
reproduction evidence, refutations, maintainer and advisory evidence); and a
publication rule that no quantity of heuristic or community observation
substitutes for deterministic evidence.

---

## Hard gates

| | |
|---|---|
| **A — Refutation instrumentation** | No new high-impact refuting capability ships until a deliberately wrong refutation is caught by CI |
| **B — Unevaluated honesty** | Loss of capability must be visible and policy-relevant |
| **C — Proposition distinction** | No new proposition without a benchmark case distinguishing it from adjacent ones |
| **D — `PREVENTED` safety** | No `PREVENTED` without deterministic, positive, scope-sound refutation |
| **E — Active consent** | No runtime or network attack behaviour in `nox scan` |
| **F — Agent trust boundary** | Agent output may create hypotheses, never authoritative verdicts without deterministic evidence |

## Primary success metrics

```
precision                         duplicate/security-condition rate
recall                            % explicit unknown / not_evaluated
false-negative rate from refutation   % evidence with provenance
wrong PREVENTED rate              deterministic replay equality
unexplained finding removals      stage-attributed latency
                                  hypotheses resolved per unit compute
```

The metric that must never disappear:

> **How often did nox conclude something did not matter, and was it right?**

## What to avoid

Replacing all regex; moving every plugin into core; inventing another
confidence model; making AI authoritative; equating reachability with impact;
equating a PoV with exploitability; letting "not evaluated" mean safe; adopting
SMT because a paper used SMT; and measuring best-in-class by number of
findings.
