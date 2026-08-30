# Evidence-Native Nox — roadmap evaluation and execution plan

Status: proposed. Supersedes nothing; `docs/roadmap.md` records shipped phases
and stays as the release history.

The proposed roadmap's North Star is right and its invariant —
**unknown must never silently become safe** — is already the doctrine written
into `degrade.Kind`, `goVulnReachable` and `evidence.Describe`. This document
evaluates the roadmap against the tree as it stands on 2026-08-30, then
restructures it into tracks that can be worked.

---

## Part 1 — Evaluation

### 1.1 Already shipped: strike Milestone 0.3

The vacuous publication guard is **already fixed**, in
`nox-intelligence/internal/domain/disclosure.go` (commit `2df420f`). PUBLIC is
reachable only across a statechart edge guarded on `humanWithCorroboration` —
human approval **and** `IndependentSources() >= 2`. Seven fail-closed tests in
`nox-core/evidence/failclosed_test.go` pin the surrounding rules, including
that no quantity of non-deterministic claims reaches `ConfidenceConfirmed`.

More importantly, **the invariant the roadmap proposes for 0.3 would be worse
than what is there.** It asks for "deterministic reproduction >= required
strength OR maintainer confirmation OR public advisory". The intelligence
service records exactly one evidence kind on candidates —
`evidence.KindIndependentObservation` (`internal/domain/candidate.go:103`) —
and that kind is not deterministic. `HasDeterministic()` is therefore false for
every candidate that can exist there. The proposed guard would swap a guard
that never refuses for one that never permits. This is documented in place at
`internal/application/service.go:156`; the reasoning should not be rediscovered.

**Action:** delete Milestone 0.3. Replace it with a cross-repo release gate
(§2.2, Track B).

### 1.2 Already partly built: rescope, don't rebuild

| Roadmap milestone | What already exists | What is actually missing |
|---|---|---|
| 1.x, 2.x, 3.4 (evidence semantics) | `nox-core/evidence`: `Kind` with 10 ranked strengths, deterministic gate, `Provenance`, `IndependentSources`, `Ledger.Confidence`, `DeriveExploitability` | Subjects, polarity, lifecycle, producer authority |
| 4.1 / 4.2 / 4.4 (capability + unknown) | `nox-core/degrade`: 11 `Kind`s, `Degradation{Kind,Detail,Impact}`, thread-safe collector; `--fail-on-degraded` wired through CLI and action.yml | The *positive* side — declaring a capability, and recording that it ran and what it concluded. Degradation only models "did not run" |
| 6.2 (cheap refutation) | `core/lexctx`: 22-language lexer with `Classify` → comment/string regions, already used by `secrets/srccontext.go` to drop config-field rules matched inside comments | It **suppresses in place**. Nothing is recorded, so a refutation is indistinguishable from the rule never firing |
| 7.1–7.3 (reachability) | `core/analyzers/deps/reachability.go`: `goVulnReachable` returns `(reachable, determined)` and answers false only on positive evidence | Go-only; result lands in `meta["reachable"]` as a string, carries no path, and no other ecosystem has an equivalent |
| 5.x (graph) | `core/attack/graph.go`: typed security graph — `NodeDatabase`, `NodeNetworkSink`, `EdgeReaches`, `EdgeDataFlow`, path search | It is confined to `core/attack`. The scan pipeline has no graph identity for findings |

### 1.3 The gap the roadmap understates

`nox-core/evidence` is imported by **`core/attack` and nothing else** — 64 call
sites, all in dynamic validation. The scan pipeline never touches it.
`core/findings.Finding` carries an analyzer-authored
`Confidence` (high/medium/low) and no ledger. `core/policy` and `core/report`
have no notion of `Exploitability` at all.

On the other side of that gap sit roughly **1,600 distinct rule IDs** across
`core/analyzers` (~914 SEC, ~500 IAC, ~50 AI, ~21 MCP, ~12 DATA, plus VULN and
SLOP). Phase 3 flips what a `Finding` *means*; Phase 10 migrates the rules that
produce them. Ordered as written, Phase 3 lands a new contract that ~1,600
rules do not satisfy, and the "legacy analyzer compatibility may remain during
migration" clause is doing all the load-bearing work with no design behind it.

**Action:** the compatibility period is not a footnote, it is a deliverable.
Track C below specifies dual-carriage explicitly (§2.3).

### 1.4 Corrections

**"Capability" is already taken.** `core/analyzers/ai` uses *capability* to
mean an **agent tool capability** — `CapHTTPRequest`, `CapWebhookPost`,
`capabilityLabel`, the capability lattice rendered by `nox agent-graph`.
Phase 4's "capability model" is a different concept in the same package
neighbourhood. Adopting the word unqualified would make `nox capabilities`
genuinely ambiguous against `nox agent-graph`. Use **analysis capability**
throughout, and `nox analysis-capabilities` (or fold it into `nox rules`).

**"Reuse the existing graph vocabulary" — which graph?** There are two.
`core/graph` (88 lines) is a plugin-emitted *display* graph: `NodeKindResource`,
`EdgeKindDependsOn`, a `Validate` that only checks dangling endpoints. It has
no security semantics. `core/attack/graph.go` is the real one. Phase 5 should
**promote the attack graph's vocabulary** into a shared package and treat
`core/graph` as a rendering projection of it — not the reverse.

**Phase 4 must precede Phase 3's output flip, not follow it.** The roadmap's
critical path puts adjudication (3) before capability/unknown semantics (4).
But the moment refutation can change output, "not evaluated" and "refuted"
must already be distinguishable in the domain — otherwise Gate A has nothing to
check against. Capability state is a *precondition* of safe adjudication.

**Milestone 6.2's value arrives before Phases 1–5 finish, and should be
allowed to.** `lexctx` already refutes; it just does it silently. Rewiring it
to *record* a refuting claim while leaving output byte-identical is a small
change that produces exactly the data Gate A needs, and it de-risks the whole
programme by proving the model on cases that are already understood.

### 1.5 Missing from the roadmap entirely

1. **Cross-repo release choreography.** `evidence` lives in `nox-core`,
   consumed by both `nox` and `nox-intelligence`, which deliberately do not
   depend on each other. Every Phase 1–3 change is a coordinated three-repo
   release. `nox-core` must stay public and Apache 2.0 or `go get
   github.com/nox-hq/nox` breaks for everyone. The kernel move is on `nox` main
   but untagged; the next `nox` release is **v1.31.0**, not a patch.

2. **Fingerprint, baseline and waiver compatibility.** Adjudication changes
   what a Finding is. Fingerprints key baselines, VEX statements and
   `nox:ignore` comments across every consuming repo. There is precedent —
   `docs/migration-fingerprint-v2.md`, and `RetiredRuleIDs`/`AliasFingerprints`
   exist precisely because retiring a duplicate rule ID un-waived findings and
   turned gates red. Phase 3 must budget for the same machinery or it will
   repeat that incident at much larger scale.

3. **The adoption cliff in Milestone 4.4.** Making `POTENTIAL`/`INCONCLUSIVE`
   fail-closed by default turns red, on upgrade, every repository currently
   gated with `nox scan . --severity-threshold high` — which is most of them.
   Fail-closed is the right end state and the wrong default to arrive at
   silently. Ship it opt-in (`policy.uncertainty: fail|warn|ignore`, default
   `warn`), with a release where the warning names the flag, before flipping.

4. **Ledger cardinality.** `docs/benchmarks/2026-Q2` records 5,698,790 findings
   on `llama_index` in 6m 2s, and 6.4M across the corpus. A typed-subject
   ledger with relationships, attached per finding at that cardinality, is a
   memory and latency problem the roadmap never sizes. Milestone 6.4 measures
   *stage* budgets; nothing measures the ledger itself.

5. **The TRIAGE-002 constraint is already recorded — do not rediscover it.**
   `.roady/spec.yaml` documents that changing the bench scorer to treat
   findings from unannotated rules as "unmeasured" was implemented and
   abandoned: the corpus asserts complete ground truth, and
   `core/bench/density_test.go` pins it. Phase 5's exit criterion ("recreate
   TRIAGE-002 and solve it through the model") is right, but the *measurement*
   must not move to make it pass.

---

## Part 2 — The plan

### 2.1 Revised critical path

```
A  Baseline, refutation corpus, cardinality budget
              ↓
B  Kernel: subjects, relations, polarity, lifecycle, authority   (nox-core v0.2.0)
              ↓
   ┌──────────┼──────────┐
   C shadow   D capability   E cheap refutation      (parallel; output unchanged)
   └──────────┼──────────┘
              ↓
        ═══ Gate A ═══   refutation corpus proves nothing real was suppressed
              ↓
C-flip  Finding becomes an adjudicated output        (nox v2.0.0)
              ↓
F  Flow identity and structural dedup  →  recreate TRIAGE-002
              ↓
G  Reachability and applicability
              ↓
        ═══ Gate B ═══   deterministic unreachability ≠ unknown, path preserved
              ↓
H  Intel as evidence network   ═══ Gate C ═══
              ↓
I  Replay and explanation      →     J  Migration and validation
```

The roadmap's ordering is preserved except that **D moves ahead of C's flip**
and **E runs in parallel from the start**, for the reasons in §1.4.

### 2.2 Track A — Baseline and safety nets

No architecture changes. Everything here is measurement.

- **A1 — Re-baseline precision.** Already an open, explicitly-blocked item in
  `.roady/spec.yaml`: "Re-measure `nox bench --precision` with the 0.3.0
  plugins installed before closing this out." The 1.000 → 0.407 → 0.597 series
  measured plugins that emitted findings; two of the three no longer do.
  Capture precision, recall, FP/TP by rule, duplicate rate, and wall time, for
  each of: no plugins, 0.3.0 plugins, every `precision-suite-*` corpus.
  Commit the result under `docs/benchmarks/2026-Q3/`.
  *Exit:* one authoritative baseline every later milestone is measured against.

- **A2 — Refutation corpus.** `testdata/refutation-suite/`, a new corpus whose
  ground truth is inverted: each case is a **real** vulnerability that a
  plausible refinement would wrongly refute. Minimum coverage, one case per
  refuter we intend to build: comment/prose lexer refinement, constant
  analysis, taint refutation, reachability, flow merging, applicability.
  A guard test asserts recall stays 1.000 on this corpus **forever**.
  *Exit:* measurable protection against "we cut false positives by hiding real
  vulnerabilities". This is Gate A's instrument and must exist before any
  refutation reaches output.

- **A3 — Ledger cardinality budget.** A spike, not a feature: attach a
  synthetic 3-claim ledger to every finding on the `llama_index` bench run and
  measure peak RSS and wall-clock delta. Publish a hard budget (proposal: ≤15%
  wall-clock, ≤25% RSS at 6M findings) that Track C is designed against.
  If the budget cannot be met, the ledger is stored out-of-band and referenced,
  and that decision is made **now**, not after C is built.

### 2.3 Track B — Kernel semantics (`nox-core`, one release)

All of Phases 1 and 2, shipped as **`nox-core` v0.2.0**, purity preserved (no
clock, no I/O, no randomness).

- **B1 — `Subject`.** A typed identity a claim is *about*: package/version,
  symbol, flow, call path, input, security control, exploit hypothesis. Start
  with exactly these seven; resist growth. `Ledger` becomes keyed by subject so
  `Strongest()` can no longer aggregate an OSV advisory about a package with an
  unreachable call path into one verdict.
- **B2 — Relations.** The smallest vocabulary that expresses
  `package affected → symbol belongs to package → application uses symbol →
  flow reaches symbol → attacker controls input → exploit hypothesis`. Six
  relation kinds, not an ontology.
- **B3 — Polarity.** `Supports` / `Refutes` / `Unknown` on `Claim`, with two
  rules enforced in the type, not by convention: a missing supporting claim is
  not a refutation, and a failed or unavailable analysis is not a refutation.
- **B4 — Lifecycle.** `Superseded`, `Retracted`, `Invalidated`, `Replaced`.
  Callers supply timestamps and staleness policy; the model records facts.
- **B5 — Producer authority.** A registry mapping producer → permitted evidence
  kinds. A lexical analyzer may claim token context; it may not emit
  `KindDynamicExploit`. `Ledger.Add` rejects — or records-but-zeroes, matching
  the existing unknown-kind treatment — a claim outside the producer's
  authority.

*Release gate:* `nox-core` v0.2.0 tagged with LICENSE, `nox` and
`nox-intelligence` both bumped and clean-cloned-and-built with no sibling
checkout present, per the topology invariant.

### 2.4 Track C — Adjudication in the scan pipeline (`nox`)

The seam already exists: `core/scan.go` Stage 3, `refineFindings`
(`core/scan.go:1029`), runs after all analyzers and plugins and before policy.

- **C1 — Shadow ledger.** `Finding` gains an optional `Ledger`. Analyzers keep
  authoring `Confidence` exactly as today; a shim synthesises a single claim
  from each analyzer's existing output. Nothing in the output changes. Measured
  against the A3 budget.
- **C2 — Adjudicator, shadow mode.** A new `core/adjudicate` consumes the
  proposition graph and derives `Exploitability` via explicit state
  transitions — no global risk equation. It writes to a new field and to
  `findings.json` only; SARIF, policy and exit codes are untouched. Divergence
  between analyzer confidence and adjudicated state is logged, and the
  divergence report is the input to C5.
- **C3 — Conflict semantics.** Within a subject: stronger evidence wins;
  deterministic evidence is not overturnable by heuristics; equal contradictory
  strength → `INCONCLUSIVE`; conflicts stay visible in the ledger. Across
  subjects: claims compose, never compete.
- **C4 — Fingerprint and waiver compatibility.** Before any output flip:
  adjudication must not change a fingerprint. If it must, reuse the
  `RetiredRuleIDs`/`AliasFingerprints` mechanism and ship the same kind of
  migration note as `docs/migration-fingerprint-v2.md`. A test asserts that
  every baseline entry and VEX statement valid before the flip is still valid
  after it.
- **C5 — The flip.** `Finding` becomes an adjudicated output;
  analyzer-authored `Confidence` becomes an input to adjudication rather than
  the authority. `Severity` keeps its meaning — potential consequence if true —
  and is *not* merged into confidence. Ships as **`nox` v2.0.0**. Gated on
  Gate A.

### 2.5 Track D — Analysis capability and honest unknown

- **D1 — Name it.** `AnalysisCapability`, distinct from the agent-tool
  `Capability` in `core/analyzers/ai`. Settle this before any code lands.
- **D2 — Registry.** Implementations (core analyzers and plugins alike) declare
  which analysis capabilities they provide: lexical context, constant
  evaluation, taint, symbol resolution, call graph, entry-point analysis,
  reachability, attacker reachability, dynamic verification.
- **D3 — Evaluation state.** Per applicable capability, per subject: evaluated-
  positive, evaluated-negative, unknown, unsupported, timed-out, not-evaluated.
  This is `degrade`'s positive counterpart and should extend it rather than
  duplicate it — `degrade` already carries the `Impact` field that answers
  "should I trust this scan?".
- **D4 — `nox analysis-capabilities`,** generating the capability matrix rather
  than maintaining it by hand.
- **D5 — CI policy on uncertainty.** `policy.uncertainty`, defaulting to
  `warn`, with `fail` available immediately and becoming the default only after
  a release where the warning names the flag (§1.5.3). `CONFIRMED` fails;
  `PLAUSIBLE` fails at or above the configured severity; `PREVENTED` reports
  and does not gate.
  *Exit:* uninstalling or breaking an analyzer cannot make a build greener.

### 2.6 Track E — Cheap refutation (runs from day one)

Each step: record a refuting claim, leave output byte-identical, measure
against the refutation corpus. This is where the architecture proves itself on
cases already understood.

- **E1 — lexctx as evidence.** `secrets/srccontext.go` already drops
  config-field rules matched inside comments. Rewire it to emit a refuting
  claim instead of silently dropping, then let adjudication do the dropping.
  Same output, recorded reasoning. This is the smallest end-to-end proof of the
  whole model and should be the **first PR after Track B**.
- **E2 — Constant analysis (AI-006 shape).** Commit `0810e63` fixed
  "constant message containing the word prompt" as an in-rule guard. Re-express
  it: regex match → inspect the call → all arguments constant → deterministic
  refuting claim.
- **E3 — Value semantics (ENRICH-004 shape).** Identifier match → inspect the
  literal → placeholder → refuting claim. The historical bug was matching
  `api_key = "` without ever reading the value.
- **E4 — Stage instrumentation.** Candidates entering, refuted, promoted,
  duration, memory — per stage. The objective is *maximise cheap refutation
  before expensive proof*, and it has to be visible to be optimised.

### 2.7 Tracks F–J (sequenced after Gate A)

- **F — Flow identity.** Promote `core/attack/graph.go`'s vocabulary to a
  shared package; bind claims to nodes, edges, symbols, flows, entry points,
  sinks, call paths. One flow → one security hypothesis, not three matches →
  three vulnerabilities. Then **recreate TRIAGE-002 as a test case and resolve
  it structurally** — without moving the bench scorer (§1.5.5).
- **G — Reachability and applicability.** Generalise `goVulnReachable`'s
  `(reachable, determined)` discipline into core contracts, make the evidence
  path-bearing (entry point → call → call → symbol, not `reachable: true`),
  build the `present → affected version → symbol relevant → used → reachable →
  attacker influence → exploitable` ladder, and make `PREVENTED` a normal,
  visible scan result rather than a suppression. *Gate B.*
- **H — Intel as evidence network.** One claim model shared with local nox;
  research maturity ladder; independence and Sybil semantics; retraction and
  supersession; local adjudication stays sovereign — if Intel disappears, nox
  still scans, still reasons, and *reports the missing capability* via D3.
  *Gate C.*
- **I — Replay and explanation.** Persist an evidence-rich artifact; make
  re-adjudication deterministic (same ledger + same adjudicator version = same
  verdict) before attempting full scan reproducibility; every finding answers
  the eight explainability questions.
- **J — Migration and validation.** Rule families in value/risk order — noisy
  AI rules, secrets, endpoint/API misuse, taint overlaps, dependency
  applicability — each answering: what is the observation, what confirms it,
  what refutes it, what capability is required, what stays unknown. Plugin
  contract evolves toward evidence producers. Only then retire
  analyzer-authored confidence. Finally, the benchmark suite of Phase 11.

### 2.8 The three gates

Unchanged from the proposal, and non-negotiable:

- **Gate A — Evidence safety.** Before refutation affects output, the
  refutation corpus (A2) proves nothing real is being suppressed.
- **Gate B — Impact safety.** Before reachability produces `PREVENTED`,
  deterministic unreachability is distinguishable from unknown and
  not-evaluated, and the evidence path is preserved.
- **Gate C — Intelligence safety.** Before early Intel strengthens a public
  conclusion, producer authority, provenance, deterministic confirmation,
  retraction and the publication invariant are all enforced in the domain
  model. Four of the five are already in place (§1.1); authority (B5) and
  retraction (B4) are the outstanding two.

### 2.9 The first three pull requests

1. **A1** — re-baseline precision with 0.3.0 plugins; commit
   `docs/benchmarks/2026-Q3/`. Unblocks a spec item that is already open.
2. **A2** — `testdata/refutation-suite/` with a recall-1.000 guard test.
   Nothing that changes output ships before this exists.
3. **A3** — cardinality spike on the `llama_index` bench; publish the budget
   Track C is designed against.

Track B starts once A3's budget is known, because it determines whether the
ledger is inline or out-of-band.

### 2.10 Explicit non-goals

Carried from the proposal, and worth restating because each is a plausible
wrong turn: do not replace all regex; do not move all plugins into core; do not
add AI adjudication — AI may research, explain, hypothesise, prioritise and
produce evidence, but the authoritative conclusion stays deterministic; do not
maximise vulnerability count.

The metric is: **how often does nox reach the correct, reproducible conclusion
about whether a security condition matters to this application?**
