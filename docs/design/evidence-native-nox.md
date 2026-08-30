# Evidence-Native Nox — roadmap evaluation and execution plan

Status: in progress. Tracks A, B, C1, C2, D, E1–E3 and F have landed — see
§2.9 for where the programme stands and what it found. `docs/roadmap.md` records shipped
phases and stays as the release history.

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

**Status: complete.** Results in `docs/benchmarks/2026-Q3/`.

- **A1 — Re-baseline precision. ✓** `docs/benchmarks/2026-Q3/README.md`.
  Core only, all 20 corpora: 203 TP, 0 FP, 7 FN — precision 1.000, recall
  0.967, every miss a TAINT-002/TAINT-006 gap in clojure, dart or shell. The
  plugin matrix on `precision-suite`: threat-enrich 0.3.0 and triage-agent
  0.3.0 together contribute **zero** findings and zero false positives, so the
  enrichment conversion worked completely; overall precision with the full
  plugin set is **0.771**, against 0.597 before. Every remaining false positive
  is `api-abuse`, the one plugin deliberately kept as a detector.
  One correction to the record: the spec's claim that #28 took API-ABUSE-001's
  corpus FPs "17 -> 0" is wrong — 0.2.2 measures 17, 0.2.3 measures 10, and the
  rule's precision is still 0.000. It goes on Track J's migration list.

- **A2 — Refutation corpus. ✓** `testdata/refutation-suite/`, seven samples,
  one per refiner on the roadmap: lexical context, generated-code suppression,
  constant analysis, sanitizer recognition, flow merging, reachability, value
  semantics. No clean samples — every file carries a real, currently-detected
  vulnerability shaped so a plausible refiner dismisses it for a reason that
  sounds good and is wrong. Scores 10 TP / 0 FP / 0 FN.
  `TestRefutationSuiteRecall` asserts recall is exactly 1.000, and was verified
  to fail with a readable message when a sample's sink is removed.
  *Known gap:* dependency-level applicability and reachability are absent,
  because those cases need OSV data and this corpus is scored offline. **Gate B
  therefore has no corpus yet** and Track G must bring one.

- **A3 — Ledger cardinality budget. ✓** `docs/benchmarks/2026-Q3/ledger-budget.md`.
  Measured: a bare finding costs 656 B live, 1,248 B with a three-claim ledger
  — 1.90×, and **6.62 GiB projected at 5,698,790 findings against 3.48 GiB
  bare**. The ratio budget (≤4×) passes; the absolute budget (≤6 GiB) does not,
  and the absolute one is what binds — a hosted CI runner offers 7 GB.
  **Decision: the ledger is not carried inline on `Finding` unconditionally.**
  Track C is designed against a reference — an out-of-band store keyed by
  fingerprint, or omission above a threshold recorded as a `degrade.Kind`,
  never a silent drop. Shrinking the ledger until it fits is not an option; the
  claims are the product.
  The gate arms itself: a reflection check fails the budget on the commit that
  gives `Finding` a ledger field, not on a later one.

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

- **C1 — Shadow ledger, out-of-band.** `Finding` gains a *reference* to a
  ledger, not a ledger — A3 settled that. Analyzers keep authoring `Confidence`
  exactly as today; a shim synthesises a single claim from each analyzer's
  existing output into the side store. Nothing in the output changes. The A3
  budget test arms itself the moment an inline field appears, so this
  constraint is enforced by CI rather than by memory.
- **C2 — Adjudicator, shadow mode.** A new `core/adjudicate` consumes the
  proposition graph and derives `Exploitability` via explicit state
  transitions — no global risk equation. It writes to a new field and to
  `findings.json` only; SARIF, policy and exit codes are untouched. Divergence
  between analyzer confidence and adjudicated state is logged, and the
  divergence report is the input to C5.
- **C3 — Conflict semantics.** *Landed, with one part of the plan rejected.*
  Within a subject: stronger evidence wins; deterministic evidence is not
  overturnable by heuristics; equal contradictory strength is a conflict;
  conflicts stay visible. Across subjects: claims compose, never compete. All
  four now have tests that assert the exact value rather than a bound — a
  reproduction supporting and a heuristic refuting stays `CONFIRMED`, because an
  assertion phrased "not high" would pass even if a guess had retired a proof.

  **Equal contradictory strength must NOT become `INCONCLUSIVE`.** The kernel's
  `Exploitability` is a dynamic-validation lifecycle, and `INCONCLUSIVE` means
  specifically that execution occurred and the evidence could not decide. A
  static scan executes nothing, so routing a static disagreement there would
  make one state mean two incompatible things — "we attacked it and could not
  tell" and "we attacked nothing and two producers disagree" — with no way for a
  reader to tell which. The intelligence service derives exploitability from the
  same function, so the ambiguity would cross a repository boundary. Nor does
  the kernel need a new state: conflict is a property of the evidence,
  orthogonal to how far validation got. A finding can be `POTENTIAL` and
  conflicted, or `CONFIRMED` and conflicted.

  So conflict stays its own axis, and the actual work of C3 was that the axis
  was being thrown away. `Verdict.Conflicted` was computed in
  `adjudicateFindings` and discarded; nothing outside the adjudicator's own test
  read it. It now reaches `ScanResult.Conflicts` as an `adjudicate.Conflict`
  naming the two statements that tied and the strength they tied at — a report
  saying only "these disagree" sends a person hunting through the ledger for
  the disagreement.

  **It does not fire today, and the reason is structural rather than lucky.** A
  refuted candidate is dropped before any supporting claim is recorded, and a
  surviving one is corroborated on a separate path, so the two polarities never
  meet. The one place they do is the checksum verifier, which files a
  `KindStatic` refutation against a candidate whose supports are
  `KindHeuristic` — and 40 does not equal 10. Conflict is therefore
  *unreachable*, not merely unobserved, and the two are indistinguishable from
  outside. What makes it reachable is a second producer filing claims about a
  subject the scanner already has an opinion on: Track H, or a plugin.
  `TestConflictIsUnreachableUntilASecondProducerExists` fails on that day and
  says to go read the disagreement.
- **C4 — Fingerprint and waiver compatibility.** *Landed.* Adjudication must
  not change a fingerprint, and three tests now hold that line rather than this
  paragraph:

  - `findings.TestFingerprintIngredientsAreClosed` classifies every field of
    `Finding` as an ingredient or not, checks each classification by mutating
    the field, and fails by name on a field nobody has classified. A field
    added by a later track cannot join the hash by accident.
  - `TestWaiversSurviveAdjudication` builds a baseline, two VEX documents and a
    set of `nox:ignore` directives against a non-adjudicating scan, then checks
    all four against an adjudicating one. Both halves come from real scans.
  - `TestExplainingInTheMessageUnwaives` measures the mistake instead of
    warning about it, because the tempting shape for C5 — a finding that
    explains itself by saying more — reaches straight into the hash.

  **No migration note is needed**, and that is a measured result rather than an
  assumption: no fingerprint moves, so the `RetiredRuleIDs` /
  `AliasFingerprints` mechanism stays in reserve. The condition under which
  C5 would need it is now a failing test rather than a thing to remember.

  Two facts came out of building it, and both constrain C5:

  **`Message` is a fingerprint ingredient.** Appending one clause to every
  message costs 22 of 37 baseline entries and every fingerprint-pinned VEX
  statement on the precision suite. Inline `nox:ignore` directives and unpinned
  VEX statements survive, because they key on the rule ID — so an operator sees
  roughly half their waivers fail, which reads as a partial outage rather than
  as a format change. C5 writes its verdict to `Exploitability`, `Status` and
  `Metadata`. Never to `Message`.

  **The ingredient set is not uniform across producers.** `FindingSet.Add`
  hashes the finding's `Message`; the rule engine hashes the text its pattern
  matched and never reads the message at all. On the precision suite that is a
  22/15 split, and nothing downstream can tell which contract a given
  fingerprint was written under — both paths emit the same `Finding` through
  the same reports. So "adjudication must not extend the message" binds one
  producer and is vacuous for the other, while "must not change the matched
  text" is the reverse. Pinned by `TestFingerprintProducersAreNotUniform`.
  This is a constraint on C5, not a live defect: fingerprints are stable today
  under either recipe.
- **C5 — The flip.** *Landed as a two-scale model, not a flip. The plan's
  version was measured and abandoned.*

  The plan: `Finding` becomes an adjudicated output, analyzer-authored
  `Confidence` demoted from authority to input, shipped as a major version.
  `Severity` keeps its meaning — potential consequence if true — and is *not*
  merged into confidence. That last part holds and always did.

  **Why the flip cannot ship.** The kernel puts `HIGH` at strength 70 —
  `source_confirmed`, `controlled_reproduction`, `public_advisory` — and a
  static scan's strongest claim is `KindStatic` at 40, which is `MEDIUM`. So
  adjudicated confidence has no top of scale available to a pattern scanner,
  and never will: the missing strength comes from executing something or from
  somebody else reporting it, not from analysing harder.

  Measured on the precision suite: 15 of 37 findings demoted, none promoted,
  and `--min-confidence high` goes from **11 findings to zero**. Not "fewer" —
  zero, on every project, permanently. A filter that always returns nothing is
  indistinguishable from a clean repository, which is the single outcome this
  programme exists to prevent. The plan would have built it into the tool.

  **What shipped instead.** The two are different quantities and both are kept:

  | field | question | authored by | range on a static scan |
  |---|---|---|---|
  | `Confidence` | how likely is this a true positive | the analyzer | low … high |
  | `EvidenceConfidence` | what strength of evidence was recorded | adjudication | LOW … MEDIUM |

  `Confidence` keeps authorship and keeps `--min-confidence`, and the precision
  suite says it deserves to — 37 true positives, no false ones, so its "high"
  is accurate. `EvidenceConfidence` is a new field beside `Exploitability`,
  absent unless the scan adjudicated. Where they disagree is reported, not
  resolved: `ScanResult.Divergences` becomes a standing output rather than the
  one-off measurement it was built as.

  **Ships as a `v1.x` minor.** Nothing breaks: no fingerprint moves (C4), no
  existing field changes meaning, and one optional field is added. The major
  version the plan called for was there to protect consumers from an output
  flip that is no longer happening.

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
- **H — Intel as evidence network.** *Landed.* One claim model shared with local nox;
  research maturity ladder; independence and Sybil semantics; retraction and
  supersession; local adjudication stays sovereign — if Intel disappears, nox
  still scans, still reasons, and *reports the missing capability* via D3.
  *Gate C.*

  **Sovereignty is landed; the network semantics are not.** Measured with the
  service unreachable: the scan completes, findings are unaffected, and a
  degradation says in plain words that it "cannot confirm the absence of known
  CVEs". Those three held already.

  The fourth did not, and it was a live false all-clear in the gate built to
  prevent them. Under `uncertainty: fail` with
  `require_capabilities: [reachability]` — the strictest configuration D5
  offers — that same scan returned `pass=true`, exit 0, no warnings. Nothing was
  lying: `reachability` genuinely is provided, because `core/analyzers/deps` is
  compiled into every build. `EvaluateCapabilities` asked whether the
  installation *could* establish reachability, a fact about the binary, and
  reported it as though it had answered whether reachability *had been*
  established for this code. Those coincide right up until something fails at
  runtime.

  A requirement is now met only when the capability is provided **and this scan
  reached a conclusion with it** — `Coverage.Answered`, where `Positive` and
  `Negative` are conclusions and `Unknown` and `TimedOut` are not. Unsupported,
  inconclusive and unexercised are worded apart, because "install a plugin",
  "the analysis could not tell" and "nothing put the question" need different
  responses and one sentence sent operators to install what they already had.

  **The rest of H was mostly already built, and saying so is the finding.**
  The claim model is genuinely shared — the service derives confidence and
  exploitability from `nox-core/evidence` and stores neither, so a stored
  verdict cannot drift from the evidence behind it. The research maturity
  ladder is `DisclosureState`, a guarded statechart from `INTERNAL` to
  `PUBLIC`, where research agents may investigate and may never disclose.
  Independence and Sybil semantics are there and unusually honest: reporters
  are a set rather than a counter, unattributed observations never corroborate,
  and `CorroborationIsAttested` documents outright that reporter identities are
  self-asserted, that threshold aggregation buys k-anonymity rather than Sybil
  resistance, and that the answer is therefore to *show* the operator whether
  anything is checkable rather than to gate on it silently.

  **Retraction was the real gap, and it is meaningful in exactly one of the two
  repositories.** In the CLI claims live for one scan and are discarded, so
  there is nothing to retract — you re-scan. In the service they persist per
  candidate across reporters and time, and the ledger is the audit trail behind
  a disclosure decision.

  Three things came out of wiring it:

  1. **`nox-core` v0.2.2 — a retracted claim now weighs nothing everywhere.**
     `Status` says of itself that it weighs nothing "exactly as an unrecognised
     Kind does", and only `counted()` honoured that. `Kinds`,
     `HasDeterministic`, `HasSemantic` and `IndependentSources` read every claim
     regardless of lifecycle — so a retracted reporter still corroborated, and
     consensus would survive the withdrawal of the belief it was made of.
     Nothing caught it because nothing had ever set a `Status`.
  2. **`Strongest` splits in two.** It stays an audit accessor over the whole
     trail, because an audit view reporting a non-empty ledger as empty is worse
     than the problem. `StrongestLive` is the verdict-facing one, and
     `adjudicate.rationale` now uses it: explaining a LOW verdict with "the
     exploit reproduced" — retracted — reads as a bug in the verdict.
  3. **Two service consumers were reading raw claims.** The KEV kill switch
     fired forever on a withdrawn entry, and `CorroborationIsAttested` reported
     a withdrawn attestation as attestation. Both found by running the service
     tests against a real database — without `NOXINTEL_TEST_DSN` every
     assertion in that file skips and the suite reports green.
- **I — Replay and explanation.** *Milestones 9.1, 9.2 and 9.3 landed; 9.4 is
  deliberately out of scope.*

  9.3 is `nox why`, and it is deterministic on purpose: it reads only what the
  scan established, so every sentence traces to a claim, a capability state or
  a rule's own metadata. `nox explain` already asks a model to write prose about
  a finding; both are useful and only one can be put in front of an auditor.

  Two of the eight questions are the ones a scanner normally omits, and they are
  where the previous tracks pay off. "What was not evaluated?" is answered from
  Track D's capability coverage, separating *nothing on this installation can
  establish it* from *the analysis ran and could not tell* from *nothing asked
  here* — three different next steps. "Does it affect this application?" is
  answered from Track G's ladder, and an undetermined result says so in the
  words "unknown, which is not the same as no".

  Two things came out of building it. The first draft printed
  `Metadata["match"]`, the raw matched value, which on a secrets finding is the
  credential — into a terminal and a CI log, from a tool whose stated posture is
  that it never uploads source code. The second is smaller and more common:
  many catalogue descriptions restate the finding's message, so "why does this
  matter?" was answered with "because it happened". It now says the catalogue is
  thin instead, which is true and is actionable by whoever maintains the rule.

  `nox scan --evidence-out evidence.json` writes what the scan established —
  input identity, capability state, every claim with its provenance, the
  relationships between subjects, and the adjudicated verdict per finding — and
  `nox replay` re-derives those verdicts from that file alone. Not the
  repository, not the rules, not the network: the question "does this evidence
  support this verdict?" never depended on them, which is what keeps it
  answerable once all three have moved on.

  `adjudicate.Version` is the other half of the contract, and it is only worth
  something if somebody remembers to bump it, so
  `TestVerdictsAreStableForThisVersion` pins a table of ledger→verdict pairs.
  Change what adjudication returns and it fails with the field that moved; the
  fix is to bump the version and update the table in the same commit, which is
  the pairing nothing else forces. A replayed difference under a *different*
  version is reported as a change rather than a defect, and exits 0 — otherwise
  every nox upgrade would look like a regression in whatever produced the
  artifact.

  **Claim order within a subject turned out to be load-bearing.** The kernel
  breaks strength ties by taking the earliest claim, deliberately and by its own
  test, so among equal-strength claims the one that carried the verdict — and
  therefore the rationale a person read — is a function of the order they were
  recorded in. The first draft of the artifact sorted claims by kind, source and
  statement, which looked tidy and rewrote the explanation on 10 of 37 findings.
  Every label still reproduced. Only the sentence moved, which is the half
  anybody actually reads. Found by the replay disagreeing with the scan that had
  just produced it.
- **J — Migration and validation.** *10.1's profiles landed; the migration
  itself is barely begun, and now measurable.* See
  `docs/design/rule-family-migration.md` for the five questions answered per
  family and the ordering, which measuring changed.

  The headline: across both corpora, **two findings carry evidence that was
  earned** rather than classified — both the same GitHub checksum. `TAINT` and
  `VULN` sit above heuristic because `reasoning.ObservationKind` promotes their
  rule prefix, which is defensible and is not migration; the metric separates
  the two so that distinction cannot quietly flatter the work.

  `IAC` is 490 rules — the second largest family, absent from the roadmap's
  ordering — and all 490 are regex or absence matchers over text. It cannot
  exceed heuristic without structural parsing, which is a feature rather than a
  migration. Saying so beats classifying a regex as static.

  Original scope follows. Rule families in value/risk order — noisy
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
  model. All five are now in the kernel — authority (B5) and retraction (B4)
  landed with `nox-core` v0.2.0. The client-side half of Gate C — that losing
  Intel degrades a scan visibly rather than silently — is enforced by the
  capability gate described under H.

### 2.9 Where the programme stands

**Landed as of 2026-08-30.** Tracks A, B, C, D, E, F, G and H are complete and
on `main`; the kernel is released at
`nox-core` v0.2.1 and both consumers are bumped. Everything ships in the `v1.x`
line: the major version the plan reserved for C5 was there to protect consumers
from an output flip the measurement ruled out.

| | what shipped | measured |
|---|---|---|
| **A** | precision baseline, refutation corpus, ledger budget | 203 TP / 0 FP / 7 FN core-only; 0.771 with plugins |
| **B** | `Subject`, `Relation`, `Polarity`, `Status`, `Authority` | nox-core v0.2.0; v0.2.1 added `SubjectCandidate` |
| **E1** | six secrets refiners record why they drop a candidate | 5 of 6 covered end to end; the sixth is unreachable and says so |
| **C1** | out-of-band shadow ledger, subject derived not stored | 0 bytes per finding; output byte-identical |
| **C2** | `core/adjudicate`, shadow only, divergence report | 15 of 37 findings diverge, all over-claimed |
| **D1–D4** | nine analysis capabilities, six evaluation states, `nox analysis-capabilities` | 3 capabilities have no implementation and say so |
| **D5** | `policy.uncertainty`, `policy.require_capabilities` | clean scan + missing required capability = exit 1 |
| **E2/E3** | four AI refiners record; secrets records what it verified | 37 → 61 supporting claims; divergence unchanged |
| **F** | `findings.FlowID`, relations in the store, TRIAGE-002 recreated | 18 flows on the corpus, every edge evidence-backed |
| **G** | applicability ladder, Gate B corpus, `PREVENTED` as a normal result | 5-case reachability suite; found a false contract on first run |
| **C4** | ingredient contract, waiver survival across a real scan pair | 0 waivers lost; message flip costs 22/37 baseline + every pinned VEX |
| **C3** | conflict reaches the scan result; INCONCLUSIVE rejected with reasons | 0 conflicts on every corpus, and structurally so, not by luck |
| **H** (part) | a capability requirement reads the run, not the installation | intel down + `require_capabilities` was pass/exit 0; now fails |
| **C5** | two scales kept apart: analyzer confidence and evidence confidence | the flip would have taken `--min-confidence high` from 11 to 0 |
| **H** | retraction wired end to end; kernel lifecycle made uniform | 5 kernel accessors ignored `Status`; 2 service consumers read raw claims |
| **I** (9.1–9.3) | evidence artifact, deterministic replay, `nox why` | 37/37 verdicts reproduced; claim order moved 10 rationales |
| — | config-driven removals leave a trail | polarity Unknown, not Refutes |

The scan pipeline now runs end to end: analyzers observe, refiners refute and
record why, config removals leave a trail, flows are named so two findings can
be one condition, one adjudicator derives the verdict, capability coverage says
what was never asked, and CI can gate on a capability going missing. The one
output the flip must not disturb — the fingerprint every waiver is keyed on —
is now held by a contract rather than by intent.

#### What the work found that the plan did not anticipate

- **`SubjectCandidate` was missing.** The original seven subject kinds came
  from the dependency-applicability chain — what nox reasons *about* — and
  omitted what nox mostly *produces*. Added in v0.2.1.
- **An existing test was vacuous.** `TestScan_DataURIPayloadIsNotASecret`
  asserted "no findings" on input that produced no raw matches, so the filter
  it guarded was never called; it passed identically with that filter deleted.
- **A validation was unreachable.** D5's `policy.uncertainty` check was written
  correctly and never ran: the loader built its `policy.Config` from a separate
  literal that omitted the field, so a mistyped value silently resolved to the
  permissive default — the exact defect the `fail_on` validation exists to
  prevent, one field over. One constructor now, and a test asserting every
  gate-affecting field is rejectable.
- **Suppression, baselining and VEX were never silent.** Each sets a `Status`
  the reporters carry. C1's stated gap was three-quarters wrong; the genuinely
  silent removals were the config-driven ones.
- **Recording more heuristics does not raise confidence.** This was predicted
  to move the divergence number and measured not to. Aggregation takes the
  strongest supporting claim; three heuristics are still a heuristic; the
  independence promotion cannot apply because they share a producer. The number
  moves on evidence of a different KIND — see below.
- **The fingerprint has two ingredient sets, not one.** C4 assumed the question
  "does adjudication move a fingerprint" had a single answer. It has one per
  producer: `FindingSet.Add` hashes `Message`, the rule engine hashes the
  matched text, and the output is indistinguishable downstream. 22/15 on the
  precision suite. See C4 above.
- **A feature nothing uses cannot be known to work.** B4 shipped the claim
  lifecycle and wired it into one function; four other accessors kept the old
  reading for two releases, with no test noticing, because no consumer ever set
  a `Status`. The inconsistency was only reachable at the moment something
  finally retracted a claim — which is also the moment it would have mattered.
- **A green suite can be a suite that skipped.** The service's database tests
  skip themselves when `NOXINTEL_TEST_DSN` is unset, and its own CI comment
  calls a run without a database "theatre". Running them for real caught a kill
  switch that fired forever on a withdrawn CISA entry — a bug introduced by the
  same change that the skipping suite had just reported green.
- **The plan's headline change would have built the failure it was written to
  prevent.** C5 was the programme's destination — retire analyzer-authored
  confidence, let the evidence speak. Implemented literally it takes
  `--min-confidence high` to zero findings on every project forever, because
  the kernel's HIGH needs strength 70 and a static scan tops out at 40. "No
  findings" that is not clean, shipped as the intended design. The plan was
  right that the two confidences are different things and wrong about which
  one to keep; measuring before flipping is the only reason that is a paragraph
  here instead of a release.
- **D5's gate protected nothing, for a reason no test could see.** It asked
  `Provided` — is this capability compiled in — and the answer is yes on every
  build, forever, whatever happens at runtime. Every unit test passed because
  every unit test set up an installation and asked about that installation. It
  took running a scan against a dead endpoint to see that the strictest
  available configuration returned a clean bill on a scan that determined
  nothing. Third defect this programme has found in the same shape: a check
  written correctly against the wrong input.
- **A guard that pins a transcription cannot guard the thing.**
  `TestCorpusTokensCarryValidChecksums` checked a hardcoded list of two token
  literals copied out of the corpora, and passed while a third drifted:
  `tp_secrets.go` kept a random body, so nox recorded a deterministic
  refutation saying "this is not a GitHub credential" against a sample the
  corpus declares a true positive — and reported it anyway. Same shape as the
  unreachable D5 validation: a check written correctly against the wrong input.
  The guard now walks the corpora. Found by C3, which went looking for subjects
  whose evidence contradicts itself and found exactly one.
- **A helper can fabricate the defect it is testing for.** The first waiver
  survival test mutated findings in place and recomputed fingerprints through
  `FindingSet.Add`. It reported 15 of 37 baseline entries broken by a flip that
  touched only `Exploitability` and `Metadata` — the flip was innocent, and the
  helper had silently re-fingerprinted the rule engine's findings under the
  wrong recipe. That 15 is what led to the split above. Both halves of the test
  now come from real scans.

#### Next, in order of value

1. **Checksum verification.** Several providers encode a checksum in the token
   itself, and verifying one is deterministic rather than heuristic. This is
   the thing that moves C2's divergence number honestly, and it is the reason
   E3 did not. It needs a verifiable test vector first: unverified checksum
   logic would put false DETERMINISTIC claims in the ledger, which is worse
   than the silence it replaces.
2. **Track G — reachability and applicability.** Gate B, `PREVENTED` as a
   normal result, and the applicability ladder. It also needs a corpus (below).
3. **J.** Tracks A–I are complete apart from full scan reproducibility (9.4),
   which stays out of scope: it needs the rule set, analyzer versions and
   advisory data snapshotted, and each is its own problem. What remains is the
   rule migration.

#### Open items no track owns

- **`api-abuse` API-ABUSE-001 has precision 0.000** and has never scored a true
  positive on the corpus. Re-measure rather than re-describe; a first-order
  candidate for Track J.
- **Gate B has no corpus.** The refutation suite is offline-only by design, so
  dependency applicability and reachability are unrepresented. Track G must
  bring one scored against a pinned vulnerability snapshot before deterministic
  unreachability may suppress anything.
- **`isBareProviderPrefix` is unreachable.** No rule matches a bare `AKIA` or
  `"glpat-"`, so the refiner never sees a candidate. Either it is dead or the
  rules changed under it.
- ~~**The intelligence service counts disputers as corroboration.**~~
  **Corrected — this was overstated.** The service has no way to record a
  dispute: both its claim producers add supporting claims, so its publish guard
  counts only supporting reporters by construction and is correct as written.
  What is true is that it counts *participants* rather than *believers*, and
  nothing stated that assumption — which `nox-core` v0.2.0 made reachable by
  adding `Polarity`. Now guarded by
  `TestEveryClaimThisServiceRecordsIsSupporting`, which fails the moment a
  non-supporting claim is added and names `Ledger.IndependentSupport` as the
  fix. Recorded here rather than deleted, because the error is more instructive
  than the item: a live security defect was reported on the strength of reading
  one call site, when checking whether the input could exist took two greps.
- **Dedup's own drop is unrecorded.** Track F names the flow, so nothing is
  lost about *what* was merged, but which specific finding was discarded is not
  written down.
- **Track D is inert until a project opts in.** `policy.require_capabilities`
  is empty everywhere by design — that is what avoids the adoption cliff — and
  it protects nothing until a repository declares what its triage depends on.

### 2.10 Explicit non-goals

Carried from the proposal, and worth restating because each is a plausible
wrong turn: do not replace all regex; do not move all plugins into core; do not
add AI adjudication — AI may research, explain, hypothesise, prioritise and
produce evidence, but the authoritative conclusion stays deterministic; do not
maximise vulnerability count.

The metric is: **how often does nox reach the correct, reproducible conclusion
about whether a security condition matters to this application?**
