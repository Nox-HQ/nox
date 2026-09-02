# Nox Roadmap

## Phase 0 — Foundation (v0.1) ✓

- Repo setup
- CLI scaffold
- File discovery
- Canonical findings schema
- Secrets scanning (SEC-001–SEC-023)
- JSON output

## Phase 1 — CI-Ready (v0.2) ✓

- SARIF output
- CycloneDX SBOM
- SPDX SBOM
- OSV dependency scanning
- Basic IaC rules

## Phase 2 — AI Security (v0.3) ✓

- AI inventory extraction
- Prompt / RAG rules
- Tool exposure rules
- Logging & privacy rules

## Phase 3 — MCP Integration (v0.4) ✓

- MCP server (18 tools)
- Resource-based artifact serving
- Agent-safe defaults
- GitHub Action example

## Phase 4 — Ecosystem Hardening (v0.5) ✓

- Rule testing harness
- Performance tuning
- Baseline/suppressions
- Documentation polish

## Phase 5 — Optional Intelligence (v0.6) ✓

- Agent-assisted explanations (agent-go)
- Policy reasoning
- Experimental workflows

## Phase 6 — Plugin Ecosystem & Competitive Parity (v0.7) ✓

- gRPC plugin system with subprocess spawning
- Plugin registry with OCI distribution and trust verification
- SDK with conformance testing and 10 plugin tracks
- Plugin scaffolding (`nox plugin init`)
- 23 plugins across 9 tracks (92 plugin rules, 213 tests):
  - core-analysis: arch-lint, container, sast
  - dynamic-runtime: api-abuse, attack-surface, dast
  - supply-chain: artifact-integrity, depconfusion, provenance
  - policy-governance: baseline-mgmt, policy-gate, risk-register
  - threat-modeling: threat-explain, threat-model
  - intelligence: risk-score, threat-enrich
  - incident-readiness: detect-ready, playbook
  - developer-experience: lsp, orchestrator, report-composer
  - agent-assistance: case-bundle, triage-agent
- Interactive TUI finding inspector (`nox show`)
- Finding detail enrichment with source context
- VEX support (OpenVEX format)
- Terraform plan scanning
- SBOM input scanning
- Encoded secret detection
- 568 built-in rules:
  - 160 secret detectors (SEC-001–SEC-160)
  - 12 data sensitivity / PII rules (DATA-001–DATA-012)
  - 21 AI security rules (AI-001–AI-021)
  - 369 IaC rules (IAC-001–IAC-369): Terraform, Kubernetes, GitHub Actions, CloudFormation, Docker, Helm, Compose, Ansible, Kustomize, Serverless Framework, Azure, GCP, CI/CD, cross-resource graph analysis
  - 6 dependency/container/license rules (VULN/CONT/LIC)
- Compliance framework mapping (~94% rule coverage):
  - CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP Top 10, OWASP LLM Top 10, OWASP Agentic
  - FedRAMP Low / Moderate / High (in GRC plugin, mapped from NIST 800-53 controls)
- AI-BOM v2.0.0: model provenance, prompt templates, tool permission matrix, connection graph
- MCP tools: data_sensitivity_report, compliance_report (8 core frameworks)

## Phase 7 — Advanced Analysis ✓

Pipeline: SAST → IaC Graph (core) → Reachability → Taint → Risk-Score → AI-Triage → K8s Runtime

### 7a. Graph-Based IaC Cross-Resource Analysis — core enhancement ✓

Extends `core/analyzers/iac/tfplan.go` with a resource relationship model.
Not a separate plugin — natural extension of the core IaC analyzer.

- Resource dependency graph from Terraform plan (HCL configuration references)
- 4 cross-resource pattern detectors:
  - IAC-366: Public subnet + unrestricted security group in same VPC
  - IAC-367: Internet-facing load balancer with HTTP listener (no TLS)
  - IAC-368: Public S3 bucket without server-side encryption config
  - IAC-369: Unrestricted security group attached to database instance
- `core/analyzers/iac/tfgraph.go`: `BuildResourceGraph()`, resource indexing, cross-resource checks
- Separate `aws_security_group_rule` and IPv6 (`::/0`) detection
- Compliance mapped: CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP Top 10
- 23 tests (19 cross-resource pattern tests + 4 graph/helper tests)
- ~270 LOC implementation + ~500 LOC tests

### 7b. Reachability Analysis — new plugin `nox-plugin-reachability` ✓

Separate plugin on the `core-analysis` track. Post-processes VULN findings to classify
vulnerable packages as reachable, unreachable, or undetermined based on import analysis.

- Import extraction for Go (`go/parser`), Python (regex), JS/TS (regex)
- Cross-references VULN finding metadata (`package`, `ecosystem`) against workspace imports
- 3 rules: REACH-001 (unreachable/info), REACH-002 (reachable/high), REACH-003 (undetermined/low)
- PyPI name mapping (~15 common divergences: Pillow→PIL, scikit-learn→sklearn, etc.)
- Enriches original VULN findings with reachability status
- `ToolWithContext("analyze_reachability")` on core-analysis track
- ~550 LOC implementation + ~450 LOC tests, 19 tests all passing

### 7c. Intraprocedural Taint Analysis — new plugin `nox-plugin-taint-analysis` ✓

Separate plugin on the `core-analysis` track. Tracks data flow from untrusted sources to
dangerous sinks within function bodies — catches multi-line flows that single-line regex misses.

- Go AST-based analysis (`go/ast` + `go/parser`) for Go files
- Regex-based analysis with variable tracking for Python, JavaScript, TypeScript
- 5 taint flow rules: TAINT-001 (SQL injection), TAINT-002 (command injection), TAINT-003 (XSS), TAINT-004 (path traversal), TAINT-005 (code injection)
- Sanitizer detection (strconv.Atoi, parseInt, html.EscapeString, etc.) to reduce false positives
- Taint propagation through variable assignments within function scope
- `Tool("scan")` on core-analysis track, passive risk, read-only
- ~1,090 LOC implementation + ~740 LOC tests + ~100 LOC testdata, 33 tests all passing

### 7d. AI-Powered Triage — merge into existing `nox-plugin-triage-agent` ✓

Merges into the existing triage-agent plugin rather than creating a new one. The triage-agent
already classifies findings by priority (immediate/scheduled/backlog/informational) — LLM-based
severity adjustment is the same domain concern, just a better tool.

- LLM-assisted severity adjustment via agent-go `plannerllm.Provider` interface
- Multi-provider support: OpenAI (implemented), Anthropic, Gemini, Ollama, Cohere (stubs ready)
- Opt-in only (`ai_triage: true` input parameter), never affects deterministic scan results
- Default behavior remains deterministic pattern-based prioritization
- Graceful degradation: returns original findings unchanged on LLM failure
- Auto-classification of true/false positives with structured JSON response parsing
- Environment-based provider config: `NOX_AI_PROVIDER`, `NOX_AI_API_KEY`, `NOX_AI_MODEL`, `NOX_AI_BASE_URL`
- `provider.go` (~90 LOC), `ai_triage.go` (~120 LOC), `ai_triage_test.go` (~190 LOC)
- OpenAI provider implementation in agent-go (~80 LOC) — supports OpenAI, Azure, Ollama (compat mode)
- 20 tests total (9 new AI triage + 11 existing), all passing

### 7e. Kubernetes Runtime Scanning — new plugin `nox-plugin-k8s-runtime` ✓

Separate plugin on the `dynamic-runtime` track. Cannot merge into `container` (which scans
static Dockerfiles) or `dast` (which probes HTTP endpoints) — live cluster inspection is a
fundamentally different concern with different dependencies (client-go), credentials (kubeconfig),
and risk class (active).

- Live cluster scanning via Kubernetes API (in-cluster config + kubeconfig fallback)
- 8 rules: KRUNT-001 (root), KRUNT-002 (privileged), KRUNT-003 (host namespace), KRUNT-004 (no network policy), KRUNT-005 (no resource limits), KRUNT-006 (unpinned image), KRUNT-007 (SA token automount), KRUNT-008 (dangerous capabilities)
- Container-level checks with `effectiveSecurityContext` merging (pod → container override)
- Init container scanning (both `.Spec.InitContainers` and `.Spec.Containers`)
- Registry port detection in `isUnpinnedImage` (distinguishes `registry:5000/app` from `image:latest`)
- Graceful degradation: cluster unreachable → diagnostic error, no crash
- `Tool("scan")` on dynamic-runtime track, active risk, needs confirmation, network hosts `*`
- Compliance mapped: CIS 5.x, NIST-800-53, PCI-DSS, OWASP Top 10
- ~310 LOC implementation + ~400 LOC tests, all passing

### Phase 7 Summary

| Feature | Location | Type | Track | Estimated LOC |
|---|---|---|---|---|
| IaC Graph Analysis | `core/analyzers/iac/tfgraph.go` | Core enhancement ✓ | — | ~270 (impl) + ~500 (tests) |
| Reachability | `nox-plugin-reachability` | New plugin ✓ | core-analysis | ~550 (impl) + ~450 (tests) |
| Taint Analysis | `nox-plugin-taint-analysis` | New plugin ✓ | core-analysis | ~1,090 (impl) + ~740 (tests) |
| AI-Powered Triage | `nox-plugin-triage-agent` | Plugin update ✓ | agent-assistance | ~290 (impl) + ~190 (tests) |
| K8s Runtime | `nox-plugin-k8s-runtime` | New plugin ✓ | dynamic-runtime | ~310 (impl) + ~400 (tests) |

Post-Phase 7 plugin count: 23 → 26 (3 new plugins, 1 core enhancement, 1 plugin update).

## Phase 8 — AI-Enhanced Security Intelligence ✓

Pipeline: SAST → IaC Graph → Reachability → Taint → Risk-Score → AI-Triage → K8s Runtime → **AI-Explain → AI-Threat-Model → GRC → Red-Team**

### 8a. AI Threat-Explain — enhance `nox-plugin-threat-explain` ✓

Adds opt-in LLM-powered explanation generation to the existing threat-explain plugin.
Enhances static explanations with contextual, audience-targeted guidance.

- Opt-in via `ai_explain: true` input parameter
- LLM receives: finding rule_id, severity, CWE, file, matched line, static explanation/impact/audience
- LLM returns: enhanced explanation, contextual impact, specific remediation guidance
- Metadata enrichment: `ai_explained`, `ai_explanation`, `ai_impact`, `ai_remediation`, `original_explanation`, `original_impact`
- Graceful degradation: LLM failure → static explanations preserved + `ai_explain_error`
- 7-provider LLM support via `plannerllm.Provider` (OpenAI, Anthropic, Gemini, Ollama, Cohere, Bedrock, Copilot)
- `provider.go`, `ai_explain.go`, `ai_explain_test.go` (9 AI tests)
- 18 tests total, all passing

### 8b. AI Threat-Model Agent — enhance `nox-plugin-threat-model` ✓

Adds AI-powered comprehensive STRIDE threat modeling to the existing threat-model plugin.
Two modes: deterministic regex (default) and AI-enhanced analysis (opt-in).

- Opt-in via `ai_model: true` input parameter
- LLM receives: deterministic findings + file inventory with detected STRIDE categories
- LLM returns: threat_id, stride_category, title, description, severity, affected_component, attack_scenario, mitigation, likelihood
- AI-generated threats use rule IDs `THREAT-AI-001+` to distinguish from deterministic rules
- Metadata: `ai_modeled`, `attack_scenario`, `mitigation`, `likelihood`, `affected_component`
- `provider.go`, `ai_threat_model.go`, `ai_threat_model_test.go` (10 AI tests)
- 19 tests total, all passing

### 8c. GRC Compliance — new plugin `nox-plugin-grc` ✓

New plugin on the `policy-governance` track. Governance, Risk & Compliance with 12 framework
coverage, gap analysis, evidence collection, and AI-powered control mapping.

- 12 compliance frameworks: SOC2, ISO 27001, GDPR, FedRAMP Low/Moderate/High, HIPAA, PCI-DSS, NIST 800-53, NIST CSF, CIS Controls v8, CMMC
- 3 tools: `assess` (compliance assessment), `gap_report` (gap analysis), `evidence` (evidence collection)
- 10 rules: GRC-001 (critical control gap), GRC-002 (coverage below threshold), GRC-003 (stale evidence), GRC-004 (conflicting controls), GRC-005 (GDPR data protection), GRC-006 (SOC2 access control), GRC-007 (FedRAMP encryption), GRC-008 (incident response), GRC-009 (NIST CSF monitoring), GRC-010 (CMMC maturity)
- Gap analysis with coverage percentage and priority remediation
- Evidence collection mapped to framework controls
- Opt-in AI-powered gap analysis via `ai_assess: true`
- `frameworks.go`, `gap_analysis.go`, `evidence.go`, `ai_gap.go`, `provider.go`
- 27 tests total, all passing

### 8d. Red Team — new plugin `nox-plugin-red-team` ✓

New plugin on the `dynamic-runtime` track. AI-powered attack path analysis and
exploit validation with two tools: passive analysis and active validation.

- 2 tools: `analyze` (passive, read-only), `validate` (active, needs confirmation)
- 7 attack chain detection patterns: auth bypass→data exposure, privilege escalation, SQL injection→exfiltration, container escape, command injection, weak auth+rate limit, XSS+data exposure
- HTTP validation: security headers, TLS configuration, rate limit testing
- 10 rules: REDTEAM-001–005 (attack chains), REDTEAM-006–010 (validation findings)
- Opt-in AI-powered attack path reasoning via `ai_analyze: true`
- Safety: `RiskActive` + `WithNeedsConfirmation()` + `WithNetworkHosts("*")`
- `attack_paths.go`, `validate.go`, `ai_analysis.go`, `provider.go`
- 33 tests total, all passing

### Phase 8 Summary

| Feature | Location | Type | Track | Tests |
|---|---|---|---|---|
| AI Threat-Explain | `nox-plugin-threat-explain` | Plugin update ✓ | threat-modeling | 18 |
| AI Threat-Model | `nox-plugin-threat-model` | Plugin update ✓ | threat-modeling | 19 |
| GRC Compliance | `nox-plugin-grc` | New plugin ✓ | policy-governance | 27 |
| Red Team | `nox-plugin-red-team` | New plugin ✓ | dynamic-runtime | 33 |
| FedRAMP Baselines | `nox-plugin-grc/fedramp.go` | GRC plugin ✓ | policy-governance | — |

Post-Phase 8: 26 → 28 plugins (2 new, 2 updated), 10 new GRC + 10 new REDTEAM rules, FedRAMP baselines in GRC plugin (8 core compliance frameworks).

### 8e. FedRAMP Compliance Baselines — moved to GRC plugin ✓

FedRAMP Low, Moderate, and High baselines with full NIST 800-53 control mappings.
Originally implemented in core, moved to the GRC plugin (`nox-plugin-grc`) as the
proper home for governance/risk/compliance framework assessments.

- 3 baselines: `fedramp-low`, `fedramp-moderate`, `fedramp-high` (in GRC plugin)
- Baselines are cumulative: High ⊇ Moderate ⊇ Low
- Control counts: Low 25 / Moderate 38 / High 42 NIST 800-53 controls
- Unique rule coverage: Low 302 / Moderate 523 / High 595 rules
- FedRAMP entries removed from `core/compliance/data.go` (1,517 lines)
- Core supported frameworks: 11 → 8; GRC plugin frameworks: 10 → 12
- `fedramp.go`, `frameworks.go` in the `nox-plugin-grc` repository
- Tests: baseline inclusion (High ⊇ Moderate ⊇ Low), control counts, framework lookup

## Phase 9 — Closing Security Analysis Gaps ✓

Three gaps vs LLM-powered security tools (e.g. Claude Code Security): self-validation,
business logic flaws, and interprocedural data flow. Addressed with targeted AI-augmented
plugins that keep nox's deterministic core intact.

Pipeline: SAST → IaC Graph → Reachability → Taint (intra + **interproc**) → Risk-Score → AI-Triage → K8s Runtime → AI-Explain → AI-Threat-Model → GRC → Red-Team → **Validator → Logic-Scan**

### 9a. Agentic Finding Validator — new plugin `nox-plugin-validator` ✓

New plugin on the `agent-assistance` track. Uses LLM reasoning to classify findings
as true positive, false positive, or needs-review — reducing false positive noise.

- Opt-in via `ai_validate: true` input parameter
- Code context extraction: flagged line ±30 lines, enclosing function, imports
- Tiered validation: high-confidence auto-confirm, medium/low → LLM
- FP findings downgraded to `info` severity (not removed — auditability)
- 4 rules: VALID-001 (confirmed TP), VALID-002 (likely FP), VALID-003 (needs review), VALID-004 (validation error)
- 7-provider LLM support via `provider.go` pattern (OpenAI, Anthropic, Gemini, Ollama, Cohere, Bedrock, Copilot)
- Graceful degradation: LLM failure → original findings preserved
- `validator.go`, `prompt.go`, `provider.go`
- ~990 LOC implementation, 17 tests all passing

### 9b. Business Logic Analyzer — new plugin `nox-plugin-logic-scan` ✓

New plugin on the `core-analysis` track. Detects IDOR, broken access control, mass
assignment, and race conditions — vulnerability classes that pattern-based rules cannot catch.

- Opt-in AI via `ai_logic: true` input parameter
- File inventory: scans for route handlers, controllers, middleware, models
- Per-endpoint analysis: route definition + auth checks + data access patterns
- Language support: Go (net/http, gin, echo, fiber), Python (Flask, Django, FastAPI), JS/TS (Express, Next.js)
- 3 deterministic rules: LOGIC-001 (IDOR/CWE-639), LOGIC-002 (missing authorization/CWE-862), LOGIC-003 (mass assignment/CWE-915)
- AI-enhanced detection for race conditions, privilege escalation, broken access control
- `scanner.go`, `extractors.go`, `provider.go`
- ~1,500 LOC implementation, 21 tests all passing

### 9c. Interprocedural Taint Enhancement — extend `nox-plugin-taint-analysis` ✓

Extends the existing taint analysis plugin to track data flow across function boundaries
within a single package/module. Catches cross-function injection patterns that
intraprocedural analysis misses.

- Go call graph via `go/ast` + `go/parser`: `CallGraph`, `FuncInfo`, parameter indexing
- `TaintContext` stack with max depth 3 for bounded analysis
- Cross-function taint propagation: tainted args → callee parameters → sink detection
- Python/JS interprocedural via regex-based `TextCallGraph` with brace/indent body extraction
- 2 new rules: TAINT-006 (cross-function SQLi/CWE-89), TAINT-007 (cross-function CMDi/CWE-78)
- Deduplication of flows across intra/interprocedural passes
- `callgraph.go` (~460 LOC), `text_callgraph.go` (~360 LOC), `callgraph_test.go` (~340 LOC)
- 3 interprocedural testdata files (Go, Python, JavaScript)
- 12 new interprocedural tests (45 total plugin tests), all passing

### Phase 9 Summary

| Feature | Location | Type | Track | Tests |
|---|---|---|---|---|
| Finding Validator | `nox-plugin-validator` | New plugin ✓ | agent-assistance | 17 |
| Business Logic | `nox-plugin-logic-scan` | New plugin ✓ | core-analysis | 21 |
| Interprocedural Taint | `nox-plugin-taint-analysis` | Plugin update ✓ | core-analysis | 45 (12 new) |

Post-Phase 9: 28 → 30 plugins (2 new, 1 updated).
New rules: VALID-001–004, LOGIC-001–003, TAINT-006–007 (9 new plugin rules).
Total plugin rules: 128 + 9 = 137. Total project rules: 568 + 137 = 705.

## Phase 10 — Dynamic Exploit Validation

Moves nox from "this looks dangerous" to "here is the attack path, here is proof
it works, and here is the test that keeps it fixed."

### 10a. Evidence spine — `core/evidence` ✓

The rules that make every downstream verdict trustworthy, implemented once.

- Exploitability lifecycle: POTENTIAL → PLAUSIBLE → PREVENTED / INCONCLUSIVE → CONFIRMED,
  independent of severity
- Evidence `Kind` with explicit strengths, from `heuristic` (10) to `public_advisory` (100)
- `Provenance` with an opaque reporter id, so corroboration can be counted without
  learning who reported
- `Ledger` aggregation with two hard rules: CONFIRMED requires deterministic evidence
  at reproduction strength; a semantic-only ledger is capped at MEDIUM
- `IndependentSources()` counts distinct reporters, not observations — 100 self-scans
  are one source
- `DeriveExploitability` — the single state machine both capabilities use. A run cut
  short by a budget is INCONCLUSIVE, never PREVENTED; silence is never prevention
- `Describe()` fixes the user-facing wording so no surface of nox ever says "safe"

### 10b. Dynamic Exploit Validation — `core/attack`, `nox attack` ✓

Target-aware, evidence-backed exploitation of agentic systems. Generalises the
`nox confirm` loop into a scenario model with assets, trust boundaries,
invariants, budgets, safety profiles, replay, and regression.

- Domain model: Asset, TrustBoundary, Invariant, Hypothesis, Scenario, PathStep
- Scenario library: `PI-DIRECT`, `PI-INDIRECT`, `TOOL-UNAUTH`, `EXFIL-FS-NET`,
  each with a benign control that must never trip
- Deterministic canary minting; reflection immunity asserted before any probe leaves
  the process — an echoing target can never be scored a hijack
- Oracles: deterministic (canary at sink), trace (unauthorized tool invoked),
  refusal (observed defense). Semantic verdicts are labelled and cannot confirm
- Safety profiles `safe` / `sandbox` / `staging` / `authorized-live`, with `safe`
  enforced by target wiring rather than by policy
- Budgets on attempts, requests, model calls, tool invocations, and wall clock
- k-of-n determinism gate; attack traces with replay commands
- Commands: `nox attack plan` (offline), `run`, `replay`, `regress` (ACTIVE, `--authorize`)
- MCP: `attack_plan` only (read-only, offline). The ACTIVE subcommands are
  deliberately not MCP tools — a model-initiated call cannot make the human
  authorization `--authorize` represents, and nox analyses untrusted repos, so an
  exposed runner would be a confused-deputy request-forgery primitive. Pinned by
  a test that fails if one is ever registered.
- Regression cases report `outcome` (HELD / REGRESSED / UNEXERCISED) separately
  from `exploitability`, mirroring VEX's `not_affected`-needs-a-justification rule
- Artifacts: `attack.plan.json`, `attack.trace.json`, `attack.cases.json`, `attack.regress.json`
- Docs: `docs/attack.md`

### Deliberately not in Phase 10

Multi-agent and MCP trust-chain exploitation, delegation attacks, and adaptive
adversarial attack agents. These depend on the foundations above being trusted
first.

**Vulnerability intelligence is not a CLI feature.** The observation network,
cross-tenant aggregation, autonomous research agents, advisory publication,
coordinated disclosure, and early warning require multi-tenant state, auth, and an
operational footprint that has no business in a CLI release cycle. The client-side
half — privacy redaction, the private evidence graph, and organisation-specific
blast radius — stays local and auditable, but it is designed against a service
rather than shipped as a stand-in for one. The CLI *consumes* the service — since
Phase 11, by default — and the boundary is what keeps both sides honest. See
`docs/design/intelligence-service.md`.

## Phase 11 — Intelligence by Default

Phase 11 changes one default and then plans against where the market is going,
not where it is. The default: every online `nox scan` asks NOX Intelligence for
advisories and verifies the answer against OSV.dev (`docs/intelligence.md`).
Opting out is one config key; `--offline` still asks nobody. Contribution stays a
separate, opt-in decision. That is the whole of 11a. Everything after it is
ordered by five observations about the market, each of which names the gap it
turns into work.

**What the market is doing.** (1) Finding vulnerabilities is commoditised —
every scanner, and every LLM, finds the same SQL injection; *triage* is the
product, and triage is a network property (what did everyone else do with this
finding?). (2) Buyers are consolidating onto platforms; a primitive survives that
by being the best-verified *source* those platforms consume, not by growing a
dashboard. (3) AI is on both sides: agents generate the code that gets scanned
and agents consume the findings, so the API shape matters more than the CLI
shape. (4) Regulation — the EU Cyber Resilience Act's reporting duties, VEX as
the exchange format — turns "is this reachable in *our* deployment?" into a
document with a deadline. (5) Trust in a shared source is earned in public:
uptime, a published payload, verified claims, and a visible way to leave.

### 11a. The default, and its opt-out ✓

- `scan.intelligence` resolves `disabled > endpoint > NOX_INTEL_ENDPOINT >
  compiled-in endpoint`; `scan.osv.base_url` names the reference for
  verification and for self-hosted mirrors.
- Every intel subcommand defaults to the same endpoint scans use.
- Verification is on by default: a withheld advisory is restored from the
  reference and reported as a degradation; an unreachable service degrades to
  the OSV.dev scan nox always ran.
- Tests assert the three states from the wire: service + reference, reference
  only, nobody.

### 11b. Trust in public — earned before the network is asked for anything

Ordered first because a compiled-in default is a promise the project makes on
behalf of every user who never reads a config file.

- **Payload page** — `docs/intelligence.md` is the canonical statement of what
  leaves the machine; the service publishes the same page and a status/uptime
  page, so the promise is checkable from either side.
- **Service CI** — the service has none today; its store tests skip without a
  database. A Postgres service container in CI makes the tenant-isolation test a
  gate, not an aspiration. Nothing network-derived ships until this is green.
- **Verified domain claims** — an organisation's `verified: true` is an operator
  assertion today; DNS TXT verification turns it into a fact the service checked.
- **The endpoint's name** — the default is compiled in, so the domain is now an
  API contract. Decide `intel.klarlabs.de` vs `intel.nox-hq.dev` once, keep a
  permanent redirect from whichever loses, and treat any later change as a
  breaking release.
- **Release notes** name the default change as the headline and the one-line
  opt-out, every release until the next default changes.
- **Operator credentials** — the founder token is reissued and stored outside a
  shell history; billing stays postponed until there is more than one reporter
  to bill.

### 11c. Reporters, not observations — the only number that matters

The evidence spine counts independence in distinct reporters, so the network's
value is exactly its reporter count, and every feature below is worthless at one.
The north-star metric is *distinct reporters per ecosystem per week*; the
service exposes it, and the roadmap re-orders around whatever moves it. Nothing
that requires corroboration (11d–11f) is promised at a reporter count that
cannot supply it.

### 11d. Triage is the product — the first network feature

- **Dismissal corpus** — "what did everyone else do with this finding": per
  fingerprint class, the share of reporters who waived, fixed, or disputed, with
  the reasons redacted to the allowlist. Arrives on the finding as
  `intel_corroboration` and in `nox why`; never changes a verdict, because
  independence and repetition are not evidence at reproduction strength.
- **KEV / EPSS / reachability as Community triage** — deterministic, public
  inputs the CLI already has or can fetch; they reorder, they do not confirm.
- **Early warning stays deferred** until reporters fund the research that
  produces it; an embargoed disclosure is excluded from early warning by design.

### 11e. Agents are the consumers — the API is the product surface

- **Intelligence API / OEM** — the same advisory + corroboration answer over a
  documented, versioned HTTP surface for platforms and agents; MCP exposes it
  through the existing read-only tools so an agent that scans with nox reasons
  with the network's triage without another integration.
- The CLI stays a thin, deterministic consumer: the service may add fields, the
  CLI may ignore them, and neither release blocks the other.

### 11f. Regulation turns exposure into a document — Enterprise

- **Organisation exposure / blast radius** — the private evidence graph answers
  "which of *our* services carry this, and is it reachable there?" on data that
  never leaves.
- **CRA / VEX reporting** — that answer rendered as VEX the way `nox vex`
  renders it today, with the corroboration that makes a `not_affected`
  defensible attached as evidence rather than asserted.

### Deliberately not in Phase 11

Research orchestration and autonomous exploit research on the service, advisory
publication, and coordinated disclosure. All three are designed in
`docs/design/intelligence-service.md` and all three depend on 11b and 11c being
true first: a network that cannot show its isolation test or count its reporters
has no business publishing advisories.

## Explicitly Out of Scope

- SaaS dashboards
- Automatic remediation (fix-suggest plugin provides suggestions only)
- Closed-source rules
