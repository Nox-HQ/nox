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
- `plugins/nox-plugin-grc/fedramp.go`, `plugins/nox-plugin-grc/frameworks.go`
- Tests: baseline inclusion (High ⊇ Moderate ⊇ Low), control counts, framework lookup

## Explicitly Out of Scope

- SaaS dashboards
- Automatic remediation (fix-suggest plugin provides suggestions only)
- Closed-source rules
