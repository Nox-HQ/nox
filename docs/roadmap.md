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
- 564 built-in rules:
  - 160 secret detectors (SEC-001–SEC-160)
  - 12 data sensitivity / PII rules (DATA-001–DATA-012)
  - 21 AI security rules (AI-001–AI-021)
  - 365 IaC rules (IAC-001–IAC-365): Terraform, Kubernetes, GitHub Actions, CloudFormation, Docker, Helm, Compose, Ansible, Kustomize, Serverless Framework, Azure, GCP, CI/CD
  - 6 dependency/container/license rules (VULN/CONT/LIC)
- Compliance framework mapping (~94% rule coverage):
  - CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP Top 10, OWASP LLM Top 10, OWASP Agentic
- AI-BOM v2.0.0: model provenance, prompt templates, tool permission matrix, connection graph
- MCP tools: data_sensitivity_report, compliance_report (8 frameworks)

## Phase 7 — Advanced Analysis (planned)

Pipeline: SAST → IaC Graph (core) → Reachability → Taint → Risk-Score → AI-Triage → K8s Runtime

### 7a. Graph-Based IaC Cross-Resource Analysis — core enhancement

Extends the existing `core/analyzers/iac/tfplan.go` with a resource relationship model.
Not a separate plugin — this is a natural extension of the core IaC analyzer.

- Build a resource dependency graph from Terraform state/plan
- Detect misconfigurations that span multiple resources (e.g., public subnet + no NACL + open security group)
- Add `core/analyzers/iac/tfgraph.go` with `buildResourceGraph()` and cross-resource pattern rules
- Estimated scope: ~200–300 LOC

### 7b. Reachability Analysis — new plugin `nox-plugin-reachability`

Separate plugin on the `core-analysis` track. Cannot merge into `sast` because SAST is
line-based regex matching while reachability requires AST parsing and call graph construction —
fundamentally different data model and dependencies (go/ast, tree-sitter).

- Language-specific call graph construction (Go, Python, JavaScript/TypeScript)
- Determine whether vulnerable dependency functions are actually called
- Reduce false positives in dependency scanning by filtering unreachable code paths
- Runs as a post-processor: consumes VULN findings, filters by reachability
- Estimated scope: ~500–800 LOC

### 7c. Cross-File Taint Analysis — new plugin `nox-plugin-taint-analysis`

Separate plugin on the `core-analysis` track. Cannot merge into `sast` because taint analysis
requires interprocedural SSA/CFG dataflow tracking — 10x more complex than pattern matching
and requires entirely different dependencies and data structures.

- Dataflow tracking across function and file boundaries
- Detect untrusted input flowing to sensitive sinks (SQL, shell, eval)
- Language-specific AST parsing for Go, Python, JavaScript
- Complements `sast` by confirming actual dataflow paths for pattern-matched findings
- Estimated scope: ~1000–1500 LOC

### 7d. AI-Powered Triage — merge into existing `nox-plugin-triage-agent`

Merges into the existing triage-agent plugin rather than creating a new one. The triage-agent
already classifies findings by priority (immediate/scheduled/backlog/informational) — LLM-based
severity adjustment is the same domain concern, just a better tool. Adding ~150–200 LOC behind
an opt-in flag keeps it lightweight and gated.

- LLM-assisted severity adjustment based on code context
- Auto-classification of true vs. false positives using historical data
- Integrates with the `assist/` module via agent-go
- Opt-in only (`--ai-triage` flag), never affects deterministic scan results
- Default behavior remains deterministic pattern-based prioritization

### 7e. Kubernetes Runtime Scanning — new plugin `nox-plugin-k8s-runtime`

Separate plugin on the `dynamic-runtime` track. Cannot merge into `container` (which scans
static Dockerfiles) or `dast` (which probes HTTP endpoints) — live cluster inspection is a
fundamentally different concern with different dependencies (client-go), credentials (kubeconfig),
and risk class (active).

- Live cluster scanning via kubectl/API access
- Compare running workloads against IaC definitions for drift detection
- Runtime-specific checks (running as root, mounted secrets, network policies)
- Breaks the offline-first constraint — clearly marked as optional
- Requires cluster credentials and namespace allow-listing in safety manifest
- Estimated scope: ~600–800 LOC

### Phase 7 Summary

| Feature | Location | Type | Track | Estimated LOC |
|---|---|---|---|---|
| IaC Graph Analysis | `core/analyzers/iac/tfgraph.go` | Core enhancement | — | ~200–300 |
| Reachability | `nox-plugin-reachability` | New plugin | core-analysis | ~500–800 |
| Taint Analysis | `nox-plugin-taint-analysis` | New plugin | core-analysis | ~1000–1500 |
| AI-Powered Triage | `nox-plugin-triage-agent` | Plugin update | agent-assistance | ~150–200 |
| K8s Runtime | `nox-plugin-k8s-runtime` | New plugin | dynamic-runtime | ~600–800 |

Post-Phase 7 plugin count: 23 → 26 (3 new plugins, 1 core enhancement, 1 plugin update).

## Explicitly Out of Scope

- SaaS dashboards
- Automatic remediation (fix-suggest plugin provides suggestions only)
- Closed-source rules
