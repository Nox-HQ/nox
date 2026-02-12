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
- Reference plugins: risk-score, secret-verify, fix-suggest, lsp
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

### Reachability Analysis
- Language-specific call graph construction (Go, Python, JavaScript/TypeScript)
- Determine whether vulnerable dependency functions are actually called
- Reduce false positives in dependency scanning by filtering unreachable code paths
- Planned as a plugin on the `core-analysis` track

### Graph-Based IaC Cross-Resource Analysis
- Build a resource dependency graph from Terraform state/plan
- Detect misconfigurations that span multiple resources (e.g., public subnet + no NACL + open security group)
- Requires extending `tfplan.go` with a resource relationship model

### Cross-File Taint Analysis
- Dataflow tracking across function and file boundaries
- Detect untrusted input flowing to sensitive sinks (SQL, shell, eval)
- Language-specific AST parsing for Go, Python, JavaScript
- Planned as a plugin on the `core-analysis` track

### AI-Powered Triage
- LLM-assisted severity adjustment based on code context
- Auto-classification of true vs. false positives using historical data
- Integrates with the `assist/` module
- Opt-in only, never affects deterministic scan results

### Kubernetes Runtime Scanning
- Live cluster scanning via kubectl/API access
- Compare running workloads against IaC definitions for drift detection
- Runtime-specific checks (running as root, mounted secrets, network policies)
- Planned as a plugin on the `dynamic-runtime` track
- Breaks the offline-first constraint — clearly marked as optional

## Explicitly Out of Scope

- SaaS dashboards
- Automatic remediation (fix-suggest plugin provides suggestions only)
- Closed-source rules
