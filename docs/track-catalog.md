# Plugin Track Catalog

Nox plugins are organized into 10 tracks, each representing a distinct security practice area.

## Track Overview

| # | Track | Risk Class | CI-Safe | Offline | Read-Only |
|---|-------|-----------|---------|---------|-----------|
| 1 | core-analysis | passive | yes | yes | yes |
| 2 | dynamic-runtime | active | no | no | no |
| 3 | ai-security | passive | yes | yes | yes |
| 4 | threat-modeling | passive | yes | yes | yes |
| 5 | supply-chain | passive | yes | no | yes |
| 6 | intelligence | passive | yes | no | yes |
| 7 | policy-governance | passive | yes | yes | yes |
| 8 | incident-readiness | passive | yes | yes | yes |
| 9 | developer-experience | passive | yes | yes | yes |
| 10 | agent-assistance | passive | yes | no | yes |

## Track 1: Core Analysis

**Characteristics:** Deterministic, artifact-based, CI-safe

Plugins that perform static analysis on source code and configuration files. These are the workhorses of the scanning pipeline — fast, deterministic, and safe to run anywhere.

**Plugins:**
- **nox-plugin-sast** — Language-specific vulnerability detection (SQL injection, XSS, path traversal)
- **nox-plugin-secrets-pro** — Enhanced secrets analysis with encoding detection and rotation tracking
- **nox-plugin-deps-deep** — Transitive dependency audit, license compliance, health scoring
- **nox-plugin-container** — Dockerfile linting, image vulnerability scanning, container SBOM

## Track 2: Dynamic & Runtime Security

**Characteristics:** Environment-aware, scope-bounded, requires confirmation

Plugins that interact with running systems. These require explicit opt-in and are not safe for unattended CI runs.

**Plugins:**
- **nox-plugin-dast** — DAST web/API scanning (passive + active modes)
- **nox-plugin-api-abuse** — API authorization testing (BOLA, BFLA, rate-limit)
- **nox-plugin-drift** — Runtime configuration drift detection (K8s, env configs)
- **nox-plugin-attack-surface** — Static endpoint extraction and exposure mapping

## Track 3: AI Security

**Characteristics:** Architecture-aware, first-class differentiator

Nox's defining feature — dedicated AI security analysis. These plugins understand AI application architectures and detect risks unique to LLM/agent systems.

**Plugins:**
- **nox-plugin-ai-inventory** — Comprehensive AI component detection and dependency graph
- **nox-plugin-ai-static** — Advanced prompt injection detection, tool safety analysis
- **nox-plugin-ai-runtime** — Runtime prompt injection probes, boundary testing
- **nox-plugin-ai-supply-chain** — Model provenance, prompt versioning, dataset integrity

## Track 4: Threat Modeling & Design

**Characteristics:** Review-focused, early design phase

Plugins that analyze architecture and design for security risks before code is written.

**Plugins:**
- **nox-plugin-threat-model** — STRIDE-based auto-modeling, threat model validation
- **nox-plugin-arch-lint** — Dependency rules, security pattern detection
- **nox-plugin-security-baseline** — Baseline capture, comparison, CI gate

## Track 5: Supply Chain & Provenance

**Characteristics:** Artifact-centric, high audit value

Plugins that verify the integrity and provenance of software artifacts.

**Plugins:**
- **nox-plugin-sbom-enrich** — SBOM vulnerability enrichment (OSV, NVD, GitHub Advisory)
- **nox-plugin-provenance** — SLSA attestation generation and verification
- **nox-plugin-artifact-integrity** — Release verification, build comparison
- **nox-plugin-depconfusion** — Dependency confusion detection and prevention

## Track 6: Intelligence & Early Warning

**Characteristics:** Signals not exploits, defensive only

Plugins that provide threat intelligence and early warning signals.

**Plugins:**
- **nox-plugin-intel** — Emerging vulnerability intelligence, watchlist generation
- **nox-plugin-exposure** — Cross-scan correlation, reachability analysis
- **nox-plugin-case-bundle** — Finding grouping, severity aggregation
- **nox-plugin-threat-enrich** — CVE enrichment, ATT&CK mapping

## Track 7: Policy, Risk & Governance

**Characteristics:** Org-specific, non-scanning, consumes findings

Plugins that evaluate findings against organizational policies and compliance frameworks.

**Plugins:**
- **nox-plugin-policy-gate** — Policy evaluation, CI gate (pass/fail)
- **nox-plugin-control-map** — Security control mapping (CIS, NIST, SOC 2, ISO 27001)
- **nox-plugin-risk-register** — Risk register generation, trend tracking
- **nox-plugin-promotion** — Artifact promotion gates and attestations

## Track 8: Incident Readiness & Response

**Characteristics:** Process-focused, zero exploit logic

Plugins that assess and improve incident response readiness.

**Plugins:**
- **nox-plugin-playbook** — Incident playbook readiness assessment
- **nox-plugin-breach-impact** — Breach impact estimation, blast radius mapping
- **nox-plugin-detect-ready** — Logging audit, alert coverage analysis

## Track 9: Developer Experience & Workflow

**Characteristics:** Adapters and helpers, not detection

Plugins that integrate Nox into developer workflows and tools.

**Plugins:**
- **nox-plugin-baseline-mgmt** — Finding baseline snapshots, diff, triage
- **nox-plugin-ide-bridge** — SARIF to editor diagnostics, pre-commit hooks
- **nox-plugin-orchestrator** — Scan orchestration, execution planning, profiles
- **nox-plugin-report-composer** — Rich reports (Markdown, HTML, JSON), dashboards

## Track 10: Agent & Assistance

**Characteristics:** Read-only, never changes results

Plugins that provide AI-powered explanations and recommendations.

**Plugins:**
- **nox-plugin-triage-agent** — LLM-powered finding prioritization and classification
- **nox-plugin-remediation** — Fix suggestions, remediation planning
- **nox-plugin-threat-explain** — Executive briefings, developer explanations

## Scaffolding a Plugin

Use `nox plugin init` to generate a complete, buildable plugin project:

```bash
nox plugin init --name nox/my-scanner --track core-analysis
```

This generates:
- `main.go` — Plugin entry point with SDK setup
- `main_test.go` — Conformance tests
- `go.mod` — Go module with SDK dependency
- `Makefile` — Build, test, lint targets
- `Dockerfile` — Multi-stage container build
- `.github/workflows/` — CI and release workflows
- `testdata/` — Directory for test fixtures
- `README.md` — Documentation template
