# Core vs Plugin Boundary

This document codifies the architectural rule that decides whether a
detection capability ships in `core/` or as a separate plugin in
their own repositories under the `Nox-HQ` org (`nox-plugin-*`), each released independently.

The boundary exists because nox is positioned as a **deterministic,
offline-first, read-only** security primitive (per `CLAUDE.md`). Core
must stay narrow and fast to keep that contract; plugins absorb everything
that violates it.

## The rule

A detection ships in **core** when **all** of the following hold:

1. **Deterministic** — same inputs produce identical outputs. No randomness,
   no timing dependency, no remote enrichment.
2. **Offline** — no network calls during scan execution. OSV lookups are
   exempt because they're feature-flagged (`--no-osv`) and the cache is
   purely additive.
3. **Read-only** — no exec, no file writes, no API mutation.
4. **Bounded cost** — analysis cost is proportional to file count and
   regex compilation. No interprocedural call graphs, no AST-level taint
   propagation, no LLM inference.
5. **Universal value** — every operator running `nox scan .` benefits.
   Never specialised to a single org's compliance posture or a niche
   ecosystem.

Anything that fails any of these is a **plugin**.

## What's in core today

| Concern | Coverage | Why core |
|---|---|---|
| Secrets (regex + entropy) | SEC-001..SEC-950 + SEC-161/162/163 | Universal; bounded cost |
| IaC misconfig | IAC-001..IAC-369 | Deterministic regex over text |
| Data sensitivity | DATA-001..DATA-012 | Universal PII detection |
| AI security | AI-001..AI-050, AI-PI-001..006, AI-EMBED-001..005, AI-AGENT-001..008, MCP-001..008 | First-class wedge; deterministic |
| Dependency vulns | VULN-001/002/003 | OSV-backed, offline-fallback |
| Container basics | CONT-001/002 | Image pin / tag enforcement |
| License | LIC-001 | License policy |
| GitHub Actions context | downgrades on `services:` blocks, paired permissions | Post-pass on findings |

## What's a plugin today

| Plugin | Track | Why plugin |
|---|---|---|
| reachability | core-analysis | Language-specific parsers (Go AST, Rust crate, Java import) inflate binary, and golang.org/x/vuln pulls the Go analysis toolchain into core |
| taint-analysis | core-analysis | Heavyweight AST + interprocedural call graphs |
| arch-lint | core-analysis | Org-specific dependency rules |
| sast | core-analysis | Language-specific code-injection patterns (SQLi, XSS, path traversal) |
| logic-scan | core-analysis | IDOR, race conditions, business-logic flaws — needs deeper analysis than regex |
| container | core-analysis | Container image scanning (vulnerable layers) — large index, network-y |
| mcp-scan | (was) core-analysis | **Now in core** as MCP-001..008 (Phase 11) |
| api-abuse | dynamic-runtime | Active probing |
| attack-surface | dynamic-runtime | Endpoint discovery via traffic |
| dast | dynamic-runtime | Active web/API scanning |
| k8s-runtime | dynamic-runtime | Live cluster connectivity |
| red-team | dynamic-runtime | Active exploit chain validation |
| artifact-integrity | supply-chain | Sigstore / OCI registry calls |
| depconfusion | supply-chain | Cross-registry checks |
| provenance | supply-chain | SLSA attestation generation |
| baseline-mgmt | policy-governance | Stateful baseline workflow |
| policy-gate | policy-governance | Org-specific policy DSL |
| risk-register | policy-governance | Stateful tracking |
| grc | policy-governance | 12 compliance frameworks (SOC2, ISO 27001, GDPR, FedRAMP L/M/H, HIPAA, PCI-DSS, NIST 800-53, NIST CSF, CIS v8, CMMC) |
| threat-explain | threat-modeling | LLM-assisted explanations |
| threat-model | threat-modeling | LLM-assisted STRIDE generation |
| risk-context, risk-score, threat-enrich | intelligence | Cross-scan / external enrichment |
| detect-ready, playbook | incident-readiness | Process assessment workflows |
| lsp, orchestrator, report-composer | developer-experience | Workflow adapters |
| case-bundle, triage-agent, validator | agent-assistance | LLM-assisted triage |

## Known overlap to resolve

These plugins predate the boundary doc and have unclear separation
from core. Each needs explicit alignment.

### container plugin vs core IAC

Core has `IAC-*` rules covering Dockerfile patterns (~50 rules under
the docker file pattern set) plus `CONT-001`/`CONT-002`. The container
plugin description says "Dockerfile linting, image vulnerability
scanning, container SBOM" — there's a real overlap on Dockerfile
linting.

**Resolution**: core owns Dockerfile static analysis (regex over file
content). Plugin owns image-layer scanning (pulls and scans image
layers — network-bound, plugin-class). Plugin description should be
narrowed to "container image scanning, layer SBOM" only.

### arch-lint plugin vs core IAC

Core IAC includes some "architecture" rules (insecure-by-default
patterns). arch-lint says "dependency rules, security pattern
detection". Probably overlaps with core IAC.

**Resolution**: arch-lint owns *org-specific* allowlist/denylist rules
and graph-based architecture constraints. Core IAC stays generic.
Move any generic patterns from arch-lint into core IAC if they apply
universally; archive arch-lint's role to org-policy enforcement.

### sast plugin (SQLi/XSS/path-traversal) and core SEC

Core SEC is secrets-only despite the name. SAST patterns (SQL
injection, XSS, path traversal) are **not** in core; the sast plugin
owns them. This is correct boundary — code-injection detection is
language-specific and benefits from per-language rule sets.

**Resolution**: rename the conceptual track in docs to clarify "core
SEC = secrets, plugin sast = code injection". No code change.

### logic-scan plugin

Distinct from core (IDOR, mass assignment, race conditions). No
overlap. Keep as plugin.

## Implications for new detections

Before adding a rule:

1. Does it satisfy all five core criteria? → core.
2. Does it need a parser, language model, network call, or stateful
   workflow? → plugin.
3. Is it universally valuable? → if no, plugin (org-specific).

Before promoting a plugin to core:

1. Strip dependencies on language-specific parsers and external services.
2. Confirm catalog count growth is acceptable (every core rule loads on
   every scan).
3. File a tracking issue documenting the migration.

## See also

- `CLAUDE.md` — project-wide architectural constraints
- `docs/track-catalog.md` — plugin track taxonomy (legacy: still
  references some now-archived plugins)
- `docs/roadmap.md` — phased delivery history
