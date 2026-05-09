# Proposal: Remediation Bot Plugin (Dependabot-like)

## Goal

Provide a Dependabot-like workflow for dependency remediation while preserving Nox core guarantees:

- deterministic scan outputs
- read-only core engine
- offline-first scanning
- explicit opt-in for write/network actions

This proposal keeps PR automation in a plugin (or CI wrapper), not in core scan execution.

## Non-goals

- Turning `nox scan` into a mutating command
- Building a hosted SaaS dashboard
- Replacing existing package managers or lockfile semantics

## Current baseline

Nox already provides:

- dependency vulnerability findings (`VULN-001`)
- fixed version metadata (`fixed_in`)
- local upgrade execution via `nox fix` (with `--dry-run` and major-bump guard)

Missing pieces for a Dependabot replacement are orchestration and PR lifecycle management.

## Proposed architecture

Implement `nox-plugin-remediate` as a plugin with explicit mutating tools.

## Future scope: code issue remediation

In addition to dependency upgrades, future versions of `nox-plugin-remediate` should support safe remediation of selected code findings.

### What this means

- apply deterministic, rule-specific code transformations for fixable findings
- generate minimal patches with precise file/line impact
- keep human review as default for code rewrites

### Candidate classes for v1 code remediation

- insecure API usage replacements (rule-specific safe substitutions)
- missing security headers or middleware wiring in known framework patterns
- hardcoded secret handling rewrites to environment variable access patterns
- unsafe deserialization/eval/shell-call wrappers where a known safe helper exists

### Design principles

- `fix-by-rule` first, not free-form code generation
- deterministic output for same input + same toolchain
- no hidden remote execution
- preserve formatting conventions and run project formatters/linters in verify stage

### Additional tools (future)

6. `remediate.plan_code`
   - Read-only.
   - Maps findings to known fixers/codemods and returns patch plan.

7. `remediate.apply_code`
   - Mutating.
   - Applies rule-specific codemods and emits patch metadata.

8. `remediate.verify_code`
   - Runs targeted validation (tests, linters, security re-scan).

### Optional LLM role (strictly optional)

LLM usage remains optional and non-authoritative:

- propose candidate fixes where no deterministic fixer exists
- explain trade-offs in PR descriptions
- never auto-merge solely based on LLM-generated patches

If LLM-assisted code patches are enabled, policy should require stronger gates:

- mandatory human approval
- stricter blast-radius threshold (typically low only)
- full test/lint/security verification and re-scan pass

### Tools

1. `remediate.plan`
   - Read-only.
   - Input: findings + policy + repo metadata.
   - Output: deterministic plan (`remediation.plan.json`).

2. `remediate.apply`
   - Mutating (writes manifests/lockfiles in a branch workspace).
   - Applies selected plan items.

3. `remediate.verify`
   - Executes allowlisted commands (tests/lint/build/security gates).
   - Returns pass/fail with artifacts.

4. `remediate.propose`
   - Network-capable.
   - Creates or updates pull requests with labels/reviewers/body template.

5. `remediate.maintain`
   - Optional scheduled task.
   - Rebase/supersede/close stale remediation PRs according to policy.

## Policy model (including blast-radius auto-merge)

Add policy section in `.nox.yaml` (or plugin-local config) to control behavior.

```yaml
remediation:
  enabled: true

  pull_requests:
    max_open: 5
    group_by: ["ecosystem", "service"]
    labels: ["security", "dependencies", "nox-remediation"]

  risk:
    auto_apply:
      severities: ["critical", "high", "medium"]
      allow_major: false

    blast_radius:
      # computed by plugin using changed files, dependency centrality,
      # runtime exposure, and test impact.
      auto_merge_max: "medium"   # low|medium|high
      require_human_review_at: "high"

    exploitability:
      prioritize_reachable: true
      prioritize_public_entrypoints: true

  merge:
    strategy: "squash"
    require_checks: ["ci", "nox-security", "unit-tests"]
    min_approval_count: 1
    auto_merge_when:
      blast_radius_in: ["low", "medium"]
      checks_passed: true
      review_approved: true

  windows:
    timezone: "UTC"
    allowed:
      - "Mon-Fri 08:00-18:00"
    freeze:
      - "2026-12-15..2027-01-05"
```

### Risk score recommendation

Plugin computes a normalized risk tuple:

- `severity` (from finding)
- `exploitability` (reachable/known EPSS-like signal when available)
- `blast_radius` (low/medium/high)
- `change_size` (files + lockfile churn)

Auto-merge policy should be evaluated from this tuple, not only CVSS.

## Suggested PR template fields

- why this update is needed (rule, advisory, fixed_in)
- affected packages and ecosystems
- blast radius assessment (low/medium/high)
- verification evidence (commands + status)
- rollback notes

## Safety and governance

- `remediate.apply` and `remediate.propose` require explicit plugin opt-in.
- Enforce command allowlist for verification.
- Enforce branch naming policy (`nox/remediate/*`).
- Enforce max files changed and max dependency count per PR.
- Never auto-merge major updates unless explicitly allowed.

## Incremental rollout

1. Plan-only mode (`remediate.plan`) in CI comments/artifacts.
2. PR mode without auto-merge.
3. Auto-merge for low blast radius only.
4. Auto-merge for low + medium with strict checks and review gate.

## Open questions

- Should blast radius be globally standardized in core types, or remain plugin-private metadata?
- Should `nox fix` expose machine-readable JSON output to simplify wrappers?
- Do we want first-class `nox remediate` orchestration command in CLI that delegates to plugin tools?
- Which rule families should get deterministic codemods first (SEC, IAC, AI, MCP), and what is the acceptance bar per fixer?

## Initial fixer backlog (first 5)

These are intentionally narrow and deterministic so they can ship safely.

1. SEC-001: weak subprocess execution pattern hardening (Go/Python/JS)
   - Pattern: shell-invoked command construction with interpolated user input.
   - Fix strategy: replace shell invocation with argv-safe APIs and explicit argument lists.
   - Safety level: medium (requires semantic checks around command behavior).
   - Verify: unit tests + command-path integration test + re-scan.

2. SEC-002: unsafe SQL string concatenation to parameterized query APIs (Go/Python/JS)
   - Pattern: SQL query string building from untrusted input.
   - Fix strategy: convert to placeholders + parameter binding in supported DB libraries.
   - Safety level: medium.
   - Verify: query behavior tests + taint re-check + lint/type-check.

3. SEC-003: hardcoded secret extraction to env/config reference (Go/Python/JS)
   - Pattern: likely secrets in literals for known key/token/password variable names.
   - Fix strategy: replace literal with env/config lookup and add TODO marker for secret provisioning docs.
   - Safety level: low-to-medium (depends on runtime config readiness).
   - Verify: build/test + startup config check + secret scanner re-run.

4. WEB-SEC-001: missing common security headers middleware (Node/Go HTTP stacks)
   - Pattern: HTTP server without baseline headers (CSP, X-Content-Type-Options, frame protections where applicable).
   - Fix strategy: inject framework-native middleware/helper in central server wiring file.
   - Safety level: low.
   - Verify: header assertion tests + integration smoke test.

5. AI-LOG-001: prompt/response sensitive logging reduction (Python/JS/Go)
   - Pattern: raw prompt/response payloads logged at info/error levels.
   - Fix strategy: replace with redacted logging helper and metadata-only fields.
   - Safety level: low.
   - Verify: logger unit tests + grep-based policy check + AI rules re-scan.

### Acceptance bar per fixer

- Deterministic rewrite output for identical inputs.
- Idempotent application (running twice yields no further changes).
- Bounded change surface (max files/LOC thresholds per fixer run).
- Language-specific golden tests for before/after fixtures.
- Mandatory re-scan proving targeted finding class is reduced.
- Automatic rollback if verify step fails.

### Suggested implementation order

1. WEB-SEC-001 (lowest risk, easy verification)
2. AI-LOG-001 (low-risk, high practical value for AI apps)
3. SEC-003 (common issue; medium operational risk)
4. SEC-002 (higher semantic risk; needs robust fixtures)
5. SEC-001 (highest behavior-change risk; ship after strong test harness)
