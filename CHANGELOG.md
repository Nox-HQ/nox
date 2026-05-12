# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Fingerprint v2** (opt-in): new `--fingerprint-version 2` flag on `nox scan`
  (or `NOX_FINGERPRINT_VERSION=2` env). V2 hashes only `rule_id + normalised
  file_path + content`; drops the start line so trivial diffs (import shifts,
  gofmt, comment edits) no longer invalidate baselined findings. Path
  normalisation collapses leading `./`, backslash → forward-slash, and `..`
  segments so `nox scan ./http` and `nox scan .` produce the same fingerprint
  for the same finding. V1 remains the default; switch a repo over by
  passing `--fingerprint-version 2` to `nox scan` (or setting the env)
  and then running `nox baseline update` so existing entries re-hash
  under V2. A dedicated `nox baseline migrate` command will land in a
  follow-up PR (#73 item 4). Closes [#73 items 1+2](https://github.com/Nox-HQ/nox/issues/73).
- **`nox baseline add`** — additive counterpart to `baseline update`.
  Adds findings not yet in the baseline without pruning stale entries.
  Accepts `--rule <id,id>` and `--fingerprint <fp,fp>` filters; the
  fingerprint flag bypasses the scan entirely and is the surgical
  "baseline these specific entries" workflow #73 item 4 calls out.
  `--reason` and `--owner` annotate every new entry. Closes [#73 item
  4](https://github.com/Nox-HQ/nox/issues/73).
- **`nox baseline diff`** — read-only preview of what
  `baseline update` would change against the current scan. Lists adds
  and prunes separately so the operator can decide whether a prune is
  real (resolved) or a regression (rule sharpened, file renamed,
  fingerprint algorithm bumped).

### Documentation / interop

- **`nox doctor` version-drift check** — doctor now scans
  `.github/workflows/*.yml` for `nox-hq/nox/cli@vX.Y.Z` pins and warns
  when CI and the local nox binary disagree. Same nox version on both
  sides makes "I just ran nox locally, it's clean" actually meaningful
  again. Reports `ok` per workflow when versions match, `DRIFT` when
  they diverge, with a suggested fix-up command (bump CI or
  `go install` locally). Closes [#73 item 7](https://github.com/Nox-HQ/nox/issues/73).
- **Exit-code semantics already correct** (item 8 follow-up). Verified
  that `nox scan` already returns 0 when every finding is baselined or
  suppressed and exits 1 only on truly-new active findings —
  `ActiveFindings()` filters `StatusBaselined` and `StatusSuppressed`
  out of the count that drives the exit code. The `|| true` shim in
  downstream CI workflows (e.g. felixgeelhaar/fortify) is no longer
  necessary; remove it on next workflow refresh.
- **`nox:disable` alias**: inline suppression now accepts both
  `nox:ignore` (legacy spelling) and `nox:disable` (matches gosec
  `#nosec`, staticcheck, golangci-lint `//nolint`). The two are
  semantically identical — same rule-list parsing, same `expires:` /
  reason handling, same scope (trailing comment vs next-line). This is
  the inline directive surface item 6 of #73 asked for; the underlying
  mechanism already shipped under the `nox:ignore` name.

### Fixed

- **AI-012 precision** — tightened the regex so it stops firing on every
  `.Execute(`/`Query(` call whose body coincidentally references an uppercase
  `Response` identifier (Go return types, struct fields, error variants). The
  rule now (a) matches the method name case-insensitively but the LLM-output
  keyword case-sensitive lowercase only, and (b) requires `\b` word boundaries
  around the keyword. Verified against `felixgeelhaar/fortify`: 4 known
  false positives in `http/middleware.go` and `http/streaming.go` are gone,
  the true-positive `cursor.execute("SELECT " + completion)` patterns still
  fire (including with nested calls in the argument list). Closes [#73 item
  3](https://github.com/Nox-HQ/nox/issues/73).

## [0.6.0] - 2026-02-24

### Added
- Graph-based cross-resource IaC analysis with 4 pattern detectors (Phase 7a).
- Reachability analysis plugin for import-based vulnerability reachability (Phase 7b).
- Intraprocedural taint analysis plugin with source-to-sink tracking (Phase 7c).
- Kubernetes runtime security scanner for live cluster scanning (Phase 7e).
- Phase 8 AI-enhanced security intelligence plugins: threat-explain, threat-model, GRC compliance, red team, and triage agent.
- FedRAMP Low/Moderate/High compliance frameworks.
- Detailed fix guidance for rule remediation.

### Changed
- Move FedRAMP Low/Moderate/High compliance baselines from core to GRC plugin.
- Core supported frameworks reduced from 11 to 8 (FedRAMP now in GRC plugin).
- Remove 1,517 FedRAMP mapping lines from `core/compliance/data.go`.

### Fixed
- Correct stale exclude path for plugin repos.

## [0.5.0] - 2026-02-17

### Added
- Graph, enrichment, and scan context SDK primitives for plugin ecosystem.

## [0.4.3] - 2026-02-17

### Fixed
- Pin GitHub Action references to commit SHAs and restore Grade A.

## [0.4.2] - 2026-02-17

### Changed
- Bump google.golang.org/grpc from 1.78.0 to 1.79.1.
- Bump github.com/charmbracelet/bubbles from 0.21.1 to 1.0.0.
- Bump github.com/openai/openai-go from 0.1.0-beta.10 to 3.22.0.
- Bump checkout, setup-go, upload-artifact, golangci-lint-action GitHub Actions.

## [0.4.1] - 2026-02-17

### Changed
- Bump google.golang.org/grpc from 1.78.0 to 1.79.1.
- Bump github.com/charmbracelet/bubbles from 0.21.1 to 1.0.0.

### Fixed
- Configure relicta GitHub plugin with post_publish hook.

## [0.4.0] - 2026-02-17

### Changed
- Swap mcp-go dependency from mark3labs/mcp-go to felixgeelhaar/mcp-go v1.6.4.
- Rewrite MCP server with typed handlers, fluent builder API, and resource templates.
- Add multi-project support with per-project scan cache and resource templates.

## [0.3.1] - 2026-02-15

### Fixed
- Suppress SEC-659 false positive on doc comment line in findings.go.
- Resolve revive lint issue for exported doc comments.
- Resolve gocritic lint issues in findings.go.
- Improve core domain test coverage from 82% to 93%.
- Suppress remaining SEC-659 false positives across codebase.

## [0.3.0] - 2026-02-15

### Added
- Import 191 Gitleaks rules (SEC-164 to SEC-355) for broad secrets coverage.
- Expand secrets rules to 900+ detectors (SEC-356 to SEC-549) for competitive parity with TruffleHog.
- Expand AI security rules and refine rule patterns for Grade A self-scan.
- Expand IAC and AI rule coverage with additional patterns.
- Add advanced exclusion patterns for flexible scan filtering.

### Fixed
- Resolve all security findings and achieve Grade A on self-scan.

## [0.2.1] - 2026-02-14

### Changed
- Harden rule handling and entropy scanning to reduce false positives.

## [0.2.0] - 2026-02-13

### Added
- OpenVEX support and compliance framework mapping (CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP Top 10, OWASP LLM Top 10, OWASP Agentic).
- Expand IaC rules to 185 and add Terraform plan scanning.
- Encoded secret detection, SBOM input scanning, and Composer lockfile parser.
- Close competitive gaps with MCP-CLI parity, supply chain analysis, and dashboard.
- History scanning, entropy-based rules, and complete Phase 3 task backlog.
- Add coverctl coverage check to pre-commit hook.
- Expand to 564 rules with data sensitivity analyzer (DATA-001 to DATA-012), AI-BOM v2.0, and full compliance coverage.
- Wire VEX, compliance, and Terraform plan scanning to MCP server and CLI.

### Fixed
- Migrate to homebrew_casks and install syft for SBOM generation.
- Suppress false-positive findings to restore A security grade.
- Remove `t.Parallel` from test that mutates package-level `timeNow`.
- Suppress CONT-001 in Dockerfile template to achieve A grade.

## [0.1.0] - 2026-02-11

### Added
- 155 built-in rules across secrets (86), AI security (18), IaC (50), and dependency SCA (1).
- OSV vulnerability enrichment for dependency scanning via batch API.
- Shannon entropy matcher for high-entropy secret detection.
- Git history commit walker for scanning past commits.
- Custom rules support via YAML definition files (`--rules`).
- Pre-commit hook installer (`nox protect install/uninstall/status`).
- Project-level pre-commit hook with CI-matching checks (`make hooks`).
- `nox show` interactive finding inspector with Bubble Tea TUI.
- `nox explain` LLM-powered finding explanations via OpenAI-compatible APIs.
- `nox diff` for findings in changed files only.
- `nox watch` for automatic re-scan on file changes.
- `nox badge` for SVG security grade badges.
- `nox baseline` for managing known findings (write, update, show).
- `nox annotate` for inline GitHub PR review comments.
- `nox completion` for shell completions (bash, zsh, fish, powershell).
- Policy engine with `fail_on`/`warn_on` severity thresholds.
- Inline suppressions via `nox:ignore` comments with expiry support.
- Unified `.nox.yaml` scan configuration.
- `--no-osv` flag and `scan.osv.disabled` config for offline mode.
- `--staged` flag for scanning only git-staged files.
- `--severity-threshold` flag for minimum severity filtering.
- Plugin ecosystem with gRPC-based plugins across 10 security tracks.
- Plugin SDK with conformance tests and safety profiles.
- Plugin registry client with semver resolution and OCI distribution.
- Plugin trust and verification layer.
- MCP server with read-only tools for AI agent integration.
- Agent-assist module with plugin capability discovery.
- GitHub Action with checksum verification.
- Release infrastructure with GoReleaser, Relicta, and Homebrew tap.
- Test coverage tracking with coverctl and badge (83.1%).
- CycloneDX 1.5 SBOM with vulnerability enrichment.
- SPDX 2.3 SBOM with SECURITY external references.
- SARIF 2.1.0 output with full rule catalog (help, descriptions, URIs).

### Fixed
- Stabilized annotate and diff tests for CI environment.
- Badge counts only active findings (excludes suppressed).
- Eliminated false positives in self-scan with pinned GitHub Actions.
- Binary files skipped in scanner.
- SARIF reporter includes full rule help text for GitHub Code Scanning.
- Suppressed findings excluded from badge, diff, and watch counts.
- Interspersed flags and positional args handled correctly.
- Timeout added to `nox explain` to prevent indefinite hangs.

[Unreleased]: https://github.com/nox-hq/nox/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/nox-hq/nox/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/nox-hq/nox/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/nox-hq/nox/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/nox-hq/nox/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/nox-hq/nox/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/nox-hq/nox/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/nox-hq/nox/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/nox-hq/nox/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/nox-hq/nox/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nox-hq/nox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nox-hq/nox/releases/tag/v0.1.0
