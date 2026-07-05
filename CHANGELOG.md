# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`nox lsp` — Language Server for editor diagnostics.** Runs a minimal LSP
  server over stdio (JSON-RPC 2.0 with `Content-Length` framing) that scans the
  active file on open/save and publishes nox findings as
  `textDocument/publishDiagnostics`. Deterministic and fully offline — it just
  runs the scanner on the one file, maps each finding's location/severity/RuleID
  onto an LSP diagnostic (critical/high→Error, medium→Warning, low→Information,
  info→Hint), and sorts them stably by line, column, then rule id. Hand-rolled
  JSON-RPC (no third-party LSP library, no network); `didClose` clears
  diagnostics and scan errors publish an empty set instead of crashing.
- **`nox scan --sort priority` — reachability-aware finding prioritization.**
  Orders findings.json by what's most actionable — severity first, then
  reachability, then confidence — instead of the default rule/path/line order
  that buries criticals. Paired with the reachability plugin (which enriches
  VULN findings with a `reachable` flag), a confirmed-reachable vuln rises and a
  likely-false-positive *unreachable* one sinks to the bottom, so the report
  leads with real risk. Deterministic (stable location tiebreak); the default
  order is unchanged, preserving baselines and diffs.
- **`nox fix --content` — deterministic patches for mechanical misconfigurations.**
  Reads `findings.json` and rewrites the flagged line to its one unambiguous
  secure value: Kubernetes hardening flips (`privileged: true`→`false`,
  `runAsNonRoot: false`→`true`, hostNetwork/hostPID/hostIPC/allowPrivilegeEscalation/
  automountServiceAccountToken, readOnlyRootFilesystem), Terraform
  (`storage_encrypted`/`enable_https_traffic_only`, `protocol "HTTP"`→`"HTTPS"`,
  `acl "public-read"`→`"private"`), CI (`continue-on-error: true`→`false`), and
  Dockerfile `ADD`→`COPY`. Template-free and no LLM — only rules with a single
  correct answer are fixed; anything needing a choice (a UID, a pinned digest, an
  allowlist, a rotated secret) is deliberately never touched. Previews the diff
  by default and applies nothing; `--content --write` applies.
- **`nox baseline init` — one-command adoption for a debt-laden repo.** Scans,
  records every current finding as accepted baseline debt (reported by
  severity), and prints the "gate the change, not the history" policy to add
  (`fail_on` + `baseline_mode: warn`). Refuses to clobber an existing baseline
  (use `update`, or `--force`). See the new `docs/adoption.md`, which ties
  together `baseline init`, per-severity budgets, `--tracked-only`, and
  `--offline` into a five-minute adoption path.
- **Broader language coverage: JS/TS module + JSX variants, plus Kotlin, Swift,
  PHP.** `.tsx`/`.jsx`/`.mjs`/`.cjs`/`.mts`/`.cts` are now classified as source,
  and every rule scoped to `*.ts`/`*.js` is auto-expanded to the variants — so a
  React/Next.js AI app's `.tsx` components (where prompts are built and the model
  is called) are scanned instead of silently skipped. `.kt`/`.swift`/`.php` join
  the source set too.
- **OWASP Top 10 for Agentic Applications (ASI01–ASI10) mapping.** Findings
  against agentic surfaces now carry their `owasp-asi*` control (in SARIF
  `properties.tags` and finding metadata), the way they already carry OWASP LLM
  and MCP Top 10 tags. Mapped: ASI01 Agent Goal Hijack (AGENT-001/004, prompt-
  injection rules), ASI02 Tool Misuse (AGENT-002/003, tool-exposure rules), ASI03
  Identity & Privilege Abuse (MCP authz/SSRF), ASI04 Agentic Supply Chain (MCP
  tool-poisoning, rug-pull, shadow servers, model supply chain), ASI05 Unexpected
  Code Execution. Runtime/multi-agent categories nox can't statically detect
  (ASI06/07/08) are deliberately left unmapped rather than over-claimed.
- **Per-severity policy budgets (`policy.budget`).** The gate can now tolerate a
  bounded amount of new debt per severity before failing — e.g. `budget: {medium:
  5, low: 20}` fails only on the 6th new medium while still failing on any new
  high/critical. It refines `fail_on`: a severity at/above the threshold with no
  budget entry defaults to 0 (fail on the first, unchanged), so an empty budget
  reproduces the previous gate exactly. Lets a team adopt a strict threshold on a
  debt-laden repo without baselining every finding.
- **Proof-of-offline attestation in the report.** `findings.json` meta now
  carries an `"offline"` boolean recording whether the scan ran under the
  zero-network guarantee (`nox scan --offline`: no OSV, no API, no token, no
  telemetry). A reviewer or CISO can confirm straight from the artifact that the
  scanner never touched the network — backed by the enforced egress test
  (`TestOSVDisabled_NoNetworkEgress`), not just a claim. `--offline` also prints
  an `[offline]` confirmation line. This is the differentiator vs. LLM-powered
  scanners that ship your code to a model provider.
- **`nox scan --tracked-only`.** Restricts the scan to git-tracked files
  (`git ls-files`), excluding untracked working-tree files (scratch files, build
  output, un-added drafts) and submodule contents. Scans exactly what is
  committed — the same set a reviewer sees — so a CI gate is reproducible and
  doesn't flag a developer's local scratch file. Ignored outside a git repo.
- **Agent-config artifact scanning (`AGENT-001..004`).** The files that steer a
  coding agent are an execution surface, not just docs — a poisoned rule file or
  an over-broad permission grant silently changes what the agent runs, reads, and
  exfiltrates. nox now scans Cursor/Cline rules (`.cursorrules`, `*.mdc`),
  `CLAUDE.md`/`AGENTS.md`/`GEMINI.md`, Claude Code skills (`SKILL.md`), and agent
  settings (`.claude/settings.json`), classifying them as AI components. New
  rules: **AGENT-001** instruction-override / prompt-injection directives in a
  rules file (OWASP LLM01), **AGENT-002** settings that disable the
  human-in-the-loop permission gate (`bypassPermissions`, `--dangerously-skip-permissions`,
  `autoApprove`), **AGENT-003** wildcard tool grants (`"Bash(*)"`), and
  **AGENT-004** exfiltration / concealment directives. filePatterns are scoped to
  exact agent-config filenames (never `*.go`/`*.md` broadly), so ordinary source
  and documentation are untouched. (#145)

### Fixed

- **`nox scan <file>` scans a single file.** A file target used to fail (it
  looked for `<file>/.nox.yaml` and the walker skipped its own root, finding
  nothing). Now it loads config from the file's directory and scans just that
  file — the basis for fast pre-commit hooks and editor integrations.
- **`scan.exclude` is now a hard exclude that survives `--changed-since`.** Since
  the tracked-file fix (#142), a file listed in `scan.exclude` that was also
  git-tracked got re-scanned — the tracked-file override treated the config
  exclude like a `.gitignore` pattern. So an explicit exclusion (e.g. a
  rule-definition file full of expected-false-positive patterns) was silently
  ignored in `--changed-since` scans, which is what failed nox's own PR gate on
  every rule change. Config excludes are now a separate hard rule the tracked
  override never resurrects.
- **Unsafe-output-handling rules no longer fire on documentation.** AI-009/012/
  015/018 (eval/exec, DB query, `innerHTML`, file path from LLM output) target
  real code sinks but matched prose in docs that *quote* those sinks — most
  visibly nox's own CHANGELOG entry `cursor.execute("SELECT " + completion)`,
  which tripped AI-012 (high) and failed the PR gate on every change that edited
  the changelog. A markdown file can't execute, so these rules now skip docs and
  test files (joining the existing prose/logging noise-glob set); real source is
  unaffected.
- **Tracked files under a gitignored directory are now scanned.** git never
  ignores a file it already tracks, even when a `.gitignore` pattern matches it
  — but nox applied ignore patterns purely from the filesystem and skipped them,
  a scanner blind spot for any repo that gitignores a directory yet commits
  sources into it (e.g. pet-medical ignores `mobile/` but tracks ~80 files under
  it, none of which were scanned — a committed secret there would go undetected).
  The scan now consults `git ls-files`: a tracked path is scanned even under an
  ignored directory, while genuinely-ignored (untracked) files stay skipped.
  Outside a git repo, behavior is unchanged. Note: repos with tracked files
  under ignored directories will see new findings on the next scan and should
  refresh their baseline. (#142)

## [1.4.2] - 2026-07-04

### Fixed

- **`.gitignore` is now honored when scanning from inside a git worktree.** In a
  linked worktree (and submodule) `.git` is a gitdir-pointer *file*, not a
  directory, so loading `.git/info/exclude` failed with `ENOTDIR` — an error
  that discarded every pattern already read from `.gitignore`, leaving the
  walker with zero ignore rules. A scan run from a worktree therefore found
  strictly more than the same HEAD scanned from the real checkout (a
  `mobile/`-ignored subtree reappeared: 721 vs 640 findings), so a baseline
  written from a plain directory never matched a worktree rescan. `info/exclude`
  is now resolved via the worktree's commondir (git shares it across worktrees),
  and a non-directory path component contributes no patterns instead of nuking
  the set. Dir and worktree scans of the same HEAD are now identical. (#140)

## [1.4.1] - 2026-07-03

### Changed

- **`nox fix --actions` now SHA-pins mutable tag refs, not just outdated ones.**
  A `uses: owner/action@v7` that already tracks the latest release is still a
  mutable ref — a supply-chain risk and a frequent PR-review flag. `--actions`
  now rewrites any tag ref to `@<sha> # <tag>`, pinning to the same-major latest
  release (or to the tag's own commit when a newer major is being held back).
  Already-SHA-pinned, up-to-date refs remain untouched, so remediation PRs are
  no longer blocked by "still using a mutable tag" review comments. Behavior for
  the dependency pass (default `nox fix`) is unchanged.

## [1.4.0] - 2026-07-03

### Added

- **`nox fix` remediates GitHub Actions pins.** `--actions` (alongside the
  package-dependency pass) or `--actions-only` scans `.github/workflows` and
  `.github/actions`, resolves each `uses:` action to its latest release via the
  GitHub API, and rewrites outdated pins to `@<sha> # <tag>` (SHA-pinned, best
  practice). Major-version jumps are skipped unless `--include-major`; branch
  pins (e.g. `@main` reusable workflows) are left alone. Needs `GITHUB_TOKEN`.
  This lets nox own dependency *and* CI-action remediation, replacing dependabot.

## [0.11.0] - 2026-06-05

### Added

- **MCP threat coverage mapped to the OWASP MCP Top 10.** New rules for tool
  poisoning (MCP-009..014), rug-pull/definition drift (MCP-015, `core/mcppin`),
  authorization & SSRF (MCP-016..021), and shadow/cross-server shadowing
  (MCP-022..024, `core/mcpshadow`). Every MCP rule carries its OWASP MCP control
  in SARIF (`properties.owasp-mcp`) plus a `tags[]` array.
- **`--offline` zero-network guarantee** and `scan.generated_paths`, a
  configurable noise filter (sensible default; `disabled`/`extend`/`override`)
  that stops the content rule families (AI-*, MCP-*) from firing on generated
  and vendored files (lockfiles, minified bundles, generated type defs).
  Dependency scanning is unaffected — lockfiles are still CVE-scanned.
  Content rules also skip machine-generated/minified blobs detected by
  content (an `AUTO-GENERATED`/`@generated`/`DO NOT EDIT` banner or a minified
  line), catching generated output embedded in a normal extension (e.g. a
  1.4 MB vite bundle exported as a `.ts` string).
- 17+ MCP client config locations are now discovered (`core/discovery/mcpclients`).

### Fixed

- **AI rule precision** (surfaced by scanning the top public MCP servers):
  - `AI-033` lacked a group around its alternation and matched bare
    `null`/`false`/`disabled` anywhere — the cause of thousands of false
    positives on generated TypeScript type definitions.
  - `AI-036` matched a bare `"35"` anywhere (version strings, hashes); it now
    requires a `gpt-` prefix.
  - `AI-026` matched any log call containing the generic words
    `content`/`output`/`message`/`response`; it now requires an LLM-specific
    token.
  - `AI-006/008/026/030/036/039/042` no longer fire in test files or
    documentation, and content rules skip whole test/fixture/sample/example
    directory trees (`scan.generated_paths.extend_dirs`/`override_dirs`) plus
    machine-generated/minified blobs detected by content.
  - `AI-018` (LLM output → file path) and `AI-049` (AI output → eval/exec) now
    require an LLM-specific token, so ordinary file I/O and DB `exec(query)` /
    `describeEval` calls no longer match.
  - MCP prose rules (`MCP-009..014/018/019`) skip comments, test files, and
    defensive contexts (e.g. an SSRF metadata IP inside a blocklist); `MCP-011`
    needs an exfil sink or sensitive path; `MCP-019` ignores loopback.
  - `MCP-022` is now informational (advisory posture signal, not a defect).
- **Policy gate** no longer counts inline-suppressed or VEX-cleared findings as
  new — a suppressed High no longer fails the gate.
- **`analyzer_rules`** rule IDs now match wildcards (e.g. `VULN-*`); the
  documented but unimplemented `skip_analyzer` action now works.
- Three rule precision fixes surfaced by the scan-of-the-week rotation:
  `AI-009` no longer flags Python's safe `ast.literal_eval`; `VULN-002`
  normalizes PEP 503 names so canonical packages (`huggingface_hub`,
  `python_pptx`) aren't flagged as typosquats of themselves; `AI-019` no
  longer matches DB/cache `.pipeline()` method calls.

### Changed

- **DDD / best-practices hardening.** Findings gain validated value objects
  (`Severity.IsValid`/`Confidence.IsValid`, `Location.Normalized`, `NewFinding`,
  `Finding.Validate`). A `FindingAnalyzer` interface formalizes the analyzer
  contract. `context.Context` is threaded through analyzers and a new
  `RunScanContext` entry point (with cancellation); `RunScan`/`RunScanWithOptions`
  are unchanged, non-breaking wrappers. The scan orchestrator is split into named
  pipeline stages. `TrustedRegistries` is now an immutable accessor.

## [0.10.1] - 2026-05-23

### Fixed

- **Scan now honours ancestor `.gitignore` files** ([#82]). Previously
  `LoadGitignore` only consulted `<target>/.gitignore`, so
  `nox scan apps/api` walked `apps/api/node_modules` even when
  `node_modules/` was ignored at the repo root. The walker now climbs
  to the enclosing `.git` directory and accumulates patterns top-down.
- **`--changed-since=<ref>` now scopes the file walk** ([#83]). The
  flag used to walk the full target tree and filter artifacts after,
  paying the full traversal cost on every push. The diff is now
  resolved before `walker.Walk()` and wired into a new
  `Walker.IncludePaths` allow-list that short-circuits descent into
  directories that contain no included path.

Empirical impact on a real Astro+Go monorepo with 521 MB of
`node_modules`: `nox scan apps` dropped from **14 min 54 s →
2.03 s** and from **1,729,404 findings → 3,630** — the rest was
secrets-pattern noise inside npm bundles.

[#82]: https://github.com/Nox-HQ/nox/issues/82
[#83]: https://github.com/Nox-HQ/nox/issues/83

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
