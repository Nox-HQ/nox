<p align="center">
  <img src="assets/logo.png" alt="Nox" width="180" />
</p>

<h1 align="center">Nox</h1>

<p align="center">
  <img src="https://github.com/nox-hq/nox/actions/workflows/ci.yml/badge.svg" alt="CI" />
  <img src=".github/nox-badge.svg" alt="Security" />
  <img src=".github/coverage-badge.svg" alt="Coverage" />
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License" />
</p>

**The security scanner for AI application developers.** Open source, offline-first, no SaaS.

If you're shipping LLM features — `chat.completions.create`, RAG ingest into a vector DB, agents with tool calls, MCP servers — nox is the static analyzer that knows how those break. Plus the boring stuff: secrets, dep CVEs, IaC, container scans.

**What nox catches that other scanners don't:**

- **Prompt injection** at the call site (AI-PI-*, OWASP LLM01)
- **Embedding leakage** when secrets / PII land in vector stores (AI-EMBED-*, LLM06)
- **Agent over-privilege** when `file_read` + `http_request` live in the same agent context (AI-AGENT-*, LLM07)
- **Agent-config execution surface** (AGENT-001..006) — the files that steer a coding agent are code: injection directives in `.cursorrules`/`CLAUDE.md`/skills, permission-bypass (`bypassPermissions`, `--dangerously-skip-permissions`), wildcard tool grants (`"Bash(*)"`), exfiltration directives in `.claude/settings.json`, unauthenticated **A2A agent cards** (`agent.json` with an empty/`none` security scheme, ASI07), and **DXT desktop-extension** manifests that interpolate `${user_config.*}` into a server command (ASI02)
- **Slopsquatting / hallucinated packages** (SLOP-001) — source imports of a package that exists in no manifest, no standard library, and no local module: the surface an attacker slopsquats after an LLM invents the name. Deterministic, offline, Python + JS/TS
- **CVE variants in your own code** (`nox variants`, VARIANT-*) — first-party code that reproduces the root cause of a known CVE (Log4Shell, Zip Slip, PyYAML full-loader, tar path traversal, SSTI, shell interpolation) even when no vulnerable dependency is present
- **Unverifiable dependency provenance** (PROV-001/002, OWASP ASI04 / SLSA) — dependencies pulled from a VCS/URL/tarball instead of a signed registry, or a VCS dep pinned to a mutable branch/tag instead of an immutable commit SHA
- **OWASP Top 10 for Agentic Applications (ASI01–ASI10)** mapping on findings, alongside the LLM and MCP Top 10 — traceable from static rule to runtime attack to GRC evidence
- **Full MCP threat coverage** mapped to the OWASP MCP Top 10 — server hardening (MCP-001..008), tool poisoning (MCP-009..014, MCP03), rug-pull / definition drift (MCP-015, MCP04), authn/authz & SSRF (MCP-016..021, MCP07), shadow & cross-server tool shadowing (MCP-022..024, MCP09)
- **Cross-file AI taint** — `request.json` → service hop → `chat.completions.create` across functions and files (TAINT-AI-*)
- **Polyglot AIBOM** — Python ingest + Go service + TS frontend produce one inventory naming every model invocation, auth env var, and endpoint
- **Verified plugin marketplace** — extension scanners (reachability, cross-file taint, k8s-runtime, red-team chains, GRC for 15 frameworks incl. EU AI Act / ISO 42001 / NIST AI RMF) install with one command, signed end-to-end via Sigstore

Built so you can keep your source local, your CI green, and your CISO answered without paying a per-seat SaaS bill or sending code to a vendor.

> **The MCP scanner that never sees your code.** No API. No token. No telemetry. Deterministic. Run `nox scan --offline` and the scan path makes zero outbound connections — enforced by a test, not a promise (`TestOSVDisabled_NoNetworkEgress`). Unlike scanners that proxy your traffic or phone home to a vendor API, nox runs entirely on your machine.

- **Deterministic** -- same inputs produce same outputs, no hidden state
- **Offline-first** -- zero required external services
- **Safe by default** -- never uploads source code, never executes untrusted code, never auto-applies fixes
- **Agent-native** -- safely callable via the Model Context Protocol (MCP)
- **Cosign-signed plugin marketplace** -- every official plugin verifies via Sigstore keyless OIDC; default trust policy refuses unsigned third-party drops

## Quick Demo

Install and scan a project in under a minute:

```bash
# Install
brew tap felixgeelhaar/tap && brew install nox
# or: go install github.com/nox-hq/nox/cli@latest

# Scan the current directory
nox scan .

# Output:
# nox dev -- scanning .
# [results] 12 findings, 47 dependencies, 3 AI components
# [done]
```

Nox writes `findings.json` to the current directory. To generate all output formats at once:

```bash
nox scan . --format all --output reports/
```

This produces:

```
reports/
  findings.json        # Nox canonical findings
  results.sarif        # SARIF 2.1.0 (GitHub Code Scanning)
  sbom.cdx.json        # CycloneDX SBOM with vulnerability enrichment
  sbom.spdx.json       # SPDX SBOM with security references
  report.html          # Standalone HTML report
  ai.inventory.json    # AI component inventory (if detected)
```

### Use in CI (GitHub Action)

```yaml
# .github/workflows/security.yml
- uses: nox-hq/nox@9133597590c30b2235093c48425c0afcecef0700 # v1.5.0
  with:
    path: '.'
    format: sarif
    annotate: 'true'    # Post inline PR comments (default: true)
- uses: github/codeql-action/upload-sarif@33119e582d3ab4ed79c2610af108cb08ff983917 # v3
  if: always()
  with:
    sarif_file: nox-results/results.sarif
```

### Use with AI Agents (MCP)

```bash
nox serve --allowed-paths /path/to/project
```

### Use in your editor (LSP)

`nox lsp` runs a Language Server over stdio, publishing findings as inline
diagnostics — squiggles, hover, the Problems panel — on open and save.
Deterministic and offline: it runs the local `nox` binary, no code leaves your
machine. Thin clients over it ship for **VS Code**
([`editors/vscode`](editors/vscode)) and **JetBrains** IDEs
([`editors/jetbrains`](editors/jetbrains) — IntelliJ IDEA Ultimate, GoLand,
PyCharm Professional, WebStorm, …; LSP4IJ for the Community editions).

```bash
nox lsp    # spoken by the editor extension; not run by hand
```

This starts an MCP server on stdio with 10 read-only tools and 5 resources. See [MCP Server](#mcp-server) for details.

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap felixgeelhaar/tap
brew install nox
```

### Go

```bash
go install github.com/nox-hq/nox/cli@latest
```

### Build from Source

```bash
git clone https://github.com/nox-hq/nox.git
cd nox
make build
./nox scan .
```

## What Nox Detects

Nox ships with **1506 built-in rules** across five analyzer suites:

### Secrets (938 rules)

Detects hardcoded secrets, API keys, tokens, and credentials across **25+ categories** (938 rules total, competitive with TruffleHog):

| Category | Rules | Examples |
|----------|-------|---------|
| Cloud Providers | SEC-001 -- SEC-015 | AWS, GCP, Azure, DigitalOcean, Heroku, Alibaba, IBM, Databricks |
| Source Control | SEC-003, SEC-016 -- SEC-022 | GitHub PAT/fine-grained/app tokens, GitLab, Bitbucket |
| Communication | SEC-023 -- SEC-029 | Slack, Discord, Telegram, Microsoft Teams |
| Payment | SEC-030 -- SEC-038 | Stripe, Square, Shopify, PayPal/Braintree |
| AI/ML Providers | SEC-039 -- SEC-044 | OpenAI, Anthropic, HuggingFace, Replicate, Cohere |
| DevOps & CI/CD | SEC-045 -- SEC-056 | NPM, PyPI, Docker Hub, Terraform, Vault, Grafana |
| SaaS & APIs | SEC-057 -- SEC-072 | Twilio, SendGrid, Datadog, PagerDuty, Linear, Okta |
| Database & Infra | SEC-073 -- SEC-076 | Connection strings (Postgres, MongoDB, Redis), Firebase |
| Crypto & Keys | SEC-004, SEC-077 -- SEC-079 | PEM private keys, Age, PGP, PKCS12 |
| Generic Patterns | SEC-005, SEC-080 -- SEC-086 | Passwords, secrets, Bearer/Basic auth, JWT, URLs with credentials |

**Secret detection features:**
- **Shannon entropy analysis** for high-entropy strings (API keys, tokens) with configurable thresholds
- **Context-aware detection** -- lowers entropy threshold when secret-suggestive keywords (`password`, `secret`, `token`, `key`, etc.) appear on the same line
- **False-positive hardening** -- automatically filters git SHAs, version strings, file paths, camelCase identifiers, hex checksums, and other non-secret patterns
- **File-pattern scoping** -- entropy rules only scan source-like files (not lockfiles, checksums, or vendored code)
- **Configurable via `.nox.yaml`** -- override entropy thresholds per rule (see [Entropy Configuration](#entropy-configuration))
- Git history scanning to find secrets in past commits
- Custom rules via YAML definition files (`--rules path/to/rules/`)

### AI Security (50 rules)

Detects AI/ML application security risks aligned with the **OWASP LLM Top 10**:

| Category | Rules | OWASP LLM | Examples |
|----------|-------|-----------|---------|
| Prompt Injection | AI-001 -- AI-003, AI-010 | LLM01 | Boundary violations, RAG injection, indirect injection |
| Tool/Agent Safety | AI-004, AI-005, AI-011 | LLM06 | MCP write tools, wildcard allowlists, unrestricted agents |
| Insecure Logging | AI-006, AI-007 | LLM02 | Prompt/response logging, API key exposure |
| Output Handling | AI-009, AI-012, AI-015, AI-018 | LLM05 | eval()/exec(), SQL injection, XSS, path traversal |
| Information Disclosure | AI-013, AI-016 | LLM02, LLM07 | Stack traces in responses, system prompt leakage |
| Supply Chain | AI-008, AI-014 | LLM03 | Unpinned models, insecure HTTP model downloads |
| Resource Management | AI-017 | LLM10 | Unlimited token limits |

### Infrastructure as Code (500 rules)

Detects misconfigurations across **7 IaC categories**:

| Category | Rules | Examples |
|----------|-------|---------|
| Dockerfile | IAC-001 -- IAC-003, IAC-022 -- IAC-025 | Root user, unpinned images, secrets in ARG, curl-pipe-sh |
| Terraform/Cloud | IAC-004 -- IAC-006, IAC-036 -- IAC-045 | Public access, disabled encryption, wildcard IAM, public S3 |
| Kubernetes | IAC-007 -- IAC-010, IAC-026 -- IAC-035 | Privileged pods, host namespaces, dangerous capabilities, cluster-admin |
| GitHub Actions | IAC-011 -- IAC-018 | pull_request_target, script injection, mutable action tags, write-all |
| Docker Compose | IAC-019 -- IAC-021, IAC-049 | Privileged mode, host networking, Docker socket mount |
| Helm | IAC-046 -- IAC-048 | Tiller deployment, hardcoded passwords, RBAC disabled |
| CI/CD General | IAC-050 | Disabled security checks |

### Dependencies & SCA (6 rules)

Parses lockfiles from **8 ecosystems** (Go, npm, PyPI, RubyGems, Cargo, Maven, Gradle, NuGet) and queries the [OSV.dev](https://osv.dev) database for known vulnerabilities:

| Rule | Description |
|------|-------------|
| VULN-001 | Known vulnerability in dependency (severity mapped from CVSS) |

- Batches queries to the OSV.dev API (up to 1000 packages per request)
- CVSS scores mapped to nox severity levels (Critical/High/Medium/Low/Info)
- Graceful degradation on network errors (offline-first)
- Disable with `--no-osv` flag or `scan.osv.disabled: true` in `.nox.yaml`
- Vulnerability data enriches CycloneDX and SPDX SBOM output

### Supply-chain integrity (deterministic, offline)

Beyond version-based SCA, nox flags supply-chain risks that have no CVE — the
insecure *shape*, not a known-bad version:

| Rule | Description |
|------|-------------|
| SLOP-001 | Imported package is not declared in any manifest, standard library, or local module — a hallucinated / slopsquatted package (Python + JS/TS) |
| VARIANT-001..006 | First-party code reproducing a known-CVE root cause (Log4Shell, PyYAML full-loader, tar path traversal, Zip Slip, SSTI, shell interpolation). See `nox variants` |
| PROV-001 | Dependency from a non-registry source (VCS/URL/tarball) — provenance cannot be verified (ASI04 / SLSA) |
| PROV-002 | VCS dependency pinned to a mutable ref instead of an immutable commit SHA |

All four never contact a registry. `nox variants [CVE-ID] [path]` reports CVE
variants directly; `nox variants --list` enumerates the signatures.

### Data Protection (12 rules)

Detects personally identifiable information (PII) and sensitive data patterns in code and configuration:

| Category | Rules | Examples |
|----------|-------|---------|
| Contact Info | DATA-001, DATA-004 | Email addresses, US phone numbers |
| Financial | DATA-003, DATA-007 | Credit card numbers (Visa/MC/Amex/Discover), IBAN |
| Government IDs | DATA-002, DATA-008 -- DATA-012 | SSN, UK National Insurance, Tax IDs, driver's license, passport |
| Health | DATA-010 | Health record identifiers (MRN, patient_id) |
| Infrastructure | DATA-005 | Hardcoded public IP addresses |
| Personal | DATA-006 | Date of birth fields |

### Memory safety (Go)

| Rule | Description |
|------|-------------|
| MEMSAFE-001 | Integer truncation reaching a `make()` size or a slice bound — a narrowed or sign-flipped length that wraps (CWE-190) |

Deliberately much narrower than gosec's `G115`, which reports every narrowing
conversion: measured across sixteen Go repositories, that produced 96 findings
and no real bugs. This rule reports only truncation that sizes memory, and
suppresses masks, modulo, unsigned shifts, guarded values and length-derived
values. Conversions whose operand type is not provable from the enclosing
function are not reported — nox parses Go with `go/ast`, not `go/types`. See
[`docs/design/go-integer-overflow.md`](docs/design/go-integer-overflow.md).

## Configuration

Create a `.nox.yaml` in your project root to customize scan behavior:

> nox reports configuration it cannot act on. A key it does not recognise, and a
> key it parses but ignores, both mean the policy you wrote is not the policy in
> force — so `nox scan` names them under `[degraded]` rather than passing in
> silence. Two keys are currently accepted and ignored: `compliance.framework`
> (no framework filtering is applied) and `cache` (nox never caches a scan, so
> the block configures nothing; the `--no-cache` flag is accepted as a no-op for
> the same reason).

`scan.include` is an allow-list of glob patterns: when set, only matching files
are scanned. `scan.exclude` still wins over it, so writing both means the
intersection. Directories are still descended — a glob cannot tell you in
advance whether a subtree contains a match, and pruning on that guess loses
files silently; use `scan.exclude` to keep a subtree out of the walk entirely.
Plugins receive the exclude patterns too, so a plugin that walks the tree itself
honours them rather than crashing on a path you asked it to skip.

```yaml
scan:
  exclude:
    - "vendor/"
    - "testdata/"
    - "*.test.js"
  osv:
    disabled: false          # Set true to skip OSV lookups (offline mode)
  rules:
    disable:
      - "AI-008"           # Unpinned model refs OK here
    severity_override:
      SEC-005: low          # Downgrade for this project

output:
  format: sarif             # Default output format
  directory: reports        # Default output directory

policy:
  fail_on: high             # Only fail on high+ severity (critical, high)
  warn_on: medium           # Warn on medium findings
  baseline_mode: warn       # warn | strict | off
  baseline_path: ""         # Default: .nox/baseline.json

explain:
  api_key_env: OPENAI_API_KEY   # Env var to read API key from
  model: gpt-4o                 # LLM model name
  base_url: ""                  # Custom OpenAI-compatible endpoint
  timeout: 2m                   # Per-request timeout
  batch_size: 10                # Findings per LLM request
  output: explanations.json     # Output file path
```

CLI flags always take precedence over config file values.

### Entropy Configuration

Fine-tune entropy-based secret detection thresholds via `.nox.yaml`:

```yaml
scan:
  entropy:
    threshold: 5.0           # General entropy threshold (default: 5.0)
    hex_threshold: 4.5       # Threshold for hex strings (default: rule-specific)
    base64_threshold: 5.2    # Threshold for base64 strings (default: rule-specific)
    require_context: true    # Only flag when secret keyword is present (default: false)
```

- **`threshold`** -- Minimum Shannon entropy (bits per character) to flag a candidate string. Higher values reduce false positives; lower values catch more secrets.
- **`require_context`** -- When `true`, only flag high-entropy strings on lines that contain secret-suggestive keywords (`password`, `secret`, `key`, `token`, `credential`, `api_key`, `private`). Useful for reducing noise in codebases with many random-looking constants.
- **Context boost** -- When a secret keyword is present on the same line, the effective threshold is automatically reduced by 0.5 bits, increasing sensitivity where it matters.

### Baseline Management

Manage known findings to track progress and suppress accepted risks:

```bash
# Create a baseline from all current findings
nox baseline write .

# Write to a specific file
nox baseline write . --output my-baseline.json

# Update baseline (add new, prune stale)
nox baseline update .
nox baseline update . --baseline my-baseline.json

# Show baseline statistics
nox baseline show .
```

### Inline Suppressions

Suppress specific findings directly in source code:

```go
// nox:ignore SEC-001 -- false positive in test
var testKey = "AKIAEXAMPLEFAKEKEY"

var apiKey = "test" // nox:ignore SEC-005
```

Supports all comment styles: `//`, `#`, `--`, `/*`, `<!--`. Multi-rule: `nox:ignore SEC-001,SEC-002`. Expiring: `nox:ignore SEC-001 -- expires:2025-12-31`.

### Diff Mode

Show only findings in changed files:

```bash
nox diff --base main --head HEAD
nox diff --base main --json
nox diff . --rules custom-rules.yaml
```

### Watch Mode

Re-scan automatically on file changes:

```bash
nox watch .
nox watch . --debounce 1s
nox watch . --json
```

### Finding Inspector

Inspect findings interactively with a TUI or as JSON:

```bash
# Interactive TUI
nox show .

# Filter by severity, rule, or file
nox show . --severity critical,high --rule "SEC-*" --file "src/"

# JSON output from a previous scan
nox show --input findings.json --json

# Control source context lines
nox show . --context 10
```

### LLM-Powered Explanations

Generate human-readable explanations of findings using any OpenAI-compatible API:

```bash
export OPENAI_API_KEY=sk-...
nox explain . --model gpt-4o --output explanations.json

# With custom endpoint and timeout
nox explain . --base-url http://localhost:11434/v1 --model llama3 --timeout 5m

# Control batch size for large scans
nox explain . --batch-size 20

# Enrich with plugin data
nox explain . --plugin-dir ./plugins --enrich threat-intel.lookup
```

This produces per-finding explanations with remediation guidance and an executive summary. The explain module is optional and never affects scan results.

### Security Badge

Generate an SVG security grade badge:

```bash
# Generate from a live scan
nox badge .

# From existing findings
nox badge --input findings.json

# Custom output path and label
nox badge . --output status.svg --label "security"

# Generate per-severity breakdown badges
nox badge . --by-severity
```

### Security Dashboard

Generate a standalone HTML dashboard with security grade, severity breakdown, and dependency overview:

```bash
# Generate and open in browser
nox dashboard .

# Save to a specific path
nox dashboard . --output reports/dashboard.html --no-browser
```

The dashboard is a single self-contained HTML file with no external dependencies — share it, embed it, or archive it.

### Shell Completions

```bash
# Bash
eval "$(nox completion bash)"

# Zsh
nox completion zsh > "${fpath[1]}/_nox"

# Fish
nox completion fish | source

# PowerShell
nox completion powershell | Out-String | Invoke-Expression
```

### PR Annotations

Post inline review comments on GitHub PRs:

```bash
nox annotate --input findings.json --pr 123 --repo owner/name
```

Auto-detects PR number and repo from `GITHUB_REF` and `GITHUB_REPOSITORY` environment variables in CI.

### Pre-commit Hooks

Block commits that contain secrets or security issues:

```bash
# Install the nox pre-commit hook
nox protect install

# With custom severity threshold
nox protect install --severity-threshold critical

# Force overwrite existing hook
nox protect install --force

# Custom hook path
nox protect install --hook-path /path/to/.git/hooks/pre-commit

# Check status
nox protect status

# Remove
nox protect uninstall
```

**For nox contributors**, install the project-level hook that also runs gofmt, go vet, and golangci-lint (including gocritic) -- matching CI:

```bash
make hooks
```

### Dynamic Exploit Validation

Static analysis tells you what is dangerous. `nox attack` tells you whether an
attacker can actually do it.

```bash
nox scan ./my-app --output .          # static, offline
nox attack plan .                     # exploit hypotheses — offline, sends nothing
nox attack run --profile safe         # simulate: what would be attempted
nox attack run --target http://127.0.0.1:8000 \
  --route /chat --fields persona,message \
  --profile sandbox --authorize       # ACTIVE
nox attack regress --record           # confirmed exploits become regression tests
```

Findings carry an exploitability state independent of severity — `POTENTIAL`,
`PLAUSIBLE`, `PREVENTED`, `INCONCLUSIVE`, `CONFIRMED`. Reaching `CONFIRMED`
requires an observed invariant violation, a sound benign control, reproduction
under a k-of-n gate, **and** deterministic evidence: a model's opinion that an
attack "probably worked" is recorded, labelled, and cannot confirm anything.

Success is never scored on a string the payload carried, so an app that merely
echoes input can never be mistaken for one that obeyed it.

`nox attack plan` is offline and read-only. `run`, `replay`, and `regress` are
ACTIVE — they send attack payloads, are never part of `nox scan`, refuse to run
without `--authorize`, and do not sandbox your target.

Over MCP, only `attack_plan` is exposed. The ACTIVE subcommands are deliberately
absent: `--authorize` exists so a *human* affirms they own the target, and nox
analyses untrusted repositories — an MCP-exposed attack runner would let text in
a README steer requests at a host of its choosing. Plan and read over MCP; act
from the CLI. See [docs/attack.md](docs/attack.md).

## CLI Reference

```
nox <command> [flags]

Commands:
  scan <path>              Scan a directory for security issues
  show [path]              Inspect findings interactively (TUI or JSON)
  explain <path>           Explain findings using an LLM
  badge [path]             Generate an SVG status badge
  baseline <cmd> [path]    Manage finding baselines (write, update, show)
  diff [path]              Show findings in changed files only
  watch [path]             Watch for changes and re-scan automatically
  annotate                 Annotate a GitHub PR with inline findings
  protect <cmd> [path]     Manage git pre-commit hooks (install, uninstall, status)
  completion <shell>       Generate shell completions (bash, zsh, fish, powershell)
  dashboard [path]         Generate an interactive HTML security dashboard
  cache <cmd>              Manage scan cache (clear, status)
  serve                    Start MCP server on stdio
  registry <cmd>           Manage plugin registries (add, list, remove)
  plugin <cmd>             Manage and invoke plugins (search, info, install, update,
                              list, remove, call, init, test, entry)
  vex <cmd>                OpenVEX waiver document tools (vex init)
  install-hook             Install pre-commit/pre-push git hooks
  fix                      Apply OSV fixed_in remediation upgrades (go/npm/pypi/cargo)
  doctor                   Report environment, plugin state, config sanity
  agent-graph              Render agent capability lattice (mermaid/dot)
  confirm                  ACTIVE: dynamically confirm AI prompt-injection findings
  attack <cmd>             Dynamic exploit validation (plan, run, replay, regress)
                              `plan` is offline; the rest are ACTIVE and need --authorize
  bench                    Scan a corpus directory; report rule fire-rates
  calibrate                Suggest severity overrides from a bench report
  version                  Print version and exit

Global Flags:
  --rules string           Path to custom rules YAML file or directory
  --quiet, -q              Suppress output except errors
  --verbose, -v            Verbose output

Scan Flags:
  --format string          Output formats: json, sarif, cdx, spdx, html, all (default: json)
  --output string          Output directory (default: .)
  --staged                 Scan only git-staged files
  --severity-threshold     Minimum severity to report (critical, high, medium, low)
  --no-osv                 Disable OSV.dev vulnerability lookups (offline mode)
  --no-cache               No-op; accepted for compatibility (scans are never cached)
  --changed-since string   Only scan files changed since git ref

Show Flags:
  --severity string        Filter by severity (comma-separated: critical,high,medium,low,info)
  --rule string            Filter by rule pattern (e.g., AI-*, SEC-001)
  --file string            Filter by file pattern (e.g., src/)
  --input string           Path to findings.json (default: run scan)
  --json                   Output JSON instead of interactive TUI
  --context int            Number of source context lines (default: 5)

Explain Flags:
  --model string           LLM model name (default: gpt-4o)
  --base-url string        Custom OpenAI-compatible API base URL
  --batch-size int         Findings per LLM request (default: 10)
  --output string          Output file path (default: explanations.json)
  --plugin-dir string      Directory containing plugin binaries for enrichment
  --enrich string          Comma-separated list of plugin tools to invoke
  --timeout duration       Timeout per LLM request (default: 2m)

Badge Flags:
  --input string           Path to findings.json (default: run scan)
  --output string          Output SVG file path (default: .github/nox-badge.svg)
  --label string           Badge label text (default: nox)
  --by-severity            Generate additional badges per severity level

Diff Flags:
  --base string            Base git ref for comparison (default: main)
  --head string            Head git ref for comparison (default: HEAD)
  --json                   Output as JSON

Watch Flags:
  --debounce duration      Debounce interval for file changes (default: 500ms)
  --json                   Output as JSON

Protect Flags:
  --severity-threshold     Minimum severity to block commit (default: high)
  --hook-path string       Custom path to pre-commit hook file
  --force                  Overwrite existing hook without prompting

Baseline Flags:
  --output string          Baseline file path for write (default: .nox/baseline.json)
  --baseline string        Baseline file path for update (default: .nox/baseline.json)

Annotate Flags:
  --input string           Path to findings.json (default: findings.json)
  --pr string              PR number (auto-detected from GITHUB_REF)
  --repo string            Repository owner/name (auto-detected from GITHUB_REPOSITORY)

Dashboard Flags:
  --output string          Output HTML file path (default: temp file)
  --no-browser             Write HTML file without opening browser

Cache Commands:
  clear                    Clear the scan cache
  status                   Show cache statistics

Serve Flags:
  --allowed-paths string   Comma-separated list of allowed workspace paths

Exit Codes:
  0   No findings (or policy pass)
  1   Findings detected (or policy fail)
  2   Error
```

See [`docs/usage.md`](docs/usage.md) for the full CLI reference.

## Architecture

Six top-level packages with strict dependency direction (`core` depends on nothing):

```
core/       Scan engine, rule catalog, report generation (no CLI, no network)
cli/        Argument parsing, TUI, output handling
server/     MCP server (stdio, sandboxed, rate-limited)
plugin/     gRPC-based plugin host with safety profiles
sdk/        Plugin authoring SDK with conformance tests
registry/   Plugin registry client (index + OCI distribution)
assist/     Optional LLM-powered explanations (no side effects)
```

### Scan Pipeline

```
1. Load config (.nox.yaml)
2. Discover artifacts (respects .gitignore + excludes)
3. Run analyzers (secrets, IaC, AI security, dependencies)
4. Apply rule config (disable, severity override)
5. Deduplicate by fingerprint
6. Sort deterministically
7. Apply inline suppressions (nox:ignore)
8. Apply baseline matching
9. Evaluate policy (pass/fail thresholds)
10. Emit reports (JSON, SARIF, CycloneDX, SPDX)
```

## Plugin Ecosystem

Nox supports a gRPC-based plugin system organized into **10 security tracks**, enabling extensibility into domains like DAST, CSPM, secret verification, and more -- without bloating the core scanner:

| Track | Purpose | Example Capabilities |
|-------|---------|---------------------|
| core-analysis | Static analysis, secrets, code patterns | Custom SAST rules, language-specific analysis |
| dynamic-runtime | Runtime behavior and dynamic analysis | DAST scanning, runtime security monitoring |
| ai-security | AI/ML-specific security concerns | Model supply chain, prompt fuzzing |
| threat-modeling | Threat identification and modeling | STRIDE analysis, attack surface mapping |
| supply-chain | Dependency and supply chain security | Malicious package detection, license compliance |
| intelligence | Threat intelligence integration | Secret verification, IOC enrichment |
| policy-governance | Policy enforcement and compliance | CSPM, regulatory compliance checks |
| incident-readiness | Incident response preparation | Runbook validation, playbook testing |
| developer-experience | Developer tooling and feedback | Fix suggestions, IDE integrations |
| agent-assistance | AI agent integration and safety | Agent guardrails, tool safety verification |

Each track has built-in safety profiles that control what plugins can and cannot do (e.g., `passive` plugins are read-only, `active` plugins can write files, `runtime` plugins can execute code).

### Scaffold a Plugin

```bash
nox plugin init --name my-scanner --track core-analysis
cd nox-plugin-my-scanner
make test
```

Additional init flags:
- `--risk-class <passive|active|runtime>` -- Override the default risk class for the track
- `--output <dir>` -- Custom output directory

See [`docs/plugin-authoring.md`](docs/plugin-authoring.md) for the full SDK guide.

### Install and Use Plugins

The official registry is auto-added on first run; no `nox registry add` needed for the public set. Operators add private registries on top.

**Declaring plugins in `.nox.yaml` is what makes them run during a scan.**
Installing a plugin puts it on the machine; listing it under `plugins.required`
is what enables it for a project. That separation is deliberate — it keeps a
scan's results from depending on which plugins happen to be installed, so
everyone cloning your project gets the same set and the same findings:

```yaml
# .nox.yaml
plugins:
  required:
    - nox/reachability@>=0.5
    - nox/ai-eval
    - nox/taint-analysis
  registries:
    # Project-level registry overrides; merged with the official source.
    # Use `name=url` to assign a name.
    - acme=https://registry.acme.internal/nox/index.json
```

```bash
nox install                       # reads plugins.required, fetches each
nox scan .                        # auto-installs missing required plugins
nox scan . --no-auto-install      # opt out
```

**Working with plugins directly (no manifest).** These commands address a
plugin by name and do not consult `.nox.yaml`. Note that `nox plugin install`
alone does *not* make a plugin participate in `nox scan` — add it to
`plugins.required` for that. `nox plugin list` shows which installed plugins
are active in the current directory:

```bash
# Search and install (registry auto-configured)
nox plugin search ai
nox plugin search --track ai-security
nox plugin install nox/ai-eval
nox plugin install nox/reachability@0.5.0

# Inspect, run, update, remove
nox plugin info nox/ai-eval
nox plugin list
nox plugin call ai-eval ai_eval endpoint=http://localhost:8080/chat
nox plugin update nox/ai-eval
nox plugin remove nox/ai-eval

# Add a private / enterprise registry on top
nox registry add https://registry.acme.internal/nox/index.json --name acme
nox registry list
nox registry remove acme
```

All plugins in the official registry ship Cosign-signed (keyless via
GitHub OIDC). The default trust policy is `default`: nox downloads
the release's `checksums.txt` + Sigstore bundle, verifies the bundle
against the plugin's `release.yml` workflow OIDC subject, and
confirms the artifact's SHA-256 is listed in the signed checksums.
Install fails closed unless either Cosign keyless **or** an in-tool
Ed25519 signature passes; operators bypass with `--allow-unverified`
or `plugins.trust_policy: permissive` in `.nox.yaml`. See
[`docs/marketplace.md`](docs/marketplace.md) for the trust model
details.

```bash
$ nox plugin install nox/reachability
Trust: community (signer: cosign-keyless:(?i)https://github.com/nox-hq/nox-plugin-reachability/.github/workflows/release.yml@.*)
Installed nox/reachability@0.6.5 (community)
```

### Currently published plugins

| Plugin | Track | What it adds |
|---|---|---|
| `nox/reachability` | core-analysis | Multi-language reachability for VULN findings (Go, PyPI, npm, Cargo, Maven, RubyGems, NuGet). Bundled in the default release archive. |
| `nox/taint-analysis` | core-analysis | Cross-file taint flow. TAINT-001..005 + interprocedural TAINT-006/007 + AI flows TAINT-AI-001/002. |
| `nox/k8s-runtime` | dynamic-runtime | Live cluster scanning. KRUNT-001..008. |
| `nox/red-team` | dynamic-runtime | Attack-chain analysis + active validation. |
| `nox/grc` | policy-governance | 12 compliance frameworks (SOC2, ISO 27001, GDPR, FedRAMP L/M/H, HIPAA, PCI-DSS, NIST 800-53, NIST CSF, CIS v8, CMMC). |
| `nox/ai-eval` | dynamic-runtime | Adversarial prompt corpus runner. Fires jailbreak / system-leak / role-confusion / tool-misuse against a chat endpoint. AI-EVAL-001..004. |

### Publish a plugin

```bash
# Tag the plugin repo. The release workflow builds binaries via
# GoReleaser, signs the checksums via Cosign keyless, generates a
# registry entry, and uploads it as a workflow artifact.
git tag v0.2.0 && git push --tags

# Open a PR against nox-hq/nox to add the entry to
# registry-scaffold/index.json. Operators see the new version in
# `nox plugin search` once the PR merges.
```

See [`docs/marketplace.md`](docs/marketplace.md) for the full publish flow and the maturity ladder. A public marketplace site rendered from the same index is published at [`nox-hq.github.io/nox`](https://nox-hq.github.io/nox/).

## MCP Server

The built-in MCP server allows AI agents to invoke scans safely:

```bash
nox serve --allowed-paths /path/to/project
```

### Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `scan` | `path` (required) | Run a security scan on a directory |
| `get_findings` | `format` (json\|sarif) | Get findings from last scan |
| `get_sbom` | `format` (cdx\|spdx) | Get software bill of materials |
| `get_finding_detail` | `finding_id`, `context_lines` | Get enriched finding with source context |
| `list_findings` | `severity`, `rule`, `file`, `limit` | List findings with filtering |
| `baseline_status` | `path` | Get baseline statistics |
| `baseline_add` | `path`, `fingerprint`, `reason` | Add finding to baseline |
| `attack_plan` | `path` | Build exploit hypotheses from the last scan. Offline: contacts no target, executes nothing |
| `plugin.list` | -- | List registered plugins |
| `plugin.call_tool` | `tool`, `input`, `workspace_root` | Invoke a plugin tool |

### Resources

| URI | Type | Description |
|-----|------|-------------|
| `nox://findings` | application/json | Canonical findings |
| `nox://sarif` | application/json | SARIF 2.1.0 report |
| `nox://sbom/cdx` | application/json | CycloneDX SBOM |
| `nox://sbom/spdx` | application/json | SPDX SBOM |
| `nox://ai-inventory` | application/json | AI component inventory |

Output is truncated at 1 MB. Workspace paths are allowlisted.

Most tools are read-only. The exceptions are explicit: `baseline_add` /
`baseline_add_many` write the baseline file, and `plugin_install` runs new code
on the operator's machine and requires `confirmed: true`, which the MCP host must
collect from a human.

**No ACTIVE capability is exposed over MCP.** `nox attack run` / `replay` /
`regress` and `nox confirm` send attack payloads at a network target, and they
are CLI-only by design. `--authorize` exists so a *human* affirms they own and
have isolated the target; a model-initiated tool call cannot make that
affirmation. And because nox analyses untrusted repositories, an MCP-exposed
attack runner would let attacker-controlled text steer requests at a host of its
choosing — the confused-deputy pattern nox itself scans for. `attack_plan` is
exposed because it only reasons over artifacts already on disk.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the pull request process.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

Nox is licensed under the [Apache License 2.0](LICENSE).
