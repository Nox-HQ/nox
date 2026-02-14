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

**Language-agnostic security scanner with first-class AI application security.**

Nox produces standard artifacts (SARIF, SBOM) and explicitly models AI application security risks. It is designed to be callable by humans, CI systems, and AI agents (via MCP).

- **Deterministic** -- same inputs produce same outputs, no hidden state
- **Offline-first** -- zero required external services
- **Safe by default** -- never uploads source code, never executes untrusted code, never auto-applies fixes
- **Agent-native** -- safely callable via the Model Context Protocol (MCP)

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
  ai.inventory.json    # AI component inventory (if detected)
```

### Use in CI (GitHub Action)

```yaml
# .github/workflows/security.yml
- uses: nox-hq/nox@v1
  with:
    path: '.'
    format: sarif
    annotate: 'true'    # Post inline PR comments (default: true)
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: nox-results/results.sarif
```

### Use with AI Agents (MCP)

```bash
nox serve --allowed-paths /path/to/project
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

Nox ships with **567 built-in rules** across five analyzer suites:

### Secrets (163 rules)

Detects hardcoded secrets, API keys, tokens, and credentials across **15 categories**:

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

### AI Security (21 rules)

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

### Infrastructure as Code (365 rules)

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

## Configuration

Create a `.nox.yaml` in your project root to customize scan behavior:

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
  serve                    Start MCP server on stdio
  registry <cmd>           Manage plugin registries (add, list, remove)
  plugin <cmd>             Manage and invoke plugins
  version                  Print version and exit

Global Flags:
  --rules string           Path to custom rules YAML file or directory
  --quiet, -q              Suppress output except errors
  --verbose, -v            Verbose output

Scan Flags:
  --format string          Output formats: json, sarif, cdx, spdx, all (default: json)
  --output string          Output directory (default: .)
  --staged                 Scan only git-staged files
  --severity-threshold     Minimum severity to report (critical, high, medium, low)
  --no-osv                 Disable OSV.dev vulnerability lookups (offline mode)

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

```bash
# Add a registry
nox registry add https://registry.nox.dev/index.json
nox registry add https://custom.registry.io/index.json --name custom

# List registries
nox registry list

# Search and install
nox plugin search sast
nox plugin search --track ai-security fuzzing
nox plugin install nox/sast
nox plugin install nox/sast@1.2.0

# List installed plugins
nox plugin list

# Get plugin info
nox plugin info nox/sast

# Call a plugin tool
nox plugin call nox/sast scan workspace_root=/path/to/project
nox plugin call nox/sast analyze --input params.json

# Update and remove
nox plugin update nox/sast
nox plugin remove nox/sast

# Remove a registry
nox registry remove custom
```

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
| `plugin.list` | -- | List registered plugins |
| `plugin.call_tool` | `tool`, `input`, `workspace_root` | Invoke a plugin tool |
| `plugin.read_resource` | `plugin`, `uri` | Read a plugin resource |

### Resources

| URI | Type | Description |
|-----|------|-------------|
| `nox://findings` | application/json | Canonical findings |
| `nox://sarif` | application/json | SARIF 2.1.0 report |
| `nox://sbom/cdx` | application/json | CycloneDX SBOM |
| `nox://sbom/spdx` | application/json | SPDX SBOM |
| `nox://ai-inventory` | application/json | AI component inventory |

All tools are read-only. Output is truncated at 1 MB. Workspace paths are allowlisted.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the pull request process.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

Nox is licensed under the [Apache License 2.0](LICENSE).
