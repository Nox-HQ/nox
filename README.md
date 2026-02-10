# Nox

![CI](https://github.com/nox-hq/nox/actions/workflows/ci.yml/badge.svg)
![Security](.github/nox-badge.svg)
![Coverage](.github/coverage-badge.svg)
![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

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
  sbom.cdx.json        # CycloneDX SBOM
  sbom.spdx.json       # SPDX SBOM
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

This starts an MCP server on stdio with read-only tools (`scan`, `get_findings`, `get_sbom`) and resources (`nox://findings`, `nox://sarif`, `nox://sbom/cdx`).

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

Nox ships with **23 built-in rules** across four analyzer suites:

### Secrets (5 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| SEC-001 | High | AWS Access Key ID |
| SEC-002 | Critical | AWS Secret Access Key |
| SEC-003 | High | GitHub token |
| SEC-004 | Critical | Private key header |
| SEC-005 | Medium | Generic API key assignment |

### AI Security (8 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| AI-001 | High | Prompt injection boundary missing or weak |
| AI-002 | High | User input concatenated into prompt template |
| AI-003 | Medium | RAG context injected without sanitisation boundary |
| AI-004 | Critical | MCP server exposes file system write without restrictions |
| AI-005 | High | MCP config allows all tools without allowlist |
| AI-006 | Medium | Prompt/response logged without redaction |
| AI-007 | High | LLM API key logged or printed |
| AI-008 | Medium | Model reference without version pin |

### Infrastructure as Code (10 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| IAC-001 | High | Dockerfile runs as root |
| IAC-002 | Medium | Dockerfile uses unpinned base image |
| IAC-003 | Low | Dockerfile uses ADD instead of COPY |
| IAC-004 | High | Terraform allows public access (0.0.0.0/0) |
| IAC-005 | High | S3 bucket missing encryption |
| IAC-006 | Critical | Security group allows unrestricted SSH |
| IAC-007 | Critical | Kubernetes pod running as privileged |
| IAC-008 | High | Kubernetes pod uses host network |
| IAC-009 | Critical | Kubernetes pod allows privilege escalation |
| IAC-010 | High | Kubernetes pod running as root |

### Dependencies

Parses lockfiles from **8 ecosystems** (Go, npm, PyPI, RubyGems, Cargo, Maven, Gradle, NuGet) and generates a software bill of materials. Vulnerability enrichment via OSV is planned.

## Configuration

Create a `.nox.yaml` in your project root to customize scan behavior:

```yaml
scan:
  exclude:
    - "vendor/"
    - "testdata/"
    - "*.test.js"
  rules:
    disable:
      - "AI-008"           # Unpinned model refs OK here
    severity_override:
      SEC-005: low          # Downgrade for this project

output:
  format: sarif             # Default output format
  directory: reports        # Default output directory

explain:
  api_key_env: OPENAI_API_KEY   # Env var to read API key from
  model: gpt-4o                 # LLM model name
  base_url: ""                  # Custom OpenAI-compatible endpoint
  timeout: 2m                   # Per-request timeout
  batch_size: 10                # Findings per LLM request
  output: explanations.json     # Output file path
```

### Policy & Baseline

Control CI pass/fail behavior and manage known findings:

```yaml
# .nox.yaml
policy:
  fail_on: high          # Only fail on high+ severity (critical, high)
  warn_on: medium        # Warn on medium findings
  baseline_mode: warn    # warn | strict | off
  baseline_path: ""      # Default: .nox/baseline.json
```

```bash
# Create a baseline from all current findings
nox baseline write .

# Update baseline (add new, prune stale)
nox baseline update .

# Show baseline statistics
nox baseline show .
```

### Inline Suppressions

Suppress specific findings directly in source code:

```go
// nox:ignore SEC-001 -- false positive in test
var testKey = "AKIAIOSFODNN7EXAMPLE"

var apiKey = "test" // nox:ignore SEC-005
```

Supports all comment styles: `//`, `#`, `--`, `/*`, `<!--`. Multi-rule: `nox:ignore SEC-001,SEC-002`. Expiring: `nox:ignore SEC-001 -- expires:2025-12-31`.

### Diff Mode

Show only findings in changed files:

```bash
nox diff --base main --head HEAD
nox diff --base main --json
```

### Watch Mode

Re-scan automatically on file changes:

```bash
nox watch .
nox watch . --debounce 1s
```

### Shell Completions

```bash
# Bash
eval "$(nox completion bash)"

# Zsh
nox completion zsh > "${fpath[1]}/_nox"

# Fish
nox completion fish | source
```

### PR Annotations

Post inline review comments on GitHub PRs:

```bash
nox annotate --input findings.json --pr 123 --repo owner/name
```

Auto-detects PR number and repo from `GITHUB_REF` and `GITHUB_REPOSITORY` environment variables in CI.

CLI flags always take precedence over config file values.

## CLI Reference

```
nox <command> [flags]

Commands:
  scan <path>         Scan a directory for security issues
  show [path]         Inspect findings interactively
  explain <path>      Explain findings using an LLM
  badge [path]        Generate an SVG status badge
  baseline <cmd>      Manage finding baselines (write, update, show)
  diff [path]         Show findings in changed files only
  watch [path]        Watch for changes and re-scan automatically
  annotate            Annotate a GitHub PR with inline findings
  completion <shell>  Generate shell completions (bash, zsh, fish, powershell)
  serve               Start MCP server on stdio
  registry            Manage plugin registries
  plugin              Manage and invoke plugins
  version             Print version and exit

Scan Flags:
  --format string   Output formats: json, sarif, cdx, spdx, all (default: json)
  --output string   Output directory (default: .)
  --quiet, -q       Suppress output except errors
  --verbose, -v     Verbose output

Exit Codes:
  0   No findings (or policy pass)
  1   Findings detected (or policy fail)
  2   Error
```

See [`docs/usage.md`](docs/usage.md) for the full CLI reference.

## Architecture

Four top-level packages with strict dependency direction (`core` depends on nothing):

```
core/       Scan engine (no CLI, no network)
cli/        Argument parsing, output handling
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
10. Emit reports
```

## Plugin Ecosystem

Nox supports a gRPC-based plugin system organized into **10 security tracks**:

| Track | Purpose |
|-------|---------|
| core-analysis | Static analysis, secrets, code patterns |
| dynamic-runtime | Runtime behavior and dynamic analysis |
| ai-security | AI/ML-specific security concerns |
| threat-modeling | Threat identification and modeling |
| supply-chain | Dependency and supply chain security |
| intelligence | Threat intelligence integration |
| policy-governance | Policy enforcement and compliance |
| incident-readiness | Incident response preparation |
| developer-experience | Developer tooling and feedback |
| agent-assistance | AI agent integration and safety |

### Scaffold a Plugin

```bash
nox plugin init --name my-scanner --track core-analysis
cd nox-plugin-my-scanner
make test
```

See [`docs/plugin-authoring.md`](docs/plugin-authoring.md) for the full SDK guide.

### Install and Use Plugins

```bash
nox registry add https://registry.nox.dev/index.json
nox plugin search sast
nox plugin install nox/sast
nox plugin call nox/sast scan workspace_root=/path/to/project
```

## MCP Server

The built-in MCP server allows AI agents to invoke scans safely:

```bash
nox serve --allowed-paths /path/to/project
```

**Tools:** `scan`, `get_findings`, `get_sbom`, `get_finding_detail`, `list_findings`, `baseline_status`, `baseline_add`, `plugin.list`, `plugin.call_tool`, `plugin.read_resource`

**Resources:** `nox://findings`, `nox://sarif`, `nox://sbom/cdx`, `nox://sbom/spdx`, `nox://ai-inventory`

All tools are read-only. Output is truncated at 1 MB. Workspace paths are allowlisted.

## LLM-Powered Explanations

Generate human-readable explanations of findings using any OpenAI-compatible API:

```bash
export OPENAI_API_KEY=sk-...
nox explain . --model gpt-4o --output explanations.json
```

This produces per-finding explanations with remediation guidance and an executive summary. The explain module is optional and never affects scan results.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the pull request process.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

Nox is licensed under the [Apache License 2.0](LICENSE).
