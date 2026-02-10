# Nox Usage Guide

Complete reference for the Nox CLI, configuration, and integrations.

## Table of Contents

- [Commands](#commands)
  - [scan](#scan)
  - [show](#show)
  - [explain](#explain)
  - [badge](#badge)
  - [baseline](#baseline)
  - [diff](#diff)
  - [watch](#watch)
  - [annotate](#annotate)
  - [completion](#completion)
  - [serve](#serve)
  - [registry](#registry)
  - [plugin](#plugin)
- [Configuration](#configuration)
  - [.nox.yaml](#noxyaml)
  - [Exclude Patterns](#exclude-patterns)
  - [Rule Overrides](#rule-overrides)
  - [Output Defaults](#output-defaults)
  - [Policy Settings](#policy-settings)
  - [Explain Defaults](#explain-defaults)
- [Inline Suppressions](#inline-suppressions)
- [Output Formats](#output-formats)
  - [findings.json](#findingsjson)
  - [results.sarif](#resultssarif)
  - [SBOM](#sbom)
  - [AI Inventory](#ai-inventory)
- [CI/CD Integration](#cicd-integration)
  - [GitHub Actions](#github-actions)
  - [GitLab CI](#gitlab-ci)
  - [Generic CI](#generic-ci)
- [MCP Server](#mcp-server)
  - [Tools](#tools)
  - [Resources](#resources)
  - [Claude Desktop](#claude-desktop)
- [Plugin Management](#plugin-management)
  - [Registries](#registries)
  - [Installing Plugins](#installing-plugins)
  - [Invoking Plugin Tools](#invoking-plugin-tools)
  - [Scaffolding a Plugin](#scaffolding-a-plugin)
- [Exit Codes](#exit-codes)

---

## Commands

### scan

Scan a directory for security issues.

```
nox scan <path> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `json` | Output formats: `json`, `sarif`, `cdx`, `spdx`, `all` (comma-separated) |
| `--output` | `.` | Output directory for report files |
| `--quiet`, `-q` | `false` | Suppress all output except errors |
| `--verbose`, `-v` | `false` | Enable verbose output |

**Examples:**

```bash
# Basic scan, writes findings.json to current directory
nox scan .

# Generate SARIF for GitHub Code Scanning
nox scan . --format sarif --output results/

# Generate all formats into a reports directory
nox scan /path/to/project --format all --output /path/to/reports

# Quiet mode for CI (exit code only)
nox scan . -q

# Verbose mode for debugging
nox scan . -v
```

The scan pipeline:

1. Loads `.nox.yaml` from the target directory (if present)
2. Discovers artifacts by walking the directory tree
3. Respects `.gitignore` patterns and `.nox.yaml` exclude patterns
4. Runs all analyzers: secrets, IaC, AI security, dependencies
5. Applies rule disabling and severity overrides from config
6. Deduplicates findings by fingerprint
7. Sorts deterministically for reproducible output
8. Applies inline suppressions (`nox:ignore` comments)
9. Applies baseline matching (marks known findings)
10. Evaluates policy (determines pass/fail based on thresholds)
11. Writes reports in the requested formats

### show

Inspect findings interactively with a terminal UI or as structured JSON.

```
nox show [path] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--severity` | (all) | Filter by severity: `critical,high,medium,low,info` (comma-separated) |
| `--rule` | (all) | Filter by rule pattern (e.g., `AI-*`, `SEC-001`) |
| `--file` | (all) | Filter by file pattern (e.g., `src/`) |
| `--input` | (none) | Path to `findings.json` to inspect (skips scan) |
| `--json` | `false` | Output JSON instead of TUI |
| `--context` | `5` | Number of source context lines |

**Examples:**

```bash
# Interactive TUI (default)
nox show .

# Inspect an existing findings file
nox show --input findings.json

# Filter critical findings as JSON (pipe-friendly)
nox show --severity critical --json | jq '.[] | .Rule.Remediation'

# Filter by rule pattern
nox show --rule "AI-*" --json

# Show findings for specific files
nox show --file "config.*" --context 10
```

**TUI Key Bindings:**

| Key | Action |
|-----|--------|
| `↑`/`↓` or `j`/`k` | Navigate list |
| `enter` | Open detail view |
| `esc` | Back to list |
| `/` | Search (fuzzy over file path, rule ID, message) |
| `s` | Cycle severity filter |
| `n`/`p` | Next/previous finding (in detail view) |
| `q` | Quit |

The detail view shows:
- Source context with the matching line highlighted
- CWE identifier
- Remediation guidance
- Reference links
- Related findings (same file or same rule)

When stdout is not a TTY or `--json` is passed, the command outputs enriched JSON with source context and rule metadata for each finding.

### explain

Explain findings using an LLM. Requires an OpenAI-compatible API.

```
nox explain <path> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--model` | `gpt-4o` | LLM model name |
| `--base-url` | (none) | Custom OpenAI-compatible API base URL |
| `--batch-size` | `10` | Findings per LLM request |
| `--output` | `explanations.json` | Output file path |
| `--plugin-dir` | (none) | Directory containing plugin binaries for enrichment |
| `--enrich` | (none) | Comma-separated list of read-only plugin tools to invoke |

**Environment Variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes (unless `--base-url` set) | API key for the LLM provider |

**Examples:**

```bash
# Explain findings using GPT-4o
export OPENAI_API_KEY=sk-...
nox explain .

# Use a local LLM endpoint
nox explain . --base-url http://localhost:8080/v1

# Enrich explanations with plugin context
nox explain . --plugin-dir ./plugins --enrich sast.get_context

# Control batch size for large finding sets
nox explain . --batch-size 5 --output detailed-explanations.json
```

The explain command:

1. Runs a full scan of the target directory
2. Batches findings and sends them to the LLM
3. Generates per-finding explanations with remediation guidance
4. Produces an executive summary
5. Reports token usage

The explain module is optional and never affects scan results.

### badge

Generate an SVG status badge showing scan results.

```
nox badge [path] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (none) | Path to `findings.json` (default: run scan) |
| `--output` | `.github/nox-badge.svg` | Output SVG file path |
| `--label` | `nox` | Badge label text |

**Examples:**

```bash
# Scan and generate badge
nox badge .

# Generate badge from existing findings
nox badge --input findings.json

# Custom label and output path
nox badge . --label "security" --output docs/badge.svg
```

The badge color reflects the highest severity level found:

| Severity | Color |
|----------|-------|
| Clean (0 findings) | Green |
| Info only | Gray |
| Low only | Yellow-green |
| Medium | Yellow |
| High | Orange |
| Critical | Red |

The badge text shows the count at the highest severity (e.g., `3 critical · 12 total`) or `clean` if no findings were detected.

**Use in CI to auto-update the badge:**

```yaml
- name: Update security badge
  run: nox badge . --output .github/nox-badge.svg

- name: Commit badge
  run: |
    git add .github/nox-badge.svg
    git diff --staged --quiet || git commit -m "chore: update nox badge [skip ci]"
    git push
```

Then reference it in your README:

```markdown
![Nox](.github/nox-badge.svg)
```

### baseline

Manage finding baselines for tracking known issues that should not block CI.

```
nox baseline <write|update|show> [path] [flags]
```

**Subcommands:**

```bash
# Write a baseline from all current findings
nox baseline write .

# Write to a custom path
nox baseline write . --output custom-baseline.json

# Merge new findings into existing baseline and prune stale entries
nox baseline update .

# Show baseline statistics
nox baseline show .
```

The baseline file is stored at `.nox/baseline.json` by default. When a finding matches a baseline entry (by fingerprint), it is marked as `baselined` and may be excluded from CI failure depending on the policy `baseline_mode` setting.

**Baseline file format:**

```json
{
  "schema_version": "1.0.0",
  "entries": [
    {
      "fingerprint": "a1b2c3...",
      "rule_id": "SEC-001",
      "file_path": "config.env",
      "severity": "high",
      "reason": "accepted risk",
      "created_at": "2026-02-10T00:00:00Z",
      "expires_at": "2026-06-01T00:00:00Z"
    }
  ]
}
```

### diff

Show findings only in files changed relative to a git base ref.

```
nox diff [path] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--base` | `main` | Base ref for comparison |
| `--head` | `HEAD` | Head ref for comparison |
| `--json` | `false` | Output as JSON |

**Examples:**

```bash
# Show findings in files changed vs main
nox diff --base main

# JSON output for CI
nox diff --base main --json

# Compare specific refs
nox diff --base v1.0.0 --head feature-branch
```

### watch

Watch for file changes and re-scan automatically. Useful during development.

```
nox watch [path] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--debounce` | `500ms` | Debounce interval for file changes |

**Examples:**

```bash
# Watch the current directory
nox watch .

# Custom debounce interval
nox watch . --debounce 1s
```

Press `Ctrl+C` to stop. The terminal is cleared between scans.

### annotate

Post inline review comments on a GitHub pull request with finding details.

```
nox annotate [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `findings.json` | Path to findings.json |
| `--pr` | (auto) | PR number (auto-detected from `GITHUB_REF`) |
| `--repo` | (auto) | Repository owner/name (auto-detected from `GITHUB_REPOSITORY`) |

**Examples:**

```bash
# Auto-detect PR context in CI
nox annotate --input nox-results/findings.json

# Explicit PR and repo
nox annotate --input findings.json --pr 42 --repo myorg/myrepo
```

Requires the `gh` CLI to be installed and authenticated. Each finding is posted as an inline comment with severity badge, rule ID, and message.

### completion

Generate shell completion scripts.

```
nox completion <bash|zsh|fish|powershell>
```

**Setup:**

```bash
# Bash (add to ~/.bashrc)
eval "$(nox completion bash)"

# Zsh (add to ~/.zshrc or use fpath)
nox completion zsh > "${fpath[1]}/_nox"

# Fish
nox completion fish | source

# PowerShell
nox completion powershell | Out-String | Invoke-Expression
```

### serve

Start an MCP (Model Context Protocol) server on stdio.

```
nox serve [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--allowed-paths` | (none) | Comma-separated list of allowed workspace paths |

**Example:**

```bash
# Allow scanning a specific project
nox serve --allowed-paths /home/user/myproject

# Allow multiple paths
nox serve --allowed-paths /path/one,/path/two
```

See [MCP Server](#mcp-server) for details on available tools and resources.

### registry

Manage plugin registry sources.

```
nox registry <subcommand> [args]
```

**Subcommands:**

```bash
# Add a registry
nox registry add https://registry.nox.dev/index.json
nox registry add https://example.com/plugins/index.json --name my-registry

# List configured registries
nox registry list

# Remove a registry
nox registry remove my-registry
```

### plugin

Manage and invoke plugins.

```
nox plugin <subcommand> [args]
```

**Subcommands:**

```bash
# Search for plugins
nox plugin search sast
nox plugin search --track ai-security vulnerability

# Show plugin details
nox plugin info nox/sast

# Install a plugin (latest version)
nox plugin install nox/sast

# Install a specific version
nox plugin install nox/sast@1.2.0

# Update all installed plugins
nox plugin update

# Update a specific plugin
nox plugin update nox/sast

# List installed plugins
nox plugin list

# Remove a plugin
nox plugin remove nox/sast

# Invoke a plugin tool
nox plugin call nox/sast scan workspace_root=/path/to/project

# Invoke with JSON input
nox plugin call nox/sast scan --input config.json

# Scaffold a new plugin project
nox plugin init --name my-scanner --track core-analysis
nox plugin init --name my-checker --track ai-security --risk-class passive --output ./plugins
```

---

## Configuration

### .nox.yaml

Place a `.nox.yaml` file in your project root to configure scan behavior. This is separate from `.gitignore` — you may want to scan files that are tracked by git but excluded from security scanning (e.g., test fixtures, vendored code).

```yaml
# .nox.yaml — Nox project configuration

scan:
  # Paths to exclude from scanning (gitignore-style patterns)
  exclude:
    - "vendor/"
    - "testdata/"
    - "dist/"
    - "*.test.js"
    - "node_modules/"

  rules:
    # Disable specific rules entirely
    disable:
      - "AI-008"      # Unpinned model refs are acceptable in this project
      - "IAC-002"      # We use floating base image tags intentionally

    # Override severity for specific rules
    severity_override:
      SEC-005: low     # Downgrade generic API key detection
      IAC-003: info    # ADD vs COPY is informational here

# Default output settings (CLI flags override these)
output:
  format: json         # json, sarif, cdx, spdx, all
  directory: .          # Output directory

# Policy settings for CI pass/fail behavior
policy:
  fail_on: high          # Only fail on high+ severity
  warn_on: medium        # Warn on medium findings
  baseline_mode: warn    # warn | strict | off
  baseline_path: ""      # Default: .nox/baseline.json

# Default explain settings (CLI flags override these)
explain:
  api_key_env: OPENAI_API_KEY   # Env var name to read API key from
  model: gpt-4o                 # LLM model name
  base_url: ""                  # Custom OpenAI-compatible endpoint
  timeout: 2m                   # Per-request timeout
  batch_size: 10                # Findings per LLM request
  output: explanations.json     # Output file path
  enrich: ""                    # Comma-separated enrichment tools
  plugin_dir: ""                # Plugin binary directory
```

If `.nox.yaml` does not exist, nox runs with default settings (no exclusions, all rules enabled, JSON output).

### Exclude Patterns

Exclude patterns follow gitignore syntax:

| Pattern | Effect |
|---------|--------|
| `vendor/` | Exclude the `vendor` directory and all contents |
| `*.test.js` | Exclude all `.test.js` files anywhere |
| `dist/` | Exclude the `dist` directory |
| `testdata/` | Exclude test data directories |

Exclude patterns from `.nox.yaml` are combined with `.gitignore` patterns. Both are applied during file discovery.

### Rule Overrides

**Disabling rules:** Add rule IDs to `scan.rules.disable`. Disabled rules produce no findings.

**Severity overrides:** Map rule IDs to new severity levels in `scan.rules.severity_override`. Valid severities: `critical`, `high`, `medium`, `low`, `info`.

### Output Defaults

The `output` section sets defaults for `--format` and `--output` flags. CLI flags always take precedence:

```bash
# Uses config defaults (e.g., format: sarif, directory: reports)
nox scan .

# CLI flags override config
nox scan . --format json --output ./custom-dir
```

### Policy Settings

The `policy` section controls CI pass/fail behavior:

```yaml
policy:
  fail_on: high          # Only fail on high+ severity findings
  warn_on: medium        # Warn on medium severity findings
  baseline_mode: warn    # How baselined findings affect results
  baseline_path: ""      # Custom baseline file path (default: .nox/baseline.json)
```

**`fail_on`** — Minimum severity to cause a non-zero exit code. Findings below this threshold do not cause failure. Valid values: `critical`, `high`, `medium`, `low`, `info`. When not set, any finding causes failure.

**`warn_on`** — Minimum severity to produce a warning (printed but does not affect exit code).

**`baseline_mode`** — Controls how baselined findings are handled:

| Mode | Behavior |
|------|----------|
| `warn` | Baselined findings produce warnings but do not count toward failure |
| `strict` | Baselined findings count toward failure (same as new findings) |
| `off` | Baseline not applied |

**Examples:**

```yaml
# Gradual adoption: only fail on critical, warn on everything else
policy:
  fail_on: critical
  warn_on: low
  baseline_mode: warn

# Strict mode: all findings must be addressed
policy:
  fail_on: info
  baseline_mode: strict
```

### Explain Defaults

The `explain` section configures defaults for `nox explain`. CLI flags always take precedence.

| Field | Default | Description |
|-------|---------|-------------|
| `api_key_env` | `OPENAI_API_KEY` | Environment variable name to read the API key from |
| `model` | `gpt-4o` | LLM model name |
| `base_url` | (empty) | Custom OpenAI-compatible API endpoint |
| `timeout` | `2m` | Per-request timeout |
| `batch_size` | `10` | Findings per LLM request |
| `output` | `explanations.json` | Output file path |
| `enrich` | (empty) | Comma-separated plugin enrichment tools |
| `plugin_dir` | (empty) | Directory containing plugin binaries |

Use `api_key_env` to configure a different provider without changing code:

```yaml
# Use Anthropic instead of OpenAI
explain:
  api_key_env: ANTHROPIC_API_KEY
  model: claude-sonnet-4-5-20250929
  base_url: https://api.anthropic.com/v1

# Use a local Ollama instance (no API key needed)
explain:
  base_url: http://localhost:11434/v1
  model: llama3
  timeout: 5m
```

The API key itself is **never** stored in `.nox.yaml` — only the name of the environment variable. This prevents accidental commits of secrets.

---

## Inline Suppressions

Suppress specific findings directly in source code using `nox:ignore` comments. This works with any comment style:

```go
// nox:ignore SEC-001 -- false positive in test data
var testKey = "AKIAIOSFODNN7EXAMPLE"
```

```python
# nox:ignore SEC-005
api_key = os.environ["API_KEY"]
```

```sql
-- nox:ignore SEC-003 -- test credentials
INSERT INTO users (token) VALUES ('test-token');
```

```html
<!-- nox:ignore AI-001 -->
<div>{{ user_input }}</div>
```

```css
/* nox:ignore IAC-001 */
```

**Syntax:** `<comment-marker> nox:ignore <RULE-ID>[,RULE-ID...] [-- reason] [expires:YYYY-MM-DD]`

**Features:**

| Feature | Syntax | Example |
|---------|--------|---------|
| Single rule | `nox:ignore SEC-001` | Suppress one rule |
| Multiple rules | `nox:ignore SEC-001,SEC-002` | Suppress multiple rules |
| With reason | `nox:ignore SEC-001 -- false positive` | Document why |
| With expiration | `nox:ignore SEC-001 -- expires:2026-06-01` | Auto-expire |
| Trailing comment | `var x = 1 // nox:ignore SEC-001` | Suppress on same line |
| Dedicated comment | `// nox:ignore SEC-001` (line above) | Suppress next line |

**Supported comment styles:** `//` (Go, JS, Java, C, Rust), `#` (Python, Ruby, Shell, YAML), `--` (SQL, Lua), `/*` (CSS, C), `<!--` (HTML, XML).

Suppressed findings are marked with `status: "suppressed"` in the output and do not count toward policy failure.

---

## Output Formats

### findings.json

Nox's canonical findings format. Contains all findings with fingerprints, severity, confidence, location, and metadata.

```json
{
  "meta": {
    "schema_version": "1.0.0",
    "generated_at": "2026-02-09T12:00:00Z",
    "tool_name": "nox",
    "tool_version": "0.1.0"
  },
  "findings": [
    {
      "ID": "SEC-001:config.env:5",
      "RuleID": "SEC-001",
      "Severity": "high",
      "Confidence": "high",
      "Location": {
        "FilePath": "config.env",
        "StartLine": 5,
        "EndLine": 5,
        "StartColumn": 10,
        "EndColumn": 30
      },
      "Message": "AWS Access Key ID detected",
      "Fingerprint": "a1b2c3...",
      "Metadata": {
        "cwe": "CWE-798"
      }
    }
  ]
}
```

### results.sarif

SARIF 2.1.0 format, compatible with GitHub Code Scanning. Upload directly:

```bash
nox scan . --format sarif
# Then upload results.sarif to GitHub Code Scanning
```

### SBOM

Software Bill of Materials in two formats:

- **`sbom.cdx.json`** — CycloneDX JSON (primary)
- **`sbom.spdx.json`** — SPDX JSON (secondary)

Generated from dependency lockfile analysis. Supported ecosystems:

| Lockfile | Ecosystem |
|----------|-----------|
| `go.sum` | Go |
| `package-lock.json` | npm |
| `requirements.txt` | PyPI |
| `Gemfile.lock` | RubyGems |
| `Cargo.lock` | Cargo |
| `pom.xml` | Maven |
| `build.gradle`, `build.gradle.kts` | Gradle |
| `packages.lock.json` | NuGet |

### AI Inventory

`ai.inventory.json` is automatically generated when AI components are detected. It catalogs:

- MCP server configurations (`mcp.json`)
- Prompt files (`.prompt`, `.prompt.md`)
- Components in `/prompts/` and `/agents/` directories

```json
{
  "schema_version": "1.0.0",
  "components": [
    {
      "name": "mcp.json",
      "type": "mcp_config",
      "path": ".claude/mcp.json",
      "details": {"server": "my-server"}
    },
    {
      "name": "system.prompt",
      "type": "prompt",
      "path": "prompts/system.prompt",
      "details": {}
    }
  ]
}
```

---

## CI/CD Integration

### GitHub Actions

#### Using the Nox Action (recommended)

The `nox-hq/nox` action downloads a pre-built binary (no Go required) and runs the scan in a single step:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  nox:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Nox security scan
        uses: nox-hq/nox@v1
        with:
          path: '.'
          format: sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: nox-results/results.sarif
```

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `format` | `sarif` | Output format(s): `json`, `sarif`, `cdx`, `spdx`, `all` |
| `output` | `nox-results` | Output directory for reports |
| `version` | `latest` | Nox version to install (e.g., `0.1.0` or `latest`) |
| `fail-on-findings` | `true` | Fail the step if findings are detected |
| `annotate` | `true` | Post inline PR annotations for findings |

**Action outputs:**

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings detected |
| `sarif-file` | Path to `results.sarif` (if generated) |
| `findings-file` | Path to `findings.json` (if generated) |
| `exit-code` | Raw nox exit code (`0`/`1`/`2`) |

**Generate all formats and upload as artifact:**

```yaml
      - name: Run Nox security scan
        uses: nox-hq/nox@v1
        with:
          format: all
          output: reports

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/results.sarif

      - name: Upload reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nox-reports
          path: reports/
```

**Allow findings without failing the workflow:**

```yaml
      - name: Run Nox security scan
        uses: nox-hq/nox@v1
        with:
          fail-on-findings: 'false'
```

#### Manual setup

If you need full control, install nox manually:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  nox:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install nox
        run: go install github.com/nox-hq/nox/cli@latest

      - name: Run security scan
        run: nox scan . --format sarif,json --output results/

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results/results.sarif

      - name: Upload findings artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nox-findings
          path: results/
```

**Fail on findings** (gate PRs):

```yaml
      - name: Run security scan
        run: nox scan . -q
        # Exit code 1 = findings detected, fails the step
```

### GitLab CI

```yaml
nox-scan:
  image: golang:1.25
  script:
    - go install github.com/nox-hq/nox/cli@latest
    - nox scan . --format sarif,json --output results/
  artifacts:
    paths:
      - results/
    reports:
      sast: results/results.sarif
```

### Generic CI

```bash
# Install
go install github.com/nox-hq/nox/cli@latest

# Scan (exit code 1 if findings detected)
nox scan . --format all --output results/ -q

# Check exit code
if [ $? -eq 1 ]; then
  echo "Security findings detected"
  exit 1
fi
```

---

## MCP Server

The MCP server allows AI agents to invoke nox safely over stdio.

```bash
nox serve --allowed-paths /path/to/project
```

### Tools

| Tool | Description | Input |
|------|-------------|-------|
| `scan` | Scan a directory | `path` (absolute path, must be in allowed-paths) |
| `get_findings` | Get findings from last scan | `format` (`json` or `sarif`, default: `json`) |
| `get_sbom` | Get SBOM from last scan | `format` (`cdx` or `spdx`, default: `cdx`) |
| `get_finding_detail` | Get enriched detail for a finding | `finding_id` (required), `context_lines` (default: 5) |
| `list_findings` | List findings with filters | `severity`, `rule`, `file`, `limit` (default: 50) |
| `baseline_status` | Show baseline statistics | `path` (absolute path to project root) |
| `baseline_add` | Add a finding to the baseline | `path`, `fingerprint` (required), `reason` |
| `plugin.list` | List registered plugins | (none) |
| `plugin.call_tool` | Invoke a plugin tool | `tool`, `input` (object), `workspace_root` |
| `plugin.read_resource` | Read a plugin resource | `plugin`, `uri` |

All tools are **read-only**. Output is truncated at **1 MB**.

### Resources

| URI | MIME Type | Description |
|-----|-----------|-------------|
| `nox://findings` | `application/json` | Findings in JSON format |
| `nox://sarif` | `application/json` | SARIF 2.1.0 |
| `nox://sbom/cdx` | `application/json` | CycloneDX SBOM |
| `nox://sbom/spdx` | `application/json` | SPDX SBOM |
| `nox://ai-inventory` | `application/json` | AI component inventory |

### Claude Desktop

Add nox to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "nox": {
      "command": "nox",
      "args": ["serve", "--allowed-paths", "/path/to/your/project"]
    }
  }
}
```

---

## Plugin Management

### Registries

Plugins are distributed through registries — JSON indexes served over HTTPS.

```bash
# Add the official registry
nox registry add https://registry.nox.dev/index.json

# Add a custom registry
nox registry add https://internal.example.com/nox/index.json --name internal

# List registries
nox registry list

# Remove a registry
nox registry remove internal
```

### Installing Plugins

```bash
# Install latest version
nox plugin install nox/sast

# Install specific version
nox plugin install nox/sast@1.2.0

# List installed plugins
nox plugin list

# Update all plugins
nox plugin update

# Update one plugin
nox plugin update nox/sast

# Remove a plugin
nox plugin remove nox/sast
```

### Invoking Plugin Tools

```bash
# Call a plugin tool with key=value arguments
nox plugin call nox/sast scan workspace_root=/path/to/project

# Call with JSON input file
nox plugin call nox/sast scan --input config.json
```

### Scaffolding a Plugin

```bash
nox plugin init --name my-scanner --track core-analysis
```

This generates a complete plugin project:

```
nox-plugin-my-scanner/
  main.go              # Plugin server with example tool
  main_test.go         # Conformance test
  go.mod               # Go module
  Makefile             # Build and test targets
  Dockerfile           # Container build
  README.md            # Documentation
  .github/workflows/
    ci.yml             # CI workflow
    release.yml        # Release workflow
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | (required) | Plugin name (alphanumeric + hyphens) |
| `--track` | (required) | Security track (e.g., `core-analysis`, `ai-security`) |
| `--risk-class` | `passive` | Risk class: `passive`, `active`, or `runtime` |
| `--output` | `.` | Output directory |

See [`docs/plugin-authoring.md`](plugin-authoring.md) for the full SDK guide and [`docs/track-catalog.md`](track-catalog.md) for track descriptions.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings (or policy pass) |
| `1` | Scan completed, findings detected (or policy fail) |
| `2` | Error (invalid arguments, scan failure, config error) |

When policy is configured via `.nox.yaml`, the exit code reflects the policy evaluation result rather than raw finding count. Findings below the `fail_on` threshold do not cause exit code 1.

Use exit codes in CI to gate deployments:

```bash
nox scan . -q || exit 1
```
