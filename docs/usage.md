# Nox Usage Guide

Complete reference for the Nox CLI, configuration, and integrations.

## Table of Contents

- [Commands](#commands)
  - [scan](#scan)
  - [explain](#explain)
  - [serve](#serve)
  - [registry](#registry)
  - [plugin](#plugin)
- [Configuration](#configuration)
  - [.nox.yaml](#noxyaml)
  - [Exclude Patterns](#exclude-patterns)
  - [Rule Overrides](#rule-overrides)
  - [Output Defaults](#output-defaults)
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
8. Writes reports in the requested formats

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

Upload SARIF results to GitHub Code Scanning:

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
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings detected |
| `2` | Error (invalid arguments, scan failure, config error) |

Use exit codes in CI to gate deployments:

```bash
nox scan . -q || exit 1
```
