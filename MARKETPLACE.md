# Nox Security Scanner — GitHub Marketplace listing copy

Paste these blocks into the marketplace listing form when publishing a
release from its release page (Edit release → "Publish this Action to the
GitHub Marketplace" → fill the form). Nothing here names a release number
except the Action pin in the example workflow, which `cli/docs_pins_test.go`
keeps on the release nox runs itself.

---

## Tagline (≤ 90 characters)

```
The security scanner that understands your AI app — open-source, deterministic, no SaaS.
```

## Primary category

`Security`

## Secondary category

`Code review`

## Description (~300 words)

Nox is an open-source security scanner for teams shipping LLM features. It
checks what AI applications add — prompt injection at the call site, secrets
reaching vector stores, over-privileged agent tools, MCP server hardening,
cross-file AI taint — alongside secrets, infrastructure as code, containers
and dependency vulnerabilities. More than 1,500 rules, one binary,
deterministic output.

**This Action** wraps `nox scan` for GitHub:

- Writes SARIF 2.1.0 for GitHub Code Scanning (upload it with
  `github/codeql-action/upload-sarif`)
- Annotates the pull request with findings, and optionally posts one summary
  comment
- Fails the job on a severity threshold you choose; honours OpenVEX
  statements and the baseline
- Scans only what changed with `changed-since`, for fast pull request feedback
- `offline: true` makes the scan's zero-network guarantee explicit

**What sets Nox apart:**

- **AI-native rule families.** Prompt injection, embedding leakage,
  agent over-privilege, MCP hardening and cross-file AI taint, mapped to the
  OWASP LLM, MCP and Agentic Top 10 lists.
- **Your code stays on the runner.** Online, a scan sends only the
  dependency list (ecosystem, package, version) to its advisory source,
  verified against OSV.dev; every other request prints a `[network]` line
  saying where it went and how to turn it off. `offline: true` makes none.
- **Signed plugins.** Official plugins verify through Sigstore keyless
  signing; the default trust policy refuses unsigned
  third-party plugins.
- **AI inventory.** One document naming every model invocation, auth
  environment variable and endpoint across Python, Go, TypeScript, Java,
  Rust and C#.
- **MCP-native.** A built-in MCP server lets coding agents query scan
  results.

Apache 2.0. One pass for secrets, AI, IaC, containers and dependencies, with
SARIF, CycloneDX and SPDX output.

## Inputs (filled automatically from action.yml)

The marketplace UI renders inputs from `action.yml`. Check the defaults read
sensibly: `path: .`, `format: sarif`, `output: nox-results`,
`annotate: true`, `fail-on-findings: true`.

## Featured icon and colour

Already declared in `action.yml`:

```yaml
branding:
  icon: 'shield'
  color: 'purple'
```

## Example workflow (paste into the listing's "Usage" section)

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  nox:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: nox-hq/nox@7ad45c0ab5057b1533087cb1c5054848974f08b2 # v1.65.0
        with:
          path: '.'
          format: sarif
          severity-threshold: high
          annotate: 'true'
          changed-since: ${{ github.base_ref && format('origin/{0}', github.base_ref) || '' }}
      - uses: github/codeql-action/upload-sarif@1c5b675653bb5c22dbe9b12b556ec555138e09fd # v4.38.1
        if: always()
        with:
          sarif_file: nox-results/results.sarif
```

## Tags / keywords

```
security, sast, sca, iac, ai-security, llm, mcp, prompt-injection,
sbom, sarif, cosign, sigstore, supply-chain, owasp-llm, aibom
```

## Pre-listing checklist

- [ ] The release's own workflow run is green, and its checksums and cosign
  signature verify
- [ ] The example workflow above pins that release (`go test ./cli -run
  TestDocumentedActionPinIsTheReleaseNoxRunsItself` passes)
- [ ] The release notes say the Action is listed on the Marketplace

After publishing the listing, edit the README hero block to add a
"Available on the GitHub Marketplace" badge:

```markdown
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Nox%20Security%20Scanner-purple?logo=github)](https://github.com/marketplace/actions/nox-security-scanner)
```
