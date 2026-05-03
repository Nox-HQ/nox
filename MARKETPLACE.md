# Nox Security Scanner — GitHub Marketplace listing copy

Paste these blocks into the marketplace listing form when publishing
v0.8.1 from the release page (Edit release → "Publish this Action to
the GitHub Marketplace" → fill the form).

---

## Tagline (≤ 90 characters)

```
The security scanner that understands your AI app — open-source, deterministic, no SaaS.
```

## Primary category

`Security`

## Secondary category

`Code review`

## Description (~350 words)

Nox is the open-source security scanner purpose-built for teams shipping
LLM features. It catches what every other scanner misses — prompt
injection at the call site, embedding leakage when secrets reach
vector stores, agent over-privilege, MCP server hardening, cross-file
AI taint — alongside the boring stuff: 160 secret detectors, 369 IaC
rules, dependency CVEs with reachability filtering, and 12 PII
patterns. **717 rules total**, deterministic, offline.

**This Action** wraps `nox scan` with first-class GitHub integration:

- Uploads SARIF 2.1.0 to GitHub Code Scanning
- Posts inline PR review comments on findings
- Honours severity thresholds and OpenVEX waivers
- Differential scan via `--changed-since` for fast PR feedback
- Caches the nox binary install across runs

**What sets Nox apart:**

- **AI-native rule families.** AI-PI (prompt injection), AI-EMB
  (embedding leakage), AI-AGENT (over-privileged agent tools),
  MCP-001..008 (MCP server hardening), TAINT-AI (cross-file AI taint).
  No commercial scanner ships these as a cohesive family today.
- **Cosign-signed plugin marketplace.** 19 official plugins, every
  release verified via Sigstore keyless OIDC. Default trust policy
  fails closed on unsigned drops.
- **Manifest-driven plugins.** Pin plugins in `.nox.yaml` like
  dependencies in `package.json`. Anyone cloning your repo gets the
  same verified scanners on first run.
- **No SaaS. No telemetry. No source upload.** Scans run entirely on
  the runner; OSV vulnerability lookups gated behind a single flag.
- **AIBOM v2.0.** Polyglot AI component inventory across Python, Go,
  TypeScript, Java, Rust, C# — every model invocation, auth env var,
  and endpoint in one document.
- **MCP-native.** Built-in MCP server lets Claude / Cursor / Continue
  query scan results read-only.

Apache 2.0. Single binary. One pass for SAST, SCA, IaC, secrets, AI,
and containers.

Compare vs Snyk, Semgrep, Trivy at https://nox-hq.dev/compare/snyk
and friends.

## Inputs (filled automatically from action.yml)

The marketplace UI auto-renders inputs from `action.yml`. Verify the
defaults read sensibly: `path: .`, `format: sarif`,
`severity-threshold: high`, `annotate: true`.

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
      - uses: actions/checkout@v4
      - uses: nox-hq/nox@v0.8.1
        with:
          path: '.'
          format: sarif
          severity-threshold: high
          annotate: 'true'
          changed-since: ${{ github.base_ref && format('origin/{0}', github.base_ref) || '' }}
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nox-results/results.sarif
```

## Tags / keywords

```
security, sast, sca, iac, ai-security, llm, mcp, prompt-injection,
sbom, sarif, cosign, sigstore, supply-chain, owasp-llm, aibom
```

## Pre-listing checklist

- [ ] All 9 dependabot PRs merged (or at least the security-relevant ones)
- [ ] `vex.json` shipped to waive false-positive code-scanning alerts
  in `core/analyzers/ai/aibom_polyglot.go` and `examples/`
- [ ] `server/server.go` SEC-506 + SEC-574 fixed or VEX-justified
- [ ] Secret scanning enabled on `Nox-HQ/nox` (Settings → Code security
  → Secret scanning → Enable)
- [ ] `v0.8.1` release page reviewed, "Set as latest" checked
- [ ] Release notes mention: GitHub Action listed on Marketplace

After publishing the listing, edit the README hero block to add a
"Available on the GitHub Marketplace" badge:

```markdown
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Nox%20Security%20Scanner-purple?logo=github)](https://github.com/marketplace/actions/nox-security-scanner)
```
