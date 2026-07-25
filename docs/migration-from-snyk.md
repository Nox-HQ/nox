# Migrating from Snyk to Nox

Nox is an open-source, language-agnostic security scanner with
first-class AI application security. This guide maps Snyk capabilities
to their nox equivalents so a Snyk team can switch without losing
coverage.

## Capability map

| Snyk capability | Nox equivalent | Notes |
|---|---|---|
| `snyk test` (deps) | `nox scan` (VULN-001..003) | OSV-backed; offline cache; same JSON shape goal |
| `snyk monitor` | `nox scan --output dir/` + commit findings.json | Nox is CI-driven; no SaaS state |
| Reachability analysis | `nox-plugin-reachability` (one `nox plugin install`) | Go, PyPI, npm, Cargo, Maven, RubyGems, NuGet — all 7 covered |
| Snyk fix / pull requests | `nox fix --input findings.json` | Go ecosystem today; npm/pypi/cargo on roadmap |
| `snyk ignore` policy file | `vex.json` (OpenVEX) | Standard format; `nox vex init` bootstraps |
| Snyk Code (SAST) | core SEC + `nox-plugin-sast` | Secrets in core, code-injection in plugin |
| Snyk IaC | core IAC-001..369 | Terraform, K8s, Dockerfile, GHA, Ansible, Kustomize, serverless |
| Snyk container | core CONT-* + `nox-plugin-container` | Pin / tag enforcement in core; image-layer scan in plugin |
| Snyk AI / `--ai-assist` | core AI-* (50 rules) + AI-PI / AI-EMBED / AI-AGENT / MCP families | OWASP LLM Top 10 baseline shipped |
| GitHub PR integration | `nox-hq/nox@v1` Action | SARIF upload, PR review comments, severity threshold |
| Snyk severity threshold | `--severity-threshold high` | Same semantics |
| Snyk org-level policy | core `.nox.yaml` + `nox-plugin-policy-gate` | Per-repo + org-policy split |

## What you gain leaving Snyk

- **OWASP LLM Top 10** detection — prompt injection (LLM01),
  embedding leakage (LLM06), agent lattice / insecure plugin (LLM07),
  MCP server hardening. No commercial scanner ships these as a
  cohesive family today.
- **Polyglot AIBOM** — single `ai.inventory.json` covering model
  invocations across Python, JavaScript/TypeScript, Go, Java, Rust,
  C# with auth env var and endpoint capture per call site.
- **No rate limits, no seat licences, no SaaS** — `nox` is a binary;
  scans run entirely offline (with optional OSV lookups gated behind
  `--no-osv`).
- **Deterministic + diff-friendly outputs** — same input, same
  fingerprints; baseline / diff / VEX flow is git-native.
- **Multi-language reachability** — one `nox plugin install`, no separate
  install. Snyk's reachability is a paid tier and per-language.

## What you give up

- **No SaaS dashboard / fleet view** — by design. Use `nox dashboard`
  to generate a static HTML view, commit it, or roll up
  per-repository findings.json files into your own data warehouse.
- **No managed vulnerability database** — Nox uses OSV. If you have
  Snyk-private CVE data, you'd need to author a custom rule pack.
- **Younger ecosystem** — fewer integrations than Snyk's enterprise
  product (Jira, ServiceNow, etc.). Build via the MCP server or
  consume `findings.json`.
- **No automated PR creation for fixes** — `nox fix` is local-only
  today. Wire to a Renovate / Dependabot pipeline if you want PRs.

## 30-minute migration

```bash
# 1. Install nox.
brew install felixgeelhaar/tap/nox    # or: download release archive

# 2. Run a baseline scan.
nox scan . --output nox-out

# 3. Bootstrap a VEX document from current findings (replaces snyk.policy).
nox vex init --input nox-out/findings.json --output vex.json

# 4. Edit vex.json — set status=not_affected for reviewed findings;
#    leave under_investigation for the rest.
$EDITOR vex.json

# 5. Wire CI (replaces snyk-monitor / snyk-test).
cp examples/ci-baseline/.github/workflows/security.yml .github/workflows/

# 6. Install the pre-commit hook so regressions never reach CI.
nox install-hook

# 7. Verify.
nox doctor
nox scan . --vex vex.json
```

## See also

- `examples/ci-baseline/` — a working GitHub Actions workflow with VEX,
  changed-since diff scoping, and Code Scanning upload.
- `examples/ai-app/` — Python LLM app demonstrating OWASP LLM Top 10
  detection.
- `examples/multi-stack/` — Go API + TypeScript frontend
  demonstrating polyglot AIBOM.
