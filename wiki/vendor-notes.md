---
updated: 2026-07-19
tags: [vendors, reference]
---

## OSV.dev

- `POST /v1/querybatch` returns **only** `{id, modified}` per match — no severity,
  summary, aliases or affected ranges. A second `GET /v1/vulns/{id}` is required
  for anything beyond "an advisory matches".
- Severity is published as **CVSS vector strings**, not numeric scores. The base
  score is not embedded but is fully determined by the vector.
- Go advisories carry `affected[].ecosystem_specific.imports` — the specific
  import paths affected. Coverage is partial: roughly 11 of 19 advisories seen in
  practice had none, which caps how much import-path scoping can decide.
- Some advisories have `introduced: 0` with no fixed version — they are
  "this package is unmaintained/unsafe" notices rather than version-fixable CVEs
  (e.g. `GO-2026-5932` for `x/crypto/openpgp`). Treating those as version bumps is
  a mistake.

## Go toolchain

- `go list -m all` reports the **module graph** and over-reports what is linked.
  `go list -deps` reports packages actually imported — use that as ground truth
  for reachability.
- `go list -e` outside a module echoes the pattern (`./...`) and exits 0.
- `go.mod` under Go 1.17+ pruning lists modules providing *imported* packages;
  deeper transitives are linked but unnamed.

## relicta

- `notes` is opt-in AI (`--ai`); there is no `--no-ai`. With `ai.enabled: true` in
  config and an unusable model it exits 1 with no output.
- `approve` is interactive and currently renders `0.0.0` / `0 commits` regardless
  of the stored plan; `--ci` auto-approves non-interactively.
- The MCP server operates on its own working directory — it reported
  `current_version: 2.7.13` for nox (actually 1.9.2). Use the CLI inside the repo.
