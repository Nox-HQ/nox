# AGENTS.md — last updated: 2026-07-19
# Keep under 400 lines. Split overflow to memory/ files.
# Project context, architecture and commands live in CLAUDE.md — do not duplicate
# them here. This file carries working style, constraints and failure modes.

## Working Style
Output format: prose with evidence; tables for measured comparisons.
Decision style: recommend directly, show the measurement behind it.
When stuck: measure before proposing — this codebase punishes assumption.
Review mode: critique hard, including my own prior claims.

## Project Context
See CLAUDE.md. In short: language-agnostic security scanner in Go, SARIF/SBOM
output, consumed by humans, CI and agents (MCP). Fleet consumes it via
`klarlabs-studio/.github`'s reusable `go-ci.yml`, which pins version + sha256.

## Constraints
# Testable formulations only.
Never: claim a dependency finding is real from a module@version match alone —
  check `ecosystem_specific.imports` against `go list -deps` first.
Never: use `go list -m all` as ground truth for what is linked; it reports the
  module graph and over-reports. Use `go list -deps`.
Never: drop a security finding silently. Demote it, annotate why, keep it visible.
Never: treat `mergeable: CLEAN` as "CI passed" — verify checks actually ran.
Always: fail open when an enrichment lookup fails (severity, reachability). An
  incomplete finding beats a missing one.
Always: when changing scanner behaviour, measure the blast radius on real repos
  before bumping the shared pin.

## Known Failure Modes
- Tends to trust a written note over a measurement → correct by re-deriving the
  claim before acting on it. The 2026-07-19 session began with a memory note
  saying "excluding go.sum drops enumeration to 0"; it was wrong in both
  directions, and acting on it would have injected ~5,263 false positives across
  28 repos.
- Tends to declare a finding a "true positive" too early → correct by requiring
  package-level evidence, not module-level. `GO-2026-5932` was asserted as a
  confirmed live vuln in a commit message on a module@version match; it is scoped
  to `x/crypto/openpgp` and was a false positive.
- Tends to rebuild collections after concurrent work → correct by mutating in
  place. Flattening a results map and rebuilding it misattributed advisories,
  because Go map iteration order is randomised.
- Tends to stack PRs without checking trigger config → correct by confirming CI
  actually ran. `ci.yml` triggers only on PRs targeting `main`; a stacked PR runs
  nothing and still reports CLEAN.

## Design Tensions To Watch
# Introduced 2026-07-19 (#248) and NOT yet resolved — see memory/open-threads.md
- CLAUDE.md states **"/core — scan engine (no CLI, no network)"**, but
  `core/analyzers/deps` both makes HTTP calls (OSV, pre-existing) and now spawns
  a subprocess (`go list -deps`, new). Core is no longer network- or exec-free.
- CLAUDE.md states **"Deterministic: same inputs produce same outputs"**.
  Reachability depends on toolchain presence and module-cache state, so the same
  repository yields `reachable=false` on one machine and `undetermined` on
  another.
- CLAUDE.md states **"never executes untrusted code"**. `go list` against an
  untrusted repository can honour a `toolchain` directive in its `go.mod` and
  download+execute a different Go toolchain. **`GOTOOLCHAIN=local` is not yet
  set.** This is the sharpest of the three.

## Decision Summary
# Full log in memory/decisions.md
- 2026-07-19: Go dependency versions come from `go.mod`, never `go.sum` — the
  latter hashes the whole module graph (~99% FP).
- 2026-07-19: OSV advisory detail must be fetched per ID; `querybatch` returns
  only `{id, modified}`, which had defaulted every finding to medium.
- 2026-07-19: CVSS base scores are computed from vector strings (v3.1 §8.1).
- 2026-07-19: Unreachable findings are demoted to `info`, never dropped.

## Active Patterns
- "brief me" → /brief (reads ./memory/status.md)
- "capture" → /capture (writes session log, updates status)
- "/mem-compact" → digest sessions older than 30 days
