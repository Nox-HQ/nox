---
updated: 2026-07-19
---
## [OPEN]

- **[SECURITY — highest priority] `go list` can execute an untrusted
  repository's toolchain.** Introduced by #248's reachability feature.
  `GOTOOLCHAIN` defaults to `auto`, so since Go 1.21 a `toolchain` directive in a
  scanned repo's `go.mod` can make the Go command **download and execute a
  different toolchain** — inside a scanner whose CLAUDE.md promises "never
  executes untrusted code". `reachability.go` sets `GOFLAGS=-mod=readonly` but
  **not `GOTOOLCHAIN=local`**. Fix: set `GOTOOLCHAIN=local`, and consider
  `GOPROXY=off` so reachability degrades to `undetermined` rather than fetching.
  Until then this is the one code path running third-party tooling on untrusted
  input.

- **#248 broke two design constraints stated in CLAUDE.md.** Needs an explicit
  decision: amend the constraints, or gate the feature behind a flag.
  - *"/core — scan engine (no CLI, no network)"* — `core/analyzers/deps` now both
    calls OSV over HTTP (pre-existing) and spawns a subprocess (new).
  - *"Deterministic: same inputs produce same outputs, no hidden state"* —
    reachability depends on toolchain presence and module-cache warmth, so the
    same repo scans differently on different machines. This is the strongest
    argument for making reachability opt-in.

- **`relicta notes` fails silently.** Exit 1, no output, no error message.
  `.relicta.yaml` sets `ai.enabled: true` with `model: gpt-4`; the failure is
  swallowed and there is no `--no-ai` escape (the flag is opt-in `--ai`). The
  v1.10.0 changelog had to be hand-written. Fix the model, or surface the error.

- **`relicta approve` misreports the release** — renders `0.0.0` and `0 commits`
  while the state file holds the correct version (`1.10.0`). A display bug, but on
  the one screen whose purpose is confirming what you are about to publish.

- **#248's commit message mischaracterises `GO-2026-5932`** as a confirmed true
  positive. It is a false positive for consumers not importing
  `x/crypto/openpgp`. The PR body carries an explicit retraction; correcting the
  commit message needs an amend + force-push. Decide whether that is worth it.

- **Import-path scoping has a data ceiling.** 11 of vorhut's 19 Go findings stay
  `undetermined` because those advisories carry no `ecosystem_specific.imports`.
  Is there a better source, or is this simply OSV coverage?

- **CVSS v4 vectors fall back to `medium`.** Only v3.0/v3.1 are computed.

- **Should reachability be opt-in?** It shells out to `go list -deps` (60s
  bounded, `-mod=readonly`), needing the toolchain and ideally a warm module
  cache. Currently automatic, degrading to `undetermined` on any failure.

## [BLOCKED]

## [WAITING]

- **Fleet rollout consequence (informational).** The shared
  `klarlabs-studio/.github` `go-ci.yml` was pinned 1.7.1 → 1.10.0 on 2026-07-19.
  Consuming repos with high/critical dependency vulnerabilities will now fail
  their gate — measured on a 10-repo sample: agent-go 56 gate-failing (42
  critical), senat-os 3, mnemos 2, seven others 0. Those vulnerabilities were
  always present and were being reported as `medium`. Expect issue reports that
  are not nox regressions.
