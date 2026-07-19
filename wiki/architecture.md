---
updated: 2026-07-19
tags: [architecture]
---

# nox architecture notes

## Dependency analysis (`core/analyzers/deps`)

`discovery.Classify` tags files by `ArtifactType`; `Lockfile` artifacts are routed
to the deps analyzer. `supportedLockfiles` maps a basename to a parser.

**Go is deliberately keyed on `go.mod`, not `go.sum`.** `go.sum` is a hash
manifest for the *entire module graph* — it records every version the resolver
considered, including ones Minimal Version Selection rejected. Scanning it reports
vulnerabilities against code that never compiles. `go.sum` remains classified as a
Lockfile so it stays out of the content rule families, but it is no longer a
version source. `resolveGoPackages` combines both:

- `go.mod` is authoritative for the modules it names (MVS-selected versions), with
  `replace` applied and local filesystem replacements dropped;
- `go.sum` supplies only modules that Go 1.17+ graph pruning omitted, at their
  highest recorded version (MVS picks the maximum required), and only for entries
  with a **source hash** — a `/go.mod`-only entry means the code was never
  downloaded.

## OSV lookups (`core/analyzers/deps/osv.go`)

Two calls, both required:

1. `POST /v1/querybatch` — matches packages to advisory IDs. **Returns only
   `{id, modified}`.**
2. `GET /v1/vulns/{id}` — the advisory body: severity, summary, aliases,
   affected ranges, and `ecosystem_specific.imports`.

Skipping (2) silently defaults every finding to `SeverityMedium` with an empty
summary and no remediation. Hydration is deduplicated by ID, bounded at
`osvHydrateConcurrency`, and fail-open.

**Results are hydrated in place, per package.** Flattening the results map and
rebuilding it misattributes advisories, because Go map iteration order is
randomised.

Severity comes from `cvssToSeverity`, which computes CVSS v3.x base scores from
vector strings (`cvss.go`, spec §8.1). OSV publishes vectors, not numbers.

## Reachability (`core/analyzers/deps/reachability.go`)

OSV scopes Go advisories to import paths. `goImportedPackages` enumerates the
linked set with `go list -deps` (60s bound, `-mod=readonly`, never mutates the
module under scan) and `goVulnReachable` intersects. Deliberately uses the
toolchain rather than parsing the repo's own imports: a vulnerable package is
often reached *through* a dependency, and missing that would silently hide real
vulnerabilities.

Unreachable findings are **demoted to `info`** with `reachable=false` and
`affected_imports`, never dropped. `undetermined` (advisory has no import
metadata, or the build cannot be enumerated) leaves the finding untouched.

Gotcha: `go list -e` outside a module echoes the unresolved pattern (`./...`) and
exits 0 — filtered, or "unknown" becomes a false "not linked".

## Release

relicta-driven (`.relicta.yaml`, state in `.relicta/releases/`):
`plan → bump → notes → approve → publish`. `publish` creates the `v*` tag; that
tag triggers `.github/workflows/release.yml` (goreleaser, cosign signing, ghcr).
`relicta plan` pins `head_sha`, so committing a changelog after planning requires
a re-plan. Convention: the release tag points at the `docs(changelog): X.Y.Z`
commit, and main uses squash merges with a `(#NNN)` suffix.

## Consumers

The fleet consumes nox through `klarlabs-studio/.github`'s reusable
`go-ci.yml`, which pins `nox-version` + `nox-sha256` (sha256-verified install).
Bumping that pin moves every consuming repo at once.
