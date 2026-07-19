---
updated: 2026-07-19
note: append-only log — never edit or delete entries; supersede with "→ superseded [date]"
---
- 2026-07-19: Adopted Agent OS memory system — persistent cross-session state via memory/ + wiki/ + cadence skills.

- 2026-07-19: **Go dependency versions come from `go.mod`, never `go.sum`.**
  `go.sum` hashes the entire module graph, so it names versions the build never
  selects — measured at ~99% false positives (148/148 stale on one repo).
  `go.sum` is consulted only for transitives that Go 1.17+ pruning omits from
  `go.mod`, and then only for entries carrying a source hash: a `/go.mod`-only
  entry means the code was never downloaded and cannot be in the build.

- 2026-07-19: **OSV advisory detail is fetched per ID; `/v1/querybatch` is not
  sufficient.** It returns only `{id, modified}`, which had silently defaulted
  every dependency finding to `medium` with an empty summary, no CVE aliases, and
  no fix version — meaning a critical dependency CVE could never trip a
  high/critical gate. Hydration is fail-open: a failed lookup leaves the finding
  intact rather than dropping it.

- 2026-07-19: **CVSS base scores are computed from vector strings** per CVSS v3.1
  §8.1. OSV publishes vectors, not numbers; parsing floats only meant every real
  severity was discarded. v2/v4 vectors keep the conservative `medium` default
  rather than guessing.

- 2026-07-19: **Unreachable dependency findings are demoted to `info`, never
  dropped.** OSV scopes Go advisories to import paths, intersected here with
  `go list -deps`. A silently removed finding is indistinguishable from a scanner
  that missed it, and reachability rests on a toolchain call that can be wrong.
  Conclusions are drawn only from positive evidence: no import metadata, or no
  enumerable build, leaves the finding exactly as it was.

- 2026-07-19: **Reachability uses the Go toolchain, not static import parsing.**
  A vulnerable package is often reached *through* a dependency rather than
  imported directly; static parsing of the repo's own files cannot see that, and
  erring in that direction silently hides real vulnerabilities.
