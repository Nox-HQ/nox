---
updated: 2026-07-19
---
## Now
- Fix relicta release tooling (`notes` silent failure, `approve` 0.0.0 display).

## Next
- Decide on CVSS v4 vector support.
- Revisit whether reachability should be opt-in / configurable.

## Later
- Better source for Go advisory import-path scoping (11/19 findings currently
  undetermined due to missing OSV `ecosystem_specific.imports`).

## Done
- v1.10.0 (2026-07-19) — Go dependency scanning fixed end to end: go.mod version
  resolution, OSV advisory detail hydration, CVSS v3.1 base scores from vectors,
  and import-path reachability scoping (#248).
