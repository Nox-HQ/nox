# Dependency reachability for Python and JavaScript

Status: proposal, not built. Decided 2026-09-27: design first, no code yet.

## What exists

Every `VULN-001` finding carries an applicability verdict
(`core/applicability`): how far up the ladder the argument got —
`present` → `affected_version` → `symbol_used` → `call_reachable` →
`attacker_reachable` — and why it stopped. Only `not_impacting` may
de-emphasise a finding, and only when an analysis **established** the negative.
"We did not find it" is `undetermined`, never a clearance.

- **Go** climbs and refutes. `go list -deps` gives the build's complete import
  closure, so "the affected package is not linked" is a fact about the build
  (`symbol_used` refuted → `not_impacting`), and the syntactic call graph can
  establish `call_reachable`. On agent-go, 51 of 80 advisories are
  `not_impacting`.
- **Python and JavaScript** only climb. `importApplicability`
  (`core/analyzers/deps/reachability.go`) records `symbol_used` when
  first-party source imports the package by name, and never refutes, because
  a vulnerable package is usually reached through another dependency and a
  missing direct import proves nothing.

Measured on the 2026-09-27 benchmark (v1.42.0 + #728):

| repository | advisories | `symbol_used` (direct import) | stopped at `affected_version` |
|---|---:|---:|---:|
| llama_index | 1,333 | 914 | 419 |
| vercel/ai (npm + pypi) | 270 | 67 | 203 |
| anthropic-sdk-python | 128 | 68 | 60 |
| crewAI | 18 | 11 | 7 |

None of them is ever `not_impacting`. That is correct today, and it is also
why a Python or JavaScript team gets no triage help from the ladder.

## What a refutation would need

A Python or JavaScript `not_impacting` has to rest on something as complete as
`go list -deps`. Three candidate facts, strongest first:

1. **Dev-only in the lockfile.** `package-lock.json` marks `"dev": true`
   (and `devOptional`), pnpm and yarn record dependency types, and `uv.lock`
   records dependency groups. A package reachable only through dev
   dependencies is not installed by `npm ci --omit=dev` or
   `uv sync --no-dev`, so it is not in the shipped runtime. This is a fact
   about the install, not a guess about imports, and it is the closest
   analogue of Go's "not linked".
   *Refutes:* `symbol_used`, with the reason "installed only as a development
   dependency". *Does not cover:* a project that ships its dev environment
   (tests run in production images, notebooks), so the verdict must name the
   assumption, and a `.nox.yaml` switch must turn it off.
2. **Not in the runtime closure of what the code imports.** The lockfile
   records declared dependency edges. If the vulnerable package is not
   imported by first-party code AND is not reachable in the lock graph from any
   package that first-party code imports, then no ordinary import loads it.
   *Weaker than (1):* dynamic imports (`importlib`, `require(variable)`),
   plugin entry points, and packages loaded by a framework from configuration
   all bypass it. So this can refute only where nox can also show there is no
   dynamic loading in first-party code, and otherwise stays `undetermined`.
   That is the Go call-graph rule applied one rung down.
3. **Function-level (`call_reachable`).** OSV records for PyPI and npm rarely
   name affected functions (Go's `ecosystem_specific.imports` has no common
   equivalent), so there is usually nothing to look for. Out of scope until
   the advisory data exists. The taint engine's call graph is the vehicle when
   it does.

## What it must never do

- Refute from absence. A package that first-party code does not import
  directly is NOT unused (see `importApplicability`). Only (1) and (2), which
  are closure facts, may refute.
- Turn "could not analyse" into a negative. An unparsable lockfile, a missing
  dependency-type field, or dynamic loading in first-party code leaves the
  verdict `undetermined`, with the reason.
- Hide the finding. `not_impacting` de-emphasises (demotes out of gating
  severity, like Go's unlinked advisories); the finding stays in the report
  with its verdict.

## Measured: how much would the dev-only fact refute? (step 1)

On the seven benchmark repositories (v1.42.0 + #728 findings), 801 advisories
stop at `affected_version`. Go's 80 are out of scope: Go has the call graph.
Of the PyPI and npm ones, those in `uv.lock` and `pnpm-lock.yaml` can be
checked against the lockfile's own dependency types
([`devonly.py`](../benchmarks/2026-09-27-head-to-head/scripts/devonly.py)):
the runtime closure is everything reachable from the project's runtime and
optional dependencies, and a package outside it is dev-only.

| lockfile | advisories | dev-only | runtime | unknown |
|---|---:|---:|---:|---:|
| `uv.lock` | 459 | 99 | 360 | 0 |
| `pnpm-lock.yaml` | 160 | 5 | 131 | 24 |
| **total** | **619** | **104 (17%)** | 491 | 24 |

Not measured: 100 in `requirements.txt` files, which record no dependency
type, and 2 in `poetry.lock`.

The dev-only ones are what a reader would expect: `jupyterlab` (51) and
`notebook` (18) pulled in through a `dev` group's `jupyter`, `black`, and
`datamodel-code-generator` (22) in the MCP SDK's dev tooling. Checked by hand
on llama_index's lilac reader: `jupyterlab` reaches that lockfile only through
`[package.dev-dependencies] dev = [..., "jupyter", ...]`. Every `uv.lock`
advisory sits in a lockfile with a detectable project root, so no lockfile was
read as "all dev" for lack of one. The 24 pnpm unknowns are packages whose
snapshot key the script's name parser does not resolve (peer-dependency
suffixes); they were left unknown, never counted as dev-only.

So the dev-only fact would resolve about one in six of the advisories the
ladder cannot resolve today, in the two lockfile formats that record it. That
is past the "a handful" bar step 1 set, so step 2 is worth building, with the
assumption named in the verdict and the switch to turn it off.

## Plan

1. **Measure first.** On the seven benchmark repositories, count how many of
   the 689 advisories stopped at `affected_version` are dev-only per their
   lockfiles, and read a sample. If it's a handful, (1) isn't worth its
   assumption; if it's hundreds, it's the single biggest triage win available
   for these ecosystems.
2. **Build (1)** for `package-lock.json` (v2/v3), pnpm, yarn and `uv.lock`,
   with the assumption in the verdict and a `.nox.yaml` switch to disable it.
   Tests: a dev-only package refutes; a package that is both dev and runtime
   (hoisted, or reached both ways) does not; a lockfile without type data
   stays undetermined.
3. **Consider (2)** only after (1) has run on real repositories, with a
   dynamic-import detector that fails closed.
4. **rule-diff** covers it like any other change: the ledger explains every
   finding whose severity drops.

Every step keeps the existing invariant: `not_impacting` requires an analysis
that ran and established the negative.
