# Reachability suite — the corpus behind Gate B

Gate B is the rule that **deterministic unreachability may suppress a finding,
and nothing else may**.

That sounds obvious and is the easiest thing in the system to get wrong,
because the four states that must not suppress are indistinguishable from the
one that may, at the only place anyone looks — the output. A finding hidden
because reachability proved it unreachable and a finding hidden because
reachability never ran produce the same artifact: no finding, and no reason
given for its absence.

The design doc records this corpus as owed:

> The refutation suite is offline-only by design, so dependency applicability
> and reachability are unrepresented. **Gate B therefore has no corpus yet**,
> and Track G must bring one before deterministic unreachability is allowed to
> suppress anything.

This is that corpus.

## How it stays deterministic offline

Every module here depends only on the **standard library**. Go issues
advisories for stdlib packages, so this is not a contrivance — and it means
`go list` needs no network and no module cache.

That constraint is load-bearing. A corpus needing either would be a corpus that
quietly stopped running in CI, and the first symptom would be that it had
stopped failing.

## The cases

Each directory carries an `expect.json` declaring the advisory's scope, the
expected `(reachable, determined)` pair, and — the field the gate turns on —
whether that conclusion may justify hiding a finding.

| case | `(reachable, determined)` | may suppress |
|---|---|---|
| `reachable` | `(true, true)` | no — it is reachable |
| `unreachable` | `(false, true)` | **yes** — the only one |
| `undetermined_no_import_metadata` | `(true, false)` | no — the advisory scopes to nothing |
| `undetermined_not_a_module` | `(true, false)` | no — the toolchain could not answer |
| `unsupported_ecosystem` | `(true, false)` | no — nox has no analysis for npm |

`may_suppress` is true for exactly one case, and `TestGateB` asserts that by
name rather than by count. A future change that made a second case suppressible
fails with the case named.

## What it found immediately

`undetermined_not_a_module` failed on the corpus's first run, and the reason is
worth keeping.

A directory with Go source and no `go.mod` does **not** make `go list -deps -e
./...` fail. It exits 0 and prints the standard library's dependency closure —
91 packages, none of them the caller's, no error. `goImportedPackages` therefore
returned a large non-empty set with `ok=true`, and every advisory import path
was missing from it, so every Go advisory would have been answered
**deterministically unreachable** for a directory nox never enumerated.

This was **not reachable in production**: the only caller passes a directory
where a `go.mod` was already found. It was reachable from the function's own
documented contract — *"when the toolchain cannot answer, this reports
ok=false"* — which was false as written, and would have become reachable the
first time a second caller believed it.

Fixed by checking for `go.mod` before running the toolchain.

## Rules for changing this corpus

1. **`may_suppress` stays true for exactly one case.** If a change makes a
   second one suppressible, the change is wrong until argued otherwise —
   loudly, in the commit, with the reasoning.
2. **Every case explains itself.** `expect.json` requires a `why`, and the test
   fails without one. A ground truth nobody explained is one nobody can check.
3. **No network, no module cache.** Standard library only.
4. **Add the case before the analysis.** Track G will extend reachability
   beyond Go; each new ecosystem should arrive with its unsupported case turned
   into a determined one, and the unsupported case for whatever comes next.
