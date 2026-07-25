# Metamorphic rule-robustness gate

CI tooling that finds bugs in nox's own detection rules by enforcing a
**metamorphic relation**:

> A *semantics-preserving* edit to a file must not change nox's finding set.
> Any finding that appears or disappears under such an edit is a rule bug — a
> false positive (appeared) or a false negative (disappeared).

This is the same technique that found three nox rule bugs by hand (a blank
line before a Dockerfile `COPY` → false positive; a comment mentioning
`HEALTHCHECK` → false negative). The harness automates and scales it, and runs
as a `pull_request` gate (`.github/workflows/metamorphic.yml`).

## Run it locally

```bash
make build                                        # produces ./nox
python3 scripts/metamorphic/selftest.py --bin ./nox   # positive controls (must pass)
python3 scripts/metamorphic/harness.py --bin ./nox    # the sweep (exit non-zero on any violation)
```

`harness.py` flags: `--bin <nox>` (default repo `./nox`), `--seeds <dir>`
(repeatable; default = precision corpus + committed synthetic seeds),
`--results <dir>` (report + repros; default a temp dir), `--limit N` (first N
seed files, for a quick run).

## What it does (pipeline)

1. **Seed** — walks the real labeled corpus `testdata/precision-suite/`
   (read-only; never written to) plus `scripts/metamorphic/seeds/` (synthetic
   Dockerfiles + GitHub workflows), because the acute known-bug class lives in
   Dockerfile/YAML *absence* rules the corpus does not contain.
2. **Mutate** — applies each semantics-preserving mutation (below), one
   transform at a time, as a list of *atomic edits* over the original lines.
3. **Scan** — runs nox on the original file and on each mutated file, each in an
   isolated one-file temp dir (`--offline`, deterministic). Exit code is ignored
   (nox exits non-zero merely when findings exist); results come from
   `findings.json`.
4. **Diff** — compares finding sets under a line-shift-invariant equivalence
   (below) to get candidate violations.
5. **Adversarial re-verify + minimize** — every candidate is re-run on a freshly
   materialised before/after pair **twice** (also catching nondeterminism); only
   deltas that reproduce survive. Survivors are reduced to a minimal repro with
   delta-debugging (ddmin) over the atomic edit set.
6. **Report** — writes `invariance_report.json` plus, for each survivor, a
   `repros/<id>/` directory with `before/`, `after/`, and `REPRO.md`; **exits
   non-zero** if any survive.

## The equivalence (line-shift vs. real bug)

Getting this right is the whole game: a blank-line insert legitimately shifts
absolute line numbers, and reporting that as a violation would flood the tool
with false alarms — the exact failure mode a security tool must avoid. Matching
ignores absolute line numbers via a **two-layer key**:

- **Layer 1 — nox's own fingerprint.** Fingerprint v2 is line-independent and
  path-normalised, and is empirically identical across every mutation class here
  (line shift, whitespace reflow, CRLF, inert comment insertion). Equal
  fingerprint ⇒ same finding, regardless of line number.
- **Layer 2 — `(RuleID, normalised-anchor)`.** The anchor is the
  whitespace-normalised text of the source line the finding points at, read from
  the file that was actually scanned. Because the anchor text travels with the
  line, it is invariant under line shifts. This layer absorbs *benign*
  fingerprint drift, so a single moved finding is never double-reported as both a
  false positive and a false negative. File-level / absence findings (e.g.
  "missing HEALTHCHECK") fall back to a `<file-level>` anchor keyed by rule.

Whatever is unmatched after both layers is a genuine delta:
`before-only → disappeared (candidate FN)`, `after-only → appeared (candidate
FP)`. Matching is multiset-based, so a change in *count* is also caught. Layer 2
cannot hide the FP/FN classes: an FN removes the finding (no anchor to match on
the after side); an FP adds a finding with a new anchor (nothing to match on the
before side).

## Mutations (all provably semantics-preserving)

| Mutation | Notes |
|---|---|
| `blank_line_top` / `blank_line_bottom` | single blank line |
| `blank_line_before_each` / `after_each` | one per line (minimised by ddmin) |
| `trailing_whitespace` | trailing spaces+tab per line |
| `crlf` | LF → CRLF, per line |
| `pad_before_trailing_comment` | widens the gap before an *existing* inline comment — never touches indentation or tokens, so safe even in indentation-sensitive Python/YAML |
| `keyword_comments` | inserts inert comments mentioning rule keywords (`HEALTHCHECK`, `USER`, `--chown`, `attested`, `eval`, `yaml.load`, `pickle`, ...) at top and after line 1 — the class that caused the real HEALTHCHECK false negative |

**Deliberately excluded:** aggressive intra-token whitespace reflow and
variable renaming. Neither can be *proven* inert generically (reflow can change
Python/YAML indentation semantics; a naive rename can cross scopes and
legitimately change a taint finding). `keyword_comments` uses directive/English
words only — never real secrets, emails, or URLs — so the comment payload is
genuinely inert (a comment containing a real email would make nox correctly
report it, which is not a rule bug).

## Why a green run is trustworthy — positive controls

A "0 violations" from a security tool is worthless unless you can show the tool
would have gone red on a real bug. `selftest.py` proves it (a gate that cannot
go red is worthless), and it runs in CI alongside the sweep:

- **PC1 detection** — deleting the `os.system` sink from `tp_injection.py` is
  reported as `TAINT-002 disappeared`.
- **PC2 line-shift invariance** — prepending 5 blank lines shifts findings but
  yields **zero** violations. This is the core requirement.
- **PC3 verify+minimize** — a real delta survives the adversarial re-verifier and
  ddmin reduces it to the single responsible edit.
- **PC4 synthetic HEALTHCHECK FN** — a hand-faked buggy output (IAC-121 dropped
  after a `# HEALTHCHECK` comment) is correctly flagged as `IAC-121
  disappeared`, demonstrating the harness *would* catch that historical bug were
  it still present.

## Determinism

Seed files are sorted, mutation order is fixed, there is no randomness, and nox
is invoked with `--offline`. Same repo state ⇒ same result. The synthetic seeds
under `seeds/` are intentionally vulnerable (unpinned base images, mutable
action tags, missing HEALTHCHECK/USER) so the absence/presence rules actually
fire; `scripts/` is excluded from the repo self-scan (`.nox.yaml`), so they do
not affect nox's own security grade, while the harness still exercises them in
isolated temp dirs.

## Files

- `harness.py` — the harness (mutations, equivalence, diff, verify, ddmin, report).
- `selftest.py` — positive controls (run to trust a green result).
- `seeds/` — committed synthetic Dockerfiles + GitHub workflows (the acute
  Dockerfile/YAML absence-rule bug class).
