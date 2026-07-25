# Metamorphic rule-robustness tooling

CI tooling that finds bugs in nox's own detection rules by enforcing a
**metamorphic relation**:

> A *semantics-preserving* edit to a file must not change nox's finding set.
> Any finding that appears or disappears under such an edit is a rule bug — a
> false positive (appeared) or a false negative (disappeared).

This is the same technique that found three nox rule bugs by hand (a blank
line before a Dockerfile `COPY` → false positive; a comment mentioning
`HEALTHCHECK` → false negative).

There are **two modes**, sharing one engine:

| | Per-PR gate | Corpus audit (oracle) |
|---|---|---|
| Script | `harness.py` | `sweep.py` |
| Workflow | `.github/workflows/metamorphic.yml` (`pull_request`) | `.github/workflows/metamorphic-audit.yml` (`schedule` weekly + `workflow_dispatch`) |
| Inputs | the PR's own testdata (`testdata/precision-suite/`) + synthetic seeds (`seeds/`) | the curated `testdata/metamorphic-corpus/` |
| Question | "does *this change* break the relation?" | "what is the *next* rule bug across many samples?" |
| Output | `invariance_report.json` + repros | `triage_report.json` + `triage_summary.md` + repros |
| Extras | — | per-rule coverage, suspicious-rule ranking, known-issues baseline |
| Fails on | any verified violation | any *new* (un-baselined) verified violation |

The gate keeps a change from regressing what the PR touches; the audit is the
standing oracle that hunts new bugs corpus-wide and ranks fragile rules.

## Run it locally

```bash
make build                                             # produces ./nox
python3 scripts/metamorphic/selftest.py --bin ./nox    # positive controls (must pass)
python3 scripts/metamorphic/harness.py --bin ./nox     # per-PR gate (exit non-zero on any violation)
python3 scripts/metamorphic/sweep.py   --bin ./nox --results out   # corpus audit
```

`harness.py` flags: `--bin <nox>` (default repo `./nox`), `--seeds <dir>`
(repeatable; default = precision corpus + committed synthetic seeds),
`--results <dir>` (report + repros; default a temp dir), `--limit N` (first N
seed files, for a quick run).

`sweep.py` flags: `--bin`, `--seeds` (default `testdata/metamorphic-corpus/`),
`--results`, `--limit`, `--known-issues <json>` (default
`known_issues.json`), and `--no-known-issues` (report every verified violation
as new — use to confirm a baselined bug still reproduces).

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

## The corpus audit (`sweep.py`) — the production oracle

`sweep.py` reuses the whole engine above (mutations, equivalence, adversarial
re-verify, ddmin) and runs it across `testdata/metamorphic-corpus/` — a curated,
diverse set of Dockerfiles, GitHub workflows, Terraform, and Python/JS/Go
secrets/taint samples (see that directory's `README.md` for the coverage
breakdown). Beyond the pass/fail gate it produces a **triage report** with three
extra products:

1. **Per-rule coverage.** Every corpus file is scanned once and each rule is
   tallied by the distinct *constructs* (line-shift-invariant anchors) it fires
   on. `rules_exercised` and the full `coverage` map land in the report.
2. **Suspicious-rule ranking.** Rules are ranked for a maintainer to review:
   - `flips_under_edit` (**risk high**) — a rule with a *new* verified violation
     (its finding appeared/disappeared under a trivial edit). A confirmed bug.
   - `single_construct` (**risk medium**) — a rule that fired on exactly one
     distinct construct across the whole corpus, so the sweep could not
     cross-check its robustness. Not a bug: a coverage/fragility signal that says
     "add a second construct for this rule or review it for over-fitting."
3. **Known-issues baseline** (`known_issues.json`). A verified violation that
   matches a documented, already-triaged pre-existing nox defect is reported but
   does **not** fail the sweep — exactly like nox's own `baseline`. This keeps the
   weekly audit green on today's known state so it only alerts on something
   *new*, while the corpus keeps the tripping construct so the oracle keeps
   watching it (a new rule with the same shape, or a regression, still fails).
   Each entry must name specific `ruleids` **and** `seeds`, so a baseline can
   never blanket-suppress a class of future bugs. Run `--no-known-issues` to see
   the raw, unsuppressed set.

The report is deterministic: sorted throughout, **no wall-clock, no absolute
paths**, so two runs on the same repo state produce byte-identical output that
diffs cleanly in review.

### Triaging a reported violation

1. Open the `metamorphic-triage` artifact from the failed audit run (or run
   `sweep.py --results out` locally). Read `triage_summary.md`.
2. For each row under **NEW verified violations**, open its
   `repros/<id>/` directory: `before/` and `after/` are the minimal one-file
   inputs, `REPRO.md` has the exact `nox scan` commands. The edit between them is
   semantics-preserving by construction, so a finding that differs is a real
   false positive (`appeared`) or false negative (`disappeared`).
3. Confirm by hand: `nox scan repros/<id>/before` vs `.../after`. If it
   reproduces, it is a detection-logic (`core/rules`/analyzer) bug — fix the rule.
4. If it is a genuine pre-existing defect that must be deferred, add a scoped
   entry to `known_issues.json` with a repro note; the audit then only re-alerts
   if the shape spreads to a new rule/seed. Remove the entry once fixed — the
   sweep goes green on its own, and a re-introduction fails again.

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

The sweep mode adds four more controls, so a green audit is trustworthy too:

- **PC5 sweep coverage** — `collect_coverage` tallies real rules from a real scan.
- **PC6 sweep triage goes red** — a planted verified violation is ranked
  **high** (`flips_under_edit`) at the top of the triage, never silently dropped.
- **PC7 sweep line-shift invariance** — an end-to-end sweep over a clean corpus
  file yields **zero** new verified violations.
- **PC8 known-issues baseline** — the baseline suppresses exactly the violation
  it names and nothing more; a same-rule violation on a *different* seed stays
  new (so a regression elsewhere still fails).

## Determinism

Seed files are sorted, mutation order is fixed, there is no randomness, and nox
is invoked with `--offline`. Same repo state ⇒ same result. The synthetic seeds
under `seeds/` are intentionally vulnerable (unpinned base images, mutable
action tags, missing HEALTHCHECK/USER) so the absence/presence rules actually
fire; `scripts/` is excluded from the repo self-scan (`.nox.yaml`), so they do
not affect nox's own security grade, while the harness still exercises them in
isolated temp dirs.

## Files

- `harness.py` — the per-PR engine (mutations, equivalence, diff, verify, ddmin,
  report).
- `sweep.py` — the corpus audit / oracle (reuses the engine; adds coverage,
  suspicious-rule ranking, known-issues baseline, triage report).
- `selftest.py` — positive controls for both modes (run to trust a green result).
- `known_issues.json` — the sweep's baseline of already-triaged, pre-existing
  verified violations (scoped by rule + seed).
- `seeds/` — committed synthetic Dockerfiles + GitHub workflows for the per-PR
  gate (the acute Dockerfile/YAML absence-rule bug class).
- `../../testdata/metamorphic-corpus/` — the curated multi-sample corpus the
  audit sweeps (see its `README.md` for coverage).

## Deferred / out of scope

- **Running against *external* repositories.** The oracle sweeps a committed,
  in-repo corpus so CI is deterministic and self-contained. Pointing it at a
  fleet of external real-world repos (more constructs, more rules) is valuable
  but is org-infrastructure — it needs checkout credentials, a scheduling budget,
  and non-deterministic inputs — so it is intentionally not wired here. `sweep.py`
  already accepts extra `--seeds <root>` arguments, so such a job can reuse this
  engine unchanged.
- **Fixing the rule bugs the oracle finds.** The oracle is built *around* the
  rules, not in them. Detection-logic fixes (`core/rules`, analyzers, taint) are a
  separate change; found defects are recorded in `known_issues.json`.
