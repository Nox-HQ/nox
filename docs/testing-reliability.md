# Testing for reliability

nox is well tested by volume — ~3,400 tests, 30 per-language precision suites
with committed baselines, metamorphic invariance sweeps, race detection,
coverage thresholds. And yet a single audit found around fifteen real bugs.

That is not a contradiction. It is a statement about **what the existing gates
measure**, and this document exists so the gap does not reopen.

## The gap

The precision suites, the metamorphic sweep and the corpora all answer one
question:

> **Does the detector find the bad thing?**

Every bug that audit found was a different question:

> **Did the check actually run at all?**

| Bug | Detector accuracy | Actually broken |
|---|---|---|
| A regression suite pointed at a 404 route printed "fix holds" | fine | plumbing |
| A payload was dropped before it was sent; the silence read as "did not reproduce" | fine | plumbing |
| `--max-duration` parsed, stored, and never fired | fine | wiring |
| A git hook exited 0 when the scan crashed | fine | fail-open default |
| `vex init` parsed an artifact shape `nox scan` never writes | fine | writer/reader contract |
| `plugin install` validated nothing, while two other paths did | fine | missing gate |
| The MCP summary collapsed fifteen rule families into "other" | fine | cross-surface drift |

A precision suite measures rules against a corpus. It cannot tell you that the
command which *runs* those rules forgot to pass the route, that a flag does
nothing, or that the MCP surface disagrees with the CLI.

**nox tested its detectors exhaustively and its plumbing barely.** Every one of
those bugs also passed a green unit suite, because the fixtures exercised the
happy path.

## The shape of a nox bug

Almost every defect above is the same failure:

> **A control that reports success while doing nothing.**

For a security tool that is the expensive direction to be wrong in. A false
positive costs a user ten minutes; a false all-clear costs them the thing the
tool exists to prevent. So the discipline below is aimed squarely at it.

## The rule: test the negative space

For every check, gate, or detector, write the test where **it cannot possibly
work**, and assert it does not report success.

Not "does it find the bug" — the corpora already cover that. Ask instead:

- What if the target is unreachable?
- What if the route is wrong?
- What if the scan crashed?
- What if the payload never actually left the process?
- What if the input is a shape we never write?
- What if the value is empty, or an unrecognised enum?

Each of those, as a required test, would have caught a shipped bug. Concrete
examples now in the tree:

- `core/attack/e2e_test.go` — a wrong route, an erroring target, and an
  unreachable target must never read as `PREVENTED` or `CONFIRMED`; a regression
  suite that could not reach its target must not exit 0.
- `core/attack/regress_test.go` — `TestUnreachableTargetIsNeverReportedAsAFixHolding`.
- `cli/protect_cmd_test.go` — the generated hook must propagate a scan error
  rather than falling through to a clean exit.

### Silence is not evidence

When nox cannot evaluate, it must say so. `INCONCLUSIVE` is a real, useful
answer; `PREVENTED` and a green exit code are claims. `core/evidence` encodes
this — a run cut short by a budget, or one with target errors, can never derive
to `PREVENTED` — and `core/evidence/failclosed_test.go` pins it mechanically
over the whole outcome space.

## The four guards

Beyond the convention, four mechanical guards catch whole classes at once. Each
is cheap, and each exists because the class it catches already bit.

### 1. Cross-surface conformance — `conformance/`

nox has three entry points over one domain (CLI, MCP, LSP). Five times an
adapter grew its own copy of a domain rule, the copies drifted, and the drift
dropped a security signal — the MCP tool showed a dependency downgrade the CLI
would refuse; the MCP agent-graph lost its capability risk colouring entirely.

`conformance/adapters_test.go` asserts the adapters still route through the
shared implementation, and flags a function name defined in more than one
adapter. **When a consolidation lands, add it to `sharedOperations`** — that is
how it becomes permanent instead of a review promise.

### 2. Artifact round-trip contracts — `core/report/`

Every artifact nox writes must be readable by the code that reads it, must
survive determinism, and must stay valid for an empty scan. The `vex init` bug
was exactly a writer/reader contract violation that no test crossed.

### 3. Fail-closed gates

Enumerate every gate — exit codes, thresholds, authorization, admission — and
assert each fails **closed**. `riskClassLevel("") → passive` and
`hook exit 2 → 0` were both fail-*open* defaults nothing asked about.

### 4. Parity guards for paired tables

Where two hand-maintained tables must agree, assert it. The lexer knew eight
source extensions the file discoverer did not, so those files were silently
never scanned; `TestSourceExtensionsCoverTheLexer` now fails if that reopens.

## Checklist for a new detector or command

- [ ] It finds the thing (corpus / unit test).
- [ ] **It does not claim success when it could not look.**
- [ ] Every flag demonstrably changes behaviour.
- [ ] Its gate fails closed on an unknown or empty value.
- [ ] If another surface exposes it, both call one implementation — registered
      in `conformance/adapters_test.go`.
- [ ] If it writes an artifact, a test reads that artifact back.
- [ ] Output is deterministic: no map iteration reaches a rendered line.
