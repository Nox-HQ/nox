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

## Flag efficacy, continued: the top-level and `attack` surfaces

The first flag-efficacy pass proved that flags are *registered* and
*documented*. Neither property implies a flag *does* anything, and the gap
between them is where a false all-clear lives — a control that parses, prints,
and reports success while changing nothing.

Two more guard files close it:

- `cli/toplevel_flag_efficacy_test.go` covers the flags that apply before a
  subcommand is chosen. Beyond the usual inert-flag check it adds an **alias
  drift** guard: `-q`/`--quiet` and `-v`/`--verbose` are two registrations
  bound to one variable, and if an edit ever gives a shorthand its own
  variable, that shorthand silently stops working while both still parse.
  `--format` and `--output` are proved behaviourally — which artifacts get
  written, and where.
- `cli/attack_flag_behaviour_test.go` drives the real `attack` entry points
  against a local target that genuinely performs the attacker-ordered
  transform, so the benign control stays clean and a CONFIRMED verdict is
  honest. `--reply-field`, `--seed`, `--min-hits`, `--route`, `--findings`,
  `--output`, `--json` and `--record` each have to change an outcome.

Two defects fell out of writing them, both in the direction nox exists to
prevent:

- `extractField` returned the **whole response body** when the body was valid
  JSON but the named reply key was absent. `Observation.Reply` is what the
  refusal oracle reads, so a misnamed `--reply-field` made nox pattern-match
  refusal phrasing against raw JSON and report **PREVENTED** — its own
  blindness dressed as a guardrail. The plain-text fallback is kept (a
  non-JSON target has no field to name); the absent-key case now returns "".
  Canary detection is unaffected: that oracle scans `Body` too.
- `attack plan --json` printed the plan and returned **without writing
  `--output`**, so `attack plan --json --output p.json` produced no `p.json`.
  `--output` decides where the plan is written and `--json` decides what is
  printed; they are orthogonal and the write now happens either way.

One guard in this batch passed **vacuously** on its first run and had to be
rebuilt: `--record` was asserted to send no requests, but the trace it recorded
confirmed nothing, so the derived suite was empty and no run would have sent
requests either. The test now records a genuinely CONFIRMED exploit first and
asserts the suite is non-empty before asserting the request count. Checking
that a guard *can* fail is not optional — see the mutation discipline above.

## The same guard, one layer up: stub implementations

Flag efficacy asks "does this control change anything?". Asking it of the
non-CLI surfaces found three stubs, of which two were reporting success.

**A rule matcher that matched nothing.** `jsonpath`, `yamlpath` and `heuristic`
were listed in `ValidMatcherTypes` and registered to a `stubMatcher` that
returned nil for every input. So a rule declaring one **validated at load time,
appeared in `nox rules`, ran on every file, and matched nothing** — the author
had no way to learn their rule never ran. Note the stub was strictly worse than
nothing: with no matcher registered, `Engine.Scan` returns `no matcher
registered for type %q (rule %s)` and fails loudly. The stub converted that
loud failure into a silent clean scan, which is the one outcome nox must never
produce. The three types are now rejected at load time and the stub is gone.

**An MCP tool that could not work.** `plugin.read_resource` was registered with
the description "Read a resource from a plugin", took `plugin` and `uri`, and
returned `"Error: plugin.read_resource is not yet implemented"` as a
**successful** result — an agent checking `isError` saw success. `PluginService`
has no resource-read RPC (`GetManifest` / `InvokeTool` / `StreamArtifacts`
only), so it could not have worked. Unregistered, and dropped from README,
`docs/usage.md` and `docs/extension.md`.

(`nox plugin test` is also a stub, but it exits 2. An honest failure needs no
fix.)

Both had a test pinning the stub behaviour as correct — `TestStubMatcher_Match`
asserted the nil return, `TestHandlePluginReadResource_Stub` asserted the error
string. Coverage of a stub is not evidence the feature works; it is evidence
the stub is faithfully doing nothing.

Three guards now hold the line, in `core/rules/stub_matcher_test.go` and
`server/tool_efficacy_test.go`:

- `ValidMatcherTypes` and the default matcher registry must be the same set.
- **Every matcher type must prove it matches**, against a case chosen for it.
  This is the one that matters: set membership and non-nil registration are both
  satisfiable by a matcher returning nil for every input, which is exactly the
  bug's shape. Only running the matcher catches it.
- No registered MCP tool may bind a handler that reports it is unimplemented,
  and every published tool parameter must be read.

Two lessons from building them, both already in the mutation discipline above
and both still nearly missed:

- The first tool guard scanned only `registerTools` — but plugin tools register
  in `registerPluginTools`, so it was blind to all three plugin tools including
  the stub it was written to catch. It passed. The guard now scans the package
  and **asserts a minimum tool count**, so silent under-coverage fails.
- The first parameter guard used a substring search for `.Plugin`, which also
  matches `.PluginScanOutput`. It reported an unread field as read. It now walks
  selector expressions in the AST.

A guard that passes on mutated source is not a guard. Both of these did.

## Config keys: the third surface

`UnknownConfigKeys` already reports keys nox cannot parse, on an explicit
principle — a security tool that silently ignores configuration reports on a
policy the operator did not ask for. But that check answers "does this key
parse?", and a field sitting in `ScanConfig` that nothing reads parses fine. It
passed in silence.

Three did:

| key | what the operator expects | what nox does |
|---|---|---|
| `scan.include` | narrow the scan to these paths | ignores it; only `scan.exclude` applies, so the scan covers **more**, not less |
| `compliance.framework` | filter to one framework | ignores it; every finding is reported |
| `cache` | configure the incremental cache | ignores it; there is no scan cache |

`IneffectiveConfigKeys` is the sibling of `UnknownConfigKeys` and reports them
the same way, naming only the inert keys the operator actually wrote and saying
what nox does instead. `--no-cache` was already handled honestly (registered as
an explicit no-op, allowlisted in `inertScanFlags` with a reason); the `cache:`
config block had no such honesty.

Guards, in `core/config_efficacy_test.go`:

- every yaml-tagged config field is read somewhere in the module, or listed in
  `inertConfigKeys` **with a reason** — there is no third option;
- the reverse: a key listed as inert that something has started reading fails,
  so wiring one up and forgetting to delete its apology cannot leave nox
  telling operators a working setting is ignored;
- the reporter names only what was written, treats a parent key as covering its
  children, and counts presence rather than value (`include: []` still says the
  operator believes `include` does something).

That guard matches field names, not types, so a dead field sharing a name with a
live one elsewhere could still hide. `core/config_liveness_test.go` closes it by
using the compiler as the oracle instead of a heuristic, and found exactly the
two fields the name-based pass could not see: `CacheSettings.Dir` and `.TTL`,
both masked by a `.Dir` and a `.TTL` on other config types.

It works in two passes, which is what makes it affordable:

1. Rename every leaf config field at once in an in-memory `go build -overlay` of
   `config.go`, and collect the fields the compiler names as undefined. Cheap,
   and sound in one direction only — an error proves a field is read, but its
   absence proves nothing, because a package that fails to compile stops its
   dependents being type-checked at all, so a field read only by `cli/` is
   invisible.
2. For each field pass 1 could not vouch for, rename that ONE field and build.
   A dead field's rename breaks nothing, so the build succeeds; a live field's
   rename breaks whatever reads it, wherever that is. No cascade either way.
   Sound in both directions, one build per suspect — which is why pass 1 runs
   first. About 15 seconds in total, skipped under `-short`.

Container fields (`Scan`, `Policy`) are excluded: renaming one breaks every
access chain at the first hop, so `cfg.Scan.Exclude` fails on `.Scan` and every
leaf beneath it looks dead. Containers stay with the AST guard.

The residual limitation, again stated rather than hidden: the rename is by field
NAME, so a name shared by several *config* structs is probed as a group and
reported live if any of them is read. That is the conservative direction — the
probe never calls a live field dead — but a dead field sharing its name with a
live sibling still hides.

The two guards disagreed once the compiler probe existed, and the disagreement
was informative: the AST guard's reverse check ("is this inert entry still
true?") condemned the correct `Dir`/`TTL` entries because it could only match
names. That check moved to the compiler-backed test, and the AST test kept only
what a name-based pass can settle soundly. Where a heuristic and the compiler
disagree, the compiler wins.

## Truncation that reports success

`bufio.Scanner` stops at a 64 KiB line and reports `ErrTooLong` through `Err()`.
A parser that neither raises the limit nor checks `Err()` therefore stops
reading at that line and returns what it had — and a truncated dependency list
is indistinguishable from a complete one. Everything after the long line is
missing from the SBOM and from vulnerability matching, with nothing to say so.

The package already knew. `maxLockfileLine` sits in
`core/analyzers/deps/parsers_ecosystem.go` under a comment saying the scanner
"stops silently at that limit, which would truncate the dependency list without
any error". It was applied to three scanners out of seventeen.

That is the lesson worth keeping: **a comment explaining a hazard does not
enforce it**. The other fourteen sites were written by people who could have
read that comment and didn't need to. Every line-oriented parse in the package
now goes through `newLineScanner`, and `TestEveryLineScannerRaisesTheLimit`
fails if a raw `bufio.NewScanner` reappears.

The raised limit is still finite, and the guard pins both halves: a 70 KiB line
must parse, and a line past `maxLockfileLine` must fail with `bufio.ErrTooLong`
rather than truncate — so a pathological file cannot exhaust memory, and a
caller can still tell truncation from a clean end of file.

This was found while working nox issue #455, where a plugin aborted its whole
scan on a minified bundle. The plugin's own fix belongs in its repository; the
same defect class in this one did not.
