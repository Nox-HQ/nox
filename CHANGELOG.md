# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.32.0] - 2026-08-31

Two programmes in one release: nox became evidence-native, and its dynamic
validation gained a domain model for reachability, verification and
reproduction. Nothing breaks — every `nox scan` behaves as before, and the new
surfaces are opt-in — so this is a minor release despite its size. What changed
is that nox now records *why* it believes each finding, can be asked, and can
prove it did not silently turn an unknown into an all-clear.

### Added

- **`nox why <finding>` answers eight questions about a finding, deterministically**
  (#526, #528). What was observed, why it matters, what supports it, what argues
  against it, **what was not evaluated**, the potential impact, **whether it
  affects this application**, and what to do. The two in bold are the ones a
  scanner usually leaves out: an analysis that never ran is a gap, not a limit,
  and silence about it lets a reader assume everything was looked at. It reads
  only what the scan established — every sentence traces to a claim, a capability
  state, or a rule's own metadata — so the same finding always produces the same
  answers. `nox explain` remains the model-written counterpart; only one of the
  two can be put in front of an auditor. Available over MCP as the `why` and
  `analysis_capabilities` tools.

- **`nox scan --evidence-out evidence.json` keeps the evidence, and `nox replay`
  re-derives the verdicts from it** (#525). A scan gathers evidence for and
  against every candidate and discards it — carrying it inline costs about 2.4×
  the size of the findings. `--evidence-out` keeps it; `nox replay` re-derives
  every verdict from that file and nothing else, not the repository, not the
  rules, not the network. That is what makes "does this evidence still support
  this verdict?" answerable months later, when all three have moved on. A
  divergence under a newer adjudicator is reported as a change, not a defect.

- **`nox why` and `nox attack plan` name what nox could not establish.** The
  reachability vocabulary (#533) distinguishes six propositions from
  "the package is linked" to "an attacker-controlled path was observed", and a
  scan that stops climbing says where and why it stopped, with the analysis
  limitation named — reflection, dynamic loading, FFI (#535). A finding's
  explanation closes with the cheapest open question something on this
  installation could actually answer (#543).

- **`policy.uncertainty` and `policy.require_capabilities` gate on what nox did
  not determine** (#509, #510, #522). A project can declare that its triage
  depends on an analysis — reachability, taint — and be failed, loudly, when
  that analysis stops being answered. The gate reads what *this scan* actually
  established, not merely what the installed build *could* establish: a scan
  whose advisory source was unreachable no longer satisfies a reachability
  requirement it never exercised.

- **`nox attack plan --evidence` carries the scan's evidence onto each
  hypothesis** (#545). The scan produces the hypothesis; the attack fills in the
  observation. A plan now carries the typed subject, the scan's ledger, the
  attacker-controlled input, a suspected trigger condition, the expected oracle,
  the assumptions nox is making, and the questions still open — so `nox attack`
  no longer rediscovers, badly, why nox thought a finding worth testing.

- **`nox attack run` reports hypotheses resolved per unit of effort** (#547),
  not coverage. A run that fired many probes and decided nothing now reads worse
  than a small run that decided something, and a run that decided nothing says
  so rather than printing a number a reader might take for a clean result.

- **GitHub tokens are verified by their embedded checksum** (#515). Several
  providers encode a checksum in the credential, and verifying one is
  deterministic rather than heuristic — the first claim in the secrets pipeline
  that can lift a finding off the "a pattern matched" floor honestly. A token
  whose checksum does not verify is deterministically not a credential of that
  provider.

- **A hardcoded JWT is verified by its structure** (#549). The checksum path is
  nearly exhausted at GitHub: its CRC32 is one of very few schemes verifiable
  offline, and most providers can only be checked by calling their API, which
  nox's architecture forbids. The honest next deterministic signal is structural
  — a JWT's header base64url-decodes to JSON naming a signing algorithm,
  checkable with no network and no key. It establishes that the value *is* a
  JWT, never that its signature holds.

- **A surviving AI finding records what it was checked against** (#551). The AI
  refiners recorded why they *dropped* a candidate and nothing about the ones
  that survived, so a reported AI finding's ledger said only "the rule fired".
  A survivor now carries the inspections it passed — it is in real code, and for
  a rule with a context requirement, that context was found. Every such claim is
  a heuristic deliberately, so this moves explanation and not confidence:
  `nox why` answers "what supports it" with something other than a tautology.

- **A served intelligence record is consumed as research, not as an opaque
  advisory** (#550). `intel.FromRecord` turns a record into a
  `ResearchProposition`: the affected package's import paths become the symbols
  the local applicability test asks about, the corroboration count and refuting
  claims cross the wire, and the maturity is read from the ledger's strongest
  *live* claim — a retracted or disputed claim weighs nothing, the same rule the
  kernel applies to confidence. Intel evidence is about a package; only local
  analysis decides whether it applies here. The researcher-intake side is
  deliberately not built: a record cannot yet carry a trigger condition or a PoC
  hypothesis, because asserting those is a disclosure decision rather than an
  adapter.

### Changed

- **A finding now carries two confidences, and they answer different questions**
  (#523). `Confidence` is the analyzer's calibrated judgement that a finding is
  a true positive — on nox's own corpus, 37 true positives and no false ones, so
  it is accurate. `EvidenceConfidence` is what the recorded evidence supports,
  and it caps at `MEDIUM` for any static scan: the evidence model puts `HIGH` at
  the strength of a controlled reproduction or a confirming source, which
  reading code does not produce. They are kept apart because merging them —
  filtering on evidence strength as though it were calibration — would empty
  `--min-confidence high` on every project, permanently. `--min-confidence`
  filters on the first.

- **The shared kernel moved to `nox-core` v0.2.3** (#520–#547). Typed subjects,
  claim polarity, a claim lifecycle, producer authority, the reproduction
  hierarchy and subject-scoped confirmation now live in the kernel both the CLI
  and the intelligence service share. A retracted claim weighs nothing
  everywhere it is read, not only where it was first wired in.

- **The passive/active boundary is enforced by test, not only by convention**
  (#542). `nox scan` reads; `nox attack` acts, requires `--authorize`, and its
  safe profile selects a network-less adapter. The scan pipeline carries no
  import of the attack package, checked by parsing its imports, because a
  convention is what a refactor does not consult.

### Fixed

- **nox no longer reports its own baseline files as leaked credentials** (#529).
  The tool-state exclusion (`.nox`, `.claude`, `.roady`, …) matched only at the
  repository root, so the same directory one level down was scanned — and a
  SHA-256 fingerprint in a nested `.nox/baseline.json` fired a high-severity
  "Cloudflare API Token". On one real repository this was 107 false positives.
  Directory exclusions now match at any depth.

- **36 vendor secret rules stopped matching any long string near a keyword**
  (#530). A rule like SEC-542 with the pattern `[a-zA-Z0-9]{32,}` and the
  file-level keyword `cloudflare` meant, in practice, "this file mentions
  cloudflare somewhere and contains 32 alphanumeric characters somewhere". The
  proximity control that fixes this already existed; a one-character bug in its
  pattern skipped exactly the unbounded quantifiers — the most dangerous form.
  Two rules were retired: SEC-542 (a duplicate of SEC-087, which detects the
  same token correctly) and SEC-524 (an Azure subscription ID is not a
  credential). Waivers written against SEC-542 keep working.

- **`nox why . --offline` no longer reads the flag as a finding selector**
  (#535). Go's flag parser stops at the first positional; the command now splits
  flags from positionals first, as `nox show` already did.

- **AI-006 no longer flags a constant sentence that contains the word
  "prompt"** (#497). `print` in the rule's call alternation also matches inside
  `Fprintf`, and the noun was then accepted anywhere in the call — including
  inside a string literal. `fmt.Fprintf(os.Stderr, "…nobody can approve a
  browser prompt.\n")` was a medium finding, and it cannot be a true one: a call
  whose arguments are all constants logs no value, so there is no prompt to
  leak. A match now survives only when the call actually logs something — the
  noun is an identifier, or code follows it inside the call (a concatenation, an
  f-string or template-literal hole, a printf argument). Five waivers in nox's
  own CLI became unnecessary and were removed.

- **Hardcoded JWTs were dropped before they became findings** (#549). The
  data-blob refiner discarded any string over 96 bytes as an opaque base64
  payload, and a full JWT runs to hundreds of bytes — so nox could not see an
  entire credential class. The threshold's own comment gave it away: it reasoned
  about "a JWT header segment" and missed that the whole token is long.
  `lexctx.LooksLikeJWT` closes it, in one place so the blob refiner and the
  secrets analyzer cannot disagree about what a JWT is. Surfacing them then
  exposed a dedup gap — three rules match a JWT and did not collapse — closed by
  making `eyJ` a canonical owner prefix. End to end, a hardcoded JWT goes from
  zero findings to one.

- **Every `brace-enclosing` absence rule silently missed CloudFormation written
  in YAML** (#552). IAC-051 and its family bound a resource block with a span
  that walks out to the enclosing `{ }`. YAML has none, so the span came back
  empty and the rule never fired — while the rules already listed `*.yaml` in
  their file patterns, so the format was always in scope. An unencrypted S3
  bucket was flagged in a JSON template and missed in the identical YAML one.
  Fixed with an indentation-bounded *enclosing* span, a distinction a false
  positive taught: the block span of a `Type:` anchor is the scalar alone, so a
  sibling encryption property fell outside it and an encrypted bucket looked
  unencrypted. The JSON path is untouched.

## [1.31.0] - 2026-08-29

A source that stays silent about a CVE, and a kernel two repositories can share.

### Added

- **`VerifyingSource`: "a superset of OSV" is now something the client checks,
  not something it accepts.** The intelligence design threat-modelled poisoning
  by *addition* — Sybil reporters, malicious metadata — and left the worse half
  uncovered. A source that withholds a real CVE produces a clean scan, and
  nothing downstream can tell "no vulnerability" from "not told about the
  vulnerability". An invented finding is noisy and eventually noticed; a missing
  one is silent forever.

  Every answer from the intelligence source is now asked of the reference in
  parallel and the difference classified. When the reference holds a record the
  intelligence source withheld, that is a `SUPPRESSION`: it raises
  `degrade.IntelSuppression` **and returns the record anyway**, so a source
  cannot make a vulnerability disappear by declining to mention it.

### Changed

- **The shared kernel moved to `github.com/nox-hq/nox-core`.** `core/evidence`,
  `core/vulnsource` and the degrade guards now live in their own module, pinned
  here at `v0.1.1` — the tag that carries the Apache-2.0 licence. This exists so
  the CLI and the intelligence service can share one implementation without
  either depending on the other.

  **This removes those import paths from this module.** Nothing in the CLI, the
  MCP surface, the LSP or the output formats changes — a `nox scan` behaves
  exactly as it did — but code importing `github.com/nox-hq/nox/core/evidence`
  or `github.com/nox-hq/nox/core/vulnsource` must now import
  `github.com/nox-hq/nox-core/...` instead. These packages were never documented
  as a public API, which is why this is a minor release rather than a major one.

### Fixed

- **`scan --help` did not mention `--format`,** the flag that makes nox emit
  an SBOM. It and five others — `--output`, `--rules`, `--quiet`/`-q`,
  `--verbose`/`-v`, `--version` — are registered on the root flag set, while
  `scan --help` printed only the scan set. All six worked; none were listed
  where somebody would look for them, so `nox scan . --format cdx` writing a
  CycloneDX 1.5 document read as a capability nox did not have. Scan's usage
  now renders them under a "Global flags" heading, from the same description
  constants the real registrations use.

- **`vex init --product` described itself as "typically the Go module path".**
  nox is not Go-only, and a bare module path is not what OpenVEX products
  look like: they are package URLs, or for a container its digest. A module
  path carries no version, so two releases produce VEX statements that cannot
  be told apart — the one thing a product identifier exists to prevent. The
  help now says so, and names the forms. No behaviour change.

### Build

- **warden gates this repository.** Lint runs at pre-commit; tests and the
  security scan run at pre-push, so a failing tree cannot reach the remote.


## [1.30.1] - 2026-08-27

Plugins that were configured, required, and silently not running.

### Fixed

- **Plugins did not run in any workspace that configured `scan.exclude`.**
  The exclusions were sent to plugins as a `[]string`, which
  `structpb.NewStruct` rejects — and it converts the whole input map or none
  of it, so the wrong type did not drop the exclusions, it failed the
  `InvokeTool` request. Twelve of twenty installed plugins never ran,
  `nox/sast` and `nox/taint-analysis` among them. Excluding lockfiles is the
  first thing most repositories configure, so the reach was close to "any
  workspace that customised its scan at all".

  Post-scan tools were unaffected: they carry a typed `ScanContext` and no
  input map, so nothing converts. That is why `nox/reachability` worked and
  `nox/taint-analysis` failed in the same scan, which made this look like one
  broken plugin rather than a host bug.

  `buildInvokeRequest` now normalizes at the boundary as well, so a caller
  writing the obvious Go type cannot reintroduce it. `[]byte` is deliberately
  left alone — structpb encodes it as base64, and listifying it would change
  the wire form a plugin receives — and values structpb genuinely cannot
  represent still error, because those are real mistakes.

- **A required plugin that failed to run reported `policy: pass`.** One that
  was never installed, whose binary was missing, or that failed to register
  already produced a degradation. One that registered and then failed every
  invocation produced only a diagnostic on stderr, so it reached neither
  `[degraded]`, the findings JSON, the MCP surface, the LSP, nor
  `--fail-on-degraded` — whose help text promises to "exit non-zero if any
  check could not complete". A repository could name a plugin in
  `plugins.required`, run `nox scan` as a push gate, and be told pass for as
  long as the plugin had been broken.

  The scan still succeeds and still exits 0 by default: running the plugins
  that worked is right, and promoting a partial run to a hard failure remains
  the operator's call via `--fail-on-degraded`, which now covers this case.
  Only error-severity diagnostics are promoted — a plugin that skips a
  vendored file and says so is working as intended.

### Added

- **`plugins.required` honours version constraints.** `*`, `1.2.3`,
  `>=1.2.3`, `^1.2.3` and `~1.2.3`. `nox plugin install nox/foo@0.5.0` was
  already accepted syntax, so operators wrote the same thing in `.nox.yaml`;
  the whole string was matched as a plugin name, so it could never resolve
  and nox reported "is not installed" for a plugin that was installed — with
  the effect that the plugin silently never ran.

  The constraint is enforced, not merely parsed: matching the name and
  ignoring the version would hand a repository whatever happens to be
  installed, which is the outcome a pin exists to prevent. An unsatisfied
  constraint degrades and names the version actually installed, unsupported
  grammar is an error rather than a silent pass, and a version that cannot be
  compared at all — a locally built plugin recording `dev` — says so instead
  of guessing.

  Below 1.0.0 the minor is the breaking axis, so `^0.2.0` admits 0.2.9 and
  not 0.3.0. Every plugin in the registry is currently 0.x, so the looser
  reading would have made the caret mean "any version" for all of them.

  Implemented without a semver dependency: nox is a security scanner, and a
  twelfth direct dependency to compare three integers is the worse trade.

## [1.30.0] - 2026-08-24

Dynamic exploit validation, and a run of fixes about controls that reported
success without doing anything.

### Added

- **`nox attack` — dynamic exploit validation for AI and agentic systems.**
  Builds exploit hypotheses from static findings and the AI inventory,
  exercises a running target, and reports evidence-backed traces.
  `plan` is offline; `run` / `replay` / `regress` / `mcp` are ACTIVE, require
  `--authorize`, and never run as part of `nox scan`.

  Verdicts come from `core/evidence`, which owns the exploitability ladder
  (POTENTIAL / PLAUSIBLE / PREVENTED / INCONCLUSIVE / CONFIRMED) and enforces
  two rules nothing else may re-implement: CONFIRMED requires deterministic
  evidence at reproduction strength — no quantity of heuristics or LLM
  judgments reaches it — and independence counts distinct reporters, not
  repeated observations. Payloads are reflection-immune: a canary value never
  appears in what is sent, so an echoing target cannot fake a hijack.

  nox never reports "safe". A target that was not reached, or a run that was
  cut short, is INCONCLUSIVE — never PREVENTED.

- **`scan.include` is implemented.** An allow-list of glob patterns: when set,
  only matching files are scanned. It previously parsed and did nothing, so a
  scan narrowed to a subtree silently covered everything. See *Upgrading*.

- **Config nox parses but does not act on is now reported.** Unrecognised keys
  were already reported (1.29.0); a key nox accepts and then ignores fails the
  operator identically — the policy written is not the policy in force. Both
  now surface as degradations from `core`, so the CLI, the MCP server, the LSP
  and `findings.json` all report them. Currently `compliance.framework` and
  `cache` (nox never caches a scan; `--no-cache` is likewise a no-op).

- **`sdk.Fingerprint` / `sdk.RelativePath` / `sdk.RunFingerprintStability`** for
  plugin authors, so a plugin's fingerprints do not move with the checkout.

### Fixed

- **SEC-163 could never match a hex string** (#467). It required entropy ≥ 4.5,
  but Shannon entropy over a 16-symbol alphabet cannot exceed log2(16) = 4.0.
  So the rule named for hex matched only candidates from *richer* alphabets and
  reported them under the hex description — one report showed it flagging a Go
  identifier while the 40-character fingerprints two files away went unreported.
  Entropy candidates now carry the set of tokenizer kinds that found them, rules
  declare `candidate_kinds`, and SEC-163 sits at 3.5, below the ceiling.

- **Plugin finding fingerprints no longer move with the checkout path** (#454).
  They were derived from the absolute path, so no plugin finding could be
  baselined anywhere the path differed — every CI runner, every worktree gate,
  any two developers. Locally the baseline matched and the scan was green; the
  gate elsewhere reported hundreds of net-new findings for the same commit.
  Paths are made repo-relative, and slash-separated, before fingerprinting —
  the second half caught by the Windows job, where native separators made one
  file fingerprint differently on Windows than on Linux.

- **Lockfile parsers truncated silently at 64 KiB.** 14 of 17 used
  `bufio.Scanner` at its default limit without checking `Err()`, so a long line
  ended the parse and returned what it had. A truncated dependency list is
  indistinguishable from a complete one, and everything after that line was
  missing from the SBOM and from vulnerability matching.

- **`scan.exclude` now reaches plugins.** A plugin walks the workspace itself,
  so without the patterns it cannot honour the exclusions the operator wrote.

- **18 shipped rules were invisible to the rule catalogue.**
  `Catalog()` aggregated 8 of the 14 analyzers that publish rules, so
  AGENTFLOW/TAINT/CRYPTO/HARDEN/PERM/MEMSAFE rules produced findings while
  the MCP `rules` tool — and anything else reading the catalogue — denied they
  existed. Catalogue count 1519 -> 1537.

- **A policy gate let an unrecognised severity through.** `policy.Evaluate`
  gated a finding only when it could *rank* its severity, so a finding whose
  severity it did not recognise slipped every gate and the scan exited 0.
  Reachable from config: an unvalidated `scan.rules.severity_override` of
  `Critical` (capitalised) made a finding invisible rather than raising it.

- **MCP-009 no longer flags code that detects injection as performing it**
  (#474). The phrase it matches is unavoidable in a guardrail's pattern list or
  an attack corpus, where the string is what is being searched for.

- **Matcher types that validated but matched nothing are rejected at load
  time.** `jsonpath`, `yamlpath` and `heuristic` were accepted by rule
  validation and served by a stub returning nil, so a rule declaring one
  loaded, listed in the catalogue, ran against every file and found nothing.
  Not registering them at all is *safer*: the scan now fails loudly.

- **`plugin.read_resource` is no longer advertised.** It was registered as a
  ReadOnly MCP tool and returned "not yet implemented" as a *successful*
  result, so an agent checking `isError` saw success. The plugin protocol has
  no resource-read RPC, so it could never have worked.

### Changed

- **`nox attack` and the intelligence layer are separate concerns.**
  Vulnerability intelligence is deliberately not in the CLI; see
  `docs/design/intelligence-service.md` for the boundary.

## Upgrading

Two changes alter existing behaviour rather than adding to it.

- **`scan.include` now narrows a scan.** If you have it set and were relying on
  the previous (broken) behaviour, you were getting a *full* scan. Enabling it
  correctly means fewer files are scanned — check the patterns match what you
  intend. `scan.exclude` still wins where both apply, and directories are still
  descended, because a glob cannot say in advance whether a subtree contains a
  match.

- **Baselines containing plugin findings will not match once.** Plugin
  fingerprints changed to become path-independent, so entries recorded under
  the old scheme need re-recording. Review the re-surfaced findings before
  running `nox baseline update` — they are the same findings, but a blanket
  update is how unreviewed findings enter a baseline.


## [1.29.1] - 2026-08-22

Two fixes about the same failure mode: a remediation that reports success
without having remediated anything.

### Fixed

- **`nox fix` applies each upgrade in the directory of the manifest its finding
  named.** It ran every package manager in `--root`, which in a monorepo is a
  directory no dependency lives in — and npm does not fail there, it *creates* a
  `package.json` and a lockfile. The run printed `applied`, a phantom root
  manifest got committed, and the real dependency stayed vulnerable on the next
  scan. Findings already carry their manifest path, so it is now used: no
  manifest for that ecosystem in that directory means the upgrade is refused and
  counted, rather than silently retargeted at the root. A manifest path that
  climbs out of the project is refused outright. Dedup is per directory, because
  two workspaces on the same vulnerable version are two upgrades.

  The npm *ecosystem* is four package managers, so the tool now comes from the
  lockfile — npm, pnpm, yarn (classic and berry), bun. `npm install` in a pnpm
  workspace wrote a second lockfile and resolved a tree nothing installs from.
  pnpm gets `--depth Infinity`, because most advisories land on transitive
  dependencies.

- **An upgrade that rewrote nothing is no longer reported as `applied`.**
  Package managers exit 0 without doing anything: pnpm answers "Already up to
  date" for a transitive dependency held down by a `pnpm.overrides` entry. nox
  printed `applied` over an unchanged lockfile, which is the worst possible
  report — the operator stops looking while the advisory stays live. The
  manifests are fingerprinted around each apply; an upgrade that moved nothing
  is reported as `no change`, with the likely cause, and counted as a failure.

- **A failing gate names the finding that failed it** (#463).

Found by running `nox fix` across a fleet of monorepos: 12 of 16 repositories
carried critical or high advisories, 8 of them in manifests a root-level run
could never have reached.

## [1.29.0] - 2026-08-10

### Added

- **Unrecognised `.nox.yaml` keys are now reported as a degradation.** A key
  nox does not understand was silently ignored, so a config could describe a
  policy that was not in force while the scan reported success.

  Two cases seen in the wild, both accepted without comment:

  - `suppressions:` is not a key nox has. Writing it suppressed nothing and
    passed — indistinguishable from a scan whose suppressions all applied.
  - a misspelled `plugins.required` (`reqiured:`) left every plugin
    undeclared, so none ran and their findings were absent rather than clean.

  Both now print on the same `[degraded]` channel as an undeclared plugin,
  naming the offending keys and the impact, on stderr and not suppressed by
  `--quiet`.

  Reported rather than fatal, deliberately: erroring would break every existing
  config carrying a stray key the moment a fleet upgrades, and a scanner that
  refuses to run is its own coverage loss. Verified against the real configs in
  this repo, fortify and statekit — none produce a warning.

## [1.28.0] - 2026-08-10

Minor rather than patch: `nox fix` now **fails a run it would previously have
reported as successful**, when a remediation lands a package below where it
started. That is the intended behaviour and the point of the release, but it
is a behavioural change for anyone scripting `nox fix`.

### Fixed

- **`nox fix` could downgrade a dependency, reintroducing the vulnerabilities
  it was meant to remove.** `planUpgrades` used each advisory's `fixed_in`
  directly as the target and never compared it with the installed version.

  An advisory's `fixed_in` is the version that closed *that* advisory, not the
  newest safe version, so a package with several advisories yields several
  fix versions — routinely including ones below what is already installed. The
  planner emitted one action per advisory and applied them in sequence, so the
  **last one won by accident**. That is order, not safety.

  felixgeelhaar/specular#51 was this: `golang.org/x/crypto` 0.54.0 → 0.51.0,
  putting nine critical advisories into a repo that scanned clean — in a PR
  titled `chore(security): nox remediation`.

  Candidates are now aggregated per package and the **highest** fix chosen,
  which clears every advisory below it in one move, and three refusals apply:

  - never a version at or below the installed one;
  - never a prerelease when the install is a stable release
    (felixgeelhaar/orbita#49 pinned `google.golang.org/grpc` to `v1.81.0-dev`,
    a real upstream tag but a development marker);
  - never a non-empty installed version nox cannot order — no ordering means
    no way to know the move is forward.

  An *absent* installed version is deliberately treated differently from an
  unparseable one: some scanners do not report it, and refusing there would
  silently stop remediating whole ecosystems. Absence is not evidence of a
  downgrade, so only the prerelease guard applies.

  Both incidents are covered by regression tests built from their real
  advisory sets.

- **`nox fix` now verifies what actually landed, not just what it planned.**
  After applying, it re-reads the manifests and fails if any package ended up
  below where it started.

  Planning correctly is not landing correctly: `go get` resolves against the
  whole module graph, so a constraint elsewhere can pull a package under the
  requested version, and a package manager can simply do something other than
  what was asked. The planner cannot see either.

  Ecosystems whose resolved version nox cannot yet read are reported as
  **unverified** rather than counted clean — unchecked is not the same as
  verified, and a guarantee that quietly covers less than it claims is the
  failure mode this whole change exists to prevent.

### Security

- `brace-expansion` 5.0.8 → 5.0.9, closing a high-severity DoS advisory (#449).

### Changed

- `github.com/openai/openai-go/v3` 3.49.0 → 3.50.0 (#450).

## [1.27.0] - 2026-08-08

The action can install the plugins a project requires.

### Added

- **The GitHub Action installs `plugins.required`** (#447)

  nox runs only the plugins named in `plugins.required`, reporting anything
  unlisted as `[degraded]` with its findings absent. The action installed nox
  and scanned, but never installed plugins — so a repository scanning through
  it could not satisfy a requirement at all. Declaring one made every run
  degraded; declaring none silently gave up the coverage.

  Both outcomes were reached in practice: `nox-plugin-freshness` deleted its
  requirement and ran without SAST, and `klarlabs-studio/roady` kept
  hand-rolled install steps rather than adopt the action.

  `nox install` already did this, so the action now calls it. A repository with
  no `.nox.yaml` is unaffected, an install failure is fatal rather than a
  silently reduced scan, and cosign is installed only when the project declares
  plugins.

### Fixed

- **Plugin enrichments are serialized to `findings.json`** (#441)

### Changed

- Dependency and action-pin remediation (#442, #443, #446)


## [1.26.0] - 2026-08-01

A shared CI workflow can finally declare the plugin it installs.

### Added

- **`NOX_REQUIRE_PLUGINS`** (#436) adds to `plugins.required`, comma-separated.

  A plugin only contributes findings when it is declared, and declaration lived
  only in a per-repository `.nox.yaml` — the wrong place for a fleet. A shared
  workflow installs the same analysis plugin everywhere and pins its version
  centrally, but could not say the one thing that makes it take effect, so every
  repository without its own `.nox.yaml` got reduced coverage. 1.25.2 made that
  visible; this makes it fixable in one place rather than thirty.

  It adds to what the repository declared and collapses duplicates, so setting
  it fleet-wide can only widen coverage — it can never silently drop a plugin a
  repository asked for.

  An environment variable rather than a flag because the callers are reusable
  workflows: a job-level `env:` reaches every `nox` invocation in the job
  without threading an argument through each call site.

## [1.25.2] - 2026-08-01

Two false-positive reductions, and a scanner that now admits when it ran less
than you asked for.

### Fixed

- **An installed plugin no longer goes silently unused** (#403, #434). A plugin
  contributed findings only if it was also named in `plugins.required`, and
  nothing recorded the difference — so `nox plugin install nox/taint-analysis`
  followed by `nox scan .` got part of the plugin's coverage with no indication
  anything was missing.

  It looks like it worked, which is the dangerous part: the built-in Go taint
  model still reports TAINT-002 and TAINT-004, so only the plugin's additional
  TAINT-003 is absent. Reduced coverage was indistinguishable from full
  coverage.

  Declaration still activates a plugin. What changed is that skipping one is
  visible — one degradation names the installed plugins that did not run and
  says how to enable them.

  Running every installed plugin regardless was implemented and measured first.
  It collapses the precision corpus, 1.0000 to 0.3394 with 72 new false
  positives from rules belonging to plugins installed for other purposes, so
  declaration was kept and the silence fixed instead.

- **Entropy rules stop flagging identifier shapes** (#430). SCREAMING_SNAKE_CASE
  constants in template strings, lowercase dot-chains and template braces are
  excluded from entropy candidates. Measured on `openai-agents-python`: 77
  findings removed, none added, of which 64 were Python test function names such
  as `test_cloudflare_create_uses_client_timeouts` reported as possible secrets.
  The predicates sit in `isLikelyNotSecret`, so SEC-161, SEC-162 and SEC-446
  benefit alongside SEC-163.

## [1.25.1] - 2026-08-01

One false positive, in the rule most likely to be pointed at a Go codebase.

### Fixed

- **A method call is no longer read as a value by the entropy matcher** (#432).
  `extractAssignmentRHS` treats `:` as an assignment operator, which is right
  for YAML and JSON (`api_key: abc…`) but also fires on a struct-literal field
  in Go, Rust or Swift:

  ```go
  Hook: domain.PrePush.ConfigKey(),
  ```

  The "RHS" extracted there is the selector expression
  `domain.PrePush.ConfigKey`, which has no value at scan time. Three guards each
  just missed it: `isTokenChar` accepts `.`, so the whole chain is captured;
  `isCamelOrPascalCase` bails on the first non-alphanumeric, so a *dotted*
  identifier is never recognized as one; and at 24 characters its Shannon
  entropy is 4.085, over SEC-163's context-boosted 4.0. The result was reported
  as a "high-entropy hex string" while containing no hex.

  A token immediately followed by `(` is a call, and a literal secret is never
  followed by an open paren, so skipping those costs no recall. Measured on two
  corpora with both binaries built from the same tree: 5 findings removed on
  one repo and 1 on nox's own, **0 added** on either. Four of the six were
  `base64.StdEncoding.EncodeToString`.

  Two related problems are deliberately left open rather than folded in. A
  selector chain with no call parens (`Hook: domain.Config.SomeKey,`) still
  reaches the entropy check — filtering dotted identifiers generally is riskier
  than it looks, since a JWT is also dot-separated and its header segment is
  short enough to pass a naive identifier test. And `hasSecretContext` matches
  keywords by substring, so `ConfigKeyword` matches on `key`, as `monkey` and
  `tokenize` would; changing that shifts which lines are eligible at all and
  wants its own measurement.

- **`git` auto-gc no longer races `t.TempDir` cleanup** (#427), which had been
  failing releases intermittently rather than failing anything real.

## [1.25.0] - 2026-07-28

Taint recall across nine languages, and the reason it took this long to notice
the gaps: the guard that was supposed to catch them had never run.

### Added

- **Twelve of the thirteen documented taint recall gaps are closed**, across
  Clojure, C++, Dart, Elixir, Groovy, Kotlin, Objective-C, Perl, PowerShell,
  Ruby, Shell and Swift. Each was a construct where a real flow reached a real
  sink and nox stayed silent, and each was annotated in a precision suite as
  ground truth rather than left undocumented. Several turned out to share one
  cause, which is why they closed in groups:

  - **Pipelines and threading.** Elixir's `|>` bound the value into the first
    stage only; PowerShell's `$x | Cmdlet` was not modelled at all; Clojure's
    `->`/`->>`/`some->`/`cond->` rewrite argument position at read time. All
    three now carry the value to the stage where the sink is. The shapes are not
    interchangeable — PowerShell cmdlets are paren-less, so peeling one pipe at
    a time swallows the rest of the chain, and Clojure needs the threaded value
    to have a NAME because the engine taints a variable at its binding. (#414,
    #415, #419)
  - **Lambda and higher-order dispatch.** Kotlin's `.let { }` and Groovy's
    `.with { }` are one concept — the lambda parameter aliases its receiver.
    Clojure's `apply` and `map` pass the real callee as data, so the sink is
    never a literal call head. (#417)
  - **Receiver and container binding.** An assignment to a member field
    (`task.arguments = [...]` then a bare `task.launch()`) or a container element
    (`$args{cmd} = $ENV{CMD}`) bound no name, so the taint was lost at the store.
    Both bind now, field-insensitively, enabled per language as a corpus demands
    it. (#418, #420)
  - **Cross-unit shared state.** A source landing in a Ruby `@ivar` or a Perl
    `our` global in one method and read by a sink in another is now joined. Only
    syntactically shared names participate — a local never joins, so same-named
    locals in one file do not collapse into one variable. (#420)
  - **Declarations that also assign.** `local x="$1"`, `std::ifstream in(path)`
    and `%{"file" => path} = conn.params` each bind a value the recognizer
    previously discarded. (#416, #417)

  All nineteen precision suites hold **precision 1.000 with zero false
  positives**. Validated against roughly **15,700 real files** across nine
  languages — cloned projects including ring, reitit, compojure, clj-http,
  Phoenix, Plug, Ecto, apache/groovy, Spock, Grails, dart-lang and flutter — with
  findings diffed by fingerprint between builds.

### Fixed

- **`DATA-005` was titled "hardcoded public IP" and matched every dotted quad**,
  so loopback and RFC 1918 addresses — the common case in real configuration —
  were reported. `DATA-001` and `DATA-005` also flagged the RFC 2606/5737
  reserved documentation values that exist precisely so examples have an address
  to use. Candidates are now parsed and classified in code rather than by
  regex alternation. On the release corpus this is `DATA-005` 3 findings to 0 on
  one repository and **`DATA-001` 112 findings to 2** on another. (#413)
- **A Clojure keyword inside a data literal was recorded as a source**, so
  CONSTRUCTING a request map — what every test fixture, mock and benchmark in the
  ecosystem does — marked the value untrusted. A keyword is a source only in
  function position, `(:headers req)`, which reads a request; as a key it builds
  one. Found on real projects; all twenty precision suites scored 1.000 on it.
  (#421)
- **Four shell sink-modelling defects** exposed by the `local` fix, each a false
  positive on real scripts: `isShellCommandByte` stopped at `-` despite its own
  comment saying otherwise, truncating `exec-add-path` to the `exec` sink; `exec`
  matched an I/O redirection that executes nothing; `curl --output "$path"` had
  its output path treated as the SSRF-controlling value; and path-qualified
  commands (`/usr/bin/curl`) resolved to no callee. (#416)
- **A crash on malformed input.** The shell double-quote scanner treated `\` as
  escaping the next byte without checking one existed, running the index past
  end-of-line. A scanner must not panic on input it is pointed at. (#416)
- **The precision ratchet misread its own metric.** `findings-per-issue` is a
  distance-from-1.00 measure, but was gated as strictly lower-is-better, so
  closing a false negative — which necessarily raises it toward the ideal — was
  reported as a regression. Every genuine recall fix would have needed laundering
  through a baseline regeneration. (#414)

### Changed

- **The rule-behaviour diff now covers the taint engine.** It runs two builds
  over pinned real repositories and reports what changed per rule, and it had
  never fired on a taint change: the path filter covered `core/analyzers/**` and
  `core/rules/**`, while every taint change lives in `core/taint/**`. Six taint
  pull requests merged unguarded. `core/taint/**` and `core/lexctx/**` are now in
  the filter, and the corpus — previously two Go/IaC repositories, which could
  not have shown a taint regression in any language — gains three entries chosen
  by measuring which produce signal, not by intuition. (#422)
- **The precision suites carry failing samples again.** Eighteen of nineteen had
  reached recall 1.0, at which point a corpus can only detect regressions and can
  no longer say what the engine cannot do. Seven annotated false negatives now
  stand — Clojure `partial`/`comp`/`as->`, shell `xargs`/pipeline-fed commands,
  Dart cross-method fields and list elements — each verified to miss before being
  added, each naming what would close it. The corresponding recall numbers are
  deliberately below 1.0; precision is unchanged at 1.000. (#424, #425)
- **Three limits documented that no longer existed** — shell arrays, shell
  `${var//a/b}` transforms and PowerShell splatting — were corrected and pinned
  with regression samples. A documented gap that is not real is the same defect
  as an unguarded one, in the other direction. (#424, #425)
- **A partially tainted URL is still reported as SSRF**, and `docs/design/
  sast-taint.md` now says why, with the number that justifies it: across ~14,000
  real files the engine emits 8 `TAINT-006` findings in total, 2 of them this
  class. Narrowing it needs URL-structure modelling; the doc names what would
  change the decision. (#423)
- **`tp_ssrf_field.dart` was withdrawn.** Its comment described a tainted URL in
  `req.url` fetched by `client.send(req)`; its code used a constant URL and put
  the tainted value in a header, so the annotated CWE did not hold. The premise
  is not realizable in Dart — `HttpClientRequest` has no settable URL field, and
  across 1213 real Dart files there is not one `request.url = ...` assignment.
  Replaced by two gaps that are real. (#425)

## [1.24.0] - 2026-07-27

### Added

- **World-writable file and directory modes are now reported (`PERM-001`,
  `PERM-002`).** A fleet that drops gosec in favour of nox loses G301
  (`MkdirAll`), G302 (`Chmod`) and G306 (`WriteFile`) outright — 22 findings
  across 14 Go repositories with no nox equivalent. `os.WriteFile`,
  `os.OpenFile`, `os.Chmod`, `os.Mkdir`, `os.MkdirAll` and `ioutil.WriteFile`
  are matched on the Go AST, so a permission literal in a comment, a string, or
  a same-named project helper is not a finding. Both octal spellings, mode
  conversions (`os.FileMode(0777)`, `fs.FileMode(…)`) and OR chains are
  evaluated. (#405)

  **The threshold is the world-write bit (`0o002`), not gosec's 0600/0750.**
  Under gosec's defaults `0o644` and `0o755` are findings, which in this
  repository alone would be 503 of them — those modes are Go's own idiomatic
  defaults, so reporting them is a preference rather than a vulnerability
  signal, and it is why gosec's permission rules are among the most-suppressed
  in the fleet. World-writable is different in kind: any local user can rewrite
  the contents, no idiom requires it, and the finding is actionable without
  knowing what the file holds. World-readable and group-writable are
  deliberately not reported. A world-writable directory carrying
  `os.ModeSticky` is the /tmp model and is not reported either.

  Medium severity at high confidence, matching gosec's own rating for the
  family. Note that a gate keyed on net-new critical/high will not fail on
  these; lower the threshold or key on `PERM-*` to make them blocking. The mode
  must be a literal in the call — a named constant needs `go/types` and is not
  reported, which is the correct direction to fail.

- **`HARDEN-001` / `HARDEN-002` — TLS misconfiguration in Go source.** Nothing in
  nox modelled `tls.Config`. Certificate validation could be switched off
  anywhere in a Go codebase and no rule said a word — a gap that matters now that
  teams are dropping gosec from their golangci config and running nox as the only
  code-level security tool. `HARDEN-001` reports `InsecureSkipVerify: true`
  (**high** — verification off means the connection is authenticated against
  nobody, and only critical/high fails a typical CI gate); `HARDEN-002` reports a
  `MinVersion` below TLS 1.2 (**medium** — RFC 8996 deprecates TLS 1.0/1.1, but
  the peer is still authenticated and a legacy floor is sometimes a defensible
  choice). Both cover the composite-literal and the post-construction assignment
  forms, resolve an aliased `crypto/tls` import, and carry `gosec: G402` in
  metadata. (#405)

  **This one is parsed, not pattern-matched.** `InsecureSkipVerify:\s*true` also
  matches a comment — grpc's xds credentials contain "InsecureSkipVerify needs to
  be set to true because …" — and no regex can tell `true` from a variable. The
  rule uses `go/parser`, which nox already depends on for Go taint extraction, so
  the check is exact and adds no dependency. Measured over 117,731 real Go files
  in a module cache: 72 findings, every sampled one a genuine assignment; a loose
  regex over the same corpus returns 82, of which 12 are comments.

  **Deliberately not reported**, so nobody has to discover it the hard way:
  `InsecureSkipVerify: skipVerify` (a variable's value is not resolvable without
  `go/types`, and reporting it anyway would fire on every config-driven client),
  and `_test.go` files (tests legitimately dial httptest servers with self-signed
  certificates; a high-severity finding on each would get the rule suppressed
  wholesale). A struct that is not provably a `crypto/tls.Config` — a wrapper
  with its own `InsecureSkipVerify` field, or an assignment whose receiver type
  needs `go/types` — is still reported, at medium confidence.

- Findings from `HARDEN-*` and `CRYPTO-*` now carry a family label in the scan
  summary ("Transport Security", "Weak Crypto") instead of falling into "Other",
  where a broken primitive was invisible at a glance. (#405)

- **`CRYPTO-002`** — predictable randomness (CWE-338): a `math/rand` or
  `math/rand/v2` draw used for a security-bearing value in Go. High severity,
  medium confidence. This is the class gosec reports as G404, which Go
  codebases lost when they dropped gosec from their lint config. (#405)

  **It does not flag `math/rand`.** `math/rand` is the *correct* tool for retry
  jitter, backoff spread, load balancing, sampling, shuffling and test
  fixtures, and those call sites outnumber the dangerous ones. The rule fires
  only where the names around the draw say the value is security-bearing — the
  variable, struct field, buffer, called function or enclosing generator
  function resolves to a word like `token`, `secret`, `key`, `nonce`, `salt`,
  `password`, `session`, `iv`, `apikey`, `csrf`, `otp` or `auth` — and a word
  like `jitter`, `backoff`, `retry`, `sample`, `shuffle` or `cache` anywhere in
  that context vetoes it outright. `crypto/rand` is never flagged: the file is
  parsed and the import path resolved, so `rand.Read` from `crypto/rand` (the
  fix this rule recommends, and identical in text) is distinguished from
  `rand.Read` from `math/rand`.

  **Measured before shipping, on real code.** Across the Go module cache, 851
  non-test files that import `math/rand` produce 4 findings; a fleet of 23 Go
  repositories (7,720 files) produces 0, and every one of gosec's 9 G404
  reports in that same fleet is a documented-benign jitter, chaos-test or
  simulation call that this rule correctly stays silent on.

  **It misses things, by construction.** A generator whose variables and
  function are named neutrally is not caught, nor is a value that reaches a
  security name a statement later, nor a dot-imported `math/rand`. Recall was
  traded away for silence on purpose: this rule is intended to be safe to gate
  on, and the absence of a finding is not evidence that a file generates its
  secrets safely.

### Fixed

- **`CRYPTO-001` missed the one-shot digest call, which is the commoner one.**
  The rule matched the CONSTRUCTOR form and nothing else, so `md5.New()` was
  reported and `md5.Sum(b)` — in the same file, same package — was not.
  `sha1` behaved identically. `Sum()` is the more idiomatic of the two calls, so
  the shape being missed was the one people actually write: a scan of
  `klarlabs-studio/agent-go` reported 10 findings before and 18 after, every new
  one a `Sum()` call the rule had been silent about, and none removed.

  The constructor-only pattern existed for a good reason — matching the bare
  word `md5` would flag a variable named `md5sum` and the word in a comment. The
  fix keeps that property by matching the package-qualified call
  (`md5.Sum(`/`md5.New(`) rather than the algorithm name, so an identifier and
  prose still do not match. Both call shapes are now asserted together in one
  test so they cannot drift apart again. (#402)

### Changed

- **`CRYPTO-001` now covers all 15 languages core's SAST supports, up from 5.**
  The rule was Go, Python, JavaScript, TypeScript and Java only; C, C++, C#,
  Kotlin, Objective-C, PHP, Ruby, Rust, Shell and Swift were silent, as were the
  JS/TS variant extensions (`.jsx`, `.mjs`, `.cjs`, `.tsx`, `.mts`, `.cts`).
  Coverage now also includes 3DES and ECB mode alongside MD5, SHA-1, DES and
  RC4, and — as in Go — both the streaming and one-shot call shapes wherever a
  language offers both (`MD5_Init` *and* `MD5()`; `MD5.Create()` *and*
  `MD5.HashData()`).

  **Two languages are deliberately narrower than they could be.** PHP does not
  match bare `md5()`/`sha1()`: they are global functions, among the most-called
  in the language, and overwhelmingly used for cache keys, ETags and Gravatar
  hashes (which the Gravatar protocol *requires* to be MD5). Flagging them would
  put a finding in nearly every PHP file in existence, and a rule like that gets
  globally disabled — taking the genuinely broken `mcrypt_*` and
  `openssl_encrypt(…, 'des-ecb', …)` detections down with it. Shell does not
  match `md5sum`/`sha1sum`/`shasum`, which verify downloads against accidental
  corruption rather than an attacker; only `openssl enc` with a broken cipher is
  matched there.

  Patterns stay bound per extension. `Digest::MD5` is a Ruby constant path,
  `md5::compute` is a Rust path and `MD5(` is an OpenSSL C function; a test
  feeds every language's positive corpus through every other language's
  extension and requires zero matches, so one language's vocabulary cannot
  manufacture findings in another's files. Two known-noisy shapes are excluded
  by name: `Cipher.getInstance("RSA/ECB/OAEP…")`, where JCA's "ECB" is a
  historical misnomer for correct RSA padding, and `printf("MD5 (%s)…")`, which
  is OpenSSL's own output format rather than a call.

  The rule reports **zero findings on nox's own repository**, before and after.
  (#405)

- **`MEMSAFE-001` — integer truncation that sizes memory.** A value narrowed to
  a smaller integer type, or flipped signed→unsigned, and then used as a
  `make()` size or a slice bound. A wire-decoded length converted
  `uint32`→`int32` goes negative above 2³¹ and panics the allocation; a length
  truncated to `uint8` silently mis-frames anything longer than 255 bytes. Both
  were found in widely deployed networking libraries while validating the rule.
  Medium severity, so it reports rather than gates. (#405)

  **This is deliberately not gosec's `G115`.** Measured before implementation,
  gosec's own rule produced 96 findings across sixteen fleet repositories plus
  nox itself, with **zero** true positives — `int32(len(out))` filling protobuf
  count fields, `byte(addr>>24)` extracting an IPv4 octet, `byte(nano%10)`
  formatting a digit. That is how a rule earns 63 blanket suppressions. Nox
  reports only the shape where truncation is a memory-safety bug, and stays
  silent on all 96. On `segmentio/kafka-go`, gosec reports 156 findings of which
  two are a real bug; this rule reports one, and it is the bug.

  Masks, modulo, logical shifts on unsigned values, comparison guards written
  through a conversion (`if uint32(r) <= MaxLatin1`), and `len`-derived values
  narrowed to 32 bits or more are all suppressed — each one a class observed
  firing on correct code. A bare index `s[i]` is not treated as a sink: it is
  syntactically indistinguishable from a map lookup, and Go bounds-checks slice
  indexes anyway.

  **`go/types` was evaluated and rejected**, with the cost written down in
  `docs/design/go-integer-overflow.md`. Full `G115` parity needs type
  resolution, every Go importer needs a resolvable module graph and a toolchain,
  and nox scans checked-out trees offline in containers that have neither. The
  measured price is 64% of gosec's findings on nox's own source — all of which
  were false positives anyway. Conversions whose operand type is not provable
  from the enclosing function are not reported.

  `G103` (`unsafe`), `G602` (slice bounds) and `G104` (unhandled errors) are
  **not** implemented, with reasons: all 20 fleet `G103` findings are in
  generated protobuf code, `G602`'s useful half is this rule's slice-bound sink,
  and `G104` is already covered by `errcheck` in the fleet's golangci config —
  duplicating it would reintroduce exactly the double-reporting that retired
  `nox-plugin-sast`.

## [1.23.0] - 2026-07-26

### Changed

- **Ten duplicate IaC rule IDs retired; one condition, one finding.** Fourteen
  pairs of IaC rules fired on the same condition, so a single misconfiguration
  was reported twice — often at two different severities, which made a
  severity-keyed gate depend on which ID it happened to read. `continue-on-error:
  true` was both low (IAC-018) and medium (IAC-310); `privileged: true` was
  covered three times over. IAC-237, IAC-283, IAC-287, IAC-291, IAC-292,
  IAC-310, IAC-312, IAC-321, IAC-333 and IAC-337 are retired into the older rule
  that already reported their condition. Two of the fourteen were not duplicates
  but generic patterns swallowing specific ones (`encrypt\w*` over
  `storage_encrypted`, `replicas` over `minReplicas`); both rules survive, with
  the generic one bounded so the two no longer overlap. (#394)

  **Existing waivers keep working.** A retired ID stays valid in baselines, VEX
  statements, `nox:ignore` comments and `scan.rules.disable` — the rule that
  absorbed it reproduces its fingerprints, bounded by the retired rule's own
  pattern so no waiver is widened. Nothing needs to be rewritten. What changes
  is the count and the ID: gates or dashboards keyed on a retired ID should move
  to the surviving one (see "Retired rule IDs" in docs/usage.md).

### Fixed

- **`nox scan --staged` ignored every command-line flag.** The staged scan was
  invoked with an empty options struct, so `--offline`, `--no-osv`,
  `--rules`, `--baseline`, `--vex` and the rest were silently dropped — while
  `.nox.yaml` was still honoured, because the staged run copies the config into
  its temporary worktree. Config therefore beat an explicit flag, with no error
  and no warning. This is the `nox protect` / `install-hook` pre-commit path, so
  a hook told to scan `--offline` could still reach the network for OSV lookups.
  The core had already grown `RunStagedScanWithOptions`; this call site was never
  updated to use it. (#362)

- Flag-over-config precedence is now contract-tested across all thirteen settings
  that can be set in both places, each including the case that makes this class
  of bug possible: a flag passed **explicitly with a value equal to its default**,
  which a naive implementation cannot distinguish from an omitted flag. (#362)

### Added

- **Release smoke test.** Before a release publishes, the built binary scans a
  fixture carrying a hardcoded credential, a vulnerable dependency and an
  insecure Dockerfile, and asserts each rule family fires and that a VEX document
  is parsed *and applied*. Two regressions this month stopped the scan running
  entirely rather than reporting wrongly; an empty report is indistinguishable
  from a clean one at a glance. (#390)

- **Rule behaviour diff.** Pull requests touching rules scan sha-pinned real
  repositories with the last release and the candidate build, and report the
  per-rule delta. Corpus precision is measured on labelled fixtures and does not
  predict real repositories. A scan that fails to run is fatal; a rule delta is
  reported for review rather than failing the build, since most rule changes are
  intentional. (#390)

- A build-time guard rejects any two IaC rules that fire on the same input, so a
  new duplicate cannot be introduced. (#394)

## [1.22.1] - 2026-07-26

### Fixed

- **`nox scan -vex` accepts OpenVEX v0.2.0 documents.** The current spec — and
  what `nox vex init` output is fed back into — models `vulnerability` and
  `products` as objects (`{"@id": "CVE-…", "name": "CVE-…"}`) rather than
  strings. `core/vex` typed both as strings, so loading such a document failed
  with exit 2 *before the scan ran*, reporting no findings at all. Both shapes
  are now accepted, preferring `@id` over `name`. (#389)

### Added

- **Release smoke test.** The built binary is now scanned against a fixture
  carrying a hardcoded credential, a dependency with a known advisory, and an
  insecure Dockerfile before a release is published, asserting each rule family
  fires and that a VEX document is parsed *and applied*. Two regressions this
  month stopped the scan running entirely rather than reporting wrongly — an
  empty report is indistinguishable from a clean one at a glance. (#390)

## [1.22.0] - 2026-07-26

### Added

- **`nox verify-secrets` — asks the issuer whether a detected credential still
  works.** A detected secret and a live secret are different findings. "This
  looks like a GitHub token" is a backlog item; "this is a working token" is an
  incident, because the credential is already public and deleting the file does
  not invalidate it. Only the issuer can tell the two apart, and the check needs
  no privilege beyond the leaked credential itself.

  ```
  nox verify-secrets --input out/findings.json

    SEC-003  config/app.js:1   LIVE   authenticates against the GitHub API (ghp_…)
    checked 1 credential(s); 1 still authenticate
  ```

  Exit status is 1 when anything still authenticates, so a pipeline can act on
  it without parsing output.

  This is deliberately **not** revocation. Revoking a credential means calling
  the provider's API with *another* credential, usually one more privileged than
  the key that leaked — a nox that could revoke your AWS keys would hold AWS
  admin credentials and be a better target than the leak it defends against.

  Two properties hold the feature together and are enforced by tests. **The
  endpoints are compiled in**: verification transmits a live credential to a
  third party, which is defensible only because that party is the issuer, and a
  configurable endpoint would make this an exfiltration primitive inside a
  security scanner. **The secret never appears in output** — not in a message
  and not in an error; the transport failure is deliberately not wrapped,
  because a `url.Error` carries the request and the request carries the
  credential.

  Anything other than a clear yes or no — rate limiting, an outage — reports
  `unknown`. Calling a live credential `revoked` because the issuer was briefly
  unreachable would be worse than not checking at all.

  `findings.json` still contains no secrets: a finding carries a file and a
  column range, and verification re-reads the file at that location, so reports
  remain shareable. A location that no longer fits the file is an error rather
  than a best guess.

  Covers GitHub tokens (`SEC-003`, `SEC-213`, `SEC-435`, `SEC-495`, `SEC-496`).
  AWS is absent deliberately: verifying an AWS key needs SigV4 request signing
  and the paired secret access key, which is a different shape of work rather
  than another entry in a table. (#386)

## [1.21.0] - 2026-07-26

### Added

- **`nox fix --outdated` now covers seven ecosystems**, up from Go alone: Go,
  npm, PyPI, Cargo, RubyGems, Composer and NuGet.

  Go resolves through `go list -m -u -json all`, which already understands
  replace directives, retractions and the module graph. The rest query their own
  registry directly, so *planning* needs no toolchain installed; only applying an
  upgrade shells out to the native command.

  Currency needs two things vulnerability scanning does not, which is why the
  dependency analyzer could not simply be reused. **Directness**: packages are
  parsed from lockfiles, which are flat and contain the whole transitive
  closure, so upgrading one writes an explicit requirement for something the
  project never imports. Names therefore come from the manifest (`package.json`,
  `Cargo.toml`, `Gemfile`, `composer.json`, `*.csproj`, `requirements.txt`) and
  resolved versions from the lockfile — a manifest range like `^4.18.0` is not a
  version, and one with no lockfile entry is skipped rather than assigned a
  version it does not have. **The latest version**, which only a registry can
  answer.

  Every registry invites the wrong answer in a different way, and each is pinned
  by a test: npm publishes channels under `dist-tags` where only `latest` is
  stable; crates.io reports `max_version` (including prereleases) beside
  `max_stable_version`; Packagist returns newest-first but mixes in
  `dev-<branch>` aliases and release candidates; and NuGet returns an
  *ascending* list with prereleases interleaved, so the last element is often a
  beta. A package with no stable release yields no suggestion at all.

  **Anything that could not be checked is reported rather than assumed
  current.** A registry that cannot answer produces a `degraded:` line and never
  an empty string — `""` is indistinguishable from "already current", so one
  rate-limited registry would otherwise mark a whole project up to date. The
  same applies to a manifest that exists but cannot be parsed (which would
  otherwise drop its entire ecosystem from the run without a word) and to a
  directory containing no supported manifest at all (which reported everything
  as current having examined nothing). The all-current message is suppressed
  whenever any check failed to complete: there is a real difference between
  "checked seven ecosystems and everything is current" and "found nothing to
  check", and only one of them is good news. (#383)

  Maven and Gradle are parsed by the scanner but deliberately have no currency
  resolver: `maven-metadata.xml` has no single "latest stable" and Gradle has no
  canonical upgrade command, so applying would mean rewriting build files — a
  different risk class from running `bundle update`. (#378, #381)

### Fixed

- Two defects that only live requests could surface, both invisible to stubbed
  tests. npm's full packument for `typescript` and `@types/node` each exceed
  8 MB, truncating the response and reporting every dependency as un-checkable;
  nox now requests the abbreviated document. And crates.io answers **HTTP 403**
  to clients that send no `User-Agent`, which Go's HTTP client does not set by
  default — so every Cargo lookup failed in reality while passing every test.
  Both now have regression tests. (#381)

## [1.20.0] - 2026-07-26

### Added

- **`nox fix --outdated` — an opt-in dependency currency pass.** By default
  `fix` upgrades a dependency only when a `VULN-001` finding names a `fixed_in`
  version: it acts on evidence of a vulnerability, not on the passage of time.
  That is the right default for a security tool, but it means `fix` cannot stand
  in for a version bumper, because a package that is merely old is never
  touched.

  The gap was observable rather than theoretical. `nox-remediate` ran green
  across all 18 plugin repositories on 2026-07-22, and every one of them was
  still on `github.com/nox-hq/nox v1.17.0` days later — working exactly as
  designed, and not doing the currency job at all, because it was never that
  job.

  `--outdated` is deliberately a separate flag. A security fix is something an
  operator wants applied without argument; routine version churn is a choice
  with its own risk of breaking a build. Folded together, you could no longer
  tell from the fact that `fix` changed something whether there had been a
  vulnerability — so currency upgrades report as `OUTDATED` and never as
  `VULN-001`.

  Narrow on purpose: Go only (`go list -m -u -json all` is an authoritative
  answer to "what is newer"); direct dependencies only, since indirect ones are
  `go mod tidy`'s business; major bumps held unless `--include-major`; and it
  never downgrades — a replace directive or a retracted version can make
  `go list` report an "update" that is not newer, which is the defect fixed for
  `VULN-001` in #372 and must not reappear on a new path.

  This is the first thing in `fix` that reaches the network, which is
  unavoidable: whether a newer release exists cannot be answered offline. It
  runs only behind the flag and never during a scan, so the offline-first
  guarantee for scanning is unchanged. (#378)

### Fixed

- Documented that `--outdated`, like `--content`, is a mode rather than a
  modifier: it returns before the dependency and Action passes, so
  `nox fix --outdated --actions` does the currency pass only and silently skips
  Action pins. Two invocations are needed for both.

## [1.19.1] - 2026-07-26

### Fixed

- **`nox plugin list` now says whether an installed plugin will actually run.**
  Installing a plugin puts it on the machine; listing it under
  `plugins.required` in the project's `.nox.yaml` is what enables it for a
  scan. That separation is deliberate — nox's first design constraint is that
  the same inputs produce the same outputs with no hidden state, so a globally
  installed plugin that ran automatically would make findings depend on which
  plugins happen to be present, and two developers on one repository would get
  different results.

  Nothing said so at the point it mattered. `nox plugin install` reported
  success, `nox plugin list` showed four columns all describing a plugin that
  was about to do nothing, and the scan came back quiet — which reads as "the
  plugin found nothing" rather than "the plugin never ran". The degradation
  model already reports required-but-not-installed, unusable-binary and
  integrity-mismatch; installed-but-not-listed was the one state with no
  signal, and unlike the others it is the expected result of following the
  install instructions.

  `plugin list` gains an `ACTIVE HERE` column reflecting the current
  directory's `plugins.required`, plus a note when any installed plugin is
  inactive. `plugin install` prints the `.nox.yaml` snippet to add, and only
  when the project does not already require it. Scan behaviour is unchanged.
  (#377)

- **The documentation was teaching the model that caused the confusion.** The
  README called declaring plugins "Recommended", which reads as a best practice
  rather than the thing that enables a plugin, and then offered "One-shot
  install (no manifest)" as an alternative path — which a reader takes to mean
  scanning works without the manifest. It does not. The commands in that
  section (`search`, `info`, `list`, `call`, `update`, `remove`) genuinely need
  no manifest because they address a plugin by name and never load `.nox.yaml`;
  only `scan` consults it. Reworded in the README and `docs/marketplace.md`.

## [1.19.0] - 2026-07-26

Six fixes, every one of them a case where nox reported something that was not
true, or failed for a reason that had nothing to do with security. Four of the
six blocked a repository outright.

### Fixed

- **A throttled version lookup no longer fails the security gate.** The action
  resolves `version: latest` through the GitHub API, and GitHub answers 403 when
  rate-limiting. `resolve_version` was a bare `curl -fsSL`, which exits non-zero
  on any 403 — so the action died before it ever reached `fetch_asset`, the
  function directly below it that had already been hardened against exactly this
  throttle. The symptom was distinctive and uninformative: `Nox PR Gate` failing
  in nine seconds with one log line, `curl: (22) The requested URL returned
  error: 403`, followed by a second red check when the SARIF upload found no
  file. Two failed checks, no scan performed, neither of them about security.

  Underneath it, the reason the throttle was reachable at all: `action.sh` has
  always sent `Authorization: Bearer ${GITHUB_TOKEN}` when that variable is set,
  but `action.yml`'s `env:` block never mapped it. A composite action's step
  sees only what that block maps, so the header expanded to nothing on **every
  run**, and both the version lookup and the asset download went out anonymous —
  against the 60-requests-per-hour budget shared by every job on the runner's IP
  address. A burst of CI runs hits that routinely.

  Both halves are fixed: the lookup retries on the same schedule as the
  download, and the token now reaches the script. If you would rather not depend
  on the lookup at all, pinning an explicit `version:` skips it entirely — the
  failure message now says so. (#375)

- **`VULN-001` no longer tells you to downgrade.** The remediation advice
  reported the first version listed as fixed for an advisory, which is not
  necessarily one that is newer than what you have installed — for a vulnerable
  package on a maintained older line, the suggestion could move you backwards.
  Fix versions are now resolved against the affected-range intervals and the
  installed version, so the recommendation is always forward. (#372)

- **One dataflow reported from both ends is now one finding.** A taint path
  discovered from its source and again from its sink produced two findings for a
  single flow, inflating counts and, on a gated repository, presenting the same
  problem twice. Flows are deduplicated on rule, path, source line, sink line
  and source variable. (#373)

- **A location-less finding no longer breaks the whole SARIF upload.** GitHub
  rejects an entire submission — every finding in it — when any result carries
  an empty `artifactLocation.uri`, with `locationFromSarifResult: expected
  artifact location`. One finding that could not be tied to a file therefore
  discarded the report. Findings without a location now emit no `locations`
  array at all, which SARIF permits, and the rest of the report uploads. (#370)

- **An explicit `-format` is no longer overridden by `.nox.yaml`.** A flag given
  on the command line lost to the config file, so the one way to override a
  project setting for a single run did not work. The flags now default to empty
  so that "absent" is distinguishable from "set to the default", and an
  explicitly-passed value wins. Same fix for `-output`. (#371)

- **Five rule-precision defects that put false high/critical findings on the
  gate.** Each fired on ordinary code containing no credential and no
  vulnerability, and all five land in the high/critical band the shared CI gate
  fails on, so each one blocked a repository outright.

  `SEC-147` matched the Resend prefix at the seam of an identifier —
  `TestSessionSto`**`re_`**`LoadsLegacySnapshot…` supplies `re_` and 38
  alphanumerics — and reported a high-severity API key on a Go test function
  name. `SEC-003` and `SEC-213` had the same seam for `ghs_`. All three now
  require a word boundary on the left; an issued key never continues a
  preceding word.

  `SEC-435` required its `gh[pousr]_` prefix and exactly ONE further character,
  so any five-character run beginning `ghs_` was a GitHub token — including
  `"ghs_fake_install_token"`, a shape GitHub does not issue. It now requires
  the issued shape (prefix plus 36 alphanumerics), which costs no detection:
  every well-formed token is already covered by `SEC-003`/`SEC-213`/`SEC-215`/
  `SEC-216`/`SEC-217`.

  `SEC-004` reported **critical** on an HTML `placeholder=` attribute holding
  `-----BEGIN RSA PRIVATE KEY-----`. That is the hint shown in an empty field,
  telling a user what to paste; the key material is theirs and arrives at
  runtime. Matches inside display-text attributes (`placeholder`, `aria-label`,
  `alt`, `title`, `label`) are dropped. `value=` and every other attribute are
  untouched — a key really can be pasted into one of those.

  `SEC-240`, the Terraform password-field rule, fired on a Go doc comment:
  its separator alternation includes `,`, so
  `// "bot_token" pops a password input, "imap_password" pops …` parses as a
  field, a separator and a quoted value. A comment holds prose describing
  configuration, not configuration. The assignment-shaped rules — derived from
  the rule table, not a hand-kept list — no longer match inside comments.
  Provider rules are unchanged: a full token in a comment is a real leak and is
  still reported, as is a credential genuinely left in a commented-out
  assignment, which the generic keyword rules still catch.

  `AI-049` ("AI output passed to eval/exec", CWE-95) fired on textbook
  parameterised SQL — ``db.Exec(`INSERT INTO schedules (id, prompt) VALUES (?,
  ?)`)`` — because the AI-vocabulary token it gates on was a *column name*
  inside the query text. `database/sql`'s `Exec` evaluates SQL, not code, so
  CWE-95 cannot apply to it. A call executing a SQL statement is dropped. The
  discriminator is the SQL text, not the receiver: `db.Exec(model_output)`, a
  model emitting raw SQL that is then executed, still fires. (#374)

## [1.18.0] - 2026-07-26

### Fixed

- **`IAC-348` no longer fires on `artifacts.when: always`.** The rule matched
  the two words with a bare pattern, but everything it says is about job
  execution — "CI job runs regardless of previous failures", with a remediation
  warning about deployment jobs running after test failures. Under `artifacts:`
  the same words mean *upload the artifacts even when the job failed*, which for
  a scanner is the point: the run you most want `results.sarif` from is the one
  that failed the gate. nox flagged its own GitLab example for doing the right
  thing. A job-level `when: always` still fires, and a file containing both
  keeps the job one — the same context-confusion class as `IAC-193` on
  `shell: bash`.

- **`nox fix --actions` no longer breaks reusable workflows, and no longer
  pins prereleases.** Two defects, both of which fired on this repository.
  It rewrote a reusable-workflow reference to a digest, but `slsa-verifier`
  resolves a trusted builder's identity from the ref, so pinning
  `slsa-github-generator` by SHA makes it unverifiable; upstream requires a tag
  "contrary to the GitHub best practice for third-party actions ... but
  intentional due to limits in GitHub Actions". And tag filtering used a
  substring match, so `v2.1.0-rc.3` passed as `v2.1.0`, tied it once the suffix
  was discarded, then won the specificity tiebreak on dotted components — so a
  release candidate was chosen over its own release. Reusable workflows (any
  path under `.github/workflows/`) are now left alone; an action published in a
  subdirectory is still pinned.

- **SLSA provenance is generated again, and its absence now fails the build.**
  The pin above had made the generator unverifiable, and the run failed in a way
  where every job except an internal `final` step reported success. Nothing
  downstream inspected the release, so v1.14.0 through v1.17.0 shipped with no
  attestation at all while the project advertised SLSA Level 3. Those releases
  have been backfilled. A new job now reads the release and fails if no in-toto
  asset is present, because a green provenance job is not evidence that
  provenance exists.

- **A failing weekly dependency-CVE audit now raises an issue.** It runs only on
  the schedule, so its failures went to the Actions tab and nowhere else — when
  it began failing on a real advisory it failed every Monday for weeks with
  nothing surfacing it. One issue is reused rather than filed weekly.

- **The VS Code extension declares the editor version it actually needs.** It
  advertised `^1.75.0` while its own `vscode-languageclient` dependency required
  `^1.82.0`; VS Code gates installation on that field, so users on 1.75–1.81
  could install an extension that failed at activation.

### Changed

- **The VS Code extension moves to `vscode-languageclient` 10 and TypeScript 7**,
  with `moduleResolution: node16` — the legacy `node` setting predates `exports`
  maps, so v10's `vscode-languageclient/node` subpath was invisible to the
  compiler. `engines.vscode` rises to `^1.91.0` accordingly, landed together
  with the dependency so the manifest is never ahead of what it can serve.

- **The build moves to Go 1.26.5**, and the workflows read the toolchain from
  `go.mod` rather than repeating a hardcoded version in three places.

### Added

- **CI type-checks the VS Code extension.** It previously had none: no workflow
  ran `npm ci` or `tsc`, so every dependency bump to it merged on a green tick
  that had never compiled it — which is how a ReDoS advisory reached this
  repository through its toolchain. The job caught a broken bump on its first
  run.

- **Dependabot configuration.** `dependabot-auto-merge.yml` had been present
  with no `dependabot.yml`, so it sat there with nothing to merge and no update
  was ever proposed. Covers the Go module, GitHub Actions, the extension's npm
  tree, and the Dockerfile base image.

## [1.17.1] - 2026-07-25

Backfilled on 2026-07-26: this release shipped without notes. Everything below
was in the tag and has been in users' hands since; it is recorded here because a
release with no changelog entry is one nobody can audit.

### Fixed

- **SLSA provenance was silently absent from six releases.** `slsa-verifier`
  resolves a trusted builder's identity *from the ref*, so pinning
  `slsa-github-generator` by commit SHA makes the attestation unverifiable —
  contrary to the usual best practice for third-party actions, and stated as a
  MUST by the generator's own documentation. The generator's `subjects`,
  `generator` and `upload-assets` steps all reported success and only the
  `final` step failed, so v1.14.0 through v1.17.0 published with **no
  provenance at all** while the project advertised SLSA Level 3. The workflow
  now references the generator by tag. Verify any release with
  `gh release view <tag> --json assets` and look for `multiple.intoto.jsonl`: a
  green workflow run is not evidence the asset attached. (#354)

- **`nox fix --actions` caused that, and no longer can.** Two defects in the
  pin resolver, both of which fired on this repository. It rewrote *reusable
  workflow* references to a digest, which is what unpinned the SLSA generator;
  reusable workflows are now never rewritten. And its tag filter used a
  substring match, so `v2.1.0-rc.3` matched a search for `v2.1.0`, parsed to
  the same version, and won the specificity tiebreak — meaning a release
  candidate could outrank the release. Prereleases can no longer outrank a
  release. (#356)

- **The VS Code extension declared a version it could not honour.**
  `engines.vscode` advertised `^1.75.0` while its own `vscode-languageclient`
  dependency required `^1.82.0`. VS Code gates installation on that field, so
  anyone on 1.75–1.81 could install the extension and have it fail at
  activation. (#358)

- **The extension could not resolve modern package exports.** It compiled under
  TypeScript's legacy `node` module resolution, which predates the `exports`
  field, so `vscode-languageclient/node` was invisible to it (TS2307). Now
  `node16`. (#359)

### Added

- **CI for the VS Code extension.** It had none: no workflow ran `npm ci` or
  `tsc`, so every change to it — and every dependency bump — merged on a green
  tick that had never compiled it. That is how GHSA-mh99-v99m-4gvg
  (brace-expansion ReDoS) reached this repository, found later by a self-scan
  rather than by CI. The type-check job caught a real breakage on its first
  run. (#357)

### Changed

- Go 1.26.5, and the last hardcoded toolchain pins removed. (#360)
- Dependency updates: `vscode-languageclient` 10.1.0, `typescript` 7.0.2,
  `@types/node` 26.1.1, `golang.org/x/sync` 0.22.0, `golang.org/x/term` 0.45.0,
  `openai-go` 3.46.0, and base-image bumps for golang and distroless.
  (#341, #345, #346, #348, #349, #363)

## [1.17.0] - 2026-07-25

### Changed

- **Reachability is a regular plugin; nox no longer bundles anything.** The
  release archive contained one plugin, registered automatically on first run.
  That was never a coherent shape: the plugin system exists for optional,
  independently-versioned extension, so a plugin present in every release is
  neither optional nor built in, and it paid the costs of both — a process
  boundary and a sandbox policy for code as trusted as nox itself, plus release
  coupling and a separate "bundled" trust level with failure modes of its own.

  Two of those were live. The record named the binary inside the install
  prefix, which the package manager deletes on upgrade, so it dangled — the
  defect 1.16.3 repaired, though the record still sat at the mercy of the next
  upgrade. And the release pre-hook built the plugin with no `GOOS`/`GOARCH`,
  compiling once for the linux/amd64 release runner while the archive step
  copied that single binary into every platform's archive: on a current
  darwin/arm64 install the shipped plugin was an ELF x86-64 executable sitting
  beside a Mach-O arm64 nox, and running it exited 126. For as long as bundling
  existed, the plugin could not execute at all on four of six platform
  archives — which is why the stale path went unnoticed, since the fallback was
  doing the work regardless.

  Reachability now installs like every other plugin, from the registry it is
  already published to and signed in: `nox plugin install nox/reachability`, or
  by declaring it under `plugins.required` in `.nox.yaml`, which the scan
  auto-installs.

  **This removes reachability from a fresh offline install.** An existing
  install has its bundled record retired on first run with a notice naming the
  install command, rather than left claiming a plugin nox no longer ships. On
  Linux the bundled binary did work, so for those installs this is a real
  change in behaviour and is reported rather than silent; a plugin the operator
  installed themselves is never touched.

### Added

- **Dependabot configuration.** `dependabot-auto-merge.yml` had been present
  without a `dependabot.yml`, so it sat there with nothing to merge and no
  update was ever proposed against this repository. Every action here is pinned
  to a commit SHA — nox ships `IAC-013` to flag mutable tags — and a SHA pin is
  frozen by definition, so the pins aged silently: this repository was on
  `actions/setup-go` v6.4.0 while the plugin repositories had moved to v7.0.0.
  Covers the root Go module, GitHub Actions, the VS Code extension's npm tree,
  and the Dockerfile base image.

## [1.16.3] - 2026-07-25

### Fixed

- **A bundled plugin is re-pointed when the binary moves.** Bundled plugins
  were registered once and never revisited, and the recorded path names the
  install prefix of that release — a Homebrew Cellar directory, say — which an
  upgrade deletes. Nothing recovered from that, and almost nothing reported it:
  `nox doctor` said "binary missing" while `nox scan` said nothing at all and
  silently fell back to whatever else provided the plugin, or ran without it.
  Observed on a real install, where bundled reachability stayed registered
  against a deleted `0.8.1` prefix, so every scan quietly used a community
  build several versions behind the one shipped. Bootstrap now re-points a
  bundled record whose recorded path no longer matches the shipped binary and
  re-records its digest, so the integrity gate does not then refuse the
  correctly-located file. Only records nox created itself (trust level
  `bundled`) are touched — a plugin the operator installed deliberately is
  never overwritten. The gap was invisible because the test seam restated the
  production loop rather than calling it, so the test exercised a copy with the
  same defect and passed; it now calls the same function bootstrap runs.

## [1.16.2] - 2026-07-25

### Fixed

- **Ansible rules no longer fire on GitHub Actions files.** Every Ansible rule
  is scoped to `*.yml` / `*.yaml`, which is every YAML file in a repository —
  workflows and composite actions included. So `shell: bash`, which a composite
  action step is *required* to declare, matched `IAC-193` "Ansible task uses
  shell module". A GitHub Actions file is not an Ansible playbook, so the
  finding is categorically wrong rather than merely less severe; these are
  dropped rather than downgraded like the other GitHub Actions false positives,
  because a downgrade still leaves an operator triaging a rule that could never
  apply. Composite actions are now covered as well as workflows: the existing
  context pass keyed off the `.github/workflows/` prefix alone, which left
  `action.yml` — exactly where `shell:` is mandatory — uncovered. Real Ansible
  playbooks still fire; detection is by path, and a playbook is an ordinary
  `.yml` that never lives at `.github/workflows/` or `action.yml`.

## [1.16.1] - 2026-07-25

### Fixed

- **`scan.exclude` now binds analysis plugins.** A plugin's `scan` tool is
  handed only the workspace root and walks the tree itself, so it never saw the
  exclusions the operator wrote. Requiring the code-analysis plugins on nox's
  own repository took a clean grade-A self-scan (3 findings) to grade F (47),
  and 38 of those 47 were on paths `.nox.yaml` explicitly excludes —
  principally the intentionally-vulnerable fixture corpora that exist to be
  found by the precision and metamorphic harnesses, not by the self-scan.
  Plugin findings are now filtered host-side through the same matcher the
  walker uses, rather than by passing the patterns down: a plugin is
  third-party code and cannot be relied on to honour an exclusion it is merely
  told about.

- **Plugin findings are recorded relative to the scan root, like every other
  finding.** They carried absolute paths, so the same file appeared under two
  spellings. The unused-waiver check groups by path, so a file with both core
  and plugin findings was evaluated twice, each pass testing every waiver in
  the file against only its own subset — reporting four live waivers on this
  repository's Dockerfile as dead. The v2 fingerprint also hashes the path, so
  a plugin finding's identity embedded an absolute machine path and no baseline
  could match it on another machine or in CI. A repository-scoped finding (one
  naming the workspace root rather than a file, such as a missing private
  registry configuration) is now canonicalised to the empty path the
  suppression pass already reads as "repository-scoped rather than located",
  instead of failing to read a directory and degrading a healthy scan.

- **One gated plugin no longer disables every other plugin.** Registration was
  all-or-nothing per phase: requiring all installed plugins hit one declaring
  `needs_confirmation`, and the rejection aborted registration for the rest, so
  the scan fell back to built-in findings having silently run none of them —
  the exact failure degradations exist to prevent. Each plugin now registers
  independently and a rejected one is degraded on its own, naming the policy it
  violated.

- **`nox:ignore` written in documentation is no longer parsed as a waiver.**
  Because a waiver that matches nothing is reported, prose describing the
  syntax produced false "waives X but matched no finding" degradations against
  correct source — and that signal is the one used to find genuinely dead
  waivers. A directive's grammar is `nox:ignore <IDs> [-- reason]`: free prose
  after the rule IDs means the line describes a directive rather than issues
  one. A directive inside a string literal is a program printing the syntax,
  and one nested inside a comment that already began the line is an example —
  the `DocExample` marking that already covered markdown fenced blocks now
  covers source comments too. Both guards fail toward keeping the directive, so
  an unrecognised language behaves exactly as before.

- **Dead waivers are found in every scanned file, not only files that already
  had a finding.** The check was driven by findings grouped by path, so a
  waiver in an otherwise-clean file was invisible — which is exactly where a
  dead waiver hides, since the usual way one dies is the finding it covered
  getting fixed. Ten such waivers in nox's own source are removed here, each
  verified inert by deleting it and re-scanning. Removing a waiver can only
  cause a finding to be reported, never hidden. Files without a `nox:` marker
  are skipped before parsing, so the sweep costs no measurable scan time.

## [1.16.0] - 2026-07-25

### Added

- **`nox confirm` — an opt-in, active loop that turns a static AI prompt-injection
  finding into a confirmed (or refuted) exploit.** Static analysis can prove that
  untrusted input *reaches* an LLM; it cannot prove the model *obeys* it. `nox
  confirm` closes that gap: it reads a prior scan's `findings.json`, selects the
  AI findings (`AGENTFLOW-001`, `TAINT-AI-001`, `AI-PI-*`), fires an adversarial
  corpus at a running target, and writes `confirmations.json` with a per-finding
  **CONFIRMED** / **UNCONFIRMED** verdict — separating a true positive from a
  false positive that static analysis alone cannot. The verdict is
  **reflection-immune**: a response is scored a hijack only on a signal the model
  had to *produce* (the uppercase transform of a lowercase seed the payload
  carried, or a secret canary that lives only in the app's trusted system header
  and is never sent), so an app that merely echoes the payload can never
  false-confirm — an invariant asserted at startup, with the command failing
  closed if it is ever broken. This is a **distinct, active** command, never part
  of `nox scan`: it **refuses to run without `--authorize`**, the `--target` is
  operator-supplied, and nox states plainly that isolating the target is the
  operator's responsibility. Exit `1` on ≥1 confirmed exploit makes it
  CI-gateable. See `docs/confirm.md`.

- **Remote, signature-verified distribution for the predictive slopsquat feed
  (`SLOP-002`).** `scan.slop.feed` now accepts an `https://` URL in addition to
  the bundled feed. A remote feed is fetched, verified against both a SHA-256
  content digest **and** an Ed25519 signature bound to an operator-pinned key,
  then cached content-addressed (mirroring the plugin-registry cache) — a
  tampered payload, a wrong signing identity, or an unsigned feed under
  `require_signature` is rejected and recorded as a degradation, never trusted.
  It fails closed and stays offline-friendly: a verified feed serves from cache
  with no network, a fetch error falls back to last-known-good, and offline with
  no cache refuses rather than silently scanning without the dimension. **Off by
  default** — no feed configured is byte-identical to before. A scheduled
  `slopfeed-publish` workflow regenerates, signs, and publishes the feed and its
  public key as release assets, giving a stable URL operators pin by key.
  Ed25519-with-a-published-key rather than cosign keyless, deliberately: keyless
  verification needs a network round-trip at scan time, which would break the
  offline/deterministic guarantee. See `docs/slopsquat-feed.md`.

## [1.15.0] - 2026-07-25

### Added

- **Predictive slopsquatting (`SLOP-002`), via a signed, versioned feed.** Where
  `SLOP-001` reactively flags an import of a package that exists nowhere,
  `SLOP-002` flags an import whose *name* matches a curated list of high-risk
  targets an LLM is likely to hallucinate and that are currently unregistered —
  a name an attacker could claim to catch hallucinated installs. The feed is a
  versioned JSON document bound by a SHA-256 content digest with an optional
  Ed25519 signature (the same trust model as the plugin registry), parsed
  fail-closed: an unknown schema, a digest mismatch, or a required-but-invalid
  signature disables the dimension and records a visible degradation rather than
  crashing or trusting bad data. **Off by default** — with no feed configured,
  behaviour is byte-identical to before. Enable via `.nox.yaml`
  `scan.slop: {feed: bundled}`; a 62-name PyPI/npm feed ships bundled, and
  `cmd/slopfeed` regenerates it (read-only registry queries, never accusing a
  registered package). Learning stays central and signed; enforcement stays
  local, offline and deterministic.

- **`nox mcp baseline` / `nox mcp drift` — rug-pull detection for MCP servers.**
  `nox mcp baseline -- <server-cmd>` captures a reviewable baseline of an MCP
  server's tool manifest to `.nox/mcp-baseline.json` (sorted, diffable, commit
  it); `nox mcp drift` re-captures and reports drift — an added/removed tool, a
  changed description, a widened schema — as findings (`MCP-DRIFT-001..006`,
  a new code-exec tool critical, a poisoned description high) that flow through
  the normal findings.json / SARIF path, exiting non-zero for CI. This is the
  safe form of on-device adaptation: the baseline is data you diff and review,
  not a mutating rule. Both commands launch a user-supplied server subprocess
  and print a sandbox reminder — untrusted servers must be isolated; nox does
  not sandbox for you.

### Security

- **`brace-expansion` in the VS Code extension is bumped past a newly-published
  ReDoS.** GHSA-mh99-v99m-4gvg affects every `brace-expansion` up to 5.0.8, so
  the 2.1.2 pin an earlier release added (to fix a *different* brace-expansion
  advisory) became vulnerable when this one was published. Reached transitively
  through `minimatch` in the extension's build toolchain — not the extension's
  runtime — but a high-severity advisory nonetheless. The `overrides` entry now
  forces `^5.0.8`; the extension still compiles clean and nox's own self-scan
  returns to grade A.

### Fixed

- **A blank line before a Dockerfile instruction no longer mis-locates the
  finding or changes its fingerprint.** 16 regex-pattern IaC rules anchored with
  `(?im)^\s*KEYWORD`, and `\s` matches newlines — so under multiline matching a
  blank line before the flagged instruction (e.g. `USER root`, `ADD`, a `sudo`
  RUN) let `^\s*` begin the match on the *preceding blank line*. The finding was
  reported on the blank line, and its matched content gained a leading newline
  that perturbed the v2 fingerprint — a false-positive/false-negative pair under
  a semantics-preserving edit that also broke baseline matching. Anchored with
  `^[ \t]*`, which cannot cross a newline (the same correction the absence
  anchors got). Found by nox's own metamorphic corpus oracle.

- **AI prompt-injection findings are now role-aware — untrusted input reaching
  the *user* role behind a static system prompt no longer fires.** Reaching an
  LLM is necessary but not sufficient for a prompt-injection: `TAINT-AI-001` and
  `AGENTFLOW-001` fired whenever untrusted input reached a chat call, so the
  *recommended* pattern — user input placed in the `user` role while the `system`
  message stays static — was reported identically to the vulnerable pattern that
  interpolates it into the `system` role. Findings now carry a `sink_role`
  (`system`/`developer`/`user`/`unknown`) and suppress only the safe case:
  `user` role with a static, untainted system message present. Every system- or
  developer-role placement still fires, and ambiguity fails toward reporting —
  a dynamically-built message array, an unreadable role, or a non-Python call
  site keeps the finding, because a missed system-role injection is worse than
  an extra one. Python call sites only for now; other languages keep their prior
  always-report behavior (#319).

- **A `data:` URI payload is no longer mistaken for a secret.** A base64-encoded
  image inlined in HTML/CSS/Markdown reported as vendor API keys — nox's own
  dashboard, which carries a base64 PNG logo on one 28 KB line, produced 8
  high-severity "LOB / ELK API Key" findings from inside the image. The
  suppression for embedded blobs already existed but consulted a lexer, which
  returns no language for markup and stylesheets, so it never ran on the file
  types most likely to hold an inline image. The `;base64,` marker is
  unambiguous in raw bytes and now needs no language. Scoped to the payload
  span: a real credential elsewhere in the same file is still reported (#308).

- **Dockerfile "missing instruction" rules are no longer fooled by a comment or
  a blank line.** Two defects, opposite directions. A comment that merely
  *mentioned* an instruction disabled the check: `# no HEALTHCHECK needed`
  satisfied `IAC-121`, and `# LABEL maintainer is deprecated` satisfied
  `IAC-124` — a false negative, the check silenced by a comment claiming the
  instruction exists. And a blank line before a `COPY --chown` fired `IAC-123`:
  the anchor `^\s*COPY` matched from the preceding blank line because `\s`
  spans newlines, so the span was computed from the wrong line and the `--chown`
  went unseen — a false positive on idiomatic Dockerfiles. Instruction
  properties are now anchored to line start, and the anchors use `[ \t]*` rather
  than `\s*` (#311).

- **A keyword in a comment no longer satisfies an absence rule's required
  property.** The wider form of the rule above: a file-span rule whose property
  is a free keyword was satisfied by that keyword appearing in any comment.
  `IAC-153` ("artifact upload without attestation") never fired when a trailing
  comment said `# attested elsewhere`. The matcher now strips `#` comments
  before the property check — a comment cannot fulfil a "must be present"
  requirement. Conservative by construction: a `#` inside a quoted value, a JSON
  string or a URL fragment is never stripped, so no absent-property false
  positive is introduced (#314).

## [1.14.0] - 2026-07-22

### Added

- **The GitHub Action exposes `fail-on-degraded`.** nox has had the flag since
  1.11.0, but the Action never mapped it, so a workflow could not make "a check
  did not complete" fail the build without dropping to a raw `run` step — the
  gate most likely to rely on it was the one that could not reach it. An
  invariant test now fails the build if any declared Action input is not wired
  through to `action.sh`, which is the defect class that hid this one: an input
  can be declared and documented while silently never reaching the scanner.

### Changed

- **An exit 2 under `fail-on-degraded` no longer reports itself as a crash.**
  nox returns 2 both for a hard error and for an incomplete scan, and the Action
  annotated both as "Nox scan failed with exit code 2" — sending the reader to
  look for a failure that did not happen, when the scan had in fact run and
  written its reports. The annotation now names the degradation case and points
  at `meta.degradations`.

- **Dependency upgrades in the shipped binary**: `google.golang.org/grpc`
  1.82.0 → 1.82.1 and `golang.org/x/text` 0.38.0 → 0.39.0, applied by nox's own
  remediation run.

## [1.13.6] - 2026-07-21

### Fixed

- **`nox fix --actions` could pin a GitHub Action backward, to an older commit
  than the one already running.** It asked the GitHub Releases API for the
  latest version and consulted tags only as a fallback "for repos without
  Releases". That precedence is wrong: a Release is an announcement, but an
  Action is consumed by *tag*, so a repository that tags `v1.0.1` without
  cutting a Release is already serving it to every workflow pinned to `@v1`.
  Against such a repository nox planned a pin to the stale Release's commit and
  labelled it with the moving tag — a silent downgrade, performed by the feature
  whose entire purpose is supply-chain pinning. Both sources are now compared
  and the newer wins; on an exact version tie the more specific tag is preferred,
  because only it still means the same commit tomorrow.

- **Scanning a single file ignored that file's `nox:ignore` comments.**
  `nox scan main.go` joined every relative path onto the target as if it were a
  directory, producing `main.go/.nox/baseline.json` and `main.go/main.go`.
  Neither can exist. The baseline miss was reported as a degradation, but the
  failed re-read meant inline waivers were never parsed, so the scan reported
  findings the operator had explicitly waived — with the explanation buried in a
  message about a path they never wrote. Scanning one file is what a pre-commit
  hook or editor integration does. Relative paths now resolve against the file's
  directory, matching what config loading already did.

- **A dependency CVE in the VS Code extension.** `brace-expansion` 2.1.1, reached
  through `minimatch`, is vulnerable to exponential-time expansion of
  consecutive non-expanding `{}` groups (GHSA-3jxr-9vmj-r5cp). Pinned to 2.1.2
  via an `overrides` entry rather than by adding a dependency the extension does
  not import.

### Changed

- **nox no longer excludes its own CI workflows from its own scan.** The
  exclusion existed for one narrow reason — pinned commit SHAs and
  `GITHUB_TOKEN` references read as high-entropy secrets — but it dropped the
  whole file, silencing every analyzer rather than the noisy one. It hid 19 IaC
  findings on nox's own workflows, including a high-severity mutable-tag pin.
  Now scoped to the secrets analyzer alone.

- **Cross-platform tests run before merge, not after.** The matrix was selected
  by event, so macOS and Windows ran only on push to `main`; a Windows
  regression could not be observed until it had already landed, and a red `main`
  blocks nothing. Three Windows-only test defects had kept CI failing for over
  100 consecutive runs. The matrix is now selected by what a change touches.

## [1.13.5] - 2026-07-21

### Fixed

- **The GitHub Action no longer fails a scan because a download was throttled.**
  It fetched the nox binary and `checksums.txt` in a single unauthenticated
  attempt, so an HTTP 403 — which GitHub returns when many jobs pull release
  assets at once — failed the whole step. A burst of CI runs across the plugin
  fleet triggered exactly that, turning a security gate red for a reason
  unrelated to security. Both downloads now retry with backoff and send the
  token when one is available. A download that keeps failing still fails, with
  the final status reported.

## [1.13.4] - 2026-07-21

### Fixed

- **`nox plugin entry` emitted signature URLs for files that are never
  published.** It wrote the cosign v3 names — a detached `checksums.txt.sig` and
  `checksums.txt.sig.bundle` — but the plugin release workflows sign with cosign
  v4, which writes a single `checksums.txt.sigstore.json` and no detached
  signature. Registry entries therefore pointed at assets that did not exist, the
  signature download returned 404, the artifact was classified `unverified`, and
  `nox plugin install` was blocked by the default trust policy. Every plugin
  version published after the move to cosign v4 was uninstallable. The bundle URL
  is now the v4 name and the dead `.sig` URL is dropped.

- **SARIF now carries `security-severity`, so GitHub Code Scanning can classify
  nox alerts.** SARIF's `level` only distinguishes error/warning/note, and nox
  emitted nothing else, so every alert arrived in Code Scanning with no security
  severity: the UI could not filter or sort by it, and severity-based alert rules
  had nothing to match on. Every rule descriptor now carries a CVSS-style score
  banded the way GitHub reads it — critical 9.5, high 8.0, medium 5.5, low 2.0.
  Info is deliberately omitted rather than scored 0, which would render as "low"
  and overstate it.

## [1.13.3] - 2026-07-21

### Fixed

- **Documentation that demonstrates `nox:ignore` is no longer reported as a pile
  of unused waivers.** 1.13.2 began reporting waivers that suppress nothing,
  which is what you want for a mistargeted or stale waiver — but it also flagged
  every fenced code block showing the syntax, because sample secrets in docs are
  deliberately too short to match a rule. A directive inside a fenced code block
  in a markdown file is now recognised as illustrative and skipped by that
  report. It still suppresses a real finding on its target line, so a genuine
  waiver written inside a doc keeps working.

## [1.13.2] - 2026-07-21

### Fixed

- **A `nox:ignore` that suppresses nothing is now reported.** A dedicated
  directive applies to the next non-blank line, so a reason that wrapped onto a
  second comment line made the waiver land on that continuation comment — the
  finding below stayed reported, and nothing indicated the suppression had
  missed. A mistyped rule ID, or a waiver left behind after the finding was
  fixed, failed just as silently. Unused waivers now surface as a suppression
  degradation naming the file, line and rule. Correctly-applied waivers and
  deliberately-expired ones stay quiet (verified: nox's own self-scan, which
  carries many `nox:ignore` comments, reports none).

## [1.13.1] - 2026-07-20

### Fixed

- **The GitHub Action failed on any scan that produced no findings.** The action
  counted findings with `grep -c … || echo "0"`; because `grep -c` exits non-zero
  when there are zero matches, the fallback fired on top of grep's own `0` and
  wrote a two-line `findings-count` value to `$GITHUB_OUTPUT`, failing the step
  with *"Unable to process file command 'output' … Invalid format '0'"*. Any
  repository whose scan found nothing — for example a PR-scoped, changed-files
  gate on a change touching only `go.mod`/`go.sum` — saw its Nox gate go red for
  no real reason. The count is now always a single clean integer.

## [1.13.0] - 2026-07-20

A large security-hardening and correctness release. Two adversarial audits of
the scanner and its plugin trust boundary drove every change below; each fix
ships with a test that fails without it, and the false-positive precision suite
stays at 1.000/1.000 throughout.

### Security

- **The plugin↔host channel is now authenticated.** A plugin subprocess binds a
  gRPC server on a loopback port for the duration of a scan. That port was
  unauthenticated, so any other local process — or, behind a permissive
  firewall, any LAN peer — could connect and drive the plugin's tools. The host
  now passes a fresh per-launch token to the plugin and presents it on every
  call; the plugin rejects anyone else.
- **Plugin binaries are re-verified before they run.** The scan path trusted
  `~/.nox/state.json` wholesale and launched whatever binary it named. It now
  re-checks the executable against a digest recorded at install and refuses to
  run a plugin whose binary changed since — so tampering can only stop a plugin,
  never escalate one.
- **`nox plugin update` and required-plugin install now enforce the trust
  policy.** Only `nox plugin install` checked signature/trust violations; the
  update and `.nox.yaml` auto-install paths were fail-open, so a higher version
  in a configured registry (or a stale/MITM'd unsigned index) could be installed
  unverified. All three paths now share one gate and fail closed.
- **Secret redaction of plugin output no longer has blind spots.** Secrets
  routed through a plugin's structured fields (a finding's file path, an AI
  component's name/type/path, a diagnostic source, a graph node path) bypassed
  redaction entirely; and the GitHub-token pattern missed `gho_`/`ghu_`/`ghr_`
  and fine-grained `github_pat_` tokens. Both are fixed.
- **An unrecognized plugin `risk_class` now fails closed.** A non-canonical value
  (`RUNTIME`, `exec`, a trailing space) slipped past the risk-class ceiling
  instead of being rejected.
- **Archive extraction is bounded.** Plugin artifact extraction had no cap on
  decompressed size, so a small archive could expand to hundreds of gigabytes
  and fill the disk. Extraction is now capped (total bytes and entry count) and
  aborts before writing an over-budget archive.
- **MCP dashboard responses honor the output-size limit.** The dashboard tools
  returned the entire findings/inventory as unbounded HTML, bypassing the 1 MB
  cap every other tool enforces; they now return a structured "too large" notice
  pointing at `summary`/`list_findings`.

### Fixed

- **Source under `prompts/` and `agents/` directories is now scanned.** Any real
  source file (`.go`, `.ts`, `.py`, …) under a directory named `prompts` or
  `agents` was misclassified as an AI component and silently skipped by taint,
  SAST, and agent-flow analysis — the very code that most needs it. Such files
  are now classified as source; genuine prompt/agent config artifacts still are
  not.
- **Go and Ruby components in an SBOM are no longer dropped from vulnerability
  scanning.** Package-URL types (`golang`, `gem`) were not normalized to the
  ecosystem names OSV expects (`go`, `rubygems`), so every Go and Ruby component
  parsed from a CycloneDX/SPDX input was silently excluded from the OSV query.
- **MCP rug-pull and server/tool-shadowing detection now runs.** MCP-015/023/024
  were implemented and unit-tested but never invoked in a scan; a relational
  pass now wires them in.
- **57 previously-dead IaC rules now fire.** They used a regex feature Go's engine
  rejects, so they silently never matched; a new block-scoped absence matcher
  restores them, guarded against hardened configs.
- **Five taint/SAST recall holes are closed** (inline source-as-sink-argument,
  attribute-accessor sources, PHP concatenation and same-line function bodies,
  JavaScript per-function scoping) with no new false positives.
- **Vendor secret rules match the credential value, not the config key name**, so
  they no longer false-positive on documentation while missing the real secret.
- **Reports are valid and reproducible.** SARIF/SBOM validity fixes; CycloneDX
  output is deterministic when one CVE affects several packages; SPDX
  `licenseDeclared` is always a valid expression; the HTML report honors
  `SOURCE_DATE_EPOCH`.
- **`requirements.txt` strict `<`/`>` bounds parse correctly**, so those packages
  are no longer dropped or mis-named (and thus missed by CVE lookup).
- **`--tracked-only` no longer inverts its scope** on a non-git target, per-finding
  metadata is isolated, and AI inventory output is deterministic.
- **Policy-gate keywords are validated** (an invalid `fail_on` no longer silently
  disables the gate) and de-duplication no longer drops distinct findings that
  share a fingerprint.
- **A latent absence-matcher span bug** that would absorb sibling YAML sequence
  items is fixed before any rule could hit it.

## [1.12.2] - 2026-07-19

### Fixed

- **Some secrets were reported multiple times.** Five vendors had two or three
  built-in rules that were byte-for-byte the same detection — identical
  description, identical pattern — so a single credential surfaced as several
  findings under different rule IDs (a Bugsnag key as three, a Heroku key as
  two), all with the same description and no way to tell them apart. The
  redundant rules are merged; where they carried different keywords those are
  combined into the surviving rule, so no file loses coverage. A before/after
  scan of a real repository produces an identical finding set. Two tests now
  prevent duplicate rules from recurring.


## [1.12.1] - 2026-07-19

### Fixed

- **129 vendor secret rules fired on ordinary code.** Rules whose pattern is
  only a character class and a length — `[a-zA-Z0-9]{32}` and similar — were
  gated by keyword at file level, so a single mention of a vendor anywhere in a
  file turned every run of characters of that length into a high-severity
  credential finding: comments, identifiers, JSON values. On nox's own source
  one rule produced 34 such findings, two of which had blocked this project's
  own PR gate.

  These rules now require the vendor keyword *near* the match, and the matched
  value to have the entropy and shape of a credential. Neither test alone is
  enough — a hostname sits right beside its keyword, and a real key can score
  lower entropy than a long code identifier — so both are applied.

  Measured on nox's own source at `--severity-threshold high`, `SEC-*` findings
  dropped from 45 to 12 with no loss of recall: the precision suite still scores
  1.000/1.000, and every one of the 129 rules still detects a credential-grade
  token of its own shape. A small residual remains on values whose character
  profile is genuinely ambiguous with a lowercase key (run-together hostnames);
  it is bounded by a test rather than removed, because the only discriminator
  that removes it also rejects real keys.


## [1.12.0] - 2026-07-19

### BREAKING CHANGES

- **Post-scan plugin tools are now subject to policy.** `InvokePostScan` called
  the gRPC client directly and applied no policy at all — no per-tool safety
  check, no read-only gate, no rate limit, no timeout, no secret redaction.
  A non-read-only post-scan tool now runs only if the operator opts in with
  `plugin_policy.max_risk_class: active`.

  This affects `nox/remediate`, whose `apply_code` and `verify_code` tools are
  declared non-read-only and will be blocked under the default passive policy
  until opted in. That is the documented behaviour, and blocking a tool that
  rewrites source until an operator asks for it is the correct default.

- **Plugin fingerprints change value.** The namespace separator moved from `:`
  to NUL. Anything baselined against a 1.11.x plugin fingerprint needs
  re-baselining.

### Fixed

- **nox's "never auto-applies fixes" guarantee was bypassable.** A plugin
  declaring a tool with `requires_scan_context` and `read_only: false` ran it
  regardless of policy, because the post-scan path applied none. Counting
  enforcement sites, that path had zero against the normal path's eight. Both
  now share one authorisation routine, so a future third invocation path
  cannot quietly skip the checks.

- **Every plugin enrichment and graph was silently discarded.** Secret
  redaction rebuilds the response and copied findings, packages, AI components
  and diagnostics — but not enrichments or graphs. Reachability annotations and
  call graphs never arrived, with no error. The post-scan bypass had been
  masking this, which is why post-scan enrichments appeared to work and
  scan-tool ones did not. Graph node properties, file paths and edge labels
  were being dropped by the same code and are now carried through, with their
  free text redacted.

- **Plugin fingerprint namespacing was defeated by delimiter injection.**
  `plugin:<name>:<ruleID>` meant plugin `acme` with rule `sql:injection` and
  plugin `acme:sql` with rule `injection` collided, letting one plugin suppress
  another's finding through first-wins deduplication.

### Added

- **yarn, pnpm and poetry lockfiles are parsed.** These ecosystems previously
  produced an empty dependency inventory; 1.11.1 made that visible, and this
  closes it. Verified against the live OSV API: a yarn project pinning lodash
  4.17.15 reports 6 vulnerabilities with severities, fix versions and CVE
  aliases where it previously reported none.

  Covers yarn v1 and berry, pnpm lockfile v5 and v6+, and poetry's
  `[[package]]` tables — including the range-versus-resolved-version trap in
  yarn descriptors and the `[metadata]` table that poetry interleaves between
  package blocks.


## [1.11.1] - 2026-07-19

> Retro-tagged on 2026-07-28. No `v1.11.1` tag was pushed at the time, so the
> changelog documented a version that could not be fetched; the tag now points
> at the commit that added this section. No release ARTIFACTS were published
> for 1.11.1 then and none exist now — its changes reached users inside 1.12.0.

A post-release review found that three of 1.11.0's own promises did not hold.
Each had full unit-test coverage of the function involved while the defect sat
at the call site — the same shape as the bug 1.11.0 was written to fix.

### Fixed

- **Critical dependency advisories reported as `medium`, again.** The CVSS-v4
  severity fallback added in 1.11.0 never received data: advisory hydration
  copied summary, aliases and CVSS entries but not the source database's
  severity label, and `/v1/querybatch` supplies none of those fields. A
  `CRITICAL` advisory scored `medium`, so critical/high gates did not fire on
  it. Severity mapping also returned on the first CVSS entry it *saw* rather
  than the first it could *score*, letting an unscorable CVSS v2 vector
  override an accurate label.

- **`--fail-on-degraded` could not fire for plugin failures**, despite naming
  them in its help text. A required plugin that was not installed was silently
  skipped, so a CI job listing a security plugin, failing to install it, and
  running with the flag exited 0 with a clean report.

- **yarn, pnpm and poetry projects scanned clean while nothing was read.**
  1.11.0 exempted unparsed lockfiles from degradation reporting to stop
  `go.sum` warning on every Go repository; that exemption silently covered
  three lockfiles nox cannot parse and has no substitute for. Only genuine
  redundancy is exempt now. A new invariant test fails the build if a lockfile
  is added to discovery without either a parser or a recorded, reported gap.

- **A suppression with an unparseable expiry became a permanent waiver.**
  `# nox:ignore SEC-001 -- expires:2026-13-01` (month 13) was accepted, the
  expiry text stripped from the displayed reason, and the finding hidden
  forever. The waiver is now not applied, the finding is reported, and the bad
  date is named. This one is long-standing and failed toward hiding findings.

- **`--fail-on-degraded` discarded every report.** It exited before report
  generation, so a pipeline that tripped the flag lost `findings.json`, the
  SARIF and the SBOM — including the findings it had collected. Reports are
  now written first, and the degraded exit outranks the policy exit code.

- **Silent supply-chain and CVE-variant data failures.** Typosquatting and
  known-malicious-package detection returned nothing when their embedded
  datasets failed to load; a whole-database parse failure disabled every
  `VARIANT-*` rule. All are reported now.

- **Dockerfile read and parse failures** are reported, in the same analyzer
  that already reported lockfile failures.

### Added

- `findings.json` records incomplete checks under `meta.degradations`. The
  consumers that most need them — CI jobs, dashboards, MCP clients — never see
  stderr, and for them an empty findings list was indistinguishable from a scan
  that never looked.

### Known gaps

`yarn.lock`, `poetry.lock` and `pnpm-lock.yaml` are still not parsed. They are
now reported as blind spots on every scan that encounters them rather than
passing silently; parsers are the fix and are not in this release.


## [1.11.0] - 2026-07-19

### BREAKING CHANGES

This is a minor release carrying breaking changes. The module path stays
`github.com/nox-hq/nox` — a v2 tag would break `go get` for library consumers
without a `/v2` path rename — so the breaks are listed here rather than
signalled by the version number. Read this section before upgrading.

- **`--vex` and `--terraform-plan` now fail when the path cannot be loaded.**
  Previously a missing or malformed file was silently ignored, so a typo'd
  path produced a clean-looking scan with no waivers applied and no plan
  scanned. Pipelines relying on a broken path being skipped will now exit 2.

- **Plugin track safety profiles are enforced.** A plugin's policy is now its
  registry track's profile merged with `.nox.yaml plugin_policy`, rather than
  `DefaultPolicy()` for everything. This *loosens* the default posture for
  tracked plugins — a `dynamic-runtime` plugin gets localhost access without
  the operator configuring it. Set `plugin_policy.ignore_track_profiles: true`
  to restore the previous behaviour. Plugins installed with `--local`, or
  before this release, have no recorded track and stay on the strict default.

- **Go API.** `Host.MergeResults` and `Host.MergeAllResults` take the
  producing plugin's name; `Host.InvokeAll` returns `[]AttributedResponse`
  instead of `[]*pluginv1.InvokeToolResponse`; `ProtoFindingToGo` takes a
  plugin name. `ScanOptions.NoCache` is removed — nothing read it.

- **`-no-cache` is now a documented no-op.** The flag is still accepted so
  existing scripts keep working, but the scan pipeline consults no incremental
  cache and never did.

### Added

- **A scan now reports what it could not check.** Graceful degradation is only
  safe if it is visible, and it was not: an OSV outage, a dead plugin, an
  unparseable lockfile, a corrupt baseline and an unreadable file during
  suppression all produced a clean exit 0, indistinguishable from a real pass.

  `ScanResult.Degradations` records each incomplete check with what failed and
  what may now be missing from the results. The CLI prints them to stderr even
  under `--quiet` — quiet suppresses noise, not a warning that the results are
  partial — and `--fail-on-degraded` makes CI treat "could not check" as
  failure, for runners where OSV is firewalled or a required plugin is absent.

  ```
  [degraded] vulnerability lookup failed for 1 packages: ...
    impact: dependency vulnerabilities are under-reported; this scan cannot
            confirm the absence of known CVEs
  ```

  Silence is preserved where nothing is wrong: a missing baseline is normal
  before the first `baseline write`, and files nox deliberately does not parse
  (`go.sum`, `yarn.lock`) are not degradations. A warning that fires on
  healthy scans is one operators learn to ignore.

- **`--fail-on-degraded`** — exit non-zero if any check could not complete.

- **`plugin_policy.ignore_track_profiles`** — force every plugin onto the
  strict default policy regardless of track. Required because the override
  semantics are one-directional: an operator can widen an allowlist but cannot
  empty one, so without this there is no way to revoke a profile's grant.

### Fixed

- **Plugin-supplied fingerprints were trusted verbatim.** Plugin findings
  merge into the same `FindingSet` as core findings, deduplicate first-wins,
  and baseline and VEX suppression key on the same value — so a plugin could
  claim a core finding's fingerprint and erase it, or claim a baselined one
  and hide itself. Fingerprints are now derived host-side and namespaced by
  plugin, so a plugin cannot reach outside its own findings while its
  findings stay individually baseline-able.

- **The plugin gRPC socket bound to all interfaces.** `net.Listen("tcp", ":0")`
  with insecure credentials meant any local process — and depending on the host
  firewall, any peer on the LAN — could invoke plugin tools for the lifetime of
  a scan. Now binds `127.0.0.1:0`.

- **Track safety profiles were documented but never applied.** The authoring
  guide presented the per-track table as the policy in force while the host
  enforced `DefaultPolicy()` for everything, so a `dynamic-runtime` plugin was
  rejected at registration for declaring the localhost access its track was
  documented to grant. The track is read from the registry entry the plugin
  was installed from and never from the plugin itself — a self-declared track
  would let a plugin choose its own sandbox.

- **Warnings reached nobody.** The CLI never configured an slog handler, so
  every `slog.Warn` in the codebase went nowhere — including the OSV
  degradation warning added in 1.4.0 specifically to prevent silent failure.
  `NOX_LOG_LEVEL` now controls verbosity.

- **`license.deny` / `license.allow` produced no findings.** The config parsed
  cleanly and was never wired to the dependency analyzer. Fixing it exposed a
  second bug: npm license detection returned early when the root
  `package.json` was missing, skipping `node_modules` entirely.

- **`--rules` was silently ignored under `--staged` and `--history`.** The
  staged scan dropped its options wholesale; the history scan never read them.

- **Analyzers ignored context cancellation.** All four non-deps analyzers
  accepted a context and never consulted it, so a cancelled scan kept reading
  files until the walk finished. They now check between artifacts.

- **A corrupt baseline was silently ignored**, changing what the gate enforces
  under `baseline_mode` with no indication. A *missing* baseline stays silent.

- **OSV advisory hydration could be blanked by a proxy.** Any JSON object
  decodes into the advisory type, so an intercepting proxy answering 200 with
  unrelated content produced a well-formed but empty record. Responses whose
  ID does not match the request are now rejected. Severity also falls back to
  the source database's label for CVSS v4-only advisories, which previously
  collapsed to `medium`.

- **The registry `deprecated` flag did nothing.** Carried in the index since
  1.4.x but absent from the entry type, so `plugin search` and `plugin install`
  went on recommending retired plugins silently. Now surfaced in search,
  install (advisory, never blocking) and info.


## [1.10.0] - 2026-07-19

### Fixed

- **Go dependency scanning reported mostly wrong versions, at uniformly wrong
  severity, with no way to act on the result** (#248). Three bugs, each of
  which hid the others.

  **Versions came from `go.sum`.** It is not a lockfile — it hashes the entire
  module graph, every version the resolver ever considered. Across 28
  repositories 5,263 findings came from it; on one repository 148 of 148 named
  a version the build does not use (`x/net` flagged at a 2019 pseudo-version
  while the build selects v0.56.0). Projects had responded by excluding
  `go.sum` outright, trading the noise for a total blind spot on Go
  dependencies. Versions now come from `go.mod` — what Minimal Version
  Selection actually chose — consulting `go.sum` only for transitives that
  module graph pruning omits, and only for entries carrying a source hash (a
  `/go.mod`-only entry means the code was never downloaded).

  **Severity and remediation were never populated.** Every finding was
  `medium` with an empty summary — not one high or critical — so a critical
  dependency CVE could never trip a high/critical gate. OSV's `/v1/querybatch`
  returns only `{id, modified}`, and OSV publishes CVSS as vector strings that
  the severity mapper could not parse; both had to be fixed for either to
  matter. Advisory detail is now fetched per distinct ID, and CVSS v3.x base
  scores are computed from the vector per the specification. This also
  restores the fix-version remediation field, which had never emitted anything
  because it reads data `querybatch` does not return.

  **Advisories were matched per module, not per package.** OSV scopes Go
  advisories to import paths: `GO-2026-5932` affects only
  `golang.org/x/crypto/openpgp`, yet was reported against builds linking only
  `chacha20`/`cryptobyte`. Affected paths are now intersected with the packages
  the build links. Findings that are provably unreachable are demoted to `info`
  with `reachable=false` and the affected paths recorded — never dropped, since
  a silent disappearance is indistinguishable from a scanner that missed
  something. Where an advisory carries no import metadata, or the build cannot
  be enumerated, the finding is left exactly as before.

  Measured: vorhut 376 → 19 findings with every in-build module retained,
  mnemos 148 → 0, and severities spread across 1 critical / 24 high / 57
  medium / 3 low where everything had been medium.

  **Behaviour change:** repositories with high or critical dependency
  vulnerabilities will start failing an enforcing gate. Those vulnerabilities
  were always present and were being reported as medium.

- **`nox cache clear` now clears the registry cache too** (#246).

- Removed an 8.9 MB binary committed to the repository (#241).

### Changed

- **The plugin registry moved to its own repository**,
  [Nox-HQ/registry](https://github.com/nox-hq/registry). The index, the sync
  tool and the marketplace builder left core, which was cataloguing seven other
  repositories: it needed a GitHub token, knew every plugin's release cadence,
  and failed CI when an unrelated repository published. Plugin availability was
  also coupled to core's default branch, since the index was served from
  `raw.githubusercontent.com/nox-hq/nox/main/...`.

  nox now only *consumes* the published index over HTTP.

  **Existing installs migrate automatically.** The old URL is written into
  `~/.nox/state.json`, and bootstrap only adds a default source when none
  exists — so the dead URL would otherwise have persisted and 404ed on every
  search and install. nox now detects it, rewrites it, and says so on stderr.
  A source you have deliberately re-pointed is left alone.

### Added

- **`CRYPTO-001`** — broken cryptographic primitives (MD5, SHA-1, DES, RC4)
  across Go, Python, JS/TS and Java (#242).
- **`TAINT-007`** — open redirect (CWE-601) as a taint-gated sink for Go,
  Python, JavaScript, Java, PHP and Ruby (#243).

### Removed

- **`nox/sast` is retired** and removed from the plugin registry. Seven of its
  nine rules duplicated classes core's taint engine already detects (SQLi, XSS,
  path traversal, command injection, deserialization, SSRF, SSTI) under a
  second rule-ID namespace, so enabling it reported the same vulnerability
  twice. Its two additive rules are now in core: weak crypto as `CRYPTO-001`,
  and open redirect as `TAINT-007` — the latter taint-gated, where the plugin
  matched a regex against the shape of the code.

  Existing installs keep working; the plugin is simply no longer offered.

## [1.9.2] - 2026-07-18

### Changed

- Bundles `nox-plugin-reachability` **v0.7.0** (multi-language reachability:
  Rust, Java, Ruby, C#), built from the published module rather than an in-tree
  copy — so the bundled binary and the standalone release are the same
  artifact.
- Removes the duplicated `plugins/` tree. Every plugin now lives solely in its
  own repository (#238).

### Note on why this version exists

v1.9.1 shipped correctly signed, but its Homebrew formula was not published:
the tap credential was rotated *while* that release was running, so the job
read the old value, warned, and skipped the formula — the graceful degradation
added in #237 working as designed, with unlucky timing.

A release cannot be re-run to publish the formula afterwards (GoReleaser
rejects re-uploading existing assets with `422 already_exists`), so this
release carries the formula update. `brew install nox` now resolves 1.9.2
rather than 1.8.0.

## [1.9.1] - 2026-07-18

### Fixed

- **A stale Homebrew tap token no longer skips cosign signing.** The tap
  formula update ran inside the same goreleaser invocation as everything else,
  so an expired `TAP_GITHUB_TOKEN` (401) failed the `release` job — and `sign`,
  `docker` and `update-major-tag` all declare `needs: release`, so all three
  were skipped. **v1.9.0 was published with unsigned artifacts, no container
  image, and the floating `v1` tag left behind.** The workflow now probes the
  credential first; a bad token degrades to a warning and a skipped formula
  update while the release, signing, image push and tag move proceed (#237).

> **v1.9.0 should not be used.** Its artifacts are unsigned. Use v1.9.1.

## [1.9.0] - 2026-07-18

### Added

- **Per-tool safety requirements** (`ToolDef.safety`, `sdk.ToolSafety(...)`).
  Safety was declared per-plugin and validated at registration, so a plugin
  bundling tools with different needs had to declare the union — the strictest
  requirement of any one tool — and that union then gated every tool it ships.
  `nox/red-team` could not run its read-only `analyze` under a passive policy
  purely because it also ships `validate`.

  Registration now asks whether *at least one* tool is usable under the policy;
  the binding check is `ValidateToolInvocation`, applied by the host to the tool
  actually being called. A tool that declares no safety block inherits the
  plugin-level one, so existing plugins are unaffected.

  Note that this is deliberately **not** derived from the existing `read_only`
  flag: that means "does not mutate the workspace", not "passive".
  `nox/llm-triage` declares a `read_only` tool that sends source code to an
  external chat endpoint, so inferring passiveness from it would have granted
  egress to precisely the tool that exfiltrates source. The two checks are
  independent and a tool must satisfy both.

### Changed

- `nox/red-team` declares per-tool safety: `analyze` passive, `validate` active
  with network and confirmation. `nox/k8s-runtime` is intentionally unchanged —
  both `scan` and `drift` genuinely need the cluster API, so neither can honestly
  declare itself passive.

### Fixed

- **Plugin modules no longer drift out of the build.** Each plugin under
  `plugins/` is a separate Go module with a `replace` to the root, and nothing
  in CI built them — `go build ./...` stops at the module boundary. A root
  dependency bump left **5 of 7 failing** with every check green. All tidied,
  plus a `plugin-modules` CI job running `go mod tidy -diff`, build and test per
  module (#236).
- **Per-tool safety survived registration.** `RegisterPlugin`/`RegisterBinary`
  rebuild the manifest from `Info` before validating it, and the conversion
  dropped `ToolDef.safety` — silently reverting to the plugin-level ceiling
  (#236).
- **IAC-351 no longer fires on `id-token: write`.** The unanchored `TOKEN`
  pattern matched as a suffix of the YAML key, producing spurious **critical**
  findings on standard GitHub Actions OIDC permissions. Measured on this repo's
  own workflows: 2 false positives before, 0 after (#233).

### Added (tooling)

- `nox plugin install --local <path> <name>` registers a locally built plugin
  binary for development. Recorded with trust level `local` and no digest so it
  is never confused with a verified marketplace artifact; safety policy applies
  unchanged (#236).

### Changed

- Cleared the 45 pre-existing `golangci-lint` issues. None were bugs; 23 fixed,
  2 declined with reasoning recorded at the site, and `hugeParam`/`rangeValCopy`
  disabled in config after review — taking their advice would trade a
  no-mutation guarantee for eliding sub-200-byte copies (#235).
- Bumped `go.klarlabs.de/mcp` to v1.24.0 (#232).

## [1.8.0] - 2026-07-10

> Reconstructed after the fact: v1.8.0 was tagged and released without a
> CHANGELOG entry. Contents below are taken from the commits in
> `v1.7.1..v1.8.0` rather than from a record written at the time.

### Added

- **Structured content from MCP read/report tools** (#230) — server tools now
  return structured output alongside text.

### Changed

- Bumped `go.klarlabs.de/mcp` to v1.21.0 (#227) and v1.22.0 (#229).
- Bumped `golang.org/x/net` to 0.55.0 in `nox-plugin-grc` (#228).

## [1.7.1] - 2026-07-06

### Fixed

- **Restored the `nox scan --baseline <path>` flag** as an optional override.
  It was removed in favour of auto-discovering `.nox/baseline.json`, which is a
  good default but a breaking change on its own: a workflow still passing
  `-baseline` errored (exit 2), and under a `nox scan … || true` pipeline that
  silently disabled scanning. Auto-discovery remains the default; when set, the
  flag (and its config equivalent `policy.baseline_path`) points the baseline at
  a non-default location — an explicit flag takes precedence over config. An
  unrecognized `scan` flag now prints an actionable hint (`run 'nox scan -h'`)
  instead of a bare parser error, so a removed/typo'd flag can't quietly become
  a silent-disable trap again.

## [1.7.0] - 2026-07-06

This release turns nox's SAST layer from a 3-language proof of concept into a
**21-language deterministic taint engine**, and raises measured precision from
0.30 to 1.00 on an honest, self-defending corpus.

### Added

- **Real SAST taint analysis across 21 languages.** A pure-Go `lexctx` lexical
  classifier plus an intraprocedural (and same-file interprocedural) dataflow
  engine track untrusted input from sources to dangerous sinks, honoring
  per-vuln-class sanitizers. Covered: Python, JavaScript/TypeScript, Go, PHP,
  Java, C#, Rust, Ruby, C/C++, Scala, Kotlin, Perl, Swift, PowerShell, Shell,
  Lua, Dart, Objective-C, Elixir, Clojure, and Groovy. Go uses the stdlib
  `go/ast` parser (pure-Go, no CGo); every other language uses a deterministic
  line/statement recognizer — no tree-sitter, no native dependencies, single
  static binary. Vulnerability classes: SQL injection (`TAINT-001`), command
  injection (`TAINT-002`), XSS (`TAINT-003`), path traversal (`TAINT-004`),
  unsafe deserialization / code injection (`TAINT-005`), and SSRF
  (`TAINT-006`). Memory-safety bugs are explicitly out of scope for the taint
  model (a different analysis).
- **Interprocedural taint (same-file).** Function summaries propagate taint
  across helper calls within a file (`source() -> wrap() -> os.system()` is
  caught through the wrapper), with the call path named in finding metadata.
- **`agentflow` analyzer for agentic dataflow.** `AGENTFLOW-001` flags untrusted
  input reaching an LLM prompt (OWASP ASI01 / CWE-1427); `AGENTFLOW-002` flags
  LLM output flowing into a dangerous sink (ASI02 / CWE-77).
- **Honest SAST precision harness.** `nox bench --precision <dir>` scores a
  labeled corpus against ground truth (per-rule and overall precision/recall/F1,
  findings-per-issue density, noise ratio). A ratchet with per-rule floors, an
  anti-cheat self-test (the corpus provably cannot fake a perfect score), a
  determinism guard, and a CI precision gate keep the number honest on every PR.

### Changed

- **SAST precision raised from 0.30 to 1.00** by fixing six false-positive
  classes at the engine level (not by curating the corpus): secret over-firing
  (specificity dedup + canonical-owner resolution), placeholder/example-credential
  allowlisting, an AI-002 prompt-context gate, decoded-base64-blob entropy
  suppression, a cross-analyzer same-vuln-class dedup, and SRI-hash recognition.
- `lexctx` now classifies Go source, activating comment/string/data-blob
  false-positive suppression for `.go` files.

### Fixed

- Removed a set of contextual/common-word keywords (`show`, `hide`, `on`,
  `part`, `num`) from the shared identifier-keyword set where they silently
  suppressed real variable/function reads across languages.

### Plugins

- **nox-plugin-llm-triage grounding.** The optional LLM triage layer is passed
  an immutable rule ID / file:line / snippet and may only return a verdict and
  rationale — it can never invent or relocate a finding.

## [1.6.0] - 2026-07-05

### Added

- **Slopsquatting / hallucinated-package detection (`SLOP-001`).** A new
  deterministic, offline analyzer flags source-code imports of a package that is
  not declared in any dependency manifest, is not a language standard-library
  module, and is not a first-party local module — the *slopsquatting* attack
  surface (an LLM hallucinates a plausible package name, a developer installs it,
  and an attacker who pre-registered the name runs code). Covers Python
  (`.py`/`.pyi`) and JS/TS (`.js/.jsx/.mjs/.cjs/.ts/.tsx/.mts/.cts`), with
  embedded stdlib/builtin lists, an import→distribution name map
  (`yaml`→`pyyaml`, `cv2`→`opencv-python`, …) and PEP 503 normalization to keep
  false positives low. Declared set parsed from `package.json`,
  `package-lock.json`, `requirements*.txt`, `pyproject.toml` (PEP 621 + Poetry),
  and `Pipfile`. Never contacts a registry. Tagged `owasp-asi04` / `owasp-llm03`.
- **CVE-variant detection + `nox variants`.** A new analyzer flags first-party
  code that reproduces the root-cause pattern of a known CVE — variants a
  version-based SCA can't see because there's no vulnerable dependency, just the
  same insecure shape written locally. Ships signatures for Log4Shell JNDI
  (CVE-2021-44228), PyYAML full-loader (CVE-2020-14343), tar `extractall` without
  filter (CVE-2007-4559), Zip Slip (CVE-2018-1002200), Jinja SSTI
  (CVE-2019-10906), and `child_process` shell interpolation (CVE-2021-21315),
  each with a safe-form exclusion. `nox variants [CVE-ID] [path]` reports variants
  (optionally filtered to one CVE); `nox variants --list` enumerates the
  signatures.
- **Dependency-provenance checks (`PROV-001`/`PROV-002`).** A new deterministic,
  offline analyzer for the supply-chain provenance gap a version-based SCA
  misses (OWASP ASI04 / SLSA): `PROV-001` flags a dependency pulled from a VCS
  repo, raw URL, or tarball instead of a signed registry; `PROV-002` flags a VCS
  dependency pinned to a mutable ref (branch/tag) instead of an immutable commit
  SHA. Parses `package.json` and `requirements*.txt`; registry ranges and
  `#sha256=` hash-verified URLs never fire. Live sigstore/SLSA attestation
  verification needs the network and is left to an opt-in plugin — this analyzer
  makes no network call.
- **Agent-config coverage for A2A and DXT (`AGENT-005`/`AGENT-006`).** `AGENT-005`
  (ASI07) flags an A2A agent card (`agent.json` / `.well-known/agent.json`) that
  declares an empty or `none` security scheme while advertising skills — an
  unauthenticated inter-agent endpoint. `AGENT-006` (ASI02) flags a DXT
  desktop-extension manifest (`manifest.json` / `*.dxt`) that interpolates a
  `${user_config.*}` value into the server executable or a shell `-c` string —
  command injection at launch. Both are scoped to avoid false positives (a
  populated `securitySchemes` block and a `${user_config.x}` passed as a discrete
  argv element are silent).
- **JetBrains plugin (`editors/jetbrains`).** A thin client over the `nox lsp`
  language server for IntelliJ IDEA Ultimate, GoLand, PyCharm Professional,
  WebStorm, and the other paid JetBrains IDEs (platform LSP API, 2023.2+), with a
  documented LSP4IJ path for the free Community editions. Mirrors the VS Code
  extension: deterministic, offline diagnostics on open/save.
- **Optional LLM-triage plugin (`nox-plugin-llm-triage`).** An opt-in escape
  hatch for teams that want an LLM's judgment on top of the deterministic core:
  it consumes the scan's findings, sends each plus a code snippet to an
  OpenAI-compatible chat endpoint, and attaches a true/false-positive verdict as
  an enrichment on the original finding. It never changes or gates the scan
  result. Active egress — refuses to run without `authorize: true`. The core
  stays deterministic and offline whether or not it is installed.

## [1.5.0] - 2026-07-05

### Added

- **VS Code extension (`editors/vscode`).** A thin client over the `nox lsp`
  language server: surfaces nox findings inline (squiggles, hover, Problems
  panel) as you open and save files. Deterministic and offline — it runs the
  local `nox` binary, no code leaves the machine. Delivers the editor-integration
  half of #47 on top of `nox lsp`; a JetBrains plugin is the same shape.
- **Post-scan plugins run automatically in `nox scan`.** Plugins whose tools
  need the findings the scan just produced — those declaring
  `requires_scan_context` — now run as part of the pipeline (before refinement,
  so their findings are deduped, suppressed, and policy-gated). The reachability
  plugin is the motivating case: listed in `plugins.required`, it now classifies
  the scan's vulnerabilities as reachable / unreachable / undetermined without a
  separate manual `nox plugin call`, feeding the `--sort priority` deprioritization
  of likely-false-positive unreachable vulns.
- **`nox lsp` — Language Server for editor diagnostics.** Runs a minimal LSP
  server over stdio (JSON-RPC 2.0 with `Content-Length` framing) that scans the
  active file on open/save and publishes nox findings as
  `textDocument/publishDiagnostics`. Deterministic and fully offline — it just
  runs the scanner on the one file, maps each finding's location/severity/RuleID
  onto an LSP diagnostic (critical/high→Error, medium→Warning, low→Information,
  info→Hint), and sorts them stably by line, column, then rule id. Hand-rolled
  JSON-RPC (no third-party LSP library, no network); `didClose` clears
  diagnostics and scan errors publish an empty set instead of crashing.
- **`nox scan --sort priority` — reachability-aware finding prioritization.**
  Orders findings.json by what's most actionable — severity first, then
  reachability, then confidence — instead of the default rule/path/line order
  that buries criticals. Paired with the reachability plugin (which enriches
  VULN findings with a `reachable` flag), a confirmed-reachable vuln rises and a
  likely-false-positive *unreachable* one sinks to the bottom, so the report
  leads with real risk. Deterministic (stable location tiebreak); the default
  order is unchanged, preserving baselines and diffs.
- **`nox fix --content` — deterministic patches for mechanical misconfigurations.**
  Reads `findings.json` and rewrites the flagged line to its one unambiguous
  secure value: Kubernetes hardening flips (`privileged: true`→`false`,
  `runAsNonRoot: false`→`true`, hostNetwork/hostPID/hostIPC/allowPrivilegeEscalation/
  automountServiceAccountToken, readOnlyRootFilesystem), Terraform
  (`storage_encrypted`/`enable_https_traffic_only`, `protocol "HTTP"`→`"HTTPS"`,
  `acl "public-read"`→`"private"`), CI (`continue-on-error: true`→`false`), and
  Dockerfile `ADD`→`COPY`. Template-free and no LLM — only rules with a single
  correct answer are fixed; anything needing a choice (a UID, a pinned digest, an
  allowlist, a rotated secret) is deliberately never touched. Previews the diff
  by default and applies nothing; `--content --write` applies.
- **`nox baseline init` — one-command adoption for a debt-laden repo.** Scans,
  records every current finding as accepted baseline debt (reported by
  severity), and prints the "gate the change, not the history" policy to add
  (`fail_on` + `baseline_mode: warn`). Refuses to clobber an existing baseline
  (use `update`, or `--force`). See the new `docs/adoption.md`, which ties
  together `baseline init`, per-severity budgets, `--tracked-only`, and
  `--offline` into a five-minute adoption path.
- **Broader language coverage: JS/TS module + JSX variants, plus Kotlin, Swift,
  PHP.** `.tsx`/`.jsx`/`.mjs`/`.cjs`/`.mts`/`.cts` are now classified as source,
  and every rule scoped to `*.ts`/`*.js` is auto-expanded to the variants — so a
  React/Next.js AI app's `.tsx` components (where prompts are built and the model
  is called) are scanned instead of silently skipped. `.kt`/`.swift`/`.php` join
  the source set too.
- **OWASP Top 10 for Agentic Applications (ASI01–ASI10) mapping.** Findings
  against agentic surfaces now carry their `owasp-asi*` control (in SARIF
  `properties.tags` and finding metadata), the way they already carry OWASP LLM
  and MCP Top 10 tags. Mapped: ASI01 Agent Goal Hijack (AGENT-001/004, prompt-
  injection rules), ASI02 Tool Misuse (AGENT-002/003, tool-exposure rules), ASI03
  Identity & Privilege Abuse (MCP authz/SSRF), ASI04 Agentic Supply Chain (MCP
  tool-poisoning, rug-pull, shadow servers, model supply chain), ASI05 Unexpected
  Code Execution. Runtime/multi-agent categories nox can't statically detect
  (ASI06/07/08) are deliberately left unmapped rather than over-claimed.
- **Per-severity policy budgets (`policy.budget`).** The gate can now tolerate a
  bounded amount of new debt per severity before failing — e.g. `budget: {medium:
  5, low: 20}` fails only on the 6th new medium while still failing on any new
  high/critical. It refines `fail_on`: a severity at/above the threshold with no
  budget entry defaults to 0 (fail on the first, unchanged), so an empty budget
  reproduces the previous gate exactly. Lets a team adopt a strict threshold on a
  debt-laden repo without baselining every finding.
- **Proof-of-offline attestation in the report.** `findings.json` meta now
  carries an `"offline"` boolean recording whether the scan ran under the
  zero-network guarantee (`nox scan --offline`: no OSV, no API, no token, no
  telemetry). A reviewer or CISO can confirm straight from the artifact that the
  scanner never touched the network — backed by the enforced egress test
  (`TestOSVDisabled_NoNetworkEgress`), not just a claim. `--offline` also prints
  an `[offline]` confirmation line. This is the differentiator vs. LLM-powered
  scanners that ship your code to a model provider.
- **`nox scan --tracked-only`.** Restricts the scan to git-tracked files
  (`git ls-files`), excluding untracked working-tree files (scratch files, build
  output, un-added drafts) and submodule contents. Scans exactly what is
  committed — the same set a reviewer sees — so a CI gate is reproducible and
  doesn't flag a developer's local scratch file. Ignored outside a git repo.
- **Agent-config artifact scanning (`AGENT-001..004`).** The files that steer a
  coding agent are an execution surface, not just docs — a poisoned rule file or
  an over-broad permission grant silently changes what the agent runs, reads, and
  exfiltrates. nox now scans Cursor/Cline rules (`.cursorrules`, `*.mdc`),
  `CLAUDE.md`/`AGENTS.md`/`GEMINI.md`, Claude Code skills (`SKILL.md`), and agent
  settings (`.claude/settings.json`), classifying them as AI components. New
  rules: **AGENT-001** instruction-override / prompt-injection directives in a
  rules file (OWASP LLM01), **AGENT-002** settings that disable the
  human-in-the-loop permission gate (`bypassPermissions`, `--dangerously-skip-permissions`,
  `autoApprove`), **AGENT-003** wildcard tool grants (`"Bash(*)"`), and
  **AGENT-004** exfiltration / concealment directives. filePatterns are scoped to
  exact agent-config filenames (never `*.go`/`*.md` broadly), so ordinary source
  and documentation are untouched. (#145)

### Fixed

- **Entropy secret detectors no longer flag natural-language prose (#104).**
  The generic SEC-161 (high-entropy assignment) and SEC-163 (high-entropy hex)
  detectors fired on long English sentences, SQL, error-message format strings,
  and prompt templates — high *aggregate* entropy but not credentials. A compact
  secret token (API key, hash, base64/hex blob) never contains internal
  whitespace, so candidates with a space or tab are now rejected. On a
  prose-heavy codebase this removes the dominant false-positive class (a real
  case had 109 of 129 findings as prose FPs); real whitespace-free secrets are
  still detected (the base64/hex tokenizers extract the token itself).
- **`nox scan <file>` scans a single file.** A file target used to fail (it
  looked for `<file>/.nox.yaml` and the walker skipped its own root, finding
  nothing). Now it loads config from the file's directory and scans just that
  file — the basis for fast pre-commit hooks and editor integrations.
- **`scan.exclude` is now a hard exclude that survives `--changed-since`.** Since
  the tracked-file fix (#142), a file listed in `scan.exclude` that was also
  git-tracked got re-scanned — the tracked-file override treated the config
  exclude like a `.gitignore` pattern. So an explicit exclusion (e.g. a
  rule-definition file full of expected-false-positive patterns) was silently
  ignored in `--changed-since` scans, which is what failed nox's own PR gate on
  every rule change. Config excludes are now a separate hard rule the tracked
  override never resurrects.
- **Unsafe-output-handling rules no longer fire on documentation.** AI-009/012/
  015/018 (eval/exec, DB query, `innerHTML`, file path from LLM output) target
  real code sinks but matched prose in docs that *quote* those sinks — most
  visibly nox's own CHANGELOG entry `cursor.execute("SELECT " + completion)`,
  which tripped AI-012 (high) and failed the PR gate on every change that edited
  the changelog. A markdown file can't execute, so these rules now skip docs and
  test files (joining the existing prose/logging noise-glob set); real source is
  unaffected.
- **Tracked files under a gitignored directory are now scanned.** git never
  ignores a file it already tracks, even when a `.gitignore` pattern matches it
  — but nox applied ignore patterns purely from the filesystem and skipped them,
  a scanner blind spot for any repo that gitignores a directory yet commits
  sources into it (e.g. pet-medical ignores `mobile/` but tracks ~80 files under
  it, none of which were scanned — a committed secret there would go undetected).
  The scan now consults `git ls-files`: a tracked path is scanned even under an
  ignored directory, while genuinely-ignored (untracked) files stay skipped.
  Outside a git repo, behavior is unchanged. Note: repos with tracked files
  under ignored directories will see new findings on the next scan and should
  refresh their baseline. (#142)

## [1.4.2] - 2026-07-04

### Fixed

- **`.gitignore` is now honored when scanning from inside a git worktree.** In a
  linked worktree (and submodule) `.git` is a gitdir-pointer *file*, not a
  directory, so loading `.git/info/exclude` failed with `ENOTDIR` — an error
  that discarded every pattern already read from `.gitignore`, leaving the
  walker with zero ignore rules. A scan run from a worktree therefore found
  strictly more than the same HEAD scanned from the real checkout (a
  `mobile/`-ignored subtree reappeared: 721 vs 640 findings), so a baseline
  written from a plain directory never matched a worktree rescan. `info/exclude`
  is now resolved via the worktree's commondir (git shares it across worktrees),
  and a non-directory path component contributes no patterns instead of nuking
  the set. Dir and worktree scans of the same HEAD are now identical. (#140)

## [1.4.1] - 2026-07-03

### Changed

- **`nox fix --actions` now SHA-pins mutable tag refs, not just outdated ones.**
  A `uses: owner/action@v7` that already tracks the latest release is still a
  mutable ref — a supply-chain risk and a frequent PR-review flag. `--actions`
  now rewrites any tag ref to `@<sha> # <tag>`, pinning to the same-major latest
  release (or to the tag's own commit when a newer major is being held back).
  Already-SHA-pinned, up-to-date refs remain untouched, so remediation PRs are
  no longer blocked by "still using a mutable tag" review comments. Behavior for
  the dependency pass (default `nox fix`) is unchanged.

## [1.4.0] - 2026-07-03

### Added

- **`nox fix` remediates GitHub Actions pins.** `--actions` (alongside the
  package-dependency pass) or `--actions-only` scans `.github/workflows` and
  `.github/actions`, resolves each `uses:` action to its latest release via the
  GitHub API, and rewrites outdated pins to `@<sha> # <tag>` (SHA-pinned, best
  practice). Major-version jumps are skipped unless `--include-major`; branch
  pins (e.g. `@main` reusable workflows) are left alone. Needs `GITHUB_TOKEN`.
  This lets nox own dependency *and* CI-action remediation, replacing dependabot.

## [0.11.0] - 2026-06-05

### Added

- **MCP threat coverage mapped to the OWASP MCP Top 10.** New rules for tool
  poisoning (MCP-009..014), rug-pull/definition drift (MCP-015, `core/mcppin`),
  authorization & SSRF (MCP-016..021), and shadow/cross-server shadowing
  (MCP-022..024, `core/mcpshadow`). Every MCP rule carries its OWASP MCP control
  in SARIF (`properties.owasp-mcp`) plus a `tags[]` array.
- **`--offline` zero-network guarantee** and `scan.generated_paths`, a
  configurable noise filter (sensible default; `disabled`/`extend`/`override`)
  that stops the content rule families (AI-*, MCP-*) from firing on generated
  and vendored files (lockfiles, minified bundles, generated type defs).
  Dependency scanning is unaffected — lockfiles are still CVE-scanned.
  Content rules also skip machine-generated/minified blobs detected by
  content (an `AUTO-GENERATED`/`@generated`/`DO NOT EDIT` banner or a minified
  line), catching generated output embedded in a normal extension (e.g. a
  1.4 MB vite bundle exported as a `.ts` string).
- 17+ MCP client config locations are now discovered (`core/discovery/mcpclients`).

### Fixed

- **AI rule precision** (surfaced by scanning the top public MCP servers):
  - `AI-033` lacked a group around its alternation and matched bare
    `null`/`false`/`disabled` anywhere — the cause of thousands of false
    positives on generated TypeScript type definitions.
  - `AI-036` matched a bare `"35"` anywhere (version strings, hashes); it now
    requires a `gpt-` prefix.
  - `AI-026` matched any log call containing the generic words
    `content`/`output`/`message`/`response`; it now requires an LLM-specific
    token.
  - `AI-006/008/026/030/036/039/042` no longer fire in test files or
    documentation, and content rules skip whole test/fixture/sample/example
    directory trees (`scan.generated_paths.extend_dirs`/`override_dirs`) plus
    machine-generated/minified blobs detected by content.
  - `AI-018` (LLM output → file path) and `AI-049` (AI output → eval/exec) now
    require an LLM-specific token, so ordinary file I/O and DB `exec(query)` /
    `describeEval` calls no longer match.
  - MCP prose rules (`MCP-009..014/018/019`) skip comments, test files, and
    defensive contexts (e.g. an SSRF metadata IP inside a blocklist); `MCP-011`
    needs an exfil sink or sensitive path; `MCP-019` ignores loopback.
  - `MCP-022` is now informational (advisory posture signal, not a defect).
- **Policy gate** no longer counts inline-suppressed or VEX-cleared findings as
  new — a suppressed High no longer fails the gate.
- **`analyzer_rules`** rule IDs now match wildcards (e.g. `VULN-*`); the
  documented but unimplemented `skip_analyzer` action now works.
- Three rule precision fixes surfaced by the scan-of-the-week rotation:
  `AI-009` no longer flags Python's safe `ast.literal_eval`; `VULN-002`
  normalizes PEP 503 names so canonical packages (`huggingface_hub`,
  `python_pptx`) aren't flagged as typosquats of themselves; `AI-019` no
  longer matches DB/cache `.pipeline()` method calls.

### Changed

- **DDD / best-practices hardening.** Findings gain validated value objects
  (`Severity.IsValid`/`Confidence.IsValid`, `Location.Normalized`, `NewFinding`,
  `Finding.Validate`). A `FindingAnalyzer` interface formalizes the analyzer
  contract. `context.Context` is threaded through analyzers and a new
  `RunScanContext` entry point (with cancellation); `RunScan`/`RunScanWithOptions`
  are unchanged, non-breaking wrappers. The scan orchestrator is split into named
  pipeline stages. `TrustedRegistries` is now an immutable accessor.

## [0.10.1] - 2026-05-23

### Fixed

- **Scan now honours ancestor `.gitignore` files** ([#82]). Previously
  `LoadGitignore` only consulted `<target>/.gitignore`, so
  `nox scan apps/api` walked `apps/api/node_modules` even when
  `node_modules/` was ignored at the repo root. The walker now climbs
  to the enclosing `.git` directory and accumulates patterns top-down.
- **`--changed-since=<ref>` now scopes the file walk** ([#83]). The
  flag used to walk the full target tree and filter artifacts after,
  paying the full traversal cost on every push. The diff is now
  resolved before `walker.Walk()` and wired into a new
  `Walker.IncludePaths` allow-list that short-circuits descent into
  directories that contain no included path.

Empirical impact on a real Astro+Go monorepo with 521 MB of
`node_modules`: `nox scan apps` dropped from **14 min 54 s →
2.03 s** and from **1,729,404 findings → 3,630** — the rest was
secrets-pattern noise inside npm bundles.

[#82]: https://github.com/Nox-HQ/nox/issues/82
[#83]: https://github.com/Nox-HQ/nox/issues/83

### Added

- **Fingerprint v2** (opt-in): new `--fingerprint-version 2` flag on `nox scan`
  (or `NOX_FINGERPRINT_VERSION=2` env). V2 hashes only `rule_id + normalised
  file_path + content`; drops the start line so trivial diffs (import shifts,
  gofmt, comment edits) no longer invalidate baselined findings. Path
  normalisation collapses leading `./`, backslash → forward-slash, and `..`
  segments so `nox scan ./http` and `nox scan .` produce the same fingerprint
  for the same finding. V1 remains the default; switch a repo over by
  passing `--fingerprint-version 2` to `nox scan` (or setting the env)
  and then running `nox baseline update` so existing entries re-hash
  under V2. A dedicated `nox baseline migrate` command will land in a
  follow-up PR (#73 item 4). Closes [#73 items 1+2](https://github.com/Nox-HQ/nox/issues/73).
- **`nox baseline add`** — additive counterpart to `baseline update`.
  Adds findings not yet in the baseline without pruning stale entries.
  Accepts `--rule <id,id>` and `--fingerprint <fp,fp>` filters; the
  fingerprint flag bypasses the scan entirely and is the surgical
  "baseline these specific entries" workflow #73 item 4 calls out.
  `--reason` and `--owner` annotate every new entry. Closes [#73 item
  4](https://github.com/Nox-HQ/nox/issues/73).
- **`nox baseline diff`** — read-only preview of what
  `baseline update` would change against the current scan. Lists adds
  and prunes separately so the operator can decide whether a prune is
  real (resolved) or a regression (rule sharpened, file renamed,
  fingerprint algorithm bumped).

### Documentation / interop

- **`nox doctor` version-drift check** — doctor now scans
  `.github/workflows/*.yml` for `nox-hq/nox/cli@vX.Y.Z` pins and warns
  when CI and the local nox binary disagree. Same nox version on both
  sides makes "I just ran nox locally, it's clean" actually meaningful
  again. Reports `ok` per workflow when versions match, `DRIFT` when
  they diverge, with a suggested fix-up command (bump CI or
  `go install` locally). Closes [#73 item 7](https://github.com/Nox-HQ/nox/issues/73).
- **Exit-code semantics already correct** (item 8 follow-up). Verified
  that `nox scan` already returns 0 when every finding is baselined or
  suppressed and exits 1 only on truly-new active findings —
  `ActiveFindings()` filters `StatusBaselined` and `StatusSuppressed`
  out of the count that drives the exit code. The `|| true` shim in
  downstream CI workflows (e.g. felixgeelhaar/fortify) is no longer
  necessary; remove it on next workflow refresh.
- **`nox:disable` alias**: inline suppression now accepts both
  `nox:ignore` (legacy spelling) and `nox:disable` (matches gosec
  `#nosec`, staticcheck, golangci-lint `//nolint`). The two are
  semantically identical — same rule-list parsing, same `expires:` /
  reason handling, same scope (trailing comment vs next-line). This is
  the inline directive surface item 6 of #73 asked for; the underlying
  mechanism already shipped under the `nox:ignore` name.

### Fixed

- **AI-012 precision** — tightened the regex so it stops firing on every
  `.Execute(`/`Query(` call whose body coincidentally references an uppercase
  `Response` identifier (Go return types, struct fields, error variants). The
  rule now (a) matches the method name case-insensitively but the LLM-output
  keyword case-sensitive lowercase only, and (b) requires `\b` word boundaries
  around the keyword. Verified against `felixgeelhaar/fortify`: 4 known
  false positives in `http/middleware.go` and `http/streaming.go` are gone,
  the true-positive `cursor.execute("SELECT " + completion)` patterns still
  fire (including with nested calls in the argument list). Closes [#73 item
  3](https://github.com/Nox-HQ/nox/issues/73).

## [0.6.0] - 2026-02-24

### Added
- Graph-based cross-resource IaC analysis with 4 pattern detectors (Phase 7a).
- Reachability analysis plugin for import-based vulnerability reachability (Phase 7b).
- Intraprocedural taint analysis plugin with source-to-sink tracking (Phase 7c).
- Kubernetes runtime security scanner for live cluster scanning (Phase 7e).
- Phase 8 AI-enhanced security intelligence plugins: threat-explain, threat-model, GRC compliance, red team, and triage agent.
- FedRAMP Low/Moderate/High compliance frameworks.
- Detailed fix guidance for rule remediation.

### Changed
- Move FedRAMP Low/Moderate/High compliance baselines from core to GRC plugin.
- Core supported frameworks reduced from 11 to 8 (FedRAMP now in GRC plugin).
- Remove 1,517 FedRAMP mapping lines from `core/compliance/data.go`.

### Fixed
- Correct stale exclude path for plugin repos.

## [0.5.0] - 2026-02-17

### Added
- Graph, enrichment, and scan context SDK primitives for plugin ecosystem.

## [0.4.3] - 2026-02-17

### Fixed
- Pin GitHub Action references to commit SHAs and restore Grade A.

## [0.4.2] - 2026-02-17

### Changed
- Bump google.golang.org/grpc from 1.78.0 to 1.79.1.
- Bump github.com/charmbracelet/bubbles from 0.21.1 to 1.0.0.
- Bump github.com/openai/openai-go from 0.1.0-beta.10 to 3.22.0.
- Bump checkout, setup-go, upload-artifact, golangci-lint-action GitHub Actions.

## [0.4.1] - 2026-02-17

### Changed
- Bump google.golang.org/grpc from 1.78.0 to 1.79.1.
- Bump github.com/charmbracelet/bubbles from 0.21.1 to 1.0.0.

### Fixed
- Configure relicta GitHub plugin with post_publish hook.

## [0.4.0] - 2026-02-17

### Changed
- Swap mcp-go dependency from mark3labs/mcp-go to felixgeelhaar/mcp-go v1.6.4.
- Rewrite MCP server with typed handlers, fluent builder API, and resource templates.
- Add multi-project support with per-project scan cache and resource templates.

## [0.3.1] - 2026-02-15

### Fixed
- Suppress SEC-659 false positive on doc comment line in findings.go.
- Resolve revive lint issue for exported doc comments.
- Resolve gocritic lint issues in findings.go.
- Improve core domain test coverage from 82% to 93%.
- Suppress remaining SEC-659 false positives across codebase.

## [0.3.0] - 2026-02-15

### Added
- Import 191 Gitleaks rules (SEC-164 to SEC-355) for broad secrets coverage.
- Expand secrets rules to 900+ detectors (SEC-356 to SEC-549) for competitive parity with TruffleHog.
- Expand AI security rules and refine rule patterns for Grade A self-scan.
- Expand IAC and AI rule coverage with additional patterns.
- Add advanced exclusion patterns for flexible scan filtering.

### Fixed
- Resolve all security findings and achieve Grade A on self-scan.

## [0.2.1] - 2026-02-14

### Changed
- Harden rule handling and entropy scanning to reduce false positives.

## [0.2.0] - 2026-02-13

### Added
- OpenVEX support and compliance framework mapping (CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA, OWASP Top 10, OWASP LLM Top 10, OWASP Agentic).
- Expand IaC rules to 185 and add Terraform plan scanning.
- Encoded secret detection, SBOM input scanning, and Composer lockfile parser.
- Close competitive gaps with MCP-CLI parity, supply chain analysis, and dashboard.
- History scanning, entropy-based rules, and complete Phase 3 task backlog.
- Add coverctl coverage check to pre-commit hook.
- Expand to 564 rules with data sensitivity analyzer (DATA-001 to DATA-012), AI-BOM v2.0, and full compliance coverage.
- Wire VEX, compliance, and Terraform plan scanning to MCP server and CLI.

### Fixed
- Migrate to homebrew_casks and install syft for SBOM generation.
- Suppress false-positive findings to restore A security grade.
- Remove `t.Parallel` from test that mutates package-level `timeNow`.
- Suppress CONT-001 in Dockerfile template to achieve A grade.

## [0.1.0] - 2026-02-11

### Added
- 155 built-in rules across secrets (86), AI security (18), IaC (50), and dependency SCA (1).
- OSV vulnerability enrichment for dependency scanning via batch API.
- Shannon entropy matcher for high-entropy secret detection.
- Git history commit walker for scanning past commits.
- Custom rules support via YAML definition files (`--rules`).
- Pre-commit hook installer (`nox protect install/uninstall/status`).
- Project-level pre-commit hook with CI-matching checks (`make hooks`).
- `nox show` interactive finding inspector with Bubble Tea TUI.
- `nox explain` LLM-powered finding explanations via OpenAI-compatible APIs.
- `nox diff` for findings in changed files only.
- `nox watch` for automatic re-scan on file changes.
- `nox badge` for SVG security grade badges.
- `nox baseline` for managing known findings (write, update, show).
- `nox annotate` for inline GitHub PR review comments.
- `nox completion` for shell completions (bash, zsh, fish, powershell).
- Policy engine with `fail_on`/`warn_on` severity thresholds.
- Inline suppressions via `nox:ignore` comments with expiry support.
- Unified `.nox.yaml` scan configuration.
- `--no-osv` flag and `scan.osv.disabled` config for offline mode.
- `--staged` flag for scanning only git-staged files.
- `--severity-threshold` flag for minimum severity filtering.
- Plugin ecosystem with gRPC-based plugins across 10 security tracks.
- Plugin SDK with conformance tests and safety profiles.
- Plugin registry client with semver resolution and OCI distribution.
- Plugin trust and verification layer.
- MCP server with read-only tools for AI agent integration.
- Agent-assist module with plugin capability discovery.
- GitHub Action with checksum verification.
- Release infrastructure with GoReleaser, Relicta, and Homebrew tap.
- Test coverage tracking with coverctl and badge (83.1%).
- CycloneDX 1.5 SBOM with vulnerability enrichment.
- SPDX 2.3 SBOM with SECURITY external references.
- SARIF 2.1.0 output with full rule catalog (help, descriptions, URIs).

### Fixed
- Stabilized annotate and diff tests for CI environment.
- Badge counts only active findings (excludes suppressed).
- Eliminated false positives in self-scan with pinned GitHub Actions.
- Binary files skipped in scanner.
- SARIF reporter includes full rule help text for GitHub Code Scanning.
- Suppressed findings excluded from badge, diff, and watch counts.
- Interspersed flags and positional args handled correctly.
- Timeout added to `nox explain` to prevent indefinite hangs.

[Unreleased]: https://github.com/nox-hq/nox/compare/v1.32.0...HEAD
[1.32.0]: https://github.com/nox-hq/nox/compare/v1.31.0...v1.32.0
[1.31.0]: https://github.com/nox-hq/nox/compare/v1.30.1...v1.31.0
[1.30.1]: https://github.com/nox-hq/nox/compare/v1.30.0...v1.30.1
[1.26.0]: https://github.com/nox-hq/nox/compare/v1.25.2...v1.26.0
[1.25.2]: https://github.com/nox-hq/nox/compare/v1.25.1...v1.25.2
[1.25.1]: https://github.com/nox-hq/nox/compare/v1.25.0...v1.25.1
[1.25.0]: https://github.com/nox-hq/nox/compare/v1.24.0...v1.25.0
[1.24.0]: https://github.com/nox-hq/nox/compare/v1.23.0...v1.24.0
[1.23.0]: https://github.com/nox-hq/nox/compare/v1.22.1...v1.23.0
[1.22.1]: https://github.com/nox-hq/nox/compare/v1.22.0...v1.22.1
[1.22.0]: https://github.com/nox-hq/nox/compare/v1.21.0...v1.22.0
[1.21.0]: https://github.com/nox-hq/nox/compare/v1.20.0...v1.21.0
[1.20.0]: https://github.com/nox-hq/nox/compare/v1.19.1...v1.20.0
[1.19.1]: https://github.com/nox-hq/nox/compare/v1.19.0...v1.19.1
[1.19.0]: https://github.com/nox-hq/nox/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/nox-hq/nox/compare/v1.17.1...v1.18.0
[1.17.1]: https://github.com/nox-hq/nox/compare/v1.17.0...v1.17.1
[1.17.0]: https://github.com/nox-hq/nox/compare/v1.16.3...v1.17.0
[1.16.3]: https://github.com/nox-hq/nox/compare/v1.16.2...v1.16.3
[1.16.2]: https://github.com/nox-hq/nox/compare/v1.16.1...v1.16.2
[1.16.1]: https://github.com/nox-hq/nox/compare/v1.16.0...v1.16.1
[1.16.0]: https://github.com/nox-hq/nox/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/nox-hq/nox/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/nox-hq/nox/compare/v1.13.6...v1.14.0
[1.13.6]: https://github.com/nox-hq/nox/compare/v1.13.5...v1.13.6
[1.13.5]: https://github.com/nox-hq/nox/compare/v1.13.4...v1.13.5
[1.13.4]: https://github.com/nox-hq/nox/compare/v1.13.3...v1.13.4
[1.13.3]: https://github.com/nox-hq/nox/compare/v1.13.2...v1.13.3
[1.13.2]: https://github.com/nox-hq/nox/compare/v1.13.1...v1.13.2
[1.13.1]: https://github.com/nox-hq/nox/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/nox-hq/nox/compare/v1.12.2...v1.13.0
[1.12.2]: https://github.com/nox-hq/nox/compare/v1.12.1...v1.12.2
[1.12.1]: https://github.com/nox-hq/nox/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/nox-hq/nox/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/nox-hq/nox/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/nox-hq/nox/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/nox-hq/nox/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/nox-hq/nox/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/nox-hq/nox/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/nox-hq/nox/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/nox-hq/nox/compare/v1.7.1...v1.8.0
[1.7.1]: https://github.com/nox-hq/nox/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/nox-hq/nox/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/nox-hq/nox/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/nox-hq/nox/compare/v1.4.2...v1.5.0
[1.4.2]: https://github.com/nox-hq/nox/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/nox-hq/nox/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/nox-hq/nox/compare/v0.11.0...v1.4.0
[0.11.0]: https://github.com/nox-hq/nox/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/nox-hq/nox/compare/v0.6.0...v0.10.1
[0.6.0]: https://github.com/nox-hq/nox/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/nox-hq/nox/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/nox-hq/nox/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/nox-hq/nox/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/nox-hq/nox/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/nox-hq/nox/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/nox-hq/nox/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/nox-hq/nox/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/nox-hq/nox/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nox-hq/nox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nox-hq/nox/releases/tag/v0.1.0
