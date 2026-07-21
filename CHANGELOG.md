# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/nox-hq/nox/compare/v1.12.2...HEAD
[1.12.2]: https://github.com/nox-hq/nox/compare/v1.12.1...v1.12.2
[1.12.1]: https://github.com/nox-hq/nox/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/nox-hq/nox/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/nox-hq/nox/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/nox-hq/nox/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/nox-hq/nox/compare/v1.9.2...v1.10.0
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
