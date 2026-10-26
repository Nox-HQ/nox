# NOX Intelligence — what a scan asks, what it sends, and how to turn it off

`nox scan` asks **NOX Intelligence** (`https://intel.klarlabs.de`) which
advisories match each dependency, and verifies every answer against OSV.dev.
This page is the complete account of what that means for the machine running
the scan. If a sentence here is not true of the binary, that is a bug.

## What leaves the machine

| when | what | to whom |
|---|---|---|
| every online scan with a lockfile | `(ecosystem, package, version)` per dependency, as one `/v1/querybatch` request — byte-for-byte the request OSV.dev has always received | the intelligence service, then the reference database (verification) |
| `scan.intelligence.contribute: true` **only** | redacted observations: per finding, the fields in `nox intel allowlist` — fingerprint, rule id, ecosystem/package/version range, verdict — never a path, a line, a snippet, a secret, or a prompt | the intelligence service |
| never | source code, file paths, file contents, prompts, credentials, customer data | — |

| every online scan, when a signed feed is not cached or has expired (24h) | two plain `GET`s of public files: `/v1/feeds/slopsquat` and, when the scan found registry-launched MCP servers, `/v1/feeds/mcp`. Nothing about the project is sent | the intelligence service |

A scan that made the lookup says so once, in a `[network]` line after the
results: how many dependencies, where they went, and how to opt out. A scan that
made no lookup (`--offline`, `--no-osv`, no dependencies) prints no such line.

`nox intel preview <path>` prints exactly what a contribution from `<path>`
would carry, without sending it. `nox intel allowlist` prints every field an
observation may carry; anything not on that list cannot be sent, by
construction (`core/intel/allowlist.go` fails closed).

Reporter identity is an HMAC of a private salt kept in
`$HOME/.nox/reporter-salt`. The salt never leaves the machine; the service
can count *distinct reporters* without learning who any of them are.

## Why the default is the service, verified

The service answers with the same advisory set OSV.dev does — its mirror is
complete against OSV — plus, over time, what only a network can know: how many
independent reporters saw the same issue, how often a finding is dismissed
across the corpus, and early warning for issues that have not reached the
public pipeline yet. When the service has something to add beyond the
advisory itself, it arrives on the finding as `intel_source`,
`intel_corroboration` (distinct reporters, never observation count) and
`intel_confidence`; a plain mirrored advisory carries none of them, and `nox why`
reads them when present.

What makes a compiled-in default defensible is **verification**: every answer
is checked against the reference database, a record the service withheld is
restored from the reference, and the discrepancy is reported as a degradation
on the scan. A service that starts dropping advisories costs its operator
trust immediately and visibly, and never costs the scan a finding. An
unreachable service degrades to exactly the OSV.dev scan nox always ran, and
says so: the scan carries an `intel_unreachable` degradation naming the
endpoint, distinct from the `intel_suppression` a withheld record raises —
silence is not withholding, and the two are never confused. Only when the
reference is unreachable as well does the scan report an advisory under-report
(`osv_lookup`), the one degradation that can hide a finding.

An answer the service marks incomplete is not an answer of "none". Each query
result may carry `nox_coverage` (`complete`, `incomplete`, `unsupported`); a
partial one raises an `intel_incomplete` degradation naming the packages and
sets `meta.advisory_lookup` to `incomplete` in `findings.json`, so `nox diff`
does not compare its advisories against a full scan. A plain OSV.dev response
carries no coverage statement and raises nothing: it claims neither
completeness nor its absence.

## The signed feeds, and the key built into nox

Two feeds come from the service, both signed with one Ed25519 key:
the predictive slopsquat feed (`SLOP-002`, [slopsquat-feed.md](slopsquat-feed.md))
and the MCP advisory feed (`MCP-026`, [mcp-advisory-feed.md](mcp-advisory-feed.md)).
They are used by default, with no configuration, because nox carries the public
half of that key:

- **Key id** `slopfeed-key-v1`, fingerprint `sha256:168327fe999925cd025ddeaf1d1cde605dfd0641395cf021da3259c8b451fa08` (SHA-256 of the raw 32-byte key),
  published at `/v1/feeds/slopsquat.pub.pem` and `/v1/feeds/mcp.pub.pem`:

```text
-----BEGIN ED25519 PUBLIC KEY-----
2ByJdNFjJEs1EDZB5C16bmRdMVdT62k3Ydv1GnqIYQs=
-----END ED25519 PUBLIC KEY-----
```

- **Verification is unchanged**: digest recomputed over the canonical entries, then
  the Ed25519 signature (MCP: over the domain-separated canonical bytes). A feed
  that fails either is never used, is never papered over with a cached copy, and
  is a **blocking** degradation (`--fail-on-degraded`).
- **Your own key wins.** `scan.slop.signature_key_path` and
  `scan.mcp_feed.signature_key_path` replace the built-in key for that feed.
  Findings record which key verified them in `metadata.feed_key`:
  `built-in:slopfeed-key-v1` or `project:sha256:...`.
- **Consulted only when the service is**: online and `scan.intelligence` not
  disabled. `--offline`, `--no-osv`, `scan.osv.disabled` make no request (a
  verified cached copy is still read); `scan.intelligence.disabled` makes none and
  asks for none. In each case the scan records a non-blocking degradation that
  says the feed was **not checked** and why, which is not "no advisories".
- **Opt out per feed**: `scan.slop.disabled: true`, `scan.mcp_feed.disabled: true`.
- **Rotation.** If a feed fails signature verification, nox makes one extra
  request for the key the service serves now. If its fingerprint differs from the
  built-in one, the degradation names both fingerprints and says to upgrade nox
  or to review the new key and pin it with `signature_key_path`. nox never starts
  trusting a key because the server served it.

## Turning it off, at every level

```yaml
scan:
  intelligence:
    disabled: true       # ask the reference database (OSV.dev) directly; the service is never contacted
```

```sh
nox scan --offline       # no lookups at all: zero outbound connections (TestScan_OfflineAsksNobody)
nox scan --no-osv        # same, for the vulnerability lookup only
```

Resolution order for the endpoint:

```text
scan.intelligence.disabled  >  scan.intelligence.endpoint  >  NOX_INTEL_ENDPOINT  >  https://intel.klarlabs.de
```

`NOX_INTEL_ENDPOINT` is read by `nox scan` and by every `nox intel`
subcommand, so a pipeline pointed at a self-hosted service has every command
agreeing on which service that is. `scan.osv.base_url` names the reference
database (a self-hosted OSV mirror works; the default is `https://api.osv.dev`).

## Contributing back

Contribution is a separate decision from querying, and it is off until
`scan.intelligence.contribute: true` is set. A lookup already transmits the
dependency list; it would be a lie to say "contribute: false" meant nothing
was sent, so the two are named separately and documented separately.

### Consent, terms and erasure

Setting `scan.intelligence.contribute: true` is not enough. `.nox.yaml` is
project config and may be committed, so it cannot speak for whoever runs the
scan; consent is recorded **per installation**, in `~/.nox/intel-consent.json`
next to the reporter salt (or beside `scan.intelligence.reporter_salt_path`).

| command | does |
|---|---|
| `nox intel consent show` | prints the contribution terms (the single source: `core/intel/terms.go`) |
| `nox intel consent accept` | shows the terms and records acceptance after you type `yes`; `--accept-terms 2026-10` does it non-interactively and must name the current version |
| `nox intel consent status` / `withdraw` | report / remove the acceptance (no network) |
| `nox intel preview <path>` | the terms, your consent status, and the exact observations a scan would send |
| `nox intel forget` | posts your reporter id and deletion key to `/v1/reporters/erase`, prints the counts the service returns, then withdraws consent and discards the reporter salt, so consenting again is a new, unlinkable reporter. Unreachable or refused: it exits non-zero and changes nothing locally |

Observations are contribution schema 2: the allowlisted fields plus
`schema_version`, `consent_version` (the terms version you accepted) and
`deletion_verifier`. The verifier is the SHA-256 of a deletion key, itself an
HMAC of the private salt under a fixed label; the key is sent only to the erase
endpoint, so only this machine can erase its id once the service has bound the
verifier. If the terms version changes, contribution pauses until you accept the
new one, and each scan says so. With contribution off, a scan makes no
contribution request and says nothing about it. An observation without a
`consent_version` is never sent.

A contribution that fails is recorded as a degradation and never fails the
scan. Only `nox scan` contributes — `diff`, `bench` and `intel preview` derive
observations and send nothing.

Why contribute: independence is counted in distinct reporters, not
observations. One organisation scanning itself a thousand times is one source.
Every reporter that joins makes corroboration — and everything derived from
it — possible for everyone else.

## Operator accounts

`nox intel login`, `register`, `add-operator`, `invite` and `enroll` manage
organisations on the service. None of them are needed to scan or to
contribute anonymously; they exist for organisation-private intelligence and
for operating the service. `--endpoint` on each defaults exactly as above.

## Blast radius across the estate

A scan already answers what a vulnerability reaches *in one repository*, on
data that never leaves. Across an organisation's whole estate, the answer
needs every service at once, which only the service holds. So it asks the
organisation to describe its estate. This is a paid capability
(`blast_radius`, Security plan and above), and the description goes to the
organisation's own private store on the service. It never reaches the shared
corpus or another tenant.

Two commands build that description. Both print it and send nothing unless
`--upload` is given:

```bash
# One service's dependencies, what its own code imports, and the
# capabilities its own code demonstrates.
nox intel components . --service checkout --exposed --data-classes payment

# Bind `nox attack run` traces to a candidate the run exercised.
nox intel evidence attack-result.json --candidate <fingerprint> \
  --component checkout:npm:lodash@4.17.20
```

What each field rests on:

- **The components** come from the scan's dependency inventory. The scan runs
  offline, since an inventory needs packages, not advisories.
- **Reachability** (`vulnerable_path_reachable`) means the service's own code
  imports the package. A candidate is usually an issue nox has never seen, so
  it cannot know the affected symbols. "The service uses this package" is the
  strongest package-level answer, and a missing import is not evidence of
  non-use.
- **Exposure** (`externally_exposed`) is the operator's `--exposed`
  declaration, applied only to packages the service's code imports. Whether a
  service faces the internet is a fact about the deployment, not the source.
- **Capabilities** are derived from sink calls in the service's own code, and
  each derived one cites the call it came from:
  - `exec.Command` gives `shell.execute`, and an HTTP client gives
    `network.egress`.
  - SQL and file sinks give only `database.read` and `filesystem.read`.
    Neither call shows write access, and claiming more than a call shows would
    inflate every assessment.
  - Add the rest with `--capabilities`. `--identities` and `--data-classes`
    are always declared.
  - Test code is excluded throughout.
- **Exploit evidence** is bound to a candidate by `--candidate`, the operator's
  statement. An attack is grounded in your own findings, not in intelligence,
  so nox cannot make that link itself.
  - A run counts as deterministic only if its winning oracle was not a model's
    judgment, and as reproduced only if the determinism gate passed.
  - Only a deterministic, reproduced run can take a component to CONFIRMED on
    the service.

`--upload` replaces the named service's components and leaves every other
service's alone. It needs an organisation token in `NOX_INTEL_TOKEN`; a
`nox intel login` session signs in an operator and is never accepted as one.

## The boundary, in one sentence

The CLI decides *what this means here* (reachability, exposure, blast radius
within one repository) on data that never leaves. The service decides *what
is emerging across the ecosystem* on data that was minimised before it left.
Estate-wide blast radius is the one place an organisation sends a description
of itself, only with `--upload`, and only into its own tenant. See
[design/intelligence-service.md](design/intelligence-service.md) for the
service side and [ADR 0002](adr/0002-intelligence-layer-is-a-separate-service.md)
for why it is a service at all.


## Attested contribution and attack evidence

A reporter id on an anonymous contribution is self-asserted, so the service stores
it and shows it as a triage signal but **never counts it as an independent source**.
Two ways to be counted, both attributed to your organisation (the service can join
them to it; that is the price, so both are off by default):

- Scan observations: set `scan.intelligence.attested: true` (with
  `contribute: true` and accepted terms) and export `NOX_INTEL_TOKEN`, an
  organisation token. Observations then go to `/v1/attested/observations`, and your
  organisation counts as one source however many seats or machines it has. With no
  token the scan sends nothing and says so; it does not fall back to a contribution
  that could not count.
- Attack evidence from your CI: `nox attack run|replay ... --contribute --candidate
  <fingerprint>`. Needs `NOX_INTEL_TOKEN` and the separate attack-evidence terms
  (`nox intel consent attack show|accept|withdraw`, or `--accept-attack-terms
  attack-2026-10`). `nox intel allowlist --attack` prints every field. Nothing about
  the target leaves: no URL, host, route, field names, payloads, responses or
  canaries; only the nox-core `RunReport` fields and a one-way digest of the trace.
  Only runs that actually executed against a target with a sound control and no
  unreachable attempts are sent; everything else is listed as skipped, so "never
  reached" is not stored as "prevented". Refusals (consent, token, candidate,
  `--profile safe`) happen before any attack fires. A failed upload never changes the
  attack's exit code.

The service treats a contributed run as **reporter-scoped**: it can raise your own
exposure view and appear as "reported by N attested reporters", and it cannot change
the candidate's confidence for anyone else or make it CONFIRMED. Erase with
`nox intel forget --attested`. Service-side rules: nox-intelligence
`docs/contributions.md`.
