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
