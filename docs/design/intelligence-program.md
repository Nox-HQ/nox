# Program: NOX Intelligence, end to end

Status: **in execution**. Companion to `intelligence-service.md` (the what) and
[ADR 0002](../adr/0002-intelligence-layer-is-a-separate-service.md) (the why).
This document is the how, in order.

## The correction this program makes to ADR 0002

ADR 0002 preferred packaging the intelligence client as a **plugin** on the
`intelligence` track, reasoning that this keeps `core/` at zero network
dependencies.

That premise does not hold against the code. `core/analyzers/deps/osv.go`
already performs `client.Do(req)` against `https://api.osv.dev`, **enabled by
default**, from inside `core/`. Core has shipped a network dependency on a
vulnerability service since dependency scanning existed.

What actually preserves *offline-first, zero required external services* is not
the absence of network code. It is three properties that already exist and must
survive this program intact:

1. `WithOSVDisabled()` / `osv.disabled` — the capability is switchable off.
2. `degrade.OSV` — a failed lookup reports *"dependency vulnerabilities are
   under-reported; this scan cannot confirm the absence of known CVEs"* rather
   than a silent clean scan.
3. Every finding remains derivable from data the scan already holds.

**Decision:** intelligence is an in-binary vulnerability source, not a plugin.
Shipping the default vulnerability source behind an optional install would be
worse, not safer. The `intelligence` track profile in `plugin/profiles.go` stays
as-is for third-party enrichment plugins; it is not the delivery vehicle for
this.

## The second correction: superset, not replacement

The request is "same content as OSV, from our system, then beyond". Taken
literally as a *replacement*, that trades a neutral public database
(OpenSSF/Google) for a vendor as sole trust root, and introduces a threat the
design doc does not cover.

`intelligence-service.md` threat-models poisoning **by addition** — Sybil
reporters, malicious metadata, agent manipulation. Replacing OSV introduces
denial **by omission**: an intelligence service that silently *drops* a real CVE
is strictly worse than one that invents a fake, because the client cannot tell
the difference between "no vulnerability" and "not told about the
vulnerability". That is the same failure class as an unexercised active check
reported as an all-clear.

**Decision:** NOX Intelligence is a **verifiable superset**. It serves OSV
content *and* its own, and the client can prove the superset property holds at
any time by querying both and diffing. A suppression — an OSV record the
intelligence service did not return — is a loud, first-class event, never a
silent absence.

This makes the "same content" claim *checkable* rather than merely asserted, and
it is the reason the service speaks the OSV wire protocol as its baseline
surface (Phase 3).

---

## Phase 1 — Extract the source seam

**Pure refactor. No behaviour change. No service. No network change.**

Today `queryOSV` is a package-level function with unexported wire types, called
inline at `core/analyzers/deps/deps.go:574`. The analyzer holds `OSVBaseURL
string` and an `*http.Client`. Nothing is swappable.

### New package `core/vulnsource`

```go
// Query is one package to look up. Ecosystem is nox's own ecosystem name;
// mapping to a wire vocabulary is the implementation's business.
type Query struct{ Ecosystem, Name, Version string }

// Record is a hydrated vulnerability. Shaped as the superset from day one so
// Phase 2 adds fields rather than reshaping the seam.
type Record struct {
    ID               string
    Summary          string
    Details          string
    Aliases          []string
    Severity         []Severity
    Affected         []Affected
    DatabaseSpecific DatabaseSpecific
}

// Source resolves queries to records. Batch-shaped: a per-package interface
// would discard OSV's 1000-query batching, which is why the interface sketched
// in intelligence-service.md is the wrong shape for this seam.
type Source interface {
    Name() string
    Lookup(ctx context.Context, qs []Query) (map[int][]Record, error)
}
```

### The refactor rule

**Everything that is an OSV protocol artifact moves inside the OSV
implementation. The seam exposes only the semantic contract.**

Specifically, these move behind `Source` and out of the analyzer's sight:

- Ecosystem filtering (`osvEcosystem`) and the kept-index remapping. This exists
  because `/v1/querybatch` rejects the *whole* request with HTTP 400 on one
  unknown ecosystem — a Dockerfile once zeroed out every Go/npm/PyPI result in
  the batch. It is an OSV wire quirk, not a seam concern.
- Batching at `osvBatchLimit = 1000`.
- Detail hydration. `/v1/querybatch` returns only `{id, modified}`; severity
  mapping and Go import-path scoping depend on fields it does not send. The seam
  returns **fully hydrated** records; hydration concurrency
  (`osvHydrateConcurrency = 8`) stays inside.
- In-place slice hydration. Result slices are hydrated, never reassigned,
  because map iteration order is randomised and rebuilding would attribute
  vulnerabilities to the wrong packages.

### Contract preserved verbatim

Two fields are load-bearing and easy to lose silently:

- `affected[].ecosystem_specific.imports` — drives `goAffectedImports` /
  `goVulnReachable`. Without it, unreachable Go advisories stop being demoted to
  `SeverityInfo` and severity inflates.
- `database_specific.severity` — the **only** severity signal for GitHub records
  carrying a CVSS v4 vector and nothing else (`mapOSVSeverity`).

Degradation semantics are unchanged: a network error or non-200 adds
`degrade.OSV` and returns partial results, never an error that reads as clean.

### Public API

`WithOSVBaseURL` and `WithOSVDisabled` keep working, reimplemented in terms of a
new `WithSource(vulnsource.Source)`. `OSVConfig` is untouched. No breaking
change to config, CLI flags, or the analyzer's exported surface.

### Exit criteria

- `osv_test.go`, `osv_wire_test.go`, `osv_hydrate_test.go`, `offline_test.go`,
  `deps_test.go`, `reachability_test.go` pass **unmodified**.
- `core/determinism_test.go` and `conformance/` pass.
- A new golden test asserts byte-identical `findings.json` for a fixed corpus
  before and after the refactor.

---

## Phase 2 — Superset model and verifiability in the client

### Records gain epistemic status

OSV answers a closed question: *is there a published advisory for this exact
(ecosystem, package, version)?* Intelligence answers an open one, and those
answers do not have the same standing. `deps.Vulnerability` is today
`{ID, Summary, Severity, Aliases, Details}` — no room for corroboration,
evidence kind, or provenance.

Added to `Record` and carried through to `Vulnerability`, SBOM, and report:

- `Status` — `PUBLISHED` | `CANDIDATE` | `EMBARGOED`
- `Evidence` — delegated to `core/evidence`; the CONFIRMED and semantic-cap
  invariants are not restated here
- `Corroboration` — distinct reporter count, never observation count
- `Provenance` — which source, which upstream record

### `VerifyingSource`

The mechanism that makes the superset claim checkable rather than asserted:

```go
// VerifyingSource queries the intelligence source and OSV, returns the
// intelligence result, and classifies the difference.
type VerifyingSource struct{ Intel, Reference Source }
```

Three outcomes, all named:

| outcome | meaning | client behaviour |
|---|---|---|
| intelligence ⊇ OSV | superset holds | normal |
| intelligence adds records | the value being bought | surfaced with `Status` |
| intelligence omits an OSV record | **suppression** | loud: degradation + finding |

Suppression is never silent. `degrade.IntelSuppression` states that the
intelligence source withheld a record the reference source published, names the
IDs, and says the scan cannot be trusted as complete.

### Gating policy

An uncorroborated `CANDIDATE` must not fail a build the way a published CVE
does — the first false positive would burn the feature. Candidates are demoted
out of gating severity by default, reusing the established
`reachable=false → SeverityInfo` demotion pattern, and are labelled
`THEORETICAL` wherever rendered (CLI, JSON, SARIF, MCP) per the design doc.

### Rendering

`core/report`, SBOM, and VEX all key on vulnerability IDs. A candidate with no
CVE gets a stable, content-derived identifier — `NOX-CAND-<fingerprint>` — from
the same privacy-preserving fingerprint the service clusters on, so the same
logical issue carries the same ID everywhere.

---

## Phase 3 — The intelligence service

New module `github.com/nox-hq/nox-intelligence` at `oss/nox-intelligence`,
importing `github.com/nox-hq/nox-core/evidence` so both sides agree on what
CONFIRMED means. Separate deployable, per ADR 0002.

### Stack

| concern | library |
|---|---|
| HTTP API | **gin** |
| logging + OTel | **bolt** (zero-alloc `slog.Handler`) → Loki/Tempo |
| disclosure + candidate lifecycle | **statekit** (typed statecharts, guards) |
| resilience on upstream fetches and ingestion | **fortify** (circuit breaker, retry, rate limit, bulkhead) |
| agent-facing surface | **mcp-go** |
| research orchestration (Phase 3b) | **agent-go**, bounded and budgeted |

### Why statekit specifically

The disclosure lifecycle is the part of this system where an incorrect
transition is a disclosure leak: `INTERNAL → UNDER_REVIEW → MAINTAINER_NOTIFIED
→ EMBARGOED → PUBLIC`, with guards on every edge and a mandatory human gate
between research and publication. Modelling that with `switch` statements is how
embargoed candidates escape. It is a typed statechart with hierarchical states
and guards — exactly statekit's shape.

### Domain (DDD, dependency rule domain → application → infrastructure)

- **Aggregates**: `Candidate`, `Observation`, `Advisory`, `Reporter`
- **Value objects**: `Fingerprint`, `SourceID`, `VersionRange`, `WeaknessClass`
- **Domain services**: clustering, independent-source estimation
- **Confidence**: delegated entirely to `core/evidence` — not reimplemented

### API surface

```
POST /v1/querybatch          OSV-wire-compatible baseline
GET  /v1/vulns/{id}          OSV-wire-compatible detail
POST /v1/intel/querybatch    superset: + status, evidence, corroboration
POST /v1/observations        contribution ingestion
GET  /healthz /readyz /metrics
```

The OSV-compatible pair is deliberate and load-bearing. It means the untouched
Phase 1 OSV client can be pointed at this service with `WithOSVBaseURL`, which
makes the baseline A/B of Phase 5 a URL swap, and makes the superset property
testable by the *reference implementation itself*.

### Storage

Postgres on Longhorn. Canary deployment runs two versions concurrently against
shared state, which rules out an embedded store.

### Enforced at the store *and* every boundary

Embargoed and internal candidates must not be discoverable through lookup,
search, MCP, or API. Per the design doc, this is enforced in both places,
because a disclosure leak is not the kind of bug to guard against exactly once.

---

## Phase 4 — Client ↔ service integration

New `intelligence` config block. Two **separate** switches, and this separation
is the point:

```yaml
intelligence:
  endpoint: https://intel.nox.example
  query: false          # read intelligence
  contribution: disabled # anonymous | org-private | public-intelligence
  verify_against_osv: true
```

The batch request already sends exactly `(ecosystem, name, version)` per
package — which *is* the redacted observation fingerprint input, minus weakness
class and rule ID. Contribution is therefore nearly free structurally, and that
is precisely the trap: if querying implicitly contributed, `contribution:
disabled` would be a lie while lookups were on. Query and contribute are
independent decisions, both off by default, both printable.

Also in this phase: allowlist redaction in `core/` (never in a plugin, so
nothing third-party can widen what leaves), `SourceID` from a private salt,
`nox intel allowlist` to print the exact field allowlist on demand, and a local
intelligence cache so the CLI works with the service absent.

---

## Phase 5 — Baseline first, then A/B against it

Built on the existing `core/bench` harness (`baseline.go`, `corpus.go`,
`precision.go`) and `core/diff`.

**Run A (baseline)** — OSV only, current behaviour, over a fixed corpus.
Recorded as the reference. Nothing is compared until this exists.

**Run B** — the same corpus through the intelligence source.

Measured:

| metric | gate |
|---|---|
| recall vs baseline | **100%** — every baseline finding reappears |
| suppressions | **0** — any is a hard failure |
| added candidates | reported, with status breakdown |
| determinism | identical output across repeated runs |
| p99 lookup latency | no worse than OSV baseline + budget |

The recall and suppression gates encode the superset property. If they do not
hold, the phase fails and nothing deploys — "we did not exercise it" must never
render as "it is clean".

---

## Phase 6 — Live deployment via rollops

Namespace `nox-intel` on the k3s cluster (`felixgeelhaar` context, edge-1 /
edge-2). Distroless non-root image, matching nox's existing base.

`RolloutConfig` with a canary strategy and — the interesting part — an analysis
gate that is not merely HTTP health:

```yaml
analysis:
  provider: prometheus
  address: http://kps-prometheus.observability:9090
  metrics:
    - name: errorRate
    - name: p99
    - name: suppressionRate   # OSV records the service failed to return
  condition: 'errorRate < 0.01 && p99 < 500 && suppressionRate == 0.0'
rollback:
  auto: true
```

The superset invariant becomes a **rollout gate**. A build that starts
suppressing OSV records fails analysis and auto-rolls back, in production,
without a human noticing first. This is the strongest available answer to the
denial-by-omission threat.

---

## Phase 7 — Founder review UI

Small embedded UI (Go `embed`, served by gin), for the human gate the design doc
requires between research and publication.

- Candidate review queue with evidence dossiers and corroboration counts
- Disclosure state transitions, driven by the statekit machine, with its guards
  visible rather than reimplemented in the frontend
- Suppression and poisoning alerts
- Explicit promote / reject actions — research agents may never autonomously
  disclose

Auth via the existing `auth-go` / `keyward` stack.

---

## Freshness: how often OSV data is updated

Never on a schedule, because nothing is stored on a schedule.

The batch query — *which advisories match this package version* — is live on
every scan. It is one request, and it is the only question whose answer changes
often, so caching it would open a window in which a freshly published CVE is
invisible.

Advisory *documents* are cached, keyed on the advisory id plus OSV's own
`modified` stamp. That is a validator rather than a guess: an entry is reusable
for exactly as long as upstream has not changed the advisory, and misses the
moment it does. There is no staleness window and no TTL.

Measured on a seven-package corpus producing 114 findings:

| scan | batch | detail | bytes |
|---|---|---|---|
| 1 (cold) | 1 | 114 | 517,544 |
| 2 | 1 | 0 | 7,878 |
| 3 | 1 | 0 | 7,878 |

Identical finding set across cold cache, warm cache, and no cache.

One trap worth recording: OSV reports `modified` truncated to microseconds in a
batch response and to nanoseconds in a detail response, for roughly half of all
advisories. Storing an advisory under the detail's value and looking it up with
the batch's meant those advisories missed every scan, refetched, and rewrote the
same file — entry count flat, nothing logged, half the traffic never gone. Only
counting requests exposed it. Entries carry the validator the caller queries by.

The service does not mirror OSV either. It proxies the same live query and
unions the answer with its own candidates, which is what makes the superset
property structural rather than a sync job that can fall behind.

## Execution notes

- Phases 1, 2, 4, 5 land in `nox`. Phase 3, 6, 7 land in `nox-intelligence`.
- `core/evidence` is imported, never forked. One definition of CONFIRMED.
- Each phase is a separate branch and PR against `main`.
