# Design: NOX Intelligence Service

Status: proposed. Nothing here is implemented. The decision to build this as a
service rather than a CLI feature is recorded in
[ADR 0002](../adr/0002-intelligence-layer-is-a-separate-service.md).

## Purpose

Turn many independent nox installations into a network that notices emerging
vulnerabilities before the disclosure pipeline does, investigates them, and tells
each organisation what they mean for its own environment.

```text
Observe → Corroborate → Research → Validate → Assess exposure → Contain
```

The CLI keeps answering "what is dangerous here?" offline. The service answers
"what is emerging across the ecosystem, and does it reach you?"

## Boundary

The single most important property is that **minimization happens before data
leaves**. Everything else follows from that.

```text
┌─ nox CLI (offline-first, ships in the binary) ──────────────┐
│                                                              │
│  scan ──► findings ──► observation ──► REDACT (allowlist)    │
│                                             │                │
│  private evidence graph ◄───────────────────┤                │
│    topology, identities, capabilities       │                │
│    exposure + blast radius (never uploaded) │                │
│                                             │                │
│  local intelligence cache ◄─────────────────┤                │
│    works with the service absent            │                │
└─────────────────────────────────────────────┼────────────────┘
                                              │ security facts only
                                              ▼
┌─ NOX Intelligence Service (multi-tenant, operated) ─────────┐
│  ingestion ─► clustering ─► independent-source estimation    │
│                    │                                          │
│                    ▼                                          │
│  candidates ─► research orchestration ─► evidence dossiers    │
│                    │                                          │
│                    ▼                                          │
│  advisories ─► embargo / coordinated disclosure ─► early warn │
│                                                                │
│  shared Security Evidence Graph                               │
└───────────────────────────────────────────────────────────────┘
```

`core/evidence` is imported by both sides. One definition of CONFIRMED.

## Client responsibilities

### Redaction, by allowlist

An observation may carry only fields somebody deliberately allowed. A denylist of
patterns fails the moment a new field is added; an allowlist fails closed.

Never leaves the environment, in any mode: source code, file paths, prompts,
credentials, secrets, file contents, customer data, raw application traffic.

The client must be able to print the exact allowlist on demand, so "what would
you send?" is answerable without reading the code.

### Privacy-preserving fingerprints

An observation fingerprint hashes only `(ecosystem, package, normalized version
range, weakness class, rule id)`. Never content, never paths. Two reporters
seeing the same logical issue must produce the **same** fingerprint — that is
what makes corroboration possible at all — while the fingerprint reveals nothing
about either reporter.

### Opaque reporter identity

`SourceID` is a stable, non-reversible identifier derived from a private salt. It
exists so the service can count *distinct reporters* without learning who they
are. Unattributed observations never count toward independence.

### Contribution modes

| mode | behaviour |
|---|---|
| `disabled` (default) | nothing leaves the environment |
| `anonymous` | security facts contribute to aggregate intelligence |
| `org-private` | observations stay inside the organisation's own instance |
| `public-intelligence` | eligible validated observations may contribute to the ecosystem, under disclosure policy |

Off by default, always. Enabling is an explicit act.

### The private evidence graph

Topology, identities, capabilities, data classes, and the exposure/blast-radius
computation over them stay on the client. The service supplies *what the
vulnerability is*; the client decides *what it means here*.

Exposure walks a ladder where every rung keeps its own evidence:

```text
PRESENT → REACHABLE → EXPOSED → EXPLOITABLE → VALIDATED → CONFIRMED
```

A candidate with no dynamic evidence can never be labelled CONFIRMED. A
theoretical path is labelled THEORETICAL wherever it is rendered — CLI, JSON,
MCP. Presenting a projection as an observation is the most damaging thing a tool
in this category can do.

Blast radius is reported per dimension — services, capabilities, identities, data
classes — with each item carrying its own reach label, so a capability an
attacker *might* reach never reads like one they demonstrably do.

Containment distinguishes **remediation** (fixes it), **containment** (breaks the
attack path), and **mitigation** (reduces likelihood), each with a *projected*
reach that is explicitly labelled as projected.

## Service responsibilities

### Corroboration, not volume

```text
100 scans from one project  ≠  100 independent confirmations
```

Clustering counts distinct reporters. This is the rule the CLI cannot enforce on
its own — locally there is only ever one reporter — and it is the reason the
service exists.

### Confidence

Delegated to `core/evidence`, with the two invariants that hold on both sides:

- **CONFIRMED requires deterministic evidence** at controlled-reproduction
  strength or above. No quantity of heuristics, repeated observations, or model
  judgments reaches it.
- **A semantic-only ledger is capped at MEDIUM.** Restating an opinion is not
  evidence.

### Research orchestration

Bounded, budgeted agents that investigate candidates: advisory correlation, code
and history analysis, threat modelling, reproduction, mitigation, impact. They
may search public sources, read available source, compare versions, and run
sandboxed reproductions. They may **not** autonomously disclose a novel
vulnerability, contact maintainers as if human, publish working exploit detail,
or attack arbitrary internet targets. Research and publication are separate
workflows with a human gate between them.

### Disclosure

States: `INTERNAL`, `UNDER_REVIEW`, `MAINTAINER_NOTIFIED`, `EMBARGOED`, `PUBLIC`.
Embargoed and internal candidates must not be discoverable through general
lookup, search, MCP, or API — enforced at the store *and* at every boundary,
because a disclosure leak is not the kind of bug to guard against in exactly one
place.

## The seam

The CLI reads intelligence through a narrow interface and works with no backend:

```go
// Source supplies intelligence to the client. The local cache and a remote
// service are both implementations; absence of a service is not an error.
type Source interface {
    Lookup(ctx context.Context, ecosystem, pkg, version string) ([]Candidate, error)
    Get(ctx context.Context, candidateID string) (Candidate, error)
}
```

Preferred packaging for the remote implementation: a plugin on the existing
`intelligence` track, alongside `risk-score` and `threat-enrich`. That keeps
`core/` at zero network dependencies and makes the network capability opt-in **by
installation** rather than by a config default. Redaction stays in core, so no
third-party plugin can widen what leaves.

## Threat model of the network itself

The network is a target. Repositories, advisories, READMEs, issue bodies,
comments, prompts, MCP resources, and package metadata are all **untrusted
research inputs** — a research agent reading them is a prompt-injection sink.

Threats to design against: intelligence poisoning, Sybil reporters, agent
manipulation via malicious package metadata, research resource exhaustion,
package reputation attacks, zero-day harvesting by observers, cross-tenant
leakage, and unsafe reproduction escaping its sandbox.

Trust matters more than telemetry volume. A network that is easy to poison is
worse than no network.

## Relationship to dynamic exploit validation

`nox attack` produces the strongest evidence nox can generate on its own: a
CONFIRMED, deterministic, reproduced attack trace. Folding one into a candidate
is what moves it from "we think this is real" to "we demonstrated it". An
INCONCLUSIVE or unreproduced trace does not.

The hand-off is a small neutral struct, not a package dependency, so neither
model is hostage to the other's shape:

```go
type ExploitEvidence struct {
    TraceID, Fingerprint string
    Exploitability       evidence.Exploitability
    Deterministic        bool
    Reproduced           bool
    ObservedAt           string
}
```

## Deliberately out of scope for a first service

Published NOX advisory identifiers, OSV-compatible upstream publication,
mitigation simulation, post-exploitation blast-radius validation, and the
autonomous research flywheel. Each depends on the corroboration and confidence
foundations being trusted first.

## Prior art in this repository

An incomplete client-side implementation — redaction by allowlist,
privacy-preserving fingerprinting, and the candidate/confidence model — is
archived on `archive/intel-domain-library-wip`. It does not build; it is a
starting point, not a dependency.
