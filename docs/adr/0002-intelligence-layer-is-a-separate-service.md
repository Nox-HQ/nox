# ADR 0002: The vulnerability intelligence layer is a separate service, not a CLI feature

- Status: Accepted
- Date: 2026-08-23
- Deciders: nox maintainers
- Supersedes: —

## Context

The Vulnerability Intelligence PRD describes a community-powered sensor network:
participating installations contribute privacy-preserving observations, those
observations are corroborated across reporters, autonomous researchers
investigate promising candidates, validated findings become advisories under a
coordinated-disclosure process, and each organisation is told what an emerging
threat means for its own environment.

A first pass implemented a slice of that as `core/intel` plus a `nox intel`
command group: an observation model, redaction, fingerprinting, a
candidate/confidence model, OSV correlation, and a local JSON store.

That framing conflates three things with genuinely different requirements:

1. **Deriving and minimizing** security facts from a scan. Pure computation over
   data the CLI already has.
2. **Aggregating** those facts across many independent reporters, and
   investigating what they mean. Requires state that spans tenants, an identity
   model, budgets for LLM research, and an operator.
3. **Interpreting** intelligence against one organisation's own topology.
   Requires data the organisation will not upload.

Only (1) and (3) can live in a CLI. (2) cannot: cross-reporter aggregation is
meaningless in a process that only ever sees one reporter. A local
`IndependentSources()` count is always 1, so the confidence model — the thing
that makes the intelligence worth reading — degenerates.

Shipping (2) as a CLI feature would also put multi-tenant auth, a database,
embargo handling, and an on-call rotation inside a binary whose release cycle,
threat model, and support expectations are built for none of that.

## Decision

**The intelligence network is a separate service.** The CLI does not ship a
stand-in for it.

The split follows what the data can and cannot leave:

### Client-side, in the binary the user runs

- **Redaction and minimization.** Non-negotiable. If the server performs the
  redaction, the raw data has already left the environment. The privacy contract
  — *share security facts, not customer artifacts* — is only credible if
  minimization happens in a binary the user can audit, and is governed by an
  allowlist of shareable fields rather than a denylist of patterns.
- **Observation derivation and fingerprinting**, so what is computed locally is
  exactly what would be shared.
- **The private evidence graph, exposure, and blast radius.** The shared network
  knows *what the vulnerability is*; the private graph knows *what it means to
  this customer*. Organisations will not upload their service topology,
  identities, or capability matrix, and should not be asked to.
- **A local cache** of intelligence, so the CLI works with the service absent.

### Service-side

- Cross-tenant observation ingestion, clustering, and independent-source
  estimation.
- Candidate promotion, research-agent orchestration and budgets, evidence
  dossiers.
- Advisory publication, alias management, embargo and coordinated disclosure.
- Early warning distribution.
- The shared Security Evidence Graph.

### Shared

`core/evidence` — the exploitability lifecycle, evidence kinds and strengths,
provenance, and confidence aggregation. Both sides must agree on what CONFIRMED
means, so the rules live in one importable package rather than being restated on
each side of the wire.

## Consequences

- `core/intel` and the `nox intel` command group are **removed** from the CLI.
  They are archived on `archive/intel-domain-library-wip` — an incomplete
  snapshot that does not build — because the client-side half is work a future
  service still needs and re-deriving it is waste.
- `core/evidence` stays and ships, with `core/attack` as its consumer today. Its
  `Reach` exposure ladder was removed along with `core/intel`: an exported API
  with no consumer is speculative surface, and it is specified in
  `docs/design/intelligence-service.md` for whoever builds the service.
- nox's stated constraint — *offline-first, zero required external services* —
  is preserved rather than quietly eroded. A scanner that needs a backend to be
  useful is a different product.
- The CLI gains no intelligence capability in the short term. This is the
  intended trade: a local-only `nox intel` would have implied a network that
  does not exist, and "we know of no candidate" would have read as "nothing is
  wrong" when it only ever meant "nobody told this binary anything".
- When the service exists, the CLI integrates through a narrow client interface.
  Making that client a plugin on the existing `intelligence` track is the
  preferred option, so the network capability is opt-in **by installation**
  rather than by a config default — a stronger guarantee. Redaction stays in
  core regardless, so no third-party plugin can widen what leaves.

## Options considered

### Option A — Intelligence as a separate service (CHOSEN)

As above.

### Option B — Ship the local-only slice now, add a backend later

Rejected. The confidence model does not survive the reduction: with one
reporter, corroboration is undefined and every candidate sits at LOW. Users
would learn to ignore the output before the service ever arrived, and `nox intel
lookup` returning nothing would be read as an all-clear.

### Option C — Everything in the service, including redaction

Rejected. It inverts the privacy contract: data must be minimized before it
leaves, not after it arrives. It would also make the private evidence graph a
hosted asset, which is precisely the thing organisations will not hand over.

## References

- `docs/design/intelligence-service.md` — the service and client-boundary design
- `docs/attack.md` — dynamic exploit validation, which shares `core/evidence`
- `CLAUDE.md` — "Offline-first: zero required external services"; "No SaaS, no
  dashboards — Nox is a security primitive, not a platform"
