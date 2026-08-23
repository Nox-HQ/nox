# `nox intel` — vulnerability intelligence and blast radius

A vulnerability scanner answers: *is something I use listed in a database of
known vulnerabilities?*

That question is reactive by construction. A vulnerability has to enter a
disclosure pipeline before any scanner knows about it, and even once it does,
"you have 12,481 vulnerable components" is not a decision — it is a backlog.

`nox intel` answers a different question:

> What is emerging, can we prove it, does it affect **this** environment, what is
> the blast radius, and what breaks the attack path?

```text
Observe → Corroborate → Correlate → Assess exposure → Contain
```

## Privacy is the product

> **Share security facts, not customer artifacts.**

Contribution is **off by default**. Nothing leaves your environment unless you
explicitly choose a sharing mode. What may ever be shared is governed by an
**allowlist** of fields, not a denylist of patterns — a field that nobody
deliberately allowed cannot leak, however it got added.

Never shared, in any mode: source code, file paths, prompts, credentials,
secrets, file contents, customer data, raw application traffic.

| mode | behaviour |
|---|---|
| `disabled` (default) | no observation leaves the environment |
| `anonymous` | privacy-preserving security facts contribute to aggregate intelligence |
| `org-private` | observations stay inside your organisation's own network |
| `public-intelligence` | eligible validated observations may contribute to the ecosystem, under disclosure policy |

`nox intel status` prints the current mode and the full allowlist, so the answer
to "what would you send?" is always one command away.

## Volume is not corroboration

The failure mode this model exists to avoid:

```text
100 scans from one project
      ≠
100 independent confirmations
```

Candidates count **distinct reporters**, not observations. One project scanning
itself a thousand times produces one independent source and stays at LOW
confidence. Unattributed observations never count as independent, because an
unattributed claim cannot be shown to be independent of any other.

## The evidence ladder

Every claim carries a kind, a strength, and a provenance:

```text
heuristic observation
     ↓
independent observation
     ↓
research hypothesis
     ↓
source-level confirmation
     ↓
controlled reproduction
     ↓
dynamic exploit confirmation
     ↓
maintainer confirmation / public advisory
```

Confidence is `LOW` / `MEDIUM` / `HIGH` / `CONFIRMED`, with two rules that are
enforced in code rather than by convention:

- **CONFIRMED requires deterministic evidence** at reproduction strength or
  above. No pile of heuristics, no number of repeated observations, and no LLM
  judgment reaches it.
- **A semantic-only ledger is capped at MEDIUM.** Restating an opinion is not
  evidence, however many times a model restates it.

`nox intel show <candidate>` prints the whole ledger — every claim, its source,
its weight — with machine-verified claims marked `*` and model judgments marked
`~`. Provenance is what makes the intelligence trustworthy, so it is never
summarised away.

## Exposure and blast radius

Inventory is not impact. Knowing a vulnerable package sits in 200 repositories
tells you nothing about what an attacker gets. `nox intel exposure` intersects a
candidate with **this** environment and walks a ladder where every rung keeps its
own evidence:

```text
PRESENT → REACHABLE → EXPOSED → EXPLOITABLE → VALIDATED → CONFIRMED
```

A candidate with no dynamic evidence can never be labelled CONFIRMED, and a
theoretical path is labelled THEORETICAL wherever it is rendered — CLI, JSON,
MCP. Presenting a projection as an observation is the single most damaging thing
a tool in this category can do.

Blast radius is reported across dimensions, each item carrying its own reach:

- **services** — what becomes reachable
- **capabilities** — what actions become available (`filesystem.read`,
  `secret.read`, `network.egress`, …)
- **identities** — which roles, credentials, and scopes become reachable
- **data classes** — what data becomes accessible

## Containment

For an emerging vulnerability with no patch, the useful question is not "how do
we fix it" but "what is the smallest change that breaks the attack path". nox
distinguishes:

- **remediation** — permanently fixes the vulnerability
- **containment** — breaks the exploitable attack path
- **mitigation** — reduces likelihood or impact

Each option carries a **projected** reach, explicitly labelled as projected. A
projection is a hypothesis about a graph, not a verified outcome.

## Disclosure safety

Candidates carry a disclosure state: `INTERNAL`, `UNDER_REVIEW`,
`MAINTAINER_NOTIFIED`, `EMBARGOED`, `PUBLIC`. Embargoed and internal candidates
are **not discoverable** through general lookup — filtered in the store and again
at the command boundary, because a disclosure leak is not the kind of bug to
guard against in exactly one place.

## Usage

```bash
# 1. Scan produces findings.json
nox scan . --output .

# 2. Turn findings into observations and cluster them into candidates
nox intel observe --workspace my-team --salt "$NOX_INTEL_SALT"

# 3. Fold in dynamic evidence from `nox attack`
nox intel observe --exploits attack.trace.json

# 4. What do we know about a package
nox intel lookup npm:left-pad@1.3.0

# 5. Why do we believe it
nox intel show NOX-CANDIDATE-1a2b3c4d

# 6. What does it mean for us
nox intel exposure NOX-CANDIDATE-1a2b3c4d --components components.json

# 7. What would we ever share
nox intel status --mode anonymous
```

The local store lives in `.nox/intel` — inside the repo, so a team can review
what their scanner learned rather than trusting a hidden global cache.

## Where dynamic validation fits

`nox attack` and `nox intel` share one spine (`core/evidence`), so a confirmed
exploit means the same thing in both. A CONFIRMED, deterministic, reproduced
attack trace is the strongest evidence nox can produce on its own, and folding it
into a candidate is what moves it from "we think this is real" to "we
demonstrated it". An INCONCLUSIVE or unreproduced trace does not.

The two packages do not depend on each other: the hand-off is a small neutral
struct, so neither model is hostage to the other's shape.

## Honest limits

- **This is V1.** The observation model, confidence model, OSV correlation, local
  store, and exposure analysis are here. Autonomous research agents, a shared
  sensor network, published NOX advisories, coordinated disclosure, and
  mitigation simulation are not.
- **No network in this package.** The store is local JSON and advisory data is
  supplied by the caller. nox stays offline-first.
- **Absence of a candidate is not absence of a vulnerability.** `nox intel
  lookup` returning nothing means nox knows nothing, and says so in those words.
- **Correlation is not causation.** Where nox learns which mitigations appear to
  work, it will say "appears to" — observational data does not establish a causal
  defense.
