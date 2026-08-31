# Rule family migration — Track J, Milestone 10.1

Track J asks for detector families to be migrated "according to observed
value/risk, not alphabetically", and for each family to answer five questions:
what is the initial observation, what confirms it, what refutes it, what
capability is required, and what remains unknown.

This document answers them. The ordering below is not the roadmap's, because
measuring changed it.

## Where the migration actually stands

`core/migration` measures this, and `TestMigrationCoverageIsMeasuredNotAsserted`
re-runs it. The metric is deliberately narrow: not "has claims" — every finding
has claims, because the scan records an observation for each one, and a metric
that is true by construction measures nothing.

What counts is a claim **stronger than a pattern match**, and it must be
**earned** rather than classified. `reasoning.ObservationKind` hands `TAINT-`
and `VULN-` findings `KindStatic` on the strength of their rule prefix. That is
defensible — dataflow analysis and a version-range match are not pattern
matches — but it is a classification decision, and counting it as migration
would show those families finished on the day the switch was written.

Measured 2026-08-30:

| corpus | findings | above heuristic | **earned** |
|---|---|---|---|
| nox itself | 66 | 2 | **0** |
| precision suite | 37 | 19 | **2** |

Two findings in the entire programme carry evidence that was earned, and both
are the same thing: a GitHub token whose embedded CRC32 checksum verifies.

That is the honest headline. Track J is, by the measure that matters, at the
beginning.

## Why "add more claims" is not the work

This was measured, not assumed. Track E3 took the precision suite from 37
supporting claims to 61 by recording every check the secrets analyzer already
performed, and left the divergence between analyzer confidence and evidence
confidence at exactly 15 — unchanged.

It could not have done anything else. Confidence aggregation takes the
*strongest* supporting claim; every one of those checks is a heuristic; three
heuristics are still a heuristic. The independence promotion cannot apply
either, because they share a producer.

So a family is migrated when it can say something a regex cannot. Filing more
regex results under more sentences is motion, not progress.

## The families

### SEC — 913 rules — *partly migrated, and the only proven path*

- **Observation.** A pattern matched a value that looks like a credential.
- **Confirms.** An embedded checksum that verifies (`KindStatic`). This is the
  one intervention measured to move a finding off the heuristic floor. GitHub's
  CRC32 is implemented; Stripe, Slack, npm and several others encode verifiable
  structure and are not.
- **Refutes.** A checksum that fails, deterministically. Also: the value is a
  documentation placeholder, sits in a comment, or is a known vocabulary word —
  six refiners, all heuristic, all currently used to drop candidates rather than
  to weigh them.
- **Capability required.** None beyond reading the file. That is what makes this
  family the cheapest real progress available.
- **Remains unknown.** Whether the credential is live, whether it is still
  valid, and whether it was ever used. Nox does not and must not check.

### IAC — 490 rules — *24 absence rules migrated; the rest as it was*

- **Observation.** A regex matched text in a configuration file. 433 `regex`
  plus 57 `absence`.
- **Confirms.** For a migrated absence rule: the document was parsed, the
  resource resolved by type, and the attribute is not set (`KindStatic`). That
  is static analysis, and it is the first claim this family has ever been able
  to make. For everything else, still nothing — a regex match over YAML or HCL
  is a heuristic however specific the pattern.
- **Refutes.** Implemented, and it is the half that pays first. A property the
  pattern could not see — reached through a YAML anchor, nested a level deeper,
  or spelled outside the alternation — refutes the finding deterministically.
  Measured: on a template with three buckets, two encrypted (one through an
  anchor) and one not, the regex path reports **2 findings, one of them false**;
  the structural path reports **1**, on the bucket that is genuinely
  unencrypted.
- **Capability required.** Structural parsing, now provided for the three
  document-shaped schemas by `core/rules/structural`: CloudFormation,
  Kubernetes and ARM, in YAML or JSON, on `gopkg.in/yaml.v3` and no new
  dependency. Terraform needs an HCL parser and has none; Dockerfiles are
  line-oriented and have no document to parse.
- **Remains unknown.** Whether the configuration is actually deployed, and
  whether the resource is reachable. Neither is visible from the file.

#### What the migration actually reached, and why it is 24 and not 57

Enumerating all 57 absence rules against the structural model separates them
into five kinds, and only the first can migrate. The counts sum to 57 because
every rule was placed, not sampled:

| kind | rules | why |
|---|---|---|
| resource-and-attribute | **24** | the property belongs to the resource the rule names — migrated |
| not a document | 20 | Dockerfile is line-oriented; Terraform and the GCP rules are HCL; a Helm template is not valid YAML until it is rendered |
| cross-resource | 8 | the property is a *different object*: a VPC's flow log, a Namespace's ResourceQuota, a workload's PodDisruptionBudget, an Azure server's `auditingSettings` child |
| sub-structure anchored | 4 | anchored on `securityContext:`, `hostPath:`, `emptyDir:` or an IAM statement rather than on a resource type |
| predicate-gated | 1 | IAC-096 applies only to a `Microsoft.Web/sites` whose `kind` is `functionapp`, and the descriptor has no field for that condition |

The cross-resource group is the honest next capability: it needs resolution
*across* resources in a document set, not within one, and the model here
deliberately stops at one resource because a lookup that silently searched the
whole file would be the regex behaviour with a parser attached.

The other three are not blocked on the parser at all. Terraform needs an HCL
dependency this scanner does not carry, a Dockerfile has no document to parse,
and the sub-structure rules would need rewriting rather than annotating — each
of which is a decision, not an omission.

#### The two rules that hold this together

- The structural path is used only when the document **parsed AND its schema was
  recognised**. "I could not read this" is not "there is nothing here", and a
  scanner that conflates them turns every unreadable file into an all-clear.
  Everything else falls back to the text path, so migrating a rule adds a
  capability rather than trading one away. `TestUnparseableTemplateFallsBackToTextMatching`
  holds it; removing the guard fails it.
- A wildcard's quantifier is explicit. `spec.template.spec.containers[]`
  satisfied by *one* of three containers has found a vulnerable pod, not a safe
  one, so pod rules use the all-quantifier. Getting this backwards hides
  findings rather than inventing them, which is why it is opt-in per rule and
  not a default.

Measured after, on the precision suite: IAC moves from
`corroborated=0 above=0 earned=0 strongest=heuristic` to
`corroborated=1 above=1 earned=1 strongest=static` — the family's first earned
evidence — with precision and recall both still 1.00.

### AI / MCP / AGENT / AGENTFLOW — 90 rules — *refiners exist, corroboration does not*

- **Observation.** A pattern matched prompt text, a tool declaration, or an
  agent configuration.
- **Confirms.** Nothing today: `corroborated=0` on both corpora. Four refiners
  landed in Track E2 and they all refute, which drops candidates; nothing
  records what was checked about the ones that survive.
- **Refutes.** In place — a constant message, a documentation example, a
  comment, a test fixture.
- **Capability required.** Constant evaluation would establish that a prompt is
  a literal rather than assembled from input, which is the distinction most of
  these rules actually care about. Nothing implements it.
- **Remains unknown.** Whether the prompt reaches a model at runtime, and
  whether any of it is attacker-influenced.

### TAINT — 9 rules — *classified above heuristic, not migrated*

- **Observation.** A dataflow path from a source to a sink, which is genuinely
  static analysis rather than a pattern match — hence `KindStatic`.
- **Confirms.** The path itself. Track F records flow identity, so two findings
  describing one flow are related rather than duplicated.
- **Refutes.** A sanitizer dominating the path. Implemented as a drop, not as a
  weighed claim.
- **Capability required.** `taint` and `symbol_resolution`, both provided.
- **Remains unknown.** Whether the source is attacker-controlled in practice,
  and whether the path is reachable from an entry point. Nothing builds a call
  graph, so `call_reachable` is out of reach for everything.

### VULN — 3 rules — *the applicability ladder, done in Track G*

- **Observation.** A lockfile pins a version an advisory names.
- **Confirms.** The advisory, and — for Go — that the affected import path is
  actually linked.
- **Refutes.** The affected package is not in the build's transitive closure.
  `goVulnReachable` answers `false` only on positive evidence, and Gate B
  enforces that an undetermined result never reads as unreachable.
- **Capability required.** `reachability`, provided for Go only. Every other
  ecosystem is unexamined rather than unaffected, and says so.
- **Remains unknown.** Everything above `symbol_used` on the ladder. No call
  graph, so no `call_reachable`, so no `attacker_reachable`.

## The ordering, revised by measurement

The roadmap's order was: noisy AI rules, secrets, endpoint/API misuse, taint
overlaps, dependency applicability. Measuring suggests a different one.

1. **SEC deterministic verification.** Started, and it went somewhere the plan
   did not predict.

   The checksum path is nearly exhausted at GitHub: its CRC32 is one of very few
   schemes verifiable OFFLINE, and most providers can only be verified by an API
   call, which nox's architecture forbids. So the honest next deterministic
   signal is not another checksum but JWT structure: a JWT's header base64url-
   decodes to JSON naming a signing algorithm, checkable with no network and no
   key.

   Building it surfaced a silent false negative. The data-blob refiner dropped
   any string over 96 bytes as an opaque base64 payload, and a full JWT runs to
   hundreds of bytes — so hardcoded JWTs were discarded before they became
   findings. nox could not see an entire credential class. `lexctx.LooksLikeJWT`
   now stops that: a structurally valid JWT is a credential, not a blob, however
   long. Surfacing it then exposed a dedup gap — three rules match a JWT and did
   not collapse — closed by adding `eyJ` as a canonical owner. End to end: a
   hardcoded JWT goes from zero findings to one, carrying a deterministic claim
   that it decodes as a token rather than resting on the pattern.

   The remaining checksum work (Stripe, Slack, npm) is not there: none publishes
   an offline-verifiable checksum. That is a result, not a gap — it says the
   deterministic wins in this family are the structural ones (JWT, and base64/
   hex decodability), not more checksums.
2. **AI corroboration.** *Done.* The refiners recorded why they dropped a
   candidate and nothing about the ones that survived, so a reported AI
   finding's ledger said only "the rule fired". A survivor now records what was
   checked: that it is in real code, and — for a rule with a context
   requirement — that the context its rule needs was actually present. Measured:
   AI-002 goes from one supporting claim to three. Heuristic, so it moves
   explanation not confidence (E3 measured that), which is the honest ceiling
   for a proximity check. The remaining AI work is constant evaluation — knowing
   a prompt is a literal rather than assembled from input — which needs a
   capability nothing implements yet.
3. **IAC structural parsing.** Largest single piece of work, largest family, and
   the only way 490 rules ever exceed heuristic. Now built for the three
   document-shaped schemas (CloudFormation, Kubernetes, ARM), migrating 24 of
   the 57 absence rules — see the family section above for why it is 24, and
   what the remaining two groups need. Measuring it first also found a bounded,
   high-value bug that did not need the feature:

   Every brace-enclosing absence rule (IAC-051 and its family) silently missed
   CloudFormation written in YAML. The span that bounds a resource block was
   `brace-enclosing`, which walks out to the enclosing `{ }` — and YAML has
   none, so the span came back empty and the rule never fired. Measured: IAC-051
   flags an unencrypted S3 bucket in a JSON template and misses the identical
   bucket in YAML. The rules already listed *.yaml in their file patterns, so
   the format was always in scope; only the span could not reach it. Fixed with
   an indentation-bounded ENCLOSING span — distinct from the block span, a
   distinction a false positive taught: the block span of a `Type:` anchor is
   the scalar alone, so a sibling encryption property fell outside it and an
   encrypted bucket looked unencrypted. This is not the structural rewrite; it
   is one bounded fix the rewrite would have subsumed, delivered now because it
   is a real false negative with a reproduction.
4. **Endpoint/API misuse** is a plugin (`nox-plugin-api-abuse`) and cannot be
   fixed from this repository. Its API-ABUSE-001 sits at precision 0.000 — never
   a true positive on the corpus — which under Milestone 10.2 makes it a
   candidate generator whose output must survive refutation before it becomes a
   finding, rather than an independent judge.

## Milestone 10.3 was answered by C5

10.3 asks to "retire obsolete forms of detector-authored epistemic confidence
rather than indefinitely maintaining two systems". Track C5 measured what that
costs and the answer is no: adjudicated confidence caps at `MEDIUM` for any
static scan, so retiring the analyzer's would take `--min-confidence high` from
11 findings to zero, permanently, on every project. The two systems measure
different things and both are kept. See §2.4.
