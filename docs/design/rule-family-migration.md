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

### IAC — 490 rules — *cannot be migrated as it stands*

- **Observation.** A regex matched text in a configuration file. All 490 rules
  are 433 `regex` plus 57 `absence`; nothing parses the document.
- **Confirms.** Nothing available today. A regex match over YAML or HCL is a
  heuristic however specific the pattern, and classifying it otherwise would put
  strength behind the one thing on the ladder that earns none.
- **Refutes.** For the 57 `absence` rules, a real refutation exists and is not
  implemented: absence-by-regex is weak, and the setting may be present in a
  form the pattern does not recognise. Structural lookup could establish that.
- **Capability required.** Structural parsing — resolve the resource, read the
  attribute. That is a feature, not a migration, and it is the single largest
  piece of work implied by Track J.
- **Remains unknown.** Whether the configuration is actually deployed, and
  whether the resource is reachable. Neither is visible from the file.

This family is second-largest and appears nowhere in the roadmap's ordering.
Recording that here rather than letting it stay unmentioned.

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
2. **AI corroboration.** The refiners exist and only refute; recording what was
   checked about survivors is the smaller half of work already begun. It will
   not move confidence — see above — but it makes `nox why` answer "what
   supports it" with something other than the rule firing.
3. **IAC structural parsing.** Largest single piece of work, largest family, and
   the only way 490 rules ever exceed heuristic. Should be scoped as a feature.
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
