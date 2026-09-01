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
| cross-resource | **7 of 8** | the property is a *different object* — migrated by companion resolution; see below |
| not a document | 20 | Dockerfile is line-oriented; Terraform and the GCP rules are HCL; a Helm template is not valid YAML until it is rendered |
| sub-structure anchored | 4 | anchored on `securityContext:`, `hostPath:`, `emptyDir:` or an IAM statement rather than on a resource type |
| predicate-gated | 1 | IAC-096 applies only to a `Microsoft.Web/sites` whose `kind` is `functionapp`, and the descriptor has no field for that condition |

The remaining three groups are not blocked on the parser at all. Terraform needs
an HCL dependency this scanner does not carry, a Dockerfile has no document to
parse, and the sub-structure rules would need rewriting rather than annotating —
each of which is a decision, not an omission.

#### Cross-resource: 31 of 57, by resolving the companion

The eight cross-resource rules ask whether a resource is protected by a
DIFFERENT object: a VPC by a flow log, a Deployment by a PodDisruptionBudget, a
Namespace by a ResourceQuota or LimitRange, a SQL server by an
`auditingSettings` or `firewallRules` child, a secret by a RotationSchedule.
None of those properties is on the resource the rule names, so the
single-resource model could not reach any of them and the text form searched the
whole file for the companion's NAME instead.

That form is wrong in three measured ways, and `core/rules/structural`'s
companion resolution answers all three:

- **It cannot see linkage.** A PodDisruptionBudget selecting `app: api`
  satisfies IAC-132 for every workload in the file. Measured, on a manifest with
  three workloads and one budget that selects one of them: the text path reports
  **0 findings**; resolution reports **2**, on the workloads nothing protects.
- **It cannot see quantity.** `absenceSpan: "file"` evaluates once and reports at
  the first anchor, so four unprotected Deployments were one finding. Resolution
  decides per subject.
- **It is satisfied by text that is not a resource.** IAC-059's property regex is
  `(?i)FlowLog`, which a `FlowLogsEnabled: false` tag matches — so a VPC with
  logging explicitly turned OFF read as a VPC with logging configured.

Four linkage mechanisms cover the seven rules, and each is named per rule rather
than inferred, because resolving with the wrong one answers "not bound" for
every subject and so invents a finding on each of them:

| link | binds by | rules |
|---|---|---|
| `ref` | a CloudFormation intrinsic naming the subject's logical name — `!Ref`, `!GetAtt`, `!Sub`, and their `Fn::` long forms | IAC-059, IAC-079 |
| `selector` | a Kubernetes label selector matching the subject's **pod template** labels | IAC-132 |
| `namespace` | `metadata.namespace` equalling the subject Namespace's name | IAC-133, IAC-134 |
| `child` | ARM child nesting, or a top-level `"<parent>/<child>"` name | IAC-084, IAC-086 |

The eighth, IAC-153, is cross-*step* rather than cross-resource: it asks whether
a GitHub Actions workflow that uploads an artifact also attests it. A workflow is
a document, but it is not one of the three schemas this package models, so
migrating it needs a fourth family — a new schema, not a new linkage.

##### The three-valued answer is what keeps this sound

Linkage resolves to bound, not-bound, or **undecidable**, and the third value is
the load-bearing one. A selector written with `matchExpressions`, an ARM name
that is a `[concat(...)]` expression, and a flow log pointed at a template
parameter are all cases where the answer needs information the file does not
carry. Reading any of them as "not bound" would report a resource that is very
likely protected. An undecidable pair therefore takes the whole file back to the
text path — the same degradation as an unparseable document, for the same
reason.

The inverse asymmetry is deliberate too. A flow log whose `ResourceId` is a
literal `vpc-0a1b2c3d` is decidably NOT bound to anything this template creates,
because referring to a resource in the same template *requires* an intrinsic.
That is a fact about the companion, not an unknown, and it is the case the text
path most reliably gets wrong.

##### What it cost, and what it found

One fixture changed. IAC-059's "hardened" sample was a VPC beside a flow log
with empty `Properties` — a flow log that targets nothing. It passed only
because the text path counted the word. It is now the true-positive case in
`TestCompanionRefusesAnUnboundFlowLog`, and the hardened fixture references the
VPC as a real template would.

Measured on the precision suite, with a clean sample binding three VPCs through
three different intrinsics and a true positive whose flow log watches the *other*
VPC: precision and recall stay at 1.00, and IAC moves from
`corroborated=1 above=1 earned=1` to `corroborated=2 above=2 earned=2`. Suite
earned evidence goes from 3 to 4.

##### What remains unknown, and is now stated rather than implied

A document set is one file. A PodDisruptionBudget in a second manifest is not
visible, and "no companion in this file" is not "no companion anywhere". That
limit is inherited — the text rule it replaces is scoped to one file too — but
the claim now says what was parsed rather than what is deployed, and
`Hit.Statement` says "the document set" for exactly that reason. Cross-FILE
resolution is the next capability this group would want, and it needs the scan
to hold a document set across files, which nothing does today.

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
2. **AI constant evaluation.** *Built, and smaller than the plan implied.*

   `capability.ConstantEvaluation` had been declared since the capability model
   was written, `core/adjudicate` listed it as a question worth asking — "is
   this value a literal, or is it built from input?" — and nothing answered it.
   It appeared in exactly two places in the tree: its own declaration, and the
   list of things nox cannot do. `capability.Builtins()` described nox as
   resolving "constants where a language engine exists", which was true of no
   engine in the repository.

   `core/consteval` answers it for Go, via `go/ast`, for the same reason the
   taint engine modelled Go first: nox is written in Go, so the parser is free,
   precise and deterministic. Every other language answers UNDETERMINED and the
   capability matrix records Unsupported, because a refutation drops a finding
   and "no evaluator here" must never read as "nothing here".

   What it reaches is narrower than "knowing a prompt is a literal rather than
   assembled from input". It answers one question — does every argument of this
   call resolve to a compile-time constant? — which refutes AI-006 on
   `fmt.Print(promptTemplate)` where `promptTemplate` is a `const`. The rule
   matches `prompt` at a word boundary, so it fires on the NAME of a constant,
   and lexical analysis cannot help: the argument IS code, it is simply code
   whose value is fixed before the program runs. A `var` does not qualify, and
   neither does a name declared in another file of the package — both are
   undetermined, and undetermined stays reported.

   **Measuring it corrected the motivation.** The case that prompted the work
   was four hand-written waivers in nox's own repository reading
   `fmt.Print(bashCompletion) // nox:ignore AI-006 -- shell completion script`.
   Constant evaluation was expected to make them unnecessary. It does not,
   because they were never necessary: `bashCompletion` has no word boundary
   before "Completion" and never matched the pattern. The word "completion" in
   the WAIVER TEXT was the only reason AI-006 fired. Each waiver caused the
   finding it waived. They are deleted, and
   `TestTriggerWordInATrailingCommentDoesNotCreateAFinding` pins the class.

   The remaining AI work is unchanged in kind and now better bounded: knowing
   that a prompt is ASSEMBLED FROM INPUT needs dataflow into the prompt
   expression, which is taint, not constant evaluation. Constant evaluation
   closes only the half where the answer is "this cannot vary at all".

3. **AI corroboration.** *Done.* The refiners recorded why they dropped a
   candidate and nothing about the ones that survived, so a reported AI
   finding's ledger said only "the rule fired". A survivor now records what was
   checked: that it is in real code, and — for a rule with a context
   requirement — that the context its rule needs was actually present. Measured:
   AI-002 goes from one supporting claim to three. Heuristic, so it moves
   explanation not confidence (E3 measured that), which is the honest ceiling
   for a proximity check. The remaining AI work is constant evaluation — knowing
   a prompt is a literal rather than assembled from input — which needs a
   capability nothing implements yet.
4. **IAC structural parsing.** Largest single piece of work, largest family, and
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
5. **Endpoint/API misuse** is a plugin (`nox-plugin-api-abuse`) and cannot be
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
