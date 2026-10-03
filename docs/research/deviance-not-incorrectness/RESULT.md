# Deviance is not incorrectness: result — decision B, exploratory only

Measured 2026-10-03. Research basis: Engler et al., *Bugs as Deviant Behavior*
(SOSP 2001), and Li & Zhou, *PR-Miner* (ESEC/FSE 2005). Both find bugs as
departures from what most of a codebase does.

> **Question:** can structural deviance within a coherent rule family surface
> detector implementation defects, without turning majority behaviour into a
> correctness oracle?
>
> **Answer, on nox's secret rules: no, not at useful precision.** At HEAD, 67
> rules break a mined structural invariant, and none of them is an
> implementation defect with a consequence. Retrospectively, mining the
> v1.35.0 rule set flags 54 rules: **0 of them** were among the 185 rules
> changed afterwards, and the CSP/ETag construction does not surface at any
> threshold where deviance still means a minority. Worse, its strongest
> invariant at v1.35.0 *is* that defective construction, and its one exception
> is a well-built rule.
>
> Deviance did lead to real things worth reading: an inventory of 31 rules with
> no credential body, and a dead anchor. Every one of them came from a human
> reading the exceptions, not from the signal being right.

Nothing here is wired into `nox rule-review`. The tooling stays in this
directory.

## What was run

**Input: the built rule set, never source text.** I dumped every exported field
of every rule by reflection (`dump_reflect_test.go.tmpl`), so the same dump
works on any version of the `Rule` struct. The existing `TestDumpRuleSet`
omits `KeywordTokens`, `OptIn` and `References`, and a partial dump has given
confident wrong answers three times before (see its own comment).

- **HEAD** (`863dccc`, the rule set unchanged since `5f86aa1`): all 1,497 rules, of which 883 are SEC.
- **v1.35.0**: 911 SEC rules and 88 AI rules. This is the last release with the
  CSP/ETag construction and with all six later-withdrawn AI rules.

**Features** (`features.py`) are read off each definition:

- format prefix, assignment binding, bare token, proximity gate;
- `vendor_bound`, `secret_shape`, `min_entropy`, post-match validation;
- word boundary, case-insensitivity, quoted value, keyword-in-pattern, capture
  group, file filter;
- severity, confidence and remediation shape.

A format is looked for only in the **value part**, after the last binding. A
vendor name in `fastly…[=:]` says where a value sits, not what it looks like.

**Families** come from the claim each rule makes: vendor credential, URL
credential, private key, generic, JWT, password or entropy. Mining runs within
one family.

**Invariants** (`mine.py`) have the form `A → C`, where C is one feature or the
OR of two *evidence* features. An invariant is kept at confidence ≥ 0.90,
support ≥ 20 and at most 10% exceptions. Disjunctions never mix in severity or
confidence: an early version produced `format_prefix OR severity=high`, which
is true of almost everything and means nothing.

**Genealogy.** Every invariant is counted twice: over rules, and over
**lineages**, where rules sharing a pattern skeleton (vendor names masked)
count as one vote.

**The extractor was wrong four times before it was usable.** It missed
`AKIA|ASIA` and `ph[xsar]_` as prefixes, read the vendor name in a binding as a
format, and missed gitleaks' `(?:=|>|:{1,3}=…)` operator as a binding. Each
was found by checking features against rules whose structure I could verify by
eye. That is itself a finding: the features are regex-over-regex, and they are
only as good as the last rule someone checked them against.

## The retrospective: CSP/ETag

At v1.35.0, 159 vendor rules were a bare character class gated only by the
vendor's name nearby. A Content-Security-Policy header three lines above an
ETag made five of them (SEC-454, 455, 546, 662, 665) report that ETag as a
credential. The v1.36.0 fix bound the vendor name to the value. In the code's
own words, that is "the idiom … every rule from SEC-936 down was written with".
So the fix *was* a family norm, which made this the best case deviance mining
could hope for.

| min confidence | invariants | rules flagged | later changed | CSP five flagged |
|---:|---:|---:|---:|:---:|
| 0.95 | 7 | 10 | 0 | 0/5 |
| **0.90** | 9 | 54 | **0** | 0/5 |
| 0.85 | 9 | 54 | 0 | 0/5 |
| 0.80 | 13 | 143 | 0 | 0/5 |
| 0.75 | 16 | **393** | 166 | 5/5 |
| 0.70 | 19 | 491 | 171 | 5/5 |

The defect appears only once 46% of the family counts as "exceptions". At that
point the output is not an outlier list; it's a split. The step from 0 to 166
later-changed rules has no plateau on either side. It is the shape of a
threshold fitted to a known answer, so no threshold is proposed.

**Majority structure ratified the defect.** The strongest invariant mined at
v1.35.0 is **`secret_shape → bare_token`: 159/160 rules (99.4%), 41/42
lineages (97.6%)**. That *is* the CSP/ETag construction, stated as the norm.
Its single exception is **SEC-437**, Slack's `xox[baprs]-…`, one of the few
rules in that sub-family carrying a real format. Had this signal shipped, it
would have sent a maintainer to the rule that was built right and implied the
159 were normal. This is question 9, answered by measurement rather than by
caution.

## The adjudicated cases

| Case | What deviance mining does | Required |
|---|---|---|
| CSP/ETag vendor construction | not surfaced at any minority threshold; its majority form is ratified (above) | should surface — **fails** |
| RSA private exponent (SEC-161) | the entropy family has 2–3 rules, below the 20-rule floor, so nothing is mined. **Pooled across families, SEC-161/162 become exceptions to the vendor norm `→ binding OR prefix`**, the exact demand the corpus vetoed | must not prescribe — holds only while families stay separate |
| Vendor-pair spellings (25 B-group rules) | 8–10 members flagged, only by severity/confidence invariants or real format structure (SEC-059); no invariant concerns duplication | must not prescribe — holds |
| Rare structured credentials | Telegram `\d{8,10}:…`, Mailchimp `-us\d`, Facebook `id\|secret`, MaxMind `…_mmk`, Ably, Terraform `.atlasv1.` all flagged | must not prescribe — holds as "inspect", but they make up 7 of the 12 design-invariant exceptions |
| AI-022/023/028/029/037/041 withdrawals | 88 AI rules yield 2 weak invariants; **none of the six is flagged by anything**; structurally they are ordinary rules that pin a parameter | must admit it cannot explain — confirmed |

## Every exception at HEAD, labelled

At HEAD there are 23 invariants in the vendor family. 11 are structural and
produce 67 exceptions; every one was read. Labels are recorded per rule in
`measurements.json` (`structural_exception_labels`).

| Label | Rules |
|---|---:|
| artifact: breaks only a co-occurrence invariant, or the extractor missed its structure | 49 |
| 2 — valid exceptional behaviour | 12 |
| 3 — proposition question | 4 |
| 1 — implementation deviation **with a consequence** | **0** |
| 1 — implementation deviation, no consequence | 1 |
| unresolved | 1 |

**Most exceptions come from style, not design.** 55 of the 67 break only
invariants such as `case_insensitive → assignment_binding`. That one holds
because binding rules write `(?i)` for the vendor name, so every prefix rule
with an inline `(?i)` "violates" it. The miner cannot tell a design convention
from a co-occurrence; a person had to sort them. Only one invariant has a
security rationale, `vendor → binding OR format_prefix`, and its 12 exceptions
are:
- 7 real formats with no literal prefix;
- 4 Azure identifier rules (SEC-419/420/421/523);
- 1 unresolved (SEC-450, LogRocket `1/[a-z0-9]{32}`, which needs the vendor's
  format to judge).

**SEC-412 is the one implementation deviation.** It is the only quoted-value
rule that is case-sensitive (`aws.{0,20}?["']…`). Run against
`aws_secret_access_key`, `AWS_SECRET_ACCESS_KEY` and `Aws_Secret`, the binary
reports all three through SEC-002 or SEC-081, which own the span. The deviation
is real, and reading it correctly ends in changing nothing.

## What reading the exceptions found

These came from a human following the exceptions, and they are the strongest
argument that the *tooling* is worth keeping. They are not evidence that the
*signal* is.

**31 vendor rules have no credential body.** Their pattern is a fixed literal,
the same 31 at v1.35.0 and HEAD. The feature that finds them was defined
*after* reading the Azure exceptions, so this is post-hoc and not a
retrospective result. They split across all three classes:

- **Proposition questions (class 3).** Resource identifiers matched as
  CWE-798 credentials with "Rotate the exposed credential immediately":
  AWS ARN prefixes (`arn:aws:` for rds, iam, secretsmanager, ecs, lambda, s3,
  ec2, dynamodb and sqs), the S3 hostname, the GKE `clusters` path, the Azure
  subscription and tenant path segments, the Key Vault and Microsoft login
  hostnames, the Kafka bootstrap-servers key, an Oracle Cloud hostname, and
  the `kubectl create secret` command. Also the OpenSSH key-line header, which
  introduces a *public* key. The exact patterns are in
  `core/analyzers/secrets/rules.go`, SEC-410 to SEC-532.
- **Prefix-only implementations of real formats (class 1 in shape).** For
  `glpat-`, `SG\.` and `sk_live_`, full-format siblings exist (SEC-018,
  SEC-309, SEC-338). For `ya29\.`, the Facebook `EAAC` prefix and the Bedrock
  prefix, **none does**, so the prefix rule is the only coverage, and narrowing
  it could lose recall. That is the RSA-key shape again: an obvious cleanup the
  evidence may veto.
- **Valid exceptional (class 2).** SEC-008, the GCP service-account JSON
  marker: the matched file carries a private key.

Most never fire on the pinned corpus, because their keyword pre-filters are
spellings code rarely contains. **They do fire on prose that names them.** The
first draft of this section quoted four of the literals verbatim, and nox's
own pre-commit hook blocked the commit with SEC-008, SEC-419, SEC-463 and
SEC-532 findings on this document. SEC-419 needed only the Azure path segment
plus its pre-filter keyword, which the draft also quoted. So the descriptions
above are paraphrased on purpose, and the paraphrase is checked: its first
version still named the Kafka key verbatim, and SEC-434 fired. This mirrors
`recorded-http-exchanges.md`, whose rule fired on the text explaining it.

They came from three batch commits on one day (2026-02-15: "add 31 more
secrets rules (SEC-411 to SEC-441)", then SEC-442 to 492, then SEC-493 to
549). The skeleton genealogy counts them as 31 independent lineages, because
every literal differs.

**A dead anchor.** SEC-519 "AWS SNS Topic ARN" matches `arn:aws:snq:`, but SNS
ARNs read `arn:aws:sns:`, so the rule cannot fire on a real ARN. No structural
miner can see a typo.

None of this prescribes anything. It is listed for a maintainer to read, under
the standing rule that a rule is fixed by its claim, not removed.

## The ten questions

1. **Can coherent families be identified reliably?** Only the vendor family is
   large enough to mine (831–857 rules). Entropy, private-key, generic, JWT and
   password families are 2–11 rules each. And **the family boundary is
   load-bearing**: pooled, the vendor norm becomes a demand on the entropy
   rules (SEC-161/162), which is the RSA-key mistake.
2. **Which features are meaningful?** Very few. Format prefix, binding and
   credential body carry design meaning. Case, word boundaries, capture groups
   and keyword spelling only co-occur with design, and they generated 55 of
   67 exceptions. The miner cannot tell the difference itself.
3. **Does family-level deviance surface known defects?** Retrospectively, no:
   0 of 185 later changes, and CSP/ETag invisible at every minority threshold.
4. **How often are outliers legitimate?** For the one meaningful invariant at
   HEAD: 7 of 12 valid, 4 proposition questions, 1 unresolved, 0 defects.
5. **Does genealogy change inferred invariants?** Yes, materially, and the
   genealogy definitions disagree. Collapsing by pattern skeleton moves
   "prefix OR binding" at v1.35.0 from 79.7% to 89.4%. That is still under 0.9,
   so it changes the answer only at a threshold chosen after the fact. The same
   skeleton genealogy counts the 31 literal-only rules, written in three batch
   commits on one day, as 31 lineages, because literals differ. Skeleton identity undercounts template copying of literal
   rules and overcounts it for shared shapes.
6. **Useful without a combined score?** The signal is not useful even as a
   plain list, so a score would only hide that.
7. **Can it explain its evidence?** Yes, an invariant with support, confidence
   and exceptions explains itself. But the explanation was wrong 49 times in 67,
   and a clear explanation of a spurious norm is still a spurious norm.
8. **Coverage beyond existing rule-review signals?** No overlap with the
   prevalence-collapse rows, so it is new coverage. Being new does not make it
   precise.
9. **Does it reward majority design when the majority is wrong?** Yes, and
   measurably: `secret_shape → bare_token`, 99.4%, exception SEC-437.
10. **Can its limits be stated?** Yes, and they are the result:
    - families under 20 rules are invisible;
    - propositions are invisible (the AI withdrawals);
    - a defect shared by a large minority is invisible, and a majority defect is
      endorsed;
    - typos are invisible (SEC-519);
    - the features are hand-written regex readers that were wrong four times.

## Decision gate: B

Option A required useful precision on implementation defects without
prescribing known-bad cleanups. The precision is **0 of 67** at HEAD and **0
of 54** retrospectively. The signal also endorses the one family-wide defect it
was meant to find, and it prescribes the RSA-key mistake as soon as family
boundaries blur. So:

- **Not exposed** through `nox rule-review`. No new signal, score, gate or
  report field.
- **The tooling stays here** (`features.py`, `mine.py`, the reflection dump)
  for exploratory reading, where it did lead a person to the no-credential-body
  inventory and to SEC-519.

> Majority structure can tell a maintainer where somebody once copied a
> pattern. It cannot tell them where to look for a defect, because in this
> catalogue the largest defect *was* the copied pattern.

## Reproducing

```bash
# HEAD: copy the template into core/catalog as a _test.go, with package catalog
# and Rules(); for v1.35.0, into core/analyzers/secrets (or ai) with
# NewAnalyzer().Rules().Rules(). Then:
NOX_RULE_DUMP_REFLECT=head-all.json go test ./core/catalog -run TestDumpRulesReflect
python3 features.py head-all.json head-feat.json
python3 mine.py head-feat.json vendor head-vendor-inv.json
```
