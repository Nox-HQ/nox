# Lifting dedup to the scanner

The invariant: **one observed security condition should not become several
findings because nox has several detection paths to it.**

It is implemented today in `core/analyzers/secrets/dedup.go`, for one analyzer,
and it works: a GitHub or Stripe token trips five to eight overlapping rules and
this is what took the precision corpus from 8.00 findings per issue to 1.00.
Collapses are recorded as *Withheld* claims rather than refutations, because the
dropped finding was true — an entropy rule that matched a real token did match a
real token; it is dropped because reporting one secret five times is noise.

This note records why lifting it to the scanner is not a move, and what it
needs first.

## What the existing facility keys on

Two signals, in order:

1. **Owner resolution** — if the matched token starts with a recognised provider
   prefix (`ghp_`, `xoxb-`, `sk_live_`, `AKIA`, …), keep that provider's
   canonical rule(s) and drop other providers' findings on the span.
2. **Specificity collapse** — a generic entropy or shape-gated finding that
   overlaps a surviving provider finding is dropped.

Signal 2 generalises: `classifyRuleSpecificity` reads `MatcherType == "entropy"`
and `Metadata["secret_shape"]`, both of which are ordinary rule properties.
Signal 1 does not: it is a table of provider prefixes, and it is the reason a
`sk_live_` collision resolves while a bare UUID does not.

## Why a scanner-level span collapse would be wrong

The obvious lift — run the same collapse over the merged finding set — destroys
correct output. `core/cross_analyzer_dedup_test.go` currently allows **16**
same-span pairs, 8 crossing analyzer families and 8 within one, and every one of
them is two different fixes that happen to share a line:

| pair | two fixes |
|---|---|
| CONT-001 \| IAC-121 | pin the base image · add a HEALTHCHECK |
| IAC-200 \| IAC-225 | set `no_log` on the task · stop hardcoding the password |
| IAC-131 \| IAC-137 | add a NetworkPolicy · set a missing hardening property |
| SEC-161 \| SEC-162 | rotate the high-entropy value · decode the blob and find out whether it holds one |

A Dockerfile's `FROM` line is the anchor for every absence rule about the file,
because an absence has no line of its own. Collapsing on span would report one
of three missing Dockerfile directives and silently drop the other two.

So **span is not a condition**, and the finding set carries nothing else that
distinguishes these cases. That is the blocker, and it is a missing capability
rather than a missing implementation.

## What it needs

A rule must be able to declare the condition it reports, so two rules can be
compared on what they claim rather than on where they landed. Candidate shapes,
in increasing cost:

1. **A `condition` key on the rule** — an opaque string such as
   `container.base-image.unpinned` or `secret.credential.exposed`, with
   equality meaning "same condition". Cheap, and it makes the claim reviewable
   in the rule definition where a reader can argue with it.
2. **Derived from CWE + subject** — no new field, but CWE is far coarser than a
   condition: IAC-121, IAC-122 and IAC-124 would collide.
3. **A relation in the reasoning store** — dedup already emits "these two
   candidates are one secret" as a relation. Generalising that vocabulary is
   the most expressive option and the largest.

Option 1 is the one that fits how the rest of the rule set is written, and it
has a natural migration: the 16 allowlisted pairs above are exactly the set that
must end up with *different* conditions, and the duplicates already merged in
`identical-pattern-audit.md` are exactly the set that must end up with the same
one. Both halves are already enumerated and measured, so the declaration can be
checked rather than trusted.

## Sequencing

Nothing in the corpus currently needs this. The duplicates it would have caught
were found by grouping the rule set by pattern and fixed by merging and binding:
one condition, one rule, so there is no second finding to collapse. The
generalised invariant test holds the line meanwhile — it asks the question of
every pair and fails on any unexplained overlap.

So this is worth building when a case arrives that the merges cannot fix —
two rules that genuinely must both exist and genuinely report one condition —
rather than now, against no measured delta. Building it now would mean shipping
a collapse whose only measurable effect on the current corpus is the risk of
removing one of those 16 correct findings.

## A second consumer has since appeared, and it needs more than this

Bench reporting now separates raw findings from authored occurrences, and
declares a third tier — *distinct security conditions* — as `not measured`. See
`renderPrevalence` in cli/bench_cmd.go. That tier is this document's `condition`
by another name, so the sequencing argument above has a new input: something
does now want it, for reporting rather than for collapsing.

It wants **more** than Option 1, though, and the gap is worth stating before
anyone reads "a second consumer" as "build Option 1 now".

A `condition` key answers *which rules report the same thing*. Tier 3 asks how
many distinct conditions a rule found, which is a question about SUBJECTS — the
things a finding is about. Within one rule the condition key is constant, so it
counts one every time and answers nothing. The motivating case is AI-029, where

    frequency_penalty=0.0,
    presence_penalty=0.0,

on consecutive lines of one documentation sample are two authored occurrences
and one decision. Same rule, same condition, and what distinguishes them from
two genuinely separate configurations is the construct they sit in.

Nothing carries that today. Checked, in the order a reader would try them:

| candidate | why it does not serve |
|---|---|
| Fingerprint (v2) | hashes rule ID, normalised path and the MATCHED CONTENT. The two lines are two strings, so they cannot collapse without making the fingerprint not a function of what matched — the property baselines and waivers rest on |
| `structural_claim` | IaC-only, and measured on geerlingguy/ansible-for-devops it collapses nothing: 17 of 245 findings carry one (7%), and where present the subject count EQUALS the finding count (IAC-139: 6 and 6) |
| `core/lexctx` | classifies regions as code, comment, string or data blob across 21 languages; no named constructs |
| `core/lexctx/ident.go` | byte predicates for identifier characters |

So tier 3 is **condition × subject**, this document specifies the first half,
and the second half is unspecified and unbacked by anything in the tree.

### The subject cannot be derived from the finding

The tempting shortcut is to compute a subject from where the finding landed.
Measured on geerlingguy/ansible-for-devops, 245 findings:

| candidate subject | subjects | collapse |
|---|---|---|
| `(rule, file)` | 125 | 49% |
| `(rule, file, line)` — today | 245 | 0% |
| `(rule, file, blank-line block)` | 144 | 41% |
| `(rule, file, bound key)` | 129 | 47% |

The collapse rates are close enough to be useless as a guide, which is the
first lesson: a subject is not the definition that collapses most, it is the
one that is right. Two cases from the same corpus settle it, and they point in
opposite directions.

**AI-029 wants the construct.** Two consecutive lines of one documentation
sample, `frequency_penalty=0.0` and `presence_penalty=0.0`, are one decision.
The values differ, so a value-keyed subject counts two. Correct answer: 1.

**IAC-211 wants the value.** One `requirements.yml` block holds three unpinned
Galaxy roles — `geerlingguy.apache`, `geerlingguy.firewall`,
`geerlingguy.haproxy` — each needing its own version pin. They share a
construct, so a construct-keyed subject counts one. Correct answer: 3. (26
blocks in that repo hold more than one finding of the same rule, so this is the
common shape, not a corner.)

No location-derived definition satisfies both. The construct rule merges three
real pins into one; the value rule splits one decision into two.

### So it is declared, like the condition

The subject has to come from the rule, because only the rule knows what its
finding is *about*: for IAC-211 that is the role reference it matched, for
AI-029 it would have been the configuration call containing it. The shape that
fits alongside Option 1 is a second declaration — `subject: value` or
`subject: construct` — read by whatever computes tier 3, with the same property
that makes Option 1 attractive: it is arguable in the rule definition, where a
reviewer can disagree with it, rather than inferred by a heuristic nobody can
see.

Verification has the same shape as Option 1's, and the fixtures already exist:
IAC-211 on `requirements.yml` must report 3, and any rule matching the AI-029
pattern must report 1. Both are measurable the day the declaration lands.

### Built, for the half that is settled

The subject half is now implemented, because measurement settled its shape and
the verification fixtures existed. `rules.SubjectKindKey` is the declaration;
`rules.SubjectIDKey` is what the engine computes from it; bench counts distinct
`(path, subject)` per rule and prints `not declared` — never `0` — for a rule
that has not said. IAC-211 declares `value` and is the worked case.

One error worth recording, caught by measuring rather than by review: the first
version keyed the subject on the matched text alone, and IAC-211's 65 findings
collapsed to 26. `- name: geerlingguy.apache` is unpinned in several
requirements.yml files at once and each is its own pin, so a subject is
FILE-LOCAL and anything counting them keys on `(path, subject)`.

Note what the worked case does NOT show: IAC-211's tier 3 equals its tier 1, 65
and 65. That is the correct answer — 65 pins to add — and not a failure to
collapse. Tier 3 only diverges from tier 1 where a rule's subject is a
construct, and no shipped rule declares `construct` yet; the one that motivated
it, AI-029, was retired for having no security proposition. So the mechanism is
live and honest, and currently has nothing to prove on the corpus.

The `condition` half of Option 1 remains unbuilt, and its sequencing argument
above still holds: nothing needs it yet.

## Something needs it now (2026-09-26)

The sentence above — "nothing needs it yet" — no longer holds. The case did not
arrive from a new measurement; it was already in the tree, in the allowlist the
invariant test consults, and it is visible by reading that list against its own
stated bar.

The bar, from the comment above `allowedCrossAnalyzerOverlap`: *"Each needs a
reason, and the reason has to name both fixes."* Every entry clears it but one:

```go
"IAC-225|SEC-080": "the IaC and secrets views of one hardcoded password",
```

That names two *views*, not two fixes. The two rules' remediations differ in
wording — IAC-225 points at a vault, SEC-080 at environment variables or a
secrets manager — but those are two mechanisms for one goal, and doing either
resolves both findings. Compare the entry a few lines above, which clears the bar
because its two remediations lead somewhere genuinely different:

```go
"SEC-161|SEC-162": "one value reported as a high-entropy assignment and as a
    base64 blob: two readings of the same bytes, kept apart because the
    remediation differs — rotate the secret, vs. decode the blob and find out
    whether it holds one",
```

Two readings, two destinations, two findings. One reader rotates a credential;
the other decodes a blob to find out whether it holds one. IAC-225 and SEC-080
send the reader to the same place.

That is the gap stated precisely, and it is a gap in the *vocabulary* rather than
in any rule: **the invariant test can say a pair is wrong, the allowlist can say
a pair is fine, and neither can say a pair should be merged.** An entry is
currently the only way to stop the test failing, so "these are one condition" has
to be written down as "these are legitimately different".

### Why this one cannot be fixed by merging

Every duplicate found so far was fixed by merging and binding: one condition, one
rule, no second finding to collapse. This one cannot be, because both rules must
keep existing. IAC-225's subject is a YAML mapping key whose name ends in
`password`; SEC-080's is a generic password assignment in any file. Each is
reachable on inputs the other never sees, and deleting either loses real
coverage. The overlap is only on the inputs both reach.

So it is exactly the shape the sequencing argument asked for: two rules that
genuinely must both exist and genuinely report one condition.

### What it adds to the migration set

The set named earlier gains a third member, and it is the one that makes a
`condition` key do work the allowlist cannot:

- the allowlisted pairs that must end up with **different** conditions,
- the merged duplicates that must end up with the **same** condition,
- and IAC-225/SEC-080, which must end up with the same condition **while both
  rules continue to exist**.

### Not fixed here

Which rule should own the condition is a judgement about which finding a reader
should receive — the IaC view carries the resource and the task, the secrets view
carries the credential shape — and suppressing either is a behavioural delta
owing its own measurement and its own ledger entry. SEC-080 fired on 75 sites
across 3 repositories on the pinned corpus, so this is not a rounding error.
Shipping it as a rider on an unrelated change would be the thing this document
exists to argue against.
