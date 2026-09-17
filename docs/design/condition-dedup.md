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

Until then the column stays printed as `not measured` rather than filled with
something that looks like an answer.
