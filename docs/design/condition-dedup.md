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
