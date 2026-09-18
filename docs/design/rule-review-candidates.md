# Rule review candidates

`nox rule-review` points a maintainer at rule propositions worth re-reading. It
does not score, rank, suppress, retire or change anything, and that restraint
is the design.

## The result to read first: precision, not coverage

**None of the three signals would have discovered why AI-029 and AI-041 were
withdrawn.** Both were retired because their condition is not a security
condition — "different from the vendor's default or recommendation" is not a
security proposition — and nothing here detects that. A human reading the
proposition caught both.

What the contradiction signal does catch is a different, narrower defect that
AI-029 happened to also have: its remediation recommended the value its trigger
flagged. That is a true positive, and it is measured at 1 true positive and 0
false positives across the 1,498-rule catalogue as it stood before the
withdrawal. AI-041 has no such defect and is correctly silent.

So what has been demonstrated is **precision, not coverage**. One signal is
trustworthy about one narrow property. Nothing here knows what a bad rule is,
and the gap between "this rule contradicts itself" and "this rule should not
exist" is the entire distance a maintainer still has to walk.

That fixes the shape of this tool, and the boundary is worth stating as a rule:

> `rule-review` reports narrow properties it can measure reliably. It does not
> estimate whether a rule is good or bad.

So it accumulates **independently validated maintainer-review signals** — each
one narrow, each one measured on its own before it is trusted — rather than
combining them into a general "bad rule" score. A combined number would imply a coverage claim that no measurement
supports, and would let a rule with three weak smells outrank a rule with one
decisive one. The sections stay separate for that reason, and a signal is
promoted to a gate only on its own evidence (see *Promotion*, below).

## Why the restraint is the design

Twice in one audit of this catalogue, a cleanup that was obviously right on
inspection measured wrong on the corpus:

- Requiring entropy context for the private-key rules would have dropped a real
  RSA private exponent.
- Merging the 29 vendor rule pairs that read as duplicates would have deleted
  credential spellings only one member of each pair covered.

Neither was overturned by any signal below. Both were overturned by running the
change against real repositories. A tool that had ranked those two as "remove
me" would have been confidently wrong, and the cost of acting on it is not
symmetric: `nox calibrate` prescribes severity overrides, which are reversible
config in one project, whereas retiring a rule reaches every baseline, VEX
statement and `nox:ignore` comment that named it — which is why a withdrawal
needs a tombstone that outlives the release (`core/rules/withdrawn.go`).

So this command answers *which propositions deserve a human read*, and the
human answers everything after that.

## The three signals

They are reported in separate sections and never combined. A rule listed under
all three is a rule to inspect, not a rule that is three times as bad; a
combined number would be a ranking, and there is no evidence the three are
commensurable.

Two are **ingested** rather than recomputed, because nox already measures them
and a second implementation would be a second answer.

| Signal | Source | Says |
|---|---|---|
| `single_construct` | `scripts/metamorphic/sweep.py` triage | the invariance check only ever exercised this rule in one place |
| prevalence collapse | `nox bench --json` `rule_prevalence` | raw findings exceed authored occurrences |
| remediation contradicts trigger | computed here, from the built-in catalogue | the remediation endorses the value the trigger requires |

The sweep's other signal, `flips_under_edit`, is deliberately **not** carried:
it is a confirmed rule bug with a minimal reproduction attached and the sweep
already fails on a new one. Re-listing it here would demote a red gate into a
suggestion.

## Remediation contradicts trigger

The only newly computed signal. AI-029 is why it exists — it flagged
`presence_penalty = 0` as "repetition penalties disabled" while its own
remediation read:

> Set presence_penalty (-2 to 0) and frequency_penalty (-2 to 0) to reduce
> repetitive token generation.

The recommended range **contains** the flagged value, so following the advice
to the letter can leave the finding in place. It fired 446 times on the pinned
corpus before anyone read the two strings next to each other.

### The definition that was measured and rejected

The obvious wider definition is "the rule's own pattern matches its own
remediation text". It was implemented first and measured on the catalogue: **35
rules**, of which essentially all were correct remediations quoting the defect
in order to say remove it —

    IAC-202  Replace failed_when: false with specific failure conditions.
    IAC-203  Enable certificate validation by removing validate_certs: false.

— and it did **not** report AI-029, whose pattern requires an `=` between
parameter and value and whose prose has none. Wrong on both ends. It is kept as
a negative fixture in `TestSelfMatchIsNotTheSignal` so it is not proposed again.

### What ships

Only the narrow checkable form: the pattern pins a **named parameter** to a
**literal value**, and the remediation, discussing that same parameter,
endorses a numeric **range** containing it. A rejecting verb ("avoid",
"remove", "replace", "never") in the clause before the range suppresses it,
which is what keeps the 35 quoted-defect remediations out.

Non-numeric pins (`false`, `LoadBalancer`) are not analysed: a literal has no
range to fall inside, and endorsement of a literal measured as the same
false-positive flood as self-matching, for the same reason.

## Measurements

Catalogue-wide, 2026-09-18:

| Catalogue | Rules | Pinned literal assignment | Contradictions |
|---|---|---|---|
| `main` (post-withdrawal) | 1,496 | 188 | **0** |
| `9c5aea8^` (pre-withdrawal) | 1,498 | 189 | **1 — AI-029** |

The pre-withdrawal run is the retrospective acceptance test, and it was run
against the real catalogue at that commit rather than a hand-copied fixture. It
reports AI-029 and nothing else: one true positive, zero false positives across
1,498 rules.

**AI-041 is not surfaced by this signal, and that is correct.** It was withdrawn
in the same release for the same underlying reason — "different from the
vendor's recommendation" is not a security proposition — but its remediation
does not contradict its trigger: it flags temperature above 0.9 and recommends
0.1–0.3, which is consistent advice. Loosening the signal until it also reported
AI-041 would mean tuning it against the answer we already knew, which is how a
signal becomes a mirror. `TestTheOtherWithdrawnRuleIsNotSurfacedHere` asserts the
silence.

**AI-041 is not surfaced by the prevalence signal either** — measured on
`docs/benchmarks/2026-09-15`, it has 35 findings across 35 authored occurrences,
a copy factor of exactly 1.0.

This is the honest limit of the current milestone: **none of the three signals
detects the failure mode that actually motivated both withdrawals**, which is a
rule whose condition is not a security condition. Both rules were caught by a
human reading the proposition. AI-029 happens to also be catchable
mechanically; AI-041 is not, by anything here.

### Prevalence collapse, labelled

19 of the 115 rules with prevalence data collapse at all. There is no threshold,
on purpose — a threshold is a judgement about how much multiplication is too
much. Labelled by hand against the per-project counts:

| Label | Rules | Basis |
|---|---|---|
| Informative — high factor concentrated in one repository | AI-022, AI-029, AI-031, DATA-001, SEC-162, SEC-801, SEC-803 | e.g. AI-031 is 244→4 on crewAI alone: one documentation page in many locale and version copies |
| Dismissible at a glance — factor under 1.05 | AI-036, SEC-082, SEC-161 | SEC-161 is 673→667: six duplicated lines out of 673 |
| Uninformative — counts too small to read | AI-039, SEC-455, SEC-509, SEC-590, SEC-629, SEC-652 | 2→1, 3→1, 4→2 |
| Moderate, spread across repositories | SEC-048, SEC-055, VULN-002 | llama_index-driven, factors 1.6–2.1 |

So 7 of 19 rows carried information and the rest were dismissible from the
factor column without opening anything.

### The cutoff that shipped

`nox rule-review` shows rows at a copy factor of **2 or above** by default;
`--all` shows every measured row. The number lives in one named constant,
`defaultCollapseFactor`, and is applied AFTER the measurement — the factor is
canonical, every collapsing rule is still computed and counted, and the report
states how many rows it withheld so a filtered list never reads as a short one.
`TestTheCutoffIsPresentationNotMeasurement` asserts that filtering never happens
inside `collapseCandidates`, so moving the number can only change what is shown
first.

A row must clear **two** bars: a copy factor of 2 and at least 3 duplicated
lines. They are complementary rather than redundant, and each exists for a case
the other lets through:

| withheld by | example | why the other bar misses it |
|---|---|---|
| the copies bar | SEC-509, `2 -> 1` | factor is exactly 2.000 — from one duplicated line |
| the factor bar | SEC-161, `673 -> 667` | six duplicated lines, comfortably over the copies bar |

### Why 3, and why 8 rows rather than 7

The copies floor was swept rather than picked. Of the 11 rules at factor >= 2 on
`docs/benchmarks/2026-09-15`:

- **every** copies floor from 3 to 36 selects the same 8 rows
- **every** findings floor from 5 to 53 selects those same 8 rows

Two differently motivated bars, each with a plateau spanning an order of
magnitude, agreeing exactly. A parameter that insensitive is not tuned, which is
what makes it defensible from a single corpus — and one corpus is all there is,
since `docs/benchmarks/2026-09-15` is the only bench report carrying prevalence
data.

Copies rather than findings, because copies **are** the quantity the signal is
about: the floor lands on the measurement instead of a proxy for it, and "one
duplicated line is not evidence of copy multiplication" needs no corpus to
justify.

The eight are AI-022, AI-029, AI-031, DATA-001, SEC-048, SEC-162, SEC-801 and
SEC-803 — the 7 labelled informative above, plus SEC-048.

**This was deliberately not tuned to produce 7.** Reaching 7 requires a findings
floor of exactly 54, because SEC-801 has 53: a cliff with no plateau on either
side, which is the shape of a number fitted to a wanted answer rather than read
off the evidence. The "7 informative" label combined a high factor *with*
concentration in one repository, which is a different filter from a magnitude
bar; SEC-048's 82 findings collapsing to 40 is a real 2x on real volume, and
excluding it would mean encoding the repository-concentration judgement as if it
were a magnitude one. 8 is where the evidence separates.

## Promotion: when a signal becomes a gate

One signal has been promoted. **A built-in rule must not prescribe as its remedy
the condition it reports as insecure**, and
`TestNoBuiltinRuleContradictsItsOwnRemediation` fails the build on one that
does.

The promotion is earned on that signal's own evidence, not granted by analogy:

- it is decidable from the rule alone — no corpus, no scan, no judgement about
  how much of anything is too much;
- it measures 1 true positive and 0 false positives across 1,498 rules;
- the invariant is one nobody argues with. An operator who follows a remediation
  to the letter must end up with the finding gone.

**The other two signals are not promoted, and must not be promoted by analogy.**
`single_construct` reports a gap in the CORPUS, not a defect in the rule — the
usual remedy is a second test input. Prevalence collapse reports that a corpus
repeats something a rule correctly detects; a correct rule fires as often as the
thing it detects appears. Failing a build on either would be failing it on a
measurement that is not about the rule being wrong.

### Scope of the gate

Built-in rules only. It deliberately does **not** run inside `CheckCoherence`,
which refuses a rule at load time. An operator's own custom rule with loose
remediation wording would then fail to load and take their scan down with it,
and a wording smell must never be able to stop somebody's scanner. The gate
belongs to this repository's catalogue, where the cost of a failure is a red
build and the fix is an edit to a string.

The gate carries its own teeth check. A test asserting "zero" over a catalogue
that contains zero is indistinguishable from a test whose detector has broken,
so `TestTheGateWouldHaveCaughtAI029` feeds the withdrawn rule's verbatim
definition through the same path and requires it to fail, and the gate itself
asserts a floor on how many rules it actually analysed.

## Deliberately not built

- **No ranking or scoring.** `TestTheReportRanksNothing` asserts the JSON schema
  has no score, rank, severity, priority, risk, verdict or action field, because
  prose promising restraint is not a constraint.
- **No automatic retirement.** See the two overturned cleanups above.
- **No repository-concentration bar.** The sharpest thing separating the rows
  that carried information was that the collapse came from ONE repository —
  AI-031 is 244->4 on crewAI alone. It is deliberately not surfaced, and the
  reason is worth stating precisely, because it is the boundary this whole
  command sits on.

  **Concentration is not purely a rule property.** `244 -> 4 on crewAI` is
  equally consistent with a rule overfitted to one repository and with crewAI
  legitimately containing that condition 244 times. Worse, the resulting number
  depends on which repositories were put in the benchmark at all, so it is
  partly a measurement of the CORPUS DESIGN rather than something intrinsic to
  the rule. The other two ingested signals do not have that problem in the same
  way: a copy factor is a ratio within whatever was scanned, and
  `single_construct` is explicitly a statement about corpus coverage.

  Before this could be surfaced, three things need settling — and they are a
  benchmark investigation, not a presentation change:

  1. **The sampling unit.** Repo, project family, authored source, released
     version, generated or documentation material — these give different
     answers, and crewAI's locale-and-version doc tree is exactly the case that
     makes them diverge.
  2. **The corpus independence model.** nox has already answered this class of
     question once and must not answer it twice differently: the evidence spine
     counts independence in *distinct reporters, not observations* — 100
     self-scans are one source (`IndependentSources()`, see `docs/roadmap.md`).
     Any concentration measure should start from that model rather than invent
     a parallel notion of independence.
  3. **Whether it predicts anything.** Concentration has to be shown to predict
     review-worthy rules before it is shown to maintainers as though it does.

  Only then is it a question of whether it belongs here.

## Running it

```bash
nox bench --json --output bench.json
python3 scripts/metamorphic/sweep.py --bin ./nox --results sweep-out
nox rule-review --bench bench.json --sweep sweep-out/triage_report.json
nox rule-review --bench bench.json --all      # every measured collapse row
```

Every source is optional. A signal whose source is absent reports `Not measured`
rather than an empty list, so "nothing found" and "never asked" stay apart —
the same distinction `renderPrevalence` draws for tier 3.
