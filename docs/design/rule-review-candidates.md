# Rule review candidates

`nox rule-review` points a maintainer at rule propositions worth re-reading. It
does not score, rank, suppress, retire or change anything, and that restraint
is the design.

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
factor column without opening anything. **If** a cutoff is later wanted, factor
≥ 2 would keep 11 rows including all 7 informative ones — but that decision is
deliberately not taken here.

## Deliberately not built

- **No CI gate.** The contradiction signal measures 0 false positives across
  1,498 rules, which is the precision data needed to *consider* one. Whether
  nox should fail its own build on a rule smell is a product decision about what
  nox nags its maintainers about, and it is not this milestone's to make.
- **No ranking or scoring.** `TestTheReportRanksNothing` asserts the JSON schema
  has no score, rank, severity, priority, risk, verdict or action field, because
  prose promising restraint is not a constraint.
- **No automatic retirement.** See the two overturned cleanups above.

## Running it

```bash
nox bench --json --output bench.json
python3 scripts/metamorphic/sweep.py --bin ./nox --results sweep-out
nox rule-review --bench bench.json --sweep sweep-out/triage_report.json
```

Every source is optional. A signal whose source is absent reports `Not measured`
rather than an empty list, so "nothing found" and "never asked" stay apart —
the same distinction `renderPrevalence` draws for tier 3.
