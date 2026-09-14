# Secret-rule inventory

Workstreams 1 and 2 of *Secret Detection Precision & Rule-Family Redesign*.

This answers one question for each of the 907 SEC rules: **why does this rule
believe the matched value is a secret?** It is an inventory, not a fix. Nothing
in it changes a rule.

It also corrects a measurement error large enough to have inverted the
conclusion, described under *How this was nearly got wrong* — read that before
quoting any number here.

## Classification

The class states the evidence a rule requires before it will fire. It is derived
from the **built** rule set, not from rule source text.

- **A — pattern-discriminative (674 rules).** The matched text is
  self-identifying: a vendor-issued prefix (`ghp_`, `sk-ant-`, `AKIA`), a
  structural URL or ARN, or a vendor key name bound by an assignment. A match is
  evidence on its own.
- **B — contextual (23 rules).** High entropy over declared candidate kinds at a
  stated bit floor, reported only where a nearby line names a secret. The
  threshold is a floor; the context is the evidence.
- **C — bare token + proximity keyword (155 rules).** A generic character run
  (`[a-zA-Z0-9]{32}` and similar) carrying nothing of the vendor's own
  credential format, gated by `RequireContextKeywords`: the vendor word must
  appear within 4 lines **and** 512 characters of the match.
- **D — bare token + file-level keyword only (55 rules).** The same generic run,
  gated only by `Keywords`, which asks whether the word appears *anywhere in the
  file*. One incidental occurrence licenses every token in the file.

There is no class with no gate at all.

## How this was nearly got wrong

The first version of this inventory reported that 214 rules gated only at file
level and produced 79.6% of all findings. Both halves were wrong, and the
errors compounded:

0. **The rule dump omitted `Metadata`.** A rule's entropy thresholds, its
   declared candidate kinds and its per-kind context requirements all live
   there. Without it SEC-161 — an entropy rule running at 5.0 bits over
   assignment/quoted/hex candidates, with the hex kind requiring context at 3.5
   — was filed as a bare token behind a file-level keyword, and named in this
   document as the weakest rule in the set and the place to start retiring. It
   is class B. The 57 rules it was to lead are class D, and they produce **9
   findings between them**.

1. **The rule dump omitted `RequireContextKeywords`.** Classifying without it,
   every proximity-gated rule looked file-gated. In fact **156 of those rules,
   including all 20 highest-firing ones, already carried the proximity gate.**
   The genuinely file-gated set is 60 rules, and on the engine those numbers
   came from they account for 3,713 findings, not five million.
2. **The fire rates came from a four-month-old benchmark.**
   `docs/benchmarks/2026-Q2/bench.json` was produced 2026-05-02. The fix for the
   exact defect those numbers exhibit — `eb46c32`, *"secrets: proximity is
   measured in characters, not lines"* — landed **2026-09-12**. The draft
   described, as a pending opportunity, work that had already shipped.
3. **A 21-40x performance regression, which does not exist.** Comparing
   2026-Q2's durations against fresh scans, I reported the engine had become
   dramatically slower. Running both binaries over one tree put it at 1.26x.
   The corpus had grown; I had attributed that to the engine.

The second mistake was caused by the first: having concluded the proximity
control was absent, I never asked whether it had since been added. A wrong
reading of the input made the stale input look consistent. The third repeated
the same error one layer out — comparing two numbers whose inputs differed and
attributing the whole difference to the one variable I was looking at.

A fourth claim, that the benchmark corpus was never pinned, was also wrong:
`curatedAutoCorpus` pins every entry to a tag, and `cli/bench_corpus_test.go`
has a test enforcing it. What was missing was narrower — the *report* recorded
no resolved commit and no engine version, which is why its numbers could be
read four months later as though they were current.

All of them are the same failure in different clothes — reasoning about a system
from a description of it rather than from the system, and comparing numbers
without checking that their inputs match. Three separate wrong conclusions came
from a dump missing one field each time. A partial dump does not produce a
partial answer; it produces a confident wrong one, and each time the wrongness
pointed at a different rule to retire.

`TestDumpRuleSet` now dumps every field that can change what a rule matches, and
the governing rule for this work is that no rule is retired or redesigned from a
lossy inventory. Establish the proposition the rule encodes, compare it against
the vendor's real credential format and against real-repo behaviour, and only
then decide. The dump test now committed at
`core/analyzers/secrets/dump_rules_test.go` exists so the rule set is read from
the engine that runs it, and `nox bench` now records `nox_version` per report
and `repo` / `ref` / `commit` per project, so a fire-rate number carries the
engine and the tree it came from.

## The defect that produced the old numbers

The largest single contributor in the May run was SEC-616 at 1,002,602 findings.
In `vercel/ai`:

```
packages/google/src/interactions/__fixtures__/image-output.json
  5.9 MB, 45 lines, 99,731 distinct 32-character alphanumeric runs
```

One base64 image payload. The literal `fcm` occurs by coincidence inside the
payload. SEC-616's proximity gate was measured in **lines**, and on a 45-line
5.9 MB file every token is "near" everything — so one accidental substring
licensed a million findings.

The rule was never the problem. The proximity abstraction was, and bounding it
in characters (512) fixed the whole family at once rather than rule by rule.
This is standing principle 14.3 having already been applied.

## Measurement

### How it is measured now

Two engines, one tree. The May-era binary (`8138ee2`, the last commit before the
2026-Q2 report) and the current binary are each run over the same pinned
checkout, so the only variable is the engine.

This replaces the comparison the first draft made — 2026-Q2's recorded counts
against a fresh scan — which was not a comparison at all. That run pinned no
commit, and the repositories have grown substantially since; the same repository
is simply a bigger tree now.

| repo | time May → now | findings May → now | SEC May → now | SEC change |
|---|---|---|---|---:|
| anthropic-sdk-python | 39s → 48s (1.23×) | 7,156 → 128 | 6,874 → 103 | **-98.5%** |
| agent-go | 11s → 18s (1.64×) | 211 → 35 | 150 → 7 | **-95.3%** |
| mcp python-sdk | 32s → 39s (1.22×) | 1,601 → 103 | 1,331 → 21 | **-98.4%** |
| openai-python | 65s → 97s (1.49×) | 17,056 → 370 | 10,817 → 33 | **-99.7%** |
| vercel/ai | 723s → 891s (1.23×) | 3,124,502 → 3,298 | 3,106,047 → 2,068 | **-99.93%** |
| **total** | **870s → 1,093s (1.26×)** | **3,150,526 → 3,934** | **3,125,219 → 2,232** | **-99.93%** |

The precision change is the point: **-99.93% SEC findings on identical input**,
and it is attributable to the engine because nothing else moved.

vercel/ai is the clearest single case, because it is where the base64 fixture
described above lives: 3,106,047 SEC findings from the May engine, 2,068 from
the current one, on the same 3.1-million-finding tree.

### Scan cost

The same A/B settles a claim I made and had wrong. Comparing 2026-Q2's recorded
durations against fresh scans suggested a 21-40x slowdown. On identical input it
is **1.26x** — 870s to 1,093s across these five repositories. The apparent
regression was almost entirely the corpus having grown between the two dates.

A 1.26x cost for a 99.9% reduction in output is a trade worth making, but it is
not free, and the profile says where it goes. Measured on
anthropic-sdk-python, 54% of scan CPU is `rules.Engine.ScanFile`, nearly all of
it inside `regexp`:

| | share of CPU |
|---|---:|
| ai analyzer | 44.5% |
| secrets analyzer | 26.2% |
| keyword pre-filter (`containsAnyKeyword`) | 10.0% |

The pre-filter share was partly waste — it rebuilt `[]byte(strings.ToLower(kw))`
for every rule on every file, roughly 1,100 times per file for the secret rules
alone, lowering constants that never change. `RuleSet.Add` now does it once
(10.0% -> 9.1%; the remainder is the substring search itself, which is real
work).

The larger structural cost is untouched and worth stating plainly: a class-C
rule whose keyword appears anywhere in a file runs a bare
`[a-zA-Z0-9]{32}` regex across the whole file, collects every token, and then
discards nearly all of them by proximity. Searching only within
`RequireContextKeywords` windows would be equivalent and much cheaper. That is a
real optimisation, not attempted here.

### Current fire rates

Seven repositories, current engine, pinned clones, recorded in
`docs/benchmarks/2026-09-13/bench.json`: **9,143 findings**, against 6,406,443
in the 2026-Q2 report.

Per class, and this is what the inventory is for:

| class | rules | findings | share of all |
|---|---:|---:|---:|
| A pattern-discriminative | 674 | 826 | 9.03% |
| B contextual | 23 | 689 | 7.54% |
| C bare token + proximity | 155 | **2,349** | **25.69%** |
| D bare token + file-level only | 55 | 9 | 0.10% |

**Class C is the whole problem, and class D is not a problem at all.** 55 rules
produce 9 findings between them; 155 produce 2,349.

An earlier revision of this document had those two the other way round, and
named class D as the place to start retiring. That was an artifact of a dump
that omitted `Metadata` — see below.

**Concentration — top 10 rules = 71.56% of all findings.** The composition has
changed completely, and only three of the ten are secret rules:

| rule | class | findings | share | repos |
|---|---|---:|---:|---|
| SLOP-001 | — | 1,293 | 14.14% | 6/7 |
| SEC-569 | C | 1,097 | 12.00% | 1/7 |
| DATA-001 | — | 979 | 10.71% | 7/7 |
| SEC-161 | **D** | 578 | 6.32% | 7/7 |
| DATA-003 | — | 565 | 6.18% | 5/7 |
| AI-029 | — | 452 | 4.94% | 2/7 |
| SEC-533 | C | 448 | 4.90% | 3/7 |
| AI-041 | — | 421 | 4.60% | 3/7 |
| SEC-082 | A | 380 | 4.16% | 4/7 |
| AI-036 | — | 330 | 3.61% | 5/7 |

Concentration is still high, but it is no longer a secrets story. Slopsquatting,
PII and AI rules hold six of the top ten. Whether those are correct at that
volume is a question for their own families, and this inventory does not answer
it.


## The format-mismatch class

A vendor-named rule that encodes nothing of the vendor's credential format is
not a vendor rule. It is a generic token matcher wearing a vendor's name, and
the name is what makes its findings look credible.

SEC-661, "Detected PostHog API Key", is the worked example. Its pattern is
`\b[a-zA-Z0-9]{32}\b` with the keyword `posthog`. Run against a file holding
both real PostHog key formats and one unrelated token:

| line | content | reported by |
|---|---|---|
| `POSTHOG_PROJECT_KEY = "phc_PHQDA5Kwzti…"` | real project key | SEC-161 only |
| `POSTHOG_PERSONAL_KEY = "phx_kL9mR3pZ…"` | real personal key | SEC-161, SEC-162 |
| `unrelated = "abcdefghijklmnopqrstuvwxyz012345"` | not a PostHog key | **SEC-661** |

The rule misses both real formats and fires on the string that is not a
credential at all.

PostHog's key types, from their documentation:

| prefix | type | status |
|---|---|---|
| `phc_` | project API key | **public** — write-only, safe in client-side code |
| `phx_` | personal API key | secret; GitHub secret scanning auto-rolls it |
| `phs_` | project secret key (beta) | secret |
| `pha_` / `phr_` | OAuth access / refresh | secret |

So SEC-661 is inverted twice over: the format it should report (`phx_`, `phs_`)
it cannot match, and the one value of that family it might plausibly meet in the
wild (`phc_`) should not be reported at all.

This also settles SEC-161's verdict. Its single candidate true positive across
578 findings was a `phc_` key in crewAI's recorded cassettes — a public key by
design. **SEC-161 has zero true positives on this corpus.** It is not retired:
it is class B, it carries real constraints, and the argument for retiring a rule
cannot be "it found nothing on seven repositories" alone.

### How widespread it is

The cross-reference asked a narrower question than expected and got a worse
answer. Searching the whole rule set for prefix literals nox encodes *anywhere*,
and matching them to the vendors of bare-token rules:

**All 155 remaining class-C rules encode nothing of their vendor's credential
format.** SEC-661 was the 156th until it was redesigned below; it is now class A.
Only two vendors in the entire catalogue have a prefix encoded at all — mailgun
(`key-`, `pubkey-`) and sendinblue (`xkeys-`).

Ranked by real-repo fire count, with what they actually match:

| rule | vendor keyword | findings | what it matches |
|---|---|---:|---|
| SEC-569 | `gemini` | 1,097 | 24-char runs in Google API response fixtures |
| SEC-533 | `ibm` | 448 | base64 and cookies — `ibm` occurs inside `…IBMki` |
| SEC-446 | `cloudflare` | 228 | `__cf_bm` bot-management cookies |
| SEC-629 | `lob` | 211 | embedding vectors |
| SEC-616 | `fcm` | 170 | base64 payload |

SEC-533 is the shape at its clearest: a three-letter vendor keyword satisfied by
a random substring of base64, licensing every 44-character run nearby.

Two properties make this class distinct from ordinary imprecision. The keyword
is a *word*, so short ones (`ibm`, `lob`, `fcm`, `wise`, `heap`, `split`) are
satisfied by accident. And the rule's name asserts a vendor the evidence never
establishes, so a reader triaging the finding starts from a false premise.

Redesigning them requires each vendor's real credential format, which is
external knowledge that has to be sourced per vendor — the PostHog answer above
took two documentation lookups. That work is not attempted here.

## Method, and what this inventory cannot tell you

The rule set is dumped from the built engine via
`NOX_RULE_DUMP=<path> go test ./core/analyzers/secrets -run TestDumpRuleSet`,
then classified by `scripts/secret-rule-inventory.py`.

Earlier attempts to extract rules from source with regexes produced wrong
answers twice: they paired one rule's `id:` with another's `pattern:`, and
counted 3 English-word keywords where the built set has 11. The classifier
itself was corrected twice more from sampling — it read `(?-i:` as a literal
prefix, and the colon in `smtp://` as an assignment operator. <!-- nox:ignore SEC-462 -- a URL scheme named in prose, not a credential; SEC-462 is item 5 under "What follows" -->

Limits worth stating:

- **This measures rule shape, not match correctness.** Class D says a rule
  requires weak evidence; it does not prove any individual match is a false
  positive. That is the labelled benchmark in Workstream 7.
- **"Never fired" means "not on these seven repositories."** Dormant rules are
  unexercised, not safe.
- **The 2026-Q2 comparison is not like-for-like.** That run pinned no commit
  SHAs, so the repositories have moved, and analyzers that did not exist in May
  (AI Security, Privacy/PII, Slopsquatting, Taint Flow, CVE Variants) now
  contribute findings. The SEC-only columns are the meaningful comparison, and
  even those carry repository drift.

## Artifacts

- `docs/design/secret-rule-inventory.json` — all 907 rules with class, gate
  kind, keyword, token shape, literals, severity, fire count and repos firing,
  plus the one-sentence explanation required by the exit criterion.
- `scripts/secret-rule-inventory.py` — the classifier.
- `core/analyzers/secrets/dump_rules_test.go` — the rule-set dump.

## What follows

The class-D retirement this document previously proposed is withdrawn. Those 55
rules produce 9 findings; retiring them would be motion, not progress, and the
list that named them was built from an inventory missing the field that decided
the classification.

The work that remains, in order:

1. **Source each vendor's real credential format** for the 156 class-C rules,
   starting with the five above that account for 2,154 of their 2,349 findings.
   This is external research, one vendor at a time, and it is the gate on
   everything after it.
2. ~~Redesign SEC-661 against PostHog's real formats.~~ **Done** — it reports
   `phx_`, `phs_`, `pha_`, `phr_` and not `phc_`, and moved from class C to
   class A. It is the template for the remaining 155.
3. ~~Fix the short-keyword problem structurally.~~ **Done.** A vendor keyword
   was matched as a plain substring, so the only evidence a bare-token rule has
   could be manufactured by coincidence — `iBm` inside a PEM certificate's own
   base64, `fcm` inside a private key's. `contextHasKeyword` now requires the
   keyword to appear as a token, where a boundary is "not a letter or digit":
   `posthog` still matches `posthog_api_key`, and a keyword carrying a
   separator is a structured prefix with no right boundary demanded (`ghp_`,
   `key-`, `sk-ant-api`, which runs into the digits of `sk-ant-api03`).
   `ExcludeContextKeywords` keep substring matching on purpose — a veto that
   fires too readily suppresses, which is the direction that cannot invent
   evidence.

   Measured: vercel/ai 3,289 → 2,915 (−11.4%), SEC-533 alone 245 → 4; crewAI
   3,200 → 3,186. Two release-relative drops on the rule-diff corpus, both
   ledgered, both PEM test assets where the private key is still reported by
   SEC-004 and SEC-299 — a wrong label removed, not coverage. The rises are
   dedup unmasking: all 9 lines where SEC-161 gained are lines a suppressed
   vendor rule vacated, so the same span is now reported as "high-entropy
   string in assignment" instead of "IBM API key", which is what the evidence
   actually supports.
4. **Then** revisit retirement, against rules whose proposition is known.

Fewer findings is not the success criterion. Every drop recorded here is
attributable to a specific commit measured on one tree, and the two claims this
document made that turned out to be wrong are recorded above rather than
removed.
