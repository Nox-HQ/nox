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

- **A — pattern-discriminative (662 rules).** The matched text is
  self-identifying: a vendor-issued prefix (`ghp_`, `sk-ant-`, `AKIA`), a
  structural URL or ARN, or a vendor key name bound by an assignment. A match is
  evidence on its own.
- **B — contextual entropy (29 rules).** High entropy, reported only where a
  nearby line names a secret.
- **C — bare token + proximity keyword (156 rules).** A generic character run
  (`[a-zA-Z0-9]{32}` and similar) with no prefix, gated by
  `RequireContextKeywords`: the vendor word must appear within 4 lines **and**
  512 characters of the match.
- **D — bare token + file-level keyword only (60 rules).** The same generic run,
  gated only by `Keywords`, which asks whether the word appears *anywhere in the
  file*. One incidental occurrence licenses every token in the file.

There is no class with no gate at all.

## How this was nearly got wrong

The first version of this inventory reported that 214 rules gated only at file
level and produced 79.6% of all findings. Both halves were wrong, and the
errors compounded:

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

All four are the same failure in different clothes — reasoning about a system
from a description of it rather than from the system, and comparing numbers
without checking that their inputs match. The dump test now committed at
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

| class | rules | fired | findings | per firing rule |
|---|---:|---:|---:|---:|
| A pattern-discriminative | 662 | 31 | 817 | 26.4 |
| B contextual entropy | 29 | 3 | 24 | 8.0 |
| C bare token + proximity | 156 | 23 | 2,349 | 102.1 |
| D bare token + file-level only | 60 | 3 | 683 | **227.7** |

Class D is now the weakest shape by a clear margin: three rules firing, 683
findings, the highest rate per firing rule in the set. That is the expected
consequence of a file-level gate, and it is the one class the character-bounded
proximity fix could not help, because those rules ask for no proximity at all.

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

The premise of Workstreams 2–5 has changed. The redesign was scoped against a
noise profile that no longer exists, and the top-20 list it was to work through
is gone — those rules now fire in the tens, not the hundred-thousands.

The target list re-derived from current numbers is short and specific:

1. **SEC-161** — class D, 578 findings, fires in **7 of 7** repositories. No
   proximity gate. The single highest-value rule to examine.
2. **SEC-569** — class C, 1,097 findings, but in **1 of 7** repositories, so
   this is one repository's shape rather than a general noise source. Sample it
   before touching it.
3. **SEC-533** — class C, 448 findings across 3 repositories.
4. **The other 57 class-D rules** — dormant here, structurally identical to
   SEC-161, and unreachable by the proximity fix by construction.
5. **SEC-462** — it matched the string `smtp://` inside an ordinary English <!-- nox:ignore SEC-462 -- this sentence is the report OF the false positive -->
   sentence in this document, during the pre-commit scan of this commit. A bare
   URL scheme with no credential in it is not a secret. Found by accident, which
   is the argument for the labelled benchmark in Workstream 7 rather than
   against this rule in particular.

`docs/design/secret-rule-inventory.json` is excluded from nox's self-scan in
`.nox.yaml`, with the reason recorded there: it is a catalogue of detectors, so
it reports nox's own rule definitions back as nox's secrets. The markdown is not
excluded — the SEC-462 match above is real output, and hiding it would remove
the evidence for item 5.

Each needs the Workstream 2 treatment that was never reached: sample real
matches, classify TP / FP / ambiguous, decide, then rule-diff with every dropped
line read and ledgered.

Fewer findings is not the success criterion. The criterion is that every removed
finding can be explained — and for the drops recorded here, the explanation is a
specific commit with a ledger entry, not an absence of evidence.
