# Refutation suite — the corpus that measures wrongful suppression

Every other corpus in `testdata/` measures nox reporting **too much**. This one
measures nox reporting **too little**, and it exists because the
evidence-native programme (`docs/design/evidence-native-nox.md`) is largely a
programme of building things that remove findings: lexical refinement, constant
analysis, taint refutation, reachability, structural deduplication,
applicability reasoning.

Each of those is correct and worth building. Each of them, done slightly wrong,
produces the same result:

> We reduced false positives by hiding real vulnerabilities.

That failure is invisible to every metric anyone routinely watches. Precision
rises. Finding counts fall. The precision suite — which scores over-firing —
reports an improvement. CI goes green. Nothing turns red anywhere, because
nothing in the existing measurement layer is looking in that direction.

## How it works

Ground truth is inverted relative to `precision-suite`. There are **no clean
samples**. Every file carries a real, currently-detected vulnerability, shaped
so that a plausible refiner would dismiss it for a reason that sounds good and
is wrong.

```
nox bench --precision testdata/refutation-suite
```

Today: **27 TP, 0 FP, 0 FN — precision 1.000, recall 1.000.**

There are two guards, and they answer different questions.

`TestRefutationSuiteRecall` (`cli/bench_refutation_test.go`) asserts recall is
exactly 1.000. Its threshold is not negotiable, and nothing that changes scan
output ships while it is failing.

`TestRefutationBranchCoverage` (`cli/bench_coverage_test.go`) asserts that
every refutation branch still has a fixture. Recall cannot answer this:
deleting the last sample for a branch deletes its expectations too, so recall
stays 1.000 over whatever remains and the branch quietly stops being guarded.
The universe of branches therefore lives in `bench.RefutationBranches`, in
code, where a testdata deletion cannot reach it; each sample claims one with a
`nox-cover:` annotation. Remove `r11_pipeline_unquoted.sh` and the recall test
still passes while coverage fails naming `sanitizer-pipeline-producer`.

## The cases

Each sample names the refiner it guards and the tempting-but-wrong reasoning
that would drop it. The header comment in each file carries the full argument.

| Sample | Guards | The wrong reasoning it catches |
|---|---|---|
| `r1_comment_adjacent.py` | Lexical context (E1) | A lexer that starts a comment at the first bare `#` rather than tracking string state swallows a sink whose argument holds a `"#"` literal |
| `r2_generated_banner.go` | Generated-code suppression (E1) | The banner is a *string*. A suppressor that greps the whole file, rather than requiring the banner in the leading comment block, silently skips hand-written code — most reliably in code that writes code |
| `r3_constant_looking.py` | Constant analysis (E2) | Resolving one operand of a concatenation to a literal and stopping. `SAFE_PREFIX` is constant; the environment read next to it is not |
| `r4_sanitizer_other_var.go` | Sanitizer recognition | Proximity is not dataflow. `html.EscapeString` runs one line above the sink, on a different variable, and its result is even interpolated into the same response |
| `r5_two_distinct.py` | Flow identity, dedup (F) | One tainted value reaching two sinks on consecutive lines shares a source, a variable and a line neighbourhood — every cheap merge signal — but is two vulnerabilities with two fixes |
| `r6_wrapper_reach.py` | Reachability (G) | An intraprocedural check finds no source-to-sink flow in *either* function and concludes the code is safe. The sink sits behind a one-line private wrapper |
| `r7_placeholder_named_secret.py` | Value semantics (E3) | Two live-format credentials bound to identifiers that say `EXAMPLE` and `SAMPLE`. The value is the evidence; the name is not. `clean_placeholders.py` pins the other half of this rule |
| `r8_replicated_no_pdb.yaml` | Absence subject preconditions (#582) | A precondition that correctly exempts a single-replica workload keeps widening until it exempts the replicated ones the rule was written for |
| `r9_longrunning_no_probes.yaml` | Absence resource kinds (#583) | Probe rules narrowed off batch workloads generalize from the workload KIND to the container's command line, which is a guess |
| `r10_batch_still_governed.yaml` | Absence resource kinds (#583) | "Some rules do not apply to CronJobs" becomes "CronJobs are exempt", removing limits, requests and security context from every scheduled job |
| `r11_pipeline_unquoted.sh` | Pipeline sanitizer producers (#585) | `jq \| @sh` quoting is generalized from the exact call that quotes to any call named `jq` — the direction that turns false positives into false negatives |

The last four are the rule-level half of the corpus and they were added because
Gate A could not see it. Every case above them guards a *refiner*. Nothing
guarded a *rule narrowed by its own applicability conditions* — so #582, #583
and #585 each removed real findings with no fixture anywhere able to catch an
over-narrowing, and two of the three were invisible to the rule-diff corpus as
well at the moment they merged.

The credentials in `r7` are synthetic and match no issued credential.

## What the rule-level cases found on their first run

Writing `r8` surfaced two defects that no existing guard could see. Both are
filed; neither is fixed here, because the instrument has to exist before the
narrowing that answers it.

**IAC-183 re-reports what IAC-132 refutes.** The two rules carry a
byte-identical absence configuration — same anchor, same property,
`absence_span: file`. #582 gave IAC-132 a subject precondition and the
structural path; IAC-183 kept neither and describes itself as a Helm rule while
matching every `*.yaml`. On a single-replica Deployment with no budget,
IAC-132 is correctly silent and IAC-183 fires. So #582's 65 removed findings
were removed under one ID and are still reported under another, and the
rule-diff report showed `IAC-132: 29 -> 16` against an IAC-183 that never
moved. It is annotated in `r8` deliberately: the corpus records what nox does
today so that removing it can be measured rather than asserted.

**IaC rules match inside YAML comments.** A file containing only
`# ... PodDisruptionBudget ...` in a comment reports IAC-395. `core/lexctx`
classifies YAML comment regions and `core/rules/matcher.go` consults it, but
the IaC path does not reach that refinement — which is the same class `r1`
guards for Python, one file format over. `r8`'s header is worded around the
trigger rather than annotating it, because annotating it would make this corpus
assert that the behaviour is correct.

## Rules for changing this corpus

1. **Never lower the threshold.** A refiner that fails this corpus is wrong
   until proven otherwise; that is the whole point of Gate A.
2. **Never delete a case to make a refiner pass.** If a sample is genuinely
   incorrect — the vulnerability is not real, or the shape does not represent
   the hazard claimed — fix or replace the *sample*, and say why in the commit
   message.
3. **Add a case before you build a refiner.** Milestones E1, E2, E3, F and G
   each remove findings. Each should arrive with the case that proves it
   removes only what it should.
4. **Add the branch before the case.** Register it in
   `bench.RefutationBranches` first and let `TestRefutationBranchCoverage`
   fail: the failing test names the proposition and the wrong reasoning, which
   is the specification for the sample that has to be written.
5. **Never delete a branch to make coverage pass.** Removing an entry from the
   registry is a claim that nox no longer refutes that way. Say so in the
   commit.

## Known gap

Dependency-level refutation — applicability and dependency reachability, Track
G's ladder from *present* through *affected version*, *used* and *reachable* —
is not represented here. Those cases need OSV data, and this corpus is scored
offline so it stays deterministic and runs in CI without a network.

That gap is deliberate and it is not free: Gate B currently has no corpus of
its own. Track G must bring one, scored against a pinned vulnerability
snapshot, before deterministic unreachability is allowed to suppress anything.
