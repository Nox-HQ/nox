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

Today: **10 TP, 0 FP, 0 FN — precision 1.000, recall 1.000.**

The guard is `TestRefutationSuiteRecall` in `cli/bench_refutation_test.go`. It
asserts recall is exactly 1.000, and its threshold is not negotiable. Nothing
that changes scan output ships while it is failing.

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

The credentials in `r7` are synthetic and match no issued credential.

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

## Known gap

Dependency-level refutation — applicability and dependency reachability, Track
G's ladder from *present* through *affected version*, *used* and *reachable* —
is not represented here. Those cases need OSV data, and this corpus is scored
offline so it stays deterministic and runs in CI without a network.

That gap is deliberate and it is not free: Gate B currently has no corpus of
its own. Track G must bring one, scored against a pinned vulnerability
snapshot, before deterministic unreachability is allowed to suppress anything.
