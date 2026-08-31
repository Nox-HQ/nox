# Milestone I — does constraint solving help nox?

Written before the measurement, so the question cannot be adjusted to fit the
answer.

Milestone I is explicitly a research spike, not an architecture commitment. Its
closing instruction is the important one:

> If the data isn't compelling, NOX should not adopt SMT simply because SAVIOR
> did. That's exactly why we're running research.

## The question, in the order it has to be asked

The milestone proposes building a tiny verifier that takes path constraints, a
trigger predicate and model assumptions, and returns SAT / UNSAT / UNKNOWN
translated into nox propositions. Before that is worth building, an earlier
question has to be answered:

**How many of nox's findings present a constraint problem at all?**

A solver is only useful where there is something to solve. If nox's findings
mostly have no branch between source and sink, or if the branches that exist
are trivially decidable, then the answer to "does SMT help" is settled without
implementing SMT — and implementing it first would be answering a question
nobody had established was being asked.

## What is already known before measuring

`taint.Flow` records source, sink, file, function, language, the interprocedural
via-chain and the sink role. It records **no path constraints, no guards, no
conditions**. So a solver has no input today, and producing that input is
path-sensitive analysis — a larger project than the solver itself.

That is a fact about the code, not a result. The measurement below is about
whether that missing input would be worth building.

## Hypotheses

- **H1.** A minority of taint flows have any guard between source and sink. If
  most flows are straight-line, path feasibility is not the bottleneck.
- **H2.** Of the guards that do exist, most are simple equality, emptiness or
  length comparisons — decidable by interval and equality reasoning, without a
  general SMT solver.
- **H3.** The guards that need real solving involve string operations, regular
  expressions or calls into functions the analysis has no summary for — cases
  where an SMT encoding is either unsound or requires modelling work far larger
  than the solving.

## Method

Over every corpus and several real repositories, for each taint finding:

1. Read the enclosing function.
2. Count the conditional statements between the source line and the sink line.
3. Classify each guard by what deciding it would require.

Classification, coarsest first:

| class | example | needs |
|---|---|---|
| `none` | no branch between source and sink | nothing |
| `equality` | `if x == "" `, `if mode != "legacy"` | equality reasoning |
| `length` | `if len(x) > 8` | interval reasoning |
| `membership` | `if allowed[x]`, `if slices.Contains(...)` | a model of the container |
| `string` | `strings.HasPrefix`, concatenation | string theory |
| `regex` | `re.MatchString(x)` | automata, and often undecidable in practice |
| `call` | `if isValid(x)` | an interprocedural summary |

## Success criteria, from the milestone

The spike must report:

- vulnerability classes where constraint solving materially helps
- languages where modelling is practical
- cost per resolved hypothesis
- false refutation rate
- frequency of `UNKNOWN`
- modelling completeness requirements
- whether simpler approaches outperform SMT for common nox cases

Two of these cannot be measured without a solver in place — cost per resolved
hypothesis, and false refutation rate. The spike will say so rather than
estimate them, and will report what the other five say about whether building
the solver to measure the remaining two is warranted.

## What would make the answer "adopt"

A result is compelling if a material fraction of findings carry guards in the
`string`, `regex` or `call` classes AND those guards are what stands between a
finding and a decision. If the guards are mostly `none`, `equality` or `length`,
the honest recommendation is that interval and equality reasoning — which is
days of work, not a dependency — covers the ground, and SMT is a solution
looking for a problem nox does not have.
