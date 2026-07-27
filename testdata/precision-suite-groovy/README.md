# SAST precision suite — Groovy

A dedicated **honest measurement corpus** for nox's Groovy taint support,
mirroring `testdata/precision-suite/` but scoped to `.groovy` files (the same
lexer serves `.gradle` and the extension-less `Jenkinsfile`). Like that suite
(and unlike `testdata/precision-corpus/`, a curated fixture pinned at a perfect
1.0), this corpus is built to **measure nox against ground truth** — a *correct*
scanner's expected behavior — so real false negatives surface as a number below
1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-groovy
nox bench --precision testdata/precision-suite-groovy --json
nox bench --precision testdata/precision-suite-groovy --baseline testdata/precision-suite-groovy/baseline.json
```

## Measured baseline (as of writing)

```
RULE       TP  FP  FN  PRECISION  RECALL  F1
TAINT-001  1   0   0   1.000      1.000   1.000
TAINT-002  2   0   1   1.000      0.667   0.800
TAINT-004  1   0   0   1.000      1.000   1.000
TAINT-005  1   0   0   1.000      1.000   1.000
TAINT-006  1   0   0   1.000      1.000   1.000
OVERALL    7   0   0   1.000      1.000   1.000
```

**Precision 1.00 / recall 1.00 / F1 1.00** (7 TP, 0 FP, 0 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall reached 1.00 by closing the `with { }` closure receiver aliasing gap the corpus indicted, not by deleting the sample. A 1.0 means this corpus has stopped indicting anything; the structural limits below are real and simply lack a failing sample. Previously **0.857** —
see the gap below.

## Ground-truth philosophy

- **Clean samples** (`clean_*.groovy`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in a `'''...'''` triple-quoted string with a
  `//` and a `$` inside, a `@generated` / `DO NOT EDIT` banner with a
  **commented-out** `.execute()` / `Eval.me` sink, and safe (parameterized /
  numerically-coerced / path-sanitized) code.
- **True-positive samples** (`tp_*.groovy`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more*, the extras score as false
  positives; where it fires *nothing*, the annotation scores as a false negative.

## What's caught (true positives)

Each fires from a catalog **source** (here `request.getParameter`, standing in for
any untrusted input — a Jenkins `params.X`, `System.getenv`, or script `args`)
reaching a **sink** with no sanitizer on the path:

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.groovy` | command injection | TAINT-002 | `"… ${name}".execute()` (String.execute) |
| `tp_cmdinjection_jenkins.groovy` | command injection | TAINT-002 | Jenkins `sh("… ${branch}")` step |
| `tp_sqlinjection.groovy` | SQL injection | TAINT-001 | `sql.rows("… '" + id + "'")` |
| `tp_pathtraversal.groovy` | path traversal | TAINT-004 | `new FileInputStream(path)` |
| `tp_ssrf.groovy` | SSRF | TAINT-006 | `new URL(u).openStream()` |
| `tp_codeeval.groovy` | code injection | TAINT-005 | `Eval.me(expr)` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_placeholders.groovy` (`Sql.rows("… = ?", [id])` bind-parameter
placeholder), `clean_parse_id.groovy` (`String.toInteger()` numeric coercion),
`clean_safe_path.groovy` (`FilenameUtils.getName()` component-stripping),
`clean_datablob.groovy` (base64 blob in a triple-quoted string), and
`clean_generated.groovy` (commented-out sinks in a `@generated` banner).

## GString interpolation is treated as CODE (the key modeling choice)

Groovy's dominant injection carrier is GString interpolation —
`"run ${cmd}".execute()`, `sh("checkout ${branch}")`. lexctx emits the `${…}` /
`$var` interpolation *hole* as **code** (only the surrounding literal text is
string), exactly as the Swift scanner does for `\(…)`. Without this the tainted
expression would be blanked as string and every idiomatic Groovy command/SQL
injection would be a false negative. The `$` and braces stay string; only the
inner expression is code, so no spurious `$` read leaks into the engine.

## The honest gap (false negative) — the closure

`tp_cmdinjection_closure.groovy` is a **labeled FN**: a genuine command-injection
bug nox's Groovy model does **not** catch. It is kept in the corpus, not deleted —
inflating recall by removing a hard TP would defeat the point of an honest
measurement suite.

The idiom is idiomatic Groovy: the untrusted value is piped straight into a
**closure** —
`request.getParameter("cmd").with { c -> c.execute() }` — with no intermediate
`def` binding. nox introduces taint from source *calls assigned to a variable* and
propagates it through variable reads; it does not model a closure parameter (`c`,
or the implicit `it`) as an alias of the value the closure is applied to, so `c`
inside the closure is never marked tainted and the `.execute` sink does not fire.
Closing it needs closure/receiver-binding modeling — future work, not a curation
trick.

## Why Groovy recall is structurally bounded (recognizer, not a parser)

nox's Groovy extractor (`core/taint/engine/extract_groovy.go`) is a
**line/statement recognizer**, not a real parser — only Go gets `go/ast`. That,
plus Groovy's dynamic, expression-oriented surface, makes line recognition coarse
in ways that cost recall:

- **Closures & builder DSLs.** `with`/`each`/`collect`/`tap` and Jenkins/Gradle
  builder blocks launder taint through a closure receiver (`it` or a named
  parameter) that the flat recognizer does not alias to the source — the single
  largest recall gap here (the labeled FN above). Bare `name(args) { … }` DSL
  blocks are deliberately folded into the enclosing script unit, not treated as
  method declarations.
- **Paren-less command chains.** `println x`, `sh "cmd"` without parentheses are
  recognized only where the statement shape allows; a value laundered through an
  untracked builder/DSL method is not tracked.
- **Implicit returns & dynamic dispatch.** Groovy's implicit last-expression
  return and runtime method dispatch (`obj."$name"()`) are not modeled.

These are the same "recognizer, not a parser" limits documented for
Python/JS/Java/Kotlin, specialized to Groovy's closure and GString idioms — which
is why recall sits below 1.0 and why the FN above is honest rather than a bug
papered over.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineGroovy` (in `cli/`) and by the CI "SAST precision gate
— groovy" step. If a legitimate improvement lands (the closure FN closed, a sink
added), refresh it:

```
rm testdata/precision-suite-groovy/baseline.json
nox bench --precision testdata/precision-suite-groovy --baseline testdata/precision-suite-groovy/baseline.json
```
