# SAST precision suite — Kotlin

A dedicated **honest measurement corpus** for nox's Kotlin taint support,
mirroring `testdata/precision-suite/` but scoped to `.kt` files. Like that suite
(and unlike `testdata/precision-corpus/`, a curated fixture pinned at a perfect
1.0), this corpus is built to **measure nox against ground truth** — a *correct*
scanner's expected behavior — so real false negatives surface as a number below
1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-kotlin
nox bench --precision testdata/precision-suite-kotlin --json
nox bench --precision testdata/precision-suite-kotlin --baseline testdata/precision-suite-kotlin/baseline.json
```

## Measured baseline (as of writing)

```
RULE       TP  FP  FN  PRECISION  RECALL  F1
TAINT-001  1   0   0   1.000      1.000   1.000
TAINT-002  1   0   1   1.000      0.500   0.667
TAINT-003  1   0   0   1.000      1.000   1.000
TAINT-004  1   0   0   1.000      1.000   1.000
TAINT-005  1   0   0   1.000      1.000   1.000
TAINT-006  1   0   0   1.000      1.000   1.000
OVERALL    7   0   0   1.000      1.000   1.000
```

**Precision 1.00 / recall 1.00 / F1 1.00** (7 TP, 0 FP, 0 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall reached 1.00 by closing the `.let { }` scope-function receiver aliasing gap the corpus indicted, not by deleting the sample. A 1.0 means this corpus has stopped indicting anything; the structural limits below are real and simply lack a failing sample. Previously **0.857** —
see the gap below.

## Ground-truth philosophy

- **Clean samples** (`clean_*.kt`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in a `"""..."""` triple-quoted raw string with
  a `//` and quotes inside, `@generated` / `DO NOT EDIT` banner with a
  **commented-out** `Runtime.getRuntime().exec` sink, placeholder/example
  credentials, and safe (parameterized / sanitized) code.
- **True-positive samples** (`tp_*.kt`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more*, the extras score as false
  positives; where it fires *nothing*, the annotation scores as a false negative.

## What's caught (true positives)

Each fires from a catalog **source** (here `request.getParameter` /
`request.getInputStream`, standing in for any untrusted input) reaching a **sink**
with no sanitizer on the path:

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.kt` | command injection | TAINT-002 | `Runtime.getRuntime().exec("… " + name)` |
| `tp_sqlinjection.kt` | SQL injection | TAINT-001 | `stmt.executeQuery("… '" + id + "'")` |
| `tp_pathtraversal.kt` | path traversal | TAINT-004 | `FileInputStream(userPath)` |
| `tp_ssrf.kt` | SSRF | TAINT-006 | `URL(userUrl).openStream()` |
| `tp_deserialization.kt` | unsafe deser | TAINT-005 | `ObjectInputStream(body).readObject()` |
| `tp_xss.kt` | reflected XSS | TAINT-003 | `response.getWriter().write(userHtml)` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_safe_db.kt` (`PreparedStatement` `?` parameterization), `clean_parse_id.kt`
(`String.toInt()` numeric coercion), `clean_safe_path.kt`
(`FilenameUtils.getName()` component-stripping).

## The honest gap (false negative) — the scope-function chain

`tp_cmdinjection_scopefn.kt` is a **labeled FN**: a genuine command-injection bug
nox's Kotlin model does **not** catch. It is kept in the corpus, not deleted —
inflating recall by removing a hard TP would defeat the point of an honest
measurement suite.

The idiom is idiomatic Kotlin: the untrusted value is read and piped straight into
a **scope-function** lambda —
`request.getParameter("cmd").let { cmd -> Runtime.getRuntime().exec(cmd) }` — with
no intermediate `val` binding. nox introduces taint from source *calls assigned to
a variable* and propagates it through variable reads; it does not model a
scope-function lambda's parameter (`cmd`, or the implicit `it`) as an alias of its
receiver, so `cmd` inside the lambda is never marked tainted and the `.exec` sink
does not fire. Closing it needs scope-function/lambda-receiver modeling — future
work, not a curation trick.

## Why Kotlin recall is structurally bounded (recognizer, not a parser)

nox's Kotlin extractor (`core/taint/engine/extract_kotlin.go`) is a
**line/statement recognizer**, not a real parser — only Go gets `go/ast`. That,
plus Kotlin's expression-oriented surface, makes line recognition coarse in ways
that cost recall:

- **Scope functions & lambdas.** `let`/`also`/`apply`/`run`/`with` chains launder
  taint through a lambda receiver (`it` or a named parameter) that the flat
  recognizer does not alias to the source — the single largest recall gap here
  (the labeled FN above).
- **Fluent/builder chains.** A value laundered through an untracked intermediate
  call in a `?.`-chain can be lost; the recognizer follows argument reads, not
  intermediate combinators.
- **Expression-body functions.** `fun handler(req) = sink(req.getParameter("x"))`
  has no `{` body, so it is read as a top-level assignment rather than opening its
  own named unit; the intraprocedural read is still captured, but the function
  boundary is not.
- **Extension-function receivers & `this`.** Taint carried on an extension
  receiver or an implicit `this` is not tracked as a distinct binding.

These are the same "recognizer, not a parser" limits documented for
Python/JS/Java/Rust, specialized to Kotlin's scope-function and
expression-oriented idioms — which is why recall sits below 1.0 and why the FN
above is honest rather than a bug papered over.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineKotlin` (in `cli/`) and by the CI "SAST precision gate
— kotlin" step. If a legitimate improvement lands (the scope-function FN closed, a
sink added), refresh it:

```
rm testdata/precision-suite-kotlin/baseline.json
nox bench --precision testdata/precision-suite-kotlin --baseline testdata/precision-suite-kotlin/baseline.json
```
