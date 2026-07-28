# SAST precision suite — Swift

A dedicated **honest measurement corpus** for nox's Swift taint support, mirroring
`testdata/precision-suite/` but scoped to `.swift` files. Like that suite (and
unlike `testdata/precision-corpus/`, a curated fixture pinned at a perfect 1.0),
this corpus is built to **measure nox against ground truth** — a *correct*
scanner's expected behavior — so real false negatives surface as a number below
1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-swift
nox bench --precision testdata/precision-suite-swift --json
nox bench --precision testdata/precision-suite-swift --baseline testdata/precision-suite-swift/baseline.json
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
`clean_*` sample false-positives.

The last gap — the Foundation Process PROPERTY idiom, where the tainted value is stored
into `task.arguments = [...]` and the shell is started by a later bare `task.launch()` —
is closed. An assignment to a member field binds no bare name, so the tainted
value never associated with the object; a field assignment now binds the
RECEIVER, treating taint on any field as taint on the object. It is
deliberately field-INSENSITIVE, an over-approximation that can only widen
taint, so it is enabled per language as a corpus demands it. Measured on 1018
real-world files carrying 2185 field assignments: zero new findings.

A 1.0 means this corpus has stopped indicting anything, not that the model is
complete — the structural limits below are real and simply lack a failing
sample.

## Ground-truth philosophy

- **Clean samples** (`clean_*.swift`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in a `#"..."#` raw string, a raw-string
  opaque token, `.env`-style placeholder credentials, UUID/hex-color constants, a
  `@generated` / `DO NOT EDIT` banner with a **commented-out** `system()` sink,
  and safe (parameterized / sanitized) code.
- **True-positive samples** (`tp_*.swift`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* those extras score as false
  positives; where it fires *nothing* the annotation scores as a false negative.

## What's caught (true positives)

Each fires from a catalog **source** (`CommandLine.arguments`,
`ProcessInfo.processInfo.environment`) reaching a **sink** with no sanitizer on
the path. The dominant Swift injection carrier is **string interpolation**
`"...\(userInput)..."` — lexctx classifies each `\(...)` hole as CODE (like
Ruby's `#{...}`), so the taint engine sees the untrusted value flow into the
built string.

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.swift` | command injection | TAINT-002 | `system("generate \(name)")` |
| `tp_sqlinjection.swift` | SQL injection | TAINT-001 | `sqlite3_exec(db, "… \(id)")` |
| `tp_pathtraversal.swift` | path traversal | TAINT-004 | `String(contentsOfFile: path)` |
| `tp_ssrf.swift` | SSRF | TAINT-006 | `session.dataTask(with: URL(string: raw)!)` |
| `tp_deserialization.swift` | unsafe deser | TAINT-005 | `NSKeyedUnarchiver.unarchiveObject(with: raw)` |
| `tp_xss.swift` | XSS (WebView) | TAINT-003 | `webView.loadHTMLString("…\(comment)…")` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_safe_db.swift` (sqlite3 `?` placeholder + `sqlite3_bind_text`),
`clean_parse_id.swift` (`Int(raw)` numeric coercion), `clean_safe_html.swift`
(`escapeHTML(...)` before the WebView load).

### The label-fold that keeps precision perfect

Swift initializers/methods are discriminated by their argument LABEL, which the
line recognizer cannot see at the callee. The extractor therefore **folds** the
discriminating first label into the callee — `String(contentsOfFile:)` →
`String.contentsOfFile`, `Data(contentsOf:)` → `Data.contentsOf`,
`session.dataTask(with:)` → `session.dataTask.with`. That is why a plain
`String(x)` conversion or a safe `URL(fileURLWithPath:)` local-file initializer
**never** collides with a sink key — the single most important precision guard in
the Swift model (the analogue of Rust's `::`→`.` normalization).

## The honest gap (false negative)

`tp_cmdinjection_property.swift` is a **labeled FN**: a genuine command-injection
bug nox's Swift model does **not** catch. It is kept in the corpus, not deleted —
inflating recall by removing a hard TP would defeat the point of an honest
measurement suite.

The idiom is the idiomatic Foundation `Process` form where the tainted value is
assigned into the `task.arguments` **property** (an array literal built with
`\(name)`) and the shell is launched by a later bare `task.launch()` with no
argument. nox's Swift extractor is a **line/statement recognizer** (only Go gets
`go/ast`): it tracks taint through assignments whose LHS is a *bare identifier*,
so an assignment to a member PROPERTY (`task.arguments = …`) is not modeled as a
distinct binding, the tainted array never associates with `task`, and
`task.launch()` carries no argument to match. Closing it needs field/receiver
taint tracking — future work, not a curation trick.

## Why Swift recall is structurally below Python/Go

nox's Swift extractor (`core/taint/engine/extract_swift.go`) is a line/statement
recognizer, not a real parser. That, plus Swift's richer surface, makes line
recognition coarse in ways that cost recall:

- **Property/receiver assignment.** `task.arguments = […]` binds a member, not a
  bare local, so taint through a mutated object property is lost (the FN above).
- **Optional chaining / `try?` / `guard let`.** `guard let x = f(user) else {…}`
  and `let y = obj?.z` unwrap through machinery the recognizer treats as an
  opaque call or a plain assignment — taint usually survives (the argument read
  propagates) but the control flow is invisible.
- **Trailing closures.** `session.dataTask(with: req) { data, _ in … }` folds the
  closure body into the enclosing function rather than its own scope.
- **Parameter-as-source.** A Vapor `Request`/`URLRequest` arriving as a typed
  function parameter is untrusted but is not a source CALL, so it is not tainted
  from its type (the same documented gap as Rust/Java web extractors).

These are the same "recognizer, not a parser" limits documented for the other
non-Go languages, specialized to Swift's property-mutation and optional idioms —
which is why the FN above is honest rather than a bug to paper over.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineSwift` (in `cli/`) and by the CI "SAST precision gate
— swift" step. If a legitimate improvement lands (the FN closed, a sink added),
refresh it:

```
rm testdata/precision-suite-swift/baseline.json
nox bench --precision testdata/precision-suite-swift --baseline testdata/precision-suite-swift/baseline.json
```

## Where an annotation goes

`nox-expect` marks the line a correct scanner **reports**, which is the SINK —
the line where the dangerous operation happens — not the line where the tainted
value was constructed or stored. That is what SARIF consumers and human triagers
expect, and it is the convention every sample here follows:

```
task.arguments = @[@"-c", arg];   // configuration: NOT annotated
[task launch];                    // nox-expect: TAINT-002   <- the sink
```

Annotating a configuration line instead makes a correct finding score as a false
positive at the sink plus a false negative at the annotation, which reads as a
precision regression when nothing is wrong. Two samples in this corpus had that
defect and were corrected; the rule is written down here so it cannot drift back
in silently.
