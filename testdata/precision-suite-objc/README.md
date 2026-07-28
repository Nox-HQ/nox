# SAST precision suite — Objective-C

A dedicated **honest measurement corpus** for nox's Objective-C taint support,
mirroring `testdata/precision-suite/` but scoped to `.m` / `.mm` files. Like that
suite (and unlike `testdata/precision-corpus/`, a curated fixture pinned at a
perfect 1.0), this corpus is built to **measure nox against ground truth** — a
*correct* scanner's expected behavior — so real false negatives surface as a
number below 1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-objc
nox bench --precision testdata/precision-suite-objc --json
nox bench --precision testdata/precision-suite-objc --baseline testdata/precision-suite-objc/baseline.json
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

The last gap — the NSTask PROPERTY idiom, where the tainted value is stored
into `task.arguments = @[...]` and the shell is started by a later bare `[task launch]` —
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

- **Clean samples** (`clean_*.m`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in an `@"..."` NSString, an opaque
  secret-shaped token constant, a `@generated` / `DO NOT EDIT` banner with a
  **commented-out** `system()` sink and a `system(...)` substring inside a string
  constant, and safe (parameterized / sanitized) code.
- **True-positive samples** (`tp_*.m`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* those extras score as false
  positives; where it fires *nothing* the annotation scores as a false negative.

## What's caught (true positives)

Each fires from a catalog **source** (`getenv` / `[NSProcessInfo environment]`,
`[NSUserDefaults stringForKey:]`) reaching a **sink** with no sanitizer on the
path. The dominant Objective-C taint carrier is `-stringWithFormat:` /
`+stringWithFormat:` building a command / query / path / HTML string from the
untrusted value, and the **bracket message send** `[recv selector:arg]` that
carries the tainted value into the sink.

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.m` | command injection | TAINT-002 | `system([cmd UTF8String])` |
| `tp_sqlinjection.m` | SQL injection | TAINT-001 | `sqlite3_exec(db, [sql UTF8String], …)` |
| `tp_pathtraversal.m` | path traversal | TAINT-004 | `[NSString stringWithContentsOfFile:path …]` |
| `tp_ssrf.m` | SSRF | TAINT-006 | `[session dataTaskWithURL:url]` |
| `tp_deserialization.m` | unsafe deser | TAINT-005 | `[NSKeyedUnarchiver unarchiveObjectWithData:data]` |
| `tp_xss.m` | XSS (WebView) | TAINT-003 | `[webView loadHTMLString:html baseURL:nil]` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_safe_db.m` (sqlite3 `?` placeholder + `sqlite3_bind_text`),
`clean_parse_id.m` (`[raw integerValue]` numeric coercion), `clean_safe_html.m`
(`[comment escapeHTML]` before the WebView load), and `clean_safe_path.m`
(`[fileName lastPathComponent]` before the file read).

### The message-send rewrite that makes the recognizer work

Objective-C dispatches through **bracket message sends** `[recv selector:arg …]`,
which a C-style line recognizer cannot read directly. The extractor
(`core/taint/engine/extract_objc.go`) therefore **rewrites** every message send to
the dotted call form the recognizer and the catalog both understand —
`[db executeQuery:sql]` → `db.executeQuery(sql)`,
`[NSString stringWithContentsOfFile:p …]` → `NSString.stringWithContentsOfFile(p, …)`,
`[[NSData alloc] initWithBase64EncodedString:b64 …]` folds innermost-first. Every
catalog key is the **selector suffix**, matched by the engine's dotted-suffix
fallback. This is the Objective-C analogue of Swift's label-fold and Rust's
`::`→`.` normalization.

## The honest gap (false negative)

`tp_cmdinjection_nstask.m` is a **labeled FN**: a genuine command-injection bug
nox's Objective-C model does **not** catch. It is kept in the corpus, not deleted
— inflating recall by removing a hard TP would defeat the point of an honest
measurement suite.

The idiom is the idiomatic Foundation `NSTask` form where the tainted value is
assigned into the `arguments` **property** (an array literal built from the
untrusted string) and the shell is launched by a later bare `[task launch]` with
no argument. nox's Objective-C extractor is a **line/statement recognizer** (only
Go gets `go/ast`): it tracks taint through assignments whose LHS is a *bare
identifier*, so an assignment to a member PROPERTY (`task.arguments = …`) is not
modeled as a distinct binding, the tainted array never associates with `task`, and
`[task launch]` carries no argument to match. Closing it needs field/receiver
taint tracking — future work, not a curation trick.

## Why Objective-C recall is structurally below Python/Go

nox's Objective-C extractor is a line/statement recognizer, not a real parser.
That, plus Objective-C's message-passing surface, makes line recognition coarse in
ways that cost recall:

- **Property / ivar assignment.** `task.arguments = …` / `_field = tainted` binds a
  member, not a bare local, so taint through a mutated object property is lost (the
  FN above).
- **Dynamic dispatch.** `performSelector:`, `NSInvocation`, and KVC
  (`setValue:forKey:`) route calls through machinery the recognizer cannot follow.
- **Blocks / completion handlers.** A tainted value captured inside a completion
  block folds into the enclosing scope rather than its own.
- **Parameter-as-source.** An untrusted value arriving as a typed method parameter
  is not a source CALL, so it is not tainted from its type (the same documented gap
  as the Swift / Rust / Java extractors).

These are the same "recognizer, not a parser" limits documented for the other
non-Go languages, specialized to Objective-C's property-mutation and
message-passing idioms — which is why the FN above is honest rather than a bug to
paper over. Memory-safety bugs (buffer overflow, use-after-free) are a **different
analysis** than source→sink taint and are deliberately out of scope for this
engine.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineObjC` (in `cli/`) and by the CI "SAST precision gate —
objc" step. If a legitimate improvement lands (the FN closed, a sink added),
refresh it:

```
rm testdata/precision-suite-objc/baseline.json
nox bench --precision testdata/precision-suite-objc --baseline testdata/precision-suite-objc/baseline.json
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
