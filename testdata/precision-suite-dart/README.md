# SAST precision suite — Dart

A dedicated **honest measurement corpus** for nox's Dart taint support, mirroring
`testdata/precision-suite/` but scoped to `.dart` files. Like that suite (and
unlike `testdata/precision-corpus/`, a curated fixture pinned at a perfect 1.0),
this corpus is built to **measure nox against ground truth** — a *correct*
scanner's expected behavior — so real false negatives surface as a number below
1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-dart
nox bench --precision testdata/precision-suite-dart --json
nox bench --precision testdata/precision-suite-dart --baseline testdata/precision-suite-dart/baseline.json
```

## Measured baseline (as of writing)

```
RULE       TP  FP  FN  PRECISION  RECALL  F1
TAINT-001  1   0   0   1.000      1.000   1.000
TAINT-002  1   0   0   1.000      1.000   1.000
TAINT-004  1   0   0   1.000      1.000   1.000
TAINT-006  1   0   1   1.000      0.500   0.667
OVERALL    4   0   1   1.000      0.800   0.889
```

**Precision 1.00 / recall 0.800 / F1 0.889** (4 TP, 0 FP, 1 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall is **0.800**, held below 1.0 by one
honestly-labeled false negative (see the gap below).

## Ground-truth philosophy

- **Clean samples** (`clean_*.dart`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 `data:` URI in a `r'...'` raw string, a raw-string
  regex token with literal `$`/`\`, `.env`-style placeholder credentials,
  UUID/hex-color constants, a `@generated` / `DO NOT EDIT` banner with a
  **commented-out** `Process.run` sink and a **nested** block comment mentioning
  `db.rawQuery`, a **parameterized** sqflite query (`?` placeholder + args list),
  and a value **coerced through `int.parse`** before a command.
- **True-positive samples** (`tp_*.dart`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* those extras score as false
  positives; where it fires *nothing* the annotation scores as a false negative.

## What's caught (true positives)

Each fires from a catalog **source** (`Platform.environment`, `args`) reaching a
**sink** with no sanitizer on the path. The dominant Dart injection carrier is
**string interpolation** `'...$userInput...'` / `'...${req.query}...'` — lexctx
classifies each `$var`/`${...}` hole as CODE (like Ruby's `#{...}` and Swift's
`\(...)`), so the taint engine sees the untrusted value flow into the built
string.

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.dart` | command injection | TAINT-002 | `Process.run('sh', ['-c', 'gen $name'], runInShell: true)` |
| `tp_sqlinjection.dart` | SQL injection | TAINT-001 | `db.rawQuery('… WHERE id = $id')` (no placeholder) |
| `tp_pathtraversal.dart` | path traversal | TAINT-004 | `File(path).readAsString()` |
| `tp_ssrf.dart` | SSRF | TAINT-006 | `http.get(Uri.parse(raw))` |

## What's suppressed (clean — no false positive)

| Sample | Why it's safe |
|---|---|
| `clean_safe_db.dart` | parameterized `db.rawQuery('… id = ?', [id])` — taint bound as an argument, not interpolated into the SQL text (arg-shape check) |
| `clean_parse_id.dart` | `int.parse(raw)` numeric coercion sanitizes before `Process.run` |
| `clean_placeholders.dart` | config constants / `.env` placeholders — no untrusted input, no sink |
| `clean_rawstring_blob.dart` | a base64 `data:` URI and a regex token in `r'...'` raw strings — data blobs, not code |
| `clean_generated.dart` | `Process.run` / `db.rawQuery` appear only in comments (incl. a nested block comment) — lexctx classifies them as comment, never code |

## The recall gap — and a question about this sample's ground truth

`tp_ssrf_field.dart` is the corpus's one unmet expectation. Its stated premise is
field/receiver taint: a tainted URL stored into a member field, fetched later by
a bare call. That class of limit is real, and it was closed for Swift and
Objective-C by receiver taint (a field assignment now binds the receiver).

**It did not close here, and inspection suggests the sample itself is the
problem — not the engine.** Recorded rather than quietly fixed, because
repairing it is a corpus-design decision:

- The header comment says the tainted URL is stored into `req.url` and fetched
  by `client.send(req)`. **The code does neither.** The URL is the constant
  `Uri.parse('http://internal/')`; the tainted value reaches a request HEADER via
  `req.headers.add('X-Forwarded', raw)`; and `req.followRedirects = true` assigns
  a literal, so its `// tainted redirect target laundered via a field` comment
  does not describe the line it sits on.
- Attacker data therefore never influences WHERE the request goes, so the
  annotated **CWE-918 does not hold for the code as written**. Making nox fire
  here would mean treating any taint reaching an HTTP request object as SSRF,
  which generalises into false positives on every request carrying a
  user-supplied header value.
- The comment also mixes two libraries: `client.send(req)` is a `package:http`
  idiom, while the code uses `dart:io`'s `HttpClient.openUrl`.
- The field-assignment premise does not appear in real code. Across **1213 real
  Dart files** (dart-lang http/shelf/args/collection, flutter/samples,
  json_serializable) there is **not one** `request.url = ...` assignment; a URL
  is set through the constructor. `client.send(request)` is common (122 uses),
  but the request is built with its URL, not mutated into one.

Three repairs are defensible and they are not equivalent — rewrite the code to
match the comment, reclassify away from CWE-918, or drop the sample. Each is a
different claim about what nox should detect, so the choice belongs to whoever
owns the corpus. Until then the expectation stands unmet and recall stays below
1.0, which is the honest state.

## Why precision is the gate

CI enforces `--baseline` (no per-rule precision/recall regression) **and**
`--min-precision 0.90` (a blunt floor). Dart precision is **1.00**, comfortably
above the floor: the arg-shape check (parameterized `rawQuery`), the `int.parse`
sanitizer, the raw-string blob heuristic, and lexctx's comment/nested-comment
classification keep every `clean_*` sample quiet. The gate pins the committed
snapshot so the known FN cannot be silently hidden and no new Dart false positive
can creep in.
