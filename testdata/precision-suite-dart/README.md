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
TAINT-006  3   0   0   1.000      1.000   1.000
OVERALL    6   0   0   1.000      1.000   1.000
```

**Precision 1.00 / recall 1.00 / F1 1.00** (6 TP, 0 FP, 0 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall reached 1.0 when the two former
false negatives in `tp_known_fns.dart` were closed (see below).

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

## The closed recall gap

`tp_known_fns.dart` carries two real flows that were honest false negatives.
Both are the Dart side of a capability the engine scopes per language, because
each is an over-approximation that can only widen taint and is enabled where a
corpus demands it. Dart opted in after the join was measured to add **zero
findings across 1072 real Dart files** (dart-lang/http, cfug/dio,
dart-lang/shelf, flutter/samples):

- **cross-method flow through an instance FIELD** — a field declared in a class
  body is shared state for that class's methods (Ruby joins `@ivar`, Perl
  `our`). The join is per class: the same field name in two classes stays two
  variables, and a local of the same name still shadows the field in its own
  method. `this.field` is normalized to the bare name. A top-level variable is
  shared by every unit in the file.
- **taint laundered through a LIST ELEMENT** — an element assignment
  (`m['k'] = x`) binds the container, as for Perl, and an in-place mutator
  (`add`, `addAll`, `insert`, `insertAll`, `addEntries`, `write`, `writeln`,
  `writeAll`) is modeled as `urls = urls.add(x)`: taint already in the
  container is kept, taint in the argument is added. Container-level, not per
  element — `urls[1]` is tainted when `urls[0]` was the store.

### Withdrawn: `tp_ssrf_field.dart`

It was annotated CWE-918 on a field/receiver-taint premise, and did not survive
inspection:

- its comment described a tainted URL stored into `req.url` and fetched by
  `client.send(req)`. The code did neither — the URL was the constant
  `Uri.parse('http://internal/')`, the tainted value reached a request HEADER,
  and `req.followRedirects = true` assigned a literal despite a comment calling
  it a tainted redirect target. Attacker data never influenced WHERE the request
  went, so the annotated CWE did not hold for the code as written.
- the comment mixed two libraries: `client.send(req)` is `package:http`, the code
  used `dart:io`'s `HttpClient.openUrl`.
- the premise is not realizable in Dart. `HttpClientRequest` exposes no settable
  URL field, and across **1213 real Dart files** there is not one
  `request.url = ...` assignment — URLs are constructor-set.

Correct SSRF coverage already existed in `tp_ssrf.dart`, so the sample was
replaced by the two gaps above rather than repaired into an idiom Dart does not
have.

## Why precision is the gate

CI enforces `--baseline` (no per-rule precision/recall regression) **and**
`--min-precision 0.90` (a blunt floor). Dart precision is **1.00**, comfortably
above the floor: the arg-shape check (parameterized `rawQuery`), the `int.parse`
sanitizer, the raw-string blob heuristic, and lexctx's comment/nested-comment
classification keep every `clean_*` sample quiet. The gate pins the committed
snapshot so a closed FN cannot silently reopen and no new Dart false positive
can creep in.
