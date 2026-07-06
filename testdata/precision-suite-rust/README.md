# SAST precision suite — Rust

A dedicated **honest measurement corpus** for nox's Rust taint support, mirroring
`testdata/precision-suite/` but scoped to `.rs` files. Like that suite (and unlike
`testdata/precision-corpus/`, a curated fixture pinned at a perfect 1.0), this
corpus is built to **measure nox against ground truth** — a *correct* scanner's
expected behavior — so real false negatives surface as a number below 1.0. A
corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-rust
nox bench --precision testdata/precision-suite-rust --json
nox bench --precision testdata/precision-suite-rust --baseline testdata/precision-suite-rust/baseline.json
```

## Measured baseline (as of writing)

```
RULE       TP  FP  FN  PRECISION  RECALL  F1
TAINT-001  1   0   0   1.000      1.000   1.000
TAINT-002  1   0   1   1.000      0.500   0.667
TAINT-004  1   0   0   1.000      1.000   1.000
TAINT-005  1   0   0   1.000      1.000   1.000
TAINT-006  1   0   0   1.000      1.000   1.000
OVERALL    5   0   1   1.000      0.833   0.909
```

**Precision 1.00 / recall 0.83 / F1 0.909** (5 TP, 0 FP, 1 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall is **0.83, the lowest of nox's
supported languages, by design and honestly** — see the gap below.

## Ground-truth philosophy

- **Clean samples** (`clean_*.rs`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in a `r#"..."#` raw string, a raw byte-string
  opaque token, `.env`-style placeholder credentials, UUID/hex-color constants, a
  `@generated` / `DO NOT EDIT` banner with a **commented-out** `Command::new`
  sink, and safe (parameterized / sanitized) code.
- **True-positive samples** (`tp_*.rs`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* those extras score as false
  positives; where it fires *nothing* the annotation scores as a false negative.

## What's caught (true positives)

Each fires from a catalog **source** (here `std::env::var`, standing in for any
untrusted input) reaching a **sink** with no sanitizer on the path:

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.rs` | command injection | TAINT-002 | `Command::new("sh").arg("-c").arg(format!(…, user))` |
| `tp_sqlinjection.rs` | SQL injection | TAINT-001 | `sqlx::query(&format!("… {} …", id))` |
| `tp_pathtraversal.rs` | path traversal | TAINT-004 | `std::fs::read(user_path)` |
| `tp_ssrf.rs` | SSRF | TAINT-006 | `reqwest::get(&user_url)` |
| `tp_deserialization.rs` | unsafe deser | TAINT-005 | `bincode::deserialize(blob)` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_safe_db.rs` (sqlx `.bind()` parameterization), `clean_parse_id.rs`
(`str::parse::<i64>()` numeric coercion), `clean_safe_path.rs`
(`Path::file_name()` component-stripping).

## The honest gap (false negative) — why Rust recall is the lowest

`tp_cmdinjection_extractor.rs` is a **labeled FN**: a genuine command-injection
bug nox's Rust model does **not** catch. It is kept in the corpus, not deleted —
inflating recall by removing a hard TP would defeat the point of an honest
measurement suite.

The idiom is a standard actix-web handler where the untrusted value arrives as a
destructured **extractor parameter** — `async fn run(query: web::Query<Params>)`
— rather than as a source **call**. nox's taint model (Python/JS/Go/Rust alike)
introduces taint from source *calls* and attribute chains, never from a function
parameter's *type*, so `query.cmd` is never marked tainted and the sink does not
fire. Closing it needs parameter-as-source modeling for web extractors — future
work, not a curation trick.

## Why Rust recall is structurally lower than Python/JS/Go

nox's Rust extractor (`core/taint/engine/extract_rust.go`) is a **line/statement
recognizer**, not a real parser — only Go gets `go/ast`. That, plus Rust's
richer surface, makes line recognition coarse in ways that cost recall:

- **Ownership & moves.** A value moved into a closure, borrowed as `&x`, or
  `.clone()`d is not tracked as a distinct binding, so taint can be lost across a
  move or spuriously carried across a borrow. The recognizer has no alias model.
- **`Result` / `Option` and the `?` operator.** `let x = f(user)?;` unwraps
  through machinery the recognizer treats as an opaque call. Taint usually
  survives (the argument read still propagates — so `?`-using TPs here *do*
  fire), but the early-return control flow `?` implies is invisible, so
  branch-conditional flows can be mismodeled.
- **Iterator / method chains.** `user.split('/').collect().join("_")` is
  recognized only as far as its argument reads; intermediate combinators are not
  modeled, so a value laundered through an untracked combinator can be lost.
- **Macro sinks.** `sqlx::query!(...)`, `diesel::sql_query!`, `format!`,
  `println!` are macros the recognizer cannot expand. It matches the macro
  **call** by name (the extractor normalizes `name!(` → `name(` and `::` → `.`),
  but a value that only becomes dangerous *inside* the expansion is missed.
- **Parameter-as-source.** As above — web-framework extractor parameters are
  untrusted but are not source calls, the single largest recall gap here.

These are the same "recognizer, not a parser" limits documented for Python/JS,
amplified by Rust's ownership/Result/macro idioms — which is why recall is
expected to sit below the other languages and why the FN above is honest rather
than a bug to paper over.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineRust` (in `cli/`) and by the CI "SAST precision gate —
rust" step. If a legitimate improvement lands (an FN closed, a sink added),
refresh it:

```
rm testdata/precision-suite-rust/baseline.json
nox bench --precision testdata/precision-suite-rust --baseline testdata/precision-suite-rust/baseline.json
```
