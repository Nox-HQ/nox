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
TAINT-002  2   0   0   1.000      1.000   1.000
TAINT-004  1   0   0   1.000      1.000   1.000
TAINT-005  1   0   0   1.000      1.000   1.000
TAINT-006  1   0   0   1.000      1.000   1.000
OVERALL    6   0   0   1.000      1.000   1.000
```

**Precision 1.00 / recall 1.00 / F1 1.00** (6 TP, 0 FP, 0 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall reached 1.00 once the last documented
false negative (a web-framework **extractor parameter** as an untrusted source)
was closed — see "The closed gap" below. The recall lift was won without any
precision loss: `clean_typed_param.rs` proves an ordinary typed parameter is
still not treated as a source.

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
| `tp_cmdinjection_extractor.rs` | command injection | TAINT-002 | `web::Query<_>` extractor param → `Command::new("sh").arg("-c").arg(&query.cmd)` |
| `tp_sqlinjection.rs` | SQL injection | TAINT-001 | `sqlx::query(&format!("… {} …", id))` |
| `tp_pathtraversal.rs` | path traversal | TAINT-004 | `std::fs::read(user_path)` |
| `tp_ssrf.rs` | SSRF | TAINT-006 | `reqwest::get(&user_url)` |
| `tp_deserialization.rs` | unsafe deser | TAINT-005 | `bincode::deserialize(blob)` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_safe_db.rs` (sqlx `.bind()` parameterization), `clean_parse_id.rs`
(`str::parse::<i64>()` numeric coercion), `clean_safe_path.rs`
(`Path::file_name()` component-stripping), and `clean_typed_param.rs` (an
ordinary `i64` / `&Config` parameter is **not** a source, so the
extractor-parameter modeling does not over-taint normal parameters).

## The closed gap — extractor-parameter-as-source

`tp_cmdinjection_extractor.rs` was the suite's **labeled false negative**: a
genuine command-injection bug where the untrusted value arrives as a
web-framework **extractor parameter** — `async fn run(query: web::Query<Params>)`
(actix) or the destructured `Query(params): Query<Params>` (axum) — rather than
as a source **call**. nox's taint model introduces taint from source *calls* and
attribute chains; a function parameter's *type* was never a source, so
`query.cmd` was never marked tainted and the sink did not fire.

It is now **caught**. `core/taint/engine/extract_rust.go` seeds any parameter
whose type is a known untrusted-input extractor — actix `web::Query<_>` /
`web::Form<_>` / `web::Json<_>` / `web::Path<_>`, and the bare axum `Query<_>` /
`Form<_>` / `Json<_>` / `Path<_>` — as tainted-on-entry, by emitting a synthetic
`binding = <extractor-source>()` statement the engine already understands. Both
the named (`query: web::Query<_>`) and the destructured (`Query(params): …`)
shapes are handled, binding the value actually used. The shared `StructuralEngine`
is untouched — the change is Rust-local, in the extractor and the `rust` catalog
block. Only these specific extractor wrappers seed taint: a plain typed parameter
does not, which `clean_typed_param.rs` verifies.

## Remaining recognizer limits (honest, still un-modeled)

nox's Rust extractor (`core/taint/engine/extract_rust.go`) is a **line/statement
recognizer**, not a real parser — only Go gets `go/ast`. Rust's richer surface
still makes line recognition coarse in ways that can cost recall on idioms this
suite does not yet exercise. These are documented honestly so recall of 1.00 on
*this* corpus is not mistaken for perfect coverage of all Rust:

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
- **Extractor coverage is a fixed list.** Parameter-as-source seeding recognizes
  the actix/axum `Query`/`Form`/`Json`/`Path` wrappers; a custom `FromRequest`
  extractor or a less-common framework type is not seeded, so its parameter is
  not tainted. Extending the list is a catalog + recognizer change, not a
  structural one.

These are the same "recognizer, not a parser" limits documented for Python/JS,
amplified by Rust's ownership/Result/macro idioms. They are why the suite keeps
measuring against ground truth rather than assuming full coverage.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineRust` (in `cli/`) and by the CI "SAST precision gate —
rust" step. If a legitimate improvement lands (an FN closed, a sink added),
refresh it:

```
rm testdata/precision-suite-rust/baseline.json
nox bench --precision testdata/precision-suite-rust --baseline testdata/precision-suite-rust/baseline.json
```
