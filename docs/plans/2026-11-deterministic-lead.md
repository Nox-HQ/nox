# Plan: the most accurate deterministic scanner

Started 2026-11-21. Goal: nox scores above every deterministic scanner on
RealVuln in every language, on code it was not tuned on, and on a neutral
benchmark, without giving up precision on real repositories.

## Where we stand

RealVuln v3.1.1, F3 (`docs/benchmarks/2026-11-21-realvuln/`), all scored with
our re-implementation of RealVuln's matcher, which reproduces every published
score we checked exactly:

| | Python | JS/TS | Java |
|---|---:|---:|---:|
| best deterministic | SonarQube 14.5 | Semgrep 12.2 | none published |
| nox (main, #1128) | 13.0 | 8.9 | 4.3 |
| Claude Sonnet 5, agentic | 52.9 | 35.3 | 24.4 |

Recall is 8%; F3 cannot exceed it by much. By class, nox finds 21% of the
injection labels it has rules for (Claude 66%) and 13% of crypto, secrets and
config (Claude 37%). Those two classes are 47% of the labels and about 1,200 of
the 1,871-label gap to Claude. The causes, each reproduced:

1. **Same-file taint.** 112 of 119 missed SQL injections had no finding within
   15 lines; the request is parsed in one file and the query built in another.
2. **Catalog coverage.** Sinks and sources nox did not name (Prisma, Drizzle,
   TypeORM, JPA native queries; framework request bindings).
3. **Line recognizers.** Five syntax-approximation defects in one day
   (ADR 0006).
4. **Location.** Cross-function flows reported at the call into the helper,
   where labels point inside it.

Precision is 5.9%: 9,290 unmatched findings, led by DATA-001 (2,176), SEC-161
(1,633), SEC-080 (807) and IaC rules (~640).

## Rules of the work

The benchmark's authors tuned their own scanner against its ground truth
(`reports/kolega-devsec-max-target-86.5.json`: a target F3 and a count of
misses to convert). We do not.

- **Held-out split.** RealVuln repos are split once, by seeded RNG, stratified
  by language and by origin (real project, training app, generated app): 70%
  development, 30% held out. Development labels may be read to find defects;
  held-out labels are only scored, at milestone gates.
- **A neutral second benchmark.** OWASP Benchmark (Java) and OWASP
  BenchmarkPython, scored with OWASP's own scorer. Never read case by case.
- **General fixes only.** A change must name the language construct or API it
  models, carry a test with its safe counterpart, and must not mention a
  benchmark file, path or repository.
- **Precision gates every change.** Precision suites green, rule-diff corpus
  read (not just passed), every new unmatched finding class sampled and read.
- **Proposition, evidence, counterexample.** Reproduce on the built binary
  before fixing; falsify every guard.

## Milestones

- **M1 — catalog and noise, current architecture.** Dev and held-out:
  Python > 14.5, JS/TS > 12.2. Java: establish a deterministic baseline.
- **M2 — tree-sitter front ends and cross-file taint** for Python, JS/TS, Java.
  Injection recall ≥ 45% on dev and held-out; overall F3 ≥ 20.
- **M3 — deterministic coverage of the remaining classes nox can state
  precisely**, and all other languages on tree-sitter. Overall F3 ≥ 25; OWASP
  Benchmark score above the best deterministic tool published for it.

## Tasks

### Measurement

- [x] Commit the RealVuln harness: per-class scorer (`score_nox.py --by-class`), the parallel rescan script with a working timeout on macOS, and the published-run scorer for other tools
- [x] Freeze the 70/30 split (seeded, stratified), commit the repo lists, and make every score report dev and held-out separately
- [x] Add OWASP Benchmark (Java) and BenchmarkPython: pinned clones, scan script, OWASP's scorer, a baseline score for nox
- [x] Java deterministic baseline: decide with the maintainer whether to run a third-party deterministic scanner for comparison only, or use published OWASP Benchmark scorecards

### M1 — catalog and noise

- [x] SQL sinks the catalog did not name (Prisma raw, Drizzle sql.raw, TypeORM query, pg-promise, JPA createNativeQuery, R2DBC, JdbcTemplate.query) — branch feat/taint-sql-sinks
- [x] SSRF: a keyword url= argument is the URL; a value in the body is not
- [x] Framework request sources: NestJS @Body/@Query/@Param, Next.js route handlers and server actions, Remix loaders/actions, FastAPI parameters, Django class-based views, Express routers mounted from other files
- [x] Sinks by class from the dev-split misses: XSS (12% recall), SSRF (15%), path traversal (26%), command injection (24%), open redirect (29%)
- [x] Crypto and config recall: hard-coded credentials (37%), weak randomness, cookie flags, CORS, TLS verification off, debug mode, JWT verification off — from the dev-split misses
- [x] Noise: DATA-001 in seed data, fixtures and migrations; vendored and committed dependency trees (node_modules, site-packages) treated as third-party; IaC-121–124 and IAC-225 sampled and narrowed per "do not remove rules"
- [x] Interprocedural finding location: report at the sink inside the helper with the call path as evidence — **moved to M2** (decided 2026-11-22): the fingerprint change is made once, with cross-file summaries; on the current engine it could recover at most 8 dev labels — done in #1154
- [x] M1 gate: score dev and held-out, read the new unmatched findings, publish the result in the benchmark doc

### M2 — tree-sitter and cross-file taint

- [x] Tree-sitter WebAssembly build: official runtime plus pinned Python, JavaScript, TypeScript, TSX and Java grammars, reproducible, SHA-pinned, flat tree export (ADR 0006) — #1149
- [x] wazero host in core: bounded parse, trap and timeout recorded as a file limitation, fallback to the line recognizer — #1150; the bound is counted work since #1156
- [x] Python front end producing taint.Units from the tree; A/B against the recognizer on dev, rule-diff corpus and precision suites; switch when no worse — #1151
- [x] JS/TS front end, same gate — #1152
- [x] Java front end, same gate (Kotlin follows) — #1153
- [x] Module index: per-language import and symbol resolution (Python modules, ESM and CommonJS, Java packages and Spring injection) — #1154, Spring injection #1155
- [x] Cross-file summaries: function summaries keyed across the module, call resolution through the index, bounded fixpoint, deterministic order — #1154 (ADR 0007)
- [x] Route entry points as sources across files: the route inventory feeds the taint engine, so a handler's parameters are sources wherever the handler is defined — done as call resolution through declared receiver types (Spring and NestJS injection) and Java for-each headers; dev F3 16.5 -> 17.0
- [x] Parameter SQL flows reachable from a route are raised from low to medium confidence; unreachable ones stay low — a scan stage after the call-graph stage (`core/param_sql_reach.go`); 15 of 64 on the RealVuln repos
- [x] Binary size and parse-time budget measured and recorded per language — docs/benchmarks/2026-11-23-treesitter-budget; the budget is now counted work, not time, so a parse no longer depends on machine load
- [x] M2 gate: dev and held-out, OWASP Benchmark, rule-diff corpus, published — targets **not met**: F3 17.0 / 12.8 (target 20), injection recall 37.0% / 27.8% (target 45%); OWASP Java 56.3, Python 52.8 (Python tree front-end regression); docs/benchmarks/2026-11-21-realvuln#m2-gate-2026-11-23

### M3 — remaining classes and languages

- [ ] Mass assignment where the framework states it: Django ModelForm fields='__all__', Spring entity binding, Mongoose create(req.body), Rails permit!, NestJS DTO without whitelist
- [ ] Authentication and session settings: CSRF protection disabled, session cookie flags, login routes without a rate limit where the framework has a standard limiter
- [ ] Information exposure: stack traces and exception messages written to responses, debug endpoints enabled in production configuration
- [ ] Remaining languages onto tree-sitter (C#, PHP, Ruby, Go via the same front end or kept on go/ast, Kotlin, Scala, Swift, Rust, C/C++, and the rest), each behind the same A/B gate
- [ ] M3 gate: dev and held-out, OWASP Benchmark, published
