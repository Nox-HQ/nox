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

### M2 follow-up — the gap to the M2 targets (decided 2026-11-23, before M3)

Gate 2026-11-24 (main 0cc6f49, all 203 rescanned): dev F3 17.0 -> 21.3, injection recall 37.0% -> 51.2% (targets 20 / 45%, met); held-out F3 12.8 -> 15.2, injection recall 27.8% -> 35.4% (not met). Held-out moved about half as far as dev; held-out JS/TS (15.4) and Java (11.2) are the gap. See docs/benchmarks/2026-11-21-realvuln/README.md#m2-gap-close-gate-2026-11-24. Decided: M2 closes on dev with the held-out shortfall recorded; M3 starts (maintainer, 2026-11-24).

- [x] Python tree-reader regression on OWASP BenchmarkPython: tab-indented `match` statements lost their case structure; 52.8 -> 56.1
- [x] Sinks the catalog does not recognise: the largest share of dev injection misses
  - [x] Java SSRF clients (RestClient/WebClient, RestTemplate, java.net.http, JAX-RS, Micronaut, jsoup, Apache): dev +15 labels, Java F3 8.8 -> 9.5. Follow-up: a value appended after a fixed host (`"http://internal/x/" + id`, a base-URL client's `uri("/api/" + id)`) is path, not SSRF; most of the 34 new unmatched findings are that shape
  - [x] Log injection (TAINT-013, #1168: request values reaching an application logger in Java, JS/TS and Python; CR/LF encoders neutralise; env/argv/system properties are not sources): dev +42 labels, none lost, F3 19.0 -> 19.5, injection recall 44.9% -> 47.8%. The unmatched are request data concatenated into log calls, CWE-117 as defined; 409 are debug/trace. Same PR: a caller's flow into a helper no longer stops at the helper's first sink (+1 label, 52 hidden findings surfaced). Follow-ups: Java `.execute` matches executors as SQL; argv/env as sources in CLI tools
  - [x] Java template injection (FreeMarker, Velocity, Handlebars) and expression injection (SpEL, OGNL, MVEL): dev +40 labels, none lost, Java F3 9.5 -> 11.4, injection recall 38.2% -> 41.4%. The 4 unmatched are real: 3 labelled CWE-917/95 where nox says CWE-94, 1 the evaluate step after a parse already reported. Not covered: Thymeleaf through a StringTemplateResolver, FreeMarker `getTemplate(name)`
  - [x] XXE, Java (DOM, SAX, StAX from a factory made in the file and never hardened) and Node (libxmljs `noent: true`, #1164): dev +8 labels, none lost, Java F3 11.4 -> 11.7, injection recall 41.4% -> 42.0%. The 1 unmatched is a real XXE on an HRIS message. Not covered: TransformerFactory, SchemaFactory/Validator, JAXB, dom4j, JDOM; Express upload bodies (`req.files`) are not sources; config-only labels with no untrusted document
  - [x] Template-file XSS (XSS-001, #1166: Jinja/Django/Nunjucks `|safe` and autoescape off, EJS `<%- %>`, JSF/Struts `escape="false"`, JSP request expressions): dev +37 labels, none lost, F3 18.3 -> 19.0, injection recall 42.0% -> 44.9%. 36 of the unmatched are raw output of stored or reflected data beside a labelled line. Not covered: Thymeleaf `th:utext`, Vue `v-html`
- [ ] Java recall: F3 a third to a half of the other languages'. 2026-11-24: Java dev F3 11.9 -> 16.5 (JS/TS 25.2, Python 25.1):
  - [x] Secret settings with a literal default in Spring/Compose config (APPCFG-007, #1169): +41 labels
  - [x] try-with-resources headers bound (#1170): +18 labels, deserialization and SQL behind a resource
  - [x] Open redirect sinks: Spring `"redirect:" + url`, RedirectView, JAX-RS, Micronaut; fixed-path targets excluded (#1171): +12
  - [x] Upload file names as sources, more `Files` sinks (#1172): +13
  - [x] Spring Security CSRF switched off or exempted (APPCFG-008): +14. Stateless token APIs stay reported at medium confidence; excluding `STATELESS` chains would drop labelled JWT apps
  - [ ] Remaining: authorization and business logic (M3), TransformerFactory/SchemaFactory XXE, Java `.execute` on executors read as SQL, `Files.copy(content, fixedPath)` read as path traversal
- [ ] Fastify `reply.send({ ... })` read as XSS: an object serialised as JSON

### M3 — remaining classes and languages

- [ ] Mass assignment where the framework states it: Django ModelForm fields='__all__', Spring entity binding, Mongoose create(req.body), Rails permit!, NestJS DTO without whitelist
- [ ] Authentication and session settings: CSRF protection disabled, session cookie flags, login routes without a rate limit where the framework has a standard limiter
  - [x] Login, OTP and token-reset routes without attempt limiting (AUTHN-002, CWE-307) and sign-up/reset-request routes without throttling (AUTHN-003, CWE-770), #1179: dev F3 22.2 -> 23.5, authentication/session recall 36 -> 108 of 527. Same PR: front-end `api.post(...)` calls no longer enter the route table
  - [x] CSRF switched off in Django and Flask (APPCFG-008 extended): `@csrf_exempt` on a state-changing session view, `CsrfViewMiddleware` removed, DRF `enforce_csrf` no-op, Flask-WTF exemptions; CWE-352 labels 14 -> 24
  - [x] CSRF on session-cookie POST routes in Flask and Express apps with no CSRF protection (AUTHN-004): dev +10 CWE-352 labels, F3 23.5 -> 23.7 on its own; the 18 unmatched are unprotected session POSTs in deliberately vulnerable apps
  - [ ] Remaining CSRF labels: state-changing GET routes (about 8)
  - [x] Account enumeration on login and reset paths (AUTHN-005, CWE-204): dev 16 of 83 labels; the 41 unmatched are the same answer on login/reset paths the labels do not mark, plus one login-event publication
  - [x] Clickjacking and session fixation switched off (APPCFG-009, CWE-1021; APPCFG-010, CWE-384): Spring frameOptions/headers disabled, X-Frame-Options ALLOWALL or removed, frame-ancestors *, helmet frameguard off, Django xframe_options_exempt; Spring sessionFixation none
- [x] Password hashing with too little work (CRYPTO-003, CWE-916): a fast digest of a password-named value, PBKDF2 under 10,000 iterations, bcrypt cost under 10. With APPCFG-009/010, from the dev Java misses: dev F3 26.9 -> 28.1, Java 18.9 -> 20.7, +64 labels, +60 unmatched (all read: real weak password hashing and framing switched off, mostly on embed routes), no finding of another rule lost
- [ ] Information exposure: stack traces and exception messages written to responses, debug endpoints enabled in production configuration
  - [x] Exception detail written into the HTTP response (ERRLEAK-001, CWE-209), JS/TS, Python, Java, #1182: dev F3 23.7 -> 25.1, information-exposure recall 18 -> 69 of 402
  - [x] Sensitive data written to logs (LOGLEAK-001, CWE-532): credentials, Authorization/cookie headers and whole request bodies in log calls, Django console mail backend, sqlite trace callbacks: dev F3 25.1 -> 26.4, CWE-532 labels 8 -> 80 of 137, information-exposure recall 69 -> 139 of 402
  - [x] Debug mode in production configuration (APPCFG-001 extended): Django DEBUG on by environment default, Tornado debug, Spring stack traces in error responses, all actuator endpoints exposed, H2 console, JSF Development stage: dev F3 26.4 -> 26.9, CWE-215 labels 10 -> 37 of 75
  - [ ] Remaining CWE-215: seeded "trace panel" views returning environment values (18, not generalisable without flagging version/health endpoints), devtools, show_sql, mail.debug
- [ ] Remaining languages onto tree-sitter (C#, PHP, Ruby, Go via the same front end or kept on go/ast, Kotlin, Scala, Swift, Rust, C/C++, and the rest), each behind the same A/B gate
  - A/B method for languages RealVuln does not cover (it holds Python, JavaScript/TypeScript, Java and Go): the same binary with `NOX_TAINT_TREESITTER=python,javascript,java` (the new front ends off) and by default (on), `nox scan --offline`, over pinned public repositories cloned at HEAD on 2026-11-26, findings keyed by rule, file and line, every added and dropped finding read in its source. `rule-diff-corpus.json` holds no C#, PHP, Ruby or Kotlin repository, so this corpus is new: PHP DVWA 502ac15, OWASP/Vulnerable-Web-Application c0f2689, Broken-Vulnerable-Code-Snippets 0766923, yeswehack/vulnerable-code-snippets 90c910e, snipe-it c424a81, WordPress 6ae3ef8, phpMyAdmin 3f93e4e; Ruby railsgoat f5951f1, brakeman fe761e5, lobsters 477e28b, mastodon 6c29cb4, forem 3dcba73; C# WebGoat.NET 1c6cab1, VulnerableCoreApp 1ae87f8, SimplyVulnerable 1c267b1, ContosoUniversity 5c4e4ec, eShop 3c6e531, nopCommerce 0344b61, OrchardCore fc98c30; Kotlin Forgo7ten/VulnerableApp 8a46101, Goatlin dc62113, InsecureShop b7db354, tut-spring-boot-kotlin 4b45a63, ktor-samples 17cc63e, spring-petclinic-kotlin 9823b3a, Exposed 2162b44, ktor 3bcd165. The four grammars are pinned and rebuilt byte-for-byte (`scripts/treesitter/build.sh --check`); 14.4 MB of modules added, see docs/benchmarks/2026-11-23-treesitter-budget
  - [x] C# on (tree_csharp.go): 7 repositories, 1,302 -> 1,304 findings, +2 / -0. Both added are TAINT-001 in WebGoat.NET's SQLiteProfileProvider.cs: `cmd.CommandText = "DELETE FROM " + TB + " WHERE ..." +\n GetClauseFor...()` built over three lines and executed on `cmd`, the shape the front end exists for. Unit tests fail on the line segmenter (SQL concatenated over lines, a call chain continued on the next line) and pass with the tree
  - [x] PHP on (tree_php.go, the `php` grammar): 7 repositories, 1,942 -> 1,947 findings, +5 / -0. DVWA bac/low.php and bac/medium.php TAINT-001: a multi-line `"INSERT ... {$ip}"` string with `$ip` from `X-Forwarded-For`, into `mysqli_query`, true; DVWA dvwaPage.inc.php TAINT-003 x2: `$pPage['body']` interpolated into a multi-line `echo`, true to DVWA's design; WordPress widgets-form.php:304 TAINT-003: `$sidebar` from POST passed through `checked()` into an `echo` over two lines, a false positive, but a precision gap and not a segmentation one: the same statement written on one line produces the same finding with the front end off
  - [x] Ruby on (tree_ruby.go), narrowed to a multi-line `binary` or `chained_string` expression: 5 repositories, 1,488 -> 1,489, +1 / -0. The one is brakeman's `test_user_input_on_multiline`, a `find_by_sql "..." +\n "...#{params[:unsafe]}"` the line segmenter lost, true. The first version joined whole statements as Java's does and stays rejected: +53 / -43 (forem +42 / -32, mastodon +5 / -6, lobsters +5 / -5, brakeman +1), of which 32 pairs were one finding moved to the first line of its method chain. Of the other 21 added, 20 were false positives (forem 19, mastodon 1: a tainted `ids` and an `Arel.sql("static string")` in one statement, `where(id: ids)` hash conditions, internal `redirect_to` paths, a backtick sink read from a regex) and one was brakeman's true positive; of the other 11 dropped, 5 were duplicates of a chain finding that remained, 2 moved lines and 4 were false positives (a hash key `redirect_to:` read as a sink, a backtick sink on a `}`, two same-named helpers matched across classes). A joined method chain reads every argument in the chain against every sink in it, which Ruby chains make common
  - [x] Kotlin on (tree_kotlin.go): 8 repositories, 610 -> 610, +0 / -0, no movement. The corpus holds no Kotlin SQL or command built across lines, so the A/B shows no harm and no gain; the gain is shown by the unit tests (SQL concatenated over lines, which the line segmenter splits). 152 of 4,018 Kotlin files (3.8%, most in Exposed) parse to an error tree and fall back to the line segmenter
  - [ ] Not measured: the corpus is small for C# and Kotlin. A Kotlin repository with SQL built across lines, and a C# one with dapper-style queries, would show more
  - [x] Scala, Swift and Rust pinned and embedded (C/C++ measured, not shipped): `tree-sitter-scala` v0.26.14, `alex-pinkus/tree-sitter-swift` 0.7.4 (the `-with-generated-files` tag), `tree-sitter-rust` v0.24.2, rebuilt byte-for-byte by `scripts/treesitter/build.sh --check`; +10.3 MB of modules (Scala 4.7, Swift 4.3, Rust 1.2). CPU cost: Signal-iOS, code-only scan, 151 s -> 279 s user with the Swift front end on (+85%), the parse speed measured for C# and Kotlin. Swift's scanner calls `exit(1)`, so `swift.wasm` also imports WASI `proc_exit`, answered by a host stub that ends the guest. Budgets and error-tree rates in docs/benchmarks/2026-11-23-treesitter-budget
  - [x] Scala, Swift and Rust on (tree_scala.go, tree_swift.go, tree_rust.go); C/C++ measured with `tree-sitter-cpp` v0.23.4 and not shipped, each narrowed to a multi-line binary expression (Scala `infix_expression`, Swift `additive_expression`, Rust and C++ `binary_expression`). Method of the first four languages, with `NOX_TAINT_TREESITTER` listing the seven languages already on (off) and those plus the new one (on), `nox scan --offline --only code`, findings keyed by rule, file, line and sink, over 30 repositories cloned shallow at HEAD on 2026-11-26: Scala gitbucket 5c65fd6, lila 8dec09d (its 1 GB `public/` assets deleted to save disk), playframework 4a843d6, slick 2354aff, scalatra 4d182cf, http4s 0d66508, scala-parser-combinators 82cf33d; Swift iGoat-Swift 8c8a8ed, DVIA-v2 96466ab, GRDB.swift 98c58f4, SQLite.swift fa0763a, vapor 170e682, fluent-kit 6f88442, Signal-iOS 4537228; Rust cargo 562527a, sqlx af2b683, diesel f354e06, actix-web 1eeec2c, axum 8d8944e, rustdesk a0c0963, nushell b1c0213, starship 9110d4b; C/C++ Damn_Vulnerable_C_Program 8dcbd20 (its 1 GB `libAFL/` deleted), redis a407a74, git acba8bf, curl d5ec024, busybox 371fe9f, mosquitto 7ae66ca, sqlite 915d9c4, pgbouncer 23347f6
    - Scala: 7 repositories, 50 -> 50, +0 / -0. The 300 lines in the corpus that end in a string and `+` (lila's HTML and chat-message building) reach no sink. The gain is shown by the unit tests (SQL concatenated over lines, a reassignment continued on the next line) and by a probe file: `val q = "SELECT ..." +\n id` then `st.executeQuery(q)` is found with the front end on and not off
    - Swift: 7 repositories, 47 -> 47, +0 / -0. The same probe finds `sqlite3_exec` on a query concatenated over two lines and a `removeItem(atPath:)` on a path concatenated over two lines, neither without the front end. 317 of 3,895 files (8.1%) parse to an error tree (Signal-iOS 237) and fall back
    - Rust: 8 repositories, 121 -> 121, +0 / -0. The probe finds a `sqlx::query(&q)` and a `Command::new("sh").arg("-c").arg(&c)` whose string is concatenated over two lines, neither without the front end. 537 of 5,875 files (9.1%) are error trees, 526 of them in cargo's `str![[r#"..."#]]` test expectations
    - C/C++: 8 repositories, 210 -> 210, +0 / -0. The probe finds a `system(c.c_str())` on a command concatenated over two lines, not without the front end. 2,335 of 4,902 files (47.6%) are error trees: 56% of `.c` files against 4% of `.cpp`, from preprocessor conditionals inside a statement and unknown macros. That is the weakest of the four: about half the C files would pay for the parse and get the line segmenter anyway, so the grammar (3.6 MB) was left out; `tree-sitter-c` for `.c` files is the thing to try
    - Narrowed from whole statements, as Ruby was. The first version joined whole statements as Java's does. Over Scala and part of Swift it moved nothing, so the corpus did not show the harm, but a probe file did: in Scala `val r = st\n .executeQuery("SELECT ...")\n .withLabel(id)` read the tainted `id` and called the sink `executeQuery` with a constant in one statement, a false positive; the same for Swift `fm.removeItem(atPath: "/tmp/x").label(id)`, Rust `sqlx::query("SELECT ...").label(&id)` and C++ `system("echo hi").then(id)`. A multi-line binary expression holds no call chain, and the probes find the concatenation shapes and none of the chains. The whole-statement results for Rust and C/C++ on the corpus were not measured
  - [x] C on (tree_c.go), `.c` files only, `tree-sitter-c` v0.24.2 (+0.7 MB). C has no method chains, so whole statements are joined, a declaration per declarator; a statement holding a block or an initializer list keeps the line segmenter. 1,859 of 3,500 `.c` files (53.1%) parse to an error tree, no better than `tree-sitter-cpp`'s 56%, but only 23 come back without a tree: a join is taken from any statement that holds no ERROR or MISSING node and lies inside no ERROR node, the rest of the file is segmented as before (ADR 0006 rule 3 amended 2026-11-27), so 99.3% of `.c` files get the tree's joins. A/B over the same eight repositories (git at acba8bf, the same commit): 211 -> 212, +1 / -0, the one added a TAINT-004 in git (`wrapper.c:188`, an environment value reaching `open` through `setup_git_directory_gently`) whose path rests on field-insensitive struct taint (`discovery.format.x = f(getenv(...))` taints `discovery`, and the prefix is read from `discovery.prefix`), exposed by a correct join; field-sensitive taint is a separate change. RealVuln dev has three `.c` files, unchanged. CPU: redis, code-only, 14.5 s -> 25.5 s user (+77%). The probe finds `system(cmd)` on `char *cmd =\n getenv(...)` and a helper `return\n getenv(...)`, neither without the front end; ten mutants of the guards are all killed
  - [ ] Go stays on go/ast: its extractor reads a real syntax tree already (the line recognizer is for the other languages), so tree-sitter would add a second parse of the same file for no segmentation gain. Not started and not planned
- [x] M3 gate: dev and held-out, OWASP Benchmark, published (2026-11-25, main b68bccf). F3 dev **26.9** (target 25, met), held-out **20.0** (not met), all 203 24.6. On Semgrep's repos nox scores 33.3 / 25.8 against Semgrep's 10.7 / 8.7. Held-out moved about 85% as far as dev, so the M3 classes generalise: auth/session recall 4.4% -> 20.1% and information exposure 0.9% -> 31.2% on held-out. OWASP Python 62.9, Java 56.4, against Semgrep p/default's 10.7 / 34.9. Open: OWASP Java 56.5 pooled against the best reproducible deterministic baseline, cognium-dev 73.5 (not met; CodeQL 59.9, FindSecBugs 39.1, docs/benchmarks/2026-09-28-owasp#published-deterministic-baselines-recorded-2026-11-26), Python has no reproducible baseline; remaining languages on tree-sitter not started; held-out Java 12.8. See docs/benchmarks/2026-11-21-realvuln/README.md#m3-gate-2026-11-25
- [x] OWASP Java above the best reproducible deterministic baseline: pooled 56.5 -> **81.5** (TPR 90.0, FPR 8.5) against cognium-dev 73.5, category-averaged 56.4 -> 79.7, at the documented `src/main/java` root. Response-writer `append`/`printf`/`format` sinks, HTML escapers as sanitizers (a decoder around one undoes it), `new Helper().run(...)` resolved to the file's own method so a constant-returning helper is a barrier (and a same-named method on another type no longer is), and CRYPTO-001 reading named and configured algorithms. RealVuln dev: 0 TP change, dev F3 28.4 unchanged; +16 CRYPTO-001 (DES key factories, bare "AES", MD5 of access codes; Broadleaf cache-key MD5s), -2 TAINT-003 behind `Encode.forHtmlAttribute`. OWASP Python unchanged (62.9). docs/benchmarks/2026-09-28-owasp#java-recall-and-helper-precision-2026-11-26
