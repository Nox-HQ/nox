# SAST precision suite — C/C++

A dedicated **honest measurement corpus** for nox's C/C++ taint support,
mirroring `testdata/precision-suite/` but scoped to C and C++ files
(`.c`/`.h` and `.cc`/`.cpp`/`.cxx`/`.hpp`/`.hh`). Like that suite (and unlike
`testdata/precision-corpus/`, a curated fixture pinned at a perfect 1.0), this
corpus is built to **measure nox against ground truth** — a *correct* scanner's
expected behavior — so real false negatives surface as a number below 1.0. A
corpus that always scores 1.0 measures nothing.

One module serves both C and C++ (`core/lexctx/scan_cpp.go`,
`core/taint/engine/extract_cpp.go`, and the catalog `cpp` block) because the two
share comment/string lexing and the dangerous-API surface modeled here.

Run it:

```
nox bench --precision testdata/precision-suite-cpp
nox bench --precision testdata/precision-suite-cpp --json
nox bench --precision testdata/precision-suite-cpp --baseline testdata/precision-suite-cpp/baseline.json
```

## Scope: injection-class taint only — memory safety is OUT OF SCOPE

nox's C/C++ support covers the **injection classes a source→sink taint engine can
soundly represent**:

- **command injection** (CWE-78) — `system` / `popen` / `exec*`
- **path traversal** (CWE-22) — `fopen` / `open` / `std::ifstream`
- **format string** (CWE-134) — a tainted **format** argument to `printf`
- **SSRF** (CWE-918) — a tainted URL to `curl_easy_setopt(CURLOPT_URL, …)`
- **SQL injection** (CWE-89) — a tainted, concatenated query to `mysql_query` /
  `PQexec`

The classic C/C++ **memory-safety** bugs — buffer overflow (`strcpy`/`strcat`/
`sprintf`/`gets` → CWE-120/CWE-787), use-after-free, and out-of-bounds
read/write — are a **fundamentally different analysis** than source→sink taint.
Detecting them soundly needs buffer-bounds tracking, lifetime/ownership analysis,
and points-to reasoning that a taint dataflow engine does not perform, and
forcing them into the taint model would only produce noise. They are therefore
**explicitly out of scope for this engine** and are a candidate for a separate
future memory-safety analysis. (This corpus does use `strcpy`/`strcat`/`snprintf`
as *taint carriers* — they build a command/query buffer from untrusted input —
but nox flags the resulting **injection**, never the overflow.)

## Measured baseline (as of writing)

```
RULE       TP  FP  FN  PRECISION  RECALL  F1
TAINT-001  1   0   0   1.000      1.000   1.000
TAINT-002  2   0   0   1.000      1.000   1.000
TAINT-004  1   0   1   1.000      0.500   0.667
TAINT-005  1   0   0   1.000      1.000   1.000
TAINT-006  1   0   0   1.000      1.000   1.000
OVERALL    7   0   0   1.000      1.000   1.000
```

**Precision 1.00 / recall 1.00 / F1 1.00** (7 TP, 0 FP, 0 FN). Precision is
perfect — every finding nox emits on this corpus is a true positive, and no
`clean_*` sample false-positives. Recall reached 1.00 by closing the std::ifstream in(path)` constructor-declaration gap the corpus indicted, not by deleting the sample. A 1.0 means this corpus has stopped indicting anything; the structural limits below are real and simply lack a failing sample. Previously **0.857** —
see the documented FN below.

## Ground-truth philosophy

- **Clean samples** (`clean_*.c` / `clean_*.cpp`) carry **no** `nox-expect`
  annotation: any finding on them is a false positive. They deliberately contain
  the noise broad rules trip on — a base64 data-URI in a C++11 raw string,
  `.env`-style placeholder credentials, a `@generated`-style banner — alongside
  the *safe* forms of the same sinks (fixed-format `printf`, `atoi`-coerced
  input, `realpath`-canonicalized paths, a parameterized prepared statement).
- **True-positive samples** (`tp_*.c` / `tp_*.cpp`) annotate, per line, the rule a
  correct scanner *should* fire. Where nox fires *more* those extras score as
  false positives; where it fires *nothing* the annotation scores as a false
  negative.

## What's caught (true positives)

Each fires from a catalog **source** (`getenv` / `fgets`, standing in for any
untrusted input) reaching a **sink** with no sanitizer on the path:

| Sample | Class | Rule | Sink idiom |
|---|---|---|---|
| `tp_cmdinjection.c` | command injection | TAINT-002 | `system(strcat(cmd, getenv(…)))` |
| `tp_cmdinjection_popen.c` | command injection | TAINT-002 | `popen(snprintf(cmd, …, fgets(…)))` |
| `tp_pathtraversal.c` | path traversal | TAINT-004 | `fopen(getenv("REPORT_PATH"), "r")` |
| `tp_sqlinjection.c` | SQL injection | TAINT-001 | `mysql_query(db, snprintf(q, …, getenv("USER_ID")))` |
| `tp_formatstring.c` | format string | TAINT-005 | `printf(getenv("MESSAGE"))` (tainted **format**) |
| `tp_ssrf.c` | SSRF | TAINT-006 | `curl_easy_setopt(h, CURLOPT_URL, getenv("AVATAR_URL"))` |

The `clean_*` counterparts prove each is suppressed when made safe:
`clean_fixed_format.c` (`printf("%s", user)` — fixed format), `clean_parse_int.c`
(`atoi` numeric coercion), `clean_realpath.c` (`realpath` canonicalization),
`clean_safe_sql.c` (prepared statement + bound parameter), plus `clean_no_source.c`
(constant-only sinks), `clean_placeholders.c` (placeholder creds), and
`clean_data_blob.cpp` (base64 blob in a raw string).

### The format-string precision guardrail

The single most important precision distinction for C/C++ is the format-string
sink. `printf(user)` — a **tainted format** — is the vulnerability (an attacker's
`%n`/`%s` reads/writes memory), while `printf("%s", user)` — a **fixed format**
with a tainted value — is **safe** and must not fire. nox models this by gating
the `printf`/`vprintf` sink on the **first** argument (the format) being tainted:
a string-literal format leaves `FirstArgTainted` false and is suppressed. The
`tp_formatstring.c` / `clean_fixed_format.c` pair pins both directions. (CWE-134
has no dedicated vuln class in the catalog, so the sink is keyed to the
`TAINT-005` rule id with CWE-134 recorded in the sink note.)

## The honest gap (false negative) — C++ constructor-init path traversal

`tp_pathtraversal_ifstream.cpp` is a **labeled FN**: a genuine path-traversal bug
nox's C/C++ model does **not** catch. It is kept in the corpus, not deleted —
inflating recall by removing a hard TP would defeat the point of an honest
measurement suite.

The idiom is the C++ **declaration-with-constructor-initializer**
`std::ifstream in(path);`. The line recognizer cannot tell this construction of a
sink object from an ordinary declaration `Type name(args)`: it reads `in(path)`
as a call to a variable `in`, not as the `ifstream` sink, so the flow does not
fire. The **functional-cast** form `std::ifstream(path)` (no binding name) *is*
caught, because there the callee is `ifstream`. Closing the `Type var(args)` case
needs distinguishing a known-sink type constructor from a plain call — future
work, not a curation trick.

## Why C/C++ recall is structurally coarse (recognizer, not a parser)

nox's C/C++ extractor (`core/taint/engine/extract_cpp.go`) is a **line/statement
recognizer**, not a real parser — only Go gets `go/ast`. That, plus C/C++'s
pointer and out-parameter idioms, makes recognition coarse in ways that cost
recall:

- **Out-parameters & pointers.** C writes results into caller buffers rather than
  returning them — `fgets(buf, …)`, `strcat(dst, src)`, `snprintf(dst, …)`. The
  extractor models the *common* buffer-writing builders and input sources
  explicitly (it treats the destination buffer as assigned from the other
  arguments, which is why the `strcat`/`snprintf` TPs fire), but an out-parameter
  written by an *unmodeled* function, or aliased through a second pointer, is not
  tracked.
- **Construction ambiguity.** `Type var(args)` (construction) is
  indistinguishable from `func(args)` (call) without type information — the
  `std::ifstream` FN above.
- **Macro-expanded sinks.** A sink hidden inside a macro expansion is matched only
  by its surface call name; a value that becomes dangerous only after expansion is
  missed.
- **Memory safety.** Out of scope entirely — see the scope section above.

These are the same "recognizer, not a parser" limits documented for the other
non-Go languages, specialized to C/C++'s pointer/out-parameter surface — which is
why recall sits below 1.0 and why the FN above is honest rather than a bug to
paper over.

## Regeneration

The committed `baseline.json` is the ratchet enforced by
`TestPrecisionSuiteBaselineCPP` (in `cli/`) and by the CI "SAST precision gate —
cpp" step. If a legitimate improvement lands (an FN closed, a sink added), refresh
it:

```
rm testdata/precision-suite-cpp/baseline.json
nox bench --precision testdata/precision-suite-cpp --baseline testdata/precision-suite-cpp/baseline.json
```
