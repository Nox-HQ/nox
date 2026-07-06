# SAST precision suite — Clojure (honest measurement corpus)

Like the sibling language suites, this corpus measures nox against **ground
truth** — what a *correct* scanner should do — so real false positives and false
negatives surface as a number below 1.0. A corpus that always scores 1.0 measures
nothing.

Run it:

```
nox bench --precision testdata/precision-suite-clojure
nox bench --precision testdata/precision-suite-clojure --baseline testdata/precision-suite-clojure/baseline.json
```

## Why Clojure has the LOWEST recall of any supported language

Clojure is a **Lisp**. A program is prefix s-expressions — `(fn arg1 arg2)`,
`(def x v)`, `(let [x v] body)` — with no `lhs = expr` assignments and no
`callee(args)` call syntax. Every other nox language is recognized by a
line/statement recognizer built around exactly those two shapes; Clojure is the
furthest of any language from that model.

Rather than reach for a full reader/evaluator (which would mean CGo or a heavy
dependency — both refused; nox ships a single pure-Go static binary), the Clojure
taint model uses a **paren-aware FORM recognizer** (`core/taint/engine/extract_clojure.go`)
that walks the balanced s-expression tree emitted over the lexctx code mask and
recognizes the two injection-carrying shapes that map cleanly onto the shared IR:

- a **binding** — `(def NAME expr)`, and each name/expr pair of `(let [NAME expr …])`
  / `(binding […])` / `(loop …)` / `(when-let …)` — where NAME is the assignee and
  `expr` is the RHS whose source/reads propagate; and
- a **call** — `(CALLEE args…)` — where the head symbol is the callee and the
  argument forms are the reads. `(defn name [params] body)` / `(fn …)` open their
  own unit with positional parameter names.

Ring request access `(:params req)` / `(:query-string req)` — a keyword used as a
function on the request map — is recognized as a source (the keyword head is the
source marker, the map argument a read).

This catches idiomatic straight-line flows, but it **cannot** follow the
constructs a Lisp uses to reorder or indirect argument position, which is exactly
where the honest false negatives live (see below).

## What this corpus currently reveals

As of writing, `nox bench --precision testdata/precision-suite-clojure` scores
**precision 1.00 / recall 0.77 / F1 0.87** (10 TP, 0 FP, 3 FN). Precision is
perfect — every finding nox emits is a true positive, and every clean stressor
(parameterized jdbc vector, `Integer/parseInt` coercion, placeholder creds,
data-URI blob, generated banner) fires nothing — while recall is the lowest of any
language, held down by three honest false negatives in threading-macro and
higher-order forms the recognizer cannot follow.

That gap is **honest, not curated**: the FN samples are annotated as the true
positives a correct scanner should fire, so the number tells the truth. The way to
raise it is to build the engine (a threading-macro desugarer, HOF modeling), never
to delete the samples.

## Sample inventory

True positives — the idiomatic straight-line flows nox **does** catch:

| File | What it exercises | Rule | nox today |
| --- | --- | --- | --- |
| `tp_cmdinjection.clj` | `(shell/sh "sh" "-c" (:params req))` | TAINT-002 ×2 | TP ×2 |
| `tp_codeinjection.clj` | `(eval …)` / `(load-string …)` of a request value | TAINT-005 ×2 | TP ×2 |
| `tp_sqlinjection.clj` | `(jdbc/query db (str "… " id))` string concat | TAINT-001 ×2 | TP ×2 |
| `tp_pathtraversal.clj` | `(slurp …)` / `(io/reader …)` of a tainted path | TAINT-004 ×2 | TP ×2 |
| `tp_ssrf.clj` | `(client/get …)` / `(client/post …)` of a tainted URL | TAINT-006 ×2 | TP ×2 |

True positives that are honest **false negatives** (annotated ground truth nox is
expected to MISS — the Lisp recall gap):

| File (line) | What flows | Rule | nox today | Why it is missed |
| --- | --- | --- | --- | --- |
| `tp_threading.clj` — `run-threaded` | `(:params req)` threaded via `->`/`->>` into `shell/sh` | TAINT-002 | **FN** | threading macros reorder the value's argument position; the positional recognizer sees `sh` called with only literal args |
| `tp_threading.clj` — `run-apply` | tainted seq spread into `sh` via `apply` | TAINT-002 | **FN** | the call head is `apply`, not `shell/sh`; the sink is reached indirectly |
| `tp_threading.clj` — `fetch-all` | `map client/get` over tainted URLs | TAINT-006 | **FN** | the sink is a HOF argument, never a literal call head |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_safe_db.clj` | parameterized `["… ?" v]` jdbc vector, `Integer/parseInt` coercion, constant command | clean |
| `clean_validated.clj` | tainted value only logged / in a response map, `parse-long` + arithmetic | clean |
| `clean_placeholders.clj` | placeholder creds (`your-api-key-here`, `changeme`, `sk_test_…`), `System/getenv` reads | clean |
| `clean_datablob.clj` | base64 data-URI SVG, git SHA, UUID, hex color, SRI integrity hash | clean (blob gating) |
| `clean_prose.clj` | `DO NOT EDIT` banner, sinks quoted in comments, inert opcode data | clean |

## Honest limits — the next indictment when a sample lands

- **Threading macros** (`->`, `->>`, `as->`, `some->`, `cond->`) rewrite argument
  position at read time; the recognizer does not desugar them, so a value threaded
  into a sink is missed. This is the dominant recall gap.
- **Higher-order dispatch** — `apply`, `map`, `partial`, `comp`, `reduce` — passes
  the sink or the tainted value as data, so the sink never appears as a literal
  call head.
- **Destructuring binds** — `{:keys [a b]}`, `[x & xs]` — are not tracked; only a
  bare-symbol binding target taints. A value bound through destructuring is lost.
- **`slurp` of a URL** is SSRF, not path traversal, but the recognizer cannot tell
  a path from a URL at the string level, so `slurp` is modeled as path traversal
  only (an SSRF-via-`slurp` flow is a documented FN).
- **Cross-function / cross-namespace flow** is the taint-analysis plugin's
  territory; this model is intraprocedural + same-file interprocedural via function
  summaries, like every other language.

Precision is defended throughout: the sinks fire only when a tracked binding
actually carries a source, and the parameterized jdbc vector keeps the value out of
the SQL-string argument, so `clean_safe_db.clj` stays clean. The `--min-precision
0.90` CI gate and the committed `baseline.json` ratchet ensure the wide, honest
recall gap can never be hidden and no new Clojure false positive can creep in.
