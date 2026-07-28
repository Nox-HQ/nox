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
**precision 1.00 / recall 0.81 / F1 0.90** (13 TP, 0 FP, 3 FN). Precision is
perfect — every finding nox emits is a true positive, and every clean stressor
(parameterized jdbc vector, `Integer/parseInt` coercion, placeholder creds,
data-URI blob, generated banner) fires nothing — while recall is the lowest of any
language. The last gap — the threading-macro form — is now closed, alongside the
two higher-order-dispatch gaps (`apply`, `map`).

Recall is deliberately BELOW 1.0 again. It reached 1.0 when the threading model
landed, at which point the corpus could only catch regressions — so
`tp_hof_construction.clj` was added, pinning three real misses. `apply` and `map`
DISPATCH a function and are modeled; `partial` and `comp` instead BUILD one, and
`as->` renames the threaded value, so in all three the sink is a value rather
than a call head the recognizer tracks. The drop from 1.00 to 0.81 is the corpus
getting harder, not the engine getting worse: precision is still 1.000 with zero
false positives. `clean_threading.clj` was added as the guard: threading
is THE idiomatic Clojure shape, so modeling it is exactly where an engine risks
inventing noise, and that sample asserts silence across `->`, `->>`, `some->`
and `cond->` chains over constants, coerced numbers and pure data transforms.
It matters more than usual here because no large real-world Clojure corpus was
available to validate against — the guard is a corpus one.

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
| `tp_threading.clj` — `run-threaded` | `(:params req)` threaded via `->`/`->>` into `shell/sh` | TAINT-002 | **caught** | the threaded value is modeled as a synthetic binding each stage reads and rebinds |
| `tp_threading.clj` — `run-apply` | tainted seq spread into `sh` via `apply` | TAINT-002 | **caught** | the statement is re-attributed to the dispatched symbol |
| `tp_threading.clj` — `fetch-all` | `map client/get` over tainted URLs | TAINT-006 | **caught** | same re-attribution |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_safe_db.clj` | parameterized `["… ?" v]` jdbc vector, `Integer/parseInt` coercion, constant command | clean |
| `clean_validated.clj` | tainted value only logged / in a response map, `parse-long` + arithmetic | clean |
| `clean_placeholders.clj` | placeholder creds (`your-api-key-here`, `changeme`, `sk_test_…`), `System/getenv` reads | clean |
| `clean_datablob.clj` | base64 data-URI SVG, git SHA, UUID, hex color, SRI integrity hash | clean (blob gating) |
| `clean_prose.clj` | `DO NOT EDIT` banner, sinks quoted in comments, inert opcode data | clean |

## Honest limits — the next indictment when a sample lands

- **Threading macros — CLOSED.** `->`, `->>`, `some->`, `some->>`, `cond->` and
  `cond->>` rewrite argument position at read time, so a threaded value never
  appears as a literal argument of the sink. The value is now modeled as a
  synthetic BINDING that each stage reads and rebinds: the engine taints a
  variable at its binding and reports a sink that reads one, so carrying the
  evidence alone was not enough — the value had to have a name. Rebinding per
  stage means the value keeps flowing AND a sanitizing stage correctly clears it.
  A nested threading form used as a stage (`(-> x (->> (sh …)))`, how `->` and
  `->>` are mixed) re-threads the same value.

  Deliberate simplification: this tracks WHAT flows, not into WHICH argument
  slot. `->` prepends and `->>` appends, but for taint the question is whether
  the value reaches the sink at all, and both do. A position-sensitive argument
  note (the parameterized-jdbc vector check) therefore does not apply to a
  threaded stage. `as->` is not handled: it names its own binding.
- **Higher-order dispatch — CLOSED for the dispatcher family.** `apply`, `map`,
  `mapv`, `pmap`, `mapcat`, `keep`, `filter`, `remove`, `some`, `every?` and
  `run!` take the function to invoke as their FIRST argument, so a sink reached
  through them was never a literal call head. The statement is now re-attributed
  to the dispatched SYMBOL and the remaining arguments scored against it. Only a
  bare symbol is re-attributed — an inline `#(...)`/`fn` literal has no name to
  attribute the flow to and leaves the dispatcher as callee. `partial` and `comp`
  build a function rather than invoking one and are still not modeled.
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
