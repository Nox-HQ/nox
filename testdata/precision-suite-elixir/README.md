# SAST precision suite — Elixir (honest measurement corpus)

This is the dedicated honest-measurement corpus for nox's **Elixir** taint model
(`lexctx` `scan_elixir` + engine `extract_elixir` + the catalog `elixir` block).
Like the other `precision-suite-*` corpora it measures nox against **ground
truth** — what a *correct* scanner should do — so real false negatives surface
as a number below 1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-elixir
nox bench --precision testdata/precision-suite-elixir --baseline testdata/precision-suite-elixir/baseline.json
```

## Measured result

As committed, `nox bench --precision testdata/precision-suite-elixir` scores:

| Metric | Value |
| --- | --- |
| **Precision** | **1.00** (0 false positives) |
| **Recall** | **1.00** |
| **F1** | **1.00** |
| TP / FP / FN | 14 / 0 / 0 |
| findings-per-issue | 1.00 |

Per rule: TAINT-001 (SQLi) 1/1, TAINT-002 (cmd injection) 4/4, TAINT-004 (path
traversal) 4/4, TAINT-005 (code injection / deserialization) 2/2, TAINT-006
(SSRF) 3/3. **Precision is 1.00** — every finding nox emits is a true positive,
and all four clean stressors fire nothing.

## What the true positives cover

Each `tp_*.exs` sample is idiomatic Elixir where an untrusted Phoenix/Plug
request value (`conn.params` / `conn.query_params` / `conn.body_params`) reaches
a dangerous call unsanitized, annotated with `nox-expect: TAINT-00X` on the sink
line:

- **tp_cmdinjection.exs** — `System.cmd("sh", ["-c", cmd])`, `:os.cmd/1`,
  `Port.open` (TAINT-002).
- **tp_codeinjection.exs** — `Code.eval_string` and `:erlang.binary_to_term`
  (TAINT-005; the latter is unsafe deserialization, CWE-502).
- **tp_sqli.exs** — a tainted value interpolated into a raw Ecto SQL string
  passed to `Repo.query` (TAINT-001).
- **tp_pathtraversal.exs** — `File.read` / `File.open` / `File.stream!` of a
  tainted path (TAINT-004).
- **tp_ssrf.exs** — `HTTPoison.get` / `:httpc.request` / `Req.get` of a tainted
  URL (TAINT-006).

## What the clean stressors cover

The four `clean_*.exs` files are the precision guardrail — a finding on any line
is a false positive:

- **clean_validated.exs** — a **parameterized** Ecto query
  (`Repo.query("... $1", [id])`, the tainted value in the bind list, not the SQL
  string), `String.to_integer` coercion, and `Path.basename` containment. Each
  neutralizes the tainted value before the sink.
- **clean_placeholders.exs** — placeholder config, prose mentioning dangerous
  idioms in **comments** (not executable code), and a **constant** `System.cmd`
  with no tainted input.
- **clean_datablob.exs** — large base64 / `data:` URI payloads inside `"""` and
  `'''` heredocs; `lexctx` marks these as data blobs so a pattern that fires
  inside them is suppressed.
- **clean_generated.exs** — a machine-generated banner, constant lookup tables,
  and a constant fixture `File.read` — no untrusted input anywhere.

## Elixir's two dominant idioms are both modeled now

The **pipe operator** `|>` is followed to the end of the chain, and **pattern
matching** now binds destructured names.

### Closed: destructuring pattern match (`tp_pathtraversal.exs` `read_destructured/1`)

`%{"file" => path} = conn.params` bound nothing: only a **simple-ident** LHS
(`x = expr`) was tracked, so a map / tuple / list match never marked the
extracted variable tainted. A destructuring LHS now emits one binding statement
per extracted name, carrying the RHS's source evidence — `%{"file" => path}`,
`%{query: q}`, `{:ok, body}` and `[head | tail]` all bind. A name is in binding
position when it is neither an atom (`:ok`) nor a keyword key (`query:`); module
aliases and `_` are skipped.

A 1.0 means this corpus has stopped indicting anything, not that Elixir dataflow
is solved. The limits below are real and simply lack a failing sample.

### Closed: multi-stage pipe (`tp_cmdinjection.exs` `run_piped/1`)

`conn.params["cmd"] |> String.trim() |> :os.cmd()` used to be a documented FN:
desugaring rewrote `x |> f(args)` into `f(x, args)` **once**, binding the value
into the first stage only, so a sink two-or-more hops downstream was missed.

Two defects were behind it, and both are fixed:

- the rewrite is now applied **to fixpoint**. Each pass peels the leftmost `|>`
  (`a |> f() |> g()` → `f(a) |> g()`), so iterating nests the whole chain into
  `g(f(a))` and the value reaches the final stage. Each pass strictly removes one
  pipe, so it terminates.
- `leadingCallHead` rejected any head whose first segment was in the SHARED
  keyword set, which carries Dart's built-in type names — including `String`,
  `Map`, `List`, `Set`, `Stream`, `Object`. Those are Elixir's core modules, so
  `String.trim()` was not recognized as a call head at all and the chain could
  not be walked. The keyword check now applies only to a **bare** head: no
  language writes `return.foo()`, so a dotted chain is a call on a module that
  merely shares a keyword's name.

That second defect was not Elixir-specific. `leadingCallHead` is shared by the
Elixir and Ruby extractors, so Ruby lost the same heads (`String.new`,
`Set.new`, `Hash.new`) — Ruby's suite happens not to exercise one, so its
numbers are unchanged, but the recognizer is correct for it now too. The
lesson is the one the keyword set's own comment already warns about: putting a
language's built-in TYPE names into a set shared across languages silently
suppresses real call heads elsewhere.

The remaining false negative is **not** a bug to be "fixed by editing the
samples" — it is the honest boundary of a deterministic line/statement
recognizer, and precisely the territory where the cross-file taint-analysis
plugin (with a real dataflow graph) takes over. It is held in the committed
`baseline.json`, so it cannot be silently hidden, and if the recognizer later
learns destructuring binds, the ratchet test reports the improvement and asks
for a baseline refresh.

## The ratchet

`cli`'s `TestPrecisionSuiteBaselineElixir` scans this corpus, compares against
`baseline.json`, and fails if any gated metric regresses (precision / recall / F1
drop, or FP / findings-per-issue rise). CI additionally enforces a hard
`--min-precision 0.90` floor via the "SAST precision gate — elixir" step, so
Elixir taint precision can never silently rot even as recall stays honestly below
1.0.
