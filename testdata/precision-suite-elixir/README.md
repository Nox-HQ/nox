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
| **Recall** | **0.86** |
| **F1** | **0.92** |
| TP / FP / FN | 12 / 0 / 2 |
| findings-per-issue | 0.86 |

Per rule: TAINT-001 (SQLi) 1/1, TAINT-002 (cmd injection) 3/4, TAINT-004 (path
traversal) 3/4, TAINT-005 (code injection / deserialization) 2/2, TAINT-006
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

## Why Elixir recall is below 1.0 (the honest false negatives)

Elixir's two dominant dataflow idioms — the **pipe operator** `|>` and
**pattern matching** — are exactly the constructs a flat, per-line recognizer
cannot follow without becoming an Elixir interpreter (which nox deliberately is
not: pure-Go, no CGo, no dependency). The two annotated false negatives make
this measurable rather than hand-waved:

1. **Multi-stage pipe** (`tp_cmdinjection.exs` `run_piped/1`):
   `conn.params["cmd"] |> String.trim() |> :os.cmd()`. nox's pipe desugaring is
   per-line and best-effort — it rewrites `x |> f(args)` to `f(x, args)`, binding
   the value into the **first** pipe stage only. A value sunk two-or-more hops
   downstream is missed. A correct scanner fires TAINT-002 here; nox does not.

2. **Destructuring pattern match** (`tp_pathtraversal.exs`
   `read_destructured/1`): `%{"file" => path} = conn.params`. nox binds only a
   **simple-ident** LHS (`x = expr`), so a map / tuple / list destructuring match
   never marks the extracted variable tainted. A correct scanner fires TAINT-004;
   nox does not.

These are **not** bugs to be "fixed by editing the samples" — they are the honest
boundary of a deterministic line/statement recognizer, and precisely the territory
where the cross-file taint-analysis plugin (with a real dataflow graph) takes over.
Both false negatives are held in the committed `baseline.json`, so they cannot be
silently hidden, and if the recognizer later learns to follow multi-stage pipes or
destructuring binds, the ratchet test reports the improvement and asks for a
baseline refresh.

## The ratchet

`cli`'s `TestPrecisionSuiteBaselineElixir` scans this corpus, compares against
`baseline.json`, and fails if any gated metric regresses (precision / recall / F1
drop, or FP / findings-per-issue rise). CI additionally enforces a hard
`--min-precision 0.90` floor via the "SAST precision gate — elixir" step, so
Elixir taint precision can never silently rot even as recall stays honestly below
1.0.
