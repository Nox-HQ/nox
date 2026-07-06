# SAST precision suite — Lua (honest measurement corpus)

This corpus measures nox's **Lua** taint model against ground truth — what a
*correct* scanner should do — so real false positives and false negatives surface
as a number. A corpus that always scores 1.0 measures nothing; this one is built
to be honest, not to flatter.

It exercises the Lua taint path end to end: `lexctx` `scan_lua` (classifies
`--`/`--[[…]]` comments and `"…"`/`[[…]]` long strings), the engine's
`extract_lua` line/statement recognizer (function headers, `local`/plain
assignments, `obj:method()` method calls normalized to `obj.method`, returns), and
the catalog `lua` block (`core/taint/data/catalog.json`).

Run it:

```
nox bench --precision testdata/precision-suite-lua
nox bench --precision testdata/precision-suite-lua --baseline testdata/precision-suite-lua/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.lua`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI inside a Lua long string, a leveled `[==[ … ]==]`
  long string whose inner `]]` must not close it, placeholder/example credentials,
  a `DO NOT EDIT` generated banner with UUID/git-SHA/hex-color constants, a
  dangerous call quoted in a comment, and the SAFE (sanitized/constant) forms of
  every tp_ flow.
- **True-positive samples** (`tp_*.lua`) annotate, per line, the rule a correct
  scanner *should* fire. Over-firing scores as a false positive; a recall gap
  scores as a false negative.

## What this corpus currently reveals

`nox bench --precision testdata/precision-suite-lua` scores **precision 1.00 /
recall 1.00 / F1 1.00** (11 TP, 0 FP, 0 FN). Every Lua injection class the corpus
annotates fires exactly once, and all four clean stressors fire nothing — the
long-string data blob and leveled long string are classified as string data (not
code), the placeholders hit the example-credential allowlist, the generated
banner and comment-quoted sink are non-code, and every sanitized/constant flow is
correctly suppressed.

The number can only move the right way without a human refreshing the snapshot:
`TestPrecisionSuiteBaselineLua` (in `cli/`) fails if precision/recall/F1 drops or
FP / findings-per-issue rises, and CI enforces a blunt `--min-precision 0.90`
floor. When a rule fix legitimately improves the score, the test tells you to
refresh `baseline.json` — the honest way to raise the number is to fix the rules
the corpus indicts, never to curate the corpus to pass.

## Sample inventory

True positives (annotated ground truth):

| File | What it exercises | Correct rule | CWE |
| --- | --- | --- | --- |
| `tp_cmdinjection.lua` | `os.execute` / `io.popen` of `arg` / env / stdin | TAINT-002 | CWE-78 |
| `tp_codeinjection.lua` | `loadstring` / `load` of a tainted chunk | TAINT-005 | CWE-95 |
| `tp_pathtraversal.lua` | `io.open` of a tainted path | TAINT-004 | CWE-22 |
| `tp_sqlinjection.lua` | `conn:execute` / `db:exec` with an interpolated request value | TAINT-001 | CWE-89 |
| `tp_ssrf.lua` | `http.request` / `httpc:request_uri` of a tainted URL | TAINT-006 | CWE-918 |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_safe.lua` | `tonumber`-coerced values, constant commands/paths, `ngx.quote_sql_str`, non-sink use | clean |
| `clean_placeholders.lua` | placeholder / example credentials + `os.getenv` | clean |
| `clean_datablob.lua` | base64 data-URI in a `[[…]]` long string, leveled `[==[…]==]` template | clean (long-string blob gating) |
| `clean_generated.lua` | `DO NOT EDIT` banner, UUID / git-SHA / hex-color constants, comment-quoted sink | clean |

## Honest limits (the next indictment when a sample lands)

The Lua model is the flat line/statement recognizer (no CGo interpreter), so it
shares the recognizer's documented boundaries:

- **Intraprocedural + straight-line only.** A source in one function and a sink in
  another are not joined; a taint laundered through a table field or an untracked
  wrapper is lost. (Cross-file flow is the taint-analysis plugin's territory.)
- **Table-value taint is not key-precise.** A value stored in one table slot and
  read from another is not tracked element-by-element.
- **Metatable / dynamic dispatch.** A sink reached through `setmetatable`
  indirection or a dynamically-built method name is missed — the recognizer keys
  on the literal `obj.method` / `obj:method` chain.

When a realistic sample exercises one of these, it will land as an honest false
negative and the number will tell the truth — the measure → build → re-measure
loop, running on Lua.
