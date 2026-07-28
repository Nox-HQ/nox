# SAST precision suite — PowerShell (honest measurement corpus)

Like the top-level `testdata/precision-suite/` corpus, this is an **honest**
measurement corpus: it measures nox's PowerShell taint model against ground truth
so real false positives and false negatives surface as a number below 1.0. A
corpus engineered to always score 1.0 measures nothing.

The corpus lives in its own directory so the PowerShell language block (lexctx
`scan_powershell.go` + engine `extract_powershell.go` / `extract_powershell_shape.go`
+ the catalog `powershell` block) is measured against PowerShell-only ground
truth and gated by its own baseline, independent of the other languages.

Run it:

```
nox bench --precision testdata/precision-suite-powershell
nox bench --precision testdata/precision-suite-powershell --json
nox bench --precision testdata/precision-suite-powershell --baseline testdata/precision-suite-powershell/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.ps1`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise that
  broad rules trip on — placeholder credentials, a base64 data-URI blob in a
  here-string, a `DO NOT EDIT` generated banner with a git SHA, and safe
  (parameterized / cast-coerced / validated) code.
- **True-positive samples** (`tp_*.ps1`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* those extra findings score as
  false positives; where it fires *nothing* the annotation scores as a false
  negative (a recall gap).

## What this corpus reveals

As of writing, `nox bench --precision testdata/precision-suite-powershell` scores
**precision 1.00 / recall 1.00 / F1 1.00** (8 TP, 0 FP, 0 FN).

Precision is perfect — every finding nox emits on this corpus is a true positive,
and every clean stressor fires nothing. Recall reached 1.0 the way the corpus
always demanded: by fixing the recognizer the corpus indicted (pipeline
dataflow), not by deleting the failing sample. `tp_pipeline_fn.ps1` is retained
as a regression test for exactly that flow.

A 1.0 here means this corpus has stopped measuring — it no longer indicts
anything. The open limits below (`-match` semantics, receiver typing)
are real and simply lack a sample; adding one that fails is the way to keep the
number honest.

### Sample inventory

True positives (annotated ground truth):

| File | Vuln class | Sink (idiomatic PowerShell) | Correct rule | nox today |
| --- | --- | --- | --- | --- |
| `tp_codeinjection.ps1` | code injection | `Invoke-Expression $expr` | TAINT-005 (CWE-95) | TP |
| `tp_cmdinjection.ps1` | command injection | `& $tool` (call operator) | TAINT-002 (CWE-78) | TP |
| `tp_startprocess.ps1` | command injection | `Start-Process -ArgumentList "…$payload"` | TAINT-002 (CWE-78) | TP |
| `tp_sqlinjection.ps1` | SQL injection | `Invoke-Sqlcmd -Query "…$id"` | TAINT-001 (CWE-89) | TP |
| `tp_pathtraversal.ps1` | path traversal | `Get-Content -Path $path` | TAINT-004 (CWE-22) | TP |
| `tp_ssrf.ps1` | SSRF | `Invoke-WebRequest -Uri $url` | TAINT-006 (CWE-918) | TP |
| `tp_pipeline_fn.ps1` | code injection | `$payload \| Invoke-Expression` | TAINT-005 | caught |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise / safe-code class | nox today |
| --- | --- | --- |
| `clean_parameterized.ps1` | `SqlCommand` + `.Parameters.AddWithValue("@id", $id)` — value bound, not concatenated | clean (sanitizer recognized) |
| `clean_intcast.ps1` | `[int]$raw` numeric coercion before a process arg | clean (cast sanitizer) |
| `clean_validated.ps1` | `-match` allow-pattern guard; only a fixed command runs | clean (tainted value never reaches the sink) |
| `clean_placeholders.ps1` | `your-api-key-here` / `<set-me-in-ci>` placeholders + `$env:` lookup | clean |
| `clean_datablob.ps1` | base64 data-URI blob in a here-string; inert `$(…)` in a literal here-string | clean (here-string blob gating) |
| `clean_generated.ps1` | `<# DO NOT EDIT #>` banner + git SHA + static manifest hashtable | clean |

## PowerShell coverage: what's caught, what's open

nox's PowerShell taint model uses the line/statement **recognizer** (pure-Go, no
CGo tree-sitter — only Go itself gets an AST-precise extractor). The recognizer
normalizes PowerShell's non-C shapes before recognition:

- the `$` variable sigil is stripped (like PHP);
- `::` static-member access and the `[Namespace.Type]` accelerator collapse to a
  dotted chain, so `[IO.File]::ReadAllText($p)` is matched by the `.ReadAllText`
  suffix;
- a `[int]` / `[long]` cast becomes an `int(…)` / `long(…)` **sanitizer** call;
- a cmdlet's `Verb-Noun` hyphen is normalized to an underscore (`Invoke-Expression`
  → `Invoke_Expression`) because the shared identifier scanner treats `-` as an
  operator — the catalog is keyed on the underscore form;
- paren-less cmdlet calls (`Get-Content $p`) are wrapped into `Get_Content($p)`;
- the call operator `& $cmd` is modeled as the synthetic `InvokeOperator` sink;
- double-quoted-string and interpolating here-string `$var` / `${…}` / `$(…)`
  fields are lexed as **code**, so an interpolated tainted value surfaces to the
  engine.

Sources: `$args`, a top-level `param()` parameter (bound from the untrusted
command line — a sentinel `PSScriptParameter` chain; **function** parameters are
NOT treated as sources, to avoid over-tainting), `$env:`, `Read-Host`, and ASP.NET
`$Request.QueryString`/`.Form`/`.Params`.

What nox catches in PowerShell today:

| Vuln class | PowerShell sink (sample) | Fires | CWE |
| --- | --- | --- | --- |
| Code injection | `Invoke-Expression $x` / `iex` | TAINT-005 | CWE-95 |
| Command injection | `& $cmd` / `Invoke-Command` / `Start-Process` | TAINT-002 | CWE-78 |
| SQL injection | `Invoke-Sqlcmd -Query "…$x"` / `SqlCommand` | TAINT-001 | CWE-89 |
| Path traversal | `Get-Content $p` / `Import-Csv` / `[IO.File]::ReadAllText` | TAINT-004 | CWE-22 |
| SSRF | `Invoke-WebRequest $url` / `iwr` / `curl` / `Invoke-RestMethod` | TAINT-006 | CWE-918 |

### Still-open limits

- **Pipeline dataflow — CLOSED.** `$x | Invoke-Expression` binds `$x` to the
  cmdlet's pipeline input, which is a real argument position. The line is now
  split at every top-level `|` and folded left into nested positional calls
  (`a | Cmd1 args | Cmd2` becomes `Cmd2(Cmd1(a, args))`), so the value reaches
  the final stage where the sink is. Stages are split-and-folded rather than
  peeled one at a time because PowerShell cmdlets are paren-LESS: peeling the
  leftmost pipe would swallow the remaining `| Cmd2` text into Cmd1's argument
  list. Pipe positions are read from the CODE view, where string bodies are
  blanked, so a regex alternation (`'^start|stop$'`) is never mistaken for a
  pipeline; `||`, the PowerShell 7 pipeline-CHAIN operator, is skipped because
  it passes no value.
- **Splatting — NOT a limit (this entry was stale).** `Invoke-WebRequest @params`
  where `$params` is a hashtable built from a source IS reported: the hashtable
  is tainted at its assignment and carries into the splatted call. Verified with
  `$p = @{Uri = $args[0]}; Invoke-WebRequest @p`, which fires TAINT-006. The
  claim is corrected rather than deleted so the record shows it was checked, and
  `tp_splatting.ps1` pins the behaviour so it cannot drift back.
- **`-match` is not a laundering sanitizer.** Regex validation with `-match` does
  not reclassify the validated variable; `clean_validated.ps1` is clean because
  the sink argument is a constant, not because `-match` neutralizes the input.
  Feeding a `-match`-validated value straight into a sink would (correctly) still
  fire — validation is not neutralization.
- **Receiver typing is AST-only.** Method-suffix sinks (`.ExecuteReader`,
  `.ReadAllText`, `.AddWithValue`) are matched by method name, not by proving the
  receiver's .NET type, exactly like the Java/C# method-suffix trade.

Grow this corpus over time; the honest way to raise the number is to fix the
recognizer the corpus indicts, not to curate the corpus to pass.
