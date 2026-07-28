# SAST precision suite — shell/bash (honest measurement corpus)

This is the dedicated honest-measurement corpus for nox's **shell/bash** taint
model (`lexctx` `scan_shell` + engine `extract_shell` + the catalog `shell`
block). Like the other `precision-suite-*` corpora it measures nox against
**ground truth** — what a *correct* scanner should do — so real false negatives
surface as a number below 1.0. A corpus that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-shell
nox bench --precision testdata/precision-suite-shell --baseline testdata/precision-suite-shell/baseline.json
```

## Measured result

As committed, `nox bench --precision testdata/precision-suite-shell` scores:

| Metric | Value |
| --- | --- |
| **Precision** | **1.00** (0 false positives) |
| **Recall** | **0.87** |
| **F1** | **0.93** |
| TP / FP / FN | 13 / 0 / 2 |
| findings-per-issue | 0.87 |

Per rule: TAINT-002 (cmd injection) 4/4, TAINT-004 (traversal) 2/2, TAINT-005
(code injection) 3/3, TAINT-006 (SSRF) 2/2. **Precision is 1.00** — every finding
nox emits is a true positive, and all four clean stressors fire nothing.

Recall is deliberately BELOW 1.0 again. It reached 1.0 when the `local`
laundering gap closed, at which point the corpus could only catch regressions and
could no longer say what the recognizer still cannot do — so `tp_pipeline_fed.sh`
was added, pinning two real misses where a tainted value reaches a sink through a
PIPELINE rather than as a literal argument (`xargs curl`, `xargs -I{} sh -c`).
The drop from 1.00 to 0.85 is the corpus getting harder, not the engine getting
worse: precision is still 1.000 with zero false positives.

Two entries that used to appear in the limits list — ARRAYS and `${var//a/b}`
transforms — were checked and are NOT limits; both propagate today. The stale
claims are corrected, and `tp_array_and_transform.sh` now PINS both so they
cannot drift back into being described as gaps. A documented gap that does not
exist is the same defect as an unguarded one, in the other direction.

## Why shell recall is the hardest of any supported language

This is expected and honest. Unlike Python/Ruby/JS (function-call-shaped, so an
`f(x)` call site and its arguments are unambiguous), **shell is command-oriented
and paren-less**: `cmd arg1 arg2`. A value is executed by being *word-split* into
a command line, laundered through `$(...)` pipelines, stored in arrays, or built
by dynamic string juggling — constructs a deterministic, flat, per-line
recognizer cannot follow without becoming a shell interpreter (which nox
deliberately is not: pure-Go, no CGo, no dependency). So nox recognizes the
straight-line eval/command patterns that carry the bulk of real shell injection
and honestly misses the dynamic ones. The recall gap is the truth, not a defect
to paper over.

### CLOSED: the two `local`-laundering false negatives (`tp_known_fns.sh`)

Both shared one root cause: **taint laundered through a `local`-declared
variable inside a function**. `local` / `declare` / `export` / `readonly` lines
were skipped wholesale as structural scaffolding, so the declared variable was
never marked tainted and a downstream `eval "$arg"` / `bash -c "$target"` was
missed.

A declaration that INITIALIZES (`local arg="$1"`) is an assignment and is now
recognized as one: the keyword and any option flags are blanked to spaces
(width-preserving, so the code and raw views stay aligned) and the assignment
underneath is read normally. A BARE declaration (`local a b c`, `declare -A
map`) still skips — it carries no dataflow, and reading it as a command would
invent a call to `local`.

The feared cost — "over-tainting the many benign `local` uses" — did not
materialize, because `local x=RHS` only taints when RHS is actually a source:
`local count=0` stays clean. What it DID do was expose four latent
sink-modelling bugs, which had been invisible only because no tainted value ever
reached them. Measured on 87 real-world shell scripts (452 declaration
assignments), the recall fix alone added **five** false positives; all four
causes are now fixed:

| Bug | Effect |
| --- | --- |
| `isShellCommandByte` stopped at `-`, though its own doc comment said command names may contain `-`, `.` and `/` | `exec-add-path` truncated to `exec`, an exact-match command-injection sink — any tainted argument to any `exec-*` helper was CWE-78 |
| `exec` matched on an I/O redirection | `exec 200>"$lock"` rebinds a file descriptor and executes nothing, but was reported as command injection |
| fetch commands ignored argument position | `curl --output "$path" "$url"` writes `$path`; a tainted output path was reported as the SSRF-controlling value |
| path-qualified commands were unrecognized | `/usr/bin/curl "$u"` resolved to no callee at all, losing the sink (a recall bug found while fixing the above) |

After all four, the same 87-script corpus yields **one** new finding, and it is a
genuine `argv → url → curl` dataflow (`curl -fSL -o "$tarball" "$url"` where
`url` interpolates `$1`). Its exploitability is arguable — the scheme and host
are literal, so only a path segment is attacker-controlled — but that is a
question about how the SSRF rule should treat a partially-tainted URL, not an
extractor defect. It is recorded here rather than suppressed.

A crash was also fixed on the way: the double-quote scanner treated `\` as
escaping the next byte without checking one existed, so a word ending in a lone
backslash ran the index past the end of the line. It was latent only because
nothing sliced the raw view by that index.

## Precision: the hard part for shell

The vulnerability in shell is `eval $user`, `bash -c "$user"`, `source
"$userpath"`, `curl "$url"` — **not** a properly quoted expansion passed to a
normal command. nox models exactly that boundary, so `clean_*.sh` scripts do not
false-positive:

- **A quoted `"$var"` to a NON-sink command is clean.** `cp "$src" /backup/` never
  fires — `cp` is not a shell interpreter, and quoting prevents word-splitting.
  The sinks are *only* `eval`, `sh -c`/`bash -c`, `source`/`.`, `curl`/`wget`.
- **`sh`/`bash` fire only in the `-c "$user"` shape.** A bare `bash /opt/run.sh`
  (running a static script file) carries no `-c` and is not a command-injection
  sink.
- **`printf %q` and `basename` are sanitizers.** `eval "$(printf %q "$raw")"` and
  `source "/etc/app/$(basename "$p")"` are recognized as neutralized.
- **`$((...))` arithmetic and `[[ ... =~ ]]` / `case` allowlists** constrain a
  value to a non-injectable form; those clean paths reach no sink.
- **Single-quoted words are inert** (`'$var'` does not expand), so a literal `$`
  in single quotes is never a live read.

## Sample inventory

True positives (annotated ground truth):

| File | What it exercises | Correct rule | nox today |
| --- | --- | --- | --- |
| `tp_codeinjection.sh` | `eval "$1"`, `eval "$formula"` (read) | TAINT-005 | TP ×2 |
| `tp_cmdinjection.sh` | `sh -c`/`bash -c` of a tainted string | TAINT-002 | TP ×3 |
| `tp_pathtraversal.sh` | `source "$cfg"`, `. "$plugin"` | TAINT-004 | TP ×2 |
| `tp_ssrf.sh` | `curl "$url"`, `wget "$QUERY_STRING"` | TAINT-006 | TP ×2 |
| `tp_known_fns.sh` | `local`-laundered `eval` / `bash -c` | TAINT-005 / -002 | **FN ×2** (honest) |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_safe.sh` | `printf %q`, `basename`, quoted arg to non-sink, `bash script.sh` (no `-c`), constant command, `$((...))` arithmetic | clean |
| `clean_validated.sh` | `case` allowlist, `[[ =~ ]]` regex validation, `echo` to a log | clean |
| `clean_placeholders.sh` | placeholder creds, env-sourced token, dangerous idioms quoted in comments | clean |
| `clean_datablob.sh` | base64 payload heredoc, quoted config-template heredoc | clean (blob gating) |

## Honesty policy

The number can only move the right way without a human refreshing the snapshot:
`TestPrecisionSuiteBaselineShell` (in `cli/`) fails if precision/recall/F1 drops
or FP / findings-per-issue rises, and the CI gate "SAST precision gate — shell"
holds a `--min-precision 0.90` floor. The honest way to raise recall is to build
the engine (e.g. model `local x="$1"`), never to curate the corpus to pass —
exactly the measure → build → re-measure loop the other language suites follow.
