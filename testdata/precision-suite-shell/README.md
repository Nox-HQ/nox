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
| **Recall** | **0.82** |
| **F1** | **0.90** |
| TP / FP / FN | 9 / 0 / 2 |
| findings-per-issue | 0.82 |

Per rule: TAINT-002 (cmd injection) 3/4, TAINT-004 (traversal) 2/2, TAINT-005
(code injection) 2/3, TAINT-006 (SSRF) 2/2. **Precision is 1.00** — every finding
nox emits is a true positive, and all four clean stressors fire nothing.

## Why shell recall is the lowest of any supported language

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

### The two honest false negatives (`tp_known_fns.sh`)

Both FNs share one root cause: **taint laundered through a `local`-declared
variable inside a function**. The recognizer skips `local` / `declare` / `export`
/ `readonly` lines (they are treated as structural scaffolding), so the declared
variable is never marked tainted and a downstream `eval "$arg"` / `bash -c
"$target"` is missed:

```bash
launder_eval() {
  local arg="$1"      # <- `local` line skipped: arg never tainted
  eval "$arg"         # nox-expect: TAINT-005  (MISSED — false negative)
}
```

Closing this means modeling `local x="$1"` as a tainted assignment without
over-tainting the many benign `local` uses — the open work, deferred honestly
rather than hacked in.

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
