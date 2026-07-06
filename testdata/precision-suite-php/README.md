# SAST precision suite — PHP (honest measurement corpus)

This corpus measures **nox's PHP taint model against ground truth** — what a
*correct* scanner should do — so real false positives and false negatives surface
as a number. A corpus that always scores 1.0 measures nothing; this one is built
to stay honest as the PHP model grows.

It is a **separate directory** from `testdata/precision-suite/` (Python/JS/Go) so
PHP is gated against PHP-only ground truth by its own `baseline.json`. PHP support
landed with `lexctx` PHP classification (`core/lexctx/scan_php.go`), a line/
statement taint extractor (`core/taint/engine/extract_php.go`, the same recognizer
family Python/JS use — not an AST parser), and a `php` block in
`core/taint/data/catalog.json`.

Run it:

```
nox bench --precision testdata/precision-suite-php
nox bench --precision testdata/precision-suite-php --json
nox bench --precision testdata/precision-suite-php --baseline testdata/precision-suite-php/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.php` / `clean_*.phtml`) carry **no** `nox-expect`
  annotation: any finding on them is a false positive. They deliberately contain
  the noise broad rules trip on — a base64 data-URI blob, a `DO NOT EDIT`
  generated banner, placeholder/example credentials, an HTML view template, and
  safe (prepared/sanitized) code.
- **True-positive samples** (`tp_*.php`) annotate, per line, the rule a correct
  scanner *should* fire. Over-firing scores as a false positive; a recall gap
  scores as a false negative.

## Measured result

As of writing, `nox bench --precision testdata/precision-suite-php` scores
**precision 1.00 / recall 1.00 / F1 1.00** (9 TP, 0 FP, 0 FN;
findings-per-issue 1.00). Every PHP flow the corpus annotates fires with its
canonical `TAINT-00x` rule, and none of the clean stressors produces a finding.

| Rule | Class | TP | Sample |
| --- | --- | --- | --- |
| TAINT-001 | SQL injection (CWE-89) | 2 | `tp_sqlinjection.php` (`$pdo->query`), `tp_sqli_mysqli.php` (`mysqli_query`) |
| TAINT-002 | Command injection (CWE-78) | 1 | `tp_cmdinjection.php` (`system`) |
| TAINT-003 | XSS (CWE-79) | 1 | `tp_xss.php` (`echo` of tainted) |
| TAINT-004 | Path traversal / LFI (CWE-22) | 2 | `tp_pathtraversal.php` (`readfile`), `tp_lfi_include.php` (`include`) |
| TAINT-005 | Deser / code injection (CWE-502 / CWE-95) | 2 | `tp_deser.php` (`unserialize`), `tp_codeinjection.php` (`eval`) |
| TAINT-006 | SSRF (CWE-918) | 1 | `tp_ssrf.php` (`curl_exec`) |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_safe_db.php` | PDO prepared statement + `intval`-coerced query | clean |
| `clean_sanitized.php` | `htmlspecialchars` / `escapeshellarg` / `basename` guards | clean |
| `clean_placeholders.php` | placeholder creds + constant command + `getenv` | clean |
| `clean_datablob.php` | base64 data-URI blob, hex color, UUID | clean (blob gating) |
| `clean_generated.php` | `DO NOT EDIT` banner, checksum constant | clean |
| `clean_template.phtml` | HTML view template, all values `htmlspecialchars`-escaped | clean |

`baseline.json` pins these numbers; `TestPrecisionSuiteBaselinePHP` (in `cli/`)
and the CI gate `SAST precision gate — php` fail if precision/recall/F1 drop or
FP / findings-per-issue rise, so the number can only move the right way without a
human refreshing the snapshot.

## How the PHP model catches these

PHP is a **templating** language: text outside `<?php … ?>` / `<?= … ?>` is
literal HTML output, so `lexctx` classifies it as non-code and the recognizer
ignores it (this is why `clean_template.phtml` is clean — the markup shell is not
code, and every echoed value is escaped). Inside code islands the extractor:

- reads superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`) as
  array-index **sources**;
- normalizes method calls (`$pdo->query`, `$mysqli->query`) to dotted chains
  (`pdo.query`) matched by the engine's method-suffix fallback;
- models the `echo`/`print` language constructs (no parentheses) as sink calls;
- strips the `$` sigil uniformly so variable tracking is self-consistent.

Sanitizers (`escapeshellarg`, `htmlspecialchars`, `intval`, `basename`,
`mysqli_real_escape_string`, PDO `prepare`) clear taint **per vuln class**, which
is what keeps `clean_safe_db.php` and `clean_sanitized.php` clean without
suppressing the real positives.

## Honest gaps — what PHP does NOT catch yet

Recall is 1.00 on *this* corpus, but that reflects the corpus's scope, not a
complete PHP semantics engine. The PHP extractor inherits the shared engine's
limits (intraprocedural, straight-line, no alias/field sensitivity), plus a few
PHP-specific ones. The day a sample lands for one of these, the number will drop
and name the gap — the measure → build → re-measure loop:

- **Inline source + sanitizer in one statement.** `$id = intval($_GET['id']);`
  taints and clears in the *same* assignment; the shared engine seeds a fresh
  source before it applies the statement's sanitizer, so it would still report.
  The clean samples here sanitize in a *separate* statement (idiomatic PHP), which
  the engine handles correctly. Fixing the single-statement form is engine work
  shared with Python/Go, out of scope for this PR.
- **Taint laundered through arrays / object properties.** `$_GET` written into
  `$data['x']` or `$obj->field` and read back is lost (no container/field
  sensitivity), the same limit the Python/JS/Go engines have.
- **String-interpolated superglobals inside `"…"`.** `"$_GET[x]"` interpolation is
  read from the string body, not as a top-level array access, so a directly
  interpolated superglobal in a double-quoted sink argument can be missed; the
  concatenation form (`. $x`) the samples use is caught.
- **Second-order / stored injection.** A value persisted (DB, file) and re-read in
  another request is cross-request flow, outside intraprocedural scope.
- **XSS beyond `echo`/`print`/`printf`.** Output via a templating engine's raw
  filter, `header()`, or a framework response object is not yet modeled.
- **Cross-file flow.** A source in one file and a sink in another is the taint-
  analysis plugin's territory, not this intraprocedural core.

Grow this corpus over time; the honest way to raise the number is to fix the
model the corpus indicts, not to curate the corpus to pass. When a fix
legitimately improves the score, `TestPrecisionSuiteBaselinePHP` tells you to
refresh `baseline.json`.
