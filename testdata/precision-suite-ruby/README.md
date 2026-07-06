# SAST precision suite — Ruby

An honest, ground-truth measurement corpus for nox's **Ruby** taint model
(`core/lexctx/scan_ruby.go` + `core/taint/engine/extract_ruby.go` +
`core/taint/data/catalog.json` `ruby` block). Like `testdata/precision-suite`,
it is built to measure nox against what a *correct* scanner should do, so real
false positives and false negatives surface as a number below 1.0 — a corpus
that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-ruby
nox bench --precision testdata/precision-suite-ruby --json
nox bench --precision testdata/precision-suite-ruby --baseline testdata/precision-suite-ruby/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.rb`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in a heredoc, a `%w[]` word array, a public
  git-SHA / schema checksum, `.env.example`-style placeholder credentials, a
  `DO NOT EDIT` generated banner, and safe (sanitized / parameterized) code that
  exercises every sanitizer.
- **True-positive samples** (`tp_*.rb`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* (over-firing) the extra findings
  score as false positives; where it fires *nothing* the annotation scores as a
  false negative.

## What this corpus reveals

As committed, `nox bench --precision testdata/precision-suite-ruby` scores
**precision 1.00 / recall 0.875 / F1 0.933** (14 TP, 0 FP, 2 FN). Precision is
perfect — every finding nox emits on Ruby is a true positive, and every clean
stressor stays clean. Recall is honestly below 1.0: two genuine flows are missed
because the Ruby extractor is a **line/statement recognizer**, not a full parser
(pure-Go, no CGo, no tree-sitter, by design). Those gaps are annotated in
`tp_known_fns.rb` so they score as recall, not silence.

### Caught (true positives)

| Class | Rule | CWE | Idioms exercised |
|-------|------|-----|------------------|
| Command injection | TAINT-002 | CWE-78 | paren-less `system "..."`, backtick `` `...` `` command literal, `exec(...)` |
| SQL injection | TAINT-001 | CWE-89 | ActiveRecord `where("... #{x}")`, `find_by_sql` string interpolation |
| Path traversal | TAINT-004 | CWE-22 | `File.read`, `File.open(...).read` |
| SSRF | TAINT-006 | CWE-918 | `Net::HTTP.get(URI(url))`, `URI.open(url)` |
| Unsafe deserialization | TAINT-005 | CWE-502 | `Marshal.load`, `YAML.load` (unsafe loader) |
| Code injection | TAINT-005 | CWE-95 | `eval(...)`, `Object#send(tainted_name, ...)` |
| XSS | TAINT-003 | CWE-79 | `tainted.html_safe` |

### Clean (no false positives)

Every `clean_*.rb` sample stays clean, including the SAFE counterpart of each
`tp_*.rb` flow:

- parameterized `User.where("id = ?", id)` (bind param, not interpolation)
- `Integer(raw)` / `to_i` numeric coercion before a shell command
- `Shellwords.escape` before `system`
- `File.basename` before `File.read`
- `YAML.safe_load` instead of `YAML.load`
- `CGI.escapeHTML` before `.html_safe`
- placeholder creds, base64 data-URI heredocs, `%w[]` arrays, public checksums,
  a generated-code banner

## Known gaps (honest false negatives)

Recall is 0.875, not 1.0. The two misses in `tp_known_fns.rb` are real bugs a
correct scanner should flag; nox's line recognizer does not, and we record that
rather than hide it:

1. **`render inline:` template injection (TAINT-003).** A tainted value in an
   inline ERB template is real XSS/SSTI. The catalog keys sinks by call *name*
   and cannot distinguish `render inline:` (dangerous) from `render plain:` /
   `render json:` (auto-escaped, safe). A bare `render` sink over-fired on the
   safe auto-escaped renders (5 false positives), so it was intentionally
   dropped — trading one recall gap for zero false positives, the right call for
   a precision-first tool. Closing this needs keyword-argument awareness
   (`inline:` vs `plain:`) in the recognizer.

2. **Cross-method flow through an instance variable (TAINT-002).** A source that
   lands in `@cmd` in one action and is read by a sink in another action is a
   real flow, but nox's same-file interprocedural pass tracks **local helper
   calls** via function summaries, not shared object/instance state, so an
   `@ivar` laundered across two methods is not joined. This is the documented
   boundary of the intraprocedural + local-summary model (identical to the
   Python/JS limit), not a Ruby-specific defect.

Both are the "measure → build → re-measure" loop working as intended: the corpus
names the gaps as numbers so future work on the recognizer can be measured
against them. **Samples are never edited to fake the score** — the engine is
built to catch what it honestly can, and the rest is recorded as recall.

## Ratchet

Committed as `baseline.json`; `TestPrecisionSuiteBaselineRuby` (in `cli/`) fails
if precision/recall/F1 drops or FP / findings-per-issue rises, so the number can
only move the right way without a human refreshing the snapshot. CI also runs
`--min-precision 0.90` as a blunt second floor.
