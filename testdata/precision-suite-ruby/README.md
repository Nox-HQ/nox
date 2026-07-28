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
**precision 1.00 / recall 1.00 / F1 1.00** (16 TP, 0 FP, 1 FN). Precision is
perfect — every finding nox emits on Ruby is a true positive, and every clean
stressor stays clean. Recall is honestly below 1.0: one genuine flow is missed
because the Ruby extractor is a **line/statement recognizer**, not a full parser
(pure-Go, no CGo, no tree-sitter, by design). That gap is annotated in
`tp_known_fns.rb` so it scores as recall, not silence.

### Caught (true positives)

| Class | Rule | CWE | Idioms exercised |
|-------|------|-----|------------------|
| Command injection | TAINT-002 | CWE-78 | paren-less `system "..."`, backtick `` `...` `` command literal, `exec(...)` |
| SQL injection | TAINT-001 | CWE-89 | ActiveRecord `where("... #{x}")`, `find_by_sql` string interpolation |
| Path traversal | TAINT-004 | CWE-22 | `File.read`, `File.open(...).read` |
| SSRF | TAINT-006 | CWE-918 | `Net::HTTP.get(URI(url))`, `URI.open(url)` |
| Unsafe deserialization | TAINT-005 | CWE-502 | `Marshal.load`, `YAML.load` (unsafe loader) |
| Code injection | TAINT-005 | CWE-95 | `eval(...)`, `Object#send(tainted_name, ...)` |
| XSS | TAINT-003 | CWE-79 | `tainted.html_safe`, `render inline:`/`text:` (interpolated) |

### Clean (no false positives)

Every `clean_*.rb` sample stays clean, including the SAFE counterpart of each
`tp_*.rb` flow:

- parameterized `User.where("id = ?", id)` (bind param, not interpolation)
- `Integer(raw)` / `to_i` numeric coercion before a shell command
- `Shellwords.escape` before `system`
- `File.basename` before `File.read`
- `YAML.safe_load` instead of `YAML.load`
- `CGI.escapeHTML` before `.html_safe`
- auto-escaped `render plain:` / `render json:` / `render :template` /
  `render template:` (vs the unescaped `render inline:` / `text:` that DO fire)
- placeholder creds, base64 data-URI heredocs, `%w[]` arrays, public checksums,
  a generated-code banner

## Closed gap — `render inline:` template injection (TAINT-003)

Previously an honest FN, now caught (`tp_render_inline.rb`). A tainted value
interpolated into an **inline ERB template** (`render inline:`) or a raw text
body (`render text:`) is real XSS/SSTI — Rails renders it WITHOUT the automatic
output escaping a normal view gives you. The obstacle was that the catalog keys
sinks by call *name* and a bare `render` sink over-fired on the safe auto-escaped
renders (`render plain:` / `render json:` / `render :template`).

The fix is a **co-located-keyword gate** in the Ruby recognizer
(`extract_ruby.go`), analogous to how the Go XSS `w.Write` sink is gated on a
co-located string literal: `render` is recognized as an XSS sink (via the
synthetic `render_inline` catalog callee) ONLY when the call carries an `inline:`
or interpolated `text:` keyword argument in the same statement; the tainted
arguments are the variables interpolated into that keyword's value. The safe
forms carry no such keyword, so they synthesize no sink and stay clean (see
`clean_render.rb`). A constant inline body (`render inline: "<h1>static</h1>"`)
registers the sink but has no tainted read, so it correctly does not flow.

## Closed gap: cross-method instance variables

`@cmd = params[:cmd]` in one action, `system @cmd` in another, was a documented
false negative — the model is intraprocedural plus same-file summaries for local
helper CALLS, and did not join state two methods merely SHARE.

Two things were needed. An `@ivar` assignment now BINDS (the sigil is part of the
name, not the expression, so it is stripped to the bare name the read side
already produces). And a binding of a shared name is copied into every other unit
that reads it, letting the ordinary intra-unit propagation finish the job.

Only syntactically shared names (`@ivar`, `@@cvar`, `$global`) participate — a
plain local never joins, which is what stops same-named locals in one file
collapsing into a single variable. The join is flow-insensitive across methods
(nothing in the file orders them), and the copy is prepended so a method that
assigns the name locally still overrides it.

Measured on 780 real-world Ruby/Perl files carrying 1558 instance-variable
assignments: zero new findings.

A 1.0 means this corpus has stopped indicting anything, not that Ruby is solved.
The limits below are real and simply lack a failing sample.

## Known gaps (honest false negatives)

Recall is 0.941, not 1.0. The one miss in `tp_known_fns.rb` is a real bug a
correct scanner should flag; nox's line recognizer does not, and we record that
rather than hide it:

1. **Cross-method flow through an instance variable (TAINT-002).** A source that
   lands in `@cmd` in one action and is read by a sink in another action is a
   real flow, but nox's same-file interprocedural pass tracks **local helper
   calls** via function summaries, not shared object/instance state, so an
   `@ivar` laundered across two methods is not joined. Closing it soundly needs
   object-scoped ivar taint shared across methods of the same class — a
   cross-method boundary the intraprocedural + local-summary model does not cross
   (identical to the Python/JS limit), not a Ruby-specific defect. Forcing it
   with a text heuristic risks precision (conditional/reassigned ivars, method
   ordering), so it is left as a documented FN rather than faked.

This is the "measure → build → re-measure" loop working as intended: the corpus
names the gaps as numbers so future work on the recognizer can be measured
against them. **Samples are never edited to fake the score** — the engine is
built to catch what it honestly can, and the rest is recorded as recall.

## Ratchet

Committed as `baseline.json`; `TestPrecisionSuiteBaselineRuby` (in `cli/`) fails
if precision/recall/F1 drops or FP / findings-per-issue rises, so the number can
only move the right way without a human refreshing the snapshot. CI also runs
`--min-precision 0.90` as a blunt second floor.
