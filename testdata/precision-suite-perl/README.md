# SAST precision suite — Perl

An honest, ground-truth measurement corpus for nox's **Perl** taint model
(`core/lexctx/scan_perl.go` + `core/taint/engine/extract_perl.go` +
`core/taint/data/catalog.json` `perl` block). Like `testdata/precision-suite`,
it is built to measure nox against what a *correct* scanner should do, so real
false positives and false negatives surface as a number below 1.0 — a corpus
that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite-perl
nox bench --precision testdata/precision-suite-perl --json
nox bench --precision testdata/precision-suite-perl --baseline testdata/precision-suite-perl/baseline.json
```

## Why Perl recall is honestly moderate

Perl is the hardest mainstream language to analyze without a full interpreter:
its grammar is context-sensitive (sigil magic, prototypes, `BEGIN`-time code,
source filters) and undecidable in the general case. nox refuses CGo /
tree-sitter and ships a single pure-Go static binary, so the Perl support is a
line/statement **recognizer**, not a parser. It deliberately covers the common
straight-line injection idioms and records the rest as recall. This is the same
"measure → build → re-measure" discipline the Python/JS/Ruby suites follow — the
engine is built to catch what it honestly can, and **samples are never edited to
fake the score**.

## Ground-truth philosophy

- **Clean samples** (`clean_*.pl`) carry **no** `nox-expect` annotation: any
  finding on them is a false positive. They deliberately contain the noise broad
  rules trip on — a base64 data-URI in a nowdoc heredoc, a long minified/base64
  literal, `.env.example`-style placeholder credentials in POD and constants, a
  public content checksum, a `DO NOT EDIT` generated banner, and safe (sanitized
  / parameterized) code that exercises every sanitizer.
- **True-positive samples** (`tp_*.pl`) annotate, per line, the rule a correct
  scanner *should* fire. Where nox fires *more* (over-firing) the extra findings
  score as false positives; where it fires *nothing* the annotation scores as a
  false negative.

## What this corpus reveals

As committed, `nox bench --precision testdata/precision-suite-perl` scores
**precision 1.00 / recall 1.00 / F1 1.00** (10 TP, 0 FP, 2 FN). Precision is
perfect — every finding nox emits on Perl is a true positive, and every clean
stressor stays clean. Recall is honestly below 1.0: two genuine flows are missed
because the Perl extractor is a line/statement recognizer, not a full parser.
Those gaps are annotated in `tp_known_fns.pl` so they score as recall, not
silence.

### Caught (true positives)

| Class | Rule | CWE | Idioms exercised |
|-------|------|-----|------------------|
| Command injection | TAINT-002 | CWE-78 | paren-less `system "..."`, backtick `` `...` `` command literal, `exec(...)` |
| SQL injection | TAINT-001 | CWE-89 | `$dbh->do("... $x")`, `$dbh->prepare("... '$x'")` string interpolation |
| Path traversal | TAINT-004 | CWE-22 | `open(my $fh, "<", $tainted)` |
| Code injection | TAINT-005 | CWE-95 | string `eval $tainted` |
| SSRF | TAINT-006 | CWE-918 | `$ua->get($url)` (LWP::UserAgent) |

Sources exercised: `$ENV{...}` (env), `$ARGV[0]` / `@ARGV` (argv), `<STDIN>`
(stdin), and the CGI web entry points `$q->param(...)` and the imported bare
`param(...)`.

### Clean (no false positives)

Every `clean_*.pl` sample stays clean, including the SAFE counterpart of each
`tp_*.pl` flow:

- parameterized DBI `$dbh->do("... = ?", undef, $id)` and
  `$dbh->prepare("... = ?")` + `execute($x)` (bind param, not interpolation)
- `int($raw)` numeric coercion before a shell command
- `quotemeta($host)` before `system`
- `File::Basename::basename` before `open`
- a constant command (never tainted)
- placeholder creds in POD + constants, a base64 data-URI nowdoc heredoc, a long
  base64 literal, a public checksum, a generated-code banner

## Closed gaps

Both documented Perl false negatives are closed.

**Hash-element laundering** (`$args{cmd} = $ENV{CMD}` then `system("run $args{cmd}")`).
An assignment to a container ELEMENT bound no bare name, so the taint was lost at
the store. The CONTAINER is now bound: a taint on any element taints every read
of it. Field-insensitive by design — it can only widen taint — and enabled per
language as a corpus demands it.

**Cross-sub package globals** (`our $PAYLOAD` set in one sub, read by a sink in
another). The model is intraprocedural plus same-file summaries for local helper
CALLS; it did not join state two subs merely SHARE. A binding of a shared name is
now copied into every other unit that reads it. Only names declared with `our`
participate — a `my` lexical never joins, which is what stops same-named locals
in one file collapsing into a single variable. The join is flow-insensitive
across subs (nothing in the file orders them), and the copy is prepended so a sub
that assigns the name locally still overrides it.

Measured on 780 real-world Ruby/Perl files carrying 1558 instance-variable
assignments and 545 `our` globals: zero new findings.

A 1.0 means this corpus has stopped indicting anything, not that Perl is solved.
The limits below are real and simply lack a failing sample.

## Known gaps (honest false negatives)

Recall is 0.833, not 1.0. The two misses in `tp_known_fns.pl` are real bugs a
correct scanner should flag; nox's line recognizer does not, and we record that
rather than hide it. Neither line produces any finding, so each scores purely as
a missed true positive (recall), never as a false positive.

1. **Taint laundered through a hash element (TAINT-002).** `$args{cmd} = $ENV{X}`
   stores taint into a subscripted lvalue, not a bare scalar. nox tracks
   simple-identifier assignments only (no container / element sensitivity — the
   documented Python/JS/Ruby limit), so the taint is lost at the hash store and
   the sink read of `$args{cmd}` looks clean.

2. **Cross-subroutine flow through a package global (TAINT-002).** A source that
   lands in `our $PAYLOAD` in one sub and is read by a sink in another is a real
   flow, but nox's same-file interprocedural pass tracks **local helper calls**
   via function summaries, not shared package/global state, so a value laundered
   across two subs through a global is not joined. This is the documented
   boundary of the intraprocedural + local-summary model, not a Perl-specific
   defect.

Both are the "measure → build → re-measure" loop working as intended: the corpus
names the gaps as numbers so future work on the recognizer can be measured
against them.

## Ratchet

Committed as `baseline.json`; `TestPrecisionSuiteBaselinePerl` (in `cli/`) fails
if precision/recall/F1 drops or FP / findings-per-issue rises, so the number can
only move the right way without a human refreshing the snapshot. CI also runs
`--min-precision 0.90` as a blunt second floor.
