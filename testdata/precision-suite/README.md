# SAST precision suite — honest measurement corpus

Unlike `testdata/precision-corpus/` (a small, controlled fixture the harness's
own unit tests run against), this corpus is built to **measure nox against
ground truth** — what a *correct* scanner should do — so real false positives
and false negatives surface as a number below 1.0. That is the point: a corpus
that always scores 1.0 measures nothing.

Run it:

```
nox bench --precision testdata/precision-suite
nox bench --precision testdata/precision-suite --json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.{py,js,ts}`) carry **no** `nox-expect` annotation:
  any finding on them is a false positive. They deliberately contain the noise
  that broad rules trip on — an embedded base64 SVG, lockfile-style hashes,
  code sinks quoted in comments, placeholder/example credentials, and safe
  (sanitized/parameterized) code.
- **True-positive samples** (`tp_*.py`) annotate the rule(s) a correct scanner
  *should* fire, per line. Where nox fires *more* (over-firing) those extra
  findings score as false positives; where it fires *nothing* (a recall gap)
  the annotation scores as a false negative.

## What this corpus currently reveals

As of writing, `nox bench --precision testdata/precision-suite` scores
**precision 0.26 / recall 0.78 / F1 0.39** (7 TP, 20 FP, 2 FN) — an honest
baseline with a precise to-do list:

1. **Secret rules over-fire.** A single GitHub or Slack token trips 6–7
   overlapping high-entropy / keyword rules (`SEC-161/163/216/...`), and some
   fire on non-secret noise. This is the dominant precision drag.
2. **Placeholder credentials are flagged as real.** `"your-api-key-here"`,
   `"changeme"`, `"xxxx…"`, and `postgres://user:password@…` in
   `clean_placeholders.py` produce false positives — nox has no allowlist for
   obvious examples (gitleaks/trufflehog/detect-secrets all do).
3. **An AI-002 fires on safe string concatenation** in `clean_safe_db.py` — a
   `"…" + var` that is not a prompt.
4. **Command / eval injection is missed** (`tp_injection.py`, `TAINT-002` /
   `TAINT-005` FNs). These are the recall gap the intraprocedural taint engine
   is built to close; the annotations are the regression target — they flip to
   true positives when it lands.

Grow this corpus over time; the honest way to raise the number is to fix the
rules the corpus indicts, not to curate the corpus to pass.
