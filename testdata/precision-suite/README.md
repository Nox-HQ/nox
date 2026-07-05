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
nox bench --precision testdata/precision-suite --baseline testdata/precision-suite/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.{py,js,ts}`) carry **no** `nox-expect` annotation:
  any finding on them is a false positive. They deliberately contain the noise
  that broad rules trip on — an embedded base64 SVG, a minified JS bundle, a
  JSON/base64 blob in a `.py`, UUIDs/hex colors/git SHAs, lockfile-style hashes,
  code sinks quoted in comments, `.env.example` placeholders, and safe
  (sanitized/parameterized) code.
- **True-positive samples** (`tp_*.{py}`) annotate the rule(s) a correct scanner
  *should* fire, per line. Where nox fires *more* (over-firing) those extra
  findings score as false positives; where it fires *nothing* (a recall gap)
  the annotation scores as a false negative.

## What this corpus currently reveals

As of writing, `nox bench --precision testdata/precision-suite` scores
**precision 0.30 / recall 1.00 / F1 0.47** (17 TP, 39 FP, 0 FN) — an honest
baseline. Recall is now perfect: the intraprocedural taint engine landed and the
injection/SSRF/traversal/deserialization flows that used to be false negatives
now fire (see item 4). All the remaining work is **precision** — the grown suite
surfaces exactly what per-rule precision/recall cannot see:

- **findings-per-issue: 2.75** — across the annotated issues, nox emits 2.75
  findings each on average; 1.00 is ideal. Two files dominate:
  `tp_secrets_cloud.py` has density **8.00** (16 findings on 2 real secrets) and
  `tp_secrets.py` **5.33**. This is the over-firing per-rule scoring misses:
  every one of those findings is a real secret (each rule "TP"s), yet a human
  sees one issue inflated 5-8×.
- **noise ratio: 0.70** — 39 of the 56 findings nox produced were false
  positives.

Committed as `baseline.json`; `TestPrecisionSuiteBaseline` (in `cli/`) fails if
any of precision/recall/F1 drops or FP / findings-per-issue rises, so the number
can only move the right way without a human refreshing the snapshot.

### The precise to-do list the corpus indicts

1. **Secret rules over-fire massively.** One GitHub, Slack, Stripe, or Google
   token trips 5–7 overlapping high-entropy / keyword rules
   (`SEC-161/162/163/216/…`). nox fires the *right* provider rule on each
   (`SEC-030` Stripe, `SEC-007` GCP, `SEC-003` GitHub, `SEC-023` Slack) but
   drowns it in duplicates. This is the dominant precision drag and the whole
   reason for the density metric.
2. **Placeholder / example credentials are flagged as real.**
   `"your-api-key-here"`, `"changeme"`, `postgres://USER:PASSWORD@…`,
   `sk_test_0000…`, and `<your-smtp-password>` in `clean_placeholders.py` and
   `clean_env_example.py` produce false positives — nox has no allowlist for
   obvious examples (gitleaks/trufflehog/detect-secrets all do).
3. **AI-002 fires on safe string concatenation** in `clean_safe_db.py` — a
   `"…" + var` that is not a prompt.
4. **Injection recall gaps — CLOSED.** The intraprocedural taint engine has
   landed, so command injection (`os.system("echo " + cmd)`), eval, path
   traversal (`open(user_path)`), unsafe deserialization (`pickle.loads(user)`),
   and SSRF (`requests.get(user_url)`) now fire as `TAINT-002/005/...`. Those
   annotations flipped from false negatives to true positives, taking suite
   recall to 1.0 — the measure→build→re-measure loop working end to end. (SSTI
   via `render_template_string(... + user)`
   is *already* caught by `VARIANT-005`, so it is annotated as a true positive.)

## Sample inventory

True positives (annotated ground truth):

| File | What it exercises | Correct rule | nox today |
| --- | --- | --- | --- |
| `tp_secrets.py` | AWS / GitHub / Slack tokens | SEC-001/003/023/508 | TP + heavy over-fire |
| `tp_secrets_cloud.py` | Stripe / GCP keys | SEC-030 / SEC-007 | TP + 5–6 over-fires each |
| `tp_prompt.py` | prompt injection (f-string) | AI-002 | TP |
| `tp_yaml.py` | unsafe `yaml.load` | SLOP-001 / VARIANT-002 | TP |
| `tp_ssti.py` | SSTI via dynamic template | VARIANT-005 (+ SLOP-001) | TP |
| `tp_injection.py` | command / eval injection | TAINT-002 / TAINT-005 | FN (recall gap) |
| `tp_pathtrav.py` | path traversal via `open()` | TAINT-004 | FN (recall gap) |
| `tp_deser.py` | unsafe `pickle.loads` | TAINT-005 | FN (recall gap) |
| `tp_ssrf.py` | SSRF via `requests.get` | TAINT-006 (+ SLOP-001) | FN (recall gap) |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_placeholders.py` | placeholder creds | 4 FP |
| `clean_env_example.py` | `.env.example` placeholders | 6 FP |
| `clean_placeholders.ts` | TS placeholder tokens | clean |
| `clean_prose_comments.py` | sinks quoted in comments | clean |
| `clean_safe_db.py` | parameterized / arg-vector / quoted | 1 FP (AI-002) |
| `clean_hashes.js` | lockfile hashes, git SHA | clean |
| `clean_svg_blob.ts` | base64 data-URI SVG | 1 FP |
| `clean_minified_bundle.js` | minified bundle strings | clean |
| `clean_json_blob.py` | base64/JSON blob constant | clean |
| `clean_identifiers.py` | UUIDs, hex colors, git SHA | clean |

Grow this corpus over time; the honest way to raise the number is to fix the
rules the corpus indicts, not to curate the corpus to pass. When a rule fix
legitimately improves the score, `TestPrecisionSuiteBaseline` tells you to
refresh `baseline.json`.
