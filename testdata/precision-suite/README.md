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
**precision 1.00 / recall 1.00 / F1 1.00** (17 TP, 0 FP, 0 FN) — up from the
original honest baseline of precision 0.30 / F1 0.47 (39 FP), and from the
interim 0.89 / F1 0.94 once the last two residual FPs were fixed (items 5–6
below). Recall stayed perfect throughout while precision was raised only by
fixing the false-positive classes the corpus indicted:

- **findings-per-issue: 1.06** (was 2.75) — across the annotated issues nox now
  emits ~1.06 findings each; 1.00 is ideal. The two secret files that used to
  dominate collapsed to their canonical provider rule: `tp_secrets_cloud.py`
  from density **8.00 → 1.00** and `tp_secrets.py` from **5.33 → 1.33**. The
  secret analyzer now deduplicates overlapping rules by specificity and resolves
  the canonical provider owner per token (see `core/analyzers/secrets/dedup.go`).
- **noise ratio: 0.00** (was 0.70) — 0 of the 17 findings nox produces are false
  positives. The last two (a SEC-161 entropy hit on a base64 data-URI SVG in
  `clean_svg_blob.ts`, and a TAINT-003 over-fire accompanying the SSTI positive
  in `tp_ssti.py`) are now fixed at the engine level (items 5–6 below).

Committed as `baseline.json`; `TestPrecisionSuiteBaseline` (in `cli/`) fails if
any of precision/recall/F1 drops or FP / findings-per-issue rises, so the number
can only move the right way without a human refreshing the snapshot.

### The precise to-do list the corpus indicts

1. **Secret rules over-fire massively — FIXED.** One GitHub, Slack, Stripe, or
   Google token used to trip 5–7 overlapping high-entropy / keyword rules
   (`SEC-161/162/163/216/…`). The secrets analyzer now collapses overlapping
   findings on a token to the canonical provider rule (`SEC-030` Stripe,
   `SEC-007` GCP, `SEC-003` GitHub, `SEC-023` Slack, `SEC-001`/`SEC-508` AWS)
   via specificity dedup + per-token owner resolution
   (`core/analyzers/secrets/dedup.go`). Density dropped from 8.00 to 1.00.
2. **Placeholder / example credentials flagged as real — FIXED.**
   `"your-api-key-here"`, `"changeme"`, `postgres://USER:PASSWORD@…`,
   `sk_test_0000…`, and `<your-smtp-password>` are now dropped by an
   example/placeholder allowlist (`core/analyzers/secrets/placeholder.go`)
   mirroring gitleaks/trufflehog/detect-secrets. `clean_placeholders.py` and
   `clean_env_example.py` are clean.
3. **AI-002 fired on safe string concatenation — FIXED.** AI-002 now requires a
   nearby prompt/LLM context token (`prompt`, `messages`, `.chat.`, model call;
   `core/analyzers/ai/prompt_context.go`), so the parameterised SQL in
   `clean_safe_db.py` no longer trips it while the real `tp_prompt.py` positive
   still fires.
4. **Injection recall gaps — CLOSED.** The intraprocedural taint engine has
   landed, so command injection (`os.system("echo " + cmd)`), eval, path
   traversal (`open(user_path)`), unsafe deserialization (`pickle.loads(user)`),
   and SSRF (`requests.get(user_url)`) now fire as `TAINT-002/005/...`. Those
   annotations flipped from false negatives to true positives, taking suite
   recall to 1.0 — the measure→build→re-measure loop working end to end. (SSTI
   via `render_template_string(... + user)`
   is *already* caught by `VARIANT-005`, so it is annotated as a true positive.)
5. **Entropy fired inside a decoded image/SVG blob — FIXED.** The secrets
   decode-and-scan path (`core/analyzers/secrets/decode.go`) base64-decodes
   embedded blobs and re-scans the decoded bytes. A data-URI SVG decodes to
   markup whose long alphanumeric runs tripped the entropy rules
   (`SEC-161/162/163`) on `clean_svg_blob.ts`. The decode path now suppresses
   entropy-only findings when the decoded content is itself a markup/image/data
   blob (SVG/XML/HTML markup or an image magic header), while a real credential
   hidden in base64 — which decodes to a bare secret, not to markup — is still
   caught by the provider pattern rules.
6. **Taint SSTI double-reported the variants SSTI — FIXED.** The taint engine's
   `TAINT-003` SSTI sink and the `VARIANT-005` CVE signature both fired on the
   same `render_template_string(... + user)` call, reporting one vulnerability
   twice. The pipeline now drops a taint finding when another analyzer already
   reports the same `vuln_class` at the same location
   (`FindingSet.SuppressDuplicateVulnClass`, wired in `core/scan.go`), keeping
   the more specific CVE signature. It is class-scoped, so it never hides a
   distinct vulnerability — an XSS taint finding is only ever suppressed by
   another XSS finding at the same span.

## Sample inventory

True positives (annotated ground truth):

| File | What it exercises | Correct rule | nox today |
| --- | --- | --- | --- |
| `tp_secrets.py` | AWS / GitHub / Slack tokens | SEC-001/003/023/508 | TP, deduped to canonical |
| `tp_secrets_cloud.py` | Stripe / GCP keys | SEC-030 / SEC-007 | TP, deduped to canonical |
| `tp_prompt.py` | prompt injection (f-string) | AI-002 | TP |
| `tp_yaml.py` | unsafe `yaml.load` | SLOP-001 / VARIANT-002 | TP |
| `tp_ssti.py` | SSTI via dynamic template | VARIANT-005 (+ SLOP-001) | TP, taint SSTI duplicate deduped |
| `tp_injection.py` | command / eval injection | TAINT-002 / TAINT-005 | FN (recall gap) |
| `tp_pathtrav.py` | path traversal via `open()` | TAINT-004 | FN (recall gap) |
| `tp_deser.py` | unsafe `pickle.loads` | TAINT-005 | FN (recall gap) |
| `tp_ssrf.py` | SSRF via `requests.get` | TAINT-006 (+ SLOP-001) | FN (recall gap) |

Clean stressors (zero annotations — any finding is a false positive):

| File | Noise class | nox today |
| --- | --- | --- |
| `clean_placeholders.py` | placeholder creds | clean |
| `clean_env_example.py` | `.env.example` placeholders | clean |
| `clean_placeholders.ts` | TS placeholder tokens | clean |
| `clean_prose_comments.py` | sinks quoted in comments | clean |
| `clean_safe_db.py` | parameterized / arg-vector / quoted | clean |
| `clean_hashes.js` | lockfile hashes, git SHA | clean |
| `clean_svg_blob.ts` | base64 data-URI SVG | clean |
| `clean_minified_bundle.js` | minified bundle strings | clean |
| `clean_json_blob.py` | base64/JSON blob constant | clean |
| `clean_identifiers.py` | UUIDs, hex colors, git SHA | clean |

Grow this corpus over time; the honest way to raise the number is to fix the
rules the corpus indicts, not to curate the corpus to pass. When a rule fix
legitimately improves the score, `TestPrecisionSuiteBaseline` tells you to
refresh `baseline.json`.
