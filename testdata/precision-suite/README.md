# SAST precision suite — honest measurement corpus

Unlike `testdata/precision-corpus/` (a small, controlled fixture the harness's
own unit tests run against), this corpus is built to **measure nox against
ground truth** — what a *correct* scanner should do — so real false positives
and false negatives surface as a number below 1.0. That is the point: a corpus
that always scores 1.0 measures nothing.

The corpus spans **Python, JS/TS, and Go** (`clean_*.{py,js,ts,go}` /
`tp_*.{py,go}`). Go samples were added once `lexctx` began classifying Go
(#197): nox is now measured in its own language for the first time. Adding them
first *lowered* recall (the six Go taint classes were genuine false negatives
until a Go taint model existed); the Go taint model has since landed
(`core/taint/data/catalog.json` `go` block + `core/taint/engine/extract_go.go`,
AST-precise via `go/ast`), flipping all six from FN to TP and taking recall back
to 1.00 — the measure → build → re-measure loop, extended to Go. A second Go
tier then reopened recall to 0.89 (four honest tier-2 false negatives: three
XSS-to-response, one map-value container taint) and has since been closed too,
returning recall to 1.00. See "Go coverage: what's caught, what's still open"
below.

Run it:

```
nox bench --precision testdata/precision-suite
nox bench --precision testdata/precision-suite --json
nox bench --precision testdata/precision-suite --baseline testdata/precision-suite/baseline.json
```

## Ground-truth philosophy

- **Clean samples** (`clean_*.{py,js,ts,go}`) carry **no** `nox-expect`
  annotation: any finding on them is a false positive. They deliberately contain
  the noise that broad rules trip on — an embedded base64 SVG, a minified JS
  bundle, a JSON/base64 blob in a `.py`, a base64 data-URI in a Go raw string,
  UUIDs/hex colors/git SHAs, lockfile-style hashes and SRI integrity hashes,
  code sinks quoted in comments, `.env.example` placeholders, a
  `DO NOT EDIT` generated-code banner, and safe (sanitized/parameterized) code.
- **True-positive samples** (`tp_*.{py,go}`) annotate the rule(s) a correct
  scanner *should* fire, per line. Where nox fires *more* (over-firing) those
  extra findings score as false positives; where it fires *nothing* (a recall
  gap) the annotation scores as a false negative.

## What this corpus currently reveals

As of writing, `nox bench --precision testdata/precision-suite` scores
**precision 1.00 / recall 1.00 / F1 1.00** (37 TP, 0 FP, 0 FN). Precision is
perfect — every finding nox emits is a true positive, and both Go clean
stressors (`clean_html_autoescape.go`, `clean_field_safe.go`) fire nothing — and
recall is back to 1.00 now that the Go tier-2 gaps are closed. The second Go tier
(`tp_xss_response.go`, `tp_field_taint.go`, `tp_container_taint.go` plus the two
clean guardrails) had named **four honest false negatives** the variable-level Go
engine missed — three XSS-to-response sinks and one map-value container taint —
dropping recall to 0.89. Those were closed by building the engine (an
XSS-to-response sink family + container-level index/field taint), not by curating
the corpus. See "Go coverage" below for what each fix added.

A configuration tier (`tp_data_pii.yaml`, `clean_data_placeholders.yaml`) was
added alongside the DATA-005 / DATA-001 precision fix, and named **nine honest
false positives** on landing: DATA-005's pattern matched every dotted quad
despite the rule being titled "public IP address", so it reported all six
loopback / RFC 1918 / link-local / RFC 5737 addresses in the clean sample, and
DATA-001 reported all three RFC 2606 / RFC 6761 reserved documentation
addresses. Measured on this corpus, DATA-005 scored **precision 0.14** and
DATA-001 **precision 0.25**, dropping corpus precision to 0.80 / F1 0.89. Both
are now 1.00 with recall unchanged at 1.00 — closed by deciding publicness in
Go against a `netip.Prefix` table rather than by widening the regex.

For the historical record, recall dipped to 0.79 when the *first* realistic **Go**
samples landed (six FNs: injection / traversal / SSRF / deserialization / SSTI),
returned to 1.00 once the first Go taint model closed them, dipped again to 0.89
when the tier-2 samples landed (the four FNs above), and returned to 1.00 once the
tier-2 engine work closed those — the measure → build → re-measure loop, running
on Go across two tiers.

For reference, the earlier journey: precision rose from an original honest
baseline of 0.30 / F1 0.47 (39 FP), through an interim 0.89 / F1 0.94, to
1.00 / F1 1.00 on Python/JS — raised only by fixing the false-positive classes
the corpus indicted (items 1–6 below), never by curating it. Recall then dipped
to 0.79 when Go samples landed (six honest FNs) and returned to 1.00 once the Go
taint model closed them.

- **findings-per-issue: 1.06** — across the annotated issues nox emits ~1.06
  findings each; it is now slightly *above* 1.00 only because the two Go secret
  files fire the language-agnostic secret regexes above 1.00
  (`tp_secrets.go` at 1.33). Every taint class — including the four newly-closed
  tier-2 flows — is exactly 1.00 (`tp_xss_response.go` 3/3, `tp_container_taint.go`
  2/2). On the Python
  secret files that once dominated, density
  collapsed to canonical: `tp_secrets_cloud.py` from **8.00 → 1.00** and
  `tp_secrets.py` from **5.33 → 1.33**, via specificity dedup + per-token owner
  resolution (`core/analyzers/secrets/dedup.go`). The Go secret files
  (`tp_secrets.go` at 1.33, `tp_secrets_cloud.go` at 1.00) score near-canonical —
  the language-agnostic secret regexes resolve cleanly on Go too.
- **noise ratio: 0.00** — 0 of the findings nox produces are false positives.
  The Go clean-stressors added here (a base64 data-URI in a Go raw string, an
  SRI integrity hash, a generated-code banner, placeholder creds) are all clean.
  The one Go FP the corpus surfaced — a **SEC-161** entropy hit on the SRI
  `sha384-…` integrity hash in `clean_identifiers.go` — was fixed at the engine
  level: the entropy matcher now recognizes and skips SRI hashes
  (`core/rules/entropy.go`, `isSRIIntegrityHash`), the same "public digest, not
  a secret" class as the existing git-SHA / checksum suppressions.

Committed as `baseline.json`; `TestPrecisionSuiteBaseline` (in `cli/`) fails if
any of precision/recall/F1 drops or FP / findings-per-issue rises, so the number
can only move the right way without a human refreshing the snapshot. The snapshot
also records a **per-rule** precision/recall floor (the `rules` array): the
ratchet fails if any individual rule regresses below its floor, so one rule
rotting can no longer hide behind another improving in the overall average. The
`rules` section is optional — a snapshot without it still loads and gates on the
overall numbers only.

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
4. **Injection recall gaps — CLOSED (Python/JS *and* Go).** The intraprocedural
   taint engine has landed, so command injection (`os.system("echo " + cmd)`),
   eval, path traversal (`open(user_path)`), unsafe deserialization
   (`pickle.loads(user)`), and SSRF (`requests.get(user_url)`) fire as
   `TAINT-002/005/...`. The **Go** taint model then closed the six Go FNs the
   same way: an AST-precise extractor (`core/taint/engine/extract_go.go`, built on
   `go/ast` because nox is itself Go) plus a `go` catalog block flip
   `tp_cmdinjection.go`/`tp_sqlinjection.go`/`tp_pathtraversal.go`/`tp_ssrf.go`/
   `tp_deserialization.go`/`tp_ssti.go` from FN to TP, taking suite recall back to
   1.0 — the measure→build→re-measure loop working end to end. (Python SSTI via
   `render_template_string(... + user)` is *already* caught by `VARIANT-005`, so it
   is annotated as a true positive; Go SSTI fires the taint engine's `TAINT-003`.)
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

True positives — Python / JS (annotated ground truth):

| File | What it exercises | Correct rule | nox today |
| --- | --- | --- | --- |
| `tp_secrets.py` | AWS / GitHub / Slack tokens | SEC-001/003/023/508 | TP, deduped to canonical |
| `tp_secrets_cloud.py` | Stripe / GCP keys | SEC-030 / SEC-007 | TP, deduped to canonical |
| `tp_prompt.py` | prompt injection (f-string) | AI-002 | TP |
| `tp_yaml.py` | unsafe `yaml.load` | SLOP-001 / VARIANT-002 | TP |
| `tp_ssti.py` | SSTI via dynamic template | VARIANT-005 (+ SLOP-001) | TP, taint SSTI duplicate deduped |
| `tp_injection.py` | command / eval injection | TAINT-002 / TAINT-005 | TP (taint engine) |
| `tp_pathtrav.py` | path traversal via `open()` | TAINT-004 | TP (taint engine) |
| `tp_deser.py` | unsafe `pickle.loads` | TAINT-005 | TP (taint engine) |
| `tp_ssrf.py` | SSRF via `requests.get` | TAINT-006 (+ SLOP-001) | TP (taint engine) |

True positives — Go (annotated ground truth; nox is measured in its own
language for the first time):

| File | What it exercises | Correct rule | nox today |
| --- | --- | --- | --- |
| `tp_secrets.go` | AWS / GitHub / Slack tokens in Go literals | SEC-001/003/023/508 | TP, deduped to canonical |
| `tp_secrets_cloud.go` | Stripe / GCP keys in Go consts | SEC-030 / SEC-007 | TP, deduped to canonical |
| `tp_cmdinjection.go` | `exec.Command("sh","-c",…)` | TAINT-002 | TP (Go taint model) |
| `tp_sqlinjection.go` | `db.Query("… '" + input)` | TAINT-001 | TP (Go taint model) |
| `tp_pathtraversal.go` | `os.ReadFile(filepath.Join(base, input))` | TAINT-004 | TP (Go taint model) |
| `tp_ssrf.go` | `http.Get(userURL)` | TAINT-006 | TP (Go taint model) |
| `tp_deserialization.go` | `gob.NewDecoder(r.Body).Decode` | TAINT-005 | TP (Go taint model) |
| `tp_ssti.go` | `text/template` parse of user input | TAINT-003 | TP (Go taint model) |
| `tp_xss_response.go` | reflected XSS to `http.ResponseWriter` (Fprintf / Write / `template.HTML`) | TAINT-003 (xss, CWE-79) | TP (XSS-to-response sink family) |
| `tp_field_taint.go` | cmd injection laundered through a struct field | TAINT-002 | TP (container-level field taint) |
| `tp_container_taint.go` | cmd injection through a map value **and** a slice element | TAINT-002 (×2) | TP ×2 (container-level index/element taint) |

True positives — configuration (annotated ground truth):

| File | What it exercises | Correct rule | nox today |
| --- | --- | --- | --- |
| `tp_data_pii.yaml` | publicly routable IPv4 + mailbox at a registrable domain in config | DATA-005 / DATA-001 | TP |

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
| `clean_rawstring_blob.go` | base64 data-URI in a Go raw string | clean (blob gating) |
| `clean_safe_db.go` | `$1` parameterized query, arg-vector exec, allowlist | clean |
| `clean_placeholders.go` | placeholder creds + `os.Getenv` | clean |
| `clean_generated.go` | `DO NOT EDIT` banner, descriptor bytes, struct tags | clean |
| `clean_identifiers.go` | UUID, git SHA, hex colors, **SRI integrity hash** | clean (SRI fix) |
| `clean_html_autoescape.go` | `html/template` context-aware auto-escaping of user data | clean (correct escaping → not a sink) |
| `clean_field_safe.go` | struct field sanitized (`strconv.Atoi`, `filepath.Base`) before the sink | clean (sanitizer recognized) |
| `clean_data_placeholders.yaml` | loopback / RFC 1918 / link-local IPs and RFC 2606 + RFC 6761 reserved email domains | clean (DATA-005/001 range + reserved-domain predicates) |

Grow this corpus over time; the honest way to raise the number is to fix the
rules the corpus indicts, not to curate the corpus to pass. When a rule fix
legitimately improves the score, `TestPrecisionSuiteBaseline` tells you to
refresh `baseline.json`.

## Go coverage: what's caught, what's still open

Adding realistic Go samples surfaced **six honest false negatives** (tier 1) then
**four more** (tier 2), and the Go taint model has since closed all ten. nox's
taint catalog (`core/taint/data/catalog.json`) now carries a `go` language block,
and `core/taint/engine/extract_go.go` does AST-precise extraction (built on
`go/ast`, not the line recognizer Python/JS use — nox is itself Go, so the pure-Go
stdlib parser is free, precise, and deterministic; see `docs/design/go-taint.md`).
All ten Go dataflow vulnerabilities now fire (six tier-1 injection/traversal/SSRF/
deserialization/SSTI classes, plus tier-2 reflected XSS-to-response and
container-level taint); the secret regexes were already language-agnostic, so Go
secrets were true positives throughout. What nox catches in Go today:

| Vuln class | Go sink (sample) | Fires | CWE |
| --- | --- | --- | --- |
| Command injection | `exec.Command("sh","-c", userInput)` | TAINT-002 | CWE-78 |
| SQL injection | `db.Query("… WHERE x='" + userInput + "'")` | TAINT-001 | CWE-89 |
| Path traversal | `os.ReadFile(filepath.Join(base, userInput))` | TAINT-004 | CWE-22 |
| SSRF | `http.Get(userURL)` | TAINT-006 | CWE-918 |
| Unsafe deserialization | `gob.NewDecoder(r.Body).Decode(&v)` | TAINT-005 | CWE-502 |
| SSTI | `text/template … Parse(userInput)` | TAINT-003 | CWE-1336 |
| Reflected XSS (Fprintf) | `fmt.Fprintf(w, "<div>%s</div>", userInput)` | TAINT-003 | CWE-79 |
| Reflected XSS (Write) | `w.Write([]byte("<b>"+userInput+"</b>"))` | TAINT-003 | CWE-79 |
| Reflected XSS (bypass) | `template.HTML(userInput)` → response | TAINT-003 | CWE-79 |
| Container taint | `m["c"]=userInput; …exec(m["c"])` | TAINT-002 | CWE-78 |

### Go coverage — tier-2 gaps, now closed

A second tier of Go samples carried four honest false negatives as annotated
ground truth, dropping recall to 0.89. They have since been closed by building the
engine (not curating the corpus), returning recall to 1.00:

| Sample (line) | What flows | Fires now | How it was closed |
| --- | --- | --- | --- |
| `tp_xss_response.go` — `greetPrintf` (`fmt.Fprintf(w, "<div>%s</div>", name)`) | request query → response writer as HTML | **TP** | `fmt.Fprintf`/`Fprint`/`Fprintln` + `io.WriteString` added as `TAINT-003` xss sinks (CWE-79); gated by taint only |
| `tp_xss_response.go` — `greetWrite` (`w.Write([]byte("<b>"+user+"</b>"))`) | request form value → `w.Write` as HTML | **TP** | `w.Write` added as an xss sink, gated on a co-located string LITERAL (the reflected-HTML `[]byte("…"+user)` shape) so a bare `w.Write(out)` of command/file output does not over-fire |
| `tp_xss_response.go` — `greetAutoescapeBypass` (`template.HTML(comment)`) | request query → `html/template` via the `template.HTML()` escape hatch | **TP** | `template.HTML(tainted)` modeled as an **auto-escape-bypass** xss sink, distinct from safe `html/template` `Execute` (which is deliberately NOT a sink, keeping `clean_html_autoescape.go` clean) |
| `tp_container_taint.go` — `runMap` (`m["c"]=user; …m["c"]`) | request value → **map value** → command sink | **TP** | **container-level taint**: an assignment whose LHS is an index (`m["c"]`), selector (`obj.Field`), star, or paren target now taints the BASE identifier, so writing one key taints the whole container and a later read of it is tainted |

The two closely-related flows the variable-level engine already reached
(`tp_field_taint.go`; `tp_container_taint.go` — `runSlice`) are now *robustly*
correct rather than incidentally caught: the same container-level base
attribution makes a struct-field or slice-element write taint the container
directly.

Still-open limits (no sample yet, the next indictment when one lands):

- **Key-level container precision.** The container fix is container-*level*, a
  sound over-approximation: writing `m["a"]` taints all of `m`, so a later read of
  a *different, clean* key `m["b"]` is treated as tainted. Key/element-level
  precision (tracking which key is tainted) would tighten this but risks recall;
  not modeled.
- **XSS write-sink receiver typing.** The `w.Write` sink matches the `.Write`
  method name (AST-only), not a proof the receiver is an `http.ResponseWriter`; a
  `bytes.Buffer.Write` of tainted-but-not-reflected bytes with an inline HTML
  literal could in principle over-fire (the literal gate makes this unlikely).
- **Reflection-based sinks** and **cross-file Go flow** (the taint-analysis
  plugin's territory). The extraction is AST-precise but stays **AST-only** (no
  `go/types`): method sinks like `.Query`/`.Exec`/`.Decode`/`.Write` are matched
  by method name, not by proving the receiver's type.

This corpus carries the annotated ground truth, so the day a gap gets a sample,
the number tells the truth — the measure → build → re-measure loop, now running on
Go across two tiers.
