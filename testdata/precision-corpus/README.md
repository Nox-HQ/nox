# Precision corpus

A **labeled corpus** for measuring nox's SAST precision and recall. Each file is
a small source sample; every finding a scan *should* produce is declared inline,
on the line that should fire, so the ground truth lives right next to the code it
describes.

Run the scorer with:

```
nox bench --precision testdata/precision-corpus
nox bench --precision testdata/precision-corpus --json
nox bench --precision testdata/precision-corpus --min-precision 0.9   # exit 1 if any rule scores below
```

## The annotation format

Put a `nox-expect` annotation in a comment **on the same line** that should
produce the finding. The keyword is followed by one or more rule IDs, separated
by commas and/or spaces:

```python
access_key = "<your-aws-access-key-id>"  # nox-expect: SEC-001 SEC-508
```

```javascript
const p = system + userInput;  // nox-expect: AI-002
```

Rules:

- **Same-line anchoring.** The annotation must sit on the line the finding
  targets. The scorer matches a finding to an expectation when the rule IDs and
  file paths agree and the expectation's line falls within the finding's
  `[StartLine, EndLine]` range.
- **List every rule that should fire on that line.** One line can trip several
  overlapping detectors (an AWS key id fires two AWS-key rules). List them all;
  a rule that fires but isn't listed counts as a false positive.
- **Clean samples carry no annotations.** A file with zero `nox-expect`
  annotations asserts that a scan produces **no findings** on it. Any finding on
  a clean file is a false positive. Use clean samples to pin down precision on
  patterns a naive rule might over-flag (e.g. a base64 blob that looks
  high-entropy but is public image data).
- **Documentation is ignored.** `.md`, `.mdx`, `.markdown`, `.rst`, and `.txt`
  files (including this README) are never parsed as samples, so annotation
  examples in prose don't leak into the ground truth.

## How scoring works

For each rule the scorer computes, comparing scan findings against expectations:

- **TP** (true positive) — a finding that matches an expectation.
- **FP** (false positive) — a finding with no matching expectation (including a
  duplicate finding for an already-satisfied expectation).
- **FN** (false negative) — an expectation no finding satisfied.

From those: `precision = TP/(TP+FP)`, `recall = TP/(TP+FN)`, and
`F1 = 2·P·R/(P+R)`. The per-rule table is sorted worst-precision-first so the
rules most worth fixing surface at the top; an overall roll-up sums every rule.

## The samples

| File | Kind | Expected |
|---|---|---|
| `hardcoded_secret.py` | true positive | SEC-001, SEC-508 (hardcoded AWS access key id) |
| `prompt_concat.py` | true positive | AI-002 ×2 (user input concatenated into an LLM prompt) |
| `code_injection.py` | true positive | AI-049 (untrusted input into `eval`) |
| `clean_icon.py` | clean | none (base64 PNG that a naive entropy rule might over-flag) |
| `clean_config.py` | clean | none (env-var secrets, structured prompt messages) |

## Adding samples

1. Write a small, self-contained source file that exercises exactly the pattern
   you want to measure.
2. Add a `nox-expect: <RuleID>` annotation on each line that should fire — or
   none, to add a clean sample.
3. Run `nox bench --precision testdata/precision-corpus` and confirm the new
   rows read as you intended (a surprise FP or FN means either the sample or the
   rule needs work — which is the whole point of the harness).
