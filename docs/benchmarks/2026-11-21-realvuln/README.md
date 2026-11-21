# RealVuln: 203 real applications, Python, JS/TS and Java

Measured 2026-11-21. nox 1.70.0, and the same build with the SEC-161 fix of
#1127, against [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark)
v3.1.1 (commit `0152445`, ground-truth hash `sha256:a5160afd…`). RealVuln is an
outside benchmark: 203 applications at pinned commits, 7,115 hand-labelled
vulnerabilities and 283 labelled false-positive traps (all traps are in the
Python repos), described in [arXiv 2604.13764](https://arxiv.org/abs/2604.13764).
It publishes the raw output of every scanner it scores, so the comparison below
uses their runs of the other tools, not ours.

## Method

- A finding matches a label when the file is equal, its CWE is in the label's
  `acceptable_cwes`, and its line is within the label's range ±10, also against
  the label's `acceptable_locations`. Each label is consumed once; vulnerable
  labels win over traps. A finding with N CWEs is N findings, as RealVuln's own
  Semgrep parser does. Every finding that matches nothing is a false positive,
  including findings in classes RealVuln does not label.
- [`scripts/score_nox.py`](scripts/score_nox.py) re-implements RealVuln's
  `scorer/matcher.py` rather than running it. It reproduces RealVuln's
  published Semgrep scores from their published Semgrep output: F3 10.0 over
  all repos and 12.2 on JS/TS, exactly; 7.3 against 7.4 on Python.
- nox runs offline (`nox scan <repo> --offline --format json`), default
  configuration, no rule tuned to a benchmark file. No repo carries a
  `.nox.yaml` or baseline. [`clone.sh`](scripts/clone.sh) fetches each repo at
  its manifest commit, [`scan.sh`](scripts/scan.sh) scans them,
  [`ab.sh`](scripts/ab.sh) re-scans a list with a second binary.
- F3 weights recall 9× over precision; it is RealVuln's headline metric.
  Scores are micro-averaged over all labels.

## Result

| | precision | recall | F2 | F3 |
|---|---:|---:|---:|---:|
| **all 203**, nox 1.70.0 | 0.033 | 0.079 | 6.2 | 6.9 |
| **all 203**, with #1127 | 0.057 | 0.079 | 7.3 | 7.6 |
| Python (66), with #1127 | 0.187 | 0.120 | 12.9 | 12.4 |
| JS/TS (74), with #1127 | 0.059 | 0.092 | 8.3 | 8.7 |
| Java (63), with #1127 | 0.025 | 0.043 | 3.7 | 4.0 |

RealVuln's published runs of the other tools, same matcher:

| | Python F3 | JS/TS F3 | Java F3 | all F3 |
|---|---:|---:|---:|---:|
| nox, with #1127 | 12.4 | 8.7 | 4.0 | 7.6 |
| Semgrep (`--config auto`) | 7.4 | 12.2 | not run | 10.0 (140 repos) |
| SonarQube | 14.4 | not run | not run | — |
| Claude Sonnet 5, agentic | 52.8 | 35.3 | 24.4 | 35.5 |
| GPT-5.6 Sol, Codex CLI | 77.8 | 72.1 | — | 74.7 (140 repos) |
| Kolega DevSec Max (the benchmark's authors) | 86.4 | 82.7 | 61.6 | 73.7 |

nox is in the rule-based tier with Semgrep and SonarQube, where the paper puts
all rule-based tools: ahead of Semgrep on Python, behind it on JS/TS, behind
SonarQube on Python. The LLM-based scanners are a different tier on this
benchmark, by 3–10×.

## What the false positives are

1.70.0 produced 16,481 unmatched findings. Before #1127, 8,872 of them were
SEC-161, and 7,241 of those were strings of random CJK characters in mock data
(`realvuln-jeecgboot`, one 6.9 MB file) and in Japanese and Chinese translation
files (`juice-shop` i18n). #1127 rejects an entropy candidate that carries a
non-ASCII character; the A/B over the 50 repos where SEC-161 fired moved only
SEC-161, and none of its 17 true positives.

After #1127, 9,242 remain. The largest sources:

| rule | unmatched | matched | what it is |
|---|---:|---:|---|
| DATA-001 | 2,176 | 3 | email addresses in seed data, migrations, a committed `node_modules` README |
| SEC-161 | 1,633 | 17 | entropy candidates; 1,111 in `ofbiz-framework` XML |
| SEC-080 | 807 | 44 | |
| TAINT-004 | 458 | 58 | |
| IAC-121–124 | 860 | 0 | mostly Java repos |

Not every unmatched finding is wrong: the matcher charges a correct report in a
class RealVuln does not label (an email address, a container setting) the same
as a wrong one. Restricting nox to findings whose CWE appears anywhere in the
ground truth changes precision from 0.057 to 0.060, so that is not where the
gap is. 249 findings come from `node_modules/` committed into two repos.

## What nox misses

Most missed labels are classes no pattern or taint rule expresses: missing or
wrong authorisation (CWE-639 414, CWE-862 289, CWE-840 222), no brute-force
limit (CWE-307 258), information exposure (CWE-200 216, CWE-209 177), mass
assignment (CWE-915 177).

On the injection classes nox has taint rules for, recall is 22%:

| CWE | found | labelled | recall |
|---|---:|---:|---:|
| CWE-89 SQL injection | 32 | 151 | 21% |
| CWE-78 OS command | 45 | 186 | 24% |
| CWE-79 XSS | 29 | 251 | 12% |
| CWE-22 path traversal | 40 | 155 | 26% |
| CWE-918 SSRF | 28 | 184 | 15% |
| CWE-94 code injection | 36 | 117 | 31% |
| CWE-502 deserialization | 29 | 92 | 32% |
| CWE-611 XXE | 32 | 109 | 29% |
| CWE-601 open redirect | 39 | 136 | 29% |
| CWE-798 hard-coded credential | 135 | 365 | 37% |
| CWE-328 weak hash | 25 | 31 | 81% |

These are the next measurements to take apart, one class at a time: each
missed label names a file and line, so each is a reproducible counterexample.

## Reproduce

```bash
B=~/.local/share/nox-realvuln
git clone --depth 1 https://github.com/kolega-ai/Real-Vuln-Benchmark $B/rvb
python3 -I -c "import json;m=json.load(open('$B/rvb/benchmark-manifest.json'));print(''.join(f\"{k} {r['repo_url']} {r['commit_sha']} {r['language']}\n\" for k,r in sorted(m['repos'].items())),end='')" > $B/repos.tsv
go build -o $B/nox ./cmd/nox
scripts/clone.sh $B && scripts/scan.sh $B
python3 -I scripts/score_nox.py $B/rvb $B/results $B/repos.tsv $B/score.json
# RealVuln's published Semgrep runs, to check the scorer:
python3 -I scripts/score_nox.py $B/rvb $B/rvb/scan-results $B/repos.tsv $B/semgrep.json semgrep
```

A full scan of the 203 repos takes several hours on one machine; `scan.sh`
runs one repo at a time and waits while the 1-minute load is 25 or more.
