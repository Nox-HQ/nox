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

### SQL injection, taken apart

Of the 119 missed CWE-89 labels, 112 had no nox finding within 15 lines. Two
causes, both reproduced on the built binary:

- **No source in the file.** Taint needs one, and the commonest shape here is
  a DAO method that concatenates its own argument into the query while the
  request is parsed in another file. The summaries already knew which
  parameters reach a SQL sink; that was used only when a caller in the same
  file passed a source in. TAINT-001 now reports it at low confidence, when the
  parameter is combined with literal SQL text (not a pass-through, a
  placeholder, a receiver, a sibling argument, or a tagged template's bound
  value). An unguarded prototype added 116 unmatched findings, 113 of them
  JVM calls named `execute` or `createQuery` that are no query built from text.
- **A helper that binds its argument first had no summary.** The summary
  matched a flow by the variable read at the sink, so `q = "..." % name;
  cursor.execute(q)` was invisible to a caller's source. Every class.
- **Sinks not in the catalog:** Prisma `$queryRawUnsafe` (9 labels), Drizzle
  `sql.raw` (6), TypeORM `DataSource.query` (6), pg-promise `db.one`/`db.many`
  (5), JPA `createNativeQuery` (9), R2DBC `DatabaseClient.sql` (3). Added,
  with Spring `JdbcTemplate.query` and Kotlin's Spring query methods: TAINT-001
  +17 matched, +12 unmatched (JS/TS F3 8.9 -> 9.3, Java 4.3 -> 4.5). Of the
  12 unmatched, read one by one: 6 are the generated apps' safe twins, which
  pick the column from a literal allowlist (`ALLOWED.has(x) ? x : "createdAt"`,
  `SORT.getOrDefault(k, "created_at")`) and bind the value; 4 are real SQL
  injection the ground truth does not label as SQL injection (the request
  value is interpolated into the query: api.ts:1680, borrowers.ts:291,
  matter-ledger.ts:10, products.ts:357); 1 is a real flow reported at the
  call site of the helper the label names (leases.ts:185); 1 interpolates a
  `List<Integer>` (openmrs). The allowlist select is now recognized.

| | TP | FP | F3 all | Python | JS/TS | Java |
|---|---:|---:|---:|---:|---:|---:|
| with #1127 | 560 | 9,242 | 7.6 | 12.4 | 8.7 | 4.0 |
| plus parameter flows and the summary fix | 585 | 9,290 | 7.9 | 13.0 | 8.9 | 4.3 |

TAINT-001 gained 25 matched and 39 unmatched findings. Read one by one, the
unmatched are string-built queries the benchmark does not label: AltoroJ's
`DBUtil` (its own comment says "BAD"), Fineract and Mifos `jdbcTemplate` calls
already carrying `// NOSONAR`, JPQL assembled by concatenation.

The summary fix first added 26 unmatched findings in other classes and 9 on the
rule-diff corpus, none a clear true positive: the forward pass keeps a value
bound through any call tainted, and summarized, that reported a database row
written as JSON as the request text it was filtered by (chronos) and an argv
list as a shell command (certbot). A summary now hands on only the parameter
or a value built from it by copying and string operations; that cost no
matched finding and left 9 in other classes. Of those, WebGoat's SQL injection
lessons are real flows reported at the call into the helper, where RealVuln
labels the sink inside it; where an interprocedural finding is located is a
separate decision, as moving it changes every such fingerprint. Five are one
SSRF defect that predates this: with `requests.post(url=url, data=body)` the
URL is a keyword argument, the slot check falls back to every argument, and a
value in the body reads as the URL.

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

## Development and held-out split

`scripts/split.tsv` is frozen (seed 20261121, `scripts/split.py`) and is never
regenerated. It holds out 63 of 203 repositories (2,618 of 7,578 vulnerable
labels, 34.5%), stratified by language group and authorship, and split by
family: the same generated application written by several models, or a fork
with its upstream, always lands on one side. Development labels may be read to
find defects; held-out labels are scored only at milestone gates.

    score_nox.py rvb <results> repos.tsv out.json nox <repos> --split scripts/split.tsv --side dev --by-class
    score_nox.py rvb - repos.tsv out.json published:semgrep    # any tool RealVuln publishes

Development baseline (nox at #1128): F3 10.3 overall (Python 14.7, JS/TS 10.3,
Java 4.7). Recall by class: injection 24.4%, crypto/secrets/config 12.3%,
information exposure 0.5%, authentication/session, authorization, business
logic and mass assignment 0.
