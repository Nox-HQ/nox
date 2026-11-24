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

Development baseline (nox at #1128): F3 9.0 overall (Python 14.7, JS/TS 10.3,
Java 4.7). An earlier version of this line gave 10.3 overall, which is the
JS/TS figure. After #1132, #1134 and the SSRF URL argument: 9.3 overall
(Python 14.7, JS/TS 10.9, Java 4.9). With framework request sources (NestJS
decorators, Python route parameters, Next.js server actions): 10.2 (Python
17.1, JS/TS 11.7, Java 4.9). With the sinks the development split's
misses named (needle, Fastify and Next.js redirects, FastAPI responses, Java
Files and java.io writers, promisified exec, ProcessBuilder.command): 10.6
(Python 18.1, JS/TS 12.4, Java 4.9). With the application-configuration rules
(debug mode, CORS from any origin, unverified JWT): 11.7 (Python 19.2, JS/TS
13.1, Java 6.2). With the cookie-flag rules: 13.1 (Python 19.8, JS/TS 16.2,
Java 6.9); held-out 8.8 -> 9.9. With hard-coded signing keys: 15.1 (Python 22.8, JS/TS
20.1, Java 6.9); held-out 11.2. Recall by class: injection 24.4%, crypto/secrets/config 12.3%,
information exposure 0.5%, authentication/session, authorization, business
logic and mass assignment 0.

## M1 gate, 2026-11-22

nox at `2eeb5af` (#1147), the same offline default configuration, every repository
rescanned with a build of that commit. The plan's M1 milestone ("catalog and noise,
current architecture") closes here. Held-out labels were not read between #1128 and
this gate; they were scored at #1128's results only now, for the comparison.

| | dev F3 | held-out F3 | all 203 F3 |
|---|---:|---:|---:|
| nox at #1128 | 9.0 | 5.8 | — |
| **nox at #1147** | **15.4** | **11.5** | **14.1** |

| nox at #1147 | precision | recall | F3 |
|---|---:|---:|---:|
| dev, Python | 0.296 | 0.225 | 23.1 |
| dev, JS/TS | 0.205 | 0.212 | 21.1 |
| dev, Java | 0.052 | 0.072 | 6.9 |
| held-out, Python | 0.374 | 0.211 | 22.1 |
| held-out, JS/TS | 0.083 | 0.120 | 11.5 |
| held-out, Java | 0.027 | 0.065 | 5.7 |

Against RealVuln's published Semgrep runs (`--config auto`), on the repositories
Semgrep was run on (Python and JS/TS; it was not run on Java), same matcher, same
split:

| Python + JS/TS | nox at #1128 | nox at #1147 | Semgrep |
|---|---:|---:|---:|
| dev (97 repos) | 12.3 | **22.0** | 10.7 |
| held-out (43 repos) | 7.6 | **15.9** | 8.7 |

The held-out gain (7.6 to 15.9) is about the same size as the development gain (12.3
to 22.0), so the changes generalise rather than fit the development labels. Held-out
JS/TS is the weakest cell (11.5 against 21.1 on dev): its unmatched findings are the
next place to look, at the M2 gate.

Recall by vulnerability class, dev / held-out: injection 30.7% / 22.4%,
crypto/secrets/config 31.2% / 32.0%, authentication/session 4.2% / 2.6%, information
exposure 3.0% / 0.4%; authorization, business logic and mass assignment 0 on both.
The zeros are the M3 classes; a deterministic scanner reports them only where the
framework states the rule.

What moved it, each measured on all 203 repositories and read before it merged:
SQL sinks and the literal-allowlist select (#1132, #1134), the SSRF URL argument
(#1138), framework request sources (#1140), sinks by class (#1142), the
application-configuration analyzer (#1144–#1146: debug mode, CORS from any origin,
unverified JWT, cookie flags, hard-coded signing keys), and dropping code-pattern
findings in committed dependency trees and e-mail addresses in seed data (#1147).
Decided at this gate: reporting a flow at the sink inside a helper instead of at its
call site moves to M2, with cross-file summaries, so every such fingerprint changes
once. On the current engine it could recover at most 8 development labels.

Not changed, deliberately: the Dockerfile hygiene rules IAC-121..124 report 860
unmatched findings and match no label. RealVuln does not label that class; that is
not evidence against the rules.

## M2 gate, 2026-11-23

nox at `b22b660` (after #1149–#1158: tree-sitter front ends for Python, JS/TS and
Java, cross-file summaries, injected-service resolution, the work-counted parse
budget, route-reachable parameter SQL), the same offline default configuration,
all 203 repositories rescanned with a build of that commit. Held-out labels were
not read between the M1 gate and this one.

**The M2 targets are not met.** The milestone asks for injection recall of at least
45% and an overall F3 of at least 20, on both splits:

| | target | dev | held-out | M1 gate dev / held-out |
|---|---:|---:|---:|---:|
| F3 | ≥ 20 | **17.0** | **12.8** | 15.4 / 11.5 |
| injection recall | ≥ 45% | **37.0%** | **27.8%** | 30.7% / 22.4% |

All 203 repositories: F3 14.1 → 15.5.

| nox at `b22b660` | precision | recall | F3 |
|---|---:|---:|---:|
| dev, Python | 0.295 | 0.225 | 23.1 |
| dev, JS/TS | 0.216 | 0.239 | 23.6 |
| dev, Java | 0.065 | 0.092 | 8.8 |
| held-out, Python | 0.375 | 0.213 | 22.2 |
| held-out, JS/TS | 0.098 | 0.149 | 14.2 |
| held-out, Java | 0.031 | 0.075 | 6.6 |

Against RealVuln's published Semgrep runs, on the repositories Semgrep was run on,
same matcher:

| Python + JS/TS | nox at M1 | nox at M2 | Semgrep |
|---|---:|---:|---:|
| dev (97 repos) | 22.0 | **23.4** | 10.7 |
| held-out (43 repos) | 15.9 | **17.5** | 8.7 |

The held-out gain (+1.3 F3, +5.4 points of injection recall) tracks the dev gain
(+1.6, +6.3), so the M2 work generalises; it is smaller than M1's. Java is still
the weakest language on both splits, and held-out JS/TS is still well below dev.

Recall by class, dev / held-out: injection 37.0% / 27.8%, crypto/secrets/config
31.2% / 32.0%, authentication/session 4.2% / 2.6%, information exposure 3.0% /
0.4%; authorization, business logic and mass assignment 0 on both, as at M1. Those
are the M3 classes.

**What changed on dev, by rule** (M1 gate → M2 gate): the taint rules gained 55
matched findings and 129 unmatched. SQL (TAINT-001) +9 matched / +11 unmatched,
command (TAINT-002) +12 / +2, path (TAINT-004) +15 / +41, code (TAINT-005) +6 / +1,
TAINT-006 +9 / +4, redirect (TAINT-007) +2 / 0, XSS (TAINT-003) +2 / +70. No
other rule among the 40 most frequent moved.

**The new unmatched XSS findings, read.** 85 unmatched TAINT-003 findings on dev
are new by location; 21 are in files that already had one (moved by the
location change of #1154 or by multi-line statements), 64 are in files that had
none. 26 of those 64 are the lessons of an XSS training application,
`out.write(htmlOutput)` after `htmlOutput += "..." + searchTerm`, with
`searchTerm` read from `request.getParameter`. These are real reflected XSS, and
the benchmark labels no XSS in that repository; the Java front end (#1153) now
reads the statement that spans lines. 8 are Fastify `reply.status(201).send({
message })`, an object serialized as JSON, which is not an HTML sink; that is a
known false-positive class and the next XSS precision fix. The rest are mixed,
among them a Handlebars `compile` of user-authored text, a real template
injection reported under the XSS rule.

**Rule-diff corpus** (26 repositories, v1.70.0 against `b22b660`, run locally
because the CI job's path filter skipped #1156 and #1157): 5 rules changed, every
drop accounted for in `scripts/rule-deltas.json` (DATA-001 20 → 14, #1147
seed-data narrowing; TAINT-004 4 → 3, #1154 location merge). The increases, read:
command-line arguments and environment variables reaching `os.path.join` in a
project's own CLI tools (certbot, five flows through helper chains the cross-file
pass now follows; the class existed at v1.70.0), a value deserialized from a
credentials file reaching `open` (anthropic-sdk-python), and a request body passed
to an LLM's `messages.create` (hackathon-starter, TAINT-AI-001), which is real.

**OWASP Benchmark** (same scorers, same scan roots; see
[the OWASP document](../2026-09-28-owasp/README.md#m2-gate-2026-11-23)): Java
47.9 → **56.3**, Python 56.1 → **52.8**. The Python loss is the Python tree-sitter
front end (#1151): the same binary with that front end switched off
(`NOX_TAINT_TREESITTER=javascript,java`) scores 56.1 again, category for category.
That front end passed its development-split A/B, so the idioms it loses are not
in that split. Per the plan the benchmark is not read case by case; the
follow-up is a differential of the two Python segmenters on development-split
files, to find the statement shapes they disagree on.

**Decided at this gate.** M2's engine work is done and measured; its targets are
not reached, and the shortfall is not in the engine the milestone built. Recall
is bounded by sinks the catalog does not recognise (455 of 822 dev injection
misses at the last count) and by Java, whose F3 is a third to a half of the
other languages' on both splits. Those, the Python front-end regression and the Fastify
XSS class are the next work, before M3's new classes.

## M2 gap-close gate, 2026-11-24

nox at `0cc6f49` (after #1159–#1173: the Python tree-reader fix, Java SSRF,
template/expression injection and XXE sinks, libxmljs XXE, template-file XSS
XSS-001, log injection TAINT-013, every sink a helper reaches, secret settings
with a literal default APPCFG-007, Java try-with-resources, Java open redirect
sinks, upload file names as sources, Spring CSRF switched off APPCFG-008), the
same offline default configuration, all 203 repositories rescanned with a build
of that commit. Held-out labels were not read between the M2 gate and this one;
the M2 gate's results reproduce exactly under the same scorer (17.0 / 12.8).

**The M2 targets are met on dev and not on held-out:**

| | target | dev | held-out | M2 gate dev / held-out |
|---|---:|---:|---:|---:|
| F3 | ≥ 20 | **21.3** | **15.2** | 17.0 / 12.8 |
| injection recall | ≥ 45% | **51.2%** | **35.4%** | 37.0% / 27.8% |

All 203 repositories: F3 15.5 → 19.2.

| nox at `0cc6f49` | precision | recall | F3 |
|---|---:|---:|---:|
| dev, Python | 0.306 | 0.246 | 25.1 |
| dev, JS/TS | 0.210 | 0.258 | 25.2 |
| dev, Java | 0.091 | 0.182 | 16.5 |
| held-out, Python | 0.368 | 0.218 | 22.7 |
| held-out, JS/TS | 0.101 | 0.163 | 15.4 |
| held-out, Java | 0.049 | 0.130 | 11.2 |

Against RealVuln's published Semgrep runs, on the repositories Semgrep was run
on, same matcher (Semgrep's figures and repository counts reproduce):

| Python + JS/TS | nox at M1 | nox at M2 | nox now | Semgrep |
|---|---:|---:|---:|---:|
| dev (97 repos) | 22.0 | 23.4 | **25.2** | 10.7 |
| held-out (43 repos) | 15.9 | 17.5 | **18.4** | 8.7 |

**Generalisation.** Dev gained 4.3 F3 and 14.2 points of injection recall;
held-out gained 2.4 and 7.6, about half. Java generalised best (held-out 6.6 →
11.2, dev 8.8 → 16.5). Held-out JS/TS moved least (14.2 → 15.4 against dev 23.6
→ 25.2) and is again the weakest held-out cell after Java. By rule on held-out:
XXE (TAINT-010) +17 matched / +1 unmatched, the secret-default rule APPCFG-007
+13 / +54, log injection +10 / +103, SSRF +7 / +11, XSS +6 / +4, CSRF
APPCFG-008 +5 / +7, open redirect +3 / +4; template-file XSS matched nothing on
held-out (+36 / +36 on dev). Log injection's held-out precision (10 of 113) is
well below its dev precision (42 of 855); both are request data written to a
log, so the difference is the labels' density, not a different finding.

Recall by class, dev / held-out: injection 51.2% / 35.4%, crypto/secrets/config
34.9% / 35.0%, authentication/session 6.8% / 4.4%, information exposure 4.5% /
0.9%; authorization, business logic and mass assignment 0 on both. Those are
the M3 classes.

**Rule-diff corpus** (26 repositories, run by CI on every PR): 8 rules changed
against v1.70.0, each read on #1168 and unchanged since: the new log-injection
rule (hackathon-starter 0 → 22, aws-cloudformation-templates 0 → 1); certbot
+1 command / +5 path flows through helper chains, from command-line arguments
and environment variables in its release tools, exposed when a helper's
second sink stopped being cut; the drops accounted for in
`scripts/rule-deltas.json` (#1147, #1154).

**OWASP Benchmark** (same scorers and scan roots; see
[the OWASP document](../2026-09-28-owasp/README.md#m2-gap-close-gate-2026-11-24)):
Python **56.1** (the tree-reader regression fixed in #1161), Java 56.3 →
**56.4**.

**Decided at this gate:** for the maintainer. The dev targets are met; the
held-out ones are not, and held-out moved about half as far as dev. Either the
milestone closes on dev with the held-out shortfall recorded, and M3 starts; or
the held-out JS/TS and Java gaps are worked on first, from dev examples of the
same shapes, without reading held-out findings.

## Measured and rejected: dropping through-call flows

Most of the unmatched findings the framework sources added (#1140) are a
value that reached the sink only through a call that does not hand its
argument on: `html = this.reports.renderTicketSummary(user, id)`. A throwaway
variant that dropped every such flow (Flow.ThroughCall), scanned over all 203
repositories against #1140:

| rule | unmatched removed | matched lost |
|---|---:|---:|
| TAINT-004 path | 161 | 11 |
| TAINT-003 XSS | 136 | 4 |
| TAINT-007 redirect | 117 | 5 |
| TAINT-001 SQL | 43 | 9 |
| TAINT-005 | 3 | 28 |
| TAINT-002 command | 4 | 10 |
| all | 484 | 72 |

Development split F3 fell from 10.2 to 9.0. Kept only for XSS, path,
redirect and SSRF it is still estimated lower (about 9.9). F3 weights recall
9x: at the current precision (0.085) and recall (0.10), one matched finding is
worth about nineteen unmatched ones. A precision change pays here only when it
loses essentially no matched finding, so through-call noise needs a narrower
signal than the flag.
