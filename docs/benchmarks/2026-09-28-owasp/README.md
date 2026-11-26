# OWASP Benchmark: Python and Java

Measured 2026-09-28. nox against Semgrep's `p/default` ruleset (1.176.0) on the
two OWASP Benchmark projects, each a set of small web handlers labelled
vulnerable or not. The score per category is Youden's index, detection rate
minus false-positive rate: 100 finds every vulnerable case and flags no safe
one, 0 is no better than chance (or silence), and a negative score flags safe
cases more often than vulnerable ones. The average is over categories, as the
OWASP scorecard reports it.

A case counts as flagged when any finding in its file carries the category's
CWE. Both tools are scored the same way by the same scripts
([`scripts/`](scripts/)), with the CWE equivalences the scorecard uses (a weak
hash reported as CWE-327 or CWE-916 counts for CWE-328, CWE-338 for CWE-330).
nox runs offline with its default configuration; no rule was tuned to a
benchmark file. Semgrep runs `p/default` with metrics off.

| | nox | Semgrep `p/default` |
|---|---:|---:|
| Python, v1.42.0 | 10.9 | 10.7 |
| Python, v1.45.0 (after #752–#757) | 49.3 | 10.7 |
| **Python, v1.46.0** | **56.1** | 10.7 |
| Java, v1.44.0 | 14.1 | 34.9 |
| Java, v1.45.0 (after #763, #764, #766) | 39.6 | 34.9 |
| **Java, v1.46.0** | **48.2** | 34.9 |

## Python (BenchmarkPython 0.1, 1,230 cases)

Commit `f129148` of OWASP-Benchmark/BenchmarkPython.

| category | cases | v1.42.0 | v1.46.0 TPR / FPR | v1.46.0 | Semgrep TPR / FPR | Semgrep |
|---|---:|---:|---|---:|---|---:|
| weakrand | 326 | 0 | 100% / 0% | **100** | 0% / 0% | 0 |
| xpathi | 186 | 0 | 67% / 24% | **43** | 0% / 0% | 0 |
| pathtraver | 168 | 11 | 43% / 14% | **29** | 3% / 2% | 1 |
| hash | 151 | 100 | 100% / 0% | **100** | 52% / 0% | 52 |
| xss | 89 | 0 | 48% / 9% | **40** | 0% / 28% | −28 |
| deserialization | 54 | 28 | 61% / 3% | 58 | 100% / 33% | **67** |
| codeinj | 53 | 5 | 60% / 30% | **30** | 100% / 100% | 0 |
| securecookie | 39 | 0 | 100% / 0% | **100** | 100% / 100% | 0 |
| trustbound | 37 | 0 | 0% / 0% | 0 | 0% / 0% | 0 |
| redirect | 34 | 9 | 69% / 33% | **36** | 8% / 5% | 3 |
| ldapi | 29 | 0 | 62% / 0% | **62** | 0% / 0% | 0 |
| xxe | 28 | 0 | 62% / 5% | **57** | 0% / 0% | 0 |
| cmdi | 20 | 0 | 69% / 0% | **69** | 54% / 100% | −46 |
| sqli | 16 | 0 | 60% / 0% | 60 | 100% / 0% | **100** |
| **average** | | **10.9** | | **56.1** | | **10.7** |

What moved it, each change measured on real repositories as well as here:

| change | PR | effect here |
|---|---|---|
| Python taint: cursor receivers, weak updates in branches, container stores, parameterised `execute` | v1.43.0 | sqli 0 → 40, cmdi 0 → 23 |
| `CRYPTO-002` for Python | #752 | weakrand 0 → 100 |
| XPath / LDAP sinks (`TAINT-008`/`009`) | #753 | xpathi 0 → 22, ldapi 0 → 41 |
| XXE sink (`TAINT-010`) | #754 | xxe 0 → 42 |
| `HARDEN-003` cookie `secure=False` | #755 | securecookie 0 → 100 |
| Flask route returns as XSS sinks; `x += y` carries taint | #756 | xss 0 → 23; cmdi, deserialization, xpathi, ldapi, redirect, pathtraver up |
| Constant-condition branch pruning | #757 | FPR down in eight categories, no detection rate moved |
| Key-sensitive containers (literal keys) | #771 | 49.3 → 56.1: fewer false positives, and sqli 40% → 60% and cmdi 54% → 69% detection, since a constant store no longer overwrites a tainted key |

**trustbound stays at 0 by choice.** `TAINT-011` (untrusted data stored in the
session) exists but is opt-in: enabled, it finds 44% of these cases at a 42%
false-positive rate, and in real Flask code it fires on ordinary login flows.
**sqli and deserialization** trail Semgrep on detection (60% and 61% against its 100%); which idioms the missed cases use has not been analysed yet.

## Java (BenchmarkJava 1.2, 2,740 cases)

Commit `20cbf3d` of OWASP-Benchmark/BenchmarkJava, `src/main/java` scanned.
Measured first at v1.44.0 (14.1), then again after the Java work that
measurement prompted (2026-09-29).

| category | cases | v1.44.0 | v1.46.0 TPR / FPR | v1.46.0 | Semgrep TPR / FPR | Semgrep |
|---|---:|---:|---|---:|---|---:|
| sqli | 504 | 4 | 68% / 26% | **42** | 93% / 73% | 20 |
| weakrand | 493 | 0 | 100% / 0% | 100 | 100% / 0% | 100 |
| xss | 455 | 13 | 46% / 20% | 26 | 82% / 52% | **30** |
| pathtraver | 268 | 4 | 39% / 16% | **23** | 90% / 79% | 12 |
| cmdi | 251 | 10 | 63% / 26% | **38** | 93% / 87% | 6 |
| crypto | 246 | 55 | 55% / 0% | **55** | 0% / 0% | 0 |
| hash | 236 | 69 | 69% / 0% | 69 | 69% / 0% | 69 |
| trustbound | 126 | 0 | 0% / 0% | 0 | 52% / 42% | **10** |
| securecookie | 67 | 0 | 100% / 0% | 100 | 100% / 0% | 100 |
| ldapi | 59 | 0 | 63% / 25% | **38** | 96% / 88% | 9 |
| xpathi | 35 | 0 | 73% / 35% | **38** | 93% / 65% | 28 |
| **average** | | **14.1** | | **48.2** | | **34.9** |

What moved it, each also measured on Kafka, Keycloak, Jenkins and 90 GitHub
servlet files:

| change | PR | effect here |
|---|---|---|
| `CRYPTO-002` and `HARDEN-003` for Java | #763 | weakrand and securecookie 0 → 100 |
| `prepareStatement` was a SQL *sanitizer*; now a sink, with Spring `JdbcTemplate` and six more request sources | #764 | sqli 4 → 14 |
| Java branch model with constant pruning, multi-line method headers, container stores, standard JVM properties not sources | #766 | sqli 14 → 36, cmdi 11 → 32, pathtraver 6 → 18, xss 14 → 24 |
| Key-sensitive containers | #771 | 39.6 → 41.2 |
| XPath and LDAP sinks by declared type | #772 | xpathi 0 → 38, ldapi 0 → 38; 41.2 → 48.2 |

What remains: **trustbound** is opt-in in nox by design (see the Python section), and **xss** trails Semgrep, which reports most of the benchmark's writes at a 52% false-positive rate. On the injection categories nox scores higher with a lower detection rate than Semgrep, which reports 50–88% of the safe cases.

## Re-measured 2026-11-21

nox at `8cec485` (after #1134), same scorers, same scan roots. BenchmarkJava
moved from `20cbf3d` to `10dfcc5`. The commits between them change no test
case or expected result, and both suites have the same number of cases.

| | v1.46.0 | 2026-11-21 |
|---|---:|---:|
| Python | 56.1 | **56.1** |
| Java | 48.2 | **47.9** |

Every category matches v1.46.0 except Java sqli, which moved from 68% / 26%
(42) to 74% / 34% (40). The SQL work since then (parameter flows #1128, sinks
#1132) found more of the vulnerable cases and flagged more of the safe ones.
Per the deterministic-lead plan, this benchmark only reports and is not read
case by case; the precision on real code is gated by RealVuln's development
split.

## M2 gate, 2026-11-23

nox at `b22b660` (after the tree-sitter front ends #1151–#1153 and cross-file taint
#1154–#1155), same scorers, same scan roots, same suite commits as 2026-11-21.

| | 2026-11-21 | M2 gate |
|---|---:|---:|
| Python | 56.1 | **52.8** |
| Java | 47.9 | **56.3** |

**Java** rose in detection across the injection categories as cross-file and
multi-line flows were followed: sqli 93% / 40%, cmdi 93% / 41%, pathtraver 85% /
29%, ldapi 96% / 38%, xss 54% / 24% (TPR / FPR). False-positive rates rose with
them; the averages net to +8.4.

**Python** fell in seven categories, all on detection (xpathi 67% → 59%, ldapi
62% → 38%, codeinj 60% → 50%, cmdi 69% → 62%, deserialization 61% → 56%, xss
48% → 45%, pathtraver 43% → 40%), with false-positive rates slightly lower. The
same binary with the Python tree-sitter front end off
(`NOX_TAINT_TREESITTER=javascript,java`) reproduces 2026-11-21 exactly, so the
loss is that front end's (#1151). It passed its development-split A/B on
RealVuln, so these idioms are not in that split. This benchmark is not read case
by case (plan rules); the cause is to be found by a differential of the two
segmenters on development-split Python.

*Resolved.* The development-split differential found nothing (no tree-reader
loss there), so, by maintainer decision, the same differential ran on this
benchmark's sources at the level of statement shapes, with no labels or
per-case scores read. The readers produced the same statements on every file
but different units in 122, all around tab-indented `match` statements: the
tree reader read a match block, which the grammar starts on the header's row,
as a one-line body and over-indented each `case`. Fixed with a test of its own
(tabs and spaces); Python is back to **56.1**, every category as on 2026-11-21.

## M2 gap-close gate, 2026-11-24

nox at `0cc6f49`, same scorers and scan roots; BenchmarkPython at `f129148`,
BenchmarkJava at `10dfcc5` (the local clone).

| | M2 gate | now |
|---|---:|---:|
| Python | 52.8 → 56.1 (#1161) | **56.1** |
| Java | 56.3 | **56.4** |

Python is every category as on 2026-11-21. Java's change is path traversal
(85% / 29% → 92% / 35%, TPR / FPR), from upload file names and the added
`java.nio.file.Files` sinks (#1172); the other categories are as at the M2 gate.

## M3 gate, 2026-11-25

nox at `b68bccf`, same scorers and scan roots, same suite commits as the M2
gap-close gate (BenchmarkPython `f129148`, BenchmarkJava `10dfcc5`).

| | M2 gap-close | M3 gate | Semgrep `p/default` |
|---|---:|---:|---:|
| Python | 56.1 | **62.9** | 10.7 |
| Java | 56.4 | **56.4** | 34.9 |

**Python** rose in eight categories, mostly on detection, with false-positive
rates flat or slightly up (TPR / FPR, M2 gap-close → now):

| category | M2 gap-close | now |
|---|---|---|
| ldapi | 62% / 0% | 88% / 0% |
| redirect | 69% / 33% | 92% / 38% |
| cmdi | 69% / 0% | 85% / 0% |
| pathtraver | 43% / 14% | 57% / 16% |
| deserialization | 61% / 3% | 72% / 3% |
| xpathi | 67% / 24% | 76% / 27% |
| xss | 48% / 9% | 55% / 9% |
| codeinj | 60% / 30% | 70% / 39% |

**Java's** average is unchanged.

Per the plan this benchmark is scored and not read case by case, so which of
#1175–#1184 moved Python is not attributed here. Finding it would take scoring
builds between the two gates, not reading cases.

## Published deterministic baselines, recorded 2026-11-26

The M3 target is an OWASP Benchmark score above the best deterministic tool
published for it. These are the published numbers, with where each comes
from. "Pooled" is TPR − FPR over all cases; "category-averaged" is the mean
of the per-category scores, which is what `score_java.py` prints. nox at the
M3 gate, scored both ways: Java pooled **56.5** (TPR 76.5%, FPR 19.9%),
category-averaged 56.4.

**Java 1.2, full suite (2,740 cases)**

| tool | score | scoring | source | kind |
|---|---:|---|---|---|
| cognium-dev 4.9.13, no LLM | **73.5** (TPR 91.0, FPR 17.4) | pooled, expected CWE in the case's file | [cogniumhq/sast-benchmarks](https://github.com/cogniumhq/sast-benchmarks), suite `20cbf3d`, open scorer and raw output | vendor-run, reproducible |
| CodeQL 2.27.0 `java-security-extended` | 59.9 | same scorer | same repository | third-party run, reproducible |
| Semgrep OSS 1.177.0 `p/java` + `p/security-audit` | 47.9 | same scorer | same repository | third-party run, reproducible |
| FindBugs + FindSecBugs 1.4.6 | 39.1 | category-averaged | OWASP's published scorecard (2016–17) | OWASP-published |
| SonarQube Java 3.14 | 33.3 | category-averaged | OWASP's published scorecard | OWASP-published |
| Semgrep `p/default` (measured here) | 34.9 | category-averaged | this directory | measured here |

Higher vendor claims exist (Proscan and Fluid Attacks 100, Kiuwan and Xygeni
83.3, Conviso about 76.5) without published raw output, so they cannot be
reproduced and are not used as the target. The cognium row was checked in its
repository and the FindSecBugs and SonarQube rows in OWASP's scorecard HTML
(`scorecard/OWASP_Benchmark_Home.html` in BenchmarkJava) on 2026-11-26;
cognium's 2026-10-22 re-run of a later version scores 73.0.

Against the strongest reproducible deterministic number, **the M3 OWASP Java
target is not met**: 56.5 against 73.5, pooled on both sides. nox is above
every OWASP-published row and above CodeQL and Semgrep as measured on the
same scorer. By category, the distance is the trust-boundary category
(0 of 126 detected: TAINT-011, request data stored in a session, is opt-in by
design because the pattern is common and usually deliberate, and is
Python-only), the false-positive rates of sqli, cmdi, pathtraver,
ldapi and xpathi (35–55%), and XSS recall (54%) — read from category totals,
not from cases.

**Python 0.1 (1,230 cases).** OWASP publishes no scorecard for it, and no
independent run was found. Two deterministic tools publish full-suite
self-claims without independent reproduction: PandaWard (1.00 per-category
average, [docs/BENCHMARKS.md](https://github.com/ratomirjovanovic/pandaward/blob/main/docs/BENCHMARKS.md))
and VyQL (macro score 0.896, [benchmarks/RESULTS.md](https://github.com/vyprai/vyql/blob/main/benchmarks/RESULTS.md)).
PandaWard's document also scores Semgrep `p/default` 0.069, CodeQL 0.132 and
Opengrep with its own bundled rules 0.735. nox's 62.9 is above every
third-party-measured row; whether it is above "the best published" depends
on whether unreproduced self-claims count, and the plan takes reproducible
numbers only. Recorded as **no reproducible baseline**.

LLM-based tools (Kolega, Cyfendo, both above 85 on both suites by their own
reports) are not deterministic and are not compared.

## Java recall and helper precision, 2026-11-26

nox on this branch against main at `6432d3f`, same scorer, scan root
(`src/main/java`) and suite commit (`10dfcc5`). TPR / FPR per category:

| category | main | now |
|---|---|---|
| xss | 54% / 24% | 100% / 9% |
| crypto | 55% / 0% | 100% / 0% |
| sqli | 93% / 40% | 96% / 20% |
| cmdi | 93% / 41% | 100% / 16% |
| pathtraver | 92% / 35% | 94% / 15% |
| ldapi | 96% / 38% | 100% / 12% |
| xpathi | 100% / 55% | 100% / 10% |
| hash, weakrand, securecookie, trustbound | unchanged | unchanged |
| **category-averaged** | **56.4** | **79.7** |
| **pooled** | **56.5** (76.5 / 19.9) | **81.5** (90.0 / 8.5) |

Against the strongest reproducible deterministic baseline above,
cognium-dev's pooled 73.5 (TPR 91.0, FPR 17.4), **the M3 OWASP Java target
is met**: 81.5 pooled, at a lower detection rate than cognium's and less than
half its false-positive rate.

What moved it. Each change is a Java/Kotlin semantics change, probed first on
self-written servlets and then scored here per category:

- **Response writer sinks.** `append`, `printf` and `format` on
  `response.getWriter()` (inline, or a local assigned from it) are XSS
  sinks; on any other receiver they are `StringBuilder.append` and
  `String.format`, and stay silent.
- **HTML escapers as sanitizers.** ESAPI `encodeForHTML`, Commons Lang 2
  `escapeHtml`, OWASP Encoder `forHtmlContent`/`forHtmlAttribute` and
  `Jsoup.clean`. A decoder around an escaper in the same statement
  (`decodeForHTML(encodeForHTML(p))`) undoes it, and XSS stays.
- **A helper on an object constructed in place.** `new Helper().run(a, b)`
  with a no-argument constructor is now resolved to the file's own `run`, as
  `run(a, b)` and `this.run(a, b)` already were, so a helper that returns a
  constant is a barrier. This is most of the false-positive drop. A call on
  any other receiver, `thing.run(p)`, is no longer taken for the local `run`
  of the same name, which had made such calls barriers too.
- **CRYPTO-001 reads an algorithm held in a name.** A constant or a local
  assigned once, and `props.getProperty(key, fallback)` resolved from the
  project's `.properties` files, plus weak forms the literal pattern did not
  list (bare `"AES"`, which is ECB; DES-family key generators; MD2/MD4).

How the crypto false positives were found: a first cut took a
`getProperty` call's literal fallback as the algorithm and raised crypto's
FPR from 0% to 23%. Counting findings by reported algorithm across the
category, and `Cipher.getInstance` argument forms across the suite, showed
the fallback was the cause: it applies only when no properties file defines
the key. It is now used only when the scan sees the project's properties and
none defines the key. Under the `src/main/java` root the scan sees none, so
configured algorithms stay unknown, which is why hash stays at 69%. With the
root at `src/main`, the configured values are read: hash rises to 100% and
the pooled score to 84.3 (see below). The headline keeps the documented root.

| scan root | category-averaged | pooled |
|---|---:|---:|
| `src/main/java` (documented) | 79.7 | 81.5 |
| `src/main` (resources visible) | 82.5 | 84.3 |

OWASP Python is unchanged at 62.9.

## Limits

- The benchmarks are synthetic. A score here is evidence about a rule's
  premise, not about its precision on real code; every change listed above was
  also measured on real repositories, and several (the XSS sink's exclusion
  from `AGENTFLOW-002`, the cookie rule's skipping of framework signatures)
  exist because the real-code measurement disagreed with the benchmark.
- The Python benchmark is young (0.1) and its handlers repeat a small set of
  idioms, so a single engine fix can move a category a long way.
- File-level CWE matching credits a finding anywhere in the case's file.
  The same rule applies to both tools.

## Reproducing

```sh
git clone https://github.com/OWASP-Benchmark/BenchmarkPython   # f129148
git clone https://github.com/OWASP-Benchmark/BenchmarkJava     # 20cbf3d
(cd BenchmarkPython && nox scan . -offline -format json -output ../nox-py)
(cd BenchmarkJava && nox scan src/main/java -offline -format json -output ../nox-java)
(cd BenchmarkPython && semgrep scan --config p/default --json --metrics=off . > ../semgrep.json)
python3 scripts/score_python.py nox-py     # from the directory holding BenchmarkPython/
python3 scripts/score_java.py nox-java     # from the directory holding BenchmarkJava/
```

Each scorer reads `semgrep.json` from its working directory, so run Semgrep
into the matching directory for each benchmark.
