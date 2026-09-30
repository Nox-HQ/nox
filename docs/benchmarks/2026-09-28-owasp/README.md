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
