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
| **Python, `main` after #752–#757** | **49.3** | 10.7 |
| **Java, `main`** | **14.1** | **34.9** |

## Python (BenchmarkPython 0.1, 1,230 cases)

Commit `f129148` of OWASP-Benchmark/BenchmarkPython.

| category | cases | v1.42.0 | `main` TPR / FPR | `main` | Semgrep TPR / FPR | Semgrep |
|---|---:|---:|---|---:|---|---:|
| weakrand | 326 | 0 | 100% / 0% | **100** | 0% / 0% | 0 |
| xpathi | 186 | 0 | 61% / 23% | **38** | 0% / 0% | 0 |
| pathtraver | 168 | 11 | 34% / 14% | **20** | 3% / 2% | 1 |
| hash | 151 | 100 | 100% / 0% | **100** | 52% / 0% | 52 |
| xss | 89 | 0 | 45% / 10% | **35** | 0% / 28% | −28 |
| deserialization | 54 | 28 | 61% / 3% | 58 | 100% / 33% | **67** |
| codeinj | 53 | 5 | 60% / 33% | **27** | 100% / 100% | 0 |
| securecookie | 39 | 0 | 100% / 0% | **100** | 100% / 100% | 0 |
| trustbound | 37 | 0 | 0% / 0% | 0 | 0% / 0% | 0 |
| redirect | 34 | 9 | 62% / 38% | **23** | 8% / 5% | 3 |
| ldapi | 29 | 0 | 62% / 0% | **62** | 0% / 0% | 0 |
| xxe | 28 | 0 | 62% / 15% | **48** | 0% / 0% | 0 |
| cmdi | 20 | 0 | 54% / 14% | **40** | 54% / 100% | −46 |
| sqli | 16 | 0 | 40% / 0% | 40 | 100% / 0% | **100** |
| **average** | | **10.9** | | **49.3** | | **10.7** |

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

**trustbound stays at 0 by choice.** `TAINT-011` (untrusted data stored in the
session) exists but is opt-in: enabled, it finds 44% of these cases at a 42%
false-positive rate, and in real Flask code it fires on ordinary login flows.
**sqli and deserialization** trail Semgrep on detection; which idioms the
missed cases use has not been analysed yet. The largest remaining source of
false positives is known: list-index and configparser-key idioms, which need
key-sensitive container taint (recorded in the roady spec).

## Java (BenchmarkJava 1.2, 2,740 cases)

Commit `20cbf3d` of OWASP-Benchmark/BenchmarkJava, `src/main/java` scanned.

| category | cases | nox TPR / FPR | nox | Semgrep TPR / FPR | Semgrep |
|---|---:|---|---:|---|---:|
| sqli | 504 | 15% / 11% | 4 | 93% / 73% | **20** |
| weakrand | 493 | 0% / 0% | 0 | 100% / 0% | **100** |
| xss | 455 | 28% / 15% | 13 | 82% / 52% | **30** |
| pathtraver | 268 | 20% / 16% | 4 | 90% / 79% | **12** |
| cmdi | 251 | 52% / 42% | **10** | 93% / 87% | 6 |
| crypto | 246 | 55% / 0% | **55** | 0% / 0% | 0 |
| hash | 236 | 69% / 0% | 69 | 69% / 0% | 69 |
| trustbound | 126 | 0% / 0% | 0 | 52% / 42% | **10** |
| securecookie | 67 | 0% / 0% | 0 | 100% / 0% | **100** |
| ldapi | 59 | 0% / 0% | 0 | 96% / 88% | **9** |
| xpathi | 35 | 0% / 0% | 0 | 93% / 65% | **28** |
| **average** | | | **14.1** | | **34.9** |

nox is behind on Java, and the table says where. Two categories account for
most of the gap: **weakrand** and **securecookie**, where Semgrep scores 100
and nox has no Java rule; `CRYPTO-002` and `HARDEN-003` are Go and Python only.
**ldapi and xpathi** have no Java sinks yet. On the flow categories nox's
detection rate is low (sqli 15%, xss 28%, pathtraver 20%), while Semgrep's is
high at false-positive rates of 50–88%. Both gaps are recorded in the roady
spec, with measurement on real Java repositories required before any rule
ships.

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
