# OWASP Benchmark

The plan's neutral second benchmark (`docs/plans/2026-11-deterministic-lead.md`):
OWASP Benchmark for Java and for Python, scored the way OWASP scores them. It
is never read case by case. A change is judged on RealVuln's development split;
this benchmark only reports.

## Pins

| suite | commit | test cases |
|---|---|---:|
| [BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) 1.2 | `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17` | 2,740 |
| [BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) 0.1 | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | 1,230 |

## Run

    git clone https://github.com/OWASP-Benchmark/BenchmarkJava && git -C BenchmarkJava checkout 10dfcc54
    git clone https://github.com/OWASP-Benchmark/BenchmarkPython && git -C BenchmarkPython checkout f1291485
    nox scan BenchmarkJava/src --offline --format json --output out-java
    nox scan BenchmarkPython --offline --format json --output out-python
    python3 -I scripts/owasp_score.py expected BenchmarkJava/expectedresults-1.2.csv out-java/findings.json
    python3 -I scripts/owasp_score.py expected BenchmarkPython/expectedresults-0.1.csv out-python/findings.json

Scan `BenchmarkJava/src`, not the repository: `results/` holds 186 MB of
other tools' output, and scanning it took over an hour for nothing scored.

## Scoring

A test case is one file. A tool identifies it when it reports, anywhere in that
file, a finding whose CWE is the test's CWE. Per category the score is TPR -
FPR; the overall TPR, FPR and score are unweighted means over categories.

`scripts/owasp_score.py` reimplements that formula instead of running OWASP's
BenchmarkUtils, which is a Maven project: running it would build and execute
downloaded code. `owasp_score.py replay <scorecard.csv>` recomputes a scorecard
OWASP published from its own per-test results. For
`scorecard/Benchmark_v1.1_Scorecard_for_SAST-01.csv` it reproduces every
category and the overall row exactly (TPR 28.96, FPR 12.22, score 16.74).

## Baseline (nox at 7f81be2, the head of #1134; 2026-11-21)

| suite | TPR | FPR | score |
|---|---:|---:|---:|
| BenchmarkJava 1.2 | 46.74 | 14.23 | **32.51** |
| BenchmarkPython 0.1 | 45.91 | 6.22 | **39.69** |

The deterministic SAST tools whose v1.2 scorecards the Java repository ships:

| tool | score |
|---|---:|
| FindSecBugs 1.4.6 | 39.10 |
| SonarQube Java plugin 3.14 | 33.34 |
| PMD 5.2.3 | 0.00 |
| FindBugs 3.0.1 | -0.07 |

These are 2016 releases. They are the scorecards available here, not the
current state of the art, and newer published results should be added before
any claim against them.

### What the zeros are

Three Java categories and three Python categories score 0, and they are not
the same kind of gap:

- **Weak random (CWE-330).** nox reports every vulnerable test (218 of 218 in
  Java, 99 of 99 in Python) and no safe one, as CWE-338, "use of
  cryptographically weak PRNG", which is a ChildOf CWE-330 in the CWE catalog.
  Exact-CWE scoring counts none of them. nox's CWE is the more specific and
  correct one, so it is not changed. Counting a child CWE as identifying its
  parent gives 41.61 (Java) and 46.83 (Python). That figure is exploratory
  and is not the headline, because it is not established that OWASP's scorer
  does the same.
- **Weak hash (CWE-328).** nox reports 113 of 129 vulnerable Java tests and
  71 of 71 Python ones, with no false positives, as CWE-327, "broken or risky
  cryptographic algorithm". For MD5 and SHA-1 as message digests, CWE-328,
  "use of weak hash", is the precise weakness. That is a real inaccuracy in
  nox's claim, to fix in the rule.
- **Trust boundary (CWE-501).** No nox rule reports a request value stored
  into the session for Java, and the Python one does not fire on these tests.
  A detection gap.
