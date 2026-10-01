# Every taint language that has a labelled suite, and scan speed

Measured 2026-09-30, nox at `main` 5ea5a46 (after #775–#780) against v1.46.0
and Semgrep `p/default` 1.176.0. Python and Java are on the OWASP Benchmarks
([2026-09-28-owasp](../2026-09-28-owasp/)); this adds every other language for
which a labelled suite exists, and a clean speed comparison.

Both tools run with their defaults, nox offline. Nothing in nox was tuned to a
benchmark file: each change behind these numbers was also measured on real
repositories, with every added and dropped finding read (see the PRs).

## Neutral suites

Score per CWE is Youden's index -- detection rate minus false-positive rate --
averaged over the CWEs, as the OWASP scorecard reports it. A case counts as
flagged when a finding of its CWE is in its file (Go, PHP) or inside the
function the truth file marks (C#). Scripts are in [`scripts/`](scripts/).

| Language | Suite | nox v1.46.0 | nox now | Semgrep |
|---|---|---:|---:|---:|
| Python | OWASP BenchmarkPython 0.1 | 56.1 | 56.1 | 10.7 |
| Java | OWASP BenchmarkJava 1.2 | 48.2 | 48.2 | 34.9 |
| Go | OWASP Benchmark ported to Go | 7.3 | **35.6** | 22.1 |
| C# | NIST Juliet C# 1.3, injection + crypto | 16.7 | **24.8** | 0.3 |
| C#, in scope ¹ | the same, request/console input, one-file flows | 0.7 | **82.6** | 1.4 |
| PHP | NIST SARD PHP Vulnerability Test Suite | −0.0 | **4.6** | 0.0 |
| PHP, HTTP input ² | the same, request-derived input | −0.1 | **12.3** | 0.1 |

¹ Juliet also feeds its sinks from TCP sockets, files, databases and the
environment, which nox does not treat as user input, and splits many flows
across files, which same-file analysis cannot follow. The in-scope row keeps
cases whose source is the HTTP request or the console and whose flow variant
is in one file (01–17, 31).
² Half of the SARD PHP cases read their "tainted" value from /tmp/tainted.txt
or a command's output.

### Go — flawgarden `go-owasp-converted` @ `985fb705`, 1,513 cases

| CWE | cases | nox TPR / FPR | nox | Semgrep |
|---|---:|---|---:|---:|
| 89 SQL | 323 | 73% / 25% | **48** | −3 |
| 79 XSS | 315 | 41% / 21% | **20** | 15 |
| 327 cipher | 169 | 38% / 3% | 35 | 35 |
| 22 path | 153 | 63% / 22% | **41** | 0 |
| 78 command | 151 | 49% / 9% | **40** | 0 |
| 328 hash | 150 | 32% / 2% | 30 | 30 |
| 330 random | 114 | 38% / 7% | **31** | 30 |
| 501 trust boundary | 48 | 0% / 0% | 0 | 0 |
| 614 cookie | 42 | 75% / 0% | 75 | **92** |

Not scored: CWE-90 and CWE-643 -- the port's LDAP and XPath cases run SQL, so
they measure nothing about LDAP or XPath. 57 of 93 CWE-327 and 55 of 88
CWE-328 vulnerable cases contain no cryptography at all, which caps both tools
at the same ~35%; 15 CWE-330 vulnerable cases never draw a random number.

### C# — NIST Juliet C# 1.3, [vulnomicon](https://github.com/flawgarden/vulnomicon) truth

In scope (request/console input, one-file flow variants):

| CWE | cases | nox TPR / FPR | Semgrep TPR / FPR |
|---|---:|---|---|
| 79 XSS | 576 | 94% / 0% | 0% / 0% |
| 89 SQL | 432 | 94% / 0% | 67% / 56% |
| 22 path | 288 | 94% / 0% | 0% / 0% |
| 78 command | 144 | 94% / 0% | 0% / 0% |
| 601 redirect | 144 | 94% / 0% | 0% / 0% |
| 90 LDAP | 144 | 94% / 0% | 0% / 0% |
| 643 XPath | 144 | 94% / 0% | 0% / 0% |
| 113 header splitting | 432 | 0% / 0% | 0% / 0% |

The missing 6% is one flow variant (15): a `switch (6)` whose taken case carries the flow, which the C# extractor does not yet resolve. HTTP response splitting
has no taint class in nox yet. On the whole suite CWE-327/328 are 100/100; a
cookie without `Secure` is not reported (CWE-614), by design: HARDEN-003 reports
the flag set to false, not left out.

### PHP — NIST SARD PHP Vulnerability Test Suite (2015-10-27), 42,212 cases

HTTP-input half:

| CWE | cases | nox TPR / FPR | nox | Semgrep |
|---|---:|---|---:|---:|
| 79 XSS | 5,040 | 34% / 22% | 12 | 0 |
| 89 SQL | 4,776 | 45% / 21% | **23** | 2 |
| 91→643 XPath | 3,024 | 50% / 32% | 18 | 0 |
| 601 redirect | 2,400 | 42% / 26% | 16 | 0 |
| 90 LDAP | 1,920 | 50% / 44% | 6 | 0 |
| 78 command | 1,248 | 50% / 35% | 15 | −1 |
| 95→94 code | 816 | 50% / 30% | 20 | 0 |
| 98 include | 1,632 | 0% / 0% | 0 | 0 |

The suite is built around sanitizer semantics: regex (`preg_match`) and
`in_array` allow-list guards, and output-context escaping (the same
`htmlspecialchars` is safe in a text node and not in a script block). nox
models casts, `intval`/`settype`/numeric `filter_var`, escaping functions and
literal ternaries, not guards or contexts yet -- which is where the remaining
false-positive rate comes from. nox reports `include($x)` as CWE-22 path
traversal; counted that way it is 18% / 14%.

## Vendor-authored fixtures (read as a floor)

JavaScript/TypeScript, Ruby, Rust and Swift have no neutral labelled suite.
CodeQL's query-test fixtures (github/codeql @ 605dc1c, MIT) are the only large
labelled set: every expected alert is marked (`$ Alert`, and `$ MISSING: Alert`
for CodeQL's own misses). They were written to exercise CodeQL and do not mark
safe cases consistently, so they are scored as recall on the alert lines and
the share of each tool's findings that land on one. Both tools scanned a copy
outside `test/`, which Semgrep's default ignore list skips.

| Language, CWE | alerts | nox v1.46.0 | nox now (precision) | Semgrep (precision) |
|---|---:|---:|---|---|
| JS XSS | 514 | 6% | **24%** (50%) | 14% (61%) |
| JS command | 289 | 1% | 16% (67%) | **28%** (79%) |
| JS path | 273 | 1% | **55%** (66%) | 5% (38%) |
| JS SQL | 165 | 0% | 4% (75%) | 1% |
| JS code | 109 | 4% | 17% (78%) | **35%** (79%) |
| JS redirect | 100 | 2% | **20%** (54%) | 2% (50%) |
| JS SSRF | 48 | 8% | **46%** (76%) | 6% (100%) |
| Ruby SQL | 46 | 0% | **37%** (85%) | 9% |
| Ruby command | 52 | 19% | **19%** (67%) | 2% |
| Ruby code | 24 | 42% | 42% (67%) | 38% (17%) |
| Ruby path | 18 | 6% | 6% (7%) | **67%** (38%) |
| Swift SQL / path | 116 / 112 | 0% | 0% | 0% |
| Rust command | 12 | 17% | 17% (40%) | 0% |

JavaScript's command and code-injection gap to Semgrep is mostly catalog
breadth for third-party packages (execa variants, cross-spawn, ssh2,
`new Function` idioms). XSS precision is held down by two things the fixtures
are built to test: regex-validation guards and response content types.
Swift's fixtures read iOS-style sources (remote strings, files) the Swift
catalog does not have.

Kotlin and Scala have no labelled suite at all.

## Scan speed

> **Correction (2026-10-01):** the times below were measured on a busy
> machine and are inflated for every tool. Semgrep's 905 s is 141 s on an idle
> machine. Load-gated numbers, with gitleaks and TruffleHog added, are in
> [2026-10-01-speed](../2026-10-01-speed/). The ranking holds; the absolute
> numbers do not.

Same machine (10 cores), one tool at a time, nothing else running, on the seven
pinned repositories of the [2026-09-27 head-to-head](../2026-09-27-head-to-head/).
nox covers secrets, dependencies, code, IaC and AI in one pass; Semgrep is code
only.

| Repository | nox v1.46.0 | nox now (#776) | Semgrep |
|---|---:|---:|---:|
| anthropic-sdk-python | 9.7 s | 9.3 s | 55.8 s |
| agent-go | 6.8 s | 3.2 s | 21.7 s |
| crewAI | 196.7 s | 67.8 s | 142.9 s |
| mcp python-sdk | 10.4 s | 9.3 s | 88.2 s |
| openai-python | 27.8 s | 17.1 s | 76.0 s |
| llama_index | 450.1 s | 160.6 s | 133.5 s |
| vercel/ai | 154.7 s | 67.6 s | 387.0 s |
| **Total** | **856 s** | **335 s** | **905 s** |
| CPU | 1,396 s | 1,674 s | 4,307 s |

Findings and the AI inventory are identical between the two nox builds on all
seven. Peak memory rises where files are many and large: llama_index 2.0 GB →
3.6 GB (Semgrep 0.9 GB).

## Limits

- Five of the suites are synthetic; a score here is evidence about a rule's
  premise, not about its precision on real code, which is why every change was
  also measured on real repositories.
- The CodeQL fixtures are CodeQL's; a high recall there means nox recognizes
  the shapes CodeQL chose to test.
- File-level matching (Go, PHP) credits a finding anywhere in the case's file,
  for both tools.

## Reproducing

```sh
# Go
git clone https://github.com/flawgarden/go-owasp-converted-mutated gobench && git -C gobench checkout 985fb705
(cd gobench && nox scan . -offline -format json -output ../nox-go)
CWES=89,79,327,22,78,328,330,501,614 python3 scripts/score_sarif.py gobench/truth.sarif nox-go/findings.json semgrep-go.json

# C#: unzip the SARD Juliet C# 1.3 zip into cs/, keep the CWE directories scored above
CWES=89,78,90,643,22,79,601,113,327,328,330,614 python3 scripts/score_sarif.py \
  vulnomicon/markup/JulietCSharp/truth.sarif nox-cs/findings.json semgrep-cs.json

# PHP: unzip the SARD PHP suite into php/
python3 scripts/php_truth.py php > php-truth.sarif
INPUT='GET|POST|array|object|unserialize' python3 scripts/score_sarif.py php-truth.sarif nox-php/findings.json semgrep-php.json

# CodeQL fixtures (copy them out of ql/test first)
python3 scripts/score_codeql.py jsfix nox-js/findings.json semgrep-js.json
```
