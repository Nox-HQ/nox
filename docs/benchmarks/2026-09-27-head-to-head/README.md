# Head-to-head 2026-09-27 — nox 1.42.0 against the tools people already run

Every earlier benchmark in this directory compared nox with an earlier nox.
This one compares it with the tools a team would otherwise use, on the same
seven repositories at the same pinned commits as [2026-09-27](../2026-09-27/):

| Concern | nox 1.42.0 is compared with |
|---|---|
| Secrets | gitleaks 8.30.1 (`dir`), TruffleHog 3.97.9 (`filesystem --no-verification`) |
| Dependency advisories | osv-scanner 2.6.0 (`scan source -r`), Trivy 0.74.0 (`fs --scanners vuln`) |
| Code | Semgrep 1.176.0 (`--config p/default`) |

All tools scanned the working tree, not git history, with their default
configuration. nox ran online, its default: NOX Intelligence, verified against
OSV.dev. TruffleHog ran without verification, because verifying means sending
credentials found in other people's repositories to third-party APIs, and no
other tool here verifies anything.

**Every difference between the tools was read, not counted.** Where a region
was too large to read line by line, it was read grouped by the value it matched
(all 557 of one gitleaks rule are four placeholder strings, for instance) and
the rest was sampled. The labels are in [`labels/`](labels/); they record file,
line and verdict, never the matched text.

## Summary

| | Where nox stands |
|---|---|
| Dependency advisories | **At parity with osv-scanner on pinned dependencies, ahead of Trivy** — after #728. 1.42.0 itself under-reported large monorepos. |
| Secrets: real credentials | **5 of the 8 found by any tool**; gitleaks also 5, TruffleHog 3. Two only nox found; three nox missed. |
| Secrets: noise | Comparable volume to gitleaks, different kind: nox's is placeholder values (`Bearer test-api-key`), gitleaks' is placeholder curl headers. |
| Code | **Barely overlaps Semgrep.** 43 of Semgrep's 531 findings are near a nox finding. Each finds things the other does not; neither is precise. |
| AI / MCP | No counterpart in any of the five tools. |
| Speed | **Slowest per scan.** 1,466 s for the seven repos; the other five together took 1,389 s. |

nox is competitive on dependencies and on finding real credentials, and it is
the only one of these tools that covers AI-application risks. It is not ahead
on secret precision, it does not replace Semgrep, and it is slow on large
repositories.

## Secrets

Lines flagged (several rules on one line count once):

| | nox | gitleaks | TruffleHog |
|---|---:|---:|---:|
| Findings | 960 | 732 | 84 |
| Lines | 825 | 732 | 64 |
| … flagged by no other tool | 790 | 726 | 31 |

The three tools barely agree: of roughly 1,600 lines, 35 are flagged by more
than one tool. So totals say nothing about who is right.

### Real credentials

Everything any tool flagged was reduced to the credentials that are, or could
be, real. Eight were found; three more are client keys that are public by
design.

| Credential | nox | gitleaks | TruffleHog |
|---|:---:|:---:|:---:|
| `sk-` key (51 chars) pasted into a Discord help-channel dump, llama_index | ✓ | – | – |
| Alibaba Cloud `AccessKeyId` in an expired presigned URL, llama_index notebook | ✓ | – | – |
| Session JWT in a crewAI test recording (expired) | ✓ | ✓ | – |
| mTLS private keys in openai-python test fixtures (2) | ✓ | ✓ | ✓ |
| GigaChat authorization key in a llama_index README | – | ✓ | – |
| MonsterAPI key hardcoded in integration source, llama_index | – | ✓ | – |
| Vercel AI Gateway key in a llama_index notebook | – | – | ✓ |
| **Of 8** | **5** | **5** | **3** |
| *Public by design:* Algolia search key · Mendable anon key · PostHog `phc_` key | 1 of 3 | 3 of 3 | 1 of 3 |

The `sk-` key lacks the `T3BlbkFJ` marker a genuine legacy OpenAI key carries,
which is why gitleaks and TruffleHog skip it; it may be a key the user altered
before pasting. None of these credentials was tested against a live API.

Why nox missed its three:

- **Vercel key.** In a notebook the line is stored JSON-escaped
  (`api_key=\"…\"`), and the escaped quotes break the match. The same line in a
  `.py` file is found (`SEC-005`).
- **GigaChat and MonsterAPI.** Neither has a recognizable format (base64 of
  `uuid:uuid`, and a bare UUID). gitleaks finds them with a keyword-plus-entropy
  fallback (`generic-api-key`); nox has no equivalent.

### What the rest is

| Share of each tool's lines | nox | gitleaks | TruffleHog |
|---|---:|---:|---:|
| Placeholder or test value | ~79% | ~78% | ~22% |
| Not a credential at all | ~20% | ~19% | ~70% |
| Real or public-by-design | ~1% | ~3% | ~8% |

Estimated from the labelled sample of each region, weighted by region size. The
full reads behind it:

- **nox.** Its four largest rules account for most of the placeholders. For
  `SEC-082` (bearer tokens), `SEC-080` (passwords) and `SEC-801`/`SEC-803` (API
  key variables), every value is a test string: `test-api-key` (86 lines),
  `test_password` (44), `sua_chave_openai` (39, Portuguese for "your OpenAI
  key"), `mock-auth-token` and so on. Its non-credentials are mostly base64
  image data in notebooks and encrypted reasoning blobs in test recordings.
- **gitleaks.** 557 of its lines are `curl -H "Authorization: Bearer …"` with
  one of four placeholders (`YOUR_CREW_TOKEN` alone is 360). 130 more are
  agent-config hashes and trace codes in crewAI's test recordings.
- **TruffleHog.** Mostly vendor detectors firing inside base64 image data,
  shared with nox, plus placeholder URLs like `user:password@example.com`.

## Dependency advisories

The unit is a distinct (repository, package, version, advisory). Advisory
identity merges every alias any tool reported (GHSA, CVE, GO, PYSEC), so tools
naming the same advisory differently are not counted as disagreeing.

| | nox 1.42.0 | nox + #728 | osv-scanner | Trivy |
|---|---:|---:|---:|---:|
| Distinct advisories | 616 | 641 | 746 | 525 |

**nox 1.42.0 under-reported large monorepos**, and this comparison is how it
was found. The lookup asked about every package once per lockfile. llama_index
pins the same packages in ~600 lockfiles, so the batches ran past the two-minute
budget and 211 of its vulnerable lockfiles reported nothing. The scan did carry
an `osv_lookup` degradation saying so. #728 asks once per package version:
llama_index goes from 397 to 608 lockfiles with advisories (osv-scanner: 616)
and from 248 to 273 distinct advisories, with nothing lost.

What remains after #728:

- **22 advisories nox reports nothing for** (agent-go's `website-astro`
  lockfile). agent-go's own `.nox.yaml` excludes `**/package-lock.json`, and
  nox obeys it. Scanned alone, the file gives the same 22 osv-scanner reports.
- **The rest of osv-scanner's lead is unpinned requirement files.** For a
  `requirements.txt` with only lower bounds, osv-scanner resolves the
  transitive dependencies itself, for example `aiohttp 3.9.5` from a file whose
  only line is `firecrawl-py>=4.3.3`, which puts no bound on aiohttp. nox takes
  the direct dependencies at their lower bound and does not resolve transitive
  ones (its 18 unique advisories are of that kind: `mcp 1.0.0` from
  `mcp>=1.0.0`). Neither tool's version is what the repository pins.
- **Trivy** misses 120 advisories both others report: pnpm lockfiles, many
  `uv.lock` files, and every crewAI advisory (0 against 12).

nox also runs reachability on Go advisories: 51 of agent-go's 80 are marked
`not_impacting` (the affected package is never linked). Python and JavaScript
advisories are all `undetermined`, so this is Go-only for now.

## Code

| | Semgrep `p/default` | nox (code families) |
|---|---:|---:|
| Findings | 531 | 618 (+ 513 AI, 198 SLOP) |
| Within 3 lines of the other tool | 43 | 40 |

They agree only on mutable GitHub Action tags and MD5/SHA-1 use. Samples of
40 from each side's unique findings:

| | Semgrep-only | nox-only |
|---|---:|---:|
| Actionable | 5 (Action tags, update cooldowns, `secrets: inherit`) | 5 (artifact attestation, Compose limits, `workflow_dispatch`) |
| Worth a look in context | 25 (f-string SQL from table names, dynamic imports, `exec`) | — |
| Personal data | — | 1 (a private address in a README) |
| False positive | 10 (`ws://` in tests, `console.log` templates, a CSV row) | 34 (29 organisation addresses like `support@`, a test phone number, a demo SSN, test session IDs, a checksum MD5) |

nox's taint analysis (61 findings, none near a Semgrep finding) found one real
issue Semgrep does not: an example Next.js route in vercel/ai
(`app/api/code-execution-files/anthropic/[file]/route.ts`) puts the caller's
`file` parameter into an Anthropic Files API request signed with the server's
key, so any caller can read any file in that account. Most of its other taint
findings are CLI scripts reading their own arguments and SDK tools calling their
vendor's API.

nox's AI (513) and SLOP (198) findings have no counterpart in any of the five
tools; their precision work is in [2026-09-27](../2026-09-27/).

## Speed and memory

Wall time and peak memory, one tool at a time on the same machine:

| Repository | nox | gitleaks | TruffleHog | osv-scanner | Trivy | Semgrep |
|---|---:|---:|---:|---:|---:|---:|
| anthropic-sdk-python | 8 s | 1 s | 1 s | 2 s | 0 s | 86 s |
| agent-go | 5 s | 1 s | 1 s | 46 s / 2.7 GB | 21 s | 5 s |
| crewAI | 238 s | 43 s | 8 s | 2 s | 0 s | 188 s |
| mcp python-sdk | 14 s | 3 s | 1 s | 5 s | 0 s | 51 s |
| openai-python | 29 s | 9 s | 1 s | 1 s | 0 s | 66 s |
| llama_index | 840 s / 2.1 GB | 121 s | 8 s | 100 s | 23 s | 112 s |
| vercel/ai | 332 s | 19 s | 2 s | 8 s | 1 s | 452 s |
| **Total** | **1,466 s** | 197 s | 22 s | 165 s | 46 s | 959 s |

nox does secrets, dependencies, code, IaC and AI in one pass, and its total is
close to the other five combined (1,389 s). Per repository it is the slowest
on crewAI and llama_index. With #728, llama_index takes 969 s: the lookups that
used to time out now complete.

## What this changes for nox

Everything below was measured after this report, against v1.42.0 on the same
seven repositories at the same commits, offline (so dependency advisories are
not in these counts), and every dropped finding was read.

| | v1.42.0 | after the follow-ups | |
|---|---:|---:|---:|
| All engine findings | 2,376 | 1,429 | −40% |
| Secrets | 960 | 359 | −63% |
| Personal data (DATA) | 369 | 23 | −94% |
| Every other rule family | unchanged | unchanged | |

Each follow-up, and what became of it:

1. **Placeholder values** — fixed in #730 and #737. A value made only of short
   words with a test marker, a translated "your", or only credential
   vocabulary is a placeholder; a random value never is.
2. **Notebook escaping** — fixed in #732. It adds 42 findings on llama_index,
   among them the Vercel key only TruffleHog found and a **Weaviate Cloud API
   key none of the three tools found**. With it, nox finds 7 of the 9 real
   credentials any tool found here; gitleaks finds 5, TruffleHog 3.
3. **Keyword-plus-entropy fallback** — not done. gitleaks' `generic-api-key`
   found two real keys among 169 findings; the precision cost is not yet
   justified.
4. **Base64 image data** — fixed in #731. Model-issued ciphertext
   (`signature`, `encrypted_content`, `thoughtSignature`) turned out to be a
   separate class and is fixed in #734.
5. **`DATA-001`** — fixed in #733: role mailboxes and a URL's userinfo are not
   personal data. `DATA-004`'s fictional 555-01xx and `1234567890` numbers
   followed in #738.
6. **Scan time** — profiled in #736: the regex engine is 53% of CPU, and one
   rule (`DATA-009`, keyword `tin`) costs 80 s on crewAI for zero findings.
   Not yet changed.
7. **Reachability** beyond Go — not started.
8. **The unrecorded detail fetch** — nox-core#3. Recording it naively would
   make the verifier call a reachable source unreachable, so it waits for the
   design there.

And one the comparison found in nox's own tooling: the rule-diff check passed
a run that crashed after three of its 25 repositories, because the crash exited
with the code that means "every drop is explained". Fixed in #735.

## Secrets, re-labelled after the follow-ups

Every secret finding nox reports on the seven repositories after the
follow-ups, at `main` on 2026-09-28 (v1.43.1 plus the unreleased rule work), was
read and labelled: 369 findings, all of them, not a sample. The labels are in
[`labels/secrets-v1.43.json`](labels/secrets-v1.43.json) (file, line, rule and
verdict; never the matched text).

| Verdict | Findings | Share |
|---|---:|---:|
| Placeholder or test value | 217 | 59% |
| Not a credential | 127 | 34% |
| Real | 20 | 5.4% |
| Public by design | 5 | 1.4% |

The 20 real lines are **10 distinct credentials, and nox now finds all 10**:
the 8 in the table above, the Weaviate Cloud key #732 surfaced, and a password
for a Neo4j instance on a public IP in a llama_index notebook that none of the
three tools reported in the original comparison. At v1.42.0 roughly 1% of 960
secret findings were real; now it is 5.4% of 369, with nothing real lost on
the way down.

The same standard as above: a key or token genuinely issued by a system counts
as real even when it sits in a test fixture or an expired recording (the mTLS
keys, the crewAI JWT), and nothing was tested against a live API.

Where the remaining noise is, largest first:

- **`SEC-082`, bearer tokens (106).** Every one is a descriptive test string
  in a test file: `'Bearer managed-secret'`, `'Bearer host-only-credential'`,
  `'Bearer ASYNC_TOKEN'`.
- **`SEC-161` (81).** 50 are `credential_id="vcrd_…"`: an identifier named
  after a credential. Most of the rest are Vertex AI grounding redirect URLs
  and response IDs in test recordings.
- **AWS's documented example keys (33, across five rules).**
  `AKIAIOSFODNN7EXAMPLE` and its secret key, in anthropic-sdk and
  openai-python tests.
- **`SEC-008` (14).** `"type": "service_account"` with no key material next to
  it.
- **`SEC-373` / `SEC-372` / `SEC-374` (12).** Plain `s3://` and storage URLs
  with no credential in them.

## Limits of this comparison

- Seven repositories, most of them AI SDKs and frameworks. That favours nox's AI
  rules and makes secret noise heavy on test fixtures and recorded API traffic.
  A different corpus would give different ratios.
- One reviewer (Claude) labelled every line from its context, and no credential
  was verified against its vendor. The labels are published so they can be
  disputed line by line.
- Every tool ran with defaults. gitleaks and Semgrep in particular are usually
  tuned per project; so is nox.
- Advisory counts depend on the day's data; all five dependency runs happened
  within the same hour.

## Reproducing

```bash
# CORPUS: one directory per repository, checked out at the commits in
# ../2026-09-27/bench.json. WORK: where outputs go.
export CORPUS=… WORK=… NOX=/path/to/nox
for t in nox gitleaks trufflehog osv trivy semgrep; do scripts/run.sh $t; done
python3 scripts/normalize.py
python3 scripts/compare_secrets.py   # also writes the stratified sample
python3 scripts/compare_deps.py --misses
python3 scripts/compare_sast.py
```
