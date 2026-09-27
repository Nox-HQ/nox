# Benchmark 2026-09-27 — v1.41.0 (+ #722)

Same seven repositories, at the same pinned commits, as
[2026-09-15](../2026-09-15/bench.json). Engine: `1d4dfa2`, which is v1.41.0
plus #722 (the vendor-binding rules). Produced with `nox bench --corpus`.

## Read this before the totals

**Compare engine findings, not totals.** `VULN-001` is advisory data — what
OSV and NOX Intelligence report for the dependency versions at scan time — and
the 2026-09-15 run has **zero** `VULN-001` findings: it ran without advisory
data. Its 87 "VULN" findings were all `VULN-002`, the typosquatting rule, which
is engine behaviour and is compared below.

So the 1,555 `VULN-001` findings here have no baseline. They are not a
regression either: the 2026-09-15 engine (`77314c3`), run today on the same
trees, reports the same advisories (agent-go: 80 and 80). Most of them are one
advisory repeated per lockfile — llama_index keeps a `uv.lock` in each of
roughly 400 integration packages, and GHSA-8mgp-746c-j5xp (nltk 3.10.3) alone
is 397 of its findings. `by_site` collapses that; `findings` does not.

## Engine findings (everything except VULN-001)

| | 2026-09-15 | 2026-09-27 | change |
|---|---:|---:|---:|
| **All engine rules** | **4,229** | **2,689** | **−36%** |
| Secrets (SEC) | 1,718 | 960 | −44% |
| AI | 1,306 | 826 | −37% |
| SLOP | 500 | 198 | −60% |
| IaC | 150 | 149 | — |
| Data (DATA) | 369 | 369 | — |
| Taint | 60 | 61 | — |
| Distinct rules firing | 115 | 100 | |

Per project (engine findings; the totals in `bench.json` include VULN-001):

| Project | SEC | AI | SLOP |
|---|---|---|---|
| crewAI | 701 → 96 | 602 → 300 | 219 → 68 |
| vercel/ai | 588 → 491 | 250 → 101 | 87 → 3 |
| llama_index | 265 → 236 | 181 → 167 | 127 → 89 |
| openai-python | 33 → 23 | 255 → 244 | 14 → 11 |
| anthropic-sdk-python | 103 → 96 | 3 → 3 | 9 → 4 |
| mcp python-sdk | 21 → 15 | 11 → 7 | 44 → 23 |
| agent-go | 7 → 3 | 4 → 4 | — |

Among the changes behind it: recorded HTTP traffic is no longer read as
credentials (#702), a reference to a secret store is not the secret (#704), a
codemod's test fixtures are not dependencies (#705), a vendor-binding rule's
value is not an identifier's prefix (#722), and SLOP-001 no longer reads imports
out of comments and docstrings (v1.39.2, v1.40.0). The per-release breakdown is
in the CHANGELOG.

## What the numbers do not say

Fewer findings is only an improvement if what disappeared was noise. Each
drop above is recorded with its measured reason in `scripts/rule-deltas.json`
at the release that made it, and each was gated in CI by `scripts/rule-diff.sh`
against a corpus where the dropped findings were read. Missed detections found
along the way were fixed in the same changes (SEC-082 YAML-list headers, JSON
keys for the binding rules).

## Reproducing

```bash
# one directory (or link) per project, each checked out at the commit above
nox bench --corpus <dir> --format json --output bench.json
```

Run online to include advisory data; `VULN-001` will differ by date.
