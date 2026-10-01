# Scan speed: nox against Semgrep, gitleaks and TruffleHog

Measured 2026-10-01 on an Apple M5 (10 cores, 24 GB), nox at `main` 607a818
(after #783 and the scoped scans of #786/#787). Each tool ran alone, over the
seven repositories of the [2026-09-27 head-to-head](../2026-09-27-head-to-head/),
pinned at the [2026-09-27](../2026-09-27/) commits.

Every run waited for an idle machine (1-minute load average below 3) and
recorded the load it started at; the highest was 2.99. Each cell is the faster
of two passes. The passes agree within a few percent for every tool except
online nox, whose lookups vary with the network by up to 30%. Raw numbers:
[`results-tools.txt`](results-tools.txt), [`results-scoped.txt`](results-scoped.txt);
harness: [`scripts/`](scripts/).

| Tool | Version | What it covers |
|---|---|---|
| nox | 607a818 | secrets, code (taint), dependencies, IaC, AI, data, supply chain |
| Semgrep | 1.176.0, `p/default` | code |
| gitleaks | 8.30.1, `dir` | secrets |
| TruffleHog | 3.97.9, `filesystem --no-verification` | secrets |

## Each tool as it ships

| Repository | nox offline | nox online | Semgrep | gitleaks | TruffleHog |
|---|---:|---:|---:|---:|---:|
| anthropic-sdk-python | 4.1 s | 5.4 s | 6.7 s | 0.7 s | 0.6 s |
| agent-go | 1.3 s | 4.8 s | 4.2 s | 0.3 s | 0.6 s |
| crewAI | 22.8 s | 20.7 s | 39.7 s | 22.8 s | 2.9 s |
| mcp python-sdk | 5.3 s | 5.4 s | 5.8 s | 1.0 s | 0.6 s |
| openai-python | 7.0 s | 7.0 s | 10.1 s | 1.8 s | 0.7 s |
| llama_index | 38.6 s | 122.4 s | 35.4 s | 40.5 s | 3.0 s |
| vercel/ai | 13.9 s | 27.2 s | 39.0 s | 5.8 s | 1.3 s |
| **Wall, total** | **93 s** | 193 s | 141 s | 73 s | 10 s |
| CPU, total | 558 s | 629 s | 580 s | 605 s | 47 s |
| Peak memory | 3.5 GB | 3.6 GB | 968 MB | 127 MB | 279 MB |

The tools do not do the same job. One nox pass covers what takes Semgrep plus
a secrets scanner plus a dependency scanner. For the same coverage as one
offline nox scan (93 s), Semgrep and gitleaks together take 214 s of wall time
and 1,185 s of CPU, and they still read no lockfile.

**Online**, nox asks NOX Intelligence about every dependency and checks the answer against
OSV.dev. On llama_index, a monorepo with hundreds of lockfiles, that adds
84 s. It is network time, not CPU: the deps scope uses 83 s of CPU across all
seven repositories (below).

## One concern at a time (scoped scans)

`nox scan --only <scope>` runs only that scope's analyzers and stages (see
[Scopes](../../usage.md#scopes)), which makes nox comparable with
single-purpose tools on their own ground:

| Repository | nox `--only secrets` | gitleaks | TruffleHog | nox `--only code` | Semgrep | nox `--only deps` (online) |
|---|---:|---:|---:|---:|---:|---:|
| anthropic-sdk-python | 0.3 s | 0.7 s | 0.6 s | 3.2 s | 6.7 s | 4.8 s |
| agent-go | 0.3 s | 0.3 s | 0.6 s | 0.8 s | 4.2 s | 2.8 s |
| crewAI | 6.5 s | 22.8 s | 2.9 s | 7.0 s | 39.7 s | 4.8 s |
| mcp python-sdk | 0.4 s | 1.0 s | 0.6 s | 4.4 s | 5.8 s | 3.1 s |
| openai-python | 1.3 s | 1.8 s | 0.7 s | 4.8 s | 10.1 s | 2.7 s |
| llama_index | 10.4 s | 40.5 s | 3.0 s | 8.5 s | 35.4 s | 93.8 s |
| vercel/ai | 7.6 s | 5.8 s | 1.3 s | 4.0 s | 39.0 s | 23.5 s |
| **Wall, total** | **27 s** | 73 s | **10 s** | **33 s** | 141 s | 135 s |
| CPU, total | 159 s | 605 s | 47 s | 58 s | 580 s | 83 s |
| Peak memory | 260 MB | 127 MB | 279 MB | 101 MB | 968 MB | 187 MB |

- **Secrets:** nox is 2.7x faster than gitleaks in total, but TruffleHog is
  2.7x faster than nox. nox runs 938 secret rules with entropy and context
  checks; TruffleHog's detectors are keyword-gated, and with
  `--no-verification` it does nothing more.
- **Code:** nox is 4.3x faster than Semgrep `p/default`, with a tenth of the
  CPU and memory. Accuracy is a separate question, answered per language in
  [2026-09-30-languages](../2026-09-30-languages/).
- **Deps** is bounded by the lookups, not by nox.

A scoped scan's findings are exactly the full scan's findings for its scopes,
fingerprints included (`TestScopedScanMatchesFullScanForItsScope`, run over
these seven repositories).

## What this does not show well

- **Peak memory.** The full scan peaks at 3.5-3.7 GB on llama_index, against
  under 300 MB for each of the scopes measured here, so the peak comes from
  the scopes not timed separately (AI, data, IaC, supply chain). Where in them
  is not yet measured. No other tool here passes 1 GB.
- **Online variance.** Lookup time depends on the network and on the intelligence
  service's cache; the two passes differed by up to 30%.

## Correction to 2026-09-30

The speed table in [2026-09-30-languages](../2026-09-30-languages/#scan-speed)
gave Semgrep 905 s and nox 335 s for the same seven repositories. Both were
inflated by a busy machine: those runs were not load-gated. Idle, Semgrep takes
141 s; nox at 607a818, which also includes the regex work of #783, takes 93 s.
The ranking in that table, nox ahead of Semgrep in total, holds. The absolute
numbers do not; use these.

## Reproducing

```sh
export BENCH_ROOT=/path/to/workdir      # holding bench7/<repo> checkouts
export NOX=/path/to/nox                 # built at the commit under test
scripts/run.sh          # every tool, two passes, load-gated
scripts/run-scoped.sh   # nox full, --only secrets/code/deps, two passes
```
