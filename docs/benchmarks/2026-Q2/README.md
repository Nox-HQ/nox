# Nox bench — 2026-Q2

Reproducible fire-rate benchmark across the curated AI-app-developer
corpus shipped with `nox bench --autocorpus`. Numbers are honest:
unfiltered scan against shallow `git clone --depth 1` checkouts of
each repo. Operators tuning a real project pin to specific severities
and gitignore exclusions; this run does neither, by design — bench
output exists to expose which rules carry signal vs which fire on
tutorial fixtures and need calibration.

## Reproducing

```bash
nox bench --autocorpus --output bench.json
nox bench --autocorpus --format markdown --output bench.md
```

The corpus is pinned in `cli/bench_cmd.go` (`curatedAutoCorpus`).

## Corpus and counters

| Project | Findings | Wall time |
|---|---|---|
| anthropics/anthropic-sdk-python | 1,061 | 1.16s |
| openai/openai-python | 1,360 | 2.46s |
| modelcontextprotocol/python-sdk | 427 | 2.07s |
| felixgeelhaar/agent-go | 3,324 | 4.49s |
| vercel/ai | 135,059 | 26.94s |
| joaomdmoura/crewai | 566,422 | 56.05s |
| run-llama/llama_index | 5,698,790 | 6m 2.71s |

`langchain-ai/langchain@v0.3.7` failed to clone (`v0.3.7` not present
as a git tag at the time of this run); will retry next quarter once
the upstream tag stabilises.

Total: 6,406,443 findings across 7 projects.

## Top 30 rules by project-coverage (signal candidates)

Each row is the count of distinct corpus projects in which the rule
fired at least once.

| Rule | Projects (of 7) |
|---|---|
| AI-006 | 7 |
| AI-026 | 7 |
| AI-050 | 7 |
| DATA-001 | 7 |
| IAC-308 | 7 |
| SEC-161 | 7 |
| SEC-163 | 7 |
| SEC-659 | 7 |
| SEC-697 | 7 |
| AI-036 | 6 |
| IAC-013 | 6 |
| IAC-157 | 6 |
| SEC-574 | 6 |
| SEC-629 | 6 |
| AI-008 | 5 |
| AI-022 | 5 |
| AI-028 | 5 |
| AI-030 | 5 |
| IAC-351 | 5 |
| SEC-162 | 5 |
| SEC-533 | 5 |
| AI-018 | 4 |
| AI-031 | 4 |
| AI-033 | 4 |
| IAC-306 | 4 |
| IAC-314 | 4 |
| SEC-085 | 4 |
| SEC-616 | 4 |
| SEC-692 | 4 |
| SEC-803 | 4 |

## Reading the numbers

**Cross-project rules (fired on every project)** are noise candidates
in this corpus — `SEC-161`/`SEC-163` are the entropy detectors,
which fire on test fixtures and minified JS in big monorepos.
Operators downgrade these via `nox calibrate --bench bench.json`.

**Mid-tier rules** (4–6 of 7 projects) are operator-relevant —
`AI-006`/`AI-026`/`AI-036` cover prompt template / tool / model
patterns the AI-app ICP cares about.

**Long tail** (1–3 of 7) are signal-strong rules whose specificity
is doing its job. Most of the AI-PI / AI-EMBED / AI-AGENT / MCP
families land here because they need specific call-site shapes that
only a real LLM project produces.

## Per-rule severity calibration

Run `nox calibrate --bench bench.json --output suggested.yaml` to
get a paste-ready `.nox.yaml` snippet that downgrades the
high-coverage / known-noise rules and promotes the rare-but-strong
ones. Operators review and merge the snippet into project config.

## Caveats

- Massive find counts on llama_index and crewai are dominated by
  scanning vendored dependencies, generated code, test fixtures, and
  minified JS that those repos check in. A real project would set
  `.gitignore` patterns to skip these directories; bench
  intentionally doesn't, so you can see what the unfiltered scan
  surface looks like.
- Numbers are local-machine readings (one Apple Silicon laptop), not
  CI runs. CI cold-cache runs are ~2x slower for cloning.
- Bench is a fire-rate measurement, not a precision measurement. A
  rule firing on every project is not necessarily a false positive
  — it's a noise candidate that needs hand-classification.

## Next steps

1. Re-run quarterly. Track fire-rate movement to detect rule drift.
2. Hand-classify the long-tail (1–3 project) rules: which fire on a
  real vulnerability, which on a stylistic non-issue.
3. Land hand-classified ground truth into `docs/benchmarks/<quarter>/
  ground-truth.json` for precision measurement.
4. Promote `--severity-threshold` defaults to ship a less-noisy
  out-of-the-box experience based on the calibration output.
