# Adopting nox on a repo with existing debt

A scanner that fails the build on every pre-existing finding gets turned off on
day one. nox is built to **gate the change, not the history**: record today's
findings as accepted debt, then fail only on *new* ones. This guide is the
five-minute path from "we've never scanned this repo" to a green, enforcing CI.

## One command to start

```bash
nox baseline init
```

`baseline init` scans the repo, records every current finding as accepted debt
in `.nox/baseline.json`, and prints the policy to add. It reports what you're
accepting, by severity:

```
baseline: recorded 640 existing findings as accepted debt in .nox/baseline.json
  by severity: 2 critical, 37 high, 218 medium, 383 low

Next — gate the change, not the history. Add to .nox.yaml:

  policy:
    fail_on: high        # new high/critical findings fail the gate
    baseline_mode: warn  # the recorded debt above only warns, never fails
```

Commit both `.nox/baseline.json` and `.nox.yaml`. From now on a **new** high or
critical fails CI; the recorded debt only warns. `init` refuses to overwrite an
existing baseline — use `nox baseline update` to refresh it, or `--force` to
recreate.

## Tightening the gate over time

**Accept a bounded amount of new debt** instead of zero, with per-severity
budgets — useful while a team ramps up:

```yaml
policy:
  fail_on: medium
  budget:
    medium: 5   # tolerate up to 5 new mediums
    low: 20     # ...and 20 new lows — but any new high/critical still fails
```

A severity at/above `fail_on` with no budget entry defaults to zero, so
high/critical always gate. An empty budget behaves exactly like the plain
threshold.

**Burn the debt down** as you fix it — re-baseline so resolved findings drop out
and don't mask a regression:

```bash
nox baseline update      # add nothing new; prune findings you've fixed
nox baseline diff        # preview what update would change first
```

## Reproducible CI

Two flags keep the gate deterministic and honest:

- **`nox scan --tracked-only`** — scan exactly what git tracks, ignoring
  untracked scratch files, build output, and un-added drafts. CI sees the same
  set a reviewer sees, and a developer's local scratch file never trips the gate.
- **`nox scan --offline`** — the zero-network guarantee: no OSV lookups, no API,
  no token, no telemetry. `findings.json` records `"offline": true` so a reviewer
  can confirm from the artifact that the scan never touched the network. Backed
  by an enforced egress test, not a promise.

## Adopting a stricter linter on the *changed* code only

To hold *new* code to a higher bar without a big-bang cleanup, scope the gate to
the diff:

```bash
nox scan --changed-since origin/main --severity-threshold high
```

This scans only files changed since the base ref, so a PR is gated on what it
introduced — not the whole backlog. It composes with the baseline and budgets
above.

## The whole flow

```bash
nox baseline init                 # 1. record existing debt, get the policy
git add .nox/baseline.json .nox.yaml && git commit -m "chore: adopt nox"
#    2. add the printed policy block to .nox.yaml
nox scan --tracked-only           # 3. CI gates new findings; debt only warns
nox baseline update               # 4. re-baseline as you fix, to keep it honest
```
