# Nox Remediate Action

Scan with [Nox](https://github.com/nox-hq/nox), generate a deterministic dependency-upgrade plan, apply it, and open a pull request — Dependabot-style automation, repository-local, no SaaS.

This is a thin composite action over the existing `nox` CLI:

1. [`nox-hq/nox`](https://github.com/nox-hq/nox) installs Nox + runs `nox scan` to produce `findings.json`.
2. `nox fix --dry-run` writes the upgrade plan.
3. `nox fix` applies upgrades (Go / npm / PyPI / Cargo).
4. An optional `verify-cmd` runs the project's test suite.
5. [`peter-evans/create-pull-request`](https://github.com/peter-evans/create-pull-request) opens a PR.

Only `VULN-001` findings with a known `fixed_in` version are eligible. Major-version bumps are skipped by default; pass `include-major: 'true'` to opt in.

## Quick start

```yaml
# .github/workflows/remediation.yml
name: Nox Remediation

on:
  schedule:
    - cron: '0 3 * * 1-5'
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  remediate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: nox-hq/nox-remediate-action@v1
        with:
          path: .
          verify-cmd: 'go test ./...'
```

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `path` | `.` | Directory to scan. |
| `version` | `latest` | Nox CLI version to install. |
| `include-major` | `false` | Apply upgrades that cross a major-version boundary. |
| `manifest-root` | `.` | Directory containing the project manifest. |
| `apply` | `true` | Apply remediation changes. When `false`, only the dry-run plan is produced. |
| `open-pr` | `true` | Open a pull request with the resulting changes. |
| `pr-branch-prefix` | `nox/remediation` | Branch prefix for the remediation PR. |
| `pr-title` | `security(deps): apply Nox remediation upgrades` | Pull-request title. |
| `pr-labels` | `security,dependencies,nox-remediation` | Comma-separated PR labels. |
| `pr-base` | _empty_ | Base branch for the PR (defaults to the repo default). |
| `verify-cmd` | _empty_ | Optional shell command to run after applying upgrades. |
| `scan-format` | `json` | Scan output format(s) for `findings.json` generation. |
| `scan-output` | `nox-out` | Scan output directory. |
| `github-token` | `${{ github.token }}` | Token used to create the pull request. |

## Outputs

| Name | Description |
|------|-------------|
| `has-updates` | `"true"` when at least one eligible upgrade was found. |
| `plan-file` | Path to the dry-run remediation plan. |
| `pr-url` | URL of the opened pull request, if any. |

## Plan-only mode

Skip auto-merge entirely and only post the plan as a PR comment by setting `apply: 'false'` and consuming the `plan-file` output:

```yaml
- id: nox
  uses: nox-hq/nox-remediate-action@v1
  with:
    apply: 'false'

- name: Comment plan on PR
  if: steps.nox.outputs.has-updates == 'true' && github.event_name == 'pull_request'
  uses: marocchino/sticky-pull-request-comment@v2
  with:
    header: nox-remediation
    path: ${{ steps.nox.outputs.plan-file }}
```

## Scope and guardrails

- **Read-only by default in `plan` mode.** No file edits without `apply: 'true'`.
- **Major-version bumps are opt-in.** Default policy refuses upgrades that cross `vX → v(X+1)`.
- **Source code is never uploaded.** All scanning is local to the runner.
- **No remote remediation server.** The action runs `nox` and `git` only.

For richer policy controls (auto-merge thresholds, blast-radius caps, semver-window pinning) see the [Nox remediate plugin](https://github.com/nox-hq/nox-plugin-remediate).

## Permissions

The job needs:

```yaml
permissions:
  contents: write       # branch + commit
  pull-requests: write  # open PR
```

If you use a different token (e.g. a GitHub App), pass it via `github-token`.

## License

Apache-2.0.
