# Example: CI Baseline Workflow

Wire nox into a GitHub Actions pipeline with a baseline + VEX waiver
flow so legacy findings stay visible without blocking new commits.

## Files

- `.github/workflows/security.yml` — workflow uploading SARIF to
  GitHub Code Scanning, posting PR comments, applying VEX waivers,
  failing only on critical+high findings, and scanning only the diff
  against `origin/main` for fast feedback on PRs.
- `vex.json` — example OpenVEX waiver document covering one CVE that
  the team has reviewed and accepted (`status: not_affected`).

## How to use this in your repo

1. Copy `.github/workflows/security.yml` into your repo.
2. Run `nox scan . --output nox-out` locally to produce a starting
   findings.json.
3. Run `nox vex init --input nox-out/findings.json --output vex.json`
   to bootstrap waivers for everything currently in the codebase.
4. Edit `vex.json` — set `status` to `not_affected` for findings the
   team has reviewed, leave the rest as `under_investigation`.
5. Commit `vex.json` and push. Subsequent CI runs only fail on new
   findings or unwaived high-severity issues.

## Why this shape

- **`severity-threshold: high`** — surfaces only findings the team
  agrees are blocking. Lower-severity findings still write to SARIF
  for visibility but don't fail CI.
- **`changed-since: origin/main`** — PR scans run against the diff,
  not the full repo. Sub-second feedback on most PRs.
- **`vex: vex.json`** — committed waivers honour the team's prior
  decisions across runs.
- **`pr-comment: true`** — inline review comments on the offending
  lines so the developer sees the finding without leaving the PR.
