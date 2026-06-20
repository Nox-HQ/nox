# Example: GitLab CI/CD

Run nox in a GitLab pipeline — gate on high-severity findings, scan only
the merge-request diff for fast feedback, and publish SARIF + JSON reports
as artifacts.

## Files

- `.gitlab-ci.yml` — a `security` stage that runs the nox container image,
  fails the pipeline on high+ findings, applies an OpenVEX waiver document
  when one is committed, and scans only the diff against the target branch
  on merge requests.

## How to use this in your repo

1. Copy `.gitlab-ci.yml` into your repository root (or merge the `nox-scan`
   job into your existing pipeline).
2. Pin the image to a release tag for reproducible runs, e.g.
   `ghcr.io/nox-hq/nox:v1.2.0` instead of `:latest`.
3. (Optional) Bootstrap waivers so legacy findings don't block new commits:
   ```sh
   nox scan . --output nox-out
   nox vex init --input nox-out/findings.json --output vex.json
   ```
   Edit `vex.json` — set `status: not_affected` for reviewed findings, leave
   the rest as `under_investigation` — then commit it. The job picks it up
   automatically (`--vex vex.json --fail-on-unwaived`), so only new or
   unwaived high-severity findings fail.

## Why this shape

- **`--severity-threshold high`** — only blocking findings fail the pipeline;
  everything still lands in the SARIF/JSON artifacts for visibility.
- **`--changed-since origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME`** — MR
  pipelines scan the diff, not the whole repo. `GIT_DEPTH: "0"` gives nox the
  history it needs to compute that diff.
- **`--vex vex.json --fail-on-unwaived`** — committed waivers carry the team's
  prior decisions across runs.
- **`artifacts.when: always`** — reports are kept even when the job fails, so
  you can inspect the findings that blocked the pipeline.

## Notes

- The reports are published as plain artifacts (`results.sarif`,
  `findings.json`). GitLab's native **SAST report** widget
  (`artifacts:reports:sast`) expects GitLab's own JSON schema, not SARIF, so
  it is not wired here; download the artifact or feed the SARIF to a viewer.
- For a non-containerised runner you can install nox directly instead of using
  the image — `go install github.com/nox-hq/nox/cli@v1.2.0` — and drop the
  `image:` block.
