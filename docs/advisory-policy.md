# Watching for new advisories: connect once, decide by policy

A dependency can become vulnerable without a line of your code changing. This
page is how nox notices that between pull requests, decides whether it matters
to your application, and does exactly as much about it as you have allowed.

## Connect to CI in one step

```bash
nox install-ci
```

writes `.github/workflows/nox.yml`, which does two things:

| job | runs on | what it does |
|---|---|---|
| `scan` | every pull request and push | scans, uploads SARIF to Code Scanning, annotates the diff |
| `advisories` | a daily schedule, and on demand | scans the code already merged, works out which advisories are **new since the previous scheduled run**, and acts on them according to your policy |

Flags: `--branch`, `--cron`, `--nox-ref`, `--nox-version`, `--force`, `--print`.
Third-party actions in the file are pinned to commits. The `nox-hq/nox` ref is a
release tag; run `nox fix --actions` to pin it too. A development build of nox
has no release tag and asks for `--nox-ref`.

Commit the file and you are connected. With no further configuration the
scheduled job only **reports**: a job summary, SARIF, and one issue per run that
found something new.

## The policy

```yaml
# .nox.yaml
advisories:
  policy: report          # report (default) | prepare | remediate

  prepare:                # which new advisories get a pull request
    min_severity: low           # critical | high | medium | low
    min_relevance: undetermined # undetermined | symbol_used | call_reachable

  remediate:              # which of those may also be auto-merged
    min_severity: high
    min_relevance: call_reachable # the default; symbol_used opts in to merging on linkage alone
    max_bump: minor             # patch | minor; a major bump is never merged unattended
```

`policy` is a ceiling. Each advisory goes only as far as its own gate allows,
so `policy: remediate` does not mean everything is merged.

| level | what happens to a new advisory that passes its gate |
|---|---|
| `report` | job summary, SARIF, an issue. Nothing else. |
| `prepare` | also a pull request (`chore(security): nox remediation ...`) carrying the planned upgrade, opened by the existing `actions/remediate` action |
| `remediate` | also `gh pr merge --auto`, and only when **every** advisory in that pull request passes the remediate gate |

Nox never merges anything itself and never bypasses branch protection.
`--auto` asks GitHub to merge when the branch's required checks and reviews are
satisfied; if the repository has none, or does not allow auto-merge, the pull
request stays open for a person. Pull requests need a bot identity to run your
checks; see [Opening pull requests that run your checks](#opening-pull-requests-that-run-your-checks).

An invalid value (`policy: remediat`) is an error and exits 2. It does not
quietly fall back to the default.

## Opening pull requests that run your checks

A pull request opened with the workflow's default `GITHUB_TOKEN` does not
trigger other workflows: GitHub does this on purpose, to stop workflows
starting each other in a loop. So its required checks never start, and
`gh pr merge --auto` waits for checks that will never report. `prepare` and
`remediate` therefore need a real identity. The generated workflow picks the
first of these that exists:

| order | credential | secrets |
|---|---|---|
| 1 | GitHub App (recommended) | `NOX_APP_ID`, `NOX_APP_PRIVATE_KEY` |
| 2 | fine-grained personal access token | `NOX_TOKEN` |
| 3 | `GITHUB_TOKEN` | none |

**GitHub App.** The workflow mints an installation token for that one job with
`actions/create-github-app-token`, scoped to contents, pull-requests and issues
write; it is revoked when the job ends, and nothing long-lived has to be rotated
by hand.

1. Create a GitHub App (Settings, Developer settings, GitHub Apps). Repository
   permissions: Contents: Read and write, Pull requests: Read and write,
   Issues: Read and write. No webhook needed.
2. Install it on the repository (only that one).
3. Generate a private key. Add repository secrets `NOX_APP_ID` (the app's
   Client ID) and `NOX_APP_PRIVATE_KEY` (the whole PEM).

**Personal access token.** Create a fine-grained token with the repository as
its only resource, the same three permissions, and an expiry you will remember
to renew. Add it as the repository secret `NOX_TOKEN`. It acts as you, and the
pull request is attributed to you.

**Neither.** The pull request is still opened, but the job emits a warning and
a summary line that CI will not run on it. In `remediate` mode auto-merge is
**not** enabled, since it could never complete; the run says so instead of
leaving it pending.

Report-only runs need none of this: the issue is created with `GITHUB_TOKEN`.

## How relevance is judged

Relevance is the applicability ladder already on every dependency finding
(`applicability`, `applicability_reached`), read honestly:

| relevance | printed as | meaning | can pass a gate? |
|---|---|---|---|
| `call_reachable` | a call path reaches it | a call path reaches the affected code | yes |
| `symbol_used` | linked, not shown to be called | the affected package is linked or imported by this build; nothing shows it is called | yes |
| `undetermined` | not determined | nox could not place the advisory against your code | yes, at `min_relevance: undetermined` |
| `not_impacting` | shown not to affect this build | a rung was **deterministically refuted** (e.g. Go: the build links no affected package) | never |

**Undetermined is not "not affected".** Most npm and PyPI advisories are
undetermined, because nox cannot see through a dependency. They are treated as
possibly affecting you, and the reason says the question went unanswered. That
is why the default prepare gate accepts them and the default remediate gate does
not: opening a pull request for review costs little, merging on no evidence of
use is a different bet. Loosen it deliberately:

```yaml
advisories:
  policy: remediate
  remediate:
    min_relevance: undetermined
```

**Linked is not called.** For every ecosystem except Go, linked is as far as
nox gets, so a merge gate that accepted `symbol_used` would be a merge gate on
severity alone. The default remediate gate is therefore `call_reachable`, and
an npm or PyPI project is prepared as a pull request for a person to merge.
A repository that decides linkage is enough says so itself:

```yaml
advisories:
  policy: remediate
  remediate:
    min_relevance: symbol_used
```

The identifiers in the first column are what `.nox.yaml` and the JSON output
use; text and markdown output print the second column.

When gates leave some of a package's advisories out of the pull request, the
package still moves once, to the highest fix across all of its active
advisories, which is the version `nox fix plan` shows. A lower target would
leave the package in the pull request still carrying an advisory the plan
fixes.

Only `not_impacting` lowers an advisory, and only to "reported with the
reason". It is never acted on and never hidden.

There is no KEV or EPSS gate. Nox does not carry exploited-in-the-wild data
today, and a threshold on a field that is never populated would silently never
fire.

## Decision table

For an advisory in the current scan. Rows are checked top to bottom; the first
match decides. The reason is printed with every decision.

| condition | action |
|---|---|
| baselined, or waived through VEX (`not_affected`, `fixed`) | none (waived) |
| present in the previous run (by ecosystem, package and advisory id or alias) | none (known) |
| the scan could not finish looking (a non-advisory degradation, e.g. `osv_lookup`) | report; exit 1 |
| no previous run to compare against | report; nothing acted on |
| policy is `report` | report |
| relevance is `not_impacting` | report |
| below `prepare.min_severity` or `prepare.min_relevance` | report |
| no fixed version, unsupported ecosystem, or the fix is not a forward upgrade | report |
| the fix crosses a major version | report (a person takes that bump) |
| passes the prepare gate | **prepare** |
| policy is `remediate`, passes the remediate gate, and the package move is within `max_bump` | **remediate** |

The pull request holds only the advisories decided `prepare` or `remediate`,
planned by the same planner `nox fix` uses, so a package with several advisories
moves once, to the highest fix among them. Auto-merge is permitted only if all
of them are `remediate`; one prepare-only advisory in the pull request holds the
whole pull request for review. The bump is judged on the package's actual move,
not on each advisory's own `fixed_in`.

The decision is a pure function of the findings, the previous run and the
policy. Same inputs, same decision, same order.

## What "new" means

`nox advisories --previous <findings.json>` compares this scan with the last
scheduled run's `findings.json`, which the workflow keeps in the Actions cache.
An advisory is **new** when it is active in this scan and neither its id nor
any alias is already reported for that package in the previous run.

- **Waived is not new.** A finding already marked `baselined` or `vex_*` by the
  scan (your `.nox/baseline.json`, `--vex` document) is `waived`. A person
  decided; it is shown, never acted on.
- **Not keyed on the fingerprint.** The fingerprint hashes the message, which
  carries the advisory summary and the applicability sentence; either changing
  would make last week's advisory look newly disclosed.
- **Not keyed on the version.** The same advisory still hitting an upgraded
  package is the same advisory.
- **No previous run is not "no advisories".** The first scheduled run, or a
  cache miss, reports everything and acts on nothing: the issue step opens an
  issue for every current advisory that no existing issue (open or closed) already
  lists, so an evicted cache cannot swallow a disclosure. Otherwise adopting this
  would open a pull request for every advisory you have ever had.
- **A scan that could not look is not a quiet week.** If the vulnerability
  lookup failed, `nox advisories` exits 1, acts on nothing, and the workflow
  does not remember the run, so the next one still compares against the last
  complete scan.

The workflow saves this run for the next one as its last step, and only if every
earlier step succeeded: a run that failed part-way must not make its advisories
look known.

GitHub evicts caches unused for seven days and disables scheduled workflows in
repositories with no activity for sixty. The daily default keeps the cache warm,
and the cache is not the record of what was reported: each issue carries a hidden
`<!-- nox-advisory:ecosystem/package/id -->` marker per advisory (aliases
included, version excluded), and the next run reads those from your issues,
open and closed. A run that finds the cache gone therefore reports what has never
been reported, once, instead of nothing. What a missing cache does cost is
action: with no previous run nothing is prepared as a pull request until a
later run has one to compare with. Delete the marker comment from an issue to
have its advisory reported again.

## Run it by hand

```bash
nox scan . --format json --output nox-results
nox advisories --input nox-results/findings.json --previous last-week/findings.json
nox advisories --policy prepare --prepare-findings prepare.json ...   # override .nox.yaml
nox fix --input prepare.json --dry-run                                # what the pull request will contain
```

Output is `text`, `json` or `markdown` (`--format`). `--github` writes step
outputs (`action`, `automerge`, `new-count`, `prepare-count`, `previous-run`,
`incomplete`) and the job summary.

Exit codes: 0 decided, 1 decided but the scan could not finish looking, 2 could
not run.
