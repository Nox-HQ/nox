# Which plugins should run without being asked

The vision says a developer "should not need to understand which internal
analyzer, intelligence component, or plugin performs each operation." Today
`nox scan .` leaves fifteen installed plugins un-run and asks the reader to pick
from them. This document records the measurement taken to decide which of them
should instead run on their own, and the answer: **none yet**. The assessment
now describes what they would check in capability terms, and the plugins that
leave no gap are no longer offered at all.

Measured 2026-10-24, nox built from `be676bb`, the 15 plugins installed on a
developer machine (`nox plugin list`), `--offline --no-osv` so that only the
plugin differs between two runs.

## Method

For each plugin, one run with that plugin alone in `plugins.required` against
one run with none, on the same tree, on six trees:

| Tree | Why |
|---|---|
| the SaaS app (Express, Postgres, Stripe, an LLM call) | the vision's own example; it has a real missing-ownership-check endpoint |
| `stefanprodan/podinfo` @ dd507173 | Go service with a Dockerfile, Kubernetes manifests, HTTP and WebSocket |
| `kubernetes/examples` @ d6b8cd27 | 30 workloads and 15 Dockerfiles |
| `sahat/hackathon-starter` @ 1927ea6b | large Express app, `package-lock.json` |
| `klarlabs-studio/chronos` @ d969c13e | Go API server, Dockerfile, compose |
| `certbot/certbot` @ 2b817be1 | Python, requirements files |

Every added finding was read. Reachability and threat-enrich were also run with
OSV on, because offline there is nothing for a reachability plugin to classify.

## Result

Added findings, per tree (SaaS, podinfo, k8s-examples, hackathon, chronos,
certbot). `E` is enrichments, which annotate existing findings.

| Plugin | Added | Runs from `nox scan` | Verdict |
|---|---|---|---|
| nox/container | 0, 1, 60, 0, 3, 6 | yes | every finding restates a core rule (IAC-121 healthcheck, IAC-122 no USER, IAC-003 ADD, CONT-002 latest tag, IAC-126 apt cache), under a second rule ID; the "no USER" and "no multi-stage" findings are always reported at line 15. Keep off: it double-counts. Core covers it |
| nox/reachability | 0, 0, 0, 1/E1, 0, 0 offline; online SaaS 40, podinfo 5, hackathon 7, certbot 37 | yes (post-scan) | **unsound.** Online it reports `body-parser`, `qs` and `path-to-regexp` as "NOT imported — likely false positive" in an Express app that calls `express.json()` and `app.use(...)`, i.e. executes all three. Express depends on them directly. It turns "did not check a transitive dependency" into a negative. Core says `undetermined`, which is true. Retire |
| nox/taint-analysis | 1, 0, 0, 0, 0, 2 | yes | the one SaaS finding is TAINT-001 "SQL injection" on `new Pool({ connectionString: process.env.DATABASE_URL })`: an environment variable is not a tainted query. Already archived for precision (0 TPs, 8 FPs over core 1.33.0). Retire |
| nox/triage-agent | 5, 121, 5, 423, 27, 212 | yes | pattern matches in test files and on `require("jsonwebtoken")`, ranked "high priority". 423 on hackathon-starter. Noise buries the signal. Retire |
| nox/threat-model | 0, 8, 0, 19, 17, 24 | yes | `if token == ""` reported as "authentication bypass pattern", `fmt.Fprintf(os.Stderr, "error: %s", err)` as "information disclosure". It flags the check, not the bypass. Retire |
| nox/depconfusion | 1, 0, 1, 20, 0, 0 | yes | 19 of hackathon-starter's 20 are "scoped package @langchain/langgraph has no explicit registry source": public packages on the public registry, which is the correct state. The SaaS one says the same of npm as a whole. Dependency confusion needs a private scope; this cannot tell. Keep opt-in, do not enable |
| nox/attack-surface | 13, 7, 11, 109, 19, 0 | yes | ATTACK-001 is an endpoint inventory at severity info, not a finding. ATTACK-002 "potentially unauthenticated" is wrong on the SaaS app for `/webhook` (Stripe-signed), `/login` (must be open) and `/api/invoices` (every route has `requireAuth`): 0 of 5. Keep opt-in; the inventory belongs in core data, not findings |
| nox/api-abuse | 2, 2, 0, 3, 7, 0 | yes | 14 findings: 1 real (SaaS `GET /:id` reads an invoice by id with no ownership check, the vision's own example), 1 true but minor (no rate limit on `/login`), 7 verbose-error patterns of debatable value, 5 false positives (a `GetEnvVar` accessor in generated `.pb.go` as "BOLA"; a `Last-Event-ID` header as a "user ID"; three `json.Decode` into request DTOs as "mass assignment"). Keep opt-in. Core has since gained AUTHZ-001, which reports the same `GET /:id` as a lead with a two-account test, so the one real finding no longer needs the plugin |
| nox/threat-enrich | 0 (E 1, 189, 806, 112, 56, 148) | yes (post-scan) | adds a CWE, OWASP and ATT&CK technique to findings.json. Deterministic, offline, 0.1 s. But nothing in nox reads it, and some mappings are wrong (CWE-359 private-information exposure to T1552 "unsecured credentials"). Keep opt-in |
| nox/grc | 0 | **no** | provides `assess`, `gap_report`, `evidence`; a scan calls none of them. Registered, never invoked |
| nox/remediate | 0 | no | rejected at registration: wants filesystem `**`, active risk class, user confirmation. It applies changes; a scan is read-only |
| nox/dast | 0 | no | rejected: network `*`. HTTP probing of a running application |
| nox/k8s-runtime | 0 | no | rejected: network `*`. Inspects running workloads, not manifests |
| nox/ai-eval | 0 | no | rejected: network `*`. Fires a jailbreak corpus at a chat endpoint |
| freshness | 0 | no | the sideloaded binary in `state.json` (`~/Developer/open_source/nox-plugin-freshness/...`) no longer exists |

Cost was never the issue: no plugin added more than about 1.3 seconds, most of it
process start and handshake. Precision is.

## Why nothing is auto-enabled

1. **A plugin that hurts precision must not run unasked.** Five of the nine that
   run from a scan (reachability, taint-analysis, triage-agent, threat-model,
   depconfusion) are measured net-negative; container restates core; two more
   (attack-surface, api-abuse) are mostly wrong. The previous measurement of
   running every installed plugin took the precision corpus from 1.0000 to
   0.3394 with 72 new false positives, and this run found nothing that changes
   that arithmetic.
2. **"Run when the technology is detected" is not enough for determinism.**
   Detecting a Dockerfile selects a plugin only if it happens to be installed.
   Two developers on one repository would get different findings depending on
   their machines, which breaks "same inputs produce the same outputs, no
   hidden state". Anything auto-enabled has to be part of nox, versioned with
   it, or declared by the project.
3. **The ones that cannot run from a scan are active by design.** dast,
   k8s-runtime and ai-eval need a live target and a network; remediate writes
   files. `nox scan` is read-only and offline-capable, and `nox attack` is where
   live testing is planned and authorized.

Safety, for the record: every plugin that runs from a scan declares no network
host, passive risk class and no file paths, and is registered under its
registry track's profile. Declaration is the enforcement: the host checks the
manifest, it does not sandbox the process. For what a declaration is worth,
`strings(1)` on the binaries shows an HTTP client linked into reachability,
k8s-runtime, dast, triage-agent, grc and ai-eval, and `os/exec` in
reachability, k8s-runtime and remediate. That is not proof of use, and it is
the reason none of this should be auto-enabled on a declaration alone.

## What changed in the product

The assessment no longer names plugins. `core/plugincap` maps each plugin to a
capability and a class:

- **Optional**, a check core does not perform: named under "Not checked"
  ("API abuse patterns (rate limiting, error detail)", "exposed endpoints and admin or debug routes",
  "dependency-confusion exposure").
- **Live**, needs a running system: named once, as live testing that needs an
  explicit go-ahead, pointing at `nox attack plan`.
- **Covered** (core does it), **Retired** (measured harmful) and **Adjunct**
  (annotates, plans or reports): not listed. Telling a developer that container
  configuration was not checked would be false, and offering reachability would
  send them to something that mislabels a real dependency.

Accounting is unchanged. The degradation still lists every plugin that did not
run, with names, as an advisory entry in `findings.json` and in the
`[degraded]` line under `--verbose`; `--fail-on-degraded` is unaffected. An
unclassified (third-party) plugin is treated as an optional check, never hidden.

## How a person turns one on

By capability, never by plugin: `nox enable api-abuse` (or `nox enable all` for
every installed optional check, `nox enable --list` to see them). It splices
`plugins.required` into `.nox.yaml`, keeping the file's comments and layout, and
reads the result back the way a scan does. The assessment prints the exact
command for the checks it did not run. This changes who types the plugin name,
not the default: nothing above meets the bar to run unasked.

## What would change the answer

- **Core absorbs the real finding.** This happened during the work: the one
  true positive here, a missing ownership check on `GET /:id`, is now reported
  by core as AUTHZ-001, with a precision the plugin never had (it fires on
  generated code and on DTO decodes). That is the route by which a plugin's
  value should reach a default scan.
- **A plugin earns a place in core, versioned with nox.** The way to run
  something without configuration deterministically is to ship it in the
  binary, which is what happened to taint and to reachability applicability.
- **A plugin passes the precision corpus on its own.** Re-run this table; the
  `core/plugincap` test pins the classes so a change is a visible diff.

## Reproducing

Build nox, install the plugins, then per tree and plugin:

```bash
printf 'plugins:\n  required:\n    - nox/api-abuse\n' > .nox.yaml
nox scan . --offline --no-osv --no-auto-install -output out/api-abuse
```

and compare `findings.json` fingerprints against a run without `.nox.yaml`.
Compare `findings` and `enrichments` both; threat-enrich adds no findings.
