# ISO/IEC 27001:2022 technical evidence

`nox compliance iso27001` turns the outputs of a scan you already ran into
supporting material for an ISO/IEC 27001:2022 assessment. An AI agent reaches
the same thing through the read-only MCP tool `compliance_iso27001`.

This is the last beat of the vision's "ultimate user experience": the developer
asks "I'm preparing for ISO 27001. What can you help me with?", and Nox answers
from the evidence it has already collected, produces artifacts a reviewer can
read, and says what it cannot supply.

## What it is

- A reading of `findings.json`, an SBOM (`sbom.cdx.json` or `sbom.spdx.json`)
  and `ai.inventory.json`. It does not scan, does not touch the network, and
  reads no clock. The same files give the same bytes.
- For 16 Annex A controls, a statement of what the scan shows, with counts, the
  rule IDs behind them, the output file each claim comes from, and that file's
  SHA-256.
- For each control, the gaps in this run (a scope that was not scanned, an SBOM
  that was not provided, a capability that never answered) and the limits that
  hold whatever the run found.
- A checklist of the organizational evidence a repository cannot show.

## What it is not

It never says that a control is met. An Annex A control is satisfied by an
organisation operating a process: a scanner cannot see who reviews access, how
incidents are handled, or whether a policy is approved. The honest claim is
"technical evidence supporting this control", with the gaps named. It is not an
audit, a readiness score or a certificate, and an auditor will want evidence
this tool cannot produce.

The vocabulary describes the evidence, never the control:

- `supporting_evidence`: the checks ran, were complete, and have nothing open.
  The control's limits still apply.
- `open_issues`: the checks ran and found issues still open.
- `limited_evidence`: some evidence exists, but only at one remove, or part of
  the checks did not run, did not complete, or had nothing to examine.
- `not_evidenced`: the scan holds no evidence for this control.

A test fails the build if any status, or any rendered word, claims a control is
met, compliant, satisfied, passed or certified, for any input.

## Using it

```
nox scan . --format json,cdx
nox compliance iso27001 .
```

It writes `compliance/iso27001.md` (for a reviewer) and
`compliance/iso27001.json` (for tooling) and prints a short summary:

```
Nox can evidence these (checks ran, nothing open):
  A.5.17 Authentication information
Evidence exists, but issues are open:
  A.8.8 Management of technical vulnerabilities (40 open finding(s))
Nox sees only part of these:
  A.5.23 Information security for use of cloud services (see gaps)
Nox has no technical evidence for these:
  A.8.26 Application security requirements
Organizational evidence you still need: 25 items ...
```

Flags: `--findings`, `--sbom`, `--ai-inventory` to point at specific files,
`--out` for the output directory, `--json` to print the assessment to stdout,
`--no-write` for the summary only. With no `findings.json` it exits 2 and tells
you what to run; it does not scan on your behalf.

Through MCP, call `compliance_iso27001` after the `scan` tool. The result
carries the summary, the full assessment and a note telling the agent not to
tell the user a control is met.

## The mapping

Control numbers and short titles are the 2022 edition's. No other standard text
is reproduced. "Evidence" is what a scan can offer; "cannot show" is the
fixed limit of that evidence.

| Control | Title | Evidence from | Cannot show |
|---|---|---|---|
| A.5.9 | Inventory of information and other associated assets | SBOM components, AI inventory | Information assets, owners, classification, currency. Indirect: never above limited. |
| A.5.17 | Authentication information | Secret scan (SEC-*) | Credential generation, rotation, MFA, history unless a history scan ran |
| A.5.19 | Information security in supplier relationships | SBOM (suppliers named) | Agreements, assessments, monitoring. Indirect. |
| A.5.21 | Managing information security in the ICT supply chain | SBOM; SLOP, PROV, LIC, CONT rules | Build tooling and hosted services outside lockfiles; supplier practices |
| A.5.23 | Information security for use of cloud services | IaC rules (IAC-*) | Deployed cloud state, provider choice, shared responsibility, exit |
| A.5.34 | Privacy and protection of personal identifiable information (PII) | DATA-* rules | What is personal data for you, lawful basis, retention, DPIA |
| A.8.4 | Access to source code | Secret scan (credentials in tree) | Who can read or write the repository, branch protection. Indirect. |
| A.8.8 | Management of technical vulnerabilities | VULN-* against OSV.dev; SBOM; waiver counts | Non-dependency vulnerabilities, reachability beyond what a finding states, the management process |
| A.8.9 | Configuration management | IAC-*, PERM-* | Approved baselines, production drift, change authorisation |
| A.8.12 | Data leakage prevention | DATA-*, SEC-* | DLP on networks, endpoints, mail; classification. Indirect. |
| A.8.24 | Use of cryptography | CRYPTO-* and findings with crypto CWEs | Key lifecycle, cryptography policy |
| A.8.25 | Secure development life cycle | The scan record itself | That it runs on every change or blocks release. Indirect. |
| A.8.26 | Application security requirements | None | Everything: requirements are written before code. Always `not_evidenced`. |
| A.8.27 | Secure system architecture and engineering principles | AI inventory; AI-, AGENT-, MCP- rules | Architecture review, documented principles, threat models. Indirect. |
| A.8.28 | Secure coding | TAINT-, VARIANT-, MEMSAFE-, HARDEN- | Defect classes and languages not covered; standards, training, review |
| A.8.29 | Security testing in development and acceptance | The scan record, plus the `dynamic_verification` capability | Penetration tests, acceptance tests. Limited unless dynamic verification answered. |

## Guards against a false all-clear

An empty result is the dangerous output of a scanner. Three rules keep it from
reading as "fine":

- A check that found nothing only counts as evidence if the outputs show it had
  something to examine. Secret scanning applies to every file; dependency checks
  need an SBOM with components; infrastructure, data and cryptography checks
  cover files that may not exist, and `findings.json` does not record whether
  they did. Those report `limited_evidence` with that stated.
- The vulnerability lookup is network-dependent, and a scan run with `--no-osv`
  writes outputs identical to a clean one. A control that rests on it says so
  when it finds nothing, and when the scan ran with `--offline`.
- A waiver is a decision, not a clean result. Findings that are baselined,
  suppressed or VEX-cleared are counted and cited, and a control with any of them
  is `limited_evidence`: the scan cannot show who accepted the risk or why.

## Organizational evidence

The report ends with a checklist of 25 items, each citing the management-system
clause or Annex A control by number only and naming the Annex A controls in this
report that depend on it: ISMS scope, policy, roles, risk assessment and
Statement of Applicability, training, audit and management review, asset
ownership, data classification, privacy records, access control and reviews,
supplier agreements, cloud governance, incident management, continuity,
logging and monitoring, key management, the vulnerability process, change
management, the secure development procedure, security requirements,
architecture principles and the testing plan.

## Why it lives in core

`CLAUDE.md` keeps `core` deterministic, offline and read-only, and
`docs/plugin-vs-core.md` sends anything that breaks those to a plugin. This
breaks none of them: it reads three files and writes two, and has no analysis
cost. `core/compliance` already hosts the OWASP MCP Top 10 mapping for the same
reason.

The GRC plugin (`nox/grc`: `assess`, `gap_report`, `evidence`) is not
duplicated here and not replaced. A scan invokes plugins only through the
`scan` tool and tools that declare `requires_scan_context`, so `nox/grc` is
unreachable from the path a developer takes (`cli/plugin_uninvocable_test.go`),
and an agent cannot reach it through the MCP server. Making it reachable would
mean extending the plugin invocation contract for one beat of the vision. A
small mapping over outputs the scan already wrote does not need a plugin
process, a network of 12 frameworks, or an LLM, which is what the plugin offers
beyond it. A framework mapping that needs those stays the plugin's job.

Hard parts left out on purpose: no HTML artifact (Markdown and JSON are what a
reviewer attaches and what tooling reads), no scoring, no percentage "coverage",
no other frameworks (the package is `core/compliance/iso27001`; SOC 2 would be
a sibling with its own table).

## Provenance

Every assessment records the nox version that wrote it, the nox version and
date of the scan (from `findings.json`, never the clock), the scopes scanned and
not scanned, the number of degradations, the repository revision at generation
time (the scan may have run earlier), and each evidence file's base name, kind
and SHA-256. Absolute paths are never recorded, so the same evidence gives the
same artifact on any machine. `iso27001.json` carries the nox report marker, so
a later `nox scan` of the directory skips it instead of reading it as source.
