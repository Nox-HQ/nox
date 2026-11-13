# ADR 0003: A SARIF result points at a descriptor carrying its own severity

- Status: Accepted
- Date: 2026-11-11
- Deciders: nox maintainers
- Supersedes: —

## Context

GitHub Code Scanning rates an alert critical, high, medium or low from one
field: `properties.security-severity` on the rule descriptor (`reportingDescriptor`)
the result points at. A result's own `level` changes only the error / warning /
note filter. Fields GitHub does not list as supported — `suppressions`, `rank`,
`kind`, result property bags — are ignored. (GitHub, "SARIF support for code
scanning", checked 2026-11-11.)

nox changes a finding's severity after its rule assigns it, on purpose and in
several places:

- reachability and context downgrades (`original_severity` in metadata);
- `scan.rules.severity_override` and `scan.conditional_severity`;
- distro urgency for packages inside a base image;
- value classes: a vendor's published example key (info), a test-mode key (medium);
- VULN-001, one rule whose findings carry each advisory's own severity.

nox's own reports, exit codes and gates follow the finding's severity. GitHub
did not. Two defects followed:

1. With the catalog embedded (`nox scan --format sarif`), every finding was
   rated at its rule's declared severity. A published AWS example key, reported
   by nox at info, was a high alert on GitHub; an unreachable critical stayed
   critical.
2. Without the catalog (the MCP surface), each rule's descriptor was built from
   whichever of its findings sorted first. One info finding sorting ahead of a
   real leak took the leak's security severity away entirely, and fixing that
   first finding re-rated every other alert of the rule.

## Decision

A descriptor carries exactly one severity, and a result points at the descriptor
carrying its own:

- A finding at its rule's **declared** severity is reported under the rule's id,
  unchanged.
- Any other finding is reported under `<rule>/<severity>` — the hierarchical
  sub-rule form SARIF §3.27.5 provides — with the rule's description, help,
  tags and CWE, the new severity, and a `parent-rule` property naming the rule.
- A rule nox does not declare (a plugin's) has no severity to compare against,
  so all of its findings are named by severity.
- The descriptor a finding gets depends on the finding and the declared catalog
  only, never on the scan's other findings. Surfaces that do not embed the
  catalog still receive it (`Reporter.Declared`) so the CLI and MCP name every
  finding identically.

The fingerprint is unchanged. `findings.json`, baselines, waivers and VEX key on
it and are unaffected.

## Alternatives considered

- **Name variants by reason** (`SEC-001/published-example`). Readable, but only
  covers the reasons enumerated; a reachability downgrade or a user override
  would stay mis-rated, and every new refiner would need a new name. Severity is
  what GitHub reads, so severity is the key.
- **Suppress or drop re-rated findings in SARIF.** GitHub ignores
  `suppressions`; dropping them hides verdicts nox still reports everywhere else.
- **Rate the descriptor at the rule's highest finding.** Still one rating for
  many severities, and still dependent on the rest of the scan.
- **One descriptor per VULN-001 advisory.** Fixes VULN-001 only; the general
  rule above already gives each VULN-001 alert its advisory's severity.

## Consequences

- On upgrade, every alert whose finding is not at its rule's declared severity
  closes once and reopens under its variant id, now at the right rating.
  Dismissals on those alerts do not carry over; GitHub matches alerts by
  `ruleId` and location fingerprint. Plugin alerts move once to `<rule>/<severity>`.
- After that, an alert's id changes only when its finding's severity does —
  e.g. a dependency becoming reachable moves `VULN-001/medium` to `VULN-001` —
  which is GitHub showing a re-rating, not churn.
- An embedded catalog grows by the variants in use, not by five per rule.
