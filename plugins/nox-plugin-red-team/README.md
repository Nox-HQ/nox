# nox-plugin-red-team

AI-powered attack path analysis and exploit validation plugin for [Nox](https://github.com/nox-hq/nox).

## Overview

Analyzes security findings to detect multi-step attack chains and optionally validates exploitability against live targets. Combines deterministic chain detection with opt-in LLM-powered attack path reasoning.

## Tools

- **analyze** — Detect attack chains from security findings (passive, read-only).
  Runs under the **default policy**: it reasons over findings the core scan
  already produced, so it needs no network access, mutates nothing, and requires
  no confirmation.
- **validate** — Validate exploitability against a target URL (active, needs
  confirmation). Requires an explicit policy opt-in, because it probes a live
  target.

The two declare their requirements separately (`ToolSafety`), so `validate`
being active does not gate `analyze`. Before per-tool safety existed, the
plugin could only declare the union of both, and `analyze` was rejected under a
passive policy despite needing nothing — this README described it as passive and
was right about the tool; the manifest simply could not express it.

## Rules

| ID | Description | Severity |
|----|-------------|----------|
| REDTEAM-001 | Multi-step attack chain detected | Critical |
| REDTEAM-002 | Privilege escalation path identified | High |
| REDTEAM-003 | Data exfiltration path identified | High |
| REDTEAM-004 | Container escape chain | High |
| REDTEAM-005 | Command injection chain | Critical |
| REDTEAM-006 | Validated: security header missing | Medium |
| REDTEAM-007 | Validated: authentication weakness exploitable | Critical |
| REDTEAM-008 | Validated: injection vulnerability confirmed | Critical |
| REDTEAM-009 | Validated: TLS misconfiguration confirmed | High |
| REDTEAM-010 | Validated: rate limiting absent | Medium |

## Safety

This plugin declares `RiskActive` with `NeedsConfirmation` and `NetworkHosts("*")`. The `validate` tool performs active HTTP probing and requires explicit user consent.

## Build

```bash
make build
make test
make lint
```

## License

Apache-2.0
