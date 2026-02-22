# nox-plugin-red-team

AI-powered attack path analysis and exploit validation plugin for [Nox](https://github.com/nox-hq/nox).

## Overview

Analyzes security findings to detect multi-step attack chains and optionally validates exploitability against live targets. Combines deterministic chain detection with opt-in LLM-powered attack path reasoning.

## Tools

- **analyze** — Detect attack chains from security findings (passive, read-only)
- **validate** — Validate exploitability against a target URL (active, needs confirmation)

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
