# nox-plugin-grc

Governance, Risk & Compliance plugin for [Nox](https://github.com/nox-hq/nox).

## Overview

Provides compliance assessment against 10 frameworks with gap analysis, evidence collection, and optional AI-powered remediation guidance.

## Frameworks

| Framework | Controls | Focus |
|-----------|----------|-------|
| SOC 2 | TSC + CC | Trust services criteria |
| ISO 27001 | Annex A | Information security management |
| GDPR | Articles 5-49 | Data protection & privacy |
| FedRAMP | AC/AU/IA/SC/SI | US federal cloud security |
| HIPAA | 164.3xx | Healthcare data protection |
| PCI-DSS | 12 requirements | Payment card security |
| NIST 800-53 | AC/AU/IA/RA/SA/SC/SI | Federal information systems |
| NIST CSF | 5 functions | Cybersecurity framework |
| CIS Controls v8 | 18 controls | Prioritized security actions |
| CMMC | 5 levels | Defense contractor maturity |

## Tools

- **assess** — Run compliance assessment against specified frameworks
- **gap_report** — Generate comprehensive gap analysis for a framework
- **evidence** — Collect compliance evidence for framework controls

## Rules

| ID | Description | Severity |
|----|-------------|----------|
| GRC-001 | Critical control gap | High |
| GRC-002 | Framework coverage below threshold | Medium |
| GRC-003 | Stale compliance evidence | Medium |
| GRC-005 | Missing data protection controls (GDPR) | High |
| GRC-006 | Insufficient access control evidence (SOC2) | High |
| GRC-007 | Missing encryption at rest evidence (FedRAMP) | High |
| GRC-009 | Missing continuous monitoring (NIST CSF) | Medium |
| GRC-010 | CMMC maturity level gap | Medium |

## Build

```bash
make build
make test
make lint
```

## License

Apache-2.0
