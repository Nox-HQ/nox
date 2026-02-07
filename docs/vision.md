# Hardline — Vision

Hardline is an open, language-agnostic security engine for modern software
systems, including AI-powered applications.

Its purpose is to provide deterministic, inspectable, and composable security
analysis that can be used by humans, CI systems, and AI agents alike.

Hardline is not a SaaS platform, not a dashboard, and not a black box.
It is a security primitive.

## Core Principles

### Determinism

Given the same inputs, Hardline must produce the same outputs.
No hidden state, no opaque heuristics, no non-versioned behavior.

### Auditability

All detection logic, rules, and mappings are inspectable and versioned.
Security findings must be explainable without proprietary context.

### Language Agnosticism

Hardline analyzes artifacts, not programming languages:

- files
- configs
- dependencies
- containers
- AI system components

### Agent-Native

Hardline is designed to be safely callable by AI agents via MCP,
with explicit sandboxing and read-only defaults.

### Safe by Default

Hardline never:

- uploads source code by default
- executes untrusted code
- performs destructive actions
- auto-applies fixes without explicit opt-in

## What Hardline Is Not

- A hosted security platform
- A SOC or SIEM tool
- A replacement for human security judgment
- An automatic remediation engine

## Long-Term Vision

Hardline aims to become:

- the reference open-source security scanner for MCP-based tooling
- a trusted SARIF and SBOM producer for modern CI pipelines
- a foundation layer upon which vendors, platforms, and agents can build
