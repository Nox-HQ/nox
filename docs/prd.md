# Product Requirements — Hardline

## Objective

Build a language-agnostic security scanner that produces standard artifacts
(SARIF, SBOM) and explicitly models AI application security risks.

## Target Users

- Individual developers
- Open-source maintainers
- Security engineers
- CI/CD systems
- AI agents (via MCP)

## Core Capabilities (Must-Have)

### Scanning Targets

- Source files (pattern-based)
- Secrets
- Dependencies (lockfiles, manifests)
- Infrastructure-as-Code
- Containers (optional early)
- AI systems (prompts, tools, RAG, logging, models)

### Outputs

Hardline must always be able to produce:

- `results.sarif` (SARIF 2.1.0, GitHub compatible)
- `sbom.cdx.json` (CycloneDX)
- `sbom.spdx.json` (SPDX)
- `findings.json` (canonical schema)
- `ai.inventory.json`

### Interfaces

- CLI (`hardline scan .`)
- MCP Server (stdio, read-only by default)

### Rule System

- Declarative rule definitions (YAML)
- Versioned rule IDs
- Deterministic matching
- Testable rules

### AI Security (First-Class)

Hardline must detect:

- prompt and RAG boundary violations
- unsafe tool exposure
- insecure logging of prompts/responses
- unpinned or unverified models/prompts

## Optional Capabilities (Explicitly Out of Core)

### Agent Assistance (Future)

- LLM-based explanations of findings
- Guided remediation suggestions
- Policy reasoning

These features must:

- be opt-in
- never affect scan results
- live in a separate module

## Non-Functional Requirements

- Offline-first
- Fast enough for CI
- Zero required external services
- Minimal dependencies in core engine

## Success Criteria

- SARIF successfully ingested by GitHub Code Scanning
- SBOMs usable by downstream tooling
- AI security findings understandable without ML knowledge
