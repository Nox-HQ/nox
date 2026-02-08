# Technical Design — Nox

## High-Level Architecture

Core design is layered:

/core

- file discovery
- analyzers
- rule engine
- findings model
- reporting (SARIF, SBOM)

/cli

- argument parsing
- output handling

/server (MCP)

- sandboxing
- rate limits
- artifact serving

/ai-assist (optional)

- agent runtime
- LLM integrations

## Core Engine

### Scan Pipeline

1. Discover artifacts
2. Classify artifact types
3. Run analyzers
4. Normalize findings
5. Fingerprint + deduplicate
6. Emit reports

### Findings Model

- Stable, versioned fingerprinting
- Explicit severity and confidence
- Precise location model
- SARIF-compatible

### Rule Engine

- YAML-based rules
- Matchers:
  - regex
  - jsonpath / yamlpath
  - heuristics
- No embedded code execution

## Reporting

### SARIF

- SARIF 2.1.0
- One run per scan
- Rule catalog populated
- Fingerprints attached to results

### SBOM

- CycloneDX JSON (primary)
- SPDX JSON (secondary)
- Optional vulnerability enrichment via OSV

## MCP Server

- Uses mcp-go
- Read-only tools
- Workspace allowlisting
- Artifact serving via MCP resources
- Output size limits

## Optional Modules

### Agent Assist

- Built on agent-go
- Consumes findings + inventory
- Produces explanations only
- No side effects

### Workflow Engine (Future)

- statekit considered only if workflows become complex
