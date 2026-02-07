# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hardline is an open-source, language-agnostic security scanner that produces standard artifacts (SARIF, SBOM) and explicitly models AI application security risks. It is designed to be callable by humans, CI systems, and AI agents (via MCP). Written in Go.

Key design constraints:
- **Deterministic**: same inputs produce same outputs, no hidden state
- **Offline-first**: zero required external services
- **Read-only by default**: never uploads source code, never executes untrusted code, never auto-applies fixes
- **No embedded code execution** in rule engine

## Architecture

Four top-level packages with strict dependency direction (`core` depends on nothing, others depend on `core`):

```
/core       — scan engine (no CLI, no network)
/cli        — argument parsing, output handling
/server     — MCP server (stdio, sandboxed, rate-limited)
/ai-assist  — optional LLM-based explanations (separate module, no side effects)
```

### Core Scan Pipeline

1. **Discover** artifacts (files, configs, lockfiles, containers, AI components)
2. **Classify** artifact types
3. **Run analyzers** (pattern-based secrets, dependencies, IaC, AI security)
4. **Normalize** findings into canonical schema
5. **Fingerprint + deduplicate**
6. **Emit reports** (SARIF, CycloneDX SBOM, SPDX SBOM, findings JSON, AI inventory JSON)

### Rule Engine

- YAML-based declarative rules with versioned IDs
- Matchers: regex, jsonpath/yamlpath, heuristics
- Rules must be testable and deterministic

### Output Formats

| File | Format |
|---|---|
| `results.sarif` | SARIF 2.1.0 (GitHub Code Scanning compatible) |
| `sbom.cdx.json` | CycloneDX JSON |
| `sbom.spdx.json` | SPDX JSON |
| `findings.json` | Canonical findings schema |
| `ai.inventory.json` | AI component inventory |

### MCP Server

- Built on `mcp-go`
- Read-only tools with workspace allowlisting
- Artifact serving via MCP resources
- Output size limits enforced

### AI Assist (Optional Module)

- Built on `agent-go`
- Consumes findings + inventory, produces explanations only
- Must never affect scan results
- Opt-in only

## Build & Development Commands

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a single test
go test ./core/... -run TestName

# Lint
golangci-lint run

# Run the CLI
go run ./cli/main.go scan .
```

## AI Security Scanning (First-Class Feature)

Hardline detects:
- Prompt and RAG boundary violations
- Unsafe tool exposure in MCP/agent configurations
- Insecure logging of prompts/responses
- Unpinned or unverified models/prompts

This is not an afterthought — AI security rules live alongside traditional security rules in the core engine.

## Development Phases

The project follows a phased roadmap starting from Phase 0 (foundation: CLI scaffold, file discovery, secrets scanning, JSON output) through Phase 5 (optional agent-assisted intelligence). See `docs/roadmap.md` for details.

## Key Design Decisions

- **Findings model**: stable versioned fingerprinting, explicit severity/confidence, precise location, SARIF-compatible
- **SBOM**: CycloneDX is primary, SPDX is secondary; optional vulnerability enrichment via OSV
- **No SaaS, no dashboards, no automatic remediation** — Hardline is a security primitive, not a platform
