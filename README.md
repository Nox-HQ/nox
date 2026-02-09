# Nox

![CI](https://github.com/nox-hq/nox/actions/workflows/ci.yml/badge.svg)
![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

**Language-agnostic security scanner with first-class AI application security.**

Nox produces standard artifacts (SARIF, SBOM) and explicitly models AI application security risks. It is designed to be callable by humans, CI systems, and AI agents (via MCP).

## Highlights

- **Deterministic** -- same inputs produce same outputs, no hidden state
- **Auditable** -- all detection logic is versioned and inspectable
- **Language-agnostic** -- analyzes artifacts: files, configs, dependencies, containers, AI components
- **Agent-native** -- safely callable by AI agents via the Model Context Protocol (MCP)
- **Safe by default** -- never uploads source code, never executes untrusted code, never auto-applies fixes
- **Offline-first** -- zero required external services
- **Standard output** -- SARIF 2.1.0, CycloneDX SBOM, SPDX SBOM

## Quick Start

### Install

```bash
go install github.com/nox-hq/nox/cli@latest
```

### Build from source

```bash
git clone https://github.com/nox-hq/nox.git
cd nox
make build
```

### Run a scan

```bash
nox scan .
```

This discovers artifacts in the current directory, runs all applicable analyzers, and writes results to the output directory.

## Architecture

Nox is organized into four top-level packages with a strict dependency direction (`core` depends on nothing, others depend on `core`):

```
core/       Scan engine (no CLI, no network)
cli/        Argument parsing, output handling
server/     MCP server (stdio, sandboxed, rate-limited)
plugin/     gRPC-based plugin system with 10 security tracks
```

### Scan Pipeline

```
Discover --> Classify --> Analyze --> Normalize --> Deduplicate --> Report
```

1. **Discover** artifacts (files, configs, lockfiles, containers, AI components)
2. **Classify** artifact types
3. **Run analyzers** (pattern-based secrets, dependencies, IaC, AI security)
4. **Normalize** findings into a canonical schema
5. **Fingerprint and deduplicate**
6. **Emit reports** in standard formats

## Output Formats

| File | Format |
|---|---|
| `results.sarif` | SARIF 2.1.0 (GitHub Code Scanning compatible) |
| `sbom.cdx.json` | CycloneDX JSON |
| `sbom.spdx.json` | SPDX JSON |
| `findings.json` | Canonical findings schema |
| `ai.inventory.json` | AI component inventory |

## AI Security

AI security is a first-class feature, not an afterthought. Nox detects:

- **Prompt and RAG boundary violations** -- injection vectors in prompt templates and retrieval pipelines
- **Unsafe MCP tool exposure** -- overly permissive tool definitions in agent configurations
- **Insecure prompt logging** -- sensitive data leaking through prompt/response logs
- **Unpinned models and prompts** -- unversioned or unverified model references

AI security rules live alongside traditional security rules in the core engine and follow the same deterministic, auditable design.

## Plugin Ecosystem

Nox supports a gRPC-based plugin system organized into 10 security tracks:

| Track | Purpose |
|---|---|
| core-analysis | Static analysis, secrets, code patterns |
| dynamic-runtime | Runtime behavior and dynamic analysis |
| ai-security | AI/ML-specific security concerns |
| threat-modeling | Threat identification and modeling |
| supply-chain | Dependency and supply chain security |
| intelligence | Threat intelligence integration |
| policy-governance | Policy enforcement and compliance |
| incident-readiness | Incident response preparation |
| developer-experience | Developer tooling and feedback |
| agent-assistance | AI agent integration and safety |

The official plugin registry includes 37 plugins across these tracks. See `docs/plugin-authoring.md` for building your own plugins using the SDK at `sdk/`.

## MCP Server

Nox includes a built-in MCP (Model Context Protocol) server that allows AI agents to invoke scans safely:

- Read-only tools with workspace allowlisting
- Artifact serving via MCP resources
- Output size limits enforced
- Sandboxed execution with rate limiting

```bash
nox server --stdio
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the pull request process.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

Nox is licensed under the [Apache License 2.0](LICENSE).
