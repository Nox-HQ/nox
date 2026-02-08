
## Project Scaffold & Go Module Setup

Initialize Go module, set up directory structure (/core, /cli, /server, /ai-assist), configure golangci-lint, Makefile with build/test/lint targets, and GitHub Actions CI workflow. This is the foundation for all other features.

---

## File Discovery Engine

Core artifact discovery system that recursively walks a workspace, respects gitignore patterns, and classifies files by type (source, config, lockfile, container definition, AI component). Provides an extensible file classifier registry for adding new artifact types.

---

## Canonical Findings Model

Core data model for security findings with stable versioned fingerprinting (deterministic hash), explicit severity and confidence levels, precise source location (file, region, line, column), deduplication by fingerprint, and SARIF-compatible location model. This is the central data structure consumed by all reporters.

---

## YAML Rule Engine

Declarative rule system using YAML definitions with versioned rule IDs, deterministic matching, and pluggable matchers (regex, jsonpath, yamlpath, heuristic). Includes rule validation, testing support, and strictly no embedded code execution. Rules are the primary configuration mechanism for all analyzers.

---

## Secrets Scanner

Pattern-based analyzer for detecting secrets, API keys, tokens, and credentials in source files and configuration. Includes built-in rules for common secret patterns (AWS keys, GitHub tokens, private keys), configurable entropy-based detection, allowlist/ignore mechanism, and line-level location reporting.

---

## Dependency Scanner

Analyzer for lockfiles and dependency manifests (npm package-lock.json, Go go.sum, Python requirements.txt/poetry.lock, Ruby Gemfile.lock) that extracts package inventories with name/version/ecosystem, checks against OSV API for known vulnerabilities, and produces CycloneDX component entries for SBOM generation.

---

## SARIF Report Output

Generate SARIF 2.1.0 reports compatible with GitHub Code Scanning. One run per scan with full rule catalog populated from matched rules, fingerprints attached to results, and precise result locations. Must pass GitHub Code Scanning ingestion validation.

---

## SBOM Output (CycloneDX & SPDX)

Generate Software Bill of Materials in CycloneDX JSON (primary, sbom.cdx.json) and SPDX JSON (secondary, sbom.spdx.json) formats from dependency analysis. Component inventory sourced from dependency scanner with optional vulnerability enrichment via OSV.

---

## JSON Findings Output

Emit canonical findings.json with the full findings model, usable as machine-readable input for downstream tooling. Deterministic output ordering and schema versioning included.

---

## CLI Interface

Command-line interface with 'nox scan &lt;path&gt;' as the primary command. Supports output format selection (sarif, cdx, spdx, json, all), exit codes reflecting finding severity, quiet/verbose modes, and config file support (.nox.yaml).

---

## Infrastructure-as-Code Rules

Basic security rules for Terraform (public access, encryption), Dockerfiles (no root, pinned base images), and Kubernetes manifests (privilege escalation, host network). All defined as YAML-based rules consumed by the rule engine.

---

## AI Security Rules

First-class AI security scanning: detect prompt/RAG boundary violations, unsafe MCP/agent tool exposure, insecure prompt/response logging, unpinned model/prompt versions. Produces ai.inventory.json with extracted AI component inventory. This is a differentiating feature of Nox.

---

## MCP Server

Model Context Protocol server using mcp-go with stdio transport. Exposes read-only tools (scan, get-findings, get-sbom), workspace allowlisting, artifact serving via MCP resources, output size limits, and rate limiting. Agent-safe by default.

---

## Agent Assist Module (Optional)

Optional LLM-powered module built on agent-go that consumes findings and AI inventory to produce human-readable explanations. Strictly no side effects, never affects scan results, opt-in only, lives in a separate module boundary from core.

---

## Plugin gRPC Interface

Protobuf definitions and gRPC service contract for plugin manifests, tool invocations, and artifact exchange. Defines the PluginService with GetManifest, InvokeTool, and StreamArtifacts RPCs. Plugin manifests declare capabilities (analyzers, reporters, tools), safety requirements (network hosts, file paths, environment variables), and API version compatibility. All message types are versioned and backwards-compatible.

---

## Plugin Host Runtime

Core runtime that discovers plugin endpoints (local binaries, containers, remote gRPC), calls GetManifest to learn capabilities, validates safety constraints against host policy, manages plugin lifecycle (init, invoke, shutdown), and merges plugin results (findings, SBOM components, AI inventory entries) into Nox's unified outputs. Supports parallel plugin execution with configurable concurrency limits.

---

## Plugin Safety Engine

Host-enforced safety model that validates and constrains plugin behavior. Enforces scope allowlists (permitted network hosts/CIDRs, file path globs, environment variables), rate limits (requests per minute, bandwidth), concurrency caps, read-only defaults, artifact size limits, and secret redaction from plugin outputs. Destructive actions require explicit opt-in via nox.yaml. Safety violations are logged and cause plugin termination.

---

## Plugin SDK

Minimal SDK for plugin authors providing: versioned protobuf definitions, gRPC server scaffolding (Go initially, with extension points for other languages), manifest and capability declaration helpers, safety envelope parsing and enforcement utilities, artifact serialization helpers (findings, SBOM components, AI inventory entries), and a conformance test runner that validates plugin behavior against the contract. Includes a plugin template generator for bootstrapping new plugins.

---

## MCP Plugin Bridge

Expose plugin capabilities through the MCP server interface. Adds plugin.list tool (enumerate installed plugins and capabilities), plugin.call_tool tool (invoke a specific plugin tool with arguments), and plugin.read_resource tool (read plugin-provided resources). Supports convenience aliases that map friendly names to plugin tools (e.g., nox.dast.scan maps to a DAST plugin's scan tool). Plugin tools inherit workspace allowlisting and output size limits from the MCP server.

---

## Plugin Registry & Distribution

Registry client for discovering and installing plugins. Supports static index fetching from registry URLs, OCI artifact download with local caching and digest verification, semantic version resolution with compatibility constraints, and multiple registry sources (official Nox registry, community registries, enterprise private registries). Registry metadata includes plugin manifests, compatibility matrices, and trust information. Implements offline-friendly caching with TTL-based refresh.

---

## Plugin Trust & Verification

Signature validation and trust management for plugins. Verifies artifact signatures against configurable trust roots, checks content digests on download and before execution, validates API version compatibility between plugin and host, runs conformance tests as part of installation verification. Implements trust levels (verified: signed by known key, community: signed but unknown key, unverified: unsigned) with configurable minimum trust requirements. Enterprise deployments can mandate verified-only plugins.

---

## CLI Plugin Commands

CLI commands for managing registries and plugins. Registry commands: 'nox registry add <url>' (add registry source), 'nox registry list' (show configured registries), 'nox registry remove <name>' (remove registry). Plugin commands: 'nox plugin search <query>' (search registries), 'nox plugin info <name>' (show plugin details and trust status), 'nox plugin install <name>[@version]' (install with verification), 'nox plugin update [name]' (update one or all plugins), 'nox plugin list' (show installed plugins), 'nox plugin remove <name>' (uninstall), 'nox plugin call <name> <tool> [args]' (invoke plugin tool directly from CLI).

---
