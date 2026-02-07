
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

Command-line interface with 'hardline scan &lt;path&gt;' as the primary command. Supports output format selection (sarif, cdx, spdx, json, all), exit codes reflecting finding severity, quiet/verbose modes, and config file support (.hardline.yaml).

---

## Infrastructure-as-Code Rules

Basic security rules for Terraform (public access, encryption), Dockerfiles (no root, pinned base images), and Kubernetes manifests (privilege escalation, host network). All defined as YAML-based rules consumed by the rule engine.

---

## AI Security Rules

First-class AI security scanning: detect prompt/RAG boundary violations, unsafe MCP/agent tool exposure, insecure prompt/response logging, unpinned model/prompt versions. Produces ai.inventory.json with extracted AI component inventory. This is a differentiating feature of Hardline.

---

## MCP Server

Model Context Protocol server using mcp-go with stdio transport. Exposes read-only tools (scan, get-findings, get-sbom), workspace allowlisting, artifact serving via MCP resources, output size limits, and rate limiting. Agent-safe by default.

---

## Agent Assist Module (Optional)

Optional LLM-powered module built on agent-go that consumes findings and AI inventory to produce human-readable explanations. Strictly no side effects, never affects scan results, opt-in only, lives in a separate module boundary from core.

---
