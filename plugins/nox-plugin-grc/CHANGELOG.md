# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **AI-governance frameworks: NIST AI RMF 1.0, ISO/IEC 42001, and the EU AI
  Act.** Maps the AI/agent/MCP rule families (AI-*, AI-PI-*, AI-EMBED-*, AGENT-*,
  MCP-*) to the AI-specific governance standards a static scanner can evidence —
  e.g. EU AI Act Art.14 (human oversight) ← AGENT-002, Art.15.5 (cybersecurity /
  resilience to manipulation) ← AGENT-001/003 + MCP tool-poisoning, NIST AI RMF
  MEASURE-2.7 (adversarial security) ← the prompt-injection rules. Process-only
  controls with no automatable check keep an empty mapping so coverage reflects
  reality. 12 → 15 frameworks.

## [0.2.0] - 2026-02-24

### Added
- FedRAMP Low, Moderate, and High compliance baselines (`fedramp.go`)
- 25/38/42 NIST 800-53 controls per baseline with full rule mappings
- 302/523/595 unique nox rules covered per baseline
- `TestFedRAMPBaselineInclusion` — verifies High ⊇ Moderate ⊇ Low
- `TestFedRAMPControlCounts` — verifies expected control counts per baseline

### Changed
- Frameworks increased from 10 to 12 (replaced single `fedramp` with 3 baselines)
- `assessFrameworkSpecific` SC-28 encryption check scoped to Moderate/High only
- `TestFrameworksByName` updated for 12 frameworks

## [0.1.0] - 2026-02-22

### Added
- Initial GRC plugin with 10 compliance frameworks
- 3 tools: assess, gap_report, evidence
- 10 rules (GRC-001 through GRC-010)
- Gap analysis with coverage percentage and priority remediation
- Evidence collection mapped to framework controls
- Opt-in AI-powered gap analysis via `ai_assess: true`
- 7-provider LLM support (OpenAI, Anthropic, Gemini, Ollama, Cohere, Bedrock, Copilot)
- SDK conformance and track conformance tests
- CI/CD, lint config, pre-commit hooks
