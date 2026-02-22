# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
