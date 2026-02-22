# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-22

### Added
- Initial red team plugin with attack path analysis and exploit validation
- 2 tools: analyze (passive), validate (active, needs confirmation)
- 10 rules (REDTEAM-001 through REDTEAM-010)
- 7 attack chain detection patterns
- HTTP header, TLS, and rate limit validation
- Opt-in AI-powered attack path reasoning via `ai_analyze: true`
- 7-provider LLM support (OpenAI, Anthropic, Gemini, Ollama, Cohere, Bedrock, Copilot)
- SDK conformance and track conformance tests
- CI/CD, lint config, pre-commit hooks
