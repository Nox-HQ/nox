# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **OWASP control mappings on runtime findings.** Each successful attack now
  carries the OWASP LLM Top 10 (2025) and OWASP Agentic Security Initiative
  (ASI) Top 10 controls it demonstrates, attached via an `owasp` metadata key
  (comma-joined `owasp-llm*` / `owasp-asi*` tags, mirroring the static AI
  analyzer rules). Mapping: jailbreak & role-confusion → `owasp-llm01`
  (Prompt Injection) + `owasp-asi01` (Agent Goal Hijack); system-prompt leak →
  `owasp-llm07` (System Prompt Leakage); tool misuse → `owasp-asi02`
  (Tool Misuse) + `owasp-llm06` (Excessive Agency). This makes nox's
  deterministic runtime red-team lane first-class and consistent with the
  static lane. A new deterministic `owaspTags(AttackKind)` is the single source
  of truth (unknown/zero kind → no mapping, never guessed).
- `TestOWASPTags` and `TestOWASPTags_EveryCorpusKindMapped` covering the kind →
  control mapping, plus `TestHandleAIEval_AttachesOWASPMetadata` asserting the
  metadata reaches an emitted finding.
