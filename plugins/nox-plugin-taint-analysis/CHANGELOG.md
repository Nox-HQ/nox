# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial intraprocedural taint analysis plugin
- Go AST-based analysis using go/ast and go/parser
- Regex-based analysis for Python, JavaScript, and TypeScript
- 5 taint flow rules: SQL injection, command injection, XSS, path traversal, code injection
- Sanitizer detection to reduce false positives
- Multi-line source-to-sink tracking within function bodies
