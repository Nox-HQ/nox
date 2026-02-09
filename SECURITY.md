# Security Policy

## Reporting a Vulnerability

We take the security of Nox seriously. If you discover a security vulnerability, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Go to [Security Advisories](https://github.com/nox-hq/nox/security/advisories/new)
2. Click "Report a vulnerability"
3. Provide a detailed description of the vulnerability

Alternatively, email security@nox-hq.dev with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- Acknowledgment within 48 hours
- Status update within 7 days
- We aim to release a fix within 30 days of confirmation

### Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No       |

### Scope

The following are in scope:

- Nox core scanner (`core/`, `cli/`, `server/`)
- Plugin host (`plugin/`)
- Official plugins (`plugin-repos/nox-plugin-*`)
- Registry client (`registry/`)

### Recognition

We appreciate responsible disclosure and will acknowledge security researchers in our release notes (with permission).

## Security Design

Nox is designed with security as a core principle:

- **Read-only by default**: never uploads source code, never executes untrusted code
- **No embedded code execution** in the rule engine
- **Sandboxed MCP server** with workspace allowlisting
- **Deterministic**: no hidden state or opaque behavior
