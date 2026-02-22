# nox-plugin-taint-analysis

Intraprocedural taint analysis plugin for [Nox](https://github.com/nox-hq/nox). Tracks data flow from untrusted sources (HTTP parameters, environment variables, CLI arguments) to dangerous sinks (SQL queries, shell commands, HTML output) within function bodies.

## Rules

| ID | Description | Severity | CWE |
|---|---|---|---|
| TAINT-001 | SQL Injection: tainted input flows to SQL execution | High | CWE-89 |
| TAINT-002 | Command Injection: tainted input flows to shell execution | Critical | CWE-78 |
| TAINT-003 | XSS: tainted input flows to HTML output | High | CWE-79 |
| TAINT-004 | Path Traversal: tainted input flows to file operations | High | CWE-22 |
| TAINT-005 | Code Injection: tainted input flows to eval/deserialization | High | CWE-94 |

## Supported Languages

- **Go**: AST-based analysis using `go/ast` and `go/parser`
- **Python**: Regex-based with variable tracking
- **JavaScript/TypeScript**: Regex-based with variable tracking

## Build

```bash
make build
make test
make lint
```

## License

Apache-2.0
