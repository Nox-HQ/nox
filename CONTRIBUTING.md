# Contributing to Nox

Thank you for your interest in contributing to Nox. This guide covers how to set up your development environment, write code that meets project standards, and submit changes.

## Development Setup

### Prerequisites

- Go 1.25 or later
- [golangci-lint](https://golangci-lint.run/usage/install/)
- [buf](https://buf.build/docs/installation) (only if working on protobuf definitions)

### Getting Started

```bash
git clone https://github.com/nox-hq/nox.git
cd nox
make check
```

`make check` runs the linter, tests, and vet in sequence. All three must pass before submitting a pull request.

### Common Commands

```bash
make build        # Build the nox binary
make test         # Run all tests
make lint         # Run golangci-lint
make vet          # Run go vet
make check        # Run lint + test + vet
make fmt          # Format code with gofmt and goimports
make tidy         # Run go mod tidy
make clean        # Remove build artifacts
```

## Coding Standards

- Follow standard Go conventions and idioms.
- All code must pass `golangci-lint run ./...`, which is enforced in CI.
- Use **conventional commits** for all commit messages:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `test:` for adding or updating tests
  - `refactor:` for code refactoring
  - `chore:` for maintenance tasks
- Keep functions focused and small. Prefer clear names over comments.
- Handle errors explicitly. Do not discard errors silently.
- Use the existing patterns in the codebase (functional options, fluent builders, proto wrapping) as reference.

## Testing

- Write tests for all new code. Untested code will not be merged.
- Run the full test suite before submitting:

```bash
go test ./...
```

or

```bash
make test
```

- For coverage reporting:

```bash
make cover
```

- Use table-driven tests where appropriate.
- Tests must be deterministic and must not depend on external services or network access.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:

```bash
git checkout -b feat/your-feature-name
```

2. **Implement** your changes, ensuring all tests pass and `make check` succeeds.

3. **Commit** using conventional commit messages. Each commit should represent a single logical change.

4. **Push** your branch and open a pull request against `main`.

5. **Fill out** the pull request template with a description of your changes, the motivation, and any relevant context.

6. **CI must pass.** Pull requests with failing checks will not be reviewed.

7. **One approval** from a maintainer is required before merging.

## Plugin Development

Nox has a gRPC-based plugin system with an SDK for building custom security analyzers. If you are developing a plugin:

- See [docs/plugin-authoring.md](docs/plugin-authoring.md) for a complete guide on writing, testing, and publishing plugins.
- The SDK is located at `sdk/` and provides conformance testing, builders, and helpers.
- Plugins are organized into 10 security tracks. See [docs/track-catalog.md](docs/track-catalog.md) for track descriptions and requirements.

## Reporting Issues

- Use the [GitHub issue tracker](https://github.com/nox-hq/nox/issues) to report bugs or request features.
- Use the provided issue templates when available.
- Include reproduction steps, expected behavior, and actual behavior in bug reports.
- For **security vulnerabilities**, do not open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

This project follows a code of conduct to ensure a welcoming and inclusive community. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.
