# nox for JetBrains

Surfaces [nox](https://github.com/nox-hq/nox) security findings inline in
JetBrains IDEs — squiggly underlines on the offending line, hover for the rule
and message, entries in the Problems view. **Deterministic and offline**: it
runs the local `nox` binary; no code leaves your machine and no model is called.

It's a thin client over the `nox lsp` language server (JSON-RPC over stdio): on
open and save, the server scans that file and publishes diagnostics — the same
findings as `nox scan`, mapped to IDE severities.

## Requirements

- `nox` on your `PATH` (`brew install nox`), or set the `NOX_PATH` environment
  variable to the binary.
- A JetBrains IDE with the **platform LSP API**: IntelliJ IDEA **Ultimate**,
  GoLand, PyCharm **Professional**, WebStorm, RubyMine, PhpStorm, CLion, or
  Rider, **2023.2 or newer**.

### Community editions (IntelliJ IDEA / PyCharm Community)

The platform LSP API isn't available in the free Community editions. Install the
[LSP4IJ](https://plugins.jetbrains.com/plugin/23257-lsp4ij) plugin and register a
new language server with the command `nox lsp` — the diagnostics are identical.

## Build from source

```bash
cd editors/jetbrains
./gradlew buildPlugin      # produces build/distributions/nox-jetbrains-*.zip
./gradlew runIde           # launch a sandbox IDE with the plugin loaded
```

Install the built ZIP via **Settings → Plugins → ⚙ → Install Plugin from Disk**.

> Note: this module is not built in nox's Go CI (it needs the JetBrains/IntelliJ
> SDK, which Gradle downloads on first build). It mirrors the
> [VS Code extension](../vscode) one-to-one over the same `nox lsp` server.

## What you get

Diagnostics mirror `nox scan`: severity maps to Error (critical/high), Warning
(medium), Weak Warning (low), Information (info); the rule ID is the diagnostic
code and `nox` is the source. Findings update on save (the server re-scans the
saved file).
