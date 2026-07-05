# nox for VS Code

Surfaces [nox](https://github.com/nox-hq/nox) security findings inline — squiggly
underlines on the offending line, hover for the rule and message, in the Problems
panel. **Deterministic and offline**: it runs the local `nox` binary; no code
leaves your machine and no model is called.

It's a thin client over the `nox lsp` language server (JSON-RPC over stdio): on
open and save, the server scans that file and publishes diagnostics.

## Requirements

- `nox` on your `PATH` (`brew install nox`, or set `nox.path`).

## Settings

| Setting | Default | Description |
|---|---|---|
| `nox.path` | `nox` | Path to the nox executable. |
| `nox.enable` | `true` | Enable the language server. |

## Build from source

```bash
cd editors/vscode
npm install
npm run compile      # tsc → out/extension.js
```

Then press F5 in VS Code (Extension Development Host) to try it, or package with
`npx vsce package`.

## What you get

Diagnostics mirror `nox scan`: severity maps to Error (critical/high), Warning
(medium), Information (low), Hint (info); the rule ID is the diagnostic code and
`nox` is the source. Findings update on save (the server re-scans the saved
file).
