# Example: Scan an MCP server before publishing

Drop-in CI for **MCP server authors**. Scans every PR and every release
tag for MCP-specific threats and blocks the merge/release on anything
High or above — before a bad version reaches the registry your users
install from.

## What it catches

Nox maps its MCP rules to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/):

| Threat | Rules | OWASP |
|---|---|---|
| Tool poisoning (instructions hidden in tool metadata) | MCP-009..014 | MCP03 |
| Rug pull (definition changed after approval) | MCP-015 | MCP04 |
| Token passthrough, confused deputy, SSRF, weak sessions | MCP-016..021 | MCP07 |
| Shadow / rogue servers, cross-server tool shadowing | MCP-022..024 | MCP09 |
| Shell exec, broad FS scope, embedded secrets, plaintext transport, remote-code fetch | MCP-001..008 | MCP01/02/04/05/07/08 |

Plus the rest of the nox corpus: secrets, dependency CVEs, IaC, containers.

## Why `offline: true`

The scan path makes **zero outbound connections** — no API, no token, no
telemetry. Your server config and source never leave the runner. This is
enforced by a test in nox itself (`TestOSVDisabled_NoNetworkEgress`), not
just documented. Unlike scanners that proxy your MCP traffic or phone home
to a vendor API, nox runs entirely in your CI.

## How to use this in your repo

1. Copy `.github/workflows/mcp-security.yml` into your MCP server repo.
2. Commit. The next PR gets inline comments on any MCP finding; the next
   `v*` tag is blocked if a High+ finding is present.
3. SARIF lands in your repo's GitHub Code Scanning tab, tagged with the
   OWASP MCP control (`properties.owasp-mcp`).

## Run it locally first

```bash
nox scan . --offline --format sarif --output nox-out
```

Rug-pull detection (MCP-015) pins each server definition on first scan;
re-run after editing `mcp.json` and a changed definition is flagged.
