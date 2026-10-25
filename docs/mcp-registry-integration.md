# Embedding nox as an MCP registry / catalog security gate

This is the integration contract for an MCP **registry, catalog, or
aggregator** that wants to scan servers for security before listing or
promoting them — using nox as the offline, vendor-neutral scanner.

Nox is a good fit for a registry security tier because it is:

- **Offline & deterministic** — no API, no token, no telemetry. The scan
  path makes zero outbound connections (enforced by a test,
  `TestOSVDisabled_NoNetworkEgress`). Your infrastructure stays the only
  party that sees a submitted server.
- **Standards-mapped** — every MCP finding carries its OWASP MCP Top 10
  control in SARIF (`properties.owasp-mcp`).
- **Signed & reproducible** — the container image is Cosign-signed by
  digest with SLSA provenance.

## 1. Pull and verify the scanner

```bash
# Pin by version; verify the signature against that release's exact identity
# before running (the organisation is Nox-HQ, and the match is case-sensitive).
VERSION=1.38.2
cosign verify "ghcr.io/nox-hq/nox:${VERSION}" \
  --certificate-identity "https://github.com/Nox-HQ/nox/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 2. Scan a submitted server (offline)

```bash
docker run --rm --network=none \
  -v "$SERVER_SRC":/src:ro \
  ghcr.io/nox-hq/nox:latest \
  --format sarif --output /src/.nox-out -q scan /src --offline
```

`--network=none` makes the zero-egress guarantee enforceable at the
container boundary as well as in nox itself.

## 3. Gate on the result

| nox exit code | Meaning | Suggested registry action |
|---|---|---|
| `0` | no findings at/above threshold | list / promote |
| `1` | findings present | hold for review; surface SARIF to the publisher |
| `2` | scan error | retry / investigate; do not auto-list |

Set the gate severity with `--severity-threshold high` to block only on
High+ (tool poisoning, rug-pull, auth/SSRF, and shadowing are all High+).

## 4. SARIF contract

Each `result` references a rule whose `properties` include:

```json
{
  "id": "MCP-011",
  "properties": {
    "cwe": "CWE-77",
    "owasp-mcp": "MCP03",
    "tags": ["ai", "mcp", "tool-poisoning", "data-exfiltration", "owasp-mcp03"]
  }
}
```

Registries can route or badge servers by `properties.owasp-mcp`
(MCP01–MCP10) and the `tags` array. The full mapping lives in
`core/compliance` and is asserted complete by test.

## 5. Rug-pull detection across submissions

To detect a server that was approved benign and later mutated (OWASP
MCP04), pin the reviewed definitions and commit the result:

```bash
nox mcp pin          # writes .nox/mcp-pins.json from the configs in this repo
git add .nox/mcp-pins.json
```

Every scan then compares each server definition with the pin and emits
**MCP-015** (with before/after hashes) for a definition that changed, or a server
that was never pinned. The finding is reported on every scan until the change is
accepted by running `nox mcp pin` again; a scan never edits the pin file. The pin
travels with the repository, so a clean CI runner sees the same approval you do.
With no pin file the scan says so (an MCP degradation) instead of staying silent.
The per-user cache earlier versions kept under `~/.nox/cache/mcp-pins/` is no
longer read.

## Questions

Open an issue at https://github.com/nox-hq/nox — we want nox to be the
default security gate for MCP distribution and will help wire it in.
