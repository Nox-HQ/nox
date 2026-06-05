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
# Pin by tag or digest; verify the signature before running.
cosign verify ghcr.io/nox-hq/nox:latest \
  --certificate-identity-regexp 'https://github.com/nox-hq/nox/.*' \
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
MCP04), persist the nox pin store (`~/.nox/cache/mcp-pins/`) between scans
of the same server identity. A changed definition emits **MCP-015** with
before/after hashes. Mount a per-server volume at that path to keep the
baseline.

## Questions

Open an issue at https://github.com/nox-hq/nox — we want nox to be the
default security gate for MCP distribution and will help wire it in.
