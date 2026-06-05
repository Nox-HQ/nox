# DRAFT — Registry / catalog outreach (task-72)

> Status: draft for review. Local only. Adapt per target before sending.
> Companion: `docs/mcp-registry-integration.md` (the technical contract).

## Targets (in priority order)

1. **Docker MCP Catalog** — closest thing to a registry that already enforces
   scanning (Cosign, SBOMs, provenance). Best "embedded scanner" fit.
   Channel: Docker MCP GitHub org / the catalog repo's discussions.
2. **Official MCP Registry** (`modelcontextprotocol/registry`) — explicitly
   delegates security downstream; a vendor-neutral, offline scanner is exactly
   the gap they punt on. Channel: a GitHub discussion/issue proposing an
   optional security-scan tier.
3. **Downstream aggregators** (mcp.so, MCPVerified, Smithery) — faster to move,
   want a differentiator. Channel: direct.

## The message (adapt per target)

**Subject: An offline, vendor-neutral security scanner for MCP servers — proposing nox as a scan tier**

Hi [name/team],

I maintain [nox](https://github.com/nox-hq/nox), an open-source (Apache-2.0)
security scanner with first-class MCP coverage mapped to the OWASP MCP Top 10:
tool poisoning, rug-pull/definition drift, auth & SSRF, and shadow/cross-server
tool shadowing.

I think it's a strong fit for [catalog/registry]'s security needs, for three
reasons:

- **Offline & vendor-neutral.** It runs fully locally — no API, no token, no
  telemetry, enforced by a test. A submitted server's code never leaves your
  infrastructure. (Unlike scanners that proxy MCP traffic or call a vendor API.)
- **Standards-mapped, CI-native.** Findings carry their OWASP MCP control in
  SARIF (`properties.owasp-mcp`) and drop straight into GitHub Code Scanning.
- **Tuned on the real ecosystem.** I ran it against the 26 most-used public MCP
  servers (including yours, if applicable) before proposing this — zero false-
  alarm noise on generated files, lockfiles, and defensive code, and zero
  spurious vulnerability claims.

There's a ready-made integration contract — cosign-verified image, a
`--network=none` offline scan, an exit-code gate, and the SARIF schema — here:
`docs/mcp-registry-integration.md`. A one-line container invocation gates a
server before listing:

```bash
docker run --rm --network=none -v "$SERVER":/src:ro \
  ghcr.io/nox-hq/nox:latest --format sarif -q scan /src --offline
```

I'd love to wire this into [catalog/registry] as an optional (or default)
security tier, and I'm happy to do the integration work. Open to a quick call
or a PR — whichever you prefer.

[name] · github.com/nox-hq/nox

## Notes for the sender

- Lead with offline/vendor-neutral — it's the wedge vs the commercial options.
- Do NOT claim you found vulns in their servers (you didn't; that's the point).
- Offer to do the integration work — lowers their cost to yes.
- For the official registry: frame as filling the security gap their docs
  already say they delegate, not as criticism.
