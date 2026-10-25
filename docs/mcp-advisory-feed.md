# MCP advisory feed

NOX Intelligence publishes a signed feed of public advisories for packages that
are MCP servers, MCP SDKs or otherwise concern the Model Context Protocol
(`GET /v1/feeds/mcp`; the producer's contract is nox-intelligence
`docs/mcp-feed.md`). `nox scan` joins it with the MCP servers it finds in your
client configs.

## What a finding says

`MCP-026` says: **an advisory affects this MCP server package.** For a server
that pins an exact version (`npx -y @scope/server@1.2.3`, `uvx pkg==1.2.3`), the
version lies inside an interval the advisory itself publishes. It does not say
your use of the server is exploitable, and a server with no `MCP-026` finding is
not thereby free of advisories: absence from the feed is absence from the feed.

| situation | reported as |
|---|---|
| exact version inside an advisory's interval | `MCP-026`, medium (high for a malicious-package record) |
| the advisory classifies the package as MCP-related only by its own text | the same, at low confidence (the weakest basis) |
| exact version, but the entry has no interval nox can test (a candidate's free-text range) | `MCP-026`, low, "could not be evaluated" |
| `npx -y pkg` / `uvx pkg` with no pinned version | `MCP-026`, info, "cannot be checked": advisories exist for the package, the version that runs is unknown |
| exact version outside every interval | nothing |
| not a registry package (`node server.js`, docker, a git source, a URL) | nothing: there is no registry identity to look up |

Versions are ordered with nox-core's comparison (`vulnsource.Interval`), which a
version it cannot order never matches.

## On by default

No configuration is needed. With NOX Intelligence enabled and the scan online,
the feed is fetched and verified under the **Ed25519 key built into nox**: key
id `slopfeed-key-v1`, fingerprint `sha256:168327fe999925cd025ddeaf1d1cde605dfd0641395cf021da3259c8b451fa08`. It is the same key as the slopsquat
feed's; see [intelligence.md](intelligence.md#the-signed-feeds-and-the-key-built-into-nox).
`MCP-026` findings carry `metadata.feed_key`, `built-in:slopfeed-key-v1` or
`project:sha256:...`, saying which key verified the feed.

```yaml
scan:
  mcp_feed:
    # signature_key_path: keys/noxintel.pub.pem   # optional: YOUR key, which overrides the built-in one
    # url: https://intel.klarlabs.de/v1/feeds/mcp   # default: <scan.intelligence endpoint>/v1/feeds/mcp
    # refresh: 24h
    # cache_dir: ~/.nox/cache/mcpfeed
    # disabled: true                                # opt out of this feed
```

To pin your own key, fetch it once (`GET /v1/feeds/mcp.pub.pem`), read it, commit
it, and name it. **Do not point nox at a key the server hands you on every
scan**: a key that arrives with the feed proves nothing about the feed.

**Rotation.** If the feed fails signature verification, nox asks the service which
key it serves now. When that fingerprint differs from the built-in one the
degradation names both and tells you to upgrade nox, or to review the new key and
pin it with `signature_key_path`. nox never accepts the served key on its own.

Verification is the slopsquat feed's, fail-closed: the digest over the canonical
entries is recomputed, then the Ed25519 signature over
`"nox-intelligence/mcp-advisories/v1\n" + canonical entries` is checked under the
pinned key. The prefix stops a signature made for the slopsquat feed under the
same key from verifying here. Only verified bytes are cached, and the cache is
re-verified on every read.

## When it runs

- Only when the scan found MCP servers launched from a package registry. A repo
  with none makes no request and reports nothing.
- Only when the intelligence service is in use (or `url` is set): with
  `scan.intelligence.disabled` and no `url`, nothing is fetched and the scan says
  the servers were not checked.
- `--offline` makes no request. It reads the verified cache; with none, it says so.
- Within `refresh` (24h by default) a cached feed is used without a request, so
  repeated scans are deterministic. If a refresh fails, the verified cached copy
  is used and the scan says the feed could not be refreshed.

## When it cannot check

Each of these is a `mcp_feed` degradation that says the servers were **not
checked**, never "no advisories":

| cause | blocks a build (`--fail-on-degraded`)? |
|---|---|
| the service answers 404: it does not serve the feed, or has not published one (the service's own `disabled_reason` is quoted) | no |
| `scan.intelligence.disabled` (or `scan.osv.disabled`): nothing is requested | no |
| offline with no cached feed | no |
| a stale cached copy was used because the refresh failed | no |
| the feed does not verify under the built-in or the pinned key (digest, signature, schema), including a rotated service key | **yes** |
| the service is unreachable with no cache | **yes** |

A feed that fails verification is never papered over with the cache: that is a
tampered or mis-keyed answer, and it is reported as one.
