# Predictive slopsquat feed (SLOP-002)

Nox's `SLOP-001` rule is **reactive**: it flags an import at scan time when the
imported package appears in no manifest, no standard library, and no local
module — a name your code depends on that resolves to nothing you brought in.
That catches a hallucinated dependency *after* an LLM has already written it
into your code.

The **predictive slopsquat feed** adds a second, forward-looking dimension
(`SLOP-002`). A feed is a versioned, content-addressed list of package names
that an LLM is *likely to hallucinate* and that were verified **unregistered
(squattable)** when the feed was generated. When an imported name matches a
high-risk feed entry, `SLOP-002` fires — even if the name is already declared in
a manifest, which is the dangerous "you may have installed the squat" case that
`SLOP-001` cannot see.

This mirrors the pattern proven by nox's OSV integration: **intelligence
accumulates centrally as a versioned data feed; every device enforces it
deterministically and offline.** The difference is that the network is removed
from scan time entirely — only the out-of-band generator touches a registry; the
scanner consumes a frozen artifact.

## Default-safe

The predictive dimension is **opt-in and off by default**. With no feed
configured, the SLOP analyzer behaves exactly as it always has: `SLOP-001` only,
no `SLOP-002`, identical findings, identical grade. Enabling a feed is purely
*additive* — it never changes the `SLOP-001` baseline.

## Enabling it

In `.nox.yaml`:

```yaml
scan:
  slop:
    # "bundled" uses the feed shipped inside the nox binary. Any other value is
    # a path to a feed JSON file (relative to the scan root, or absolute).
    feed: bundled

    # Optional signature enforcement (see "Trust model"). Digest integrity is
    # always enforced regardless of these.
    require_signature: false          # reject an unsigned / bad-signature feed
    signature_key_path: keys/slopsquat.pub.pem  # PEM Ed25519 public key
```

To point at your own regenerated feed instead of the bundled one:

```yaml
scan:
  slop:
    feed: security/slopsquat-blocklist.v1.json
```

## What `SLOP-002` reports

For an imported name that matches a feed entry, `SLOP-002` emits a finding whose
severity is derived from the entry's risk tier (deliberately one notch below the
tier's face value — it is a predictive heuristic, not proof of compromise):

| feed tier  | `SLOP-002` severity | confidence |
|------------|---------------------|------------|
| `critical` | High                | Medium     |
| `high`     | Medium              | Medium     |
| `medium`   | Low                 | Medium     |

The finding carries the feed provenance in its metadata: `tier`, `pattern`,
`neighbor_of`, `verified_at`, `feed_version`, and `feed_digest`, so every
predictive finding is traceable back to the exact feed that produced it.

## Feed format

A feed is a single JSON document (schema `slopsquat-blocklist/v1`):

```json
{
  "schema_version": "slopsquat-blocklist/v1",
  "version": "2026.07.25",
  "generated_at": "2026-07-25T10:30:22Z",
  "source": "cmd/slopfeed",
  "digest": "sha256:f9ae0d9a…",
  "signature": {                      // optional
    "algorithm": "ed25519",
    "key_id": "…",
    "value": "base64(sig)"
  },
  "entries": [
    {
      "name": "openai-utils",
      "ecosystem": "pypi",            // "pypi" | "npm"
      "pattern": "obvious",           // obvious | composition | typo
      "risk": 0.82,
      "tier": "critical",             // critical | high | medium
      "reason": "UNREGISTERED (404 confirmed twice on 2026-07-25) …",
      "verified_at": "2026-07-25"
    }
  ]
}
```

The only claim an entry makes is the narrow, defensible one: *this name was
unregistered (verified on `verified_at`) and is one an LLM is likely to emit, so
an attacker could register it to catch hallucinated installs.* A feed never
contains a registered package — see "No false accusations" below.

## Trust model

The format mirrors the plugin registry's trust model (`registry/trust`):

- **Content digest.** Every feed carries `digest: "sha256:<hex>"` computed over a
  canonical (sorted, fixed-field-order) serialization of its entries. On load,
  nox recomputes the digest and **rejects any feed whose bytes do not match.**
  This catches truncation, tampering, and corruption.
- **Fails closed.** A feed that does not decode, whose schema is unknown, whose
  digest mismatches, or whose required signature does not verify is **rejected**:
  the predictive dimension stays off, the scan continues, and a visible
  *degradation* (`slop_feed`) is recorded so the missing coverage is never
  mistaken for "nothing high-risk found". A malformed feed never crashes the
  scan.
- **Signature (optional).** The format reserves an Ed25519 signature over the
  same canonical bytes, so a feed can be Sigstore/cosign-signed exactly like a
  plugin artifact. Verification is a pluggable hook; set `require_signature:
  true` with a `signature_key_path` to enforce it. A present-but-invalid
  signature is always a hard failure, even when `require_signature` is false.

Only this repository ships a real feed today; **standing up a signed CDN
distribution channel is org infrastructure and is intentionally deferred** (see
"Deferred"). The consumer already has the verification seam.

## Regenerating the feed

The feed is produced by `cmd/slopfeed`, the maintained port of the research
prototype. It models how LLMs hallucinate names, generates the candidates, and
checks public registries **read-only, rate-limited, re-verifying every 404**:

```bash
# Live regeneration (writes the bundled feed). Good-citizen defaults: a
# descriptive User-Agent, a 300–400ms delay between requests, exponential
# backoff on 429/5xx, and a stratified request budget.
go run ./cmd/slopfeed \
  --out core/analyzers/slop/feed/data/slopsquat-blocklist.v1.json \
  --limit 150 --sleep 350ms --version "$(date -u +%Y.%m.%d)"

# Candidate model only, no network (inspect what would be checked):
go run ./cmd/slopfeed --dry-run
```

The generator writes the digest automatically. Re-run periodically: registries
change, and a name unregistered today can be claimed tomorrow (by a defender
*or* an attacker), so each entry is stamped with the `verified_at` date it was
confirmed unregistered.

### No false accusations

The generator asserts exactly one thing — "**unregistered + high-likelihood =
squattable**" — and it verifies the "unregistered" half before writing it:

- A `404` is **re-queried a second time**; only a name that returns `404`
  **twice** is written (registries are eventually consistent, so one `404` is not
  proof). A `404`-then-`200` is treated as registered.
- A **registered** name (HTTP `200`) is **never** written to the feed and never
  accused of anything. The generator only ever proposes names that are *not*
  known-real packages, and drops any candidate that collides with a real seed.

## Responsible disclosure / dual-use

A predictive blocklist is, by construction, also an attacker's shopping list:
the entries are unregistered names an attacker could claim. The constructive use
is **defensive registration** — the same move security teams already use for
high-value typosquats. The names in a feed could be pre-registered (by the
ecosystems, by the maintainers of the neighbouring real packages, or via a
coordinated placeholder) to deny them to attackers.

Treat a freshly generated feed as sensitive: share it through responsible
channels with that defensive framing rather than publishing a raw list. The
bundled feed in this repo is a small, curated set already verified unregistered;
it exists so the feature works out of the box and has something to test against.

## Deferred (org infrastructure)

- **Signed CDN distribution.** Real Sigstore/cosign signing of feeds and a
  hosted, mirrored distribution channel (à la the plugin registry) is
  organization infrastructure. The format carries a digest and a signature seam
  today; the pipeline that signs and serves feeds is out of scope for this
  change.
- **Live LLM emission priors.** The candidate priors model the generator from
  documented hallucination modes. Real LLM logprobs / emission frequencies would
  sharpen them and are the obvious next step.
