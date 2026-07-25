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

In `.nox.yaml`, `scan.slop.feed` accepts three kinds of value:

```yaml
scan:
  slop:
    # "bundled" uses the feed shipped inside the nox binary. A local path
    # (relative to the scan root, or absolute) uses a feed JSON file. An
    # https:// URL uses a remotely published, signature-verified feed.
    feed: bundled

    # Optional signature enforcement (see "Trust model"). Digest integrity is
    # always enforced regardless of these.
    require_signature: false          # reject an unsigned / bad-signature feed
    signature_key_path: keys/slopsquat.pub.pem  # PEM Ed25519 public key
```

To point at your own regenerated feed file instead of the bundled one:

```yaml
scan:
  slop:
    feed: security/slopsquat-blocklist.v1.json
```

To consume the **remotely published, signed** feed (recommended — the feed
accumulates centrally and every device pulls and verifies it, the OSV pattern):

```yaml
scan:
  slop:
    feed: https://github.com/nox-hq/nox/releases/download/slopfeed-latest/slopsquat-blocklist.v1.json
    require_signature: true                         # fail closed on a bad/absent signature
    signature_key_path: security/slopfeed.pub.pem   # the pinned publisher key
    cache_dir: .nox/cache/slopfeed                  # optional; defaults to ~/.nox/cache/slopfeed
    refresh: 24h                                    # optional; how long a cached copy is fresh (default 24h)
```

nox fetches the feed once, verifies its digest **and** its Ed25519 signature
against the pinned public key, and caches the verified bytes content-addressed on
disk. Subsequent scans within `refresh` use the cache with **no network call**,
so scans stay offline and deterministic. `nox scan --offline` never touches the
network at all: a URL feed is served from the verified cache, or the predictive
dimension fails closed with a visible degradation.

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
- **Signature.** The format carries an Ed25519 signature over the same canonical
  bytes. Verification is a pluggable hook; set `require_signature: true` with a
  `signature_key_path` to enforce it. A present-but-invalid signature is always a
  hard failure, even when `require_signature` is false. nox verifies against the
  key **you pin** — it never trusts a key embedded in the feed itself, so a
  self-described key cannot forge trust.
- **Remote feeds fail closed on every path.** For an `https://` feed, a fetch
  error, a non-200 status, an oversized body, a digest mismatch, a
  wrong-identity or absent-but-required signature, or (offline) a missing cache
  all disable the predictive dimension and record a `slop_feed` degradation. An
  attacker who MITMs the feed cannot inject a name nox would then flag, nor
  suppress an existing one, without a signature that verifies under the pinned
  key — verification gates *use*, and only verified bytes are ever cached.

### Why Ed25519 (published key) rather than cosign keyless

Plugins are signed with cosign keyless (Sigstore). The feed uses **Ed25519 with a
published public key** instead, for one reason: **offline, deterministic
verification.** cosign keyless verification needs the `cosign` binary on PATH and
a network round-trip (Rekor / OIDC trust root) at *verify* time — which would
reintroduce the network into scan time, breaking the offline-first and
determinism guarantees this feature exists to keep. Ed25519 verification is a few
lines of the standard library, fully offline, and reuses the exact primitives in
`registry/trust` (`ParsePublicKey`, `VerifySignature`) and the feed's own
`Ed25519Verifier`. The trade-off is key management (below) instead of an OIDC
identity.

## Remote signed distribution (the full trust chain)

Intelligence accumulates centrally as a signed, versioned artifact; every device
pulls and verifies it. End to end:

1. **Generate** — the `slopfeed-publish` workflow runs `cmd/slopfeed`, which
   models hallucinated names and re-verifies each one **unregistered** against
   public registries (read-only, rate-limited). This is the *only* network step,
   and it runs out of band in CI, never at scan time.
2. **Sign** — the same run signs the feed with `--sign-key`, an Ed25519 private
   key held **only** as the `SLOPFEED_SIGNING_KEY` repository secret. `Sign`
   re-derives the content digest and signs the canonical entry bytes, so no entry
   can change without invalidating the signature.
3. **Publish** — the workflow uploads the signed `slopsquat-blocklist.v1.json`
   and the matching `slopfeed.pub.pem` public key as release assets: a dated,
   immutable `slopfeed/<version>` release for provenance, and a rolling
   `slopfeed-latest` release that gives operators a **stable HTTPS URL**.
4. **Fetch** — a client with an `https://` feed configured downloads it once,
   bounded in size and time, and caches the verified bytes content-addressed
   under `cache_dir`.
5. **Verify** — nox recomputes the digest and checks the Ed25519 signature
   against the operator's pinned `signature_key_path`. Only bytes that verify are
   cached or trusted.
6. **Enforce** — a verified feed drives `SLOP-002`. Any failure fails closed with
   a `slop_feed` degradation; a fresh verified cache serves later scans offline.

### What a maintainer must configure

The publish pipeline assumes a signing identity. Before it can publish:

```bash
# 1. Generate the feed-signing keypair (once).
openssl genpkey -algorithm ed25519 -out slopfeed.key
openssl pkey -in slopfeed.key -pubout -out slopfeed.pub.pem

# 2. Store the PRIVATE key as the repository secret SLOPFEED_SIGNING_KEY
#    (paste the contents of slopfeed.key). NEVER commit the private key.
#    Optionally set the SLOPFEED_KEY_ID variable for signature labelling.

# 3. Distribute the PUBLIC key (slopfeed.pub.pem) to operators out of band:
#    commit it to consuming repos and point signature_key_path at it. It is also
#    attached to every release for convenience, but pin it from a channel you
#    trust (trust-on-first-use or a reviewed commit), not from the same URL you
#    fetch the feed from.
```

The workflow (`.github/workflows/slopfeed-publish.yml`, `schedule` +
`workflow_dispatch`) fails loudly if `SLOPFEED_SIGNING_KEY` is unset rather than
publishing an unsigned feed. It requests only `contents: write` on the publishing
job and needs no `id-token` (Ed25519 signing is secret-based, not keyless OIDC).

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

## Deferred / next steps

- **Live LLM emission priors.** The candidate priors model the generator from
  documented hallucination modes. Real LLM logprobs / emission frequencies would
  sharpen them and are the obvious next step.
- **Key rotation & transparency.** Rotating the Ed25519 signing key today means
  re-distributing the pinned public key to operators. A published key history (or
  a small transparency log) would let clients rotate without a manual re-pin. The
  signature already records a `key_id` to make this tractable.
- **Mirrored distribution.** The feed is served from GitHub release assets over
  HTTPS. A mirrored/CDN channel would add availability, but is not required for
  correctness — a signed feed is safe to fetch from any mirror because
  verification, not transport, is the trust boundary.
