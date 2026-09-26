# Scanning a recorded HTTP exchange

A VCR cassette is a YAML file recording real requests and real responses from a
test run. Python projects using `vcrpy` or `betamax` and Ruby projects using
`VCR` commit thousands of them.

They are also, measured, the single largest source of secret findings nox
produces on real software.

## The measurement

crewAI at 1.15.21, scanned with nox 1.35.0: **SEC-161 and SEC-162 produced 540
findings and every one was inside `tests/cassettes/`.** Classified by the token
immediately preceding the matched value:

| count | preceded by | what it is |
|---:|---|---|
| 202 | `__cf_bm` | Cloudflare bot-management cookie, from `Set-Cookie` |
| 148 | *(nothing)* | continuation lines of a wrapped base64 response body |
| 58 | `id` | request and response identifiers |
| 44 | `embedding` | base64 float32 vectors, up to 8,193 characters |
| 32 | `_cfuvid` | Cloudflare visitor cookie, from `Set-Cookie` |
| 32 | `thoughtSignature` | Gemini response metadata |
| 8 | `api_key` | PostHog's `phc_` project key |

Not one is a credential the repository holds. The `api_key` row is the sharpest:
SEC-661 was redesigned specifically to stop reporting `phc_`, because PostHog
documents it as publishable — and the generic entropy rule reported it anyway,
from inside a recorded response body.

## The thing that made this urgent

Before any of that could be suppressed, one question had to be answered: **what
would nox find in a cassette that is worth finding?**

`vcrpy` does not filter headers. Unless the author configured `filter_headers`,
the `authorization:` header goes into the file verbatim, and committing a live
API key that way is a known, common accident. That is the finding a cassette
scan exists to produce.

nox could not produce it.

SEC-082's pattern was `(?i)(authorization|auth)\s*[=:]\s*['"]?Bearer\s+…`. Go's
`\s` crosses a newline, so `authorization:\n  Bearer x` matched. What did not
match is the form every recording uses, because an HTTP header may repeat and
is therefore a **list**:

```yaml
    headers:
      authorization:
      - Bearer <token>
```

`\s*` cannot cross the `-`. Measured: a credential written inline was reported,
and the identical credential written as a one-element YAML sequence was not.

(The placeholder is deliberate. An earlier draft wrote a realistic
`sk-proj-`-prefixed value here, and SEC-082 reported this document — the rule
firing on the text explaining the rule, which is a true positive and a blocked
pull request. The shape being illustrated is the sequence dash, not the token, so
the literal was not carrying its weight. Nothing is waived: `<` is outside the
character class the pattern accepts after `Bearer `, so there is no longer a
credential-shaped string here to report.)

**Had the suppression shipped first, cassettes would have become quiet while
remaining unchecked, and the two states read identically from the outside.**
SEC-082 and SEC-083 now accept the sequence indicator in both block (`- x`) and
flow (`[x]`) form — which fixes every YAML header map, not only cassettes.

## The rule

> Inside a recorded HTTP exchange, a credential this repository holds appears in
> a request header that authenticates the request, or in the request URI.
> Everything else — request and response bodies, response headers, cookies in
> either direction — is traffic.

A cookie is excluded in both directions deliberately. In a recording it is a
session the server issued and the client echoed back; it expired long ago, and
nobody here can rotate it.

## What the rule is applied to, and what it is not

The gate covers **SEC-161 and SEC-162 only** — the rules whose entire claim is
that some bytes are random. A recording is full of random bytes that are not
credentials, so entropy establishes nothing there.

Every rule that encodes a vendor's credential format is left alone and fires
anywhere in the recording, request body included. That is where an OAuth
`client_secret` sits in a recorded token exchange, and a rule that matched
`ghp_…` has established what it found regardless of which YAML key it sat under.

**The gap this leaves, stated rather than discovered later:** a credential with
no recognised vendor format, hardcoded into a recorded request *body*, is now
reported by nothing. Entropy alone would have caught it. That is the price of
removing 254 findings from one repository, and it is bounded by the provider
rules covering every format nox knows.

## Recognising one

By reading the document, never the path. A cassette is conventionally under
`tests/cassettes/`, but that is a convention: gating on the path would miss
cassettes stored elsewhere and — the expensive direction — suppress every
genuine secret in any directory somebody happened to name that.

Two conditions, both required:

1. a top-level `interactions:` or `http_interactions:` key, and
2. at least one `request:` block.

The second is not redundant. The gate confines the entropy rules to the request
side, so a document with the marker and no request block would have no
credential-bearing span at all and *everything* in it would be withheld.
`interactions:` is a plausible key in an ordinary configuration file.

## Bounding the blocks

By indentation, with one correction that cost a debugging round: a YAML sequence
sits at the **same** indentation as the key it belongs to. Bounding on `indent >
keyIndent` alone ends the `authorization:` block at the key line and leaves
`- Bearer …` outside it — classifying the one credential worth finding as
traffic. A sequence item at equal indent continues the block.

HAR — the JSON format with the same request/response shape — is not handled.
That is a gap, not an oversight; it is written down here so it can be closed
deliberately.
