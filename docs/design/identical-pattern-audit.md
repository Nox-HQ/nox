# Identical-pattern audit

An identical regex is evidence of possible duplication, not proof of it. This
audits every group of SEC rules sharing a pattern, and separates three things
that look alike in a `group by pattern` and are not alike at all.

**25 groups, 144 rules.** Measured on the built rule set at `712f67c`.

## The three kinds

| kind | groups | rules | what it is |
|---|---:|---:|---|
| A — vendor family sharing a token shape | 4 | 99 | not duplication |
| B — true semantic duplicate | 12 | 25 | one condition, two IDs |
| C — shape collision across vendors | 8 | 18 | one shape, different vendors |
| — entropy rules, no regex at all | 1 | 2 | an artifact of grouping |

The last row is SEC-161 and SEC-162. They share a pattern only because both are
entropy rules and carry no regex, so a `group by pattern` puts them together on
the empty string. They are not a collision of any kind, and are listed here so
the arithmetic reconciles rather than quietly dropping two rules.

### A — a vendor family sharing a token shape (99 rules)

Four patterns carry 99 rules between them:

| pattern | rules | example members |
|---|---:|---|
| `[a-zA-Z0-9]{32}` | 55 | Typeform, NuGet, Datadog, Adyen, SendGrid, Grafana, Splunk… |
| `[a-zA-Z0-9-]{32,}` | 24 | AI21, RunPod, Mistral, Groq, xAI, ElevenLabs, OpenRouter… |
| `[a-z0-9]{32}` | 15 | Braintree, Mixpanel, Braze, DigitalOcean, SparkPost… |
| `[a-zA-Z0-9]{20}` | 5 | PagerDuty, Zuora, Gitter, Mixpanel, Hotjar |

These are **not** duplicates: each names a different vendor and each has a
different keyword. What they share is the absence of any encoding of their
vendor's credential format — they are the class-C population, and the fix is the
binding treatment already applied to nine of them, not a merge. Merging them
would be wrong in the opposite direction: it would assert that a NuGet key and a
Splunk key are one condition.

The one thing the grouping does show is scale. Ninety-nine rules distinguish
themselves from each other by a keyword alone.

### B — true semantic duplicates (12 groups, 25 rules)

Same pattern, same vendor, same condition, two IDs:

| condition | rules |
|---|---|
| Shopify shared secret / access / custom app / private app | SEC-034+321, 035+318, 036+319, 037+320 |
| OpenSSH private key | SEC-391 + SEC-428 |
| PGP private key | SEC-392 + SEC-429 |
| Braintree access token | SEC-038 + SEC-142 |
| Mailchimp API key | SEC-059 + SEC-378 |
| SendGrid API key | SEC-153 + SEC-376 |
| GCP / Gemini `AIza` key | SEC-007 + SEC-115 + SEC-415 |
| AWS access key id | SEC-411 + SEC-508 |
| Bittrex access vs secret key | SEC-173 + SEC-174 |

The Bittrex pair is the interesting one: the two descriptions claim *different*
credentials — an access key and a secret key — but the pattern cannot tell them
apart, so both fire on whichever is present. A distinction that exists only in
the description is not a distinction the scanner makes.

These are the merge candidates. Each needs a canonical rule chosen and the
others retired into it with frozen patterns, the way SEC-569 → SEC-007 and the
seven bare-token retirements were done, so baselines and waivers keep resolving.

### C — shape collisions across vendors (8 groups, 18 rules)

Two rules for *different* vendors that share a shape. Here the risk is not
noise but **misattribution**: telling an operator to rotate a credential that
does not exist, while the one that does goes unnamed.

| shape | rules | prefix? | collapses? |
|---|---|---|---|
| `sk_live_[a-zA-Z0-9]{24}` | Stripe SEC-548, Square SEC-551, PayPal SEC-554 | yes | **yes** |
| `live_[a-zA-Z0-9]{32}` | Checkout.com SEC-562, Payoneer SEC-572 | yes | yes |
| UUID | Heroku SEC-402, Coinbase SEC-565 | **no** | **NO** |
| `[A-Za-z0-9_-]{64}` | Linode SEC-472, Scaleway SEC-527 | **no** | **NO** |
| `[a-zA-Z0-9]{30}` | Huawei SEC-530, OneSignal SEC-614 | **no** | **NO** |
| `[a-zA-Z0-9]{24}` | Square POS SEC-575, LaunchDarkly SEC-658 | **no** | **NO** |
| `[a-zA-Z0-9_-]{32,}` | Auth0 SEC-478, Webflow SEC-482 | **no** | **NO** |
| `[a-f0-9]{32}` | Bugsnag SEC-399, New Relic SEC-544, Bitfinex SEC-568 | **no** | **NO** |

Measured, not inferred:

| input | engine | output |
|---|---|---|
| a Stripe live secret key (`sk_live_` + 24) | 5 findings | **1** — SEC-030, Stripe |
| a bare UUID near `heroku_api` and `coinbase` | 2 findings | **2** — Heroku *and* Coinbase |
| a bare 64-character token near `linode_token` and `scaleway` | 2 findings | **2** — Linode *and* Scaleway |

(The literals are described rather than written out. An earlier draft spelled
them, and nox's own pre-commit scan reported three findings on this file --
including both SEC-402 and SEC-565 on the one UUID, which is the collision this
section is about, demonstrated on the document describing it.)

The prefixed collisions are already handled. The unprefixed ones are not, and
the reason is precise — see below.

## Why the prefixed ones collapse and the rest do not

`core/analyzers/secrets/dedup.go` already implements span-scoped semantic
dedup, and it is well built: it resolves the canonical owner of a span from the
token's **provider prefix**, drops other providers' findings on that span, then
drops generic entropy findings overlapping a surviving provider finding. It
records each collapse as a *Withheld* claim rather than a refutation, precisely
because the dropped finding was true — an entropy rule that matched a real
GitHub token did match a real GitHub token; it is dropped because reporting one
secret five times is noise.

That is the invariant *one observed condition should not become multiple
findings*, already implemented — for one analyzer, keyed on one signal.

Its limit is that signal. Owner resolution needs a prefix, so a shape with no
prefix has nothing to resolve, and both vendors' rules survive. That is the
whole of category C's live risk, and it is why `sk_live_` is safe while a bare
UUID is not.

## What follows

1. ~~Merge category B.~~ **Done.** Twelve groups, 13 rules retired into their
   canonical rule with frozen patterns; 899 → 886.
2. ~~Category C needs an owner signal that is not a prefix.~~ **Done for the
   unprefixed groups.** Thirteen rules are now bound to their own vendor's key
   name, so the two sides of each collision no longer match the same text and
   there is nothing for dedup to arbitrate.

   Two lessons came out of the binding itself. A rule's KEYWORD gates its
   pattern, so a keyword narrower than the binding (`webflow_key` against a
   `webflow…=` binding) stops the rule firing on the spellings it was just
   bound for — five rules needed their keywords widened. And SEC-575 is bound
   to `square_pos`, not `square`, because "squarespace" contains "square".

   **The two prefixed groups are left, and they are a different problem.**
   `sk_live_` belongs to Stripe; SEC-551 claims it as a Square access token and
   SEC-554 as a PayPal key. Binding those would produce
   `square_access… = sk_live_…`, which is still a rule looking for the wrong
   vendor's format. They need Square's and PayPal's real formats sourced, the
   way PostHog's and Cloudflare's were, and are deliberately untouched here
   rather than guessed at. The same applies to `live_` (SEC-562, SEC-572).
3. **Kubernetes is ungated on purpose — a claim I got wrong and checked.**

   An earlier revision of this document called the missing kubernetes row in
   `documentKindGates` "the seventh instance of a defect fixed six times" and
   proposed adding it. That is wrong, and the rule set already said so:
   `TestKubernetesIsNotGated` exists *"so a later change that adds a Kubernetes
   gate has to argue with this first"*, and its reason is measured — Kubernetes
   rules legitimately apply to documents that are not manifests, an Ansible
   `k8s_module` task among them, where IAC-143 on `namespace: default` was a
   true positive.

   I wrote the gate, and that test failed it, along with nine others. The gate
   is reverted.

   So IAC-031's `ignoreFilePatterns` is not a stopgap for a family fix that
   never comes — it is the correct shape of the fix. A Compose service is not a
   Kubernetes document and IAC-501 owns the condition there, which is a
   statement about one format rather than about the family's scope. The six
   gated families each had a rule scoped to a format it never belonged to;
   kubernetes rules belong wherever Kubernetes resources are declared, which is
   more places than "a Kubernetes manifest file".

4. **Lift dedup to the scanner.** The facility to generalise already exists and
   should not be rewritten; what it needs is to run over the merged finding set
   rather than inside one analyzer, and to key on the condition rather than on a
   provider prefix. `core/cross_analyzer_dedup_test.go` asks the boundary
   question and cannot see any group in this document, all of which are
   same-analyzer.

Category A is not a merge target and should not be treated as one.
