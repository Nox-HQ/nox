# DRAFT — We scanned the 26 most-used MCP servers. Zero vulnerabilities. Here's what we actually learned.

> Status: draft for review. Numbers are real (scans run 2026-06, nox built
> from main). Do not publish until reviewed. No third-party vulnerability is
> reported — there were none to report.

We just shipped MCP threat detection in [nox](https://github.com/nox-hq/nox):
24 rules across tool poisoning, rug-pull, authorization/SSRF, and shadow
servers, all mapped to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

Before asking anyone to trust it, we pointed it at the ecosystem — the 26
most-used public MCP servers (the official `modelcontextprotocol/servers`
monorepo, GitHub, Microsoft Playwright, Notion, Supabase, Cloudflare, Sentry,
MongoDB, Stripe, Grafana, Atlassian, and more) plus 17 of our own.

The headline isn't a vuln count. It's the opposite.

## Finding 1: the top of the ecosystem is clean

**Zero genuine MCP vulnerabilities across all 43 servers. Zero findings
requiring disclosure.** No tool poisoning, no rug-pulls, no token passthrough,
no shadowed tools, in any of them. That's good news worth saying plainly: the
most-installed MCP servers are well-built.

So this post isn't a hit list. It's about the harder, less glamorous problem.

## Finding 2: the hard problem is precision, not detection

A security scanner that cries wolf is worse than no scanner. Our first passes
were noisy — and every bit of noise taught us something. A few of the bugs we
found *in our own scanner*:

- **A pattern that matched the word `false`.** Our "content filtering disabled"
  rule was missing a regex group, so it matched bare `null`/`false`/`disabled`
  anywhere. On Cloudflare's MCP server it fired **6,327 times** — almost all on
  an auto-generated TypeScript type-definition file. Real bug, real fix.
- **A rule that matched `"35"`.** The "deprecated GPT-3.5" check was so loose it
  matched the digits `35` in version strings and hashes. Now it requires a
  `gpt-` prefix.
- **Flagging our users' defenses.** Our SSRF rule fired on a server's own
  *blocklist* of cloud-metadata IPs — code that was doing exactly the right
  thing. We taught the rule to recognize a deny-list context.
- **A 1.4 MB minified bundle hiding in a `.ts` file.** One server ships a vite
  build output as a string export. Filename-based filters missed it; we added
  content-based detection of generated/minified blobs.

Across the corpus, false positives collapsed round over round:

| Server | MCP/AI findings, first pass | after tuning |
|---|---|---|
| Cloudflare | 6,327 | 0 |
| MongoDB | 38 | 1 |
| Stripe | 183 | ~few |
| (20 of 26 servers) | — | 0 |

Total across 26 servers after tuning: **0 true positives**, the rest
informational or filtered noise. Every fix is locked behind a regression test.

## The near-miss that says it all

Our tool-poisoning rule flagged a line in GitHub's MCP server:

> *"Do NOT tell the user the issue was created… the user MUST click Submit."*

The rule keys on "do not tell the user" — a concealment phrase. But the code is
doing the *responsible* thing: telling the model not to claim success before the
user confirms. **The scanner surfaced it; a human cleared it in seconds.** That
loop — machine breadth, human judgment — is the point. We'd rather show you a
handful of explainable maybes than hide behind a green check.

## Why this matters: it never left our machines

Every one of these scans ran `--offline`. No API, no token, no telemetry — the
scan path makes zero outbound connections, and that's enforced by a test, not a
promise. We scanned other people's servers without their code ever leaving the
runner, and we have nothing to disclose because there was nothing to find.

That's the whole pitch. Point nox at your MCP server:

```bash
nox scan . --offline
```

Findings map to the OWASP MCP Top 10 and upload to GitHub Code Scanning. It
never phones home. We tuned it against 43 real servers — including the most
popular ones in the world — before asking you to run it.

---

*nox is open source (Apache-2.0). MCP rules, the offline guarantee, and the
generated-file noise filter are all in [main](https://github.com/nox-hq/nox).*
