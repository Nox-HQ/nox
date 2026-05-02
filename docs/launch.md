# Launch playbook

Working draft. Audience: AI app developer (Python / TypeScript LLM
shops, LangChain / LlamaIndex / Vercel AI users, MCP server authors).
Secondary: DevSecOps engineers at AI-using SaaS.

## ICP statement

> AI app developers who ship LLM features and need a security
> baseline that knows about prompt injection, embedding leakage,
> agent tool-use lattices, and MCP server hardening — without paying
> a per-developer SaaS bill or sending source code to a vendor.

Concrete: someone writing `client.chat.completions.create(...)` in
production this quarter.

## Positioning statement (April Dunford shape)

> For AI app developers
> who need to ship LLM features without shipping LLM-specific
> vulnerabilities,
> nox is the open-source security scanner
> that detects OWASP LLM Top 10 risks (prompt injection, embedding
> leakage, agent over-privilege) alongside traditional secrets,
> IaC, and dependency scanning,
> unlike commercial scanners that bolted AI on as an afterthought
> or LLM firewalls that only catch runtime issues.
> We built it because static analyzers stop at SQL injection and
> runtime guards miss the prompt that ships with the code.

## One-line claims (use across landing page / HN / tweet)

- "OWASP LLM Top 10 detection in 30 seconds. Apache 2.0. No SaaS."
- "30+ AI security rules. Cross-file taint. Polyglot AIBOM."
- "The first security scanner that knows what your LangChain agent can do."

## Three-demo arc (ordered by emotional payoff)

### 1. Prompt injection in real LangChain code (45 seconds)

Open `examples/ai-app/agent.py`. Run `nox scan .`. Family summary
shows AI / Prompt Injection (LLM01). Tip line points at `nox fix`.
Operator sees a class of bug they didn't know was static-detectable.

### 2. Polyglot AIBOM (45 seconds)

`examples/multi-stack/`. Go API + TypeScript frontend, two LLM
providers. Run `nox scan . --output out`. Show `out/ai.inventory.json`
with both invocations: model name, file, line, auth env var. Pitch:
"this is the inventory your CISO has been asking for, and it took
zero configuration."

### 3. Adversarial corpus against running app (60 seconds)

`nox-plugin-ai-eval` plugin. Stand up the agent.py app. Run:

```bash
nox plugin call ai-eval ai_eval \
  endpoint=http://localhost:5000/chat \
  authorize=true \
  authorized_target=http://localhost:5000/chat
```

Output: "Endpoint succumbed to jailbreak (AI-EVAL-J01): marker
'dan ready' matched". Pitch: "static catches the call site;
dynamic catches whether the model actually falls over. Both ship."

## HN post (draft)

**Title:** Show HN: nox – open-source scanner with prompt-injection
and agent-lattice detection

**Body:**

Hey HN. I've been writing security tools for a few years and kept
running into the same gap: every static analyzer stops at SQL
injection / XSS / hardcoded secrets, and every "AI security" tool
is either a runtime firewall or a SaaS dashboard for vulnerability
counts. Nothing detects prompt injection at the call site.

Nox is what I built to close the gap. It's an open-source scanner
(Apache 2.0, Go binary, no SaaS) that ships with:

- **OWASP LLM Top 10 baseline** as 30+ static rules — prompt
  injection (AI-PI-*), embedding leakage to vector DB (AI-EMBED-*),
  agent tool-use lattice (AI-AGENT-*), MCP server hardening (MCP-*)
- **Polyglot AIBOM** — Python ML + Go service + TS frontend produce
  one inventory naming every model invocation across all three
  with auth env var and endpoint
- **Cross-file AI taint flow** — HTTP source → service hop → LLM
  sink works across function and file boundaries (TAINT-AI-*)
- **Adversarial corpus runner** as an opt-in plugin — fires a
  bundled jailbreak / prompt-leak / role-confusion / tool-misuse
  corpus against your running app and reports which attacks
  succeeded

Plus the boring stuff: secrets, IaC, dep CVEs with OSV fixed-in
remediation (`nox fix --apply`), SARIF for code-scanning, OpenVEX
waivers, GitHub Action, MCP server for Claude Desktop / Cursor.

Try it:

```bash
brew install felixgeelhaar/tap/nox
git clone https://github.com/nox-hq/nox && cd nox
nox scan examples/ai-app
```

Repo: https://github.com/nox-hq/nox
Marketplace: https://nox-hq.github.io/nox
Migration from Snyk: docs/migration-from-snyk.md

Looking for feedback on rule precision (we shipped TAINT-AI cross-
file detection 2 weeks ago) and what AI-specific rule families
you'd want next.

## Tweet thread (draft)

1/ Shipping nox today: open-source security scanner with first-class
LLM Top 10 detection. Apache 2.0. No SaaS.

2/ Prompt injection at the call site (not at runtime). Embedding
leakage when secrets land in vector stores. Agent tool-use lattice
when file_read + http_request live in the same agent. MCP
hardening rules. 30+ rules, all in core.

3/ Polyglot AIBOM. Python ingest + Go service + TS frontend = one
ai.inventory.json with model name + auth env + line number per
call site. Cross-language join is the moat.

4/ Cross-file AI taint flow. `request.json` → service → `chat.
completions.create` works across functions and files. Plugin
ships TAINT-AI-001 / TAINT-AI-002 today.

5/ Bonus: opt-in adversarial corpus plugin. Fires a real
jailbreak/prompt-leak/role-confusion corpus at your running app
and reports which attacks succeed. Static + dynamic in one tool.

6/ `brew install felixgeelhaar/tap/nox` then `nox scan .` Done.
GitHub Action available, MCP server for Claude/Cursor included.

7/ Repo + marketplace: github.com/nox-hq/nox

## Comparison page outline

| Capability | nox | Snyk | Semgrep | LLM-firewall |
|---|---|---|---|---|
| Prompt injection static rules | ✓ (AI-PI-*) | partial (Python only, beta) | partial (community) | runtime only |
| Embedding leakage detection | ✓ | — | — | — |
| Agent tool-use lattice | ✓ | — | — | — |
| MCP server hardening | ✓ (MCP-001..008) | — | — | — |
| Cross-file AI taint flow | ✓ (TAINT-AI-*) | — | — | — |
| Polyglot AIBOM | ✓ | partial (Python SBOM) | — | — |
| OSV remediation auto-fix | ✓ (`nox fix`) | ✓ | — | — |
| Open source license | Apache 2.0 | proprietary | Apache 2.0 (Pro = commercial) | proprietary |
| Per-seat pricing | $0 | $$$ | $$ | $$$ |
| Source ever leaves your machine | never (offline) | yes | yes (cloud rules) | yes (proxy) |

Numbers redacted until bench publishes. Don't quote rule counts; quote outcomes.

## Bench publication plan

1. Land `nox bench --autocorpus` (separate task #39).
2. Run against top 50 OSS Python projects + top 50 OSS Go.
3. Publish bench.json + bench.md to docs/benchmarks/2026-Q2.
4. Headline: "fired N rules across 100 OSS repos, X% true positive
   on hand-validated subset of Y."
5. Re-run quarterly.

## Channels (week 1)

- HN Show HN post (Tuesday morning PT for max attention)
- Tweet thread on personal account, RT from any colleague
- LinkedIn post with the benchmark numbers
- Lobste.rs link
- r/golang, r/devsecops cross-posts (light, no spam)
- DM to 5 sympathetic AI app dev influencers

## Channels (week 2-4)

- Comparison page on marketplace site
- Loom demo video (script in docs/loom-demo-script.md)
- Snyk migration walkthrough blog post
- Conference CFP submissions (BSides AI, AppSec Days)
- Outreach to LangChain / LlamaIndex teams for partner blog
- Outreach to Anthropic / OpenAI security teams for endorsement

## Anti-goals

- DON'T pitch nox as a Snyk replacement first. Lead with the AI
  wedge; Snyk-replacement is the carry-along.
- DON'T claim numbers we haven't measured. Bench output anchors
  every claim.
- DON'T sell to enterprise procurement before the AI app dev
  community adopts. Bottom-up only.
- DON'T add a SaaS upsell in v0.x. Position is "no SaaS"; breaking
  it costs the wedge.
