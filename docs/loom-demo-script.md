# Loom Demo Script — Nox 5-Minute Walkthrough

Target length: 5 minutes. Tone: confident, low-key. No competitor
call-outs; let the capability speak for itself. Each section lists the
spoken script in bold, screen action in italics, and the runtime
budget.

Pre-record setup:
- Terminal: 24-row, large font, dark theme
- Two demos cloned locally: `examples/ai-app/`, `examples/multi-stack/`
- Browser tab open to a clean repo's GitHub Code Scanning page
- `nox` 1.0+ on PATH, plugins bundled

---

## 0:00 – 0:15 · Hook

**"This is Nox. It's an open-source security scanner that ships with
prompt-injection detection, vector-DB leakage rules, and an agent
tool-use lattice analyser — the OWASP LLM Top 10 as a baseline, not a
plugin."**

*Show terminal at the prompt. Type `nox version` and hit enter.*

---

## 0:15 – 0:50 · What nox does in one scan

**"One command, no signup, no API key. Let me run it against an AI
app I deliberately broke."**

*Switch to `examples/ai-app/` directory. Run:*

```bash
nox scan .
```

*Wait for output (should complete in <5s). Highlight the family
summary line:*

> [families] AI / Prompt Injection (LLM01):2, AI / Embedding Leakage
> (LLM06):2, AI / Agent Lattice (LLM07):3, MCP Hardening:2

**"Eleven findings, grouped by category. Three Tip lines at the
bottom telling me what to do next. No 1500-rule firehose; just what's
relevant to this codebase."**

*Scroll to the [tip] lines.*

---

## 0:50 – 1:50 · The AI moat — three rule families

**"Let me show you what's actually under those families."**

*Open `agent.py` in the editor side-by-side with terminal.*

```bash
nox scan . --format json --output out --quiet
cat out/findings.json | jq '.findings[] | select(.RuleID | startswith("AI-PI")) | {RuleID, Location: .Location.FilePath, Line: .Location.StartLine, Message}'
```

**"AI-PI-001 — that's prompt injection. The function on line 17 of
agent.py interpolates `request.json` straight into a chat completion
call. AI-PI-002 — same risk, but worse: tainted input lands in the
system role, where the model is trained to defer."**

*Show the agent.py source matching the line numbers.*

**"AI-EMBED-001 — embedding `os.getenv('STRIPE_SECRET')` into
Pinecone. Once that lands in a vector store, it's there forever.
Retrieval-query hit returns the secret to whoever asks."**

*Open `ingest.py` and circle the `client.embeddings.create(... input=os.getenv ...)` line.*

**"AI-AGENT-001 — shell_exec is a tool the agent can call. By itself
that's critical. AI-AGENT-002 — file_read plus http_request in the
same agent context: an LLM with both can read your secrets and POST
them to an attacker server. The lattice analyser computes the
combination, so you see the exfiltration risk, not just two
unconnected findings."**

*Open `tools.py`. Highlight the three `Tool(name=...)` registrations.*

---

## 1:50 – 2:35 · Polyglot AIBOM

**"Real AI apps span languages. Inference in Go, frontend in
TypeScript, ingest in Python. Single-language scanners produce three
disconnected reports. Watch this."**

*Switch to `examples/multi-stack/`. Run:*

```bash
nox scan . --output out
cat out/ai.inventory.json | jq '.model_provenance'
```

*Highlight two entries in the output:*

```json
[
  {
    "name": "claude-3-5-sonnet-20241022",
    "registry": "anthropic",
    "path": "api/server.go",
    "line": 27,
    "auth_env_var": "ANTHROPIC_API_KEY"
  },
  {
    "name": "gpt-4o",
    "registry": "openai",
    "path": "frontend/src/chat.ts",
    "line": 18,
    "auth_env_var": "OPENAI_API_KEY"
  }
]
```

**"Two models, two languages, captured automatically. File, line,
auth env var, endpoint when present. This is what the AI Bill of
Materials looks like when the data goes in cross-language."**

*Open `ai.inventory.json`. Scroll to `components` block to show
agent_framework and vector_store entries.*

---

## 2:35 – 3:15 · One-liner remediation

**"Findings without remediation are a triage tax. Nox emits the OSV
fixed_in version on every dependency CVE. Then `nox fix` applies them
for you."**

*Run:*

```bash
nox fix --input out/findings.json --dry-run
```

*Show the plan output. Major-bumps clearly marked as skipped.*

```
plan: go get github.com/example/dep -> 1.2.4  (VULN-001)
note: 1 major-bump upgrade skipped (use --include-major to apply)
```

**"Dry-run by default. `--include-major` if you want to take the
breaking changes. Run without `--dry-run` and it edits the go.mod and
runs `go mod tidy`. No PR back-and-forth."**

---

## 3:15 – 4:00 · Baseline, waiver, hook

**"Three commands wire nox into a project."**

*Run, narrating each:*

```bash
nox vex init --input out/findings.json --output vex.json
```

**"`vex init` produces an OpenVEX waiver document — one statement
per finding, all defaulted to `under_investigation`. You triage by
editing the file and committing it."**

```bash
nox install-hook
```

**"`install-hook` writes a pre-commit hook that scans staged files
and blocks commits with critical or high findings. `git commit
--no-verify` still bypasses if you need to."**

```bash
nox doctor
```

**"`doctor` reports your environment, plugin state, external tooling.
First thing to paste in a bug report."**

---

## 4:00 – 4:30 · CI

**"For CI, drop the action into your workflows directory."**

*Open `examples/ci-baseline/.github/workflows/security.yml` in the
editor. Walk through the inputs:*

- `severity-threshold: high` — blocks on critical+high only
- `vex: vex.json` — honours committed waivers
- `changed-since: origin/main` — sub-second PR scans
- SARIF upload step — findings land in the GitHub Code Scanning tab

*Switch to the browser tab showing GitHub Code Scanning. Show one
nox-emitted finding rendered with file/line annotation.*

**"PR comments inline, code-scanning tab populated, no SaaS in the
loop."**

---

## 4:30 – 4:55 · Close

**"What you saw: OWASP LLM Top 10 detection, polyglot AIBOM with
auth-source capture, OSV remediation, baseline-via-VEX, pre-commit
hook, GitHub Action, code-scanning integration. All on one binary,
all offline-capable, all open-source under Apache 2.0."**

**"`brew install felixgeelhaar/tap/nox` to start. Repo and docs at
github.com/nox-hq/nox. Issues and PRs welcome."**

*Show the GitHub repo's README briefly, then fade.*

---

## 4:55 – 5:00 · End card

*Static end card with:*

- nox logo
- `github.com/nox-hq/nox`
- `brew install felixgeelhaar/tap/nox`

---

## Production notes

- **Cuts**: every section is a clean break — re-record any one of them
  without redoing the rest.
- **B-roll**: while scanning, show file content side-by-side; while
  narrating CI, show the YAML and the live result.
- **No competitor mentions**: the demo stands on the capability. If a
  viewer compares against another tool, that's their call to make.
- **Audio**: pause one beat at the end of each section. Don't
  rush-link them — the silence helps the takeaway land.
- **Captions**: bold-the-feature-names so the hard-to-spell ones
  (AI-EMBED, AI-AGENT-LATTICE, OpenVEX) come through clearly even
  with sound off.
- **Length budget**: 5:00 hard cap. If it runs long, drop the `nox
  doctor` mention from section 5 — it's the easiest lift.

## Outline at a glance

| Time | Section | What's on screen |
|---|---|---|
| 0:00 | Hook | `nox version` |
| 0:15 | One-scan demo | `nox scan .` family summary |
| 0:50 | AI moat | jq on findings.json, agent.py, ingest.py, tools.py |
| 1:50 | Polyglot AIBOM | jq on ai.inventory.json |
| 2:35 | nox fix | dry-run plan output |
| 3:15 | vex init / install-hook / doctor | three sequential commands |
| 4:00 | CI | security.yml in editor + Code Scanning tab |
| 4:30 | Close | tagline + repo URL |
