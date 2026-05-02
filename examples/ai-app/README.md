# Example: AI App

Reference Python LangChain + OpenAI app that intentionally exhibits the
OWASP LLM Top 10 risks nox detects.

## What's wrong with this code

Run `nox scan .` from this directory and you'll see, at minimum:

- `AI-PI-001` — `agent.py` interpolates `request.json` straight into a
  ChatCompletion prompt (LLM01: prompt injection).
- `AI-PI-002` — system role receives untrusted persona string from
  request body.
- `AI-EMBED-001` — `ingest.py` embeds `os.getenv("STRIPE_SECRET")`
  into Pinecone (LLM06: secret leakage to vector store).
- `AI-AGENT-002` — `tools.py` registers `read_file` + `http_post`
  (file_read + http_request lattice → exfiltration risk, LLM07).
- `MCP-002` — `mcp.json` grants the filesystem MCP server scope to
  `/Users/<you>` instead of a project subdirectory.

Everything in this directory is **deliberately broken** to demonstrate
detection. Don't ship code that looks like this.

## How to run

```bash
nox scan .
nox scan . --format sarif --output out
nox vex init --input out/findings.json --output vex.json
```

## What an unbroken version looks like

See `safe.py` for the same functional shape with each finding fixed
(structured messages, env-var reference instead of literal secret,
narrow tool capabilities, scoped MCP path).
