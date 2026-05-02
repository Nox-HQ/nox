# Example: Multi-Stack AI Service

Reference polyglot project: a Go inference API that calls Anthropic
Claude, paired with a TypeScript frontend that streams from OpenAI.
Demonstrates nox's cross-language AIBOM detection and reachability
analysis.

## What nox sees

```bash
nox scan .
```

Expected output highlights:

- AIBOM `ai.inventory.json` lists **two model invocations across two
  languages**:
  - `anthropic / claude-3-5-sonnet-20241022` (Go, `api/server.go:42`)
  - `openai / gpt-4o` (TypeScript, `frontend/src/chat.ts:18`)
  - Each includes the `auth_env_var` (`ANTHROPIC_API_KEY`,
    `OPENAI_API_KEY`) and detected endpoint
- Reachability finding upgrade: VULN-001 deps that are imported
  somewhere get tagged `Reachable=true` (REACH-002, high) vs
  unreachable (REACH-001, info)
- Framework components recognised: `langchaingo`, `vercel-ai`

## What this represents

A real production AI app frequently spans languages: data ingest in
Python, inference services in Go, UI in TypeScript. Single-language
SBOM/AIBOM tools force the operator to assemble three reports
manually. nox produces a single coherent inventory across all three.
