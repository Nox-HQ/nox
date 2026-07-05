# nox-plugin-llm-triage

Optional **LLM second-opinion triage** for nox findings.

nox's core is deliberately deterministic and offline — no model, zero egress.
This plugin is the opt-in escape hatch for teams that want an LLM's judgment on
top: it reads the scan's findings, sends each one (plus a small code snippet) to
a configured chat endpoint, and attaches a triage verdict —
`true_positive`, `false_positive`, or `uncertain` — as an **enrichment** on the
original finding. It never changes or gates the scan result; enrichments
annotate, they don't decide.

## Why it's a plugin, not a core feature

The core's value is that the same inputs always produce the same outputs with no
network. An LLM breaks both properties. Keeping triage in an out-of-band,
opt-in plugin means:

- the deterministic core and its CI gate are unaffected whether or not this
  plugin is installed;
- egress of your source code to a third party is an explicit, auditable choice.

## Safety

`llm_triage` is an **active** tool with network egress. It sends your source
snippets to the configured model, so it requires explicit confirmation:

```jsonc
{
  "endpoint": "https://api.openai.com/v1/chat/completions",
  "auth_header": "Authorization: Bearer $OPENAI_API_KEY",
  "model": "gpt-4o-mini",
  "authorize": true,          // required — confirms you accept sending code out
  "workspace_root": ".",
  "min_severity": "medium",   // optional: skip below this severity
  "max_findings": 50           // optional: cap the number judged
}
```

Without `authorize: true` the tool refuses to run.

## Endpoint

Any OpenAI-compatible chat-completions endpoint works (OpenAI, a local
Ollama/LM Studio shim, a gateway). Temperature is pinned to 0 for the most
reproducible verdicts an LLM allows.

## Build

```bash
make build      # produces ./nox-plugin-llm-triage
make test
```

The plugin speaks the nox plugin gRPC protocol; nox invokes it post-scan with
the finding set as scan context and merges the returned enrichments.
