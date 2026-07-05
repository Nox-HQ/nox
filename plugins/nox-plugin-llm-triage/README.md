# nox-plugin-llm-triage

Optional **LLM second-opinion triage** for nox findings.

nox's core is deliberately deterministic and offline — no model, zero egress.
This plugin is the opt-in escape hatch for teams that want an LLM's judgment on
top: it reads the scan's findings, sends each one (plus a small code snippet) to
a configured chat endpoint, and attaches a triage verdict —
`true_positive`, `false_positive`, or `uncertain` — as an **enrichment** on the
original finding. It never changes or gates the scan result; enrichments
annotate, they don't decide.

The model is a **second opinion, not a scanner**: nox finds and grounds every
candidate deterministically, and the LLM only confirms/explains the residual.

## Grounding guarantee — the LLM can never invent a finding

Every finding is located deterministically (rule ID, file, line, fingerprint)
before any LLM is involved. The plugin asks the model to judge **only that one
finding at that one location** and enforces it structurally:

- `buildPrompt` hands the model the exact, immutable rule ID, `file:line`, and
  code snippet, and explicitly instructs it: *do not report new findings, do not
  propose a different location.*
- `parseVerdict` extracts a **verdict + rationale only** — it never reads a file
  path or line number from the reply.
- The resulting enrichment is anchored to the **original finding's fingerprint**
  (copied from the input finding, never from model output).

So a model that hallucinates a different file/line — or claims a second issue —
in its prose is inert: the text can only ever land in the free-form rationale,
never as a new or moved finding. The only observable effect of triage is an
enrichment on a pre-existing, deterministically located finding.

## Deterministic-first routing — spend tokens only on the residual

Before any LLM call, findings are **de-duplicated** (by fingerprint, or rule +
`file:line` when a fingerprint is absent) so the model is never asked the same
question twice. Then routing gates decide what actually needs a second opinion:

- `skip_high_confidence` (default **true**) — don't re-judge `CONFIDENCE_HIGH`
  findings; they're already trustworthy deterministic hits. Low/medium/unset
  confidence is the "residual" the LLM focuses on.
- `only_rules` — restrict triage to matching rule families (glob or `PREFIX-*`),
  e.g. point the LLM at just the noisy entropy secret rules.
- `skip_rules` — exclude matching rule families (applied after `only_rules`, so
  an exclusion always wins).
- `min_severity` — skip findings below a severity threshold.

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
  "max_findings": 50,          // optional: cap the number judged
  "skip_high_confidence": true, // optional (default true): only judge residual
  "only_rules": ["SECRET-*"],  // optional: restrict to these rule families
  "skip_rules": ["LICENSE-*"]  // optional: exclude these rule families
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
