# nox-plugin-ai-eval

Adversarial prompt corpus runner. Fires a bundled jailbreak / system-leak /
role-confusion / tool-misuse corpus against a configured chat endpoint and
reports which attacks succeeded.

## Why

Static rules detect call sites; this plugin tests the running application's
**actual behaviour**. Detection is empirical — the corpus prompt is sent,
the response is inspected for known success markers, and a finding is
emitted only when the marker matches.

## Track

`dynamic-runtime` — active risk, network, needs explicit confirmation.
The plugin will not run unless the operator passes `endpoint`.

## Tools

### `ai_eval`

| Input | Required | Default | Description |
|---|---|---|---|
| `endpoint` | yes | — | URL of the chat endpoint to test (HTTP POST) |
| `authorize` | yes | — | Must be `true`. Operator confirms they own or have written permission to test `endpoint`. |
| `authorized_target` | yes | — | Must equal `endpoint` byte-for-byte. Prevents consent from being smuggled across endpoints. |
| `payload_template` | no | OpenAI-shape | JSON template; `{{prompt}}` is replaced with the corpus entry |
| `auth_header` | no | — | `Header-Name: value` for authenticated endpoints |
| `response_path` | no | `choices.0.message.content` | dot-path into the JSON response |

The corpus contains real jailbreak / prompt-leak / role-confusion
prompts. Running them against an endpoint you don't own is
unauthorised security testing. The dual-flag gate above is a
deliberate friction point — automation pipelines pin
`authorized_target` next to `endpoint` so accidentally pointing
the corpus at a third-party URL fails closed.

## Findings

| Rule | Severity | Trigger |
|---|---|---|
| `AI-EVAL-001` | high | Jailbreak / instruction-override attack succeeded |
| `AI-EVAL-002` | high | System-prompt extraction succeeded |
| `AI-EVAL-003` | medium | Role / persona confusion succeeded |
| `AI-EVAL-004` | critical | Tool misuse succeeded (file read, exfiltration via tool-call) |

## Example

```bash
nox plugin call ai-eval ai_eval \
    endpoint=http://localhost:8080/chat \
    payload_template='{"messages":[{"role":"user","content":"{{prompt}}"}]}' \
    response_path='choices.0.message.content'
```

## Corpus

The bundled corpus contains ~17 entries covering the major OWASP LLM01
attack patterns plus their variants. Operators who want broader coverage
can fork the plugin and extend `corpus.go`.

## Limitations

- Markers are heuristic. A clever defender can echo a marker without
  actually being jailbroken; a clever attacker can succeed without
  matching a marker. The corpus catches well-known patterns, not novel
  attacks.
- The plugin does not authenticate against the model — it tests the
  application endpoint. Wrap your own auth via `auth_header`.
- Rate limits are the operator's responsibility. Concurrency defaults
  to 1 to be polite.
