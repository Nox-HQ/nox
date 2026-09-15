# What makes an AI configuration setting a security finding?

The AI family had 50 rules. On the pinned seven-repository corpus it produced
780 sites — second only to SEC — and **503 of those (64%) came from twelve rules
that report a model-configuration preference, not a security condition.**

This note settles the question those twelve raise, because it cannot be settled
by measurement: precision work makes a detector match what it claims, and every
one of these twelve already matches exactly what it claims. The problem is what
they claim.

## The decision

> A model-configuration parameter is a security finding only when the configured
> value creates a consequence an attacker can reach. Divergence from a
> recommended value is not a security condition, and a vendor default is not one
> by construction.

The second clause follows from the first. If a vendor's default were a
vulnerability, every application using the SDK as documented would be
vulnerable on its first line, and the finding would carry no information about
the application that received it.

## The evidence that forced it

Three of the twelve refute themselves without leaving the rule table.

**AI-023 and AI-041 assert contradictory requirements of the same parameter.**
AI-023 reports `top_p ≤ 0.69` as a defect — "reducing output diversity". AI-041
reports `top_p > 0.9` as a defect — "increases randomness and reduces
consistency". Between them they assert that `top_p` must lie in a narrow band
or the code has a security finding. OpenAI's documented default is `1.0`, which
AI-041 reports. So the two rules jointly say: use the SDK as documented and you
are vulnerable; tune it away from the default and you may become vulnerable in
the other direction.

**AI-034 reports every legal value of its parameter.** Its pattern is
`(function_call|tool_choice|force_tool)\s*[:=]\s*["']?(any|auto|required)` —
and `any`, `auto` and `required` are the complete set of values the parameter
accepts. `auto` is the default for every major provider. A detector that fires
at every setting of a knob is not measuring the knob. 69 sites across 3
repositories, none of which could have avoided it by configuring anything
differently.

**AI-029's remediation contains the value it reports.** The rule reports
`presence_penalty = 0`; the remediation says "Set presence_penalty (-2 to 0)".
Zero is inside the recommended range. Following the advice exactly reproduces
the finding.

The rest fail the decision on their face: AI-036 (`gpt-3.5` appears anywhere in
the file — 329 sites, the family's largest, and a model-selection question),
AI-050 (retries disabled — an availability and cost choice, filed under
CWE-705 "Incorrect Control Flow Scoping", which is about something else
entirely), AI-048 (response caching disabled, filed under CWE-693 "Protection
Mechanism Failure" — and disabling a shared cache is frequently the
*security-conscious* choice, because a cache shared across tenants leaks),
AI-044 (context window "very high", remediation "typically 2K-8K tokens", advice
that every frontier model released since 2024 has made obsolete), AI-037
(system prompt longer than 2000 characters), AI-028 (no seed set), AI-024 (empty
stop-sequence list), AI-022 (temperature ≥ 0.8).

## What was removed, and what survives

Removed: **AI-022, AI-023, AI-024, AI-028, AI-029, AI-034, AI-036, AI-037,
AI-041, AI-044, AI-048, AI-050.**

Removed rather than retired. `Retires` exists so a surviving rule can reproduce
a retired one's fingerprint and keep baselines, VEX statements and `nox:ignore`
comments resolving. That mechanism needs a successor that reports the same
condition. These have no successor: the condition they reported is not one nox
should report, so there is nothing to absorb them into. The precedent is MCP-008
(see `core/analyzers/ai/mcp_registration_test.go`).

Four neighbouring rules look similar and are kept, because each names a
consequence rather than a preference:

| Rule | Why it survives |
|---|---|
| AI-017 | `max_tokens = -1` or ≥ 100000 is unbounded generation cost an attacker can drive. CWE-770 is the right CWE and the value is not a default. |
| AI-035 | `max_iterations = 0/-1/None` removes the bound on an agent loop. Same shape: attacker-reachable, not a default. |
| AI-033 | Content filtering explicitly set to `false`/`None` is a safety boundary switched off, not a parameter tuned. |
| AI-046 | Input sanitisation explicitly disabled is the guard against prompt injection switched off. |

The distinction in every row is the same one: these report a protection
**removed**, not a value **chosen**.

## Consequence for open work

PR #657 narrows AI-022 so it stops reporting `temperature: 1.0` on o1/o3
reasoning models, where 1.0 is the documented default. That fix is correct
about its case and is superseded here: the general form of its argument — a
documented default is not a finding — removes the rule it was fixing.

## What this does not decide

AI-019 ("model loaded without hash verification") is a real supply-chain
proposition expressed badly: its pattern matches every `from_pretrained(` call
and its own comment concedes that a pinned call matches too. It is a *fix*, not
a removal, and is handled separately.
