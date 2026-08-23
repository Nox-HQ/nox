# `nox attack` — dynamic exploit validation

`nox scan` tells you what is dangerous. `nox attack` tells you whether an
attacker can actually do it.

Static analysis can see that untrusted data reaches a model, that an agent holds
both `read_file` and `send_http`, that a tool is exposed without authorization.
What it cannot see is whether those facts compose into a working attack — whether
the model can be pushed hard enough, whether the agent will actually call the
sensitive tool, whether a guardrail stops it. So static findings carry false
positives, and the security team pays for them in manual triage.

`nox attack` closes that gap:

```text
Discover → Analyze → Hypothesize → Attack → Verify → Reproduce → Regress
```

It reuses what the scan already learned — agents, tools, MCP servers, trust
boundaries, sensitive assets, data flows, findings — to build **exploit
hypotheses grounded in your application**, then tries to demonstrate them against
a target you point it at, and reports what it could and could not establish.

## This is an ACTIVE capability (read this first)

`nox scan` is read-only and offline-first. `nox attack run`, `replay`, and
`regress` are the opposite track:

- **They execute network probes.** They send *attack payloads* to your target.
- **They are opt-in.** Never part of `nox scan`, never automatic, and they refuse
  to run without `--authorize` for any profile other than `safe`.
- **nox does NOT run or sandbox your target.** You point it at a system you own
  and have isolated. Egress control, resource limits, a disposable environment —
  yours to provide.

`nox attack plan` is the exception: it is offline and read-only, and sends
nothing.

Only run this against systems you are authorized to test.

## Usage

```bash
# 1. Scan produces findings.json + ai.inventory.json (static, offline)
nox scan ./my-app --output .

# 2. Build exploit hypotheses from what the scan learned (offline)
nox attack plan .

# 3. Simulate — see what would be attempted, send nothing
nox attack run --profile safe

# 4. Execute against a running, isolated target
nox attack run \
  --target http://127.0.0.1:8000 \
  --route /chat --fields persona,message \
  --profile sandbox --authorize

# 5. Reproduce one confirmed exploit
nox attack replay TRACE-... --target http://127.0.0.1:8000 --authorize

# 6. Turn confirmed exploits into permanent regression tests
nox attack regress --record
nox attack regress --target http://127.0.0.1:8000 --authorize
```

Artifacts: `attack.plan.json`, `attack.trace.json`, `attack.cases.json`,
`attack.regress.json`. All are plain JSON, diffable, and reviewable in a PR.

Exit codes: `run` and `replay` return `1` when something is CONFIRMED. `regress`
returns `1` on a regression and `2` when no case could be exercised at all —
a suite whose probes never reached the target has proven nothing, and returning
`0` for it would turn a misconfigured endpoint into a green build.

## The finding lifecycle

Exploitability is tracked **independently of severity**. A CRITICAL finding can
be PREVENTED; a MEDIUM one can be CONFIRMED.

| state | meaning |
|---|---|
| `POTENTIAL` | static evidence only; no attack path constructed |
| `PLAUSIBLE` | a credible attack path exists; nothing was executed |
| `PREVENTED` | executed, and a defense was observed stopping it |
| `INCONCLUSIVE` | executed, but the evidence was insufficient to decide |
| `CONFIRMED` | a security invariant was observed being violated, and it reproduced |

These transitions live in `core/evidence`, deliberately outside this package, so
that "CONFIRMED" means exactly one thing wherever nox produces an
evidence-backed verdict — including a future intelligence service, which is not
part of the CLI (see [ADR 0002](adr/0002-intelligence-layer-is-a-separate-service.md)).

## What it takes to reach CONFIRMED

Four conditions, all required:

1. An oracle observed the **security invariant** being violated — not that the
   model said something odd, but that a boundary was crossed.
2. The **benign control** did not trip. Every scenario carries a control payload
   that must never produce a signal; if it does, the environment cannot tell
   obedience from noise and nothing is confirmed.
3. The violation **reproduced** under the determinism gate (k-of-n).
4. The evidence is **deterministic**. A model's opinion that an attack "probably
   worked" is recorded, labelled, and explicitly cannot confirm anything.

Anything short of all four lands on INCONCLUSIVE, never on PREVENTED, and never
on "clean".

## Reflection immunity

The worst failure this tool can have is a false confirmation, so success is never
scored on a string the payload itself carried. Every canary is minted such that
its value **cannot appear in any payload nox sends** — an app that merely echoes
your input can never be mistaken for one that obeyed it. The invariant is
asserted before a single probe leaves the process; if it fails, nox fails closed.

This is the same property `nox confirm` established, generalised to the whole
scenario library.

## Canaries and planting

Detection depends on a canary the attacker never supplied. For prompt-injection
scenarios nox mints those from the seed and the target's own trusted context, so
nothing needs planting.

Exfiltration is different: `EXFIL-FS-NET` asks the target to read a secret file
and send it somewhere, and there is nothing to steal unless a secret exists.
That file is the one thing nox writes into the environment under test, so it is
opt-in:

```bash
nox attack run --plant-dir ./sandbox-data --profile staging --authorize ...
```

nox writes one obviously-fake secrets file into that directory and removes it
when the run ends. It **will not** create the directory, **will not** overwrite
an existing file, and **will not** plant under `--profile safe` (which sends
nothing, so the write would be pointless). The planted file identifies itself as
a nox canary in its own contents, so an operator who finds a stray copy can tell
it from a real leaked credential.

Without `--plant-dir`, the exfiltration scenario has nothing to exfiltrate and
**cannot** be confirmed. nox says so explicitly before the run rather than
returning a bare `INCONCLUSIVE` — an inconclusive verdict with no stated cause
reads like a target that was tested and found clean, which is precisely the
false all-clear this tool exists to avoid.

## Safety profiles

| profile | network | authorization | intended for |
|---|---|---|---|
| `safe` | none — the target adapter cannot reach the network | not required | simulation; seeing what *would* be attempted |
| `sandbox` | yes | `--authorize` | a disposable instance you control |
| `staging` | yes | `--authorize` | a non-production environment |
| `authorized-live` | yes | `--authorize` | only with explicit, documented authorization |

`safe` is enforced by wiring, not by a promise: the profile selects a target
adapter with no network capability at all.

## Budgets

Every run is bounded — attempts, network requests, model calls, tool invocations,
wall clock. When a budget trips, the run stops and says which one. Traces cut
short by a budget are marked INCONCLUSIVE and can never be reported as
PREVENTED: a run that was interrupted did not demonstrate a defense.

## Scenario library (V1)

| id | category |
|---|---|
| `PI-DIRECT` | direct prompt injection |
| `PI-INDIRECT` | indirect prompt injection (via a retrieved document or tool output) |
| `TOOL-UNAUTH` | unauthorized tool invocation |
| `EXFIL-FS-NET` | filesystem-to-network exfiltration |

Each scenario declares its objective, preconditions, techniques, safety
constraints, the invariants it tests, and the minimum profile it may run under.

## Regression

A confirmed exploit is only half the value; the other half is knowing it stays
fixed. `nox attack regress --record` turns confirmed traces into a case suite,
and `nox attack regress` re-runs it. Because model behaviour is not
deterministic, cases pass a **k-of-n threshold** rather than an exact match —
nox does not pretend a language model is a pure function.

Each case records the route and field its exploit was found in, so a suite
replays with no flags. Supplying `--route` overrides that, for when a fix moved
the endpoint.

Each case reports **two** things, because they answer different questions and
conflating them makes one of them wrong:

| field | question | values |
|---|---|---|
| `outcome` | did the recorded exploit reproduce? | `HELD` / `REGRESSED` / `UNEXERCISED` |
| `exploitability` | what has been demonstrated about the target? | `CONFIRMED` / `PREVENTED` / `INCONCLUSIVE` |

CI gates on `outcome`. A case that `HELD` is a passing test — and it is
`PREVENTED` only when the target was observed actively refusing; otherwise the
claim is `INCONCLUSIVE`, because nothing was demonstrated.

This is the same distinction nox already makes in VEX, where `not_affected`
requires a justification and `under_investigation` is the honest fallback. A
passing test is not a security claim.

## Honest limits

- **Failure to exploit is not proof of safety.** nox reports "not exploited under
  the strategies tested"; it never reports "safe". A stronger attacker, a
  different corpus, or a different day may succeed where this run did not.
- **The corpus is bounded.** Four scenario families with a handful of payload
  strategies each. A production red-team corpus is far larger; the point here is
  target-aware validation, not payload volume.
- **HTTP targets only, in V1.** MCP clients and servers, CLI agents, and
  framework adapters are the same shape with a different transport, and are
  future work.
- **nox does not sandbox your target.** Isolation is the operator's job.
- **Non-determinism is real.** Set `temperature=0` or a seed where the target
  supports it, and use `--min-hits` below `--samples` so a transient refusal does
  not hide a real exploit.

## MCP exposure

Only the offline half is reachable over MCP:

| tool | exposed | why |
|---|---|---|
| `attack_plan` | yes, read-only | reasons over scan artifacts, contacts nothing |
| `attack run` / `replay` / `regress` | **no** | fires attack payloads at a network target |

`--authorize` exists so a **human** affirms they own and have isolated the
target. Accepting that as a boolean on a model-initiated tool call launders the
affirmation through the very thing it constrains.

There is a second reason, and it is the sharper one: nox scans untrusted code. A
repository under analysis is attacker-controlled text, and an agent reading it
can be steered into calling tools with attacker-chosen arguments. An
MCP-exposed `attack_run` would turn nox into a request-forgery primitive aimed
at any host named in a README — the confused-deputy attack that `TOOL-UNAUTH`
exists to detect. Shipping it would make nox an instance of the vulnerability
class it tests for.

The rule is **plan and read over MCP; act from the CLI**, where the operator is
the one typing. It matches `fix_plan`, which returns a plan and tells operators
to apply it with `nox fix`, and `nox confirm`, which has never been an MCP tool.

## Relationship to `nox confirm`

`nox confirm` remains as-is: a focused, well-tested loop for AI prompt-injection
findings against a Flask-shaped HTTP target. `nox attack` is its generalisation —
a scenario model, an asset and invariant model, budgets, profiles, replay, and
regression. Both share the reflection-immunity property that makes their verdicts
worth reading.
