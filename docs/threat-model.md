# Threat model from scan evidence

`nox model` turns the outputs of a scan you already ran into the raw material of
a threat model: the elements of the system nox can evidence, the data flows and
trust boundaries between them, a STRIDE table with the evidence for each element
and category, the questions the gaps raise, and what nox cannot see. The same
model is available to agents through the read-only MCP tool `threat_model`.

It is the second artifact built from scan evidence after
[`nox compliance iso27001`](compliance-iso27001.md), and it follows the same
rules.

- It reads `findings.json`, `ai.inventory.json` and an SBOM. It never scans,
  never touches the network and never reads a clock.
- It describes evidence. It never says a threat is absent, handled, mitigated or
  that a system is secure. A test pins that no rendered output uses such a word.
- It is deterministic. The same inputs give byte-identical output.
- Every element, flow and STRIDE cell cites the scan output it comes from.

This is not the retired `nox/threat-model` plugin. That plugin guessed threats
from code patterns (it reported `if token == ""` as an authentication bypass)
and measured as noise. This model invents nothing: where nox has no evidence the
cell says so.

## Use

```bash
nox scan . --format json,cdx        # findings.json, sbom.cdx.json, ai.inventory.json
nox model .                         # writes threat-model/model.md and model.json
nox model . --previous last/model.json   # also report what changed
```

Flags: `--out DIR` (default `threat-model`), `--findings`, `--sbom`,
`--ai-inventory`, `--repo`, `--json` (print the model, write nothing),
`--no-write`, `--no-diagram`, `--previous model.json`. Only `findings.json` is
required. A missing SBOM or AI inventory is recorded as a gap in the model, never
treated as an empty one.

## What the model contains

### System elements

Each element has an ID that carries no line number, so a later model can tell a
new element from a moved one.

| Element | Source | What is evidenced |
|---|---|---|
| Entry points (routes) | `findings.json` `routes`, written by the authorization reader (Express-style JavaScript and TypeScript) | method, mounted path, registration `file:line`, and the authentication and authorization middleware visible on the route's chain, by name |
| Authorization leads | `findings.json` `leads` | a route that loads a record by a caller-supplied id with no visible ownership check; also names a route when `routes` was not recorded |
| AI agents | `ai.inventory.json` `tool_permission_matrix` | tools and their capability tags (`shell_exec`, `email_send`, `database_read`, ...); a tool with no recognised capability is named as such |
| MCP servers and client | `ai.inventory.json` components (`.mcp.json` and `mcp.json`) | server name, launch command and arguments (never the `env` block) |
| Models | `ai.inventory.json` `model_provenance` | model, provider, whether pinned, the environment variable the credential is read from |
| Data stores | SBOM packages (PostgreSQL, MySQL, MongoDB, Redis, SQLite, Elasticsearch) and infrastructure findings (public bucket, database instance) | the package or the finding |
| External services | SBOM packages (Stripe, Twilio, SendGrid, SMTP, Slack, AWS, Sentry, Firebase, brokers) and AI SDKs | the package; an AI provider the inventory already names through a model is not listed twice |
| Deployment surface | infrastructure findings (ingress, Kubernetes workloads, container images, public network rules, cloud data stores) | the findings of the rules in `core/threatmodel/tables.go` |
| Dependencies | SBOM | package count; supply-chain findings attach here |

A package in the SBOM shows the application can talk to a store or service, not
that it does: neither CycloneDX output records whether a package is direct or
transitive, and the evidence text says so.

### Data flows and trust boundaries

A flow exists because something in the scan joins its two ends. A boundary
exists because a flow crosses it.

| Boundary | Flow | Evidence |
|---|---|---|
| `request`: untrusted caller → route | an untrusted caller reaches every route | the route registration |
| `exposure`: internet → exposed deployment resource | the internet reaches an ingress, public bucket, public database or open network rule | the finding that says it is reachable |
| `prompt`: untrusted input → LLM prompt | a route reaches the model | the prompt-injection finding (the same definition `nox attack plan` uses, read from its attack graph) |
| `tool-dispatch`: model output → agent tool dispatch | the model reaches the agent registered in the same file | the same finding; nox does not trace the call |
| `tool:<effect>`: model output → shell, filesystem, outbound network, database, ... | an agent reaches the effect its tools' capabilities name | the inventory's tool registration |
| `tool:mcp-server`: model output → MCP server tool | the MCP client reaches each configured server | the configuration |
| `data-access`, `third-party`, `model-call` | the application reaches a store, service or model | the package or model reference |
| `taint:<class>`: untrusted input → shell command, database query, file path, ... | a route (or the untrusted callers) reaches the sink of a taint finding | the taint finding |

`model.md` includes a Mermaid diagram of the flows (`--no-diagram` leaves it
out). Node numbering and edge order follow element and flow IDs, so the diagram
is as reproducible as the rest.

### STRIDE per element

For each element and each of Spoofing, Tampering, Repudiation, Information
disclosure, Denial of service and Elevation of privilege the cell holds one of
four statuses, all of which describe the evidence and none the system:

| Status | Meaning |
|---|---|
| `open_issues` | active findings behind the cell |
| `leads_to_verify` | something worth checking that is not a finding: an authorization lead, or a route with no authentication middleware visible |
| `limited_evidence` | context that describes the element with nothing open (the middleware on a route, the tools an agent holds, an unpinned launch command), or only waived findings |
| `not_evidenced` | **nox has no evidence either way** |

A finding reaches a cell through the weakness (CWE) its rule declares
(`strideByCWE`), with `AUTHZ-001` named by rule. A finding that declares nothing,
or a weakness the mapping does not cover, is listed under the element as a
finding with no STRIDE category and is not forced into a cell. Findings attach to
elements by file; to a route only when they sit below that route's registration
and above the next one; and in a file that holds several infrastructure resources
(one Terraform file with a bucket and a database) only to the resource the rule
names. Anything no element accounts for is counted as unattributed in the
summary, never dropped silently. Waived findings are counted apart: a person
decided to stop looking, which is a decision to cite and not a fix.

### Questions for the team

Derived from gaps, each citing its basis: a tool that exposes `shell_exec` to the
model ("who may trigger it?"), a tool whose capability nox does not recognise, a
route with no authentication middleware visible, an ownership lead, a resource
reachable from outside, an MCP server, a model that is not pinned, a service the
application sends data to. A kind that raises more than twelve questions is cut
with a line saying how many were left out.

### What nox cannot see

Stated in every model. Fixed limits: business logic and intent, runtime
configuration, the identity provider and session handling, network topology
beyond infrastructure findings, frameworks nox does not read (routes and
authorization leads are Express-only; Fastify, NestJS, Next.js, Python, Go and
Java entry points, gRPC, queue consumers and scheduled jobs are not enumerated),
infrastructure no rule reported on, dependency directness, call tracing between
elements, data sensitivity, third-party and MCP server internals. Per-run limits
are added when a scope was not scanned, the scan ran offline or did not complete,
or an input is missing.

## What changed

`--previous model.json` compares against an earlier model and reports elements,
flows and trust boundaries added or removed ("new trust boundary: model output →
shell") and STRIDE cells whose evidence changed, with the evidence that came and
went. Identity is the element ID; a cell is compared on stable evidence keys (rule
and file, or the statement), never on line numbers, so a finding that moved is not
a change.

A comparison that cannot be made says so. If the AI inventory or the SBOM was
given to only one of the two models, or the earlier model recorded no routes (it
may predate route recording), the elements depending on that input are not
compared and a note says why; a different scan scope is noted. Actors and host
capabilities exist only as the ends of flows, so they are reported through the
flow and boundary that brought them.

## Determinism and provenance

The model reads no clock: `scan_generated_at` is the scan's own timestamp, and
nothing here depends on `SOURCE_DATE_EPOCH`. `provenance.artifacts` records the
SHA-256 of every input, by base name. The revision is the repository `HEAD` when
the model was written, and the model says the scan may have run at an earlier
one. `model.json` carries the nox report marker (`meta.tool_name`), so a later
scan of the directory recognises it as nox's own output rather than source.

## What the scan now records for this

Two small scan-side changes make the evidence available:

- `findings.json` has a `routes` key listing every Express route the
  authorization reader read, with the middleware it could see. Routes are
  context, not findings: they reach no gate, exit code, SARIF output or
  fingerprint. The key is absent when no routes were read.
- The AI inventory reads the project-scoped `.mcp.json` as it reads `mcp.json`
  (it was inventoried as one opaque component, with no servers and no tool
  matrix), and records each server's launch command and arguments.
