# Nox Extension System

Nox's plugin architecture enables a rich ecosystem of runtime, environment, and intelligence plugins while preserving Nox's core guarantees: deterministic, inspectable, safe by default, composable, and agent-aware.

---

## Plugin Architecture

### Core Responsibilities
- Declare capabilities via a manifest
- Accept tool invocations
- Emit findings and artifacts
- Honor host-enforced safety constraints

### Plugin Lifecycle
1. Nox discovers plugin endpoint
2. Nox calls `GetManifest`
3. Nox validates safety requirements
4. Plugin tools/resources become available
5. Results are merged into Nox outputs

Plugins **never** bypass host policy.

---

## Safety Model (Non-Negotiable)

Because plugins may access networks, environments, or credentials,
Nox enforces strict safety rules.

### Host-Enforced Constraints
- Scope allowlists (hosts, CIDRs, paths)
- Rate limits and concurrency caps
- Default read-only execution
- Artifact size limits
- Secret redaction
- Explicit opt-in for destructive actions

### Plugin-Declared Requirements
Plugins must declare:
- Required scopes
- Default limits
- Risk classification (e.g. `runtime`, `network`, `active`)
- Whether human confirmation is recommended

If a plugin violates declared safety guarantees, it is disabled.

---

## gRPC Interface

Plugins communicate with Nox over gRPC using versioned protobuf definitions.

### Service Contract

```protobuf
// proto/nox/plugin/v1/plugin.proto

service PluginService {
  rpc GetManifest(GetManifestRequest) returns (PluginManifest);
  rpc InvokeTool(InvokeToolRequest) returns (InvokeToolResponse);
  rpc StreamArtifacts(StreamArtifactsRequest) returns (stream Artifact);
}

message PluginManifest {
  string name = 1;
  string version = 2;
  string api_version = 3;
  repeated Capability capabilities = 4;
  SafetyRequirements safety = 5;
}

message Capability {
  string name = 1;           // e.g. "dast.scan", "cloud.audit"
  string description = 2;
  repeated ToolDef tools = 3;
  repeated ResourceDef resources = 4;
}

message SafetyRequirements {
  repeated string network_hosts = 1;
  repeated string network_cidrs = 2;
  repeated string file_paths = 3;
  repeated string env_vars = 4;
  string risk_class = 5;     // "passive", "active", "runtime"
  bool needs_confirmation = 6;
}
```

### Plugin Manifest
Plugins declare:
- **Capabilities**: analyzers, reporters, tools they provide
- **Safety requirements**: network hosts, file paths, environment variables needed
- **API version compatibility**: ensures host-plugin contract match

All message types are versioned and backwards-compatible.

---

## MCP Integration

Nox exposes plugin functionality to MCP clients.

### MCP Surface
Nox provides generic MCP tools:
- `plugin.list`
- `plugin.call_tool`

Additionally, Nox may expose **convenience aliases**:
- `nox.dast.scan`
- `nox.policy.evaluate`

These are thin wrappers around plugin tools.

### MCP Resources
Plugin artifacts are exposed as MCP resources:

```
dast://runs/<id>/results.sarif
dast://runs/<id>/findings.json
```

This allows agents and tools to consume large artifacts safely.

---

## Agent Integration (Optional)

Plugins may advertise **capabilities** that agent runtimes can reason about.

Examples:
- `dast.passive`
- `dast.openapi_discovery`
- `cloud.read_only`
- `policy.enforcement`

Agent runtimes (e.g. agent-go) may:
- discover available capabilities
- prompt users for required inputs
- call tools
- summarize results

Agents **never** influence scan results or core logic.

---

## Plugin SDK

Nox provides a minimal SDK to simplify plugin development.

### SDK Includes
- Versioned protobuf definitions
- gRPC server scaffolding
- Manifest and capability helpers
- Safety envelope parsing
- Artifact helpers
- Conformance test runner

### SDK Excludes
- Scan engines
- Logging frameworks
- Workflow engines
- Agent logic

The SDK is intentionally small and stable.

---

### Findings must identify a place in the repository, not on the machine

Report **repo-relative paths** and derive fingerprints from them. A fingerprint
that folds in the absolute path moves with the checkout directory, and because
a baseline matches on fingerprint, every finding the plugin produces reappears
as net-new anywhere the path differs — every CI runner, every `git worktree`
pre-push gate, any two developers.

The failure is invisible where people look. Locally the baseline matches and the
scan is green; the gate elsewhere reports hundreds of net-new findings for the
same commit, with nothing in the output attributing the difference to the path.
It reads as a stale baseline and invites a blanket `nox baseline update`, which
accepts those findings unreviewed into a baseline that will not match on the
next run either. This was nox issue #454.

The SDK provides both halves:

```go
fp := sdk.Fingerprint(workspaceRoot, absPath, "SAST-001", matchedSymbol)
loc := &pluginv1.Location{FilePath: sdk.RelativePath(workspaceRoot, absPath)}
```

`sdk.Fingerprint` deliberately omits the line number: a finding that shifts when
an import is added is still the same finding, and including the line expires the
baseline entry on the next unrelated edit. Pass one explicitly if your plugin
genuinely needs line-level identity.

Prove it in your conformance test, which seeds identical content into two
differently-named directories and compares:

```go
func TestConformance(t *testing.T) {
    sdk.RunConformance(t, srv)
    sdk.RunFingerprintStability(t, srv, writeFixture)
}
```

The host also normalises plugin-reported paths against the workspace root before
computing the fingerprint it stores, so a plugin that gets this wrong is not
catastrophic — but the host cannot repair a *claimed* fingerprint, which is
opaque to it. Only the plugin can make that stable.

## Plugin Distribution & Marketplace

Nox supports a **decentralized plugin marketplace** model.

### Registry Concept
A registry is a static index containing:
- plugin metadata
- versions
- artifact locations
- signatures
- capability declarations

Registries may be:
- official
- community-run
- enterprise-internal

### Distribution Format
Plugins are distributed as **OCI artifacts**:
- immutable
- content-addressed
- cacheable
- mirrorable

Artifacts contain:
- platform-specific plugin binaries
- plugin manifest
- optional documentation

---

## Trust & Verification

Nox verifies plugins before installation:

- Signature validation (publisher identity)
- Artifact digest verification
- API compatibility check
- Conformance tests

### Trust Levels
- **Verified** (default allow)
- **Community** (explicit user trust required)
- **Unverified** (default deny)

Trust roots are configurable.

---

## CLI UX

### Registry Management
```sh
nox registry add https://registry.nox-hq.dev/index.json
nox registry list
nox registry remove <name>
```

### Plugin Discovery
```sh
nox plugin search dast
nox plugin info nox/dast
```

### Installation & Updates
```sh
nox plugin install nox/dast
nox plugin update nox/dast
nox plugin list --installed
```

### Removal
```sh
nox plugin remove nox/dast
```

### Running Plugin Tools
```sh
nox dast scan https://staging.example.com
nox plugin call nox-dast dast.scan --input scan.json
```

---

## Examples of Plugins

- Web DAST (HTTP/TLS/API)
- AI Runtime Security
- Cloud Configuration Scanner
- Kubernetes Runtime Scanner
- Supply Chain Provenance Checker
- Policy Gate / CI Enforcement
- Threat Intelligence Enrichment
- Agent-Only Triage & Explanation

---

## Explicit Non-Goals

The extension system will not:

- Auto-execute untrusted code
- Allow plugins to bypass host policy
- Require a hosted service
- Enable silent destructive actions
- Replace human authorization

---

## Summary

The Nox extension system enables a rich ecosystem of
runtime, environment, and intelligence plugins while preserving
Nox's core values:

- deterministic
- inspectable
- safe by default
- composable
- agent-aware, not agent-dependent

Extensions expand Nox's reach — they never weaken its guarantees.
