# Hardline Extension System

Hardline's plugin architecture enables a rich ecosystem of runtime, environment, and intelligence plugins while preserving Hardline's core guarantees: deterministic, inspectable, safe by default, composable, and agent-aware.

---

## Plugin Architecture

### Core Responsibilities
- Declare capabilities via a manifest
- Accept tool invocations
- Emit findings and artifacts
- Honor host-enforced safety constraints

### Plugin Lifecycle
1. Hardline discovers plugin endpoint
2. Hardline calls `GetManifest`
3. Hardline validates safety requirements
4. Plugin tools/resources become available
5. Results are merged into Hardline outputs

Plugins **never** bypass host policy.

---

## Safety Model (Non-Negotiable)

Because plugins may access networks, environments, or credentials,
Hardline enforces strict safety rules.

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

Plugins communicate with Hardline over gRPC using versioned protobuf definitions.

### Service Contract

```protobuf
// proto/hardline/plugin/v1/plugin.proto

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

Hardline exposes plugin functionality to MCP clients.

### MCP Surface
Hardline provides generic MCP tools:
- `plugin.list`
- `plugin.call_tool`
- `plugin.read_resource`

Additionally, Hardline may expose **convenience aliases**:
- `hardline.dast.scan`
- `hardline.policy.evaluate`

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

Hardline provides a minimal SDK to simplify plugin development.

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

## Plugin Distribution & Marketplace

Hardline supports a **decentralized plugin marketplace** model.

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

Hardline verifies plugins before installation:

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
hardline registry add https://registry.hardline.dev/index.json
hardline registry list
hardline registry remove <name>
```

### Plugin Discovery
```sh
hardline plugin search dast
hardline plugin info hardline/dast
```

### Installation & Updates
```sh
hardline plugin install hardline/dast
hardline plugin update hardline/dast
hardline plugin list --installed
```

### Removal
```sh
hardline plugin remove hardline/dast
```

### Running Plugin Tools
```sh
hardline dast scan https://staging.example.com
hardline plugin call hardline-dast dast.scan --input scan.json
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

The Hardline extension system enables a rich ecosystem of
runtime, environment, and intelligence plugins while preserving
Hardline's core values:

- deterministic
- inspectable
- safe by default
- composable
- agent-aware, not agent-dependent

Extensions expand Hardline's reach — they never weaken its guarantees.
