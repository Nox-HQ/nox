# Plugin Authoring Guide

This guide covers everything you need to build, test, and distribute a Nox plugin.

## Quick Start

```bash
# Scaffold a new plugin
nox plugin init --name nox/my-scanner --track core-analysis

# Build and test
cd nox-plugin-my-scanner
go mod tidy
make build
make test
```

## Architecture Overview

Nox plugins communicate with the host via gRPC using the `PluginService` interface:

```
Host (nox)                    Plugin (subprocess)
    |                              |
    |--- GetManifest(v1) --------->|
    |<-- ManifestResponse ---------|
    |                              |
    |--- InvokeTool(name, input) ->|
    |<-- InvokeToolResponse -------|
    |                              |
    |--- SIGTERM ----------------->|
    |         (5s grace period)    |
```

### Lifecycle

1. **Start**: Host spawns the plugin binary as a subprocess
2. **Handshake**: Plugin prints `NOX_PLUGIN_ADDR=host:port` to stdout, host connects
3. **Manifest**: Host calls `GetManifest` to learn capabilities and safety requirements
4. **Validation**: Host validates manifest against the active safety policy
5. **Invocation**: Host calls `InvokeTool` for each scan operation
6. **Shutdown**: Host sends SIGTERM, waits 5s, then SIGKILL

## SDK Reference

### Manifest Builder

```go
manifest := sdk.NewManifest("nox/my-plugin", "1.0.0").
    Capability("scanning", "Security scanning").
        Tool("scan", "Run security scan", true).       // true = read-only
        Tool("analyze", "Deep analysis", true).
        Resource("findings://{id}", "Finding", "Get finding details", "application/json").
    Done().
    Safety(
        sdk.WithRiskClass(sdk.RiskPassive),
        sdk.WithMaxArtifactBytes(50 * 1024 * 1024),
    ).
    Build()
```

### Plugin Server

```go
srv := sdk.NewPluginServer(manifest).
    HandleTool("scan", handleScan).
    HandleTool("analyze", handleAnalyze)

ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
defer cancel()
srv.Serve(ctx)
```

### Response Builder

```go
func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
    return sdk.NewResponse().
        Finding("RULE-001", sdk.SeverityHigh, sdk.ConfidenceHigh, "SQL injection detected").
            At("app.go", 42, 42).
            Columns(10, 35).
            WithMetadata("cwe", "CWE-89").
            WithFingerprint("sha256:abc123").
        Done().
        Package("express", "4.18.0", "npm").
        AIComponent("gpt-4", "model", "config.yaml").
            Detail("provider", "openai").
            Detail("temperature", "0.7").
        Done().
        Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, "scan completed", "my-plugin").
        Build(), nil
}
```

### Reporting a dataflow

A plugin that reports a source→sink flow under a rule ID core also emits
(`TAINT-*`) must say which flow it found, or the same vulnerability is
reported twice: core anchors a flow at its sink, plugins commonly anchor at
the source, and the two locations and wordings give two fingerprints that no
baseline can suppress together.

Emit three metadata keys and nox will collapse the pair, keeping the sink
anchor:

```go
    .WithMetadata("source_line", "11").  // where the untrusted value entered
    .WithMetadata("source_var", "q").    // the tainted identifier
    .WithMetadata("sink_line", "12").    // where it reached the sink
```

Omit `sink_line` if the finding is already located at the sink. A finding
missing `source_line` or `source_var` is not treated as a flow report and is
never collapsed — including a flow no other analyzer found, which is always
kept.

### Tool Request

```go
type ToolRequest struct {
    ToolName      string
    Input         map[string]any  // Parsed from gRPC Struct
    WorkspaceRoot string          // Absolute path to project root
}
```

## Safety Model

Every plugin declares its safety requirements in the manifest, and may additionally declare them **per tool**. The host validates the plugin-level block at registration, and the specific tool's requirements at invocation.

### Plugin-level vs per-tool safety

The plugin-level `Safety(...)` block is the **ceiling** — everything the plugin might ever need, declared up front so an operator can see it before anything runs. Individual tools may declare narrower requirements with `ToolSafety(...)`:

```go
Capability("red-team", "Attack path analysis").
    // Reasons over findings the core scan already produced: no network,
    // no mutation, nothing to confirm.
    Tool("analyze", "Detect attack chains", true).
    ToolSafety(sdk.WithRiskClass(sdk.RiskPassive)).
    // Probes a live target, so it stays opt-in.
    Tool("validate", "Validate exploitability", false).
    ToolSafety(
        sdk.WithRiskClass(sdk.RiskActive),
        sdk.WithNeedsConfirmation(),
        sdk.WithNetworkHosts("*"),
    ).
    Done().
    Safety(  // the ceiling across both tools
        sdk.WithRiskClass(sdk.RiskActive),
        sdk.WithNeedsConfirmation(),
        sdk.WithNetworkHosts("*"),
    )
```

A tool with no `ToolSafety` inherits the plugin-level block, so plugins written before this existed behave exactly as they did.

**Why it exists.** Safety used to be plugin-scoped only, and validated at registration. A plugin bundling tools with different needs had to declare the union — the strictest requirement of any one tool — and that union then gated *every* tool it shipped. `nox/red-team` could not run its read-only `analyze` under a passive policy purely because it also ships `validate`.

Registration therefore now asks *"is at least one tool usable under this policy?"*, and the binding check happens per invocation.

> **`read_only` does not mean passive.** It means "does not mutate the workspace". A read-only tool may still send data to the network — `nox/llm-triage` declares a read-only tool that ships source code to an external chat endpoint. Declare `ToolSafety` honestly per tool; do not infer passiveness from `readOnly: true`, and do not copy the narrowest block onto a tool that needs more. The host enforces exactly what you declare.

### Risk Classes

| Class | Description | Default Policy |
|-------|-------------|----------------|
| `passive` | Read-only analysis, no side effects | Allowed by default |
| `active` | May modify files or make network requests | Requires explicit opt-in |
| `runtime` | May execute arbitrary code | Requires explicit opt-in |

### Safety Options

```go
sdk.WithRiskClass(sdk.RiskPassive)           // Risk classification
sdk.WithNetworkHosts("*.osv.dev")            // Required network access
sdk.WithNetworkCIDRs("10.0.0.0/8")          // Required CIDR ranges
sdk.WithFilePaths("/tmp/nox-workdir")        // Required file paths
sdk.WithEnvVars("OPENAI_API_KEY")            // Required environment variables
sdk.WithNeedsConfirmation()                  // Requires user confirmation
sdk.WithMaxArtifactBytes(50 * 1024 * 1024)   // Maximum artifact size
```

### Track-Specific Profiles

`plugin.ProfileForTrack(track)` returns a suggested policy per track:

| Track | Risk | Network | Confirmation |
|-------|------|---------|-------------|
| core-analysis | passive | none | no |
| dynamic-runtime | active | localhost | yes |
| ai-security | passive | none | no |
| supply-chain | passive | *.osv.dev, *.github.com | no |
| agent-assistance | passive | LLM APIs | no |

These profiles are **enforced**. The host resolves each plugin's policy as its
track profile merged with the operator's `.nox.yaml` `plugin_policy` block,
where operator settings win. A `dynamic-runtime` plugin therefore gets
localhost access without the operator configuring anything, and a
`core-analysis` plugin does not — even in the same scan, since policy is
per-plugin rather than host-wide.

### Where the track comes from

**The track is read from the registry entry your plugin was published under,
captured at install time — never from your manifest.** The gRPC manifest
carries no track field by design: a self-declared track would let a plugin
choose its own sandbox, which is not a sandbox.

The practical consequences:

- A plugin installed with `--local` has no registry entry, so it has **no
  track** and runs under the strict default policy: `passive` risk class, empty
  allowlists. Declaring `network_hosts` in a sideloaded plugin means rejection
  at registration. Test your plugin as installed from a registry, not only
  sideloaded, or you will not exercise the policy it actually runs under.
- Plugins installed before tracks were recorded also have no track and get the
  strict default until reinstalled.

If your plugin needs more than its track grants, the operator must opt in:

```yaml
# .nox.yaml
plugin_policy:
  max_risk_class: active
  allowed_network_hosts: ["localhost", "127.0.0.1"]
```

Operators who want the pre-track behaviour — every plugin on the strict default
regardless of track — set:

```yaml
plugin_policy:
  ignore_track_profiles: true
```

This exists because the override semantics are one-directional: an operator can
widen an allowlist but cannot empty one, since a zero-length list reads as "not
configured". Without the flag there would be no way to revoke the localhost
access the `dynamic-runtime` profile grants.

## Testing

### Conformance Tests

Every plugin must pass the conformance test suite:

```go
func TestConformance(t *testing.T) {
    manifest := sdk.NewManifest("my-plugin", "0.0.0-test").
        // ... build manifest ...
        Build()

    srv := sdk.NewPluginServer(manifest).
        HandleTool("scan", handleScan)

    // Basic conformance
    sdk.RunConformance(t, srv)

    // Track-specific conformance
    sdk.RunForTrack(t, srv, registry.TrackCoreAnalysis)
}
```

### What Conformance Checks

**Base conformance (all tracks):**
- `GetManifest` returns valid name, version, api_version
- `GetManifest` rejects unsupported API versions
- `InvokeTool` returns NotFound for unknown tools
- All declared tools can be invoked
- Findings have non-empty rule_id and non-UNSPECIFIED severity
- Packages have non-empty names
- AI components have non-empty names

**Track-specific conformance:**
- Risk class matches track expectations
- Read-only tools for passive tracks
- No network declarations for offline tracks
- Manifest is deterministic (two calls return identical results)

## Distribution

### Signing

Plugins are signed with Ed25519 keys. Generate a signing key:

```bash
openssl genpkey -algorithm Ed25519 -out signing-key.pem
```

Store the base64-encoded key as a GitHub secret `NOX_SIGNING_KEY`:

```bash
base64 -w0 signing-key.pem  # Store this as the secret value
```

### Release Workflow

Tag a version to trigger the release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The GitHub Actions workflow will:
1. Build multi-platform binaries (linux/darwin, amd64/arm64)
2. Sign artifacts with Ed25519
3. Create a GitHub Release
4. Dispatch to the registry for index update

### Registry

Users install plugins from the registry:

```bash
nox registry add https://registry.nox-hq.dev/index.json
nox plugin search my-scanner
nox plugin install nox/my-scanner@^1.0.0
```

## Troubleshooting

### Plugin won't start

- Ensure the binary prints `NOX_PLUGIN_ADDR=host:port` to stdout
- Check that the gRPC server is listening on the printed address
- Verify the binary has execute permissions

### Manifest rejected

- Check risk class against the active policy
- Verify network hosts are allowed
- Ensure file paths are within allowed directories

### Tool invocation fails

- Check that tool names match between manifest and handler registration
- Verify the workspace_root is accessible
- Check for context cancellation (timeout)
