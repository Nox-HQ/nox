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

### Tool Request

```go
type ToolRequest struct {
    ToolName      string
    Input         map[string]any  // Parsed from gRPC Struct
    WorkspaceRoot string          // Absolute path to project root
}
```

## Safety Model

Every plugin declares its safety requirements in the manifest. The host validates these against the active policy before allowing registration.

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

Each track has pre-built safety profiles. Use `plugin.ProfileForTrack(track)` to get defaults:

| Track | Risk | Network | Confirmation |
|-------|------|---------|-------------|
| core-analysis | passive | none | no |
| dynamic-runtime | active | localhost | yes |
| ai-security | passive | none | no |
| supply-chain | passive | *.osv.dev, *.github.com | no |
| agent-assistance | passive | LLM APIs | no |

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
