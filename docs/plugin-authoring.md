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

### What `nox scan` actually invokes

Registering is not the same as running. A scan calls exactly two kinds of tool:

| when | which tools |
|---|---|
| analysis phase | the tool named **`scan`**, on every plugin that declares it |
| after the scan | every tool declaring **`requires_scan_context`**, given the findings |

A tool that is neither is **never invoked by a scan**. It is reachable only
through `nox plugin call <plugin> <tool>`, which is a legitimate design for
tools an operator runs deliberately — compliance assessments, exploit
validation — but it means listing such a plugin in `plugins.required` gets you
nothing at scan time.

Two plugins in the published registry are in exactly that position today:
`nox/red-team` (`analyze`, `validate`) and `nox/grc` (`assess`, `gap_report`,
`evidence`). Both work when called explicitly. Since nox 1.34.0 a scan says so:

```
[degraded] required plugin "nox/grc" exposes no tool that nox scan invokes
           (it provides: assess, gap_report, evidence)
```

If you want your plugin to contribute to a scan, name its entry point `scan`,
or set `requires_scan_context` on the tool that reasons over findings.

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
| dynamic-runtime | active | `localhost`, `127.0.0.1`, `::1` | yes |
| ai-security | passive | none | no |
| threat-modeling | passive | none | no |
| supply-chain | passive | `*.osv.dev`, `*.github.com`, `*.npmjs.org`, `*.pypi.org`, `pypi.org`, `proxy.golang.org` | no |
| intelligence | passive | `*.osv.dev`, `*.github.com`, `*.nvd.nist.gov` | no |
| policy-governance | passive | none | no |
| incident-readiness | passive | none | no |
| developer-experience | passive | none | no |
| agent-assistance | passive | `*.openai.com`, `*.anthropic.com`, `*.googleapis.com` | no |

A wildcard matches subdomains only: `*.pypi.org` does not match `pypi.org`,
which is why the apex is listed separately. Generated from
`plugin.ProfileForTrack`; if the two disagree, the code is right and this table
is a bug.

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

`nox plugin init` generates the pipeline every nox plugin releases with:
`.github/workflows/ci.yml`, `.github/workflows/release.yml`,
`.goreleaser.yaml` and `plugin.yaml`. Keep them; the registry verifies what
they produce.

### Before you release: `nox plugin test`

```bash
make build
nox plugin test ./nox-plugin-my-scanner
```

This runs the built binary the way a scan will: registered with a host under
its track's policy (read from `plugin.yaml`, or `--track`), then its `scan`
tool invoked against `--target` (default `.`). It fails on what a scan would
silently degrade — most often a network host the track does not allow, which
otherwise surfaces only after the plugin is published and installed.

It complements the in-process conformance suite above rather than replacing it.

### Signing

There is no key to manage. The release workflow signs `checksums.txt` with
cosign **keyless**, using the workflow's GitHub OIDC identity, and publishes
the bundle as `checksums.txt.sigstore.json`. Anyone can verify a release
against the workflow that built it:

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Earlier versions of this guide described Ed25519 signing with a
`NOX_SIGNING_KEY` secret. That pipeline produced artifacts the registry does
not verify; do not use it.

### Release workflow

```bash
git tag v0.1.0
git push origin v0.1.0
```

The tag runs GoReleaser, which:

1. runs the tests, then builds linux/darwin (amd64, arm64) and windows/amd64
2. archives each binary with `README.md` and `plugin.yaml`
3. writes `checksums.txt` and signs it (see above)
4. generates an SBOM per archive and publishes the GitHub release

### Registry

The official registry is `index.json` in
[`nox-hq/registry`](https://github.com/nox-hq/registry). A plugin's **first**
release needs an entry there written by hand — its description, track and
maintainers, and `minimum_nox_version` if it depends on a policy or SDK change —
because nothing can infer those. From then on the Registry workflow adds each
new release automatically: every morning it opens a PR with the versions the
index is missing, their digests taken from the release's own `checksums.txt`.
Its reconcile step fails, deliberately, while a released plugin has no entry at
all.

nox registers the official registry on first run, so users install directly:

```bash
nox plugin search my-scanner
nox plugin install nox/my-scanner@^1.0.0
```

To add a registry explicitly, for example after opting out of the default with
`NOX_NO_DEFAULT_REGISTRY=1`:

```bash
nox registry add https://raw.githubusercontent.com/nox-hq/registry/main/index.json --name official
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

### The plugin registers but nothing happens during a scan

- Check the tool is named `scan` or declares `requires_scan_context` — see
  [What `nox scan` actually invokes](#what-nox-scan-actually-invokes). Anything
  else is only reachable via `nox plugin call`.
- A read-only tool still inherits the **plugin-level** safety ceiling unless it
  declares its own `ToolSafety(...)`. A passive `plan`-style tool shipped
  alongside an active `apply` one is refused with it under a passive policy,
  which is not what you want: declare the narrower requirements per tool and
  the host will admit the plugin and refuse only the active tool.
- Widen a sandbox with `plugin_policy` in `.nox.yaml`. Overrides are
  one-directional — you can add to an allowlist but not empty one; use
  `ignore_track_profiles: true` to revoke what a track profile grants.
