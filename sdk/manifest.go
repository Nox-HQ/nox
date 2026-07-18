package sdk

import (
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// ManifestBuilder provides a fluent API for constructing GetManifestResponse.
type ManifestBuilder struct {
	resp *pluginv1.GetManifestResponse
}

// NewManifest creates a ManifestBuilder with the given plugin name and version.
// ApiVersion is set to "v1" automatically.
func NewManifest(name, version string) *ManifestBuilder {
	return &ManifestBuilder{
		resp: &pluginv1.GetManifestResponse{
			Name:       name,
			Version:    version,
			ApiVersion: "v1",
		},
	}
}

// Capability begins a new capability with the given name and description.
// Use the returned CapabilityBuilder to add tools and resources, then call
// Done() to return to the ManifestBuilder.
func (b *ManifestBuilder) Capability(name, description string) *CapabilityBuilder {
	c := &pluginv1.Capability{
		Name:        name,
		Description: description,
	}
	return &CapabilityBuilder{parent: b, cap: c}
}

// Safety sets the plugin's safety requirements using functional options.
func (b *ManifestBuilder) Safety(opts ...SafetyOption) *ManifestBuilder {
	sr := &pluginv1.SafetyRequirements{}
	for _, opt := range opts {
		opt(sr)
	}
	b.resp.Safety = sr
	return b
}

// Build returns the fully populated GetManifestResponse.
func (b *ManifestBuilder) Build() *pluginv1.GetManifestResponse {
	return b.resp
}

// CapabilityBuilder provides a fluent API for constructing a single Capability.
type CapabilityBuilder struct {
	parent *ManifestBuilder
	cap    *pluginv1.Capability
}

// Tool adds a tool definition to the capability.
func (cb *CapabilityBuilder) Tool(name, description string, readOnly bool) *CapabilityBuilder {
	cb.cap.Tools = append(cb.cap.Tools, &pluginv1.ToolDef{
		Name:        name,
		Description: description,
		ReadOnly:    readOnly,
	})
	return cb
}

// ToolWithContext adds a tool definition that requires scan context.
// Tools with scan context receive the core scan results (findings, packages,
// AI components) as input, enabling post-scan analysis.
func (cb *CapabilityBuilder) ToolWithContext(name, description string, readOnly bool) *CapabilityBuilder {
	cb.cap.Tools = append(cb.cap.Tools, &pluginv1.ToolDef{
		Name:                name,
		Description:         description,
		ReadOnly:            readOnly,
		RequiresScanContext: true,
	})
	return cb
}

// ToolSafety declares safety requirements for the most recently added tool,
// overriding the plugin-level block for invocations of that tool.
//
// Use this whenever a plugin ships tools with genuinely different needs.
// Without it the plugin-level block must be the union — the strictest
// requirement of any single tool — and that union then gates every tool the
// plugin ships:
//
//	// analyze is read-only and local, yet was unusable under a passive policy
//	// purely because `validate` (same plugin) needs network + confirmation.
//	Tool("analyze", "...", true).
//	    ToolSafety(WithRiskClass(RiskPassive)).
//	Tool("validate", "...", false).
//	    ToolSafety(WithRiskClass(RiskActive), WithNeedsConfirmation(), WithNetworkHosts("*")).
//
// A tool with no ToolSafety inherits the plugin-level block, so plugins written
// before this existed are unaffected.
//
// Declare requirements honestly per tool rather than copying the narrowest one:
// this is what the host enforces at invocation. In particular, do not treat
// `readOnly: true` as implying passive — read-only means "does not mutate the
// workspace", and a read-only tool may still send data to the network.
//
// Panics if called before any Tool/ToolWithContext on this capability: there
// would be nothing to attach to, which is a programming error worth surfacing
// at startup rather than silently dropping the requirements.
func (cb *CapabilityBuilder) ToolSafety(opts ...SafetyOption) *CapabilityBuilder {
	if len(cb.cap.Tools) == 0 {
		panic("sdk: ToolSafety called before any Tool was added to the capability")
	}
	sr := &pluginv1.SafetyRequirements{}
	for _, opt := range opts {
		opt(sr)
	}
	cb.cap.Tools[len(cb.cap.Tools)-1].Safety = sr
	return cb
}

// Resource adds a resource definition to the capability.
func (cb *CapabilityBuilder) Resource(uriTemplate, name, description, mimeType string) *CapabilityBuilder {
	cb.cap.Resources = append(cb.cap.Resources, &pluginv1.ResourceDef{
		UriTemplate: uriTemplate,
		Name:        name,
		Description: description,
		MimeType:    mimeType,
	})
	return cb
}

// Done appends the capability to the manifest and returns the parent ManifestBuilder.
func (cb *CapabilityBuilder) Done() *ManifestBuilder {
	cb.parent.resp.Capabilities = append(cb.parent.resp.Capabilities, cb.cap)
	return cb.parent
}

// SafetyOption is a functional option for configuring SafetyRequirements.
type SafetyOption func(*pluginv1.SafetyRequirements)

// WithNetworkHosts sets the allowed network hosts.
func WithNetworkHosts(hosts ...string) SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.NetworkHosts = hosts
	}
}

// WithNetworkCIDRs sets the allowed network CIDRs.
func WithNetworkCIDRs(cidrs ...string) SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.NetworkCidrs = cidrs
	}
}

// WithFilePaths sets the allowed file paths.
func WithFilePaths(paths ...string) SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.FilePaths = paths
	}
}

// WithEnvVars sets the required environment variables.
func WithEnvVars(vars ...string) SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.EnvVars = vars
	}
}

// WithRiskClass sets the risk classification.
func WithRiskClass(rc string) SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.RiskClass = rc
	}
}

// WithNeedsConfirmation marks the plugin as requiring user confirmation.
func WithNeedsConfirmation() SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.NeedsConfirmation = true
	}
}

// WithMaxArtifactBytes sets the maximum artifact size in bytes.
func WithMaxArtifactBytes(n int64) SafetyOption {
	return func(sr *pluginv1.SafetyRequirements) {
		sr.MaxArtifactBytes = n
	}
}
