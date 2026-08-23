package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nox-hq/nox/core"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

// Host is the aggregate root for plugin management. All plugin interactions
// flow through Host, which enforces safety policies, routes tool invocations,
// and merges results back into the core domain model.
type Host struct {
	policy      Policy
	plugins     map[string]*Plugin // name → plugin
	toolIndex   map[string]*Plugin // "pluginName.toolName" → plugin
	diagnostics []Diagnostic
	violations  []RuntimeViolation
	redactor    *Redactor
	telemetry   *telemetryCollector
	mu          sync.RWMutex
	logger      *slog.Logger

	// overrides holds the operator's explicit .nox.yaml settings, kept
	// separately from policy so they can be merged onto a track profile.
	// policy remains the effective policy for plugins with no known track,
	// and governs host-global concerns (concurrency, the InvokeAll deadline).
	overrides           Policy
	ignoreTrackProfiles bool
}

// WithPolicyOverrides supplies the operator's explicit .nox.yaml settings so
// they can be merged onto each plugin's track profile.
//
// Without this the host has only a fully-resolved policy, in which every
// DefaultPolicy-derived value is indistinguishable from a deliberate operator
// choice — merging a track profile through it would be a no-op.
func WithPolicyOverrides(o *Policy) HostOption {
	return func(h *Host) { h.overrides = *o }
}

// WithIgnoreTrackProfiles forces every plugin onto DefaultPolicy() regardless
// of track. See PolicyConfig.IgnoreTrackProfiles.
func WithIgnoreTrackProfiles(ignore bool) HostOption {
	return func(h *Host) { h.ignoreTrackProfiles = ignore }
}

// policyForTrack resolves the effective policy for a plugin of the given
// track. An empty or unrecognised track yields the host's default policy,
// which is the strict one — see EffectivePolicy for why that matters.
func (h *Host) policyForTrack(track registry.Track) Policy {
	if track == "" || h.ignoreTrackProfiles {
		return h.policy
	}
	return EffectivePolicy(track, &h.overrides, h.ignoreTrackProfiles)
}

// HostOption is a functional option for configuring a Host.
type HostOption func(*Host)

// WithPolicy sets the safety policy for the host.
func WithPolicy(p *Policy) HostOption {
	return func(h *Host) { h.policy = *p }
}

// WithLogger sets the logger for the host.
func WithLogger(l *slog.Logger) HostOption {
	return func(h *Host) { h.logger = l }
}

// NewHost creates a Host with the given options.
// Defaults: DefaultPolicy(), slog.Default(), NewRedactor().
func NewHost(opts ...HostOption) *Host {
	h := &Host{
		policy:    DefaultPolicy(),
		plugins:   make(map[string]*Plugin),
		toolIndex: make(map[string]*Plugin),
		redactor:  NewRedactor(),
		telemetry: newTelemetryCollector(),
		logger:    slog.Default(),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RegisterPlugin creates a Plugin from an existing gRPC connection,
// performs the handshake, validates the manifest against the host policy,
// and registers it. Returns an error if handshake fails or policy is violated.
func (h *Host) RegisterPlugin(ctx context.Context, conn *grpc.ClientConn) error {
	p := NewPlugin(conn)

	if err := p.Handshake(ctx, HostAPIVersion); err != nil {
		_ = p.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	info := p.Info()
	violations := ValidateManifest(&pluginv1.GetManifestResponse{
		Name:         info.Name,
		Version:      info.Version,
		ApiVersion:   info.APIVersion,
		Capabilities: infoToProtoCapabilities(&info),
		Safety:       info.Safety,
	}, &h.policy)

	if len(violations) > 0 {
		_ = p.Close()
		msgs := make([]string, len(violations))
		for i, v := range violations {
			msgs[i] = v.Error()
		}
		return fmt.Errorf("plugin %q rejected: %s", info.Name, strings.Join(msgs, "; "))
	}

	p.setPolicy(h.policy)
	p.rateLimiter = NewRateLimiter(h.policy.RequestsPerMinute, h.policy.BandwidthBytesPerMin)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.plugins[info.Name] = p
	h.buildToolIndex()
	h.logger.Info("registered plugin", "name", info.Name, "version", info.Version)

	return nil
}

// RegisterBinary spawns a plugin binary subprocess and registers it under the
// host's default policy. Use RegisterBinaryWithTrack when the plugin's registry
// track is known, so its track profile applies.
func (h *Host) RegisterBinary(ctx context.Context, path string, args []string) error {
	return h.RegisterBinaryWithTrack(ctx, path, args, "")
}

// RegisterBinaryWithTrack spawns a plugin binary and registers it under the
// policy for the given registry track, merged with the operator's overrides.
//
// SECURITY: track must come from the registry entry the plugin was installed
// from. It is not, and must not be, anything the plugin asserts about itself —
// see EffectivePolicy. Pass an empty track whenever provenance is uncertain
// (sideloaded binaries, installs predating track recording); that selects the
// strict default policy.
func (h *Host) RegisterBinaryWithTrack(ctx context.Context, path string, args []string, track registry.Track) error {
	policy := h.policyForTrack(track)

	timeout := policy.ToolInvocationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	p, err := StartBinary(ctx, path, args, timeout)
	if err != nil {
		return fmt.Errorf("starting plugin binary: %w", err)
	}

	if err := p.Handshake(ctx, HostAPIVersion); err != nil {
		_ = p.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	info := p.Info()
	violations := ValidateManifest(&pluginv1.GetManifestResponse{
		Name:         info.Name,
		Version:      info.Version,
		ApiVersion:   info.APIVersion,
		Capabilities: infoToProtoCapabilities(&info),
		Safety:       info.Safety,
	}, &policy)

	if len(violations) > 0 {
		_ = p.Close()
		msgs := make([]string, len(violations))
		for i, v := range violations {
			msgs[i] = v.Error()
		}
		return fmt.Errorf("plugin %q rejected: %s", info.Name, strings.Join(msgs, "; "))
	}

	p.setPolicy(policy)
	p.rateLimiter = NewRateLimiter(policy.RequestsPerMinute, policy.BandwidthBytesPerMin)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.plugins[info.Name] = p
	h.buildToolIndex()
	h.logger.Info("registered plugin binary",
		"name", info.Name, "path", path, "track", string(track), "max_risk_class", string(policy.MaxRiskClass))

	return nil
}

// Plugins returns info for all registered plugins.
func (h *Host) Plugins() []Info {
	h.mu.RLock()
	defer h.mu.RUnlock()

	infos := make([]Info, 0, len(h.plugins))
	for _, p := range h.plugins {
		infos = append(infos, p.Info())
	}
	return infos
}

// authorizeTool applies every pre-invocation control to a single tool call:
// per-tool safety requirements, the read-only gate, and the request rate limit.
//
// It exists because these checks were duplicated into one invocation path and
// absent from the other. InvokePostScan called the gRPC client directly, so a
// post-scan tool ran with no policy applied at all — including a non-read-only
// tool under a passive policy, which is how nox's "never auto-applies fixes"
// guarantee came to be bypassable. Any new invocation path must go through
// here.
//
// A returned error is a RuntimeViolation and the plugin has already been shut
// down by handleViolationLocked.
func (h *Host) authorizeTool(ctx context.Context, p *Plugin, toolName string) error {
	return h.authorize(ctx, p, toolName, true)
}

// authorizeToolWithoutTermination applies the same controls but leaves the
// plugin running when it refuses.
//
// Termination is the right response to a tool the CALLER asked for: the plugin
// tried to do something its policy forbids. It is the wrong response when the
// HOST chose the tool — InvokePostScan enumerates every requires_scan_context
// tool itself, so terminating on refusal punishes a well-behaved plugin and
// takes its read-only siblings down with it (they then fail "not ready").
// A plugin shipping a passive plan_code alongside an active apply_code would
// lose plan_code entirely, which is the shape the SDK docs recommend.
func (h *Host) authorizeToolWithoutTermination(ctx context.Context, p *Plugin, toolName string) error {
	return h.authorize(ctx, p, toolName, false)
}

func (h *Host) authorize(ctx context.Context, p *Plugin, toolName string, terminate bool) error {
	pluginName := p.Info().Name

	// refuse records the violation and, for caller-initiated invocations,
	// shuts the plugin down.
	refuse := func(v RuntimeViolation) error {
		h.mu.Lock()
		if terminate {
			h.handleViolationLocked(v, p)
		} else {
			h.violations = append(h.violations, v)
		}
		h.mu.Unlock()
		return v
	}

	// Enforcement reads the plugin's OWN effective policy, not the host's:
	// plugins of different tracks run under different policies in the same
	// host, so a dynamic-runtime plugin's grants must not leak to a
	// core-analysis one sharing the process.
	policy := p.Policy()

	// Per-tool safety enforcement.
	//
	// Registration only establishes that SOMETHING in this plugin is runnable
	// (see ValidateManifest); the binding check is here, against the tool
	// actually being called. A tool declaring its own safety is judged on that;
	// one that does not inherits the plugin-level block, which is how every
	// plugin behaved before ToolDef.safety existed.
	if ti := p.getToolInfo(toolName); ti != nil && ti.Safety != nil {
		if violations := validateSafety(ti.Safety, &policy); len(violations) > 0 {
			msgs := make([]string, 0, len(violations))
			for _, pv := range violations {
				msgs = append(msgs, pv.Error())
			}
			v := RuntimeViolation{
				Type:       ViolationUnauthorizedAction,
				PluginName: pluginName,
				Message: fmt.Sprintf(
					"tool %q requirements not allowed by policy: %s",
					toolName, strings.Join(msgs, "; "),
				),
				Timestamp: time.Now(),
			}
			return refuse(v)
		}
	}

	// Read-only enforcement: reject non-read-only tools under passive policy.
	//
	// Deliberately a SEPARATE, independent check. `read_only` means "does not
	// mutate the workspace" — not "passive": nox/llm-triage declares a read_only
	// tool that ships source code to an external chat endpoint. Neither property
	// implies the other, so a tool must satisfy both.
	if policy.MaxRiskClass == RiskClassPassive {
		if ti := p.getToolInfo(toolName); ti != nil && !ti.ReadOnly {
			v := RuntimeViolation{
				Type:       ViolationUnauthorizedAction,
				PluginName: pluginName,
				Message:    fmt.Sprintf("tool %q is not read-only but policy is passive", toolName),
				Timestamp:  time.Now(),
			}
			return refuse(v)
		}
	}

	// Rate limit check.
	if p.rateLimiter != nil {
		if err := p.rateLimiter.AllowRequest(ctx); err != nil {
			v := RuntimeViolation{
				Type:       ViolationRateLimit,
				PluginName: pluginName,
				Message:    fmt.Sprintf("request rate limit exceeded: %v", err),
				Timestamp:  time.Now(),
			}
			return refuse(v)
		}
	}

	return nil
}

// invokePostScanTool sends one post-scan request under the plugin's own
// invocation timeout. It is a separate function so the timeout's cancel is
// scoped to a single call rather than deferred until the whole loop finishes.
func (h *Host) invokePostScanTool(ctx context.Context, p *Plugin, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
	if timeout := p.Policy().ToolInvocationTimeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return p.invokeRequest(ctx, req)
}

// processResponse applies the post-invocation controls: the bandwidth limit and
// secret redaction. Like authorizeTool, it is shared so no invocation path can
// deliver a plugin's output unredacted.
func (h *Host) processResponse(ctx context.Context, p *Plugin, resp *pluginv1.InvokeToolResponse) (*pluginv1.InvokeToolResponse, error) {
	pluginName := p.Info().Name

	if p.rateLimiter != nil {
		size := estimateResponseSize(resp)
		if err := p.rateLimiter.AllowBandwidth(ctx, size); err != nil {
			v := RuntimeViolation{
				Type:       ViolationBandwidth,
				PluginName: pluginName,
				Message:    fmt.Sprintf("bandwidth limit exceeded (%d bytes): %v", size, err),
				Timestamp:  time.Now(),
			}
			h.mu.Lock()
			h.handleViolationLocked(v, p)
			h.mu.Unlock()
			return nil, v
		}
	}

	// Secret redaction. Redaction is a warning, not a termination event.
	resp, redacted := h.redactor.RedactResponse(resp)
	if redacted {
		v := RuntimeViolation{
			Type:       ViolationSecretLeaked,
			PluginName: pluginName,
			Message:    "plugin output contained secrets (redacted before delivery)",
			Timestamp:  time.Now(),
		}
		h.mu.Lock()
		h.violations = append(h.violations, v)
		h.diagnostics = append(h.diagnostics, Diagnostic{
			Severity: "warning",
			Message:  v.Error(),
			Source:   pluginName,
		})
		h.mu.Unlock()
		h.logger.Warn("secret redacted from plugin output", "plugin", pluginName)
	}

	h.mu.Lock()
	h.collectDiagnostics(pluginName, resp)
	h.mu.Unlock()

	return resp, nil
}

// InvokeTool routes a tool invocation to the appropriate plugin.
// Supports qualified "pluginName.toolName" and unqualified "toolName" (first match).
// Enforces read-only policy, rate limits, bandwidth limits, and secret redaction.
func (h *Host) InvokeTool(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) (*pluginv1.InvokeToolResponse, error) {
	p, resolvedName, err := h.resolveToolPlugin(toolName)
	if err != nil {
		return nil, err
	}

	pluginName := p.Info().Name

	if err := h.authorizeTool(ctx, p, resolvedName); err != nil {
		return nil, err
	}

	timeout := p.Policy().ToolInvocationTimeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	invokeStart := time.Now()
	resp, err := p.InvokeTool(ctx, resolvedName, input, workspaceRoot)
	invokeDuration := time.Since(invokeStart)
	if err != nil {
		h.telemetry.Record(pluginName, invokeDuration, 0, 0, 0, 0, true)
		return nil, err
	}

	resp, err = h.processResponse(ctx, p, resp)
	if err != nil {
		return nil, err
	}

	h.telemetry.Record(pluginName, invokeDuration,
		len(resp.GetFindings()),
		len(resp.GetPackages()),
		len(resp.GetAiComponents()),
		len(resp.GetDiagnostics()),
		false,
	)

	return resp, nil
}

// InvokeAll invokes a tool on all plugins that declare it.
// Uses errgroup with a concurrency semaphore from Policy.MaxConcurrency.
// Individual plugin errors become diagnostics, not fatal errors.
// Enforcement (rate limiting, read-only, redaction) is applied per-plugin.
func (h *Host) InvokeAll(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) ([]AttributedResponse, error) {
	h.mu.RLock()
	var targets []*Plugin
	for _, p := range h.plugins {
		if p.HasTool(toolName) {
			targets = append(targets, p)
		}
	}
	h.mu.RUnlock()

	if len(targets) == 0 {
		return nil, nil
	}

	// Bound the whole group by the LONGEST timeout any participating plugin is
	// allowed, then bound each plugin individually by its own below. Using a
	// single host-wide deadline would cut short a dynamic-runtime plugin whose
	// track grants it five minutes just because a core-analysis plugin's track
	// grants two.
	timeout := h.policy.ToolInvocationTimeout
	for _, p := range targets {
		if t := p.Policy().ToolInvocationTimeout; t > timeout {
			timeout = t
		}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Concurrency is genuinely host-global: it bounds this process's fan-out,
	// not any single plugin's entitlement.
	concurrency := h.policy.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	type indexedResp struct {
		index  int
		plugin string
		resp   *pluginv1.InvokeToolResponse
	}

	results := make([]indexedResp, 0, len(targets))
	var resultsMu sync.Mutex

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	for i, p := range targets {
		g.Go(func() error {
			pluginName := p.Info().Name
			policy := p.Policy()

			// Every pre-invocation control, via the shared gate. This path
			// previously re-inlined only the read-only check and the rate
			// limit, silently omitting per-tool safety validation — and this
			// is the path `nox scan` actually uses, so a tool declaring
			// requirements its policy forbids ran anyway.
			if err := h.authorizeTool(gCtx, p, toolName); err != nil {
				return nil // Non-fatal: the violation is already recorded.
			}

			invokeCtx := gCtx
			if t := policy.ToolInvocationTimeout; t > 0 {
				var cancel context.CancelFunc
				invokeCtx, cancel = context.WithTimeout(gCtx, t)
				defer cancel()
			}

			resp, err := p.InvokeTool(invokeCtx, toolName, input, workspaceRoot)
			if err != nil {
				h.mu.Lock()
				h.diagnostics = append(h.diagnostics, Diagnostic{
					Severity: "error",
					Message:  fmt.Sprintf("plugin %q InvokeTool(%q) failed: %v", pluginName, toolName, err),
					Source:   pluginName,
				})
				h.mu.Unlock()
				return nil // Non-fatal: record as diagnostic.
			}

			// Bandwidth accounting, secret redaction and diagnostics, via the
			// shared post-invocation path.
			resp, err = h.processResponse(gCtx, p, resp)
			if err != nil {
				return nil // Non-fatal: the violation is already recorded.
			}

			resultsMu.Lock()
			results = append(results, indexedResp{index: i, plugin: p.Info().Name, resp: resp})
			resultsMu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Place responses at their original index to preserve ordering.
	ordered := make([]AttributedResponse, len(targets))
	for _, r := range results {
		ordered[r.index] = AttributedResponse{PluginName: r.plugin, Response: r.resp}
	}
	// Compact: remove nil entries from skipped plugins (violations, errors).
	responses := ordered[:0]
	for _, r := range ordered {
		if r.Response != nil {
			responses = append(responses, r)
		}
	}
	return responses, nil
}

// MergeResults converts a single plugin response into domain types and
// adds them to the ScanResult. This method is not thread-safe with respect
// to FindingSet and AIInventory — call sequentially.
//
// workspaceRoot is the directory the plugin was pointed at; finding paths are
// made relative to it so a fingerprint does not move with the checkout (#454).
func (h *Host) MergeResults(pluginName string, resp *pluginv1.InvokeToolResponse, result *core.ScanResult, workspaceRoot string) {
	if resp == nil || result == nil {
		return
	}

	for _, pf := range resp.GetFindings() {
		result.Findings.Add(ProtoFindingToGo(pf, pluginName, workspaceRoot))
	}

	for _, pp := range resp.GetPackages() {
		result.Inventory.Add(ProtoPackageToGo(pp))
	}

	for _, pac := range resp.GetAiComponents() {
		result.AIInventory.Add(ProtoAIComponentToGo(pac))
	}

	for _, pg := range resp.GetGraphs() {
		result.Graphs = append(result.Graphs, ProtoGraphToGo(pg))
	}
	for _, pe := range resp.GetEnrichments() {
		result.Enrichments = append(result.Enrichments, ProtoEnrichmentToGo(pe))
	}
}

// MergeAllResults merges multiple plugin responses sequentially. workspaceRoot
// is the directory the plugins were pointed at; see MergeResults.
func (h *Host) MergeAllResults(responses []AttributedResponse, result *core.ScanResult, workspaceRoot string) {
	for _, r := range responses {
		h.MergeResults(r.PluginName, r.Response, result, workspaceRoot)
	}
}

// InvokePostScan invokes tools that require scan context. It builds a
// ScanContext from the current ScanResult and passes it to each tool
// that declares requires_scan_context=true.
func (h *Host) InvokePostScan(ctx context.Context, result *core.ScanResult, workspaceRoot string) error {
	scanCtx := GoScanResultToProtoContext(result)

	h.mu.RLock()
	type postScanEntry struct {
		plugin *Plugin
		tool   string
	}
	var postScanTools []postScanEntry
	for _, p := range h.plugins {
		for _, cap := range p.Info().Capabilities {
			for _, t := range cap.Tools {
				if t.RequiresScanContext {
					postScanTools = append(postScanTools, postScanEntry{p, t.Name})
				}
			}
		}
	}
	h.mu.RUnlock()

	for _, pt := range postScanTools {
		req := &pluginv1.InvokeToolRequest{
			ToolName:      pt.tool,
			WorkspaceRoot: workspaceRoot,
			ScanContext:   scanCtx,
		}

		// Post-scan tools are subject to exactly the same controls as any
		// other invocation. This path used to call the gRPC client directly,
		// so a post-scan tool ran with no policy, no rate limit, no timeout and
		// no secret redaction — which made nox's "never auto-applies fixes"
		// guarantee bypassable by any plugin declaring a non-read-only tool
		// with requires_scan_context.
		if err := h.authorizeToolWithoutTermination(ctx, pt.plugin, pt.tool); err != nil {
			h.mu.Lock()
			h.diagnostics = append(h.diagnostics, Diagnostic{
				Severity: "error",
				Message:  fmt.Sprintf("post-scan tool %q not permitted: %v", pt.tool, err),
				Source:   pt.plugin.Info().Name,
			})
			h.mu.Unlock()
			continue
		}

		resp, err := h.invokePostScanTool(ctx, pt.plugin, req)
		if err != nil {
			h.mu.Lock()
			h.diagnostics = append(h.diagnostics, Diagnostic{
				Severity: "error",
				Message:  fmt.Sprintf("post-scan tool %q failed: %v", pt.tool, err),
				Source:   pt.plugin.Info().Name,
			})
			h.mu.Unlock()
			continue
		}

		resp, err = h.processResponse(ctx, pt.plugin, resp)
		if err != nil {
			h.mu.Lock()
			h.diagnostics = append(h.diagnostics, Diagnostic{
				Severity: "error",
				Message:  fmt.Sprintf("post-scan tool %q response rejected: %v", pt.tool, err),
				Source:   pt.plugin.Info().Name,
			})
			h.mu.Unlock()
			continue
		}

		h.MergeResults(pt.plugin.Info().Name, resp, result, workspaceRoot)
	}

	return nil
}

// Diagnostics returns all collected diagnostics.
func (h *Host) Diagnostics() []Diagnostic {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Diagnostic, len(h.diagnostics))
	copy(out, h.diagnostics)
	return out
}

// Violations returns all recorded runtime violations.
func (h *Host) Violations() []RuntimeViolation {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]RuntimeViolation, len(h.violations))
	copy(out, h.violations)
	return out
}

// Telemetry returns a snapshot of collected plugin telemetry.
func (h *Host) Telemetry() []Telemetry {
	return h.telemetry.Snapshot()
}

// handleViolation logs a violation, records it, marks the plugin as failed,
// terminates it, and removes it from the host. Acquires h.mu internally.
func (h *Host) handleViolation(v RuntimeViolation, p *Plugin) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handleViolationLocked(v, p)
}

// handleViolationLocked is the lock-held implementation of handleViolation.
// Must be called with h.mu held.
func (h *Host) handleViolationLocked(v RuntimeViolation, p *Plugin) {
	h.logger.Error("runtime violation",
		"type", string(v.Type),
		"plugin", v.PluginName,
		"message", v.Message,
	)

	h.violations = append(h.violations, v)
	h.diagnostics = append(h.diagnostics, Diagnostic{
		Severity: "error",
		Message:  v.Error(),
		Source:   v.PluginName,
	})

	p.fail()
	_ = p.Close()

	delete(h.plugins, v.PluginName)
	h.buildToolIndex()
}

// estimateResponseSize sums the approximate byte size of text fields in a
// plugin response, for bandwidth accounting.
func estimateResponseSize(resp *pluginv1.InvokeToolResponse) int64 {
	if resp == nil {
		return 0
	}
	var size int64
	for _, f := range resp.GetFindings() {
		size += int64(len(f.GetMessage()))
		for k, v := range f.GetMetadata() {
			size += int64(len(k) + len(v))
		}
	}
	for _, d := range resp.GetDiagnostics() {
		size += int64(len(d.GetMessage()))
	}
	for _, ac := range resp.GetAiComponents() {
		for k, v := range ac.GetDetails() {
			size += int64(len(k) + len(v))
		}
	}
	for _, p := range resp.GetPackages() {
		size += int64(len(p.GetName()) + len(p.GetVersion()) + len(p.GetEcosystem()))
	}
	for _, g := range resp.GetGraphs() {
		size += int64(len(g.GetName()) + len(g.GetDescription()))
		for _, n := range g.GetNodes() {
			size += int64(len(n.GetId()) + len(n.GetLabel()) + len(n.GetFilePath()))
			for k, v := range n.GetProperties() {
				size += int64(len(k) + len(v))
			}
		}
		for _, e := range g.GetEdges() {
			size += int64(len(e.GetSource()) + len(e.GetTarget()) + len(e.GetLabel()))
			for k, v := range e.GetProperties() {
				size += int64(len(k) + len(v))
			}
		}
	}
	for _, e := range resp.GetEnrichments() {
		size += int64(len(e.GetFindingFingerprint()) + len(e.GetKind()) + len(e.GetTitle()) + len(e.GetBody()) + len(e.GetSource()))
		for k, v := range e.GetMetadata() {
			size += int64(len(k) + len(v))
		}
	}
	return size
}

// AvailableTools returns all registered tool names in "pluginName.toolName" format.
func (h *Host) AvailableTools() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	tools := make([]string, 0, len(h.toolIndex))
	for name := range h.toolIndex {
		tools = append(tools, name)
	}
	return tools
}

// Close shuts down all registered plugins.
func (h *Host) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var errs []error
	for name, p := range h.plugins {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing plugin %q: %w", name, err))
		}
	}
	h.plugins = make(map[string]*Plugin)
	h.toolIndex = make(map[string]*Plugin)

	if len(errs) > 0 {
		return fmt.Errorf("errors closing plugins: %v", errs)
	}
	return nil
}

// buildToolIndex rebuilds the tool index from all registered plugins.
// Must be called with h.mu held.
func (h *Host) buildToolIndex() {
	h.toolIndex = make(map[string]*Plugin)
	for _, p := range h.plugins {
		info := p.Info()
		for _, cap := range info.Capabilities {
			for _, tool := range cap.Tools {
				qualified := info.Name + "." + tool.Name
				h.toolIndex[qualified] = p
			}
		}
	}
}

// collectDiagnostics extracts diagnostics from a response and appends them.
// Must be called with h.mu held if called from concurrent context.
func (h *Host) collectDiagnostics(pluginName string, resp *pluginv1.InvokeToolResponse) {
	for _, d := range resp.GetDiagnostics() {
		sev := "info"
		switch d.GetSeverity() {
		case pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR:
			sev = "error"
		case pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING:
			sev = "warning"
		case pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO:
			sev = "info"
		}
		source := d.GetSource()
		if source == "" {
			source = pluginName
		}
		h.diagnostics = append(h.diagnostics, Diagnostic{
			Severity: sev,
			Message:  d.GetMessage(),
			Source:   source,
		})
	}
}

// resolveToolPlugin finds the plugin responsible for a given tool name.
// Supports qualified "pluginName.toolName" and unqualified "toolName" (first match).
func (h *Host) resolveToolPlugin(toolName string) (*Plugin, string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Try qualified name first.
	if p, ok := h.toolIndex[toolName]; ok {
		// Extract just the tool name part after the dot.
		parts := strings.SplitN(toolName, ".", 2)
		return p, parts[1], nil
	}

	// Try unqualified: find first plugin with this tool.
	for qualified, p := range h.toolIndex {
		parts := strings.SplitN(qualified, ".", 2)
		if len(parts) == 2 && parts[1] == toolName {
			return p, toolName, nil
		}
	}

	return nil, "", fmt.Errorf("no plugin provides tool %q", toolName)
}

// infoToProtoCapabilities converts Info capabilities back to proto
// for manifest validation. This is needed because ValidateManifest works
// with the proto GetManifestResponse type.
func infoToProtoCapabilities(info *Info) []*pluginv1.Capability {
	caps := make([]*pluginv1.Capability, len(info.Capabilities))
	for i, c := range info.Capabilities {
		capability := &pluginv1.Capability{
			Name:        c.Name,
			Description: c.Description,
		}
		for _, t := range c.Tools {
			capability.Tools = append(capability.Tools, &pluginv1.ToolDef{
				Name:                t.Name,
				Description:         t.Description,
				ReadOnly:            t.ReadOnly,
				RequiresScanContext: t.RequiresScanContext,
				// Must be carried back: RegisterPlugin/RegisterBinary rebuild the
				// manifest from Info before validating it, so dropping per-tool
				// safety here silently reverts registration to judging the
				// plugin-level ceiling alone — exactly the behaviour per-tool
				// safety exists to replace.
				Safety: t.Safety,
			})
		}
		for _, r := range c.Resources {
			capability.Resources = append(capability.Resources, &pluginv1.ResourceDef{
				UriTemplate: r.URITemplate,
				Name:        r.Name,
				Description: r.Description,
				MimeType:    r.MimeType,
			})
		}
		caps[i] = capability
	}
	return caps
}
