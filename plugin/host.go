package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/felixgeelhaar/hardline/core"
	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
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
	mu          sync.RWMutex
	logger      *slog.Logger
}

// HostOption is a functional option for configuring a Host.
type HostOption func(*Host)

// WithPolicy sets the safety policy for the host.
func WithPolicy(p Policy) HostOption {
	return func(h *Host) { h.policy = p }
}

// WithLogger sets the logger for the host.
func WithLogger(l *slog.Logger) HostOption {
	return func(h *Host) { h.logger = l }
}

// NewHost creates a Host with the given options.
// Defaults: DefaultPolicy(), slog.Default().
func NewHost(opts ...HostOption) *Host {
	h := &Host{
		policy:    DefaultPolicy(),
		plugins:   make(map[string]*Plugin),
		toolIndex: make(map[string]*Plugin),
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
		Capabilities: infoToProtoCapabilities(info),
		Safety:       info.Safety,
	}, h.policy)

	if len(violations) > 0 {
		_ = p.Close()
		msgs := make([]string, len(violations))
		for i, v := range violations {
			msgs[i] = v.Error()
		}
		return fmt.Errorf("plugin %q rejected: %s", info.Name, strings.Join(msgs, "; "))
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.plugins[info.Name] = p
	h.buildToolIndex()
	h.logger.Info("registered plugin", "name", info.Name, "version", info.Version)

	return nil
}

// RegisterBinary spawns a plugin binary subprocess and registers it.
func (h *Host) RegisterBinary(ctx context.Context, path string, args []string) error {
	timeout := h.policy.ToolInvocationTimeout
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
		Capabilities: infoToProtoCapabilities(info),
		Safety:       info.Safety,
	}, h.policy)

	if len(violations) > 0 {
		_ = p.Close()
		msgs := make([]string, len(violations))
		for i, v := range violations {
			msgs[i] = v.Error()
		}
		return fmt.Errorf("plugin %q rejected: %s", info.Name, strings.Join(msgs, "; "))
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.plugins[info.Name] = p
	h.buildToolIndex()
	h.logger.Info("registered plugin binary", "name", info.Name, "path", path)

	return nil
}

// Plugins returns info for all registered plugins.
func (h *Host) Plugins() []PluginInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	infos := make([]PluginInfo, 0, len(h.plugins))
	for _, p := range h.plugins {
		infos = append(infos, p.Info())
	}
	return infos
}

// InvokeTool routes a tool invocation to the appropriate plugin.
// Supports qualified "pluginName.toolName" and unqualified "toolName" (first match).
func (h *Host) InvokeTool(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) (*pluginv1.InvokeToolResponse, error) {
	p, resolvedName, err := h.resolveToolPlugin(toolName)
	if err != nil {
		return nil, err
	}

	timeout := h.policy.ToolInvocationTimeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	resp, err := p.InvokeTool(ctx, resolvedName, input, workspaceRoot)
	if err != nil {
		return nil, err
	}

	h.collectDiagnostics(p.Info().Name, resp)
	return resp, nil
}

// InvokeAll invokes a tool on all plugins that declare it.
// Uses errgroup with a concurrency semaphore from Policy.MaxConcurrency.
// Individual plugin errors become diagnostics, not fatal errors.
func (h *Host) InvokeAll(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) ([]*pluginv1.InvokeToolResponse, error) {
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

	timeout := h.policy.ToolInvocationTimeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	concurrency := h.policy.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	type indexedResp struct {
		index int
		resp  *pluginv1.InvokeToolResponse
	}

	results := make([]indexedResp, 0, len(targets))
	var resultsMu sync.Mutex

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	for i, p := range targets {
		i, p := i, p
		g.Go(func() error {
			resp, err := p.InvokeTool(gCtx, toolName, input, workspaceRoot)
			if err != nil {
				h.mu.Lock()
				h.diagnostics = append(h.diagnostics, Diagnostic{
					Severity: "error",
					Message:  fmt.Sprintf("plugin %q InvokeTool(%q) failed: %v", p.Info().Name, toolName, err),
					Source:   p.Info().Name,
				})
				h.mu.Unlock()
				return nil // Non-fatal: record as diagnostic.
			}
			h.mu.Lock()
			h.collectDiagnostics(p.Info().Name, resp)
			h.mu.Unlock()

			resultsMu.Lock()
			results = append(results, indexedResp{index: i, resp: resp})
			resultsMu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	responses := make([]*pluginv1.InvokeToolResponse, len(results))
	for i, r := range results {
		responses[i] = r.resp
	}
	return responses, nil
}

// MergeResults converts a single plugin response into domain types and
// adds them to the ScanResult. This method is not thread-safe with respect
// to FindingSet and AIInventory — call sequentially.
func (h *Host) MergeResults(resp *pluginv1.InvokeToolResponse, result *core.ScanResult) {
	if resp == nil || result == nil {
		return
	}

	for _, pf := range resp.GetFindings() {
		result.Findings.Add(ProtoFindingToGo(pf))
	}

	for _, pp := range resp.GetPackages() {
		result.Inventory.Add(ProtoPackageToGo(pp))
	}

	for _, pac := range resp.GetAiComponents() {
		result.AIInventory.Add(ProtoAIComponentToGo(pac))
	}
}

// MergeAllResults merges multiple plugin responses sequentially.
func (h *Host) MergeAllResults(responses []*pluginv1.InvokeToolResponse, result *core.ScanResult) {
	for _, resp := range responses {
		h.MergeResults(resp, result)
	}
}

// Diagnostics returns all collected diagnostics.
func (h *Host) Diagnostics() []Diagnostic {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Diagnostic, len(h.diagnostics))
	copy(out, h.diagnostics)
	return out
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

// infoToProtoCapabilities converts PluginInfo capabilities back to proto
// for manifest validation. This is needed because ValidateManifest works
// with the proto GetManifestResponse type.
func infoToProtoCapabilities(info PluginInfo) []*pluginv1.Capability {
	caps := make([]*pluginv1.Capability, len(info.Capabilities))
	for i, c := range info.Capabilities {
		cap := &pluginv1.Capability{
			Name:        c.Name,
			Description: c.Description,
		}
		for _, t := range c.Tools {
			cap.Tools = append(cap.Tools, &pluginv1.ToolDef{
				Name:        t.Name,
				Description: t.Description,
				ReadOnly:    t.ReadOnly,
			})
		}
		for _, r := range c.Resources {
			cap.Resources = append(cap.Resources, &pluginv1.ResourceDef{
				UriTemplate: r.URITemplate,
				Name:        r.Name,
				Description: r.Description,
				MimeType:    r.MimeType,
			})
		}
		caps[i] = cap
	}
	return caps
}
