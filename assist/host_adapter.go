package assist

import (
	"context"
	"fmt"

	"github.com/felixgeelhaar/hardline/plugin"
	"google.golang.org/protobuf/encoding/protojson"
)

// HostAdapter adapts a plugin.Host to the PluginSource interface,
// providing read-only access to plugin capabilities and tools for the
// assist package. It never calls MergeResults or modifies scan state.
type HostAdapter struct {
	host          *plugin.Host
	workspaceRoot string
}

// NewHostAdapter creates a HostAdapter wrapping the given plugin.Host.
// workspaceRoot is passed to InvokeReadOnly calls.
func NewHostAdapter(host *plugin.Host, workspaceRoot string) *HostAdapter {
	return &HostAdapter{host: host, workspaceRoot: workspaceRoot}
}

// Capabilities converts the host's registered plugins into PluginCapability values.
func (a *HostAdapter) Capabilities(_ context.Context) []PluginCapability {
	infos := a.host.Plugins()
	var caps []PluginCapability
	for _, info := range infos {
		for _, ci := range info.Capabilities {
			cap := PluginCapability{
				PluginName:  info.Name,
				PluginVer:   info.Version,
				Name:        ci.Name,
				Description: ci.Description,
			}
			for _, ti := range ci.Tools {
				cap.Tools = append(cap.Tools, PluginTool{
					Name:        ti.Name,
					Description: ti.Description,
					ReadOnly:    ti.ReadOnly,
				})
			}
			caps = append(caps, cap)
		}
	}
	return caps
}

// InvokeReadOnly calls a plugin tool via the host and serialises the proto
// response to a JSON string. It never calls MergeResults.
func (a *HostAdapter) InvokeReadOnly(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) (*PluginToolResult, error) {
	ws := workspaceRoot
	if ws == "" {
		ws = a.workspaceRoot
	}

	resp, err := a.host.InvokeTool(ctx, toolName, input, ws)
	if err != nil {
		return nil, fmt.Errorf("invoking tool %q: %w", toolName, err)
	}

	output, err := protojson.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshalling tool response: %w", err)
	}

	// Extract diagnostics as strings.
	var diags []string
	for _, d := range resp.GetDiagnostics() {
		diags = append(diags, d.GetMessage())
	}

	// Determine plugin name from tool name (best effort).
	pluginName := ""
	infos := a.host.Plugins()
	for _, info := range infos {
		for _, ci := range info.Capabilities {
			for _, ti := range ci.Tools {
				if ti.Name == toolName || info.Name+"."+ti.Name == toolName {
					pluginName = info.Name
				}
			}
		}
	}

	return &PluginToolResult{
		ToolName:    toolName,
		PluginName:  pluginName,
		Output:      string(output),
		Diagnostics: diags,
	}, nil
}
