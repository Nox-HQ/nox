package assist

import (
	"context"
	"fmt"
	"strings"
)

// maxToolResultLen is the maximum character length for tool result output
// included in LLM context. Longer outputs are truncated.
const maxToolResultLen = 4096

// PluginSource abstracts read-only access to plugin capabilities and tools.
// The assist package uses this interface to discover plugin context and
// optionally invoke read-only enrichment tools without depending on plugin
// internals.
type PluginSource interface {
	// Capabilities returns the capabilities of all registered plugins.
	Capabilities(ctx context.Context) []PluginCapability

	// InvokeReadOnly calls a read-only tool and returns its serialised output.
	// It must never call MergeResults or modify scan state.
	InvokeReadOnly(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) (*PluginToolResult, error)
}

// PluginCapability describes a single plugin and its capabilities.
type PluginCapability struct {
	PluginName  string
	PluginVer   string
	Name        string
	Description string
	Tools       []PluginTool
}

// PluginTool describes a single tool declared by a plugin.
type PluginTool struct {
	Name        string
	Description string
	ReadOnly    bool
}

// PluginToolResult holds the output of a read-only tool invocation.
type PluginToolResult struct {
	ToolName    string
	PluginName  string
	Output      string
	Diagnostics []string
}

// formatPluginContext formats plugin capabilities into a text block suitable
// for inclusion in an LLM prompt. Returns "" if caps is empty.
func formatPluginContext(caps []PluginCapability) string {
	if len(caps) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Available plugin capabilities:\n")
	for _, cap := range caps {
		fmt.Fprintf(&b, "\nPlugin: %s (v%s)\n", cap.PluginName, cap.PluginVer)
		fmt.Fprintf(&b, "  Capability: %s — %s\n", cap.Name, cap.Description)
		if len(cap.Tools) > 0 {
			b.WriteString("  Tools:\n")
			for _, t := range cap.Tools {
				ro := ""
				if t.ReadOnly {
					ro = " [read-only]"
				}
				fmt.Fprintf(&b, "    - %s: %s%s\n", t.Name, t.Description, ro)
			}
		}
	}
	return b.String()
}

// formatToolResult formats a single tool invocation result into a text block
// suitable for inclusion in an LLM prompt. Output longer than maxToolResultLen
// is truncated with an indicator.
func formatToolResult(result *PluginToolResult) string {
	if result == nil {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Enrichment from %s (plugin: %s):\n", result.ToolName, result.PluginName)

	output := result.Output
	if len(output) > maxToolResultLen {
		output = output[:maxToolResultLen] + "\n... [truncated]"
	}
	b.WriteString(output)

	if len(result.Diagnostics) > 0 {
		b.WriteString("\nDiagnostics:\n")
		for _, d := range result.Diagnostics {
			fmt.Fprintf(&b, "  - %s\n", d)
		}
	}

	return b.String()
}
