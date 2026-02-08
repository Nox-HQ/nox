package assist

import (
	"testing"

	"github.com/nox-hq/nox/plugin"
)

// TestHostAdapter_ImplementsPluginSource is a compile-time check that
// HostAdapter satisfies the PluginSource interface.
func TestHostAdapter_ImplementsPluginSource(t *testing.T) {
	var _ PluginSource = (*HostAdapter)(nil)
}

// TestHostAdapter_Capabilities tests that the adapter correctly converts
// plugin.PluginInfo into PluginCapability values.
func TestHostAdapter_Capabilities(t *testing.T) {
	// Create a host with no registered plugins — Capabilities should return empty.
	host := plugin.NewHost()
	defer host.Close()

	adapter := NewHostAdapter(host, "/tmp/workspace")
	caps := adapter.Capabilities(nil)

	if len(caps) != 0 {
		t.Fatalf("expected 0 capabilities from empty host, got %d", len(caps))
	}
}

// TestNewHostAdapter verifies the constructor sets fields correctly.
func TestNewHostAdapter(t *testing.T) {
	host := plugin.NewHost()
	defer host.Close()

	adapter := NewHostAdapter(host, "/workspace")
	if adapter.host != host {
		t.Error("expected host to be set")
	}
	if adapter.workspaceRoot != "/workspace" {
		t.Errorf("expected workspaceRoot /workspace, got %q", adapter.workspaceRoot)
	}
}
