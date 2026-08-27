package ai

import (
	"testing"

	"github.com/nox-hq/nox-core/degrade"
)

// TestExtractMCPToolPermissions_MalformedDegrades proves a mcp.json that does
// not parse is surfaced as a degradation instead of silently contributing an
// empty tool matrix.
func TestExtractMCPToolPermissions_MalformedDegrades(t *testing.T) {
	deg := &degrade.Degradations{}
	got := extractMCPToolPermissions("mcp.json", []byte(`{"mcpServers":{"fs":{"command":"x"},}}`), deg)
	if got != nil {
		t.Fatalf("malformed config must yield no tool sets, got %+v", got)
	}
	if deg.Len() == 0 {
		t.Fatal("malformed mcp.json must record a degradation")
	}
}

// TestExtractMCPToolPermissions_BadServerDefDegrades proves the per-server parse
// failure (a server value that is not an object) is surfaced rather than
// silently defaulting the server to all-tools with no signal.
func TestExtractMCPToolPermissions_BadServerDefDegrades(t *testing.T) {
	deg := &degrade.Degradations{}
	// Valid outer JSON; the "fs" server value is a string, not an object, so the
	// per-server decode fails and the server defaults to Tools=["*"].
	got := extractMCPToolPermissions("mcp.json", []byte(`{"mcpServers":{"fs":"not-an-object"}}`), deg)
	if len(got) != 1 {
		t.Fatalf("expected one (defaulted) tool set, got %+v", got)
	}
	if len(got[0].Tools) != 1 || got[0].Tools[0] != "*" {
		t.Fatalf("unreadable server must default to all-tools, got %+v", got[0].Tools)
	}
	if deg.Len() == 0 {
		t.Fatal("an unreadable server definition defaulted to all-tools must record a degradation")
	}
}

// TestExtractMCPToolPermissions_ValidNoDegradation guards against false
// degradations on a well-formed config.
func TestExtractMCPToolPermissions_ValidNoDegradation(t *testing.T) {
	deg := &degrade.Degradations{}
	got := extractMCPToolPermissions("mcp.json", []byte(`{"mcpServers":{"fs":{"command":"mcp-fs","args":["--tools","read"]}}}`), deg)
	if len(got) != 1 {
		t.Fatalf("expected one tool set, got %+v", got)
	}
	if deg.Len() != 0 {
		t.Fatalf("valid config must not degrade, got %d", deg.Len())
	}
}

// TestExtractMCPToolPermissions_NilCollectorSafe proves a nil collector (the
// default for callers that pass no option) is safe.
func TestExtractMCPToolPermissions_NilCollectorSafe(t *testing.T) {
	got := extractMCPToolPermissions("mcp.json", []byte(`{"mcpServers":{"fs":"bad",}}`), nil)
	if got != nil {
		t.Fatalf("malformed config with nil collector must yield nil, got %+v", got)
	}
}
