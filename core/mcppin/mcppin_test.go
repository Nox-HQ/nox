package mcppin

import (
	"testing"
	"time"
)

func fixedNow() func() time.Time {
	t := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newTestPinner(t *testing.T) *Pinner {
	t.Helper()
	p := New(WithDir(t.TempDir()), WithNow(fixedNow()))
	if err := p.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

const benignConfig = `{
  "mcpServers": {
    "fs": {"command": "mcp-server-filesystem", "args": ["./project"]}
  }
}`

// Same definition, different key order and whitespace — must hash identically.
const benignReordered = `{
  "mcpServers": {
    "fs": {"args": ["./project"], "command": "mcp-server-filesystem"}
  }
}`

const driftedConfig = `{
  "mcpServers": {
    "fs": {"command": "mcp-server-filesystem", "args": ["/"]}
  }
}`

func TestFirstObservation_NoFinding(t *testing.T) {
	p := newTestPinner(t)
	got := p.CheckArtifact("mcp.json", []byte(benignConfig))
	if len(got) != 0 {
		t.Fatalf("first observation should record silently, got %d findings: %+v", len(got), got)
	}
}

func TestNoDrift_NoFinding(t *testing.T) {
	p := newTestPinner(t)
	_ = p.CheckArtifact("mcp.json", []byte(benignConfig))
	got := p.CheckArtifact("mcp.json", []byte(benignConfig))
	if len(got) != 0 {
		t.Fatalf("unchanged definition must not flag, got %+v", got)
	}
}

func TestKeyOrderIndependent_NoDrift(t *testing.T) {
	p := newTestPinner(t)
	_ = p.CheckArtifact("mcp.json", []byte(benignConfig))
	got := p.CheckArtifact("mcp.json", []byte(benignReordered))
	if len(got) != 0 {
		t.Fatalf("reordered-but-equivalent definition must not flag, got %+v", got)
	}
}

func TestDrift_FiresOnce(t *testing.T) {
	p := newTestPinner(t)
	_ = p.CheckArtifact("mcp.json", []byte(benignConfig))

	got := p.CheckArtifact("mcp.json", []byte(driftedConfig))
	if len(got) != 1 {
		t.Fatalf("expected exactly one MCP-015 on drift, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.RuleID != RuleID {
		t.Errorf("rule ID = %q, want %q", f.RuleID, RuleID)
	}
	if f.Metadata["old_hash"] == "" || f.Metadata["new_hash"] == "" {
		t.Errorf("drift finding missing before/after hashes: %+v", f.Metadata)
	}
	if f.Metadata["old_hash"] == f.Metadata["new_hash"] {
		t.Errorf("old and new hashes must differ on drift")
	}

	// Re-scanning the now-pinned drifted definition must be quiet (alert once).
	again := p.CheckArtifact("mcp.json", []byte(driftedConfig))
	if len(again) != 0 {
		t.Fatalf("drift should alert once then re-pin, got %+v", again)
	}
}

func TestPersistence_Roundtrip(t *testing.T) {
	dir := t.TempDir()

	p1 := New(WithDir(dir), WithNow(fixedNow()))
	if err := p1.Load(); err != nil {
		t.Fatalf("load p1: %v", err)
	}
	_ = p1.CheckArtifact("mcp.json", []byte(benignConfig))
	if err := p1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh pinner over the same dir must see the persisted pin and detect drift
	// without a prior in-memory observation.
	p2 := New(WithDir(dir), WithNow(fixedNow()))
	if err := p2.Load(); err != nil {
		t.Fatalf("load p2: %v", err)
	}
	got := p2.CheckArtifact("mcp.json", []byte(driftedConfig))
	if len(got) != 1 {
		t.Fatalf("persisted pin should yield drift after reload, got %d: %+v", len(got), got)
	}
}

func TestClear_Reapproves(t *testing.T) {
	dir := t.TempDir()
	p := New(WithDir(dir), WithNow(fixedNow()))
	if err := p.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	_ = p.CheckArtifact("mcp.json", []byte(benignConfig))
	if err := p.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	// After clear, the drifted definition is treated as a fresh baseline.
	got := p.CheckArtifact("mcp.json", []byte(driftedConfig))
	if len(got) != 0 {
		t.Fatalf("cleared store should re-approve silently, got %+v", got)
	}
}

func TestNonMCPContent_Ignored(t *testing.T) {
	p := newTestPinner(t)
	got := p.CheckArtifact("config.json", []byte(`{"unrelated": true}`))
	if len(got) != 0 {
		t.Fatalf("non-MCP content must be ignored, got %+v", got)
	}
}
