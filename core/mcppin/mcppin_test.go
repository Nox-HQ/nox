package mcppin

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
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

// mustCheck runs CheckArtifact and fails the test on the (unexpected) parse
// error path, so the happy-path assertions stay readable.
func mustCheck(t *testing.T, p *Pinner, path string, content []byte) []findings.Finding {
	t.Helper()
	got, err := p.CheckArtifact(path, content)
	if err != nil {
		t.Fatalf("CheckArtifact(%s): unexpected error: %v", path, err)
	}
	return got
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
	got := mustCheck(t, p, "mcp.json", []byte(benignConfig))
	if len(got) != 0 {
		t.Fatalf("first observation should record silently, got %d findings: %+v", len(got), got)
	}
}

func TestNoDrift_NoFinding(t *testing.T) {
	p := newTestPinner(t)
	_ = mustCheck(t, p, "mcp.json", []byte(benignConfig))
	got := mustCheck(t, p, "mcp.json", []byte(benignConfig))
	if len(got) != 0 {
		t.Fatalf("unchanged definition must not flag, got %+v", got)
	}
}

func TestKeyOrderIndependent_NoDrift(t *testing.T) {
	p := newTestPinner(t)
	_ = mustCheck(t, p, "mcp.json", []byte(benignConfig))
	got := mustCheck(t, p, "mcp.json", []byte(benignReordered))
	if len(got) != 0 {
		t.Fatalf("reordered-but-equivalent definition must not flag, got %+v", got)
	}
}

func TestDrift_FiresOnce(t *testing.T) {
	p := newTestPinner(t)
	_ = mustCheck(t, p, "mcp.json", []byte(benignConfig))

	got := mustCheck(t, p, "mcp.json", []byte(driftedConfig))
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
	again := mustCheck(t, p, "mcp.json", []byte(driftedConfig))
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
	_ = mustCheck(t, p1, "mcp.json", []byte(benignConfig))
	if err := p1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh pinner over the same dir must see the persisted pin and detect drift
	// without a prior in-memory observation.
	p2 := New(WithDir(dir), WithNow(fixedNow()))
	if err := p2.Load(); err != nil {
		t.Fatalf("load p2: %v", err)
	}
	got := mustCheck(t, p2, "mcp.json", []byte(driftedConfig))
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
	_ = mustCheck(t, p, "mcp.json", []byte(benignConfig))
	if err := p.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	// After clear, the drifted definition is treated as a fresh baseline.
	got := mustCheck(t, p, "mcp.json", []byte(driftedConfig))
	if len(got) != 0 {
		t.Fatalf("cleared store should re-approve silently, got %+v", got)
	}
}

func TestNonMCPContent_Ignored(t *testing.T) {
	p := newTestPinner(t)
	got := mustCheck(t, p, "config.json", []byte(`{"unrelated": true}`))
	if len(got) != 0 {
		t.Fatalf("non-MCP content must be ignored, got %+v", got)
	}
}

// TestCorruptStore_IsError proves the rug-pull-disarming bug is fixed: a pin
// store that exists but does not parse must be a hard error, NOT a silent reset
// to empty. Before the fix Load returned nil and re-baselined every server, so a
// tampered server would be silently re-approved.
func TestCorruptStore_IsError(t *testing.T) {
	dir := t.TempDir()

	// Establish a real, non-empty store, then corrupt the file on disk.
	p1 := New(WithDir(dir), WithNow(fixedNow()))
	if err := p1.Load(); err != nil {
		t.Fatalf("load p1: %v", err)
	}
	_ = mustCheck(t, p1, "mcp.json", []byte(benignConfig))
	if err := p1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	storePath := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(storePath, []byte(`{"pins": not-json`), 0o644); err != nil {
		t.Fatalf("corrupt store: %v", err)
	}

	p2 := New(WithDir(dir), WithNow(fixedNow()))
	if err := p2.Load(); err == nil {
		t.Fatal("Load of a corrupt store must error, not silently reset to empty")
	}
}

// TestMalformedConfig_IsError proves malformed content handed in for pinning
// surfaces rather than being silently treated as "no servers to pin" (which is
// how a rogue config would evade rug-pull detection).
func TestMalformedConfig_IsError(t *testing.T) {
	p := newTestPinner(t)
	// Trailing comma — clearly an intended MCP config that does not parse.
	got, err := p.CheckArtifact("mcp.json", []byte(`{"mcpServers":{"fs":{"command":"x"},}}`))
	if err == nil {
		t.Fatal("malformed MCP config must return an error, got nil")
	}
	if got != nil {
		t.Fatalf("malformed config must return nil findings, got %+v", got)
	}
}
