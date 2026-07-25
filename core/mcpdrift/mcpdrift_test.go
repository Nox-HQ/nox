package mcpdrift

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

func capture(t *testing.T, mode string) Manifest {
	t.Helper()
	cmd, env := mockCommand(mode)
	m, err := CaptureManifest(context.Background(), CaptureOptions{Command: cmd, Env: env, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("CaptureManifest(%s): %v", mode, err)
	}
	return m
}

// TestCaptureManifest_Deterministic proves two captures of an unchanged server
// are byte-identical after canonicalization, regardless of wire key/tool order.
func TestCaptureManifest_Deterministic(t *testing.T) {
	m1 := capture(t, "benign")
	m2 := capture(t, "benign")

	if got := len(m1.Tools); got != 2 {
		t.Fatalf("expected 2 tools, got %d", got)
	}
	// Tools must be sorted by name.
	if m1.Tools[0].Name != "get_forecast" || m1.Tools[1].Name != "weather" {
		t.Fatalf("tools not sorted by name: %s, %s", m1.Tools[0].Name, m1.Tools[1].Name)
	}
	if m1.Fingerprint() != m2.Fingerprint() {
		t.Fatalf("fingerprints differ across identical captures:\n %s\n %s", m1.Fingerprint(), m2.Fingerprint())
	}
	b1, _ := json.Marshal(m1)
	b2, _ := json.Marshal(m2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("captures not byte-identical:\n%s\n%s", b1, b2)
	}
}

// TestDrift_None_OnUnchangedServer: a benign re-capture shows no drift and emits
// no findings.
func TestDrift_None_OnUnchangedServer(t *testing.T) {
	base := capture(t, "benign")
	current := capture(t, "benign")

	d := DiffManifests(base, current)
	if d.IsDrift() {
		t.Fatalf("expected no drift, got %+v", d)
	}
	if fs := ToFindings(d, ".nox/mcp-baseline.json", base.ServerName); len(fs) != 0 {
		t.Fatalf("expected 0 findings on unchanged server, got %d", len(fs))
	}
}

// TestDrift_RugPull_Detected: benign baseline vs a rug-pull capture yields the
// expected added/removed/changed sets and the right finding severities.
func TestDrift_RugPull_Detected(t *testing.T) {
	base := capture(t, "benign")
	current := capture(t, "rugpull")

	d := DiffManifests(base, current)
	if !d.IsDrift() {
		t.Fatal("expected drift, got none")
	}

	// added: run_command (exec)
	if len(d.AddedTools) != 1 || d.AddedTools[0].Name != "run_command" {
		t.Fatalf("expected run_command added, got %+v", d.AddedTools)
	}
	if len(d.RemovedTools) != 0 {
		t.Fatalf("expected no removed tools, got %v", d.RemovedTools)
	}
	// changes: weather description_changed, get_forecast schema_widened
	byTool := map[string]ToolChange{}
	for _, c := range d.Changes {
		byTool[c.Tool] = c
	}
	if c, ok := byTool["weather"]; !ok || c.Type != DescriptionChanged {
		t.Fatalf("expected weather description_changed, got %+v", byTool["weather"])
	}
	if c, ok := byTool["get_forecast"]; !ok || c.Type != SchemaWidened {
		t.Fatalf("expected get_forecast schema_widened, got %+v", byTool["get_forecast"])
	} else if len(c.AddedProps) != 1 || c.AddedProps[0] != "api_key" {
		t.Fatalf("expected added prop api_key, got %v", c.AddedProps)
	}

	// findings → severities
	fs := ToFindings(d, ".nox/mcp-baseline.json", base.ServerName)
	sev := map[string]findings.Severity{}
	for _, f := range fs {
		sev[f.RuleID] = f.Severity
	}
	if sev[RuleNewExecTool] != findings.SeverityCritical {
		t.Errorf("new exec tool: expected critical, got %q", sev[RuleNewExecTool])
	}
	if sev[RuleDescriptionChanged] != findings.SeverityCritical {
		t.Errorf("poisoned description change: expected critical, got %q", sev[RuleDescriptionChanged])
	}
	if sev[RuleSchemaWidened] != findings.SeverityHigh {
		t.Errorf("schema widened: expected high, got %q", sev[RuleSchemaWidened])
	}
}

// TestBaselineRoundTrip: save then load yields the same comparable manifest, and
// re-diffing a loaded baseline against a fresh identical capture shows no drift.
func TestBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nox", "mcp-baseline.json")

	cmd, _ := mockCommand("benign")
	base := capture(t, "benign")
	bl := NewBaseline(cmd, base, time.Now())
	if err := bl.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Manifest.Fingerprint() != base.Fingerprint() {
		t.Fatalf("fingerprint changed across save/load: %s vs %s", loaded.Manifest.Fingerprint(), base.Fingerprint())
	}

	current := capture(t, "benign")
	if DiffManifests(loaded.Manifest, current).IsDrift() {
		t.Fatal("expected no drift after round-trip against unchanged server")
	}
}

// TestSaveDeterministic: saving the same baseline twice (same timestamp) yields
// byte-identical files — the diffable-data guarantee.
func TestSaveDeterministic(t *testing.T) {
	dir := t.TempDir()
	cmd, _ := mockCommand("benign")
	base := capture(t, "benign")
	ts := time.Unix(1700000000, 0)

	p1 := filepath.Join(dir, "a.json")
	p2 := filepath.Join(dir, "b.json")
	if err := NewBaseline(cmd, base, ts).Save(p1); err != nil {
		t.Fatal(err)
	}
	if err := NewBaseline(cmd, base, ts).Save(p2); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(p1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("baseline serialization not deterministic:\n%s\n---\n%s", b1, b2)
	}
}

// TestRemovedToolFinding checks the removed-tool path and its severity.
func TestRemovedToolFinding(t *testing.T) {
	base := capture(t, "rugpull") // has run_command
	current := capture(t, "benign")

	d := DiffManifests(base, current)
	if len(d.RemovedTools) != 1 || d.RemovedTools[0] != "run_command" {
		t.Fatalf("expected run_command removed, got %v", d.RemovedTools)
	}
	fs := ToFindings(d, ".nox/mcp-baseline.json", base.ServerName)
	var found bool
	for _, f := range fs {
		if f.RuleID == RuleRemovedTool {
			found = true
			if f.Severity != findings.SeverityMedium {
				t.Errorf("removed tool: expected medium, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected a removed-tool finding")
	}
}
