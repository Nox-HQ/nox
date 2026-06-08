package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/graph"
)

// writeNoxConfigRequiring writes a .nox.yaml into dir declaring the given
// plugins under plugins.required.
func writeNoxConfigRequiring(t *testing.T, dir string, required ...string) {
	t.Helper()
	body := "plugins:\n  required:\n"
	for _, r := range required {
		body += "    - " + r + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write .nox.yaml: %v", err)
	}
}

// setHook installs a ScanPluginHook for the duration of a test and restores
// the previous value afterwards.
func setHook(t *testing.T, fn func(ctx context.Context, target string, required []string) (*PluginScanOutput, error)) {
	t.Helper()
	prev := ScanPluginHook
	ScanPluginHook = fn
	t.Cleanup(func() { ScanPluginHook = prev })
}

func TestRunScan_MergesPluginFindings(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/taint-analysis")

	var gotTarget string
	var gotRequired []string
	setHook(t, func(_ context.Context, target string, required []string) (*PluginScanOutput, error) {
		gotTarget = target
		gotRequired = required
		f := findings.NewFinding(
			"TAINT-004", findings.SeverityHigh, findings.ConfidenceHigh,
			findings.Location{FilePath: "main.go", StartLine: 10, EndLine: 10},
			"Path Traversal: tainted input flows to file operations",
		)
		return &PluginScanOutput{
			Findings:    []findings.Finding{f},
			Enrichments: []findings.Enrichment{{}},
			Graphs:      []graph.Graph{{}},
		}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	// Hook received the target + the configured required list.
	if gotTarget != dir {
		t.Errorf("hook target = %q, want %q", gotTarget, dir)
	}
	if len(gotRequired) != 1 || gotRequired[0] != "nox/taint-analysis" {
		t.Errorf("hook required = %v, want [nox/taint-analysis]", gotRequired)
	}

	// The plugin finding is present...
	var found *findings.Finding
	for _, f := range result.Findings.ActiveFindings() {
		if f.RuleID == "TAINT-004" {
			ff := f
			found = &ff
			break
		}
	}
	if found == nil {
		t.Fatal("plugin finding TAINT-004 not merged into scan results")
	}
	// ...and was refined like any built-in finding (fingerprint assigned),
	// which is the point of merging before Stage 3.
	if found.Fingerprint == "" {
		t.Error("plugin finding was not fingerprinted (merged after refinement?)")
	}

	// Enrichments + graphs propagate to the result.
	if len(result.Enrichments) != 1 {
		t.Errorf("result.Enrichments = %d, want 1", len(result.Enrichments))
	}
	if len(result.Graphs) != 1 {
		t.Errorf("result.Graphs = %d, want 1", len(result.Graphs))
	}
}

func TestRunScan_NoHook_NoOp(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/taint-analysis")
	setHook(t, nil)

	if _, err := RunScan(dir); err != nil {
		t.Fatalf("RunScan with nil hook should succeed: %v", err)
	}
}

func TestRunScan_HookSkippedWhenNoRequired(t *testing.T) {
	dir := t.TempDir() // no .nox.yaml => no plugins.required

	called := false
	setHook(t, func(context.Context, string, []string) (*PluginScanOutput, error) {
		called = true
		return nil, nil
	})

	if _, err := RunScan(dir); err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if called {
		t.Error("hook called despite empty plugins.required")
	}
}

func TestRunScan_HookErrorIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/taint-analysis")
	setHook(t, func(context.Context, string, []string) (*PluginScanOutput, error) {
		return nil, context.DeadlineExceeded
	})

	if _, err := RunScan(dir); err != nil {
		t.Fatalf("plugin hook error should be non-fatal, got: %v", err)
	}
}
