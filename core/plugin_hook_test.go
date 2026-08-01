package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// TestRunScan_PluginAndBuiltinTaintFlowReportedOnce covers the double-report in
// issue #368: the taint-analysis plugin anchors a flow at its SOURCE line while
// the built-in taint model anchors the same flow at its SINK line, so one
// vulnerability arrived as two findings with two fingerprints — two alerts and
// two baseline entries.
//
// The source files and the plugin payload below are the reproduction from the
// issue: the built-in engine really runs over them, and the hook emits exactly
// what nox/taint-analysis@0.7.2 emits for them.
func TestRunScan_PluginAndBuiltinTaintFlowReportedOnce(t *testing.T) {
	dir := t.TempDir()
	writeNoxConfigRequiring(t, dir, "nox/taint-analysis")

	// Source on line 11, sink on line 12.
	writeGoFile(t, dir, "sqli.go", `package repro

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handleSQL(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, err := db.Query("SELECT * FROM users WHERE name = '" + q + "'")
	if err != nil {
		return
	}
	defer rows.Close()
	w.Write([]byte("ok"))
}
`)
	// Source on line 9, sink on line 10; the tainted read is echoed on line 14,
	// which only the plugin detects.
	writeGoFile(t, dir, "path.go", `package repro

import (
	"net/http"
	"os"
)

func handlePath(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("p")
	b, err := os.ReadFile("/data/" + p)
	if err != nil {
		return
	}
	w.Write(b)
}
`)

	setHook(t, func(context.Context, string, []string) (*PluginScanOutput, error) {
		return &PluginScanOutput{Findings: []findings.Finding{
			{
				RuleID: "TAINT-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
				Location: findings.Location{FilePath: "sqli.go", StartLine: 11, EndLine: 11},
				Message:  "SQL Injection: tainted input flows to SQL execution: q flows from http_query (line 11) to db.Query (line 12) in handleSQL",
				Metadata: map[string]string{
					"cwe": "CWE-89", "function": "handleSQL", "language": "go",
					"sink_line": "12", "source_kind": "http_query", "source_line": "11", "source_var": "q",
				},
			},
			{
				RuleID: "TAINT-004", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
				Location: findings.Location{FilePath: "path.go", StartLine: 9, EndLine: 9},
				Message:  "Path Traversal: tainted input flows to file operations: p flows from http_query (line 9) to os.ReadFile (line 10) in handlePath",
				Metadata: map[string]string{
					"cwe": "CWE-22", "function": "handlePath", "language": "go",
					"sink_line": "10", "source_kind": "http_query", "source_line": "9", "source_var": "p",
				},
			},
			{
				RuleID: "TAINT-003", Severity: findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
				Location: findings.Location{FilePath: "path.go", StartLine: 10, EndLine: 10},
				Message:  "XSS: tainted input flows to HTML output: b flows from http_query (line 10) to w.Write (line 14) in handlePath",
				Metadata: map[string]string{
					"cwe": "CWE-79", "function": "handlePath", "language": "go",
					"sink_line": "14", "source_kind": "http_query", "source_line": "10", "source_var": "b",
				},
			},
		}}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	byRule := map[string][]findings.Finding{}
	for _, f := range result.Findings.Findings() {
		if strings.HasPrefix(f.RuleID, "TAINT-") {
			byRule[f.RuleID] = append(byRule[f.RuleID], f)
		}
	}

	// Direction 1: the two anchors on one flow collapse to one finding, kept at
	// the sink — that is where the fix goes, and it is the anchor already in
	// everyone's baselines.
	for _, tc := range []struct {
		rule     string
		file     string
		sinkLine int
	}{
		{"TAINT-001", "sqli.go", 12},
		{"TAINT-004", "path.go", 10},
	} {
		got := byRule[tc.rule]
		if len(got) != 1 {
			t.Errorf("%s: got %d findings, want 1 (same flow reported by both the built-in model and the plugin)", tc.rule, len(got))
			for _, f := range got {
				t.Logf("  %s:%d %s", f.Location.FilePath, f.Location.StartLine, f.Message)
			}
			continue
		}
		if got[0].Location.FilePath != tc.file || got[0].Location.StartLine != tc.sinkLine {
			t.Errorf("%s: kept %s:%d, want the sink anchor %s:%d",
				tc.rule, got[0].Location.FilePath, got[0].Location.StartLine, tc.file, tc.sinkLine)
		}
	}

	// Direction 2: the plugin's genuinely-new flow — an XSS the built-in model
	// does not detect at all — is untouched. Collapsing duplicates must never
	// cost real coverage.
	xss := byRule["TAINT-003"]
	if len(xss) != 1 {
		t.Fatalf("TAINT-003: got %d findings, want the plugin's unique XSS flow kept", len(xss))
	}
	if xss[0].Location.StartLine != 10 || xss[0].Metadata["source_var"] != "b" {
		t.Errorf("TAINT-003: kept %s:%d (source_var=%q), want the plugin finding at path.go:10 (source_var=b)",
			xss[0].Location.FilePath, xss[0].Location.StartLine, xss[0].Metadata["source_var"])
	}
}

// writeGoFile writes a Go source file into dir for a scan test.
func writeGoFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
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

func TestRunScan_HookRunsEvenWhenNoRequired(t *testing.T) {
	dir := t.TempDir() // no .nox.yaml => no plugins.required

	called := false
	setHook(t, func(context.Context, string, []string) (*PluginScanOutput, error) {
		called = true
		return nil, nil
	})

	if _, err := RunScan(dir); err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	// The hook now runs even with nothing declared: it is what reports that
	// installed plugins were skipped. It still contributes no findings — the
	// declaration remains the activation switch (#403).
	if !called {
		t.Error("hook not called; installed-but-undeclared plugins would go unreported")
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
