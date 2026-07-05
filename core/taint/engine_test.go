package taint

import "testing"

// TestHeuristicEngineDetectsFlow verifies the stub engine reports a flow when a
// tainted variable reaches a sink in the same scope.
func TestHeuristicEngineDetectsFlow(t *testing.T) {
	eng := NewHeuristicEngine(nil)
	// Models Python "name = request.args" followed by "os.system(name)".
	unit := Unit{
		FilePath: "app.py",
		FuncName: "handle",
		Language: "python",
		Stmts: []Statement{
			{Line: 1, Assigns: "name", Calls: []string{"request.args"}},
			{Line: 2, Calls: []string{"os.system"}, Reads: []string{"name"}},
		},
	}
	flows := eng.Analyze(unit)
	if len(flows) != 1 {
		t.Fatalf("Analyze() returned %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Sink.VulnClass != VulnCommandInjection {
		t.Errorf("flow VulnClass = %q, want command_injection", f.Sink.VulnClass)
	}
	if f.Sink.RuleID != "TAINT-002" {
		t.Errorf("flow RuleID = %q, want TAINT-002", f.Sink.RuleID)
	}
	if f.SourceLine != 1 || f.SinkLine != 2 {
		t.Errorf("flow lines = source %d sink %d, want 1 and 2", f.SourceLine, f.SinkLine)
	}
	if f.Source.Kind != SourceHTTPQuery {
		t.Errorf("flow source kind = %q, want http_query", f.Source.Kind)
	}
}

// TestHeuristicEnginePropagatesThroughAssignment verifies taint flows across an
// intermediate assignment.
func TestHeuristicEnginePropagatesThroughAssignment(t *testing.T) {
	eng := NewHeuristicEngine(nil)
	unit := Unit{
		FilePath: "app.py",
		Language: "python",
		Stmts: []Statement{
			{Line: 1, Assigns: "raw", Calls: []string{"os.getenv"}},
			{Line: 2, Assigns: "cmd", Reads: []string{"raw"}},
			{Line: 3, Calls: []string{"subprocess.call"}, Reads: []string{"cmd"}},
		},
	}
	flows := eng.Analyze(unit)
	if len(flows) != 1 {
		t.Fatalf("Analyze() returned %d flows, want 1", len(flows))
	}
	if flows[0].Source.Kind != SourceEnv {
		t.Errorf("source kind = %q, want env", flows[0].Source.Kind)
	}
}

// TestHeuristicEngineSanitizerBreaksFlow verifies a sanitizer between source and
// sink suppresses the flow.
func TestHeuristicEngineSanitizerBreaksFlow(t *testing.T) {
	eng := NewHeuristicEngine(nil)
	unit := Unit{
		FilePath: "app.py",
		Language: "python",
		Stmts: []Statement{
			{Line: 1, Assigns: "raw", Calls: []string{"request.args"}},
			{Line: 2, Assigns: "safe", Calls: []string{"shlex.quote"}, Reads: []string{"raw"}},
			{Line: 3, Calls: []string{"os.system"}, Reads: []string{"safe"}},
		},
	}
	if flows := eng.Analyze(unit); len(flows) != 0 {
		t.Fatalf("Analyze() returned %d flows, want 0 (sanitized)", len(flows))
	}
}

// TestHeuristicEngineNoSourceNoFlow verifies a sink with no tainted input is not
// reported (avoids trivial false positives).
func TestHeuristicEngineNoSourceNoFlow(t *testing.T) {
	eng := NewHeuristicEngine(nil)
	unit := Unit{
		FilePath: "app.py",
		Language: "python",
		Stmts: []Statement{
			{Line: 1, Assigns: "cmd", Reads: []string{}},
			{Line: 2, Calls: []string{"os.system"}, Reads: []string{"cmd"}},
		},
	}
	if flows := eng.Analyze(unit); len(flows) != 0 {
		t.Fatalf("Analyze() returned %d flows, want 0 (no source)", len(flows))
	}
}

// TestHeuristicEngineDeterministic verifies repeated runs yield identical output.
func TestHeuristicEngineDeterministic(t *testing.T) {
	eng := NewHeuristicEngine(nil)
	unit := Unit{
		FilePath: "app.js",
		Language: "javascript",
		Stmts: []Statement{
			{Line: 1, Assigns: "q", Calls: []string{"req.query"}},
			{Line: 2, Calls: []string{"child_process.exec"}, Reads: []string{"q"}},
			{Line: 3, Calls: []string{"eval"}, Reads: []string{"q"}},
		},
	}
	first := eng.Analyze(unit)
	for i := 0; i < 5; i++ {
		got := eng.Analyze(unit)
		if len(got) != len(first) {
			t.Fatalf("run %d: len = %d, want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].SinkCall != first[j].SinkCall || got[j].SinkLine != first[j].SinkLine {
				t.Errorf("run %d flow %d differs: %+v vs %+v", i, j, got[j], first[j])
			}
		}
	}
	if len(first) != 2 {
		t.Fatalf("want 2 flows (exec + eval), got %d", len(first))
	}
	// Deterministic order: line 2 before line 3.
	if first[0].SinkLine > first[1].SinkLine {
		t.Errorf("flows not sorted by sink line: %d then %d", first[0].SinkLine, first[1].SinkLine)
	}
}
