package threatmodel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// before returns the fixture with the agent's shell tool, the MCP server and
// the ingress removed, as an earlier state of the same system.
func before() Input {
	in := fixture()
	in.Inventory.ToolMatrix = []ai.ToolPermissionSet{{
		Agent: "assistant.js", Path: "src/routes/assistant.js",
		Tools:        []string{"query_db"},
		Capabilities: map[string][]string{},
	}}
	in.Inventory.Components = nil
	var keep []findings.Finding
	for _, f := range in.Report.Findings {
		if f.RuleID != "IAC-149" {
			keep = append(keep, f)
		}
	}
	in.Report.Findings = keep
	return in
}

func TestCompareReportsNewBoundariesElementsAndFlows(t *testing.T) {
	d := Compare(Build(before()), Build(fixture()))

	boundaries := map[string]bool{}
	for _, b := range d.BoundariesAdded {
		boundaries[b.Label] = true
	}
	for _, want := range []string{"model output → shell", "model output → outbound network", "model output → MCP server tool"} {
		if !boundaries[want] {
			t.Errorf("missing new trust boundary %q; got %v", want, boundaries)
		}
	}
	elems := map[string]bool{}
	for _, e := range d.ElementsAdded {
		elems[e.ID] = true
	}
	for _, want := range []string{"mcp:shell@.mcp.json", "deploy:ingress@deploy/k8s/ingress.yaml"} {
		if !elems[want] {
			t.Errorf("missing new element %q; got %v", want, elems)
		}
	}
	if elems["actor:internet"] || elems["effect:shell"] {
		t.Error("actors and host capabilities arrive through flows, not as elements of their own")
	}
	foundFlow := false
	for _, f := range d.FlowsAdded {
		if f.Boundary == "tool:shell" {
			foundFlow = true
		}
	}
	if !foundFlow {
		t.Errorf("the shell flow must be reported: %+v", d.FlowsAdded)
	}
	if len(d.ElementsRemoved) != 0 || len(d.BoundariesRemoved) != 0 {
		t.Errorf("nothing was removed: %+v %+v", d.ElementsRemoved, d.BoundariesRemoved)
	}
}

func TestCompareReportsRemovals(t *testing.T) {
	d := Compare(Build(fixture()), Build(before()))
	if len(d.BoundariesRemoved) == 0 || len(d.ElementsRemoved) == 0 {
		t.Errorf("the reverse comparison must report removals: %+v", d)
	}
}

// A cell whose evidence changed is reported with the evidence that came and
// went, keyed without line numbers.
func TestCompareReportsCellsWhoseEvidenceChanged(t *testing.T) {
	d := Compare(Build(before()), Build(fixture()))
	var got *CellChange
	for i, c := range d.CellsChanged {
		if c.Element == "agent:src/routes/assistant.js" && c.Category == ElevationOfPrivilege {
			got = &d.CellsChanged[i]
		}
	}
	if got == nil {
		t.Fatalf("the agent's elevation-of-privilege cell changed (it gained shell_exec): %+v", d.CellsChanged)
	}
	joined := strings.Join(got.Added, "\n")
	if !strings.Contains(joined, "run_shell (shell_exec)") {
		t.Errorf("added = %v", got.Added)
	}
	for _, k := range append(got.Added, got.Removed...) {
		if strings.Contains(k, ".js:") {
			t.Errorf("evidence keys must not carry line numbers: %q", k)
		}
	}
}

// Moving a finding by a few lines is not a change in what is evidenced.
func TestCompareIgnoresLinesThatOnlyMoved(t *testing.T) {
	moved := fixture()
	for i := range moved.Report.Findings {
		moved.Report.Findings[i].Location.StartLine += 3
	}
	for i := range moved.Report.Routes {
		moved.Report.Routes[i].Line += 3
	}
	d := Compare(Build(fixture()), Build(moved))
	if !d.Empty() {
		t.Errorf("a pure line shift is a change: %+v", d)
	}
}

func TestCompareIdenticalModelsIsEmpty(t *testing.T) {
	if d := Compare(Build(fixture()), Build(fixture())); !d.Empty() || len(d.Caveats) != 0 {
		t.Errorf("delta = %+v", d)
	}
}

// A comparison that cannot be made must say so: a previous model built without
// an AI inventory has no agents to lose, and the new ones are not "new".
func TestCompareSaysWhenAnInputWasMissingFromOneSide(t *testing.T) {
	noAI := fixture()
	noAI.Inventory = nil
	d := Compare(Build(noAI), Build(fixture()))
	if len(d.Caveats) == 0 || !strings.Contains(d.Caveats[0], "AI inventory") {
		t.Fatalf("caveats = %v", d.Caveats)
	}
	for _, e := range d.ElementsAdded {
		switch e.Kind {
		case KindAgent, KindModel, KindMCPServer, KindMCPClient:
			t.Errorf("%s was reported added although the earlier model had no inventory", e.ID)
		}
	}
	for _, b := range d.BoundariesAdded {
		if strings.HasPrefix(b.ID, "tool:") || b.ID == boundaryPrompt {
			t.Errorf("boundary %s was reported added although AI elements were not compared", b.ID)
		}
	}
}

func TestCompareSaysWhenRoutesWerenotRecordedBefore(t *testing.T) {
	old := fixture()
	old.Report.Routes = nil
	d := Compare(Build(old), Build(fixture()))
	found := false
	for _, c := range d.Caveats {
		if strings.Contains(c, "routes were not compared") {
			found = true
		}
	}
	if !found {
		t.Fatalf("caveats = %v", d.Caveats)
	}
	for _, e := range d.ElementsAdded {
		if e.Kind == KindRoute {
			t.Errorf("route %s reported as new against a model that recorded none", e.ID)
		}
	}
}

func TestCompareNotesDifferentScopes(t *testing.T) {
	scoped := fixture()
	scoped.Report.Meta.Scope = &report.ScanScope{Scanned: []string{"ai"}, NotScanned: []string{"iac"}}
	d := Compare(Build(fixture()), Build(scoped))
	if len(d.Caveats) == 0 || !strings.Contains(strings.Join(d.Caveats, " "), "different scopes") {
		t.Errorf("caveats = %v", d.Caveats)
	}
}

func TestPreviousRoundTripsThroughModelJSON(t *testing.T) {
	prev := Build(before())
	dir := t.TempDir()
	path := filepath.Join(dir, "model.json")
	if err := os.WriteFile(path, mustJSON(prev), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrevious(path)
	if err != nil {
		t.Fatal(err)
	}
	cur := Build(fixture())
	if a, b := Compare(prev, cur), Compare(loaded, cur); len(a.BoundariesAdded) != len(b.BoundariesAdded) || len(a.CellsChanged) != len(b.CellsChanged) {
		t.Errorf("a model read back from disk compares differently:\n%+v\n%+v", a, b)
	}
	withChanges := cur.WithChanges(loaded)
	if withChanges.Changes == nil || withChanges.Changes.Empty() {
		t.Error("WithChanges must record the delta")
	}
}

func TestLoadPreviousRefusesAnythingThatIsNotAModel(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"findings.json": `{"meta":{"tool_name":"nox"},"findings":[]}`,
		"junk.json":     `not json`,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrevious(p); err == nil {
			t.Errorf("%s was accepted as a previous model", name)
		}
	}
	if _, err := LoadPrevious(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing previous model must be an error, never an empty model")
	}
}
