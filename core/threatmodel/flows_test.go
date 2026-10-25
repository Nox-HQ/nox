package threatmodel

import (
	"strings"
	"testing"
)

func TestEveryRouteIsReachedByAnUntrustedCaller(t *testing.T) {
	m := build(t)
	flows := flowsOn(m, boundaryRequest)
	if len(flows) != 3 {
		t.Fatalf("got %d request flows, want one per route", len(flows))
	}
	for _, f := range flows {
		if f.From != "actor:caller" || len(f.Evidence) == 0 {
			t.Errorf("flow %+v must start at the caller and cite the registration", f)
		}
	}
	login := flowsOn(m, boundaryRequest)
	for _, f := range login {
		if f.To == "route:POST /login" && !strings.Contains(f.Label, "no authentication middleware visible") {
			t.Errorf("the flow to an unauthenticated route should say so: %q", f.Label)
		}
	}
}

func TestPublicDeploymentResourcesAreReachedFromTheInternet(t *testing.T) {
	m := build(t)
	for _, to := range []string{
		"deploy:ingress@deploy/k8s/ingress.yaml",
		"deploy:bucket@deploy/tf/main.tf",
		"deploy:database@deploy/tf/main.tf",
	} {
		if !hasFlow(m, "actor:internet", to, boundaryExposure) {
			t.Errorf("no exposure flow to %s", to)
		}
	}
	// IAC-037 is about encryption, not reachability.
	for _, f := range flowsOn(m, boundaryExposure) {
		for _, ev := range f.Evidence {
			if ev.RuleID == "IAC-037" {
				t.Errorf("a rule about encryption must not evidence exposure: %+v", f)
			}
		}
	}
}

// The prompt boundary comes from the attack graph's definition of "untrusted
// input reaches a prompt call", so the two documents cannot disagree, and the
// flow starts at the route the finding sits in.
func TestUntrustedInputReachesThePromptFromTheRouteItSitsIn(t *testing.T) {
	m := build(t)
	if !hasFlow(m, "route:POST /api/assistant/summarise", "model:gpt-4o@src/routes/assistant.js", boundaryPrompt) {
		t.Fatalf("no prompt flow; flows: %+v", m.Flows)
	}
	f := flowsOn(m, boundaryPrompt)[0]
	if f.Evidence[0].RuleID != "TAINT-AI-001" || f.Evidence[0].Ref != "src/routes/assistant.js:28" {
		t.Errorf("the flow must cite the finding: %+v", f.Evidence)
	}
	if !hasFlow(m, "model:gpt-4o@src/routes/assistant.js", "agent:src/routes/assistant.js", boundaryDispatch) {
		t.Error("model output must reach the agent registered in the same file")
	}
}

func TestModelOutputReachesTheEffectsOfTheAgentsTools(t *testing.T) {
	m := build(t)
	agent := "agent:src/routes/assistant.js"
	cases := map[string]string{
		"tool:shell":        "effect:shell",
		"tool:outbound":     "effect:outbound",
		"tool:unclassified": "effect:unclassified",
	}
	for boundary, to := range cases {
		if !hasFlow(m, agent, to, boundary) {
			t.Errorf("no flow %s -> %s on %s", agent, to, boundary)
		}
	}
	for _, b := range m.Boundaries {
		if b.ID == "tool:shell" && b.Label != "model output → shell" {
			t.Errorf("boundary label = %q", b.Label)
		}
	}
}

func TestAnUnclassifiedToolIsAFlowNotADrop(t *testing.T) {
	m := build(t)
	flows := flowsOn(m, "tool:unclassified")
	if len(flows) != 1 || !strings.Contains(flows[0].Label, "query_db") || !strings.Contains(flows[0].Label, "not classified") {
		t.Errorf("flows = %+v", flows)
	}
}

func TestMCPClientReachesItsServers(t *testing.T) {
	m := build(t)
	if !hasFlow(m, "mcp-client:.mcp.json", "mcp:shell@.mcp.json", boundaryMCP) {
		t.Errorf("no MCP flow: %+v", flowsOn(m, boundaryMCP))
	}
}

func TestApplicationReachesStoresServicesAndModelsItsPackagesAndReferencesNameOnly(t *testing.T) {
	m := build(t)
	for _, c := range []struct{ to, boundary string }{
		{"store:postgresql", boundaryDataAccess},
		{"service:stripe", boundaryService},
		{"model:gpt-4o@src/routes/assistant.js", boundaryModelCall},
	} {
		if !hasFlow(m, "app", c.to, c.boundary) {
			t.Errorf("no flow app -> %s", c.to)
		}
	}
	for _, f := range flowsOn(m, boundaryDataAccess) {
		if !strings.Contains(f.Label, "package") || strings.Contains(f.Label, "queries") {
			t.Errorf("a dependency shows the application can talk to a store, not that it does: %q", f.Label)
		}
	}
}

func TestTaintFindingsBecomeFlowsToTheirSinkEffects(t *testing.T) {
	m := build(t)
	if !hasFlow(m, "route:POST /api/assistant/summarise", "effect:shell", "taint:command_injection") {
		t.Errorf("no taint flow to the shell; flows: %+v", flowsOn(m, "taint:command_injection"))
	}
	var b Boundary
	for _, x := range m.Boundaries {
		if x.ID == "taint:command_injection" {
			b = x
		}
	}
	if b.Label != "untrusted input → shell command" {
		t.Errorf("boundary = %+v", b)
	}
}

// A boundary exists because a flow crosses it; none is listed on its own.
func TestEveryBoundaryHasAFlowAndEveryFlowHasEvidence(t *testing.T) {
	m := build(t)
	counts := map[string]int{}
	for _, f := range m.Flows {
		counts[f.Boundary]++
		if len(f.Evidence) == 0 {
			t.Errorf("flow %s has no evidence", f.ID)
		}
		els := map[string]bool{}
		for _, e := range m.Elements {
			els[e.ID] = true
		}
		if !els[f.From] || !els[f.To] {
			t.Errorf("flow %s joins an element that is not in the model", f.ID)
		}
	}
	for _, b := range m.Boundaries {
		if counts[b.ID] == 0 || counts[b.ID] != b.Flows {
			t.Errorf("boundary %s lists %d flows, has %d", b.ID, b.Flows, counts[b.ID])
		}
	}
	if len(m.Boundaries) != len(counts) {
		t.Errorf("%d boundaries for %d flow groups", len(m.Boundaries), len(counts))
	}
}

func TestEveryElementHasEvidence(t *testing.T) {
	for _, e := range build(t).Elements {
		if len(e.Evidence) == 0 {
			t.Errorf("element %s has no evidence", e.ID)
		}
	}
}

func TestMermaidIsDeterministicAndEscapesLabels(t *testing.T) {
	m := build(t)
	a, b := m.Mermaid(), m.Mermaid()
	if a != b {
		t.Fatal("diagram differs between calls")
	}
	if !strings.HasPrefix(a, "flowchart LR\n") || !strings.Contains(a, "-->|\"tool:shell\"|") {
		t.Errorf("diagram = %s", a)
	}
	if strings.Contains(a, "<") {
		t.Error("angle brackets must not reach a Mermaid label")
	}
}

// A tool the inventory tags sql_exec reaches the database effect, on its own
// boundary, and is not reported as unclassified.
func TestSQLExecToolReachesTheDatabaseEffect(t *testing.T) {
	in := fixture()
	in.Inventory.ToolMatrix[0].Capabilities["query_db"] = []string{"sql_exec"}
	m := Build(in)
	if !hasFlow(m, "agent:src/routes/assistant.js", "effect:database", "tool:database") {
		t.Fatalf("no database flow: %+v", m.Flows)
	}
	if len(flowsOn(m, "tool:unclassified")) != 0 {
		t.Error("a tagged tool must not be reported as unclassified")
	}
	for _, b := range m.Boundaries {
		if b.ID == "tool:database" && b.Label != "model output → database" {
			t.Errorf("label = %q", b.Label)
		}
	}
}

// IAC-504 (public access block disabled) is about the bucket, and IAC-502 (a
// literal secret in an environment variable) about the workload; both are
// attached by rule even in a file of several resources.
func TestNewInfrastructureRulesAttachToTheirResource(t *testing.T) {
	in := fixture()
	in.Report.Findings = append(in.Report.Findings,
		finding("IAC-504", "high", "deploy/tf/main.tf", 8, "Public access block disabled", "", map[string]string{"cwe": "CWE-284"}),
		finding("IAC-502", "high", "deploy/k8s/ingress.yaml", 9, "Literal secret in env", "", map[string]string{"cwe": "CWE-798"}))
	m := Build(in)
	if !strings.Contains(rules(cell(t, m, "deploy:bucket@deploy/tf/main.tf", ElevationOfPrivilege)), "IAC-504") {
		t.Error("IAC-504 must reach the bucket")
	}
	if strings.Contains(rules(cell(t, m, "deploy:database@deploy/tf/main.tf", ElevationOfPrivilege)), "IAC-504") {
		t.Error("IAC-504 must not reach the database")
	}
	if !hasElement(m, "deploy:workload@deploy/k8s/ingress.yaml") {
		t.Error("IAC-502 proves a workload exists")
	}
}
