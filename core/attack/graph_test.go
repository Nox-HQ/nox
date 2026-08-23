package attack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
)

// realisticInventory is a support agent that can read files, reach the network,
// and ask a human for approval — the shape the agent-lattice analyzer flags.
func realisticInventory() *ai.Inventory {
	inv := ai.NewInventory()
	inv.Components = []ai.Component{
		{Name: "support-agent", Type: "agent", Path: "agents/support.py"},
	}
	inv.ToolMatrix = []ai.ToolPermissionSet{
		{
			Agent: "support-agent",
			Path:  "agents/support.py",
			Tools: []string{"read_file", "http_post", "request_approval"},
			Capabilities: map[string][]string{
				"read_file":        {string(ai.CapFileRead)},
				"http_post":        {string(ai.CapHTTPRequest)},
				"request_approval": {string(ai.CapHumanApproval)},
			},
		},
	}
	inv.ModelProvenance = []ai.ModelReference{
		{Name: "gpt-4o", Path: "agents/support.py", AuthEnvVar: "OPENAI_API_KEY"},
	}
	return inv
}

func realisticFinding() findings.Finding {
	return findings.Finding{
		RuleID:      "AGENTFLOW-001",
		Fingerprint: "fp-inj-1",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceHigh,
		Location:    findings.Location{FilePath: "agents/support.py", StartLine: 42},
		Message:     "untrusted input reaches an LLM prompt",
		Metadata:    map[string]string{"function": "chat", "route": "/chat"},
	}
}

func nodeByID(t *testing.T, g *AttackGraph, id string) AttackNode {
	t.Helper()
	for _, n := range g.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("node %q not in graph; have %v", id, nodeIDs(g))
	return AttackNode{}
}

func nodeIDs(g *AttackGraph) []string {
	out := make([]string, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n.ID)
	}
	return out
}

func hasEdge(g *AttackGraph, from string, kind EdgeKind, to string) bool {
	want := edgeID(from, kind, to)
	for _, e := range g.Edges {
		if e.ID == want {
			return true
		}
	}
	return false
}

func TestBuildGraphNodesAndEdgeKinds(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())

	if errs := g.Validate(); len(errs) != 0 {
		t.Fatalf("graph is not structurally valid: %v", errs)
	}

	const (
		entry  = "entry:agents/support.py:42"
		model  = "model:agents/support.py:42"
		agent  = "agent:support-agent"
		readT  = "tool:agent:support-agent:read_file"
		postT  = "tool:agent:support-agent:http_post"
		apprvT = "tool:agent:support-agent:request_approval"
		fsRes  = "res:filesystem:agent:support-agent"
		sink   = "sink:http:agent:support-agent"
		authz  = "authz:agent:support-agent"
	)

	nodeCases := []struct {
		id         string
		kind       NodeKind
		sensitive  bool
		privileged bool
	}{
		{entry, NodeEntryPoint, false, false},
		{model, NodeModel, false, false},
		{"asset:system-prompt", NodeAsset, true, false},
		{agent, NodeAgent, false, false},
		{readT, NodeTool, false, false},
		{postT, NodeTool, false, false},
		{apprvT, NodeTool, false, false},
		{fsRes, NodeResource, true, false},
		{sink, NodeNetworkSink, false, true},
		{authz, NodeAuthzBoundary, false, false},
		{"model:gpt-4o", NodeModel, false, false},
		{"identity:OPENAI_API_KEY", NodeIdentity, true, false},
	}
	for _, tc := range nodeCases {
		n := nodeByID(t, g, tc.id)
		if n.Kind != tc.kind {
			t.Errorf("node %s: kind = %q, want %q", tc.id, n.Kind, tc.kind)
		}
		if n.Sensitive != tc.sensitive {
			t.Errorf("node %s: sensitive = %v, want %v", tc.id, n.Sensitive, tc.sensitive)
		}
		if n.Privileged != tc.privileged {
			t.Errorf("node %s: privileged = %v, want %v", tc.id, n.Privileged, tc.privileged)
		}
		if len(n.Evidence) == 0 {
			t.Errorf("node %s has no grounding evidence", tc.id)
		}
	}

	edgeCases := []struct {
		from string
		kind EdgeKind
		to   string
		why  string
	}{
		{entry, EdgeDataFlow, model, "untrusted input flows into the prompt call"},
		{model, EdgeReaches, "asset:system-prompt", "the prompt call holds the system instruction"},
		{model, EdgeDataFlow, agent, "prompt call and agent share a file"},
		{agent, EdgeInvokes, readT, "agent may invoke its tool"},
		{agent, EdgeInvokes, postT, "agent may invoke its tool"},
		{readT, EdgeReaches, fsRes, "a file_read tool reads the filesystem"},
		{postT, EdgeDataFlow, sink, "an http tool writes to the network"},
		{fsRes, EdgeDataFlow, postT, "read content is available to the egress tool in the same set"},
		{authz, EdgeAuthorizes, postT, "the approval gate governs the privileged tool"},
		{"identity:OPENAI_API_KEY", EdgeAuthorizes, "model:gpt-4o", "the credential authorizes model calls"},
	}
	for _, tc := range edgeCases {
		if !hasEdge(g, tc.from, tc.kind, tc.to) {
			t.Errorf("missing %s edge %s -> %s (%s)", tc.kind, tc.from, tc.to, tc.why)
		}
	}

	// Invocation and delegation must not have collapsed into one kind.
	if hasEdge(g, agent, EdgeDelegates, readT) {
		t.Error("a tool grant was recorded as a delegation")
	}
}

func TestBuildGraphEmptyInputsAreValidNotPanicking(t *testing.T) {
	cases := []struct {
		name string
		ff   []findings.Finding
		inv  *ai.Inventory
	}{
		{"both nil", nil, nil},
		{"empty inventory", nil, ai.NewInventory()},
		{"findings only, none injection", []findings.Finding{{RuleID: "SEC-999", Fingerprint: "fp"}}, nil},
		{"inventory with empty matrix", nil, &ai.Inventory{ToolMatrix: []ai.ToolPermissionSet{{}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := BuildGraph(tc.ff, tc.inv)
			if g == nil {
				t.Fatal("BuildGraph returned nil")
			}
			if len(g.Nodes) != 0 || len(g.Edges) != 0 {
				t.Fatalf("expected an empty graph, got %d nodes / %d edges", len(g.Nodes), len(g.Edges))
			}
			if errs := g.Validate(); len(errs) != 0 {
				t.Errorf("empty graph must validate, got %v", errs)
			}
			if paths := g.Paths(0); len(paths) != 0 {
				t.Errorf("expected no paths, got %d", len(paths))
			}
			if g.Truncation != nil {
				t.Errorf("an exhaustive enumeration must not report truncation: %+v", g.Truncation)
			}
			if cuts := g.CutEdges(nil); cuts != nil {
				t.Errorf("expected no cut edges, got %v", cuts)
			}
		})
	}
}

func TestPathsReachSensitiveAndPrivilegedTerminals(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())
	paths := g.Paths(0)
	if len(paths) == 0 {
		t.Fatal("expected attack paths from the entry point")
	}
	if g.Truncation != nil {
		t.Fatalf("this graph is small enough to enumerate exhaustively, got %+v", g.Truncation)
	}

	terminals := map[string]bool{}
	for _, p := range paths {
		if p.EntryID != "entry:agents/support.py:42" {
			t.Errorf("path %s starts at %q, not the entry point", p.ID, p.EntryID)
		}
		if len(p.Edges) != len(p.Nodes)-1 {
			t.Errorf("path %s: %d edges for %d nodes", p.ID, len(p.Edges), len(p.Nodes))
		}
		if len(p.Steps) != len(p.Nodes) {
			t.Errorf("path %s: %d steps for %d nodes", p.ID, len(p.Steps), len(p.Nodes))
		}
		terminals[p.TerminalID] = true
	}
	for _, want := range []string{
		"asset:system-prompt",
		"res:filesystem:agent:support-agent",
		"sink:http:agent:support-agent",
	} {
		if !terminals[want] {
			t.Errorf("no path terminates at %q; terminals were %v", want, terminals)
		}
	}

	// The approval gate is a control, not a route: authorizes edges must never
	// appear inside a path.
	for _, p := range paths {
		for _, id := range p.Edges {
			if strings.Contains(id, "-["+string(EdgeAuthorizes)+"]->") {
				t.Errorf("path %s traverses an authorization edge %q", p.ID, id)
			}
		}
	}
}

func TestPathsToTerminatesAtNamedNode(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())
	paths := g.PathsTo("asset:system-prompt", 0)
	if len(paths) == 0 {
		t.Fatal("expected at least one path to the system prompt")
	}
	for _, p := range paths {
		if p.TerminalID != "asset:system-prompt" {
			t.Errorf("path %s terminates at %q", p.ID, p.TerminalID)
		}
	}
	if got := g.PathsTo("node:does-not-exist", 0); len(got) != 0 {
		t.Errorf("expected no paths to an unknown node, got %d", len(got))
	}
}

// TestNoNetworkCapabilityYieldsNoExfilPath proves absence of a path is a real
// result. The agent can read the filesystem, so the disclosure path exists; it
// cannot reach the network, so no exfiltration path does.
func TestNoNetworkCapabilityYieldsNoExfilPath(t *testing.T) {
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{
		{
			Agent:        "reader-agent",
			Path:         "agents/reader.py",
			Tools:        []string{"read_file"},
			Capabilities: map[string][]string{"read_file": {string(ai.CapFileRead)}},
		},
	}
	f := realisticFinding()
	f.Location.FilePath = "agents/reader.py"
	f.Fingerprint = "fp-reader"

	g := BuildGraph([]findings.Finding{f}, inv)
	paths := g.Paths(0)

	// The read path is present: this is a targeted absence, not an empty graph.
	var sawFilesystem bool
	for _, p := range paths {
		if p.TerminalID == "res:filesystem:agent:reader-agent" {
			sawFilesystem = true
		}
		if n := nodeByID(t, g, p.TerminalID); n.Kind == NodeNetworkSink {
			t.Errorf("path %s reaches a network sink the agent has no capability for", p.ID)
		}
	}
	if !sawFilesystem {
		t.Fatalf("expected a path to the readable filesystem; terminals were %v", paths)
	}
	for _, n := range g.Nodes {
		if n.Kind == NodeNetworkSink {
			t.Errorf("graph invented a network sink node %q for an agent with no egress capability", n.ID)
		}
	}
}

// TestDelegationCycleTerminates uses mutual delegation, which is common in real
// agent topologies and would hang a naive walk.
func TestDelegationCycleTerminates(t *testing.T) {
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{
		{Agent: "alpha", Path: "a.py", Tools: []string{"read_file"},
			Capabilities: map[string][]string{"read_file": {string(ai.CapFileRead)}}},
		{Agent: "beta", Path: "b.py", Tools: []string{"http_post"},
			Capabilities: map[string][]string{"http_post": {string(ai.CapHTTPRequest)}}},
		{Agent: "gamma", Path: "c.py", Tools: []string{"shell_exec"},
			Capabilities: map[string][]string{"shell_exec": {string(ai.CapShellExec)}}},
	}
	inv.ConnectionGraph = []ai.Connection{
		{From: "alpha", To: "beta", Type: "delegate"},
		{From: "beta", To: "gamma", Type: "delegate"},
		{From: "gamma", To: "alpha", Type: "delegate"}, // closes the cycle
		{From: "beta", To: "alpha", Type: "delegate"},  // and a two-node cycle
	}
	f := realisticFinding()
	f.Location.FilePath = "a.py"
	f.Fingerprint = "fp-cycle"

	g := BuildGraph([]findings.Finding{f}, inv)
	if !hasEdge(g, "agent:alpha", EdgeDelegates, "agent:beta") {
		t.Fatal("expected a delegation edge alpha -> beta")
	}

	done := make(chan []AttackPath, 1)
	go func() { done <- g.Paths(0) }()
	paths := <-done // a hang here fails the test by timing out the package run

	if len(paths) == 0 {
		t.Fatal("expected paths through the delegation cycle")
	}
	for _, p := range paths {
		seen := map[string]bool{}
		for _, id := range p.Nodes {
			if seen[id] {
				t.Fatalf("path %s revisits node %q: cycle guard failed", p.ID, id)
			}
			seen[id] = true
		}
	}
	// Reaching gamma's shell requires traversing the delegation chain.
	var sawShell bool
	for _, p := range paths {
		if p.TerminalID == "asset:shell:agent:gamma" {
			sawShell = true
		}
	}
	if !sawShell {
		t.Error("expected the delegation chain to reach gamma's shell capability")
	}
}

func TestDepthCapIsEnforcedAndReported(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())

	full := g.Paths(0)
	shallow := g.Paths(2)

	if len(shallow) >= len(full) {
		t.Fatalf("a 2-hop budget must return fewer paths than the full enumeration (%d vs %d)", len(shallow), len(full))
	}
	for _, p := range shallow {
		if len(p.Edges) > 2 {
			t.Errorf("path %s has %d hops, over the depth limit", p.ID, len(p.Edges))
		}
	}
	if g.Truncation == nil {
		t.Fatal("a depth-capped enumeration must report truncation")
	}
	if !g.Truncation.DepthCapped {
		t.Error("Truncation.DepthCapped must be set when branches are abandoned at the limit")
	}
	if g.Truncation.DepthLimit != 2 {
		t.Errorf("DepthLimit = %d, want 2", g.Truncation.DepthLimit)
	}
	if g.Truncation.Reason == "" {
		t.Error("truncation must carry a human-readable reason")
	}

	// Re-running exhaustively must clear the stale truncation record, or a
	// complete result would keep claiming it was capped.
	g.Paths(0)
	if g.Truncation != nil {
		t.Errorf("exhaustive re-run must clear truncation, got %+v", g.Truncation)
	}
}

func TestPathCapIsEnforcedAndReported(t *testing.T) {
	// 20 read tools x 20 egress tools chained through one shared filesystem
	// node yields 400+ simple paths, comfortably over MaxEnumeratedPaths.
	set := ai.ToolPermissionSet{Agent: "fanout-agent", Path: "agents/fanout.py", Capabilities: map[string][]string{}}
	for i := 0; i < 20; i++ {
		r := fmt.Sprintf("read_file_%02d", i)
		w := fmt.Sprintf("http_post_%02d", i)
		set.Tools = append(set.Tools, r, w)
		set.Capabilities[r] = []string{string(ai.CapFileRead)}
		set.Capabilities[w] = []string{string(ai.CapHTTPRequest)}
	}
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{set}

	f := realisticFinding()
	f.Location.FilePath = "agents/fanout.py"
	f.Fingerprint = "fp-fanout"

	g := BuildGraph([]findings.Finding{f}, inv)
	paths := g.Paths(0)

	if len(paths) != MaxEnumeratedPaths {
		t.Fatalf("expected enumeration to stop at the %d-path budget, got %d", MaxEnumeratedPaths, len(paths))
	}
	if g.Truncation == nil || !g.Truncation.PathCapped {
		t.Fatalf("a path-capped enumeration must report truncation, got %+v", g.Truncation)
	}
	if g.Truncation.PathLimit != MaxEnumeratedPaths {
		t.Errorf("PathLimit = %d, want %d", g.Truncation.PathLimit, MaxEnumeratedPaths)
	}
	if !strings.Contains(g.Truncation.Reason, "not enumerated") && !strings.Contains(g.Truncation.Reason, "subset") {
		t.Errorf("truncation reason must say the result is incomplete: %q", g.Truncation.Reason)
	}
}

// TestCutEdgesIdentifiesTheHighestValueCut verifies the claim by brute force:
// remove each edge, re-enumerate, and confirm the reported top cut really does
// break the most paths.
func TestCutEdgesIdentifiesTheHighestValueCut(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())
	paths := g.Paths(0)
	cuts := g.CutEdges(paths)
	if len(cuts) == 0 {
		t.Fatal("expected cut edges for a graph with attack paths")
	}
	top := cuts[0]
	if top.Action == "" {
		t.Error("a cut edge must carry an operator action")
	}

	bestActual := 0
	for _, e := range g.Edges {
		reduced := g.RemoveEdge(e.ID)
		broke := len(paths) - len(reduced.Paths(0))
		if broke > bestActual {
			bestActual = broke
		}
	}
	if bestActual == 0 {
		t.Fatal("no edge removal changed reachability; the fixture is degenerate")
	}

	reduced := g.RemoveEdge(top.EdgeID)
	actual := len(paths) - len(reduced.Paths(0))
	if actual != top.PathsBroken {
		t.Errorf("cut %q claims to break %d paths, actually breaks %d", top.EdgeID, top.PathsBroken, actual)
	}
	if actual != bestActual {
		t.Errorf("cut %q breaks %d paths but some edge breaks %d", top.EdgeID, actual, bestActual)
	}
	for i := 1; i < len(cuts); i++ {
		if cuts[i].PathsBroken > cuts[i-1].PathsBroken {
			t.Fatalf("cuts are not ordered best-first at index %d", i)
		}
	}
}

func TestCutEdgeActionNamesTheGrant(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())
	cuts := g.CutEdges(g.Paths(0))

	var action string
	for _, c := range cuts {
		if c.EdgeID == edgeID("agent:support-agent", EdgeInvokes, "tool:agent:support-agent:read_file") {
			action = c.Action
		}
	}
	if action == "" {
		t.Fatalf("expected a cut for the agent's read_file grant; got %d cuts", len(cuts))
	}
	for _, want := range []string{"support-agent", string(ai.CapFileRead), "read_file"} {
		if !strings.Contains(action, want) {
			t.Errorf("action %q does not name %q", action, want)
		}
	}
}

func TestBuildGraphDeterministic(t *testing.T) {
	inv := realisticInventory()
	// A second agent and a shuffled connection list exercise the sort paths.
	inv.ToolMatrix = append(inv.ToolMatrix, ai.ToolPermissionSet{
		Agent: "billing-agent", Server: "payments-mcp", Path: "agents/billing.py",
		Tools:        []string{"charge_card", "db_read"},
		Capabilities: map[string][]string{"charge_card": {string(ai.CapPaymentInitiate)}, "db_read": {string(ai.CapDatabaseRead)}},
	})
	inv.ConnectionGraph = []ai.Connection{
		{From: "support-agent", To: "billing-agent", Type: "delegate"},
		{From: "billing-agent", To: "gpt-4o", Type: "model_call"},
	}
	ff := []findings.Finding{realisticFinding()}

	marshal := func() []byte {
		g := BuildGraph(ff, inv)
		g.Cuts = g.CutEdges(g.Paths(0))
		b, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first, second := marshal(), marshal()
	if !bytes.Equal(first, second) {
		t.Fatalf("BuildGraph is not byte-identical on repeat:\n%s\n%s", first, second)
	}

	// Input order must not matter either.
	shuffled := ai.NewInventory()
	shuffled.SchemaVersion = inv.SchemaVersion
	shuffled.Components = inv.Components
	shuffled.ModelProvenance = inv.ModelProvenance
	shuffled.ToolMatrix = []ai.ToolPermissionSet{inv.ToolMatrix[1], inv.ToolMatrix[0]}
	shuffled.ConnectionGraph = []ai.Connection{inv.ConnectionGraph[1], inv.ConnectionGraph[0]}
	g := BuildGraph(ff, shuffled)
	g.Cuts = g.CutEdges(g.Paths(0))
	reordered, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reordered) {
		t.Errorf("BuildGraph output depends on input order:\n%s\n%s", first, reordered)
	}
}

func TestBuildPlanAttachesGraphAndDerivesPaths(t *testing.T) {
	plan, err := BuildPlan(PlanInput{
		Root:      "/repo",
		Findings:  []findings.Finding{realisticFinding()},
		Inventory: realisticInventory(),
		Now:       "2026-08-23T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Graph == nil {
		t.Fatal("plan carries no attack graph")
	}
	if errs := plan.Graph.Validate(); len(errs) != 0 {
		t.Fatalf("plan graph is invalid: %v", errs)
	}
	if len(plan.Graph.Cuts) == 0 {
		t.Error("plan graph carries no cut edges")
	}

	byScenario := map[string]Hypothesis{}
	for _, h := range plan.Hypotheses {
		byScenario[h.ScenarioID] = h
	}

	// The injection hypotheses have a real route: entry -> model -> system prompt.
	pi, ok := byScenario[ScenarioPIDirect]
	if !ok {
		t.Fatal("expected a PI-DIRECT hypothesis")
	}
	if !strings.Contains(pi.Rationale, "real route") {
		t.Errorf("PI-DIRECT rationale does not claim a graph route: %q", pi.Rationale)
	}
	if len(pi.Path) == 0 || pi.Path[0].ID != "entry:agents/support.py:42" {
		t.Errorf("PI-DIRECT path is not the graph path: %+v", pi.Path)
	}
	if last := pi.Path[len(pi.Path)-1]; last.ID != "asset:system-prompt" {
		t.Errorf("PI-DIRECT path ends at %q, want the system prompt", last.ID)
	}

	// The exfiltration hypothesis has a real route through the tool chain.
	ex, ok := byScenario[ScenarioExfilFSNet]
	if !ok {
		t.Fatal("expected an EXFIL-FS-NET hypothesis")
	}
	if last := ex.Path[len(ex.Path)-1]; last.Kind != StepSink {
		t.Errorf("EXFIL path ends at %+v, want a sink step", last)
	}
	if !strings.Contains(ex.Rationale, "real route") {
		t.Errorf("EXFIL rationale does not claim a graph route: %q", ex.Rationale)
	}
}

// TestBuildPlanSaysSoWhenNoGraphPathExists is the honesty case: with no entry
// point the tool hypothesis keeps its generic shape and admits it.
func TestBuildPlanSaysSoWhenNoGraphPathExists(t *testing.T) {
	inv := ai.NewInventory()
	inv.ToolMatrix = []ai.ToolPermissionSet{{
		Agent: "orphan-agent", Path: "agents/orphan.py",
		Tools:        []string{"shell_exec"},
		Capabilities: map[string][]string{"shell_exec": {string(ai.CapShellExec)}},
	}}
	plan, err := BuildPlan(PlanInput{Inventory: inv, Now: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("expected a TOOL-UNAUTH hypothesis")
	}
	for _, h := range plan.Hypotheses {
		if !strings.Contains(h.Rationale, "No end-to-end path") {
			t.Errorf("hypothesis %s does not disclose the missing graph path: %q", h.ID, h.Rationale)
		}
		if len(h.Path) == 0 {
			t.Errorf("hypothesis %s lost its fallback path", h.ID)
		}
	}
}

func TestAttackGraphProjectsOntoCoreGraph(t *testing.T) {
	g := BuildGraph([]findings.Finding{realisticFinding()}, realisticInventory())
	generic := g.ToGraph()
	if len(generic.Nodes) != len(g.Nodes) || len(generic.Edges) != len(g.Edges) {
		t.Fatalf("projection lost structure: %d/%d nodes, %d/%d edges",
			len(generic.Nodes), len(g.Nodes), len(generic.Edges), len(g.Edges))
	}
	if errs := generic.Validate(); len(errs) != 0 {
		t.Errorf("projected graph is invalid: %v", errs)
	}
	for _, n := range generic.Nodes {
		if n.Kind == "" {
			t.Errorf("node %q lost its kind in projection", n.ID)
		}
	}
}

func TestCapabilityTagsPreferRecordedTags(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		recorded []string
		want     []ai.CapabilityTag
	}{
		{"recorded wins over the name", "harmless_helper", []string{string(ai.CapShellExec)}, []ai.CapabilityTag{ai.CapShellExec}},
		{"name fallback: read", "read_file", nil, []ai.CapabilityTag{ai.CapFileRead}},
		{"name fallback: http", "http_fetch", nil, []ai.CapabilityTag{ai.CapHTTPRequest}},
		{"name fallback: shell", "shell_exec", nil, []ai.CapabilityTag{ai.CapShellExec}},
		{"approval is not an http request", "request_approval", nil, []ai.CapabilityTag{ai.CapHumanApproval}},
		{"unknown stays unclassified", "do_a_thing", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capabilityTags(tc.tool, tc.recorded)
			if len(got) != len(tc.want) {
				t.Fatalf("capabilityTags(%q) = %v, want %v", tc.tool, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("capabilityTags(%q)[%d] = %q, want %q", tc.tool, i, got[i], tc.want[i])
				}
			}
		})
	}
}
