package change

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func vuln(file, pkg, version, id, aliases string, sev findings.Severity) findings.Finding {
	return findings.Finding{
		RuleID:   "VULN-001",
		Severity: sev,
		Location: findings.Location{FilePath: file, StartLine: 1},
		// The message carries the version, as the real one does, so a
		// fingerprint over it would change when the package is upgraded.
		Message:     "Known vulnerability " + id + " in " + pkg + "@" + version,
		Fingerprint: "fp-" + id + "-" + version,
		Metadata: map[string]string{
			"ecosystem": "npm", "package": pkg, "version": version, "vuln_id": id, "aliases": aliases,
		},
	}
}

func plain(rule, file string, line int, msg string, sev findings.Severity) findings.Finding {
	return findings.Finding{RuleID: rule, Severity: sev, Location: findings.Location{FilePath: file, StartLine: line}, Message: msg}
}

func st(label string, ff ...findings.Finding) State {
	return State{Label: label, Findings: ff, LeadsRecorded: true}
}

func TestDependencyAdvisoriesIgnoreTheVersionInTheMessage(t *testing.T) {
	// Upgrading a package that is still affected by the same advisory is the
	// same advisory: not resolved, not new.
	prev := st("main", vuln("package-lock.json", "lodash", "4.17.0", "GHSA-1", "CVE-1", findings.SeverityHigh))
	cur := st("HEAD", vuln("package-lock.json", "lodash", "4.17.10", "GHSA-1", "CVE-1", findings.SeverityHigh))
	d := Compare(prev, cur)
	if len(d.New) != 0 || len(d.Resolved) != 0 {
		t.Fatalf("upgrade within the vulnerable range read as new=%v resolved=%v, want neither", d.New, d.Resolved)
	}
}

func TestDependencyAdvisoryMatchesThroughAnAlias(t *testing.T) {
	prev := st("main", vuln("package-lock.json", "axios", "1.0.0", "GHSA-1", "CVE-9", findings.SeverityHigh))
	cur := st("HEAD", vuln("package-lock.json", "axios", "1.0.0", "CVE-9", "GHSA-1", findings.SeverityHigh))
	d := Compare(prev, cur)
	if len(d.New) != 0 || len(d.Resolved) != 0 {
		t.Fatalf("the same advisory under its alias read as new=%v resolved=%v", d.New, d.Resolved)
	}
}

func TestUpgradeThatClearsOneAdvisoryButNotAnother(t *testing.T) {
	prev := st("main",
		vuln("package-lock.json", "lodash", "4.17.0", "GHSA-1", "", findings.SeverityHigh),
		vuln("package-lock.json", "lodash", "4.17.0", "GHSA-2", "", findings.SeverityHigh))
	cur := st("HEAD", vuln("package-lock.json", "lodash", "4.17.5", "GHSA-2", "", findings.SeverityHigh))
	d := Compare(prev, cur)
	if len(d.Resolved) != 1 || d.Resolved[0].Advisory != "GHSA-1" {
		t.Fatalf("resolved = %v, want only GHSA-1", d.Resolved)
	}
	if len(d.New) != 0 {
		t.Fatalf("new = %v, want none", d.New)
	}
}

func TestNewAdvisoryOnANewPackageIsNewAndOldOnesAreNot(t *testing.T) {
	var old []findings.Finding
	for _, id := range []string{"GHSA-a", "GHSA-b", "GHSA-c"} {
		old = append(old, vuln("package-lock.json", "axios", "1.7.4", id, "", findings.SeverityMedium))
	}
	prev := st("main", old...)
	cur := st("HEAD", append(append([]findings.Finding{}, old...),
		vuln("package-lock.json", "jsonwebtoken", "8.5.1", "GHSA-j1", "", findings.SeverityHigh),
		vuln("package-lock.json", "jsonwebtoken", "8.5.1", "GHSA-j2", "", findings.SeverityHigh))...)
	d := Compare(prev, cur)
	if len(d.New) != 2 {
		t.Fatalf("new = %d, want 2 (only jsonwebtoken)", len(d.New))
	}
	for _, it := range d.New {
		if it.Package != "jsonwebtoken" {
			t.Errorf("pre-existing %s advisory listed as new", it.Package)
		}
	}
	txt := Text(d, 0)
	if !strings.Contains(txt, "2 advisories for jsonwebtoken@8.5.1") || strings.Contains(txt, "axios") {
		t.Errorf("rendering should name jsonwebtoken only:\n%s", txt)
	}
}

func TestSameAdvisoryInTwoManifestsIsTwoThings(t *testing.T) {
	prev := st("main", vuln("a/package-lock.json", "x", "1", "GHSA-1", "", findings.SeverityLow))
	cur := st("HEAD",
		vuln("a/package-lock.json", "x", "1", "GHSA-1", "", findings.SeverityLow),
		vuln("b/package-lock.json", "x", "1", "GHSA-1", "", findings.SeverityLow))
	d := Compare(prev, cur)
	if len(d.New) != 1 || d.New[0].File != "b/package-lock.json" {
		t.Fatalf("new = %v, want the b/ manifest", d.New)
	}
}

func TestLineMoveIsNeitherNewNorResolved(t *testing.T) {
	// Even with the line-bearing V1 fingerprint pinned on both sides.
	a := plain("SEC-1", "src/a.js", 10, "hardcoded secret", findings.SeverityHigh)
	a.Fingerprint = findings.ComputeFingerprintWith(a.RuleID, a.Location, a.Message, findings.FingerprintV1)
	b := a
	b.Location.StartLine = 14
	b.Fingerprint = findings.ComputeFingerprintWith(b.RuleID, b.Location, b.Message, findings.FingerprintV1)
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("test premise: V1 fingerprints should differ across a line move")
	}
	d := Compare(st("main", a), st("HEAD", b))
	if !d.Empty() {
		t.Fatalf("a pure line move changed the delta: new=%v resolved=%v", d.New, d.Resolved)
	}
}

func TestNewAndResolvedFindings(t *testing.T) {
	gone := plain("SEC-1", "src/a.js", 3, "old problem", findings.SeverityHigh)
	stays := plain("SEC-2", "src/b.js", 3, "stays", findings.SeverityLow)
	fresh := plain("IAC-9", "main.tf", 7, "open ingress", findings.SeverityCritical)
	d := Compare(st("A", gone, stays), st("B", stays, fresh))
	if len(d.New) != 1 || d.New[0].RuleID != "IAC-9" {
		t.Errorf("new = %v", d.New)
	}
	if len(d.Resolved) != 1 || d.Resolved[0].RuleID != "SEC-1" {
		t.Errorf("resolved = %v", d.Resolved)
	}
	if d.Regressions() != 1 {
		t.Errorf("regressions = %d, want 1", d.Regressions())
	}
}

func TestRepeatedFindingCountsAreExact(t *testing.T) {
	one := plain("SEC-1", "a.js", 1, "same message", findings.SeverityHigh)
	two := plain("SEC-1", "a.js", 9, "same message", findings.SeverityHigh)
	d := Compare(st("m", one), st("h", one, two))
	if len(d.New) != 1 {
		t.Fatalf("a second occurrence of one fingerprint must read as one new finding, got %d", len(d.New))
	}
	d = Compare(st("m", one, two), st("h", one))
	if len(d.Resolved) != 1 {
		t.Fatalf("losing one of two occurrences must read as one resolved, got %d", len(d.Resolved))
	}
}

func TestWaivedIsNotResolved(t *testing.T) {
	f := plain("SEC-1", "a.js", 1, "m", findings.SeverityHigh)
	w := f
	w.Status = findings.StatusBaselined
	d := Compare(st("m", f), st("h", w))
	if len(d.Resolved) != 0 || len(d.Waived) != 1 {
		t.Fatalf("a baselined finding read as resolved=%v waived=%v", d.Resolved, d.Waived)
	}
}

func TestWaivedBeforeAndStillWaivedIsSilent(t *testing.T) {
	f := plain("SEC-1", "a.js", 1, "m", findings.SeverityHigh)
	f.Status = findings.StatusBaselined
	if d := Compare(st("m", f), st("h", f)); !d.Empty() {
		t.Fatalf("delta = %+v, want empty", d)
	}
}

func TestSeverityChange(t *testing.T) {
	lo := plain("SEC-1", "a.js", 1, "m", findings.SeverityLow)
	hi := lo
	hi.Severity = findings.SeverityCritical
	d := Compare(st("m", lo), st("h", hi))
	if len(d.SeverityChanged) != 1 || !d.SeverityChanged[0].Regression {
		t.Fatalf("severity changes = %+v", d.SeverityChanged)
	}
	d = Compare(st("m", hi), st("h", lo))
	if len(d.SeverityChanged) != 1 || d.SeverityChanged[0].Regression {
		t.Fatalf("a drop must not be a regression: %+v", d.SeverityChanged)
	}
	if d.Regressions() != 0 {
		t.Errorf("regressions = %d, want 0", d.Regressions())
	}
}

func lead(route, file string, line int) report.Lead {
	return report.Lead{Category: "authorization", RuleID: "AUTHZ-001", Route: route, FilePath: file, Line: line, Statement: "s", Test: "t"}
}

func TestLeadsByRouteAndFile(t *testing.T) {
	prev := State{Label: "m", LeadsRecorded: true, Leads: []report.Lead{lead("GET /invoices/:id", "r/i.js", 4), lead("GET /gone", "r/g.js", 2)}}
	cur := State{Label: "h", LeadsRecorded: true, Leads: []report.Lead{lead("GET /invoices/:id", "r/i.js", 40), lead("GET /customers/:id", "r/c.js", 9)}}
	d := Compare(prev, cur)
	if len(d.NewLeads) != 1 || d.NewLeads[0].Route != "GET /customers/:id" {
		t.Errorf("new leads = %v (the invoices lead only moved lines)", d.NewLeads)
	}
	if len(d.ResolvedLeads) != 1 || d.ResolvedLeads[0].Route != "GET /gone" {
		t.Errorf("resolved leads = %v", d.ResolvedLeads)
	}
}

func TestLeadsAreNotComparedWhenTheEarlierRunDidNotRecordThem(t *testing.T) {
	prev := State{Label: "m", LeadsRecorded: false}
	cur := State{Label: "h", LeadsRecorded: true, Leads: []report.Lead{lead("GET /x", "x.js", 1)}}
	d := Compare(prev, cur)
	if len(d.NewLeads) != 0 {
		t.Fatalf("leads reported as new against a run that never recorded any: %v", d.NewLeads)
	}
	if len(d.Caveats) == 0 {
		t.Fatal("an uncomparable lead set must be stated, not silently dropped")
	}
}

func inv(sets ...ai.ToolPermissionSet) *ai.Inventory {
	i := ai.NewInventory()
	i.Checks = []string{"agents"}
	i.ToolMatrix = sets
	return i
}

func set(agent string, tools map[string][]string) ai.ToolPermissionSet {
	s := ai.ToolPermissionSet{Agent: agent, Path: agent, Capabilities: map[string][]string{}}
	for _, t := range []string{"a_tool", "run_shell", "send_email", "query_db"} {
		if caps, ok := tools[t]; ok {
			s.Tools = append(s.Tools, t)
			if len(caps) > 0 {
				s.Capabilities[t] = caps
			}
		}
	}
	return s
}

func TestAgentGainedCapabilities(t *testing.T) {
	prev := State{Label: "m", Inventory: inv(set("assistant.js", map[string][]string{"query_db": nil}))}
	cur := State{Label: "h", Inventory: inv(set("assistant.js", map[string][]string{
		"query_db": nil, "run_shell": {"shell_exec"}, "send_email": {"email_send"}}))}
	d := Compare(prev, cur)
	if len(d.Agents) != 1 {
		t.Fatalf("agents = %+v", d.Agents)
	}
	txt := Text(d, 0)
	for _, want := range []string{"Agent assistant.js", "gained", "shell_exec (tool run_shell)", "email_send (tool send_email)"} {
		if !strings.Contains(txt, want) {
			t.Errorf("rendering lacks %q:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "query_db") {
		t.Errorf("the tool the agent already had is listed as gained:\n%s", txt)
	}
}

func TestAgentGainedCapabilityOnAnExistingTool(t *testing.T) {
	prev := State{Inventory: inv(set("a", map[string][]string{"run_shell": {"file_read"}}))}
	cur := State{Inventory: inv(set("a", map[string][]string{"run_shell": {"file_read", "shell_exec"}}))}
	d := Compare(prev, cur)
	if len(d.Agents) != 1 || len(d.Agents[0].Gained) != 1 || d.Agents[0].Gained[0].Capabilities[0] != "shell_exec" {
		t.Fatalf("agents = %+v", d.Agents)
	}
}

func TestAgentLostAndRemoved(t *testing.T) {
	prev := State{Inventory: inv(
		set("a", map[string][]string{"run_shell": {"shell_exec"}, "query_db": nil}),
		set("b", map[string][]string{"send_email": {"email_send"}}))}
	cur := State{Inventory: inv(set("a", map[string][]string{"query_db": nil}))}
	d := Compare(prev, cur)
	if len(d.Agents) != 2 {
		t.Fatalf("agents = %+v", d.Agents)
	}
	if len(d.Agents[0].Lost) != 1 || !d.Agents[1].Removed {
		t.Fatalf("agents = %+v", d.Agents)
	}
}

func TestNewComponent(t *testing.T) {
	p, c := inv(), inv()
	c.Add(ai.Component{Name: "mcp", Type: "mcp_runtime", Path: ".mcp.json"})
	d := Compare(State{Inventory: p}, State{Inventory: c})
	if len(d.ComponentsAdded) != 1 || d.ComponentsAdded[0].Type != "mcp_runtime" {
		t.Fatalf("components = %+v", d.ComponentsAdded)
	}
}

func TestInventoryThatNeverRanIsNotComparable(t *testing.T) {
	never := ai.NewInventory() // no Checks: the AI analyzer did not run
	cur := inv(set("a", map[string][]string{"run_shell": {"shell_exec"}}))
	d := Compare(State{Inventory: never}, State{Inventory: cur})
	if len(d.Agents) != 0 {
		t.Fatalf("an inventory that never looked must not make every agent new: %+v", d.Agents)
	}
	if len(d.Caveats) == 0 {
		t.Fatal("expected a caveat saying the AI inventory was not compared")
	}
}

func TestCaveatsForIncompleteAndScopedRuns(t *testing.T) {
	prev := State{Label: "m", Incomplete: []string{"OSV lookup failed"}, Scanned: []string{"secrets"}}
	cur := State{Label: "h"}
	d := Compare(prev, cur)
	if len(d.Caveats) != 2 {
		t.Fatalf("caveats = %v, want an incomplete-run and a scope-mismatch caveat", d.Caveats)
	}
}

func TestCompareIsDeterministic(t *testing.T) {
	var cur []findings.Finding
	for _, f := range []string{"z.js", "a.js", "m.js"} {
		cur = append(cur, plain("SEC-1", f, 1, "m", findings.SeverityHigh), plain("SEC-2", f, 2, "n", findings.SeverityHigh))
	}
	a := Text(Compare(st("m"), st("h", cur...)), 0)
	rev := make([]findings.Finding, len(cur))
	for i := range cur {
		rev[len(cur)-1-i] = cur[i]
	}
	b := Text(Compare(st("m"), st("h", rev...)), 0)
	if a != b {
		t.Fatalf("input order changed the output:\n%s\n---\n%s", a, b)
	}
}

func TestRenderEmptyAndLimit(t *testing.T) {
	if txt := Text(Compare(st("main"), st("HEAD")), 0); !strings.Contains(txt, "Since main:") || !strings.Contains(txt, "Nothing new") {
		t.Errorf("empty delta rendering:\n%s", txt)
	}
	var cur []findings.Finding
	for i := 0; i < 8; i++ {
		cur = append(cur, plain("SEC-1", "f"+string(rune('a'+i))+".js", 1, "m", findings.SeverityHigh))
	}
	txt := Text(Compare(st("m"), st("h", cur...)), 5)
	if !strings.Contains(txt, "...and 3 more") {
		t.Errorf("limit not applied:\n%s", txt)
	}
}
