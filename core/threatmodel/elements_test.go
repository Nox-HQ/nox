package threatmodel

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/report"
)

// Routes are elements with their authentication posture, named for what is
// visible and never for what is true.
func TestRoutesAreElementsWithTheirVisibleAuthentication(t *testing.T) {
	m := build(t)
	login := elementByID(t, m, "route:POST /login")
	if login.Attributes["authentication_middleware"] != "none visible" {
		t.Errorf("login = %v, want no authentication middleware visible", login.Attributes)
	}
	if login.Location != "src/server.js:6" || login.Zone != ZoneApplication {
		t.Errorf("login location/zone = %s/%s", login.Location, login.Zone)
	}
	inv := elementByID(t, m, "route:GET /api/invoices/:id")
	if inv.Attributes["authentication_middleware"] != "requireAuth" {
		t.Errorf("invoice route = %v, want requireAuth", inv.Attributes)
	}
	if inv.Attributes["authorization_lead"] != "yes" {
		t.Errorf("the ownership lead must mark the route it is about: %v", inv.Attributes)
	}
	if got := cell(t, m, login.ID, Spoofing); got.Status != LeadsToVerify {
		t.Errorf("a route with no visible authentication is a lead to verify, got %s", got.Status)
	}
	if got := cell(t, m, inv.ID, Spoofing); got.Status != LimitedEvidence {
		t.Errorf("visible authentication middleware is context, not support: got %s", got.Status)
	}
}

// A findings.json written before routes were recorded still names the routes
// its leads are about; the lead is evidence the route exists.
func TestLeadAloneEvidencesItsRoute(t *testing.T) {
	in := fixture()
	in.Report.Routes = nil
	m := Build(in)
	e := elementByID(t, m, "route:GET /api/invoices/:id")
	if e.Attributes["authentication_middleware"] != "not recorded" {
		t.Errorf("a route known only from a lead must not claim a posture: %v", e.Attributes)
	}
	if hasElement(m, "route:POST /login") {
		t.Error("routes that were never recorded must not appear")
	}
	if m.Provenance.Coverage.Routes {
		t.Error("coverage must say routes were not recorded")
	}
	found := false
	for _, l := range m.Limits {
		if strings.Contains(l, "before routes were recorded") {
			found = true
		}
	}
	if !found {
		t.Errorf("limits must say the findings.json predates route recording: %v", m.Limits)
	}
}

// The IDOR lead lands on the route's Information disclosure and Elevation of
// privilege cells, as a lead and not as a finding.
func TestOwnershipLeadIsALeadNotAFinding(t *testing.T) {
	m := build(t)
	for _, c := range []Category{ElevationOfPrivilege, InformationDisclosure} {
		got := cell(t, m, "route:GET /api/invoices/:id", c)
		if got.Status != LeadsToVerify || got.Leads != 1 || got.Findings != 0 {
			t.Errorf("%s = %+v, want one lead and no findings", c, got)
		}
		if len(got.Evidence) == 0 || !strings.Contains(got.Evidence[0].Ref, "src/routes/invoices.js:14") {
			t.Errorf("%s evidence must cite the lookup at invoices.js:14: %+v", c, got.Evidence)
		}
	}
}

// An agent is an element, its tools and capabilities are what the inventory
// recorded, and a tool whose capability is unknown says so.
func TestAgentCarriesRecordedCapabilitiesAndNamesUnclassifiedTools(t *testing.T) {
	m := build(t)
	a := elementByID(t, m, "agent:src/routes/assistant.js")
	tools := a.Attributes["tools"]
	for _, want := range []string{"run_shell (shell_exec)", "send_email (email_send)", "query_db (capability not classified)"} {
		if !strings.Contains(tools, want) {
			t.Errorf("tools = %q, want %q", tools, want)
		}
	}
	if a.Attributes["unclassified_tools"] != "query_db" {
		t.Errorf("unclassified tools = %q", a.Attributes["unclassified_tools"])
	}
}

func TestMCPServersComeFromTheInventoryWithTheirLaunchCommand(t *testing.T) {
	m := build(t)
	s := elementByID(t, m, "mcp:shell@.mcp.json")
	if s.Attributes["command"] != "npx" || s.Attributes["args"] != "-y mcp-server-shell" {
		t.Errorf("server attributes = %v", s.Attributes)
	}
	if !hasElement(m, "mcp-client:.mcp.json") {
		t.Error("a client element must stand for the file that launches the servers")
	}
	tamper := cell(t, m, s.ID, Tampering)
	if tamper.Status != LimitedEvidence || !strings.Contains(tamper.Evidence[0].Statement, "no version pinned") {
		t.Errorf("an unpinned npx launch is context for tampering: %+v", tamper)
	}
	if cell(t, m, s.ID, ElevationOfPrivilege).Status != LimitedEvidence {
		t.Error("a server whose tool list is * is context for elevation of privilege")
	}
}

func TestPinnedLaunchIsNotReportedAsUnpinned(t *testing.T) {
	in := fixture()
	in.Inventory.Components[0].Details["args"] = "-y mcp-server-shell@1.4.2"
	m := Build(in)
	if got := cell(t, m, "mcp:shell@.mcp.json", Tampering); got.Status != NotEvidenced {
		t.Errorf("a pinned launch has no unpinned-launch evidence, got %+v", got)
	}
}

func TestModelCarriesProviderPinningAndCredentialName(t *testing.T) {
	m := build(t)
	e := elementByID(t, m, "model:gpt-4o@src/routes/assistant.js")
	if e.Attributes["provider"] != "openai" || e.Attributes["pinned"] != "false" || e.Attributes["credential_env_var"] != "OPENAI_API_KEY" {
		t.Errorf("model attributes = %v", e.Attributes)
	}
	if e.Zone != ZoneModel {
		t.Errorf("zone = %s", e.Zone)
	}
}

// Packages suggest services and stores; an AI provider the inventory already
// names through a model is not listed a second time.
func TestDependenciesBecomeStoresAndServicesButAIProvidersAreNotDuplicated(t *testing.T) {
	m := build(t)
	if e := elementByID(t, m, "store:postgresql"); e.Kind != KindDataStore || e.Attributes["basis"] != "dependency" {
		t.Errorf("postgres = %+v", e)
	}
	if e := elementByID(t, m, "service:stripe"); e.Kind != KindService {
		t.Errorf("stripe = %+v", e)
	}
	if hasElement(m, "service:openai") {
		t.Error("the openai package duplicates the model the inventory names")
	}
	if hasElement(m, "service:axios") || hasElement(m, "store:axios") {
		t.Error("an HTTP client is not a service")
	}

	in := fixture()
	in.Inventory.ModelProvenance = nil
	if e := elementByID(t, Build(in), "service:openai"); e.Kind != KindService {
		t.Errorf("with no model named, the AI SDK package is the evidence: %+v", e)
	}
}

func TestDependencyEvidenceSaysDirectnessIsUnknown(t *testing.T) {
	m := build(t)
	e := elementByID(t, m, "store:postgresql")
	if !strings.Contains(e.Evidence[0].Statement, "does not say whether it is direct or transitive") {
		t.Errorf("evidence overclaims: %q", e.Evidence[0].Statement)
	}
}

// Infrastructure is read from findings: a rule's finding proves its resource
// exists. Resources are keyed by file and kind, with names from the structural
// claim when the rule recorded one.
func TestInfrastructureElementsComeFromTheirRulesFindings(t *testing.T) {
	m := build(t)
	ing := elementByID(t, m, "deploy:ingress@deploy/k8s/ingress.yaml")
	if !strings.Contains(ing.Name, "web") {
		t.Errorf("ingress should be named from the structural claim: %q", ing.Name)
	}
	if e := elementByID(t, m, "deploy:bucket@deploy/tf/main.tf"); e.Kind != KindDataStore || e.Zone != ZoneData {
		t.Errorf("bucket = %+v", e)
	}
	if e := elementByID(t, m, "deploy:database@deploy/tf/main.tf"); e.Kind != KindDataStore {
		t.Errorf("database = %+v", e)
	}
}

// One Terraform file holds a bucket and a database. A finding there is
// attached only to the resource its rule names, so the bucket's public ACL is
// never reported against the database.
func TestFindingsInAFileOfSeveralResourcesAttachOnlyToTheResourceTheRuleNames(t *testing.T) {
	m := build(t)
	bucket := cell(t, m, "deploy:bucket@deploy/tf/main.tf", ElevationOfPrivilege)
	db := cell(t, m, "deploy:database@deploy/tf/main.tf", ElevationOfPrivilege)
	if rules(bucket) != "IAC-040" {
		t.Errorf("bucket EoP rules = %q, want only IAC-040", rules(bucket))
	}
	if rules(db) != "IAC-036" {
		t.Errorf("database EoP rules = %q, want only IAC-036", rules(db))
	}
	if cell(t, m, "deploy:bucket@deploy/tf/main.tf", Tampering).Status != NotEvidenced {
		t.Error("IAC-164 names no resource kind, so it belongs to neither the bucket nor the database")
	}
	if m.Summary.UnattributedFindings < 2 {
		t.Errorf("IAC-164 and the hard-coded credential in an unmodelled file are unattributed, got %d", m.Summary.UnattributedFindings)
	}
}

func rules(c Cell) string {
	var ids []string
	for _, e := range c.Evidence {
		if e.RuleID != "" {
			ids = append(ids, e.RuleID)
		}
	}
	return strings.Join(ids, ",")
}

// A waived finding is a decision to cite, not a fix: it keeps the element, is
// counted apart, and never makes a cell look empty.
func TestWaivedFindingsAreCountedApartAndNeverVanish(t *testing.T) {
	m := build(t)
	c := cell(t, m, "deploy:database@deploy/tf/main.tf", InformationDisclosure)
	if c.Findings != 0 || c.Waived != 1 {
		t.Errorf("counts = %d active, %d waived", c.Findings, c.Waived)
	}
	if c.Status != LimitedEvidence {
		t.Errorf("a cell with only a waived finding is context, not clear: %s", c.Status)
	}
	if len(c.Evidence) != 1 || !c.Evidence[0].Waived {
		t.Errorf("evidence = %+v", c.Evidence)
	}
}

// A finding that declares a weakness the mapping does not cover is listed
// apart rather than forced into a category.
func TestFindingsOutsideTheMappingAreListedApart(t *testing.T) {
	m := build(t)
	var deps Row
	for _, r := range m.STRIDE {
		if r.Element == "dependencies" {
			deps = r
		}
	}
	if len(deps.Other) == 0 || deps.Other[0].RuleID != "VULN-001" {
		t.Errorf("advisories carry no STRIDE category and must sit under other findings: %+v", deps.Other)
	}
	for _, c := range deps.Cells {
		if c.Status != NotEvidenced {
			t.Errorf("advisories must not be forced into %s", c.Category)
		}
	}
}

func TestEmptyScanYieldsNoElementsAndSaysSo(t *testing.T) {
	m := Build(Input{NoxVersion: "x", Report: report.JSONReport{Meta: report.Meta{ToolName: "nox"}}})
	if len(m.Elements) != 0 || len(m.Flows) != 0 || len(m.Boundaries) != 0 {
		t.Errorf("nothing was read, nothing may be invented: %+v", m.Summary)
	}
	md := m.Markdown(true)
	if !strings.Contains(md, "hold nothing this model can describe") {
		t.Error("an empty model must say it is empty because of what was read")
	}
	want := []string{"No ai.inventory.json", "No SBOM", "No Express routes were read"}
	for _, w := range want {
		found := false
		for _, l := range m.Limits {
			if strings.Contains(l, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("limits lack %q: %v", w, m.Limits)
		}
	}
}
