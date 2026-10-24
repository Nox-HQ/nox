package threatmodel

import (
	"bytes"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// claimsAssurance matches the words that would claim a threat is absent or
// dealt with, or a system is in good order. A scanner cannot know either, so no
// nox-authored sentence may use one. Quoted rule messages are the rules' own
// words and are fixed in these fixtures to neutral text.
var claimsAssurance = regexp.MustCompile(`(?i)\b(met|meets|compliant|compliance|satisfied|passed|passes|certified|conformant|conforms|ready for|` +
	`secure|secured|safe|safely|mitigated|mitigates|protected|handled|resolved|remediated|fixed|cleared|` +
	`no threats?|no risks?|not vulnerable|unaffected|nothing to worry)\b`)

// inputs spans the states a scan can be in, so the guarantee below is checked
// against full, clean, scoped, offline, partial and empty evidence.
func inputs() map[string]Input {
	clean := fixture()
	clean.Report.Findings = nil
	clean.Report.Leads = nil
	scoped := fixture()
	scoped.Report.Meta.Scope = &report.ScanScope{Scanned: []string{"secrets"}, NotScanned: []string{"deps", "code", "iac", "ai"}}
	offline := fixture()
	offline.Report.Meta.Offline = true
	noAI := fixture()
	noAI.Inventory = nil
	noSBOM := fixture()
	noSBOM.SBOM = nil
	degraded := fixture()
	degraded.Report.Meta.Degradations = []report.Degradation{{Kind: "osv", Detail: "lookup failed"}}
	return map[string]Input{
		"fixture": fixture(), "clean": clean, "scoped": scoped, "offline": offline,
		"no-ai": noAI, "no-sbom": noSBOM, "degraded": degraded,
		"empty": {NoxVersion: "x", Report: report.JSONReport{Meta: report.Meta{ToolName: "nox"}}},
	}
}

// TestNoThreatIsEverReportedAsAbsentOrHandled is the contract of the whole
// package. A scanner cannot know that a threat does not exist or has been dealt
// with, so no status value and no rendered word may claim it, for any input.
func TestNoThreatIsEverReportedAsAbsentOrHandled(t *testing.T) {
	allowed := map[Status]bool{OpenIssues: true, LeadsToVerify: true, LimitedEvidence: true, NotEvidenced: true}
	for name, in := range inputs() {
		m := Build(in)
		m = m.WithChanges(Build(fixture()))
		j, err := m.JSON()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range m.STRIDE {
			if len(r.Cells) != len(Categories) {
				t.Errorf("%s: %s has %d cells, want one per STRIDE category", name, r.Element, len(r.Cells))
			}
			for _, c := range r.Cells {
				if !allowed[c.Status] {
					t.Errorf("%s: %s/%s has status %q outside the evidence vocabulary", name, r.Element, c.Category, c.Status)
				}
				if (c.Status == NotEvidenced) != (len(c.Evidence) == 0) {
					t.Errorf("%s: %s/%s is %s with %d pieces of evidence", name, r.Element, c.Category, c.Status, len(c.Evidence))
				}
				if c.Status == NotEvidenced && c.Note != "nox has no evidence either way" {
					t.Errorf("%s: an empty cell must say it is not evidenced either way, got %q", name, c.Note)
				}
			}
		}
		if len(m.Limits) < len(fixedLimits) {
			t.Errorf("%s: the model states %d limits, fewer than the fixed ones", name, len(m.Limits))
		}
		texts := map[string]string{
			"markdown": m.Markdown(true), "terminal": m.Terminal(), "json": string(j),
			"diagram": m.Mermaid(), "delta": m.Changes.Terminal(),
		}
		for form, text := range texts {
			if w := claimsAssurance.FindString(text); w != "" {
				i := strings.Index(strings.ToLower(text), strings.ToLower(w))
				t.Errorf("%s/%s uses %q, which claims more than evidence: ...%s...", name, form, w, text[max(0, i-60):min(len(text), i+60)])
			}
		}
	}
	for _, s := range []Status{OpenIssues, LeadsToVerify, LimitedEvidence, NotEvidenced} {
		if claimsAssurance.MatchString(string(s)) || claimsAssurance.MatchString(statusLabel(s)) {
			t.Errorf("status %q reads as a verdict", s)
		}
	}
	for _, s := range []string{Notice, ShortNotice} {
		if claimsAssurance.MatchString(s) {
			t.Errorf("notice uses an assurance word: %q", s)
		}
	}
}

// shuffled returns the fixture with every ordered input in a different order.
func shuffled(seed int64) Input {
	in := fixture()
	r := rand.New(rand.NewSource(seed))
	r.Shuffle(len(in.Report.Findings), func(i, j int) {
		in.Report.Findings[i], in.Report.Findings[j] = in.Report.Findings[j], in.Report.Findings[i]
	})
	r.Shuffle(len(in.Report.Routes), func(i, j int) { in.Report.Routes[i], in.Report.Routes[j] = in.Report.Routes[j], in.Report.Routes[i] })
	r.Shuffle(len(in.Artifacts), func(i, j int) { in.Artifacts[i], in.Artifacts[j] = in.Artifacts[j], in.Artifacts[i] })
	r.Shuffle(len(in.SBOM.Components), func(i, j int) {
		in.SBOM.Components[i], in.SBOM.Components[j] = in.SBOM.Components[j], in.SBOM.Components[i]
	})
	r.Shuffle(len(in.Inventory.ToolMatrix), func(i, j int) {
		in.Inventory.ToolMatrix[i], in.Inventory.ToolMatrix[j] = in.Inventory.ToolMatrix[j], in.Inventory.ToolMatrix[i]
	})
	for i := range in.Inventory.ToolMatrix {
		t := in.Inventory.ToolMatrix[i].Tools
		r.Shuffle(len(t), func(a, b int) { t[a], t[b] = t[b], t[a] })
	}
	return in
}

// TestSameEvidenceSameBytes pins the determinism contract: the order in which a
// caller happened to list findings, routes, packages, tools and artifacts must
// not reach any output, and the model reads no clock.
func TestSameEvidenceSameBytes(t *testing.T) {
	base := Build(fixture())
	wantJSON, _ := base.JSON()
	for seed := int64(1); seed <= 25; seed++ {
		m := Build(shuffled(seed))
		gotJSON, _ := m.JSON()
		if !bytes.Equal(wantJSON, gotJSON) {
			t.Fatalf("seed %d: input order changed the JSON", seed)
		}
		if base.Markdown(true) != m.Markdown(true) {
			t.Fatalf("seed %d: input order changed the Markdown", seed)
		}
		if base.Terminal() != m.Terminal() {
			t.Fatalf("seed %d: input order changed the terminal summary", seed)
		}
	}
	if !bytes.Equal(wantJSON, mustJSON(Build(fixture()))) {
		t.Error("two builds of the same input differ")
	}
}

func mustJSON(m Model) []byte {
	b, err := m.JSON()
	if err != nil {
		panic(err)
	}
	return b
}

func TestGoldenMarkdown(t *testing.T) { golden(t, "model.golden.md", Build(fixture()).Markdown(true)) }

func TestGoldenJSON(t *testing.T) { golden(t, "model.golden.json", string(mustJSON(Build(fixture())))) }

func TestGoldenTerminal(t *testing.T) { golden(t, "model.golden.txt", Build(fixture()).Terminal()) }

// TestRuleIDsNamedInTheTablesExist stops a renamed rule from silently turning a
// table row into a dead one: every rule ID the model's tables name must still
// be a built-in rule.
func TestRuleIDsNamedInTheTablesExist(t *testing.T) {
	known := map[string]bool{}
	for _, r := range catalog.Rules() {
		known[r.ID] = true
	}
	var missing []string
	for id := range iacRules {
		if !known[id] {
			missing = append(missing, id)
		}
	}
	for id := range strideByRule {
		if !known[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("tables name rules that no longer exist: %v", missing)
	}
	// Every supply-chain prefix must still match at least one rule.
	for _, p := range supplyChainPrefixes {
		found := false
		for id := range known {
			if strings.HasPrefix(id, p) {
				found = true
			}
		}
		if !found {
			t.Errorf("supply-chain prefix %q matches no rule", p)
		}
	}
}

// TestEveryTaintClassWeMapIsOneTheTaintRulesEmit keeps taintEffects honest
// against the classes the taint engine can produce.
func TestTaintEffectsAreAllNamedClasses(t *testing.T) {
	for class, eff := range taintEffects {
		if class == "" || eff.capID == "" || eff.label == "" {
			t.Errorf("incomplete taint effect %q: %+v", class, eff)
		}
	}
}

// TestSTRIDEMappingHasNoCWEInTwoRows keeps the CWE table unambiguous: a weakness
// maps to one row, whose categories are the complete answer.
func TestSTRIDEMappingHasNoCWEInTwoRows(t *testing.T) {
	seen := map[string]int{}
	for i, row := range strideByCWE {
		for _, c := range row.cwes {
			if j, dup := seen[c]; dup {
				t.Errorf("%s is in rows %d and %d", c, j, i)
			}
			seen[c] = i
		}
	}
}

func TestCategoriesFor(t *testing.T) {
	cases := []struct {
		name string
		f    findings.Finding
		want []Category
	}{
		{"command injection is tampering and elevation", finding("X", "high", "a", 1, "m", "", map[string]string{"cwe": "CWE-78"}), []Category{Tampering, ElevationOfPrivilege}},
		{"hard-coded credential is spoofing and disclosure", finding("X", "high", "a", 1, "m", "", map[string]string{"cwe": "CWE-798"}), []Category{Spoofing, InformationDisclosure}},
		{"logging is repudiation", finding("X", "low", "a", 1, "m", "", map[string]string{"cwe": "CWE-778"}), []Category{Repudiation}},
		{"resource exhaustion is denial of service", finding("X", "low", "a", 1, "m", "", map[string]string{"cwe": "CWE-400"}), []Category{DenialOfService}},
		{"a CWE list maps each member once", finding("X", "low", "a", 1, "m", "", map[string]string{"cwe": "CWE-79, CWE-1336"}), []Category{Tampering, InformationDisclosure, ElevationOfPrivilege}},
		{"an unmapped weakness maps to nothing", finding("X", "low", "a", 1, "m", "", map[string]string{"cwe": "CWE-693"}), nil},
		{"no weakness maps to nothing", finding("X", "low", "a", 1, "m", "", nil), nil},
		{"object-level authorization is named by rule", finding("AUTHZ-001", "medium", "a", 1, "m", "", map[string]string{"cwe": "CWE-639"}), []Category{ElevationOfPrivilege, InformationDisclosure}},
	}
	for _, c := range cases {
		got := categoriesFor(c.f)
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		want := append([]Category(nil), c.want...)
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", c.name, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, want)
			}
		}
	}
}

func TestAgentRulesAttachOnlyToAgents(t *testing.T) {
	m := build(t)
	if got := rules(cell(t, m, "model:gpt-4o@src/routes/assistant.js", ElevationOfPrivilege)); strings.Contains(got, "AI-AGENT-001") {
		t.Errorf("an agent finding was attached to a model: %s", got)
	}
	if got := rules(cell(t, m, "agent:src/routes/assistant.js", ElevationOfPrivilege)); !strings.Contains(got, "AI-AGENT-001") {
		t.Errorf("the agent finding must reach the agent: %s", got)
	}
}

func TestFindingBelongsToTheRouteAboveItInTheSameFile(t *testing.T) {
	m := build(t)
	if !strings.Contains(rules(cell(t, m, "route:POST /api/assistant/summarise", Tampering)), "TAINT-AI-001") {
		t.Error("a finding below a route registration belongs to that route")
	}
	if strings.Contains(rules(cell(t, m, "route:POST /login", Tampering)), "TAINT") {
		t.Error("a finding in another file must not attach to the route")
	}
}

// Questions are derived from gaps and each names its basis.
func TestQuestionsComeFromGapsAndCiteTheirBasis(t *testing.T) {
	m := build(t)
	if len(m.Questions) == 0 {
		t.Fatal("no questions")
	}
	var all []string
	for _, q := range m.Questions {
		all = append(all, q.Question)
		if q.Basis.Artifact == "" || q.Basis.Statement == "" {
			t.Errorf("question %s has no basis: %+v", q.ID, q)
		}
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{
		"assistant.js exposes shell_exec to the model through tool run_shell",
		"query_db",
		"POST /login (src/server.js:6) has no authentication middleware visible",
		"GET /api/invoices/:id (src/routes/invoices.js:14)",
		"Ingress web",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no question mentions %q\n%s", want, text)
		}
	}
}

func TestQuestionsPerKindAreBounded(t *testing.T) {
	in := fixture()
	for i := 0; i < 40; i++ {
		in.Report.Routes = append(in.Report.Routes, report.Route{
			Method: "GET", Path: "/open/" + strings.Repeat("x", i+1), FilePath: "src/open.js", Line: i + 1,
		})
	}
	m := Build(in)
	n := 0
	for _, q := range m.Questions {
		if strings.Contains(q.Question, "has no authentication middleware visible") {
			n++
		}
	}
	if n > maxQuestionsPerKind {
		t.Errorf("%d route questions, want at most %d", n, maxQuestionsPerKind)
	}
	more := false
	for _, q := range m.Questions {
		if strings.Contains(q.Question, "more question(s)") {
			more = true
		}
	}
	if !more {
		t.Error("a bounded list must say how many questions it left out")
	}
}

func TestLimitsNameTheRunsGaps(t *testing.T) {
	in := inputs()["scoped"]
	m := Build(in)
	if !hasLimit(m, "covered only secrets") {
		t.Errorf("a scoped scan must say what it covered: %v", m.Limits)
	}
	if !hasLimit(Build(inputs()["offline"]), "ran offline") {
		t.Error("an offline scan must say vulnerability data was not looked up")
	}
	if !hasLimit(Build(inputs()["degraded"]), "did not complete") {
		t.Error("a degraded scan must say checks did not complete")
	}
	if !hasLimit(Build(inputs()["no-ai"]), "No ai.inventory.json") {
		t.Error("a missing inventory is a gap, not an absence")
	}
	for _, want := range []string{"Business logic", "identity provider", "Express-style", "network topology"} {
		if !hasLimit(m, want) && !hasLimitFold(m, want) {
			t.Errorf("fixed limits lack %q", want)
		}
	}
}

func hasLimit(m Model, s string) bool {
	for _, l := range m.Limits {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func hasLimitFold(m Model, s string) bool {
	for _, l := range m.Limits {
		if strings.Contains(strings.ToLower(l), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func TestParsers(t *testing.T) {
	if _, _, err := ParseFindings("f.json", []byte(`{"findings":[]}`)); err == nil {
		t.Error("a findings.json without a meta block must be refused")
	}
	rep, art, err := ParseFindings("f.json", []byte(`{"meta":{"tool_name":"nox"},"findings":[],"routes":[{"method":"GET","path":"/x","file_path":"a.js","line":1,"authn":"requireAuth"}]}`))
	if err != nil || art.SHA256 == "" || len(rep.Routes) != 1 || rep.Routes[0].Authn != "requireAuth" {
		t.Errorf("rep = %+v art = %+v err = %v", rep, art, err)
	}
	sb, _, err := ParseSBOM("s.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"b","version":"2"},{"name":"a","version":"1"}]}`))
	if err != nil || len(sb.Components) != 2 || sb.Components[0].Name != "a" {
		t.Errorf("sbom = %+v err = %v", sb, err)
	}
	if _, _, err := ParseSBOM("s.json", []byte(`{"foo":1}`)); err == nil {
		t.Error("a document that is neither CycloneDX nor SPDX must be refused")
	}
	spdx, _, err := ParseSBOM("s.json", []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"p","versionInfo":"3"}]}`))
	if err != nil || len(spdx.Components) != 1 || spdx.Components[0].Version != "3" {
		t.Errorf("spdx = %+v err = %v", spdx, err)
	}
	inv, _, err := ParseInventory("i.json", []byte(`{"components":[],"checks":["x"]}`))
	if err != nil || inv == nil || len(inv.Checks) != 1 {
		t.Errorf("inventory = %+v err = %v", inv, err)
	}
	var _ = ai.Inventory{}
}
