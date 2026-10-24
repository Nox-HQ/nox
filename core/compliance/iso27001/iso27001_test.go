package iso27001

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

func finding(rule, sev string, status findings.Status, meta map[string]string) findings.Finding {
	return findings.Finding{
		ID: rule + "-x", RuleID: rule, Severity: findings.Severity(sev),
		Status: status, Metadata: meta,
	}
}

// fixture is a small but representative scan: dependency vulnerabilities, a
// taint finding, a waived finding, a full scope, and one answered capability.
func fixture() Input {
	return Input{
		NoxVersion: "9.9.9",
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Report: report.JSONReport{
			Meta: report.Meta{
				SchemaVersion: "1.0.0", GeneratedAt: "2026-10-24T17:18:36Z",
				ToolName: "nox", ToolVersion: "1.2.3",
				Capabilities: []report.CapabilityCoverage{{Capability: "dynamic_verification", Provided: true, Answered: 0}},
			},
			Findings: []findings.Finding{
				finding("VULN-001", "high", findings.StatusNew, map[string]string{"fixed_in": "1.2.0"}),
				finding("VULN-001", "medium", findings.StatusNew, map[string]string{"fixed_in": "2.0.0"}),
				finding("VULN-001", "low", findings.StatusSuppressed, map[string]string{"fixed_in": "2.0.0"}),
				finding("TAINT-AI-001", "high", findings.StatusNew, map[string]string{"cwe": "CWE-77"}),
				finding("CRYPTO-001", "medium", findings.StatusNew, map[string]string{"cwe": "CWE-327"}),
			},
		},
		Artifacts: []Artifact{
			{Name: "ai.inventory.json", Kind: "ai-inventory", SHA256: "cc"},
			{Name: "findings.json", Kind: "findings", SHA256: "aa"},
			{Name: "sbom.cdx.json", Kind: "sbom", SHA256: "bb"},
		},
		SBOM: &SBOM{Name: "sbom.cdx.json", Format: "CycloneDX 1.5", Components: 12},
		AI:   &AIInventory{Name: "ai.inventory.json", Models: 1, UnpinnedModels: 1},
	}
}

func byID(t *testing.T, a Assessment, id string) Control {
	t.Helper()
	for _, c := range a.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s not in assessment", id)
	return Control{}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden; rerun with -update and review the diff", name)
	}
}

func TestGoldenMarkdown(t *testing.T) {
	golden(t, "iso27001.golden.md", Assess(fixture()).Markdown())
}

func TestGoldenJSON(t *testing.T) {
	b, err := Assess(fixture()).JSON()
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "iso27001.golden.json", string(b))
}

func TestGoldenTerminal(t *testing.T) {
	golden(t, "iso27001.golden.txt", Assess(fixture()).Terminal())
}

// TestSameEvidenceSameBytes pins the determinism contract: the order in which
// a caller happened to list the artifacts must not reach the output.
func TestSameEvidenceSameBytes(t *testing.T) {
	a, b := fixture(), fixture()
	b.Artifacts = []Artifact{b.Artifacts[2], b.Artifacts[0], b.Artifacts[1]}
	ja, _ := Assess(a).JSON()
	jb, _ := Assess(b).JSON()
	if !bytes.Equal(ja, jb) {
		t.Error("artifact order changed the JSON")
	}
	if Assess(a).Markdown() != Assess(b).Markdown() {
		t.Error("artifact order changed the Markdown")
	}
}

var claimsMet = regexp.MustCompile(`(?i)\b(met|meets|compliant|compliance|satisfied|passed|passes|certified|conformant|conforms|ready for)\b`)

// inputs spans the states a scan can be in, so the guarantee below is checked
// against clean, dirty, scoped, offline and empty evidence, not one fixture.
func inputs() map[string]Input {
	clean := fixture()
	clean.Report.Findings = nil
	scoped := fixture()
	scoped.Report.Meta.Scope = &report.ScanScope{Scanned: []string{"secrets"}, NotScanned: []string{"deps", "code", "iac", "ai", "data", "supply-chain"}}
	offline := fixture()
	offline.Report.Meta.Offline = true
	dynamic := fixture()
	dynamic.Report.Meta.Capabilities = []report.CapabilityCoverage{{Capability: "dynamic_verification", Answered: 3}}
	dynamic.Report.Findings = nil
	return map[string]Input{
		"fixture": fixture(), "clean": clean, "scoped": scoped, "offline": offline,
		"dynamic": dynamic, "empty": {NoxVersion: "x", Report: report.JSONReport{Meta: report.Meta{ToolName: "nox"}}},
	}
}

// TestNoControlIsEverReportedAsMet is the contract of the whole package. A
// scanner cannot know that an Annex A control is satisfied, so no status value
// and no rendered word may claim it, for any input.
func TestNoControlIsEverReportedAsMet(t *testing.T) {
	allowed := map[Status]bool{SupportingEvidence: true, OpenIssues: true, LimitedEvidence: true, NotEvidenced: true}
	for name, in := range inputs() {
		a := Assess(in)
		j, err := a.JSON()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range a.Controls {
			if !allowed[c.Status] {
				t.Errorf("%s: %s has status %q outside the evidence vocabulary", name, c.ID, c.Status)
			}
			if len(c.Limits) == 0 {
				t.Errorf("%s: %s names nothing the evidence cannot show", name, c.ID)
			}
			if len(c.Organizational) == 0 {
				t.Errorf("%s: %s names no organizational evidence", name, c.ID)
			}
		}
		for form, text := range map[string]string{"markdown": a.Markdown(), "terminal": a.Terminal(), "json": string(j)} {
			if m := claimsMet.FindString(text); m != "" {
				t.Errorf("%s/%s uses %q, which claims more than technical evidence", name, form, m)
			}
		}
	}
	for _, s := range []Status{SupportingEvidence, OpenIssues, LimitedEvidence, NotEvidenced} {
		if claimsMet.MatchString(string(s)) || claimsMet.MatchString(statusLabel(s)) {
			t.Errorf("status %q reads as a verdict", s)
		}
	}
}

// TestTitlesAreTheCurrentEdition guards against drifting to the 2013 numbering
// or to paraphrased titles: every control carries its 2022 number and title.
func TestTitlesAreTheCurrentEdition(t *testing.T) {
	want := map[string]string{
		"A.5.9":  "Inventory of information and other associated assets",
		"A.5.17": "Authentication information",
		"A.5.19": "Information security in supplier relationships",
		"A.5.21": "Managing information security in the ICT supply chain",
		"A.5.23": "Information security for use of cloud services",
		"A.5.34": "Privacy and protection of personal identifiable information (PII)",
		"A.8.4":  "Access to source code",
		"A.8.8":  "Management of technical vulnerabilities",
		"A.8.9":  "Configuration management",
		"A.8.12": "Data leakage prevention",
		"A.8.24": "Use of cryptography",
		"A.8.25": "Secure development life cycle",
		"A.8.26": "Application security requirements",
		"A.8.27": "Secure system architecture and engineering principles",
		"A.8.28": "Secure coding",
		"A.8.29": "Security testing in development and acceptance",
	}
	a := Assess(fixture())
	if len(a.Controls) != len(want) {
		t.Fatalf("mapped %d controls, expected %d", len(a.Controls), len(want))
	}
	for _, c := range a.Controls {
		if want[c.ID] != c.Title {
			t.Errorf("%s title = %q, want %q", c.ID, c.Title, want[c.ID])
		}
	}
}

func TestEveryOrganizationalReferenceExists(t *testing.T) {
	known := map[string]bool{}
	for _, it := range orgItems {
		known[it.ID] = true
	}
	for _, c := range controls {
		for _, id := range c.org {
			if !known[id] {
				t.Errorf("%s references unknown organizational item %s", c.id, id)
			}
		}
	}
	for _, it := range Assess(fixture()).Organizational {
		if it.Needed == "" || it.Reference == "" {
			t.Errorf("%s has no description or reference", it.ID)
		}
	}
}

func TestOpenFindingsAreCountedAndCited(t *testing.T) {
	a := Assess(fixture())
	c := byID(t, a, "A.8.8")
	if c.Status != OpenIssues {
		t.Fatalf("status = %s, want open_issues", c.Status)
	}
	e := c.Evidence[0]
	if e.Findings != 2 || e.Waived != 1 || e.Artifact != "findings.json" {
		t.Errorf("evidence = %+v, want 2 open, 1 waived, from findings.json", e)
	}
	if !strings.Contains(e.Statement, "2 of them name a version that fixes them") {
		t.Errorf("statement omits the fix count: %s", e.Statement)
	}
	if got := byID(t, a, "A.8.24"); got.Status != OpenIssues {
		t.Errorf("a CWE-327 finding should open A.8.24, got %s", got.Status)
	}
}

// TestWaivedFindingsAreADecisionToCite: a control whose only findings are
// waived is not clean. The waiver is a recorded acceptance of risk the scan
// cannot vouch for, so it must not read as supporting evidence.
func TestWaivedFindingsAreADecisionToCite(t *testing.T) {
	in := fixture()
	in.Report.Findings = []findings.Finding{finding("IAC-018", "high", findings.StatusSuppressed, nil)}
	c := byID(t, Assess(in), "A.5.23")
	if c.Status != LimitedEvidence {
		t.Fatalf("A.5.23 with only a waived finding = %s, want limited_evidence", c.Status)
	}
	if c.Evidence[0].Waived != 1 || !strings.Contains(strings.Join(c.Gaps, " "), "waived") {
		t.Errorf("waiver not surfaced: %+v gaps=%v", c.Evidence[0], c.Gaps)
	}
}

func TestSecretsCleanIsSupportingNotMet(t *testing.T) {
	c := byID(t, Assess(inputs()["clean"]), "A.5.17")
	if c.Status != SupportingEvidence {
		t.Fatalf("clean secret scan = %s, want supporting_evidence", c.Status)
	}
}

// TestEmptyResultNeedsASubject is the false all-clear this package must not
// produce: infrastructure checks that found nothing in a repository with no
// infrastructure code are not evidence about infrastructure.
func TestEmptyResultNeedsASubject(t *testing.T) {
	a := Assess(inputs()["clean"])
	for _, id := range []string{"A.5.23", "A.8.9", "A.5.34", "A.8.24", "A.8.28"} {
		c := byID(t, a, id)
		if c.Status != LimitedEvidence {
			t.Errorf("%s = %s, want limited_evidence", id, c.Status)
		}
		if len(c.Gaps) == 0 || !strings.Contains(c.Gaps[0], "do not show that any files of this kind were present") {
			t.Errorf("%s does not say why an empty result is weak: %v", id, c.Gaps)
		}
	}
}

// TestAdvisoryLookupIsNotAssumed: a scan run with --no-osv records nothing, so
// zero vulnerabilities cannot be read as "none known".
func TestAdvisoryLookupIsNotAssumed(t *testing.T) {
	c := byID(t, Assess(inputs()["clean"]), "A.8.8")
	if c.Status != LimitedEvidence {
		t.Fatalf("A.8.8 with no recorded lookup = %s, want limited_evidence", c.Status)
	}
	if !strings.Contains(strings.Join(c.Gaps, " "), "--no-osv") {
		t.Errorf("gap does not name the ambiguity: %v", c.Gaps)
	}
	off := byID(t, Assess(inputs()["offline"]), "A.8.8")
	if !strings.Contains(strings.Join(off.Gaps, " "), "ran offline") {
		t.Errorf("offline scan not flagged: %v", off.Gaps)
	}
}

func TestScopeNotScannedIsNotEvidence(t *testing.T) {
	a := Assess(inputs()["scoped"])
	for _, id := range []string{"A.8.8", "A.5.23", "A.8.24", "A.5.21"} {
		c := byID(t, a, id)
		if c.Status == SupportingEvidence || c.Status == OpenIssues {
			t.Errorf("%s = %s although its scope was not scanned", id, c.Status)
		}
	}
	if byID(t, a, "A.8.8").Status != NotEvidenced {
		t.Errorf("A.8.8 should have no evidence when deps was not scanned")
	}
	if byID(t, a, "A.5.17").Status != SupportingEvidence {
		t.Errorf("secrets scope ran clean; A.5.17 should have supporting evidence")
	}
	if !strings.Contains(a.Terminal(), "Not scanned:") {
		t.Error("terminal summary does not say which scopes were not scanned")
	}
}

func TestMissingSBOMIsAGapNotAnEmptyOne(t *testing.T) {
	in := fixture()
	in.SBOM = nil
	c := byID(t, Assess(in), "A.5.19")
	if c.Status != NotEvidenced {
		t.Errorf("A.5.19 without an SBOM = %s, want not_evidenced", c.Status)
	}
	if len(c.Gaps) == 0 || !strings.Contains(c.Gaps[0], "No SBOM") {
		t.Errorf("missing SBOM not named: %v", c.Gaps)
	}
}

func TestNothingIsEvidencedForRequirements(t *testing.T) {
	for name, in := range inputs() {
		if s := byID(t, Assess(in), "A.8.26").Status; s != NotEvidenced {
			t.Errorf("%s: A.8.26 = %s; a scan holds no evidence about requirements", name, s)
		}
	}
}

func TestSecurityTestingNeedsDynamicEvidence(t *testing.T) {
	if s := byID(t, Assess(fixture()), "A.8.29"); s.Status != LimitedEvidence || len(s.Gaps) == 0 {
		t.Errorf("static-only A.8.29 = %s gaps=%v, want limited_evidence with a gap", s.Status, s.Gaps)
	}
	if s := byID(t, Assess(inputs()["dynamic"]), "A.8.29").Status; s != SupportingEvidence {
		t.Errorf("A.8.29 with dynamic verification = %s, want supporting_evidence", s)
	}
}

func TestIndirectControlsNeverRiseAboveLimited(t *testing.T) {
	for name, in := range inputs() {
		a := Assess(in)
		for _, def := range controls {
			if def.indirect && byID(t, a, def.id).Status == SupportingEvidence {
				t.Errorf("%s: indirect control %s reported supporting_evidence", name, def.id)
			}
		}
	}
}

func TestEveryOrganizationalItemNamesTheControlsThatNeedIt(t *testing.T) {
	a := Assess(fixture())
	for _, it := range a.Organizational {
		if it.ID == "ORG-VULN-PROCESS" && !contains(it.Controls, "A.8.8") {
			t.Errorf("ORG-VULN-PROCESS controls = %v, want A.8.8 among them", it.Controls)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestParsers(t *testing.T) {
	rep, art, err := ParseFindings("findings.json", []byte(`{"meta":{"tool_name":"nox","tool_version":"1"},"findings":[]}`))
	if err != nil || rep.Meta.ToolName != "nox" || art.SHA256 != Digest([]byte(`{"meta":{"tool_name":"nox","tool_version":"1"},"findings":[]}`)) {
		t.Errorf("ParseFindings = %v %v %v", rep, art, err)
	}
	if _, _, err := ParseFindings("x.json", []byte(`[]`)); err == nil {
		t.Error("an array is not a findings report")
	}
	if _, _, err := ParseFindings("x.json", []byte(`{"findings":[]}`)); err == nil {
		t.Error("a document with no meta is not a findings.json written by nox")
	}
	s, _, err := ParseSBOM("s.json", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{},{}]}`))
	if err != nil || s.Components != 2 || s.Format != "CycloneDX 1.5" {
		t.Errorf("CycloneDX = %+v %v", s, err)
	}
	s, _, err = ParseSBOM("s.json", []byte(`{"spdxVersion":"SPDX-2.3","packages":[{}]}`))
	if err != nil || s.Components != 1 {
		t.Errorf("SPDX = %+v %v", s, err)
	}
	if _, _, err := ParseSBOM("s.json", []byte(`{}`)); err == nil {
		t.Error("an unrecognised SBOM must be rejected, not counted as empty")
	}
	ai, _, err := ParseAIInventory("a.json", []byte(`{"components":[{}],"model_provenance":[{"pinned":true},{"pinned":false}],"checks":["a"]}`))
	if err != nil || ai.Components != 1 || ai.Models != 2 || ai.UnpinnedModels != 1 {
		t.Errorf("AI inventory = %+v %v", ai, err)
	}
}
