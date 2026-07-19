package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// TestSARIF_NoDanglingRuleReference is the regression test for a silent
// GitHub Code Scanning rejection. Plugin findings carry rule IDs absent from
// the RuleSet, and the catalog was built from the RuleSet alone, so those
// results got RuleIndex 0 — a ruleId that resolves to nothing and a ruleIndex
// pointing at whatever sorts first. GitHub validates this and rejects the whole
// upload. Every result's ruleIndex must point at the descriptor whose id equals
// its ruleId.
func TestSARIF_NoDanglingRuleReference(t *testing.T) {
	t.Parallel()

	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{ID: "AAA-001", Severity: "high", Description: "builtin"})
	rep := NewReporter("test", rs)

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "TAINT-003", Severity: "high", Message: "plugin flow",
		Location: findings.Location{FilePath: "a.py", StartLine: 5}})
	fs.Add(findings.Finding{RuleID: "AAA-001", Severity: "high", Message: "builtin",
		Location: findings.Location{FilePath: "b.go", StartLine: 3}})

	doc := generateDoc(t, rep, fs)
	run := doc["runs"].([]any)[0].(map[string]any)
	catalog := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)

	for _, res := range run["results"].([]any) {
		m := res.(map[string]any)
		id := m["ruleId"].(string)
		ri := int(m["ruleIndex"].(float64))
		if ri < 0 || ri >= len(catalog) {
			t.Fatalf("ruleIndex %d out of range for %q", ri, id)
		}
		if got := catalog[ri].(map[string]any)["id"].(string); got != id {
			t.Errorf("result ruleId=%q but ruleIndex points at %q — dangling reference", id, got)
		}
	}
}

// TestSARIF_URIsAreEncoded guards artifact URI validity: a raw space or '#' in
// a path produces an invalid URI reference (a '#' truncates the path at the
// fragment). Verified with a path that contains both.
func TestSARIF_URIsAreEncoded(t *testing.T) {
	t.Parallel()

	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{ID: "A-1", Severity: "high", Description: "d"})
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "A-1", Severity: "high", Message: "m",
		Location: findings.Location{FilePath: "src/my code/a#b.py", StartLine: 1}})

	out := generateBytes(t, NewReporter("t", rs), fs)
	if strings.Contains(out, `"uri": "src/my code/a#b.py"`) || strings.Contains(out, "a#b.py") {
		t.Error("artifact URI was emitted unencoded")
	}
}

// TestSARIF_FileLevelFindingOmitsRegion guards against an empty "region": {}
// object, which strict SARIF validators reject.
func TestSARIF_FileLevelFindingOmitsRegion(t *testing.T) {
	t.Parallel()

	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{ID: "A-1", Severity: "high", Description: "d"})
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "A-1", Severity: "high", Message: "m",
		Location: findings.Location{FilePath: "cfg.yaml"}}) // no line

	if strings.Contains(generateBytes(t, NewReporter("t", rs), fs), `"region":{}`) {
		t.Error("emitted an empty region object for a file-level finding")
	}
}

// TestSARIF_MetadataSurvives guards the downgrade audit trail, which was dropped
// entirely from SARIF — a critical→low downgrade showed only "low" with no record.
func TestSARIF_MetadataSurvives(t *testing.T) {
	t.Parallel()

	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{ID: "A-1", Severity: "low", Description: "d"})
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "A-1", Severity: "low", Message: "m",
		Location: findings.Location{FilePath: "a.go", StartLine: 1},
		Metadata: map[string]string{"original_severity": "critical"}})

	if !strings.Contains(generateBytes(t, NewReporter("t", rs), fs), "original_severity") {
		t.Error("Finding.Metadata dropped from SARIF output")
	}
}

func generateBytes(t *testing.T, r *Reporter, fs *findings.FindingSet) string {
	t.Helper()
	out, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return string(out)
}

func generateDoc(t *testing.T, r *Reporter, fs *findings.FindingSet) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(generateBytes(t, r, fs)), &doc); err != nil {
		t.Fatalf("json: %v", err)
	}
	return doc
}
