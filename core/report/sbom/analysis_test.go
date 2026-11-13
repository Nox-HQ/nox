package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
)

func depFinding(pkg, version, id, applicability, stoppedAt string) findings.Finding {
	return findings.Finding{RuleID: "VULN-001", Metadata: map[string]string{
		"ecosystem": "npm", "package": pkg, "version": version, "vuln_id": id,
		"applicability": applicability, "applicability_stopped_at": stoppedAt,
	}}
}

// A dependency vulnerability nox decided is not impacting is recorded as a
// CycloneDX VEX analysis, `not_affected` with the justification the refuted
// step supports, so a consumer of the SBOM reads the verdict in the standard
// field rather than in nox's own metadata (#1012). Undecided and impacting
// verdicts carry no analysis: nox does not claim exploitability.
func TestCycloneDXRecordsNotImpactingVerdictsAsVEX(t *testing.T) {
	fs := []findings.Finding{
		depFinding("lodash", "4.17.20", "GHSA-1234-5678-9012", "not_impacting", "symbol_used"),
		depFinding("lodash", "4.17.20", "GHSA-abcd-efgh-ijkl", "undetermined", "call_reachable"),
		// The same advisory on another version is a different verdict.
		depFinding("lodash", "4.17.19", "GHSA-abcd-efgh-ijkl", "not_impacting", "call_reachable"),
		// Not a dependency finding.
		{RuleID: "SEC-001", Metadata: map[string]string{"package": "lodash", "version": "4.17.20",
			"vuln_id": "GHSA-abcd-efgh-ijkl", "applicability": "not_impacting"}},
	}
	data, err := NewCycloneDXReporter("0.1.0").WithFindings(fs).Generate(testInventoryWithVulns())
	if err != nil {
		t.Fatal(err)
	}
	var report CDXReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	got := map[string]*CDXAnalysis{}
	for _, v := range report.Vulnerabilities {
		got[v.ID] = v.Analysis
	}
	a := got["GHSA-1234-5678-9012"]
	if a == nil || a.State != "not_affected" || a.Justification != "code_not_present" || a.Detail == "" {
		t.Errorf("not-impacting verdict: analysis %+v, want not_affected / code_not_present with a detail", a)
	}
	if a != nil && (strings.Contains(a.Detail, "symbol_used") || !strings.Contains(a.Detail, "not linked by this build")) {
		t.Errorf("detail %q names the step by its identifier instead of saying what was shown", a.Detail)
	}
	if got["GHSA-abcd-efgh-ijkl"] != nil {
		t.Errorf("undetermined verdict carries an analysis: %+v", got["GHSA-abcd-efgh-ijkl"])
	}
}

func TestCycloneDXJustificationFollowsTheRefutedStep(t *testing.T) {
	for stoppedAt, want := range map[string]string{
		"symbol_used":        "code_not_present",
		"call_reachable":     "code_not_reachable",
		"attacker_reachable": "",
	} {
		inv := &deps.PackageInventory{}
		inv.Add(deps.Package{Name: "x", Version: "1.0.0", Ecosystem: "npm"})
		inv.SetVulnerabilities(0, []deps.Vulnerability{{ID: "GHSA-x"}})
		data, err := NewCycloneDXReporter("0.1.0").
			WithFindings([]findings.Finding{depFinding("x", "1.0.0", "GHSA-x", "not_impacting", stoppedAt)}).
			Generate(inv)
		if err != nil {
			t.Fatal(err)
		}
		var report CDXReport
		_ = json.Unmarshal(data, &report)
		a := report.Vulnerabilities[0].Analysis
		if a == nil || a.State != "not_affected" || a.Justification != want {
			t.Errorf("stopped at %s: analysis %+v, want not_affected with justification %q", stoppedAt, a, want)
		}
	}
}

// An advisory the finding names by an alias of the SBOM's id is the same one.
func TestCycloneDXAnalysisMatchesByAlias(t *testing.T) {
	inv := &deps.PackageInventory{}
	inv.Add(deps.Package{Name: "x", Version: "1.0.0", Ecosystem: "go"})
	inv.SetVulnerabilities(0, []deps.Vulnerability{{ID: "GHSA-x", Aliases: []string{"GO-2026-1"}}})
	f := depFinding("x", "1.0.0", "GO-2026-1", "not_impacting", "symbol_used")
	f.Metadata["ecosystem"] = "go"
	data, err := NewCycloneDXReporter("0.1.0").WithFindings([]findings.Finding{f}).Generate(inv)
	if err != nil {
		t.Fatal(err)
	}
	var report CDXReport
	_ = json.Unmarshal(data, &report)
	if a := report.Vulnerabilities[0].Analysis; a == nil || a.State != "not_affected" {
		t.Errorf("analysis %+v; the finding names the SBOM's advisory by its alias", a)
	}
}
