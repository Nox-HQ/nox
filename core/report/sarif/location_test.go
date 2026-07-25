package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// A finding with no file location must not cost every other finding its
// upload.
//
// Some verdicts are about the dependency graph rather than a line of source —
// a reachability class, or a repository-scoped "no private registry
// configured" — and they arrive with an empty path. nox wrote that straight
// into SARIF as artifactLocation.uri "", and GitHub rejects the SUBMISSION,
// not the result:
//
//	Code Scanning could not process the submitted SARIF file:
//	locationFromSarifResult: expected artifact location
//
// So one plugin emitting one location-less finding silently costs a repository
// its entire code-scanning upload, while the same scan looks clean locally.
// Any analyzer can produce this shape, so the blast radius belongs in core.
func TestGenerate_LocationLessFindingDoesNotEmitEmptyURI(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.NewFinding("REACH-001", findings.SeverityInfo, findings.ConfidenceHigh,
		findings.Location{FilePath: ""}, "dependency is not reachable"))
	fs.Add(findings.NewFinding("SEC-001", findings.SeverityHigh, findings.ConfidenceHigh,
		findings.Location{FilePath: "main.go", StartLine: 12}, "hardcoded secret"))

	out, err := NewReporter("test", rules.NewRuleSet()).Generate(fs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(string(out), `"uri": ""`) {
		t.Error(`SARIF contains artifactLocation.uri "" — GitHub rejects the whole file for this`)
	}
	// A nil slice serialises as `"locations": null`, which is no better than an
	// empty uri: the key must be absent entirely.
	if strings.Contains(string(out), `"locations": null`) {
		t.Error(`SARIF contains "locations": null — the key must be omitted, not nulled`)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}

	byRule := map[string]int{}
	for _, r := range doc.Runs[0].Results {
		byRule[r.RuleID] = len(r.Locations)
		for _, l := range r.Locations {
			if l.PhysicalLocation.ArtifactLocation.URI == "" {
				t.Errorf("%s emitted a location with an empty uri", r.RuleID)
			}
		}
	}

	// Both findings must survive. Dropping the located one would be a
	// regression; dropping the location-less one loses a real verdict.
	if _, ok := byRule["SEC-001"]; !ok {
		t.Error("the located finding disappeared from SARIF")
	}
	if _, ok := byRule["REACH-001"]; !ok {
		t.Error("the location-less finding was dropped entirely; it should be reported without a location")
	}
	if n := byRule["REACH-001"]; n != 0 {
		t.Errorf("location-less finding carries %d locations, want 0 — an absent array cannot trip "+
			"'expected artifact location', an empty-uri entry does", n)
	}
	if n := byRule["SEC-001"]; n != 1 {
		t.Errorf("located finding carries %d locations, want 1", n)
	}
}
