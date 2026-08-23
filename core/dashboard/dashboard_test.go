package dashboard

import (
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
)

func scanResult(t *testing.T, fs *findings.FindingSet) *nox.ScanResult {
	t.Helper()
	return &nox.ScanResult{
		Findings:    fs,
		Inventory:   &deps.PackageInventory{},
		AIInventory: ai.NewInventory(),
	}
}

// The template's placeholder must be replaced with real data — a dashboard that
// still contains __NOX_DATA__ rendered nothing.
func TestGenerateHTMLInjectsData(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.NewFinding("SEC-001", findings.SeverityHigh, findings.ConfidenceHigh,
		findings.Location{FilePath: "config.env", StartLine: 1, EndLine: 1}, "hardcoded secret"))

	html, err := GenerateHTML(scanResult(t, fs), "0.1.0", t.TempDir())
	if err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	if !strings.Contains(html, "<html") || !strings.Contains(html, "Security Dashboard") {
		t.Fatal("expected valid dashboard HTML")
	}
	if strings.Contains(html, "__NOX_DATA__") {
		t.Fatal("placeholder was not replaced with scan data")
	}
	if !strings.Contains(html, "SEC-001") {
		t.Fatal("finding rule ID should be injected into the data")
	}
}

// A clean scan still renders a valid dashboard.
func TestGenerateHTMLCleanScan(t *testing.T) {
	html, err := GenerateHTML(scanResult(t, findings.NewFindingSet()), "0.1.0", t.TempDir())
	if err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	if !strings.Contains(html, "<html") || strings.Contains(html, "__NOX_DATA__") {
		t.Fatal("clean scan should still inject an (empty) data set")
	}
}
