package detail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func TestLoadFromFileAndFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")

	rep := report.JSONReport{
		Meta: report.Meta{
			SchemaVersion: "1.0.0",
			GeneratedAt:   "2026-01-01T00:00:00Z",
			ToolName:      "nox",
			ToolVersion:   "0.1.0",
		},
		Findings: []findings.Finding{
			{
				ID:       "F-1",
				RuleID:   "SEC-001",
				Severity: findings.SeverityHigh,
				Location: findings.Location{FilePath: "src/app.go"},
			},
			{
				ID:       "F-2",
				RuleID:   "DATA-001",
				Severity: findings.SeverityLow,
				Location: findings.Location{FilePath: "config/settings.yml"},
			},
		},
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write findings file: %v", err)
	}

	store, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.BasePath() != dir {
		t.Fatalf("expected base path %s, got %s", dir, store.BasePath())
	}
	if store.Count() != 2 {
		t.Fatalf("expected 2 findings, got %d", store.Count())
	}

	high := store.Filter(Filter{Severities: []findings.Severity{findings.SeverityHigh}})
	if len(high) != 1 || high[0].RuleID != "SEC-001" {
		t.Fatalf("expected SEC-001 high finding, got: %+v", high)
	}

	dataRules := store.Filter(Filter{RulePattern: "DATA-*"})
	if len(dataRules) != 1 || dataRules[0].RuleID != "DATA-001" {
		t.Fatalf("expected DATA-001 finding, got: %+v", dataRules)
	}

	appFiles := store.Filter(Filter{FilePattern: "src/*"})
	if len(appFiles) != 1 || appFiles[0].Location.FilePath != "src/app.go" {
		t.Fatalf("expected src/app.go finding, got: %+v", appFiles)
	}

	if _, ok := store.ByID("F-1"); !ok {
		t.Fatal("expected to find finding F-1")
	}
}

func TestLoadFromSet(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{ID: "F-1", RuleID: "SEC-001"})

	store := LoadFromSet(fs, "/repo")
	if store.Count() != 1 {
		t.Fatalf("expected 1 finding, got %d", store.Count())
	}
	if store.BasePath() != "/repo" {
		t.Fatalf("expected base path /repo, got %s", store.BasePath())
	}
}

func TestMatchesPattern_InvalidGlob(t *testing.T) {
	if matchesPattern("abc", "[") {
		t.Fatal("expected invalid glob to return false")
	}
}
