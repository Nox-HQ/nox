package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sampleFindingSet returns a FindingSet with two findings added in reverse
// order (rule-002 before rule-001) so tests can verify deterministic sorting.
func sampleFindingSet() *findings.FindingSet {
	fs := findings.NewFindingSet()

	fs.Add(findings.Finding{
		ID:         "f-2",
		RuleID:     "rule-002",
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceHigh,
		Location: findings.Location{
			FilePath:    "pkg/auth/handler.go",
			StartLine:   42,
			EndLine:     42,
			StartColumn: 10,
			EndColumn:   35,
		},
		Message:  "Insecure comparison of secret token",
		Metadata: map[string]string{"category": "crypto"},
	})

	fs.Add(findings.Finding{
		ID:         "f-1",
		RuleID:     "rule-001",
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceMedium,
		Location: findings.Location{
			FilePath:    "cmd/server/main.go",
			StartLine:   15,
			EndLine:     15,
			StartColumn: 1,
			EndColumn:   40,
		},
		Message:  "Hardcoded credential detected",
		Metadata: map[string]string{"category": "secrets"},
	})

	return fs
}

// sampleRuleSet returns a RuleSet with two rules matching the sample findings.
func sampleRuleSet() *rules.RuleSet {
	rs := rules.NewRuleSet()

	rs.Add(rules.Rule{
		ID:          "rule-001",
		Version:     "1.0.0",
		Description: "Detects hardcoded credentials in source files",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		MatcherType: "regex",
		Pattern:     `(?i)(password|secret|token)\s*=\s*"[^"]{8,}"`,
		Tags:        []string{"secrets", "security"},
		Metadata:    map[string]string{"cwe": "CWE-798"},
	})

	rs.Add(rules.Rule{
		ID:          "rule-002",
		Version:     "1.0.0",
		Description: "Detects insecure comparison of secret values",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		MatcherType: "regex",
		Pattern:     `==\s*(secret|token|password)`,
		Tags:        []string{"crypto", "security"},
		Metadata:    map[string]string{"cwe": "CWE-208"},
	})

	return rs
}

// mustUnmarshal unmarshals JSON bytes into a Report or fails the test.
func mustUnmarshal(t *testing.T, data []byte) Report {
	t.Helper()
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to unmarshal SARIF report: %v", err)
	}
	return report
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGenerateProducesValidJSONWithCorrectVersion(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	// Verify it is valid JSON.
	if !json.Valid(data) {
		t.Fatal("Generate produced invalid JSON")
	}

	report := mustUnmarshal(t, data)

	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", report.Version)
	}

	if report.Schema == "" {
		t.Error("expected $schema to be non-empty")
	}
}

func TestToolDriverHasCorrectNameAndVersion(t *testing.T) {
	r := NewReporter("1.2.3", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	driver := report.Runs[0].Tool.Driver

	if driver.Name != "nox" {
		t.Errorf("expected driver name 'nox', got %q", driver.Name)
	}

	if driver.Version != "1.2.3" {
		t.Errorf("expected driver version '1.2.3', got %q", driver.Version)
	}

	if driver.InformationURI == "" {
		t.Error("expected informationUri to be non-empty")
	}
}

func TestFindingsMapToCorrectSARIFLevels(t *testing.T) {
	tests := []struct {
		name     string
		severity findings.Severity
		want     string
	}{
		{"critical maps to error", findings.SeverityCritical, "error"},
		{"high maps to error", findings.SeverityHigh, "error"},
		{"medium maps to warning", findings.SeverityMedium, "warning"},
		{"low maps to note", findings.SeverityLow, "note"},
		{"info maps to note", findings.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityToLevel(tt.severity)
			if got != tt.want {
				t.Errorf("severityToLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestResultsHaveCorrectLevels(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	results := report.Runs[0].Results

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// After deterministic sorting, rule-001 (high) comes first, then
	// rule-002 (medium).
	levelByRule := make(map[string]string)
	for _, res := range results {
		levelByRule[res.RuleID] = res.Level
	}

	if levelByRule["rule-001"] != "error" {
		t.Errorf("rule-001 (high severity) expected level 'error', got %q", levelByRule["rule-001"])
	}

	if levelByRule["rule-002"] != "warning" {
		t.Errorf("rule-002 (medium severity) expected level 'warning', got %q", levelByRule["rule-002"])
	}
}

func TestLocationsContainCorrectFileAndPosition(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	results := report.Runs[0].Results

	// Find the result for rule-001 which is in cmd/server/main.go.
	var rule001Result *Result
	for i := range results {
		if results[i].RuleID == "rule-001" {
			rule001Result = &results[i]
			break
		}
	}

	if rule001Result == nil {
		t.Fatal("could not find result for rule-001")
	}

	if len(rule001Result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(rule001Result.Locations))
	}

	loc := rule001Result.Locations[0].PhysicalLocation

	if loc.ArtifactLocation.URI != "cmd/server/main.go" {
		t.Errorf("expected URI 'cmd/server/main.go', got %q", loc.ArtifactLocation.URI)
	}

	if loc.Region.StartLine != 15 {
		t.Errorf("expected StartLine 15, got %d", loc.Region.StartLine)
	}

	if loc.Region.StartColumn != 1 {
		t.Errorf("expected StartColumn 1, got %d", loc.Region.StartColumn)
	}

	if loc.Region.EndLine != 15 {
		t.Errorf("expected EndLine 15, got %d", loc.Region.EndLine)
	}

	if loc.Region.EndColumn != 40 {
		t.Errorf("expected EndColumn 40, got %d", loc.Region.EndColumn)
	}
}

func TestFingerprintsAreIncludedInResults(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	results := report.Runs[0].Results

	for _, res := range results {
		if res.Fingerprints == nil {
			t.Errorf("result for %s has nil fingerprints map", res.RuleID)
			continue
		}

		fp, ok := res.Fingerprints["nox/v1"]
		if !ok {
			t.Errorf("result for %s missing 'nox/v1' fingerprint key", res.RuleID)
			continue
		}

		if fp == "" {
			t.Errorf("result for %s has empty fingerprint value", res.RuleID)
		}
	}
}

func TestRuleCatalogPopulatedFromRuleSet(t *testing.T) {
	rs := sampleRuleSet()
	r := NewReporter("0.1.0", rs)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	driver := report.Runs[0].Tool.Driver

	if len(driver.Rules) != 2 {
		t.Fatalf("expected 2 rules in catalog, got %d", len(driver.Rules))
	}

	// Rules should be sorted by ID.
	if driver.Rules[0].ID != "rule-001" {
		t.Errorf("expected first rule ID 'rule-001', got %q", driver.Rules[0].ID)
	}
	if driver.Rules[1].ID != "rule-002" {
		t.Errorf("expected second rule ID 'rule-002', got %q", driver.Rules[1].ID)
	}

	// Verify descriptions come from the RuleSet, not from findings.
	if driver.Rules[0].ShortDescription.Text != "Detects hardcoded credentials in source files" {
		t.Errorf("expected rule-001 description from RuleSet, got %q", driver.Rules[0].ShortDescription.Text)
	}

	// Verify default configuration levels.
	if driver.Rules[0].DefaultConfiguration.Level != "error" {
		t.Errorf("expected rule-001 default level 'error', got %q", driver.Rules[0].DefaultConfiguration.Level)
	}
	if driver.Rules[1].DefaultConfiguration.Level != "warning" {
		t.Errorf("expected rule-002 default level 'warning', got %q", driver.Rules[1].DefaultConfiguration.Level)
	}

	// Verify properties (metadata) are carried over.
	if driver.Rules[0].Properties == nil {
		t.Fatal("expected rule-001 to have properties from metadata")
	}
	if driver.Rules[0].Properties["cwe"] != "CWE-798" {
		t.Errorf("expected rule-001 properties[cwe] = 'CWE-798', got %q", driver.Rules[0].Properties["cwe"])
	}
}

func TestRuleCatalogFromFindingsWhenNoRuleSet(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	driver := report.Runs[0].Tool.Driver

	if len(driver.Rules) != 2 {
		t.Fatalf("expected 2 rules in catalog, got %d", len(driver.Rules))
	}

	// Rules should be sorted by ID even when derived from findings.
	if driver.Rules[0].ID != "rule-001" {
		t.Errorf("expected first rule 'rule-001', got %q", driver.Rules[0].ID)
	}
	if driver.Rules[1].ID != "rule-002" {
		t.Errorf("expected second rule 'rule-002', got %q", driver.Rules[1].ID)
	}
}

func TestRuleIndexInResultsMatchesCatalog(t *testing.T) {
	rs := sampleRuleSet()
	r := NewReporter("0.1.0", rs)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	driver := report.Runs[0].Tool.Driver
	results := report.Runs[0].Results

	// Build a lookup from rule ID to catalog index.
	catalogIndex := make(map[string]int)
	for i, rd := range driver.Rules {
		catalogIndex[rd.ID] = i
	}

	for _, res := range results {
		expected, ok := catalogIndex[res.RuleID]
		if !ok {
			t.Errorf("result references rule %q not in catalog", res.RuleID)
			continue
		}
		if res.RuleIndex != expected {
			t.Errorf("result for %s has ruleIndex %d, expected %d", res.RuleID, res.RuleIndex, expected)
		}
	}
}

func TestEmptyFindingSetProducesValidSARIF(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := findings.NewFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !json.Valid(data) {
		t.Fatal("Generate produced invalid JSON for empty FindingSet")
	}

	report := mustUnmarshal(t, data)

	if report.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %q", report.Version)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	results := report.Runs[0].Results
	if results == nil {
		t.Error("expected results to be non-nil (empty slice)")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}

	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty findings, got %d", len(rules))
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	r := NewReporter("0.1.0", nil)

	fs1 := sampleFindingSet()
	data1, err := r.Generate(fs1)
	if err != nil {
		t.Fatalf("first Generate returned error: %v", err)
	}

	fs2 := sampleFindingSet()
	data2, err := r.Generate(fs2)
	if err != nil {
		t.Fatalf("second Generate returned error: %v", err)
	}

	// SARIF output has no timestamp, so byte-level comparison is valid.
	if string(data1) != string(data2) {
		t.Errorf("outputs are not deterministic:\n  first:  %s\n  second: %s", data1, data2)
	}
}

func TestGenerateSortsFindingsDeterministically(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	results := report.Runs[0].Results

	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}

	// Findings were added as rule-002 then rule-001. After deterministic
	// sorting, rule-001 must come first.
	if results[0].RuleID != "rule-001" {
		t.Errorf("expected first result rule-001, got %q", results[0].RuleID)
	}
	if results[1].RuleID != "rule-002" {
		t.Errorf("expected second result rule-002, got %q", results[1].RuleID)
	}
}

func TestWriteToFileCreatesValidSARIFFile(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	dir := t.TempDir()
	path := filepath.Join(dir, "report.sarif")

	if err := r.WriteToFile(fs, path); err != nil {
		t.Fatalf("WriteToFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read written file: %v", err)
	}

	report := mustUnmarshal(t, data)

	if report.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0 in file, got %q", report.Version)
	}

	if len(report.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results in file, got %d", len(report.Runs[0].Results))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("could not stat written file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("expected file permissions 0644, got %04o", perm)
	}
}

func TestReporterImplementsReporterInterface(t *testing.T) {
	// Compile-time verification that Reporter satisfies report.Reporter.
	// This is a type assertion at the package level. We verify it here
	// indirectly by calling Generate through the interface.
	r := NewReporter("0.1.0", nil)
	fs := findings.NewFindingSet()

	// This call would fail to compile if Reporter did not implement
	// the Generate method with the correct signature.
	_, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate via Reporter interface returned error: %v", err)
	}
}

func TestSeverityToLevelUnknownSeverity(t *testing.T) {
	// An unknown severity should default to "note".
	got := severityToLevel(findings.Severity("unknown"))
	if got != "note" {
		t.Errorf("severityToLevel(unknown) = %q, want 'note'", got)
	}
}

func TestResultMessageMatchesFindingMessage(t *testing.T) {
	r := NewReporter("0.1.0", nil)
	fs := sampleFindingSet()

	data, err := r.Generate(fs)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	report := mustUnmarshal(t, data)
	results := report.Runs[0].Results

	messageByRule := make(map[string]string)
	for _, res := range results {
		messageByRule[res.RuleID] = res.Message.Text
	}

	if messageByRule["rule-001"] != "Hardcoded credential detected" {
		t.Errorf("unexpected message for rule-001: %q", messageByRule["rule-001"])
	}

	if messageByRule["rule-002"] != "Insecure comparison of secret token" {
		t.Errorf("unexpected message for rule-002: %q", messageByRule["rule-002"])
	}
}
