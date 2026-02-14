package detail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func TestReadSourceContext(t *testing.T) {
	// Create a temp file with known content.
	dir := t.TempDir()
	content := "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n"
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	loc := findings.Location{
		FilePath:  "test.txt",
		StartLine: 5,
		EndLine:   5,
	}

	ctx := ReadSourceContext(dir, loc, 2)
	if ctx == nil {
		t.Fatal("ReadSourceContext returned nil")
	}

	// Should have lines 3-7 (2 before + match + 2 after).
	if got := len(ctx.Lines); got != 5 {
		t.Errorf("got %d lines, want 5", got)
	}

	// Check match indices.
	if ctx.MatchStart != 2 {
		t.Errorf("MatchStart = %d, want 2", ctx.MatchStart)
	}
	if ctx.MatchEnd != 2 {
		t.Errorf("MatchEnd = %d, want 2", ctx.MatchEnd)
	}

	// Check that the match line is correct.
	if ctx.Lines[2].Text != "line5" {
		t.Errorf("match line text = %q, want %q", ctx.Lines[2].Text, "line5")
	}
	if !ctx.Lines[2].IsMatch {
		t.Error("match line IsMatch = false, want true")
	}
	if ctx.Lines[0].IsMatch {
		t.Error("context line IsMatch = true, want false")
	}
}

func TestReadSourceContextMissingFile(t *testing.T) {
	loc := findings.Location{
		FilePath:  "nonexistent.txt",
		StartLine: 1,
		EndLine:   1,
	}
	ctx := ReadSourceContext(t.TempDir(), loc, 3)
	if ctx != nil {
		t.Error("expected nil for missing file")
	}
}

func TestReadSourceContext_BinaryFile(t *testing.T) {
	dir := t.TempDir()
	// Write a file with null bytes to trigger binary detection.
	binaryContent := []byte("line1\nline2\x00binary\nline4\n")
	if err := os.WriteFile(filepath.Join(dir, "binary.dat"), binaryContent, 0o644); err != nil {
		t.Fatal(err)
	}

	loc := findings.Location{
		FilePath:  "binary.dat",
		StartLine: 1,
		EndLine:   1,
	}
	ctx := ReadSourceContext(dir, loc, 2)
	if ctx != nil {
		t.Error("expected nil for binary file, got non-nil")
	}
}

func TestReadSourceContextEmptyLocation(t *testing.T) {
	ctx := ReadSourceContext(t.TempDir(), findings.Location{}, 3)
	if ctx != nil {
		t.Error("expected nil for empty location")
	}
}

func TestEnrich(t *testing.T) {
	dir := t.TempDir()
	content := "line1\nline2\nAKIA0123456789012345\nline4\nline5\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	f := findings.Finding{
		ID:       "SEC-001:config.env:3",
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{
			FilePath:  "config.env",
			StartLine: 3,
			EndLine:   3,
		},
		Message: "AWS Access Key ID detected",
	}

	other := findings.Finding{
		ID:       "SEC-002:config.env:4",
		RuleID:   "SEC-002",
		Severity: findings.SeverityCritical,
		Location: findings.Location{
			FilePath:  "config.env",
			StartLine: 4,
			EndLine:   4,
		},
		Message: "AWS Secret Access Key detected",
	}

	cat := catalog.Catalog()
	detail := Enrich(&f, dir, []findings.Finding{f, other}, cat, 2)

	if detail.Source == nil {
		t.Error("expected non-nil Source")
	}
	if detail.Rule == nil {
		t.Fatal("expected non-nil Rule")
	}
	if detail.Rule.ID != "SEC-001" {
		t.Errorf("Rule.ID = %q, want %q", detail.Rule.ID, "SEC-001")
	}
	if detail.Rule.Remediation == "" {
		t.Error("expected non-empty Rule.Remediation")
	}
	if len(detail.Related) != 1 {
		t.Errorf("got %d related findings, want 1", len(detail.Related))
	}
}

func TestStoreFilter(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "SEC-001:a.env:1", RuleID: "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "a.env", StartLine: 1},
		Message:  "test",
	})
	fs.Add(findings.Finding{
		ID: "AI-004:mcp.json:5", RuleID: "AI-004",
		Severity: findings.SeverityCritical,
		Location: findings.Location{FilePath: "mcp.json", StartLine: 5},
		Message:  "test",
	})
	fs.Add(findings.Finding{
		ID: "IAC-001:Dockerfile:3", RuleID: "IAC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "Dockerfile", StartLine: 3},
		Message:  "test",
	})

	store := LoadFromSet(fs, ".")

	// Filter by severity.
	critical := store.Filter(Filter{Severities: []findings.Severity{findings.SeverityCritical}})
	if len(critical) != 1 {
		t.Errorf("critical filter: got %d, want 1", len(critical))
	}

	// Filter by rule pattern.
	secRules := store.Filter(Filter{RulePattern: "SEC-*"})
	if len(secRules) != 1 {
		t.Errorf("SEC-* filter: got %d, want 1", len(secRules))
	}

	// Filter by file pattern.
	dockerFiles := store.Filter(Filter{FilePattern: "Dockerfile"})
	if len(dockerFiles) != 1 {
		t.Errorf("Dockerfile filter: got %d, want 1", len(dockerFiles))
	}

	// No filter returns all.
	all := store.Filter(Filter{})
	if len(all) != 3 {
		t.Errorf("no filter: got %d, want 3", len(all))
	}
}

func TestStoreByID(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "SEC-001:a.env:1", RuleID: "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "a.env", StartLine: 1},
		Message:  "test",
	})

	store := LoadFromSet(fs, ".")

	f, ok := store.ByID("SEC-001:a.env:1")
	if !ok {
		t.Fatal("ByID did not find finding")
	}
	if f.RuleID != "SEC-001" {
		t.Errorf("got RuleID %q, want %q", f.RuleID, "SEC-001")
	}

	_, ok = store.ByID("nonexistent")
	if ok {
		t.Error("ByID found nonexistent finding")
	}
}

// ---------------------------------------------------------------------------
// LoadFromFile tests (0% → covered)
// ---------------------------------------------------------------------------

func TestLoadFromFile_Valid(t *testing.T) {
	dir := t.TempDir()
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "SEC-001:a.go:1", RuleID: "SEC-001",
		Severity: findings.SeverityHigh,
		Location: findings.Location{FilePath: "a.go", StartLine: 1},
		Message:  "test finding",
	})

	// Write a valid findings.json using the JSONReporter.
	rep := report.NewJSONReporter("test")
	data, err := rep.Generate(fs)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("expected 1 finding, got %d", store.Count())
	}
	if store.BasePath() != dir {
		t.Errorf("BasePath = %q, want %q", store.BasePath(), dir)
	}
}

func TestLoadFromFile_NonexistentPath(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/findings.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// All, Count, BasePath tests (0% → covered)
// ---------------------------------------------------------------------------

func TestStoreAllCountBasePath(t *testing.T) {
	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{
		ID: "A:f:1", RuleID: "A",
		Severity: findings.SeverityLow,
		Location: findings.Location{FilePath: "f", StartLine: 1},
		Message:  "m",
	})
	fs.Add(findings.Finding{
		ID: "B:g:2", RuleID: "B",
		Severity: findings.SeverityMedium,
		Location: findings.Location{FilePath: "g", StartLine: 2},
		Message:  "m2",
	})

	store := LoadFromSet(fs, "/my/base")

	all := store.All()
	if len(all) != 2 {
		t.Fatalf("All() returned %d findings, want 2", len(all))
	}
	if store.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", store.Count())
	}
	if store.BasePath() != "/my/base" {
		t.Errorf("BasePath() = %q, want %q", store.BasePath(), "/my/base")
	}
}

// ---------------------------------------------------------------------------
// matchesPattern edge cases
// ---------------------------------------------------------------------------

func TestMatchesPattern_GlobError(t *testing.T) {
	// filepath.Match returns an error for invalid patterns like "[".
	// matchesPattern should fall back to substring matching.
	got := matchesPattern("abc[def", "[")
	if !got {
		t.Error("expected substring fallback to match")
	}
}

func TestMatchesPattern_NoMatch(t *testing.T) {
	got := matchesPattern("hello.go", "*.py")
	if got {
		t.Error("expected no match for *.py against hello.go")
	}
}

// ---------------------------------------------------------------------------
// LoadFromFile round-trip with real JSON structure
// ---------------------------------------------------------------------------

func TestLoadFromFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := []findings.Finding{
		{
			ID: "SEC-001:test.go:5", RuleID: "SEC-001",
			Severity: findings.SeverityHigh,
			Location: findings.Location{FilePath: "test.go", StartLine: 5},
			Message:  "secret detected",
		},
		{
			ID: "IAC-001:Dockerfile:10", RuleID: "IAC-001",
			Severity: findings.SeverityMedium,
			Location: findings.Location{FilePath: "Dockerfile", StartLine: 10},
			Message:  "unpinned base image",
		},
	}

	// Write findings manually in the report.JSONReport format.
	rep := report.JSONReport{
		Meta: report.Meta{
			SchemaVersion: "1.0.0",
			ToolName:      "nox",
			ToolVersion:   "test",
		},
		Findings: original,
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if store.Count() != 2 {
		t.Fatalf("Count = %d, want 2", store.Count())
	}

	// Verify we can look up by ID.
	f, ok := store.ByID("SEC-001:test.go:5")
	if !ok {
		t.Fatal("expected to find SEC-001:test.go:5")
	}
	if f.Message != "secret detected" {
		t.Errorf("message = %q, want %q", f.Message, "secret detected")
	}
}
