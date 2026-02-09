package detail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
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
	detail := Enrich(f, dir, []findings.Finding{f, other}, cat, 2)

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
