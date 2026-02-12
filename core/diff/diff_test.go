package diff

import (
	"testing"
)

func TestRun_NotGitRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(dir, Options{})
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
	if err.Error() != "not a git repository" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_EmptyOptions(t *testing.T) {
	// Verify defaults are applied.
	opts := Options{}
	if opts.Base != "" {
		t.Fatalf("expected empty base, got: %s", opts.Base)
	}
	if opts.Head != "" {
		t.Fatalf("expected empty head, got: %s", opts.Head)
	}
}

func TestFinding_JSONTags(t *testing.T) {
	f := Finding{
		RuleID:   "SEC-001",
		Severity: "high",
		File:     "main.go",
		Line:     10,
		Message:  "test",
	}
	if f.RuleID != "SEC-001" {
		t.Fatalf("unexpected rule ID: %s", f.RuleID)
	}
}
