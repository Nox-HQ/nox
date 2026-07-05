package main

import (
	"os"
	"path/filepath"
	"testing"
)

// runContentFix previews by default (never rewrites) and applies only with
// write=true, flipping each flagged line to its one secure value.
func TestRunContentFix(t *testing.T) {
	dir := t.TempDir()
	deploy := filepath.Join(dir, "deploy.yaml")
	const before = "spec:\n  securityContext:\n    privileged: true\n    runAsNonRoot: false\n"
	if err := os.WriteFile(deploy, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}

	// findings.json referencing the two fixable lines.
	findingsJSON := `{"findings":[
	  {"RuleID":"IAC-007","Severity":"critical","Location":{"FilePath":"` + deploy + `","StartLine":3}},
	  {"RuleID":"IAC-035","Severity":"high","Location":{"FilePath":"` + deploy + `","StartLine":4}}
	]}`
	inputPath := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(inputPath, []byte(findingsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Preview must not modify the file.
	if code := runContentFix(inputPath, false); code != 0 {
		t.Fatalf("preview exit = %d", code)
	}
	if got, _ := os.ReadFile(deploy); string(got) != before {
		t.Fatalf("preview modified the file:\n%s", got)
	}

	// --write applies the secure flips.
	if code := runContentFix(inputPath, true); code != 0 {
		t.Fatalf("write exit = %d", code)
	}
	const after = "spec:\n  securityContext:\n    privileged: false\n    runAsNonRoot: true\n"
	if got, _ := os.ReadFile(deploy); string(got) != after {
		t.Fatalf("write produced:\n%s\nwant:\n%s", got, after)
	}
}

// A finding whose rule has no deterministic fix is left alone.
func TestRunContentFix_NoFixForRule(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "findings.json")
	// SEC-001 (a secret) has no mechanical fix — nox never guesses a value.
	if err := os.WriteFile(inputPath, []byte(`{"findings":[{"RuleID":"SEC-001","Location":{"FilePath":"x","StartLine":1}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runContentFix(inputPath, true); code != 0 {
		t.Fatalf("exit = %d, want 0 (no-op)", code)
	}
}
