package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestComplianceISO27001WritesReviewerAndToolingArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeFindingsJSON(t, dir, []findings.Finding{{RuleID: "VULN-001", Severity: "high", Metadata: map[string]string{"fixed_in": "2.0.0"}}})
	if err := os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"a"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "evidence")

	if code := runCompliance([]string{"iso27001", dir, "--out", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	md, err := os.ReadFile(filepath.Join(out, "iso27001.md"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile(filepath.Join(out, "iso27001.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"A.8.8", "findings.json", "sbom.cdx.json", "Organizational evidence required"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	// The JSON carries the nox report marker so a later scan of this directory
	// recognises it as nox's own output instead of reading it as source.
	if !strings.Contains(string(js), `"tool_name": "nox"`) {
		t.Error("iso27001.json lacks the nox report marker")
	}
}

// TestComplianceNeedsExistingScanOutput: with no scan output the command must say what to
// run, not quietly scan, and must exit non-zero rather than emit an empty
// assessment that reads as a clean one.
func TestComplianceNeedsExistingScanOutput(t *testing.T) {
	dir := t.TempDir()
	if code := runCompliance([]string{"iso27001", dir, "--out", filepath.Join(dir, "o")}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "o")); err == nil {
		t.Error("an output directory was created for a failed run")
	}
}

func TestComplianceRejectsUnknownFramework(t *testing.T) {
	if code := runCompliance([]string{"soc9"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestComplianceAssessmentIsReproducible(t *testing.T) {
	dir := t.TempDir()
	writeFindingsJSON(t, dir, nil)
	read := func(out string) string {
		if code := runCompliance([]string{"iso27001", dir, "--out", out}); code != 0 {
			t.Fatalf("exit %d", code)
		}
		b, err := os.ReadFile(filepath.Join(out, "iso27001.json"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if read(filepath.Join(dir, "a")) != read(filepath.Join(dir, "b")) {
		t.Error("the same scan outputs produced different assessments")
	}
}
