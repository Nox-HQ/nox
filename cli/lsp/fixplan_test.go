package lsp

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/remediate"
)

// An editor diagnostic carries what `nox fix plan` says about its finding, from
// the same plan, so the editor and the terminal cannot disagree.
func TestDiagnosticsCarryTheFixPlan(t *testing.T) {
	taint := findings.Finding{
		RuleID: "TAINT-AI-001", Severity: findings.SeverityHigh, Message: "Untrusted input reaches a prompt",
		Location:    findings.Location{FilePath: "assistant.js", StartLine: 9},
		Fingerprint: "fp-taint",
		Metadata:    map[string]string{"vuln_class": "prompt_injection"},
	}
	ff := []findings.Finding{taint}
	diags := findingsToDiagnosticsWithPlan(ff, remediate.Build(remediate.Input{Findings: ff}))

	if len(diags) != 1 || diags[0].Data == nil {
		t.Fatalf("diagnostic has no fix data: %+v", diags)
	}
	if diags[0].Data.Class != string(remediate.ClassInfo) {
		t.Errorf("class = %q, want %q", diags[0].Data.Class, remediate.ClassInfo)
	}
	if !strings.HasPrefix(diags[0].Message, "Untrusted input reaches a prompt\n\nFix: nox cannot fix this automatically.") {
		t.Errorf("message = %q", diags[0].Message)
	}
}

// With no plan the diagnostics are exactly what they were.
func TestDiagnosticsWithoutAPlanAreUnchanged(t *testing.T) {
	f := findings.Finding{RuleID: "X-1", Message: "m", Fingerprint: "fp"}
	d := findingsToDiagnostics([]findings.Finding{f})[0]
	if d.Data != nil || d.Message != "m" {
		t.Fatalf("diagnostic changed without a plan: %+v", d)
	}
}
