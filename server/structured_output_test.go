package server

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/report"

	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/diff"
	mcp "go.klarlabs.de/mcp"
	"go.klarlabs.de/mcp/schema"
)

// textOf concatenates the text content blocks of a StructuredResult. The
// converted tool handlers put their JSON rendering (or an "Error: ..." message)
// in text content, so tests can assert on it exactly as they did when the
// handlers returned a plain string.
func textOf(r mcp.StructuredResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// TestStructuredOutputSchemasGenerate guards the failure mode of OutputSchema:
// ToolBuilder.OutputSchema calls schema.Generate, and if that errors the
// builder short-circuits and the tool is never registered — silently. The
// direct-call handler tests would not catch that (they bypass registration),
// so assert here that every advertised output type generates a schema cleanly.
func TestStructuredOutputSchemasGenerate(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"summary", summaryOutput{}},
		{"list_findings", listFindingsOutput{}},
		{"baseline_status", baselineStatusOutput{}},
		{"data_sensitivity_report", report.DataSensitivityReport{}},
		{"get_finding_detail", detail.FindingDetail{}},
		{"get_finding_by_fingerprint", fingerprintLookupOutput{}},
		{"diff", diff.Result{}},
		{"rules", rulesOutput{}},
		{"vex_status", vexStatusOutput{}},
		{"fix_plan", fixPlanResponse{}},
		{"version", versionOutput{}},
	}
	for _, c := range cases {
		if _, err := schema.Generate(c.v); err != nil {
			t.Errorf("OutputSchema(%s): schema.Generate failed, so the tool would silently not register: %v", c.name, err)
		}
	}
}

// TestStructuredResultCarriesTypedContent confirms the structured() helper
// emits both a JSON text rendering and structuredContent, and that toolError
// flags isError while preserving the "Error: " text prefix the tests rely on.
func TestStructuredResultCarriesTypedContent(t *testing.T) {
	res, err := structured(summaryOutput{ActiveFindings: 3, BySeverity: map[string]int{"high": 3}})
	if err != nil {
		t.Fatalf("structured: %v", err)
	}
	if res.IsError {
		t.Error("structured result unexpectedly flagged isError")
	}
	if res.StructuredContent == nil {
		t.Fatal("structuredContent must be populated for a structured tool")
	}
	if got, ok := res.StructuredContent["active_findings"].(float64); !ok || got != 3 {
		t.Errorf("structuredContent[active_findings] = %v, want 3", res.StructuredContent["active_findings"])
	}
	if !strings.Contains(textOf(res), `"active_findings": 3`) {
		t.Errorf("text content missing JSON rendering: %s", textOf(res))
	}

	e := toolError("no scan results available")
	if !e.IsError {
		t.Error("toolError must flag isError")
	}
	if !strings.HasPrefix(textOf(e), "Error:") {
		t.Errorf("toolError text = %q, want an \"Error:\" prefix", textOf(e))
	}
}
