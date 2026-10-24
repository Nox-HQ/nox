package lsp

import (
	"sort"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/remediate"
)

// Position is a zero-based line/character offset in a text document.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range is a half-open [start, end) span in a text document.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Diagnostic is an LSP diagnostic derived from a nox finding.
type Diagnostic struct {
	Range    Range  `json:"range"`
	Severity int    `json:"severity"`
	Code     string `json:"code"`
	Source   string `json:"source"`
	Message  string `json:"message"`
	// Data carries the fix plan's verdict on the finding for a client that
	// wants more than the message: whether nox can fix it, and how.
	Data *FixData `json:"data,omitempty"`
}

// FixData is the fix plan's entry for one diagnostic.
type FixData struct {
	Item    int    `json:"item"`
	Class   string `json:"class"`
	Kind    string `json:"kind"`
	Command string `json:"command,omitempty"`
}

// LSP DiagnosticSeverity values.
const (
	severityError       = 1
	severityWarning     = 2
	severityInformation = 3
	severityHint        = 4
)

// severityToLSP maps a nox severity onto an LSP DiagnosticSeverity.
func severityToLSP(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return severityError
	case findings.SeverityMedium:
		return severityWarning
	case findings.SeverityLow:
		return severityInformation
	default: // info and anything unrecognised
		return severityHint
	}
}

// findingToDiagnostic converts a single nox finding into an LSP diagnostic.
// nox locations use 1-based lines and 0-based columns; LSP uses 0-based for
// both. Negative coordinates are clamped to 0, and a non-positive-width column
// span is widened to a single character so editors always render a mark.
func findingToDiagnostic(f *findings.Finding) Diagnostic {
	loc := f.Location

	startLine := loc.StartLine - 1
	if startLine < 0 {
		startLine = 0
	}

	endLineBase := loc.StartLine
	if loc.EndLine > endLineBase {
		endLineBase = loc.EndLine
	}
	endLine := endLineBase - 1
	if endLine < 0 {
		endLine = 0
	}

	startChar := loc.StartColumn
	if startChar < 0 {
		startChar = 0
	}
	endChar := loc.EndColumn
	if endChar <= startChar {
		endChar = startChar + 1
	}

	return Diagnostic{
		Range: Range{
			Start: Position{Line: startLine, Character: startChar},
			End:   Position{Line: endLine, Character: endChar},
		},
		Severity: severityToLSP(f.Severity),
		Code:     f.RuleID,
		Source:   "nox",
		Message:  f.Message,
	}
}

// annotated adds the fix plan's verdict to a diagnostic: a sentence in the
// message an editor already shows, and the structured form in Data.
func annotated(d Diagnostic, f *findings.Finding, plan remediate.Plan) Diagnostic {
	a, ok := plan.AnnotationFor(f.Fingerprint)
	if !ok {
		return d
	}
	d.Message += "\n\nFix: " + a.Text
	d.Data = &FixData{Item: a.N, Class: string(a.Class), Kind: string(a.Kind), Command: a.Command}
	return d
}

// findingsToDiagnostics converts and stably sorts a set of findings into
// diagnostics ordered by start line, then start column, then rule id.
func findingsToDiagnostics(fs []findings.Finding) []Diagnostic {
	return findingsToDiagnosticsWithPlan(fs, remediate.Plan{})
}

// findingsToDiagnosticsWithPlan is findingsToDiagnostics with each diagnostic
// carrying what `nox fix plan` says about its finding.
func findingsToDiagnosticsWithPlan(fs []findings.Finding, plan remediate.Plan) []Diagnostic {
	diags := make([]Diagnostic, 0, len(fs))
	for i := range fs {
		diags = append(diags, annotated(findingToDiagnostic(&fs[i]), &fs[i], plan))
	}
	sort.SliceStable(diags, func(i, j int) bool {
		a, b := diags[i], diags[j]
		if a.Range.Start.Line != b.Range.Start.Line {
			return a.Range.Start.Line < b.Range.Start.Line
		}
		if a.Range.Start.Character != b.Range.Start.Character {
			return a.Range.Start.Character < b.Range.Start.Character
		}
		return a.Code < b.Code
	})
	return diags
}
