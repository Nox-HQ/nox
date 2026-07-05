package lsp

import (
	"sort"

	"github.com/nox-hq/nox/core/findings"
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

// findingsToDiagnostics converts and stably sorts a set of findings into
// diagnostics ordered by start line, then start column, then rule id.
func findingsToDiagnostics(fs []findings.Finding) []Diagnostic {
	diags := make([]Diagnostic, 0, len(fs))
	for i := range fs {
		diags = append(diags, findingToDiagnostic(&fs[i]))
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
