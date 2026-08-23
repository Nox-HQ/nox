package server

import (
	"encoding/json"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	mcp "go.klarlabs.de/mcp"
)

// structured renders a typed output value as an MCP StructuredResult: the same
// value is emitted both as indented JSON text (so text-only clients are
// unchanged) and as structuredContent matching the tool's advertised
// outputSchema. Structured clients get typed data they can consume without
// parsing free text. Marshalling errors degrade to an isError result rather
// than a transport error, matching the tools' existing fail-soft convention.
func structured(v any) (mcp.StructuredResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError("marshalling result: " + err.Error()), nil
	}
	var sc map[string]any
	if err := json.Unmarshal(data, &sc); err != nil {
		return toolError("structuring result: " + err.Error()), nil
	}
	return mcp.StructuredResult{
		Content:           []mcp.Content{mcp.NewTextContent(string(data))},
		StructuredContent: sc,
	}, nil
}

// toolError renders a tool-level error as an isError StructuredResult, keeping
// the human-readable "Error: ..." text visible to the model while signalling
// isError to structured clients. The text mirrors the string the handlers
// previously returned, so existing text-based callers are unaffected.
func toolError(msg string) mcp.StructuredResult {
	return mcp.StructuredResult{
		Content: []mcp.Content{mcp.NewTextContent("Error: " + msg)},
		IsError: true,
	}
}

// The output types below are the single source of truth for both a handler's
// result value and the outputSchema advertised for its tool — build the struct,
// hand it to structured(), and pass a zero value to OutputSchema().

// summaryOutput is the aggregate overview returned by the "summary" tool.
type summaryOutput struct {
	ActiveFindings int            `json:"active_findings"`
	TotalFindings  int            `json:"total_findings"`
	Suppressed     int            `json:"suppressed"`
	BySeverity     map[string]int `json:"by_severity"`
	ByConfidence   map[string]int `json:"by_confidence"`
	ByFamily       map[string]int `json:"by_family"`
	Dependencies   int            `json:"dependencies"`
	AIComponents   int            `json:"ai_components"`
}

// enrichedFinding is a scan finding joined with its rule catalog metadata.
type enrichedFinding struct {
	findings.Finding
	Rule *catalog.RuleMeta `json:"rule,omitempty"`
}

// listFindingsOutput is the paginated envelope returned by "list_findings": it
// reports the total match count and whether more pages remain, so a caller
// paging through results is never handed a silently truncated slice.
type listFindingsOutput struct {
	Total    int               `json:"total"`
	Offset   int               `json:"offset"`
	Limit    int               `json:"limit"`
	Returned int               `json:"returned"`
	HasMore  bool              `json:"has_more"`
	Findings []enrichedFinding `json:"findings"`
}

// baselineStatusOutput is the baseline overview returned by "baseline_status".
type baselineStatusOutput struct {
	Total      int            `json:"total"`
	Expired    int            `json:"expired"`
	BySeverity map[string]int `json:"by_severity"`
	Path       string         `json:"path"`
}

// fingerprintLookupOutput is the single-finding status lookup returned by
// "get_finding_by_fingerprint". Found is always emitted (so a caller can
// distinguish a miss from a hit); the remaining fields are populated only on a
// match, keeping the not-found response to {found:false, fingerprint}.
type fingerprintLookupOutput struct {
	Found       bool                `json:"found"`
	ID          string              `json:"id,omitempty"`
	Fingerprint string              `json:"fingerprint,omitempty"`
	RuleID      string              `json:"rule_id,omitempty"`
	Severity    findings.Severity   `json:"severity,omitempty"`
	Confidence  findings.Confidence `json:"confidence,omitempty"`
	Status      findings.Status     `json:"status,omitempty"`
	Message     string              `json:"message,omitempty"`
	Location    *findings.Location  `json:"location,omitempty"`
}

// rulesOutput is the rule-catalog listing returned by "rules". The catalog is
// keyed by rule ID internally; the tool exposes it as a stable, ID-sorted slice
// inside an envelope so structured clients get an array they can iterate plus a
// total, rather than an unordered object.
type rulesOutput struct {
	Total int                `json:"total"`
	Rules []catalog.RuleMeta `json:"rules"`
}

// vexStatusOutput is the VEX document summary returned by "vex_status": the
// statement count, a per-status breakdown, and a human-readable summary line.
type vexStatusOutput struct {
	Path       string         `json:"path"`
	Statements int            `json:"statements"`
	ByStatus   map[string]int `json:"by_status"`
	Summary    string         `json:"summary"`
}

// versionOutput is the server version returned by "version".
type versionOutput struct {
	Version string `json:"version"`
}
