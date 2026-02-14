// Package detail provides enriched finding details with source context, rule
// metadata, and related findings. It is the data layer for the "nox show"
// command, MCP tools, and the assist module.
package detail

import (
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
)

// FindingDetail is a Finding enriched with source context and rule metadata.
type FindingDetail struct {
	findings.Finding
	Source  *SourceContext    `json:"source,omitempty"`
	Rule    *catalog.RuleMeta `json:"rule,omitempty"`
	Related []RelatedFinding  `json:"related,omitempty"`
}

// RelatedFinding is a summary of a finding related to the detailed one.
type RelatedFinding struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Enrich produces a FindingDetail for the given finding.
func Enrich(f *findings.Finding, basePath string, allFindings []findings.Finding, cat map[string]catalog.RuleMeta, contextLines int) *FindingDetail {
	if f == nil {
		return nil
	}
	detail := &FindingDetail{
		Finding: *f,
	}

	// Attach source context.
	detail.Source = ReadSourceContext(basePath, f.Location, contextLines)

	// Attach rule metadata.
	if meta, ok := cat[f.RuleID]; ok {
		detail.Rule = &meta
	}

	// Find related findings (same file or same rule, excluding self).
	for i := range allFindings {
		other := allFindings[i]
		if other.ID == f.ID {
			continue
		}
		sameFile := other.Location.FilePath == f.Location.FilePath
		sameRule := other.RuleID == f.RuleID
		if sameFile || sameRule {
			detail.Related = append(detail.Related, RelatedFinding{
				ID:       other.ID,
				RuleID:   other.RuleID,
				FilePath: other.Location.FilePath,
				Line:     other.Location.StartLine,
				Message:  other.Message,
			})
		}
	}

	return detail
}
