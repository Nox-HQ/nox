// Package annotate builds GitHub PR review payloads from security findings.
// The payload construction lives here so both CLI and MCP can use it;
// the actual GitHub API call remains in the CLI layer.
package annotate

import (
	"fmt"

	"github.com/nox-hq/nox/core/findings"
)

// ReviewComment is a single line-level comment on a PR.
type ReviewComment struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	Body string `json:"body"`
	Side string `json:"side"`
}

// ReviewPayload is the full PR review request body.
type ReviewPayload struct {
	Event    string          `json:"event"`
	Body     string          `json:"body"`
	Comments []ReviewComment `json:"comments"`
}

// BuildReviewPayload constructs a GitHub PR review payload from findings.
func BuildReviewPayload(ff []findings.Finding) *ReviewPayload {
	if len(ff) == 0 {
		return nil
	}

	var comments []ReviewComment
	for i := range ff {
		badge := SeverityBadge(ff[i].Severity)
		body := fmt.Sprintf("%s **%s** `%s`\n\n%s", badge, ff[i].Severity, ff[i].RuleID, ff[i].Message)

		c := ReviewComment{
			Path: ff[i].Location.FilePath,
			Body: body,
			Side: "RIGHT",
		}
		if ff[i].Location.StartLine > 0 {
			c.Line = ff[i].Location.StartLine
		}
		comments = append(comments, c)
	}

	return &ReviewPayload{
		Event:    "COMMENT",
		Body:     fmt.Sprintf("Nox found **%d finding(s)** in this PR.", len(ff)),
		Comments: comments,
	}
}

// SeverityBadge returns a GitHub-flavored emoji badge for the given severity.
func SeverityBadge(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical:
		return ":red_circle:"
	case findings.SeverityHigh:
		return ":orange_circle:"
	case findings.SeverityMedium:
		return ":yellow_circle:"
	case findings.SeverityLow:
		return ":large_blue_circle:"
	default:
		return ":white_circle:"
	}
}
