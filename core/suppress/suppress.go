// Package suppress provides inline suppression detection for nox findings.
// Developers can suppress specific rules by adding comments like:
//
//	// nox:ignore SEC-001 -- false positive in test
//	# nox:ignore SEC-001,SEC-002
//	<!-- nox:ignore AI-001 -->
//	/* nox:ignore IAC-001 */
//	-- nox:ignore DEP-001 -- known issue expires:2025-12-31
package suppress

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
	"time"
)

// Suppression represents a single inline suppression directive found in source.
type Suppression struct {
	RuleIDs  []string
	FilePath string
	Line     int // the line the suppression applies to
	Reason   string
	Expires  *time.Time
}

// suppressionRE matches nox:ignore directives in any comment style.
var suppressionRE = regexp.MustCompile(
	`(?://|#|--|/\*|<!--)\s*nox:ignore\s+([\w-]+(?:,[\w-]+)*)\s*(?:--\s*(.*))?`,
)

// expiresRE extracts an expires:YYYY-MM-DD from the reason text.
var expiresRE = regexp.MustCompile(`expires:(\d{4}-\d{2}-\d{2})`)

// ScanForSuppressions scans file content for nox:ignore directives and returns
// all suppressions found. Each suppression targets either the same line
// (trailing comment) or the next non-blank, non-comment line.
func ScanForSuppressions(content []byte, filePath string) []Suppression {
	var result []Suppression

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for i, line := range lines {
		lineNum := i + 1
		match := suppressionRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		ruleIDs := strings.Split(match[1], ",")
		reason := strings.TrimSpace(match[2])

		// Clean up reason: remove closing comment markers.
		reason = strings.TrimSuffix(reason, "*/")
		reason = strings.TrimSuffix(reason, "-->")
		reason = strings.TrimSpace(reason)

		// Parse expiration from reason.
		var expires *time.Time
		if em := expiresRE.FindStringSubmatch(reason); em != nil {
			if t, err := time.Parse("2006-01-02", em[1]); err == nil {
				expires = &t
			}
			reason = strings.TrimSpace(expiresRE.ReplaceAllString(reason, ""))
		}

		// Determine target line: if the line is only a comment (suppression
		// directive), it applies to the next non-blank line. If the suppression
		// is a trailing comment on a code line, it applies to the same line.
		targetLine := lineNum
		trimmed := strings.TrimSpace(line)
		if isOnlyComment(trimmed) {
			targetLine = nextNonBlankLine(lines, i)
		}

		result = append(result, Suppression{
			RuleIDs:  ruleIDs,
			FilePath: filePath,
			Line:     targetLine,
			Reason:   reason,
			Expires:  expires,
		})
	}

	return result
}

// MatchesFinding returns true if this suppression applies to the given rule
// and line, considering expiration.
func (s Suppression) MatchesFinding(ruleID string, line int, now time.Time) bool {
	if s.Line != line {
		return false
	}
	if s.Expires != nil && now.After(*s.Expires) {
		return false
	}
	for _, id := range s.RuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

// isOnlyComment returns true if the line consists entirely of a comment.
func isOnlyComment(trimmed string) bool {
	for _, prefix := range []string{"//", "#", "--", "/*", "<!--"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// nextNonBlankLine returns the 1-based line number of the next non-blank,
// non-comment line after index i. If none exists, returns i+2 (the line
// immediately after the comment).
func nextNonBlankLine(lines []string, i int) int {
	for j := i + 1; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" {
			continue
		}
		if isOnlyComment(trimmed) && suppressionRE.MatchString(trimmed) {
			continue
		}
		return j + 1
	}
	return i + 2
}
