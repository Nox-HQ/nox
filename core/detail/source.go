package detail

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// SourceLine represents a single line from a source file with its line number.
type SourceLine struct {
	Number  int    `json:"number"`
	Text    string `json:"text"`
	IsMatch bool   `json:"is_match"`
}

// SourceContext holds the lines surrounding a finding location.
type SourceContext struct {
	Lines      []SourceLine `json:"lines"`
	MatchStart int          `json:"match_start"`
	MatchEnd   int          `json:"match_end"`
}

// ReadSourceContext reads contextLines lines before and after the finding
// location from the file at basePath/location.FilePath.
// Returns nil if the file cannot be read.
func ReadSourceContext(basePath string, loc findings.Location, contextLines int) *SourceContext {
	if loc.FilePath == "" || loc.StartLine <= 0 {
		return nil
	}

	path := filepath.Join(basePath, loc.FilePath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Detect binary files by checking for null bytes.
	for _, b := range data {
		if b == 0 {
			return nil
		}
	}

	lines := strings.Split(string(data), "\n")
	totalLines := len(lines)

	startLine := loc.StartLine
	endLine := loc.EndLine
	if endLine <= 0 || endLine < startLine {
		endLine = startLine
	}

	// Calculate window bounds (1-indexed).
	windowStart := startLine - contextLines
	if windowStart < 1 {
		windowStart = 1
	}
	windowEnd := endLine + contextLines
	if windowEnd > totalLines {
		windowEnd = totalLines
	}

	var sourceLines []SourceLine
	matchStart := -1
	matchEnd := -1

	for i := windowStart; i <= windowEnd; i++ {
		isMatch := i >= startLine && i <= endLine
		if isMatch && matchStart == -1 {
			matchStart = len(sourceLines)
		}
		if isMatch {
			matchEnd = len(sourceLines)
		}
		sourceLines = append(sourceLines, SourceLine{
			Number:  i,
			Text:    lines[i-1],
			IsMatch: isMatch,
		})
	}

	return &SourceContext{
		Lines:      sourceLines,
		MatchStart: matchStart,
		MatchEnd:   matchEnd,
	}
}
