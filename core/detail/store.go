package detail

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// Store loads and queries findings.
type Store struct {
	findings []findings.Finding
	basePath string
}

// Filter defines criteria for filtering findings.
type Filter struct {
	Severities  []findings.Severity
	RulePattern string
	FilePattern string
	// IncludeSuppressed when true includes findings with StatusSuppressed, StatusBaselined,
	// StatusVEXNotAffected, and StatusVEXFixed. Defaults to false.
	IncludeSuppressed bool
}

// LoadFromFile loads findings from a findings.json file.
func LoadFromFile(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading findings file: %w", err)
	}

	var rep report.JSONReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parsing findings JSON: %w", err)
	}

	// Derive basePath from the findings file location.
	basePath := filepath.Dir(path)

	return &Store{
		findings: rep.Findings,
		basePath: basePath,
	}, nil
}

// LoadFromSet wraps an in-memory FindingSet.
func LoadFromSet(fs *findings.FindingSet, basePath string) *Store {
	return &Store{
		findings: fs.Findings(),
		basePath: basePath,
	}
}

// Filter returns findings matching the given criteria.
func (s *Store) Filter(f Filter) []findings.Finding {
	var result []findings.Finding
	for i := range s.findings {
		finding := s.findings[i]
		if !matchesSeverity(finding.Severity, f.Severities) {
			continue
		}
		if !matchesPattern(finding.RuleID, f.RulePattern) {
			continue
		}
		if !matchesPattern(finding.Location.FilePath, f.FilePattern) {
			continue
		}
		if !f.IncludeSuppressed && !finding.Status.IsActive() {
			continue
		}
		result = append(result, finding)
	}
	return result
}

// ByID looks up a finding by its ID.
func (s *Store) ByID(id string) (findings.Finding, bool) {
	for i := range s.findings {
		finding := s.findings[i]
		if finding.ID == id {
			return finding, true
		}
	}
	return findings.Finding{}, false
}

// All returns all findings.
func (s *Store) All() []findings.Finding {
	return s.findings
}

// Count returns the total number of findings.
func (s *Store) Count() int {
	return len(s.findings)
}

// BasePath returns the base path used for source context resolution.
func (s *Store) BasePath() string {
	return s.basePath
}

func matchesSeverity(sev findings.Severity, allowed []findings.Severity) bool {
	if len(allowed) == 0 {
		return true
	}
	for i := range allowed {
		if allowed[i] == sev {
			return true
		}
	}
	return false
}

// matchesPattern matches a value against a glob-like pattern.
// Supports trailing "*" wildcard and prefix matching.
func matchesPattern(value, pattern string) bool {
	if pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	// Try filepath.Match for glob patterns, fall back to prefix match.
	if matched, err := filepath.Match(pattern, value); err == nil {
		return matched
	}
	return strings.Contains(value, pattern)
}
