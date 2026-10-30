package rules_test

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// TestPlannedMatchAgreesWithRegexp holds PlannedRegexp.Match to
// regexp.Match: through the plan, through each fallback (no plan, a fold
// outlier in the file, a plan dearer than the scan) and on content that does
// and does not match.
func TestPlannedMatchAgreesWithRegexp(t *testing.T) {
	patterns := []struct {
		pattern string
		planned bool
	}{
		{`(?m)(?:from\s+langchain|import\s+langchain|require\s*\(\s*['"]langchain|"langchain")`, true},
		{`(?i)(?:secret|token)\s*[=:]\s*\S+`, true},
		{`\b(?:apikey|api_key)\b`, true},
		{`tmc/langchaingo`, true},
		{`[a-z]+\d`, true},  // a leading class: planned from its first bytes
		{`[\w.]+\d`, false}, // too many first bytes: always the full scan
		{`^import\s+os`, false},
	}
	words := []string{
		"from ", "import ", "langchain", "require('langchain')", "\"langchain\"",
		"Secret = x", "TOKEN: abc", "apikey", "api_key", "xapikey", "tmc/langchaingo",
		"\u212aey", "\u017fecret = y", "\n", " ", "abc9", "a.b_c7", "\u00e9", "\xff",
	}
	r := rand.New(rand.NewSource(736))
	for _, tc := range patterns {
		p := rules.MustCompilePlanned(tc.pattern)
		if p.HasPlan() != tc.planned {
			t.Fatalf("%s: HasPlan() = %v, want %v", tc.pattern, p.HasPlan(), tc.planned)
		}
		re := regexp.MustCompile(tc.pattern)
		for range 5000 {
			var b strings.Builder
			for range r.Intn(12) {
				b.WriteString(words[r.Intn(len(words))])
			}
			content := []byte(b.String())
			if got, want := p.Match(content), re.Match(content); got != want {
				t.Fatalf("%s on %q: Match = %v, regexp says %v", tc.pattern, content, got, want)
			}
		}
	}
}
