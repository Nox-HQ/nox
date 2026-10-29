package rules

import (
	"path/filepath"
	"testing"
)

// globMatches is the decision fileMatchesRule made before patterns were
// compiled: a pattern applies when filepath.Match accepts the path or its base.
func globMatches(pattern, path string) bool {
	if m, _ := filepath.Match(pattern, path); m {
		return true
	}
	m, _ := filepath.Match(pattern, filepath.Base(path))
	return m
}

// TestCompiledFilePatternsMatchLikeFilepathMatch is #736: the rule loop called
// filepath.Match twice per pattern, per rule, per file — 7.6% of scan CPU on
// crewAI's 30,000 files. Most patterns are `*.ext` or a plain file name, which
// a suffix or equality test answers without the glob machinery. The compiled
// form must decide exactly as filepath.Match did, for every pattern shape.
func TestCompiledFilePatternsMatchLikeFilepathMatch(t *testing.T) {
	patterns := []string{
		"*.py", "*.yaml", "*.test.ts", "*_test.go", "*", "*.", "Dockerfile",
		"docker-compose.yml", "testdata/*", "*.md", "Dockerfile.*", "*.tf*",
		"[Mm]akefile", "go.?um", "a\\*b", ".env", "*.env", "pkg/*.go", "",
	}
	paths := []string{
		"main.py", "a/b/main.py", "x.yaml", "deep/x.yaml", "app.test.ts",
		"src/app.test.ts", "foo_test.go", "pkg/foo_test.go", "Dockerfile",
		"svc/Dockerfile", "Dockerfile.dev", "docker-compose.yml",
		"deploy/docker-compose.yml", "testdata/fixture.py", "a/testdata/x",
		"README.md", "main.tf", "main.tfvars", "Makefile", "makefile", "go.sum",
		"a*b", ".env", "prod.env", "config/.env", "pkg/x.go", "pkg/sub/x.go",
		"py", ".py", "a.", "noext", "",
	}
	for _, p := range patterns {
		c := compileFilePattern(p)
		for _, path := range paths {
			if got, want := c.matches(path, filepath.Base(path)), globMatches(p, path); got != want {
				t.Errorf("pattern %q on %q: compiled says %v, filepath.Match says %v", p, path, got, want)
			}
		}
	}
}

// TestFileMatchesRuleIsTheSameWithAndWithoutCompilation checks the cache
// RuleSet.Add fills: a rule added to a set and the same rule built directly
// decide alike, and a pattern changed after Add is still honoured.
func TestFileMatchesRuleIsTheSameWithAndWithoutCompilation(t *testing.T) {
	rule := &Rule{ID: "T-1", FilePatterns: []string{"*.go", "Dockerfile"}, IgnoreFilePatterns: []string{"*_test.go"}}
	direct := *rule
	rs := NewRuleSet()
	rs.Add(rule)
	for _, path := range []string{"a.go", "a_test.go", "x/Dockerfile", "a.py", "pkg/b_test.go"} {
		if got, want := fileMatchesRule(path, rule), fileMatchesRule(path, &direct); got != want {
			t.Errorf("%q: added rule says %v, directly built rule says %v", path, got, want)
		}
	}
	// A pattern appended after Add must still apply.
	rule.IgnoreFilePatterns = append(rule.IgnoreFilePatterns, "a.go")
	if fileMatchesRule("a.go", rule) {
		t.Error("an ignore pattern appended after RuleSet.Add was not applied")
	}
}
