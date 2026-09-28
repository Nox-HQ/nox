package rules

import (
	"reflect"
	"regexp"
	"testing"
)

// Go's case folding equates KELVIN SIGN with k and LONG S with s, so `(?i)key`
// matches "Key" written with a Kelvin sign. An ASCII search for the prefix
// cannot see that, so a file containing either rune takes the full scan and
// the result is still FindAll's.
func TestAFoldOutlierFallsBackToTheFullScan(t *testing.T) {
	const pattern = `(?i)(?:api_key|secret)\s*=\s*"[a-z0-9]{8,}"`
	for _, content := range []string{
		"x = 1\nKEY_UNUSED\napi_Key = \"abcdef1234\"\n",
		"ſecret = \"abcdef1234\"\n",
	} {
		re := regexp.MustCompile(pattern)
		want := re.FindAllStringIndex(content, -1)
		if len(want) == 0 {
			t.Fatalf("test premise: FindAll should match %q", content)
		}
		got := NewRegexMatcher().Match([]byte(content), &Rule{ID: "T", Pattern: pattern, MatcherType: "regex"})
		if len(got) != len(want) {
			t.Fatalf("%q: Match found %d, FindAll %d", content, len(got), len(want))
		}
	}
}

// A pattern the plan cannot prove starts with a literal keeps the full scan.
func TestAPatternWithoutALiteralStartHasNoPlan(t *testing.T) {
	for _, p := range []string{
		`\B(?:akia|asia)[0-9A-Z]{16}`, // leading non-boundary
		`\b\.env\b`,                   // \b before a non-word literal
		`[a-z0-9]{32}`,                // character class
		`(?m)^password\s*=`,           // start-of-line anchor
		`key.*|[0-9]+`,                // one alternative has no literal
		`a`,                           // single-character literal
		`(?:secret)?\s*[=:]\s*x`,      // optional literal: a match can start elsewhere
	} {
		if planFor(p) != nil {
			t.Errorf("%q got a literal-prefix plan", p)
		}
	}
	for _, p := range []string{`(?i)(?:phone|tel)\s*[=:]\s*\d+`, `\bAKIA[0-9A-Z]{16}`, `(?i)\b(?:eval|exec)\s*\(`} {
		if planFor(p) == nil {
			t.Errorf("%q opens with literals (after \\b) and got no plan", p)
		}
	}
}

// Overlapping literal occurrences and a match that crosses lines both come
// out as FindAll's.
func TestPrefixPathEdgeCases(t *testing.T) {
	for _, c := range []struct{ pattern, content string }{
		{`(?i)aa\w*`, "aaaa aAa AAAAb"},
		{`(?i)token\s*=\s*"[^"]+"`, "token =\n  \"multi-line value\"\nTOKEN=\"x\""},
		{`(?:foo|foobar)baz`, "foobarbaz foobaz"},
		{`\bAKIA[0-9A-Z]{4}`, "AKIA1234 xAKIA1234 _AKIA1234 (AKIA1234"},
		{`(?i)\b(?:eval|exec)\(`, "eval( retrieval( myexec( .EXEC( EvAl("},
	} {
		re := regexp.MustCompile(c.pattern)
		want := re.FindAllSubmatchIndex([]byte(c.content), -1)
		p := planFor(c.pattern)
		if p == nil {
			t.Fatalf("%q: no plan", c.pattern)
		}
		if got := p.findAll([]byte(c.content), true); !reflect.DeepEqual(got, want) {
			t.Errorf("%q on %q: prefix path %v, FindAll %v", c.pattern, c.content, got, want)
		}
	}
}
