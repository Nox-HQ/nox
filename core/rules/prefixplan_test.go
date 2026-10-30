package rules

import (
	"reflect"
	"regexp"
	"strings"
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
		if q := planFor(p); q != nil && q.first == nil {
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

// A pattern that opens with a bounded run of one character class before its
// literal -- the vendor-token template, `(?i)[\w.-]{0,50}?(?:okta)…` -- starts
// each match somewhere in the run of class characters just before the literal,
// so it is matched from the literal too, with the start recovered by walking
// back over the run. The cases pin what that walk must get right: the run
// capped at the repeat's bound, a run cut short by the end of the previous
// match, a literal whose continuation fails, several literals on one run, and
// non-ASCII class members.
func TestLeadClassPathEdgeCases(t *testing.T) {
	for _, c := range []struct{ pattern, content string }{
		{`(?i)[\w.-]{0,5}?(?:okta)[ \w]{0,3}[=:]\s*([a-z0-9]{4})`, "my.long_name_okta = abcd\nxokta:1234 okta=zz"},
		{`(?i)[\w.-]{0,5}?(?:okta)[ \w]{0,3}[=:]\s*([a-z0-9]{4})`, "aaaaaaaaaaokta=abcd"},
		{`(?i)[\w.-]{0,50}?(?:okta|sumo)[=:]([a-z0-9]{2})`, "okta=ab.sumo=cd okta:okta=ef"},
		{`[\w.-]{0,50}?(?:okta)=([a-z]{2})`, "xoktaokta=ab okta=1 oktaoktaokta=cd"},
		{`(?i)[\w.-]{0,50}?(?:[Ss]umo)=([a-z]{2})`, "sumo=ab SUMO=cd xSumo=ef"},
		{`(?i)[\w.-]{0,10}?(?:okta)=(\w{2})`, "abKokta=cd é_okta=ef"},
		{`(?i)[\w.-]{0,50}?(?:okta)(?:=|$)`, "a.okta= b_okta"},
		// Two runs, the first class within the second (SEC-286's shape).
		{`[\w.-]{0,3}?(?i:[\w.-]{0,2}?(?:okta))=(\w{2})`, "abcdefokta=xy ..okta=zz a-b.c-d.okta=ww"},
		{`[\w]{0,50}?(?i:[\w.-]{0,3}?(?:[Ss]umo))=(\w{2})`, "abc.-.sumo=xy abc..-.sumo=zz xyz.sumo=ww"},
	} {
		re := regexp.MustCompile(c.pattern)
		want := re.FindAllSubmatchIndex([]byte(c.content), -1)
		if len(want) == 0 {
			t.Fatalf("test premise: FindAll should match %q in %q", c.pattern, c.content)
		}
		p := planFor(c.pattern)
		if p == nil {
			t.Fatalf("%q: no plan", c.pattern)
		}
		if !p.usable([]byte(c.content)) {
			if !strings.ContainsAny(c.content, "Kſ") {
				t.Fatalf("%q on %q: plan unusable", c.pattern, c.content)
			}
			continue
		}
		if got := p.findAll([]byte(c.content), true); !reflect.DeepEqual(got, want) {
			t.Errorf("%q on %q: plan %v, FindAll %v", c.pattern, c.content, got, want)
		}
	}
}

// The lead-class path is taken only where the start can be recovered exactly.
func TestLeadClassPathDeclines(t *testing.T) {
	for _, p := range []string{
		`[a-z0-9]{32}`,                  // no literal after the run
		`[\w.-]{2,50}?okta=x`,           // a run with a minimum: the start is not the run's
		`[\w]{0,50}?\bokta=x`,           // the literal opens with a boundary
		`[\w]{0,50}?(?:okta)?=x`,        // the literal is optional
		`[\w.-]{0,50}?[\w]{0,5}?okta=x`, // two runs, the first class wider
	} {
		if q := planFor(p); q != nil && q.lead != nil {
			t.Errorf("%q got a lead-class plan", p)
		}
	}
}

// Many candidates on one long line would each run to the end of the line;
// there the full scan runs instead, and the result is FindAll's either way.
func TestDenseCandidatesOnALongLineTakeTheScan(t *testing.T) {
	const pattern = `(?i)(agent|bot)\s*.*?\b(auto|self)\s*[-_]?\b(?:improve|modify)`
	long := []byte(strings.Repeat("agent ", 20000) + "self-improve\n")
	p := planFor(pattern)
	if p == nil {
		t.Fatal("test premise: the pattern has a plan")
	}
	if _, ok := p.match(long, false); ok {
		t.Error("the plan ran on 20,000 candidates sharing one line")
	}
	if _, ok := p.match([]byte("agent: self-improve\n"), false); !ok {
		t.Error("the plan did not run on a short file")
	}
	re := regexp.MustCompile(pattern)
	got := NewRegexMatcher().Match(long, &Rule{ID: "T", Pattern: pattern, MatcherType: "regex"})
	if want := re.FindAllIndex(long, -1); len(got) != len(want) {
		t.Errorf("Match found %d, FindAll %d", len(got), len(want))
	}
}

// A pattern that opens with a character class instead of a literal is
// matched from the offsets where its first byte can occur (DATA-003's card
// numbers, DATA-002's SSNs): every match starts at such a byte, so trying
// each in order returns what FindAll returns, as for a literal start.
func TestFirstBytePathEdgeCases(t *testing.T) {
	for _, c := range []struct{ pattern, content string }{
		{`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b`, "card 4111111111111111, x4111111111111111 5500000000000004 41111111111111"},
		{`\b\d{3}-\d{2}-\d{4}\b`, "ssn 123-45-6789 a123-45-6789 1234-56-7890 \u00e9123-45-6789"},
		{`\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b`, "DE89 3704 0044 0532 0130 00 xDE89370400440532013000 GB82WEST"},
		{`key.*|[0-9]+`, "a key here 123 and k9 key"},
		{`[0-9]+[a-z]`, "12345678x 99 7y"},
	} {
		re := regexp.MustCompile(c.pattern)
		want := re.FindAllSubmatchIndex([]byte(c.content), -1)
		if len(want) == 0 {
			t.Fatalf("test premise: FindAll should match %q in %q", c.pattern, c.content)
		}
		p := planFor(c.pattern)
		if p == nil || p.first == nil {
			t.Fatalf("%q: no first-byte plan", c.pattern)
		}
		if got := p.findAll([]byte(c.content), true); !reflect.DeepEqual(got, want) {
			t.Errorf("%q on %q: plan %v, FindAll %v", c.pattern, c.content, got, want)
		}
	}
}

// The first-byte path is taken only where its first bytes are provably all
// the starts, and few enough to be worth trying one by one.
func TestFirstBytePathDeclines(t *testing.T) {
	for _, p := range []string{
		`\s*[=:]\s*\d+`,     // whitespace starts: on nearly every line
		`(?i)[a-z]{2}\d{4}`, // case folding brings in KELVIN SIGN and LONG S
		`[^"]{8}x`,          // a negated class can start with any rune
		`[\w.-]{4}x`,        // too many possible first bytes to narrow anything
		`\b[.$]env`,         // \b before a byte that is not a word character
		`(?m)^[0-9]{3}`,     // start-of-line anchor
		`[0-9]*`,            // matches the empty string
		`abc[0-9]`,          // a literal prefix, which regexp already skips to
	} {
		if q := planFor(p); q != nil && q.first != nil {
			t.Errorf("%q got a first-byte plan", p)
		}
	}
}

// Dense candidates give up on the plan before building a candidate list as
// long as the file, and the full scan's result is returned.
func TestDenseFirstBytesTakeTheScan(t *testing.T) {
	pattern := `[0-9]{3}-[0-9]{4}`
	content := []byte(strings.Repeat("0123456789", 1000) + " 555-1234")
	p := planFor(pattern)
	if p == nil || p.first == nil {
		t.Fatalf("%q: no first-byte plan", pattern)
	}
	if _, ok := p.match(content, false); ok {
		t.Errorf("a file of digits took the first-byte plan")
	}
}
