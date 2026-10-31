package rules

import (
	"math/rand"
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
		`key.*|[0-9]+`,                // one alternative has no literal
		`a`,                           // single-character literal
		`(?:secret)?\s*[=:]\s*x`,      // optional literal: a match can start elsewhere
		`\bfoo=\d|bar=\d`,             // \b opens one alternative only
		`\bfoo=\d|\b\.env`,            // \b before a non-word literal in one branch
	} {
		if q := planFor(p); q != nil && q.first == nil {
			t.Errorf("%q got a literal-prefix plan", p)
		}
	}
	for _, p := range []string{`(?i)(?:phone|tel)\s*[=:]\s*\d+`, `\bAKIA[0-9A-Z]{16}`, `(?i)\b(?:eval|exec)\s*\(`, `(?i)(?:\bkind:\s*x|\bdata:\s*y)`, `(?m)^password\s*=`} {
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
		// A literal and then a small class: one literal per class character.
		{`(?i)(f["']|\.format\(|%s).*?(user_input|user_query)`, "x = f\"{user_input}\" F'{user_query}' f`user_input` '%S' % user_query"},
		{`ab[cd]e|ab[x]`, "abce abde abxe abfe"},
		// \b opening every alternative (SEC-254's shape), which the parser
		// does not factor out.
		{`(?i)(?:\bkind:\s*secret.{0,20}?\bdata:|\bdata:.{0,20}?\bkind:\s*secret)`, "kind: Secret\ndata: x  metadata: kind: secret xdata: kind: secret data:\nKIND:SECRET DATA:"},
		{`\bfoo=\d|\bbar=\d`, "foo=1 xfoo=2 _bar=3 (bar=4 bar=5foo=6"},
	} {
		re := regexp.MustCompile(c.pattern)
		want := re.FindAllSubmatchIndex([]byte(c.content), -1)
		p := planFor(c.pattern)
		if p == nil {
			t.Fatalf("%q: no plan", c.pattern)
		}
		if got := p.findAll(nil, []byte(c.content), true); !reflect.DeepEqual(got, want) {
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
		// An optional character is a run of at most one (MCP-016's `"?`).
		{`(?i)"?(?:forward|relay)[_-]?token"?\s*[:=]\s*true`, `"forward_token": true, relayToken=true ""relay_token"=true`},
		{`"?okta"?=(\w{2})`, `okta=ab "okta"=cd x"okta=ef ""okta=gh`},
		// A run after `\b` (SEC-469's shape): only the furthest start of the run
		// can have a boundary before it, so it is checked there.
		{`\b[A-Z0-9_]*(?:TOKEN|API_KEY)=([a-z]{2})`, "GH_TOKEN=ab xAPI_KEY=cd x_TOKEN=ef TOKEN=gh .MY_API_KEY=ij"},
		{`\b[A-Z0-9_]*(?:TOKEN)=([a-z]{2})`, "aTOKEN=ab TOKENTOKEN=cd A_TOKEN=x A_TOKEN=ef"},
		{`\b[A-Z_]{0,3}TOKEN=([a-z]{2})`, "ABCDEFTOKEN=ab X_TOKEN=cd"},
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
		if got := p.findAll(nil, []byte(c.content), true); !reflect.DeepEqual(got, want) {
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
		`\b[\w.-]*TOKEN=x`,              // \b before a run of non-word characters
		`\b[A-Z]*\.env`,                 // \b before a run whose literal is not a word
		`(?i)k?okta=x`,                  // an optional letter that folds: not one byte
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
		// The fixed opening (follow): positions cut off by the end of the
		// file, a literal inside it, a capture, a repeat with room to vary.
		{`[A-Z]{2}[0-9]{2}`, "AB12 A1 AB1 XY9"},
		{`[A-Z]{2}-[0-9]+`, "AB-1 AB- A-1 ZZ-99"},
		{`([A-Z][0-9]){2}[a-z]?`, "A1B2c A1B A1B2"},
		{`[A-Z]{1,3}[0-9]`, "A1 ABC2 ABCD3 AB"},
		{`[0-9](?i:x)[0-9]`, "1X2 1x2 1y2"},
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
		if got := p.findAll(nil, []byte(c.content), true); !reflect.DeepEqual(got, want) {
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
		`\b[A-C0-2]*`,       // matches "" at a boundary, which no first byte marks
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
	// Every "123-4567" fits the pattern's fixed opening, so each is a
	// candidate: one in eight bytes.
	content := []byte(strings.Repeat("123-4567", 1250) + " 555-1234")
	p := planFor(pattern)
	if p == nil || p.first == nil {
		t.Fatalf("%q: no first-byte plan", pattern)
	}
	if _, ok := p.match(content, false); ok {
		t.Errorf("a file of digits took the first-byte plan")
	}
}

// A first-byte plan with a fixed opening drops a candidate whose next bytes
// do not fit it. Seeded patterns and contents: the plan must find what the
// full scan finds wherever it applies.
func TestFirstBytePathFollowMatchesFindAll(t *testing.T) {
	atoms := []string{`[A-C]`, `[0-2]`, `x`, `-`, `[A-C0-2]`}
	reps := []string{"", "", "{2}", "{1,2}", "+", "?", "*"}
	r := rand.New(rand.NewSource(957))
	followed := 0
	for range 3000 {
		var b strings.Builder
		if r.Intn(3) == 0 {
			b.WriteString(`\b`)
		}
		for n := 1 + r.Intn(5); n > 0; n-- {
			atom := atoms[r.Intn(len(atoms))]
			if r.Intn(6) == 0 {
				atom = "(" + atom + atoms[r.Intn(len(atoms))] + ")"
			}
			b.WriteString(atom + reps[r.Intn(len(reps))])
		}
		pattern := b.String()
		p := planFor(pattern)
		if p == nil || p.first == nil {
			continue
		}
		if len(p.follow) > 0 {
			followed++
		}
		re := regexp.MustCompile(pattern)
		for range 5 {
			content := randomBytes(r, r.Intn(40), "ABC012x- \n")
			want := re.FindAllSubmatchIndex(content, -1)
			if got := p.findAll(nil, content, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q on %q: plan %v, FindAll %v", pattern, content, got, want)
			}
		}
	}
	if followed < 300 {
		t.Fatalf("only %d patterns had a fixed opening; the comparison is not exercising it", followed)
	}
}

// A first byte too near the end of the file for the fixed opening to fit is
// not a candidate. The anchored match would reject it anyway; counted, it
// would push a file over the density limit for nothing.
func TestFirstBytePathDropsACandidateCutOffByTheEnd(t *testing.T) {
	p := planFor(`[A-Z]{2}[0-9]{2}`)
	if p == nil || len(p.follow) != 3 {
		t.Fatalf("test premise: want a first-byte plan with three follow positions, got %+v", p)
	}
	starts, _ := p.firstCandidates([]byte("AB12 AB1"), -1)
	if !reflect.DeepEqual(starts, []int{0}) {
		t.Errorf("candidates %v, want [0]: the AB1 at the end cannot start a match", starts)
	}
}

// An alternation every branch of which opens with `\b` is planned with the
// boundary checked once, at the candidate. Seeded alternations and contents:
// the plan must find what the full scan finds.
func TestBoundaryOpeningEveryBranchMatchesFindAll(t *testing.T) {
	words := []string{"ab", "ba", "aab", "b_a", "a1"}
	tails := []string{"", "=", "[0-9]", "=[0-9]+", ".?b"}
	r := rand.New(rand.NewSource(958))
	planned := 0
	for range 2000 {
		var branches []string
		for n := 2 + r.Intn(3); n > 0; n-- {
			branches = append(branches, `\b`+words[r.Intn(len(words))]+tails[r.Intn(len(tails))])
		}
		pattern := strings.Join(branches, "|")
		if r.Intn(2) == 0 {
			pattern = "(?i)(?:" + pattern + ")"
		}
		p := planFor(pattern)
		if p == nil || p.first != nil {
			continue
		}
		planned++
		re := regexp.MustCompile(pattern)
		for range 5 {
			content := randomBytes(r, r.Intn(40), "abAB_1= .x")
			want := re.FindAllSubmatchIndex(content, -1)
			if got := p.findAll(nil, content, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q on %q: plan %v, FindAll %v", pattern, content, got, want)
			}
		}
	}
	if planned < 1000 {
		t.Fatalf("only %d alternations got a plan; the comparison is not exercising it", planned)
	}
}

// A line-anchored pattern, `(?m)^P R`, is found from the starts of the lines
// R's literals occur on (buildLinePlan). The leads cover runs, optional and
// required characters, classes and `.`, none of which holds a newline; the
// tails reach across lines and assert boundaries; the content puts literals
// at line starts, mid-line, several to a line, and flush against both ends.
func TestLineAnchoredPlanMatchesFindAll(t *testing.T) {
	leads := []string{"", "[ \t]*", "-?", "-[ \t]+", "[ \t]*-?[ \t]*", "x?", ".*", "[^\n]{0,3}", "(?:- )?", `\b`, `\s*`, "[^x]*"}
	// The last two words reach a branch's literal over a run (IAC-351's
	// `(?:PASSWORD|SECRET_KEY|(?:[A-Z0-9_]*_)?TOKEN)`), or over one that can
	// cross a newline, which must keep the full scan.
	words := []string{"ab", "ba", "(?:ab|ba)", "(?:aab|b_a)", "a1", "(?:ab|(?:[a-z1]*_)?ba)", `(?:ab|\s*ba)`}
	tails := []string{"", ":", "[ \t]*:", `\b`, "[^:]*:", "$", `\s*b`}
	r := rand.New(rand.NewSource(964))
	planned := 0
	for range 3000 {
		pattern := "(?m)^" + leads[r.Intn(len(leads))] + words[r.Intn(len(words))] + tails[r.Intn(len(tails))]
		if r.Intn(3) == 0 {
			pattern = "(?i)" + pattern
		}
		p := planFor(pattern)
		if p == nil {
			continue
		}
		if !p.line {
			t.Fatalf("%q planned, but not as a line plan", pattern)
		}
		planned++
		re := regexp.MustCompile(pattern)
		for range 5 {
			content := randomBytes(r, r.Intn(48), "abAB_1:- \t\nx")
			want := re.FindAllSubmatchIndex(content, -1)
			if got := p.findAll(nil, content, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q on %q: plan %v, FindAll %v", pattern, content, got, want)
			}
		}
	}
	if planned < 2000 {
		t.Fatalf("only %d line-anchored patterns got a plan; the comparison is not exercising it", planned)
	}
}

// TestLineAnchoredPlanDeclines keeps the full scan where a match could start
// on an earlier line than its literal, or need not reach a literal at all.
func TestLineAnchoredPlanDeclines(t *testing.T) {
	for _, pattern := range []string{
		`(?m)^\s*foo`,       // \s holds a newline
		`(?m)^(?s:.)*foo`,   // so does . under s
		`(?m)^[^x]*foo`,     // and a negated class
		`(?m)^foo|bar`,      // the anchor is one branch's
		`(?m)^[a-z]+=`,      // no literal to find the line by
		`^foo`,              // start of text, not of a line
		`(?m)^(?:ab|\s*ba)`, // one branch reaches its literal across lines
	} {
		if planFor(pattern) != nil {
			t.Errorf("%q: planned, want the full scan", pattern)
		}
	}
	iac351 := `(?im)^[ \t]*(?:PASSWORD|SECRET_KEY|(?:[A-Z0-9_]*_)?TOKEN)[ \t]*:[ \t]*['"]?[A-Za-z0-9]`
	if p := planFor(iac351); p == nil || !p.line {
		t.Errorf("%q: want a line plan from its branches' literals", iac351)
	}
}

// A plan whose prefixes are exactly what the opening literals match drops an
// occurrence the rest of the pattern cannot start after (afterPrefixes). The
// heads include prefixes of one another (`ip` and `ipx`), folded and two-part
// heads; the rests open with classes, optional runs, alternations and groups
// that can be skipped; the content puts literals flush against the end.
func TestFollowBytesMatchFindAll(t *testing.T) {
	heads := []string{"ab", "(?:ab|ba)", "(?:ab|abx)", "(?:ip|host)", "a(?:b|x)"}
	rests := []string{`=`, `\s*[=:]`, `[0-9]+`, `(?:=|:)x`, `[ \t]*=?b`, `x?=`, `(?:\s|-)+1`, `"?:`}
	r := rand.New(rand.NewSource(968))
	filtered := 0
	for range 3000 {
		pattern := heads[r.Intn(len(heads))] + rests[r.Intn(len(rests))]
		if r.Intn(3) == 0 {
			pattern = "(?i)" + pattern
		}
		p := planFor(pattern)
		if p == nil {
			continue
		}
		if p.after != nil {
			filtered++
		}
		re := regexp.MustCompile(pattern)
		for range 5 {
			content := randomBytes(r, r.Intn(40), "abABxip=: \t\n1-\"host")
			want := re.FindAllSubmatchIndex(content, -1)
			if got := p.findAll(nil, content, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q on %q: plan %v, FindAll %v", pattern, content, got, want)
			}
		}
	}
	if filtered < 1000 {
		t.Fatalf("only %d patterns had follow bytes; the comparison is not exercising them", filtered)
	}
}

// A pattern opening with an optional group before its literals is found from
// both literal sets (buildOptionalLeadPlan), and a `\b` opening only some of
// the group's branches is decided from the byte before the candidate (ctx).
// The content puts literals after word and non-word bytes, at offset 0, and
// after multi-byte and invalid UTF-8.
func TestOptionalLeadPlanMatchesFindAll(t *testing.T) {
	groups := []string{`(?:\bab|ba)\s+`, `(?:(?:\bab|\bba|n't)\s+)`, `(?:ab|ba)-`, `\bab `, `(?:x[0-9]|\bab)`}
	rests := []string{`(?:cd|dc)`, `(?:cd|dc)\s*x`, `cd[0-9]+`, `(?:cd\s+x|ba\s+y)`, `(?:cd|ab)\b`}
	r := rand.New(rand.NewSource(972))
	planned := 0
	for range 3000 {
		pattern := "(?:" + groups[r.Intn(len(groups))] + ")?" + rests[r.Intn(len(rests))]
		if r.Intn(3) == 0 {
			pattern = "(?i)" + pattern
		}
		p := planFor(pattern)
		if p == nil {
			continue
		}
		if p.ctx != nil {
			planned++
		}
		re := regexp.MustCompile(pattern)
		for range 5 {
			var content []byte
			for range r.Intn(10) {
				content = append(content, []string{"ab", "ba", "cd", "dc", " ", "\t", "x", "y", "1", "-", "n't", "é", "\xff", "\n", "AB", "_"}[r.Intn(16)]...)
			}
			want := re.FindAllSubmatchIndex(content, -1)
			if got := p.findAll(nil, content, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q on %q: plan %v, FindAll %v", pattern, content, got, want)
			}
		}
	}
	if planned < 1500 {
		t.Fatalf("only %d optional-lead patterns got a plan; the comparison is not exercising it", planned)
	}
	mcp011 := `(?i)(?:(?:\bnot|\bnever|n't|\bwithout)\s+)?(?:(?:exfiltrate|send|upload|leak|transmit|post|forward)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|\.env\b|/etc/passwd|api[_-]?keys?|secrets?|credentials?|environment\s+variables?|access[_-]?tokens?)|(?:read|cat)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|\.env\b|/etc/passwd))`
	if p := planFor(mcp011); p == nil || p.ctx == nil {
		t.Errorf("MCP-011 has no optional-lead plan")
	}
}
