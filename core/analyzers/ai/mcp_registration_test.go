package ai

import (
	"regexp"
	"strings"
	"testing"
)

// MCP-008 was the eighth rule found anchored to end of text, and the only one
// of the eight that could not be repaired.
//
// "MCP tool handler appears unbounded (no rate limit / scope guard)" is an
// absence claim made from a presence pattern, and the absence is not visible
// where the pattern looked: a rate limiter or scope check is middleware,
// declared away from the registration site and often in another file. So it was
// removed rather than retired — nothing else reports the condition, because the
// condition cannot be established there.
//
// The probe that condemned it also found MCP-005 covering a third of the idiom
// it names, which is what the tests below pin.

// goFluentBuilder is the mcp-go registration form, and the one nox's own server
// uses. Note the capital `Tool` and the intermediate chain calls: `server\.tool`
// and `\)\s*\.handler` between them excluded this entire dialect.
const goFluentBuilder = `package main

func register(srv *Server) {
	srv.Tool("described").
		Description("this one is documented").
		ReadOnly().
		Handler(handleA)

	srv.Tool("undescribed").
		ReadOnly().
		Handler(handleB)

	srv.Tool("bare").Handler(handleC)
}
`

// tsSdk is the TypeScript spelling.
const tsSdk = `const server = new McpServer({ name: "demo" });
server.tool("fetch").handler(async (args) => doFetch(args));
server.tool("write").description("writes").handler(async (args) => doWrite(args));
`

func ruleLines(t *testing.T, path, body, ruleID string) []int {
	t.Helper()
	a := NewAnalyzer()
	results, err := a.ScanFile(path, []byte(body))
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", path, err)
	}
	var lines []int
	for _, f := range results {
		if f.RuleID == ruleID {
			lines = append(lines, f.Location.StartLine)
		}
	}
	return lines
}

// TestMCP005CoversBothDialects is the recall half, and the measured one: before
// this change the Go form produced nothing at all, in nox's own server included.
func TestMCP005CoversBothDialects(t *testing.T) {
	got := ruleLines(t, "server.go", goFluentBuilder, "MCP-005")
	if len(got) != 2 {
		t.Errorf("MCP-005 reported lines %v on the Go fluent builder; want the two "+
			"registrations with no Description() — `undescribed` and `bare`", got)
	}
	if got := ruleLines(t, "server.ts", tsSdk, "MCP-005"); len(got) != 1 {
		t.Errorf("MCP-005 reported lines %v on the TypeScript form; want only the one "+
			"registration with no description()", got)
	}
}

// TestMCP005IsSilentWhereADescriptionExists is the other half. A rule that
// reported every registration would be no better than one that reported none.
func TestMCP005IsSilentWhereADescriptionExists(t *testing.T) {
	for _, line := range ruleLines(t, "server.go", goFluentBuilder, "MCP-005") {
		if line == 4 {
			t.Error("MCP-005 fired on a registration that calls Description()")
		}
	}
	for _, line := range ruleLines(t, "server.ts", tsSdk, "MCP-005") {
		if line == 3 {
			t.Error("MCP-005 fired on a registration that calls description()")
		}
	}
}

// TestTheKeywordGateAdmitsBothDialects. The keyword gates the FILE, so
// `server.tool` excluded every Go server before the pattern was consulted —
// which is why widening the pattern alone changed nothing, and why this is
// asserted separately from the pattern's behaviour.
func TestTheKeywordGateAdmitsBothDialects(t *testing.T) {
	r, ok := NewAnalyzer().Rules().ByID("MCP-005")
	if !ok {
		t.Fatal("MCP-005 not found")
	}
	for _, sample := range []string{
		"srv.Tool(\"x\").Handler(h)",
		"server.tool(\"x\").handler(h)",
	} {
		lower := strings.ToLower(sample)
		var admitted bool
		for _, kw := range r.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				admitted = true
			}
		}
		if !admitted {
			t.Errorf("the keyword gate rejects a file containing %q, so the pattern "+
				"never runs on it; keywords are %v", sample, r.Keywords)
		}
	}
}

// TestAnUnknownBuilderCallDoesNotNarrowTheRule is the reason MCP-005 decides
// with a predicate rather than by enumerating the builder calls allowed between
// the name and the handler. Enumeration works until someone adds a method: a
// new `.annotations()` would put the handler out of reach and silently narrow
// the rule to nothing, with no test able to notice.
func TestAnUnknownBuilderCallDoesNotNarrowTheRule(t *testing.T) {
	const withNewMethod = `func register(srv *Server) {
	srv.Tool("undescribed").
		Annotations(someFutureThing).
		ReadOnly().
		Handler(handleB)
}
`
	if got := ruleLines(t, "server.go", withNewMethod, "MCP-005"); len(got) != 1 {
		t.Errorf("MCP-005 reported %v; a builder call it has never heard of must not "+
			"stop it seeing that the chain names no description", got)
	}
}

// TestMCP008IsGone states the removal, so a later edit that reintroduces the
// rule has to argue with this instead of quietly restoring an unfireable one.
func TestMCP008IsGone(t *testing.T) {
	if _, ok := NewAnalyzer().Rules().ByID("MCP-008"); ok {
		t.Error("MCP-008 is back. Its claim — a handler with no rate limit or scope " +
			"guard — cannot be established at a registration site, because the guard " +
			"is middleware declared elsewhere.")
	}
}

// TestNoAIRuleIsAnchoredToEndOfText closes the class for this analyzer the way
// TestNoIaCRuleIsAnchoredToEndOfText closes it for IaC. Go reads `$` as end of
// TEXT unless the multi-line flag is set, and rule patterns are matched against
// whole-file content.
func TestNoAIRuleIsAnchoredToEndOfText(t *testing.T) {
	multiline := regexp.MustCompile(`\(\?[a-zA-Z]*m[a-zA-Z]*\)`)
	for _, r := range NewAnalyzer().Rules().Rules() {
		p := r.Pattern
		if p == "" || !strings.HasSuffix(p, "$") || strings.HasSuffix(p, `\$`) {
			continue
		}
		if !multiline.MatchString(p) {
			t.Errorf("%s ends in `$` without (?m), so it can only match on the last "+
				"line of a file: %s", r.ID, p)
		}
	}
}
