package suppress

import (
	"testing"
	"time"
)

func TestScanForSuppressions_GoComment(t *testing.T) {
	content := []byte("// nox:ignore SEC-001 -- false positive\nvar secret = \"test\"\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].RuleIDs[0] != "SEC-001" {
		t.Fatalf("expected SEC-001, got %s", supps[0].RuleIDs[0])
	}
	if supps[0].Line != 2 {
		t.Fatalf("expected line 2, got %d", supps[0].Line)
	}
	if supps[0].Reason != "false positive" {
		t.Fatalf("expected reason 'false positive', got %q", supps[0].Reason)
	}
}

func TestScanForSuppressions_PythonComment(t *testing.T) {
	content := []byte("# nox:ignore SEC-002\npassword = 'test'\n")
	supps := ScanForSuppressions(content, "script.py")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].RuleIDs[0] != "SEC-002" {
		t.Fatalf("expected SEC-002, got %s", supps[0].RuleIDs[0])
	}
}

func TestScanForSuppressions_SQLComment(t *testing.T) {
	content := []byte("-- nox:ignore SEC-003\nSELECT * FROM users;\n")
	supps := ScanForSuppressions(content, "query.sql")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].RuleIDs[0] != "SEC-003" {
		t.Fatal("wrong rule ID")
	}
}

func TestScanForSuppressions_CSSComment(t *testing.T) {
	content := []byte("/* nox:ignore IAC-001 */\n.class { color: red; }\n")
	supps := ScanForSuppressions(content, "style.css")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
}

func TestScanForSuppressions_HTMLComment(t *testing.T) {
	content := []byte("<!-- nox:ignore AI-001 -->\n<div>content</div>\n")
	supps := ScanForSuppressions(content, "index.html")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
}

func TestScanForSuppressions_MultiRule(t *testing.T) {
	content := []byte("// nox:ignore SEC-001,SEC-002\nvar x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if len(supps[0].RuleIDs) != 2 {
		t.Fatalf("expected 2 rule IDs, got %d", len(supps[0].RuleIDs))
	}
	if supps[0].RuleIDs[0] != "SEC-001" || supps[0].RuleIDs[1] != "SEC-002" {
		t.Fatalf("expected SEC-001,SEC-002, got %v", supps[0].RuleIDs)
	}
}

func TestScanForSuppressions_TrailingComment(t *testing.T) {
	content := []byte("var secret = \"test\" // nox:ignore SEC-001\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	// Trailing comment: applies to the same line.
	if supps[0].Line != 1 {
		t.Fatalf("expected line 1 for trailing comment, got %d", supps[0].Line)
	}
}

func TestScanForSuppressions_WithExpiration(t *testing.T) {
	content := []byte("// nox:ignore SEC-001 -- known issue expires:2025-12-31\nvar x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].Expires == nil {
		t.Fatal("expected expiration date")
	}
	expected := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	if !supps[0].Expires.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, *supps[0].Expires)
	}
}

func TestMatchesFinding_Match(t *testing.T) {
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
	}

	if !s.MatchesFinding("SEC-001", 5, time.Now()) {
		t.Fatal("expected match")
	}
}

func TestMatchesFinding_WrongRule(t *testing.T) {
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
	}

	if s.MatchesFinding("SEC-002", 5, time.Now()) {
		t.Fatal("expected no match for wrong rule")
	}
}

func TestMatchesFinding_WrongLine(t *testing.T) {
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
	}

	if s.MatchesFinding("SEC-001", 6, time.Now()) {
		t.Fatal("expected no match for wrong line")
	}
}

func TestMatchesFinding_Expired(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
		Expires: &past,
	}

	if s.MatchesFinding("SEC-001", 5, time.Now()) {
		t.Fatal("expected no match for expired suppression")
	}
}

func TestMatchesFinding_NotYetExpired(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	s := Suppression{
		RuleIDs: []string{"SEC-001"},
		Line:    5,
		Expires: &future,
	}

	if !s.MatchesFinding("SEC-001", 5, time.Now()) {
		t.Fatal("expected match for non-expired suppression")
	}
}

func TestScanForSuppressions_NoMatch(t *testing.T) {
	content := []byte("var x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 0 {
		t.Fatalf("expected 0 suppressions, got %d", len(supps))
	}
}

func TestScanForSuppressions_NextLineSkipsBlank(t *testing.T) {
	content := []byte("// nox:ignore SEC-001\n\nvar x = 1\n")
	supps := ScanForSuppressions(content, "main.go")

	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	// Should skip the blank line and target line 3.
	if supps[0].Line != 3 {
		t.Fatalf("expected line 3, got %d", supps[0].Line)
	}
}

// TestScanForSuppressions_DisableAlias — `nox:disable` is accepted
// as a synonym for `nox:ignore` to match gosec/staticcheck/golangci
// convention. Behaviour must be identical: rule list, reason,
// expires, and target-line resolution all work the same way.
func TestScanForSuppressions_DisableAlias(t *testing.T) {
	t.Parallel()
	content := []byte(`# nox:disable SEC-001 -- documented FP
secret = "AKIA..."`)
	supps := ScanForSuppressions(content, "main.py")
	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if len(supps[0].RuleIDs) != 1 || supps[0].RuleIDs[0] != "SEC-001" {
		t.Errorf("rule IDs = %v", supps[0].RuleIDs)
	}
	if supps[0].Reason != "documented FP" {
		t.Errorf("reason = %q", supps[0].Reason)
	}
	if supps[0].Line != 2 {
		t.Errorf("line = %d, want 2", supps[0].Line)
	}
}

// TestScanForSuppressions_DisableAndIgnoreInterop — both spellings
// can appear in the same file and target different rules. Asserts the
// IDENTITY of each suppression (rule ID, target line, reason), not
// just that both rule IDs appear somewhere in the output.
func TestScanForSuppressions_DisableAndIgnoreInterop(t *testing.T) {
	t.Parallel()
	content := []byte(`// nox:ignore SEC-001
foo()
// nox:disable SEC-002 -- alt spelling
bar()`)
	supps := ScanForSuppressions(content, "main.go")
	if len(supps) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(supps))
	}

	byRule := map[string]Suppression{}
	for _, s := range supps {
		if len(s.RuleIDs) != 1 {
			t.Errorf("expected each suppression to carry one rule, got %v", s.RuleIDs)
			continue
		}
		byRule[s.RuleIDs[0]] = s
	}

	ig, ok := byRule["SEC-001"]
	if !ok {
		t.Fatal("missing SEC-001 suppression")
	}
	if ig.Line != 2 {
		t.Errorf("SEC-001 target line = %d, want 2", ig.Line)
	}
	if ig.Reason != "" {
		t.Errorf("SEC-001 reason = %q, want empty", ig.Reason)
	}

	dis, ok := byRule["SEC-002"]
	if !ok {
		t.Fatal("missing SEC-002 suppression")
	}
	if dis.Line != 4 {
		t.Errorf("SEC-002 target line = %d, want 4", dis.Line)
	}
	if dis.Reason != "alt spelling" {
		t.Errorf("SEC-002 reason = %q, want %q", dis.Reason, "alt spelling")
	}
}

// TestScanForSuppressions_HTMLCommentReason — HTML comments leak a
// trailing `>` into the reason capture because `--` of `-->` doubles
// as the reason separator. The cleanup loop strips it; assert the
// reason ends up clean.
func TestScanForSuppressions_HTMLCommentReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		reason string
	}{
		{"no reason", `<!-- nox:ignore SEC-001 -->`, ""},
		{"with reason", `<!-- nox:ignore SEC-001 -- false positive -->`, "false positive"},
		{"disable alias", `<!-- nox:disable SEC-001 -- known issue -->`, "known issue"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			supps := ScanForSuppressions([]byte(c.line+"\ntarget\n"), "page.html")
			if len(supps) != 1 {
				t.Fatalf("expected 1 suppression, got %d", len(supps))
			}
			if supps[0].Reason != c.reason {
				t.Errorf("reason = %q, want %q", supps[0].Reason, c.reason)
			}
		})
	}
}

// TestScanForSuppressions_DisableTrailingComment — disable as a
// trailing comment must still apply to the same line.
func TestScanForSuppressions_DisableTrailingComment(t *testing.T) {
	t.Parallel()
	content := []byte(`secret = "AKIA..." # nox:disable SEC-001
`)
	supps := ScanForSuppressions(content, "main.py")
	if len(supps) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(supps))
	}
	if supps[0].Line != 1 {
		t.Errorf("line = %d, want 1 (trailing comment applies to same line)", supps[0].Line)
	}
}

// A nox:ignore inside a fenced code block in markdown is documentation showing
// the syntax, not a waiver anyone expects to apply. It is flagged so the caller
// can skip reporting it as unused — but it must still parse and still match, so
// a genuine waiver written in a doc keeps working.
func TestScanForSuppressions_MarkdownFenceIsDocExample(t *testing.T) {
	md := "# Docs\n\nExample:\n\n```go\n// nox:ignore SEC-001 -- shown in docs\nvar k = \"AKIAEXAMPLEFAKEKEY\"\n```\n\n<!-- nox:ignore SEC-002 -- a real waiver, outside any fence -->\nreal line\n"

	got := ScanForSuppressions([]byte(md), "README.md")
	if len(got) != 2 {
		t.Fatalf("expected 2 suppressions, got %d: %+v", len(got), got)
	}
	byRule := map[string]Suppression{}
	for _, s := range got {
		byRule[s.RuleIDs[0]] = s
	}
	if !byRule["SEC-001"].DocExample {
		t.Error("directive inside a fenced block should be marked DocExample")
	}
	if byRule["SEC-002"].DocExample {
		t.Error("directive outside a fence must NOT be marked DocExample")
	}
	// Marking must not disturb matching: the fenced one still targets its line.
	if !byRule["SEC-001"].MatchesFinding("SEC-001", byRule["SEC-001"].Line, time.Now()) {
		t.Error("a fenced directive must still match a finding on its target line")
	}
}

// The same directive in a non-markdown file is never a doc example.
func TestScanForSuppressions_FenceOnlyAppliesToMarkdown(t *testing.T) {
	src := "```\n// nox:ignore SEC-001 -- not markdown\nvar k = 1\n"
	got := ScanForSuppressions([]byte(src), "main.go")
	if len(got) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(got))
	}
	if got[0].DocExample {
		t.Error("backticks in a .go file must not mark a directive as a doc example")
	}
}

// `nox:ignore` appearing in PROSE or in a STRING LITERAL is documentation
// about the syntax, not a waiver. Both forms were parsed as real directives,
// and because a waiver that matches nothing is reported, nox produced false
// "waives X but matched no finding" degradations against its own source —
// the instrumentation accusing correct code of carrying dead waivers.
//
// The two real instances, both from nox's own tree:
//
//   - a doc comment that wrapped so the phrase "…holds no nox:ignore comments,
//     so nothing was missed" began a line, parsed as waiving rule "comments";
//   - pre-commit help text, `echo "nox: use '// nox:ignore RULE-ID -- reason'"`,
//     parsed as waiving rule "RULE-ID".
//
// A directive's grammar is `nox:ignore <IDs> [-- reason]`: after the rule IDs
// the line must end, close the comment, or introduce a reason with `--`.
// Free prose after the IDs means the text is describing a directive, not
// issuing one. And a directive inside a string literal is a program printing
// the syntax, never a waiver on the string's own line.
func TestScanForSuppressions_ProseAndStringsAreNotDirectives(t *testing.T) {
	cases := []struct {
		name, path, line string
		want             bool // true = a real directive
	}{
		{
			name: "prose: wrapped doc comment mentioning the directive",
			path: "scan.go",
			line: "\t\t// nox:ignore comments, so nothing was missed and nothing is reported.",
			want: false,
		},
		{
			name: "string literal: help text teaching the syntax",
			path: "protect_cmd.go",
			line: `    echo "nox: use '// nox:ignore RULE-ID -- reason' to suppress false positives"`,
			want: false,
		},
		// Everything below is a real waiver and must keep working.
		{
			name: "real: rule id with reason",
			path: "scan.go",
			line: "\tfoo() // nox:ignore SEC-163 -- em dash in string not hex",
			want: true,
		},
		{
			name: "real: bare rule id, end of line",
			path: "scan.go",
			line: "\t// nox:ignore IAC-123",
			want: true,
		},
		{
			name: "real: comma-separated list",
			path: "server.go",
			line: "\t// nox:ignore SEC-659,SEC-506,SEC-574,SEC-664 -- reviewed",
			want: true,
		},
		{
			name: "real: space-separated list with reason",
			path: "corpus.go",
			line: "\tX = \"y\" // nox:ignore SEC-161 SEC-162 SEC-163 -- test canary, not a live secret",
			want: true,
		},
		{
			name: "real: yaml hash comment",
			path: "ci.yml",
			line: "  contents: write # nox:ignore IAC-314 -- needed for releases",
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanForSuppressions([]byte(tc.line+"\n"), tc.path)
			isDirective := len(got) > 0 && !got[0].DocExample
			if isDirective != tc.want {
				t.Errorf("directive=%v, want %v\n  line: %s\n  parsed: %+v", isDirective, tc.want, tc.line, got)
			}
		})
	}
}

// A directive nested inside a comment that already started the line is an
// EXAMPLE, not a waiver: this package's own doc comment lists the supported
// spellings (`//\t// nox:ignore SEC-001 -- …`), and a comment describing the
// parser quotes one inline. Both were read as live directives.
//
// It stayed invisible while the unused-waiver check only looked at files that
// already had a finding; sweeping clean files surfaced six of them in this one
// file. DocExample already existed for markdown fenced blocks — the same idea,
// extended to the code blocks and inline quotes that appear in source comments.
//
// Marking, not dropping: a doc example still matches a finding on its target
// line exactly as a markdown one does. It is only excluded from "this waiver
// suppresses nothing", where it would be pure noise.
func TestScanForSuppressions_NestedInCommentIsDocExample(t *testing.T) {
	cases := []struct {
		name, path, line string
		wantDoc          bool
	}{
		{
			name:    "go doc comment code block",
			path:    "suppress.go",
			line:    "//\t// nox:ignore SEC-001 -- false positive in test",
			wantDoc: true,
		},
		{
			name:    "go doc comment listing the yaml spelling",
			path:    "suppress.go",
			line:    "//\t# nox:ignore SEC-001,SEC-002",
			wantDoc: true,
		},
		{
			name:    "go doc comment listing the html spelling",
			path:    "suppress.go",
			line:    "//\t<!-- nox:ignore AI-001 -->",
			wantDoc: true,
		},
		{
			name:    "prose comment quoting a directive inline",
			path:    "suppress.go",
			line:    "\t// contains `echo \"nox: use '// nox:ignore RULE-ID -- reason'\"`, which was",
			wantDoc: true,
		},
		// Real waivers: the directive's own marker starts the comment.
		{
			name:    "real: own-line directive",
			path:    "main.go",
			line:    "\t\t// nox:ignore IAC-123 -- reviewed",
			wantDoc: false,
		},
		{
			name:    "real: trailing directive after code",
			path:    "main.go",
			line:    "\tfoo() // nox:ignore SEC-163 -- em dash not hex",
			wantDoc: false,
		},
		{
			name:    "real: yaml trailing directive",
			path:    "ci.yml",
			line:    "  contents: write # nox:ignore IAC-314 -- needed for releases",
			wantDoc: false,
		},
		{
			name:    "real: yaml own-line directive",
			path:    "ci.yml",
			line:    "# nox:ignore SEC-001,SEC-002 -- reviewed",
			wantDoc: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanForSuppressions([]byte(tc.line+"\n"), tc.path)
			if len(got) == 0 {
				t.Fatalf("no directive parsed at all from: %s", tc.line)
			}
			if got[0].DocExample != tc.wantDoc {
				t.Errorf("DocExample=%v, want %v\n  line: %s", got[0].DocExample, tc.wantDoc, tc.line)
			}
		})
	}
}
