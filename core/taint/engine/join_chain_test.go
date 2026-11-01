package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestJoinChainContinuations(t *testing.T) {
	ln := func(s string) logicalLine { return logicalLine{line: 1, code: s, raw: s} }
	tests := []struct {
		name  string
		in    []string
		extra []string
		want  []string
	}{
		{"fluent chain", []string{"x = a.b()", "    .c(q)", "    .d()"}, nil, []string{"x = a.b().c(q).d()"}},
		{"php arrow", []string{"$x = $a->b()", "  ->c($q);"}, []string{"->"}, []string{"$x = $a->b()->c($q);"}},
		{"after a block close", []string{"}", ".c()"}, nil, []string{"}", ".c()"}},
		{"after a statement end", []string{"f();", ".c()"}, nil, []string{"f();", ".c()"}},
		{"range is not member access", []string{"for i in 0", "..n {"}, nil, []string{"for i in 0", "..n {"}},
		{"php arrow ignored unless asked", []string{"a", "->b"}, nil, []string{"a", "->b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var in []logicalLine
			for _, s := range tt.in {
				in = append(in, ln(s))
			}
			got := joinChainContinuations(in, joinAlways, tt.extra...)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d lines %v, want %d %v", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if got[i].code != tt.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i].code, tt.want[i])
				}
			}
		})
	}
}

// A comment is blanked to spaces in the code view and kept in the raw view. If a
// join trimmed each view by its own content, a trailing comment on a middle
// line shortened one and not the other, the views drifted out of alignment, and
// the call's raw arguments were lost: Command::new("sh") stopped being seen as a
// shell program (testdata/precision-suite-rust tp_cmdinjection.rs).
func TestJoinChainContinuationsKeepsViewsAligned(t *testing.T) {
	src := "let out = Command::new(\"sh\")\n    .arg(\"-c\") // run it\n    .arg(format!(\"x {}\", name)) // nox-expect\n    .output();\n"
	content := []byte(src)
	lines := logicalLines(content, lexctx.Classify(lexctx.LangRust, content), true)
	joined := joinChainContinuations(lines, joinAlways)
	if len(joined) != 1 {
		t.Fatalf("got %d lines, want 1: %+v", len(joined), joined)
	}
	if len(joined[0].code) != len(joined[0].raw) {
		t.Errorf("views misaligned: code %d bytes, raw %d bytes", len(joined[0].code), len(joined[0].raw))
	}
}

// Rust joins only a request builder: the Command::new(..).arg(..) chain is
// reported on the .arg line, and joining it would move that finding.
func TestJoinOnlyBuildersLeavesCommandChainsAlone(t *testing.T) {
	in := []logicalLine{
		{line: 1, code: "let out = Command::new(\"sh\")", raw: "let out = Command::new(\"sh\")"},
		{line: 2, code: ".arg(x)", raw: ".arg(x)"},
	}
	if got := joinChainContinuations(in, joinOnlyBuilders); len(got) != 2 {
		t.Errorf("Command chain was joined: %+v", got)
	}
	in = []logicalLine{
		{line: 1, code: "let r = CreateChatCompletionRequestArgs::default()", raw: "let r = CreateChatCompletionRequestArgs::default()"},
		{line: 2, code: ".model(\"m\")", raw: ".model(\"m\")"},
	}
	if got := joinChainContinuations(in, joinOnlyBuilders); len(got) != 1 {
		t.Errorf("request builder was not joined: %+v", got)
	}
}
