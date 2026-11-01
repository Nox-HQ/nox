package engine

import "testing"

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
			got := joinChainContinuations(in, tt.extra...)
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
