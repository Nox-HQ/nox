package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// readsFor extracts the variables one statement reads, which is what decides
// whether taint reaches a sink.
func readsFor(t *testing.T, src, marker string) []string {
	t.Helper()
	units := ExtractUnits("a.go", lexctx.LangGo, []byte(src))
	for _, u := range units {
		for i := range u.Stmts {
			st := &u.Stmts[i]
			for _, c := range st.Calls {
				if strings.Contains(c, marker) {
					return st.Reads
				}
			}
		}
	}
	t.Fatalf("no statement calling %q found", marker)
	return nil
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// A tainted value assembled into a composite literal is still passed to the
// sink. Before this, the walk stopped at the brace: a struct, slice or map
// literal was opaque, so the identifiers inside it were never read.
//
// It is the dominant shape in Go SDK calls — a model invocation's parameters, a
// query config, an options struct are all composite literals — and it made Go
// asymmetric with Python, where the equivalent nested dict was already tracked.
func TestCompositeLiteralArgumentsAreRead(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "struct literal field",
			src:  "package p\nfunc f(user string) { sink(Params{Query: user}) }\n",
			want: "user",
		},
		{
			name: "slice literal element",
			src:  "package p\nfunc f(user string) { sink([]string{user}) }\n",
			want: "user",
		},
		{
			name: "map literal value",
			src:  "package p\nfunc f(user string) { sink(map[string]string{\"k\": user}) }\n",
			want: "user",
		},
		{
			name: "nested literal, concatenated",
			// The real SDK shape: a slice inside a struct, with the tainted
			// value concatenated into a string.
			src:  "package p\nfunc f(user string) { sink(Params{Messages: []string{\"you are \" + user}}) }\n",
			want: "user",
		},
		{
			name: "literal nested two deep",
			src:  "package p\nfunc f(user string) { sink(A{B: B{C: []string{user}}}) }\n",
			want: "user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reads := readsFor(t, tt.src, "sink")
			if !contains(reads, tt.want) {
				t.Errorf("reads = %v, want to contain %q; a tainted value inside a "+
					"composite literal never reaches the sink", reads, tt.want)
			}
		})
	}
}

// A struct literal's KEYS are field names, not variables. Reading them would add
// every field name in every literal to the statement's reads — systematic noise
// that could taint a value because a field happened to share a variable's name.
//
// The cost is a tainted MAP key going unseen. That is the safe direction to
// miss: an invented read produces findings, a missed one does not.
func TestStructLiteralFieldNamesAreNotReads(t *testing.T) {
	src := "package p\nfunc f() { sink(Params{Query: \"literal\", Model: \"gpt\"}) }\n"
	reads := readsFor(t, src, "sink")
	for _, bad := range []string{"Query", "Model"} {
		if contains(reads, bad) {
			t.Errorf("field name %q was read as a variable: reads = %v", bad, reads)
		}
	}
}

// The fix must not make every literal a source of reads. A literal with no
// identifiers in it reads nothing.
func TestLiteralWithNoIdentifiersReadsNothing(t *testing.T) {
	src := "package p\nfunc f() { sink([]string{\"a\", \"b\"}) }\n"
	reads := readsFor(t, src, "sink")
	for _, r := range reads {
		if r == "a" || r == "b" {
			t.Errorf("a string literal element was read as a variable: %v", reads)
		}
	}
}
