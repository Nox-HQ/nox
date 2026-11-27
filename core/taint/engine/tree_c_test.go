package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/treesitter"
)

// The C front end (tree_c.go), tested as tree_languages2_test.go tests its
// siblings: each joining test fails on the line segmenter
// (NOX_TAINT_TREESITTER=none) and passes with the tree.

func cTreeOnly(t *testing.T, path, src string) []unitDraft {
	t.Helper()
	t.Setenv("NOX_TAINT_TREESITTER", "c")
	return extractUnitsAt(path, lexctx.LangCPP, []byte(src))
}

// stmtCalling is the first statement of unit fn that calls callee.
func stmtCalling(us []unitDraft, fn, callee string) *stmtDraft {
	for _, u := range us {
		if u.funcName != fn {
			continue
		}
		for i := range u.stmts {
			if slices.Contains(u.stmts[i].calls, callee) {
				return &u.stmts[i]
			}
		}
	}
	return nil
}

func TestCTreeJoinsAStatementAcrossLines(t *testing.T) {
	joined := []struct{ name, src, assigns string }{
		{"initializer on the next line", "void h(void) {\n  char *c =\n      getenv(\"CMD\");\n  system(c);\n}\n", "c"},
		{"cast on its own line", "void h(void) {\n  char *c = (char *)\n      getenv(\"CMD\");\n  system(c);\n}\n", "c"},
		{"assignment continued", "void h(void) {\n  char *c;\n  c =\n      getenv(\"CMD\");\n  system(c);\n}\n", "c"},
	}
	for _, tt := range joined {
		t.Run(tt.name, func(t *testing.T) {
			s := jsStmtAssigning(cTreeOnly(t, "x.c", tt.src), "h", tt.assigns)
			if s == nil || !slices.Contains(s.calls, "getenv") {
				t.Fatalf("%s must be assigned from getenv; got %+v", tt.assigns, s)
			}
		})
	}
	t.Run("a return continued on the next line", func(t *testing.T) {
		// Split, the return reads nothing and the function's summary loses
		// that it returns its caller a tainted value.
		us := cTreeOnly(t, "x.c", "char *h(void) {\n  return\n      getenv(\"CMD\");\n}\n")
		s := stmtCalling(us, "h", "getenv")
		if s == nil || !s.isReturn {
			t.Fatalf("the return must call getenv; got %+v", s)
		}
	})
	t.Run("the flow is reported", func(t *testing.T) {
		src := "void h(void) {\n  char *c =\n      getenv(\"CMD\");\n  system(c);\n}\n"
		t.Setenv("NOX_TAINT_TREESITTER", "c")
		flows := NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("x.c", lexctx.LangCPP, []byte(src)))
		if !hasRule(flows, "TAINT-002") {
			t.Fatalf("getenv to system across lines: want TAINT-002; got %v", ruleIDs(flows))
		}
	})
}

func TestCTreeKeepsTheLineSegmenterWhereTheTreeCannotDecide(t *testing.T) {
	t.Run("a statement holding an error is not joined", func(t *testing.T) {
		// Error recovery guesses where the declaration ends and takes in the
		// next line's call: joined, system would be called assigning c from
		// getenv in one statement.
		for _, src := range []string{
			"void h(void) {\n  char *c =\n      getenv(\"CMD\") ? : ;\n  system(c);\n}\n",
			"void h(void) {\n  int a[] = { ]\n  char *c =\n      getenv(\"CMD\");\n  system(c);\n}\n",
		} {
			if s := stmtCalling(cTreeOnly(t, "x.c", src), "h", "system"); s != nil && slices.Contains(s.calls, "getenv") {
				t.Errorf("%q: a statement holding an error was joined: %+v", src, s)
			}
		}
	})
	t.Run("an error elsewhere costs only its own statements", func(t *testing.T) {
		// g's body does not parse (an unknown macro used as a statement
		// keyword); h's statements are joined all the same.
		src := "void g(void) {\n  UNKNOWN_FOREACH(x) int y = ) 1;\n}\n" +
			"void h(void) {\n  char *c =\n      getenv(\"CMD\");\n  system(c);\n}\n"
		s := jsStmtAssigning(cTreeOnly(t, "x.c", src), "h", "c")
		if s == nil || !slices.Contains(s.calls, "getenv") {
			t.Fatalf("an error in g stopped h's join; got %+v", s)
		}
	})
	t.Run("headers and C++ keep the line segmenter", func(t *testing.T) {
		src := "void h(void) {\n  char *c =\n      getenv(\"CMD\");\n  system(c);\n}\n"
		for _, path := range []string{"x.h", "x.cpp", "x.cc"} {
			if s := jsStmtAssigning(cTreeOnly(t, path, src), "h", "c"); s != nil && slices.Contains(s.calls, "getenv") {
				t.Errorf("%s was read by the C tree: %+v", path, s)
			}
		}
	})
	t.Run("a declaration is joined per declarator", func(t *testing.T) {
		// Joined whole, b would be assigned reading a's initializer.
		us := cTreeOnly(t, "x.c", "void h(void) {\n  char *b = \"ls\",\n       *a =\n          getenv(\"CMD\");\n  system(b);\n}\n")
		if s := jsStmtAssigning(us, "h", "b"); s == nil || slices.Contains(s.calls, "getenv") {
			t.Fatalf("b must be assigned its own constant; got %+v", s)
		}
	})
}

// The join set itself, for the guards whose effect the extractor also limits
// (it splits at semicolons and braces): a statement holding an error, an
// initializer list or a block is never joined.
func TestCTreeLineJoins(t *testing.T) {
	cases := []struct {
		name, src string
		line      int // a line that must not be joined with the next
	}{
		{"an error inside the statement", "void h(void) {\n  char *c =\n      @ getenv(\"CMD\");\n  system(c);\n}\n", 2},
		{"a declarator inside an ERROR node", "void h(void) {\n  x = ( {\n  char *c =\n      getenv(\"CMD\");\n  system(c);\n}\n", 3},
		{"an initializer list", "void h(void) {\n  struct e t[] = {\n    {\"a\", getenv(\"CMD\")},\n    {\"b\", \"ls\"},\n  };\n}\n", 3},
		{"a statement expression", "void h(void) {\n  int n = ({\n    int m = 1;\n    m; });\n}\n", 2},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.src)
			tree, _ := sharedTreeParser().ParseFile(context.Background(), "c", src, treesitter.Budget{})
			if tree == nil {
				t.Fatal("no tree")
			}
			if join := treeLineJoins(tree, src, cStatementKinds, cBodyKinds); join[tt.line] {
				t.Fatalf("line %d joined: %v", tt.line, join)
			}
		})
	}
	// And the clean statement is joined, so the cases above fail for their
	// guard and not because nothing joins.
	src := []byte("void h(void) {\n  char *c =\n      getenv(\"CMD\");\n}\n")
	tree, _ := sharedTreeParser().ParseFile(context.Background(), "c", src, treesitter.Budget{})
	if join := treeLineJoins(tree, src, cStatementKinds, cBodyKinds); !join[2] {
		t.Fatalf("a clean declarator was not joined: %v", join)
	}
}
