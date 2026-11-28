package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/treesitter"
)

// The C++ front end (tree_cpp.go): each joining test fails on the line
// segmenter (NOX_TAINT_TREESITTER=none) and passes with the tree.

func cppTreeOnly(t *testing.T, path, src string) []unitDraft {
	t.Helper()
	t.Setenv("NOX_TAINT_TREESITTER", "cpp")
	return extractUnitsAt(path, lexctx.LangCPP, []byte(src))
}

// stmtCallingWith is the first statement of fn that calls callee reading v.
func stmtCallingWith(us []unitDraft, fn, callee, v string) *stmtDraft {
	for _, u := range us {
		if u.funcName != fn {
			continue
		}
		for i := range u.stmts {
			if slices.Contains(u.stmts[i].calls, callee) && slices.Contains(u.stmts[i].reads, v) {
				return &u.stmts[i]
			}
		}
	}
	return nil
}

func TestCPPTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := cppTreeOnly(t, "x.cpp", "void h(Db &db, const std::string &id) {\n  std::string q = \"SELECT * FROM t WHERE id = \" +\n      id;\n  db.exec(q);\n}\n")
		if s := jsStmtAssigning(us, "h", "q"); s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", s)
		}
	})
	t.Run("initializer on the next line", func(t *testing.T) {
		us := cppTreeOnly(t, "x.cc", "void h() {\n  std::string c =\n      getenv(\"CMD\");\n  system(c.c_str());\n}\n")
		if s := jsStmtAssigning(us, "h", "c"); s == nil || !slices.Contains(s.calls, "getenv") {
			t.Fatalf("c must be assigned from getenv; got %+v", s)
		}
	})
	t.Run("a return continued on the next line", func(t *testing.T) {
		us := cppTreeOnly(t, "x.cxx", "std::string h() {\n  return\n      getenv(\"CMD\");\n}\n")
		if s := stmtCalling(us, "h", "getenv"); s == nil || !s.isReturn {
			t.Fatalf("the return must call getenv; got %+v", s)
		}
	})
	t.Run("the flow is reported", func(t *testing.T) {
		src := "void h() {\n  std::string c = std::string(\"ls \") +\n      getenv(\"CMD\");\n  system(c.c_str());\n}\n"
		t.Setenv("NOX_TAINT_TREESITTER", "cpp")
		flows := NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("x.cpp", lexctx.LangCPP, []byte(src)))
		if !hasRule(flows, "TAINT-002") {
			t.Fatalf("getenv to system across lines: want TAINT-002; got %v", ruleIDs(flows))
		}
	})
}

func TestCPPTreeKeepsChainsAndBodiesApart(t *testing.T) {
	// Joined, each would call the sink with a constant while reading the
	// tainted id in the same statement, a flow the code does not have.
	chains := map[string]string{
		"member chain": "void h(Db &db, const std::string &id) {\n  auto r = db\n      .exec(\"SELECT 1\")\n      .bind(id);\n}\n",
		"arrow chain":  "void h(Db *db, const std::string &id) {\n  db->exec(\"SELECT 1\")\n      ->bind(id);\n}\n",
	}
	for name, src := range chains {
		t.Run(name, func(t *testing.T) {
			us := cppTreeOnly(t, "x.cpp", src)
			for _, callee := range []string{"db.exec", "db->exec", "exec"} {
				if s := stmtCallingWith(us, "h", callee, "id"); s != nil {
					t.Fatalf("%s and id joined into one statement: %+v", callee, s)
				}
			}
		})
	}
	t.Run("a lambda body keeps its own statements", func(t *testing.T) {
		us := cppTreeOnly(t, "x.cpp", "void h(Db &db) {\n  auto f = [&](const std::string &id) {\n    db.exec(\"SELECT 1\");\n    log(id);\n  };\n}\n")
		if s := stmtCallingWith(us, "h", "db.exec", "id"); s != nil {
			t.Fatalf("the lambda body was joined: %+v", s)
		}
	})
	t.Run("an error elsewhere costs only its own statements", func(t *testing.T) {
		src := "void g() {\n  UNKNOWN_FOREACH(x) int y = ) 1;\n}\n" +
			"void h() {\n  std::string c =\n      getenv(\"CMD\");\n}\n"
		if s := jsStmtAssigning(cppTreeOnly(t, "x.cpp", src), "h", "c"); s == nil || !slices.Contains(s.calls, "getenv") {
			t.Fatalf("an error in g stopped h's join; got %+v", s)
		}
	})
	t.Run("headers keep the line segmenter", func(t *testing.T) {
		src := "void h() {\n  std::string c =\n      getenv(\"CMD\");\n}\n"
		if s := jsStmtAssigning(cppTreeOnly(t, "x.h", src), "h", "c"); s != nil && slices.Contains(s.calls, "getenv") {
			t.Fatalf("a header was read by the C++ tree: %+v", s)
		}
	})
}

// The join set itself: a chained call blocks its statement, a binary
// expression free of chains joins even inside one, and an error statement
// never joins.
func TestCPPTreeLineJoins(t *testing.T) {
	joins := func(t *testing.T, src string) map[int]bool {
		t.Helper()
		b := []byte(src)
		tree, _ := sharedTreeParser().ParseFile(context.Background(), "cpp", b, treesitter.Budget{})
		if tree == nil {
			t.Fatal("no tree")
		}
		return treeLineJoinsBlocked(tree, b, cppStatementKinds, cppBodyKinds, cppChainedCall)
	}
	if j := joins(t, "void h() {\n  auto r = db\n      .exec(\"x\")\n      .bind(id);\n}\n"); j[2] || j[3] {
		t.Errorf("a chained statement was joined: %v", j)
	}
	if j := joins(t, "void h() {\n  out << db.exec(\"x\").get() << a +\n      b;\n}\n"); !j[2] {
		t.Errorf("a binary expression without a chain, inside a chained statement, was not joined: %v", j)
	}
	if j := joins(t, "void h() {\n  std::string q = make().prefix +\n      id;\n}\n"); !j[2] {
		t.Errorf("a member read off a call's result blocked the join: %v", j)
	}
	if j := joins(t, "void h() {\n  std::string c =\n      @ getenv(\"CMD\");\n}\n"); j[2] {
		t.Errorf("a statement holding an error was joined: %v", j)
	}
	if j := joins(t, "void h() {\n  std::string c =\n      getenv(\"CMD\");\n}\n"); !j[2] {
		t.Errorf("a clean declarator was not joined: %v", j)
	}
}
