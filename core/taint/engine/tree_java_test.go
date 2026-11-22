package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func javaTreeUnits(t *testing.T, src string) []unitDraft {
	t.Helper()
	content := []byte(src)
	lines, ok := javaTreeLines(content, lexctx.Classify(lexctx.LangJava, content))
	if !ok {
		t.Fatal("the parser declined the source")
	}
	return extractJava(splitSemicolons(joinChainContinuations(lines, joinAlways)))
}

func TestJavaTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := javaTreeUnits(t, "class C {\n  void h(HttpServletRequest request, Statement st) throws Exception {\n    String id = request.getParameter(\"id\");\n    String q = \"SELECT * FROM users \" +\n               \"WHERE id = \" + id;\n    st.executeQuery(q);\n  }\n}\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", s)
		}
	})
	t.Run("declarators stay separate bindings", func(t *testing.T) {
		us := javaTreeUnits(t, "class C {\n  void h(HttpServletRequest request) {\n    String a = request.getParameter(\"a\"),\n           b = clean(a);\n  }\n}\n")
		if s := jsStmtAssigning(us, "h", "a"); s == nil || slices.Contains(s.reads, "clean") {
			t.Fatalf("a's binding must not take b's declarator; got %+v", s)
		}
	})
	t.Run("an anonymous class body keeps its own statements", func(t *testing.T) {
		us := javaTreeUnits(t, "class C {\n  Runnable r = new Runnable() {\n    public void run() {\n      String v = System.getenv(\"V\");\n      exec(v);\n    }\n  };\n}\n")
		if jsStmtAssigning(us, "run", "v") == nil {
			t.Fatalf("run must bind v; got %+v", us)
		}
	})
}
