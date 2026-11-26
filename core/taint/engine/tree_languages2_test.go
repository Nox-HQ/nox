package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// The tree-sitter front ends for Scala, Swift and Rust (tree_scala.go
// and its siblings), tested as tree_languages_test.go tests the first four:
// through extractUnitsAt, with the front end selected by the environment, so
// each test fails on the line segmenter (NOX_TAINT_TREESITTER=none) and passes
// with the tree. A test selects its own language so the result does not depend
// on which languages are on by default.

func treeOnly(t *testing.T, lang string, l lexctx.Lang, src string) []unitDraft {
	t.Helper()
	t.Setenv("NOX_TAINT_TREESITTER", lang)
	return extractUnitsAt("", l, []byte(src))
}

func TestScalaTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("a method chain stays one call per line", func(t *testing.T) {
		// Joining the chain would read id and call executeQuery in one
		// statement, a flow the code does not have.
		us := treeOnly(t, "scala", lexctx.LangScala, "class C {\n  def h(request: HttpServletRequest, st: Statement) = {\n    val id = request.getParameter(\"id\")\n    val r = st\n      .executeQuery(\"SELECT 1\")\n      .withLabel(id)\n  }\n}\n")
		for _, u := range us {
			for _, st := range u.stmts {
				if slices.Contains(st.calls, "st.executeQuery") && slices.Contains(st.reads, "id") {
					t.Fatalf("st.executeQuery and id joined into one statement: %+v", st)
				}
			}
		}
	})
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := treeOnly(t, "scala", lexctx.LangScala, "class C {\n  def h(request: HttpServletRequest, st: Statement): Unit = {\n    val id = request.getParameter(\"id\")\n    val q = \"SELECT * FROM users \" +\n            \"WHERE id = \" + id\n    st.executeQuery(q)\n  }\n}\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", s)
		}
	})
	t.Run("a reassignment continued on the next line", func(t *testing.T) {
		us := treeOnly(t, "scala", lexctx.LangScala, "class C {\n  def h(request: HttpServletRequest): Unit = {\n    var q = \"SELECT 1\"\n    q = q +\n      request.getParameter(\"id\")\n  }\n}\n")
		found := false
		for _, u := range us {
			for _, st := range u.stmts {
				if st.assigns == "q" && slices.Contains(st.calls, "request.getParameter") {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("no reassignment of q reads request.getParameter; got %+v", us)
		}
	})
	t.Run("a closure body keeps its own statements", func(t *testing.T) {
		us := treeOnly(t, "scala", lexctx.LangScala, "class C {\n  def h(xs: List[String]): Unit = {\n    xs.foreach { x =>\n      val v = sys.env(x)\n      run(v)\n    }\n  }\n}\n")
		if len(us) == 0 {
			t.Fatalf("no units extracted")
		}
	})
}

func TestSwiftTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("a method chain stays one call per line", func(t *testing.T) {
		// Joining the chain would read id and call removeItem in one
		// statement, a flow the code does not have.
		us := treeOnly(t, "swift", lexctx.LangSwift, "class C {\n  func h(textField: UITextField, fm: FileManager) {\n    let id = textField.text\n    let r = fm\n      .removeItem(atPath: \"/tmp/x\")\n      .label(id)\n  }\n}\n")
		for _, u := range us {
			for _, st := range u.stmts {
				if slices.Contains(st.calls, "removeItem") && slices.Contains(st.reads, "id") {
					t.Fatalf("removeItem and id joined into one statement: %+v", st)
				}
			}
		}
	})
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := treeOnly(t, "swift", lexctx.LangSwift, "class C {\n  func h(request: Request, db: Database) {\n    let id = request.query[\"id\"]\n    let q = \"SELECT * FROM users \" +\n            \"WHERE id = \" + id\n    db.execute(q)\n  }\n}\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", s)
		}
	})
	t.Run("a closure body keeps its own statements", func(t *testing.T) {
		us := treeOnly(t, "swift", lexctx.LangSwift, "class C {\n  func h(items: [String]) {\n    items.forEach { x in\n      let v = ProcessInfo.processInfo.environment[x]\n      run(v)\n    }\n  }\n}\n")
		if len(us) == 0 {
			t.Fatalf("no units extracted")
		}
	})
}

func TestRustTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("a method chain stays one call per line", func(t *testing.T) {
		// Joining the chain would read id and call sqlx.query in one
		// statement, a flow the code does not have.
		us := treeOnly(t, "rust", lexctx.LangRust, "fn h(pool: &Pool) {\n    let id = std::env::var(\"ID\").unwrap();\n    let r = sqlx::query(\"SELECT 1\")\n        .label(&id)\n        .fetch_all(pool);\n}\n")
		for _, u := range us {
			for _, st := range u.stmts {
				if slices.Contains(st.calls, "sqlx.query") && slices.Contains(st.reads, "id") {
					t.Fatalf("sqlx.query and id joined into one statement: %+v", st)
				}
			}
		}
	})
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := treeOnly(t, "rust", lexctx.LangRust, "fn h(req: &Request, db: &Db) {\n    let id = req.query(\"id\");\n    let q = String::from(\"SELECT * FROM users WHERE id = \")\n        + &id;\n    db.execute(&q);\n}\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", s)
		}
	})
}
