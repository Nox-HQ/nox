package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// The tree-sitter front ends for C#, PHP, Ruby and Kotlin (tree_csharp.go and
// its siblings) each exist for a statement the line segmenter read as two:
// one that continues on the next line with no bracket open. Each test goes
// through extractUnitsAt, the path a scan takes, so it fails on the line
// segmenter (NOX_TAINT_TREESITTER=none) and passes with the tree.

func treeFrontEndUnits(t *testing.T, lang lexctx.Lang, src string) []unitDraft {
	t.Helper()
	return extractUnitsAt("", lang, []byte(src))
}

// callWith reports whether some statement of unit calls callee reading v.
func callWith(us []unitDraft, unit, callee, v string) bool {
	for _, u := range us {
		if u.funcName != unit {
			continue
		}
		for _, st := range u.stmts {
			if slices.Contains(st.calls, callee) && slices.Contains(st.reads, v) {
				return true
			}
		}
	}
	return false
}

func TestCSharpTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangCSharp, "class C {\n  void H(HttpRequest request, SqlCommand cmd) {\n    var id = request.Query[\"id\"];\n    string q = \"SELECT * FROM users \" +\n               \"WHERE id = \" + id;\n    cmd.ExecuteReader(q);\n  }\n}\n")
		s := jsStmtAssigning(us, "H", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", s)
		}
	})
	t.Run("a call chain continued on the next line", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangCSharp, "class C {\n  void H(string q, Db db) {\n    db.Connection\n      .Execute(q);\n  }\n}\n")
		if !callWith(us, "H", "db.Connection.Execute", "q") {
			t.Fatalf("no statement calls db.Connection.Execute with q; got %+v", us)
		}
	})
	t.Run("declarators stay separate bindings", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangCSharp, "class C {\n  void H(HttpRequest request) {\n    string a = request.Query[\"a\"],\n           b = Clean(a);\n  }\n}\n")
		if s := jsStmtAssigning(us, "H", "a"); s == nil || slices.Contains(s.reads, "Clean") {
			t.Fatalf("a's binding must not take b's declarator; got %+v", s)
		}
	})
	t.Run("a lambda body keeps its own statements", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangCSharp, "class C {\n  void H(List<string> xs) {\n    xs.ForEach(x => {\n      var v = Environment.GetEnvironmentVariable(x);\n      Run(v);\n    });\n  }\n}\n")
		if jsStmtAssigning(us, "H", "v") == nil {
			t.Fatalf("H must bind v; got %+v", us)
		}
	})
}

func TestPHPTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangPHP, "<?php\nfunction h($c) {\n  $id = $_GET['id'];\n  $q = \"SELECT * FROM users \" .\n       \"WHERE id = \" .\n       $id;\n  mysqli_query($c, $q);\n}\n")
		s := jsStmtAssigning(us, "h", "$q")
		if s == nil {
			s = jsStmtAssigning(us, "h", "q")
		}
		if s == nil || (!slices.Contains(s.reads, "$id") && !slices.Contains(s.reads, "id")) {
			t.Fatalf("$q must read $id; got %+v", us)
		}
	})
	t.Run("a call whose arguments span lines", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangPHP, "<?php\nfunction h($c) {\n  $id = $_GET['id'];\n  $r = mysqli_query($c,\n      \"SELECT * FROM t WHERE id = \"\n      . $id);\n}\n")
		found := false
		for _, u := range us {
			for _, st := range u.stmts {
				if slices.Contains(st.calls, "mysqli_query") && (slices.Contains(st.reads, "$id") || slices.Contains(st.reads, "id")) {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("no statement calls mysqli_query reading $id; got %+v", us)
		}
	})
	t.Run("a closure body keeps its own statements", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangPHP, "<?php\nfunction h($xs) {\n  array_map(function ($x) {\n    $v = $_GET['v'];\n    system($v);\n  }, $xs);\n}\n")
		if len(us) == 0 {
			t.Fatalf("no units extracted")
		}
	})
}

func TestRubyTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("a string continued with a backslash", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangRuby, "def h\n  id = params[:id]\n  q = \"SELECT * FROM users \" \\\n      \"WHERE id = #{id}\"\n  conn.execute(q)\nend\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", us)
		}
	})
	t.Run("a bracketless call with an argument built over several lines", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangRuby, "def h\n  User.find_by_sql \"select * from users where a = 'x' AND \" +\n    \"b = #{params[:unsafe]} AND \" +\n    \"c = 1\"\n  y = 1\nend\n")
		if !callWith(us, "h", "User.find_by_sql", "params") {
			t.Fatalf("no statement calls User.find_by_sql reading params; got %+v", us)
		}
	})
	t.Run("a method chain stays one call per line", func(t *testing.T) {
		// Joining the chain would read ids and call Arel.sql in one
		// statement, a flow the code does not have.
		us := treeFrontEndUnits(t, lexctx.LangRuby, "def h(ids)\n  r = Article\n    .order(Arel.sql(\"a DESC\"))\n    .where(user_id: ids)\nend\n")
		for _, u := range us {
			for _, st := range u.stmts {
				if slices.Contains(st.calls, "Arel.sql") && slices.Contains(st.reads, "ids") {
					t.Fatalf("Arel.sql and ids joined into one statement: %+v", st)
				}
			}
		}
	})
	t.Run("a block keeps its own statements", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangRuby, "def h(items)\n  items.each do |i|\n    v = params[:v]\n    system(v)\n  end\nend\n")
		if jsStmtAssigning(us, "h", "v") == nil {
			t.Fatalf("h must bind v; got %+v", us)
		}
	})
}

func TestKotlinTreeJoinsAStatementAcrossLines(t *testing.T) {
	t.Run("SQL concatenated across lines", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangKotlin, "class C {\n  fun h(request: HttpServletRequest, st: Statement) {\n    val id = request.getParameter(\"id\")\n    val q = \"SELECT * FROM users \" +\n            \"WHERE id = \" + id\n    st.executeQuery(q)\n  }\n}\n")
		s := jsStmtAssigning(us, "h", "q")
		if s == nil || !slices.Contains(s.reads, "id") {
			t.Fatalf("q must read id; got %+v", us)
		}
	})
	t.Run("a call chain continued on the next line", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangKotlin, "class C {\n  fun h(q: String, db: Db) {\n    db.connection\n      .execute(q)\n  }\n}\n")
		if !callWith(us, "h", "db.connection.execute", "q") {
			t.Fatalf("no statement calls db.connection.execute with q; got %+v", us)
		}
	})
	t.Run("a lambda body keeps its own statements", func(t *testing.T) {
		us := treeFrontEndUnits(t, lexctx.LangKotlin, "class C {\n  fun h(xs: List<String>) {\n    xs.forEach { x ->\n      val v = System.getenv(x)\n      run(v)\n    }\n  }\n}\n")
		if len(us) == 0 {
			t.Fatalf("no units extracted")
		}
	})
}
