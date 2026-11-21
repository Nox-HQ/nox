package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// paramSQLLines returns the sink lines of the parameter-sourced SQL flows.
func paramSQLLines(flows []taint.Flow) []int {
	var lines []int
	for i := range flows {
		if flows[i].Source.Kind == SourceParameter && flows[i].Sink.VulnClass == taint.VulnSQLInjection {
			lines = append(lines, flows[i].SinkLine)
		}
	}
	return lines
}

// The shapes the RealVuln benchmark labels and nox missed: a DAO-style function
// assembles its argument into the query, and the request is parsed in a file
// this one does not show. Every case names the line of the sink.
func TestAQueryBuiltFromAParameterIsReported(t *testing.T) {
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		src  string
		line int
	}{
		{"python format at the call", lexctx.LangPython,
			"def login(cursor, username):\n    return cursor.execute(\"SELECT * FROM users WHERE username = '{}'\".format(username)).fetchone()\n", 2},
		{"python percent into a local", lexctx.LangPython,
			"def find(cursor, name):\n    q = \"SELECT * FROM users WHERE name = '%s'\" % name\n    cursor.execute(q)\n", 3},
		{"python f-string", lexctx.LangPython,
			"def find(cursor, name):\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n", 2},
		{"python built in pieces", lexctx.LangPython,
			"def search(cursor, name):\n    q = \"SELECT * FROM users\"\n    q += \" WHERE name = '%s'\" % name\n    cursor.execute(q)\n", 4},
		{"java concatenation at the call", lexctx.LangJava,
			"package a;\n\npublic class Dao {\n    public boolean login(Statement st, String user) throws Exception {\n        ResultSet rs = st.executeQuery(\"SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = '\" + user + \"'\");\n        return rs.next();\n    }\n}\n", 5},
		{"javascript template literal", lexctx.LangJavaScript,
			"function getProduct(productId) {\n  const q = `SELECT * FROM products WHERE id = '${productId}'`;\n  return db.query(q);\n}\n", 3},
	} {
		got := paramSQLLines(analyzeFile(t, c.lang, c.src))
		if len(got) != 1 || got[0] != c.line {
			t.Errorf("%s: parameter SQL flows at lines %v, want [%d]", c.name, got, c.line)
		}
	}
}

// The premise that keeps the parameter flow from reporting every function
// that hands a string to something named execute: the parameter must be built
// into SQL text. Each case reaches a SQL sink from a parameter without that.
func TestAParameterNotBuiltIntoSQLTextIsNotReported(t *testing.T) {
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		src  string
	}{
		{"python pass-through wrapper", lexctx.LangPython,
			"def run(cursor, sql):\n    cursor.execute(sql)\n"},
		{"python parameterized", lexctx.LangPython,
			"def find(cursor, name):\n    cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n"},
		{"python prose, not SQL", lexctx.LangPython,
			"def note(cursor, who):\n    msg = \"tell me where \" + who + \" and when\"\n    cursor.execute(msg)\n"},
		{"java executor named execute", lexctx.LangJava,
			"package a;\n\npublic class Jobs {\n    public void later(Runnable task) {\n        pool.execute(task);\n    }\n}\n"},
		{"java prepared statement wrapper", lexctx.LangJava,
			"package a;\n\npublic class Conn {\n    public PreparedStatement wrap(String sql) throws Exception {\n        return delegate.prepareStatement(sql);\n    }\n}\n"},
		{"javascript placeholders", lexctx.LangJavaScript,
			"function list(limit) {\n  return db.query(\"SELECT * FROM products LIMIT ?\", [limit]);\n}\n"},
	} {
		if got := paramSQLLines(analyzeFile(t, c.lang, c.src)); len(got) != 0 {
			t.Errorf("%s: reported at lines %v", c.name, got)
		}
	}
}

// One query is one finding. A source in a caller in the same file is reported
// as the cross-function flow it is, and the parameter flow inside the helper
// would only repeat it.
func TestAParameterFlowDoesNotRepeatACallersFlow(t *testing.T) {
	src := "from flask import request\n\ndef find(cursor, name):\n    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n\ndef h():\n    return find(cursor, request.args.get('name'))\n"
	flows := analyzeFile(t, lexctx.LangPython, src)
	if got := paramSQLLines(flows); len(got) != 0 {
		t.Errorf("parameter flow repeated the caller's: %v", got)
	}
	if !flowWithIntermediate(flows, "find") {
		t.Errorf("the caller's flow through find was not reported: %+v", flows)
	}
}

// Which variables an expression combines with SQL text. Beside it is not in
// it: the receiver of the call taking the SQL and a sibling argument of that
// call are separate operands (the PHP and C# clean fixtures of the precision
// suites, which the first version of this reported).
func TestSQLBuiltVars(t *testing.T) {
	for raw, want := range map[string]string{
		`"SELECT a FROM t WHERE id = " + id`:                            "id",
		`"select * from users where name = '" + n`:                      "n",
		`"INSERT INTO t VALUES ('" + v + "')"`:                          "v",
		`"update users set name = '" + n + "'"`:                         "n",
		`" AND name LIKE '%" + q + "%'"`:                                "q",
		`" ORDER BY " + col`:                                            "col",
		`"SELECT * FROM u WHERE n = '%s' AND r = '%s'" % (a, b)`:        "a b",
		`"SELECT * FROM u WHERE n = '{}'".format(name)`:                 "name",
		`String.format("SELECT * FROM u WHERE id = %s", id)`:            "id",
		`"select a file from the list: " + f`:                           "f", // statement shape in either case; a known cost
		`$pdo->prepare("SELECT name FROM users WHERE id = :id")`:        "",
		`new SqlCommand("SELECT name FROM users WHERE id = @id", conn)`: "",
		`this.db.query("SELECT * FROM t WHERE id = ?", [id])`:           "",
		`"tell me where " + who`:                                        "",
		`"Update failed for " + who`:                                    "",
		"`SELECT * FROM t WHERE id = '${id}'`":                          "id",
		"sql`select * from jobs where d ilike ${term} limit 50`":        "",
		"sql.raw(`select * from jobs where ${filter} limit 50`)":        "filter",
		`"Hello, " + name`:                                              "",
	} {
		got := strings.Join(sqlBuiltVars(blankStringsForTest(raw), raw), " ")
		if got != want {
			t.Errorf("sqlBuiltVars(%s) = %q, want %q", raw, got, want)
		}
	}
}

// blankStringsForTest blanks double-quoted literals and the text of template
// literals the way the code view does, keeping offsets and keeping a
// template's ${...} substitutions as code.
func blankStringsForTest(raw string) string {
	b := []byte(raw)
	var quote byte
	sub := 0
	for i := 0; i < len(b); i++ {
		switch {
		case sub > 0:
			switch b[i] {
			case '{':
				sub++
			case '}':
				sub--
			}
		case quote == 0 && (b[i] == '"' || b[i] == '`'):
			quote = b[i]
			b[i] = ' '
		case quote != 0 && b[i] == quote:
			quote = 0
			b[i] = ' '
		case quote == '`' && b[i] == '$' && i+1 < len(b) && b[i+1] == '{':
			sub = 1
			i++
		case quote != 0:
			b[i] = ' '
		}
	}
	return string(b)
}
