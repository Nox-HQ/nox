package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// The Python SQL sinks are cursor.execute and connection.execute, matched on
// the call chain as written, so they matched only when the variable was named
// `cursor` or `connection`. Real code, and every SQL case in the OWASP
// Benchmark for Python, writes `cur = con.cursor(); cur.execute(sql)`: nox
// scored 0 of 16 there while Semgrep scored 16.
func TestAPythonCursorIsACursorWhateverItIsCalled(t *testing.T) {
	const flask = "from flask import request\nimport sqlite3\n\n"
	for _, c := range []struct{ name, body string }{
		{"cur from con.cursor()", "def h():\n    q = request.form.get('q')\n    con = sqlite3.connect('x.db')\n    cur = con.cursor()\n    cur.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"},
		{"c from db.cursor()", "def h():\n    q = request.args.get('q')\n    c = get_db().cursor()\n    c.execute(\"SELECT * FROM t WHERE a = '\" + q + \"'\")\n"},
		{"with ... as c", "def h():\n    q = request.args.get('q')\n    with con.cursor() as c:\n        c.execute(f\"DELETE FROM t WHERE a = '{q}'\")\n"},
		{"conn from connect()", "def h():\n    q = request.args.get('q')\n    conn = sqlite3.connect('x.db')\n    conn.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"},
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, flask+c.body); !slices.Contains(got, "TAINT-001") {
			t.Errorf("%s: no SQL injection reported (got %v)", c.name, got)
		}
	}

	// A parameterised query is the safe form and stays unreported, whether
	// the SQL is written inline or held in a variable -- the second was
	// reported for any cursor, because "the first argument is a variable" was
	// read as "the first argument is tainted" (OWASP BenchmarkTest00011).
	for name, body := range map[string]string{
		"inline sql":   "def h():\n    q = request.form.get('q')\n    cur = sqlite3.connect('x.db').cursor()\n    cur.execute(\"SELECT * FROM t WHERE a = ?\", (q,))\n",
		"sql variable": "def h():\n    q = request.form.get('q')\n    sql = 'SELECT * FROM t WHERE a = ?'\n    cur = con.cursor()\n    cur.execute(sql, (q,))\n",
		"named cursor": "def h():\n    q = request.form.get('q')\n    sql = f'SELECT * FROM t WHERE a = ?'\n    cursor.execute(sql, (q,))\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, flask+body); slices.Contains(got, "TAINT-001") {
			t.Errorf("%s: a parameterised query was reported: %v", name, got)
		}
	}
	// ... and taint that reaches the SQL string itself is still reported.
	mixed := flask + "def h():\n    q = request.form.get('q')\n    sql = f\"SELECT * FROM t WHERE a = '{q}' AND b = ?\"\n    cur = con.cursor()\n    cur.execute(sql, (1,))\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, mixed); !slices.Contains(got, "TAINT-001") {
		t.Errorf("taint in the SQL string of a two-argument call was not reported: %v", got)
	}
}
