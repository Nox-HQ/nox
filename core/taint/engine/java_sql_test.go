package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A prepared statement is safe only when its SQL string is constant. The
// catalog listed prepareStatement as a SQL sanitizer, which cleared the
// classic JDBC injection -- `prepareStatement("... '" + param + "'")` --
// instead of reporting it.
func TestJavaPreparedStatementWithTaintedSQLIsInjection(t *testing.T) {
	// Reported once, where the statement is prepared -- not again at the
	// zero-argument execute() that runs it.
	once := "class A {\n  void doPost(HttpServletRequest request) throws Exception {\n    String param = request.getParameter(\"q\");\n" +
		"    PreparedStatement st = connection.prepareStatement(\"SELECT * FROM U WHERE N='\" + param + \"'\");\n    ResultSet rs = st.executeQuery();\n  }\n}\n"
	if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, once); len(got) != 1 {
		t.Errorf("want exactly one TAINT-001, got %v", got)
	}

	head := "class A {\n  void doPost(HttpServletRequest request) throws Exception {\n    String param = request.getParameter(\"q\");\n"
	tail := "  }\n}\n"
	for name, body := range map[string]string{
		"prepareStatement":       "    String sql = \"SELECT * FROM U WHERE N='\" + param + \"'\";\n    PreparedStatement st = connection.prepareStatement(sql);\n    st.execute();\n",
		"prepareCall":            "    CallableStatement cs = connection.prepareCall(\"{call p('\" + param + \"')}\");\n",
		"Spring queryForObject":  "    String sql = \"SELECT n FROM U WHERE id='\" + param + \"'\";\n    Object o = jdbcTemplate.queryForObject(sql, String.class);\n",
		"addBatch":               "    statement.addBatch(\"INSERT INTO U VALUES ('\" + param + \"')\");\n",
		"getParameterMap source": "    String v = request.getParameterMap().get(\"q\")[0];\n    statement.executeQuery(\"SELECT * FROM U WHERE N='\" + v + \"'\");\n",
		"getRequestURI source":   "    String u = request.getRequestURI();\n    statement.executeUpdate(\"DELETE FROM L WHERE p='\" + u + \"'\");\n",
	} {
		if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+body+tail); !slices.Contains(got, "TAINT-001") {
			t.Errorf("%s: SQL injection not reported (got %v)", name, got)
		}
	}
	for name, body := range map[string]string{
		"parameterized: constant SQL, tainted bind value": "    PreparedStatement st = connection.prepareStatement(\"SELECT * FROM U WHERE N=?\");\n    st.setString(1, param);\n    st.executeQuery();\n",
		"Spring bind parameter":                           "    Object o = jdbcTemplate.queryForMap(\"SELECT * FROM U WHERE id=?\", param);\n",
		"Spring bind parameter, inline source":            "    Object o = jdbcTemplate.queryForMap(SQL, request.getParameter(\"id\"));\n",
		"literal SQL, inline source as bind parameter":    "    Object o = jdbcTemplate.queryForMap(\"SELECT * FROM U WHERE id=?\", request.getParameter(\"id\"));\n",
		"numeric coercion":                                "    int id = Integer.parseInt(param);\n    PreparedStatement st = connection.prepareStatement(\"SELECT * FROM U WHERE id=\" + id);\n",
	} {
		if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+body+tail); slices.Contains(got, "TAINT-001") {
			t.Errorf("%s: reported (got %v)", name, got)
		}
	}
}
