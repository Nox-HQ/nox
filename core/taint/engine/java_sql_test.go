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

func TestJavaStandardPropertiesAreNotSources(t *testing.T) {
	head := "class A {\n  void f() throws Exception {\n"
	sink := "    Runtime.getRuntime().exec(\"ls \" + v);\n  }\n}\n"
	for key, want := range map[string]bool{
		"user.dir": false, "os.name": false, "java.io.tmpdir": false, "line.separator": false,
		"app.command": true, // a custom -D property is set by whoever launches the JVM
	} {
		src := head + "    String v = System.getProperty(\"" + key + "\");\n" + sink
		got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, src), "TAINT-002")
		if got != want {
			t.Errorf("System.getProperty(%q): reported=%v, want %v", key, got, want)
		}
	}
}

// A method whose `throws` clause and `{` sit on the next line is still a
// method: its statements belong to it, not to the module.
func TestJavaMultiLineMethodHeader(t *testing.T) {
	src := "class A {\n  public void doPost(HttpServletRequest request, HttpServletResponse response)\n" +
		"      throws ServletException, IOException {\n    String q = request.getParameter(\"q\");\n  }\n}\n"
	var names []string
	for _, u := range ExtractUnits("A.java", lexctx.LangJava, []byte(src)) {
		names = append(names, u.FuncName)
		if u.FuncName == "doPost" && (len(u.Params) != 2 || len(u.Stmts) == 0) {
			t.Errorf("doPost params=%v stmts=%d", u.Params, len(u.Stmts))
		}
	}
	if !slices.Contains(names, "doPost") {
		t.Fatalf("doPost not recognized as a method: units %q", names)
	}
}

// A value stored into a Java collection or builder keeps its taint, so a
// helper that routes a parameter through a map still returns it tainted.
func TestJavaContainerStoresCarryTaint(t *testing.T) {
	head := "class A {\n  void doPost(HttpServletRequest request) throws Exception {\n    String param = request.getParameter(\"q\");\n"
	sink := "    Runtime.getRuntime().exec(bar);\n  }\n}\n"
	for name, mid := range map[string]string{
		"map put/get":         "    java.util.Map<String, Object> m = new java.util.HashMap<>();\n    m.put(\"k\", param);\n    String bar = (String) m.get(\"k\");\n",
		"list add":            "    java.util.List<String> l = new java.util.ArrayList<>();\n    l.add(param);\n    String bar = l.get(0);\n",
		"StringBuilder chain": "    StringBuilder sb = new StringBuilder();\n    sb.append(\"ls \").append(param);\n    String bar = sb.toString();\n",
	} {
		if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+mid+sink); !slices.Contains(got, "TAINT-002") {
			t.Errorf("%s: taint lost in the store (got %v)", name, got)
		}
	}
	clean := head + "    java.util.List<String> l = new java.util.ArrayList<>();\n    l.add(\"constant\");\n    String bar = l.get(0);\n" + sink
	if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, clean); slices.Contains(got, "TAINT-002") {
		t.Errorf("a list of constants was reported: %v", got)
	}
	helper := "class A {\n  public void doPost(HttpServletRequest request) throws Exception {\n    String param = request.getParameter(\"q\");\n" +
		"    String bar = doSomething(request, param);\n    Runtime.getRuntime().exec(bar);\n  }\n" +
		"  private static String doSomething(HttpServletRequest request, String param) {\n" +
		"    java.util.Map<String, Object> m = new java.util.HashMap<>();\n    m.put(\"keyB\", param);\n    String bar = (String) m.get(\"keyB\");\n    return bar;\n  }\n}\n"
	if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, helper); !slices.Contains(got, "TAINT-002") {
		t.Errorf("taint through a helper's map was lost (got %v)", got)
	}
}
