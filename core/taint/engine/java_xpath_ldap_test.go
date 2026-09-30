package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestJavaXPathAndLDAPSinks(t *testing.T) {
	head := "class A {\n  void doPost(HttpServletRequest request) throws Exception {\n    String bar = request.getParameter(\"q\");\n"
	tail := "  }\n}\n"
	cases := []struct {
		name, body, rule string
		want             bool
	}{
		{"XPath.evaluate", "    javax.xml.xpath.XPath xp = xpf.newXPath();\n    String expression = \"/Employees/Employee[@emplid='\" + bar + \"']\";\n    String result = xp.evaluate(expression, xmlDocument);\n", "TAINT-008", true},
		{"XPath.compile chain", "    javax.xml.xpath.XPath xp = xpf.newXPath();\n    String expression = \"/E[@id='\" + bar + \"']\";\n    Object n = xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);\n", "TAINT-008", true},
		{"XPath with a constant expression, tainted document", "    javax.xml.xpath.XPath xp = xpf.newXPath();\n    String result = xp.evaluate(\"/E[@id='1']\", bar);\n", "TAINT-008", false},
		{"ESAPI encodeForXPath", "    javax.xml.xpath.XPath xp = xpf.newXPath();\n    String safe = ESAPI.encoder().encodeForXPath(bar);\n    String result = xp.evaluate(\"/E[@id='\" + safe + \"']\", doc);\n", "TAINT-008", false},
		{"an evaluate that is not XPath", "    ExpressionEngine engine = new ExpressionEngine();\n    Object v = engine.evaluate(bar, ctx);\n", "TAINT-008", false},
		{"DirContext.search", "    javax.naming.directory.DirContext ctx = ads.getDirContext();\n    String filter = \"(&(objectclass=person)(uid=\" + bar + \"))\";\n    ctx.search(\"ou=users\", filter, sc);\n", "TAINT-009", true},
		{"InitialDirContext.search", "    javax.naming.directory.InitialDirContext idc = (javax.naming.directory.InitialDirContext) ctx;\n    idc.search(\"ou=users\", \"(uid=\" + bar + \")\", sc);\n", "TAINT-009", true},
		{"ESAPI encodeForLDAP", "    DirContext ctx = ads.getDirContext();\n    String safe = ESAPI.encoder().encodeForLDAP(bar);\n    ctx.search(\"ou=users\", \"(uid=\" + safe + \")\", sc);\n", "TAINT-009", false},
		{"a search that is not LDAP", "    SearchIndex index = new SearchIndex();\n    index.search(bar);\n", "TAINT-009", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+c.body+tail), c.rule); got != c.want {
			t.Errorf("%s: %s reported=%v, want %v", c.name, c.rule, got, c.want)
		}
	}
}
