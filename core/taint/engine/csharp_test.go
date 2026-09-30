package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func runCSharpCases(t *testing.T, cases []struct {
	name, body string
	want       []string
}) {
	t.Helper()
	for _, c := range cases {
		src := "class C {\n public void Bad(HttpRequest req, HttpResponse resp) {\n  string data = req.QueryString[\"id\"];\n" + c.body + " }\n}\n"
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("t.cs", lexctx.LangCSharp, []byte(src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCSharpWebHandlers covers the ASP.NET and ADO.NET idioms: request and
// response by declared type, a query built in a property, the using and
// foreach headers, branches, and XPath/LDAP by declared type.
func TestCSharpWebHandlers(t *testing.T) {
	runCSharpCases(t, []struct {
		name, body string
		want       []string
	}{
		{"CommandText then ExecuteNonQuery", "  SqlCommand cmd = new SqlCommand(null, conn);\n  cmd.CommandText = \"select \" + data;\n  cmd.ExecuteNonQuery();\n", []string{"TAINT-001"}},
		{"CommandText built with +=", "  SqlCommand cmd = new SqlCommand(null, conn);\n  cmd.CommandText += \"select \" + data;\n  cmd.ExecuteNonQuery();\n", []string{"TAINT-001"}},
		{"parameterized query", "  SqlCommand cmd = new SqlCommand(\"select * from u where n=@n\", conn);\n  cmd.Parameters.AddWithValue(\"@n\", data);\n  cmd.ExecuteNonQuery();\n", nil},
		{"response write", "  resp.Write(\"<p>\" + data + \"</p>\");\n", []string{"TAINT-003"}},
		{"encoded response write", "  resp.Write(HttpUtility.HtmlEncode(data));\n", nil},
		{"redirect", "  resp.Redirect(data);\n", []string{"TAINT-007"}},
		{"using header opens a path", "  using (StreamReader sr = new StreamReader(\"/up/\" + data))\n  {\n   sr.ReadLine();\n  }\n", []string{"TAINT-004"}},
		{"foreach over a tainted split", "  string q = \"\";\n  foreach (string part in data.Split(','))\n  {\n   q = q + part;\n  }\n  new SqlCommand(\"select \" + q, conn).ExecuteNonQuery();\n", []string{"TAINT-001"}},
		{"if arm may overwrite", "  if (data.Length > 3)\n  {\n   data = \"safe\";\n  }\n  resp.Write(data);\n", []string{"TAINT-003"}},
		{"constant condition takes the safe arm", "  if (5 == 5)\n  {\n   data = \"safe\";\n  }\n  resp.Write(data);\n", nil},
		{"XPath by declared type", "  XPathNavigator nav = doc.CreateNavigator();\n  string q = \"//u[name='\" + data + \"']\";\n  nav.Evaluate(q);\n", []string{"TAINT-008"}},
		{"another type's Evaluate", "  Calculator calc = new Calculator();\n  calc.Evaluate(data);\n", nil},
		{"LDAP filter property", "  DirectorySearcher search = new DirectorySearcher(de);\n  search.Filter = \"(uid=\" + data + \")\";\n  search.FindOne();\n", []string{"TAINT-009"}},
	})
}

func TestCSharpXPathEscaped(t *testing.T) {
	runCSharpCases(t, []struct {
		name, body string
		want       []string
	}{
		{"escaped into the XPath literal", "  string u = System.Security.SecurityElement.Escape(data);\n  XPathNavigator nav = doc.CreateNavigator();\n  nav.Evaluate(\"//u[name='\" + u + \"']\");\n", nil},
	})
}
