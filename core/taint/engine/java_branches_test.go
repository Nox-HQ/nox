package engine

import (
	"slices"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestJavaBranchModel(t *testing.T) {
	head := "class A {\n  void doPost(HttpServletRequest request) throws Exception {\n    String param = request.getParameter(\"q\");\n    String bar = \"safe\";\n"
	sink := "    Runtime.getRuntime().exec(bar);\n  }\n}\n"
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"brace-less if, constant true: else arm is dead", "    int num = 86;\n    if ((7 * 42) - num > 200) bar = \"x\";\n    else bar = param;\n", false},
		{"brace-less if, constant false: else arm runs", "    int num = 106;\n    if ((7 * 42) - num > 200) bar = \"x\";\n    else bar = param;\n", true},
		{"braced if, constant false: body is dead", "    int num = 106;\n    if ((7 * 42) - num > 200) {\n      bar = param;\n    }\n", false},
		{"braced if/else, constant true: else dead", "    int num = 86;\n    if ((7 * 42) - num > 200) {\n      bar = \"x\";\n    } else {\n      bar = param;\n    }\n", false},
		{"unknown condition keeps the tainted arm", "    if (param.length() > 3) {\n      bar = param;\n    }\n", true},
		{"a weak update keeps earlier taint", "    bar = param;\n    if (param.isEmpty()) {\n      bar = \"x\";\n    }\n", true},
		{"ternary, constant true picks the safe side", "    int num = 86;\n    bar = (7 * 42) - num > 200 ? \"x\" : param;\n", false},
		{"ternary, constant false picks param", "    int num = 106;\n    bar = (7 * 42) - num > 200 ? \"x\" : param;\n", true},
		{"switch on a constant: the matching case is the only one", "    String guess = \"ABC\";\n    char target = guess.charAt(1);\n    switch (target) {\n      case 'A':\n        bar = param;\n        break;\n      case 'B':\n        bar = \"bob\";\n        break;\n      case 'C':\n      case 'D':\n        bar = param;\n        break;\n      default:\n        bar = param;\n        break;\n    }\n", false},
		{"switch on a constant: stacked labels", "    String guess = \"ABC\";\n    char target = guess.charAt(2);\n    switch (target) {\n      case 'A':\n        bar = \"a\";\n        break;\n      case 'C':\n      case 'D':\n        bar = param;\n        break;\n      default:\n        bar = \"z\";\n        break;\n    }\n", true},
		{"switch fall-through from the taken case", "    String guess = \"ABC\";\n    char target = guess.charAt(0);\n    switch (target) {\n      case 'A':\n        bar = \"a\";\n      case 'B':\n        bar = param;\n        break;\n      default:\n        break;\n    }\n", true},
		{"string contains, constant", "    String t = \"This should never happen\";\n    if (t.contains(\"should\")) bar = param;\n", true},
		{"a reassigned local is not constant", "    int num = 106;\n    num = 50;\n    if ((7 * 42) - num > 200) bar = param;\n", true},
		{"a loop variable is not constant", "    for (int i = 0; i < 3; i++) {\n      if (i == 2) bar = param;\n    }\n", true},
	}
	for _, c := range cases {
		got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+c.body+sink), "TAINT-002")
		if got != c.want {
			t.Errorf("%s: reported=%v, want %v", c.name, got, c.want)
		}
	}
}

// A sink inside a brace-less branch is a statement, not scaffolding.
func TestJavaBraceLessBranchStatementIsKept(t *testing.T) {
	src := "class A {\n  void f(HttpServletRequest request) throws Exception {\n    String p = request.getParameter(\"q\");\n" +
		"    if (p != null) Runtime.getRuntime().exec(p);\n  }\n}\n"
	if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, src); !slices.Contains(got, "TAINT-002") {
		t.Errorf("the sink in a brace-less if was dropped: %v", got)
	}
}

// Jenkins' FormFieldValidator.error escapes through hudson.Util.escape; a
// brace-less `if (x) error(msg);` became visible with the branch model and
// must not read as XSS.
func TestJavaHTMLEscapersSanitize(t *testing.T) {
	for _, esc := range []string{"Util.escape", "HtmlUtils.htmlEscape"} {
		src := "class A {\n  void f(HttpServletRequest request, HttpServletResponse response) throws Exception {\n" +
			"    String q = request.getParameter(\"q\");\n    response.getWriter().println(" + esc + "(q));\n  }\n}\n"
		if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, src); slices.Contains(got, "TAINT-003") {
			t.Errorf("%s did not sanitize XSS: %v", esc, got)
		}
	}
}

// A value escaped on its way into a local helper is not reported by the
// helper's own sink (Jenkins FormFieldValidator: error(msg) escapes and then
// writes). The unescaped call through the same helper still is.
func TestHelperArgumentWrappedInSanitizer(t *testing.T) {
	tmpl := "class A {\n  void check(HttpServletRequest request) throws Exception {\n    String msg = request.getParameter(\"q\");\n    error(msg);\n  }\n" +
		"  public void error(String message) throws Exception {\n    errorWithMarkup(%s);\n  }\n" +
		"  public void errorWithMarkup(String html) throws Exception {\n    response.getWriter().print(html);\n  }\n}\n"
	escaped := strings.Replace(tmpl, "%s", "Util.escape(message)", 1)
	if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, escaped); slices.Contains(got, "TAINT-003") {
		t.Errorf("escaped argument reported: %v", got)
	}
	raw := strings.Replace(tmpl, "%s", "message", 1)
	if got := analyzeRuleIDs(t, "A.java", lexctx.LangJava, raw); !slices.Contains(got, "TAINT-003") {
		t.Errorf("unescaped argument through the helper not reported: %v", got)
	}
}
