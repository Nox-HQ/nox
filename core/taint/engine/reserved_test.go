package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestVariablesNamedLikeOtherLanguagesKeywords: a name that is a keyword only
// in some other language is an ordinary variable.
func TestVariablesNamedLikeOtherLanguagesKeywords(t *testing.T) {
	for _, c := range []struct {
		name, file string
		lang       lexctx.Lang
		src        string
		want       []string
	}{
		{"python type", "a.py", lexctx.LangPython, "from flask import request\nimport os\ndef h():\n    type = request.args.get('t')\n    os.system('ls ' + type)\n", []string{"TAINT-002"}},
		{"python match", "a.py", lexctx.LangPython, "from flask import request\nimport os\ndef h():\n    match = request.args.get('m')\n    os.system('grep ' + match)\n", []string{"TAINT-002"}},
		{"python string", "a.py", lexctx.LangPython, "from flask import request\nimport os\ndef h():\n    string = request.form['s']\n    os.system(string)\n", []string{"TAINT-002"}},
		{"javascript set", "a.js", lexctx.LangJavaScript, "function h(req, res) {\n  const set = req.query.s;\n  res.send(set);\n}\n", []string{"TAINT-003"}},
		{"javascript object", "a.js", lexctx.LangJavaScript, "function h(req, res) {\n  const object = req.body.o;\n  db.query('SELECT ' + object);\n}\n", []string{"TAINT-001"}},
		{"java open", "A.java", lexctx.LangJava, "class A {\n  void h(HttpServletRequest request) throws Exception {\n    String open = request.getParameter(\"o\");\n    Runtime.getRuntime().exec(\"sh -c \" + open);\n  }\n}\n", []string{"TAINT-002"}},
		{"a real python keyword is still not a variable", "a.py", lexctx.LangPython, "from flask import request\nimport os\ndef h():\n    q = request.args.get('q')\n    os.system('ls')\n    return None\n", nil},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(c.file, c.lang, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
