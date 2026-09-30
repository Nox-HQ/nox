package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestInlineHandlerBodies: a function body passed as an argument is split into
// statements, while an object literal argument stays part of its call.
func TestInlineHandlerBodies(t *testing.T) {
	for _, c := range []struct {
		name, file, src string
		want            []string
	}{
		{"express arrow handler", "a.js", "app.get('/', (req, res) => {\n  const q = req.query.x;\n  res.send(q);\n});\n", []string{"TAINT-003"}},
		{"express function handler", "a.js", "app.get('/', function (req, res) {\n  const q = req.query.x;\n  res.send(q);\n});\n", []string{"TAINT-003"}},
		{"async router handler", "a.js", "router.post('/x', async (req, res) => {\n  const q = req.body.name;\n  await db.query('SELECT ' + q);\n});\n", []string{"TAINT-001"}},
		{"object literal argument keeps its call", "a.js", "function h(req, res) {\n  const q = req.query.x;\n  res.send({\n    name: q,\n  });\n}\n", []string{"TAINT-003"}},
		{"innerHTML store", "a.js", "function h(req) {\n  const q = req.query.x;\n  document.getElementById('o').innerHTML = '<b>' + q;\n}\n", []string{"TAINT-003"}},
		{"textContent store is not a sink", "a.js", "function h(req) {\n  const q = req.query.x;\n  el.textContent = q;\n}\n", nil},
		{"java lambda body", "A.java", "class A {\n  void h(HttpServletRequest request) {\n    exec.submit(() -> {\n      String p = request.getParameter(\"p\");\n      Runtime.getRuntime().exec(\"sh -c \" + p);\n    });\n  }\n}\n", []string{"TAINT-002"}},
		{"compound assignment builds the query", "a.js", "function h(req) {\n  let sql = 'SELECT * FROM t WHERE ';\n  sql += 'id = ' + req.query.id;\n  db.query(sql);\n}\n", []string{"TAINT-001"}},
	} {
		lang := lexctx.LangJavaScript
		if strings.HasSuffix(c.file, ".java") {
			lang = lexctx.LangJava
		}
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(c.file, lang, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestInlineBodyElseArms: `} else {`, `try {` and `else{` inside a callback
// open blocks, so each arm's statements stay on their own lines.
func TestInlineBodyElseArms(t *testing.T) {
	src := "app.get('/', function (req, res) {\n  if (req.query.a) {\n    res.send('ok');\n  } else {\n    res.send('FOO: ' + req.params.id);\n  }\n  try {\n    res.send('x');\n  } finally{\n    res.send('y');\n  }\n});\n"
	flows := NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(src)))
	if len(flows) != 1 || flows[0].SinkLine != 5 {
		t.Fatalf("want one flow at line 5, got %+v", flows)
	}
}
