package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestJavaScriptSinksInReturns: a sink written as a return value is a sink,
// and a returned value still flows through a helper.
func TestJavaScriptSinksInReturns(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"return res.send", "function h(req, res) {\n  const q = req.query.q;\n  return res.send('<p>' + q);\n}\n", []string{"TAINT-003"}},
		{"return chained status", "function h(req, res) {\n  return res.status(400).send('bad: ' + req.params.id);\n}\n", []string{"TAINT-003"}},
		{"return db.query", "function h(req) {\n  const u = req.body.u;\n  return db.query('SELECT * FROM t WHERE u = ' + u);\n}\n", []string{"TAINT-001"}},
		{"returned value through a helper", "function wrap(s) {\n  return '<b>' + s + '</b>';\n}\nfunction h(req, res) {\n  const n = wrap(req.query.n);\n  res.send(n);\n}\n", []string{"TAINT-003"}},
		{"return of a constant", "function h(req, res) {\n  return res.send('ok');\n}\n", nil},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
