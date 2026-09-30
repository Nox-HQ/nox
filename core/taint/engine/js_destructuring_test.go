package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestJavaScriptDestructuringAndNextRoutes: destructured names carry the
// value's taint, and a Next.js route's params are request data.
func TestJavaScriptDestructuringAndNextRoutes(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"object destructuring", "function h(req, res) {\n  const { name } = req.body;\n  res.send(name);\n}\n", []string{"TAINT-003"}},
		{"renamed key and default", "function h(req) {\n  const { id: userId = 0, other } = req.query;\n  db.query('SELECT ' + userId);\n}\n", []string{"TAINT-001"}},
		{"array destructuring", "function h(req, res) {\n  const [first] = req.body.list;\n  res.send(first);\n}\n", []string{"TAINT-003"}},
		{"nested pattern", "function h(req, res) {\n  const { user: { email } } = req.body;\n  res.send(email);\n}\n", []string{"TAINT-003"}},
		{"destructuring a constant", "function h(req, res) {\n  const { a } = { a: 'x' };\n  res.send(a);\n}\n", nil},
		{"next.js route params", "export async function GET(request: Request, { params }: { params: Promise<{ file: string }> }) {\n  const { file } = await params;\n  const url = `https://api.example.com/v1/files/${file}`;\n  const r = await fetch(url);\n}\n", []string{"TAINT-006"}},
		{"next.js request body", "export async function POST(request: Request) {\n  const body = await request.json();\n  await db.query('SELECT ' + body.id);\n}\n", []string{"TAINT-001"}},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("route.ts", lexctx.LangJavaScript, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestJavaScriptCallWithCallback: the call a callback is passed to is still
// a sink.
func TestJavaScriptCallWithCallback(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"exec with a function callback", "const cp = require('child_process');\nfunction h(req) {\n  var c = cp.exec(req.query.cmd, {}, function (err) {\n    console.log(err);\n  });\n}\n", []string{"TAINT-002"}},
		{"exec with an arrow callback", "const cp = require('child_process');\nfunction h(req) {\n  cp.exec('ls ' + req.query.d, (err, out) => {\n    console.log(out);\n  });\n}\n", []string{"TAINT-002"}},
		{"readFile with an async arrow", "const fs = require('fs');\nfunction h(req) {\n  fs.readFile(req.query.p, async (e, d) => {\n    console.log(d);\n  });\n}\n", []string{"TAINT-004"}},
		{"a constant command with a callback", "const cp = require('child_process');\nfunction h(req) {\n  cp.exec('ls', (err, out) => {\n    console.log(req.query.x);\n  });\n}\n", nil},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCurrentLocationIsNotAnOpenRedirect: a URL built from the current page's
// own URL stays on its origin; its hash is attacker text.
func TestCurrentLocationIsNotAnOpenRedirect(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"rebuilt current URL", "function f(el) {\n  const url = new URL(window.location.href);\n  url.searchParams.set('sort', el.value);\n  window.location.replace(url.href);\n}\n", nil},
		{"hash as the target", "function f() {\n  const t = location.hash.slice(1);\n  location.href = t;\n}\n", []string{"TAINT-007"}},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDestructuringEvaluatesOnce: the value's calls run once however many
// names the pattern binds.
func TestDestructuringEvaluatesOnce(t *testing.T) {
	src := "const fs = require('fs');\nasync function f() {\n  const { text, usage, finishReason } = await generateText({\n    messages: [{ type: 'text', text: 'hi' }, { data: fs.readFileSync('./data/cat.png') }],\n  });\n}\n"
	if got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(src)))); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}
