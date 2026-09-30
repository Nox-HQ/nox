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
