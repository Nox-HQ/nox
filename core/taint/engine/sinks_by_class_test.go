package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Sinks the development split's missed labels named that the catalog did not:
// each reached by a request value, beside the same call given a value the
// request does not control (a literal, or the request value only in a slot
// that is not the dangerous one).
func TestSinksFromTheDevSplitMisses(t *testing.T) {
	js := func(stmt string) string {
		return "const needle = require('needle');\nconst util = require('util');\nconst { exec } = require('child_process');\nconst execAsync = util.promisify(exec);\n" +
			"app.get('/f', async (req, reply) => {\n  const v = req.query.v;\n  " + stmt + ";\n});\n"
	}
	java := func(decl, stmt string) string {
		return "package a;\nimport java.io.*;\nimport java.nio.file.*;\npublic class C {\n  public void h(HttpServletRequest request) throws Exception {\n    String v = request.getParameter(\"v\");\n    " +
			decl + "\n    " + stmt + ";\n  }\n}\n"
	}
	py := func(stmt string) string {
		return "from flask import request\nfrom fastapi.responses import RedirectResponse, HTMLResponse\n\ndef h():\n    v = request.args.get('v')\n    " + stmt + "\n"
	}
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		src  string
		rule string
		want bool
	}{
		// JavaScript.
		{"needle.get URL", lexctx.LangJavaScript, js("needle.get(v, () => {})"), "TAINT-006", true},
		{"needle.post fixed URL, value in body", lexctx.LangJavaScript, js("needle.post('https://api.example.com/x', { q: v }, () => {})"), "TAINT-006", false},
		{"fastify reply.redirect", lexctx.LangJavaScript, js("return reply.redirect(v)"), "TAINT-007", true},
		{"fastify reply.redirect literal", lexctx.LangJavaScript, js("return reply.redirect('/home')"), "TAINT-007", false},
		{"NextResponse.redirect", lexctx.LangJavaScript, js("return NextResponse.redirect(v)"), "TAINT-007", true},
		{"promisified exec", lexctx.LangJavaScript, js("await execAsync('ls ' + v)"), "TAINT-002", true},
		{"promisified exec literal", lexctx.LangJavaScript, js("await execAsync('ls /tmp')"), "TAINT-002", false},
		{"angular bypassSecurityTrustHtml", lexctx.LangJavaScript, js("return this.sanitizer.bypassSecurityTrustHtml(v)"), "TAINT-003", true},

		// Java.
		{"Files.write path", lexctx.LangJava, java("", `Files.write(Paths.get(v), new byte[0])`), "TAINT-004", true},
		{"Files.write is not XSS", lexctx.LangJava, java("", `Files.write(Paths.get(v), new byte[0])`), "TAINT-003", false},
		{"Files.write fixed path, value as data", lexctx.LangJava, java("", `Files.write(Paths.get("/var/app/out.txt"), v.getBytes())`), "TAINT-004", false},
		{"new FileOutputStream", lexctx.LangJava, java("", `new FileOutputStream(v)`), "TAINT-004", true},
		{"new FileWriter", lexctx.LangJava, java("", `new FileWriter(v)`), "TAINT-004", true},
		{"ProcessBuilder.command", lexctx.LangJava, java(`ProcessBuilder pb = new ProcessBuilder();`, `pb.command("sh", "-c", v); pb.start()`), "TAINT-002", true},
		{"var ProcessBuilder.command", lexctx.LangJava, java(`var builder = new ProcessBuilder();`, `builder.command("sh", "-c", v)`), "TAINT-002", true},
		{"command on something else", lexctx.LangJava, java(`Cli cli = new Cli();`, `cli.command("sh", "-c", v)`), "TAINT-002", false},

		// Python.
		{"FastAPI RedirectResponse", lexctx.LangPython, py("return RedirectResponse(v)"), "TAINT-007", true},
		{"FastAPI RedirectResponse literal", lexctx.LangPython, py("return RedirectResponse('/home')"), "TAINT-007", false},
		{"FastAPI HTMLResponse", lexctx.LangPython, py("return HTMLResponse('<p>' + v + '</p>')"), "TAINT-003", true},
		{"BaseHTTPRequestHandler wfile.write", lexctx.LangPython, py("self.wfile.write(('<p>%s</p>' % v).encode())"), "TAINT-003", true},
	} {
		got := slices.Contains(analyzeRuleIDs(t, "t"+extFor(c.lang), c.lang, c.src), c.rule)
		if got != c.want {
			t.Errorf("%s: %s reported = %v, want %v", c.name, c.rule, got, c.want)
		}
	}
}
