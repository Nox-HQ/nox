package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestJavaScriptServersAndDrivers covers the Node request objects and SQL
// driver handles the catalog did not know.
func TestJavaScriptServersAndDrivers(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"raw http server url", "const cp = require('child_process');\nconst url = require('url');\nhttp.createServer(function (req, res) {\n  const cmd = url.parse(req.url, true).query.path;\n  cp.execSync(cmd);\n});\n", []string{"TAINT-002"}},
		{"pg client by constructor", "const { Client } = require('pg');\nconst client = new Client();\napp.get('/u', async (req, res) => {\n  await client.query('SELECT * FROM u WHERE id = ' + req.query.id);\n});\n", []string{"TAINT-001"}},
		{"mysql2 connection", "const mysql = require('mysql2/promise');\nasync function h(req) {\n  const conn = await mysql.createConnection(cfg);\n  await conn.execute('SELECT * FROM u WHERE n = \"' + req.body.n + '\"');\n}\n", []string{"TAINT-001"}},
		{"sqlite3 database", "const sqlite3 = require('sqlite3');\nconst store = new sqlite3.Database(':memory:');\nfunction h(req) {\n  store.all('SELECT * FROM u WHERE n = ' + req.query.n);\n}\n", []string{"TAINT-001"}},
		{"a graphql client's query is not SQL", "const client = new ApolloClient({});\nfunction h(req) {\n  client.query({ query: req.body.q });\n}\n", nil},
		{"koa query", "router.get('/', async (ctx) => {\n  const f = ctx.query.file;\n  fs.readFileSync(f);\n});\n", []string{"TAINT-004"}},
		{"lambda event body", "const cp = require('child_process');\nexports.handler = async (event) => {\n  const q = JSON.parse(event.body).q;\n  cp.execSync('grep ' + q);\n};\n", []string{"TAINT-002"}},
		{"escaped output", "function h(req, res) {\n  res.send('Unknown user: ' + escape(req.params.id));\n}\n", nil},
		{"DOM redirect", "function go() {\n  const t = document.referrer;\n  location.href = t;\n}\n", []string{"TAINT-007"}},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJavaScriptInlineRequire(t *testing.T) {
	src := "function h(req) {\n  require('child_process').execSync('grep ' + req.query.q);\n  require(\"child_process\").exec(req.body.c);\n}\n"
	got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.js", lexctx.LangJavaScript, []byte(src))))
	if strings.Join(got, ",") != "TAINT-002,TAINT-002" {
		t.Errorf("got %v", got)
	}
}
