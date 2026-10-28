package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

// scanApp writes files into a fresh directory, scans it and writes the scan
// outputs `nox model` reads beside the source, as `nox scan --format json` does.
func scanApp(t *testing.T, files map[string]string) string {
	t.Helper()
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, DisableOSV: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.JSONReporter("test").WriteToFile(res.Findings, filepath.Join(dir, "findings.json")); err != nil {
		t.Fatal(err)
	}
	if res.AIInventory != nil {
		raw, err := res.AIInventory.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ai.inventory.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const (
	modelServerJS = "const express = require('express');\nconst app = express();\n" +
		"app.post('/login', login);\napp.use('/api/invoices', require('./routes/invoices'));\napp.listen(3000);\n"
	modelInvoicesJS = "const express = require('express');\nconst db = require('../db');\n" +
		"const { requireAuth } = require('../auth');\nconst router = express.Router();\n\n" +
		"router.get('/:id', requireAuth, async (req, res) => {\n" +
		"  const { rows } = await db.query(\"SELECT * FROM invoices WHERE id = $1\", [req.params.id]);\n" +
		"  res.json(rows[0]);\n});\n\nmodule.exports = router;\n"
	modelMCP = `{"mcpServers":{"shell":{"command":"npx","args":["-y","mcp-server-shell"]}}}`
)

func TestModelWritesReviewerAndToolingArtifacts(t *testing.T) {
	dir := scanApp(t, map[string]string{"src/server.js": modelServerJS, "src/routes/invoices.js": modelInvoicesJS, ".mcp.json": modelMCP})
	out := filepath.Join(dir, "tm")
	if code := runModel([]string{dir, "--out", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	md, err := os.ReadFile(filepath.Join(out, "model.md"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile(filepath.Join(out, "model.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"POST /login", "GET /api/invoices/:id", "MCP server shell", "```mermaid", "What nox cannot see", "Questions for the team"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("model.md lacks %q", want)
		}
	}
	// The JSON carries the nox report marker so a later scan of this directory
	// recognises it as nox's own output and does not read it back as source.
	if !strings.Contains(string(js), `"tool_name": "nox"`) || !strings.Contains(string(js), `"report": "threat-model"`) {
		t.Error("model.json lacks the nox report marker")
	}
}

func TestModelNeedsExistingScanOutput(t *testing.T) {
	dir := t.TempDir()
	if code := runModel([]string{dir, "--out", filepath.Join(dir, "o")}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "o")); err == nil {
		t.Error("an output directory was created for a failed run")
	}
}

func TestModelIsReproducible(t *testing.T) {
	dir := scanApp(t, map[string]string{"src/server.js": modelServerJS, "src/routes/invoices.js": modelInvoicesJS, ".mcp.json": modelMCP})
	read := func(out string) (string, string) {
		if code := runModel([]string{dir, "--out", out}); code != 0 {
			t.Fatalf("exit %d", code)
		}
		j, _ := os.ReadFile(filepath.Join(out, "model.json"))
		m, _ := os.ReadFile(filepath.Join(out, "model.md"))
		return string(j), string(m)
	}
	j1, m1 := read(filepath.Join(dir, "a"))
	j2, m2 := read(filepath.Join(dir, "b"))
	if j1 != j2 || m1 != m2 {
		t.Error("the same scan outputs produced different models")
	}
}

func TestModelPreviousReportsWhatChanged(t *testing.T) {
	old := scanApp(t, map[string]string{"src/server.js": modelServerJS, "src/routes/invoices.js": modelInvoicesJS})
	oldOut := filepath.Join(old, "tm")
	if code := runModel([]string{old, "--out", oldOut}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	cur := scanApp(t, map[string]string{"src/server.js": modelServerJS, "src/routes/invoices.js": modelInvoicesJS, ".mcp.json": modelMCP})
	out := filepath.Join(cur, "tm")
	if code := runModel([]string{cur, "--out", out, "--previous", filepath.Join(oldOut, "model.json")}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	md, err := os.ReadFile(filepath.Join(out, "model.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Changes since the previous model", "new MCP server: MCP server shell", "new trust boundary: model output → MCP server tool"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("model.md lacks %q", want)
		}
	}
	if code := runModel([]string{cur, "--previous", filepath.Join(cur, "findings.json"), "--no-write"}); code != 2 {
		t.Errorf("a findings.json is not a previous model; exit %d, want 2", code)
	}
}
