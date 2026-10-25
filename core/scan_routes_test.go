package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/report"
)

// The routes the authorization reader found are recorded in findings.json as
// context for a system model. They are not findings: they must not change the
// findings, the SARIF output or the exit code, and a scan with no Express
// routes must record none.
func TestScanRecordsRoutesBesideTheFindingsAndNowhereElse(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	dir := t.TempDir()
	files := map[string]string{
		"src/server.js": "const express = require('express');\nconst app = express();\n" +
			"app.post('/login', login);\napp.use('/api', require('./items'));\napp.listen(3000);\n",
		"src/items.js": "const express = require('express');\nconst router = express.Router();\n" +
			"router.use(requireAuth);\nrouter.get('/items', list);\nmodule.exports = router;\n",
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, DisableOSV: true})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := res.JSONReporter("test").WriteToFile(res.Findings, path); err != nil {
		t.Fatal(err)
	}
	rep, err := report.LoadFindingsFileReport(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]report.Route{}
	for _, r := range rep.Routes {
		got[r.Method+" "+r.Path] = r
	}
	if len(got) != 2 {
		t.Fatalf("routes = %+v, want POST /login and GET /api/items", rep.Routes)
	}
	if got["POST /login"].Authn != "" || got["GET /api/items"].Authn != "requireAuth" {
		t.Errorf("middleware not recorded as the source shows it: %+v", got)
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Message, "/login") && strings.HasPrefix(f.RuleID, "AUTHZ") {
			t.Errorf("a route became a finding: %+v", f)
		}
	}
	sarif, err := res.SARIFReporter("test").Generate(res.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sarif), "/api/items") {
		t.Error("routes leaked into SARIF")
	}

	// A project with no Express routes records none: the key is absent.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "main.go"), []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2, err := RunScanWithOptions(empty, ScanOptions{Offline: true, DisableOSV: true})
	if err != nil {
		t.Fatal(err)
	}
	if r2.ReportRoutes() != nil {
		t.Errorf("routes = %+v for a Go program", r2.ReportRoutes())
	}
}
