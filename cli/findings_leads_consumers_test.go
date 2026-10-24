package main

import (
	"os"
	"path/filepath"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/compliance/iso27001"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/report"
)

// findings.json now carries the scan's authorization leads under "leads" and
// "lead_checks". Every consumer of the artifact must read a document with those
// keys exactly as it read one without them: a hint stored beside the findings
// must not turn into an error, a finding or a changed verdict anywhere.
func TestFindingsJSONWithLeadsIsToleratedByEveryConsumer(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	dir := t.TempDir()
	files := map[string]string{
		"src/server.js": "const express = require('express');\nconst app = express();\n" +
			"app.use('/api/invoices', require('./routes/invoices'));\napp.listen(3000);\n",
		"src/routes/invoices.js": "const express = require('express');\nconst db = require('../db');\n" +
			"const { requireAuth } = require('../auth');\nconst router = express.Router();\n\n" +
			"router.get('/:id', requireAuth, async (req, res) => {\n" +
			"  const { rows } = await db.query(\"SELECT * FROM invoices WHERE id = $1\", [req.params.id]);\n" +
			"  res.json(rows[0]);\n});\n\nmodule.exports = router;\n",
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
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{Offline: true, DisableOSV: true})
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	path := filepath.Join(out, "findings.json")
	if err := res.JSONReporter("test").WriteToFile(res.Findings, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := report.LoadFindingsFileReport(path)
	if err != nil {
		t.Fatalf("the shared loader rejects a findings.json with leads: %v", err)
	}
	if len(rep.Leads) != 1 || len(rep.LeadChecks) != 1 {
		t.Fatalf("premise: the scan should have recorded one lead, got leads=%v checks=%v", rep.Leads, rep.LeadChecks)
	}
	for _, f := range rep.Findings {
		if f.RuleID == "AUTHZ-001" {
			t.Fatal("a lead leaked into the findings array")
		}
	}

	if _, err := detail.LoadFromFile(path); err != nil {
		t.Errorf("detail store: %v", err)
	}
	if _, _, err := iso27001.ParseFindings("findings.json", raw); err != nil {
		t.Errorf("compliance: %v", err)
	}

	notAnError := func(name string, code int) {
		t.Helper()
		if code == 2 {
			t.Errorf("%s exited 2 (an error) on a findings.json with leads", name)
		}
	}
	notAnError("vex init", runVexInit([]string{"--input", path, "--output", filepath.Join(out, "vex.json")}))
	notAnError("badge", runBadge([]string{"--input", path, "--output", filepath.Join(out, "b.svg")}))
	notAnError("advisories", runAdvisories([]string{"--input", path, "--root", dir}))
	notAnError("ci-gate", runCIGate([]string{"--input", path, "--baseline", filepath.Join(out, "none.json")}))
	notAnError("fix plan", runFixSub("plan", []string{"--input", path, "--root", dir}))
	notAnError("scan --previous", runScan([]string{dir, "--offline", "--previous", path}, "json", t.TempDir(), "", true, false))
}
