package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The routes AUTHZ-001 holds are leads by default, not findings, and a lead
// must leave no trace among the findings of a machine output: not in the
// findings array, not in SARIF (results or rule catalogue), not in the exit
// code or a fingerprint. So the same app with and without an unscoped lookup
// renders byte-identical reports in default mode, except that findings.json
// records the lead under its own "leads" key (so core/change can tell a later
// run that a route is new), and ScanResult.Leads tells them apart.
// Enabled, the rule reports the finding exactly as before and holds no lead
// for it.
func TestAuthzLeadsLeaveNoTraceInMachineOutputs(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

	const unscoped = `db.query("SELECT * FROM invoices WHERE id = $1", [req.params.id])`
	const scoped = `db.query("SELECT * FROM invoices WHERE id = $1 AND owner_id = $2", [req.params.id, req.user.sub])`
	app := func(t *testing.T, lookup, config string) string {
		t.Helper()
		dir := t.TempDir()
		files := map[string]string{
			"src/server.js": "const express = require('express');\nconst app = express();\n" +
				"app.use('/api/invoices', require('./routes/invoices'));\n" +
				"app.get('/run', (req, res) => { require('child_process').exec(req.query.cmd); res.end(); });\n" +
				"app.listen(3000);\n",
			"src/routes/invoices.js": "const express = require('express');\nconst db = require('../db');\n" +
				"const { requireAuth } = require('../auth');\nconst router = express.Router();\n\n" +
				"router.get('/:id', requireAuth, async (req, res) => {\n" +
				"  const { rows } = await " + lookup + ";\n" +
				"  res.json(rows[0]);\n});\n\nmodule.exports = router;\n",
		}
		if config != "" {
			files[".nox.yaml"] = config
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
		return dir
	}
	scan := func(t *testing.T, dir string) (*ScanResult, map[string][]byte) {
		t.Helper()
		result, err := RunScanWithOptions(dir, ScanOptions{Offline: true, DisableOSV: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		out := map[string][]byte{}
		b, err := result.JSONReporter("test").Generate(result.Findings)
		if err != nil {
			t.Fatal(err)
		}
		out["findings.json"] = b
		sr := result.SARIFReporter("test")
		sr.Rules = result.Rules
		if b, err = sr.Generate(result.Findings); err != nil {
			t.Fatal(err)
		}
		out["results.sarif"] = b
		return result, out
	}

	withLead, leadOut := scan(t, app(t, unscoped, ""))
	without, cleanOut := scan(t, app(t, scoped, ""))
	if len(withLead.Leads) != 1 || withLead.Leads[0].Route != "GET /api/invoices/:id" ||
		withLead.Leads[0].FilePath != "src/routes/invoices.js" || withLead.Leads[0].Line != 7 {
		t.Fatalf("leads = %+v, want GET /api/invoices/:id at src/routes/invoices.js:7", withLead.Leads)
	}
	if len(without.Leads) != 0 {
		t.Fatalf("the scoped lookup is a lead: %+v", without.Leads)
	}
	if len(withLead.LeadChecks) != 1 || withLead.LeadChecks[0] != "authorization and authentication (Express, Fastify, Flask, FastAPI routes; leads only) and webhook signatures (Stripe, GitHub and Slack receivers in those routes)" {
		t.Errorf("lead checks = %v", withLead.LeadChecks)
	}
	// findings.json carries the lead, but only under its own keys, so that a
	// later run can say a route is new. Everything a finding consumer reads is
	// identical: with those two keys removed the documents are byte-equal.
	if !bytes.Contains(leadOut["findings.json"], []byte(`"leads"`)) {
		t.Error("findings.json does not record the lead, so a later run cannot compare against it")
	}
	if bytes.Contains(cleanOut["findings.json"], []byte(`"leads"`)) {
		t.Error("findings.json lists leads for an app that has none")
	}
	for name, b := range leadOut {
		got, want := b, cleanOut[name]
		if name == "findings.json" {
			got, want = withoutLeadKeys(t, got), withoutLeadKeys(t, want)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs between the app with a lead and without one", name)
		}
		if bytes.Contains(got, []byte("AUTHZ")) {
			t.Errorf("%s mentions AUTHZ in default mode", name)
		}
	}
	if len(withLead.Findings.Findings()) == 0 {
		t.Fatal("the app no longer produces any finding; the comparison would prove nothing")
	}

	enabled, enabledOut := scan(t, app(t, unscoped, "scan:\n  rules:\n    enable: [AUTHZ-001]\n"))
	if len(enabled.Leads) != 0 {
		t.Errorf("an enabled rule also held a lead: %+v", enabled.Leads)
	}
	n := 0
	for _, f := range enabled.Findings.Findings() {
		if f.RuleID == "AUTHZ-001" {
			n++
		}
	}
	if n != 1 || !bytes.Contains(enabledOut["results.sarif"], []byte(`"AUTHZ-001"`)) {
		t.Errorf("enabled: %d AUTHZ-001 findings, want 1, reported in SARIF", n)
	}
}

// withoutLeadKeys re-encodes a findings document without the keys that carry
// leads.
func withoutLeadKeys(t *testing.T, doc []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatalf("the document is not a JSON object: %v", err)
	}
	delete(m, "leads")
	delete(m, "lead_checks")
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}
