package core

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// A query built from a parameter is low confidence: nothing in the file shows
// a caller passing request data. When the call graph finds that function on a
// path from an HTTP route handler, a request does arrive there, and the
// finding is raised to medium with the route as its basis. A function no
// route reaches keeps low. The fingerprint does not move.
func TestParameterSQLReachableFromARouteIsMedium(t *testing.T) {
	files := map[string]string{
		"package.json": `{"dependencies":{"express":"4.17.1","pg":"8.11.0"}}`,
		"server.js": "const express = require('express');\nconst { pool } = require('./db');\nconst app = express();\n\n" +
			"function findUser(name) {\n  return pool.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n}\n\n" +
			"function purgeUser(name) {\n  return pool.query(\"DELETE FROM users WHERE name = '\" + name + \"'\");\n}\n\n" +
			"app.get('/users', (req, res) => {\n  res.json(findUser(currentTenant()));\n});\n\napp.listen(3000);\n",
	}
	res, err := RunScanWithOptions(writeNPMProject(t, files), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byLine := map[int]findings.Finding{}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "TAINT-001" && f.Metadata["source_kind"] == "parameter" {
			byLine[f.Location.StartLine] = f
		}
	}
	reached, ok := byLine[6]
	if !ok {
		t.Fatalf("no parameter SQL finding at findUser (line 6); got %v", byLine)
	}
	if reached.Confidence != findings.ConfidenceMedium {
		t.Errorf("findUser: confidence %s, want medium (reached from GET /users)", reached.Confidence)
	}
	m := reached.Metadata
	if m["original_confidence"] != "low" || m["confidence_basis"] != "route_reachable" {
		t.Errorf("findUser: the raise is not recorded: %v", m)
	}
	if !strings.Contains(reached.Message, "HTTP route") || !strings.Contains(reached.Message, "/users") {
		t.Errorf("findUser: message does not name the route: %s", reached.Message)
	}

	unreached, ok := byLine[10]
	if !ok {
		t.Fatalf("no parameter SQL finding at purgeUser (line 10); got %v", byLine)
	}
	if unreached.Confidence != findings.ConfidenceLow {
		t.Errorf("purgeUser: confidence %s, want low (no route reaches it)", unreached.Confidence)
	}
	if _, raised := unreached.Metadata["confidence_basis"]; raised {
		t.Errorf("purgeUser: carries a raise it did not get: %v", unreached.Metadata)
	}
	// Same analyzer wording, same kind of finding: the raise is metadata and
	// a sentence, not a new identity. The two fingerprints differ by line
	// only because the findings do.
	if reached.Fingerprint == "" || reached.Fingerprint == unreached.Fingerprint {
		t.Errorf("fingerprints %q and %q", reached.Fingerprint, unreached.Fingerprint)
	}
}

// The raise moves confidence and the message, never the fingerprint, and it
// applies once: a finding already raised, one not low, one whose source is
// not a parameter, and one reached only from a test or main are left alone.
func TestRaiseRouteReachableParameterFlows(t *testing.T) {
	mk := func(conf findings.Confidence, meta map[string]string) findings.Finding {
		f := findings.NewFinding("TAINT-001", findings.SeverityHigh, conf, findings.Location{FilePath: "dao.js", StartLine: 3}, "msg.")
		f.Metadata = meta
		return f
	}
	route := func(extra ...string) map[string]string {
		m := map[string]string{"source_kind": "parameter", "entry_kind": "route", "entry_reason": "handles GET /u (Express or Fastify)"}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
		return m
	}
	fs := findings.NewFindingSet()
	fs.Add(mk(findings.ConfidenceLow, route()))
	fs.Add(mk(findings.ConfidenceLow, route("entry_kind", "test")))
	fs.Add(mk(findings.ConfidenceLow, route("entry_kind", "concrete")))
	fs.Add(mk(findings.ConfidenceLow, route("source_kind", "http_query")))
	fs.Add(mk(findings.ConfidenceHigh, route()))
	before := fs.Findings()
	fps := make([]string, len(before))
	for i, f := range before {
		fps[i] = f.Fingerprint
	}
	raiseRouteReachableParameterFlows(fs)
	raiseRouteReachableParameterFlows(fs) // idempotent
	got := fs.Findings()
	want := []findings.Confidence{findings.ConfidenceMedium, findings.ConfidenceLow, findings.ConfidenceLow, findings.ConfidenceLow, findings.ConfidenceHigh}
	for i, f := range got {
		if f.Confidence != want[i] {
			t.Errorf("finding %d: confidence %s, want %s (%v)", i, f.Confidence, want[i], f.Metadata)
		}
		if f.Fingerprint != fps[i] {
			t.Errorf("finding %d: fingerprint moved", i)
		}
	}
	if n := strings.Count(got[0].Message, "HTTP route"); n != 1 {
		t.Errorf("message names the route %d times: %s", n, got[0].Message)
	}
	if got[1].Message != "msg." {
		t.Errorf("an unraised finding's message changed: %s", got[1].Message)
	}
}
