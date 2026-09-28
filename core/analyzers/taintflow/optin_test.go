package taintflow

import (
	"context"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// An opt-in sink (TAINT-011, trust boundary) is silent until its rule is named
// in scan.rules.enable, and its rule says so in the catalogue.
func TestOptInSinkReportsOnlyWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", "from flask import request, session\n\ndef h():\n    u = request.form.get('u')\n    session['user'] = u\n")

	if ids := scan(t, art); slices.Contains(ids, "TAINT-011") {
		t.Fatalf("opt-in rule reported without being enabled: %v", ids)
	}

	a := NewAnalyzer()
	a.EnableOptIn([]string{"TAINT-011"})
	fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range fs.Findings() {
		ids = append(ids, f.RuleID)
	}
	if !slices.Contains(ids, "TAINT-011") {
		t.Fatalf("enabled opt-in rule not reported: %v", ids)
	}

	for _, r := range a.Rules().Rules() {
		if r.ID == "TAINT-011" && !r.OptIn {
			t.Error("TAINT-011 is not marked opt-in in the rule catalogue")
		}
	}
}
