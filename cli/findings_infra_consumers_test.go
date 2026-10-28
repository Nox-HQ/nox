package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/compliance/iso27001"
	"github.com/nox-hq/nox/core/detail"
	"github.com/nox-hq/nox/core/report"
)

// findings.json now carries the deployment inventory under "infrastructure".
// Every consumer of the artifact must read a document with that key exactly as
// it read one without it: context stored beside the findings must not turn into
// an error, a finding or a changed verdict anywhere.
func TestFindingsJSONWithInfrastructureIsToleratedByEveryConsumer(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	dir := t.TempDir()
	files := map[string]string{
		"deploy/tf/main.tf": "resource \"aws_s3_bucket\" \"uploads\" {\n  bucket = \"uploads\"\n}\n" +
			"resource \"aws_s3_bucket_public_access_block\" \"uploads\" {\n  bucket = aws_s3_bucket.uploads.id\n" +
			"  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n",
		"src/app.js": "console.log('hello');\n",
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
	if !strings.Contains(string(raw), `"infrastructure"`) {
		t.Fatal("premise: the scan should have recorded its infrastructure inventory")
	}

	rep, err := report.LoadFindingsFileReport(path)
	if err != nil {
		t.Fatalf("the shared loader rejects a findings.json with an inventory: %v", err)
	}
	if rep.Infrastructure == nil || len(rep.Infrastructure.Resources) == 0 {
		t.Fatalf("premise: the inventory did not survive the round trip: %+v", rep.Infrastructure)
	}
	if got := rep.Infrastructure.Resources[0].Properties["public_access_block"]; got != "all true" {
		t.Errorf("the hardened bucket's block was not recorded: %q", got)
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
			t.Errorf("%s exited 2 (an error) on a findings.json with an inventory", name)
		}
	}
	notAnError("vex init", runVexInit([]string{"--input", path, "--output", filepath.Join(out, "vex.json")}))
	notAnError("badge", runBadge([]string{"--input", path, "--output", filepath.Join(out, "b.svg")}))
	notAnError("advisories", runAdvisories([]string{"--input", path, "--root", dir}))
	notAnError("ci-gate", runCIGate([]string{"--input", path, "--baseline", filepath.Join(out, "none.json")}))
	notAnError("fix plan", runFixSub("plan", []string{"--input", path, "--root", dir}))
	notAnError("scan --previous", runScan([]string{dir, "--offline", "--previous", path}, "json", t.TempDir(), "", true, false))
}
