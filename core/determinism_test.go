package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/report"
)

// TestScanDeterminism is the run-to-run identity proof: the same tree scanned
// twice must produce byte-identical output. This exercises the whole pipeline —
// parallel analyzers (whose goroutine completion order varies), dedup,
// fingerprinting, and the deterministic sort — and, with SOURCE_DATE_EPOCH
// frozen, the report metadata too. A regression here means nox stopped being
// reproducible, which breaks CI caching, baseline diffs, and the offline moat.
func TestScanDeterminism(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

	dir := t.TempDir()
	writeFixtureTree(t, dir, map[string]string{
		// Multiple analyzers, several findings each, so ordering matters.
		"Dockerfile":       "FROM ubuntu:latest\nRUN echo hi\n",
		"requirements.txt": "flask\nrequests\n",
		"app.py": `import os
import flask
import quantum_flux_helper
prompt = f"Answer this: {user_input}"
model = "gpt-4"
`,
		"infra/main.tf": `resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
`,
	})

	gen := func() []byte {
		res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		b, err := report.NewJSONReporter("test").Generate(res.Findings)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		return b
	}

	first := gen()
	// A meaningful test needs the fixture to actually produce findings; an empty
	// scan is trivially "deterministic".
	if res, _ := RunScanWithOptions(dir, ScanOptions{Offline: true}); len(res.Findings.Findings()) == 0 {
		t.Fatal("fixture produced no findings; determinism test would be vacuous")
	}
	for i := 0; i < 3; i++ {
		if again := gen(); !bytes.Equal(first, again) {
			t.Fatalf("scan output not byte-identical on run %d\n--- first ---\n%s\n--- again ---\n%s", i+2, first, again)
		}
	}
}

func writeFixtureTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
