package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// Analysis limitations describe code an analysis could not follow, detected by
// source constructs such as `ctypes` or `importlib`. On a lockfile those words
// are package names: labelling a VULN finding on uv.lock "ffi" claims a
// limitation no analysis had, and reading 580 MB of lockfiles to do it cost
// llama_index 49 s of CPU online. Only files with a source language are read.
func TestAnalysisLimitationsAreForSourceFilesOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("uv.lock", "[[package]]\nname = \"ctypes-callable\"\n[[package]]\nname = \"importlib-metadata\"\n")
	write("app.py", "import ctypes\nlib = ctypes.CDLL('x')\n")

	fs := findings.NewFindingSet()
	fs.Add(findings.Finding{RuleID: "VULN-001", Fingerprint: "a", Location: findings.Location{FilePath: "uv.lock", StartLine: 2}})
	fs.Add(findings.Finding{RuleID: "TAINT-001", Fingerprint: "b", Location: findings.Location{FilePath: "app.py", StartLine: 2}})
	recordAnalysisLimitations(fs, dir, nil)

	for _, f := range fs.Findings() {
		got := f.Metadata["analysis_limitations"]
		switch f.Location.FilePath {
		case "uv.lock":
			if got != "" {
				t.Errorf("a lockfile finding was labelled %q", got)
			}
		case "app.py":
			if got != "ffi" {
				t.Errorf("the Python file calling ctypes was labelled %q, want ffi", got)
			}
		}
	}
}
