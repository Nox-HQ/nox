package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The taint engine's refutations name what the engine could not see.
//
// A sanitizer refutation is a universal claim about this value at this sink,
// and it is only as good as the analysis behind it — syntactic, per-file. A
// value that arrives through an interface, a function value or reflection is a
// value the engine did not follow, and the sanitizer it saw may not be the one
// that ran. Naming that is what lets a reader decide whether it matters to
// their code.
func TestTaintRefutationsCarryTheirScope(t *testing.T) {
	dir := t.TempDir()
	src := `import subprocess, shlex
from flask import request

def run():
    cmd = shlex.quote(request.args.get("c"))
    subprocess.call(cmd, shell=True)
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var checked int
	for _, s := range res.Reasoning.Subjects() {
		for _, c := range res.Reasoning.About(s).Claims {
			if !c.Refutes() || c.Provenance.Tool != "taint" {
				continue
			}
			checked++
			if c.Attributes["scope"] == "" {
				t.Errorf("a taint refutation names no analysis: %q", c.Statement)
			}
			if !strings.Contains(c.Attributes["limits"], "interface dispatch") {
				t.Errorf("a taint refutation does not name its blind spot: %q",
					c.Attributes["limits"])
			}
		}
	}
	if checked == 0 {
		t.Fatal("the sanitized flow produced no taint refutation; this test asserts nothing")
	}
}
