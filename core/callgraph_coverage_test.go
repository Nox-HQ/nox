package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
)

// mixedModule writes a Go module that also contains a YAML file, so one scan
// holds findings in a language the call graph reads and one it cannot.
func mixedModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.21\n",
		"main.go": `package main

import "crypto/md5"

func weak() []byte {
	h := md5.New()
	return h.Sum(nil)
}

func main() { weak() }
`,
		"deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n" +
			"  replicas: 1\n  template:\n    spec:\n      containers:\n      - name: c\n" +
			"        image: nginx:latest\n        securityContext:\n          privileged: true\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

func stateOf(t *testing.T, res *ScanResult, f findings.Finding, c capability.AnalysisCapability) capability.State {
	t.Helper()
	return res.Coverage.State(SubjectForFinding(f), c)
}

// A language the call graph cannot read reports UNSUPPORTED, not NOT_EVALUATED.
//
// This is the half that keeps declaring call_graph at installation level
// honest. Provided() is a claim that an implementation exists; for a YAML
// finding nothing could have asked the question, and not_evaluated would read
// as a gap somebody could close by running something differently.
func TestCallGraphIsUnsupportedOutsideGo(t *testing.T) {
	dir := mixedModule(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var checkedYAML, checkedGo int
	for _, f := range res.Findings.Findings() {
		switch filepath.Ext(f.Location.FilePath) {
		case ".yaml":
			checkedYAML++
			for _, c := range []capability.AnalysisCapability{
				capability.CallGraph, capability.EntryPoint,
			} {
				if got := stateOf(t, res, f, c); got != capability.Unsupported {
					t.Errorf("%s on a YAML finding = %q, want unsupported. Nothing could have "+
						"asked this question there, and %q reads as a gap somebody could close.",
						c, got, got)
				}
			}
		case ".go":
			checkedGo++
			if got := stateOf(t, res, f, capability.CallGraph); got == capability.Unsupported {
				t.Errorf("call_graph on a Go finding = unsupported; the analysis exists for Go")
			}
		}
	}
	if checkedYAML == 0 {
		t.Fatal("the fixture produced no YAML finding; this test asserts nothing")
	}
	if checkedGo == 0 {
		t.Fatal("the fixture produced no Go finding; this test asserts nothing")
	}
}

// A Go finding reached from main carries the chain that reaches it.
func TestAGoFindingCarriesItsCallPath(t *testing.T) {
	dir := mixedModule(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var found bool
	for _, f := range res.Findings.Findings() {
		if filepath.Ext(f.Location.FilePath) != ".go" {
			continue
		}
		if path := f.Metadata["call_path"]; path != "" {
			found = true
			if f.Metadata["entry_kind"] != "concrete" {
				t.Errorf("entry_kind = %q for a path from main, want concrete",
					f.Metadata["entry_kind"])
			}
			if got := stateOf(t, res, f, capability.EntryPoint); got != capability.Positive {
				t.Errorf("entry_point = %q for a finding reached from main, want positive", got)
			}
		}
	}
	if !found {
		t.Error("no Go finding carries a call path; main calls weak(), which holds the finding")
	}
}

// Gate B at the scan. The call graph may never suppress a finding, in any
// language, however confident it looks — it cannot see interface dispatch, and
// "no path found" is not "no path exists".
func TestCallGraphNeverSuppressesAFinding(t *testing.T) {
	dir := mixedModule(t)
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		for _, c := range []capability.AnalysisCapability{
			capability.CallGraph, capability.EntryPoint,
		} {
			got := stateOf(t, res, f, c)
			if got.SuppressesFinding() {
				t.Errorf("%s reported %q for %s, which may suppress a finding. A syntactic "+
					"graph cannot see every call Go can make, so it must never reach a "+
					"state that hides one.", c, got, f.RuleID)
			}
		}
	}
}

// A Go project with no go.mod is unsupported rather than badly answered: the
// import paths cannot be resolved, so a graph would be mostly disconnected and
// its silence would mean nothing.
func TestGoWithoutAModuleIsUnsupported(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\nimport \"crypto/md5\"\n\nfunc main() { md5.New() }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var checked int
	for _, f := range res.Findings.Findings() {
		if filepath.Ext(f.Location.FilePath) != ".go" {
			continue
		}
		checked++
		if got := stateOf(t, res, f, capability.CallGraph); got != capability.Unsupported {
			t.Errorf("call_graph = %q with no go.mod, want unsupported", got)
		}
	}
	if checked == 0 {
		t.Skip("no Go finding in the fixture")
	}
}
