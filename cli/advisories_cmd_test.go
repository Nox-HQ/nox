package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
	"gopkg.in/yaml.v3"
)

func advFinding(id, pkg, fixed string, sev findings.Severity) findings.Finding {
	return findings.Finding{
		RuleID:   "VULN-001",
		Severity: sev,
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 1},
		Metadata: map[string]string{
			"vuln_id": id, "package": pkg, "version": "1.0.0", "ecosystem": "npm",
			"fixed_in": fixed, "applicability": "undetermined", "applicability_reached": "affected_version",
			"applicability_stopped_at": "symbol_used", "applicability_because": "unsupported",
		},
	}
}

func writeReport(t *testing.T, path string, ff []findings.Finding, degr ...report.Degradation) {
	t.Helper()
	rep := report.JSONReport{Findings: ff}
	rep.Meta.Degradations = degr
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func advRoot(t *testing.T, nox string) string {
	t.Helper()
	root := t.TempDir()
	if nox != "" {
		if err := os.WriteFile(filepath.Join(root, ".nox.yaml"), []byte(nox), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The pull request holds the newly disclosed advisories and nothing else, so a
// week of known advisories never rides along on an unrelated fix.
func TestAdvisoriesPrepareFileHoldsOnlyTheNewOnes(t *testing.T) {
	root := advRoot(t, "advisories:\n  policy: prepare\n")
	old := advFinding("GHSA-old", "a", "1.0.1", findings.SeverityHigh)
	fresh := advFinding("GHSA-new", "b", "1.0.1", findings.SeverityHigh)
	cur, prev, out := filepath.Join(root, "now.json"), filepath.Join(root, "prev.json"), filepath.Join(root, "prepare.json")
	writeReport(t, cur, []findings.Finding{old, fresh})
	writeReport(t, prev, []findings.Finding{old})

	if rc := runAdvisories([]string{"--root", root, "--input", cur, "--previous", prev, "--prepare-findings", out, "--format", "json"}); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	rep, err := report.LoadFindingsFileReport(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Metadata["vuln_id"] != "GHSA-new" {
		t.Fatalf("prepare file should hold exactly GHSA-new: %+v", rep.Findings)
	}
}

// Default config, default policy: nothing is prepared.
func TestAdvisoriesDefaultPreparesNothing(t *testing.T) {
	root := advRoot(t, "")
	cur, prev, out := filepath.Join(root, "now.json"), filepath.Join(root, "prev.json"), filepath.Join(root, "prepare.json")
	writeReport(t, cur, []findings.Finding{advFinding("GHSA-new", "b", "1.0.1", findings.SeverityCritical)})
	writeReport(t, prev, nil)
	if rc := runAdvisories([]string{"--root", root, "--input", cur, "--previous", prev, "--prepare-findings", out}); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	rep, err := report.LoadFindingsFileReport(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("report policy must prepare nothing: %+v", rep.Findings)
	}
}

// A scan whose lookup failed exits non-zero. A quiet week and a blind week must
// not look alike to the job that runs this.
func TestAdvisoriesIncompleteScanFails(t *testing.T) {
	root := advRoot(t, "advisories:\n  policy: remediate\n")
	cur, prev := filepath.Join(root, "now.json"), filepath.Join(root, "prev.json")
	writeReport(t, cur, nil, report.Degradation{Kind: "osv_lookup", Detail: "OSV unreachable", Impact: "advisories may be missing"})
	writeReport(t, prev, nil)
	if rc := runAdvisories([]string{"--root", root, "--input", cur, "--previous", prev}); rc != 1 {
		t.Fatalf("exit %d, want 1", rc)
	}

	// An advisory-only degradation (a plugin the operator never asked for) is not
	// a blind scan.
	writeReport(t, cur, nil, report.Degradation{Kind: "plugin", Detail: "x", Advisory: true})
	if rc := runAdvisories([]string{"--root", root, "--input", cur, "--previous", prev}); rc != 0 {
		t.Fatalf("advisory degradation exit %d, want 0", rc)
	}
}

func TestAdvisoriesBadInputsAreUsageErrors(t *testing.T) {
	root := advRoot(t, "advisories:\n  policy: yolo\n")
	cur := filepath.Join(root, "now.json")
	writeReport(t, cur, nil)
	if rc := runAdvisories([]string{"--root", root, "--input", cur}); rc != 2 {
		t.Errorf("invalid policy exit %d, want 2", rc)
	}
	if rc := runAdvisories([]string{"--root", t.TempDir(), "--input", filepath.Join(root, "absent.json")}); rc != 2 {
		t.Errorf("missing input exit %d, want 2", rc)
	}
	if rc := runAdvisories([]string{"--root", t.TempDir(), "--input", cur, "--format", "yaml"}); rc != 2 {
		t.Errorf("bad format exit %d, want 2", rc)
	}
}

func TestAdvisoriesWritesGitHubOutputs(t *testing.T) {
	root := advRoot(t, "advisories:\n  policy: prepare\n")
	cur, prev := filepath.Join(root, "now.json"), filepath.Join(root, "prev.json")
	writeReport(t, cur, []findings.Finding{advFinding("GHSA-new", "b", "1.0.1", findings.SeverityHigh)})
	writeReport(t, prev, nil)
	outFile, sumFile := filepath.Join(root, "out"), filepath.Join(root, "sum")
	t.Setenv("GITHUB_OUTPUT", outFile)
	t.Setenv("GITHUB_STEP_SUMMARY", sumFile)
	if rc := runAdvisories([]string{"--root", root, "--input", cur, "--previous", prev, "--github"}); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	out, _ := os.ReadFile(outFile) //nolint:gosec // test temp file
	for _, want := range []string{"action=prepare", "automerge=false", "new-count=1", "prepare-count=1", "previous-run=true", "incomplete=false"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("GITHUB_OUTPUT missing %q:\n%s", want, out)
		}
	}
	sum, _ := os.ReadFile(sumFile) //nolint:gosec // test temp file
	if !strings.Contains(string(sum), "GHSA-new") || !strings.Contains(string(sum), "could not be determined") {
		t.Errorf("summary should name the advisory and say relevance was not determined:\n%s", sum)
	}
}

func TestInstallCIRendersValidWorkflow(t *testing.T) {
	d, err := resolveInstallCI("main", "17 5 * * *", "v1.2.3", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderInstallCI(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "[[") || strings.Contains(out, "<no value>") {
		t.Fatalf("unfilled template action:\n%s", out)
	}
	var wf struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			If    string `yaml:"if"`
			Steps []struct {
				Uses string `yaml:"uses"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(out), &wf); err != nil {
		t.Fatalf("generated workflow is not YAML: %v", err)
	}
	for _, trigger := range []string{"pull_request", "push", "schedule", "workflow_dispatch"} {
		if _, ok := wf.On[trigger]; !ok {
			t.Errorf("workflow does not run on %s", trigger)
		}
	}
	if len(wf.Jobs) != 2 {
		t.Errorf("want scan and advisories jobs, got %d", len(wf.Jobs))
	}
	// Third-party actions are pinned to a commit; only nox-hq/nox takes the ref
	// the operator asked for.
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if s.Uses == "" || strings.HasPrefix(s.Uses, "nox-hq/nox") {
				continue
			}
			at := strings.LastIndex(s.Uses, "@")
			if at < 0 || len(s.Uses)-at-1 != 40 {
				t.Errorf("job %s: %q is not pinned to a commit SHA", name, s.Uses)
			}
		}
	}
	if !strings.Contains(out, "nox-hq/nox/actions/remediate@v1.2.3") {
		t.Error("remediate action should use the requested ref")
	}
}

func TestInstallCIRefusesUnsafeValues(t *testing.T) {
	for _, c := range [][4]string{
		{"main'\nx: y", "17 5 * * *", "v1", "latest"},
		{"main", "17 5 * * * *", "v1", "latest"},
		{"main", "17 5 * * *", "v1 # evil", "latest"},
		{"main", "17 5 * * *", "v1", "1; rm -rf /"},
	} {
		if _, err := resolveInstallCI(c[0], c[1], c[2], c[3]); err == nil {
			t.Errorf("accepted %q", c)
		}
	}
}

func TestInstallCIDevBuildNeedsARef(t *testing.T) {
	old := version
	version = "dev"
	t.Cleanup(func() { version = old })
	if _, err := resolveInstallCI("main", "17 5 * * *", "", ""); err == nil {
		t.Fatal("a dev build has no release tag to default to; it must ask")
	}
}

func TestInstallCIWritesOnceAndRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	args := []string{"--dir", dir, "--nox-ref", "v1.2.3"}
	if rc := runInstallCI(args); rc != 0 {
		t.Fatalf("first install exit %d", rc)
	}
	path := filepath.Join(dir, ".github", "workflows", "nox.yml")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if rc := runInstallCI(args); rc != 2 {
		t.Fatalf("second install exit %d, want 2", rc)
	}
	if rc := runInstallCI(append(args, "--force")); rc != 0 {
		t.Fatalf("--force exit %d", rc)
	}
}
