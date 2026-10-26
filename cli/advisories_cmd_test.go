package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core"
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

// installCIWorkflow renders the workflow and returns its text and its
// advisories job's steps, for the bot-token tests.
type ciStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
	Run  string            `yaml:"run"`
}

func renderedAdvisoriesSteps(t *testing.T) (out string, steps map[string]ciStep) {
	t.Helper()
	d, err := resolveInstallCI("main", "17 5 * * *", "v1.2.3", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	out, err = renderInstallCI(d)
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []ciStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(out), &wf); err != nil {
		t.Fatalf("generated workflow is not YAML: %v", err)
	}
	steps = map[string]ciStep{}
	for _, s := range wf.Jobs["advisories"].Steps {
		steps[s.Name] = s
	}
	return out, steps
}

func TestInstallCIUsesAGitHubAppTokenWhenConfigured(t *testing.T) {
	out, steps := renderedAdvisoriesSteps(t)
	app := steps["Mint a short-lived GitHub App token"]
	if app.ID != "app-token" || !strings.HasPrefix(app.Uses, "actions/create-github-app-token@") {
		t.Fatalf("app-token step missing: %+v", app)
	}
	if !strings.HasSuffix(app.Uses, "@64ab729a6294000f5aa4a4bc0b73d1f32bc45510") || !strings.Contains(out, "# v3.3.0") {
		t.Errorf("app-token action not pinned to the v3.3.0 commit: %s", app.Uses)
	}
	if app.If != "steps.bot.outputs.kind == 'app'" {
		t.Errorf("app-token step must only run when the app secrets exist, if = %q", app.If)
	}
	// Minimum permissions, and nothing else.
	perms := map[string]string{}
	for k, v := range app.With {
		if strings.HasPrefix(k, "permission-") {
			perms[k] = v.(string)
		}
	}
	want := map[string]string{"permission-contents": "write", "permission-pull-requests": "write", "permission-issues": "write"}
	if len(perms) != len(want) {
		t.Errorf("permissions = %v, want %v", perms, want)
	}
	for k, v := range want {
		if perms[k] != v {
			t.Errorf("%s = %q, want %q", k, perms[k], v)
		}
	}
	rem := steps["Prepare the remediation pull request"]
	if got := rem.With["github-token"]; got != "${{ steps.app-token.outputs.token || secrets.NOX_TOKEN || github.token }}" {
		t.Errorf("remediate token order is app, pat, github; got %v", got)
	}
}

func TestInstallCITokenChoiceNeverExposesASecret(t *testing.T) {
	_, steps := renderedAdvisoriesSteps(t)
	bot := steps["Choose the token that opens pull requests"]
	for k, v := range bot.Env {
		if !strings.Contains(v, "!= ''") {
			t.Errorf("env %s must test presence only, got %q", k, v)
		}
	}
	if strings.Contains(bot.Run, "secrets.") || strings.Contains(bot.Run, "echo \"${NOX") {
		t.Errorf("the choosing script must not touch a secret:\n%s", bot.Run)
	}
	// Only the steps that need a credential reference a secret.
	for name, s := range steps {
		raw, _ := yaml.Marshal(s)
		if strings.Contains(string(raw), "secrets.") &&
			name != "Mint a short-lived GitHub App token" &&
			name != "Prepare the remediation pull request" &&
			name != "Allow auto-merge for safe upgrades" &&
			name != "Choose the token that opens pull requests" {
			t.Errorf("step %q should not receive a secret", name)
		}
		if strings.Contains(s.Run, "secrets.") {
			t.Errorf("step %q interpolates a secret into a script", name)
		}
	}
}

func TestInstallCIGitHubTokenFallbackWarnsAndSkipsAutoMerge(t *testing.T) {
	_, steps := renderedAdvisoriesSteps(t)
	bot := steps["Choose the token that opens pull requests"]
	for _, want := range []string{"kind=github", "::warning::", "CI will not run", "auto-merge cannot complete", "GITHUB_STEP_SUMMARY", "docs/advisory-policy.md#opening-pull-requests-that-run-your-checks"} {
		if !strings.Contains(bot.Run, want) {
			t.Errorf("fallback should mention %q:\n%s", want, bot.Run)
		}
	}
	merge := steps["Allow auto-merge for safe upgrades"]
	if !strings.Contains(merge.If, "steps.bot.outputs.kind != 'github'") {
		t.Errorf("auto-merge must be skipped on a GITHUB_TOKEN PR, if = %q", merge.If)
	}
	if strings.Contains(merge.Env["GH_TOKEN"], "github.token") {
		t.Errorf("auto-merge must never fall back to GITHUB_TOKEN: %q", merge.Env["GH_TOKEN"])
	}
	expl := steps["Explain why auto-merge was not enabled"]
	if !strings.Contains(expl.If, "steps.bot.outputs.kind == 'github'") || !strings.Contains(expl.Run, "::warning::") {
		t.Errorf("a GITHUB_TOKEN PR should say why auto-merge is off: %+v", expl)
	}
}

func TestInstallCIPAT(t *testing.T) {
	_, steps := renderedAdvisoriesSteps(t)
	bot := steps["Choose the token that opens pull requests"]
	if !strings.Contains(bot.Env["HAS_PAT"], "secrets.NOX_TOKEN != ''") || !strings.Contains(bot.Run, "kind=pat") {
		t.Errorf("a NOX_TOKEN secret should select the pat path: %+v", bot)
	}
	// The app wins over the PAT.
	if strings.Index(bot.Run, "kind=app") > strings.Index(bot.Run, "kind=pat") {
		t.Error("the app must be preferred over the PAT")
	}
}

func TestInstallCIEveryUsesIsPinnedOnAllJobs(t *testing.T) {
	out, _ := renderedAdvisoriesSteps(t)
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:- )?uses: (\S+)`).FindAllStringSubmatch(out, -1) {
		if strings.HasPrefix(m[1], "nox-hq/nox") {
			continue
		}
		at := strings.LastIndex(m[1], "@")
		if at < 0 || !sha.MatchString(m[1][at+1:]) {
			t.Errorf("%q is not pinned to a 40-hex commit", m[1])
		}
	}
}

const releaseSHA = "9133597590c30b2235093c48425c0afcecef0700"

func withBuild(t *testing.T, v, c string) {
	t.Helper()
	ov, oc := version, commit
	version, commit = v, c
	t.Cleanup(func() { version, commit = ov, oc })
}

// The default ref is the release commit with the version as a trailing comment,
// at every place the template names nox-hq/nox, and it is not a tag.
func TestInstallCIDefaultPinsReleaseCommit(t *testing.T) {
	withBuild(t, "1.52.0", releaseSHA)
	d, err := resolveInstallCI("main", "17 5 * * *", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Warning != "" {
		t.Errorf("unexpected warning %q", d.Warning)
	}
	out, err := renderInstallCI(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"uses: nox-hq/nox@" + releaseSHA + " # v1.52.0",
		"uses: nox-hq/nox/actions/remediate@" + releaseSHA + " # v1.52.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "nox@v1.52.0") {
		t.Error("workflow still pins the mutable tag")
	}
}

// A release version whose commit was not embedded must not fall back to the tag.
func TestInstallCIRefusesReleaseWithoutCommit(t *testing.T) {
	withBuild(t, "1.52.0", "none")
	if _, err := resolveInstallCI("main", "17 5 * * *", "", ""); err == nil {
		t.Fatal("wrote a ref without a commit to pin")
	}
}

func TestInstallCIWarnsOnExplicitTag(t *testing.T) {
	d, err := resolveInstallCI("main", "17 5 * * *", "v1.2.3", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Warning, "IAC-013") {
		t.Errorf("a tag ref should warn, got %q", d.Warning)
	}
}

// The generated workflow passes nox's own scan: no IAC-013.
func TestInstallCIWorkflowHasNoIAC013(t *testing.T) {
	withBuild(t, "1.52.0", releaseSHA)
	d, err := resolveInstallCI("main", "17 5 * * *", "", "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderInstallCI(d)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil { //nolint:gosec // test dir
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wf, "nox.yml"), []byte(out), 0o644); err != nil { //nolint:gosec // test file
		t.Fatal(err)
	}
	res, err := core.RunScanWithOptions(dir, core.ScanOptions{ToolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "IAC-013" {
			t.Errorf("generated workflow trips IAC-013 at %s:%d", f.Location.FilePath, f.Location.StartLine)
		}
	}
}
