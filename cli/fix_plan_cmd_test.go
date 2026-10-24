package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/fix"
)

const workflowBody = `name: ci
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
        continue-on-error: true
`

const podBody = `apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: example/app:1.0.0
      securityContext:
        privileged: true
`

// fixTree writes a small project with two mechanical misconfigurations, scans
// it with the real engine, and writes findings.json the way `nox scan` does.
func fixTree(t *testing.T) (root, findingsPath string) {
	t.Helper()
	root = t.TempDir()
	for name, body := range map[string]string{
		".github/workflows/ci.yml": workflowBody,
		"k8s/pod.yaml":             podBody,
	} {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := nox.RunScanWithOptions(root, nox.ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"findings": res.Findings.ActiveFindings()})
	if err != nil {
		t.Fatal(err)
	}
	findingsPath = filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(findingsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, findingsPath
}

func TestFixPlanClassifiesTheTwoMisconfigurations(t *testing.T) {
	root, in := fixTree(t)
	var code int
	out := captureStdout(t, func() { code = runFix([]string{"plan", "--input", in, "--root", root, "--format", "json"}) })
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	var plan struct {
		Items []struct {
			Class string   `json:"class"`
			Kind  string   `json:"kind"`
			Rules []string `json:"rules"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("plan is not JSON: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, it := range plan.Items {
		for _, r := range it.Rules {
			got[r] = it.Class
		}
	}
	if got["IAC-018"] != "safe_to_apply" || got["IAC-007"] != "needs_review" {
		t.Fatalf("classes = %v\n%s", got, out)
	}
	// Planning writes nothing.
	if readFile(t, filepath.Join(root, "k8s", "pod.yaml")) != podBody {
		t.Fatal("fix plan modified a file")
	}
}

func TestFixApplyChangesOnlyTheSafeSetAndVerifiesIt(t *testing.T) {
	root, in := fixTree(t)
	var code int
	out := captureStdout(t, func() { code = runFix([]string{"apply", "--input", in, "--root", root, "--offline"}) })
	if code != 0 {
		t.Fatalf("exit = %d\n%s", code, out)
	}
	if !strings.Contains(readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml")), "continue-on-error: false") {
		t.Fatal("the safe change was not applied")
	}
	if readFile(t, filepath.Join(root, "k8s", "pod.yaml")) != podBody {
		t.Fatal("a change that needs review was applied without being asked for")
	}
	for _, want := range []string{"Verified fixed (1)", "Verified fixed: 1 of 1 changes.", "still yours to resolve"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestFixApplyIncludeReviewAppliesAndVerifiesBoth(t *testing.T) {
	root, in := fixTree(t)
	var code int
	out := captureStdout(t, func() {
		code = runFix([]string{"apply", "--include-review", "--input", in, "--root", root, "--offline"})
	})
	if code != 0 {
		t.Fatalf("exit = %d\n%s", code, out)
	}
	if !strings.Contains(readFile(t, filepath.Join(root, "k8s", "pod.yaml")), "privileged: false") {
		t.Fatal("the reviewed change was not applied")
	}
	if !strings.Contains(out, "Verified fixed: 2 of 2 changes.") {
		t.Fatalf("report:\n%s", out)
	}
}

// The verifier reads the re-run, not the edit. A change that rewrites the line
// without removing what the rule matches must come back as still present.
func TestFixApplyReportsStillPresentWhenTheEditDoesNotClearTheFinding(t *testing.T) {
	orig := fix.ContentFixes["IAC-018"]
	bad := orig
	bad.Repl = "${1}true # reviewed" // rewrites the line, but the rule still matches it
	fix.ContentFixes["IAC-018"] = bad
	t.Cleanup(func() { fix.ContentFixes["IAC-018"] = orig })

	root, in := fixTree(t)
	var code int
	out := captureStdout(t, func() { code = runFix([]string{"apply", "--input", in, "--root", root, "--offline"}) })

	if !strings.Contains(readFile(t, filepath.Join(root, ".github", "workflows", "ci.yml")), "continue-on-error: true # reviewed") {
		t.Fatal("test setup: the edit was not made")
	}
	if code == 0 {
		t.Fatalf("exit 0 for a change that did not clear its finding:\n%s", out)
	}
	if !strings.Contains(out, "Still present (1)") || strings.Contains(out, "Verified fixed (") {
		t.Fatalf("report claims more than the re-run showed:\n%s", out)
	}
}

func TestFixApplyJSONIsOneDocument(t *testing.T) {
	root, in := fixTree(t)
	var code int
	out := captureStdout(t, func() {
		code = runFix([]string{"apply", "--format", "json", "--input", in, "--root", root, "--offline"})
	})
	if code != 0 {
		t.Fatalf("exit = %d\n%s", code, out)
	}
	var res struct {
		Attempts []struct {
			Applied bool `json:"applied"`
		} `json:"attempts"`
		Report struct {
			Counts struct {
				Fixed int `json:"verified_fixed"`
			} `json:"counts"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, out)
	}
	if len(res.Attempts) != 1 || !res.Attempts[0].Applied || res.Report.Counts.Fixed != 1 {
		t.Fatalf("result = %+v", res)
	}
}

func TestFixVerifyChecksAChangeMadeByHand(t *testing.T) {
	root, in := fixTree(t)
	path := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.WriteFile(path, []byte(strings.Replace(workflowBody, "true", "false", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() { code = runFix([]string{"verify", "--input", in, "--root", root, "--offline"}) })
	if code == 0 {
		t.Fatalf("exit 0 although the pod is still privileged:\n%s", out)
	}
	for _, want := range []string{"Verified fixed (1)", "Still present (1)"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

// A plan from a different tree than the one on disk must not write a stale line.
func TestApplyPatchesRefusesAStaleLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pod.yaml")
	if err := os.WriteFile(path, []byte("securityContext:\n  privileged: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := applyPatches([]fix.Patch{{RuleID: "IAC-007", File: "pod.yaml", Line: 2}}, dir)
	if err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("err = %v", err)
	}
}

func TestFixSubcommandUsageErrors(t *testing.T) {
	if code := runFix([]string{"plan", "--input", filepath.Join(t.TempDir(), "absent.json")}); code != 2 {
		t.Fatalf("missing findings.json: exit = %d, want 2", code)
	}
	root, in := fixTree(t)
	if code := runFix([]string{"plan", "--input", in, "--root", root, "--format", "xml"}); code != 2 {
		t.Fatalf("bad format: exit = %d, want 2", code)
	}
}

// The original flag-driven nox fix is untouched by the subcommands.
func TestBareFixStillTakesItsOwnFlags(t *testing.T) {
	re := regexp.MustCompile(`no eligible upgrades`)
	dir := t.TempDir()
	in := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(in, []byte(`{"findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { _ = runFix([]string{"--input", in, "--dry-run"}) })
	if !re.MatchString(out) {
		t.Fatalf("legacy path changed: %q", out)
	}
}
