package iac

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// IAC-153 says an uploaded artifact has no provenance attestation, which
// matters for an artifact someone will consume as a build. Two uploads cannot
// be that (#1010): one in a workflow that runs only for pull requests, which
// publishes nothing, and one in a step that runs even when the job failed
// (`if: always()`, `failure()`, `!cancelled()`), which is how CI keeps
// diagnostics such as scan reports. A failed build is not released.
func TestIAC153OnlyReportsUploadsThatCouldBeBuilds(t *testing.T) {
	const upload = `      - uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: out
          path: out/
`
	job := func(on, stepIf string) string {
		s := "name: W\n" + on + "\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
		if stepIf != "" {
			return s + "      - name: keep\n        if: " + stepIf + "\n" + strings.Replace(upload, "      - uses:", "        uses:", 1)
		}
		return s + upload
	}
	cases := []struct {
		name  string
		file  string
		fires bool
	}{
		{"push to main", job("on:\n  push:\n    branches: [main]", ""), true},
		{"release", job("on:\n  release:\n    types: [published]", ""), true},
		{"tag push", job("on:\n  push:\n    tags: ['v*']", ""), true},
		{"manual dispatch may publish", job("on: [pull_request, workflow_dispatch]", ""), true},
		{"pull_request_target can publish", job("on: pull_request_target", ""), true},
		{"on success only", job("on: push", "success()"), true},
		{"pull request only, scalar", job("on: pull_request", ""), false},
		{"pull request only, list", job("on: [pull_request]", ""), false},
		{"pull request and merge queue, map", job("on:\n  pull_request:\n    branches: [main]\n  merge_group:", ""), false},
		{"always", job("on: push", "always()"), false},
		{"always in an expression", job("on: push", "${{ always() }}"), false},
		{"failure", job("on: push", "failure()"), false},
		{"not cancelled", job("on: push", "${{ !cancelled() }}"), false},
	}
	a := NewAnalyzer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.ScanFile(".github/workflows/w.yml", []byte(tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if hasRule(got, "IAC-153") != tc.fires {
				t.Errorf("IAC-153 fired = %v, want %v\n%s", !tc.fires, tc.fires, tc.file)
			}
		})
	}
}

// One diagnostic upload does not excuse a build upload in the same workflow.
func TestIAC153KeepsTheBuildUploadBesideADiagnosticOne(t *testing.T) {
	wf := `name: W
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: make
      - uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: dist
          path: dist/
      - name: keep reports
        if: always()
        uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: reports
          path: reports/
`
	got, err := NewAnalyzer().ScanFile(".github/workflows/w.yml", []byte(wf))
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range got {
		if f.RuleID == "IAC-153" {
			lines = append(lines, f.Location.StartLine)
		}
	}
	if len(lines) != 1 || lines[0] != 8 {
		t.Fatalf("IAC-153 on lines %v, want only the build upload on line 8", lines)
	}
}

// The absence matcher reports only the first upload in a file. When that one is
// diagnostic, the finding moves to the build upload after it rather than
// disappearing with it, and keeps the fingerprint the anchor text gives it.
func TestIAC153MovesPastALeadingDiagnosticUpload(t *testing.T) {
	wf := `name: W
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - name: keep reports
        if: always()
        uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: reports
          path: reports/
      - run: make
      - uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: dist
          path: dist/
`
	got, err := NewAnalyzer().ScanFile(".github/workflows/w.yml", []byte(wf))
	if err != nil {
		t.Fatal(err)
	}
	var hits []findings.Finding
	for _, f := range got {
		if f.RuleID == "IAC-153" {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 || hits[0].Location.StartLine != 14 {
		t.Fatalf("IAC-153 findings %+v, want one on the build upload, line 14", hits)
	}
	if want := findings.ComputeFingerprint("IAC-153", hits[0].Location, "actions/upload-artifact"); hits[0].Fingerprint != want {
		t.Errorf("fingerprint %s, want %s", hits[0].Fingerprint, want)
	}
}

// A commented-out upload is not a step. The finding lands on the real upload
// after it, rather than on the comment, where the comment filter would drop it.
func TestIAC153SkipsACommentedOutUpload(t *testing.T) {
	wf := `name: W
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      # - uses: actions/upload-artifact@v4 (disabled until the bucket exists)
      - run: make
      - uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6.0.0
        with:
          name: dist
          path: dist/
`
	got, err := NewAnalyzer().ScanFile(".github/workflows/w.yml", []byte(wf))
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range got {
		if f.RuleID == "IAC-153" {
			lines = append(lines, f.Location.StartLine)
		}
	}
	if len(lines) != 1 || lines[0] != 9 {
		t.Fatalf("IAC-153 on lines %v, want the real upload on line 9", lines)
	}
}
