package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReportCIVersionDrift_MatchingVersion is a smoke test that the
// drift detector doesn't panic when CI and local agree. We can't
// easily assert stdout from `runDoctor`, but we can drive the helper
// directly and verify it tolerates the inputs.
func TestReportCIVersionDrift_MatchingVersion(t *testing.T) {
	dir := t.TempDir()
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `name: ci
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: go install github.com/nox-hq/nox/cli@v0.10.0`
	if err := os.WriteFile(filepath.Join(workflows, "ci.yml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	// Just exercise the path; correctness is verified by the regex test
	// below + the manual `nox doctor` run.
	reportCIVersionDrift(dir, "0.10.0")
}

func TestCIVersionRE(t *testing.T) {
	cases := map[string]string{
		"go install github.com/nox-hq/nox/cli@v0.10.0": "0.10.0",
		"go install github.com/nox-hq/nox/cli@v0.8.1":  "0.8.1",
		"uses: nox-hq/nox@v0.9.5":                      "0.9.5",
		"uses: nox-hq/nox-remediate-action@v1":         "", // major-only; we don't capture
		"uses: nox-hq/nox@v0.10.0   # pinned":          "0.10.0",
		"some unrelated line":                          "",
	}
	for input, want := range cases {
		m := ciNoxVersionRE.FindStringSubmatch(input)
		var got string
		if len(m) == 2 {
			got = m[1]
		}
		if got != want {
			t.Errorf("input=%q  got=%q  want=%q", input, got, want)
		}
	}
}

func TestStripVPrefix(t *testing.T) {
	cases := map[string]string{
		"v0.10.0": "0.10.0",
		"0.10.0":  "0.10.0",
		"v":       "",
		"":        "",
	}
	for in, want := range cases {
		if got := stripVPrefix(in); got != want {
			t.Errorf("stripVPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasSuffix(t *testing.T) {
	if !hasSuffix("ci.yml", ".yml") {
		t.Error("expected ci.yml has .yml suffix")
	}
	if hasSuffix("yml", ".yaml") {
		t.Error("\"yml\" should not have .yaml suffix")
	}
	if !hasSuffix("ci.yaml", ".yaml") {
		t.Error("expected ci.yaml has .yaml suffix")
	}
}
