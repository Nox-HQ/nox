package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to an in-memory
// buffer and returns whatever fn wrote. Used to verify the
// human-readable behaviour the PR description promises (silent paths,
// DRIFT label, fix-up command).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

func writeWorkflow(t *testing.T, root, name, body string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReportCIVersionDrift_Silent_NoWorkflowsDir — repos without any
// .github/workflows directory must produce ZERO output. The doctor
// caller relies on this to skip the section header entirely.
func TestReportCIVersionDrift_Silent_NoWorkflowsDir(t *testing.T) {
	out := captureStdout(t, func() {
		reportCIVersionDrift(t.TempDir(), "0.10.0")
	})
	if out != "" {
		t.Errorf("expected silent output, got %q", out)
	}
}

// TestReportCIVersionDrift_Silent_NoNoxRefs — repos with workflow
// files that don't reference nox must also stay silent.
func TestReportCIVersionDrift_Silent_NoNoxRefs(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: 'make test'}]\n")
	out := captureStdout(t, func() {
		reportCIVersionDrift(dir, "0.10.0")
	})
	if out != "" {
		t.Errorf("expected silent output, got %q", out)
	}
}

// TestReportCIVersionDrift_DriftDetected — pinned version differs
// from local; output must contain DRIFT marker, the local version,
// and the fix-up command.
func TestReportCIVersionDrift_DriftDetected(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml",
		"steps:\n  - run: go install github.com/nox-hq/nox/cli@v0.8.1\n")
	out := captureStdout(t, func() {
		reportCIVersionDrift(dir, "0.10.0")
	})
	for _, want := range []string{"[ci]", "DRIFT", "ci.yml", "v0.8.1", "local: 0.10.0", "bump CI to v0.10.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestReportCIVersionDrift_AllMatch — pinned version matches local;
// output must contain `ok` markers and NOT contain `DRIFT`.
func TestReportCIVersionDrift_AllMatch(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml",
		"steps:\n  - run: go install github.com/nox-hq/nox/cli@v0.10.0\n")
	out := captureStdout(t, func() {
		reportCIVersionDrift(dir, "0.10.0")
	})
	if !strings.Contains(out, "ok    ci.yml") {
		t.Errorf("expected `ok` marker, got:\n%s", out)
	}
	if strings.Contains(out, "DRIFT") {
		t.Errorf("unexpected DRIFT in matching output:\n%s", out)
	}
}

// TestReportCIVersionDrift_DevLocal — local version is a dev build
// (not a real semver); output must list the pins but skip the DRIFT
// comparison.
func TestReportCIVersionDrift_DevLocal(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml",
		"steps:\n  - run: go install github.com/nox-hq/nox/cli@v0.8.1\n")
	out := captureStdout(t, func() {
		reportCIVersionDrift(dir, "dev")
	})
	if !strings.Contains(out, "skipping drift comparison") {
		t.Errorf("expected skip notice, got:\n%s", out)
	}
	if strings.Contains(out, "DRIFT") {
		t.Errorf("DRIFT must not fire when local is not a semver:\n%s", out)
	}
}

func TestCIVersionRE(t *testing.T) {
	cases := map[string]string{
		"go install github.com/nox-hq/nox/cli@v0.10.0": "0.10.0",
		"go install github.com/nox-hq/nox/cli@v0.8.1":  "0.8.1",
		"uses: nox-hq/nox@v0.9.5":                      "0.9.5",
		"uses: nox-hq/nox-remediate-action@v1":         "", // major-only; not captured
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
