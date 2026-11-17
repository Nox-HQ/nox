package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/internal/testkey"
)

// captureSplit runs fn with stdout and stderr captured separately. captureCLI
// merges them, which is exactly what a test of "stdout carries only the
// report" cannot use.
func captureSplit(t *testing.T, fn func() int) (code int, stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW
	read := func(r *os.File) chan string {
		ch := make(chan string, 1)
		go func() {
			var b bytes.Buffer
			_, _ = io.Copy(&b, r)
			ch <- b.String()
		}()
		return ch
	}
	outCh, errCh := read(outR), read(errR)
	code = fn()
	_ = outW.Close()
	_ = errW.Close()
	os.Stdout, os.Stderr = origOut, origErr
	return code, <-outCh, <-errCh
}

// streamFixture is a tree with one secret (a finding) and one pinned
// dependency (so cdx and spdx have a component).
func streamFixture(t *testing.T, withFinding bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if withFinding {
		if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte("AWS_KEY="+testkey.AWSAccessKeyID()+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func assertNoReportFiles(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		for _, name := range []string{".nox", "findings.json", "results.sarif", "sbom.cdx.json", "sbom.spdx.json", "ai.inventory.json", "-"} {
			if _, err := os.Lstat(filepath.Join(d, name)); err == nil {
				t.Errorf("%s was created in %s by a run that streams to stdout", name, d)
			}
		}
	}
}

// --output - streams one report, and only the report: --verbose is on so every
// note and "[report] wrote" line is armed, and none may reach stdout.
func TestScanOutputDashStreamsOnlyTheReport(t *testing.T) {
	cases := []struct {
		format string
		check  func(t *testing.T, doc map[string]any)
	}{
		{"json", func(t *testing.T, doc map[string]any) {
			if _, ok := doc["findings"]; !ok {
				t.Error("findings.json has no findings key")
			}
		}},
		{"sarif", func(t *testing.T, doc map[string]any) {
			if doc["version"] != "2.1.0" {
				t.Errorf("sarif version = %v, want 2.1.0", doc["version"])
			}
		}},
		{"cdx", func(t *testing.T, doc map[string]any) {
			if doc["bomFormat"] != "CycloneDX" {
				t.Errorf("bomFormat = %v", doc["bomFormat"])
			}
		}},
		{"spdx", func(t *testing.T, doc map[string]any) {
			if _, ok := doc["spdxVersion"]; !ok {
				t.Error("no spdxVersion")
			}
		}},
	}
	for _, withFinding := range []bool{true, false} {
		for _, tc := range cases {
			name := tc.format + "/clean"
			want := 0
			if withFinding {
				name, want = tc.format+"/findings", 1
			}
			t.Run(name, func(t *testing.T) {
				dir := streamFixture(t, withFinding)
				cwd := t.TempDir()
				t.Chdir(cwd)

				code, stdout, stderr := captureSplit(t, func() int {
					return run([]string{"--verbose", "scan", dir, "--format", tc.format, "--output", "-", "--offline"})
				})
				// SBOMs carry no verdict of their own; the exit code is the
				// scan's, so a tree with a secret still exits 1.
				if code != want {
					t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, want, stderr)
				}
				var doc map[string]any
				if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
					t.Fatalf("stdout is not one JSON document: %v\nstdout head: %.300q", err, stdout)
				}
				tc.check(t, doc)
				if !strings.Contains(stderr, "scanning") {
					t.Errorf("the progress notes should be on stderr, got:\n%s", stderr)
				}
				assertNoReportFiles(t, dir, cwd)
			})
		}
	}
}

// A usage error writes nothing: no stdout, no files.
func TestScanOutputDashRequiresExactlyOneFormat(t *testing.T) {
	for _, format := range []string{"json,sarif", "all", "html"} {
		t.Run(format, func(t *testing.T) {
			dir := streamFixture(t, true)
			cwd := t.TempDir()
			t.Chdir(cwd)

			code, stdout, stderr := captureSplit(t, func() int {
				return run([]string{"scan", dir, "--format", format, "--output", "-", "--offline"})
			})
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout must be empty, got %q", stdout)
			}
			if format != "html" && !strings.Contains(stderr, "`--output -` streams one report; choose a single --format") {
				t.Errorf("stderr lacks the usage message:\n%s", stderr)
			}
			assertNoReportFiles(t, dir, cwd)
		})
	}
}

// A scan that fails before a report exists prints nothing on stdout.
func TestScanOutputDashFailureLeavesStdoutEmpty(t *testing.T) {
	dir := streamFixture(t, true)
	cwd := t.TempDir()
	t.Chdir(cwd)

	code, stdout, _ := captureSplit(t, func() int {
		return run([]string{"scan", dir, "--format", "sarif", "--output", "-", "--offline", "--rules", filepath.Join(cwd, "missing-rules.yaml")})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty when the scan fails, got %.200q", stdout)
	}
	assertNoReportFiles(t, dir, cwd)
}

// --fail-on-degraded is applied after the report is fully written.
func TestScanOutputDashFailOnDegradedKeepsTheReport(t *testing.T) {
	dir := streamFixture(t, false)
	// A malformed lockfile is a check that could not complete.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())

	code, stdout, stderr := captureSplit(t, func() int {
		return run([]string{"scan", dir, "--format", "sarif", "--output", "-", "--offline", "--fail-on-degraded"})
	})
	if !strings.Contains(stderr, "[degraded]") {
		t.Skipf("fixture did not degrade the scan; stderr:\n%s", stderr)
	}
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("the report must be complete before the degraded exit: %v", err)
	}
}

// File output is the same bytes as the stream: both come from one Generate.
func TestScanOutputDashMatchesFileOutput(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	dir := streamFixture(t, true)
	t.Chdir(t.TempDir())
	outDir := t.TempDir()

	if code, _, stderr := captureSplit(t, func() int {
		return run([]string{"--quiet", "scan", dir, "--format", "sarif", "--output", outDir, "--offline"})
	}); code != 1 {
		t.Fatalf("file run exit = %d\n%s", code, stderr)
	}
	want, err := os.ReadFile(filepath.Join(outDir, "results.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := captureSplit(t, func() int {
		return run([]string{"--quiet", "scan", dir, "--format", "sarif", "--output", "-", "--offline"})
	})
	if code != 1 {
		t.Fatalf("stream run exit = %d", code)
	}
	if stdout != string(want) {
		t.Errorf("streamed SARIF differs from the file written by the same scan")
	}
}
