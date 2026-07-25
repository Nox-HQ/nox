package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The unused-waiver check only ever looked at files that already had a
// finding, because it iterated the findings grouped by path. A waiver in an
// otherwise-clean file was therefore invisible: the one place a dead waiver is
// most likely to hide — a file whose findings were all fixed, leaving the
// nox:ignore behind — was the one place never checked.
//
// It surfaced by accident: enabling analysis plugins spread findings across
// many more files, and five dead waivers in nox's own source appeared at once
// purely because those files now had some unrelated finding. Whether a waiver
// is reported must not depend on whether something else in the same file
// happened to fire.
func TestRunScan_DeadWaiverInCleanFileIsReported(t *testing.T) {
	dir := t.TempDir()

	// A file with no findings at all, carrying a waiver for a rule that does
	// not fire here. Nothing else in this file is reportable.
	clean := "package main\n\n// nox:ignore SEC-001 -- fixed long ago, waiver left behind\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	for _, d := range result.Degradations {
		if d.Kind == "suppression" && strings.Contains(d.Detail, "SEC-001") {
			return // reported, as it must be
		}
	}
	t.Errorf("a dead waiver in a file with no findings was not reported; degradations: %+v", result.Degradations)
}

// The converse: a waiver that is actually suppressing a finding must never be
// reported as dead, and the clean-file sweep must not invent reports for files
// that carry no directive at all.
func TestRunScan_LiveWaiverAndCleanFilesAreSilent(t *testing.T) {
	dir := t.TempDir()

	// No directives anywhere, nothing reportable.
	if err := os.WriteFile(filepath.Join(dir, "quiet.go"),
		[]byte("package main\n\nfunc Add(a, b int) int { return a + b }\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	for _, d := range result.Degradations {
		if d.Kind == "suppression" {
			t.Errorf("a file with no waivers produced a suppression degradation: %s", d.Detail)
		}
	}
}
