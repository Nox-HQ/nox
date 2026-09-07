package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

// workflowWithSteps writes a GitHub workflow with n continue-on-error steps.
// Each is a real, distinct finding, and under fingerprint v2 they all share one
// digest because IAC-018's message is a static description.
func workflowWithSteps(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "name: demo\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
	for i := 0; i < n; i++ {
		body += "      - name: step\n        run: echo hi\n        continue-on-error: true\n"
	}
	path := filepath.Join(dir, ".github", "workflows", "w.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing workflow: %v", err)
	}
	return dir
}

func iac018(fs *findings.FindingSet) []findings.Finding {
	var out []findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == "IAC-018" {
			out = append(out, f)
		}
	}
	return out
}

func writeBaselineFor(t *testing.T, dir string, entries []baseline.Entry) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".nox"), 0o755); err != nil {
		t.Fatalf("mkdir .nox: %v", err)
	}
	data, err := json.Marshal(baseline.Baseline{SchemaVersion: "1.0.0", Entries: entries})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".nox", "baseline.json"), data, 0o600); err != nil {
		t.Fatalf("writing baseline: %v", err)
	}
}

// The whole chain, through a real scan, because the unit tests in core/baseline
// prove the Matcher and not that the pipeline uses it.
//
// Accept one continue-on-error step, then add two more. Under the old
// fingerprint-only lookup all three were suppressed and `nox scan` printed
// "0 findings (3 suppressed)" — the third had never been seen by anyone, and it
// was introduced after the baseline was written.
func TestABaselineEntryDoesNotAbsorbLaterFindings(t *testing.T) {
	dir := workflowWithSteps(t, 3)

	// Establish what the fingerprint is, and accept ONE of the three.
	first, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := iac018(first.Findings)
	if len(found) != 3 {
		t.Fatalf("fixture produced %d IAC-018 findings, want 3", len(found))
	}
	if found[0].Fingerprint != found[1].Fingerprint || found[1].Fingerprint != found[2].Fingerprint {
		t.Skip("the three findings no longer share a fingerprint; this test has nothing to prove")
	}

	writeBaselineFor(t, dir, baseline.FromFindings(found[:1]))

	second, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	var baselined, active int
	for _, f := range iac018(second.Findings) {
		if f.Status == findings.StatusBaselined {
			baselined++
		} else if f.Status.IsActive() {
			active++
		}
	}
	if baselined != 1 {
		t.Errorf("%d findings were baselined by a one-entry baseline, want 1", baselined)
	}
	if active != 2 {
		t.Errorf("%d findings are active, want 2. One entry accepted one finding; the other "+
			"two were never accepted by anyone, and silence about them is a false negative "+
			"that grows every time somebody adds another step.", active)
	}
}

// The property the fix must not cost. Fingerprint v2 drops the line so a
// baseline survives code moving, and a fix that keyed on position would have
// traded a silent failure for a noisy one.
func TestAMovedFindingStaysBaselinedThroughAScan(t *testing.T) {
	dir := workflowWithSteps(t, 1)

	first, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := iac018(first.Findings)
	if len(found) != 1 {
		t.Fatalf("fixture produced %d IAC-018 findings, want 1", len(found))
	}
	writeBaselineFor(t, dir, baseline.FromFindings(found))

	// Push the step down the file.
	path := filepath.Join(dir, ".github", "workflows", "w.yml")
	body, err := os.ReadFile(path) //nolint:gosec // test-owned fixture
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if err := os.WriteFile(path, append([]byte("# a\n# b\n# c\n# d\n"), body...), 0o600); err != nil {
		t.Fatalf("rewriting fixture: %v", err)
	}

	second, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	moved := iac018(second.Findings)
	if len(moved) != 1 {
		t.Fatalf("after the move there are %d IAC-018 findings, want 1", len(moved))
	}
	if moved[0].Status != findings.StatusBaselined {
		t.Errorf("a baselined finding became %q after moving to line %d; v2 drops the line "+
			"from the fingerprint precisely so this cannot happen",
			moved[0].Status, moved[0].Location.StartLine)
	}
}
