package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/baseline"
)

// Findings that share a fingerprint (nox-hq/nox#1105): a rule with a static
// message gives one v2 digest to every occurrence in a file, and the matcher
// consumes one baseline entry per occurrence. add/update must therefore write
// one entry per occurrence, not one per fingerprint.

const workflowTwoSteps = `name: w
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - name: first step
        continue-on-error: true
        run: "true"
      - name: second step
        continue-on-error: true
        run: "true"
`

const workflowOneStep = `name: w
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - name: first step
        continue-on-error: true
        run: "true"
`

func writeBaselineWorkflow(t *testing.T, dir, body string) {
	t.Helper()
	p := filepath.Join(dir, ".github", "workflows", "w.yml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// iacFingerprint scans dir and returns the shared IAC-018 fingerprint and how
// many occurrences carry it, so the tests do not hard-code a digest.
func iacFingerprint(t *testing.T, dir string) (fingerprint string, occurrences int) {
	t.Helper()
	res, err := nox.RunScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "IAC-018" {
			fingerprint = f.Fingerprint
			occurrences++
		}
	}
	return fingerprint, occurrences
}

// uncovered reports how many findings the baseline at path still leaves
// reported, using the same matcher a scan applies.
func uncovered(t *testing.T, dir, path string) int {
	t.Helper()
	res, err := nox.RunScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	bl, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return len(bl.Uncovered(res.Findings.Findings()))
}

func countFP(t *testing.T, path, fp string) int {
	t.Helper()
	bl, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	n := 0
	for i := range bl.Entries {
		if bl.Entries[i].Fingerprint == fp {
			n++
		}
	}
	return n
}

func TestBaselineAdd_OneEntryPerOccurrence(t *testing.T) {
	tests := []struct {
		name     string
		seed     int // entries for the shared fingerprint already in the file
		runs     int
		wantEnts int
	}{
		{"two occurrences, empty baseline", 0, 1, 2},
		{"idempotent on re-run", 0, 3, 2},
		{"one entry present adds only the missing one", 1, 1, 2},
		{"already complete adds nothing", 2, 1, 2},
		{"spare entries are not pruned by add", 3, 1, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBaselineWorkflow(t, dir, workflowTwoSteps)
			fp, occ := iacFingerprint(t, dir)
			if occ != 2 {
				t.Fatalf("fixture must yield 2 occurrences, got %d", occ)
			}
			blPath := filepath.Join(dir, "bl.json")
			bl := &baseline.Baseline{}
			for i := 0; i < tc.seed; i++ {
				bl.Add(&baseline.Entry{Fingerprint: fp, RuleID: "IAC-018", CreatedAt: time.Now().UTC()})
			}
			if err := bl.Save(blPath); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.runs; i++ {
				if code := runBaseline([]string{"add", "--rule", "IAC-018", "--baseline", blPath, dir}); code != 0 {
					t.Fatalf("add exit %d", code)
				}
			}
			if got := countFP(t, blPath, fp); got != tc.wantEnts {
				t.Errorf("entries for fingerprint = %d, want %d", got, tc.wantEnts)
			}
			if n := uncovered(t, dir, blPath); n != 0 {
				t.Errorf("%d findings still reported after add", n)
			}
		})
	}
}

func TestBaselineUpdate_OneEntryPerOccurrenceAndPrune(t *testing.T) {
	dir := t.TempDir()
	writeBaselineWorkflow(t, dir, workflowTwoSteps)
	fp, _ := iacFingerprint(t, dir)
	blPath := filepath.Join(dir, "bl.json")

	for i := 0; i < 2; i++ { // second run must be idempotent
		if code := runBaseline([]string{"update", "--baseline", blPath, dir}); code != 0 {
			t.Fatalf("update exit %d", code)
		}
		if got := countFP(t, blPath, fp); got != 2 {
			t.Fatalf("run %d: entries = %d, want 2", i, got)
		}
	}
	if n := uncovered(t, dir, blPath); n != 0 {
		t.Fatalf("%d findings still reported after update", n)
	}

	// One occurrence disappears: prune keeps exactly one entry for it.
	writeBaselineWorkflow(t, dir, workflowOneStep)
	if code := runBaseline([]string{"update", "--baseline", blPath, dir}); code != 0 {
		t.Fatalf("update exit %d", code)
	}
	if got := countFP(t, blPath, fp); got != 1 {
		t.Errorf("after one occurrence vanished, entries = %d, want 1", got)
	}
}

func TestBaselineAdd_DistinctFingerprintsUnaffected(t *testing.T) {
	dir := t.TempDir()
	writeBaselineWorkflow(t, dir, workflowTwoSteps)
	blPath := filepath.Join(dir, "bl.json")
	if code := runBaseline([]string{"add", "--baseline", blPath, dir}); code != 0 {
		t.Fatalf("add exit %d", code)
	}
	res, err := nox.RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mustLoad(t, blPath).Len(), len(res.Findings.Findings()); got != want {
		t.Errorf("entries = %d, want one per finding (%d)", got, want)
	}
}

func mustLoad(t *testing.T, path string) *baseline.Baseline {
	t.Helper()
	bl, err := baseline.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return bl
}

// --fingerprint runs no scan, so a repeat in the list is the count.
func TestBaselineAdd_FingerprintRepeatIsCount(t *testing.T) {
	tests := []struct {
		name string
		runs []string
		want int
	}{
		{"repeat adds that many", []string{"aaaa,aaaa"}, 2},
		{"idempotent", []string{"aaaa,aaaa", "aaaa,aaaa"}, 2},
		{"top up adds the difference", []string{"aaaa", "aaaa,aaaa,aaaa"}, 3},
		{"never shrinks", []string{"aaaa,aaaa", "aaaa"}, 2},
		{"single stays single", []string{"aaaa", "aaaa"}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			blPath := filepath.Join(dir, "bl.json")
			for _, list := range tc.runs {
				if code := runBaseline([]string{"add", "--baseline", blPath, "--fingerprint", list, dir}); code != 0 {
					t.Fatalf("add exit %d", code)
				}
			}
			if got := countFP(t, blPath, "aaaa"); got != tc.want {
				t.Errorf("entries = %d, want %d", got, tc.want)
			}
		})
	}
}
