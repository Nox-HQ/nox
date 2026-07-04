package main

import (
	"os"
	"path/filepath"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

func TestRunBaseline_NoArgs(t *testing.T) {
	code := runBaseline([]string{})
	if code != 2 {
		t.Fatalf("expected exit code 2 for no args, got %d", code)
	}
}

func TestRunBaseline_UnknownSubcommand(t *testing.T) {
	code := runBaseline([]string{"invalid"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown subcommand, got %d", code)
	}
}

func TestRunBaseline_Init(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	blPath := filepath.Join(dir, "bl.json")

	if code := runBaseline([]string{"init", "--output", blPath, dir}); code != 0 {
		t.Fatalf("init exit code = %d, want 0", code)
	}
	bl, err := baseline.Load(blPath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() == 0 {
		t.Fatal("expected init to record findings as baseline debt")
	}

	// A second init must refuse rather than clobber an existing baseline.
	if code := runBaseline([]string{"init", "--output", blPath, dir}); code == 0 {
		t.Error("second init should refuse when a baseline already exists")
	}
	// --force recreates it.
	if code := runBaseline([]string{"init", "--force", "--output", blPath, dir}); code != 0 {
		t.Errorf("init --force exit code = %d, want 0", code)
	}
}

func TestRunBaseline_Write(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a secret to get findings.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	baselinePath := filepath.Join(dir, "test-baseline.json")
	code := runBaseline([]string{"write", "--output", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify baseline file exists.
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		t.Fatal("expected baseline file to be created")
	}

	// Verify baseline can be loaded and has entries.
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() == 0 {
		t.Fatal("expected baseline to have entries")
	}
}

func TestRunBaseline_WriteDefaultPath(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a finding.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"write", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify default baseline path exists.
	defaultPath := baseline.DefaultPath(dir)
	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		t.Fatal("expected baseline file at default path")
	}
}

func TestRunBaseline_WriteCleanDir(t *testing.T) {
	dir := t.TempDir()

	// Create a clean file with no findings.
	clean := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	baselinePath := filepath.Join(dir, "baseline.json")
	code := runBaseline([]string{"write", "--output", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Baseline should exist but be empty.
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() != 0 {
		t.Fatalf("expected empty baseline, got %d entries", bl.Len())
	}
}

func TestRunBaseline_WriteScanError(t *testing.T) {
	code := runBaseline([]string{"write", "/nonexistent/path/xyz123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan error, got %d", code)
	}
}

func TestRunBaseline_Update(t *testing.T) {
	dir := t.TempDir()

	// Create initial finding.
	secret1 := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config1.env"), []byte(secret1), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Write initial baseline.
	baselinePath := filepath.Join(dir, "baseline.json")
	code := runBaseline([]string{"write", "--output", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for write, got %d", code)
	}

	initialBL, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading initial baseline: %v", err)
	}
	initialCount := initialBL.Len()

	// Add a new finding with different content to get a different fingerprint.
	secret2 := "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
	if err := os.WriteFile(filepath.Join(dir, "config2.env"), []byte(secret2), 0o644); err != nil {
		t.Fatalf("writing second test file: %v", err)
	}

	// Update baseline.
	code = runBaseline([]string{"update", "--baseline", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for update, got %d", code)
	}

	// Verify baseline has more entries.
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if bl.Len() <= initialCount {
		t.Fatalf("expected baseline to have more than %d entries, got %d", initialCount, bl.Len())
	}
}

func TestRunBaseline_UpdateDefaultPath(t *testing.T) {
	dir := t.TempDir()

	// Create initial baseline.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"write", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for write, got %d", code)
	}

	// Update using default path.
	code = runBaseline([]string{"update", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for update, got %d", code)
	}
}

func TestRunBaseline_UpdateScanError(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")

	// Create a baseline.
	bl := &baseline.Baseline{}
	if err := bl.Save(baselinePath); err != nil {
		t.Fatalf("saving baseline: %v", err)
	}

	// Try to update with nonexistent path.
	code := runBaseline([]string{"update", "--baseline", baselinePath, "/nonexistent/path/xyz123"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for scan error, got %d", code)
	}
}

func TestRunBaseline_UpdateLoadError(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "invalid.json")

	// Write invalid JSON to baseline file.
	if err := os.WriteFile(baselinePath, []byte("invalid json{"), 0o644); err != nil {
		t.Fatalf("writing invalid baseline: %v", err)
	}

	code := runBaseline([]string{"update", "--baseline", baselinePath, dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for load error, got %d", code)
	}
}

func TestRunBaseline_Show(t *testing.T) {
	dir := t.TempDir()

	// Create findings and baseline.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"write", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for write, got %d", code)
	}

	// Show baseline.
	code = runBaseline([]string{"show", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for show, got %d", code)
	}
}

func TestRunBaseline_ShowEmpty(t *testing.T) {
	dir := t.TempDir()

	// Create empty baseline.
	bl := &baseline.Baseline{}
	if err := bl.Save(baseline.DefaultPath(dir)); err != nil {
		t.Fatalf("saving baseline: %v", err)
	}

	code := runBaseline([]string{"show", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for empty baseline, got %d", code)
	}
}

func TestRunBaseline_ShowLoadError(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON to baseline file.
	baselinePath := baseline.DefaultPath(dir)
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		t.Fatalf("creating .nox dir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("invalid json{"), 0o644); err != nil {
		t.Fatalf("writing invalid baseline: %v", err)
	}

	code := runBaseline([]string{"show", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for load error, got %d", code)
	}
}

// TestRunBaselineAdd_PreservesEntries — the additive command must not
// prune anything. Pre-existing baseline entries that no longer match a
// scan must still be in the file after add runs.
func TestRunBaselineAdd_PreservesEntries(t *testing.T) {
	dir := t.TempDir()

	// Seed a baseline with a stale entry that won't match any scan.
	baselinePath := filepath.Join(dir, "baseline.json")
	bl := &baseline.Baseline{}
	bl.Add(&baseline.Entry{
		Fingerprint: "deadbeef1234567890abcdef0123456789abcdef0123456789abcdef01234567",
		RuleID:      "SEC-999",
		FilePath:    "obsolete.go",
		Reason:      "kept for posterity",
	})
	if err := bl.Save(baselinePath); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}

	// Add a real finding so the scan turns something up.
	secret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(secret), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	code := runBaseline([]string{"add", "--baseline", baselinePath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	got, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	// Original stale entry must still be present.
	var foundStale bool
	for i := range got.Entries {
		if got.Entries[i].Fingerprint == "deadbeef1234567890abcdef0123456789abcdef0123456789abcdef01234567" {
			foundStale = true
			break
		}
	}
	if !foundStale {
		t.Error("baseline add pruned the stale entry; it should be additive only")
	}
	// And at least one new entry should have been added from the scan.
	if got.Len() < 2 {
		t.Errorf("expected baseline to grow; got %d entries (started with 1)", got.Len())
	}
}

// TestRunBaselineAdd_FingerprintFilter — when --fingerprint is set,
// no scan runs; only the supplied fingerprints get inserted.
func TestRunBaselineAdd_FingerprintFilter(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")

	code := runBaseline([]string{
		"add",
		"--baseline", baselinePath,
		"--fingerprint", "aaaa1111,bbbb2222",
		"--reason", "documented false positive",
		"--owner", "platform",
		dir,
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	got, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if got.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", got.Len())
	}
	for i := range got.Entries {
		if got.Entries[i].Reason != "documented false positive" {
			t.Errorf("entry %d missing reason", i)
		}
		if got.Entries[i].Owner != "platform" {
			t.Errorf("entry %d missing owner", i)
		}
	}
}

// TestRunBaselineAdd_FingerprintIdempotent — re-adding the same
// fingerprint must not duplicate it.
func TestRunBaselineAdd_FingerprintIdempotent(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")

	for i := 0; i < 3; i++ {
		code := runBaseline([]string{
			"add", "--baseline", baselinePath, "--fingerprint", "abcdef12", dir,
		})
		if code != 0 {
			t.Fatalf("run %d: exit %d", i, code)
		}
	}
	got, _ := baseline.Load(baselinePath)
	if got.Len() != 1 {
		t.Errorf("expected 1 entry after 3 idempotent adds, got %d", got.Len())
	}
}

// TestRunBaselineDiff_ReportsAddsAndPrunes — the read-only diff lists
// what update would change without writing the file.
func TestRunBaselineDiff_ReportsAddsAndPrunes(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")

	// Pre-seed a stale entry.
	bl := &baseline.Baseline{}
	bl.Add(&baseline.Entry{
		Fingerprint: "deadbeef0000000000000000000000000000000000000000000000000000beef",
		RuleID:      "SEC-999",
		FilePath:    "gone.go",
	})
	if err := bl.Save(baselinePath); err != nil {
		t.Fatal(err)
	}

	// Add a fresh finding so the scan turns something up.
	if err := os.WriteFile(filepath.Join(dir, "config.env"),
		[]byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code := runBaseline([]string{"diff", "--baseline", baselinePath, dir})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	// File must NOT have changed (diff is read-only).
	got, _ := baseline.Load(baselinePath)
	if got.Len() != 1 {
		t.Errorf("baseline mutated by `diff`; expected 1 entry, got %d", got.Len())
	}
}

func TestRunBaseline_Migrate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.env"),
		[]byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	blPath := filepath.Join(dir, "bl.json")

	// Write a baseline at V1, then restore the process default.
	prev := findings.GetFingerprintVersion()
	findings.SetFingerprintVersion(findings.FingerprintV1)
	if code := runBaseline([]string{"write", "--output", blPath, dir}); code != 0 {
		findings.SetFingerprintVersion(prev)
		t.Fatalf("baseline write (v1) exit %d", code)
	}
	findings.SetFingerprintVersion(prev)

	before, err := baseline.Load(blPath)
	if err != nil || before.Len() == 0 {
		t.Fatalf("loading v1 baseline: %v (len=%d)", err, before.Len())
	}
	v1fps := map[string]bool{}
	for _, e := range before.Entries {
		v1fps[e.Fingerprint] = true
		if e.CreatedAt.IsZero() {
			t.Fatal("expected created_at to be set on v1 entry")
		}
	}

	// Migrate v1 -> v2.
	if code := runBaseline([]string{"migrate", "--baseline", blPath, dir}); code != 0 {
		t.Fatalf("baseline migrate exit %d", code)
	}

	after, err := baseline.Load(blPath)
	if err != nil {
		t.Fatalf("loading migrated baseline: %v", err)
	}
	if after.Len() != before.Len() {
		t.Fatalf("entry count changed: %d -> %d", before.Len(), after.Len())
	}
	for _, e := range after.Entries {
		if v1fps[e.Fingerprint] {
			t.Errorf("fingerprint %s was not re-computed (still v1)", e.Fingerprint[:12])
		}
		if e.CreatedAt.IsZero() {
			t.Error("migrate dropped created_at metadata")
		}
	}

	// The migrated fingerprints must match a fresh v2 scan exactly, so the
	// baseline actually suppresses those findings under the v2 default.
	result, err := nox.RunScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	v2fps := map[string]bool{}
	for _, f := range result.Findings.Findings() {
		v2fps[f.Fingerprint] = true
	}
	for _, e := range after.Entries {
		if !v2fps[e.Fingerprint] {
			t.Errorf("migrated fingerprint %s does not match any v2 scan finding", e.Fingerprint[:12])
		}
	}
}
