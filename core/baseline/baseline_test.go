package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

func TestLoadSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	bl := &Baseline{}
	now := time.Now().UTC()
	bl.Add(&Entry{
		Fingerprint: "abc123",
		RuleID:      "SEC-001",
		FilePath:    "config.env",
		Severity:    findings.SeverityHigh,
		CreatedAt:   now,
	})

	if err := bl.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", loaded.Len())
	}
	if loaded.Entries[0].Fingerprint != "abc123" {
		t.Fatalf("expected fingerprint abc123, got %s", loaded.Entries[0].Fingerprint)
	}
	if loaded.Entries[0].RuleID != "SEC-001" {
		t.Fatalf("expected RuleID SEC-001, got %s", loaded.Entries[0].RuleID)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	bl, err := Load("/nonexistent/baseline.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if bl.Len() != 0 {
		t.Fatalf("expected empty baseline, got %d entries", bl.Len())
	}
}

func TestMatch_Found(t *testing.T) {
	bl := &Baseline{}
	bl.Add(&Entry{
		Fingerprint: "fp1",
		RuleID:      "SEC-001",
		CreatedAt:   time.Now(),
	})

	f := findings.Finding{Fingerprint: "fp1"}
	if bl.Match(&f) == nil {
		t.Fatal("expected match, got nil")
	}
}

func TestMatch_NotFound(t *testing.T) {
	bl := &Baseline{}
	bl.Add(&Entry{
		Fingerprint: "fp1",
		RuleID:      "SEC-001",
		CreatedAt:   time.Now(),
	})

	f := findings.Finding{Fingerprint: "fp2"}
	if bl.Match(&f) != nil {
		t.Fatal("expected no match")
	}
}

func TestMatch_Expired(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	bl := &Baseline{}
	bl.Add(&Entry{
		Fingerprint: "fp1",
		RuleID:      "SEC-001",
		CreatedAt:   time.Now().Add(-48 * time.Hour),
		ExpiresAt:   &past,
	})

	f := findings.Finding{Fingerprint: "fp1"}
	if bl.Match(&f) != nil {
		t.Fatal("expected expired entry to not match")
	}
}

func TestPrune(t *testing.T) {
	bl := &Baseline{}
	bl.Add(&Entry{Fingerprint: "fp1", RuleID: "SEC-001", CreatedAt: time.Now()})
	bl.Add(&Entry{Fingerprint: "fp2", RuleID: "SEC-002", CreatedAt: time.Now()})
	bl.Add(&Entry{Fingerprint: "fp3", RuleID: "SEC-003", CreatedAt: time.Now()})

	current := []findings.Finding{
		{Fingerprint: "fp1"},
		{Fingerprint: "fp3"},
	}

	removed := bl.Prune(current)
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
	if bl.Len() != 2 {
		t.Fatalf("expected 2 remaining, got %d", bl.Len())
	}
}

func TestSave_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "baseline.json")

	bl := &Baseline{}
	bl.Add(&Entry{Fingerprint: "fp1", RuleID: "SEC-001", CreatedAt: time.Now()})

	if err := bl.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// File should exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	got := DefaultPath("/project")
	want := filepath.FromSlash("/project/.nox/baseline.json")
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestFromFindings(t *testing.T) {
	ff := []findings.Finding{
		{Fingerprint: "fp1", RuleID: "SEC-001", Severity: findings.SeverityHigh, Location: findings.Location{FilePath: "a.go"}},
		{Fingerprint: "fp2", RuleID: "SEC-002", Severity: findings.SeverityLow, Location: findings.Location{FilePath: "b.go"}},
	}

	entries := FromFindings(ff)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Fingerprint != "fp1" {
		t.Fatal("wrong fingerprint")
	}
	if entries[1].Severity != findings.SeverityLow {
		t.Fatal("wrong severity")
	}
}

func TestExpiredCount(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	bl := &Baseline{}
	bl.Add(&Entry{Fingerprint: "fp1", CreatedAt: time.Now(), ExpiresAt: &past})
	bl.Add(&Entry{Fingerprint: "fp2", CreatedAt: time.Now(), ExpiresAt: &future})
	bl.Add(&Entry{Fingerprint: "fp3", CreatedAt: time.Now()}) // no expiration

	if bl.ExpiredCount() != 1 {
		t.Fatalf("expected 1 expired, got %d", bl.ExpiredCount())
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := os.WriteFile(path, []byte("{invalid json!!!}"), 0o644); err != nil {
		t.Fatalf("writing invalid baseline: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoad_ReadError(t *testing.T) {
	// Create a directory where a file is expected — os.ReadFile will fail.
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when path is a directory, got nil")
	}
}

func TestSave_MkdirAllFails(t *testing.T) {
	// Create a read-only file where a directory is expected.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o444); err != nil {
		t.Fatalf("writing blocker: %v", err)
	}

	bl := &Baseline{}
	bl.Add(&Entry{Fingerprint: "fp1", RuleID: "SEC-001", CreatedAt: time.Now()})

	// Try to save inside the file (MkdirAll will fail because blocker is a file, not a dir).
	err := bl.Save(filepath.Join(blocker, "sub", "baseline.json"))
	if err == nil {
		t.Fatal("expected error when MkdirAll fails, got nil")
	}
}

func TestSave_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	bl1 := &Baseline{}
	bl1.Add(&Entry{Fingerprint: "fp1", RuleID: "SEC-001", CreatedAt: time.Now()})
	if err := bl1.Save(path); err != nil {
		t.Fatalf("first save: %v", err)
	}

	bl2 := &Baseline{}
	bl2.Add(&Entry{Fingerprint: "fp2", RuleID: "SEC-002", CreatedAt: time.Now()})
	bl2.Add(&Entry{Fingerprint: "fp3", RuleID: "SEC-003", CreatedAt: time.Now()})
	if err := bl2.Save(path); err != nil {
		t.Fatalf("second save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("expected 2 entries after overwrite, got %d", loaded.Len())
	}
}

func TestAdd_NilIndex(t *testing.T) {
	// Verify Add initializes the index when nil.
	bl := &Baseline{} // index is nil
	bl.Add(&Entry{Fingerprint: "fp1", RuleID: "SEC-001", CreatedAt: time.Now()})

	f := findings.Finding{Fingerprint: "fp1"}
	if bl.Match(&f) == nil {
		t.Fatal("expected match after Add with nil initial index")
	}
}

func TestBuildIndex_RebuildsCorrectly(t *testing.T) {
	bl := &Baseline{}
	bl.Add(&Entry{Fingerprint: "fp1", RuleID: "SEC-001", CreatedAt: time.Now()})
	bl.Add(&Entry{Fingerprint: "fp2", RuleID: "SEC-002", CreatedAt: time.Now()})

	// Force rebuild.
	bl.buildIndex()

	f1 := findings.Finding{Fingerprint: "fp1"}
	f2 := findings.Finding{Fingerprint: "fp2"}
	if bl.Match(&f1) == nil {
		t.Fatal("expected match for fp1 after rebuild")
	}
	if bl.Match(&f2) == nil {
		t.Fatal("expected match for fp2 after rebuild")
	}
}
