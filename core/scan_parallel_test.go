package core

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// TestParallelVsSequentialDeterministic verifies that parallel and sequential
// analyzer execution produce identical findings (after dedup + sort).
func TestParallelVsSequentialDeterministic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Write a Go file with a hardcoded secret and a config file with IaC patterns.
	writeFile(t, filepath.Join(dir, "main.go"), `package main
const token = "AKIAIOSFODNN7EXAMPLE" // nox:test
func main() {}
`)
	writeFile(t, filepath.Join(dir, "deploy.tf"), `resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
`)

	seqResult, err := RunScanWithOptions(dir, ScanOptions{Sequential: true})
	if err != nil {
		t.Fatalf("sequential scan: %v", err)
	}

	parResult, err := RunScanWithOptions(dir, ScanOptions{Sequential: false})
	if err != nil {
		t.Fatalf("parallel scan: %v", err)
	}

	seqFindings := sortedFingerprints(seqResult.Findings)
	parFindings := sortedFingerprints(parResult.Findings)

	if len(seqFindings) != len(parFindings) {
		t.Fatalf("count mismatch: sequential=%d parallel=%d", len(seqFindings), len(parFindings))
	}

	for i := range seqFindings {
		if seqFindings[i] != parFindings[i] {
			t.Errorf("fingerprint mismatch at %d: seq=%s par=%s", i, seqFindings[i], parFindings[i])
		}
	}
}

// TestParallelScanProducesFindings verifies that parallel scan finds expected patterns.
func TestParallelScanProducesFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "secret.txt"), `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`)

	result, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings.Findings()) == 0 {
		t.Fatal("expected findings, got none")
	}
}

// TestSequentialFlagForcesSequential verifies Sequential option works.
func TestSequentialFlagForcesSequential(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), `import os
password = os.environ.get("DB_PASS")
`)

	result, err := RunScanWithOptions(dir, ScanOptions{Sequential: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Should not panic or error — basic sanity.
	_ = len(result.Findings.Findings())
}

// TestParallelScanEmptyDir verifies parallel scan on empty directory.
func TestParallelScanEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	result, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	count := len(result.Findings.Findings())
	if count != 0 {
		t.Errorf("expected 0 findings, got %d", count)
	}
}

// TestParallelScanInventoryPopulated verifies inventory is set in both modes.
func TestParallelScanInventoryPopulated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/test
go 1.21
require golang.org/x/text v0.14.0
`)

	for _, seq := range []bool{true, false} {
		result, err := RunScanWithOptions(dir, ScanOptions{Sequential: seq})
		if err != nil {
			t.Fatalf("seq=%v scan: %v", seq, err)
		}
		if result.Inventory == nil {
			t.Errorf("seq=%v: inventory is nil", seq)
		}
		if result.AIInventory == nil {
			t.Errorf("seq=%v: AI inventory is nil", seq)
		}
	}
}

// TestParallelMultipleRuns verifies determinism across multiple parallel runs.
func TestParallelMultipleRuns(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  password: "supersecret123"
`)

	var fingerprints [][]string
	for i := 0; i < 5; i++ {
		result, err := RunScanWithOptions(dir, ScanOptions{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		fingerprints = append(fingerprints, sortedFingerprints(result.Findings))
	}

	for i := 1; i < len(fingerprints); i++ {
		if len(fingerprints[0]) != len(fingerprints[i]) {
			t.Fatalf("run 0 has %d findings, run %d has %d", len(fingerprints[0]), i, len(fingerprints[i]))
		}
		for j := range fingerprints[0] {
			if fingerprints[0][j] != fingerprints[i][j] {
				t.Errorf("run 0 vs %d: fingerprint mismatch at %d", i, j)
			}
		}
	}
}

// TestParallelScanRulesSetPopulated verifies rule set is merged from all analyzers.
func TestParallelScanRulesSetPopulated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.go"), `package main`)

	result, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if result.Rules == nil {
		t.Fatal("rules is nil")
	}
	if len(result.Rules.Rules()) == 0 {
		t.Error("expected rules to be populated from analyzers")
	}
}

// TestParallelScanPolicyResult verifies policy evaluation still works.
func TestParallelScanPolicyResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "secret.txt"), `AKIAIOSFODNN7EXAMPLE`)
	writeFile(t, filepath.Join(dir, ".nox.yaml"), `policy:
  fail_on: critical
`)

	result, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if result.PolicyResult == nil {
		t.Fatal("expected policy result")
	}
}

func sortedFingerprints(fs *findings.FindingSet) []string {
	items := fs.Findings()
	fps := make([]string, len(items))
	for i := range items {
		fps[i] = items[i].Fingerprint
	}
	sort.Strings(fps)
	return fps
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
