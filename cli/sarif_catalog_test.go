package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nox-hq/nox/internal/testkey"
)

// results.sarif describes the rules its results point at, and only those.
//
// It used to embed the whole catalog: 1,503 descriptors, 1.97 MB, for a scan
// with six results. Code Scanning reads a descriptor only through a result, so
// the other 1,497 were bytes every upload paid for and nothing read. The MCP
// report already listed only what its results referenced; the two now agree.
func TestScanSARIFDescribesOnlyTheRulesItsResultsUse(t *testing.T) {
	dir := t.TempDir()
	content := "AWS_KEY=" + testkey.AWSAccessKeyID() + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	outDir := filepath.Join(dir, "output")
	if code := run([]string{"scan", dir, "--quiet", "--offline", "--format", "sarif", "--output", outDir}); code != 1 {
		t.Fatalf("expected exit code 1 for findings, got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "results.sarif"))
	if err != nil {
		t.Fatalf("reading results.sarif: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing SARIF: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if len(run.Results) == 0 {
		t.Fatal("the scan reported nothing; the test needs at least one result")
	}

	used := map[string]bool{}
	for _, r := range run.Results {
		used[r.RuleID] = true
	}
	described := map[string]bool{}
	var unused []string
	for _, r := range run.Tool.Driver.Rules {
		described[r.ID] = true
		if !used[r.ID] {
			unused = append(unused, r.ID)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		if len(unused) > 5 {
			unused = append(unused[:5], "…")
		}
		t.Errorf("results.sarif describes %d rules for %d results; %d no result points at, e.g. %v",
			len(run.Tool.Driver.Rules), len(run.Results), len(run.Tool.Driver.Rules)-len(used), unused)
	}
	for id := range used {
		if !described[id] {
			t.Errorf("result rule %s has no descriptor", id)
		}
	}
}
