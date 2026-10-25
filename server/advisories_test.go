package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/advisory"
	"github.com/nox-hq/nox/core/report"
)

// advisoryScan is depScanResult with the advisory identity a real lookup records.
func advisoryScan() *nox.ScanResult {
	res := depScanResult("golang.org/x/crypto", "0.51.0", "0.54.0")
	items := res.Findings.Findings()
	for i := range items {
		res.Findings.SetMetadata(i, "vuln_id", "GHSA-test-0001")
	}
	return res
}

func callAdvisories(t *testing.T, s *Server, in advisoriesInput) (advisoriesOutput, bool) {
	t.Helper()
	out, err := s.handleAdvisories(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.IsError {
		return advisoriesOutput{}, false
	}
	var resp advisoriesOutput
	if err := json.Unmarshal([]byte(textOf(out)), &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, textOf(out))
	}
	return resp, true
}

func writePrevious(t *testing.T, dir string) string {
	t.Helper()
	data, err := json.Marshal(report.JSONReport{})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "previous.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The tool serves what `nox advisories` computes: its decision, headline and
// text are the shared core's, not a second implementation.
func TestAdvisoriesToolServesTheSharedDecision(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", nil)
	res := advisoryScan()
	s.setCache(dir, res)
	s.lastPath = dir

	// No previous run: nothing is new, nothing is acted on, and it says so.
	resp, ok := callAdvisories(t, s, advisoriesInput{})
	if !ok {
		t.Fatal("advisories failed")
	}
	if resp.Decision.PreviousRun || resp.Decision.Action != advisory.ActionReport || resp.Decision.Decisions[0].Novelty != advisory.NoveltyUnestablished {
		t.Errorf("without a previous run nothing may be acted on: %+v", resp.Decision)
	}

	// With an empty previous run the advisory is new, and the answer is exactly
	// the core's for the same inputs.
	prev := writePrevious(t, dir)
	s2 := New("0.1.0", []string{dir})
	s2.setCache(dir, res)
	s2.lastPath = dir
	resp, ok = callAdvisories(t, s2, advisoriesInput{Previous: prev, Policy: "prepare"})
	if !ok {
		t.Fatal("advisories failed with a previous run")
	}
	pol, err := advisory.Settings{Policy: "prepare"}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	want := advisory.Evaluate(advisory.Input{Findings: res.Findings.Findings(), Policy: pol, HavePrevious: true})
	if resp.Summary != advisory.Headline(want) || resp.Text != advisory.Text(want) {
		t.Errorf("MCP text differs from the CLI's rendering:\n%s\n---\n%s", resp.Text, advisory.Text(want))
	}
	if len(resp.Decision.Decisions) != 1 || resp.Decision.Decisions[0].Novelty != advisory.NoveltyNew {
		t.Errorf("the advisory is absent from the previous run, so it is new: %+v", resp.Decision.Decisions)
	}
	if resp.Decision.Action != advisory.ActionPrepare {
		t.Errorf("policy prepare must prepare a new advisory: %+v", resp.Decision)
	}
}

// A scan that could not finish looking is not a clean result and acts on
// nothing, over MCP as over the CLI.
func TestAdvisoriesToolIsNotCleanWhenTheScanWasIncomplete(t *testing.T) {
	dir := t.TempDir()
	s := New("0.1.0", []string{dir})
	res := advisoryScan()
	res.Degradations = []degrade.Degradation{{Kind: "osv", Detail: "lookup failed", Impact: "advisories may be missing"}}
	s.setCache(dir, res)
	s.lastPath = dir

	resp, ok := callAdvisories(t, s, advisoriesInput{Previous: writePrevious(t, dir), Policy: "remediate"})
	if !ok {
		t.Fatal("advisories failed")
	}
	if resp.Decision.Incomplete == "" || resp.Decision.Action != advisory.ActionReport || resp.Decision.AutoMerge {
		t.Errorf("an incomplete scan must act on nothing: %+v", resp.Decision)
	}
}

func TestAdvisoriesToolRefusesAPathOutsideTheWorkspace(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	s := New("0.1.0", []string{dir})
	s.setCache(dir, depScanResult("golang.org/x/crypto", "0.51.0", "0.54.0"))
	s.lastPath = dir
	if _, ok := callAdvisories(t, s, advisoriesInput{Previous: writePrevious(t, other)}); ok {
		t.Error("a previous run outside the allowed workspace must be refused")
	}
}

func TestAdvisoriesToolNeedsAScan(t *testing.T) {
	if _, ok := callAdvisories(t, New("0.1.0", nil), advisoriesInput{}); ok {
		t.Error("expected an error before any scan")
	}
}
