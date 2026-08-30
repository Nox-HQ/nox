package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reach"
)

// Milestone A's invariant: evidence about an earlier proposition must never
// establish a later one.
//
// It was violated on main when this was written, and not subtly. The deps
// analyzer establishes that an advisory's affected import is in the build's
// linked package set — reach.SymbolReferenced — wrote it as
// meta["reachable"], and recordCapabilityCoverage recorded that as
// capability.Reachability. So a project declaring
// require_capabilities: [reachability] was told the question had been answered
// on the strength of a weaker one, and the same boolean set the severity.

func vulnerableModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module reachtest\n\ngo 1.21\n")
	write("main.go", "package main\n\nfunc main() {}\n")
	return dir
}

// TestLinkerEvidenceDoesNotEstablishReachability drives the coverage mapping
// directly rather than through a scan.
//
// The first version of this test scanned a fixture module and asserted that no
// finding claimed the reachability capability. It passed — and it passed with
// the defect restored, because the fixture had no dependencies, so no VULN
// finding existed and the mapping never ran. A test that cannot reach the code
// it is about is not a test. Feeding recordCapabilityCoverage a finding that
// carries a reach outcome is what makes the assertion mean something.
func TestLinkerEvidenceDoesNotEstablishReachability(t *testing.T) {
	for _, outcome := range []reach.Outcome{reach.Established, reach.Refuted, reach.Undetermined} {
		fs := findings.NewFindingSet()
		fs.Add(findings.Finding{
			RuleID: "VULN-001", Severity: findings.SeverityHigh,
			Location: findings.Location{FilePath: "go.mod", StartLine: 1},
			Message:  "vulnerable dependency",
			Metadata: map[string]string{
				"reach_level":   string(reach.SymbolReferenced),
				"reach_outcome": string(outcome),
				"reach_scope":   "go list -deps, build go build closure",
			},
		})
		cov := capability.NewCoverage(capability.DefaultRegistry())
		recordCapabilityCoverage(cov, fs)

		subject := SubjectForFinding(fs.Findings()[0])

		// The capability that must NOT be claimed. `go list -deps` is a linker
		// answer; nothing in nox builds a call graph, so call-graph
		// reachability is unevaluated for every finding and must read that way.
		switch got := cov.State(subject, capability.Reachability); got {
		case capability.Positive, capability.Negative:
			t.Errorf("outcome %q recorded reachability=%q. Evidence for "+
				"symbol_referenced is establishing a strictly later proposition, "+
				"and a project declaring require_capabilities: [reachability] would "+
				"be told the question was answered", outcome, got)
		}
		if answered, _ := cov.Answered(capability.Reachability); answered != 0 {
			t.Errorf("outcome %q leaves reachability with %d answered result(s)",
				outcome, answered)
		}

		// And the capability that SHOULD be: the level actually established.
		if got := cov.State(subject, capability.SymbolResolution); got == capability.NotEvaluated {
			t.Errorf("outcome %q recorded nothing for symbol resolution, so the level "+
				"the analysis DID establish is invisible", outcome)
		}
	}
}

// TestTheUnscopedReachableBooleanIsGone is Milestone A's acceptance criterion:
// nox cannot represent a generic reachability negative without the scope and
// assumptions under which it holds.
//
// The old representation was meta["reachable"] = "false" — a bare boolean, no
// entry-point set, no build identity, no statement of what defeated the search.
// Track G added a scoped representation beside it and left this one in place,
// and on live data the two disagreed: one finding carried reachable=true and
// applicability=undetermined at the same time.
func TestTheUnscopedReachableBooleanIsGone(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions(vulnerableModule(t), ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.Findings() {
		if f.RuleID != "VULN-001" {
			continue
		}
		if _, ok := f.Metadata["reachable"]; ok {
			t.Errorf("%s still carries an unscoped `reachable` boolean. A negative "+
				"reachability claim is universal and is only true within the scope "+
				"searched; a bare boolean cannot say which", f.Fingerprint)
		}
		if out := f.Metadata["reach_outcome"]; out != "" && f.Metadata["reach_scope"] == "" {
			t.Errorf("%s reports outcome %q with no scope", f.Fingerprint, out)
		}
	}
}
