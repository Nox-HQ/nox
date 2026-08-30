package deps

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// expectation is one case's declared ground truth: what the advisory scopes to,
// what reachability should conclude, and — the field the gate turns on —
// whether that conclusion may justify hiding a finding.
type expectation struct {
	AdvisoryImports []string `json:"advisory_imports"`
	WantReachable   bool     `json:"want_reachable"`
	WantDetermined  bool     `json:"want_determined"`
	WantState       string   `json:"want_state"`
	MaySuppress     bool     `json:"may_suppress"`
	Why             string   `json:"why"`
}

// suiteDir resolves testdata/reachability-suite from this package.
func suiteDir() string {
	return filepath.Join("..", "..", "..", "testdata", "reachability-suite")
}

// loadCases reads every case in the suite.
func loadCases(t *testing.T) map[string]expectation {
	t.Helper()
	entries, err := os.ReadDir(suiteDir())
	if err != nil {
		t.Fatalf("reading suite: %v", err)
	}
	out := make(map[string]expectation)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(suiteDir(), e.Name(), "expect.json"))
		if err != nil {
			t.Fatalf("%s: reading expect.json: %v", e.Name(), err)
		}
		var exp expectation
		if err := json.Unmarshal(raw, &exp); err != nil {
			t.Fatalf("%s: parsing expect.json: %v", e.Name(), err)
		}
		if exp.Why == "" {
			t.Errorf("%s: expect.json has no `why`; a ground truth nobody explained "+
				"is one nobody can check", e.Name())
		}
		out[e.Name()] = exp
	}
	if len(out) == 0 {
		t.Fatal("the suite has no cases")
	}
	return out
}

// TestReachabilitySuiteMatchesGroundTruth scores the corpus.
//
// It measures the (reachable, determined) PAIR rather than a boolean, because
// the pair is the entire point: a scanner that collapses it reports "not
// reachable" for code it never managed to look at.
//
// The suite is deterministic and offline by construction. Every module depends
// only on the standard library — Go issues advisories for stdlib packages, so
// this is not a contrivance — which means `go list` needs no network and no
// module cache. A corpus that needed either would be a corpus that quietly
// stopped running, and the first thing anyone would notice is that it had
// stopped failing.
func TestReachabilitySuiteMatchesGroundTruth(t *testing.T) {
	for name, exp := range loadCases(t) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(suiteDir(), name)
			linked, linkedKnown := goImportedPackages(context.Background(), dir)
			reachable, determined := goVulnReachable(exp.AdvisoryImports, linked, linkedKnown)

			if determined != exp.WantDetermined {
				t.Errorf("determined = %v, want %v — %s", determined, exp.WantDetermined, exp.Why)
			}
			if reachable != exp.WantReachable {
				t.Errorf("reachable = %v, want %v — %s", reachable, exp.WantReachable, exp.Why)
			}
		})
	}
}

// TestGateB is the gate.
//
// Deterministic unreachability may suppress a finding. Nothing else may — not
// an advisory without import metadata, not a toolchain that failed, not an
// ecosystem nox cannot analyse. All four look identical downstream: no
// reachability annotation, and so no reason shown for a finding to be absent.
// The difference between them exists only if something checks it.
//
// Deliberately expressed as "which cases could justify suppression", not "which
// cases return false". A future refactor returning false for an undetermined
// case would pass a test written the second way, and would be the exact failure
// this gate exists to stop: nox reporting its own blind spot as an all-clear.
func TestGateB(t *testing.T) {
	var suppressible []string
	for name, exp := range loadCases(t) {
		dir := filepath.Join(suiteDir(), name)
		linked, linkedKnown := goImportedPackages(context.Background(), dir)
		reachable, determined := goVulnReachable(exp.AdvisoryImports, linked, linkedKnown)

		// The only honest basis for hiding a finding: the analysis ran, and it
		// established the affected code is not reached.
		couldSuppress := determined && !reachable

		if couldSuppress != exp.MaySuppress {
			t.Errorf("%s: couldSuppress = %v, want %v — %s",
				name, couldSuppress, exp.MaySuppress, exp.Why)
		}
		if couldSuppress {
			suppressible = append(suppressible, name)
		}
	}

	if len(suppressible) != 1 || suppressible[0] != "unreachable" {
		t.Errorf("cases that could justify suppression = %v, want exactly [unreachable]. "+
			"Every other case in this suite is an absence of knowledge, and an absence "+
			"of knowledge that can hide a finding is how a scanner reports a blind spot "+
			"as an all-clear.", suppressible)
	}
}

// TestUndeterminedNeverAnswersFalse pins the contract at its source.
//
// goVulnReachable answers false ONLY on positive evidence. Anything less
// returns (true, false): reachable-by-default, undetermined. The default
// direction is the safety property — an undetermined case defaulting to "not
// reachable" would suppress findings nobody examined, silently.
func TestUndeterminedNeverAnswersFalse(t *testing.T) {
	linked := map[string]struct{}{"crypto/sha256": {}}

	for _, tc := range []struct {
		name        string
		imports     []string
		linked      map[string]struct{}
		linkedKnown bool
	}{
		{"no advisory imports", nil, linked, true},
		{"empty advisory imports", []string{}, linked, true},
		{"linked set unknown", []string{"crypto/md5"}, nil, false},
		{"linked set unknown despite entries", []string{"crypto/md5"}, linked, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reachable, determined := goVulnReachable(tc.imports, tc.linked, tc.linkedKnown)
			if determined {
				t.Error("determined = true with nothing to determine it from")
			}
			if !reachable {
				t.Error("reachable = false on an UNDETERMINED result; a finding nobody " +
					"examined would be suppressed as though it had been cleared")
			}
		})
	}
}

// TestSubpackagesOfAnAffectedImportAreReachable. An advisory scoping to
// golang.org/x/crypto/openpgp covers its subpackages, and missing that would
// report a reachable vulnerability as unreachable — a false negative produced
// by the very mechanism meant to reduce false positives.
func TestSubpackagesOfAnAffectedImportAreReachable(t *testing.T) {
	linked := map[string]struct{}{"golang.org/x/crypto/openpgp/packet": {}}
	reachable, determined := goVulnReachable([]string{"golang.org/x/crypto/openpgp"}, linked, true)
	if !determined || !reachable {
		t.Errorf("subpackage of an affected import: reachable=%v determined=%v, want both true",
			reachable, determined)
	}

	// A package that merely shares a prefix is not a subpackage.
	other := map[string]struct{}{"golang.org/x/crypto/openpgpx": {}}
	reachable, determined = goVulnReachable([]string{"golang.org/x/crypto/openpgp"}, other, true)
	if !determined || reachable {
		t.Errorf("prefix-sharing package treated as affected: reachable=%v determined=%v, "+
			"want reachable=false determined=true", reachable, determined)
	}
}
