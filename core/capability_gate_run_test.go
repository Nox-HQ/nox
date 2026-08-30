package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Track H, Gate C: local adjudication stays sovereign. If the intelligence
// service disappears, nox still scans, still reasons, and reports the missing
// capability rather than passing a gate it has not satisfied.
//
// The first two hold that from both sides. Only the pair is worth anything:
// a gate that fails when the analysis did not run is easy, and so is a gate
// that fails always.

func writeGateProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestAnUnexercisedCapabilityDoesNotSatisfyItsRequirement is the regression
// test for a measured false all-clear.
//
// A Go module whose advisory source is unreachable produces no findings and
// records a degradation saying, in plain words, that it "cannot confirm the
// absence of known CVEs". Under uncertainty=fail with
// require_capabilities: [reachability] — the strictest configuration this gate
// offers — it used to return pass=true, exit 0, no warnings.
//
// Nothing was lying. `reachability` genuinely is provided: core/analyzers/deps
// is compiled into every build. The gate asked whether the installation COULD
// establish reachability, which is a fact about the binary, and reported it as
// though it answered whether reachability HAD been established for this code.
// Those coincide right up until something fails at runtime, which is the only
// moment the gate exists for.
func TestAnUnexercisedCapabilityDoesNotSatisfyItsRequirement(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	dir := writeGateProject(t, map[string]string{
		"go.mod": "module probe\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2\n",
		"go.sum": "",
		// Port 1 is reliably refused and never routed, so this test does not
		// depend on the network being down — only on nothing listening there.
		".nox.yaml": "scan:\n  intelligence:\n    endpoint: http://127.0.0.1:1\n" +
			"    verify_against_osv: false\n" +
			"policy:\n  uncertainty: fail\n  require_capabilities: [reachability]\n",
	})

	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("the scan itself failed; sovereignty means nox still scans: %v", err)
	}
	if len(res.Degradations) == 0 {
		t.Fatal("an unreachable advisory source produced no degradation; the fixture " +
			"is not reproducing the condition this test is about")
	}
	if res.PolicyResult == nil {
		t.Fatal("a declared capability requirement produced no policy result")
	}
	if res.PolicyResult.Pass {
		t.Error("a scan that established nothing about reachability satisfied a " +
			"requirement for reachability. The degradation says this scan cannot " +
			"confirm the absence of known CVEs; the gate said pass")
	}
	if res.PolicyResult.ExitCode == 0 {
		t.Error("uncertainty=fail returned exit 0 on an unmet requirement")
	}
	joined := strings.Join(res.PolicyResult.Warnings, " ")
	if !strings.Contains(joined, "reachability") {
		t.Errorf("the warning does not name the capability: %q", joined)
	}
	// The three outcomes need different actions from the reader, so they must
	// not collapse into one sentence. This one is provided-but-unexercised;
	// telling the operator it is "not provided by this installation" would send
	// them to install a plugin they already have.
	if strings.Contains(joined, "not provided by this installation") {
		t.Errorf("a provided-but-unexercised capability was reported as missing from "+
			"the installation: %q", joined)
	}
}

// TestAnAnsweredCapabilitySatisfiesItsRequirement is the other half, and the
// reason the first test proves anything.
//
// A gate that fails whenever an analysis did not run is trivial to write and
// indistinguishable, from the first test alone, from a gate that fails always.
// This scans the committed corpus offline with a requirement the scan really
// does exercise — every finding in a lexable file records lexical context —
// and asserts the build stays green.
func TestAnAnsweredCapabilitySatisfiesItsRequirement(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	dir := writeGateProject(t, map[string]string{
		"app/creds.py": "GITHUB_TOKEN = \"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\"\n",
		// fail_on: critical so the severity gate stays out of the way. The
		// fixture's finding is high, and a build failing on severity would make
		// this test pass or fail for a reason that is not the capability gate.
		".nox.yaml": "policy:\n  fail_on: critical\n  uncertainty: fail\n" +
			"  require_capabilities: [lexical_context]\n",
	})

	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings.Findings()) == 0 {
		t.Fatal("the fixture produced no findings, so nothing exercised any " +
			"capability and this test would pass for the wrong reason")
	}
	if answered, _ := res.Coverage.Answered("lexical_context"); answered == 0 {
		t.Fatal("lexical context concluded about nothing; the fixture is wrong")
	}
	if res.PolicyResult == nil {
		t.Fatal("a declared capability requirement produced no policy result")
	}
	if !res.PolicyResult.Pass {
		t.Errorf("a capability this scan actually exercised failed its own requirement: %v",
			res.PolicyResult.Warnings)
	}
	if len(res.PolicyResult.Warnings) != 0 {
		t.Errorf("a met requirement still warned: %v", res.PolicyResult.Warnings)
	}
}

// TestScanAlwaysSuppliesARunView. EvaluateCapabilities falls back to the
// installation answer when it is handed no run view, and that fallback is
// permissive — it is the behaviour this track was written to replace.
//
// It is kept for callers outside the scan pipeline that genuinely have no
// coverage to offer. What must never happen is the scan itself taking it,
// because that would restore the old outcome silently and every test above
// would still pass: they assert on the result, and the permissive path
// produces a plausible one.
func TestScanAlwaysSuppliesARunView(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	dir := writeGateProject(t, map[string]string{
		"app/creds.py": "GITHUB_TOKEN = \"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\"\n",
		".nox.yaml": "policy:\n  fail_on: critical\n  uncertainty: fail\n" +
			"  require_capabilities: [call_graph]\n",
	})
	res, err := RunScanWithOptions(dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Coverage == nil {
		t.Fatal("the scan produced no coverage, so the policy gate fell back to the " +
			"installation-only answer that Track H replaced")
	}
	// call_graph has no implementation at all, so this is the unsupported
	// branch — the one case where the installation answer is the whole story.
	if res.PolicyResult == nil || res.PolicyResult.Pass {
		t.Error("a capability nothing implements satisfied a requirement for it")
	}
	if !strings.Contains(strings.Join(res.PolicyResult.Warnings, " "),
		"not provided by this installation") {
		t.Errorf("an unimplemented capability was not reported as unprovided: %v",
			res.PolicyResult.Warnings)
	}
}
