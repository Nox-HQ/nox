package remediate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
)

// fakeRescan returns a fixed re-run and records the scopes it was asked for.
type fakeRescan struct {
	rs     Rescan
	err    error
	scopes []nox.Scope
	asked  bool
}

func (f *fakeRescan) fn() Rescanner {
	return func(_ context.Context, scopes []nox.Scope) (Rescan, error) {
		f.asked, f.scopes = true, scopes
		return f.rs, f.err
	}
}

func rescanOf(ff ...findings.Finding) Rescan {
	return Rescan{Active: ff, All: ff, Unchecked: map[nox.Scope]string{}}
}

// axiosBefore is the original scan: axios 1.7.4 with two advisories.
func axiosBefore() []findings.Finding {
	return []findings.Finding{
		dep("axios", "1.7.4", "1.18.0", "GHSA-axios-0001", "fp-a1", findings.SeverityHigh),
		dep("axios", "1.7.4", "1.20.0", "GHSA-axios-0002", "fp-a2", findings.SeverityMedium),
	}
}

func applied(plan Plan) []Attempt {
	var out []Attempt
	for _, it := range plan.Items {
		out = append(out, Attempt{N: it.N, Applied: true})
	}
	return out
}

func TestVerifyFixedOnlyWhenTheRerunDoesNotReportIt(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	rr := &fakeRescan{rs: rescanOf()}
	rep := Verify(context.Background(), plan, before, applied(plan), rr.fn())

	if got := rep.Outcomes[0].Status; got != StatusFixed {
		t.Fatalf("status = %s, want %s", got, StatusFixed)
	}
	if rep.Counts.Fixed != 1 {
		t.Fatalf("counts = %+v", rep.Counts)
	}
	if len(rr.scopes) != 1 || rr.scopes[0] != nox.ScopeDeps {
		t.Fatalf("re-ran %v, want exactly the dependency scope that produced the findings", rr.scopes)
	}
}

// The falsification: the package moved, so every fingerprint changed, but it
// moved to a release the advisories still affect. A verifier that compared
// fingerprints would call this fixed.
func TestVerifyStillPresentWhenUpgradeLandsOnAnAffectedVersion(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	still := []findings.Finding{
		dep("axios", "1.7.9", "1.18.0", "GHSA-axios-0001", "fp-NEW-a1", findings.SeverityHigh),
		dep("axios", "1.7.9", "1.20.0", "GHSA-axios-0002", "fp-NEW-a2", findings.SeverityMedium),
	}
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{rs: rescanOf(still...)}).fn())

	o := rep.Outcomes[0]
	if o.Status != StatusStillPresent {
		t.Fatalf("status = %s, want %s: %s", o.Status, StatusStillPresent, o.Detail)
	}
	if o.Remaining != 2 || !strings.Contains(o.Detail, "1.7.9") {
		t.Fatalf("detail does not say where axios landed: %+v", o)
	}
	if rep.Counts.Fixed != 0 {
		t.Fatalf("claimed a fix that did not happen: %+v", rep.Counts)
	}
}

func TestVerifyPartialFixIsStillPresent(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	left := dep("axios", "1.19.0", "1.20.0", "GHSA-axios-0002", "fp-x", findings.SeverityMedium)
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{rs: rescanOf(left)}).fn())
	o := rep.Outcomes[0]
	if o.Status != StatusStillPresent || o.Remaining != 1 || o.Targeted != 2 {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestVerifyNewFindingOnTheUpgradedPackage(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	fresh := dep("axios", "1.20.0", "1.20.1", "GHSA-axios-9999", "fp-new", findings.SeverityHigh)
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{rs: rescanOf(fresh)}).fn())
	o := rep.Outcomes[0]
	if o.Status != StatusNewFinding || len(o.New) != 1 || !strings.Contains(o.New[0], "GHSA-axios-9999") {
		t.Fatalf("outcome = %+v", o)
	}
	if len(rep.NewElsewhere) != 0 {
		t.Fatalf("a finding attached to a change was also listed as unattached: %v", rep.NewElsewhere)
	}
}

func TestVerifyNewFindingElsewhereIsReportedNotAttached(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	other := dep("lodash", "4.0.0", "4.17.21", "GHSA-lodash-1", "fp-l", findings.SeverityHigh)
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{rs: rescanOf(other)}).fn())
	if rep.Outcomes[0].Status != StatusFixed {
		t.Fatalf("axios should still be fixed: %+v", rep.Outcomes[0])
	}
	if len(rep.NewElsewhere) != 1 {
		t.Fatalf("new_elsewhere = %v", rep.NewElsewhere)
	}
}

// A check that could not run is not a pass.
func TestVerifyNotVerifiedWhenTheCheckCouldNotRun(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	rs := rescanOf()
	rs.Unchecked[nox.ScopeDeps] = "this run is offline, so known vulnerabilities cannot be looked up again"
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{rs: rs}).fn())
	o := rep.Outcomes[0]
	if o.Status != StatusNotVerified || !strings.Contains(o.Detail, "offline") {
		t.Fatalf("outcome = %+v", o)
	}
	if rep.Counts.Fixed != 0 || rep.Counts.NotVerified != 1 {
		t.Fatalf("counts = %+v", rep.Counts)
	}
}

func TestVerifyNotVerifiedWhenTheRerunFails(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{err: errors.New("disk full")}).fn())
	if o := rep.Outcomes[0]; o.Status != StatusNotVerified || !strings.Contains(o.Detail, "disk full") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestVerifyNotAppliedIsNotRescanned(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	rr := &fakeRescan{rs: rescanOf()}
	rep := Verify(context.Background(), plan, before, []Attempt{{N: 1, Error: "npm exploded"}}, rr.fn())
	if rr.asked {
		t.Fatal("re-ran checks although nothing was applied")
	}
	if o := rep.Outcomes[0]; o.Status != StatusNotApplied || !strings.Contains(o.Detail, "npm exploded") {
		t.Fatalf("outcome = %+v", o)
	}
}

// A finding that vanished because it was suppressed is hidden, not fixed.
func TestVerifySuppressedIsNotFixed(t *testing.T) {
	before := axiosBefore()
	plan := Build(Input{Findings: before})
	hidden := before[0]
	hidden.Status = findings.StatusSuppressed
	rs := Rescan{Active: nil, All: []findings.Finding{hidden}, Unchecked: map[nox.Scope]string{}}
	rep := Verify(context.Background(), plan, before, applied(plan), (&fakeRescan{rs: rs}).fn())
	if o := rep.Outcomes[0]; o.Status != StatusStillPresent || !strings.Contains(o.Detail, "suppressed") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestVerifyScopesFollowTheRulesThatProducedTheFindings(t *testing.T) {
	ff := []findings.Finding{iac("IAC-018", ".github/workflows/ci.yml", 5, "fp-coe")}
	plan := Build(Input{Findings: ff})
	rr := &fakeRescan{rs: rescanOf()}
	Verify(context.Background(), plan, ff, applied(plan), rr.fn())
	if len(rr.scopes) != 1 || rr.scopes[0] != nox.ScopeIaC {
		t.Fatalf("re-ran %v, want only infrastructure configuration", rr.scopes)
	}

	// A rule no scope owns (a custom rule) runs in every scan, so the re-run
	// must be a full one rather than a scope that never held it.
	custom := []findings.Finding{iac("ORG-001", "a.txt", 1, "fp-custom")}
	plan = Build(Input{Findings: custom})
	rr = &fakeRescan{rs: rescanOf()}
	Verify(context.Background(), plan, custom, applied(plan), rr.fn())
	if rr.scopes != nil {
		t.Fatalf("re-ran %v for a custom rule, want a full scan", rr.scopes)
	}
}

func TestVerifyReportsItemsNothingWasAttemptedFor(t *testing.T) {
	ff := append(axiosBefore(), promptInjection())
	plan := Build(Input{Findings: ff})
	var only []Attempt
	for _, it := range plan.Items {
		if it.Kind == KindUpgrade {
			only = append(only, Attempt{N: it.N, Applied: true})
		}
	}
	rep := Verify(context.Background(), plan, ff, only, (&fakeRescan{rs: rescanOf(promptInjection())}).fn())
	if len(rep.Untouched) != 1 {
		t.Fatalf("untouched = %v", rep.Untouched)
	}
}

func TestReportGolden(t *testing.T) {
	before := append(axiosBefore(),
		dep("body-parser", "1.20.3", "1.20.9", "GHSA-bp-0001", "fp-b1", findings.SeverityHigh),
		dep("qs", "6.13.0", "6.16.0", "GHSA-qs-0001", "fp-q1", findings.SeverityMedium),
		dep("pg", "8.0.0", "8.0.1", "GHSA-pg-0001", "fp-p1", findings.SeverityLow),
		dep("jsonwebtoken", "9.0.0", "9.0.2", "GHSA-jwt-0001", "fp-j1", findings.SeverityHigh),
		promptInjection())
	plan := Build(Input{Findings: before})

	still := dep("qs", "6.14.0", "6.16.0", "GHSA-qs-0001", "fp-NEW-q", findings.SeverityMedium)
	fresh := dep("jsonwebtoken", "9.0.2", "9.0.3", "GHSA-jwt-NEW", "fp-jn", findings.SeverityMedium)
	rs := rescanOf(still, fresh)
	var attempts []Attempt
	for _, it := range plan.Items {
		switch {
		case it.Kind == KindCode:
		case it.Upgrade != nil && it.Upgrade.Package == "body-parser":
			attempts = append(attempts, Attempt{N: it.N, Error: "body-parser is transitive and a parent's version range excludes the fix"})
		default:
			attempts = append(attempts, Attempt{N: it.N, Applied: true})
		}
	}
	rep := Verify(context.Background(), plan, before, attempts, (&fakeRescan{rs: rs}).fn())

	var buf bytes.Buffer
	if err := RenderReport(&buf, rep); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.golden", buf.String())

	buf.Reset()
	if err := WriteReportJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.json.golden", buf.String())
}

func TestReportSummaryNeverOverclaims(t *testing.T) {
	r := Report{Outcomes: make([]Outcome, 3), Counts: Counts{Fixed: 1, NotVerified: 2}}
	s := r.Summary()
	if !strings.Contains(s, "1 of 3") || !strings.Contains(s, "2 could not be checked") {
		t.Fatalf("summary = %q", s)
	}
}
