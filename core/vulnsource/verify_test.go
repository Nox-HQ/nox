package vulnsource

import (
	"context"
	"errors"
	"testing"

	"github.com/nox-hq/nox/core/degrade"
)

// fakeSource answers from a fixture keyed by package name.
type fakeSource struct {
	name string
	recs map[string][]Record
	err  error
	// deg, when set, is recorded on every Lookup — standing in for a source
	// that reached the network and failed.
	deg     *degrade.Degradations
	degKind degrade.Kind
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Lookup(_ context.Context, qs []Query) (map[int][]Record, error) {
	if f.deg != nil {
		f.deg.Add(f.degKind, "lookup failed", "under-reported")
	}
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[int][]Record)
	for i, q := range qs {
		if r, ok := f.recs[q.Name]; ok {
			out[i] = r
		}
	}
	return out, nil
}

func rec(id string) Record { return Record{ID: id} }

func candidate(id string) Record {
	return Record{ID: id, Intelligence: &Intelligence{Status: StatusCandidate}}
}

func queries(names ...string) []Query {
	out := make([]Query, len(names))
	for i, n := range names {
		out[i] = Query{Ecosystem: "npm", Name: n, Version: "1.0.0"}
	}
	return out
}

func verifying(intel, ref *fakeSource, deg *degrade.Degradations) *VerifyingSource {
	return NewVerifying(intel, func(rd *degrade.Degradations) Source {
		ref.deg, ref.degKind = nil, ""
		if ref.err != nil {
			ref.deg, ref.degKind = rd, degrade.OSV
		}
		return ref
	}, deg)
}

// The case the whole mechanism exists for: a source that withholds a published
// advisory. It must be detected, reported, and — critically — must not cost the
// scan the finding.
func TestVerifying_SuppressionIsCaughtAndCostsNoCoverage(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", recs: map[string][]Record{
		"lodash": {rec("GHSA-aaa")}, // GHSA-bbb withheld
	}}
	ref := &fakeSource{name: "osv.dev", recs: map[string][]Record{
		"lodash": {rec("GHSA-aaa"), rec("GHSA-bbb")},
	}}
	deg := &degrade.Degradations{}

	got, err := verifying(intel, ref, deg).Lookup(context.Background(), queries("lodash"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	ids := idSet(got[0])
	if _, ok := ids["GHSA-bbb"]; !ok {
		t.Error("the withheld record was not restored — a discrepancy cost coverage")
	}
	if len(got[0]) != 2 {
		t.Errorf("got %d records, want 2", len(got[0]))
	}

	var found bool
	for _, d := range deg.Items() {
		if d.Kind == degrade.IntelSuppression {
			found = true
		}
	}
	if !found {
		t.Error("suppression was not reported as a degradation")
	}
}

func TestVerifying_SuppressionFailsTheProperty(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", recs: map[string][]Record{"lodash": {rec("GHSA-aaa")}}}
	ref := &fakeSource{name: "osv.dev", recs: map[string][]Record{
		"lodash": {rec("GHSA-aaa"), rec("GHSA-bbb")},
	}}

	v := verifying(intel, ref, &degrade.Degradations{})
	if _, err := v.Lookup(context.Background(), queries("lodash")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	res := v.Verification()
	if res.Holds() {
		t.Error("Holds() is true despite a suppression")
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].VulnID != "GHSA-bbb" {
		t.Errorf("Suppressed = %+v, want exactly GHSA-bbb", res.Suppressed)
	}
	if res.SuppressionRate() != 1 {
		t.Errorf("SuppressionRate = %v, want 1 (one suppressed, none added)", res.SuppressionRate())
	}
}

// A genuine superset: everything the reference has, plus candidates it does
// not. The property holds and the extra records are attributed as added.
func TestVerifying_SupersetHoldsAndAttributesTheExtras(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", recs: map[string][]Record{
		"lodash": {rec("GHSA-aaa"), candidate("NOX-CAND-abc123")},
	}}
	ref := &fakeSource{name: "osv.dev", recs: map[string][]Record{"lodash": {rec("GHSA-aaa")}}}

	v := verifying(intel, ref, &degrade.Degradations{})
	got, err := v.Lookup(context.Background(), queries("lodash"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got[0]) != 2 {
		t.Fatalf("got %d records, want 2", len(got[0]))
	}

	res := v.Verification()
	if !res.Holds() {
		t.Errorf("Holds() is false for a genuine superset: %+v", res)
	}
	if len(res.Added) != 1 || res.Added[0].VulnID != "NOX-CAND-abc123" {
		t.Fatalf("Added = %+v, want the candidate", res.Added)
	}
	if res.Added[0].Status != StatusCandidate {
		t.Errorf("added status = %q, want CANDIDATE", res.Added[0].Status)
	}
	if res.SuppressionRate() != 0 {
		t.Errorf("SuppressionRate = %v, want 0", res.SuppressionRate())
	}
}

// An unreachable reference means the property was not checked. Reporting that
// as verified is the same error as reporting an unexercised check as clean, so
// Holds() is false and the rate is the worst value rather than the best.
func TestVerifying_UnreachableReferenceIsNotAPass(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", recs: map[string][]Record{"lodash": {rec("GHSA-aaa")}}}
	ref := &fakeSource{name: "osv.dev", err: errors.New("network unreachable")}
	deg := &degrade.Degradations{}

	v := verifying(intel, ref, deg)
	got, err := v.Lookup(context.Background(), queries("lodash"))
	if err != nil {
		t.Fatalf("Lookup should still answer from intel: %v", err)
	}
	if len(got[0]) != 1 {
		t.Errorf("intel's answer was lost: %+v", got)
	}

	res := v.Verification()
	if res.Checked {
		t.Error("Checked is true although the reference never answered")
	}
	if res.Holds() {
		t.Error("Holds() is true on an unchecked verification")
	}
	if res.SuppressionRate() != 1 {
		t.Errorf("SuppressionRate = %v, want 1 — an unchecked run must not promote",
			res.SuppressionRate())
	}

	var found bool
	for _, d := range deg.Items() {
		if d.Kind == degrade.IntelUnverified {
			found = true
		}
	}
	if !found {
		t.Error("an unverified run was not reported")
	}
}

// The reference's own degradation must not be reported as the scan's: the
// intelligence source answered fine, so "vulnerabilities are under-reported"
// would be false. Only the unverified-run degradation belongs to the scan.
func TestVerifying_ReferenceDegradationDoesNotLeak(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", recs: map[string][]Record{"lodash": {rec("GHSA-aaa")}}}
	ref := &fakeSource{name: "osv.dev", err: errors.New("boom")}
	deg := &degrade.Degradations{}

	if _, err := verifying(intel, ref, deg).Lookup(context.Background(), queries("lodash")); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for _, d := range deg.Items() {
		if d.Kind == degrade.OSV {
			t.Errorf("the reference's own degradation leaked into the scan: %+v", d)
		}
	}
}

// An intelligence source that cannot answer at all is a hard failure. There is
// nothing to verify, and returning the reference's records instead would
// quietly turn a broken deployment into an apparently working one.
func TestVerifying_IntelErrorFailsHard(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", err: errors.New("boom")}
	ref := &fakeSource{name: "osv.dev", recs: map[string][]Record{"lodash": {rec("GHSA-aaa")}}}

	_, err := verifying(intel, ref, &degrade.Degradations{}).Lookup(context.Background(), queries("lodash"))
	if err == nil {
		t.Fatal("expected an error when the intelligence source cannot answer")
	}
}

// Discrepancy order must not depend on map iteration, for the same reason scan
// output is sorted: a report that reshuffles between runs cannot be diffed.
func TestVerifying_DiscrepanciesAreOrdered(t *testing.T) {
	ref := &fakeSource{name: "osv.dev", recs: map[string][]Record{
		"zulu":  {rec("GHSA-zzz")},
		"alpha": {rec("GHSA-aaa"), rec("GHSA-bbb")},
		"mike":  {rec("GHSA-mmm")},
	}}
	intel := &fakeSource{name: "nox-intel", recs: map[string][]Record{}}

	var first []Discrepancy
	for i := range 5 {
		v := verifying(intel, ref, &degrade.Degradations{})
		if _, err := v.Lookup(context.Background(), queries("zulu", "alpha", "mike")); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		got := v.Verification().Suppressed
		if i == 0 {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run %d: %d discrepancies, want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d position %d = %+v, want %+v", i, j, got[j], first[j])
			}
		}
	}
	if len(first) != 4 {
		t.Fatalf("expected 4 suppressions, got %d", len(first))
	}
	if first[0].Query.Name != "alpha" || first[0].VulnID != "GHSA-aaa" {
		t.Errorf("first discrepancy = %+v, want alpha/GHSA-aaa", first[0])
	}
}
